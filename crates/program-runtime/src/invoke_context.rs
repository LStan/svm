use {
    crate::{
        loaded_programs::{
            ProgramCacheEntry, ProgramCacheEntryType, ProgramCacheForTxBatch,
            ProgramRuntimeEnvironments,
        },
        stable_log,
        sysvar_cache::SysvarCache,
    },
    solana_account::{create_account_shared_data_for_test, AccountSharedData},
    solana_clock::Slot,
    solana_compute_budget::compute_budget::ComputeBudget,
    solana_epoch_schedule::EpochSchedule,
    solana_feature_set::{
        lift_cpi_caller_restriction, move_precompile_verification_to_svm,
        remove_accounts_executable_flag_checks, FeatureSet,
    },
    solana_hash::Hash,
    solana_instruction::{error::InstructionError, AccountMeta},
    solana_log_collector::{ic_msg, LogCollector},
    solana_measure::measure::Measure,
    solana_precompiles::Precompile,
    solana_pubkey::Pubkey,
    solana_sbpf::{
        ebpf::MM_HEAP_START,
        error::{EbpfError, ProgramResult},
        memory_region::MemoryMapping,
        program::{BuiltinFunction, SBPFVersion},
        vm::{Config, ContextObject, EbpfVm},
    },
    solana_sdk_ids::{bpf_loader_deprecated, native_loader, sysvar},
    solana_stable_layout::stable_instruction::StableInstruction,
    solana_timings::{ExecuteDetailsTimings, ExecuteTimings},
    solana_transaction_context::{
        IndexOfAccount, InstructionAccount, TransactionAccount, TransactionContext,
    },
    solana_type_overrides::sync::{atomic::Ordering, Arc},
    std::{
        alloc::Layout,
        cell::RefCell,
        fmt::{self, Debug},
        rc::Rc,
    },
};

pub type BuiltinFunctionWithContext = BuiltinFunction<InvokeContext<'static>>;

/// Adapter so we can unify the interfaces of built-in programs and syscalls
#[macro_export]
macro_rules! declare_process_instruction {
    ($process_instruction:ident, $cu_to_consume:expr, |$invoke_context:ident| $inner:tt) => {
        $crate::solana_sbpf::declare_builtin_function!(
            $process_instruction,
            fn rust(
                invoke_context: &mut $crate::invoke_context::InvokeContext,
                _arg0: u64,
                _arg1: u64,
                _arg2: u64,
                _arg3: u64,
                _arg4: u64,
                _memory_mapping: &mut $crate::solana_sbpf::memory_region::MemoryMapping,
            ) -> std::result::Result<u64, Box<dyn std::error::Error>> {
                fn process_instruction_inner(
                    $invoke_context: &mut $crate::invoke_context::InvokeContext,
                ) -> std::result::Result<(), $crate::__private::InstructionError>
                    $inner

                let consumption_result = if $cu_to_consume > 0
                {
                    invoke_context.consume_checked($cu_to_consume)
                } else {
                    Ok(())
                };
                consumption_result
                    .and_then(|_| {
                        process_instruction_inner(invoke_context)
                            .map(|_| 0)
                            .map_err(|err| Box::new(err) as Box<dyn std::error::Error>)
                    })
                    .into()
            }
        );
    };
}

impl ContextObject for InvokeContext<'_> {
    fn trace(&mut self, state: [u64; 12]) {
        self.syscall_context
            .last_mut()
            .unwrap()
            .as_mut()
            .unwrap()
            .trace_log
            .push(state);
    }

    fn consume(&mut self, amount: u64) {
        // 1 to 1 instruction to compute unit mapping
        // ignore overflow, Ebpf will bail if exceeded
        let mut compute_meter = self.compute_meter.borrow_mut();
        *compute_meter = compute_meter.saturating_sub(amount);
    }

    fn get_remaining(&self) -> u64 {
        *self.compute_meter.borrow()
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AllocErr;
impl fmt::Display for AllocErr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Error: Memory allocation failed")
    }
}

pub struct BpfAllocator {
    len: u64,
    pos: u64,
}

impl BpfAllocator {
    pub fn new(len: u64) -> Self {
        Self { len, pos: 0 }
    }

    pub fn alloc(&mut self, layout: Layout) -> Result<u64, AllocErr> {
        let bytes_to_align = (self.pos as *const u8).align_offset(layout.align()) as u64;
        if self
            .pos
            .saturating_add(bytes_to_align)
            .saturating_add(layout.size() as u64)
            <= self.len
        {
            self.pos = self.pos.saturating_add(bytes_to_align);
            let addr = MM_HEAP_START.saturating_add(self.pos);
            self.pos = self.pos.saturating_add(layout.size() as u64);
            Ok(addr)
        } else {
            Err(AllocErr)
        }
    }
}

pub struct EnvironmentConfig<'a> {
    pub blockhash: Hash,
    pub blockhash_lamports_per_signature: u64,
    epoch_total_stake: u64,
    get_epoch_vote_account_stake_callback: &'a dyn Fn(&'a Pubkey) -> u64,
    pub feature_set: Arc<FeatureSet>,
    sysvar_cache: &'a SysvarCache,
}
impl<'a> EnvironmentConfig<'a> {
    pub fn new(
        blockhash: Hash,
        blockhash_lamports_per_signature: u64,
        epoch_total_stake: u64,
        get_epoch_vote_account_stake_callback: &'a dyn Fn(&'a Pubkey) -> u64,
        feature_set: Arc<FeatureSet>,
        sysvar_cache: &'a SysvarCache,
    ) -> Self {
        Self {
            blockhash,
            blockhash_lamports_per_signature,
            epoch_total_stake,
            get_epoch_vote_account_stake_callback,
            feature_set,
            sysvar_cache,
        }
    }
}

pub struct SyscallContext {
    pub allocator: BpfAllocator,
    pub accounts_metadata: Vec<SerializedAccountMetadata>,
    pub trace_log: Vec<[u64; 12]>,
}

#[derive(Debug, Clone)]
pub struct SerializedAccountMetadata {
    pub original_data_len: usize,
    pub vm_data_addr: u64,
    pub vm_key_addr: u64,
    pub vm_lamports_addr: u64,
    pub vm_owner_addr: u64,
}

/// Main pipeline from runtime to program execution.
pub struct InvokeContext<'a> {
    /// Information about the currently executing transaction.
    pub transaction_context: &'a mut TransactionContext,
    /// The local program cache for the transaction batch.
    pub program_cache_for_tx_batch: &'a mut ProgramCacheForTxBatch,
    /// Runtime configurations used to provision the invocation environment.
    pub environment_config: EnvironmentConfig<'a>,
    /// The compute budget for the current invocation.
    compute_budget: ComputeBudget,
    /// Instruction compute meter, for tracking compute units consumed against
    /// the designated compute budget during program execution.
    compute_meter: RefCell<u64>,
    log_collector: Option<Rc<RefCell<LogCollector>>>,
    /// Latest measurement not yet accumulated in [ExecuteDetailsTimings::execute_us]
    pub execute_time: Option<Measure>,
    pub timings: ExecuteDetailsTimings,
    pub syscall_context: Vec<Option<SyscallContext>>,
    traces: Vec<Vec<[u64; 12]>>,
}

impl<'a> InvokeContext<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transaction_context: &'a mut TransactionContext,
        program_cache_for_tx_batch: &'a mut ProgramCacheForTxBatch,
        environment_config: EnvironmentConfig<'a>,
        log_collector: Option<Rc<RefCell<LogCollector>>>,
        compute_budget: ComputeBudget,
    ) -> Self {
        Self {
            transaction_context,
            program_cache_for_tx_batch,
            environment_config,
            log_collector,
            compute_budget,
            compute_meter: RefCell::new(compute_budget.compute_unit_limit),
            execute_time: None,
            timings: ExecuteDetailsTimings::default(),
            syscall_context: Vec::new(),
            traces: Vec::new(),
        }
    }

    pub fn get_environments_for_slot(
        &self,
        effective_slot: Slot,
    ) -> Result<&ProgramRuntimeEnvironments, InstructionError> {
        let epoch_schedule = self.environment_config.sysvar_cache.get_epoch_schedule()?;
        let epoch = epoch_schedule.get_epoch(effective_slot);
        Ok(self
            .program_cache_for_tx_batch
            .get_environments_for_epoch(epoch))
    }

    /// Push a stack frame onto the invocation stack
    pub fn push(&mut self) -> Result<(), InstructionError> {
        let instruction_context = self
            .transaction_context
            .get_instruction_context_at_index_in_trace(
                self.transaction_context.get_instruction_trace_length(),
            )?;
        let program_id = instruction_context
            .get_last_program_key(self.transaction_context)
            .map_err(|_| InstructionError::UnsupportedProgramId)?;
        if self
            .transaction_context
            .get_instruction_context_stack_height()
            != 0
        {
            let contains = (0..self
                .transaction_context
                .get_instruction_context_stack_height())
                .any(|level| {
                    self.transaction_context
                        .get_instruction_context_at_nesting_level(level)
                        .and_then(|instruction_context| {
                            instruction_context
                                .try_borrow_last_program_account(self.transaction_context)
                        })
                        .map(|program_account| program_account.get_key() == program_id)
                        .unwrap_or(false)
                });
            let is_last = self
                .transaction_context
                .get_current_instruction_context()
                .and_then(|instruction_context| {
                    instruction_context.try_borrow_last_program_account(self.transaction_context)
                })
                .map(|program_account| program_account.get_key() == program_id)
                .unwrap_or(false);
            if contains && !is_last {
                // Reentrancy not allowed unless caller is calling itself
                return Err(InstructionError::ReentrancyNotAllowed);
            }
        }

        self.syscall_context.push(None);
        self.transaction_context.push()
    }

    /// Pop a stack frame from the invocation stack
    fn pop(&mut self) -> Result<(), InstructionError> {
        if let Some(Some(syscall_context)) = self.syscall_context.pop() {
            self.traces.push(syscall_context.trace_log);
        }
        self.transaction_context.pop()
    }

    /// Current height of the invocation stack, top level instructions are height
    /// `solana_instruction::TRANSACTION_LEVEL_STACK_HEIGHT`
    pub fn get_stack_height(&self) -> usize {
        self.transaction_context
            .get_instruction_context_stack_height()
    }

    /// Entrypoint for a cross-program invocation from a builtin program
    pub fn native_invoke(
        &mut self,
        instruction: StableInstruction,
        signers: &[Pubkey],
    ) -> Result<(), InstructionError> {
        let (instruction_accounts, program_indices) =
            self.prepare_instruction(&instruction, signers)?;
        let mut compute_units_consumed = 0;
        self.process_instruction(
            &instruction.data,
            &instruction_accounts,
            &program_indices,
            &mut compute_units_consumed,
            &mut ExecuteTimings::default(),
        )?;
        Ok(())
    }

    /// Helper to prepare for process_instruction()
    #[allow(clippy::type_complexity)]
    pub fn prepare_instruction(
        &mut self,
        instruction: &StableInstruction,
        signers: &[Pubkey],
    ) -> Result<(Vec<InstructionAccount>, Vec<IndexOfAccount>), InstructionError> {
        // Finds the index of each account in the instruction by its pubkey.
        // Then normalizes / unifies the privileges of duplicate accounts.
        // Note: This is an O(n^2) algorithm,
        // but performed on a very small slice and requires no heap allocations.
        let instruction_context = self.transaction_context.get_current_instruction_context()?;
        let mut deduplicated_instruction_accounts: Vec<InstructionAccount> = Vec::new();
        let mut duplicate_indicies = Vec::with_capacity(instruction.accounts.len() as usize);
        for (instruction_account_index, account_meta) in instruction.accounts.iter().enumerate() {
            let index_in_transaction = self
                .transaction_context
                .find_index_of_account(&account_meta.pubkey)
                .ok_or_else(|| {
                    ic_msg!(
                        self,
                        "Instruction references an unknown account {}",
                        account_meta.pubkey,
                    );
                    InstructionError::MissingAccount
                })?;
            if let Some(duplicate_index) =
                deduplicated_instruction_accounts
                    .iter()
                    .position(|instruction_account| {
                        instruction_account.index_in_transaction == index_in_transaction
                    })
            {
                duplicate_indicies.push(duplicate_index);
                let instruction_account = deduplicated_instruction_accounts
                    .get_mut(duplicate_index)
                    .ok_or(InstructionError::NotEnoughAccountKeys)?;
                instruction_account.is_signer |= account_meta.is_signer;
                instruction_account.is_writable |= account_meta.is_writable;
            } else {
                let index_in_caller = instruction_context
                    .find_index_of_instruction_account(
                        self.transaction_context,
                        &account_meta.pubkey,
                    )
                    .ok_or_else(|| {
                        ic_msg!(
                            self,
                            "Instruction references an unknown account {}",
                            account_meta.pubkey,
                        );
                        InstructionError::MissingAccount
                    })?;
                duplicate_indicies.push(deduplicated_instruction_accounts.len());
                deduplicated_instruction_accounts.push(InstructionAccount {
                    index_in_transaction,
                    index_in_caller,
                    index_in_callee: instruction_account_index as IndexOfAccount,
                    is_signer: account_meta.is_signer,
                    is_writable: account_meta.is_writable,
                });
            }
        }
        for instruction_account in deduplicated_instruction_accounts.iter() {
            let borrowed_account = instruction_context.try_borrow_instruction_account(
                self.transaction_context,
                instruction_account.index_in_caller,
            )?;

            // Readonly in caller cannot become writable in callee
            if instruction_account.is_writable && !borrowed_account.is_writable() {
                ic_msg!(
                    self,
                    "{}'s writable privilege escalated",
                    borrowed_account.get_key(),
                );
                return Err(InstructionError::PrivilegeEscalation);
            }

            // To be signed in the callee,
            // it must be either signed in the caller or by the program
            if instruction_account.is_signer
                && !(borrowed_account.is_signer() || signers.contains(borrowed_account.get_key()))
            {
                ic_msg!(
                    self,
                    "{}'s signer privilege escalated",
                    borrowed_account.get_key()
                );
                return Err(InstructionError::PrivilegeEscalation);
            }
        }
        let instruction_accounts = duplicate_indicies
            .into_iter()
            .map(|duplicate_index| {
                deduplicated_instruction_accounts
                    .get(duplicate_index)
                    .cloned()
                    .ok_or(InstructionError::NotEnoughAccountKeys)
            })
            .collect::<Result<Vec<InstructionAccount>, InstructionError>>()?;

        // Find and validate executables / program accounts
        let callee_program_id = instruction.program_id;
        let program_account_index = if self
            .get_feature_set()
            .is_active(&lift_cpi_caller_restriction::id())
        {
            self.transaction_context
                .find_index_of_program_account(&callee_program_id)
                .ok_or_else(|| {
                    ic_msg!(self, "Unknown program {}", callee_program_id);
                    InstructionError::MissingAccount
                })?
        } else {
            let program_account_index = instruction_context
                .find_index_of_instruction_account(self.transaction_context, &callee_program_id)
                .ok_or_else(|| {
                    ic_msg!(self, "Unknown program {}", callee_program_id);
                    InstructionError::MissingAccount
                })?;
            let borrowed_program_account = instruction_context
                .try_borrow_instruction_account(self.transaction_context, program_account_index)?;
            #[allow(deprecated)]
            if !self
                .get_feature_set()
                .is_active(&remove_accounts_executable_flag_checks::id())
                && !borrowed_program_account.is_executable()
            {
                ic_msg!(self, "Account {} is not executable", callee_program_id);
                return Err(InstructionError::AccountNotExecutable);
            }
            borrowed_program_account.get_index_in_transaction()
        };

        Ok((instruction_accounts, vec![program_account_index]))
    }

    /// Processes an instruction and returns how many compute units were used
    pub fn process_instruction(
        &mut self,
        instruction_data: &[u8],
        instruction_accounts: &[InstructionAccount],
        program_indices: &[IndexOfAccount],
        compute_units_consumed: &mut u64,
        timings: &mut ExecuteTimings,
    ) -> Result<(), InstructionError> {
        *compute_units_consumed = 0;
        self.transaction_context
            .get_next_instruction_context()?
            .configure(program_indices, instruction_accounts, instruction_data);
        self.push()?;
        self.process_executable_chain(compute_units_consumed, timings)
            // MUST pop if and only if `push` succeeded, independent of `result`.
            // Thus, the `.and()` instead of an `.and_then()`.
            .and(self.pop())
    }

    /// Processes a precompile instruction
    pub fn process_precompile<'ix_data>(
        &mut self,
        precompile: &Precompile,
        instruction_data: &[u8],
        instruction_accounts: &[InstructionAccount],
        program_indices: &[IndexOfAccount],
        message_instruction_datas_iter: impl Iterator<Item = &'ix_data [u8]>,
    ) -> Result<(), InstructionError> {
        self.transaction_context
            .get_next_instruction_context()?
            .configure(program_indices, instruction_accounts, instruction_data);
        self.push()?;

        let feature_set = self.get_feature_set();
        let move_precompile_verification_to_svm =
            feature_set.is_active(&move_precompile_verification_to_svm::id());
        if move_precompile_verification_to_svm {
            let instruction_datas: Vec<_> = message_instruction_datas_iter.collect();
            precompile
                .verify(instruction_data, &instruction_datas, feature_set)
                .map_err(InstructionError::from)
                .and(self.pop())
        } else {
            self.pop()
        }
    }

    /// Calls the instruction's program entrypoint method
    fn process_executable_chain(
        &mut self,
        compute_units_consumed: &mut u64,
        timings: &mut ExecuteTimings,
    ) -> Result<(), InstructionError> {
        let instruction_context = self.transaction_context.get_current_instruction_context()?;
        let process_executable_chain_time = Measure::start("process_executable_chain_time");

        let builtin_id = {
            debug_assert!(instruction_context.get_number_of_program_accounts() <= 1);
            let borrowed_root_account = instruction_context
                .try_borrow_program_account(self.transaction_context, 0)
                .map_err(|_| InstructionError::UnsupportedProgramId)?;
            let owner_id = borrowed_root_account.get_owner();
            if native_loader::check_id(owner_id) {
                *borrowed_root_account.get_key()
            } else {
                *owner_id
            }
        };

        // The Murmur3 hash value (used by RBPF) of the string "entrypoint"
        const ENTRYPOINT_KEY: u32 = 0x71E3CF81;
        let entry = self
            .program_cache_for_tx_batch
            .find(&builtin_id)
            .ok_or(InstructionError::UnsupportedProgramId)?;
        let function = match &entry.program {
            ProgramCacheEntryType::Builtin(program) => program
                .get_function_registry()
                .lookup_by_key(ENTRYPOINT_KEY)
                .map(|(_name, function)| function),
            _ => None,
        }
        .ok_or(InstructionError::UnsupportedProgramId)?;
        entry.ix_usage_counter.fetch_add(1, Ordering::Relaxed);

        let program_id = *instruction_context.get_last_program_key(self.transaction_context)?;
        self.transaction_context
            .set_return_data(program_id, Vec::new())?;
        let logger = self.get_log_collector();
        stable_log::program_invoke(&logger, &program_id, self.get_stack_height());
        let pre_remaining_units = self.get_remaining();
        // In program-runtime v2 we will create this VM instance only once per transaction.
        // `program_runtime_environment_v2.get_config()` will be used instead of `mock_config`.
        // For now, only built-ins are invoked from here, so the VM and its Config are irrelevant.
        let mock_config = Config::default();
        let empty_memory_mapping =
            MemoryMapping::new(Vec::new(), &mock_config, SBPFVersion::V0).unwrap();
        let mut vm = EbpfVm::new(
            self.program_cache_for_tx_batch
                .environments
                .program_runtime_v2
                .clone(),
            SBPFVersion::V0,
            // Removes lifetime tracking
            unsafe { std::mem::transmute::<&mut InvokeContext, &mut InvokeContext>(self) },
            empty_memory_mapping,
            0,
        );
        vm.invoke_function(function);
        let result = match vm.program_result {
            ProgramResult::Ok(_) => {
                stable_log::program_success(&logger, &program_id);
                Ok(())
            }
            ProgramResult::Err(ref err) => {
                if let EbpfError::SyscallError(syscall_error) = err {
                    if let Some(instruction_err) = syscall_error.downcast_ref::<InstructionError>()
                    {
                        stable_log::program_failure(&logger, &program_id, instruction_err);
                        Err(instruction_err.clone())
                    } else {
                        stable_log::program_failure(&logger, &program_id, syscall_error);
                        Err(InstructionError::ProgramFailedToComplete)
                    }
                } else {
                    stable_log::program_failure(&logger, &program_id, err);
                    Err(InstructionError::ProgramFailedToComplete)
                }
            }
        };
        let post_remaining_units = self.get_remaining();
        *compute_units_consumed = pre_remaining_units.saturating_sub(post_remaining_units);

        if builtin_id == program_id && result.is_ok() && *compute_units_consumed == 0 {
            return Err(InstructionError::BuiltinProgramsMustConsumeComputeUnits);
        }

        timings
            .execute_accessories
            .process_instructions
            .process_executable_chain_us += process_executable_chain_time.end_as_us();
        result
    }

    /// Get this invocation's LogCollector
    pub fn get_log_collector(&self) -> Option<Rc<RefCell<LogCollector>>> {
        self.log_collector.clone()
    }

    /// Consume compute units
    pub fn consume_checked(&self, amount: u64) -> Result<(), Box<dyn std::error::Error>> {
        let mut compute_meter = self.compute_meter.borrow_mut();
        let exceeded = *compute_meter < amount;
        *compute_meter = compute_meter.saturating_sub(amount);
        if exceeded {
            return Err(Box::new(InstructionError::ComputationalBudgetExceeded));
        }
        Ok(())
    }

    /// Set compute units
    ///
    /// Only use for tests and benchmarks
    pub fn mock_set_remaining(&self, remaining: u64) {
        *self.compute_meter.borrow_mut() = remaining;
    }

    /// Get this invocation's compute budget
    pub fn get_compute_budget(&self) -> &ComputeBudget {
        &self.compute_budget
    }

    /// Get the current feature set.
    pub fn get_feature_set(&self) -> &FeatureSet {
        &self.environment_config.feature_set
    }

    /// Set feature set.
    ///
    /// Only use for tests and benchmarks.
    pub fn mock_set_feature_set(&mut self, feature_set: Arc<FeatureSet>) {
        self.environment_config.feature_set = feature_set;
    }

    /// Get cached sysvars
    pub fn get_sysvar_cache(&self) -> &SysvarCache {
        self.environment_config.sysvar_cache
    }

    /// Get cached epoch total stake.
    pub fn get_epoch_total_stake(&self) -> u64 {
        self.environment_config.epoch_total_stake
    }

    /// Get cached stake for the epoch vote account.
    pub fn get_epoch_vote_account_stake(&self, pubkey: &'a Pubkey) -> u64 {
        (self
            .environment_config
            .get_epoch_vote_account_stake_callback)(pubkey)
    }

    // Should alignment be enforced during user pointer translation
    pub fn get_check_aligned(&self) -> bool {
        self.transaction_context
            .get_current_instruction_context()
            .and_then(|instruction_context| {
                let program_account =
                    instruction_context.try_borrow_last_program_account(self.transaction_context);
                debug_assert!(program_account.is_ok());
                program_account
            })
            .map(|program_account| *program_account.get_owner() != bpf_loader_deprecated::id())
            .unwrap_or(true)
    }

    // Set this instruction syscall context
    pub fn set_syscall_context(
        &mut self,
        syscall_context: SyscallContext,
    ) -> Result<(), InstructionError> {
        *self
            .syscall_context
            .last_mut()
            .ok_or(InstructionError::CallDepth)? = Some(syscall_context);
        Ok(())
    }

    // Get this instruction's SyscallContext
    pub fn get_syscall_context(&self) -> Result<&SyscallContext, InstructionError> {
        self.syscall_context
            .last()
            .and_then(std::option::Option::as_ref)
            .ok_or(InstructionError::CallDepth)
    }

    // Get this instruction's SyscallContext
    pub fn get_syscall_context_mut(&mut self) -> Result<&mut SyscallContext, InstructionError> {
        self.syscall_context
            .last_mut()
            .and_then(|syscall_context| syscall_context.as_mut())
            .ok_or(InstructionError::CallDepth)
    }

    /// Return a references to traces
    pub fn get_traces(&self) -> &Vec<Vec<[u64; 12]>> {
        &self.traces
    }
}

#[macro_export]
macro_rules! with_mock_invoke_context {
    (
        $invoke_context:ident,
        $transaction_context:ident,
        $transaction_accounts:expr $(,)?
    ) => {
        use {
            solana_compute_budget::compute_budget::ComputeBudget,
            solana_feature_set::FeatureSet,
            solana_log_collector::LogCollector,
            solana_type_overrides::sync::Arc,
            $crate::{
                __private::{Hash, ReadableAccount, Rent, TransactionContext},
                invoke_context::{EnvironmentConfig, InvokeContext},
                loaded_programs::ProgramCacheForTxBatch,
                sysvar_cache::SysvarCache,
            },
        };
        let compute_budget = ComputeBudget::default();
        let mut $transaction_context = TransactionContext::new(
            $transaction_accounts,
            Rent::default(),
            compute_budget.max_instruction_stack_depth,
            compute_budget.max_instruction_trace_length,
        );
        let mut sysvar_cache = SysvarCache::default();
        sysvar_cache.fill_missing_entries(|pubkey, callback| {
            for index in 0..$transaction_context.get_number_of_accounts() {
                if $transaction_context
                    .get_key_of_account_at_index(index)
                    .unwrap()
                    == pubkey
                {
                    callback(
                        $transaction_context
                            .get_account_at_index(index)
                            .unwrap()
                            .borrow()
                            .data(),
                    );
                }
            }
        });
        let environment_config = EnvironmentConfig::new(
            Hash::default(),
            0,
            0,
            &|_| 0,
            Arc::new(FeatureSet::all_enabled()),
            &sysvar_cache,
        );
        let mut program_cache_for_tx_batch = ProgramCacheForTxBatch::default();
        let mut $invoke_context = InvokeContext::new(
            &mut $transaction_context,
            &mut program_cache_for_tx_batch,
            environment_config,
            Some(LogCollector::new_ref()),
            compute_budget,
        );
    };
}

pub fn mock_process_instruction<F: FnMut(&mut InvokeContext), G: FnMut(&mut InvokeContext)>(
    loader_id: &Pubkey,
    mut program_indices: Vec<IndexOfAccount>,
    instruction_data: &[u8],
    mut transaction_accounts: Vec<TransactionAccount>,
    instruction_account_metas: Vec<AccountMeta>,
    expected_result: Result<(), InstructionError>,
    builtin_function: BuiltinFunctionWithContext,
    mut pre_adjustments: F,
    mut post_adjustments: G,
) -> Vec<AccountSharedData> {
    let mut instruction_accounts: Vec<InstructionAccount> =
        Vec::with_capacity(instruction_account_metas.len());
    for (instruction_account_index, account_meta) in instruction_account_metas.iter().enumerate() {
        let index_in_transaction = transaction_accounts
            .iter()
            .position(|(key, _account)| *key == account_meta.pubkey)
            .unwrap_or(transaction_accounts.len())
            as IndexOfAccount;
        let index_in_callee = instruction_accounts
            .get(0..instruction_account_index)
            .unwrap()
            .iter()
            .position(|instruction_account| {
                instruction_account.index_in_transaction == index_in_transaction
            })
            .unwrap_or(instruction_account_index) as IndexOfAccount;
        instruction_accounts.push(InstructionAccount {
            index_in_transaction,
            index_in_caller: index_in_transaction,
            index_in_callee,
            is_signer: account_meta.is_signer,
            is_writable: account_meta.is_writable,
        });
    }
    if program_indices.is_empty() {
        program_indices.insert(0, transaction_accounts.len() as IndexOfAccount);
        let processor_account = AccountSharedData::new(0, 0, &native_loader::id());
        transaction_accounts.push((*loader_id, processor_account));
    }
    let pop_epoch_schedule_account = if !transaction_accounts
        .iter()
        .any(|(key, _)| *key == sysvar::epoch_schedule::id())
    {
        transaction_accounts.push((
            sysvar::epoch_schedule::id(),
            create_account_shared_data_for_test(&EpochSchedule::default()),
        ));
        true
    } else {
        false
    };
    with_mock_invoke_context!(invoke_context, transaction_context, transaction_accounts);
    let mut program_cache_for_tx_batch = ProgramCacheForTxBatch::default();
    program_cache_for_tx_batch.replenish(
        *loader_id,
        Arc::new(ProgramCacheEntry::new_builtin(0, 0, builtin_function)),
    );
    invoke_context.program_cache_for_tx_batch = &mut program_cache_for_tx_batch;
    pre_adjustments(&mut invoke_context);
    let result = invoke_context.process_instruction(
        instruction_data,
        &instruction_accounts,
        &program_indices,
        &mut 0,
        &mut ExecuteTimings::default(),
    );
    assert_eq!(result, expected_result);
    post_adjustments(&mut invoke_context);
    let mut transaction_accounts = transaction_context.deconstruct_without_keys().unwrap();
    if pop_epoch_schedule_account {
        transaction_accounts.pop();
    }
    transaction_accounts.pop();
    transaction_accounts
}
