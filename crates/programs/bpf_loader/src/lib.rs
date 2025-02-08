#![deny(clippy::arithmetic_side_effects)]
#![deny(clippy::indexing_slicing)]

pub mod serialization;
pub mod syscalls;

#[cfg(feature = "svm-internal")]
use qualifier_attr::qualifiers;
use {
    solana_account::WritableAccount,
    solana_bincode::limited_deserialize,
    solana_clock::Slot,
    solana_compute_budget::compute_budget::MAX_INSTRUCTION_STACK_DEPTH,
    solana_feature_set::{
        bpf_account_data_direct_mapping, disable_new_loader_v3_deployments,
        enable_bpf_loader_set_authority_checked_ix, remove_accounts_executable_flag_checks,
    },
    solana_instruction::{error::InstructionError, AccountMeta},
    solana_loader_v3_interface::{
        instruction::UpgradeableLoaderInstruction, state::UpgradeableLoaderState,
    },
    solana_log_collector::{ic_logger_msg, ic_msg, LogCollector},
    solana_program_entrypoint::{MAX_PERMITTED_DATA_INCREASE, SUCCESS},
    solana_program_runtime::{
        invoke_context::{BpfAllocator, InvokeContext, SerializedAccountMetadata, SyscallContext},
        loaded_programs::{
            ProgramCacheEntry, ProgramCacheEntryOwner, ProgramCacheEntryType,
            ProgramCacheForTxBatch, ProgramRuntimeEnvironment, DELAY_VISIBILITY_SLOT_OFFSET,
        },
        mem_pool::VmMemoryPool,
        stable_log,
        sysvar_cache::get_sysvar_with_account_check,
    },
    solana_pubkey::Pubkey,
    solana_sbpf::{
        declare_builtin_function,
        ebpf::{self, MM_HEAP_START},
        elf::Executable,
        error::{EbpfError, ProgramResult},
        memory_region::{AccessType, MemoryCowCallback, MemoryMapping, MemoryRegion},
        program::BuiltinProgram,
        verifier::RequisiteVerifier,
        vm::{ContextObject, EbpfVm},
    },
    solana_sdk_ids::{bpf_loader, bpf_loader_deprecated, bpf_loader_upgradeable, native_loader},
    solana_system_interface::{instruction as system_instruction, MAX_PERMITTED_DATA_LENGTH},
    solana_transaction_context::{IndexOfAccount, InstructionContext, TransactionContext},
    solana_type_overrides::sync::{atomic::Ordering, Arc},
    std::{cell::RefCell, mem, rc::Rc},
    syscalls::morph_into_deployment_environment_v1,
};

#[cfg_attr(feature = "svm-internal", qualifiers(pub))]
const DEFAULT_LOADER_COMPUTE_UNITS: u64 = 570;
#[cfg_attr(feature = "svm-internal", qualifiers(pub))]
const DEPRECATED_LOADER_COMPUTE_UNITS: u64 = 1_140;
#[cfg_attr(feature = "svm-internal", qualifiers(pub))]
const UPGRADEABLE_LOADER_COMPUTE_UNITS: u64 = 2_370;

thread_local! {
    pub static MEMORY_POOL: RefCell<VmMemoryPool> = RefCell::new(VmMemoryPool::new());
}

#[allow(clippy::too_many_arguments)]
pub fn load_program_from_bytes(
    log_collector: Option<Rc<RefCell<LogCollector>>>,
    programdata: &[u8],
    loader_key: &Pubkey,
    account_size: usize,
    deployment_slot: Slot,
    program_runtime_environment: Arc<BuiltinProgram<InvokeContext<'static>>>,
    reloading: bool,
) -> Result<ProgramCacheEntry, InstructionError> {
    let effective_slot = deployment_slot.saturating_add(DELAY_VISIBILITY_SLOT_OFFSET);
    let loaded_program = if reloading {
        // Safety: this is safe because the program is being reloaded in the cache.
        unsafe {
            ProgramCacheEntry::reload(
                loader_key,
                program_runtime_environment,
                deployment_slot,
                effective_slot,
                programdata,
                account_size,
            )
        }
    } else {
        ProgramCacheEntry::new(
            loader_key,
            program_runtime_environment,
            deployment_slot,
            effective_slot,
            programdata,
            account_size,
        )
    }
    .map_err(|err| {
        ic_logger_msg!(log_collector, "{}", err);
        InstructionError::InvalidAccountData
    })?;
    Ok(loaded_program)
}

/// Directly deploy a program using a provided invoke context.
/// This function should only be invoked from the runtime, since it does not
/// provide any account loads or checks.
pub fn deploy_program(
    log_collector: Option<Rc<RefCell<LogCollector>>>,
    program_cache_for_tx_batch: &mut ProgramCacheForTxBatch,
    program_runtime_environment: ProgramRuntimeEnvironment,
    program_id: &Pubkey,
    loader_key: &Pubkey,
    account_size: usize,
    programdata: &[u8],
    deployment_slot: Slot,
) -> Result<(), InstructionError> {
    let deployment_program_runtime_environment =
        morph_into_deployment_environment_v1(program_runtime_environment.clone()).map_err(|e| {
            ic_logger_msg!(log_collector, "Failed to register syscalls: {}", e);
            InstructionError::ProgramEnvironmentSetupFailure
        })?;
    // Verify using stricter deployment_program_runtime_environment
    let executable = Executable::<InvokeContext>::load(
        programdata,
        Arc::new(deployment_program_runtime_environment),
    )
    .map_err(|err| {
        ic_logger_msg!(log_collector, "{}", err);
        InstructionError::InvalidAccountData
    })?;
    executable.verify::<RequisiteVerifier>().map_err(|err| {
        ic_logger_msg!(log_collector, "{}", err);
        InstructionError::InvalidAccountData
    })?;
    // Reload but with program_runtime_environment
    let executor = load_program_from_bytes(
        log_collector,
        programdata,
        loader_key,
        account_size,
        deployment_slot,
        program_runtime_environment,
        true,
    )?;
    if let Some(old_entry) = program_cache_for_tx_batch.find(program_id) {
        executor.tx_usage_counter.store(
            old_entry.tx_usage_counter.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        executor.ix_usage_counter.store(
            old_entry.ix_usage_counter.load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
    }
    program_cache_for_tx_batch.store_modified_entry(*program_id, Arc::new(executor));
    Ok(())
}

#[macro_export]
macro_rules! deploy_program {
    ($invoke_context:expr, $program_id:expr, $loader_key:expr, $account_size:expr, $programdata:expr, $deployment_slot:expr $(,)?) => {
        let environments = $invoke_context
            .get_environments_for_slot($deployment_slot.saturating_add(
                solana_program_runtime::loaded_programs::DELAY_VISIBILITY_SLOT_OFFSET,
            ))
            .map_err(|_err| {
                // This will never fail since the epoch schedule is already configured.
                InstructionError::ProgramEnvironmentSetupFailure
            })?;
        $crate::deploy_program(
            $invoke_context.get_log_collector(),
            $invoke_context.program_cache_for_tx_batch,
            environments.program_runtime_v1.clone(),
            $program_id,
            $loader_key,
            $account_size,
            $programdata,
            $deployment_slot,
        )?;
    };
}

fn write_program_data(
    program_data_offset: usize,
    bytes: &[u8],
    invoke_context: &mut InvokeContext,
) -> Result<(), InstructionError> {
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let mut program = instruction_context.try_borrow_instruction_account(transaction_context, 0)?;
    let data = program.get_data_mut()?;
    let write_offset = program_data_offset.saturating_add(bytes.len());
    if data.len() < write_offset {
        ic_msg!(
            invoke_context,
            "Write overflow: {} < {}",
            data.len(),
            write_offset,
        );
        return Err(InstructionError::AccountDataTooSmall);
    }
    data.get_mut(program_data_offset..write_offset)
        .ok_or(InstructionError::AccountDataTooSmall)?
        .copy_from_slice(bytes);
    Ok(())
}

/// Only used in macro, do not use directly!
pub fn calculate_heap_cost(heap_size: u32, heap_cost: u64) -> u64 {
    const KIBIBYTE: u64 = 1024;
    const PAGE_SIZE_KB: u64 = 32;
    let mut rounded_heap_size = u64::from(heap_size);
    rounded_heap_size =
        rounded_heap_size.saturating_add(PAGE_SIZE_KB.saturating_mul(KIBIBYTE).saturating_sub(1));
    rounded_heap_size
        .checked_div(PAGE_SIZE_KB.saturating_mul(KIBIBYTE))
        .expect("PAGE_SIZE_KB * KIBIBYTE > 0")
        .saturating_sub(1)
        .saturating_mul(heap_cost)
}

/// Only used in macro, do not use directly!
#[cfg_attr(feature = "svm-internal", qualifiers(pub))]
fn create_vm<'a, 'b>(
    program: &'a Executable<InvokeContext<'b>>,
    regions: Vec<MemoryRegion>,
    accounts_metadata: Vec<SerializedAccountMetadata>,
    invoke_context: &'a mut InvokeContext<'b>,
    stack: &mut [u8],
    heap: &mut [u8],
) -> Result<EbpfVm<'a, InvokeContext<'b>>, Box<dyn std::error::Error>> {
    let stack_size = stack.len();
    let heap_size = heap.len();
    let accounts = Rc::clone(invoke_context.transaction_context.accounts());
    let memory_mapping = create_memory_mapping(
        program,
        stack,
        heap,
        regions,
        Some(Box::new(move |index_in_transaction| {
            // The two calls below can't really fail. If they fail because of a bug,
            // whatever is writing will trigger an EbpfError::AccessViolation like
            // if the region was readonly, and the transaction will fail gracefully.
            let mut account = accounts
                .try_borrow_mut(index_in_transaction as IndexOfAccount)
                .map_err(|_| ())?;
            accounts
                .touch(index_in_transaction as IndexOfAccount)
                .map_err(|_| ())?;

            if account.is_shared() {
                // See BorrowedAccount::make_data_mut() as to why we reserve extra
                // MAX_PERMITTED_DATA_INCREASE bytes here.
                account.reserve(MAX_PERMITTED_DATA_INCREASE);
            }
            Ok(account.data_as_mut_slice().as_mut_ptr() as u64)
        })),
    )?;
    invoke_context.set_syscall_context(SyscallContext {
        allocator: BpfAllocator::new(heap_size as u64),
        accounts_metadata,
        trace_log: Vec::new(),
    })?;
    Ok(EbpfVm::new(
        program.get_loader().clone(),
        program.get_sbpf_version(),
        invoke_context,
        memory_mapping,
        stack_size,
    ))
}

/// Create the SBF virtual machine
#[macro_export]
macro_rules! create_vm {
    ($vm:ident, $program:expr, $regions:expr, $accounts_metadata:expr, $invoke_context:expr $(,)?) => {
        let invoke_context = &*$invoke_context;
        let stack_size = $program.get_config().stack_size();
        let heap_size = invoke_context.get_compute_budget().heap_size;
        let heap_cost_result = invoke_context.consume_checked($crate::calculate_heap_cost(
            heap_size,
            invoke_context.get_compute_budget().heap_cost,
        ));
        let $vm = heap_cost_result.and_then(|_| {
            let (mut stack, mut heap) = $crate::MEMORY_POOL
                .with_borrow_mut(|pool| (pool.get_stack(stack_size), pool.get_heap(heap_size)));
            let vm = $crate::create_vm(
                $program,
                $regions,
                $accounts_metadata,
                $invoke_context,
                stack
                    .as_slice_mut()
                    .get_mut(..stack_size)
                    .expect("invalid stack size"),
                heap.as_slice_mut()
                    .get_mut(..heap_size as usize)
                    .expect("invalid heap size"),
            );
            vm.map(|vm| (vm, stack, heap))
        });
    };
}

#[macro_export]
macro_rules! mock_create_vm {
    ($vm:ident, $additional_regions:expr, $accounts_metadata:expr, $invoke_context:expr $(,)?) => {
        let loader = solana_type_overrides::sync::Arc::new(BuiltinProgram::new_mock());
        let function_registry = solana_sbpf::program::FunctionRegistry::default();
        let executable = solana_sbpf::elf::Executable::<InvokeContext>::from_text_bytes(
            &[0x9D, 0, 0, 0, 0, 0, 0, 0],
            loader,
            SBPFVersion::V3,
            function_registry,
        )
        .unwrap();
        executable
            .verify::<solana_sbpf::verifier::RequisiteVerifier>()
            .unwrap();
        $crate::create_vm!(
            $vm,
            &executable,
            $additional_regions,
            $accounts_metadata,
            $invoke_context,
        );
        let $vm = $vm.map(|(vm, _, _)| vm);
    };
}

fn create_memory_mapping<'a, 'b, C: ContextObject>(
    executable: &'a Executable<C>,
    stack: &'b mut [u8],
    heap: &'b mut [u8],
    additional_regions: Vec<MemoryRegion>,
    cow_cb: Option<MemoryCowCallback>,
) -> Result<MemoryMapping<'a>, Box<dyn std::error::Error>> {
    let config = executable.get_config();
    let sbpf_version = executable.get_sbpf_version();
    let regions: Vec<MemoryRegion> = vec![
        executable.get_ro_region(),
        MemoryRegion::new_writable_gapped(
            stack,
            ebpf::MM_STACK_START,
            if !sbpf_version.dynamic_stack_frames() && config.enable_stack_frame_gaps {
                config.stack_frame_size as u64
            } else {
                0
            },
        ),
        MemoryRegion::new_writable(heap, MM_HEAP_START),
    ]
    .into_iter()
    .chain(additional_regions)
    .collect();

    Ok(if let Some(cow_cb) = cow_cb {
        MemoryMapping::new_with_cow(regions, cow_cb, config, sbpf_version)?
    } else {
        MemoryMapping::new(regions, config, sbpf_version)?
    })
}

declare_builtin_function!(
    Entrypoint,
    fn rust(
        invoke_context: &mut InvokeContext,
        _arg0: u64,
        _arg1: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        process_instruction_inner(invoke_context)
    }
);

#[cfg_attr(feature = "svm-internal", qualifiers(pub))]
pub(crate) fn process_instruction_inner(
    invoke_context: &mut InvokeContext,
) -> Result<u64, Box<dyn std::error::Error>> {
    let log_collector = invoke_context.get_log_collector();
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let program_account =
        instruction_context.try_borrow_last_program_account(transaction_context)?;

    // Program Management Instruction
    if native_loader::check_id(program_account.get_owner()) {
        drop(program_account);
        let program_id = instruction_context.get_last_program_key(transaction_context)?;
        return if bpf_loader_upgradeable::check_id(program_id) {
            invoke_context.consume_checked(UPGRADEABLE_LOADER_COMPUTE_UNITS)?;
            process_loader_upgradeable_instruction(invoke_context)
        } else if bpf_loader::check_id(program_id) {
            invoke_context.consume_checked(DEFAULT_LOADER_COMPUTE_UNITS)?;
            ic_logger_msg!(
                log_collector,
                "BPF loader management instructions are no longer supported",
            );
            Err(InstructionError::UnsupportedProgramId)
        } else if bpf_loader_deprecated::check_id(program_id) {
            invoke_context.consume_checked(DEPRECATED_LOADER_COMPUTE_UNITS)?;
            ic_logger_msg!(log_collector, "Deprecated loader is no longer supported");
            Err(InstructionError::UnsupportedProgramId)
        } else {
            ic_logger_msg!(log_collector, "Invalid BPF loader id");
            Err(
                if invoke_context
                    .get_feature_set()
                    .is_active(&remove_accounts_executable_flag_checks::id())
                {
                    InstructionError::UnsupportedProgramId
                } else {
                    InstructionError::IncorrectProgramId
                },
            )
        }
        .map(|_| 0)
        .map_err(|error| Box::new(error) as Box<dyn std::error::Error>);
    }

    // Program Invocation
    #[allow(deprecated)]
    if !invoke_context
        .get_feature_set()
        .is_active(&remove_accounts_executable_flag_checks::id())
        && !program_account.is_executable()
    {
        ic_logger_msg!(log_collector, "Program is not executable");
        return Err(Box::new(InstructionError::IncorrectProgramId));
    }

    let executor = invoke_context
        .program_cache_for_tx_batch
        .find(program_account.get_key())
        .ok_or_else(|| {
            ic_logger_msg!(log_collector, "Program is not cached");
            if invoke_context
                .get_feature_set()
                .is_active(&remove_accounts_executable_flag_checks::id())
            {
                InstructionError::UnsupportedProgramId
            } else {
                InstructionError::InvalidAccountData
            }
        })?;
    drop(program_account);

    executor.ix_usage_counter.fetch_add(1, Ordering::Relaxed);
    match &executor.program {
        ProgramCacheEntryType::FailedVerification(_)
        | ProgramCacheEntryType::Closed
        | ProgramCacheEntryType::DelayVisibility => {
            ic_logger_msg!(log_collector, "Program is not deployed");
            let instruction_error = if invoke_context
                .get_feature_set()
                .is_active(&remove_accounts_executable_flag_checks::id())
            {
                InstructionError::UnsupportedProgramId
            } else {
                InstructionError::InvalidAccountData
            };
            Err(Box::new(instruction_error) as Box<dyn std::error::Error>)
        }
        ProgramCacheEntryType::Loaded(executable) => execute(executable, invoke_context),
        _ => {
            let instruction_error = if invoke_context
                .get_feature_set()
                .is_active(&remove_accounts_executable_flag_checks::id())
            {
                InstructionError::UnsupportedProgramId
            } else {
                InstructionError::IncorrectProgramId
            };
            Err(Box::new(instruction_error) as Box<dyn std::error::Error>)
        }
    }
    .map(|_| 0)
}

fn process_loader_upgradeable_instruction(
    invoke_context: &mut InvokeContext,
) -> Result<(), InstructionError> {
    let log_collector = invoke_context.get_log_collector();
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let instruction_data = instruction_context.get_instruction_data();
    let program_id = instruction_context.get_last_program_key(transaction_context)?;

    match limited_deserialize(instruction_data, solana_packet::PACKET_DATA_SIZE as u64)? {
        UpgradeableLoaderInstruction::InitializeBuffer => {
            instruction_context.check_number_of_instruction_accounts(2)?;
            let mut buffer =
                instruction_context.try_borrow_instruction_account(transaction_context, 0)?;

            if UpgradeableLoaderState::Uninitialized != buffer.get_state()? {
                ic_logger_msg!(log_collector, "Buffer account already initialized");
                return Err(InstructionError::AccountAlreadyInitialized);
            }

            let authority_key = Some(*transaction_context.get_key_of_account_at_index(
                instruction_context.get_index_of_instruction_account_in_transaction(1)?,
            )?);

            buffer.set_state(&UpgradeableLoaderState::Buffer {
                authority_address: authority_key,
            })?;
        }
        UpgradeableLoaderInstruction::Write { offset, bytes } => {
            instruction_context.check_number_of_instruction_accounts(2)?;
            let buffer =
                instruction_context.try_borrow_instruction_account(transaction_context, 0)?;

            if let UpgradeableLoaderState::Buffer { authority_address } = buffer.get_state()? {
                if authority_address.is_none() {
                    ic_logger_msg!(log_collector, "Buffer is immutable");
                    return Err(InstructionError::Immutable); // TODO better error code
                }
                let authority_key = Some(*transaction_context.get_key_of_account_at_index(
                    instruction_context.get_index_of_instruction_account_in_transaction(1)?,
                )?);
                if authority_address != authority_key {
                    ic_logger_msg!(log_collector, "Incorrect buffer authority provided");
                    return Err(InstructionError::IncorrectAuthority);
                }
                if !instruction_context.is_instruction_account_signer(1)? {
                    ic_logger_msg!(log_collector, "Buffer authority did not sign");
                    return Err(InstructionError::MissingRequiredSignature);
                }
            } else {
                ic_logger_msg!(log_collector, "Invalid Buffer account");
                return Err(InstructionError::InvalidAccountData);
            }
            drop(buffer);
            write_program_data(
                UpgradeableLoaderState::size_of_buffer_metadata().saturating_add(offset as usize),
                &bytes,
                invoke_context,
            )?;
        }
        UpgradeableLoaderInstruction::DeployWithMaxDataLen { max_data_len } => {
            if invoke_context
                .get_feature_set()
                .is_active(&disable_new_loader_v3_deployments::id())
            {
                ic_logger_msg!(log_collector, "Unsupported instruction");
                return Err(InstructionError::InvalidInstructionData);
            }

            instruction_context.check_number_of_instruction_accounts(4)?;
            let payer_key = *transaction_context.get_key_of_account_at_index(
                instruction_context.get_index_of_instruction_account_in_transaction(0)?,
            )?;
            let programdata_key = *transaction_context.get_key_of_account_at_index(
                instruction_context.get_index_of_instruction_account_in_transaction(1)?,
            )?;
            let rent = get_sysvar_with_account_check::rent(invoke_context, instruction_context, 4)?;
            let clock =
                get_sysvar_with_account_check::clock(invoke_context, instruction_context, 5)?;
            instruction_context.check_number_of_instruction_accounts(8)?;
            let authority_key = Some(*transaction_context.get_key_of_account_at_index(
                instruction_context.get_index_of_instruction_account_in_transaction(7)?,
            )?);

            // Verify Program account

            let program =
                instruction_context.try_borrow_instruction_account(transaction_context, 2)?;
            if UpgradeableLoaderState::Uninitialized != program.get_state()? {
                ic_logger_msg!(log_collector, "Program account already initialized");
                return Err(InstructionError::AccountAlreadyInitialized);
            }
            if program.get_data().len() < UpgradeableLoaderState::size_of_program() {
                ic_logger_msg!(log_collector, "Program account too small");
                return Err(InstructionError::AccountDataTooSmall);
            }
            if program.get_lamports() < rent.minimum_balance(program.get_data().len()) {
                ic_logger_msg!(log_collector, "Program account not rent-exempt");
                return Err(InstructionError::ExecutableAccountNotRentExempt);
            }
            let new_program_id = *program.get_key();
            drop(program);

            // Verify Buffer account

            let buffer =
                instruction_context.try_borrow_instruction_account(transaction_context, 3)?;
            if let UpgradeableLoaderState::Buffer { authority_address } = buffer.get_state()? {
                if authority_address != authority_key {
                    ic_logger_msg!(log_collector, "Buffer and upgrade authority don't match");
                    return Err(InstructionError::IncorrectAuthority);
                }
                if !instruction_context.is_instruction_account_signer(7)? {
                    ic_logger_msg!(log_collector, "Upgrade authority did not sign");
                    return Err(InstructionError::MissingRequiredSignature);
                }
            } else {
                ic_logger_msg!(log_collector, "Invalid Buffer account");
                return Err(InstructionError::InvalidArgument);
            }
            let buffer_key = *buffer.get_key();
            let buffer_data_offset = UpgradeableLoaderState::size_of_buffer_metadata();
            let buffer_data_len = buffer.get_data().len().saturating_sub(buffer_data_offset);
            let programdata_data_offset = UpgradeableLoaderState::size_of_programdata_metadata();
            let programdata_len = UpgradeableLoaderState::size_of_programdata(max_data_len);
            if buffer.get_data().len() < UpgradeableLoaderState::size_of_buffer_metadata()
                || buffer_data_len == 0
            {
                ic_logger_msg!(log_collector, "Buffer account too small");
                return Err(InstructionError::InvalidAccountData);
            }
            drop(buffer);
            if max_data_len < buffer_data_len {
                ic_logger_msg!(
                    log_collector,
                    "Max data length is too small to hold Buffer data"
                );
                return Err(InstructionError::AccountDataTooSmall);
            }
            if programdata_len > MAX_PERMITTED_DATA_LENGTH as usize {
                ic_logger_msg!(log_collector, "Max data length is too large");
                return Err(InstructionError::InvalidArgument);
            }

            // Create ProgramData account
            let (derived_address, bump_seed) =
                Pubkey::find_program_address(&[new_program_id.as_ref()], program_id);
            if derived_address != programdata_key {
                ic_logger_msg!(log_collector, "ProgramData address is not derived");
                return Err(InstructionError::InvalidArgument);
            }

            // Drain the Buffer account to payer before paying for programdata account
            {
                let mut buffer =
                    instruction_context.try_borrow_instruction_account(transaction_context, 3)?;
                let mut payer =
                    instruction_context.try_borrow_instruction_account(transaction_context, 0)?;
                payer.checked_add_lamports(buffer.get_lamports())?;
                buffer.set_lamports(0)?;
            }

            let owner_id = *program_id;
            let mut instruction = system_instruction::create_account(
                &payer_key,
                &programdata_key,
                1.max(rent.minimum_balance(programdata_len)),
                programdata_len as u64,
                program_id,
            );

            // pass an extra account to avoid the overly strict UnbalancedInstruction error
            instruction
                .accounts
                .push(AccountMeta::new(buffer_key, false));

            let transaction_context = &invoke_context.transaction_context;
            let instruction_context = transaction_context.get_current_instruction_context()?;
            let caller_program_id =
                instruction_context.get_last_program_key(transaction_context)?;
            let signers = [[new_program_id.as_ref(), &[bump_seed]]]
                .iter()
                .map(|seeds| Pubkey::create_program_address(seeds, caller_program_id))
                .collect::<Result<Vec<Pubkey>, solana_pubkey::PubkeyError>>()?;
            invoke_context.native_invoke(instruction.into(), signers.as_slice())?;

            // Load and verify the program bits
            let transaction_context = &invoke_context.transaction_context;
            let instruction_context = transaction_context.get_current_instruction_context()?;
            let buffer =
                instruction_context.try_borrow_instruction_account(transaction_context, 3)?;
            deploy_program!(
                invoke_context,
                &new_program_id,
                &owner_id,
                UpgradeableLoaderState::size_of_program().saturating_add(programdata_len),
                buffer
                    .get_data()
                    .get(buffer_data_offset..)
                    .ok_or(InstructionError::AccountDataTooSmall)?,
                clock.slot,
            );
            drop(buffer);

            let transaction_context = &invoke_context.transaction_context;
            let instruction_context = transaction_context.get_current_instruction_context()?;

            // Update the ProgramData account and record the program bits
            {
                let mut programdata =
                    instruction_context.try_borrow_instruction_account(transaction_context, 1)?;
                programdata.set_state(&UpgradeableLoaderState::ProgramData {
                    slot: clock.slot,
                    upgrade_authority_address: authority_key,
                })?;
                let dst_slice = programdata
                    .get_data_mut()?
                    .get_mut(
                        programdata_data_offset
                            ..programdata_data_offset.saturating_add(buffer_data_len),
                    )
                    .ok_or(InstructionError::AccountDataTooSmall)?;
                let mut buffer =
                    instruction_context.try_borrow_instruction_account(transaction_context, 3)?;
                let src_slice = buffer
                    .get_data()
                    .get(buffer_data_offset..)
                    .ok_or(InstructionError::AccountDataTooSmall)?;
                dst_slice.copy_from_slice(src_slice);
                buffer.set_data_length(UpgradeableLoaderState::size_of_buffer(0))?;
            }

            // Update the Program account
            let mut program =
                instruction_context.try_borrow_instruction_account(transaction_context, 2)?;
            program.set_state(&UpgradeableLoaderState::Program {
                programdata_address: programdata_key,
            })?;
            program.set_executable(true)?;
            drop(program);

            ic_logger_msg!(log_collector, "Deployed program {:?}", new_program_id);
        }
        UpgradeableLoaderInstruction::Upgrade => {
            instruction_context.check_number_of_instruction_accounts(3)?;
            let programdata_key = *transaction_context.get_key_of_account_at_index(
                instruction_context.get_index_of_instruction_account_in_transaction(0)?,
            )?;
            let rent = get_sysvar_with_account_check::rent(invoke_context, instruction_context, 4)?;
            let clock =
                get_sysvar_with_account_check::clock(invoke_context, instruction_context, 5)?;
            instruction_context.check_number_of_instruction_accounts(7)?;
            let authority_key = Some(*transaction_context.get_key_of_account_at_index(
                instruction_context.get_index_of_instruction_account_in_transaction(6)?,
            )?);

            // Verify Program account

            let program =
                instruction_context.try_borrow_instruction_account(transaction_context, 1)?;
            #[allow(deprecated)]
            if !invoke_context
                .get_feature_set()
                .is_active(&remove_accounts_executable_flag_checks::id())
                && !program.is_executable()
            {
                ic_logger_msg!(log_collector, "Program account not executable");
                return Err(InstructionError::AccountNotExecutable);
            }
            if !program.is_writable() {
                ic_logger_msg!(log_collector, "Program account not writeable");
                return Err(InstructionError::InvalidArgument);
            }
            if program.get_owner() != program_id {
                ic_logger_msg!(log_collector, "Program account not owned by loader");
                return Err(InstructionError::IncorrectProgramId);
            }
            if let UpgradeableLoaderState::Program {
                programdata_address,
            } = program.get_state()?
            {
                if programdata_address != programdata_key {
                    ic_logger_msg!(log_collector, "Program and ProgramData account mismatch");
                    return Err(InstructionError::InvalidArgument);
                }
            } else {
                ic_logger_msg!(log_collector, "Invalid Program account");
                return Err(InstructionError::InvalidAccountData);
            }
            let new_program_id = *program.get_key();
            drop(program);

            // Verify Buffer account

            let buffer =
                instruction_context.try_borrow_instruction_account(transaction_context, 2)?;
            if let UpgradeableLoaderState::Buffer { authority_address } = buffer.get_state()? {
                if authority_address != authority_key {
                    ic_logger_msg!(log_collector, "Buffer and upgrade authority don't match");
                    return Err(InstructionError::IncorrectAuthority);
                }
                if !instruction_context.is_instruction_account_signer(6)? {
                    ic_logger_msg!(log_collector, "Upgrade authority did not sign");
                    return Err(InstructionError::MissingRequiredSignature);
                }
            } else {
                ic_logger_msg!(log_collector, "Invalid Buffer account");
                return Err(InstructionError::InvalidArgument);
            }
            let buffer_lamports = buffer.get_lamports();
            let buffer_data_offset = UpgradeableLoaderState::size_of_buffer_metadata();
            let buffer_data_len = buffer.get_data().len().saturating_sub(buffer_data_offset);
            if buffer.get_data().len() < UpgradeableLoaderState::size_of_buffer_metadata()
                || buffer_data_len == 0
            {
                ic_logger_msg!(log_collector, "Buffer account too small");
                return Err(InstructionError::InvalidAccountData);
            }
            drop(buffer);

            // Verify ProgramData account

            let programdata =
                instruction_context.try_borrow_instruction_account(transaction_context, 0)?;
            let programdata_data_offset = UpgradeableLoaderState::size_of_programdata_metadata();
            let programdata_balance_required =
                1.max(rent.minimum_balance(programdata.get_data().len()));
            if programdata.get_data().len()
                < UpgradeableLoaderState::size_of_programdata(buffer_data_len)
            {
                ic_logger_msg!(log_collector, "ProgramData account not large enough");
                return Err(InstructionError::AccountDataTooSmall);
            }
            if programdata.get_lamports().saturating_add(buffer_lamports)
                < programdata_balance_required
            {
                ic_logger_msg!(
                    log_collector,
                    "Buffer account balance too low to fund upgrade"
                );
                return Err(InstructionError::InsufficientFunds);
            }
            if let UpgradeableLoaderState::ProgramData {
                slot,
                upgrade_authority_address,
            } = programdata.get_state()?
            {
                if clock.slot == slot {
                    ic_logger_msg!(log_collector, "Program was deployed in this block already");
                    return Err(InstructionError::InvalidArgument);
                }
                if upgrade_authority_address.is_none() {
                    ic_logger_msg!(log_collector, "Program not upgradeable");
                    return Err(InstructionError::Immutable);
                }
                if upgrade_authority_address != authority_key {
                    ic_logger_msg!(log_collector, "Incorrect upgrade authority provided");
                    return Err(InstructionError::IncorrectAuthority);
                }
                if !instruction_context.is_instruction_account_signer(6)? {
                    ic_logger_msg!(log_collector, "Upgrade authority did not sign");
                    return Err(InstructionError::MissingRequiredSignature);
                }
            } else {
                ic_logger_msg!(log_collector, "Invalid ProgramData account");
                return Err(InstructionError::InvalidAccountData);
            };
            let programdata_len = programdata.get_data().len();
            drop(programdata);

            // Load and verify the program bits
            let buffer =
                instruction_context.try_borrow_instruction_account(transaction_context, 2)?;
            deploy_program!(
                invoke_context,
                &new_program_id,
                program_id,
                UpgradeableLoaderState::size_of_program().saturating_add(programdata_len),
                buffer
                    .get_data()
                    .get(buffer_data_offset..)
                    .ok_or(InstructionError::AccountDataTooSmall)?,
                clock.slot,
            );
            drop(buffer);

            let transaction_context = &invoke_context.transaction_context;
            let instruction_context = transaction_context.get_current_instruction_context()?;

            // Update the ProgramData account, record the upgraded data, and zero
            // the rest
            let mut programdata =
                instruction_context.try_borrow_instruction_account(transaction_context, 0)?;
            {
                programdata.set_state(&UpgradeableLoaderState::ProgramData {
                    slot: clock.slot,
                    upgrade_authority_address: authority_key,
                })?;
                let dst_slice = programdata
                    .get_data_mut()?
                    .get_mut(
                        programdata_data_offset
                            ..programdata_data_offset.saturating_add(buffer_data_len),
                    )
                    .ok_or(InstructionError::AccountDataTooSmall)?;
                let buffer =
                    instruction_context.try_borrow_instruction_account(transaction_context, 2)?;
                let src_slice = buffer
                    .get_data()
                    .get(buffer_data_offset..)
                    .ok_or(InstructionError::AccountDataTooSmall)?;
                dst_slice.copy_from_slice(src_slice);
            }
            programdata
                .get_data_mut()?
                .get_mut(programdata_data_offset.saturating_add(buffer_data_len)..)
                .ok_or(InstructionError::AccountDataTooSmall)?
                .fill(0);

            // Fund ProgramData to rent-exemption, spill the rest
            let mut buffer =
                instruction_context.try_borrow_instruction_account(transaction_context, 2)?;
            let mut spill =
                instruction_context.try_borrow_instruction_account(transaction_context, 3)?;
            spill.checked_add_lamports(
                programdata
                    .get_lamports()
                    .saturating_add(buffer_lamports)
                    .saturating_sub(programdata_balance_required),
            )?;
            buffer.set_lamports(0)?;
            programdata.set_lamports(programdata_balance_required)?;
            buffer.set_data_length(UpgradeableLoaderState::size_of_buffer(0))?;

            ic_logger_msg!(log_collector, "Upgraded program {:?}", new_program_id);
        }
        UpgradeableLoaderInstruction::SetAuthority => {
            instruction_context.check_number_of_instruction_accounts(2)?;
            let mut account =
                instruction_context.try_borrow_instruction_account(transaction_context, 0)?;
            let present_authority_key = transaction_context.get_key_of_account_at_index(
                instruction_context.get_index_of_instruction_account_in_transaction(1)?,
            )?;
            let new_authority = instruction_context
                .get_index_of_instruction_account_in_transaction(2)
                .and_then(|index_in_transaction| {
                    transaction_context.get_key_of_account_at_index(index_in_transaction)
                })
                .ok();

            match account.get_state()? {
                UpgradeableLoaderState::Buffer { authority_address } => {
                    if new_authority.is_none() {
                        ic_logger_msg!(log_collector, "Buffer authority is not optional");
                        return Err(InstructionError::IncorrectAuthority);
                    }
                    if authority_address.is_none() {
                        ic_logger_msg!(log_collector, "Buffer is immutable");
                        return Err(InstructionError::Immutable);
                    }
                    if authority_address != Some(*present_authority_key) {
                        ic_logger_msg!(log_collector, "Incorrect buffer authority provided");
                        return Err(InstructionError::IncorrectAuthority);
                    }
                    if !instruction_context.is_instruction_account_signer(1)? {
                        ic_logger_msg!(log_collector, "Buffer authority did not sign");
                        return Err(InstructionError::MissingRequiredSignature);
                    }
                    account.set_state(&UpgradeableLoaderState::Buffer {
                        authority_address: new_authority.cloned(),
                    })?;
                }
                UpgradeableLoaderState::ProgramData {
                    slot,
                    upgrade_authority_address,
                } => {
                    if upgrade_authority_address.is_none() {
                        ic_logger_msg!(log_collector, "Program not upgradeable");
                        return Err(InstructionError::Immutable);
                    }
                    if upgrade_authority_address != Some(*present_authority_key) {
                        ic_logger_msg!(log_collector, "Incorrect upgrade authority provided");
                        return Err(InstructionError::IncorrectAuthority);
                    }
                    if !instruction_context.is_instruction_account_signer(1)? {
                        ic_logger_msg!(log_collector, "Upgrade authority did not sign");
                        return Err(InstructionError::MissingRequiredSignature);
                    }
                    account.set_state(&UpgradeableLoaderState::ProgramData {
                        slot,
                        upgrade_authority_address: new_authority.cloned(),
                    })?;
                }
                _ => {
                    ic_logger_msg!(log_collector, "Account does not support authorities");
                    return Err(InstructionError::InvalidArgument);
                }
            }

            ic_logger_msg!(log_collector, "New authority {:?}", new_authority);
        }
        UpgradeableLoaderInstruction::SetAuthorityChecked => {
            if !invoke_context
                .get_feature_set()
                .is_active(&enable_bpf_loader_set_authority_checked_ix::id())
            {
                return Err(InstructionError::InvalidInstructionData);
            }

            instruction_context.check_number_of_instruction_accounts(3)?;
            let mut account =
                instruction_context.try_borrow_instruction_account(transaction_context, 0)?;
            let present_authority_key = transaction_context.get_key_of_account_at_index(
                instruction_context.get_index_of_instruction_account_in_transaction(1)?,
            )?;
            let new_authority_key = transaction_context.get_key_of_account_at_index(
                instruction_context.get_index_of_instruction_account_in_transaction(2)?,
            )?;

            match account.get_state()? {
                UpgradeableLoaderState::Buffer { authority_address } => {
                    if authority_address.is_none() {
                        ic_logger_msg!(log_collector, "Buffer is immutable");
                        return Err(InstructionError::Immutable);
                    }
                    if authority_address != Some(*present_authority_key) {
                        ic_logger_msg!(log_collector, "Incorrect buffer authority provided");
                        return Err(InstructionError::IncorrectAuthority);
                    }
                    if !instruction_context.is_instruction_account_signer(1)? {
                        ic_logger_msg!(log_collector, "Buffer authority did not sign");
                        return Err(InstructionError::MissingRequiredSignature);
                    }
                    if !instruction_context.is_instruction_account_signer(2)? {
                        ic_logger_msg!(log_collector, "New authority did not sign");
                        return Err(InstructionError::MissingRequiredSignature);
                    }
                    account.set_state(&UpgradeableLoaderState::Buffer {
                        authority_address: Some(*new_authority_key),
                    })?;
                }
                UpgradeableLoaderState::ProgramData {
                    slot,
                    upgrade_authority_address,
                } => {
                    if upgrade_authority_address.is_none() {
                        ic_logger_msg!(log_collector, "Program not upgradeable");
                        return Err(InstructionError::Immutable);
                    }
                    if upgrade_authority_address != Some(*present_authority_key) {
                        ic_logger_msg!(log_collector, "Incorrect upgrade authority provided");
                        return Err(InstructionError::IncorrectAuthority);
                    }
                    if !instruction_context.is_instruction_account_signer(1)? {
                        ic_logger_msg!(log_collector, "Upgrade authority did not sign");
                        return Err(InstructionError::MissingRequiredSignature);
                    }
                    if !instruction_context.is_instruction_account_signer(2)? {
                        ic_logger_msg!(log_collector, "New authority did not sign");
                        return Err(InstructionError::MissingRequiredSignature);
                    }
                    account.set_state(&UpgradeableLoaderState::ProgramData {
                        slot,
                        upgrade_authority_address: Some(*new_authority_key),
                    })?;
                }
                _ => {
                    ic_logger_msg!(log_collector, "Account does not support authorities");
                    return Err(InstructionError::InvalidArgument);
                }
            }

            ic_logger_msg!(log_collector, "New authority {:?}", new_authority_key);
        }
        UpgradeableLoaderInstruction::Close => {
            instruction_context.check_number_of_instruction_accounts(2)?;
            if instruction_context.get_index_of_instruction_account_in_transaction(0)?
                == instruction_context.get_index_of_instruction_account_in_transaction(1)?
            {
                ic_logger_msg!(
                    log_collector,
                    "Recipient is the same as the account being closed"
                );
                return Err(InstructionError::InvalidArgument);
            }
            let mut close_account =
                instruction_context.try_borrow_instruction_account(transaction_context, 0)?;
            let close_key = *close_account.get_key();
            let close_account_state = close_account.get_state()?;
            close_account.set_data_length(UpgradeableLoaderState::size_of_uninitialized())?;
            match close_account_state {
                UpgradeableLoaderState::Uninitialized => {
                    let mut recipient_account = instruction_context
                        .try_borrow_instruction_account(transaction_context, 1)?;
                    recipient_account.checked_add_lamports(close_account.get_lamports())?;
                    close_account.set_lamports(0)?;

                    ic_logger_msg!(log_collector, "Closed Uninitialized {}", close_key);
                }
                UpgradeableLoaderState::Buffer { authority_address } => {
                    instruction_context.check_number_of_instruction_accounts(3)?;
                    drop(close_account);
                    common_close_account(
                        &authority_address,
                        transaction_context,
                        instruction_context,
                        &log_collector,
                    )?;

                    ic_logger_msg!(log_collector, "Closed Buffer {}", close_key);
                }
                UpgradeableLoaderState::ProgramData {
                    slot,
                    upgrade_authority_address: authority_address,
                } => {
                    instruction_context.check_number_of_instruction_accounts(4)?;
                    drop(close_account);
                    let program_account = instruction_context
                        .try_borrow_instruction_account(transaction_context, 3)?;
                    let program_key = *program_account.get_key();

                    if !program_account.is_writable() {
                        ic_logger_msg!(log_collector, "Program account is not writable");
                        return Err(InstructionError::InvalidArgument);
                    }
                    if program_account.get_owner() != program_id {
                        ic_logger_msg!(log_collector, "Program account not owned by loader");
                        return Err(InstructionError::IncorrectProgramId);
                    }
                    let clock = invoke_context.get_sysvar_cache().get_clock()?;
                    if clock.slot == slot {
                        ic_logger_msg!(log_collector, "Program was deployed in this block already");
                        return Err(InstructionError::InvalidArgument);
                    }

                    match program_account.get_state()? {
                        UpgradeableLoaderState::Program {
                            programdata_address,
                        } => {
                            if programdata_address != close_key {
                                ic_logger_msg!(
                                    log_collector,
                                    "ProgramData account does not match ProgramData account"
                                );
                                return Err(InstructionError::InvalidArgument);
                            }

                            drop(program_account);
                            common_close_account(
                                &authority_address,
                                transaction_context,
                                instruction_context,
                                &log_collector,
                            )?;
                            let clock = invoke_context.get_sysvar_cache().get_clock()?;
                            invoke_context
                                .program_cache_for_tx_batch
                                .store_modified_entry(
                                    program_key,
                                    Arc::new(ProgramCacheEntry::new_tombstone(
                                        clock.slot,
                                        ProgramCacheEntryOwner::LoaderV3,
                                        ProgramCacheEntryType::Closed,
                                    )),
                                );
                        }
                        _ => {
                            ic_logger_msg!(log_collector, "Invalid Program account");
                            return Err(InstructionError::InvalidArgument);
                        }
                    }

                    ic_logger_msg!(log_collector, "Closed Program {}", program_key);
                }
                _ => {
                    ic_logger_msg!(log_collector, "Account does not support closing");
                    return Err(InstructionError::InvalidArgument);
                }
            }
        }
        UpgradeableLoaderInstruction::ExtendProgram { additional_bytes } => {
            if additional_bytes == 0 {
                ic_logger_msg!(log_collector, "Additional bytes must be greater than 0");
                return Err(InstructionError::InvalidInstructionData);
            }

            const PROGRAM_DATA_ACCOUNT_INDEX: IndexOfAccount = 0;
            const PROGRAM_ACCOUNT_INDEX: IndexOfAccount = 1;
            #[allow(dead_code)]
            // System program is only required when a CPI is performed
            const OPTIONAL_SYSTEM_PROGRAM_ACCOUNT_INDEX: IndexOfAccount = 2;
            const OPTIONAL_PAYER_ACCOUNT_INDEX: IndexOfAccount = 3;

            let programdata_account = instruction_context
                .try_borrow_instruction_account(transaction_context, PROGRAM_DATA_ACCOUNT_INDEX)?;
            let programdata_key = *programdata_account.get_key();

            if program_id != programdata_account.get_owner() {
                ic_logger_msg!(log_collector, "ProgramData owner is invalid");
                return Err(InstructionError::InvalidAccountOwner);
            }
            if !programdata_account.is_writable() {
                ic_logger_msg!(log_collector, "ProgramData is not writable");
                return Err(InstructionError::InvalidArgument);
            }

            let program_account = instruction_context
                .try_borrow_instruction_account(transaction_context, PROGRAM_ACCOUNT_INDEX)?;
            if !program_account.is_writable() {
                ic_logger_msg!(log_collector, "Program account is not writable");
                return Err(InstructionError::InvalidArgument);
            }
            if program_account.get_owner() != program_id {
                ic_logger_msg!(log_collector, "Program account not owned by loader");
                return Err(InstructionError::InvalidAccountOwner);
            }
            let program_key = *program_account.get_key();
            match program_account.get_state()? {
                UpgradeableLoaderState::Program {
                    programdata_address,
                } => {
                    if programdata_address != programdata_key {
                        ic_logger_msg!(
                            log_collector,
                            "Program account does not match ProgramData account"
                        );
                        return Err(InstructionError::InvalidArgument);
                    }
                }
                _ => {
                    ic_logger_msg!(log_collector, "Invalid Program account");
                    return Err(InstructionError::InvalidAccountData);
                }
            }
            drop(program_account);

            let old_len = programdata_account.get_data().len();
            let new_len = old_len.saturating_add(additional_bytes as usize);
            if new_len > MAX_PERMITTED_DATA_LENGTH as usize {
                ic_logger_msg!(
                    log_collector,
                    "Extended ProgramData length of {} bytes exceeds max account data length of {} bytes",
                    new_len,
                    MAX_PERMITTED_DATA_LENGTH
                );
                return Err(InstructionError::InvalidRealloc);
            }

            let clock_slot = invoke_context
                .get_sysvar_cache()
                .get_clock()
                .map(|clock| clock.slot)?;

            let upgrade_authority_address = if let UpgradeableLoaderState::ProgramData {
                slot,
                upgrade_authority_address,
            } = programdata_account.get_state()?
            {
                if clock_slot == slot {
                    ic_logger_msg!(log_collector, "Program was extended in this block already");
                    return Err(InstructionError::InvalidArgument);
                }

                if upgrade_authority_address.is_none() {
                    ic_logger_msg!(
                        log_collector,
                        "Cannot extend ProgramData accounts that are not upgradeable"
                    );
                    return Err(InstructionError::Immutable);
                }
                upgrade_authority_address
            } else {
                ic_logger_msg!(log_collector, "ProgramData state is invalid");
                return Err(InstructionError::InvalidAccountData);
            };

            let required_payment = {
                let balance = programdata_account.get_lamports();
                let rent = invoke_context.get_sysvar_cache().get_rent()?;
                let min_balance = rent.minimum_balance(new_len).max(1);
                min_balance.saturating_sub(balance)
            };

            // Borrowed accounts need to be dropped before native_invoke
            drop(programdata_account);

            // Dereference the program ID to prevent overlapping mutable/immutable borrow of invoke context
            let program_id = *program_id;
            if required_payment > 0 {
                let payer_key = *transaction_context.get_key_of_account_at_index(
                    instruction_context.get_index_of_instruction_account_in_transaction(
                        OPTIONAL_PAYER_ACCOUNT_INDEX,
                    )?,
                )?;

                invoke_context.native_invoke(
                    system_instruction::transfer(&payer_key, &programdata_key, required_payment)
                        .into(),
                    &[],
                )?;
            }

            let transaction_context = &invoke_context.transaction_context;
            let instruction_context = transaction_context.get_current_instruction_context()?;
            let mut programdata_account = instruction_context
                .try_borrow_instruction_account(transaction_context, PROGRAM_DATA_ACCOUNT_INDEX)?;
            programdata_account.set_data_length(new_len)?;

            let programdata_data_offset = UpgradeableLoaderState::size_of_programdata_metadata();

            deploy_program!(
                invoke_context,
                &program_key,
                &program_id,
                UpgradeableLoaderState::size_of_program().saturating_add(new_len),
                programdata_account
                    .get_data()
                    .get(programdata_data_offset..)
                    .ok_or(InstructionError::AccountDataTooSmall)?,
                clock_slot,
            );
            drop(programdata_account);

            let mut programdata_account = instruction_context
                .try_borrow_instruction_account(transaction_context, PROGRAM_DATA_ACCOUNT_INDEX)?;
            programdata_account.set_state(&UpgradeableLoaderState::ProgramData {
                slot: clock_slot,
                upgrade_authority_address,
            })?;

            ic_logger_msg!(
                log_collector,
                "Extended ProgramData account by {} bytes",
                additional_bytes
            );
        }
    }

    Ok(())
}

fn common_close_account(
    authority_address: &Option<Pubkey>,
    transaction_context: &TransactionContext,
    instruction_context: &InstructionContext,
    log_collector: &Option<Rc<RefCell<LogCollector>>>,
) -> Result<(), InstructionError> {
    if authority_address.is_none() {
        ic_logger_msg!(log_collector, "Account is immutable");
        return Err(InstructionError::Immutable);
    }
    if *authority_address
        != Some(*transaction_context.get_key_of_account_at_index(
            instruction_context.get_index_of_instruction_account_in_transaction(2)?,
        )?)
    {
        ic_logger_msg!(log_collector, "Incorrect authority provided");
        return Err(InstructionError::IncorrectAuthority);
    }
    if !instruction_context.is_instruction_account_signer(2)? {
        ic_logger_msg!(log_collector, "Authority did not sign");
        return Err(InstructionError::MissingRequiredSignature);
    }

    let mut close_account =
        instruction_context.try_borrow_instruction_account(transaction_context, 0)?;
    let mut recipient_account =
        instruction_context.try_borrow_instruction_account(transaction_context, 1)?;

    recipient_account.checked_add_lamports(close_account.get_lamports())?;
    close_account.set_lamports(0)?;
    close_account.set_state(&UpgradeableLoaderState::Uninitialized)?;
    Ok(())
}

#[cfg_attr(feature = "svm-internal", qualifiers(pub))]
fn execute<'a, 'b: 'a>(
    executable: &'a Executable<InvokeContext<'static>>,
    invoke_context: &'a mut InvokeContext<'b>,
) -> Result<(), Box<dyn std::error::Error>> {
    // We dropped the lifetime tracking in the Executor by setting it to 'static,
    // thus we need to reintroduce the correct lifetime of InvokeContext here again.
    let executable = unsafe {
        mem::transmute::<&'a Executable<InvokeContext<'static>>, &'a Executable<InvokeContext<'b>>>(
            executable,
        )
    };
    let log_collector = invoke_context.get_log_collector();
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let (program_id, is_loader_deprecated) = {
        let program_account =
            instruction_context.try_borrow_last_program_account(transaction_context)?;
        (
            *program_account.get_key(),
            *program_account.get_owner() == bpf_loader_deprecated::id(),
        )
    };
    #[cfg(any(target_os = "windows", not(target_arch = "x86_64")))]
    let use_jit = false;
    #[cfg(all(not(target_os = "windows"), target_arch = "x86_64"))]
    let use_jit = executable.get_compiled_program().is_some();
    let direct_mapping = invoke_context
        .get_feature_set()
        .is_active(&bpf_account_data_direct_mapping::id());

    let (parameter_bytes, regions, accounts_metadata) = serialization::serialize_parameters(
        invoke_context.transaction_context,
        instruction_context,
        !direct_mapping,
    )?;

    // save the account addresses so in case we hit an AccessViolation error we
    // can map to a more specific error
    let account_region_addrs = accounts_metadata
        .iter()
        .map(|m| {
            let vm_end = m
                .vm_data_addr
                .saturating_add(m.original_data_len as u64)
                .saturating_add(if !is_loader_deprecated {
                    MAX_PERMITTED_DATA_INCREASE as u64
                } else {
                    0
                });
            m.vm_data_addr..vm_end
        })
        .collect::<Vec<_>>();

    let execution_result = {
        let compute_meter_prev = invoke_context.get_remaining();
        create_vm!(vm, executable, regions, accounts_metadata, invoke_context);
        let (mut vm, stack, heap) = match vm {
            Ok(info) => info,
            Err(e) => {
                ic_logger_msg!(log_collector, "Failed to create SBF VM: {}", e);
                return Err(Box::new(InstructionError::ProgramEnvironmentSetupFailure));
            }
        };

        let (compute_units_consumed, result) = vm.execute_program(executable, !use_jit);
        MEMORY_POOL.with_borrow_mut(|memory_pool| {
            memory_pool.put_stack(stack);
            memory_pool.put_heap(heap);
            debug_assert!(memory_pool.stack_len() <= MAX_INSTRUCTION_STACK_DEPTH);
            debug_assert!(memory_pool.heap_len() <= MAX_INSTRUCTION_STACK_DEPTH);
        });
        drop(vm);

        ic_logger_msg!(
            log_collector,
            "Program {} consumed {} of {} compute units",
            &program_id,
            compute_units_consumed,
            compute_meter_prev
        );
        let (_returned_from_program_id, return_data) =
            invoke_context.transaction_context.get_return_data();
        if !return_data.is_empty() {
            stable_log::program_return(&log_collector, &program_id, return_data);
        }
        match result {
            ProgramResult::Ok(status) if status != SUCCESS => {
                let error: InstructionError = status.into();
                Err(Box::new(error) as Box<dyn std::error::Error>)
            }
            ProgramResult::Err(mut error) => {
                if invoke_context
                    .get_feature_set()
                    .is_active(&solana_feature_set::deplete_cu_meter_on_vm_failure::id())
                    && !matches!(error, EbpfError::SyscallError(_))
                {
                    // when an exception is thrown during the execution of a
                    // Basic Block (e.g., a null memory dereference or other
                    // faults), determining the exact number of CUs consumed
                    // up to the point of failure requires additional effort
                    // and is unnecessary since these cases are rare.
                    //
                    // In order to simplify CU tracking, simply consume all
                    // remaining compute units so that the block cost
                    // tracker uses the full requested compute unit cost for
                    // this failed transaction.
                    invoke_context.consume(invoke_context.get_remaining());
                }

                if direct_mapping {
                    if let EbpfError::AccessViolation(
                        AccessType::Store,
                        address,
                        _size,
                        _section_name,
                    ) = error
                    {
                        // If direct_mapping is enabled and a program tries to write to a readonly
                        // region we'll get a memory access violation. Map it to a more specific
                        // error so it's easier for developers to see what happened.
                        if let Some((instruction_account_index, _)) = account_region_addrs
                            .iter()
                            .enumerate()
                            .find(|(_, vm_region)| vm_region.contains(&address))
                        {
                            let transaction_context = &invoke_context.transaction_context;
                            let instruction_context =
                                transaction_context.get_current_instruction_context()?;

                            let account = instruction_context.try_borrow_instruction_account(
                                transaction_context,
                                instruction_account_index as IndexOfAccount,
                            )?;

                            error = EbpfError::SyscallError(Box::new(
                                #[allow(deprecated)]
                                if !invoke_context
                                    .get_feature_set()
                                    .is_active(&remove_accounts_executable_flag_checks::id())
                                    && account.is_executable()
                                {
                                    InstructionError::ExecutableDataModified
                                } else if account.is_writable() {
                                    InstructionError::ExternalAccountDataModified
                                } else {
                                    InstructionError::ReadonlyDataModified
                                },
                            ));
                        }
                    }
                }
                Err(if let EbpfError::SyscallError(err) = error {
                    err
                } else {
                    error.into()
                })
            }
            _ => Ok(()),
        }
    };

    fn deserialize_parameters(
        invoke_context: &mut InvokeContext,
        parameter_bytes: &[u8],
        copy_account_data: bool,
    ) -> Result<(), InstructionError> {
        serialization::deserialize_parameters(
            invoke_context.transaction_context,
            invoke_context
                .transaction_context
                .get_current_instruction_context()?,
            copy_account_data,
            parameter_bytes,
            &invoke_context.get_syscall_context()?.accounts_metadata,
        )
    }

    let execute_or_deserialize_result = execution_result.and_then(|_| {
        deserialize_parameters(invoke_context, parameter_bytes.as_slice(), !direct_mapping)
            .map_err(|error| Box::new(error) as Box<dyn std::error::Error>)
    });

    execute_or_deserialize_result
}

#[cfg_attr(feature = "svm-internal", qualifiers(pub))]
mod test_utils {
    #[cfg(feature = "svm-internal")]
    use {
        super::*, crate::syscalls::create_program_runtime_environment_v1,
        solana_account::ReadableAccount, solana_loader_v4_interface::state::LoaderV4State,
        solana_program_runtime::loaded_programs::DELAY_VISIBILITY_SLOT_OFFSET,
        solana_sdk_ids::loader_v4,
    };

    #[cfg(feature = "svm-internal")]
    fn check_loader_id(id: &Pubkey) -> bool {
        bpf_loader::check_id(id)
            || bpf_loader_deprecated::check_id(id)
            || bpf_loader_upgradeable::check_id(id)
            || loader_v4::check_id(id)
    }

    #[cfg(feature = "svm-internal")]
    #[cfg_attr(feature = "svm-internal", qualifiers(pub))]
    fn load_all_invoked_programs(invoke_context: &mut InvokeContext) {
        let program_runtime_environment = create_program_runtime_environment_v1(
            invoke_context.get_feature_set(),
            invoke_context.get_compute_budget(),
            false, /* deployment */
            false, /* debugging_features */
        );
        let program_runtime_environment = Arc::new(program_runtime_environment.unwrap());
        let num_accounts = invoke_context.transaction_context.get_number_of_accounts();
        for index in 0..num_accounts {
            let account = invoke_context
                .transaction_context
                .get_account_at_index(index)
                .expect("Failed to get the account")
                .borrow();

            let owner = account.owner();
            if check_loader_id(owner) {
                let programdata_data_offset = if loader_v4::check_id(owner) {
                    LoaderV4State::program_data_offset()
                } else {
                    0
                };
                let pubkey = invoke_context
                    .transaction_context
                    .get_key_of_account_at_index(index)
                    .expect("Failed to get account key");

                if let Ok(loaded_program) = load_program_from_bytes(
                    None,
                    account
                        .data()
                        .get(programdata_data_offset.min(account.data().len())..)
                        .unwrap(),
                    owner,
                    account.data().len(),
                    0,
                    program_runtime_environment.clone(),
                    false,
                ) {
                    invoke_context
                        .program_cache_for_tx_batch
                        .set_slot_for_tests(DELAY_VISIBILITY_SLOT_OFFSET);
                    invoke_context
                        .program_cache_for_tx_batch
                        .store_modified_entry(*pubkey, Arc::new(loaded_program));
                }
            }
        }
    }
}
