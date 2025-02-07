#[cfg(feature = "dev-context-only-utils")]
use qualifier_attr::{field_qualifiers, qualifiers};
use {
    crate::{
        account_loader::{
            collect_rent_from_account, load_transaction, validate_fee_payer, AccountLoader,
            CheckedTransactionDetails, LoadedTransaction, TransactionCheckResult,
            TransactionLoadResult, ValidatedTransactionDetails,
        },
        account_overrides::AccountOverrides,
        message_processor::process_message,
        nonce_info::NonceInfo,
        program_loader::{get_program_modification_slot, load_program_with_pubkey},
        rollback_accounts::RollbackAccounts,
        transaction_account_state_info::TransactionAccountStateInfo,
        transaction_error_metrics::TransactionErrorMetrics,
        transaction_execution_result::{ExecutedTransaction, TransactionExecutionDetails},
        transaction_processing_callback::TransactionProcessingCallback,
        transaction_processing_result::{ProcessedTransaction, TransactionProcessingResult},
    },
    log::debug,
    percentage::Percentage,
    solana_account::{state_traits::StateMut, AccountSharedData, ReadableAccount, PROGRAM_OWNERS},
    solana_bpf_loader_program::syscalls::{
        create_program_runtime_environment_v1, create_program_runtime_environment_v2,
    },
    solana_clock::{Epoch, Slot},
    solana_compute_budget::compute_budget::ComputeBudget,
    solana_compute_budget_instruction::instructions_processor::process_compute_budget_instructions,
    solana_feature_set::{
        enable_transaction_loading_failure_fees, remove_accounts_executable_flag_checks, FeatureSet,
    },
    solana_fee_structure::{FeeBudgetLimits, FeeDetails, FeeStructure},
    solana_hash::Hash,
    solana_instruction::TRANSACTION_LEVEL_STACK_HEIGHT,
    solana_log_collector::LogCollector,
    solana_measure::{measure::Measure, measure_us},
    solana_message::compiled_instruction::CompiledInstruction,
    solana_nonce::{
        state::{DurableNonce, State as NonceState},
        versions::Versions as NonceVersions,
    },
    solana_program_runtime::{
        invoke_context::{EnvironmentConfig, InvokeContext},
        loaded_programs::{
            ForkGraph, ProgramCache, ProgramCacheEntry, ProgramCacheForTxBatch,
            ProgramCacheMatchCriteria, ProgramRuntimeEnvironment,
        },
        solana_sbpf::{program::BuiltinProgram, vm::Config as VmConfig},
        sysvar_cache::SysvarCache,
    },
    solana_pubkey::Pubkey,
    solana_sdk::{
        inner_instruction::{InnerInstruction, InnerInstructionsList},
        rent_collector::RentCollector,
    },
    solana_sdk_ids::{native_loader, system_program},
    solana_svm_rent_collector::svm_rent_collector::SVMRentCollector,
    solana_svm_transaction::{svm_message::SVMMessage, svm_transaction::SVMTransaction},
    solana_timings::{ExecuteTimingType, ExecuteTimings},
    solana_transaction_context::{ExecutionRecord, TransactionContext},
    solana_transaction_error::{TransactionError, TransactionResult},
    solana_type_overrides::sync::{atomic::Ordering, Arc, RwLock, RwLockReadGuard},
    std::{
        collections::{hash_map::Entry, HashMap, HashSet},
        fmt::{Debug, Formatter},
        rc::Rc,
        sync::Weak,
    },
};

/// A list of log messages emitted during a transaction
pub type TransactionLogMessages = Vec<String>;

/// The output of the transaction batch processor's
/// `load_and_execute_sanitized_transactions` method.
pub struct LoadAndExecuteSanitizedTransactionsOutput {
    /// Error metrics for transactions that were processed.
    pub error_metrics: TransactionErrorMetrics,
    /// Timings for transaction batch execution.
    pub execute_timings: ExecuteTimings,
    /// Vector of results indicating whether a transaction was processed or
    /// could not be processed. Note processed transactions can still have a
    /// failure result meaning that the transaction will be rolled back.
    pub processing_results: Vec<TransactionProcessingResult>,
}

/// Configuration of the recording capabilities for transaction execution
#[derive(Copy, Clone, Default)]
pub struct ExecutionRecordingConfig {
    pub enable_cpi_recording: bool,
    pub enable_log_recording: bool,
    pub enable_return_data_recording: bool,
}

impl ExecutionRecordingConfig {
    pub fn new_single_setting(option: bool) -> Self {
        ExecutionRecordingConfig {
            enable_return_data_recording: option,
            enable_log_recording: option,
            enable_cpi_recording: option,
        }
    }
}

/// Configurations for processing transactions.
#[derive(Default)]
pub struct TransactionProcessingConfig<'a> {
    /// Encapsulates overridden accounts, typically used for transaction
    /// simulation.
    pub account_overrides: Option<&'a AccountOverrides>,
    /// Whether or not to check a program's modification slot when replenishing
    /// a program cache instance.
    pub check_program_modification_slot: bool,
    /// The compute budget to use for transaction execution.
    pub compute_budget: Option<ComputeBudget>,
    /// The maximum number of bytes that log messages can consume.
    pub log_messages_bytes_limit: Option<usize>,
    /// Whether to limit the number of programs loaded for the transaction
    /// batch.
    pub limit_to_load_programs: bool,
    /// Recording capabilities for transaction execution.
    pub recording_config: ExecutionRecordingConfig,
    /// The max number of accounts that a transaction may lock.
    pub transaction_account_lock_limit: Option<usize>,
}

/// Runtime environment for transaction batch processing.
pub struct TransactionProcessingEnvironment<'a> {
    /// The blockhash to use for the transaction batch.
    pub blockhash: Hash,
    /// Lamports per signature that corresponds to this blockhash.
    ///
    /// Note: This value is primarily used for nonce accounts. If set to zero,
    /// it will disable transaction fees. However, any non-zero value will not
    /// change transaction fees. For this reason, it is recommended to use the
    /// `fee_per_signature` field to adjust transaction fees.
    pub blockhash_lamports_per_signature: u64,
    /// The total stake for the current epoch.
    pub epoch_total_stake: u64,
    /// Runtime feature set to use for the transaction batch.
    pub feature_set: Arc<FeatureSet>,
    /// Transaction fee to charge per signature, in lamports.
    pub fee_lamports_per_signature: u64,
    /// Rent collector to use for the transaction batch.
    pub rent_collector: Option<&'a dyn SVMRentCollector>,
}

impl Default for TransactionProcessingEnvironment<'_> {
    fn default() -> Self {
        Self {
            blockhash: Hash::default(),
            blockhash_lamports_per_signature: 0,
            epoch_total_stake: 0,
            feature_set: Arc::<FeatureSet>::default(),
            fee_lamports_per_signature: FeeStructure::default().lamports_per_signature, // <-- Default fee.
            rent_collector: None,
        }
    }
}

#[cfg_attr(feature = "frozen-abi", derive(AbiExample))]
#[cfg_attr(
    feature = "dev-context-only-utils",
    field_qualifiers(slot(pub), epoch(pub))
)]
pub struct TransactionBatchProcessor<FG: ForkGraph> {
    /// Bank slot (i.e. block)
    slot: Slot,

    /// Bank epoch
    epoch: Epoch,

    /// SysvarCache is a collection of system variables that are
    /// accessible from on chain programs. It is passed to SVM from
    /// client code (e.g. Bank) and forwarded to process_message.
    sysvar_cache: RwLock<SysvarCache>,

    /// Programs required for transaction batch processing
    pub program_cache: Arc<RwLock<ProgramCache<FG>>>,

    /// Builtin program ids
    pub builtin_program_ids: RwLock<HashSet<Pubkey>>,
}

impl<FG: ForkGraph> Debug for TransactionBatchProcessor<FG> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransactionBatchProcessor")
            .field("slot", &self.slot)
            .field("epoch", &self.epoch)
            .field("sysvar_cache", &self.sysvar_cache)
            .field("program_cache", &self.program_cache)
            .finish()
    }
}

impl<FG: ForkGraph> Default for TransactionBatchProcessor<FG> {
    fn default() -> Self {
        Self {
            slot: Slot::default(),
            epoch: Epoch::default(),
            sysvar_cache: RwLock::<SysvarCache>::default(),
            program_cache: Arc::new(RwLock::new(ProgramCache::new(
                Slot::default(),
                Epoch::default(),
            ))),
            builtin_program_ids: RwLock::new(HashSet::new()),
        }
    }
}

impl<FG: ForkGraph> TransactionBatchProcessor<FG> {
    /// Create a new, uninitialized `TransactionBatchProcessor`.
    ///
    /// In this context, uninitialized means that the `TransactionBatchProcessor`
    /// has been initialized with an empty program cache. The cache contains no
    /// programs (including builtins) and has not been configured with a valid
    /// fork graph.
    ///
    /// When using this method, it's advisable to call `set_fork_graph_in_program_cache`
    /// as well as `add_builtin` to configure the cache before using the processor.
    pub fn new_uninitialized(slot: Slot, epoch: Epoch) -> Self {
        Self {
            slot,
            epoch,
            program_cache: Arc::new(RwLock::new(ProgramCache::new(slot, epoch))),
            ..Self::default()
        }
    }

    /// Create a new `TransactionBatchProcessor`.
    ///
    /// The created processor's program cache is initialized with the provided
    /// fork graph and loaders. If any loaders are omitted, a default "empty"
    /// loader (no syscalls) will be used.
    ///
    /// The cache will still not contain any builtin programs. It's advisable to
    /// call `add_builtin` to add the required builtins before using the processor.
    pub fn new(
        slot: Slot,
        epoch: Epoch,
        fork_graph: Weak<RwLock<FG>>,
        program_runtime_environment_v1: Option<ProgramRuntimeEnvironment>,
        program_runtime_environment_v2: Option<ProgramRuntimeEnvironment>,
    ) -> Self {
        let processor = Self::new_uninitialized(slot, epoch);
        {
            let mut program_cache = processor.program_cache.write().unwrap();
            program_cache.set_fork_graph(fork_graph);
            processor.configure_program_runtime_environments_inner(
                &mut program_cache,
                program_runtime_environment_v1,
                program_runtime_environment_v2,
            );
        }
        processor
    }

    /// Create a new `TransactionBatchProcessor` from the current instance, but
    /// with the provided slot and epoch.
    ///
    /// * Inherits the program cache and builtin program ids from the current
    ///   instance.
    /// * Resets the sysvar cache.
    pub fn new_from(&self, slot: Slot, epoch: Epoch) -> Self {
        Self {
            slot,
            epoch,
            sysvar_cache: RwLock::<SysvarCache>::default(),
            program_cache: self.program_cache.clone(),
            builtin_program_ids: RwLock::new(self.builtin_program_ids.read().unwrap().clone()),
        }
    }

    fn configure_program_runtime_environments_inner(
        &self,
        program_cache: &mut ProgramCache<FG>,
        program_runtime_environment_v1: Option<ProgramRuntimeEnvironment>,
        program_runtime_environment_v2: Option<ProgramRuntimeEnvironment>,
    ) {
        let empty_loader = || Arc::new(BuiltinProgram::new_loader(VmConfig::default()));

        program_cache.latest_root_slot = self.slot;
        program_cache.latest_root_epoch = self.epoch;
        program_cache.environments.program_runtime_v1 =
            program_runtime_environment_v1.unwrap_or(empty_loader());
        program_cache.environments.program_runtime_v2 =
            program_runtime_environment_v2.unwrap_or(empty_loader());
    }

    /// Configures the program runtime environments (loaders) in the
    /// transaction processor's program cache.
    pub fn configure_program_runtime_environments(
        &self,
        program_runtime_environment_v1: Option<ProgramRuntimeEnvironment>,
        program_runtime_environment_v2: Option<ProgramRuntimeEnvironment>,
    ) {
        self.configure_program_runtime_environments_inner(
            &mut self.program_cache.write().unwrap(),
            program_runtime_environment_v1,
            program_runtime_environment_v2,
        );
    }

    /// Returns the current environments depending on the given epoch
    /// Returns None if the call could result in a deadlock
    #[cfg(feature = "dev-context-only-utils")]
    pub fn get_environments_for_epoch(
        &self,
        epoch: Epoch,
    ) -> Option<solana_program_runtime::loaded_programs::ProgramRuntimeEnvironments> {
        self.program_cache
            .try_read()
            .ok()
            .map(|cache| cache.get_environments_for_epoch(epoch))
    }

    pub fn sysvar_cache(&self) -> RwLockReadGuard<SysvarCache> {
        self.sysvar_cache.read().unwrap()
    }

    /// Main entrypoint to the SVM.
    pub fn load_and_execute_sanitized_transactions<CB: TransactionProcessingCallback>(
        &self,
        callbacks: &CB,
        sanitized_txs: &[impl SVMTransaction],
        check_results: Vec<TransactionCheckResult>,
        environment: &TransactionProcessingEnvironment,
        config: &TransactionProcessingConfig,
    ) -> LoadAndExecuteSanitizedTransactionsOutput {
        // If `check_results` does not have the same length as `sanitized_txs`,
        // transactions could be truncated as a result of `.iter().zip()` in
        // many of the below methods.
        // See <https://doc.rust-lang.org/std/iter/trait.Iterator.html#method.zip>.
        debug_assert_eq!(
            sanitized_txs.len(),
            check_results.len(),
            "Length of check_results does not match length of sanitized_txs"
        );

        // Initialize metrics.
        let mut error_metrics = TransactionErrorMetrics::default();
        let mut execute_timings = ExecuteTimings::default();
        let mut processing_results = Vec::with_capacity(sanitized_txs.len());

        let native_loader = native_loader::id();
        let (program_accounts_map, filter_executable_us) = measure_us!({
            let mut program_accounts_map = Self::filter_executable_program_accounts(
                callbacks,
                sanitized_txs,
                &check_results,
                PROGRAM_OWNERS,
            );
            for builtin_program in self.builtin_program_ids.read().unwrap().iter() {
                program_accounts_map.insert(*builtin_program, (&native_loader, 0));
            }
            program_accounts_map
        });

        let (mut program_cache_for_tx_batch, program_cache_us) = measure_us!({
            let program_cache_for_tx_batch = self.replenish_program_cache(
                callbacks,
                &program_accounts_map,
                &mut execute_timings,
                config.check_program_modification_slot,
                config.limit_to_load_programs,
            );

            if program_cache_for_tx_batch.hit_max_limit {
                return LoadAndExecuteSanitizedTransactionsOutput {
                    error_metrics,
                    execute_timings,
                    processing_results: (0..sanitized_txs.len())
                        .map(|_| Err(TransactionError::ProgramCacheHitMaxLimit))
                        .collect(),
                };
            }

            program_cache_for_tx_batch
        });

        // Determine a capacity for the internal account cache. This
        // over-allocates but avoids ever reallocating, and spares us from
        // deduplicating the account keys lists.
        let account_keys_in_batch = sanitized_txs.iter().map(|tx| tx.account_keys().len()).sum();

        // Create the account loader, which wraps all external account fetching.
        let mut account_loader = AccountLoader::new_with_account_cache_capacity(
            config.account_overrides,
            callbacks,
            environment.feature_set.clone(),
            account_keys_in_batch,
        );

        let enable_transaction_loading_failure_fees = environment
            .feature_set
            .is_active(&enable_transaction_loading_failure_fees::id());

        let (mut validate_fees_us, mut load_us, mut execution_us): (u64, u64, u64) = (0, 0, 0);

        // Validate, execute, and collect results from each transaction in order.
        // With SIMD83, transactions must be executed in order, because transactions
        // in the same batch may modify the same accounts. Transaction order is
        // preserved within entries written to the ledger.
        for (tx, check_result) in sanitized_txs.iter().zip(check_results) {
            let (validate_result, single_validate_fees_us) =
                measure_us!(check_result.and_then(|tx_details| {
                    Self::validate_transaction_nonce_and_fee_payer(
                        &mut account_loader,
                        tx,
                        tx_details,
                        &environment.blockhash,
                        environment.fee_lamports_per_signature,
                        environment
                            .rent_collector
                            .unwrap_or(&RentCollector::default()),
                        &mut error_metrics,
                        callbacks,
                    )
                }));
            validate_fees_us = validate_fees_us.saturating_add(single_validate_fees_us);

            let (load_result, single_load_us) = measure_us!(load_transaction(
                &mut account_loader,
                tx,
                validate_result,
                &mut error_metrics,
                environment
                    .rent_collector
                    .unwrap_or(&RentCollector::default()),
            ));
            load_us = load_us.saturating_add(single_load_us);

            let (processing_result, single_execution_us) = measure_us!(match load_result {
                TransactionLoadResult::NotLoaded(err) => Err(err),
                TransactionLoadResult::FeesOnly(fees_only_tx) => {
                    if enable_transaction_loading_failure_fees {
                        // Update loaded accounts cache with nonce and fee-payer
                        account_loader
                            .update_accounts_for_failed_tx(tx, &fees_only_tx.rollback_accounts);

                        Ok(ProcessedTransaction::FeesOnly(Box::new(fees_only_tx)))
                    } else {
                        Err(fees_only_tx.load_error)
                    }
                }
                TransactionLoadResult::Loaded(loaded_transaction) => {
                    let executed_tx = self.execute_loaded_transaction(
                        callbacks,
                        tx,
                        loaded_transaction,
                        &mut execute_timings,
                        &mut error_metrics,
                        &mut program_cache_for_tx_batch,
                        environment,
                        config,
                    );

                    // Update loaded accounts cache with account states which might have changed.
                    // Also update local program cache with modifications made by the transaction,
                    // if it executed successfully.
                    account_loader.update_accounts_for_executed_tx(tx, &executed_tx);
                    if executed_tx.was_successful() {
                        program_cache_for_tx_batch.merge(&executed_tx.programs_modified_by_tx);
                    }

                    Ok(ProcessedTransaction::Executed(Box::new(executed_tx)))
                }
            });
            execution_us = execution_us.saturating_add(single_execution_us);

            processing_results.push(processing_result);
        }

        // Skip eviction when there's no chance this particular tx batch has increased the size of
        // ProgramCache entries. Note that loaded_missing is deliberately defined, so that there's
        // still at least one other batch, which will evict the program cache, even after the
        // occurrences of cooperative loading.
        if program_cache_for_tx_batch.loaded_missing || program_cache_for_tx_batch.merged_modified {
            const SHRINK_LOADED_PROGRAMS_TO_PERCENTAGE: u8 = 90;
            self.program_cache
                .write()
                .unwrap()
                .evict_using_2s_random_selection(
                    Percentage::from(SHRINK_LOADED_PROGRAMS_TO_PERCENTAGE),
                    self.slot,
                );
        }

        debug!(
            "load: {}us execute: {}us txs_len={}",
            load_us,
            execution_us,
            sanitized_txs.len(),
        );

        execute_timings
            .saturating_add_in_place(ExecuteTimingType::ValidateFeesUs, validate_fees_us);
        execute_timings
            .saturating_add_in_place(ExecuteTimingType::FilterExecutableUs, filter_executable_us);
        execute_timings
            .saturating_add_in_place(ExecuteTimingType::ProgramCacheUs, program_cache_us);
        execute_timings.saturating_add_in_place(ExecuteTimingType::LoadUs, load_us);
        execute_timings.saturating_add_in_place(ExecuteTimingType::ExecuteUs, execution_us);

        LoadAndExecuteSanitizedTransactionsOutput {
            error_metrics,
            execute_timings,
            processing_results,
        }
    }

    fn validate_transaction_nonce_and_fee_payer<CB: TransactionProcessingCallback>(
        account_loader: &mut AccountLoader<CB>,
        message: &impl SVMMessage,
        checked_details: CheckedTransactionDetails,
        environment_blockhash: &Hash,
        fee_lamports_per_signature: u64,
        rent_collector: &dyn SVMRentCollector,
        error_counters: &mut TransactionErrorMetrics,
        callbacks: &CB,
    ) -> TransactionResult<ValidatedTransactionDetails> {
        // If this is a nonce transaction, validate the nonce info.
        // This must be done for every transaction to support SIMD83 because
        // it may have changed due to use, authorization, or deallocation.
        // This function is a successful no-op if given a blockhash transaction.
        if let CheckedTransactionDetails {
            nonce: Some(ref nonce_info),
            lamports_per_signature: _,
        } = checked_details
        {
            let next_durable_nonce = DurableNonce::from_blockhash(environment_blockhash);
            Self::validate_transaction_nonce(
                account_loader,
                message,
                nonce_info,
                &next_durable_nonce,
                error_counters,
            )?;
        }

        // Now validate the fee-payer for the transaction unconditionally.
        Self::validate_transaction_fee_payer(
            account_loader,
            message,
            checked_details,
            fee_lamports_per_signature,
            rent_collector,
            error_counters,
            callbacks,
        )
    }

    // Loads transaction fee payer, collects rent if necessary, then calculates
    // transaction fees, and deducts them from the fee payer balance. If the
    // account is not found or has insufficient funds, an error is returned.
    fn validate_transaction_fee_payer<CB: TransactionProcessingCallback>(
        account_loader: &mut AccountLoader<CB>,
        message: &impl SVMMessage,
        checked_details: CheckedTransactionDetails,
        fee_lamports_per_signature: u64,
        rent_collector: &dyn SVMRentCollector,
        error_counters: &mut TransactionErrorMetrics,
        callbacks: &CB,
    ) -> TransactionResult<ValidatedTransactionDetails> {
        let compute_budget_limits = process_compute_budget_instructions(
            message.program_instructions_iter(),
            &account_loader.feature_set,
        )
        .inspect_err(|_err| {
            error_counters.invalid_compute_budget += 1;
        })?;

        let fee_payer_address = message.fee_payer();

        let Some(mut loaded_fee_payer) = account_loader.load_account(fee_payer_address, true)
        else {
            error_counters.account_not_found += 1;
            return Err(TransactionError::AccountNotFound);
        };

        let fee_payer_loaded_rent_epoch = loaded_fee_payer.account.rent_epoch();
        loaded_fee_payer.rent_collected = collect_rent_from_account(
            &account_loader.feature_set,
            rent_collector,
            fee_payer_address,
            &mut loaded_fee_payer.account,
        )
        .rent_amount;

        let CheckedTransactionDetails {
            nonce,
            lamports_per_signature,
        } = checked_details;

        let fee_budget_limits = FeeBudgetLimits::from(compute_budget_limits);
        let fee_details = if lamports_per_signature == 0 {
            FeeDetails::default()
        } else {
            callbacks.calculate_fee(
                message,
                fee_lamports_per_signature,
                fee_budget_limits.prioritization_fee,
                account_loader.feature_set.as_ref(),
            )
        };

        let fee_payer_index = 0;
        validate_fee_payer(
            fee_payer_address,
            &mut loaded_fee_payer.account,
            fee_payer_index,
            error_counters,
            rent_collector,
            fee_details.total_fee(),
        )?;

        // Capture fee-subtracted fee payer account and next nonce account state
        // to commit if transaction execution fails.
        let rollback_accounts = RollbackAccounts::new(
            nonce,
            *fee_payer_address,
            loaded_fee_payer.account.clone(),
            loaded_fee_payer.rent_collected,
            fee_payer_loaded_rent_epoch,
        );

        Ok(ValidatedTransactionDetails {
            fee_details,
            rollback_accounts,
            compute_budget_limits,
            loaded_fee_payer_account: loaded_fee_payer,
        })
    }

    fn validate_transaction_nonce<CB: TransactionProcessingCallback>(
        account_loader: &mut AccountLoader<CB>,
        message: &impl SVMMessage,
        nonce_info: &NonceInfo,
        next_durable_nonce: &DurableNonce,
        error_counters: &mut TransactionErrorMetrics,
    ) -> TransactionResult<()> {
        // When SIMD83 is enabled, if the nonce has been used in this batch already, we must drop
        // the transaction. This is the same as if it was used in different batches in the same slot.
        // If the nonce account was closed in the batch, we error as if the blockhash didn't validate.
        // We must validate the account in case it was reopened, either as a normal system account,
        // or a fake nonce account. We must also check the signer in case the authority was changed.
        //
        // Note these checks are *not* obviated by fee-only transactions.
        let nonce_is_valid = account_loader
            .load_account(nonce_info.address(), true)
            .and_then(|loaded_nonce| {
                let current_nonce_account = &loaded_nonce.account;
                system_program::check_id(current_nonce_account.owner()).then_some(())?;
                StateMut::<NonceVersions>::state(current_nonce_account).ok()
            })
            .and_then(
                |current_nonce_versions| match current_nonce_versions.state() {
                    NonceState::Initialized(ref current_nonce_data) => {
                        let nonce_can_be_advanced =
                            &current_nonce_data.durable_nonce != next_durable_nonce;

                        let nonce_authority_is_valid = message
                            .account_keys()
                            .iter()
                            .enumerate()
                            .any(|(i, address)| {
                                address == &current_nonce_data.authority && message.is_signer(i)
                            });

                        if nonce_authority_is_valid {
                            Some(nonce_can_be_advanced)
                        } else {
                            None
                        }
                    }
                    _ => None,
                },
            );

        match nonce_is_valid {
            None => {
                error_counters.blockhash_not_found += 1;
                Err(TransactionError::BlockhashNotFound)
            }
            Some(false) => {
                error_counters.account_not_found += 1;
                Err(TransactionError::AccountNotFound)
            }
            Some(true) => Ok(()),
        }
    }

    /// Returns a map from executable program accounts (all accounts owned by any loader)
    /// to their usage counters, for the transactions with a valid blockhash or nonce.
    fn filter_executable_program_accounts<'a, CB: TransactionProcessingCallback>(
        callbacks: &CB,
        txs: &[impl SVMMessage],
        check_results: &[TransactionCheckResult],
        program_owners: &'a [Pubkey],
    ) -> HashMap<Pubkey, (&'a Pubkey, u64)> {
        let mut result: HashMap<Pubkey, (&'a Pubkey, u64)> = HashMap::new();
        check_results.iter().zip(txs).for_each(|etx| {
            if let (Ok(_), tx) = etx {
                tx.account_keys()
                    .iter()
                    .for_each(|key| match result.entry(*key) {
                        Entry::Occupied(mut entry) => {
                            let (_, count) = entry.get_mut();
                            *count = count.saturating_add(1);
                        }
                        Entry::Vacant(entry) => {
                            if let Some(index) =
                                callbacks.account_matches_owners(key, program_owners)
                            {
                                if let Some(owner) = program_owners.get(index) {
                                    entry.insert((owner, 1));
                                }
                            }
                        }
                    });
            }
        });
        result
    }

    #[cfg_attr(feature = "dev-context-only-utils", qualifiers(pub))]
    fn replenish_program_cache<CB: TransactionProcessingCallback>(
        &self,
        callback: &CB,
        program_accounts_map: &HashMap<Pubkey, (&Pubkey, u64)>,
        execute_timings: &mut ExecuteTimings,
        check_program_modification_slot: bool,
        limit_to_load_programs: bool,
    ) -> ProgramCacheForTxBatch {
        let mut missing_programs: Vec<(Pubkey, (ProgramCacheMatchCriteria, u64))> =
            program_accounts_map
                .iter()
                .map(|(pubkey, (_, count))| {
                    let match_criteria = if check_program_modification_slot {
                        get_program_modification_slot(callback, pubkey)
                            .map_or(ProgramCacheMatchCriteria::Tombstone, |slot| {
                                ProgramCacheMatchCriteria::DeployedOnOrAfterSlot(slot)
                            })
                    } else {
                        ProgramCacheMatchCriteria::NoCriteria
                    };
                    (*pubkey, (match_criteria, *count))
                })
                .collect();

        let mut loaded_programs_for_txs: Option<ProgramCacheForTxBatch> = None;
        loop {
            let (program_to_store, task_cookie, task_waiter) = {
                // Lock the global cache.
                let program_cache = self.program_cache.read().unwrap();
                // Initialize our local cache.
                let is_first_round = loaded_programs_for_txs.is_none();
                if is_first_round {
                    loaded_programs_for_txs = Some(ProgramCacheForTxBatch::new_from_cache(
                        self.slot,
                        self.epoch,
                        &program_cache,
                    ));
                }
                // Figure out which program needs to be loaded next.
                let program_to_load = program_cache.extract(
                    &mut missing_programs,
                    loaded_programs_for_txs.as_mut().unwrap(),
                    is_first_round,
                );

                let program_to_store = program_to_load.map(|(key, count)| {
                    // Load, verify and compile one program.
                    let program = load_program_with_pubkey(
                        callback,
                        &program_cache.get_environments_for_epoch(self.epoch),
                        &key,
                        self.slot,
                        execute_timings,
                        false,
                    )
                    .expect("called load_program_with_pubkey() with nonexistent account");
                    program.tx_usage_counter.store(count, Ordering::Relaxed);
                    (key, program)
                });

                let task_waiter = Arc::clone(&program_cache.loading_task_waiter);
                (program_to_store, task_waiter.cookie(), task_waiter)
                // Unlock the global cache again.
            };

            if let Some((key, program)) = program_to_store {
                loaded_programs_for_txs.as_mut().unwrap().loaded_missing = true;
                let mut program_cache = self.program_cache.write().unwrap();
                // Submit our last completed loading task.
                if program_cache.finish_cooperative_loading_task(self.slot, key, program)
                    && limit_to_load_programs
                {
                    // This branch is taken when there is an error in assigning a program to a
                    // cache slot. It is not possible to mock this error for SVM unit
                    // tests purposes.
                    let mut ret = ProgramCacheForTxBatch::new_from_cache(
                        self.slot,
                        self.epoch,
                        &program_cache,
                    );
                    ret.hit_max_limit = true;
                    return ret;
                }
            } else if missing_programs.is_empty() {
                break;
            } else {
                // Sleep until the next finish_cooperative_loading_task() call.
                // Once a task completes we'll wake up and try to load the
                // missing programs inside the tx batch again.
                let _new_cookie = task_waiter.wait(task_cookie);
            }
        }

        loaded_programs_for_txs.unwrap()
    }

    pub fn prepare_program_cache_for_upcoming_feature_set<CB: TransactionProcessingCallback>(
        &self,
        callbacks: &CB,
        upcoming_feature_set: &FeatureSet,
        compute_budget: &ComputeBudget,
        slot_index: u64,
        slots_in_epoch: u64,
    ) {
        // Recompile loaded programs one at a time before the next epoch hits
        let slots_in_recompilation_phase =
            (solana_program_runtime::loaded_programs::MAX_LOADED_ENTRY_COUNT as u64)
                .min(slots_in_epoch)
                .checked_div(2)
                .unwrap();
        let mut program_cache = self.program_cache.write().unwrap();
        if program_cache.upcoming_environments.is_some() {
            if let Some((key, program_to_recompile)) = program_cache.programs_to_recompile.pop() {
                let effective_epoch = program_cache.latest_root_epoch.saturating_add(1);
                drop(program_cache);
                let environments_for_epoch = self
                    .program_cache
                    .read()
                    .unwrap()
                    .get_environments_for_epoch(effective_epoch);
                if let Some(recompiled) = load_program_with_pubkey(
                    callbacks,
                    &environments_for_epoch,
                    &key,
                    self.slot,
                    &mut ExecuteTimings::default(),
                    false,
                ) {
                    recompiled.tx_usage_counter.fetch_add(
                        program_to_recompile
                            .tx_usage_counter
                            .load(Ordering::Relaxed),
                        Ordering::Relaxed,
                    );
                    recompiled.ix_usage_counter.fetch_add(
                        program_to_recompile
                            .ix_usage_counter
                            .load(Ordering::Relaxed),
                        Ordering::Relaxed,
                    );
                    let mut program_cache = self.program_cache.write().unwrap();
                    program_cache.assign_program(key, recompiled);
                }
            }
        } else if self.epoch != program_cache.latest_root_epoch
            || slot_index.saturating_add(slots_in_recompilation_phase) >= slots_in_epoch
        {
            // Anticipate the upcoming program runtime environment for the next epoch,
            // so we can try to recompile loaded programs before the feature transition hits.
            drop(program_cache);
            let mut program_cache = self.program_cache.write().unwrap();
            let program_runtime_environment_v1 = create_program_runtime_environment_v1(
                upcoming_feature_set,
                compute_budget,
                false, /* deployment */
                false, /* debugging_features */
            )
            .unwrap();
            let program_runtime_environment_v2 = create_program_runtime_environment_v2(
                compute_budget,
                false, /* debugging_features */
            );
            let mut upcoming_environments = program_cache.environments.clone();
            let changed_program_runtime_v1 =
                *upcoming_environments.program_runtime_v1 != program_runtime_environment_v1;
            let changed_program_runtime_v2 =
                *upcoming_environments.program_runtime_v2 != program_runtime_environment_v2;
            if changed_program_runtime_v1 {
                upcoming_environments.program_runtime_v1 = Arc::new(program_runtime_environment_v1);
            }
            if changed_program_runtime_v2 {
                upcoming_environments.program_runtime_v2 = Arc::new(program_runtime_environment_v2);
            }
            program_cache.upcoming_environments = Some(upcoming_environments);
            program_cache.programs_to_recompile = program_cache
                .get_flattened_entries(changed_program_runtime_v1, changed_program_runtime_v2);
            program_cache
                .programs_to_recompile
                .sort_by_cached_key(|(_id, program)| program.decayed_usage_counter(self.slot));
        }
    }

    /// Execute a transaction using the provided loaded accounts and update
    /// the executors cache if the transaction was successful.
    #[allow(clippy::too_many_arguments)]
    fn execute_loaded_transaction<CB: TransactionProcessingCallback>(
        &self,
        callback: &CB,
        tx: &impl SVMTransaction,
        mut loaded_transaction: LoadedTransaction,
        execute_timings: &mut ExecuteTimings,
        error_metrics: &mut TransactionErrorMetrics,
        program_cache_for_tx_batch: &mut ProgramCacheForTxBatch,
        environment: &TransactionProcessingEnvironment,
        config: &TransactionProcessingConfig,
    ) -> ExecutedTransaction {
        let transaction_accounts = std::mem::take(&mut loaded_transaction.accounts);

        // Ensure the length of accounts matches the expected length from tx.account_keys().
        // This is a sanity check in case that someone starts adding some additional accounts
        // since this has been done before. See discussion in PR #4497 for details
        debug_assert!(transaction_accounts.len() == tx.account_keys().len());

        fn transaction_accounts_lamports_sum(
            accounts: &[(Pubkey, AccountSharedData)],
        ) -> Option<u128> {
            accounts.iter().try_fold(0u128, |sum, (_, account)| {
                sum.checked_add(u128::from(account.lamports()))
            })
        }

        let default_rent_collector = RentCollector::default();
        let rent_collector = environment
            .rent_collector
            .unwrap_or(&default_rent_collector);

        let lamports_before_tx =
            transaction_accounts_lamports_sum(&transaction_accounts).unwrap_or(0);

        let compute_budget = config
            .compute_budget
            .unwrap_or_else(|| ComputeBudget::from(loaded_transaction.compute_budget_limits));

        let mut transaction_context = TransactionContext::new(
            transaction_accounts,
            rent_collector.get_rent().clone(),
            compute_budget.max_instruction_stack_depth,
            compute_budget.max_instruction_trace_length,
        );
        transaction_context.set_remove_accounts_executable_flag_checks(
            environment
                .feature_set
                .is_active(&remove_accounts_executable_flag_checks::id()),
        );
        #[cfg(debug_assertions)]
        transaction_context.set_signature(tx.signature());

        let pre_account_state_info =
            TransactionAccountStateInfo::new(&transaction_context, tx, rent_collector);

        let log_collector = if config.recording_config.enable_log_recording {
            match config.log_messages_bytes_limit {
                None => Some(LogCollector::new_ref()),
                Some(log_messages_bytes_limit) => Some(LogCollector::new_ref_with_limit(Some(
                    log_messages_bytes_limit,
                ))),
            }
        } else {
            None
        };

        let mut executed_units = 0u64;
        let sysvar_cache = &self.sysvar_cache.read().unwrap();
        let epoch_vote_account_stake_callback =
            |pubkey| callback.get_current_epoch_vote_account_stake(pubkey);

        let mut invoke_context = InvokeContext::new(
            &mut transaction_context,
            program_cache_for_tx_batch,
            EnvironmentConfig::new(
                environment.blockhash,
                environment.blockhash_lamports_per_signature,
                environment.epoch_total_stake,
                &epoch_vote_account_stake_callback,
                Arc::clone(&environment.feature_set),
                sysvar_cache,
            ),
            log_collector.clone(),
            compute_budget,
        );

        let mut process_message_time = Measure::start("process_message_time");
        let process_result = process_message(
            tx,
            &loaded_transaction.program_indices,
            &mut invoke_context,
            execute_timings,
            &mut executed_units,
        );
        process_message_time.stop();

        drop(invoke_context);

        execute_timings.execute_accessories.process_message_us += process_message_time.as_us();

        let mut status = process_result
            .and_then(|info| {
                let post_account_state_info =
                    TransactionAccountStateInfo::new(&transaction_context, tx, rent_collector);
                TransactionAccountStateInfo::verify_changes(
                    &pre_account_state_info,
                    &post_account_state_info,
                    &transaction_context,
                    rent_collector,
                )
                .map(|_| info)
            })
            .map_err(|err| {
                match err {
                    TransactionError::InvalidRentPayingAccount
                    | TransactionError::InsufficientFundsForRent { .. } => {
                        error_metrics.invalid_rent_paying_account += 1;
                    }
                    TransactionError::InvalidAccountIndex => {
                        error_metrics.invalid_account_index += 1;
                    }
                    _ => {
                        error_metrics.instruction_error += 1;
                    }
                }
                err
            });

        let log_messages: Option<TransactionLogMessages> =
            log_collector.and_then(|log_collector| {
                Rc::try_unwrap(log_collector)
                    .map(|log_collector| log_collector.into_inner().into_messages())
                    .ok()
            });

        let inner_instructions = if config.recording_config.enable_cpi_recording {
            Some(Self::inner_instructions_list_from_instruction_trace(
                &transaction_context,
            ))
        } else {
            None
        };

        let ExecutionRecord {
            accounts,
            return_data,
            touched_account_count,
            accounts_resize_delta: accounts_data_len_delta,
        } = transaction_context.into();

        if status.is_ok()
            && transaction_accounts_lamports_sum(&accounts)
                .filter(|lamports_after_tx| lamports_before_tx == *lamports_after_tx)
                .is_none()
        {
            status = Err(TransactionError::UnbalancedTransaction);
        }
        let status = status.map(|_| ());

        loaded_transaction.accounts = accounts;
        execute_timings.details.total_account_count += loaded_transaction.accounts.len() as u64;
        execute_timings.details.changed_account_count += touched_account_count;

        let return_data = if config.recording_config.enable_return_data_recording
            && !return_data.data.is_empty()
        {
            Some(return_data)
        } else {
            None
        };

        ExecutedTransaction {
            execution_details: TransactionExecutionDetails {
                status,
                log_messages,
                inner_instructions,
                return_data,
                executed_units,
                accounts_data_len_delta,
            },
            loaded_transaction,
            programs_modified_by_tx: program_cache_for_tx_batch.drain_modified_entries(),
        }
    }

    /// Extract the InnerInstructionsList from a TransactionContext
    fn inner_instructions_list_from_instruction_trace(
        transaction_context: &TransactionContext,
    ) -> InnerInstructionsList {
        debug_assert!(transaction_context
            .get_instruction_context_at_index_in_trace(0)
            .map(|instruction_context| instruction_context.get_stack_height()
                == TRANSACTION_LEVEL_STACK_HEIGHT)
            .unwrap_or(true));
        let mut outer_instructions = Vec::new();
        for index_in_trace in 0..transaction_context.get_instruction_trace_length() {
            if let Ok(instruction_context) =
                transaction_context.get_instruction_context_at_index_in_trace(index_in_trace)
            {
                let stack_height = instruction_context.get_stack_height();
                if stack_height == TRANSACTION_LEVEL_STACK_HEIGHT {
                    outer_instructions.push(Vec::new());
                } else if let Some(inner_instructions) = outer_instructions.last_mut() {
                    let stack_height = u8::try_from(stack_height).unwrap_or(u8::MAX);
                    let instruction = CompiledInstruction::new_from_raw_parts(
                        instruction_context
                            .get_index_of_program_account_in_transaction(
                                instruction_context
                                    .get_number_of_program_accounts()
                                    .saturating_sub(1),
                            )
                            .unwrap_or_default() as u8,
                        instruction_context.get_instruction_data().to_vec(),
                        (0..instruction_context.get_number_of_instruction_accounts())
                            .map(|instruction_account_index| {
                                instruction_context
                                    .get_index_of_instruction_account_in_transaction(
                                        instruction_account_index,
                                    )
                                    .unwrap_or_default() as u8
                            })
                            .collect(),
                    );
                    inner_instructions.push(InnerInstruction {
                        instruction,
                        stack_height,
                    });
                } else {
                    debug_assert!(false);
                }
            } else {
                debug_assert!(false);
            }
        }
        outer_instructions
    }

    pub fn fill_missing_sysvar_cache_entries<CB: TransactionProcessingCallback>(
        &self,
        callbacks: &CB,
    ) {
        let mut sysvar_cache = self.sysvar_cache.write().unwrap();
        sysvar_cache.fill_missing_entries(|pubkey, set_sysvar| {
            if let Some(account) = callbacks.get_account_shared_data(pubkey) {
                set_sysvar(account.data());
            }
        });
    }

    pub fn reset_sysvar_cache(&self) {
        let mut sysvar_cache = self.sysvar_cache.write().unwrap();
        sysvar_cache.reset();
    }

    pub fn get_sysvar_cache_for_tests(&self) -> SysvarCache {
        self.sysvar_cache.read().unwrap().clone()
    }

    /// Add a built-in program
    pub fn add_builtin<CB: TransactionProcessingCallback>(
        &self,
        callbacks: &CB,
        program_id: Pubkey,
        name: &str,
        builtin: ProgramCacheEntry,
    ) {
        debug!("Adding program {} under {:?}", name, program_id);
        callbacks.add_builtin_account(name, &program_id);
        self.builtin_program_ids.write().unwrap().insert(program_id);
        self.program_cache
            .write()
            .unwrap()
            .assign_program(program_id, Arc::new(builtin));
        debug!("Added program {} under {:?}", name, program_id);
    }

    #[cfg(feature = "dev-context-only-utils")]
    #[cfg_attr(feature = "dev-context-only-utils", qualifiers(pub))]
    fn writable_sysvar_cache(&self) -> &RwLock<SysvarCache> {
        &self.sysvar_cache
    }
}
