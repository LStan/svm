#[cfg(feature = "dev-context-only-utils")]
use qualifier_attr::field_qualifiers;
use {
    crate::{
        account_overrides::AccountOverrides,
        nonce_info::NonceInfo,
        rollback_accounts::RollbackAccounts,
        transaction_error_metrics::TransactionErrorMetrics,
        transaction_execution_result::ExecutedTransaction,
        transaction_processing_callback::{AccountState, TransactionProcessingCallback},
    },
    ahash::{AHashMap, AHashSet},
    solana_account::{
        Account, AccountSharedData, ReadableAccount, WritableAccount, PROGRAM_OWNERS,
    },
    solana_compute_budget::compute_budget_limits::ComputeBudgetLimits,
    solana_feature_set::{self as feature_set, FeatureSet},
    solana_fee_structure::FeeDetails,
    solana_instruction::{BorrowedAccountMeta, BorrowedInstruction},
    solana_instructions_sysvar::construct_instructions_data,
    solana_nonce::state::State as NonceState,
    solana_nonce_account::{get_system_account_kind, SystemAccountKind},
    solana_pubkey::Pubkey,
    solana_rent::RentDue,
    solana_rent_debits::RentDebits,
    solana_sdk::rent_collector::{CollectedInfo, RENT_EXEMPT_RENT_EPOCH},
    solana_sdk_ids::{
        native_loader,
        sysvar::{self, slot_history},
    },
    solana_svm_rent_collector::svm_rent_collector::SVMRentCollector,
    solana_svm_transaction::svm_message::SVMMessage,
    solana_transaction_context::{IndexOfAccount, TransactionAccount},
    solana_transaction_error::{TransactionError, TransactionResult as Result},
    std::{
        num::{NonZeroU32, Saturating},
        sync::Arc,
    },
};

// for the load instructions
pub(crate) type TransactionRent = u64;
pub(crate) type TransactionProgramIndices = Vec<Vec<IndexOfAccount>>;
pub type TransactionCheckResult = Result<CheckedTransactionDetails>;
type TransactionValidationResult = Result<ValidatedTransactionDetails>;

#[derive(PartialEq, Eq, Debug)]
pub(crate) enum TransactionLoadResult {
    /// All transaction accounts were loaded successfully
    Loaded(LoadedTransaction),
    /// Some transaction accounts needed for execution were unable to be loaded
    /// but the fee payer and any nonce account needed for fee collection were
    /// loaded successfully
    FeesOnly(FeesOnlyTransaction),
    /// Some transaction accounts needed for fee collection were unable to be
    /// loaded
    NotLoaded(TransactionError),
}

#[derive(PartialEq, Eq, Debug, Clone)]
#[cfg_attr(feature = "dev-context-only-utils", derive(Default))]
pub struct CheckedTransactionDetails {
    pub(crate) nonce: Option<NonceInfo>,
    pub(crate) lamports_per_signature: u64,
}

impl CheckedTransactionDetails {
    pub fn new(nonce: Option<NonceInfo>, lamports_per_signature: u64) -> Self {
        Self {
            nonce,
            lamports_per_signature,
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
#[cfg_attr(feature = "dev-context-only-utils", derive(Default))]
pub(crate) struct ValidatedTransactionDetails {
    pub(crate) rollback_accounts: RollbackAccounts,
    pub(crate) compute_budget_limits: ComputeBudgetLimits,
    pub(crate) fee_details: FeeDetails,
    pub(crate) loaded_fee_payer_account: LoadedTransactionAccount,
}

#[derive(PartialEq, Eq, Debug, Clone)]
#[cfg_attr(feature = "dev-context-only-utils", derive(Default))]
pub(crate) struct LoadedTransactionAccount {
    pub(crate) account: AccountSharedData,
    pub(crate) loaded_size: usize,
    pub(crate) rent_collected: u64,
}

#[derive(PartialEq, Eq, Debug, Clone)]
#[cfg_attr(feature = "dev-context-only-utils", derive(Default))]
#[cfg_attr(
    feature = "dev-context-only-utils",
    field_qualifiers(
        program_indices(pub),
        compute_budget_limits(pub),
        loaded_accounts_data_size(pub)
    )
)]
pub struct LoadedTransaction {
    pub accounts: Vec<TransactionAccount>,
    pub(crate) program_indices: TransactionProgramIndices,
    pub fee_details: FeeDetails,
    pub rollback_accounts: RollbackAccounts,
    pub(crate) compute_budget_limits: ComputeBudgetLimits,
    pub rent: TransactionRent,
    pub rent_debits: RentDebits,
    pub(crate) loaded_accounts_data_size: u32,
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct FeesOnlyTransaction {
    pub load_error: TransactionError,
    pub rollback_accounts: RollbackAccounts,
    pub fee_details: FeeDetails,
}

#[cfg_attr(feature = "dev-context-only-utils", derive(Clone))]
pub(crate) struct AccountLoader<'a, CB: TransactionProcessingCallback> {
    account_cache: AHashMap<Pubkey, AccountSharedData>,
    callbacks: &'a CB,
    pub(crate) feature_set: Arc<FeatureSet>,
}
impl<'a, CB: TransactionProcessingCallback> AccountLoader<'a, CB> {
    pub(crate) fn new_with_account_cache_capacity(
        account_overrides: Option<&'a AccountOverrides>,
        callbacks: &'a CB,
        feature_set: Arc<FeatureSet>,
        capacity: usize,
    ) -> AccountLoader<'a, CB> {
        let mut account_cache = AHashMap::with_capacity(capacity);

        // SlotHistory may be overridden for simulation.
        // No other uses of AccountOverrides are expected.
        if let Some(slot_history) =
            account_overrides.and_then(|overrides| overrides.get(&slot_history::id()))
        {
            account_cache.insert(slot_history::id(), slot_history.clone());
        }

        Self {
            account_cache,
            callbacks,
            feature_set,
        }
    }

    pub(crate) fn load_account(
        &mut self,
        account_key: &Pubkey,
        is_writable: bool,
    ) -> Option<LoadedTransactionAccount> {
        let account = if let Some(account) = self.account_cache.get(account_key) {
            // If lamports is 0, a previous transaction deallocated this account.
            // We return None instead of the account we found so it can be created fresh.
            // We never evict from the cache, or else we would fetch stale state from accounts-db.
            if account.lamports() == 0 {
                None
            } else {
                Some(account.clone())
            }
        } else if let Some(account) = self.callbacks.get_account_shared_data(account_key) {
            self.account_cache.insert(*account_key, account.clone());
            Some(account)
        } else {
            None
        };

        // Inspect prior to collecting rent, since rent collection can modify the account.
        self.callbacks.inspect_account(
            account_key,
            if let Some(ref account) = account {
                AccountState::Alive(account)
            } else {
                AccountState::Dead
            },
            is_writable,
        );

        account.map(|account| LoadedTransactionAccount {
            loaded_size: account.data().len(),
            account,
            rent_collected: 0,
        })
    }

    pub(crate) fn update_accounts_for_executed_tx(
        &mut self,
        message: &impl SVMMessage,
        executed_transaction: &ExecutedTransaction,
    ) {
        if executed_transaction.was_successful() {
            self.update_accounts_for_successful_tx(
                message,
                &executed_transaction.loaded_transaction.accounts,
            );
        } else {
            self.update_accounts_for_failed_tx(
                message,
                &executed_transaction.loaded_transaction.rollback_accounts,
            );
        }
    }

    pub(crate) fn update_accounts_for_failed_tx(
        &mut self,
        message: &impl SVMMessage,
        rollback_accounts: &RollbackAccounts,
    ) {
        let fee_payer_address = message.fee_payer();
        match rollback_accounts {
            RollbackAccounts::FeePayerOnly { fee_payer_account } => {
                self.account_cache
                    .insert(*fee_payer_address, fee_payer_account.clone());
            }
            RollbackAccounts::SameNonceAndFeePayer { nonce } => {
                self.account_cache
                    .insert(*nonce.address(), nonce.account().clone());
            }
            RollbackAccounts::SeparateNonceAndFeePayer {
                nonce,
                fee_payer_account,
            } => {
                self.account_cache
                    .insert(*nonce.address(), nonce.account().clone());
                self.account_cache
                    .insert(*fee_payer_address, fee_payer_account.clone());
            }
        }
    }

    fn update_accounts_for_successful_tx(
        &mut self,
        message: &impl SVMMessage,
        transaction_accounts: &[TransactionAccount],
    ) {
        for (i, (address, account)) in (0..message.account_keys().len()).zip(transaction_accounts) {
            if !message.is_writable(i) {
                continue;
            }

            // Accounts that are invoked and also not passed as an instruction
            // account to a program don't need to be stored because it's assumed
            // to be impossible for a committable transaction to modify an
            // invoked account if said account isn't passed to some program.
            if message.is_invoked(i) && !message.is_instruction_account(i) {
                continue;
            }

            self.account_cache.insert(*address, account.clone());
        }
    }
}

/// Collect rent from an account if rent is still enabled and regardless of
/// whether rent is enabled, set the rent epoch to u64::MAX if the account is
/// rent exempt.
pub fn collect_rent_from_account(
    feature_set: &FeatureSet,
    rent_collector: &dyn SVMRentCollector,
    address: &Pubkey,
    account: &mut AccountSharedData,
) -> CollectedInfo {
    if !feature_set.is_active(&feature_set::disable_rent_fees_collection::id()) {
        rent_collector.collect_rent(address, account)
    } else {
        // When rent fee collection is disabled, we won't collect rent for any account. If there
        // are any rent paying accounts, their `rent_epoch` won't change either. However, if the
        // account itself is rent-exempted but its `rent_epoch` is not u64::MAX, we will set its
        // `rent_epoch` to u64::MAX. In such case, the behavior stays the same as before.
        if account.rent_epoch() != RENT_EXEMPT_RENT_EPOCH
            && rent_collector.get_rent_due(
                account.lamports(),
                account.data().len(),
                account.rent_epoch(),
            ) == RentDue::Exempt
        {
            account.set_rent_epoch(RENT_EXEMPT_RENT_EPOCH);
        }

        CollectedInfo::default()
    }
}

/// Check whether the payer_account is capable of paying the fee. The
/// side effect is to subtract the fee amount from the payer_account
/// balance of lamports. If the payer_acount is not able to pay the
/// fee, the error_metrics is incremented, and a specific error is
/// returned.
pub fn validate_fee_payer(
    payer_address: &Pubkey,
    payer_account: &mut AccountSharedData,
    payer_index: IndexOfAccount,
    error_metrics: &mut TransactionErrorMetrics,
    rent_collector: &dyn SVMRentCollector,
    fee: u64,
) -> Result<()> {
    if payer_account.lamports() == 0 {
        error_metrics.account_not_found += 1;
        return Err(TransactionError::AccountNotFound);
    }
    let system_account_kind = get_system_account_kind(payer_account).ok_or_else(|| {
        error_metrics.invalid_account_for_fee += 1;
        TransactionError::InvalidAccountForFee
    })?;
    let min_balance = match system_account_kind {
        SystemAccountKind::System => 0,
        SystemAccountKind::Nonce => {
            // Should we ever allow a fees charge to zero a nonce account's
            // balance. The state MUST be set to uninitialized in that case
            rent_collector
                .get_rent()
                .minimum_balance(NonceState::size())
        }
    };

    payer_account
        .lamports()
        .checked_sub(min_balance)
        .and_then(|v| v.checked_sub(fee))
        .ok_or_else(|| {
            error_metrics.insufficient_funds += 1;
            TransactionError::InsufficientFundsForFee
        })?;

    let payer_pre_rent_state = rent_collector.get_account_rent_state(payer_account);
    payer_account
        .checked_sub_lamports(fee)
        .map_err(|_| TransactionError::InsufficientFundsForFee)?;

    let payer_post_rent_state = rent_collector.get_account_rent_state(payer_account);
    rent_collector.check_rent_state_with_account(
        &payer_pre_rent_state,
        &payer_post_rent_state,
        payer_address,
        payer_account,
        payer_index,
    )
}

pub(crate) fn load_transaction<CB: TransactionProcessingCallback>(
    account_loader: &mut AccountLoader<CB>,
    message: &impl SVMMessage,
    validation_result: TransactionValidationResult,
    error_metrics: &mut TransactionErrorMetrics,
    rent_collector: &dyn SVMRentCollector,
) -> TransactionLoadResult {
    match validation_result {
        Err(e) => TransactionLoadResult::NotLoaded(e),
        Ok(tx_details) => {
            let load_result = load_transaction_accounts(
                account_loader,
                message,
                tx_details.loaded_fee_payer_account,
                &tx_details.compute_budget_limits,
                error_metrics,
                rent_collector,
            );

            match load_result {
                Ok(loaded_tx_accounts) => TransactionLoadResult::Loaded(LoadedTransaction {
                    accounts: loaded_tx_accounts.accounts,
                    program_indices: loaded_tx_accounts.program_indices,
                    fee_details: tx_details.fee_details,
                    rent: loaded_tx_accounts.rent,
                    rent_debits: loaded_tx_accounts.rent_debits,
                    rollback_accounts: tx_details.rollback_accounts,
                    compute_budget_limits: tx_details.compute_budget_limits,
                    loaded_accounts_data_size: loaded_tx_accounts.loaded_accounts_data_size,
                }),
                Err(err) => TransactionLoadResult::FeesOnly(FeesOnlyTransaction {
                    load_error: err,
                    fee_details: tx_details.fee_details,
                    rollback_accounts: tx_details.rollback_accounts,
                }),
            }
        }
    }
}

#[derive(PartialEq, Eq, Debug, Clone)]
struct LoadedTransactionAccounts {
    pub(crate) accounts: Vec<TransactionAccount>,
    pub(crate) program_indices: TransactionProgramIndices,
    pub(crate) rent: TransactionRent,
    pub(crate) rent_debits: RentDebits,
    pub(crate) loaded_accounts_data_size: u32,
}

fn load_transaction_accounts<CB: TransactionProcessingCallback>(
    account_loader: &mut AccountLoader<CB>,
    message: &impl SVMMessage,
    loaded_fee_payer_account: LoadedTransactionAccount,
    compute_budget_limits: &ComputeBudgetLimits,
    error_metrics: &mut TransactionErrorMetrics,
    rent_collector: &dyn SVMRentCollector,
) -> Result<LoadedTransactionAccounts> {
    let mut tx_rent: TransactionRent = 0;
    let account_keys = message.account_keys();
    let mut accounts = Vec::with_capacity(account_keys.len());
    let mut validated_loaders = AHashSet::with_capacity(PROGRAM_OWNERS.len());
    let mut rent_debits = RentDebits::default();
    let mut accumulated_accounts_data_size: Saturating<u32> = Saturating(0);

    let mut collect_loaded_account = |key, loaded_account| -> Result<()> {
        let LoadedTransactionAccount {
            account,
            loaded_size,
            rent_collected,
        } = loaded_account;

        accumulate_and_check_loaded_account_data_size(
            &mut accumulated_accounts_data_size,
            loaded_size,
            compute_budget_limits.loaded_accounts_bytes,
            error_metrics,
        )?;

        tx_rent += rent_collected;
        rent_debits.insert(key, rent_collected, account.lamports());

        accounts.push((*key, account));
        Ok(())
    };

    // Since the fee payer is always the first account, collect it first.
    // We can use it directly because it was already loaded during validation.
    collect_loaded_account(message.fee_payer(), loaded_fee_payer_account)?;

    // Attempt to load and collect remaining non-fee payer accounts
    for (account_index, account_key) in account_keys.iter().enumerate().skip(1) {
        let loaded_account = load_transaction_account(
            account_loader,
            message,
            account_key,
            account_index,
            rent_collector,
        );
        collect_loaded_account(account_key, loaded_account)?;
    }

    let program_indices = message
        .program_instructions_iter()
        .map(|(program_id, instruction)| {
            let mut account_indices = Vec::with_capacity(2);
            if native_loader::check_id(program_id) {
                return Ok(account_indices);
            }

            let program_index = instruction.program_id_index as usize;

            let Some(LoadedTransactionAccount {
                account: program_account,
                ..
            }) = account_loader.load_account(program_id, false)
            else {
                error_metrics.account_not_found += 1;
                return Err(TransactionError::ProgramAccountNotFound);
            };

            if !account_loader
                .feature_set
                .is_active(&feature_set::remove_accounts_executable_flag_checks::id())
                && !program_account.executable()
            {
                error_metrics.invalid_program_for_execution += 1;
                return Err(TransactionError::InvalidProgramForExecution);
            }
            account_indices.insert(0, program_index as IndexOfAccount);

            let owner_id = program_account.owner();
            if native_loader::check_id(owner_id) {
                return Ok(account_indices);
            }

            if !validated_loaders.contains(owner_id) {
                // NOTE there are several feature gate activations that affect this code:
                // * `remove_accounts_executable_flag_checks`: this implicitly makes system, vote, stake, et al valid loaders
                //   it is impossible to mark an account executable and also have it be owned by one of them
                //   so, with the feature disabled, we always fail the executable check if they are a program id owner
                //   however, with the feature enabled, any account owned by an account owned by native loader is a "program"
                //   this is benign (any such transaction will fail at execution) but it affects which transactions pay fees
                // * `enable_transaction_loading_failure_fees`: loading failures behave the same as execution failures
                //   at this point we can restrict valid loaders to those contained in `PROGRAM_OWNERS`
                //   since any other pseudo-loader owner is destined to fail at execution
                // * SIMD-186: explicitly defines a sensible transaction data size algorithm
                //   at this point we stop counting loaders toward transaction data size entirely
                //
                // when _all three_ of `remove_accounts_executable_flag_checks`, `enable_transaction_loading_failure_fees`,
                // and SIMD-186 are active, we do not need to load loaders at all to comply with consensus rules
                // we may verify program ids are owned by `PROGRAM_OWNERS` purely as an optimization
                // this could even be done before loading the rest of the accounts for a transaction
                if let Some(LoadedTransactionAccount {
                    account: owner_account,
                    loaded_size: owner_size,
                    ..
                }) = account_loader.load_account(owner_id, false)
                {
                    if !native_loader::check_id(owner_account.owner())
                        || (!account_loader
                            .feature_set
                            .is_active(&feature_set::remove_accounts_executable_flag_checks::id())
                            && !owner_account.executable())
                    {
                        error_metrics.invalid_program_for_execution += 1;
                        return Err(TransactionError::InvalidProgramForExecution);
                    }
                    accumulate_and_check_loaded_account_data_size(
                        &mut accumulated_accounts_data_size,
                        owner_size,
                        compute_budget_limits.loaded_accounts_bytes,
                        error_metrics,
                    )?;
                    validated_loaders.insert(*owner_id);
                } else {
                    error_metrics.account_not_found += 1;
                    return Err(TransactionError::ProgramAccountNotFound);
                }
            }
            Ok(account_indices)
        })
        .collect::<Result<Vec<Vec<IndexOfAccount>>>>()?;

    Ok(LoadedTransactionAccounts {
        accounts,
        program_indices,
        rent: tx_rent,
        rent_debits,
        loaded_accounts_data_size: accumulated_accounts_data_size.0,
    })
}

fn load_transaction_account<CB: TransactionProcessingCallback>(
    account_loader: &mut AccountLoader<CB>,
    message: &impl SVMMessage,
    account_key: &Pubkey,
    account_index: usize,
    rent_collector: &dyn SVMRentCollector,
) -> LoadedTransactionAccount {
    let is_writable = message.is_writable(account_index);
    let loaded_account = if solana_sdk_ids::sysvar::instructions::check_id(account_key) {
        // Since the instructions sysvar is constructed by the SVM and modified
        // for each transaction instruction, it cannot be loaded.
        LoadedTransactionAccount {
            loaded_size: 0,
            account: construct_instructions_account(message),
            rent_collected: 0,
        }
    } else if let Some(mut loaded_account) = account_loader.load_account(account_key, is_writable) {
        loaded_account.rent_collected = if is_writable {
            collect_rent_from_account(
                &account_loader.feature_set,
                rent_collector,
                account_key,
                &mut loaded_account.account,
            )
            .rent_amount
        } else {
            0
        };

        loaded_account
    } else {
        let mut default_account = AccountSharedData::default();
        // All new accounts must be rent-exempt (enforced in Bank::execute_loaded_transaction).
        // Currently, rent collection sets rent_epoch to u64::MAX, but initializing the account
        // with this field already set would allow us to skip rent collection for these accounts.
        default_account.set_rent_epoch(RENT_EXEMPT_RENT_EPOCH);
        LoadedTransactionAccount {
            loaded_size: default_account.data().len(),
            account: default_account,
            rent_collected: 0,
        }
    };

    loaded_account
}

/// Accumulate loaded account data size into `accumulated_accounts_data_size`.
/// Returns TransactionErr::MaxLoadedAccountsDataSizeExceeded if
/// `accumulated_accounts_data_size` exceeds
/// `requested_loaded_accounts_data_size_limit`.
fn accumulate_and_check_loaded_account_data_size(
    accumulated_loaded_accounts_data_size: &mut Saturating<u32>,
    account_data_size: usize,
    requested_loaded_accounts_data_size_limit: NonZeroU32,
    error_metrics: &mut TransactionErrorMetrics,
) -> Result<()> {
    let Ok(account_data_size) = u32::try_from(account_data_size) else {
        error_metrics.max_loaded_accounts_data_size_exceeded += 1;
        return Err(TransactionError::MaxLoadedAccountsDataSizeExceeded);
    };
    *accumulated_loaded_accounts_data_size += account_data_size;
    if accumulated_loaded_accounts_data_size.0 > requested_loaded_accounts_data_size_limit.get() {
        error_metrics.max_loaded_accounts_data_size_exceeded += 1;
        Err(TransactionError::MaxLoadedAccountsDataSizeExceeded)
    } else {
        Ok(())
    }
}

fn construct_instructions_account(message: &impl SVMMessage) -> AccountSharedData {
    let account_keys = message.account_keys();
    let mut decompiled_instructions = Vec::with_capacity(message.num_instructions());
    for (program_id, instruction) in message.program_instructions_iter() {
        let accounts = instruction
            .accounts
            .iter()
            .map(|account_index| {
                let account_index = usize::from(*account_index);
                BorrowedAccountMeta {
                    is_signer: message.is_signer(account_index),
                    is_writable: message.is_writable(account_index),
                    pubkey: account_keys.get(account_index).unwrap(),
                }
            })
            .collect();

        decompiled_instructions.push(BorrowedInstruction {
            accounts,
            data: instruction.data,
            program_id,
        });
    }

    AccountSharedData::from(Account {
        data: construct_instructions_data(&decompiled_instructions),
        owner: sysvar::id(),
        ..Account::default()
    })
}
