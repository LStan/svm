#[cfg(feature = "dev-context-only-utils")]
use qualifier_attr::qualifiers;
use {
    crate::transaction_processing_callback::TransactionProcessingCallback,
    solana_account::{state_traits::StateMut, AccountSharedData, ReadableAccount},
    solana_clock::Slot,
    solana_instruction::error::InstructionError,
    solana_program::bpf_loader_upgradeable::{self, UpgradeableLoaderState},
    solana_program_runtime::loaded_programs::{
        LoadProgramMetrics, ProgramCacheEntry, ProgramCacheEntryOwner, ProgramCacheEntryType,
        ProgramRuntimeEnvironment, ProgramRuntimeEnvironments, DELAY_VISIBILITY_SLOT_OFFSET,
    },
    solana_pubkey::Pubkey,
    solana_sdk::loader_v4::{self, LoaderV4State, LoaderV4Status},
    solana_sdk_ids::{bpf_loader, bpf_loader_deprecated},
    solana_timings::ExecuteTimings,
    solana_transaction_error::{TransactionError, TransactionResult},
    solana_type_overrides::sync::Arc,
};

#[derive(Debug)]
pub(crate) enum ProgramAccountLoadResult {
    InvalidAccountData(ProgramCacheEntryOwner),
    ProgramOfLoaderV1(AccountSharedData),
    ProgramOfLoaderV2(AccountSharedData),
    ProgramOfLoaderV3(AccountSharedData, AccountSharedData, Slot),
    ProgramOfLoaderV4(AccountSharedData, Slot),
}

pub(crate) fn load_program_from_bytes(
    load_program_metrics: &mut LoadProgramMetrics,
    programdata: &[u8],
    loader_key: &Pubkey,
    account_size: usize,
    deployment_slot: Slot,
    program_runtime_environment: ProgramRuntimeEnvironment,
    reloading: bool,
) -> std::result::Result<ProgramCacheEntry, Box<dyn std::error::Error>> {
    if reloading {
        // Safety: this is safe because the program is being reloaded in the cache.
        unsafe {
            ProgramCacheEntry::reload(
                loader_key,
                program_runtime_environment.clone(),
                deployment_slot,
                deployment_slot.saturating_add(DELAY_VISIBILITY_SLOT_OFFSET),
                programdata,
                account_size,
                load_program_metrics,
            )
        }
    } else {
        ProgramCacheEntry::new(
            loader_key,
            program_runtime_environment.clone(),
            deployment_slot,
            deployment_slot.saturating_add(DELAY_VISIBILITY_SLOT_OFFSET),
            programdata,
            account_size,
            load_program_metrics,
        )
    }
}

pub(crate) fn load_program_accounts<CB: TransactionProcessingCallback>(
    callbacks: &CB,
    pubkey: &Pubkey,
) -> Option<ProgramAccountLoadResult> {
    let program_account = callbacks.get_account_shared_data(pubkey)?;

    if loader_v4::check_id(program_account.owner()) {
        return Some(
            solana_loader_v4_program::get_state(program_account.data())
                .ok()
                .and_then(|state| {
                    (!matches!(state.status, LoaderV4Status::Retracted)).then_some(state.slot)
                })
                .map(|slot| ProgramAccountLoadResult::ProgramOfLoaderV4(program_account, slot))
                .unwrap_or(ProgramAccountLoadResult::InvalidAccountData(
                    ProgramCacheEntryOwner::LoaderV4,
                )),
        );
    }

    if bpf_loader_deprecated::check_id(program_account.owner()) {
        return Some(ProgramAccountLoadResult::ProgramOfLoaderV1(program_account));
    }

    if bpf_loader::check_id(program_account.owner()) {
        return Some(ProgramAccountLoadResult::ProgramOfLoaderV2(program_account));
    }

    if let Ok(UpgradeableLoaderState::Program {
        programdata_address,
    }) = program_account.state()
    {
        if let Some(programdata_account) = callbacks.get_account_shared_data(&programdata_address) {
            if let Ok(UpgradeableLoaderState::ProgramData {
                slot,
                upgrade_authority_address: _,
            }) = programdata_account.state()
            {
                return Some(ProgramAccountLoadResult::ProgramOfLoaderV3(
                    program_account,
                    programdata_account,
                    slot,
                ));
            }
        }
    }
    Some(ProgramAccountLoadResult::InvalidAccountData(
        ProgramCacheEntryOwner::LoaderV3,
    ))
}

/// Loads the program with the given pubkey.
///
/// If the account doesn't exist it returns `None`. If the account does exist, it must be a program
/// account (belong to one of the program loaders). Returns `Some(InvalidAccountData)` if the program
/// account is `Closed`, contains invalid data or any of the programdata accounts are invalid.
#[cfg_attr(feature = "dev-context-only-utils", qualifiers(pub))]
pub(crate) fn load_program_with_pubkey<CB: TransactionProcessingCallback>(
    callbacks: &CB,
    environments: &ProgramRuntimeEnvironments,
    pubkey: &Pubkey,
    slot: Slot,
    execute_timings: &mut ExecuteTimings,
    reload: bool,
) -> Option<Arc<ProgramCacheEntry>> {
    let mut load_program_metrics = LoadProgramMetrics {
        program_id: pubkey.to_string(),
        ..LoadProgramMetrics::default()
    };

    let loaded_program = match load_program_accounts(callbacks, pubkey)? {
        ProgramAccountLoadResult::InvalidAccountData(owner) => Ok(
            ProgramCacheEntry::new_tombstone(slot, owner, ProgramCacheEntryType::Closed),
        ),

        ProgramAccountLoadResult::ProgramOfLoaderV1(program_account) => load_program_from_bytes(
            &mut load_program_metrics,
            program_account.data(),
            program_account.owner(),
            program_account.data().len(),
            0,
            environments.program_runtime_v1.clone(),
            reload,
        )
        .map_err(|_| (0, ProgramCacheEntryOwner::LoaderV1)),

        ProgramAccountLoadResult::ProgramOfLoaderV2(program_account) => load_program_from_bytes(
            &mut load_program_metrics,
            program_account.data(),
            program_account.owner(),
            program_account.data().len(),
            0,
            environments.program_runtime_v1.clone(),
            reload,
        )
        .map_err(|_| (0, ProgramCacheEntryOwner::LoaderV2)),

        ProgramAccountLoadResult::ProgramOfLoaderV3(program_account, programdata_account, slot) => {
            programdata_account
                .data()
                .get(UpgradeableLoaderState::size_of_programdata_metadata()..)
                .ok_or(Box::new(InstructionError::InvalidAccountData).into())
                .and_then(|programdata| {
                    load_program_from_bytes(
                        &mut load_program_metrics,
                        programdata,
                        program_account.owner(),
                        program_account
                            .data()
                            .len()
                            .saturating_add(programdata_account.data().len()),
                        slot,
                        environments.program_runtime_v1.clone(),
                        reload,
                    )
                })
                .map_err(|_| (slot, ProgramCacheEntryOwner::LoaderV3))
        }

        ProgramAccountLoadResult::ProgramOfLoaderV4(program_account, slot) => program_account
            .data()
            .get(LoaderV4State::program_data_offset()..)
            .ok_or(Box::new(InstructionError::InvalidAccountData).into())
            .and_then(|elf_bytes| {
                load_program_from_bytes(
                    &mut load_program_metrics,
                    elf_bytes,
                    &loader_v4::id(),
                    program_account.data().len(),
                    slot,
                    environments.program_runtime_v1.clone(),
                    reload,
                )
            })
            .map_err(|_| (slot, ProgramCacheEntryOwner::LoaderV4)),
    }
    .unwrap_or_else(|(slot, owner)| {
        let env = environments.program_runtime_v1.clone();
        ProgramCacheEntry::new_tombstone(
            slot,
            owner,
            ProgramCacheEntryType::FailedVerification(env),
        )
    });

    load_program_metrics.submit_datapoint(&mut execute_timings.details);
    loaded_program.update_access_slot(slot);
    Some(Arc::new(loaded_program))
}

/// Find the slot in which the program was most recently modified.
/// Returns slot 0 for programs deployed with v1/v2 loaders, since programs deployed
/// with those loaders do not retain deployment slot information.
/// Returns an error if the program's account state can not be found or parsed.
pub(crate) fn get_program_modification_slot<CB: TransactionProcessingCallback>(
    callbacks: &CB,
    pubkey: &Pubkey,
) -> TransactionResult<Slot> {
    let program = callbacks
        .get_account_shared_data(pubkey)
        .ok_or(TransactionError::ProgramAccountNotFound)?;
    if bpf_loader_upgradeable::check_id(program.owner()) {
        if let Ok(UpgradeableLoaderState::Program {
            programdata_address,
        }) = program.state()
        {
            let programdata = callbacks
                .get_account_shared_data(&programdata_address)
                .ok_or(TransactionError::ProgramAccountNotFound)?;
            if let Ok(UpgradeableLoaderState::ProgramData {
                slot,
                upgrade_authority_address: _,
            }) = programdata.state()
            {
                return Ok(slot);
            }
        }
        Err(TransactionError::ProgramAccountNotFound)
    } else if loader_v4::check_id(program.owner()) {
        let state = solana_loader_v4_program::get_state(program.data())
            .map_err(|_| TransactionError::ProgramAccountNotFound)?;
        Ok(state.slot)
    } else {
        Ok(0)
    }
}
