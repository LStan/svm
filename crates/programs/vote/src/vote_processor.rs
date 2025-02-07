//! Vote program processor

use {
    crate::vote_state,
    log::*,
    solana_bincode::limited_deserialize,
    solana_feature_set as feature_set,
    solana_instruction::error::InstructionError,
    solana_program_runtime::{
        declare_process_instruction, invoke_context::InvokeContext,
        sysvar_cache::get_sysvar_with_account_check,
    },
    solana_pubkey::Pubkey,
    solana_transaction_context::{BorrowedAccount, InstructionContext, TransactionContext},
    solana_vote_interface::{instruction::VoteInstruction, program::id, state::VoteAuthorize},
    std::collections::HashSet,
};

fn process_authorize_with_seed_instruction(
    invoke_context: &InvokeContext,
    instruction_context: &InstructionContext,
    transaction_context: &TransactionContext,
    vote_account: &mut BorrowedAccount,
    new_authority: &Pubkey,
    authorization_type: VoteAuthorize,
    current_authority_derived_key_owner: &Pubkey,
    current_authority_derived_key_seed: &str,
) -> Result<(), InstructionError> {
    let clock = get_sysvar_with_account_check::clock(invoke_context, instruction_context, 1)?;
    let mut expected_authority_keys: HashSet<Pubkey> = HashSet::default();
    if instruction_context.is_instruction_account_signer(2)? {
        let base_pubkey = transaction_context.get_key_of_account_at_index(
            instruction_context.get_index_of_instruction_account_in_transaction(2)?,
        )?;
        expected_authority_keys.insert(Pubkey::create_with_seed(
            base_pubkey,
            current_authority_derived_key_seed,
            current_authority_derived_key_owner,
        )?);
    };
    vote_state::authorize(
        vote_account,
        new_authority,
        authorization_type,
        &expected_authority_keys,
        &clock,
    )
}

// Citing `runtime/src/block_cost_limit.rs`, vote has statically defined 2100
// units; can consume based on instructions in the future like `bpf_loader` does.
pub const DEFAULT_COMPUTE_UNITS: u64 = 2_100;

declare_process_instruction!(Entrypoint, DEFAULT_COMPUTE_UNITS, |invoke_context| {
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let data = instruction_context.get_instruction_data();

    trace!("process_instruction: {:?}", data);

    let mut me = instruction_context.try_borrow_instruction_account(transaction_context, 0)?;
    if *me.get_owner() != id() {
        return Err(InstructionError::InvalidAccountOwner);
    }

    let signers = instruction_context.get_signers(transaction_context)?;
    match limited_deserialize(data, solana_packet::PACKET_DATA_SIZE as u64)? {
        VoteInstruction::InitializeAccount(vote_init) => {
            let rent = get_sysvar_with_account_check::rent(invoke_context, instruction_context, 1)?;
            if !rent.is_exempt(me.get_lamports(), me.get_data().len()) {
                return Err(InstructionError::InsufficientFunds);
            }
            let clock =
                get_sysvar_with_account_check::clock(invoke_context, instruction_context, 2)?;
            vote_state::initialize_account(&mut me, &vote_init, &signers, &clock)
        }
        VoteInstruction::Authorize(voter_pubkey, vote_authorize) => {
            let clock =
                get_sysvar_with_account_check::clock(invoke_context, instruction_context, 1)?;
            vote_state::authorize(&mut me, &voter_pubkey, vote_authorize, &signers, &clock)
        }
        VoteInstruction::AuthorizeWithSeed(args) => {
            instruction_context.check_number_of_instruction_accounts(3)?;
            process_authorize_with_seed_instruction(
                invoke_context,
                instruction_context,
                transaction_context,
                &mut me,
                &args.new_authority,
                args.authorization_type,
                &args.current_authority_derived_key_owner,
                args.current_authority_derived_key_seed.as_str(),
            )
        }
        VoteInstruction::AuthorizeCheckedWithSeed(args) => {
            instruction_context.check_number_of_instruction_accounts(4)?;
            let new_authority = transaction_context.get_key_of_account_at_index(
                instruction_context.get_index_of_instruction_account_in_transaction(3)?,
            )?;
            if !instruction_context.is_instruction_account_signer(3)? {
                return Err(InstructionError::MissingRequiredSignature);
            }
            process_authorize_with_seed_instruction(
                invoke_context,
                instruction_context,
                transaction_context,
                &mut me,
                new_authority,
                args.authorization_type,
                &args.current_authority_derived_key_owner,
                args.current_authority_derived_key_seed.as_str(),
            )
        }
        VoteInstruction::UpdateValidatorIdentity => {
            instruction_context.check_number_of_instruction_accounts(2)?;
            let node_pubkey = transaction_context.get_key_of_account_at_index(
                instruction_context.get_index_of_instruction_account_in_transaction(1)?,
            )?;
            vote_state::update_validator_identity(&mut me, node_pubkey, &signers)
        }
        VoteInstruction::UpdateCommission(commission) => {
            let sysvar_cache = invoke_context.get_sysvar_cache();

            vote_state::update_commission(
                &mut me,
                commission,
                &signers,
                sysvar_cache.get_epoch_schedule()?.as_ref(),
                sysvar_cache.get_clock()?.as_ref(),
                invoke_context.get_feature_set(),
            )
        }
        VoteInstruction::Vote(vote) | VoteInstruction::VoteSwitch(vote, _) => {
            if invoke_context
                .get_feature_set()
                .is_active(&feature_set::deprecate_legacy_vote_ixs::id())
                && invoke_context
                    .get_feature_set()
                    .is_active(&feature_set::enable_tower_sync_ix::id())
            {
                return Err(InstructionError::InvalidInstructionData);
            }
            let slot_hashes =
                get_sysvar_with_account_check::slot_hashes(invoke_context, instruction_context, 1)?;
            let clock =
                get_sysvar_with_account_check::clock(invoke_context, instruction_context, 2)?;
            vote_state::process_vote_with_account(
                &mut me,
                &slot_hashes,
                &clock,
                &vote,
                &signers,
                invoke_context.get_feature_set(),
            )
        }
        VoteInstruction::UpdateVoteState(vote_state_update)
        | VoteInstruction::UpdateVoteStateSwitch(vote_state_update, _) => {
            if invoke_context
                .get_feature_set()
                .is_active(&feature_set::deprecate_legacy_vote_ixs::id())
                && invoke_context
                    .get_feature_set()
                    .is_active(&feature_set::enable_tower_sync_ix::id())
            {
                return Err(InstructionError::InvalidInstructionData);
            }
            let sysvar_cache = invoke_context.get_sysvar_cache();
            let slot_hashes = sysvar_cache.get_slot_hashes()?;
            let clock = sysvar_cache.get_clock()?;
            vote_state::process_vote_state_update(
                &mut me,
                slot_hashes.slot_hashes(),
                &clock,
                vote_state_update,
                &signers,
                invoke_context.get_feature_set(),
            )
        }
        VoteInstruction::CompactUpdateVoteState(vote_state_update)
        | VoteInstruction::CompactUpdateVoteStateSwitch(vote_state_update, _) => {
            if invoke_context
                .get_feature_set()
                .is_active(&feature_set::deprecate_legacy_vote_ixs::id())
                && invoke_context
                    .get_feature_set()
                    .is_active(&feature_set::enable_tower_sync_ix::id())
            {
                return Err(InstructionError::InvalidInstructionData);
            }
            let sysvar_cache = invoke_context.get_sysvar_cache();
            let slot_hashes = sysvar_cache.get_slot_hashes()?;
            let clock = sysvar_cache.get_clock()?;
            vote_state::process_vote_state_update(
                &mut me,
                slot_hashes.slot_hashes(),
                &clock,
                vote_state_update,
                &signers,
                invoke_context.get_feature_set(),
            )
        }
        VoteInstruction::TowerSync(tower_sync)
        | VoteInstruction::TowerSyncSwitch(tower_sync, _) => {
            if !invoke_context
                .get_feature_set()
                .is_active(&feature_set::enable_tower_sync_ix::id())
            {
                return Err(InstructionError::InvalidInstructionData);
            }
            let sysvar_cache = invoke_context.get_sysvar_cache();
            let slot_hashes = sysvar_cache.get_slot_hashes()?;
            let clock = sysvar_cache.get_clock()?;
            vote_state::process_tower_sync(
                &mut me,
                slot_hashes.slot_hashes(),
                &clock,
                tower_sync,
                &signers,
                invoke_context.get_feature_set(),
            )
        }
        VoteInstruction::Withdraw(lamports) => {
            instruction_context.check_number_of_instruction_accounts(2)?;
            let rent_sysvar = invoke_context.get_sysvar_cache().get_rent()?;
            let clock_sysvar = invoke_context.get_sysvar_cache().get_clock()?;

            drop(me);
            vote_state::withdraw(
                transaction_context,
                instruction_context,
                0,
                lamports,
                1,
                &signers,
                &rent_sysvar,
                &clock_sysvar,
            )
        }
        VoteInstruction::AuthorizeChecked(vote_authorize) => {
            instruction_context.check_number_of_instruction_accounts(4)?;
            let voter_pubkey = transaction_context.get_key_of_account_at_index(
                instruction_context.get_index_of_instruction_account_in_transaction(3)?,
            )?;
            if !instruction_context.is_instruction_account_signer(3)? {
                return Err(InstructionError::MissingRequiredSignature);
            }
            let clock =
                get_sysvar_with_account_check::clock(invoke_context, instruction_context, 1)?;
            vote_state::authorize(&mut me, voter_pubkey, vote_authorize, &signers, &clock)
        }
    }
});
