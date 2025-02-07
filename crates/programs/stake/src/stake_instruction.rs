use {
    crate::stake_state::{
        authorize, authorize_with_seed, deactivate, deactivate_delinquent, delegate, initialize,
        merge, move_lamports, move_stake, new_warmup_cooldown_rate_epoch, set_lockup, split,
        withdraw,
    },
    log::*,
    solana_bincode::limited_deserialize,
    solana_instruction::error::InstructionError,
    solana_program_runtime::{
        declare_process_instruction, sysvar_cache::get_sysvar_with_account_check,
    },
    solana_pubkey::Pubkey,
    solana_stake_interface::{
        error::StakeError,
        instruction::{LockupArgs, StakeInstruction},
        program::id,
        state::{Authorized, Lockup},
    },
    solana_transaction_context::{IndexOfAccount, InstructionContext, TransactionContext},
};

fn get_optional_pubkey<'a>(
    transaction_context: &'a TransactionContext,
    instruction_context: &'a InstructionContext,
    instruction_account_index: IndexOfAccount,
    should_be_signer: bool,
) -> Result<Option<&'a Pubkey>, InstructionError> {
    Ok(
        if instruction_account_index < instruction_context.get_number_of_instruction_accounts() {
            if should_be_signer
                && !instruction_context.is_instruction_account_signer(instruction_account_index)?
            {
                return Err(InstructionError::MissingRequiredSignature);
            }
            Some(
                transaction_context.get_key_of_account_at_index(
                    instruction_context.get_index_of_instruction_account_in_transaction(
                        instruction_account_index,
                    )?,
                )?,
            )
        } else {
            None
        },
    )
}

pub const DEFAULT_COMPUTE_UNITS: u64 = 750;

declare_process_instruction!(Entrypoint, DEFAULT_COMPUTE_UNITS, |invoke_context| {
    let transaction_context = &invoke_context.transaction_context;
    let instruction_context = transaction_context.get_current_instruction_context()?;
    let data = instruction_context.get_instruction_data();

    trace!("process_instruction: {:?}", data);

    let get_stake_account = || {
        let me = instruction_context.try_borrow_instruction_account(transaction_context, 0)?;
        if *me.get_owner() != id() {
            return Err(InstructionError::InvalidAccountOwner);
        }
        Ok(me)
    };

    // The EpochRewards sysvar only exists after the
    // partitioned_epoch_rewards_superfeature feature is activated. If it
    // exists, check the `active` field
    let epoch_rewards_active = invoke_context
        .get_sysvar_cache()
        .get_epoch_rewards()
        .map(|epoch_rewards| epoch_rewards.active)
        .unwrap_or(false);

    let signers = instruction_context.get_signers(transaction_context)?;

    let stake_instruction: StakeInstruction =
        limited_deserialize(data, solana_packet::PACKET_DATA_SIZE as u64)?;
    if epoch_rewards_active && !matches!(stake_instruction, StakeInstruction::GetMinimumDelegation)
    {
        return Err(StakeError::EpochRewardsActive.into());
    }
    match stake_instruction {
        StakeInstruction::Initialize(authorized, lockup) => {
            let mut me = get_stake_account()?;
            let rent = get_sysvar_with_account_check::rent(invoke_context, instruction_context, 1)?;
            initialize(&mut me, &authorized, &lockup, &rent)
        }
        StakeInstruction::Authorize(authorized_pubkey, stake_authorize) => {
            let mut me = get_stake_account()?;
            let clock =
                get_sysvar_with_account_check::clock(invoke_context, instruction_context, 1)?;
            instruction_context.check_number_of_instruction_accounts(3)?;
            let custodian_pubkey =
                get_optional_pubkey(transaction_context, instruction_context, 3, false)?;

            authorize(
                &mut me,
                &signers,
                &authorized_pubkey,
                stake_authorize,
                &clock,
                custodian_pubkey,
            )
        }
        StakeInstruction::AuthorizeWithSeed(args) => {
            let mut me = get_stake_account()?;
            instruction_context.check_number_of_instruction_accounts(2)?;
            let clock =
                get_sysvar_with_account_check::clock(invoke_context, instruction_context, 2)?;
            let custodian_pubkey =
                get_optional_pubkey(transaction_context, instruction_context, 3, false)?;

            authorize_with_seed(
                transaction_context,
                instruction_context,
                &mut me,
                1,
                &args.authority_seed,
                &args.authority_owner,
                &args.new_authorized_pubkey,
                args.stake_authorize,
                &clock,
                custodian_pubkey,
            )
        }
        StakeInstruction::DelegateStake => {
            let me = get_stake_account()?;
            instruction_context.check_number_of_instruction_accounts(2)?;
            let clock =
                get_sysvar_with_account_check::clock(invoke_context, instruction_context, 2)?;
            let stake_history = get_sysvar_with_account_check::stake_history(
                invoke_context,
                instruction_context,
                3,
            )?;
            instruction_context.check_number_of_instruction_accounts(5)?;
            drop(me);
            delegate(
                invoke_context,
                transaction_context,
                instruction_context,
                0,
                1,
                &clock,
                &stake_history,
                &signers,
                invoke_context.get_feature_set(),
            )
        }
        StakeInstruction::Split(lamports) => {
            let me = get_stake_account()?;
            instruction_context.check_number_of_instruction_accounts(2)?;
            drop(me);
            split(
                invoke_context,
                transaction_context,
                instruction_context,
                0,
                lamports,
                1,
                &signers,
            )
        }
        StakeInstruction::Merge => {
            let me = get_stake_account()?;
            instruction_context.check_number_of_instruction_accounts(2)?;
            let clock =
                get_sysvar_with_account_check::clock(invoke_context, instruction_context, 2)?;
            let stake_history = get_sysvar_with_account_check::stake_history(
                invoke_context,
                instruction_context,
                3,
            )?;
            drop(me);
            merge(
                invoke_context,
                transaction_context,
                instruction_context,
                0,
                1,
                &clock,
                &stake_history,
                &signers,
            )
        }
        StakeInstruction::Withdraw(lamports) => {
            let me = get_stake_account()?;
            instruction_context.check_number_of_instruction_accounts(2)?;
            let clock =
                get_sysvar_with_account_check::clock(invoke_context, instruction_context, 2)?;
            let stake_history = get_sysvar_with_account_check::stake_history(
                invoke_context,
                instruction_context,
                3,
            )?;
            instruction_context.check_number_of_instruction_accounts(5)?;
            drop(me);
            withdraw(
                transaction_context,
                instruction_context,
                0,
                lamports,
                1,
                &clock,
                &stake_history,
                4,
                if instruction_context.get_number_of_instruction_accounts() >= 6 {
                    Some(5)
                } else {
                    None
                },
                new_warmup_cooldown_rate_epoch(invoke_context),
            )
        }
        StakeInstruction::Deactivate => {
            let mut me = get_stake_account()?;
            let clock =
                get_sysvar_with_account_check::clock(invoke_context, instruction_context, 1)?;
            deactivate(invoke_context, &mut me, &clock, &signers)
        }
        StakeInstruction::SetLockup(lockup) => {
            let mut me = get_stake_account()?;
            let clock = invoke_context.get_sysvar_cache().get_clock()?;
            set_lockup(&mut me, &lockup, &signers, &clock)
        }
        StakeInstruction::InitializeChecked => {
            let mut me = get_stake_account()?;
            instruction_context.check_number_of_instruction_accounts(4)?;
            let staker_pubkey = transaction_context.get_key_of_account_at_index(
                instruction_context.get_index_of_instruction_account_in_transaction(2)?,
            )?;
            let withdrawer_pubkey = transaction_context.get_key_of_account_at_index(
                instruction_context.get_index_of_instruction_account_in_transaction(3)?,
            )?;
            if !instruction_context.is_instruction_account_signer(3)? {
                return Err(InstructionError::MissingRequiredSignature);
            }

            let authorized = Authorized {
                staker: *staker_pubkey,
                withdrawer: *withdrawer_pubkey,
            };

            let rent = get_sysvar_with_account_check::rent(invoke_context, instruction_context, 1)?;
            initialize(&mut me, &authorized, &Lockup::default(), &rent)
        }
        StakeInstruction::AuthorizeChecked(stake_authorize) => {
            let mut me = get_stake_account()?;
            let clock =
                get_sysvar_with_account_check::clock(invoke_context, instruction_context, 1)?;
            instruction_context.check_number_of_instruction_accounts(4)?;
            let authorized_pubkey = transaction_context.get_key_of_account_at_index(
                instruction_context.get_index_of_instruction_account_in_transaction(3)?,
            )?;
            if !instruction_context.is_instruction_account_signer(3)? {
                return Err(InstructionError::MissingRequiredSignature);
            }
            let custodian_pubkey =
                get_optional_pubkey(transaction_context, instruction_context, 4, false)?;

            authorize(
                &mut me,
                &signers,
                authorized_pubkey,
                stake_authorize,
                &clock,
                custodian_pubkey,
            )
        }
        StakeInstruction::AuthorizeCheckedWithSeed(args) => {
            let mut me = get_stake_account()?;
            instruction_context.check_number_of_instruction_accounts(2)?;
            let clock =
                get_sysvar_with_account_check::clock(invoke_context, instruction_context, 2)?;
            instruction_context.check_number_of_instruction_accounts(4)?;
            let authorized_pubkey = transaction_context.get_key_of_account_at_index(
                instruction_context.get_index_of_instruction_account_in_transaction(3)?,
            )?;
            if !instruction_context.is_instruction_account_signer(3)? {
                return Err(InstructionError::MissingRequiredSignature);
            }
            let custodian_pubkey =
                get_optional_pubkey(transaction_context, instruction_context, 4, false)?;

            authorize_with_seed(
                transaction_context,
                instruction_context,
                &mut me,
                1,
                &args.authority_seed,
                &args.authority_owner,
                authorized_pubkey,
                args.stake_authorize,
                &clock,
                custodian_pubkey,
            )
        }
        StakeInstruction::SetLockupChecked(lockup_checked) => {
            let mut me = get_stake_account()?;
            let custodian_pubkey =
                get_optional_pubkey(transaction_context, instruction_context, 2, true)?;

            let lockup = LockupArgs {
                unix_timestamp: lockup_checked.unix_timestamp,
                epoch: lockup_checked.epoch,
                custodian: custodian_pubkey.cloned(),
            };
            let clock = invoke_context.get_sysvar_cache().get_clock()?;
            set_lockup(&mut me, &lockup, &signers, &clock)
        }
        StakeInstruction::GetMinimumDelegation => {
            let feature_set = invoke_context.get_feature_set();
            let minimum_delegation = crate::get_minimum_delegation(feature_set);
            let minimum_delegation = Vec::from(minimum_delegation.to_le_bytes());
            invoke_context
                .transaction_context
                .set_return_data(id(), minimum_delegation)
        }
        StakeInstruction::DeactivateDelinquent => {
            let mut me = get_stake_account()?;
            instruction_context.check_number_of_instruction_accounts(3)?;

            let clock = invoke_context.get_sysvar_cache().get_clock()?;
            deactivate_delinquent(
                transaction_context,
                instruction_context,
                &mut me,
                1,
                2,
                clock.epoch,
            )
        }
        #[allow(deprecated)]
        StakeInstruction::Redelegate => {
            let _ = get_stake_account()?;
            Err(InstructionError::InvalidInstructionData)
        }
        StakeInstruction::MoveStake(lamports) => {
            if invoke_context
                .get_feature_set()
                .is_active(&solana_feature_set::move_stake_and_move_lamports_ixs::id())
            {
                instruction_context.check_number_of_instruction_accounts(3)?;
                move_stake(
                    invoke_context,
                    transaction_context,
                    instruction_context,
                    0,
                    lamports,
                    1,
                    2,
                )
            } else {
                Err(InstructionError::InvalidInstructionData)
            }
        }
        StakeInstruction::MoveLamports(lamports) => {
            if invoke_context
                .get_feature_set()
                .is_active(&solana_feature_set::move_stake_and_move_lamports_ixs::id())
            {
                instruction_context.check_number_of_instruction_accounts(3)?;
                move_lamports(
                    invoke_context,
                    transaction_context,
                    instruction_context,
                    0,
                    lamports,
                    1,
                    2,
                )
            } else {
                Err(InstructionError::InvalidInstructionData)
            }
        }
    }
});
