use {
    solana_account::ReadableAccount,
    solana_sdk_ids::native_loader,
    solana_svm_rent_collector::{rent_state::RentState, svm_rent_collector::SVMRentCollector},
    solana_svm_transaction::svm_message::SVMMessage,
    solana_transaction_context::{IndexOfAccount, TransactionContext},
    solana_transaction_error::TransactionResult as Result,
};

#[derive(PartialEq, Debug)]
pub(crate) struct TransactionAccountStateInfo {
    rent_state: Option<RentState>, // None: readonly account
}

impl TransactionAccountStateInfo {
    pub(crate) fn new(
        transaction_context: &TransactionContext,
        message: &impl SVMMessage,
        rent_collector: &dyn SVMRentCollector,
    ) -> Vec<Self> {
        (0..message.account_keys().len())
            .map(|i| {
                let rent_state = if message.is_writable(i) {
                    let state = if let Ok(account) =
                        transaction_context.get_account_at_index(i as IndexOfAccount)
                    {
                        let account = account.borrow();

                        // Native programs appear to be RentPaying because they carry low lamport
                        // balances; however they will never be loaded as writable
                        debug_assert!(!native_loader::check_id(account.owner()));

                        Some(rent_collector.get_account_rent_state(&account))
                    } else {
                        None
                    };
                    debug_assert!(
                        state.is_some(),
                        "message and transaction context out of sync, fatal"
                    );
                    state
                } else {
                    None
                };
                Self { rent_state }
            })
            .collect()
    }

    pub(crate) fn verify_changes(
        pre_state_infos: &[Self],
        post_state_infos: &[Self],
        transaction_context: &TransactionContext,
        rent_collector: &dyn SVMRentCollector,
    ) -> Result<()> {
        for (i, (pre_state_info, post_state_info)) in
            pre_state_infos.iter().zip(post_state_infos).enumerate()
        {
            rent_collector.check_rent_state(
                pre_state_info.rent_state.as_ref(),
                post_state_info.rent_state.as_ref(),
                transaction_context,
                i as IndexOfAccount,
            )?;
        }
        Ok(())
    }
}
