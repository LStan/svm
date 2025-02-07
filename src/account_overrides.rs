use {
    solana_account::AccountSharedData, solana_pubkey::Pubkey, solana_sdk_ids::sysvar,
    std::collections::HashMap,
};

/// Encapsulates overridden accounts, typically used for transaction
/// simulations. Account overrides are currently not used when loading the
/// durable nonce account or when constructing the instructions sysvar account.
#[derive(Default)]
pub struct AccountOverrides {
    accounts: HashMap<Pubkey, AccountSharedData>,
}

impl AccountOverrides {
    /// Insert or remove an account with a given pubkey to/from the list of overrides.
    fn set_account(&mut self, pubkey: &Pubkey, account: Option<AccountSharedData>) {
        match account {
            Some(account) => self.accounts.insert(*pubkey, account),
            None => self.accounts.remove(pubkey),
        };
    }

    /// Sets in the slot history
    ///
    /// Note: no checks are performed on the correctness of the contained data
    pub fn set_slot_history(&mut self, slot_history: Option<AccountSharedData>) {
        self.set_account(&sysvar::slot_history::id(), slot_history);
    }

    /// Gets the account if it's found in the list of overrides
    pub(crate) fn get(&self, pubkey: &Pubkey) -> Option<&AccountSharedData> {
        self.accounts.get(pubkey)
    }
}
