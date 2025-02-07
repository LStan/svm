//! Functions related to nonce accounts.

use {
    solana_account::{state_traits::StateMut, AccountSharedData, ReadableAccount},
    solana_hash::Hash,
    solana_nonce::{
        state::{Data, State},
        versions::Versions,
    },
    solana_sdk_ids::system_program,
    std::cell::RefCell,
};

pub fn create_account(lamports: u64) -> RefCell<AccountSharedData> {
    RefCell::new(
        AccountSharedData::new_data_with_space(
            lamports,
            &Versions::new(State::Uninitialized),
            State::size(),
            &system_program::id(),
        )
        .expect("nonce_account"),
    )
}

/// Checks if the recent_blockhash field in Transaction verifies, and returns
/// nonce account data if so.
pub fn verify_nonce_account(
    account: &AccountSharedData,
    recent_blockhash: &Hash, // Transaction.message.recent_blockhash
) -> Option<Data> {
    (account.owner() == &system_program::id())
        .then(|| {
            StateMut::<Versions>::state(account)
                .ok()?
                .verify_recent_blockhash(recent_blockhash)
                .cloned()
        })
        .flatten()
}

pub fn lamports_per_signature_of(account: &AccountSharedData) -> Option<u64> {
    match StateMut::<Versions>::state(account).ok()?.state() {
        State::Initialized(data) => Some(data.fee_calculator.lamports_per_signature),
        State::Uninitialized => None,
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SystemAccountKind {
    System,
    Nonce,
}

pub fn get_system_account_kind(account: &AccountSharedData) -> Option<SystemAccountKind> {
    if system_program::check_id(account.owner()) {
        if account.data().is_empty() {
            Some(SystemAccountKind::System)
        } else if account.data().len() == State::size() {
            let nonce_versions: Versions = account.state().ok()?;
            match nonce_versions.state() {
                State::Uninitialized => None,
                State::Initialized(_) => Some(SystemAccountKind::Nonce),
            }
        } else {
            None
        }
    } else {
        None
    }
}
