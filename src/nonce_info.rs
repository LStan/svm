#[cfg(feature = "dev-context-only-utils")]
use {
    qualifier_attr::qualifiers,
    solana_account::state_traits::StateMut,
    solana_nonce::{
        state::{DurableNonce, State as NonceState},
        versions::Versions as NonceVersions,
    },
    thiserror::Error,
};
use {solana_account::AccountSharedData, solana_pubkey::Pubkey};

/// Holds limited nonce info available during transaction checks
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NonceInfo {
    address: Pubkey,
    account: AccountSharedData,
}

#[derive(Error, Debug, PartialEq)]
#[cfg(feature = "dev-context-only-utils")]
#[cfg_attr(feature = "dev-context-only-utils", qualifiers(pub))]
enum AdvanceNonceError {
    #[error("Invalid account")]
    Invalid,
    #[error("Uninitialized nonce")]
    Uninitialized,
}

impl NonceInfo {
    pub fn new(address: Pubkey, account: AccountSharedData) -> Self {
        Self { address, account }
    }

    // Advance the stored blockhash to prevent fee theft by someone
    // replaying nonce transactions that have failed with an
    // `InstructionError`.
    #[cfg(feature = "dev-context-only-utils")]
    #[cfg_attr(feature = "dev-context-only-utils", qualifiers(pub))]
    fn try_advance_nonce(
        &mut self,
        durable_nonce: DurableNonce,
        lamports_per_signature: u64,
    ) -> Result<(), AdvanceNonceError> {
        let nonce_versions = StateMut::<NonceVersions>::state(&self.account)
            .map_err(|_| AdvanceNonceError::Invalid)?;
        if let NonceState::Initialized(ref data) = nonce_versions.state() {
            let nonce_state =
                NonceState::new_initialized(&data.authority, durable_nonce, lamports_per_signature);
            let nonce_versions = NonceVersions::new(nonce_state);
            self.account.set_state(&nonce_versions).unwrap();
            Ok(())
        } else {
            Err(AdvanceNonceError::Uninitialized)
        }
    }

    pub fn address(&self) -> &Pubkey {
        &self.address
    }

    pub fn account(&self) -> &AccountSharedData {
        &self.account
    }
}
