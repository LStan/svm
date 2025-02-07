#[cfg(feature = "serde")]
use serde_derive::{Deserialize, Serialize};
use {
    solana_fee_calculator::FeeCalculator, solana_hash::Hash, solana_pubkey::Pubkey,
    solana_sha256_hasher::hashv,
};

const DURABLE_NONCE_HASH_PREFIX: &[u8] = "DURABLE_NONCE".as_bytes();

#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DurableNonce(Hash);

/// Initialized data of a durable transaction nonce account.
///
/// This is stored within [`State`] for initialized nonce accounts.
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub struct Data {
    /// Address of the account that signs transactions using the nonce account.
    pub authority: Pubkey,
    /// Durable nonce value derived from a valid previous blockhash.
    pub durable_nonce: DurableNonce,
    /// The fee calculator associated with the blockhash.
    pub fee_calculator: FeeCalculator,
}

impl Data {
    /// Create new durable transaction nonce data.
    pub fn new(
        authority: Pubkey,
        durable_nonce: DurableNonce,
        lamports_per_signature: u64,
    ) -> Self {
        Data {
            authority,
            durable_nonce,
            fee_calculator: FeeCalculator::new(lamports_per_signature),
        }
    }

    /// Hash value used as recent_blockhash field in Transactions.
    /// Named blockhash for legacy reasons, but durable nonce and blockhash
    /// have separate domains.
    pub fn blockhash(&self) -> Hash {
        self.durable_nonce.0
    }

    /// Get the cost per signature for the next transaction to use this nonce.
    pub fn get_lamports_per_signature(&self) -> u64 {
        self.fee_calculator.lamports_per_signature
    }
}

impl DurableNonce {
    pub fn from_blockhash(blockhash: &Hash) -> Self {
        Self(hashv(&[DURABLE_NONCE_HASH_PREFIX, blockhash.as_ref()]))
    }

    /// Hash value used as recent_blockhash field in Transactions.
    pub fn as_hash(&self) -> &Hash {
        &self.0
    }
}

/// The state of a durable transaction nonce account.
///
/// When created in memory with [`State::default`] or when deserialized from an
/// uninitialized account, a nonce account will be [`State::Uninitialized`].
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
#[derive(Debug, Default, PartialEq, Eq, Clone)]
pub enum State {
    #[default]
    Uninitialized,
    Initialized(Data),
}

impl State {
    /// Create new durable transaction nonce state.
    pub fn new_initialized(
        authority: &Pubkey,
        durable_nonce: DurableNonce,
        lamports_per_signature: u64,
    ) -> Self {
        Self::Initialized(Data::new(*authority, durable_nonce, lamports_per_signature))
    }

    /// Get the serialized size of the nonce state.
    pub const fn size() -> usize {
        80 // see test_nonce_state_size.
    }
}
