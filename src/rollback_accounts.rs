use {
    crate::nonce_info::NonceInfo,
    solana_account::{AccountSharedData, ReadableAccount, WritableAccount},
    solana_clock::Epoch,
    solana_pubkey::Pubkey,
};

/// Captured account state used to rollback account state for nonce and fee
/// payer accounts after a failed executed transaction.
#[derive(PartialEq, Eq, Debug, Clone)]
pub enum RollbackAccounts {
    FeePayerOnly {
        fee_payer_account: AccountSharedData,
    },
    SameNonceAndFeePayer {
        nonce: NonceInfo,
    },
    SeparateNonceAndFeePayer {
        nonce: NonceInfo,
        fee_payer_account: AccountSharedData,
    },
}

#[cfg(feature = "dev-context-only-utils")]
impl Default for RollbackAccounts {
    fn default() -> Self {
        Self::FeePayerOnly {
            fee_payer_account: AccountSharedData::default(),
        }
    }
}

impl RollbackAccounts {
    pub(crate) fn new(
        nonce: Option<NonceInfo>,
        fee_payer_address: Pubkey,
        mut fee_payer_account: AccountSharedData,
        fee_payer_rent_debit: u64,
        fee_payer_loaded_rent_epoch: Epoch,
    ) -> Self {
        // When the fee payer account is rolled back due to transaction failure,
        // rent should not be charged so credit the previously debited rent
        // amount.
        fee_payer_account.set_lamports(
            fee_payer_account
                .lamports()
                .saturating_add(fee_payer_rent_debit),
        );

        if let Some(nonce) = nonce {
            if &fee_payer_address == nonce.address() {
                // `nonce` contains an AccountSharedData which has already been advanced to the current DurableNonce
                // `fee_payer_account` is an AccountSharedData as it currently exists on-chain
                // thus if the nonce account is being used as the fee payer, we need to update that data here
                // so we capture both the data change for the nonce and the lamports/rent epoch change for the fee payer
                fee_payer_account.set_data_from_slice(nonce.account().data());

                RollbackAccounts::SameNonceAndFeePayer {
                    nonce: NonceInfo::new(fee_payer_address, fee_payer_account),
                }
            } else {
                RollbackAccounts::SeparateNonceAndFeePayer {
                    nonce,
                    fee_payer_account,
                }
            }
        } else {
            // When rolling back failed transactions which don't use nonces, the
            // runtime should not update the fee payer's rent epoch so reset the
            // rollback fee payer account's rent epoch to its originally loaded
            // rent epoch value. In the future, a feature gate could be used to
            // alter this behavior such that rent epoch updates are handled the
            // same for both nonce and non-nonce failed transactions.
            fee_payer_account.set_rent_epoch(fee_payer_loaded_rent_epoch);
            RollbackAccounts::FeePayerOnly { fee_payer_account }
        }
    }

    /// Number of accounts tracked for rollback
    pub fn count(&self) -> usize {
        match self {
            Self::FeePayerOnly { .. } | Self::SameNonceAndFeePayer { .. } => 1,
            Self::SeparateNonceAndFeePayer { .. } => 2,
        }
    }

    /// Size of accounts tracked for rollback, used when calculating the actual
    /// cost of transaction processing in the cost model.
    pub fn data_size(&self) -> usize {
        match self {
            Self::FeePayerOnly { fee_payer_account } => fee_payer_account.data().len(),
            Self::SameNonceAndFeePayer { nonce } => nonce.account().data().len(),
            Self::SeparateNonceAndFeePayer {
                nonce,
                fee_payer_account,
            } => fee_payer_account
                .data()
                .len()
                .saturating_add(nonce.account().data().len()),
        }
    }
}
