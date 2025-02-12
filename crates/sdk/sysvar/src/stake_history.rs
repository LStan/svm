//! History of stake activations and de-activations.
//!
//! The _stake history sysvar_ provides access to the [`StakeHistory`] type.
//!
//! The [`Sysvar::get`] method always returns
//! [`ProgramError::UnsupportedSysvar`], and in practice the data size of this
//! sysvar is too large to process on chain. One can still use the
//! [`SysvarId::id`], [`SysvarId::check_id`] and [`Sysvar::size_of`] methods in
//! an on-chain program, and it can be accessed off-chain through RPC.
//!
//! [`ProgramError::UnsupportedSysvar`]: https://docs.rs/solana-program-error/latest/solana_program_error/enum.ProgramError.html#variant.UnsupportedSysvar
//! [`SysvarId::id`]: https://docs.rs/solana-sysvar-id/latest/solana_sysvar_id/trait.SysvarId.html
//! [`SysvarId::check_id`]: https://docs.rs/solana-sysvar-id/latest/solana_sysvar_id/trait.SysvarId.html#tymethod.check_id
//!
//! # Examples
//!
//! Calling via the RPC client:
//!
//! ```
//! # use solana_program::example_mocks::solana_sdk;
//! # use solana_program::example_mocks::solana_rpc_client;
//! # use solana_program::stake_history::StakeHistory;
//! # use solana_sdk::account::Account;
//! # use solana_rpc_client::rpc_client::RpcClient;
//! # use solana_sdk_ids::sysvar::stake_history;
//! # use anyhow::Result;
//! #
//! fn print_sysvar_stake_history(client: &RpcClient) -> Result<()> {
//! #   client.set_get_account_response(stake_history::ID, Account {
//! #       lamports: 114979200,
//! #       data: vec![0, 0, 0, 0, 0, 0, 0, 0],
//! #       owner: solana_sdk_ids::system_program::ID,
//! #       executable: false,
//! #       rent_epoch: 307,
//! #   });
//! #
//!     let stake_history = client.get_account(&stake_history::ID)?;
//!     let data: StakeHistory = bincode::deserialize(&stake_history.data)?;
//!
//!     Ok(())
//! }
//! #
//! # let client = RpcClient::new(String::new());
//! # print_sysvar_stake_history(&client)?;
//! #
//! # Ok::<(), anyhow::Error>(())
//! ```

#[cfg(feature = "bincode")]
use crate::Sysvar;
pub use solana_sdk_ids::sysvar::stake_history::{check_id, id, ID};
#[deprecated(
    since = "2.2.0",
    note = "Use solana_stake_interface::stake_history instead"
)]
pub use crate::stake_history_impl::{
    StakeHistory, StakeHistoryEntry, StakeHistoryGetEntry, MAX_ENTRIES,
};
use {crate::get_sysvar, solana_clock::Epoch};

#[cfg(feature = "bincode")]
impl Sysvar for StakeHistory {
    // override
    fn size_of() -> usize {
        // hard-coded so that we don't have to construct an empty
        16392 // golden, update if MAX_ENTRIES changes
    }
}

// we do not provide Default because this requires the real current epoch
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct StakeHistorySysvar(pub Epoch);

// precompute so we can statically allocate buffer
const EPOCH_AND_ENTRY_SERIALIZED_SIZE: u64 = 32;

impl StakeHistoryGetEntry for StakeHistorySysvar {
    fn get_entry(&self, target_epoch: Epoch) -> Option<StakeHistoryEntry> {
        let current_epoch = self.0;

        // if current epoch is zero this returns None because there is no history yet
        let newest_historical_epoch = current_epoch.checked_sub(1)?;
        let oldest_historical_epoch = current_epoch.saturating_sub(MAX_ENTRIES as u64);

        // target epoch is old enough to have fallen off history; presume fully active/deactive
        if target_epoch < oldest_historical_epoch {
            return None;
        }

        // epoch delta is how many epoch-entries we offset in the stake history vector, which may be zero
        // None means target epoch is current or in the future; this is a user error
        let epoch_delta = newest_historical_epoch.checked_sub(target_epoch)?;

        // offset is the number of bytes to our desired entry, including eight for vector length
        let offset = epoch_delta
            .checked_mul(EPOCH_AND_ENTRY_SERIALIZED_SIZE)?
            .checked_add(std::mem::size_of::<u64>() as u64)?;

        let mut entry_buf = [0; EPOCH_AND_ENTRY_SERIALIZED_SIZE as usize];
        let result = get_sysvar(
            &mut entry_buf,
            &id(),
            offset,
            EPOCH_AND_ENTRY_SERIALIZED_SIZE,
        );

        match result {
            Ok(()) => {
                // All safe because `entry_buf` is a 32-length array
                let entry_epoch = u64::from_le_bytes(entry_buf[0..8].try_into().unwrap());
                let effective = u64::from_le_bytes(entry_buf[8..16].try_into().unwrap());
                let activating = u64::from_le_bytes(entry_buf[16..24].try_into().unwrap());
                let deactivating = u64::from_le_bytes(entry_buf[24..32].try_into().unwrap());

                // this would only fail if stake history skipped an epoch or the binary format of the sysvar changed
                assert_eq!(entry_epoch, target_epoch);

                Some(StakeHistoryEntry {
                    effective,
                    activating,
                    deactivating,
                })
            }
            _ => None,
        }
    }
}
