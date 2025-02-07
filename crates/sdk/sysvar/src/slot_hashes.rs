//! The most recent hashes of a slot's parent banks.
//!
//! The _slot hashes sysvar_ provides access to the [`SlotHashes`] type.
//!
//! The [`Sysvar::from_account_info`] and [`Sysvar::get`] methods always return
//! [`solana_program_error::ProgramError::UnsupportedSysvar`] because this sysvar account is too large
//! to process on-chain. Thus this sysvar cannot be accessed on chain, though
//! one can still use the [`SysvarId::id`], [`SysvarId::check_id`] and
//! [`Sysvar::size_of`] methods in an on-chain program, and it can be accessed
//! off-chain through RPC.
//!
//! [`SysvarId::id`]: https://docs.rs/solana-sysvar-id/latest/solana_sysvar_id/trait.SysvarId.html#tymethod.id
//! [`SysvarId::check_id`]: https://docs.rs/solana-sysvar-id/latest/solana_sysvar_id/trait.SysvarId.html#tymethod.check_id
//!
//! # Examples
//!
//! Calling via the RPC client:
//!
//! ```
//! # use solana_program::example_mocks::solana_sdk;
//! # use solana_program::example_mocks::solana_rpc_client;
//! # use solana_sdk::account::Account;
//! # use solana_rpc_client::rpc_client::RpcClient;
//! # use solana_sdk_ids::sysvar::slot_hashes;
//! # use solana_slot_hashes::SlotHashes;
//! # use anyhow::Result;
//! #
//! fn print_sysvar_slot_hashes(client: &RpcClient) -> Result<()> {
//! #   client.set_get_account_response(slot_hashes::ID, Account {
//! #       lamports: 1009200,
//! #       data: vec![1, 0, 0, 0, 0, 0, 0, 0, 86, 190, 235, 7, 0, 0, 0, 0, 133, 242, 94, 158, 223, 253, 207, 184, 227, 194, 235, 27, 176, 98, 73, 3, 175, 201, 224, 111, 21, 65, 73, 27, 137, 73, 229, 19, 255, 192, 193, 126],
//! #       owner: solana_sdk_ids::system_program::ID,
//! #       executable: false,
//! #       rent_epoch: 307,
//! # });
//! #
//!     let slot_hashes = client.get_account(&slot_hashes::ID)?;
//!     let data: SlotHashes = bincode::deserialize(&slot_hashes.data)?;
//!
//!     Ok(())
//! }
//! #
//! # let client = RpcClient::new(String::new());
//! # print_sysvar_slot_hashes(&client)?;
//! #
//! # Ok::<(), anyhow::Error>(())
//! ```

#[cfg(feature = "bytemuck")]
use bytemuck_derive::{Pod, Zeroable};
#[cfg(feature = "bincode")]
use {crate::Sysvar, solana_account_info::AccountInfo};
use {solana_clock::Slot, solana_hash::Hash};

#[cfg(all(feature = "bincode", feature = "bytemuck"))]
const U64_SIZE: usize = std::mem::size_of::<u64>();

pub use {
    solana_sdk_ids::sysvar::slot_hashes::{check_id, id, ID},
    solana_slot_hashes::SlotHashes,
    solana_sysvar_id::SysvarId,
};

#[cfg(feature = "bincode")]
impl Sysvar for SlotHashes {
    // override
    fn size_of() -> usize {
        // hard-coded so that we don't have to construct an empty
        20_488 // golden, update if MAX_ENTRIES changes
    }
    fn from_account_info(
        _account_info: &AccountInfo,
    ) -> Result<Self, solana_program_error::ProgramError> {
        // This sysvar is too large to bincode::deserialize in-program
        Err(solana_program_error::ProgramError::UnsupportedSysvar)
    }
}

/// A bytemuck-compatible (plain old data) version of `SlotHash`.
#[cfg_attr(feature = "bytemuck", derive(Pod, Zeroable))]
#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct PodSlotHash {
    pub slot: Slot,
    pub hash: Hash,
}

#[cfg(feature = "bytemuck")]
/// API for querying of the `SlotHashes` sysvar by on-chain programs.
///
/// Hangs onto the allocated raw buffer from the account data, which can be
/// queried or accessed directly as a slice of `PodSlotHash`.
#[derive(Default)]
pub struct PodSlotHashes {
    data: Vec<u8>,
    slot_hashes_start: usize,
    slot_hashes_end: usize,
}

#[cfg(feature = "bytemuck")]
impl PodSlotHashes {
    /// Fetch all of the raw sysvar data using the `sol_get_sysvar` syscall.
    pub fn fetch() -> Result<Self, solana_program_error::ProgramError> {
        // Allocate an uninitialized buffer for the raw sysvar data.
        let sysvar_len = SlotHashes::size_of();
        let mut data = vec![0; sysvar_len];

        // Ensure the created buffer is aligned to 8.
        if data.as_ptr().align_offset(8) != 0 {
            return Err(solana_program_error::ProgramError::InvalidAccountData);
        }

        // Populate the buffer by fetching all sysvar data using the
        // `sol_get_sysvar` syscall.
        crate::get_sysvar(
            &mut data,
            &SlotHashes::id(),
            /* offset */ 0,
            /* length */ sysvar_len as u64,
        )?;

        // Get the number of slot hashes present in the data by reading the
        // `u64` length at the beginning of the data, then use that count to
        // calculate the length of the slot hashes data.
        //
        // The rest of the buffer is uninitialized and should not be accessed.
        let length = data
            .get(..U64_SIZE)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u64::from_le_bytes)
            .and_then(|length| length.checked_mul(std::mem::size_of::<PodSlotHash>() as u64))
            .ok_or(solana_program_error::ProgramError::InvalidAccountData)?;

        let slot_hashes_start = U64_SIZE;
        let slot_hashes_end = slot_hashes_start.saturating_add(length as usize);

        Ok(Self {
            data,
            slot_hashes_start,
            slot_hashes_end,
        })
    }

    /// Return the `SlotHashes` sysvar data as a slice of `PodSlotHash`.
    /// Returns a slice of only the initialized sysvar data.
    pub fn as_slice(&self) -> Result<&[PodSlotHash], solana_program_error::ProgramError> {
        self.data
            .get(self.slot_hashes_start..self.slot_hashes_end)
            .and_then(|data| bytemuck::try_cast_slice(data).ok())
            .ok_or(solana_program_error::ProgramError::InvalidAccountData)
    }

    /// Given a slot, get its corresponding hash in the `SlotHashes` sysvar
    /// data. Returns `None` if the slot is not found.
    pub fn get(&self, slot: &Slot) -> Result<Option<Hash>, solana_program_error::ProgramError> {
        self.as_slice().map(|pod_hashes| {
            pod_hashes
                .binary_search_by(|PodSlotHash { slot: this, .. }| slot.cmp(this))
                .map(|idx| pod_hashes[idx].hash)
                .ok()
        })
    }

    /// Given a slot, get its position in the `SlotHashes` sysvar data. Returns
    /// `None` if the slot is not found.
    pub fn position(
        &self,
        slot: &Slot,
    ) -> Result<Option<usize>, solana_program_error::ProgramError> {
        self.as_slice().map(|pod_hashes| {
            pod_hashes
                .binary_search_by(|PodSlotHash { slot: this, .. }| slot.cmp(this))
                .ok()
        })
    }
}

/// API for querying the `SlotHashes` sysvar.
#[deprecated(since = "2.1.0", note = "Please use `PodSlotHashes` instead")]
pub struct SlotHashesSysvar;

#[cfg(feature = "bincode")]
#[allow(deprecated)]
impl SlotHashesSysvar {
    #[cfg(feature = "bytemuck")]
    /// Get a value from the sysvar entries by its key.
    /// Returns `None` if the key is not found.
    pub fn get(slot: &Slot) -> Result<Option<Hash>, solana_program_error::ProgramError> {
        get_pod_slot_hashes().map(|pod_hashes| {
            pod_hashes
                .binary_search_by(|PodSlotHash { slot: this, .. }| slot.cmp(this))
                .map(|idx| pod_hashes[idx].hash)
                .ok()
        })
    }

    #[cfg(feature = "bytemuck")]
    /// Get the position of an entry in the sysvar by its key.
    /// Returns `None` if the key is not found.
    pub fn position(slot: &Slot) -> Result<Option<usize>, solana_program_error::ProgramError> {
        get_pod_slot_hashes().map(|pod_hashes| {
            pod_hashes
                .binary_search_by(|PodSlotHash { slot: this, .. }| slot.cmp(this))
                .ok()
        })
    }
}

#[cfg(feature = "bytemuck")]
fn get_pod_slot_hashes() -> Result<Vec<PodSlotHash>, solana_program_error::ProgramError> {
    let mut pod_hashes = vec![PodSlotHash::default(); solana_slot_hashes::MAX_ENTRIES];
    {
        let data = bytemuck::try_cast_slice_mut::<PodSlotHash, u8>(&mut pod_hashes)
            .map_err(|_| solana_program_error::ProgramError::InvalidAccountData)?;

        // Ensure the created buffer is aligned to 8.
        if data.as_ptr().align_offset(8) != 0 {
            return Err(solana_program_error::ProgramError::InvalidAccountData);
        }

        let offset = 8; // Vector length as `u64`.
        let length = (SlotHashes::size_of() as u64).saturating_sub(offset);
        crate::get_sysvar(data, &SlotHashes::id(), offset, length)?;
    }
    Ok(pod_hashes)
}
