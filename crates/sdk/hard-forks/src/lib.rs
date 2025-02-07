//! The list of slot boundaries at which a hard fork should
//! occur.

#![cfg_attr(feature = "frozen-abi", feature(min_specialization))]

#[cfg_attr(feature = "frozen-abi", derive(solana_frozen_abi_macro::AbiExample))]
#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Deserialize, serde_derive::Serialize)
)]
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HardForks {
    hard_forks: Vec<(u64, usize)>,
}
impl HardForks {
    // Register a fork to occur at all slots >= `slot` with a parent slot < `slot`
    pub fn register(&mut self, new_slot: u64) {
        if let Some(i) = self
            .hard_forks
            .iter()
            .position(|(slot, _)| *slot == new_slot)
        {
            self.hard_forks[i] = (new_slot, self.hard_forks[i].1.saturating_add(1));
        } else {
            self.hard_forks.push((new_slot, 1));
        }
        #[allow(clippy::stable_sort_primitive)]
        self.hard_forks.sort();
    }

    // Returns a sorted-by-slot iterator over the registered hark forks
    pub fn iter(&self) -> std::slice::Iter<(u64, usize)> {
        self.hard_forks.iter()
    }

    // Returns `true` is there are currently no registered hard forks
    pub fn is_empty(&self) -> bool {
        self.hard_forks.is_empty()
    }

    // Returns data to include in the bank hash for the given slot if a hard fork is scheduled
    pub fn get_hash_data(&self, slot: u64, parent_slot: u64) -> Option<[u8; 8]> {
        // The expected number of hard forks in a cluster is small.
        // If this turns out to be false then a more efficient data
        // structure may be needed here to avoid this linear search
        let fork_count: usize = self
            .hard_forks
            .iter()
            .map(|(fork_slot, fork_count)| {
                if parent_slot < *fork_slot && slot >= *fork_slot {
                    *fork_count
                } else {
                    0
                }
            })
            .sum();

        (fork_count > 0).then(|| (fork_count as u64).to_le_bytes())
    }
}
