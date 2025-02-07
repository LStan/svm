use {siphasher::sip::SipHasher13, solana_hash::Hash, solana_pubkey::Pubkey, std::hash::Hasher};

#[derive(Debug, Clone)]
pub struct EpochRewardsHasher {
    hasher: SipHasher13,
    partitions: usize,
}

impl EpochRewardsHasher {
    /// Use SipHasher13 keyed on the `seed` for calculating epoch reward partition
    pub fn new(partitions: usize, seed: &Hash) -> Self {
        let mut hasher = SipHasher13::new();
        hasher.write(seed.as_ref());
        Self { hasher, partitions }
    }

    /// Return partition index (0..partitions) by hashing `address` with the `hasher`
    pub fn hash_address_to_partition(self, address: &Pubkey) -> usize {
        let Self {
            mut hasher,
            partitions,
        } = self;
        hasher.write(address.as_ref());
        let hash64 = hasher.finish();

        hash_to_partition(hash64, partitions)
    }
}

/// Compute the partition index by modulo the address hash to number of partitions w.o bias.
/// (rand_int * DESIRED_RANGE_MAX) / (RAND_MAX + 1)
// Clippy objects to `u128::from(u64::MAX).saturating_add(1)`, even though it
// can never overflow
#[allow(clippy::arithmetic_side_effects)]
fn hash_to_partition(hash: u64, partitions: usize) -> usize {
    ((partitions as u128)
        .saturating_mul(u128::from(hash))
        .saturating_div(u128::from(u64::MAX).saturating_add(1))) as usize
}
