//! Implementation of `SVMRentCollector` for `RentCollector` from the Solana
//! SDK.

use {
    crate::svm_rent_collector::SVMRentCollector,
    solana_sdk::{
        account::AccountSharedData,
        clock::Epoch,
        pubkey::Pubkey,
        rent::{Rent, RentDue},
        rent_collector::{CollectedInfo, RentCollector},
    },
};

impl SVMRentCollector for RentCollector {
    fn collect_rent(&self, address: &Pubkey, account: &mut AccountSharedData) -> CollectedInfo {
        self.collect_from_existing_account(address, account)
    }

    fn get_rent(&self) -> &Rent {
        &self.rent
    }

    fn get_rent_due(&self, lamports: u64, data_len: usize, account_rent_epoch: Epoch) -> RentDue {
        self.get_rent_due(lamports, data_len, account_rent_epoch)
    }
}
