use {
    crate::compute_budget_instruction_details::*, solana_compute_budget::compute_budget_limits::*,
    solana_feature_set::FeatureSet, solana_pubkey::Pubkey,
    solana_svm_transaction::instruction::SVMInstruction,
    solana_transaction_error::TransactionError,
};

/// Processing compute_budget could be part of tx sanitizing, failed to process
/// these instructions will drop the transaction eventually without execution,
/// may as well fail it early.
/// If succeeded, the transaction's specific limits/requests (could be default)
/// are retrieved and returned,
pub fn process_compute_budget_instructions<'a>(
    instructions: impl Iterator<Item = (&'a Pubkey, SVMInstruction<'a>)> + Clone,
    feature_set: &FeatureSet,
) -> Result<ComputeBudgetLimits, TransactionError> {
    ComputeBudgetInstructionDetails::try_from(instructions)?
        .sanitize_and_convert_to_compute_budget_limits(feature_set)
}
