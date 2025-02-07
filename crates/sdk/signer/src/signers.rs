use {
    crate::{Signer, SignerError},
    solana_pubkey::Pubkey,
    solana_signature::Signature,
};

/// Convenience trait for working with mixed collections of `Signer`s
pub trait Signers {
    fn pubkeys(&self) -> Vec<Pubkey>;
    fn try_pubkeys(&self) -> Result<Vec<Pubkey>, SignerError>;
    fn sign_message(&self, message: &[u8]) -> Vec<Signature>;
    fn try_sign_message(&self, message: &[u8]) -> Result<Vec<Signature>, SignerError>;
    fn is_interactive(&self) -> bool;
}

/// Any `T` where `T` impls `IntoIterator` yielding
/// `Signer`s implements `Signers`.
///
/// This includes `[&dyn Signer]`, `[Box<dyn Signer>]`,
/// `[&dyn Signer; N]`, `Vec<dyn Signer>`, `Vec<Keypair>`, etc.
///
/// When used as a generic function param, `&T`
/// should be used instead of `T` where T: Signers, due to the `?Sized` bounds on T.
/// E.g. [Signer] implements `Signers`, but `&[Signer]` does not
impl<T: ?Sized, S: Signer + ?Sized> Signers for T
where
    for<'a> &'a T: IntoIterator<Item = &'a S>,
{
    fn pubkeys(&self) -> Vec<Pubkey> {
        self.into_iter().map(|keypair| keypair.pubkey()).collect()
    }

    fn try_pubkeys(&self) -> Result<Vec<Pubkey>, SignerError> {
        self.into_iter()
            .map(|keypair| keypair.try_pubkey())
            .collect()
    }

    fn sign_message(&self, message: &[u8]) -> Vec<Signature> {
        self.into_iter()
            .map(|keypair| keypair.sign_message(message))
            .collect()
    }

    fn try_sign_message(&self, message: &[u8]) -> Result<Vec<Signature>, SignerError> {
        self.into_iter()
            .map(|keypair| keypair.try_sign_message(message))
            .collect()
    }

    fn is_interactive(&self) -> bool {
        self.into_iter().any(|s| s.is_interactive())
    }
}
