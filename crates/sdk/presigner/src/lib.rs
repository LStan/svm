pub use solana_signer::PresignerError;
use {
    solana_pubkey::Pubkey,
    solana_signature::Signature,
    solana_signer::{Signer, SignerError},
};

/// A `Signer` implementation that represents a `Signature` that has been
/// constructed externally. Performs a signature verification against the
/// expected message upon `sign()` requests to affirm its relationship to
/// the `message` bytes
#[derive(Clone, Debug, Default)]
pub struct Presigner {
    pubkey: Pubkey,
    signature: Signature,
}

impl Presigner {
    pub fn new(pubkey: &Pubkey, signature: &Signature) -> Self {
        Self {
            pubkey: *pubkey,
            signature: *signature,
        }
    }
}

impl Signer for Presigner {
    fn try_pubkey(&self) -> Result<Pubkey, SignerError> {
        Ok(self.pubkey)
    }

    fn try_sign_message(&self, message: &[u8]) -> Result<Signature, SignerError> {
        if self.signature.verify(self.pubkey.as_ref(), message) {
            Ok(self.signature)
        } else {
            Err(PresignerError::VerificationFailure.into())
        }
    }

    fn is_interactive(&self) -> bool {
        false
    }
}

impl<T> PartialEq<T> for Presigner
where
    T: Signer,
{
    fn eq(&self, other: &T) -> bool {
        self.pubkey() == other.pubkey()
    }
}
