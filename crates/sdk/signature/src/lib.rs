//! 64-byte signature type.
#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(feature = "frozen-abi", feature(min_specialization))]
#[cfg(any(test, feature = "verify"))]
use core::convert::TryInto;
use core::{
    fmt,
    str::{from_utf8, FromStr},
};
#[cfg(feature = "std")]
extern crate std;
#[cfg(feature = "std")]
use std::{error::Error, vec::Vec};
#[cfg(feature = "serde")]
use {
    serde_big_array::BigArray,
    serde_derive::{Deserialize, Serialize},
};

/// Number of bytes in a signature
pub const SIGNATURE_BYTES: usize = 64;
/// Maximum string length of a base58 encoded signature
const MAX_BASE58_SIGNATURE_LEN: usize = 88;

#[repr(transparent)]
#[cfg_attr(feature = "frozen-abi", derive(solana_frozen_abi_macro::AbiExample))]
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Deserialize, Serialize))]
pub struct Signature(
    #[cfg_attr(feature = "serde", serde(with = "BigArray"))] [u8; SIGNATURE_BYTES],
);

impl Default for Signature {
    fn default() -> Self {
        Self([0u8; 64])
    }
}

impl solana_sanitize::Sanitize for Signature {}

#[cfg(feature = "rand")]
impl Signature {
    pub fn new_unique() -> Self {
        Self::from(core::array::from_fn(|_| rand::random()))
    }
}

#[cfg(any(test, feature = "verify"))]
impl Signature {
    pub(self) fn verify_verbose(
        &self,
        pubkey_bytes: &[u8],
        message_bytes: &[u8],
    ) -> Result<(), ed25519_dalek::SignatureError> {
        let publickey = ed25519_dalek::PublicKey::from_bytes(pubkey_bytes)?;
        let signature = self.0.as_slice().try_into()?;
        publickey.verify_strict(message_bytes, &signature)
    }

    pub fn verify(&self, pubkey_bytes: &[u8], message_bytes: &[u8]) -> bool {
        self.verify_verbose(pubkey_bytes, message_bytes).is_ok()
    }
}

impl AsRef<[u8]> for Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

fn write_as_base58(f: &mut fmt::Formatter, s: &Signature) -> fmt::Result {
    let mut out = [0u8; MAX_BASE58_SIGNATURE_LEN];
    let out_slice: &mut [u8] = &mut out;
    // This will never fail because the only possible error is BufferTooSmall,
    // and we will never call it with too small a buffer.
    let len = bs58::encode(s.0).onto(out_slice).unwrap();
    let as_str = from_utf8(&out[..len]).unwrap();
    f.write_str(as_str)
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_as_base58(f, self)
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write_as_base58(f, self)
    }
}

impl From<Signature> for [u8; 64] {
    fn from(signature: Signature) -> Self {
        signature.0
    }
}

impl From<[u8; SIGNATURE_BYTES]> for Signature {
    #[inline]
    fn from(signature: [u8; SIGNATURE_BYTES]) -> Self {
        Self(signature)
    }
}

impl<'a> TryFrom<&'a [u8]> for Signature {
    type Error = <[u8; SIGNATURE_BYTES] as TryFrom<&'a [u8]>>::Error;

    #[inline]
    fn try_from(signature: &'a [u8]) -> Result<Self, Self::Error> {
        <[u8; SIGNATURE_BYTES]>::try_from(signature).map(Self::from)
    }
}

#[cfg(feature = "std")]
impl TryFrom<Vec<u8>> for Signature {
    type Error = <[u8; SIGNATURE_BYTES] as TryFrom<Vec<u8>>>::Error;

    #[inline]
    fn try_from(signature: Vec<u8>) -> Result<Self, Self::Error> {
        <[u8; SIGNATURE_BYTES]>::try_from(signature).map(Self::from)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseSignatureError {
    WrongSize,
    Invalid,
}

#[cfg(feature = "std")]
impl Error for ParseSignatureError {}

impl fmt::Display for ParseSignatureError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ParseSignatureError::WrongSize => {
                f.write_str("string decoded to wrong size for signature")
            }
            ParseSignatureError::Invalid => f.write_str("failed to decode string to signature"),
        }
    }
}

impl FromStr for Signature {
    type Err = ParseSignatureError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > MAX_BASE58_SIGNATURE_LEN {
            return Err(ParseSignatureError::WrongSize);
        }
        let mut bytes = [0; SIGNATURE_BYTES];
        let decoded_size = bs58::decode(s)
            .onto(&mut bytes)
            .map_err(|_| ParseSignatureError::Invalid)?;
        if decoded_size != SIGNATURE_BYTES {
            Err(ParseSignatureError::WrongSize)
        } else {
            Ok(bytes.into())
        }
    }
}
