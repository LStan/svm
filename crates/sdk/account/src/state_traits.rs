//! Useful extras for `Account` state.

use {
    crate::{Account, AccountSharedData},
    bincode::ErrorKind,
    solana_instruction::error::InstructionError,
    std::cell::Ref,
};

/// Convenience trait to covert bincode errors to instruction errors.
pub trait StateMut<T> {
    fn state(&self) -> Result<T, InstructionError>;
    fn set_state(&mut self, state: &T) -> Result<(), InstructionError>;
}
pub trait State<T> {
    fn state(&self) -> Result<T, InstructionError>;
    fn set_state(&self, state: &T) -> Result<(), InstructionError>;
}

impl<T> StateMut<T> for Account
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    fn state(&self) -> Result<T, InstructionError> {
        self.deserialize_data()
            .map_err(|_| InstructionError::InvalidAccountData)
    }
    fn set_state(&mut self, state: &T) -> Result<(), InstructionError> {
        self.serialize_data(state).map_err(|err| match *err {
            ErrorKind::SizeLimit => InstructionError::AccountDataTooSmall,
            _ => InstructionError::GenericError,
        })
    }
}

impl<T> StateMut<T> for AccountSharedData
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    fn state(&self) -> Result<T, InstructionError> {
        self.deserialize_data()
            .map_err(|_| InstructionError::InvalidAccountData)
    }
    fn set_state(&mut self, state: &T) -> Result<(), InstructionError> {
        self.serialize_data(state).map_err(|err| match *err {
            ErrorKind::SizeLimit => InstructionError::AccountDataTooSmall,
            _ => InstructionError::GenericError,
        })
    }
}

impl<T> StateMut<T> for Ref<'_, AccountSharedData>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    fn state(&self) -> Result<T, InstructionError> {
        self.deserialize_data()
            .map_err(|_| InstructionError::InvalidAccountData)
    }
    fn set_state(&mut self, _state: &T) -> Result<(), InstructionError> {
        panic!("illegal");
    }
}
