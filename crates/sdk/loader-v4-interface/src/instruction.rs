//! Instructions for the v4 built-in loader program.
#[cfg(feature = "bincode")]
use {
    solana_instruction::{AccountMeta, Instruction},
    solana_pubkey::Pubkey,
    solana_sdk_ids::loader_v4::id,
};

#[repr(u8)]
#[cfg_attr(
    feature = "serde",
    derive(serde_derive::Deserialize, serde_derive::Serialize)
)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum LoaderV4Instruction {
    /// Write ELF data into an undeployed program account.
    ///
    /// # Account references
    ///   0. `[writable]` The program account to write to.
    ///   1. `[signer]` The authority of the program.
    Write {
        /// Offset at which to write the given bytes.
        offset: u32,
        /// Serialized program data
        #[cfg_attr(feature = "serde", serde(with = "serde_bytes"))]
        bytes: Vec<u8>,
    },

    /// Copy ELF data into an undeployed program account.
    ///
    /// # Account references
    ///   0. `[writable]` The program account to write to.
    ///   1. `[signer]` The authority of the program.
    ///   2. `[]` The program account to copy from.
    Copy {
        /// Offset at which to write.
        destination_offset: u32,
        /// Offset at which to read.
        source_offset: u32,
        /// Amount of bytes to copy.
        length: u32,
    },

    /// Changes the size of an undeployed program account.
    ///
    /// A program account is automatically initialized when its size is first increased.
    /// In this initial truncate, this sets the authority needed for subsequent operations.
    /// Decreasing to size zero closes the program account and resets it into an uninitialized state.
    /// Closing the program requires a recipient account.
    /// Providing additional lamports upfront might be necessary to reach rent exemption.
    /// Superflous funds are transferred to the recipient account if provided.
    ///
    /// # Account references
    ///   0. `[writable]` The program account to change the size of.
    ///   1. `[signer]` The authority of the program.
    ///   2. `[writable]` Optional, the recipient account.
    SetProgramLength {
        /// The new size after the operation.
        new_size: u32,
    },

    /// Verify the data of a program account to be a valid ELF.
    ///
    /// If this succeeds the program becomes executable, and is ready to use.
    /// A source program account can be provided to overwrite the data before deployment
    /// in one step, instead retracting the program and writing to it and redeploying it.
    /// The source program is truncated to zero (thus closed) and lamports necessary for
    /// rent exemption are transferred, in case that the source was bigger than the program.
    ///
    /// # Account references
    ///   0. `[writable]` The program account to deploy.
    ///   1. `[signer]` The authority of the program.
    ///   2. `[writable]` Optional, an undeployed source program account to take data and lamports from.
    Deploy,

    /// Undo the deployment of a program account.
    ///
    /// The program is no longer executable and goes into maintenance.
    /// Necessary for writing data and truncating.
    ///
    /// # Account references
    ///   0. `[writable]` The program account to retract.
    ///   1. `[signer]` The authority of the program.
    Retract,

    /// Transfers the authority over a program account.
    ///
    /// # Account references
    ///   0. `[writable]` The program account to change the authority of.
    ///   1. `[signer]` The current authority of the program.
    ///   2. `[signer]` The new authority of the program.
    TransferAuthority,

    /// Finalizes the program account, rendering it immutable.
    ///
    /// # Account references
    ///   0. `[writable]` The program account to change the authority of.
    ///   1. `[signer]` The current authority of the program.
    ///   2. `[]` The next version of the program (can be itself).
    Finalize,
}

pub fn is_write_instruction(instruction_data: &[u8]) -> bool {
    !instruction_data.is_empty() && 0 == instruction_data[0]
}

pub fn is_copy_instruction(instruction_data: &[u8]) -> bool {
    !instruction_data.is_empty() && 1 == instruction_data[0]
}

pub fn is_set_program_length_instruction(instruction_data: &[u8]) -> bool {
    !instruction_data.is_empty() && 2 == instruction_data[0]
}

pub fn is_deploy_instruction(instruction_data: &[u8]) -> bool {
    !instruction_data.is_empty() && 3 == instruction_data[0]
}

pub fn is_retract_instruction(instruction_data: &[u8]) -> bool {
    !instruction_data.is_empty() && 4 == instruction_data[0]
}

pub fn is_transfer_authority_instruction(instruction_data: &[u8]) -> bool {
    !instruction_data.is_empty() && 5 == instruction_data[0]
}

pub fn is_finalize_instruction(instruction_data: &[u8]) -> bool {
    !instruction_data.is_empty() && 6 == instruction_data[0]
}

/// Returns the instructions required to initialize a program/buffer account.
#[cfg(feature = "bincode")]
pub fn create_buffer(
    payer_address: &Pubkey,
    buffer_address: &Pubkey,
    lamports: u64,
    authority: &Pubkey,
    new_size: u32,
    recipient_address: &Pubkey,
) -> Vec<Instruction> {
    vec![
        solana_system_interface::instruction::create_account(
            payer_address,
            buffer_address,
            lamports,
            0,
            &id(),
        ),
        set_program_length(buffer_address, authority, new_size, recipient_address),
    ]
}

/// Returns the instructions required to set the length of the program account.
#[cfg(feature = "bincode")]
pub fn set_program_length(
    program_address: &Pubkey,
    authority: &Pubkey,
    new_size: u32,
    recipient_address: &Pubkey,
) -> Instruction {
    Instruction::new_with_bincode(
        id(),
        &LoaderV4Instruction::SetProgramLength { new_size },
        vec![
            AccountMeta::new(*program_address, false),
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new(*recipient_address, false),
        ],
    )
}

/// Returns the instructions required to write a chunk of program data to a
/// buffer account.
#[cfg(feature = "bincode")]
pub fn write(
    program_address: &Pubkey,
    authority: &Pubkey,
    offset: u32,
    bytes: Vec<u8>,
) -> Instruction {
    Instruction::new_with_bincode(
        id(),
        &LoaderV4Instruction::Write { offset, bytes },
        vec![
            AccountMeta::new(*program_address, false),
            AccountMeta::new_readonly(*authority, true),
        ],
    )
}

/// Returns the instructions required to copy a chunk of program data.
#[cfg(feature = "bincode")]
pub fn copy(
    program_address: &Pubkey,
    authority: &Pubkey,
    source_address: &Pubkey,
    destination_offset: u32,
    source_offset: u32,
    length: u32,
) -> Instruction {
    Instruction::new_with_bincode(
        id(),
        &LoaderV4Instruction::Copy {
            destination_offset,
            source_offset,
            length,
        },
        vec![
            AccountMeta::new(*program_address, false),
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new_readonly(*source_address, false),
        ],
    )
}

/// Returns the instructions required to deploy a program.
#[cfg(feature = "bincode")]
pub fn deploy(program_address: &Pubkey, authority: &Pubkey) -> Instruction {
    Instruction::new_with_bincode(
        id(),
        &LoaderV4Instruction::Deploy,
        vec![
            AccountMeta::new(*program_address, false),
            AccountMeta::new_readonly(*authority, true),
        ],
    )
}

/// Returns the instructions required to deploy a program using a buffer.
#[cfg(feature = "bincode")]
pub fn deploy_from_source(
    program_address: &Pubkey,
    authority: &Pubkey,
    source_address: &Pubkey,
) -> Instruction {
    Instruction::new_with_bincode(
        id(),
        &LoaderV4Instruction::Deploy,
        vec![
            AccountMeta::new(*program_address, false),
            AccountMeta::new_readonly(*authority, true),
            AccountMeta::new(*source_address, false),
        ],
    )
}

/// Returns the instructions required to retract a program.
#[cfg(feature = "bincode")]
pub fn retract(program_address: &Pubkey, authority: &Pubkey) -> Instruction {
    Instruction::new_with_bincode(
        id(),
        &LoaderV4Instruction::Retract,
        vec![
            AccountMeta::new(*program_address, false),
            AccountMeta::new_readonly(*authority, true),
        ],
    )
}

/// Returns the instructions required to transfer authority over a program.
#[cfg(feature = "bincode")]
pub fn transfer_authority(
    program_address: &Pubkey,
    authority: &Pubkey,
    new_authority: &Pubkey,
) -> Instruction {
    let accounts = vec![
        AccountMeta::new(*program_address, false),
        AccountMeta::new_readonly(*authority, true),
        AccountMeta::new_readonly(*new_authority, true),
    ];

    Instruction::new_with_bincode(id(), &LoaderV4Instruction::TransferAuthority, accounts)
}

/// Returns the instructions required to finalize program.
#[cfg(feature = "bincode")]
pub fn finalize(
    program_address: &Pubkey,
    authority: &Pubkey,
    next_version_program_address: &Pubkey,
) -> Instruction {
    let accounts = vec![
        AccountMeta::new(*program_address, false),
        AccountMeta::new_readonly(*authority, true),
        AccountMeta::new_readonly(*next_version_program_address, false),
    ];

    Instruction::new_with_bincode(id(), &LoaderV4Instruction::Finalize, accounts)
}
