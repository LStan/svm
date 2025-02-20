pub use self::{
    cpi::{SyscallInvokeSignedC, SyscallInvokeSignedRust},
    logging::{
        SyscallLog, SyscallLogBpfComputeUnits, SyscallLogData, SyscallLogPubkey, SyscallLogU64,
    },
    mem_ops::{SyscallMemcmp, SyscallMemcpy, SyscallMemmove, SyscallMemset},
    sysvar::{
        SyscallGetClockSysvar, SyscallGetEpochRewardsSysvar, SyscallGetEpochScheduleSysvar,
        SyscallGetFeesSysvar, SyscallGetLastRestartSlotSysvar, SyscallGetRentSysvar,
        SyscallGetSysvar,
    },
};
#[allow(deprecated)]
use {
    solana_account_info::AccountInfo,
    solana_big_mod_exp::{big_mod_exp, BigModExpParams},
    solana_blake3_hasher as blake3,
    solana_bn254::prelude::{
        alt_bn128_addition, alt_bn128_multiplication, alt_bn128_multiplication_128,
        alt_bn128_pairing, AltBn128Error, ALT_BN128_ADDITION_OUTPUT_LEN,
        ALT_BN128_MULTIPLICATION_OUTPUT_LEN, ALT_BN128_PAIRING_ELEMENT_LEN,
        ALT_BN128_PAIRING_OUTPUT_LEN,
    },
    solana_compute_budget::compute_budget::ComputeBudget,
    solana_cpi::MAX_RETURN_DATA,
    solana_feature_set::{
        self as feature_set, abort_on_invalid_curve, blake3_syscall_enabled,
        bpf_account_data_direct_mapping, curve25519_syscall_enabled,
        disable_deploy_of_alloc_free_syscall, disable_fees_sysvar, disable_sbpf_v0_execution,
        enable_alt_bn128_compression_syscall, enable_alt_bn128_syscall, enable_big_mod_exp_syscall,
        enable_get_epoch_stake_syscall, enable_poseidon_syscall,
        enable_sbpf_v1_deployment_and_execution, enable_sbpf_v2_deployment_and_execution,
        enable_sbpf_v3_deployment_and_execution, get_sysvar_syscall_enabled,
        last_restart_slot_sysvar, reenable_sbpf_v0_execution,
        remaining_compute_units_syscall_enabled, FeatureSet,
    },
    solana_hash::Hash,
    solana_instruction::{error::InstructionError, AccountMeta, ProcessedSiblingInstruction},
    solana_keccak_hasher as keccak,
    solana_log_collector::{ic_logger_msg, ic_msg},
    solana_poseidon as poseidon,
    solana_precompiles::is_precompile,
    solana_program_entrypoint::{BPF_ALIGN_OF_U128, MAX_PERMITTED_DATA_INCREASE, SUCCESS},
    solana_program_memory::is_nonoverlapping,
    solana_program_runtime::{invoke_context::InvokeContext, stable_log},
    solana_pubkey::{Pubkey, PubkeyError, MAX_SEEDS, MAX_SEED_LEN, PUBKEY_BYTES},
    solana_sbpf::{
        declare_builtin_function,
        memory_region::{AccessType, MemoryMapping},
        program::{BuiltinProgram, SBPFVersion},
        vm::Config,
    },
    solana_sdk_ids::{bpf_loader, bpf_loader_deprecated, native_loader},
    solana_secp256k1_recover::{
        Secp256k1RecoverError, SECP256K1_PUBLIC_KEY_LENGTH, SECP256K1_SIGNATURE_LENGTH,
    },
    solana_sha256_hasher::Hasher,
    solana_sysvar::Sysvar,
    solana_sysvar_id::SysvarId,
    solana_transaction_context::{IndexOfAccount, InstructionAccount},
    solana_type_overrides::sync::Arc,
    std::{
        alloc::Layout,
        marker::PhantomData,
        mem::{align_of, size_of},
        slice::from_raw_parts_mut,
        str::{from_utf8, Utf8Error},
    },
    thiserror::Error as ThisError,
};

mod cpi;
mod logging;
mod mem_ops;
mod sysvar;

/// Maximum signers
const MAX_SIGNERS: usize = 16;

/// Error definitions
#[derive(Debug, ThisError, PartialEq, Eq)]
pub enum SyscallError {
    #[error("{0}: {1:?}")]
    InvalidString(Utf8Error, Vec<u8>),
    #[error("SBF program panicked")]
    Abort,
    #[error("SBF program Panicked in {0} at {1}:{2}")]
    Panic(String, u64, u64),
    #[error("Cannot borrow invoke context")]
    InvokeContextBorrowFailed,
    #[error("Malformed signer seed: {0}: {1:?}")]
    MalformedSignerSeed(Utf8Error, Vec<u8>),
    #[error("Could not create program address with signer seeds: {0}")]
    BadSeeds(PubkeyError),
    #[error("Program {0} not supported by inner instructions")]
    ProgramNotSupported(Pubkey),
    #[error("Unaligned pointer")]
    UnalignedPointer,
    #[error("Too many signers")]
    TooManySigners,
    #[error("Instruction passed to inner instruction is too large ({0} > {1})")]
    InstructionTooLarge(usize, usize),
    #[error("Too many accounts passed to inner instruction")]
    TooManyAccounts,
    #[error("Overlapping copy")]
    CopyOverlapping,
    #[error("Return data too large ({0} > {1})")]
    ReturnDataTooLarge(u64, u64),
    #[error("Hashing too many sequences")]
    TooManySlices,
    #[error("InvalidLength")]
    InvalidLength,
    #[error("Invoked an instruction with data that is too large ({data_len} > {max_data_len})")]
    MaxInstructionDataLenExceeded { data_len: u64, max_data_len: u64 },
    #[error("Invoked an instruction with too many accounts ({num_accounts} > {max_accounts})")]
    MaxInstructionAccountsExceeded {
        num_accounts: u64,
        max_accounts: u64,
    },
    #[error("Invoked an instruction with too many account info's ({num_account_infos} > {max_account_infos})")]
    MaxInstructionAccountInfosExceeded {
        num_account_infos: u64,
        max_account_infos: u64,
    },
    #[error("InvalidAttribute")]
    InvalidAttribute,
    #[error("Invalid pointer")]
    InvalidPointer,
    #[error("Arithmetic overflow")]
    ArithmeticOverflow,
}

type Error = Box<dyn std::error::Error>;

trait HasherImpl {
    const NAME: &'static str;
    type Output: AsRef<[u8]>;

    fn create_hasher() -> Self;
    fn hash(&mut self, val: &[u8]);
    fn result(self) -> Self::Output;
    fn get_base_cost(compute_budget: &ComputeBudget) -> u64;
    fn get_byte_cost(compute_budget: &ComputeBudget) -> u64;
    fn get_max_slices(compute_budget: &ComputeBudget) -> u64;
}

struct Sha256Hasher(Hasher);
struct Blake3Hasher(blake3::Hasher);
struct Keccak256Hasher(keccak::Hasher);

impl HasherImpl for Sha256Hasher {
    const NAME: &'static str = "Sha256";
    type Output = Hash;

    fn create_hasher() -> Self {
        Sha256Hasher(Hasher::default())
    }

    fn hash(&mut self, val: &[u8]) {
        self.0.hash(val);
    }

    fn result(self) -> Self::Output {
        self.0.result()
    }

    fn get_base_cost(compute_budget: &ComputeBudget) -> u64 {
        compute_budget.sha256_base_cost
    }
    fn get_byte_cost(compute_budget: &ComputeBudget) -> u64 {
        compute_budget.sha256_byte_cost
    }
    fn get_max_slices(compute_budget: &ComputeBudget) -> u64 {
        compute_budget.sha256_max_slices
    }
}

impl HasherImpl for Blake3Hasher {
    const NAME: &'static str = "Blake3";
    type Output = blake3::Hash;

    fn create_hasher() -> Self {
        Blake3Hasher(blake3::Hasher::default())
    }

    fn hash(&mut self, val: &[u8]) {
        self.0.hash(val);
    }

    fn result(self) -> Self::Output {
        self.0.result()
    }

    fn get_base_cost(compute_budget: &ComputeBudget) -> u64 {
        compute_budget.sha256_base_cost
    }
    fn get_byte_cost(compute_budget: &ComputeBudget) -> u64 {
        compute_budget.sha256_byte_cost
    }
    fn get_max_slices(compute_budget: &ComputeBudget) -> u64 {
        compute_budget.sha256_max_slices
    }
}

impl HasherImpl for Keccak256Hasher {
    const NAME: &'static str = "Keccak256";
    type Output = keccak::Hash;

    fn create_hasher() -> Self {
        Keccak256Hasher(keccak::Hasher::default())
    }

    fn hash(&mut self, val: &[u8]) {
        self.0.hash(val);
    }

    fn result(self) -> Self::Output {
        self.0.result()
    }

    fn get_base_cost(compute_budget: &ComputeBudget) -> u64 {
        compute_budget.sha256_base_cost
    }
    fn get_byte_cost(compute_budget: &ComputeBudget) -> u64 {
        compute_budget.sha256_byte_cost
    }
    fn get_max_slices(compute_budget: &ComputeBudget) -> u64 {
        compute_budget.sha256_max_slices
    }
}

// The VmSlice class is used for cases when you need a slice that is stored in the BPF
// interpreter's virtual address space. Because this source code can be compiled with
// addresses of different bit depths, we cannot assume that the 64-bit BPF interpreter's
// pointer sizes can be mapped to physical pointer sizes. In particular, if you need a
// slice-of-slices in the virtual space, the inner slices will be different sizes in a
// 32-bit app build than in the 64-bit virtual space. Therefore instead of a slice-of-slices,
// you should implement a slice-of-VmSlices, which can then use VmSlice::translate() to
// map to the physical address.
// This class must consist only of 16 bytes: a u64 ptr and a u64 len, to match the 64-bit
// implementation of a slice in Rust. The PhantomData entry takes up 0 bytes.

#[repr(C)]
pub struct VmSlice<T> {
    ptr: u64,
    len: u64,
    resource_type: PhantomData<T>,
}

impl<T> VmSlice<T> {
    pub fn new(ptr: u64, len: u64) -> Self {
        VmSlice {
            ptr,
            len,
            resource_type: PhantomData,
        }
    }

    pub fn ptr(&self) -> u64 {
        self.ptr
    }
    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Adjust the length of the vector. This is unchecked, and it assumes that the pointer
    /// points to valid memory of the correct length after vm-translation.
    pub fn resize(&mut self, len: u64) {
        self.len = len;
    }

    /// Returns a slice using a mapped physical address
    pub fn translate(
        &self,
        memory_mapping: &MemoryMapping,
        check_aligned: bool,
    ) -> Result<&[T], Error> {
        translate_slice::<T>(memory_mapping, self.ptr, self.len, check_aligned)
    }

    pub fn translate_mut(
        &mut self,
        memory_mapping: &MemoryMapping,
        check_aligned: bool,
    ) -> Result<&mut [T], Error> {
        translate_slice_mut::<T>(memory_mapping, self.ptr, self.len, check_aligned)
    }
}

fn consume_compute_meter(invoke_context: &InvokeContext, amount: u64) -> Result<(), Error> {
    invoke_context.consume_checked(amount)?;
    Ok(())
}

macro_rules! register_feature_gated_function {
    ($result:expr, $is_feature_active:expr, $name:expr, $call:expr $(,)?) => {
        if $is_feature_active {
            $result.register_function($name, $call)
        } else {
            Ok(())
        }
    };
}

pub(crate) fn morph_into_deployment_environment_v1(
    from: Arc<BuiltinProgram<InvokeContext>>,
) -> Result<BuiltinProgram<InvokeContext>, Error> {
    let mut config = from.get_config().clone();
    config.reject_broken_elfs = true;
    // Once the tests are being build using a toolchain which supports the newer SBPF versions,
    // the deployment of older versions will be disabled:
    // config.enabled_sbpf_versions =
    //     *config.enabled_sbpf_versions.end()..=*config.enabled_sbpf_versions.end();

    let mut result = BuiltinProgram::new_loader(config);

    for (_key, (name, value)) in from.get_function_registry().iter() {
        // Deployment of programs with sol_alloc_free is disabled. So do not register the syscall.
        if name != *b"sol_alloc_free_" {
            result.register_function(unsafe { std::str::from_utf8_unchecked(name) }, value)?;
        }
    }

    Ok(result)
}

pub fn create_program_runtime_environment_v1<'a>(
    feature_set: &FeatureSet,
    compute_budget: &ComputeBudget,
    reject_deployment_of_broken_elfs: bool,
    debugging_features: bool,
) -> Result<BuiltinProgram<InvokeContext<'a>>, Error> {
    let enable_alt_bn128_syscall = feature_set.is_active(&enable_alt_bn128_syscall::id());
    let enable_alt_bn128_compression_syscall =
        feature_set.is_active(&enable_alt_bn128_compression_syscall::id());
    let enable_big_mod_exp_syscall = feature_set.is_active(&enable_big_mod_exp_syscall::id());
    let blake3_syscall_enabled = feature_set.is_active(&blake3_syscall_enabled::id());
    let curve25519_syscall_enabled = feature_set.is_active(&curve25519_syscall_enabled::id());
    let disable_fees_sysvar = feature_set.is_active(&disable_fees_sysvar::id());
    let disable_deploy_of_alloc_free_syscall = reject_deployment_of_broken_elfs
        && feature_set.is_active(&disable_deploy_of_alloc_free_syscall::id());
    let last_restart_slot_syscall_enabled = feature_set.is_active(&last_restart_slot_sysvar::id());
    let enable_poseidon_syscall = feature_set.is_active(&enable_poseidon_syscall::id());
    let remaining_compute_units_syscall_enabled =
        feature_set.is_active(&remaining_compute_units_syscall_enabled::id());
    let get_sysvar_syscall_enabled = feature_set.is_active(&get_sysvar_syscall_enabled::id());
    let enable_get_epoch_stake_syscall =
        feature_set.is_active(&enable_get_epoch_stake_syscall::id());
    let min_sbpf_version = if !feature_set.is_active(&disable_sbpf_v0_execution::id())
        || feature_set.is_active(&reenable_sbpf_v0_execution::id())
    {
        SBPFVersion::V0
    } else {
        SBPFVersion::V3
    };
    let max_sbpf_version = if feature_set.is_active(&enable_sbpf_v3_deployment_and_execution::id())
    {
        SBPFVersion::V3
    } else if feature_set.is_active(&enable_sbpf_v2_deployment_and_execution::id()) {
        SBPFVersion::V2
    } else if feature_set.is_active(&enable_sbpf_v1_deployment_and_execution::id()) {
        SBPFVersion::V1
    } else {
        SBPFVersion::V0
    };
    debug_assert!(min_sbpf_version <= max_sbpf_version);

    let config = Config {
        max_call_depth: compute_budget.max_call_depth,
        stack_frame_size: compute_budget.stack_frame_size,
        enable_address_translation: true,
        enable_stack_frame_gaps: !feature_set.is_active(&bpf_account_data_direct_mapping::id()),
        instruction_meter_checkpoint_distance: 10000,
        enable_instruction_meter: true,
        enable_instruction_tracing: debugging_features,
        enable_symbol_and_section_labels: debugging_features,
        reject_broken_elfs: reject_deployment_of_broken_elfs,
        noop_instruction_rate: 256,
        sanitize_user_provided_values: true,
        enabled_sbpf_versions: min_sbpf_version..=max_sbpf_version,
        optimize_rodata: false,
        aligned_memory_mapping: !feature_set.is_active(&bpf_account_data_direct_mapping::id()),
        // Warning, do not use `Config::default()` so that configuration here is explicit.
    };
    let mut result = BuiltinProgram::new_loader(config);

    // Abort
    result.register_function("abort", SyscallAbort::vm)?;

    // Panic
    result.register_function("sol_panic_", SyscallPanic::vm)?;

    // Logging
    result.register_function("sol_log_", SyscallLog::vm)?;
    result.register_function("sol_log_64_", SyscallLogU64::vm)?;
    result.register_function("sol_log_pubkey", SyscallLogPubkey::vm)?;
    result.register_function("sol_log_compute_units_", SyscallLogBpfComputeUnits::vm)?;

    // Program defined addresses (PDA)
    result.register_function(
        "sol_create_program_address",
        SyscallCreateProgramAddress::vm,
    )?;
    result.register_function(
        "sol_try_find_program_address",
        SyscallTryFindProgramAddress::vm,
    )?;

    // Sha256
    result.register_function("sol_sha256", SyscallHash::vm::<Sha256Hasher>)?;

    // Keccak256
    result.register_function("sol_keccak256", SyscallHash::vm::<Keccak256Hasher>)?;

    // Secp256k1 Recover
    result.register_function("sol_secp256k1_recover", SyscallSecp256k1Recover::vm)?;

    // Blake3
    register_feature_gated_function!(
        result,
        blake3_syscall_enabled,
        "sol_blake3",
        SyscallHash::vm::<Blake3Hasher>,
    )?;

    // Elliptic Curve Operations
    register_feature_gated_function!(
        result,
        curve25519_syscall_enabled,
        "sol_curve_validate_point",
        SyscallCurvePointValidation::vm,
    )?;
    register_feature_gated_function!(
        result,
        curve25519_syscall_enabled,
        "sol_curve_group_op",
        SyscallCurveGroupOps::vm,
    )?;
    register_feature_gated_function!(
        result,
        curve25519_syscall_enabled,
        "sol_curve_multiscalar_mul",
        SyscallCurveMultiscalarMultiplication::vm,
    )?;

    // Sysvars
    result.register_function("sol_get_clock_sysvar", SyscallGetClockSysvar::vm)?;
    result.register_function(
        "sol_get_epoch_schedule_sysvar",
        SyscallGetEpochScheduleSysvar::vm,
    )?;
    register_feature_gated_function!(
        result,
        !disable_fees_sysvar,
        "sol_get_fees_sysvar",
        SyscallGetFeesSysvar::vm,
    )?;
    result.register_function("sol_get_rent_sysvar", SyscallGetRentSysvar::vm)?;

    register_feature_gated_function!(
        result,
        last_restart_slot_syscall_enabled,
        "sol_get_last_restart_slot",
        SyscallGetLastRestartSlotSysvar::vm,
    )?;

    result.register_function(
        "sol_get_epoch_rewards_sysvar",
        SyscallGetEpochRewardsSysvar::vm,
    )?;

    // Memory ops
    result.register_function("sol_memcpy_", SyscallMemcpy::vm)?;
    result.register_function("sol_memmove_", SyscallMemmove::vm)?;
    result.register_function("sol_memset_", SyscallMemset::vm)?;
    result.register_function("sol_memcmp_", SyscallMemcmp::vm)?;

    // Processed sibling instructions
    result.register_function(
        "sol_get_processed_sibling_instruction",
        SyscallGetProcessedSiblingInstruction::vm,
    )?;

    // Stack height
    result.register_function("sol_get_stack_height", SyscallGetStackHeight::vm)?;

    // Return data
    result.register_function("sol_set_return_data", SyscallSetReturnData::vm)?;
    result.register_function("sol_get_return_data", SyscallGetReturnData::vm)?;

    // Cross-program invocation
    result.register_function("sol_invoke_signed_c", SyscallInvokeSignedC::vm)?;
    result.register_function("sol_invoke_signed_rust", SyscallInvokeSignedRust::vm)?;

    // Memory allocator
    register_feature_gated_function!(
        result,
        !disable_deploy_of_alloc_free_syscall,
        "sol_alloc_free_",
        SyscallAllocFree::vm,
    )?;

    // Alt_bn128
    register_feature_gated_function!(
        result,
        enable_alt_bn128_syscall,
        "sol_alt_bn128_group_op",
        SyscallAltBn128::vm,
    )?;

    // Big_mod_exp
    register_feature_gated_function!(
        result,
        enable_big_mod_exp_syscall,
        "sol_big_mod_exp",
        SyscallBigModExp::vm,
    )?;

    // Poseidon
    register_feature_gated_function!(
        result,
        enable_poseidon_syscall,
        "sol_poseidon",
        SyscallPoseidon::vm,
    )?;

    // Accessing remaining compute units
    register_feature_gated_function!(
        result,
        remaining_compute_units_syscall_enabled,
        "sol_remaining_compute_units",
        SyscallRemainingComputeUnits::vm
    )?;

    // Alt_bn128_compression
    register_feature_gated_function!(
        result,
        enable_alt_bn128_compression_syscall,
        "sol_alt_bn128_compression",
        SyscallAltBn128Compression::vm,
    )?;

    // Sysvar getter
    register_feature_gated_function!(
        result,
        get_sysvar_syscall_enabled,
        "sol_get_sysvar",
        SyscallGetSysvar::vm,
    )?;

    // Get Epoch Stake
    register_feature_gated_function!(
        result,
        enable_get_epoch_stake_syscall,
        "sol_get_epoch_stake",
        SyscallGetEpochStake::vm,
    )?;

    // Log data
    result.register_function("sol_log_data", SyscallLogData::vm)?;

    Ok(result)
}

pub fn create_program_runtime_environment_v2<'a>(
    compute_budget: &ComputeBudget,
    debugging_features: bool,
) -> BuiltinProgram<InvokeContext<'a>> {
    let config = Config {
        max_call_depth: compute_budget.max_call_depth,
        stack_frame_size: compute_budget.stack_frame_size,
        enable_address_translation: true, // To be deactivated once we have BTF inference and verification
        enable_stack_frame_gaps: false,
        instruction_meter_checkpoint_distance: 10000,
        enable_instruction_meter: true,
        enable_instruction_tracing: debugging_features,
        enable_symbol_and_section_labels: debugging_features,
        reject_broken_elfs: true,
        noop_instruction_rate: 256,
        sanitize_user_provided_values: true,
        enabled_sbpf_versions: SBPFVersion::Reserved..=SBPFVersion::Reserved,
        optimize_rodata: true,
        aligned_memory_mapping: true,
        // Warning, do not use `Config::default()` so that configuration here is explicit.
    };
    BuiltinProgram::new_loader(config)
}

fn address_is_aligned<T>(address: u64) -> bool {
    (address as *mut T as usize)
        .checked_rem(align_of::<T>())
        .map(|rem| rem == 0)
        .expect("T to be non-zero aligned")
}

fn translate(
    memory_mapping: &MemoryMapping,
    access_type: AccessType,
    vm_addr: u64,
    len: u64,
) -> Result<u64, Error> {
    memory_mapping
        .map(access_type, vm_addr, len)
        .map_err(|err| err.into())
        .into()
}

fn translate_type_inner<'a, T>(
    memory_mapping: &MemoryMapping,
    access_type: AccessType,
    vm_addr: u64,
    check_aligned: bool,
) -> Result<&'a mut T, Error> {
    let host_addr = translate(memory_mapping, access_type, vm_addr, size_of::<T>() as u64)?;
    if !check_aligned {
        // Ok(unsafe { std::mem::transmute::<u64, &mut T>(host_addr) })
        Ok(unsafe { &mut *(host_addr as *mut T) })
    } else if !address_is_aligned::<T>(host_addr) {
        Err(SyscallError::UnalignedPointer.into())
    } else {
        Ok(unsafe { &mut *(host_addr as *mut T) })
    }
}
fn translate_type_mut<'a, T>(
    memory_mapping: &MemoryMapping,
    vm_addr: u64,
    check_aligned: bool,
) -> Result<&'a mut T, Error> {
    translate_type_inner::<T>(memory_mapping, AccessType::Store, vm_addr, check_aligned)
}
fn translate_type<'a, T>(
    memory_mapping: &MemoryMapping,
    vm_addr: u64,
    check_aligned: bool,
) -> Result<&'a T, Error> {
    translate_type_inner::<T>(memory_mapping, AccessType::Load, vm_addr, check_aligned)
        .map(|value| &*value)
}

fn translate_slice_inner<'a, T>(
    memory_mapping: &MemoryMapping,
    access_type: AccessType,
    vm_addr: u64,
    len: u64,
    check_aligned: bool,
) -> Result<&'a mut [T], Error> {
    if len == 0 {
        return Ok(&mut []);
    }

    let total_size = len.saturating_mul(size_of::<T>() as u64);
    if isize::try_from(total_size).is_err() {
        return Err(SyscallError::InvalidLength.into());
    }

    let host_addr = translate(memory_mapping, access_type, vm_addr, total_size)?;

    if check_aligned && !address_is_aligned::<T>(host_addr) {
        return Err(SyscallError::UnalignedPointer.into());
    }
    Ok(unsafe { from_raw_parts_mut(host_addr as *mut T, len as usize) })
}
fn translate_slice_mut<'a, T>(
    memory_mapping: &MemoryMapping,
    vm_addr: u64,
    len: u64,
    check_aligned: bool,
) -> Result<&'a mut [T], Error> {
    translate_slice_inner::<T>(
        memory_mapping,
        AccessType::Store,
        vm_addr,
        len,
        check_aligned,
    )
}
fn translate_slice<'a, T>(
    memory_mapping: &MemoryMapping,
    vm_addr: u64,
    len: u64,
    check_aligned: bool,
) -> Result<&'a [T], Error> {
    translate_slice_inner::<T>(
        memory_mapping,
        AccessType::Load,
        vm_addr,
        len,
        check_aligned,
    )
    .map(|value| &*value)
}

fn translate_slice_of_slices_inner<'a, T>(
    memory_mapping: &MemoryMapping,
    access_type: AccessType,
    vm_addr: u64,
    len: u64,
    check_aligned: bool,
) -> Result<&'a mut [VmSlice<T>], Error> {
    if len == 0 {
        return Ok(&mut []);
    }

    let total_size = len.saturating_mul(size_of::<VmSlice<T>>() as u64);
    if isize::try_from(total_size).is_err() {
        return Err(SyscallError::InvalidLength.into());
    }

    let host_addr = translate(memory_mapping, access_type, vm_addr, total_size)?;

    if check_aligned && !address_is_aligned::<VmSlice<T>>(host_addr) {
        return Err(SyscallError::UnalignedPointer.into());
    }
    Ok(unsafe { from_raw_parts_mut(host_addr as *mut VmSlice<T>, len as usize) })
}

#[allow(dead_code)]
fn translate_slice_of_slices_mut<'a, T>(
    memory_mapping: &MemoryMapping,
    vm_addr: u64,
    len: u64,
    check_aligned: bool,
) -> Result<&'a mut [VmSlice<T>], Error> {
    translate_slice_of_slices_inner::<T>(
        memory_mapping,
        AccessType::Store,
        vm_addr,
        len,
        check_aligned,
    )
}

fn translate_slice_of_slices<'a, T>(
    memory_mapping: &MemoryMapping,
    vm_addr: u64,
    len: u64,
    check_aligned: bool,
) -> Result<&'a [VmSlice<T>], Error> {
    translate_slice_of_slices_inner::<T>(
        memory_mapping,
        AccessType::Load,
        vm_addr,
        len,
        check_aligned,
    )
    .map(|value| &*value)
}

/// Take a virtual pointer to a string (points to SBF VM memory space), translate it
/// pass it to a user-defined work function
fn translate_string_and_do(
    memory_mapping: &MemoryMapping,
    addr: u64,
    len: u64,
    check_aligned: bool,
    work: &mut dyn FnMut(&str) -> Result<u64, Error>,
) -> Result<u64, Error> {
    let buf = translate_slice::<u8>(memory_mapping, addr, len, check_aligned)?;
    match from_utf8(buf) {
        Ok(message) => work(message),
        Err(err) => Err(SyscallError::InvalidString(err, buf.to_vec()).into()),
    }
}

declare_builtin_function!(
    /// Abort syscall functions, called when the SBF program calls `abort()`
    /// LLVM will insert calls to `abort()` if it detects an untenable situation,
    /// `abort()` is not intended to be called explicitly by the program.
    /// Causes the SBF program to be halted immediately
    SyscallAbort,
    fn rust(
        _invoke_context: &mut InvokeContext,
        _arg1: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        _memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        Err(SyscallError::Abort.into())
    }
);

declare_builtin_function!(
    /// Panic syscall function, called when the SBF program calls 'sol_panic_()`
    /// Causes the SBF program to be halted immediately
    SyscallPanic,
    fn rust(
        invoke_context: &mut InvokeContext,
        file: u64,
        len: u64,
        line: u64,
        column: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        consume_compute_meter(invoke_context, len)?;

        translate_string_and_do(
            memory_mapping,
            file,
            len,
            invoke_context.get_check_aligned(),
            &mut |string: &str| Err(SyscallError::Panic(string.to_string(), line, column).into()),
        )
    }
);

declare_builtin_function!(
    /// Dynamic memory allocation syscall called when the SBF program calls
    /// `sol_alloc_free_()`.  The allocator is expected to allocate/free
    /// from/to a given chunk of memory and enforce size restrictions.  The
    /// memory chunk is given to the allocator during allocator creation and
    /// information about that memory (start address and size) is passed
    /// to the VM to use for enforcement.
    SyscallAllocFree,
    fn rust(
        invoke_context: &mut InvokeContext,
        size: u64,
        free_addr: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        _memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let align = if invoke_context.get_check_aligned() {
            BPF_ALIGN_OF_U128
        } else {
            align_of::<u8>()
        };
        let Ok(layout) = Layout::from_size_align(size as usize, align) else {
            return Ok(0);
        };
        let allocator = &mut invoke_context.get_syscall_context_mut()?.allocator;
        if free_addr == 0 {
            match allocator.alloc(layout) {
                Ok(addr) => Ok(addr),
                Err(_) => Ok(0),
            }
        } else {
            // Unimplemented
            Ok(0)
        }
    }
);

fn translate_and_check_program_address_inputs<'a>(
    seeds_addr: u64,
    seeds_len: u64,
    program_id_addr: u64,
    memory_mapping: &mut MemoryMapping,
    check_aligned: bool,
) -> Result<(Vec<&'a [u8]>, &'a Pubkey), Error> {
    let untranslated_seeds =
        translate_slice_of_slices::<u8>(memory_mapping, seeds_addr, seeds_len, check_aligned)?;
    if untranslated_seeds.len() > MAX_SEEDS {
        return Err(SyscallError::BadSeeds(PubkeyError::MaxSeedLengthExceeded).into());
    }
    let seeds = untranslated_seeds
        .iter()
        .map(|untranslated_seed| {
            if untranslated_seed.len() > MAX_SEED_LEN as u64 {
                return Err(SyscallError::BadSeeds(PubkeyError::MaxSeedLengthExceeded).into());
            }
            untranslated_seed.translate(memory_mapping, check_aligned)
        })
        .collect::<Result<Vec<_>, Error>>()?;
    let program_id = translate_type::<Pubkey>(memory_mapping, program_id_addr, check_aligned)?;
    Ok((seeds, program_id))
}

declare_builtin_function!(
    /// Create a program address
    SyscallCreateProgramAddress,
    fn rust(
        invoke_context: &mut InvokeContext,
        seeds_addr: u64,
        seeds_len: u64,
        program_id_addr: u64,
        address_addr: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let cost = invoke_context
            .get_compute_budget()
            .create_program_address_units;
        consume_compute_meter(invoke_context, cost)?;

        let (seeds, program_id) = translate_and_check_program_address_inputs(
            seeds_addr,
            seeds_len,
            program_id_addr,
            memory_mapping,
            invoke_context.get_check_aligned(),
        )?;

        let Ok(new_address) = Pubkey::create_program_address(&seeds, program_id) else {
            return Ok(1);
        };
        let address = translate_slice_mut::<u8>(
            memory_mapping,
            address_addr,
            32,
            invoke_context.get_check_aligned(),
        )?;
        address.copy_from_slice(new_address.as_ref());
        Ok(0)
    }
);

declare_builtin_function!(
    /// Create a program address
    SyscallTryFindProgramAddress,
    fn rust(
        invoke_context: &mut InvokeContext,
        seeds_addr: u64,
        seeds_len: u64,
        program_id_addr: u64,
        address_addr: u64,
        bump_seed_addr: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let cost = invoke_context
            .get_compute_budget()
            .create_program_address_units;
        consume_compute_meter(invoke_context, cost)?;

        let (seeds, program_id) = translate_and_check_program_address_inputs(
            seeds_addr,
            seeds_len,
            program_id_addr,
            memory_mapping,
            invoke_context.get_check_aligned(),
        )?;

        let mut bump_seed = [u8::MAX];
        for _ in 0..u8::MAX {
            {
                let mut seeds_with_bump = seeds.to_vec();
                seeds_with_bump.push(&bump_seed);

                if let Ok(new_address) =
                    Pubkey::create_program_address(&seeds_with_bump, program_id)
                {
                    let bump_seed_ref = translate_type_mut::<u8>(
                        memory_mapping,
                        bump_seed_addr,
                        invoke_context.get_check_aligned(),
                    )?;
                    let address = translate_slice_mut::<u8>(
                        memory_mapping,
                        address_addr,
                        std::mem::size_of::<Pubkey>() as u64,
                        invoke_context.get_check_aligned(),
                    )?;
                    if !is_nonoverlapping(
                        bump_seed_ref as *const _ as usize,
                        std::mem::size_of_val(bump_seed_ref),
                        address.as_ptr() as usize,
                        std::mem::size_of::<Pubkey>(),
                    ) {
                        return Err(SyscallError::CopyOverlapping.into());
                    }
                    *bump_seed_ref = bump_seed[0];
                    address.copy_from_slice(new_address.as_ref());
                    return Ok(0);
                }
            }
            bump_seed[0] = bump_seed[0].saturating_sub(1);
            consume_compute_meter(invoke_context, cost)?;
        }
        Ok(1)
    }
);

declare_builtin_function!(
    /// secp256k1_recover
    SyscallSecp256k1Recover,
    fn rust(
        invoke_context: &mut InvokeContext,
        hash_addr: u64,
        recovery_id_val: u64,
        signature_addr: u64,
        result_addr: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let cost = invoke_context.get_compute_budget().secp256k1_recover_cost;
        consume_compute_meter(invoke_context, cost)?;

        let hash = translate_slice::<u8>(
            memory_mapping,
            hash_addr,
            keccak::HASH_BYTES as u64,
            invoke_context.get_check_aligned(),
        )?;
        let signature = translate_slice::<u8>(
            memory_mapping,
            signature_addr,
            SECP256K1_SIGNATURE_LENGTH as u64,
            invoke_context.get_check_aligned(),
        )?;
        let secp256k1_recover_result = translate_slice_mut::<u8>(
            memory_mapping,
            result_addr,
            SECP256K1_PUBLIC_KEY_LENGTH as u64,
            invoke_context.get_check_aligned(),
        )?;

        let Ok(message) = libsecp256k1::Message::parse_slice(hash) else {
            return Ok(Secp256k1RecoverError::InvalidHash.into());
        };
        let Ok(adjusted_recover_id_val) = recovery_id_val.try_into() else {
            return Ok(Secp256k1RecoverError::InvalidRecoveryId.into());
        };
        let Ok(recovery_id) = libsecp256k1::RecoveryId::parse(adjusted_recover_id_val) else {
            return Ok(Secp256k1RecoverError::InvalidRecoveryId.into());
        };
        let Ok(signature) = libsecp256k1::Signature::parse_standard_slice(signature) else {
            return Ok(Secp256k1RecoverError::InvalidSignature.into());
        };

        let public_key = match libsecp256k1::recover(&message, &signature, &recovery_id) {
            Ok(key) => key.serialize(),
            Err(_) => {
                return Ok(Secp256k1RecoverError::InvalidSignature.into());
            }
        };

        secp256k1_recover_result.copy_from_slice(&public_key[1..65]);
        Ok(SUCCESS)
    }
);

declare_builtin_function!(
    // Elliptic Curve Point Validation
    //
    // Currently, only curve25519 Edwards and Ristretto representations are supported
    SyscallCurvePointValidation,
    fn rust(
        invoke_context: &mut InvokeContext,
        curve_id: u64,
        point_addr: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        use solana_curve25519::{curve_syscall_traits::*, edwards, ristretto};
        match curve_id {
            CURVE25519_EDWARDS => {
                let cost = invoke_context
                    .get_compute_budget()
                    .curve25519_edwards_validate_point_cost;
                consume_compute_meter(invoke_context, cost)?;

                let point = translate_type::<edwards::PodEdwardsPoint>(
                    memory_mapping,
                    point_addr,
                    invoke_context.get_check_aligned(),
                )?;

                if edwards::validate_edwards(point) {
                    Ok(0)
                } else {
                    Ok(1)
                }
            }
            CURVE25519_RISTRETTO => {
                let cost = invoke_context
                    .get_compute_budget()
                    .curve25519_ristretto_validate_point_cost;
                consume_compute_meter(invoke_context, cost)?;

                let point = translate_type::<ristretto::PodRistrettoPoint>(
                    memory_mapping,
                    point_addr,
                    invoke_context.get_check_aligned(),
                )?;

                if ristretto::validate_ristretto(point) {
                    Ok(0)
                } else {
                    Ok(1)
                }
            }
            _ => {
                if invoke_context
                    .get_feature_set()
                    .is_active(&abort_on_invalid_curve::id())
                {
                    Err(SyscallError::InvalidAttribute.into())
                } else {
                    Ok(1)
                }
            }
        }
    }
);

declare_builtin_function!(
    // Elliptic Curve Group Operations
    //
    // Currently, only curve25519 Edwards and Ristretto representations are supported
    SyscallCurveGroupOps,
    fn rust(
        invoke_context: &mut InvokeContext,
        curve_id: u64,
        group_op: u64,
        left_input_addr: u64,
        right_input_addr: u64,
        result_point_addr: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        use solana_curve25519::{curve_syscall_traits::*, edwards, ristretto, scalar};
        match curve_id {
            CURVE25519_EDWARDS => match group_op {
                ADD => {
                    let cost = invoke_context
                        .get_compute_budget()
                        .curve25519_edwards_add_cost;
                    consume_compute_meter(invoke_context, cost)?;

                    let left_point = translate_type::<edwards::PodEdwardsPoint>(
                        memory_mapping,
                        left_input_addr,
                        invoke_context.get_check_aligned(),
                    )?;
                    let right_point = translate_type::<edwards::PodEdwardsPoint>(
                        memory_mapping,
                        right_input_addr,
                        invoke_context.get_check_aligned(),
                    )?;

                    if let Some(result_point) = edwards::add_edwards(left_point, right_point) {
                        *translate_type_mut::<edwards::PodEdwardsPoint>(
                            memory_mapping,
                            result_point_addr,
                            invoke_context.get_check_aligned(),
                        )? = result_point;
                        Ok(0)
                    } else {
                        Ok(1)
                    }
                }
                SUB => {
                    let cost = invoke_context
                        .get_compute_budget()
                        .curve25519_edwards_subtract_cost;
                    consume_compute_meter(invoke_context, cost)?;

                    let left_point = translate_type::<edwards::PodEdwardsPoint>(
                        memory_mapping,
                        left_input_addr,
                        invoke_context.get_check_aligned(),
                    )?;
                    let right_point = translate_type::<edwards::PodEdwardsPoint>(
                        memory_mapping,
                        right_input_addr,
                        invoke_context.get_check_aligned(),
                    )?;

                    if let Some(result_point) = edwards::subtract_edwards(left_point, right_point) {
                        *translate_type_mut::<edwards::PodEdwardsPoint>(
                            memory_mapping,
                            result_point_addr,
                            invoke_context.get_check_aligned(),
                        )? = result_point;
                        Ok(0)
                    } else {
                        Ok(1)
                    }
                }
                MUL => {
                    let cost = invoke_context
                        .get_compute_budget()
                        .curve25519_edwards_multiply_cost;
                    consume_compute_meter(invoke_context, cost)?;

                    let scalar = translate_type::<scalar::PodScalar>(
                        memory_mapping,
                        left_input_addr,
                        invoke_context.get_check_aligned(),
                    )?;
                    let input_point = translate_type::<edwards::PodEdwardsPoint>(
                        memory_mapping,
                        right_input_addr,
                        invoke_context.get_check_aligned(),
                    )?;

                    if let Some(result_point) = edwards::multiply_edwards(scalar, input_point) {
                        *translate_type_mut::<edwards::PodEdwardsPoint>(
                            memory_mapping,
                            result_point_addr,
                            invoke_context.get_check_aligned(),
                        )? = result_point;
                        Ok(0)
                    } else {
                        Ok(1)
                    }
                }
                _ => {
                    if invoke_context
                        .get_feature_set()
                        .is_active(&abort_on_invalid_curve::id())
                    {
                        Err(SyscallError::InvalidAttribute.into())
                    } else {
                        Ok(1)
                    }
                }
            },

            CURVE25519_RISTRETTO => match group_op {
                ADD => {
                    let cost = invoke_context
                        .get_compute_budget()
                        .curve25519_ristretto_add_cost;
                    consume_compute_meter(invoke_context, cost)?;

                    let left_point = translate_type::<ristretto::PodRistrettoPoint>(
                        memory_mapping,
                        left_input_addr,
                        invoke_context.get_check_aligned(),
                    )?;
                    let right_point = translate_type::<ristretto::PodRistrettoPoint>(
                        memory_mapping,
                        right_input_addr,
                        invoke_context.get_check_aligned(),
                    )?;

                    if let Some(result_point) = ristretto::add_ristretto(left_point, right_point) {
                        *translate_type_mut::<ristretto::PodRistrettoPoint>(
                            memory_mapping,
                            result_point_addr,
                            invoke_context.get_check_aligned(),
                        )? = result_point;
                        Ok(0)
                    } else {
                        Ok(1)
                    }
                }
                SUB => {
                    let cost = invoke_context
                        .get_compute_budget()
                        .curve25519_ristretto_subtract_cost;
                    consume_compute_meter(invoke_context, cost)?;

                    let left_point = translate_type::<ristretto::PodRistrettoPoint>(
                        memory_mapping,
                        left_input_addr,
                        invoke_context.get_check_aligned(),
                    )?;
                    let right_point = translate_type::<ristretto::PodRistrettoPoint>(
                        memory_mapping,
                        right_input_addr,
                        invoke_context.get_check_aligned(),
                    )?;

                    if let Some(result_point) =
                        ristretto::subtract_ristretto(left_point, right_point)
                    {
                        *translate_type_mut::<ristretto::PodRistrettoPoint>(
                            memory_mapping,
                            result_point_addr,
                            invoke_context.get_check_aligned(),
                        )? = result_point;
                        Ok(0)
                    } else {
                        Ok(1)
                    }
                }
                MUL => {
                    let cost = invoke_context
                        .get_compute_budget()
                        .curve25519_ristretto_multiply_cost;
                    consume_compute_meter(invoke_context, cost)?;

                    let scalar = translate_type::<scalar::PodScalar>(
                        memory_mapping,
                        left_input_addr,
                        invoke_context.get_check_aligned(),
                    )?;
                    let input_point = translate_type::<ristretto::PodRistrettoPoint>(
                        memory_mapping,
                        right_input_addr,
                        invoke_context.get_check_aligned(),
                    )?;

                    if let Some(result_point) = ristretto::multiply_ristretto(scalar, input_point) {
                        *translate_type_mut::<ristretto::PodRistrettoPoint>(
                            memory_mapping,
                            result_point_addr,
                            invoke_context.get_check_aligned(),
                        )? = result_point;
                        Ok(0)
                    } else {
                        Ok(1)
                    }
                }
                _ => {
                    if invoke_context
                        .get_feature_set()
                        .is_active(&abort_on_invalid_curve::id())
                    {
                        Err(SyscallError::InvalidAttribute.into())
                    } else {
                        Ok(1)
                    }
                }
            },

            _ => {
                if invoke_context
                    .get_feature_set()
                    .is_active(&abort_on_invalid_curve::id())
                {
                    Err(SyscallError::InvalidAttribute.into())
                } else {
                    Ok(1)
                }
            }
        }
    }
);

declare_builtin_function!(
    // Elliptic Curve Multiscalar Multiplication
    //
    // Currently, only curve25519 Edwards and Ristretto representations are supported
    SyscallCurveMultiscalarMultiplication,
    fn rust(
        invoke_context: &mut InvokeContext,
        curve_id: u64,
        scalars_addr: u64,
        points_addr: u64,
        points_len: u64,
        result_point_addr: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        use solana_curve25519::{curve_syscall_traits::*, edwards, ristretto, scalar};

        if points_len > 512 {
            return Err(Box::new(SyscallError::InvalidLength));
        }

        match curve_id {
            CURVE25519_EDWARDS => {
                let cost = invoke_context
                    .get_compute_budget()
                    .curve25519_edwards_msm_base_cost
                    .saturating_add(
                        invoke_context
                            .get_compute_budget()
                            .curve25519_edwards_msm_incremental_cost
                            .saturating_mul(points_len.saturating_sub(1)),
                    );
                consume_compute_meter(invoke_context, cost)?;

                let scalars = translate_slice::<scalar::PodScalar>(
                    memory_mapping,
                    scalars_addr,
                    points_len,
                    invoke_context.get_check_aligned(),
                )?;

                let points = translate_slice::<edwards::PodEdwardsPoint>(
                    memory_mapping,
                    points_addr,
                    points_len,
                    invoke_context.get_check_aligned(),
                )?;

                if let Some(result_point) = edwards::multiscalar_multiply_edwards(scalars, points) {
                    *translate_type_mut::<edwards::PodEdwardsPoint>(
                        memory_mapping,
                        result_point_addr,
                        invoke_context.get_check_aligned(),
                    )? = result_point;
                    Ok(0)
                } else {
                    Ok(1)
                }
            }

            CURVE25519_RISTRETTO => {
                let cost = invoke_context
                    .get_compute_budget()
                    .curve25519_ristretto_msm_base_cost
                    .saturating_add(
                        invoke_context
                            .get_compute_budget()
                            .curve25519_ristretto_msm_incremental_cost
                            .saturating_mul(points_len.saturating_sub(1)),
                    );
                consume_compute_meter(invoke_context, cost)?;

                let scalars = translate_slice::<scalar::PodScalar>(
                    memory_mapping,
                    scalars_addr,
                    points_len,
                    invoke_context.get_check_aligned(),
                )?;

                let points = translate_slice::<ristretto::PodRistrettoPoint>(
                    memory_mapping,
                    points_addr,
                    points_len,
                    invoke_context.get_check_aligned(),
                )?;

                if let Some(result_point) =
                    ristretto::multiscalar_multiply_ristretto(scalars, points)
                {
                    *translate_type_mut::<ristretto::PodRistrettoPoint>(
                        memory_mapping,
                        result_point_addr,
                        invoke_context.get_check_aligned(),
                    )? = result_point;
                    Ok(0)
                } else {
                    Ok(1)
                }
            }

            _ => {
                if invoke_context
                    .get_feature_set()
                    .is_active(&abort_on_invalid_curve::id())
                {
                    Err(SyscallError::InvalidAttribute.into())
                } else {
                    Ok(1)
                }
            }
        }
    }
);

declare_builtin_function!(
    /// Set return data
    SyscallSetReturnData,
    fn rust(
        invoke_context: &mut InvokeContext,
        addr: u64,
        len: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let budget = invoke_context.get_compute_budget();

        let cost = len
            .checked_div(budget.cpi_bytes_per_unit)
            .unwrap_or(u64::MAX)
            .saturating_add(budget.syscall_base_cost);
        consume_compute_meter(invoke_context, cost)?;

        if len > MAX_RETURN_DATA as u64 {
            return Err(SyscallError::ReturnDataTooLarge(len, MAX_RETURN_DATA as u64).into());
        }

        let return_data = if len == 0 {
            Vec::new()
        } else {
            translate_slice::<u8>(
                memory_mapping,
                addr,
                len,
                invoke_context.get_check_aligned(),
            )?
            .to_vec()
        };
        let transaction_context = &mut invoke_context.transaction_context;
        let program_id = *transaction_context
            .get_current_instruction_context()
            .and_then(|instruction_context| {
                instruction_context.get_last_program_key(transaction_context)
            })?;

        transaction_context.set_return_data(program_id, return_data)?;

        Ok(0)
    }
);

declare_builtin_function!(
    /// Get return data
    SyscallGetReturnData,
    fn rust(
        invoke_context: &mut InvokeContext,
        return_data_addr: u64,
        length: u64,
        program_id_addr: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let budget = invoke_context.get_compute_budget();

        consume_compute_meter(invoke_context, budget.syscall_base_cost)?;

        let (program_id, return_data) = invoke_context.transaction_context.get_return_data();
        let length = length.min(return_data.len() as u64);
        if length != 0 {
            let cost = length
                .saturating_add(size_of::<Pubkey>() as u64)
                .checked_div(budget.cpi_bytes_per_unit)
                .unwrap_or(u64::MAX);
            consume_compute_meter(invoke_context, cost)?;

            let return_data_result = translate_slice_mut::<u8>(
                memory_mapping,
                return_data_addr,
                length,
                invoke_context.get_check_aligned(),
            )?;

            let to_slice = return_data_result;
            let from_slice = return_data
                .get(..length as usize)
                .ok_or(SyscallError::InvokeContextBorrowFailed)?;
            if to_slice.len() != from_slice.len() {
                return Err(SyscallError::InvalidLength.into());
            }
            to_slice.copy_from_slice(from_slice);

            let program_id_result = translate_type_mut::<Pubkey>(
                memory_mapping,
                program_id_addr,
                invoke_context.get_check_aligned(),
            )?;

            if !is_nonoverlapping(
                to_slice.as_ptr() as usize,
                length as usize,
                program_id_result as *const _ as usize,
                std::mem::size_of::<Pubkey>(),
            ) {
                return Err(SyscallError::CopyOverlapping.into());
            }

            *program_id_result = *program_id;
        }

        // Return the actual length, rather the length returned
        Ok(return_data.len() as u64)
    }
);

declare_builtin_function!(
    /// Get a processed sigling instruction
    SyscallGetProcessedSiblingInstruction,
    fn rust(
        invoke_context: &mut InvokeContext,
        index: u64,
        meta_addr: u64,
        program_id_addr: u64,
        data_addr: u64,
        accounts_addr: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let budget = invoke_context.get_compute_budget();

        consume_compute_meter(invoke_context, budget.syscall_base_cost)?;

        // Reverse iterate through the instruction trace,
        // ignoring anything except instructions on the same level
        let stack_height = invoke_context.get_stack_height();
        let instruction_trace_length = invoke_context
            .transaction_context
            .get_instruction_trace_length();
        let mut reverse_index_at_stack_height = 0;
        let mut found_instruction_context = None;
        for index_in_trace in (0..instruction_trace_length).rev() {
            let instruction_context = invoke_context
                .transaction_context
                .get_instruction_context_at_index_in_trace(index_in_trace)?;
            if instruction_context.get_stack_height() < stack_height {
                break;
            }
            if instruction_context.get_stack_height() == stack_height {
                if index.saturating_add(1) == reverse_index_at_stack_height {
                    found_instruction_context = Some(instruction_context);
                    break;
                }
                reverse_index_at_stack_height = reverse_index_at_stack_height.saturating_add(1);
            }
        }

        if let Some(instruction_context) = found_instruction_context {
            let result_header = translate_type_mut::<ProcessedSiblingInstruction>(
                memory_mapping,
                meta_addr,
                invoke_context.get_check_aligned(),
            )?;

            if result_header.data_len == (instruction_context.get_instruction_data().len() as u64)
                && result_header.accounts_len
                    == (instruction_context.get_number_of_instruction_accounts() as u64)
            {
                let program_id = translate_type_mut::<Pubkey>(
                    memory_mapping,
                    program_id_addr,
                    invoke_context.get_check_aligned(),
                )?;
                let data = translate_slice_mut::<u8>(
                    memory_mapping,
                    data_addr,
                    result_header.data_len,
                    invoke_context.get_check_aligned(),
                )?;
                let accounts = translate_slice_mut::<AccountMeta>(
                    memory_mapping,
                    accounts_addr,
                    result_header.accounts_len,
                    invoke_context.get_check_aligned(),
                )?;

                if !is_nonoverlapping(
                    result_header as *const _ as usize,
                    std::mem::size_of::<ProcessedSiblingInstruction>(),
                    program_id as *const _ as usize,
                    std::mem::size_of::<Pubkey>(),
                ) || !is_nonoverlapping(
                    result_header as *const _ as usize,
                    std::mem::size_of::<ProcessedSiblingInstruction>(),
                    accounts.as_ptr() as usize,
                    std::mem::size_of::<AccountMeta>()
                        .saturating_mul(result_header.accounts_len as usize),
                ) || !is_nonoverlapping(
                    result_header as *const _ as usize,
                    std::mem::size_of::<ProcessedSiblingInstruction>(),
                    data.as_ptr() as usize,
                    result_header.data_len as usize,
                ) || !is_nonoverlapping(
                    program_id as *const _ as usize,
                    std::mem::size_of::<Pubkey>(),
                    data.as_ptr() as usize,
                    result_header.data_len as usize,
                ) || !is_nonoverlapping(
                    program_id as *const _ as usize,
                    std::mem::size_of::<Pubkey>(),
                    accounts.as_ptr() as usize,
                    std::mem::size_of::<AccountMeta>()
                        .saturating_mul(result_header.accounts_len as usize),
                ) || !is_nonoverlapping(
                    data.as_ptr() as usize,
                    result_header.data_len as usize,
                    accounts.as_ptr() as usize,
                    std::mem::size_of::<AccountMeta>()
                        .saturating_mul(result_header.accounts_len as usize),
                ) {
                    return Err(SyscallError::CopyOverlapping.into());
                }

                *program_id = *instruction_context
                    .get_last_program_key(invoke_context.transaction_context)?;
                data.clone_from_slice(instruction_context.get_instruction_data());
                let account_metas = (0..instruction_context.get_number_of_instruction_accounts())
                    .map(|instruction_account_index| {
                        Ok(AccountMeta {
                            pubkey: *invoke_context
                                .transaction_context
                                .get_key_of_account_at_index(
                                    instruction_context
                                        .get_index_of_instruction_account_in_transaction(
                                            instruction_account_index,
                                        )?,
                                )?,
                            is_signer: instruction_context
                                .is_instruction_account_signer(instruction_account_index)?,
                            is_writable: instruction_context
                                .is_instruction_account_writable(instruction_account_index)?,
                        })
                    })
                    .collect::<Result<Vec<_>, InstructionError>>()?;
                accounts.clone_from_slice(account_metas.as_slice());
            }
            result_header.data_len = instruction_context.get_instruction_data().len() as u64;
            result_header.accounts_len =
                instruction_context.get_number_of_instruction_accounts() as u64;
            return Ok(true as u64);
        }
        Ok(false as u64)
    }
);

declare_builtin_function!(
    /// Get current call stack height
    SyscallGetStackHeight,
    fn rust(
        invoke_context: &mut InvokeContext,
        _arg1: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        _memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let budget = invoke_context.get_compute_budget();

        consume_compute_meter(invoke_context, budget.syscall_base_cost)?;

        Ok(invoke_context.get_stack_height() as u64)
    }
);

declare_builtin_function!(
    /// alt_bn128 group operations
    SyscallAltBn128,
    fn rust(
        invoke_context: &mut InvokeContext,
        group_op: u64,
        input_addr: u64,
        input_size: u64,
        result_addr: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        use solana_bn254::prelude::{ALT_BN128_ADD, ALT_BN128_MUL, ALT_BN128_PAIRING};
        let budget = invoke_context.get_compute_budget();
        let (cost, output): (u64, usize) = match group_op {
            ALT_BN128_ADD => (
                budget.alt_bn128_addition_cost,
                ALT_BN128_ADDITION_OUTPUT_LEN,
            ),
            ALT_BN128_MUL => (
                budget.alt_bn128_multiplication_cost,
                ALT_BN128_MULTIPLICATION_OUTPUT_LEN,
            ),
            ALT_BN128_PAIRING => {
                let ele_len = input_size
                    .checked_div(ALT_BN128_PAIRING_ELEMENT_LEN as u64)
                    .expect("div by non-zero constant");
                let cost = budget
                    .alt_bn128_pairing_one_pair_cost_first
                    .saturating_add(
                        budget
                            .alt_bn128_pairing_one_pair_cost_other
                            .saturating_mul(ele_len.saturating_sub(1)),
                    )
                    .saturating_add(budget.sha256_base_cost)
                    .saturating_add(input_size)
                    .saturating_add(ALT_BN128_PAIRING_OUTPUT_LEN as u64);
                (cost, ALT_BN128_PAIRING_OUTPUT_LEN)
            }
            _ => {
                return Err(SyscallError::InvalidAttribute.into());
            }
        };

        consume_compute_meter(invoke_context, cost)?;

        let input = translate_slice::<u8>(
            memory_mapping,
            input_addr,
            input_size,
            invoke_context.get_check_aligned(),
        )?;

        let call_result = translate_slice_mut::<u8>(
            memory_mapping,
            result_addr,
            output as u64,
            invoke_context.get_check_aligned(),
        )?;

        let calculation = match group_op {
            ALT_BN128_ADD => alt_bn128_addition,
            ALT_BN128_MUL => {
                let fix_alt_bn128_multiplication_input_length = invoke_context
                    .get_feature_set()
                    .is_active(&feature_set::fix_alt_bn128_multiplication_input_length::id());
                if fix_alt_bn128_multiplication_input_length {
                    alt_bn128_multiplication
                } else {
                    alt_bn128_multiplication_128
                }
            }
            ALT_BN128_PAIRING => alt_bn128_pairing,
            _ => {
                return Err(SyscallError::InvalidAttribute.into());
            }
        };

        let simplify_alt_bn128_syscall_error_codes = invoke_context
            .get_feature_set()
            .is_active(&feature_set::simplify_alt_bn128_syscall_error_codes::id());

        let result_point = match calculation(input) {
            Ok(result_point) => result_point,
            Err(e) => {
                return if simplify_alt_bn128_syscall_error_codes {
                    Ok(1)
                } else {
                    Ok(e.into())
                };
            }
        };

        // This can never happen and should be removed when the
        // simplify_alt_bn128_syscall_error_codes feature gets activated
        if result_point.len() != output && !simplify_alt_bn128_syscall_error_codes {
            return Ok(AltBn128Error::SliceOutOfBounds.into());
        }

        call_result.copy_from_slice(&result_point);
        Ok(SUCCESS)
    }
);

declare_builtin_function!(
    /// Big integer modular exponentiation
    SyscallBigModExp,
    fn rust(
        invoke_context: &mut InvokeContext,
        params: u64,
        return_value: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let params = &translate_slice::<BigModExpParams>(
            memory_mapping,
            params,
            1,
            invoke_context.get_check_aligned(),
        )?
        .first()
        .ok_or(SyscallError::InvalidLength)?;

        if params.base_len > 512 || params.exponent_len > 512 || params.modulus_len > 512 {
            return Err(Box::new(SyscallError::InvalidLength));
        }

        let input_len: u64 = std::cmp::max(params.base_len, params.exponent_len);
        let input_len: u64 = std::cmp::max(input_len, params.modulus_len);

        let budget = invoke_context.get_compute_budget();
        // the compute units are calculated by the quadratic equation `0.5 input_len^2 + 190`
        consume_compute_meter(
            invoke_context,
            budget.syscall_base_cost.saturating_add(
                input_len
                    .saturating_mul(input_len)
                    .checked_div(budget.big_modular_exponentiation_cost_divisor)
                    .unwrap_or(u64::MAX)
                    .saturating_add(budget.big_modular_exponentiation_base_cost),
            ),
        )?;

        let base = translate_slice::<u8>(
            memory_mapping,
            params.base as *const _ as u64,
            params.base_len,
            invoke_context.get_check_aligned(),
        )?;

        let exponent = translate_slice::<u8>(
            memory_mapping,
            params.exponent as *const _ as u64,
            params.exponent_len,
            invoke_context.get_check_aligned(),
        )?;

        let modulus = translate_slice::<u8>(
            memory_mapping,
            params.modulus as *const _ as u64,
            params.modulus_len,
            invoke_context.get_check_aligned(),
        )?;

        let value = big_mod_exp(base, exponent, modulus);

        let return_value = translate_slice_mut::<u8>(
            memory_mapping,
            return_value,
            params.modulus_len,
            invoke_context.get_check_aligned(),
        )?;
        return_value.copy_from_slice(value.as_slice());

        Ok(0)
    }
);

declare_builtin_function!(
    // Poseidon
    SyscallPoseidon,
    fn rust(
        invoke_context: &mut InvokeContext,
        parameters: u64,
        endianness: u64,
        vals_addr: u64,
        vals_len: u64,
        result_addr: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let parameters: poseidon::Parameters = parameters.try_into()?;
        let endianness: poseidon::Endianness = endianness.try_into()?;

        if vals_len > 12 {
            ic_msg!(
                invoke_context,
                "Poseidon hashing {} sequences is not supported",
                vals_len,
            );
            return Err(SyscallError::InvalidLength.into());
        }

        let budget = invoke_context.get_compute_budget();
        let Some(cost) = budget.poseidon_cost(vals_len) else {
            ic_msg!(
                invoke_context,
                "Overflow while calculating the compute cost"
            );
            return Err(SyscallError::ArithmeticOverflow.into());
        };
        consume_compute_meter(invoke_context, cost.to_owned())?;

        let hash_result = translate_slice_mut::<u8>(
            memory_mapping,
            result_addr,
            poseidon::HASH_BYTES as u64,
            invoke_context.get_check_aligned(),
        )?;
        let inputs = translate_slice_of_slices::<u8>(
            memory_mapping,
            vals_addr,
            vals_len,
            invoke_context.get_check_aligned(),
        )?;
        let inputs = inputs
            .iter()
            .map(|input| input.translate(memory_mapping, invoke_context.get_check_aligned()))
            .collect::<Result<Vec<_>, Error>>()?;

        let simplify_alt_bn128_syscall_error_codes = invoke_context
            .get_feature_set()
            .is_active(&feature_set::simplify_alt_bn128_syscall_error_codes::id());

        let hash = match poseidon::hashv(parameters, endianness, inputs.as_slice()) {
            Ok(hash) => hash,
            Err(e) => {
                return if simplify_alt_bn128_syscall_error_codes {
                    Ok(1)
                } else {
                    Ok(e.into())
                };
            }
        };
        hash_result.copy_from_slice(&hash.to_bytes());

        Ok(SUCCESS)
    }
);

declare_builtin_function!(
    /// Read remaining compute units
    SyscallRemainingComputeUnits,
    fn rust(
        invoke_context: &mut InvokeContext,
        _arg1: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        _memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let budget = invoke_context.get_compute_budget();
        consume_compute_meter(invoke_context, budget.syscall_base_cost)?;

        use solana_sbpf::vm::ContextObject;
        Ok(invoke_context.get_remaining())
    }
);

declare_builtin_function!(
    /// alt_bn128 g1 and g2 compression and decompression
    SyscallAltBn128Compression,
    fn rust(
        invoke_context: &mut InvokeContext,
        op: u64,
        input_addr: u64,
        input_size: u64,
        result_addr: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        use solana_bn254::compression::prelude::{
            alt_bn128_g1_compress, alt_bn128_g1_decompress, alt_bn128_g2_compress,
            alt_bn128_g2_decompress, ALT_BN128_G1_COMPRESS, ALT_BN128_G1_DECOMPRESS,
            ALT_BN128_G2_COMPRESS, ALT_BN128_G2_DECOMPRESS, G1, G1_COMPRESSED, G2, G2_COMPRESSED,
        };
        let budget = invoke_context.get_compute_budget();
        let base_cost = budget.syscall_base_cost;
        let (cost, output): (u64, usize) = match op {
            ALT_BN128_G1_COMPRESS => (
                base_cost.saturating_add(budget.alt_bn128_g1_compress),
                G1_COMPRESSED,
            ),
            ALT_BN128_G1_DECOMPRESS => {
                (base_cost.saturating_add(budget.alt_bn128_g1_decompress), G1)
            }
            ALT_BN128_G2_COMPRESS => (
                base_cost.saturating_add(budget.alt_bn128_g2_compress),
                G2_COMPRESSED,
            ),
            ALT_BN128_G2_DECOMPRESS => {
                (base_cost.saturating_add(budget.alt_bn128_g2_decompress), G2)
            }
            _ => {
                return Err(SyscallError::InvalidAttribute.into());
            }
        };

        consume_compute_meter(invoke_context, cost)?;

        let input = translate_slice::<u8>(
            memory_mapping,
            input_addr,
            input_size,
            invoke_context.get_check_aligned(),
        )?;

        let call_result = translate_slice_mut::<u8>(
            memory_mapping,
            result_addr,
            output as u64,
            invoke_context.get_check_aligned(),
        )?;

        let simplify_alt_bn128_syscall_error_codes = invoke_context
            .get_feature_set()
            .is_active(&feature_set::simplify_alt_bn128_syscall_error_codes::id());

        match op {
            ALT_BN128_G1_COMPRESS => {
                let result_point = match alt_bn128_g1_compress(input) {
                    Ok(result_point) => result_point,
                    Err(e) => {
                        return if simplify_alt_bn128_syscall_error_codes {
                            Ok(1)
                        } else {
                            Ok(e.into())
                        };
                    }
                };
                call_result.copy_from_slice(&result_point);
                Ok(SUCCESS)
            }
            ALT_BN128_G1_DECOMPRESS => {
                let result_point = match alt_bn128_g1_decompress(input) {
                    Ok(result_point) => result_point,
                    Err(e) => {
                        return if simplify_alt_bn128_syscall_error_codes {
                            Ok(1)
                        } else {
                            Ok(e.into())
                        };
                    }
                };
                call_result.copy_from_slice(&result_point);
                Ok(SUCCESS)
            }
            ALT_BN128_G2_COMPRESS => {
                let result_point = match alt_bn128_g2_compress(input) {
                    Ok(result_point) => result_point,
                    Err(e) => {
                        return if simplify_alt_bn128_syscall_error_codes {
                            Ok(1)
                        } else {
                            Ok(e.into())
                        };
                    }
                };
                call_result.copy_from_slice(&result_point);
                Ok(SUCCESS)
            }
            ALT_BN128_G2_DECOMPRESS => {
                let result_point = match alt_bn128_g2_decompress(input) {
                    Ok(result_point) => result_point,
                    Err(e) => {
                        return if simplify_alt_bn128_syscall_error_codes {
                            Ok(1)
                        } else {
                            Ok(e.into())
                        };
                    }
                };
                call_result.copy_from_slice(&result_point);
                Ok(SUCCESS)
            }
            _ => Err(SyscallError::InvalidAttribute.into()),
        }
    }
);

declare_builtin_function!(
    // Generic Hashing Syscall
    SyscallHash<H: HasherImpl>,
    fn rust(
        invoke_context: &mut InvokeContext,
        vals_addr: u64,
        vals_len: u64,
        result_addr: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let compute_budget = invoke_context.get_compute_budget();
        let hash_base_cost = H::get_base_cost(compute_budget);
        let hash_byte_cost = H::get_byte_cost(compute_budget);
        let hash_max_slices = H::get_max_slices(compute_budget);
        if hash_max_slices < vals_len {
            ic_msg!(
                invoke_context,
                "{} Hashing {} sequences in one syscall is over the limit {}",
                H::NAME,
                vals_len,
                hash_max_slices,
            );
            return Err(SyscallError::TooManySlices.into());
        }

        consume_compute_meter(invoke_context, hash_base_cost)?;

        let hash_result = translate_slice_mut::<u8>(
            memory_mapping,
            result_addr,
            std::mem::size_of::<H::Output>() as u64,
            invoke_context.get_check_aligned(),
        )?;
        let mut hasher = H::create_hasher();
        if vals_len > 0 {
            let vals = translate_slice_of_slices::<u8>(
                memory_mapping,
                vals_addr,
                vals_len,
                invoke_context.get_check_aligned(),
            )?;

            for val in vals.iter() {
                let bytes = val.translate(memory_mapping, invoke_context.get_check_aligned())?;
                let cost = compute_budget.mem_op_base_cost.max(
                    hash_byte_cost.saturating_mul(
                        val.len()
                            .checked_div(2)
                            .expect("div by non-zero literal"),
                    ),
                );
                consume_compute_meter(invoke_context, cost)?;
                hasher.hash(bytes);
            }
        }
        hash_result.copy_from_slice(hasher.result().as_ref());
        Ok(0)
    }
);

declare_builtin_function!(
    // Get Epoch Stake Syscall
    SyscallGetEpochStake,
    fn rust(
        invoke_context: &mut InvokeContext,
        var_addr: u64,
        _arg2: u64,
        _arg3: u64,
        _arg4: u64,
        _arg5: u64,
        memory_mapping: &mut MemoryMapping,
    ) -> Result<u64, Error> {
        let compute_budget = invoke_context.get_compute_budget();

        if var_addr == 0 {
            // As specified by SIMD-0133: If `var_addr` is a null pointer:
            //
            // Compute units:
            //
            // ```
            // syscall_base
            // ```
            let compute_units = compute_budget.syscall_base_cost;
            consume_compute_meter(invoke_context, compute_units)?;
            //
            // Control flow:
            //
            // - The syscall aborts the virtual machine if:
            //     - Compute budget is exceeded.
            // - Otherwise, the syscall returns a `u64` integer representing the total active
            //   stake on the cluster for the current epoch.
            Ok(invoke_context.get_epoch_total_stake())
        } else {
            // As specified by SIMD-0133: If `var_addr` is _not_ a null pointer:
            //
            // Compute units:
            //
            // ```
            // syscall_base + floor(PUBKEY_BYTES/cpi_bytes_per_unit) + mem_op_base
            // ```
            let compute_units = compute_budget
                .syscall_base_cost
                .saturating_add(
                    (PUBKEY_BYTES as u64)
                        .checked_div(compute_budget.cpi_bytes_per_unit)
                        .unwrap_or(u64::MAX),
                )
                .saturating_add(compute_budget.mem_op_base_cost);
            consume_compute_meter(invoke_context, compute_units)?;
            //
            // Control flow:
            //
            // - The syscall aborts the virtual machine if:
            //     - Not all bytes in VM memory range `[vote_addr, vote_addr + 32)` are
            //       readable.
            //     - Compute budget is exceeded.
            // - Otherwise, the syscall returns a `u64` integer representing the total active
            //   stake delegated to the vote account at the provided address.
            //   If the provided vote address corresponds to an account that is not a vote
            //   account or does not exist, the syscall will return `0` for active stake.
            let check_aligned = invoke_context.get_check_aligned();
            let vote_address = translate_type::<Pubkey>(memory_mapping, var_addr, check_aligned)?;

            Ok(invoke_context.get_epoch_vote_account_stake(vote_address))
        }
    }
);
