use {
    solana_builtins_default_costs::{
        get_builtin_migration_feature_index, BuiltinMigrationFeatureIndex, MAYBE_BUILTIN_KEY,
    },
    solana_packet::PACKET_DATA_SIZE,
    solana_pubkey::Pubkey,
};

// The maximum number of pubkeys that a packet can contain.
pub(crate) const FILTER_SIZE: u8 = (PACKET_DATA_SIZE / core::mem::size_of::<Pubkey>()) as u8;

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) enum ProgramKind {
    NotBuiltin,
    Builtin,
    // Builtin program maybe in process of being migrated to core bpf,
    // if core_bpf_migration_feature is activated, then the migration has
    // completed and it should no longer be considered as builtin
    MigratingBuiltin {
        core_bpf_migration_feature_index: usize,
    },
}

pub(crate) struct BuiltinProgramsFilter {
    // array of slots for all possible static and sanitized program_id_index,
    // each slot indicates if a program_id_index has not been checked (eg, None),
    // or already checked with result (eg, Some(ProgramKind)) that can be reused.
    program_kind: [Option<ProgramKind>; FILTER_SIZE as usize],
}

impl BuiltinProgramsFilter {
    pub(crate) fn new() -> Self {
        BuiltinProgramsFilter {
            program_kind: [None; FILTER_SIZE as usize],
        }
    }

    pub(crate) fn get_program_kind(&mut self, index: usize, program_id: &Pubkey) -> ProgramKind {
        *self
            .program_kind
            .get_mut(index)
            .expect("program id index is sanitized")
            .get_or_insert_with(|| Self::check_program_kind(program_id))
    }

    #[inline]
    fn check_program_kind(program_id: &Pubkey) -> ProgramKind {
        if !MAYBE_BUILTIN_KEY[program_id.as_ref()[0] as usize] {
            return ProgramKind::NotBuiltin;
        }

        match get_builtin_migration_feature_index(program_id) {
            BuiltinMigrationFeatureIndex::NotBuiltin => ProgramKind::NotBuiltin,
            BuiltinMigrationFeatureIndex::BuiltinNoMigrationFeature => ProgramKind::Builtin,
            BuiltinMigrationFeatureIndex::BuiltinWithMigrationFeature(
                core_bpf_migration_feature_index,
            ) => ProgramKind::MigratingBuiltin {
                core_bpf_migration_feature_index,
            },
        }
    }
}
