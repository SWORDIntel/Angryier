//! Exact source/profile-witness identities for selected x86 XOP UIMM32 memory forms.
//!
//! Candidate identity recognition only: no instruction semantics or fidelity
//! claims are made. A caller must provide the machine mode explicitly.

use angryier_arch::{AccessKind, DecodedInstruction, OperandKind, OperandVisibility};

use crate::isanity_catalogue_forms::InstructionMode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Uimm32MemoryForm {
    pub canonical_id: &'static str,
    pub iform: &'static str,
    pub iform_value: u32,
    pub mode: InstructionMode,
    pub gpr_width_bits: Option<u16>,
    pub memory_width_bits: Option<u16>,
    pub witnesses: &'static [&'static [u8]],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnsupportedUimm32MemoryIdentity {
    pub canonical_id: &'static str,
    pub iform: &'static str,
    pub iform_value: u32,
    pub source_mode: &'static str,
    pub reason: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnsupportedUimm32MemoryProfileObservation {
    pub canonical_id: &'static str,
    pub iform: &'static str,
    pub iform_value: u32,
    pub source_mode: &'static str,
    pub profile: &'static str,
    pub chip: &'static str,
    pub reason: &'static str,
    pub witness: &'static [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recognition {
    Mapped {
        canonical_id: &'static str,
        iform: &'static str,
    },
    UnknownIform,
    WrongMode,
    WrongEncoding,
    WrongOperandShape,
}

include!("isanity_uimm32_memory_generated.rs");

/// Resolve an exact pinned XED witness under a caller-selected machine mode.
pub fn resolve_decoded(
    bytes: &[u8],
    mode: InstructionMode,
    iform: &str,
    iform_value: u32,
    decoded: &DecodedInstruction,
) -> Recognition {
    if !UIMM32_MEMORY_FORMS.iter().any(|form| form.iform == iform)
        && !UIMM32_MEMORY_UNSUPPORTED.iter().any(|form| form.iform == iform)
    {
        return Recognition::UnknownIform;
    }
    if !UIMM32_MEMORY_FORMS
        .iter()
        .any(|form| form.iform == iform && form.iform_value == iform_value)
        && !UIMM32_MEMORY_UNSUPPORTED
            .iter()
            .any(|form| form.iform == iform && form.iform_value == iform_value)
    {
        return Recognition::WrongEncoding;
    }
    let Some(form) = UIMM32_MEMORY_FORMS.iter().find(|form| {
        form.iform == iform && form.iform_value == iform_value && form.mode == mode && form.witnesses.contains(&bytes)
    }) else {
        let has_mode = UIMM32_MEMORY_FORMS
            .iter()
            .any(|form| form.iform == iform && form.iform_value == iform_value && form.mode == mode);
        return if has_mode {
            Recognition::WrongEncoding
        } else {
            Recognition::WrongMode
        };
    };
    let explicit: Vec<_> = decoded
        .operands
        .iter()
        .filter(|operand| operand.visibility == OperandVisibility::Explicit)
        .collect();
    if explicit.len() != 3 {
        return Recognition::WrongOperandShape;
    }
    let gpr = explicit[0];
    let memory = explicit[1];
    let immediate = explicit[2];
    if gpr.access != AccessKind::Write
        || !matches!(gpr.kind, OperandKind::Register(_))
        || form.gpr_width_bits.is_some_and(|width| gpr.width_bits != width)
        || memory.access != AccessKind::Read
        || !matches!(memory.kind, OperandKind::Memory(_))
        || form.memory_width_bits.is_some_and(|width| memory.width_bits != width)
        || immediate.width_bits != 32
        || immediate.access != AccessKind::Read
        || !matches!(immediate.kind, OperandKind::Immediate(value) if !value.signed)
    {
        return Recognition::WrongOperandShape;
    }
    Recognition::Mapped {
        canonical_id: form.canonical_id,
        iform: form.iform,
    }
}

/// Source identities that Angryier cannot select without conflating modes.
pub fn unsupported_identities() -> &'static [UnsupportedUimm32MemoryIdentity] {
    UIMM32_MEMORY_UNSUPPORTED
}

/// Return exact chip-profile/address-width observations excluded from mapping.
pub fn unsupported_profile_observations() -> &'static [UnsupportedUimm32MemoryProfileObservation] {
    UIMM32_MEMORY_UNSUPPORTED_PROFILES
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "xed")]
    #[test]
    fn exact_witnesses_resolve_only_in_the_explicit_legacy_or_long_mode()
    -> Result<(), angryier_arch_xed_ffi::XedAdapterError> {
        use angryier_arch_xed_ffi::{XedDecoder, XedMachineMode};
        use angryier_types::TargetProfileId;

        assert_eq!(UIMM32_MEMORY_FORMS.len(), UIMM32_MEMORY_MAPPED_COUNT);
        assert_eq!(unsupported_identities().len(), UIMM32_MEMORY_UNSUPPORTED_COUNT);
        assert_eq!(UIMM32_MEMORY_FORMS.len() + unsupported_identities().len(), 15);
        assert_eq!(
            unsupported_profile_observations().len(),
            UIMM32_MEMORY_UNSUPPORTED_PROFILE_COUNT
        );
        for (mode, xed_mode) in [
            (InstructionMode::Long64, XedMachineMode::Intel64),
            (InstructionMode::Legacy32, XedMachineMode::Legacy32),
        ] {
            let decoder = XedDecoder::with_profile_id_and_mode(TargetProfileId(1), xed_mode);
            for form in UIMM32_MEMORY_FORMS.iter().filter(|form| form.mode == mode) {
                for witness in form.witnesses {
                    let (decoded, iform) = decoder.decode_with_iform(0x4000, witness)?;
                    assert_eq!(iform.name, form.iform, "{witness:02x?}");
                    assert_eq!(iform.value, form.iform_value);
                    assert_eq!(
                        resolve_decoded(witness, mode, &iform.name, iform.value, &decoded),
                        Recognition::Mapped {
                            canonical_id: form.canonical_id,
                            iform: form.iform
                        },
                        "{witness:02x?}"
                    );
                }
            }
        }
        Ok(())
    }

    #[cfg(feature = "xed")]
    #[test]
    fn rejects_near_misses_and_wrong_iform_discriminants() -> Result<(), angryier_arch_xed_ffi::XedAdapterError> {
        use angryier_arch_xed_ffi::{XedDecoder, XedMachineMode};
        use angryier_types::TargetProfileId;

        for form in UIMM32_MEMORY_FORMS {
            let xed_mode = match form.mode {
                InstructionMode::Long64 => XedMachineMode::Intel64,
                InstructionMode::Legacy32 => XedMachineMode::Legacy32,
                InstructionMode::Legacy16 => XedMachineMode::Legacy16,
            };
            let decoder = XedDecoder::with_profile_id_and_mode(TargetProfileId(1), xed_mode);
            let witness = form.witnesses[0];
            let (decoded, iform) = decoder.decode_with_iform(0x4000, witness)?;
            let mut changed = witness.to_vec();
            *changed.last_mut().expect("nonempty instruction") ^= 1;
            assert_eq!(
                resolve_decoded(&changed, form.mode, &iform.name, iform.value, &decoded),
                Recognition::WrongEncoding
            );
            assert_eq!(
                resolve_decoded(witness, form.mode, &iform.name, iform.value.wrapping_add(1), &decoded),
                Recognition::WrongEncoding
            );
        }
        Ok(())
    }

    #[test]
    fn compatibility_modes_remain_reason_coded_and_distinct() {
        assert!(unsupported_identities().iter().all(|identity| {
            identity.reason.starts_with("unsupported-mode:")
                && matches!(identity.source_mode, "legacy16" | "compat16" | "compat32")
        }));
        assert_eq!(
            UIMM32_MEMORY_FORMS
                .iter()
                .map(|form| form.canonical_id)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            6
        );
        let ids: std::collections::HashSet<_> = UIMM32_MEMORY_FORMS
            .iter()
            .map(|form| form.canonical_id)
            .chain(unsupported_identities().iter().map(|form| form.canonical_id))
            .collect();
        assert_eq!(ids.len(), 15);
        assert_eq!(unsupported_profile_observations().len(), 69);
        assert!(
            unsupported_profile_observations()
                .iter()
                .all(|observation| !observation.reason.is_empty() && !observation.chip.is_empty())
        );
        assert_eq!(
            unsupported_profile_observations()
                .iter()
                .filter(|observation| observation.reason.starts_with("decoder-error:"))
                .count(),
            57
        );
        assert_eq!(
            unsupported_profile_observations()
                .iter()
                .filter(|observation| observation.reason.starts_with("unsupported-address-size:16:"))
                .count(),
            12
        );
    }
}
