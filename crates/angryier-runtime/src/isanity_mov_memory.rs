//! Exact-witness candidate identity recognition for the reviewed ISANITY MOV
//! GPRv-memory slice. This is identity evidence only: semantics remain
//! unmapped and fidelity unassessed. The six rows cover only three direct-RAX
//! XED byte witnesses per identity; other addressing forms remain unknown.

use angryier_arch::{AccessKind, DecodedInstruction, OperandKind, OperandVisibility};
use angryier_arch_xed_ffi::XedIformMetadata;

use crate::isanity_catalogue_forms::InstructionMode;

pub const PROVIDER: &str = "Intel XED";
pub const PROVIDER_VERSION: &str = "xed-sys 0.6.0+xed-2024.05.20";
pub const EVIDENCE_SHA256: &str = "4c72d18360748f61b4357b89e1005b66876597bc02e4ac89008b9d1451e57800";
pub const ADDRESSING_EVIDENCE_SHA256: &str = "8f8b5c75537d1a8a5f117432ab711f9c1e3a5e4c7bc9c48dc8517f0f11740165";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecoderProvenance<'a> {
    pub provider: &'a str,
    pub version: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperandKindTag {
    Register,
    Memory,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExpectedOperand {
    pub kind: OperandKindTag,
    pub width_bits: u16,
    pub access: AccessKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MovMemoryForm {
    pub canonical_id: &'static str,
    pub iform: &'static str,
    pub iform_value: u32,
    pub mode: InstructionMode,
    pub operands: [ExpectedOperand; 2],
    pub witnesses: &'static [&'static [u8]],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recognition {
    CandidateRecognized {
        canonical_id: &'static str,
        iform: &'static str,
    },
    UnknownIform,
    WrongProviderIdentity,
    WrongMode,
    WrongIformValue,
    WrongEncoding,
    WrongOperandShape,
}

include!("isanity_mov_memory_generated.rs");

/// Accept only an exact pinned XED form metadata/decode pair and byte witness.
/// Callers must supply `iform` and `decoded` from the same decode operation.
pub fn resolve_decoded(
    provenance: DecoderProvenance<'_>,
    bytes: &[u8],
    mode: InstructionMode,
    iform: &XedIformMetadata,
    decoded: &DecodedInstruction,
) -> Recognition {
    if provenance.provider != PROVIDER
        || provenance.version != PROVIDER_VERSION
        || iform.xed_sys_version != PROVIDER_VERSION
    {
        return Recognition::WrongProviderIdentity;
    }
    if !MOV_MEMORY_FORMS.iter().any(|form| form.iform == iform.name) {
        return Recognition::UnknownIform;
    }
    if !MOV_MEMORY_FORMS
        .iter()
        .any(|form| form.iform == iform.name && form.iform_value == iform.value)
    {
        return Recognition::WrongIformValue;
    }
    if !MOV_MEMORY_FORMS
        .iter()
        .any(|form| form.iform == iform.name && form.iform_value == iform.value && form.mode == mode)
    {
        return Recognition::WrongMode;
    }
    let Some(form) = MOV_MEMORY_FORMS.iter().find(|form| {
        form.iform == iform.name
            && form.iform_value == iform.value
            && form.mode == mode
            && form.witnesses.contains(&bytes)
    }) else {
        return Recognition::WrongEncoding;
    };
    if decoded.length as usize != bytes.len() {
        return Recognition::WrongEncoding;
    }
    if decoded.operands.len() != form.operands.len()
        || decoded.operands.iter().zip(form.operands).any(|(actual, expected)| {
            actual.visibility != OperandVisibility::Explicit
                || actual.width_bits != expected.width_bits
                || actual.access != expected.access
                || !matches!(
                    (expected.kind, actual.kind),
                    (OperandKindTag::Register, OperandKind::Register(_))
                        | (OperandKindTag::Memory, OperandKind::Memory(_))
                )
        })
    {
        return Recognition::WrongOperandShape;
    }
    Recognition::CandidateRecognized {
        canonical_id: form.canonical_id,
        iform: form.iform,
    }
}

pub fn forms() -> &'static [MovMemoryForm] {
    MOV_MEMORY_FORMS
}

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_arch_xed_ffi::{XedDecoder, XedMachineMode};
    use angryier_types::TargetProfileId;

    const PINNED_XED: DecoderProvenance<'static> = DecoderProvenance {
        provider: PROVIDER,
        version: PROVIDER_VERSION,
    };

    fn decoder() -> XedDecoder {
        XedDecoder::with_profile_id_and_mode(TargetProfileId(1), XedMachineMode::Intel64)
    }

    #[test]
    fn all_pinned_base_and_addressing_witnesses_resolve_as_candidate_identities()
    -> Result<(), angryier_arch_xed_ffi::XedAdapterError> {
        assert_eq!(forms().len(), 6);
        assert_eq!(
            forms()
                .iter()
                .map(|row| row.iform)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            2
        );
        assert_eq!(forms().iter().map(|row| row.witnesses.len()).sum::<usize>(), 108);
        for form in forms() {
            assert_eq!(form.mode, InstructionMode::Long64);
            for bytes in form.witnesses {
                let (decoded, iform) = decoder().decode_with_iform(0x4000, bytes)?;
                assert_eq!(iform.xed_sys_version, PROVIDER_VERSION);
                assert_eq!(iform.name, form.iform, "{bytes:02x?}");
                assert_eq!(iform.value, form.iform_value, "{bytes:02x?}");
                assert_eq!(decoded.length as usize, bytes.len());
                assert_eq!(
                    resolve_decoded(PINNED_XED, bytes, InstructionMode::Long64, &iform, &decoded),
                    Recognition::CandidateRecognized {
                        canonical_id: form.canonical_id,
                        iform: form.iform
                    },
                    "{bytes:02x?}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn provider_mode_iform_bytes_and_operand_near_misses_stay_unrecognized()
    -> Result<(), angryier_arch_xed_ffi::XedAdapterError> {
        for form in forms() {
            let bytes = form.witnesses[0];
            let (decoded, iform) = decoder().decode_with_iform(0x4000, bytes)?;
            assert_eq!(
                resolve_decoded(
                    DecoderProvenance {
                        provider: "other",
                        version: PROVIDER_VERSION
                    },
                    bytes,
                    InstructionMode::Long64,
                    &iform,
                    &decoded
                ),
                Recognition::WrongProviderIdentity
            );
            assert_eq!(
                resolve_decoded(
                    DecoderProvenance {
                        provider: PROVIDER,
                        version: "other"
                    },
                    bytes,
                    InstructionMode::Long64,
                    &iform,
                    &decoded
                ),
                Recognition::WrongProviderIdentity
            );
            let mut other_release = iform.clone();
            other_release.xed_sys_version = "other XED release";
            assert_eq!(
                resolve_decoded(PINNED_XED, bytes, InstructionMode::Long64, &other_release, &decoded),
                Recognition::WrongProviderIdentity
            );
            let mut wrong_value = iform.clone();
            wrong_value.value = wrong_value.value.wrapping_add(1);
            assert_eq!(
                resolve_decoded(PINNED_XED, bytes, InstructionMode::Long64, &wrong_value, &decoded),
                Recognition::WrongIformValue
            );
            assert_eq!(
                resolve_decoded(PINNED_XED, bytes, InstructionMode::Legacy32, &iform, &decoded),
                Recognition::WrongMode
            );
            let mut changed = bytes.to_vec();
            *changed.last_mut().expect("nonempty instruction") ^= 1;
            assert_eq!(
                resolve_decoded(PINNED_XED, &changed, InstructionMode::Long64, &iform, &decoded),
                Recognition::WrongEncoding
            );
            let mut wrong_length = decoded.clone();
            wrong_length.length = wrong_length.length.wrapping_add(1);
            assert_eq!(
                resolve_decoded(PINNED_XED, bytes, InstructionMode::Long64, &iform, &wrong_length),
                Recognition::WrongEncoding
            );
            let mut with_lookahead = bytes.to_vec();
            with_lookahead.push(0x90);
            assert_eq!(
                resolve_decoded(PINNED_XED, &with_lookahead, InstructionMode::Long64, &iform, &decoded),
                Recognition::WrongEncoding
            );
            let mut reversed = decoded.clone();
            reversed.operands.reverse();
            assert_eq!(
                resolve_decoded(PINNED_XED, bytes, InstructionMode::Long64, &iform, &reversed),
                Recognition::WrongOperandShape
            );
            let mut wrong_access = decoded.clone();
            wrong_access.operands[0].access = match wrong_access.operands[0].access {
                AccessKind::Read => AccessKind::Write,
                _ => AccessKind::Read,
            };
            assert_eq!(
                resolve_decoded(PINNED_XED, bytes, InstructionMode::Long64, &iform, &wrong_access),
                Recognition::WrongOperandShape
            );
            let mut wrong_width = decoded.clone();
            wrong_width.operands[0].width_bits = wrong_width.operands[0].width_bits.wrapping_add(1);
            assert_eq!(
                resolve_decoded(PINNED_XED, bytes, InstructionMode::Long64, &iform, &wrong_width),
                Recognition::WrongOperandShape
            );
            let mut wrong_name = iform.clone();
            wrong_name.name = "XED_IFORM_NOT_A_CANDIDATE".to_owned();
            assert_eq!(
                resolve_decoded(PINNED_XED, bytes, InstructionMode::Long64, &wrong_name, &decoded),
                Recognition::UnknownIform
            );
        }
        Ok(())
    }

    #[test]
    fn alternate_addressing_is_not_promoted_without_a_witness() -> Result<(), angryier_arch_xed_ffi::XedAdapterError> {
        let form = forms()
            .iter()
            .find(|form| form.iform == "XED_IFORM_MOV_GPRv_MEMv" && form.operands[1].width_bits == 64)
            .unwrap();
        let (decoded, iform) = decoder().decode_with_iform(0x4000, &[0x48, 0x8b, 0x0c, 0x08])?; // [RAX+RCX]
        assert_eq!(iform.name, form.iform);
        assert_eq!(
            resolve_decoded(
                PINNED_XED,
                &[0x48, 0x8b, 0x0c, 0x08],
                InstructionMode::Long64,
                &iform,
                &decoded
            ),
            Recognition::WrongEncoding
        );
        Ok(())
    }
}
