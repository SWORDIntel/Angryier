//! Exact-witness candidate identity handoff for the ISANITY zero-operand slice.
//!
//! This adapter covers only the pinned long64 SAHF and LAHF byte witnesses.
//! Both have zero explicit operands but two suppressed XED operands. The
//! `lahf` predicate is preserved as candidate metadata; a successful XED decode
//! does not establish that the runtime CPU supports or enables that feature.
//! No instruction semantics or encoding-space completeness are implied.

use angryier_arch::{AccessKind, DecodedInstruction, OperandKind, OperandVisibility, RegisterWriteBehavior};
use angryier_arch_xed_ffi::XedIformMetadata;

use crate::isanity_catalogue_forms::InstructionMode;

pub const ZERO_OPERAND_PROVIDER: &str = "Intel XED";
pub const ZERO_OPERAND_PROVIDER_VERSION: &str = "xed-sys 0.6.0+xed-2024.05.20";
pub const ZERO_OPERAND_EVIDENCE_SHA256: &str = "034f0ecd88afa166797598dc09a2123845ccf2e24332c00f6cbdf8015bc5cb28";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecoderProvenance<'a> {
    pub provider: &'a str,
    pub version: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ZeroOperandCandidate {
    pub canonical_id: &'static str,
    pub iform: &'static str,
    pub iform_value: u32,
    pub witness: &'static [u8],
    /// Exact source-map predicate; this is metadata, not an execution check.
    pub feature_predicate: &'static str,
    pub suppressed_operands: [SuppressedOperand; 2],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SuppressedOperand {
    pub index: u8,
    pub width_bits: u16,
    pub access: AccessKind,
    pub parent_register_id: u32,
    pub bit_offset: u16,
    pub view_width_bits: u16,
    pub write_behavior: RegisterWriteBehavior,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recognition {
    CandidateRecognized {
        canonical_id: &'static str,
        iform: &'static str,
        feature_predicate: &'static str,
    },
    UnknownIform,
    WrongIformValue,
    WrongProviderIdentity,
    WrongMode,
    WrongEncoding,
    WrongOperandShape,
}

include!("isanity_zero_operand_generated.rs");

/// Resolve only an exact, version-scoped XED decode of one pinned witness.
/// `iform` and `decoded` must originate from the same `decode_with_iform` call.
pub fn resolve_decoded(
    provenance: DecoderProvenance<'_>,
    bytes: &[u8],
    mode: InstructionMode,
    iform: &XedIformMetadata,
    decoded: &DecodedInstruction,
) -> Recognition {
    if provenance.provider != ZERO_OPERAND_PROVIDER
        || provenance.version != ZERO_OPERAND_PROVIDER_VERSION
        || iform.xed_sys_version != ZERO_OPERAND_PROVIDER_VERSION
    {
        return Recognition::WrongProviderIdentity;
    }

    let Some(candidate) = ZERO_OPERAND_CANDIDATES
        .iter()
        .find(|candidate| candidate.iform == iform.name)
    else {
        return Recognition::UnknownIform;
    };
    if candidate.iform_value != iform.value {
        return Recognition::WrongIformValue;
    }
    if mode != InstructionMode::Long64 {
        return Recognition::WrongMode;
    }
    if bytes != candidate.witness || decoded.length as usize != candidate.witness.len() {
        return Recognition::WrongEncoding;
    }
    if !has_exact_suppressed_operands(decoded, candidate.suppressed_operands) {
        return Recognition::WrongOperandShape;
    }

    Recognition::CandidateRecognized {
        canonical_id: candidate.canonical_id,
        iform: candidate.iform,
        feature_predicate: candidate.feature_predicate,
    }
}

fn has_exact_suppressed_operands(decoded: &DecodedInstruction, expected: [SuppressedOperand; 2]) -> bool {
    if decoded.operands.len() != expected.len() {
        return false;
    }
    decoded.operands.iter().zip(expected).all(|(actual, expected)| {
        actual.index == expected.index
            && actual.width_bits == expected.width_bits
            && actual.access == expected.access
            && actual.visibility == OperandVisibility::Suppressed
            && matches!(
                actual.kind,
                OperandKind::Register(view)
                    if view.parent.0 == expected.parent_register_id
                        && view.bit_offset == expected.bit_offset
                        && view.width_bits == expected.view_width_bits
                        && view.write_behavior == expected.write_behavior
            )
    })
}

pub fn candidates() -> &'static [ZeroOperandCandidate] {
    ZERO_OPERAND_CANDIDATES
}

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_arch_xed_ffi::{XedDecoder, XedMachineMode};
    use angryier_types::TargetProfileId;

    const PINNED_XED: DecoderProvenance<'static> = DecoderProvenance {
        provider: ZERO_OPERAND_PROVIDER,
        version: ZERO_OPERAND_PROVIDER_VERSION,
    };

    fn decoder() -> XedDecoder {
        XedDecoder::with_profile_id_and_mode(TargetProfileId(1), XedMachineMode::Intel64)
    }

    #[test]
    fn exact_pinned_long64_witnesses_map_as_candidates_only() -> Result<(), angryier_arch_xed_ffi::XedAdapterError> {
        assert_eq!(candidates().len(), 2);
        for candidate in candidates() {
            let (decoded, iform) = decoder().decode_with_iform(0x4000, candidate.witness)?;
            assert_eq!(iform.xed_sys_version, ZERO_OPERAND_PROVIDER_VERSION);
            assert_eq!(iform.name, candidate.iform);
            assert_eq!(iform.value, candidate.iform_value);
            assert_eq!(decoded.length as usize, candidate.witness.len());
            assert_eq!(decoded.operands.len(), 2);
            assert!(
                decoded
                    .operands
                    .iter()
                    .all(|operand| operand.visibility == OperandVisibility::Suppressed)
            );
            assert_eq!(candidate.feature_predicate, "lahf");
            assert_eq!(
                resolve_decoded(PINNED_XED, candidate.witness, InstructionMode::Long64, &iform, &decoded),
                Recognition::CandidateRecognized {
                    canonical_id: candidate.canonical_id,
                    iform: candidate.iform,
                    feature_predicate: "lahf",
                },
                "{} {:?}",
                candidate.iform,
                decoded.operands,
            );
        }
        Ok(())
    }

    #[test]
    fn provider_mode_iform_and_byte_mutations_do_not_map() -> Result<(), angryier_arch_xed_ffi::XedAdapterError> {
        for candidate in candidates() {
            let (decoded, iform) = decoder().decode_with_iform(0x4000, candidate.witness)?;
            assert_eq!(
                resolve_decoded(
                    DecoderProvenance {
                        provider: "other",
                        version: ZERO_OPERAND_PROVIDER_VERSION
                    },
                    candidate.witness,
                    InstructionMode::Long64,
                    &iform,
                    &decoded,
                ),
                Recognition::WrongProviderIdentity
            );
            assert_eq!(
                resolve_decoded(
                    DecoderProvenance {
                        provider: ZERO_OPERAND_PROVIDER,
                        version: "other"
                    },
                    candidate.witness,
                    InstructionMode::Long64,
                    &iform,
                    &decoded,
                ),
                Recognition::WrongProviderIdentity
            );
            let mut wrong_version = iform.clone();
            wrong_version.xed_sys_version = "another XED release";
            assert_eq!(
                resolve_decoded(
                    PINNED_XED,
                    candidate.witness,
                    InstructionMode::Long64,
                    &wrong_version,
                    &decoded
                ),
                Recognition::WrongProviderIdentity
            );
            let mut wrong_value = iform.clone();
            wrong_value.value = wrong_value.value.wrapping_add(1);
            assert_eq!(
                resolve_decoded(
                    PINNED_XED,
                    candidate.witness,
                    InstructionMode::Long64,
                    &wrong_value,
                    &decoded
                ),
                Recognition::WrongIformValue
            );
            let mut wrong_name = iform.clone();
            wrong_name.name = "XED_IFORM_NOT_A_CANDIDATE".to_owned();
            assert_eq!(
                resolve_decoded(
                    PINNED_XED,
                    candidate.witness,
                    InstructionMode::Long64,
                    &wrong_name,
                    &decoded
                ),
                Recognition::UnknownIform
            );
            assert_eq!(
                resolve_decoded(
                    PINNED_XED,
                    candidate.witness,
                    InstructionMode::Legacy32,
                    &iform,
                    &decoded
                ),
                Recognition::WrongMode
            );
            let changed_bytes = [candidate.witness[0] ^ 1];
            assert_eq!(
                resolve_decoded(PINNED_XED, &changed_bytes, InstructionMode::Long64, &iform, &decoded),
                Recognition::WrongEncoding
            );
            let prefixed = [0x66, candidate.witness[0]];
            if let Ok((prefixed_decoded, prefixed_iform)) = decoder().decode_with_iform(0x4000, &prefixed) {
                assert_eq!(
                    resolve_decoded(
                        PINNED_XED,
                        &prefixed,
                        InstructionMode::Long64,
                        &prefixed_iform,
                        &prefixed_decoded,
                    ),
                    Recognition::WrongEncoding
                );
            }
            let mut wrong_length = decoded.clone();
            wrong_length.length += 1;
            assert_eq!(
                resolve_decoded(
                    PINNED_XED,
                    candidate.witness,
                    InstructionMode::Long64,
                    &iform,
                    &wrong_length
                ),
                Recognition::WrongEncoding
            );
        }
        Ok(())
    }

    #[test]
    fn suppressed_operand_shape_is_exact_and_ordered() -> Result<(), angryier_arch_xed_ffi::XedAdapterError> {
        for candidate in candidates() {
            let (decoded, iform) = decoder().decode_with_iform(0x4000, candidate.witness)?;
            let mut explicit = decoded.clone();
            explicit.operands[0].visibility = OperandVisibility::Explicit;
            assert_eq!(
                resolve_decoded(
                    PINNED_XED,
                    candidate.witness,
                    InstructionMode::Long64,
                    &iform,
                    &explicit
                ),
                Recognition::WrongOperandShape
            );
            let mut reordered = decoded.clone();
            reordered.operands.swap(0, 1);
            assert_eq!(
                resolve_decoded(
                    PINNED_XED,
                    candidate.witness,
                    InstructionMode::Long64,
                    &iform,
                    &reordered
                ),
                Recognition::WrongOperandShape
            );
            let mut changed_access = decoded.clone();
            changed_access.operands[0].access = AccessKind::ReadWrite;
            assert_eq!(
                resolve_decoded(
                    PINNED_XED,
                    candidate.witness,
                    InstructionMode::Long64,
                    &iform,
                    &changed_access
                ),
                Recognition::WrongOperandShape
            );
            let mut missing_operand = decoded.clone();
            missing_operand.operands.pop();
            assert_eq!(
                resolve_decoded(
                    PINNED_XED,
                    candidate.witness,
                    InstructionMode::Long64,
                    &iform,
                    &missing_operand
                ),
                Recognition::WrongOperandShape
            );
        }
        Ok(())
    }
}
