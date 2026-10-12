//! Exact long64 witnesses for the ISANITY fixed-opcode UIMM8 scout.
//!
//! This is candidate identity recognition only; it does not claim instruction
//! semantics, encoding legality, fidelity, or support for other modes.

use angryier_arch::{AccessKind, DecodedInstruction, OperandKind, OperandVisibility};

use crate::isanity_catalogue_forms::InstructionMode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixedImmediateOperandKind {
    Register,
    Immediate,
}

/// Provenance supplied by the decoder observation; both fields are required
/// and must match the pinned XED source used to generate this candidate slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecoderProvenance<'a> {
    pub provider: &'a str,
    pub version: &'a str,
}

pub const PINNED_PROVIDER: &str = "Intel XED";
pub const PINNED_PROVIDER_VERSION: &str = "xed-sys 0.6.0+xed-2024.05.20";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedImmediateOperand {
    pub kind: FixedImmediateOperandKind,
    pub width_bits: u16,
    pub access: AccessKind,
    pub visibility: OperandVisibility,
    pub parent_register_id: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedOpcodeImmediateForm {
    pub canonical_id: &'static str,
    pub iform: &'static str,
    pub iform_value: u32,
    pub mode: InstructionMode,
    pub opcode: u8,
    pub witnesses: &'static [&'static [u8]],
    pub operands: &'static [FixedImmediateOperand],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnsupportedFixedImmediateIdentity {
    pub canonical_id: &'static str,
    pub iform: &'static str,
    pub iform_value: u32,
    pub source_mode: &'static str,
    pub reason: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedImmediateLong64Exclusion {
    pub iform: &'static str,
    pub iform_value: u32,
    pub reason: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recognition {
    Mapped {
        canonical_id: &'static str,
        iform: &'static str,
    },
    ExcludedBySourceMode {
        iform: &'static str,
        reason: &'static str,
    },
    UnknownIform,
    WrongMode,
    WrongProviderIdentity,
    WrongEncoding,
    WrongOperandShape,
}

include!("isanity_fixed_opcode_immediates_generated.rs");

/// Resolve a pinned witness using an explicit machine mode and exact decoder metadata.
pub fn resolve_decoded(
    provenance: DecoderProvenance<'_>,
    bytes: &[u8],
    mode: InstructionMode,
    iform: &str,
    iform_value: u32,
    decoded: &DecodedInstruction,
) -> Recognition {
    if provenance.provider != PINNED_PROVIDER || provenance.version != PINNED_PROVIDER_VERSION {
        return Recognition::WrongProviderIdentity;
    }
    if let Some(exclusion) = FIXED_IMMEDIATE_LONG64_EXCLUSIONS
        .iter()
        .find(|row| row.iform == iform && row.iform_value == iform_value && mode == InstructionMode::Long64)
    {
        return Recognition::ExcludedBySourceMode {
            iform: exclusion.iform,
            reason: exclusion.reason,
        };
    }
    if !FIXED_IMMEDIATE_FORMS.iter().any(|form| form.iform == iform)
        && !FIXED_IMMEDIATE_UNSUPPORTED.iter().any(|form| form.iform == iform)
        && !FIXED_IMMEDIATE_LONG64_EXCLUSIONS.iter().any(|row| row.iform == iform)
    {
        return Recognition::UnknownIform;
    }
    if !FIXED_IMMEDIATE_FORMS
        .iter()
        .any(|form| form.iform == iform && form.iform_value == iform_value)
        && !FIXED_IMMEDIATE_UNSUPPORTED
            .iter()
            .any(|form| form.iform == iform && form.iform_value == iform_value)
        && !FIXED_IMMEDIATE_LONG64_EXCLUSIONS
            .iter()
            .any(|row| row.iform == iform && row.iform_value == iform_value)
    {
        return Recognition::WrongEncoding;
    }
    let Some(form) = FIXED_IMMEDIATE_FORMS
        .iter()
        .find(|form| form.iform == iform && form.iform_value == iform_value && form.mode == mode)
    else {
        return Recognition::WrongMode;
    };
    if !form.witnesses.contains(&bytes)
        || bytes.len() != 2
        || bytes.first().copied() != Some(form.opcode)
        || decoded.length as usize != bytes.len()
    {
        return Recognition::WrongEncoding;
    }
    if decoded.operands.len() != form.operands.len()
        || decoded.operands.iter().zip(form.operands).any(|(operand, expected)| {
            operand.visibility != expected.visibility
                || operand.width_bits != expected.width_bits
                || operand.access != expected.access
                || match (&operand.kind, expected.kind) {
                    (OperandKind::Register(view), FixedImmediateOperandKind::Register) => {
                        Some(view.parent.0) != expected.parent_register_id
                    }
                    (OperandKind::Immediate(value), FixedImmediateOperandKind::Immediate) => {
                        value.signed
                            || value.value > u8::MAX as u64
                            || bytes.get(1).copied().map(u64::from) != Some(value.value)
                    }
                    _ => true,
                }
        })
    {
        return Recognition::WrongOperandShape;
    }
    Recognition::Mapped {
        canonical_id: form.canonical_id,
        iform: form.iform,
    }
}

/// Return all 36 mode-qualified rows outside this adapter's long64 scope.
pub fn unsupported_identities() -> &'static [UnsupportedFixedImmediateIdentity] {
    FIXED_IMMEDIATE_UNSUPPORTED
}

/// AAD/AAM are explicitly excluded because their source patterns are `not64`.
pub fn long64_exclusions() -> &'static [FixedImmediateLong64Exclusion] {
    FIXED_IMMEDIATE_LONG64_EXCLUSIONS
}

#[cfg(test)]
mod tests {
    use super::*;

    const XED_PROVENANCE: DecoderProvenance<'static> = DecoderProvenance {
        provider: PINNED_PROVIDER,
        version: PINNED_PROVIDER_VERSION,
    };

    #[cfg(feature = "xed")]
    #[test]
    fn all_long64_immediate_values_decode_to_their_exact_identity() -> Result<(), angryier_arch_xed_ffi::XedAdapterError>
    {
        use angryier_arch_xed_ffi::{XedDecoder, XedMachineMode};
        use angryier_types::TargetProfileId;

        assert_eq!(FIXED_IMMEDIATE_FORMS.len(), FIXED_IMMEDIATE_MAPPED_COUNT);
        assert_eq!(unsupported_identities().len(), FIXED_IMMEDIATE_UNSUPPORTED_COUNT);
        assert_eq!(long64_exclusions().len(), FIXED_IMMEDIATE_LONG64_EXCLUSION_COUNT);
        assert_eq!(FIXED_IMMEDIATE_FORMS.len() + unsupported_identities().len(), 40);
        let decoder = XedDecoder::with_profile_id_and_mode(TargetProfileId(1), XedMachineMode::Intel64);
        for form in FIXED_IMMEDIATE_FORMS {
            assert_eq!(form.witnesses.len(), 256, "{}", form.iform);
            for witness in form.witnesses {
                let (decoded, iform) = decoder.decode_with_iform(0x4000, witness)?;
                assert_eq!(iform.name, form.iform, "{witness:02x?}");
                assert_eq!(iform.value, form.iform_value, "{witness:02x?}");
                assert_eq!(
                    resolve_decoded(
                        XED_PROVENANCE,
                        witness,
                        InstructionMode::Long64,
                        &iform.name,
                        iform.value,
                        &decoded
                    ),
                    Recognition::Mapped {
                        canonical_id: form.canonical_id,
                        iform: form.iform
                    },
                    "{witness:02x?}; decoded operands: {:#?}; expected: {:#?}",
                    decoded.operands,
                    form.operands
                );
            }
        }
        Ok(())
    }

    #[cfg(feature = "xed")]
    #[test]
    fn rejects_near_misses_and_wrong_mode_or_operand_metadata() -> Result<(), angryier_arch_xed_ffi::XedAdapterError> {
        use angryier_arch_xed_ffi::{XedDecoder, XedMachineMode};
        use angryier_types::TargetProfileId;

        let decoder = XedDecoder::with_profile_id_and_mode(TargetProfileId(1), XedMachineMode::Intel64);
        for form in FIXED_IMMEDIATE_FORMS {
            let witness = form.witnesses[0];
            let (decoded, iform) = decoder.decode_with_iform(0x4000, witness)?;
            let mut changed = witness.to_vec();
            changed[0] ^= 1;
            assert_eq!(
                resolve_decoded(XED_PROVENANCE, &changed, form.mode, &iform.name, iform.value, &decoded),
                Recognition::WrongEncoding
            );
            assert_eq!(
                resolve_decoded(
                    XED_PROVENANCE,
                    &witness[..1],
                    form.mode,
                    &iform.name,
                    iform.value,
                    &decoded
                ),
                Recognition::WrongEncoding,
                "a one-byte truncated stream must not resolve: {witness:02x?}"
            );
            assert_eq!(
                resolve_decoded(
                    XED_PROVENANCE,
                    witness,
                    InstructionMode::Legacy32,
                    &iform.name,
                    iform.value,
                    &decoded
                ),
                Recognition::WrongMode
            );
            let mut wrong_operand = decoded.clone();
            wrong_operand.operands[0].width_bits ^= 8;
            assert_eq!(
                resolve_decoded(
                    XED_PROVENANCE,
                    witness,
                    form.mode,
                    &iform.name,
                    iform.value,
                    &wrong_operand
                ),
                Recognition::WrongOperandShape
            );
            let mut empty_operands = decoded.clone();
            empty_operands.operands.clear();
            assert_eq!(
                resolve_decoded(
                    XED_PROVENANCE,
                    witness,
                    form.mode,
                    &iform.name,
                    iform.value,
                    &empty_operands
                ),
                Recognition::WrongOperandShape
            );
            let mut extra_operand = decoded.clone();
            extra_operand.operands.push(decoded.operands[0].clone());
            assert_eq!(
                resolve_decoded(
                    XED_PROVENANCE,
                    witness,
                    form.mode,
                    &iform.name,
                    iform.value,
                    &extra_operand
                ),
                Recognition::WrongOperandShape
            );
            let changed_immediate = [witness[0], witness[1] ^ 1];
            assert_eq!(
                resolve_decoded(
                    XED_PROVENANCE,
                    &changed_immediate,
                    form.mode,
                    &iform.name,
                    iform.value,
                    &decoded
                ),
                Recognition::WrongOperandShape
            );
            let mut truncated_immediate = decoded.clone();
            let immediate = truncated_immediate
                .operands
                .iter_mut()
                .find_map(|operand| match &mut operand.kind {
                    OperandKind::Immediate(value) => Some(value),
                    _ => None,
                })
                .expect("fixed-immediate witness exposes an immediate operand");
            immediate.value = u64::from(witness[1]) + 0x100;
            assert_eq!(
                resolve_decoded(
                    XED_PROVENANCE,
                    witness,
                    form.mode,
                    &iform.name,
                    iform.value,
                    &truncated_immediate
                ),
                Recognition::WrongOperandShape,
                "immediate must not be truncated to its low byte: {witness:02x?}"
            );
        }
        let (decoded, _) = decoder.decode_with_iform(0x4000, FIXED_IMMEDIATE_FORMS[0].witnesses[0])?;
        for exclusion in long64_exclusions() {
            assert_eq!(
                resolve_decoded(
                    XED_PROVENANCE,
                    &[0xd5, 0x00],
                    InstructionMode::Long64,
                    exclusion.iform,
                    exclusion.iform_value,
                    &decoded
                ),
                Recognition::ExcludedBySourceMode {
                    iform: exclusion.iform,
                    reason: exclusion.reason
                }
            );
        }
        let witness = FIXED_IMMEDIATE_FORMS[0].witnesses[0];
        let (decoded, iform) = decoder.decode_with_iform(0x4000, witness)?;
        let form = FIXED_IMMEDIATE_FORMS[0];
        for provenance in [
            DecoderProvenance {
                provider: "other decoder",
                version: PINNED_PROVIDER_VERSION,
            },
            DecoderProvenance {
                provider: PINNED_PROVIDER,
                version: "xed-sys 0.6.0+xed-other",
            },
        ] {
            assert_eq!(
                resolve_decoded(provenance, witness, form.mode, &iform.name, iform.value, &decoded),
                Recognition::WrongProviderIdentity
            );
        }
        Ok(())
    }

    #[test]
    fn unsupported_modes_are_retained_and_aad_aam_are_excluded_from_long64() {
        assert_eq!(unsupported_identities().len(), 36);
        assert!(
            unsupported_identities().iter().all(|identity| {
                identity.reason.starts_with("unsupported-mode:") && identity.source_mode != "long64"
            })
        );
        assert_eq!(long64_exclusions().len(), 2);
        assert_eq!(
            long64_exclusions()
                .iter()
                .map(|row| row.iform)
                .collect::<std::collections::HashSet<_>>(),
            ["XED_IFORM_AAD_IMMb", "XED_IFORM_AAM_IMMb"].into_iter().collect()
        );
        assert!(
            long64_exclusions()
                .iter()
                .all(|row| { row.reason == "source-prefix-constraint:not-long64; no long64 candidate identity" })
        );
        let ids: std::collections::HashSet<_> = FIXED_IMMEDIATE_FORMS
            .iter()
            .map(|form| form.canonical_id)
            .chain(unsupported_identities().iter().map(|form| form.canonical_id))
            .collect();
        assert_eq!(ids.len(), 40);
        assert!(
            FIXED_IMMEDIATE_FORMS
                .iter()
                .all(|form| !matches!(form.iform, "XED_IFORM_AAD_IMMb" | "XED_IFORM_AAM_IMMb"))
        );
    }
}
