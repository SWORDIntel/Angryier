//! Exact source/XED witness recognition for selected direct-ModRM UIMM16/32 forms.
//!
//! This adapter attaches candidate identities only. It does not infer semantics,
//! exhaustive encoding legality, or profile/feature availability. Compatibility
//! modes are preserved as candidates but remain unmapped because Angryier's XED
//! mode API cannot distinguish them from the corresponding legacy modes.

use angryier_arch::{AccessKind, DecodedInstruction, OperandKind, OperandVisibility};

use crate::isanity_catalogue_forms::InstructionMode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectExecutionMode {
    Long64,
    Legacy32,
    Legacy16,
    Compat32,
    Compat16,
}

impl DirectExecutionMode {
    fn source_name(self) -> &'static str {
        match self {
            Self::Long64 => "long64",
            Self::Legacy32 => "legacy32",
            Self::Legacy16 => "legacy16",
            Self::Compat32 => "compat32",
            Self::Compat16 => "compat16",
        }
    }

    fn mapped_mode(self) -> Option<InstructionMode> {
        match self {
            Self::Long64 => Some(InstructionMode::Long64),
            Self::Legacy32 => Some(InstructionMode::Legacy32),
            Self::Legacy16 => Some(InstructionMode::Legacy16),
            Self::Compat32 | Self::Compat16 => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectOperandKind {
    Register,
    Immediate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectAccess {
    Read,
    Write,
    ReadWrite,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModRmField {
    Reg,
    Rm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UimmDirectOperand {
    pub kind: DirectOperandKind,
    pub width_bits: Option<u16>,
    pub access: DirectAccess,
    pub visibility: OperandVisibility,
    /// Present only when the source identity binds this register to ModRM.REG/RM.
    pub selector: Option<ModRmField>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UimmDirectWitness {
    pub bytes: &'static [u8],
    pub reg: u8,
    pub rm: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UimmDirectModrmForm {
    pub canonical_id: &'static str,
    pub iform: &'static str,
    pub iform_value: u32,
    pub mode: InstructionMode,
    pub immediate_width_bits: u16,
    pub operands: &'static [UimmDirectOperand],
    pub witnesses: &'static [UimmDirectWitness],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnsupportedUimmDirectModrmIdentity {
    pub canonical_id: &'static str,
    pub iform: &'static str,
    pub iform_value: u32,
    pub source_mode: &'static str,
    pub reason: &'static str,
    pub witnesses: &'static [&'static [u8]],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecoderProvenance<'a> {
    pub provider: &'a str,
    pub version: &'a str,
    pub profile: &'a str,
}

pub const PINNED_PROVIDER: &str = "Intel XED";
pub const PINNED_PROVIDER_VERSION: &str = "xed-sys 0.6.0+xed-2024.05.20";
pub const PINNED_PROVIDER_PROFILE: &str = "XED_CHIP_INVALID";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recognition {
    Mapped {
        canonical_id: &'static str,
        iform: &'static str,
    },
    Unsupported {
        canonical_id: &'static str,
        iform: &'static str,
        source_mode: &'static str,
        reason: &'static str,
    },
    UnknownIform,
    WrongProviderIdentity,
    WrongMode,
    WrongEncoding,
    WrongOperandShape,
}

include!("isanity_uimm16_32_direct_modrm_generated.rs");

/// Resolve only a complete source/XED witness with exact provider, mode, IFORM,
/// immediate and ordered normalized operand/ModRM selector metadata.
pub fn resolve_decoded(
    provenance: DecoderProvenance<'_>,
    bytes: &[u8],
    mode: DirectExecutionMode,
    iform: &str,
    iform_value: u32,
    decoded: &DecodedInstruction,
) -> Recognition {
    if provenance.provider != PINNED_PROVIDER
        || provenance.version != PINNED_PROVIDER_VERSION
        || provenance.profile != PINNED_PROVIDER_PROFILE
    {
        return Recognition::WrongProviderIdentity;
    }
    let known = UIMM16_32_DIRECT_MODRM_FORMS.iter().any(|row| row.iform == iform)
        || UIMM16_32_DIRECT_MODRM_UNSUPPORTED.iter().any(|row| row.iform == iform);
    if !known {
        return Recognition::UnknownIform;
    }
    let iform_value_exists = UIMM16_32_DIRECT_MODRM_FORMS
        .iter()
        .any(|row| row.iform == iform && row.iform_value == iform_value)
        || UIMM16_32_DIRECT_MODRM_UNSUPPORTED
            .iter()
            .any(|row| row.iform == iform && row.iform_value == iform_value);
    if !iform_value_exists {
        return Recognition::WrongEncoding;
    }
    let Some(form) = UIMM16_32_DIRECT_MODRM_FORMS
        .iter()
        .find(|row| row.iform == iform && row.iform_value == iform_value && mode.mapped_mode() == Some(row.mode))
    else {
        if let Some(unsupported) = UIMM16_32_DIRECT_MODRM_UNSUPPORTED.iter().find(|row| {
            row.iform == iform
                && row.iform_value == iform_value
                && row.source_mode == mode.source_name()
                && row.witnesses.contains(&bytes)
        }) {
            return Recognition::Unsupported {
                canonical_id: unsupported.canonical_id,
                iform: unsupported.iform,
                source_mode: unsupported.source_mode,
                reason: unsupported.reason,
            };
        }
        return Recognition::WrongMode;
    };
    let Some(witness) = form.witnesses.iter().find(|witness| witness.bytes == bytes) else {
        return Recognition::WrongEncoding;
    };
    if decoded.length as usize != bytes.len() {
        return Recognition::WrongEncoding;
    }
    // XED's suppressed RFLAGS projection is provider-only, not part of the
    // sidecar identity. Its observed count is pinned per IFORM below.
    let suppressed: Vec<_> = decoded
        .operands
        .iter()
        .filter(|operand| operand.visibility == OperandVisibility::Suppressed)
        .collect();
    if expected_suppressed_provider_operands(iform) != Some(suppressed.len())
        || suppressed.iter().any(|operand| {
            !matches!(
                operand.kind,
                OperandKind::Register(view)
                    if view.parent.0 == angryier_arch_intel64::register_id::RFLAGS.0
                        && view.width_bits == 64
                        && operand.width_bits == 64
                        && operand.access == AccessKind::Write
            )
        })
    {
        return Recognition::WrongOperandShape;
    }
    let source_operands: Vec<_> = decoded
        .operands
        .iter()
        .filter(|operand| operand.visibility != OperandVisibility::Suppressed)
        .collect();
    if source_operands.len() != form.operands.len() {
        return Recognition::WrongOperandShape;
    }
    let immediate_bytes = (form.immediate_width_bits / 8) as usize;
    let Some(immediate_raw) = bytes.get(bytes.len().saturating_sub(immediate_bytes)..) else {
        return Recognition::WrongEncoding;
    };
    if immediate_raw.len() != immediate_bytes {
        return Recognition::WrongEncoding;
    }
    let immediate_value = immediate_raw
        .iter()
        .enumerate()
        .fold(0u64, |value, (shift, byte)| value | (u64::from(*byte) << (shift * 8)));

    for (decoded_operand, expected) in source_operands.into_iter().zip(form.operands) {
        let access_matches = matches!(
            (decoded_operand.access, expected.access),
            (AccessKind::Read, DirectAccess::Read)
                | (AccessKind::Write, DirectAccess::Write)
                | (AccessKind::ReadWrite, DirectAccess::ReadWrite)
        );
        if decoded_operand.visibility != expected.visibility
            || !access_matches
            || expected
                .width_bits
                .is_some_and(|width| decoded_operand.width_bits != width)
        {
            return Recognition::WrongOperandShape;
        }
        match (&decoded_operand.kind, expected.kind) {
            (OperandKind::Register(view), DirectOperandKind::Register) => {
                if let Some(selector) = expected.selector {
                    let selected_index = match selector {
                        ModRmField::Reg => witness.reg,
                        ModRmField::Rm => witness.rm,
                    };
                    if view.parent.0 != u32::from(selected_index) {
                        return Recognition::WrongOperandShape;
                    }
                }
            }
            (OperandKind::Immediate(value), DirectOperandKind::Immediate) => {
                if value.signed
                    || value.value != immediate_value
                    || decoded_operand.width_bits != form.immediate_width_bits
                {
                    return Recognition::WrongOperandShape;
                }
            }
            _ => return Recognition::WrongOperandShape,
        }
    }
    Recognition::Mapped {
        canonical_id: form.canonical_id,
        iform: form.iform,
    }
}

pub fn unsupported_identities() -> &'static [UnsupportedUimmDirectModrmIdentity] {
    UIMM16_32_DIRECT_MODRM_UNSUPPORTED
}

pub fn profile_residue_counts() -> &'static [(&'static str, usize)] {
    DIRECT_MODRM_PROFILE_RESIDUE_COUNTS
}

pub fn source_exclusion_counts() -> &'static [(&'static str, usize)] {
    DIRECT_MODRM_SOURCE_EXCLUSION_COUNTS
}

fn expected_suppressed_provider_operands(iform: &str) -> Option<usize> {
    Some(match iform {
        "XED_IFORM_BEXTR_XOP_GPR32d_GPR32d_IMMd" | "XED_IFORM_BEXTR_XOP_GPRyy_GPRyy_IMMd" => 1,
        "XED_IFORM_LWPINS_GPRyy_GPR32d_IMMd" => 1,
        "XED_IFORM_LWPVAL_GPRyy_GPR32d_IMMd"
        | "XED_IFORM_URDMSR_GPR64u64_IMM32"
        | "XED_IFORM_UWRMSR_IMM32_GPR64u64" => 0,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const XED: DecoderProvenance<'static> = DecoderProvenance {
        provider: PINNED_PROVIDER,
        version: PINNED_PROVIDER_VERSION,
        profile: PINNED_PROVIDER_PROFILE,
    };

    #[cfg(feature = "xed")]
    #[test]
    fn every_explicitly_representable_source_witness_decodes_to_exact_identity()
    -> Result<(), angryier_arch_xed_ffi::XedAdapterError> {
        use angryier_arch_xed_ffi::{XedDecoder, XedMachineMode};
        use angryier_types::TargetProfileId;

        assert_eq!(UIMM16_32_DIRECT_MODRM_FORMS.len(), DIRECT_MODRM_MAPPED_COUNT);
        assert_eq!(unsupported_identities().len(), DIRECT_MODRM_UNSUPPORTED_COUNT);
        assert_eq!(
            UIMM16_32_DIRECT_MODRM_FORMS.len() + unsupported_identities().len(),
            DIRECT_MODRM_CANDIDATE_COUNT
        );
        assert_eq!(
            UIMM16_32_DIRECT_MODRM_FORMS
                .iter()
                .map(|f| f.witnesses.len())
                .sum::<usize>()
                + unsupported_identities()
                    .iter()
                    .map(|f| f.witnesses.len())
                    .sum::<usize>(),
            DIRECT_MODRM_WITNESS_COUNT
        );
        assert_eq!(
            profile_residue_counts().iter().map(|(_, n)| n).sum::<usize>(),
            DIRECT_MODRM_PROFILE_RESIDUE_COUNT
        );
        assert_eq!(
            source_exclusion_counts().iter().map(|(_, n)| n).sum::<usize>(),
            DIRECT_MODRM_SOURCE_EXCLUSION_COUNT
        );
        assert_eq!(
            DIRECT_MODRM_SOURCE_EXCLUSION_COUNT + 6,
            DIRECT_MODRM_SOURCE_AUDIT_TOTAL_COUNT
        );
        for form in UIMM16_32_DIRECT_MODRM_FORMS {
            let mode = match form.mode {
                InstructionMode::Long64 => XedMachineMode::Intel64,
                InstructionMode::Legacy32 => XedMachineMode::Legacy32,
                InstructionMode::Legacy16 => XedMachineMode::Legacy16,
            };
            let decoder = XedDecoder::with_profile_id_and_mode(TargetProfileId(1), mode);
            for witness in form.witnesses {
                let (decoded, iform) = decoder.decode_with_iform(0x4000, witness.bytes)?;
                assert_eq!(iform.xed_sys_version, PINNED_PROVIDER_VERSION);
                assert_eq!(iform.name, form.iform, "{:02x?}", witness.bytes);
                assert_eq!(iform.value, form.iform_value, "{:02x?}", witness.bytes);
                assert_eq!(decoded.length as usize, witness.bytes.len());
                assert_eq!(
                    decoded
                        .operands
                        .iter()
                        .filter(|operand| operand.visibility == OperandVisibility::Suppressed)
                        .count(),
                    expected_suppressed_provider_operands(form.iform).unwrap(),
                    "provider-only suppressed operands for {}",
                    form.iform
                );
                assert_eq!(
                    resolve_decoded(
                        XED,
                        witness.bytes,
                        DirectExecutionMode::from(form.mode),
                        &iform.name,
                        iform.value,
                        &decoded
                    ),
                    Recognition::Mapped {
                        canonical_id: form.canonical_id,
                        iform: form.iform
                    },
                    "{:02x?}; decoded={:#?}",
                    witness.bytes,
                    decoded.operands
                );
            }
        }
        Ok(())
    }

    #[test]
    fn exact_bytes_and_metadata_are_required_and_compat_modes_are_preserved() {
        assert_eq!(
            unsupported_identities()
                .iter()
                .map(|row| row.witnesses.len())
                .sum::<usize>(),
            176
        );
        assert!(
            unsupported_identities()
                .iter()
                .filter(|row| row.reason.starts_with("unsupported-mode:"))
                .map(|row| row.witnesses.len())
                .sum::<usize>()
                == 160
        );
        assert_eq!(
            resolve_decoded(
                DecoderProvenance {
                    provider: "other",
                    ..XED
                },
                &[],
                DirectExecutionMode::Long64,
                "XED_IFORM_NOT_PRESENT",
                0,
                &empty_decoded()
            ),
            Recognition::WrongProviderIdentity
        );
        assert_eq!(
            resolve_decoded(
                DecoderProvenance {
                    profile: "XED_CHIP_INVALID_OTHER",
                    ..XED
                },
                &[],
                DirectExecutionMode::Long64,
                "XED_IFORM_NOT_PRESENT",
                0,
                &empty_decoded()
            ),
            Recognition::WrongProviderIdentity
        );
        assert_eq!(
            resolve_decoded(
                XED,
                &[],
                DirectExecutionMode::Long64,
                "XED_IFORM_NOT_PRESENT",
                0,
                &empty_decoded()
            ),
            Recognition::UnknownIform
        );
        for candidate in unsupported_identities() {
            let mode = match candidate.source_mode {
                "compat16" => DirectExecutionMode::Compat16,
                "compat32" => DirectExecutionMode::Compat32,
                "long64" => DirectExecutionMode::Long64,
                _ => unreachable!(),
            };
            for witness in candidate.witnesses {
                let resolution = resolve_decoded(
                    XED,
                    witness,
                    mode,
                    candidate.iform,
                    candidate.iform_value,
                    &empty_decoded(),
                );
                assert!(
                    matches!(
                        resolution,
                    Recognition::Unsupported { canonical_id, source_mode, .. }
                            if canonical_id == candidate.canonical_id && source_mode == candidate.source_mode
                    ),
                    "{} / {} / {:02x?}: {resolution:?}",
                    candidate.iform,
                    candidate.source_mode,
                    witness
                );
            }
        }
        assert_eq!(
            unsupported_identities()
                .iter()
                .filter(|row| row.reason.starts_with("unobservable-operand:"))
                .map(|row| row.witnesses.len())
                .sum::<usize>(),
            16
        );
    }

    #[cfg(feature = "xed")]
    #[test]
    fn rejects_truncated_bytes_and_near_miss_iform_metadata() -> Result<(), angryier_arch_xed_ffi::XedAdapterError> {
        use angryier_arch_xed_ffi::{XedDecoder, XedMachineMode};
        use angryier_types::TargetProfileId;
        let form = &UIMM16_32_DIRECT_MODRM_FORMS[0];
        let witness = &form.witnesses[0];
        let mode = match form.mode {
            InstructionMode::Long64 => XedMachineMode::Intel64,
            InstructionMode::Legacy32 => XedMachineMode::Legacy32,
            InstructionMode::Legacy16 => XedMachineMode::Legacy16,
        };
        let decoder = XedDecoder::with_profile_id_and_mode(TargetProfileId(1), mode);
        let (decoded, iform) = decoder.decode_with_iform(0x4000, witness.bytes)?;
        assert_eq!(
            resolve_decoded(
                XED,
                &witness.bytes[..witness.bytes.len() - 1],
                DirectExecutionMode::from(form.mode),
                &iform.name,
                iform.value,
                &decoded
            ),
            Recognition::WrongEncoding
        );
        let suppressed_index = decoded
            .operands
            .iter()
            .position(|operand| operand.visibility == OperandVisibility::Suppressed)
            .expect("the pinned IFORM has one provider-suppressed RFLAGS operand");
        let resolve_mutation = |mutated: &DecodedInstruction| {
            resolve_decoded(
                XED,
                witness.bytes,
                DirectExecutionMode::from(form.mode),
                &iform.name,
                iform.value,
                mutated,
            )
        };
        let mut missing = decoded.clone();
        missing.operands.remove(suppressed_index);
        assert_eq!(resolve_mutation(&missing), Recognition::WrongOperandShape);

        let mut duplicate = decoded.clone();
        duplicate.operands.push(duplicate.operands[suppressed_index].clone());
        assert_eq!(resolve_mutation(&duplicate), Recognition::WrongOperandShape);

        let mut wrong_width = decoded.clone();
        wrong_width.operands[suppressed_index].width_bits -= 1;
        assert_eq!(resolve_mutation(&wrong_width), Recognition::WrongOperandShape);

        let mut wrong_access = decoded.clone();
        wrong_access.operands[suppressed_index].access = AccessKind::Read;
        assert_eq!(resolve_mutation(&wrong_access), Recognition::WrongOperandShape);

        let mut wrong_visibility = decoded.clone();
        wrong_visibility.operands[suppressed_index].visibility = OperandVisibility::Implicit;
        assert_eq!(resolve_mutation(&wrong_visibility), Recognition::WrongOperandShape);

        let mut wrong_parent = decoded.clone();
        if let OperandKind::Register(view) = &mut wrong_parent.operands[suppressed_index].kind {
            view.parent = angryier_arch::RegisterId(0);
        }
        assert_eq!(resolve_mutation(&wrong_parent), Recognition::WrongOperandShape);

        let mut wrong_modrm_register = decoded.clone();
        if let OperandKind::Register(view) = &mut wrong_modrm_register.operands[0].kind {
            view.parent = angryier_arch::RegisterId(view.parent.0 ^ 1);
        }
        assert_eq!(resolve_mutation(&wrong_modrm_register), Recognition::WrongOperandShape);
        assert_eq!(
            resolve_decoded(
                XED,
                witness.bytes,
                DirectExecutionMode::from(form.mode),
                &iform.name,
                iform.value.wrapping_add(1),
                &decoded
            ),
            Recognition::WrongEncoding
        );
        assert_eq!(
            resolve_decoded(
                XED,
                witness.bytes,
                DirectExecutionMode::from(form.mode),
                &iform.name,
                iform.value,
                &decoded
            ),
            Recognition::Mapped {
                canonical_id: form.canonical_id,
                iform: form.iform
            }
        );
        Ok(())
    }

    fn empty_decoded() -> DecodedInstruction {
        DecodedInstruction {
            address: 0,
            length: 0,
            form_id: 0,
            features: Vec::new(),
            operands: Vec::new(),
            modifiers: Default::default(),
        }
    }
}

impl From<InstructionMode> for DirectExecutionMode {
    fn from(mode: InstructionMode) -> Self {
        match mode {
            InstructionMode::Long64 => Self::Long64,
            InstructionMode::Legacy32 => Self::Legacy32,
            InstructionMode::Legacy16 => Self::Legacy16,
        }
    }
}
