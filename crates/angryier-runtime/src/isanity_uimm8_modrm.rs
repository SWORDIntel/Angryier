//! Exact source-witness identities for non-long64 x86 opcode 0x82 UIMM8 forms.
//!
//! This maps canonical candidate identities only; it does not implement
//! instruction semantics or certify encoding fidelity. Runtime recognition is
//! deliberately restricted to the exact pinned profile witness bytes.

use angryier_arch::{AccessKind, DecodedInstruction, OperandKind, OperandVisibility};

use crate::isanity_catalogue_forms::InstructionMode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Uimm8ModrmForm {
    pub canonical_id: &'static str,
    pub iform: &'static str,
    pub iform_value: u32,
    pub mode: InstructionMode,
    pub witness: &'static [u8],
    pub lock_prefix: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnsupportedUimm8ModrmIdentity {
    pub canonical_id: &'static str,
    pub iform: &'static str,
    pub iform_value: u32,
    pub source_mode: &'static str,
    pub reason: &'static str,
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

include!("isanity_uimm8_modrm_generated.rs");

/// Resolve an exact pinned witness and matching decoder IFORM.
pub fn resolve_decoded(
    bytes: &[u8],
    mode: InstructionMode,
    iform: &str,
    iform_value: u32,
    decoded: &DecodedInstruction,
) -> Recognition {
    if !UIMM8_MODRM_FORMS.iter().any(|form| form.iform == iform)
        && !UIMM8_MODRM_UNSUPPORTED.iter().any(|form| form.iform == iform)
    {
        return Recognition::UnknownIform;
    }
    if !UIMM8_MODRM_FORMS
        .iter()
        .any(|form| form.iform == iform && form.iform_value == iform_value)
        && !UIMM8_MODRM_UNSUPPORTED
            .iter()
            .any(|form| form.iform == iform && form.iform_value == iform_value)
    {
        return Recognition::WrongEncoding;
    }
    let Some(form) = UIMM8_MODRM_FORMS
        .iter()
        .find(|form| form.iform == iform && form.iform_value == iform_value && form.mode == mode)
    else {
        return Recognition::WrongMode;
    };
    if bytes != form.witness
        || decoded.length as usize != form.witness.len()
        || bytes.get(usize::from(form.lock_prefix)) != Some(&0x82)
        || (form.lock_prefix && bytes.first() != Some(&0xf0))
        || (!form.lock_prefix && bytes.first() == Some(&0xf0))
    {
        return Recognition::WrongEncoding;
    }
    let explicit: Vec<_> = decoded
        .operands
        .iter()
        .filter(|operand| operand.visibility == OperandVisibility::Explicit)
        .collect();
    if explicit.len() != 2 {
        return Recognition::WrongOperandShape;
    }
    let memory = explicit[0];
    let immediate = explicit[1];
    if memory.width_bits != 8
        || memory.access != AccessKind::ReadWrite
        || !matches!(memory.kind, OperandKind::Memory(_))
        || immediate.width_bits != 8
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

/// Return identities not selectable by Angryier's current decoder mode API.
pub fn unsupported_identities() -> &'static [UnsupportedUimm8ModrmIdentity] {
    UIMM8_MODRM_UNSUPPORTED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "xed")]
    #[test]
    fn pinned_legacy32_witnesses_select_exact_candidate_identities()
    -> Result<(), angryier_arch_xed_ffi::XedAdapterError> {
        assert_eq!(UIMM8_MODRM_FORMS.len(), UIMM8_MODRM_MAPPED_COUNT);
        assert_eq!(unsupported_identities().len(), UIMM8_MODRM_UNSUPPORTED_COUNT);
        assert_eq!(UIMM8_MODRM_FORMS.len() + unsupported_identities().len(), 24);
        let decoder = angryier_arch_xed_ffi::XedDecoder::with_profile_id_and_mode(
            angryier_types::TargetProfileId(1),
            angryier_arch_xed_ffi::XedMachineMode::Legacy32,
        );
        for form in UIMM8_MODRM_FORMS {
            let (decoded, iform) = decoder.decode_with_iform(0x4000, form.witness)?;
            assert_eq!(iform.name, form.iform, "{:02x?}", form.witness);
            assert_eq!(iform.value, form.iform_value);
            assert_eq!(
                resolve_decoded(form.witness, form.mode, &iform.name, iform.value, &decoded),
                Recognition::Mapped {
                    canonical_id: form.canonical_id,
                    iform: form.iform
                }
            );
        }
        Ok(())
    }

    #[cfg(feature = "xed")]
    #[test]
    fn rejects_near_miss_bytes_mode_iform_and_operand_shape() -> Result<(), angryier_arch_xed_ffi::XedAdapterError> {
        let decoder = angryier_arch_xed_ffi::XedDecoder::with_profile_id_and_mode(
            angryier_types::TargetProfileId(1),
            angryier_arch_xed_ffi::XedMachineMode::Legacy32,
        );
        for form in UIMM8_MODRM_FORMS {
            let (decoded, iform) = decoder.decode_with_iform(0x4000, form.witness)?;
            let mut changed = form.witness.to_vec();
            *changed.last_mut().unwrap() ^= 1;
            assert_eq!(
                resolve_decoded(&changed, form.mode, &iform.name, iform.value, &decoded),
                Recognition::WrongEncoding
            );
            assert_eq!(
                resolve_decoded(
                    form.witness,
                    InstructionMode::Legacy16,
                    &iform.name,
                    iform.value,
                    &decoded
                ),
                Recognition::WrongMode
            );
            assert_eq!(
                resolve_decoded(
                    form.witness,
                    form.mode,
                    &iform.name,
                    iform.value.wrapping_add(1),
                    &decoded
                ),
                Recognition::WrongEncoding
            );
            let mut signed = decoded.clone();
            let index = signed
                .operands
                .iter()
                .enumerate()
                .filter(|(_, operand)| operand.visibility == OperandVisibility::Explicit)
                .nth(1)
                .map(|(index, _)| index)
                .unwrap();
            if let OperandKind::Immediate(mut value) = signed.operands[index].kind {
                value.signed = true;
                signed.operands[index].kind = OperandKind::Immediate(value);
            } else {
                panic!("expected explicit immediate");
            }
            assert_eq!(
                resolve_decoded(form.witness, form.mode, &iform.name, iform.value, &signed),
                Recognition::WrongOperandShape
            );
        }
        Ok(())
    }

    #[test]
    fn unsupported_modes_are_reason_coded_and_candidate_only() {
        assert!(
            unsupported_identities()
                .iter()
                .all(|identity| { identity.reason.starts_with("unsupported-mode:") })
        );
        assert_eq!(
            UIMM8_MODRM_FORMS
                .iter()
                .map(|form| form.iform)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            4
        );
        let ids: std::collections::HashSet<_> = UIMM8_MODRM_FORMS
            .iter()
            .map(|form| form.canonical_id)
            .chain(unsupported_identities().iter().map(|form| form.canonical_id))
            .collect();
        assert_eq!(ids.len(), 24);
    }
}
