//! ISANITY's implicit-accumulator immediate candidates, mapped by exact
//! IFORM, execution mode, operand width, opcode, and immediate layout.
//!
//! These rows attach candidate identities only. They do not add or certify
//! instruction semantics or encoding fidelity.

use angryier_arch::{DecodedInstruction, OperandKind, OperandVisibility};

use crate::isanity_catalogue_forms::InstructionMode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccumulatorImmediateForm {
    pub canonical_id: &'static str,
    pub iform: &'static str,
    pub iform_value: u32,
    pub mode: InstructionMode,
    pub opcode_byte: u8,
    pub prefix_byte: Option<u8>,
    pub operand_width_bits: u16,
    pub immediate_width_bits: u16,
    pub immediate_width_bytes: u8,
    pub signed_immediate: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnsupportedAccumulatorIdentity {
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
    WrongLengthOrBytes,
    WrongOperandShape,
}

include!("isanity_accumulator_immediates_generated.rs");

/// Map a decoded accumulator-immediate instruction to its mode-qualified
/// ISANITY identity. The IFORM is supplied by the same pinned decoder that
/// produced `decoded`; bytes are checked against the canonical prefix/opcode
/// and immediate width so different width cells cannot alias.
pub fn resolve_decoded(
    bytes: &[u8],
    mode: InstructionMode,
    iform: &str,
    iform_value: u32,
    decoded: &DecodedInstruction,
) -> Recognition {
    let known = ACCUMULATOR_IMMEDIATE_FORMS.iter().any(|form| form.iform == iform)
        || ACCUMULATOR_IMMEDIATE_UNSUPPORTED.iter().any(|form| form.iform == iform);
    if !known {
        return Recognition::UnknownIform;
    }
    let candidates: Vec<_> = ACCUMULATOR_IMMEDIATE_FORMS
        .iter()
        .filter(|form| form.iform == iform && form.iform_value == iform_value)
        .collect();
    if candidates.is_empty() {
        return Recognition::WrongLengthOrBytes;
    }
    let mode_candidates: Vec<_> = candidates.iter().copied().filter(|form| form.mode == mode).collect();
    if mode_candidates.is_empty() {
        return Recognition::WrongMode;
    }
    let matching_patterns: Vec<_> = mode_candidates
        .into_iter()
        .filter(|form| {
            let prefix_len = usize::from(form.prefix_byte.is_some());
            let expected_len = prefix_len + 1 + usize::from(form.immediate_width_bytes);
            bytes.len() == expected_len
                && decoded.length as usize == bytes.len()
                && !form
                    .prefix_byte
                    .is_some_and(|prefix| bytes.first().copied() != Some(prefix))
                && bytes.get(prefix_len).copied() == Some(form.opcode_byte)
        })
        .collect();
    if matching_patterns.is_empty() {
        return Recognition::WrongLengthOrBytes;
    }
    let [form] = matching_patterns.as_slice() else {
        return Recognition::WrongLengthOrBytes;
    };
    let form = *form;
    let explicit: Vec<_> = decoded
        .operands
        .iter()
        .filter(|operand| operand.visibility == OperandVisibility::Explicit)
        .collect();
    if explicit.len() != 1 {
        return Recognition::WrongOperandShape;
    }
    let immediate = &explicit[0];
    let OperandKind::Immediate(immediate_value) = &immediate.kind else {
        return Recognition::WrongOperandShape;
    };
    if immediate.width_bits != form.immediate_width_bits || immediate_value.signed != form.signed_immediate {
        return Recognition::WrongOperandShape;
    }
    Recognition::Mapped {
        canonical_id: form.canonical_id,
        iform: form.iform,
    }
}

/// All candidate identities outside the runtime's three supported mode
/// selectors, with a machine-readable reason string. These remain available
/// for future adapters without pretending Angryier can select their mode.
pub fn unsupported_identities() -> &'static [UnsupportedAccumulatorIdentity] {
    ACCUMULATOR_IMMEDIATE_UNSUPPORTED
}

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_arch::ImmediateOperand;

    #[cfg(feature = "xed")]
    fn mode_tag(mode: InstructionMode) -> angryier_arch_xed_ffi::XedMachineMode {
        match mode {
            InstructionMode::Long64 => angryier_arch_xed_ffi::XedMachineMode::Intel64,
            InstructionMode::Legacy32 => angryier_arch_xed_ffi::XedMachineMode::Legacy32,
            InstructionMode::Legacy16 => angryier_arch_xed_ffi::XedMachineMode::Legacy16,
        }
    }

    fn bytes_for(form: &AccumulatorImmediateForm, value: u8) -> Vec<u8> {
        let mut bytes =
            Vec::with_capacity(usize::from(form.prefix_byte.is_some()) + 1 + usize::from(form.immediate_width_bytes));
        if let Some(prefix) = form.prefix_byte {
            bytes.push(prefix);
        }
        bytes.push(form.opcode_byte);
        bytes.extend(std::iter::repeat_n(value, usize::from(form.immediate_width_bytes)));
        bytes
    }

    #[test]
    fn generated_slices_partition_all_candidates_and_reason_code_unsupported_modes() {
        assert_eq!(
            ACCUMULATOR_IMMEDIATE_FORMS.len(),
            IMM8_MAPPED_COUNT + SIMMZ_MAPPED_COUNT
        );
        assert_eq!(IMM8_MAPPED_COUNT, 27);
        assert_eq!(SIMMZ_MAPPED_COUNT, 63);
        assert_eq!(unsupported_identities().len(), ACCUMULATOR_UNSUPPORTED_COUNT);
        assert_eq!(ACCUMULATOR_IMMEDIATE_FORMS.len() + unsupported_identities().len(), 198);
        assert!(
            unsupported_identities()
                .iter()
                .all(|form| form.reason.starts_with("unsupported-execution-mode:"))
        );
        let ids = ACCUMULATOR_IMMEDIATE_FORMS
            .iter()
            .map(|form| form.canonical_id)
            .chain(unsupported_identities().iter().map(|form| form.canonical_id))
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(ids.len(), 198);
        assert!(ACCUMULATOR_IMMEDIATE_FORMS.iter().all(|form| {
            !crate::isanity_catalogue_forms::GENERATED_CANONICAL_FORMS
                .iter()
                .any(|existing| existing.canonical_id == form.canonical_id)
        }));
    }

    #[test]
    fn synthetic_decode_shape_resolves_each_mode_and_rejects_prefix_width_or_shape_aliases() {
        for form in ACCUMULATOR_IMMEDIATE_FORMS {
            let bytes = bytes_for(form, 0);
            let decoded = DecodedInstruction {
                address: 0x4000,
                length: bytes.len() as u8,
                form_id: 0,
                features: Vec::new(),
                operands: vec![angryier_arch::Operand {
                    index: 0,
                    width_bits: form.immediate_width_bits,
                    access: angryier_arch::AccessKind::Read,
                    visibility: OperandVisibility::Explicit,
                    kind: OperandKind::Immediate(ImmediateOperand {
                        value: 0,
                        signed: form.signed_immediate,
                    }),
                }],
                modifiers: angryier_arch::InstructionModifiers::default(),
            };
            let mapped = Recognition::Mapped {
                canonical_id: form.canonical_id,
                iform: form.iform,
            };
            assert_eq!(
                resolve_decoded(&bytes, form.mode, form.iform, form.iform_value, &decoded),
                mapped,
                "{} {:?}",
                form.iform,
                form.mode
            );
            let mut wrong_opcode = bytes.clone();
            let opcode_at = usize::from(form.prefix_byte.is_some());
            wrong_opcode[opcode_at] ^= 1;
            assert_eq!(
                resolve_decoded(&wrong_opcode, form.mode, form.iform, form.iform_value, &decoded),
                Recognition::WrongLengthOrBytes
            );
            assert_eq!(
                resolve_decoded(&bytes, form.mode, form.iform, form.iform_value + 1, &decoded),
                Recognition::WrongLengthOrBytes
            );
            let mut wrong_operand = decoded.clone();
            wrong_operand.operands[0].width_bits ^= 8;
            assert_eq!(
                resolve_decoded(&bytes, form.mode, form.iform, form.iform_value, &wrong_operand),
                Recognition::WrongOperandShape
            );
        }
    }

    #[cfg(feature = "xed")]
    #[test]
    fn all_supported_mode_width_opcode_cells_round_trip_with_pinned_xed()
    -> Result<(), angryier_arch_xed_ffi::XedAdapterError> {
        for form in ACCUMULATOR_IMMEDIATE_FORMS {
            let decoder = angryier_arch_xed_ffi::XedDecoder::with_profile_id_and_mode(
                angryier_types::TargetProfileId(1),
                mode_tag(form.mode),
            );
            let values: Vec<u8> = if form.immediate_width_bytes == 1 {
                (0..=u8::MAX).collect()
            } else {
                vec![0x00, 0x01, 0x7f, 0x80, 0xff]
            };
            for fill in values {
                let bytes = bytes_for(form, fill);
                let (decoded, iform) = decoder.decode_with_iform(0x4000, &bytes)?;
                assert_eq!(iform.xed_sys_version, "xed-sys 0.6.0+xed-2024.05.20");
                assert_eq!(
                    iform.name, form.iform,
                    "{} {:?} bytes={bytes:02x?}",
                    form.iform, form.mode
                );
                assert_eq!(iform.value, form.iform_value);
                assert_eq!(decoded.length as usize, bytes.len());
                assert_eq!(
                    resolve_decoded(&bytes, form.mode, &iform.name, iform.value, &decoded),
                    Recognition::Mapped {
                        canonical_id: form.canonical_id,
                        iform: form.iform
                    },
                    "{} {:?} bytes={bytes:02x?} operands={:?}",
                    form.iform,
                    form.mode,
                    decoded.operands,
                );
            }
        }
        Ok(())
    }
}
