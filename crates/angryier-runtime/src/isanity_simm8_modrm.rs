//! Source-pinned candidate identities for legacy x86 opcode 0x82 SIMM8 forms.
//!
//! The table maps candidate identities only. It does not implement instruction
//! semantics or certify encoding fidelity. Although Angryier has a legacy16
//! selector, its XED normalization rejects 16-bit memory-address metadata, so
//! only legacy32 tuples are currently selectable. Other source modes are kept
//! as reason-coded unsupported records.

use angryier_arch::{AccessKind, DecodedInstruction, OperandKind, OperandVisibility};

use crate::isanity_catalogue_forms::InstructionMode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Simm8ModrmForm {
    pub canonical_id: &'static str,
    pub iform: &'static str,
    pub iform_value: u32,
    pub mode: InstructionMode,
    pub lock_prefix: bool,
    pub memory_access: AccessKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnsupportedSimm8ModrmIdentity {
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

include!("isanity_simm8_modrm_generated.rs");

/// Resolve only the canonical source-observed envelope: optional LOCK prefix,
/// opcode 82, memory ModRM extension, and a final signed imm8. The IFORM must
/// come from the same pinned XED decode as `decoded`.
pub fn resolve_decoded(
    bytes: &[u8],
    mode: InstructionMode,
    iform: &str,
    iform_value: u32,
    decoded: &DecodedInstruction,
) -> Recognition {
    if !SIMM8_MODRM_FORMS.iter().any(|form| form.iform == iform)
        && !SIMM8_MODRM_UNSUPPORTED.iter().any(|form| form.iform == iform)
    {
        return Recognition::UnknownIform;
    }
    if !SIMM8_MODRM_FORMS
        .iter()
        .any(|form| form.iform == iform && form.iform_value == iform_value)
        && !SIMM8_MODRM_UNSUPPORTED
            .iter()
            .any(|form| form.iform == iform && form.iform_value == iform_value)
    {
        return Recognition::WrongEncoding;
    }
    let Some(form) = SIMM8_MODRM_FORMS
        .iter()
        .find(|form| form.iform == iform && form.iform_value == iform_value && form.mode == mode)
    else {
        return Recognition::WrongMode;
    };

    let prefix_len = usize::from(form.lock_prefix);
    let modrm_index = prefix_len + 1;
    if decoded.length as usize != bytes.len()
        || bytes.len() < modrm_index + 2
        || (form.lock_prefix && bytes.first() != Some(&0xf0))
        || (!form.lock_prefix && bytes.first() == Some(&0xf0))
        || bytes.get(prefix_len) != Some(&0x82)
    {
        return Recognition::WrongEncoding;
    }
    let modrm = bytes[modrm_index];
    if modrm >> 6 == 3 || ((modrm >> 3) & 7) != form.iform_reg_extension() {
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
        || memory.access != form.memory_access
        || !matches!(memory.kind, OperandKind::Memory(_))
        || immediate.width_bits != 8
        || immediate.access != AccessKind::Read
        || !matches!(
            immediate.kind,
            OperandKind::Immediate(value) if value.signed
        )
    {
        return Recognition::WrongOperandShape;
    }
    Recognition::Mapped {
        canonical_id: form.canonical_id,
        iform: form.iform,
    }
}

impl Simm8ModrmForm {
    fn iform_reg_extension(&self) -> u8 {
        SIMM8_MODRM_EXTENSION_BY_ID
            .iter()
            .find_map(|(canonical_id, extension)| (*canonical_id == self.canonical_id).then_some(*extension))
            .expect("generated identity must have a ModRM extension")
    }
}

/// Candidate identities outside the runtime's legacy16/legacy32 mode
/// selectors, retained with a machine-readable reason.
pub fn unsupported_identities() -> &'static [UnsupportedSimm8ModrmIdentity] {
    SIMM8_MODRM_UNSUPPORTED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "xed")]
    fn mode_tag(mode: InstructionMode) -> angryier_arch_xed_ffi::XedMachineMode {
        match mode {
            InstructionMode::Legacy16 => angryier_arch_xed_ffi::XedMachineMode::Legacy16,
            InstructionMode::Legacy32 => angryier_arch_xed_ffi::XedMachineMode::Legacy32,
            InstructionMode::Long64 => angryier_arch_xed_ffi::XedMachineMode::Intel64,
        }
    }

    #[cfg(feature = "xed")]
    fn witness(form: &Simm8ModrmForm, immediate: u8) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(4 + usize::from(form.lock_prefix));
        if form.lock_prefix {
            bytes.push(0xf0);
        }
        bytes.extend_from_slice(&[0x82, form.iform_extension_byte(), immediate]);
        bytes
    }

    #[cfg(feature = "xed")]
    fn memory_form(form: &Simm8ModrmForm, mod_bits: u8, rm: u8) -> Vec<u8> {
        let mut bytes = Vec::new();
        if form.lock_prefix {
            bytes.push(0xf0);
        }
        bytes.push(0x82);
        bytes.push((mod_bits << 6) | form.iform_extension_byte() | rm);
        if rm == 4 {
            bytes.push(0x20); // no index, base EAX
        }
        if mod_bits == 0 && rm == 5 {
            bytes.extend_from_slice(&[0, 0, 0, 0]);
        } else if mod_bits == 1 {
            bytes.push(0);
        } else if mod_bits == 2 {
            bytes.extend_from_slice(&[0, 0, 0, 0]);
        }
        bytes.push(0x80);
        bytes
    }

    #[test]
    fn generated_records_partition_mappable_and_reason_coded_modes() {
        assert_eq!(SIMM8_MODRM_FORMS.len(), SIMM8_MODRM_MAPPED_COUNT);
        assert_eq!(unsupported_identities().len(), SIMM8_MODRM_UNSUPPORTED_COUNT);
        assert_eq!(SIMM8_MODRM_FORMS.len() + unsupported_identities().len(), 66);
        assert!(
            unsupported_identities()
                .iter()
                .all(|form| form.reason.starts_with("unsupported-mode:"))
        );
        assert_eq!(
            SIMM8_MODRM_FORMS
                .iter()
                .map(|form| {
                    let mode = match form.mode {
                        InstructionMode::Legacy16 => "legacy16",
                        InstructionMode::Legacy32 => "legacy32",
                        InstructionMode::Long64 => "long64",
                    };
                    (form.iform, mode)
                })
                .collect::<std::collections::HashSet<_>>()
                .len(),
            11
        );
        let ids: std::collections::HashSet<_> = SIMM8_MODRM_FORMS
            .iter()
            .map(|form| form.canonical_id)
            .chain(unsupported_identities().iter().map(|form| form.canonical_id))
            .collect();
        assert_eq!(ids.len(), 66);
    }

    #[cfg(feature = "xed")]
    #[test]
    fn xed_selects_each_supported_iform_for_boundary_signed_immediates()
    -> Result<(), angryier_arch_xed_ffi::XedAdapterError> {
        for form in SIMM8_MODRM_FORMS {
            let decoder = angryier_arch_xed_ffi::XedDecoder::with_profile_id_and_mode(
                angryier_types::TargetProfileId(1),
                mode_tag(form.mode),
            );
            for immediate in 0..=u8::MAX {
                let bytes = witness(form, immediate);
                let (decoded, iform) = decoder.decode_with_iform(0x4000, &bytes)?;
                assert_eq!(iform.name, form.iform, "{:?} {bytes:02x?}", form.mode);
                assert_eq!(iform.value, form.iform_value);
                assert_eq!(
                    resolve_decoded(&bytes, form.mode, &iform.name, iform.value, &decoded),
                    Recognition::Mapped {
                        canonical_id: form.canonical_id,
                        iform: form.iform
                    },
                    "{} {:?} {bytes:02x?} {:?}",
                    form.iform,
                    form.mode,
                    decoded.operands
                );
            }
            // The source pattern permits every memory ModRM selector with
            // mod=00/01/10. Confirm the real mode32 backend selects the same
            // IFORM throughout that 24-cell memory addressing space.
            for mod_bits in 0..=2 {
                for rm in 0..=7 {
                    let bytes = memory_form(form, mod_bits, rm);
                    let (decoded, iform) = decoder.decode_with_iform(0x4000, &bytes)?;
                    assert_eq!(iform.name, form.iform, "{:?} {bytes:02x?}", form.mode);
                    assert_eq!(iform.value, form.iform_value);
                    assert!(
                        matches!(
                            resolve_decoded(&bytes, form.mode, &iform.name, iform.value, &decoded),
                            Recognition::Mapped { canonical_id, .. } if canonical_id == form.canonical_id
                        ),
                        "{} {:?} {bytes:02x?} {:?}",
                        form.iform,
                        form.mode,
                        decoded.operands
                    );
                }
            }
        }
        Ok(())
    }

    #[cfg(feature = "xed")]
    #[test]
    fn xed_backend_rejects_wrong_opcode_lock_state_extension_and_register_form()
    -> Result<(), angryier_arch_xed_ffi::XedAdapterError> {
        for form in SIMM8_MODRM_FORMS {
            let decoder = angryier_arch_xed_ffi::XedDecoder::with_profile_id_and_mode(
                angryier_types::TargetProfileId(1),
                mode_tag(form.mode),
            );
            let valid = witness(form, 0xff);
            let (decoded, iform) = decoder.decode_with_iform(0x4000, &valid)?;
            let mut wrong_opcode = valid.clone();
            wrong_opcode[usize::from(form.lock_prefix)] = 0x80;
            assert_eq!(
                resolve_decoded(&wrong_opcode, form.mode, &iform.name, iform.value, &decoded),
                Recognition::WrongEncoding
            );
            assert_eq!(
                resolve_decoded(&valid, form.mode, &iform.name, iform.value + 1, &decoded),
                Recognition::WrongEncoding
            );
            assert_eq!(
                resolve_decoded(&valid, InstructionMode::Legacy16, &iform.name, iform.value, &decoded),
                Recognition::WrongMode
            );
            let mut wrong_ext = valid.clone();
            wrong_ext[usize::from(form.lock_prefix) + 1] ^= 0x08;
            assert_eq!(
                resolve_decoded(&wrong_ext, form.mode, &iform.name, iform.value, &decoded),
                Recognition::WrongEncoding
            );
            let mut wrong_lock = valid.clone();
            if form.lock_prefix {
                wrong_lock.remove(0);
            } else {
                wrong_lock.insert(0, 0xf0);
            }
            assert_eq!(
                resolve_decoded(&wrong_lock, form.mode, &iform.name, iform.value, &decoded),
                Recognition::WrongEncoding
            );
            let mut register_form = valid.clone();
            register_form[usize::from(form.lock_prefix) + 1] |= 0xc0;
            assert_eq!(
                resolve_decoded(&register_form, form.mode, &iform.name, iform.value, &decoded),
                Recognition::WrongEncoding
            );
            let mut unsigned_immediate = decoded.clone();
            let immediate_index = unsigned_immediate
                .operands
                .iter()
                .enumerate()
                .filter(|(_, operand)| operand.visibility == OperandVisibility::Explicit)
                .nth(1)
                .map(|(index, _)| index)
                .expect("XED decode should contain an explicit immediate");
            if let OperandKind::Immediate(mut value) = unsigned_immediate.operands[immediate_index].kind {
                value.signed = false;
                unsigned_immediate.operands[immediate_index].kind = OperandKind::Immediate(value);
            } else {
                panic!("XED decode did not produce the expected explicit immediate");
            }
            assert_eq!(
                resolve_decoded(&valid, form.mode, &iform.name, iform.value, &unsigned_immediate),
                Recognition::WrongOperandShape
            );
        }
        Ok(())
    }

    #[cfg(feature = "xed")]
    impl Simm8ModrmForm {
        fn iform_extension_byte(&self) -> u8 {
            SIMM8_MODRM_EXTENSION_BY_ID
                .iter()
                .find_map(|(canonical_id, extension)| (*canonical_id == self.canonical_id).then_some(*extension << 3))
                .expect("generated identity must have a ModRM extension")
        }
    }
}
