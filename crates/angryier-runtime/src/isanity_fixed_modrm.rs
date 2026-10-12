//! Additive identity handoff for ISANITY's fixed-ModRM, zero-operand slice.
//! This identifies exact encodings only; it does not add legacy forms or semantics.

use angryier_arch::{DecodedInstruction, OperandVisibility};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeneratedFixedModrmForm {
    pub iform: &'static str,
    pub iform_value: u32,
    pub opcode_map: &'static str,
    pub opcode: u8,
    pub modrm_reg: u8,
    pub modrm_rm: u8,
    pub canonical_id: &'static str,
    pub canonical_sha256: &'static str,
    pub example_bytes: &'static str,
    pub explicit_operands: usize,
}

include!("isanity_fixed_modrm_generated.rs");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixedModrmHandoff {
    Mapped {
        canonical_id: &'static str,
        canonical_sha256: &'static str,
        iform: &'static str,
    },
    UnknownIform,
    WrongExecutionMode,
    WrongOperandShape,
    WrongEncoding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstructionMode {
    Long64,
    Legacy32,
    Legacy16,
}

pub fn catalogue_sha256() -> &'static str {
    FIXED_MODRM_CATALOGUE_SHA256
}

pub fn pinned_xed_source_sha256() -> &'static str {
    FIXED_MODRM_XED_SOURCE_SHA256
}

/// Resolve exact complete instruction bytes, the IFORM from those bytes, the
/// mode, and the number of explicit operands from that same decode. Prefixes,
/// even where a XED pattern is less restrictive, are not accepted by this
/// first byte-exact handoff slice.
pub fn resolve(bytes: &[u8], mode: InstructionMode, iform: &str, explicit_operand_count: usize) -> FixedModrmHandoff {
    let Some(form) = GENERATED_FIXED_MODRM_FORMS.iter().find(|form| form.iform == iform) else {
        return FixedModrmHandoff::UnknownIform;
    };
    if mode != InstructionMode::Long64 {
        return FixedModrmHandoff::WrongExecutionMode;
    }
    if explicit_operand_count != form.explicit_operands {
        return FixedModrmHandoff::WrongOperandShape;
    }
    let (opcode_start, modrm_index) = match form.opcode_map {
        "primary" => (0, 1),
        "0f" => (1, 2),
        _ => return FixedModrmHandoff::WrongEncoding,
    };
    if bytes.len() != modrm_index + 1 || (opcode_start == 1 && bytes[0] != 0x0f) || bytes[opcode_start] != form.opcode {
        return FixedModrmHandoff::WrongEncoding;
    }
    let modrm = bytes[modrm_index];
    if modrm >> 6 != 3 || (modrm >> 3) & 7 != form.modrm_reg || modrm & 7 != form.modrm_rm {
        return FixedModrmHandoff::WrongEncoding;
    }
    FixedModrmHandoff::Mapped {
        canonical_id: form.canonical_id,
        canonical_sha256: form.canonical_sha256,
        iform: form.iform,
    }
}

/// Resolve from Angryier's normalized decode, counting explicit operands only.
/// The supplied IFORM and bytes must come from the same pinned XED decode.
pub fn resolve_decoded(
    bytes: &[u8],
    mode: InstructionMode,
    iform: &str,
    decoded: &DecodedInstruction,
) -> FixedModrmHandoff {
    let explicit_operand_count = decoded
        .operands
        .iter()
        .filter(|operand| operand.visibility == OperandVisibility::Explicit)
        .count();
    resolve(bytes, mode, iform, explicit_operand_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_generated_identity_maps_only_its_exact_pinned_bytes() {
        assert_eq!(GENERATED_FIXED_MODRM_FORMS.len(), 18);
        let mut ids = Vec::new();
        for form in GENERATED_FIXED_MODRM_FORMS {
            let bytes = hex_bytes(form.example_bytes);
            assert_eq!(
                resolve(&bytes, InstructionMode::Long64, form.iform, 0),
                FixedModrmHandoff::Mapped {
                    canonical_id: form.canonical_id,
                    canonical_sha256: form.canonical_sha256,
                    iform: form.iform,
                },
                "{}",
                form.iform
            );
            ids.push(form.canonical_id);
        }
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 18);
    }

    #[test]
    fn rejects_each_forms_opcode_modrm_near_misses_and_mismatched_iforms() {
        for form in GENERATED_FIXED_MODRM_FORMS {
            let exact = hex_bytes(form.example_bytes);
            let mut mutations = Vec::new();
            for index in 0..exact.len() {
                let mut candidate = exact.clone();
                candidate[index] ^= 1;
                mutations.push(candidate);
            }
            mutations.push(exact[..exact.len() - 1].to_vec());
            let mut trailing = exact.clone();
            trailing.push(0x90);
            mutations.push(trailing);
            let mut prefixed = vec![0x66];
            prefixed.extend_from_slice(&exact);
            mutations.push(prefixed);
            for candidate in mutations {
                assert_eq!(
                    resolve(&candidate, InstructionMode::Long64, form.iform, 0),
                    FixedModrmHandoff::WrongEncoding,
                    "{} accepted near miss {:02x?}",
                    form.iform,
                    candidate
                );
            }
            let other_iform = GENERATED_FIXED_MODRM_FORMS
                .iter()
                .find(|candidate| candidate.iform != form.iform)
                .expect("the slice has multiple entries")
                .iform;
            assert_eq!(
                resolve(&exact, InstructionMode::Long64, other_iform, 0),
                FixedModrmHandoff::WrongEncoding,
                "{} bytes must not map as {other_iform}",
                form.iform
            );
        }
    }

    #[test]
    fn mode_and_explicit_operand_metadata_are_required() {
        let form = &GENERATED_FIXED_MODRM_FORMS[0];
        let bytes = hex_bytes(form.example_bytes);
        assert_eq!(
            resolve(&bytes, InstructionMode::Legacy32, form.iform, 0),
            FixedModrmHandoff::WrongExecutionMode
        );
        assert_eq!(
            resolve(&bytes, InstructionMode::Legacy16, form.iform, 0),
            FixedModrmHandoff::WrongExecutionMode
        );
        assert_eq!(
            resolve(&bytes, InstructionMode::Long64, form.iform, 1),
            FixedModrmHandoff::WrongOperandShape
        );
        assert_eq!(
            resolve(&bytes, InstructionMode::Long64, "XED_IFORM_NOT_IN_SLICE", 0),
            FixedModrmHandoff::UnknownIform
        );
    }

    #[cfg(feature = "xed")]
    #[test]
    fn pinned_xed_decodes_every_identity_with_zero_explicit_operands()
    -> Result<(), angryier_arch_xed_ffi::XedAdapterError> {
        use angryier_arch::OperandVisibility;
        let decoder = angryier_arch_xed_ffi::XedDecoder::new();
        for form in GENERATED_FIXED_MODRM_FORMS {
            let bytes = hex_bytes(form.example_bytes);
            let (decoded, iform) = decoder.decode_with_iform(0x4000, &bytes)?;
            assert_eq!(iform.xed_sys_version, "xed-sys 0.6.0+xed-2024.05.20");
            assert_eq!(iform.name, form.iform);
            assert_eq!(iform.value, form.iform_value);
            assert_eq!(decoded.length as usize, bytes.len());
            assert_eq!(
                decoded
                    .operands
                    .iter()
                    .filter(|operand| operand.visibility == OperandVisibility::Explicit)
                    .count(),
                0,
                "{} explicit operands",
                form.iform
            );
            assert_eq!(
                resolve_decoded(&bytes, InstructionMode::Long64, &iform.name, &decoded),
                FixedModrmHandoff::Mapped {
                    canonical_id: form.canonical_id,
                    canonical_sha256: form.canonical_sha256,
                    iform: form.iform,
                }
            );
        }
        Ok(())
    }

    fn hex_bytes(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).expect("ASCII hex"), 16).expect("valid hex"))
            .collect()
    }
}
