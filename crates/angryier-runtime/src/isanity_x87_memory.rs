//! Long64 exact-witness identities for the reviewed ISANITY x87 memory slice.
//!
//! Recognition is candidate identity provenance only. It does not establish
//! encoding legality, execution semantics, or fidelity.

use angryier_arch::{DecodedInstruction, OperandKind, OperandVisibility};

use crate::isanity_catalogue_forms::InstructionMode;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct X87MemoryForm {
    pub canonical_id: &'static str,
    pub iform: &'static str,
    pub iform_value: u32,
    pub mode: InstructionMode,
    pub witness: &'static [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnsupportedX87MemoryIdentity {
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

include!("isanity_x87_memory_generated.rs");

/// Resolve only a pinned long64 witness with matching XED IFORM and mode.
pub fn resolve_decoded(
    bytes: &[u8],
    mode: InstructionMode,
    iform: &str,
    iform_value: u32,
    decoded: &DecodedInstruction,
) -> Recognition {
    if !X87_MEMORY_FORMS.iter().any(|form| form.iform == iform)
        && !X87_MEMORY_UNSUPPORTED.iter().any(|form| form.iform == iform)
    {
        return Recognition::UnknownIform;
    }
    if !X87_MEMORY_FORMS
        .iter()
        .any(|form| form.iform == iform && form.iform_value == iform_value)
        && !X87_MEMORY_UNSUPPORTED
            .iter()
            .any(|form| form.iform == iform && form.iform_value == iform_value)
    {
        return Recognition::WrongEncoding;
    }
    let Some(form) = X87_MEMORY_FORMS.iter().find(|form| {
        form.iform == iform && form.iform_value == iform_value && form.mode == mode && form.witness == bytes
    }) else {
        let has_mode = X87_MEMORY_FORMS
            .iter()
            .any(|form| form.iform == iform && form.iform_value == iform_value && form.mode == mode);
        return if has_mode {
            Recognition::WrongEncoding
        } else {
            Recognition::WrongMode
        };
    };
    if decoded.length as usize != form.witness.len()
        || !decoded.operands.iter().any(|operand| {
            operand.visibility == OperandVisibility::Explicit && matches!(operand.kind, OperandKind::Memory(_))
        })
    {
        return Recognition::WrongOperandShape;
    }
    Recognition::Mapped {
        canonical_id: form.canonical_id,
        iform: form.iform,
    }
}

/// Candidate rows from non-long64 contexts deliberately not mapped here.
pub fn unsupported_identities() -> &'static [UnsupportedX87MemoryIdentity] {
    X87_MEMORY_UNSUPPORTED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "xed")]
    #[test]
    fn pinned_long64_witnesses_decode_to_their_exact_x87_memory_identities()
    -> Result<(), angryier_arch_xed_ffi::XedAdapterError> {
        use angryier_arch_xed_ffi::XedDecoder;

        assert_eq!(X87_MEMORY_FORMS.len(), X87_MEMORY_MAPPED_COUNT);
        assert_eq!(unsupported_identities().len(), X87_MEMORY_UNSUPPORTED_COUNT);
        assert_eq!(X87_MEMORY_FORMS.len() + unsupported_identities().len(), 371);
        let decoder = XedDecoder::new();
        for form in X87_MEMORY_FORMS {
            let (decoded, iform) = decoder.decode_with_iform(0x4000, form.witness)?;
            assert_eq!(iform.name, form.iform, "{:02x?}", form.witness);
            assert_eq!(iform.value, form.iform_value, "{:02x?}", form.witness);
            assert_eq!(
                resolve_decoded(
                    form.witness,
                    InstructionMode::Long64,
                    &iform.name,
                    iform.value,
                    &decoded
                ),
                Recognition::Mapped {
                    canonical_id: form.canonical_id,
                    iform: form.iform,
                },
                "{:02x?}",
                form.witness
            );
        }
        Ok(())
    }

    #[cfg(feature = "xed")]
    #[test]
    fn refuses_mutated_bytes_wrong_mode_and_wrong_iform_value() -> Result<(), angryier_arch_xed_ffi::XedAdapterError> {
        use angryier_arch_xed_ffi::XedDecoder;

        let decoder = XedDecoder::new();
        for form in X87_MEMORY_FORMS {
            let (decoded, iform) = decoder.decode_with_iform(0x4000, form.witness)?;
            let mut changed = form.witness.to_vec();
            *changed.last_mut().expect("nonempty witness") ^= 1;
            assert_eq!(
                resolve_decoded(&changed, InstructionMode::Long64, &iform.name, iform.value, &decoded),
                Recognition::WrongEncoding
            );
            assert_eq!(
                resolve_decoded(
                    form.witness,
                    InstructionMode::Legacy32,
                    &iform.name,
                    iform.value,
                    &decoded
                ),
                Recognition::WrongMode
            );
            assert_eq!(
                resolve_decoded(
                    form.witness,
                    InstructionMode::Long64,
                    &iform.name,
                    iform.value.wrapping_add(1),
                    &decoded
                ),
                Recognition::WrongEncoding
            );
        }
        Ok(())
    }

    #[test]
    fn all_other_source_modes_remain_reason_coded() {
        assert_eq!(unsupported_identities().len(), 318);
        assert!(unsupported_identities().iter().all(|identity| {
            identity.reason.starts_with("unsupported-mode:")
                && matches!(
                    identity.source_mode,
                    "legacy32" | "legacy16" | "compat32" | "compat16" | "real32" | "real16"
                )
        }));
        let ids: std::collections::HashSet<_> = X87_MEMORY_FORMS
            .iter()
            .map(|form| form.canonical_id)
            .chain(unsupported_identities().iter().map(|form| form.canonical_id))
            .collect();
        assert_eq!(ids.len(), 371);
    }
}
