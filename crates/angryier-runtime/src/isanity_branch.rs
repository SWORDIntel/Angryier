//! Additive identity handoff for the source-backed long64 near-Jcc rel32 family.
//! Legacy form IDs and execution semantics are deliberately unchanged.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeneratedBranchForm {
    pub iform: &'static str,
    pub opcode_low_nibble: u8,
    pub canonical_id: &'static str,
}

include!("isanity_branch_generated.rs");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BranchHandoff {
    Mapped {
        canonical_id: &'static str,
        iform: &'static str,
        opcode: u8,
        branch_hint: Option<u8>,
    },
    UnknownIform,
    WrongEncoding,
}

/// Resolve a 64-bit near conditional branch with a rel32, optionally preceded
/// by one source-permitted 2E/3E branch-hint prefix. The IFORM must come from
/// decoding these same bytes with pinned XED. Short branches and other prefixes
/// stay unknown.
pub fn resolve_near_jcc_rel32(bytes: &[u8], iform: &str) -> BranchHandoff {
    let Some(form) = GENERATED_BRANCH_FORMS.iter().find(|row| row.iform == iform) else {
        return BranchHandoff::UnknownIform;
    };
    let (branch_hint, offset) = match bytes.first().copied() {
        Some(0x2e | 0x3e) => (Some(bytes[0]), 1),
        _ => (None, 0),
    };
    if bytes.len() != offset + 6 || bytes[offset] != 0x0f || bytes[offset + 1] != 0x80 + form.opcode_low_nibble {
        return BranchHandoff::WrongEncoding;
    }
    BranchHandoff::Mapped {
        canonical_id: form.canonical_id,
        iform: form.iform,
        opcode: bytes[offset + 1],
        branch_hint,
    }
}

pub fn catalogue_sha256() -> &'static str {
    BRANCH_CATALOGUE_SHA256
}

pub fn pinned_xed_source_sha256() -> &'static str {
    BRANCH_XED_SOURCE_SHA256
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_source_derived_condition_resolves_only_its_exact_rel32_opcode() {
        assert_eq!(GENERATED_BRANCH_FORMS.len(), 16);
        for form in GENERATED_BRANCH_FORMS {
            for hint in [None, Some(0x2e), Some(0x3e)] {
                let mut bytes = Vec::with_capacity(7);
                if let Some(hint) = hint {
                    bytes.push(hint);
                }
                bytes.extend_from_slice(&[0x0f, 0x80 + form.opcode_low_nibble, 0, 0, 0, 0]);
                assert_eq!(
                    resolve_near_jcc_rel32(&bytes, form.iform),
                    BranchHandoff::Mapped {
                        canonical_id: form.canonical_id,
                        iform: form.iform,
                        opcode: 0x80 + form.opcode_low_nibble,
                        branch_hint: hint,
                    }
                );
            }
        }
    }

    #[test]
    fn accepts_declared_branch_hints_and_rejects_other_prefixes() {
        let je = &GENERATED_BRANCH_FORMS[4];
        assert_eq!(je.opcode_low_nibble, 4);
        assert_eq!(
            resolve_near_jcc_rel32(&[0x74, 0], je.iform),
            BranchHandoff::WrongEncoding
        );
        assert_eq!(
            resolve_near_jcc_rel32(&[0x2e, 0x0f, 0x84, 0, 0, 0, 0], je.iform),
            BranchHandoff::Mapped {
                canonical_id: je.canonical_id,
                iform: je.iform,
                opcode: 0x84,
                branch_hint: Some(0x2e),
            }
        );
        assert!(matches!(
            resolve_near_jcc_rel32(&[0x3e, 0x0f, 0x84, 0, 0, 0, 0], je.iform),
            BranchHandoff::Mapped {
                branch_hint: Some(0x3e),
                ..
            }
        ));
        assert_eq!(
            resolve_near_jcc_rel32(&[0x66, 0x0f, 0x84, 0, 0, 0, 0], je.iform),
            BranchHandoff::WrongEncoding
        );
        assert_eq!(
            resolve_near_jcc_rel32(&[0x2e, 0x3e, 0x0f, 0x84, 0, 0, 0, 0], je.iform),
            BranchHandoff::WrongEncoding
        );
        assert_eq!(
            resolve_near_jcc_rel32(&[0x0f, 0x85, 0, 0, 0, 0], je.iform),
            BranchHandoff::WrongEncoding
        );
        assert_eq!(
            resolve_near_jcc_rel32(&[0x0f, 0x84, 0, 0, 0, 0], "XED_IFORM_JMP_RELBRd"),
            BranchHandoff::UnknownIform
        );
    }

    #[cfg(feature = "xed")]
    #[test]
    fn pinned_xed_observations_match_every_generated_branch_identity()
    -> Result<(), angryier_arch_xed_ffi::XedAdapterError> {
        let decoder = angryier_arch_xed_ffi::XedDecoder::new();
        for form in GENERATED_BRANCH_FORMS {
            for hint in [None, Some(0x2e), Some(0x3e)] {
                let mut bytes = Vec::with_capacity(7);
                if let Some(hint) = hint {
                    bytes.push(hint);
                }
                bytes.extend_from_slice(&[0x0f, 0x80 + form.opcode_low_nibble, 0, 0, 0, 0]);
                let (_, decoded_form) = decoder.decode_with_iform(0x4000, &bytes)?;
                assert_eq!(decoded_form.name, form.iform);
                assert!(matches!(
                    resolve_near_jcc_rel32(&bytes, &decoded_form.name),
                    BranchHandoff::Mapped { canonical_id, branch_hint, .. }
                        if canonical_id == form.canonical_id && branch_hint == hint
                ));
            }
        }
        Ok(())
    }
}
