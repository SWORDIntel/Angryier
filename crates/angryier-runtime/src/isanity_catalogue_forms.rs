//! Exact-witness, source-pinned recognition for additive ISANITY slices.
//! This attaches identities only; it does not add semantic implementations.
//! Only concrete sidecar observations are listed; the table is not exhaustive
//! over each identity's legal ModRM/address/immediate-byte domain.

use angryier_arch::{AccessKind, DecodedInstruction, OperandKind, OperandVisibility};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstructionMode {
    Long64,
    Legacy32,
    Legacy16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OperandKindTag {
    Register,
    Memory,
    Immediate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessTag {
    Read,
    Write,
    ReadWrite,
    ConditionalWrite,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeneratedCanonicalOperand {
    pub kind: OperandKindTag,
    pub width_bits: Option<u16>,
    pub access: AccessTag,
    pub signed_immediate: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeneratedCanonicalForm {
    pub source_catalogue: &'static str,
    pub iform: &'static str,
    pub iform_value: u32,
    pub mode: InstructionMode,
    /// MOV opcode-register records carry their selected B0..BF byte explicitly.
    pub opcode_byte: Option<u8>,
    /// Position of that byte in the exact witness (after the exact prefix, if any).
    pub opcode_offset: Option<usize>,
    pub witnesses: &'static [&'static [u8]],
    pub canonical_id: &'static str,
    pub operands: &'static [GeneratedCanonicalOperand],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeneratedUnmappedForm {
    pub iform: &'static str,
    pub iform_value: u32,
    pub mode: InstructionMode,
    pub witnesses: &'static [&'static [u8]],
    pub canonical_id: &'static str,
    pub reason: &'static str,
}

include!("isanity_catalogue_forms_generated.rs");

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
    AmbiguousIdentity,
    Unmapped {
        canonical_id: &'static str,
        iform: &'static str,
        reason: &'static str,
    },
}

/// Resolve only the exact XED-witnessed byte sequence and matching IFORM.
/// Explicit normalized operand kind/access/width and signed-immediate flags
/// are checked against the identity shape captured from the canonical slice.
pub fn resolve_decoded(
    bytes: &[u8],
    mode: InstructionMode,
    iform: &str,
    iform_value: u32,
    decoded: &DecodedInstruction,
) -> Recognition {
    let known_iform = GENERATED_CANONICAL_FORMS.iter().any(|form| form.iform == iform)
        || GENERATED_UNMAPPED_REGISTER_DIRECT_FORMS
            .iter()
            .any(|form| form.iform == iform);
    if !known_iform {
        return Recognition::UnknownIform;
    }
    let mapped_for_iform: Vec<_> = GENERATED_CANONICAL_FORMS
        .iter()
        .filter(|form| form.iform == iform && form.iform_value == iform_value)
        .collect();
    let unmapped_for_iform: Vec<_> = GENERATED_UNMAPPED_REGISTER_DIRECT_FORMS
        .iter()
        .filter(|form| form.iform == iform && form.iform_value == iform_value)
        .collect();
    if mapped_for_iform.is_empty() && unmapped_for_iform.is_empty() {
        return Recognition::WrongLengthOrBytes;
    }
    if !mapped_for_iform.iter().any(|form| form.mode == mode)
        && !unmapped_for_iform.iter().any(|form| form.mode == mode)
    {
        return Recognition::WrongMode;
    }
    let mapped_matches: Vec<_> = mapped_for_iform
        .into_iter()
        .filter(|form| form.mode == mode && decoded.length as usize == bytes.len() && form.witnesses.contains(&bytes))
        .collect();
    let unmapped_matches: Vec<_> = unmapped_for_iform
        .into_iter()
        .filter(|form| form.mode == mode && decoded.length as usize == bytes.len() && form.witnesses.contains(&bytes))
        .collect();
    if mapped_matches.len() + unmapped_matches.len() > 1 {
        return Recognition::AmbiguousIdentity;
    }
    if let Some(form) = unmapped_matches.first() {
        return Recognition::Unmapped {
            canonical_id: form.canonical_id,
            iform: form.iform,
            reason: form.reason,
        };
    }
    let Some(form) = mapped_matches.first() else {
        return Recognition::WrongLengthOrBytes;
    };
    if form
        .opcode_byte
        .is_some_and(|opcode| form.opcode_offset.and_then(|offset| bytes.get(offset)).copied() != Some(opcode))
    {
        return Recognition::WrongLengthOrBytes;
    }
    let explicit: Vec<_> = decoded
        .operands
        .iter()
        .filter(|operand| operand.visibility == OperandVisibility::Explicit)
        .collect();
    if explicit.len() != form.operands.len()
        || explicit.iter().zip(form.operands).any(|(actual, expected)| {
            let kind_matches = matches!(
                (expected.kind, &actual.kind),
                (OperandKindTag::Register, OperandKind::Register(_))
                    | (OperandKindTag::Memory, OperandKind::Memory(_))
                    | (OperandKindTag::Immediate, OperandKind::Immediate(_))
            );
            let access_matches = matches!(
                (expected.access, actual.access),
                (AccessTag::Read, AccessKind::Read)
                    | (AccessTag::Write, AccessKind::Write)
                    | (AccessTag::ReadWrite, AccessKind::ReadWrite)
                    | (AccessTag::ConditionalWrite, AccessKind::ConditionalWrite)
            );
            let width_matches = expected.width_bits.is_none_or(|width| actual.width_bits == width);
            let signed_matches = match &actual.kind {
                OperandKind::Immediate(immediate) => immediate.signed == expected.signed_immediate,
                _ => !expected.signed_immediate,
            };
            !kind_matches || !access_matches || !width_matches || !signed_matches
        })
    {
        return Recognition::WrongOperandShape;
    }
    Recognition::Mapped {
        canonical_id: form.canonical_id,
        iform: form.iform,
    }
}

pub fn excluded_iforms() -> &'static [(&'static str, &'static str)] {
    GENERATED_LONG64_EXCLUSIONS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_table_has_unique_ids_and_keeps_source_constrained_form_out() {
        assert_eq!(GENERATED_CANONICAL_FORMS.len(), GENERATED_CANONICAL_FORM_COUNT);
        assert_eq!(GENERATED_CANONICAL_FORM_COUNT, 316);
        assert_eq!(GENERATED_MOV_OPCODE_REGISTER_FORM_COUNT, 24);
        assert_eq!(GENERATED_PRIMARY_REGISTER_DIRECT_FORM_COUNT, 241);
        assert_eq!(GENERATED_PRIMARY_REGISTER_DIRECT_UNMAPPED_COUNT, 0);
        let mut ids = GENERATED_CANONICAL_FORMS
            .iter()
            .map(|form| form.canonical_id)
            .collect::<Vec<_>>();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), GENERATED_CANONICAL_FORM_COUNT);
        assert_eq!(GENERATED_LONG64_EXCLUSIONS.len(), 2);
        assert_eq!(
            GENERATED_LONG64_EXCLUSIONS
                .iter()
                .find(|(iform, _)| *iform == "XED_IFORM_BEXTR_XOP_GPR32d_GPR32d_IMMd")
                .expect("legacy32-only BEXTR exclusion")
                .0,
            "XED_IFORM_BEXTR_XOP_GPR32d_GPR32d_IMMd"
        );
        assert!(
            GENERATED_LONG64_EXCLUSIONS
                .iter()
                .any(|(iform, reason)| *iform == "XED_IFORM_PALIGNR_MMXq_MEMq_IMMb"
                    && reason.contains("register role"))
        );
    }

    #[test]
    fn source_derived_fixed_opcode_forms_map_only_their_pinned_bytes_and_decode_metadata() {
        let expected = [
            (
                "XED_IFORM_SETSSBSY",
                "isanity:form:v2:sha256:fef4c7d65adc7c874157491be50c4c16a349715d3077db70371ce3a6381ef3b3",
                &[0xf3, 0x0f, 0x01, 0xe8][..],
            ),
            (
                "XED_IFORM_XRESLDTRK",
                "isanity:form:v2:sha256:460e49ff909d37d8aae3c78c244f547d213e96c27ed5d5bf7b2877a6855e9f15",
                &[0xf2, 0x0f, 0x01, 0xe9][..],
            ),
            (
                "XED_IFORM_XSUSLDTRK",
                "isanity:form:v2:sha256:b7713d8b1923ccfb7c12f7235637c91396da5e04319047a66bd5e93073051887",
                &[0xf2, 0x0f, 0x01, 0xe8][..],
            ),
        ];
        for (iform, canonical_id, bytes) in expected {
            let form = GENERATED_CANONICAL_FORMS
                .iter()
                .find(|form| form.iform == iform)
                .expect("source-derived fixed-opcode IFORM is generated");
            assert_eq!(form.canonical_id, canonical_id);
            assert_eq!(form.mode, InstructionMode::Long64);
            assert_eq!(form.witnesses, &[bytes]);
            let decoded = DecodedInstruction {
                address: 0x4000,
                length: bytes.len() as u8,
                form_id: 0,
                features: Vec::new(),
                operands: Vec::new(),
                modifiers: angryier_arch::InstructionModifiers::default(),
            };
            assert_eq!(
                resolve_decoded(bytes, InstructionMode::Long64, iform, form.iform_value, &decoded),
                Recognition::Mapped { canonical_id, iform }
            );
            assert_eq!(
                resolve_decoded(bytes, InstructionMode::Long64, iform, form.iform_value + 1, &decoded),
                Recognition::WrongLengthOrBytes,
                "mismatched decoder IFORM value must not map {iform}"
            );
            let mut wrong_prefix = bytes.to_vec();
            wrong_prefix[0] ^= 1;
            assert_eq!(
                resolve_decoded(
                    &wrong_prefix,
                    InstructionMode::Long64,
                    iform,
                    form.iform_value,
                    &decoded
                ),
                Recognition::WrongLengthOrBytes,
                "wrong mandatory prefix must not map {iform}"
            );
            assert_eq!(
                resolve_decoded(bytes, InstructionMode::Legacy32, iform, form.iform_value, &decoded),
                Recognition::WrongMode,
                "out-of-profile mode must not map {iform}"
            );
        }
    }

    #[test]
    fn primary_register_direct_slice_has_241_exact_maps_and_no_unmapped_records() {
        assert_eq!(GENERATED_PRIMARY_REGISTER_DIRECT_SOURCE_COUNT, 241);
        let mapped: Vec<_> = GENERATED_CANONICAL_FORMS
            .iter()
            .filter(|form| form.source_catalogue == "x86-register-direct-v2.json")
            .collect();
        assert_eq!(mapped.len(), GENERATED_PRIMARY_REGISTER_DIRECT_FORM_COUNT);
        assert_eq!(mapped.len(), 241);
        assert!(GENERATED_UNMAPPED_REGISTER_DIRECT_FORMS.is_empty());
        assert_eq!(
            GENERATED_UNMAPPED_REGISTER_DIRECT_FORMS.len(),
            GENERATED_PRIMARY_REGISTER_DIRECT_UNMAPPED_COUNT
        );

        let mut identities = mapped.iter().map(|form| form.canonical_id).collect::<Vec<_>>();
        identities.extend(
            GENERATED_UNMAPPED_REGISTER_DIRECT_FORMS
                .iter()
                .map(|form| form.canonical_id),
        );
        identities.sort_unstable();
        identities.dedup();
        assert_eq!(identities.len(), GENERATED_PRIMARY_REGISTER_DIRECT_SOURCE_COUNT);
    }

    #[test]
    fn logical_register_register_forms_are_complete_and_discriminated() {
        let logical = GENERATED_CANONICAL_FORMS
            .iter()
            .filter(|form| {
                form.source_catalogue == "x86-register-direct-v2.json"
                    && ["XED_IFORM_AND_GPR", "XED_IFORM_OR_GPR", "XED_IFORM_XOR_GPR"]
                        .iter()
                        .any(|prefix| form.iform.starts_with(prefix))
                    && form.iform.contains("_GPR")
                    && form.operands.len() == 2
                    && form
                        .operands
                        .iter()
                        .all(|operand| operand.kind == OperandKindTag::Register)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            logical.len(),
            24,
            "8/16/32/64-bit forms × two opcode directions × three operations"
        );

        let mut names = logical.iter().map(|form| form.iform).collect::<Vec<_>>();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            12,
            "three operations × two direction-specific IFORMs × two operand naming families"
        );

        let mut widths = logical
            .iter()
            .map(|form| form.operands[0].width_bits.expect("register width is pinned"))
            .collect::<Vec<_>>();
        widths.sort_unstable();
        assert_eq!(
            widths,
            [
                8, 8, 8, 8, 8, 8, 16, 16, 16, 16, 16, 16, 32, 32, 32, 32, 32, 32, 64, 64, 64, 64, 64, 64
            ]
        );

        let form = logical[0];
        let bytes = form.witnesses[0];
        let decoded_operands = form
            .operands
            .iter()
            .enumerate()
            .map(|(index, operand)| angryier_arch::Operand {
                index: index as u8,
                width_bits: operand.width_bits.expect("logical register width"),
                access: match operand.access {
                    AccessTag::Read => AccessKind::Read,
                    AccessTag::Write => AccessKind::Write,
                    AccessTag::ReadWrite => AccessKind::ReadWrite,
                    AccessTag::ConditionalWrite => AccessKind::ConditionalWrite,
                },
                visibility: OperandVisibility::Explicit,
                kind: OperandKind::Register(angryier_arch::RegisterView::full(
                    angryier_arch::RegisterId(index as u32),
                    operand.width_bits.expect("logical register width"),
                )),
            })
            .collect();
        let decoded = DecodedInstruction {
            address: 0x4000,
            length: bytes.len() as u8,
            form_id: 0,
            features: Vec::new(),
            operands: decoded_operands,
            modifiers: angryier_arch::InstructionModifiers::default(),
        };
        assert_eq!(
            resolve_decoded(bytes, form.mode, form.iform, form.iform_value, &decoded),
            Recognition::Mapped {
                canonical_id: form.canonical_id,
                iform: form.iform,
            }
        );
        assert_eq!(
            resolve_decoded(
                bytes,
                form.mode,
                "XED_IFORM_NOT_IN_THE_PINNED_SLICE",
                form.iform_value,
                &decoded
            ),
            Recognition::UnknownIform,
            "unknown decoder form names remain unresolved"
        );
        let other_direction = logical
            .iter()
            .find(|candidate| {
                candidate.iform != form.iform
                    && candidate
                        .iform
                        .starts_with(&form.iform[..form.iform.find("_GPR").unwrap_or(form.iform.len())])
            })
            .map(|candidate| candidate.iform);
        if let Some(other_direction) = other_direction {
            assert_eq!(
                resolve_decoded(bytes, form.mode, other_direction, form.iform_value, &decoded),
                Recognition::WrongLengthOrBytes,
                "an opcode-direction sibling must not inherit this witness's FormId"
            );
        }
    }

    #[test]
    fn mov_b0_bf_selector_records_resolve_only_with_exact_opcode_mode_and_operands() {
        let mov = GENERATED_CANONICAL_FORMS
            .iter()
            .filter(|form| form.source_catalogue == "x86-mov-opcode-register-v2.json")
            .collect::<Vec<_>>();
        assert_eq!(mov.len(), GENERATED_MOV_OPCODE_REGISTER_FORM_COUNT);
        assert_eq!(
            mov.iter()
                .filter(|form| form.iform == "XED_IFORM_MOV_GPR8_IMMb_B0")
                .count(),
            8
        );
        assert_eq!(
            mov.iter()
                .filter(|form| form.iform == "XED_IFORM_MOV_GPRv_IMMv")
                .count(),
            16
        );
        let mut keys = Vec::new();
        for form in &mov {
            let opcode = form.opcode_byte.expect("MOV slice pins an exact opcode");
            let offset = form.opcode_offset.expect("MOV slice pins exact opcode offset");
            assert!(form.witnesses.iter().all(|bytes| bytes.get(offset) == Some(&opcode)));
            assert_eq!(form.mode, InstructionMode::Long64);
            keys.push((form.iform, form.iform_value, opcode, form.operands[0].width_bits));
            let bytes = form.witnesses[0];
            let decoded = DecodedInstruction {
                address: 0x4000,
                length: bytes.len() as u8,
                form_id: 0,
                features: Vec::new(),
                operands: form
                    .operands
                    .iter()
                    .enumerate()
                    .map(|(index, operand)| {
                        let width = operand.width_bits.expect("MOV operand width is pinned");
                        let kind = match operand.kind {
                            OperandKindTag::Register => OperandKind::Register(angryier_arch::RegisterView::full(
                                angryier_arch::RegisterId(index as u32),
                                width,
                            )),
                            OperandKindTag::Immediate => OperandKind::Immediate(angryier_arch::ImmediateOperand {
                                value: 1,
                                signed: operand.signed_immediate,
                            }),
                            _ => panic!("MOV selector slice has only register/immediate operands"),
                        };
                        angryier_arch::Operand {
                            index: index as u8,
                            width_bits: width,
                            access: match operand.access {
                                AccessTag::Read => AccessKind::Read,
                                AccessTag::Write => AccessKind::Write,
                                AccessTag::ReadWrite => AccessKind::ReadWrite,
                                AccessTag::ConditionalWrite => AccessKind::ConditionalWrite,
                            },
                            visibility: OperandVisibility::Explicit,
                            kind,
                        }
                    })
                    .collect(),
                modifiers: angryier_arch::InstructionModifiers::default(),
            };
            assert_eq!(
                resolve_decoded(bytes, form.mode, form.iform, form.iform_value, &decoded),
                Recognition::Mapped {
                    canonical_id: form.canonical_id,
                    iform: form.iform
                },
                "exact MOV selector identity should map at opcode {opcode:#04x}"
            );
            assert_eq!(
                resolve_decoded(bytes, InstructionMode::Legacy32, form.iform, form.iform_value, &decoded),
                Recognition::WrongMode,
                "MOV identity must remain long64-only"
            );
            let mut wrong_opcode = bytes.to_vec();
            wrong_opcode[offset] ^= 0x80;
            assert_eq!(
                resolve_decoded(&wrong_opcode, form.mode, form.iform, form.iform_value, &decoded),
                Recognition::WrongLengthOrBytes,
                "wrong B0..BF opcode must not inherit a selector identity"
            );
            let mut wrong_operands = decoded.clone();
            wrong_operands.operands[0].width_bits ^= 8;
            assert_eq!(
                resolve_decoded(bytes, form.mode, form.iform, form.iform_value, &wrong_operands),
                Recognition::WrongOperandShape,
                "operand-width drift must fail closed"
            );
        }
        keys.sort_unstable();
        keys.dedup();
        assert_eq!(keys.len(), 24, "same-IFORM B8 identities remain opcode-qualified");
        for opcode in 0xB8..=0xBF {
            let siblings = mov
                .iter()
                .filter(|form| form.opcode_byte == Some(opcode))
                .collect::<Vec<_>>();
            assert_eq!(
                siblings.len(),
                2,
                "B8 selector {opcode:#04x} has W32 and REX.W W64 identities"
            );
            assert_ne!(siblings[0].canonical_id, siblings[1].canonical_id);
            assert_ne!(siblings[0].operands[0].width_bits, siblings[1].operands[0].width_bits);
        }
    }

    #[test]
    fn p4_test_register_register_identities_are_exactly_discriminated() {
        let expected = [
            (
                "isanity:form:v2:sha256:59bb748f9e4ef728874b52ba681a1807ba0fdfead23848d05e913593b9d3582f",
                8,
                &[0x84, 0xc0][..],
            ),
            (
                "isanity:form:v2:sha256:309651eac1a79edcba1d70df669325b5a5042f9086acf66feb6c53dace5d6c55",
                16,
                &[0x66, 0x85, 0xc1][..],
            ),
            (
                "isanity:form:v2:sha256:fc695360164a7858b4ffd59981c934dee931323d7ddc998a3d8ba495abc291f4",
                32,
                &[0x85, 0xc1][..],
            ),
            (
                "isanity:form:v2:sha256:ea47f52c52267a015f6d55dc0ae29c6204e319faa0f9768b47e69eaff9906198",
                64,
                &[0x48, 0x85, 0xc1][..],
            ),
        ];
        let forms = GENERATED_CANONICAL_FORMS
            .iter()
            .filter(|form| {
                form.source_catalogue == "x86-register-direct-v2.json"
                    && form.iform.starts_with("XED_IFORM_TEST_GPR")
                    && form.operands.len() == 2
                    && form
                        .operands
                        .iter()
                        .all(|operand| operand.kind == OperandKindTag::Register)
            })
            .collect::<Vec<_>>();
        assert_eq!(forms.len(), expected.len());

        for (canonical_id, width, witness) in expected {
            let form = forms
                .iter()
                .find(|form| form.canonical_id == canonical_id)
                .expect("TEST FormId from the P4 semantic slice is present");
            assert_eq!(
                form.iform,
                if width == 8 {
                    "XED_IFORM_TEST_GPR8_GPR8"
                } else {
                    "XED_IFORM_TEST_GPRv_GPRv"
                }
            );
            assert_eq!(form.mode, InstructionMode::Long64);
            assert!(form.operands.iter().all(|operand| operand.width_bits == Some(width)));
            assert!(
                form.witnesses.contains(&witness),
                "pinned witness missing for width {width}"
            );

            let decoded = DecodedInstruction {
                address: 0x4000,
                length: witness.len() as u8,
                form_id: 0,
                features: Vec::new(),
                operands: form
                    .operands
                    .iter()
                    .enumerate()
                    .map(|(index, operand)| angryier_arch::Operand {
                        index: index as u8,
                        width_bits: operand.width_bits.expect("TEST register width is pinned"),
                        access: AccessKind::Read,
                        visibility: OperandVisibility::Explicit,
                        kind: OperandKind::Register(angryier_arch::RegisterView::full(
                            angryier_arch::RegisterId(index as u32),
                            width,
                        )),
                    })
                    .collect(),
                modifiers: angryier_arch::InstructionModifiers::default(),
            };
            assert_eq!(
                resolve_decoded(witness, form.mode, form.iform, form.iform_value, &decoded),
                Recognition::Mapped {
                    canonical_id,
                    iform: form.iform
                },
                "exact TEST identity should resolve for width {width}"
            );

            let mut wrong_opcode = witness.to_vec();
            let opcode_index = usize::from(wrong_opcode[0] == 0x66 || wrong_opcode[0] == 0x48);
            wrong_opcode[opcode_index] = if wrong_opcode[opcode_index] == 0x84 { 0x85 } else { 0x84 };
            assert_eq!(
                resolve_decoded(&wrong_opcode, form.mode, form.iform, form.iform_value, &decoded),
                Recognition::WrongLengthOrBytes,
                "TEST opcode mismatch must not map width {width}"
            );

            if width == 16 || width == 64 {
                let mut wrong_width = witness.to_vec();
                let prefix_index = 0;
                wrong_width[prefix_index] = if width == 16 { 0x48 } else { 0x66 };
                assert!(
                    matches!(
                        resolve_decoded(&wrong_width, form.mode, form.iform, form.iform_value, &decoded),
                        Recognition::WrongLengthOrBytes | Recognition::WrongOperandShape
                    ),
                    "operand-size prefix mismatch must not map width {width}"
                );
            }
        }

        let form = forms[0];
        let witness = form.witnesses[0];
        let decoded = DecodedInstruction {
            address: 0x4000,
            length: witness.len() as u8,
            form_id: 0,
            features: Vec::new(),
            operands: form
                .operands
                .iter()
                .enumerate()
                .map(|(index, operand)| angryier_arch::Operand {
                    index: index as u8,
                    width_bits: operand.width_bits.expect("TEST register width is pinned"),
                    access: AccessKind::Read,
                    visibility: OperandVisibility::Explicit,
                    kind: OperandKind::Register(angryier_arch::RegisterView::full(
                        angryier_arch::RegisterId(index as u32),
                        operand.width_bits.expect("TEST register width is pinned"),
                    )),
                })
                .collect(),
            modifiers: angryier_arch::InstructionModifiers::default(),
        };
        assert_eq!(
            resolve_decoded(
                witness,
                form.mode,
                "XED_IFORM_NOT_IN_THE_PINNED_SLICE",
                form.iform_value,
                &decoded
            ),
            Recognition::UnknownIform
        );
        assert_eq!(
            resolve_decoded(witness, form.mode, form.iform, u32::MAX, &decoded),
            Recognition::WrongLengthOrBytes,
            "unknown IFORM value must not map"
        );
    }

    #[test]
    fn all_48_cmovcc_identities_keep_conditional_write_access() {
        let forms = GENERATED_CANONICAL_FORMS
            .iter()
            .filter(|form| {
                form.source_catalogue == "x86-register-direct-v2.json" && form.iform.starts_with("XED_IFORM_CMOV")
            })
            .collect::<Vec<_>>();
        assert_eq!(forms.len(), 48);
        for form in forms {
            assert_eq!(form.operands[0].access, AccessTag::ConditionalWrite, "{}", form.iform);
            assert_eq!(form.operands[1].access, AccessTag::Read, "{}", form.iform);
            let operands = form
                .operands
                .iter()
                .enumerate()
                .map(|(index, expected)| angryier_arch::Operand {
                    index: index as u8,
                    width_bits: expected.width_bits.expect("CMOV width is source-pinned"),
                    access: match expected.access {
                        AccessTag::Read => AccessKind::Read,
                        AccessTag::Write => AccessKind::Write,
                        AccessTag::ReadWrite => AccessKind::ReadWrite,
                        AccessTag::ConditionalWrite => AccessKind::ConditionalWrite,
                    },
                    visibility: OperandVisibility::Explicit,
                    kind: OperandKind::Register(angryier_arch::RegisterView::full(
                        angryier_arch::RegisterId(index as u32),
                        expected.width_bits.expect("CMOV width is source-pinned"),
                    )),
                })
                .collect::<Vec<_>>();
            let decoded = DecodedInstruction {
                address: 0x4000,
                length: form.witnesses[0].len() as u8,
                form_id: 0,
                features: Vec::new(),
                operands,
                modifiers: angryier_arch::InstructionModifiers::default(),
            };
            assert_eq!(
                resolve_decoded(form.witnesses[0], form.mode, form.iform, form.iform_value, &decoded),
                Recognition::Mapped {
                    canonical_id: form.canonical_id,
                    iform: form.iform
                },
                "conditional destination access must round-trip for {}",
                form.iform,
            );
        }
    }

    #[cfg(feature = "xed")]
    #[test]
    fn pinned_xed_exact_witnesses_match_form_length_and_operand_metadata()
    -> Result<(), angryier_arch_xed_ffi::XedAdapterError> {
        use angryier_arch::OperandVisibility;
        let decoder = angryier_arch_xed_ffi::XedDecoder::new();
        for form in GENERATED_CANONICAL_FORMS {
            assert!(
                !form.witnesses.is_empty(),
                "{} has no source-backed witnesses",
                form.iform
            );
            for bytes in form.witnesses {
                let (mut decoded, iform) = decoder.decode_with_iform(0x4000, bytes)?;
                assert_eq!(iform.xed_sys_version, "xed-sys 0.6.0+xed-2024.05.20");
                assert_eq!(iform.name, form.iform);
                assert_eq!(iform.value, form.iform_value);
                assert_eq!(decoded.length as usize, bytes.len(), "{}", form.iform);
                assert_eq!(
                    resolve_decoded(bytes, form.mode, &iform.name, iform.value, &decoded),
                    Recognition::Mapped {
                        canonical_id: form.canonical_id,
                        iform: form.iform,
                    },
                    "{} operands={:?} expected={:?}",
                    form.iform,
                    decoded.operands,
                    form.operands
                );
                let explicit_count = decoded
                    .operands
                    .iter()
                    .filter(|operand| operand.visibility == OperandVisibility::Explicit)
                    .count();
                assert_eq!(explicit_count, form.operands.len(), "{}", form.iform);

                let mut wrong_bytes = bytes.to_vec();
                wrong_bytes.push(0x90);
                assert_eq!(
                    resolve_decoded(&wrong_bytes, form.mode, &iform.name, iform.value, &decoded),
                    Recognition::WrongLengthOrBytes,
                    "{} accepted trailing bytes",
                    form.iform
                );
                assert_eq!(
                    resolve_decoded(bytes, InstructionMode::Legacy16, &iform.name, iform.value, &decoded),
                    Recognition::WrongMode,
                    "{} accepted a different mode",
                    form.iform
                );

                if let Some(explicit) = decoded
                    .operands
                    .iter_mut()
                    .find(|operand| operand.visibility == OperandVisibility::Explicit)
                {
                    explicit.access = if explicit.access == AccessKind::Write {
                        AccessKind::Read
                    } else {
                        AccessKind::Write
                    };
                    assert_eq!(
                        resolve_decoded(bytes, form.mode, &iform.name, iform.value, &decoded),
                        Recognition::WrongOperandShape,
                        "{} accepted mutated operand access",
                        form.iform
                    );
                }
            }
        }
        for form in GENERATED_UNMAPPED_REGISTER_DIRECT_FORMS {
            for bytes in form.witnesses {
                let (decoded, iform) = decoder.decode_with_iform(0x4000, bytes)?;
                assert_eq!(iform.xed_sys_version, "xed-sys 0.6.0+xed-2024.05.20");
                assert_eq!(iform.name, form.iform);
                assert_eq!(iform.value, form.iform_value);
                assert_eq!(decoded.length as usize, bytes.len());
                assert_eq!(
                    resolve_decoded(bytes, form.mode, &iform.name, iform.value, &decoded),
                    Recognition::Unmapped {
                        canonical_id: form.canonical_id,
                        iform: form.iform,
                        reason: form.reason,
                    },
                    "{} must retain its explicit no-lossy-access-model disposition",
                    form.iform
                );
            }
        }
        Ok(())
    }
}
