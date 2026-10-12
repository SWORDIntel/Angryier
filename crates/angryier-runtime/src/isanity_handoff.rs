//! Versioned bridge from a decoded register-direct instruction to ISANITY's
//! canonical identities. This is additive: the legacy `form_map::map_form`
//! API and IDs are intentionally unchanged.

use angryier_arch::{AccessKind, DecodedInstruction, OperandVisibility};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeneratedForm {
    pub iform: &'static str,
    pub opcode: u8,
    pub reg_operand: u8,
    pub rm_operand: u8,
    pub canonical_id: &'static str,
    pub canonical_sha256: &'static str,
    pub legacy_form: &'static str,
    pub legacy_id: u32,
}

include!("isanity_handoff_generated.rs");

/// The catalogue digest used to generate this runtime snapshot.
pub fn catalogue_sha256() -> &'static str {
    GENERATED_CATALOGUE_SHA256
}

/// The pinned XED source digest recorded by the ISANITY catalogue.
pub fn pinned_xed_source_sha256() -> &'static str {
    GENERATED_XED_SOURCE_SHA256
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnresolvedReason {
    UnknownIform,
    WrongExecutionMode,
    InvalidOrOutOfScopeEncoding,
    WrongLegacyForm,
    WrongOperandShape,
}

/// Decode mode required to make the canonical identity's `long64` scope
/// explicit without coupling the runtime map to a particular XED release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstructionMode {
    Long64,
    Legacy32,
    Legacy16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Handoff {
    Mapped {
        canonical_id: &'static str,
        canonical_sha256: &'static str,
        iform: &'static str,
        legacy_form: &'static str,
        legacy_id: u32,
    },
    Unresolved(UnresolvedReason),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LegacyReverseLookup {
    Unmapped,
    Unique(&'static str),
    Ambiguous(Vec<&'static str>),
}

/// Resolve one complete instruction byte sequence. `iform` and operand
/// metadata must come from the same XED decode of `bytes`; `legacy_id` is the
/// result of Angryier's existing `form_map::map_form` call. Requiring both
/// prevents a mnemonic/shape-only lookup from collapsing opcode direction.
pub fn resolve(
    bytes: &[u8],
    mode: InstructionMode,
    iform: &str,
    operand_widths: &[u16],
    operand_accesses: &[AccessKind],
    legacy_id: u32,
) -> Handoff {
    let Some(form) = GENERATED_FORMS.iter().find(|entry| entry.iform == iform) else {
        return Handoff::Unresolved(UnresolvedReason::UnknownIform);
    };
    if mode != InstructionMode::Long64 {
        return Handoff::Unresolved(UnresolvedReason::WrongExecutionMode);
    }
    if legacy_id != form.legacy_id {
        return Handoff::Unresolved(UnresolvedReason::WrongLegacyForm);
    }
    if operand_widths != [64, 64] || operand_accesses != expected_accesses(form.legacy_form) {
        return Handoff::Unresolved(UnresolvedReason::WrongOperandShape);
    }
    let Some((opcode, rex_w, modrm)) = parse_register_direct(bytes) else {
        return Handoff::Unresolved(UnresolvedReason::InvalidOrOutOfScopeEncoding);
    };
    if opcode != form.opcode || !rex_w || modrm >> 6 != 0b11 {
        return Handoff::Unresolved(UnresolvedReason::InvalidOrOutOfScopeEncoding);
    }
    Handoff::Mapped {
        canonical_id: form.canonical_id,
        canonical_sha256: form.canonical_sha256,
        iform: form.iform,
        legacy_form: form.legacy_form,
        legacy_id: form.legacy_id,
    }
}

/// Convenience bridge for an existing normalized decode. Pass the exact
/// instruction-byte slice and IFORM name captured from the same XED decode;
/// only explicit operands participate in the canonical two-GPR signature.
pub fn resolve_decoded(bytes: &[u8], mode: InstructionMode, iform: &str, decoded: &DecodedInstruction) -> Handoff {
    let operands: Vec<_> = decoded
        .operands
        .iter()
        .filter(|operand| operand.visibility == OperandVisibility::Explicit)
        .collect();
    let widths: Vec<_> = operands.iter().map(|operand| operand.width_bits).collect();
    let accesses: Vec<_> = operands.iter().map(|operand| operand.access).collect();
    resolve(bytes, mode, iform, &widths, &accesses, decoded.form_id)
}

/// Canonical identity to the legacy provider form is exact for this slice.
pub fn legacy_for_canonical(canonical_id: &str) -> Option<u32> {
    GENERATED_FORMS
        .iter()
        .find(|entry| entry.canonical_id == canonical_id)
        .map(|entry| entry.legacy_id)
}

/// Return all canonical identities represented by a legacy ID. The legacy
/// form intentionally collapses two opcode directions, so callers must
/// preserve the `Ambiguous` result instead of picking one arbitrarily.
pub fn canonical_ids_for_legacy(legacy_id: u32) -> LegacyReverseLookup {
    let ids: Vec<_> = GENERATED_FORMS
        .iter()
        .filter(|entry| entry.legacy_id == legacy_id)
        .map(|entry| entry.canonical_id)
        .collect();
    match ids.as_slice() {
        [] => LegacyReverseLookup::Unmapped,
        [one] => LegacyReverseLookup::Unique(one),
        _ => LegacyReverseLookup::Ambiguous(ids),
    }
}

fn expected_accesses(form: &str) -> &'static [AccessKind] {
    use AccessKind::{Read, ReadWrite, Write};
    match form {
        "MOV_R64_R64" => &[Write, Read],
        "ADD_R64_R64" | "SUB_R64_R64" => &[ReadWrite, Read],
        "CMP_R64_R64" => &[Read, Read],
        _ => &[],
    }
}

/// Parse the deliberately narrow primary-opcode, REX.W register-direct
/// encoding shape. Prefixes other than one REX are excluded by the current
/// canonical identity predicates. The complete instruction must be exactly
/// REX + opcode + ModRM (or opcode + ModRM when REX.W is absent).
fn parse_register_direct(bytes: &[u8]) -> Option<(u8, bool, u8)> {
    let mut index = 0;
    let mut rex = None;
    while index < bytes.len() {
        let byte = bytes[index];
        if (0x40..=0x4f).contains(&byte) {
            if rex.replace(byte).is_some() {
                return None;
            }
            index += 1;
            continue;
        }
        // No legacy, mandatory, address-size, or lock/repetition prefixes are
        // admitted by this exact REX.W identity slice.
        if matches!(
            byte,
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0xf0 | 0xf2 | 0xf3
        ) {
            return None;
        }
        break;
    }
    let opcode = *bytes.get(index)?;
    let modrm = *bytes.get(index + 1)?;
    if bytes.len() != index + 2 {
        return None;
    }
    Some((opcode, rex.is_some_and(|value| value & 0x08 != 0), modrm))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MOV: u32 = 0x01;
    const ADD: u32 = 0x02;
    const SUB: u32 = 0x03;
    const CMP: u32 = 0x0a;

    fn resolve_one(bytes: &[u8], iform: &str, accesses: &[AccessKind], legacy: u32) -> Handoff {
        resolve(bytes, InstructionMode::Long64, iform, &[64, 64], accesses, legacy)
    }

    #[test]
    fn all_eight_xed_directions_resolve_to_distinct_canonical_ids() {
        let vectors = [
            (
                &[0x48, 0x89, 0xc8][..],
                "XED_IFORM_MOV_GPRv_GPRv_89",
                &[AccessKind::Write, AccessKind::Read][..],
                MOV,
            ),
            (
                &[0x48, 0x8b, 0xc8][..],
                "XED_IFORM_MOV_GPRv_GPRv_8B",
                &[AccessKind::Write, AccessKind::Read][..],
                MOV,
            ),
            (
                &[0x48, 0x01, 0xc8][..],
                "XED_IFORM_ADD_GPRv_GPRv_01",
                &[AccessKind::ReadWrite, AccessKind::Read][..],
                ADD,
            ),
            (
                &[0x48, 0x03, 0xc8][..],
                "XED_IFORM_ADD_GPRv_GPRv_03",
                &[AccessKind::ReadWrite, AccessKind::Read][..],
                ADD,
            ),
            (
                &[0x48, 0x29, 0xc8][..],
                "XED_IFORM_SUB_GPRv_GPRv_29",
                &[AccessKind::ReadWrite, AccessKind::Read][..],
                SUB,
            ),
            (
                &[0x48, 0x2b, 0xc8][..],
                "XED_IFORM_SUB_GPRv_GPRv_2B",
                &[AccessKind::ReadWrite, AccessKind::Read][..],
                SUB,
            ),
            (
                &[0x48, 0x39, 0xc8][..],
                "XED_IFORM_CMP_GPRv_GPRv_39",
                &[AccessKind::Read, AccessKind::Read][..],
                CMP,
            ),
            (
                &[0x48, 0x3b, 0xc8][..],
                "XED_IFORM_CMP_GPRv_GPRv_3B",
                &[AccessKind::Read, AccessKind::Read][..],
                CMP,
            ),
        ];
        let mut ids = Vec::new();
        for (bytes, iform, accesses, legacy_id) in vectors {
            let Handoff::Mapped {
                canonical_id,
                legacy_id: actual_legacy,
                ..
            } = resolve_one(bytes, iform, accesses, legacy_id)
            else {
                panic!("expected mapped result for {iform}");
            };
            assert_eq!(actual_legacy, legacy_id);
            assert_eq!(legacy_for_canonical(canonical_id), Some(legacy_id));
            ids.push(canonical_id);
        }
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), 8);
    }

    #[test]
    fn rejects_wrong_direction_prefix_width_modrm_and_iform() {
        let iform = "XED_IFORM_MOV_GPRv_GPRv_89";
        let rw = [AccessKind::Write, AccessKind::Read];
        for bytes in [
            &[0x89, 0xc8][..],             // no REX.W
            &[0x48, 0x8b, 0xc8][..],       // opposite opcode direction
            &[0x48, 0x89, 0x08][..],       // memory MOD, not register-direct
            &[0x48, 0x66, 0x89, 0xc8][..], // out-of-scope prefix
            &[0x48, 0x89][..],             // truncated ModRM
            &[0x48, 0x89, 0xc8, 0x90][..], // not one complete instruction
            &[0x48, 0x40, 0x89, 0xc8][..], // ambiguous duplicate REX
        ] {
            assert_eq!(
                resolve_one(bytes, iform, &rw, MOV),
                Handoff::Unresolved(UnresolvedReason::InvalidOrOutOfScopeEncoding)
            );
        }
        assert_eq!(
            resolve(&[0x48, 0x89, 0xc8], InstructionMode::Long64, iform, &[32, 32], &rw, MOV),
            Handoff::Unresolved(UnresolvedReason::WrongOperandShape)
        );
        assert_eq!(
            resolve_one(&[0x48, 0x89, 0xc8], iform, &rw, ADD),
            Handoff::Unresolved(UnresolvedReason::WrongLegacyForm)
        );
        assert_eq!(
            resolve_one(&[0x48, 0x89, 0xc8], "XED_IFORM_MOV_GPR8_GPR8_88", &rw, MOV),
            Handoff::Unresolved(UnresolvedReason::UnknownIform)
        );
        assert_eq!(
            resolve(
                &[0x48, 0x89, 0xc8],
                InstructionMode::Legacy32,
                iform,
                &[64, 64],
                &rw,
                MOV
            ),
            Handoff::Unresolved(UnresolvedReason::WrongExecutionMode)
        );
    }

    #[test]
    fn legacy_reverse_lookup_reports_the_directional_ambiguity() {
        for legacy in [MOV, ADD, SUB, CMP] {
            let LegacyReverseLookup::Ambiguous(ids) = canonical_ids_for_legacy(legacy) else {
                panic!("each legacy form intentionally represents two opcode directions");
            };
            assert_eq!(ids.len(), 2);
            assert_ne!(ids[0], ids[1]);
        }
        assert_eq!(canonical_ids_for_legacy(0xffff_fffe), LegacyReverseLookup::Unmapped);
        assert_eq!(GENERATED_FORMS.len(), 8);
        assert!(
            GENERATED_FORMS
                .iter()
                .all(|form| form.canonical_id.ends_with(form.canonical_sha256))
        );
        assert_eq!(catalogue_sha256().len(), 64);
        assert_eq!(pinned_xed_source_sha256().len(), 64);
    }

    #[cfg(feature = "xed")]
    #[test]
    fn live_xed_decode_hands_off_using_iform_operands_and_bytes_together() {
        use angryier_arch_xed_ffi::XedDecoder;

        let vectors = [
            (&[0x48, 0x89, 0xc8][..], "XED_IFORM_MOV_GPRv_GPRv_89"),
            (&[0x48, 0x8b, 0xc8][..], "XED_IFORM_MOV_GPRv_GPRv_8B"),
            (&[0x48, 0x01, 0xc8][..], "XED_IFORM_ADD_GPRv_GPRv_01"),
            (&[0x48, 0x03, 0xc8][..], "XED_IFORM_ADD_GPRv_GPRv_03"),
            (&[0x48, 0x29, 0xc8][..], "XED_IFORM_SUB_GPRv_GPRv_29"),
            (&[0x48, 0x2b, 0xc8][..], "XED_IFORM_SUB_GPRv_GPRv_2B"),
            (&[0x48, 0x39, 0xc8][..], "XED_IFORM_CMP_GPRv_GPRv_39"),
            (&[0x48, 0x3b, 0xc8][..], "XED_IFORM_CMP_GPRv_GPRv_3B"),
        ];
        let decoder = XedDecoder::new();
        for (bytes, expected_iform) in vectors {
            let (mut decoded, iform) = decoder
                .decode_with_iform(0x4000, bytes)
                .expect("pinned XED decodes vector");
            assert_eq!(iform.name, expected_iform);
            let legacy_id = crate::form_map::map_form(&decoded).expect("legacy map still resolves");
            decoded.form_id = legacy_id;
            assert!(matches!(
                resolve_decoded(bytes, InstructionMode::Long64, &iform.name, &decoded),
                Handoff::Mapped { .. }
            ));
        }
    }
}
