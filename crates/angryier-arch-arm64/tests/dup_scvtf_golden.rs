//! DUP/SCVTF encoding domains, cross-checked with llvm-mc (AArch64).
use angryier_arch::{AccessKind, Decoder, OperandKind};
use angryier_arch_arm64::{Arm64Decoder, forms_fp as fp, forms_simd as simd};
use angryier_types::TargetProfileId;

#[test]
fn dup_element_and_general_domains_and_views() -> Result<(), Box<dyn std::error::Error>> {
    let decoder = Arm64Decoder::with_profile_id(TargetProfileId(3));
    for (base, scalar, general, q) in [
        (0x0E00_0400u32, false, false, false),
        (0x4E00_0400, false, false, true),
        (0x5E00_0400, true, false, true),
        (0x0E00_0C00, false, true, false),
        (0x4E00_0C00, false, true, true),
    ] {
        for imm5 in 0..32u32 {
            let size = imm5.trailing_zeros();
            let valid = size <= 3 && (scalar || q || size != 3);
            for rn in 0..32 {
                for rd in 0..32 {
                    let word = base | (imm5 << 16) | (rn << 5) | rd;
                    let decoded = decoder.decode(0x1000, &word.to_le_bytes());
                    if !valid {
                        if let Ok(insn) = decoded {
                            assert!(
                                !(simd::DUP_ELEMENT..=simd::DUP_GPR_D).contains(&insn.form_id),
                                "{word:08x}"
                            );
                        }
                        continue;
                    }
                    let insn = decoded?;
                    let lane_bits = 8u16 << size;
                    let form = if scalar {
                        simd::DUP_SCALAR
                    } else if !general {
                        simd::DUP_ELEMENT
                    } else {
                        [simd::DUP_GPR_B, simd::DUP_GPR_H, simd::DUP_GPR_S, simd::DUP_GPR_D][size as usize]
                    };
                    assert_eq!(insn.form_id, form, "{word:08x}");
                    assert_eq!(insn.operands.len(), 2);
                    assert_eq!(insn.operands[0].access, AccessKind::Write);
                    assert_eq!(insn.operands[1].access, AccessKind::Read);
                    let dst = match insn.operands[0].kind {
                        OperandKind::Register(view) => view,
                        ref other => return Err(format!("unexpected destination {other:?}").into()),
                    };
                    let src = match insn.operands[1].kind {
                        OperandKind::Register(view) => view,
                        ref other => return Err(format!("unexpected source {other:?}").into()),
                    };
                    assert_eq!(dst.parent.0, 36 + rd);
                    assert_eq!(
                        dst.width_bits,
                        if scalar {
                            lane_bits
                        } else if q {
                            128
                        } else {
                            64
                        }
                    );
                    assert_eq!(src.parent.0, if general { rn } else { 36 + rn });
                    assert_eq!(
                        src.width_bits,
                        if general {
                            if size == 3 { 64 } else { 32 }
                        } else {
                            lane_bits
                        }
                    );
                    assert_eq!(
                        src.bit_offset,
                        if general {
                            0
                        } else {
                            (imm5 >> (size + 1)) as u16 * lane_bits
                        }
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn scvtf_all_nonfixed_forms_and_register_fields() -> Result<(), Box<dyn std::error::Error>> {
    let decoder = Arm64Decoder::with_profile_id(TargetProfileId(3));
    for (base, form, dst_width, src_width, general) in [
        (0x1E22_0000u32, fp::SCVTF_S_W, 32, 32, true),
        (0x1E62_0000, fp::SCVTF_D_W, 64, 32, true),
        (0x9E22_0000, fp::SCVTF_S_X, 32, 64, true),
        (0x9E62_0000, fp::SCVTF_D_X, 64, 64, true),
        (0x5E21_D800, fp::SCVTF_S_S, 32, 32, false),
        (0x5E61_D800, fp::SCVTF_D_D, 64, 64, false),
        (0x0E21_D800, fp::SCVTF_V2S, 64, 64, false),
        (0x4E21_D800, fp::SCVTF_V4S, 128, 128, false),
        (0x4E61_D800, fp::SCVTF_V2D, 128, 128, false),
    ] {
        for rn in 0..32 {
            for rd in 0..32 {
                let word = base | (rn << 5) | rd;
                let insn = decoder.decode(0x1000, &word.to_le_bytes())?;
                assert_eq!(insn.form_id, form);
                assert_eq!(insn.operands.len(), 2);
                for (index, parent, width, access) in [
                    (0, 36 + rd, dst_width, AccessKind::Write),
                    (1, if general { rn } else { 36 + rn }, src_width, AccessKind::Read),
                ] {
                    let op = &insn.operands[index];
                    let view = match op.kind {
                        OperandKind::Register(view) => view,
                        ref other => return Err(format!("unexpected operand {other:?}").into()),
                    };
                    assert_eq!(view.parent.0, parent);
                    assert_eq!(view.width_bits, width);
                    assert_eq!(view.bit_offset, 0);
                    assert_eq!(op.width_bits, width);
                    assert_eq!(op.access, access);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn fixed_field_mutations_never_alias_dup_or_scvtf() -> Result<(), Box<dyn std::error::Error>> {
    let decoder = Arm64Decoder::with_profile_id(TargetProfileId(3));
    for (base, mask, first, last) in [
        (0x0E1F_0420u32, 0xBFE0_FC00u32, simd::DUP_ELEMENT, simd::DUP_GPR_D),
        (0x5E1F_0420, 0xFFE0_FC00, simd::DUP_ELEMENT, simd::DUP_GPR_D),
        (0x4E01_0C20, 0xBFE0_FC00, simd::DUP_ELEMENT, simd::DUP_GPR_D),
        (0x1E22_0020, 0x7FBF_FC00, fp::SCVTF_S_W, fp::SCVTF_V2D),
        (0x5E21_D820, 0xFFBF_FC00, fp::SCVTF_S_W, fp::SCVTF_V2D),
        (0x0E21_D820, 0xBFBF_FC00, fp::SCVTF_S_W, fp::SCVTF_V2D),
    ] {
        for bit in 0..32 {
            if mask & (1 << bit) == 0 {
                continue;
            }
            let word = base ^ (1 << bit);
            if let Ok(insn) = decoder.decode(0x1000, &word.to_le_bytes()) {
                // A mutation can become a different valid instruction, but not
                // an unrelated encoding within this family's advertised forms.
                if !(first..=last).contains(&insn.form_id) {
                    continue;
                }
                let mask_matches = match insn.form_id {
                    simd::DUP_ELEMENT => word & 0xBFE0_FC00 == 0x0E00_0400,
                    simd::DUP_SCALAR => word & 0xFFE0_FC00 == 0x5E00_0400,
                    simd::DUP_GPR_B | simd::DUP_GPR_H | simd::DUP_GPR_S | simd::DUP_GPR_D => {
                        word & 0xBFE0_FC00 == 0x0E00_0C00
                    }
                    fp::SCVTF_S_W | fp::SCVTF_D_W | fp::SCVTF_S_X | fp::SCVTF_D_X => word & 0x7FBF_FC00 == 0x1E22_0000,
                    fp::SCVTF_S_S | fp::SCVTF_D_D => word & 0xFFBF_FC00 == 0x5E21_D800,
                    _ => word & 0xBFBF_FC00 == 0x0E21_D800 && !(word & (1 << 22) != 0 && word & (1 << 30) == 0),
                };
                assert!(mask_matches, "{word:08x}");
            }
        }
    }
    Ok(())
}

#[test]
fn unsigned_fixedpoint_half_and_reserved_conversions_stay_outside_subset() -> Result<(), Box<dyn std::error::Error>> {
    let decoder = Arm64Decoder::with_profile_id(TargetProfileId(3));
    for word in [
        0x1E23_0020u32,
        0x7E21_D820,
        0x2E21_D820, // unsigned
        0x1E02_FC20,
        0x5F3F_E420,
        0x0F3F_E420, // fixed point
        0x1EE2_0020,
        0x1EA2_0020,
        0x0E61_D820,
    ] {
        // FP16/reserved/1D vector
        if let Ok(insn) = decoder.decode(0x1000, &word.to_le_bytes()) {
            assert!(!(fp::SCVTF_S_W..=fp::SCVTF_V2D).contains(&insn.form_id), "{word:08x}");
        }
    }
    Ok(())
}
