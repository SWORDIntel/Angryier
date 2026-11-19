//! Scalar FP decode golden vectors, generated with llvm-mc (aarch64).

use angryier_arch::{Decoder, OperandKind};
use angryier_arch_arm64::{Arm64Decoder, forms_fp};
use angryier_types::TargetProfileId;

fn decode(word: u32) -> Result<angryier_arch::DecodedInstruction, String> {
    let decoder = Arm64Decoder::with_profile_id(TargetProfileId(7));
    decoder
        .decode(0x1000, &word.to_le_bytes())
        .map_err(|error| format!("FP word {word:#010x} failed to decode: {error:?}"))
}

#[test]
fn fp_two_source_forms() -> Result<(), String> {
    // fadd s0, s1, s2 = 0x1E222820.
    assert_eq!(decode(0x1E22_2820)?.form_id, forms_fp::FADD_S);
    // fadd d0, d1, d2 = 0x1E622820.
    assert_eq!(decode(0x1E62_2820)?.form_id, forms_fp::FADD_D);
    // fsub s0, s1, s2 = 0x1E223820.
    assert_eq!(decode(0x1E22_3820)?.form_id, forms_fp::FSUB_S);
    // fmul d0, d1, d2 = 0x1E620820.
    assert_eq!(decode(0x1E62_0820)?.form_id, forms_fp::FMUL_D);
    // fdiv s0, s1, s2 = 0x1E221820.
    assert_eq!(decode(0x1E22_1820)?.form_id, forms_fp::FDIV_S);
    // fmul s2, s0, s1 = 0x1E210802.
    let insn = decode(0x1E21_0802)?;
    assert_eq!(insn.form_id, forms_fp::FMUL_S);
    match &insn.operands[0].kind {
        OperandKind::Register(view) => assert_eq!(view.parent.0, 38), // V2
        other => return Err(format!("expected register operand, got {other:?}")),
    }
    Ok(())
}

#[test]
fn fp_one_source_forms() -> Result<(), String> {
    // fneg d0, d1 = 0x1E614020.
    assert_eq!(decode(0x1E61_4020)?.form_id, forms_fp::FNEG_D);
    // fsqrt s0, s1 = 0x1E21C020.
    assert_eq!(decode(0x1E21_C020)?.form_id, forms_fp::FSQRT_S);
    // fabs d0, d1 = 0x1E60C020.
    assert_eq!(decode(0x1E60_C020)?.form_id, forms_fp::FABS_D);
    Ok(())
}

#[test]
fn fcmp_forms() -> Result<(), String> {
    // fcmp s1, s2 = 0x1E222020.
    assert_eq!(decode(0x1E22_2020)?.form_id, forms_fp::FCMP_S);
    // fcmp d1, d2 = 0x1E622020.
    assert_eq!(decode(0x1E62_2020)?.form_id, forms_fp::FCMP_D);
    Ok(())
}

#[test]
fn fmov_general_fp_moves() -> Result<(), String> {
    // llvm-mc: fmov s18, w11 = 0x1E270172.
    assert_eq!(decode(0x1E27_0172)?.form_id, forms_fp::FMOV_S_W);
    // fmov w11, s18 = 0x1E26024B.
    assert_eq!(decode(0x1E26_024B)?.form_id, forms_fp::FMOV_W_S);
    // fmov d7, x2 = 0x9E670047.
    assert_eq!(decode(0x9E67_0047)?.form_id, forms_fp::FMOV_D_X);
    // fmov x2, d7 = 0x9E6600E2.
    assert_eq!(decode(0x9E66_00E2)?.form_id, forms_fp::FMOV_X_D);
    Ok(())
}

#[test]
fn fmov_immediate_expansion() -> Result<(), String> {
    // llvm-mc sweep: the decoder expands VFPExpandImm to the IEEE bit pattern.
    let cases: &[(u32, u64, bool)] = &[
        (0x1E2C_1000, 0x3F00_0000, false),          // fmov s0, #0.5
        (0x1E2E_1001, 0x3F80_0000, false),          // fmov s1, #1.0
        (0x1E2F_1002, 0x3FC0_0000, false),          // fmov s2, #1.5
        (0x1E20_1003, 0x4000_0000, false),          // fmov s3, #2.0
        (0x1E2D_1004, 0x3F40_0000, false),          // fmov s4, #0.75
        (0x1E6C_1000, 0x3FE0_0000_0000_0000, true), // fmov d0, #0.5
        (0x1E6E_1001, 0x3FF0_0000_0000_0000, true), // fmov d1, #1.0
        (0x1E60_1003, 0x4000_0000_0000_0000, true), // fmov d3, #2.0
        (0x1E26_9009, 0x41A0_0000, false),          // fmov s9, #20.0
        (0x1E31_9002, 0xC060_0000, false),          // fmov s2, #-3.5
        (0x1E60_9000, 0x4004_0000_0000_0000, true), // fmov d0, #2.5
    ];
    for (word, bits, double) in cases {
        let insn = decode(*word)?;
        let expected_form = if *double { forms_fp::FMOV_ID } else { forms_fp::FMOV_IS };
        assert_eq!(insn.form_id, expected_form, "word {word:#010x}");
        match &insn.operands[1].kind {
            OperandKind::Immediate(op) => assert_eq!(op.value, *bits, "word {word:#010x}"),
            other => {
                return Err(format!(
                    "expected immediate operand for word {word:#010x}, got {other:?}"
                ));
            }
        }
    }
    Ok(())
}

#[test]
fn fmov_immediate_exhaustive_values_and_destinations() -> Result<(), String> {
    use angryier_arch::{AccessKind, OperandVisibility};
    for double in [false, true] {
        for imm8 in 0..256u32 {
            // Independent numeric definition: +/- (1 + fraction/16) * 2^E.
            let exponent = ((imm8 >> 4) & 3) as i32 + if imm8 & 0x40 == 0 { 1 } else { -3 };
            let value =
                (16 + (imm8 & 15)) as f64 / 16.0 * 2f64.powi(exponent) * if imm8 & 0x80 == 0 { 1.0 } else { -1.0 };
            let expected = if double {
                value.to_bits()
            } else {
                u64::from((value as f32).to_bits())
            };
            for rd in 0..32 {
                let word = 0x1E20_1000 | (u32::from(double) << 22) | (imm8 << 13) | rd;
                let insn = decode(word)?;
                assert_eq!(insn.form_id, if double { forms_fp::FMOV_ID } else { forms_fp::FMOV_IS });
                assert_eq!(insn.operands.len(), 2);
                let destination = &insn.operands[0];
                assert_eq!(destination.access, AccessKind::Write);
                assert_eq!(destination.visibility, OperandVisibility::Explicit);
                assert_eq!(destination.width_bits, if double { 64 } else { 32 });
                let OperandKind::Register(view) = destination.kind else {
                    return Err(format!("expected FP destination register, got {:?}", destination.kind));
                };
                assert_eq!(view.parent.0, 36 + rd);
                assert_eq!(view.width_bits, destination.width_bits);
                let immediate = &insn.operands[1];
                assert_eq!(immediate.access, AccessKind::Read);
                assert_eq!(immediate.width_bits, destination.width_bits);
                let OperandKind::Immediate(value) = immediate.kind else {
                    return Err(format!("expected FP immediate operand, got {:?}", immediate.kind));
                };
                assert_eq!(value.value, expected, "{word:08x}");
                assert_eq!(value.signed, imm8 & 0x80 != 0);
            }
        }
    }
    Ok(())
}

#[test]
fn fmov_immediate_fixed_fields_do_not_alias_other_forms() {
    let decoder = Arm64Decoder::with_profile_id(TargetProfileId(3));
    let variable = (1 << 22) | (255 << 13) | 31;
    for double in [false, true] {
        for imm8 in 0..256u32 {
            let base = 0x1E20_1000 | (u32::from(double) << 22) | (imm8 << 13) | 31;
            for bit in 0..32 {
                if variable & (1 << bit) != 0 {
                    continue;
                }
                let word: u32 = base ^ (1 << bit);
                if let Ok(insn) = decoder.decode(0x1000, &word.to_le_bytes()) {
                    assert!(
                        ![forms_fp::FMOV_IS, forms_fp::FMOV_ID].contains(&insn.form_id),
                        "{word:08x}"
                    );
                }
                // Rn is reserved, not a hidden source; type[1] is outside S/D.
                if (5..10).contains(&bit) || bit == 23 {
                    assert!(decoder.decode(0x1000, &word.to_le_bytes()).is_err(), "{word:08x}");
                }
            }
        }
    }
}

#[test]
fn fcvt_fcsel_forms() -> Result<(), String> {
    // llvm-mc: fcvt s0, d1 = 0x1E624020, fcvt d0, s1 = 0x1E22C020.
    assert_eq!(decode(0x1E62_4020)?.form_id, forms_fp::FCVT_S_D);
    assert_eq!(decode(0x1E22_C020)?.form_id, forms_fp::FCVT_D_S);
    // fcsel s0, s1, s2, eq = 0x1E220C20; fcsel d0, d1, d2, ne = 0x1E621C20.
    assert_eq!(decode(0x1E22_0C20)?.form_id, forms_fp::FCSEL_S);
    let insn = decode(0x1E62_1C20)?;
    assert_eq!(insn.form_id, forms_fp::FCSEL_D);
    match &insn.operands[3].kind {
        OperandKind::Immediate(op) => assert_eq!(op.value, 1), // NE
        other => return Err(format!("expected condition immediate, got {other:?}")),
    }
    Ok(())
}

#[test]
fn fcvtz_forms() -> Result<(), String> {
    use angryier_arch::{AccessKind, OperandVisibility, RegisterWriteBehavior};
    for (base, form, dst_width, src_width) in [
        (0x1E38_0000, forms_fp::FCVTZS_W_S, 32, 32),
        (0x1E78_0000, forms_fp::FCVTZS_W_D, 32, 64),
        (0x9E38_0000, forms_fp::FCVTZS_X_S, 64, 32),
        (0x9E78_0000, forms_fp::FCVTZS_X_D, 64, 64),
        (0x1E39_0000, forms_fp::FCVTZU_W_S, 32, 32),
        (0x1E79_0000, forms_fp::FCVTZU_W_D, 32, 64),
        (0x9E39_0000, forms_fp::FCVTZU_X_S, 64, 32),
        (0x9E79_0000, forms_fp::FCVTZU_X_D, 64, 64),
    ] {
        for rn in 0..32 {
            for rd in 0..32 {
                let insn = decode(base | (rn << 5) | rd)?;
                assert_eq!(insn.form_id, form);
                assert_eq!(insn.operands.len(), 2);
                for (index, width, access, parent) in [
                    (0, dst_width, AccessKind::Write, rd),
                    (1, src_width, AccessKind::Read, 36 + rn),
                ] {
                    let operand = &insn.operands[index];
                    assert_eq!(operand.index, index as u8);
                    assert_eq!(operand.width_bits, width);
                    assert_eq!(operand.access, access);
                    assert_eq!(operand.visibility, OperandVisibility::Explicit);
                    let OperandKind::Register(view) = operand.kind else {
                        return Err(format!("expected register operand, got {:?}", operand.kind));
                    };
                    assert_eq!(view.parent.0, parent);
                    assert_eq!(view.width_bits, width);
                    assert_eq!(view.bit_offset, 0);
                    assert_eq!(
                        view.write_behavior,
                        if index == 0 && dst_width == 64 {
                            RegisterWriteBehavior::ReplaceParent
                        } else {
                            RegisterWriteBehavior::ZeroExtendParent
                        }
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn fcsel_all_conditions_and_register_fields() -> Result<(), String> {
    for double in [false, true] {
        for rm in 0..32 {
            for cond in 0..16 {
                for (rd, rn) in [(0, 1), (17, 30), (31, 31)] {
                    let word = 0x1E20_0C00 | (u32::from(double) << 22) | (rm << 16) | (cond << 12) | (rn << 5) | rd;
                    let insn = decode(word)?;
                    assert_eq!(insn.form_id, if double { forms_fp::FCSEL_D } else { forms_fp::FCSEL_S });
                    for (index, reg) in [(0, rd), (1, rn), (2, rm)] {
                        let OperandKind::Register(view) = insn.operands[index].kind else {
                            return Err(format!(
                                "expected FP register operand, got {:?}",
                                insn.operands[index].kind
                            ));
                        };
                        assert_eq!(view.parent.0, 36 + reg);
                        assert_eq!(view.width_bits, if double { 64 } else { 32 });
                    }
                    let OperandKind::Immediate(value) = insn.operands[3].kind else {
                        return Err(format!("expected condition immediate, got {:?}", insn.operands[3].kind));
                    };
                    assert_eq!(value.value, u64::from(cond));
                    assert!(!value.signed);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn fcvt_precisions_and_register_fields() -> Result<(), String> {
    for (base, form, dst_width, src_width) in [
        (0x1E62_4000, forms_fp::FCVT_S_D, 32, 64),
        (0x1E22_C000, forms_fp::FCVT_D_S, 64, 32),
    ] {
        for rn in 0..32 {
            for rd in 0..32 {
                let insn = decode(base | (rn << 5) | rd)?;
                assert_eq!(insn.form_id, form);
                for (index, reg, width) in [(0, rd, dst_width), (1, rn, src_width)] {
                    let OperandKind::Register(view) = insn.operands[index].kind else {
                        return Err(format!(
                            "expected FP register operand, got {:?}",
                            insn.operands[index].kind
                        ));
                    };
                    assert_eq!(view.parent.0, 36 + reg);
                    assert_eq!(view.width_bits, width);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn conversion_and_selection_reserved_encodings_are_rejected() {
    let decoder = Arm64Decoder::with_profile_id(TargetProfileId(3));
    for base in [
        0x1E38_0020,
        0x1E78_0020,
        0x9E38_0020,
        0x9E78_0020,
        0x1E39_0020,
        0x1E79_0020,
        0x9E39_0020,
        0x9E79_0020,
    ] {
        // type=10 is reserved; type=11 is FP16 (outside this subset).
        let word: u32 = base | (1 << 23);
        assert!(decoder.decode(0x1000, &word.to_le_bytes()).is_err(), "{word:08x}");
        // Mutating the top-level class must not produce any FCVTZ form,
        // independently of what another decoder family does with the word.
        for bit in [29, 30] {
            let word: u32 = base | (1 << bit);
            if let Ok(insn) = decoder.decode(0x1000, &word.to_le_bytes()) {
                assert!(!(forms_fp::FCVTZS_W_S..=forms_fp::FCVTZU_X_D).contains(&insn.form_id));
            }
        }
    }
    for word in [
        0x1E70_0020u32, // FCVTMS W0,D1: different rounding mode
        0x1E18_FC20,    // FCVTZS W0,S1,#1: fixed-point scale, not integer form
        0x1E38_0420,    // nonzero reserved conversion opcode bits
        0x1E22_4020,    // FCVT S0,S1: invalid identical precision
        0x1E62_C020,    // FCVT D0,D1: invalid identical precision
        0x9E62_4020,    // FCVT has no sf/X variant
        0x1EE2_4020,    // FCVT source FP16 is outside subset
        0x1EA2_4020,    // FCVT reserved source precision
        0x9E22_0C20,    // FCSEL has no sf/X variant
        0x1EA2_0C20,    // FCSEL reserved precision
        0x1EE2_0C20,    // FCSEL FP16 outside subset
    ] {
        assert!(decoder.decode(0x1000, &word.to_le_bytes()).is_err(), "{word:08x}");
    }
}
