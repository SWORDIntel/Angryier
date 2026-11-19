//! Golden decode vectors for the FP/SIMD memory forms (LDR/STR S/D/Q, LDUR/
//! STUR, register-offset, pre/post-index, PC-relative literal loads, and
//! LDP/STP S/D pairs), drawn from llvm-mc (`-triple=aarch64 -show-encoding`).

use angryier_arch::{Decoder, OperandKind};
use angryier_arch_arm64::{Arm64Decoder, forms::FORM_BASE};
use angryier_types::TargetProfileId;

// The form ids live in the pub(crate) `forms_simd` module, so the integration
// test re-derives them from the public FORM_BASE and the 0x190 extension offset.
const LDR_S: u32 = FORM_BASE + 0x190;
const LDR_D: u32 = FORM_BASE + 0x191;
const LDR_Q: u32 = FORM_BASE + 0x192;
const STR_S: u32 = FORM_BASE + 0x193;
const STR_D: u32 = FORM_BASE + 0x194;
const STR_Q: u32 = FORM_BASE + 0x195;
const LDUR_S: u32 = FORM_BASE + 0x196;
const LDUR_D: u32 = FORM_BASE + 0x197;
const LDUR_Q: u32 = FORM_BASE + 0x198;
const STUR_S: u32 = FORM_BASE + 0x199;
const STUR_D: u32 = FORM_BASE + 0x19A;
const STUR_Q: u32 = FORM_BASE + 0x19B;
const LDR_S_LIT: u32 = FORM_BASE + 0x19C;
const LDR_D_LIT: u32 = FORM_BASE + 0x19D;
const LDR_S_REG: u32 = FORM_BASE + 0x19E;
const LDR_D_REG: u32 = FORM_BASE + 0x19F;
const LDR_Q_REG: u32 = FORM_BASE + 0x1A0;
const STR_S_REG: u32 = FORM_BASE + 0x1A1;
const STR_D_REG: u32 = FORM_BASE + 0x1A2;
const STR_Q_REG: u32 = FORM_BASE + 0x1A3;
const LDP_S: u32 = FORM_BASE + 0x1A4;
const LDP_D: u32 = FORM_BASE + 0x1A5;
const STP_S: u32 = FORM_BASE + 0x1A6;
const STP_D: u32 = FORM_BASE + 0x1A7;
const LDR_S_POST: u32 = FORM_BASE + 0x1A8;
const LDR_D_POST: u32 = FORM_BASE + 0x1A9;
const STR_S_POST: u32 = FORM_BASE + 0x1AA;
const STR_D_POST: u32 = FORM_BASE + 0x1AB;
const LDR_S_PRE: u32 = FORM_BASE + 0x1AC;
const LDR_D_PRE: u32 = FORM_BASE + 0x1AD;
const STR_S_PRE: u32 = FORM_BASE + 0x1AE;
const STR_D_PRE: u32 = FORM_BASE + 0x1AF;

fn decoder() -> Arm64Decoder {
    Arm64Decoder::with_profile_id(TargetProfileId(7))
}

fn decode(word: u32) -> Result<angryier_arch::DecodedInstruction, Box<dyn std::error::Error>> {
    let bytes = word.to_le_bytes();
    Ok(decoder().decode(0x1000, &bytes)?)
}

/// Asserts the form id and the memory operand displacement at operand `mem`.
fn assert_mem(
    insn: &angryier_arch::DecodedInstruction,
    form: u32,
    mem: u8,
    displacement: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(insn.form_id, form);
    match &insn.operands[usize::from(mem)].kind {
        OperandKind::Memory(mem) => assert_eq!(mem.displacement, displacement),
        other => return Err(format!("unexpected operand {other:?}").into()),
    }
    Ok(())
}

#[test]
fn ldr_str_scaled_imm() -> Result<(), Box<dyn std::error::Error>> {
    assert_mem(&decode(0xBD40_0420)?, LDR_S, 1, 4)?; // ldr s0, [x1, #4]
    assert_mem(&decode(0xFD40_0420)?, LDR_D, 1, 8)?; // ldr d0, [x1, #8]
    assert_mem(&decode(0x3DC0_0420)?, LDR_Q, 1, 16)?; // ldr q0, [x1, #16]
    assert_mem(&decode(0xBD00_0420)?, STR_S, 1, 4)?; // str s0, [x1, #4]
    assert_mem(&decode(0xFD00_0420)?, STR_D, 1, 8)?; // str d0, [x1, #8]
    assert_mem(&decode(0x3D80_07E0)?, STR_Q, 1, 16)?; // str q0, [sp, #16]
    Ok(())
}

#[test]
fn ldur_stur_unscaled() -> Result<(), Box<dyn std::error::Error>> {
    assert_mem(&decode(0xBC5F_C020)?, LDUR_S, 1, -4)?; // ldur s0, [x1, #-4]
    assert_mem(&decode(0xFC40_8020)?, LDUR_D, 1, 8)?; // ldur d0, [x1, #8]
    assert_mem(&decode(0x3CC1_0020)?, LDUR_Q, 1, 16)?; // ldur q0, [x1, #16]
    assert_mem(&decode(0xBC1F_C020)?, STUR_S, 1, -4)?; // stur s0, [x1, #-4]
    assert_mem(&decode(0xFC00_8020)?, STUR_D, 1, 8)?; // stur d0, [x1, #8]
    assert_mem(&decode(0x3C81_0020)?, STUR_Q, 1, 16)?; // stur q0, [x1, #16]
    Ok(())
}

#[test]
fn ldst_register_offset() -> Result<(), Box<dyn std::error::Error>> {
    assert_mem(&decode(0xBC62_6820)?, LDR_S_REG, 1, 0)?; // ldr s0, [x1, x2]
    assert_mem(&decode(0xFC62_6820)?, LDR_D_REG, 1, 0)?; // ldr d0, [x1, x2]
    assert_mem(&decode(0x3CE2_6820)?, LDR_Q_REG, 1, 0)?; // ldr q0, [x1, x2]
    assert_mem(&decode(0xBC22_6820)?, STR_S_REG, 1, 0)?; // str s0, [x1, x2]
    assert_mem(&decode(0xFC22_6820)?, STR_D_REG, 1, 0)?; // str d0, [x1, x2]
    assert_mem(&decode(0x3CA2_6820)?, STR_Q_REG, 1, 0)?; // str q0, [x1, x2]

    // Scaled register offset (S bit set): ldr s0, [x1, x2, lsl #2].
    let insn = decode(0xBC62_7820)?;
    assert_eq!(insn.form_id, LDR_S_REG);
    match &insn.operands[1].kind {
        OperandKind::Memory(mem) => {
            assert_eq!(mem.scale, 4);
            assert!(mem.index.is_some());
        }
        other => return Err(format!("unexpected operand {other:?}").into()),
    }
    Ok(())
}

#[test]
fn ldst_pre_post_index() -> Result<(), Box<dyn std::error::Error>> {
    assert_mem(&decode(0xBC40_4C20)?, LDR_S_PRE, 1, 4)?; // ldr s0, [x1, #4]!
    assert_mem(&decode(0xFC40_8C20)?, LDR_D_PRE, 1, 8)?; // ldr d0, [x1, #8]!
    assert_mem(&decode(0xBC00_4C20)?, STR_S_PRE, 1, 4)?; // str s0, [x1, #4]!
    assert_mem(&decode(0xFC00_8C20)?, STR_D_PRE, 1, 8)?; // str d0, [x1, #8]!
    assert_mem(&decode(0xBC40_4420)?, LDR_S_POST, 1, 4)?; // ldr s0, [x1], #4
    assert_mem(&decode(0xFC40_8420)?, LDR_D_POST, 1, 8)?; // ldr d0, [x1], #8
    assert_mem(&decode(0xBC00_4420)?, STR_S_POST, 1, 4)?; // str s0, [x1], #4
    assert_mem(&decode(0xFC00_8420)?, STR_D_POST, 1, 8)?; // str d0, [x1], #8
    Ok(())
}

#[test]
fn ldr_literal() -> Result<(), Box<dyn std::error::Error>> {
    assert_mem(&decode(0x1C00_0800)?, LDR_S_LIT, 1, 256)?; // ldr s0, #256
    assert_mem(&decode(0x5C00_1001)?, LDR_D_LIT, 1, 512)?; // ldr d1, #512
    Ok(())
}

#[test]
fn ldp_stp_pairs() -> Result<(), Box<dyn std::error::Error>> {
    assert_mem(&decode(0x2D41_07E0)?, LDP_S, 2, 8)?; // ldp s0, s1, [sp, #8]
    assert_mem(&decode(0x6D40_87E0)?, LDP_D, 2, 8)?; // ldp d0, d1, [sp, #8]
    assert_mem(&decode(0x2D01_07E0)?, STP_S, 2, 8)?; // stp s0, s1, [sp, #8]
    assert_mem(&decode(0x6D00_87E0)?, STP_D, 2, 8)?; // stp d0, d1, [sp, #8]

    // Post-index: stp d0, d1, [sp], #16! (write-back base + mode tag operands).
    let insn = decode(0x6C81_07E0)?;
    assert_eq!(insn.form_id, STP_D);
    match &insn.operands[2].kind {
        OperandKind::Memory(mem) => assert_eq!(mem.displacement, 16),
        other => return Err(format!("unexpected operand {other:?}").into()),
    }
    assert_eq!(insn.operands.len(), 5);
    // Pre-index: ldp s0, s1, [sp, #8]!.
    let insn = decode(0x2DC1_07E0)?;
    assert_eq!(insn.form_id, LDP_S);
    match &insn.operands[2].kind {
        OperandKind::Memory(mem) => assert_eq!(mem.displacement, 8),
        other => return Err(format!("unexpected operand {other:?}").into()),
    }
    assert_eq!(insn.operands.len(), 5);
    Ok(())
}

#[test]
fn q_pairs_and_acquire_release() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_arch_arm64::forms_simd;
    // llvm-mc: stp q0, q1, [x2] = 0xAD000440.
    assert_eq!(decode(0xAD00_0440)?.form_id, forms_simd::STP_Q);
    // ldp q0, q1, [x2] = 0xAD400440.
    assert_eq!(decode(0xAD40_0440)?.form_id, forms_simd::LDP_Q);
    // ldar x8, [x9] = 0xC8DFFD28.
    assert_eq!(decode(0xC8DF_FD28)?.form_id, forms_simd::LDAR_X);
    // ldarb w8, [x9] = 0x08DFFD28.
    assert_eq!(decode(0x08DF_FD28)?.form_id, forms_simd::LDAR_B);
    // stlr x8, [x9] = 0xC89FFD28.
    assert_eq!(decode(0xC89F_FD28)?.form_id, forms_simd::STLR_X);
    // stlrh w8, [x9] = 0x489FFD28.
    assert_eq!(decode(0x489F_FD28)?.form_id, forms_simd::STLR_H);
    Ok(())
}

#[test]
fn simd_arithmetic_forms() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_arch_arm64::forms_simd;
    // mov v0.16b, v1.16b = 0x4EA11C20.
    assert_eq!(decode(0x4EA1_1C20)?.form_id, forms_simd::MOV_V);
    // add v0.16b, v1.16b, v2.16b = 0x4E228420.
    assert_eq!(decode(0x4E22_8420)?.form_id, forms_simd::ADD_V16B);
    // add v0.8h, v1.8h, v2.8h = 0x4E628420.
    assert_eq!(decode(0x4E62_8420)?.form_id, forms_simd::ADD_V8H);
    // add v0.4s, v1.4s, v2.4s = 0x4EA28420.
    assert_eq!(decode(0x4EA2_8420)?.form_id, forms_simd::ADD_V4S);
    // add v0.2d, v1.2d, v2.2d = 0x4EE28420.
    assert_eq!(decode(0x4EE2_8420)?.form_id, forms_simd::ADD_V2D);
    // sub v0.4s = 0x6EA28420.
    assert_eq!(decode(0x6EA2_8420)?.form_id, forms_simd::SUB_V4S);
    // and/orr/eor v16b.
    assert_eq!(decode(0x4E22_1C20)?.form_id, forms_simd::AND_V16B);
    assert_eq!(decode(0x4EA2_1C20)?.form_id, forms_simd::ORR_V16B);
    assert_eq!(decode(0x6E22_1C20)?.form_id, forms_simd::EOR_V16B);
    // fadd v0.2s = 0x0E22D420, fadd v0.4s = 0x4E22D420, fadd v0.2d = 0x4E62D420.
    assert_eq!(decode(0x0E22_D420)?.form_id, forms_simd::FADD_V2S);
    assert_eq!(decode(0x4E22_D420)?.form_id, forms_simd::FADD_V4S);
    assert_eq!(decode(0x4E62_D420)?.form_id, forms_simd::FADD_V2D);
    // fmul v0.4s = 0x6E22DC20, fsub v0.2d = 0x4EE2D420, fdiv v0.4s = 0x6E22FC20.
    assert_eq!(decode(0x6E22_DC20)?.form_id, forms_simd::FMUL_V4S);
    assert_eq!(decode(0x4EE2_D420)?.form_id, forms_simd::FSUB_V2D);
    assert_eq!(decode(0x6E22_FC20)?.form_id, forms_simd::FDIV_V4S);
    Ok(())
}
