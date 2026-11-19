//! Golden decode vectors for the A64 subset, drawn from real AArch64 machine
//! words observed in disassembly of real-world Android shared objects plus
//! hand-verified encodings from the ARM ARM.

use std::error::Error;

use angryier_arch::{Decoder, OperandKind, RegisterView};
use angryier_arch_arm64::{Arm64Decoder, Arm64RegisterFile, forms, regs::register_id};
use angryier_types::TargetProfileId;

fn decoder() -> Arm64Decoder {
    Arm64Decoder::with_profile_id(TargetProfileId(7))
}

fn decode(word: u32) -> Result<angryier_arch::DecodedInstruction, Box<dyn Error>> {
    let bytes = word.to_le_bytes();
    Ok(decoder().decode(0x1000, &bytes)?)
}

#[test]
fn registers_are_canonical() -> Result<(), Box<dyn Error>> {
    let file = Arm64RegisterFile::canonical();
    assert_eq!(file.gprs.len(), 32);
    assert_eq!(register_id::X0.0, 0);
    assert_eq!(register_id::X30.0, 30);
    assert_eq!(register_id::SP.0, 68);
    Ok(())
}

#[test]
fn bl_displacement() -> Result<(), Box<dyn Error>> {
    // bl +0x19aa10 (titan disassembly 0x94066a84).
    let insn = decode(0x9406_6a84)?;
    assert_eq!(insn.form_id, forms::BL);
    match &insn.operands[0].kind {
        OperandKind::RelativeBranch(op) => assert_eq!(op.displacement, 0x19aa10),
        other => return Err(format!("unexpected operand {other:?}").into()),
    }
    Ok(())
}

#[test]
fn b_unconditional() -> Result<(), Box<dyn Error>> {
    let insn = decode(0x17ff_fff6)?; // b -0x28
    assert_eq!(insn.form_id, forms::B);
    match &insn.operands[0].kind {
        OperandKind::RelativeBranch(op) => assert_eq!(op.displacement, -0x28),
        other => return Err(format!("unexpected operand {other:?}").into()),
    }
    Ok(())
}

#[test]
fn b_cond() -> Result<(), Box<dyn Error>> {
    // b.eq +0x20 (titan: 54000020 is b.eq; use a known encoding).
    let insn = decode(0x5400_0020)?;
    assert_eq!(insn.form_id, forms::B_COND_BASE); // EQ
    Ok(())
}

#[test]
fn cbz_cbnz() -> Result<(), Box<dyn Error>> {
    let cbz = decode(0xb400_0040)?; // cbz x0, +8
    assert_eq!(cbz.form_id, forms::CBZ_X);
    let cbnz = decode(0xb500_0040)?; // cbnz x0, +8
    assert_eq!(cbnz.form_id, forms::CBNZ_X);
    Ok(())
}

#[test]
fn tbz_tbnz() -> Result<(), Box<dyn Error>> {
    let tbz = decode(0x3628_0040)?; // tbz w0, #5, +8
    assert_eq!(tbz.form_id, forms::TBZ);
    assert_eq!(tbz.operands[0].width_bits, 32);
    match &tbz.operands[1].kind {
        OperandKind::Immediate(bit) => assert_eq!(bit.value, 5),
        other => return Err(format!("unexpected operand {other:?}").into()),
    }
    match &tbz.operands[2].kind {
        OperandKind::RelativeBranch(branch) => assert_eq!(branch.displacement, 8),
        other => return Err(format!("unexpected operand {other:?}").into()),
    }
    let tbnz = decode(0xb740_0042)?; // tbnz x2, #40, +8
    assert_eq!(tbnz.form_id, forms::TBNZ);
    assert_eq!(tbnz.operands[0].width_bits, 64);
    match &tbnz.operands[1].kind {
        OperandKind::Immediate(bit) => assert_eq!(bit.value, 40),
        other => return Err(format!("unexpected operand {other:?}").into()),
    }
    Ok(())
}

#[test]
fn ret_blr_br() -> Result<(), Box<dyn Error>> {
    let ret = decode(0xd65f_03c0)?;
    assert_eq!(ret.form_id, forms::RET);
    match &ret.operands[0].kind {
        OperandKind::Register(RegisterView { parent, .. }) => assert_eq!(parent.0, 30),
        other => return Err(format!("unexpected operand {other:?}").into()),
    }
    let blr = decode(0xd63f_0280)?; // blr x20 (titan)
    assert_eq!(blr.form_id, forms::BLR);
    let br = decode(0xd61f_0100)?; // br x8 (titan)
    assert_eq!(br.form_id, forms::BR);
    Ok(())
}

#[test]
fn add_sub_immediate() -> Result<(), Box<dyn Error>> {
    // add x8, x8, #0x28 (titan 0x9100a108).
    let insn = decode(0x9100_a108)?;
    assert_eq!(insn.form_id, forms::ADD_X_IMM);
    match &insn.operands[2].kind {
        OperandKind::Immediate(op) => assert_eq!(op.value, 0x28),
        other => return Err(format!("unexpected operand {other:?}").into()),
    }
    // subs w8, w8, #0x2 (titan 0x71000408 shape).
    let insn = decode(0x7100_0408)?;
    assert_eq!(insn.form_id, forms::SUBS_W_IMM);
    Ok(())
}

#[test]
fn add_sub_shifted_register() -> Result<(), Box<dyn Error>> {
    // sub w8, w8, w8, lsl #2 (titan 0x4b080908).
    let insn = decode(0x4b08_0908)?;
    assert_eq!(insn.form_id, forms::SUB_W_REG);
    assert_eq!(insn.operands.len(), 5);
    Ok(())
}

#[test]
fn logical_shifted_register() -> Result<(), Box<dyn Error>> {
    // and x0, x0, x8 (titan 0x8a080000 shape: and x0,x0,x8).
    let insn = decode(0x8a08_0000)?;
    assert_eq!(insn.form_id, forms::AND_X_REG);
    // orr x19, x8, x9 (0xaa090113)
    let insn = decode(0xaa09_0113)?;
    assert_eq!(insn.form_id, forms::ORR_X_REG);
    Ok(())
}

#[test]
fn wide_immediate_movz_movk() -> Result<(), Box<dyn Error>> {
    // movz w8, #0x35 (titan 0x52800068 is mov w8,#0x3; use movz w8,#0x35 = 0x528006a8)
    let insn = decode(0x5280_06a8)?;
    assert_eq!(insn.form_id, forms::MOVZ_W);
    // movk w8, #0x35, lsl #16 (titan 0x72a006a8 shape)
    let insn = decode(0x72a0_06a8)?;
    assert_eq!(insn.form_id, forms::MOVK_W);
    Ok(())
}

#[test]
fn csel() -> Result<(), Box<dyn Error>> {
    // csel w0, w1, w2, eq = 0x1a820020 (verified against ARM ARM).
    let insn = decode(0x1a82_0020)?;
    assert_eq!(insn.form_id, forms::CSEL_W);
    Ok(())
}

#[test]
fn madd() -> Result<(), Box<dyn Error>> {
    // madd w8, w8, w8, w8 = 0x1b080908.
    let insn = decode(0x1b08_0908)?;
    assert_eq!(insn.form_id, forms::MADD_W);
    Ok(())
}

#[test]
fn ldr_str_unsigned_imm() -> Result<(), Box<dyn Error>> {
    // ldr x8, [x21] (titan 0xf94002a8).
    let insn = decode(0xf940_02a8)?;
    assert_eq!(insn.form_id, forms::LDR_X);
    // str w8, [sp, #8] (titan 0xb9000be8).
    let insn = decode(0xb900_0be8)?;
    assert_eq!(insn.form_id, forms::STR_W);
    match &insn.operands[1].kind {
        OperandKind::Memory(mem) => {
            assert_eq!(mem.displacement, 8);
        }
        other => return Err(format!("unexpected operand {other:?}").into()),
    }
    // strh w9, [sp, #12] (titan 0x79001be9).
    let insn = decode(0x7900_1be9)?;
    assert_eq!(insn.form_id, forms::STR_H);
    Ok(())
}

#[test]
fn ldrsw() -> Result<(), Box<dyn Error>> {
    // ldrsw x8, [x19, #8] = 0xb9801268.
    let insn = decode(0xb980_1268)?;
    assert_eq!(insn.form_id, forms::LDRSW);
    Ok(())
}

#[test]
fn ldur_stur() -> Result<(), Box<dyn Error>> {
    // ldur w0, [x1, #4] = 0xb8401020.
    let insn = decode(0xb840_1020)?;
    assert_eq!(insn.form_id, forms::LDUR_W);
    // ldur x0, [x29, #-40] = 0xf85d83a0 (bit22=1 selects LDUR).
    let insn = decode(0xf85d_83a0)?;
    assert_eq!(insn.form_id, forms::LDUR_X);
    match &insn.operands[1].kind {
        OperandKind::Memory(mem) => assert_eq!(mem.displacement, -40),
        other => return Err(format!("unexpected operand {other:?}").into()),
    }
    // stur x8, [x29, #-40] = 0xf81d03a8.
    let insn = decode(0xf81d_03a8)?;
    assert_eq!(insn.form_id, forms::STUR_X);
    Ok(())
}

#[test]
fn ldst_register_offset() -> Result<(), Box<dyn Error>> {
    // ldr w9, [x19, x9, lsl #2] = 0xb8697a69.
    let word = 0xb869_7a69;
    let insn = decode(word)?;
    assert_eq!(insn.form_id, forms::LDR_W_REG);
    match &insn.operands[1].kind {
        OperandKind::Memory(mem) => {
            assert_eq!(mem.scale, 4);
            assert!(matches!(
                mem.index,
                Some(angryier_arch::MemoryIndex::ExtendedRegister {
                    extension: angryier_arch::MemoryIndexExtension::Uxtx,
                    ..
                })
            ));
        }
        other => return Err(format!("unexpected operand {other:?}").into()),
    }
    for (option, extension) in [
        (0b010, angryier_arch::MemoryIndexExtension::Uxtw),
        (0b011, angryier_arch::MemoryIndexExtension::Uxtx),
        (0b110, angryier_arch::MemoryIndexExtension::Sxtw),
        (0b111, angryier_arch::MemoryIndexExtension::Sxtx),
    ] {
        let word = (word & !(0b111 << 13)) | (option << 13);
        let decoded = decode(word)?;
        match &decoded.operands[1].kind {
            OperandKind::Memory(mem) => assert!(matches!(
                mem.index,
                Some(angryier_arch::MemoryIndex::ExtendedRegister { extension: found, .. }) if found == extension
            )),
            other => return Err(format!("unexpected operand {other:?}").into()),
        }
    }
    assert!(
        decode(word & !(0b111 << 13)).is_err(),
        "reserved option must stay unsupported"
    );
    Ok(())
}

#[test]
fn ldp_stp_preindex() -> Result<(), Box<dyn Error>> {
    // stp x29, x30, [sp, #-16]! (titan 0xa9bf7bfd).
    let insn = decode(0xa9bf_7bfd)?;
    assert_eq!(insn.form_id, forms::STP_X);
    match &insn.operands[2].kind {
        OperandKind::Memory(mem) => assert_eq!(mem.displacement, -16),
        other => return Err(format!("unexpected operand {other:?}").into()),
    }
    let post = decode(0xa881_0440)?; // stp x0, x1, [x2], #16
    match &post.operands[2].kind {
        OperandKind::Memory(mem) => assert_eq!(mem.displacement, 0),
        other => return Err(format!("unexpected operand {other:?}").into()),
    }
    match &post.operands[4].kind {
        OperandKind::Immediate(displacement) => assert_eq!(displacement.value, 16),
        other => return Err(format!("unexpected operand {other:?}").into()),
    }
    let pair_w = decode(0x2941_0440)?; // ldp w0, w1, [x2, #8]
    match &pair_w.operands[2].kind {
        OperandKind::Memory(mem) => assert_eq!(mem.displacement, 8),
        other => return Err(format!("unexpected operand {other:?}").into()),
    }
    Ok(())
}

#[test]
fn adr_adrp() -> Result<(), Box<dyn Error>> {
    // adr x8, +0x28 = 0x10000148.
    let insn = decode(0x1000_0148)?;
    assert_eq!(insn.form_id, forms::ADR);
    // adrp x8, page (titan 0x90000008: adrp x8, 0x62a000-page).
    let insn = decode(0x9000_0008)?;
    assert_eq!(insn.form_id, forms::ADRP);
    Ok(())
}

#[test]
fn nop_svc() -> Result<(), Box<dyn Error>> {
    let nop = decode(0xd503_201f)?;
    assert_eq!(nop.form_id, forms::NOP);
    let svc = decode(0xd400_0001)?;
    assert_eq!(svc.form_id, forms::SVC);
    Ok(())
}

#[test]
fn unsupported_word_reports_error() -> Result<(), Box<dyn Error>> {
    // fmov s0, #0.5 (FCVT — still outside the
    // subset).
    let bytes = 0x1E70_0020u32.to_le_bytes();
    let result = decoder().decode(0x2000, &bytes);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn adc_sbc_ccmp_forms() -> Result<(), Box<dyn Error>> {
    // adc x8, x9, x10 = 0x9A0A0128.
    let insn = decode(0x9A0A_0128)?;
    assert_eq!(insn.form_id, forms::ADC_X);
    // adcs w8, w9, w10 = 0x3A0A0128.
    let insn = decode(0x3A0A_0128)?;
    assert_eq!(insn.form_id, forms::ADCS_W);
    // sbc x8, x9, x10 = 0xDA0A0128.
    let insn = decode(0xDA0A_0128)?;
    assert_eq!(insn.form_id, forms::SBC_X);
    // sbcs w8, w9, w10 = 0x7A0A0128.
    let insn = decode(0x7A0A_0128)?;
    assert_eq!(insn.form_id, forms::SBCS_W);
    // ccmp w8, w9, #3, eq = 0x7A490103 (llvm-mc).
    let insn = decode(0x7A49_0103)?;
    assert_eq!(insn.form_id, forms::CCMP_W);
    // ccmn x8, x9, #3, ne = 0xBA491103 (llvm-mc).
    let insn = decode(0xBA49_1103)?;
    assert_eq!(insn.form_id, forms::CCMN_X);
    Ok(())
}

#[test]
fn csel_cset_family() -> Result<(), Box<dyn Error>> {
    // cset w9, ne = 0x1a9f07e9 (titan).
    let insn = decode(0x1A9F_07E9)?;
    assert_eq!(insn.form_id, forms::CSINC_W);
    // csel x0, x1, x2, eq = 0x9A820020.
    let insn = decode(0x9A82_0020)?;
    assert_eq!(insn.form_id, forms::CSEL_X);
    Ok(())
}

#[test]
fn div_forms() -> Result<(), Box<dyn Error>> {
    // sdiv w8, w2, w9 = 0x1ac90c48 (titan).
    let insn = decode(0x1AC9_0C48)?;
    assert_eq!(insn.form_id, forms::SDIV_W);
    // udiv x8, x9, x10 = 0x9ACA0928 (llvm-mc; bit10 = 0 selects unsigned).
    let insn = decode(0x9ACA_0928)?;
    assert_eq!(insn.form_id, forms::UDIV_X);
    Ok(())
}

#[test]
fn mul_long_forms() -> Result<(), Box<dyn Error>> {
    // umull x8, w0, w8 = 0x9ba87c08 (titan).
    let insn = decode(0x9BA8_7C08)?;
    assert_eq!(insn.form_id, forms::UMULL_X);
    // smaddl x8, w9, w10, x11 = 0x9B2A2D28 (llvm-mc).
    let insn = decode(0x9B2A_2D28)?;
    assert_eq!(insn.form_id, forms::SMADDL_X);
    // smull x8, w9, w10 = 0x9B2A7D28 (llvm-mc).
    let insn = decode(0x9B2A_7D28)?;
    assert_eq!(insn.form_id, forms::SMULL_X);
    Ok(())
}

#[test]
fn ldst_pre_post_index() -> Result<(), Box<dyn Error>> {
    // str x30, [sp, #-16]! = 0xf81f0ffe (titan).
    let insn = decode(0xF81F_0FFE)?;
    assert_eq!(insn.form_id, forms::STR_X_PRE);
    match &insn.operands[1].kind {
        OperandKind::Memory(mem) => assert_eq!(mem.displacement, -16),
        other => return Err(format!("unexpected operand {other:?}").into()),
    }
    // ldr x0, [x1], #8 = 0xf8408420 (llvm-mc).
    let insn = decode(0xF840_8420)?;
    assert_eq!(insn.form_id, forms::LDR_X_POST);
    Ok(())
}

#[test]
fn ldpsw_and_sign_extend_unscaled() -> Result<(), Box<dyn Error>> {
    // ldpsw x8, x9, [x21, #48] = 0x694626a8 (titan).
    let insn = decode(0x6946_26A8)?;
    assert_eq!(insn.form_id, forms::LDPSW);
    // ldursw x8, [x29, #-8] = 0xb89f83a8 (llvm-mc).
    let insn = decode(0xB89F_83A8)?;
    assert_eq!(insn.form_id, forms::LDURSW);
    // ldursb x8, [x29, #-1] = 0x389ff3a8 (llvm-mc).
    let insn = decode(0x389F_F3A8)?;
    assert_eq!(insn.form_id, forms::LDURSB_X);
    Ok(())
}
