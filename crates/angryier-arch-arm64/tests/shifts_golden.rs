//! Golden decode vectors for the A64 variable-shift family (LSLV/LSRV/ASRV/
//! RORV, W and X), drawn from llvm-mc (`llvm-mc -triple=aarch64 -show-encoding`).

use angryier_arch::{AccessKind, Decoder, Operand, OperandKind, RegisterView};
use angryier_arch_arm64::{Arm64Decoder, forms::FORM_BASE};
use angryier_types::TargetProfileId;

// The form ids live in the (pub(crate)) `forms_shifts` module, so the
// integration test re-derives them from the public FORM_BASE and the 0x130
// extension offset.
const LSLV_W: u32 = FORM_BASE + 0x130;
const LSLV_X: u32 = FORM_BASE + 0x131;
const LSRV_W: u32 = FORM_BASE + 0x132;
const LSRV_X: u32 = FORM_BASE + 0x133;
const ASRV_W: u32 = FORM_BASE + 0x134;
const ASRV_X: u32 = FORM_BASE + 0x135;
const RORV_W: u32 = FORM_BASE + 0x136;
const RORV_X: u32 = FORM_BASE + 0x137;

fn decoder() -> Arm64Decoder {
    Arm64Decoder::with_profile_id(TargetProfileId(7))
}

fn decode(word: u32) -> Result<angryier_arch::DecodedInstruction, Box<dyn std::error::Error>> {
    let bytes = word.to_le_bytes();
    Ok(decoder().decode(0x1000, &bytes)?)
}

/// Asserts a register operand's parent id, width, and access kind.
fn assert_reg(
    operand: &Operand,
    parent: u32,
    width_bits: u16,
    access: AccessKind,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(operand.access, access);
    match &operand.kind {
        OperandKind::Register(RegisterView {
            parent: view_parent,
            width_bits: view_width,
            ..
        }) => {
            assert_eq!(view_parent.0, parent);
            assert_eq!(*view_width, width_bits);
        }
        other => return Err(format!("unexpected operand {other:?}").into()),
    }
    Ok(())
}

/// Every variable-shift form decodes to three register operands: the written
/// destination Rd, the shifted value Rn, and the shift-amount Rm.
fn assert_shift_shape(
    insn: &angryier_arch::DecodedInstruction,
    form: u32,
    rd: u32,
    width: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(insn.form_id, form);
    assert_eq!(insn.operands.len(), 3);
    assert_reg(&insn.operands[0], rd, width, AccessKind::Write)?;
    assert_reg(&insn.operands[1], 0, width, AccessKind::Read)?; // Rn = x0
    assert_reg(&insn.operands[2], 1, width, AccessKind::Read)?; // Rm = x1
    Ok(())
}

#[test]
fn lslv_w_x() -> Result<(), Box<dyn std::error::Error>> {
    // lslv w2, w0, w1 = 0x1ac12002; lslv x2, x0, x1 = 0x9ac12002 (llvm-mc).
    assert_shift_shape(&decode(0x1AC1_2002)?, LSLV_W, 2, 32)?;
    assert_shift_shape(&decode(0x9AC1_2002)?, LSLV_X, 2, 64)?;
    Ok(())
}

#[test]
fn lsrv_w_x() -> Result<(), Box<dyn std::error::Error>> {
    // lsrv w3, w0, w1 = 0x1ac12403; lsrv x3, x0, x1 = 0x9ac12403 (llvm-mc).
    assert_shift_shape(&decode(0x1AC1_2403)?, LSRV_W, 3, 32)?;
    assert_shift_shape(&decode(0x9AC1_2403)?, LSRV_X, 3, 64)?;
    Ok(())
}

#[test]
fn asrv_w_x() -> Result<(), Box<dyn std::error::Error>> {
    // asrv w4, w0, w1 = 0x1ac12804; asrv x4, x0, x1 = 0x9ac12804 (llvm-mc).
    assert_shift_shape(&decode(0x1AC1_2804)?, ASRV_W, 4, 32)?;
    assert_shift_shape(&decode(0x9AC1_2804)?, ASRV_X, 4, 64)?;
    Ok(())
}

#[test]
fn rorv_w_x() -> Result<(), Box<dyn std::error::Error>> {
    // rorv w5, w0, w1 = 0x1ac12c05; rorv x5, x0, x1 = 0x9ac12c05 (llvm-mc).
    assert_shift_shape(&decode(0x1AC1_2C05)?, RORV_W, 5, 32)?;
    assert_shift_shape(&decode(0x9AC1_2C05)?, RORV_X, 5, 64)?;
    Ok(())
}

#[test]
fn non_shift_two_source_word_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    // udiv x8, x9, x10 (0x9ACA0928) shares bits[28:21] == 0b11010110 but has
    // bits[15:12] == 0b0000, so it must not be claimed by the shift group; the
    // core decoder already handles it and the extension returns None.
    let bytes = 0x9ACA_0928u32.to_le_bytes();
    let insn = decoder().decode(0x2000, &bytes)?;
    assert_eq!(insn.form_id, angryier_arch_arm64::forms::UDIV_X);
    Ok(())
}
