//! decode_shifts — variable-shift extension decode group (LSLV/LSRV/ASRV/RORV).
//! Owned by a parallel work stream.

use angryier_arch::{
    AccessKind, DecodedInstruction, FeatureId, InstructionModifiers, Operand, OperandKind, OperandVisibility,
    RegisterView,
};
use angryier_types::{Address, TargetProfileId};

use crate::Arm64DecodeError;
use crate::forms_shifts;
use crate::regs;

#[inline]
fn bits(word: u32, hi: u32, lo: u32) -> u32 {
    (word >> lo) & ((1 << (hi - lo + 1)) - 1)
}

#[inline]
fn bit(word: u32, n: u32) -> u32 {
    (word >> n) & 1
}

fn modifiers() -> InstructionModifiers {
    InstructionModifiers {
        encoding: crate::encoding_class::A64,
        ..InstructionModifiers::default()
    }
}

fn reg_operand(index: u8, view: RegisterView, access: AccessKind) -> Operand {
    Operand {
        index,
        width_bits: view.width_bits,
        access,
        visibility: OperandVisibility::Explicit,
        kind: OperandKind::Register(view),
    }
}

fn instruction(_profile: TargetProfileId, address: Address, form: u32, operands: Vec<Operand>) -> DecodedInstruction {
    DecodedInstruction {
        address,
        length: 4,
        form_id: form,
        features: vec![FeatureId(0)],
        operands,
        modifiers: modifiers(),
    }
}

/// Data-processing (2 source), variable-shift register: `bits[28:21] ==
/// 0b11010110` with the 2-source opcode `0b0010` at `bits[15:12]`; the shift
/// kind lives at `bits[11:10]` (00=LSLV, 01=LSRV, 10=ASRV, 11=RORV) and `sf`
/// (bit 31) selects the 64-bit X form.
pub(crate) fn try_decode(
    profile: TargetProfileId,
    address: Address,
    word: u32,
) -> Option<Result<DecodedInstruction, Arm64DecodeError>> {
    if bits(word, 28, 21) != 0b1101_0110 || bits(word, 15, 12) != 0b0010 {
        return None;
    }
    let sf = bit(word, 31);
    let rm = bits(word, 20, 16);
    let rn = bits(word, 9, 5);
    let rd = bits(word, 4, 0);
    let form = match (bits(word, 11, 10), sf) {
        (0b00, 0) => forms_shifts::LSLV_W,
        (0b00, 1) => forms_shifts::LSLV_X,
        (0b01, 0) => forms_shifts::LSRV_W,
        (0b01, 1) => forms_shifts::LSRV_X,
        (0b10, 0) => forms_shifts::ASRV_W,
        (0b10, 1) => forms_shifts::ASRV_X,
        (0b11, 0) => forms_shifts::RORV_W,
        _ => forms_shifts::RORV_X,
    };
    let operands = vec![
        reg_operand(0, regs::gpr_view(rd, sf, false), AccessKind::Write),
        reg_operand(1, regs::gpr_view(rn, sf, false), AccessKind::Read),
        reg_operand(2, regs::gpr_view(rm, sf, false), AccessKind::Read),
    ];
    Some(Ok(instruction(profile, address, form, operands)))
}
