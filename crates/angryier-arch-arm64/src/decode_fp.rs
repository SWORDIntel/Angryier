//! Scalar FP decode (FADD/FSUB/FMUL/FDIV/FNEG/FSQRT/FABS/FCMP, FMOV
//! general<->FP, FMOV-immediate; S and D). Form residues and expansion
//! semantics cross-verified with llvm-mc (aarch64).

use angryier_arch::{AccessKind, DecodedInstruction};
use angryier_types::{Address, TargetProfileId};

use crate::Arm64DecodeError;
use crate::forms_fp;
use crate::regs;

fn bits(word: u32, hi: u32, lo: u32) -> u32 {
    (word >> lo) & ((1 << (hi - lo + 1)) - 1)
}

fn bit(word: u32, n: u32) -> u32 {
    (word >> n) & 1
}

/// Masks Rm[20:16], Rn[9:5], Rd[4:0] and the type bit[22].
const TWO_SOURCE_MASK: u32 = !((0x1F << 16) | (0x1F << 5) | 0x1F | (1 << 22));
/// Masks Rn[9:5], Rd[4:0] and the type bit[22].
const ONE_SOURCE_MASK: u32 = !((0x1F << 5) | 0x1F | (1 << 22));

fn instruction(address: Address, form: u32, operands: Vec<angryier_arch::Operand>) -> DecodedInstruction {
    DecodedInstruction {
        address,
        length: 4,
        form_id: form,
        features: vec![angryier_arch::FeatureId(0)],
        operands,
        modifiers: angryier_arch::InstructionModifiers {
            encoding: crate::encoding_class::A64,
            ..angryier_arch::InstructionModifiers::default()
        },
    }
}

fn fp_view(reg: u32, double: bool) -> angryier_arch::RegisterView {
    regs::v_view(reg, if double { 3 } else { 2 })
}

pub(crate) fn try_decode(
    _profile: TargetProfileId,
    address: Address,
    word: u32,
) -> Option<Result<DecodedInstruction, Arm64DecodeError>> {
    // Shared group gate: bits[28:24] == 0b11110 with bits[30:29] == 0b00
    // (0x1E-class S/W forms and 0x9E-class X/D forms; bit31 carries width
    // for the general<->FP moves).
    if let Some(decoded) = scvtf(address, word) {
        return Some(decoded);
    }
    if bits(word, 28, 24) != 0b1_1110 || bits(word, 30, 29) != 0b00 {
        return None;
    }

    // FMOV general<->FP (pure bit moves): 12-bit opcode at bits[21:10],
    // 0x980 = GPR destination, 0x9C0 = FP destination.
    if bits(word, 21, 10) == 0b1001_1000_0000 || bits(word, 21, 10) == 0b1001_1100_0000 {
        let to_fp = bits(word, 21, 10) == 0b1001_1100_0000;
        let word_size = bit(word, 31) == 1;
        let rn = bits(word, 9, 5);
        let rd = bits(word, 4, 0);
        let gpr_view = |reg: u32| {
            if word_size {
                regs::gpr_view(reg, 1, false)
            } else {
                regs::gpr_view(reg, 0, false)
            }
        };
        let fpr_view = |reg: u32| {
            if word_size {
                regs::v_view(reg, 3)
            } else {
                regs::v_view(reg, 2)
            }
        };
        let form = match (to_fp, word_size) {
            (true, false) => forms_fp::FMOV_S_W,
            (false, false) => forms_fp::FMOV_W_S,
            (true, true) => forms_fp::FMOV_D_X,
            (false, true) => forms_fp::FMOV_X_D,
        };
        let width = if word_size { 64 } else { 32 };
        let dst = angryier_arch::Operand {
            index: 0,
            width_bits: width,
            access: AccessKind::Write,
            visibility: angryier_arch::OperandVisibility::Explicit,
            kind: angryier_arch::OperandKind::Register(if to_fp { fpr_view(rd) } else { gpr_view(rd) }),
        };
        let src = angryier_arch::Operand {
            index: 1,
            width_bits: width,
            access: AccessKind::Read,
            visibility: angryier_arch::OperandVisibility::Explicit,
            kind: angryier_arch::OperandKind::Register(if to_fp { gpr_view(rn) } else { fpr_view(rn) }),
        };
        return Some(Ok(instruction(address, form, vec![dst, src])));
    }

    // Scalar arithmetic (exact residues).
    if let Some(decoded) = scalar_arith(address, word) {
        return Some(decoded);
    }

    // Only sf, S/D precision, signedness and register fields may vary.
    // In particular type[1] (bit 23) must be zero for S/D conversions.
    if word & 0x7FBE_FC00 == 0x1E38_0000 {
        let unsigned = bit(word, 16) == 1;
        let word_size = bit(word, 31) == 1;
        let double = bit(word, 22) == 1;
        let rn = bits(word, 9, 5);
        let rd = bits(word, 4, 0);
        let form = match (unsigned, word_size, double) {
            (false, false, false) => forms_fp::FCVTZS_W_S,
            (false, false, true) => forms_fp::FCVTZS_W_D,
            (false, true, false) => forms_fp::FCVTZS_X_S,
            (false, true, true) => forms_fp::FCVTZS_X_D,
            (true, false, false) => forms_fp::FCVTZU_W_S,
            (true, false, true) => forms_fp::FCVTZU_W_D,
            (true, true, false) => forms_fp::FCVTZU_X_S,
            (true, true, true) => forms_fp::FCVTZU_X_D,
        };
        return Some(Ok(instruction(
            address,
            form,
            vec![
                angryier_arch::Operand {
                    index: 0,
                    width_bits: if word_size { 64 } else { 32 },
                    access: AccessKind::Write,
                    visibility: angryier_arch::OperandVisibility::Explicit,
                    kind: angryier_arch::OperandKind::Register(regs::gpr_view(rd, u32::from(word_size), false)),
                },
                angryier_arch::Operand {
                    index: 1,
                    width_bits: if double { 64 } else { 32 },
                    access: AccessKind::Read,
                    visibility: angryier_arch::OperandVisibility::Explicit,
                    kind: angryier_arch::OperandKind::Register(fp_view(rn, double)),
                },
            ],
        )));
    }

    // FCVT fixes both precisions; FCSEL leaves Rm and condition variable.
    {
        let opcode = bits(word, 21, 10);
        let double = bit(word, 22) == 1;
        let rn = bits(word, 9, 5);
        let rm = bits(word, 20, 16);
        let rd = bits(word, 4, 0);
        match opcode {
            0b1000_1001_0000 if word & 0xFFFF_FC00 == 0x1E62_4000 => {
                // FCVT Sd, Dn (double -> single).
                return Some(Ok(instruction(
                    address,
                    forms_fp::FCVT_S_D,
                    vec![
                        angryier_arch::Operand {
                            index: 0,
                            width_bits: 32,
                            access: AccessKind::Write,
                            visibility: angryier_arch::OperandVisibility::Explicit,
                            kind: angryier_arch::OperandKind::Register(fp_view(rd, false)),
                        },
                        angryier_arch::Operand {
                            index: 1,
                            width_bits: 64,
                            access: AccessKind::Read,
                            visibility: angryier_arch::OperandVisibility::Explicit,
                            kind: angryier_arch::OperandKind::Register(fp_view(rn, true)),
                        },
                    ],
                )));
            }
            0b1000_1011_0000 if word & 0xFFFF_FC00 == 0x1E22_C000 => {
                // FCVT Dd, Sn (single -> double).
                return Some(Ok(instruction(
                    address,
                    forms_fp::FCVT_D_S,
                    vec![
                        angryier_arch::Operand {
                            index: 0,
                            width_bits: 64,
                            access: AccessKind::Write,
                            visibility: angryier_arch::OperandVisibility::Explicit,
                            kind: angryier_arch::OperandKind::Register(fp_view(rd, true)),
                        },
                        angryier_arch::Operand {
                            index: 1,
                            width_bits: 32,
                            access: AccessKind::Read,
                            visibility: angryier_arch::OperandVisibility::Explicit,
                            kind: angryier_arch::OperandKind::Register(fp_view(rn, false)),
                        },
                    ],
                )));
            }
            _ if word & 0xFFA0_0C00 == 0x1E20_0C00 => {
                // FCSEL Sd, Sn, Sm, cond.
                let cond = bits(word, 15, 12);
                let form = if double { forms_fp::FCSEL_D } else { forms_fp::FCSEL_S };
                return Some(Ok(instruction(
                    address,
                    form,
                    vec![
                        angryier_arch::Operand {
                            index: 0,
                            width_bits: if double { 64 } else { 32 },
                            access: AccessKind::Write,
                            visibility: angryier_arch::OperandVisibility::Explicit,
                            kind: angryier_arch::OperandKind::Register(fp_view(rd, double)),
                        },
                        angryier_arch::Operand {
                            index: 1,
                            width_bits: if double { 64 } else { 32 },
                            access: AccessKind::Read,
                            visibility: angryier_arch::OperandVisibility::Explicit,
                            kind: angryier_arch::OperandKind::Register(fp_view(rn, double)),
                        },
                        angryier_arch::Operand {
                            index: 2,
                            width_bits: if double { 64 } else { 32 },
                            access: AccessKind::Read,
                            visibility: angryier_arch::OperandVisibility::Explicit,
                            kind: angryier_arch::OperandKind::Register(fp_view(rm, double)),
                        },
                        angryier_arch::Operand {
                            index: 3,
                            width_bits: 8,
                            access: AccessKind::Read,
                            visibility: angryier_arch::OperandVisibility::Explicit,
                            kind: angryier_arch::OperandKind::Immediate(angryier_arch::ImmediateOperand {
                                value: u64::from(cond),
                                signed: false,
                            }),
                        },
                    ],
                )));
            }
            _ => {}
        }
    }

    // FMOV <Sd|Dd>, #imm (VFPExpandImm family).
    if let Some(decoded) = fmov_imm(address, word) {
        return Some(decoded);
    }

    None
}

fn scalar_arith(address: Address, word: u32) -> Option<Result<DecodedInstruction, Arm64DecodeError>> {
    let double = bit(word, 22) == 1;
    let rn = bits(word, 9, 5);
    let rm = bits(word, 20, 16);
    let rd = bits(word, 4, 0);
    let width = if double { 64 } else { 32 };
    let operand = |index: u8, reg: u32, access: AccessKind| angryier_arch::Operand {
        index,
        width_bits: width,
        access,
        visibility: angryier_arch::OperandVisibility::Explicit,
        kind: angryier_arch::OperandKind::Register(fp_view(reg, double)),
    };
    let two = word & TWO_SOURCE_MASK;
    let (s_form, d_form, two_source) = match two {
        0x1E20_2800 => (forms_fp::FADD_S, forms_fp::FADD_D, true),
        0x1E20_3800 => (forms_fp::FSUB_S, forms_fp::FSUB_D, true),
        0x1E20_1800 => (forms_fp::FDIV_S, forms_fp::FDIV_D, true),
        0x1E20_0800 => (forms_fp::FMUL_S, forms_fp::FMUL_D, true),
        0x1E20_2000 => (forms_fp::FCMP_S, forms_fp::FCMP_D, false),
        _ => {
            let one = word & ONE_SOURCE_MASK;
            match one {
                0x1E21_4000 => (forms_fp::FNEG_S, forms_fp::FNEG_D, false),
                0x1E21_C000 => (forms_fp::FSQRT_S, forms_fp::FSQRT_D, false),
                0x1E20_C000 => (forms_fp::FABS_S, forms_fp::FABS_D, false),
                _ => return None,
            }
        }
    };
    let form = if double { d_form } else { s_form };
    let is_compare = matches!(form, forms_fp::FCMP_S | forms_fp::FCMP_D);
    let operands = if two_source {
        vec![
            operand(0, rd, AccessKind::Write),
            operand(1, rn, AccessKind::Read),
            operand(2, rm, AccessKind::Read),
        ]
    } else if is_compare {
        vec![operand(0, rn, AccessKind::Read), operand(1, rm, AccessKind::Read)]
    } else {
        vec![operand(0, rd, AccessKind::Write), operand(1, rn, AccessKind::Read)]
    };
    Some(Ok(instruction(address, form, operands)))
}

fn scvtf(address: Address, word: u32) -> Option<Result<DecodedInstruction, Arm64DecodeError>> {
    let rd = bits(word, 4, 0);
    let rn = bits(word, 9, 5);
    let double = bit(word, 22) == 1;
    let (form, destination, source) = if word & 0x7FBF_FC00 == 0x1E22_0000 {
        let wide = bit(word, 31) == 1;
        let form = match (double, wide) {
            (false, false) => forms_fp::SCVTF_S_W,
            (true, false) => forms_fp::SCVTF_D_W,
            (false, true) => forms_fp::SCVTF_S_X,
            (true, true) => forms_fp::SCVTF_D_X,
        };
        (
            form,
            fp_view(rd, double),
            regs::gpr_view(rn, if wide { 1 } else { 0 }, false),
        )
    } else if word & 0xFFBF_FC00 == 0x5E21_D800 {
        (
            if double {
                forms_fp::SCVTF_D_D
            } else {
                forms_fp::SCVTF_S_S
            },
            fp_view(rd, double),
            fp_view(rn, double),
        )
    } else if word & 0xBFBF_FC00 == 0x0E21_D800 {
        let q = bit(word, 30) == 1;
        if double && !q {
            return None;
        }
        let form = match (double, q) {
            (false, false) => forms_fp::SCVTF_V2S,
            (false, true) => forms_fp::SCVTF_V4S,
            (true, true) => forms_fp::SCVTF_V2D,
            _ => return None,
        };
        let view = |reg| if q { regs::q_view(reg) } else { regs::v_view(reg, 3) };
        (form, view(rd), view(rn))
    } else {
        return None;
    };
    Some(Ok(instruction(
        address,
        form,
        vec![
            angryier_arch::Operand {
                index: 0,
                width_bits: destination.width_bits,
                access: AccessKind::Write,
                visibility: angryier_arch::OperandVisibility::Explicit,
                kind: angryier_arch::OperandKind::Register(destination),
            },
            angryier_arch::Operand {
                index: 1,
                width_bits: source.width_bits,
                access: AccessKind::Read,
                visibility: angryier_arch::OperandVisibility::Explicit,
                kind: angryier_arch::OperandKind::Register(source),
            },
        ],
    )))
}

/// Decode and expand the scalar immediate with the architectural VFPExpandImm layout.
fn fmov_imm(address: Address, word: u32) -> Option<Result<DecodedInstruction, Arm64DecodeError>> {
    // Only precision[0], imm8[20:13] and Rd vary. Bits[15:13] belong to
    // the immediate, while Rn[9:5] and precision[1] must be zero.
    if word & 0xFFA0_1FE0 != 0x1E20_1000 {
        return None;
    }
    let double = bit(word, 22) == 1;
    let imm8 = bits(word, 20, 13);
    let sign = (imm8 >> 7) & 1;
    let b = (imm8 >> 6) & 1;
    let (exponent_bits, fraction_bits) = if double { (11, 52) } else { (8, 23) };
    // NOT(b), Replicate(b, E-3), imm8[5:4], followed by imm8[3:0]
    // and a zero-filled fraction. No host floating-point rounding is involved.
    let exponent = ((b ^ 1) << (exponent_bits - 1)) | ((((1 << (exponent_bits - 3)) - 1) * b) << 2) | ((imm8 >> 4) & 3);
    let bits64 = (u64::from(sign) << (exponent_bits + fraction_bits))
        | (u64::from(exponent) << fraction_bits)
        | (u64::from(imm8 & 15) << (fraction_bits - 4));
    let form = if double { forms_fp::FMOV_ID } else { forms_fp::FMOV_IS };
    let rd = bits(word, 4, 0);
    Some(Ok(instruction(
        address,
        form,
        vec![
            angryier_arch::Operand {
                index: 0,
                width_bits: if double { 64 } else { 32 },
                access: AccessKind::Write,
                visibility: angryier_arch::OperandVisibility::Explicit,
                kind: angryier_arch::OperandKind::Register(fp_view(rd, double)),
            },
            angryier_arch::Operand {
                index: 1,
                width_bits: if double { 64 } else { 32 },
                access: AccessKind::Read,
                visibility: angryier_arch::OperandVisibility::Explicit,
                kind: angryier_arch::OperandKind::Immediate(angryier_arch::ImmediateOperand {
                    value: bits64,
                    signed: sign == 1,
                }),
            },
        ],
    )))
}
