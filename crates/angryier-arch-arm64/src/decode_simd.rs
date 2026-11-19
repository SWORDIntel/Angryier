//! decode_simd — FP/SIMD memory decode group.
//!
//! Covers the scalar FP/SIMD load/store family (LDR/STR S/D/Q, unscaled
//! LDUR/STUR, register-offset, pre/post-index, PC-relative literal loads, and
//! LDP/STP S/D pairs). Semantics reuse the existing Load/Store machinery with
//! FP register views, so no new IR operations are required.

use angryier_arch::{
    AccessKind, DecodedInstruction, FeatureId, ImmediateOperand, InstructionModifiers, MemoryBase, MemoryIndex,
    MemoryOperand, Operand, OperandKind, OperandVisibility, RegisterView,
};
use angryier_types::{Address, TargetProfileId};

use crate::{Arm64DecodeError, forms_simd, regs};

#[inline]
fn bits(word: u32, hi: u32, lo: u32) -> u32 {
    (word >> lo) & ((1 << (hi - lo + 1)) - 1)
}

#[inline]
fn bit(word: u32, n: u32) -> u32 {
    (word >> n) & 1
}

#[inline]
fn sext(value: u32, width: u32) -> i64 {
    let shift = 64 - width;
    ((value as u64) << shift) as i64 >> shift
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

fn imm_operand(index: u8, value: u64, signed: bool, width_bits: u16) -> Operand {
    Operand {
        index,
        width_bits,
        access: AccessKind::Read,
        visibility: OperandVisibility::Explicit,
        kind: OperandKind::Immediate(ImmediateOperand { value, signed }),
    }
}

fn mem_operand(
    index: u8,
    access: AccessKind,
    base: Option<RegisterView>,
    mem_index: Option<RegisterView>,
    scale: u8,
    displacement: i64,
    displacement_width_bits: u8,
) -> Operand {
    Operand {
        index,
        width_bits: 64,
        access,
        visibility: OperandVisibility::Explicit,
        kind: OperandKind::Memory(MemoryOperand {
            memory_index: 0,
            address_width_bits: 64,
            segment: None,
            segment_base: None,
            base: base.map(MemoryBase::Register),
            index: mem_index.map(MemoryIndex::Register),
            scale,
            displacement,
            displacement_width_bits,
        }),
    }
}

/// Register number 31 resolves to SP for memory base operands.
fn base_view(n: u32) -> RegisterView {
    if n == 31 {
        RegisterView {
            parent: regs::register_id::SP,
            bit_offset: 0,
            width_bits: 64,
            write_behavior: angryier_arch::RegisterWriteBehavior::ReplaceParent,
        }
    } else {
        regs::gpr_view(n, 1, false)
    }
}

/// FP register view for a scalar load/store width: 32 -> S, 64 -> D, 128 -> Q.
fn fp_view(n: u32, width_bits: u16) -> RegisterView {
    match width_bits {
        32 => regs::v_view(n, 2),
        64 => regs::v_view(n, 3),
        _ => regs::q_view(n),
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

fn unsupported(address: Address, word: u32) -> Arm64DecodeError {
    Arm64DecodeError::UnsupportedEncoding { address, word }
}

fn simd_arith(
    profile: TargetProfileId,
    address: Address,
    word: u32,
) -> Option<Result<DecodedInstruction, Arm64DecodeError>> {
    const OP_MASK: u32 = !((0x1F << 16) | (0x1F << 5) | 0x1F);
    let residue = word & OP_MASK;
    let rm = bits(word, 20, 16);
    let rn = bits(word, 9, 5);
    let rd = bits(word, 4, 0);
    let q_view = |reg: u32| regs::q_view(reg);
    let (form, lanes, lane_bits) = match residue {
        0x4EA0_1C00 if rm == rn => (forms_simd::MOV_V, 16u16, 8u16),
        0x4E20_8400 => (forms_simd::ADD_V16B, 16, 8),
        0x4E60_8400 => (forms_simd::ADD_V8H, 8, 16),
        0x4EA0_8400 => (forms_simd::ADD_V4S, 4, 32),
        0x4EE0_8400 => (forms_simd::ADD_V2D, 2, 64),
        0x6E60_8400 => (forms_simd::SUB_V8H, 8, 16),
        0x6EA0_8400 => (forms_simd::SUB_V4S, 4, 32),
        0x6EE0_8400 => (forms_simd::SUB_V2D, 2, 64),
        0x4E20_1C00 => (forms_simd::AND_V16B, 16, 8),
        0x4EA0_1C00 => (forms_simd::ORR_V16B, 16, 8),
        0x6E20_1C00 => (forms_simd::EOR_V16B, 16, 8),
        0x0E20_D400 => (forms_simd::FADD_V2S, 2, 32),
        0x4E20_D400 => (forms_simd::FADD_V4S, 4, 32),
        0x4E60_D400 => (forms_simd::FADD_V2D, 2, 64),
        0x4EE0_D400 => (forms_simd::FSUB_V2D, 2, 64),
        0x6E20_DC00 => (forms_simd::FMUL_V4S, 4, 32),
        0x6E20_FC00 => (forms_simd::FDIV_V4S, 4, 32),
        _ => return None,
    };
    let width = lanes * lane_bits;
    let operand = |index: u8, reg: u32, access: AccessKind| angryier_arch::Operand {
        index,
        width_bits: width,
        access,
        visibility: angryier_arch::OperandVisibility::Explicit,
        kind: angryier_arch::OperandKind::Register(q_view(reg)),
    };
    Some(Ok(instruction(
        profile,
        address,
        form,
        vec![
            operand(0, rd, AccessKind::Write),
            operand(1, rn, AccessKind::Read),
            operand(2, rm, AccessKind::Read),
        ],
    )))
}

fn dup(profile: TargetProfileId, address: Address, word: u32) -> Option<Result<DecodedInstruction, Arm64DecodeError>> {
    let scalar = word & 0xFFE0_FC00 == 0x5E00_0400;
    let element = word & 0xBFE0_FC00 == 0x0E00_0400;
    let general = word & 0xBFE0_FC00 == 0x0E00_0C00;
    if !scalar && !element && !general {
        return None;
    }
    let imm5 = bits(word, 20, 16);
    let size = imm5.trailing_zeros();
    // In the GPR form, imm5 bits above its lowest set bit are ignored.
    if size > 3 {
        return None;
    }
    let q = bit(word, 30) == 1;
    if !scalar && !q && size == 3 {
        return None;
    }
    let lane_bits = 8u16 << size;
    let rd = bits(word, 4, 0);
    let rn = bits(word, 9, 5);
    let destination = if scalar {
        regs::v_view(rd, size)
    } else if q {
        regs::q_view(rd)
    } else {
        regs::v_view(rd, 3)
    };
    let source = if general {
        regs::gpr_view(rn, if size == 3 { 1 } else { 0 }, false)
    } else {
        let mut view = regs::v_view(rn, size);
        view.bit_offset = (imm5 >> (size + 1)) as u16 * lane_bits;
        view
    };
    let form = if scalar {
        forms_simd::DUP_SCALAR
    } else if element {
        forms_simd::DUP_ELEMENT
    } else {
        match size {
            0 => forms_simd::DUP_GPR_B,
            1 => forms_simd::DUP_GPR_H,
            2 => forms_simd::DUP_GPR_S,
            _ => forms_simd::DUP_GPR_D,
        }
    };
    Some(Ok(instruction(
        profile,
        address,
        form,
        vec![
            reg_operand(0, destination, AccessKind::Write),
            reg_operand(1, source, AccessKind::Read),
        ],
    )))
}

pub(crate) fn try_decode(
    profile: TargetProfileId,
    address: Address,
    word: u32,
) -> Option<Result<DecodedInstruction, Arm64DecodeError>> {
    if let Some(decoded) = dup(profile, address, word) {
        return Some(decoded);
    }
    // FP scalar load/store family: bits[29:27] == 0b111 with bit26 set (the
    // GPR load/store group keeps bit26 clear).
    if bits(word, 29, 27) == 0b111 && bit(word, 26) == 1 {
        return Some(decode_fp_ldst(profile, address, word));
    }
    // LDR (literal) S/D: bits[31:24] == 0x1C (S) or 0x5C (D).
    if bits(word, 31, 24) == 0x1C || bits(word, 31, 24) == 0x5C {
        return Some(decode_fp_literal(profile, address, word));
    }
    // SIMD lane-wise arithmetic first: exact llvm-mc residues; the FP-pair
    // gate below shares bits[29:27] and must not shadow these.
    if let Some(decoded) = simd_arith(profile, address, word) {
        return Some(decoded);
    }

    // LDP/STP FP: bits[29:27] == 0b101 with bit26 set.
    if bits(word, 29, 27) == 0b101 && bit(word, 26) == 1 {
        return Some(decode_fp_pair(profile, address, word));
    }
    // LDAR/STLR (acquire/release single loads and stores): group
    // bits[28:24] == 0b01000 with bits[21:10] all-ones; bits[23:22] = 0b11
    // selects LDAR, 0b10 selects STLR. Ordering semantics are documented
    // debt: they execute as plain loads/stores.
    if bits(word, 28, 24) == 0b01000 && bits(word, 21, 10) == 0x7FF {
        let size = bits(word, 31, 30); // 0b00=B, 0b01=H, 0b10=X
        let load = bit(word, 22) == 1; // bit22: 1 = LDAR, 0 = STLR
        let rn = bits(word, 9, 5);
        let rt = bits(word, 4, 0);
        let (_width, form) = match (size, load) {
            (0b00, true) => (8u16, forms_simd::LDAR_B),
            (0b01, true) => (16u16, forms_simd::LDAR_H),
            (0b10, true) => (32u16, forms_simd::LDAR_W),
            (0b11, true) => (64u16, forms_simd::LDAR_X),
            (0b00, false) => (8u16, forms_simd::STLR_B),
            (0b01, false) => (16u16, forms_simd::STLR_H),
            (0b10, false) => (32u16, forms_simd::STLR_W),
            (0b11, false) => (64u16, forms_simd::STLR_X),
            _ => return None,
        };
        let access = if load { AccessKind::Write } else { AccessKind::Read };
        let mem_access = if load { AccessKind::Read } else { AccessKind::Write };
        let rt_view = regs::gpr_view(rt, u32::from(size == 0b11), false);
        return Some(Ok(instruction(
            profile,
            address,
            form,
            vec![
                reg_operand(0, rt_view, access),
                mem_operand(1, mem_access, Some(base_view(rn)), None, 1, 0, 0),
            ],
        )));
    }
    None
}

fn decode_fp_ldst(
    profile: TargetProfileId,
    address: Address,
    word: u32,
) -> Result<DecodedInstruction, Arm64DecodeError> {
    let size = bits(word, 31, 30);
    // B (8-bit) shares size 0b00 with Q and is distinguished by bit23 == 0;
    // H (16-bit) is size 0b01. Both are outside this group's scope.
    let (width, scale_bytes) = match size {
        0b00 if bit(word, 23) == 1 => (128u16, 16u8),
        0b10 => (32u16, 4u8),
        0b11 => (64u16, 8u8),
        _ => return Err(unsupported(address, word)),
    };
    let load = bit(word, 22) == 1;
    let rn = bits(word, 9, 5);
    let rt = bits(word, 4, 0);
    let access = if load { AccessKind::Write } else { AccessKind::Read };
    let mem_access = if load { AccessKind::Read } else { AccessKind::Write };

    // Scaled immediate (unsigned offset): bits[25:24] == 0b01.
    if bits(word, 25, 24) == 0b01 {
        let imm12 = bits(word, 21, 10) as i64;
        let displacement = imm12.wrapping_mul(i64::from(scale_bytes));
        let form = match (load, width) {
            (true, 32) => forms_simd::LDR_S,
            (true, 64) => forms_simd::LDR_D,
            (true, _) => forms_simd::LDR_Q,
            (false, 32) => forms_simd::STR_S,
            (false, 64) => forms_simd::STR_D,
            (false, _) => forms_simd::STR_Q,
        };
        return Ok(instruction(
            profile,
            address,
            form,
            vec![
                reg_operand(0, fp_view(rt, width), access),
                mem_operand(1, mem_access, Some(base_view(rn)), None, scale_bytes, displacement, 12),
            ],
        ));
    }

    // bits[25:24] == 0b00: unscaled, register-offset, pre-index, or post-index,
    // selected by bits[11:10].
    match bits(word, 11, 10) {
        0b00 => {
            // LDUR/STUR (unscaled 9-bit signed byte offset).
            let imm9 = sext(bits(word, 20, 12), 9);
            let form = match (load, width) {
                (true, 32) => forms_simd::LDUR_S,
                (true, 64) => forms_simd::LDUR_D,
                (true, _) => forms_simd::LDUR_Q,
                (false, 32) => forms_simd::STUR_S,
                (false, 64) => forms_simd::STUR_D,
                (false, _) => forms_simd::STUR_Q,
            };
            Ok(instruction(
                profile,
                address,
                form,
                vec![
                    reg_operand(0, fp_view(rt, width), access),
                    mem_operand(1, mem_access, Some(base_view(rn)), None, 1, imm9, 9),
                ],
            ))
        }
        0b10 => {
            // Register offset: index in bits[20:16], scale bit at bit12.
            let rm = bits(word, 20, 16);
            let scale_bit = bit(word, 12);
            let scale = if scale_bit == 1 { scale_bytes } else { 1 };
            let form = match (load, width) {
                (true, 32) => forms_simd::LDR_S_REG,
                (true, 64) => forms_simd::LDR_D_REG,
                (true, _) => forms_simd::LDR_Q_REG,
                (false, 32) => forms_simd::STR_S_REG,
                (false, 64) => forms_simd::STR_D_REG,
                (false, _) => forms_simd::STR_Q_REG,
            };
            Ok(instruction(
                profile,
                address,
                form,
                vec![
                    reg_operand(0, fp_view(rt, width), access),
                    mem_operand(
                        1,
                        mem_access,
                        Some(base_view(rn)),
                        Some(regs::gpr_view(rm, 1, false)),
                        scale,
                        0,
                        0,
                    ),
                ],
            ))
        }
        0b01 | 0b11 => {
            // Pre/post-index are modelled for S/D only; Q pre/post fail closed.
            if width == 128 {
                return Err(unsupported(address, word));
            }
            let imm9 = sext(bits(word, 20, 12), 9);
            let pre = bits(word, 11, 10) == 0b11;
            let form = match (load, pre, width) {
                (true, true, 32) => forms_simd::LDR_S_PRE,
                (true, true, _) => forms_simd::LDR_D_PRE,
                (true, false, 32) => forms_simd::LDR_S_POST,
                (true, false, _) => forms_simd::LDR_D_POST,
                (false, true, 32) => forms_simd::STR_S_PRE,
                (false, true, _) => forms_simd::STR_D_PRE,
                (false, false, 32) => forms_simd::STR_S_POST,
                (false, false, _) => forms_simd::STR_D_POST,
            };
            Ok(instruction(
                profile,
                address,
                form,
                vec![
                    reg_operand(0, fp_view(rt, width), access),
                    mem_operand(1, mem_access, Some(base_view(rn)), None, 1, imm9, 9),
                    reg_operand(2, base_view(rn), AccessKind::ReadWrite),
                ],
            ))
        }
        _ => Err(unsupported(address, word)),
    }
}

fn decode_fp_literal(
    profile: TargetProfileId,
    address: Address,
    word: u32,
) -> Result<DecodedInstruction, Arm64DecodeError> {
    let is_s = bits(word, 31, 24) == 0x1C;
    let rt = bits(word, 4, 0);
    let imm19 = bits(word, 23, 5);
    let displacement = sext(imm19, 19) << 2;
    let (form, width) = if is_s {
        (forms_simd::LDR_S_LIT, 32u16)
    } else {
        (forms_simd::LDR_D_LIT, 64u16)
    };
    // The displacement is PC-relative; the literal provider computes the target
    // from the instruction address plus this displacement.
    Ok(instruction(
        profile,
        address,
        form,
        vec![
            reg_operand(0, fp_view(rt, width), AccessKind::Write),
            mem_operand(1, AccessKind::Read, None, None, 1, displacement, 19),
        ],
    ))
}

fn decode_fp_pair(
    profile: TargetProfileId,
    address: Address,
    word: u32,
) -> Result<DecodedInstruction, Arm64DecodeError> {
    let opc = bits(word, 31, 30); // 0b00 = S, 0b01 = D, 0b10 = Q
    let mode = bits(word, 24, 23); // 0b10 = offset, 0b01 = post, 0b11 = pre
    let load = bit(word, 22) == 1;
    let imm7 = sext(bits(word, 21, 15), 7);
    let rt2 = bits(word, 14, 10);
    let rn = bits(word, 9, 5);
    let rt = bits(word, 4, 0);

    let (width, scale_bytes): (u16, u8) = match opc {
        0b00 => (32, 4),
        0b01 => (64, 8),
        0b10 => (128, 16),
        _ => return Err(unsupported(address, word)),
    };
    let form = match (load, width) {
        (true, 32) => forms_simd::LDP_S,
        (true, 64) => forms_simd::LDP_D,
        (true, _) => forms_simd::LDP_Q,
        (false, 32) => forms_simd::STP_S,
        (false, 64) => forms_simd::STP_D,
        (false, _) => forms_simd::STP_Q,
    };
    let access = if load { AccessKind::Write } else { AccessKind::Read };
    let mem_access = if load { AccessKind::Read } else { AccessKind::Write };
    let displacement = imm7.wrapping_mul(i64::from(scale_bytes));
    let mut operands = vec![
        reg_operand(0, fp_view(rt, width), access),
        reg_operand(1, fp_view(rt2, width), access),
        mem_operand(2, mem_access, Some(base_view(rn)), None, scale_bytes, displacement, 7),
    ];
    if mode != 0b10 {
        // Post (0b01) or pre (0b11) index: write-back base plus a mode tag so
        // the pair provider can select the correct access address.
        operands.push(reg_operand(3, base_view(rn), AccessKind::ReadWrite));
        operands.push(imm_operand(4, if mode == 0b01 { 1 } else { 2 }, false, 8));
    }
    Ok(instruction(profile, address, form, operands))
}
