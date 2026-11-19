//! Safe-Rust A64 decoder for the integer core subset (ANG-023 phase 1).
//!
//! Fixed-width 32-bit little-endian A64 instructions. Unsupported or
//! unimplemented encodings produce [`Arm64DecodeError::UnsupportedEncoding`]
//! with the raw word; FP/SIMD and system encodings are added in later
//! increments.

use angryier_arch::{
    AccessKind, DecodedInstruction, Decoder, ImmediateOperand, InstructionModifiers, MemoryBase, MemoryIndex,
    MemoryIndexExtension, MemoryOperand, Operand, OperandKind, OperandVisibility, RegisterView, RelativeBranchOperand,
};
use angryier_types::{Address, TargetProfileId};
use core::fmt;

use crate::forms;
use crate::regs;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arm64DecodeError {
    /// Fewer than 4 bytes available.
    Truncated { address: Address, available: usize },
    /// Decodable group not yet implemented in the A64 subset.
    UnsupportedEncoding { address: Address, word: u32 },
}

impl fmt::Display for Arm64DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { address, available } => {
                write!(f, "truncated instruction at 0x{address:x} ({available} bytes)")
            }
            Self::UnsupportedEncoding { address, word } => {
                write!(f, "unsupported A64 encoding 0x{word:08x} at 0x{address:x}")
            }
        }
    }
}

impl std::error::Error for Arm64DecodeError {}

/// A64 decoder producing Angryier `DecodedInstruction` values.
#[derive(Clone, Copy, Debug)]
pub struct Arm64Decoder {
    profile: TargetProfileId,
}

impl Arm64Decoder {
    pub fn new(profile: TargetProfileId) -> Self {
        Self { profile }
    }

    pub fn with_profile_id(profile: TargetProfileId) -> Self {
        Self::new(profile)
    }
}

impl Decoder for Arm64Decoder {
    type Error = Arm64DecodeError;

    fn decode(&self, address: Address, bytes: &[u8]) -> Result<DecodedInstruction, Self::Error> {
        if bytes.len() < 4 {
            return Err(Arm64DecodeError::Truncated {
                address,
                available: bytes.len(),
            });
        }
        let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        decode_word(self.profile, address, word)
    }
}

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

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

fn branch_operand(index: u8, displacement: i64) -> Operand {
    Operand {
        index,
        width_bits: 64,
        access: AccessKind::Read,
        visibility: OperandVisibility::Explicit,
        kind: OperandKind::RelativeBranch(RelativeBranchOperand {
            displacement,
            displacement_width_bits: 64,
        }),
    }
}

/// Memory address components shared by the integer load/store decoders.
struct MemAddress {
    base: Option<RegisterView>,
    index: Option<MemoryIndex>,
    scale: u8,
    displacement: i64,
    displacement_width_bits: u8,
}

/// Builds a memory operand. `base`/`index` are register numbers (0..=30,
/// with 31 = SP). `scale` is the element multiplier (1/2/4/8).
fn mem_operand(index: u8, access: AccessKind, address_width_bits: u16, address: MemAddress) -> Operand {
    Operand {
        index,
        width_bits: address_width_bits,
        access,
        visibility: OperandVisibility::Explicit,
        kind: OperandKind::Memory(MemoryOperand {
            memory_index: 0,
            address_width_bits,
            segment: None,
            segment_base: None,
            base: address.base.map(MemoryBase::Register),
            index: address.index,
            scale: address.scale,
            displacement: address.displacement,
            displacement_width_bits: address.displacement_width_bits,
        }),
    }
}

/// Register number 31 resolves to SP for memory base/index operands.
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

fn instruction(
    _profile: TargetProfileId,
    address: Address,
    word: u32,
    form: u32,
    operands: Vec<Operand>,
) -> DecodedInstruction {
    let _ = word;
    DecodedInstruction {
        address,
        length: 4,
        form_id: form,
        features: vec![angryier_arch::FeatureId(0)],
        operands,
        modifiers: modifiers(),
    }
}

// ---------------------------------------------------------------------------
// Main dispatch
// ---------------------------------------------------------------------------

fn decode_word(profile: TargetProfileId, address: Address, word: u32) -> Result<DecodedInstruction, Arm64DecodeError> {
    let unsupported = || Err(Arm64DecodeError::UnsupportedEncoding { address, word });

    // NOP / HINT / SVC and system space.
    if word == 0xD503_201F {
        return Ok(instruction(profile, address, word, forms::NOP, vec![]));
    }
    if bits(word, 31, 23) == 0b1_1010_1010 && bit(word, 22) == 0 {
        // HINT group (imm7 in bits[11:5]); NOP handled above.
        return Ok(instruction(profile, address, word, forms::HINT, vec![]));
    }
    if bits(word, 31, 21) == 0b110_1010_0000 && bits(word, 4, 0) == 1 {
        let imm16 = bits(word, 20, 5) as u64;
        return Ok(instruction(
            profile,
            address,
            word,
            forms::SVC,
            vec![imm_operand(0, imm16, false, 16)],
        ));
    }

    // Branches.
    if bit(word, 31) == 0 && bits(word, 30, 26) == 0b0_0101 {
        let off = sext(bits(word, 25, 0), 26) << 2;
        return Ok(instruction(
            profile,
            address,
            word,
            forms::B,
            vec![branch_operand(0, off)],
        ));
    }
    if bits(word, 31, 26) == 0b1_00101 {
        let off = sext(bits(word, 25, 0), 26) << 2;
        return Ok(instruction(
            profile,
            address,
            word,
            forms::BL,
            vec![branch_operand(0, off)],
        ));
    }
    if bits(word, 31, 25) == 0b010_1010 && bit(word, 4) == 0 {
        let cond = bits(word, 3, 0);
        if cond >= 0xF {
            return unsupported();
        }
        let off = sext(bits(word, 23, 5), 19) << 2;
        return Ok(instruction(
            profile,
            address,
            word,
            forms::B_COND_BASE + cond,
            vec![branch_operand(0, off)],
        ));
    }
    if bits(word, 30, 24) == 0b011_0100 || bits(word, 30, 24) == 0b011_0101 {
        let sf = bit(word, 31);
        let rt = bits(word, 4, 0);
        let off = sext(bits(word, 23, 5), 19) << 2;
        let form = if sf == 0 { forms::CBZ_W } else { forms::CBZ_X };
        let form = if bits(word, 24, 24) == 0 { form } else { form + 2 }; // CBNZ
        return Ok(instruction(
            profile,
            address,
            word,
            form,
            vec![
                reg_operand(0, regs::gpr_view(rt, sf, false), AccessKind::Read),
                branch_operand(1, off),
            ],
        ));
    }
    if bits(word, 30, 24) == 0b011_0110 || bits(word, 30, 24) == 0b011_0111 {
        let rt = bits(word, 4, 0);
        let bit_index = (bit(word, 31) << 5) | bits(word, 23, 19);
        let off = sext(bits(word, 18, 5), 14) << 2;
        let form = if bits(word, 24, 24) == 0 {
            forms::TBZ
        } else {
            forms::TBNZ
        };
        return Ok(instruction(
            profile,
            address,
            word,
            form,
            vec![
                reg_operand(0, regs::gpr_view(rt, bit(word, 31), false), AccessKind::Read),
                imm_operand(1, bit_index as u64, false, 6),
                branch_operand(2, off),
            ],
        ));
    }
    if word & 0xFFFF_FC1F == 0xD61F_0000 {
        let rn = bits(word, 9, 5);
        return Ok(instruction(
            profile,
            address,
            word,
            forms::BR,
            vec![reg_operand(0, regs::gpr_view(rn, 1, false), AccessKind::Read)],
        ));
    }
    if word & 0xFFFF_FC1F == 0xD63F_0000 {
        let rn = bits(word, 9, 5);
        return Ok(instruction(
            profile,
            address,
            word,
            forms::BLR,
            vec![reg_operand(0, regs::gpr_view(rn, 1, false), AccessKind::Read)],
        ));
    }
    if word & 0xFFFF_FC1F == 0xD65F_0000 {
        let rn = bits(word, 9, 5);
        return Ok(instruction(
            profile,
            address,
            word,
            forms::RET,
            vec![reg_operand(0, regs::gpr_view(rn, 1, false), AccessKind::Read)],
        ));
    }

    // PC-relative.
    if bits(word, 28, 24) == 0b1_0000 {
        let immhi = bits(word, 23, 5);
        let immlo = bits(word, 1, 0);
        let imm = sext((immhi << 2) | immlo, 21);
        let form = if bit(word, 31) == 0 { forms::ADR } else { forms::ADRP };
        let imm = if form == forms::ADRP { imm << 12 } else { imm };
        return Ok(instruction(
            profile,
            address,
            word,
            form,
            vec![
                reg_operand(0, regs::gpr_view(bits(word, 4, 0), 1, false), AccessKind::Write),
                imm_operand(1, imm as u64, true, 64),
            ],
        ));
    }

    // Add/subtract immediate.
    if let Some(opc) = addsub_imm_opc(word) {
        return Ok(decode_addsub_imm(profile, address, word, opc));
    }
    // Add/subtract shifted register.
    if bits(word, 28, 24) == 0b0_1011 && bits(word, 23, 22) == 0 {
        return Ok(decode_addsub_reg(profile, address, word));
    }
    if bits(word, 28, 24) == 0b0_1011 {
        // shifted-register forms with shift != LSL handled in decode_addsub_reg.
        return Ok(decode_addsub_reg(profile, address, word));
    }
    // Logical immediate.
    if bits(word, 28, 23) == 0b10_0100 {
        return Ok(decode_logical_imm(profile, address, word));
    }
    // Logical shifted register.
    if bits(word, 28, 24) == 0b0_1010 {
        return Ok(decode_logical_reg(profile, address, word));
    }
    // Wide immediate.
    if bits(word, 28, 23) == 0b10_0101 {
        return Ok(decode_wide_imm(profile, address, word));
    }
    // Bitfield.
    if bits(word, 28, 23) == 0b10_0110 {
        return Ok(decode_bitfield(profile, address, word));
    }
    // Extract.
    if bits(word, 28, 23) == 0b10_0111 && bits(word, 30, 29) == 0 {
        return Ok(decode_extr(profile, address, word));
    }
    // Conditional select (CSEL/CSINC/CSINV/CSNEG incl. CSET/CSETM aliases):
    // bits[28:21] == 0b11010100; the op2 field at bits[11:10] selects the
    // variant. This group precedes ADC/SBC (0b11010000) and CCMN/CCMP
    // (0b11010010) in the same 8-bit field.
    if bits(word, 28, 21) == 0b1101_0100 {
        return Ok(decode_csel(profile, address, word));
    }
    // Add/subtract with carry: bits[28:21] == 0b11010000 (ADC/ADCS/SBC/SBCS).
    if bits(word, 28, 21) == 0b1101_0000 {
        return Ok(decode_adc(profile, address, word));
    }
    // Conditional compare: bits[28:21] == 0b11010010 (CCMN/CCMP).
    if bits(word, 28, 21) == 0b1101_0010 {
        return Ok(decode_ccmp(profile, address, word));
    }
    // Divide: bits[28:21] == 0b11010110, bits[15:11] == 0b00001.
    if bits(word, 28, 21) == 0b1101_0110 && bits(word, 15, 11) == 0b0_0001 {
        return Ok(decode_div(profile, address, word));
    }
    // MADD/MSUB: bit[21] == 0 (the multiply-long family sets bit21);
    // bit[15] selects MSUB.
    if bits(word, 30, 24) == 0b001_1011 && bit(word, 21) == 0 {
        return Ok(decode_madd(profile, address, word));
    }

    // Loads/stores.
    if bits(word, 29, 24) == 0b11_1001 {
        // Unsigned scaled-immediate (LDR/STR/LDRSW).
        return Ok(decode_ldst_imm(profile, address, word));
    }
    if bits(word, 29, 24) == 0b11_1000 && bits(word, 11, 10) == 0b00 {
        // Unscaled immediate (LDUR/STUR).
        return Ok(decode_ldst_unscaled(profile, address, word));
    }
    if bits(word, 29, 24) == 0b11_1000 && bits(word, 11, 10) == 0b10 {
        // Register offset (LDR/STR reg).
        return decode_ldst_reg(profile, address, word);
    }
    if bits(word, 29, 27) == 0b101 && bit(word, 26) == 0 {
        // LDP/STP (offset/post/pre-index).
        return decode_ldst_pair(profile, address, word);
    }

    // Multiply-long family (UMULL/SMULL/UMADDL/UMSUBL/SMADDL/SMSUBL):
    // bits[30:24] == 0b0011011 with bit[21] set (MADD/MSUB keep bit21 == 0).
    // llvm-mc: umull = 0x9BAA7D28, smull = 0x9B2A7D28, umaddl = 0x9BAA2D28,
    // umsubl = 0x9BAAAD28, smaddl = 0x9B2A2D28, smsubl = 0x9B2AAD28:
    // bit23 = unsigned/signed, bit15 = add/sub, Ra == 31 = plain long multiply.
    if bits(word, 30, 24) == 0b001_1011 && bit(word, 21) == 1 {
        return Ok(decode_mul_long(profile, address, word));
    }
    // Pre/post-indexed single loads and stores: unscaled group with
    // bits[11:10] != 00.
    if bits(word, 29, 24) == 0b11_1000 && bits(word, 11, 10) != 0b00 {
        return decode_ldst_indexed(profile, address, word);
    }

    // Extension groups (owned by separate modules):
    // variable shifts, scalar FP arithmetic, FP/SIMD memory forms.
    if let Some(decoded) = crate::decode_ext::try_decode(profile, address, word) {
        return decoded;
    }

    unsupported()
}

fn decode_adc(profile: TargetProfileId, address: Address, word: u32) -> DecodedInstruction {
    let sf = bit(word, 31);
    let op = bits(word, 30, 29);
    let rm = bits(word, 20, 16);
    let rn = bits(word, 9, 5);
    let rd = bits(word, 4, 0);
    let base = match (op, sf) {
        (0, 0) => forms::ADC_W,
        (0, 1) => forms::ADC_X,
        (1, 0) => forms::ADCS_W,
        (1, 1) => forms::ADCS_X,
        (2, 0) => forms::SBC_W,
        (2, 1) => forms::SBC_X,
        (3, 0) => forms::SBCS_W,
        _ => forms::SBCS_X,
    };
    instruction(
        profile,
        address,
        word,
        base,
        vec![
            reg_operand(0, regs::gpr_view(rd, sf, false), AccessKind::Write),
            reg_operand(1, regs::gpr_view(rn, sf, false), AccessKind::Read),
            reg_operand(2, regs::gpr_view(rm, sf, false), AccessKind::Read),
        ],
    )
}

fn decode_ccmp(profile: TargetProfileId, address: Address, word: u32) -> DecodedInstruction {
    let sf = bit(word, 31);
    // The op field is a single bit (bit30): 0 = CCMN, 1 = CCMP; bit29 is S.
    let op = bit(word, 30);
    let rm = bits(word, 20, 16);
    let rn = bits(word, 9, 5);
    let base = match (op, sf) {
        (0, 0) => forms::CCMN_W,
        (0, 1) => forms::CCMN_X,
        (1, 0) => forms::CCMP_W,
        _ => forms::CCMP_X,
    };
    instruction(
        profile,
        address,
        word,
        base,
        vec![
            reg_operand(0, regs::gpr_view(rn, sf, false), AccessKind::Read),
            reg_operand(1, regs::gpr_view(rm, sf, false), AccessKind::Read),
        ],
    )
}

fn decode_div(profile: TargetProfileId, address: Address, word: u32) -> DecodedInstruction {
    let sf = bit(word, 31);
    let rm = bits(word, 20, 16);
    let rn = bits(word, 9, 5);
    let rd = bits(word, 4, 0);
    let base = match (bit(word, 10), sf) {
        (0, 0) => forms::UDIV_W,
        (0, 1) => forms::UDIV_X,
        (1, 0) => forms::SDIV_W,
        _ => forms::SDIV_X,
    };
    instruction(
        profile,
        address,
        word,
        base,
        vec![
            reg_operand(0, regs::gpr_view(rd, sf, false), AccessKind::Write),
            reg_operand(1, regs::gpr_view(rn, sf, false), AccessKind::Read),
            reg_operand(2, regs::gpr_view(rm, sf, false), AccessKind::Read),
        ],
    )
}

fn decode_mul_long(profile: TargetProfileId, address: Address, word: u32) -> DecodedInstruction {
    let rm = bits(word, 20, 16);
    let ra = bits(word, 14, 10);
    let rn = bits(word, 9, 5);
    let rd = bits(word, 4, 0);
    let signed = bit(word, 23) == 0;
    let subtract = bit(word, 15) == 1;
    let accumulate = ra != 31;
    let base = match (signed, subtract, accumulate) {
        (false, false, false) => forms::UMULL_X,
        (true, false, false) => forms::SMULL_X,
        (false, false, true) => forms::UMADDL_X,
        (false, true, true) => forms::UMSUBL_X,
        (true, false, true) => forms::SMADDL_X,
        _ => forms::SMSUBL_X,
    };
    instruction(
        profile,
        address,
        word,
        base,
        vec![
            reg_operand(0, regs::gpr_view(rd, 1, false), AccessKind::Write),
            reg_operand(1, regs::gpr_view(rn, 0, false), AccessKind::Read),
            reg_operand(2, regs::gpr_view(rm, 0, false), AccessKind::Read),
            reg_operand(3, regs::gpr_view(ra, 1, false), AccessKind::Read),
        ],
    )
}

fn decode_ldst_indexed(
    profile: TargetProfileId,
    address: Address,
    word: u32,
) -> Result<DecodedInstruction, Arm64DecodeError> {
    let size = ldst_size(word);
    let load = bit(word, 22) != 0;
    let rn = bits(word, 9, 5);
    let rt = bits(word, 4, 0);
    let imm9 = sext(bits(word, 20, 12), 9);
    let mode = bits(word, 11, 10); // 01 = post-index, 11 = pre-index
    // Post-index covers all four widths; pre-index extends W/X with
    // dedicated B/H ids (0x12B..0x12E).
    let base = match (load, mode) {
        (true, 0b01) => forms::LDR_B_POST + size,
        (false, 0b01) => forms::STR_B_POST + size,
        (true, 0b11) => match size {
            0 => forms::LDR_B_PRE,
            1 => forms::LDR_H_PRE,
            2 => forms::LDR_W_PRE,
            _ => forms::LDR_X_PRE,
        },
        _ => match size {
            0 => forms::STR_B_PRE,
            1 => forms::STR_H_PRE,
            2 => forms::STR_W_PRE,
            _ => forms::STR_X_PRE,
        },
    };
    // Represent post/pre-index uniformly: the write-back base is operand 2.
    let access = if load { AccessKind::Write } else { AccessKind::Read };
    Ok(instruction(
        profile,
        address,
        word,
        base,
        vec![
            reg_operand(0, regs::gpr_view(rt, size / 2, false), access),
            mem_operand(
                1,
                if load { AccessKind::Read } else { AccessKind::Write },
                64,
                MemAddress {
                    base: Some(base_view(rn)),
                    index: None,
                    scale: 1,
                    displacement: imm9,
                    displacement_width_bits: 9,
                },
            ),
            reg_operand(2, base_view(rn), AccessKind::ReadWrite),
        ],
    ))
}

fn addsub_imm_opc(word: u32) -> Option<u32> {
    match bits(word, 30, 24) {
        0b001_0001 => Some(0), // ADD
        0b011_0001 => Some(1), // ADDS
        0b101_0001 => Some(2), // SUB
        0b111_0001 => Some(3), // SUBS
        _ => None,
    }
}

fn decode_addsub_imm(profile: TargetProfileId, address: Address, word: u32, opc: u32) -> DecodedInstruction {
    let sf = bit(word, 31);
    let rd = bits(word, 4, 0);
    let rn = bits(word, 9, 5);
    let imm12 = bits(word, 21, 10) as u64;
    let sh = bit(word, 22);
    let (value, signed) = if sh == 1 { (imm12 << 12, false) } else { (imm12, false) };
    let size = if sf == 0 { 32 } else { 64 };
    let base = match (opc, sf) {
        (0, 0) => forms::ADD_W_IMM,
        (0, 1) => forms::ADD_X_IMM,
        (1, 0) => forms::ADDS_W_IMM,
        (1, 1) => forms::ADDS_X_IMM,
        (2, 0) => forms::SUB_W_IMM,
        (2, 1) => forms::SUB_X_IMM,
        (3, 0) => forms::SUBS_W_IMM,
        _ => forms::SUBS_X_IMM,
    };
    instruction(
        profile,
        address,
        word,
        base,
        vec![
            reg_operand(0, regs::gpr_view(rd, sf, false), AccessKind::Write),
            reg_operand(1, regs::gpr_view(rn, sf, false), AccessKind::Read),
            imm_operand(2, value, signed, size),
        ],
    )
}

fn decode_addsub_reg(profile: TargetProfileId, address: Address, word: u32) -> DecodedInstruction {
    let sf = bit(word, 31);
    let opc = bits(word, 30, 29);
    let shift = bits(word, 23, 22);
    let rm = bits(word, 20, 16);
    let imm6 = bits(word, 15, 10);
    let rn = bits(word, 9, 5);
    let rd = bits(word, 4, 0);
    let base = match (opc, sf) {
        (0, 0) => forms::ADD_W_REG,
        (0, 1) => forms::ADD_X_REG,
        (1, 0) => forms::ADDS_W_REG,
        (1, 1) => forms::ADDS_X_REG,
        (2, 0) => forms::SUB_W_REG,
        (2, 1) => forms::SUB_X_REG,
        (3, 0) => forms::SUBS_W_REG,
        _ => forms::SUBS_X_REG,
    };
    instruction(
        profile,
        address,
        word,
        base,
        vec![
            reg_operand(0, regs::gpr_view(rd, sf, false), AccessKind::Write),
            reg_operand(1, regs::gpr_view(rn, sf, false), AccessKind::Read),
            reg_operand(2, regs::gpr_view(rm, sf, false), AccessKind::Read),
            imm_operand(3, imm6 as u64, false, 8),
            imm_operand(4, shift as u64, false, 8),
        ],
    )
}

fn decode_logical_imm(profile: TargetProfileId, address: Address, word: u32) -> DecodedInstruction {
    let sf = bit(word, 31);
    let opc = bits(word, 30, 29);
    let n = bit(word, 22);
    let immr = bits(word, 21, 16);
    let imms = bits(word, 15, 10);
    let rn = bits(word, 9, 5);
    let rd = bits(word, 4, 0);
    let (imm, valid) = decode_bit_masks(n, immr, imms, sf == 1);
    let _ = valid; // encodings not expressible as a mask decode as zero
    let base = match (opc, sf) {
        (0, 0) => forms::AND_W_IMM,
        (0, 1) => forms::AND_X_IMM,
        (1, 0) => forms::ORR_W_IMM,
        (1, 1) => forms::ORR_X_IMM,
        (2, 0) => forms::EOR_W_IMM,
        (2, 1) => forms::EOR_X_IMM,
        (3, 0) => forms::ANDS_W_IMM,
        _ => forms::ANDS_X_IMM,
    };
    instruction(
        profile,
        address,
        word,
        base,
        vec![
            reg_operand(0, regs::gpr_view(rd, sf, false), AccessKind::Write),
            reg_operand(1, regs::gpr_view(rn, sf, false), AccessKind::Read),
            imm_operand(2, imm, false, if sf == 0 { 32 } else { 64 }),
        ],
    )
}

/// Implements the ARM ARM `DecodeBitMasks` function; returns (wmask, valid).
/// The intermediate mask is built at 128-bit width so the all-ones 64-bit
/// pattern (s == levels, N == 1) cannot overflow the shift.
fn decode_bit_masks(n: u32, immr: u32, imms: u32, immediate: bool) -> (u64, bool) {
    let len = highest_set_bit((n << 6) | (!imms & 0x3F));
    if len < 1 {
        return (0, false);
    }
    let levels = (1u32 << len) - 1;
    let s = imms & levels;
    let r = immr & levels;
    if immediate && s == levels {
        return (0, false);
    }
    // esize is 64 for N == 1 and 32 for N == 0; the element pattern is
    // Ones(s+1) zero-extended to esize bits.
    let esize: u32 = if n == 1 { 64 } else { 32 };
    let ones: u128 = (1u128 << (s + 1)) - 1;
    let welem = ones & ((1u128 << esize) - 1);
    let wmask = rotate_right_128(welem, r, esize);
    (replicate(wmask as u64, len + 1), true)
}

fn rotate_right_128(value: u128, shift: u32, width: u32) -> u128 {
    let width = width.clamp(1, 128);
    let shift = shift % width;
    if shift == 0 {
        value & ((1u128 << width) - 1)
    } else {
        ((value >> shift) | (value << (width - shift))) & ((1u128 << width) - 1)
    }
}

fn highest_set_bit(value: u32) -> u32 {
    let mut pos = 0;
    for i in 0..32 {
        if value & (1 << i) != 0 {
            pos = i;
        }
    }
    pos
}

fn replicate(value: u64, width: u32) -> u64 {
    let mut out = value;
    let mut w = width;
    while w < 64 {
        out |= out << w;
        w *= 2;
    }
    out
}

fn decode_logical_reg(profile: TargetProfileId, address: Address, word: u32) -> DecodedInstruction {
    let sf = bit(word, 31);
    let opc = bits(word, 30, 29);
    let shift = bits(word, 23, 22);
    let rm = bits(word, 20, 16);
    let imm6 = bits(word, 15, 10);
    let rn = bits(word, 9, 5);
    let rd = bits(word, 4, 0);
    let base = match (opc, sf) {
        (0, 0) => forms::AND_W_REG,
        (0, 1) => forms::AND_X_REG,
        (1, 0) => forms::ORR_W_REG,
        (1, 1) => forms::ORR_X_REG,
        (2, 0) => forms::EOR_W_REG,
        (2, 1) => forms::EOR_X_REG,
        (3, 0) => forms::ANDS_W_REG,
        _ => forms::ANDS_X_REG,
    };
    instruction(
        profile,
        address,
        word,
        base,
        vec![
            reg_operand(0, regs::gpr_view(rd, sf, false), AccessKind::Write),
            reg_operand(1, regs::gpr_view(rn, sf, false), AccessKind::Read),
            reg_operand(2, regs::gpr_view(rm, sf, false), AccessKind::Read),
            imm_operand(3, imm6 as u64, false, 8),
            imm_operand(4, shift as u64, false, 8),
        ],
    )
}

fn decode_wide_imm(profile: TargetProfileId, address: Address, word: u32) -> DecodedInstruction {
    let sf = bit(word, 31);
    let opc = bits(word, 30, 29);
    let hw = bits(word, 22, 21);
    let imm16 = bits(word, 20, 5) as u64;
    let rd = bits(word, 4, 0);
    let base = match (opc, sf) {
        (0, 0) => forms::MOVN_W,
        (0, 1) => forms::MOVN_X,
        (2, 0) => forms::MOVZ_W,
        (2, 1) => forms::MOVZ_X,
        (3, 0) => forms::MOVK_W,
        _ => forms::MOVK_X,
    };
    instruction(
        profile,
        address,
        word,
        base,
        vec![
            reg_operand(0, regs::gpr_view(rd, sf, false), AccessKind::Write),
            imm_operand(1, imm16, false, 16),
            imm_operand(2, hw as u64, false, 8),
        ],
    )
}

fn decode_bitfield(profile: TargetProfileId, address: Address, word: u32) -> DecodedInstruction {
    let sf = bit(word, 31);
    let opc = bits(word, 30, 29);
    let n = bit(word, 22);
    let immr = bits(word, 21, 16);
    let imms = bits(word, 15, 10);
    let rn = bits(word, 9, 5);
    let rd = bits(word, 4, 0);
    let base = match (opc, sf) {
        (2, 0) => forms::UBFM_W,
        (2, 1) => forms::UBFM_X,
        (0, 0) => forms::SBFM_W,
        _ => forms::SBFM_X,
    };
    instruction(
        profile,
        address,
        word,
        base,
        vec![
            reg_operand(0, regs::gpr_view(rd, sf, false), AccessKind::Write),
            reg_operand(1, regs::gpr_view(rn, sf, false), AccessKind::Read),
            imm_operand(2, immr as u64, false, 8),
            imm_operand(3, imms as u64, false, 8),
            imm_operand(4, n as u64, false, 8),
        ],
    )
}

fn decode_extr(profile: TargetProfileId, address: Address, word: u32) -> DecodedInstruction {
    let sf = bit(word, 31);
    let rm = bits(word, 20, 16);
    let imms = bits(word, 15, 10);
    let rn = bits(word, 9, 5);
    let rd = bits(word, 4, 0);
    let form = if sf == 0 { forms::EXTR_W } else { forms::EXTR_X };
    instruction(
        profile,
        address,
        word,
        form,
        vec![
            reg_operand(0, regs::gpr_view(rd, sf, false), AccessKind::Write),
            reg_operand(1, regs::gpr_view(rn, sf, false), AccessKind::Read),
            reg_operand(2, regs::gpr_view(rm, sf, false), AccessKind::Read),
            imm_operand(3, imms as u64, false, 8),
        ],
    )
}

fn decode_csel(profile: TargetProfileId, address: Address, word: u32) -> DecodedInstruction {
    let sf = bit(word, 31);
    // op2 at bits[11:10]: 00=CSEL, 01=CSINC, 10=CSINV, 11=CSNEG.
    let op2 = bits(word, 11, 10);
    let rm = bits(word, 20, 16);
    let cond = bits(word, 15, 12);
    let rn = bits(word, 9, 5);
    let rd = bits(word, 4, 0);
    let base = match (op2, sf) {
        (0, 0) => forms::CSEL_W,
        (0, 1) => forms::CSEL_X,
        (1, 0) => forms::CSINC_W,
        (1, 1) => forms::CSINC_X,
        (2, 0) => forms::CSINV_W,
        (2, 1) => forms::CSINV_X,
        (3, 0) => forms::CSNEG_W,
        _ => forms::CSNEG_X,
    };
    instruction(
        profile,
        address,
        word,
        base,
        vec![
            reg_operand(0, regs::gpr_view(rd, sf, false), AccessKind::Write),
            reg_operand(1, regs::gpr_view(rn, sf, false), AccessKind::Read),
            reg_operand(2, regs::gpr_view(rm, sf, false), AccessKind::Read),
            imm_operand(3, cond as u64, false, 8),
        ],
    )
}

fn decode_madd(profile: TargetProfileId, address: Address, word: u32) -> DecodedInstruction {
    let sf = bit(word, 31);
    let rm = bits(word, 20, 16);
    let ra = bits(word, 14, 10);
    let rn = bits(word, 9, 5);
    let rd = bits(word, 4, 0);
    let form = match (bit(word, 15), sf) {
        (0, 0) => forms::MADD_W,
        (0, 1) => forms::MADD_X,
        (1, 0) => forms::MSUB_W,
        _ => forms::MSUB_X,
    };
    instruction(
        profile,
        address,
        word,
        form,
        vec![
            reg_operand(0, regs::gpr_view(rd, sf, false), AccessKind::Write),
            reg_operand(1, regs::gpr_view(rn, sf, false), AccessKind::Read),
            reg_operand(2, regs::gpr_view(rm, sf, false), AccessKind::Read),
            reg_operand(3, regs::gpr_view(ra, sf, false), AccessKind::Read),
        ],
    )
}

// ---------------------------------------------------------------------------
// Loads and stores
// ---------------------------------------------------------------------------

fn ldst_size(word: u32) -> u32 {
    bits(word, 31, 30)
}

fn ldst_form(load: bool, size: u32, unscaled: bool) -> u32 {
    let base = if unscaled { forms::LDUR_B } else { forms::LDR_B };
    let offset = size;
    if load { base + offset } else { base + offset + 4 }
}

fn decode_ldst_imm(profile: TargetProfileId, address: Address, word: u32) -> DecodedInstruction {
    let size = ldst_size(word);
    let opc = bits(word, 23, 22);
    let rn = bits(word, 9, 5);
    let rt = bits(word, 4, 0);
    let imm12 = bits(word, 21, 10) as u64;
    let scale = 1u64 << size;
    let displacement = imm12.wrapping_mul(scale) as i64;

    // LDRSW: opc == 0b10 (sign-extending 32-bit load, Rt is a W register).
    if opc == 0b10 && size == 2 {
        let view = regs::w_view(rt);
        return instruction(
            profile,
            address,
            word,
            forms::LDRSW,
            vec![
                reg_operand(0, view, AccessKind::Write),
                mem_operand(
                    1,
                    AccessKind::Read,
                    64,
                    MemAddress {
                        base: Some(base_view(rn)),
                        index: None,
                        scale: 1,
                        displacement,
                        displacement_width_bits: 12,
                    },
                ),
            ],
        );
    }
    let load = opc == 0b01;
    let (form, view) = if load {
        (forms::LDR_B + size, regs::gpr_view(rt, u32::from(size == 3), false))
    } else {
        (forms::STR_B + size, regs::gpr_view(rt, u32::from(size == 3), false))
    };
    instruction(
        profile,
        address,
        word,
        form,
        vec![
            reg_operand(0, view, if load { AccessKind::Write } else { AccessKind::Read }),
            mem_operand(
                1,
                if load { AccessKind::Read } else { AccessKind::Write },
                64,
                MemAddress {
                    base: Some(base_view(rn)),
                    index: None,
                    scale: scale as u8,
                    displacement,
                    displacement_width_bits: 12,
                },
            ),
        ],
    )
}

fn decode_ldst_unscaled(profile: TargetProfileId, address: Address, word: u32) -> DecodedInstruction {
    let size = ldst_size(word);
    let opc = bits(word, 23, 22);
    let rn = bits(word, 9, 5);
    let rt = bits(word, 4, 0);
    let imm9 = sext(bits(word, 20, 12), 9);
    // Sign-extending unscaled loads (LDURSB/LDURSH/LDURSW): opc 0b10; the
    // size field selects the element (0=B, 1=H, 2=W, 3=H-X-form) and bit22
    // selects the destination view (1 = W, 0 = X). llvm-mc: ldursb w = 0x38DF,
    // ldursb x = 0x389F, ldursh x = 0x78..9F, ldursw = 0xB8..9F.
    if opc == 0b10 {
        let x_view = bit(word, 22) == 0;
        let form = match (size, x_view) {
            (0, true) => forms::LDURSB_X,
            (0, false) => forms::LDURSB_W,
            (1, true) => forms::LDURSH_X,
            (1, false) => forms::LDURSH_W,
            (2, _) => forms::LDURSW,
            (3, true) => forms::LDURSH_X,
            _ => forms::LDURSH_W,
        };
        return instruction(
            profile,
            address,
            word,
            form,
            vec![
                reg_operand(
                    0,
                    if x_view {
                        regs::gpr_view(rt, 1, false)
                    } else {
                        regs::gpr_view(rt, 0, false)
                    },
                    AccessKind::Write,
                ),
                mem_operand(
                    1,
                    AccessKind::Read,
                    64,
                    MemAddress {
                        base: Some(base_view(rn)),
                        index: None,
                        scale: 1,
                        displacement: imm9,
                        displacement_width_bits: 9,
                    },
                ),
            ],
        );
    }
    let load = opc == 0b01;
    let form = ldst_form(load, size, true);
    instruction(
        profile,
        address,
        word,
        form,
        vec![
            reg_operand(
                0,
                regs::gpr_view(rt, u32::from(size == 3), false),
                if load { AccessKind::Write } else { AccessKind::Read },
            ),
            mem_operand(
                1,
                if load { AccessKind::Read } else { AccessKind::Write },
                64,
                MemAddress {
                    base: Some(base_view(rn)),
                    index: None,
                    scale: 1,
                    displacement: imm9,
                    displacement_width_bits: 9,
                },
            ),
        ],
    )
}

fn decode_ldst_reg(
    profile: TargetProfileId,
    address: Address,
    word: u32,
) -> Result<DecodedInstruction, Arm64DecodeError> {
    let size = ldst_size(word);
    let load = bit(word, 22) != 0;
    let rm = bits(word, 20, 16);
    let option = bits(word, 15, 13);
    let scale_bit = bit(word, 12);
    let rn = bits(word, 9, 5);
    let rt = bits(word, 4, 0);
    let extension = match option {
        0b010 => MemoryIndexExtension::Uxtw,
        0b011 => MemoryIndexExtension::Uxtx,
        0b110 => MemoryIndexExtension::Sxtw,
        0b111 => MemoryIndexExtension::Sxtx,
        _ => return Err(Arm64DecodeError::UnsupportedEncoding { address, word }),
    };
    let index_size: u32 = if matches!(extension, MemoryIndexExtension::Uxtw | MemoryIndexExtension::Sxtw) {
        0
    } else {
        1
    };
    let scale = if scale_bit == 1 { 1u8 << size } else { 1u8 };
    let form = if load {
        forms::LDR_B_REG + size
    } else {
        forms::STR_B_REG + size
    };
    Ok(instruction(
        profile,
        address,
        word,
        form,
        vec![
            reg_operand(
                0,
                regs::gpr_view(rt, u32::from(size == 3), false),
                if load { AccessKind::Write } else { AccessKind::Read },
            ),
            mem_operand(
                1,
                if load { AccessKind::Read } else { AccessKind::Write },
                64,
                MemAddress {
                    base: Some(base_view(rn)),
                    index: Some(MemoryIndex::ExtendedRegister {
                        register: regs::gpr_view(rm, index_size, false),
                        extension,
                    }),
                    scale,
                    displacement: 0,
                    displacement_width_bits: 0,
                },
            ),
        ],
    ))
}

fn decode_ldst_pair(
    profile: TargetProfileId,
    address: Address,
    word: u32,
) -> Result<DecodedInstruction, Arm64DecodeError> {
    // LDPSW: opc 01 with bits[25:24] == 0b01 (bits[31:24] == 0x69).
    if bits(word, 31, 24) == 0b0110_1001 && bit(word, 23) == 0 {
        let imm7 = sext(bits(word, 21, 15), 7);
        let rt2 = bits(word, 14, 10);
        let rn = bits(word, 9, 5);
        let rt = bits(word, 4, 0);
        return Ok(instruction(
            profile,
            address,
            word,
            forms::LDPSW,
            vec![
                reg_operand(0, regs::gpr_view(rt, 1, false), AccessKind::Write),
                reg_operand(1, regs::gpr_view(rt2, 1, false), AccessKind::Write),
                mem_operand(
                    2,
                    AccessKind::Read,
                    64,
                    MemAddress {
                        base: Some(base_view(rn)),
                        index: None,
                        scale: 4,
                        displacement: imm7 << 2,
                        displacement_width_bits: 7,
                    },
                ),
            ],
        ));
    }
    let opc = bits(word, 31, 30);
    if opc != 0b00 && opc != 0b10 {
        return Err(Arm64DecodeError::UnsupportedEncoding { address, word });
    }
    let mode = bits(word, 24, 23);
    let imm7 = sext(bits(word, 21, 15), 7);
    let rt2 = bits(word, 14, 10);
    let rn = bits(word, 9, 5);
    let rt = bits(word, 4, 0);
    let load = bit(word, 22) != 0;
    let size = u32::from(opc == 0b10);
    let form = match (load, size) {
        (false, 0) => forms::STP_W,
        (false, 1) => forms::STP_X,
        (true, 0) => forms::LDP_W,
        _ => forms::LDP_X,
    };
    // The base write-back is expressed as an additional written register
    // operand only for post/pre-index modes (mode 0b01 or 0b11).
    let post_index = mode == 0b01;
    let writeback = post_index || mode == 0b11;
    let displacement = imm7 << (if size == 0 { 2 } else { 3 });
    let mut operands = vec![
        reg_operand(
            0,
            regs::gpr_view(rt, size, false),
            if load { AccessKind::Write } else { AccessKind::Read },
        ),
        reg_operand(
            1,
            regs::gpr_view(rt2, size, false),
            if load { AccessKind::Write } else { AccessKind::Read },
        ),
        mem_operand(
            2,
            if load { AccessKind::Read } else { AccessKind::Write },
            64,
            MemAddress {
                base: Some(base_view(rn)),
                index: None,
                scale: if size == 0 { 4 } else { 8 },
                displacement: if post_index { 0 } else { displacement },
                displacement_width_bits: 7,
            },
        ),
    ];
    if writeback {
        operands.push(reg_operand(3, base_view(rn), AccessKind::ReadWrite));
        operands.push(imm_operand(4, displacement as u64, true, 9));
    }
    Ok(instruction(profile, address, word, form, operands))
}
