//! Intel XED instruction-class → Angryier semantic-form mapping.
//!
//! The native XED bridge (`angryier-arch-xed-ffi`) reports raw XED instruction
//! classes as `form_id`. The handwritten semantic corpus
//! (`angryier-semantics-intel64`) matches on engine-owned form ids instead.
//! This module is the translation layer between the two namespaces; it lives
//! in the runtime because only the integration layer knows both sides.
//!
//! Only instructions whose corpus semantics are exact are mapped. Simplified
//! corpus forms (for example the two-operand `MUL`/`DIV` models, which do not
//! reproduce the real `RAX:RDX` behavior) are deliberately left unmapped so
//! that semantic resolution fails explicitly rather than executing
//! approximate semantics.
//!
//! Unmapped instructions are reported as form id [`UNMAPPED_FORM_ID`] (`0`),
//! which is not a registered corpus form.

use angryier_arch::{DecodedInstruction, Operand, OperandKind, OperandVisibility};
use angryier_arch_intel64::register_id;
use angryier_arch_xed_ffi::iclass;
use angryier_semantics_intel64::forms;

/// Form id reported for instructions XED can decode but the corpus cannot
/// execute exactly. No registered corpus form uses this id.
pub const UNMAPPED_FORM_ID: u32 = 0;

/// Sentinel form ids for string instructions. These are not corpus forms: a
/// `rep`-prefixed string instruction encodes an internal loop, which cannot be
/// straight-line corpus semantics. The runtime executes them directly.
pub const STOSB_FORM_ID: u32 = 0xFFFF_0000;
pub const STOSW_FORM_ID: u32 = 0xFFFF_0001;
pub const STOSD_FORM_ID: u32 = 0xFFFF_0002;
pub const STOSQ_FORM_ID: u32 = 0xFFFF_0003;
pub const MOVSB_FORM_ID: u32 = 0xFFFF_0004;
pub const MOVSW_FORM_ID: u32 = 0xFFFF_0005;
pub const MOVSD_FORM_ID: u32 = 0xFFFF_0006;
pub const MOVSQ_FORM_ID: u32 = 0xFFFF_0007;
pub const REP_STOSB_FORM_ID: u32 = 0xFFFF_0008;
pub const REP_STOSW_FORM_ID: u32 = 0xFFFF_0009;
pub const REP_STOSD_FORM_ID: u32 = 0xFFFF_000A;
pub const REP_STOSQ_FORM_ID: u32 = 0xFFFF_000B;
pub const REP_MOVSB_FORM_ID: u32 = 0xFFFF_000C;
pub const REP_MOVSW_FORM_ID: u32 = 0xFFFF_000D;
pub const REP_MOVSD_FORM_ID: u32 = 0xFFFF_000E;
pub const REP_MOVSQ_FORM_ID: u32 = 0xFFFF_000F;

/// Operand shape used to discriminate forms that share an XED iclass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    Reg64,
    Reg32,
    Reg16,
    Reg8,
    /// The 8-bit `CL` register, used by variable-count shifts and rotates.
    Imm,
    /// 8-bit memory access.
    Mem8,
    /// 16-bit memory access.
    Mem16,
    /// 32-bit memory access.
    Mem32,
    /// 64-bit memory access.
    Mem64,
    /// 128-bit memory access.
    Mem128,
    /// Address-generation operand (`lea`); sized variants are not used since
    /// `lea` never touches memory contents.
    Mem,
    /// 128-bit vector register (xmm view of a zmm parent).
    Xmm,
    /// 256-bit vector register (ymm view of a zmm parent).
    Ymm,
    /// 512-bit vector register (zmm).
    Zmm,
    Rel,
    Other,
}

fn shape_of(operand: &Operand) -> Shape {
    match &operand.kind {
        OperandKind::Register(register) => match register.width_bits {
            512 => Shape::Zmm,
            256 => Shape::Ymm,
            128 => Shape::Xmm,
            64 => Shape::Reg64,
            32 => Shape::Reg32,
            16 => Shape::Reg16,
            8 => Shape::Reg8,
            _ => Shape::Other,
        },
        OperandKind::Immediate(_) => Shape::Imm,
        OperandKind::Memory(_) => match operand.width_bits {
            256 | 512 => Shape::Mem,
            8 => Shape::Mem8,
            16 => Shape::Mem16,
            32 => Shape::Mem32,
            64 => Shape::Mem64,
            128 => Shape::Mem128,
            _ => Shape::Other,
        },
        OperandKind::AddressGeneration(_) => Shape::Mem,
        OperandKind::RelativeBranch(_) => Shape::Rel,
        OperandKind::FarPointer(_) => Shape::Other,
    }
}

/// Maps a decoded instruction to an engine-owned semantic form id.
///
/// Returns `None` when the instruction class or operand shape has no exact
/// corpus semantics.
///
/// XED reports implicit and suppressed operands (flags, `RIP`, stack
/// accesses, the implicit `CL` of variable-count shifts) alongside explicit
/// ones. Implicit operands participate in shape discrimination (for example
/// the implicit accumulator register of `cmp eax, imm32`); only suppressed
/// bookkeeping operands (stack slots, flag writes) are excluded. An implicit
/// `CL` selects the variable-count shift/rotate forms.
fn is_cl(operand: &Operand) -> bool {
    matches!(
        &operand.kind,
        OperandKind::Register(register)
            if register.width_bits == 8
                && register.parent.0 == register_id::GPR_BASE + 1
                && register.bit_offset == 0
    )
}

pub fn map_form(decoded: &DecodedInstruction) -> Option<u32> {
    // Implicit operands join the shape (accumulator of `cmp eax, imm`), but a
    // suppressed operand never does. The implicit `CL` of variable-count
    // shifts is detected separately by `has_cl`, so it is excluded here.
    let explicit: Vec<Shape> = decoded
        .operands
        .iter()
        .filter(|operand| {
            operand.visibility != OperandVisibility::Suppressed
                && !(operand.visibility == OperandVisibility::Implicit && is_cl(operand))
        })
        .map(shape_of)
        .collect();
    let shapes = explicit.as_slice();
    let has_cl = decoded
        .operands
        .iter()
        .any(|operand| operand.visibility == OperandVisibility::Implicit && is_cl(operand));

    match decoded.form_id {
        iclass::XED_ICLASS_MOV => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::MOV_R64_R64),
            [Shape::Reg64, Shape::Imm] => Some(forms::MOV_R64_IMM64),
            [Shape::Reg64, Shape::Mem64] => Some(forms::MOV_R64_MEM64),
            [Shape::Mem64, Shape::Reg64] => Some(forms::MOV_MEM64_R64),
            [Shape::Mem64, Shape::Imm] => Some(forms::MOV_MEM64_IMM32),
            [Shape::Reg32, Shape::Reg32] => Some(forms::MOV_R32_R32),
            [Shape::Reg32, Shape::Imm] => Some(forms::MOV_R32_IMM32),
            [Shape::Reg32, Shape::Mem32] => Some(forms::MOV_R32_MEM32),
            [Shape::Mem32, Shape::Reg32] => Some(forms::MOV_MEM32_R32),
            [Shape::Reg16, Shape::Reg16] => Some(forms::MOV_R16_R16),
            [Shape::Reg16, Shape::Imm] => Some(forms::MOV_R16_IMM16),
            [Shape::Reg8, Shape::Reg8] => Some(forms::MOV_R8_R8),
            [Shape::Reg8, Shape::Imm] => Some(forms::MOV_R8_IMM8),
            [Shape::Reg8, Shape::Mem8] => Some(forms::MOV_R8_MEM8),
            [Shape::Mem16, Shape::Reg16] => Some(forms::MOV_MEM16_R16),
            [Shape::Reg16, Shape::Mem16] => Some(forms::MOV_R16_MEM16),
            [Shape::Mem8, Shape::Reg8] => Some(forms::MOV_MEM8_R8),
            [Shape::Mem8, Shape::Imm] => Some(forms::MOV_MEM8_IMM8),
            [Shape::Mem16, Shape::Imm] => Some(forms::MOV_MEM16_IMM16),
            [Shape::Mem32, Shape::Imm] => Some(forms::MOV_MEM32_IMM32),
            _ => None,
        },
        iclass::XED_ICLASS_ADD => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::ADD_R64_R64),
            [Shape::Reg64, Shape::Imm] => Some(forms::ADD_R64_IMM32),
            [Shape::Reg64, Shape::Mem64] => Some(forms::ADD_R64_MEM64),
            [Shape::Mem64, Shape::Reg64] => Some(forms::ADD_MEM64_R64),
            [Shape::Mem64, Shape::Imm] => Some(forms::ADD_MEM64_IMM32),
            [Shape::Mem32, Shape::Imm] => Some(forms::ADD_MEM32_IMM32),
            [Shape::Reg32, Shape::Reg32] => Some(forms::ADD_R32_R32),
            [Shape::Reg32, Shape::Imm] => Some(forms::ADD_R32_IMM8),
            [Shape::Reg32, Shape::Mem32] => Some(forms::ADD_R32_MEM32),
            [Shape::Reg8, Shape::Mem8] => Some(forms::ADD_R8_MEM8),
            [Shape::Mem8, Shape::Reg8] => Some(forms::ADD_MEM8_R8),
            [Shape::Mem8, Shape::Imm] => Some(forms::ADD_MEM8_IMM8),
            [Shape::Mem16, Shape::Imm] => Some(forms::ADD_MEM16_IMM16),
            [Shape::Reg8, Shape::Reg8] => Some(forms::ADD_R8_R8),
            [Shape::Reg8, Shape::Imm] => Some(forms::ADD_R8_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_SUB => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::SUB_R64_R64),
            [Shape::Reg64, Shape::Imm] => Some(forms::SUB_R64_IMM32),
            [Shape::Reg32, Shape::Reg32] => Some(forms::SUB_R32_R32),
            [Shape::Reg32, Shape::Imm] => Some(forms::SUB_R32_IMM8),
            [Shape::Reg32, Shape::Mem32] => Some(forms::SUB_R32_MEM32),
            [Shape::Reg8, Shape::Mem8] => Some(forms::SUB_R8_MEM8),
            [Shape::Mem8, Shape::Reg8] => Some(forms::SUB_MEM8_R8),
            [Shape::Mem8, Shape::Imm] => Some(forms::SUB_MEM8_IMM8),
            [Shape::Mem16, Shape::Imm] => Some(forms::SUB_MEM16_IMM16),
            [Shape::Reg8, Shape::Reg8] => Some(forms::SUB_R8_R8),
            [Shape::Reg8, Shape::Imm] => Some(forms::SUB_R8_IMM8),
            [Shape::Mem32, Shape::Imm] => Some(forms::SUB_MEM32_IMM32),
            [Shape::Mem64, Shape::Imm] => Some(forms::SUB_MEM64_IMM32),
            [Shape::Reg64, Shape::Mem64] => Some(forms::SUB_R64_MEM64),
            [Shape::Mem64, Shape::Reg64] => Some(forms::SUB_MEM64_R64),
            [Shape::Mem32, Shape::Reg32] => Some(forms::SUB_MEM32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_CMP => match shapes {
            [Shape::Reg8, Shape::Reg8] => Some(forms::CMP_R8_R8),
            [Shape::Reg8, Shape::Imm] => Some(forms::CMP_R8_IMM8),
            [Shape::Mem8, Shape::Imm] => Some(forms::CMP_MEM8_IMM8),
            [Shape::Mem64, Shape::Reg64] => Some(forms::CMP_MEM64_R64),
            [Shape::Mem32, Shape::Reg32] => Some(forms::CMP_MEM32_R32),
            [Shape::Mem8, Shape::Reg8] => Some(forms::CMP_MEM8_R8),
            [Shape::Mem16, Shape::Reg16] => Some(forms::CMP_MEM16_R16),
            [Shape::Mem32, Shape::Imm] => Some(forms::CMP_MEM32_IMM32),
            [Shape::Mem16, Shape::Imm] => Some(forms::CMP_MEM16_IMM16),

            [Shape::Reg64, Shape::Reg64] => Some(forms::CMP_R64_R64),
            [Shape::Reg64, Shape::Imm] => Some(forms::CMP_R64_IMM32),
            [Shape::Reg64, Shape::Mem64] => Some(forms::CMP_R64_MEM64),
            [Shape::Mem64, Shape::Imm] => Some(forms::CMP_MEM64_IMM32),
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMP_R32_R32),
            [Shape::Reg32, Shape::Imm] => Some(forms::CMP_R32_IMM8),
            [Shape::Reg32, Shape::Mem32] => Some(forms::CMP_R32_MEM32),
            [Shape::Reg8, Shape::Mem8] => Some(forms::CMP_R8_MEM8),
            _ => None,
        },
        iclass::XED_ICLASS_AND => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::AND_R64_R64),
            [Shape::Reg64, Shape::Imm] => Some(forms::AND_R64_IMM32),
            [Shape::Reg32, Shape::Reg32] => Some(forms::AND_R32_R32),
            [Shape::Reg32, Shape::Imm] => Some(forms::AND_R32_IMM32),
            [Shape::Reg32, Shape::Mem32] => Some(forms::AND_R32_MEM32),
            [Shape::Reg64, Shape::Mem64] => Some(forms::AND_R64_MEM64),
            [Shape::Reg8, Shape::Mem8] => Some(forms::AND_R8_MEM8),
            [Shape::Mem32, Shape::Imm] => Some(forms::AND_MEM32_IMM32),
            [Shape::Mem64, Shape::Imm] => Some(forms::AND_MEM64_IMM32),
            [Shape::Mem32, Shape::Reg32] => Some(forms::AND_MEM32_R32),
            [Shape::Mem64, Shape::Reg64] => Some(forms::AND_MEM64_R64),
            [Shape::Mem8, Shape::Reg8] => Some(forms::AND_MEM8_R8),
            [Shape::Mem8, Shape::Imm] => Some(forms::AND_MEM8_IMM8),
            [Shape::Mem16, Shape::Imm] => Some(forms::AND_MEM16_IMM16),
            [Shape::Reg8, Shape::Reg8] => Some(forms::AND_R8_R8),
            [Shape::Reg8, Shape::Imm] => Some(forms::AND_R8_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_OR => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::OR_R64_R64),
            [Shape::Reg64, Shape::Imm] => Some(forms::OR_R64_IMM32),
            [Shape::Reg32, Shape::Reg32] => Some(forms::OR_R32_R32),
            [Shape::Reg32, Shape::Imm] => Some(forms::OR_R32_IMM32),
            [Shape::Reg32, Shape::Mem32] => Some(forms::OR_R32_MEM32),
            [Shape::Reg64, Shape::Mem64] => Some(forms::OR_R64_MEM64),
            [Shape::Reg8, Shape::Mem8] => Some(forms::OR_R8_MEM8),
            [Shape::Mem32, Shape::Imm] => Some(forms::OR_MEM32_IMM32),
            [Shape::Mem64, Shape::Imm] => Some(forms::OR_MEM64_IMM32),
            [Shape::Mem32, Shape::Reg32] => Some(forms::OR_MEM32_R32),
            [Shape::Mem64, Shape::Reg64] => Some(forms::OR_MEM64_R64),
            [Shape::Mem8, Shape::Reg8] => Some(forms::OR_MEM8_R8),
            [Shape::Mem8, Shape::Imm] => Some(forms::OR_MEM8_IMM8),
            [Shape::Mem16, Shape::Imm] => Some(forms::OR_MEM16_IMM16),
            [Shape::Reg8, Shape::Reg8] => Some(forms::OR_R8_R8),
            [Shape::Reg8, Shape::Imm] => Some(forms::OR_R8_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_XOR => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::XOR_R64_R64),
            [Shape::Reg64, Shape::Imm] => Some(forms::XOR_R64_IMM32),
            [Shape::Reg32, Shape::Reg32] => Some(forms::XOR_R32_R32),
            [Shape::Reg32, Shape::Imm] => Some(forms::XOR_R32_IMM32),
            [Shape::Reg32, Shape::Mem32] => Some(forms::XOR_R32_MEM32),
            [Shape::Reg64, Shape::Mem64] => Some(forms::XOR_R64_MEM64),
            [Shape::Reg8, Shape::Mem8] => Some(forms::XOR_R8_MEM8),
            [Shape::Mem32, Shape::Imm] => Some(forms::XOR_MEM32_IMM32),
            [Shape::Mem64, Shape::Imm] => Some(forms::XOR_MEM64_IMM32),
            [Shape::Mem32, Shape::Reg32] => Some(forms::XOR_MEM32_R32),
            [Shape::Mem64, Shape::Reg64] => Some(forms::XOR_MEM64_R64),
            [Shape::Mem8, Shape::Reg8] => Some(forms::XOR_MEM8_R8),
            [Shape::Mem8, Shape::Imm] => Some(forms::XOR_MEM8_IMM8),
            [Shape::Mem16, Shape::Imm] => Some(forms::XOR_MEM16_IMM16),
            [Shape::Reg8, Shape::Reg8] => Some(forms::XOR_R8_R8),
            [Shape::Reg8, Shape::Imm] => Some(forms::XOR_R8_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_TEST => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::TEST_R64_R64),
            [Shape::Reg64, Shape::Imm] => Some(forms::TEST_R64_IMM32),
            [Shape::Reg32, Shape::Reg32] => Some(forms::TEST_R32_R32),
            [Shape::Reg32, Shape::Imm] => Some(forms::TEST_R32_IMM32),
            [Shape::Reg8, Shape::Reg8] => Some(forms::TEST_R8_R8),
            [Shape::Reg16, Shape::Reg16] => Some(forms::TEST_R16_R16),
            [Shape::Reg16, Shape::Imm] => Some(forms::TEST_R16_IMM16),
            [Shape::Mem16, Shape::Reg16] => Some(forms::TEST_MEM16_R16),
            [Shape::Reg8, Shape::Imm] => Some(forms::TEST_R8_IMM8),
            [Shape::Mem8, Shape::Reg8] => Some(forms::TEST_MEM8_R8),
            [Shape::Mem8, Shape::Imm] => Some(forms::TEST_MEM8_IMM8),
            [Shape::Mem16, Shape::Imm] => Some(forms::TEST_MEM16_IMM16),
            [Shape::Mem32, Shape::Imm] => Some(forms::TEST_MEM32_IMM32),
            [Shape::Mem64, Shape::Imm] => Some(forms::TEST_MEM64_IMM32),
            _ => None,
        },
        iclass::XED_ICLASS_SHL => match shapes {
            [Shape::Reg64, Shape::Imm] => Some(forms::SHL_R64_IMM8),
            [Shape::Reg64] if has_cl => Some(forms::SHL_R64_CL),
            // `D1` encodings carry an implicit immediate operand of 1.
            [Shape::Reg64] => Some(forms::SHL_R64_IMM8),
            [Shape::Reg32, Shape::Imm] => Some(forms::SHL_R32_IMM8),
            [Shape::Reg32] if has_cl => Some(forms::SHL_R32_CL),
            [Shape::Reg32] => Some(forms::SHL_R32_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_SHR => match shapes {
            [Shape::Reg64, Shape::Imm] => Some(forms::SHR_R64_IMM8),
            [Shape::Reg64] if has_cl => Some(forms::SHR_R64_CL),
            // `D1` encodings carry an implicit immediate operand of 1.
            [Shape::Reg64] => Some(forms::SHR_R64_IMM8),
            [Shape::Reg32, Shape::Imm] => Some(forms::SHR_R32_IMM8),
            [Shape::Reg32] if has_cl => Some(forms::SHR_R32_CL),
            [Shape::Reg32] => Some(forms::SHR_R32_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_SAR => match shapes {
            [Shape::Reg64, Shape::Imm] => Some(forms::SAR_R64_IMM8),
            [Shape::Reg64] if has_cl => Some(forms::SAR_R64_CL),
            // `D1` encodings carry an implicit immediate operand of 1.
            [Shape::Reg64] => Some(forms::SAR_R64_IMM8),
            [Shape::Reg32, Shape::Imm] => Some(forms::SAR_R32_IMM8),
            [Shape::Reg32] if has_cl => Some(forms::SAR_R32_CL),
            [Shape::Reg32] => Some(forms::SAR_R32_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_ROL => match shapes {
            [Shape::Reg64, Shape::Imm] => Some(forms::ROL_R64_IMM8),
            [Shape::Reg64] if has_cl => Some(forms::ROL_R64_CL),
            [Shape::Reg64] => Some(forms::ROL_R64_IMM8),
            [Shape::Reg32, Shape::Imm] => Some(forms::ROL_R32_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_ROR => match shapes {
            [Shape::Reg64, Shape::Imm] => Some(forms::ROR_R64_IMM8),
            [Shape::Reg64] if has_cl => Some(forms::ROR_R64_CL),
            [Shape::Reg64] => Some(forms::ROR_R64_IMM8),
            [Shape::Reg32, Shape::Imm] => Some(forms::ROR_R32_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_RCL => match shapes {
            [Shape::Reg64, Shape::Imm] => Some(forms::RCL_R64_IMM8),
            [Shape::Reg64] if has_cl => Some(forms::RCL_R64_CL),
            [Shape::Reg64] => Some(forms::RCL_R64_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_RCR => match shapes {
            [Shape::Reg64, Shape::Imm] => Some(forms::RCR_R64_IMM8),
            [Shape::Reg64] if has_cl => Some(forms::RCR_R64_CL),
            [Shape::Reg64] => Some(forms::RCR_R64_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_INC => match shapes {
            [Shape::Reg64] => Some(forms::INC_R64),
            [Shape::Reg32] => Some(forms::INC_R32),
            _ => None,
        },
        iclass::XED_ICLASS_DEC => match shapes {
            [Shape::Reg64] => Some(forms::DEC_R64),
            [Shape::Reg32] => Some(forms::DEC_R32),
            _ => None,
        },
        iclass::XED_ICLASS_NEG => match shapes {
            [Shape::Reg64] => Some(forms::NEG_R64),
            [Shape::Reg32] => Some(forms::NEG_R32),
            _ => None,
        },
        iclass::XED_ICLASS_NOT => match shapes {
            [Shape::Reg64] => Some(forms::NOT_R64),
            [Shape::Reg32] => Some(forms::NOT_R32),
            _ => None,
        },
        iclass::XED_ICLASS_IMUL => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::IMUL_R64_R64),
            [Shape::Reg64, Shape::Mem64] => Some(forms::IMUL_R64_MEM64),
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::IMUL_R64_R64_IMM32),
            [Shape::Reg32, Shape::Reg32] => Some(forms::IMUL_R32_R32),
            [Shape::Reg32, Shape::Reg32, Shape::Imm] => Some(forms::IMUL_R32_R32_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_LEAVE => Some(forms::LEAVE),
        iclass::XED_ICLASS_STOSB => Some(STOSB_FORM_ID),
        iclass::XED_ICLASS_STOSW => Some(STOSW_FORM_ID),
        iclass::XED_ICLASS_STOSD => Some(STOSD_FORM_ID),
        iclass::XED_ICLASS_STOSQ => Some(STOSQ_FORM_ID),
        iclass::XED_ICLASS_MOVSB => Some(MOVSB_FORM_ID),
        iclass::XED_ICLASS_MOVSW => Some(MOVSW_FORM_ID),
        iclass::XED_ICLASS_MOVSD => Some(MOVSD_FORM_ID),
        iclass::XED_ICLASS_MOVSQ => Some(MOVSQ_FORM_ID),
        iclass::XED_ICLASS_REP_STOSB => Some(REP_STOSB_FORM_ID),
        iclass::XED_ICLASS_REP_STOSW => Some(REP_STOSW_FORM_ID),
        iclass::XED_ICLASS_REP_STOSD => Some(REP_STOSD_FORM_ID),
        iclass::XED_ICLASS_REP_STOSQ => Some(REP_STOSQ_FORM_ID),
        iclass::XED_ICLASS_REP_MOVSB => Some(REP_MOVSB_FORM_ID),
        iclass::XED_ICLASS_REP_MOVSW => Some(REP_MOVSW_FORM_ID),
        iclass::XED_ICLASS_REP_MOVSD => Some(REP_MOVSD_FORM_ID),
        iclass::XED_ICLASS_REP_MOVSQ => Some(REP_MOVSQ_FORM_ID),
        iclass::XED_ICLASS_PUSHF | iclass::XED_ICLASS_PUSHFQ => match shapes {
            [] => Some(forms::PUSHF),
            _ => None,
        },
        iclass::XED_ICLASS_POPF | iclass::XED_ICLASS_POPFQ => match shapes {
            [] => Some(forms::POPF),
            _ => None,
        },
        iclass::XED_ICLASS_PUSH => match shapes {
            [Shape::Reg64] => Some(forms::PUSH_R64),
            [Shape::Reg32] => Some(forms::PUSH_R32),
            [Shape::Imm] => Some(forms::PUSH_IMM32),
            [Shape::Mem64] => Some(forms::PUSH_MEM64),
            [Shape::Mem16] => Some(forms::PUSH_MEM16),
            _ => None,
        },
        iclass::XED_ICLASS_POP => match shapes {
            [Shape::Reg64] => Some(forms::POP_R64),
            [Shape::Reg32] => Some(forms::POP_R32),
            _ => None,
        },
        iclass::XED_ICLASS_LEA => match shapes {
            [Shape::Reg64, Shape::Mem] => Some(forms::LEA_R64_MEM),
            [Shape::Reg32, Shape::Mem] => Some(forms::LEA_R32_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_XCHG => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::XCHG_R64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::XCHG_R32_R32),
            [Shape::Mem32, Shape::Reg32] => Some(forms::XCHG_MEM32_R32),
            [Shape::Mem64, Shape::Reg64] => Some(forms::XCHG_MEM64_R64),
            [Shape::Mem8, Shape::Reg8] => Some(forms::XCHG_MEM8_R8),
            _ => None,
        },
        iclass::XED_ICLASS_XADD => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::XADD_R64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::XADD_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_CMPXCHG => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMPXCHG_R64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMPXCHG_R32_R32),
            [Shape::Mem32, Shape::Reg32] => Some(forms::CMPXCHG_MEM32_R32),
            [Shape::Mem64, Shape::Reg64] => Some(forms::CMPXCHG_MEM64_R64),
            [Shape::Mem8, Shape::Reg8] => Some(forms::CMPXCHG_MEM8_R8),
            _ => None,
        },
        iclass::XED_ICLASS_MOVZX => match shapes {
            [Shape::Reg64, Shape::Reg32] => Some(forms::MOVZX_R64_R32),
            [Shape::Reg64, Shape::Reg8] => Some(forms::MOVZX_R64_R8),
            [Shape::Reg64, Shape::Mem8] => Some(forms::MOVZX_R64_MEM8),
            [Shape::Reg64, Shape::Mem16] => Some(forms::MOVZX_R64_MEM16),
            [Shape::Reg32, Shape::Reg16] => Some(forms::MOVZX_R32_R16),
            [Shape::Reg32, Shape::Reg8] => Some(forms::MOVZX_R32_R8),
            [Shape::Reg32, Shape::Mem8] => Some(forms::MOVZX_R32_MEM8),
            [Shape::Reg32, Shape::Mem16] => Some(forms::MOVZX_R32_MEM16),
            [Shape::Reg64, Shape::Reg16] => Some(forms::MOVZX_R64_R16),
            _ => None,
        },
        iclass::XED_ICLASS_ENDBR32 | iclass::XED_ICLASS_ENDBR64 => Some(forms::NOP2),
        iclass::XED_ICLASS_MOVSXD => match shapes {
            [Shape::Reg64, Shape::Reg32] => Some(forms::MOVSX_R64_R32),
            [Shape::Reg64, Shape::Mem32] => Some(forms::MOVSX_R64_MEM32),
            _ => None,
        },
        iclass::XED_ICLASS_MOVQ => match shapes {
            [Shape::Xmm, Shape::Reg64] => Some(forms::MOVQ_XMM_R64),
            [Shape::Xmm, Shape::Mem64] => Some(forms::MOVQ_XMM_MEM64),
            [Shape::Reg64, Shape::Xmm] => Some(forms::MOVQ_R64_XMM),
            [Shape::Mem64, Shape::Xmm] => Some(forms::MOVQ_MEM64_XMM),
            [Shape::Xmm, Shape::Xmm] => Some(forms::MOVQ_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_MOVD => match shapes {
            [Shape::Xmm, Shape::Reg32] => Some(forms::MOVD_XMM_R32),
            [Shape::Xmm, Shape::Mem32] => Some(forms::MOVD_XMM_MEM32),
            [Shape::Reg32, Shape::Xmm] => Some(forms::MOVD_R32_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_MOVAPS => match shapes {
            [Shape::Mem128, Shape::Xmm] => Some(forms::MOVAPS_MEM_XMM),
            [Shape::Xmm, Shape::Mem128] => Some(forms::MOVAPS_XMM_MEM),
            [Shape::Xmm, Shape::Xmm] => Some(forms::MOVAPS_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_MOVDQU => match shapes {
            [Shape::Xmm, Shape::Mem128] => Some(forms::MOVDQU_XMM_MEM),
            [Shape::Mem128, Shape::Xmm] => Some(forms::MOVDQU_MEM_XMM),
            [Shape::Xmm, Shape::Xmm] => Some(forms::MOVDQU_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_VMOVDQA => match shapes {
            [Shape::Ymm, Shape::Mem] => Some(forms::VMOVDQA_YMM_MEM),
            [Shape::Mem, Shape::Ymm] => Some(forms::VMOVDQA_MEM_YMM),
            [Shape::Ymm, Shape::Ymm] => Some(forms::VMOVDQA_YMM_YMM),
            [Shape::Xmm, Shape::Mem128] => Some(forms::VMOVDQA_XMM_MEM),
            [Shape::Mem128, Shape::Xmm] => Some(forms::VMOVDQA_MEM_XMM),
            [Shape::Xmm, Shape::Xmm] => Some(forms::VMOVDQA_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_VMOVDQU => match shapes {
            [Shape::Ymm, Shape::Mem] => Some(forms::VMOVDQU_YMM_MEM),
            [Shape::Mem, Shape::Ymm] => Some(forms::VMOVDQU_MEM_YMM),
            [Shape::Ymm, Shape::Ymm] => Some(forms::VMOVDQU_YMM_YMM),
            [Shape::Xmm, Shape::Mem128] => Some(forms::VMOVDQU_XMM_MEM),
            [Shape::Mem128, Shape::Xmm] => Some(forms::VMOVDQU_MEM_XMM),
            [Shape::Xmm, Shape::Xmm] => Some(forms::VMOVDQU_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_VMOVAPS => match shapes {
            [Shape::Ymm, Shape::Mem] => Some(forms::VMOVAPS_YMM_MEM),
            [Shape::Mem, Shape::Ymm] => Some(forms::VMOVAPS_MEM_YMM),
            [Shape::Xmm, Shape::Mem128] => Some(forms::VMOVAPS_XMM_MEM),
            [Shape::Mem128, Shape::Xmm] => Some(forms::VMOVAPS_MEM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_VMOVUPS => match shapes {
            [Shape::Ymm, Shape::Mem] => Some(forms::VMOVUPS_YMM_MEM),
            [Shape::Mem, Shape::Ymm] => Some(forms::VMOVUPS_MEM_YMM),
            [Shape::Xmm, Shape::Mem128] => Some(forms::VMOVUPS_XMM_MEM),
            [Shape::Mem128, Shape::Xmm] => Some(forms::VMOVUPS_MEM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPXOR => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPXOR_YMM_YMM_YMM),
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::VPXOR_XMM_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPOR => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPOR_YMM_YMM_YMM),
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::VPOR_XMM_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPAND => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPAND_YMM_YMM_YMM),
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::VPAND_XMM_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_VXORPS => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VXORPS_YMM_YMM_YMM),
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::VXORPS_XMM_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPCMPEQB => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPCMPEQB_YMM_YMM_YMM),
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::VPCMPEQB_XMM_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPMOVMSKB => match shapes {
            [Shape::Reg32, Shape::Ymm] => Some(forms::VPMOVMSKB_R32_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPBROADCASTB => match shapes {
            [Shape::Ymm, Shape::Xmm] => Some(forms::VPBROADCASTB_YMM_XMM),
            [Shape::Ymm, Shape::Mem8] => Some(forms::VPBROADCASTB_YMM_MEM8),
            _ => None,
        },
        iclass::XED_ICLASS_VPBROADCASTQ => match shapes {
            [Shape::Ymm, Shape::Xmm] => Some(forms::VPBROADCASTQ_YMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_VZEROUPPER => Some(forms::VZEROUPPER),
        iclass::XED_ICLASS_VPINSRB => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Reg8, Shape::Imm] => Some(forms::VPINSRB_XMM_XMM_R8_IMM8),
            [Shape::Xmm, Shape::Xmm, Shape::Mem8, Shape::Imm] => Some(forms::VPINSRB_XMM_XMM_MEM8_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_VPINSRW => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Reg16, Shape::Imm] => Some(forms::VPINSRW_XMM_XMM_R16_IMM8),
            [Shape::Xmm, Shape::Xmm, Shape::Mem16, Shape::Imm] => Some(forms::VPINSRW_XMM_XMM_MEM16_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_VPINSRD => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Reg32, Shape::Imm] => Some(forms::VPINSRD_XMM_XMM_R32_IMM8),
            [Shape::Xmm, Shape::Xmm, Shape::Mem32, Shape::Imm] => Some(forms::VPINSRD_XMM_XMM_MEM32_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_VPINSRQ => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Reg64, Shape::Imm] => Some(forms::VPINSRQ_XMM_XMM_R64_IMM8),
            [Shape::Xmm, Shape::Xmm, Shape::Mem64, Shape::Imm] => Some(forms::VPINSRQ_XMM_XMM_MEM64_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_VINSERTI128 => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Xmm, Shape::Imm] => Some(forms::VINSERTI128_YMM_YMM_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_VINSERTF128 => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Xmm, Shape::Imm] => Some(forms::VINSERTF128_YMM_YMM_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_VEXTRACTI128 => match shapes {
            [Shape::Xmm, Shape::Ymm, Shape::Imm] => Some(forms::VEXTRACTI128_XMM_YMM_IMM8),
            [Shape::Mem128, Shape::Ymm, Shape::Imm] => Some(forms::VEXTRACTI128_MEM128_YMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_VEXTRACTF128 => match shapes {
            [Shape::Xmm, Shape::Ymm, Shape::Imm] => Some(forms::VEXTRACTF128_XMM_YMM_IMM8),
            [Shape::Mem128, Shape::Ymm, Shape::Imm] => Some(forms::VEXTRACTF128_MEM128_YMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_VMOVD => match shapes {
            [Shape::Xmm, Shape::Reg32] => Some(forms::VMOVD_XMM_R32),
            [Shape::Reg32, Shape::Xmm] => Some(forms::VMOVD_R32_XMM),
            [Shape::Xmm, Shape::Mem32] => Some(forms::VMOVD_XMM_MEM32),
            [Shape::Mem32, Shape::Xmm] => Some(forms::VMOVD_MEM32_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_VMOVQ => match shapes {
            [Shape::Xmm, Shape::Reg64] => Some(forms::VMOVQ_XMM_R64),
            [Shape::Reg64, Shape::Xmm] => Some(forms::VMOVQ_R64_XMM),
            [Shape::Xmm, Shape::Mem64] => Some(forms::VMOVQ_XMM_MEM64),
            [Shape::Mem64, Shape::Xmm] => Some(forms::VMOVQ_MEM64_XMM),

            _ => None,
        },
        iclass::XED_ICLASS_MOVDQA => match shapes {
            [Shape::Mem128, Shape::Xmm] => Some(forms::MOVDQA_MEM_XMM),
            [Shape::Xmm, Shape::Mem128] => Some(forms::MOVDQA_XMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_MOVUPS => match shapes {
            [Shape::Mem128, Shape::Xmm] => Some(forms::MOVUPS_MEM_XMM),
            [Shape::Xmm, Shape::Mem128] => Some(forms::MOVUPS_XMM_MEM),
            [Shape::Xmm, Shape::Xmm] => Some(forms::MOVUPS_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PUNPCKLQDQ => Some(forms::PUNPCKLQDQ_XMM_XMM),
        iclass::XED_ICLASS_PUNPCKLBW => Some(forms::PUNPCKLBW_XMM_XMM),
        iclass::XED_ICLASS_PUNPCKLWD => Some(forms::PUNPCKLWD_XMM_XMM),
        iclass::XED_ICLASS_PUNPCKLDQ => Some(forms::PUNPCKLDQ_XMM_XMM),
        iclass::XED_ICLASS_PUNPCKHBW => Some(forms::PUNPCKHBW_XMM_XMM),
        iclass::XED_ICLASS_PUNPCKHWD => Some(forms::PUNPCKHWD_XMM_XMM),
        iclass::XED_ICLASS_PUNPCKHDQ => Some(forms::PUNPCKHDQ_XMM_XMM),
        iclass::XED_ICLASS_PUNPCKHQDQ => Some(forms::PUNPCKHQDQ_XMM_XMM),
        iclass::XED_ICLASS_PXOR => Some(forms::PXOR_XMM_XMM),
        iclass::XED_ICLASS_PADDQ => Some(forms::PADDQ_XMM_XMM),
        iclass::XED_ICLASS_PSUBQ => Some(forms::PSUBQ_XMM_XMM),
        iclass::XED_ICLASS_PMINUB => Some(forms::PMINUB_XMM_XMM),
        iclass::XED_ICLASS_PMAXUB => Some(forms::PMAXUB_XMM_XMM),
        iclass::XED_ICLASS_PAND => Some(forms::PAND_XMM_XMM),
        iclass::XED_ICLASS_PANDN => Some(forms::PANDN_XMM_XMM),
        iclass::XED_ICLASS_POR => Some(forms::POR_XMM_XMM),
        iclass::XED_ICLASS_PSHUFD => Some(forms::PSHUFD_XMM_IMM8),
        iclass::XED_ICLASS_PCMPEQB => Some(forms::PCMPEQB_XMM_XMM),
        iclass::XED_ICLASS_PCMPEQW => Some(forms::PCMPEQW_XMM_XMM),
        iclass::XED_ICLASS_PCMPEQD => Some(forms::PCMPEQD_XMM_XMM),
        iclass::XED_ICLASS_PCMPEQQ => Some(forms::PCMPEQQ_XMM_XMM),
        iclass::XED_ICLASS_PCMPGTB => Some(forms::PCMPGTB_XMM_XMM),
        iclass::XED_ICLASS_PCMPGTW => Some(forms::PCMPGTW_XMM_XMM),
        iclass::XED_ICLASS_PCMPGTD => Some(forms::PCMPGTD_XMM_XMM),
        iclass::XED_ICLASS_PMOVMSKB => Some(forms::PMOVMSKB_R32_XMM),
        iclass::XED_ICLASS_MOVMSKPS => Some(forms::MOVMSKPS_R32_XMM),
        iclass::XED_ICLASS_MOVMSKPD => Some(forms::MOVMSKPD_R32_XMM),
        iclass::XED_ICLASS_MOVHPS => match shapes {
            [Shape::Xmm, Shape::Mem64] => Some(forms::MOVHPS_XMM_MEM64),
            [Shape::Mem64, Shape::Xmm] => Some(forms::MOVHPS_MEM64_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_MOVHPD => match shapes {
            [Shape::Xmm, Shape::Mem64] => Some(forms::MOVHPD_XMM_MEM64),
            [Shape::Mem64, Shape::Xmm] => Some(forms::MOVHPS_MEM64_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_MOVLPS => match shapes {
            [Shape::Xmm, Shape::Mem64] => Some(forms::MOVLPS_XMM_MEM64),
            [Shape::Mem64, Shape::Xmm] => Some(forms::MOVLPS_MEM64_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_MOVLPD => match shapes {
            [Shape::Xmm, Shape::Mem64] => Some(forms::MOVLPD_XMM_MEM64),
            [Shape::Mem64, Shape::Xmm] => Some(forms::MOVLPS_MEM64_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_MOVSS => match shapes {
            [Shape::Xmm, Shape::Mem32] => Some(forms::MOVSS_XMM_MEM32),
            [Shape::Mem32, Shape::Xmm] => Some(forms::MOVSS_MEM32_XMM),
            [Shape::Xmm, Shape::Xmm] => Some(forms::MOVSS_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_MOVSD_XMM => match shapes {
            [Shape::Xmm, Shape::Mem64] => Some(forms::MOVSD_XMM_MEM64),
            [Shape::Mem64, Shape::Xmm] => Some(forms::MOVSD_MEM64_XMM),
            [Shape::Xmm, Shape::Xmm] => Some(forms::MOVSD_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_MOVSX => match shapes {
            [Shape::Reg64, Shape::Reg32] => Some(forms::MOVSX_R64_R32),
            [Shape::Reg64, Shape::Reg8] => Some(forms::MOVSX_R64_R8),
            [Shape::Reg64, Shape::Reg16] => Some(forms::MOVSX_R64_R16),
            [Shape::Reg64, Shape::Mem8] => Some(forms::MOVSX_R64_MEM8),
            [Shape::Reg64, Shape::Mem16] => Some(forms::MOVSX_R64_MEM16),
            [Shape::Reg32, Shape::Reg16] => Some(forms::MOVSX_R32_R16),
            [Shape::Reg32, Shape::Reg8] => Some(forms::MOVSX_R32_R8),
            [Shape::Reg32, Shape::Mem8] => Some(forms::MOVSX_R32_MEM8),
            [Shape::Reg32, Shape::Mem16] => Some(forms::MOVSX_R32_MEM16),
            _ => None,
        },
        iclass::XED_ICLASS_ADC => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::ADC_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_SBB => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::SBB_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_BT => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::BT_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_BTS => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::BTS_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_BTR => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::BTR_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_BTC => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::BTC_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_BSF => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::BSF_R64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::BSF_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_BSR => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::BSR_R64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::BSR_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_POPCNT => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::POPCNT_R64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::POPCNT_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_TZCNT => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::TZCNT_R64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::TZCNT_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_LZCNT => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::LZCNT_R64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::LZCNT_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_BSWAP => match shapes {
            [Shape::Reg64] => Some(forms::BSWAP_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CLC => Some(forms::CLC),
        iclass::XED_ICLASS_STC => Some(forms::STC),
        iclass::XED_ICLASS_CMC => Some(forms::CMC),
        iclass::XED_ICLASS_CBW => Some(forms::CBW),
        iclass::XED_ICLASS_CWDE => Some(forms::CWDE),
        iclass::XED_ICLASS_CDQE => Some(forms::CDQE),
        iclass::XED_ICLASS_CWD => Some(forms::CWD),
        iclass::XED_ICLASS_CDQ => Some(forms::CDQ),
        iclass::XED_ICLASS_CMOVZ => match shapes {
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMOVZ_R32_R32),
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVZ_R64_R64),
            [Shape::Reg64, Shape::Mem64] => Some(forms::CMOVZ_R64_R64),
            [Shape::Reg32, Shape::Mem32] => Some(forms::CMOVZ_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVNZ => match shapes {
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMOVNZ_R32_R32),
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVNZ_R64_R64),
            [Shape::Reg64, Shape::Mem64] => Some(forms::CMOVNZ_R64_R64),
            [Shape::Reg32, Shape::Mem32] => Some(forms::CMOVNZ_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVL => match shapes {
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMOVL_R32_R32),
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVL_R64_R64),
            [Shape::Reg64, Shape::Mem64] => Some(forms::CMOVL_R64_R64),
            [Shape::Reg32, Shape::Mem32] => Some(forms::CMOVL_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVNL => match shapes {
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMOVGE_R32_R32),
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVGE_R64_R64),
            [Shape::Reg64, Shape::Mem64] => Some(forms::CMOVGE_R64_R64),
            [Shape::Reg32, Shape::Mem32] => Some(forms::CMOVGE_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVLE => match shapes {
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMOVLE_R32_R32),
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVLE_R64_R64),
            [Shape::Reg64, Shape::Mem64] => Some(forms::CMOVLE_R64_R64),
            [Shape::Reg32, Shape::Mem32] => Some(forms::CMOVLE_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVNLE => match shapes {
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMOVG_R32_R32),
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVG_R64_R64),
            [Shape::Reg64, Shape::Mem64] => Some(forms::CMOVG_R64_R64),
            [Shape::Reg32, Shape::Mem32] => Some(forms::CMOVG_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVB => match shapes {
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMOVB_R32_R32),
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVB_R64_R64),
            [Shape::Reg64, Shape::Mem64] => Some(forms::CMOVB_R64_R64),
            [Shape::Reg32, Shape::Mem32] => Some(forms::CMOVB_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVNB => match shapes {
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMOVAE_R32_R32),
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVAE_R64_R64),
            [Shape::Reg64, Shape::Mem64] => Some(forms::CMOVAE_R64_R64),
            [Shape::Reg32, Shape::Mem32] => Some(forms::CMOVAE_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVBE => match shapes {
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMOVBE_R32_R32),
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVBE_R64_R64),
            [Shape::Reg64, Shape::Mem64] => Some(forms::CMOVBE_R64_R64),
            [Shape::Reg32, Shape::Mem32] => Some(forms::CMOVBE_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVNBE => match shapes {
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMOVA_R32_R32),
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVA_R64_R64),
            [Shape::Reg64, Shape::Mem64] => Some(forms::CMOVA_R64_R64),
            [Shape::Reg32, Shape::Mem32] => Some(forms::CMOVA_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVS => match shapes {
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMOVS_R32_R32),
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVS_R64_R64),
            [Shape::Reg64, Shape::Mem64] => Some(forms::CMOVS_R64_R64),
            [Shape::Reg32, Shape::Mem32] => Some(forms::CMOVS_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVNS => match shapes {
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMOVNS_R32_R32),
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVNS_R64_R64),
            [Shape::Reg64, Shape::Mem64] => Some(forms::CMOVNS_R64_R64),
            [Shape::Reg32, Shape::Mem32] => Some(forms::CMOVNS_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_SETZ => match shapes {
            [Shape::Reg8] => Some(forms::SETZ_R8),
            _ => None,
        },
        iclass::XED_ICLASS_SETNZ => match shapes {
            [Shape::Reg8] => Some(forms::SETNZ_R8),
            _ => None,
        },
        iclass::XED_ICLASS_SETL => match shapes {
            [Shape::Reg8] => Some(forms::SETL_R8),
            _ => None,
        },
        iclass::XED_ICLASS_SETNL => match shapes {
            [Shape::Reg8] => Some(forms::SETGE_R8),
            _ => None,
        },
        iclass::XED_ICLASS_SETLE => match shapes {
            [Shape::Reg8] => Some(forms::SETLE_R8),
            _ => None,
        },
        iclass::XED_ICLASS_SETNLE => match shapes {
            [Shape::Reg8] => Some(forms::SETG_R8),
            _ => None,
        },
        iclass::XED_ICLASS_SETB => match shapes {
            [Shape::Reg8] => Some(forms::SETB_R8),
            _ => None,
        },
        iclass::XED_ICLASS_SETNB => match shapes {
            [Shape::Reg8] => Some(forms::SETAE_R8),
            _ => None,
        },
        iclass::XED_ICLASS_SETBE => match shapes {
            [Shape::Reg8] => Some(forms::SETBE_R8),
            _ => None,
        },
        iclass::XED_ICLASS_SETNBE => match shapes {
            [Shape::Reg8] => Some(forms::SETA_R8),
            _ => None,
        },
        iclass::XED_ICLASS_SETS => match shapes {
            [Shape::Reg8] => Some(forms::SETS_R8),
            _ => None,
        },
        iclass::XED_ICLASS_SETNS => match shapes {
            [Shape::Reg8] => Some(forms::SETNS_R8),
            _ => None,
        },
        iclass::XED_ICLASS_JZ => match shapes {
            [Shape::Rel] => Some(forms::JZ_REL32),
            _ => None,
        },
        iclass::XED_ICLASS_JNZ => match shapes {
            [Shape::Rel] => Some(forms::JNZ_REL32),
            _ => None,
        },
        iclass::XED_ICLASS_JB => match shapes {
            [Shape::Rel] => Some(forms::JB_REL32),
            _ => None,
        },
        iclass::XED_ICLASS_JNB => match shapes {
            [Shape::Rel] => Some(forms::JAE_REL32),
            _ => None,
        },
        iclass::XED_ICLASS_JBE => match shapes {
            [Shape::Rel] => Some(forms::JBE_REL32),
            _ => None,
        },
        iclass::XED_ICLASS_JNBE => match shapes {
            [Shape::Rel] => Some(forms::JA_REL32),
            _ => None,
        },
        iclass::XED_ICLASS_JL => match shapes {
            [Shape::Rel] => Some(forms::JL_REL32),
            _ => None,
        },
        iclass::XED_ICLASS_JNL => match shapes {
            [Shape::Rel] => Some(forms::JGE_REL32),
            _ => None,
        },
        iclass::XED_ICLASS_JLE => match shapes {
            [Shape::Rel] => Some(forms::JLE_REL32),
            _ => None,
        },
        iclass::XED_ICLASS_JNLE => match shapes {
            [Shape::Rel] => Some(forms::JG_REL32),
            _ => None,
        },
        iclass::XED_ICLASS_JS => match shapes {
            [Shape::Rel] => Some(forms::JS_REL32),
            _ => None,
        },
        iclass::XED_ICLASS_JNS => match shapes {
            [Shape::Rel] => Some(forms::JNS_REL32),
            _ => None,
        },
        iclass::XED_ICLASS_JO => match shapes {
            [Shape::Rel] => Some(forms::JO_REL32),
            _ => None,
        },
        iclass::XED_ICLASS_JNO => match shapes {
            [Shape::Rel] => Some(forms::JNO_REL32),
            _ => None,
        },
        iclass::XED_ICLASS_JP => match shapes {
            [Shape::Rel] => Some(forms::JPE_REL32),
            _ => None,
        },
        iclass::XED_ICLASS_JNP => match shapes {
            [Shape::Rel] => Some(forms::JPO_REL32),
            _ => None,
        },
        iclass::XED_ICLASS_JMP => match shapes {
            [Shape::Reg64] => Some(forms::JMP_INDIRECT_R64),
            [Shape::Mem64] => Some(forms::JMP_INDIRECT_MEM64),
            [Shape::Rel] => Some(forms::JMP_REL32),
            _ => None,
        },
        iclass::XED_ICLASS_CALL_NEAR => match shapes {
            [Shape::Rel] => Some(forms::CALL_REL32),
            [Shape::Reg64] => Some(forms::CALL_INDIRECT_R64),
            [Shape::Mem64] => Some(forms::CALL_INDIRECT_MEM64),
            _ => None,
        },
        iclass::XED_ICLASS_RET_NEAR => match shapes {
            [] => Some(forms::RET),
            _ => None,
        },
        // `syscall` is executed by the environment model, not the semantic
        // corpus; it maps to the runtime's reserved syscall form id.
        iclass::XED_ICLASS_DIV => match shapes {
            [Shape::Reg64] => Some(forms::DIV_R64),
            [Shape::Reg32] => Some(forms::DIV_R32),
            [Shape::Mem64] => Some(forms::DIV_MEM64),
            [Shape::Mem32] => Some(forms::DIV_MEM32),
            _ => None,
        },
        iclass::XED_ICLASS_MUL => match shapes {
            [Shape::Reg64] => Some(forms::MUL_R64),
            [Shape::Reg32] => Some(forms::MUL_R32),
            [Shape::Mem64] => Some(forms::MUL_MEM64),
            [Shape::Mem32] => Some(forms::MUL_MEM32),
            _ => None,
        },
        iclass::XED_ICLASS_CMPXCHG_LOCK => match shapes {
            [Shape::Mem32, Shape::Reg32] => Some(forms::CMPXCHG_MEM32_R32),
            [Shape::Mem64, Shape::Reg64] => Some(forms::CMPXCHG_MEM64_R64),
            [Shape::Mem8, Shape::Reg8] => Some(forms::CMPXCHG_MEM8_R8),
            _ => None,
        },
        // Locked read-modify-write ops are semantically identical to their
        // unlocked forms in this single-threaded engine.
        iclass::XED_ICLASS_OR_LOCK => match shapes {
            [Shape::Mem32, Shape::Reg32] => Some(forms::OR_MEM32_R32),
            [Shape::Mem64, Shape::Reg64] => Some(forms::OR_MEM64_R64),
            [Shape::Mem8, Shape::Reg8] => Some(forms::OR_MEM8_R8),
            [Shape::Mem32, Shape::Imm] => Some(forms::OR_MEM32_IMM32),
            [Shape::Mem64, Shape::Imm] => Some(forms::OR_MEM64_IMM32),
            [Shape::Mem8, Shape::Imm] => Some(forms::OR_MEM8_IMM8),
            [Shape::Mem16, Shape::Imm] => Some(forms::OR_MEM16_IMM16),
            _ => None,
        },
        iclass::XED_ICLASS_AND_LOCK => match shapes {
            [Shape::Mem32, Shape::Reg32] => Some(forms::AND_MEM32_R32),
            [Shape::Mem64, Shape::Reg64] => Some(forms::AND_MEM64_R64),
            [Shape::Mem8, Shape::Reg8] => Some(forms::AND_MEM8_R8),
            [Shape::Mem32, Shape::Imm] => Some(forms::AND_MEM32_IMM32),
            [Shape::Mem64, Shape::Imm] => Some(forms::AND_MEM64_IMM32),
            [Shape::Mem8, Shape::Imm] => Some(forms::AND_MEM8_IMM8),
            [Shape::Mem16, Shape::Imm] => Some(forms::AND_MEM16_IMM16),
            _ => None,
        },
        iclass::XED_ICLASS_XOR_LOCK => match shapes {
            [Shape::Mem32, Shape::Reg32] => Some(forms::XOR_MEM32_R32),
            [Shape::Mem64, Shape::Reg64] => Some(forms::XOR_MEM64_R64),
            [Shape::Mem8, Shape::Reg8] => Some(forms::XOR_MEM8_R8),
            [Shape::Mem32, Shape::Imm] => Some(forms::XOR_MEM32_IMM32),
            [Shape::Mem64, Shape::Imm] => Some(forms::XOR_MEM64_IMM32),
            [Shape::Mem8, Shape::Imm] => Some(forms::XOR_MEM8_IMM8),
            [Shape::Mem16, Shape::Imm] => Some(forms::XOR_MEM16_IMM16),
            _ => None,
        },
        iclass::XED_ICLASS_ADD_LOCK => match shapes {
            [Shape::Mem32, Shape::Reg32] => Some(forms::ADD_MEM32_R32),
            [Shape::Mem64, Shape::Reg64] => Some(forms::ADD_MEM64_R64),
            [Shape::Mem8, Shape::Reg8] => Some(forms::ADD_MEM8_R8),
            [Shape::Mem32, Shape::Imm] => Some(forms::ADD_MEM32_IMM32),
            [Shape::Mem64, Shape::Imm] => Some(forms::ADD_MEM64_IMM32),
            [Shape::Mem8, Shape::Imm] => Some(forms::ADD_MEM8_IMM8),
            [Shape::Mem16, Shape::Imm] => Some(forms::ADD_MEM16_IMM16),
            _ => None,
        },
        iclass::XED_ICLASS_SUB_LOCK => match shapes {
            [Shape::Mem32, Shape::Reg32] => Some(forms::SUB_MEM32_R32),
            [Shape::Mem64, Shape::Reg64] => Some(forms::SUB_MEM64_R64),
            [Shape::Mem8, Shape::Reg8] => Some(forms::SUB_MEM8_R8),
            [Shape::Mem32, Shape::Imm] => Some(forms::SUB_MEM32_IMM32),
            [Shape::Mem64, Shape::Imm] => Some(forms::SUB_MEM64_IMM32),
            [Shape::Mem8, Shape::Imm] => Some(forms::SUB_MEM8_IMM8),
            [Shape::Mem16, Shape::Imm] => Some(forms::SUB_MEM16_IMM16),
            _ => None,
        },
        iclass::XED_ICLASS_SYSCALL => Some(crate::SYSCALL_FORM_ID),
        iclass::XED_ICLASS_CPUID => Some(crate::CPUID_FORM_ID),
        iclass::XED_ICLASS_NOP => Some(forms::NOP),
        iclass::XED_ICLASS_HLT => Some(forms::HLT),
        iclass::XED_ICLASS_UD2 => Some(forms::UD2),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_arch_xed_ffi::XedDecoder;

    fn mapped(bytes: &[u8]) -> Result<Option<u32>, Box<dyn std::error::Error>> {
        let decoder = XedDecoder::new();
        let decoded = decoder.decode(0x401000, bytes)?;
        Ok(map_form(&decoded))
    }

    #[test]
    fn maps_fixture_instructions() -> Result<(), Box<dyn std::error::Error>> {
        // cmp $0x2a, %rax (imm8 sign-extended form)
        assert_eq!(mapped(&[0x48, 0x83, 0xF8, 0x2A])?, Some(forms::CMP_R64_IMM32));
        // jne rel8
        assert_eq!(mapped(&[0x75, 0x01])?, Some(forms::JNZ_REL32));
        // jne rel32
        assert_eq!(mapped(&[0x0F, 0x85, 0x01, 0x00, 0x00, 0x00])?, Some(forms::JNZ_REL32));
        // hlt
        assert_eq!(mapped(&[0xF4])?, Some(forms::HLT));
        // nop
        assert_eq!(mapped(&[0x90])?, Some(forms::NOP));
        // ret
        assert_eq!(mapped(&[0xC3])?, Some(forms::RET));
        Ok(())
    }

    #[test]
    fn maps_common_integer_forms() -> Result<(), Box<dyn std::error::Error>> {
        // mov $0x2a, %rax / mov %rax, %rbx / mov 8(%rbx), %rax
        assert_eq!(
            mapped(&[0x48, 0xC7, 0xC0, 0x2A, 0x00, 0x00, 0x00])?,
            Some(forms::MOV_R64_IMM64)
        );
        assert_eq!(mapped(&[0x48, 0x89, 0xC3])?, Some(forms::MOV_R64_R64));
        assert_eq!(mapped(&[0x48, 0x8B, 0x43, 0x08])?, Some(forms::MOV_R64_MEM64));
        // add %rbx, %rax / sub $1, %rax / cmp %rbx, %rax
        assert_eq!(mapped(&[0x48, 0x01, 0xD8])?, Some(forms::ADD_R64_R64));
        assert_eq!(mapped(&[0x48, 0x83, 0xE8, 0x01])?, Some(forms::SUB_R64_IMM32));
        assert_eq!(mapped(&[0x48, 0x39, 0xD8])?, Some(forms::CMP_R64_R64));
        // shl $3, %rax / shl %cl, %rax
        assert_eq!(mapped(&[0x48, 0xC1, 0xE0, 0x03])?, Some(forms::SHL_R64_IMM8));
        assert_eq!(mapped(&[0x48, 0xD3, 0xE0])?, Some(forms::SHL_R64_CL));
        // inc %rax / not %rax
        assert_eq!(mapped(&[0x48, 0xFF, 0xC0])?, Some(forms::INC_R64));
        assert_eq!(mapped(&[0x48, 0xF7, 0xD0])?, Some(forms::NOT_R64));
        // imul %rbx, %rax / imul $5, %rbx, %rax
        assert_eq!(mapped(&[0x48, 0x0F, 0xAF, 0xC3])?, Some(forms::IMUL_R64_R64));
        assert_eq!(mapped(&[0x48, 0x6B, 0xC3, 0x05])?, Some(forms::IMUL_R64_R64_IMM32));
        // lea 0x10(%rbx), %rax
        assert_eq!(mapped(&[0x48, 0x8D, 0x43, 0x10])?, Some(forms::LEA_R64_MEM));
        // push %rbp / pop %rbp
        assert_eq!(mapped(&[0x55])?, Some(forms::PUSH_R64));
        assert_eq!(mapped(&[0x5D])?, Some(forms::POP_R64));
        // setz %al / jmp rel32 / call rel32
        assert_eq!(mapped(&[0x0F, 0x94, 0xC0])?, Some(forms::SETZ_R8));
        assert_eq!(mapped(&[0xE9, 0x00, 0x00, 0x00, 0x00])?, Some(forms::JMP_REL32));
        assert_eq!(mapped(&[0xE8, 0x00, 0x00, 0x00, 0x00])?, Some(forms::CALL_REL32));
        Ok(())
    }

    #[test]
    fn unmapped_forms_report_zero() -> Result<(), Box<dyn std::error::Error>> {
        // mul %rbx maps to the corpus MulR64 form.
        assert_eq!(mapped(&[0x48, 0xF7, 0xE3])?, Some(forms::MUL_R64));
        // Packed FP forms (addps) are not yet mapped.
        assert_eq!(mapped(&[0x0F, 0x58, 0xC1])?, None);
        // cpuid is executed by the CPUID feature model, not the corpus.
        assert_eq!(mapped(&[0x0F, 0xA2])?, Some(crate::CPUID_FORM_ID));
        // syscall is executed by the environment model, not the corpus.
        assert_eq!(mapped(&[0x0F, 0x05])?, Some(crate::SYSCALL_FORM_ID));
        Ok(())
    }

    #[test]
    fn unmapped_id_is_not_a_corpus_form() {
        assert_eq!(UNMAPPED_FORM_ID, 0);
        assert_ne!(forms::MOV_R64_R64, UNMAPPED_FORM_ID);
        assert_ne!(forms::HLT, UNMAPPED_FORM_ID);
        assert_ne!(crate::SYSCALL_FORM_ID, UNMAPPED_FORM_ID);
    }
}
