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

/// Operand shape used to discriminate forms that share an XED iclass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    Reg64,
    Reg32,
    Reg16,
    Reg8,
    /// The 8-bit `CL` register, used by variable-count shifts and rotates.
    RegCl,
    Imm,
    Mem,
    Rel,
    Other,
}

fn shape_of(operand: &Operand) -> Shape {
    match &operand.kind {
        OperandKind::Register(register) => match register.width_bits {
            64 => Shape::Reg64,
            32 => Shape::Reg32,
            16 => Shape::Reg16,
            8 if register.parent.0 == register_id::GPR_BASE + 1 && register.bit_offset == 0 => Shape::RegCl,
            8 => Shape::Reg8,
            _ => Shape::Other,
        },
        OperandKind::Immediate(_) => Shape::Imm,
        OperandKind::Memory(_) | OperandKind::AddressGeneration(_) => Shape::Mem,
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
/// ones. Only explicit operands participate in shape discrimination; an
/// implicit `CL` selects the variable-count shift/rotate forms.
pub fn map_form(decoded: &DecodedInstruction) -> Option<u32> {
    let explicit: Vec<Shape> = decoded
        .operands
        .iter()
        .filter(|operand| operand.visibility == OperandVisibility::Explicit)
        .map(shape_of)
        .collect();
    let shapes = explicit.as_slice();
    let has_cl = decoded
        .operands
        .iter()
        .any(|operand| operand.visibility != OperandVisibility::Explicit && shape_of(operand) == Shape::RegCl);

    match decoded.form_id {
        iclass::XED_ICLASS_MOV => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::MOV_R64_R64),
            [Shape::Reg64, Shape::Imm] => Some(forms::MOV_R64_IMM64),
            [Shape::Reg64, Shape::Mem] => Some(forms::MOV_R64_MEM64),
            [Shape::Mem, Shape::Reg64] => Some(forms::MOV_MEM64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::MOV_R32_R32),
            [Shape::Reg32, Shape::Imm] => Some(forms::MOV_R32_IMM32),
            [Shape::Reg32, Shape::Mem] => Some(forms::MOV_R32_MEM32),
            [Shape::Mem, Shape::Reg32] => Some(forms::MOV_MEM32_R32),
            [Shape::Reg16, Shape::Reg16] => Some(forms::MOV_R16_R16),
            [Shape::Reg16, Shape::Imm] => Some(forms::MOV_R16_IMM16),
            [Shape::Reg8, Shape::Reg8] => Some(forms::MOV_R8_R8),
            [Shape::Reg8, Shape::Imm] => Some(forms::MOV_R8_IMM8),
            [Shape::Reg8, Shape::Mem] => Some(forms::MOV_R8_MEM8),
            [Shape::Mem, Shape::Reg8] => Some(forms::MOV_MEM8_R8),
            _ => None,
        },
        iclass::XED_ICLASS_ADD => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::ADD_R64_R64),
            [Shape::Reg64, Shape::Imm] => Some(forms::ADD_R64_IMM32),
            [Shape::Reg64, Shape::Mem] => Some(forms::ADD_R64_MEM64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::ADD_R32_R32),
            [Shape::Reg32, Shape::Imm] => Some(forms::ADD_R32_IMM8),
            [Shape::Reg32, Shape::Mem] => Some(forms::ADD_R32_MEM32),
            [Shape::Reg8, Shape::Mem] => Some(forms::ADD_R8_MEM8),
            _ => None,
        },
        iclass::XED_ICLASS_SUB => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::SUB_R64_R64),
            [Shape::Reg64, Shape::Imm] => Some(forms::SUB_R64_IMM32),
            [Shape::Reg32, Shape::Reg32] => Some(forms::SUB_R32_R32),
            [Shape::Reg32, Shape::Imm] => Some(forms::SUB_R32_IMM8),
            [Shape::Reg32, Shape::Mem] => Some(forms::SUB_R32_MEM32),
            [Shape::Reg8, Shape::Mem] => Some(forms::SUB_R8_MEM8),
            _ => None,
        },
        iclass::XED_ICLASS_CMP => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMP_R64_R64),
            [Shape::Reg64, Shape::Imm] => Some(forms::CMP_R64_IMM32),
            [Shape::Reg64, Shape::Mem] => Some(forms::CMP_R64_MEM64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMP_R32_R32),
            [Shape::Reg32, Shape::Imm] => Some(forms::CMP_R32_IMM8),
            [Shape::Reg32, Shape::Mem] => Some(forms::CMP_R32_MEM32),
            [Shape::Reg8, Shape::Mem] => Some(forms::CMP_R8_MEM8),
            _ => None,
        },
        iclass::XED_ICLASS_AND => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::AND_R64_R64),
            [Shape::Reg64, Shape::Imm] => Some(forms::AND_R64_IMM32),
            [Shape::Reg32, Shape::Reg32] => Some(forms::AND_R32_R32),
            [Shape::Reg32, Shape::Imm] => Some(forms::AND_R32_IMM32),
            _ => None,
        },
        iclass::XED_ICLASS_OR => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::OR_R64_R64),
            [Shape::Reg64, Shape::Imm] => Some(forms::OR_R64_IMM32),
            [Shape::Reg32, Shape::Reg32] => Some(forms::OR_R32_R32),
            [Shape::Reg32, Shape::Imm] => Some(forms::OR_R32_IMM32),
            _ => None,
        },
        iclass::XED_ICLASS_XOR => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::XOR_R64_R64),
            [Shape::Reg64, Shape::Imm] => Some(forms::XOR_R64_IMM32),
            [Shape::Reg32, Shape::Reg32] => Some(forms::XOR_R32_R32),
            [Shape::Reg32, Shape::Imm] => Some(forms::XOR_R32_IMM32),
            _ => None,
        },
        iclass::XED_ICLASS_TEST => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::TEST_R64_R64),
            [Shape::Reg64, Shape::Imm] => Some(forms::TEST_R64_IMM32),
            [Shape::Reg32, Shape::Imm] => Some(forms::TEST_R32_IMM32),
            _ => None,
        },
        iclass::XED_ICLASS_SHL => match shapes {
            [Shape::Reg64, Shape::Imm] => Some(forms::SHL_R64_IMM8),
            [Shape::Reg64] if has_cl => Some(forms::SHL_R64_CL),
            [Shape::Reg32, Shape::Imm] => Some(forms::SHL_R32_IMM8),
            [Shape::Reg32] if has_cl => Some(forms::SHL_R32_CL),
            _ => None,
        },
        iclass::XED_ICLASS_SHR => match shapes {
            [Shape::Reg64, Shape::Imm] => Some(forms::SHR_R64_IMM8),
            [Shape::Reg64] if has_cl => Some(forms::SHR_R64_CL),
            [Shape::Reg32, Shape::Imm] => Some(forms::SHR_R32_IMM8),
            [Shape::Reg32] if has_cl => Some(forms::SHR_R32_CL),
            _ => None,
        },
        iclass::XED_ICLASS_SAR => match shapes {
            [Shape::Reg64, Shape::Imm] => Some(forms::SAR_R64_IMM8),
            [Shape::Reg64] if has_cl => Some(forms::SAR_R64_CL),
            [Shape::Reg32, Shape::Imm] => Some(forms::SAR_R32_IMM8),
            [Shape::Reg32] if has_cl => Some(forms::SAR_R32_CL),
            _ => None,
        },
        iclass::XED_ICLASS_ROL => match shapes {
            [Shape::Reg64, Shape::Imm] => Some(forms::ROL_R64_IMM8),
            [Shape::Reg64] if has_cl => Some(forms::ROL_R64_CL),
            [Shape::Reg32, Shape::Imm] => Some(forms::ROL_R32_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_ROR => match shapes {
            [Shape::Reg64, Shape::Imm] => Some(forms::ROR_R64_IMM8),
            [Shape::Reg64] if has_cl => Some(forms::ROR_R64_CL),
            [Shape::Reg32, Shape::Imm] => Some(forms::ROR_R32_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_RCL => match shapes {
            [Shape::Reg64, Shape::Imm] => Some(forms::RCL_R64_IMM8),
            [Shape::Reg64] if has_cl => Some(forms::RCL_R64_CL),
            _ => None,
        },
        iclass::XED_ICLASS_RCR => match shapes {
            [Shape::Reg64, Shape::Imm] => Some(forms::RCR_R64_IMM8),
            [Shape::Reg64] if has_cl => Some(forms::RCR_R64_CL),
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
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::IMUL_R64_R64_IMM32),
            [Shape::Reg32, Shape::Reg32] => Some(forms::IMUL_R32_R32),
            [Shape::Reg32, Shape::Reg32, Shape::Imm] => Some(forms::IMUL_R32_R32_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_PUSH => match shapes {
            [Shape::Reg64] => Some(forms::PUSH_R64),
            [Shape::Reg32] => Some(forms::PUSH_R32),
            [Shape::Imm] => Some(forms::PUSH_IMM32),
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
            _ => None,
        },
        iclass::XED_ICLASS_MOVZX => match shapes {
            [Shape::Reg64, Shape::Reg32] => Some(forms::MOVZX_R64_R32),
            [Shape::Reg64, Shape::Reg8] => Some(forms::MOVZX_R64_R8),
            [Shape::Reg32, Shape::Reg16] => Some(forms::MOVZX_R32_R16),
            [Shape::Reg32, Shape::Reg8] => Some(forms::MOVZX_R32_R8),
            _ => None,
        },
        iclass::XED_ICLASS_MOVSX => match shapes {
            [Shape::Reg64, Shape::Reg32] => Some(forms::MOVSX_R64_R32),
            [Shape::Reg64, Shape::Reg8] => Some(forms::MOVSX_R64_R8),
            [Shape::Reg32, Shape::Reg16] => Some(forms::MOVSX_R32_R16),
            [Shape::Reg32, Shape::Reg8] => Some(forms::MOVSX_R32_R8),
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
            _ => None,
        },
        iclass::XED_ICLASS_BSR => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::BSR_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_POPCNT => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::POPCNT_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_TZCNT => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::TZCNT_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_LZCNT => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::LZCNT_R64_R64),
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
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVZ_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVNZ => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVNZ_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVL => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVL_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVNL => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVGE_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVLE => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVLE_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVNLE => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVG_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVB => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVB_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVNB => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVAE_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVBE => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVBE_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVNBE => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVA_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVS => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVS_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVNS => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVNS_R64_R64),
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
            [Shape::Rel] => Some(forms::JMP_REL32),
            _ => None,
        },
        iclass::XED_ICLASS_CALL_NEAR => match shapes {
            [Shape::Rel] => Some(forms::CALL_REL32),
            _ => None,
        },
        iclass::XED_ICLASS_RET_NEAR => match shapes {
            [] => Some(forms::RET),
            _ => None,
        },
        // `syscall` is executed by the environment model, not the semantic
        // corpus; it maps to the runtime's reserved syscall form id.
        iclass::XED_ICLASS_SYSCALL => Some(crate::SYSCALL_FORM_ID),
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
        // Simplified corpus semantics: mul/div are deliberately not mapped.
        assert_eq!(mapped(&[0x48, 0xF7, 0xE3])?, None);
        // SSE forms are not yet mapped.
        assert_eq!(mapped(&[0x0F, 0x58, 0xC1])?, None);
        // cpuid has no corpus semantics.
        assert_eq!(mapped(&[0x0F, 0xA2])?, None);
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
