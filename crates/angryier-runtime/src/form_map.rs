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
use angryier_semantics_intel64::{amx_forms, evex_forms, forms};

/// Form id reported for instructions XED can decode but the corpus cannot
/// execute exactly. No registered corpus form uses this id.
pub const UNMAPPED_FORM_ID: u32 = 0;

// The x87 iclasses come from the bridge's `iclass` re-export. Pin their
// numeric values (xed-2024.05.20) so a bindings update that renumbers them
// fails to compile instead of silently mis-mapping.
const _: () = {
    assert!(iclass::XED_ICLASS_FADD == 249);
    assert!(iclass::XED_ICLASS_FCOMI == 263);
    assert!(iclass::XED_ICLASS_FCOMIP == 264);
    assert!(iclass::XED_ICLASS_FDIV == 270);
    assert!(iclass::XED_ICLASS_FDIVR == 272);
    assert!(iclass::XED_ICLASS_FLD == 291);
    assert!(iclass::XED_ICLASS_FLD1 == 292);
    assert!(iclass::XED_ICLASS_FLDZ == 300);
    assert!(iclass::XED_ICLASS_FMUL == 301);
    assert!(iclass::XED_ICLASS_FNINIT == 304);
    assert!(iclass::XED_ICLASS_FST == 321);
    assert!(iclass::XED_ICLASS_FSTP == 322);
    assert!(iclass::XED_ICLASS_FSTPNCE == 323);
    assert!(iclass::XED_ICLASS_FSUB == 324);
    assert!(iclass::XED_ICLASS_FSUBR == 326);
    assert!(iclass::XED_ICLASS_FUCOMI == 330);
    assert!(iclass::XED_ICLASS_FUCOMIP == 331);
};

/// Sentinel form ids for string instructions. These are not corpus forms: a
/// `rep`-prefixed string instruction encodes an internal loop, which cannot be
/// straight-line corpus semantics. The runtime executes them directly.
pub const STOSB_FORM_ID: u32 = 0xFFFF_0000;
pub const STOSW_FORM_ID: u32 = 0xFFFF_0001;
pub const STOSD_FORM_ID: u32 = 0xFFFF_0002;
pub const STOSQ_FORM_ID: u32 = 0xFFFF_0003;
pub const MOVSB_FORM_ID: u32 = 0xFFFF_0004;
pub const LODSB_FORM_ID: u32 = 0xFFFF_0010;
pub const LODSW_FORM_ID: u32 = 0xFFFF_0011;
pub const LODSD_FORM_ID: u32 = 0xFFFF_0012;
pub const LODSQ_FORM_ID: u32 = 0xFFFF_0013;
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
pub const REP_INSB_FORM_ID: u32 = 0xFFFF_0014;
pub const REP_INSW_FORM_ID: u32 = 0xFFFF_0015;
pub const REP_INSD_FORM_ID: u32 = 0xFFFF_0016;
pub const REP_OUTSB_FORM_ID: u32 = 0xFFFF_0017;
pub const REP_OUTSW_FORM_ID: u32 = 0xFFFF_0018;
pub const REP_OUTSD_FORM_ID: u32 = 0xFFFF_0019;
pub const CMPSB_FORM_ID: u32 = 0xFFFF_001A;
pub const CMPSW_FORM_ID: u32 = 0xFFFF_001B;
pub const CMPSD_FORM_ID: u32 = 0xFFFF_001C;
pub const CMPSQ_FORM_ID: u32 = 0xFFFF_001D;
pub const SCASB_FORM_ID: u32 = 0xFFFF_001E;
pub const SCASW_FORM_ID: u32 = 0xFFFF_001F;
pub const SCASD_FORM_ID: u32 = 0xFFFF_0020;
pub const SCASQ_FORM_ID: u32 = 0xFFFF_0021;
pub const REPE_CMPSB_FORM_ID: u32 = 0xFFFF_0022;
pub const REPE_CMPSW_FORM_ID: u32 = 0xFFFF_0023;
pub const REPE_CMPSD_FORM_ID: u32 = 0xFFFF_0024;
pub const REPE_CMPSQ_FORM_ID: u32 = 0xFFFF_0025;
pub const REPNE_CMPSB_FORM_ID: u32 = 0xFFFF_0026;
pub const REPNE_CMPSW_FORM_ID: u32 = 0xFFFF_0027;
pub const REPNE_CMPSD_FORM_ID: u32 = 0xFFFF_0028;
pub const REPNE_CMPSQ_FORM_ID: u32 = 0xFFFF_0029;
pub const REPE_SCASB_FORM_ID: u32 = 0xFFFF_002A;
pub const REPE_SCASW_FORM_ID: u32 = 0xFFFF_002B;
pub const REPE_SCASD_FORM_ID: u32 = 0xFFFF_002C;
pub const REPE_SCASQ_FORM_ID: u32 = 0xFFFF_002D;
pub const REPNE_SCASB_FORM_ID: u32 = 0xFFFF_002E;
pub const REPNE_SCASW_FORM_ID: u32 = 0xFFFF_002F;
pub const REPNE_SCASD_FORM_ID: u32 = 0xFFFF_0030;
pub const REPNE_SCASQ_FORM_ID: u32 = 0xFFFF_0031;

pub const REP_CMPSB_FORM_ID: u32 = REPE_CMPSB_FORM_ID;
pub const REP_CMPSW_FORM_ID: u32 = REPE_CMPSW_FORM_ID;
pub const REP_CMPSD_FORM_ID: u32 = REPE_CMPSD_FORM_ID;
pub const REP_CMPSQ_FORM_ID: u32 = REPE_CMPSQ_FORM_ID;
pub const REP_SCASB_FORM_ID: u32 = REPE_SCASB_FORM_ID;
pub const REP_SCASW_FORM_ID: u32 = REPE_SCASW_FORM_ID;
pub const REP_SCASD_FORM_ID: u32 = REPE_SCASD_FORM_ID;
pub const REP_SCASQ_FORM_ID: u32 = REPE_SCASQ_FORM_ID;

/// Operand shape used to discriminate forms that share an XED iclass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    Reg64,
    Reg32,
    Reg16,
    Reg8,
    /// An x87 stack register (80-bit view of an X87_BASE parent).
    Stack,
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
    /// 80-bit x87 extended-precision memory access.
    Mem80,
    #[allow(dead_code)]
    FarPtr,
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
    /// AMX tile register (TMM0..TMM7, 8192-bit view of a tile parent).
    Tmm,
    Rel,
    Other,
}

fn shape_of(operand: &Operand) -> Shape {
    match &operand.kind {
        OperandKind::Register(register)
            if (register_id::X87_BASE..register_id::X87_BASE + 8).contains(&register.parent.0) =>
        {
            Shape::Stack
        }
        OperandKind::Register(register)
            if (register_id::TILE_BASE..register_id::TILE_BASE + 8).contains(&register.parent.0)
                || register.width_bits == 8192 =>
        {
            Shape::Tmm
        }
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
            256 | 512 | 0 => Shape::Mem,
            8 => Shape::Mem8,
            16 => Shape::Mem16,
            32 => Shape::Mem32,
            64 => Shape::Mem64,
            80 => Shape::Mem80,
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

/// Width of the suppressed stack-memory operand reported for the APX
/// `PUSH2`/`PUSH2P`/`POP2`/`POP2P` register-pair encodings. Both members of a
/// pair decode to the same `[Reg64, Reg64]` shape, so this width is the only
/// decoder-visible distinction between the plain variants (64-bit stack
/// slots) and the promoted `P` variants (128-bit stack slots).
fn stack_pair_width(decoded: &DecodedInstruction) -> Option<u16> {
    decoded
        .operands
        .iter()
        .find(|operand| {
            operand.visibility == OperandVisibility::Suppressed && matches!(operand.kind, OperandKind::Memory(_))
        })
        .map(|operand| operand.width_bits)
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
    let immediate_width = decoded
        .operands
        .iter()
        .find(|operand| matches!(operand.kind, OperandKind::Immediate(_)))
        .map(|operand| operand.width_bits);

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
            [Shape::Reg16]
                if matches!(
                    decoded.operands.first().map(|operand| operand.access),
                    Some(angryier_arch::AccessKind::Write)
                ) =>
            {
                Some(forms::MOV_R16_SREG)
            }
            [Shape::Reg32]
                if matches!(
                    decoded.operands.first().map(|operand| operand.access),
                    Some(angryier_arch::AccessKind::Write)
                ) =>
            {
                Some(forms::MOV_R32_SREG)
            }
            [Shape::Reg64]
                if matches!(
                    decoded.operands.first().map(|operand| operand.access),
                    Some(angryier_arch::AccessKind::Write)
                ) =>
            {
                Some(forms::MOV_R64_SREG)
            }
            [Shape::Mem16]
                if matches!(
                    decoded.operands.first().map(|operand| operand.access),
                    Some(angryier_arch::AccessKind::Write)
                ) =>
            {
                Some(forms::MOV_MEM16_SREG)
            }
            [Shape::Reg16]
                if matches!(
                    decoded.operands.first().map(|operand| operand.access),
                    Some(angryier_arch::AccessKind::Read)
                ) =>
            {
                Some(forms::MOV_SREG_R16)
            }
            [Shape::Mem16]
                if matches!(
                    decoded.operands.first().map(|operand| operand.access),
                    Some(angryier_arch::AccessKind::Read)
                ) =>
            {
                Some(forms::MOV_SREG_MEM16)
            }
            _ => None,
        },
        iclass::XED_ICLASS_ADD | iclass::XED_ICLASS_ADD_LOCK => match shapes {
            // APX NDD three-destination encodings.
            [Shape::Reg64, Shape::Reg64, Shape::Reg64] => Some(forms::ADD_R64_R64_R64_NDD),
            [Shape::Reg32, Shape::Reg32, Shape::Reg32] => Some(forms::ADD_R32_R32_R32_NDD),
            [Shape::Mem32, Shape::Reg32] => Some(forms::ADD_MEM32_R32),
            [Shape::Reg16, Shape::Imm] if immediate_width == Some(8) => Some(forms::ADD_R16_IMM8),
            [Shape::Mem16, Shape::Imm] if immediate_width == Some(8) => Some(forms::ADD_MEM16_IMM8),
            [Shape::Reg64, Shape::Reg64] => Some(forms::ADD_R64_R64),
            [Shape::Reg64, Shape::Imm] => Some(forms::ADD_R64_IMM32),
            [Shape::Reg64, Shape::Mem64] => Some(forms::ADD_R64_MEM64),
            [Shape::Mem64, Shape::Reg64] => Some(forms::ADD_MEM64_R64),
            [Shape::Mem64, Shape::Imm] => Some(forms::ADD_MEM64_IMM32),
            [Shape::Mem32, Shape::Imm] => Some(forms::ADD_MEM32_IMM32),
            [Shape::Reg32, Shape::Reg32] => Some(forms::ADD_R32_R32),
            [Shape::Reg16, Shape::Reg16] => Some(forms::ADD_R16_R16),
            [Shape::Reg16, Shape::Imm] => Some(forms::ADD_R16_IMM16),
            [Shape::Reg32, Shape::Imm] => Some(forms::ADD_R32_IMM8),
            [Shape::Reg32, Shape::Mem32] => Some(forms::ADD_R32_MEM32),
            [Shape::Reg8, Shape::Mem8] => Some(forms::ADD_R8_MEM8),
            [Shape::Mem8, Shape::Reg8] => Some(forms::ADD_MEM8_R8),
            [Shape::Mem8, Shape::Imm] => Some(forms::ADD_MEM8_IMM8),
            [Shape::Mem16, Shape::Imm] => Some(forms::ADD_MEM16_IMM16_V2),
            [Shape::Reg8, Shape::Reg8] => Some(forms::ADD_R8_R8),
            [Shape::Reg8, Shape::Imm] => Some(forms::ADD_R8_IMM8),
            [Shape::Reg16, Shape::Mem16] => Some(forms::ADD_R16_MEM16),
            [Shape::Mem16, Shape::Reg16] => Some(forms::ADD_MEM16_R16),
            _ => None,
        },
        iclass::XED_ICLASS_SUB | iclass::XED_ICLASS_SUB_LOCK => match shapes {
            // APX NDD three-destination encodings.
            [Shape::Reg64, Shape::Reg64, Shape::Reg64] => Some(forms::SUB_R64_R64_R64_NDD),
            [Shape::Reg32, Shape::Reg32, Shape::Reg32] => Some(forms::SUB_R32_R32_R32_NDD),
            [Shape::Reg16, Shape::Imm] if immediate_width == Some(8) => Some(forms::SUB_R16_IMM8),
            [Shape::Mem16, Shape::Imm] if immediate_width == Some(8) => Some(forms::SUB_MEM16_IMM8),
            [Shape::Reg64, Shape::Reg64] => Some(forms::SUB_R64_R64),
            [Shape::Reg64, Shape::Imm] => Some(forms::SUB_R64_IMM32),
            [Shape::Reg32, Shape::Reg32] => Some(forms::SUB_R32_R32),
            [Shape::Reg32, Shape::Imm] => Some(forms::SUB_R32_IMM8),
            [Shape::Reg32, Shape::Mem32] => Some(forms::SUB_R32_MEM32),
            [Shape::Reg16, Shape::Imm] => Some(forms::SUB_R16_IMM16),
            [Shape::Reg8, Shape::Mem8] => Some(forms::SUB_R8_MEM8),
            [Shape::Mem8, Shape::Reg8] => Some(forms::SUB_MEM8_R8),
            [Shape::Mem8, Shape::Imm] => Some(forms::SUB_MEM8_IMM8),
            [Shape::Mem16, Shape::Imm] => Some(forms::SUB_MEM16_IMM16_V2),
            [Shape::Reg8, Shape::Reg8] => Some(forms::SUB_R8_R8),
            [Shape::Reg8, Shape::Imm] => Some(forms::SUB_R8_IMM8),
            [Shape::Mem32, Shape::Imm] => Some(forms::SUB_MEM32_IMM32),
            [Shape::Mem64, Shape::Imm] => Some(forms::SUB_MEM64_IMM32),
            [Shape::Reg64, Shape::Mem64] => Some(forms::SUB_R64_MEM64),
            [Shape::Mem64, Shape::Reg64] => Some(forms::SUB_MEM64_R64),
            [Shape::Mem32, Shape::Reg32] => Some(forms::SUB_MEM32_R32),
            [Shape::Reg16, Shape::Reg16] => Some(forms::SUB_R16_R16),
            [Shape::Reg16, Shape::Mem16] => Some(forms::SUB_R16_MEM16),
            [Shape::Mem16, Shape::Reg16] => Some(forms::SUB_MEM16_R16),
            _ => None,
        },
        iclass::XED_ICLASS_CMP => match shapes {
            [Shape::Mem16, Shape::Imm] if immediate_width == Some(8) => Some(forms::CMP_MEM16_IMM8),
            [Shape::Reg16, Shape::Imm] if immediate_width == Some(8) => Some(forms::CMP_R16_IMM8),
            [Shape::Mem16, Shape::Imm] if immediate_width == Some(8) => Some(forms::CMP_MEM16_IMM8),
            [Shape::Reg8, Shape::Reg8] => Some(forms::CMP_R8_R8),
            [Shape::Reg8, Shape::Imm] => Some(forms::CMP_R8_IMM8),
            [Shape::Mem8, Shape::Imm] => Some(forms::CMP_MEM8_IMM8),
            [Shape::Mem64, Shape::Reg64] => Some(forms::CMP_MEM64_R64),
            [Shape::Mem32, Shape::Reg32] => Some(forms::CMP_MEM32_R32),
            [Shape::Mem8, Shape::Reg8] => Some(forms::CMP_MEM8_R8),
            [Shape::Mem16, Shape::Reg16] => Some(forms::CMP_MEM16_R16_V2),
            [Shape::Mem32, Shape::Imm] => Some(forms::CMP_MEM32_IMM32),
            [Shape::Mem16, Shape::Imm] => Some(forms::CMP_MEM16_IMM16_V2),
            // The 16-bit immediate forms are memory-shaped in the corpus, but
            // their operand-generic providers cover register destinations
            // exactly (same reuse as the CMOV memory shapes above).
            [Shape::Reg16, Shape::Imm] => Some(forms::CMP_R16_IMM16),

            [Shape::Reg64, Shape::Reg64] => Some(forms::CMP_R64_R64),
            [Shape::Reg64, Shape::Imm] => Some(forms::CMP_R64_IMM32),
            [Shape::Reg64, Shape::Mem64] => Some(forms::CMP_R64_MEM64),
            [Shape::Mem64, Shape::Imm] => Some(forms::CMP_MEM64_IMM32),
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMP_R32_R32),
            [Shape::Reg32, Shape::Imm] => Some(forms::CMP_R32_IMM8),
            [Shape::Reg32, Shape::Mem32] => Some(forms::CMP_R32_MEM32),
            [Shape::Reg8, Shape::Mem8] => Some(forms::CMP_R8_MEM8),
            [Shape::Reg16, Shape::Reg16] => Some(forms::CMP_R16_R16),
            [Shape::Reg16, Shape::Mem16] => Some(forms::CMP_R16_MEM16),
            _ => None,
        },
        iclass::XED_ICLASS_AND | iclass::XED_ICLASS_AND_LOCK => match shapes {
            // APX NDD three-destination encodings.
            [Shape::Reg64, Shape::Reg64, Shape::Reg64] => Some(forms::AND_R64_R64_R64_NDD),
            [Shape::Reg32, Shape::Reg32, Shape::Reg32] => Some(forms::AND_R32_R32_R32_NDD),
            [Shape::Reg16, Shape::Imm] if immediate_width == Some(8) => Some(forms::AND_R16_IMM8),
            [Shape::Mem16, Shape::Imm] if immediate_width == Some(8) => Some(forms::AND_MEM16_IMM8),
            [Shape::Reg16, Shape::Reg16] => Some(forms::AND_R16_R16),
            [Shape::Reg16, Shape::Mem16] => Some(forms::AND_R16_MEM16),
            [Shape::Mem16, Shape::Reg16] => Some(forms::AND_MEM16_R16),
            [Shape::Reg64, Shape::Reg64] => Some(forms::AND_R64_R64),
            [Shape::Reg64, Shape::Imm] => Some(forms::AND_R64_IMM32),
            [Shape::Reg32, Shape::Reg32] => Some(forms::AND_R32_R32),
            [Shape::Reg32, Shape::Imm] => Some(forms::AND_R32_IMM32),
            [Shape::Reg32, Shape::Mem32] => Some(forms::AND_R32_MEM32),
            [Shape::Reg64, Shape::Mem64] => Some(forms::AND_R64_MEM64),
            [Shape::Reg16, Shape::Imm] => Some(forms::AND_R16_IMM16),
            [Shape::Reg8, Shape::Mem8] => Some(forms::AND_R8_MEM8),
            [Shape::Mem32, Shape::Imm] => Some(forms::AND_MEM32_IMM32),
            [Shape::Mem64, Shape::Imm] => Some(forms::AND_MEM64_IMM32),
            [Shape::Mem32, Shape::Reg32] => Some(forms::AND_MEM32_R32),
            [Shape::Mem64, Shape::Reg64] => Some(forms::AND_MEM64_R64),
            [Shape::Mem8, Shape::Reg8] => Some(forms::AND_MEM8_R8),
            [Shape::Mem8, Shape::Imm] => Some(forms::AND_MEM8_IMM8),
            [Shape::Mem16, Shape::Imm] => Some(forms::AND_MEM16_IMM16_V2),
            [Shape::Reg8, Shape::Reg8] => Some(forms::AND_R8_R8),
            [Shape::Reg8, Shape::Imm] => Some(forms::AND_R8_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_OR | iclass::XED_ICLASS_OR_LOCK => match shapes {
            // APX NDD three-destination encodings.
            [Shape::Reg64, Shape::Reg64, Shape::Reg64] => Some(forms::OR_R64_R64_R64_NDD),
            [Shape::Reg32, Shape::Reg32, Shape::Reg32] => Some(forms::OR_R32_R32_R32_NDD),
            [Shape::Reg16, Shape::Imm] if immediate_width == Some(8) => Some(forms::OR_R16_IMM8),
            [Shape::Mem16, Shape::Imm] if immediate_width == Some(8) => Some(forms::OR_MEM16_IMM8),
            [Shape::Reg64, Shape::Reg64] => Some(forms::OR_R64_R64),
            [Shape::Reg64, Shape::Imm] => Some(forms::OR_R64_IMM32),
            [Shape::Reg32, Shape::Reg32] => Some(forms::OR_R32_R32),
            [Shape::Reg32, Shape::Imm] => Some(forms::OR_R32_IMM32),
            [Shape::Reg32, Shape::Mem32] => Some(forms::OR_R32_MEM32),
            [Shape::Reg64, Shape::Mem64] => Some(forms::OR_R64_MEM64),
            [Shape::Reg16, Shape::Imm] => Some(forms::OR_R16_IMM16),
            [Shape::Reg8, Shape::Mem8] => Some(forms::OR_R8_MEM8),
            [Shape::Mem32, Shape::Imm] => Some(forms::OR_MEM32_IMM32),
            [Shape::Mem64, Shape::Imm] => Some(forms::OR_MEM64_IMM32),
            [Shape::Mem32, Shape::Reg32] => Some(forms::OR_MEM32_R32),
            [Shape::Mem64, Shape::Reg64] => Some(forms::OR_MEM64_R64),
            [Shape::Mem8, Shape::Reg8] => Some(forms::OR_MEM8_R8),
            [Shape::Mem8, Shape::Imm] => Some(forms::OR_MEM8_IMM8),
            [Shape::Mem16, Shape::Imm] => Some(forms::OR_MEM16_IMM16_V2),
            [Shape::Reg8, Shape::Reg8] => Some(forms::OR_R8_R8),
            [Shape::Reg8, Shape::Imm] => Some(forms::OR_R8_IMM8),
            [Shape::Reg16, Shape::Reg16] => Some(forms::OR_R16_R16),
            [Shape::Reg16, Shape::Mem16] => Some(forms::OR_R16_MEM16),
            [Shape::Mem16, Shape::Reg16] => Some(forms::OR_MEM16_R16),
            _ => None,
        },
        iclass::XED_ICLASS_XOR | iclass::XED_ICLASS_XOR_LOCK => match shapes {
            // APX NDD three-destination encodings.
            [Shape::Reg64, Shape::Reg64, Shape::Reg64] => Some(forms::XOR_R64_R64_R64_NDD),
            [Shape::Reg32, Shape::Reg32, Shape::Reg32] => Some(forms::XOR_R32_R32_R32_NDD),
            [Shape::Reg16, Shape::Imm] if immediate_width == Some(8) => Some(forms::XOR_R16_IMM8),
            [Shape::Mem16, Shape::Imm] if immediate_width == Some(8) => Some(forms::XOR_MEM16_IMM8),
            [Shape::Reg64, Shape::Reg64] => Some(forms::XOR_R64_R64),
            [Shape::Reg64, Shape::Imm] => Some(forms::XOR_R64_IMM32),
            [Shape::Reg32, Shape::Reg32] => Some(forms::XOR_R32_R32),
            [Shape::Reg32, Shape::Imm] => Some(forms::XOR_R32_IMM32),
            [Shape::Reg32, Shape::Mem32] => Some(forms::XOR_R32_MEM32),
            [Shape::Reg64, Shape::Mem64] => Some(forms::XOR_R64_MEM64),
            [Shape::Reg16, Shape::Imm] => Some(forms::XOR_R16_IMM16),
            [Shape::Reg8, Shape::Mem8] => Some(forms::XOR_R8_MEM8),
            [Shape::Mem32, Shape::Imm] => Some(forms::XOR_MEM32_IMM32),
            [Shape::Mem64, Shape::Imm] => Some(forms::XOR_MEM64_IMM32),
            [Shape::Mem32, Shape::Reg32] => Some(forms::XOR_MEM32_R32),
            [Shape::Mem64, Shape::Reg64] => Some(forms::XOR_MEM64_R64),
            [Shape::Mem8, Shape::Reg8] => Some(forms::XOR_MEM8_R8),
            [Shape::Mem8, Shape::Imm] => Some(forms::XOR_MEM8_IMM8),
            [Shape::Mem16, Shape::Imm] => Some(forms::XOR_MEM16_IMM16_V2),
            [Shape::Reg8, Shape::Reg8] => Some(forms::XOR_R8_R8),
            [Shape::Reg8, Shape::Imm] => Some(forms::XOR_R8_IMM8),
            [Shape::Reg16, Shape::Reg16] => Some(forms::XOR_R16_R16),
            [Shape::Reg16, Shape::Mem16] => Some(forms::XOR_R16_MEM16),
            [Shape::Mem16, Shape::Reg16] => Some(forms::XOR_MEM16_R16),
            _ => None,
        },
        iclass::XED_ICLASS_TEST => match shapes {
            [Shape::Mem32, Shape::Reg32] => Some(forms::TEST_MEM32_R32),
            [Shape::Mem64, Shape::Reg64] => Some(forms::TEST_MEM64_R64),
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
            // APX NDD three-destination encodings.
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::SHL_R64_R64_IMM8_NDD),
            [Shape::Reg32, Shape::Reg32, Shape::Imm] => Some(forms::SHL_R32_R32_IMM8_NDD),
            [Shape::Mem8, Shape::Imm] => Some(forms::SHL_MEM8_IMM8),
            [Shape::Mem8] if has_cl => Some(forms::SHL_MEM8_CL),
            [Shape::Reg8] if has_cl => Some(forms::SHL_R8_CL),
            [Shape::Mem16, Shape::Imm] => Some(forms::SHL_MEM16_IMM8),
            [Shape::Mem16] if has_cl => Some(forms::SHL_MEM16_CL),
            [Shape::Mem32, Shape::Imm] => Some(forms::SHL_MEM32_IMM8),
            [Shape::Mem32] if has_cl => Some(forms::SHL_MEM32_CL),
            [Shape::Mem64, Shape::Imm] => Some(forms::SHL_MEM64_IMM8),
            [Shape::Mem64] if has_cl => Some(forms::SHL_MEM64_CL),
            [Shape::Reg64, Shape::Imm] => Some(forms::SHL_R64_IMM8),
            [Shape::Reg64] if has_cl => Some(forms::SHL_R64_CL),
            // `D1` encodings carry an implicit immediate operand of 1.
            [Shape::Reg64] => Some(forms::SHL_R64_IMM8),
            [Shape::Reg32, Shape::Imm] => Some(forms::SHL_R32_IMM8),
            [Shape::Reg8, Shape::Imm] => Some(forms::SHL_R8_IMM8),
            [Shape::Reg32] if has_cl => Some(forms::SHL_R32_CL),
            [Shape::Reg32] => Some(forms::SHL_R32_IMM8),
            [Shape::Reg16, Shape::Imm] => Some(forms::SHL_R16_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_SHR => match shapes {
            // APX NDD three-destination encodings.
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::SHR_R64_R64_IMM8_NDD),
            [Shape::Reg32, Shape::Reg32, Shape::Imm] => Some(forms::SHR_R32_R32_IMM8_NDD),
            [Shape::Mem8, Shape::Imm] => Some(forms::SHR_MEM8_IMM8),
            [Shape::Mem8] if has_cl => Some(forms::SHR_MEM8_CL),
            [Shape::Reg8] if has_cl => Some(forms::SHR_R8_CL),
            [Shape::Mem16, Shape::Imm] => Some(forms::SHR_MEM16_IMM8),
            [Shape::Mem16] if has_cl => Some(forms::SHR_MEM16_CL),
            [Shape::Mem32, Shape::Imm] => Some(forms::SHR_MEM32_IMM8),
            [Shape::Mem32] if has_cl => Some(forms::SHR_MEM32_CL),
            [Shape::Mem64, Shape::Imm] => Some(forms::SHR_MEM64_IMM8),
            [Shape::Mem64] if has_cl => Some(forms::SHR_MEM64_CL),
            [Shape::Reg64, Shape::Imm] => Some(forms::SHR_R64_IMM8),
            [Shape::Reg64] if has_cl => Some(forms::SHR_R64_CL),
            // `D1` encodings carry an implicit immediate operand of 1.
            [Shape::Reg64] => Some(forms::SHR_R64_IMM8),
            [Shape::Reg32, Shape::Imm] => Some(forms::SHR_R32_IMM8),
            [Shape::Reg32] if has_cl => Some(forms::SHR_R32_CL),
            [Shape::Reg32] => Some(forms::SHR_R32_IMM8),
            [Shape::Reg16, Shape::Imm] => Some(forms::SHR_R16_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_SAR => match shapes {
            // APX NDD three-destination encodings.
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::SAR_R64_R64_IMM8_NDD),
            [Shape::Reg32, Shape::Reg32, Shape::Imm] => Some(forms::SAR_R32_R32_IMM8_NDD),
            [Shape::Mem8, Shape::Imm] => Some(forms::SAR_MEM8_IMM8),
            [Shape::Mem8] if has_cl => Some(forms::SAR_MEM8_CL),
            [Shape::Reg8] if has_cl => Some(forms::SAR_R8_CL),
            [Shape::Mem16, Shape::Imm] => Some(forms::SAR_MEM16_IMM8),
            [Shape::Mem16] if has_cl => Some(forms::SAR_MEM16_CL),
            [Shape::Mem32, Shape::Imm] => Some(forms::SAR_MEM32_IMM8),
            [Shape::Mem32] if has_cl => Some(forms::SAR_MEM32_CL),
            [Shape::Mem64, Shape::Imm] => Some(forms::SAR_MEM64_IMM8),
            [Shape::Mem64] if has_cl => Some(forms::SAR_MEM64_CL),
            [Shape::Reg64, Shape::Imm] => Some(forms::SAR_R64_IMM8),
            [Shape::Reg64] if has_cl => Some(forms::SAR_R64_CL),
            // `D1` encodings carry an implicit immediate operand of 1.
            [Shape::Reg64] => Some(forms::SAR_R64_IMM8),
            [Shape::Reg32, Shape::Imm] => Some(forms::SAR_R32_IMM8),
            [Shape::Reg32] if has_cl => Some(forms::SAR_R32_CL),
            [Shape::Reg32] => Some(forms::SAR_R32_IMM8),
            [Shape::Reg16, Shape::Imm] => Some(forms::SAR_R16_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_ROL => match shapes {
            [Shape::Mem8, Shape::Imm] => Some(forms::ROL_MEM8_IMM8),
            [Shape::Mem8] if has_cl => Some(forms::ROL_MEM8_CL),
            [Shape::Reg8] if has_cl => Some(forms::ROL_R8_CL),
            [Shape::Mem16, Shape::Imm] => Some(forms::ROL_MEM16_IMM8),
            [Shape::Mem16] if has_cl => Some(forms::ROL_MEM16_CL),
            [Shape::Mem32, Shape::Imm] => Some(forms::ROL_MEM32_IMM8),
            [Shape::Mem32] if has_cl => Some(forms::ROL_MEM32_CL),
            [Shape::Mem64, Shape::Imm] => Some(forms::ROL_MEM64_IMM8),
            [Shape::Mem64] if has_cl => Some(forms::ROL_MEM64_CL),
            [Shape::Reg64, Shape::Imm] => Some(forms::ROL_R64_IMM8),
            [Shape::Reg64] if has_cl => Some(forms::ROL_R64_CL),
            [Shape::Reg64] => Some(forms::ROL_R64_IMM8),
            [Shape::Reg32, Shape::Imm] => Some(forms::ROL_R32_IMM8),
            [Shape::Reg32] if has_cl => Some(forms::ROL_R32_CL),
            [Shape::Reg32] => Some(forms::ROL_R32_IMM8),
            [Shape::Reg16, Shape::Imm] => Some(forms::ROL_R16_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_ROR => match shapes {
            [Shape::Mem8, Shape::Imm] => Some(forms::ROR_MEM8_IMM8),
            [Shape::Reg8, Shape::Imm] => Some(forms::ROR_R8_IMM8),
            [Shape::Mem8] if has_cl => Some(forms::ROR_MEM8_CL),
            [Shape::Reg8] if has_cl => Some(forms::ROR_R8_CL),
            [Shape::Mem16, Shape::Imm] => Some(forms::ROR_MEM16_IMM8),
            [Shape::Mem16] if has_cl => Some(forms::ROR_MEM16_CL),
            [Shape::Mem32, Shape::Imm] => Some(forms::ROR_MEM32_IMM8),
            [Shape::Mem32] if has_cl => Some(forms::ROR_MEM32_CL),
            [Shape::Mem64, Shape::Imm] => Some(forms::ROR_MEM64_IMM8),
            [Shape::Mem64] if has_cl => Some(forms::ROR_MEM64_CL),
            [Shape::Reg64, Shape::Imm] => Some(forms::ROR_R64_IMM8),
            [Shape::Reg64] if has_cl => Some(forms::ROR_R64_CL),
            [Shape::Reg64] => Some(forms::ROR_R64_IMM8),
            [Shape::Reg32, Shape::Imm] => Some(forms::ROR_R32_IMM8),
            [Shape::Reg32] if has_cl => Some(forms::ROR_R32_CL),
            [Shape::Reg32] => Some(forms::ROR_R32_IMM8),
            [Shape::Reg16, Shape::Imm] => Some(forms::ROR_R16_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_RCL => match shapes {
            [Shape::Mem8, Shape::Imm] => Some(forms::RCL_MEM8_IMM8),
            [Shape::Mem8] if has_cl => Some(forms::RCL_MEM8_CL),
            [Shape::Reg8] if has_cl => Some(forms::RCL_R8_CL),
            [Shape::Mem16, Shape::Imm] => Some(forms::RCL_MEM16_IMM8),
            [Shape::Mem16] if has_cl => Some(forms::RCL_MEM16_CL),
            [Shape::Mem32, Shape::Imm] => Some(forms::RCL_MEM32_IMM8),
            [Shape::Mem32] if has_cl => Some(forms::RCL_MEM32_CL),
            [Shape::Mem64, Shape::Imm] => Some(forms::RCL_MEM64_IMM8),
            [Shape::Mem64] if has_cl => Some(forms::RCL_MEM64_CL),
            [Shape::Reg64, Shape::Imm] => Some(forms::RCL_R64_IMM8),
            [Shape::Reg64] if has_cl => Some(forms::RCL_R64_CL),
            [Shape::Reg64] => Some(forms::RCL_R64_IMM8),
            [Shape::Reg16, Shape::Imm] => Some(forms::RCL_R16_IMM8),
            [Shape::Reg32, Shape::Imm] => Some(forms::RCL_R32_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_RCR => match shapes {
            [Shape::Mem8, Shape::Imm] => Some(forms::RCR_MEM8_IMM8),
            [Shape::Reg8, Shape::Imm] => Some(forms::RCR_R8_IMM8),
            [Shape::Mem8] if has_cl => Some(forms::RCR_MEM8_CL),
            [Shape::Reg8] if has_cl => Some(forms::RCR_R8_CL),
            [Shape::Mem16, Shape::Imm] => Some(forms::RCR_MEM16_IMM8),
            [Shape::Mem16] if has_cl => Some(forms::RCR_MEM16_CL),
            [Shape::Mem32, Shape::Imm] => Some(forms::RCR_MEM32_IMM8),
            [Shape::Mem32] if has_cl => Some(forms::RCR_MEM32_CL),
            [Shape::Mem64, Shape::Imm] => Some(forms::RCR_MEM64_IMM8),
            [Shape::Mem64] if has_cl => Some(forms::RCR_MEM64_CL),
            [Shape::Reg64, Shape::Imm] => Some(forms::RCR_R64_IMM8),
            [Shape::Reg64] if has_cl => Some(forms::RCR_R64_CL),
            [Shape::Reg64] => Some(forms::RCR_R64_IMM8),
            [Shape::Reg16, Shape::Imm] => Some(forms::RCR_R16_IMM8),
            [Shape::Reg32, Shape::Imm] => Some(forms::RCR_R32_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_INC => match shapes {
            [Shape::Reg16] => Some(forms::INC_R16),
            [Shape::Reg64] => Some(forms::INC_R64),
            [Shape::Reg32] => Some(forms::INC_R32),
            [Shape::Reg8] => Some(forms::INC_R8),
            // LOCK-prefixed and unlocked memory inc/dec (refcount paths):
            // single-vCPU RMW semantics are identical.
            [Shape::Mem64] => Some(forms::INC_MEM64),
            [Shape::Mem32] => Some(forms::INC_MEM32),
            [Shape::Mem16] => Some(forms::INC_MEM16),
            [Shape::Mem8] => Some(forms::INC_MEM8),
            _ => None,
        },
        iclass::XED_ICLASS_INC_LOCK => match shapes {
            [Shape::Mem64] => Some(forms::INC_MEM64),
            [Shape::Mem32] => Some(forms::INC_MEM32),
            [Shape::Mem16] => Some(forms::INC_MEM16),
            [Shape::Mem8] => Some(forms::INC_MEM8),
            _ => None,
        },
        iclass::XED_ICLASS_DEC => match shapes {
            [Shape::Reg64] => Some(forms::DEC_R64),
            [Shape::Reg32] => Some(forms::DEC_R32),
            [Shape::Reg8] => Some(forms::DEC_R8),
            [Shape::Mem64] => Some(forms::DEC_MEM64),
            [Shape::Mem32] => Some(forms::DEC_MEM32),
            [Shape::Mem16] => Some(forms::DEC_MEM16),
            [Shape::Mem8] => Some(forms::DEC_MEM8),
            _ => None,
        },
        iclass::XED_ICLASS_DEC_LOCK => match shapes {
            [Shape::Mem64] => Some(forms::DEC_MEM64),
            [Shape::Mem32] => Some(forms::DEC_MEM32),
            [Shape::Mem16] => Some(forms::DEC_MEM16),
            [Shape::Mem8] => Some(forms::DEC_MEM8),
            _ => None,
        },
        iclass::XED_ICLASS_NEG => match shapes {
            [Shape::Reg64] => Some(forms::NEG_R64),
            [Shape::Reg32] => Some(forms::NEG_R32),
            [Shape::Reg8] => Some(forms::NEG_R8),
            _ => None,
        },
        iclass::XED_ICLASS_NOT => match shapes {
            [Shape::Reg64] => Some(forms::NOT_R64),
            [Shape::Reg32] => Some(forms::NOT_R32),
            [Shape::Reg8] => Some(forms::NOT_R8),
            _ => None,
        },
        iclass::XED_ICLASS_IMUL => match shapes {
            [Shape::Reg16, Shape::Reg16, Shape::Imm] if immediate_width == Some(8) => Some(forms::IMUL_R16_R16_IMM8),
            [Shape::Reg16, Shape::Mem16, Shape::Imm] if immediate_width == Some(8) => Some(forms::IMUL_R16_MEM16_IMM8),
            [Shape::Reg32, Shape::Mem32, Shape::Imm] if immediate_width == Some(8) => Some(forms::IMUL_R32_MEM32_IMM8),
            [Shape::Reg64, Shape::Reg64, Shape::Imm] if immediate_width == Some(8) => Some(forms::IMUL_R64_R64_IMM8),
            [Shape::Reg64, Shape::Mem64, Shape::Imm] if immediate_width == Some(8) => Some(forms::IMUL_R64_MEM64_IMM8),
            [Shape::Reg64] => Some(forms::IMUL_1OP_R64),
            [Shape::Reg64, Shape::Reg64] => Some(forms::IMUL_R64_R64),
            [Shape::Reg64, Shape::Mem64] => Some(forms::IMUL_R64_MEM64),
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::IMUL_R64_R64_IMM32),
            [Shape::Reg32, Shape::Reg32] => Some(forms::IMUL_R32_R32),
            [Shape::Reg32, Shape::Reg32, Shape::Imm] => Some(forms::IMUL_R32_R32_IMM8),
            [Shape::Reg16, Shape::Reg16] => Some(forms::IMUL_R16_R16),
            [Shape::Reg16, Shape::Mem16] => Some(forms::IMUL_R16_MEM16),
            [Shape::Reg16, Shape::Reg16, Shape::Imm] => Some(forms::IMUL_R16_R16_IMM16),
            [Shape::Reg16, Shape::Mem16, Shape::Imm] => Some(forms::IMUL_R16_MEM16_IMM16),
            [Shape::Reg32, Shape::Mem32] => Some(forms::IMUL_R32_MEM32),
            [Shape::Reg32, Shape::Mem32, Shape::Imm] => Some(forms::IMUL_R32_MEM32_IMM32),
            [Shape::Reg64, Shape::Mem64, Shape::Imm] => Some(forms::IMUL_R64_MEM64_IMM32),
            _ => None,
        },
        iclass::XED_ICLASS_CQO => Some(forms::CQO),
        iclass::XED_ICLASS_KANDW => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Reg64] => Some(evex_forms::KANDW_K_K_K),
            _ => None,
        },
        iclass::XED_ICLASS_KANDNW => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Reg64] => Some(evex_forms::KANDNW_K_K_K),
            _ => None,
        },
        iclass::XED_ICLASS_KORW => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Reg64] => Some(evex_forms::KORW_K_K_K),
            _ => None,
        },
        iclass::XED_ICLASS_KXORW => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Reg64] => Some(evex_forms::KXORW_K_K_K),
            _ => None,
        },
        iclass::XED_ICLASS_KNOTW => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(evex_forms::KNOTW_K_K),
            _ => None,
        },
        iclass::XED_ICLASS_KXNORW => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Reg64] => Some(evex_forms::KXNORW_K_K_K),
            _ => None,
        },
        iclass::XED_ICLASS_KANDQ => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Reg64] => Some(evex_forms::KANDQ_K_K_K),
            _ => None,
        },
        iclass::XED_ICLASS_KANDNQ => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Reg64] => Some(evex_forms::KANDNQ_K_K_K),
            _ => None,
        },
        iclass::XED_ICLASS_KORQ => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Reg64] => Some(evex_forms::KORQ_K_K_K),
            _ => None,
        },
        iclass::XED_ICLASS_KXORQ => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Reg64] => Some(evex_forms::KXORQ_K_K_K),
            _ => None,
        },
        iclass::XED_ICLASS_KNOTQ => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(evex_forms::KNOTQ_K_K),
            _ => None,
        },
        iclass::XED_ICLASS_KXNORQ => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Reg64] => Some(evex_forms::KXNORQ_K_K_K),
            _ => None,
        },
        iclass::XED_ICLASS_LEAVE => Some(forms::LEAVE),
        iclass::XED_ICLASS_STOSB => Some(STOSB_FORM_ID),
        iclass::XED_ICLASS_STOSW => Some(STOSW_FORM_ID),
        iclass::XED_ICLASS_STOSD => Some(STOSD_FORM_ID),
        iclass::XED_ICLASS_STOSQ => Some(STOSQ_FORM_ID),
        iclass::XED_ICLASS_MOVSB => Some(MOVSB_FORM_ID),
        iclass::XED_ICLASS_LODSB => Some(LODSB_FORM_ID),
        iclass::XED_ICLASS_LODSW => Some(LODSW_FORM_ID),
        iclass::XED_ICLASS_LODSD => Some(LODSD_FORM_ID),
        iclass::XED_ICLASS_LODSQ => Some(LODSQ_FORM_ID),
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
            [Shape::Reg16] => Some(forms::PUSH_R16),
            [Shape::Imm] => Some(forms::PUSH_IMM32),
            [Shape::Mem64] => Some(forms::PUSH_MEM64),
            [Shape::Mem16] => Some(forms::PUSH_MEM16),
            _ => None,
        },
        iclass::XED_ICLASS_POP => match shapes {
            [Shape::Reg64] => Some(forms::POP_R64),
            [Shape::Reg32] => Some(forms::POP_R32),
            [Shape::Mem64] => Some(forms::POP_MEM64),
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
            [Shape::Reg8, Shape::Reg8] => Some(forms::XCHG_R8_R8),
            [Shape::Mem32, Shape::Reg32] => Some(forms::XCHG_MEM32_R32),
            [Shape::Mem64, Shape::Reg64] => Some(forms::XCHG_MEM64_R64),
            [Shape::Mem8, Shape::Reg8] => Some(forms::XCHG_MEM8_R8),
            _ => None,
        },
        iclass::XED_ICLASS_XADD => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::XADD_R64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::XADD_R32_R32),
            [Shape::Reg16, Shape::Reg16] => Some(forms::XADD_R16_R16),
            [Shape::Reg8, Shape::Reg8] => Some(forms::XADD_R8_R8),
            _ => None,
        },
        iclass::XED_ICLASS_CMPXCHG => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMPXCHG_R64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMPXCHG_R32_R32),
            [Shape::Reg16, Shape::Reg16] => Some(forms::CMPXCHG_R16_R16),
            [Shape::Reg8, Shape::Reg8] => Some(forms::CMPXCHG_R8_R8),
            [Shape::Mem32, Shape::Reg32] => Some(forms::CMPXCHG_MEM32_R32),
            [Shape::Mem64, Shape::Reg64] => Some(forms::CMPXCHG_MEM64_R64),
            [Shape::Mem16, Shape::Reg16] => Some(forms::CMPXCHG_MEM16_R16),
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
            [Shape::Reg32, Shape::Mem32] => Some(forms::MOVSXD_R32_MEM32),
            [Shape::Reg64, Shape::Reg32] => Some(forms::MOVSXD_R64_R32),
            [Shape::Reg64, Shape::Mem32] => Some(forms::MOVSXD_R64_MEM32),
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
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Zmm] => Some(forms::VXORPS_ZMM_ZMM_ZMM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Mem] => Some(forms::VXORPS_ZMM_ZMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VADDPS => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VADDPS_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VADDPS_YMM_YMM_MEM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Zmm] => Some(forms::VADDPS_ZMM_ZMM_ZMM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Mem] => Some(forms::VADDPS_ZMM_ZMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VSUBPS => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VSUBPS_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VSUBPS_YMM_YMM_MEM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Zmm] => Some(forms::VSUBPS_ZMM_ZMM_ZMM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Mem] => Some(forms::VSUBPS_ZMM_ZMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VMULPS => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VMULPS_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VMULPS_YMM_YMM_MEM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Zmm] => Some(forms::VMULPS_ZMM_ZMM_ZMM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Mem] => Some(forms::VMULPS_ZMM_ZMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VDIVPS => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VDIVPS_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VDIVPS_YMM_YMM_MEM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Zmm] => Some(forms::VDIVPS_ZMM_ZMM_ZMM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Mem] => Some(forms::VDIVPS_ZMM_ZMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VADDSS => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::VADDSS_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Xmm, Shape::Mem32] => Some(forms::VADDSS_XMM_XMM_MEM32),
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Xmm] => Some(evex_forms::VADDSS_EVEX_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Mem32] => Some(evex_forms::VADDSS_EVEX_XMM_XMM_MEM32),
            _ => None,
        },
        iclass::XED_ICLASS_VSUBSS => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::VSUBSS_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Xmm, Shape::Mem32] => Some(forms::VSUBSS_XMM_XMM_MEM32),
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Xmm] => Some(evex_forms::VSUBSS_EVEX_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Mem32] => Some(evex_forms::VSUBSS_EVEX_XMM_XMM_MEM32),
            _ => None,
        },
        iclass::XED_ICLASS_VMULSS => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::VMULSS_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Xmm, Shape::Mem32] => Some(forms::VMULSS_XMM_XMM_MEM32),
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Xmm] => Some(evex_forms::VMULSS_EVEX_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Mem32] => Some(evex_forms::VMULSS_EVEX_XMM_XMM_MEM32),
            _ => None,
        },
        iclass::XED_ICLASS_VDIVSS => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::VDIVSS_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Xmm, Shape::Mem32] => Some(forms::VDIVSS_XMM_XMM_MEM32),
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Xmm] => Some(evex_forms::VDIVSS_EVEX_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Mem32] => Some(evex_forms::VDIVSS_EVEX_XMM_XMM_MEM32),
            _ => None,
        },
        iclass::XED_ICLASS_VANDPS => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VANDPS_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VANDPS_YMM_YMM_MEM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Zmm] => Some(forms::VANDPS_ZMM_ZMM_ZMM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Mem] => Some(forms::VANDPS_ZMM_ZMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VANDNPS => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VANDNPS_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VANDNPS_YMM_YMM_MEM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Zmm] => Some(forms::VANDNPS_ZMM_ZMM_ZMM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Mem] => Some(forms::VANDNPS_ZMM_ZMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VORPS => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VORPS_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VORPS_YMM_YMM_MEM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Zmm] => Some(forms::VORPS_ZMM_ZMM_ZMM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Mem] => Some(forms::VORPS_ZMM_ZMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VADDPD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VADDPD_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VADDPD_YMM_YMM_MEM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Zmm] => Some(forms::VADDPD_ZMM_ZMM_ZMM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Mem] => Some(forms::VADDPD_ZMM_ZMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VSUBPD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VSUBPD_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VSUBPD_YMM_YMM_MEM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Zmm] => Some(forms::VSUBPD_ZMM_ZMM_ZMM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Mem] => Some(forms::VSUBPD_ZMM_ZMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VMULPD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VMULPD_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VMULPD_YMM_YMM_MEM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Zmm] => Some(forms::VMULPD_ZMM_ZMM_ZMM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Mem] => Some(forms::VMULPD_ZMM_ZMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VDIVPD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VDIVPD_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VDIVPD_YMM_YMM_MEM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Zmm] => Some(forms::VDIVPD_ZMM_ZMM_ZMM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Mem] => Some(forms::VDIVPD_ZMM_ZMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VADDSD => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::VADDSD_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Xmm, Shape::Mem64] => Some(forms::VADDSD_XMM_XMM_MEM64),
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Xmm] => Some(evex_forms::VADDSD_EVEX_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Mem64] => Some(evex_forms::VADDSD_EVEX_XMM_XMM_MEM64),
            _ => None,
        },
        iclass::XED_ICLASS_VSUBSD => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::VSUBSD_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Xmm, Shape::Mem64] => Some(forms::VSUBSD_XMM_XMM_MEM64),
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Xmm] => Some(evex_forms::VSUBSD_EVEX_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Mem64] => Some(evex_forms::VSUBSD_EVEX_XMM_XMM_MEM64),
            _ => None,
        },
        iclass::XED_ICLASS_VMULSD => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::VMULSD_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Xmm, Shape::Mem64] => Some(forms::VMULSD_XMM_XMM_MEM64),
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Xmm] => Some(evex_forms::VMULSD_EVEX_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Mem64] => Some(evex_forms::VMULSD_EVEX_XMM_XMM_MEM64),
            _ => None,
        },
        iclass::XED_ICLASS_VDIVSD => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::VDIVSD_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Xmm, Shape::Mem64] => Some(forms::VDIVSD_XMM_XMM_MEM64),
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Xmm] => Some(evex_forms::VDIVSD_EVEX_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Mem64] => Some(evex_forms::VDIVSD_EVEX_XMM_XMM_MEM64),
            _ => None,
        },
        iclass::XED_ICLASS_VANDPD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VANDPD_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VANDPD_YMM_YMM_MEM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Zmm] => Some(forms::VANDPD_ZMM_ZMM_ZMM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Mem] => Some(forms::VANDPD_ZMM_ZMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VANDNPD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VANDNPD_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VANDNPD_YMM_YMM_MEM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Zmm] => Some(forms::VANDNPD_ZMM_ZMM_ZMM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Mem] => Some(forms::VANDNPD_ZMM_ZMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VORPD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VORPD_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VORPD_YMM_YMM_MEM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Zmm] => Some(forms::VORPD_ZMM_ZMM_ZMM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Mem] => Some(forms::VORPD_ZMM_ZMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VXORPD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VXORPD_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VXORPD_YMM_YMM_MEM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Zmm] => Some(forms::VXORPD_ZMM_ZMM_ZMM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Mem] => Some(forms::VXORPD_ZMM_ZMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VCVTSS2SD => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::VCVTSS2SD_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Xmm, Shape::Mem32] => Some(forms::VCVTSS2SD_XMM_XMM_MEM32),
            _ => None,
        },
        iclass::XED_ICLASS_VCVTSD2SS => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::VCVTSD2SS_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Xmm, Shape::Mem64] => Some(forms::VCVTSD2SS_XMM_XMM_MEM64),
            _ => None,
        },
        iclass::XED_ICLASS_VBLENDPS => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm, Shape::Imm] => Some(forms::VBLENDPS_YMM_YMM_YMM_IMM8),
            [Shape::Ymm, Shape::Ymm, Shape::Mem, Shape::Imm] => Some(forms::VBLENDPS_YMM_YMM_MEM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_VBLENDPD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm, Shape::Imm] => Some(forms::VBLENDPD_YMM_YMM_YMM_IMM8),
            [Shape::Ymm, Shape::Ymm, Shape::Mem, Shape::Imm] => Some(forms::VBLENDPD_YMM_YMM_MEM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_VBLENDVPS => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VBLENDVPS_YMM_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem, Shape::Ymm] => Some(forms::VBLENDVPS_YMM_YMM_MEM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VBLENDVPD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VBLENDVPD_YMM_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem, Shape::Ymm] => Some(forms::VBLENDVPD_YMM_YMM_MEM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPERM2F128 => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm, Shape::Imm] => Some(forms::VPERM2F128_YMM_YMM_YMM_IMM8),
            [Shape::Ymm, Shape::Ymm, Shape::Mem, Shape::Imm] => Some(forms::VPERM2F128_YMM_YMM_MEM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_VPERMILPS => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Imm] => Some(forms::VPERMILPS_YMM_YMM_IMM8),
            [Shape::Ymm, Shape::Mem, Shape::Imm] => Some(forms::VPERMILPS_YMM_MEM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_VPERMILPD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Imm] => Some(forms::VPERMILPD_YMM_YMM_IMM8),
            [Shape::Ymm, Shape::Mem, Shape::Imm] => Some(forms::VPERMILPD_YMM_MEM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_VPERM2I128 => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm, Shape::Imm] => Some(forms::VPERM2I128_YMM_YMM_YMM_IMM8),
            [Shape::Ymm, Shape::Ymm, Shape::Mem, Shape::Imm] => Some(forms::VPERM2I128_YMM_YMM_MEM256_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_VPERMD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPERMD_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VPERMD_YMM_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPERMPS => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPERMPS_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VPERMPS_YMM_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPERMQ => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Imm] => Some(forms::VPERMQ_YMM_YMM_IMM8),
            [Shape::Ymm, Shape::Mem, Shape::Imm] => Some(forms::VPERMQ_YMM_MEM256_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_VPERMPD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Imm] => Some(forms::VPERMPD_YMM_YMM_IMM8),
            [Shape::Ymm, Shape::Mem, Shape::Imm] => Some(forms::VPERMPD_YMM_MEM256_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_VSHUFPS => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm, Shape::Imm] => Some(forms::VSHUFPS_YMM_YMM_YMM_IMM8),
            [Shape::Ymm, Shape::Ymm, Shape::Mem, Shape::Imm] => Some(forms::VSHUFPS_YMM_YMM_MEM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_VSHUFPD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm, Shape::Imm] => Some(forms::VSHUFPD_YMM_YMM_YMM_IMM8),
            [Shape::Ymm, Shape::Ymm, Shape::Mem, Shape::Imm] => Some(forms::VSHUFPD_YMM_YMM_MEM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_VUNPCKLPS => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VUNPCKLPS_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VUNPCKLPS_YMM_YMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VUNPCKHPS => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VUNPCKHPS_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VUNPCKHPS_YMM_YMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VUNPCKLPD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VUNPCKLPD_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VUNPCKLPD_YMM_YMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VUNPCKHPD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VUNPCKHPD_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VUNPCKHPD_YMM_YMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VMINPS => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VMINPS_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VMINPS_YMM_YMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VMAXPS => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VMAXPS_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VMAXPS_YMM_YMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VMINPD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VMINPD_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VMINPD_YMM_YMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VMAXPD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VMAXPD_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VMAXPD_YMM_YMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VMINSS => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::VMINSS_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Xmm, Shape::Mem32] => Some(forms::VMINSS_XMM_XMM_MEM32),
            _ => None,
        },
        iclass::XED_ICLASS_VMAXSS => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::VMAXSS_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Xmm, Shape::Mem32] => Some(forms::VMAXSS_XMM_XMM_MEM32),
            _ => None,
        },
        iclass::XED_ICLASS_VMINSD => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::VMINSD_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Xmm, Shape::Mem64] => Some(forms::VMINSD_XMM_XMM_MEM64),
            _ => None,
        },
        iclass::XED_ICLASS_VMAXSD => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::VMAXSD_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Xmm, Shape::Mem64] => Some(forms::VMAXSD_XMM_XMM_MEM64),
            _ => None,
        },
        iclass::XED_ICLASS_VSQRTPS => match shapes {
            [Shape::Ymm, Shape::Ymm] => Some(forms::VSQRTPS_YMM_YMM),
            [Shape::Ymm, Shape::Mem] => Some(forms::VSQRTPS_YMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VSQRTPD => match shapes {
            [Shape::Ymm, Shape::Ymm] => Some(forms::VSQRTPD_YMM_YMM),
            [Shape::Ymm, Shape::Mem] => Some(forms::VSQRTPD_YMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VSQRTSS => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::VSQRTSS_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Xmm, Shape::Mem32] => Some(forms::VSQRTSS_XMM_XMM_MEM32),
            _ => None,
        },
        iclass::XED_ICLASS_VSQRTSD => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::VSQRTSD_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Xmm, Shape::Mem64] => Some(forms::VSQRTSD_XMM_XMM_MEM64),
            _ => None,
        },
        iclass::XED_ICLASS_VPSLLVD => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::VPSLLVD_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Xmm, Shape::Mem128 | Shape::Mem] => Some(forms::VPSLLVD_XMM_XMM_MEM128),
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPSLLVD_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VPSLLVD_YMM_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPSLLVQ => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::VPSLLVQ_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Xmm, Shape::Mem128 | Shape::Mem] => Some(forms::VPSLLVQ_XMM_XMM_MEM128),
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPSLLVQ_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VPSLLVQ_YMM_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPSRAVD => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::VPSRAVD_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Xmm, Shape::Mem128 | Shape::Mem] => Some(forms::VPSRAVD_XMM_XMM_MEM128),
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPSRAVD_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VPSRAVD_YMM_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPSRLVD => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::VPSRLVD_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Xmm, Shape::Mem128 | Shape::Mem] => Some(forms::VPSRLVD_XMM_XMM_MEM128),
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPSRLVD_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VPSRLVD_YMM_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPSRLVQ => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::VPSRLVQ_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Xmm, Shape::Mem128 | Shape::Mem] => Some(forms::VPSRLVQ_XMM_XMM_MEM128),
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPSRLVQ_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VPSRLVQ_YMM_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPCMPEQB => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPCMPEQB_YMM_YMM_YMM),
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::VPCMPEQB_XMM_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPCMPEQW => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPCMPEQW_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VPCMPEQW_YMM_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPCMPEQD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPCMPEQD_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VPCMPEQD_YMM_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPCMPEQQ => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPCMPEQQ_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VPCMPEQQ_YMM_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPCMPGTB => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPCMPGTB_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VPCMPGTB_YMM_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPCMPGTW => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPCMPGTW_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VPCMPGTW_YMM_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPCMPGTD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPCMPGTD_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VPCMPGTD_YMM_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPCMPGTQ => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPCMPGTQ_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VPCMPGTQ_YMM_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPADDUSB => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPADDUSB_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VPADDUSB_YMM_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPADDUSW => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPADDUSW_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VPADDUSW_YMM_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPSUBUSB => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPSUBUSB_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VPSUBUSB_YMM_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPSUBUSW => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPSUBUSW_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VPSUBUSW_YMM_YMM_MEM256),
            _ => None,
        },
        // AVX2 VEX plain-integer band (0x0A00): providers were registered with
        // these YMM forms; the arms make them reachable from real decodes. VEX
        // XMM (128-bit) and EVEX variants stay explicitly unmapped.
        iclass::XED_ICLASS_VPADDB => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPADDB_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPADDW => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPADDW_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPADDD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPADDD_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPADDQ => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPADDQ_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPSUBB => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPSUBB_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPSUBW => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPSUBW_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPSUBD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPSUBD_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPSUBQ => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPSUBQ_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPMULLW => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPMULLW_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPMULHW => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPMULHW_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPMADDWD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPMADDWD_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPSLLW => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Imm] => Some(forms::VPSLLW_YMM_YMM_IMM8),
            [Shape::Ymm, Shape::Ymm, Shape::Xmm] => Some(forms::VPSLLW_YMM_YMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPSLLD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Imm] => Some(forms::VPSLLD_YMM_YMM_IMM8),
            [Shape::Ymm, Shape::Ymm, Shape::Xmm] => Some(forms::VPSLLD_YMM_YMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPSLLQ => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Imm] => Some(forms::VPSLLQ_YMM_YMM_IMM8),
            [Shape::Ymm, Shape::Ymm, Shape::Xmm] => Some(forms::VPSLLQ_YMM_YMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPSRLW => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Imm] => Some(forms::VPSRLW_YMM_YMM_IMM8),
            [Shape::Ymm, Shape::Ymm, Shape::Xmm] => Some(forms::VPSRLW_YMM_YMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPSRLD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Imm] => Some(forms::VPSRLD_YMM_YMM_IMM8),
            [Shape::Ymm, Shape::Ymm, Shape::Xmm] => Some(forms::VPSRLD_YMM_YMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPSRLQ => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Imm] => Some(forms::VPSRLQ_YMM_YMM_IMM8),
            [Shape::Ymm, Shape::Ymm, Shape::Xmm] => Some(forms::VPSRLQ_YMM_YMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPSRAW => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Imm] => Some(forms::VPSRAW_YMM_YMM_IMM8),
            [Shape::Ymm, Shape::Ymm, Shape::Xmm] => Some(forms::VPSRAW_YMM_YMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPSRAD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Imm] => Some(forms::VPSRAD_YMM_YMM_IMM8),
            [Shape::Ymm, Shape::Ymm, Shape::Xmm] => Some(forms::VPSRAD_YMM_YMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPSHUFD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Imm] => Some(forms::VPSHUFD_YMM_YMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_VPSHUFB => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPSHUFB_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPUNPCKLBW => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPUNPCKLBW_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPUNPCKLWD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPUNPCKLWD_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPUNPCKLDQ => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPUNPCKLDQ_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPUNPCKLQDQ => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPUNPCKLQDQ_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPUNPCKHBW => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPUNPCKHBW_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPUNPCKHWD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPUNPCKHWD_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPUNPCKHDQ => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPUNPCKHDQ_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPUNPCKHQDQ => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPUNPCKHQDQ_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPMINUB => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPMINUB_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPMINSB => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPMINSB_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPMINUW => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPMINUW_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPMINSW => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPMINSW_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPMINUD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPMINUD_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPMINSD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPMINSD_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPMAXUB => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPMAXUB_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPMAXSB => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPMAXSB_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPMAXUW => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPMAXUW_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPMAXSW => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPMAXSW_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPMAXUD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPMAXUD_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPMAXSD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPMAXSD_YMM_YMM_YMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPBROADCASTW => match shapes {
            [Shape::Ymm, Shape::Xmm] => Some(forms::VPBROADCASTW_YMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_VPBROADCASTD => match shapes {
            [Shape::Ymm, Shape::Xmm] => Some(forms::VPBROADCASTD_YMM_XMM),
            _ => None,
        },

        iclass::XED_ICLASS_VPAVGB => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPAVGB_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VPAVGB_YMM_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPAVGW => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPAVGW_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VPAVGW_YMM_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPMULLD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPMULLD_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VPMULLD_YMM_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPMULHUW => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPMULHUW_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VPMULHUW_YMM_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPABSB => match shapes {
            [Shape::Ymm, Shape::Ymm] => Some(forms::VPABSB_YMM_YMM),
            [Shape::Ymm, Shape::Mem] => Some(forms::VPABSB_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPABSW => match shapes {
            [Shape::Ymm, Shape::Ymm] => Some(forms::VPABSW_YMM_YMM),
            [Shape::Ymm, Shape::Mem] => Some(forms::VPABSW_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPABSD => match shapes {
            [Shape::Ymm, Shape::Ymm] => Some(forms::VPABSD_YMM_YMM),
            [Shape::Ymm, Shape::Mem] => Some(forms::VPABSD_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPSIGNB => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPSIGNB_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VPSIGNB_YMM_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPSIGNW => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPSIGNW_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VPSIGNW_YMM_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPSIGND => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPSIGND_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VPSIGND_YMM_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPACKSSWB => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPACKSSWB_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VPACKSSWB_YMM_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPACKSSDW => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPACKSSDW_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VPACKSSDW_YMM_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPACKUSWB => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPACKUSWB_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VPACKUSWB_YMM_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPACKUSDW => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] => Some(forms::VPACKUSDW_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Ymm, Shape::Mem] => Some(forms::VPACKUSDW_YMM_YMM_MEM256),
            _ => None,
        },
        iclass::XED_ICLASS_VPDPBUSD => match shapes {
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Xmm] => Some(evex_forms::VPDPBUSD_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Mem128] => Some(evex_forms::VPDPBUSD_XMM_XMM_MEM128),
            [Shape::Ymm, Shape::Reg64, Shape::Ymm, Shape::Ymm] => Some(evex_forms::VPDPBUSD_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Reg64, Shape::Ymm, Shape::Mem] => Some(evex_forms::VPDPBUSD_YMM_YMM_MEM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Zmm] => Some(evex_forms::VPDPBUSD_ZMM_ZMM_ZMM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Mem] => Some(evex_forms::VPDPBUSD_ZMM_ZMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VPDPBUSDS => match shapes {
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Xmm] => Some(evex_forms::VPDPBUSDS_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Mem128] => Some(evex_forms::VPDPBUSDS_XMM_XMM_MEM128),
            [Shape::Ymm, Shape::Reg64, Shape::Ymm, Shape::Ymm] => Some(evex_forms::VPDPBUSDS_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Reg64, Shape::Ymm, Shape::Mem] => Some(evex_forms::VPDPBUSDS_YMM_YMM_MEM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Zmm] => Some(evex_forms::VPDPBUSDS_ZMM_ZMM_ZMM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Mem] => Some(evex_forms::VPDPBUSDS_ZMM_ZMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VPDPWSSD => match shapes {
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Xmm] => Some(evex_forms::VPDPWSSD_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Mem128] => Some(evex_forms::VPDPWSSD_XMM_XMM_MEM128),
            [Shape::Ymm, Shape::Reg64, Shape::Ymm, Shape::Ymm] => Some(evex_forms::VPDPWSSD_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Reg64, Shape::Ymm, Shape::Mem] => Some(evex_forms::VPDPWSSD_YMM_YMM_MEM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Zmm] => Some(evex_forms::VPDPWSSD_ZMM_ZMM_ZMM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Mem] => Some(evex_forms::VPDPWSSD_ZMM_ZMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VPDPWSSDS => match shapes {
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Xmm] => Some(evex_forms::VPDPWSSDS_XMM_XMM_XMM),
            [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Mem128] => Some(evex_forms::VPDPWSSDS_XMM_XMM_MEM128),
            [Shape::Ymm, Shape::Reg64, Shape::Ymm, Shape::Ymm] => Some(evex_forms::VPDPWSSDS_YMM_YMM_YMM),
            [Shape::Ymm, Shape::Reg64, Shape::Ymm, Shape::Mem] => Some(evex_forms::VPDPWSSDS_YMM_YMM_MEM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Zmm] => Some(evex_forms::VPDPWSSDS_ZMM_ZMM_ZMM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Mem] => Some(evex_forms::VPDPWSSDS_ZMM_ZMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VPDPBSSD => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] | [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Xmm] => {
                Some(evex_forms::VPDPBSSD_XMM_XMM_XMM)
            }
            [Shape::Xmm, Shape::Xmm, Shape::Mem128] | [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Mem128] => {
                Some(evex_forms::VPDPBSSD_XMM_XMM_MEM128)
            }
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] | [Shape::Ymm, Shape::Reg64, Shape::Ymm, Shape::Ymm] => {
                Some(evex_forms::VPDPBSSD_YMM_YMM_YMM)
            }
            [Shape::Ymm, Shape::Ymm, Shape::Mem] | [Shape::Ymm, Shape::Reg64, Shape::Ymm, Shape::Mem] => {
                Some(evex_forms::VPDPBSSD_YMM_YMM_MEM)
            }
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Zmm] => Some(evex_forms::VPDPBSSD_ZMM_ZMM_ZMM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Mem] => Some(evex_forms::VPDPBSSD_ZMM_ZMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VPDPBSSDS => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] | [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Xmm] => {
                Some(evex_forms::VPDPBSSDS_XMM_XMM_XMM)
            }
            [Shape::Xmm, Shape::Xmm, Shape::Mem128] | [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Mem128] => {
                Some(evex_forms::VPDPBSSDS_XMM_XMM_MEM128)
            }
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] | [Shape::Ymm, Shape::Reg64, Shape::Ymm, Shape::Ymm] => {
                Some(evex_forms::VPDPBSSDS_YMM_YMM_YMM)
            }
            [Shape::Ymm, Shape::Ymm, Shape::Mem] | [Shape::Ymm, Shape::Reg64, Shape::Ymm, Shape::Mem] => {
                Some(evex_forms::VPDPBSSDS_YMM_YMM_MEM)
            }
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Zmm] => Some(evex_forms::VPDPBSSDS_ZMM_ZMM_ZMM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Mem] => Some(evex_forms::VPDPBSSDS_ZMM_ZMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VPDPBSUD => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] | [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Xmm] => {
                Some(evex_forms::VPDPBSUD_XMM_XMM_XMM)
            }
            [Shape::Xmm, Shape::Xmm, Shape::Mem128] | [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Mem128] => {
                Some(evex_forms::VPDPBSUD_XMM_XMM_MEM128)
            }
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] | [Shape::Ymm, Shape::Reg64, Shape::Ymm, Shape::Ymm] => {
                Some(evex_forms::VPDPBSUD_YMM_YMM_YMM)
            }
            [Shape::Ymm, Shape::Ymm, Shape::Mem] | [Shape::Ymm, Shape::Reg64, Shape::Ymm, Shape::Mem] => {
                Some(evex_forms::VPDPBSUD_YMM_YMM_MEM)
            }
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Zmm] => Some(evex_forms::VPDPBSUD_ZMM_ZMM_ZMM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Mem] => Some(evex_forms::VPDPBSUD_ZMM_ZMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VPDPBSUDS => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Xmm] | [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Xmm] => {
                Some(evex_forms::VPDPBSUDS_XMM_XMM_XMM)
            }
            [Shape::Xmm, Shape::Xmm, Shape::Mem128] | [Shape::Xmm, Shape::Reg64, Shape::Xmm, Shape::Mem128] => {
                Some(evex_forms::VPDPBSUDS_XMM_XMM_MEM128)
            }
            [Shape::Ymm, Shape::Ymm, Shape::Ymm] | [Shape::Ymm, Shape::Reg64, Shape::Ymm, Shape::Ymm] => {
                Some(evex_forms::VPDPBSUDS_YMM_YMM_YMM)
            }
            [Shape::Ymm, Shape::Ymm, Shape::Mem] | [Shape::Ymm, Shape::Reg64, Shape::Ymm, Shape::Mem] => {
                Some(evex_forms::VPDPBSUDS_YMM_YMM_MEM)
            }
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Zmm] => Some(evex_forms::VPDPBSUDS_ZMM_ZMM_ZMM),
            [Shape::Zmm, Shape::Reg64, Shape::Zmm, Shape::Mem] => Some(evex_forms::VPDPBSUDS_ZMM_ZMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_VPBLENDD => match shapes {
            [Shape::Ymm, Shape::Ymm, Shape::Ymm, Shape::Imm] => Some(forms::VPBLENDD_YMM_YMM_YMM_IMM8),
            [Shape::Ymm, Shape::Ymm, Shape::Mem, Shape::Imm] => Some(forms::VPBLENDD_YMM_YMM_MEM256_IMM8),
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
        iclass::XED_ICLASS_MOVNTDQ => match shapes {
            [Shape::Mem128, Shape::Xmm] => Some(forms::MOVNTDQ_MEM128_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_MOVNTI => match shapes {
            [Shape::Mem32, Shape::Reg32] => Some(forms::MOVNTI_MEM32_R32),
            [Shape::Mem64, Shape::Reg64] => Some(forms::MOVNTI_MEM64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_PREFETCHNTA => Some(forms::PREFETCHNTA_MEM8),
        iclass::XED_ICLASS_PREFETCHT0 => Some(forms::PREFETCHT0_MEM8),
        iclass::XED_ICLASS_PREFETCHT1 => Some(forms::PREFETCHT1_MEM8),
        iclass::XED_ICLASS_PREFETCHT2 => Some(forms::PREFETCHT2_MEM8),
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
        iclass::XED_ICLASS_XORPS => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::XORPS_XMM_XMM),
            [Shape::Xmm, Shape::Mem128] => Some(forms::XORPS_XMM_MEM128),
            _ => None,
        },
        iclass::XED_ICLASS_XORPD => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::XORPD_XMM_XMM),
            [Shape::Xmm, Shape::Mem128] => Some(forms::XORPD_XMM_MEM128),
            _ => None,
        },
        iclass::XED_ICLASS_PADDQ => Some(forms::PADDQ_XMM_XMM),
        iclass::XED_ICLASS_PSHUFB => Some(forms::PSHUFB_XMM_XMM),
        iclass::XED_ICLASS_PMULLW => Some(forms::PMULLW_XMM_XMM),
        iclass::XED_ICLASS_PMADDWD => Some(forms::PMADDWD_XMM_XMM),
        iclass::XED_ICLASS_PACKSSWB => Some(forms::PACKSSWB_XMM_XMM),
        iclass::XED_ICLASS_PSADBW => Some(forms::PSADBW_XMM_XMM),
        iclass::XED_ICLASS_PHADDW => Some(forms::PHADDW_XMM_XMM),
        iclass::XED_ICLASS_PABSB => Some(forms::PABSB_XMM_XMM),
        iclass::XED_ICLASS_PABSD => Some(forms::PABSD_XMM_XMM),
        iclass::XED_ICLASS_PSIGNB => Some(forms::PSIGNB_XMM_XMM),
        iclass::XED_ICLASS_PSUBQ => Some(forms::PSUBQ_XMM_XMM),
        iclass::XED_ICLASS_PSLLD => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PSLLD_XMM_XMM),
            [Shape::Xmm, Shape::Imm] => Some(forms::PSLLD_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_PSRLD => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PSRLD_XMM_XMM),
            [Shape::Xmm, Shape::Imm] => Some(forms::PSRLD_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_PMINUB => Some(forms::PMINUB_XMM_XMM),
        iclass::XED_ICLASS_PTEST => Some(forms::PTEST_XMM_XMM),
        iclass::XED_ICLASS_PACKUSWB => Some(forms::PACKUSWB_XMM_XMM),
        iclass::XED_ICLASS_PADDB => Some(forms::PADDB_XMM_XMM),
        iclass::XED_ICLASS_PADDW => Some(forms::PADDW_XMM_XMM),
        iclass::XED_ICLASS_PADDD => Some(forms::PADDD_XMM_XMM),
        iclass::XED_ICLASS_PBLENDVB => Some(forms::PBLENDVB_XMM_XMM),
        iclass::XED_ICLASS_PCMPGTQ => Some(forms::PCMPGTQ_XMM_XMM),
        iclass::XED_ICLASS_PSUBD => Some(forms::PSUBD_XMM_XMM),
        iclass::XED_ICLASS_PMINSB => Some(forms::PMINSB_XMM_XMM),
        iclass::XED_ICLASS_PMINUD => Some(forms::PMINUD_XMM_XMM),
        iclass::XED_ICLASS_PMAXSD => Some(forms::PMAXSD_XMM_XMM),
        iclass::XED_ICLASS_PMOVZXBD => Some(forms::PMOVZXBD_XMM_XMM),

        // Legacy SSE packed-float and remaining integer families. Providers for
        // these forms were registered long ago; these arms make them reachable
        // from real decodes (mem-shaped variants stay explicitly unmapped).
        iclass::XED_ICLASS_ADDPS => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::ADDPS_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_SUBPS => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::SUBPS_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_MULPS => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::MULPS_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_DIVPS => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::DIVPS_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_ADDPD => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::ADDPD_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_SUBPD => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::SUBPD_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_MULPD => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::MULPD_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_DIVPD => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::DIVPD_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_MINPS => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::MINPS_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_MAXPS => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::MAXPS_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_HADDPS => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::HADDPS_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_HADDPD => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::HADDPD_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_HSUBPS => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::HSUBPS_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_HSUBPD => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::HSUBPD_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_CMPPS => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Imm] => Some(forms::CMPPS_XMM_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_CMPPD => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Imm] => Some(forms::CMPPD_XMM_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_MOVAPD => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::MOVAPD_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_MOVUPD => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::MOVUPD_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PSUBB => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PSUBB_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PSUBW => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PSUBW_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PMULLD => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMULLD_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PSLLW => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PSLLW_XMM_XMM),
            [Shape::Xmm, Shape::Imm] => Some(forms::PSLLW_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_PSRLW => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PSRLW_XMM_XMM),
            [Shape::Xmm, Shape::Imm] => Some(forms::PSRLW_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_PSRAW => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PSRAW_XMM_XMM),
            [Shape::Xmm, Shape::Imm] => Some(forms::PSRAW_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_PSRAD => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PSRAD_XMM_XMM),
            [Shape::Xmm, Shape::Imm] => Some(forms::PSRAD_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_PSLLQ => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PSLLQ_XMM_XMM),
            [Shape::Xmm, Shape::Imm] => Some(forms::PSLLQ_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_PSRLQ => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PSRLQ_XMM_XMM),
            [Shape::Xmm, Shape::Imm] => Some(forms::PSRLQ_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_PSLLDQ => match shapes {
            [Shape::Xmm, Shape::Imm] => Some(forms::PSLLDQ_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_PSRLDQ => match shapes {
            [Shape::Xmm, Shape::Imm] => Some(forms::PSRLDQ_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_PMAXSB => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMAXSB_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PMAXSW => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMAXSW_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PMAXUW => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMAXUW_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PMINSW => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMINSW_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PMINUW => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMINUW_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PMULHW => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMULHW_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PMULHUW => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMULHUW_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PACKSSDW => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PACKSSDW_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PACKUSDW => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PACKUSDW_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PSHUFHW => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Imm] => Some(forms::PSHUFHW_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_PSHUFLW => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Imm] => Some(forms::PSHUFLW_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_PMADDUBSW => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMADDUBSW_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PHADDD => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PHADDD_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PHSUBW => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PHSUBW_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PHSUBD => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PHSUBD_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PHADDSW => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PHADDSW_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PHSUBSW => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PHSUBSW_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PABSW => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PABSW_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PSIGNW => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PSIGNW_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PSIGND => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PSIGND_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PMULHRSW => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMULHRSW_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PMULDQ => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMULDQ_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PBLENDW => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Imm] => Some(forms::PBLENDW_XMM_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_BLENDPS => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Imm] => Some(forms::BLENDPS_XMM_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_BLENDPD => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Imm] => Some(forms::BLENDPD_XMM_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_DPPS => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Imm] => Some(forms::DPPS_XMM_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_DPPD => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Imm] => Some(forms::DPPD_XMM_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_PEXTRB => match shapes {
            [Shape::Reg32, Shape::Xmm, Shape::Imm] => Some(forms::PEXTRB_R32_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_PHMINPOSUW => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PHMINPOSUW_XMM_XMM),
            _ => None,
        },

        iclass::XED_ICLASS_PINSRB => match shapes {
            [Shape::Xmm, Shape::Reg32, Shape::Imm] => Some(forms::PINSRB_XMM_R32_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_MPSADBW => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Imm] => Some(forms::MPSADBW_XMM_XMM_IMM8),
            _ => None,
        },
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
        iclass::XED_ICLASS_MOVHLPS => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::MOVHLPS_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_MOVLHPS => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::MOVLHPS_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_MOVSS => match shapes {
            [Shape::Xmm, Shape::Mem32] => Some(forms::MOVSS_XMM_MEM32),
            [Shape::Mem32, Shape::Xmm] => Some(forms::MOVSS_MEM32_XMM),
            [Shape::Xmm, Shape::Xmm] => Some(forms::MOVSS_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_ADDSD => Some(forms::ADDSD_XMM_XMM),
        iclass::XED_ICLASS_SUBSD => Some(forms::SUBSD_XMM_XMM),
        iclass::XED_ICLASS_MULSD => Some(forms::MULSD_XMM_XMM),
        iclass::XED_ICLASS_DIVSD => Some(forms::DIVSD_XMM_XMM),
        iclass::XED_ICLASS_UCOMISD => Some(forms::UCOMISD_XMM_XMM),
        iclass::XED_ICLASS_MOVSD_XMM => match shapes {
            [Shape::Xmm, Shape::Mem64] => Some(forms::MOVSD_XMM_MEM64),
            [Shape::Mem64, Shape::Xmm] => Some(forms::MOVSD_MEM64_XMM),
            [Shape::Xmm, Shape::Xmm] => Some(forms::MOVSD_XMM_XMM),
            _ => None,
        },
        // x87 family. Load and arithmetic encodings report the implicit ST(0)
        // operand first, so memory operands trail; the FST/FSTP stores report
        // the memory destination first.
        iclass::XED_ICLASS_FNINIT => Some(forms::FINIT),
        iclass::XED_ICLASS_FLD1 => Some(forms::FLD1),
        iclass::XED_ICLASS_FLDZ => Some(forms::FLDZ),
        iclass::XED_ICLASS_FLDPI => Some(forms::FLDPI),
        iclass::XED_ICLASS_FLDL2E => Some(forms::FLDL2E),
        iclass::XED_ICLASS_FLDL2T => Some(forms::FLDL2T),
        iclass::XED_ICLASS_FLDLG2 => Some(forms::FLDLG2),
        iclass::XED_ICLASS_FLDLN2 => Some(forms::FLDLN2),
        iclass::XED_ICLASS_FLD => match shapes {
            [.., Shape::Mem32] => Some(forms::FLD_M32),
            [.., Shape::Mem64] => Some(forms::FLD_M64),
            [.., Shape::Mem80] => Some(forms::FLD_M80),
            [Shape::Stack, Shape::Stack] => Some(forms::FLD_STI),
            _ => None,
        },
        iclass::XED_ICLASS_FST => match shapes {
            [Shape::Mem32, ..] => Some(forms::FST_M32),
            [Shape::Mem64, ..] => Some(forms::FST_M64),
            [Shape::Stack, ..] => Some(forms::FST_STI),
            _ => None,
        },
        iclass::XED_ICLASS_FNOP => Some(forms::FNOP),
        // XED reports the D9 D8+i `fstp st(i)` encoding as FSTPNCE; both
        // iclasses route to the same corpus form.
        iclass::XED_ICLASS_FSTP | iclass::XED_ICLASS_FSTPNCE => match shapes {
            [Shape::Mem32, ..] => Some(forms::FSTP_M32),
            [Shape::Mem64, ..] => Some(forms::FSTP_M64),
            [Shape::Stack, Shape::Stack] => Some(forms::FSTP_STI),
            _ => None,
        },
        family @ (iclass::XED_ICLASS_FADD
        | iclass::XED_ICLASS_FSUB
        | iclass::XED_ICLASS_FSUBR
        | iclass::XED_ICLASS_FMUL
        | iclass::XED_ICLASS_FDIV
        | iclass::XED_ICLASS_FDIVR) => {
            let (st0_dst, sti_dst, m32, m64) = match family {
                iclass::XED_ICLASS_FADD => (
                    forms::FADD_ST0_STI,
                    forms::FADD_STI_ST0,
                    forms::FADD_M32,
                    forms::FADD_M64,
                ),
                iclass::XED_ICLASS_FSUB => (
                    forms::FSUB_ST0_STI,
                    forms::FSUB_STI_ST0,
                    forms::FSUB_M32,
                    forms::FSUB_M64,
                ),
                iclass::XED_ICLASS_FSUBR => (
                    forms::FSUBR_ST0_STI,
                    forms::FSUBR_STI_ST0,
                    forms::FSUBR_M32,
                    forms::FSUBR_M64,
                ),
                iclass::XED_ICLASS_FMUL => (
                    forms::FMUL_ST0_STI,
                    forms::FMUL_STI_ST0,
                    forms::FMUL_M32,
                    forms::FMUL_M64,
                ),
                iclass::XED_ICLASS_FDIV => (
                    forms::FDIV_ST0_STI,
                    forms::FDIV_STI_ST0,
                    forms::FDIV_M32,
                    forms::FDIV_M64,
                ),
                _ => (
                    forms::FDIVR_ST0_STI,
                    forms::FDIVR_STI_ST0,
                    forms::FDIVR_M32,
                    forms::FDIVR_M64,
                ),
            };
            // Operand 0 names the read-write destination: ST(0) for the D8
            // encodings, ST(i) for the DC encodings.
            let dst_is_st0 = match decoded.operands.first().map(|operand| &operand.kind) {
                Some(OperandKind::Register(view)) => view.parent.0 == register_id::X87_BASE,
                _ => return None,
            };
            match shapes {
                [.., Shape::Mem32] => Some(m32),
                [.., Shape::Mem64] => Some(m64),
                [Shape::Stack, Shape::Stack] => Some(if dst_is_st0 { st0_dst } else { sti_dst }),
                _ => None,
            }
        }
        iclass::XED_ICLASS_FUCOMI => match shapes {
            [Shape::Stack, Shape::Stack] => Some(forms::FUCOMI_ST0_STI),
            _ => None,
        },
        iclass::XED_ICLASS_FUCOMIP => match shapes {
            [Shape::Stack, Shape::Stack] => Some(forms::FUCOMIP_ST0_STI),
            _ => None,
        },
        iclass::XED_ICLASS_FCOMI => match shapes {
            [Shape::Stack, Shape::Stack] => Some(forms::FCOMI_ST0_STI),
            _ => None,
        },
        iclass::XED_ICLASS_FCOMIP => match shapes {
            [Shape::Stack, Shape::Stack] => Some(forms::FCOMIP_ST0_STI),
            _ => None,
        },
        iclass::XED_ICLASS_FCMOVB => match shapes {
            [Shape::Stack, ..] => Some(forms::FCMOVB_ST0_STI),
            _ => None,
        },
        iclass::XED_ICLASS_FCMOVE => match shapes {
            [Shape::Stack, ..] => Some(forms::FCMOVE_ST0_STI),
            _ => None,
        },
        iclass::XED_ICLASS_FCMOVBE => match shapes {
            [Shape::Stack, ..] => Some(forms::FCMOVBE_ST0_STI),
            _ => None,
        },
        iclass::XED_ICLASS_FCMOVU => match shapes {
            [Shape::Stack, ..] => Some(forms::FCMOVU_ST0_STI),
            _ => None,
        },
        iclass::XED_ICLASS_FCMOVNB => match shapes {
            [Shape::Stack, ..] => Some(forms::FCMOVNB_ST0_STI),
            _ => None,
        },
        iclass::XED_ICLASS_FCMOVNE => match shapes {
            [Shape::Stack, ..] => Some(forms::FCMOVNE_ST0_STI),
            _ => None,
        },
        iclass::XED_ICLASS_FCMOVNBE => match shapes {
            [Shape::Stack, ..] => Some(forms::FCMOVNBE_ST0_STI),
            _ => None,
        },
        iclass::XED_ICLASS_FCMOVNU => match shapes {
            [Shape::Stack, ..] => Some(forms::FCMOVNU_ST0_STI),
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
            [Shape::Reg32, Shape::Imm] => Some(forms::ADC_R32_IMM32),
            [Shape::Reg8, Shape::Imm] => Some(forms::ADC_R8_IMM8),
            [Shape::Mem8, Shape::Imm] => Some(forms::ADC_MEM8_IMM8),
            [Shape::Reg8, Shape::Reg8] => Some(forms::ADC_R8_R8),
            [Shape::Reg8, Shape::Mem8] => Some(forms::ADC_R8_MEM8),
            [Shape::Mem8, Shape::Reg8] => Some(forms::ADC_MEM8_R8),
            [Shape::Reg16, Shape::Imm] if immediate_width == Some(8) => Some(forms::ADC_R16_IMM8),
            [Shape::Mem16, Shape::Imm] if immediate_width == Some(8) => Some(forms::ADC_MEM16_IMM8),
            [Shape::Reg64, Shape::Reg64] => Some(forms::ADC_R64_R64),
            [Shape::Reg16, Shape::Reg16] => Some(forms::ADC_R16_R16),
            [Shape::Reg16, Shape::Imm] => Some(forms::ADC_R16_IMM16),
            [Shape::Reg16, Shape::Mem16] => Some(forms::ADC_R16_MEM16),
            [Shape::Mem16, Shape::Reg16] => Some(forms::ADC_MEM16_R16),
            [Shape::Mem16, Shape::Imm] => Some(forms::ADC_MEM16_IMM16),
            _ => None,
        },
        iclass::XED_ICLASS_SBB => match shapes {
            [Shape::Reg32, Shape::Imm] => Some(forms::SBB_R32_IMM32),
            [Shape::Reg8, Shape::Imm] => Some(forms::SBB_R8_IMM8),
            [Shape::Mem8, Shape::Imm] => Some(forms::SBB_MEM8_IMM8),
            [Shape::Reg8, Shape::Reg8] => Some(forms::SBB_R8_R8),
            [Shape::Reg8, Shape::Mem8] => Some(forms::SBB_R8_MEM8),
            [Shape::Mem8, Shape::Reg8] => Some(forms::SBB_MEM8_R8),
            [Shape::Reg16, Shape::Imm] if immediate_width == Some(8) => Some(forms::SBB_R16_IMM8),
            [Shape::Mem16, Shape::Imm] if immediate_width == Some(8) => Some(forms::SBB_MEM16_IMM8),
            [Shape::Reg64, Shape::Reg64] => Some(forms::SBB_R64_R64),
            [Shape::Reg16, Shape::Reg16] => Some(forms::SBB_R16_R16),
            [Shape::Reg16, Shape::Imm] => Some(forms::SBB_R16_IMM16),
            [Shape::Reg16, Shape::Mem16] => Some(forms::SBB_R16_MEM16),
            [Shape::Mem16, Shape::Reg16] => Some(forms::SBB_MEM16_R16),
            [Shape::Mem16, Shape::Imm] => Some(forms::SBB_MEM16_IMM16),
            [Shape::Reg32, Shape::Reg32] => Some(forms::SBB_R32_R32),
            [Shape::Reg32, Shape::Mem32] => Some(forms::SBB_R32_MEM32),
            [Shape::Mem32, Shape::Reg32] => Some(forms::SBB_MEM32_R32),
            [Shape::Reg64, Shape::Mem64] => Some(forms::SBB_R64_MEM64),
            [Shape::Mem64, Shape::Reg64] => Some(forms::SBB_MEM64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_BT => match shapes {
            [Shape::Mem32, Shape::Imm] => Some(forms::BT_MEM32_IMM8),
            [Shape::Mem64, Shape::Imm] => Some(forms::BT_MEM64_IMM8),
            [Shape::Reg64, Shape::Reg64] => Some(forms::BT_R64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::BT_R32_R32),
            [Shape::Reg64, Shape::Imm] => Some(forms::BT_R64_IMM8),
            [Shape::Reg32, Shape::Imm] => Some(forms::BT_R32_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_BTS => match shapes {
            [Shape::Mem32, Shape::Imm] => Some(forms::BTS_MEM32_IMM8),
            [Shape::Mem64, Shape::Imm] => Some(forms::BTS_MEM64_IMM8),
            [Shape::Mem32, Shape::Reg32] => Some(forms::BTS_MEM32_R32),
            [Shape::Mem64, Shape::Reg64] => Some(forms::BTS_MEM64_R64),
            [Shape::Reg64, Shape::Reg64] => Some(forms::BTS_R64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::BTS_R32_R32),
            [Shape::Reg64, Shape::Imm] => Some(forms::BTS_R64_IMM8),
            [Shape::Reg32, Shape::Imm] => Some(forms::BTS_R32_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_BTR => match shapes {
            [Shape::Mem32, Shape::Imm] => Some(forms::BTR_MEM32_IMM8),
            [Shape::Mem64, Shape::Imm] => Some(forms::BTR_MEM64_IMM8),
            [Shape::Mem32, Shape::Reg32] => Some(forms::BTR_MEM32_R32),
            [Shape::Mem64, Shape::Reg64] => Some(forms::BTR_MEM64_R64),
            [Shape::Reg64, Shape::Reg64] => Some(forms::BTR_R64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::BTR_R32_R32),
            [Shape::Reg64, Shape::Imm] => Some(forms::BTR_R64_IMM8),
            [Shape::Reg32, Shape::Imm] => Some(forms::BTR_R32_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_BTC => match shapes {
            [Shape::Mem32, Shape::Imm] => Some(forms::BTC_MEM32_IMM8),
            [Shape::Mem64, Shape::Imm] => Some(forms::BTC_MEM64_IMM8),
            [Shape::Mem32, Shape::Reg32] => Some(forms::BTC_MEM32_R32),
            [Shape::Mem64, Shape::Reg64] => Some(forms::BTC_MEM64_R64),
            [Shape::Reg64, Shape::Reg64] => Some(forms::BTC_R64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::BTC_R32_R32),
            [Shape::Reg64, Shape::Imm] => Some(forms::BTC_R64_IMM8),
            [Shape::Reg32, Shape::Imm] => Some(forms::BTC_R32_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_BSF => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::BSF_R64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::BSF_R32_R32),
            [Shape::Reg64, Shape::Mem64] => Some(forms::BSF_R64_MEM64),
            [Shape::Reg32, Shape::Mem32] => Some(forms::BSF_R32_MEM32),
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
        // AMX tile management and matrix operations
        iclass::XED_ICLASS_TILERELEASE => Some(amx_forms::TILERELEASE),
        iclass::XED_ICLASS_TILEZERO => match shapes {
            [Shape::Tmm] => Some(amx_forms::TILEZERO_TMM),
            _ => None,
        },
        iclass::XED_ICLASS_LDTILECFG => match shapes {
            [Shape::Mem] => Some(amx_forms::LDTILECFG_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_STTILECFG => match shapes {
            [Shape::Mem] => Some(amx_forms::STTILECFG_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_TILELOADD => match shapes {
            [Shape::Tmm, Shape::Mem] => Some(amx_forms::TILELOADD_TMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_TILELOADDT1 => match shapes {
            [Shape::Tmm, Shape::Mem] => Some(amx_forms::TILELOADDT1_TMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_TILESTORED => match shapes {
            [Shape::Mem, Shape::Tmm] => Some(amx_forms::TILESTORED_MEM_TMM),
            _ => None,
        },
        iclass::XED_ICLASS_TDPBSSD => match shapes {
            [Shape::Tmm, Shape::Tmm, Shape::Tmm] => Some(amx_forms::TDPBSSD_TMM_TMM_TMM),
            _ => None,
        },
        iclass::XED_ICLASS_TDPBSUD => match shapes {
            [Shape::Tmm, Shape::Tmm, Shape::Tmm] => Some(amx_forms::TDPBSUD_TMM_TMM_TMM),
            _ => None,
        },
        iclass::XED_ICLASS_TDPBUSD => match shapes {
            [Shape::Tmm, Shape::Tmm, Shape::Tmm] => Some(amx_forms::TDPBUSD_TMM_TMM_TMM),
            _ => None,
        },
        iclass::XED_ICLASS_TDPBUUD => match shapes {
            [Shape::Tmm, Shape::Tmm, Shape::Tmm] => Some(amx_forms::TDPBUUD_TMM_TMM_TMM),
            _ => None,
        },
        iclass::XED_ICLASS_TDPBF16PS => match shapes {
            [Shape::Tmm, Shape::Tmm, Shape::Tmm] => Some(amx_forms::TDPBF16PS_TMM_TMM_TMM),
            _ => None,
        },
        iclass::XED_ICLASS_TDPFP16PS => match shapes {
            [Shape::Tmm, Shape::Tmm, Shape::Tmm] => Some(amx_forms::TDPFP16PS_TMM_TMM_TMM),
            _ => None,
        },
        // CET shadow stack instructions
        iclass::XED_ICLASS_RDSSPD => match shapes {
            [Shape::Reg32] => Some(forms::RDSSPD_R32),
            _ => None,
        },
        iclass::XED_ICLASS_RDSSPQ => match shapes {
            [Shape::Reg64] => Some(forms::RDSSPQ_R64),
            _ => None,
        },
        iclass::XED_ICLASS_INCSSPD => match shapes {
            [Shape::Reg32] => Some(forms::INCSSPD_R32),
            _ => None,
        },
        iclass::XED_ICLASS_INCSSPQ => match shapes {
            [Shape::Reg64] => Some(forms::INCSSPQ_R64),
            _ => None,
        },
        iclass::XED_ICLASS_SAVEPREVSSP => Some(forms::SAVEPREVSSP),
        iclass::XED_ICLASS_RSTORSSP => match shapes {
            [Shape::Mem64] => Some(forms::RSTORSSP_MEM64),
            _ => None,
        },
        iclass::XED_ICLASS_SETSSBSY => Some(forms::SETSSBSY),
        iclass::XED_ICLASS_CLRSSBSY => match shapes {
            [Shape::Mem64] => Some(forms::CLRSSBSY_MEM64),
            _ => None,
        },
        iclass::XED_ICLASS_WRSSD => match shapes {
            [Shape::Mem32, Shape::Reg32] => Some(forms::WRSSD_MEM32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_WRSSQ => match shapes {
            [Shape::Mem64, Shape::Reg64] => Some(forms::WRSSQ_MEM64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_WRUSSD => match shapes {
            [Shape::Mem32, Shape::Reg32] => Some(forms::WRUSSD_MEM32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_WRUSSQ => match shapes {
            [Shape::Mem64, Shape::Reg64] => Some(forms::WRUSSQ_MEM64_R64),
            _ => None,
        },
        // APX (Advanced Performance Extensions) instructions
        iclass::XED_ICLASS_JMPABS => match shapes {
            // The absolute target decodes as a far-pointer operand.
            [Shape::Other] => Some(forms::JMPABS_IMM64),
            _ => None,
        },
        iclass::XED_ICLASS_PUSH2 | iclass::XED_ICLASS_PUSH2P => match shapes {
            // The register pair shape is identical for both variants; the
            // suppressed stack-memory operand width (64 vs 128) discriminates.
            [Shape::Reg64, Shape::Reg64] => match stack_pair_width(decoded) {
                Some(64) => Some(forms::PUSH2_R64_R64),
                Some(128) => Some(forms::PUSH2P_R64_R64),
                _ => None,
            },
            _ => None,
        },
        iclass::XED_ICLASS_POP2 | iclass::XED_ICLASS_POP2P => match shapes {
            [Shape::Reg64, Shape::Reg64] => match stack_pair_width(decoded) {
                Some(64) => Some(forms::POP2_R64_R64),
                Some(128) => Some(forms::POP2P_R64_R64),
                _ => None,
            },
            _ => None,
        },
        // CCMPcc: conditional compare; the explicit third operand is the DFV
        // (default-flags) immediate mask. Only the 64-bit forms are registered.
        iclass::XED_ICLASS_CCMPO => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CCMPO_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CCMPNO => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CCMPNO_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CCMPB => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CCMPB_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CCMPNB => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CCMPNB_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CCMPZ => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CCMPZ_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CCMPNZ => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CCMPNZ_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CCMPBE => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CCMPBE_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CCMPNBE => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CCMPNBE_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CCMPS => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CCMPS_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CCMPNS => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CCMPNS_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CCMPT => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CCMPT_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CCMPF => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CCMPF_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CCMPL => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CCMPL_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CCMPNL => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CCMPNL_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CCMPLE => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CCMPLE_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CCMPNLE => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CCMPNLE_R64_R64),
            _ => None,
        },
        // CTESTcc: conditional test; same DFV immediate operand as CCMPcc.
        iclass::XED_ICLASS_CTESTO => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CTESTO_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CTESTNO => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CTESTNO_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CTESTB => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CTESTB_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CTESTNB => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CTESTNB_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CTESTZ => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CTESTZ_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CTESTNZ => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CTESTNZ_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CTESTBE => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CTESTBE_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CTESTNBE => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CTESTNBE_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CTESTS => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CTESTS_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CTESTNS => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CTESTNS_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CTESTT => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CTESTT_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CTESTF => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CTESTF_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CTESTL => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CTESTL_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CTESTNL => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CTESTNL_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CTESTLE => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CTESTLE_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CTESTNLE => match shapes {
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::CTESTNLE_R64_R64),
            _ => None,
        },
        // CFCMOVcc: only the 8 conditions with landed corpus forms are mapped;
        // the remaining 8 iclasses (CFCMOVO/NO/S/NS/BE/NBE/P/NP) fall through
        // to the unmapped catch-all on purpose.
        iclass::XED_ICLASS_CFCMOVZ => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::CFCMOVZ_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CFCMOVNZ => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::CFCMOVNZ_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CFCMOVB => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::CFCMOVB_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CFCMOVNB => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::CFCMOVNB_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CFCMOVL => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::CFCMOVL_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CFCMOVNL => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::CFCMOVNL_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CFCMOVLE => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::CFCMOVLE_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CFCMOVNLE => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::CFCMOVNLE_R64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_BSWAP => match shapes {
            [Shape::Reg64] => Some(forms::BSWAP_R64),
            [Shape::Reg32] => Some(forms::BSWAP_R32),
            _ => None,
        },
        iclass::XED_ICLASS_ANDN => match shapes {
            [Shape::Reg32, Shape::Reg32, Shape::Reg32] => Some(forms::ANDN_R32_R32_R32),
            [Shape::Reg32, Shape::Reg32, Shape::Mem32] => Some(forms::ANDN_R32_R32_MEM32),
            [Shape::Reg64, Shape::Reg64, Shape::Reg64] => Some(forms::ANDN_R64_R64_R64),
            [Shape::Reg64, Shape::Reg64, Shape::Mem64] => Some(forms::ANDN_R64_R64_MEM64),
            _ => None,
        },
        iclass::XED_ICLASS_BEXTR => match shapes {
            [Shape::Reg32, Shape::Reg32, Shape::Reg32] => Some(forms::BEXTR_R32_R32_R32),
            [Shape::Reg32, Shape::Mem32, Shape::Reg32] => Some(forms::BEXTR_R32_MEM32_R32),
            [Shape::Reg64, Shape::Reg64, Shape::Reg64] => Some(forms::BEXTR_R64_R64_R64),
            [Shape::Reg64, Shape::Mem64, Shape::Reg64] => Some(forms::BEXTR_R64_MEM64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_BLSI => match shapes {
            [Shape::Reg32, Shape::Reg32] => Some(forms::BLSI_R32_R32),
            [Shape::Reg32, Shape::Mem32] => Some(forms::BLSI_R32_MEM32),
            [Shape::Reg64, Shape::Reg64] => Some(forms::BLSI_R64_R64),
            [Shape::Reg64, Shape::Mem64] => Some(forms::BLSI_R64_MEM64),
            _ => None,
        },
        iclass::XED_ICLASS_BLSMSK => match shapes {
            [Shape::Reg32, Shape::Reg32] => Some(forms::BLSMSK_R32_R32),
            [Shape::Reg32, Shape::Mem32] => Some(forms::BLSMSK_R32_MEM32),
            [Shape::Reg64, Shape::Reg64] => Some(forms::BLSMSK_R64_R64),
            [Shape::Reg64, Shape::Mem64] => Some(forms::BLSMSK_R64_MEM64),
            _ => None,
        },
        iclass::XED_ICLASS_BLSR => match shapes {
            [Shape::Reg32, Shape::Reg32] => Some(forms::BLSR_R32_R32),
            [Shape::Reg32, Shape::Mem32] => Some(forms::BLSR_R32_MEM32),
            [Shape::Reg64, Shape::Reg64] => Some(forms::BLSR_R64_R64),
            [Shape::Reg64, Shape::Mem64] => Some(forms::BLSR_R64_MEM64),
            _ => None,
        },
        iclass::XED_ICLASS_BZHI => match shapes {
            [Shape::Reg32, Shape::Reg32, Shape::Reg32] => Some(forms::BZHI_R32_R32_R32),
            [Shape::Reg32, Shape::Mem32, Shape::Reg32] => Some(forms::BZHI_R32_MEM32_R32),
            [Shape::Reg64, Shape::Reg64, Shape::Reg64] => Some(forms::BZHI_R64_R64_R64),
            [Shape::Reg64, Shape::Mem64, Shape::Reg64] => Some(forms::BZHI_R64_MEM64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_MULX => match shapes {
            [Shape::Reg32, Shape::Reg32, Shape::Reg32] => Some(forms::MULX_R32_R32_R32),
            [Shape::Reg32, Shape::Reg32, Shape::Mem32] => Some(forms::MULX_R32_R32_MEM32),
            [Shape::Reg64, Shape::Reg64, Shape::Reg64] => Some(forms::MULX_R64_R64_R64),
            [Shape::Reg64, Shape::Reg64, Shape::Mem64] => Some(forms::MULX_R64_R64_MEM64),
            _ => None,
        },
        iclass::XED_ICLASS_RORX => match shapes {
            [Shape::Reg32, Shape::Reg32, Shape::Imm] => Some(forms::RORX_R32_R32_IMM8),
            [Shape::Reg32, Shape::Mem32, Shape::Imm] => Some(forms::RORX_R32_MEM32_IMM8),
            [Shape::Reg64, Shape::Reg64, Shape::Imm] => Some(forms::RORX_R64_R64_IMM8),
            [Shape::Reg64, Shape::Mem64, Shape::Imm] => Some(forms::RORX_R64_MEM64_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_SARX => match shapes {
            [Shape::Reg32, Shape::Reg32, Shape::Reg32] => Some(forms::SARX_R32_R32_R32),
            [Shape::Reg32, Shape::Mem32, Shape::Reg32] => Some(forms::SARX_R32_MEM32_R32),
            [Shape::Reg64, Shape::Reg64, Shape::Reg64] => Some(forms::SARX_R64_R64_R64),
            [Shape::Reg64, Shape::Mem64, Shape::Reg64] => Some(forms::SARX_R64_MEM64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_SHLX => match shapes {
            [Shape::Reg32, Shape::Reg32, Shape::Reg32] => Some(forms::SHLX_R32_R32_R32),
            [Shape::Reg32, Shape::Mem32, Shape::Reg32] => Some(forms::SHLX_R32_MEM32_R32),
            [Shape::Reg64, Shape::Reg64, Shape::Reg64] => Some(forms::SHLX_R64_R64_R64),
            [Shape::Reg64, Shape::Mem64, Shape::Reg64] => Some(forms::SHLX_R64_MEM64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_SHRX => match shapes {
            [Shape::Reg32, Shape::Reg32, Shape::Reg32] => Some(forms::SHRX_R32_R32_R32),
            [Shape::Reg32, Shape::Mem32, Shape::Reg32] => Some(forms::SHRX_R32_MEM32_R32),
            [Shape::Reg64, Shape::Reg64, Shape::Reg64] => Some(forms::SHRX_R64_R64_R64),
            [Shape::Reg64, Shape::Mem64, Shape::Reg64] => Some(forms::SHRX_R64_MEM64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_CLC => Some(forms::CLC),
        iclass::XED_ICLASS_STC => Some(forms::STC),
        iclass::XED_ICLASS_FWAIT => Some(forms::FWAIT),
        iclass::XED_ICLASS_CLTS => Some(forms::CLTS),
        iclass::XED_ICLASS_CMC => Some(forms::CMC),
        iclass::XED_ICLASS_CBW => Some(forms::CBW),
        iclass::XED_ICLASS_CWDE => Some(forms::CWDE),
        iclass::XED_ICLASS_CDQE => Some(forms::CDQE),
        iclass::XED_ICLASS_CWD => Some(forms::CWD),
        iclass::XED_ICLASS_CDQ => Some(forms::CDQ),
        iclass::XED_ICLASS_CMOVO => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVO_R64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMOVO_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVNO => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVNO_R64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMOVNO_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVP => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVP_R64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMOVP_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVNP => match shapes {
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVNP_R64_R64),
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMOVNP_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVZ => match shapes {
            [Shape::Reg16, Shape::Reg16 | Shape::Mem16] => Some(forms::CMOVZ_R16_R16),
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMOVZ_R32_R32),
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVZ_R64_R64),
            [Shape::Reg64, Shape::Mem64] => Some(forms::CMOVZ_R64_R64),
            [Shape::Reg32, Shape::Mem32] => Some(forms::CMOVZ_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVNZ => match shapes {
            [Shape::Reg16, Shape::Reg16 | Shape::Mem16] => Some(forms::CMOVNZ_R16_R16),
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMOVNZ_R32_R32),
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVNZ_R64_R64),
            [Shape::Reg64, Shape::Mem64] => Some(forms::CMOVNZ_R64_R64),
            [Shape::Reg32, Shape::Mem32] => Some(forms::CMOVNZ_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVL => match shapes {
            [Shape::Reg16, Shape::Reg16 | Shape::Mem16] => Some(forms::CMOVL_R16_R16),
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMOVL_R32_R32),
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVL_R64_R64),
            [Shape::Reg64, Shape::Mem64] => Some(forms::CMOVL_R64_R64),
            [Shape::Reg32, Shape::Mem32] => Some(forms::CMOVL_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVNL => match shapes {
            [Shape::Reg16, Shape::Reg16 | Shape::Mem16] => Some(forms::CMOVNL_R16_R16),
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMOVGE_R32_R32),
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVGE_R64_R64),
            [Shape::Reg64, Shape::Mem64] => Some(forms::CMOVGE_R64_R64),
            [Shape::Reg32, Shape::Mem32] => Some(forms::CMOVGE_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVLE => match shapes {
            [Shape::Reg16, Shape::Reg16 | Shape::Mem16] => Some(forms::CMOVLE_R16_R16),
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMOVLE_R32_R32),
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVLE_R64_R64),
            [Shape::Reg64, Shape::Mem64] => Some(forms::CMOVLE_R64_R64),
            [Shape::Reg32, Shape::Mem32] => Some(forms::CMOVLE_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVNLE => match shapes {
            [Shape::Reg16, Shape::Reg16 | Shape::Mem16] => Some(forms::CMOVNLE_R16_R16),
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMOVG_R32_R32),
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVG_R64_R64),
            [Shape::Reg64, Shape::Mem64] => Some(forms::CMOVG_R64_R64),
            [Shape::Reg32, Shape::Mem32] => Some(forms::CMOVG_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVB => match shapes {
            [Shape::Reg16, Shape::Reg16 | Shape::Mem16] => Some(forms::CMOVB_R16_R16),
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMOVB_R32_R32),
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVB_R64_R64),
            [Shape::Reg64, Shape::Mem64] => Some(forms::CMOVB_R64_R64),
            [Shape::Reg32, Shape::Mem32] => Some(forms::CMOVB_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVNB => match shapes {
            [Shape::Reg16, Shape::Reg16 | Shape::Mem16] => Some(forms::CMOVNB_R16_R16),
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMOVAE_R32_R32),
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVAE_R64_R64),
            [Shape::Reg64, Shape::Mem64] => Some(forms::CMOVAE_R64_R64),
            [Shape::Reg32, Shape::Mem32] => Some(forms::CMOVAE_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVBE => match shapes {
            [Shape::Reg16, Shape::Reg16 | Shape::Mem16] => Some(forms::CMOVBE_R16_R16),
            [Shape::Reg32, Shape::Reg32] => Some(forms::CMOVBE_R32_R32),
            [Shape::Reg64, Shape::Reg64] => Some(forms::CMOVBE_R64_R64),
            [Shape::Reg64, Shape::Mem64] => Some(forms::CMOVBE_R64_R64),
            [Shape::Reg32, Shape::Mem32] => Some(forms::CMOVBE_R32_R32),
            _ => None,
        },
        iclass::XED_ICLASS_CMOVNBE => match shapes {
            [Shape::Reg16, Shape::Reg16 | Shape::Mem16] => Some(forms::CMOVNBE_R16_R16),
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
            [Shape::Mem8] => Some(forms::SETZ_MEM8),
            _ => None,
        },
        iclass::XED_ICLASS_SETNZ => match shapes {
            [Shape::Reg8] => Some(forms::SETNZ_R8),
            [Shape::Mem8] => Some(forms::SETNZ_MEM8),
            _ => None,
        },
        iclass::XED_ICLASS_SETL => match shapes {
            [Shape::Reg8] => Some(forms::SETL_R8),
            [Shape::Mem8] => Some(forms::SETL_MEM8),
            _ => None,
        },
        iclass::XED_ICLASS_SETNL => match shapes {
            [Shape::Reg8] => Some(forms::SETGE_R8),
            [Shape::Mem8] => Some(forms::SETGE_MEM8),
            _ => None,
        },
        iclass::XED_ICLASS_SETLE => match shapes {
            [Shape::Reg8] => Some(forms::SETLE_R8),
            [Shape::Mem8] => Some(forms::SETLE_MEM8),
            _ => None,
        },
        iclass::XED_ICLASS_SETNLE => match shapes {
            [Shape::Reg8] => Some(forms::SETG_R8),
            [Shape::Mem8] => Some(forms::SETG_MEM8),
            _ => None,
        },
        iclass::XED_ICLASS_SETB => match shapes {
            [Shape::Reg8] => Some(forms::SETB_R8),
            [Shape::Mem8] => Some(forms::SETB_MEM8),
            _ => None,
        },
        iclass::XED_ICLASS_SETNB => match shapes {
            [Shape::Reg8] => Some(forms::SETAE_R8),
            [Shape::Mem8] => Some(forms::SETAE_MEM8),
            _ => None,
        },
        iclass::XED_ICLASS_SETBE => match shapes {
            [Shape::Reg8] => Some(forms::SETBE_R8),
            [Shape::Mem8] => Some(forms::SETBE_MEM8),
            _ => None,
        },
        iclass::XED_ICLASS_SETNBE => match shapes {
            [Shape::Reg8] => Some(forms::SETA_R8),
            [Shape::Mem8] => Some(forms::SETA_MEM8),
            _ => None,
        },
        iclass::XED_ICLASS_SETS => match shapes {
            [Shape::Reg8] => Some(forms::SETS_R8),
            [Shape::Mem8] => Some(forms::SETS_MEM8),
            _ => None,
        },
        iclass::XED_ICLASS_SETNS => match shapes {
            [Shape::Reg8] => Some(forms::SETNS_R8),
            [Shape::Mem8] => Some(forms::SETNS_MEM8),
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
            [Shape::Imm] => Some(forms::RET_IMM16),
            _ => None,
        },
        // `syscall` is executed by the environment model, not the semantic
        // corpus; it maps to the runtime's reserved syscall form id.
        iclass::XED_ICLASS_IDIV => match shapes {
            [Shape::Reg64] => Some(forms::IDIV_R64),
            _ => None,
        },
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
        iclass::XED_ICLASS_CRC32 => match shapes {
            [Shape::Reg32, Shape::Reg32] => Some(forms::CRC32_R32_R32),
            [Shape::Reg64, Shape::Reg64] => Some(forms::CRC32_R64_R64),
            [Shape::Reg32, Shape::Reg8] => Some(forms::CRC32_R32_R8),
            [Shape::Reg64, Shape::Reg8] => Some(forms::CRC32_R64_R8),
            [Shape::Reg32, Shape::Mem32] => Some(forms::CRC32_R32_MEM32),
            [Shape::Reg64, Shape::Mem64] => Some(forms::CRC32_R64_MEM64),
            [Shape::Reg32, Shape::Mem8] => Some(forms::CRC32_R32_MEM8),
            [Shape::Reg64, Shape::Mem8] => Some(forms::CRC32_R64_MEM8),
            _ => None,
        },
        iclass::XED_ICLASS_CMPXCHG_LOCK => match shapes {
            [Shape::Mem32, Shape::Reg32] => Some(forms::CMPXCHG_MEM32_R32),
            [Shape::Mem64, Shape::Reg64] => Some(forms::CMPXCHG_MEM64_R64),
            [Shape::Mem8, Shape::Reg8] => Some(forms::CMPXCHG_MEM8_R8),
            _ => None,
        },
        iclass::XED_ICLASS_SYSCALL => Some(crate::SYSCALL_FORM_ID),
        iclass::XED_ICLASS_CPUID => Some(crate::CPUID_FORM_ID),
        iclass::XED_ICLASS_NOP => Some(forms::NOP),
        iclass::XED_ICLASS_HLT => Some(forms::HLT),
        iclass::XED_ICLASS_UD2 => Some(forms::UD2),
        iclass::XED_ICLASS_RDTSC => Some(forms::RDTSC),
        iclass::XED_ICLASS_RDTSCP => Some(forms::RDTSCP),
        iclass::XED_ICLASS_XGETBV => Some(forms::XGETBV),
        iclass::XED_ICLASS_WBINVD => Some(forms::WBINVD),
        iclass::XED_ICLASS_INVD => Some(forms::INVD),
        iclass::XED_ICLASS_RDMSR => Some(forms::RDMSR),
        iclass::XED_ICLASS_WRMSR => Some(forms::WRMSR),
        iclass::XED_ICLASS_LFENCE | iclass::XED_ICLASS_SFENCE | iclass::XED_ICLASS_MFENCE => Some(forms::FENCE),
        iclass::XED_ICLASS_PAUSE => Some(forms::NOP),
        iclass::XED_ICLASS_IN => match shapes {
            [Shape::Reg8, Shape::Reg16] => Some(forms::IN_AL_DX),
            [Shape::Reg16, Shape::Reg16] => Some(forms::IN_AX_DX),
            [Shape::Reg32, Shape::Reg16] => Some(forms::IN_EAX_DX),
            [Shape::Reg8, Shape::Imm] => Some(forms::IN_AL_IMM8),
            [Shape::Reg16, Shape::Imm] => Some(forms::IN_AX_IMM8),
            [Shape::Reg32, Shape::Imm] => Some(forms::IN_EAX_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_OUT => match shapes {
            [Shape::Reg16, Shape::Reg8] => Some(forms::OUT_DX_AL),
            [Shape::Reg16, Shape::Reg16] => Some(forms::OUT_DX_AX),
            [Shape::Reg16, Shape::Reg32] => Some(forms::OUT_DX_EAX),
            [Shape::Imm, Shape::Reg8] => Some(forms::OUT_IMM8_AL),
            [Shape::Imm, Shape::Reg16] => Some(forms::OUT_IMM8_AX),
            [Shape::Imm, Shape::Reg32] => Some(forms::OUT_IMM8_EAX),
            _ => None,
        },
        iclass::XED_ICLASS_INT => Some(forms::INT_IMM8),
        iclass::XED_ICLASS_INT1 | iclass::XED_ICLASS_INT3 => Some(forms::NOP2),
        iclass::XED_ICLASS_INSB => Some(forms::INSB),
        iclass::XED_ICLASS_INSW => Some(forms::INSW),
        iclass::XED_ICLASS_INSD => Some(forms::INSD),
        iclass::XED_ICLASS_OUTSB => Some(forms::OUTSB),
        iclass::XED_ICLASS_OUTSW => Some(forms::OUTSW),
        iclass::XED_ICLASS_OUTSD => Some(forms::OUTSD),
        iclass::XED_ICLASS_REP_INSB => Some(REP_INSB_FORM_ID),
        iclass::XED_ICLASS_REP_INSW => Some(REP_INSW_FORM_ID),
        iclass::XED_ICLASS_REP_INSD => Some(REP_INSD_FORM_ID),
        iclass::XED_ICLASS_REP_OUTSB => Some(REP_OUTSB_FORM_ID),
        iclass::XED_ICLASS_REP_OUTSW => Some(REP_OUTSW_FORM_ID),
        iclass::XED_ICLASS_REP_OUTSD => Some(REP_OUTSD_FORM_ID),
        iclass::XED_ICLASS_LOOP => Some(forms::LOOP_REL8),
        iclass::XED_ICLASS_LOOPE => Some(forms::LOOPE_REL8),
        iclass::XED_ICLASS_LOOPNE => Some(forms::LOOPNE_REL8),
        iclass::XED_ICLASS_JRCXZ => Some(forms::JRCXZ_REL8),
        iclass::XED_ICLASS_RET_FAR => match shapes {
            [] => Some(forms::RET_FAR),
            [Shape::Imm] => Some(forms::RET_FAR_IMM16),
            _ => None,
        },
        iclass::XED_ICLASS_ENTER => Some(forms::ENTER_IMM16_IMM8),
        iclass::XED_ICLASS_LAHF => Some(forms::LAHF),
        iclass::XED_ICLASS_SAHF => Some(forms::SAHF),
        iclass::XED_ICLASS_CLD => Some(forms::CLD),
        iclass::XED_ICLASS_STD => Some(forms::STD),
        iclass::XED_ICLASS_CMPSB => Some(CMPSB_FORM_ID),
        iclass::XED_ICLASS_CMPSW => Some(CMPSW_FORM_ID),
        iclass::XED_ICLASS_CMPSD => Some(CMPSD_FORM_ID),
        iclass::XED_ICLASS_CMPSQ => Some(CMPSQ_FORM_ID),
        iclass::XED_ICLASS_SCASB => Some(SCASB_FORM_ID),
        iclass::XED_ICLASS_SCASW => Some(SCASW_FORM_ID),
        iclass::XED_ICLASS_SCASD => Some(SCASD_FORM_ID),
        iclass::XED_ICLASS_SCASQ => Some(SCASQ_FORM_ID),
        iclass::XED_ICLASS_REPE_CMPSB => Some(REPE_CMPSB_FORM_ID),
        iclass::XED_ICLASS_REPE_CMPSW => Some(REPE_CMPSW_FORM_ID),
        iclass::XED_ICLASS_REPE_CMPSD => Some(REPE_CMPSD_FORM_ID),
        iclass::XED_ICLASS_REPE_CMPSQ => Some(REPE_CMPSQ_FORM_ID),
        iclass::XED_ICLASS_REPNE_CMPSB => Some(REPNE_CMPSB_FORM_ID),
        iclass::XED_ICLASS_REPNE_CMPSW => Some(REPNE_CMPSW_FORM_ID),
        iclass::XED_ICLASS_REPNE_CMPSD => Some(REPNE_CMPSD_FORM_ID),
        iclass::XED_ICLASS_REPNE_CMPSQ => Some(REPNE_CMPSQ_FORM_ID),
        iclass::XED_ICLASS_REPE_SCASB => Some(REPE_SCASB_FORM_ID),
        iclass::XED_ICLASS_REPE_SCASW => Some(REPE_SCASW_FORM_ID),
        iclass::XED_ICLASS_REPE_SCASD => Some(REPE_SCASD_FORM_ID),
        iclass::XED_ICLASS_REPE_SCASQ => Some(REPE_SCASQ_FORM_ID),
        iclass::XED_ICLASS_REPNE_SCASB => Some(REPNE_SCASB_FORM_ID),
        iclass::XED_ICLASS_REPNE_SCASW => Some(REPNE_SCASW_FORM_ID),
        iclass::XED_ICLASS_REPNE_SCASD => Some(REPNE_SCASD_FORM_ID),
        iclass::XED_ICLASS_REPNE_SCASQ => Some(REPNE_SCASQ_FORM_ID),
        iclass::XED_ICLASS_FCOM => match shapes {
            [.., Shape::Mem32] => Some(forms::FCOM_M32),
            [.., Shape::Mem64] => Some(forms::FCOM_M64),
            _ => Some(forms::FCOM_STI),
        },
        iclass::XED_ICLASS_FCOMP => match shapes {
            [.., Shape::Mem32] => Some(forms::FCOMP_M32),
            [.., Shape::Mem64] => Some(forms::FCOMP_M64),
            _ => Some(forms::FCOMP_STI),
        },
        iclass::XED_ICLASS_FCOMPP => Some(forms::FCOMPP),
        // FNSTSW/FSTSW: AX register dump (`DF E0`), or m16 store.
        iclass::XED_ICLASS_FNSTSW => match shapes {
            [Shape::Reg16] => Some(forms::FSTSW_AX),
            [Shape::Mem16, ..] => Some(forms::FSTSW_M16),
            _ => None,
        },
        iclass::XED_ICLASS_FLDCW => match shapes {
            [Shape::Mem16, ..] => Some(forms::FLDCW_M16),
            _ => None,
        },
        iclass::XED_ICLASS_FNSTCW => match shapes {
            [Shape::Mem16, ..] => Some(forms::FNSTCW_M16),
            _ => None,
        },
        iclass::XED_ICLASS_FNCLEX => Some(forms::FNCLEX),
        iclass::XED_ICLASS_FTST => Some(forms::FTST),
        iclass::XED_ICLASS_FXAM => Some(forms::FXAM),
        iclass::XED_ICLASS_FDECSTP => Some(forms::FDECSTP),
        iclass::XED_ICLASS_FINCSTP => Some(forms::FINCSTP),
        iclass::XED_ICLASS_FFREE => match shapes {
            [Shape::Stack, ..] => Some(forms::FFREE_STI),
            _ => None,
        },
        iclass::XED_ICLASS_FRNDINT => Some(forms::FRNDINT),
        iclass::XED_ICLASS_FIADD => match shapes {
            [.., Shape::Mem16] => Some(forms::FIADD_M16),
            [.., Shape::Mem32] => Some(forms::FIADD_M32),
            _ => None,
        },
        iclass::XED_ICLASS_FISUB => match shapes {
            [.., Shape::Mem16] => Some(forms::FISUB_M16),
            [.., Shape::Mem32] => Some(forms::FISUB_M32),
            _ => None,
        },
        iclass::XED_ICLASS_FISUBR => match shapes {
            [.., Shape::Mem16] => Some(forms::FISUBR_M16),
            [.., Shape::Mem32] => Some(forms::FISUBR_M32),
            _ => None,
        },
        iclass::XED_ICLASS_FIMUL => match shapes {
            [.., Shape::Mem16] => Some(forms::FIMUL_M16),
            [.., Shape::Mem32] => Some(forms::FIMUL_M32),
            _ => None,
        },
        iclass::XED_ICLASS_FIDIV => match shapes {
            [.., Shape::Mem16] => Some(forms::FIDIV_M16),
            [.., Shape::Mem32] => Some(forms::FIDIV_M32),
            _ => None,
        },
        iclass::XED_ICLASS_FIDIVR => match shapes {
            [.., Shape::Mem16] => Some(forms::FIDIVR_M16),
            [.., Shape::Mem32] => Some(forms::FIDIVR_M32),
            _ => None,
        },
        iclass::XED_ICLASS_FICOM => match shapes {
            [.., Shape::Mem16] => Some(forms::FICOM_M16),
            [.., Shape::Mem32] => Some(forms::FICOM_M32),
            _ => None,
        },
        iclass::XED_ICLASS_FICOMP => match shapes {
            [.., Shape::Mem16] => Some(forms::FICOMP_M16),
            [.., Shape::Mem32] => Some(forms::FICOMP_M32),
            _ => None,
        },
        iclass::XED_ICLASS_FILD => match shapes {
            [.., Shape::Mem16] => Some(forms::FILD_M16),
            [.., Shape::Mem32] => Some(forms::FILD_M32),
            [.., Shape::Mem64] => Some(forms::FILD_M64),
            _ => None,
        },
        iclass::XED_ICLASS_FIST => match shapes {
            [Shape::Mem16, ..] => Some(forms::FIST_M16),
            [Shape::Mem32, ..] => Some(forms::FIST_M32),
            _ => None,
        },
        iclass::XED_ICLASS_FISTP => match shapes {
            [Shape::Mem16, ..] => Some(forms::FISTP_M16),
            [Shape::Mem32, ..] => Some(forms::FISTP_M32),
            [Shape::Mem64, ..] => Some(forms::FISTP_M64),
            _ => None,
        },
        iclass::XED_ICLASS_FABS => Some(forms::FABS),
        iclass::XED_ICLASS_FCHS => Some(forms::FCHS),
        iclass::XED_ICLASS_FSQRT => Some(forms::FSQRT),
        iclass::XED_ICLASS_FXCH => match shapes {
            [] => Some(forms::FXCH),
            [Shape::Stack] => Some(forms::FXCH_STI),
            [Shape::Stack, Shape::Stack] => Some(forms::FXCH_STI),
            _ => Some(forms::FXCH),
        },
        iclass::XED_ICLASS_ADDSS => Some(forms::ADDSS_XMM_XMM),
        iclass::XED_ICLASS_SUBSS => Some(forms::SUBSS_XMM_XMM),
        iclass::XED_ICLASS_MULSS => Some(forms::MULSS_XMM_XMM),
        iclass::XED_ICLASS_DIVSS => Some(forms::DIVSS_XMM_XMM),
        iclass::XED_ICLASS_SQRTSS => Some(forms::SQRTSS_XMM_XMM),
        iclass::XED_ICLASS_SQRTSD => Some(forms::SQRTSD_XMM_XMM),
        iclass::XED_ICLASS_COMISS => Some(forms::COMISS_XMM_XMM),
        iclass::XED_ICLASS_COMISD => Some(forms::COMISD_XMM_XMM),
        iclass::XED_ICLASS_UCOMISS => Some(forms::UCOMISS_XMM_XMM),
        iclass::XED_ICLASS_CVTSS2SD => Some(forms::CVTSS2SD_XMM_XMM),
        iclass::XED_ICLASS_CVTSD2SS => Some(forms::CVTSD2SS_XMM_XMM),
        iclass::XED_ICLASS_MAXSS => Some(forms::MAXSS_XMM_XMM),
        iclass::XED_ICLASS_MAXSD => Some(forms::MAXSD_XMM_XMM),
        iclass::XED_ICLASS_MINSS => Some(forms::MINSS_XMM_XMM),
        iclass::XED_ICLASS_MINSD => Some(forms::MINSD_XMM_XMM),
        iclass::XED_ICLASS_PEXTRD => match shapes {
            [Shape::Reg32, Shape::Xmm, Shape::Imm] => Some(forms::PEXTRD_R32_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_PEXTRQ => match shapes {
            [Shape::Reg64, Shape::Xmm, Shape::Imm] => Some(forms::PEXTRQ_R64_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_PINSRD => match shapes {
            [Shape::Xmm, Shape::Reg32, Shape::Imm] => Some(forms::PINSRD_XMM_R32_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_PINSRQ => match shapes {
            [Shape::Xmm, Shape::Reg64, Shape::Imm] => Some(forms::PINSRQ_XMM_R64_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_PMAXUD => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMAXUD_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PMINSD => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMINSD_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_ROUNDPS => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Imm] => Some(forms::ROUNDPS_XMM_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_ROUNDPD => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Imm] => Some(forms::ROUNDPD_XMM_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_ROUNDSS => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Imm] => Some(forms::ROUNDSS_XMM_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_ROUNDSD => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Imm] => Some(forms::ROUNDSD_XMM_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_BLENDVPS => match shapes {
            [Shape::Xmm, Shape::Xmm] | [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::BLENDVPS_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_BLENDVPD => match shapes {
            [Shape::Xmm, Shape::Xmm] | [Shape::Xmm, Shape::Xmm, Shape::Xmm] => Some(forms::BLENDVPD_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_INSERTPS => match shapes {
            [Shape::Xmm, Shape::Xmm, Shape::Imm] => Some(forms::INSERTPS_XMM_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_EXTRACTPS => match shapes {
            [Shape::Reg32, Shape::Xmm, Shape::Imm] => Some(forms::EXTRACTPS_R32_XMM_IMM8),
            _ => None,
        },
        iclass::XED_ICLASS_MOVNTDQA => match shapes {
            [Shape::Xmm, Shape::Mem128] => Some(forms::MOVNTDQA_XMM_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_PMOVSXBW => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMOVSXBW_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PMOVZXBW => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMOVZXBW_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PMOVSXBD => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMOVSXBD_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PMOVSXWD => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMOVSXWD_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PMOVZXWD => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMOVZXWD_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PMOVSXDQ => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMOVSXDQ_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PMOVZXDQ => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMOVZXDQ_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PMOVSXWQ => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMOVSXWQ_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PMOVZXWQ => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMOVZXWQ_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PMOVSXBQ => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMOVSXBQ_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_PMOVZXBQ => match shapes {
            [Shape::Xmm, Shape::Xmm] => Some(forms::PMOVZXBQ_XMM_XMM),
            _ => None,
        },
        iclass::XED_ICLASS_XADD_LOCK => match shapes {
            [Shape::Mem32, Shape::Reg32] => Some(forms::XADD_MEM32_R32),
            [Shape::Mem64, Shape::Reg64] => Some(forms::XADD_MEM64_R64),
            [Shape::Mem16, Shape::Reg16] => Some(forms::XADD_MEM16_R16),
            [Shape::Mem8, Shape::Reg8] => Some(forms::XADD_MEM8_R8),
            _ => None,
        },
        iclass::XED_ICLASS_SETO => match shapes {
            [Shape::Reg8] => Some(forms::SETO_R8),
            [Shape::Mem8] => Some(forms::SETO_MEM8),
            _ => None,
        },
        iclass::XED_ICLASS_SETNO => match shapes {
            [Shape::Reg8] => Some(forms::SETNO_R8),
            [Shape::Mem8] => Some(forms::SETNO_MEM8),
            _ => None,
        },
        iclass::XED_ICLASS_SETP => match shapes {
            [Shape::Reg8] => Some(forms::SETP_R8),
            [Shape::Mem8] => Some(forms::SETP_MEM8),
            _ => None,
        },
        iclass::XED_ICLASS_SETNP => match shapes {
            [Shape::Reg8] => Some(forms::SETNP_R8),
            [Shape::Mem8] => Some(forms::SETNP_MEM8),
            _ => None,
        },
        iclass::XED_ICLASS_CLFLUSH => match shapes {
            [Shape::Mem] | [Shape::Mem8] | [Shape::Mem16] | [Shape::Mem32] | [Shape::Mem64] => Some(forms::CLFLUSH_MEM),
            _ => None,
        },
        iclass::XED_ICLASS_MOVBE => match shapes {
            [Shape::Reg16, Shape::Mem16] => Some(forms::MOVBE_R16_MEM16),
            [Shape::Reg32, Shape::Mem32] => Some(forms::MOVBE_R32_MEM32),
            [Shape::Reg64, Shape::Mem64] => Some(forms::MOVBE_R64_MEM64),
            [Shape::Mem16, Shape::Reg16] => Some(forms::MOVBE_MEM16_R16),
            [Shape::Mem32, Shape::Reg32] => Some(forms::MOVBE_MEM32_R32),
            [Shape::Mem64, Shape::Reg64] => Some(forms::MOVBE_MEM64_R64),
            _ => None,
        },
        iclass::XED_ICLASS_JMP_FAR => match shapes {
            [Shape::Mem] | [Shape::Mem64] | [Shape::Mem32] | [Shape::Mem16] | [Shape::Mem80] | [Shape::FarPtr] => {
                Some(forms::JMP_FAR_MEM)
            }
            _ => None,
        },
        iclass::XED_ICLASS_MOV_CR => match decoded.operands.first().map(|operand| operand.access) {
            Some(angryier_arch::AccessKind::Write) => Some(forms::MOV_R64_CR),
            Some(angryier_arch::AccessKind::Read) => Some(forms::MOV_CR_R64),
            _ => None,
        },
        iclass::XED_ICLASS_MOV_DR => match decoded.operands.first().map(|operand| operand.access) {
            Some(angryier_arch::AccessKind::Write) => Some(forms::MOV_R64_DR),
            Some(angryier_arch::AccessKind::Read) => Some(forms::MOV_DR_R64),
            _ => None,
        },
        iclass::XED_ICLASS_IRETD => Some(forms::IRETD),
        // x87 transcendental family: form IDs reserved; providers are absent
        // (missing FloatingOp primitives — see forms::FSIN/FCOS/... in
        // angryier-semantics-intel64/src/lib.rs).
        iclass::XED_ICLASS_FSIN => Some(forms::FSIN),
        iclass::XED_ICLASS_FCOS => Some(forms::FCOS),
        iclass::XED_ICLASS_FPTAN => Some(forms::FPTAN),
        iclass::XED_ICLASS_FPATAN => Some(forms::FPATAN),
        iclass::XED_ICLASS_F2XM1 => Some(forms::F2XM1),
        iclass::XED_ICLASS_FYL2X => Some(forms::FYL2X),
        iclass::XED_ICLASS_FYL2XP1 => Some(forms::FYL2XP1),
        iclass::XED_ICLASS_FSCALE => Some(forms::FSCALE),
        iclass::XED_ICLASS_FSINCOS => Some(forms::FSINCOS),
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
    fn maps_amx_forms() -> Result<(), Box<dyn std::error::Error>> {
        // tilerelease
        assert_eq!(mapped(&[0xc4, 0xe2, 0x78, 0x49, 0xc0])?, Some(amx_forms::TILERELEASE));
        // tilezero %tmm0
        assert_eq!(mapped(&[0xc4, 0xe2, 0x7b, 0x49, 0xc0])?, Some(amx_forms::TILEZERO_TMM));
        // ldtilecfg (%rax)
        assert_eq!(mapped(&[0xc4, 0xe2, 0x78, 0x49, 0x00])?, Some(amx_forms::LDTILECFG_MEM));
        // sttilecfg (%rax)
        assert_eq!(mapped(&[0xc4, 0xe2, 0x79, 0x49, 0x00])?, Some(amx_forms::STTILECFG_MEM));
        // tileloadd (%rax,%rcx,1), %tmm0
        assert_eq!(
            mapped(&[0xc4, 0xe2, 0x7b, 0x4b, 0x04, 0x08])?,
            Some(amx_forms::TILELOADD_TMM_MEM)
        );
        // tilestored %tmm0, (%rax,%rcx,1)
        assert_eq!(
            mapped(&[0xc4, 0xe2, 0x7a, 0x4b, 0x04, 0x08])?,
            Some(amx_forms::TILESTORED_MEM_TMM)
        );
        // tdpbssd %tmm2, %tmm1, %tmm0
        assert_eq!(
            mapped(&[0xc4, 0xe2, 0x6b, 0x5e, 0xc1])?,
            Some(amx_forms::TDPBSSD_TMM_TMM_TMM)
        );
        // tdpbsud %tmm2, %tmm1, %tmm0
        assert_eq!(
            mapped(&[0xc4, 0xe2, 0x6a, 0x5e, 0xc1])?,
            Some(amx_forms::TDPBSUD_TMM_TMM_TMM)
        );
        // tdpbusd %tmm2, %tmm1, %tmm0
        assert_eq!(
            mapped(&[0xc4, 0xe2, 0x69, 0x5e, 0xc1])?,
            Some(amx_forms::TDPBUSD_TMM_TMM_TMM)
        );
        // tdpbuud %tmm2, %tmm1, %tmm0
        assert_eq!(
            mapped(&[0xc4, 0xe2, 0x68, 0x5e, 0xc1])?,
            Some(amx_forms::TDPBUUD_TMM_TMM_TMM)
        );
        // tdpbf16ps %tmm2, %tmm1, %tmm0
        assert_eq!(
            mapped(&[0xc4, 0xe2, 0x6a, 0x5c, 0xc1])?,
            Some(amx_forms::TDPBF16PS_TMM_TMM_TMM)
        );
        // tdpfp16ps %tmm2, %tmm1, %tmm0
        assert_eq!(
            mapped(&[0xc4, 0xe2, 0x6b, 0x5c, 0xc1])?,
            Some(amx_forms::TDPFP16PS_TMM_TMM_TMM)
        );
        Ok(())
    }

    #[test]
    fn maps_cet_forms() -> Result<(), Box<dyn std::error::Error>> {
        // endbr64
        assert_eq!(mapped(&[0xf3, 0x0f, 0x1e, 0xfa])?, Some(forms::NOP2));
        // rdsspd %eax
        assert_eq!(mapped(&[0xf3, 0x0f, 0x1e, 0xc8])?, Some(forms::RDSSPD_R32));
        // rdsspq %rax
        assert_eq!(mapped(&[0xf3, 0x48, 0x0f, 0x1e, 0xc8])?, Some(forms::RDSSPQ_R64));
        // incsspd %eax
        assert_eq!(mapped(&[0xf3, 0x0f, 0xae, 0xe8])?, Some(forms::INCSSPD_R32));
        // incsspq %rax
        assert_eq!(mapped(&[0xf3, 0x48, 0x0f, 0xae, 0xe8])?, Some(forms::INCSSPQ_R64));
        // saveprevssp
        assert_eq!(mapped(&[0xf3, 0x0f, 0x01, 0xea])?, Some(forms::SAVEPREVSSP));
        // rstorssp (%rax)
        assert_eq!(mapped(&[0xf3, 0x0f, 0x01, 0x28])?, Some(forms::RSTORSSP_MEM64));
        // setssbsy
        assert_eq!(mapped(&[0xf3, 0x0f, 0x01, 0xe8])?, Some(forms::SETSSBSY));
        // clrssbsy (%rax)
        assert_eq!(mapped(&[0xf3, 0x0f, 0xae, 0x30])?, Some(forms::CLRSSBSY_MEM64));
        // wrssd %eax, (%rcx)
        assert_eq!(mapped(&[0x0f, 0x38, 0xf6, 0x01])?, Some(forms::WRSSD_MEM32_R32));
        // wrssq %rax, (%rcx)
        assert_eq!(mapped(&[0x48, 0x0f, 0x38, 0xf6, 0x01])?, Some(forms::WRSSQ_MEM64_R64));
        // wrussd %eax, (%rcx)
        assert_eq!(mapped(&[0x66, 0x0f, 0x38, 0xf5, 0x01])?, Some(forms::WRUSSD_MEM32_R32));
        // wrussq %rax, (%rcx)
        assert_eq!(
            mapped(&[0x66, 0x48, 0x0f, 0x38, 0xf5, 0x01])?,
            Some(forms::WRUSSQ_MEM64_R64)
        );
        Ok(())
    }

    #[test]
    fn maps_apx_forms() -> Result<(), Box<dyn std::error::Error>> {
        // jmpabs 0x1122334455667788
        assert_eq!(
            mapped(&[0xd5, 0x00, 0xa1, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11])?,
            Some(forms::JMPABS_IMM64)
        );
        // push2 %r15, %rcx (64-bit stack slots)
        assert_eq!(
            mapped(&[0x62, 0xf4, 0x04, 0x18, 0xff, 0xf1])?,
            Some(forms::PUSH2_R64_R64)
        );
        // push2p %r15, %rcx (128-bit stack slots)
        assert_eq!(
            mapped(&[0x62, 0xf4, 0x84, 0x18, 0xff, 0xf1])?,
            Some(forms::PUSH2P_R64_R64)
        );
        // pop2 %r15, %rcx
        assert_eq!(
            mapped(&[0x62, 0xf4, 0x04, 0x18, 0x8f, 0xc1])?,
            Some(forms::POP2_R64_R64)
        );
        // pop2p %r15, %rcx
        assert_eq!(
            mapped(&[0x62, 0xf4, 0x84, 0x18, 0x8f, 0xc1])?,
            Some(forms::POP2P_R64_R64)
        );
        // ccmpz %rcx, %rax, dfv=0 (cc nibble is byte[3]'s low nibble)
        assert_eq!(
            mapped(&[0x62, 0xf4, 0x84, 0x04, 0x39, 0xc8])?,
            Some(forms::CCMPZ_R64_R64)
        );
        // ccmpb %rcx, %rax, dfv=0
        assert_eq!(
            mapped(&[0x62, 0xf4, 0x84, 0x02, 0x39, 0xc8])?,
            Some(forms::CCMPB_R64_R64)
        );
        // ctestz %rcx, %rax, dfv=0 (same cc-nibble rule as ccmp)
        assert_eq!(
            mapped(&[0x62, 0xf4, 0x84, 0x04, 0x85, 0xc8])?,
            Some(forms::CTESTZ_R64_R64)
        );
        // ctestb %rcx, %rax, dfv=0
        assert_eq!(
            mapped(&[0x62, 0xf4, 0x84, 0x02, 0x85, 0xc8])?,
            Some(forms::CTESTB_R64_R64)
        );
        // cfcmovz %rdx, %rax
        assert_eq!(
            mapped(&[0x62, 0xf4, 0xfc, 0x08, 0x44, 0xd0])?,
            Some(forms::CFCMOVZ_R64_R64)
        );
        // cfcmovb %rdx, %rax (cc=2: opcode 0x42, P2 bit 3 clear)
        assert_eq!(
            mapped(&[0x62, 0xf4, 0xfc, 0x08, 0x42, 0xd0])?,
            Some(forms::CFCMOVB_R64_R64)
        );
        // add %r17, %r16, %r9 (NDD, NF)
        assert_eq!(
            mapped(&[0x62, 0x7c, 0xfc, 0x14, 0x01, 0xc9])?,
            Some(forms::ADD_R64_R64_R64_NDD)
        );
        // shl %r17, %r16, 3 (NDD)
        assert_eq!(
            mapped(&[0x62, 0xfc, 0xfc, 0x10, 0xc1, 0xe1, 0x03])?,
            Some(forms::SHL_R64_R64_IMM8_NDD)
        );
        // Non-collision guard: the legacy two-operand `add %ecx, %eax` keeps
        // mapping to the legacy form, not the NDD three-destination form.
        assert_eq!(mapped(&[0x01, 0xc8])?, Some(forms::ADD_R32_R32));
        assert_ne!(mapped(&[0x01, 0xc8])?, Some(forms::ADD_R32_R32_R32_NDD));
        Ok(())
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
        assert_eq!(mapped(&[0x48, 0x6B, 0xC3, 0x05])?, Some(forms::IMUL_R64_R64_IMM8));
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
        // Packed FP reg forms are wired; their memory variants stay
        // explicitly unmapped (no registered provider shape).
        assert_eq!(mapped(&[0x0F, 0x58, 0xC1])?, Some(forms::ADDPS_XMM_XMM));
        assert_eq!(mapped(&[0x0F, 0x58, 0x00])?, None);
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

    #[test]
    fn maps_x87_forms() -> Result<(), Box<dyn std::error::Error>> {
        // fninit / fld1 / fldz
        assert_eq!(mapped(&[0xDB, 0xE3])?, Some(forms::FINIT));
        assert_eq!(mapped(&[0xD9, 0xE8])?, Some(forms::FLD1));
        assert_eq!(mapped(&[0xD9, 0xEE])?, Some(forms::FLDZ));
        // fld m64 / fld m32 / fld %st(1)
        assert_eq!(mapped(&[0xDD, 0x00])?, Some(forms::FLD_M64));
        assert_eq!(mapped(&[0xD9, 0x00])?, Some(forms::FLD_M32));
        assert_eq!(mapped(&[0xD9, 0xC1])?, Some(forms::FLD_STI));
        // fst m32 / fst m64
        assert_eq!(mapped(&[0xD9, 0x10])?, Some(forms::FST_M32));
        assert_eq!(mapped(&[0xDD, 0x10])?, Some(forms::FST_M64));
        // fstp m32 / fstp m64 / fstp %st(1) (DD encoding)
        assert_eq!(mapped(&[0xD9, 0x18])?, Some(forms::FSTP_M32));
        assert_eq!(mapped(&[0xDD, 0x18])?, Some(forms::FSTP_M64));
        assert_eq!(mapped(&[0xDD, 0xD9])?, Some(forms::FSTP_STI));
        // fstp %st(0) via the D9 encoding decodes as FSTPNCE, not FSTP.
        assert_eq!(mapped(&[0xD9, 0xD8])?, Some(forms::FSTP_STI));
        // Arithmetic, both stack directions and both memory widths.
        assert_eq!(mapped(&[0xD8, 0xC1])?, Some(forms::FADD_ST0_STI));
        assert_eq!(mapped(&[0xDC, 0xC1])?, Some(forms::FADD_STI_ST0));
        assert_eq!(mapped(&[0xD8, 0x00])?, Some(forms::FADD_M32));
        assert_eq!(mapped(&[0xDC, 0x00])?, Some(forms::FADD_M64));
        // XED swaps the FSUB/FSUBR (and FDIV/FDIVR) iclasses on the DC
        // encodings; the destination register still picks the form.
        assert_eq!(mapped(&[0xD8, 0xE1])?, Some(forms::FSUB_ST0_STI));
        assert_eq!(mapped(&[0xDC, 0xE1])?, Some(forms::FSUBR_STI_ST0));
        assert_eq!(mapped(&[0xD8, 0xE9])?, Some(forms::FSUBR_ST0_STI));
        assert_eq!(mapped(&[0xDC, 0xE9])?, Some(forms::FSUB_STI_ST0));
        assert_eq!(mapped(&[0xDC, 0x20])?, Some(forms::FSUB_M64));
        assert_eq!(mapped(&[0xDC, 0x28])?, Some(forms::FSUBR_M64));
        assert_eq!(mapped(&[0xD8, 0xC9])?, Some(forms::FMUL_ST0_STI));
        assert_eq!(mapped(&[0xDC, 0xC9])?, Some(forms::FMUL_STI_ST0));
        assert_eq!(mapped(&[0xDC, 0x08])?, Some(forms::FMUL_M64));
        assert_eq!(mapped(&[0xD8, 0xF1])?, Some(forms::FDIV_ST0_STI));
        assert_eq!(mapped(&[0xDC, 0xF1])?, Some(forms::FDIVR_STI_ST0));
        assert_eq!(mapped(&[0xDC, 0x30])?, Some(forms::FDIV_M64));
        assert_eq!(mapped(&[0xD8, 0xF9])?, Some(forms::FDIVR_ST0_STI));
        assert_eq!(mapped(&[0xDC, 0xF9])?, Some(forms::FDIV_STI_ST0));
        assert_eq!(mapped(&[0xDC, 0x38])?, Some(forms::FDIVR_M64));
        // Compare family.
        assert_eq!(mapped(&[0xDB, 0xE9])?, Some(forms::FUCOMI_ST0_STI));
        assert_eq!(mapped(&[0xDF, 0xE9])?, Some(forms::FUCOMIP_ST0_STI));
        assert_eq!(mapped(&[0xDB, 0xF1])?, Some(forms::FCOMI_ST0_STI));
        assert_eq!(mapped(&[0xDF, 0xF1])?, Some(forms::FCOMIP_ST0_STI));
        Ok(())
    }

    #[test]
    fn maps_extended_x87_and_system_forms() -> Result<(), Box<dyn std::error::Error>> {
        // `9B` is FWAIT (mapped on its own); the FSTSW that follows decodes
        // as a separate instruction and maps to the AX dump form.
        assert_eq!(mapped(&[0x9B, 0xDF, 0xE0])?, Some(forms::FWAIT));
        assert_eq!(mapped(&[0xDF, 0xE0])?, Some(forms::FSTSW_AX));
        // fst %st(1)
        assert_eq!(mapped(&[0xDD, 0xD1])?, Some(forms::FST_STI));
        // fnop (XED's decoding of the `fst %st(0)` alias)
        assert_eq!(mapped(&[0xD9, 0xD0])?, Some(forms::FNOP));
        // fldpi
        assert_eq!(mapped(&[0xD9, 0xEB])?, Some(forms::FLDPI));
        // fnclex
        assert_eq!(mapped(&[0xDB, 0xE2])?, Some(forms::FNCLEX));
        // ftst, fxam
        assert_eq!(mapped(&[0xD9, 0xE4])?, Some(forms::FTST));
        assert_eq!(mapped(&[0xD9, 0xE5])?, Some(forms::FXAM));
        // fdecstp, fincstp
        assert_eq!(mapped(&[0xD9, 0xF6])?, Some(forms::FDECSTP));
        assert_eq!(mapped(&[0xD9, 0xF7])?, Some(forms::FINCSTP));
        // ffree %st(1)
        assert_eq!(mapped(&[0xDD, 0xC1])?, Some(forms::FFREE_STI));
        // fcmovb %st(1), %st(0)
        assert_eq!(mapped(&[0xDA, 0xC1])?, Some(forms::FCMOVB_ST0_STI));
        // frndint, fsincos
        assert_eq!(mapped(&[0xD9, 0xFC])?, Some(forms::FRNDINT));
        assert_eq!(mapped(&[0xD9, 0xFB])?, Some(forms::FSINCOS));
        // rdtscp, xgetbv, wbinvd, invd
        assert_eq!(mapped(&[0x0F, 0x01, 0xF9])?, Some(forms::RDTSCP));
        assert_eq!(mapped(&[0x0F, 0x01, 0xD0])?, Some(forms::XGETBV));
        assert_eq!(mapped(&[0x0F, 0x09])?, Some(forms::WBINVD));
        assert_eq!(mapped(&[0x0F, 0x08])?, Some(forms::INVD));
        Ok(())
    }

    #[test]
    fn maps_16bit_immediate_forms() -> Result<(), Box<dyn std::error::Error>> {
        // cmp $imm16, %dx (imm16 and sign-extended imm8 encodings)
        assert_eq!(mapped(&[0x66, 0x81, 0xFA, 0x34, 0x12])?, Some(forms::CMP_R16_IMM16));
        assert_eq!(mapped(&[0x66, 0x83, 0xFA, 0x7F])?, Some(forms::CMP_R16_IMM8));
        // The remaining 16-bit ALU immediate siblings.
        assert_eq!(mapped(&[0x66, 0x81, 0xC2, 0x34, 0x12])?, Some(forms::ADD_R16_IMM16));
        assert_eq!(mapped(&[0x66, 0x81, 0xEA, 0x34, 0x12])?, Some(forms::SUB_R16_IMM16));
        assert_eq!(mapped(&[0x66, 0x81, 0xE2, 0x34, 0x12])?, Some(forms::AND_R16_IMM16));
        assert_eq!(mapped(&[0x66, 0x81, 0xCA, 0x34, 0x12])?, Some(forms::OR_R16_IMM16));
        assert_eq!(mapped(&[0x66, 0x81, 0xF2, 0x34, 0x12])?, Some(forms::XOR_R16_IMM16));
        // test $imm16, %dx was already mapped.
        assert_eq!(mapped(&[0x66, 0xF7, 0xC2, 0x34, 0x12])?, Some(forms::TEST_R16_IMM16));
        Ok(())
    }

    #[test]
    fn maps_x87_transcendental_forms() -> Result<(), Box<dyn std::error::Error>> {
        // fsin (D9 FE), fcos (D9 FF), fptan (D9 F2), fpatan (D9 F3)
        assert_eq!(mapped(&[0xD9, 0xFE])?, Some(forms::FSIN));
        assert_eq!(mapped(&[0xD9, 0xFF])?, Some(forms::FCOS));
        assert_eq!(mapped(&[0xD9, 0xF2])?, Some(forms::FPTAN));
        assert_eq!(mapped(&[0xD9, 0xF3])?, Some(forms::FPATAN));
        // f2xm1 (D9 F0), fyl2x (D9 F1), fyl2xp1 (D9 F9), fscale (D9 FD)
        assert_eq!(mapped(&[0xD9, 0xF0])?, Some(forms::F2XM1));
        assert_eq!(mapped(&[0xD9, 0xF1])?, Some(forms::FYL2X));
        assert_eq!(mapped(&[0xD9, 0xF9])?, Some(forms::FYL2XP1));
        assert_eq!(mapped(&[0xD9, 0xFD])?, Some(forms::FSCALE));
        Ok(())
    }

    #[test]
    fn maps_avx_double_precision_forms() -> Result<(), Box<dyn std::error::Error>> {
        // vaddpd %ymm2, %ymm1, %ymm0
        assert_eq!(mapped(&[0xC5, 0xF5, 0x58, 0xC2])?, Some(forms::VADDPD_YMM_YMM_YMM));
        // vaddsd %xmm2, %xmm1, %xmm0
        assert_eq!(mapped(&[0xC5, 0xF3, 0x58, 0xC2])?, Some(forms::VADDSD_XMM_XMM_XMM));
        // vmulpd %ymm2, %ymm1, %ymm0
        assert_eq!(mapped(&[0xC5, 0xF5, 0x59, 0xC2])?, Some(forms::VMULPD_YMM_YMM_YMM));
        // vmulsd %xmm2, %xmm1, %xmm0
        assert_eq!(mapped(&[0xC5, 0xF3, 0x59, 0xC2])?, Some(forms::VMULSD_XMM_XMM_XMM));
        // vandpd %ymm2, %ymm1, %ymm0
        assert_eq!(mapped(&[0xC5, 0xF5, 0x54, 0xC2])?, Some(forms::VANDPD_YMM_YMM_YMM));
        // vxorpd %ymm2, %ymm1, %ymm0
        assert_eq!(mapped(&[0xC5, 0xF5, 0x57, 0xC2])?, Some(forms::VXORPD_YMM_YMM_YMM));
        Ok(())
    }

    #[test]
    fn maps_avx_blend_cvt_perm_forms() -> Result<(), Box<dyn std::error::Error>> {
        // vcvtss2sd %xmm2, %xmm2, %xmm0
        assert_eq!(mapped(&[0xC5, 0xEA, 0x5A, 0xC2])?, Some(forms::VCVTSS2SD_XMM_XMM_XMM));
        // vcvtsd2ss %xmm2, %xmm2, %xmm0
        assert_eq!(mapped(&[0xC5, 0xEB, 0x5A, 0xC2])?, Some(forms::VCVTSD2SS_XMM_XMM_XMM));
        // vblendps $0x03, %ymm2, %ymm1, %ymm0
        assert_eq!(
            mapped(&[0xC4, 0xE3, 0x75, 0x0C, 0xC2, 0x03])?,
            Some(forms::VBLENDPS_YMM_YMM_YMM_IMM8)
        );
        // vblendpd $0x03, %ymm2, %ymm1, %ymm0
        assert_eq!(
            mapped(&[0xC4, 0xE3, 0x75, 0x0D, 0xC2, 0x03])?,
            Some(forms::VBLENDPD_YMM_YMM_YMM_IMM8)
        );
        // vperm2f128 $0x03, %ymm2, %ymm1, %ymm0
        assert_eq!(
            mapped(&[0xC4, 0xE3, 0x75, 0x06, 0xC2, 0x03])?,
            Some(forms::VPERM2F128_YMM_YMM_YMM_IMM8)
        );
        // vpermilps $0x1b, %ymm1, %ymm0
        assert_eq!(
            mapped(&[0xC4, 0xE3, 0x7D, 0x04, 0xC1, 0x1B])?,
            Some(forms::VPERMILPS_YMM_YMM_IMM8)
        );
        // vpermilpd $0x05, %ymm1, %ymm0
        assert_eq!(
            mapped(&[0xC4, 0xE3, 0x7D, 0x05, 0xC1, 0x05])?,
            Some(forms::VPERMILPD_YMM_YMM_IMM8)
        );
        Ok(())
    }

    #[test]
    fn maps_avx_shuf_unpck_forms() -> Result<(), Box<dyn std::error::Error>> {
        // vshufps $0x1b, %ymm2, %ymm1, %ymm0
        assert_eq!(
            mapped(&[0xC5, 0xF4, 0xC6, 0xC2, 0x1B])?,
            Some(forms::VSHUFPS_YMM_YMM_YMM_IMM8)
        );
        // vshufpd $0x03, %ymm2, %ymm1, %ymm0
        assert_eq!(
            mapped(&[0xC5, 0xF5, 0xC6, 0xC2, 0x03])?,
            Some(forms::VSHUFPD_YMM_YMM_YMM_IMM8)
        );
        // vunpcklps %ymm2, %ymm1, %ymm0
        assert_eq!(mapped(&[0xC5, 0xF4, 0x14, 0xC2])?, Some(forms::VUNPCKLPS_YMM_YMM_YMM));
        // vunpckhps %ymm2, %ymm1, %ymm0
        assert_eq!(mapped(&[0xC5, 0xF4, 0x15, 0xC2])?, Some(forms::VUNPCKHPS_YMM_YMM_YMM));
        // vunpcklpd %ymm2, %ymm1, %ymm0
        assert_eq!(mapped(&[0xC5, 0xF5, 0x14, 0xC2])?, Some(forms::VUNPCKLPD_YMM_YMM_YMM));
        // vunpckhpd %ymm2, %ymm1, %ymm0
        assert_eq!(mapped(&[0xC5, 0xF5, 0x15, 0xC2])?, Some(forms::VUNPCKHPD_YMM_YMM_YMM));
        Ok(())
    }

    #[test]
    fn maps_avx_minmax_sqrt_forms() -> Result<(), Box<dyn std::error::Error>> {
        // vminps %ymm2, %ymm1, %ymm0
        assert_eq!(mapped(&[0xC5, 0xF4, 0x5D, 0xC2])?, Some(forms::VMINPS_YMM_YMM_YMM));
        // vmaxps %ymm2, %ymm1, %ymm0
        assert_eq!(mapped(&[0xC5, 0xF4, 0x5F, 0xC2])?, Some(forms::VMAXPS_YMM_YMM_YMM));
        // vminpd %ymm2, %ymm1, %ymm0
        assert_eq!(mapped(&[0xC5, 0xF5, 0x5D, 0xC2])?, Some(forms::VMINPD_YMM_YMM_YMM));
        // vmaxpd %ymm2, %ymm1, %ymm0
        assert_eq!(mapped(&[0xC5, 0xF5, 0x5F, 0xC2])?, Some(forms::VMAXPD_YMM_YMM_YMM));
        // vminss %xmm2, %xmm1, %xmm0
        assert_eq!(mapped(&[0xC5, 0xF2, 0x5D, 0xC2])?, Some(forms::VMINSS_XMM_XMM_XMM));
        // vmaxss %xmm2, %xmm1, %xmm0
        assert_eq!(mapped(&[0xC5, 0xF2, 0x5F, 0xC2])?, Some(forms::VMAXSS_XMM_XMM_XMM));
        // vminsd %xmm2, %xmm1, %xmm0
        assert_eq!(mapped(&[0xC5, 0xF3, 0x5D, 0xC2])?, Some(forms::VMINSD_XMM_XMM_XMM));
        // vmaxsd %xmm2, %xmm1, %xmm0
        assert_eq!(mapped(&[0xC5, 0xF3, 0x5F, 0xC2])?, Some(forms::VMAXSD_XMM_XMM_XMM));
        // vsqrtps %ymm2, %ymm0
        assert_eq!(mapped(&[0xC5, 0xFC, 0x51, 0xC2])?, Some(forms::VSQRTPS_YMM_YMM));
        // vsqrtpd %ymm2, %ymm0
        assert_eq!(mapped(&[0xC5, 0xFD, 0x51, 0xC2])?, Some(forms::VSQRTPD_YMM_YMM));
        // vsqrtss %xmm2, %xmm1, %xmm0
        assert_eq!(mapped(&[0xC5, 0xF2, 0x51, 0xC2])?, Some(forms::VSQRTSS_XMM_XMM_XMM));
        // vsqrtsd %xmm2, %xmm1, %xmm0
        assert_eq!(mapped(&[0xC5, 0xF3, 0x51, 0xC2])?, Some(forms::VSQRTSD_XMM_XMM_XMM));
        Ok(())
    }

    #[test]
    fn maps_avx2_varshift_perm_forms() -> Result<(), Box<dyn std::error::Error>> {
        // vpsllvd %ymm1, %ymm0, %ymm0
        assert_eq!(
            mapped(&[0xC4, 0xE2, 0x7D, 0x47, 0xC1])?,
            Some(forms::VPSLLVD_YMM_YMM_YMM)
        );
        // vpsllvq %ymm1, %ymm0, %ymm0
        assert_eq!(
            mapped(&[0xC4, 0xE2, 0xFD, 0x47, 0xC1])?,
            Some(forms::VPSLLVQ_YMM_YMM_YMM)
        );
        // vpsravd %ymm1, %ymm0, %ymm0
        assert_eq!(
            mapped(&[0xC4, 0xE2, 0x7D, 0x46, 0xC1])?,
            Some(forms::VPSRAVD_YMM_YMM_YMM)
        );
        // vpsrlvd %ymm1, %ymm0, %ymm0
        assert_eq!(
            mapped(&[0xC4, 0xE2, 0x7D, 0x45, 0xC1])?,
            Some(forms::VPSRLVD_YMM_YMM_YMM)
        );
        // vpsrlvq %ymm1, %ymm0, %ymm0
        assert_eq!(
            mapped(&[0xC4, 0xE2, 0xFD, 0x45, 0xC1])?,
            Some(forms::VPSRLVQ_YMM_YMM_YMM)
        );
        // vpsllvd %xmm1, %xmm0, %xmm0
        assert_eq!(
            mapped(&[0xC4, 0xE2, 0x79, 0x47, 0xC1])?,
            Some(forms::VPSLLVD_XMM_XMM_XMM)
        );
        // vpermd %ymm1, %ymm0, %ymm0
        assert_eq!(
            mapped(&[0xC4, 0xE2, 0x7D, 0x36, 0xC1])?,
            Some(forms::VPERMD_YMM_YMM_YMM)
        );
        // vpermps %ymm1, %ymm0, %ymm0
        assert_eq!(
            mapped(&[0xC4, 0xE2, 0x7D, 0x16, 0xC1])?,
            Some(forms::VPERMPS_YMM_YMM_YMM)
        );
        // vpermq $0x1b, %ymm0, %ymm0
        assert_eq!(
            mapped(&[0xC4, 0xE3, 0xFD, 0x00, 0xC0, 0x1B])?,
            Some(forms::VPERMQ_YMM_YMM_IMM8)
        );
        // vpermpd $0x1b, %ymm0, %ymm0
        assert_eq!(
            mapped(&[0xC4, 0xE3, 0xFD, 0x01, 0xC0, 0x1B])?,
            Some(forms::VPERMPD_YMM_YMM_IMM8)
        );
        // vperm2i128 $0x1, %ymm1, %ymm0, %ymm0
        assert_eq!(
            mapped(&[0xC4, 0xE3, 0x7D, 0x46, 0xC1, 0x01])?,
            Some(forms::VPERM2I128_YMM_YMM_YMM_IMM8)
        );
        Ok(())
    }

    #[test]
    fn maps_avx512_evex_forms() -> Result<(), Box<dyn std::error::Error>> {
        // EVEX decodes report the implicit opmask (k0) as an operand, so the
        // mapped shapes are [Zmm, Reg64, Zmm, Zmm] / [Zmm, Reg64, Zmm, Mem].
        // vaddps %zmm2, %zmm1, %zmm0
        assert_eq!(
            mapped(&[0x62, 0xF1, 0x74, 0x48, 0x58, 0xC2])?,
            Some(forms::VADDPS_ZMM_ZMM_ZMM)
        );
        // vaddps (%rax), %zmm1, %zmm0
        assert_eq!(
            mapped(&[0x62, 0xF1, 0x74, 0x48, 0x58, 0x00])?,
            Some(forms::VADDPS_ZMM_ZMM_MEM)
        );
        // vaddpd %zmm2, %zmm1, %zmm0
        assert_eq!(
            mapped(&[0x62, 0xF1, 0xF5, 0x48, 0x58, 0xC2])?,
            Some(forms::VADDPD_ZMM_ZMM_ZMM)
        );
        // vmulpd %zmm2, %zmm1, %zmm0
        assert_eq!(
            mapped(&[0x62, 0xF1, 0xF5, 0x48, 0x59, 0xC2])?,
            Some(forms::VMULPD_ZMM_ZMM_ZMM)
        );
        // vxorps %zmm2, %zmm1, %zmm0
        assert_eq!(
            mapped(&[0x62, 0xF1, 0x74, 0x48, 0x57, 0xC2])?,
            Some(forms::VXORPS_ZMM_ZMM_ZMM)
        );
        // vandpd %zmm2, %zmm1, %zmm0
        assert_eq!(
            mapped(&[0x62, 0xF1, 0xF5, 0x48, 0x54, 0xC2])?,
            Some(forms::VANDPD_ZMM_ZMM_ZMM)
        );
        Ok(())
    }

    #[test]
    fn maps_avx2_saturating_abs_pack_forms() -> Result<(), Box<dyn std::error::Error>> {
        // vpaddusb %ymm2, %ymm1, %ymm0
        assert_eq!(mapped(&[0xC5, 0xF5, 0xDC, 0xC2])?, Some(forms::VPADDUSB_YMM_YMM_YMM));
        // vpmulld %ymm2, %ymm1, %ymm0
        assert_eq!(
            mapped(&[0xC4, 0xE2, 0x75, 0x40, 0xC2])?,
            Some(forms::VPMULLD_YMM_YMM_YMM)
        );
        // vpabsb %ymm1, %ymm0
        assert_eq!(mapped(&[0xC4, 0xE2, 0x7D, 0x1C, 0xC1])?, Some(forms::VPABSB_YMM_YMM));
        // vpblendd $0x3, %ymm2, %ymm1, %ymm0
        assert_eq!(
            mapped(&[0xC4, 0xE3, 0x75, 0x02, 0xC2, 0x03])?,
            Some(forms::VPBLENDD_YMM_YMM_YMM_IMM8)
        );
        // vpcmpeqd (%rax), %ymm1, %ymm0
        assert_eq!(mapped(&[0xC5, 0xF5, 0x76, 0x00])?, Some(forms::VPCMPEQD_YMM_YMM_MEM256));
        Ok(())
    }

    #[test]
    fn maps_avx512_scalar_and_opmask_forms() -> Result<(), Box<dyn std::error::Error>> {
        // EVEX scalar forms report the opmask as a Reg64 operand:
        // [Xmm, Reg64(k), Xmm, Xmm] and [Xmm, Reg64(k), Xmm, Mem].
        // vaddsd %xmm2, %xmm1, %xmm0
        assert_eq!(
            mapped(&[0x62, 0xF1, 0xF7, 0x08, 0x58, 0xC2])?,
            Some(evex_forms::VADDSD_EVEX_XMM_XMM_XMM)
        );
        // vaddss %xmm2, %xmm1, %xmm0
        assert_eq!(
            mapped(&[0x62, 0xF1, 0x76, 0x08, 0x58, 0xC2])?,
            Some(evex_forms::VADDSS_EVEX_XMM_XMM_XMM)
        );
        // vsubsd %xmm2, %xmm1, %xmm0
        assert_eq!(
            mapped(&[0x62, 0xF1, 0xF7, 0x08, 0x5C, 0xC2])?,
            Some(evex_forms::VSUBSD_EVEX_XMM_XMM_XMM)
        );
        // vsubss %xmm2, %xmm1, %xmm0
        assert_eq!(
            mapped(&[0x62, 0xF1, 0x76, 0x08, 0x5C, 0xC2])?,
            Some(evex_forms::VSUBSS_EVEX_XMM_XMM_XMM)
        );
        // vmulsd %xmm2, %xmm1, %xmm0
        assert_eq!(
            mapped(&[0x62, 0xF1, 0xF7, 0x08, 0x59, 0xC2])?,
            Some(evex_forms::VMULSD_EVEX_XMM_XMM_XMM)
        );
        // vmulss %xmm2, %xmm1, %xmm0
        assert_eq!(
            mapped(&[0x62, 0xF1, 0x76, 0x08, 0x59, 0xC2])?,
            Some(evex_forms::VMULSS_EVEX_XMM_XMM_XMM)
        );
        // vdivsd %xmm2, %xmm1, %xmm0
        assert_eq!(
            mapped(&[0x62, 0xF1, 0xF7, 0x08, 0x5E, 0xC2])?,
            Some(evex_forms::VDIVSD_EVEX_XMM_XMM_XMM)
        );
        // vdivss %xmm2, %xmm1, %xmm0
        assert_eq!(
            mapped(&[0x62, 0xF1, 0x76, 0x08, 0x5E, 0xC2])?,
            Some(evex_forms::VDIVSS_EVEX_XMM_XMM_XMM)
        );
        // Opmask word forms (VEX 0F 4x): KANDW %k2, %k3, %k4
        assert_eq!(mapped(&[0xC5, 0xE4, 0x41, 0xE2])?, Some(evex_forms::KANDW_K_K_K));
        // KANDNW %k2, %k3, %k4
        assert_eq!(mapped(&[0xC5, 0xE4, 0x42, 0xE2])?, Some(evex_forms::KANDNW_K_K_K));
        // KORW %k2, %k3, %k4
        assert_eq!(mapped(&[0xC5, 0xE4, 0x45, 0xE2])?, Some(evex_forms::KORW_K_K_K));
        // KXORW %k2, %k3, %k4
        assert_eq!(mapped(&[0xC5, 0xE4, 0x47, 0xE2])?, Some(evex_forms::KXORW_K_K_K));
        // KXNORW %k2, %k3, %k4
        assert_eq!(mapped(&[0xC5, 0xE4, 0x46, 0xE2])?, Some(evex_forms::KXNORW_K_K_K));
        // KNOTW %k2, %k4 (two-operand form)
        assert_eq!(mapped(&[0xC5, 0xF8, 0x44, 0xE2])?, Some(evex_forms::KNOTW_K_K));
        // Opmask qword forms (VEX3 W=1): KANDQ %k2, %k3, %k4
        assert_eq!(mapped(&[0xC4, 0xE1, 0xE4, 0x41, 0xE2])?, Some(evex_forms::KANDQ_K_K_K));
        // KORQ %k2, %k3, %k4
        assert_eq!(mapped(&[0xC4, 0xE1, 0xE4, 0x45, 0xE2])?, Some(evex_forms::KORQ_K_K_K));
        // KNOTQ %k2, %k4 (two-operand form)
        assert_eq!(mapped(&[0xC4, 0xE1, 0xF8, 0x44, 0xE2])?, Some(evex_forms::KNOTQ_K_K));
        Ok(())
    }

    #[test]
    fn maps_vnni_forms() -> Result<(), Box<dyn std::error::Error>> {
        // All VNNI encodings are EVEX and report [dst, opmask, src1, src2].
        // vpdpbusd %ymm2, %ymm1, %ymm0
        assert_eq!(
            mapped(&[0x62, 0xF2, 0x75, 0x28, 0x50, 0xC2])?,
            Some(evex_forms::VPDPBUSD_YMM_YMM_YMM)
        );
        // vpdpbusd (%rax), %ymm1, %ymm0
        assert_eq!(
            mapped(&[0x62, 0xF2, 0x75, 0x28, 0x50, 0x00])?,
            Some(evex_forms::VPDPBUSD_YMM_YMM_MEM)
        );
        // vpdpbusd %xmm2, %xmm1, %xmm0
        assert_eq!(
            mapped(&[0x62, 0xF2, 0x75, 0x08, 0x50, 0xC2])?,
            Some(evex_forms::VPDPBUSD_XMM_XMM_XMM)
        );
        // vpdpbusd %zmm2, %zmm1, %zmm0{%k1}
        assert_eq!(
            mapped(&[0x62, 0xF2, 0x75, 0x49, 0x50, 0xC2])?,
            Some(evex_forms::VPDPBUSD_ZMM_ZMM_ZMM)
        );
        // vpdpbusds %ymm2, %ymm1, %ymm0
        assert_eq!(
            mapped(&[0x62, 0xF2, 0x75, 0x28, 0x51, 0xC2])?,
            Some(evex_forms::VPDPBUSDS_YMM_YMM_YMM)
        );
        // vpdpwssd %ymm2, %ymm1, %ymm0
        assert_eq!(
            mapped(&[0x62, 0xF2, 0x75, 0x28, 0x52, 0xC2])?,
            Some(evex_forms::VPDPWSSD_YMM_YMM_YMM)
        );
        // vpdpwssds %ymm2, %ymm1, %ymm0
        assert_eq!(
            mapped(&[0x62, 0xF2, 0x75, 0x28, 0x53, 0xC2])?,
            Some(evex_forms::VPDPWSSDS_YMM_YMM_YMM)
        );
        // VNNI-INT8 forms (VEX-encoded: [dst, src1, src2])
        // vpdpbssd %xmm2, %xmm1, %xmm0
        assert_eq!(
            mapped(&[0xC4, 0xE2, 0x73, 0x50, 0xC2])?,
            Some(evex_forms::VPDPBSSD_XMM_XMM_XMM)
        );
        // vpdpbssd (%rax), %xmm1, %xmm0
        assert_eq!(
            mapped(&[0xC4, 0xE2, 0x73, 0x50, 0x00])?,
            Some(evex_forms::VPDPBSSD_XMM_XMM_MEM128)
        );
        // vpdpbssd %ymm2, %ymm1, %ymm0
        assert_eq!(
            mapped(&[0xC4, 0xE2, 0x77, 0x50, 0xC2])?,
            Some(evex_forms::VPDPBSSD_YMM_YMM_YMM)
        );
        // vpdpbssd (%rax), %ymm1, %ymm0
        assert_eq!(
            mapped(&[0xC4, 0xE2, 0x77, 0x50, 0x00])?,
            Some(evex_forms::VPDPBSSD_YMM_YMM_MEM)
        );
        // vpdpbssds %ymm2, %ymm1, %ymm0
        assert_eq!(
            mapped(&[0xC4, 0xE2, 0x77, 0x51, 0xC2])?,
            Some(evex_forms::VPDPBSSDS_YMM_YMM_YMM)
        );
        // vpdpbsud %ymm2, %ymm1, %ymm0
        assert_eq!(
            mapped(&[0xC4, 0xE2, 0x76, 0x50, 0xC2])?,
            Some(evex_forms::VPDPBSUD_YMM_YMM_YMM)
        );
        // vpdpbsuds %ymm2, %ymm1, %ymm0
        assert_eq!(
            mapped(&[0xC4, 0xE2, 0x76, 0x51, 0xC2])?,
            Some(evex_forms::VPDPBSUDS_YMM_YMM_YMM)
        );
        Ok(())
    }

    #[test]
    fn maps_decode_wiring_slice_avx2_and_legacy_forms() -> Result<(), Box<dyn std::error::Error>> {
        // AVX2 VEX integer band (0x0A00). All encodings assembled and
        // disassembled with GNU as/objdump before pinning; see the
        // decode-wiring slice in docs/ROADMAP.md.
        // vpaddb/vpaddw/vpaddd/vpaddq %ymm2, %ymm1, %ymm0
        assert_eq!(mapped(&[0xC5, 0xF5, 0xFC, 0xC2])?, Some(forms::VPADDB_YMM_YMM_YMM));
        assert_eq!(mapped(&[0xC5, 0xF5, 0xFD, 0xC2])?, Some(forms::VPADDW_YMM_YMM_YMM));
        assert_eq!(mapped(&[0xC5, 0xF5, 0xFE, 0xC2])?, Some(forms::VPADDD_YMM_YMM_YMM));
        assert_eq!(mapped(&[0xC5, 0xF5, 0xD4, 0xC2])?, Some(forms::VPADDQ_YMM_YMM_YMM));
        // vpsubb/vpsubw/vpsubd/vpsubq
        assert_eq!(mapped(&[0xC5, 0xF5, 0xF8, 0xC2])?, Some(forms::VPSUBB_YMM_YMM_YMM));
        assert_eq!(mapped(&[0xC5, 0xF5, 0xF9, 0xC2])?, Some(forms::VPSUBW_YMM_YMM_YMM));
        assert_eq!(mapped(&[0xC5, 0xF5, 0xFA, 0xC2])?, Some(forms::VPSUBD_YMM_YMM_YMM));
        assert_eq!(mapped(&[0xC5, 0xF5, 0xFB, 0xC2])?, Some(forms::VPSUBQ_YMM_YMM_YMM));
        // vpmullw/vpmulhw/vpmaddwd
        assert_eq!(mapped(&[0xC5, 0xF5, 0xD5, 0xC2])?, Some(forms::VPMULLW_YMM_YMM_YMM));
        assert_eq!(mapped(&[0xC5, 0xF5, 0xE5, 0xC2])?, Some(forms::VPMULHW_YMM_YMM_YMM));
        assert_eq!(mapped(&[0xC5, 0xF5, 0xF5, 0xC2])?, Some(forms::VPMADDWD_YMM_YMM_YMM));
        // vpsllw $7, %ymm1, %ymm0 and count-register forms
        assert_eq!(mapped(&[0xC5, 0xFD, 0x71, 0xF1, 0x07])?, Some(forms::VPSLLW_YMM_YMM_IMM8));
        assert_eq!(mapped(&[0xC5, 0xFD, 0x72, 0xF1, 0x07])?, Some(forms::VPSLLD_YMM_YMM_IMM8));
        assert_eq!(mapped(&[0xC5, 0xFD, 0x73, 0xF1, 0x07])?, Some(forms::VPSLLQ_YMM_YMM_IMM8));
        assert_eq!(mapped(&[0xC5, 0xFD, 0x71, 0xD1, 0x07])?, Some(forms::VPSRLW_YMM_YMM_IMM8));
        assert_eq!(mapped(&[0xC5, 0xFD, 0x72, 0xD1, 0x07])?, Some(forms::VPSRLD_YMM_YMM_IMM8));
        assert_eq!(mapped(&[0xC5, 0xFD, 0x73, 0xD1, 0x07])?, Some(forms::VPSRLQ_YMM_YMM_IMM8));
        assert_eq!(mapped(&[0xC5, 0xFD, 0x71, 0xE1, 0x07])?, Some(forms::VPSRAW_YMM_YMM_IMM8));
        assert_eq!(mapped(&[0xC5, 0xFD, 0x72, 0xE1, 0x07])?, Some(forms::VPSRAD_YMM_YMM_IMM8));
        assert_eq!(mapped(&[0xC5, 0xF5, 0xF1, 0xC2])?, Some(forms::VPSLLW_YMM_YMM_XMM));
        assert_eq!(mapped(&[0xC5, 0xF5, 0xF2, 0xC2])?, Some(forms::VPSLLD_YMM_YMM_XMM));
        assert_eq!(mapped(&[0xC5, 0xF5, 0xF3, 0xC2])?, Some(forms::VPSLLQ_YMM_YMM_XMM));
        assert_eq!(mapped(&[0xC5, 0xF5, 0xD1, 0xC2])?, Some(forms::VPSRLW_YMM_YMM_XMM));
        assert_eq!(mapped(&[0xC5, 0xF5, 0xD2, 0xC2])?, Some(forms::VPSRLD_YMM_YMM_XMM));
        assert_eq!(mapped(&[0xC5, 0xF5, 0xD3, 0xC2])?, Some(forms::VPSRLQ_YMM_YMM_XMM));
        assert_eq!(mapped(&[0xC5, 0xF5, 0xE1, 0xC2])?, Some(forms::VPSRAW_YMM_YMM_XMM));
        assert_eq!(mapped(&[0xC5, 0xF5, 0xE2, 0xC2])?, Some(forms::VPSRAD_YMM_YMM_XMM));
        // vpshufd $0x1b, %ymm1, %ymm0 / vpshufb %ymm2, %ymm1, %ymm0
        assert_eq!(mapped(&[0xC5, 0xFD, 0x70, 0xC1, 0x1B])?, Some(forms::VPSHUFD_YMM_YMM_IMM8));
        assert_eq!(mapped(&[0xC4, 0xE2, 0x75, 0x00, 0xC2])?, Some(forms::VPSHUFB_YMM_YMM_YMM));
        // vpunpckl/h families
        assert_eq!(mapped(&[0xC5, 0xF5, 0x60, 0xC2])?, Some(forms::VPUNPCKLBW_YMM_YMM_YMM));
        assert_eq!(mapped(&[0xC5, 0xF5, 0x61, 0xC2])?, Some(forms::VPUNPCKLWD_YMM_YMM_YMM));
        assert_eq!(mapped(&[0xC5, 0xF5, 0x62, 0xC2])?, Some(forms::VPUNPCKLDQ_YMM_YMM_YMM));
        assert_eq!(mapped(&[0xC5, 0xF5, 0x6C, 0xC2])?, Some(forms::VPUNPCKLQDQ_YMM_YMM_YMM));
        assert_eq!(mapped(&[0xC5, 0xF5, 0x68, 0xC2])?, Some(forms::VPUNPCKHBW_YMM_YMM_YMM));
        assert_eq!(mapped(&[0xC5, 0xF5, 0x69, 0xC2])?, Some(forms::VPUNPCKHWD_YMM_YMM_YMM));
        assert_eq!(mapped(&[0xC5, 0xF5, 0x6A, 0xC2])?, Some(forms::VPUNPCKHDQ_YMM_YMM_YMM));
        assert_eq!(mapped(&[0xC5, 0xF5, 0x6D, 0xC2])?, Some(forms::VPUNPCKHQDQ_YMM_YMM_YMM));
        // vpmin/vpmax families (imm8-free)
        assert_eq!(mapped(&[0xC5, 0xF5, 0xDA, 0xC2])?, Some(forms::VPMINUB_YMM_YMM_YMM));
        assert_eq!(mapped(&[0xC4, 0xE2, 0x75, 0x38, 0xC2])?, Some(forms::VPMINSB_YMM_YMM_YMM));
        assert_eq!(mapped(&[0xC4, 0xE2, 0x75, 0x3A, 0xC2])?, Some(forms::VPMINUW_YMM_YMM_YMM));
        assert_eq!(mapped(&[0xC5, 0xF5, 0xEA, 0xC2])?, Some(forms::VPMINSW_YMM_YMM_YMM));
        assert_eq!(mapped(&[0xC4, 0xE2, 0x75, 0x3B, 0xC2])?, Some(forms::VPMINUD_YMM_YMM_YMM));
        assert_eq!(mapped(&[0xC4, 0xE2, 0x75, 0x39, 0xC2])?, Some(forms::VPMINSD_YMM_YMM_YMM));
        assert_eq!(mapped(&[0xC5, 0xF5, 0xDE, 0xC2])?, Some(forms::VPMAXUB_YMM_YMM_YMM));
        assert_eq!(mapped(&[0xC4, 0xE2, 0x75, 0x3C, 0xC2])?, Some(forms::VPMAXSB_YMM_YMM_YMM));
        assert_eq!(mapped(&[0xC4, 0xE2, 0x75, 0x3E, 0xC2])?, Some(forms::VPMAXUW_YMM_YMM_YMM));
        assert_eq!(mapped(&[0xC5, 0xF5, 0xEE, 0xC2])?, Some(forms::VPMAXSW_YMM_YMM_YMM));
        assert_eq!(mapped(&[0xC4, 0xE2, 0x75, 0x3F, 0xC2])?, Some(forms::VPMAXUD_YMM_YMM_YMM));
        assert_eq!(mapped(&[0xC4, 0xE2, 0x75, 0x3D, 0xC2])?, Some(forms::VPMAXSD_YMM_YMM_YMM));
        // vpbroadcastw/vpbroadcastd %xmm1, %ymm0
        assert_eq!(mapped(&[0xC4, 0xE2, 0x7D, 0x79, 0xC1])?, Some(forms::VPBROADCASTW_YMM_XMM));
        assert_eq!(mapped(&[0xC4, 0xE2, 0x7D, 0x58, 0xC1])?, Some(forms::VPBROADCASTD_YMM_XMM));
        // The VEX GPR-source broadcast decodes as an XMM source operand;
        // it must map to the wired XMM-source form, not the EVEX-only R32 form.
        assert_eq!(mapped(&[0xC4, 0xE2, 0x7D, 0x78, 0xC0])?, Some(forms::VPBROADCASTB_YMM_XMM));

        // Legacy SSE packed float.
        assert_eq!(mapped(&[0x0F, 0x58, 0xC1])?, Some(forms::ADDPS_XMM_XMM));
        assert_eq!(mapped(&[0x0F, 0x5C, 0xC1])?, Some(forms::SUBPS_XMM_XMM));
        assert_eq!(mapped(&[0x0F, 0x59, 0xC1])?, Some(forms::MULPS_XMM_XMM));
        assert_eq!(mapped(&[0x0F, 0x5E, 0xC1])?, Some(forms::DIVPS_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0x58, 0xC1])?, Some(forms::ADDPD_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0x5C, 0xC1])?, Some(forms::SUBPD_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0x59, 0xC1])?, Some(forms::MULPD_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0x5E, 0xC1])?, Some(forms::DIVPD_XMM_XMM));
        assert_eq!(mapped(&[0x0F, 0x5D, 0xC1])?, Some(forms::MINPS_XMM_XMM));
        assert_eq!(mapped(&[0x0F, 0x5F, 0xC1])?, Some(forms::MAXPS_XMM_XMM));
        assert_eq!(mapped(&[0xF2, 0x0F, 0x7C, 0xC1])?, Some(forms::HADDPS_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0x7C, 0xC1])?, Some(forms::HADDPD_XMM_XMM));
        assert_eq!(mapped(&[0xF2, 0x0F, 0x7D, 0xC1])?, Some(forms::HSUBPS_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0x7D, 0xC1])?, Some(forms::HSUBPD_XMM_XMM));
        assert_eq!(mapped(&[0x0F, 0xC2, 0xC1, 0x01])?, Some(forms::CMPPS_XMM_XMM_IMM8));
        assert_eq!(mapped(&[0x66, 0x0F, 0xC2, 0xC1, 0x01])?, Some(forms::CMPPD_XMM_XMM_IMM8));
        assert_eq!(mapped(&[0x66, 0x0F, 0x28, 0xC1])?, Some(forms::MOVAPD_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0x10, 0xC1])?, Some(forms::MOVUPD_XMM_XMM));

        // Legacy SSE integer remainder band.
        assert_eq!(mapped(&[0x66, 0x0F, 0xF8, 0xC1])?, Some(forms::PSUBB_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0xF9, 0xC1])?, Some(forms::PSUBW_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0x38, 0x40, 0xC1])?, Some(forms::PMULLD_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0x71, 0xF0, 0x07])?, Some(forms::PSLLW_XMM_IMM8));
        assert_eq!(mapped(&[0x66, 0x0F, 0x71, 0xD0, 0x07])?, Some(forms::PSRLW_XMM_IMM8));
        assert_eq!(mapped(&[0x66, 0x0F, 0x71, 0xE0, 0x07])?, Some(forms::PSRAW_XMM_IMM8));
        assert_eq!(mapped(&[0x66, 0x0F, 0x72, 0xE0, 0x07])?, Some(forms::PSRAD_XMM_IMM8));
        assert_eq!(mapped(&[0x66, 0x0F, 0x73, 0xF0, 0x07])?, Some(forms::PSLLQ_XMM_IMM8));
        assert_eq!(mapped(&[0x66, 0x0F, 0x73, 0xD0, 0x07])?, Some(forms::PSRLQ_XMM_IMM8));
        assert_eq!(mapped(&[0x66, 0x0F, 0xF1, 0xC2])?, Some(forms::PSLLW_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0xF3, 0xC2])?, Some(forms::PSLLQ_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0xD1, 0xC2])?, Some(forms::PSRLW_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0xD3, 0xC2])?, Some(forms::PSRLQ_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0xE1, 0xC2])?, Some(forms::PSRAW_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0xE2, 0xC2])?, Some(forms::PSRAD_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0x73, 0xF8, 0x03])?, Some(forms::PSLLDQ_XMM_IMM8));
        assert_eq!(mapped(&[0x66, 0x0F, 0x73, 0xD8, 0x03])?, Some(forms::PSRLDQ_XMM_IMM8));
        assert_eq!(mapped(&[0x66, 0x0F, 0x38, 0x3C, 0xC1])?, Some(forms::PMAXSB_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0xEE, 0xC1])?, Some(forms::PMAXSW_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0x38, 0x3E, 0xC1])?, Some(forms::PMAXUW_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0xEA, 0xC1])?, Some(forms::PMINSW_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0x38, 0x3A, 0xC1])?, Some(forms::PMINUW_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0xE5, 0xC1])?, Some(forms::PMULHW_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0xE4, 0xC1])?, Some(forms::PMULHUW_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0x6B, 0xC1])?, Some(forms::PACKSSDW_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0x38, 0x2B, 0xC1])?, Some(forms::PACKUSDW_XMM_XMM));
        assert_eq!(mapped(&[0xF3, 0x0F, 0x70, 0xC1, 0x1B])?, Some(forms::PSHUFHW_XMM_IMM8));
        assert_eq!(mapped(&[0xF2, 0x0F, 0x70, 0xC1, 0x1B])?, Some(forms::PSHUFLW_XMM_IMM8));
        assert_eq!(mapped(&[0x66, 0x0F, 0x38, 0x04, 0xC1])?, Some(forms::PMADDUBSW_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0x38, 0x02, 0xC1])?, Some(forms::PHADDD_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0x38, 0x05, 0xC1])?, Some(forms::PHSUBW_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0x38, 0x06, 0xC1])?, Some(forms::PHSUBD_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0x38, 0x03, 0xC1])?, Some(forms::PHADDSW_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0x38, 0x07, 0xC1])?, Some(forms::PHSUBSW_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0x38, 0x1D, 0xC1])?, Some(forms::PABSW_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0x38, 0x09, 0xC1])?, Some(forms::PSIGNW_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0x38, 0x0A, 0xC1])?, Some(forms::PSIGND_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0x38, 0x0B, 0xC1])?, Some(forms::PMULHRSW_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0x38, 0x28, 0xC1])?, Some(forms::PMULDQ_XMM_XMM));
        assert_eq!(mapped(&[0x66, 0x0F, 0x3A, 0x0E, 0xC1, 0x0F])?, Some(forms::PBLENDW_XMM_XMM_IMM8));
        assert_eq!(mapped(&[0x66, 0x0F, 0x3A, 0x0C, 0xC1, 0x0F])?, Some(forms::BLENDPS_XMM_XMM_IMM8));
        assert_eq!(mapped(&[0x66, 0x0F, 0x3A, 0x0D, 0xC1, 0x0F])?, Some(forms::BLENDPD_XMM_XMM_IMM8));
        assert_eq!(mapped(&[0x66, 0x0F, 0x3A, 0x40, 0xC1, 0x0F])?, Some(forms::DPPS_XMM_XMM_IMM8));
        assert_eq!(mapped(&[0x66, 0x0F, 0x3A, 0x41, 0xC1, 0x0F])?, Some(forms::DPPD_XMM_XMM_IMM8));
        assert_eq!(mapped(&[0x66, 0x0F, 0x3A, 0x14, 0xC8, 0x03])?, Some(forms::PEXTRB_R32_XMM_IMM8));
        assert_eq!(mapped(&[0x66, 0x0F, 0x38, 0x41, 0xC1])?, Some(forms::PHMINPOSUW_XMM_XMM));

        // Misc: SETcc-mem, CMPXCHG 16/8-bit, XADD 16/8-bit, CRC32 variants,
        // TEST m64/r64, BSF memory sources, CMOV r32 stragglers.
        assert_eq!(mapped(&[0x0F, 0x94, 0x00])?, Some(forms::SETZ_MEM8));
        assert_eq!(mapped(&[0x0F, 0x95, 0x00])?, Some(forms::SETNZ_MEM8));
        assert_eq!(mapped(&[0x0F, 0x92, 0x00])?, Some(forms::SETB_MEM8));
        assert_eq!(mapped(&[0x0F, 0x93, 0x00])?, Some(forms::SETAE_MEM8));
        assert_eq!(mapped(&[0x0F, 0x96, 0x00])?, Some(forms::SETBE_MEM8));
        assert_eq!(mapped(&[0x0F, 0x97, 0x00])?, Some(forms::SETA_MEM8));
        assert_eq!(mapped(&[0x0F, 0x9C, 0x00])?, Some(forms::SETL_MEM8));
        assert_eq!(mapped(&[0x0F, 0x9D, 0x00])?, Some(forms::SETGE_MEM8));
        assert_eq!(mapped(&[0x0F, 0x9E, 0x00])?, Some(forms::SETLE_MEM8));
        assert_eq!(mapped(&[0x0F, 0x9F, 0x00])?, Some(forms::SETG_MEM8));
        assert_eq!(mapped(&[0x0F, 0x98, 0x00])?, Some(forms::SETS_MEM8));
        assert_eq!(mapped(&[0x0F, 0x99, 0x00])?, Some(forms::SETNS_MEM8));
        assert_eq!(mapped(&[0x66, 0x0F, 0xB1, 0xC0])?, Some(forms::CMPXCHG_R16_R16));
        assert_eq!(mapped(&[0x0F, 0xB0, 0xC0])?, Some(forms::CMPXCHG_R8_R8));
        assert_eq!(mapped(&[0x66, 0x0F, 0xB1, 0x00])?, Some(forms::CMPXCHG_MEM16_R16));
        assert_eq!(mapped(&[0x66, 0x0F, 0xC1, 0xC0])?, Some(forms::XADD_R16_R16));
        assert_eq!(mapped(&[0x0F, 0xC0, 0xC0])?, Some(forms::XADD_R8_R8));
        assert_eq!(mapped(&[0xF2, 0x0F, 0x38, 0xF1, 0x00])?, Some(forms::CRC32_R32_MEM32));
        assert_eq!(mapped(&[0xF2, 0x48, 0x0F, 0x38, 0xF1, 0x00])?, Some(forms::CRC32_R64_MEM64));
        assert_eq!(mapped(&[0xF2, 0x0F, 0x38, 0xF0, 0xC0])?, Some(forms::CRC32_R32_R8));
        assert_eq!(mapped(&[0xF2, 0x0F, 0x38, 0xF0, 0x00])?, Some(forms::CRC32_R32_MEM8));
        assert_eq!(mapped(&[0xF2, 0x48, 0x0F, 0x38, 0xF0, 0xC0])?, Some(forms::CRC32_R64_R8));
        assert_eq!(mapped(&[0xF2, 0x48, 0x0F, 0x38, 0xF0, 0x00])?, Some(forms::CRC32_R64_MEM8));
        assert_eq!(mapped(&[0x48, 0x85, 0x00])?, Some(forms::TEST_MEM64_R64));
        assert_eq!(mapped(&[0x48, 0x0F, 0xBC, 0x00])?, Some(forms::BSF_R64_MEM64));
        assert_eq!(mapped(&[0x0F, 0xBC, 0x00])?, Some(forms::BSF_R32_MEM32));
        assert_eq!(mapped(&[0x0F, 0x4A, 0xC0])?, Some(forms::CMOVP_R32_R32));
        assert_eq!(mapped(&[0x0F, 0x4B, 0xC0])?, Some(forms::CMOVNP_R32_R32));
        assert_eq!(mapped(&[0x0F, 0x40, 0xC0])?, Some(forms::CMOVO_R32_R32));
        assert_eq!(mapped(&[0x0F, 0x41, 0xC0])?, Some(forms::CMOVNO_R32_R32));
        Ok(())
    }
}
