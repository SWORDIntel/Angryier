#![forbid(unsafe_code)]

//! Handwritten Intel 64 semantic corpus (Phase 4).
//!
//! This crate contains a deliberately small but structurally representative
//! set of Intel 64 instruction semantics. The goal is to exercise the rich
//! semantic IR, sealing, lowering, and concrete interpreter contracts before
//! the semantic generator amplifies design mistakes.
//!
//! See `docs/status/implementation-plan.md` Phase 4 for the exit gate.

// The AVX-512 module is compiled both in-crate and (via `#[path]`) into its
// standalone test crate; a stable self-name keeps `angryier_semantics_intel64::`
// paths valid in every context.
extern crate self as angryier_semantics_intel64;

mod amx;
pub mod apx;
mod avx10;
mod avx512;
mod bmi;
pub mod cet;
mod providers;
mod providers_ext;
mod registry;
mod x87;

pub mod declarative;
pub use amx::forms as amx_forms;
pub use avx10::forms as avx10_forms;
pub use avx512::forms as evex_forms;
pub use avx512::*;
pub use bmi::*;
pub use declarative::{DeclarativeProvider, GENERATED_RULE_BASE, generated_providers};
pub use providers::*;
pub use providers_ext::*;
pub use registry::Intel64CorpusRegistry;
pub use x87::*;

use angryier_types::SemanticRuleId;

/// Stable form identifiers for the handwritten corpus.
///
/// These are Angryier-internal IDs. When native XED is integrated, the XED
/// adapter will map XED iform enumerations to these values. Until then,
/// synthetic decode objects use these IDs directly.
pub mod forms {
    // INC/DEC with memory operands (the driver-campaign refcount shapes).
    // LOCK-prefixed and unlocked encodings decode to the same iclass; on a
    // single-vCPU symbolic emulator the LOCK prefix adds no semantic beyond
    // atomicity, so both route to these forms (debt-recorded: multi-core
    // memory-ordering semantics are not modeled).
    pub const INC_MEM8: u32 = 0x10001;
    pub const INC_MEM16: u32 = 0x10002;
    pub const INC_MEM32: u32 = 0x10003;
    pub const INC_MEM64: u32 = 0x10004;
    pub const DEC_MEM8: u32 = 0x10005;
    pub const DEC_MEM16: u32 = 0x10006;
    pub const DEC_MEM32: u32 = 0x10007;
    pub const DEC_MEM64: u32 = 0x10008;

    // Scalar integer arithmetic (two-register, r64 r64)
    pub const MOV_R64_R64: u32 = 0x0001;
    pub const ADD_R64_R64: u32 = 0x0002;
    pub const SUB_R64_R64: u32 = 0x0003;
    pub const XOR_R64_R64: u32 = 0x0004;
    pub const AND_R64_R64: u32 = 0x0005;
    pub const OR_R64_R64: u32 = 0x0006;

    // Shifts (r64, imm8)
    pub const SHL_R64_IMM8: u32 = 0x0007;
    pub const SHR_R64_IMM8: u32 = 0x0008;
    pub const SAR_R64_IMM8: u32 = 0x0009;

    // Comparison (r64, r64, flags only)
    pub const CMP_R64_R64: u32 = 0x000A;

    // Control flow
    pub const JZ_REL32: u32 = 0x000B;
    pub const JNZ_REL32: u32 = 0x000C;
    pub const JMP_REL32: u32 = 0x000D;

    // Immediate operand forms
    pub const MOV_R64_IMM64: u32 = 0x000E;
    pub const ADD_R64_IMM32: u32 = 0x000F;
    pub const SUB_R64_IMM32: u32 = 0x0010;
    pub const CMP_R64_IMM32: u32 = 0x0011;

    // Register shifts (r64, CL)
    pub const SHL_R64_CL: u32 = 0x0012;
    pub const SHR_R64_CL: u32 = 0x0013;
    pub const SAR_R64_CL: u32 = 0x0014;

    // More conditional branches
    pub const JC_REL32: u32 = 0x0015;
    pub const JNC_REL32: u32 = 0x0016;
    pub const JS_REL32: u32 = 0x0017;
    pub const JNS_REL32: u32 = 0x0018;
    pub const JL_REL32: u32 = 0x0019;
    pub const JGE_REL32: u32 = 0x001A;

    // Unary operations
    pub const INC_R64: u32 = 0x001B;
    pub const DEC_R64: u32 = 0x001C;
    pub const NEG_R64: u32 = 0x001D;
    pub const NOT_R64: u32 = 0x001E;

    // NOP
    pub const NOP: u32 = 0x001F;

    // Memory load/store
    pub const MOV_R64_MEM64: u32 = 0x0020;
    pub const MOV_MEM64_R64: u32 = 0x0021;
    pub const ADD_R64_MEM64: u32 = 0x0022;
    pub const CMP_R64_MEM64: u32 = 0x0023;

    // Multiply/divide
    pub const IMUL_R64_R64: u32 = 0x0024;
    pub const MUL_R64_R64: u32 = 0x0025;
    pub const DIV_R64_R64: u32 = 0x0026;
    pub const IDIV_R64_R64: u32 = 0x0027;

    // Rotates
    pub const ROL_R64_IMM8: u32 = 0x0028;
    pub const ROR_R64_IMM8: u32 = 0x0029;
    pub const RCL_R64_IMM8: u32 = 0x002A;
    pub const RCR_R64_IMM8: u32 = 0x002B;

    // Stack push/pop and LEA
    pub const PUSH_R64: u32 = 0x002C;
    pub const POP_R64: u32 = 0x002D;
    pub const LEA_R64_MEM: u32 = 0x002E;

    // Exchange, test, exchange-and-add
    pub const XCHG_R64_R64: u32 = 0x002F;
    pub const TEST_R64_R64: u32 = 0x0030;
    pub const XADD_R64_R64: u32 = 0x0031;

    // Register aliasing / partial writes / zero/sign extension
    pub const MOV_R32_R32: u32 = 0x0032;
    pub const MOV_R8_R8: u32 = 0x0033;
    pub const MOVZX_R64_R32: u32 = 0x0034;
    pub const MOVSX_R64_R32: u32 = 0x0035;
    pub const MOVZX_R64_R8: u32 = 0x0036;
    pub const MOVSX_R64_R8: u32 = 0x0037;

    // CL rotates
    pub const ROL_R64_CL: u32 = 0x0038;
    pub const ROR_R64_CL: u32 = 0x0039;
    pub const RCL_R64_CL: u32 = 0x003A;
    pub const RCR_R64_CL: u32 = 0x003B;

    // Conditional moves
    pub const CMOVZ_R64_R64: u32 = 0x003C;
    pub const CMOVNZ_R64_R64: u32 = 0x003D;
    pub const CMOVL_R64_R64: u32 = 0x003E;
    pub const CMOVGE_R64_R64: u32 = 0x003F;

    // Bit test
    pub const BT_R64_R64: u32 = 0x0040;
    pub const BTS_R64_R64: u32 = 0x0041;
    pub const BTR_R64_R64: u32 = 0x0042;
    pub const BTC_R64_R64: u32 = 0x0043;
    pub const BT_R32_R32: u32 = 0x02F0;
    pub const BTS_R32_R32: u32 = 0x02F1;
    pub const BTR_R32_R32: u32 = 0x02F2;
    pub const BTC_R32_R32: u32 = 0x02F3;
    pub const BT_R64_IMM8: u32 = 0x02F4;
    pub const BTS_R64_IMM8: u32 = 0x02F5;
    pub const BTR_R64_IMM8: u32 = 0x02F6;
    pub const BTC_R64_IMM8: u32 = 0x02F7;
    pub const BT_R32_IMM8: u32 = 0x02F8;
    pub const BTS_R32_IMM8: u32 = 0x02F9;
    pub const BTR_R32_IMM8: u32 = 0x02FA;
    pub const BTC_R32_IMM8: u32 = 0x02FB;

    // Flag manipulation
    pub const CLC: u32 = 0x0044;
    pub const STC: u32 = 0x0045;
    pub const CMC: u32 = 0x0046;

    // SETcc
    pub const SETZ_R8: u32 = 0x0047;
    pub const SETNZ_R8: u32 = 0x0048;
    pub const SETL_R8: u32 = 0x0049;
    pub const SETGE_R8: u32 = 0x004A;

    // Add/sub with carry
    pub const ADC_R64_R64: u32 = 0x004B;
    pub const SBB_R64_R64: u32 = 0x004C;

    // Sign extension
    pub const CBW: u32 = 0x004D;
    pub const CWDE: u32 = 0x004E;
    pub const CDQE: u32 = 0x004F;

    // DX:AX / EDX:EAX sign extension
    pub const CWD: u32 = 0x0050;
    pub const CDQ: u32 = 0x0051;

    // Compare and exchange
    pub const CMPXCHG_R64_R64: u32 = 0x0052;

    // Multi-byte NOP variant
    pub const NOP2: u32 = 0x0053;

    // Stack immediate
    pub const PUSH_IMM8: u32 = 0x0054;
    pub const PUSH_IMM32: u32 = 0x0055;

    // Call/return
    pub const CALL_REL32: u32 = 0x0056;
    pub const RET: u32 = 0x0057;

    // More conditional branches
    pub const JLE_REL32: u32 = 0x0058;
    pub const JG_REL32: u32 = 0x0059;
    pub const JA_REL32: u32 = 0x005A;
    pub const JB_REL32: u32 = 0x005B;
    pub const JBE_REL32: u32 = 0x005C;
    pub const JAE_REL32: u32 = 0x005D;

    // Additional register-aliasing / partial-write forms
    pub const MOV_R16_R16: u32 = 0x005E;
    pub const MOVZX_R32_R16: u32 = 0x005F;
    pub const MOVSX_R32_R16: u32 = 0x0060;
    pub const MOVZX_R32_R8: u32 = 0x0061;
    pub const MOVSX_R32_R8: u32 = 0x0062;
    pub const MOV_R32_IMM32: u32 = 0x0063;
    pub const MOV_R16_IMM16: u32 = 0x0064;
    pub const MOV_R8_IMM8: u32 = 0x0065;

    // Additional 32-bit arithmetic
    pub const ADD_R32_R32: u32 = 0x0066;
    pub const SUB_R32_R32: u32 = 0x0067;
    pub const XOR_R32_R32: u32 = 0x0068;
    pub const AND_R32_R32: u32 = 0x0069;
    pub const OR_R32_R32: u32 = 0x006A;
    pub const CMP_R32_R32: u32 = 0x006B;
    pub const INC_R32: u32 = 0x006C;
    pub const DEC_R32: u32 = 0x006D;
    pub const NEG_R32: u32 = 0x006E;
    pub const NOT_R32: u32 = 0x006F;

    // Additional conditional moves
    pub const CMOVA_R64_R64: u32 = 0x0070;
    pub const CMOVB_R64_R64: u32 = 0x0071;
    pub const CMOVBE_R64_R64: u32 = 0x0072;
    pub const CMOVAE_R64_R64: u32 = 0x0073;
    pub const CMOVS_R64_R64: u32 = 0x0074;
    pub const CMOVNS_R64_R64: u32 = 0x0075;
    pub const CMOVC_R64_R64: u32 = 0x0076;
    pub const CMOVNC_R64_R64: u32 = 0x0077;
    pub const CMOVLE_R64_R64: u32 = 0x0078;
    pub const CMOVG_R64_R64: u32 = 0x0079;

    // Additional SETcc
    pub const SETA_R8: u32 = 0x007A;
    pub const SETB_R8: u32 = 0x007B;
    pub const SETBE_R8: u32 = 0x007C;
    pub const SETAE_R8: u32 = 0x007D;
    pub const SETS_R8: u32 = 0x007E;
    pub const SETNS_R8: u32 = 0x007F;
    pub const SETC_R8: u32 = 0x0080;
    pub const SETNC_R8: u32 = 0x0081;
    pub const SETLE_R8: u32 = 0x0082;
    pub const SETG_R8: u32 = 0x0083;

    // Additional conditional branches
    pub const JO_REL32: u32 = 0x0084;
    pub const JNO_REL32: u32 = 0x0085;
    pub const JPE_REL32: u32 = 0x0086;
    pub const JPO_REL32: u32 = 0x0087;

    // Bit manipulation (expressible with existing primitives)
    pub const BSF_R64_R64: u32 = 0x0088;
    pub const BSR_R64_R64: u32 = 0x0089;
    pub const POPCNT_R64_R64: u32 = 0x008A;
    pub const TZCNT_R64_R64: u32 = 0x008B;
    pub const LZCNT_R64_R64: u32 = 0x008C;
    pub const BSWAP_R64: u32 = 0x008D;

    // Additional shifts and rotates
    pub const SHL_R32_IMM8: u32 = 0x008E;
    pub const SHR_R32_IMM8: u32 = 0x008F;
    pub const SAR_R32_IMM8: u32 = 0x0090;
    pub const SHL_R32_CL: u32 = 0x0091;
    pub const SHR_R32_CL: u32 = 0x0092;
    pub const SAR_R32_CL: u32 = 0x0093;
    pub const ROL_R32_IMM8: u32 = 0x0094;
    pub const ROR_R32_IMM8: u32 = 0x0095;

    // Additional memory operations
    pub const MOV_R32_MEM32: u32 = 0x0096;
    pub const MOV_MEM32_R32: u32 = 0x0097;
    pub const ADD_R32_MEM32: u32 = 0x0098;
    pub const SUB_R32_MEM32: u32 = 0x0099;
    pub const CMP_R32_MEM32: u32 = 0x009A;
    pub const MOV_R8_MEM8: u32 = 0x009B;
    pub const MOV_MEM8_R8: u32 = 0x009C;
    pub const ADD_R8_MEM8: u32 = 0x009D;
    pub const SUB_R8_MEM8: u32 = 0x009E;
    pub const CMP_R8_MEM8: u32 = 0x009F;

    // Additional immediate arithmetic
    pub const ADD_R32_IMM8: u32 = 0x00A0;
    pub const SUB_R32_IMM8: u32 = 0x00A1;
    pub const CMP_R32_IMM8: u32 = 0x00A2;
    pub const AND_R64_IMM32: u32 = 0x00A3;
    pub const OR_R64_IMM32: u32 = 0x00A4;
    pub const XOR_R64_IMM32: u32 = 0x00A5;
    pub const TEST_R64_IMM32: u32 = 0x00A6;
    pub const AND_R32_IMM32: u32 = 0x00A7;
    pub const OR_R32_IMM32: u32 = 0x00A8;
    pub const XOR_R32_IMM32: u32 = 0x00A9;
    pub const TEST_R32_IMM32: u32 = 0x00AA;

    // Exchange and add variants
    pub const XADD_R32_R32: u32 = 0x00AB;
    pub const CMPXCHG_R32_R32: u32 = 0x00AC;

    // Additional stack operations
    pub const PUSH_R32: u32 = 0x00AD;
    pub const POP_R32: u32 = 0x00AE;

    // Multiply variants
    pub const IMUL_R64_R64_IMM32: u32 = 0x00AF;
    pub const IMUL_R32_R32: u32 = 0x00B0;
    pub const IMUL_R32_R32_IMM8: u32 = 0x00B1;
    pub const IMUL_R32_R32_IMM32: u32 = 0x00B2;
    pub const MUL_R32_R32: u32 = 0x00B3;
    pub const DIV_R32_R32: u32 = 0x00B4;
    pub const IDIV_R32_R32: u32 = 0x00B5;

    // LEA 32-bit
    pub const LEA_R32_MEM: u32 = 0x00B6;

    // MOVQ / MOVAPS-class scalar moves (using integer path for now)
    pub const MOVQ_XMM_XMM: u32 = 0x00B7;

    // NOP variants
    pub const NOP3: u32 = 0x00B8;
    pub const NOP4: u32 = 0x00B9;
    pub const NOP5: u32 = 0x00BA;
    pub const NOP6: u32 = 0x00BB;
    pub const NOP7: u32 = 0x00BC;
    pub const NOP8: u32 = 0x00BD;
    pub const NOP9: u32 = 0x00BE;

    // HLT / UD2
    pub const HLT: u32 = 0x00BF;
    pub const UD2: u32 = 0x00C0;

    // SSE scalar single-precision (xmm, xmm)
    pub const ADDSS_XMM_XMM: u32 = 0x00C1;
    pub const SUBSS_XMM_XMM: u32 = 0x00C2;
    pub const MULSS_XMM_XMM: u32 = 0x00C3;
    pub const DIVSS_XMM_XMM: u32 = 0x00C4;
    pub const SQRTSS_XMM_XMM: u32 = 0x00C5;

    // SSE scalar double-precision (xmm, xmm)
    pub const ADDSD_XMM_XMM: u32 = 0x00C6;
    pub const SUBSD_XMM_XMM: u32 = 0x00C7;
    pub const MULSD_XMM_XMM: u32 = 0x00C8;
    pub const DIVSD_XMM_XMM: u32 = 0x00C9;
    pub const SQRTSD_XMM_XMM: u32 = 0x00CA;

    // SSE packed single-precision (xmm, xmm) — 4x32 lanes
    pub const ADDPS_XMM_XMM: u32 = 0x00CB;
    pub const SUBPS_XMM_XMM: u32 = 0x00CC;
    pub const MULPS_XMM_XMM: u32 = 0x00CD;
    pub const DIVPS_XMM_XMM: u32 = 0x00CE;

    // SSE packed double-precision (xmm, xmm) — 2x64 lanes
    pub const ADDPD_XMM_XMM: u32 = 0x00CF;
    pub const SUBPD_XMM_XMM: u32 = 0x00D0;
    pub const MULPD_XMM_XMM: u32 = 0x00D1;
    pub const DIVPD_XMM_XMM: u32 = 0x00D2;

    // SSE2 packed integer byte (xmm, xmm) — 16x8 lanes
    pub const PADDB_XMM_XMM: u32 = 0x00D3;
    pub const PSUBB_XMM_XMM: u32 = 0x00D4;

    // SSE2 packed integer word (xmm, xmm) — 8x16 lanes
    pub const PADDW_XMM_XMM: u32 = 0x00D5;
    pub const PSUBW_XMM_XMM: u32 = 0x00D6;
    pub const PMULLW_XMM_XMM: u32 = 0x00D7;

    // SSE2 packed integer dword (xmm, xmm) — 4x32 lanes
    pub const PADDD_XMM_XMM: u32 = 0x00D8;
    pub const PSUBD_XMM_XMM: u32 = 0x00D9;
    pub const PMULLD_XMM_XMM: u32 = 0x00DA;

    // SSE2 packed integer qword (xmm, xmm) — 2x64 lanes
    pub const PADDQ_XMM_XMM: u32 = 0x00DB;
    pub const PSUBQ_XMM_XMM: u32 = 0x00DC;

    // SSE2 packed logical (xmm, xmm) — full 128-bit
    pub const PAND_XMM_XMM: u32 = 0x00DD;
    pub const POR_XMM_XMM: u32 = 0x00DE;
    pub const PXOR_XMM_XMM: u32 = 0x00DF;

    // SSE2 packed shifts (xmm, imm8) — uniform count per lane
    pub const PSLLW_XMM_IMM8: u32 = 0x00E0;
    pub const PSRLW_XMM_IMM8: u32 = 0x00E1;
    pub const PSRAW_XMM_IMM8: u32 = 0x00E2;
    pub const PSLLD_XMM_IMM8: u32 = 0x00E3;
    pub const PSRLD_XMM_IMM8: u32 = 0x00E4;
    pub const PSRAD_XMM_IMM8: u32 = 0x00E5;
    pub const PSLLQ_XMM_IMM8: u32 = 0x00E6;
    pub const PSRLQ_XMM_IMM8: u32 = 0x00E7;

    // SSE2 packed integer compare (xmm, xmm) — lane-wise mask
    pub const PCMPEQB_XMM_XMM: u32 = 0x00E8;
    pub const PCMPEQW_XMM_XMM: u32 = 0x00E9;
    pub const PCMPEQD_XMM_XMM: u32 = 0x00EA;
    pub const PCMPGTB_XMM_XMM: u32 = 0x00EB;
    pub const PCMPGTW_XMM_XMM: u32 = 0x00EC;
    pub const PCMPGTD_XMM_XMM: u32 = 0x00ED;

    // SSE4 packed integer min/max (xmm, xmm) — lane-wise
    pub const PMAXSB_XMM_XMM: u32 = 0x00EE;
    pub const PMAXSW_XMM_XMM: u32 = 0x00EF;
    pub const PMAXSD_XMM_XMM: u32 = 0x00F0;
    pub const PMAXUB_XMM_XMM: u32 = 0x00F1;
    pub const PMAXUW_XMM_XMM: u32 = 0x00F2;
    pub const PMAXUD_XMM_XMM: u32 = 0x00F3;
    pub const PMINSB_XMM_XMM: u32 = 0x00F4;
    pub const PMINSW_XMM_XMM: u32 = 0x00F5;
    pub const PMINSD_XMM_XMM: u32 = 0x00F6;
    pub const PMINUB_XMM_XMM: u32 = 0x00F7;
    pub const PMINUW_XMM_XMM: u32 = 0x00F8;
    pub const PMINUD_XMM_XMM: u32 = 0x00F9;

    // SSE2 packed multiply high (xmm, xmm) — 8x16 lanes
    pub const PMULHW_XMM_XMM: u32 = 0x00FA;
    pub const PMULHUW_XMM_XMM: u32 = 0x00FB;

    // SSSE3 packed shuffle bytes (xmm, xmm) — byte-level shuffle
    pub const PSHUFB_XMM_XMM: u32 = 0x00FC;

    // SSE2 packed unpack/interleave low (xmm, xmm)
    pub const PUNPCKLBW_XMM_XMM: u32 = 0x00FD;
    pub const PUNPCKLWD_XMM_XMM: u32 = 0x00FE;
    pub const PUNPCKLDQ_XMM_XMM: u32 = 0x00FF;
    pub const PUNPCKLQDQ_XMM_XMM: u32 = 0x0100;

    // SSE2 packed unpack/interleave high (xmm, xmm)
    pub const PUNPCKHBW_XMM_XMM: u32 = 0x0101;
    pub const PUNPCKHWD_XMM_XMM: u32 = 0x0102;
    pub const PUNPCKHDQ_XMM_XMM: u32 = 0x0103;
    pub const PUNPCKHQDQ_XMM_XMM: u32 = 0x0104;

    // SSE2 packed saturate (xmm, xmm) — signed saturation pack
    pub const PACKSSWB_XMM_XMM: u32 = 0x0105;
    pub const PACKSSDW_XMM_XMM: u32 = 0x0106;

    // SSE2/SSE4 packed saturate (xmm, xmm) — unsigned saturation pack
    pub const PACKUSWB_XMM_XMM: u32 = 0x0107;
    pub const PACKUSDW_XMM_XMM: u32 = 0x0108;

    // SSE2 packed multiply and add (xmm, xmm) — 8x16→4x32
    pub const PMADDWD_XMM_XMM: u32 = 0x0109;

    // SSE2 packed sum of absolute differences (xmm, xmm) — 16x8→2x64
    pub const PSADBW_XMM_XMM: u32 = 0x010A;

    // SSE2 packed shuffle doublewords (xmm, imm8) — 4x32→4x32
    pub const PSHUFD_XMM_IMM8: u32 = 0x010B;

    // SSE2 packed shuffle high words (xmm, imm8) — shuffle high 4x16, low 64 unchanged
    pub const PSHUFHW_XMM_IMM8: u32 = 0x010C;

    // SSE2 packed shuffle low words (xmm, imm8) — shuffle low 4x16, high 64 unchanged
    pub const PSHUFLW_XMM_IMM8: u32 = 0x010D;

    // SSSE3 packed multiply and add unsigned/signed bytes (xmm, xmm) — 16x8→8x16
    pub const PMADDUBSW_XMM_XMM: u32 = 0x010E;

    // SSE2 packed shift with register count (xmm, xmm)
    pub const PSLLW_XMM_XMM: u32 = 0x010F;
    pub const PSLLD_XMM_XMM: u32 = 0x0110;
    pub const PSLLQ_XMM_XMM: u32 = 0x0111;
    pub const PSRLW_XMM_XMM: u32 = 0x0112;
    pub const PSRLD_XMM_XMM: u32 = 0x0113;
    pub const PSRLQ_XMM_XMM: u32 = 0x0114;
    pub const PSRAW_XMM_XMM: u32 = 0x0115;
    pub const PSRAD_XMM_XMM: u32 = 0x0116;

    // SSSE3 horizontal add/subtract (xmm, xmm)
    pub const PHADDW_XMM_XMM: u32 = 0x0117;
    pub const PHADDD_XMM_XMM: u32 = 0x0118;
    pub const PHSUBW_XMM_XMM: u32 = 0x0119;
    pub const PHSUBD_XMM_XMM: u32 = 0x011A;

    // SSSE3 packed absolute value (xmm, xmm)
    pub const PABSB_XMM_XMM: u32 = 0x011B;
    pub const PABSW_XMM_XMM: u32 = 0x011C;
    pub const PABSD_XMM_XMM: u32 = 0x011D;

    // SSSE3 packed sign (xmm, xmm)
    pub const PSIGNB_XMM_XMM: u32 = 0x011E;
    pub const PSIGNW_XMM_XMM: u32 = 0x011F;
    pub const PSIGND_XMM_XMM: u32 = 0x0120;

    // SSSE3 packed multiply high with round and scale (xmm, xmm)
    pub const PMULHRSW_XMM_XMM: u32 = 0x0121;

    // SSSE3 horizontal add/subtract with saturation (xmm, xmm)
    pub const PHADDSW_XMM_XMM: u32 = 0x0122;
    pub const PHSUBSW_XMM_XMM: u32 = 0x0123;

    // SSE4.1 packed compare qword equal (xmm, xmm)
    pub const PCMPEQQ_XMM_XMM: u32 = 0x0124;

    // SSE4.1 packed multiply doublewords (xmm, xmm)
    pub const PMULDQ_XMM_XMM: u32 = 0x0125;

    // SSE4.1 variable blend bytes (xmm, xmm, xmm0)
    pub const PBLENDVB_XMM_XMM: u32 = 0x0126;

    // SSE4.1 packed move with sign/zero extend (xmm, xmm/m128)
    pub const PMOVSXBW_XMM_XMM: u32 = 0x0127;
    pub const PMOVZXBW_XMM_XMM: u32 = 0x0128;
    pub const PMOVSXBD_XMM_XMM: u32 = 0x0129;
    pub const PMOVZXBD_XMM_XMM: u32 = 0x012A;
    pub const PMOVSXWD_XMM_XMM: u32 = 0x012B;
    pub const PMOVZXWD_XMM_XMM: u32 = 0x012C;
    pub const PMOVSXDQ_XMM_XMM: u32 = 0x012D;
    pub const PMOVZXDQ_XMM_XMM: u32 = 0x012E;
    pub const PMOVSXWQ_XMM_XMM: u32 = 0x012F;
    pub const PMOVZXWQ_XMM_XMM: u32 = 0x0130;
    pub const PMOVSXBQ_XMM_XMM: u32 = 0x0131;
    pub const PMOVZXBQ_XMM_XMM: u32 = 0x0132;

    // SSE4.1 immediate blends (xmm, xmm, imm8)
    pub const PBLENDW_XMM_XMM_IMM8: u32 = 0x0133;
    pub const BLENDPS_XMM_XMM_IMM8: u32 = 0x0134;
    pub const BLENDPD_XMM_XMM_IMM8: u32 = 0x0135;

    // SSE4.1 packed dot product (xmm, xmm, imm8)
    pub const DPPS_XMM_XMM_IMM8: u32 = 0x0136;
    pub const DPPD_XMM_XMM_IMM8: u32 = 0x0137;

    // SSE4.1 byte extract/insert (r32/xmm, xmm/r32, imm8)
    pub const PEXTRB_R32_XMM_IMM8: u32 = 0x0138;
    pub const PINSRB_XMM_R32_IMM8: u32 = 0x0139;

    // SSE/SSE2 scalar float compare with flags (xmm, xmm)
    pub const UCOMISS_XMM_XMM: u32 = 0x013A;
    pub const UCOMISD_XMM_XMM: u32 = 0x013B;
    pub const COMISS_XMM_XMM: u32 = 0x013C;
    pub const COMISD_XMM_XMM: u32 = 0x013D;

    // SSE4.1 packed/scalar round with imm8 (xmm, xmm, imm8)
    pub const ROUNDPS_XMM_XMM_IMM8: u32 = 0x013E;
    pub const ROUNDPD_XMM_XMM_IMM8: u32 = 0x013F;
    pub const ROUNDSS_XMM_XMM_IMM8: u32 = 0x0140;
    pub const ROUNDSD_XMM_XMM_IMM8: u32 = 0x0141;

    // SSE4.1 PTEST (xmm, xmm)
    pub const PTEST_XMM_XMM: u32 = 0x0142;

    // SSE4.2 CRC32 (r32/r64, r32/r64)
    pub const CRC32_R32_R32: u32 = 0x0143;
    pub const CRC32_R64_R64: u32 = 0x0144;

    // SSE4.1 dword/qword extract/insert (r32/r64, xmm, imm8)
    pub const PEXTRD_R32_XMM_IMM8: u32 = 0x0145;
    pub const PEXTRQ_R64_XMM_IMM8: u32 = 0x0146;
    pub const PINSRD_XMM_R32_IMM8: u32 = 0x0147;
    pub const PINSRQ_XMM_R64_IMM8: u32 = 0x0148;

    // SSE4.1 INSERTPS/EXTRACTPS (xmm/xmm, r32/xmm, imm8)
    pub const INSERTPS_XMM_XMM_IMM8: u32 = 0x0149;
    pub const EXTRACTPS_R32_XMM_IMM8: u32 = 0x014A;

    // 32-bit rotates with CL
    pub const ROL_R32_CL: u32 = 0x014B;
    pub const ROR_R32_CL: u32 = 0x014C;

    // Packed float compare with imm8
    pub const CMPPS_XMM_XMM_IMM8: u32 = 0x014D;
    pub const CMPPD_XMM_XMM_IMM8: u32 = 0x014E;

    // Packed float min/max
    pub const MINPS_XMM_XMM: u32 = 0x014F;
    pub const MAXPS_XMM_XMM: u32 = 0x0150;

    // Move mask to r32
    pub const MOVMSKPS_R32_XMM: u32 = 0x0151;
    pub const MOVMSKPD_R32_XMM: u32 = 0x0152;

    // PMOVMSKB
    pub const PMOVMSKB_R32_XMM: u32 = 0x0153;

    // SSE3/SSE4 packed float horizontal add/sub (xmm, xmm)
    pub const HADDPS_XMM_XMM: u32 = 0x0154;
    pub const HADDPD_XMM_XMM: u32 = 0x0155;
    pub const HSUBPS_XMM_XMM: u32 = 0x0156;
    pub const HSUBPD_XMM_XMM: u32 = 0x0157;

    // SSE4.1 packed min/max 64-bit (xmm, xmm)
    pub const PMAXSQ_XMM_XMM: u32 = 0x0158;
    pub const PMINSQ_XMM_XMM: u32 = 0x0159;

    // SSE/SSE2 packed aligned/unaligned moves (xmm, xmm) — register-to-register
    pub const MOVAPS_XMM_XMM: u32 = 0x015A;
    pub const MOVAPD_XMM_XMM: u32 = 0x015B;
    pub const MOVUPS_XMM_XMM: u32 = 0x015C;
    pub const MOVUPD_XMM_XMM: u32 = 0x015D;

    // SSE/SSE2 scalar moves (xmm, xmm) — register-to-register
    pub const MOVSS_XMM_XMM: u32 = 0x015E;
    pub const MOVSD_XMM_XMM: u32 = 0x015F;

    // SSE4.1 MPSADBW (xmm, xmm, imm8)
    pub const MPSADBW_XMM_XMM_IMM8: u32 = 0x0160;

    // SSE4.1 PHMINPOSUW (xmm, xmm)
    pub const PHMINPOSUW_XMM_XMM: u32 = 0x0161;

    // SSE4.2 PCMPGTQ (xmm, xmm)
    pub const PCMPGTQ_XMM_XMM: u32 = 0x0162;

    // SSE2 PSLLDQ (xmm, imm8)
    pub const PSLLDQ_XMM_IMM8: u32 = 0x0163;

    // SSE2 PSRLDQ (xmm, imm8)
    pub const PSRLDQ_XMM_IMM8: u32 = 0x0164;

    // SSE2 PANDN (xmm, xmm)
    pub const PANDN_XMM_XMM: u32 = 0x0165;

    // LEAVE
    pub const LEAVE: u32 = 0x0166;

    // MOV [m64], imm32
    pub const MOV_MEM64_IMM32: u32 = 0x0167;

    // CMP [m64], imm32 (flags only)
    pub const CMP_MEM64_IMM32: u32 = 0x0168;

    // ADD [m64], r64
    pub const ADD_MEM64_R64: u32 = 0x0169;

    // ADD [m64], imm32
    pub const ADD_MEM64_IMM32: u32 = 0x016A;

    // IMUL r64, [m64]
    pub const IMUL_R64_MEM64: u32 = 0x016B;

    // MOVSXD r64, [m32]
    pub const MOVSX_R64_MEM32: u32 = 0x016C;

    // MOVZX/MOVSX with memory sources
    pub const MOVZX_R64_MEM8: u32 = 0x016D;
    pub const MOVZX_R64_MEM16: u32 = 0x016E;
    pub const MOVZX_R32_MEM8: u32 = 0x016F;
    pub const MOVZX_R32_MEM16: u32 = 0x0170;
    pub const MOVSX_R64_MEM8: u32 = 0x0171;
    pub const MOVSX_R64_MEM16: u32 = 0x0172;
    pub const MOVSX_R64_R16: u32 = 0x025C;
    pub const MOVZX_R64_R16: u32 = 0x025D;
    pub const IMUL_1OP_R64: u32 = 0x025E;
    pub const CQO: u32 = 0x025F;
    pub const IDIV_R64: u32 = 0x0260;
    pub const ADD_R16_R16: u32 = 0x0261;
    pub const INC_R8: u32 = 0x0262;
    pub const DEC_R8: u32 = 0x0263;
    pub const NEG_R8: u32 = 0x0264;
    pub const NOT_R8: u32 = 0x0265;
    pub const SHL_R8_IMM8: u32 = 0x0266;
    pub const BSWAP_R32: u32 = 0x0267;
    pub const MOVSX_R32_MEM8: u32 = 0x0173;
    pub const MOVSX_R32_MEM16: u32 = 0x0174;

    // 8-bit TEST/CMP forms (used heavily by libc string code)
    pub const TEST_R8_R8: u32 = 0x0175;
    pub const TEST_R8_IMM8: u32 = 0x0176;
    pub const TEST_MEM8_R8: u32 = 0x0177;
    pub const CMP_R8_IMM8: u32 = 0x0178;
    pub const CMP_R8_R8: u32 = 0x0179;
    pub const CMP_MEM8_IMM8: u32 = 0x017A;
    pub const TEST_R32_R32: u32 = 0x017B;

    // GPR/vector and memory transfer forms (libc TLS init, memcpy/memset)
    pub const MOVQ_XMM_R64: u32 = 0x017C;
    pub const MOVQ_XMM_MEM64: u32 = 0x017D;
    pub const MOVQ_R64_XMM: u32 = 0x017E;
    pub const MOVQ_MEM64_XMM: u32 = 0x017F;
    pub const MOVD_XMM_R32: u32 = 0x0180;
    pub const MOVD_XMM_MEM32: u32 = 0x0181;
    pub const MOVD_R32_XMM: u32 = 0x0182;
    pub const MOVAPS_MEM_XMM: u32 = 0x0183;
    pub const MOVAPS_XMM_MEM: u32 = 0x0184;
    pub const MOVDQA_MEM_XMM: u32 = 0x0185;
    pub const MOVDQA_XMM_MEM: u32 = 0x0186;
    pub const MOVUPS_MEM_XMM: u32 = 0x0187;
    pub const MOVUPS_XMM_MEM: u32 = 0x0188;
    pub const MOVQ_XMM_MEM: u32 = 0x0189;

    // MOV [m8/m16/m32], imm forms
    pub const MOV_MEM8_IMM8: u32 = 0x018A;
    pub const MOV_MEM16_IMM16: u32 = 0x018B;
    pub const MOV_MEM32_IMM32: u32 = 0x018C;

    // CMP [mN], rN — memory-minus-register compare
    pub const CMP_MEM64_R64: u32 = 0x018D;
    pub const CMP_MEM32_R32: u32 = 0x018E;
    pub const CMP_MEM8_R8: u32 = 0x018F;

    // Indirect jump through a register (`jmp *%rax`).
    pub const JMP_INDIRECT_R64: u32 = 0x0190;
    // Indirect call through a register (`call *%rax`).
    pub const CALL_INDIRECT_R64: u32 = 0x0191;
    // Indirect jump through memory (`jmp *(%rax)`).
    pub const JMP_INDIRECT_MEM64: u32 = 0x0192;
    // Indirect call through memory (`call *(%rax)`).
    pub const CALL_INDIRECT_MEM64: u32 = 0x0193;

    // 16-bit memory moves (`mov r16, r16`/`imm16` already exist at 0x5E/0x64).
    pub const MOV_MEM16_R16: u32 = 0x0194;
    pub const MOV_R16_MEM16: u32 = 0x0195;

    // Read-modify-write [mN], imm forms
    pub const OR_MEM32_IMM32: u32 = 0x0198;
    pub const OR_MEM64_IMM32: u32 = 0x0199;
    pub const AND_MEM32_IMM32: u32 = 0x019A;
    pub const AND_MEM64_IMM32: u32 = 0x019B;
    pub const ADD_MEM32_IMM32: u32 = 0x019C;
    pub const SUB_MEM32_IMM32: u32 = 0x019E;
    pub const SUB_MEM64_IMM32: u32 = 0x019F;
    pub const XOR_MEM32_IMM32: u32 = 0x01A0;
    pub const XOR_MEM64_IMM32: u32 = 0x01A1;

    // CMP [mN], immN
    pub const CMP_MEM32_IMM32: u32 = 0x01A2;
    pub const CMP_MEM16_IMM16: u32 = 0x01A3;

    // TEST [mN], immN
    pub const TEST_MEM8_IMM8: u32 = 0x01A5;
    pub const TEST_MEM16_IMM16: u32 = 0x01A6;
    pub const TEST_MEM32_IMM32: u32 = 0x01A7;
    pub const TEST_MEM64_IMM32: u32 = 0x01A8;

    // Register-minus/logic-with-memory forms
    pub const OR_R32_MEM32: u32 = 0x01A9;
    pub const OR_R64_MEM64: u32 = 0x01AA;
    pub const AND_R32_MEM32: u32 = 0x01AB;
    pub const AND_R64_MEM64: u32 = 0x01AC;
    pub const XOR_R32_MEM32: u32 = 0x01AD;
    pub const XOR_R64_MEM64: u32 = 0x01AE;
    pub const OR_R8_MEM8: u32 = 0x01AF;
    pub const AND_R8_MEM8: u32 = 0x01B0;
    pub const XOR_R8_MEM8: u32 = 0x01B1;

    // Read-modify-write [mN], rN forms
    pub const OR_MEM32_R32: u32 = 0x01B2;
    pub const OR_MEM64_R64: u32 = 0x01B3;
    pub const AND_MEM32_R32: u32 = 0x01B4;
    pub const AND_MEM64_R64: u32 = 0x01B5;
    pub const XOR_MEM32_R32: u32 = 0x01B6;
    pub const XOR_MEM64_R64: u32 = 0x01B7;
    pub const OR_MEM8_R8: u32 = 0x01B8;
    pub const AND_MEM8_R8: u32 = 0x01B9;
    pub const XOR_MEM8_R8: u32 = 0x01BA;
    pub const ADD_MEM8_R8: u32 = 0x01BB;
    pub const SUB_MEM8_R8: u32 = 0x01BC;

    // 32-bit conditional moves
    pub const CMOVZ_R32_R32: u32 = 0x01BD;
    pub const CMOVNZ_R32_R32: u32 = 0x01BE;
    pub const CMOVL_R32_R32: u32 = 0x01BF;
    pub const CMOVGE_R32_R32: u32 = 0x01C0;
    pub const CMOVLE_R32_R32: u32 = 0x01C1;
    pub const CMOVG_R32_R32: u32 = 0x01C2;
    pub const CMOVA_R32_R32: u32 = 0x01C3;
    pub const CMOVB_R32_R32: u32 = 0x01C4;
    pub const CMOVBE_R32_R32: u32 = 0x01C5;
    pub const CMOVAE_R32_R32: u32 = 0x01C6;
    pub const CMOVS_R32_R32: u32 = 0x01C7;
    pub const CMOVNS_R32_R32: u32 = 0x01C8;
    pub const CMOVC_R32_R32: u32 = 0x01C9;
    pub const CMOVNC_R32_R32: u32 = 0x01CA;
    pub const CMOVNP_R32_R32: u32 = 0x01CB;
    pub const CMOVP_R32_R32: u32 = 0x01CC;
    pub const CMOVNO_R32_R32: u32 = 0x01CD;
    pub const CMOVO_R32_R32: u32 = 0x01CE;

    // r8, imm8 read-modify-write forms
    pub const AND_R8_IMM8: u32 = 0x01CF;
    pub const OR_R8_IMM8: u32 = 0x01D0;
    pub const XOR_R8_IMM8: u32 = 0x01D1;
    pub const ADD_R8_IMM8: u32 = 0x01D2;
    pub const SUB_R8_IMM8: u32 = 0x01D3;

    // MOVDQU unaligned loads/stores
    pub const MOVDQU_XMM_MEM: u32 = 0x01E2;
    pub const MOVDQU_MEM_XMM: u32 = 0x01E3;
    pub const MOVDQU_XMM_XMM: u32 = 0x01E4;

    // [m8], imm8 read-modify-write forms
    pub const OR_MEM8_IMM8: u32 = 0x01E5;
    pub const AND_MEM8_IMM8: u32 = 0x01E6;
    pub const XOR_MEM8_IMM8: u32 = 0x01E7;
    pub const ADD_MEM8_IMM8: u32 = 0x01E8;
    pub const SUB_MEM8_IMM8: u32 = 0x01E9;
    // [m16], imm16 / [m64], imm8 variants
    pub const OR_MEM16_IMM16: u32 = 0x01EA;
    pub const AND_MEM16_IMM16: u32 = 0x01EB;
    pub const XOR_MEM16_IMM16: u32 = 0x01EC;
    pub const ADD_MEM16_IMM16: u32 = 0x01ED;
    pub const SUB_MEM16_IMM16: u32 = 0x01EE;
    pub const CMP_MEM16_R16: u32 = 0x01EF;

    // r8, r8 forms
    pub const XOR_R8_R8: u32 = 0x01F0;
    pub const OR_R8_R8: u32 = 0x01F1;
    pub const AND_R8_R8: u32 = 0x01F2;
    pub const ADD_R8_R8: u32 = 0x01F3;
    pub const SUB_R8_R8: u32 = 0x01F4;

    // SUB memory/register forms
    pub const SUB_R64_MEM64: u32 = 0x01F5;
    pub const SUB_MEM64_R64: u32 = 0x01F6;
    pub const SUB_MEM32_R32: u32 = 0x01F7;

    // Compare-and-exchange
    pub const CMPXCHG_MEM32_R32: u32 = 0x01F8;
    pub const CMPXCHG_MEM64_R64: u32 = 0x01F9;
    pub const CMPXCHG_MEM8_R8: u32 = 0x01FA;
    pub const ADD_MEM32_R32: u32 = 0x01FD;

    // Exchange
    pub const XCHG_MEM32_R32: u32 = 0x01FE;
    pub const XCHG_MEM64_R64: u32 = 0x01FF;
    pub const XCHG_MEM8_R8: u32 = 0x0200;
    pub const XCHG_R32_R32: u32 = 0x0201;

    // 16-bit test
    pub const TEST_R16_R16: u32 = 0x0203;
    pub const TEST_R16_IMM16: u32 = 0x0204;
    pub const TEST_MEM16_R16: u32 = 0x0205;

    // 32-bit bit scans / counts
    pub const BSF_R32_R32: u32 = 0x0206;
    pub const BSR_R32_R32: u32 = 0x0207;
    pub const TZCNT_R32_R32: u32 = 0x0208;
    pub const LZCNT_R32_R32: u32 = 0x0209;
    pub const POPCNT_R32_R32: u32 = 0x020A;
    pub const BSF_R64_MEM64: u32 = 0x020B;
    pub const BSF_R32_MEM32: u32 = 0x020C;

    // High/low-half packed moves
    pub const MOVHPS_XMM_MEM64: u32 = 0x020D;
    pub const MOVHPD_XMM_MEM64: u32 = 0x020E;
    pub const MOVLPS_XMM_MEM64: u32 = 0x020F;
    pub const MOVLPD_XMM_MEM64: u32 = 0x0210;
    pub const MOVHPS_MEM64_XMM: u32 = 0x0211;
    pub const MOVLPS_MEM64_XMM: u32 = 0x0212;
    // movss/movsd scalar moves
    pub const MOVSS_XMM_MEM32: u32 = 0x0213;
    pub const MOVSS_MEM32_XMM: u32 = 0x0214;
    pub const MOVSD_XMM_MEM64: u32 = 0x0215;
    pub const MOVSD_MEM64_XMM: u32 = 0x0216;
    // movhlps/movlhps register lane moves (SSE)
    pub const MOVHLPS_XMM_XMM: u32 = 0x0217;
    pub const MOVLHPS_XMM_XMM: u32 = 0x0218;
    // xorps/xorpd packed bitwise XOR (SSE/SSE2; lane-wise byte XOR is the
    // bitwise XOR regardless of the interpreted element type)
    pub const XORPS_XMM_XMM: u32 = 0x02FC;
    pub const XORPS_XMM_MEM128: u32 = 0x02FD;
    pub const XORPD_XMM_XMM: u32 = 0x02FE;
    pub const XORPD_XMM_MEM128: u32 = 0x02FF;

    // YMM (VEX.256) moves and lane-wise ops
    pub const VMOVDQA_YMM_MEM: u32 = 0x0219;
    pub const VMOVDQA_MEM_YMM: u32 = 0x021A;
    pub const VMOVDQA_YMM_YMM: u32 = 0x021B;
    pub const VMOVDQU_YMM_MEM: u32 = 0x021C;
    pub const VMOVDQU_MEM_YMM: u32 = 0x021D;
    pub const VMOVDQU_YMM_YMM: u32 = 0x021E;
    pub const VMOVAPS_YMM_MEM: u32 = 0x021F;
    pub const VMOVAPS_MEM_YMM: u32 = 0x0220;
    pub const VMOVUPS_YMM_MEM: u32 = 0x0221;
    pub const VMOVUPS_MEM_YMM: u32 = 0x0222;
    pub const VPXOR_YMM_YMM_YMM: u32 = 0x0223;
    pub const VPOR_YMM_YMM_YMM: u32 = 0x0224;
    pub const VPAND_YMM_YMM_YMM: u32 = 0x0225;
    pub const VPCMPEQB_YMM_YMM_YMM: u32 = 0x0226;
    pub const VPMOVMSKB_R32_YMM: u32 = 0x0227;
    pub const VPBROADCASTB_YMM_XMM: u32 = 0x0228;
    pub const VPBROADCASTQ_YMM_XMM: u32 = 0x0229;
    pub const VPBROADCASTB_YMM_MEM8: u32 = 0x022A;
    pub const VXORPS_YMM_YMM_YMM: u32 = 0x022C;
    pub const VZEROUPPER: u32 = 0x022D;
    pub const VMOVD_YMM_R32: u32 = 0x022E;
    pub const VMOVD_R32_YMM: u32 = 0x022F;
    pub const VMOVQ_YMM_R64: u32 = 0x0230;
    pub const VMOVQ_R64_YMM: u32 = 0x0231;

    // VEX.128 3-operand forms
    pub const VPXOR_XMM_XMM_XMM: u32 = 0x0232;
    pub const VPOR_XMM_XMM_XMM: u32 = 0x0233;
    pub const VPAND_XMM_XMM_XMM: u32 = 0x0234;
    pub const VXORPS_XMM_XMM_XMM: u32 = 0x0235;
    pub const VPCMPEQB_XMM_XMM_XMM: u32 = 0x0236;
    pub const VPINSRB_XMM_XMM_R8_IMM8: u32 = 0x0237;
    pub const VPINSRW_XMM_XMM_R16_IMM8: u32 = 0x0238;
    pub const VPINSRD_XMM_XMM_R32_IMM8: u32 = 0x0239;
    pub const VPINSRQ_XMM_XMM_R64_IMM8: u32 = 0x023A;
    pub const VINSERTI128_YMM_YMM_XMM_IMM8: u32 = 0x023B;
    pub const VINSERTF128_YMM_YMM_XMM_IMM8: u32 = 0x023C;
    pub const VEXTRACTI128_XMM_YMM_IMM8: u32 = 0x023D;
    pub const VEXTRACTF128_XMM_YMM_IMM8: u32 = 0x023E;
    pub const VPINSRB_XMM_XMM_MEM8_IMM8: u32 = 0x023F;
    pub const VPINSRW_XMM_XMM_MEM16_IMM8: u32 = 0x0240;
    pub const VPINSRD_XMM_XMM_MEM32_IMM8: u32 = 0x0241;
    pub const VPINSRQ_XMM_XMM_MEM64_IMM8: u32 = 0x0242;

    // VEX.128 move forms
    pub const VMOVDQA_XMM_MEM: u32 = 0x0243;
    pub const VMOVDQA_MEM_XMM: u32 = 0x0244;
    pub const VMOVDQA_XMM_XMM: u32 = 0x0245;
    pub const VMOVDQU_XMM_MEM: u32 = 0x0246;
    pub const VMOVDQU_MEM_XMM: u32 = 0x0247;
    pub const VMOVDQU_XMM_XMM: u32 = 0x0248;
    pub const VMOVAPS_XMM_MEM: u32 = 0x0249;
    pub const VMOVAPS_MEM_XMM: u32 = 0x024A;
    pub const VMOVUPS_XMM_MEM: u32 = 0x024B;
    pub const VMOVUPS_MEM_XMM: u32 = 0x024C;
    pub const VEXTRACTI128_MEM128_YMM_IMM8: u32 = 0x024D;
    pub const VEXTRACTF128_MEM128_YMM_IMM8: u32 = 0x024E;

    // VEX movd/movq
    pub const VMOVD_XMM_R32: u32 = 0x024F;
    pub const VMOVD_R32_XMM: u32 = 0x0250;
    pub const VMOVD_XMM_MEM32: u32 = 0x0251;
    pub const VMOVD_MEM32_XMM: u32 = 0x0252;
    pub const VMOVQ_XMM_R64: u32 = 0x0253;
    pub const VMOVQ_R64_XMM: u32 = 0x0254;
    pub const VMOVQ_XMM_MEM64: u32 = 0x0255;
    pub const VMOVQ_MEM64_XMM: u32 = 0x0256;

    // AVX packed-single arithmetic, scalar-single arithmetic, and packed logic.
    pub const VADDPS_YMM_YMM_YMM: u32 = 0x0400;
    pub const VADDPS_YMM_YMM_MEM: u32 = 0x0401;
    pub const VSUBPS_YMM_YMM_YMM: u32 = 0x0402;
    pub const VSUBPS_YMM_YMM_MEM: u32 = 0x0403;
    pub const VMULPS_YMM_YMM_YMM: u32 = 0x0404;
    pub const VMULPS_YMM_YMM_MEM: u32 = 0x0405;
    pub const VDIVPS_YMM_YMM_YMM: u32 = 0x0406;
    pub const VDIVPS_YMM_YMM_MEM: u32 = 0x0407;
    pub const VADDSS_XMM_XMM_XMM: u32 = 0x0408;
    pub const VADDSS_XMM_XMM_MEM32: u32 = 0x0409;
    pub const VSUBSS_XMM_XMM_XMM: u32 = 0x040A;
    pub const VSUBSS_XMM_XMM_MEM32: u32 = 0x040B;
    pub const VMULSS_XMM_XMM_XMM: u32 = 0x040C;
    pub const VMULSS_XMM_XMM_MEM32: u32 = 0x040D;
    pub const VDIVSS_XMM_XMM_XMM: u32 = 0x040E;
    pub const VDIVSS_XMM_XMM_MEM32: u32 = 0x040F;
    pub const VANDPS_YMM_YMM_YMM: u32 = 0x0410;
    pub const VANDPS_YMM_YMM_MEM: u32 = 0x0411;
    pub const VANDNPS_YMM_YMM_YMM: u32 = 0x0412;
    pub const VANDNPS_YMM_YMM_MEM: u32 = 0x0413;
    pub const VORPS_YMM_YMM_YMM: u32 = 0x0414;
    pub const VORPS_YMM_YMM_MEM: u32 = 0x0415;
    pub const VADDPS_XMM_XMM_XMM: u32 = 0x0416;
    pub const VADDPS_XMM_XMM_MEM: u32 = 0x0417;
    pub const VSUBPS_XMM_XMM_XMM: u32 = 0x0418;
    pub const VSUBPS_XMM_XMM_MEM: u32 = 0x0419;
    pub const VMULPS_XMM_XMM_XMM: u32 = 0x041A;
    pub const VMULPS_XMM_XMM_MEM: u32 = 0x041B;
    pub const VDIVPS_XMM_XMM_XMM: u32 = 0x041C;
    pub const VDIVPS_XMM_XMM_MEM: u32 = 0x041D;
    // VEX.128 packed bitwise operations. Each operation has register and
    // memory-source encodings; all clear bits 128..511 of the destination.
    pub const VANDPS_XMM_XMM_XMM: u32 = 0x3010;
    pub const VANDPS_XMM_XMM_MEM: u32 = 0x3011;
    pub const VANDNPS_XMM_XMM_XMM: u32 = 0x3012;
    pub const VANDNPS_XMM_XMM_MEM: u32 = 0x3013;
    pub const VORPS_XMM_XMM_XMM: u32 = 0x3014;
    pub const VORPS_XMM_XMM_MEM: u32 = 0x3015;
    pub const VXORPS_XMM_XMM_MEM: u32 = 0x3016;
    pub const VANDPD_XMM_XMM_XMM: u32 = 0x3017;
    pub const VANDPD_XMM_XMM_MEM: u32 = 0x3018;
    pub const VANDNPD_XMM_XMM_XMM: u32 = 0x3019;
    pub const VANDNPD_XMM_XMM_MEM: u32 = 0x301A;
    pub const VORPD_XMM_XMM_XMM: u32 = 0x301B;
    pub const VORPD_XMM_XMM_MEM: u32 = 0x301C;
    pub const VXORPD_XMM_XMM_XMM: u32 = 0x301D;
    pub const VXORPD_XMM_XMM_MEM: u32 = 0x301E;
    pub const VPXOR_XMM_XMM_MEM: u32 = 0x301F;
    pub const VPOR_XMM_XMM_MEM: u32 = 0x3020;
    pub const VPAND_XMM_XMM_MEM: u32 = 0x3021;

    // AVX packed-double arithmetic, scalar-double arithmetic, and packed logic.
    pub const VADDPD_YMM_YMM_YMM: u32 = 0x0F48;
    pub const VADDPD_YMM_YMM_MEM: u32 = 0x0F49;
    pub const VSUBPD_YMM_YMM_YMM: u32 = 0x0F4A;
    pub const VSUBPD_YMM_YMM_MEM: u32 = 0x0F4B;
    pub const VMULPD_YMM_YMM_YMM: u32 = 0x0F4C;
    pub const VMULPD_YMM_YMM_MEM: u32 = 0x0F4D;
    pub const VDIVPD_YMM_YMM_YMM: u32 = 0x0F4E;
    pub const VDIVPD_YMM_YMM_MEM: u32 = 0x0F4F;
    pub const VADDSD_XMM_XMM_XMM: u32 = 0x0F50;
    pub const VADDSD_XMM_XMM_MEM64: u32 = 0x0F51;
    pub const VSUBSD_XMM_XMM_XMM: u32 = 0x0F52;
    pub const VSUBSD_XMM_XMM_MEM64: u32 = 0x0F53;
    pub const VMULSD_XMM_XMM_XMM: u32 = 0x0F54;
    pub const VMULSD_XMM_XMM_MEM64: u32 = 0x0F55;
    pub const VDIVSD_XMM_XMM_XMM: u32 = 0x0F56;
    pub const VDIVSD_XMM_XMM_MEM64: u32 = 0x0F57;
    pub const VANDPD_YMM_YMM_YMM: u32 = 0x0F58;
    pub const VANDPD_YMM_YMM_MEM: u32 = 0x0F59;
    pub const VANDNPD_YMM_YMM_YMM: u32 = 0x0F5A;
    pub const VANDNPD_YMM_YMM_MEM: u32 = 0x0F5B;
    pub const VORPD_YMM_YMM_YMM: u32 = 0x0F5C;
    pub const VORPD_YMM_YMM_MEM: u32 = 0x0F5D;
    pub const VXORPD_YMM_YMM_YMM: u32 = 0x0F5E;
    pub const VXORPD_YMM_YMM_MEM: u32 = 0x0F5F;

    // AVX conversion, blend, and permutation family.
    pub const VCVTSS2SD_XMM_XMM_XMM: u32 = 0x0F60;
    pub const VCVTSS2SD_XMM_XMM_MEM32: u32 = 0x0F61;
    pub const VCVTSD2SS_XMM_XMM_XMM: u32 = 0x0F62;
    pub const VCVTSD2SS_XMM_XMM_MEM64: u32 = 0x0F63;
    pub const VBLENDPS_YMM_YMM_YMM_IMM8: u32 = 0x0F64;
    pub const VBLENDPS_YMM_YMM_MEM_IMM8: u32 = 0x0F65;
    pub const VBLENDPD_YMM_YMM_YMM_IMM8: u32 = 0x0F66;
    pub const VBLENDPD_YMM_YMM_MEM_IMM8: u32 = 0x0F67;
    pub const VBLENDVPS_YMM_YMM_YMM_YMM: u32 = 0x0F68;
    pub const VBLENDVPS_YMM_YMM_MEM_YMM: u32 = 0x0F69;
    pub const VBLENDVPD_YMM_YMM_YMM_YMM: u32 = 0x0F6A;
    pub const VBLENDVPD_YMM_YMM_MEM_YMM: u32 = 0x0F6B;
    pub const VPERM2F128_YMM_YMM_YMM_IMM8: u32 = 0x0F6C;
    pub const VPERM2F128_YMM_YMM_MEM_IMM8: u32 = 0x0F6D;
    pub const VPERMILPS_YMM_YMM_IMM8: u32 = 0x0F6E;
    pub const VPERMILPS_YMM_MEM_IMM8: u32 = 0x0F6F;
    pub const VPERMILPD_YMM_YMM_IMM8: u32 = 0x0F70;
    pub const VPERMILPD_YMM_MEM_IMM8: u32 = 0x0F71;

    // AVX shuffle and unpack forms (0x0F72..0x0F7D).
    pub const VSHUFPS_YMM_YMM_YMM_IMM8: u32 = 0x0F72;
    pub const VSHUFPS_YMM_YMM_MEM_IMM8: u32 = 0x0F73;
    pub const VSHUFPD_YMM_YMM_YMM_IMM8: u32 = 0x0F74;
    pub const VSHUFPD_YMM_YMM_MEM_IMM8: u32 = 0x0F75;
    pub const VUNPCKLPS_YMM_YMM_YMM: u32 = 0x0F76;
    pub const VUNPCKLPS_YMM_YMM_MEM: u32 = 0x0F77;
    pub const VUNPCKHPS_YMM_YMM_YMM: u32 = 0x0F78;
    pub const VUNPCKHPS_YMM_YMM_MEM: u32 = 0x0F79;
    pub const VUNPCKLPD_YMM_YMM_YMM: u32 = 0x0F7A;
    pub const VUNPCKLPD_YMM_YMM_MEM: u32 = 0x0F7B;
    pub const VUNPCKHPD_YMM_YMM_YMM: u32 = 0x0F7C;
    pub const VUNPCKHPD_YMM_YMM_MEM: u32 = 0x0F7D;

    // AVX min/max and square-root family (0x0880..0x0897).
    pub const VMINPS_YMM_YMM_YMM: u32 = 0x0880;
    pub const VMINPS_YMM_YMM_MEM: u32 = 0x0881;
    pub const VMAXPS_YMM_YMM_YMM: u32 = 0x0882;
    pub const VMAXPS_YMM_YMM_MEM: u32 = 0x0883;
    pub const VMINPD_YMM_YMM_YMM: u32 = 0x0884;
    pub const VMINPD_YMM_YMM_MEM: u32 = 0x0885;
    pub const VMAXPD_YMM_YMM_YMM: u32 = 0x0886;
    pub const VMAXPD_YMM_YMM_MEM: u32 = 0x0887;
    pub const VMINSS_XMM_XMM_XMM: u32 = 0x0888;
    pub const VMINSS_XMM_XMM_MEM32: u32 = 0x0889;
    pub const VMAXSS_XMM_XMM_XMM: u32 = 0x088A;
    pub const VMAXSS_XMM_XMM_MEM32: u32 = 0x088B;
    pub const VMINSD_XMM_XMM_XMM: u32 = 0x088C;
    pub const VMINSD_XMM_XMM_MEM64: u32 = 0x088D;
    pub const VMAXSD_XMM_XMM_XMM: u32 = 0x088E;
    pub const VMAXSD_XMM_XMM_MEM64: u32 = 0x088F;
    pub const VSQRTPS_YMM_YMM: u32 = 0x0890;
    pub const VSQRTPS_YMM_MEM: u32 = 0x0891;
    pub const VSQRTPD_YMM_YMM: u32 = 0x0892;
    pub const VSQRTPD_YMM_MEM: u32 = 0x0893;
    pub const VSQRTSS_XMM_XMM_XMM: u32 = 0x0894;
    pub const VSQRTSS_XMM_XMM_MEM32: u32 = 0x0895;
    pub const VSQRTSD_XMM_XMM_XMM: u32 = 0x0896;
    pub const VSQRTSD_XMM_XMM_MEM64: u32 = 0x0897;

    // AVX2 variable shifts and cross-lane permutes (0x08A0..0x08BD).
    // Variable shifts (0x08A0..0x08B3):
    pub const VPSLLVD_XMM_XMM_XMM: u32 = 0x08A0;
    pub const VPSLLVD_XMM_XMM_MEM128: u32 = 0x08A1;
    pub const VPSLLVD_YMM_YMM_YMM: u32 = 0x08A2;
    pub const VPSLLVD_YMM_YMM_MEM256: u32 = 0x08A3;
    pub const VPSLLVQ_XMM_XMM_XMM: u32 = 0x08A4;
    pub const VPSLLVQ_XMM_XMM_MEM128: u32 = 0x08A5;
    pub const VPSLLVQ_YMM_YMM_YMM: u32 = 0x08A6;
    pub const VPSLLVQ_YMM_YMM_MEM256: u32 = 0x08A7;
    pub const VPSRAVD_XMM_XMM_XMM: u32 = 0x08A8;
    pub const VPSRAVD_XMM_XMM_MEM128: u32 = 0x08A9;
    pub const VPSRAVD_YMM_YMM_YMM: u32 = 0x08AA;
    pub const VPSRAVD_YMM_YMM_MEM256: u32 = 0x08AB;
    pub const VPSRLVD_XMM_XMM_XMM: u32 = 0x08AC;
    pub const VPSRLVD_XMM_XMM_MEM128: u32 = 0x08AD;
    pub const VPSRLVD_YMM_YMM_YMM: u32 = 0x08AE;
    pub const VPSRLVD_YMM_YMM_MEM256: u32 = 0x08AF;
    pub const VPSRLVQ_XMM_XMM_XMM: u32 = 0x08B0;
    pub const VPSRLVQ_XMM_XMM_MEM128: u32 = 0x08B1;
    pub const VPSRLVQ_YMM_YMM_YMM: u32 = 0x08B2;
    pub const VPSRLVQ_YMM_YMM_MEM256: u32 = 0x08B3;

    // Cross-lane permutes (0x08B4..0x08BD):
    pub const VPERMD_YMM_YMM_YMM: u32 = 0x08B4;
    pub const VPERMD_YMM_YMM_MEM256: u32 = 0x08B5;
    pub const VPERMPS_YMM_YMM_YMM: u32 = 0x08B6;
    pub const VPERMPS_YMM_YMM_MEM256: u32 = 0x08B7;
    pub const VPERMQ_YMM_YMM_IMM8: u32 = 0x08B8;
    pub const VPERMQ_YMM_MEM256_IMM8: u32 = 0x08B9;
    pub const VPERMPD_YMM_YMM_IMM8: u32 = 0x08BA;
    pub const VPERMPD_YMM_MEM256_IMM8: u32 = 0x08BB;
    pub const VPERM2I128_YMM_YMM_YMM_IMM8: u32 = 0x08BC;
    pub const VPERM2I128_YMM_YMM_MEM256_IMM8: u32 = 0x08BD;

    // AVX2 saturating add/sub unsigned + average (0x08BE..0x08C9).
    pub const VPADDUSB_YMM_YMM_YMM: u32 = 0x08BE;
    pub const VPADDUSB_YMM_YMM_MEM256: u32 = 0x08BF;
    pub const VPADDUSW_YMM_YMM_YMM: u32 = 0x08C0;
    pub const VPADDUSW_YMM_YMM_MEM256: u32 = 0x08C1;
    pub const VPSUBUSB_YMM_YMM_YMM: u32 = 0x08C2;
    pub const VPSUBUSB_YMM_YMM_MEM256: u32 = 0x08C3;
    pub const VPSUBUSW_YMM_YMM_YMM: u32 = 0x08C4;
    pub const VPSUBUSW_YMM_YMM_MEM256: u32 = 0x08C5;
    pub const VPAVGB_YMM_YMM_YMM: u32 = 0x08C6;
    pub const VPAVGB_YMM_YMM_MEM256: u32 = 0x08C7;
    pub const VPAVGW_YMM_YMM_YMM: u32 = 0x08C8;
    pub const VPAVGW_YMM_YMM_MEM256: u32 = 0x08C9;

    // AVX2 multiply low dword + multiply high unsigned word (0x08CA..0x08CD).
    pub const VPMULLD_YMM_YMM_YMM: u32 = 0x08CA;
    pub const VPMULLD_YMM_YMM_MEM256: u32 = 0x08CB;
    pub const VPMULHUW_YMM_YMM_YMM: u32 = 0x08CC;
    pub const VPMULHUW_YMM_YMM_MEM256: u32 = 0x08CD;

    // AVX2 packed absolute value (0x08CE..0x08D3).
    pub const VPABSB_YMM_YMM: u32 = 0x08CE;
    pub const VPABSB_YMM_MEM256: u32 = 0x08CF;
    pub const VPABSW_YMM_YMM: u32 = 0x08D0;
    pub const VPABSW_YMM_MEM256: u32 = 0x08D1;
    pub const VPABSD_YMM_YMM: u32 = 0x08D2;
    pub const VPABSD_YMM_MEM256: u32 = 0x08D3;

    // AVX2 packed sign (0x08D4..0x08D9).
    pub const VPSIGNB_YMM_YMM_YMM: u32 = 0x08D4;
    pub const VPSIGNB_YMM_YMM_MEM256: u32 = 0x08D5;
    pub const VPSIGNW_YMM_YMM_YMM: u32 = 0x08D6;
    pub const VPSIGNW_YMM_YMM_MEM256: u32 = 0x08D7;
    pub const VPSIGND_YMM_YMM_YMM: u32 = 0x08D8;
    pub const VPSIGND_YMM_YMM_MEM256: u32 = 0x08D9;

    // AVX2 pack with saturation (0x08DA..0x08E1).
    pub const VPACKSSWB_YMM_YMM_YMM: u32 = 0x08DA;
    pub const VPACKSSWB_YMM_YMM_MEM256: u32 = 0x08DB;
    pub const VPACKSSDW_YMM_YMM_YMM: u32 = 0x08DC;
    pub const VPACKSSDW_YMM_YMM_MEM256: u32 = 0x08DD;
    pub const VPACKUSWB_YMM_YMM_YMM: u32 = 0x08DE;
    pub const VPACKUSWB_YMM_YMM_MEM256: u32 = 0x08DF;
    pub const VPACKUSDW_YMM_YMM_YMM: u32 = 0x08E0;
    pub const VPACKUSDW_YMM_YMM_MEM256: u32 = 0x08E1;

    // AVX2 blend with immediate (0x08E2..0x08E3).
    pub const VPBLENDD_YMM_YMM_YMM_IMM8: u32 = 0x08E2;
    pub const VPBLENDD_YMM_YMM_MEM256_IMM8: u32 = 0x08E3;

    // Memory forms for existing VPCMPEQ/VPCMPGT YMM providers (0x08E4..0x08EA).
    pub const VPCMPEQW_YMM_YMM_MEM256: u32 = 0x08E4;
    pub const VPCMPEQD_YMM_YMM_MEM256: u32 = 0x08E5;
    pub const VPCMPEQQ_YMM_YMM_MEM256: u32 = 0x08E6;
    pub const VPCMPGTB_YMM_YMM_MEM256: u32 = 0x08E7;
    pub const VPCMPGTW_YMM_YMM_MEM256: u32 = 0x08E8;
    pub const VPCMPGTD_YMM_YMM_MEM256: u32 = 0x08E9;
    pub const VPCMPGTQ_YMM_YMM_MEM256: u32 = 0x08EA;

    // AVX-512 EVEX packed single/double arithmetic + logic (ZMM, 0x0900..0x091F).
    // EVEX decodes report the implicit opmask (k0) as an operand, so the
    // form-map shapes are [Zmm, Reg64, Zmm, {Zmm, Mem}].
    pub const VADDPS_ZMM_ZMM_ZMM: u32 = 0x0900;
    pub const VADDPS_ZMM_ZMM_MEM: u32 = 0x0901;
    pub const VSUBPS_ZMM_ZMM_ZMM: u32 = 0x0902;
    pub const VSUBPS_ZMM_ZMM_MEM: u32 = 0x0903;
    pub const VMULPS_ZMM_ZMM_ZMM: u32 = 0x0904;
    pub const VMULPS_ZMM_ZMM_MEM: u32 = 0x0905;
    pub const VDIVPS_ZMM_ZMM_ZMM: u32 = 0x0906;
    pub const VDIVPS_ZMM_ZMM_MEM: u32 = 0x0907;
    pub const VADDPD_ZMM_ZMM_ZMM: u32 = 0x0908;
    pub const VADDPD_ZMM_ZMM_MEM: u32 = 0x0909;
    pub const VSUBPD_ZMM_ZMM_ZMM: u32 = 0x090A;
    pub const VSUBPD_ZMM_ZMM_MEM: u32 = 0x090B;
    pub const VMULPD_ZMM_ZMM_ZMM: u32 = 0x090C;
    pub const VMULPD_ZMM_ZMM_MEM: u32 = 0x090D;
    pub const VDIVPD_ZMM_ZMM_ZMM: u32 = 0x090E;
    pub const VDIVPD_ZMM_ZMM_MEM: u32 = 0x090F;
    pub const VANDPS_ZMM_ZMM_ZMM: u32 = 0x0910;
    pub const VANDPS_ZMM_ZMM_MEM: u32 = 0x0911;
    pub const VANDNPS_ZMM_ZMM_ZMM: u32 = 0x0912;
    pub const VANDNPS_ZMM_ZMM_MEM: u32 = 0x0913;
    pub const VORPS_ZMM_ZMM_ZMM: u32 = 0x0914;
    pub const VORPS_ZMM_ZMM_MEM: u32 = 0x0915;
    pub const VXORPS_ZMM_ZMM_ZMM: u32 = 0x0916;
    pub const VXORPS_ZMM_ZMM_MEM: u32 = 0x0917;
    pub const VANDPD_ZMM_ZMM_ZMM: u32 = 0x0918;
    pub const VANDPD_ZMM_ZMM_MEM: u32 = 0x0919;
    pub const VANDNPD_ZMM_ZMM_ZMM: u32 = 0x091A;
    pub const VANDNPD_ZMM_ZMM_MEM: u32 = 0x091B;
    pub const VORPD_ZMM_ZMM_ZMM: u32 = 0x091C;
    pub const VORPD_ZMM_ZMM_MEM: u32 = 0x091D;
    pub const VXORPD_ZMM_ZMM_ZMM: u32 = 0x091E;
    pub const VXORPD_ZMM_ZMM_MEM: u32 = 0x091F;

    // 16-bit integer arithmetic, IMUL, and MOVSXD expansion.
    pub const ADD_R16_IMM16: u32 = 0x0420;
    pub const ADD_R16_IMM8: u32 = 0x0421;
    pub const ADD_R16_MEM16: u32 = 0x0422;
    pub const ADD_MEM16_R16: u32 = 0x0423;
    pub const ADD_MEM16_IMM16_V2: u32 = 0x0424;
    pub const ADD_MEM16_IMM8: u32 = 0x0425;
    pub const ADC_R16_R16: u32 = 0x0426;
    pub const ADC_R16_IMM16: u32 = 0x0427;
    pub const ADC_R16_IMM8: u32 = 0x0428;
    pub const ADC_R16_MEM16: u32 = 0x0429;
    pub const ADC_MEM16_R16: u32 = 0x042A;
    pub const ADC_MEM16_IMM16: u32 = 0x042B;
    pub const ADC_MEM16_IMM8: u32 = 0x042C;
    pub const SBB_R16_R16: u32 = 0x042D;
    pub const SBB_R16_IMM16: u32 = 0x042E;
    pub const SBB_R16_IMM8: u32 = 0x042F;
    pub const SBB_R16_MEM16: u32 = 0x0430;
    pub const SBB_MEM16_R16: u32 = 0x0431;
    pub const SBB_MEM16_IMM16: u32 = 0x0432;
    pub const SBB_MEM16_IMM8: u32 = 0x0433;
    pub const CMP_R16_R16: u32 = 0x0434;
    pub const CMP_R16_IMM16: u32 = 0x0435;
    pub const CMP_R16_IMM8: u32 = 0x0436;
    pub const CMP_R16_MEM16: u32 = 0x0437;
    pub const CMP_MEM16_R16_V2: u32 = 0x0438;
    pub const CMP_MEM16_IMM16_V2: u32 = 0x0439;
    pub const CMP_MEM16_IMM8: u32 = 0x043A;
    pub const OR_R16_R16: u32 = 0x043B;
    pub const OR_R16_IMM16: u32 = 0x043C;
    pub const OR_R16_IMM8: u32 = 0x043D;
    pub const OR_R16_MEM16: u32 = 0x043E;
    pub const OR_MEM16_R16: u32 = 0x043F;
    pub const OR_MEM16_IMM16_V2: u32 = 0x0440;
    pub const OR_MEM16_IMM8: u32 = 0x0441;
    pub const XOR_R16_R16: u32 = 0x0442;
    pub const XOR_R16_IMM16: u32 = 0x0443;
    pub const XOR_R16_IMM8: u32 = 0x0444;
    pub const XOR_R16_MEM16: u32 = 0x0445;
    pub const XOR_MEM16_R16: u32 = 0x0446;
    pub const XOR_MEM16_IMM16_V2: u32 = 0x0447;
    pub const XOR_MEM16_IMM8: u32 = 0x0448;
    pub const SUB_R16_R16: u32 = 0x0449;
    pub const SUB_R16_IMM16: u32 = 0x044A;
    pub const SUB_R16_IMM8: u32 = 0x044B;
    pub const SUB_R16_MEM16: u32 = 0x044C;
    pub const SUB_MEM16_R16: u32 = 0x044D;
    pub const SUB_MEM16_IMM16_V2: u32 = 0x044E;
    pub const SUB_MEM16_IMM8: u32 = 0x044F;
    pub const IMUL_R16_R16: u32 = 0x0450;
    pub const IMUL_R16_MEM16: u32 = 0x0451;
    pub const IMUL_R16_R16_IMM16: u32 = 0x0452;
    pub const IMUL_R16_R16_IMM8: u32 = 0x0453;
    pub const IMUL_R16_MEM16_IMM16: u32 = 0x0454;
    pub const IMUL_R16_MEM16_IMM8: u32 = 0x0455;
    pub const IMUL_R32_MEM32: u32 = 0x0456;
    pub const IMUL_R32_MEM32_IMM32: u32 = 0x0457;
    pub const IMUL_R64_MEM64_IMM32: u32 = 0x0458;
    pub const MOVSXD_R64_R32: u32 = 0x0459;
    pub const MOVSXD_R64_MEM32: u32 = 0x045A;
    pub const IMUL_R32_MEM32_IMM8: u32 = 0x045B;
    pub const IMUL_R64_R64_IMM8: u32 = 0x045C;
    pub const IMUL_R64_MEM64_IMM8: u32 = 0x045D;

    // push/pop memory operand
    pub const PUSH_MEM64: u32 = 0x0257;
    pub const PUSH_MEM16: u32 = 0x0258;
    pub const POP_MEM64: u32 = 0x0259;

    // pushf/popf (64-bit operand size in 64-bit mode)
    pub const PUSHF: u32 = 0x025A;
    pub const POPF: u32 = 0x025B;

    // Unsigned divide (rdx:rax / operand -> rax=quot, rdx=rem)
    pub const DIV_R64: u32 = 0x01D4;
    pub const DIV_R32: u32 = 0x01D5;
    pub const DIV_MEM64: u32 = 0x01D6;
    pub const DIV_MEM32: u32 = 0x01D7;
    pub const MUL_R64: u32 = 0x01D9;
    pub const MUL_MEM64: u32 = 0x01DA;
    pub const MUL_R32: u32 = 0x01DB;
    pub const MUL_MEM32: u32 = 0x01DC;

    /// RDTSC — Read Time-Stamp Counter. Writes the 64-bit TSC to EDX:EAX.
    /// Deterministic for replay: returns a monotonically increasing counter
    /// (each read increments by 1), NOT the real CPU timestamp.
    pub const RDTSC: u32 = 0x01DD;

    /// RDMSR — Read Model-Specific Register (ECX selector → EDX:EAX).
    /// The model returns zero for every MSR (debt-recorded: no MSR state is
    /// tracked), deterministic for replay.
    pub const RDMSR: u32 = 0x01DF;

    /// WRMSR — Write Model-Specific Register (EDX:EAX → ECX selector).
    /// No-op in the model (debt-recorded: writes are not observable state).
    pub const WRMSR: u32 = 0x01E0;

    /// LFENCE/SFENCE/MFENCE — memory-ordering fences. No-ops on a
    /// single-vCPU emulator (debt-recorded: no memory-ordering semantics).
    pub const FENCE: u32 = 0x01E1;

    // Port I/O (x86 IN/OUT). Reads return zero (device absent) and writes
    // are dropped (debt-recorded: no device model).
    pub const IN_AL_DX: u32 = 0x0300;
    pub const IN_AX_DX: u32 = 0x0301;
    pub const IN_EAX_DX: u32 = 0x0302;
    pub const OUT_DX_AL: u32 = 0x0303;
    pub const OUT_DX_AX: u32 = 0x0304;
    pub const OUT_DX_EAX: u32 = 0x0305;

    // Port I/O immediate-port forms (IN AL/AX/EAX, imm8 / OUT imm8, AL/AX/EAX).
    pub const IN_AL_IMM8: u32 = 0x0500;
    pub const IN_AX_IMM8: u32 = 0x0501;
    pub const IN_EAX_IMM8: u32 = 0x0502;
    pub const OUT_IMM8_AL: u32 = 0x0503;
    pub const OUT_IMM8_AX: u32 = 0x0504;
    pub const OUT_IMM8_EAX: u32 = 0x0505;

    // String port I/O forms (INSB/INSW/INSD / OUTSB/OUTSW/OUTSD).
    pub const INSB: u32 = 0x0506;
    pub const INSW: u32 = 0x0507;
    pub const INSD: u32 = 0x0508;
    pub const OUTSB: u32 = 0x0509;
    pub const OUTSW: u32 = 0x050A;
    pub const OUTSD: u32 = 0x050B;

    /// INT imm8 — Software interrupt. On Windows, `int 0x29` is `__fastfail`
    /// (security check failure → immediate termination). Semantic reads the
    /// vector and terminates, preserving the vector in RAX for diagnostics.
    pub const INT_IMM8: u32 = 0x01DE;

    // x87 FPU state initialization (fninit)
    pub const FINIT: u32 = 0x0268;

    // x87 FLD (push): m32real, m64real, st(i), and the constants 1.0 / 0.0
    pub const FLD_M32: u32 = 0x0269;
    pub const FLD_M64: u32 = 0x026A;
    pub const FLD_STI: u32 = 0x026B;
    pub const FLD1: u32 = 0x026C;
    pub const FLDZ: u32 = 0x026D;

    // x87 FST/FSTP: st(i) destination (FST st(i) is blocked on decoder support),
    // m32real and m64real destinations
    pub const FSTP_STI: u32 = 0x026E;
    pub const FST_M32: u32 = 0x026F;
    pub const FST_M64: u32 = 0x0270;
    pub const FSTP_M32: u32 = 0x0271;
    pub const FSTP_M64: u32 = 0x0272;

    // x87 arithmetic. ST0_STI = destination st(0) (D8 encodings);
    // STI_ST0 = destination st(i) (DC encodings); memory forms add to st(0).
    pub const FADD_ST0_STI: u32 = 0x0273;
    pub const FADD_STI_ST0: u32 = 0x0274;
    pub const FADD_M32: u32 = 0x0275;
    pub const FADD_M64: u32 = 0x0276;
    pub const FSUB_ST0_STI: u32 = 0x0277;
    pub const FSUB_STI_ST0: u32 = 0x0278;
    pub const FSUB_M32: u32 = 0x0279;
    pub const FSUB_M64: u32 = 0x027A;
    pub const FSUBR_ST0_STI: u32 = 0x027B;
    pub const FSUBR_STI_ST0: u32 = 0x027C;
    pub const FSUBR_M32: u32 = 0x027D;
    pub const FSUBR_M64: u32 = 0x027E;
    pub const FMUL_ST0_STI: u32 = 0x027F;
    pub const FMUL_STI_ST0: u32 = 0x0280;
    pub const FMUL_M32: u32 = 0x0281;
    pub const FMUL_M64: u32 = 0x0282;
    pub const FDIV_ST0_STI: u32 = 0x0283;
    pub const FDIV_STI_ST0: u32 = 0x0284;
    pub const FDIV_M32: u32 = 0x0285;
    pub const FDIV_M64: u32 = 0x0286;
    pub const FDIVR_ST0_STI: u32 = 0x0287;
    pub const FDIVR_STI_ST0: u32 = 0x0288;
    pub const FDIVR_M32: u32 = 0x0289;
    pub const FDIVR_M64: u32 = 0x028A;

    // x87 compare into RFLAGS (ZF/PF/CF); P variants pop afterwards
    pub const FUCOMI_ST0_STI: u32 = 0x028B;
    pub const FUCOMIP_ST0_STI: u32 = 0x028C;
    pub const FCOMI_ST0_STI: u32 = 0x028D;
    pub const FCOMIP_ST0_STI: u32 = 0x028E;

    // Memory-operand and cache-hint batch.
    pub const SHL_MEM16_IMM8: u32 = 0x0700;
    pub const SHL_MEM16_CL: u32 = 0x0701;
    pub const SHL_MEM32_IMM8: u32 = 0x0702;
    pub const SHL_MEM32_CL: u32 = 0x0703;
    pub const SHL_MEM64_IMM8: u32 = 0x0704;
    pub const SHL_MEM64_CL: u32 = 0x0705;
    pub const SHR_MEM16_IMM8: u32 = 0x0706;
    pub const SHR_MEM16_CL: u32 = 0x0707;
    pub const SHR_MEM32_IMM8: u32 = 0x0708;
    pub const SHR_MEM32_CL: u32 = 0x0709;
    pub const SHR_MEM64_IMM8: u32 = 0x070A;
    pub const SHR_MEM64_CL: u32 = 0x070B;
    pub const SAR_MEM16_IMM8: u32 = 0x070C;
    pub const SAR_MEM16_CL: u32 = 0x070D;
    pub const SAR_MEM32_IMM8: u32 = 0x070E;
    pub const SAR_MEM32_CL: u32 = 0x070F;
    pub const SAR_MEM64_IMM8: u32 = 0x0710;
    pub const SAR_MEM64_CL: u32 = 0x0711;
    pub const ROL_MEM16_IMM8: u32 = 0x0712;
    pub const ROL_MEM16_CL: u32 = 0x0713;
    pub const ROL_MEM32_IMM8: u32 = 0x0714;
    pub const ROL_MEM32_CL: u32 = 0x0715;
    pub const ROL_MEM64_IMM8: u32 = 0x0716;
    pub const ROL_MEM64_CL: u32 = 0x0717;
    pub const ROR_MEM16_IMM8: u32 = 0x0718;
    pub const ROR_MEM16_CL: u32 = 0x0719;
    pub const ROR_MEM32_IMM8: u32 = 0x071A;
    pub const ROR_MEM32_CL: u32 = 0x071B;
    pub const ROR_MEM64_IMM8: u32 = 0x071C;
    pub const ROR_MEM64_CL: u32 = 0x071D;
    pub const RCL_MEM16_IMM8: u32 = 0x071E;
    pub const RCL_MEM16_CL: u32 = 0x071F;
    pub const RCL_MEM32_IMM8: u32 = 0x0720;
    pub const RCL_MEM32_CL: u32 = 0x0721;
    pub const RCL_MEM64_IMM8: u32 = 0x0722;
    pub const RCL_MEM64_CL: u32 = 0x0723;
    pub const RCR_MEM16_IMM8: u32 = 0x0724;
    pub const RCR_MEM16_CL: u32 = 0x0725;
    pub const RCR_MEM32_IMM8: u32 = 0x0726;
    pub const RCR_MEM32_CL: u32 = 0x0727;
    pub const RCR_MEM64_IMM8: u32 = 0x0728;
    pub const RCR_MEM64_CL: u32 = 0x0729;
    pub const BTS_MEM32_R32: u32 = 0x072A;
    pub const BTS_MEM64_R64: u32 = 0x072B;
    pub const BTR_MEM32_R32: u32 = 0x072C;
    pub const BTR_MEM64_R64: u32 = 0x072D;
    pub const BTC_MEM32_R32: u32 = 0x072E;
    pub const BTC_MEM64_R64: u32 = 0x072F;
    pub const AND_R16_R16: u32 = 0x0730;
    pub const AND_R16_IMM16: u32 = 0x0731;
    pub const AND_R16_IMM8: u32 = 0x0732;
    pub const AND_R16_MEM16: u32 = 0x0733;
    pub const AND_MEM16_R16: u32 = 0x0734;
    pub const AND_MEM16_IMM16_V2: u32 = 0x0735;
    pub const AND_MEM16_IMM8: u32 = 0x0736;
    pub const CMOVZ_R16_R16: u32 = 0x0737;
    pub const CMOVNZ_R16_R16: u32 = 0x0738;
    pub const CMOVB_R16_R16: u32 = 0x0739;
    pub const CMOVNB_R16_R16: u32 = 0x073A;
    pub const CMOVL_R16_R16: u32 = 0x073B;
    pub const CMOVNL_R16_R16: u32 = 0x073C;
    pub const CMOVBE_R16_R16: u32 = 0x073D;
    pub const CMOVNBE_R16_R16: u32 = 0x073E;
    pub const CMOVLE_R16_R16: u32 = 0x073F;
    pub const CMOVNLE_R16_R16: u32 = 0x0740;
    pub const MOVNTDQ_MEM128_XMM: u32 = 0x0741;
    pub const MOVNTI_MEM32_R32: u32 = 0x0742;
    pub const MOVNTI_MEM64_R64: u32 = 0x0743;
    pub const PREFETCHNTA_MEM8: u32 = 0x0744;
    pub const PREFETCHT0_MEM8: u32 = 0x0745;
    pub const PREFETCHT1_MEM8: u32 = 0x0746;
    pub const PREFETCHT2_MEM8: u32 = 0x0747;
    pub const PREFETCHW_MEM8: u32 = 0x0748;

    // Control flow, stack frame, and flags batch (0x0600..0x06FF)
    pub const LOOP_REL8: u32 = 0x0600;
    pub const LOOPE_REL8: u32 = 0x0601;
    pub const LOOPNE_REL8: u32 = 0x0602;
    pub const JRCXZ_REL8: u32 = 0x0603;
    pub const RET_FAR: u32 = 0x0604;
    pub const RET_IMM16: u32 = 0x0605;
    pub const ENTER_IMM16_IMM8: u32 = 0x0606;
    pub const RET_FAR_IMM16: u32 = 0x0607;
    pub const LAHF: u32 = 0x0608;
    pub const SAHF: u32 = 0x0609;
    pub const CLD: u32 = 0x060A;
    pub const STD: u32 = 0x060B;

    // Extended x87 FPU family (0x0800..0x08FF)
    pub const FCOM_STI: u32 = 0x0800;
    pub const FCOM_M32: u32 = 0x0801;
    pub const FCOM_M64: u32 = 0x0802;
    pub const FCOMP_STI: u32 = 0x0803;
    pub const FCOMP_M32: u32 = 0x0804;
    pub const FCOMP_M64: u32 = 0x0805;
    pub const FCOMPP: u32 = 0x0806;
    pub const FIADD_M16: u32 = 0x0807;
    pub const FIADD_M32: u32 = 0x0808;
    pub const FISUB_M16: u32 = 0x0809;
    pub const FISUB_M32: u32 = 0x080A;
    pub const FISUBR_M16: u32 = 0x080B;
    pub const FISUBR_M32: u32 = 0x080C;
    pub const FIMUL_M16: u32 = 0x080D;
    pub const FIMUL_M32: u32 = 0x080E;
    pub const FIDIV_M16: u32 = 0x080F;
    pub const FIDIV_M32: u32 = 0x0810;
    pub const FIDIVR_M16: u32 = 0x0811;
    pub const FIDIVR_M32: u32 = 0x0812;
    pub const FICOM_M16: u32 = 0x0813;
    pub const FICOM_M32: u32 = 0x0814;
    pub const FICOMP_M16: u32 = 0x0815;
    pub const FICOMP_M32: u32 = 0x0816;
    pub const FILD_M16: u32 = 0x0817;
    pub const FILD_M32: u32 = 0x0818;
    pub const FILD_M64: u32 = 0x0819;
    pub const FIST_M16: u32 = 0x081A;
    pub const FIST_M32: u32 = 0x081B;
    pub const FISTP_M16: u32 = 0x081C;
    pub const FISTP_M32: u32 = 0x081D;
    pub const FISTP_M64: u32 = 0x081E;
    pub const FABS: u32 = 0x081F;
    pub const FCHS: u32 = 0x0820;
    pub const FSQRT: u32 = 0x0821;
    pub const FXCH: u32 = 0x0822;
    pub const FXCH_STI: u32 = 0x0823;
    pub const FSTSW_AX: u32 = 0x0824;
    pub const FLDPI: u32 = 0x0825;
    pub const FLDL2E: u32 = 0x0826;
    pub const FLDL2T: u32 = 0x0827;
    pub const FLDLG2: u32 = 0x0828;
    pub const FLDLN2: u32 = 0x0829;
    pub const FST_STI: u32 = 0x082A;
    pub const FNOP: u32 = 0x082B;
    pub const FSTSW_M16: u32 = 0x082C;
    pub const FLDCW_M16: u32 = 0x082D;
    pub const FNSTCW_M16: u32 = 0x082E;
    pub const FNCLEX: u32 = 0x082F;
    pub const FTST: u32 = 0x0830;
    pub const FXAM: u32 = 0x0831;
    pub const FDECSTP: u32 = 0x0832;
    pub const FINCSTP: u32 = 0x0833;
    pub const FFREE_STI: u32 = 0x0834;
    pub const FRNDINT: u32 = 0x0835;
    pub const FSINCOS: u32 = 0x0836;
    pub const FCMOVB_ST0_STI: u32 = 0x0837;
    pub const FCMOVE_ST0_STI: u32 = 0x0838;
    pub const FCMOVBE_ST0_STI: u32 = 0x0839;
    pub const FCMOVU_ST0_STI: u32 = 0x083A;
    pub const FCMOVNB_ST0_STI: u32 = 0x083B;
    pub const FCMOVNE_ST0_STI: u32 = 0x083C;
    pub const FCMOVNBE_ST0_STI: u32 = 0x083D;
    pub const FCMOVNU_ST0_STI: u32 = 0x083E;

    // Intel 64 System & Control forms (0x083F..0x084F)
    pub const RDTSCP: u32 = 0x083F;
    pub const XGETBV: u32 = 0x0840;
    pub const WBINVD: u32 = 0x0841;
    pub const INVD: u32 = 0x0842;

    // BMI1 instructions (0x0850..0x0863)
    pub const ANDN_R32_R32_R32: u32 = 0x0850;
    pub const ANDN_R32_R32_MEM32: u32 = 0x0851;
    pub const ANDN_R64_R64_R64: u32 = 0x0852;
    pub const ANDN_R64_R64_MEM64: u32 = 0x0853;
    pub const BEXTR_R32_R32_R32: u32 = 0x0854;
    pub const BEXTR_R32_MEM32_R32: u32 = 0x0855;
    pub const BEXTR_R64_R64_R64: u32 = 0x0856;
    pub const BEXTR_R64_MEM64_R64: u32 = 0x0857;
    pub const BLSI_R32_R32: u32 = 0x0858;
    pub const BLSI_R32_MEM32: u32 = 0x0859;
    pub const BLSI_R64_R64: u32 = 0x085A;
    pub const BLSI_R64_MEM64: u32 = 0x085B;
    pub const BLSMSK_R32_R32: u32 = 0x085C;
    pub const BLSMSK_R32_MEM32: u32 = 0x085D;
    pub const BLSMSK_R64_R64: u32 = 0x085E;
    pub const BLSMSK_R64_MEM64: u32 = 0x085F;
    pub const BLSR_R32_R32: u32 = 0x0860;
    pub const BLSR_R32_MEM32: u32 = 0x0861;
    pub const BLSR_R64_R64: u32 = 0x0862;
    pub const BLSR_R64_MEM64: u32 = 0x0863;

    // BMI2 instructions (0x0864..0x087B)
    pub const BZHI_R32_R32_R32: u32 = 0x0864;
    pub const BZHI_R32_MEM32_R32: u32 = 0x0865;
    pub const BZHI_R64_R64_R64: u32 = 0x0866;
    pub const BZHI_R64_MEM64_R64: u32 = 0x0867;
    pub const MULX_R32_R32_R32: u32 = 0x0868;
    pub const MULX_R32_R32_MEM32: u32 = 0x0869;
    pub const MULX_R64_R64_R64: u32 = 0x086A;
    pub const MULX_R64_R64_MEM64: u32 = 0x086B;
    pub const RORX_R32_R32_IMM8: u32 = 0x086C;
    pub const RORX_R32_MEM32_IMM8: u32 = 0x086D;
    pub const RORX_R64_R64_IMM8: u32 = 0x086E;
    pub const RORX_R64_MEM64_IMM8: u32 = 0x086F;
    pub const SARX_R32_R32_R32: u32 = 0x0870;
    pub const SARX_R32_MEM32_R32: u32 = 0x0871;
    pub const SARX_R64_R64_R64: u32 = 0x0872;
    pub const SARX_R64_MEM64_R64: u32 = 0x0873;
    pub const SHLX_R32_R32_R32: u32 = 0x0874;
    pub const SHLX_R32_MEM32_R32: u32 = 0x0875;
    pub const SHLX_R64_R64_R64: u32 = 0x0876;
    pub const SHLX_R64_MEM64_R64: u32 = 0x0877;
    pub const SHRX_R32_R32_R32: u32 = 0x0878;
    pub const SHRX_R32_MEM32_R32: u32 = 0x0879;
    pub const SHRX_R64_R64_R64: u32 = 0x087A;
    pub const SHRX_R64_MEM64_R64: u32 = 0x087B;

    // x87 transcendental family (assigned form ID band: 0x0F40..0x0F7F)
    // Providers are SKIPPED: the IR/interpreter has no sin/cos/tan/atan/exp2/log2
    // or scale primitive (FloatingOp::{Sin,Cos,Tan,Atan,Exp,Log,Scale} do not
    // exist and the interpreter crate is owned by a sibling agent).
    pub const FSIN: u32 = 0x0F40;
    pub const FCOS: u32 = 0x0F41;
    pub const FPTAN: u32 = 0x0F42;
    pub const FPATAN: u32 = 0x0F43;
    pub const F2XM1: u32 = 0x0F44;
    pub const FYL2X: u32 = 0x0F45;
    pub const FYL2XP1: u32 = 0x0F46;
    pub const FSCALE: u32 = 0x0F47;

    // SSE4.1 / SSE4.2 completion batch (0x0C00..0x0CFF)
    pub const BLENDVPS_XMM_XMM: u32 = 0x0C00;
    pub const BLENDVPD_XMM_XMM: u32 = 0x0C01;
    pub const MOVNTDQA_XMM_MEM: u32 = 0x0C02;

    // Scalar SSE floating-point conversion and min/max batch (0x0D00..0x0DFF)
    pub const CVTSS2SD_XMM_XMM: u32 = 0x0D00;
    pub const CVTSD2SS_XMM_XMM: u32 = 0x0D01;
    pub const MAXSS_XMM_XMM: u32 = 0x0D02;
    pub const MAXSD_XMM_XMM: u32 = 0x0D03;
    pub const MINSS_XMM_XMM: u32 = 0x0D04;
    pub const MINSD_XMM_XMM: u32 = 0x0D05;

    // Tail census batch (0x0B00..0x0BFF): XADD, CMPXCHG, SETcc mem, TEST mem, CLFLUSH, MOVBE, CRC32, JMP_FAR
    pub const XADD_MEM32_R32: u32 = 0x0B00;
    pub const XADD_MEM64_R64: u32 = 0x0B01;
    pub const XADD_MEM16_R16: u32 = 0x0B02;
    pub const XADD_MEM8_R8: u32 = 0x0B03;
    pub const XADD_R16_R16: u32 = 0x0B04;
    pub const XADD_R8_R8: u32 = 0x0B05;

    pub const CMPXCHG_MEM16_R16: u32 = 0x0B06;
    pub const CMPXCHG_R16_R16: u32 = 0x0B07;
    pub const CMPXCHG_R8_R8: u32 = 0x0B08;

    pub const SETZ_MEM8: u32 = 0x0B10;
    pub const SETNZ_MEM8: u32 = 0x0B11;
    pub const SETB_MEM8: u32 = 0x0B12;
    pub const SETAE_MEM8: u32 = 0x0B13;
    pub const SETBE_MEM8: u32 = 0x0B14;
    pub const SETA_MEM8: u32 = 0x0B15;
    pub const SETL_MEM8: u32 = 0x0B16;
    pub const SETGE_MEM8: u32 = 0x0B17;
    pub const SETLE_MEM8: u32 = 0x0B18;
    pub const SETG_MEM8: u32 = 0x0B19;
    pub const SETS_MEM8: u32 = 0x0B1A;
    pub const SETNS_MEM8: u32 = 0x0B1B;
    pub const SETO_R8: u32 = 0x0B1C;
    pub const SETO_MEM8: u32 = 0x0B1D;
    pub const SETNO_R8: u32 = 0x0B1E;
    pub const SETNO_MEM8: u32 = 0x0B1F;
    pub const SETP_R8: u32 = 0x0B20;
    pub const SETP_MEM8: u32 = 0x0B21;
    pub const SETNP_R8: u32 = 0x0B22;
    pub const SETNP_MEM8: u32 = 0x0B23;

    pub const TEST_MEM32_R32: u32 = 0x0B24;
    pub const TEST_MEM64_R64: u32 = 0x0B25;
    pub const TEST_R32_MEM32: u32 = 0x0B26;
    pub const TEST_R64_MEM64: u32 = 0x0B27;

    pub const CLFLUSH_MEM: u32 = 0x0B30;

    pub const MOVBE_R16_MEM16: u32 = 0x0B40;
    pub const MOVBE_R32_MEM32: u32 = 0x0B41;
    pub const MOVBE_R64_MEM64: u32 = 0x0B42;
    pub const MOVBE_MEM16_R16: u32 = 0x0B43;
    pub const MOVBE_MEM32_R32: u32 = 0x0B44;
    pub const MOVBE_MEM64_R64: u32 = 0x0B45;

    pub const CRC32_R32_MEM32: u32 = 0x0B50;
    pub const CRC32_R64_MEM64: u32 = 0x0B51;
    pub const CRC32_R32_R8: u32 = 0x0B52;
    pub const CRC32_R32_MEM8: u32 = 0x0B53;
    pub const CRC32_R64_R8: u32 = 0x0B54;
    pub const CRC32_R64_MEM8: u32 = 0x0B55;

    pub const JMP_FAR_MEM: u32 = 0x0B60;

    // AVX-256 (VEX) integer family (0x0A00..0x0AFF)
    pub const VPADDB_YMM_YMM_YMM: u32 = 0x0A00;
    pub const VPADDW_YMM_YMM_YMM: u32 = 0x0A01;
    pub const VPADDD_YMM_YMM_YMM: u32 = 0x0A02;
    pub const VPADDQ_YMM_YMM_YMM: u32 = 0x0A03;
    pub const VPSUBB_YMM_YMM_YMM: u32 = 0x0A04;
    pub const VPSUBW_YMM_YMM_YMM: u32 = 0x0A05;
    pub const VPSUBD_YMM_YMM_YMM: u32 = 0x0A06;
    pub const VPSUBQ_YMM_YMM_YMM: u32 = 0x0A07;
    pub const VPCMPEQW_YMM_YMM_YMM: u32 = 0x0A08;
    pub const VPCMPEQD_YMM_YMM_YMM: u32 = 0x0A09;
    pub const VPCMPEQQ_YMM_YMM_YMM: u32 = 0x0A0A;
    pub const VPCMPGTB_YMM_YMM_YMM: u32 = 0x0A0B;
    pub const VPCMPGTW_YMM_YMM_YMM: u32 = 0x0A0C;
    pub const VPCMPGTD_YMM_YMM_YMM: u32 = 0x0A0D;
    pub const VPCMPGTQ_YMM_YMM_YMM: u32 = 0x0A0E;
    pub const VPMULLW_YMM_YMM_YMM: u32 = 0x0A0F;
    pub const VPMULHW_YMM_YMM_YMM: u32 = 0x0A10;
    pub const VPMADDWD_YMM_YMM_YMM: u32 = 0x0A11;
    pub const VPSLLW_YMM_YMM_IMM8: u32 = 0x0A12;
    pub const VPSLLD_YMM_YMM_IMM8: u32 = 0x0A13;
    pub const VPSLLQ_YMM_YMM_IMM8: u32 = 0x0A14;
    pub const VPSRLW_YMM_YMM_IMM8: u32 = 0x0A15;
    pub const VPSRLD_YMM_YMM_IMM8: u32 = 0x0A16;
    pub const VPSRLQ_YMM_YMM_IMM8: u32 = 0x0A17;
    pub const VPSRAW_YMM_YMM_IMM8: u32 = 0x0A18;
    pub const VPSRAD_YMM_YMM_IMM8: u32 = 0x0A19;
    pub const VPSLLW_YMM_YMM_XMM: u32 = 0x0A1A;
    pub const VPSLLD_YMM_YMM_XMM: u32 = 0x0A1B;
    pub const VPSLLQ_YMM_YMM_XMM: u32 = 0x0A1C;
    pub const VPSRLW_YMM_YMM_XMM: u32 = 0x0A1D;
    pub const VPSRLD_YMM_YMM_XMM: u32 = 0x0A1E;
    pub const VPSRLQ_YMM_YMM_XMM: u32 = 0x0A1F;
    pub const VPSRAW_YMM_YMM_XMM: u32 = 0x0A20;
    pub const VPSRAD_YMM_YMM_XMM: u32 = 0x0A21;
    pub const VPSHUFD_YMM_YMM_IMM8: u32 = 0x0A22;
    pub const VPSHUFB_YMM_YMM_YMM: u32 = 0x0A23;
    pub const VPUNPCKLBW_YMM_YMM_YMM: u32 = 0x0A24;
    pub const VPUNPCKLWD_YMM_YMM_YMM: u32 = 0x0A25;
    pub const VPUNPCKLDQ_YMM_YMM_YMM: u32 = 0x0A26;
    pub const VPUNPCKLQDQ_YMM_YMM_YMM: u32 = 0x0A27;
    pub const VPUNPCKHBW_YMM_YMM_YMM: u32 = 0x0A28;
    pub const VPUNPCKHWD_YMM_YMM_YMM: u32 = 0x0A29;
    pub const VPUNPCKHDQ_YMM_YMM_YMM: u32 = 0x0A2A;
    pub const VPUNPCKHQDQ_YMM_YMM_YMM: u32 = 0x0A2B;
    pub const VPMINUB_YMM_YMM_YMM: u32 = 0x0A2C;
    pub const VPMINSB_YMM_YMM_YMM: u32 = 0x0A2D;
    pub const VPMINUW_YMM_YMM_YMM: u32 = 0x0A2E;
    pub const VPMINSW_YMM_YMM_YMM: u32 = 0x0A2F;
    pub const VPMINUD_YMM_YMM_YMM: u32 = 0x0A30;
    pub const VPMINSD_YMM_YMM_YMM: u32 = 0x0A31;
    pub const VPMAXUB_YMM_YMM_YMM: u32 = 0x0A32;
    pub const VPMAXSB_YMM_YMM_YMM: u32 = 0x0A33;
    pub const VPMAXUW_YMM_YMM_YMM: u32 = 0x0A34;
    pub const VPMAXSW_YMM_YMM_YMM: u32 = 0x0A35;
    pub const VPMAXUD_YMM_YMM_YMM: u32 = 0x0A36;
    pub const VPMAXSD_YMM_YMM_YMM: u32 = 0x0A37;
    pub const VPBROADCASTW_YMM_XMM: u32 = 0x0A38;
    pub const VPBROADCASTD_YMM_XMM: u32 = 0x0A39;
    pub const VPBROADCASTB_YMM_R32: u32 = 0x0A3A;
    pub const VPBROADCASTW_YMM_R32: u32 = 0x0A3B;
    pub const VPBROADCASTD_YMM_R32: u32 = 0x0A3C;
    pub const VPBROADCASTQ_YMM_R64: u32 = 0x0A3D;

    // Census-tail completion: 8-bit shifts/rotates (CL and mem-imm8),
    // ADC/SBB r8/m8 imm8, ADD mem32-r32, MOVSXD r32, BTS/BTR/BTC mem-imm8.
    pub const MOVSXD_R32_MEM32: u32 = 0x0E81;
    pub const ADC_R8_IMM8: u32 = 0x0E82;
    pub const ADC_MEM8_IMM8: u32 = 0x0E83;
    pub const SBB_R8_IMM8: u32 = 0x0E84;
    pub const SBB_MEM8_IMM8: u32 = 0x0E85;
    pub const BTS_MEM32_IMM8: u32 = 0x0E86;
    pub const BTS_MEM64_IMM8: u32 = 0x0E87;
    pub const BTR_MEM32_IMM8: u32 = 0x0E88;
    pub const BTR_MEM64_IMM8: u32 = 0x0E89;
    pub const BTC_MEM32_IMM8: u32 = 0x0E8A;
    pub const BTC_MEM64_IMM8: u32 = 0x0E8B;
    pub const SHL_R8_CL: u32 = 0x0E8C;
    pub const SHR_R8_CL: u32 = 0x0E8D;
    pub const SAR_R8_CL: u32 = 0x0E8E;
    pub const ROL_R8_CL: u32 = 0x0E8F;
    pub const ROR_R8_CL: u32 = 0x0E90;
    pub const RCL_R8_CL: u32 = 0x0E91;
    pub const RCR_R8_CL: u32 = 0x0E92;
    pub const SHL_MEM8_IMM8: u32 = 0x0E93;
    pub const SHR_MEM8_IMM8: u32 = 0x0E94;
    pub const SAR_MEM8_IMM8: u32 = 0x0E95;
    pub const ROL_MEM8_IMM8: u32 = 0x0E96;
    pub const ROR_MEM8_IMM8: u32 = 0x0E97;
    pub const RCL_MEM8_IMM8: u32 = 0x0E98;
    pub const RCR_MEM8_IMM8: u32 = 0x0E99;
    pub const SHL_MEM8_CL: u32 = 0x0E9A;
    pub const SHR_MEM8_CL: u32 = 0x0E9B;
    pub const SAR_MEM8_CL: u32 = 0x0E9C;
    pub const ROL_MEM8_CL: u32 = 0x0E9D;
    pub const ROR_MEM8_CL: u32 = 0x0E9E;
    pub const RCL_MEM8_CL: u32 = 0x0E9F;
    pub const RCR_MEM8_CL: u32 = 0x0EA0;
    pub const ADC_R8_R8: u32 = 0x0EA1;
    pub const ADC_MEM8_R8: u32 = 0x0EA2;
    pub const SBB_R8_R8: u32 = 0x0EA3;
    pub const SBB_MEM8_R8: u32 = 0x0EA4;
    pub const BT_MEM32_IMM8: u32 = 0x0EA6;
    pub const BT_MEM64_IMM8: u32 = 0x0EA7;
    pub const FWAIT: u32 = 0x0EA8;
    pub const CLTS: u32 = 0x0EA9;
    pub const INC_R16: u32 = 0x0EAB;
    pub const CMOVO_R64_R64: u32 = 0x0EAC;
    pub const CMOVNO_R64_R64: u32 = 0x0EAD;
    pub const CMOVP_R64_R64: u32 = 0x0EAE;
    pub const CMOVNP_R64_R64: u32 = 0x0EAF;
    pub const ADC_R32_IMM32: u32 = 0x0EB1;
    pub const SBB_R32_IMM32: u32 = 0x0EB2;

    // SBB width completion and scalar D1 shifts/rotates (agent band).
    pub const SBB_R32_R32: u32 = 0x0E00;
    pub const SBB_R32_MEM32: u32 = 0x0E01;
    pub const SBB_MEM32_R32: u32 = 0x0E02;
    pub const SBB_R64_MEM64: u32 = 0x0E03;
    pub const SBB_MEM64_R64: u32 = 0x0E04;
    pub const SHL_R16_IMM8: u32 = 0x0E05;
    pub const SHR_R16_IMM8: u32 = 0x0E06;
    pub const SAR_R16_IMM8: u32 = 0x0E07;
    pub const ROL_R16_IMM8: u32 = 0x0E08;
    pub const ROR_R16_IMM8: u32 = 0x0E09;
    pub const RCL_R16_IMM8: u32 = 0x0E0A;
    pub const RCR_R16_IMM8: u32 = 0x0E0B;
    pub const RCL_R32_IMM8: u32 = 0x0E0C;
    pub const RCR_R32_IMM8: u32 = 0x0E0D;

    // Privileged system-register moves. CR/DR state is intentionally absent
    // from the deterministic execution model.
    pub const MOV_R64_CR: u32 = 0x0F00;
    pub const MOV_CR_R64: u32 = 0x0F01;
    pub const MOV_R64_DR: u32 = 0x0F02;
    pub const MOV_DR_R64: u32 = 0x0F03;

    // Final census-tail forms. Segment-register operands are absent from the
    // normalized XED operand list, so direction is encoded in the form id.
    pub const MOV_R16_SREG: u32 = 0x0F80;
    pub const MOV_R64_SREG: u32 = 0x0F81;
    pub const MOV_MEM16_SREG: u32 = 0x0F82;
    pub const MOV_SREG_R16: u32 = 0x0F83;
    pub const MOV_SREG_MEM16: u32 = 0x0F84;
    pub const FLD_M80: u32 = 0x0F85;
    pub const IRETD: u32 = 0x0F86;
    pub const PUSH_R16: u32 = 0x0F87;
    pub const XCHG_R8_R8: u32 = 0x0F88;
    pub const ROR_R8_IMM8: u32 = 0x0F89;
    pub const RCR_R8_IMM8: u32 = 0x0F8A;
    pub const MOV_R32_SREG: u32 = 0x0F8B;
    pub const ADC_R8_MEM8: u32 = 0x0F8C;
    pub const SBB_R8_MEM8: u32 = 0x0F8D;

    // CET (Control-flow Enforcement Technology) forms
    pub const INCSSPD_R32: u32 = 0x0F90;
    pub const INCSSPQ_R64: u32 = 0x0F91;
    pub const RDSSPD_R32: u32 = 0x0F92;
    pub const RDSSPQ_R64: u32 = 0x0F93;
    pub const SAVEPREVSSP: u32 = 0x0F94;
    pub const RSTORSSP_MEM64: u32 = 0x0F95;
    pub const SETSSBSY: u32 = 0x0F96;
    pub const CLRSSBSY_MEM64: u32 = 0x0F97;
    pub const WRSSD_MEM32_R32: u32 = 0x0F98;
    pub const WRSSQ_MEM64_R64: u32 = 0x0F99;
    pub const WRUSSD_MEM32_R32: u32 = 0x0F9A;
    pub const WRUSSQ_MEM64_R64: u32 = 0x0F9B;
    // Advanced Performance Extensions (APX) forms (0x0FA0..0x0FDC)
    pub const JMPABS_IMM64: u32 = 0x0FA0;
    pub const PUSH2_R64_R64: u32 = 0x0FA1;
    pub const PUSH2P_R64_R64: u32 = 0x0FA2;
    pub const POP2_R64_R64: u32 = 0x0FA3;
    pub const POP2P_R64_R64: u32 = 0x0FA4;
    pub const CCMPO_R64_R64: u32 = 0x0FA5;
    pub const CCMPNO_R64_R64: u32 = 0x0FA6;
    pub const CCMPB_R64_R64: u32 = 0x0FA7;
    pub const CCMPNB_R64_R64: u32 = 0x0FA8;
    pub const CCMPZ_R64_R64: u32 = 0x0FA9;
    pub const CCMPNZ_R64_R64: u32 = 0x0FAA;
    pub const CCMPBE_R64_R64: u32 = 0x0FAB;
    pub const CCMPNBE_R64_R64: u32 = 0x0FAC;
    pub const CCMPS_R64_R64: u32 = 0x0FAD;
    pub const CCMPNS_R64_R64: u32 = 0x0FAE;
    pub const CCMPT_R64_R64: u32 = 0x0FAF;
    pub const CCMPF_R64_R64: u32 = 0x0FB0;
    pub const CCMPL_R64_R64: u32 = 0x0FB1;
    pub const CCMPNL_R64_R64: u32 = 0x0FB2;
    pub const CCMPLE_R64_R64: u32 = 0x0FB3;
    pub const CCMPNLE_R64_R64: u32 = 0x0FB4;
    pub const CTESTO_R64_R64: u32 = 0x0FB5;
    pub const CTESTNO_R64_R64: u32 = 0x0FB6;
    pub const CTESTB_R64_R64: u32 = 0x0FB7;
    pub const CTESTNB_R64_R64: u32 = 0x0FB8;
    pub const CTESTZ_R64_R64: u32 = 0x0FB9;
    pub const CTESTNZ_R64_R64: u32 = 0x0FBA;
    pub const CTESTBE_R64_R64: u32 = 0x0FBB;
    pub const CTESTNBE_R64_R64: u32 = 0x0FBC;
    pub const CTESTS_R64_R64: u32 = 0x0FBD;
    pub const CTESTNS_R64_R64: u32 = 0x0FBE;
    pub const CTESTT_R64_R64: u32 = 0x0FBF;
    pub const CTESTF_R64_R64: u32 = 0x0FC0;
    pub const CTESTL_R64_R64: u32 = 0x0FC1;
    pub const CTESTNL_R64_R64: u32 = 0x0FC2;
    pub const CTESTLE_R64_R64: u32 = 0x0FC3;
    pub const CTESTNLE_R64_R64: u32 = 0x0FC4;
    pub const ADD_R64_R64_R64_NDD: u32 = 0x0FC5;
    pub const SUB_R64_R64_R64_NDD: u32 = 0x0FC6;
    pub const AND_R64_R64_R64_NDD: u32 = 0x0FC7;
    pub const OR_R64_R64_R64_NDD: u32 = 0x0FC8;
    pub const XOR_R64_R64_R64_NDD: u32 = 0x0FC9;
    pub const ADD_R32_R32_R32_NDD: u32 = 0x0FCA;
    pub const SUB_R32_R32_R32_NDD: u32 = 0x0FCB;
    pub const AND_R32_R32_R32_NDD: u32 = 0x0FCC;
    pub const OR_R32_R32_R32_NDD: u32 = 0x0FCD;
    pub const XOR_R32_R32_R32_NDD: u32 = 0x0FCE;
    pub const SHL_R64_R64_IMM8_NDD: u32 = 0x0FCF;
    pub const SHR_R64_R64_IMM8_NDD: u32 = 0x0FD0;
    pub const SAR_R64_R64_IMM8_NDD: u32 = 0x0FD1;
    pub const SHL_R32_R32_IMM8_NDD: u32 = 0x0FD2;
    pub const SHR_R32_R32_IMM8_NDD: u32 = 0x0FD3;
    pub const SAR_R32_R32_IMM8_NDD: u32 = 0x0FD4;
    pub const CFCMOVZ_R64_R64: u32 = 0x0FD5;
    pub const CFCMOVNZ_R64_R64: u32 = 0x0FD6;
    pub const CFCMOVB_R64_R64: u32 = 0x0FD7;
    pub const CFCMOVNB_R64_R64: u32 = 0x0FD8;
    pub const CFCMOVL_R64_R64: u32 = 0x0FD9;
    pub const CFCMOVNL_R64_R64: u32 = 0x0FDA;
    pub const CFCMOVLE_R64_R64: u32 = 0x0FDB;
    pub const CFCMOVNLE_R64_R64: u32 = 0x0FDC;
}

/// RFLAGS bit positions used by the corpus.
pub mod rflags {
    pub const CF_BIT: u8 = 0;
    pub const PF_BIT: u8 = 2;
    pub const AF_BIT: u8 = 4;
    pub const ZF_BIT: u8 = 6;
    pub const SF_BIT: u8 = 7;
    pub const DF_BIT: u8 = 10;
    pub const OF_BIT: u8 = 11;

    /// Mask with all corpus-computed flag bits cleared (preserves reserved/other bits).
    /// Flags the corpus recomputes on every flag-writing instruction:
    /// CF, PF, AF, ZF, SF, OF.
    pub const CORPUS_FLAG_MASK: u64 =
        !((1 << CF_BIT) | (1 << PF_BIT) | (1 << AF_BIT) | (1 << ZF_BIT) | (1 << SF_BIT) | (1 << OF_BIT));
}

/// Starting rule ID for corpus providers. Each provider gets a sequential ID.
pub const CORPUS_RULE_BASE: u64 = 0x1000;

pub const fn rule_id(offset: u64) -> SemanticRuleId {
    SemanticRuleId(CORPUS_RULE_BASE + offset)
}
