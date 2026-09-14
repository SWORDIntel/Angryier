#![forbid(unsafe_code)]

//! Handwritten Intel 64 semantic corpus (Phase 4).
//!
//! This crate contains a deliberately small but structurally representative
//! set of Intel 64 instruction semantics. The goal is to exercise the rich
//! semantic IR, sealing, lowering, and concrete interpreter contracts before
//! the semantic generator amplifies design mistakes.
//!
//! See `docs/status/implementation-plan.md` Phase 4 for the exit gate.

mod providers;
mod providers_ext;
mod registry;

pub use providers::*;
pub use providers_ext::*;
pub use registry::Intel64CorpusRegistry;

use angryier_types::SemanticRuleId;

/// Stable form identifiers for the handwritten corpus.
///
/// These are Angryier-internal IDs. When native XED is integrated, the XED
/// adapter will map XED iform enumerations to these values. Until then,
/// synthetic decode objects use these IDs directly.
pub mod forms {
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
}

/// RFLAGS bit positions used by the corpus.
pub mod rflags {
    pub const CF_BIT: u8 = 0;
    pub const PF_BIT: u8 = 2;
    pub const AF_BIT: u8 = 4;
    pub const ZF_BIT: u8 = 6;
    pub const SF_BIT: u8 = 7;
    pub const OF_BIT: u8 = 11;

    /// Mask with all corpus-computed flag bits cleared (preserves reserved/other bits).
    pub const CORPUS_FLAG_MASK: u64 = !((1 << CF_BIT) | (1 << ZF_BIT) | (1 << SF_BIT) | (1 << OF_BIT));
}

/// Starting rule ID for corpus providers. Each provider gets a sequential ID.
pub const CORPUS_RULE_BASE: u64 = 0x1000;

pub const fn rule_id(offset: u64) -> SemanticRuleId {
    SemanticRuleId(CORPUS_RULE_BASE + offset)
}
