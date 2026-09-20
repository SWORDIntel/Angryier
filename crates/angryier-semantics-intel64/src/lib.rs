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
    pub const VPSHUFD_YMM_YMM_IMM8: u32 = 0x022B;
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
