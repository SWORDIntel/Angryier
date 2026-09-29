//! Native Intel XED decoder via FFI.
//!
//! This crate is the unsafe native bridge that links `libxed` (built from source
//! by the `xed-sys` crate) and translates raw XED decode output into Angryier's
//! value-only [`XedDecodedMetadata`]. The metadata is then validated and
//! normalized into [`DecodedInstruction`] by the safe
//! [`angryier_decode_xed`](::angryier_decode_xed) adapter.
//!
//! No raw `xed_sys` type crosses this crate's public API. The [`XedDecoder`]
//! type implements [`angriarch::Decoder`](::angryier_arch::Decoder) and returns
//! fully-normalized [`DecodedInstruction`] values.
//!
//! # Build requirements
//!
//! `xed-sys` builds Intel XED from source at compile time. You need:
//!
//! - Python 3.8 or later (to build XED).
//! - A C compiler.
//!
//! If the `bindgen` feature is enabled (it is by default when regenerating
//! bindings), `clang` is also required.

mod backend;
mod feature;
mod register;

pub use backend::NativeXedBackend;

/// XED instruction-class enumerants used by Intel 64 form-mapping layers.
///
/// These are re-exported from `xed-sys` so mapping code compiles against the
/// exact XED release this bridge links against. `form_id` values reported by
/// [`XedDecoder`] are raw XED instruction classes; translating them into
/// engine-owned semantic form ids is the integration layer's responsibility.
pub mod iclass {
    pub use xed_sys::XED_ICLASS_IRETD;
    pub use xed_sys::{
        XED_ICLASS_ADC, XED_ICLASS_ADD, XED_ICLASS_ADD_LOCK, XED_ICLASS_ADDSD, XED_ICLASS_ADDSS, XED_ICLASS_AND,
        XED_ICLASS_AND_LOCK, XED_ICLASS_ANDN, XED_ICLASS_BEXTR, XED_ICLASS_BLENDVPD, XED_ICLASS_BLENDVPS,
        XED_ICLASS_BLSI, XED_ICLASS_BLSMSK, XED_ICLASS_BLSR, XED_ICLASS_BSF, XED_ICLASS_BSR, XED_ICLASS_BSWAP,
        XED_ICLASS_BT, XED_ICLASS_BTC, XED_ICLASS_BTR, XED_ICLASS_BTS, XED_ICLASS_BZHI, XED_ICLASS_CALL_NEAR,
        XED_ICLASS_CBW, XED_ICLASS_CDQ, XED_ICLASS_CDQE, XED_ICLASS_CLC, XED_ICLASS_CLD, XED_ICLASS_CLFLUSH,
        XED_ICLASS_CLTS, XED_ICLASS_CMC, XED_ICLASS_CMOVB, XED_ICLASS_CMOVBE, XED_ICLASS_CMOVL, XED_ICLASS_CMOVLE,
        XED_ICLASS_CMOVNB, XED_ICLASS_CMOVNBE, XED_ICLASS_CMOVNL, XED_ICLASS_CMOVNLE, XED_ICLASS_CMOVNO,
        XED_ICLASS_CMOVNP, XED_ICLASS_CMOVNS, XED_ICLASS_CMOVNZ, XED_ICLASS_CMOVO, XED_ICLASS_CMOVP, XED_ICLASS_CMOVS,
        XED_ICLASS_CMOVZ, XED_ICLASS_CMP, XED_ICLASS_CMPSB, XED_ICLASS_CMPSD, XED_ICLASS_CMPSQ, XED_ICLASS_CMPSW,
        XED_ICLASS_CMPXCHG, XED_ICLASS_CMPXCHG_LOCK, XED_ICLASS_COMISD, XED_ICLASS_COMISS, XED_ICLASS_CPUID,
        XED_ICLASS_CQO, XED_ICLASS_CRC32, XED_ICLASS_CVTSD2SS, XED_ICLASS_CVTSS2SD, XED_ICLASS_CWD, XED_ICLASS_CWDE,
        XED_ICLASS_DEC, XED_ICLASS_DEC_LOCK, XED_ICLASS_DIV, XED_ICLASS_DIVSD, XED_ICLASS_DIVSS, XED_ICLASS_ENDBR32,
        XED_ICLASS_ENDBR64, XED_ICLASS_ENTER, XED_ICLASS_EXTRACTPS, XED_ICLASS_F2XM1, XED_ICLASS_FABS, XED_ICLASS_FADD,
        XED_ICLASS_FCHS, XED_ICLASS_FCMOVB, XED_ICLASS_FCMOVBE, XED_ICLASS_FCMOVE, XED_ICLASS_FCMOVNB,
        XED_ICLASS_FCMOVNBE, XED_ICLASS_FCMOVNE, XED_ICLASS_FCMOVNU, XED_ICLASS_FCMOVU, XED_ICLASS_FCOM,
        XED_ICLASS_FCOMI, XED_ICLASS_FCOMIP, XED_ICLASS_FCOMP, XED_ICLASS_FCOMPP, XED_ICLASS_FCOS, XED_ICLASS_FDECSTP,
        XED_ICLASS_FDIV, XED_ICLASS_FDIVR, XED_ICLASS_FFREE, XED_ICLASS_FIADD, XED_ICLASS_FICOM, XED_ICLASS_FICOMP,
        XED_ICLASS_FIDIV, XED_ICLASS_FIDIVR, XED_ICLASS_FILD, XED_ICLASS_FIMUL, XED_ICLASS_FINCSTP, XED_ICLASS_FIST,
        XED_ICLASS_FISTP, XED_ICLASS_FISUB, XED_ICLASS_FISUBR, XED_ICLASS_FLD, XED_ICLASS_FLD1, XED_ICLASS_FLDCW,
        XED_ICLASS_FLDL2E, XED_ICLASS_FLDL2T, XED_ICLASS_FLDLG2, XED_ICLASS_FLDLN2, XED_ICLASS_FLDPI, XED_ICLASS_FLDZ,
        XED_ICLASS_FMUL, XED_ICLASS_FNCLEX, XED_ICLASS_FNINIT, XED_ICLASS_FNOP, XED_ICLASS_FNSTCW, XED_ICLASS_FNSTSW,
        XED_ICLASS_FPATAN, XED_ICLASS_FPTAN, XED_ICLASS_FRNDINT, XED_ICLASS_FSCALE, XED_ICLASS_FSIN,
        XED_ICLASS_FSINCOS, XED_ICLASS_FSQRT, XED_ICLASS_FST, XED_ICLASS_FSTP, XED_ICLASS_FSTPNCE, XED_ICLASS_FSUB,
        XED_ICLASS_FSUBR, XED_ICLASS_FTST, XED_ICLASS_FUCOMI, XED_ICLASS_FUCOMIP, XED_ICLASS_FWAIT, XED_ICLASS_FXAM,
        XED_ICLASS_FXCH, XED_ICLASS_FYL2X, XED_ICLASS_FYL2XP1, XED_ICLASS_HLT, XED_ICLASS_IDIV, XED_ICLASS_IMUL,
        XED_ICLASS_IN, XED_ICLASS_INC, XED_ICLASS_INC_LOCK, XED_ICLASS_INSB, XED_ICLASS_INSD, XED_ICLASS_INSERTPS,
        XED_ICLASS_INSW, XED_ICLASS_INT, XED_ICLASS_INT1, XED_ICLASS_INT3, XED_ICLASS_INVD, XED_ICLASS_JB,
        XED_ICLASS_JBE, XED_ICLASS_JL, XED_ICLASS_JLE, XED_ICLASS_JMP, XED_ICLASS_JMP_FAR, XED_ICLASS_JNB,
        XED_ICLASS_JNBE, XED_ICLASS_JNL, XED_ICLASS_JNLE, XED_ICLASS_JNO, XED_ICLASS_JNP, XED_ICLASS_JNS,
        XED_ICLASS_JNZ, XED_ICLASS_JO, XED_ICLASS_JP, XED_ICLASS_JRCXZ, XED_ICLASS_JS, XED_ICLASS_JZ,
        XED_ICLASS_KANDNQ, XED_ICLASS_KANDNW, XED_ICLASS_KANDQ, XED_ICLASS_KANDW, XED_ICLASS_KNOTQ, XED_ICLASS_KNOTW,
        XED_ICLASS_KORQ, XED_ICLASS_KORW, XED_ICLASS_KXNORQ, XED_ICLASS_KXNORW, XED_ICLASS_KXORQ, XED_ICLASS_KXORW,
        XED_ICLASS_LAHF, XED_ICLASS_LEA, XED_ICLASS_LEAVE, XED_ICLASS_LFENCE, XED_ICLASS_LODSB, XED_ICLASS_LODSD,
        XED_ICLASS_LODSQ, XED_ICLASS_LODSW, XED_ICLASS_LOOP, XED_ICLASS_LOOPE, XED_ICLASS_LOOPNE, XED_ICLASS_LZCNT,
        XED_ICLASS_MAXSD, XED_ICLASS_MAXSS, XED_ICLASS_MFENCE, XED_ICLASS_MINSD, XED_ICLASS_MINSS, XED_ICLASS_MOV,
        XED_ICLASS_MOVAPS, XED_ICLASS_MOVBE, XED_ICLASS_MOVD, XED_ICLASS_MOVDQA, XED_ICLASS_MOVDQU, XED_ICLASS_MOVHLPS,
        XED_ICLASS_MOVHPD, XED_ICLASS_MOVHPS, XED_ICLASS_MOVLHPS, XED_ICLASS_MOVLPD, XED_ICLASS_MOVLPS,
        XED_ICLASS_MOVMSKPD, XED_ICLASS_MOVMSKPS, XED_ICLASS_MOVNTDQ, XED_ICLASS_MOVNTDQA, XED_ICLASS_MOVNTI,
        XED_ICLASS_MOVQ, XED_ICLASS_MOVSB, XED_ICLASS_MOVSD, XED_ICLASS_MOVSD_XMM, XED_ICLASS_MOVSQ, XED_ICLASS_MOVSS,
        XED_ICLASS_MOVSW, XED_ICLASS_MOVSX, XED_ICLASS_MOVSXD, XED_ICLASS_MOVUPS, XED_ICLASS_MOVZX, XED_ICLASS_MPSADBW,
        XED_ICLASS_MUL, XED_ICLASS_MULSD, XED_ICLASS_MULSS, XED_ICLASS_MULX, XED_ICLASS_NEG, XED_ICLASS_NOP,
        XED_ICLASS_NOT, XED_ICLASS_OR, XED_ICLASS_OR_LOCK, XED_ICLASS_OUT, XED_ICLASS_OUTSB, XED_ICLASS_OUTSD,
        XED_ICLASS_OUTSW, XED_ICLASS_PABSB, XED_ICLASS_PABSD, XED_ICLASS_PACKSSWB, XED_ICLASS_PACKUSWB,
        XED_ICLASS_PADDB, XED_ICLASS_PADDD, XED_ICLASS_PADDQ, XED_ICLASS_PADDSB, XED_ICLASS_PADDUSB, XED_ICLASS_PADDW,
        XED_ICLASS_PAND, XED_ICLASS_PANDN, XED_ICLASS_PAUSE, XED_ICLASS_PBLENDVB, XED_ICLASS_PCMPEQB,
        XED_ICLASS_PCMPEQD, XED_ICLASS_PCMPEQQ, XED_ICLASS_PCMPEQW, XED_ICLASS_PCMPGTB, XED_ICLASS_PCMPGTD,
        XED_ICLASS_PCMPGTQ, XED_ICLASS_PCMPGTW, XED_ICLASS_PEXTRD, XED_ICLASS_PEXTRQ, XED_ICLASS_PEXTRW,
        XED_ICLASS_PHADDW, XED_ICLASS_PINSRB, XED_ICLASS_PINSRD, XED_ICLASS_PINSRQ, XED_ICLASS_PMADDWD,
        XED_ICLASS_PMAXSD, XED_ICLASS_PMAXUB, XED_ICLASS_PMAXUD, XED_ICLASS_PMINSB, XED_ICLASS_PMINSD,
        XED_ICLASS_PMINUB, XED_ICLASS_PMINUD, XED_ICLASS_PMOVMSKB, XED_ICLASS_PMOVSXBD, XED_ICLASS_PMOVSXBQ,
        XED_ICLASS_PMOVSXBW, XED_ICLASS_PMOVSXDQ, XED_ICLASS_PMOVSXWD, XED_ICLASS_PMOVSXWQ, XED_ICLASS_PMOVZXBD,
        XED_ICLASS_PMOVZXBQ, XED_ICLASS_PMOVZXBW, XED_ICLASS_PMOVZXDQ, XED_ICLASS_PMOVZXWD, XED_ICLASS_PMOVZXWQ,
        XED_ICLASS_PMULLW, XED_ICLASS_POP, XED_ICLASS_POPCNT, XED_ICLASS_POPF, XED_ICLASS_POPFQ, XED_ICLASS_POR,
        XED_ICLASS_PREFETCHNTA, XED_ICLASS_PREFETCHT0, XED_ICLASS_PREFETCHT1, XED_ICLASS_PREFETCHT2, XED_ICLASS_PSADBW,
        XED_ICLASS_PSHUFB, XED_ICLASS_PSHUFD, XED_ICLASS_PSIGNB, XED_ICLASS_PSLLD, XED_ICLASS_PSRLD, XED_ICLASS_PSUBD,
        XED_ICLASS_PSUBQ, XED_ICLASS_PTEST, XED_ICLASS_PUNPCKHBW, XED_ICLASS_PUNPCKHDQ, XED_ICLASS_PUNPCKHQDQ,
        XED_ICLASS_PUNPCKHWD, XED_ICLASS_PUNPCKLBW, XED_ICLASS_PUNPCKLDQ, XED_ICLASS_PUNPCKLQDQ, XED_ICLASS_PUNPCKLWD,
        XED_ICLASS_PUSH, XED_ICLASS_PUSHF, XED_ICLASS_PUSHFQ, XED_ICLASS_PXOR, XED_ICLASS_RCL, XED_ICLASS_RCR,
        XED_ICLASS_RDMSR, XED_ICLASS_RDTSC, XED_ICLASS_RDTSCP, XED_ICLASS_REP_INSB, XED_ICLASS_REP_INSD,
        XED_ICLASS_REP_INSW, XED_ICLASS_REP_MOVSB, XED_ICLASS_REP_MOVSD, XED_ICLASS_REP_MOVSQ, XED_ICLASS_REP_MOVSW,
        XED_ICLASS_REP_OUTSB, XED_ICLASS_REP_OUTSD, XED_ICLASS_REP_OUTSW, XED_ICLASS_REP_STOSB, XED_ICLASS_REP_STOSD,
        XED_ICLASS_REP_STOSQ, XED_ICLASS_REP_STOSW, XED_ICLASS_REPE_CMPSB, XED_ICLASS_REPE_CMPSD,
        XED_ICLASS_REPE_CMPSQ, XED_ICLASS_REPE_CMPSW, XED_ICLASS_REPE_SCASB, XED_ICLASS_REPE_SCASD,
        XED_ICLASS_REPE_SCASQ, XED_ICLASS_REPE_SCASW, XED_ICLASS_REPNE_CMPSB, XED_ICLASS_REPNE_CMPSD,
        XED_ICLASS_REPNE_CMPSQ, XED_ICLASS_REPNE_CMPSW, XED_ICLASS_REPNE_SCASB, XED_ICLASS_REPNE_SCASD,
        XED_ICLASS_REPNE_SCASQ, XED_ICLASS_REPNE_SCASW, XED_ICLASS_RET_FAR, XED_ICLASS_RET_NEAR, XED_ICLASS_ROL,
        XED_ICLASS_ROR, XED_ICLASS_RORX, XED_ICLASS_ROUNDPD, XED_ICLASS_ROUNDPS, XED_ICLASS_ROUNDSD,
        XED_ICLASS_ROUNDSS, XED_ICLASS_SAHF, XED_ICLASS_SAR, XED_ICLASS_SARX, XED_ICLASS_SBB, XED_ICLASS_SCASB,
        XED_ICLASS_SCASD, XED_ICLASS_SCASQ, XED_ICLASS_SCASW, XED_ICLASS_SETB, XED_ICLASS_SETBE, XED_ICLASS_SETL,
        XED_ICLASS_SETLE, XED_ICLASS_SETNB, XED_ICLASS_SETNBE, XED_ICLASS_SETNL, XED_ICLASS_SETNLE, XED_ICLASS_SETNO,
        XED_ICLASS_SETNP, XED_ICLASS_SETNS, XED_ICLASS_SETNZ, XED_ICLASS_SETO, XED_ICLASS_SETP, XED_ICLASS_SETS,
        XED_ICLASS_SETZ, XED_ICLASS_SFENCE, XED_ICLASS_SHL, XED_ICLASS_SHLX, XED_ICLASS_SHR, XED_ICLASS_SHRX,
        XED_ICLASS_SQRTSD, XED_ICLASS_SQRTSS, XED_ICLASS_STC, XED_ICLASS_STD, XED_ICLASS_STOSB, XED_ICLASS_STOSD,
        XED_ICLASS_STOSQ, XED_ICLASS_STOSW, XED_ICLASS_SUB, XED_ICLASS_SUB_LOCK, XED_ICLASS_SUBSD, XED_ICLASS_SUBSS,
        XED_ICLASS_SYSCALL, XED_ICLASS_TEST, XED_ICLASS_TZCNT, XED_ICLASS_UCOMISD, XED_ICLASS_UCOMISS, XED_ICLASS_UD2,
        XED_ICLASS_VADDPD, XED_ICLASS_VADDPS, XED_ICLASS_VADDSD, XED_ICLASS_VADDSS, XED_ICLASS_VANDNPD,
        XED_ICLASS_VANDNPS, XED_ICLASS_VANDPD, XED_ICLASS_VANDPS, XED_ICLASS_VBLENDPD, XED_ICLASS_VBLENDPS,
        XED_ICLASS_VBLENDVPD, XED_ICLASS_VBLENDVPS, XED_ICLASS_VCVTSD2SS, XED_ICLASS_VCVTSS2SD, XED_ICLASS_VDIVPD,
        XED_ICLASS_VDIVPS, XED_ICLASS_VDIVSD, XED_ICLASS_VDIVSS, XED_ICLASS_VEXTRACTF128, XED_ICLASS_VEXTRACTI128,
        XED_ICLASS_VINSERTF128, XED_ICLASS_VINSERTI128, XED_ICLASS_VMAXPD, XED_ICLASS_VMAXPS, XED_ICLASS_VMAXSD,
        XED_ICLASS_VMAXSS, XED_ICLASS_VMINPD, XED_ICLASS_VMINPS, XED_ICLASS_VMINSD, XED_ICLASS_VMINSS,
        XED_ICLASS_VMOVAPS, XED_ICLASS_VMOVD, XED_ICLASS_VMOVDQA, XED_ICLASS_VMOVDQU, XED_ICLASS_VMOVQ,
        XED_ICLASS_VMOVUPS, XED_ICLASS_VMULPD, XED_ICLASS_VMULPS, XED_ICLASS_VMULSD, XED_ICLASS_VMULSS,
        XED_ICLASS_VORPD, XED_ICLASS_VORPS, XED_ICLASS_VPABSB, XED_ICLASS_VPABSD, XED_ICLASS_VPABSW,
        XED_ICLASS_VPACKSSDW, XED_ICLASS_VPACKSSWB, XED_ICLASS_VPACKUSDW, XED_ICLASS_VPACKUSWB, XED_ICLASS_VPADDB,
        XED_ICLASS_VPADDD, XED_ICLASS_VPADDQ, XED_ICLASS_VPADDUSB, XED_ICLASS_VPADDUSW, XED_ICLASS_VPADDW,
        XED_ICLASS_VPAND, XED_ICLASS_VPAVGB, XED_ICLASS_VPAVGW, XED_ICLASS_VPBLENDD, XED_ICLASS_VPBROADCASTB,
        XED_ICLASS_VPBROADCASTD, XED_ICLASS_VPBROADCASTQ, XED_ICLASS_VPBROADCASTW, XED_ICLASS_VPCMPEQB,
        XED_ICLASS_VPCMPEQD, XED_ICLASS_VPCMPEQQ, XED_ICLASS_VPCMPEQW, XED_ICLASS_VPCMPGTB, XED_ICLASS_VPCMPGTD,
        XED_ICLASS_VPCMPGTQ, XED_ICLASS_VPCMPGTW, XED_ICLASS_VPDPBUSD, XED_ICLASS_VPDPBUSDS, XED_ICLASS_VPDPWSSD,
        XED_ICLASS_VPDPWSSDS, XED_ICLASS_VPERM2F128, XED_ICLASS_VPERM2I128, XED_ICLASS_VPERMD, XED_ICLASS_VPERMILPD,
        XED_ICLASS_VPERMILPS, XED_ICLASS_VPERMPD, XED_ICLASS_VPERMPS, XED_ICLASS_VPERMQ, XED_ICLASS_VPINSRB,
        XED_ICLASS_VPINSRD, XED_ICLASS_VPINSRQ, XED_ICLASS_VPINSRW, XED_ICLASS_VPMADDWD, XED_ICLASS_VPMAXSB,
        XED_ICLASS_VPMAXSD, XED_ICLASS_VPMAXSW, XED_ICLASS_VPMAXUB, XED_ICLASS_VPMAXUD, XED_ICLASS_VPMAXUW,
        XED_ICLASS_VPMINSB, XED_ICLASS_VPMINSD, XED_ICLASS_VPMINSW, XED_ICLASS_VPMINUB, XED_ICLASS_VPMINUD,
        XED_ICLASS_VPMINUW, XED_ICLASS_VPMOVMSKB, XED_ICLASS_VPMULHUW, XED_ICLASS_VPMULHW, XED_ICLASS_VPMULLD,
        XED_ICLASS_VPMULLW, XED_ICLASS_VPOR, XED_ICLASS_VPSHUFB, XED_ICLASS_VPSHUFD, XED_ICLASS_VPSIGNB,
        XED_ICLASS_VPSIGND, XED_ICLASS_VPSIGNW, XED_ICLASS_VPSLLD, XED_ICLASS_VPSLLQ, XED_ICLASS_VPSLLVD,
        XED_ICLASS_VPSLLVQ, XED_ICLASS_VPSLLW, XED_ICLASS_VPSRAD, XED_ICLASS_VPSRAVD, XED_ICLASS_VPSRAW,
        XED_ICLASS_VPSRLD, XED_ICLASS_VPSRLQ, XED_ICLASS_VPSRLVD, XED_ICLASS_VPSRLVQ, XED_ICLASS_VPSRLW,
        XED_ICLASS_VPSUBB, XED_ICLASS_VPSUBD, XED_ICLASS_VPSUBQ, XED_ICLASS_VPSUBUSB, XED_ICLASS_VPSUBUSW,
        XED_ICLASS_VPSUBW, XED_ICLASS_VPUNPCKHBW, XED_ICLASS_VPUNPCKHDQ, XED_ICLASS_VPUNPCKHQDQ, XED_ICLASS_VPUNPCKHWD,
        XED_ICLASS_VPUNPCKLBW, XED_ICLASS_VPUNPCKLDQ, XED_ICLASS_VPUNPCKLQDQ, XED_ICLASS_VPUNPCKLWD, XED_ICLASS_VPXOR,
        XED_ICLASS_VSHUFPD, XED_ICLASS_VSHUFPS, XED_ICLASS_VSQRTPD, XED_ICLASS_VSQRTPS, XED_ICLASS_VSQRTSD,
        XED_ICLASS_VSQRTSS, XED_ICLASS_VSUBPD, XED_ICLASS_VSUBPS, XED_ICLASS_VSUBSD, XED_ICLASS_VSUBSS,
        XED_ICLASS_VUNPCKHPD, XED_ICLASS_VUNPCKHPS, XED_ICLASS_VUNPCKLPD, XED_ICLASS_VUNPCKLPS, XED_ICLASS_VXORPD,
        XED_ICLASS_VXORPS, XED_ICLASS_VZEROUPPER, XED_ICLASS_WBINVD, XED_ICLASS_WRMSR, XED_ICLASS_XADD,
        XED_ICLASS_XADD_LOCK, XED_ICLASS_XCHG, XED_ICLASS_XGETBV, XED_ICLASS_XOR, XED_ICLASS_XOR_LOCK,
        XED_ICLASS_XORPD, XED_ICLASS_XORPS,
    };
    pub use xed_sys::{XED_ICLASS_MOV_CR, XED_ICLASS_MOV_DR};
}

use angryier_arch::{DecodedInstruction, Decoder};
use angryier_arch_intel64::{FeatureSet, Intel64ProfileKind, Intel64TargetProfile, IntelFeature};
use angryier_decode_xed::{BoundXedDecoder, XedAdapterError, XedDecodeConfig, XedDecoderAdapter, XedMachineMode};
use angryier_types::{Address, TargetProfileId};

/// All Intel feature families, used for the default permissive target profile.
const ALL_INTEL_FEATURES: [IntelFeature; 18] = [
    IntelFeature::Sse,
    IntelFeature::Sse2,
    IntelFeature::Sse3,
    IntelFeature::Ssse3,
    IntelFeature::Sse41,
    IntelFeature::Sse42,
    IntelFeature::AesNi,
    IntelFeature::Sha,
    IntelFeature::Bmi1,
    IntelFeature::Bmi2,
    IntelFeature::Avx,
    IntelFeature::Avx2,
    IntelFeature::Avx512,
    IntelFeature::AvxVnni,
    IntelFeature::Avx10,
    IntelFeature::Amx,
    IntelFeature::Cet,
    IntelFeature::Apx,
];

/// A native Intel XED decoder.
///
/// Wraps the safe [`BoundXedDecoder`] with the [`NativeXedBackend`] and a
/// permissive Intel 64 target profile (all feature families enabled) so that
/// any valid x86-64 instruction decodes without a target-profile violation.
///
/// Implements [`Decoder`] for single-instruction decoding and provides
/// [`decode_batch`](Self::decode_batch) for linear sweep decoding.
#[derive(Debug)]
pub struct XedDecoder {
    inner: BoundXedDecoder<NativeXedBackend>,
}

impl XedDecoder {
    /// Creates a new native XED decoder with a permissive Intel 64 target
    /// profile (all feature families enabled).
    pub fn new() -> Self {
        Self::with_profile_id(TargetProfileId(1))
    }

    /// Creates a new native XED decoder with a specific target profile id and
    /// all feature families enabled.
    pub fn with_profile_id(profile_id: TargetProfileId) -> Self {
        let config = XedDecodeConfig {
            mode: XedMachineMode::Intel64,
            profile: Intel64TargetProfile {
                id: profile_id,
                kind: Intel64ProfileKind::Custom,
                features: FeatureSet {
                    features: ALL_INTEL_FEATURES.to_vec(),
                    xcr0: 0,
                },
            },
        };
        Self {
            inner: BoundXedDecoder {
                adapter: XedDecoderAdapter { config },
                backend: NativeXedBackend,
            },
        }
    }

    /// Decodes a single instruction from the given byte slice.
    ///
    /// This is the primary decode entry point. It takes the raw instruction
    /// bytes and the instruction's address and returns a fully-normalized
    /// [`DecodedInstruction`].
    pub fn decode(&self, address: Address, bytes: &[u8]) -> Result<DecodedInstruction, XedAdapterError> {
        Decoder::decode(self, address, bytes)
    }

    /// Decodes a sequence of bytes into multiple instructions via linear sweep.
    ///
    /// Starting at `start_address`, each instruction is decoded and the sweep
    /// advances by the decoded instruction length. Decoding stops when the
    /// input is exhausted. If a decode error is encountered, it is returned
    /// immediately (short-circuiting the sweep).
    pub fn decode_batch(
        &self,
        bytes: &[u8],
        start_address: Address,
    ) -> Result<Vec<DecodedInstruction>, XedAdapterError> {
        let mut instructions = Vec::new();
        let mut offset = 0usize;
        let mut address = start_address;

        while offset < bytes.len() {
            let decoded = self.decode(address, &bytes[offset..])?;
            let length = decoded.length as usize;
            instructions.push(decoded);
            address = address.wrapping_add(length as u64);
            offset += length;
        }

        Ok(instructions)
    }
}

impl Default for XedDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder for XedDecoder {
    type Error = XedAdapterError;

    fn decode(&self, address: Address, bytes: &[u8]) -> Result<DecodedInstruction, Self::Error> {
        let mut decoded = self.inner.decode(address, bytes)?;
        append_system_register_operand(&mut decoded, bytes);
        normalize_push16_stack_operand(&mut decoded);
        Ok(decoded)
    }
}

/// Retain the encoded CR/DR selector, whose XED register class is outside
/// Angryier's architectural register file, as a synthetic immediate operand.
fn append_system_register_operand(decoded: &mut DecodedInstruction, bytes: &[u8]) {
    if !matches!(decoded.form_id, xed_sys::XED_ICLASS_MOV_CR | xed_sys::XED_ICLASS_MOV_DR) {
        return;
    }
    let Some(opcode_pos) = bytes
        .windows(2)
        .position(|window| window[0] == 0x0f && matches!(window[1], 0x20..=0x23))
    else {
        return;
    };
    let Some(&modrm) = bytes.get(opcode_pos + 2) else {
        return;
    };
    let rex_r = bytes[..opcode_pos]
        .iter()
        .rev()
        .find(|byte| (0x40..=0x4f).contains(*byte))
        .map_or(0, |rex| (rex >> 2) & 1);
    let selector = u64::from(((modrm >> 3) & 7) | (rex_r << 3));
    decoded.operands.push(angryier_arch::Operand {
        index: 1,
        width_bits: 4,
        access: angryier_arch::AccessKind::Read,
        visibility: angryier_arch::OperandVisibility::Explicit,
        kind: angryier_arch::OperandKind::Immediate(angryier_arch::ImmediateOperand {
            value: selector,
            signed: false,
        }),
    });
}

/// XED describes every suppressed PUSH stack slot relative to the old RSP
/// with an eight-byte displacement, even for the operand-size-overridden
/// 16-bit encoding. Normalize that address to the architectural two-byte
/// decrement so semantic operand writes land at the post-push RSP.
fn normalize_push16_stack_operand(decoded: &mut DecodedInstruction) {
    if decoded.form_id != xed_sys::XED_ICLASS_PUSH
        || !decoded
            .operands
            .iter()
            .any(|operand| operand.visibility == angryier_arch::OperandVisibility::Explicit && operand.width_bits == 16)
    {
        return;
    }
    for operand in &mut decoded.operands {
        if operand.visibility == angryier_arch::OperandVisibility::Suppressed
            && operand.width_bits == 16
            && let angryier_arch::OperandKind::Memory(memory) = &mut operand.kind
        {
            memory.displacement = -2;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_arch::{AccessKind, OperandKind, OperandVisibility};
    use angryier_arch_intel64::register_id::GPR_BASE;

    // XED iclass enumerant values (from xed-sys bindings).
    const ICLASS_MOV: u32 = 499;
    const ICLASS_ADD: u32 = 10;
    const ICLASS_NOP: u32 = 554;
    const ICLASS_RET_NEAR: u32 = 822;
    const ICLASS_PUSH: u32 = 749;
    const ICLASS_POP: u32 = 689;

    /// Decodes bytes and asserts the length and iclass (form_id).
    fn decode_checked(
        decoder: &XedDecoder,
        bytes: &[u8],
        expected_len: u8,
        expected_form_id: u32,
    ) -> Result<DecodedInstruction, XedAdapterError> {
        let decoded = decoder.decode(0x4000, bytes)?;
        assert_eq!(decoded.length, expected_len, "wrong length for {bytes:02x?}");
        assert_eq!(
            decoded.form_id, expected_form_id,
            "wrong form_id (iclass) for {bytes:02x?}"
        );
        Ok(decoded)
    }

    /// Extracts a register view from an operand, asserting it is a register.
    fn as_register(operand: &angryier_arch::Operand) -> &angryier_arch::RegisterView {
        assert!(
            matches!(operand.kind, OperandKind::Register(_)),
            "operand {operand:?} should be a register"
        );
        if let OperandKind::Register(reg) = &operand.kind {
            reg
        } else {
            unreachable!()
        }
    }

    /// Extracts a memory operand, asserting the operand is a memory operand.
    fn as_memory(operand: &angryier_arch::Operand) -> &angryier_arch::MemoryOperand {
        assert!(
            matches!(operand.kind, OperandKind::Memory(_)),
            "operand {operand:?} should be memory"
        );
        if let OperandKind::Memory(mem) = &operand.kind {
            mem
        } else {
            unreachable!()
        }
    }

    #[test]
    fn decode_mov_rbp_rsp() -> Result<(), XedAdapterError> {
        let decoder = XedDecoder::new();
        let decoded = decode_checked(&decoder, &[0x48, 0x89, 0xe5], 3, ICLASS_MOV)?;

        // Two register operands: RBP (write), RSP (read).
        assert_eq!(decoded.operands.len(), 2, "MOV RBP,RSP should have 2 operands");

        let op0 = &decoded.operands[0];
        assert_eq!(op0.access, AccessKind::Write);
        assert_eq!(op0.visibility, OperandVisibility::Explicit);
        let reg0 = as_register(op0);
        assert_eq!(reg0.parent.0, GPR_BASE + 5, "operand 0 should be RBP parent");
        assert_eq!(reg0.width_bits, 64);

        let op1 = &decoded.operands[1];
        assert_eq!(op1.access, AccessKind::Read);
        let reg1 = as_register(op1);
        assert_eq!(reg1.parent.0, GPR_BASE + 4, "operand 1 should be RSP parent");
        assert_eq!(reg1.width_bits, 64);
        Ok(())
    }

    #[test]
    fn decode_mov_rcx_rax() -> Result<(), XedAdapterError> {
        let decoder = XedDecoder::new();
        let decoded = decode_checked(&decoder, &[0x48, 0x89, 0xc1], 3, ICLASS_MOV)?;

        assert_eq!(decoded.operands.len(), 2);

        let op0 = &decoded.operands[0];
        assert_eq!(op0.access, AccessKind::Write);
        let reg0 = as_register(op0);
        assert_eq!(reg0.parent.0, GPR_BASE + 1, "operand 0 should be RCX parent");

        let op1 = &decoded.operands[1];
        assert_eq!(op1.access, AccessKind::Read);
        let reg1 = as_register(op1);
        assert_eq!(reg1.parent.0, GPR_BASE, "operand 1 should be RAX parent");
        Ok(())
    }

    #[test]
    fn decode_add_rax_5() -> Result<(), XedAdapterError> {
        let decoder = XedDecoder::new();
        let decoded = decode_checked(&decoder, &[0x48, 0x83, 0xc0, 0x05], 4, ICLASS_ADD)?;

        // XED reports REG0 (RAX, read-write), IMM0 (5, read), and a suppressed
        // RFLAGS operand. The RFLAGS operand is suppressed but valid.
        let has_rax = decoded.operands.iter().any(|op| {
            matches!(&op.kind, OperandKind::Register(reg) if reg.parent.0 == GPR_BASE)
                && op.access == AccessKind::ReadWrite
        });
        assert!(has_rax, "ADD RAX,5 should have a read-write RAX operand");

        let imm = decoded
            .operands
            .iter()
            .find(|op| matches!(&op.kind, OperandKind::Immediate(_)));
        assert!(imm.is_some(), "ADD RAX,5 should have an immediate operand");
        if let Some(OperandKind::Immediate(immediate)) = imm.map(|op| &op.kind) {
            assert_eq!(immediate.value, 5);
            assert!(immediate.signed);
        }
        Ok(())
    }

    #[test]
    fn decode_nop() -> Result<(), XedAdapterError> {
        let decoder = XedDecoder::new();
        let decoded = decode_checked(&decoder, &[0x90], 1, ICLASS_NOP)?;
        assert!(decoded.operands.is_empty(), "NOP should have no operands");
        Ok(())
    }

    #[test]
    fn decode_ret() -> Result<(), XedAdapterError> {
        let decoder = XedDecoder::new();
        let decoded = decode_checked(&decoder, &[0xc3], 1, ICLASS_RET_NEAR)?;
        // RET has a memory read operand (stack pop) and a suppressed RIP write.
        let has_mem = decoded
            .operands
            .iter()
            .any(|op| matches!(&op.kind, OperandKind::Memory(_)));
        assert!(has_mem, "RET should have a memory operand");
        Ok(())
    }

    #[test]
    fn decode_push_rbp() -> Result<(), XedAdapterError> {
        let decoder = XedDecoder::new();
        let decoded = decode_checked(&decoder, &[0x55], 1, ICLASS_PUSH)?;

        // PUSH has an explicit RBP (read) and a memory write operand.
        let has_rbp = decoded.operands.iter().any(|op| {
            matches!(&op.kind, OperandKind::Register(reg) if reg.parent.0 == GPR_BASE + 5)
                && op.access == AccessKind::Read
        });
        assert!(has_rbp, "PUSH RBP should have a read RBP operand");

        let has_mem_write = decoded
            .operands
            .iter()
            .any(|op| matches!(&op.kind, OperandKind::Memory(_)) && op.access == AccessKind::Write);
        assert!(has_mem_write, "PUSH RBP should have a memory write operand");
        Ok(())
    }

    #[test]
    fn decode_pop_rbp() -> Result<(), XedAdapterError> {
        let decoder = XedDecoder::new();
        let decoded = decode_checked(&decoder, &[0x5d], 1, ICLASS_POP)?;

        // POP has an explicit RBP (write) and a memory read operand.
        let has_rbp_write = decoded.operands.iter().any(|op| {
            matches!(&op.kind, OperandKind::Register(reg) if reg.parent.0 == GPR_BASE + 5)
                && op.access == AccessKind::Write
        });
        assert!(has_rbp_write, "POP RBP should have a write RBP operand");

        let has_mem_read = decoded
            .operands
            .iter()
            .any(|op| matches!(&op.kind, OperandKind::Memory(_)) && op.access == AccessKind::Read);
        assert!(has_mem_read, "POP RBP should have a memory read operand");
        Ok(())
    }

    #[test]
    fn decode_mov_rax_mem_displacement() -> Result<(), XedAdapterError> {
        let decoder = XedDecoder::new();
        let bytes = [0x48, 0x8b, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00];
        let decoded = decode_checked(&decoder, &bytes, 8, ICLASS_MOV)?;

        // Two operands: RAX (write) and a memory operand with displacement 0x28.
        assert_eq!(decoded.operands.len(), 2, "MOV RAX,[0x28] should have 2 operands");

        let mem_op = decoded
            .operands
            .iter()
            .find(|op| matches!(&op.kind, OperandKind::Memory(_)));
        assert!(mem_op.is_some(), "MOV RAX,[0x28] should have a memory operand");
        if let Some(op) = mem_op {
            let memory = as_memory(op);
            assert_eq!(memory.displacement, 0x28);
            assert_eq!(memory.displacement_width_bits, 32);
            assert_eq!(memory.address_width_bits, 64);
            assert!(memory.base.is_none(), "no base register for [disp32]");
            assert!(memory.index.is_none(), "no index register for [disp32]");
            assert_eq!(memory.scale, 1);
        }
        Ok(())
    }

    #[test]
    fn decode_batch_linear_sweep() -> Result<(), XedAdapterError> {
        let decoder = XedDecoder::new();
        // PUSH RBP ; MOV RBP,RSP ; NOP ; RET
        let bytes: &[u8] = &[0x55, 0x48, 0x89, 0xe5, 0x90, 0xc3];
        let instructions = decoder.decode_batch(bytes, 0x1000)?;

        assert_eq!(instructions.len(), 4);
        assert_eq!(instructions[0].length, 1);
        assert_eq!(instructions[0].form_id, ICLASS_PUSH);
        assert_eq!(instructions[1].length, 3);
        assert_eq!(instructions[1].form_id, ICLASS_MOV);
        assert_eq!(instructions[2].length, 1);
        assert_eq!(instructions[2].form_id, ICLASS_NOP);
        assert_eq!(instructions[3].length, 1);
        assert_eq!(instructions[3].form_id, ICLASS_RET_NEAR);

        // Addresses advance by instruction length.
        assert_eq!(instructions[0].address, 0x1000);
        assert_eq!(instructions[1].address, 0x1001);
        assert_eq!(instructions[2].address, 0x1004);
        assert_eq!(instructions[3].address, 0x1005);
        Ok(())
    }

    #[test]
    fn decode_empty_input_errors() {
        let decoder = XedDecoder::new();
        let result = decoder.decode(0x4000, &[]);
        assert_eq!(result, Err(XedAdapterError::EmptyInput));
    }

    #[test]
    fn decode_invalid_bytes_errors() {
        let decoder = XedDecoder::new();
        // 0x06 is PUSH ES, invalid in 64-bit mode.
        let result = decoder.decode(0x4000, &[0x06]);
        assert_eq!(result, Err(XedAdapterError::DecodeFailed));
    }
}
