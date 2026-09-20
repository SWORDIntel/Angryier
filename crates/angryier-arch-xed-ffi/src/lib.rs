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
    pub use xed_sys::{
        XED_ICLASS_ADC, XED_ICLASS_ADD, XED_ICLASS_ADD_LOCK, XED_ICLASS_ADDSD, XED_ICLASS_AND, XED_ICLASS_AND_LOCK,
        XED_ICLASS_BSF, XED_ICLASS_BSR, XED_ICLASS_BSWAP, XED_ICLASS_BT, XED_ICLASS_BTC, XED_ICLASS_BTR,
        XED_ICLASS_BTS, XED_ICLASS_CALL_NEAR, XED_ICLASS_CBW, XED_ICLASS_CDQ, XED_ICLASS_CDQE, XED_ICLASS_CLC,
        XED_ICLASS_CMC, XED_ICLASS_CMOVB, XED_ICLASS_CMOVBE, XED_ICLASS_CMOVL, XED_ICLASS_CMOVLE, XED_ICLASS_CMOVNB,
        XED_ICLASS_CMOVNBE, XED_ICLASS_CMOVNL, XED_ICLASS_CMOVNLE, XED_ICLASS_CMOVNO, XED_ICLASS_CMOVNP,
        XED_ICLASS_CMOVNS, XED_ICLASS_CMOVNZ, XED_ICLASS_CMOVO, XED_ICLASS_CMOVP, XED_ICLASS_CMOVS, XED_ICLASS_CMOVZ,
        XED_ICLASS_CMP, XED_ICLASS_CMPXCHG, XED_ICLASS_CMPXCHG_LOCK, XED_ICLASS_CPUID, XED_ICLASS_CQO, XED_ICLASS_CWD,
        XED_ICLASS_CWDE, XED_ICLASS_DEC, XED_ICLASS_DIV, XED_ICLASS_DIVSD, XED_ICLASS_ENDBR32, XED_ICLASS_ENDBR64,
        XED_ICLASS_HLT, XED_ICLASS_IDIV, XED_ICLASS_IMUL, XED_ICLASS_INC, XED_ICLASS_JB, XED_ICLASS_JBE, XED_ICLASS_JL,
        XED_ICLASS_JLE, XED_ICLASS_JMP, XED_ICLASS_JNB, XED_ICLASS_JNBE, XED_ICLASS_JNL, XED_ICLASS_JNLE,
        XED_ICLASS_JNO, XED_ICLASS_JNP, XED_ICLASS_JNS, XED_ICLASS_JNZ, XED_ICLASS_JO, XED_ICLASS_JP, XED_ICLASS_JS,
        XED_ICLASS_JZ, XED_ICLASS_LEA, XED_ICLASS_LEAVE, XED_ICLASS_LODSB, XED_ICLASS_LODSD, XED_ICLASS_LODSQ,
        XED_ICLASS_LODSW, XED_ICLASS_LZCNT, XED_ICLASS_MOV, XED_ICLASS_MOVAPS, XED_ICLASS_MOVD, XED_ICLASS_MOVDQA,
        XED_ICLASS_MOVDQU, XED_ICLASS_MOVHPD, XED_ICLASS_MOVHPS, XED_ICLASS_MOVLPD, XED_ICLASS_MOVLPS,
        XED_ICLASS_MOVMSKPD, XED_ICLASS_MOVMSKPS, XED_ICLASS_MOVQ, XED_ICLASS_MOVSB, XED_ICLASS_MOVSD,
        XED_ICLASS_MOVSD_XMM, XED_ICLASS_MOVSQ, XED_ICLASS_MOVSS, XED_ICLASS_MOVSW, XED_ICLASS_MOVSX,
        XED_ICLASS_MOVSXD, XED_ICLASS_MOVUPS, XED_ICLASS_MOVZX, XED_ICLASS_MUL, XED_ICLASS_MULSD, XED_ICLASS_NEG,
        XED_ICLASS_NOP, XED_ICLASS_NOT, XED_ICLASS_OR, XED_ICLASS_OR_LOCK, XED_ICLASS_PABSB, XED_ICLASS_PABSD,
        XED_ICLASS_PACKSSWB, XED_ICLASS_PADDQ, XED_ICLASS_PAND, XED_ICLASS_PANDN, XED_ICLASS_PCMPEQB,
        XED_ICLASS_PCMPEQD, XED_ICLASS_PCMPEQQ, XED_ICLASS_PCMPEQW, XED_ICLASS_PCMPGTB, XED_ICLASS_PCMPGTD,
        XED_ICLASS_PCMPGTW, XED_ICLASS_PHADDW, XED_ICLASS_PMADDWD, XED_ICLASS_PMAXUB, XED_ICLASS_PMINUB,
        XED_ICLASS_PMOVMSKB, XED_ICLASS_PMULLW, XED_ICLASS_POP, XED_ICLASS_POPCNT, XED_ICLASS_POPF, XED_ICLASS_POPFQ,
        XED_ICLASS_POR, XED_ICLASS_PSADBW, XED_ICLASS_PSHUFB, XED_ICLASS_PSHUFD, XED_ICLASS_PSIGNB, XED_ICLASS_PSLLD,
        XED_ICLASS_PSRLD, XED_ICLASS_PSUBQ, XED_ICLASS_PUNPCKHBW, XED_ICLASS_PUNPCKHDQ, XED_ICLASS_PUNPCKHQDQ,
        XED_ICLASS_PUNPCKHWD, XED_ICLASS_PUNPCKLBW, XED_ICLASS_PUNPCKLDQ, XED_ICLASS_PUNPCKLQDQ, XED_ICLASS_PUNPCKLWD,
        XED_ICLASS_PUSH, XED_ICLASS_PUSHF, XED_ICLASS_PUSHFQ, XED_ICLASS_PXOR, XED_ICLASS_RCL, XED_ICLASS_RCR,
        XED_ICLASS_REP_MOVSB, XED_ICLASS_REP_MOVSD, XED_ICLASS_REP_MOVSQ, XED_ICLASS_REP_MOVSW, XED_ICLASS_REP_STOSB,
        XED_ICLASS_REP_STOSD, XED_ICLASS_REP_STOSQ, XED_ICLASS_REP_STOSW, XED_ICLASS_RET_NEAR, XED_ICLASS_ROL,
        XED_ICLASS_ROR, XED_ICLASS_SAR, XED_ICLASS_SBB, XED_ICLASS_SETB, XED_ICLASS_SETBE, XED_ICLASS_SETL,
        XED_ICLASS_SETLE, XED_ICLASS_SETNB, XED_ICLASS_SETNBE, XED_ICLASS_SETNL, XED_ICLASS_SETNLE, XED_ICLASS_SETNO,
        XED_ICLASS_SETNP, XED_ICLASS_SETNS, XED_ICLASS_SETNZ, XED_ICLASS_SETO, XED_ICLASS_SETP, XED_ICLASS_SETS,
        XED_ICLASS_SETZ, XED_ICLASS_SHL, XED_ICLASS_SHR, XED_ICLASS_STC, XED_ICLASS_STOSB, XED_ICLASS_STOSD,
        XED_ICLASS_STOSQ, XED_ICLASS_STOSW, XED_ICLASS_SUB, XED_ICLASS_SUB_LOCK, XED_ICLASS_SUBSD, XED_ICLASS_SYSCALL,
        XED_ICLASS_TEST, XED_ICLASS_TZCNT, XED_ICLASS_UCOMISD, XED_ICLASS_UD2, XED_ICLASS_VEXTRACTF128,
        XED_ICLASS_VEXTRACTI128, XED_ICLASS_VINSERTF128, XED_ICLASS_VINSERTI128, XED_ICLASS_VMOVAPS, XED_ICLASS_VMOVD,
        XED_ICLASS_VMOVDQA, XED_ICLASS_VMOVDQU, XED_ICLASS_VMOVQ, XED_ICLASS_VMOVUPS, XED_ICLASS_VPAND,
        XED_ICLASS_VPBROADCASTB, XED_ICLASS_VPBROADCASTQ, XED_ICLASS_VPCMPEQB, XED_ICLASS_VPINSRB, XED_ICLASS_VPINSRD,
        XED_ICLASS_VPINSRQ, XED_ICLASS_VPINSRW, XED_ICLASS_VPMOVMSKB, XED_ICLASS_VPOR, XED_ICLASS_VPXOR,
        XED_ICLASS_VXORPS, XED_ICLASS_VZEROUPPER, XED_ICLASS_XADD, XED_ICLASS_XCHG, XED_ICLASS_XOR,
        XED_ICLASS_XOR_LOCK,
    };
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
        self.inner.decode(address, bytes)
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
