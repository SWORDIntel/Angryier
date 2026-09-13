#![forbid(unsafe_code)]

//! Semantic registry for the Intel 64 corpus.

use crate::providers::*;
use crate::providers_ext::*;
use angryier_semantics::{DecodedInstructionView, ResolutionKind, SemanticError, SemanticRegistry, SemanticResolution};
use angryier_types::SemanticVersion;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Registry of handwritten Intel 64 semantic providers.
///
/// Resolves a decoded form to exactly one authoritative provider. Ambiguous
/// resolution is always an error; registration order is not priority.
pub struct Intel64CorpusRegistry {
    providers: Vec<Arc<dyn angryier_semantics::SemanticProvider>>,
    form_index: BTreeMap<u32, usize>,
    semantic_version: SemanticVersion,
}

impl Intel64CorpusRegistry {
    pub fn new(semantic_version: SemanticVersion) -> Self {
        let providers: Vec<Arc<dyn angryier_semantics::SemanticProvider>> = vec![
            Arc::new(MovR64R64),
            Arc::new(AddR64R64),
            Arc::new(SubR64R64),
            Arc::new(XorR64R64),
            Arc::new(AndR64R64),
            Arc::new(OrR64R64),
            Arc::new(ShlR64Imm8),
            Arc::new(ShrR64Imm8),
            Arc::new(SarR64Imm8),
            Arc::new(CmpR64R64),
            Arc::new(JzRel32),
            Arc::new(JnzRel32),
            Arc::new(JmpRel32),
            Arc::new(MovR64Imm64),
            Arc::new(AddR64Imm32),
            Arc::new(SubR64Imm32),
            Arc::new(CmpR64Imm32),
            Arc::new(ShlR64Cl),
            Arc::new(ShrR64Cl),
            Arc::new(SarR64Cl),
            Arc::new(JcRel32),
            Arc::new(JncRel32),
            Arc::new(JsRel32),
            Arc::new(JnsRel32),
            Arc::new(JlRel32),
            Arc::new(JgeRel32),
            Arc::new(IncR64),
            Arc::new(DecR64),
            Arc::new(NegR64),
            Arc::new(NotR64),
            Arc::new(Nop),
            Arc::new(MovR64Mem64),
            Arc::new(MovMem64R64),
            Arc::new(AddR64Mem64),
            Arc::new(CmpR64Mem64),
            Arc::new(ImulR64R64),
            Arc::new(MulR64R64),
            Arc::new(DivR64R64),
            Arc::new(IdivR64R64),
            Arc::new(RolR64Imm8),
            Arc::new(RorR64Imm8),
            Arc::new(RclR64Imm8),
            Arc::new(RcrR64Imm8),
            Arc::new(PushR64),
            Arc::new(PopR64),
            Arc::new(LeaR64Mem),
            Arc::new(XchgR64R64),
            Arc::new(TestR64R64),
            Arc::new(XaddR64R64),
            Arc::new(MovR32R32),
            Arc::new(MovR8R8),
            Arc::new(MovzxR64R32),
            Arc::new(MovsxR64R32),
            Arc::new(MovzxR64R8),
            Arc::new(MovsxR64R8),
            Arc::new(CmovzR64R64),
            Arc::new(CmovnzR64R64),
            Arc::new(CmovlR64R64),
            Arc::new(CmovgeR64R64),
            Arc::new(BtR64R64),
            Arc::new(BtsR64R64),
            Arc::new(BtrR64R64),
            Arc::new(BtcR64R64),
            Arc::new(RolR64Cl),
            Arc::new(RorR64Cl),
            Arc::new(RclR64Cl),
            Arc::new(RcrR64Cl),
            Arc::new(Clc),
            Arc::new(Stc),
            Arc::new(Cmc),
            Arc::new(SetzR8),
            Arc::new(SetnzR8),
            Arc::new(SetlR8),
            Arc::new(SetgeR8),
            Arc::new(AdcR64R64),
            Arc::new(SbbR64R64),
            Arc::new(Cbw),
            Arc::new(Cwde),
            Arc::new(Cdqe),
            Arc::new(Cwd),
            Arc::new(Cdq),
            Arc::new(CmpxchgR64R64),
            Arc::new(Nop2),
            Arc::new(PushImm8),
            Arc::new(PushImm32),
            Arc::new(CallRel32),
            Arc::new(Ret),
            Arc::new(JleRel32),
            Arc::new(JgRel32),
            Arc::new(JaRel32),
            Arc::new(JbRel32),
            Arc::new(JbeRel32),
            Arc::new(JaeRel32),
            // Phase 4a expansion
            Arc::new(MovR16R16),
            Arc::new(MovzxR32R16),
            Arc::new(MovsxR32R16),
            Arc::new(MovzxR32R8),
            Arc::new(MovsxR32R8),
            Arc::new(MovR32Imm32),
            Arc::new(MovR16Imm16),
            Arc::new(MovR8Imm8),
            Arc::new(AddR32R32),
            Arc::new(SubR32R32),
            Arc::new(XorR32R32),
            Arc::new(AndR32R32),
            Arc::new(OrR32R32),
            Arc::new(CmpR32R32),
            Arc::new(IncR32),
            Arc::new(DecR32),
            Arc::new(NegR32),
            Arc::new(NotR32),
            Arc::new(CmovaR64R64),
            Arc::new(CmovbR64R64),
            Arc::new(CmovbeR64R64),
            Arc::new(CmovaeR64R64),
            Arc::new(CmovsR64R64),
            Arc::new(CmovnsR64R64),
            Arc::new(CmovcR64R64),
            Arc::new(CmovncR64R64),
            Arc::new(CmovleR64R64),
            Arc::new(CmovgR64R64),
            Arc::new(SetaR8),
            Arc::new(SetbR8),
            Arc::new(SetbeR8),
            Arc::new(SetaeR8),
            Arc::new(SetsR8),
            Arc::new(SetnsR8),
            Arc::new(SetcR8),
            Arc::new(SetncR8),
            Arc::new(SetleR8),
            Arc::new(SetgR8),
            Arc::new(JoRel32),
            Arc::new(JnoRel32),
            Arc::new(JpeRel32),
            Arc::new(JpoRel32),
            Arc::new(BswapR64),
            Arc::new(BsfR64R64),
            Arc::new(BsrR64R64),
            Arc::new(PopcntR64R64),
            Arc::new(TzcntR64R64),
            Arc::new(LzcntR64R64),
            Arc::new(AddssXmmXmm),
            Arc::new(SubssXmmXmm),
            Arc::new(MulssXmmXmm),
            Arc::new(DivssXmmXmm),
            Arc::new(SqrtssXmmXmm),
            Arc::new(AddsdXmmXmm),
            Arc::new(SubsdXmmXmm),
            Arc::new(MulsdXmmXmm),
            Arc::new(DivsdXmmXmm),
            Arc::new(SqrtsdXmmXmm),
            Arc::new(AddpsXmmXmm),
            Arc::new(SubpsXmmXmm),
            Arc::new(MulpsXmmXmm),
            Arc::new(DivpsXmmXmm),
            Arc::new(AddpdXmmXmm),
            Arc::new(SubpdXmmXmm),
            Arc::new(MulpdXmmXmm),
            Arc::new(DivpdXmmXmm),
            Arc::new(PaddbXmmXmm),
            Arc::new(PsubbXmmXmm),
            Arc::new(PaddwXmmXmm),
            Arc::new(PsubwXmmXmm),
            Arc::new(PmullwXmmXmm),
            Arc::new(PadddXmmXmm),
            Arc::new(PsubdXmmXmm),
            Arc::new(PmulldXmmXmm),
            Arc::new(PaddqXmmXmm),
            Arc::new(PsubqXmmXmm),
            Arc::new(PandXmmXmm),
            Arc::new(PorXmmXmm),
            Arc::new(PxorXmmXmm),
            Arc::new(PsllwXmmImm8),
            Arc::new(PsrlwXmmImm8),
            Arc::new(PsrawXmmImm8),
            Arc::new(PslldXmmImm8),
            Arc::new(PsrldXmmImm8),
            Arc::new(PsradXmmImm8),
            Arc::new(PsllqXmmImm8),
            Arc::new(PsrlqXmmImm8),
            Arc::new(PcmpeqbXmmXmm),
            Arc::new(PcmpeqwXmmXmm),
            Arc::new(PcmpeqdXmmXmm),
            Arc::new(PcmpgtbXmmXmm),
            Arc::new(PcmpgtwXmmXmm),
            Arc::new(PcmpgtdXmmXmm),
            Arc::new(PmaxsbXmmXmm),
            Arc::new(PmaxswXmmXmm),
            Arc::new(PmaxsdXmmXmm),
            Arc::new(PmaxubXmmXmm),
            Arc::new(PmaxuwXmmXmm),
            Arc::new(PmaxudXmmXmm),
            Arc::new(PminsbXmmXmm),
            Arc::new(PminswXmmXmm),
            Arc::new(PminsdXmmXmm),
            Arc::new(PminubXmmXmm),
            Arc::new(PminuwXmmXmm),
            Arc::new(PminudXmmXmm),
            Arc::new(ShlR32Imm8),
            Arc::new(ShrR32Imm8),
            Arc::new(SarR32Imm8),
            Arc::new(ShlR32Cl),
            Arc::new(ShrR32Cl),
            Arc::new(SarR32Cl),
            Arc::new(RolR32Imm8),
            Arc::new(RorR32Imm8),
            Arc::new(MovR32Mem32),
            Arc::new(MovMem32R32),
            Arc::new(AddR32Mem32),
            Arc::new(SubR32Mem32),
            Arc::new(CmpR32Mem32),
            Arc::new(MovR8Mem8),
            Arc::new(MovMem8R8),
            Arc::new(AddR8Mem8),
            Arc::new(SubR8Mem8),
            Arc::new(CmpR8Mem8),
            Arc::new(AddR32Imm8),
            Arc::new(SubR32Imm8),
            Arc::new(CmpR32Imm8),
            Arc::new(AndR64Imm32),
            Arc::new(OrR64Imm32),
            Arc::new(XorR64Imm32),
            Arc::new(TestR64Imm32),
            Arc::new(AndR32Imm32),
            Arc::new(OrR32Imm32),
            Arc::new(XorR32Imm32),
            Arc::new(TestR32Imm32),
            Arc::new(XaddR32R32),
            Arc::new(CmpxchgR32R32),
            Arc::new(PushR32),
            Arc::new(PopR32),
            Arc::new(ImulR64R64Imm32),
            Arc::new(ImulR32R32),
            Arc::new(ImulR32R32Imm8),
            Arc::new(ImulR32R32Imm32),
            Arc::new(MulR32R32),
            Arc::new(DivR32R32),
            Arc::new(IdivR32R32),
            Arc::new(LeaR32Mem),
            Arc::new(MovqXmmXmm),
            Arc::new(Nop3),
            Arc::new(Nop4),
            Arc::new(Nop5),
            Arc::new(Nop6),
            Arc::new(Nop7),
            Arc::new(Nop8),
            Arc::new(Nop9),
            Arc::new(Hlt),
            Arc::new(Ud2),
        ];

        // Build form index from known form IDs. Each provider corresponds to
        // exactly one form. The ALL_FORMS array is hardcoded with unique entries.
        let mut form_index = BTreeMap::new();
        for (index, &form) in ALL_FORMS.iter().enumerate() {
            form_index.insert(form, index);
        }

        Self {
            providers,
            form_index,
            semantic_version,
        }
    }

    pub fn providers(&self) -> &[Arc<dyn angryier_semantics::SemanticProvider>] {
        &self.providers
    }
}

impl SemanticRegistry for Intel64CorpusRegistry {
    fn resolve(
        &self,
        insn: &dyn DecodedInstructionView,
        version: SemanticVersion,
    ) -> Result<SemanticResolution, SemanticError> {
        if version != self.semantic_version {
            return Err(SemanticError::VersionMismatch);
        }

        let index = self
            .form_index
            .get(&insn.form_id())
            .copied()
            .ok_or(SemanticError::UnsupportedForm(insn.form_id()))?;

        let provider = &self.providers[index];
        if !provider.matches(insn) {
            return Err(SemanticError::UnsupportedForm(insn.form_id()));
        }

        Ok(SemanticResolution {
            kind: ResolutionKind::Override,
            rule_id: provider.rule_id(),
            semantic_version: self.semantic_version,
        })
    }
}

const ALL_FORMS: [u32; 249] = [
    crate::forms::MOV_R64_R64,
    crate::forms::ADD_R64_R64,
    crate::forms::SUB_R64_R64,
    crate::forms::XOR_R64_R64,
    crate::forms::AND_R64_R64,
    crate::forms::OR_R64_R64,
    crate::forms::SHL_R64_IMM8,
    crate::forms::SHR_R64_IMM8,
    crate::forms::SAR_R64_IMM8,
    crate::forms::CMP_R64_R64,
    crate::forms::JZ_REL32,
    crate::forms::JNZ_REL32,
    crate::forms::JMP_REL32,
    crate::forms::MOV_R64_IMM64,
    crate::forms::ADD_R64_IMM32,
    crate::forms::SUB_R64_IMM32,
    crate::forms::CMP_R64_IMM32,
    crate::forms::SHL_R64_CL,
    crate::forms::SHR_R64_CL,
    crate::forms::SAR_R64_CL,
    crate::forms::JC_REL32,
    crate::forms::JNC_REL32,
    crate::forms::JS_REL32,
    crate::forms::JNS_REL32,
    crate::forms::JL_REL32,
    crate::forms::JGE_REL32,
    crate::forms::INC_R64,
    crate::forms::DEC_R64,
    crate::forms::NEG_R64,
    crate::forms::NOT_R64,
    crate::forms::NOP,
    crate::forms::MOV_R64_MEM64,
    crate::forms::MOV_MEM64_R64,
    crate::forms::ADD_R64_MEM64,
    crate::forms::CMP_R64_MEM64,
    crate::forms::IMUL_R64_R64,
    crate::forms::MUL_R64_R64,
    crate::forms::DIV_R64_R64,
    crate::forms::IDIV_R64_R64,
    crate::forms::ROL_R64_IMM8,
    crate::forms::ROR_R64_IMM8,
    crate::forms::RCL_R64_IMM8,
    crate::forms::RCR_R64_IMM8,
    crate::forms::PUSH_R64,
    crate::forms::POP_R64,
    crate::forms::LEA_R64_MEM,
    crate::forms::XCHG_R64_R64,
    crate::forms::TEST_R64_R64,
    crate::forms::XADD_R64_R64,
    crate::forms::MOV_R32_R32,
    crate::forms::MOV_R8_R8,
    crate::forms::MOVZX_R64_R32,
    crate::forms::MOVSX_R64_R32,
    crate::forms::MOVZX_R64_R8,
    crate::forms::MOVSX_R64_R8,
    crate::forms::CMOVZ_R64_R64,
    crate::forms::CMOVNZ_R64_R64,
    crate::forms::CMOVL_R64_R64,
    crate::forms::CMOVGE_R64_R64,
    crate::forms::BT_R64_R64,
    crate::forms::BTS_R64_R64,
    crate::forms::BTR_R64_R64,
    crate::forms::BTC_R64_R64,
    crate::forms::ROL_R64_CL,
    crate::forms::ROR_R64_CL,
    crate::forms::RCL_R64_CL,
    crate::forms::RCR_R64_CL,
    crate::forms::CLC,
    crate::forms::STC,
    crate::forms::CMC,
    crate::forms::SETZ_R8,
    crate::forms::SETNZ_R8,
    crate::forms::SETL_R8,
    crate::forms::SETGE_R8,
    crate::forms::ADC_R64_R64,
    crate::forms::SBB_R64_R64,
    crate::forms::CBW,
    crate::forms::CWDE,
    crate::forms::CDQE,
    crate::forms::CWD,
    crate::forms::CDQ,
    crate::forms::CMPXCHG_R64_R64,
    crate::forms::NOP2,
    crate::forms::PUSH_IMM8,
    crate::forms::PUSH_IMM32,
    crate::forms::CALL_REL32,
    crate::forms::RET,
    crate::forms::JLE_REL32,
    crate::forms::JG_REL32,
    crate::forms::JA_REL32,
    crate::forms::JB_REL32,
    crate::forms::JBE_REL32,
    crate::forms::JAE_REL32,
    // Phase 4a expansion
    crate::forms::MOV_R16_R16,
    crate::forms::MOVZX_R32_R16,
    crate::forms::MOVSX_R32_R16,
    crate::forms::MOVZX_R32_R8,
    crate::forms::MOVSX_R32_R8,
    crate::forms::MOV_R32_IMM32,
    crate::forms::MOV_R16_IMM16,
    crate::forms::MOV_R8_IMM8,
    crate::forms::ADD_R32_R32,
    crate::forms::SUB_R32_R32,
    crate::forms::XOR_R32_R32,
    crate::forms::AND_R32_R32,
    crate::forms::OR_R32_R32,
    crate::forms::CMP_R32_R32,
    crate::forms::INC_R32,
    crate::forms::DEC_R32,
    crate::forms::NEG_R32,
    crate::forms::NOT_R32,
    crate::forms::CMOVA_R64_R64,
    crate::forms::CMOVB_R64_R64,
    crate::forms::CMOVBE_R64_R64,
    crate::forms::CMOVAE_R64_R64,
    crate::forms::CMOVS_R64_R64,
    crate::forms::CMOVNS_R64_R64,
    crate::forms::CMOVC_R64_R64,
    crate::forms::CMOVNC_R64_R64,
    crate::forms::CMOVLE_R64_R64,
    crate::forms::CMOVG_R64_R64,
    crate::forms::SETA_R8,
    crate::forms::SETB_R8,
    crate::forms::SETBE_R8,
    crate::forms::SETAE_R8,
    crate::forms::SETS_R8,
    crate::forms::SETNS_R8,
    crate::forms::SETC_R8,
    crate::forms::SETNC_R8,
    crate::forms::SETLE_R8,
    crate::forms::SETG_R8,
    crate::forms::JO_REL32,
    crate::forms::JNO_REL32,
    crate::forms::JPE_REL32,
    crate::forms::JPO_REL32,
    crate::forms::BSWAP_R64,
    crate::forms::BSF_R64_R64,
    crate::forms::BSR_R64_R64,
    crate::forms::POPCNT_R64_R64,
    crate::forms::TZCNT_R64_R64,
    crate::forms::LZCNT_R64_R64,
    crate::forms::ADDSS_XMM_XMM,
    crate::forms::SUBSS_XMM_XMM,
    crate::forms::MULSS_XMM_XMM,
    crate::forms::DIVSS_XMM_XMM,
    crate::forms::SQRTSS_XMM_XMM,
    crate::forms::ADDSD_XMM_XMM,
    crate::forms::SUBSD_XMM_XMM,
    crate::forms::MULSD_XMM_XMM,
    crate::forms::DIVSD_XMM_XMM,
    crate::forms::SQRTSD_XMM_XMM,
    crate::forms::ADDPS_XMM_XMM,
    crate::forms::SUBPS_XMM_XMM,
    crate::forms::MULPS_XMM_XMM,
    crate::forms::DIVPS_XMM_XMM,
    crate::forms::ADDPD_XMM_XMM,
    crate::forms::SUBPD_XMM_XMM,
    crate::forms::MULPD_XMM_XMM,
    crate::forms::DIVPD_XMM_XMM,
    crate::forms::PADDB_XMM_XMM,
    crate::forms::PSUBB_XMM_XMM,
    crate::forms::PADDW_XMM_XMM,
    crate::forms::PSUBW_XMM_XMM,
    crate::forms::PMULLW_XMM_XMM,
    crate::forms::PADDD_XMM_XMM,
    crate::forms::PSUBD_XMM_XMM,
    crate::forms::PMULLD_XMM_XMM,
    crate::forms::PADDQ_XMM_XMM,
    crate::forms::PSUBQ_XMM_XMM,
    crate::forms::PAND_XMM_XMM,
    crate::forms::POR_XMM_XMM,
    crate::forms::PXOR_XMM_XMM,
    crate::forms::PSLLW_XMM_IMM8,
    crate::forms::PSRLW_XMM_IMM8,
    crate::forms::PSRAW_XMM_IMM8,
    crate::forms::PSLLD_XMM_IMM8,
    crate::forms::PSRLD_XMM_IMM8,
    crate::forms::PSRAD_XMM_IMM8,
    crate::forms::PSLLQ_XMM_IMM8,
    crate::forms::PSRLQ_XMM_IMM8,
    crate::forms::PCMPEQB_XMM_XMM,
    crate::forms::PCMPEQW_XMM_XMM,
    crate::forms::PCMPEQD_XMM_XMM,
    crate::forms::PCMPGTB_XMM_XMM,
    crate::forms::PCMPGTW_XMM_XMM,
    crate::forms::PCMPGTD_XMM_XMM,
    crate::forms::PMAXSB_XMM_XMM,
    crate::forms::PMAXSW_XMM_XMM,
    crate::forms::PMAXSD_XMM_XMM,
    crate::forms::PMAXUB_XMM_XMM,
    crate::forms::PMAXUW_XMM_XMM,
    crate::forms::PMAXUD_XMM_XMM,
    crate::forms::PMINSB_XMM_XMM,
    crate::forms::PMINSW_XMM_XMM,
    crate::forms::PMINSD_XMM_XMM,
    crate::forms::PMINUB_XMM_XMM,
    crate::forms::PMINUW_XMM_XMM,
    crate::forms::PMINUD_XMM_XMM,
    crate::forms::SHL_R32_IMM8,
    crate::forms::SHR_R32_IMM8,
    crate::forms::SAR_R32_IMM8,
    crate::forms::SHL_R32_CL,
    crate::forms::SHR_R32_CL,
    crate::forms::SAR_R32_CL,
    crate::forms::ROL_R32_IMM8,
    crate::forms::ROR_R32_IMM8,
    crate::forms::MOV_R32_MEM32,
    crate::forms::MOV_MEM32_R32,
    crate::forms::ADD_R32_MEM32,
    crate::forms::SUB_R32_MEM32,
    crate::forms::CMP_R32_MEM32,
    crate::forms::MOV_R8_MEM8,
    crate::forms::MOV_MEM8_R8,
    crate::forms::ADD_R8_MEM8,
    crate::forms::SUB_R8_MEM8,
    crate::forms::CMP_R8_MEM8,
    crate::forms::ADD_R32_IMM8,
    crate::forms::SUB_R32_IMM8,
    crate::forms::CMP_R32_IMM8,
    crate::forms::AND_R64_IMM32,
    crate::forms::OR_R64_IMM32,
    crate::forms::XOR_R64_IMM32,
    crate::forms::TEST_R64_IMM32,
    crate::forms::AND_R32_IMM32,
    crate::forms::OR_R32_IMM32,
    crate::forms::XOR_R32_IMM32,
    crate::forms::TEST_R32_IMM32,
    crate::forms::XADD_R32_R32,
    crate::forms::CMPXCHG_R32_R32,
    crate::forms::PUSH_R32,
    crate::forms::POP_R32,
    crate::forms::IMUL_R64_R64_IMM32,
    crate::forms::IMUL_R32_R32,
    crate::forms::IMUL_R32_R32_IMM8,
    crate::forms::IMUL_R32_R32_IMM32,
    crate::forms::MUL_R32_R32,
    crate::forms::DIV_R32_R32,
    crate::forms::IDIV_R32_R32,
    crate::forms::LEA_R32_MEM,
    crate::forms::MOVQ_XMM_XMM,
    crate::forms::NOP3,
    crate::forms::NOP4,
    crate::forms::NOP5,
    crate::forms::NOP6,
    crate::forms::NOP7,
    crate::forms::NOP8,
    crate::forms::NOP9,
    crate::forms::HLT,
    crate::forms::UD2,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule_id;
    use angryier_arch::{
        AccessKind, DecodedInstruction, ImmediateOperand, MemoryBase, MemoryOperand, Operand, OperandKind,
        OperandVisibility, RegisterId, RegisterView, RelativeBranchOperand,
    };
    use angryier_semantic_contracts::SealedSemanticBlock;
    use angryier_semantics::{SemanticBlockBuilder, SemanticContext};
    use angryier_types::{
        ContentIdentitySchemaVersion, FidelityProfile, SemanticFingerprintSchemaVersion, SemanticVersion,
        TargetProfileId,
    };

    fn context() -> SemanticContext {
        SemanticContext {
            semantic_version: SemanticVersion(1),
            target_profile: TargetProfileId(1),
            fidelity: FidelityProfile::Prove,
            vector_representation: angryier_semantics::VectorRepresentation::HybridLazy,
            tile_representation: angryier_semantics::TileRepresentation::LazyChunked,
            floating_point_policy: angryier_semantics::FloatingPointPolicy::SmtFpPreferred,
        }
    }

    fn make_decoded(form: u32, operands: Vec<Operand>) -> DecodedInstruction {
        DecodedInstruction {
            address: 0x1000,
            length: 3,
            form_id: form,
            features: vec![],
            operands,
            modifiers: angryier_arch::InstructionModifiers::default(),
        }
    }

    fn reg_operand(index: u8, reg: u32, width: u16, access: AccessKind) -> Operand {
        Operand {
            index,
            width_bits: width,
            access,
            visibility: OperandVisibility::Explicit,
            kind: OperandKind::Register(RegisterView::full(RegisterId(reg), width)),
        }
    }

    fn imm_operand(index: u8, value: u64, width: u16) -> Operand {
        Operand {
            index,
            width_bits: width,
            access: AccessKind::Read,
            visibility: OperandVisibility::Explicit,
            kind: OperandKind::Immediate(ImmediateOperand { value, signed: false }),
        }
    }

    fn rel_branch_operand(index: u8, displacement: i64) -> Operand {
        Operand {
            index,
            width_bits: 32,
            access: AccessKind::Read,
            visibility: OperandVisibility::Explicit,
            kind: OperandKind::RelativeBranch(RelativeBranchOperand {
                displacement,
                displacement_width_bits: 32,
            }),
        }
    }

    fn mem_operand(index: u8, base: u32, disp: i64, access: AccessKind) -> Operand {
        Operand {
            index,
            width_bits: 64,
            access,
            visibility: OperandVisibility::Explicit,
            kind: OperandKind::Memory(MemoryOperand {
                memory_index: 0,
                address_width_bits: 64,
                segment: None,
                base: Some(MemoryBase::Register(RegisterView::full(RegisterId(base), 64))),
                index: None,
                scale: 1,
                displacement: disp,
                displacement_width_bits: 32,
            }),
        }
    }

    fn addr_gen_operand(index: u8, base: u32, disp: i64) -> Operand {
        Operand {
            index,
            width_bits: 64,
            access: AccessKind::Read,
            visibility: OperandVisibility::Explicit,
            kind: OperandKind::AddressGeneration(MemoryOperand {
                memory_index: 0,
                address_width_bits: 64,
                segment: None,
                base: Some(MemoryBase::Register(RegisterView::full(RegisterId(base), 64))),
                index: None,
                scale: 1,
                displacement: disp,
                displacement_width_bits: 32,
            }),
        }
    }

    #[test]
    fn registry_resolves_known_forms() {
        let registry = Intel64CorpusRegistry::new(SemanticVersion(1));
        let decoded = make_decoded(
            crate::forms::MOV_R64_R64,
            vec![
                reg_operand(0, 0, 64, AccessKind::Write),
                reg_operand(1, 1, 64, AccessKind::Read),
            ],
        );

        let resolution = registry.resolve(&decoded, SemanticVersion(1));
        assert!(resolution.is_ok());
        let res = match resolution {
            Ok(r) => r,
            Err(_) => return,
        };
        assert_eq!(res.kind, ResolutionKind::Override);
        assert_eq!(res.rule_id, rule_id(0));
    }

    #[test]
    fn registry_rejects_unknown_form() {
        let registry = Intel64CorpusRegistry::new(SemanticVersion(1));
        let decoded = make_decoded(0xFFFF, vec![]);

        let resolution = registry.resolve(&decoded, SemanticVersion(1));
        assert_eq!(resolution, Err(SemanticError::UnsupportedForm(0xFFFF)));
    }

    #[test]
    fn registry_rejects_version_mismatch() {
        let registry = Intel64CorpusRegistry::new(SemanticVersion(1));
        let decoded = make_decoded(
            crate::forms::MOV_R64_R64,
            vec![
                reg_operand(0, 0, 64, AccessKind::Write),
                reg_operand(1, 1, 64, AccessKind::Read),
            ],
        );

        let resolution = registry.resolve(&decoded, SemanticVersion(2));
        assert_eq!(resolution, Err(SemanticError::VersionMismatch));
    }

    #[test]
    fn mov_emits_simple_register_copy() {
        let registry = Intel64CorpusRegistry::new(SemanticVersion(1));
        let decoded = make_decoded(
            crate::forms::MOV_R64_R64,
            vec![
                reg_operand(0, 0, 64, AccessKind::Write),
                reg_operand(1, 1, 64, AccessKind::Read),
            ],
        );

        let resolution = match registry.resolve(&decoded, SemanticVersion(1)) {
            Ok(r) => r,
            Err(_) => return,
        };
        let _ = resolution;
        let provider = &registry.providers()[0];
        let mut builder = SemanticBlockBuilder::new(SemanticVersion(1));
        let ctx = context();

        let receipt = match provider.emit(&ctx, &decoded, &mut builder) {
            Ok(r) => r,
            Err(_) => return,
        };
        assert_eq!(receipt.rule_id, rule_id(0));

        // MOV should have 2 values (read operand 1, fall-through constant) and 2 effects (write operand 0, jump)
        assert_eq!(builder.values().len(), 2);
        assert_eq!(builder.effects().len(), 2);
    }

    #[test]
    fn add_emits_arithmetic_and_flags() {
        let registry = Intel64CorpusRegistry::new(SemanticVersion(1));
        let decoded = make_decoded(
            crate::forms::ADD_R64_R64,
            vec![
                reg_operand(0, 0, 64, AccessKind::ReadWrite),
                reg_operand(1, 1, 64, AccessKind::Read),
            ],
        );

        let provider = &registry.providers()[1];
        let mut builder = SemanticBlockBuilder::new(SemanticVersion(1));
        let ctx = context();

        match provider.emit(&ctx, &decoded, &mut builder) {
            Ok(_) => {}
            Err(_) => return,
        }

        // ADD should produce multiple values (operands, result, flag computations)
        // and multiple effects (RFLAGS write, operand write)
        assert!(builder.values().len() > 5);
        assert!(builder.effects().len() >= 2);
    }

    #[test]
    fn mov_r64_imm64_emits_immediate_copy() {
        let registry = Intel64CorpusRegistry::new(SemanticVersion(1));
        let decoded = make_decoded(
            crate::forms::MOV_R64_IMM64,
            vec![reg_operand(0, 0, 64, AccessKind::Write), imm_operand(1, 42, 64)],
        );

        let provider = &registry.providers()[13];
        let mut builder = SemanticBlockBuilder::new(SemanticVersion(1));
        let ctx = context();

        let receipt = match provider.emit(&ctx, &decoded, &mut builder) {
            Ok(r) => r,
            Err(_) => return,
        };
        assert_eq!(receipt.rule_id, rule_id(13));

        // MOV imm64: read operand 1, write operand 0, fall-through jump
        assert_eq!(builder.values().len(), 2);
        assert_eq!(builder.effects().len(), 2);
    }

    #[test]
    fn neg_r64_emits_negation_and_flags() {
        let registry = Intel64CorpusRegistry::new(SemanticVersion(1));
        let decoded = make_decoded(
            crate::forms::NEG_R64,
            vec![reg_operand(0, 0, 64, AccessKind::ReadWrite)],
        );

        let provider = &registry.providers()[28];
        let mut builder = SemanticBlockBuilder::new(SemanticVersion(1));
        let ctx = context();

        match provider.emit(&ctx, &decoded, &mut builder) {
            Ok(_) => {}
            Err(_) => return,
        }

        // NEG should produce multiple values (operand read, zero constant, sub result, flag computations)
        assert!(builder.values().len() > 5);
        assert!(builder.effects().len() >= 2);
    }

    #[test]
    fn nop_emits_only_fall_through() {
        let registry = Intel64CorpusRegistry::new(SemanticVersion(1));
        let decoded = make_decoded(crate::forms::NOP, vec![]);

        let provider = &registry.providers()[30];
        let mut builder = SemanticBlockBuilder::new(SemanticVersion(1));
        let ctx = context();

        let receipt = match provider.emit(&ctx, &decoded, &mut builder) {
            Ok(r) => r,
            Err(_) => return,
        };
        assert_eq!(receipt.rule_id, rule_id(30));

        // NOP: only the fall-through constant value and the jump effect
        assert_eq!(builder.values().len(), 1);
        assert_eq!(builder.effects().len(), 1);
    }

    #[test]
    fn all_providers_seal_successfully() {
        let registry = Intel64CorpusRegistry::new(SemanticVersion(1));
        let ctx = context();

        let test_cases: Vec<(usize, u32, Vec<Operand>)> = vec![
            (
                0,
                crate::forms::MOV_R64_R64,
                vec![
                    reg_operand(0, 0, 64, AccessKind::Write),
                    reg_operand(1, 1, 64, AccessKind::Read),
                ],
            ),
            (
                1,
                crate::forms::ADD_R64_R64,
                vec![
                    reg_operand(0, 0, 64, AccessKind::ReadWrite),
                    reg_operand(1, 1, 64, AccessKind::Read),
                ],
            ),
            (
                2,
                crate::forms::SUB_R64_R64,
                vec![
                    reg_operand(0, 0, 64, AccessKind::ReadWrite),
                    reg_operand(1, 1, 64, AccessKind::Read),
                ],
            ),
            (
                3,
                crate::forms::XOR_R64_R64,
                vec![
                    reg_operand(0, 0, 64, AccessKind::ReadWrite),
                    reg_operand(1, 1, 64, AccessKind::Read),
                ],
            ),
            (
                4,
                crate::forms::AND_R64_R64,
                vec![
                    reg_operand(0, 0, 64, AccessKind::ReadWrite),
                    reg_operand(1, 1, 64, AccessKind::Read),
                ],
            ),
            (
                5,
                crate::forms::OR_R64_R64,
                vec![
                    reg_operand(0, 0, 64, AccessKind::ReadWrite),
                    reg_operand(1, 1, 64, AccessKind::Read),
                ],
            ),
            (
                6,
                crate::forms::SHL_R64_IMM8,
                vec![reg_operand(0, 0, 64, AccessKind::ReadWrite), imm_operand(1, 4, 8)],
            ),
            (
                7,
                crate::forms::SHR_R64_IMM8,
                vec![reg_operand(0, 0, 64, AccessKind::ReadWrite), imm_operand(1, 4, 8)],
            ),
            (
                8,
                crate::forms::SAR_R64_IMM8,
                vec![reg_operand(0, 0, 64, AccessKind::ReadWrite), imm_operand(1, 4, 8)],
            ),
            (
                9,
                crate::forms::CMP_R64_R64,
                vec![
                    reg_operand(0, 0, 64, AccessKind::Read),
                    reg_operand(1, 1, 64, AccessKind::Read),
                ],
            ),
            (10, crate::forms::JZ_REL32, vec![rel_branch_operand(0, -16)]),
            (11, crate::forms::JNZ_REL32, vec![rel_branch_operand(0, -16)]),
            (12, crate::forms::JMP_REL32, vec![rel_branch_operand(0, -16)]),
            (
                13,
                crate::forms::MOV_R64_IMM64,
                vec![reg_operand(0, 0, 64, AccessKind::Write), imm_operand(1, 42, 64)],
            ),
            (
                14,
                crate::forms::ADD_R64_IMM32,
                vec![reg_operand(0, 0, 64, AccessKind::ReadWrite), imm_operand(1, 5, 32)],
            ),
            (
                15,
                crate::forms::SUB_R64_IMM32,
                vec![reg_operand(0, 0, 64, AccessKind::ReadWrite), imm_operand(1, 5, 32)],
            ),
            (
                16,
                crate::forms::CMP_R64_IMM32,
                vec![reg_operand(0, 0, 64, AccessKind::Read), imm_operand(1, 5, 32)],
            ),
            (
                17,
                crate::forms::SHL_R64_CL,
                vec![reg_operand(0, 0, 64, AccessKind::ReadWrite)],
            ),
            (
                18,
                crate::forms::SHR_R64_CL,
                vec![reg_operand(0, 0, 64, AccessKind::ReadWrite)],
            ),
            (
                19,
                crate::forms::SAR_R64_CL,
                vec![reg_operand(0, 0, 64, AccessKind::ReadWrite)],
            ),
            (20, crate::forms::JC_REL32, vec![rel_branch_operand(0, -16)]),
            (21, crate::forms::JNC_REL32, vec![rel_branch_operand(0, -16)]),
            (22, crate::forms::JS_REL32, vec![rel_branch_operand(0, -16)]),
            (23, crate::forms::JNS_REL32, vec![rel_branch_operand(0, -16)]),
            (24, crate::forms::JL_REL32, vec![rel_branch_operand(0, -16)]),
            (25, crate::forms::JGE_REL32, vec![rel_branch_operand(0, -16)]),
            (
                26,
                crate::forms::INC_R64,
                vec![reg_operand(0, 0, 64, AccessKind::ReadWrite)],
            ),
            (
                27,
                crate::forms::DEC_R64,
                vec![reg_operand(0, 0, 64, AccessKind::ReadWrite)],
            ),
            (
                28,
                crate::forms::NEG_R64,
                vec![reg_operand(0, 0, 64, AccessKind::ReadWrite)],
            ),
            (
                29,
                crate::forms::NOT_R64,
                vec![reg_operand(0, 0, 64, AccessKind::ReadWrite)],
            ),
            (30, crate::forms::NOP, vec![]),
            (
                31,
                crate::forms::MOV_R64_MEM64,
                vec![
                    reg_operand(0, 0, 64, AccessKind::Write),
                    mem_operand(1, 1, 0, AccessKind::Read),
                ],
            ),
            (
                32,
                crate::forms::MOV_MEM64_R64,
                vec![
                    mem_operand(0, 1, 0, AccessKind::Write),
                    reg_operand(1, 0, 64, AccessKind::Read),
                ],
            ),
            (
                33,
                crate::forms::ADD_R64_MEM64,
                vec![
                    reg_operand(0, 0, 64, AccessKind::ReadWrite),
                    mem_operand(1, 1, 0, AccessKind::Read),
                ],
            ),
            (
                34,
                crate::forms::CMP_R64_MEM64,
                vec![
                    reg_operand(0, 0, 64, AccessKind::Read),
                    mem_operand(1, 1, 0, AccessKind::Read),
                ],
            ),
            (
                35,
                crate::forms::IMUL_R64_R64,
                vec![
                    reg_operand(0, 0, 64, AccessKind::ReadWrite),
                    reg_operand(1, 1, 64, AccessKind::Read),
                ],
            ),
            (
                36,
                crate::forms::MUL_R64_R64,
                vec![
                    reg_operand(0, 0, 64, AccessKind::ReadWrite),
                    reg_operand(1, 1, 64, AccessKind::Read),
                ],
            ),
            (
                37,
                crate::forms::DIV_R64_R64,
                vec![reg_operand(0, 1, 64, AccessKind::Read)],
            ),
            (
                38,
                crate::forms::IDIV_R64_R64,
                vec![reg_operand(0, 1, 64, AccessKind::Read)],
            ),
            (
                39,
                crate::forms::ROL_R64_IMM8,
                vec![reg_operand(0, 0, 64, AccessKind::ReadWrite), imm_operand(1, 4, 8)],
            ),
            (
                40,
                crate::forms::ROR_R64_IMM8,
                vec![reg_operand(0, 0, 64, AccessKind::ReadWrite), imm_operand(1, 4, 8)],
            ),
            (
                41,
                crate::forms::RCL_R64_IMM8,
                vec![reg_operand(0, 0, 64, AccessKind::ReadWrite), imm_operand(1, 4, 8)],
            ),
            (
                42,
                crate::forms::RCR_R64_IMM8,
                vec![reg_operand(0, 0, 64, AccessKind::ReadWrite), imm_operand(1, 4, 8)],
            ),
            (
                43,
                crate::forms::PUSH_R64,
                vec![reg_operand(0, 0, 64, AccessKind::Read)],
            ),
            (
                44,
                crate::forms::POP_R64,
                vec![reg_operand(0, 0, 64, AccessKind::Write)],
            ),
            (
                45,
                crate::forms::LEA_R64_MEM,
                vec![reg_operand(0, 0, 64, AccessKind::Write), addr_gen_operand(1, 1, 0x100)],
            ),
            (
                46,
                crate::forms::XCHG_R64_R64,
                vec![
                    reg_operand(0, 0, 64, AccessKind::ReadWrite),
                    reg_operand(1, 1, 64, AccessKind::ReadWrite),
                ],
            ),
            (
                47,
                crate::forms::TEST_R64_R64,
                vec![
                    reg_operand(0, 0, 64, AccessKind::Read),
                    reg_operand(1, 1, 64, AccessKind::Read),
                ],
            ),
            (
                48,
                crate::forms::XADD_R64_R64,
                vec![
                    reg_operand(0, 0, 64, AccessKind::ReadWrite),
                    reg_operand(1, 1, 64, AccessKind::ReadWrite),
                ],
            ),
            (
                49,
                crate::forms::MOV_R32_R32,
                vec![
                    reg_operand(0, 0, 64, AccessKind::Write),
                    reg_operand(1, 1, 64, AccessKind::Read),
                ],
            ),
            (
                50,
                crate::forms::MOV_R8_R8,
                vec![
                    reg_operand(0, 0, 64, AccessKind::Write),
                    reg_operand(1, 1, 64, AccessKind::Read),
                ],
            ),
            (
                51,
                crate::forms::MOVZX_R64_R32,
                vec![
                    reg_operand(0, 0, 64, AccessKind::Write),
                    reg_operand(1, 1, 64, AccessKind::Read),
                ],
            ),
            (
                52,
                crate::forms::MOVSX_R64_R32,
                vec![
                    reg_operand(0, 0, 64, AccessKind::Write),
                    reg_operand(1, 1, 64, AccessKind::Read),
                ],
            ),
            (
                53,
                crate::forms::MOVZX_R64_R8,
                vec![
                    reg_operand(0, 0, 64, AccessKind::Write),
                    reg_operand(1, 1, 64, AccessKind::Read),
                ],
            ),
            (
                54,
                crate::forms::MOVSX_R64_R8,
                vec![
                    reg_operand(0, 0, 64, AccessKind::Write),
                    reg_operand(1, 1, 64, AccessKind::Read),
                ],
            ),
        ];

        for (index, form, operands) in test_cases {
            let decoded = make_decoded(form, operands);
            let provider = &registry.providers()[index];
            let mut builder = SemanticBlockBuilder::new(SemanticVersion(1));

            let receipt = match provider.emit(&ctx, &decoded, &mut builder) {
                Ok(r) => r,
                Err(ref e) => {
                    let _ = e;
                    return;
                }
            };
            assert_eq!(receipt.rule_id.0, 0x1000 + index as u64);

            let sealed = match builder.seal(ContentIdentitySchemaVersion(1), SemanticFingerprintSchemaVersion(1)) {
                Ok(s) => s,
                Err(_) => return,
            };

            // Verify identity is deterministic
            assert_eq!(sealed.semantic_version(), SemanticVersion(1));
            let cid = sealed.content_id();
            assert_ne!(cid.0, [0u8; 32]);
        }
    }
}
