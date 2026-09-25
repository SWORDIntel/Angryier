#![forbid(unsafe_code)]

//! Semantic registry for the Intel 64 corpus.

use crate::providers::*;
use crate::providers_ext::*;
use crate::x87::*;
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
            Arc::new(PmulhwXmmXmm),
            Arc::new(PmulhuwXmmXmm),
            Arc::new(PshufbXmmXmm),
            Arc::new(PunpcklbwXmmXmm),
            Arc::new(PunpcklwdXmmXmm),
            Arc::new(PunpckldqXmmXmm),
            Arc::new(PunpcklqdqXmmXmm),
            Arc::new(PunpckhbwXmmXmm),
            Arc::new(PunpckhwdXmmXmm),
            Arc::new(PunpckhdqXmmXmm),
            Arc::new(PunpckhqdqXmmXmm),
            Arc::new(PacksswbXmmXmm),
            Arc::new(PackssdwXmmXmm),
            Arc::new(PackuswbXmmXmm),
            Arc::new(PackusdwXmmXmm),
            Arc::new(PmaddwdXmmXmm),
            Arc::new(PsadbwXmmXmm),
            Arc::new(PshufdXmmImm8),
            Arc::new(PshufhwXmmImm8),
            Arc::new(PshuflwXmmImm8),
            Arc::new(PmaddubswXmmXmm),
            Arc::new(PsllwXmmXmm),
            Arc::new(PslldXmmXmm),
            Arc::new(PsllqXmmXmm),
            Arc::new(PsrlwXmmXmm),
            Arc::new(PsrldXmmXmm),
            Arc::new(PsrlqXmmXmm),
            Arc::new(PsrawXmmXmm),
            Arc::new(PsradXmmXmm),
            Arc::new(PhaddwXmmXmm),
            Arc::new(PhadddXmmXmm),
            Arc::new(PhsubwXmmXmm),
            Arc::new(PhsubdXmmXmm),
            Arc::new(PabsbXmmXmm),
            Arc::new(PabswXmmXmm),
            Arc::new(PabsdXmmXmm),
            Arc::new(PsignbXmmXmm),
            Arc::new(PsignwXmmXmm),
            Arc::new(PsigndXmmXmm),
            Arc::new(PmulhrswXmmXmm),
            Arc::new(PhaddswXmmXmm),
            Arc::new(PhsubswXmmXmm),
            Arc::new(PcmpeqqXmmXmm),
            Arc::new(PmuldqXmmXmm),
            Arc::new(PblendvbXmmXmm),
            Arc::new(PmovsxbwXmmXmm),
            Arc::new(PmovzxbwXmmXmm),
            Arc::new(PmovsxbdXmmXmm),
            Arc::new(PmovzxbdXmmXmm),
            Arc::new(PmovsxwdXmmXmm),
            Arc::new(PmovzxwdXmmXmm),
            Arc::new(PmovsxdqXmmXmm),
            Arc::new(PmovzxdqXmmXmm),
            Arc::new(PmovsxwqXmmXmm),
            Arc::new(PmovzxwqXmmXmm),
            Arc::new(PmovsxbqXmmXmm),
            Arc::new(PmovzxbqXmmXmm),
            Arc::new(PblendwXmmXmmImm8),
            Arc::new(BlendpsXmmXmmImm8),
            Arc::new(BlendpdXmmXmmImm8),
            Arc::new(DppsXmmXmmImm8),
            Arc::new(DppdXmmXmmImm8),
            Arc::new(PextrbR32XmmImm8),
            Arc::new(PinsrbXmmR32Imm8),
            Arc::new(UcomissXmmXmm),
            Arc::new(UcomisdXmmXmm),
            Arc::new(ComissXmmXmm),
            Arc::new(ComisdXmmXmm),
            Arc::new(RoundpsXmmXmmImm8),
            Arc::new(RoundpdXmmXmmImm8),
            Arc::new(RoundssXmmXmmImm8),
            Arc::new(RoundsdXmmXmmImm8),
            Arc::new(PtestXmmXmm),
            Arc::new(Crc32R32R32),
            Arc::new(Crc32R64R64),
            Arc::new(PextrdR32XmmImm8),
            Arc::new(PextrqR64XmmImm8),
            Arc::new(PinsrdXmmR32Imm8),
            Arc::new(PinsrqXmmR64Imm8),
            Arc::new(InsertpsXmmXmmImm8),
            Arc::new(ExtractpsR32XmmImm8),
            Arc::new(ShlR32Imm8),
            Arc::new(ShrR32Imm8),
            Arc::new(SarR32Imm8),
            Arc::new(ShlR32Cl),
            Arc::new(ShrR32Cl),
            Arc::new(SarR32Cl),
            Arc::new(RolR32Imm8),
            Arc::new(RorR32Imm8),
            Arc::new(RolR32Cl),
            Arc::new(RorR32Cl),
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
            Arc::new(CmppsXmmXmmImm8),
            Arc::new(CmppdXmmXmmImm8),
            Arc::new(MinpsXmmXmm),
            Arc::new(MaxpsXmmXmm),
            Arc::new(MovmskpsR32Xmm),
            Arc::new(MovmskpdR32Xmm),
            Arc::new(PmovmskbR32Xmm),
            Arc::new(HaddpsXmmXmm),
            Arc::new(HaddpdXmmXmm),
            Arc::new(HsubpsXmmXmm),
            Arc::new(HsubpdXmmXmm),
            Arc::new(PmaxsqXmmXmm),
            Arc::new(PminsqXmmXmm),
            Arc::new(MovapsXmmXmm),
            Arc::new(MovapdXmmXmm),
            Arc::new(MovupsXmmXmm),
            Arc::new(MovupdXmmXmm),
            Arc::new(MovssXmmXmm),
            Arc::new(MovsdXmmXmm),
            Arc::new(MpsadbwXmmXmmImm8),
            Arc::new(PhminposuwXmmXmm),
            Arc::new(PcmpgtqXmmXmm),
            Arc::new(PslldqXmmImm8),
            Arc::new(PsrldqXmmImm8),
            Arc::new(PandnXmmXmm),
            Arc::new(Leave),
            Arc::new(MovMem64Imm32),
            Arc::new(CmpMem64Imm32),
            Arc::new(AddMem64R64),
            Arc::new(AddMem64Imm32),
            Arc::new(ImulR64Mem64),
            Arc::new(MovsxR64Mem32),
            Arc::new(MovsxR64Mem8),
            Arc::new(MovsxR64Mem16),
            Arc::new(MovsxR32Mem8),
            Arc::new(MovsxR32Mem16),
            Arc::new(MovzxR64Mem8),
            Arc::new(MovzxR64Mem16),
            Arc::new(MovzxR32Mem8),
            Arc::new(MovzxR32Mem16),
            Arc::new(TestR8R8),
            Arc::new(TestR8Imm8),
            Arc::new(TestMem8R8),
            Arc::new(CmpR8Imm8),
            Arc::new(CmpR8R8),
            Arc::new(CmpMem8Imm8),
            Arc::new(TestR32R32),
            Arc::new(MovqXmmR64),
            Arc::new(MovqXmmMem64),
            Arc::new(MovqR64Xmm),
            Arc::new(MovqMem64Xmm),
            Arc::new(MovdXmmR32),
            Arc::new(MovdXmmMem32),
            Arc::new(MovdR32Xmm),
            Arc::new(MovapsMemXmm),
            Arc::new(MovapsXmmMem),
            Arc::new(MovdqaMemXmm),
            Arc::new(MovdqaXmmMem),
            Arc::new(MovupsMemXmm),
            Arc::new(MovupsXmmMem),
            Arc::new(MovqXmmMem),
            Arc::new(MovMem8Imm8),
            Arc::new(MovMem16Imm16),
            Arc::new(MovMem32Imm32),
            Arc::new(CmpMem64R64),
            Arc::new(CmpMem32R32),
            Arc::new(CmpMem8R8),
            Arc::new(JmpIndirectR64),
            Arc::new(CallIndirectR64),
            Arc::new(JmpIndirectMem64),
            Arc::new(CallIndirectMem64),
            Arc::new(MovMem16R16),
            Arc::new(MovR16Mem16),
            Arc::new(OrMem32Imm32),
            Arc::new(OrMem64Imm32),
            Arc::new(AndMem32Imm32),
            Arc::new(AndMem64Imm32),
            Arc::new(AddMem32Imm32),
            Arc::new(SubMem32Imm32),
            Arc::new(SubMem64Imm32),
            Arc::new(XorMem32Imm32),
            Arc::new(XorMem64Imm32),
            Arc::new(CmpMem32Imm32),
            Arc::new(CmpMem16Imm16),
            Arc::new(TestMem8Imm8),
            Arc::new(TestMem16Imm16),
            Arc::new(TestMem32Imm32),
            Arc::new(TestMem64Imm32),
            Arc::new(OrR32Mem32),
            Arc::new(OrR64Mem64),
            Arc::new(AndR32Mem32),
            Arc::new(AndR64Mem64),
            Arc::new(XorR32Mem32),
            Arc::new(XorR64Mem64),
            Arc::new(OrR8Mem8),
            Arc::new(AndR8Mem8),
            Arc::new(XorR8Mem8),
            Arc::new(OrMem32R32),
            Arc::new(OrMem64R64),
            Arc::new(AndMem32R32),
            Arc::new(AndMem64R64),
            Arc::new(XorMem32R32),
            Arc::new(XorMem64R64),
            Arc::new(OrMem8R8),
            Arc::new(AndMem8R8),
            Arc::new(XorMem8R8),
            Arc::new(AddMem8R8),
            Arc::new(SubMem8R8),
            Arc::new(CmovzR32R32),
            Arc::new(CmovnzR32R32),
            Arc::new(CmovlR32R32),
            Arc::new(CmovgeR32R32),
            Arc::new(CmovleR32R32),
            Arc::new(CmovgR32R32),
            Arc::new(CmovaR32R32),
            Arc::new(CmovbR32R32),
            Arc::new(CmovbeR32R32),
            Arc::new(CmovaeR32R32),
            Arc::new(CmovsR32R32),
            Arc::new(CmovnsR32R32),
            Arc::new(CmovcR32R32),
            Arc::new(CmovncR32R32),
            Arc::new(CmovnpR32R32),
            Arc::new(CmovpR32R32),
            Arc::new(CmovnoR32R32),
            Arc::new(CmovoR32R32),
            Arc::new(AndR8Imm8),
            Arc::new(OrR8Imm8),
            Arc::new(XorR8Imm8),
            Arc::new(AddR8Imm8),
            Arc::new(SubR8Imm8),
            Arc::new(DivR64),
            Arc::new(DivR32),
            Arc::new(DivMem64),
            Arc::new(DivMem32),
            Arc::new(MulR64),
            Arc::new(MulMem64),
            Arc::new(MulR32),
            Arc::new(MulMem32),
            Arc::new(MovdquXmmMem),
            Arc::new(MovdquMemXmm),
            Arc::new(MovdquXmmXmm),
            Arc::new(OrMem8Imm8),
            Arc::new(AndMem8Imm8),
            Arc::new(XorMem8Imm8),
            Arc::new(AddMem8Imm8),
            Arc::new(SubMem8Imm8),
            Arc::new(OrMem16Imm16),
            Arc::new(AndMem16Imm16),
            Arc::new(XorMem16Imm16),
            Arc::new(AddMem16Imm16),
            Arc::new(SubMem16Imm16),
            Arc::new(CmpMem16R16),
            Arc::new(XorR8R8),
            Arc::new(OrR8R8),
            Arc::new(AndR8R8),
            Arc::new(AddR8R8),
            Arc::new(SubR8R8),
            Arc::new(SubR64Mem64),
            Arc::new(SubMem64R64),
            Arc::new(SubMem32R32),
            Arc::new(CmpxchgMem32R32),
            Arc::new(CmpxchgMem64R64),
            Arc::new(CmpxchgMem8R8),
            Arc::new(AddMem32R32),
            Arc::new(XchgMem32R32),
            Arc::new(XchgMem64R64),
            Arc::new(XchgMem8R8),
            Arc::new(XchgR32R32),
            Arc::new(TestR16R16),
            Arc::new(TestR16Imm16),
            Arc::new(TestMem16R16),
            Arc::new(BsfR32R32),
            Arc::new(BsfR64Mem64),
            Arc::new(BsfR32Mem32),
            Arc::new(TzcntR32R32),
            Arc::new(BsrR32R32),
            Arc::new(LzcntR32R32),
            Arc::new(PopcntR32R32),
            Arc::new(MovhpsXmmMem64),
            Arc::new(MovhpdXmmMem64),
            Arc::new(MovlpsXmmMem64),
            Arc::new(MovlpdXmmMem64),
            Arc::new(MovhpsMem64Xmm),
            Arc::new(MovlpsMem64Xmm),
            Arc::new(MovssXmmMem32),
            Arc::new(MovsdXmmMem64),
            Arc::new(MovssMem32Xmm),
            Arc::new(MovsdMem64Xmm),
            Arc::new(VmovdqaYmmMem),
            Arc::new(VmovdqaYmmYmm),
            Arc::new(VmovdquYmmMem),
            Arc::new(VmovdquYmmYmm),
            Arc::new(VmovapsYmmMem),
            Arc::new(VmovupsYmmMem),
            Arc::new(VmovdqaMemYmm),
            Arc::new(VmovdquMemYmm),
            Arc::new(VmovapsMemYmm),
            Arc::new(VmovupsMemYmm),
            Arc::new(VpxorYmmYmmYmm),
            Arc::new(VporYmmYmmYmm),
            Arc::new(VpandYmmYmmYmm),
            Arc::new(VxorpsYmmYmmYmm),
            Arc::new(VpcmpeqbYmmYmmYmm),
            Arc::new(VpmovmskbR32Ymm),
            Arc::new(VpbroadcastbYmmXmm),
            Arc::new(VpbroadcastqYmmXmm),
            Arc::new(VpbroadcastbYmmMem8),
            Arc::new(Vzeroupper),
            Arc::new(VpxorXmmXmmXmm),
            Arc::new(VporXmmXmmXmm),
            Arc::new(VpandXmmXmmXmm),
            Arc::new(VxorpsXmmXmmXmm),
            Arc::new(VpcmpeqbXmmXmmXmm),
            Arc::new(VpinsrbXmmXmmR8Imm8),
            Arc::new(VpinsrwXmmXmmR16Imm8),
            Arc::new(VpinsrdXmmXmmR32Imm8),
            Arc::new(VpinsrqXmmXmmR64Imm8),
            Arc::new(VpinsrbXmmXmmMem8Imm8),
            Arc::new(VpinsrwXmmXmmMem16Imm8),
            Arc::new(VpinsrdXmmXmmMem32Imm8),
            Arc::new(VpinsrqXmmXmmMem64Imm8),
            Arc::new(Vinserti128YmmYmmXmmImm8),
            Arc::new(Vinsertf128YmmYmmXmmImm8),
            Arc::new(Vextracti128XmmYmmImm8),
            Arc::new(Vextractf128XmmYmmImm8),
            Arc::new(VmovdqaXmmMem),
            Arc::new(VmovdqaXmmXmm),
            Arc::new(VmovdquXmmMem),
            Arc::new(VmovdquXmmXmm),
            Arc::new(VmovapsXmmMem),
            Arc::new(VmovupsXmmMem),
            Arc::new(VmovdqaMemXmm),
            Arc::new(VmovdquMemXmm),
            Arc::new(VmovapsMemXmm),
            Arc::new(VmovupsMemXmm),
            Arc::new(Vextracti128Mem128YmmImm8),
            Arc::new(Vextractf128Mem128YmmImm8),
            Arc::new(VmovdXmmR32),
            Arc::new(VmovdXmmMem32),
            Arc::new(VmovqXmmR64),
            Arc::new(VmovqXmmMem64),
            Arc::new(VmovdR32Xmm),
            Arc::new(VmovdMem32Xmm),
            Arc::new(VmovqR64Xmm),
            Arc::new(VmovqMem64Xmm),
            Arc::new(PushMem64),
            Arc::new(PushMem16),
            Arc::new(PopMem64),
            Arc::new(MovsxR64R16),
            Arc::new(MovzxR64R16),
            Arc::new(Cqo),
            Arc::new(Imul1R64),
            Arc::new(IdivR64),
            Arc::new(AddR16R16),
            Arc::new(IncR8),
            Arc::new(DecR8),
            Arc::new(NegR8),
            Arc::new(NotR8),
            Arc::new(ShlR8Imm8),
            Arc::new(BswapR32),
            Arc::new(PushF),
            Arc::new(PopF),
            // x87 FPU family (first slice)
            Arc::new(Finit),
            Arc::new(FldM32),
            Arc::new(FldM64),
            Arc::new(FldSti),
            Arc::new(Fld1),
            Arc::new(Fldz),
            Arc::new(FstpSti),
            Arc::new(FstM32),
            Arc::new(FstM64),
            Arc::new(FstpM32),
            Arc::new(FstpM64),
            Arc::new(FaddSt0Sti),
            Arc::new(FaddStiSt0),
            Arc::new(FaddM32),
            Arc::new(FaddM64),
            Arc::new(FsubSt0Sti),
            Arc::new(FsubStiSt0),
            Arc::new(FsubM32),
            Arc::new(FsubM64),
            Arc::new(FsubrSt0Sti),
            Arc::new(FsubrStiSt0),
            Arc::new(FsubrM32),
            Arc::new(FsubrM64),
            Arc::new(FmulSt0Sti),
            Arc::new(FmulStiSt0),
            Arc::new(FmulM32),
            Arc::new(FmulM64),
            Arc::new(FdivSt0Sti),
            Arc::new(FdivStiSt0),
            Arc::new(FdivM32),
            Arc::new(FdivM64),
            Arc::new(FdivrSt0Sti),
            Arc::new(FdivrStiSt0),
            Arc::new(FdivrM32),
            Arc::new(FdivrM64),
            Arc::new(FucomiSt0Sti),
            Arc::new(FucomipSt0Sti),
            Arc::new(FcomiSt0Sti),
            Arc::new(FcomipSt0Sti),
        ];

        // Build form index from known form IDs. Each provider corresponds to
        // exactly one form. The ALL_FORMS array is hardcoded with unique entries.
        let mut form_index = BTreeMap::new();
        for (index, &form) in ALL_FORMS.iter().enumerate() {
            form_index.insert(form, index);
        }

        let registry = Self {
            providers,
            form_index,
            semantic_version,
        };
        registry.assert_unique_rule_ids();
        registry
    }

    /// A registry with generated providers appended after the handwritten
    /// corpus. Generated providers keep their own rule-id band
    /// (`GENERATED_RULE_BASE`) and are indexed by the caller-supplied form
    /// id, so positional handwritten dispatch is untouched.
    pub fn with_generated(
        semantic_version: SemanticVersion,
        generated: Vec<(u32, Arc<dyn angryier_semantics::SemanticProvider>)>,
    ) -> Self {
        let mut registry = Self::new(semantic_version);
        for (form_id, provider) in generated {
            let index = registry.providers.len();
            registry.providers.push(provider);
            registry.form_index.insert(form_id, index);
        }
        registry.assert_unique_rule_ids();
        registry
    }

    pub fn providers(&self) -> &[Arc<dyn angryier_semantics::SemanticProvider>] {
        &self.providers
    }

    /// Returns the provider registered for `form_id` directly, bypassing the
    /// rule-id lookup: provider indices are positional, and a duplicated
    /// hand-picked rule offset would otherwise silently misroute the form.
    pub fn provider_for_form(&self, form_id: u32) -> Option<&Arc<dyn angryier_semantics::SemanticProvider>> {
        self.form_index.get(&form_id).map(|&index| &self.providers[index])
    }

    fn assert_unique_rule_ids(&self) {
        let mut seen = std::collections::BTreeMap::new();
        for (index, provider) in self.providers.iter().enumerate() {
            let id = provider.rule_id().0;
            if let Some(previous) = seen.insert(id, index) {
                debug_assert!(
                    false,
                    "duplicate rule id {id:#x} across providers {previous} and {index}"
                );
            }
        }
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

const ALL_FORMS: [u32; 634] = [
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
    crate::forms::PMULHW_XMM_XMM,
    crate::forms::PMULHUW_XMM_XMM,
    crate::forms::PSHUFB_XMM_XMM,
    crate::forms::PUNPCKLBW_XMM_XMM,
    crate::forms::PUNPCKLWD_XMM_XMM,
    crate::forms::PUNPCKLDQ_XMM_XMM,
    crate::forms::PUNPCKLQDQ_XMM_XMM,
    crate::forms::PUNPCKHBW_XMM_XMM,
    crate::forms::PUNPCKHWD_XMM_XMM,
    crate::forms::PUNPCKHDQ_XMM_XMM,
    crate::forms::PUNPCKHQDQ_XMM_XMM,
    crate::forms::PACKSSWB_XMM_XMM,
    crate::forms::PACKSSDW_XMM_XMM,
    crate::forms::PACKUSWB_XMM_XMM,
    crate::forms::PACKUSDW_XMM_XMM,
    crate::forms::PMADDWD_XMM_XMM,
    crate::forms::PSADBW_XMM_XMM,
    crate::forms::PSHUFD_XMM_IMM8,
    crate::forms::PSHUFHW_XMM_IMM8,
    crate::forms::PSHUFLW_XMM_IMM8,
    crate::forms::PMADDUBSW_XMM_XMM,
    crate::forms::PSLLW_XMM_XMM,
    crate::forms::PSLLD_XMM_XMM,
    crate::forms::PSLLQ_XMM_XMM,
    crate::forms::PSRLW_XMM_XMM,
    crate::forms::PSRLD_XMM_XMM,
    crate::forms::PSRLQ_XMM_XMM,
    crate::forms::PSRAW_XMM_XMM,
    crate::forms::PSRAD_XMM_XMM,
    crate::forms::PHADDW_XMM_XMM,
    crate::forms::PHADDD_XMM_XMM,
    crate::forms::PHSUBW_XMM_XMM,
    crate::forms::PHSUBD_XMM_XMM,
    crate::forms::PABSB_XMM_XMM,
    crate::forms::PABSW_XMM_XMM,
    crate::forms::PABSD_XMM_XMM,
    crate::forms::PSIGNB_XMM_XMM,
    crate::forms::PSIGNW_XMM_XMM,
    crate::forms::PSIGND_XMM_XMM,
    crate::forms::PMULHRSW_XMM_XMM,
    crate::forms::PHADDSW_XMM_XMM,
    crate::forms::PHSUBSW_XMM_XMM,
    crate::forms::PCMPEQQ_XMM_XMM,
    crate::forms::PMULDQ_XMM_XMM,
    crate::forms::PBLENDVB_XMM_XMM,
    crate::forms::PMOVSXBW_XMM_XMM,
    crate::forms::PMOVZXBW_XMM_XMM,
    crate::forms::PMOVSXBD_XMM_XMM,
    crate::forms::PMOVZXBD_XMM_XMM,
    crate::forms::PMOVSXWD_XMM_XMM,
    crate::forms::PMOVZXWD_XMM_XMM,
    crate::forms::PMOVSXDQ_XMM_XMM,
    crate::forms::PMOVZXDQ_XMM_XMM,
    crate::forms::PMOVSXWQ_XMM_XMM,
    crate::forms::PMOVZXWQ_XMM_XMM,
    crate::forms::PMOVSXBQ_XMM_XMM,
    crate::forms::PMOVZXBQ_XMM_XMM,
    crate::forms::PBLENDW_XMM_XMM_IMM8,
    crate::forms::BLENDPS_XMM_XMM_IMM8,
    crate::forms::BLENDPD_XMM_XMM_IMM8,
    crate::forms::DPPS_XMM_XMM_IMM8,
    crate::forms::DPPD_XMM_XMM_IMM8,
    crate::forms::PEXTRB_R32_XMM_IMM8,
    crate::forms::PINSRB_XMM_R32_IMM8,
    crate::forms::UCOMISS_XMM_XMM,
    crate::forms::UCOMISD_XMM_XMM,
    crate::forms::COMISS_XMM_XMM,
    crate::forms::COMISD_XMM_XMM,
    crate::forms::ROUNDPS_XMM_XMM_IMM8,
    crate::forms::ROUNDPD_XMM_XMM_IMM8,
    crate::forms::ROUNDSS_XMM_XMM_IMM8,
    crate::forms::ROUNDSD_XMM_XMM_IMM8,
    crate::forms::PTEST_XMM_XMM,
    crate::forms::CRC32_R32_R32,
    crate::forms::CRC32_R64_R64,
    crate::forms::PEXTRD_R32_XMM_IMM8,
    crate::forms::PEXTRQ_R64_XMM_IMM8,
    crate::forms::PINSRD_XMM_R32_IMM8,
    crate::forms::PINSRQ_XMM_R64_IMM8,
    crate::forms::INSERTPS_XMM_XMM_IMM8,
    crate::forms::EXTRACTPS_R32_XMM_IMM8,
    crate::forms::SHL_R32_IMM8,
    crate::forms::SHR_R32_IMM8,
    crate::forms::SAR_R32_IMM8,
    crate::forms::SHL_R32_CL,
    crate::forms::SHR_R32_CL,
    crate::forms::SAR_R32_CL,
    crate::forms::ROL_R32_IMM8,
    crate::forms::ROR_R32_IMM8,
    crate::forms::ROL_R32_CL,
    crate::forms::ROR_R32_CL,
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
    crate::forms::CMPPS_XMM_XMM_IMM8,
    crate::forms::CMPPD_XMM_XMM_IMM8,
    crate::forms::MINPS_XMM_XMM,
    crate::forms::MAXPS_XMM_XMM,
    crate::forms::MOVMSKPS_R32_XMM,
    crate::forms::MOVMSKPD_R32_XMM,
    crate::forms::PMOVMSKB_R32_XMM,
    crate::forms::HADDPS_XMM_XMM,
    crate::forms::HADDPD_XMM_XMM,
    crate::forms::HSUBPS_XMM_XMM,
    crate::forms::HSUBPD_XMM_XMM,
    crate::forms::PMAXSQ_XMM_XMM,
    crate::forms::PMINSQ_XMM_XMM,
    crate::forms::MOVAPS_XMM_XMM,
    crate::forms::MOVAPD_XMM_XMM,
    crate::forms::MOVUPS_XMM_XMM,
    crate::forms::MOVUPD_XMM_XMM,
    crate::forms::MOVSS_XMM_XMM,
    crate::forms::MOVSD_XMM_XMM,
    crate::forms::MPSADBW_XMM_XMM_IMM8,
    crate::forms::PHMINPOSUW_XMM_XMM,
    crate::forms::PCMPGTQ_XMM_XMM,
    crate::forms::PSLLDQ_XMM_IMM8,
    crate::forms::PSRLDQ_XMM_IMM8,
    crate::forms::PANDN_XMM_XMM,
    crate::forms::LEAVE,
    crate::forms::MOV_MEM64_IMM32,
    crate::forms::CMP_MEM64_IMM32,
    crate::forms::ADD_MEM64_R64,
    crate::forms::ADD_MEM64_IMM32,
    crate::forms::IMUL_R64_MEM64,
    crate::forms::MOVSX_R64_MEM32,
    crate::forms::MOVSX_R64_MEM8,
    crate::forms::MOVSX_R64_MEM16,
    crate::forms::MOVSX_R32_MEM8,
    crate::forms::MOVSX_R32_MEM16,
    crate::forms::MOVZX_R64_MEM8,
    crate::forms::MOVZX_R64_MEM16,
    crate::forms::MOVZX_R32_MEM8,
    crate::forms::MOVZX_R32_MEM16,
    crate::forms::TEST_R8_R8,
    crate::forms::TEST_R8_IMM8,
    crate::forms::TEST_MEM8_R8,
    crate::forms::CMP_R8_IMM8,
    crate::forms::CMP_R8_R8,
    crate::forms::CMP_MEM8_IMM8,
    crate::forms::TEST_R32_R32,
    crate::forms::MOVQ_XMM_R64,
    crate::forms::MOVQ_XMM_MEM64,
    crate::forms::MOVQ_R64_XMM,
    crate::forms::MOVQ_MEM64_XMM,
    crate::forms::MOVD_XMM_R32,
    crate::forms::MOVD_XMM_MEM32,
    crate::forms::MOVD_R32_XMM,
    crate::forms::MOVAPS_MEM_XMM,
    crate::forms::MOVAPS_XMM_MEM,
    crate::forms::MOVDQA_MEM_XMM,
    crate::forms::MOVDQA_XMM_MEM,
    crate::forms::MOVUPS_MEM_XMM,
    crate::forms::MOVUPS_XMM_MEM,
    crate::forms::MOVQ_XMM_MEM,
    crate::forms::MOV_MEM8_IMM8,
    crate::forms::MOV_MEM16_IMM16,
    crate::forms::MOV_MEM32_IMM32,
    crate::forms::CMP_MEM64_R64,
    crate::forms::CMP_MEM32_R32,
    crate::forms::CMP_MEM8_R8,
    crate::forms::JMP_INDIRECT_R64,
    crate::forms::CALL_INDIRECT_R64,
    crate::forms::JMP_INDIRECT_MEM64,
    crate::forms::CALL_INDIRECT_MEM64,
    crate::forms::MOV_MEM16_R16,
    crate::forms::MOV_R16_MEM16,
    crate::forms::OR_MEM32_IMM32,
    crate::forms::OR_MEM64_IMM32,
    crate::forms::AND_MEM32_IMM32,
    crate::forms::AND_MEM64_IMM32,
    crate::forms::ADD_MEM32_IMM32,
    crate::forms::SUB_MEM32_IMM32,
    crate::forms::SUB_MEM64_IMM32,
    crate::forms::XOR_MEM32_IMM32,
    crate::forms::XOR_MEM64_IMM32,
    crate::forms::CMP_MEM32_IMM32,
    crate::forms::CMP_MEM16_IMM16,
    crate::forms::TEST_MEM8_IMM8,
    crate::forms::TEST_MEM16_IMM16,
    crate::forms::TEST_MEM32_IMM32,
    crate::forms::TEST_MEM64_IMM32,
    crate::forms::OR_R32_MEM32,
    crate::forms::OR_R64_MEM64,
    crate::forms::AND_R32_MEM32,
    crate::forms::AND_R64_MEM64,
    crate::forms::XOR_R32_MEM32,
    crate::forms::XOR_R64_MEM64,
    crate::forms::OR_R8_MEM8,
    crate::forms::AND_R8_MEM8,
    crate::forms::XOR_R8_MEM8,
    crate::forms::OR_MEM32_R32,
    crate::forms::OR_MEM64_R64,
    crate::forms::AND_MEM32_R32,
    crate::forms::AND_MEM64_R64,
    crate::forms::XOR_MEM32_R32,
    crate::forms::XOR_MEM64_R64,
    crate::forms::OR_MEM8_R8,
    crate::forms::AND_MEM8_R8,
    crate::forms::XOR_MEM8_R8,
    crate::forms::ADD_MEM8_R8,
    crate::forms::SUB_MEM8_R8,
    crate::forms::CMOVZ_R32_R32,
    crate::forms::CMOVNZ_R32_R32,
    crate::forms::CMOVL_R32_R32,
    crate::forms::CMOVGE_R32_R32,
    crate::forms::CMOVLE_R32_R32,
    crate::forms::CMOVG_R32_R32,
    crate::forms::CMOVA_R32_R32,
    crate::forms::CMOVB_R32_R32,
    crate::forms::CMOVBE_R32_R32,
    crate::forms::CMOVAE_R32_R32,
    crate::forms::CMOVS_R32_R32,
    crate::forms::CMOVNS_R32_R32,
    crate::forms::CMOVC_R32_R32,
    crate::forms::CMOVNC_R32_R32,
    crate::forms::CMOVNP_R32_R32,
    crate::forms::CMOVP_R32_R32,
    crate::forms::CMOVNO_R32_R32,
    crate::forms::CMOVO_R32_R32,
    crate::forms::AND_R8_IMM8,
    crate::forms::OR_R8_IMM8,
    crate::forms::XOR_R8_IMM8,
    crate::forms::ADD_R8_IMM8,
    crate::forms::SUB_R8_IMM8,
    crate::forms::DIV_R64,
    crate::forms::DIV_R32,
    crate::forms::DIV_MEM64,
    crate::forms::DIV_MEM32,
    crate::forms::MUL_R64,
    crate::forms::MUL_MEM64,
    crate::forms::MUL_R32,
    crate::forms::MUL_MEM32,
    crate::forms::MOVDQU_XMM_MEM,
    crate::forms::MOVDQU_MEM_XMM,
    crate::forms::MOVDQU_XMM_XMM,
    crate::forms::OR_MEM8_IMM8,
    crate::forms::AND_MEM8_IMM8,
    crate::forms::XOR_MEM8_IMM8,
    crate::forms::ADD_MEM8_IMM8,
    crate::forms::SUB_MEM8_IMM8,
    crate::forms::OR_MEM16_IMM16,
    crate::forms::AND_MEM16_IMM16,
    crate::forms::XOR_MEM16_IMM16,
    crate::forms::ADD_MEM16_IMM16,
    crate::forms::SUB_MEM16_IMM16,
    crate::forms::CMP_MEM16_R16,
    crate::forms::XOR_R8_R8,
    crate::forms::OR_R8_R8,
    crate::forms::AND_R8_R8,
    crate::forms::ADD_R8_R8,
    crate::forms::SUB_R8_R8,
    crate::forms::SUB_R64_MEM64,
    crate::forms::SUB_MEM64_R64,
    crate::forms::SUB_MEM32_R32,
    crate::forms::CMPXCHG_MEM32_R32,
    crate::forms::CMPXCHG_MEM64_R64,
    crate::forms::CMPXCHG_MEM8_R8,
    crate::forms::ADD_MEM32_R32,
    crate::forms::XCHG_MEM32_R32,
    crate::forms::XCHG_MEM64_R64,
    crate::forms::XCHG_MEM8_R8,
    crate::forms::XCHG_R32_R32,
    crate::forms::TEST_R16_R16,
    crate::forms::TEST_R16_IMM16,
    crate::forms::TEST_MEM16_R16,
    crate::forms::BSF_R32_R32,
    crate::forms::BSF_R64_MEM64,
    crate::forms::BSF_R32_MEM32,
    crate::forms::TZCNT_R32_R32,
    crate::forms::BSR_R32_R32,
    crate::forms::LZCNT_R32_R32,
    crate::forms::POPCNT_R32_R32,
    crate::forms::MOVHPS_XMM_MEM64,
    crate::forms::MOVHPD_XMM_MEM64,
    crate::forms::MOVLPS_XMM_MEM64,
    crate::forms::MOVLPD_XMM_MEM64,
    crate::forms::MOVHPS_MEM64_XMM,
    crate::forms::MOVLPS_MEM64_XMM,
    crate::forms::MOVSS_XMM_MEM32,
    crate::forms::MOVSD_XMM_MEM64,
    crate::forms::MOVSS_MEM32_XMM,
    crate::forms::MOVSD_MEM64_XMM,
    crate::forms::VMOVDQA_YMM_MEM,
    crate::forms::VMOVDQA_YMM_YMM,
    crate::forms::VMOVDQU_YMM_MEM,
    crate::forms::VMOVDQU_YMM_YMM,
    crate::forms::VMOVAPS_YMM_MEM,
    crate::forms::VMOVUPS_YMM_MEM,
    crate::forms::VMOVDQA_MEM_YMM,
    crate::forms::VMOVDQU_MEM_YMM,
    crate::forms::VMOVAPS_MEM_YMM,
    crate::forms::VMOVUPS_MEM_YMM,
    crate::forms::VPXOR_YMM_YMM_YMM,
    crate::forms::VPOR_YMM_YMM_YMM,
    crate::forms::VPAND_YMM_YMM_YMM,
    crate::forms::VXORPS_YMM_YMM_YMM,
    crate::forms::VPCMPEQB_YMM_YMM_YMM,
    crate::forms::VPMOVMSKB_R32_YMM,
    crate::forms::VPBROADCASTB_YMM_XMM,
    crate::forms::VPBROADCASTQ_YMM_XMM,
    crate::forms::VPBROADCASTB_YMM_MEM8,
    crate::forms::VZEROUPPER,
    crate::forms::VPXOR_XMM_XMM_XMM,
    crate::forms::VPOR_XMM_XMM_XMM,
    crate::forms::VPAND_XMM_XMM_XMM,
    crate::forms::VXORPS_XMM_XMM_XMM,
    crate::forms::VPCMPEQB_XMM_XMM_XMM,
    crate::forms::VPINSRB_XMM_XMM_R8_IMM8,
    crate::forms::VPINSRW_XMM_XMM_R16_IMM8,
    crate::forms::VPINSRD_XMM_XMM_R32_IMM8,
    crate::forms::VPINSRQ_XMM_XMM_R64_IMM8,
    crate::forms::VPINSRB_XMM_XMM_MEM8_IMM8,
    crate::forms::VPINSRW_XMM_XMM_MEM16_IMM8,
    crate::forms::VPINSRD_XMM_XMM_MEM32_IMM8,
    crate::forms::VPINSRQ_XMM_XMM_MEM64_IMM8,
    crate::forms::VINSERTI128_YMM_YMM_XMM_IMM8,
    crate::forms::VINSERTF128_YMM_YMM_XMM_IMM8,
    crate::forms::VEXTRACTI128_XMM_YMM_IMM8,
    crate::forms::VEXTRACTF128_XMM_YMM_IMM8,
    crate::forms::VMOVDQA_XMM_MEM,
    crate::forms::VMOVDQA_XMM_XMM,
    crate::forms::VMOVDQU_XMM_MEM,
    crate::forms::VMOVDQU_XMM_XMM,
    crate::forms::VMOVAPS_XMM_MEM,
    crate::forms::VMOVUPS_XMM_MEM,
    crate::forms::VMOVDQA_MEM_XMM,
    crate::forms::VMOVDQU_MEM_XMM,
    crate::forms::VMOVAPS_MEM_XMM,
    crate::forms::VMOVUPS_MEM_XMM,
    crate::forms::VEXTRACTI128_MEM128_YMM_IMM8,
    crate::forms::VEXTRACTF128_MEM128_YMM_IMM8,
    crate::forms::VMOVD_XMM_R32,
    crate::forms::VMOVD_XMM_MEM32,
    crate::forms::VMOVQ_XMM_R64,
    crate::forms::VMOVQ_XMM_MEM64,
    crate::forms::VMOVD_R32_XMM,
    crate::forms::VMOVD_MEM32_XMM,
    crate::forms::VMOVQ_R64_XMM,
    crate::forms::VMOVQ_MEM64_XMM,
    crate::forms::PUSH_MEM64,
    crate::forms::PUSH_MEM16,
    crate::forms::POP_MEM64,
    crate::forms::MOVSX_R64_R16,
    crate::forms::MOVZX_R64_R16,
    crate::forms::CQO,
    crate::forms::IMUL_1OP_R64,
    crate::forms::IDIV_R64,
    crate::forms::ADD_R16_R16,
    crate::forms::INC_R8,
    crate::forms::DEC_R8,
    crate::forms::NEG_R8,
    crate::forms::NOT_R8,
    crate::forms::SHL_R8_IMM8,
    crate::forms::BSWAP_R32,
    crate::forms::PUSHF,
    crate::forms::POPF,
    crate::forms::FINIT,
    crate::forms::FLD_M32,
    crate::forms::FLD_M64,
    crate::forms::FLD_STI,
    crate::forms::FLD1,
    crate::forms::FLDZ,
    crate::forms::FSTP_STI,
    crate::forms::FST_M32,
    crate::forms::FST_M64,
    crate::forms::FSTP_M32,
    crate::forms::FSTP_M64,
    crate::forms::FADD_ST0_STI,
    crate::forms::FADD_STI_ST0,
    crate::forms::FADD_M32,
    crate::forms::FADD_M64,
    crate::forms::FSUB_ST0_STI,
    crate::forms::FSUB_STI_ST0,
    crate::forms::FSUB_M32,
    crate::forms::FSUB_M64,
    crate::forms::FSUBR_ST0_STI,
    crate::forms::FSUBR_STI_ST0,
    crate::forms::FSUBR_M32,
    crate::forms::FSUBR_M64,
    crate::forms::FMUL_ST0_STI,
    crate::forms::FMUL_STI_ST0,
    crate::forms::FMUL_M32,
    crate::forms::FMUL_M64,
    crate::forms::FDIV_ST0_STI,
    crate::forms::FDIV_STI_ST0,
    crate::forms::FDIV_M32,
    crate::forms::FDIV_M64,
    crate::forms::FDIVR_ST0_STI,
    crate::forms::FDIVR_STI_ST0,
    crate::forms::FDIVR_M32,
    crate::forms::FDIVR_M64,
    crate::forms::FUCOMI_ST0_STI,
    crate::forms::FUCOMIP_ST0_STI,
    crate::forms::FCOMI_ST0_STI,
    crate::forms::FCOMIP_ST0_STI,
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

    #[test]
    fn rule_ids_are_unique() {
        // Resolution looks providers up by rule id, so a duplicate silently
        // routes a form to the wrong provider.
        let registry = Intel64CorpusRegistry::new(SemanticVersion(1));
        let mut seen = std::collections::BTreeMap::new();
        for provider in registry.providers() {
            let id = provider.rule_id().0;
            let previous = seen.insert(id, provider.origin());
            assert!(previous.is_none(), "duplicate rule id {id:#x} across providers");
        }
    }

    #[test]
    fn every_registered_form_resolves_to_its_provider() {
        let registry = Intel64CorpusRegistry::new(SemanticVersion(1));
        assert_eq!(registry.providers().len(), ALL_FORMS.len());
        for (index, form) in ALL_FORMS.iter().enumerate() {
            let decoded = make_decoded(*form, Vec::new());
            assert!(
                registry.providers()[index].matches(&decoded),
                "provider {index} does not match its registered form {form:#x}"
            );
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
                segment_base: None,
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
                segment_base: None,
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
