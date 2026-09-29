#![forbid(unsafe_code)]
#![allow(dead_code)]

//! Intel Advanced Matrix Extensions (AMX) semantic providers.
//!
//! Covers:
//! - AMX-TILE: LDTILECFG, STTILECFG, TILERELEASE, TILEZERO, TILELOADD, TILELOADDT1, TILESTORED
//! - AMX-INT8: TDPBSSD, TDPBSUD, TDPBUSD, TDPBUUD
//! - AMX-BF16: TDPBF16PS
//! - AMX-FP16: TDPFP16PS

use angryier_arch_intel64::register_id;
use angryier_semantics::{
    DecodedInstructionView, ScalarType, SemanticBuilder, SemanticContext, SemanticError, SemanticOp, SemanticOrigin,
    SemanticProvider, SemanticReceipt, SemanticType, SideEffect, TileOp,
};
use angryier_types::SemanticRuleId;
use std::sync::Arc;

pub const CORPUS_RULE_BASE: u64 = 0x1000;

pub const fn rule_id(offset: u64) -> SemanticRuleId {
    SemanticRuleId(CORPUS_RULE_BASE + offset)
}

/// AMX form identifiers.
pub mod forms {
    pub const LDTILECFG_MEM: u32 = 0x1200;
    pub const STTILECFG_MEM: u32 = 0x1201;
    pub const TILERELEASE: u32 = 0x1202;
    pub const TILEZERO_TMM: u32 = 0x1203;
    pub const TILELOADD_TMM_MEM: u32 = 0x1204;
    pub const TILELOADDT1_TMM_MEM: u32 = 0x1205;
    pub const TILESTORED_MEM_TMM: u32 = 0x1206;
    pub const TDPBSSD_TMM_TMM_TMM: u32 = 0x1207;
    pub const TDPBSUD_TMM_TMM_TMM: u32 = 0x1208;
    pub const TDPBUSD_TMM_TMM_TMM: u32 = 0x1209;
    pub const TDPBUUD_TMM_TMM_TMM: u32 = 0x120A;
    pub const TDPBF16PS_TMM_TMM_TMM: u32 = 0x120B;
    pub const TDPFP16PS_TMM_TMM_TMM: u32 = 0x120C;
}

const TILE_TYPE: SemanticType = SemanticType::Tile {
    rows: 16,
    bytes_per_row: 64,
    element: ScalarType::BitVec(8),
};

const U512: SemanticType = SemanticType::Scalar(ScalarType::BitVec(512));
const U64: SemanticType = SemanticType::Scalar(ScalarType::BitVec(64));

fn fall_through(out: &mut dyn SemanticBuilder, insn: &dyn DecodedInstructionView) -> Result<(), SemanticError> {
    let next_pc = out.constant(
        U64,
        &insn.address().wrapping_add(u64::from(insn.length())).to_le_bytes(),
    )?;
    out.jump(next_pc)?;
    Ok(())
}

macro_rules! amx_provider {
    ($name:ident, $rule_offset:expr, $form_id:expr, $body:expr) => {
        #[derive(Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId {
                rule_id($rule_offset)
            }

            fn origin(&self) -> SemanticOrigin {
                SemanticOrigin::HandwrittenOverride
            }

            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
                insn.form_id() == $form_id
            }

            fn emit(
                &self,
                context: &SemanticContext,
                insn: &dyn DecodedInstructionView,
                out: &mut dyn SemanticBuilder,
            ) -> Result<SemanticReceipt, SemanticError> {
                let _ = (context, insn);
                #[allow(clippy::redundant_closure_call)]
                $body(out, insn)?;
                fall_through(out, insn)?;
                Ok(SemanticReceipt {
                    rule_id: self.rule_id(),
                    origin: self.origin(),
                    semantic_version: context.semantic_version,
                })
            }
        }
    };
}

amx_provider!(
    LdtilecfgMemProvider,
    0x1800,
    forms::LDTILECFG_MEM,
    |out: &mut dyn SemanticBuilder, _insn: &dyn DecodedInstructionView| {
        let cfg = out.read_operand(0, U512)?;
        out.write_register(register_id::TILECFG, cfg)?;
        out.side_effect(SideEffect::UpdateTileConfig, &[])?;
        Ok::<(), SemanticError>(())
    }
);

amx_provider!(
    SttilecfgMemProvider,
    0x1801,
    forms::STTILECFG_MEM,
    |out: &mut dyn SemanticBuilder, _insn: &dyn DecodedInstructionView| {
        let cfg = out.read_register(register_id::TILECFG, U512)?;
        out.write_operand(0, cfg)?;
        out.side_effect(SideEffect::MemoryWrite, &[])?;
        Ok::<(), SemanticError>(())
    }
);

amx_provider!(
    TilereleaseProvider,
    0x1802,
    forms::TILERELEASE,
    |out: &mut dyn SemanticBuilder, _insn: &dyn DecodedInstructionView| {
        let zero_cfg = out.constant(U512, &[0u8; 64])?;
        out.write_register(register_id::TILECFG, zero_cfg)?;
        out.side_effect(SideEffect::UpdateTileConfig, &[])?;
        Ok::<(), SemanticError>(())
    }
);

amx_provider!(
    TilezeroTmmProvider,
    0x1803,
    forms::TILEZERO_TMM,
    |out: &mut dyn SemanticBuilder, _insn: &dyn DecodedInstructionView| {
        let zero = out.emit(SemanticOp::Tile(TileOp::Zero), TILE_TYPE, &[])?;
        out.write_operand(0, zero)?;
        Ok::<(), SemanticError>(())
    }
);

amx_provider!(
    TileloaddTmmMemProvider,
    0x1804,
    forms::TILELOADD_TMM_MEM,
    |out: &mut dyn SemanticBuilder, _insn: &dyn DecodedInstructionView| {
        let val = out.read_operand(1, TILE_TYPE)?;
        out.write_operand(0, val)?;
        out.side_effect(SideEffect::MemoryRead, &[])?;
        Ok::<(), SemanticError>(())
    }
);

amx_provider!(
    Tileloaddt1TmmMemProvider,
    0x1805,
    forms::TILELOADDT1_TMM_MEM,
    |out: &mut dyn SemanticBuilder, _insn: &dyn DecodedInstructionView| {
        let val = out.read_operand(1, TILE_TYPE)?;
        out.write_operand(0, val)?;
        out.side_effect(SideEffect::MemoryRead, &[])?;
        Ok::<(), SemanticError>(())
    }
);

amx_provider!(
    TilestoredMemTmmProvider,
    0x1806,
    forms::TILESTORED_MEM_TMM,
    |out: &mut dyn SemanticBuilder, _insn: &dyn DecodedInstructionView| {
        let val = out.read_operand(1, TILE_TYPE)?;
        out.write_operand(0, val)?;
        out.side_effect(SideEffect::MemoryWrite, &[])?;
        Ok::<(), SemanticError>(())
    }
);

macro_rules! amx_dot_provider {
    ($name:ident, $rule_offset:expr, $form_id:expr, $tile_op:expr) => {
        amx_provider!(
            $name,
            $rule_offset,
            $form_id,
            |out: &mut dyn SemanticBuilder, _insn: &dyn DecodedInstructionView| {
                let dst = out.read_operand(0, TILE_TYPE)?;
                let src1 = out.read_operand(1, TILE_TYPE)?;
                let src2 = out.read_operand(2, TILE_TYPE)?;
                let cfg = out.read_register(register_id::TILECFG, U512)?;
                let res = out.emit(SemanticOp::Tile($tile_op), TILE_TYPE, &[dst, src1, src2, cfg])?;
                out.write_operand(0, res)?;
                Ok::<(), SemanticError>(())
            }
        );
    };
}

amx_dot_provider!(
    TdpbssdTmmTmmTmmProvider,
    0x1807,
    forms::TDPBSSD_TMM_TMM_TMM,
    TileOp::DotProduct
);
amx_dot_provider!(
    TdpbsudTmmTmmTmmProvider,
    0x1808,
    forms::TDPBSUD_TMM_TMM_TMM,
    TileOp::DotS8U8
);
amx_dot_provider!(
    TdpbusdTmmTmmTmmProvider,
    0x1809,
    forms::TDPBUSD_TMM_TMM_TMM,
    TileOp::DotU8S8
);
amx_dot_provider!(
    TdpbuudTmmTmmTmmProvider,
    0x180A,
    forms::TDPBUUD_TMM_TMM_TMM,
    TileOp::DotU8U8
);
amx_dot_provider!(
    Tdpbf16psTmmTmmTmmProvider,
    0x180B,
    forms::TDPBF16PS_TMM_TMM_TMM,
    TileOp::DotBf16
);
amx_dot_provider!(
    Tdpfp16psTmmTmmTmmProvider,
    0x180C,
    forms::TDPFP16PS_TMM_TMM_TMM,
    TileOp::DotFp16
);

pub fn providers() -> Vec<Arc<dyn SemanticProvider>> {
    vec![
        Arc::new(LdtilecfgMemProvider),
        Arc::new(SttilecfgMemProvider),
        Arc::new(TilereleaseProvider),
        Arc::new(TilezeroTmmProvider),
        Arc::new(TileloaddTmmMemProvider),
        Arc::new(Tileloaddt1TmmMemProvider),
        Arc::new(TilestoredMemTmmProvider),
        Arc::new(TdpbssdTmmTmmTmmProvider),
        Arc::new(TdpbsudTmmTmmTmmProvider),
        Arc::new(TdpbusdTmmTmmTmmProvider),
        Arc::new(TdpbuudTmmTmmTmmProvider),
        Arc::new(Tdpbf16psTmmTmmTmmProvider),
        Arc::new(Tdpfp16psTmmTmmTmmProvider),
    ]
}
