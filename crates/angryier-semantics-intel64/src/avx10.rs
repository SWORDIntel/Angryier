#![forbid(unsafe_code)]
#![allow(dead_code)]

//! AVX10 (EVEX) integer vector ALU semantic providers.
//!
//! Covers EVEX-encoded vector integer ALU operations across 128-bit (XMM),
//! 256-bit (YMM), and 512-bit (ZMM) vector lengths with opmasking ({k1..k7})
//! and zeroing masking ({z}) support:
//! - Vector addition/subtraction: VPADDB, VPADDW, VPADDD, VPADDQ,
//!   VPSUBB, VPSUBW, VPSUBD, VPSUBQ
//! - Vector bitwise logic: VPANDD, VPANDQ, VPANDND, VPANDNQ,
//!   VPORD, VPORQ, VPXORD, VPXORQ
//! - Vector min/max: VPMINSD, VPMINUD, VPMAXSD, VPMAXUD

use angryier_semantics::{
    DecodedInstructionView, PrimitiveOp, ScalarType, SemanticBuilder, SemanticContext, SemanticError, SemanticOp,
    SemanticOrigin, SemanticProvider, SemanticReceipt, SemanticType, ValueId, VectorOp,
};
use angryier_types::SemanticRuleId;
use std::sync::Arc;

pub const AVX10_RULE_BASE: u64 = 0x2C00;

pub const fn rule_id(offset: u64) -> SemanticRuleId {
    SemanticRuleId(AVX10_RULE_BASE + offset)
}

/// AVX10 EVEX form identifiers.
pub mod forms {
    // Vector addition (0x1300..0x130B)
    pub const VPADDB_XMM_XMM_XMM: u32 = 0x1300;
    pub const VPADDB_YMM_YMM_YMM: u32 = 0x1301;
    pub const VPADDB_ZMM_ZMM_ZMM: u32 = 0x1302;
    pub const VPADDW_XMM_XMM_XMM: u32 = 0x1303;
    pub const VPADDW_YMM_YMM_YMM: u32 = 0x1304;
    pub const VPADDW_ZMM_ZMM_ZMM: u32 = 0x1305;
    pub const VPADDD_XMM_XMM_XMM: u32 = 0x1306;
    pub const VPADDD_YMM_YMM_YMM: u32 = 0x1307;
    pub const VPADDD_ZMM_ZMM_ZMM: u32 = 0x1308;
    pub const VPADDQ_XMM_XMM_XMM: u32 = 0x1309;
    pub const VPADDQ_YMM_YMM_YMM: u32 = 0x130A;
    pub const VPADDQ_ZMM_ZMM_ZMM: u32 = 0x130B;

    // Vector subtraction (0x130C..0x1317)
    pub const VPSUBB_XMM_XMM_XMM: u32 = 0x130C;
    pub const VPSUBB_YMM_YMM_YMM: u32 = 0x130D;
    pub const VPSUBB_ZMM_ZMM_ZMM: u32 = 0x130E;
    pub const VPSUBW_XMM_XMM_XMM: u32 = 0x130F;
    pub const VPSUBW_YMM_YMM_YMM: u32 = 0x1310;
    pub const VPSUBW_ZMM_ZMM_ZMM: u32 = 0x1311;
    pub const VPSUBD_XMM_XMM_XMM: u32 = 0x1312;
    pub const VPSUBD_YMM_YMM_YMM: u32 = 0x1313;
    pub const VPSUBD_ZMM_ZMM_ZMM: u32 = 0x1314;
    pub const VPSUBQ_XMM_XMM_XMM: u32 = 0x1315;
    pub const VPSUBQ_YMM_YMM_YMM: u32 = 0x1316;
    pub const VPSUBQ_ZMM_ZMM_ZMM: u32 = 0x1317;

    // Vector bitwise logic (0x1318..0x132F)
    pub const VPANDD_XMM_XMM_XMM: u32 = 0x1318;
    pub const VPANDD_YMM_YMM_YMM: u32 = 0x1319;
    pub const VPANDD_ZMM_ZMM_ZMM: u32 = 0x131A;
    pub const VPANDQ_XMM_XMM_XMM: u32 = 0x131B;
    pub const VPANDQ_YMM_YMM_YMM: u32 = 0x131C;
    pub const VPANDQ_ZMM_ZMM_ZMM: u32 = 0x131D;
    pub const VPANDND_XMM_XMM_XMM: u32 = 0x131E;
    pub const VPANDND_YMM_YMM_YMM: u32 = 0x131F;
    pub const VPANDND_ZMM_ZMM_ZMM: u32 = 0x1320;
    pub const VPANDNQ_XMM_XMM_XMM: u32 = 0x1321;
    pub const VPANDNQ_YMM_YMM_YMM: u32 = 0x1322;
    pub const VPANDNQ_ZMM_ZMM_ZMM: u32 = 0x1323;
    pub const VPORD_XMM_XMM_XMM: u32 = 0x1324;
    pub const VPORD_YMM_YMM_YMM: u32 = 0x1325;
    pub const VPORD_ZMM_ZMM_ZMM: u32 = 0x1326;
    pub const VPORQ_XMM_XMM_XMM: u32 = 0x1327;
    pub const VPORQ_YMM_YMM_YMM: u32 = 0x1328;
    pub const VPORQ_ZMM_ZMM_ZMM: u32 = 0x1329;
    pub const VPXORD_XMM_XMM_XMM: u32 = 0x132A;
    pub const VPXORD_YMM_YMM_YMM: u32 = 0x132B;
    pub const VPXORD_ZMM_ZMM_ZMM: u32 = 0x132C;
    pub const VPXORQ_XMM_XMM_XMM: u32 = 0x132D;
    pub const VPXORQ_YMM_YMM_YMM: u32 = 0x132E;
    pub const VPXORQ_ZMM_ZMM_ZMM: u32 = 0x132F;

    // Vector min/max (0x1330..0x133B)
    pub const VPMINSD_XMM_XMM_XMM: u32 = 0x1330;
    pub const VPMINSD_YMM_YMM_YMM: u32 = 0x1331;
    pub const VPMINSD_ZMM_ZMM_ZMM: u32 = 0x1332;
    pub const VPMINUD_XMM_XMM_XMM: u32 = 0x1333;
    pub const VPMINUD_YMM_YMM_YMM: u32 = 0x1334;
    pub const VPMINUD_ZMM_ZMM_ZMM: u32 = 0x1335;
    pub const VPMAXSD_XMM_XMM_XMM: u32 = 0x1336;
    pub const VPMAXSD_YMM_YMM_YMM: u32 = 0x1337;
    pub const VPMAXSD_ZMM_ZMM_ZMM: u32 = 0x1338;
    pub const VPMAXUD_XMM_XMM_XMM: u32 = 0x1339;
    pub const VPMAXUD_YMM_YMM_YMM: u32 = 0x133A;
    pub const VPMAXUD_ZMM_ZMM_ZMM: u32 = 0x133B;
}

const U64: SemanticType = SemanticType::Scalar(ScalarType::BitVec(64));

const I8X16: SemanticType = SemanticType::Vector {
    lanes: 16,
    lane: ScalarType::BitVec(8),
};
const I8X32: SemanticType = SemanticType::Vector {
    lanes: 32,
    lane: ScalarType::BitVec(8),
};
const I8X64: SemanticType = SemanticType::Vector {
    lanes: 64,
    lane: ScalarType::BitVec(8),
};

const I16X8: SemanticType = SemanticType::Vector {
    lanes: 8,
    lane: ScalarType::BitVec(16),
};
const I16X16: SemanticType = SemanticType::Vector {
    lanes: 16,
    lane: ScalarType::BitVec(16),
};
const I16X32: SemanticType = SemanticType::Vector {
    lanes: 32,
    lane: ScalarType::BitVec(16),
};

const I32X4: SemanticType = SemanticType::Vector {
    lanes: 4,
    lane: ScalarType::BitVec(32),
};
const I32X8: SemanticType = SemanticType::Vector {
    lanes: 8,
    lane: ScalarType::BitVec(32),
};
const I32X16: SemanticType = SemanticType::Vector {
    lanes: 16,
    lane: ScalarType::BitVec(32),
};

const I64X2: SemanticType = SemanticType::Vector {
    lanes: 2,
    lane: ScalarType::BitVec(64),
};
const I64X4: SemanticType = SemanticType::Vector {
    lanes: 4,
    lane: ScalarType::BitVec(64),
};
const I64X8: SemanticType = SemanticType::Vector {
    lanes: 8,
    lane: ScalarType::BitVec(64),
};

fn const_u64(out: &mut dyn SemanticBuilder, val: u64) -> Result<ValueId, SemanticError> {
    out.constant(U64, &val.to_le_bytes())
}

/// Discovers if an EVEX instruction has an opmask register (k0..k7) as operand 1.
///
/// Returns `Some(0)` for `k0` (unmasked), `Some(1..=7)` for `k1..k7`, or `None` if
/// no opmask register is present.
fn evex_opmask(insn: &dyn DecodedInstructionView) -> Option<u32> {
    if insn.operand_count() < 4 {
        return None;
    }
    let op = insn.operand(1)?;
    let angryier_semantics::OperandKind::Register(reg) = op.kind else {
        return None;
    };
    const OPMASK_BASE: u32 = 0x0140;
    let id = reg.parent.0;
    if (OPMASK_BASE..=OPMASK_BASE + 7).contains(&id) {
        Some(id - OPMASK_BASE)
    } else {
        None
    }
}

/// Applies EVEX opmask semantics (merging or zeroing masking) to a computed vector result.
fn apply_evex_mask(
    insn: &dyn DecodedInstructionView,
    out: &mut dyn SemanticBuilder,
    dst_ty: SemanticType,
    old_dst: Option<ValueId>,
    new_val: ValueId,
) -> Result<ValueId, SemanticError> {
    let Some(k) = evex_opmask(insn) else {
        return Ok(new_val);
    };
    if k == 0 {
        return Ok(new_val);
    }
    let mask = out.read_operand(1, U64)?;
    if insn.is_zeroing_mask() {
        let dummy = old_dst.unwrap_or(new_val);
        out.emit(SemanticOp::Vector(VectorOp::MaskZero), dst_ty, &[dummy, new_val, mask])
    } else {
        let old = match old_dst {
            Some(v) => v,
            None => out.read_operand(0, dst_ty)?,
        };
        out.emit(SemanticOp::Vector(VectorOp::MaskMerge), dst_ty, &[old, new_val, mask])
    }
}

fn fall_through(out: &mut dyn SemanticBuilder, insn: &dyn DecodedInstructionView) -> Result<(), SemanticError> {
    let next_pc = const_u64(out, insn.address().wrapping_add(u64::from(insn.length())))?;
    out.jump(next_pc)?;
    Ok(())
}

fn receipt(offset: u64, context: &SemanticContext) -> SemanticReceipt {
    SemanticReceipt {
        rule_id: rule_id(offset),
        origin: SemanticOrigin::HandwrittenOverride,
        semantic_version: context.semantic_version,
    }
}

/// Discovers the operand indices for EVEX instructions.
///
/// Under XED decoding, EVEX vector instructions include the opmask register (e.g. `k0`)
/// as operand 1, placing source 1 at index 2 and source 2 at index 3. Synthetic decode
/// objects without the opmask use indices 1 and 2.
fn evex_source_indices(insn: &dyn DecodedInstructionView) -> (u8, u8) {
    if insn.operand_count() >= 4 { (2, 3) } else { (1, 2) }
}

// ---------------------------------------------------------------------------
// Macros for LaneWise vector ALU operations (XMM 128, YMM 256, ZMM 512)
// ---------------------------------------------------------------------------

macro_rules! lanewise_xmm {
    ($name:ident, $form:expr, $op:expr, $ty:expr, $rule:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId {
                rule_id($rule)
            }
            fn origin(&self) -> SemanticOrigin {
                SemanticOrigin::HandwrittenOverride
            }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
                insn.form_id() == $form
            }
            fn emit(
                &self,
                context: &SemanticContext,
                insn: &dyn DecodedInstructionView,
                out: &mut dyn SemanticBuilder,
            ) -> Result<SemanticReceipt, SemanticError> {
                let (src1_idx, src2_idx) = evex_source_indices(insn);
                let left = out.read_operand(src1_idx, $ty)?;
                let right = out.read_operand(src2_idx, $ty)?;
                let result = out.emit(SemanticOp::Vector(VectorOp::LaneWise($op)), $ty, &[left, right])?;
                let final_res = apply_evex_mask(insn, out, $ty, None, result)?;
                out.write_operand(0, final_res)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

macro_rules! lanewise_ymm {
    ($name:ident, $form:expr, $op:expr, $slice_ty:expr, $full_ty:expr, $rule:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId {
                rule_id($rule)
            }
            fn origin(&self) -> SemanticOrigin {
                SemanticOrigin::HandwrittenOverride
            }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
                insn.form_id() == $form
            }
            fn emit(
                &self,
                context: &SemanticContext,
                insn: &dyn DecodedInstructionView,
                out: &mut dyn SemanticBuilder,
            ) -> Result<SemanticReceipt, SemanticError> {
                let (src1_idx, src2_idx) = evex_source_indices(insn);
                let left = out.read_operand(src1_idx, $full_ty)?;
                let right = out.read_operand(src2_idx, $full_ty)?;
                let off0 = const_u64(out, 0)?;
                let off128 = const_u64(out, 128)?;
                let left_lo = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    $slice_ty,
                    &[left, off0],
                )?;
                let left_hi = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    $slice_ty,
                    &[left, off128],
                )?;
                let right_lo = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    $slice_ty,
                    &[right, off0],
                )?;
                let right_hi = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    $slice_ty,
                    &[right, off128],
                )?;
                let res_lo = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWise($op)),
                    $slice_ty,
                    &[left_lo, right_lo],
                )?;
                let res_hi = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWise($op)),
                    $slice_ty,
                    &[left_hi, right_hi],
                )?;
                let result = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Concat),
                    $full_ty,
                    &[res_lo, res_hi],
                )?;
                let final_res = apply_evex_mask(insn, out, $full_ty, None, result)?;
                out.write_operand(0, final_res)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

macro_rules! lanewise_zmm {
    ($name:ident, $form:expr, $op:expr, $slice_ty:expr, $mid_ty:expr, $full_ty:expr, $rule:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId {
                rule_id($rule)
            }
            fn origin(&self) -> SemanticOrigin {
                SemanticOrigin::HandwrittenOverride
            }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
                insn.form_id() == $form
            }
            fn emit(
                &self,
                context: &SemanticContext,
                insn: &dyn DecodedInstructionView,
                out: &mut dyn SemanticBuilder,
            ) -> Result<SemanticReceipt, SemanticError> {
                let (src1_idx, src2_idx) = evex_source_indices(insn);
                let left = out.read_operand(src1_idx, $full_ty)?;
                let right = out.read_operand(src2_idx, $full_ty)?;
                let off0 = const_u64(out, 0)?;
                let off128 = const_u64(out, 128)?;
                let off256 = const_u64(out, 256)?;
                let off384 = const_u64(out, 384)?;
                let left_0 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    $slice_ty,
                    &[left, off0],
                )?;
                let left_1 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    $slice_ty,
                    &[left, off128],
                )?;
                let left_2 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    $slice_ty,
                    &[left, off256],
                )?;
                let left_3 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    $slice_ty,
                    &[left, off384],
                )?;
                let right_0 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    $slice_ty,
                    &[right, off0],
                )?;
                let right_1 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    $slice_ty,
                    &[right, off128],
                )?;
                let right_2 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    $slice_ty,
                    &[right, off256],
                )?;
                let right_3 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    $slice_ty,
                    &[right, off384],
                )?;
                let res_0 = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWise($op)),
                    $slice_ty,
                    &[left_0, right_0],
                )?;
                let res_1 = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWise($op)),
                    $slice_ty,
                    &[left_1, right_1],
                )?;
                let res_2 = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWise($op)),
                    $slice_ty,
                    &[left_2, right_2],
                )?;
                let res_3 = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWise($op)),
                    $slice_ty,
                    &[left_3, right_3],
                )?;
                let lo = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Concat),
                    $mid_ty,
                    &[res_0, res_1],
                )?;
                let hi = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Concat),
                    $mid_ty,
                    &[res_2, res_3],
                )?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), $full_ty, &[lo, hi])?;
                let final_res = apply_evex_mask(insn, out, $full_ty, None, result)?;
                out.write_operand(0, final_res)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

// ---------------------------------------------------------------------------
// Macros for vector bitwise logic (XMM 128, YMM 256, ZMM 512)
// ---------------------------------------------------------------------------

macro_rules! logic_evex {
    ($name:ident, $form:expr, $op:ident, $ty:expr, $rule:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId {
                rule_id($rule)
            }
            fn origin(&self) -> SemanticOrigin {
                SemanticOrigin::HandwrittenOverride
            }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
                insn.form_id() == $form
            }
            fn emit(
                &self,
                context: &SemanticContext,
                insn: &dyn DecodedInstructionView,
                out: &mut dyn SemanticBuilder,
            ) -> Result<SemanticReceipt, SemanticError> {
                let (src1_idx, src2_idx) = evex_source_indices(insn);
                let left = out.read_operand(src1_idx, $ty)?;
                let right = out.read_operand(src2_idx, $ty)?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::$op), $ty, &[left, right])?;
                let final_res = apply_evex_mask(insn, out, $ty, None, result)?;
                out.write_operand(0, final_res)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

macro_rules! andn_evex {
    ($name:ident, $form:expr, $ty:expr, $rule:expr) => {
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl SemanticProvider for $name {
            fn rule_id(&self) -> SemanticRuleId {
                rule_id($rule)
            }
            fn origin(&self) -> SemanticOrigin {
                SemanticOrigin::HandwrittenOverride
            }
            fn matches(&self, insn: &dyn DecodedInstructionView) -> bool {
                insn.form_id() == $form
            }
            fn emit(
                &self,
                context: &SemanticContext,
                insn: &dyn DecodedInstructionView,
                out: &mut dyn SemanticBuilder,
            ) -> Result<SemanticReceipt, SemanticError> {
                let (src1_idx, src2_idx) = evex_source_indices(insn);
                let left = out.read_operand(src1_idx, $ty)?;
                let right = out.read_operand(src2_idx, $ty)?;
                let not_left = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), $ty, &[left])?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::And), $ty, &[not_left, right])?;
                let final_res = apply_evex_mask(insn, out, $ty, None, result)?;
                out.write_operand(0, final_res)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

// ---------------------------------------------------------------------------
// 1. Vector addition (VPADDB, VPADDW, VPADDD, VPADDQ)
// ---------------------------------------------------------------------------

lanewise_xmm!(
    VpaddbXmmXmmXmm,
    forms::VPADDB_XMM_XMM_XMM,
    PrimitiveOp::Add,
    I8X16,
    0x00
);
lanewise_ymm!(
    VpaddbYmmYmmYmm,
    forms::VPADDB_YMM_YMM_YMM,
    PrimitiveOp::Add,
    I8X16,
    I8X32,
    0x01
);
lanewise_zmm!(
    VpaddbZmmZmmZmm,
    forms::VPADDB_ZMM_ZMM_ZMM,
    PrimitiveOp::Add,
    I8X16,
    I8X32,
    I8X64,
    0x02
);

lanewise_xmm!(
    VpaddwXmmXmmXmm,
    forms::VPADDW_XMM_XMM_XMM,
    PrimitiveOp::Add,
    I16X8,
    0x03
);
lanewise_ymm!(
    VpaddwYmmYmmYmm,
    forms::VPADDW_YMM_YMM_YMM,
    PrimitiveOp::Add,
    I16X8,
    I16X16,
    0x04
);
lanewise_zmm!(
    VpaddwZmmZmmZmm,
    forms::VPADDW_ZMM_ZMM_ZMM,
    PrimitiveOp::Add,
    I16X8,
    I16X16,
    I16X32,
    0x05
);

lanewise_xmm!(
    VpadddXmmXmmXmm,
    forms::VPADDD_XMM_XMM_XMM,
    PrimitiveOp::Add,
    I32X4,
    0x06
);
lanewise_ymm!(
    VpadddYmmYmmYmm,
    forms::VPADDD_YMM_YMM_YMM,
    PrimitiveOp::Add,
    I32X4,
    I32X8,
    0x07
);
lanewise_zmm!(
    VpadddZmmZmmZmm,
    forms::VPADDD_ZMM_ZMM_ZMM,
    PrimitiveOp::Add,
    I32X4,
    I32X8,
    I32X16,
    0x08
);

lanewise_xmm!(
    VpaddqXmmXmmXmm,
    forms::VPADDQ_XMM_XMM_XMM,
    PrimitiveOp::Add,
    I64X2,
    0x09
);
lanewise_ymm!(
    VpaddqYmmYmmYmm,
    forms::VPADDQ_YMM_YMM_YMM,
    PrimitiveOp::Add,
    I64X2,
    I64X4,
    0x0A
);
lanewise_zmm!(
    VpaddqZmmZmmZmm,
    forms::VPADDQ_ZMM_ZMM_ZMM,
    PrimitiveOp::Add,
    I64X2,
    I64X4,
    I64X8,
    0x0B
);

// ---------------------------------------------------------------------------
// 2. Vector subtraction (VPSUBB, VPSUBW, VPSUBD, VPSUBQ)
// ---------------------------------------------------------------------------

lanewise_xmm!(
    VpsubbXmmXmmXmm,
    forms::VPSUBB_XMM_XMM_XMM,
    PrimitiveOp::Sub,
    I8X16,
    0x0C
);
lanewise_ymm!(
    VpsubbYmmYmmYmm,
    forms::VPSUBB_YMM_YMM_YMM,
    PrimitiveOp::Sub,
    I8X16,
    I8X32,
    0x0D
);
lanewise_zmm!(
    VpsubbZmmZmmZmm,
    forms::VPSUBB_ZMM_ZMM_ZMM,
    PrimitiveOp::Sub,
    I8X16,
    I8X32,
    I8X64,
    0x0E
);

lanewise_xmm!(
    VpsubwXmmXmmXmm,
    forms::VPSUBW_XMM_XMM_XMM,
    PrimitiveOp::Sub,
    I16X8,
    0x0F
);
lanewise_ymm!(
    VpsubwYmmYmmYmm,
    forms::VPSUBW_YMM_YMM_YMM,
    PrimitiveOp::Sub,
    I16X8,
    I16X16,
    0x10
);
lanewise_zmm!(
    VpsubwZmmZmmZmm,
    forms::VPSUBW_ZMM_ZMM_ZMM,
    PrimitiveOp::Sub,
    I16X8,
    I16X16,
    I16X32,
    0x11
);

lanewise_xmm!(
    VpsubdXmmXmmXmm,
    forms::VPSUBD_XMM_XMM_XMM,
    PrimitiveOp::Sub,
    I32X4,
    0x12
);
lanewise_ymm!(
    VpsubdYmmYmmYmm,
    forms::VPSUBD_YMM_YMM_YMM,
    PrimitiveOp::Sub,
    I32X4,
    I32X8,
    0x13
);
lanewise_zmm!(
    VpsubdZmmZmmZmm,
    forms::VPSUBD_ZMM_ZMM_ZMM,
    PrimitiveOp::Sub,
    I32X4,
    I32X8,
    I32X16,
    0x14
);

lanewise_xmm!(
    VpsubqXmmXmmXmm,
    forms::VPSUBQ_XMM_XMM_XMM,
    PrimitiveOp::Sub,
    I64X2,
    0x15
);
lanewise_ymm!(
    VpsubqYmmYmmYmm,
    forms::VPSUBQ_YMM_YMM_YMM,
    PrimitiveOp::Sub,
    I64X2,
    I64X4,
    0x16
);
lanewise_zmm!(
    VpsubqZmmZmmZmm,
    forms::VPSUBQ_ZMM_ZMM_ZMM,
    PrimitiveOp::Sub,
    I64X2,
    I64X4,
    I64X8,
    0x17
);

// ---------------------------------------------------------------------------
// 3. Vector bitwise logic (VPANDD, VPANDQ, VPANDND, VPANDNQ, VPORD, VPORQ, VPXORD, VPXORQ)
// ---------------------------------------------------------------------------

logic_evex!(VpanddXmmXmmXmm, forms::VPANDD_XMM_XMM_XMM, And, I32X4, 0x18);
logic_evex!(VpanddYmmYmmYmm, forms::VPANDD_YMM_YMM_YMM, And, I32X8, 0x19);
logic_evex!(VpanddZmmZmmZmm, forms::VPANDD_ZMM_ZMM_ZMM, And, I32X16, 0x1A);

logic_evex!(VpandqXmmXmmXmm, forms::VPANDQ_XMM_XMM_XMM, And, I64X2, 0x1B);
logic_evex!(VpandqYmmYmmYmm, forms::VPANDQ_YMM_YMM_YMM, And, I64X4, 0x1C);
logic_evex!(VpandqZmmZmmZmm, forms::VPANDQ_ZMM_ZMM_ZMM, And, I64X8, 0x1D);

andn_evex!(VpandndXmmXmmXmm, forms::VPANDND_XMM_XMM_XMM, I32X4, 0x1E);
andn_evex!(VpandndYmmYmmYmm, forms::VPANDND_YMM_YMM_YMM, I32X8, 0x1F);
andn_evex!(VpandndZmmZmmZmm, forms::VPANDND_ZMM_ZMM_ZMM, I32X16, 0x20);

andn_evex!(VpandnqXmmXmmXmm, forms::VPANDNQ_XMM_XMM_XMM, I64X2, 0x21);
andn_evex!(VpandnqYmmYmmYmm, forms::VPANDNQ_YMM_YMM_YMM, I64X4, 0x22);
andn_evex!(VpandnqZmmZmmZmm, forms::VPANDNQ_ZMM_ZMM_ZMM, I64X8, 0x23);

logic_evex!(VpordXmmXmmXmm, forms::VPORD_XMM_XMM_XMM, Or, I32X4, 0x24);
logic_evex!(VpordYmmYmmYmm, forms::VPORD_YMM_YMM_YMM, Or, I32X8, 0x25);
logic_evex!(VpordZmmZmmZmm, forms::VPORD_ZMM_ZMM_ZMM, Or, I32X16, 0x26);

logic_evex!(VporqXmmXmmXmm, forms::VPORQ_XMM_XMM_XMM, Or, I64X2, 0x27);
logic_evex!(VporqYmmYmmYmm, forms::VPORQ_YMM_YMM_YMM, Or, I64X4, 0x28);
logic_evex!(VporqZmmZmmZmm, forms::VPORQ_ZMM_ZMM_ZMM, Or, I64X8, 0x29);

logic_evex!(VpxordXmmXmmXmm, forms::VPXORD_XMM_XMM_XMM, Xor, I32X4, 0x2A);
logic_evex!(VpxordYmmYmmYmm, forms::VPXORD_YMM_YMM_YMM, Xor, I32X8, 0x2B);
logic_evex!(VpxordZmmZmmZmm, forms::VPXORD_ZMM_ZMM_ZMM, Xor, I32X16, 0x2C);

logic_evex!(VpxorqXmmXmmXmm, forms::VPXORQ_XMM_XMM_XMM, Xor, I64X2, 0x2D);
logic_evex!(VpxorqYmmYmmYmm, forms::VPXORQ_YMM_YMM_YMM, Xor, I64X4, 0x2E);
logic_evex!(VpxorqZmmZmmZmm, forms::VPXORQ_ZMM_ZMM_ZMM, Xor, I64X8, 0x2F);

// ---------------------------------------------------------------------------
// 4. Vector min/max (VPMINSD, VPMINUD, VPMAXSD, VPMAXUD)
// ---------------------------------------------------------------------------

lanewise_xmm!(
    VpminsdXmmXmmXmm,
    forms::VPMINSD_XMM_XMM_XMM,
    PrimitiveOp::MinS,
    I32X4,
    0x30
);
lanewise_ymm!(
    VpminsdYmmYmmYmm,
    forms::VPMINSD_YMM_YMM_YMM,
    PrimitiveOp::MinS,
    I32X4,
    I32X8,
    0x31
);
lanewise_zmm!(
    VpminsdZmmZmmZmm,
    forms::VPMINSD_ZMM_ZMM_ZMM,
    PrimitiveOp::MinS,
    I32X4,
    I32X8,
    I32X16,
    0x32
);

lanewise_xmm!(
    VpminudXmmXmmXmm,
    forms::VPMINUD_XMM_XMM_XMM,
    PrimitiveOp::MinU,
    I32X4,
    0x33
);
lanewise_ymm!(
    VpminudYmmYmmYmm,
    forms::VPMINUD_YMM_YMM_YMM,
    PrimitiveOp::MinU,
    I32X4,
    I32X8,
    0x34
);
lanewise_zmm!(
    VpminudZmmZmmZmm,
    forms::VPMINUD_ZMM_ZMM_ZMM,
    PrimitiveOp::MinU,
    I32X4,
    I32X8,
    I32X16,
    0x35
);

lanewise_xmm!(
    VpmaxsdXmmXmmXmm,
    forms::VPMAXSD_XMM_XMM_XMM,
    PrimitiveOp::MaxS,
    I32X4,
    0x36
);
lanewise_ymm!(
    VpmaxsdYmmYmmYmm,
    forms::VPMAXSD_YMM_YMM_YMM,
    PrimitiveOp::MaxS,
    I32X4,
    I32X8,
    0x37
);
lanewise_zmm!(
    VpmaxsdZmmZmmZmm,
    forms::VPMAXSD_ZMM_ZMM_ZMM,
    PrimitiveOp::MaxS,
    I32X4,
    I32X8,
    I32X16,
    0x38
);

lanewise_xmm!(
    VpmaxudXmmXmmXmm,
    forms::VPMAXUD_XMM_XMM_XMM,
    PrimitiveOp::MaxU,
    I32X4,
    0x39
);
lanewise_ymm!(
    VpmaxudYmmYmmYmm,
    forms::VPMAXUD_YMM_YMM_YMM,
    PrimitiveOp::MaxU,
    I32X4,
    I32X8,
    0x3A
);
lanewise_zmm!(
    VpmaxudZmmZmmZmm,
    forms::VPMAXUD_ZMM_ZMM_ZMM,
    PrimitiveOp::MaxU,
    I32X4,
    I32X8,
    I32X16,
    0x3B
);

// ---------------------------------------------------------------------------
// Provider slice registration
// ---------------------------------------------------------------------------

pub fn providers() -> Vec<Arc<dyn SemanticProvider>> {
    vec![
        // Vector addition (12)
        Arc::new(VpaddbXmmXmmXmm),
        Arc::new(VpaddbYmmYmmYmm),
        Arc::new(VpaddbZmmZmmZmm),
        Arc::new(VpaddwXmmXmmXmm),
        Arc::new(VpaddwYmmYmmYmm),
        Arc::new(VpaddwZmmZmmZmm),
        Arc::new(VpadddXmmXmmXmm),
        Arc::new(VpadddYmmYmmYmm),
        Arc::new(VpadddZmmZmmZmm),
        Arc::new(VpaddqXmmXmmXmm),
        Arc::new(VpaddqYmmYmmYmm),
        Arc::new(VpaddqZmmZmmZmm),
        // Vector subtraction (12)
        Arc::new(VpsubbXmmXmmXmm),
        Arc::new(VpsubbYmmYmmYmm),
        Arc::new(VpsubbZmmZmmZmm),
        Arc::new(VpsubwXmmXmmXmm),
        Arc::new(VpsubwYmmYmmYmm),
        Arc::new(VpsubwZmmZmmZmm),
        Arc::new(VpsubdXmmXmmXmm),
        Arc::new(VpsubdYmmYmmYmm),
        Arc::new(VpsubdZmmZmmZmm),
        Arc::new(VpsubqXmmXmmXmm),
        Arc::new(VpsubqYmmYmmYmm),
        Arc::new(VpsubqZmmZmmZmm),
        // Vector bitwise logic (24)
        Arc::new(VpanddXmmXmmXmm),
        Arc::new(VpanddYmmYmmYmm),
        Arc::new(VpanddZmmZmmZmm),
        Arc::new(VpandqXmmXmmXmm),
        Arc::new(VpandqYmmYmmYmm),
        Arc::new(VpandqZmmZmmZmm),
        Arc::new(VpandndXmmXmmXmm),
        Arc::new(VpandndYmmYmmYmm),
        Arc::new(VpandndZmmZmmZmm),
        Arc::new(VpandnqXmmXmmXmm),
        Arc::new(VpandnqYmmYmmYmm),
        Arc::new(VpandnqZmmZmmZmm),
        Arc::new(VpordXmmXmmXmm),
        Arc::new(VpordYmmYmmYmm),
        Arc::new(VpordZmmZmmZmm),
        Arc::new(VporqXmmXmmXmm),
        Arc::new(VporqYmmYmmYmm),
        Arc::new(VporqZmmZmmZmm),
        Arc::new(VpxordXmmXmmXmm),
        Arc::new(VpxordYmmYmmYmm),
        Arc::new(VpxordZmmZmmZmm),
        Arc::new(VpxorqXmmXmmXmm),
        Arc::new(VpxorqYmmYmmYmm),
        Arc::new(VpxorqZmmZmmZmm),
        // Vector min/max (12)
        Arc::new(VpminsdXmmXmmXmm),
        Arc::new(VpminsdYmmYmmYmm),
        Arc::new(VpminsdZmmZmmZmm),
        Arc::new(VpminudXmmXmmXmm),
        Arc::new(VpminudYmmYmmYmm),
        Arc::new(VpminudZmmZmmZmm),
        Arc::new(VpmaxsdXmmXmmXmm),
        Arc::new(VpmaxsdYmmYmmYmm),
        Arc::new(VpmaxsdZmmZmmZmm),
        Arc::new(VpmaxudXmmXmmXmm),
        Arc::new(VpmaxudYmmYmmYmm),
        Arc::new(VpmaxudZmmZmmZmm),
    ]
}

pub fn avx10_providers() -> Vec<Arc<dyn SemanticProvider>> {
    providers()
}

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_arch::{
        AccessKind, DecodedInstruction, InstructionModifiers, Operand, OperandKind, OperandVisibility, PredicateMask,
        PredicateMode, RegisterId, RegisterView,
    };
    use angryier_semantic_contracts::SealedSemanticBlock;
    use angryier_semantics::{SemanticBlockBuilder, SemanticContext};
    use angryier_types::{
        ContentIdentitySchemaVersion, FidelityProfile, SemanticFingerprintSchemaVersion, SemanticVersion,
        TargetProfileId,
    };

    fn test_context() -> SemanticContext {
        SemanticContext {
            semantic_version: SemanticVersion(1),
            target_profile: TargetProfileId(1),
            fidelity: FidelityProfile::Prove,
            vector_representation: angryier_semantics::VectorRepresentation::HybridLazy,
            tile_representation: angryier_semantics::TileRepresentation::LazyChunked,
            floating_point_policy: angryier_semantics::FloatingPointPolicy::SmtFpPreferred,
        }
    }

    fn make_test_decoded(form: u32, operands: Vec<Operand>, modifiers: InstructionModifiers) -> DecodedInstruction {
        DecodedInstruction {
            address: 0x4000,
            length: 4,
            form_id: form,
            features: vec![],
            operands,
            modifiers,
        }
    }

    fn reg_op(index: u8, reg_id: u32, width: u16, access: AccessKind) -> Operand {
        Operand {
            index,
            width_bits: width,
            access,
            visibility: OperandVisibility::Explicit,
            kind: OperandKind::Register(RegisterView::full(RegisterId(reg_id), width)),
        }
    }

    #[test]
    fn test_all_60_providers_metadata_and_form_coverage() {
        let all = providers();
        assert_eq!(all.len(), 60);

        let mut seen_rules = std::collections::BTreeSet::new();
        for (idx, provider) in all.iter().enumerate() {
            let rid = provider.rule_id();
            assert_eq!(rid.0, AVX10_RULE_BASE + idx as u64);
            assert!(seen_rules.insert(rid.0), "duplicate rule ID {:#x}", rid.0);
            assert_eq!(provider.origin(), SemanticOrigin::HandwrittenOverride);

            let expected_form = 0x1300 + idx as u32;
            let insn = make_test_decoded(expected_form, vec![], InstructionModifiers::default());
            assert!(
                provider.matches(&insn),
                "provider {} failed to match form {:#x}",
                idx,
                expected_form
            );
        }
    }

    #[test]
    fn test_vpaddd_xmm_ymm_zmm_unmasked() -> Result<(), angryier_semantics::SemanticError> {
        let ctx = test_context();

        // XMM 128
        {
            let insn = make_test_decoded(
                forms::VPADDD_XMM_XMM_XMM,
                vec![
                    reg_op(0, 0x100, 128, AccessKind::Write),
                    reg_op(1, 0x101, 128, AccessKind::Read),
                    reg_op(2, 0x102, 128, AccessKind::Read),
                ],
                InstructionModifiers::default(),
            );
            let p = VpadddXmmXmmXmm;
            let mut builder = SemanticBlockBuilder::new(SemanticVersion(1));
            let receipt = p.emit(&ctx, &insn, &mut builder)?;
            assert_eq!(receipt.rule_id, rule_id(0x06));
            let sealed = builder.seal(ContentIdentitySchemaVersion(1), SemanticFingerprintSchemaVersion(1))?;
            assert_eq!(sealed.semantic_version(), SemanticVersion(1));
        }

        // YMM 256
        {
            let insn = make_test_decoded(
                forms::VPADDD_YMM_YMM_YMM,
                vec![
                    reg_op(0, 0x100, 256, AccessKind::Write),
                    reg_op(1, 0x101, 256, AccessKind::Read),
                    reg_op(2, 0x102, 256, AccessKind::Read),
                ],
                InstructionModifiers::default(),
            );
            let p = VpadddYmmYmmYmm;
            let mut builder = SemanticBlockBuilder::new(SemanticVersion(1));
            let receipt = p.emit(&ctx, &insn, &mut builder)?;
            assert_eq!(receipt.rule_id, rule_id(0x07));
            let sealed = builder.seal(ContentIdentitySchemaVersion(1), SemanticFingerprintSchemaVersion(1))?;
            assert_eq!(sealed.semantic_version(), SemanticVersion(1));
        }

        // ZMM 512
        {
            let insn = make_test_decoded(
                forms::VPADDD_ZMM_ZMM_ZMM,
                vec![
                    reg_op(0, 0x100, 512, AccessKind::Write),
                    reg_op(1, 0x101, 512, AccessKind::Read),
                    reg_op(2, 0x102, 512, AccessKind::Read),
                ],
                InstructionModifiers::default(),
            );
            let p = VpadddZmmZmmZmm;
            let mut builder = SemanticBlockBuilder::new(SemanticVersion(1));
            let receipt = p.emit(&ctx, &insn, &mut builder)?;
            assert_eq!(receipt.rule_id, rule_id(0x08));
            let sealed = builder.seal(ContentIdentitySchemaVersion(1), SemanticFingerprintSchemaVersion(1))?;
            assert_eq!(sealed.semantic_version(), SemanticVersion(1));
        }
        Ok(())
    }

    #[test]
    fn test_vpsubq_opmask_merging() -> Result<(), angryier_semantics::SemanticError> {
        let ctx = test_context();
        // 4 operands: [dst, opmask k1, src1, src2]
        let insn = make_test_decoded(
            forms::VPSUBQ_XMM_XMM_XMM,
            vec![
                reg_op(0, 0x100, 128, AccessKind::ReadWrite),
                reg_op(1, 0x0141, 64, AccessKind::Read), // k1
                reg_op(2, 0x101, 128, AccessKind::Read),
                reg_op(3, 0x102, 128, AccessKind::Read),
            ],
            InstructionModifiers::default(),
        );
        let p = VpsubqXmmXmmXmm;
        let mut builder = SemanticBlockBuilder::new(SemanticVersion(1));
        let receipt = p.emit(&ctx, &insn, &mut builder)?;
        assert_eq!(receipt.rule_id, rule_id(0x15));

        // Verify MaskMerge is present in values
        let has_mask_merge = builder.values().iter().any(|v| {
            matches!(
                v.definition,
                angryier_semantics::SemanticValueDefinition::Operation {
                    op: SemanticOp::Vector(VectorOp::MaskMerge),
                    ..
                }
            )
        });
        assert!(has_mask_merge, "expected MaskMerge operation");
        Ok(())
    }

    #[test]
    fn test_vpandd_opmask_zeroing() -> Result<(), angryier_semantics::SemanticError> {
        let ctx = test_context();
        let modifiers = InstructionModifiers {
            predicate: Some(PredicateMask {
                register: RegisterView::full(RegisterId(0x0142), 64),
                mode: PredicateMode::Zero,
            }),
            ..Default::default()
        };

        // 4 operands: [dst, opmask k2, src1, src2]
        let insn = make_test_decoded(
            forms::VPANDD_YMM_YMM_YMM,
            vec![
                reg_op(0, 0x100, 256, AccessKind::Write),
                reg_op(1, 0x0142, 64, AccessKind::Read), // k2
                reg_op(2, 0x101, 256, AccessKind::Read),
                reg_op(3, 0x102, 256, AccessKind::Read),
            ],
            modifiers,
        );
        let p = VpanddYmmYmmYmm;
        let mut builder = SemanticBlockBuilder::new(SemanticVersion(1));
        let receipt = p.emit(&ctx, &insn, &mut builder)?;
        assert_eq!(receipt.rule_id, rule_id(0x19));

        // Verify MaskZero is present in values
        let has_mask_zero = builder.values().iter().any(|v| {
            matches!(
                v.definition,
                angryier_semantics::SemanticValueDefinition::Operation {
                    op: SemanticOp::Vector(VectorOp::MaskZero),
                    ..
                }
            )
        });
        assert!(has_mask_zero, "expected MaskZero operation");
        Ok(())
    }

    #[test]
    fn test_min_max_and_logic_providers_emit_cleanly() -> Result<(), angryier_semantics::SemanticError> {
        let ctx = test_context();

        // VPMINSD YMM
        {
            let insn = make_test_decoded(
                forms::VPMINSD_YMM_YMM_YMM,
                vec![
                    reg_op(0, 0x100, 256, AccessKind::Write),
                    reg_op(1, 0x101, 256, AccessKind::Read),
                    reg_op(2, 0x102, 256, AccessKind::Read),
                ],
                InstructionModifiers::default(),
            );
            let mut builder = SemanticBlockBuilder::new(SemanticVersion(1));
            let receipt = VpminsdYmmYmmYmm.emit(&ctx, &insn, &mut builder)?;
            assert_eq!(receipt.rule_id, rule_id(0x31));
        }

        // VPMAXUD ZMM
        {
            let insn = make_test_decoded(
                forms::VPMAXUD_ZMM_ZMM_ZMM,
                vec![
                    reg_op(0, 0x100, 512, AccessKind::Write),
                    reg_op(1, 0x101, 512, AccessKind::Read),
                    reg_op(2, 0x102, 512, AccessKind::Read),
                ],
                InstructionModifiers::default(),
            );
            let mut builder = SemanticBlockBuilder::new(SemanticVersion(1));
            let receipt = VpmaxudZmmZmmZmm.emit(&ctx, &insn, &mut builder)?;
            assert_eq!(receipt.rule_id, rule_id(0x3B));
        }

        // VPANDND XMM
        {
            let insn = make_test_decoded(
                forms::VPANDND_XMM_XMM_XMM,
                vec![
                    reg_op(0, 0x100, 128, AccessKind::Write),
                    reg_op(1, 0x101, 128, AccessKind::Read),
                    reg_op(2, 0x102, 128, AccessKind::Read),
                ],
                InstructionModifiers::default(),
            );
            let mut builder = SemanticBlockBuilder::new(SemanticVersion(1));
            let receipt = VpandndXmmXmmXmm.emit(&ctx, &insn, &mut builder)?;
            assert_eq!(receipt.rule_id, rule_id(0x1E));
        }

        // VPXORQ ZMM
        {
            let insn = make_test_decoded(
                forms::VPXORQ_ZMM_ZMM_ZMM,
                vec![
                    reg_op(0, 0x100, 512, AccessKind::Write),
                    reg_op(1, 0x101, 512, AccessKind::Read),
                    reg_op(2, 0x102, 512, AccessKind::Read),
                ],
                InstructionModifiers::default(),
            );
            let mut builder = SemanticBlockBuilder::new(SemanticVersion(1));
            let receipt = VpxorqZmmZmmZmm.emit(&ctx, &insn, &mut builder)?;
            assert_eq!(receipt.rule_id, rule_id(0x2F));
        }
        Ok(())
    }
}
