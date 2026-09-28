#![forbid(unsafe_code)]
#![allow(dead_code)]

//! AVX-512 (EVEX) arithmetic, logic, and opmask semantic providers.
//!
//! Covers:
//! - Packed single/double precision float arithmetic: VADDPS, VSUBPS, VMULPS, VDIVPS,
//!   VADDPD, VSUBPD, VMULPD, VDIVPD (ZMM reg-reg and reg-mem512 forms)
//! - Scalar single/double precision float arithmetic (EVEX forms): VADDSS, VSUBSS, VMULSS, VDIVSS,
//!   VADDSD, VSUBSD, VMULSD, VDIVSD (XMM reg-reg and reg-mem32/mem64 forms)
//! - Packed single/double float logic: VANDPS, VANDPD, VANDNPS, VANDNPD,
//!   VORPS, VORPD, VXORPS, VXORPD (ZMM reg-reg and reg-mem512 forms)
//! - Opmask logic: KANDW, KANDNW, KORW, KXORW, KNOTW, KXNORW,
//!   KANDQ, KANDNQ, KORQ, KXORQ, KNOTQ, KXNORQ

use angryier_semantics::{
    DecodedInstructionView, FloatFormat, FloatingOp, PrimitiveOp, ScalarType, SemanticBuilder, SemanticContext,
    SemanticError, SemanticOp, SemanticOrigin, SemanticProvider, SemanticReceipt, SemanticType, ValueId, VectorOp,
};
use angryier_types::SemanticRuleId;

// The engine's authoritative form constants (the lib re-exports itself as
// `angryier_semantics_intel64` so this path also holds in the standalone
// test crate that includes this file via `#[path]`).
use angryier_semantics_intel64::forms as engine_forms;
use std::sync::Arc;

pub const CORPUS_RULE_BASE: u64 = 0x1000;

pub const fn rule_id(offset: u64) -> SemanticRuleId {
    SemanticRuleId(CORPUS_RULE_BASE + offset)
}

/// AVX-512 / EVEX form identifiers.
pub mod forms {
    // AVX-512 EVEX packed single-precision arithmetic (0x1100..0x1107)
    pub const VADDPS_ZMM_ZMM_ZMM: u32 = 0x1100;
    pub const VADDPS_ZMM_ZMM_MEM: u32 = 0x1101;
    pub const VSUBPS_ZMM_ZMM_ZMM: u32 = 0x1102;
    pub const VSUBPS_ZMM_ZMM_MEM: u32 = 0x1103;
    pub const VMULPS_ZMM_ZMM_ZMM: u32 = 0x1104;
    pub const VMULPS_ZMM_ZMM_MEM: u32 = 0x1105;
    pub const VDIVPS_ZMM_ZMM_ZMM: u32 = 0x1106;
    pub const VDIVPS_ZMM_ZMM_MEM: u32 = 0x1107;

    // AVX-512 EVEX packed double-precision arithmetic (0x1108..0x110F)
    pub const VADDPD_ZMM_ZMM_ZMM: u32 = 0x1108;
    pub const VADDPD_ZMM_ZMM_MEM: u32 = 0x1109;
    pub const VSUBPD_ZMM_ZMM_ZMM: u32 = 0x110A;
    pub const VSUBPD_ZMM_ZMM_MEM: u32 = 0x110B;
    pub const VMULPD_ZMM_ZMM_ZMM: u32 = 0x110C;
    pub const VMULPD_ZMM_ZMM_MEM: u32 = 0x110D;
    pub const VDIVPD_ZMM_ZMM_ZMM: u32 = 0x110E;
    pub const VDIVPD_ZMM_ZMM_MEM: u32 = 0x110F;

    // AVX-512 EVEX scalar single-precision arithmetic (0x1110..0x1117)
    pub const VADDSS_EVEX_XMM_XMM_XMM: u32 = 0x1110;
    pub const VADDSS_EVEX_XMM_XMM_MEM32: u32 = 0x1111;
    pub const VSUBSS_EVEX_XMM_XMM_XMM: u32 = 0x1112;
    pub const VSUBSS_EVEX_XMM_XMM_MEM32: u32 = 0x1113;
    pub const VMULSS_EVEX_XMM_XMM_XMM: u32 = 0x1114;
    pub const VMULSS_EVEX_XMM_XMM_MEM32: u32 = 0x1115;
    pub const VDIVSS_EVEX_XMM_XMM_XMM: u32 = 0x1116;
    pub const VDIVSS_EVEX_XMM_XMM_MEM32: u32 = 0x1117;

    // AVX-512 EVEX scalar double-precision arithmetic (0x1118..0x111F)
    pub const VADDSD_EVEX_XMM_XMM_XMM: u32 = 0x1118;
    pub const VADDSD_EVEX_XMM_XMM_MEM64: u32 = 0x1119;
    pub const VSUBSD_EVEX_XMM_XMM_XMM: u32 = 0x111A;
    pub const VSUBSD_EVEX_XMM_XMM_MEM64: u32 = 0x111B;
    pub const VMULSD_EVEX_XMM_XMM_XMM: u32 = 0x111C;
    pub const VMULSD_EVEX_XMM_XMM_MEM64: u32 = 0x111D;
    pub const VDIVSD_EVEX_XMM_XMM_XMM: u32 = 0x111E;
    pub const VDIVSD_EVEX_XMM_XMM_MEM64: u32 = 0x111F;

    // AVX-512 EVEX packed logic (0x1120..0x112F)
    pub const VANDPS_ZMM_ZMM_ZMM: u32 = 0x1120;
    pub const VANDPS_ZMM_ZMM_MEM: u32 = 0x1121;
    pub const VANDNPS_ZMM_ZMM_ZMM: u32 = 0x1122;
    pub const VANDNPS_ZMM_ZMM_MEM: u32 = 0x1123;
    pub const VORPS_ZMM_ZMM_ZMM: u32 = 0x1124;
    pub const VORPS_ZMM_ZMM_MEM: u32 = 0x1125;
    pub const VXORPS_ZMM_ZMM_ZMM: u32 = 0x1126;
    pub const VXORPS_ZMM_ZMM_MEM: u32 = 0x1127;
    pub const VANDPD_ZMM_ZMM_ZMM: u32 = 0x1128;
    pub const VANDPD_ZMM_ZMM_MEM: u32 = 0x1129;
    pub const VANDNPD_ZMM_ZMM_ZMM: u32 = 0x112A;
    pub const VANDNPD_ZMM_ZMM_MEM: u32 = 0x112B;
    pub const VORPD_ZMM_ZMM_ZMM: u32 = 0x112C;
    pub const VORPD_ZMM_ZMM_MEM: u32 = 0x112D;
    pub const VXORPD_ZMM_ZMM_ZMM: u32 = 0x112E;
    pub const VXORPD_ZMM_ZMM_MEM: u32 = 0x112F;

    // AVX-512 mask logic ops (0x1130..0x113B)
    pub const KANDW_K_K_K: u32 = 0x1130;
    pub const KANDNW_K_K_K: u32 = 0x1131;
    pub const KORW_K_K_K: u32 = 0x1132;
    pub const KXORW_K_K_K: u32 = 0x1133;
    pub const KNOTW_K_K: u32 = 0x1134;
    pub const KXNORW_K_K_K: u32 = 0x1135;
    pub const KANDQ_K_K_K: u32 = 0x1136;
    pub const KANDNQ_K_K_K: u32 = 0x1137;
    pub const KORQ_K_K_K: u32 = 0x1138;
    pub const KXORQ_K_K_K: u32 = 0x1139;
    pub const KNOTQ_K_K: u32 = 0x113A;
    pub const KXNORQ_K_K_K: u32 = 0x113B;
}

const U512: SemanticType = SemanticType::Scalar(ScalarType::BitVec(512));
const U128: SemanticType = SemanticType::Scalar(ScalarType::BitVec(128));
const U96: SemanticType = SemanticType::Scalar(ScalarType::BitVec(96));
const U64: SemanticType = SemanticType::Scalar(ScalarType::BitVec(64));

const F32: SemanticType = SemanticType::Scalar(ScalarType::Float(FloatFormat::F32));
const F64: SemanticType = SemanticType::Scalar(ScalarType::Float(FloatFormat::F64));

const F32X4: SemanticType = SemanticType::Vector {
    lanes: 4,
    lane: ScalarType::Float(FloatFormat::F32),
};
const F32X8: SemanticType = SemanticType::Vector {
    lanes: 8,
    lane: ScalarType::Float(FloatFormat::F32),
};
const F32X16: SemanticType = SemanticType::Vector {
    lanes: 16,
    lane: ScalarType::Float(FloatFormat::F32),
};

const F64X2: SemanticType = SemanticType::Vector {
    lanes: 2,
    lane: ScalarType::Float(FloatFormat::F64),
};
const F64X4: SemanticType = SemanticType::Vector {
    lanes: 4,
    lane: ScalarType::Float(FloatFormat::F64),
};
const F64X8: SemanticType = SemanticType::Vector {
    lanes: 8,
    lane: ScalarType::Float(FloatFormat::F64),
};

fn const_u64(out: &mut dyn SemanticBuilder, val: u64) -> Result<ValueId, SemanticError> {
    out.constant(U64, &val.to_le_bytes())
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
// Packed single-precision float arithmetic (512-bit ZMM)
// ---------------------------------------------------------------------------

macro_rules! packed_float_zmm {
    ($name:ident, $form:expr, $op:expr, $rule:expr) => {
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
                let left = out.read_operand(src1_idx, F32X16)?;
                let right = out.read_operand(src2_idx, F32X16)?;
                let off0 = const_u64(out, 0)?;
                let off128 = const_u64(out, 128)?;
                let off256 = const_u64(out, 256)?;
                let off384 = const_u64(out, 384)?;

                let left_0 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F32X4, &[left, off0])?;
                let left_1 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    F32X4,
                    &[left, off128],
                )?;
                let left_2 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    F32X4,
                    &[left, off256],
                )?;
                let left_3 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    F32X4,
                    &[left, off384],
                )?;

                let right_0 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F32X4, &[right, off0])?;
                let right_1 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    F32X4,
                    &[right, off128],
                )?;
                let right_2 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    F32X4,
                    &[right, off256],
                )?;
                let right_3 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    F32X4,
                    &[right, off384],
                )?;

                let res_0 = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWiseFloat($op)),
                    F32X4,
                    &[left_0, right_0],
                )?;
                let res_1 = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWiseFloat($op)),
                    F32X4,
                    &[left_1, right_1],
                )?;
                let res_2 = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWiseFloat($op)),
                    F32X4,
                    &[left_2, right_2],
                )?;
                let res_3 = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWiseFloat($op)),
                    F32X4,
                    &[left_3, right_3],
                )?;

                let low_256 = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), F32X8, &[res_0, res_1])?;
                let high_256 = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), F32X8, &[res_2, res_3])?;
                let result = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Concat),
                    F32X16,
                    &[low_256, high_256],
                )?;

                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

packed_float_zmm!(
    VaddpsZmmZmmZmm,
    engine_forms::VADDPS_ZMM_ZMM_ZMM,
    FloatingOp::Add,
    0x1600
);
packed_float_zmm!(
    VaddpsZmmZmmMem,
    engine_forms::VADDPS_ZMM_ZMM_MEM,
    FloatingOp::Add,
    0x1601
);
packed_float_zmm!(
    VsubpsZmmZmmZmm,
    engine_forms::VSUBPS_ZMM_ZMM_ZMM,
    FloatingOp::Sub,
    0x1602
);
packed_float_zmm!(
    VsubpsZmmZmmMem,
    engine_forms::VSUBPS_ZMM_ZMM_MEM,
    FloatingOp::Sub,
    0x1603
);
packed_float_zmm!(
    VmulpsZmmZmmZmm,
    engine_forms::VMULPS_ZMM_ZMM_ZMM,
    FloatingOp::Mul,
    0x1604
);
packed_float_zmm!(
    VmulpsZmmZmmMem,
    engine_forms::VMULPS_ZMM_ZMM_MEM,
    FloatingOp::Mul,
    0x1605
);
packed_float_zmm!(
    VdivpsZmmZmmZmm,
    engine_forms::VDIVPS_ZMM_ZMM_ZMM,
    FloatingOp::Div,
    0x1606
);
packed_float_zmm!(
    VdivpsZmmZmmMem,
    engine_forms::VDIVPS_ZMM_ZMM_MEM,
    FloatingOp::Div,
    0x1607
);

// ---------------------------------------------------------------------------
// Packed double-precision float arithmetic (512-bit ZMM)
// ---------------------------------------------------------------------------

macro_rules! packed_double_zmm {
    ($name:ident, $form:expr, $op:expr, $rule:expr) => {
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
                let left = out.read_operand(src1_idx, F64X8)?;
                let right = out.read_operand(src2_idx, F64X8)?;
                let off0 = const_u64(out, 0)?;
                let off128 = const_u64(out, 128)?;
                let off256 = const_u64(out, 256)?;
                let off384 = const_u64(out, 384)?;

                let left_0 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F64X2, &[left, off0])?;
                let left_1 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    F64X2,
                    &[left, off128],
                )?;
                let left_2 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    F64X2,
                    &[left, off256],
                )?;
                let left_3 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    F64X2,
                    &[left, off384],
                )?;

                let right_0 = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F64X2, &[right, off0])?;
                let right_1 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    F64X2,
                    &[right, off128],
                )?;
                let right_2 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    F64X2,
                    &[right, off256],
                )?;
                let right_3 = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    F64X2,
                    &[right, off384],
                )?;

                let res_0 = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWiseFloat($op)),
                    F64X2,
                    &[left_0, right_0],
                )?;
                let res_1 = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWiseFloat($op)),
                    F64X2,
                    &[left_1, right_1],
                )?;
                let res_2 = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWiseFloat($op)),
                    F64X2,
                    &[left_2, right_2],
                )?;
                let res_3 = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWiseFloat($op)),
                    F64X2,
                    &[left_3, right_3],
                )?;

                let low_256 = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), F64X4, &[res_0, res_1])?;
                let high_256 = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), F64X4, &[res_2, res_3])?;
                let result = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Concat),
                    F64X8,
                    &[low_256, high_256],
                )?;

                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

packed_double_zmm!(
    VaddpdZmmZmmZmm,
    engine_forms::VADDPD_ZMM_ZMM_ZMM,
    FloatingOp::Add,
    0x1608
);
packed_double_zmm!(
    VaddpdZmmZmmMem,
    engine_forms::VADDPD_ZMM_ZMM_MEM,
    FloatingOp::Add,
    0x1609
);
packed_double_zmm!(
    VsubpdZmmZmmZmm,
    engine_forms::VSUBPD_ZMM_ZMM_ZMM,
    FloatingOp::Sub,
    0x160A
);
packed_double_zmm!(
    VsubpdZmmZmmMem,
    engine_forms::VSUBPD_ZMM_ZMM_MEM,
    FloatingOp::Sub,
    0x160B
);
packed_double_zmm!(
    VmulpdZmmZmmZmm,
    engine_forms::VMULPD_ZMM_ZMM_ZMM,
    FloatingOp::Mul,
    0x160C
);
packed_double_zmm!(
    VmulpdZmmZmmMem,
    engine_forms::VMULPD_ZMM_ZMM_MEM,
    FloatingOp::Mul,
    0x160D
);
packed_double_zmm!(
    VdivpdZmmZmmZmm,
    engine_forms::VDIVPD_ZMM_ZMM_ZMM,
    FloatingOp::Div,
    0x160E
);
packed_double_zmm!(
    VdivpdZmmZmmMem,
    engine_forms::VDIVPD_ZMM_ZMM_MEM,
    FloatingOp::Div,
    0x160F
);

// ---------------------------------------------------------------------------
// Scalar single-precision float arithmetic (EVEX encoded, XMM operand)
// ---------------------------------------------------------------------------

macro_rules! scalar_float_evex {
    ($name:ident, $form:expr, $op:expr, $memory:expr, $rule:expr) => {
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
                let src1 = out.read_operand(src1_idx, F32X4)?;
                let zero = const_u64(out, 0)?;
                let thirty_two = const_u64(out, 32)?;
                let left = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F32, &[src1, zero])?;
                let right = if $memory {
                    out.read_operand(src2_idx, F32)?
                } else {
                    let src2 = out.read_operand(src2_idx, F32X4)?;
                    out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F32, &[src2, zero])?
                };
                let low = out.emit(SemanticOp::Float($op), F32, &[left, right])?;
                let upper = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U96,
                    &[src1, thirty_two],
                )?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), F32X4, &[low, upper])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

scalar_float_evex!(
    VaddssEvexXmmXmmXmm,
    forms::VADDSS_EVEX_XMM_XMM_XMM,
    FloatingOp::Add,
    false,
    0x1610
);
scalar_float_evex!(
    VaddssEvexXmmXmmMem32,
    forms::VADDSS_EVEX_XMM_XMM_MEM32,
    FloatingOp::Add,
    true,
    0x1611
);
scalar_float_evex!(
    VsubssEvexXmmXmmXmm,
    forms::VSUBSS_EVEX_XMM_XMM_XMM,
    FloatingOp::Sub,
    false,
    0x1612
);
scalar_float_evex!(
    VsubssEvexXmmXmmMem32,
    forms::VSUBSS_EVEX_XMM_XMM_MEM32,
    FloatingOp::Sub,
    true,
    0x1613
);
scalar_float_evex!(
    VmulssEvexXmmXmmXmm,
    forms::VMULSS_EVEX_XMM_XMM_XMM,
    FloatingOp::Mul,
    false,
    0x1614
);
scalar_float_evex!(
    VmulssEvexXmmXmmMem32,
    forms::VMULSS_EVEX_XMM_XMM_MEM32,
    FloatingOp::Mul,
    true,
    0x1615
);
scalar_float_evex!(
    VdivssEvexXmmXmmXmm,
    forms::VDIVSS_EVEX_XMM_XMM_XMM,
    FloatingOp::Div,
    false,
    0x1616
);
scalar_float_evex!(
    VdivssEvexXmmXmmMem32,
    forms::VDIVSS_EVEX_XMM_XMM_MEM32,
    FloatingOp::Div,
    true,
    0x1617
);

// ---------------------------------------------------------------------------
// Scalar double-precision float arithmetic (EVEX encoded, XMM operand)
// ---------------------------------------------------------------------------

macro_rules! scalar_double_evex {
    ($name:ident, $form:expr, $op:expr, $memory:expr, $rule:expr) => {
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
                let src1 = out.read_operand(src1_idx, F64X2)?;
                let zero = const_u64(out, 0)?;
                let sixty_four = const_u64(out, 64)?;
                let left = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F64, &[src1, zero])?;
                let right = if $memory {
                    out.read_operand(src2_idx, F64)?
                } else {
                    let src2 = out.read_operand(src2_idx, F64X2)?;
                    out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F64, &[src2, zero])?
                };
                let low = out.emit(SemanticOp::Float($op), F64, &[left, right])?;
                let upper = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U64,
                    &[src1, sixty_four],
                )?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), F64X2, &[low, upper])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

scalar_double_evex!(
    VaddsdEvexXmmXmmXmm,
    forms::VADDSD_EVEX_XMM_XMM_XMM,
    FloatingOp::Add,
    false,
    0x1618
);
scalar_double_evex!(
    VaddsdEvexXmmXmmMem64,
    forms::VADDSD_EVEX_XMM_XMM_MEM64,
    FloatingOp::Add,
    true,
    0x1619
);
scalar_double_evex!(
    VsubsdEvexXmmXmmXmm,
    forms::VSUBSD_EVEX_XMM_XMM_XMM,
    FloatingOp::Sub,
    false,
    0x161A
);
scalar_double_evex!(
    VsubsdEvexXmmXmmMem64,
    forms::VSUBSD_EVEX_XMM_XMM_MEM64,
    FloatingOp::Sub,
    true,
    0x161B
);
scalar_double_evex!(
    VmulsdEvexXmmXmmXmm,
    forms::VMULSD_EVEX_XMM_XMM_XMM,
    FloatingOp::Mul,
    false,
    0x161C
);
scalar_double_evex!(
    VmulsdEvexXmmXmmMem64,
    forms::VMULSD_EVEX_XMM_XMM_MEM64,
    FloatingOp::Mul,
    true,
    0x161D
);
scalar_double_evex!(
    VdivsdEvexXmmXmmXmm,
    forms::VDIVSD_EVEX_XMM_XMM_XMM,
    FloatingOp::Div,
    false,
    0x161E
);
scalar_double_evex!(
    VdivsdEvexXmmXmmMem64,
    forms::VDIVSD_EVEX_XMM_XMM_MEM64,
    FloatingOp::Div,
    true,
    0x161F
);

// ---------------------------------------------------------------------------
// Packed logic (512-bit ZMM)
// ---------------------------------------------------------------------------

macro_rules! logic_zmm {
    ($name:ident, $form:expr, $op:ident, $rule:expr) => {
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
                let left = out.read_operand(src1_idx, U512)?;
                let right = out.read_operand(src2_idx, U512)?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::$op), U512, &[left, right])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

macro_rules! andn_zmm {
    ($name:ident, $form:expr, $rule:expr) => {
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
                let left = out.read_operand(src1_idx, U512)?;
                let right = out.read_operand(src2_idx, U512)?;
                let not_left = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U512, &[left])?;
                let result = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U512, &[not_left, right])?;
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

logic_zmm!(VandpsZmmZmmZmm, engine_forms::VANDPS_ZMM_ZMM_ZMM, And, 0x1620);
logic_zmm!(VandpsZmmZmmMem, engine_forms::VANDPS_ZMM_ZMM_MEM, And, 0x1621);
andn_zmm!(VandnpsZmmZmmZmm, engine_forms::VANDNPS_ZMM_ZMM_ZMM, 0x1622);
andn_zmm!(VandnpsZmmZmmMem, engine_forms::VANDNPS_ZMM_ZMM_MEM, 0x1623);
logic_zmm!(VorpsZmmZmmZmm, engine_forms::VORPS_ZMM_ZMM_ZMM, Or, 0x1624);
logic_zmm!(VorpsZmmZmmMem, engine_forms::VORPS_ZMM_ZMM_MEM, Or, 0x1625);
logic_zmm!(VxorpsZmmZmmZmm, engine_forms::VXORPS_ZMM_ZMM_ZMM, Xor, 0x1626);
logic_zmm!(VxorpsZmmZmmMem, engine_forms::VXORPS_ZMM_ZMM_MEM, Xor, 0x1627);

logic_zmm!(VandpdZmmZmmZmm, engine_forms::VANDPD_ZMM_ZMM_ZMM, And, 0x1628);
logic_zmm!(VandpdZmmZmmMem, engine_forms::VANDPD_ZMM_ZMM_MEM, And, 0x1629);
andn_zmm!(VandnpdZmmZmmZmm, engine_forms::VANDNPD_ZMM_ZMM_ZMM, 0x162A);
andn_zmm!(VandnpdZmmZmmMem, engine_forms::VANDNPD_ZMM_ZMM_MEM, 0x162B);
logic_zmm!(VorpdZmmZmmZmm, engine_forms::VORPD_ZMM_ZMM_ZMM, Or, 0x162C);
logic_zmm!(VorpdZmmZmmMem, engine_forms::VORPD_ZMM_ZMM_MEM, Or, 0x162D);
logic_zmm!(VxorpdZmmZmmZmm, engine_forms::VXORPD_ZMM_ZMM_ZMM, Xor, 0x162E);
logic_zmm!(VxorpdZmmZmmMem, engine_forms::VXORPD_ZMM_ZMM_MEM, Xor, 0x162F);

// ---------------------------------------------------------------------------
// Mask-register logic operations (KAND, KANDN, KOR, KXOR, KNOT, KXNOR)
// ---------------------------------------------------------------------------

macro_rules! mask_binop {
    ($name:ident, $form:expr, $op:ident, $mask16:expr, $rule:expr) => {
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
                let src1 = out.read_operand(1, U64)?;
                let src2 = out.read_operand(2, U64)?;
                let res = out.emit(SemanticOp::Primitive(PrimitiveOp::$op), U64, &[src1, src2])?;
                let result = if $mask16 {
                    let mask = const_u64(out, 0xFFFF)?;
                    out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[res, mask])?
                } else {
                    res
                };
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

macro_rules! mask_andn {
    ($name:ident, $form:expr, $mask16:expr, $rule:expr) => {
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
                let src1 = out.read_operand(1, U64)?;
                let src2 = out.read_operand(2, U64)?;
                let not_src1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U64, &[src1])?;
                let res = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[not_src1, src2])?;
                let result = if $mask16 {
                    let mask = const_u64(out, 0xFFFF)?;
                    out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[res, mask])?
                } else {
                    res
                };
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

macro_rules! mask_knot {
    ($name:ident, $form:expr, $mask16:expr, $rule:expr) => {
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
                let src1 = out.read_operand(1, U64)?;
                let not_src1 = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U64, &[src1])?;
                let result = if $mask16 {
                    let mask = const_u64(out, 0xFFFF)?;
                    out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[not_src1, mask])?
                } else {
                    not_src1
                };
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

macro_rules! mask_kxnor {
    ($name:ident, $form:expr, $mask16:expr, $rule:expr) => {
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
                let src1 = out.read_operand(1, U64)?;
                let src2 = out.read_operand(2, U64)?;
                let xor_val = out.emit(SemanticOp::Primitive(PrimitiveOp::Xor), U64, &[src1, src2])?;
                let not_xor = out.emit(SemanticOp::Primitive(PrimitiveOp::Not), U64, &[xor_val])?;
                let result = if $mask16 {
                    let mask = const_u64(out, 0xFFFF)?;
                    out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[not_xor, mask])?
                } else {
                    not_xor
                };
                out.write_operand(0, result)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

mask_binop!(KandwKKK, forms::KANDW_K_K_K, And, true, 0x1630);
mask_andn!(KandnwKKK, forms::KANDNW_K_K_K, true, 0x1631);
mask_binop!(KorwKKK, forms::KORW_K_K_K, Or, true, 0x1632);
mask_binop!(KxorwKKK, forms::KXORW_K_K_K, Xor, true, 0x1633);
mask_knot!(KnotwKK, forms::KNOTW_K_K, true, 0x1634);
mask_kxnor!(KxnorwKKK, forms::KXNORW_K_K_K, true, 0x1635);

mask_binop!(KandqKKK, forms::KANDQ_K_K_K, And, false, 0x1636);
mask_andn!(KandnqKKK, forms::KANDNQ_K_K_K, false, 0x1637);
mask_binop!(KorqKKK, forms::KORQ_K_K_K, Or, false, 0x1638);
mask_binop!(KxorqKKK, forms::KXORQ_K_K_K, Xor, false, 0x1639);
mask_knot!(KnotqKK, forms::KNOTQ_K_K, false, 0x163A);
mask_kxnor!(KxnorqKKK, forms::KXNORQ_K_K_K, false, 0x163B);

/// Returns all AVX-512 and opmask semantic providers.
pub fn providers() -> Vec<Arc<dyn SemanticProvider>> {
    vec![
        // Packed single-precision arithmetic (8)
        Arc::new(VaddpsZmmZmmZmm),
        Arc::new(VaddpsZmmZmmMem),
        Arc::new(VsubpsZmmZmmZmm),
        Arc::new(VsubpsZmmZmmMem),
        Arc::new(VmulpsZmmZmmZmm),
        Arc::new(VmulpsZmmZmmMem),
        Arc::new(VdivpsZmmZmmZmm),
        Arc::new(VdivpsZmmZmmMem),
        // Packed double-precision arithmetic (8)
        Arc::new(VaddpdZmmZmmZmm),
        Arc::new(VaddpdZmmZmmMem),
        Arc::new(VsubpdZmmZmmZmm),
        Arc::new(VsubpdZmmZmmMem),
        Arc::new(VmulpdZmmZmmZmm),
        Arc::new(VmulpdZmmZmmMem),
        Arc::new(VdivpdZmmZmmZmm),
        Arc::new(VdivpdZmmZmmMem),
        // Scalar single-precision arithmetic (8)
        Arc::new(VaddssEvexXmmXmmXmm),
        Arc::new(VaddssEvexXmmXmmMem32),
        Arc::new(VsubssEvexXmmXmmXmm),
        Arc::new(VsubssEvexXmmXmmMem32),
        Arc::new(VmulssEvexXmmXmmXmm),
        Arc::new(VmulssEvexXmmXmmMem32),
        Arc::new(VdivssEvexXmmXmmXmm),
        Arc::new(VdivssEvexXmmXmmMem32),
        // Scalar double-precision arithmetic (8)
        Arc::new(VaddsdEvexXmmXmmXmm),
        Arc::new(VaddsdEvexXmmXmmMem64),
        Arc::new(VsubsdEvexXmmXmmXmm),
        Arc::new(VsubsdEvexXmmXmmMem64),
        Arc::new(VmulsdEvexXmmXmmXmm),
        Arc::new(VmulsdEvexXmmXmmMem64),
        Arc::new(VdivsdEvexXmmXmmXmm),
        Arc::new(VdivsdEvexXmmXmmMem64),
        // Packed single/double float logic (16)
        Arc::new(VandpsZmmZmmZmm),
        Arc::new(VandpsZmmZmmMem),
        Arc::new(VandnpsZmmZmmZmm),
        Arc::new(VandnpsZmmZmmMem),
        Arc::new(VorpsZmmZmmZmm),
        Arc::new(VorpsZmmZmmMem),
        Arc::new(VxorpsZmmZmmZmm),
        Arc::new(VxorpsZmmZmmMem),
        Arc::new(VandpdZmmZmmZmm),
        Arc::new(VandpdZmmZmmMem),
        Arc::new(VandnpdZmmZmmZmm),
        Arc::new(VandnpdZmmZmmMem),
        Arc::new(VorpdZmmZmmZmm),
        Arc::new(VorpdZmmZmmMem),
        Arc::new(VxorpdZmmZmmZmm),
        Arc::new(VxorpdZmmZmmMem),
        // Opmask logic (12)
        Arc::new(KandwKKK),
        Arc::new(KandnwKKK),
        Arc::new(KorwKKK),
        Arc::new(KxorwKKK),
        Arc::new(KnotwKK),
        Arc::new(KxnorwKKK),
        Arc::new(KandqKKK),
        Arc::new(KandnqKKK),
        Arc::new(KorqKKK),
        Arc::new(KxorqKKK),
        Arc::new(KnotqKK),
        Arc::new(KxnorqKKK),
    ]
}

/// Alias matching module-specific naming pattern.
pub fn avx512_providers() -> Vec<Arc<dyn SemanticProvider>> {
    providers()
}
