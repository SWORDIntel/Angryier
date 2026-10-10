#![forbid(unsafe_code)]
#![allow(dead_code)]

//! AVX-512 (EVEX) arithmetic, logic, and opmask semantic providers.
//!
//! Covers:
//! - Packed single/double precision float arithmetic: VADDPS, VSUBPS, VMULPS, VDIVPS,
//!   VADDPD, VSUBPD, VMULPD, VDIVPD (ZMM reg-reg and reg-mem512 forms)
//! - EVEX packed single/double-precision float arithmetic: VADDPS, VSUBPS, VMULPS, VDIVPS,
//!   VADDPD, VSUBPD, VMULPD, VDIVPD
//!   (XMM reg-reg/reg-mem128 and YMM reg-reg/reg-mem256 forms, with opmask
//!   merge/zero and upper-lane zeroing; masked-memory and embedded-broadcast
//!   forms are intentionally unmapped)
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

    // AVX-512/AVX VNNI dot-product forms (0x1140..0x1157).
    // All VNNI encodings are EVEX: [dst, opmask, src1, src2].
    pub const VPDPBUSD_XMM_XMM_XMM: u32 = 0x1140;
    pub const VPDPBUSD_XMM_XMM_MEM128: u32 = 0x1141;
    pub const VPDPBUSD_YMM_YMM_YMM: u32 = 0x1142;
    pub const VPDPBUSD_YMM_YMM_MEM: u32 = 0x1143;
    pub const VPDPBUSD_ZMM_ZMM_ZMM: u32 = 0x1144;
    pub const VPDPBUSD_ZMM_ZMM_MEM: u32 = 0x1145;
    pub const VPDPBUSDS_XMM_XMM_XMM: u32 = 0x1146;
    pub const VPDPBUSDS_XMM_XMM_MEM128: u32 = 0x1147;
    pub const VPDPBUSDS_YMM_YMM_YMM: u32 = 0x1148;
    pub const VPDPBUSDS_YMM_YMM_MEM: u32 = 0x1149;
    pub const VPDPBUSDS_ZMM_ZMM_ZMM: u32 = 0x114A;
    pub const VPDPBUSDS_ZMM_ZMM_MEM: u32 = 0x114B;
    pub const VPDPWSSD_XMM_XMM_XMM: u32 = 0x114C;
    pub const VPDPWSSD_XMM_XMM_MEM128: u32 = 0x114D;
    pub const VPDPWSSD_YMM_YMM_YMM: u32 = 0x114E;
    pub const VPDPWSSD_YMM_YMM_MEM: u32 = 0x114F;
    pub const VPDPWSSD_ZMM_ZMM_ZMM: u32 = 0x1150;
    pub const VPDPWSSD_ZMM_ZMM_MEM: u32 = 0x1151;
    pub const VPDPWSSDS_XMM_XMM_XMM: u32 = 0x1152;
    pub const VPDPWSSDS_XMM_XMM_MEM128: u32 = 0x1153;
    pub const VPDPWSSDS_YMM_YMM_YMM: u32 = 0x1154;
    pub const VPDPWSSDS_YMM_YMM_MEM: u32 = 0x1155;
    pub const VPDPWSSDS_ZMM_ZMM_ZMM: u32 = 0x1156;
    pub const VPDPWSSDS_ZMM_ZMM_MEM: u32 = 0x1157;

    // AVX VNNI INT8 dot-product forms (0x1158..0x116F).
    pub const VPDPBSSD_XMM_XMM_XMM: u32 = 0x1158;
    pub const VPDPBSSD_XMM_XMM_MEM128: u32 = 0x1159;
    pub const VPDPBSSD_YMM_YMM_YMM: u32 = 0x115A;
    pub const VPDPBSSD_YMM_YMM_MEM: u32 = 0x115B;
    pub const VPDPBSSD_ZMM_ZMM_ZMM: u32 = 0x115C;
    pub const VPDPBSSD_ZMM_ZMM_MEM: u32 = 0x115D;
    pub const VPDPBSSDS_XMM_XMM_XMM: u32 = 0x115E;
    pub const VPDPBSSDS_XMM_XMM_MEM128: u32 = 0x115F;
    pub const VPDPBSSDS_YMM_YMM_YMM: u32 = 0x1160;
    pub const VPDPBSSDS_YMM_YMM_MEM: u32 = 0x1161;
    pub const VPDPBSSDS_ZMM_ZMM_ZMM: u32 = 0x1162;
    pub const VPDPBSSDS_ZMM_ZMM_MEM: u32 = 0x1163;
    pub const VPDPBSUD_XMM_XMM_XMM: u32 = 0x1164;
    pub const VPDPBSUD_XMM_XMM_MEM128: u32 = 0x1165;
    pub const VPDPBSUD_YMM_YMM_YMM: u32 = 0x1166;
    pub const VPDPBSUD_YMM_YMM_MEM: u32 = 0x1167;
    pub const VPDPBSUD_ZMM_ZMM_ZMM: u32 = 0x1168;
    pub const VPDPBSUD_ZMM_ZMM_MEM: u32 = 0x1169;
    pub const VPDPBSUDS_XMM_XMM_XMM: u32 = 0x116A;
    pub const VPDPBSUDS_XMM_XMM_MEM128: u32 = 0x116B;
    pub const VPDPBSUDS_YMM_YMM_YMM: u32 = 0x116C;
    pub const VPDPBSUDS_YMM_YMM_MEM: u32 = 0x116D;
    pub const VPDPBSUDS_ZMM_ZMM_ZMM: u32 = 0x116E;
    pub const VPDPBSUDS_ZMM_ZMM_MEM: u32 = 0x116F;

    // AVX-512 EVEX packed single-precision arithmetic, 128/256-bit forms
    // (0x1170..0x117F). EVEX decodes report the opmask operand (k0..k7) as
    // operand 1, so the form-map shapes are [Xmm|Ymm, Reg64, Xmm|Ymm, {Xmm|Ymm,
    // Mem128|Mem}]. The `{1to4}`/`{1to8}` embedded-broadcast memory encodings
    // decode with a 32-bit memory operand (shape Mem32) and stay unmapped:
    // `VectorOp::Broadcast` has no compact-IR lowering, so broadcast semantics
    // cannot be represented end to end.
    pub const VADDPS_EVEX_XMM_XMM_XMM: u32 = 0x1170;
    pub const VADDPS_EVEX_XMM_XMM_MEM128: u32 = 0x1171;
    pub const VADDPS_EVEX_YMM_YMM_YMM: u32 = 0x1172;
    pub const VADDPS_EVEX_YMM_YMM_MEM: u32 = 0x1173;
    pub const VSUBPS_EVEX_XMM_XMM_XMM: u32 = 0x1174;
    pub const VSUBPS_EVEX_XMM_XMM_MEM128: u32 = 0x1175;
    pub const VSUBPS_EVEX_YMM_YMM_YMM: u32 = 0x1176;
    pub const VSUBPS_EVEX_YMM_YMM_MEM: u32 = 0x1177;
    pub const VMULPS_EVEX_XMM_XMM_XMM: u32 = 0x1178;
    pub const VMULPS_EVEX_XMM_XMM_MEM128: u32 = 0x1179;
    pub const VMULPS_EVEX_YMM_YMM_YMM: u32 = 0x117A;
    pub const VMULPS_EVEX_YMM_YMM_MEM: u32 = 0x117B;
    pub const VDIVPS_EVEX_XMM_XMM_XMM: u32 = 0x117C;
    pub const VDIVPS_EVEX_XMM_XMM_MEM128: u32 = 0x117D;
    pub const VDIVPS_EVEX_YMM_YMM_YMM: u32 = 0x117E;
    pub const VDIVPS_EVEX_YMM_YMM_MEM: u32 = 0x117F;

    // EVEX packed double-precision arithmetic, 128/256-bit forms (0x1180..0x119F).
    pub const VADDPD_EVEX_XMM_XMM_XMM: u32 = 0x1180;
    pub const VADDPD_EVEX_XMM_XMM_MEM128: u32 = 0x1181;
    pub const VADDPD_EVEX_YMM_YMM_YMM: u32 = 0x1182;
    pub const VADDPD_EVEX_YMM_YMM_MEM: u32 = 0x1183;
    pub const VSUBPD_EVEX_XMM_XMM_XMM: u32 = 0x1184;
    pub const VSUBPD_EVEX_XMM_XMM_MEM128: u32 = 0x1185;
    pub const VSUBPD_EVEX_YMM_YMM_YMM: u32 = 0x1186;
    pub const VSUBPD_EVEX_YMM_YMM_MEM: u32 = 0x1187;
    pub const VMULPD_EVEX_XMM_XMM_XMM: u32 = 0x1188;
    pub const VMULPD_EVEX_XMM_XMM_MEM128: u32 = 0x1189;
    pub const VMULPD_EVEX_YMM_YMM_YMM: u32 = 0x118A;
    pub const VMULPD_EVEX_YMM_YMM_MEM: u32 = 0x118B;
    pub const VDIVPD_EVEX_XMM_XMM_XMM: u32 = 0x118C;
    pub const VDIVPD_EVEX_XMM_XMM_MEM128: u32 = 0x118D;
    pub const VDIVPD_EVEX_YMM_YMM_YMM: u32 = 0x118E;
    pub const VDIVPD_EVEX_YMM_YMM_MEM: u32 = 0x118F;
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
const F32X12: SemanticType = SemanticType::Vector {
    lanes: 12,
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
const F64X6: SemanticType = SemanticType::Vector {
    lanes: 6,
    lane: ScalarType::Float(FloatFormat::F64),
};
const F64X8: SemanticType = SemanticType::Vector {
    lanes: 8,
    lane: ScalarType::Float(FloatFormat::F64),
};

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
const U1: SemanticType = SemanticType::Scalar(ScalarType::BitVec(1));

const I32X16: SemanticType = SemanticType::Vector {
    lanes: 16,
    lane: ScalarType::BitVec(32),
};
const I64X8: SemanticType = SemanticType::Vector {
    lanes: 8,
    lane: ScalarType::BitVec(64),
};

fn const_u64(out: &mut dyn SemanticBuilder, val: u64) -> Result<ValueId, SemanticError> {
    out.constant(U64, &val.to_le_bytes())
}

fn const_f32(out: &mut dyn SemanticBuilder, val: f32) -> Result<ValueId, SemanticError> {
    out.constant(F32, &val.to_le_bytes())
}

fn const_f64(out: &mut dyn SemanticBuilder, val: f64) -> Result<ValueId, SemanticError> {
    out.constant(F64, &val.to_le_bytes())
}

/// An all-zero F32 vector constant of `lanes` lanes (the upper-lane zeroing
/// tail for EVEX.128/EVEX.256 destination writes).
fn zero_f32_lanes(out: &mut dyn SemanticBuilder, ty: SemanticType, lanes: usize) -> Result<ValueId, SemanticError> {
    let mut bytes = Vec::with_capacity(lanes * 4);
    for _ in 0..lanes {
        bytes.extend_from_slice(&0f32.to_le_bytes());
    }
    out.constant(ty, &bytes)
}

fn zero_f64_lanes(out: &mut dyn SemanticBuilder, ty: SemanticType, lanes: usize) -> Result<ValueId, SemanticError> {
    let mut bytes = Vec::with_capacity(lanes * 8);
    for _ in 0..lanes {
        bytes.extend_from_slice(&0f64.to_le_bytes());
    }
    out.constant(ty, &bytes)
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

                let final_res = apply_evex_mask(insn, out, F32X16, None, result)?;
                out.write_operand(0, final_res)?;
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

                let final_res = apply_evex_mask(insn, out, F64X8, None, result)?;
                out.write_operand(0, final_res)?;
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
// Packed single-precision float arithmetic, EVEX 128/256-bit forms
// ---------------------------------------------------------------------------
//
// EVEX XMM/YMM destinations are partial views of a 512-bit ZMM parent whose
// write behavior is `SemanticDefined` (the parent is preserved unless the
// provider says otherwise). EVEX semantics require the lanes above VL to be
// zeroed, so each provider concatenates the masked low vector with an all-zero
// tail and replaces the whole ZMM parent via `write_register`.

macro_rules! packed_float_evex_xmm {
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
                let destination = insn.operand(0).ok_or(SemanticError::InvalidOperand)?;
                let parent = match destination.kind {
                    angryier_semantics::OperandKind::Register(view)
                        if destination.width_bits == 128 && view.width_bits == 128 && view.bit_offset == 0 =>
                    {
                        view.parent
                    }
                    _ => return Err(SemanticError::InvalidOperand),
                };
                let (src1_idx, src2_idx) = evex_source_indices(insn);
                let left = out.read_operand(src1_idx, F32X4)?;
                let right = out.read_operand(src2_idx, F32X4)?;
                let low = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWiseFloat($op)),
                    F32X4,
                    &[left, right],
                )?;
                let masked_low = apply_evex_mask(insn, out, F32X4, None, low)?;
                let upper_zero = zero_f32_lanes(out, F32X12, 12)?;
                let full = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Concat),
                    F32X16,
                    &[masked_low, upper_zero],
                )?;
                out.write_register(parent, full)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

// EVEX.128: VL=4 lanes, upper 384 bits (F32X12) of the ZMM parent zeroed.
packed_float_evex_xmm!(
    VaddpsEvexXmmXmmXmm,
    forms::VADDPS_EVEX_XMM_XMM_XMM,
    FloatingOp::Add,
    0x1670
);
packed_float_evex_xmm!(
    VaddpsEvexXmmXmmMem128,
    forms::VADDPS_EVEX_XMM_XMM_MEM128,
    FloatingOp::Add,
    0x1671
);
packed_float_evex_xmm!(
    VsubpsEvexXmmXmmXmm,
    forms::VSUBPS_EVEX_XMM_XMM_XMM,
    FloatingOp::Sub,
    0x1672
);
packed_float_evex_xmm!(
    VsubpsEvexXmmXmmMem128,
    forms::VSUBPS_EVEX_XMM_XMM_MEM128,
    FloatingOp::Sub,
    0x1673
);
packed_float_evex_xmm!(
    VmulpsEvexXmmXmmXmm,
    forms::VMULPS_EVEX_XMM_XMM_XMM,
    FloatingOp::Mul,
    0x1674
);
packed_float_evex_xmm!(
    VmulpsEvexXmmXmmMem128,
    forms::VMULPS_EVEX_XMM_XMM_MEM128,
    FloatingOp::Mul,
    0x1675
);
packed_float_evex_xmm!(
    VdivpsEvexXmmXmmXmm,
    forms::VDIVPS_EVEX_XMM_XMM_XMM,
    FloatingOp::Div,
    0x1676
);
packed_float_evex_xmm!(
    VdivpsEvexXmmXmmMem128,
    forms::VDIVPS_EVEX_XMM_XMM_MEM128,
    FloatingOp::Div,
    0x1677
);

macro_rules! packed_float_evex_ymm {
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
                let destination = insn.operand(0).ok_or(SemanticError::InvalidOperand)?;
                let parent = match destination.kind {
                    angryier_semantics::OperandKind::Register(view)
                        if destination.width_bits == 256 && view.width_bits == 256 && view.bit_offset == 0 =>
                    {
                        view.parent
                    }
                    _ => return Err(SemanticError::InvalidOperand),
                };
                let (src1_idx, src2_idx) = evex_source_indices(insn);
                let left = out.read_operand(src1_idx, F32X8)?;
                let right = out.read_operand(src2_idx, F32X8)?;
                let off0 = const_u64(out, 0)?;
                let off128 = const_u64(out, 128)?;
                // Lane-wise float ops evaluate in 128-bit lanes, so the two
                // halves are computed separately and rejoined (same chunking
                // the ZMM providers use).
                let left_lo = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F32X4, &[left, off0])?;
                let left_hi = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    F32X4,
                    &[left, off128],
                )?;
                let right_lo = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F32X4, &[right, off0])?;
                let right_hi = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    F32X4,
                    &[right, off128],
                )?;
                let res_lo = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWiseFloat($op)),
                    F32X4,
                    &[left_lo, right_lo],
                )?;
                let res_hi = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWiseFloat($op)),
                    F32X4,
                    &[left_hi, right_hi],
                )?;
                let result = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Concat),
                    F32X8,
                    &[res_lo, res_hi],
                )?;
                let masked = apply_evex_mask(insn, out, F32X8, None, result)?;
                let upper_zero = zero_f32_lanes(out, F32X8, 8)?;
                let full = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Concat),
                    F32X16,
                    &[masked, upper_zero],
                )?;
                out.write_register(parent, full)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

// EVEX.256: VL=8 lanes, upper 256 bits (F32X8) of the ZMM parent zeroed.
packed_float_evex_ymm!(
    VaddpsEvexYmmYmmYmm,
    forms::VADDPS_EVEX_YMM_YMM_YMM,
    FloatingOp::Add,
    0x1678
);
packed_float_evex_ymm!(
    VaddpsEvexYmmYmmMem,
    forms::VADDPS_EVEX_YMM_YMM_MEM,
    FloatingOp::Add,
    0x1679
);
packed_float_evex_ymm!(
    VsubpsEvexYmmYmmYmm,
    forms::VSUBPS_EVEX_YMM_YMM_YMM,
    FloatingOp::Sub,
    0x167A
);
packed_float_evex_ymm!(
    VsubpsEvexYmmYmmMem,
    forms::VSUBPS_EVEX_YMM_YMM_MEM,
    FloatingOp::Sub,
    0x167B
);
packed_float_evex_ymm!(
    VmulpsEvexYmmYmmYmm,
    forms::VMULPS_EVEX_YMM_YMM_YMM,
    FloatingOp::Mul,
    0x167C
);
packed_float_evex_ymm!(
    VmulpsEvexYmmYmmMem,
    forms::VMULPS_EVEX_YMM_YMM_MEM,
    FloatingOp::Mul,
    0x167D
);
packed_float_evex_ymm!(
    VdivpsEvexYmmYmmYmm,
    forms::VDIVPS_EVEX_YMM_YMM_YMM,
    FloatingOp::Div,
    0x167E
);
packed_float_evex_ymm!(
    VdivpsEvexYmmYmmMem,
    forms::VDIVPS_EVEX_YMM_YMM_MEM,
    FloatingOp::Div,
    0x167F
);

// ---------------------------------------------------------------------------
// Packed double-precision float arithmetic, EVEX 128/256-bit forms
// ---------------------------------------------------------------------------

macro_rules! packed_double_evex_xmm {
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
                let destination = insn.operand(0).ok_or(SemanticError::InvalidOperand)?;
                let parent = match destination.kind {
                    angryier_semantics::OperandKind::Register(view)
                        if destination.width_bits == 128 && view.width_bits == 128 && view.bit_offset == 0 =>
                    {
                        view.parent
                    }
                    _ => return Err(SemanticError::InvalidOperand),
                };
                let (src1_idx, src2_idx) = evex_source_indices(insn);
                let left = out.read_operand(src1_idx, F64X2)?;
                let right = out.read_operand(src2_idx, F64X2)?;
                let low = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWiseFloat($op)),
                    F64X2,
                    &[left, right],
                )?;
                let masked_low = apply_evex_mask(insn, out, F64X2, None, low)?;
                let upper_zero = zero_f64_lanes(out, F64X6, 6)?;
                let full = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Concat),
                    F64X8,
                    &[masked_low, upper_zero],
                )?;
                out.write_register(parent, full)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

macro_rules! packed_double_evex_ymm {
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
                let destination = insn.operand(0).ok_or(SemanticError::InvalidOperand)?;
                let parent = match destination.kind {
                    angryier_semantics::OperandKind::Register(view)
                        if destination.width_bits == 256 && view.width_bits == 256 && view.bit_offset == 0 =>
                    {
                        view.parent
                    }
                    _ => return Err(SemanticError::InvalidOperand),
                };
                let (src1_idx, src2_idx) = evex_source_indices(insn);
                let left = out.read_operand(src1_idx, F64X4)?;
                let right = out.read_operand(src2_idx, F64X4)?;
                // Lane-wise float lowering is defined over 128-bit chunks.
                let off0 = const_u64(out, 0)?;
                let off128 = const_u64(out, 128)?;
                let left_lo = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F64X2, &[left, off0])?;
                let left_hi = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    F64X2,
                    &[left, off128],
                )?;
                let right_lo = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F64X2, &[right, off0])?;
                let right_hi = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    F64X2,
                    &[right, off128],
                )?;
                let res_lo = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWiseFloat($op)),
                    F64X2,
                    &[left_lo, right_lo],
                )?;
                let res_hi = out.emit(
                    SemanticOp::Vector(VectorOp::LaneWiseFloat($op)),
                    F64X2,
                    &[left_hi, right_hi],
                )?;
                let result = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Concat),
                    F64X4,
                    &[res_lo, res_hi],
                )?;
                let masked = apply_evex_mask(insn, out, F64X4, None, result)?;
                let upper_zero = zero_f64_lanes(out, F64X4, 4)?;
                let full = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Concat),
                    F64X8,
                    &[masked, upper_zero],
                )?;
                out.write_register(parent, full)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

packed_double_evex_xmm!(
    VaddpdEvexXmmXmmXmm,
    forms::VADDPD_EVEX_XMM_XMM_XMM,
    FloatingOp::Add,
    0x1680
);
packed_double_evex_xmm!(
    VaddpdEvexXmmXmmMem128,
    forms::VADDPD_EVEX_XMM_XMM_MEM128,
    FloatingOp::Add,
    0x1681
);
packed_double_evex_xmm!(
    VsubpdEvexXmmXmmXmm,
    forms::VSUBPD_EVEX_XMM_XMM_XMM,
    FloatingOp::Sub,
    0x1682
);
packed_double_evex_xmm!(
    VsubpdEvexXmmXmmMem128,
    forms::VSUBPD_EVEX_XMM_XMM_MEM128,
    FloatingOp::Sub,
    0x1683
);
packed_double_evex_xmm!(
    VmulpdEvexXmmXmmXmm,
    forms::VMULPD_EVEX_XMM_XMM_XMM,
    FloatingOp::Mul,
    0x1684
);
packed_double_evex_xmm!(
    VmulpdEvexXmmXmmMem128,
    forms::VMULPD_EVEX_XMM_XMM_MEM128,
    FloatingOp::Mul,
    0x1685
);
packed_double_evex_xmm!(
    VdivpdEvexXmmXmmXmm,
    forms::VDIVPD_EVEX_XMM_XMM_XMM,
    FloatingOp::Div,
    0x1686
);
packed_double_evex_xmm!(
    VdivpdEvexXmmXmmMem128,
    forms::VDIVPD_EVEX_XMM_XMM_MEM128,
    FloatingOp::Div,
    0x1687
);
packed_double_evex_ymm!(
    VaddpdEvexYmmYmmYmm,
    forms::VADDPD_EVEX_YMM_YMM_YMM,
    FloatingOp::Add,
    0x1688
);
packed_double_evex_ymm!(
    VaddpdEvexYmmYmmMem,
    forms::VADDPD_EVEX_YMM_YMM_MEM,
    FloatingOp::Add,
    0x1689
);
packed_double_evex_ymm!(
    VsubpdEvexYmmYmmYmm,
    forms::VSUBPD_EVEX_YMM_YMM_YMM,
    FloatingOp::Sub,
    0x168A
);
packed_double_evex_ymm!(
    VsubpdEvexYmmYmmMem,
    forms::VSUBPD_EVEX_YMM_YMM_MEM,
    FloatingOp::Sub,
    0x168B
);
packed_double_evex_ymm!(
    VmulpdEvexYmmYmmYmm,
    forms::VMULPD_EVEX_YMM_YMM_YMM,
    FloatingOp::Mul,
    0x168C
);
packed_double_evex_ymm!(
    VmulpdEvexYmmYmmMem,
    forms::VMULPD_EVEX_YMM_YMM_MEM,
    FloatingOp::Mul,
    0x168D
);
packed_double_evex_ymm!(
    VdivpdEvexYmmYmmYmm,
    forms::VDIVPD_EVEX_YMM_YMM_YMM,
    FloatingOp::Div,
    0x168E
);
packed_double_evex_ymm!(
    VdivpdEvexYmmYmmMem,
    forms::VDIVPD_EVEX_YMM_YMM_MEM,
    FloatingOp::Div,
    0x168F
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
                let final_low = if let Some(k) = evex_opmask(insn) {
                    if k >= 1 {
                        let mask = out.read_operand(1, U64)?;
                        let one = const_u64(out, 1)?;
                        let mask_bit0 = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[mask, one])?;
                        let cond = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[mask_bit0, one])?;
                        if insn.is_zeroing_mask() {
                            let zero_f = const_f32(out, 0.0)?;
                            out.emit(
                                SemanticOp::Primitive(PrimitiveOp::Select),
                                F32,
                                &[cond, low, zero_f],
                            )?
                        } else {
                            let old_dst = out.read_operand(0, F32X4)?;
                            let old_low =
                                out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F32, &[old_dst, zero])?;
                            out.emit(
                                SemanticOp::Primitive(PrimitiveOp::Select),
                                F32,
                                &[cond, low, old_low],
                            )?
                        }
                    } else {
                        low
                    }
                } else {
                    low
                };
                let upper = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U96,
                    &[src1, thirty_two],
                )?;
                let result = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Concat),
                    F32X4,
                    &[final_low, upper],
                )?;
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
                let final_low = if let Some(k) = evex_opmask(insn) {
                    if k >= 1 {
                        let mask = out.read_operand(1, U64)?;
                        let one = const_u64(out, 1)?;
                        let mask_bit0 = out.emit(SemanticOp::Primitive(PrimitiveOp::And), U64, &[mask, one])?;
                        let cond = out.emit(SemanticOp::Primitive(PrimitiveOp::Eq), U1, &[mask_bit0, one])?;
                        if insn.is_zeroing_mask() {
                            let zero_f = const_f64(out, 0.0)?;
                            out.emit(
                                SemanticOp::Primitive(PrimitiveOp::Select),
                                F64,
                                &[cond, low, zero_f],
                            )?
                        } else {
                            let old_dst = out.read_operand(0, F64X2)?;
                            let old_low =
                                out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), F64, &[old_dst, zero])?;
                            out.emit(
                                SemanticOp::Primitive(PrimitiveOp::Select),
                                F64,
                                &[cond, low, old_low],
                            )?
                        }
                    } else {
                        low
                    }
                } else {
                    low
                };
                let upper = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Extract),
                    U64,
                    &[src1, sixty_four],
                )?;
                let result = out.emit(
                    SemanticOp::Primitive(PrimitiveOp::Concat),
                    F64X2,
                    &[final_low, upper],
                )?;
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

macro_rules! andn_zmm {
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

logic_zmm!(VandpsZmmZmmZmm, engine_forms::VANDPS_ZMM_ZMM_ZMM, And, I32X16, 0x1620);
logic_zmm!(VandpsZmmZmmMem, engine_forms::VANDPS_ZMM_ZMM_MEM, And, I32X16, 0x1621);
andn_zmm!(VandnpsZmmZmmZmm, engine_forms::VANDNPS_ZMM_ZMM_ZMM, I32X16, 0x1622);
andn_zmm!(VandnpsZmmZmmMem, engine_forms::VANDNPS_ZMM_ZMM_MEM, I32X16, 0x1623);
logic_zmm!(VorpsZmmZmmZmm, engine_forms::VORPS_ZMM_ZMM_ZMM, Or, I32X16, 0x1624);
logic_zmm!(VorpsZmmZmmMem, engine_forms::VORPS_ZMM_ZMM_MEM, Or, I32X16, 0x1625);
logic_zmm!(VxorpsZmmZmmZmm, engine_forms::VXORPS_ZMM_ZMM_ZMM, Xor, I32X16, 0x1626);
logic_zmm!(VxorpsZmmZmmMem, engine_forms::VXORPS_ZMM_ZMM_MEM, Xor, I32X16, 0x1627);

logic_zmm!(VandpdZmmZmmZmm, engine_forms::VANDPD_ZMM_ZMM_ZMM, And, I64X8, 0x1628);
logic_zmm!(VandpdZmmZmmMem, engine_forms::VANDPD_ZMM_ZMM_MEM, And, I64X8, 0x1629);
andn_zmm!(VandnpdZmmZmmZmm, engine_forms::VANDNPD_ZMM_ZMM_ZMM, I64X8, 0x162A);
andn_zmm!(VandnpdZmmZmmMem, engine_forms::VANDNPD_ZMM_ZMM_MEM, I64X8, 0x162B);
logic_zmm!(VorpdZmmZmmZmm, engine_forms::VORPD_ZMM_ZMM_ZMM, Or, I64X8, 0x162C);
logic_zmm!(VorpdZmmZmmMem, engine_forms::VORPD_ZMM_ZMM_MEM, Or, I64X8, 0x162D);
logic_zmm!(VxorpdZmmZmmZmm, engine_forms::VXORPD_ZMM_ZMM_ZMM, Xor, I64X8, 0x162E);
logic_zmm!(VxorpdZmmZmmMem, engine_forms::VXORPD_ZMM_ZMM_MEM, Xor, I64X8, 0x162F);

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

// ---------------------------------------------------------------------------
// VNNI dot-product accumulate providers (VPDPBUSD(S) / VPDPWSSD(S))
// ---------------------------------------------------------------------------
//
// VNNI form: dst += Σ src1[*] * src2[*] grouped by i32 lane.
// The dot is emitted as a dedicated vector op (DotU8S8 / Madd16), the
// accumulate as LaneWise(Add) or SatAddS for the saturating variants.

// The lane-wise evaluator handles at most 128-bit vectors, so VNNI ops
// decompose into 128-bit slices the same way the packed-float providers do.
macro_rules! vnni_dot {
    ($name:ident, $form:expr, $dot_op:expr, $acc_op:expr, $out_ty:expr, $mid_ty:expr, $src_ty:expr, $sl_out_ty:expr, $sl_src_ty:expr, $slices:expr, $rule:expr) => {
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
                let dst = out.read_operand(0, $out_ty)?;
                let (src1_idx, src2_idx) = evex_source_indices(insn);
                let a = out.read_operand(src1_idx, $src_ty)?;
                let b = out.read_operand(src2_idx, $src_ty)?;
                let mut acc_slices: Vec<ValueId> = Vec::with_capacity($slices);
                for i in 0..$slices {
                    let off = const_u64(out, (i as u64) * 128)?;
                    let dst_i = out.emit(
                        SemanticOp::Primitive(PrimitiveOp::Extract),
                        $sl_out_ty,
                        &[dst, off],
                    )?;
                    let a_i = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), $sl_src_ty, &[a, off])?;
                    let b_i = out.emit(SemanticOp::Primitive(PrimitiveOp::Extract), $sl_src_ty, &[b, off])?;
                    let dot_i = out.emit(SemanticOp::Vector($dot_op), $sl_out_ty, &[a_i, b_i])?;
                    acc_slices.push(out.emit(SemanticOp::Vector($acc_op), $sl_out_ty, &[dst_i, dot_i])?);
                }
                let result = if acc_slices.len() == 1 {
                    acc_slices[0]
                } else if acc_slices.len() == 2 {
                    out.emit(
                        SemanticOp::Primitive(PrimitiveOp::Concat),
                        $out_ty,
                        &[acc_slices[0], acc_slices[1]],
                    )?
                } else {
                    let lo = out.emit(
                        SemanticOp::Primitive(PrimitiveOp::Concat),
                        $mid_ty,
                        &[acc_slices[0], acc_slices[1]],
                    )?;
                    let hi = out.emit(
                        SemanticOp::Primitive(PrimitiveOp::Concat),
                        $mid_ty,
                        &[acc_slices[2], acc_slices[3]],
                    )?;
                    out.emit(SemanticOp::Primitive(PrimitiveOp::Concat), $out_ty, &[lo, hi])?
                };
                let final_res = apply_evex_mask(insn, out, $out_ty, Some(dst), result)?;
                out.write_operand(0, final_res)?;
                fall_through(out, insn)?;
                Ok(receipt($rule, context))
            }
        }
    };
}

// VPDPBUSD: u8×i8 dot, non-saturating accumulate
vnni_dot!(
    VpdpbusdXmmXmmXmm,
    forms::VPDPBUSD_XMM_XMM_XMM,
    VectorOp::DotU8S8,
    VectorOp::LaneWise(PrimitiveOp::Add),
    I32X4,
    I32X4,
    I8X16,
    I32X4,
    I8X16,
    1,
    0x1640
);
vnni_dot!(
    VpdpbusdXmmXmmMem128,
    forms::VPDPBUSD_XMM_XMM_MEM128,
    VectorOp::DotU8S8,
    VectorOp::LaneWise(PrimitiveOp::Add),
    I32X4,
    I32X4,
    I8X16,
    I32X4,
    I8X16,
    1,
    0x1641
);
vnni_dot!(
    VpdpbusdYmmYmmYmm,
    forms::VPDPBUSD_YMM_YMM_YMM,
    VectorOp::DotU8S8,
    VectorOp::LaneWise(PrimitiveOp::Add),
    I32X8,
    I32X8,
    I8X32,
    I32X4,
    I8X16,
    2,
    0x1642
);
vnni_dot!(
    VpdpbusdYmmYmmMem,
    forms::VPDPBUSD_YMM_YMM_MEM,
    VectorOp::DotU8S8,
    VectorOp::LaneWise(PrimitiveOp::Add),
    I32X8,
    I32X8,
    I8X32,
    I32X4,
    I8X16,
    2,
    0x1643
);
vnni_dot!(
    VpdpbusdZmmZmmZmm,
    forms::VPDPBUSD_ZMM_ZMM_ZMM,
    VectorOp::DotU8S8,
    VectorOp::LaneWise(PrimitiveOp::Add),
    I32X16,
    I32X8,
    I8X64,
    I32X4,
    I8X16,
    4,
    0x1644
);
vnni_dot!(
    VpdpbusdZmmZmmMem,
    forms::VPDPBUSD_ZMM_ZMM_MEM,
    VectorOp::DotU8S8,
    VectorOp::LaneWise(PrimitiveOp::Add),
    I32X16,
    I32X8,
    I8X64,
    I32X4,
    I8X16,
    4,
    0x1645
);
// VPDPBUSDS: u8×i8 dot, signed-saturating accumulate
vnni_dot!(
    VpdpbusdsXmmXmmXmm,
    forms::VPDPBUSDS_XMM_XMM_XMM,
    VectorOp::DotU8S8,
    VectorOp::SatAddS,
    I32X4,
    I32X4,
    I8X16,
    I32X4,
    I8X16,
    1,
    0x1646
);
vnni_dot!(
    VpdpbusdsXmmXmmMem128,
    forms::VPDPBUSDS_XMM_XMM_MEM128,
    VectorOp::DotU8S8,
    VectorOp::SatAddS,
    I32X4,
    I32X4,
    I8X16,
    I32X4,
    I8X16,
    1,
    0x1647
);
vnni_dot!(
    VpdpbusdsYmmYmmYmm,
    forms::VPDPBUSDS_YMM_YMM_YMM,
    VectorOp::DotU8S8,
    VectorOp::SatAddS,
    I32X8,
    I32X8,
    I8X32,
    I32X4,
    I8X16,
    2,
    0x1648
);
vnni_dot!(
    VpdpbusdsYmmYmmMem,
    forms::VPDPBUSDS_YMM_YMM_MEM,
    VectorOp::DotU8S8,
    VectorOp::SatAddS,
    I32X8,
    I32X8,
    I8X32,
    I32X4,
    I8X16,
    2,
    0x1649
);
vnni_dot!(
    VpdpbusdsZmmZmmZmm,
    forms::VPDPBUSDS_ZMM_ZMM_ZMM,
    VectorOp::DotU8S8,
    VectorOp::SatAddS,
    I32X16,
    I32X8,
    I8X64,
    I32X4,
    I8X16,
    4,
    0x164A
);
vnni_dot!(
    VpdpbusdsZmmZmmMem,
    forms::VPDPBUSDS_ZMM_ZMM_MEM,
    VectorOp::DotU8S8,
    VectorOp::SatAddS,
    I32X16,
    I32X8,
    I8X64,
    I32X4,
    I8X16,
    4,
    0x164B
);
// VPDPWSSD: i16 madd, non-saturating accumulate
vnni_dot!(
    VpdpwssdXmmXmmXmm,
    forms::VPDPWSSD_XMM_XMM_XMM,
    VectorOp::Madd16,
    VectorOp::LaneWise(PrimitiveOp::Add),
    I32X4,
    I32X4,
    I16X8,
    I32X4,
    I16X8,
    1,
    0x164C
);
vnni_dot!(
    VpdpwssdXmmXmmMem128,
    forms::VPDPWSSD_XMM_XMM_MEM128,
    VectorOp::Madd16,
    VectorOp::LaneWise(PrimitiveOp::Add),
    I32X4,
    I32X4,
    I16X8,
    I32X4,
    I16X8,
    1,
    0x164D
);
vnni_dot!(
    VpdpwssdYmmYmmYmm,
    forms::VPDPWSSD_YMM_YMM_YMM,
    VectorOp::Madd16,
    VectorOp::LaneWise(PrimitiveOp::Add),
    I32X8,
    I32X8,
    I16X16,
    I32X4,
    I16X8,
    2,
    0x164E
);
vnni_dot!(
    VpdpwssdYmmYmmMem,
    forms::VPDPWSSD_YMM_YMM_MEM,
    VectorOp::Madd16,
    VectorOp::LaneWise(PrimitiveOp::Add),
    I32X8,
    I32X8,
    I16X16,
    I32X4,
    I16X8,
    2,
    0x164F
);
vnni_dot!(
    VpdpwssdZmmZmmZmm,
    forms::VPDPWSSD_ZMM_ZMM_ZMM,
    VectorOp::Madd16,
    VectorOp::LaneWise(PrimitiveOp::Add),
    I32X16,
    I32X8,
    I16X32,
    I32X4,
    I16X8,
    4,
    0x1650
);
vnni_dot!(
    VpdpwssdZmmZmmMem,
    forms::VPDPWSSD_ZMM_ZMM_MEM,
    VectorOp::Madd16,
    VectorOp::LaneWise(PrimitiveOp::Add),
    I32X16,
    I32X8,
    I16X32,
    I32X4,
    I16X8,
    4,
    0x1651
);
// VPDPWSSDS: i16 madd, signed-saturating accumulate
vnni_dot!(
    VpdpwssdsXmmXmmXmm,
    forms::VPDPWSSDS_XMM_XMM_XMM,
    VectorOp::Madd16,
    VectorOp::SatAddS,
    I32X4,
    I32X4,
    I16X8,
    I32X4,
    I16X8,
    1,
    0x1652
);
vnni_dot!(
    VpdpwssdsXmmXmmMem128,
    forms::VPDPWSSDS_XMM_XMM_MEM128,
    VectorOp::Madd16,
    VectorOp::SatAddS,
    I32X4,
    I32X4,
    I16X8,
    I32X4,
    I16X8,
    1,
    0x1653
);
vnni_dot!(
    VpdpwssdsYmmYmmYmm,
    forms::VPDPWSSDS_YMM_YMM_YMM,
    VectorOp::Madd16,
    VectorOp::SatAddS,
    I32X8,
    I32X8,
    I16X16,
    I32X4,
    I16X8,
    2,
    0x1654
);
vnni_dot!(
    VpdpwssdsYmmYmmMem,
    forms::VPDPWSSDS_YMM_YMM_MEM,
    VectorOp::Madd16,
    VectorOp::SatAddS,
    I32X8,
    I32X8,
    I16X16,
    I32X4,
    I16X8,
    2,
    0x1655
);
vnni_dot!(
    VpdpwssdsZmmZmmZmm,
    forms::VPDPWSSDS_ZMM_ZMM_ZMM,
    VectorOp::Madd16,
    VectorOp::SatAddS,
    I32X16,
    I32X8,
    I16X32,
    I32X4,
    I16X8,
    4,
    0x1656
);
vnni_dot!(
    VpdpwssdsZmmZmmMem,
    forms::VPDPWSSDS_ZMM_ZMM_MEM,
    VectorOp::Madd16,
    VectorOp::SatAddS,
    I32X16,
    I32X8,
    I16X32,
    I32X4,
    I16X8,
    4,
    0x1657
);

// VPDPBSSD: s8×s8 dot, non-saturating accumulate
vnni_dot!(
    VpdpbssdXmmXmmXmm,
    forms::VPDPBSSD_XMM_XMM_XMM,
    VectorOp::DotS8S8,
    VectorOp::LaneWise(PrimitiveOp::Add),
    I32X4,
    I32X4,
    I8X16,
    I32X4,
    I8X16,
    1,
    0x1658
);
vnni_dot!(
    VpdpbssdXmmXmmMem128,
    forms::VPDPBSSD_XMM_XMM_MEM128,
    VectorOp::DotS8S8,
    VectorOp::LaneWise(PrimitiveOp::Add),
    I32X4,
    I32X4,
    I8X16,
    I32X4,
    I8X16,
    1,
    0x1659
);
vnni_dot!(
    VpdpbssdYmmYmmYmm,
    forms::VPDPBSSD_YMM_YMM_YMM,
    VectorOp::DotS8S8,
    VectorOp::LaneWise(PrimitiveOp::Add),
    I32X8,
    I32X8,
    I8X32,
    I32X4,
    I8X16,
    2,
    0x165A
);
vnni_dot!(
    VpdpbssdYmmYmmMem,
    forms::VPDPBSSD_YMM_YMM_MEM,
    VectorOp::DotS8S8,
    VectorOp::LaneWise(PrimitiveOp::Add),
    I32X8,
    I32X8,
    I8X32,
    I32X4,
    I8X16,
    2,
    0x165B
);
vnni_dot!(
    VpdpbssdZmmZmmZmm,
    forms::VPDPBSSD_ZMM_ZMM_ZMM,
    VectorOp::DotS8S8,
    VectorOp::LaneWise(PrimitiveOp::Add),
    I32X16,
    I32X8,
    I8X64,
    I32X4,
    I8X16,
    4,
    0x165C
);
vnni_dot!(
    VpdpbssdZmmZmmMem,
    forms::VPDPBSSD_ZMM_ZMM_MEM,
    VectorOp::DotS8S8,
    VectorOp::LaneWise(PrimitiveOp::Add),
    I32X16,
    I32X8,
    I8X64,
    I32X4,
    I8X16,
    4,
    0x165D
);

// VPDPBSSDS: s8×s8 dot, signed saturating accumulate
vnni_dot!(
    VpdpbssdsXmmXmmXmm,
    forms::VPDPBSSDS_XMM_XMM_XMM,
    VectorOp::DotS8S8,
    VectorOp::SatAddS,
    I32X4,
    I32X4,
    I8X16,
    I32X4,
    I8X16,
    1,
    0x165E
);
vnni_dot!(
    VpdpbssdsXmmXmmMem128,
    forms::VPDPBSSDS_XMM_XMM_MEM128,
    VectorOp::DotS8S8,
    VectorOp::SatAddS,
    I32X4,
    I32X4,
    I8X16,
    I32X4,
    I8X16,
    1,
    0x165F
);
vnni_dot!(
    VpdpbssdsYmmYmmYmm,
    forms::VPDPBSSDS_YMM_YMM_YMM,
    VectorOp::DotS8S8,
    VectorOp::SatAddS,
    I32X8,
    I32X8,
    I8X32,
    I32X4,
    I8X16,
    2,
    0x1660
);
vnni_dot!(
    VpdpbssdsYmmYmmMem,
    forms::VPDPBSSDS_YMM_YMM_MEM,
    VectorOp::DotS8S8,
    VectorOp::SatAddS,
    I32X8,
    I32X8,
    I8X32,
    I32X4,
    I8X16,
    2,
    0x1661
);
vnni_dot!(
    VpdpbssdsZmmZmmZmm,
    forms::VPDPBSSDS_ZMM_ZMM_ZMM,
    VectorOp::DotS8S8,
    VectorOp::SatAddS,
    I32X16,
    I32X8,
    I8X64,
    I32X4,
    I8X16,
    4,
    0x1662
);
vnni_dot!(
    VpdpbssdsZmmZmmMem,
    forms::VPDPBSSDS_ZMM_ZMM_MEM,
    VectorOp::DotS8S8,
    VectorOp::SatAddS,
    I32X16,
    I32X8,
    I8X64,
    I32X4,
    I8X16,
    4,
    0x1663
);

// VPDPBSUD: s8×u8 dot, non-saturating accumulate
vnni_dot!(
    VpdpbsudXmmXmmXmm,
    forms::VPDPBSUD_XMM_XMM_XMM,
    VectorOp::DotS8U8,
    VectorOp::LaneWise(PrimitiveOp::Add),
    I32X4,
    I32X4,
    I8X16,
    I32X4,
    I8X16,
    1,
    0x1664
);
vnni_dot!(
    VpdpbsudXmmXmmMem128,
    forms::VPDPBSUD_XMM_XMM_MEM128,
    VectorOp::DotS8U8,
    VectorOp::LaneWise(PrimitiveOp::Add),
    I32X4,
    I32X4,
    I8X16,
    I32X4,
    I8X16,
    1,
    0x1665
);
vnni_dot!(
    VpdpbsudYmmYmmYmm,
    forms::VPDPBSUD_YMM_YMM_YMM,
    VectorOp::DotS8U8,
    VectorOp::LaneWise(PrimitiveOp::Add),
    I32X8,
    I32X8,
    I8X32,
    I32X4,
    I8X16,
    2,
    0x1666
);
vnni_dot!(
    VpdpbsudYmmYmmMem,
    forms::VPDPBSUD_YMM_YMM_MEM,
    VectorOp::DotS8U8,
    VectorOp::LaneWise(PrimitiveOp::Add),
    I32X8,
    I32X8,
    I8X32,
    I32X4,
    I8X16,
    2,
    0x1667
);
vnni_dot!(
    VpdpbsudZmmZmmZmm,
    forms::VPDPBSUD_ZMM_ZMM_ZMM,
    VectorOp::DotS8U8,
    VectorOp::LaneWise(PrimitiveOp::Add),
    I32X16,
    I32X8,
    I8X64,
    I32X4,
    I8X16,
    4,
    0x1668
);
vnni_dot!(
    VpdpbsudZmmZmmMem,
    forms::VPDPBSUD_ZMM_ZMM_MEM,
    VectorOp::DotS8U8,
    VectorOp::LaneWise(PrimitiveOp::Add),
    I32X16,
    I32X8,
    I8X64,
    I32X4,
    I8X16,
    4,
    0x1669
);

// VPDPBSUDS: s8×u8 dot, signed saturating accumulate
vnni_dot!(
    VpdpbsudsXmmXmmXmm,
    forms::VPDPBSUDS_XMM_XMM_XMM,
    VectorOp::DotS8U8,
    VectorOp::SatAddS,
    I32X4,
    I32X4,
    I8X16,
    I32X4,
    I8X16,
    1,
    0x166A
);
vnni_dot!(
    VpdpbsudsXmmXmmMem128,
    forms::VPDPBSUDS_XMM_XMM_MEM128,
    VectorOp::DotS8U8,
    VectorOp::SatAddS,
    I32X4,
    I32X4,
    I8X16,
    I32X4,
    I8X16,
    1,
    0x166B
);
vnni_dot!(
    VpdpbsudsYmmYmmYmm,
    forms::VPDPBSUDS_YMM_YMM_YMM,
    VectorOp::DotS8U8,
    VectorOp::SatAddS,
    I32X8,
    I32X8,
    I8X32,
    I32X4,
    I8X16,
    2,
    0x166C
);
vnni_dot!(
    VpdpbsudsYmmYmmMem,
    forms::VPDPBSUDS_YMM_YMM_MEM,
    VectorOp::DotS8U8,
    VectorOp::SatAddS,
    I32X8,
    I32X8,
    I8X32,
    I32X4,
    I8X16,
    2,
    0x166D
);
vnni_dot!(
    VpdpbsudsZmmZmmZmm,
    forms::VPDPBSUDS_ZMM_ZMM_ZMM,
    VectorOp::DotS8U8,
    VectorOp::SatAddS,
    I32X16,
    I32X8,
    I8X64,
    I32X4,
    I8X16,
    4,
    0x166E
);
vnni_dot!(
    VpdpbsudsZmmZmmMem,
    forms::VPDPBSUDS_ZMM_ZMM_MEM,
    VectorOp::DotS8U8,
    VectorOp::SatAddS,
    I32X16,
    I32X8,
    I8X64,
    I32X4,
    I8X16,
    4,
    0x166F
);

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
        // VNNI dot-product accumulate (24)
        Arc::new(VpdpbusdXmmXmmXmm),
        Arc::new(VpdpbusdXmmXmmMem128),
        Arc::new(VpdpbusdYmmYmmYmm),
        Arc::new(VpdpbusdYmmYmmMem),
        Arc::new(VpdpbusdZmmZmmZmm),
        Arc::new(VpdpbusdZmmZmmMem),
        Arc::new(VpdpbusdsXmmXmmXmm),
        Arc::new(VpdpbusdsXmmXmmMem128),
        Arc::new(VpdpbusdsYmmYmmYmm),
        Arc::new(VpdpbusdsYmmYmmMem),
        Arc::new(VpdpbusdsZmmZmmZmm),
        Arc::new(VpdpbusdsZmmZmmMem),
        Arc::new(VpdpwssdXmmXmmXmm),
        Arc::new(VpdpwssdXmmXmmMem128),
        Arc::new(VpdpwssdYmmYmmYmm),
        Arc::new(VpdpwssdYmmYmmMem),
        Arc::new(VpdpwssdZmmZmmZmm),
        Arc::new(VpdpwssdZmmZmmMem),
        Arc::new(VpdpwssdsXmmXmmXmm),
        Arc::new(VpdpwssdsXmmXmmMem128),
        Arc::new(VpdpwssdsYmmYmmYmm),
        Arc::new(VpdpwssdsYmmYmmMem),
        Arc::new(VpdpwssdsZmmZmmZmm),
        Arc::new(VpdpwssdsZmmZmmMem),
        // VNNI-INT8 dot-product accumulate (24)
        Arc::new(VpdpbssdXmmXmmXmm),
        Arc::new(VpdpbssdXmmXmmMem128),
        Arc::new(VpdpbssdYmmYmmYmm),
        Arc::new(VpdpbssdYmmYmmMem),
        Arc::new(VpdpbssdZmmZmmZmm),
        Arc::new(VpdpbssdZmmZmmMem),
        Arc::new(VpdpbssdsXmmXmmXmm),
        Arc::new(VpdpbssdsXmmXmmMem128),
        Arc::new(VpdpbssdsYmmYmmYmm),
        Arc::new(VpdpbssdsYmmYmmMem),
        Arc::new(VpdpbssdsZmmZmmZmm),
        Arc::new(VpdpbssdsZmmZmmMem),
        Arc::new(VpdpbsudXmmXmmXmm),
        Arc::new(VpdpbsudXmmXmmMem128),
        Arc::new(VpdpbsudYmmYmmYmm),
        Arc::new(VpdpbsudYmmYmmMem),
        Arc::new(VpdpbsudZmmZmmZmm),
        Arc::new(VpdpbsudZmmZmmMem),
        Arc::new(VpdpbsudsXmmXmmXmm),
        Arc::new(VpdpbsudsXmmXmmMem128),
        Arc::new(VpdpbsudsYmmYmmYmm),
        Arc::new(VpdpbsudsYmmYmmMem),
        Arc::new(VpdpbsudsZmmZmmZmm),
        Arc::new(VpdpbsudsZmmZmmMem),
        // Packed single-precision arithmetic, EVEX 128/256-bit forms (16)
        Arc::new(VaddpsEvexXmmXmmXmm),
        Arc::new(VaddpsEvexXmmXmmMem128),
        Arc::new(VsubpsEvexXmmXmmXmm),
        Arc::new(VsubpsEvexXmmXmmMem128),
        Arc::new(VmulpsEvexXmmXmmXmm),
        Arc::new(VmulpsEvexXmmXmmMem128),
        Arc::new(VdivpsEvexXmmXmmXmm),
        Arc::new(VdivpsEvexXmmXmmMem128),
        Arc::new(VaddpsEvexYmmYmmYmm),
        Arc::new(VaddpsEvexYmmYmmMem),
        Arc::new(VsubpsEvexYmmYmmYmm),
        Arc::new(VsubpsEvexYmmYmmMem),
        Arc::new(VmulpsEvexYmmYmmYmm),
        Arc::new(VmulpsEvexYmmYmmMem),
        Arc::new(VdivpsEvexYmmYmmYmm),
        Arc::new(VdivpsEvexYmmYmmMem),
        // Packed double-precision arithmetic, EVEX 128/256-bit forms (16)
        Arc::new(VaddpdEvexXmmXmmXmm),
        Arc::new(VaddpdEvexXmmXmmMem128),
        Arc::new(VsubpdEvexXmmXmmXmm),
        Arc::new(VsubpdEvexXmmXmmMem128),
        Arc::new(VmulpdEvexXmmXmmXmm),
        Arc::new(VmulpdEvexXmmXmmMem128),
        Arc::new(VdivpdEvexXmmXmmXmm),
        Arc::new(VdivpdEvexXmmXmmMem128),
        Arc::new(VaddpdEvexYmmYmmYmm),
        Arc::new(VaddpdEvexYmmYmmMem),
        Arc::new(VsubpdEvexYmmYmmYmm),
        Arc::new(VsubpdEvexYmmYmmMem),
        Arc::new(VmulpdEvexYmmYmmYmm),
        Arc::new(VmulpdEvexYmmYmmMem),
        Arc::new(VdivpdEvexYmmYmmYmm),
        Arc::new(VdivpdEvexYmmYmmMem),
    ]
}

/// Alias matching module-specific naming pattern.
pub fn avx512_providers() -> Vec<Arc<dyn SemanticProvider>> {
    providers()
}
