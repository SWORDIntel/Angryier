//! Declarative semantic patterns — the machine-readable schema the semantic
//! generator compiles into providers. Each pattern enumerates the operand
//! reads, primitive ops, flag policy, and writes for a whole instruction
//! family shape; the architecture crate (`angryier-semantics-intel64`)
//! interprets the pattern into `SemanticOp`s at emit time, so generated
//! providers flow through the same lowering, concrete/symbolic execution,
//! and differential-oracle pipeline as handwritten ones.

use angryier_semantics::PrimitiveOp;
/// How a generated ALU form updates RFLAGS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlagPolicy {
    /// No flag writes (moves, packed SIMD, rotates are separate).
    None,
    /// Full arithmetic flag set at operand width (add/sub/inc/dec family).
    Arithmetic,
    /// Logical flag set: ZF/SF/PF from the result, CF/OF cleared.
    Logical,
    /// Arithmetic flags except CF is preserved (INC/DEC).
    PreserveCf,
}

/// A declarative instruction pattern. All operand positions refer to the
/// XED-visible explicit operand order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SemanticPattern {
    /// `dst = dst <op> src` on two explicit register/memory operands of the
    /// given width, with the named flag policy.
    BinaryAlu {
        /// The primitive operation.
        op: PrimitiveOp,
        /// Operand width in bits.
        width_bits: u16,
        /// Flag update policy.
        flags: FlagPolicy,
    },
    /// Lane-wise packed operation over the whole operand (SSE/AVX integer and
    /// float families): `dst[i] = dst[i] <op> src[i]` per lane.
    PackedLane {
        /// The lane-wise primitive (Add/Sub/Mul/And/Or/Xor or float).
        op: PrimitiveOp,
        /// Lane count.
        lanes: u16,
        /// Lane width in bits.
        lane_bits: u16,
    },
    /// `dst = extend(src)` — MOVSX/MOVZX shape.
    Extend {
        /// Source operand width in bits.
        src_bits: u16,
        /// Destination operand width in bits.
        dst_bits: u16,
        /// Sign-extend when true, zero-extend when false.
        signed: bool,
    },
    /// `dst = ~dst` (NOT) or `dst = 0 - dst` (NEG) on a single operand.
    UnaryAlu {
        /// Not (bitwise) or Neg (negate with sub flags).
        negate: bool,
        /// Operand width in bits.
        width_bits: u16,
    },
    /// `dst = dst <<|>>|>>>|<<< count` — shifts/rotates by imm8.
    Shift {
        /// Left, right-logical, right-arithmetic, rotate-left, rotate-right.
        kind: ShiftPattern,
        /// Operand width in bits.
        width_bits: u16,
    },
}

/// Shift/rotate flavor for [`SemanticPattern::Shift`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShiftPattern {
    /// `shl`
    Left,
    /// `shr`
    RightLogical,
    /// `sar`
    RightArithmetic,
    /// `rol`
    RotateLeft,
    /// `ror`
    RotateRight,
}

impl SemanticPattern {
    /// Canonical byte encoding — stable across compilation runs so the
    /// generated rule's `ContentId` is deterministic.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(16);
        match self {
            Self::BinaryAlu { op, width_bits, flags } => {
                bytes.push(1);
                bytes.push(prim_tag(*op));
                bytes.extend_from_slice(&width_bits.to_le_bytes());
                bytes.push(flag_tag(*flags));
            }
            Self::PackedLane { op, lanes, lane_bits } => {
                bytes.push(2);
                bytes.push(prim_tag(*op));
                bytes.extend_from_slice(&lanes.to_le_bytes());
                bytes.extend_from_slice(&lane_bits.to_le_bytes());
            }
            Self::Extend {
                src_bits,
                dst_bits,
                signed,
            } => {
                bytes.push(3);
                bytes.extend_from_slice(&src_bits.to_le_bytes());
                bytes.extend_from_slice(&dst_bits.to_le_bytes());
                bytes.push(u8::from(*signed));
            }
            Self::UnaryAlu { negate, width_bits } => {
                bytes.push(4);
                bytes.push(u8::from(*negate));
                bytes.extend_from_slice(&width_bits.to_le_bytes());
            }
            Self::Shift { kind, width_bits } => {
                bytes.push(5);
                bytes.push(shift_tag(*kind));
                bytes.extend_from_slice(&width_bits.to_le_bytes());
            }
        }
        bytes
    }
}

fn prim_tag(op: PrimitiveOp) -> u8 {
    match op {
        PrimitiveOp::Add => 1,
        PrimitiveOp::Sub => 2,
        PrimitiveOp::Mul => 3,
        PrimitiveOp::And => 4,
        PrimitiveOp::Or => 5,
        PrimitiveOp::Xor => 6,
        PrimitiveOp::Not => 7,
        PrimitiveOp::ShiftLeft => 8,
        PrimitiveOp::LogicalShiftRight => 9,
        PrimitiveOp::ArithmeticShiftRight => 10,
        _ => 0,
    }
}

fn flag_tag(policy: FlagPolicy) -> u8 {
    match policy {
        FlagPolicy::None => 0,
        FlagPolicy::Arithmetic => 1,
        FlagPolicy::Logical => 2,
        FlagPolicy::PreserveCf => 3,
    }
}

fn shift_tag(kind: ShiftPattern) -> u8 {
    match kind {
        ShiftPattern::Left => 0,
        ShiftPattern::RightLogical => 1,
        ShiftPattern::RightArithmetic => 2,
        ShiftPattern::RotateLeft => 3,
        ShiftPattern::RotateRight => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_bytes_are_deterministic() {
        let a = SemanticPattern::PackedLane {
            op: PrimitiveOp::Add,
            lanes: 8,
            lane_bits: 16,
        };
        let b = SemanticPattern::PackedLane {
            op: PrimitiveOp::Add,
            lanes: 8,
            lane_bits: 16,
        };
        assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    }

    #[test]
    fn canonical_bytes_distinguish_patterns() {
        let add = SemanticPattern::BinaryAlu {
            op: PrimitiveOp::Add,
            width_bits: 64,
            flags: FlagPolicy::Arithmetic,
        };
        let sub = SemanticPattern::BinaryAlu {
            op: PrimitiveOp::Sub,
            width_bits: 64,
            flags: FlagPolicy::Arithmetic,
        };
        assert_ne!(add.canonical_bytes(), sub.canonical_bytes());
    }
}
