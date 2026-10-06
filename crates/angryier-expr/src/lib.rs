#![forbid(unsafe_code)]

use angryier_types::fx::FxHashMap;
use angryier_types::{DependencyKey, ExprId, ExpressionNormalizationVersion};
use std::sync::{
    RwLock,
    atomic::{AtomicU64, Ordering},
};

const SHARD_BITS: u32 = 6;
const SHARD_COUNT: usize = 1 << SHARD_BITS;
const LOCAL_BITS: u32 = u32::BITS - SHARD_BITS;
const LOCAL_MASK: u32 = (1 << LOCAL_BITS) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExprSort {
    BitVec(u16),
    Float {
        exponent_bits: u8,
        significand_bits: u8,
    },
    Bool,
    Vector {
        lanes: u16,
        lane_bits: u16,
    },
    Opmask(u16),
    Tile {
        rows: u8,
        bytes_per_row: u16,
        element_bits: u16,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExprOp {
    Constant,
    Symbol,
    Add,
    Sub,
    Mul,
    UDiv,
    SDiv,
    And,
    Or,
    Xor,
    Not,
    Shl,
    LShr,
    AShr,
    Eq,
    Ult,
    Ule,
    Slt,
    Sle,
    Ite,
    Concat,
    Extract,
    ZExt,
    SExt,
    /// Rotate left by the count operand modulo the node's width. Operands are
    /// `[value, count]`; the value must share the node's bitvector sort and
    /// the count is any bitvector (the count mod width semantics matches
    /// SMT-LIB `rotate_left` with a same-width count and x86's rotate-count
    /// masking).
    RotL,
    /// Rotate right by the count operand modulo the node's width — the
    /// mirror of [`ExprOp::RotL`].
    RotR,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ExprNode {
    pub sort: ExprSort,
    pub op: ExprOp,
    pub operands: Vec<ExprId>,
    pub immediate: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DependencySummary {
    pub key: DependencyKey,
    pub symbolic_sources: Vec<u64>,
}

pub trait ExprArena: Send + Sync {
    type Error;

    fn intern(&self, node: ExprNode) -> Result<ExprId, Self::Error>;
    fn get(&self, id: ExprId) -> Option<ExprNode>;
    fn dependency_summary(&self, id: ExprId) -> Option<DependencySummary>;
    fn normalization_version(&self) -> ExpressionNormalizationVersion;

    /// Cheap sort probe: returns a copy of just the node's sort instead of a
    /// full [`ExprNode`] clone. The default falls back to [`get`](Self::get);
    /// concrete arenas override it with a lock-and-copy of the small enum.
    fn sort_of(&self, id: ExprId) -> Option<ExprSort> {
        self.get(id).map(|node| node.sort)
    }

    /// Cheap op probe: returns a copy of just the node's operator instead of a
    /// full [`ExprNode`] clone. The default falls back to [`get`](Self::get).
    fn op_of(&self, id: ExprId) -> Option<ExprOp> {
        self.get(id).map(|node| node.op)
    }
}

/// Object-safe trait for reading expression nodes by ID.
/// Used by native solver FFI bridges to translate expression trees to solver ASTs.
pub trait ExprReader: Send + Sync {
    fn read(&self, id: ExprId) -> Option<ExprNode>;
}

pub trait HotCanonicalizer: Send + Sync {
    fn canonicalize(&self, node: ExprNode) -> ExprNode;
}

pub trait DeepCanonicalizer: Send + Sync {
    type Error;
    fn canonicalize_equivalence_class(&self, root: ExprId) -> Result<DependencyKey, Self::Error>;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExprArenaStats {
    pub intern_requests: u64,
    pub intern_hits: u64,
    pub nodes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExprArenaError {
    InvalidSort,
    InvalidArity { op: ExprOp, expected: usize, actual: usize },
    InvalidImmediate,
    UnknownOperand(ExprId),
    SortMismatch(ExprOp),
    CapacityExceeded,
    LockPoisoned,
}

impl core::fmt::Display for ExprArenaError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidSort => formatter.write_str("expression has an invalid sort"),
            Self::InvalidArity { op, expected, actual } => {
                write!(formatter, "{op:?} expects {expected} operands, received {actual}")
            }
            Self::InvalidImmediate => formatter.write_str("expression has invalid immediate data"),
            Self::UnknownOperand(id) => write!(formatter, "expression references unknown operand {}", id.0),
            Self::SortMismatch(op) => write!(formatter, "{op:?} operand/result sorts are incompatible"),
            Self::CapacityExceeded => formatter.write_str("expression shard capacity exceeded"),
            Self::LockPoisoned => formatter.write_str("expression arena lock was poisoned"),
        }
    }
}

impl std::error::Error for ExprArenaError {}

#[derive(Clone, Copy, Debug, Default)]
pub struct BasicHotCanonicalizer;

impl HotCanonicalizer for BasicHotCanonicalizer {
    fn canonicalize(&self, mut node: ExprNode) -> ExprNode {
        if is_commutative(node.op) {
            node.operands.sort_by_key(|operand| operand.0);
        }
        node
    }
}

#[derive(Clone, Debug)]
struct ExprRecord {
    node: ExprNode,
    dependency: DependencySummary,
}

#[derive(Default)]
struct ArenaShard {
    by_node: FxHashMap<ExprNode, ExprId>,
    records: Vec<ExprRecord>,
}

pub struct ShardedExprArena {
    version: ExpressionNormalizationVersion,
    prefix: [u8; 22],
    shards: [RwLock<ArenaShard>; SHARD_COUNT],
    requests: AtomicU64,
    hits: AtomicU64,
    nodes: AtomicU64,
}

impl ShardedExprArena {
    pub fn new(version: ExpressionNormalizationVersion) -> Self {
        let mut prefix = [0u8; 22];
        prefix[..14].copy_from_slice(b"ANGRYIER\0EXPR\0");
        prefix[14..22].copy_from_slice(&version.0.to_le_bytes());
        Self {
            version,
            prefix,
            shards: std::array::from_fn(|_| RwLock::new(ArenaShard::default())),
            requests: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            nodes: AtomicU64::new(0),
        }
    }

    pub fn stats(&self) -> ExprArenaStats {
        ExprArenaStats {
            intern_requests: self.requests.load(Ordering::Relaxed),
            intern_hits: self.hits.load(Ordering::Relaxed),
            nodes: self.nodes.load(Ordering::Relaxed),
        }
    }

    fn record(&self, id: ExprId) -> Result<ExprRecord, ExprArenaError> {
        let (shard, local) = decode_id(id);
        let shard = self.shards[shard].read().map_err(|_| ExprArenaError::LockPoisoned)?;
        shard
            .records
            .get(local)
            .cloned()
            .ok_or(ExprArenaError::UnknownOperand(id))
    }

    /// Lightweight operator probe: copies one enum instead of cloning the
    /// whole record (two `Vec`s plus the dependency summary).
    fn op_checked(&self, id: ExprId) -> Result<ExprOp, ExprArenaError> {
        let (shard, local) = decode_id(id);
        let shard = self.shards[shard].read().map_err(|_| ExprArenaError::LockPoisoned)?;
        shard
            .records
            .get(local)
            .map(|record| record.node.op)
            .ok_or(ExprArenaError::UnknownOperand(id))
    }

    fn build_dependency(&self, node: &ExprNode) -> Result<DependencySummary, ExprArenaError> {
        let op_count = node.operands.len();
        if op_count > 3 {
            return Err(ExprArenaError::InvalidArity {
                op: node.op,
                expected: 3,
                actual: op_count,
            });
        }

        let mut child_keys_buf = [DependencyKey([0; 32]); 3];
        let mut child_sorts_buf = [ExprSort::Bool; 3];
        let child_keys = &mut child_keys_buf[..op_count];
        let child_sorts = &mut child_sorts_buf[..op_count];

        let mut child_sources_0 = Vec::new();
        let mut child_sources_1 = Vec::new();
        let mut child_sources_2 = Vec::new();

        match op_count {
            0 => {}
            1 => {
                let (shard_idx, local) = decode_id(node.operands[0]);
                let shard = self.shards[shard_idx]
                    .read()
                    .map_err(|_| ExprArenaError::LockPoisoned)?;
                let record = shard
                    .records
                    .get(local)
                    .ok_or(ExprArenaError::UnknownOperand(node.operands[0]))?;
                child_keys[0] = record.dependency.key;
                child_sorts[0] = record.node.sort;
                child_sources_0 = record.dependency.symbolic_sources.clone();
            }
            2 => {
                let (s0, l0) = decode_id(node.operands[0]);
                let (s1, l1) = decode_id(node.operands[1]);
                if s0 == s1 {
                    let shard = self.shards[s0].read().map_err(|_| ExprArenaError::LockPoisoned)?;
                    let rec0 = shard
                        .records
                        .get(l0)
                        .ok_or(ExprArenaError::UnknownOperand(node.operands[0]))?;
                    child_keys[0] = rec0.dependency.key;
                    child_sorts[0] = rec0.node.sort;
                    child_sources_0 = rec0.dependency.symbolic_sources.clone();

                    let rec1 = shard
                        .records
                        .get(l1)
                        .ok_or(ExprArenaError::UnknownOperand(node.operands[1]))?;
                    child_keys[1] = rec1.dependency.key;
                    child_sorts[1] = rec1.node.sort;
                    child_sources_1 = rec1.dependency.symbolic_sources.clone();
                } else {
                    {
                        let shard0 = self.shards[s0].read().map_err(|_| ExprArenaError::LockPoisoned)?;
                        let rec0 = shard0
                            .records
                            .get(l0)
                            .ok_or(ExprArenaError::UnknownOperand(node.operands[0]))?;
                        child_keys[0] = rec0.dependency.key;
                        child_sorts[0] = rec0.node.sort;
                        child_sources_0 = rec0.dependency.symbolic_sources.clone();
                    }
                    {
                        let shard1 = self.shards[s1].read().map_err(|_| ExprArenaError::LockPoisoned)?;
                        let rec1 = shard1
                            .records
                            .get(l1)
                            .ok_or(ExprArenaError::UnknownOperand(node.operands[1]))?;
                        child_keys[1] = rec1.dependency.key;
                        child_sorts[1] = rec1.node.sort;
                        child_sources_1 = rec1.dependency.symbolic_sources.clone();
                    }
                }
            }
            _ => {
                for (i, &operand) in node.operands.iter().enumerate() {
                    let (shard_idx, local) = decode_id(operand);
                    let shard = self.shards[shard_idx]
                        .read()
                        .map_err(|_| ExprArenaError::LockPoisoned)?;
                    let record = shard
                        .records
                        .get(local)
                        .ok_or(ExprArenaError::UnknownOperand(operand))?;
                    child_keys[i] = record.dependency.key;
                    child_sorts[i] = record.node.sort;
                    match i {
                        0 => child_sources_0 = record.dependency.symbolic_sources.clone(),
                        1 => child_sources_1 = record.dependency.symbolic_sources.clone(),
                        _ => child_sources_2 = record.dependency.symbolic_sources.clone(),
                    }
                }
            }
        }

        validate_sorts(node, child_sorts)?;

        let symbolic_sources = if node.op == ExprOp::Symbol {
            let bytes: [u8; 8] = node
                .immediate
                .as_slice()
                .try_into()
                .map_err(|_| ExprArenaError::InvalidImmediate)?;
            vec![u64::from_le_bytes(bytes)]
        } else {
            match op_count {
                0 => Vec::new(),
                1 => child_sources_0,
                2 => merge_sorted_sources(&child_sources_0, &child_sources_1),
                _ => {
                    let m01 = merge_sorted_sources(&child_sources_0, &child_sources_1);
                    merge_sorted_sources(&m01, &child_sources_2)
                }
            }
        };

        let key = compute_dependency_key(&self.prefix, node.sort, node.op, &node.immediate, child_keys);

        Ok(DependencySummary { key, symbolic_sources })
    }

    fn fold_constants(&self, node: ExprNode) -> Result<ExprNode, ExprArenaError> {
        if node.operands.is_empty() {
            return Ok(node);
        }
        // A node with any non-constant operand cannot fold: probe operators
        // first (one small enum copy each) and only pull full records on the
        // all-constant path.
        for &operand in &node.operands {
            if self.op_checked(operand)? != ExprOp::Constant {
                return Ok(node);
            }
        }
        let records: Vec<_> = node
            .operands
            .iter()
            .copied()
            .map(|operand| self.record(operand))
            .collect::<Result<_, _>>()?;
        let sorts: Vec<_> = records.iter().map(|record| record.node.sort).collect();
        validate_sorts(&node, &sorts)?;

        let folded = match node.op {
            ExprOp::Add | ExprOp::Sub | ExprOp::Mul | ExprOp::And | ExprOp::Or | ExprOp::Xor | ExprOp::Not => {
                let ExprSort::BitVec(bits) = node.sort else {
                    return Ok(node);
                };
                if bits > 128 {
                    return Ok(node);
                }
                let left = constant_u128(&records[0].node.immediate);
                let value = match node.op {
                    ExprOp::Add => left.wrapping_add(constant_u128(&records[1].node.immediate)),
                    ExprOp::Sub => left.wrapping_sub(constant_u128(&records[1].node.immediate)),
                    ExprOp::Mul => left.wrapping_mul(constant_u128(&records[1].node.immediate)),
                    ExprOp::And => left & constant_u128(&records[1].node.immediate),
                    ExprOp::Or => left | constant_u128(&records[1].node.immediate),
                    ExprOp::Xor => left ^ constant_u128(&records[1].node.immediate),
                    ExprOp::Not => !left,
                    _ => return Ok(node),
                } & bit_mask(bits);
                ExprNode {
                    sort: node.sort,
                    op: ExprOp::Constant,
                    operands: Vec::new(),
                    immediate: value.to_le_bytes()[..usize::from(bits).div_ceil(8)].to_vec(),
                }
            }
            ExprOp::RotL | ExprOp::RotR => {
                let ExprSort::BitVec(bits) = node.sort else {
                    return Ok(node);
                };
                if bits > 128 {
                    return Ok(node);
                }
                // The rotate amount is the count modulo the operand width —
                // the op's defining semantics (SMT-LIB rotate_left/right with
                // a same-width count, and x86's count masking). The rotation
                // is composed from shifts scoped to `bits`: u128::rotate_*
                // would wrap within the full 128-bit carrier and the wrapped
                // bits would be masked away.
                let value = constant_u128(&records[0].node.immediate);
                let count = constant_u128(&records[1].node.immediate);
                let amount = (count % u128::from(bits)) as u32;
                let rotated = if amount == 0 {
                    value
                } else if node.op == ExprOp::RotL {
                    (value << amount) | (value >> (u32::from(bits) - amount))
                } else {
                    (value >> amount) | (value << (u32::from(bits) - amount))
                } & bit_mask(bits);
                ExprNode {
                    sort: node.sort,
                    op: ExprOp::Constant,
                    operands: Vec::new(),
                    immediate: rotated.to_le_bytes()[..usize::from(bits).div_ceil(8)].to_vec(),
                }
            }
            ExprOp::Eq => ExprNode {
                sort: ExprSort::Bool,
                op: ExprOp::Constant,
                operands: Vec::new(),
                immediate: vec![u8::from(records[0].node == records[1].node)],
            },
            ExprOp::Ult | ExprOp::Ule | ExprOp::Slt | ExprOp::Sle => {
                // The sort rule pins both operands to one bitvector width;
                // unsigned comparisons read the literals directly, signed
                // ones sign-extend each literal from that width.
                let width = match records[0].node.sort {
                    ExprSort::BitVec(bits) if bits <= 128 => bits,
                    _ => return Ok(node),
                };
                let left = constant_u128(&records[0].node.immediate);
                let right = constant_u128(&records[1].node.immediate);
                let holds = match node.op {
                    ExprOp::Ult => left < right,
                    ExprOp::Ule => left <= right,
                    op => {
                        let signed = |value: u128| -> i128 {
                            if width > 0 && width < 128 && value & (1u128 << (width - 1)) != 0 {
                                (value | !bit_mask(width)) as i128
                            } else {
                                value as i128
                            }
                        };
                        if op == ExprOp::Slt {
                            signed(left) < signed(right)
                        } else {
                            signed(left) <= signed(right)
                        }
                    }
                };
                ExprNode {
                    sort: ExprSort::Bool,
                    op: ExprOp::Constant,
                    operands: Vec::new(),
                    immediate: vec![u8::from(holds)],
                }
            }
            ExprOp::Ite => {
                if records[0].node.immediate == [0] {
                    records[2].node.clone()
                } else {
                    records[1].node.clone()
                }
            }
            ExprOp::ZExt => {
                let ExprSort::BitVec(bits) = node.sort else {
                    return Ok(node);
                };
                if bits > 128 {
                    return Ok(node);
                }
                let value = match records[0].node.sort {
                    ExprSort::Bool => u128::from(records[0].node.immediate.first().copied().unwrap_or(0)),
                    ExprSort::BitVec(_) => constant_u128(&records[0].node.immediate),
                    _ => return Ok(node),
                } & bit_mask(bits);
                ExprNode {
                    sort: node.sort,
                    op: ExprOp::Constant,
                    operands: Vec::new(),
                    immediate: value.to_le_bytes()[..usize::from(bits).div_ceil(8)].to_vec(),
                }
            }
            ExprOp::SExt => {
                let ExprSort::BitVec(bits) = node.sort else {
                    return Ok(node);
                };
                if bits > 128 {
                    return Ok(node);
                }
                let (value, in_bits) = match records[0].node.sort {
                    ExprSort::Bool => (
                        u128::from(records[0].node.immediate.first().copied().unwrap_or(0)),
                        1u16,
                    ),
                    ExprSort::BitVec(w) => (constant_u128(&records[0].node.immediate), w),
                    _ => return Ok(node),
                };
                let extended = if in_bits > 0 && in_bits < 128 && (value & (1u128 << (in_bits - 1))) != 0 {
                    (value | (!bit_mask(in_bits))) & bit_mask(bits)
                } else {
                    value & bit_mask(bits)
                };
                ExprNode {
                    sort: node.sort,
                    op: ExprOp::Constant,
                    operands: Vec::new(),
                    immediate: extended.to_le_bytes()[..usize::from(bits).div_ceil(8)].to_vec(),
                }
            }
            ExprOp::Extract => {
                let ExprSort::BitVec(bits) = node.sort else {
                    return Ok(node);
                };
                if bits > 128 {
                    return Ok(node);
                }
                let Ok(immediate) = <[u8; 4]>::try_from(node.immediate.as_slice()) else {
                    return Ok(node);
                };
                let offset = u16::from_le_bytes([immediate[0], immediate[1]]);
                let width = u16::from_le_bytes([immediate[2], immediate[3]]);
                if width != bits {
                    return Ok(node);
                }
                let value = constant_u128(&records[0].node.immediate);
                let extracted = if offset >= 128 {
                    0
                } else {
                    (value >> offset) & bit_mask(bits)
                };
                ExprNode {
                    sort: node.sort,
                    op: ExprOp::Constant,
                    operands: Vec::new(),
                    immediate: extracted.to_le_bytes()[..usize::from(bits).div_ceil(8)].to_vec(),
                }
            }
            ExprOp::Concat => {
                let ExprSort::BitVec(output_bits) = node.sort else {
                    return Ok(node);
                };
                if output_bits > 128 {
                    return Ok(node);
                }
                let ExprSort::BitVec(right_bits) = records[1].node.sort else {
                    return Ok(node);
                };
                let hi = constant_u128(&records[0].node.immediate);
                let lo = constant_u128(&records[1].node.immediate);
                let value = if right_bits >= 128 {
                    lo & bit_mask(output_bits)
                } else {
                    ((hi << right_bits) | lo) & bit_mask(output_bits)
                };
                ExprNode {
                    sort: node.sort,
                    op: ExprOp::Constant,
                    operands: Vec::new(),
                    immediate: value.to_le_bytes()[..usize::from(output_bits).div_ceil(8)].to_vec(),
                }
            }
            ExprOp::Shl | ExprOp::LShr | ExprOp::AShr => {
                let ExprSort::BitVec(bits) = node.sort else {
                    return Ok(node);
                };
                if bits > 128 {
                    return Ok(node);
                }
                let left = constant_u128(&records[0].node.immediate);
                let shift = constant_u128(&records[1].node.immediate);
                let value = match node.op {
                    ExprOp::Shl => {
                        if shift >= u128::from(bits) {
                            0
                        } else {
                            (left << shift) & bit_mask(bits)
                        }
                    }
                    ExprOp::LShr => {
                        if shift >= u128::from(bits) {
                            0
                        } else {
                            (left >> shift) & bit_mask(bits)
                        }
                    }
                    ExprOp::AShr => {
                        let signed = if bits > 0 && bits < 128 && (left & (1u128 << (bits - 1))) != 0 {
                            (left | (!bit_mask(bits))) as i128
                        } else {
                            left as i128
                        };
                        let shifted = if shift >= u128::from(bits) {
                            if signed < 0 { !0i128 } else { 0i128 }
                        } else {
                            signed >> shift
                        };
                        (shifted as u128) & bit_mask(bits)
                    }
                    _ => unreachable!(),
                };
                ExprNode {
                    sort: node.sort,
                    op: ExprOp::Constant,
                    operands: Vec::new(),
                    immediate: value.to_le_bytes()[..usize::from(bits).div_ceil(8)].to_vec(),
                }
            }
            ExprOp::UDiv | ExprOp::SDiv => {
                let ExprSort::BitVec(bits) = node.sort else {
                    return Ok(node);
                };
                if bits > 128 {
                    return Ok(node);
                }
                let left = constant_u128(&records[0].node.immediate);
                let right = constant_u128(&records[1].node.immediate);
                if right == 0 {
                    return Ok(node);
                }
                let value = match node.op {
                    ExprOp::UDiv => (left / right) & bit_mask(bits),
                    ExprOp::SDiv => {
                        let to_signed = |v: u128| -> i128 {
                            if bits > 0 && bits < 128 && (v & (1u128 << (bits - 1))) != 0 {
                                (v | (!bit_mask(bits))) as i128
                            } else {
                                v as i128
                            }
                        };
                        let sleft = to_signed(left);
                        let sright = to_signed(right);
                        let sres = sleft.checked_div(sright).unwrap_or(0);
                        (sres as u128) & bit_mask(bits)
                    }
                    _ => unreachable!(),
                };
                ExprNode {
                    sort: node.sort,
                    op: ExprOp::Constant,
                    operands: Vec::new(),
                    immediate: value.to_le_bytes()[..usize::from(bits).div_ceil(8)].to_vec(),
                }
            }
            _ => return Ok(node),
        };
        Ok(folded)
    }
}

impl ExprArena for ShardedExprArena {
    type Error = ExprArenaError;

    fn intern(&self, node: ExprNode) -> Result<ExprId, Self::Error> {
        self.requests.fetch_add(1, Ordering::Relaxed);
        let node = BasicHotCanonicalizer.canonicalize(node);
        validate_node(&node)?;
        let node = self.fold_constants(node)?;

        // Shard routing uses a cheap deterministic hash of the node so the
        // hash-cons table can be probed BEFORE the SHA-256 dependency key is
        // computed. On a hit (the common case for re-executed blocks) the
        // dependency hash is never re-derived: the stored record already
        // carries the key computed once at insertion.
        let shard_index = node_shard(&node);
        {
            let shard = self.shards[shard_index]
                .read()
                .map_err(|_| ExprArenaError::LockPoisoned)?;
            if let Some(existing) = shard.by_node.get(&node).copied() {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Ok(existing);
            }
        }

        let dependency = self.build_dependency(&node)?;
        let mut shard = self.shards[shard_index]
            .write()
            .map_err(|_| ExprArenaError::LockPoisoned)?;
        // Re-check under the write lock: another thread may have inserted the
        // same node between the read probe and here.
        if let Some(existing) = shard.by_node.get(&node).copied() {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Ok(existing);
        }
        let local = u32::try_from(shard.records.len()).map_err(|_| ExprArenaError::CapacityExceeded)?;
        if local > LOCAL_MASK {
            return Err(ExprArenaError::CapacityExceeded);
        }
        let id = ExprId(((shard_index as u32) << LOCAL_BITS) | local);
        shard.records.push(ExprRecord {
            node: node.clone(),
            dependency,
        });
        shard.by_node.insert(node, id);
        self.nodes.fetch_add(1, Ordering::Relaxed);
        Ok(id)
    }

    fn get(&self, id: ExprId) -> Option<ExprNode> {
        self.record(id).ok().map(|record| record.node)
    }

    fn dependency_summary(&self, id: ExprId) -> Option<DependencySummary> {
        self.record(id).ok().map(|record| record.dependency)
    }

    fn sort_of(&self, id: ExprId) -> Option<ExprSort> {
        let (shard, local) = decode_id(id);
        let shard = self.shards[shard].read().ok()?;
        shard.records.get(local).map(|record| record.node.sort)
    }

    fn op_of(&self, id: ExprId) -> Option<ExprOp> {
        let (shard, local) = decode_id(id);
        let shard = self.shards[shard].read().ok()?;
        shard.records.get(local).map(|record| record.node.op)
    }

    fn normalization_version(&self) -> ExpressionNormalizationVersion {
        self.version
    }
}

impl ExprReader for ShardedExprArena {
    fn read(&self, id: ExprId) -> Option<ExprNode> {
        self.get(id)
    }
}

fn decode_id(id: ExprId) -> (usize, usize) {
    ((id.0 >> LOCAL_BITS) as usize, (id.0 & LOCAL_MASK) as usize)
}

/// FNV-1a 64 mixing state for [`node_shard`].
const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fnv_mix(hash: u64, bytes: &[u8]) -> u64 {
    let mut mixed = hash;
    for byte in bytes {
        mixed ^= u64::from(*byte);
        mixed = mixed.wrapping_mul(FNV_PRIME);
    }
    mixed
}

/// Cheap deterministic shard routing for a canonicalized node.
///
/// This is routing only — the authoritative content identity remains the
/// SHA-256 [`DependencyKey`] computed once at insertion and stored in the
/// record. `by_node` inside the shard is the final arbiter of equality, so
/// hash collisions merely co-locate nodes. The encoding length-prefixes the
/// variable-length parts (immediate, operand list) so that distinct nodes
/// cannot produce identical byte streams.
fn node_shard(node: &ExprNode) -> usize {
    let mut hash = FNV_OFFSET_BASIS;
    hash = fnv_mix(hash, sort_tag(node.sort).as_slice());
    hash = fnv_mix(hash, &[op_tag(node.op)]);
    hash = fnv_mix(hash, &(node.immediate.len() as u64).to_le_bytes());
    hash = fnv_mix(hash, &node.immediate);
    hash = fnv_mix(hash, &(node.operands.len() as u64).to_le_bytes());
    for operand in &node.operands {
        hash = fnv_mix(hash, &operand.0.to_le_bytes());
    }
    (hash as usize) & (SHARD_COUNT - 1)
}

/// Flat deterministic encoding of a sort for shard routing (mirrors the
/// domain separation of [`encode_sort`] without the SHA-256 dependency).
fn sort_tag(sort: ExprSort) -> [u8; 8] {
    let mut tag = [0_u8; 8];
    match sort {
        ExprSort::BitVec(bits) => {
            tag[0] = 0;
            tag[1..3].copy_from_slice(&bits.to_le_bytes());
        }
        ExprSort::Float {
            exponent_bits,
            significand_bits,
        } => {
            tag[0] = 1;
            tag[1] = exponent_bits;
            tag[2] = significand_bits;
        }
        ExprSort::Bool => tag[0] = 2,
        ExprSort::Vector { lanes, lane_bits } => {
            tag[0] = 3;
            tag[1..3].copy_from_slice(&lanes.to_le_bytes());
            tag[3..5].copy_from_slice(&lane_bits.to_le_bytes());
        }
        ExprSort::Opmask(bits) => {
            tag[0] = 4;
            tag[1..3].copy_from_slice(&bits.to_le_bytes());
        }
        ExprSort::Tile {
            rows,
            bytes_per_row,
            element_bits,
        } => {
            tag[0] = 5;
            tag[1] = rows;
            tag[2..4].copy_from_slice(&bytes_per_row.to_le_bytes());
            tag[4..6].copy_from_slice(&element_bits.to_le_bytes());
        }
    }
    tag
}

fn validate_node(node: &ExprNode) -> Result<(), ExprArenaError> {
    match node.sort {
        ExprSort::BitVec(0)
        | ExprSort::Float { exponent_bits: 0, .. }
        | ExprSort::Float {
            significand_bits: 0, ..
        }
        | ExprSort::Vector { lanes: 0, .. }
        | ExprSort::Vector { lane_bits: 0, .. }
        | ExprSort::Opmask(0)
        | ExprSort::Tile { rows: 0, .. }
        | ExprSort::Tile { bytes_per_row: 0, .. }
        | ExprSort::Tile { element_bits: 0, .. } => return Err(ExprArenaError::InvalidSort),
        _ => {}
    }
    let expected = match node.op {
        ExprOp::Constant | ExprOp::Symbol => 0,
        ExprOp::Not | ExprOp::Extract | ExprOp::ZExt | ExprOp::SExt => 1,
        ExprOp::Ite => 3,
        _ => 2,
    };
    if node.operands.len() != expected {
        return Err(ExprArenaError::InvalidArity {
            op: node.op,
            expected,
            actual: node.operands.len(),
        });
    }
    match node.op {
        ExprOp::Constant if constant_is_canonical(node.sort, &node.immediate) => Ok(()),
        ExprOp::Constant => Err(ExprArenaError::InvalidImmediate),
        ExprOp::Symbol if node.immediate.len() != 8 => Err(ExprArenaError::InvalidImmediate),
        ExprOp::Symbol => Ok(()),
        ExprOp::Extract if node.immediate.len() == 4 => Ok(()),
        _ if !node.immediate.is_empty() => Err(ExprArenaError::InvalidImmediate),
        _ => Ok(()),
    }
}

fn constant_is_canonical(sort: ExprSort, bytes: &[u8]) -> bool {
    let bits = match sort {
        ExprSort::BitVec(bits) if bits > 0 => usize::from(bits),
        ExprSort::Float {
            exponent_bits,
            significand_bits,
        } if exponent_bits > 0 && significand_bits > 0 => usize::from(exponent_bits) + usize::from(significand_bits),
        ExprSort::Bool => return bytes == [0] || bytes == [1],
        ExprSort::Vector { lanes, lane_bits } => {
            let Some(bits) = usize::from(lanes).checked_mul(usize::from(lane_bits)) else {
                return false;
            };
            bits
        }
        ExprSort::Opmask(bits) => usize::from(bits),
        ExprSort::Tile {
            rows, bytes_per_row, ..
        } => {
            let Some(byte_len) = usize::from(rows).checked_mul(usize::from(bytes_per_row)) else {
                return false;
            };
            return bytes.len() == byte_len;
        }
        _ => return false,
    };
    if bytes.len() != bits.div_ceil(8) {
        return false;
    }
    let used = bits % 8;
    used == 0 || bytes.last().is_some_and(|byte| byte & !((1_u8 << used) - 1) == 0)
}

fn validate_sorts(node: &ExprNode, inputs: &[ExprSort]) -> Result<(), ExprArenaError> {
    let valid = match node.op {
        ExprOp::Constant | ExprOp::Symbol => true,
        ExprOp::Add
        | ExprOp::Sub
        | ExprOp::Mul
        | ExprOp::UDiv
        | ExprOp::SDiv
        | ExprOp::And
        | ExprOp::Or
        | ExprOp::Xor => inputs == [node.sort, node.sort],
        ExprOp::Not => inputs == [node.sort],
        ExprOp::Shl | ExprOp::LShr | ExprOp::AShr => {
            inputs.first() == Some(&node.sort) && matches!(inputs.get(1), Some(ExprSort::BitVec(_)))
        }
        ExprOp::RotL | ExprOp::RotR => {
            matches!(node.sort, ExprSort::BitVec(bits) if bits > 0)
                && inputs.first() == Some(&node.sort)
                && matches!(inputs.get(1), Some(ExprSort::BitVec(_)))
        }
        ExprOp::Eq => node.sort == ExprSort::Bool && inputs.first() == inputs.get(1),
        ExprOp::Ult | ExprOp::Ule | ExprOp::Slt | ExprOp::Sle => {
            node.sort == ExprSort::Bool
                && inputs.first() == inputs.get(1)
                && matches!(inputs.first(), Some(ExprSort::BitVec(_)))
        }
        ExprOp::Ite => {
            inputs.first() == Some(&ExprSort::Bool)
                && inputs.get(1) == Some(&node.sort)
                && inputs.get(2) == Some(&node.sort)
        }
        ExprOp::Concat => match (node.sort, inputs.first(), inputs.get(1)) {
            (ExprSort::BitVec(output), Some(ExprSort::BitVec(left)), Some(ExprSort::BitVec(right))) => {
                left.checked_add(*right) == Some(output)
            }
            _ => false,
        },
        ExprOp::Extract => validate_extract(node, inputs),
        ExprOp::ZExt | ExprOp::SExt => match (node.sort, inputs.first()) {
            (ExprSort::BitVec(output), Some(ExprSort::BitVec(input))) => output > *input,
            // A Bool is a 1-bit value — extending it is well-defined.
            (ExprSort::BitVec(output), Some(ExprSort::Bool)) => output > 1,
            _ => false,
        },
    };
    if !valid {
        return Err(ExprArenaError::SortMismatch(node.op));
    }
    Ok(())
}

fn validate_extract(node: &ExprNode, inputs: &[ExprSort]) -> bool {
    let (ExprSort::BitVec(output), Some(ExprSort::BitVec(input))) = (node.sort, inputs.first()) else {
        return false;
    };
    let Ok(immediate) = <[u8; 4]>::try_from(node.immediate.as_slice()) else {
        return false;
    };
    let offset = u16::from_le_bytes([immediate[0], immediate[1]]);
    let width = u16::from_le_bytes([immediate[2], immediate[3]]);
    width == output && offset.checked_add(width).is_some_and(|end| end <= *input)
}

fn is_commutative(op: ExprOp) -> bool {
    matches!(
        op,
        ExprOp::Add | ExprOp::Mul | ExprOp::And | ExprOp::Or | ExprOp::Xor | ExprOp::Eq
    )
}

#[inline]
fn encode_sort_into(buf: &mut [u8], sort: ExprSort) -> usize {
    match sort {
        ExprSort::BitVec(bits) => {
            buf[0] = 0;
            buf[1..3].copy_from_slice(&bits.to_le_bytes());
            3
        }
        ExprSort::Float {
            exponent_bits,
            significand_bits,
        } => {
            buf[0] = 1;
            buf[1] = exponent_bits;
            buf[2] = significand_bits;
            3
        }
        ExprSort::Bool => {
            buf[0] = 2;
            1
        }
        ExprSort::Vector { lanes, lane_bits } => {
            buf[0] = 3;
            buf[1..3].copy_from_slice(&lanes.to_le_bytes());
            buf[3..5].copy_from_slice(&lane_bits.to_le_bytes());
            5
        }
        ExprSort::Opmask(bits) => {
            buf[0] = 4;
            buf[1..3].copy_from_slice(&bits.to_le_bytes());
            3
        }
        ExprSort::Tile {
            rows,
            bytes_per_row,
            element_bits,
        } => {
            buf[0] = 5;
            buf[1] = rows;
            buf[2..4].copy_from_slice(&bytes_per_row.to_le_bytes());
            buf[4..6].copy_from_slice(&element_bits.to_le_bytes());
            6
        }
    }
}

#[inline]
fn compute_dependency_key(
    prefix: &[u8; 22],
    sort: ExprSort,
    op: ExprOp,
    immediate: &[u8],
    child_keys: &[DependencyKey],
) -> DependencyKey {
    let imm_len = immediate.len();
    let child_count = child_keys.len();
    let total_len = 22 + 6 + 1 + 8 + imm_len + 8 + child_count * 32;
    if total_len <= 256 {
        let mut buf = [0u8; 256];
        buf[..22].copy_from_slice(prefix);
        let mut cursor = 22;
        cursor += encode_sort_into(&mut buf[cursor..], sort);
        buf[cursor] = op as u8;
        cursor += 1;
        buf[cursor..cursor + 8].copy_from_slice(&(imm_len as u64).to_le_bytes());
        cursor += 8;
        buf[cursor..cursor + imm_len].copy_from_slice(immediate);
        cursor += imm_len;
        buf[cursor..cursor + 8].copy_from_slice(&(child_count as u64).to_le_bytes());
        cursor += 8;
        for key in child_keys {
            buf[cursor..cursor + 32].copy_from_slice(&key.0);
            cursor += 32;
        }
        let hash = blake3::hash(&buf[..cursor]);
        DependencyKey(*hash.as_bytes())
    } else {
        let mut bytes = Vec::with_capacity(total_len);
        bytes.extend_from_slice(prefix);
        let mut sort_buf = [0u8; 8];
        let sort_len = encode_sort_into(&mut sort_buf, sort);
        bytes.extend_from_slice(&sort_buf[..sort_len]);
        bytes.push(op as u8);
        bytes.extend_from_slice(&(imm_len as u64).to_le_bytes());
        bytes.extend_from_slice(immediate);
        bytes.extend_from_slice(&(child_count as u64).to_le_bytes());
        for key in child_keys {
            bytes.extend_from_slice(&key.0);
        }
        let hash = blake3::hash(&bytes);
        DependencyKey(*hash.as_bytes())
    }
}

#[inline]
fn merge_sorted_sources(s0: &[u64], s1: &[u64]) -> Vec<u64> {
    if s0.is_empty() {
        return s1.to_vec();
    }
    if s1.is_empty() {
        return s0.to_vec();
    }
    if s0 == s1 {
        return s0.to_vec();
    }
    let mut merged = Vec::with_capacity(s0.len() + s1.len());
    let (mut i, mut j) = (0, 0);
    while i < s0.len() && j < s1.len() {
        match s0[i].cmp(&s1[j]) {
            std::cmp::Ordering::Less => {
                merged.push(s0[i]);
                i += 1;
            }
            std::cmp::Ordering::Greater => {
                merged.push(s1[j]);
                j += 1;
            }
            std::cmp::Ordering::Equal => {
                merged.push(s0[i]);
                i += 1;
                j += 1;
            }
        }
    }
    merged.extend_from_slice(&s0[i..]);
    merged.extend_from_slice(&s1[j..]);
    merged
}

fn op_tag(op: ExprOp) -> u8 {
    op as u8
}

fn constant_u128(bytes: &[u8]) -> u128 {
    let mut widened = [0_u8; 16];
    let len = bytes.len().min(16);
    widened[..len].copy_from_slice(&bytes[..len]);
    u128::from_le_bytes(widened)
}

fn bit_mask(bits: u16) -> u128 {
    if bits == 128 { u128::MAX } else { (1_u128 << bits) - 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn symbol(source: u64) -> ExprNode {
        ExprNode {
            sort: ExprSort::BitVec(64),
            op: ExprOp::Symbol,
            operands: Vec::new(),
            immediate: source.to_le_bytes().to_vec(),
        }
    }

    #[test]
    fn identical_and_commuted_nodes_intern_once() -> Result<(), ExprArenaError> {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let left = arena.intern(symbol(10))?;
        let right = arena.intern(symbol(20))?;
        let first = arena.intern(ExprNode {
            sort: ExprSort::BitVec(64),
            op: ExprOp::Add,
            operands: vec![left, right],
            immediate: Vec::new(),
        })?;
        let commuted = arena.intern(ExprNode {
            sort: ExprSort::BitVec(64),
            op: ExprOp::Add,
            operands: vec![right, left],
            immediate: Vec::new(),
        })?;

        assert_eq!(first, commuted);
        assert_eq!(arena.stats().nodes, 3);
        assert_eq!(arena.stats().intern_hits, 1);
        Ok(())
    }

    #[test]
    fn dependency_summary_unions_symbolic_sources() -> Result<(), ExprArenaError> {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let left = arena.intern(symbol(10))?;
        let right = arena.intern(symbol(20))?;
        let root = arena.intern(ExprNode {
            sort: ExprSort::Bool,
            op: ExprOp::Eq,
            operands: vec![left, right],
            immediate: Vec::new(),
        })?;
        let summary = arena
            .dependency_summary(root)
            .ok_or(ExprArenaError::UnknownOperand(root))?;

        assert_eq!(summary.symbolic_sources, vec![10, 20]);
        assert_ne!(summary.key, DependencyKey([0; 32]));
        Ok(())
    }

    #[test]
    fn unknown_operands_fail_closed() {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let result = arena.intern(ExprNode {
            sort: ExprSort::BitVec(64),
            op: ExprOp::Not,
            operands: vec![ExprId(99)],
            immediate: Vec::new(),
        });

        assert_eq!(result, Err(ExprArenaError::UnknownOperand(ExprId(99))));
    }

    #[test]
    fn normalization_version_separates_dependency_identity() -> Result<(), ExprArenaError> {
        let first = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let second = ShardedExprArena::new(ExpressionNormalizationVersion(2));
        let first_id = first.intern(symbol(1))?;
        let second_id = second.intern(symbol(1))?;

        assert_ne!(first.dependency_summary(first_id), second.dependency_summary(second_id));
        Ok(())
    }

    #[test]
    fn incompatible_sorts_and_noncanonical_constants_fail_closed() -> Result<(), ExprArenaError> {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let left = arena.intern(symbol(1))?;
        let boolean = arena.intern(ExprNode {
            sort: ExprSort::Bool,
            op: ExprOp::Constant,
            operands: Vec::new(),
            immediate: vec![1],
        })?;

        assert_eq!(
            arena.intern(ExprNode {
                sort: ExprSort::BitVec(64),
                op: ExprOp::Add,
                operands: vec![left, boolean],
                immediate: Vec::new(),
            }),
            Err(ExprArenaError::SortMismatch(ExprOp::Add))
        );
        assert_eq!(
            arena.intern(ExprNode {
                sort: ExprSort::BitVec(9),
                op: ExprOp::Constant,
                operands: Vec::new(),
                immediate: vec![0, 0xff],
            }),
            Err(ExprArenaError::InvalidImmediate)
        );
        Ok(())
    }

    #[test]
    fn folds_small_bitvector_constants_before_interning() -> Result<(), ExprArenaError> {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let left = arena.intern(ExprNode {
            sort: ExprSort::BitVec(8),
            op: ExprOp::Constant,
            operands: Vec::new(),
            immediate: vec![250],
        })?;
        let right = arena.intern(ExprNode {
            sort: ExprSort::BitVec(8),
            op: ExprOp::Constant,
            operands: Vec::new(),
            immediate: vec![10],
        })?;
        let sum = arena.intern(ExprNode {
            sort: ExprSort::BitVec(8),
            op: ExprOp::Add,
            operands: vec![left, right],
            immediate: Vec::new(),
        })?;

        assert_eq!(
            arena.get(sum),
            Some(ExprNode {
                sort: ExprSort::BitVec(8),
                op: ExprOp::Constant,
                operands: Vec::new(),
                immediate: vec![4]
            })
        );
        Ok(())
    }

    #[test]
    fn vector_mask_and_tile_sorts_round_trip() -> Result<(), ExprArenaError> {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        for (source, sort) in [
            (
                1_u64,
                ExprSort::Vector {
                    lanes: 16,
                    lane_bits: 32,
                },
            ),
            (2_u64, ExprSort::Opmask(64)),
            (
                3_u64,
                ExprSort::Tile {
                    rows: 16,
                    bytes_per_row: 64,
                    element_bits: 8,
                },
            ),
        ] {
            let id = arena.intern(ExprNode {
                sort,
                op: ExprOp::Symbol,
                operands: Vec::new(),
                immediate: source.to_le_bytes().to_vec(),
            })?;
            assert_eq!(arena.get(id).map(|node| node.sort), Some(sort));
        }
        Ok(())
    }

    fn bitvec_constant(value: u128, bits: u16) -> ExprNode {
        let len = usize::from(bits).div_ceil(8);
        let bytes = value.to_le_bytes();
        ExprNode {
            sort: ExprSort::BitVec(bits),
            op: ExprOp::Constant,
            operands: Vec::new(),
            immediate: bytes[..len].to_vec(),
        }
    }

    fn bool_constant(value: bool) -> ExprNode {
        ExprNode {
            sort: ExprSort::Bool,
            op: ExprOp::Constant,
            operands: Vec::new(),
            immediate: vec![u8::from(value)],
        }
    }

    fn binary_bitvec_op(op: ExprOp, left: ExprId, right: ExprId) -> ExprNode {
        ExprNode {
            sort: ExprSort::BitVec(8),
            op,
            operands: vec![left, right],
            immediate: Vec::new(),
        }
    }

    #[test]
    fn constant_fold_add() -> Result<(), ExprArenaError> {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let left = arena.intern(bitvec_constant(20, 8))?;
        let right = arena.intern(bitvec_constant(22, 8))?;
        let sum = arena.intern(binary_bitvec_op(ExprOp::Add, left, right))?;
        assert_eq!(arena.get(sum), Some(bitvec_constant(42, 8)));
        Ok(())
    }

    #[test]
    fn constant_fold_sub() -> Result<(), ExprArenaError> {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let left = arena.intern(bitvec_constant(100, 8))?;
        let right = arena.intern(bitvec_constant(30, 8))?;
        let diff = arena.intern(binary_bitvec_op(ExprOp::Sub, left, right))?;
        assert_eq!(arena.get(diff), Some(bitvec_constant(70, 8)));
        Ok(())
    }

    #[test]
    fn constant_fold_mul() -> Result<(), ExprArenaError> {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let left = arena.intern(bitvec_constant(5, 8))?;
        let right = arena.intern(bitvec_constant(6, 8))?;
        let product = arena.intern(binary_bitvec_op(ExprOp::Mul, left, right))?;
        assert_eq!(arena.get(product), Some(bitvec_constant(30, 8)));
        Ok(())
    }

    #[test]
    fn constant_fold_and() -> Result<(), ExprArenaError> {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let left = arena.intern(bitvec_constant(0xff, 8))?;
        let right = arena.intern(bitvec_constant(0x0f, 8))?;
        let result = arena.intern(binary_bitvec_op(ExprOp::And, left, right))?;
        assert_eq!(arena.get(result), Some(bitvec_constant(0x0f, 8)));
        Ok(())
    }

    #[test]
    fn constant_fold_or() -> Result<(), ExprArenaError> {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let left = arena.intern(bitvec_constant(0xf0, 8))?;
        let right = arena.intern(bitvec_constant(0x0f, 8))?;
        let result = arena.intern(binary_bitvec_op(ExprOp::Or, left, right))?;
        assert_eq!(arena.get(result), Some(bitvec_constant(0xff, 8)));
        Ok(())
    }

    #[test]
    fn constant_fold_xor() -> Result<(), ExprArenaError> {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let left = arena.intern(bitvec_constant(0xff, 8))?;
        let right = arena.intern(bitvec_constant(0x0f, 8))?;
        let result = arena.intern(binary_bitvec_op(ExprOp::Xor, left, right))?;
        assert_eq!(arena.get(result), Some(bitvec_constant(0xf0, 8)));
        Ok(())
    }

    #[test]
    fn constant_fold_not() -> Result<(), ExprArenaError> {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let operand = arena.intern(bitvec_constant(0x0f, 8))?;
        let result = arena.intern(ExprNode {
            sort: ExprSort::BitVec(8),
            op: ExprOp::Not,
            operands: vec![operand],
            immediate: Vec::new(),
        })?;
        assert_eq!(arena.get(result), Some(bitvec_constant(0xf0, 8)));
        Ok(())
    }

    #[test]
    fn constant_fold_eq_true() -> Result<(), ExprArenaError> {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let left = arena.intern(bitvec_constant(42, 8))?;
        let right = arena.intern(bitvec_constant(42, 8))?;
        let result = arena.intern(ExprNode {
            sort: ExprSort::Bool,
            op: ExprOp::Eq,
            operands: vec![left, right],
            immediate: Vec::new(),
        })?;
        assert_eq!(arena.get(result), Some(bool_constant(true)));
        Ok(())
    }

    #[test]
    fn constant_fold_eq_false() -> Result<(), ExprArenaError> {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let left = arena.intern(bitvec_constant(42, 8))?;
        let right = arena.intern(bitvec_constant(43, 8))?;
        let result = arena.intern(ExprNode {
            sort: ExprSort::Bool,
            op: ExprOp::Eq,
            operands: vec![left, right],
            immediate: Vec::new(),
        })?;
        assert_eq!(arena.get(result), Some(bool_constant(false)));
        Ok(())
    }

    #[test]
    fn constant_fold_ite_true_branch() -> Result<(), ExprArenaError> {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let cond = arena.intern(bool_constant(true))?;
        let true_branch = arena.intern(bitvec_constant(42, 8))?;
        let false_branch = arena.intern(bitvec_constant(99, 8))?;
        let result = arena.intern(ExprNode {
            sort: ExprSort::BitVec(8),
            op: ExprOp::Ite,
            operands: vec![cond, true_branch, false_branch],
            immediate: Vec::new(),
        })?;
        assert_eq!(arena.get(result), Some(bitvec_constant(42, 8)));
        Ok(())
    }

    #[test]
    fn constant_fold_ite_false_branch() -> Result<(), ExprArenaError> {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let cond = arena.intern(bool_constant(false))?;
        let true_branch = arena.intern(bitvec_constant(42, 8))?;
        let false_branch = arena.intern(bitvec_constant(99, 8))?;
        let result = arena.intern(ExprNode {
            sort: ExprSort::BitVec(8),
            op: ExprOp::Ite,
            operands: vec![cond, true_branch, false_branch],
            immediate: Vec::new(),
        })?;
        assert_eq!(arena.get(result), Some(bitvec_constant(99, 8)));
        Ok(())
    }

    #[test]
    fn constant_fold_rotl() -> Result<(), ExprArenaError> {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let value = arena.intern(bitvec_constant(0b1001_0110, 8))?;
        let count = arena.intern(bitvec_constant(3, 8))?;
        let result = arena.intern(binary_bitvec_op(ExprOp::RotL, value, count))?;
        assert_eq!(arena.get(result), Some(bitvec_constant(0b1011_0100, 8)));
        Ok(())
    }

    #[test]
    fn constant_fold_rotr() -> Result<(), ExprArenaError> {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let value = arena.intern(bitvec_constant(0b1001_0110, 8))?;
        let count = arena.intern(bitvec_constant(2, 8))?;
        let result = arena.intern(binary_bitvec_op(ExprOp::RotR, value, count))?;
        assert_eq!(arena.get(result), Some(bitvec_constant(0b1010_0101, 8)));
        Ok(())
    }

    #[test]
    fn rotate_count_folds_modulo_width() -> Result<(), ExprArenaError> {
        // A count at or above the width rotates by count mod width (x86
        // rotate-count masking and SMT-LIB same-width rotate semantics).
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let value = arena.intern(bitvec_constant(0xF0, 8))?;
        let count = arena.intern(bitvec_constant(66, 8))?;
        let rotl = arena.intern(binary_bitvec_op(ExprOp::RotL, value, count))?;
        assert_eq!(arena.get(rotl), Some(bitvec_constant(0xC3, 8)));

        let rotr = arena.intern(binary_bitvec_op(ExprOp::RotR, value, count))?;
        assert_eq!(arena.get(rotr), Some(bitvec_constant(0x3C, 8)));
        Ok(())
    }

    fn binary_bitvec_op_width(op: ExprOp, width: u16, left: ExprId, right: ExprId) -> ExprNode {
        ExprNode {
            sort: ExprSort::BitVec(width),
            op,
            operands: vec![left, right],
            immediate: Vec::new(),
        }
    }

    #[test]
    fn rotate_sort_rules() -> Result<(), ExprArenaError> {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let value64 = arena.intern(bitvec_constant(1, 64))?;
        let count8 = arena.intern(bitvec_constant(1, 8))?;
        let count64 = arena.intern(bitvec_constant(1, 64))?;
        let count32 = arena.intern(bitvec_constant(1, 32))?;
        let boolean = arena.intern(bool_constant(true))?;

        // The value shares the node sort; the count may be any bitvector
        // width (shift-shaped rule, sibling of Shl).
        assert!(
            arena
                .intern(binary_bitvec_op_width(ExprOp::RotL, 64, value64, count8))
                .is_ok()
        );
        assert!(
            arena
                .intern(binary_bitvec_op_width(ExprOp::RotR, 64, value64, count64))
                .is_ok()
        );
        // A boolean count is not a rotate amount.
        assert_eq!(
            arena.intern(binary_bitvec_op_width(ExprOp::RotL, 64, value64, boolean)),
            Err(ExprArenaError::SortMismatch(ExprOp::RotL))
        );
        // The rotated value must share the node sort.
        assert_eq!(
            arena.intern(binary_bitvec_op_width(ExprOp::RotL, 32, value64, count32)),
            Err(ExprArenaError::SortMismatch(ExprOp::RotL))
        );
        Ok(())
    }

    #[test]
    fn rotate_nodes_hash_cons_like_siblings() -> Result<(), ExprArenaError> {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let value = arena.intern(bitvec_constant(0x1234, 16))?;
        let other = arena.intern(bitvec_constant(0x0002, 16))?;
        let first = arena.intern(binary_bitvec_op_width(ExprOp::RotL, 16, value, other))?;
        let second = arena.intern(binary_bitvec_op_width(ExprOp::RotL, 16, value, other))?;
        assert_eq!(first, second);
        // Rotations are directional: operand order and direction are
        // structural (0x1234 rotl 2 = 0x48D0, rotr 2 = 0x048D, and
        // 0x0002 rotl 4 = 0x0020 all differ).
        let swapped = arena.intern(binary_bitvec_op_width(ExprOp::RotL, 16, other, value))?;
        assert_ne!(first, swapped);
        let mirrored = arena.intern(binary_bitvec_op_width(ExprOp::RotR, 16, value, other))?;
        assert_ne!(first, mirrored);
        Ok(())
    }

    #[test]
    fn hash_consing_returns_same_id() -> Result<(), ExprArenaError> {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let first = arena.intern(symbol(7))?;
        let second = arena.intern(symbol(7))?;
        assert_eq!(first, second);
        assert_eq!(arena.stats().nodes, 1);
        assert_eq!(arena.stats().intern_hits, 1);
        Ok(())
    }

    #[test]
    fn hash_consing_commutative_canonicalization() -> Result<(), ExprArenaError> {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let left = arena.intern(symbol(1))?;
        let right = arena.intern(symbol(2))?;
        let first = arena.intern(ExprNode {
            sort: ExprSort::BitVec(64),
            op: ExprOp::Xor,
            operands: vec![left, right],
            immediate: Vec::new(),
        })?;
        let second = arena.intern(ExprNode {
            sort: ExprSort::BitVec(64),
            op: ExprOp::Xor,
            operands: vec![right, left],
            immediate: Vec::new(),
        })?;
        assert_eq!(first, second);
        assert_eq!(arena.stats().intern_hits, 1);
        Ok(())
    }

    #[test]
    fn symbol_has_correct_sources() -> Result<(), ExprArenaError> {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let id = arena.intern(symbol(123))?;
        let summary = arena.dependency_summary(id).ok_or(ExprArenaError::UnknownOperand(id))?;
        assert_eq!(summary.symbolic_sources, vec![123]);
        Ok(())
    }

    #[test]
    fn invalid_sort_zero_width_rejected() {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let result = arena.intern(ExprNode {
            sort: ExprSort::BitVec(0),
            op: ExprOp::Constant,
            operands: Vec::new(),
            immediate: Vec::new(),
        });
        assert_eq!(result, Err(ExprArenaError::InvalidSort));
    }

    #[test]
    fn invalid_sort_float_zero_exponent_rejected() {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let result = arena.intern(ExprNode {
            sort: ExprSort::Float {
                exponent_bits: 0,
                significand_bits: 8,
            },
            op: ExprOp::Symbol,
            operands: Vec::new(),
            immediate: 1_u64.to_le_bytes().to_vec(),
        });
        assert_eq!(result, Err(ExprArenaError::InvalidSort));
    }

    #[test]
    fn dependency_key_is_stable() -> Result<(), ExprArenaError> {
        let arena_a = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let arena_b = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let left_a = arena_a.intern(symbol(10))?;
        let right_a = arena_a.intern(symbol(20))?;
        let expr_a = arena_a.intern(ExprNode {
            sort: ExprSort::BitVec(64),
            op: ExprOp::Add,
            operands: vec![left_a, right_a],
            immediate: Vec::new(),
        })?;
        let left_b = arena_b.intern(symbol(10))?;
        let right_b = arena_b.intern(symbol(20))?;
        let expr_b = arena_b.intern(ExprNode {
            sort: ExprSort::BitVec(64),
            op: ExprOp::Add,
            operands: vec![left_b, right_b],
            immediate: Vec::new(),
        })?;
        let summary_a = arena_a
            .dependency_summary(expr_a)
            .ok_or(ExprArenaError::UnknownOperand(expr_a))?;
        let summary_b = arena_b
            .dependency_summary(expr_b)
            .ok_or(ExprArenaError::UnknownOperand(expr_b))?;
        assert_eq!(summary_a.key, summary_b.key);
        Ok(())
    }

    #[test]
    fn different_expressions_have_different_keys() -> Result<(), ExprArenaError> {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let left = arena.intern(symbol(10))?;
        let right = arena.intern(symbol(20))?;
        let add = arena.intern(ExprNode {
            sort: ExprSort::BitVec(64),
            op: ExprOp::Add,
            operands: vec![left, right],
            immediate: Vec::new(),
        })?;
        let sub = arena.intern(ExprNode {
            sort: ExprSort::BitVec(64),
            op: ExprOp::Sub,
            operands: vec![left, right],
            immediate: Vec::new(),
        })?;
        let add_summary = arena
            .dependency_summary(add)
            .ok_or(ExprArenaError::UnknownOperand(add))?;
        let sub_summary = arena
            .dependency_summary(sub)
            .ok_or(ExprArenaError::UnknownOperand(sub))?;
        assert_ne!(add_summary.key, sub_summary.key);
        Ok(())
    }

    #[test]
    fn arena_stats_track_interns() -> Result<(), ExprArenaError> {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let a = arena.intern(symbol(1))?;
        let b = arena.intern(symbol(2))?;
        let _ = arena.intern(ExprNode {
            sort: ExprSort::BitVec(64),
            op: ExprOp::Add,
            operands: vec![a, b],
            immediate: Vec::new(),
        })?;
        let stats = arena.stats();
        assert_eq!(stats.intern_requests, 3);
        assert_eq!(stats.nodes, 3);
        assert_eq!(stats.intern_hits, 0);
        let _ = arena.intern(symbol(1))?;
        let stats_after = arena.stats();
        assert_eq!(stats_after.intern_requests, 4);
        assert_eq!(stats_after.intern_hits, 1);
        assert_eq!(stats_after.nodes, 3);
        Ok(())
    }

    #[test]
    fn get_returns_interned_node() -> Result<(), ExprArenaError> {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let node = symbol(55);
        let id = arena.intern(node.clone())?;
        assert_eq!(arena.get(id), Some(node));
        Ok(())
    }

    #[test]
    fn concurrent_reads_dont_block() -> Result<(), ExprArenaError> {
        let arena = std::sync::Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
        let id = arena.intern(symbol(42))?;
        let arena_a = arena.clone();
        let arena_b = arena.clone();
        let handle_a = std::thread::spawn(move || arena_a.get(id));
        let handle_b = std::thread::spawn(move || arena_b.get(id));
        let result_a = handle_a.join().map_err(|_| ExprArenaError::LockPoisoned)?;
        let result_b = handle_b.join().map_err(|_| ExprArenaError::LockPoisoned)?;
        assert!(result_a.is_some());
        assert!(result_b.is_some());
        assert_eq!(result_a, result_b);
        Ok(())
    }

    #[test]
    fn write_blocks_reads() -> Result<(), ExprArenaError> {
        let arena = std::sync::Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
        let id = arena.intern(symbol(99))?;
        let arena_writer = arena.clone();
        let arena_reader = arena.clone();
        let writer = std::thread::spawn(move || arena_writer.intern(symbol(100)));
        let reader = std::thread::spawn(move || arena_reader.get(id));
        let write_result = writer.join().map_err(|_| ExprArenaError::LockPoisoned)?;
        let read_result = reader.join().map_err(|_| ExprArenaError::LockPoisoned)?;
        assert!(write_result.is_ok());
        assert!(read_result.is_some());
        Ok(())
    }

    #[test]
    fn read_does_not_block_read() -> Result<(), ExprArenaError> {
        let arena = std::sync::Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
        let id = arena.intern(symbol(7))?;
        let arena_a = arena.clone();
        let arena_b = arena.clone();
        let handle_a = std::thread::spawn(move || arena_a.dependency_summary(id));
        let handle_b = std::thread::spawn(move || arena_b.dependency_summary(id));
        let summary_a = handle_a.join().map_err(|_| ExprArenaError::LockPoisoned)?;
        let summary_b = handle_b.join().map_err(|_| ExprArenaError::LockPoisoned)?;
        assert!(summary_a.is_some());
        assert!(summary_b.is_some());
        assert_eq!(summary_a, summary_b);
        Ok(())
    }

    /// Independent re-derivation of the dependency-key recipe. The arena's
    /// `DependencyKey` value feeds canonical solver-query identity, so the
    /// exact byte stream handed to BLAKE3 is pinned here: any change to when
    /// or how the key is computed must keep these bytes identical.
    fn expected_key(version: u64, node: &ExprNode, child_keys: &[DependencyKey]) -> DependencyKey {
        fn encode_sort(hasher: &mut blake3::Hasher, sort: ExprSort) {
            match sort {
                ExprSort::BitVec(bits) => {
                    hasher.update(&[0]);
                    hasher.update(&bits.to_le_bytes());
                }
                ExprSort::Float {
                    exponent_bits,
                    significand_bits,
                } => {
                    hasher.update(&[1, exponent_bits, significand_bits]);
                }
                ExprSort::Bool => {
                    hasher.update(&[2]);
                }
                ExprSort::Vector { lanes, lane_bits } => {
                    hasher.update(&[3]);
                    hasher.update(&lanes.to_le_bytes());
                    hasher.update(&lane_bits.to_le_bytes());
                }
                ExprSort::Opmask(bits) => {
                    hasher.update(&[4]);
                    hasher.update(&bits.to_le_bytes());
                }
                ExprSort::Tile {
                    rows,
                    bytes_per_row,
                    element_bits,
                } => {
                    hasher.update(&[5, rows]);
                    hasher.update(&bytes_per_row.to_le_bytes());
                    hasher.update(&element_bits.to_le_bytes());
                }
            }
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"ANGRYIER\0EXPR\0");
        hasher.update(&version.to_le_bytes());
        encode_sort(&mut hasher, node.sort);
        hasher.update(&[node.op as u8]);
        hasher.update(&(node.immediate.len() as u64).to_le_bytes());
        hasher.update(&node.immediate);
        hasher.update(&(child_keys.len() as u64).to_le_bytes());
        for key in child_keys {
            hasher.update(&key.0);
        }
        DependencyKey(*hasher.finalize().as_bytes())
    }

    #[test]
    fn dependency_key_recipe_is_bit_identical() -> Result<(), ExprArenaError> {
        let version = ExpressionNormalizationVersion(7);
        let arena = ShardedExprArena::new(version);

        // Leaf: symbol node (immediate feeds both key and symbolic sources).
        let sym_node = symbol(0xABCD);
        let sym_id = arena.intern(sym_node.clone())?;
        assert_eq!(
            arena.dependency_summary(sym_id).map(|summary| summary.key),
            Some(expected_key(version.0, &sym_node, &[]))
        );

        // Binary: add over two symbols.
        let left = arena.intern(symbol(10))?;
        let right = arena.intern(symbol(20))?;
        let add_node = ExprNode {
            sort: ExprSort::BitVec(64),
            op: ExprOp::Add,
            operands: vec![left, right],
            immediate: Vec::new(),
        };
        let add_id = arena.intern(add_node.clone())?;
        let child_keys = [
            arena.dependency_summary(left).map(|s| s.key),
            arena.dependency_summary(right).map(|s| s.key),
        ];
        assert_eq!(
            arena.dependency_summary(add_id).map(|summary| summary.key),
            Some(expected_key(
                version.0,
                &add_node,
                &[
                    child_keys[0].ok_or(ExprArenaError::UnknownOperand(left))?,
                    child_keys[1].ok_or(ExprArenaError::UnknownOperand(right))?,
                ]
            ))
        );

        // Immediate-carrying op: extract over the add.
        let extract_node = ExprNode {
            sort: ExprSort::BitVec(8),
            op: ExprOp::Extract,
            operands: vec![add_id],
            immediate: vec![4, 0, 8, 0],
        };
        let extract_id = arena.intern(extract_node.clone())?;
        assert_eq!(
            arena.dependency_summary(extract_id).map(|summary| summary.key),
            Some(expected_key(
                version.0,
                &extract_node,
                &[arena
                    .dependency_summary(add_id)
                    .map(|s| s.key)
                    .ok_or(ExprArenaError::UnknownOperand(add_id))?]
            ))
        );
        Ok(())
    }

    #[test]
    fn hash_cons_hits_serve_the_stored_dependency_key() -> Result<(), ExprArenaError> {
        // The hit path must return the id whose stored dependency key was
        // computed once at insertion — no re-hash, same value.
        let miss_arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let hit_arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));

        let node = ExprNode {
            sort: ExprSort::BitVec(64),
            op: ExprOp::Xor,
            operands: vec![miss_arena.intern(symbol(5))?, miss_arena.intern(symbol(6))?],
            immediate: Vec::new(),
        };
        let miss_id = miss_arena.intern(node.clone())?;
        let expected = miss_arena
            .dependency_summary(miss_id)
            .map(|summary| summary.key)
            .ok_or(ExprArenaError::UnknownOperand(miss_id))?;

        let hit_left = hit_arena.intern(symbol(5))?;
        let hit_right = hit_arena.intern(symbol(6))?;
        let hit_node = ExprNode {
            sort: ExprSort::BitVec(64),
            op: ExprOp::Xor,
            operands: vec![hit_left, hit_right],
            immediate: Vec::new(),
        };
        let first = hit_arena.intern(hit_node.clone())?;
        let second = hit_arena.intern(hit_node)?; // hash-cons hit
        assert_eq!(first, second);
        assert_eq!(hit_arena.stats().intern_hits, 1);
        assert_eq!(
            hit_arena.dependency_summary(second).map(|s| s.key),
            Some(expected),
            "hit path must serve the stored (insertion-time) dependency key"
        );
        Ok(())
    }

    #[test]
    fn lightweight_probes_match_full_get() -> Result<(), ExprArenaError> {
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let left = arena.intern(symbol(1))?;
        let eq_id = arena.intern(ExprNode {
            sort: ExprSort::Bool,
            op: ExprOp::Eq,
            operands: vec![left, left],
            immediate: Vec::new(),
        })?;

        assert_eq!(arena.sort_of(left), Some(ExprSort::BitVec(64)));
        assert_eq!(arena.op_of(left), Some(ExprOp::Symbol));
        assert_eq!(arena.sort_of(eq_id), Some(ExprSort::Bool));
        assert_eq!(arena.op_of(eq_id), Some(ExprOp::Eq));
        assert_eq!(arena.sort_of(ExprId(u32::MAX)), None);
        assert_eq!(arena.op_of(ExprId(u32::MAX)), None);
        // Trait-object path uses the probes too.
        let dynamic: &dyn ExprArena<Error = ExprArenaError> = &arena;
        assert_eq!(dynamic.sort_of(eq_id), Some(ExprSort::Bool));
        assert_eq!(dynamic.op_of(eq_id), Some(ExprOp::Eq));
        Ok(())
    }

    #[test]
    fn sort_mismatch_errors_survive_the_hit_probe() -> Result<(), ExprArenaError> {
        // A node with bad sorts can never be in the hash-cons table (it is
        // rejected before insertion), so the pre-hash probe must not swallow
        // the error — it still surfaces from the dependency build.
        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let bits = arena.intern(symbol(1))?;
        let boolean = arena.intern(ExprNode {
            sort: ExprSort::Bool,
            op: ExprOp::Constant,
            operands: Vec::new(),
            immediate: vec![1],
        })?;

        assert_eq!(
            arena.intern(ExprNode {
                sort: ExprSort::BitVec(64),
                op: ExprOp::Add,
                operands: vec![bits, boolean],
                immediate: Vec::new(),
            }),
            Err(ExprArenaError::SortMismatch(ExprOp::Add))
        );
        Ok(())
    }
}
