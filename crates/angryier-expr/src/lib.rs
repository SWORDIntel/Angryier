#![forbid(unsafe_code)]

use angryier_types::{DependencyKey, ExprId, ExpressionNormalizationVersion};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashMap},
    sync::{
        RwLock,
        atomic::{AtomicU64, Ordering},
    },
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
    by_node: HashMap<ExprNode, ExprId>,
    records: Vec<ExprRecord>,
}

pub struct ShardedExprArena {
    version: ExpressionNormalizationVersion,
    shards: [RwLock<ArenaShard>; SHARD_COUNT],
    requests: AtomicU64,
    hits: AtomicU64,
    nodes: AtomicU64,
}

impl ShardedExprArena {
    pub fn new(version: ExpressionNormalizationVersion) -> Self {
        Self {
            version,
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

    fn build_dependency(&self, node: &ExprNode) -> Result<DependencySummary, ExprArenaError> {
        let mut sources = BTreeSet::new();
        let mut child_keys = Vec::with_capacity(node.operands.len());
        let mut child_sorts = Vec::with_capacity(node.operands.len());
        for operand in &node.operands {
            let record = self.record(*operand)?;
            sources.extend(record.dependency.symbolic_sources);
            child_keys.push(record.dependency.key);
            child_sorts.push(record.node.sort);
        }
        validate_sorts(node, &child_sorts)?;
        if node.op == ExprOp::Symbol {
            let bytes: [u8; 8] = node
                .immediate
                .as_slice()
                .try_into()
                .map_err(|_| ExprArenaError::InvalidImmediate)?;
            sources.insert(u64::from_le_bytes(bytes));
        }

        let mut hasher = Sha256::new();
        hasher.update(b"ANGRYIER\0EXPR\0");
        hasher.update(self.version.0.to_le_bytes());
        encode_sort(&mut hasher, node.sort);
        hasher.update([op_tag(node.op)]);
        hasher.update((node.immediate.len() as u64).to_le_bytes());
        hasher.update(&node.immediate);
        hasher.update((child_keys.len() as u64).to_le_bytes());
        for key in child_keys {
            hasher.update(key.0);
        }
        Ok(DependencySummary {
            key: DependencyKey(hasher.finalize().into()),
            symbolic_sources: sources.into_iter().collect(),
        })
    }

    fn fold_constants(&self, node: ExprNode) -> Result<ExprNode, ExprArenaError> {
        if node.operands.is_empty() {
            return Ok(node);
        }
        let records: Vec<_> = node
            .operands
            .iter()
            .copied()
            .map(|operand| self.record(operand))
            .collect::<Result<_, _>>()?;
        let sorts: Vec<_> = records.iter().map(|record| record.node.sort).collect();
        validate_sorts(&node, &sorts)?;
        if records.iter().any(|record| record.node.op != ExprOp::Constant) {
            return Ok(node);
        }

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
            ExprOp::Eq => ExprNode {
                sort: ExprSort::Bool,
                op: ExprOp::Constant,
                operands: Vec::new(),
                immediate: vec![u8::from(records[0].node == records[1].node)],
            },
            ExprOp::Ite => {
                if records[0].node.immediate == [0] {
                    records[2].node.clone()
                } else {
                    records[1].node.clone()
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
        let dependency = self.build_dependency(&node)?;
        let shard_index = usize::from(dependency.key.0[0]) % SHARD_COUNT;
        let mut shard = self.shards[shard_index]
            .write()
            .map_err(|_| ExprArenaError::LockPoisoned)?;
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

fn encode_sort(hasher: &mut Sha256, sort: ExprSort) {
    match sort {
        ExprSort::BitVec(bits) => {
            hasher.update([0]);
            hasher.update(bits.to_le_bytes());
        }
        ExprSort::Float {
            exponent_bits,
            significand_bits,
        } => {
            hasher.update([1, exponent_bits, significand_bits]);
        }
        ExprSort::Bool => hasher.update([2]),
        ExprSort::Vector { lanes, lane_bits } => {
            hasher.update([3]);
            hasher.update(lanes.to_le_bytes());
            hasher.update(lane_bits.to_le_bytes());
        }
        ExprSort::Opmask(bits) => {
            hasher.update([4]);
            hasher.update(bits.to_le_bytes());
        }
        ExprSort::Tile {
            rows,
            bytes_per_row,
            element_bits,
        } => {
            hasher.update([5, rows]);
            hasher.update(bytes_per_row.to_le_bytes());
            hasher.update(element_bits.to_le_bytes());
        }
    }
}

fn op_tag(op: ExprOp) -> u8 {
    op as u8
}

fn constant_u128(bytes: &[u8]) -> u128 {
    let mut widened = [0_u8; 16];
    widened[..bytes.len()].copy_from_slice(bytes);
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
}
