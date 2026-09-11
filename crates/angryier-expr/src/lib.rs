#![forbid(unsafe_code)]

use angryier_types::{DependencyKey, ExprId, ExpressionNormalizationVersion};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, HashMap},
    sync::{
        Mutex,
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
    shards: [Mutex<ArenaShard>; SHARD_COUNT],
    requests: AtomicU64,
    hits: AtomicU64,
    nodes: AtomicU64,
}

impl ShardedExprArena {
    pub fn new(version: ExpressionNormalizationVersion) -> Self {
        Self {
            version,
            shards: std::array::from_fn(|_| Mutex::new(ArenaShard::default())),
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
        let shard = self.shards[shard].lock().map_err(|_| ExprArenaError::LockPoisoned)?;
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
            .lock()
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
}
