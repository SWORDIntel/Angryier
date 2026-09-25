//! Alpha-equivalence query reuse (Gate C experiment).
//!
//! Exact canonical-query reuse is proven on real execution traces: slicing
//! makes the canonical key identical across inputs reaching the same branch.
//! This module adds the next tier — reuse across *alpha-equivalent* queries:
//! queries whose constraint/predicate structure is identical modulo a
//! consistent renaming of symbols. Alpha-equivalence preserves Sat/Unsat
//! (symbols are free variables; a bijective renaming is satisfiability
//! preserving), so an alpha hit may answer a query without re-solving.
//!
//! Because a hash collision or a normalization bug could conflate logically
//! distinct queries (poisoning), the tier ships as a validated experiment:
//! the cache's alpha index only *proposes* candidates, and every proposal is
//! confirmed by an exact backend solve before it is trusted
//! (`AlphaReuseConfig::suppress_without_confirmation` defaults to `false`).
//! Confirmations and contradictions are counted so the tier can be evaluated
//! on real workloads before suppression is ever enabled.
//!
//! Normalization is a two-pass de-Bruijn-style canonicalization:
//! 1. a symbol-blind structural digest per node, used to order the operands
//!    of commutative operations (Add/Mul/And/Or/Xor/Eq) and to order the
//!    constraint multiset;
//! 2. a full walk assigning each symbol a global first-occurrence index and
//!    emitting op/sort/immediate/operand structure to a byte stream, which
//!    is hashed into the [`AlphaKey`].
//!
//! Known incompleteness (missed reuse, never false reuse): first-occurrence
//! index assignment cannot canonicalize symbol permutations that only differ
//! across tied-digest siblings, and constraint ties broken by expression id
//! can order differently across arenas. Both cases yield distinct keys for
//! alpha-equivalent queries — a missed cache hit, not a wrong answer.

use crate::SolverQuery;
use angryier_expr::{ExprOp, ExprReader, ExprSort};
use angryier_types::{ConstraintId, ExprId};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};

/// Alpha-normalized query fingerprint: equal keys mean the queries are
/// structurally identical modulo consistent symbol renaming (up to SHA-256
/// collision, which the confirmation tier is designed to catch).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AlphaKey(pub [u8; 32]);

/// Configuration of the alpha-equivalence reuse experiment.
///
/// Gate C discipline: exact canonical-query reuse is proven on real traces,
/// so the alpha tier may be *built and validated*, but reuse that suppresses
/// solver work without confirmation stays disabled by default.
///
/// - `enabled` gates all alpha machinery (indexing, proposals,
///   confirmation). Default `false`: the cache behaves exactly as the
///   exact-reuse-only cache.
/// - `suppress_without_confirmation` — EXPERIMENTAL, DEFAULT OFF — lets an
///   alpha hit answer a query WITHOUT a confirming exact solve (outcome
///   only; the model and unsat core are not reused across renamings).
///   Enable only after the confirmation/contradiction counters have been
///   validated on your workload: a poisoned alpha index then answers
///   without a safety net.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AlphaReuseConfig {
    pub enabled: bool,
    pub suppress_without_confirmation: bool,
}

/// Observable state of the alpha tier: how often the alpha index was
/// consulted (`proposals`), how many proposals an exact confirmatory solve
/// agreed with (`confirmations`) or disagreed with (`contradictions` — each
/// one is a would-be poisoning had suppression been on), and how many
/// queries were answered without a solve while suppression was enabled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AlphaReuseStats {
    pub proposals: u64,
    pub confirmations: u64,
    pub contradictions: u64,
    pub suppressed_reuses: u64,
    pub indexed_buckets: u64,
    pub indexed_candidates: u64,
}

/// Computes the alpha key of `query`, reading expression structure through
/// `reader`. Returns `None` (fail closed: no alpha reuse) when any referenced
/// expression is unreadable.
pub fn alpha_key(reader: &dyn ExprReader, query: &SolverQuery) -> Option<AlphaKey> {
    let mut digests: HashMap<ExprId, [u8; 32]> = HashMap::new();
    let mut constraints: Vec<(ExprId, ConstraintId)> = Vec::new();
    let mut seen_exprs: HashSet<ExprId> = HashSet::new();
    for (constraint_id, expr) in query.constraint_expressions() {
        shape_digest(reader, *expr, &mut digests)?;
        // Duplicate constraint expressions are idempotent assertions; the
        // exact key dedups identical dependency keys the same way.
        if seen_exprs.insert(*expr) {
            constraints.push((*expr, *constraint_id));
        }
    }
    let predicate = query.predicate();
    shape_digest(reader, predicate, &mut digests)?;

    // Deterministic constraint order: conjunction is order-insensitive, so
    // sorting by structural digest maximizes matching; ties fall back to
    // expression id (stable within an arena, possibly ordering differently
    // across arenas — a missed hit, never a false one).
    constraints.sort_by(|(left_expr, left_id), (right_expr, right_id)| {
        let left = digests.get(left_expr).copied().unwrap_or([0; 32]);
        let right = digests.get(right_expr).copied().unwrap_or([0; 32]);
        left.cmp(&right)
            .then(left_expr.0.cmp(&right_expr.0))
            .then(left_id.0.cmp(&right_id.0))
    });

    let mut symbols: HashMap<ExprId, u32> = HashMap::new();
    let mut encoded: Vec<u8> = Vec::new();
    for (expr, _) in &constraints {
        emit_alpha(reader, *expr, &mut symbols, &mut encoded)?;
    }
    emit_alpha(reader, predicate, &mut symbols, &mut encoded)?;

    let mut hasher = Sha256::new();
    hasher.update(b"ANGRYIER\0ALPHA-QUERY\0");
    hasher.update(query.canonicalization_version().0.to_le_bytes());
    hasher.update(query.target_profile().0.to_le_bytes());
    hasher.update((constraints.len() as u64).to_le_bytes());
    hasher.update(&encoded);
    Some(AlphaKey(hasher.finalize().into()))
}

/// Commutative operations whose operands are canonically ordered by digest.
fn is_commutative(op: ExprOp) -> bool {
    matches!(
        op,
        ExprOp::Add | ExprOp::Mul | ExprOp::And | ExprOp::Or | ExprOp::Xor | ExprOp::Eq
    )
}

/// Stable per-variant operation tag (never reuse values across variants).
fn op_code(op: ExprOp) -> u8 {
    match op {
        ExprOp::Constant => 1,
        ExprOp::Symbol => 2,
        ExprOp::Add => 3,
        ExprOp::Sub => 4,
        ExprOp::Mul => 5,
        ExprOp::UDiv => 6,
        ExprOp::SDiv => 7,
        ExprOp::And => 8,
        ExprOp::Or => 9,
        ExprOp::Xor => 10,
        ExprOp::Not => 11,
        ExprOp::Shl => 12,
        ExprOp::LShr => 13,
        ExprOp::AShr => 14,
        ExprOp::Eq => 15,
        ExprOp::Ult => 16,
        ExprOp::Ule => 17,
        ExprOp::Slt => 18,
        ExprOp::Sle => 19,
        ExprOp::Ite => 20,
        ExprOp::Concat => 21,
        ExprOp::Extract => 22,
        ExprOp::ZExt => 23,
        ExprOp::SExt => 24,
    }
}

fn encode_sort(sort: &ExprSort, out: &mut Vec<u8>) {
    match sort {
        ExprSort::BitVec(width) => {
            out.push(1);
            out.extend_from_slice(&width.to_le_bytes());
        }
        ExprSort::Float {
            exponent_bits,
            significand_bits,
        } => {
            out.push(2);
            out.push(*exponent_bits);
            out.push(*significand_bits);
        }
        ExprSort::Bool => out.push(3),
        ExprSort::Vector { lanes, lane_bits } => {
            out.push(4);
            out.extend_from_slice(&lanes.to_le_bytes());
            out.extend_from_slice(&lane_bits.to_le_bytes());
        }
        ExprSort::Opmask(width) => {
            out.push(5);
            out.extend_from_slice(&width.to_le_bytes());
        }
        ExprSort::Tile {
            rows,
            bytes_per_row,
            element_bits,
        } => {
            out.push(6);
            out.push(*rows);
            out.extend_from_slice(&bytes_per_row.to_le_bytes());
            out.extend_from_slice(&element_bits.to_le_bytes());
        }
    }
}

/// Pass 1: symbol-blind structural digest with commutative operand
/// multiset ordering. Symbols all digest identically (renaming-invariant);
/// immediates, ops, sorts and operand multiplicity are preserved.
fn shape_digest(reader: &dyn ExprReader, id: ExprId, memo: &mut HashMap<ExprId, [u8; 32]>) -> Option<[u8; 32]> {
    if let Some(digest) = memo.get(&id) {
        return Some(*digest);
    }
    let node = reader.read(id)?;
    let mut children: Vec<[u8; 32]> = Vec::with_capacity(node.operands.len());
    for operand in &node.operands {
        children.push(shape_digest(reader, *operand, memo)?);
    }
    if is_commutative(node.op) {
        children.sort_unstable();
    }
    let mut hasher = Sha256::new();
    hasher.update([op_code(node.op)]);
    let mut sort_bytes = Vec::new();
    encode_sort(&node.sort, &mut sort_bytes);
    hasher.update(sort_bytes);
    if node.op != ExprOp::Symbol {
        // Symbol immediates are the names being abstracted away: all
        // same-sort symbols must digest identically, or commutative operand
        // ordering would depend on the very names normalization removes.
        hasher.update((node.immediate.len() as u32).to_le_bytes());
        hasher.update(&node.immediate);
    }
    hasher.update((children.len() as u32).to_le_bytes());
    for digest in children {
        hasher.update(digest);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    memo.insert(id, digest);
    Some(digest)
}

/// Pass 2: emit the renaming-invariant encoding for the subtree at `id`.
/// Symbols become first-occurrence indices assigned globally across the
/// whole query walk (constraints in canonical order, then the predicate), so
/// one symbol shared by several constraints keeps one index.
///
/// Commutative operands are emitted as a sorted multiset of per-operand
/// encodings: sorting the operand buffers presents the multiset
/// canonically, absorbing the symbol-index permutations that a renaming
/// induces (e.g. `x*y` vs `y*x` emit identical bytes). Non-commutative
/// operands keep their order, which is part of the structure.
fn emit_alpha(
    reader: &dyn ExprReader,
    id: ExprId,
    symbols: &mut HashMap<ExprId, u32>,
    out: &mut Vec<u8>,
) -> Option<()> {
    let node = reader.read(id)?;
    out.push(op_code(node.op));
    encode_sort(&node.sort, out);
    if node.op == ExprOp::Symbol {
        // The renaming point: symbol identity becomes an index; the symbol's
        // own payload (immediate) is deliberately not encoded.
        let next = symbols.len() as u32;
        let index = *symbols.entry(id).or_insert(next);
        out.extend_from_slice(&index.to_le_bytes());
        return Some(());
    }
    out.extend_from_slice(&(node.immediate.len() as u32).to_le_bytes());
    out.extend_from_slice(&node.immediate);
    out.extend_from_slice(&(node.operands.len() as u32).to_le_bytes());
    if is_commutative(node.op) {
        let mut buffers: Vec<Vec<u8>> = Vec::with_capacity(node.operands.len());
        for operand in &node.operands {
            let mut buffer = Vec::new();
            emit_alpha(reader, *operand, symbols, &mut buffer)?;
            buffers.push(buffer);
        }
        buffers.sort_unstable();
        for buffer in buffers {
            out.extend(buffer);
        }
    } else {
        for operand in &node.operands {
            emit_alpha(reader, *operand, symbols, out)?;
        }
    }
    Some(())
}
