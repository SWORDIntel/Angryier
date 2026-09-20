//! Fuzzy-SAT: a mutation-based approximate solver tier for the EXPLORE/HUNT
//! concolic path.
//!
//! Simple branch constraints — `x == C`, `x < C`, `x != C`, and shallow
//! conjunctions over a few symbols — dominate concolic path exploration. A
//! full SMT invocation pays setup and translation costs for queries a targeted
//! evaluation loop answers in microseconds. This backend evaluates the query
//! expression directly against candidate assignments: comparison constants
//! seed the candidates (so `x == C` resolves in one probe), then a
//! deterministic mutation loop perturbs them. Shapes outside its envelope
//! (many symbols, very deep expressions) return `Unknown` so the portfolio
//! router falls back to a real SMT backend.
//!
//! Fuzzy-SAT is explicitly unsound-by-design for EXPLORE/HUNT: an `Unknown`
//! never proves unsatisfiability — it means "not cheaply solvable", and the
//! caller must route onward when it needs a guarantee.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use angryier_expr::{ExprNode, ExprOp, ExprReader, ExprSort};
use angryier_solver::{SolverBackend, SolverQuery, SolverResult};
use angryier_types::{ConstraintId, ExprId, SolverOutcomeKind};

/// Maximum distinct input symbols a query may use before Fuzzy-SAT declines.
const MAX_SYMBOLS: usize = 32;
/// Maximum expression nodes visited before Fuzzy-SAT declines.
const MAX_NODES: usize = 512;
/// Default candidate/mutation budget per query.
const DEFAULT_BUDGET: usize = 4_096;

/// A mutation-based [`SolverBackend`] for simple concolic constraints.
pub struct FuzzySatBackend {
    reader: Arc<dyn ExprReader>,
    budget: usize,
}

impl FuzzySatBackend {
    /// Creates a backend reading expressions through `reader`.
    pub fn new(reader: Arc<dyn ExprReader>) -> Self {
        Self {
            reader,
            budget: DEFAULT_BUDGET,
        }
    }

    /// Overrides the candidate/mutation budget.
    pub fn with_budget(mut self, budget: usize) -> Self {
        self.budget = budget;
        self
    }

    /// Collects every symbol expression reachable from `root` plus the seed
    /// constants appearing in comparisons with those symbols. Returns `None`
    /// when the query exceeds the fuzzy envelope.
    fn gather(&self, root: ExprId, symbols: &mut Vec<ExprId>, seeds: &mut Vec<u128>) -> Option<()> {
        let mut stack = vec![root];
        let mut visited = 0usize;
        while let Some(id) = stack.pop() {
            visited += 1;
            if visited > MAX_NODES || symbols.len() > MAX_SYMBOLS {
                return None;
            }
            let node = self.reader.read(id)?;
            match node.op {
                ExprOp::Symbol => {
                    if !symbols.contains(&id) {
                        symbols.push(id);
                    }
                }
                ExprOp::Constant => {
                    if let Some(value) = constant_bits(&node) {
                        seeds.push(value);
                    }
                }
                _ => stack.extend(node.operands.iter().copied()),
            }
        }
        Some(())
    }

    /// Evaluates `id` under `env`: `Some(value)` for full evaluation, `None`
    /// when the expression is malformed or exceeds the node budget.
    fn eval(&self, id: ExprId, env: &BTreeMap<ExprId, u128>, budget: &mut usize) -> Option<u128> {
        if *budget == 0 {
            return None;
        }
        *budget -= 1;
        let node = self.reader.read(id)?;
        let width = sort_width(&node);
        let mask = mask_for(width);
        let operand = |index: usize, env: &BTreeMap<ExprId, u128>, budget: &mut usize| -> Option<u128> {
            let child = *node.operands.get(index)?;
            self.eval(child, env, budget)
        };
        let value = match node.op {
            ExprOp::Constant => constant_bits(&node)?,
            ExprOp::Symbol => env.get(&id).copied().unwrap_or(0),
            ExprOp::Add => operand(0, env, budget)?.wrapping_add(operand(1, env, budget)?),
            ExprOp::Sub => operand(0, env, budget)?.wrapping_sub(operand(1, env, budget)?),
            ExprOp::Mul => operand(0, env, budget)?.wrapping_mul(operand(1, env, budget)?),
            ExprOp::UDiv => operand(0, env, budget)?.checked_div(operand(1, env, budget)?).unwrap_or(0),
            ExprOp::SDiv => {
                let divisor = operand(1, env, budget)? as i128;
                if divisor == 0 {
                    0
                } else {
                    (operand(0, env, budget)? as i128).wrapping_div(divisor) as u128
                }
            }
            ExprOp::And => operand(0, env, budget)? & operand(1, env, budget)?,
            ExprOp::Or => operand(0, env, budget)? | operand(1, env, budget)?,
            ExprOp::Xor => operand(0, env, budget)? ^ operand(1, env, budget)?,
            ExprOp::Not => !operand(0, env, budget)?,
            ExprOp::Shl => operand(0, env, budget)?.wrapping_shl(operand(1, env, budget)? as u32),
            ExprOp::LShr => operand(0, env, budget)?.wrapping_shr(operand(1, env, budget)? as u32),
            ExprOp::AShr => {
                let value = sign_extend(operand(0, env, budget)?, node_width(&node.operands[0], self));
                let shift = operand(1, env, budget)? as u32;
                (value.wrapping_shr(shift.min(127))) as u128
            }
            ExprOp::Eq => u128::from(
                operand(0, env, budget)? & operand_mask(0, &node, self)
                    == operand(1, env, budget)? & operand_mask(0, &node, self),
            ),
            ExprOp::Ult => u128::from(operand(0, env, budget)? < operand(1, env, budget)?),
            ExprOp::Ule => u128::from(operand(0, env, budget)? <= operand(1, env, budget)?),
            ExprOp::Slt => {
                let w = node_width(&node.operands[0], self);
                u128::from(sign_extend(operand(0, env, budget)?, w) < sign_extend(operand(1, env, budget)?, w))
            }
            ExprOp::Sle => {
                let w = node_width(&node.operands[0], self);
                u128::from(sign_extend(operand(0, env, budget)?, w) <= sign_extend(operand(1, env, budget)?, w))
            }
            ExprOp::Ite => {
                if operand(0, env, budget)? != 0 {
                    operand(1, env, budget)?
                } else {
                    operand(2, env, budget)?
                }
            }
            ExprOp::Concat => {
                let high = operand(0, env, budget)?;
                let low_width = node_width(&node.operands[1], self);
                let low = operand(1, env, budget)? & mask_for(low_width);
                (high << low_width) | low
            }
            ExprOp::Extract => {
                let start = immediate_u16(&node, 0)? as u128;
                let bits = immediate_u16(&node, 1)? as u128;
                (operand(0, env, budget)? >> start) & mask_for(bits as u16)
            }
            ExprOp::ZExt => operand(0, env, budget)?,
            ExprOp::SExt => {
                let input_width = node_width(&node.operands[0], self);
                let extended = sign_extend(operand(0, env, budget)?, input_width);
                extended as u128
            }
        };
        Some(value & mask)
    }

    /// Evaluates the full query: every constraint plus the predicate must hold.
    fn is_sat(&self, query: &SolverQuery, env: &BTreeMap<ExprId, u128>) -> bool {
        let mut budget = MAX_NODES * 4;
        query
            .constraint_expressions()
            .iter()
            .all(|(_, expr)| self.eval(*expr, env, &mut budget) == Some(1))
            && self.eval(query.predicate(), env, &mut budget) == Some(1)
    }
}

impl SolverBackend for FuzzySatBackend {
    fn name(&self) -> &'static str {
        "fuzzy-sat"
    }

    fn solve(&mut self, query: &SolverQuery) -> SolverResult {
        let started = Instant::now();
        let elapsed = || started.elapsed();
        let unknown = |elapsed: Duration| SolverResult {
            outcome: SolverOutcomeKind::Unknown,
            model: Vec::new(),
            unsat_core: Vec::new(),
            elapsed,
        };

        // Collect symbols and seed constants across predicate + constraints.
        let mut symbols = Vec::new();
        let mut seeds = vec![0u128, 1];
        if self.gather(query.predicate(), &mut symbols, &mut seeds).is_none() {
            return unknown(elapsed());
        }
        for (_, expr) in query.constraint_expressions() {
            if self.gather(*expr, &mut symbols, &mut seeds).is_none() {
                return unknown(elapsed());
            }
        }
        seeds.sort_unstable();
        seeds.dedup();

        // Zero-assignment fast path (the concrete trace itself).
        let mut env = BTreeMap::new();
        if self.is_sat(query, &env) {
            return unknown(elapsed()); // already satisfied; nothing to invert
        }

        // Candidate seeding: each symbol takes each seed value, then mutations
        // combine seeded symbols (xorshift over the iteration counter keeps it
        // deterministic and dependency-free).
        let mut rng = 0x9E3779B97F4A7C15u64;
        for iteration in 0..self.budget {
            env.clear();
            if iteration < symbols.len() * seeds.len() {
                // Systematic pass: one symbol gets a seed, rest stay zero.
                let symbol = symbols[iteration / seeds.len()];
                let seed = seeds[iteration % seeds.len()];
                env.insert(symbol, seed);
            } else {
                // Mutation pass: perturb a seed across all symbols.
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                for (index, symbol) in symbols.iter().enumerate() {
                    let seed = seeds[rng as usize % seeds.len()];
                    env.insert(*symbol, seed.wrapping_add(u128::from(rng.wrapping_shr(index as u32))));
                }
            }
            if self.is_sat(query, &env) {
                let model = env
                    .iter()
                    .map(|(expression, value)| (u64::from(expression.0), value.to_le_bytes().to_vec()))
                    .collect();
                return SolverResult {
                    outcome: SolverOutcomeKind::Sat,
                    model,
                    unsat_core: Vec::new(),
                    elapsed: elapsed(),
                };
            }
        }
        unknown(elapsed())
    }

    fn solve_batch(&mut self, _shared: &[ConstraintId], predicates: &[SolverQuery]) -> Vec<SolverResult> {
        predicates.iter().map(|query| self.solve(query)).collect()
    }
}

/// Bit width of a node (bitvector sort width; booleans count as 1).
fn sort_width(node: &ExprNode) -> u16 {
    match node.sort {
        ExprSort::BitVec(width) => width,
        // Booleans evaluate as 0/1; non-scalar sorts are outside the fuzzy
        // envelope and report a nominal 64 bits (they are never constructed
        // by the concolic shadow today).
        _ => 64,
    }
}

/// Bit width of a child expression, or 64 when unreadable.
fn node_width(id: &ExprId, backend: &FuzzySatBackend) -> u16 {
    backend.reader.read(*id).map(|node| sort_width(&node)).unwrap_or(64)
}

/// Mask over the compared operand width for Eq nodes (operand 0's width).
fn operand_mask(_index: usize, node: &ExprNode, _backend: &FuzzySatBackend) -> u128 {
    let _ = node;
    u128::MAX // operands are already masked to their own width by eval
}

/// The constant payload of a `Constant` node as an integer.
fn constant_bits(node: &ExprNode) -> Option<u128> {
    let mut value = 0u128;
    for (index, byte) in node.immediate.iter().enumerate().take(16) {
        value |= u128::from(*byte) << (8 * index);
    }
    Some(value & mask_for(sort_width(node)))
}

/// Little-endian u16 read of `immediate` at `index * 2`.
fn immediate_u16(node: &ExprNode, index: usize) -> Option<u16> {
    let lo = *node.immediate.get(index * 2)?;
    let hi = *node.immediate.get(index * 2 + 1)?;
    Some(u16::from_le_bytes([lo, hi]))
}

fn mask_for(width: u16) -> u128 {
    if width >= 128 { u128::MAX } else { (1u128 << width) - 1 }
}

/// Sign-extends a `width`-bit value to i128.
fn sign_extend(value: u128, width: u16) -> i128 {
    let value = value & mask_for(width);
    if width == 0 || width >= 128 {
        return value as i128;
    }
    let sign = 1u128 << (width - 1);
    if value & sign != 0 {
        (value | !mask_for(width)) as i128
    } else {
        value as i128
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_expr::ShardedExprArena;
    use angryier_solver::{CanonicalConstraint, SolverQuery};
    use angryier_types::{
        ConstraintCanonicalizationVersion, DependencyKey, ExpressionNormalizationVersion, SolverQueryId,
        TargetProfileId,
    };
    use core::time::Duration;

    fn setup() -> (Arc<ShardedExprArena>, FuzzySatBackend) {
        let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
        let backend = FuzzySatBackend::new(arena.clone());
        (arena, backend)
    }

    fn symbol(arena: &ShardedExprArena, id: u64, width: u16) -> ExprId {
        arena
            .intern(ExprNode {
                sort: ExprSort::BitVec(width),
                op: ExprOp::Symbol,
                operands: Vec::new(),
                immediate: id.to_le_bytes().to_vec(),
            })
            .expect("intern")
    }

    fn constant(arena: &ShardedExprArena, width: u16, value: u64) -> ExprId {
        let byte_count = usize::from(width).div_ceil(8);
        let mut bytes = value.to_le_bytes().to_vec();
        bytes.resize(byte_count, 0);
        arena
            .intern(ExprNode {
                sort: ExprSort::BitVec(width),
                op: ExprOp::Constant,
                operands: Vec::new(),
                immediate: bytes,
            })
            .expect("intern")
    }

    fn eq(arena: &ShardedExprArena, left: ExprId, right: ExprId) -> ExprId {
        arena
            .intern(ExprNode {
                sort: ExprSort::Bool,
                op: ExprOp::Eq,
                operands: vec![left, right],
                immediate: Vec::new(),
            })
            .expect("intern")
    }

    fn query(_arena: &ShardedExprArena, predicate: ExprId) -> SolverQuery {
        let key = DependencyKey([7; 32]);
        SolverQuery::canonical(
            SolverQueryId(1),
            &[],
            predicate,
            key,
            TargetProfileId(1),
            ConstraintCanonicalizationVersion(1),
            Duration::from_secs(5),
        )
        .expect("query")
        // The canonical identity check is bypassed in tests by construction.
    }

    use angryier_expr::ExprArena;

    #[test]
    fn solves_equality_constraint() {
        let (arena, mut backend) = setup();
        let x = symbol(&arena, 0, 64);
        let c42 = constant(&arena, 64, 42);
        let predicate = eq(&arena, x, c42);
        let result = backend.solve(&query(&arena, predicate));
        assert_eq!(result.outcome, SolverOutcomeKind::Sat);
        assert!(!result.model.is_empty());
    }

    #[test]
    fn solves_comparison_with_constraint() {
        let (arena, mut backend) = setup();
        let x = symbol(&arena, 0, 64);
        let c10 = constant(&arena, 64, 10);
        let lt = arena
            .intern(ExprNode {
                sort: ExprSort::Bool,
                op: ExprOp::Ult,
                operands: vec![x, c10],
                immediate: Vec::new(),
            })
            .expect("intern");
        // Constraint: x == 5 (keeps the model on-path); predicate: x < 10.
        let c5 = constant(&arena, 64, 5);
        let constraint_expr = eq(&arena, x, c5);
        let constraint = CanonicalConstraint {
            id: ConstraintId(0),
            key: DependencyKey([1; 32]),
            expr: constraint_expr,
        };
        let q = SolverQuery::canonical(
            SolverQueryId(2),
            &[constraint],
            lt,
            DependencyKey([9; 32]),
            TargetProfileId(1),
            ConstraintCanonicalizationVersion(1),
            Duration::from_secs(5),
        )
        .expect("query");
        let result = backend.solve(&q);
        assert_eq!(result.outcome, SolverOutcomeKind::Sat);
    }
}
