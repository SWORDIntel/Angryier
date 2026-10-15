//! Output-rooted symbolic reduction for virtual-machine handler effects.
//!
//! Handler execution contains large amounts of interpreter-only arithmetic.
//! Instead of retaining every intermediate expression, a caller supplies all
//! externally observable effects and any guards that determine whether those
//! effects execute. This module slices backwards from those roots and applies
//! the existing, width-aware deobfuscator.
//!
//! This is *not* automatic side-effect discovery or a proof that two handler
//! programs are equivalent. Omitting an observable effect is a caller error;
//! memory writes retain both their symbolic address and value, in order.
//! No SMT assertions are discarded, and failures never silently truncate a
//! dependency DAG.

use std::collections::BTreeSet;

use angryier_types::ExprId;

use crate::ExprArena;
use crate::deobf::deobfuscate;

/// A VM state update the caller has established as observable. An ordered
/// list of writes must not be deduplicated: aliasing memory stores may matter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmEffectKind {
    Register { register: u32 },
    Flags,
    VirtualPc,
    DispatchTarget,
    Memory { address: ExprId, bytes: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmEffect {
    pub kind: VmEffectKind,
    pub value: ExprId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmReducedEffects {
    /// The caller's effect order is preserved exactly.
    pub effects: Vec<VmEffect>,
    pub guards: Vec<ExprId>,
    /// Reachable unique nodes from all original observable roots.
    pub original_nodes: usize,
    /// Reachable unique nodes after width-aware algebraic simplification.
    pub reduced_nodes: usize,
    pub symbolic_sources: Vec<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmReductionError {
    NoObservableRoots,
    UnknownExpression { id: ExprId },
    NodeBudgetExceeded { limit: usize },
}

/// Collect the exact backward dependency slice with no recursion. In addition
/// to the value expression, symbolic memory *addresses* are required roots.
/// A missing DAG node or exhausted budget aborts the whole reduction.
fn slice_roots<A: ExprArena + ?Sized>(
    arena: &A,
    roots: impl IntoIterator<Item = ExprId>,
    max_nodes: usize,
) -> Result<BTreeSet<ExprId>, VmReductionError> {
    let mut pending: Vec<ExprId> = roots.into_iter().collect();
    let mut visited = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if visited.contains(&id) {
            continue;
        }
        if visited.len() >= max_nodes {
            return Err(VmReductionError::NodeBudgetExceeded { limit: max_nodes });
        }
        let node = arena.get(id).ok_or(VmReductionError::UnknownExpression { id })?;
        visited.insert(id);
        pending.extend(node.operands);
    }
    Ok(visited)
}

fn effect_roots(effects: &[VmEffect], guards: &[ExprId]) -> Vec<ExprId> {
    let mut roots = Vec::with_capacity(effects.len().saturating_mul(2).saturating_add(guards.len()));
    roots.extend_from_slice(guards);
    for effect in effects {
        roots.push(effect.value);
        if let VmEffectKind::Memory { address, .. } = effect.kind {
            roots.push(address);
        }
    }
    roots
}

/// Simplify precisely the caller-declared effects and path guards. The
/// preflight walk enforces the budget *before* expensive simplification.
/// The output still needs independent semantic-equivalence validation.
pub fn reduce_vm_effects<A: ExprArena + ?Sized>(
    arena: &A,
    effects: &[VmEffect],
    guards: &[ExprId],
    max_nodes: usize,
) -> Result<VmReducedEffects, VmReductionError> {
    if effects.is_empty() && guards.is_empty() {
        return Err(VmReductionError::NoObservableRoots);
    }
    let before = slice_roots(arena, effect_roots(effects, guards), max_nodes)?;

    let reduced_effects: Vec<VmEffect> = effects
        .iter()
        .map(|effect| VmEffect {
            kind: match effect.kind {
                VmEffectKind::Memory { address, bytes } => VmEffectKind::Memory {
                    address: deobfuscate(arena, address),
                    bytes,
                },
                other => other,
            },
            value: deobfuscate(arena, effect.value),
        })
        .collect();
    let reduced_guards: Vec<ExprId> = guards.iter().map(|&root| deobfuscate(arena, root)).collect();

    let after = slice_roots(arena, effect_roots(&reduced_effects, &reduced_guards), max_nodes)?;
    let mut sources = BTreeSet::new();
    for root in effect_roots(&reduced_effects, &reduced_guards) {
        // All roots were already checked by slice_roots. Missing dependency
        // metadata is not evidence that a value is independent of inputs.
        let summary = arena
            .dependency_summary(root)
            .ok_or(VmReductionError::UnknownExpression { id: root })?;
        sources.extend(summary.symbolic_sources);
    }

    Ok(VmReducedEffects {
        effects: reduced_effects,
        guards: reduced_guards,
        original_nodes: before.len(),
        reduced_nodes: after.len(),
        symbolic_sources: sources.into_iter().collect(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExprNode, ExprOp, ExprSort, ShardedExprArena};
    use angryier_types::ExpressionNormalizationVersion;

    fn arena() -> ShardedExprArena {
        ShardedExprArena::new(ExpressionNormalizationVersion(1))
    }

    fn symbol(arena: &ShardedExprArena, source: u64) -> Result<ExprId, String> {
        arena
            .intern(ExprNode {
                sort: ExprSort::BitVec(32),
                op: ExprOp::Symbol,
                operands: Vec::new(),
                immediate: source.to_le_bytes().to_vec(),
            })
            .map_err(|error| format!("{error:?}"))
    }

    fn binary(arena: &ShardedExprArena, op: ExprOp, x: ExprId, y: ExprId) -> Result<ExprId, String> {
        arena
            .intern(ExprNode {
                sort: ExprSort::BitVec(32),
                op,
                operands: vec![x, y],
                immediate: Vec::new(),
            })
            .map_err(|error| format!("{error:?}"))
    }

    #[test]
    fn mba_handler_effect_reduces_and_retains_both_dependencies() -> Result<(), String> {
        let arena = arena();
        let x = symbol(&arena, 1)?;
        let y = symbol(&arena, 2)?;
        let lhs = binary(&arena, ExprOp::Or, x, y)?;
        let rhs = binary(&arena, ExprOp::And, x, y)?;
        let obfuscated = binary(&arena, ExprOp::Add, lhs, rhs)?;
        let result = reduce_vm_effects(
            &arena,
            &[VmEffect {
                kind: VmEffectKind::Register { register: 3 },
                value: obfuscated,
            }],
            &[],
            64,
        )
        .map_err(|error| format!("{error:?}"))?;
        assert_eq!(result.effects[0].value, binary(&arena, ExprOp::Add, x, y)?);
        assert!(result.reduced_nodes < result.original_nodes);
        assert_eq!(result.symbolic_sources, vec![1, 2]);
        Ok(())
    }

    #[test]
    fn memory_effect_keeps_symbolic_address_value_and_order() -> Result<(), String> {
        let arena = arena();
        let addr = symbol(&arena, 3)?;
        let value = symbol(&arena, 4)?;
        let effects = [
            VmEffect {
                kind: VmEffectKind::Memory {
                    address: addr,
                    bytes: 4,
                },
                value,
            },
            VmEffect {
                kind: VmEffectKind::Memory {
                    address: addr,
                    bytes: 4,
                },
                value: addr,
            },
        ];
        let result = reduce_vm_effects(&arena, &effects, &[addr], 16).map_err(|error| format!("{error:?}"))?;
        assert_eq!(result.effects, effects);
        assert_eq!(result.guards, vec![addr]);
        assert_eq!(result.symbolic_sources, vec![3, 4]);
        Ok(())
    }

    #[test]
    fn unknown_root_and_small_budget_fail_without_truncation() -> Result<(), String> {
        let arena = arena();
        let x = symbol(&arena, 1)?;
        let y = symbol(&arena, 2)?;
        let sum = binary(&arena, ExprOp::Add, x, y)?;
        assert_eq!(
            reduce_vm_effects(&arena, &[], &[], 8),
            Err(VmReductionError::NoObservableRoots)
        );
        assert_eq!(
            reduce_vm_effects(&arena, &[], &[ExprId(u32::MAX)], 8),
            Err(VmReductionError::UnknownExpression { id: ExprId(u32::MAX) })
        );
        assert_eq!(
            reduce_vm_effects(&arena, &[], &[sum], 2),
            Err(VmReductionError::NodeBudgetExceeded { limit: 2 })
        );
        Ok(())
    }

    #[test]
    fn independent_arena_nodes_do_not_pollute_backward_slice() -> Result<(), String> {
        let arena = arena();
        let x = symbol(&arena, 1)?;
        let y = symbol(&arena, 2)?;
        let _noise = binary(&arena, ExprOp::Add, y, y)?;
        let result = reduce_vm_effects(
            &arena,
            &[VmEffect {
                kind: VmEffectKind::VirtualPc,
                value: x,
            }],
            &[],
            3,
        )
        .map_err(|error| format!("{error:?}"))?;
        assert_eq!(result.original_nodes, 1);
        assert_eq!(result.reduced_nodes, 1);
        assert_eq!(result.symbolic_sources, vec![1]);
        Ok(())
    }
}
