//! Materialize observed multi-block AngryIR SSA effects into Angryier ExprIds.
//!
//! Reuses SymbolicEvaluator's actual block implementation, seeded from the
//! preserved pre-handler COW execution state. No synthetic VM semantics and
//! no conversion of IrValueId numerics to ExprId IDs.
//!
//! The result contains ordered register/memory/dispatch effects, chosen
//! branch predicates, potentially faulting memory reads, and simplification.
//! It is an *unverified candidate summary*; differential replay/SMT
//! equivalence remains mandatory before substituting it for execution.

use std::collections::BTreeMap;

use angryier_arch_intel64::register_id;
use angryier_execution::{SymbolicArena, SymbolicEvaluator, SymbolicSessionMemory, SymbolicStateSnapshot};
use angryier_expr::vm_effects::{VmEffect, VmEffectKind, VmReducedEffects, reduce_vm_effects};
use angryier_ir::{
    IrOp, IrType, IrValueId,
    vm_footprint::{VmIrEffect, VmIrSource},
    vm_trace::{VmObservedBlock, VmScopedValue, VmTraceCaveat, collect_observed_vm_trace},
};
use angryier_state::RegisterState;
use angryier_types::ExprId;

use crate::vm_observe::VmHandlerCapture;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VmMaterializationError {
    InvalidCapture(&'static str),
    MissingInitialRegister { register: u32 },
    UnsupportedRegisterWidth { register: u32, bytes: usize },
    MissingExternalExpr { expression: ExprId },
    MissingSsa { step: usize, value: IrValueId },
    UnsupportedValueType { step: usize, value: IrValueId, ty: IrType },
    UnsupportedPartialRegister { step: usize, register: u32 },
    MultipleWritesToRegister { step: usize, register: u32 },
    InconsistentRegisterWriteTrace { step: usize, register: u32 },
    MissingBranchEvidence { step: usize },
    SymbolicEvaluation { step: usize, reason: String },
    UnderconstrainedSemanticDebt { count: u64 },
    Reduction(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmMaterializedRead {
    pub step: usize,
    pub address: ExprId,
    pub mask: Option<ExprId>,
    pub result: ExprId,
    pub width_bytes: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmMaterializedBranch {
    pub step: usize,
    pub condition: ExprId,
    pub taken: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmMaterializedCandidate {
    /// Full pre-reduction effects (ordered). No store may be discarded.
    pub original_effects: Vec<VmEffect>,
    /// Original trace step corresponding to every ordered effect.
    pub effect_steps: Vec<usize>,
    /// Algebraically reduced version and non-negated branch-condition roots.
    pub reduced: VmReducedEffects,
    /// Loads kept even when the corresponding result is otherwise dead.
    /// The replay gate must separately validate fault/alias behavior.
    pub potentially_faulting_reads: Vec<VmMaterializedRead>,
    /// Both the expression and the observed choice are retained: false
    /// branches must not be mistaken for true branch assumptions.
    pub chosen_branches: Vec<VmMaterializedBranch>,
    pub input_had_fidelity_debt: bool,
    pub caveats: Vec<VmTraceCaveat>,
}

fn value_at(
    values: &[Option<(ExprId, IrType)>],
    step: usize,
    value: IrValueId,
) -> Result<(ExprId, IrType), VmMaterializationError> {
    values
        .get(value.0 as usize)
        .and_then(|item| *item)
        .ok_or(VmMaterializationError::MissingSsa { step, value })
}

fn byte_width(ty: IrType) -> Option<u32> {
    let bits = match ty {
        IrType::Bits(w) | IrType::Vector { width_bits: w, .. } | IrType::Opmask { width_bits: w } => u32::from(w),
        IrType::Float16 | IrType::BFloat16 => 16,
        IrType::Float32 => 32,
        IrType::Float64 => 64,
        IrType::Float80 => 80,
        IrType::Tile => 8192,
    };
    (bits > 0).then(|| bits.div_ceil(8))
}

/// Convert a captured and structurally checked handler path to candidate
/// expressions, using only the existing evaluator and input COW state.
///
/// The evaluator emits a post-write expression for EVERY register effect,
/// including repeated writes and partial-parent preservation. Those effects
/// are matched back to the original instruction index; a mismatch fails
/// closed rather than using an unrelated final-register expression.
///
/// No `PROVE` claim: the output is still path-specific, may contain
/// uninterpreted input symbols, and has not passed independent replay/SMT.
pub fn materialize_vm_handler(
    capture: &VmHandlerCapture,
    arena: &SymbolicArena,
    max_expression_nodes: usize,
) -> Result<VmMaterializedCandidate, VmMaterializationError> {
    if capture.steps.is_empty() || capture.steps.len() != capture.footprint.edges.len() || max_expression_nodes == 0 {
        return Err(VmMaterializationError::InvalidCapture(
            "missing steps/edges or zero expression budget",
        ));
    }
    // Caller-visible capture structures are mutable. Revalidate the entire
    // scoped IR footprint against the pinned trace window before trusting
    // its effect/source lists or evaluating any potentially faulting loads.
    let replay_steps: Vec<VmObservedBlock<'_>> = capture
        .steps
        .iter()
        .map(|step| VmObservedBlock {
            block: &step.block,
            before: step.before,
            after: step.after,
            code_epoch: step.code_epoch,
        })
        .collect();
    let verified = collect_observed_vm_trace(
        capture.window.identity,
        capture.window.entry,
        capture.window.exit,
        &replay_steps,
        capture.window.limits,
    )
    .map_err(|_| VmMaterializationError::InvalidCapture("trace identity/IR revalidation failed"))?;
    if verified != capture.footprint {
        return Err(VmMaterializationError::InvalidCapture(
            "capture footprint differs from recorded IR",
        ));
    }
    let rip = capture
        .initial_state
        .registers
        .read(register_id::RIP.0)
        .map_err(|_| VmMaterializationError::InvalidCapture("entry RIP unavailable"))?;
    if rip.as_slice() != capture.window.entry.native_pc.to_le_bytes() {
        return Err(VmMaterializationError::InvalidCapture(
            "initial-state RIP differs from captured handler entry",
        ));
    }

    let mut seeded_registers = BTreeMap::new();
    for source in &capture.footprint.sources {
        match source.source {
            VmIrSource::Register(register) => {
                if seeded_registers.contains_key(&register) {
                    continue;
                }
                let bytes = capture
                    .initial_state
                    .registers
                    .read(register)
                    .map_err(|_| VmMaterializationError::MissingInitialRegister { register })?;
                if bytes.is_empty() || bytes.len() > 8 {
                    return Err(VmMaterializationError::UnsupportedRegisterWidth {
                        register,
                        bytes: bytes.len(),
                    });
                }
                let mut raw = [0u8; 8];
                raw[..bytes.len()].copy_from_slice(&bytes);
                seeded_registers.insert(register, u64::from_le_bytes(raw));
            }
            VmIrSource::Expression(expression) => {
                if arena.get(expression).is_none() {
                    return Err(VmMaterializationError::MissingExternalExpr { expression });
                }
            }
            VmIrSource::MemoryRead(_) => {}
        }
    }
    // Seed RSP so the evaluator uses the actual stack even when the static
    // footprint doesn't contain an explicit RSP read (e.g. a callee model).
    const RSP: u32 = register_id::GPR_BASE + 4;
    if !seeded_registers.contains_key(&RSP) {
        let bytes = capture
            .initial_state
            .registers
            .read(RSP)
            .map_err(|_| VmMaterializationError::MissingInitialRegister { register: RSP })?;
        if bytes.len() != 8 {
            return Err(VmMaterializationError::UnsupportedRegisterWidth {
                register: RSP,
                bytes: bytes.len(),
            });
        }
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&bytes);
        seeded_registers.insert(RSP, u64::from_le_bytes(raw));
    }

    let mut evaluator = SymbolicEvaluator::new(arena);
    evaluator.restore(&SymbolicStateSnapshot {
        registers: BTreeMap::new(),
        concrete_registers: seeded_registers,
        constraints: Vec::new(),
        symbols: Vec::new(),
        expr_concrete: BTreeMap::new(),
    });
    let mut memory = SymbolicSessionMemory::new(capture.initial_state.memory.clone());
    let mut effects = Vec::new();
    let mut effect_steps = Vec::new();
    let mut reads = Vec::new();
    let mut branches = Vec::new();
    let mut guards = Vec::new();

    for (step_index, recorded) in capture.steps.iter().enumerate() {
        match recorded.outcome {
            crate::StepOutcome::Stepped { pc, next_pc, .. }
                if pc == recorded.before.native_pc && next_pc == recorded.after.native_pc => {}
            _ => {
                return Err(VmMaterializationError::InvalidCapture(
                    "recorded execution outcome does not match native transition",
                ));
            }
        }
        if recorded.before != capture.footprint.edges[step_index].from
            || recorded.after != capture.footprint.edges[step_index].to
        {
            return Err(VmMaterializationError::InvalidCapture(
                "footprint/recorded-step identity mismatch",
            ));
        }
        let evaluation = evaluator
            .eval_block_with_memory_values(&recorded.block, &mut memory)
            .map_err(|error| VmMaterializationError::SymbolicEvaluation {
                step: step_index,
                reason: error.to_string(),
            })?;

        let mut write_cursor = 0usize;
        for scoped in capture.footprint.effects.iter().filter(|e| e.step == step_index) {
            match scoped.effect {
                VmIrEffect::MemoryWrite { address, value } => {
                    let (addr, _) = value_at(&evaluation.values, step_index, address)?;
                    let (val, ty) = value_at(&evaluation.values, step_index, value)?;
                    let bytes = byte_width(ty).ok_or(VmMaterializationError::UnsupportedValueType {
                        step: step_index,
                        value,
                        ty,
                    })?;
                    effect_steps.push(step_index);
                    effects.push(VmEffect {
                        kind: VmEffectKind::Memory { address: addr, bytes },
                        value: val,
                    });
                }
                VmIrEffect::RegisterWrite { register, value, kind } => {
                    // Consume the actual post-write value, not the block's
                    // FINAL register value. A handler can write RFLAGS/RSP
                    // or a VM-context register dozens of times per block.
                    let trace = evaluation.register_writes.get(write_cursor).ok_or(
                        VmMaterializationError::InconsistentRegisterWriteTrace {
                            step: step_index,
                            register,
                        },
                    )?;
                    write_cursor += 1;
                    if !matches!(
                        recorded.block.instructions.get(trace.instruction_index)
                            .map(|instruction| &instruction.op),
                        Some(IrOp::WriteRegister {
                            register: actual_register,
                            value: actual_value,
                            kind: actual_kind,
                        }) if *actual_register == register && *actual_value == value
                            && *actual_kind == kind && trace.register == register
                    ) {
                        return Err(VmMaterializationError::InconsistentRegisterWriteTrace {
                            step: step_index,
                            register,
                        });
                    }
                    effect_steps.push(step_index);
                    effects.push(VmEffect {
                        kind: VmEffectKind::Register { register },
                        value: trace.expression,
                    });
                }
                VmIrEffect::MemoryRead { address, mask, result } => {
                    let (addr, _) = value_at(&evaluation.values, step_index, address)?;
                    let (value, ty) = value_at(&evaluation.values, step_index, result)?;
                    let width_bytes = byte_width(ty).ok_or(VmMaterializationError::UnsupportedValueType {
                        step: step_index,
                        value: result,
                        ty,
                    })?;
                    let mask = match mask {
                        Some(v) => Some(value_at(&evaluation.values, step_index, v)?.0),
                        None => None,
                    };
                    reads.push(VmMaterializedRead {
                        step: step_index,
                        address: addr,
                        mask,
                        result: value,
                        width_bytes,
                    });
                }
                VmIrEffect::Branch { condition, .. } => {
                    let (expr, _) = value_at(&evaluation.values, step_index, condition)?;
                    let taken = capture
                        .footprint
                        .chosen_branches
                        .iter()
                        .find_map(|(value, direction)| {
                            (*value
                                == VmScopedValue {
                                    step: step_index,
                                    value: condition,
                                })
                            .then_some(*direction)
                        })
                        .ok_or(VmMaterializationError::MissingBranchEvidence { step: step_index })?;
                    branches.push(VmMaterializedBranch {
                        step: step_index,
                        condition: expr,
                        taken,
                    });
                    guards.push(expr);
                }
                VmIrEffect::IndirectJump { target } => {
                    let (expr, _) = value_at(&evaluation.values, step_index, target)?;
                    effect_steps.push(step_index);
                    effects.push(VmEffect {
                        kind: VmEffectKind::DispatchTarget,
                        value: expr,
                    });
                }
                VmIrEffect::Jump { .. } | VmIrEffect::Call { .. } | VmIrEffect::Return | VmIrEffect::Trap { .. } => {}
            }
        }
        if write_cursor != evaluation.register_writes.len() {
            return Err(VmMaterializationError::InvalidCapture(
                "unconsumed ordered register writes after materialization",
            ));
        }
    }
    if evaluator.debt_total() > 0 {
        return Err(VmMaterializationError::UnderconstrainedSemanticDebt {
            count: evaluator.debt_total(),
        });
    }
    if effects.is_empty() && guards.is_empty() {
        return Err(VmMaterializationError::InvalidCapture(
            "no effect/guard roots to reduce",
        ));
    }
    let reduced = reduce_vm_effects(arena, &effects, &guards, max_expression_nodes)
        .map_err(|error| VmMaterializationError::Reduction(format!("{error:?}")))?;
    Ok(VmMaterializedCandidate {
        original_effects: effects,
        effect_steps,
        reduced,
        potentially_faulting_reads: reads,
        chosen_branches: branches,
        input_had_fidelity_debt: !capture.initial_state.fidelity.is_exact(),
        caveats: capture.footprint.caveats.clone(),
    })
}
