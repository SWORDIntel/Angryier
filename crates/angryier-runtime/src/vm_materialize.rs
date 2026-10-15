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

use std::collections::{BTreeMap, BTreeSet};

use angryier_arch_intel64::register_id;
use angryier_execution::{
    SymbolicArena, SymbolicEvaluator, SymbolicSessionMemory, SymbolicStateSnapshot,
};
use angryier_expr::{ExprArena, vm_effects::{reduce_vm_effects, VmEffect, VmEffectKind, VmReducedEffects}};
use angryier_ir::{
    IrType, IrValueId, RegisterWriteKind,
    vm_footprint::{VmIrEffect, VmIrSource},
    vm_trace::{VmScopedValue, VmTraceCaveat},
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
    MissingBranchEvidence { step: usize },
    SymbolicEvaluation { step: usize, reason: String },
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
    values.get(value.0 as usize).and_then(|item| *item)
        .ok_or(VmMaterializationError::MissingSsa { step, value })
}

fn byte_width(ty: IrType) -> Option<u32> {
    let bits = match ty {
        IrType::Bits(w) | IrType::Vector { width_bits: w, .. }
        | IrType::Opmask { width_bits: w } => u32::from(w),
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
/// For this initial bridge, blocks containing partial-parent register writes
/// or more than one write to the same register are REFUSED. Their effect
/// ordering needs an intermediate-write observer; using the final register
/// value for an earlier write would be incorrect. No approximation is made.
///
/// No `PROVE` claim: the output is still path-specific, may contain
/// uninterpreted input symbols, and has not passed independent replay/SMT.
pub fn materialize_vm_handler(
    capture: &VmHandlerCapture,
    arena: &SymbolicArena,
    max_expression_nodes: usize,
) -> Result<VmMaterializedCandidate, VmMaterializationError> {
    if capture.steps.is_empty()
        || capture.steps.len() != capture.footprint.edges.len()
        || max_expression_nodes == 0
    {
        return Err(VmMaterializationError::InvalidCapture("missing steps/edges or zero expression budget"));
    }
    let mut seeded_registers = BTreeMap::new();
    for source in &capture.footprint.sources {
        match source.source {
            VmIrSource::Register(register) => {
                if seeded_registers.contains_key(&register) {
                    continue;
                }
                let bytes = capture.initial_state.registers.read(register)
                    .map_err(|_| VmMaterializationError::MissingInitialRegister { register })?;
                if bytes.is_empty() || bytes.len() > 8 {
                    return Err(VmMaterializationError::UnsupportedRegisterWidth {
                        register, bytes: bytes.len(),
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
        let bytes = capture.initial_state.registers.read(RSP)
            .map_err(|_| VmMaterializationError::MissingInitialRegister { register: RSP })?;
        if bytes.len() != 8 {
            return Err(VmMaterializationError::UnsupportedRegisterWidth { register: RSP, bytes: bytes.len() });
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
    let mut reads = Vec::new();
    let mut branches = Vec::new();
    let mut guards = Vec::new();

    for (step_index, recorded) in capture.steps.iter().enumerate() {
        if recorded.before != capture.footprint.edges[step_index].from
            || recorded.after != capture.footprint.edges[step_index].to
        {
            return Err(VmMaterializationError::InvalidCapture("footprint/recorded-step identity mismatch"));
        }
        let evaluation = evaluator.eval_block_with_memory_values(&recorded.block, &mut memory)
            .map_err(|error| VmMaterializationError::SymbolicEvaluation {
                step: step_index,
                reason: error.to_string(),
            })?;

        let writes: Vec<(u32, RegisterWriteKind)> = capture.footprint.effects.iter()
            .filter(|e| e.step == step_index)
            .filter_map(|e| match e.effect {
                VmIrEffect::RegisterWrite { register, kind, .. } => Some((register, kind)),
                _ => None,
            })
            .collect();
        let mut seen = BTreeSet::new();
        for (register, kind) in &writes {
            if !seen.insert(*register) {
                return Err(VmMaterializationError::MultipleWritesToRegister { step: step_index, register: *register });
            }
            if matches!(kind, RegisterWriteKind::PreserveParent { .. }) {
                return Err(VmMaterializationError::UnsupportedPartialRegister { step: step_index, register: *register });
            }
        }
        let after_registers = evaluator.snapshot().registers;
        for scoped in capture.footprint.effects.iter().filter(|e| e.step == step_index) {
            match scoped.effect {
                VmIrEffect::MemoryWrite { address, value } => {
                    let (addr, _) = value_at(&evaluation.values, step_index, address)?;
                    let (val, ty) = value_at(&evaluation.values, step_index, value)?;
                    let bytes = byte_width(ty).ok_or(VmMaterializationError::UnsupportedValueType {
                        step: step_index, value, ty,
                    })?;
                    effects.push(VmEffect {
                        kind: VmEffectKind::Memory { address: addr, bytes },
                        value: val,
                    });
                }
                VmIrEffect::RegisterWrite { register, value, .. } => {
                    let (raw_expr, _) = value_at(&evaluation.values, step_index, value)?;
                    // For zero-extend-parent writes, the evaluator's stored
                    // full-width value is authoritative; for direct writes,
                    // retaining it is also semantically equivalent.
                    let expression = after_registers.get(&register)
                        .map(|(expr, _)| *expr).unwrap_or(raw_expr);
                    effects.push(VmEffect {
                        kind: VmEffectKind::Register { register },
                        value: expression,
                    });
                }
                VmIrEffect::MemoryRead { address, mask, result } => {
                    let (addr, _) = value_at(&evaluation.values, step_index, address)?;
                    let (value, ty) = value_at(&evaluation.values, step_index, result)?;
                    let width_bytes = byte_width(ty).ok_or(
                        VmMaterializationError::UnsupportedValueType {
                            step: step_index, value: result, ty,
                        },
                    )?;
                    let mask = match mask {
                        Some(v) => Some(value_at(&evaluation.values, step_index, v)?.0),
                        None => None,
                    };
                    reads.push(VmMaterializedRead {
                        step: step_index, address: addr, mask,
                        result: value, width_bytes,
                    });
                }
                VmIrEffect::Branch { condition, .. } => {
                    let (expr, _) = value_at(&evaluation.values, step_index, condition)?;
                    let taken = capture.footprint.chosen_branches.iter().find_map(|(value, direction)| {
                        (*value == VmScopedValue { step: step_index, value: condition })
                            .then_some(*direction)
                    }).ok_or(VmMaterializationError::MissingBranchEvidence { step: step_index })?;
                    branches.push(VmMaterializedBranch { step: step_index, condition: expr, taken });
                    guards.push(expr);
                }
                VmIrEffect::IndirectJump { target } => {
                    let (expr, _) = value_at(&evaluation.values, step_index, target)?;
                    effects.push(VmEffect { kind: VmEffectKind::DispatchTarget, value: expr });
                }
                VmIrEffect::Jump { .. } | VmIrEffect::Call { .. }
                | VmIrEffect::Return | VmIrEffect::Trap { .. } => {}
            }
        }
    }
    if effects.is_empty() && guards.is_empty() {
        return Err(VmMaterializationError::InvalidCapture("no effect/guard roots to reduce"));
    }
    let reduced = reduce_vm_effects(arena, &effects, &guards, max_expression_nodes)
        .map_err(|error| VmMaterializationError::Reduction(format!("{error:?}")))?;
    Ok(VmMaterializedCandidate {
        original_effects: effects,
        reduced,
        potentially_faulting_reads: reads,
        chosen_branches: branches,
        input_had_fidelity_debt: !capture.initial_state.fidelity.is_exact(),
        caveats: capture.footprint.caveats.clone(),
    })
}
