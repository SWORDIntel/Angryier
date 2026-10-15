//! Concrete captured-state replay check for a materialized VM candidate.
//!
//! This checks whether applying the reduced ordered effects to the *exact*
//! captured initial register/memory state reproduces the independently
//! recorded final state on that ONE input. It also checks observed branch
//! decisions and computed indirect targets. The result is not SMT proof,
//! universal handler equivalence, memory alias proof on other inputs,
//! or permission to replace the native handler in PROVE mode.
//!
//! Potentially faulting loads remain replay obligations even on success.

use angryier_arch_intel64::{Intel64RegisterFile, register_id};
use angryier_execution::{constant_value, SymbolicArena};
use angryier_expr::{ExprArena, ExprSort, vm_effects::VmEffectKind};
use angryier_ir::vm_trace::VmTraceCaveat;
use angryier_memory::{ByteValue, LayeredMemory};
use angryier_state::RegisterState;
use angryier_types::Address;

use crate::{vm_materialize::VmMaterializedCandidate, vm_observe::VmHandlerCapture};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VmReplayError {
    InconsistentEffects,
    ExistingFidelityDebt,
    ExecutableChanged,
    UnresolvedSymbolicValue { effect: usize },
    UnsupportedEffect { effect: usize },
    RegisterTypeMismatch { register: u32 },
    RegisterWriteFailed { register: u32 },
    RegisterMismatch { register: u32 },
    MemoryWriteFailed { address: Address },
    MemoryMismatch { address: Address },
    MissingMemoryEvidence { address: Address },
    BranchDecisionMismatch { step: usize },
    IndirectControlMismatch { step: usize },
    FinalPcMismatch,
}

/// This verdict is *per-capture*; it cannot be used as a reusable
/// semantics-equivalence certificate without independent SMT/differential
/// validation under the proposed summary's explicit preconditions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmConcreteReplayReport {
    pub checked_registers: usize,
    pub checked_memory_stores: usize,
    pub checked_branch_decisions: usize,
    pub checked_indirect_targets: usize,
    pub unresolved_fault_obligations: usize,
    pub observed_input_only: bool,
}

fn constant(arena: &SymbolicArena, expr: angryier_types::ExprId, index: usize)
    -> Result<u64, VmReplayError>
{
    constant_value(arena, expr)
        .map_err(|_| VmReplayError::UnresolvedSymbolicValue { effect: index })
}

/// Test the candidate's concrete effects against a separate native-execution
/// state. The function does not execute an unknown binary: both snapshots
/// and symbolic expressions are supplied by the caller.
///
/// Only scalar bitvector register writes and memory writes of 1..=8 bytes
/// are accepted by this first gate. Missing evidence is an explicit error,
/// never assumed to be a matching zero.
pub fn check_vm_concrete_replay(
    capture: &VmHandlerCapture,
    candidate: &VmMaterializedCandidate,
    arena: &SymbolicArena,
) -> Result<VmConcreteReplayReport, VmReplayError> {
    if capture.steps.is_empty()
        || candidate.effect_steps.len() != candidate.reduced.effects.len()
        || candidate.original_effects.len() != candidate.reduced.effects.len()
        || candidate.effect_steps.iter().any(|step| *step >= capture.steps.len())
    {
        return Err(VmReplayError::InconsistentEffects);
    }
    if candidate.input_had_fidelity_debt
        || !capture.initial_state.fidelity.is_exact()
        || !capture.final_state.fidelity.is_exact()
    {
        return Err(VmReplayError::ExistingFidelityDebt);
    }
    if candidate.caveats.iter().any(|c| matches!(c, VmTraceCaveat::ExecutableCodeEpochChanged { .. })) {
        return Err(VmReplayError::ExecutableChanged);
    }

    let mut registers = capture.initial_state.registers.clone();
    let mut memory = capture.initial_state.memory.clone();
    let mut touched = Vec::<(Address, usize)>::new();
    let mut indirect_targets = 0usize;

    for (index, effect) in candidate.reduced.effects.iter().enumerate() {
        let step = candidate.effect_steps[index];
        match effect.kind {
            VmEffectKind::Register { register } => {
                let raw = registers.read(register)
                    .map_err(|_| VmReplayError::RegisterWriteFailed { register })?;
                let expr = arena.get(effect.value)
                    .ok_or(VmReplayError::UnresolvedSymbolicValue { effect: index })?;
                let ExprSort::BitVec(width) = expr.sort else {
                    return Err(VmReplayError::RegisterTypeMismatch { register });
                };
                if raw.is_empty() || raw.len() > 8
                    || usize::from(width).div_ceil(8) != raw.len()
                {
                    return Err(VmReplayError::RegisterTypeMismatch { register });
                }
                let value = constant(arena, effect.value, index)?;
                registers = registers.write(register, &value.to_le_bytes()[..raw.len()])
                    .map_err(|_| VmReplayError::RegisterWriteFailed { register })?;
            }
            VmEffectKind::Memory { address, bytes } => {
                if !(1..=8).contains(&bytes) {
                    return Err(VmReplayError::UnsupportedEffect { effect: index });
                }
                let at = constant(arena, address, index)?;
                let value = constant(arena, effect.value, index)?;
                let concrete: Vec<ByteValue> = value.to_le_bytes()
                    .iter().take(bytes as usize)
                    .copied().map(ByteValue::Concrete).collect();
                memory = memory.write(at, &concrete)
                    .map_err(|_| VmReplayError::MemoryWriteFailed { address: at })?;
                touched.push((at, bytes as usize));
            }
            VmEffectKind::DispatchTarget => {
                let target = constant(arena, effect.value, index)?;
                if target != capture.steps[step].after.native_pc {
                    return Err(VmReplayError::IndirectControlMismatch { step });
                }
                indirect_targets += 1;
            }
            VmEffectKind::Flags | VmEffectKind::VirtualPc => {
                // These need explicit architecture/VM context binding. A
                // register write to RFLAGS can instead use Register{..}.
                return Err(VmReplayError::UnsupportedEffect { effect: index });
            }
        }
    }

    let mut verified_branches = 0usize;
    for branch in &candidate.chosen_branches {
        let cond = constant(arena, branch.condition, branch.step)?;
        if (cond & 1 != 0) != branch.taken {
            return Err(VmReplayError::BranchDecisionMismatch { step: branch.step });
        }
        verified_branches += 1;
    }

    // Native RIP is a separate control-flow obligation: no register write
    // was fabricated merely to make the replayed register file agree.
    let recorded_pc = capture.final_state.registers.read(register_id::RIP.0)
        .map_err(|_| VmReplayError::FinalPcMismatch)?;
    if recorded_pc.as_slice() != capture.window.exit.native_pc.to_le_bytes() {
        return Err(VmReplayError::FinalPcMismatch);
    }

    let mut checked_registers = 0usize;
    for (&register, _) in &Intel64RegisterFile::canonical().architectural_registers {
        if register.0 == register_id::RIP.0 {
            continue;
        }
        let got = registers.read(register.0)
            .map_err(|_| VmReplayError::RegisterMismatch { register: register.0 })?;
        let actual = capture.final_state.registers.read(register.0)
            .map_err(|_| VmReplayError::RegisterMismatch { register: register.0 })?;
        if got != actual {
            return Err(VmReplayError::RegisterMismatch { register: register.0 });
        }
        checked_registers += 1;
    }

    for &(at, bytes) in &touched {
        let replay = memory.read(at, bytes)
            .map_err(|_| VmReplayError::MissingMemoryEvidence { address: at })?;
        let final_bytes = capture.final_state.memory.read(at, bytes)
            .map_err(|_| VmReplayError::MissingMemoryEvidence { address: at })?;
        if replay != final_bytes {
            return Err(VmReplayError::MemoryMismatch { address: at });
        }
    }

    Ok(VmConcreteReplayReport {
        checked_registers,
        checked_memory_stores: touched.len(),
        checked_branch_decisions: verified_branches,
        checked_indirect_targets: indirect_targets,
        unresolved_fault_obligations: candidate.potentially_faulting_reads.len(),
        observed_input_only: true,
    })
}
