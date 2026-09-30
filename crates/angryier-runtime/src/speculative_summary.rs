#![forbid(unsafe_code)]

//! Speculative Summary Application (roadmap §5 item 8 — speculative tier).
//!
//! This module implements **optimistic function-summary application**: a
//! candidate summary is applied to the register state *before* formal purity
//! verification finishes (e.g., before the IR scan completes or a concolic
//! side-check settles). If verification succeeds the application is
//! **committed**; if it fails — or if the postcondition invariant does not
//! hold — the state is **rolled back** to a lightweight checkpoint captured
//! just before application.
//!
//! # Design
//!
//! The speculative applier is intentionally narrow:
//!
//! * **Lightweight checkpoint** — only GPR ids and their concrete values plus
//!   the stack pointer are saved. This is O(#registers) space and O(1) time,
//!   and sufficient to recover from a rollback because a summary that reaches
//!   `apply_speculative` has already passed the operand-surface purity filter
//!   (no memory writes, no partial register writes). The symbolic register map
//!   is snapshotted per touched register.
//!
//! * **Postcondition verification** — given the speculative register delta
//!   already applied and the *actual* delta produced by a later (possibly
//!   concrete) oracle, `verify_summary_postcondition` checks that every
//!   register the summary wrote matches the oracle delta within tolerance.
//!   Mismatches drive rollback.
//!
//! * **Metrics** — four atomic counters (no lock) track the cumulative
//!   operational history of the applier instance, suitable for benchmarks
//!   and regression tests.
//!
//! # Soundness note
//!
//! A speculative application that is **not** followed by either `commit` or
//! `rollback` leaves state in an undefined intermediate form. Callers MUST
//! always pair `apply_speculative` with exactly one of `commit` or `rollback`.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use angryier_ir::IrType;
use angryier_types::ExprId;

use crate::function_summaries::{FunctionSummary, FunctionTemplate};

// ── State abstraction ──────────────────────────────────────────────────────

/// Trait abstracting state targets that can receive speculative register
/// updates and checkpoints.
pub trait SpeculativeStateTarget {
    /// Current program counter.
    fn pc(&self) -> u64;
    /// Sets the program counter.
    fn set_pc(&mut self, pc: u64);
    /// Reads a concrete register value if present.
    fn read_concrete(&self, reg: u32) -> Option<u64>;
    /// Writes a concrete register value.
    fn write_concrete(&mut self, reg: u32, val: u64);
    /// Reads a symbolic register binding if present.
    fn read_symbolic(&self, reg: u32) -> Option<(ExprId, IrType)>;
    /// Writes a symbolic register binding.
    fn write_symbolic(&mut self, reg: u32, expr: ExprId, ty: IrType);
    /// Removes a symbolic register binding.
    fn remove_symbolic(&mut self, reg: u32);
}

/// Lightweight register state for execution and testing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpeculativeExecutionState {
    /// Program counter.
    pub pc: u64,
    /// Concrete register values.
    pub concrete_registers: BTreeMap<u32, u64>,
    /// Symbolic register bindings.
    pub symbolic_registers: BTreeMap<u32, (ExprId, IrType)>,
}

impl SpeculativeExecutionState {
    /// Creates a new execution state with the specified PC.
    pub fn new(pc: u64) -> Self {
        Self {
            pc,
            concrete_registers: BTreeMap::new(),
            symbolic_registers: BTreeMap::new(),
        }
    }

    /// Builder helper to set an initial concrete register value.
    pub fn with_concrete_reg(mut self, reg: u32, val: u64) -> Self {
        self.concrete_registers.insert(reg, val);
        self
    }

    /// Builder helper to set an initial symbolic register binding.
    pub fn with_symbolic_reg(mut self, reg: u32, expr: ExprId, ty: IrType) -> Self {
        self.symbolic_registers.insert(reg, (expr, ty));
        self
    }
}

impl SpeculativeStateTarget for SpeculativeExecutionState {
    fn pc(&self) -> u64 {
        self.pc
    }

    fn set_pc(&mut self, pc: u64) {
        self.pc = pc;
    }

    fn read_concrete(&self, reg: u32) -> Option<u64> {
        self.concrete_registers.get(&reg).copied()
    }

    fn write_concrete(&mut self, reg: u32, val: u64) {
        self.concrete_registers.insert(reg, val);
    }

    fn read_symbolic(&self, reg: u32) -> Option<(ExprId, IrType)> {
        self.symbolic_registers.get(&reg).copied()
    }

    fn write_symbolic(&mut self, reg: u32, expr: ExprId, ty: IrType) {
        self.symbolic_registers.insert(reg, (expr, ty));
    }

    fn remove_symbolic(&mut self, reg: u32) {
        self.symbolic_registers.remove(&reg);
    }
}

impl SpeculativeStateTarget for crate::SymbolicState {
    fn pc(&self) -> u64 {
        self.process.pc().unwrap_or(0)
    }

    fn set_pc(&mut self, pc: u64) {
        let _ = self.process.write_pc(pc);
    }

    fn read_concrete(&self, reg: u32) -> Option<u64> {
        self.concrete_registers
            .get(&reg)
            .copied()
            .or_else(|| self.process.read_register(reg).ok())
    }

    fn write_concrete(&mut self, reg: u32, val: u64) {
        self.concrete_registers.insert(reg, val);
        let _ = self.process.write_register(reg, val);
    }

    fn read_symbolic(&self, reg: u32) -> Option<(ExprId, IrType)> {
        self.registers.get(&reg).copied()
    }

    fn write_symbolic(&mut self, reg: u32, expr: ExprId, ty: IrType) {
        self.registers.insert(reg, (expr, ty));
    }

    fn remove_symbolic(&mut self, reg: u32) {
        self.registers.remove(&reg);
    }
}

impl SpeculativeStateTarget
    for (
        &mut BTreeMap<u32, u64>,
        &mut BTreeMap<u32, (ExprId, IrType)>,
        &mut u64,
    )
{
    fn pc(&self) -> u64 {
        *self.2
    }

    fn set_pc(&mut self, pc: u64) {
        *self.2 = pc;
    }

    fn read_concrete(&self, reg: u32) -> Option<u64> {
        self.0.get(&reg).copied()
    }

    fn write_concrete(&mut self, reg: u32, val: u64) {
        self.0.insert(reg, val);
    }

    fn read_symbolic(&self, reg: u32) -> Option<(ExprId, IrType)> {
        self.1.get(&reg).copied()
    }

    fn write_symbolic(&mut self, reg: u32, expr: ExprId, ty: IrType) {
        self.1.insert(reg, (expr, ty));
    }

    fn remove_symbolic(&mut self, reg: u32) {
        self.1.remove(&reg);
    }
}

// ── Candidate Summary ──────────────────────────────────────────────────────

/// A candidate function summary packaged for speculative application.
#[derive(Clone, Debug)]
pub struct CandidateSummary {
    /// The function summary metadata.
    pub summary: FunctionSummary,
    /// Optional expression template for symbolic registers.
    pub template: Option<FunctionTemplate>,
    /// Concrete register values to apply (e.g. RAX return value).
    pub concrete_effects: BTreeMap<u32, u64>,
    /// Return address where execution should resume after the call.
    pub ret_addr: u64,
}

impl CandidateSummary {
    /// Creates a new candidate summary with template and concrete effects.
    pub fn new(
        summary: FunctionSummary,
        template: Option<FunctionTemplate>,
        concrete_effects: BTreeMap<u32, u64>,
        ret_addr: u64,
    ) -> Self {
        Self {
            summary,
            template,
            concrete_effects,
            ret_addr,
        }
    }

    /// Creates a candidate summary with concrete register values only.
    pub fn from_concrete(
        summary: FunctionSummary,
        concrete_effects: BTreeMap<u32, u64>,
        ret_addr: u64,
    ) -> Self {
        Self {
            summary,
            template: None,
            concrete_effects,
            ret_addr,
        }
    }

    /// Creates a candidate summary with an expression template.
    pub fn from_template(
        summary: FunctionSummary,
        template: FunctionTemplate,
        ret_addr: u64,
    ) -> Self {
        Self {
            summary,
            template: Some(template),
            concrete_effects: BTreeMap::new(),
            ret_addr,
        }
    }
}

// ── Register snapshot ──────────────────────────────────────────────────────

/// Lightweight rollback checkpoint: the concrete register values and
/// symbolic bindings saved immediately before a speculative application.
///
/// Only the registers the summary touches (plus the stack pointer) are
/// saved, so memory is proportional to the summary's register delta, not
/// to the whole architectural state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpeculativeCheckpoint {
    /// Saved concrete register values: `(register_id, concrete_value)`.
    /// The stack pointer (`rsp`) is always included.
    pub saved_concrete: BTreeMap<u32, u64>,
    /// Saved symbolic register bindings for the same register ids.
    /// `None` for a register that had no symbolic binding at checkpoint time.
    pub saved_symbolic: BTreeMap<u32, Option<(ExprId, IrType)>>,
    /// The program counter at checkpoint time — restored on rollback so
    /// the outer engine can re-execute normally.
    pub saved_pc: u64,
}

// ── Speculative state ──────────────────────────────────────────────────────

/// The register state after a speculative summary application.
///
/// Returned by [`SpeculativeSummaryApplier::apply_speculative`]; consumed by
/// [`SpeculativeSummaryApplier::verify_summary_postcondition`],
/// [`SpeculativeSummaryApplier::commit`], and
/// [`SpeculativeSummaryApplier::rollback`].
#[derive(Clone, Debug)]
pub struct SpeculativeState {
    /// The registers written by the speculative application: `(register_id,
    /// concrete_value, symbolic_binding_if_any)`.
    #[allow(clippy::type_complexity)]
    pub applied_registers: Vec<(u32, u64, Option<(ExprId, IrType)>)>,
    /// Checkpoint saved before application — used by `rollback`.
    pub checkpoint: SpeculativeCheckpoint,
    /// The return address the speculative step lands on.
    pub speculative_ret_addr: u64,
    /// Body depth in instructions, representing cycles saved on commit.
    pub cycles_saved: u64,
}

// ── Metrics ────────────────────────────────────────────────────────────────

/// A read-out of the four operational metrics.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SpeculativeMetrics {
    /// Total attempted speculative applications.
    pub speculative_applications: u64,
    /// Committed (successful) applications.
    pub speculative_hits: u64,
    /// Rolled-back applications.
    pub speculative_rollbacks: u64,
    /// Estimated cycles saved by committed applications.
    pub speedup_cycles_saved: u64,
}

// ── Verification ───────────────────────────────────────────────────────────

/// Reason a postcondition check failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PostconditionMismatch {
    /// A register written by the summary did not match the oracle delta.
    RegisterMismatch {
        register: u32,
        speculative: u64,
        actual: u64,
    },
    /// The oracle delta includes a register the summary did not write — the
    /// summary is underspecified for this call shape.
    OracleSurplus { register: u32, actual: u64 },
}

/// Result of postcondition verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerificationOutcome {
    /// All registers match — ready to commit.
    Ok,
    /// At least one register disagrees — must roll back.
    Mismatch(Vec<PostconditionMismatch>),
}

impl VerificationOutcome {
    /// True if verification succeeded without mismatches.
    pub fn is_ok(&self) -> bool {
        matches!(self, Self::Ok)
    }

    /// True if any mismatches were detected.
    pub fn is_mismatch(&self) -> bool {
        matches!(self, Self::Mismatch(_))
    }
}

// ── Applier ────────────────────────────────────────────────────────────────

/// Speculative application of candidate function summaries.
///
/// Enables speculative execution of function summary templates before
/// formal verification or purity checks finish. Maintains lightweight
/// checkpoints and tracks metrics across applications, hits, and rollbacks.
#[derive(Debug, Default)]
pub struct SpeculativeSummaryApplier {
    speculative_applications: AtomicU64,
    speculative_hits: AtomicU64,
    speculative_rollbacks: AtomicU64,
    speedup_cycles_saved: AtomicU64,
}

impl SpeculativeSummaryApplier {
    /// Creates a fresh applier with zeroed metrics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Total attempted speculative applications.
    pub fn speculative_applications(&self) -> u64 {
        self.speculative_applications.load(Ordering::Relaxed)
    }

    /// Total successful commits.
    pub fn speculative_hits(&self) -> u64 {
        self.speculative_hits.load(Ordering::Relaxed)
    }

    /// Total rollbacks.
    pub fn speculative_rollbacks(&self) -> u64 {
        self.speculative_rollbacks.load(Ordering::Relaxed)
    }

    /// Total estimated cycles saved.
    pub fn speedup_cycles_saved(&self) -> u64 {
        self.speedup_cycles_saved.load(Ordering::Relaxed)
    }

    /// Returns a snapshot of current metrics.
    pub fn metrics(&self) -> SpeculativeMetrics {
        SpeculativeMetrics {
            speculative_applications: self.speculative_applications(),
            speculative_hits: self.speculative_hits(),
            speculative_rollbacks: self.speculative_rollbacks(),
            speedup_cycles_saved: self.speedup_cycles_saved(),
        }
    }

    /// Speculatively applies `candidate_summary` to the engine state.
    ///
    /// Saves a lightweight rollback checkpoint in the returned [`SpeculativeState`]
    /// and writes the summary's effects (template symbolic bindings and concrete
    /// values) directly to `state`, setting `state.pc` to `candidate_summary.ret_addr`.
    pub fn apply_speculative<S: SpeculativeStateTarget>(
        &self,
        state: &mut S,
        _target_fn: u64,
        candidate_summary: &CandidateSummary,
    ) -> SpeculativeState {
        self.speculative_applications.fetch_add(1, Ordering::Relaxed);

        // 1. Identify touched registers: arg registers, concrete effects, template effects, RSP.
        let mut touched: Vec<u32> = candidate_summary.summary.arg_registers();
        for &r in candidate_summary.concrete_effects.keys() {
            if !touched.contains(&r) {
                touched.push(r);
            }
        }
        if let Some(template) = &candidate_summary.template {
            for &(r, _, _) in &template.effects {
                if !touched.contains(&r) {
                    touched.push(r);
                }
            }
        }
        let rsp_id = angryier_arch_intel64::register_id::GPR_BASE + 4;
        if !touched.contains(&rsp_id) {
            touched.push(rsp_id);
        }

        // 2. Save lightweight checkpoint.
        let mut saved_concrete = BTreeMap::new();
        let mut saved_symbolic = BTreeMap::new();
        for &reg in &touched {
            saved_concrete.insert(reg, state.read_concrete(reg).unwrap_or(0));
            saved_symbolic.insert(reg, state.read_symbolic(reg));
        }

        let checkpoint = SpeculativeCheckpoint {
            saved_concrete,
            saved_symbolic,
            saved_pc: state.pc(),
        };

        // 3. Apply speculative updates into state.
        let mut applied_registers = Vec::new();

        if let Some(template) = &candidate_summary.template {
            for &(reg, expr, ty) in &template.effects {
                state.write_symbolic(reg, expr, ty);
                let concrete_val = candidate_summary
                    .concrete_effects
                    .get(&reg)
                    .copied()
                    .unwrap_or(0);
                if candidate_summary.concrete_effects.contains_key(&reg) {
                    state.write_concrete(reg, concrete_val);
                }
                applied_registers.push((reg, concrete_val, Some((expr, ty))));
            }
        }

        for (&reg, &val) in &candidate_summary.concrete_effects {
            state.write_concrete(reg, val);
            if !applied_registers.iter().any(|(r, _, _)| *r == reg) {
                let sym = state.read_symbolic(reg);
                applied_registers.push((reg, val, sym));
            }
        }

        state.set_pc(candidate_summary.ret_addr);

        SpeculativeState {
            applied_registers,
            checkpoint,
            speculative_ret_addr: candidate_summary.ret_addr,
            cycles_saved: candidate_summary.summary.depth,
        }
    }

    /// Verifies that speculative state matches expected actual delta from an oracle.
    pub fn verify_summary_postcondition(
        &self,
        speculative_state: &SpeculativeState,
        actual_delta: &BTreeMap<u32, u64>,
    ) -> VerificationOutcome {
        let mut mismatches = Vec::new();

        let spec_map: BTreeMap<u32, u64> = speculative_state
            .applied_registers
            .iter()
            .map(|&(r, v, _)| (r, v))
            .collect();

        for (&reg, &actual) in actual_delta {
            match spec_map.get(&reg) {
                Some(&speculative) if speculative == actual => {}
                Some(&speculative) => {
                    mismatches.push(PostconditionMismatch::RegisterMismatch {
                        register: reg,
                        speculative,
                        actual,
                    });
                }
                None => {
                    mismatches.push(PostconditionMismatch::OracleSurplus { register: reg, actual });
                }
            }
        }

        if mismatches.is_empty() {
            VerificationOutcome::Ok
        } else {
            VerificationOutcome::Mismatch(mismatches)
        }
    }

    /// Commits a speculative application when verification passes.
    ///
    /// Returns the committed return address program counter.
    pub fn commit(&self, speculative_state: &SpeculativeState) -> u64 {
        self.speculative_hits.fetch_add(1, Ordering::Relaxed);
        self.speedup_cycles_saved
            .fetch_add(speculative_state.cycles_saved, Ordering::Relaxed);
        speculative_state.speculative_ret_addr
    }

    /// Restores state from the lightweight checkpoint if verification fails or purity is violated.
    pub fn rollback<S: SpeculativeStateTarget>(
        &self,
        state: &mut S,
        checkpoint: &SpeculativeCheckpoint,
    ) {
        for (&reg, &value) in &checkpoint.saved_concrete {
            state.write_concrete(reg, value);
        }
        for (&reg, &binding) in &checkpoint.saved_symbolic {
            match binding {
                Some((expr, ty)) => state.write_symbolic(reg, expr, ty),
                None => state.remove_symbolic(reg),
            }
        }
        state.set_pc(checkpoint.saved_pc);
        self.speculative_rollbacks.fetch_add(1, Ordering::Relaxed);
    }
}

// ── Unit tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_arch::{
        AccessKind, DecodedInstruction, InstructionModifiers, Operand, OperandKind,
        OperandVisibility, RegisterId, RegisterView,
    };
    use angryier_arch_intel64::register_id;
    use angryier_semantics_intel64::forms as f;

    const RAX: u32 = register_id::GPR_BASE;
    const RCX: u32 = register_id::GPR_BASE + 1;
    const RDX: u32 = register_id::GPR_BASE + 2;
    const RSP: u32 = register_id::GPR_BASE + 4;

    /// Builds a minimal `FunctionSummary` with the given `reads` register list.
    fn make_summary(reads: Vec<u32>) -> FunctionSummary {
        let mut operands = Vec::new();
        for (i, &r) in reads.iter().enumerate() {
            operands.push(Operand {
                index: i as u8,
                width_bits: 64,
                access: AccessKind::Read,
                visibility: OperandVisibility::Explicit,
                kind: OperandKind::Register(RegisterView::full(RegisterId(r), 64)),
            });
        }
        let nop = DecodedInstruction {
            address: 0x1000,
            form_id: f::NOP,
            length: 1,
            features: Vec::new(),
            operands,
            modifiers: InstructionModifiers::default(),
        };
        let ret = DecodedInstruction {
            address: 0x1001,
            form_id: f::RET,
            length: 1,
            features: Vec::new(),
            operands: Vec::new(),
            modifiers: InstructionModifiers::default(),
        };
        FunctionSummary {
            entry: 0x1000,
            insns: vec![nop, ret],
            chain_jumps: BTreeMap::new(),
            reads,
            depth: 2,
            width: 64,
        }
    }

    // ── test: successful application and commit ────────────────────────────

    #[test]
    fn test_apply_and_commit() {
        let applier = SpeculativeSummaryApplier::new();
        let summary = make_summary(vec![RCX]);

        let mut state = SpeculativeExecutionState::new(0x1000)
            .with_concrete_reg(RAX, 0xDEAD)
            .with_concrete_reg(RCX, 0x1)
            .with_concrete_reg(RSP, 0x7FFF_0000);

        let mut new_vals = BTreeMap::new();
        new_vals.insert(RAX, 0xBEEF_u64);

        let candidate = CandidateSummary::from_concrete(summary.clone(), new_vals, 0x1005);
        let spec_state = applier.apply_speculative(&mut state, 0x2000, &candidate);

        // Verify speculative state was applied to state registers
        assert_eq!(state.read_concrete(RAX), Some(0xBEEF));
        assert_eq!(state.read_concrete(RCX), Some(0x1));
        assert_eq!(state.pc(), 0x1005);

        // Verification matches
        let mut actual_delta = BTreeMap::new();
        actual_delta.insert(RAX, 0xBEEF_u64);
        let outcome = applier.verify_summary_postcondition(&spec_state, &actual_delta);
        assert_eq!(outcome, VerificationOutcome::Ok);

        // Commit
        let committed_pc = applier.commit(&spec_state);
        assert_eq!(committed_pc, 0x1005);

        let m = applier.metrics();
        assert_eq!(m.speculative_applications, 1);
        assert_eq!(m.speculative_hits, 1);
        assert_eq!(m.speculative_rollbacks, 0);
        assert_eq!(m.speedup_cycles_saved, summary.depth);
    }

    // ── test: postcondition mismatch triggers rollback ─────────────────────

    #[test]
    fn test_postcondition_mismatch_and_rollback() {
        let applier = SpeculativeSummaryApplier::new();
        let summary = make_summary(vec![]);

        let mut state = SpeculativeExecutionState::new(0x2000)
            .with_concrete_reg(RAX, 0xAAAA)
            .with_concrete_reg(RSP, 0x7FFF_0000);

        let mut new_vals = BTreeMap::new();
        new_vals.insert(RAX, 0xBBBB_u64);

        let candidate = CandidateSummary::from_concrete(summary, new_vals, 0x2005);
        let spec_state = applier.apply_speculative(&mut state, 0x3000, &candidate);

        assert_eq!(state.read_concrete(RAX), Some(0xBBBB));

        // Oracle says actual result is different
        let mut actual_delta = BTreeMap::new();
        actual_delta.insert(RAX, 0xCCCC_u64);

        let outcome = applier.verify_summary_postcondition(&spec_state, &actual_delta);
        match outcome {
            VerificationOutcome::Mismatch(mismatches) => {
                assert_eq!(mismatches.len(), 1);
                assert_eq!(
                    mismatches[0],
                    PostconditionMismatch::RegisterMismatch {
                        register: RAX,
                        speculative: 0xBBBB,
                        actual: 0xCCCC,
                    }
                );
            }
            VerificationOutcome::Ok => panic!("expected mismatch"),
        }

        // Roll back
        applier.rollback(&mut state, &spec_state.checkpoint);

        assert_eq!(state.read_concrete(RAX), Some(0xAAAA));
        assert_eq!(state.pc(), 0x2000);

        let m = applier.metrics();
        assert_eq!(m.speculative_applications, 1);
        assert_eq!(m.speculative_hits, 0);
        assert_eq!(m.speculative_rollbacks, 1);
    }

    // ── test: oracle surplus register causes mismatch ─────────────────────

    #[test]
    fn test_oracle_surplus_mismatch() {
        let applier = SpeculativeSummaryApplier::new();
        let summary = make_summary(vec![]);

        let mut state = SpeculativeExecutionState::new(0x4000)
            .with_concrete_reg(RAX, 0x1)
            .with_concrete_reg(RSP, 0x7FFF_0000);

        let mut new_vals = BTreeMap::new();
        new_vals.insert(RAX, 0x2_u64);

        let candidate = CandidateSummary::from_concrete(summary, new_vals, 0x4005);
        let spec_state = applier.apply_speculative(&mut state, 0x5000, &candidate);

        // Oracle also wrote RCX
        let mut actual_delta = BTreeMap::new();
        actual_delta.insert(RAX, 0x2_u64);
        actual_delta.insert(RCX, 0xFF_u64);

        let outcome = applier.verify_summary_postcondition(&spec_state, &actual_delta);
        match outcome {
            VerificationOutcome::Mismatch(mismatches) => {
                assert!(mismatches.contains(&PostconditionMismatch::OracleSurplus {
                    register: RCX,
                    actual: 0xFF,
                }));
            }
            VerificationOutcome::Ok => panic!("expected mismatch, got Ok"),
        }
    }

    // ── test: state fidelity after commit ─────────────────────────────────

    #[test]
    fn test_state_fidelity_after_commit() {
        let applier = SpeculativeSummaryApplier::new();
        let summary = make_summary(vec![RCX]);

        let mut state = SpeculativeExecutionState::new(0x6000)
            .with_concrete_reg(RAX, 0x10)
            .with_concrete_reg(RCX, 0x20)
            .with_concrete_reg(RDX, 0x30)
            .with_concrete_reg(RSP, 0x7FFF_0000);

        let mut new_vals = BTreeMap::new();
        new_vals.insert(RAX, 0x99_u64);

        let candidate = CandidateSummary::from_concrete(summary, new_vals, 0x6010);
        let spec_state = applier.apply_speculative(&mut state, 0x7000, &candidate);

        applier.commit(&spec_state);

        assert_eq!(state.read_concrete(RAX), Some(0x99), "committed RAX");
        assert_eq!(state.read_concrete(RCX), Some(0x20), "RCX untouched");
        assert_eq!(state.read_concrete(RDX), Some(0x30), "RDX untouched");
        assert_eq!(state.read_concrete(RSP), Some(0x7FFF_0000), "RSP untouched");
        assert_eq!(state.pc(), 0x6010, "PC at ret_addr");
    }

    // ── test: state fidelity after rollback ───────────────────────────────

    #[test]
    fn test_state_fidelity_after_rollback() {
        let applier = SpeculativeSummaryApplier::new();
        let summary = make_summary(vec![]);

        let dummy_expr = ExprId(42);
        let mut state = SpeculativeExecutionState::new(0x8000)
            .with_concrete_reg(RAX, 0xAABB)
            .with_concrete_reg(RSP, 0x7FFF_0000)
            .with_symbolic_reg(RAX, dummy_expr, IrType::Bits(64));

        let mut new_vals = BTreeMap::new();
        new_vals.insert(RAX, 0xCCDD_u64);

        let candidate = CandidateSummary::from_concrete(summary, new_vals, 0x8010);
        let spec_state = applier.apply_speculative(&mut state, 0x9000, &candidate);

        assert_eq!(state.read_concrete(RAX), Some(0xCCDD));
        assert_eq!(state.pc(), 0x8010);

        // Roll back
        applier.rollback(&mut state, &spec_state.checkpoint);

        assert_eq!(state.read_concrete(RAX), Some(0xAABB), "concrete RAX restored");
        assert_eq!(state.pc(), 0x8000, "PC restored to pre-apply");
        assert_eq!(
            state.read_symbolic(RAX),
            Some((dummy_expr, IrType::Bits(64))),
            "symbolic binding restored"
        );

        let m = applier.metrics();
        assert_eq!(m.speculative_rollbacks, 1);
        assert_eq!(m.speculative_hits, 0);
    }

    // ── test: postcondition Ok path ────────────────────────────────────────

    #[test]
    fn test_postcondition_ok() {
        let applier = SpeculativeSummaryApplier::new();
        let summary = make_summary(vec![]);

        let mut state = SpeculativeExecutionState::new(0xA000)
            .with_concrete_reg(RAX, 0x1)
            .with_concrete_reg(RSP, 0x7FFF_0000);

        let mut new_vals = BTreeMap::new();
        new_vals.insert(RAX, 0x42_u64);

        let candidate = CandidateSummary::from_concrete(summary, new_vals, 0xA010);
        let spec_state = applier.apply_speculative(&mut state, 0xB000, &candidate);

        let mut actual_delta = BTreeMap::new();
        actual_delta.insert(RAX, 0x42_u64);

        let outcome = applier.verify_summary_postcondition(&spec_state, &actual_delta);
        assert_eq!(outcome, VerificationOutcome::Ok);
    }

    // ── test: metrics accumulate across multiple operations ───────────────

    #[test]
    fn test_metrics_accumulate() {
        let applier = SpeculativeSummaryApplier::new();
        let summary = make_summary(vec![]);

        for i in 0..4_u64 {
            let mut state = SpeculativeExecutionState::new(0xC000)
                .with_concrete_reg(RAX, i)
                .with_concrete_reg(RSP, 0x7FFF_0000);

            let mut new_vals = BTreeMap::new();
            new_vals.insert(RAX, i + 100);

            let candidate = CandidateSummary::from_concrete(summary.clone(), new_vals, 0xC010);
            let spec_state = applier.apply_speculative(&mut state, 0xD000, &candidate);

            if i % 2 == 0 {
                applier.commit(&spec_state);
            } else {
                applier.rollback(&mut state, &spec_state.checkpoint);
            }
        }

        let m = applier.metrics();
        assert_eq!(m.speculative_applications, 4, "4 applications");
        assert_eq!(m.speculative_hits, 2, "i=0,2 committed");
        assert_eq!(m.speculative_rollbacks, 2, "i=1,3 rolled back");
        assert_eq!(m.speedup_cycles_saved, 4, "2 commits * depth 2");
    }

    // ── test: template application and symbolic effect rollback ───────────

    #[test]
    fn test_template_symbolic_effects() {
        let applier = SpeculativeSummaryApplier::new();
        let summary = make_summary(vec![]);

        let sym_rax = ExprId(101);
        let template = FunctionTemplate {
            effects: vec![(RAX, sym_rax, IrType::Bits(64))],
            placeholders: vec![(RAX, ExprId(1))],
        };

        let mut state = SpeculativeExecutionState::new(0xE000)
            .with_concrete_reg(RAX, 0x1111)
            .with_concrete_reg(RSP, 0x7FFF_0000);

        let mut concrete_effects = BTreeMap::new();
        concrete_effects.insert(RAX, 0x2222);

        let candidate = CandidateSummary::new(summary, Some(template), concrete_effects, 0xE005);
        let spec_state = applier.apply_speculative(&mut state, 0xF000, &candidate);

        assert_eq!(state.read_symbolic(RAX), Some((sym_rax, IrType::Bits(64))));
        assert_eq!(state.read_concrete(RAX), Some(0x2222));
        assert_eq!(state.pc(), 0xE005);

        // Roll back restores absence of symbolic binding and original concrete RAX
        applier.rollback(&mut state, &spec_state.checkpoint);
        assert_eq!(state.read_symbolic(RAX), None);
        assert_eq!(state.read_concrete(RAX), Some(0x1111));
        assert_eq!(state.pc(), 0xE000);
    }
}
