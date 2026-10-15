//! Opt-in, per-instruction control/stack audit and first-divergence checks.
//!
//! The regular interpreter remains free of instrumentation overhead. A caller
//! can select only suspected CALL/RET and import sites. Every observation
//! captures pre/post RIP, RSP, and the top-of-stack only when readable and
//! fully concrete. Unknown stack bytes are never treated as return addresses.

use angryier_arch::Decoder;
use angryier_arch_intel64::register_id;
use angryier_memory::{ByteValue, LayeredMemory};
use angryier_types::Address;

use crate::{Process, Runtime, RuntimeError, StepOutcome};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlSnapshot {
    pub pc: Address,
    pub rsp: Option<u64>,
    pub stack_top: Option<u64>,
    pub rax: Option<u64>,
}

impl ControlSnapshot {
    fn capture(process: &Process) -> Result<Self, RuntimeError> {
        let pc = process.pc()?;
        let rsp = process.read_register(register_id::GPR_BASE + 4).ok();
        let stack_top = rsp.and_then(|address| {
            let bytes = process.state.memory.read(address, 8).ok()?;
            let mut value = [0u8; 8];
            for (i, b) in bytes.iter().enumerate() {
                if let ByteValue::Concrete(byte) = b {
                    value[i] = *byte;
                } else {
                    return None;
                }
            }
            Some(u64::from_le_bytes(value))
        });
        Ok(Self {
            pc,
            rsp,
            stack_top,
            rax: process.read_register(register_id::GPR_BASE).ok(),
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReturnValidation {
    NotReturn,
    Verified,
    MissingStackEvidence,
    WrongReturn {
        target: Address,
        actual: Address,
        expected_rsp: u64,
        actual_rsp: Option<u64>,
    },
}

#[derive(Debug)]
pub struct AuditedStep {
    pub before: ControlSnapshot,
    pub outcome: Result<StepOutcome, RuntimeError>,
    pub after: ControlSnapshot,
    pub return_validation: ReturnValidation,
}

/// When the observed instruction was an ordinary RET or call-correct
/// SimProcedure, validate the popped return address and RSP advancement.
fn verify_return(
    before: ControlSnapshot,
    after: ControlSnapshot,
    outcome: &Result<StepOutcome, RuntimeError>,
    is_instance_hook: bool,
) -> ReturnValidation {
    let expected_return = matches!(
        outcome,
        Ok(StepOutcome::Stepped { form_id, .. })
            if *form_id == angryier_semantics_intel64::forms::RET
    ) || (is_instance_hook && matches!(outcome, Ok(StepOutcome::SimProcedure { .. })));
    if !expected_return {
        return ReturnValidation::NotReturn;
    }
    let (Some(top), Some(rsp)) = (before.stack_top, before.rsp) else {
        return ReturnValidation::MissingStackEvidence;
    };
    let Some(expected_rsp) = rsp.checked_add(8) else {
        return ReturnValidation::MissingStackEvidence;
    };
    if after.pc == top && after.rsp == Some(expected_rsp) {
        ReturnValidation::Verified
    } else {
        ReturnValidation::WrongReturn {
            target: top,
            actual: after.pc,
            expected_rsp,
            actual_rsp: after.rsp,
        }
    }
}

impl<D: Decoder> Runtime<D> {
    /// A single step with precise pre/post control state even if execution
    /// returns an error. Does not modify Process trace or engine behavior
    /// beyond whatever the underlying step would have done.
    pub fn step_audited(&self, process: &mut Process) -> Result<AuditedStep, RuntimeError> {
        let before = ControlSnapshot::capture(process)?;
        let is_instance_hook = process.simproc_instances.contains_key(&before.pc);
        let outcome = self.step(process);
        let after = ControlSnapshot::capture(process)?;
        let return_validation = verify_return(before, after, &outcome, is_instance_hook);
        Ok(AuditedStep {
            before,
            outcome,
            after,
            return_validation,
        })
    }
}

/// Trace snapshots from an external observer must be captured with the same
/// image bytes and initial state as Angryier. An identity mismatch explicitly
/// prevents comparing unrelated execution runs as if they were deterministic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TraceIdentity {
    pub executable_digest: [u8; 32],
    pub initial_state_digest: [u8; 32],
    pub arch_id: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TraceDifference {
    IdentityMismatch,
    StepCount {
        expected: usize,
        actual: usize,
    },
    /// One trace had valid evidence for a field while the other did not.
    /// Missing evidence is NOT equivalent to equality.
    EvidenceGap {
        index: usize,
        field: &'static str,
    },
    Control {
        index: usize,
        native: ControlSnapshot,
        emulated: ControlSnapshot,
    },
}

/// Compare snapshots at the same step boundary. The caller must supply
/// exact matching identity metadata; provenance is never inferred from
/// PC equality alone. Unexpected step counts are incomplete, not success.
pub fn first_divergence(
    native_identity: TraceIdentity,
    native: &[ControlSnapshot],
    emulated_identity: TraceIdentity,
    emulated: &[ControlSnapshot],
) -> Option<TraceDifference> {
    if native_identity != emulated_identity {
        return Some(TraceDifference::IdentityMismatch);
    }
    for (index, (a, b)) in native.iter().zip(emulated.iter()).enumerate() {
        if a.pc != b.pc
            || (a.rsp.is_some() && b.rsp.is_some() && a.rsp != b.rsp)
            || (a.stack_top.is_some() && b.stack_top.is_some() && a.stack_top != b.stack_top)
        {
            return Some(TraceDifference::Control {
                index,
                native: *a,
                emulated: *b,
            });
        }
        if a.rsp.is_some() != b.rsp.is_some() {
            return Some(TraceDifference::EvidenceGap { index, field: "rsp" });
        }
        if a.stack_top.is_some() != b.stack_top.is_some() {
            return Some(TraceDifference::EvidenceGap {
                index,
                field: "stack_top",
            });
        }
    }
    (native.len() != emulated.len()).then_some(TraceDifference::StepCount {
        expected: native.len(),
        actual: emulated.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(pc: u64, rsp: Option<u64>, top: Option<u64>) -> ControlSnapshot {
        ControlSnapshot {
            pc,
            rsp,
            stack_top: top,
            rax: None,
        }
    }

    #[test]
    fn checked_return_validation_detects_pc_and_rsp_corruption() {
        let before = state(0x1000, Some(0x2000), Some(0x4000));
        let good = state(0x4000, Some(0x2008), None);
        let bad = state(0x1234, Some(0x2000), None);
        let result = Ok(StepOutcome::Stepped {
            pc: 0x1000,
            next_pc: 0x4000,
            length: 1,
            form_id: angryier_semantics_intel64::forms::RET,
        });
        assert_eq!(verify_return(before, good, &result, false), ReturnValidation::Verified);
        assert!(matches!(
            verify_return(before, bad, &result, false),
            ReturnValidation::WrongReturn { .. }
        ));
        assert_eq!(
            verify_return(state(0x1000, None, None), good, &result, false),
            ReturnValidation::MissingStackEvidence
        );
    }

    #[test]
    fn first_divergence_checks_capture_identity_and_first_change() {
        let id = TraceIdentity {
            executable_digest: [1; 32],
            initial_state_digest: [2; 32],
            arch_id: 1,
        };
        let native = [
            state(0x1000, Some(0x8000), Some(0x1100)),
            state(0x1100, Some(0x8008), None),
        ];
        let emulated = [native[0], state(0x0f1e, Some(0x8008), None)];
        assert_eq!(first_divergence(id, &native, id, &native), None);
        assert!(matches!(
            first_divergence(id, &native, id, &emulated),
            Some(TraceDifference::Control { index: 1, .. })
        ));
        let incomplete = [native[0], state(0x1100, None, None)];
        assert_eq!(
            first_divergence(id, &native, id, &incomplete),
            Some(TraceDifference::EvidenceGap { index: 1, field: "rsp" }),
        );
        let mut changed = id;
        changed.initial_state_digest = [9; 32];
        assert_eq!(
            first_divergence(id, &native, changed, &emulated),
            Some(TraceDifference::IdentityMismatch)
        );
    }
}
