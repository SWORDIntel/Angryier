//! Full-symbolic (PROVE-leg) fidelity on a real Windows kernel driver:
//! the expression-tracking session must agree with the concrete interpreter
//! step-for-step to termination — with and without the solver backend.
//!
//! Fixed 2026-09-28 (round 2): constant branch conditions no longer fork
//! without a solver; the arena folds concrete-only arithmetic/compare
//! expressions; call frames the IR pushes are mirrored into process memory
//! (so SimProcedure dispatches don't discard them), and `ret` restores rsp.
//! Before the fix the tracking trace diverged from concrete at step 49 and
//! the solver-gated run died at step 71 with UnresolvedAddress.
#![cfg(feature = "xed")]
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use angryier_expr::{ExprReader, ShardedExprArena};
use angryier_models::KernelPoolTracker;
use angryier_runtime::{Runtime, SymbolicSession};
use angryier_types::{ExpressionNormalizationVersion, SemanticVersion, TargetProfileId};

fn driver_image(name: &str) -> Option<Vec<u8>> {
    let home = std::env::var("HOME").ok()?;
    let dir = PathBuf::from(home).join("Documents/driver_analysis/drivers/sources/caledonia-drivers/bin-elastic");
    std::fs::read(dir.join(name)).ok()
}

#[test]
fn concrete_vs_tracking_trace_matches_without_solver() -> Result<(), Box<dyn std::error::Error>> {
    let Some(bytes) = driver_image("GVCIDrv64.sys") else {
        eprintln!("SKIP: driver corpus not present");
        return Ok(());
    };

    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));

    // 1. Concrete run: collect the pc trace up to termination (194 steps).
    let mut concrete_proc = runtime.load_pe_driver(&bytes)?;
    let concrete_tracker = Arc::new(KernelPoolTracker::new());
    runtime.attach_kernel_pool_model(&mut concrete_proc, concrete_tracker)?;

    let mut concrete_trace = Vec::new();
    while !concrete_proc.terminated {
        concrete_trace.push(concrete_proc.pc()?);
        runtime.step(&mut concrete_proc)?;
    }
    assert!(!concrete_trace.is_empty(), "concrete run must execute");

    // 2. Expression-tracking mode without a solver: the pc trace must match
    //    concrete step-for-step (no phantom forks on constant conditions).
    let mut tracking_proc = runtime.load_pe_driver(&bytes)?;
    let tracking_tracker = Arc::new(KernelPoolTracker::new());
    runtime.attach_kernel_pool_model(&mut tracking_proc, tracking_tracker)?;
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), tracking_proc);

    let mut tracking_trace = Vec::new();
    while !session.states.is_empty() && !session.states[0].process.terminated {
        let pc = session.states[0].process.pc()?;
        let step_idx = tracking_trace.len() + 1;
        tracking_trace.push(pc);
        assert!(
            step_idx <= concrete_trace.len(),
            "tracking outran concrete at step {step_idx} (pc={pc:#x})"
        );
        assert_eq!(
            pc,
            concrete_trace[step_idx - 1],
            "Trace mismatch at step {step_idx}: concrete={:#x} vs tracking={:#x}",
            concrete_trace[step_idx - 1],
            pc
        );
        match session.step_state(0) {
            Ok(angryier_runtime::SymbolicStepOutcome::Terminated) => break,
            Ok(_) => {}
            Err(e) => {
                return Err(format!("symbolic step error at step {step_idx} (pc={pc:#x}): {e:?}").into());
            }
        }
    }

    assert_eq!(
        tracking_trace.len(),
        concrete_trace.len(),
        "Tracking trace length must match concrete trace length"
    );
    assert_eq!(tracking_trace, concrete_trace);
    Ok(())
}

#[cfg(feature = "z3")]
#[test]
fn z3_backend_run_with_policy_terminates_cleanly() -> Result<(), Box<dyn std::error::Error>> {
    let Some(bytes) = driver_image("GVCIDrv64.sys") else {
        eprintln!("SKIP: driver corpus not present");
        return Ok(());
    };

    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut tracking_proc = runtime.load_pe_driver(&bytes)?;
    let tracking_tracker = Arc::new(KernelPoolTracker::new());
    runtime.attach_kernel_pool_model(&mut tracking_proc, tracking_tracker)?;
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), tracking_proc);

    let reader: Arc<dyn ExprReader> = arena.clone();
    let mut backend = angryier_solver_z3::Z3Backend::native_ffi(reader)?;
    let policy = angryier_runtime::ExplorationPolicy::default();

    let report = session.run_with_policy(1000, 16, Some(&mut backend), Duration::from_secs(10), false, &policy)?;

    assert!(
        report.terminated >= 1,
        "Must reach at least 1 terminated state (last_error: {:?})",
        report.last_error
    );
    assert_eq!(
        report.failed, 0,
        "Failed states must be 0 (last_error: {:?})",
        report.last_error
    );
    assert_eq!(report.steps, 194, "GVCIDrv64 DriverEntry is 194 steps");
    Ok(())
}
