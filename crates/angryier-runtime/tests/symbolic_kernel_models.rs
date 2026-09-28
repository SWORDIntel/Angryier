//! Regression: the symbolic session must dispatch kernel SimProcedures on
//! `call [IAT]` — function-summary lazy extraction used to collapse the
//! import stub's bare `ret` cell as a "pure function", silently skipping
//! the kernel model (pool allocations, status returns) and diverging the
//! symbolic path from concrete.
//!
//! Fixed 2026-09-28: `try_function_summary` refuses targets that are
//! SimProcedure hook addresses (import stubs, the exit hook), so stepping
//! reaches the stub and the top-of-step dispatch runs the model.
#![cfg(feature = "xed")]
use std::path::PathBuf;
use std::sync::Arc;

use angryier_expr::ShardedExprArena;
use angryier_models::KernelPoolTracker;
use angryier_runtime::{Runtime, SymbolicSession};
use angryier_types::{ExpressionNormalizationVersion, SemanticVersion, TargetProfileId};

fn driver_image(name: &str) -> Option<Vec<u8>> {
    let home = std::env::var("HOME").ok()?;
    let dir = PathBuf::from(home).join("Documents/driver_analysis/drivers/sources/caledonia-drivers/bin-elastic");
    std::fs::read(dir.join(name)).ok()
}

fn fixture_image(name: &str) -> Option<Vec<u8>> {
    let home = std::env::var("HOME").ok()?;
    let dir = PathBuf::from(home).join("Documents/byovd-harness/ghidra_pipeline/fixtures/bin");
    std::fs::read(dir.join(name)).ok()
}

#[test]
fn symbolic_session_dispatches_kernel_models() -> Result<(), Box<dyn std::error::Error>> {
    let Some(bytes) = driver_image("GVCIDrv64.sys") else {
        eprintln!("SKIP: driver corpus not present");
        return Ok(());
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_pe_driver(&bytes)?;
    let tracker = Arc::new(KernelPoolTracker::new());
    runtime.attach_kernel_pool_model(&mut process, tracker.clone())?;
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);

    // Step past the first `call [IAT]` (step ~39 in DriverEntry). With the
    // summary-interception bug, the stub's `ret` collapsed the call and the
    // model never dispatched; with the fix, pc reaches the stub and the
    // SimProcedure fires.
    for _ in 0..60 {
        if session.step_state(0).is_err() {
            break;
        }
        if session.states.is_empty() || session.states[0].process.terminated {
            break;
        }
    }
    let dispatches = session.states[0].process.simproc_dispatches;
    assert!(
        dispatches >= 1,
        "kernel SimProcedure must dispatch in symbolic mode (dispatches={dispatches})"
    );
    Ok(())
}

#[test]
fn symbolic_session_records_pool_events() -> Result<(), Box<dyn std::error::Error>> {
    // A pool-allocating fixture: the symbolic session must run the
    // allocator model end-to-end (a collapsed call would leave allocs=0).
    let Some(bytes) = fixture_image("allocsize_overflow_vuln_import_O2.sys") else {
        eprintln!("SKIP: fixture corpus not present");
        return Ok(());
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_pe_driver(&bytes)?;
    let tracker = Arc::new(KernelPoolTracker::new());
    runtime.attach_kernel_pool_model(&mut process, tracker.clone())?;
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    for _ in 0..2000 {
        if session.step_state(0).is_err() {
            break;
        }
        if session.states.is_empty() || session.states[0].process.terminated {
            break;
        }
    }
    let snap = tracker.snapshot();
    assert!(
        snap.allocs + snap.frees > 0,
        "pool tracker must record events in symbolic mode (allocs={}, frees={})",
        snap.allocs,
        snap.frees
    );
    Ok(())
}
