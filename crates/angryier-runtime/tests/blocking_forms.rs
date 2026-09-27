//! Diagnostic: load multiple real drivers, run until blocked, and report
//! which unmapped instruction forms stop execution. This gives the full
//! scope of ISA coverage work needed for real driver analysis.

#![cfg(feature = "xed")]

use angryier_runtime::Runtime;
use angryier_types::{SemanticVersion, TargetProfileId};

fn test_driver(path: &str, max_steps: usize) {
    let image = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("SKIP {}", path.rsplit('/').next().unwrap_or("?"));
            return;
        }
    };

    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = match runtime.load_pe_driver(&image) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{}: LOAD FAILED {:?}", path.rsplit('/').next().unwrap_or("?"), e);
            return;
        }
    };
    let tracker = std::sync::Arc::new(angryier_models::KernelPoolTracker::new());
    let _ = runtime.attach_kernel_pool_model(&mut process, tracker.clone());

    let mut steps = 0;
    for i in 0..max_steps {
        match runtime.step(&mut process) {
            Ok(_) => steps += 1,
            Err(e) => {
                let name = path.rsplit('/').next().unwrap_or("?");
                eprintln!(
                    "{}: {} steps, blocked at pc={:#x}: {:?}",
                    name,
                    steps,
                    process.pc().unwrap_or(0),
                    e
                );
                return;
            }
        }
        if process.terminated {
            eprintln!(
                "{}: {} steps, TERMINATED cleanly",
                path.rsplit('/').next().unwrap_or("?"),
                steps
            );
            return;
        }
    }
    eprintln!(
        "{}: {} steps (step limit reached)",
        path.rsplit('/').next().unwrap_or("?"),
        steps
    );
}

#[test]
fn scan_blocking_forms() {
    let drivers = [
        "/home/john/Documents/driver_analysis/drivers/sources/caledonia-drivers/bin-elastic/GVCIDrv64.sys",
        "/home/john/Documents/byovd-harness/ghidra_pipeline/fixtures/bin/double_free_vuln_O2.sys",
        "/home/john/Documents/byovd-harness/ghidra_pipeline/fixtures/bin/probe_missing_vuln_O2.sys",
        "/home/john/Documents/byovd-harness/ghidra_pipeline/fixtures/bin/safe_double_free_O0.sys",
        "/home/john/Documents/byovd-harness/ghidra_pipeline/fixtures/bin/allocsize_overflow_vuln_O0.sys",
    ];
    for path in &drivers {
        test_driver(path, 500);
    }
}
