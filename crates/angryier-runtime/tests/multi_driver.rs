//! Test multiple real drivers from the corpus.
#![cfg(feature = "xed")]

use angryier_runtime::Runtime;
use angryier_types::{SemanticVersion, TargetProfileId};

fn test_driver(name: &str, path: &str) {
    let image = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => { eprintln!("SKIP {}", name); return; }
    };

    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = match runtime.load_pe_driver(&image) {
        Ok(p) => p,
        Err(e) => { eprintln!("{}: LOAD FAILED {:?}", name, e); return; }
    };
    let tracker = std::sync::Arc::new(angryier_models::KernelPoolTracker::new());
    let _ = runtime.attach_kernel_pool_model(&mut process, tracker.clone());

    let mut steps = 0;
    for _ in 0..500 {
        match runtime.step(&mut process) {
            Ok(_) => steps += 1,
            Err(e) => {
                eprintln!("{}: {} steps, blocked: {:?}", name, steps, e);
                return;
            }
        }
        if process.terminated {
            let report = tracker.snapshot();
            eprintln!("{}: {} steps, TERMINATED, pool: a={} f={} df={}",
                name, steps, report.allocs, report.frees, report.double_frees.len());
            return;
        }
    }
    eprintln!("{}: {} steps (limit)", name, steps);
}

#[test]
fn multi_driver_execution() {
    let base = "/home/john/Documents/driver_analysis/drivers/sources/caledonia-drivers/bin-elastic";
    test_driver("GVCIDrv64", &format!("{}/GVCIDrv64.sys", base));
    test_driver("AsIO2", &format!("{}/AsIO2.sys", base));
    test_driver("AMDRyzenMaster", &format!("{}/AMDRyzenMasterDriver.sys", base));
    test_driver("AMDPowerProfiler", &format!("{}/AMDPowerProfiler.sys", base));

    // Fixtures
    let fx = "/home/john/Documents/byovd-harness/ghidra_pipeline/fixtures/bin";
    test_driver("double_free_O2", &format!("{}/double_free_vuln_O2.sys", fx));
    test_driver("allocsize_vuln_O0", &format!("{}/allocsize_overflow_vuln_O0.sys", fx));
    test_driver("safe_double_O0", &format!("{}/safe_double_free_O0.sys", fx));
}
