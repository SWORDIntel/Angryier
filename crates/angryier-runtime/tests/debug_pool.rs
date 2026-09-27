#![cfg(feature = "xed")]
use angryier_runtime::Runtime;
use angryier_types::{SemanticVersion, TargetProfileId};

#[test]
fn debug_pool_tracker() {
    let path = "/home/john/Documents/byovd-harness/ghidra_pipeline/fixtures/bin/double_free_vuln_O2.sys";
    let image = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("SKIP: double_free_vuln_O2.sys not available");
            return;
        }
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let Ok(mut process) = runtime.load_pe_driver(&image) else {
        eprintln!("LOAD FAILED");
        return;
    };
    let tracker = std::sync::Arc::new(angryier_models::KernelPoolTracker::new());
    if runtime.attach_kernel_pool_model(&mut process, tracker.clone()).is_err() {
        eprintln!("ATTACH FAILED");
        return;
    }

    // Verify tracker is shared
    eprintln!("tracker Arc ptr: {:p}", std::sync::Arc::as_ptr(&tracker));
    if let Some(kp) = &process.kernel_pool {
        eprintln!("kernel_pool Arc ptr: {:p}", std::sync::Arc::as_ptr(kp));
    } else {
        eprintln!("kernel_pool is NONE!");
    }

    // Run and check
    let Ok(summary) = runtime.run(&mut process, 1000) else {
        eprintln!("RUN FAILED");
        return;
    };
    eprintln!(
        "simproc_dispatches={} terminated={}",
        summary.simproc_dispatches, process.terminated
    );
    eprintln!("pool snapshot: {:?}", tracker.snapshot());
    // private field, snapshot only
}

/// Verify GVCIDrv64's 6 SimProcedure dispatches — which kernel APIs were called?
#[test]
fn gvcidrv_dispatch_detail() {
    let path = "/home/john/Documents/driver_analysis/drivers/sources/caledonia-drivers/bin-elastic/GVCIDrv64.sys";
    let image = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("SKIP: GVCIDrv64.sys not available");
            return;
        }
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let Ok(mut process) = runtime.load_pe_driver(&image) else {
        eprintln!("LOAD FAILED");
        return;
    };
    let tracker = std::sync::Arc::new(angryier_models::KernelPoolTracker::new());
    if runtime.attach_kernel_pool_model(&mut process, tracker.clone()).is_err() {
        eprintln!("ATTACH FAILED");
        return;
    }

    // List what hooks are registered
    let mut hooked = Vec::new();
    for (addr, (_, name)) in &process.pe_import_stubs {
        let hook = process
            .simproc_instances
            .get(addr)
            .map(|p| p.name().to_string())
            .unwrap_or_else(|| "unhooked".to_string());
        hooked.push(format!("  {:#x} {} → {}", addr, name, hook));
    }
    eprintln!("IAT hooks ({}):", hooked.len());
    for h in hooked.iter().take(10) {
        eprintln!("{}", h);
    }

    // Run and check
    let Ok(summary) = runtime.run(&mut process, 1000) else {
        eprintln!("RUN FAILED");
        return;
    };
    eprintln!(
        "dispatches={} terminated={}",
        summary.simproc_dispatches, process.terminated
    );
    let report = tracker.snapshot();
    eprintln!(
        "pool: a={} f={} df={}",
        report.allocs,
        report.frees,
        report.double_frees.len()
    );
}
