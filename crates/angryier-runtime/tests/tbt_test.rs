#![cfg(feature = "xed")]
use angryier_runtime::Runtime;
use angryier_types::{SemanticVersion, TargetProfileId};

#[test]
fn tbtbus_execution() {
    let image = match std::fs::read("/tmp/tbt_driver.sys") {
        Ok(b) => b,
        Err(_) => {
            eprintln!("SKIP: TbtBusDrv not available");
            return;
        }
    };
    eprintln!("TbtBusDrv: {} bytes", image.len());

    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = match runtime.load_pe_driver(&image) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("LOAD FAILED: {:?}", e);
            return;
        }
    };
    let tracker = std::sync::Arc::new(angryier_models::KernelPoolTracker::new());
    let _ = runtime.attach_kernel_pool_model(&mut process, tracker.clone());

    eprintln!(
        "entry={}, imports={}",
        process
            .pc()
            .map(|p| format!("{p:#x}"))
            .unwrap_or_else(|_| "err".to_string()),
        process.pe_imports().count()
    );

    let mut steps = 0;
    for i in 0..1000 {
        match runtime.step(&mut process) {
            Ok(_) => steps += 1,
            Err(e) => {
                eprintln!("blocked at step {} pc={:#x}: {:?}", i + 1, process.pc().unwrap_or(0), e);
                break;
            }
        }
        if process.terminated {
            eprintln!("TERMINATED at step {}, simprocs={}", steps, process.simproc_dispatches);
            let report = tracker.snapshot();
            eprintln!(
                "pool: a={} f={} df={}",
                report.allocs,
                report.frees,
                report.double_frees.len()
            );
            return;
        }
    }
    eprintln!("{} steps (limit), simprocs={}", steps, process.simproc_dispatches);
    let report = tracker.snapshot();
    eprintln!(
        "pool: a={} f={} df={}",
        report.allocs,
        report.frees,
        report.double_frees.len()
    );
}
