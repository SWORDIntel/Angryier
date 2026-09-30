#![cfg(feature = "xed")]
// Quick test: load a real signed driver with actual kernel imports
// and see how far execution gets
#[test]
fn gvcidrv64_execution() -> Result<(), Box<dyn std::error::Error>> {
    let path = "/home/john/Documents/driver_analysis/drivers/sources/caledonia-drivers/bin-elastic/GVCIDrv64.sys";
    let image = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => {
            eprintln!("SKIP: driver not found");
            return Ok(());
        }
    };

    let runtime = angryier_runtime::Runtime::with_native_xed(
        angryier_types::SemanticVersion(1),
        angryier_types::TargetProfileId(1),
    );
    let mut process = runtime.load_pe_driver(&image)?;
    let tracker = std::sync::Arc::new(angryier_models::KernelPoolTracker::new());
    runtime.attach_kernel_pool_model(&mut process, tracker.clone())?;

    eprintln!(
        "loaded GVCIDrv64.sys ({} bytes), entry={:#x}",
        image.len(),
        process.pc()?
    );

    let mut steps = 0;
    let mut last_pc = 0;
    for i in 0..500 {
        last_pc = process.pc()?;
        match runtime.step(&mut process) {
            Ok(_) => steps += 1,
            Err(e) => {
                eprintln!("stopped at step {} pc={:#x}: {:?}", i + 1, last_pc, e);
                break;
            }
        }
        if process.terminated {
            eprintln!("terminated at step {}", i + 1);
            break;
        }
    }
    eprintln!("executed {} steps (last pc={:#x})", steps, last_pc);

    let report = tracker.snapshot();
    eprintln!(
        "pool: allocs={} frees={} double_frees={}",
        report.allocs,
        report.frees,
        report.double_frees.len()
    );

    // List which imports are hooked
    let imports: Vec<_> = process.pe_imports().collect();
    eprintln!("imports: {} from IAT", imports.len());
    for (_, dll, name) in imports.iter().take(8) {
        eprintln!("  {}!{}", dll, name);
    }

    Ok(())
}
