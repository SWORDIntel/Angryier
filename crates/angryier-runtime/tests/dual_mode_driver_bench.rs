#![cfg(feature = "xed")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use angryier_expr::ShardedExprArena;
use angryier_models::KernelPoolTracker;
use angryier_runtime::{Runtime, SymbolicSession};
use angryier_types::{ExpressionNormalizationVersion, SemanticVersion, TargetProfileId};

fn fixture_candidate_paths() -> Vec<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/john".to_string());
    vec![
        PathBuf::from(&home)
            .join("Documents/driver_analysis/drivers/sources/caledonia-drivers/bin-elastic/GVCIDrv64.sys"),
        PathBuf::from(&home)
            .join("Documents/byovd-harness/ghidra_pipeline/fixtures/bin/double_free_vuln_import_O2.sys"),
    ]
}

#[test]
fn dual_mode_driver_bench() -> Result<(), Box<dyn std::error::Error>> {
    let mut found = None;
    for path in fixture_candidate_paths() {
        if let Ok(bytes) = std::fs::read(&path) {
            let filename = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| path.display().to_string());
            found = Some((filename, path, bytes));
            break;
        }
    }

    let Some((driver_name, driver_path, image_bytes)) = found else {
        eprintln!("SKIP: No driver fixture found in search paths");
        return Ok(());
    };

    println!("\n================================================================================");
    println!("DUAL-MODE RELEASE PERFORMANCE BENCHMARK ON REAL DRIVER");
    println!("Fixture: {} ({})", driver_name, driver_path.display());
    println!("Image size: {} bytes", image_bytes.len());
    println!("================================================================================");

    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));

    // -------------------------------------------------------------------------
    // Warmup & Deterministic Baseline
    // -------------------------------------------------------------------------
    let mut warmup_proc = runtime.load_pe_driver(&image_bytes)?;
    let tracker = Arc::new(KernelPoolTracker::new());
    runtime.attach_kernel_pool_model(&mut warmup_proc, tracker)?;
    let mut trace_steps = 0u64;
    while !warmup_proc.terminated && trace_steps < 5000 {
        runtime.step(&mut warmup_proc)?;
        trace_steps += 1;
    }

    assert!(trace_steps > 0, "Driver execution stepped 0 instructions");
    assert!(warmup_proc.terminated, "Driver must terminate cleanly at exit hook");
    println!(
        "Baseline trace: {} steps (terminated cleanly: {})\n",
        trace_steps, warmup_proc.terminated
    );

    const ITERATIONS: u64 = 50;

    // -------------------------------------------------------------------------
    // Mode 1: Concrete fast path (pure execution stepping time)
    // -------------------------------------------------------------------------
    let mut concrete_steps = 0u64;
    let mut concrete_elapsed = Duration::ZERO;
    for _ in 0..ITERATIONS {
        let mut proc = runtime.load_pe_driver(&image_bytes)?;
        let tracker = Arc::new(KernelPoolTracker::new());
        runtime.attach_kernel_pool_model(&mut proc, tracker)?;
        let start = Instant::now();
        for _ in 0..trace_steps {
            if proc.terminated {
                break;
            }
            if runtime.step(&mut proc).is_ok() {
                concrete_steps += 1;
            } else {
                break;
            }
        }
        concrete_elapsed += start.elapsed();
    }

    // -------------------------------------------------------------------------
    // Mode 2: Concolic session (EXPLORE: pure execution stepping time)
    // -------------------------------------------------------------------------
    let mut concolic_steps = 0u64;
    let mut concolic_elapsed = Duration::ZERO;
    let mut concolic_path_constraints = 0usize;
    let mut concolic_requires_prove = false;
    for i in 0..ITERATIONS {
        let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
        let mut proc = runtime.load_pe_driver(&image_bytes)?;
        let tracker = Arc::new(KernelPoolTracker::new());
        runtime.attach_kernel_pool_model(&mut proc, tracker)?;
        let mut session = runtime.concolic(proc, arena.as_ref());
        let start = Instant::now();
        for _ in 0..trace_steps {
            if session.process.terminated {
                break;
            }
            if session.step().is_ok() {
                concolic_steps += 1;
            } else {
                break;
            }
        }
        concolic_elapsed += start.elapsed();
        if i == 0 {
            concolic_path_constraints = session.path_constraints().len();
            concolic_requires_prove = session.requires_prove();
        }
    }

    // -------------------------------------------------------------------------
    // Mode 3: Full Symbolic evaluation (PROVE: pure execution stepping time)
    // -------------------------------------------------------------------------
    let mut symbolic_steps = 0u64;
    let mut symbolic_elapsed = Duration::ZERO;
    let mut symbolic_forks = 0u64;
    let mut symbolic_peak_states = 0u64;
    let mut symbolic_failed = 0u64;
    let mut symbolic_terminated = 0u64;
    let mut symbolic_live_at_end = 0u64;
    for i in 0..ITERATIONS {
        let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
        let mut proc = runtime.load_pe_driver(&image_bytes)?;
        let tracker = Arc::new(KernelPoolTracker::new());
        runtime.attach_kernel_pool_model(&mut proc, tracker)?;
        let mut session = SymbolicSession::new(&runtime, arena.as_ref(), proc);
        let start = Instant::now();
        let report = session.run(trace_steps, 32, None, Duration::from_secs(10), false)?;
        symbolic_elapsed += start.elapsed();
        symbolic_steps += report.steps;
        if i == 0 {
            symbolic_forks = report.forks;
            symbolic_peak_states = report.peak_states;
            symbolic_failed = report.failed;
            symbolic_terminated = report.terminated;
            symbolic_live_at_end = report.live_states;
        }
    }

    // -------------------------------------------------------------------------
    // Metrics & Calculations
    // -------------------------------------------------------------------------
    let ms = |d: Duration| d.as_secs_f64() * 1000.0;
    let steps_per_sec = |steps: u64, d: Duration| steps as f64 / d.as_secs_f64().max(1e-9);

    let concrete_ms = ms(concrete_elapsed);
    let concolic_ms = ms(concolic_elapsed);
    let symbolic_ms = ms(symbolic_elapsed);

    let concrete_sps = steps_per_sec(concrete_steps, concrete_elapsed);
    let concolic_sps = steps_per_sec(concolic_steps, concolic_elapsed);
    let symbolic_sps = steps_per_sec(symbolic_steps, symbolic_elapsed);

    // Multipliers
    let concolic_vs_symbolic_multiplier = concolic_sps / symbolic_sps.max(1e-9);
    let concolic_vs_concrete_overhead = concolic_ms / concrete_ms.max(1e-9);
    let symbolic_vs_concrete_slowdown = symbolic_ms / concrete_ms.max(1e-9);

    // -------------------------------------------------------------------------
    // Performance Summary Table
    // -------------------------------------------------------------------------
    println!(
        "--- PERFORMANCE BENCHMARK RESULTS ({} iterations per mode) ---",
        ITERATIONS
    );
    println!("+---------------+------------+------------+---------------+");
    println!("| Mode          |      Steps |    Wall ms |       Steps/s |");
    println!("+---------------+------------+------------+---------------+");
    println!(
        "| Concrete      | {:10} | {:10.2} | {:13.1} |",
        concrete_steps, concrete_ms, concrete_sps
    );
    println!(
        "| Concolic      | {:10} | {:10.2} | {:13.1} |",
        concolic_steps, concolic_ms, concolic_sps
    );
    println!(
        "| Full-Symbolic | {:10} | {:10.2} | {:13.1} |",
        symbolic_steps, symbolic_ms, symbolic_sps
    );
    println!("+---------------+------------+------------+---------------+\n");

    println!("--- MULTIPLIERS & GATE A TARGET ---");
    println!(
        "- Concolic vs Full-Symbolic Speed Multiplier: {:.2}x (Gate A Target: 5-10x)",
        concolic_vs_symbolic_multiplier
    );
    println!(
        "- Concolic / Concrete Overhead:               {:.2}x ({:.1}% concrete speed)",
        concolic_vs_concrete_overhead,
        (1.0 / concolic_vs_concrete_overhead) * 100.0
    );
    println!(
        "- Full-Symbolic / Concrete Slowdown:          {:.2}x ({:.1}% concrete speed)",
        symbolic_vs_concrete_slowdown,
        (1.0 / symbolic_vs_concrete_slowdown) * 100.0
    );

    println!("\n--- EXECUTION DETAILS ---");
    println!(
        "- Step budget per iteration: {} steps (100% of driver trace)",
        trace_steps
    );
    println!(
        "- Total steps per mode:      {} steps across {} runs",
        trace_steps * ITERATIONS,
        ITERATIONS
    );
    println!(
        "- Concolic detail:           {} path constraints, requires_prove: {}",
        concolic_path_constraints, concolic_requires_prove
    );
    println!(
        "- Full-Symbolic detail:      {} forks/run, peak {} live states, {} failed, {} terminated, {} live at stop",
        symbolic_forks, symbolic_peak_states, symbolic_failed, symbolic_terminated, symbolic_live_at_end
    );
    println!("================================================================================\n");

    // -------------------------------------------------------------------------
    // Assertions
    // -------------------------------------------------------------------------
    assert_eq!(concrete_steps, trace_steps * ITERATIONS);
    assert_eq!(concolic_steps, trace_steps * ITERATIONS);
    assert_eq!(symbolic_steps, trace_steps * ITERATIONS);
    assert!(concrete_elapsed.as_secs_f64() > 0.0);
    assert!(concolic_elapsed.as_secs_f64() > 0.0);
    assert!(symbolic_elapsed.as_secs_f64() > 0.0);

    Ok(())
}
