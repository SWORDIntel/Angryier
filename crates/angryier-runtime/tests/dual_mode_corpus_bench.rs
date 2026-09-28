#![cfg(feature = "xed")]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use angryier_expr::ShardedExprArena;
use angryier_models::KernelPoolTracker;
use angryier_runtime::{Runtime, SymbolicSession};
use angryier_types::{ExpressionNormalizationVersion, SemanticVersion, TargetProfileId};

const STEP_BUDGET: u64 = 2000;
const ITERATIONS_PER_DRIVER: u64 = 10;
const SYMBOLIC_TIMEOUT: Duration = Duration::from_secs(10);

fn fixture_dirs() -> Vec<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/john".to_string());
    vec![
        PathBuf::from(&home).join("Documents/driver_analysis/drivers/sources/caledonia-drivers/bin-elastic"),
        PathBuf::from(&home).join("Documents/byovd-harness/ghidra_pipeline/fixtures/bin"),
    ]
}

fn collect_image_files(dir: &PathBuf) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return files,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            files.push(path);
        }
    }
    files
}

#[derive(Debug, Clone)]
struct DriverBenchmarkResult {
    name: String,
    trace_steps_single: u64,
    concrete_steps: u64,
    concrete_ms: f64,
    concolic_ms: f64,
    symbolic_ms: f64,
    concolic_vs_concrete_overhead: f64,
    concolic_vs_symbolic_multiplier: f64,
}

#[test]
fn dual_mode_corpus_bench() -> Result<(), Box<dyn std::error::Error>> {
    let mut all_files = Vec::new();
    for dir in &fixture_dirs() {
        all_files.extend(collect_image_files(dir));
    }
    all_files.sort();
    all_files.dedup();

    if all_files.is_empty() {
        eprintln!("SKIP: No driver fixtures found in search paths");
        return Ok(());
    }

    // Sort by file size ascending (prefer smaller drivers first)
    all_files.sort_by_key(|p| std::fs::metadata(p).map(|m| m.len()).unwrap_or(u64::MAX));

    let total_discovered = all_files.len();
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));

    let mut results: Vec<DriverBenchmarkResult> = Vec::new();
    let mut load_failed: Vec<String> = Vec::new();
    let mut zero_step_skipped: Vec<String> = Vec::new();

    for file_path in &all_files {
        let file_name = file_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| file_path.display().to_string());

        let bytes = match std::fs::read(file_path) {
            Ok(b) => b,
            Err(_) => {
                load_failed.push(file_name);
                continue;
            }
        };

        // Try loading as PE driver
        let Ok(mut warmup_proc) = runtime.load_pe_driver(&bytes) else {
            load_failed.push(file_name);
            continue;
        };

        // Attach kernel pool model
        let tracker = Arc::new(KernelPoolTracker::new());
        let _ = runtime.attach_kernel_pool_model(&mut warmup_proc, tracker);

        // Warmup & determine baseline trace step count
        let mut trace_steps = 0u64;
        while !warmup_proc.terminated && trace_steps < STEP_BUDGET {
            if runtime.step(&mut warmup_proc).is_err() {
                break;
            }
            trace_steps += 1;
        }

        if trace_steps == 0 {
            zero_step_skipped.push(file_name);
            continue;
        }

        // Mode 1: Concrete
        let mut concrete_steps = 0u64;
        let mut concrete_elapsed = Duration::ZERO;
        for _ in 0..ITERATIONS_PER_DRIVER {
            let Ok(mut proc) = runtime.load_pe_driver(&bytes) else {
                break;
            };
            let tracker = Arc::new(KernelPoolTracker::new());
            let _ = runtime.attach_kernel_pool_model(&mut proc, tracker);
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

        // Mode 2: Concolic
        let mut concolic_steps = 0u64;
        let mut concolic_elapsed = Duration::ZERO;
        for _ in 0..ITERATIONS_PER_DRIVER {
            let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
            let Ok(mut proc) = runtime.load_pe_driver(&bytes) else {
                break;
            };
            let tracker = Arc::new(KernelPoolTracker::new());
            let _ = runtime.attach_kernel_pool_model(&mut proc, tracker);
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
        }

        // Mode 3: Full-Symbolic
        let mut symbolic_steps = 0u64;
        let mut symbolic_elapsed = Duration::ZERO;
        for _ in 0..ITERATIONS_PER_DRIVER {
            let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
            let Ok(mut proc) = runtime.load_pe_driver(&bytes) else {
                break;
            };
            let tracker = Arc::new(KernelPoolTracker::new());
            let _ = runtime.attach_kernel_pool_model(&mut proc, tracker);
            let mut session = SymbolicSession::new(&runtime, arena.as_ref(), proc);
            let start = Instant::now();
            if let Ok(report) = session.run(trace_steps, 32, None, SYMBOLIC_TIMEOUT, false) {
                symbolic_steps += report.steps;
            }
            symbolic_elapsed += start.elapsed();
        }

        let ms = |d: Duration| d.as_secs_f64() * 1000.0;
        let steps_per_sec = |steps: u64, d: Duration| steps as f64 / d.as_secs_f64().max(1e-9);

        let concrete_ms = ms(concrete_elapsed);
        let concolic_ms = ms(concolic_elapsed);
        let symbolic_ms = ms(symbolic_elapsed);

        let _concrete_sps = steps_per_sec(concrete_steps, concrete_elapsed);
        let concolic_sps = steps_per_sec(concolic_steps, concolic_elapsed);
        let symbolic_sps = steps_per_sec(symbolic_steps, symbolic_elapsed);

        let concolic_vs_symbolic_multiplier = concolic_sps / symbolic_sps.max(1e-9);
        let concolic_vs_concrete_overhead = concolic_ms / concrete_ms.max(1e-6);

        results.push(DriverBenchmarkResult {
            name: file_name,
            trace_steps_single: trace_steps,
            concrete_steps,
            concrete_ms,
            concolic_ms,
            symbolic_ms,
            concolic_vs_concrete_overhead,
            concolic_vs_symbolic_multiplier,
        });
    }

    // -------------------------------------------------------------------------
    // Output Benchmark Results Table
    // -------------------------------------------------------------------------
    println!(
        "\n============================================================================================================="
    );
    println!(
        "DUAL-MODE CORPUS TIMING BENCHMARK ({} iterations per mode, budget {} steps)",
        ITERATIONS_PER_DRIVER, STEP_BUDGET
    );
    println!(
        "============================================================================================================="
    );
    println!(
        "{:<38} | {:>6} | {:>11} | {:>11} | {:>11} | {:>17} | {:>17}",
        "Driver Name", "Steps", "Concrete ms", "Concolic ms", "Symbolic ms", "Concolic/Concrete", "Concolic/Symbolic"
    );
    println!(
        "{:-<38}-+-{:-<6}-+-{:-<11}-+-{:-<11}-+-{:-<11}-+-{:-<17}-+-{:-<17}",
        "", "", "", "", "", "", ""
    );

    for r in &results {
        println!(
            "{:<38} | {:>6} | {:>11.3} | {:>11.3} | {:>11.3} | {:>16.2}x | {:>16.2}x",
            r.name,
            r.trace_steps_single,
            r.concrete_ms,
            r.concolic_ms,
            r.symbolic_ms,
            r.concolic_vs_concrete_overhead,
            r.concolic_vs_symbolic_multiplier
        );
    }
    println!(
        "=============================================================================================================\n"
    );

    // -------------------------------------------------------------------------
    // Aggregate Metrics & Statistics
    // -------------------------------------------------------------------------
    let n = results.len();
    assert!(n > 0, "No drivers were benchmarked");

    let mut multipliers: Vec<f64> = results.iter().map(|r| r.concolic_vs_symbolic_multiplier).collect();
    multipliers.sort_by(|a, b| a.total_cmp(b));

    let mean_multiplier: f64 = multipliers.iter().sum::<f64>() / n as f64;
    let median_multiplier: f64 = if n % 2 == 1 {
        multipliers[n / 2]
    } else {
        (multipliers[n / 2 - 1] + multipliers[n / 2]) / 2.0
    };

    let log_sum: f64 = multipliers.iter().map(|m| m.max(1e-9).ln()).sum();
    let geom_mean_multiplier: f64 = (log_sum / n as f64).exp();

    let mut overheads: Vec<f64> = results.iter().map(|r| r.concolic_vs_concrete_overhead).collect();
    overheads.sort_by(|a, b| a.total_cmp(b));
    let mean_overhead: f64 = overheads.iter().sum::<f64>() / n as f64;
    let median_overhead: f64 = if n % 2 == 1 {
        overheads[n / 2]
    } else {
        (overheads[n / 2 - 1] + overheads[n / 2]) / 2.0
    };

    // Honest negatives: where concolic is NOT faster than symbolic (multiplier <= 1.0)
    let honest_negatives: Vec<&DriverBenchmarkResult> = results
        .iter()
        .filter(|r| r.concolic_vs_symbolic_multiplier <= 1.0)
        .collect();

    let total_steps_all: u64 = results.iter().map(|r| r.concrete_steps).sum();

    let min_driver = results
        .iter()
        .min_by(|a, b| {
            a.concolic_vs_symbolic_multiplier
                .total_cmp(&b.concolic_vs_symbolic_multiplier)
        })
        .map_or("", |r| r.name.as_str());
    let max_driver = results
        .iter()
        .max_by(|a, b| {
            a.concolic_vs_symbolic_multiplier
                .total_cmp(&b.concolic_vs_symbolic_multiplier)
        })
        .map_or("", |r| r.name.as_str());

    println!("=================================================================================");
    println!("AGGREGATE CORPUS PERFORMANCE METRICS");
    println!("=================================================================================");
    println!("Coverage:");
    println!("  Total discovered:   {} images", total_discovered);
    println!("  Load failed:        {} images", load_failed.len());
    println!("  Zero-step skipped:  {} images", zero_step_skipped.len());
    println!(
        "  Benchmarked:        {} drivers ({}% of discovered)",
        n,
        (n * 100) / total_discovered
    );
    println!("  Total steps timed:  {} steps across all modes", total_steps_all * 3);
    println!();
    println!("Concolic vs Full-Symbolic Speed Multiplier:");
    println!("  Mean Multiplier:        {:.2}x", mean_multiplier);
    println!("  Median Multiplier:      {:.2}x", median_multiplier);
    println!("  Geometric Mean:         {:.2}x", geom_mean_multiplier);
    println!(
        "  Min Multiplier:         {:.2}x ({})",
        multipliers.first().copied().unwrap_or(0.0),
        min_driver
    );
    println!(
        "  Max Multiplier:         {:.2}x ({})",
        multipliers.last().copied().unwrap_or(0.0),
        max_driver
    );
    println!();
    println!("Concolic vs Concrete Overhead:");
    println!("  Mean Overhead:          {:.2}x", mean_overhead);
    println!("  Median Overhead:        {:.2}x", median_overhead);
    println!();
    println!("Honest Negatives (Concolic NOT faster than Full-Symbolic, multiplier <= 1.00x):");
    println!(
        "  Count: {} / {} drivers ({:.1}%)",
        honest_negatives.len(),
        n,
        (honest_negatives.len() as f64 / n as f64) * 100.0
    );
    if honest_negatives.is_empty() {
        println!("  (None - Concolic was faster across 100% of tested drivers)");
    } else {
        for hn in &honest_negatives {
            println!(
                "  - {:<36} : {:.2}x multiplier ({} steps, concolic={:.3}ms, symbolic={:.3}ms)",
                hn.name, hn.concolic_vs_symbolic_multiplier, hn.trace_steps_single, hn.concolic_ms, hn.symbolic_ms
            );
        }
    }
    println!("=================================================================================\n");

    Ok(())
}
