//! Concolic-vs-concrete fidelity test across the FULL driver corpus.
//!
//! Evaluates all loadable x64 drivers from the test corpus in both concrete
//! and concolic EXPLORE modes (with the kernel pool model attached) up to a
//! bounded budget (5000 steps), asserting identical steps, termination status,
//! and RAX exit/register values, while tracking and reporting `requires_prove`.
#![cfg(feature = "xed")]

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use angryier_arch::Decoder;
use angryier_arch_intel64::register_id;
use angryier_expr::ShardedExprArena;
use angryier_memory::{ByteValue, LayeredMemory};
use angryier_runtime::Runtime;
use angryier_types::{ExpressionNormalizationVersion, SemanticVersion, TargetProfileId};

const STEP_BUDGET: u64 = 5000;

fn fixture_dirs() -> Vec<PathBuf> {
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => "/home/john".to_string(),
    };
    vec![
        PathBuf::from(&home).join("Documents/driver_analysis/drivers/sources/caledonia-drivers/bin-elastic"),
        PathBuf::from(&home).join("Documents/byovd-harness/ghidra_pipeline/fixtures/bin"),
    ]
}

fn collect_image_files(dir: &Path) -> Vec<PathBuf> {
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
    files.sort();
    files
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExecutionResult {
    steps: u64,
    terminated: bool,
    rax: u64,
    final_pc: u64,
    error: Option<String>,
}

#[derive(Debug, Clone)]
struct ConcolicExecutionResult {
    exec: ExecutionResult,
    requires_prove: bool,
    debt_entries: Vec<(angryier_types::AnalysisDebtKind, u64)>,
}

fn run_concrete(
    runtime: &Runtime<angryier_runtime::XedFormTranslator<angryier_arch_xed_ffi::XedDecoder>>,
    image: &[u8],
    max_steps: u64,
) -> Option<ExecutionResult> {
    let mut process = runtime.load_pe_driver(image).ok()?;
    let tracker = Arc::new(angryier_models::KernelPoolTracker::new());
    let _ = runtime.attach_kernel_pool_model(&mut process, tracker.clone());

    let mut steps = 0u64;
    let mut err = None;
    for _ in 0..max_steps {
        if let Err(e) = runtime.step(&mut process) {
            err = Some(format!("{e:?}"));
            break;
        }
        steps += 1;
        if process.terminated {
            break;
        }
    }
    let rax = process.read_register(register_id::GPR_BASE).unwrap_or(0);
    let final_pc = process.pc().unwrap_or(0);
    Some(ExecutionResult {
        steps,
        terminated: process.terminated,
        rax,
        final_pc,
        error: err,
    })
}

fn run_concolic(
    runtime: &Runtime<angryier_runtime::XedFormTranslator<angryier_arch_xed_ffi::XedDecoder>>,
    image: &[u8],
    max_steps: u64,
) -> Option<ConcolicExecutionResult> {
    let mut process = runtime.load_pe_driver(image).ok()?;
    let tracker = Arc::new(angryier_models::KernelPoolTracker::new());
    let _ = runtime.attach_kernel_pool_model(&mut process, tracker.clone());
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = runtime.concolic(process, arena.as_ref());

    let mut steps = 0u64;
    let mut err = None;
    for _ in 0..max_steps {
        if let Err(e) = session.step() {
            err = Some(format!("{e:?}"));
            break;
        }
        steps += 1;
        if session.process.terminated {
            break;
        }
    }
    let rax = session.process.read_register(register_id::GPR_BASE).unwrap_or(0);
    let final_pc = session.process.pc().unwrap_or(0);
    let requires_prove = session.requires_prove();
    let debt_entries = session
        .process
        .state
        .fidelity
        .entries
        .iter()
        .map(|e| (e.kind, e.source))
        .collect();
    Some(ConcolicExecutionResult {
        exec: ExecutionResult {
            steps,
            terminated: session.process.terminated,
            rax,
            final_pc,
            error: err,
        },
        requires_prove,
        debt_entries,
    })
}

const GPR_NAMES: [&str; 16] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
];

fn diagnose_divergence(
    runtime: &Runtime<angryier_runtime::XedFormTranslator<angryier_arch_xed_ffi::XedDecoder>>,
    image: &[u8],
    max_steps: u64,
) -> String {
    let Ok(mut proc_c) = runtime.load_pe_driver(image) else {
        return "Failed to load concrete driver during diagnosis".to_string();
    };
    let tracker_c = Arc::new(angryier_models::KernelPoolTracker::new());
    let _ = runtime.attach_kernel_pool_model(&mut proc_c, tracker_c);

    let Ok(proc_x) = runtime.load_pe_driver(image) else {
        return "Failed to load concolic driver during diagnosis".to_string();
    };
    let tracker_x = Arc::new(angryier_models::KernelPoolTracker::new());
    let _ = runtime.attach_kernel_pool_model(&mut proc_x.clone(), tracker_x);
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session_x = runtime.concolic(proc_x, arena.as_ref());

    for step_idx in 0..max_steps {
        let pc_c = proc_c.pc().unwrap_or(0);
        let pc_x = session_x.process.pc().unwrap_or(0);

        if pc_c != pc_x {
            return format!(
                "Divergence before step {step_idx}: PC mismatch! concrete PC={pc_c:#x}, concolic PC={pc_x:#x}"
            );
        }

        // Compare all GPRs and RFLAGS before stepping
        for (i, name) in GPR_NAMES.iter().enumerate() {
            let val_c = proc_c.read_register(register_id::GPR_BASE + i as u32).unwrap_or(0);
            let val_x = session_x
                .process
                .read_register(register_id::GPR_BASE + i as u32)
                .unwrap_or(0);
            if val_c != val_x {
                return format!(
                    "Divergence before step {step_idx} at PC {pc_c:#x}: register {name} mismatch! concrete={val_c:#x}, concolic={val_x:#x}"
                );
            }
        }
        let rflags_c = proc_c.read_register(register_id::RFLAGS.0).unwrap_or(0);
        let rflags_x = session_x.process.read_register(register_id::RFLAGS.0).unwrap_or(0);
        if rflags_c != rflags_x {
            return format!(
                "Divergence before step {step_idx} at PC {pc_c:#x}: RFLAGS mismatch! concrete={rflags_c:#x}, concolic={rflags_x:#x}"
            );
        }

        let res_c = runtime.step(&mut proc_c);
        let res_x = session_x.step();

        match (&res_c, &res_x) {
            (Ok(out_c), Ok(out_x)) => {
                let post_pc_c = proc_c.pc().unwrap_or(0);
                let post_pc_x = session_x.process.pc().unwrap_or(0);
                if post_pc_c != post_pc_x {
                    return format!(
                        "Divergence after step {step_idx} (executed PC {pc_c:#x}):\n  Concrete outcome: {out_c:?}, next PC={post_pc_c:#x}\n  Concolic outcome: {out_x:?}, next PC={post_pc_x:#x}"
                    );
                }
                for (i, name) in GPR_NAMES.iter().enumerate() {
                    let val_c = proc_c.read_register(register_id::GPR_BASE + i as u32).unwrap_or(0);
                    let val_x = session_x
                        .process
                        .read_register(register_id::GPR_BASE + i as u32)
                        .unwrap_or(0);
                    if val_c != val_x {
                        return format!(
                            "Divergence after step {step_idx} (executed PC {pc_c:#x}):\n  Register {name} mismatch: concrete={val_c:#x}, concolic={val_x:#x}"
                        );
                    }
                }
            }
            (Err(err_c), Ok(_)) => {
                return format!(
                    "Divergence at step {step_idx} (PC {pc_c:#x}): concrete failed with {err_c:?}, concolic succeeded"
                );
            }
            (Ok(_), Err(err_x)) => {
                return format!(
                    "Divergence at step {step_idx} (PC {pc_c:#x}): concrete succeeded, concolic failed with {err_x:?}"
                );
            }
            (Err(err_c), Err(err_x)) => {
                if format!("{err_c:?}") != format!("{err_x:?}") {
                    return format!(
                        "Divergence at step {step_idx} (PC {pc_c:#x}): both failed but errors differ:\n  concrete: {err_c:?}\n  concolic: {err_x:?}"
                    );
                }
                break;
            }
        }

        if proc_c.terminated || session_x.process.terminated {
            if proc_c.terminated != session_x.process.terminated {
                return format!(
                    "Divergence after step {step_idx}: termination mismatch! concrete.terminated={}, concolic.terminated={}",
                    proc_c.terminated, session_x.process.terminated
                );
            }
            break;
        }
    }

    "No single-step divergence found (divergence may be in final state comparison)".to_string()
}

#[derive(Default)]
struct CorpusSummary {
    total_images: usize,
    loadable_count: usize,
    load_failed_count: usize,
    exact_match_count: usize,
    divergence_count: usize,
    shadow_debt_count: usize,
    clean_match_count: usize, // matched with requires_prove = false
}

#[test]
fn concolic_corpus_fidelity_sweep() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));

    let mut all_files = Vec::new();
    for dir in &fixture_dirs() {
        all_files.extend(collect_image_files(dir));
    }
    all_files.sort();
    all_files.dedup();

    let mut summary = CorpusSummary {
        total_images: all_files.len(),
        ..Default::default()
    };

    struct DriverReport {
        name: String,
        concrete_steps: u64,
        concolic_steps: u64,
        concrete_term: bool,
        concolic_term: bool,
        concrete_rax: u64,
        concolic_rax: u64,
        matched: bool,
        requires_prove: bool,
        debt_details: Vec<String>,
        elapsed_s: f64,
        diagnostic: Option<String>,
    }

    let mut reports: Vec<DriverReport> = Vec::new();
    let mut load_fails: Vec<String> = Vec::new();

    let start_total = Instant::now();

    for file_path in &all_files {
        let file_name = file_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| file_path.display().to_string());

        let bytes = match std::fs::read(file_path) {
            Ok(b) => b,
            Err(_) => continue,
        };

        // Try concrete run
        let start_driver = Instant::now();
        let concrete_res = run_concrete(&runtime, &bytes, STEP_BUDGET);
        let concolic_res = run_concolic(&runtime, &bytes, STEP_BUDGET);

        let (c_res, x_res) = match (concrete_res, concolic_res) {
            (Some(c), Some(x)) => (c, x),
            (None, None) => {
                summary.load_failed_count += 1;
                load_fails.push(file_name);
                continue;
            }
            (Some(c), None) => {
                // Concrete loaded but concolic failed to load/start
                summary.loadable_count += 1;
                summary.divergence_count += 1;
                let elapsed_s = start_driver.elapsed().as_secs_f64();
                reports.push(DriverReport {
                    name: file_name,
                    concrete_steps: c.steps,
                    concolic_steps: 0,
                    concrete_term: c.terminated,
                    concolic_term: false,
                    concrete_rax: c.rax,
                    concolic_rax: 0,
                    matched: false,
                    requires_prove: false,
                    debt_details: Vec::new(),
                    elapsed_s,
                    diagnostic: Some("Concolic session failed to load/initialize".to_string()),
                });
                continue;
            }
            (None, Some(_)) => {
                // Concrete failed but concolic succeeded
                summary.loadable_count += 1;
                summary.divergence_count += 1;
                let elapsed_s = start_driver.elapsed().as_secs_f64();
                reports.push(DriverReport {
                    name: file_name,
                    concrete_steps: 0,
                    concolic_steps: 0,
                    concrete_term: false,
                    concolic_term: false,
                    concrete_rax: 0,
                    concolic_rax: 0,
                    matched: false,
                    requires_prove: false,
                    debt_details: Vec::new(),
                    elapsed_s,
                    diagnostic: Some("Concrete run failed to load/initialize".to_string()),
                });
                continue;
            }
        };

        summary.loadable_count += 1;
        let elapsed_s = start_driver.elapsed().as_secs_f64();

        let matched = c_res == x_res.exec;
        let requires_prove = x_res.requires_prove;

        let debt_details: Vec<String> = if requires_prove {
            let mut seen_pcs = std::collections::HashSet::new();
            let mut unique_entries = Vec::new();
            for &(kind, pc) in &x_res.debt_entries {
                if seen_pcs.insert(pc) {
                    unique_entries.push((kind, pc));
                }
            }
            unique_entries
                .iter()
                .map(|&(kind, pc)| {
                    let insn_bytes = match runtime.load_pe_driver(&bytes) {
                        Ok(proc) => proc.state.memory.read(pc, 15).ok().map(|b| {
                            b.iter()
                                .map(|x| match *x {
                                    ByteValue::Concrete(v) => v,
                                    _ => 0xcc,
                                })
                                .collect::<Vec<u8>>()
                        }),
                        Err(_) => None,
                    };
                    let insn_info = match &insn_bytes {
                        Some(b) => runtime
                            .decoder
                            .decode(pc, b)
                            .ok()
                            .map(|d| {
                                let n = usize::from(d.length);
                                format!("form_id={:#x} (len {}) bytes={:02x?}", d.form_id, d.length, &b[..n])
                            })
                            .unwrap_or_else(|| "decode_failed".to_string()),
                        None => "read_failed".to_string(),
                    };
                    format!("{kind:?} at pc={pc:#x} [{insn_info}]")
                })
                .collect()
        } else {
            Vec::new()
        };

        if matched {
            summary.exact_match_count += 1;
            if requires_prove {
                summary.shadow_debt_count += 1;
            } else {
                summary.clean_match_count += 1;
            }
        } else {
            summary.divergence_count += 1;
        }

        let diagnostic = if !matched {
            Some(diagnose_divergence(&runtime, &bytes, STEP_BUDGET))
        } else {
            None
        };

        reports.push(DriverReport {
            name: file_name,
            concrete_steps: c_res.steps,
            concolic_steps: x_res.exec.steps,
            concrete_term: c_res.terminated,
            concolic_term: x_res.exec.terminated,
            concrete_rax: c_res.rax,
            concolic_rax: x_res.exec.rax,
            matched,
            requires_prove,
            debt_details,
            elapsed_s,
            diagnostic,
        });
    }

    let total_elapsed_s = start_total.elapsed().as_secs_f64();

    // Print table
    println!(
        "\n========================================================================================================"
    );
    println!("                                CONCOLIC CORPUS FIDELITY SWEEP REPORT");
    println!(
        "========================================================================================================"
    );
    println!(
        "{:<38} | {:>8} | {:>8} | {:^7} | {:^14} | {:>8}",
        "Driver Name", "Concrete", "Concolic", "Match?", "requires_prove", "Time (s)"
    );
    println!(
        "--------------------------------------------------------------------------------------------------------"
    );

    for r in &reports {
        let match_str = if r.matched { "YES" } else { "NO" };
        let debt_str = if r.requires_prove { "true (DEBT)" } else { "false" };
        println!(
            "{:<38} | {:>8} | {:>8} | {:^7} | {:^14} | {:>8.4}",
            r.name, r.concrete_steps, r.concolic_steps, match_str, debt_str, r.elapsed_s
        );
    }
    println!(
        "========================================================================================================"
    );

    // Print shadow debt breakdown if any
    let debt_reports: Vec<&DriverReport> = reports.iter().filter(|r| r.requires_prove).collect();
    if !debt_reports.is_empty() {
        println!(
            "\n--- SHADOW DEBT (requires_prove=true) BREAKDOWN ({} drivers) ---",
            debt_reports.len()
        );
        for r in &debt_reports {
            println!("  Driver: {}", r.name);
            for detail in &r.debt_details {
                println!("    * {detail}");
            }
        }
    }

    // Print divergences if any
    let divergences: Vec<&DriverReport> = reports.iter().filter(|r| !r.matched).collect();
    if !divergences.is_empty() {
        println!("\n!!! DIVERGENCES DETECTED ({} drivers) !!!", divergences.len());
        for d in &divergences {
            println!("\n--- Divergence: {} ---", d.name);
            println!(
                "  Concrete: steps={} terminated={} rax={:#x}",
                d.concrete_steps, d.concrete_term, d.concrete_rax
            );
            println!(
                "  Concolic: steps={} terminated={} rax={:#x} requires_prove={}",
                d.concolic_steps, d.concolic_term, d.concolic_rax, d.requires_prove
            );
            if let Some(ref diag) = d.diagnostic {
                println!("  Diagnostic:\n    {}", diag.replace('\n', "\n    "));
            }
        }
    } else {
        println!(
            "\n>>> ZERO DIVERGENCES: All {} loadable drivers matched exactly! <<<",
            summary.loadable_count
        );
    }

    // Print Aggregate Summary
    println!(
        "\n========================================================================================================"
    );
    println!("                                       AGGREGATE SUMMARY");
    println!(
        "========================================================================================================"
    );
    println!("Total corpus files discovered : {}", summary.total_images);
    println!("Loadable x64 driver images    : {}", summary.loadable_count);
    println!("Unloadable / 32-bit / non-PE  : {}", summary.load_failed_count);
    println!(
        "Exact execution matches       : {} / {}",
        summary.exact_match_count, summary.loadable_count
    );
    println!(
        "Execution divergences         : {} / {}",
        summary.divergence_count, summary.loadable_count
    );
    println!(
        "Drivers reporting shadow debt : {} / {}",
        summary.shadow_debt_count, summary.loadable_count
    );
    println!(
        "Drivers clean (no debt)       : {} / {}",
        summary.clean_match_count, summary.loadable_count
    );
    println!("Total sweep duration          : {:.4}s", total_elapsed_s);
    println!(
        "========================================================================================================\n"
    );

    // Allowlist check: per Task 4:
    // "The test must assert: no driver DIVERGES (steps/exit mismatch) — shadow debt (requires_prove=true) is allowed and reported,
    // but the concrete execution must match. If some drivers legitimately diverge today, mark them with an explicit allowlist and document why."
    let allowlist: std::collections::HashSet<&str> = [
        // Add any justified divergent drivers here if found
    ]
    .into_iter()
    .collect();

    let unallowed_divergences: Vec<&DriverReport> = reports
        .iter()
        .filter(|r| !r.matched && !allowlist.contains(r.name.as_str()))
        .collect();

    assert!(
        unallowed_divergences.is_empty(),
        "Found {} unallowed driver divergences: {:?}",
        unallowed_divergences.len(),
        unallowed_divergences.iter().map(|r| &r.name).collect::<Vec<_>>()
    );

    assert!(
        summary.loadable_count >= 70,
        "Expected at least 70 loadable drivers, found {}",
        summary.loadable_count
    );

    Ok(())
}
