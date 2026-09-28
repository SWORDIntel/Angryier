//! Corpus execution sweep: load EVERY PE test image, attach the kernel
//! model, and step it — classifying the outcome so the campaign can see
//! how far the corpus gets and what the remaining walls are.
//!
//! Outcome classes:
//!   TERMINATED  — the driver returned through the exit hook.
//!   BLOCK-FORM  — blocked on an unsupported instruction form.
//!   BLOCK-NULL  — executed a null/undefined target (missing code guards).
//!   BLOCK-OTHER — some other execution error.
//!   BUDGET      — still running at the step budget (deep execution).
#![cfg(feature = "xed")]
use std::path::PathBuf;

use angryier_arch::Decoder;
use angryier_memory::LayeredMemory;
use angryier_runtime::Runtime;
use angryier_types::{SemanticVersion, TargetProfileId};

const STEP_BUDGET: u64 = 3000;

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
    files.sort();
    files
}

#[derive(Default)]
struct Totals {
    terminated: usize,
    blocked_form: usize,
    blocked_null: usize,
    blocked_other: usize,
    budget: usize,
    load_failed: usize,
    total_steps: u64,
}

#[test]
fn corpus_execution_sweep() -> Result<(), Box<dyn std::error::Error>> {
    let mut all_files = Vec::new();
    for dir in &fixture_dirs() {
        all_files.extend(collect_image_files(dir));
    }
    all_files.sort();
    all_files.dedup();

    let mut totals = Totals::default();
    let mut rows: Vec<(String, String, u64, f64, String)> = Vec::new();

    for file_path in &all_files {
        let file_name = file_path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| file_path.display().to_string());
        let bytes = match std::fs::read(file_path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
        let Ok(mut process) = runtime.load_pe_driver(&bytes) else {
            totals.load_failed += 1;
            rows.push((file_name, "LOAD-FAIL".to_string(), 0, 0.0, String::new()));
            continue;
        };
        let tracker = std::sync::Arc::new(angryier_models::KernelPoolTracker::new());
        let _ = runtime.attach_kernel_pool_model(&mut process, tracker.clone());

        let mut steps = 0u64;
        let mut blocked = None;
        let mut block_pc = 0u64;
        let run_start = std::time::Instant::now();
        for _ in 0..STEP_BUDGET {
            match runtime.step(&mut process) {
                Ok(_) => steps += 1,
                Err(e) => {
                    block_pc = process.pc().unwrap_or(0);
                    blocked = Some(format!("{e:?}"));
                    break;
                }
            }
            if process.terminated {
                break;
            }
        }

        let (class, detail) = match blocked {
            Some(err) if err.contains("MissingCodeGuards") => {
                totals.blocked_null += 1;
                ("BLOCK-NULL".to_string(), err)
            }
            Some(err) if err.contains("UnsupportedForm") || err.contains("Unsupported") => {
                totals.blocked_form += 1;
                ("BLOCK-FORM".to_string(), err)
            }
            Some(err) => {
                totals.blocked_other += 1;
                ("BLOCK-OTHER".to_string(), err)
            }
            None if process.terminated => {
                totals.terminated += 1;
                ("TERMINATED".to_string(), String::new())
            }
            None => {
                totals.budget += 1;
                ("BUDGET".to_string(), String::new())
            }
        };
        totals.total_steps += steps;
        let run_seconds = run_start.elapsed().as_secs_f64();
        rows.push((
            file_name,
            class.clone(),
            steps,
            run_seconds,
            if class == "BLOCK-FORM" || class == "BLOCK-OTHER" {
                let bytes = process.state.memory.read(block_pc, 15).ok().map(|b| {
                    b.iter()
                        .map(|x| match x {
                            angryier_memory::ByteValue::Concrete(v) => *v,
                            _ => 0xcc,
                        })
                        .collect::<Vec<u8>>()
                });
                let iclass = match &bytes {
                    Some(b) => runtime
                        .decoder
                        .decode(block_pc, b)
                        .ok()
                        .map(|d| {
                            let n = usize::from(d.length);
                            format!("iclass={} bytes={:02x?}", d.form_id, &b[..n])
                        })
                        .unwrap_or_default(),
                    None => String::new(),
                };
                format!("pc={block_pc:#x} {iclass} {detail}")
            } else {
                detail
            },
        ));
    }

    let n = rows.len();

    println!("\n=== corpus execution sweep ({n} images) ===");
    println!(
        "TERMINATED={} BLOCK-NULL={} BLOCK-FORM={} BLOCK-OTHER={} BUDGET={} LOAD-FAIL={}",
        totals.terminated,
        totals.blocked_null,
        totals.blocked_form,
        totals.blocked_other,
        totals.budget,
        totals.load_failed
    );
    println!("total steps executed: {}", totals.total_steps);
    println!("\n--- per image (sorted by steps, descending) ---");
    rows.sort_by_key(|a| std::cmp::Reverse(a.2));
    for (name, class, steps, seconds, detail) in rows {
        let short = detail.split(['(', ' ', ':']).next().unwrap_or("").to_string();
        let mut line = format!("{name:44} {class:12} {steps:>6} steps");
        if !short.is_empty() && class != "BUDGET" && class != "TERMINATED" {
            line.push_str(&format!("  [{detail}]"));
        }
        println!("{line} in {seconds:.4}s");
    }
    Ok(())
}
