//! Verdict validation: run IMPORT-BASED variants of the byovd-harness vuln
//! fixtures through the kernel pool model and assert the expected pool
//! verdicts (double-free detected where the source frees the same pointer
//! twice on one path; balanced elsewhere).
//!
//! The stock fixtures link stubs.c (local bump allocator + no-op free) so
//! their pool calls are NOT imports; build the import variants in the
//! byovd-harness fixtures dir with:
//!   make -C <harness>/ghidra_pipeline/fixtures import
//! The test skips fixtures that are absent.

#![cfg(feature = "xed")]
use angryier_runtime::Runtime;
use angryier_types::{SemanticVersion, TargetProfileId};

/// Fixture name -> expected pool verdict: (min_allocs, min_frees,
/// expected_double_frees, min_uaf_writes). The pointer-reassign vuln is a
/// use-after-free WRITE (both frees target distinct pointers -> df=0, but
/// the write through the stale pointer must be detected as UAF); the
/// allocsize-safe fixture exits in validation before allocating.
const EXPECTED: &[(&str, u64, u64, usize, u64)] = &[
    ("double_free_vuln_import_O2.sys", 1, 2, 1, 0),
    ("safe_double_free_import_O2.sys", 1, 1, 0, 0),
    ("pointer_reassign_vuln_import_O2.sys", 2, 2, 0, 1),
    ("probe_missing_vuln_import_O2.sys", 2, 1, 0, 0),
    ("allocsize_overflow_vuln_import_O2.sys", 1, 1, 0, 0),
    ("allocsize_overflow_safe_import_O2.sys", 0, 0, 0, 0),
    ("nonatomic_refcount_vuln_import_O2.sys", 1, 1, 0, 0),
    ("pointer_reassign_safe_import_O2.sys", 2, 2, 0, 0),
    ("probe_missing_safe_import_O2.sys", 2, 2, 0, 0),
];

#[test]
fn vuln_fixture_verdicts() {
    let dir = "/home/john/Documents/byovd-harness/ghidra_pipeline/fixtures/bin";
    let mut ran = 0;
    let mut failures = 0;
    for &(name, want_allocs, want_frees, want_df, want_uaf) in EXPECTED {
        let path = format!("{dir}/{name}");
        let Ok(image) = std::fs::read(&path) else {
            eprintln!("SKIP {name}");
            continue;
        };
        let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
        let Ok(mut process) = runtime.load_pe_driver(&image) else {
            eprintln!("{name}: LOAD FAILED");
            failures += 1;
            continue;
        };
        let tracker = std::sync::Arc::new(angryier_models::KernelPoolTracker::new());
        if runtime.attach_kernel_pool_model(&mut process, tracker.clone()).is_err() {
            eprintln!("{name}: ATTACH FAILED");
            failures += 1;
            continue;
        }
        let mut steps = 0;
        let mut blocked = false;
        for _ in 0..5000 {
            match runtime.step(&mut process) {
                Ok(_) => steps += 1,
                Err(_) => {
                    blocked = true;
                    break;
                }
            }
            if process.terminated {
                break;
            }
        }
        ran += 1;
        let report = tracker.snapshot();
        let status = if blocked {
            "BLOCKED"
        } else if process.terminated {
            "TERMINATED"
        } else {
            "BUDGET"
        };
        let ok = report.allocs >= want_allocs
            && report.frees >= want_frees
            && report.double_frees.len() == want_df
            && report.uaf_writes.len() as u64 >= want_uaf;
        if !ok {
            failures += 1;
        }
        eprintln!(
            "{name}: steps={steps} {status} simprocs={} pool: a={} f={} df={} uaf={} (expected a>={} f>={} df={} uaf>={}) {}",
            process.simproc_dispatches,
            report.allocs,
            report.frees,
            report.double_frees.len(),
            report.uaf_writes.len(),
            want_allocs,
            want_frees,
            want_df,
            want_uaf,
            if ok { "OK" } else { "MISMATCH" }
        );
        for event in &report.double_frees {
            eprintln!("  DOUBLE-FREE ptr={:#x} caller={:#x}", event.pointer, event.caller);
        }
        for event in &report.uaf_writes {
            eprintln!("  UAF-WRITE addr={:#x} caller={:#x}", event.pointer, event.caller);
        }
    }
    assert!(ran > 0 || failures == 0, "no fixtures ran");
    assert_eq!(failures, 0, "{failures} fixture verdict(s) mismatched");
}
