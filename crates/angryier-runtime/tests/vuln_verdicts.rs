//! Verdict validation: run IMPORT-BASED variants of the byovd-harness vuln
//! fixtures through the kernel pool model and report reachable
//! alloc/free/double-free events.
//!
//! The stock fixtures link stubs.c (local bump allocator + no-op free) so
//! their pool calls are NOT imports; build the import variants with:
//!   x86_64-w64-mingw32-dlltool -d crates/angryier-runtime/tests/fixtures/ntoskrnl.def -l /tmp/libntoskrnl.a
//!   x86_64-w64-mingw32-gcc -g -O2 -nodefaultlibs -nostartfiles -fno-stack-protector \
//!       -fno-builtin -shared -Wl,--entry,DriverEntry -o /tmp/fixture_import/<name>_import_O2.sys \
//!       <harness>/fixtures/src/<name>.c -L/tmp -lntoskrnl
//! The test skips when the fixtures are absent.
#![cfg(feature = "xed")]
use angryier_runtime::Runtime;
use angryier_types::{SemanticVersion, TargetProfileId};

#[test]
fn vuln_fixture_verdicts() {
    let dir = "/tmp/fixture_import";
    let fixtures = [
        "double_free_vuln_import_O2.sys",
        "allocsize_overflow_vuln_import_O2.sys",
        "nonatomic_refcount_vuln_import_O2.sys",
    ];
    for name in fixtures {
        let path = format!("{dir}/{name}");
        let Ok(image) = std::fs::read(&path) else {
            eprintln!("SKIP {name}");
            continue;
        };
        let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
        let Ok(mut process) = runtime.load_pe_driver(&image) else {
            eprintln!("{name}: LOAD FAILED");
            continue;
        };
        let tracker = std::sync::Arc::new(angryier_models::KernelPoolTracker::new());
        if runtime.attach_kernel_pool_model(&mut process, tracker.clone()).is_err() {
            eprintln!("{name}: ATTACH FAILED");
            continue;
        }
        let mut steps = 0;
        let mut blocked = None;
        for _ in 0..5000 {
            match runtime.step(&mut process) {
                Ok(_) => steps += 1,
                Err(e) => {
                    blocked = Some(format!("{e:?}"));
                    break;
                }
            }
            if process.terminated {
                break;
            }
        }
        let report = tracker.snapshot();
        let status = if blocked.is_some() {
            format!("BLOCKED({})", blocked.as_deref().unwrap_or(""))
        } else if process.terminated {
            "TERMINATED".to_string()
        } else {
            "BUDGET".to_string()
        };
        eprintln!(
            "{name}: steps={steps} {status} simprocs={} pool: a={} f={} df={}",
            process.simproc_dispatches,
            report.allocs,
            report.frees,
            report.double_frees.len()
        );
        for event in &report.double_frees {
            eprintln!("  DOUBLE-FREE ptr={:#x} caller={:#x}", event.pointer, event.caller);
        }
    }
}
