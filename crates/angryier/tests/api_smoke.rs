//! Stable-API smoke tests: hermetic error paths plus an optional
//! end-to-end leg against the real driver corpus (skipped when the corpus
//! is absent, matching the repo's driver-test convention).

use std::path::PathBuf;

use angryier::{ApiError, Engine, RunOptions, StepKind};

fn harness_fixture(name: &str) -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    let path = PathBuf::from(home)
        .join("Documents/byovd-harness/ghidra_pipeline/fixtures/bin")
        .join(name);
    path.is_file().then_some(path)
}

#[test]
fn load_rejects_garbage() {
    let engine = Engine::new().expect("engine construction");
    let path = std::env::temp_dir().join("angryier_api_garbage.bin");
    std::fs::write(&path, b"this is not a binary image at all").expect("write fixture");
    let err = engine.load(&path).expect_err("garbage must fail to load");
    assert!(matches!(err, ApiError::Load(_)), "got {err:?}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn load_dynamic_rejects_pe() {
    let engine = Engine::new().expect("engine construction");
    let path = std::env::temp_dir().join("angryier_api_mz.bin");
    std::fs::write(&path, b"MZ\x90\x90\x90").expect("write fixture");
    let err = engine
        .load_dynamic(&path)
        .expect_err("PE input must be rejected by load_dynamic");
    assert!(matches!(err, ApiError::InvalidArgument(_)), "got {err:?}");
    let _ = std::fs::remove_file(&path);
}

#[test]
fn driver_corpus_end_to_end() {
    // A real PE32+ driver fixture: DriverEntry terminates cleanly under
    // the full symbolic session (kernel SimProcedure dispatch verified by
    // `angryier-runtime::symbolic_kernel_models` for the import variant).
    let Some(driver) = harness_fixture("allocsize_overflow_vuln_O2.sys") else {
        eprintln!("SKIP: fixture corpus not present");
        return;
    };
    let engine = Engine::new().expect("engine construction");
    let image = engine.load(&driver).expect("driver loads");
    assert_eq!(image.kind(), angryier::ImageKind::PeDriver);

    let report = engine
        .run(
            &image,
            &RunOptions {
                steps: 1000,
                ..RunOptions::default()
            },
        )
        .expect("driver run");
    assert_eq!(report.terminated, 1, "report: {report:?}");
    assert!(report.failed == 0, "report: {report:?}");
    assert!(report.steps >= 20, "report: {report:?}");
}

#[test]
fn session_handle_steps_and_validates() {
    let Some(driver) = harness_fixture("allocsize_overflow_vuln_O2.sys") else {
        eprintln!("SKIP: fixture corpus not present");
        return;
    };
    let engine = Engine::new().expect("engine construction");
    let image = engine.load(&driver).expect("driver loads");

    // Width and name validation error honestly without executing.
    let mut session = engine.open(&image).expect("open session");
    let err = session
        .symbolic("rdi", 8)
        .expect_err("sub-64-bit GPR symbols must be rejected");
    assert!(matches!(err, ApiError::InvalidArgument(_)), "got {err:?}");
    let err = session
        .symbolic("zzz", 64)
        .expect_err("unknown registers must be rejected");
    assert!(matches!(err, ApiError::InvalidArgument(_)), "got {err:?}");
    session.symbolic("rdi", 64).expect("64-bit mark accepted");

    // Step until termination or an honest engine error (real binaries can
    // hit unmapped/unresolved edges under the session's solver-less
    // stepping — the handle reports them instead of pretending); reg/pc
    // stay readable along the way.
    let mut saw_pc = false;
    let mut stepped = 0u64;
    for _ in 0..500 {
        match session.step() {
            Ok(StepKind::Terminated) => break,
            Ok(StepKind::Stepped | StepKind::Branched) => {
                saw_pc |= session.pc().expect("pc") != 0;
                stepped += 1;
            }
            Err(_) => break,
        }
    }
    assert!(stepped > 0, "session must execute at least one step");
    assert!(saw_pc, "pc must be readable after stepping");
}
