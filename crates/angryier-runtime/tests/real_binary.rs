//! Gate 0 end-to-end test: a real, statically-linked ELF64 binary is loaded,
//! decoded with native Intel XED, executed through the concrete interpreter,
//! and dispatched into a SimProcedure.
//!
//! The fixture is assembled and linked at test time with the system binutils
//! (`as` + `ld`). When the toolchain is unavailable the test reports a skip
//! instead of failing.

#![cfg(feature = "xed")]

use std::path::PathBuf;
use std::process::Command;

use angryier_arch_intel64::register_id;
use angryier_runtime::{Runtime, StepOutcome};
use angryier_types::{SemanticVersion, TargetProfileId};

/// A real Intel 64 program using only forms the corpus executes exactly:
/// compare the input register against 42 and branch.
const FIXTURE_SOURCE: &str = r"
    .global _start
    .text
_start:
    cmp $42, %rax
    jne fail_path
ok_path:
    hlt
fail_path:
    hlt
";

/// Assembles and links the fixture into a real ELF64 executable.
///
/// Returns `None` when the binutils toolchain is unavailable or fails.
fn build_fixture() -> Option<Vec<u8>> {
    let dir: PathBuf = std::env::temp_dir().join(format!("angryier-fixture-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    let source = dir.join("fixture.s");
    let object = dir.join("fixture.o");
    let binary = dir.join("fixture.elf");
    std::fs::write(&source, FIXTURE_SOURCE).ok()?;

    let assembled = Command::new("as")
        .arg("--64")
        .arg("-o")
        .arg(&object)
        .arg(&source)
        .output()
        .ok()?;
    if !assembled.status.success() {
        return None;
    }
    let linked = Command::new("ld").arg("-o").arg(&binary).arg(&object).output().ok()?;
    if !linked.status.success() {
        return None;
    }
    let bytes = std::fs::read(&binary).ok()?;
    let _ = std::fs::remove_dir_all(&dir);
    Some(bytes)
}

/// Fixture bytes, built once and shared by all tests (test threads run in
/// parallel and must not race on the same temporary directory).
fn fixture_bytes() -> Option<&'static [u8]> {
    static FIXTURE: std::sync::OnceLock<Option<Vec<u8>>> = std::sync::OnceLock::new();
    FIXTURE.get_or_init(build_fixture).as_deref()
}

/// Runs until a SimProcedure is dispatched or execution stops.
fn run_to_simproc(
    runtime: &Runtime<impl angryier_arch::Decoder>,
    process: &mut angryier_runtime::Process,
) -> Result<Vec<(u64, String)>, Box<dyn std::error::Error>> {
    let mut dispatches = Vec::new();
    loop {
        match runtime.step(process)? {
            StepOutcome::Stepped { .. } => {}
            StepOutcome::SimProcedure { address, name } => {
                dispatches.push((address, name));
                return Ok(dispatches);
            }
            StepOutcome::Terminated { .. } | StepOutcome::Trap { .. } => return Ok(dispatches),
        }
    }
}

#[test]
fn real_binary_runs_end_to_end_with_native_xed() -> Result<(), Box<dyn std::error::Error>> {
    let Some(bytes) = fixture_bytes() else {
        eprintln!("skipping: binutils (as/ld) unavailable");
        return Ok(());
    };

    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_elf(bytes)?;

    // Symbols come from the real ELF symbol table.
    let ok_path = process.symbol("ok_path").ok_or("missing ok_path symbol")?.address;
    let fail_path = process.symbol("fail_path").ok_or("missing fail_path symbol")?.address;
    assert_ne!(ok_path, fail_path, "ok_path and fail_path must differ");

    process.hook_simproc(ok_path, "exit");
    process.hook_simproc(fail_path, "exit");

    // RAX = 6 != 42: the JNZ must be taken to fail_path.
    process.write_register(register_id::GPR_BASE, 6)?;
    let dispatches = run_to_simproc(&runtime, &mut process)?;
    assert_eq!(dispatches.len(), 1, "expected exactly one SimProcedure dispatch");
    assert_eq!(dispatches[0].0, fail_path, "branch taken to fail_path");
    assert_eq!(process.step_count, 2, "cmp + jne executed");

    // RAX = 42: the branch falls through to ok_path.
    let mut process = runtime.load_elf(bytes)?;
    process.hook_simproc(ok_path, "exit");
    process.hook_simproc(fail_path, "exit");
    process.write_register(register_id::GPR_BASE, 42)?;
    let dispatches = run_to_simproc(&runtime, &mut process)?;
    assert_eq!(dispatches.len(), 1, "expected exactly one SimProcedure dispatch");
    assert_eq!(dispatches[0].0, ok_path, "branch fell through to ok_path");
    Ok(())
}

#[test]
fn unmapped_instructions_fail_explicitly() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    // `syscall` decodes under XED but has no exact corpus semantics; the
    // runtime must report an unsupported form instead of guessing.
    let mut process = runtime.load_elf(&build_syscall_fixture().ok_or("binutils unavailable")?)?;
    let error = runtime
        .step(&mut process)
        .err()
        .ok_or("expected an unsupported-form error")?;
    let message = error.to_string();
    assert!(
        message.contains("UnsupportedForm(0)"),
        "unmapped instructions must report form id 0, got: {message}"
    );
    Ok(())
}

/// Builds a fixture whose first instruction is `syscall` (0F 05).
fn build_syscall_fixture() -> Option<Vec<u8>> {
    let dir: PathBuf = std::env::temp_dir().join(format!("angryier-fixture-syscall-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    let source = dir.join("fixture.s");
    let object = dir.join("fixture.o");
    let binary = dir.join("fixture.elf");
    std::fs::write(
        &source,
        "    .global _start\n    .text\n_start:\n    syscall\n    hlt\n",
    )
    .ok()?;

    let assembled = Command::new("as")
        .arg("--64")
        .arg("-o")
        .arg(&object)
        .arg(&source)
        .output()
        .ok()?;
    if !assembled.status.success() {
        return None;
    }
    let linked = Command::new("ld").arg("-o").arg(&binary).arg(&object).output().ok()?;
    if !linked.status.success() {
        return None;
    }
    let bytes = std::fs::read(&binary).ok()?;
    let _ = std::fs::remove_dir_all(&dir);
    Some(bytes)
}

/// Gate 0 branch solving: run the real binary, solve the branch symbolically
/// with the native Z3 backend, generate a new input, and confirm the replayed
/// run reaches the opposite path.
#[cfg(feature = "z3")]
#[test]
fn solved_branch_generates_input_that_flips_the_path() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use std::time::Duration;

    use angryier_expr::{ExprReader, ShardedExprArena};
    use angryier_runtime::BranchDirection;
    use angryier_solver_z3::Z3Backend;
    use angryier_types::ExpressionNormalizationVersion;

    let Some(bytes) = fixture_bytes() else {
        eprintln!("skipping: binutils (as/ld) unavailable");
        return Ok(());
    };

    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_elf(bytes)?;
    let ok_path = process.symbol("ok_path").ok_or("missing ok_path symbol")?.address;
    let fail_path = process.symbol("fail_path").ok_or("missing fail_path symbol")?.address;
    process.hook_simproc(ok_path, "exit");
    process.hook_simproc(fail_path, "exit");

    // Run with RAX = 6: the JNZ is taken to fail_path.
    process.write_register(register_id::GPR_BASE, 6)?;
    let dispatches = run_to_simproc(&runtime, &mut process)?;
    assert_eq!(dispatches[0].0, fail_path, "initial run must reach fail_path");

    // Solve for the opposite direction: fall through to ok_path.
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let reader: Arc<dyn ExprReader> = arena.clone();
    let mut backend = Z3Backend::native_ffi(reader)?;
    let solution = runtime.solve_branch(
        &process,
        BranchDirection::NotTaken,
        arena.as_ref(),
        &mut backend,
        Duration::from_secs(10),
    )?;
    assert!(solution.is_sat(), "fall-through direction must be satisfiable");
    assert_eq!(solution.branch.not_taken, ok_path);
    assert!(!solution.assignments.is_empty(), "solver must return an input");
    let rax = solution
        .assignments
        .iter()
        .find(|assignment| assignment.register == register_id::GPR_BASE)
        .ok_or("solver must assign the input register")?;
    assert_eq!(rax.value, 42, "the only input reaching ok_path is RAX = 42");

    // Replay with the solved input: the run must reach ok_path.
    process.reset_to_entry();
    process.apply_inputs(&solution.assignments)?;
    let dispatches = run_to_simproc(&runtime, &mut process)?;
    assert_eq!(dispatches[0].0, ok_path, "replayed run must reach ok_path");
    Ok(())
}
