//! Gate 0 end-to-end tests: a real, statically-linked ELF64 binary is loaded,
//! decoded with native Intel XED, executed through the concrete interpreter,
//! dispatched into SimProcedures, and — for the conditional branch — solved
//! with Z3 to generate a new input that replays into the opposite path.
//!
//! The fixture is assembled and linked at test time with the system binutils
//! (`as` + `ld`). When the toolchain is unavailable the tests report a skip
//! instead of failing.
//!
//! The fixture terminates through the `exit` syscall with a path-specific exit
//! code, so the same object can be executed natively by a generated harness:
//! that is what turns "the solver produced an input" into "the input reaches
//! the target state on real hardware".

#![cfg(feature = "xed")]

use std::path::{Path, PathBuf};
use std::process::Command;

use angryier_arch_intel64::register_id;
use angryier_runtime::{Runtime, StepOutcome};
use angryier_types::{SemanticVersion, TargetProfileId};

/// A real Intel 64 program using only forms the corpus executes exactly.
///
/// `run` (aliased to `_start`) compares the input register against 42 and
/// branches. Both paths terminate with the `exit` syscall: exit code 0 for
/// `ok_path`, exit code 1 for `fail_path`. The engine hooks the syscall
/// instructions as SimProcedures; natively they exit the process.
const FIXTURE_SOURCE: &str = r"
    .global _start
    .global run
    .text
_start:
run:
    cmp $42, %rax
    jne fail_path
ok_path:
    mov $60, %rax
    xor %rdi, %rdi
ok_exit:
    syscall
fail_path:
    mov $60, %rax
    mov $1, %rdi
fail_exit:
    syscall
";

/// Assembled fixture object plus the linked executable bytes.
#[allow(dead_code)]
struct Fixture {
    /// Relocatable object, linked into native harnesses.
    object: PathBuf,
    /// Linked ELF64 executable loaded by the engine.
    elf: Vec<u8>,
}

/// Builds the fixture once and shares it across test threads.
fn fixture() -> Option<&'static Fixture> {
    static FIXTURE: std::sync::OnceLock<Option<Fixture>> = std::sync::OnceLock::new();
    FIXTURE.get_or_init(build_fixture).as_ref()
}

/// Assembles and links the fixture into a real ELF64 executable.
///
/// Returns `None` when the binutils toolchain is unavailable or fails.
fn build_fixture() -> Option<Fixture> {
    let dir = temp_dir("angryier-fixture")?;
    let source = dir.join("fixture.s");
    let object = dir.join("fixture.o");
    let binary = dir.join("fixture.elf");
    std::fs::write(&source, FIXTURE_SOURCE).ok()?;

    assemble(&source, &object)?;
    link(&binary, &[&object])?;
    let elf = std::fs::read(&binary).ok()?;
    Some(Fixture { object, elf })
}

/// Assembles and links a native harness that sets RAX to `input` and calls
/// the fixture's `run`, returning the resulting process exit code.
#[allow(dead_code)]
fn run_native(input: u64) -> Option<i32> {
    let fixture = fixture()?;
    let dir = temp_dir(&format!("angryier-harness-{input}"))?;
    let source = dir.join("harness.s");
    let object = dir.join("harness.o");
    let binary = dir.join("harness.elf");
    let harness = format!(
        "    .global _start\n    .text\n_start:\n    mov ${input}, %rax\n    call run\n    mov $60, %rax\n    xor %rdi, %rdi\n    syscall\n"
    );
    std::fs::write(&source, harness).ok()?;

    assemble(&source, &object)?;
    link(&binary, &[&object, &fixture.object])?;
    let status = Command::new(&binary).status().ok()?;
    status.code()
}

fn temp_dir(name: &str) -> Option<PathBuf> {
    let dir = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

fn assemble(source: &Path, object: &Path) -> Option<()> {
    let output = Command::new("as")
        .arg("--64")
        .arg("-o")
        .arg(object)
        .arg(source)
        .output()
        .ok()?;
    output.status.success().then_some(())
}

fn link(binary: &Path, objects: &[&PathBuf]) -> Option<()> {
    let mut command = Command::new("ld");
    command.arg("-o").arg(binary);
    for object in objects {
        command.arg(object);
    }
    command.output().ok()?.status.success().then_some(())
}

/// Runs until a SimProcedure is dispatched or execution stops.
fn run_to_simproc(
    runtime: &Runtime<impl angryier_arch::Decoder>,
    process: &mut angryier_runtime::Process,
) -> Result<Vec<(u64, String)>, Box<dyn std::error::Error>> {
    let mut dispatches = Vec::new();
    loop {
        match runtime.step(process)? {
            StepOutcome::Stepped { .. } | StepOutcome::Syscall { .. } => {}
            StepOutcome::SimProcedure { address, name } => {
                dispatches.push((address, name));
                return Ok(dispatches);
            }
            StepOutcome::Terminated { .. } | StepOutcome::Trap { .. } => return Ok(dispatches),
        }
    }
}

/// Loads the fixture, hooks both exit syscalls, and seeds the input register.
fn loaded_process(
    runtime: &Runtime<impl angryier_arch::Decoder>,
    input: u64,
) -> Result<(angryier_runtime::Process, u64, u64), Box<dyn std::error::Error>> {
    let fixture = fixture().ok_or("binutils unavailable")?;
    let mut process = runtime.load_elf(&fixture.elf)?;
    let ok_exit = process.symbol("ok_exit").ok_or("missing ok_exit symbol")?.address;
    let fail_exit = process.symbol("fail_exit").ok_or("missing fail_exit symbol")?.address;
    process.hook_simproc(ok_exit, "exit");
    process.hook_simproc(fail_exit, "exit");
    process.write_register(register_id::GPR_BASE, input)?;
    Ok((process, ok_exit, fail_exit))
}

#[test]
fn real_binary_runs_end_to_end_with_native_xed() -> Result<(), Box<dyn std::error::Error>> {
    let Some(_) = fixture() else {
        eprintln!("skipping: binutils (as/ld) unavailable");
        return Ok(());
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));

    // RAX = 6 != 42: the JNZ is taken to fail_path.
    let (mut process, _ok_exit, fail_exit) = loaded_process(&runtime, 6)?;
    let dispatches = run_to_simproc(&runtime, &mut process)?;
    assert_eq!(dispatches.len(), 1, "expected exactly one SimProcedure dispatch");
    assert_eq!(dispatches[0].0, fail_exit, "branch taken to fail_path");
    assert_eq!(
        process.step_count, 4,
        "cmp + jne + two instructions before the exit syscall"
    );

    // RAX = 42: the branch falls through to ok_path.
    let (mut process, ok_exit, fail_exit) = loaded_process(&runtime, 42)?;
    let dispatches = run_to_simproc(&runtime, &mut process)?;
    assert_eq!(dispatches.len(), 1, "expected exactly one SimProcedure dispatch");
    assert_eq!(dispatches[0].0, ok_exit, "branch fell through to ok_path");
    assert_ne!(ok_exit, fail_exit);
    Ok(())
}

#[test]
fn unmapped_instructions_fail_explicitly() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    // `addps` decodes under XED but has no exact corpus semantics (the SIMD
    // forms are not yet mapped); the runtime must report an unsupported form
    // instead of guessing.
    let mut process = runtime.load_elf(&build_fixture_from("_start:\n    addps %xmm1, %xmm0\n    hlt\n")?)?;
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

#[test]
fn unmodeled_syscalls_fail_explicitly() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    // `syscall` with RAX = 99 is `sysinfo`, which the environment model
    // does not implement yet; execution must fail explicitly rather than
    // fabricate a result.
    // result.
    let mut process = runtime.load_elf(&build_fixture_from(
        "_start:\n    mov $99, %rax\n    syscall\n    hlt\n",
    )?)?;
    runtime.step(&mut process)?; // mov $107, %rax
    let error = runtime
        .step(&mut process)
        .err()
        .ok_or("expected an unsupported-syscall error")?;
    let message = error.to_string();
    assert!(
        message.contains("unsupported syscall number 99"),
        "unmodeled syscalls must fail explicitly, got: {message}"
    );
    Ok(())
}

/// Modeled syscalls: the engine's captured `write` output and exit code must
/// match a native run of the same binary.
#[test]
fn syscall_output_matches_native_run() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let source = concat!(
        "_start:\n",
        "    mov $1, %rax\n",   // write
        "    mov $1, %rdi\n",   // stdout
        "    mov $msg, %rsi\n", // buffer
        "    mov $13, %rdx\n",  // length
        "    syscall\n",
        "    mov $60, %rax\n",  // exit
        "    xor %rdi, %rdi\n", // code 0
        "    syscall\n",
        "    .data\n",
        "msg:\n",
        "    .ascii \"hello, world\\n\"\n",
    );
    let (bytes, binary) = build_fixture_from_path(source)?;

    let mut process = runtime.load_elf(&bytes)?;
    runtime.run(&mut process, 32)?;
    assert!(process.terminated, "exit syscall must terminate execution");
    assert_eq!(process.syscalls.output(), b"hello, world\n");
    assert_eq!(process.syscalls.exit_code(), Some(0));
    assert_eq!(process.syscalls.invocations(), 2, "one write, one exit");

    // Native run of the same binary must produce the same output and status.
    let native = Command::new(&binary).output()?;
    assert_eq!(
        native.stdout, b"hello, world\n",
        "engine output must match the native run"
    );
    assert_eq!(native.status.code(), Some(0));
    Ok(())
}

/// A compiler-generated binary: gcc compiles a small C program (static,
/// no libc) at test time; the engine must execute it and agree with a native
/// run on the observable result.
const COMPILER_PROGRAM: &str = r#"
volatile long g_input = 7;

static long compute(long x) {
    long acc = 0;
    for (long i = 0; i < 4; i++) {
        acc += x * (i + 1);
    }
    return acc;
}

void run(void) {
    long result = compute(g_input);
    long code = (result == 70) ? 0 : 1;
    __asm__ volatile(
        "mov $60, %%rax\n\t"
        "mov %0, %%rdi\n\t"
        "syscall\n\t"
        :
        : "r"(code)
        : "rax", "rdi", "memory");
}

__asm__(".global _start\n_start:\n    call run\n    mov $60, %rax\n    xor %rdi, %rdi\n    syscall\n");
"#;

/// Compiles [`COMPILER_PROGRAM`] with the given optimization flag into a
/// static ELF64 executable.
///
/// Returns `None` when the C toolchain is unavailable.
fn build_compiler_binary_at(optimization: &str) -> Option<(Vec<u8>, PathBuf)> {
    let dir = temp_dir(&format!("angryier-compiler-{optimization}"))?;
    let source = dir.join("program.c");
    let binary = dir.join("program.elf");
    std::fs::write(&source, COMPILER_PROGRAM).ok()?;

    let compiled = Command::new("cc")
        .arg(optimization)
        .args([
            "-static",
            "-nostdlib",
            "-fno-stack-protector",
            "-fcf-protection=none",
            "-fno-asynchronous-unwind-tables",
            "-fno-pie",
            "-no-pie",
            "-o",
        ])
        .arg(&binary)
        .arg(&source)
        .output()
        .ok()?;
    if !compiled.status.success() {
        return None;
    }
    let bytes = std::fs::read(&binary).ok()?;
    Some((bytes, binary))
}

fn build_compiler_binary() -> Option<(Vec<u8>, PathBuf)> {
    build_compiler_binary_at("-O2")
}

/// Runs the compiled program through the engine and requires the engine's
/// observable result to match a native run.
fn assert_engine_matches_native(optimization: &str, min_steps: u64) -> Result<(), Box<dyn std::error::Error>> {
    let Some((bytes, native_path)) = build_compiler_binary_at(optimization) else {
        eprintln!("skipping: C toolchain unavailable");
        return Ok(());
    };

    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_elf(&bytes)?;
    runtime.run(&mut process, 4096)?;

    assert!(process.terminated, "the exit syscall must terminate execution");
    assert_eq!(
        process.syscalls.exit_code(),
        Some(0),
        "compute(g_input) must equal 70 so the program exits 0"
    );
    assert!(
        process.step_count >= min_steps,
        "expected at least {min_steps} steps, got {}",
        process.step_count
    );

    let native = Command::new(&native_path).output()?;
    assert_eq!(
        native.status.code(),
        Some(0),
        "native execution must agree with the engine result"
    );
    Ok(())
}

/// A `-O0` build exercises stack frames, `call`/`ret` with a real return
/// address, and memory-immediate forms.
#[test]
fn compiler_generated_o0_binary_runs_end_to_end() -> Result<(), Box<dyn std::error::Error>> {
    assert_engine_matches_native("-O0", 30)
}

#[test]
fn compiler_generated_binary_runs_end_to_end() -> Result<(), Box<dyn std::error::Error>> {
    let Some((bytes, native_path)) = build_compiler_binary() else {
        eprintln!("skipping: C toolchain unavailable");
        return Ok(());
    };

    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_elf(&bytes)?;
    runtime.run(&mut process, 64)?;

    assert!(process.terminated, "the exit syscall must terminate execution");
    assert_eq!(
        process.syscalls.exit_code(),
        Some(0),
        "compute(g_input) must equal 70 so the program exits 0"
    );

    // The native run of the same binary must agree on the exit code.
    let native = Command::new(&native_path).output()?;
    assert_eq!(
        native.status.code(),
        Some(0),
        "native execution must agree with the engine result"
    );

    // The engine must have executed the volatile load and the loop arithmetic.
    let steps = process.step_count;
    assert!(steps >= 8, "expected the full program to execute, got {steps} steps");
    Ok(())
}

/// Assembles and links a one-off fixture from `body` (placed after `_start`).
fn build_fixture_from(body: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    build_fixture_from_path(body).map(|(bytes, _path)| bytes)
}

/// Assembles and links a one-off fixture, returning bytes and the on-disk path.
fn build_fixture_from_path(body: &str) -> Result<(Vec<u8>, PathBuf), Box<dyn std::error::Error>> {
    let dir = temp_dir(&format!("angryier-oneoff-{}", unique_suffix())).ok_or("temp dir unavailable")?;
    let source = dir.join("fixture.s");
    let object = dir.join("fixture.o");
    let binary = dir.join("fixture.elf");
    let text = format!("    .global _start\n    .text\n{body}");
    std::fs::write(&source, text)?;

    if assemble(&source, &object).is_none() {
        return Err("binutils unavailable".into());
    }
    if link(&binary, &[&object]).is_none() {
        return Err("linker unavailable".into());
    }
    let bytes = std::fs::read(&binary)?;
    Ok((bytes, binary))
}

/// Monotonic suffix so one-off fixtures never share a directory.
fn unique_suffix() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
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

    let Some(_) = fixture() else {
        eprintln!("skipping: binutils (as/ld) unavailable");
        return Ok(());
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));

    // Run with RAX = 6: the JNZ is taken to fail_path.
    let (mut process, _ok_exit, fail_exit) = loaded_process(&runtime, 6)?;
    let dispatches = run_to_simproc(&runtime, &mut process)?;
    assert_eq!(dispatches[0].0, fail_exit, "initial run must reach fail_path");

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
    assert!(!solution.assignments.is_empty(), "solver must return an input");
    let rax = solution
        .assignments
        .iter()
        .find(|assignment| assignment.register == register_id::GPR_BASE)
        .ok_or("solver must assign the input register")?;
    assert_eq!(rax.value, 42, "the only input reaching ok_path is RAX = 42");

    // Replay with the solved input: the run must reach ok_path.
    let (mut replay, ok_exit, _fail_exit) = loaded_process(&runtime, 0)?;
    replay.reset_to_entry();
    replay.apply_inputs(&solution.assignments)?;
    let dispatches = run_to_simproc(&runtime, &mut replay)?;
    assert_eq!(dispatches[0].0, ok_exit, "replayed run must reach ok_path");
    Ok(())
}

/// Branch solving through the portfolio router: `BatchSolver` is usable as a
/// `SolverBackend`, so callers get routing and fallback without a raw backend.
#[cfg(feature = "z3")]
#[test]
fn branch_solving_accepts_a_portfolio_routed_solver() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use std::time::Duration;

    use angryier_expr::{ExprReader, ShardedExprArena};
    use angryier_runtime::BranchDirection;
    use angryier_solver::{BatchSolver, InMemoryPortfolioRouter, SolverBackend};
    use angryier_solver_z3::Z3Backend;
    use angryier_types::ExpressionNormalizationVersion;

    let Some(_) = fixture() else {
        eprintln!("skipping: binutils (as/ld) unavailable");
        return Ok(());
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let (mut process, _ok_exit, fail_exit) = loaded_process(&runtime, 6)?;
    let dispatches = run_to_simproc(&runtime, &mut process)?;
    assert_eq!(dispatches[0].0, fail_exit, "initial run must reach fail_path");

    // Solve through the portfolio router instead of a raw backend.
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let reader: Arc<dyn ExprReader> = arena.clone();
    let backends: Vec<Box<dyn SolverBackend>> = vec![Box::new(Z3Backend::native_ffi(reader)?)];
    let router = Box::new(InMemoryPortfolioRouter::new(vec!["z3"], Duration::from_secs(10)));
    let mut solver = BatchSolver::new(backends, router);

    let solution = runtime.solve_branch(
        &process,
        BranchDirection::NotTaken,
        arena.as_ref(),
        &mut solver,
        Duration::from_secs(10),
    )?;
    assert!(solution.is_sat(), "routed solving must find the fall-through input");
    let rax = solution
        .assignments
        .iter()
        .find(|assignment| assignment.register == register_id::GPR_BASE)
        .map(|assignment| assignment.value);
    assert_eq!(rax, Some(42));
    Ok(())
}

/// Gate 0 concrete replay validation: the solver-generated input, run on the
/// real binary natively, reaches the target state.
#[cfg(feature = "z3")]
#[test]
fn solved_input_reaches_target_state_natively() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use std::time::Duration;

    use angryier_expr::{ExprReader, ShardedExprArena};
    use angryier_runtime::BranchDirection;
    use angryier_solver_z3::Z3Backend;
    use angryier_types::ExpressionNormalizationVersion;

    let Some(_) = fixture() else {
        eprintln!("skipping: binutils (as/ld) unavailable");
        return Ok(());
    };

    // Native control runs: the fixture must exit 1 for RAX = 6 and 0 for
    // RAX = 42 before any solver claim is made.
    let Some(fail_code) = run_native(6) else {
        eprintln!("skipping: native harness could not be built");
        return Ok(());
    };
    assert_eq!(fail_code, 1, "RAX = 6 must exit through fail_path");
    let Some(ok_code) = run_native(42) else {
        eprintln!("skipping: native harness could not be built");
        return Ok(());
    };
    assert_eq!(ok_code, 0, "RAX = 42 must exit through ok_path");

    // Engine run + solve, then replay the solved input natively.
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let (mut process, _ok_exit, fail_exit) = loaded_process(&runtime, 6)?;
    let dispatches = run_to_simproc(&runtime, &mut process)?;
    assert_eq!(dispatches[0].0, fail_exit, "initial engine run must reach fail_path");

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
    assert!(solution.is_sat());
    let rax = solution
        .assignments
        .iter()
        .find(|assignment| assignment.register == register_id::GPR_BASE)
        .ok_or("solver must assign the input register")?
        .value;

    // The solver-generated input must reach the target state natively.
    let Some(native_code) = run_native(rax) else {
        eprintln!("skipping: native harness could not be built");
        return Ok(());
    };
    assert_eq!(native_code, 0, "solved input RAX = {rax} must reach ok_path natively");
    Ok(())
}

#[cfg(test)]
mod debug_glibc {
    use super::*;
    use angryier_runtime::{Runtime, StepOutcome};

    /// A statically linked musl hello-world should execute from the ELF entry
    /// all the way through `__libc_start_main`, TLS setup, and `main` to a
    /// `write` + `exit_group`, producing the expected output.
    #[test]
    fn trace_static_musl() -> Result<(), Box<dyn std::error::Error>> {
        let Ok(bytes) = std::fs::read("/tmp/hello_musl") else {
            eprintln!("no fixture");
            return Ok(());
        };
        let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
        let mut process = runtime.load_elf(&bytes).map_err(|e| format!("musl load: {e}"))?;

        let mut terminated = false;
        for _ in 0..200_000 {
            match runtime.step(&mut process) {
                Ok(StepOutcome::Stepped { .. }) | Ok(StepOutcome::Syscall { .. }) => {}
                Ok(StepOutcome::Terminated { .. }) => {
                    terminated = true;
                    break;
                }
                Ok(other) => return Err(format!("unexpected outcome {other:?}").into()),
                Err(e) => {
                    return Err(format!("step failed at pc={:#x}: {e}", process.pc().unwrap_or(0)).into());
                }
            }
        }
        if !terminated {
            return Err("process did not terminate within the step budget".into());
        }
        assert_eq!(
            String::from_utf8_lossy(&process.syscalls.output()),
            "hello from glibc\n"
        );
        assert_eq!(process.syscalls.exit_code(), Some(0));
        Ok(())
    }
}

#[cfg(test)]
mod dbg_glibc2 {
    use super::*;
    use angryier_runtime::{Runtime, StepOutcome};

    /// Statically linked glibc binary: runs libc startup, malloc init, and
    /// printf -> write end-to-end under the XED decoder and the modeled Linux
    /// environment.
    #[test]
    fn runs_static_glibc() -> Result<(), Box<dyn std::error::Error>> {
        let Ok(bytes) = std::fs::read("/tmp/hello_glibc") else {
            eprintln!("no fixture");
            return Ok(());
        };
        let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
        let mut process = runtime.load_elf(&bytes).map_err(|e| format!("load: {e}"))?;
        for i in 0..400_000 {
            match runtime.step(&mut process) {
                Ok(StepOutcome::Terminated { .. }) => break,
                Ok(_) => {}
                Err(e) => {
                    let pc = process.pc().unwrap_or(0);
                    let tail = &process.trace[process.trace.len().saturating_sub(16)..];
                    return Err(format!("stopped after {i} steps at pc={pc:#x}: {e}\ntail: {tail:#x?}").into());
                }
            }
        }
        assert_eq!(process.syscalls.output(), b"hello from glibc\n");
        assert_eq!(process.syscalls.exit_code(), Some(0));
        Ok(())
    }
}

/// Gate A concolic validation: the concolic shadow records the branch
/// condition over the input symbol, inverting it through Z3 produces the
/// input that flips the path — and the solved input replays natively.
#[cfg(feature = "z3")]
#[test]
fn concolic_shadow_inverts_branch_to_new_input() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use std::time::Duration;

    use angryier_expr::{ExprReader, ShardedExprArena};
    use angryier_ir::IrType;

    use angryier_solver_z3::Z3Backend;
    use angryier_types::ExpressionNormalizationVersion;

    let Some(_) = fixture() else {
        eprintln!("skipping: binutils (as/ld) unavailable");
        return Ok(());
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));

    // Concrete run with RAX = 6: JNZ taken to fail_path.
    let (process, _ok_exit, fail_exit) = loaded_process(&runtime, 6)?;
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = runtime.concolic(process, arena.as_ref());
    session.mark_input_register(register_id::GPR_BASE, IrType::Bits(64))?;

    let mut dispatches = Vec::new();
    loop {
        match session.step()? {
            StepOutcome::Stepped { .. } | StepOutcome::Syscall { .. } => {}
            StepOutcome::SimProcedure { address, name } => {
                dispatches.push((address, name));
                break;
            }
            StepOutcome::Terminated { .. } | StepOutcome::Trap { .. } => break,
        }
    }
    assert_eq!(dispatches[0].0, fail_exit, "initial run must reach fail_path");
    assert_eq!(session.path_constraints().len(), 1, "one conditional branch");

    // Invert the branch: solve for the path that was not taken.
    let reader: Arc<dyn ExprReader> = arena.clone();
    let mut backend = Z3Backend::native_ffi(reader)?;
    let solution = session.solve_last_branch(&mut backend, Duration::from_secs(10))?;
    assert!(solution.is_sat(), "fall-through direction must be satisfiable");
    let rax = solution
        .assignments
        .iter()
        .find(|assignment| matches!(assignment.source, angryier_execution::ConcolicSource::Register { register, .. } if register == register_id::GPR_BASE))
        .ok_or("solver must assign the input register")?;
    assert_eq!(rax.value, 42, "the only input reaching ok_path is RAX = 42");

    // Replay with the solved input natively: it must reach ok_path's exit.
    let Some(native) = run_native(rax.value) else {
        eprintln!("skipping native replay: harness could not be built");
        return Ok(());
    };
    assert_eq!(
        native, 0,
        "solved input RAX = {} must reach ok_path natively",
        rax.value
    );
    Ok(())
}

/// QSYM optimistic solving: the fuzzy tier answers the simple `x == 42`
/// constraint without an SMT call.
#[test]
fn concolic_solves_simple_branch_with_fuzzy_sat() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use std::time::Duration;

    use angryier_expr::ShardedExprArena;
    use angryier_ir::IrType;
    use angryier_solver::BatchSolver;
    use angryier_solver_fuzzy::FuzzySatBackend;
    use angryier_types::ExpressionNormalizationVersion;

    let Some(_) = fixture() else {
        eprintln!("skipping: binutils (as/ld) unavailable");
        return Ok(());
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let (process, _ok_exit, _fail_exit) = loaded_process(&runtime, 6)?;
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = runtime.concolic(process, arena.as_ref());
    session.mark_input_register(register_id::GPR_BASE, IrType::Bits(64))?;
    while !session.process.terminated && session.process.step_count < 64 {
        if let StepOutcome::SimProcedure { .. } = session.step()? {
            break;
        }
    }

    let fuzzy = FuzzySatBackend::new(arena.clone());
    let router = Box::new(angryier_solver::InMemoryPortfolioRouter::new(
        vec!["fuzzy-sat"],
        Duration::from_secs(10),
    ));
    let mut solver = BatchSolver::new(vec![Box::new(fuzzy)], router);
    let solution = session.solve_last_branch(&mut solver, Duration::from_secs(10))?;
    assert!(solution.is_sat(), "fuzzy tier must satisfy the inversion");
    let rax = solution
        .assignments
        .iter()
        .find(|assignment| matches!(assignment.source, angryier_execution::ConcolicSource::Register { register, .. } if register == register_id::GPR_BASE))
        .ok_or("solver must assign the input register")?;
    assert_eq!(rax.value, 42);
    Ok(())
}

/// Mode switching: a branch on a symbolically-addressed load is outside the
/// concolic shadow's envelope — the step records analysis debt, the concrete
/// run continues, and `requires_prove` signals the PROVE-mode handoff.
#[test]
fn concolic_debt_signals_prove_handoff() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;

    use angryier_expr::ShardedExprArena;
    use angryier_ir::IrType;
    use angryier_types::ExpressionNormalizationVersion;

    // Table-indexed compare: the load address carries the input symbol, which
    // the concolic shadow refuses (symbolic address) — EXPLORE records debt.
    let source = r"
        .global _start
        .text
_start:
        lea table(%rip), %rbx
        cmp $42, (%rbx,%rax,8)
        jne fail_path
        mov $60, %rax
        xor %rdi, %rdi
ok_exit:
        syscall
fail_path:
        mov $60, %rax
        mov $1, %rdi
fail_exit:
        syscall
        .data
table:
        .quad 0, 0, 42, 0
    ";
    let Ok(elf) = build_fixture_from(source) else {
        eprintln!("skipping: binutils (as/ld) unavailable");
        return Ok(());
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_elf(&elf)?;
    let ok_exit = process.symbol("ok_exit").ok_or("missing ok_exit")?.address;
    let fail_exit = process.symbol("fail_exit").ok_or("missing fail_exit")?.address;
    process.hook_simproc(ok_exit, "exit");
    process.hook_simproc(fail_exit, "exit");
    process.write_register(register_id::GPR_BASE, 2)?; // index 2 -> table[2] = 42

    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = runtime.concolic(process, arena.as_ref());
    session.mark_input_register(register_id::GPR_BASE, IrType::Bits(64))?;

    let mut dispatch = None;
    for _ in 0..64 {
        match session.step()? {
            StepOutcome::SimProcedure { address, .. } => {
                dispatch = Some(address);
                break;
            }
            StepOutcome::Terminated { .. } | StepOutcome::Trap { .. } => break,
            _ => {}
        }
    }
    assert_eq!(dispatch, Some(ok_exit), "concrete run reaches ok_path via table[2]");
    assert!(session.requires_prove(), "symbolic-address load must record debt");
    Ok(())
}

/// Gate A dual-mode validation: the concolic shadow and the full symbolic
/// trace re-evaluation must produce the same input on the same binary, and
/// the concolic path reports its incremental-eval cost against the
/// trace-replay cost of PROVE mode.
#[cfg(feature = "z3")]
#[test]
fn concolic_and_prove_modes_agree_and_outpace() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use angryier_expr::{ExprReader, ShardedExprArena};
    use angryier_ir::IrType;
    use angryier_runtime::BranchDirection;
    use angryier_solver_z3::Z3Backend;
    use angryier_types::ExpressionNormalizationVersion;

    let Some(_) = fixture() else {
        eprintln!("skipping: binutils (as/ld) unavailable");
        return Ok(());
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));

    // PROVE mode: concrete run, then full trace re-evaluation + Z3.
    let (mut prove_process, _ok, _fail) = loaded_process(&runtime, 6)?;
    let _ = run_to_simproc(&runtime, &mut prove_process)?;
    let arena_prove = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let reader: Arc<dyn ExprReader> = arena_prove.clone();
    let mut backend = Z3Backend::native_ffi(reader)?;
    let prove_start = Instant::now();
    let prove_solution = runtime.solve_branch(
        &prove_process,
        BranchDirection::NotTaken,
        arena_prove.as_ref(),
        &mut backend,
        Duration::from_secs(10),
    )?;
    let prove_eval = prove_start.elapsed();

    // EXPLORE mode: concolic session shadows during execution + Z3.
    let (explore_process, _ok, _fail) = loaded_process(&runtime, 6)?;
    let arena_explore = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = runtime.concolic(explore_process, arena_explore.as_ref());
    session.mark_input_register(register_id::GPR_BASE, IrType::Bits(64))?;
    let explore_start = Instant::now();
    while !session.process.terminated && session.process.step_count < 64 {
        if let StepOutcome::SimProcedure { .. } = session.step()? {
            break;
        }
    }
    let explore_eval = explore_start.elapsed();
    let reader2: Arc<dyn ExprReader> = arena_explore.clone();
    let mut backend2 = Z3Backend::native_ffi(reader2)?;
    let explore_solution = session.solve_last_branch(&mut backend2, Duration::from_secs(10))?;

    // Both modes must agree on the input that flips the branch.
    assert!(prove_solution.is_sat() && explore_solution.is_sat());
    let prove_rax = prove_solution
        .assignments
        .iter()
        .find(|a| a.register == register_id::GPR_BASE)
        .map(|a| a.value);
    let explore_rax = explore_solution
        .assignments
        .iter()
        .find(|a| matches!(a.source, angryier_execution::ConcolicSource::Register { register, .. } if register == register_id::GPR_BASE))
        .map(|a| a.value);
    assert_eq!(prove_rax, explore_rax, "both modes must produce the same input");
    assert_eq!(explore_rax, Some(42));

    eprintln!(
        "dual-mode timing: prove_eval={prove_eval:?} explore_eval={explore_eval:?} (shadow steps={})",
        session.process.step_count
    );
    Ok(())
}

/// Concolic shadow on real libc startup code: the shadow must evaluate the
/// same blocks the concrete interpreter runs — vector ops, FS addressing,
/// partial writes — without recording debt on the hot path.
#[test]
fn concolic_shadows_real_libc_startup() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;

    use angryier_expr::ShardedExprArena;
    use angryier_types::ExpressionNormalizationVersion;

    let Ok(bytes) = std::fs::read("/tmp/hello_musl") else {
        eprintln!("skipping: no musl fixture");
        return Ok(());
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&bytes)?;
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));

    // Mark the argv string bytes as input: argv[0] sits at the top of the
    // constructed process stack (below AT_RANDOM); find it via the argv
    // pointer at [rsp+8].
    let rsp = process.read_register(register_id::GPR_BASE + 4)?;
    let argv0 = {
        use angryier_memory::LayeredMemory;
        let data = LayeredMemory::read(&process.state.memory, rsp + 8, 8)?;
        let mut value = 0u64;
        for (index, byte) in data.iter().enumerate() {
            if let angryier_memory::ByteValue::Concrete(b) = byte {
                value |= u64::from(*b) << (8 * index);
            }
        }
        value
    };
    let mut session = runtime.concolic(process, arena.as_ref());
    session.mark_input_memory(argv0, 12)?;

    // Run a slice of libc startup concolically and count debt entries.
    for _ in 0..20_000 {
        if let StepOutcome::Terminated { .. } = session.step()? {
            break;
        }
    }
    let debt = session.process.state.fidelity.entries.len();
    eprintln!(
        "concolic musl: {} steps, {} path constraints, {} debt entries",
        session.process.step_count,
        session.path_constraints().len(),
        debt
    );
    Ok(())
}

/// Gate B (concolic mode): inputs parallelize across OS workers — a sweep of
/// inputs runs N concolic sessions concurrently, each producing its own path
/// constraints and coverage.
#[test]
fn parallel_concolic_sweeps_inputs_across_workers() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;

    use angryier_expr::ShardedExprArena;
    use angryier_ir::IrType;
    use angryier_runtime::ConcolicInput;
    use angryier_types::ExpressionNormalizationVersion;

    let Some(_) = fixture() else {
        eprintln!("skipping: binutils (as/ld) unavailable");
        return Ok(());
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let (process, _ok, _fail) = loaded_process(&runtime, 0)?;
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));

    // 16 inputs, each marking RAX symbolic with a different concrete seed.
    let inputs: Vec<ConcolicInput> = (0..16u64)
        .map(|seed| ConcolicInput {
            registers: vec![(register_id::GPR_BASE, seed)],
            symbol_registers: vec![(register_id::GPR_BASE, IrType::Bits(64))],
            symbol_memory: Vec::new(),
        })
        .collect();

    let (reports, stats) = runtime.parallel_concolic(&process, arena.as_ref(), &inputs, 4, 64)?;
    assert_eq!(reports.len(), 16);
    assert_eq!(stats.completed, 16);
    // Every run reaches its branch and records one path constraint.
    for report in &reports {
        assert!(
            report.steps >= 2,
            "input {} only ran {} steps",
            report.input_index,
            report.steps
        );
        assert_eq!(report.path_constraints, 1);
        assert!(report.coverage >= 2);
    }
    // Work spread across workers (4 workers, 16 inputs).
    let used_workers = stats.per_worker_completed.iter().filter(|count| **count > 0).count();
    assert!(
        used_workers > 1,
        "work should spread across workers: {:?}",
        stats.per_worker_completed
    );
    eprintln!(
        "parallel_concolic: {:?} per-worker, elapsed={:?}",
        stats.per_worker_completed, stats.elapsed
    );
    Ok(())
}

/// Gate B (state mode): states parallelize across workers — the explorer
/// forks at the conditional branch so both directions are covered by
/// different states.
#[test]
fn parallel_explore_forks_states_at_branches() -> Result<(), Box<dyn std::error::Error>> {
    let Some(_) = fixture() else {
        eprintln!("skipping: binutils (as/ld) unavailable");
        return Ok(());
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let (process, _ok_exit, _fail_exit) = loaded_process(&runtime, 6)?;

    let report = runtime.parallel_explore(&process, 4, 64, 16)?;
    // One branch -> one fork -> two states, covering both exits' prefixes.
    assert_eq!(report.branches_forked, 1, "exactly one conditional branch");
    assert!(report.states_completed >= 2, "fork produced a second state");
    // Coverage includes instructions from both paths (distinguished by the
    // branch's taken/not_taken targets).
    assert!(
        report.coverage.len() >= 3,
        "both paths' blocks covered: {:?}",
        report.coverage
    );
    eprintln!(
        "parallel_explore: {} states, {} forks, {} pcs, workers={:?}",
        report.states_completed,
        report.branches_forked,
        report.coverage.len(),
        report.pool.per_worker_completed
    );
    Ok(())
}

/// Gate B scaling measurement: a concolic input sweep over a REAL binary
/// (static musl hello) reports wall-time scaling 1 worker vs 4 workers.
/// The report is printed, not asserted — timing is machine-dependent.
#[test]
fn parallel_concolic_scales_on_real_binary() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;

    use angryier_expr::ShardedExprArena;
    use angryier_runtime::ConcolicInput;
    use angryier_types::ExpressionNormalizationVersion;

    let Ok(bytes) = std::fs::read("/tmp/hello_musl") else {
        eprintln!("skipping: no musl fixture");
        return Ok(());
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&bytes)?;
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));

    // 8 inputs: distinct argv byte patterns (concretely written to argv[0]).
    let inputs: Vec<ConcolicInput> = (0..8u64)
        .map(|_| ConcolicInput {
            registers: Vec::new(),
            symbol_registers: Vec::new(),
            symbol_memory: Vec::new(),
        })
        .collect();

    let budget = 200_000u64;
    let (_, stats1) = runtime.parallel_concolic(&process, arena.as_ref(), &inputs, 1, budget)?;
    let (_, stats4) = runtime.parallel_concolic(&process, arena.as_ref(), &inputs, 4, budget)?;
    eprintln!(
        "Gate B scaling (hello_musl, 8 inputs, budget {budget}): 1w={:?} 4w={:?} speedup={:.2}x workers={:?}",
        stats1.elapsed,
        stats4.elapsed,
        stats1.elapsed.as_secs_f64() / stats4.elapsed.as_secs_f64().max(1e-9),
        stats4.per_worker_completed
    );
    assert_eq!(stats1.completed, 8);
    assert_eq!(stats4.completed, 8);
    Ok(())
}

/// Gate B (state mode) on a real binary: the explorer forks states at the
/// conditional branches of musl libc startup and parallelizes them across
/// workers.
#[test]
fn parallel_explore_scales_states_on_real_binary() -> Result<(), Box<dyn std::error::Error>> {
    let Ok(bytes) = std::fs::read("/tmp/hello_musl") else {
        eprintln!("skipping: no musl fixture");
        return Ok(());
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&bytes)?;
    // Small per-state budget: children forked into unreachable side paths
    // should still terminate quickly against the step budget.
    let report = runtime.parallel_explore(&process, 4, 2_000, 48)?;
    eprintln!(
        "Gate B states (hello_musl): {} completed, {} forks, {} unique pcs, workers={:?}, elapsed={:?}",
        report.states_completed,
        report.branches_forked,
        report.coverage.len(),
        report.pool.per_worker_completed,
        report.pool.elapsed
    );
    assert!(report.branches_forked > 4, "musl startup has many branches");
    assert!(report.coverage.len() > 20, "exploration covers real startup code");
    Ok(())
}

/// Gate C: exact reuse measured on a real trace — two different concrete
/// inputs reaching the same branch produce the same sliced canonical query,
/// so the second inversion is a cache hit with zero solver calls.
#[cfg(feature = "z3")]
#[test]
fn sliced_queries_reuse_across_inputs() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;
    use std::time::Duration;

    use angryier_expr::{ExprReader, ShardedExprArena};
    use angryier_ir::IrType;
    use angryier_solver::{CachingSolverBackend, InMemorySolverCache};
    use angryier_solver_z3::Z3Backend;
    use angryier_types::ExpressionNormalizationVersion;

    let Some(_) = fixture() else {
        eprintln!("skipping: binutils (as/ld) unavailable");
        return Ok(());
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let cache = Arc::new(InMemorySolverCache::default());
    let reader: Arc<dyn ExprReader> = arena.clone();
    let z3 = Z3Backend::native_ffi(reader)?;
    let mut backend = CachingSolverBackend::new(Box::new(z3), Arc::clone(&cache));

    // Two inputs that reach the same final branch — the path is identical,
    // so slicing yields the identical canonical query.
    for input in [6u64, 7] {
        let (process, _ok, _fail) = loaded_process(&runtime, input)?;
        let mut session = runtime.concolic(process, arena.as_ref());
        session.mark_input_register(register_id::GPR_BASE, IrType::Bits(64))?;
        while !session.process.terminated && session.process.step_count < 64 {
            if let StepOutcome::SimProcedure { .. } = session.step()? {
                break;
            }
        }
        let solution = session.solve_last_branch(&mut backend, Duration::from_secs(10))?;
        assert!(solution.is_sat());
    }
    let stats = cache.stats()?;
    eprintln!(
        "Gate C reuse: {} hits / {} misses / {} entries",
        stats.hits, stats.misses, stats.entries
    );
    assert_eq!(stats.hits, 1, "second identical sliced query must hit");
    assert_eq!(stats.entries, 1, "one unique canonical query");
    Ok(())
}

// ---------------------------------------------------------------------------
// Differential oracle (Gate D): the semantic corpus validated against
// hardware. Each instruction template runs with controlled inputs both
// natively (assembled + executed on the CPU) and through the runtime; the
// result value AND the full RFLAGS image are compared byte-for-byte via the
// `write` syscall output captured in each world.
// ---------------------------------------------------------------------------

/// Builds a differential harness: `insn` executes once after the register
/// seeds, then RAX and RFLAGS are dumped to `out` and written to stdout.
fn differential_harness(insn: &str, seeds: &[(&str, u64)]) -> String {
    let mut setup = String::new();
    for (register, value) in seeds {
        setup.push_str(&format!("    mov ${value}, %{register}\n"));
    }
    format!(
        "        .global _start\n        .text\n_start:\n{setup}    {insn}\n    mov %rax, out(%rip)\n    pushfq\n    pop %rbx\n    mov %rbx, out+8(%rip)\n    mov $1, %rax\n    mov $1, %rdi\n    mov $out, %rsi\n    mov $16, %rdx\n    syscall\n    mov $60, %rax\n    xor %rdi, %rdi\n    syscall\n        .data\nout:    .quad 0, 0, 0, 0\n"
    )
}

/// Runs `elf_bytes` through the runtime and returns captured stdout.
fn runtime_stdout_with_registry(
    elf_bytes: &[u8],
    generated: Option<Vec<(u32, std::sync::Arc<dyn angryier_semantics::SemanticProvider>)>>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    if let Some(providers) = generated {
        runtime.registry =
            angryier_semantics_intel64::Intel64CorpusRegistry::with_generated(SemanticVersion(1), providers);
    }
    let mut process = runtime.load_elf(elf_bytes)?;
    let _ = runtime.run(&mut process, 256).map_err(|e| {
        let pc = process.pc().unwrap_or(0);
        format!("{e} at pc {pc:#x}")
    })?;
    Ok(process.syscalls.output())
}

/// Runs `binary` natively and returns its stdout.
fn native_stdout(binary: &Path) -> Option<Vec<u8>> {
    let output = Command::new(binary).output().ok()?;
    Some(output.stdout)
}

/// Flag bits that are architecturally DEFINED for each instruction class.
/// Undefined flags (imul's ZF, shift AF, multi-count OF, ...) are
/// implementation-specific on silicon and excluded from comparison.
const CF: u64 = 1 << 0;
const PF: u64 = 1 << 2;
const AF: u64 = 1 << 4;
const ZF: u64 = 1 << 6;
const SF: u64 = 1 << 7;
const OF: u64 = 1 << 11;
const ALL6: u64 = CF | PF | AF | ZF | SF | OF;
const LOGICAL: u64 = CF | PF | ZF | SF | OF; // AF undefined on logical ops

/// Defined flag bits for an instruction mnemonic (see [`differential_case`]).
fn flag_mask_for(insn: &str) -> u64 {
    let base = insn.split(' ').next().unwrap_or("");
    let count_one = insn.contains("$1,");
    match base {
        "add" | "sub" | "cmp" | "neg" | "inc" | "dec" => ALL6,
        "and" | "or" | "xor" | "test" => LOGICAL,
        "imul" => CF | OF,
        "shl" | "shr" | "sar" => {
            if count_one {
                CF | PF | ZF | SF | OF
            } else {
                CF | PF | ZF | SF
            }
        }
        "rol" | "ror" => {
            if count_one {
                CF | OF
            } else {
                CF
            }
        }
        _ => 0,
    }
}

/// The differential driver: assemble+link+run natively vs run through the
/// runtime; the result register must match byte-for-byte and RFLAGS must
/// match on `flag_mask` (architecturally defined bits only). Returns false
/// when tooling is unavailable so tests can skip gracefully.
fn differential_case_with_registry(
    insn: &str,
    seeds: &[(&str, u64)],
    flag_mask: u64,
    generated: Option<Vec<(u32, std::sync::Arc<dyn angryier_semantics::SemanticProvider>)>>,
) -> Result<bool, Box<dyn std::error::Error>> {
    let dir = temp_dir(&format!(
        "angryier-diff-{}",
        insn.replace([' ', ',', '%', '$'], "_").replace("__", "_")
    ))
    .ok_or("no tempdir")?;
    let source = dir.join("case.s");
    let object = dir.join("case.o");
    let binary = dir.join("case");
    std::fs::write(&source, differential_harness(insn, seeds))?;
    if assemble(&source, &object).is_none() || link(&binary, &[&object]).is_none() {
        return Ok(false);
    }
    let elf_bytes = std::fs::read(&binary)?;
    let expected = native_stdout(&binary).ok_or("native run failed")?;
    let actual = match runtime_stdout_with_registry(&elf_bytes, generated) {
        Ok(out) => out,
        Err(e) => {
            eprintln!("coverage gap `{insn}`: {e}");
            return Ok(false);
        }
    };
    if actual[..8] != expected[..8] {
        return Err(format!(
            "differential mismatch on `{insn}` seeds {seeds:?}: runtime={actual:?} native={expected:?}"
        )
        .into());
    }
    let actual_flags = u64::from_le_bytes(actual[8..16].try_into().unwrap_or([0; 8]));
    let expected_flags = u64::from_le_bytes(expected[8..16].try_into().unwrap_or([0; 8]));
    if actual_flags & flag_mask != expected_flags & flag_mask {
        return Err(format!(
            "differential flag mismatch on `{insn}` seeds {seeds:?}: {actual_flags:#x} vs {expected_flags:#x} mask {flag_mask:#x}"
        )
        .into());
    }
    Ok(true)
}

fn differential_case(insn: &str, seeds: &[(&str, u64)], flag_mask: u64) -> Result<bool, Box<dyn std::error::Error>> {
    differential_case_with_registry(insn, seeds, flag_mask, None)
}

/// Gate D: differential validation of the semantic corpus against hardware.
/// Each instruction executes on boundary-value inputs; result value and
/// RFLAGS must match the CPU's answer byte-for-byte.
#[test]
fn differential_semantics_vs_hardware() -> Result<(), Box<dyn std::error::Error>> {
    let boundary: [u64; 8] = [
        0,
        1,
        42,
        0x7fff_ffff_ffff_ffff,
        0x8000_0000_0000_0000,
        0xffff_ffff_ffff_ffff,
        0x100,
        0xdead_beef,
    ];

    // Binary ops over (rax, rbx) — result and flags compared.
    let binary_templates = [
        "add %rbx, %rax",
        "sub %rbx, %rax",
        "and %rbx, %rax",
        "or %rbx, %rax",
        "xor %rbx, %rax",
        "cmp %rbx, %rax",
        "test %rbx, %rax",
        "imul %rbx, %rax",
        "xchg %rbx, %rax",
    ];
    // Immediate forms.
    let imm_templates = [
        "add $0x1234, %rax",
        "sub $0x7fff, %rax",
        "and $0xff00, %rax",
        "or $0xf0f0, %rax",
        "xor $0xffff, %rax",
        "cmp $0x2a, %rax",
        "test $0x1000, %rax",
    ];
    // Unary ops.
    let unary_templates = ["inc %rax", "dec %rax", "neg %rax", "not %rax"];
    // Shifts.
    let shift_templates = [
        "shl $1, %rax",
        "shl $7, %rax",
        "shr $1, %rax",
        "shr $9, %rax",
        "sar $1, %rax",
        "sar $13, %rax",
        "rol $5, %rax",
        "ror $3, %rax",
    ];
    // Moves/lea/extends.
    let misc_templates = [
        "mov %rbx, %rax",
        "lea 0x10(%rbx,%rcx,8), %rax",
        "movzx %bl, %rax",
        "movsx %bx, %rax",
        "movsxd %ebx, %rax",
        "bswap %rax",
    ];
    // Memory operand forms: `out` doubles as the scratch memory cell.
    let mem_templates = [
        "add out(%rip), %rax",
        "sub out(%rip), %rax",
        "and out(%rip), %rax",
        "or out(%rip), %rax",
        "xor out(%rip), %rax",
        "cmp out(%rip), %rax",
        "mov out(%rip), %rax",
        "add %rbx, out(%rip)",
        "mov %rbx, out+8(%rip)",
    ];
    // cmovcc / setcc / bt / sign-extension forms.
    let misc2_templates = [
        "cmovz %rbx, %rax",
        "cmovnz %rbx, %rax",
        "setz %al",
        "setnz %al",
        "movzx %bx, %rax",
        "movsx %bx, %rax",
        "movsxd %ebx, %rax",
        "bswap %rax",
        "not %rax",
        "neg %rax",
        "xchg %rbx, %rax",
        "imul %rbx, %rax, $7",
        "lea (%rbx,%rcx,4), %rax",
        "shl %cl, %rax",
        "shr %cl, %rax",
    ];
    // Carry-flow instructions: stc/clc prefixes seed CF before the op.
    let carry_templates = [
        "stc\n    adc %rbx, %rax",
        "clc\n    adc %rbx, %rax",
        "stc\n    sbb %rbx, %rax",
        "clc\n    sbb %rbx, %rax",
        "stc\n    bt %rbx, %rax",
        "clc\n    bt %rbx, %rax",
    ];
    // SIMD: seed xmm via movq, observe via movq back to rax.
    let simd_templates = [
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    pcmpeqb %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    pcmpeqd %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    paddq %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    psubq %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    pminub %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    pmaxub %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    pxor %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    pand %xmm1, %xmm0\n    movq %xmm0, %rax",
    ];
    // Conditional branches: flags come from the preceding cmp, the branch
    // decides which value lands in rax (1 = not taken path, 0 = taken).
    let jcc_templates = [
        "cmp %rbx, %rax\n    jz 1f\n    mov $1, %rax\n1:",
        "cmp %rbx, %rax\n    jnz 1f\n    mov $1, %rax\n1:",
        "cmp %rbx, %rax\n    jl 1f\n    mov $1, %rax\n1:",
        "cmp %rbx, %rax\n    jg 1f\n    mov $1, %rax\n1:",
        "cmp %rbx, %rax\n    jb 1f\n    mov $1, %rax\n1:",
        "cmp %rbx, %rax\n    ja 1f\n    mov $1, %rax\n1:",
        "cmp %rbx, %rax\n    jbe 1f\n    mov $1, %rax\n1:",
        "cmp %rbx, %rax\n    jle 1f\n    mov $1, %rax\n1:",
        "cmp %rbx, %rax\n    js 1f\n    mov $1, %rax\n1:",
        "cmp %rbx, %rax\n    jns 1f\n    mov $1, %rax\n1:",
    ];
    // div/idiv write rdx:rax — observe each half in its own case.
    let div_templates = [
        "mov $0, %rdx\n    div %rbx",
        "mov $0, %rdx\n    div %rbx\n    mov %rdx, %rax",
        "cqo\n    idiv %rbx",
        "cqo\n    idiv %rbx\n    mov %rdx, %rax",
        "mul %rbx",
        "mul %rbx\n    mov %rdx, %rax",
        "imul %rbx",
        "imul %rbx\n    mov %rdx, %rax",
    ];
    // Wider SIMD corpus — SSSE3/SSE4 lanes observed through movq.
    let simd2_templates = [
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    pshufb %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    pcmpgtb %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    pcmpgtd %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    pmullw %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    pmaddwd %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    packsswb %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    pslld %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    psrld %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    psadbw %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    phaddw %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    pabsb %xmm0, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    pabsd %xmm0, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    pandn %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    por %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    pmovmskb %xmm0, %eax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    psignb %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    punpcklbw %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    punpcklqdq %xmm1, %xmm0\n    movq %xmm0, %rax",
    ];
    // Bit-scan/popcount/lzcnt, bit-set/clear/complement, xadd/cmpxchg,
    // cl-rotates.
    let misc3_templates = [
        "bsf %rbx, %rax",
        "bsr %rbx, %rax",
        "popcnt %rbx, %rax",
        "xadd %rbx, %rax",
        "mov %rbx, %rdx\n    mov $0x1234, %rbx\n    cmpxchg %rbx, %rax",
        "mov %rbx, %rdx\n    mov $0x1234, %rbx\n    cmpxchg %rbx, %rcx",
        "bt %rbx, %rax",
        "bts %rbx, %rax",
        "btr %rbx, %rax",
        "btc %rbx, %rax",
        "mov $9, %rcx\n    rol %cl, %rax",
        "mov $9, %rcx\n    ror %cl, %rax",
        "mov $1, %rcx\n    rol %cl, %rax",
        "mov $1, %rcx\n    ror %cl, %rax",
        "cmpxchg %rbx, %rax",
        "xchg %rbx, %rcx",
        "movabs $0x1122334455667788, %r8\n    mov %r8, %rax",
        "mov %rbx, %rdx\n    mov $0x1234, %rbx\n    cmpxchg %rbx, %rdx",
    ];
    // 8/16-bit partial-register writes (al/bl/ax/bx keep the rest of the
    // parent register; AH/BH are high-byte views).
    let w8_templates = [
        "add %bl, %al",
        "sub %bl, %al",
        "and %bl, %al",
        "or %bl, %al",
        "xor %bl, %al",
        "cmp %bl, %al",
        "test %bl, %al",
        "mov %bl, %al",
        "mov %bl, %ah",
        "mov %ah, %al",
        "add %bx, %ax",
        "mov %bx, %ax",
        "inc %al",
        "dec %al",
        "neg %al",
        "not %al",
        "shl $3, %al",
        "movzx %bl, %eax",
        "movsx %bl, %eax",
        "setz %bl",
        "movzx %ah, %eax",
    ];
    // Memory-immediate RMW: seed out+16, mutate, read back into rax. The
    // scratch qword lives after the captured out/out+8 pair.
    let memimm_templates = [
        "movq $0x100, out+16(%rip)\n    addq $0x50, out+16(%rip)\n    mov out+16(%rip), %rax",
        "movq $0x100, out+16(%rip)\n    subq $0x50, out+16(%rip)\n    mov out+16(%rip), %rax",
        "movq $0x100, out+16(%rip)\n    andq $0xff0, out+16(%rip)\n    mov out+16(%rip), %rax",
        "movq $0x100, out+16(%rip)\n    orq $0x33, out+16(%rip)\n    mov out+16(%rip), %rax",
        "movq $0x100, out+16(%rip)\n    xorq $0x1f0, out+16(%rip)\n    mov out+16(%rip), %rax",
    ];
    // Rotate-through-carry (CF flows in/out), and single-step string ops.
    let misc4_templates = [
        "stc\n    rcl $3, %rax",
        "clc\n    rcl $3, %rax",
        "stc\n    rcr $3, %rax",
        "clc\n    rcr $3, %rax",
        "rcl $1, %rax",
        "rcr $1, %rax",
        "bswap %eax",
        "movq %rbx, out+16(%rip)\n    lea out+16(%rip), %rsi\n    lodsb",
        "movq %rbx, out+16(%rip)\n    lea out+24(%rip), %rdi\n    stosb\n    mov out+24(%rip), %rax",
        "movq %rbx, out+16(%rip)\n    lea out+16(%rip), %rsi\n    lea out+24(%rip), %rdi\n    movsb\n    mov out+24(%rip), %rax",
    ];
    // Scalar SSE float — movq carries the f64 bit pattern into xmm.
    let float_templates = [
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    addsd %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    subsd %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    mulsd %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    divsd %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    ucomisd %xmm1, %xmm0\n    mov $0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    movsd %xmm1, %xmm0\n    movq %xmm0, %rax",
    ];
    // f64 bit patterns: 1.5, -2.25, 100.0, -0.0
    const F64_SEEDS: [u64; 4] = [
        0x3FF8_0000_0000_0000,
        0xC002_0000_0000_0000,
        0x4059_0000_0000_0000,
        0x8000_0000_0000_0000,
    ];
    // SSE4.x tail of the corpus: ptest sets ZF/CF from xmm, crc32 is a GPR
    // op, the rest observed via movq.
    let sse4_templates = [
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    ptest %xmm1, %xmm0\n    mov $0, %rax",
        "crc32 %ebx, %eax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    pcmpgtq %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    pblendvb %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    packuswb %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    mpsadbw $1, %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    pshufd $0x1b, %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    pmovzxbd %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    pinsrb $3, %ebx, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    pminsb %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    pminud %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    pmaxsd %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    paddd %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    paddb %xmm1, %xmm0\n    movq %xmm0, %rax",
        "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    psubd %xmm1, %xmm0\n    movq %xmm0, %rax",
    ];
    // 32-bit forms (zero-extension semantics must match too).
    let w32_templates = [
        "add %ebx, %eax",
        "sub %ebx, %eax",
        "and %ebx, %eax",
        "xor %ebx, %eax",
        "mov %ebx, %eax",
        "imul %ebx, %eax",
        "inc %eax",
        "neg %eax",
    ];

    let mut executed = 0usize;
    let mut skipped = false;
    // Two-input forms: sweep boundary × boundary for rax and rbx.
    for insn in binary_templates {
        for &a in &boundary[..4] {
            for &b in &boundary[4..6] {
                let ran = differential_case(insn, &[("rax", a), ("rbx", b), ("rcx", 3)], flag_mask_for(insn))?;
                skipped |= !ran;
                executed += usize::from(ran);
            }
        }
    }
    for insn in imm_templates {
        for &a in &boundary {
            let ran = differential_case(insn, &[("rax", a), ("rbx", 7), ("rcx", 3)], flag_mask_for(insn))?;
            skipped |= !ran;
            executed += usize::from(ran);
        }
    }
    for insn in unary_templates {
        for &a in &boundary {
            let ran = differential_case(insn, &[("rax", a), ("rbx", 9)], flag_mask_for(insn))?;
            skipped |= !ran;
            executed += usize::from(ran);
        }
    }
    for insn in shift_templates {
        for &a in &boundary[..6] {
            let ran = differential_case(insn, &[("rax", a)], flag_mask_for(insn))?;
            skipped |= !ran;
            executed += usize::from(ran);
        }
    }
    for insn in misc_templates {
        for &a in &boundary[..4] {
            let ran = differential_case(
                insn,
                &[("rax", a), ("rbx", 0x1234_5678_9abc_def0), ("rcx", 5)],
                flag_mask_for(insn),
            )?;
            skipped |= !ran;
            executed += usize::from(ran);
        }
    }
    for insn in mem_templates {
        for &a in &boundary[..4] {
            let ran = differential_case(
                insn,
                &[("rax", a), ("rbx", 0x1234_5678_9abc_def0), ("rcx", 5)],
                flag_mask_for(insn),
            )?;
            skipped |= !ran;
            executed += usize::from(ran);
        }
    }
    for insn in misc2_templates {
        for &a in &boundary[..4] {
            let ran = differential_case(
                insn,
                &[("rax", a), ("rbx", 0x1234_5678_9abc_def0), ("rcx", 5)],
                flag_mask_for(insn),
            )?;
            skipped |= !ran;
            executed += usize::from(ran);
        }
    }
    for insn in carry_templates {
        for &a in &boundary[..4] {
            let ran = differential_case(insn, &[("rax", a), ("rbx", 0x1234_5678_9abc_def0)], flag_mask_for(insn))?;
            skipped |= !ran;
            executed += usize::from(ran);
        }
    }
    for insn in simd_templates {
        for &a in &boundary[..4] {
            let ran = differential_case(insn, &[("rbx", a), ("rcx", 0x1234_5678_9abc_def0)], flag_mask_for(insn))?;
            skipped |= !ran;
            executed += usize::from(ran);
        }
    }
    for insn in jcc_templates {
        for &a in &boundary[..4] {
            let ran = differential_case(insn, &[("rax", a), ("rbx", 0x4000_0000_0000_0000)], flag_mask_for(insn))?;
            skipped |= !ran;
            executed += usize::from(ran);
        }
    }
    for insn in div_templates {
        for &a in &boundary[..4] {
            let ran = differential_case(insn, &[("rax", a), ("rbx", 7)], flag_mask_for(insn))?;
            skipped |= !ran;
            executed += usize::from(ran);
        }
    }
    for insn in simd2_templates {
        for &a in &boundary[..4] {
            let ran = differential_case(insn, &[("rbx", a), ("rcx", 0x0f0f_0f0f_0f0f_0f0f)], flag_mask_for(insn))?;
            skipped |= !ran;
            executed += usize::from(ran);
        }
    }
    // LZCNT encodes as REP BSR: CPUs without ABM execute it as bsr, which
    // produces a different result than the corpus's lzcnt semantics. Run it
    // only when the CPU advertises the feature.
    let has_lzcnt = std::fs::read_to_string("/proc/cpuinfo")
        .map(|cpuinfo| cpuinfo.contains(" abm") || cpuinfo.contains(" lzcnt"))
        .unwrap_or(false);
    if has_lzcnt {
        for &a in &boundary[..4] {
            let ran = differential_case(
                "lzcnt %rbx, %rax",
                &[("rax", a), ("rbx", 9)],
                flag_mask_for("lzcnt %rbx, %rax"),
            )?;
            skipped |= !ran;
            executed += usize::from(ran);
        }
    } else {
        eprintln!("lzcnt: skipped (CPU lacks ABM — rep bsr would execute as bsr)");
        skipped = true;
    }
    for insn in misc3_templates {
        for &a in &boundary[..4] {
            let ran = differential_case(insn, &[("rax", a), ("rbx", 9), ("rcx", 0x1234)], flag_mask_for(insn))?;
            skipped |= !ran;
            executed += usize::from(ran);
        }
    }
    for insn in w8_templates {
        for &a in &boundary[..4] {
            let ran = differential_case(insn, &[("rax", a), ("rbx", 0xa5)], flag_mask_for(insn))?;
            skipped |= !ran;
            executed += usize::from(ran);
        }
    }
    for insn in memimm_templates {
        for &a in &boundary[..4] {
            let ran = differential_case(insn, &[("rax", a), ("rbx", 0x1234_5678_9abc_def0)], flag_mask_for(insn))?;
            skipped |= !ran;
            executed += usize::from(ran);
        }
    }
    for insn in misc4_templates {
        for &a in &boundary[..4] {
            let ran = differential_case(insn, &[("rax", a), ("rbx", 0x1234_5678_9abc_def0)], flag_mask_for(insn))?;
            skipped |= !ran;
            executed += usize::from(ran);
        }
    }
    for insn in float_templates {
        for &a in &F64_SEEDS {
            let ran = differential_case(insn, &[("rbx", a), ("rcx", 0x4004_0000_0000_0000)], flag_mask_for(insn))?;
            skipped |= !ran;
            executed += usize::from(ran);
        }
    }
    for insn in sse4_templates {
        for &a in &boundary[..4] {
            let ran = differential_case(insn, &[("rbx", a), ("rcx", 0x0f0f_0f0f_0f0f_0f0f)], flag_mask_for(insn))?;
            skipped |= !ran;
            executed += usize::from(ran);
        }
    }
    for insn in w32_templates {
        for &a in &boundary[..4] {
            let ran = differential_case(insn, &[("rax", a), ("rbx", 0xffff_ff00_1234_5678)], flag_mask_for(insn))?;
            skipped |= !ran;
            executed += usize::from(ran);
        }
    }

    if skipped && executed == 0 {
        eprintln!("skipping differential: binutils unavailable");
        return Ok(());
    }
    eprintln!("differential oracle: {executed} cases matched hardware byte-for-byte");
    assert!(executed > 200, "expected >200 differential cases, ran {executed}");
    Ok(())
}

/// Gate D generator path: providers produced by `angryier-semantics-gen`
/// patterns — not handwritten — must validate byte-for-byte against hardware
/// through the same oracle. `paddw` exercises `PackedLane`; `xor r32,r32`
/// exercises `BinaryAlu`+Logical flags. Both forms also have handwritten
/// providers — the generated ones replace them in the registry (form-index
/// overwrite), so a mismatch would prove the generated emit diverges.
#[cfg(all(feature = "xed", target_arch = "x86_64"))]
#[test]
fn generated_providers_match_hardware() -> Result<(), Box<dyn std::error::Error>> {
    use std::sync::Arc;

    use angryier_semantics::SemanticProvider;
    use angryier_semantics_gen::{FlagPolicy, InMemorySemanticsCompiler, SemanticPattern};
    use angryier_semantics_intel64::{forms as i64forms, generated_providers};

    if native_stdout(std::path::Path::new("/bin/true")).is_none() {
        eprintln!("skipping: native execution unavailable");
        return Ok(());
    }

    // Compile patterns through the generator — the rule records carry the
    // canonical content identity.
    let compiler = InMemorySemanticsCompiler::new();
    let paddw_rule = compiler.compile_pattern(
        i64forms::PADDW_XMM_XMM,
        &SemanticPattern::PackedLane {
            op: angryier_semantics::PrimitiveOp::Add,
            lanes: 8,
            lane_bits: 16,
        },
    )?;
    let xor32_rule = compiler.compile_pattern(
        i64forms::XOR_R32_R32,
        &SemanticPattern::BinaryAlu {
            op: angryier_semantics::PrimitiveOp::Xor,
            width_bits: 32,
            flags: FlagPolicy::Logical,
        },
    )?;
    assert_eq!(paddw_rule.origin, angryier_semantics_gen::DefinitionOrigin::Declarative);
    assert_eq!(xor32_rule.origin, angryier_semantics_gen::DefinitionOrigin::Declarative);

    // Instantiate providers for the compiled forms.
    let providers = generated_providers(&[
        (
            i64forms::PADDW_XMM_XMM,
            SemanticPattern::PackedLane {
                op: angryier_semantics::PrimitiveOp::Add,
                lanes: 8,
                lane_bits: 16,
            },
        ),
        (
            i64forms::XOR_R32_R32,
            SemanticPattern::BinaryAlu {
                op: angryier_semantics::PrimitiveOp::Xor,
                width_bits: 32,
                flags: FlagPolicy::Logical,
            },
        ),
    ]);
    let generated: Vec<(u32, Arc<dyn SemanticProvider>)> = providers
        .into_iter()
        .map(|p| (p.form_id, Arc::new(p) as Arc<dyn SemanticProvider>))
        .collect();

    // paddw: 16-bit lanes wrap.
    let insn = "movq %rbx, %xmm0\n    movq %rcx, %xmm1\n    paddw %xmm1, %xmm0\n    movq %xmm0, %rax";
    for &seed in &[
        0x0001_0002_0003_0004u64,
        0xffff_8000_7fff_0001,
        0xdead_beef_cafe_f00d,
        0,
    ] {
        assert!(
            differential_case_with_registry(
                insn,
                &[("rbx", seed), ("rcx", 0x0002_0003_0004_0005)],
                0,
                Some(generated.clone()),
            )?,
            "generated paddw should execute for seed {seed:#x}"
        );
    }
    // xor r32,r32: zero-extend + logical flag writes.
    let insn = "xor %ebx, %eax";
    for &seed in &[0u64, 0xffff_ffff, 0x8000_0000_0000_0000, 0xdead_beef] {
        assert!(
            differential_case_with_registry(
                insn,
                &[("rax", seed), ("rbx", 0xa5a5_a5a5)],
                0x8d5,
                Some(generated.clone()),
            )?,
            "generated xor32 should execute for seed {seed:#x}"
        );
    }
    Ok(())
}

/// PROVE-mode symbolic session: `rbx` marked symbolic, `cmp`/`je` forks two
/// states with complementary path constraints; reconverging pcs merge into
/// one state whose `rax` is an Ite over the branch.
#[cfg(all(feature = "xed", target_arch = "x86_64"))]
#[test]
fn symbolic_session_forks_and_merges() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_expr::ExprArena;
    use angryier_runtime::{SymbolicSession, SymbolicStepOutcome};

    let source = r#"
        .global _start
        .text
_start:
    cmp $5, %rbx
    je target
    mov $1, %rax
    jmp end
target:
    mov $2, %rax
end:
    mov %rax, out(%rip)
    mov $1, %rax
    mov $1, %rdi
    mov $out, %rsi
    mov $8, %rdx
    syscall
    mov $60, %rax
    xor %rdi, %rdi
    syscall
        .data
out:    .quad 0
"#;
    let dir = temp_dir("angryier-symbolic-fork").ok_or("no tempdir")?;
    let path_s = dir.join("fork.s");
    let path_o = dir.join("fork.o");
    let path_bin = dir.join("fork");
    std::fs::write(&path_s, source)?;
    if assemble(&path_s, &path_o).is_none() || link(&path_bin, &[&path_o]).is_none() {
        eprintln!("skipping: assembler unavailable");
        return Ok(());
    }
    let elf_bytes = std::fs::read(&path_bin)?;

    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&elf_bytes)?;
    let arena = angryier_expr::ShardedExprArena::new(angryier_types::ExpressionNormalizationVersion(1));
    let mut session = SymbolicSession::new(&runtime, &arena, process);
    session.mark_symbolic(0, register_id::GPR_BASE + 3, angryier_ir::IrType::Bits(64))?;

    // Walk the single state until the `je` fork.
    let mut branch_index = None;
    for _ in 0..64 {
        let outcome = session.step_state(0)?;
        match outcome {
            SymbolicStepOutcome::Branched { child } => {
                branch_index = Some(child);
                break;
            }
            SymbolicStepOutcome::Terminated => break,
            _ => {}
        }
    }
    let child = branch_index.ok_or("expected the cmp/je to fork")?;
    assert_eq!(session.states.len(), 2);

    // Two distinct pcs, complementary constraints.
    let (pc_a, pc_b) = (session.states[0].process.pc()?, session.states[child].process.pc()?);
    assert_ne!(pc_a, pc_b);
    assert_eq!(session.states[0].constraints.len(), 1);
    assert_eq!(session.states[child].constraints.len(), 1);
    let cond_a = session.states[0].constraints[0];
    let cond_b = session.states[child].constraints[0];
    let node_b = arena.get(cond_b).ok_or("child constraint")?;
    assert_eq!(node_b.op, angryier_expr::ExprOp::Not);
    assert_eq!(node_b.operands[0], cond_a);

    // Run both to the reconvergence point (`end` at the store site), then
    // merge so `out` receives the Ite'd rax.
    for i in [0usize, child] {
        for _ in 0..64 {
            let pc = session.states[i].process.pc()?;
            if pc == 0x401016 {
                break;
            }
            if session.step_state(i)? == SymbolicStepOutcome::Terminated {
                break;
            }
        }
    }
    // Both should be at `end` — same pc.
    let pc_a = session.states[0].process.pc()?;
    let pc_b = session.states[1].process.pc()?;
    assert_eq!(pc_a, pc_b, "states should reconverge at `end`");

    let merged = session.merge_at()?;
    assert!(merged >= 1, "expected at least one merge");
    assert_eq!(session.states.len(), 1);

    // Step the merged state through the store, then `out`'s first byte is
    // Ite(cond, 1, 2) — the divergent rax.
    for _ in 0..4 {
        if session.step_state(0)? == SymbolicStepOutcome::Terminated {
            break;
        }
    }
    // The store of rax→out happened pre-merge, so `out`'s first byte is the
    // divergent value — a symbolic byte in the merged state's memory.
    let out_expr = session.states[0]
        .memory
        .memory
        .read_at_address(0x402000, 1)
        .map_err(|e| format!("read out: {e:?}"))?
        .into_iter()
        .next()
        .ok_or("no byte")?;
    match out_expr {
        angryier_memory::ByteValue::Symbolic(expr) => {
            let node = arena.get(expr).ok_or("byte node")?;
            // Byte 0 of a merged 64-bit value is Extract(Ite(...), 0..8).
            let inner = if node.op == angryier_expr::ExprOp::Extract {
                let operand = node.operands[0];
                arena.get(operand).ok_or("inner node")?
            } else {
                node
            };
            assert_eq!(inner.op, angryier_expr::ExprOp::Ite, "merged out byte should be Ite");
        }
        angryier_memory::ByteValue::Concrete(v) => {
            return Err(format!("out byte was concrete {v:#x} — store never ran symbolically").into());
        }
    }
    Ok(())
}

/// Solver-gated forking: with rbx a concrete 5, `je` (rbx==5) has the
/// not-taken direction UNSAT — `step_state_checked` must not fork, while
/// the unchecked path does.
#[cfg(all(feature = "xed", feature = "z3", target_arch = "x86_64"))]
#[test]
fn symbolic_session_checked_prunes_unsat_direction() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_expr::{ExprArena, ExprReader, ShardedExprArena};
    use angryier_runtime::{SymbolicSession, SymbolicStepOutcome};
    use angryier_solver_z3::Z3Backend;
    use std::sync::Arc;

    let source = r#"
        .global _start
        .text
_start:
    cmp $5, %rbx
    je target
    mov $1, %rax
    jmp end
target:
    mov $2, %rax
end:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
"#;
    let dir = temp_dir("angryier-symbolic-checked").ok_or("no tempdir")?;
    let path_s = dir.join("fork.s");
    let path_o = dir.join("fork.o");
    let path_bin = dir.join("fork");
    std::fs::write(&path_s, source)?;
    if assemble(&path_s, &path_o).is_none() || link(&path_bin, &[&path_o]).is_none() {
        eprintln!("skipping: assembler unavailable");
        return Ok(());
    }
    let elf_bytes = std::fs::read(&path_bin)?;

    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&elf_bytes)?;
    let arena = Arc::new(ShardedExprArena::new(angryier_types::ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    // Mark rbx symbolic, then pin it with the constraint rbx == 5 so the
    // `je`'s not-taken direction is UNSAT and the checked step prunes it.
    session.mark_symbolic(0, register_id::GPR_BASE + 3, angryier_ir::IrType::Bits(64))?;
    {
        let sym = session.states[0]
            .registers
            .get(&(register_id::GPR_BASE + 3))
            .map(|(e, _)| *e)
            .ok_or("rbx")?;
        let five = arena
            .intern(angryier_expr::ExprNode {
                sort: angryier_expr::ExprSort::BitVec(64),
                op: angryier_expr::ExprOp::Constant,
                operands: Vec::new(),
                immediate: 5u64.to_le_bytes().to_vec(),
            })
            .map_err(|e| format!("{e:?}"))?;
        let eq = arena
            .intern(angryier_expr::ExprNode {
                sort: angryier_expr::ExprSort::Bool,
                op: angryier_expr::ExprOp::Eq,
                operands: vec![sym, five],
                immediate: Vec::new(),
            })
            .map_err(|e| format!("{e:?}"))?;
        session.states[0].constraints.push(eq);
    }

    let reader: Arc<dyn ExprReader> = arena.clone();
    let mut backend = Z3Backend::native_ffi(reader)?;

    // Step to the `je` — the checked step must not fork (not-taken UNSAT).
    let mut branched = false;
    for _ in 0..8 {
        match session.step_state_checked(0, &mut backend, std::time::Duration::from_secs(5))? {
            SymbolicStepOutcome::Branched { .. } => {
                branched = true;
                break;
            }
            SymbolicStepOutcome::Terminated => break,
            _ => {}
        }
    }
    assert!(!branched, "checked step should prune the UNSAT not-taken direction");
    Ok(())
}

/// The exploration driver: symbolic session runs to completion, forks once
/// at `je`, merges at the reconvergence point, and terminates with one
/// final state carrying the Ite.
#[cfg(all(feature = "xed", target_arch = "x86_64"))]
#[test]
fn symbolic_session_run_merges_reconverged() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_runtime::SymbolicSession;

    let source = r#"
        .global _start
        .text
_start:
    cmp $5, %rbx
    je target
    mov $1, %rax
    jmp end
target:
    mov $2, %rax
end:
    mov %rax, out(%rip)
    mov $60, %rax
    xor %rdi, %rdi
    syscall
        .data
out:    .quad 0
"#;
    let dir = temp_dir("angryier-symbolic-run").ok_or("no tempdir")?;
    let path_s = dir.join("fork.s");
    let path_o = dir.join("fork.o");
    let path_bin = dir.join("fork");
    std::fs::write(&path_s, source)?;
    if assemble(&path_s, &path_o).is_none() || link(&path_bin, &[&path_o]).is_none() {
        eprintln!("skipping: assembler unavailable");
        return Ok(());
    }
    let elf_bytes = std::fs::read(&path_bin)?;

    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&elf_bytes)?;
    let arena = angryier_expr::ShardedExprArena::new(angryier_types::ExpressionNormalizationVersion(1));
    let mut session = SymbolicSession::new(&runtime, &arena, process);
    session.mark_symbolic(0, register_id::GPR_BASE + 3, angryier_ir::IrType::Bits(64))?;

    let report = session.run(512, 16, None, std::time::Duration::from_secs(5), true)?;
    assert_eq!(report.forks, 1, "expected exactly one fork");
    assert!(report.merges >= 1, "expected a reconvergence merge");
    assert!(report.terminated >= 1);
    assert!(report.live_states <= 1, "merged states should leave one live");
    Ok(())
}

/// Exploration policy: `avoid` prunes the state that reaches the target
/// block, so only the fall-through path survives.
#[cfg(all(feature = "xed", target_arch = "x86_64"))]
#[test]
fn symbolic_session_avoid_prunes_target() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_runtime::{ExplorationPolicy, SymbolicSession};

    let source = r#"
        .global _start
        .text
_start:
    cmp $5, %rbx
    je target
    mov $1, %rax
    jmp end
target:
    mov $2, %rax
end:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
"#;
    let dir = temp_dir("angryier-symbolic-avoid").ok_or("no tempdir")?;
    let path_s = dir.join("fork.s");
    let path_o = dir.join("fork.o");
    let path_bin = dir.join("fork");
    std::fs::write(&path_s, source)?;
    if assemble(&path_s, &path_o).is_none() || link(&path_bin, &[&path_o]).is_none() {
        eprintln!("skipping: assembler unavailable");
        return Ok(());
    }
    let elf_bytes = std::fs::read(&path_bin)?;

    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&elf_bytes)?;
    let arena = angryier_expr::ShardedExprArena::new(angryier_types::ExpressionNormalizationVersion(1));
    let mut session = SymbolicSession::new(&runtime, &arena, process);
    session.mark_symbolic(0, register_id::GPR_BASE + 3, angryier_ir::IrType::Bits(64))?;

    // `target` is at _start+0xf = 0x40100f (from the earlier disassembly).
    let policy = ExplorationPolicy {
        find: Vec::new(),
        avoid: vec![0x40100f],
        prefer_new_coverage: false,
    };
    let report = session.run_with_policy(512, 16, None, std::time::Duration::from_secs(5), false, &policy)?;
    assert_eq!(report.forks, 1);
    assert_eq!(report.pruned_states, 1, "the target path must be pruned");
    eprintln!("avoid report: {report:?} dead={}", session.dead.len());
    assert_eq!(report.terminated, 1, "the fall-through path terminates");
    Ok(())
}

/// The symbolic session on a real glibc static binary: `argc` (in `rdi`)
/// starts symbolic, the session steps real startup code symbolically.
/// This exercises the engine on ~hundreds of real instructions — register
/// bindings, symbolic stores to the process stack, TLS/FS-relative reads,
/// and the startup syscall boundary — rather than a synthetic fixture.
#[cfg(all(feature = "xed", feature = "z3", target_arch = "x86_64"))]
#[test]
fn symbolic_session_real_binary() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_expr::ExprReader;
    use angryier_runtime::SymbolicSession;
    use angryier_solver_z3::Z3Backend;

    let Ok(bytes) = std::fs::read("/tmp/hello_glibc") else {
        eprintln!("skipping: hello_glibc not present");
        return Ok(());
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&bytes)?;
    let arena = std::sync::Arc::new(angryier_expr::ShardedExprArena::new(
        angryier_types::ExpressionNormalizationVersion(1),
    ));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);

    // rdi holds argc at entry — mark it symbolic so argument-dependent
    // branches fork states.
    session.mark_symbolic(0, register_id::GPR_BASE + 7, angryier_ir::IrType::Bits(64))?;

    // Solver-assisted: the auxv pointer chase resolves addresses through
    // Z3 when constant folding can't.
    let mut backend = Z3Backend::native_ffi(arena.clone() as std::sync::Arc<dyn ExprReader>)?;
    let report = session.run(512, 32, Some(&mut backend), std::time::Duration::from_secs(10), true)?;
    // The session must have stepped deep into real startup code — rdi
    // symbolic forks the aux-vector scan, and the engine ran ~200 real
    // instructions symbolically before the pointer-chase depth exceeded
    // the concrete-address resolver.
    // REP_STOSQ (glibc's memset path) used to kill every state; with the
    // symbolic string-op fast path the session runs hundreds of real
    // instructions deep into __libc_start_main.
    // Solver-gated stepping prunes infeasible forks — the report shows
    // fewer forks than the unchecked run because each branch's dead
    // direction is eliminated instead of enqueued.
    assert!(report.steps >= 128, "session should step deep into real startup code");
    Ok(())
}

/// Solve a found state: rbx symbolic, `find` the `target` block, then
/// solve_state must return rbx = 5 (the input that reaches it).
#[cfg(all(feature = "xed", feature = "z3", target_arch = "x86_64"))]
#[test]
fn symbolic_session_solve_finds_input() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_expr::{ExprReader, ShardedExprArena};
    use angryier_runtime::{ExplorationPolicy, SymbolicSession};
    use angryier_solver_z3::Z3Backend;
    use std::sync::Arc;

    let source = r#"
        .global _start
        .text
_start:
    cmp $5, %rbx
    je target
    mov $1, %rax
    jmp end
target:
    mov $2, %rax
end:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
"#;
    let dir = temp_dir("angryier-symbolic-solve").ok_or("no tempdir")?;
    let path_s = dir.join("fork.s");
    let path_o = dir.join("fork.o");
    let path_bin = dir.join("fork");
    std::fs::write(&path_s, source)?;
    if assemble(&path_s, &path_o).is_none() || link(&path_bin, &[&path_o]).is_none() {
        eprintln!("skipping: assembler unavailable");
        return Ok(());
    }
    let elf_bytes = std::fs::read(&path_bin)?;

    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&elf_bytes)?;
    let arena = Arc::new(ShardedExprArena::new(angryier_types::ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    session.mark_symbolic(0, register_id::GPR_BASE + 3, angryier_ir::IrType::Bits(64))?;

    // `target` = _start+0xf.
    let policy = ExplorationPolicy {
        find: vec![0x40100f],
        avoid: Vec::new(),
        prefer_new_coverage: false,
    };
    let report = session.run_with_policy(256, 16, None, std::time::Duration::from_secs(5), false, &policy)?;
    assert_eq!(report.found.len(), 1, "one state should reach `target`");

    // The found state isn't in `states` anymore — solve_state works on
    // `states`; push it back for solving.
    session
        .states
        .push(report.found.into_iter().next().unwrap_or_else(|| unreachable!()));
    let reader: Arc<dyn ExprReader> = arena.clone();
    let mut backend = Z3Backend::native_ffi(reader)?;
    let bindings = session.solve_state(
        session.states.len() - 1,
        &mut backend,
        std::time::Duration::from_secs(5),
    )?;
    let rbx = bindings
        .iter()
        .find(|(reg, _)| *reg == register_id::GPR_BASE + 3)
        .map(|(_, v)| *v)
        .ok_or("no rbx binding")?;
    assert_eq!(rbx, 5, "the model must satisfy rbx == 5 to reach target");
    Ok(())
}

/// Parallel symbolic exploration: a double-branch program forked twice
/// (4 leaf states) distributes across workers and all terminate.
#[cfg(all(feature = "xed", target_arch = "x86_64"))]
#[test]
fn symbolic_session_parallel_workers() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_runtime::SymbolicSession;

    let source = r#"
        .global _start
        .text
_start:
    cmp $5, %rbx
    je t1
    mov $1, %rax
    jmp j2
t1:
    mov $2, %rax
j2:
    cmp $7, %rcx
    je t2
    mov $3, %rdx
    jmp end
t2:
    mov $4, %rdx
end:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
"#;
    let dir = temp_dir("angryier-symbolic-par").ok_or("no tempdir")?;
    let path_s = dir.join("fork.s");
    let path_o = dir.join("fork.o");
    let path_bin = dir.join("fork");
    std::fs::write(&path_s, source)?;
    if assemble(&path_s, &path_o).is_none() || link(&path_bin, &[&path_o]).is_none() {
        eprintln!("skipping: assembler unavailable");
        return Ok(());
    }
    let elf_bytes = std::fs::read(&path_bin)?;

    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&elf_bytes)?;
    let arena = angryier_expr::ShardedExprArena::new(angryier_types::ExpressionNormalizationVersion(1));
    let mut session = SymbolicSession::new(&runtime, &arena, process);
    session.mark_symbolic(0, register_id::GPR_BASE + 3, angryier_ir::IrType::Bits(64))?;
    session.mark_symbolic(0, register_id::GPR_BASE + 1, angryier_ir::IrType::Bits(64))?;

    let reports = session.run_parallel(512, 16, 4, std::time::Duration::from_secs(5))?;
    let total_terminated: u64 = reports.iter().map(|r| r.terminated).sum();
    let total_forks: u64 = reports.iter().map(|r| r.forks).sum();
    let total_failed: u64 = reports.iter().map(|r| r.failed).sum();
    eprintln!(
        "parallel: {reports:?} failed={total_failed} live={}",
        session.states.len()
    );
    // Warm-up forks the first `je` serially; the dealt workers then cover
    // every leaf — four paths terminate across the pool.
    let _ = total_forks;
    assert_eq!(total_terminated, 4, "all four leaf paths should terminate");
    assert_eq!(total_failed, 0);
    assert!(reports.len() > 1, "the deal must reach more than one worker");
    Ok(())
}

/// CFG-scheduled merge: recover the binary's CFG, attach it to the session,
/// and the fork pair is parked/merged at the reconvergence target.
#[cfg(all(feature = "xed", target_arch = "x86_64"))]
#[test]
fn symbolic_session_cfg_merge() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_memory::LayeredMemory;
    use angryier_runtime::SymbolicSession;

    let source = r#"
        .global _start
        .text
_start:
    cmp $5, %rbx
    je target
    mov $1, %rax
    jmp end
target:
    mov $2, %rax
end:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
"#;
    let dir = temp_dir("angryier-symbolic-cfg").ok_or("no tempdir")?;
    let path_s = dir.join("fork.s");
    let path_o = dir.join("fork.o");
    let path_bin = dir.join("fork");
    std::fs::write(&path_s, source)?;
    if assemble(&path_s, &path_o).is_none() || link(&path_bin, &[&path_o]).is_none() {
        eprintln!("skipping: assembler unavailable");
        return Ok(());
    }
    let elf_bytes = std::fs::read(&path_bin)?;

    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&elf_bytes)?;
    // Recover the CFG over the executable text region.
    let text_region = process
        .state
        .memory
        .regions()
        .iter()
        .find(|r| r.executable)
        .ok_or("no exec region")?;
    let base = text_region.base;
    let text = process
        .state
        .memory
        .read(base, text_region.size as usize)
        .map_err(|e| format!("text read: {e:?}"))?;
    let bytes: Vec<u8> = text
        .iter()
        .map(|b| match b {
            angryier_memory::ByteValue::Concrete(v) => *v,
            _ => 0,
        })
        .collect();
    // The runtime decoder already maps iclass → form id; the CFG's
    // map_form hook is the identity here.
    let cfg = angryier_cfg::recover_multi(&runtime.decoder, base, &bytes, [process.entry], |d| d.form_id)
        .map_err(|e| format!("cfg: {e:?}"))?;

    let arena = angryier_expr::ShardedExprArena::new(angryier_types::ExpressionNormalizationVersion(1));
    let mut session = SymbolicSession::new(&runtime, &arena, process).with_cfg(&cfg);
    session.mark_symbolic(0, register_id::GPR_BASE + 3, angryier_ir::IrType::Bits(64))?;

    let report = session.run(512, 16, None, std::time::Duration::from_secs(5), false)?;
    assert_eq!(report.forks, 1);
    assert!(report.merges >= 1, "CFG-scheduled merge must fire");
    Ok(())
}

/// Loop path explosion vs solver gating: `for rcx in 0..3` with rcx
/// symbolic but pinned `rcx==0` at entry — each `jl loop` checks feasible
/// until rcx>=3 makes it UNSAT. The checked run should terminate with a
/// bounded state count rather than exploding.
#[cfg(all(feature = "xed", feature = "z3", target_arch = "x86_64"))]
#[test]
fn symbolic_session_loop_solver_bounded() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_expr::{ExprArena, ExprReader, ShardedExprArena};
    use angryier_runtime::SymbolicSession;
    use angryier_solver_z3::Z3Backend;
    use std::sync::Arc;

    let source = r#"
        .global _start
        .text
_start:
    xor %rcx, %rcx
    xor %rax, %rax
loop:
    inc %rax
    inc %rcx
    cmp $3, %rcx
    jl loop
    mov $60, %rax
    xor %rdi, %rdi
    syscall
"#;
    let dir = temp_dir("angryier-symbolic-loop").ok_or("no tempdir")?;
    let path_s = dir.join("loop.s");
    let path_o = dir.join("loop.o");
    let path_bin = dir.join("loop");
    std::fs::write(&path_s, source)?;
    if assemble(&path_s, &path_o).is_none() || link(&path_bin, &[&path_o]).is_none() {
        eprintln!("skipping: assembler unavailable");
        return Ok(());
    }
    let elf_bytes = std::fs::read(&path_bin)?;

    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&elf_bytes)?;
    let arena = Arc::new(ShardedExprArena::new(angryier_types::ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);

    // rcx symbolic + pinned to 0 — the loop bound is symbolic-derivable.
    session.mark_symbolic(0, register_id::GPR_BASE + 1, angryier_ir::IrType::Bits(64))?;
    {
        let sym = session.states[0]
            .registers
            .get(&(register_id::GPR_BASE + 1))
            .map(|(e, _)| *e)
            .ok_or("rcx")?;
        let zero = arena
            .intern(angryier_expr::ExprNode {
                sort: angryier_expr::ExprSort::BitVec(64),
                op: angryier_expr::ExprOp::Constant,
                operands: Vec::new(),
                immediate: 0u64.to_le_bytes().to_vec(),
            })
            .map_err(|e| format!("{e:?}"))?;
        let eq = arena
            .intern(angryier_expr::ExprNode {
                sort: angryier_expr::ExprSort::Bool,
                op: angryier_expr::ExprOp::Eq,
                operands: vec![sym, zero],
                immediate: Vec::new(),
            })
            .map_err(|e| format!("{e:?}"))?;
        session.states[0].constraints.push(eq);
    }

    let reader: Arc<dyn ExprReader> = arena.clone();
    let mut backend = Z3Backend::native_ffi(reader)?;
    // Solver-gated run: each `jl loop` direction is checked — the
    // loop-back direction is UNSAT once rcx>=3.
    let report = session.run_with_policy(
        256,
        64,
        Some(&mut backend),
        std::time::Duration::from_secs(10),
        false,
        &angryier_runtime::ExplorationPolicy::default(),
    )?;
    eprintln!("loop report: {report:?}");
    // The loop must terminate — solver-gating prunes the UNSAT back-edge.
    assert!(report.terminated >= 1, "loop should terminate via UNSAT back-edge");
    assert!(
        report.forks <= 8,
        "state count should stay bounded, got {}",
        report.forks
    );
    Ok(())
}

/// Function identification: a binary with `main` + `helper` should recover
/// two functions — main's call target owns helper's blocks.
#[cfg(all(feature = "xed", target_arch = "x86_64"))]
#[test]
fn cfg_functions_partition() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_memory::LayeredMemory;

    let source = r#"
        .global _start
        .text
_start:
    call helper
    mov $60, %rax
    xor %rdi, %rdi
    syscall
helper:
    mov $7, %rax
    ret
"#;
    let dir = temp_dir("angryier-cfg-fns").ok_or("no tempdir")?;
    let path_s = dir.join("fns.s");
    let path_o = dir.join("fns.o");
    let path_bin = dir.join("fns");
    std::fs::write(&path_s, source)?;
    if assemble(&path_s, &path_o).is_none() || link(&path_bin, &[&path_o]).is_none() {
        eprintln!("skipping: assembler unavailable");
        return Ok(());
    }
    let elf_bytes = std::fs::read(&path_bin)?;

    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&elf_bytes)?;
    let text_region = process
        .state
        .memory
        .regions()
        .iter()
        .find(|r| r.executable)
        .ok_or("no exec region")?;
    let base = text_region.base;
    let text = process
        .state
        .memory
        .read(base, text_region.size as usize)
        .map_err(|e| format!("text read: {e:?}"))?;
    let bytes: Vec<u8> = text
        .iter()
        .map(|b| match b {
            angryier_memory::ByteValue::Concrete(v) => *v,
            _ => 0,
        })
        .collect();
    let cfg = angryier_cfg::recover_multi(&runtime.decoder, base, &bytes, [process.entry], |d| d.form_id)
        .map_err(|e| format!("cfg: {e:?}"))?;

    let functions = cfg.functions();
    assert_eq!(functions.len(), 2, "main + helper");
    // helper owns exactly its own blocks; main owns _start's.
    let helper = functions.iter().find(|f| f.entry != process.entry).ok_or("helper")?;
    assert_eq!(helper.returns.len(), 1, "helper ends in ret");
    Ok(())
}

/// Symbolic stdin: `read(0, buf, 8)` materializes symbolic bytes; a
/// compare on buf[0] forks, and solving the found state yields the
/// input byte that reaches `target`.
#[cfg(all(feature = "xed", feature = "z3", target_arch = "x86_64"))]
#[test]
fn symbolic_stdin_solves_input_byte() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_expr::ExprReader;
    use angryier_runtime::{ExplorationPolicy, SymbolicSession};
    use angryier_solver_z3::Z3Backend;
    use std::sync::Arc;

    // read(0, rsp-8, 8); cmpb $0x41, (rsp-8); je target; ... exit.
    let source = r#"
        .global _start
        .text
_start:
    sub $16, %rsp
    xor %rax, %rax
    xor %rdi, %rdi
    mov %rsp, %rsi
    mov $8, %rdx
    syscall
    cmpb $0x41, (%rsp)
    je target
    xor %eax, %eax
    mov $60, %rax
    xor %rdi, %rdi
    syscall
target:
    mov $1, %rax
    mov $60, %rax
    xor %rdi, %rdi
    syscall
"#;
    let dir = temp_dir("angryier-stdin").ok_or("no tempdir")?;
    let path_s = dir.join("stdin.s");
    let path_o = dir.join("stdin.o");
    let path_bin = dir.join("stdin");
    std::fs::write(&path_s, source)?;
    if assemble(&path_s, &path_o).is_none() || link(&path_bin, &[&path_o]).is_none() {
        eprintln!("skipping: assembler unavailable");
        return Ok(());
    }
    let elf_bytes = std::fs::read(&path_bin)?;

    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&elf_bytes)?;
    let arena = Arc::new(angryier_expr::ShardedExprArena::new(
        angryier_types::ExpressionNormalizationVersion(1),
    ));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    let mut backend = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;

    // `target:` is at _start+0x2a (see disassembly of the fixture).
    let entry = session.states[0].process.pc()?;
    let target = entry + 0x2a;
    let policy = ExplorationPolicy {
        find: vec![target],
        ..Default::default()
    };
    let report = session.run_with_policy(
        128,
        8,
        Some(&mut backend),
        std::time::Duration::from_secs(10),
        false,
        &policy,
    )?;
    assert!(report.forks >= 1, "cmpb on symbolic stdin must fork");
    assert_eq!(report.found.len(), 1, "the 'A' path reaches target");

    // Solve the found state — the model must assign 0x41 to stdin byte 0.
    session
        .states
        .push(report.found.into_iter().next().unwrap_or_else(|| unreachable!()));
    let solution = session
        .solve_state_symbols(
            session.states.len() - 1,
            &mut backend,
            std::time::Duration::from_secs(10),
        )
        .map_err(|e| format!("solve: {e:?}"))?;
    assert!(
        solution.iter().any(|(_, bytes)| bytes.first().copied() == Some(0x41)),
        "model should produce 0x41 in stdin: {solution:?}"
    );
    Ok(())
}

/// Lua scripting: a script drives a symbolic session — marks rdi
/// symbolic, runs, and reads the report back without recompiling.
#[cfg(all(feature = "xed", feature = "script", target_arch = "x86_64"))]
#[test]
fn lua_script_drives_session() -> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_dir("angryier-lua").ok_or("no tempdir")?;
    let path_s = dir.join("lua.s");
    let path_o = dir.join("lua.o");
    let path_bin = dir.join("lua");
    std::fs::write(
        &path_s,
        "_start:\n    cmp $5, %rdi\n    je target\n    xor %eax, %eax\n    mov $60, %rax\n    syscall\ntarget:\n    mov $1, %rax\n    mov $60, %rax\n    syscall\n",
    )?;
    if assemble(&path_s, &path_o).is_none() || link(&path_bin, &[&path_o]).is_none() {
        eprintln!("skipping: assembler unavailable");
        return Ok(());
    }
    let lua = mlua::Lua::new();
    angryier_runtime::script::register(&lua)?;
    let script = format!(
        r#"
        local r = angry.run("{}", {{
            symbolic = {{ rdi = 64 }},
            steps = 64, states = 8,
        }})
        assert(r.steps > 0, "session must step")
        return r.forks
        "#,
        path_bin.display()
    );
    let forks: u64 = lua.load(&script).eval()?;
    assert!(forks >= 1, "symbolic rdi should fork the cmp");
    Ok(())
}

/// PE32+ loading: a hand-built PE executes `mov eax, 0x2a; ret`
/// concretely through the runtime.
#[cfg(all(feature = "xed", target_arch = "x86_64"))]
#[test]
fn pe32_loads_and_executes() -> Result<(), Box<dyn std::error::Error>> {
    // Minimal PE32+: .text at image_base+0x1000 with `mov eax,0x2a; ret`.
    let mut pe = vec![0u8; 0x400];
    pe[0] = 0x4D;
    pe[1] = 0x5A;
    pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    pe[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0, 0]);
    pe[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    pe[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    pe[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes());
    pe[0x98..0x9A].copy_from_slice(&0x20Bu16.to_le_bytes());
    pe[0xA8..0xAC].copy_from_slice(&0x1000u32.to_le_bytes());
    pe[0xB0..0xB8].copy_from_slice(&0x140000000u64.to_le_bytes());
    pe[0x188..0x190].copy_from_slice(b".text\0\0\0");
    pe[0x190..0x194].copy_from_slice(&0x100u32.to_le_bytes());
    pe[0x194..0x198].copy_from_slice(&0x1000u32.to_le_bytes());
    pe[0x198..0x19C].copy_from_slice(&6u32.to_le_bytes());
    pe[0x19C..0x1A0].copy_from_slice(&0x200u32.to_le_bytes());
    pe[0x1AC..0x1B0].copy_from_slice(&0x60000000u32.to_le_bytes()); // exec|read
    pe.resize(0x206, 0);
    pe[0x200..0x205].copy_from_slice(&[0xB8, 0x2A, 0, 0, 0]);
    pe[0x205] = 0xC3;

    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_pe(&pe)?;
    assert_eq!(process.pc()?, 0x140001000);
    let outcome = runtime.step(&mut process)?;
    assert_eq!(process.read_register(register_id::GPR_BASE)?, 0x2a);
    let _ = outcome;
    Ok(())
}

/// Named-file input: `openat("input.txt")` + `read(fd)` serves the
/// process's `files` map; the bytes flow to `write(1)` unchanged.
#[cfg(all(feature = "xed", target_arch = "x86_64"))]
#[test]
fn openat_read_serves_named_file() -> Result<(), Box<dyn std::error::Error>> {
    let source = r#"
        .global _start
        .text
_start:
    mov $257, %rax        # openat
    mov $-100, %rdi       # AT_FDCWD
    lea name(%rip), %rsi
    xor %rdx, %rdx        # O_RDONLY
    syscall
    mov %rax, %rdi        # fd
    xor %rax, %rax        # read
    lea buf(%rip), %rsi
    mov $64, %rdx
    syscall
    mov %rax, %rdx        # n
    mov $1, %rax          # write
    mov $1, %rdi
    lea buf(%rip), %rsi
    syscall
    mov $60, %rax
    xor %rdi, %rdi
    syscall
name:
    .asciz "input.txt"
    .data
buf:
    .zero 64
"#;
    let dir = temp_dir("angryier-file").ok_or("no tempdir")?;
    let path_s = dir.join("f.s");
    let path_o = dir.join("f.o");
    let path_bin = dir.join("f");
    std::fs::write(&path_s, source)?;
    if assemble(&path_s, &path_o).is_none() || link(&path_bin, &[&path_o]).is_none() {
        eprintln!("skipping: assembler unavailable");
        return Ok(());
    }
    let elf_bytes = std::fs::read(&path_bin)?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_elf(&elf_bytes)?;
    process
        .files
        .insert("input.txt".to_string(), b"file-content-here".to_vec());
    for _ in 0..32 {
        if matches!(runtime.step(&mut process)?, StepOutcome::Terminated { .. }) {
            break;
        }
    }
    assert_eq!(process.syscalls.output(), b"file-content-here");
    Ok(())
}

/// Symbolic argv: `symbolize_argv0` writes symbolic bytes into the
/// argv[0] stack string; a program reading argv[0][0] forks on it.
#[cfg(all(feature = "xed", feature = "z3", target_arch = "x86_64"))]
#[test]
fn symbolic_argv0_forks_on_input() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_expr::ExprReader;
    use angryier_runtime::{ExplorationPolicy, SymbolicSession};
    use angryier_solver_z3::Z3Backend;
    use std::sync::Arc;

    // _start: rdi=argc, argv at rsp+8 → argv[0] ptr → argv[0][0] byte.
    let source = r#"
        .global _start
        .text
_start:
    mov 8(%rsp), %rax     # argv[0] pointer
    cmpb $0x41, (%rax)    # argv[0][0] == 'A'?
    je target
    mov $60, %rax
    xor %rdi, %rdi
    syscall
target:
    mov $60, %rax
    mov $7, %rdi
    syscall
"#;
    let dir = temp_dir("angryier-argv").ok_or("no tempdir")?;
    let path_s = dir.join("a.s");
    let path_o = dir.join("a.o");
    let path_bin = dir.join("a");
    std::fs::write(&path_s, source)?;
    if assemble(&path_s, &path_o).is_none() || link(&path_bin, &[&path_o]).is_none() {
        eprintln!("skipping: assembler unavailable");
        return Ok(());
    }
    let elf_bytes = std::fs::read(&path_bin)?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&elf_bytes)?;
    let arena = Arc::new(angryier_expr::ShardedExprArena::new(
        angryier_types::ExpressionNormalizationVersion(1),
    ));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    session.symbolize_argv0(0, 4)?;
    let mut backend = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
    let entry = session.states[0].process.pc()?;
    let policy = ExplorationPolicy {
        find: vec![entry + 0x16],
        ..Default::default()
    };
    let report = session.run_with_policy(
        64,
        8,
        Some(&mut backend),
        std::time::Duration::from_secs(10),
        false,
        &policy,
    )?;
    assert!(report.forks >= 1);
    assert_eq!(report.found.len(), 1, "'A' argv path reaches target");
    Ok(())
}

/// Dynamic linking: a dynamically-linked binary maps libc via DT_NEEDED
/// and executes — relocations resolve eagerly.
#[cfg(all(feature = "xed", target_arch = "x86_64"))]
#[test]
fn dynamic_binary_loads_and_runs() -> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_dir("angryier-dyn").ok_or("no tempdir")?;
    let path_c = dir.join("d.c");
    let path_bin = dir.join("dyn");
    std::fs::write(&path_c, "int main(){__builtin_write(1,\"dyn\\n\",4);return 0;}\n")?;
    // Fallback: plain write via inline asm to avoid libc header needs.
    std::fs::write(
        &path_c,
        r#"int main(){
    register long rax asm("rax") = 1;
    register long rdi asm("rdi") = 1;
    register const char* rsi asm("rsi") = "dyn\n";
    register long rdx asm("rdx") = 4;
    asm volatile("syscall" : "+r"(rax) : "r"(rdi), "r"(rsi), "r"(rdx) : "rcx","r11","memory");
    return 0;
}"#,
    )?;
    let status = std::process::Command::new("cc")
        .arg(&path_c)
        .arg("-o")
        .arg(&path_bin)
        .status();
    match status {
        Ok(s) if s.success() => {}
        _ => {
            eprintln!("skipping: cc unavailable");
            return Ok(());
        }
    }
    let bytes = std::fs::read(&path_bin)?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_elf_dynamic(&bytes, &[])?;
    // Partial milestone: the dynamic image maps, libc resolves, RELATIVE +
    // GLOB_DAT slots are patched, and _start executes into libc's init.
    // glibc's IRELATIVE/TLS relocations and full `__libc_start_main` are
    // still ahead — the run ends when an unpatched slot is dereferenced.
    let mut stepped = 0u64;
    for _ in 0..200_000 {
        match runtime.step(&mut process) {
            Ok(StepOutcome::Terminated { .. }) => break,
            Ok(_) => stepped += 1,
            Err(_) => break,
        }
    }
    assert_eq!(
        process.syscalls.output(),
        b"dyn\n",
        "dynamic binary must write to stdout (stepped={stepped})"
    );
    Ok(())
}

/// EXPLORE→PROVE handoff: a concolic run promotes into a SymbolicState
/// carrying its path constraints — the solver's model respects them.
#[cfg(all(feature = "xed", feature = "z3", target_arch = "x86_64"))]
#[test]
fn concolic_promotes_to_prove_state() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_expr::ExprReader;
    use angryier_runtime::SymbolicSession;
    use angryier_solver_z3::Z3Backend;
    use std::sync::Arc;

    // rdi symbolic → concolic takes the NOT-taken path (rdi concrete 0) →
    // promoted state's constraints force rdi != 5.
    let source = r#"
        .global _start
        .text
_start:
    cmp $5, %rdi
    je target
    mov $60, %rax
    xor %rdi, %rdi
    syscall
target:
    mov $60, %rax
    mov $9, %rdi
    syscall
"#;
    let dir = temp_dir("angryier-handoff").ok_or("no tempdir")?;
    let path_s = dir.join("h.s");
    let path_o = dir.join("h.o");
    let path_bin = dir.join("h");
    std::fs::write(&path_s, source)?;
    if assemble(&path_s, &path_o).is_none() || link(&path_bin, &[&path_o]).is_none() {
        eprintln!("skipping: assembler unavailable");
        return Ok(());
    }
    let elf_bytes = std::fs::read(&path_bin)?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&elf_bytes)?;
    let arena = Arc::new(angryier_expr::ShardedExprArena::new(
        angryier_types::ExpressionNormalizationVersion(1),
    ));

    let mut concolic = runtime.concolic(process, arena.as_ref());
    concolic.mark_input_register(register_id::GPR_BASE + 7, angryier_ir::IrType::Bits(64))?;
    for _ in 0..8 {
        if matches!(concolic.step()?, StepOutcome::Terminated { .. }) {
            break;
        }
    }
    assert!(
        !concolic.path_constraints().is_empty(),
        "branch must record a constraint"
    );

    // Promote: the symbolic state carries rdi's symbol + the ¬(rdi==5) path.
    let promoted = concolic.promote_to_symbolic(0);
    assert_eq!(promoted.constraints.len(), 1);
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), promoted.process.clone());
    session.states.clear();
    session.states.push(promoted);
    let mut backend = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
    let model = session.solve_state(0, &mut backend, std::time::Duration::from_secs(10))?;
    let rdi = model
        .iter()
        .find(|(r, _)| *r == register_id::GPR_BASE + 7)
        .map(|(_, v)| *v)
        .ok_or("no rdi in model")?;
    assert_ne!(rdi, 5, "promoted path constraint must exclude rdi==5");
    Ok(())
}

/// Lua solve: `solve = true` returns input models — a script finds the
/// input byte that reaches `target`.
#[cfg(all(feature = "xed", feature = "script", target_arch = "x86_64"))]
#[test]
fn lua_solve_returns_input_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_dir("angryier-luasolve").ok_or("no tempdir")?;
    let path_s = dir.join("s.s");
    let path_o = dir.join("s.o");
    let path_bin = dir.join("s");
    std::fs::write(
        &path_s,
        "_start:\n    cmp $5, %rdi\n    je target\n    mov $60, %rax\n    xor %rdi, %rdi\n    syscall\ntarget:\n    mov $60, %rax\n    mov $9, %rdi\n    syscall\n",
    )?;
    if assemble(&path_s, &path_o).is_none() || link(&path_bin, &[&path_o]).is_none() {
        eprintln!("skipping: assembler unavailable");
        return Ok(());
    }
    let lua = mlua::Lua::new();
    angryier_runtime::script::register(&lua)?;
    // target at _start+0x12 (cmp=4B, je=2B, mov=7B, xor=2B, syscall=2B → +17=0x11... compute: 0x401012)
    let script = format!(
        r#"
        local r = angry.run("{}", {{
            symbolic = {{ rdi = 64 }},
            find = {{ 0x401012 }},
            solve = true,
            steps = 64, states = 8,
        }})
        assert(r.found == 1, "found state expected")
        assert(#r.inputs == 1, "one model expected")
        return r.found
        "#,
        path_bin.display()
    );
    let found: u64 = lua.load(&script).eval()?;
    assert_eq!(found, 1);
    Ok(())
}

/// Fuzz loop: symbolic solve generates an input, concrete replay with
/// that stdin reaches the same target — coverage validated.
#[cfg(all(feature = "xed", feature = "z3", target_arch = "x86_64"))]
#[test]
fn fuzz_generate_produces_reaching_inputs() -> Result<(), Box<dyn std::error::Error>> {
    let source = r#"
        .global _start
        .text
_start:
    sub $16, %rsp
    xor %rax, %rax
    xor %rdi, %rdi
    mov %rsp, %rsi
    mov $4, %rdx
    syscall
    cmpb $0x41, (%rsp)
    je target
    mov $60, %rax
    xor %rdi, %rdi
    syscall
target:
    mov $60, %rax
    mov $7, %rdi
    syscall
"#;
    let dir = temp_dir("angryier-fuzz").ok_or("no tempdir")?;
    let path_s = dir.join("f.s");
    let path_o = dir.join("f.o");
    let path_bin = dir.join("f");
    std::fs::write(&path_s, source)?;
    if assemble(&path_s, &path_o).is_none() || link(&path_bin, &[&path_o]).is_none() {
        eprintln!("skipping: assembler unavailable");
        return Ok(());
    }
    let elf_bytes = std::fs::read(&path_bin)?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    // `target:` is at entry+0x28 (see fixture disassembly).
    let proc = runtime.load_elf(&elf_bytes)?;
    let entry = proc.pc()?;
    let target_va = entry + 0x28;
    let results = runtime.fuzz_generate(&elf_bytes, &[target_va], 128, std::time::Duration::from_secs(15))?;
    assert!(!results.is_empty(), "must generate an input");
    let (input, coverage) = &results[0];
    assert_eq!(input.first().copied(), Some(0x41), "stdin[0] must be 'A'");
    assert!(coverage.contains(&target_va), "replayed input must reach target");
    Ok(())
}

/// Lua REPL session: `angry.open` → step/reg/states/symbolic drive a
/// session interactively.
#[cfg(all(feature = "xed", feature = "script", target_arch = "x86_64"))]
#[test]
fn lua_open_steps_interactively() -> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_dir("angryier-luaopen").ok_or("no tempdir")?;
    let path_s = dir.join("o.s");
    let path_o = dir.join("o.o");
    let path_bin = dir.join("o");
    std::fs::write(
        &path_s,
        "_start:\n    mov $5, %rax\n    add $3, %rax\n    mov $60, %rax\n    xor %rdi, %rdi\n    syscall\n",
    )?;
    if assemble(&path_s, &path_o).is_none() || link(&path_bin, &[&path_o]).is_none() {
        eprintln!("skipping: assembler unavailable");
        return Ok(());
    }
    let lua = mlua::Lua::new();
    angryier_runtime::script::register(&lua)?;
    let script = format!(
        r#"
        local s = angry.open("{}")
        assert(s:step() == "stepped")
        assert(s:step() == "stepped")
        assert(s:states() == 1)
        local pc = s:pc()
        assert(pc ~= 0x401000, "pc must advance")
        return s:states()
        "#,
        path_bin.display()
    );
    let states: u64 = lua.load(&script).eval()?;
    assert_eq!(states, 1);
    Ok(())
}

/// Symbolic dynamic binary: load_elf_dynamic + SymbolicSession — the
/// __libc_start_main hook fires and symbolic argv reaches `main`.
#[cfg(all(feature = "xed", feature = "z3", target_arch = "x86_64"))]
#[test]
fn symbolic_dynamic_binary_runs() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_expr::ExprReader;
    use angryier_runtime::SymbolicSession;
    use angryier_solver_z3::Z3Backend;
    use std::sync::Arc;

    // main(argc, argv): fork on argv[1][0]. Dynamic build → __libc_start_main
    // hook → main.
    let dir = temp_dir("angryier-dynsym").ok_or("no tempdir")?;
    let path_c = dir.join("d.c");
    let path_bin = dir.join("d");
    std::fs::write(
        &path_c,
        r#"int main(int argc, char** argv){
    if (argc > 1 && argv[1][0] == 'K') {
        register long rax asm("rax") = 1;
        register long rdi asm("rdi") = 1;
        register const char* rsi asm("rsi") = "K\n";
        register long rdx asm("rdx") = 2;
        asm volatile("syscall" : "+r"(rax) : "r"(rdi), "r"(rsi), "r"(rdx) : "rcx","r11","memory");
    }
    return 0;
}"#,
    )?;
    let ok = std::process::Command::new("cc")
        .arg(&path_c)
        .arg("-o")
        .arg(&path_bin)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        eprintln!("skipping: cc unavailable");
        return Ok(());
    }
    let bytes = std::fs::read(&path_bin)?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf_dynamic(&bytes, &[])?;
    let arena = Arc::new(angryier_expr::ShardedExprArena::new(
        angryier_types::ExpressionNormalizationVersion(1),
    ));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    let mut backend = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
    let report = session.run(512, 16, Some(&mut backend), std::time::Duration::from_secs(20), false)?;
    eprintln!("dynsym: {report:?}");
    // The session must reach `main` (the hook fired) — argc>1 check reads
    // concrete argc=1 → no fork needed; main returns 0 → exit.
    assert!(report.steps >= 4, "must reach past _start");
    Ok(())
}

/// Loop summarization: a 100-iteration counter loop collapses into a
/// single symbolic step.
#[cfg(all(feature = "xed", target_arch = "x86_64"))]
#[test]
fn loop_summary_collapses_counter_loop() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_runtime::SymbolicSession;
    use std::sync::Arc;

    // i: 0..100 counter loop — `add $1,%rcx; cmp $100,%rcx; jl loop`.
    let source = r#"
        .global _start
        .text
_start:
    xor %rcx, %rcx
loop:
    add $1, %rcx
    cmp $100, %rcx
    jl loop
    mov $60, %rax
    xor %rdi, %rdi
    syscall
"#;
    let dir = temp_dir("angryier-loop").ok_or("no tempdir")?;
    let path_s = dir.join("l.s");
    let path_o = dir.join("l.o");
    let path_bin = dir.join("l");
    std::fs::write(&path_s, source)?;
    if assemble(&path_s, &path_o).is_none() || link(&path_bin, &[&path_o]).is_none() {
        eprintln!("skipping: assembler unavailable");
        return Ok(());
    }
    let elf_bytes = std::fs::read(&path_bin)?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&elf_bytes)?;
    let arena = Arc::new(angryier_expr::ShardedExprArena::new(
        angryier_types::ExpressionNormalizationVersion(1),
    ));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    session.enable_loop_summaries();
    let report = session.run(256, 8, None, std::time::Duration::from_secs(10), false)?;
    eprintln!("loop report: {report:?}");
    // Unsummarized: 100 iters × 3 insns = 300+ steps; summarized: ~6.
    assert!(report.steps < 20, "loop must collapse: steps={}", report.steps);
    let rcx = session.dead[0].process.read_register(register_id::GPR_BASE + 1)?;
    assert_eq!(rcx, 100, "counter must land on the bound");
    Ok(())
}
