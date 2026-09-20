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
    // `syscall` with RAX = 0 is `read`, which the environment model does not
    // implement yet; execution must fail explicitly rather than fabricate a
    // result.
    let mut process = runtime.load_elf(&build_fixture_from("_start:\n    syscall\n    hlt\n")?)?;
    let error = runtime
        .step(&mut process)
        .err()
        .ok_or("expected an unsupported-syscall error")?;
    let message = error.to_string();
    assert!(
        message.contains("unsupported syscall number 0"),
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
    fn trace_static_musl() {
        let Ok(bytes) = std::fs::read("/tmp/hello_musl") else {
            eprintln!("no fixture");
            return;
        };
        let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
        let mut process = runtime.load_elf(&bytes).expect("musl ELF loads");

        let mut terminated = false;
        for _ in 0..200_000 {
            match runtime.step(&mut process) {
                Ok(StepOutcome::Stepped { .. }) | Ok(StepOutcome::Syscall { .. }) => {}
                Ok(StepOutcome::Terminated { .. }) => {
                    terminated = true;
                    break;
                }
                Ok(other) => panic!("unexpected outcome {other:?}"),
                Err(e) => panic!("step failed at pc={:#x}: {e}", process.pc().unwrap_or(0)),
            }
        }
        assert!(terminated, "process did not terminate within the step budget");
        assert_eq!(
            String::from_utf8_lossy(&process.syscalls.output()),
            "hello from glibc\n"
        );
        assert_eq!(process.syscalls.exit_code(), Some(0));
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
    fn runs_static_glibc() {
        let Ok(bytes) = std::fs::read("/tmp/hello_glibc") else {
            eprintln!("no fixture");
            return;
        };
        let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
        let mut process = runtime.load_elf(&bytes).expect("load");
        for i in 0..400_000 {
            match runtime.step(&mut process) {
                Ok(StepOutcome::Terminated { .. }) => break,
                Ok(_) => {}
                Err(e) => {
                    let pc = process.pc().unwrap_or(0);
                    let tail = &process.trace[process.trace.len().saturating_sub(16)..];
                    panic!("stopped after {i} steps at pc={pc:#x}: {e}\ntail: {tail:#x?}");
                }
            }
        }
        assert_eq!(process.syscalls.output(), b"hello from glibc\n");
        assert_eq!(process.syscalls.exit_code(), Some(0));
    }
}

#[cfg(test)]
mod dbg_musl_stuck {
    use super::*;
    use angryier_runtime::{Runtime, StepOutcome};

    #[test]
    fn where_stuck() {
        let Ok(bytes) = std::fs::read("/tmp/hello_musl") else {
            return;
        };
        let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
        let mut process = runtime.load_elf(&bytes).expect("load");
        for i in 0..200_000 {
            match runtime.step(&mut process) {
                Ok(StepOutcome::Terminated { .. }) => {
                    eprintln!("terminated at {i}");
                    return;
                }
                Ok(_) => {}
                Err(e) => {
                    eprintln!("err at {i} pc={:#x}: {e}", process.pc().unwrap_or(0));
                    break;
                }
            }
        }
        let tail = &process.trace[process.trace.len().saturating_sub(30)..];
        eprintln!("tail: {tail:#x?}");
        eprintln!("output: {:?}", String::from_utf8_lossy(&process.syscalls.output()));
    }
}
