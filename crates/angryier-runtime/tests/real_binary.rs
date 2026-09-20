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
        match session.step()? {
            StepOutcome::SimProcedure { .. } => break,
            _ => {}
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
        match session.step()? {
            StepOutcome::SimProcedure { .. } => break,
            _ => {}
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
        match session.step()? {
            StepOutcome::Terminated { .. } => break,
            _ => {}
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
    let (process, ok_exit, fail_exit) = loaded_process(&runtime, 6)?;

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
            match session.step()? {
                StepOutcome::SimProcedure { .. } => break,
                _ => {}
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
