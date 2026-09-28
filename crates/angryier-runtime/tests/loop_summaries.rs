//! Differential proof tests for generalized loop summarization (roadmap
//! item 8, Phase 10): symbolic trip counts, Eq/Ne exit conditions, and
//! straight-line multi-block bodies.
//!
//! Every fixture is a real static ELF64 binary assembled and linked at test
//! time with the system binutils (`as` + `ld`); tests skip gracefully when
//! the toolchain is unavailable.
//!
//! Equivalence protocol (the `real_binary.rs` replay-validation pattern):
//! run the symbolic session with summaries enabled, take a terminated
//! state, `solve_state` it for concrete input bindings, then replay the
//! model through the plain stepping engine and assert the replayed behavior
//! matches what the summarized run predicts — same exit state, and a real
//! step-count reduction. Concrete fixtures additionally run the direct
//! differential: summaries on vs summaries off, both to termination.

#![cfg(feature = "xed")]
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use angryier_arch_intel64::register_id;
use angryier_runtime::{Runtime, StepOutcome, SymbolicSession};
use angryier_types::{SemanticVersion, TargetProfileId};

/// rbx register id (GPR_BASE + 3) — the symbolic bound in most fixtures.
const RBX: u32 = register_id::GPR_BASE + 3;
/// rcx register id (GPR_BASE + 1) — the usual induction counter.
const RCX: u32 = register_id::GPR_BASE + 1;
/// Solver budget per query.
const TIMEOUT: Duration = Duration::from_secs(20);

fn temp_dir(name: &str) -> Option<PathBuf> {
    let dir = std::env::temp_dir().join(format!("angryier-{name}-{}", std::process::id()));
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

/// Assembles and links `source` into a static ELF64 executable, returning
/// its bytes. `None` when the binutils toolchain is unavailable or fails.
fn build_elf(name: &str, source: &str) -> Option<Vec<u8>> {
    let dir = temp_dir(name)?;
    let path_s = dir.join("f.s");
    let path_o = dir.join("f.o");
    let path_bin = dir.join("f");
    std::fs::write(&path_s, source).ok()?;
    assemble(&path_s, &path_o)?;
    link(&path_bin, &[&path_o])?;
    std::fs::read(&path_bin).ok()
}

/// Runs a concrete process under the plain stepping engine until it
/// terminates or `budget` steps elapse. Returns the exit code (rdi at the
/// exit syscall) and the steps taken; the code is `None` when the budget
/// ran out first (the loop did not terminate).
fn run_concrete(
    runtime: &Runtime<impl angryier_arch::Decoder>,
    process: &mut angryier_runtime::Process,
    budget: u64,
) -> Result<(Option<u64>, u64), Box<dyn std::error::Error>> {
    let mut steps = 0u64;
    while steps < budget {
        if process.terminated {
            break;
        }
        match runtime.step(process)? {
            StepOutcome::Terminated { .. } | StepOutcome::Trap { .. } => {
                return Ok((process.read_register(register_id::GPR_BASE + 7).ok(), steps));
            }
            _ => steps += 1,
        }
    }
    Ok((None, steps))
}

/// Runs the fixture symbolically with summaries on or off and returns the
/// report (all states driven to termination or the step budget). The
/// backend must be built on `arena` — the session interns its expressions
/// there.
fn run_symbolic(
    elf: &[u8],
    summaries: bool,
    max_steps: u64,
    arena: &Arc<angryier_expr::ShardedExprArena>,
    backend: Option<&mut dyn angryier_solver::SolverBackend>,
) -> Result<angryier_runtime::SymbolicRunReport, Box<dyn std::error::Error>> {
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(elf)?;
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    if summaries {
        session.enable_loop_summaries();
    }
    let report = session.run(max_steps, 16, backend, TIMEOUT, false)?;
    Ok(report)
}

/// Concrete differential: the fixture steps to termination through the
/// plain concrete engine (ground-truth machine behavior), then runs
/// symbolically with summaries enabled — same exit state, same exit
/// counter, and the loop collapses (far fewer steps).
///
/// (The no-summary *symbolic* run is not a usable baseline here: without a
/// solver every jcc forks — concrete conditions do not constant-fold on
/// the symbolic path — so it explores both directions of every iteration.)
fn assert_concrete_differential(
    elf: &[u8],
    expected_exit: u64,
    plain_min_steps: u64,
    summarized_max_steps: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut plain = runtime.load_elf(elf)?;
    let (plain_exit, plain_steps) = run_concrete(&runtime, &mut plain, 8192)?;
    assert_eq!(
        plain_exit,
        Some(expected_exit),
        "plain run must terminate with the expected code"
    );
    assert!(plain_steps >= plain_min_steps, "plain steps: {plain_steps}");

    let process = runtime.load_elf(elf)?;
    let arena = Arc::new(angryier_expr::ShardedExprArena::new(
        angryier_types::ExpressionNormalizationVersion(1),
    ));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    session.enable_loop_summaries();
    let report = session.run(4096, 16, None, TIMEOUT, false)?;
    assert!(report.terminated >= 1, "summarized run must terminate: {report:?}");
    assert!(report.steps < summarized_max_steps, "loop must collapse: {report:?}");
    assert!(
        report.steps * 2 < plain_steps.max(24),
        "summarized {} steps vs plain {}",
        report.steps,
        plain_steps
    );
    let counter = session
        .dead
        .iter()
        .find(|state| state.process.terminated)
        .and_then(|state| state.process.read_register(RCX).ok())
        .ok_or("no terminated state with a counter")?;
    assert_eq!(counter, expected_exit, "exit counter must match plain stepping");
    Ok(())
}

/// Count-up loop, `jl` exit, concrete bound — the baseline shape.
#[test]
fn concrete_lt_loop_differential() -> Result<(), Box<dyn std::error::Error>> {
    let source = r#"
        .global _start
        .text
_start:
        xor %rcx, %rcx
loop:
        add $1, %rcx
        cmp $100, %rcx
        jl loop
        mov %rcx, %rdi
        mov $60, %rax
        syscall
"#;
    let elf = build_elf("lt-concrete", source).ok_or("assembler unavailable")?;
    assert_concrete_differential(&elf, 100, 290, 20)
}

/// Count-up `jle` exit (counter runs one past the bound) and a countdown
/// `jg` loop (negative step) — both inequality directions.
#[test]
fn concrete_le_and_countdown_differential() -> Result<(), Box<dyn std::error::Error>> {
    let le_source = r#"
        .global _start
        .text
_start:
        xor %rcx, %rcx
loop:
        add $1, %rcx
        cmp $49, %rcx
        jle loop
        mov %rcx, %rdi
        mov $60, %rax
        syscall
"#;
    let elf = build_elf("le-concrete", le_source).ok_or("assembler unavailable")?;
    assert_concrete_differential(&elf, 50, 145, 20)?;

    let down_source = r#"
        .global _start
        .text
_start:
        mov $50, %rcx
loop:
        sub $1, %rcx
        cmp $10, %rcx
        jg loop
        mov %rcx, %rdi
        mov $60, %rax
        syscall
"#;
    let elf = build_elf("gt-concrete", down_source).ok_or("assembler unavailable")?;
    assert_concrete_differential(&elf, 10, 115, 20)
}

/// 32-bit induction slice (`inc %ecx` / `cmp $50, %ecx`): the summary must
/// mask to the 32-bit compare domain and write back zero-extended.
#[test]
fn concrete_32bit_loop_differential() -> Result<(), Box<dyn std::error::Error>> {
    let source = r#"
        .global _start
        .text
_start:
        xor %rcx, %rcx
loop:
        inc %ecx
        cmp $50, %ecx
        jl loop
        mov %rcx, %rdi
        mov $60, %rax
        syscall
"#;
    let elf = build_elf("w32-concrete", source).ok_or("assembler unavailable")?;
    assert_concrete_differential(&elf, 50, 145, 20)
}

/// `while (i != 37) i++` — a Ne-exit loop with a cleanly divisible unit
/// step: summarized exactly like the inequality loops.
#[test]
fn concrete_ne_loop_differential() -> Result<(), Box<dyn std::error::Error>> {
    let source = r#"
        .global _start
        .text
_start:
        xor %rcx, %rcx
loop:
        add $1, %rcx
        cmp $37, %rcx
        jne loop
        mov %rcx, %rdi
        mov $60, %rax
        syscall
"#;
    let elf = build_elf("ne-concrete", source).ok_or("assembler unavailable")?;
    assert_concrete_differential(&elf, 37, 100, 20)
}

/// `i += 3` towards 40 — the step does not divide the distance, so the
/// bound is never reached: summarization must fall through to stepping
/// (never a wrong summary), and the run simply does not terminate. The
/// solver-gated run keeps the concrete branch direction, so the budget is
/// spent looping rather than forking.
#[cfg(all(feature = "z3", target_arch = "x86_64"))]
#[test]
fn concrete_ne_undivisible_falls_through() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_expr::ExprReader;
    use angryier_solver_z3::Z3Backend;

    let source = r#"
        .global _start
        .text
_start:
        xor %rcx, %rcx
loop:
        add $3, %rcx
        cmp $40, %rcx
        jne loop
        mov %rcx, %rdi
        mov $60, %rax
        syscall
"#;
    let elf = build_elf("ne-unclean", source).ok_or("assembler unavailable")?;
    let arena = Arc::new(angryier_expr::ShardedExprArena::new(
        angryier_types::ExpressionNormalizationVersion(1),
    ));
    let mut backend = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
    let report = run_symbolic(&elf, true, 66, &arena, Some(&mut backend))?;
    assert_eq!(report.terminated, 0, "must not terminate: {report:?}");
    assert_eq!(report.steps, 66, "must keep stepping to the budget");
    Ok(())
}

/// `do { i++ } while (i == limit)` — an Eq-exit loop (je back edge). The
/// trip count is 1 or 2 depending on whether the first incremented value
/// lands exactly on the bound; both fixtures must summarize to that.
#[test]
fn concrete_eq_exit_two_shapes() -> Result<(), Box<dyn std::error::Error>> {
    let lands_on_bound = r#"
        .global _start
        .text
_start:
        mov $4, %rcx
loop:
        add $1, %rcx
        cmp $5, %rcx
        je loop
        mov %rcx, %rdi
        mov $60, %rax
        syscall
"#;
    let elf = build_elf("eq-hit", lands_on_bound).ok_or("assembler unavailable")?;
    // 4 -> 5 (== bound, back edge) -> 6 (!= bound, exit): two iterations.
    assert_concrete_differential(&elf, 6, 8, 20)?;

    let misses_bound = r#"
        .global _start
        .text
_start:
        xor %rcx, %rcx
loop:
        add $1, %rcx
        cmp $5, %rcx
        je loop
        mov %rcx, %rdi
        mov $60, %rax
        syscall
"#;
    let elf = build_elf("eq-miss", misses_bound).ok_or("assembler unavailable")?;
    // 0 -> 1 (!= 5): exits after a single body — one pass plus the tail.
    assert_concrete_differential(&elf, 1, 5, 20)
}

/// A symbolic bound (`cmp %rbx, %rcx; jl`) read from a register marked
/// symbolic: the summary builds the exit counter as
/// `ite(0 < rbx, rbx, 1)` and constrains `rbx <= exit`. The solved model
/// must replay through plain stepping to exactly the predicted exit code,
/// with a real step-count reduction.
#[cfg(all(feature = "z3", target_arch = "x86_64"))]
#[test]
fn symbolic_bound_lt_loop_proves_equivalent() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_expr::ExprReader;
    use angryier_solver_z3::Z3Backend;

    let source = r#"
        .global _start
        .text
_start:
        cmp $30, %rbx
        jb out
        cmp $1000, %rbx
        ja out
        xor %rcx, %rcx
loop:
        add $1, %rcx
        cmp %rbx, %rcx
        jl loop
        mov %rcx, %rdi
        mov $60, %rax
        syscall
out:
        xor %rdi, %rdi
        mov $60, %rax
        syscall
"#;
    let elf = build_elf("lt-symbolic", source).ok_or("assembler unavailable")?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&elf)?;
    let arena = Arc::new(angryier_expr::ShardedExprArena::new(
        angryier_types::ExpressionNormalizationVersion(1),
    ));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    session.mark_symbolic(0, RBX, angryier_ir::IrType::Bits(64))?;
    session.enable_loop_summaries();
    let mut backend = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
    let report = session.run(256, 16, Some(&mut backend), TIMEOUT, false)?;
    assert!(report.terminated >= 1, "must terminate: {report:?}");
    assert!(report.steps < 40, "loop must collapse: {report:?}");

    // Find a terminated state whose model drives the loop (rbx in
    // [30, 1000]) — that is the summarized path.
    let mut model = None;
    for state in session.dead.iter().filter(|s| s.process.terminated) {
        session.states.push(state.clone());
        let index = session.states.len() - 1;
        let bindings = session.solve_state(index, &mut backend, TIMEOUT).unwrap_or_default();
        session.states.pop();
        if let Some(value) = bindings.iter().find(|(r, _)| *r == RBX).map(|(_, v)| *v)
            && (30..=1000).contains(&value)
        {
            model = Some(value);
            break;
        }
    }
    let value = model.ok_or("no model reaches the summarized loop")?;

    // The summarized run's prediction: exit counter = rbx (since 0 < rbx),
    // so the program exits with code = rbx.
    let expected_exit = value;

    // Replay through plain stepping.
    let mut replay = runtime.load_elf(&elf)?;
    replay.write_register(RBX, value)?;
    let (exit, steps) = run_concrete(&runtime, &mut replay, 8192)?;
    let exit = exit.ok_or("replay did not terminate")?;
    assert_eq!(
        exit, expected_exit,
        "replayed exit must match the summarized prediction"
    );
    assert!(
        steps >= 3 * value,
        "replay must actually run the loop: {steps} steps for rbx={value}"
    );
    assert!(
        report.steps * 2 < steps,
        "summarized {} steps vs replayed {}",
        report.steps,
        steps
    );
    Ok(())
}

/// A symbolic bound behind a `jne` exit with step 3: the summary emits the
/// divisibility constraint `(rbx - 0) % 3 == 0`, so every model the solver
/// returns is a multiple of 3 — exactly the inputs for which the concrete
/// loop terminates.
#[cfg(all(feature = "z3", target_arch = "x86_64"))]
#[test]
fn symbolic_ne_loop_divisibility_constraint() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_expr::ExprReader;
    use angryier_solver_z3::Z3Backend;

    let source = r#"
        .global _start
        .text
_start:
        cmp $60, %rbx
        jb out
        cmp $900, %rbx
        ja out
        xor %rcx, %rcx
loop:
        add $3, %rcx
        cmp %rbx, %rcx
        jne loop
        mov %rcx, %rdi
        mov $60, %rax
        syscall
out:
        xor %rdi, %rdi
        mov $60, %rax
        syscall
"#;
    let elf = build_elf("ne-symbolic", source).ok_or("assembler unavailable")?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&elf)?;
    let arena = Arc::new(angryier_expr::ShardedExprArena::new(
        angryier_types::ExpressionNormalizationVersion(1),
    ));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    session.mark_symbolic(0, RBX, angryier_ir::IrType::Bits(64))?;
    session.enable_loop_summaries();
    let mut backend = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
    let report = session.run(256, 16, Some(&mut backend), TIMEOUT, false)?;
    assert!(report.terminated >= 1, "must terminate: {report:?}");
    assert!(report.steps < 40, "loop must collapse: {report:?}");

    let mut model = None;
    for state in session.dead.iter().filter(|s| s.process.terminated) {
        session.states.push(state.clone());
        let index = session.states.len() - 1;
        let bindings = session.solve_state(index, &mut backend, TIMEOUT).unwrap_or_default();
        session.states.pop();
        if let Some(value) = bindings.iter().find(|(r, _)| *r == RBX).map(|(_, v)| *v)
            && (60..=900).contains(&value)
        {
            model = Some(value);
            break;
        }
    }
    let value = model.ok_or("no model reaches the summarized loop")?;
    assert_eq!(value % 3, 0, "the divisibility constraint must shape the model");

    let mut replay = runtime.load_elf(&elf)?;
    replay.write_register(RBX, value)?;
    let (exit, steps) = run_concrete(&runtime, &mut replay, 8192)?;
    let exit = exit.ok_or("replay did not terminate")?;
    assert_eq!(exit, value, "replay must land exactly on the symbolic bound");
    assert!(
        report.steps * 2 < steps,
        "summarized {} steps vs replayed {}",
        report.steps,
        steps
    );
    Ok(())
}

/// An Eq-exit loop with a symbolic bound: the exit counter is
/// `ite(4 + 1 == rbx, rbx + 1, 4 + 1)`. Every model in the guarded range
/// replays to the formula's prediction, and the two control values (bound
/// hit / bound missed) are checked concretely as well.
#[cfg(all(feature = "z3", target_arch = "x86_64"))]
#[test]
fn symbolic_eq_exit_proves_equivalent() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_expr::ExprReader;
    use angryier_solver_z3::Z3Backend;

    let source = r#"
        .global _start
        .text
_start:
        cmp $5, %rbx
        jb out
        cmp $7, %rbx
        ja out
        mov $4, %rcx
loop:
        add $1, %rcx
        cmp %rbx, %rcx
        je loop
        mov %rcx, %rdi
        mov $60, %rax
        syscall
out:
        xor %rdi, %rdi
        mov $60, %rax
        syscall
"#;
    let elf = build_elf("eq-symbolic", source).ok_or("assembler unavailable")?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));

    // Closed-form prediction: first value is 5; if it equals the bound the
    // loop runs one more body (exit 5 + 1 = rbx + 1), else it exits at 5.
    let predicted = |bound: u64| if bound == 5 { 6 } else { 5 };
    for bound in [5u64, 6, 7] {
        let mut replay = runtime.load_elf(&elf)?;
        replay.write_register(RBX, bound)?;
        let (exit, _) = run_concrete(&runtime, &mut replay, 64)?;
        assert_eq!(exit, Some(predicted(bound)), "concrete replay for rbx={bound}");
    }

    let process = runtime.load_elf(&elf)?;
    let arena = Arc::new(angryier_expr::ShardedExprArena::new(
        angryier_types::ExpressionNormalizationVersion(1),
    ));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    session.mark_symbolic(0, RBX, angryier_ir::IrType::Bits(64))?;
    session.enable_loop_summaries();
    let mut backend = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
    let report = session.run(128, 16, Some(&mut backend), TIMEOUT, false)?;
    assert!(report.terminated >= 1, "must terminate: {report:?}");
    assert!(report.steps < 40, "loop must collapse: {report:?}");

    let mut model = None;
    for state in session.dead.iter().filter(|s| s.process.terminated) {
        session.states.push(state.clone());
        let index = session.states.len() - 1;
        let bindings = session.solve_state(index, &mut backend, TIMEOUT).unwrap_or_default();
        session.states.pop();
        if let Some(value) = bindings.iter().find(|(r, _)| *r == RBX).map(|(_, v)| *v)
            && (5..=7).contains(&value)
        {
            model = Some(value);
            break;
        }
    }
    let value = model.ok_or("no model reaches the summarized loop")?;
    let mut replay = runtime.load_elf(&elf)?;
    replay.write_register(RBX, value)?;
    let (exit, _) = run_concrete(&runtime, &mut replay, 64)?;
    assert_eq!(exit, Some(predicted(value)), "replayed exit must match the ite formula");
    Ok(())
}

/// Nested mixed loops: an outer concrete loop that keeps stepping (its
/// body contains the inner loop's branch, so it is not straight-line)
/// around an inner single-block loop with a symbolic bound that collapses
/// every outer iteration. The loop path is driven with solver-checked
/// stepping (forks keep both directions on Unknown, so the run loop would
/// spend its budget on unsatisfiable phantoms); the solved model replays
/// to the same final state with far more steps.
#[cfg(all(feature = "z3", target_arch = "x86_64"))]
#[test]
fn nested_mixed_loops_prove_equivalent() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_expr::ExprReader;
    use angryier_solver_z3::Z3Backend;

    let source = r#"
        .global _start
        .text
_start:
        cmp $30, %rbx
        jb out
        cmp $100, %rbx
        ja out
        xor %rcx, %rcx
outer:
        xor %rdx, %rdx
inner:
        add $1, %rdx
        cmp %rbx, %rdx
        jl inner
        add $1, %rcx
        cmp $3, %rcx
        jl outer
        mov %rdx, %rdi
        mov $60, %rax
        syscall
out:
        xor %rdi, %rdi
        mov $60, %rax
        syscall
"#;
    let elf = build_elf("nested-mixed", source).ok_or("assembler unavailable")?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&elf)?;
    let arena = Arc::new(angryier_expr::ShardedExprArena::new(
        angryier_types::ExpressionNormalizationVersion(1),
    ));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    session.mark_symbolic(0, RBX, angryier_ir::IrType::Bits(64))?;
    session.enable_loop_summaries();
    let mut backend = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;

    // Drive the loop path: after each guard fork the newest state is the
    // not-taken (loop-ward) child.
    let mut loop_path_steps = 0u64;
    let mut index = session.states.len() - 1;
    while loop_path_steps < 128 {
        index = session.states.len() - 1;
        match session.step_state_checked(index, &mut backend, TIMEOUT)? {
            angryier_runtime::SymbolicStepOutcome::Terminated => break,
            _ => loop_path_steps += 1,
        }
    }
    assert!(
        matches!(
            session.step_state_checked(index, &mut backend, TIMEOUT),
            Ok(angryier_runtime::SymbolicStepOutcome::Terminated)
        ),
        "loop path must terminate"
    );
    // Three outer rounds of (reset + one summary + three insns) plus the
    // prologue and tail — the inner loops collapsed to one step each.
    assert!(
        loop_path_steps < 60,
        "inner loops must collapse: {loop_path_steps} steps"
    );

    // Solve the terminated loop-path state and replay it concretely.
    let bindings = session.solve_state(index, &mut backend, TIMEOUT)?;
    let value = bindings
        .iter()
        .find(|(r, _)| *r == RBX)
        .map(|(_, v)| *v)
        .ok_or("no model for the symbolic bound")?;
    assert!(
        (30..=100).contains(&value),
        "guard constraints must shape the model: {value}"
    );

    let mut replay = runtime.load_elf(&elf)?;
    replay.write_register(RBX, value)?;
    let (exit, steps) = run_concrete(&runtime, &mut replay, 8192)?;
    let exit = exit.ok_or("replay did not terminate")?;
    // The final inner counter of the last outer round is the bound itself.
    assert_eq!(exit, value, "replayed exit must match the summarized prediction");
    assert!(
        loop_path_steps * 2 < steps,
        "summarized {loop_path_steps} steps vs replayed {steps}"
    );
    Ok(())
}

/// Straight-line bodies spanning several CFG blocks, chained by explicit
/// intra-body jumps (a two-block and a three-block chain): both summarize
/// exactly like the single-block form. A body entered from the outside
/// mid-way (a jump targeting an interior block) is deliberately NOT
/// extracted — the entering block reaches the latch without passing the
/// header, so the natural-loop body is not a chain and the summary stays
/// off (conservative: stepping remains exactly correct).
#[test]
fn multi_block_body_summarizes() -> Result<(), Box<dyn std::error::Error>> {
    let two_blocks = r#"
        .global _start
        .text
_start:
        xor %rcx, %rcx
        jmp loop
loop:
        add $1, %rcx
        jmp mid
mid:
        cmp $100, %rcx
        jl loop
        mov %rcx, %rdi
        mov $60, %rax
        syscall
"#;
    let elf = build_elf("mb-jump", two_blocks).ok_or("assembler unavailable")?;
    assert_concrete_differential(&elf, 100, 290, 20)?;

    let three_blocks = r#"
        .global _start
        .text
_start:
        xor %rcx, %rcx
        jmp loop
loop:
        add $1, %rcx
        jmp a
a:
        nop
        jmp b
b:
        cmp $100, %rcx
        jl loop
        mov %rcx, %rdi
        mov $60, %rax
        syscall
"#;
    let elf = build_elf("mb-three", three_blocks).ok_or("assembler unavailable")?;
    assert_concrete_differential(&elf, 100, 290, 20)
}

/// An early-exit branch inside the body makes it not straight-line: the
/// loop must keep stepping (no wrong summary) and still terminate through
/// the early exit. Short bound so the solver-less run (every jcc forks;
/// phantom children terminate immediately) stays inside the budget — the
/// step count proves the body really executed.
#[test]
fn early_exit_body_is_not_summarized() -> Result<(), Box<dyn std::error::Error>> {
    let source = r#"
        .global _start
        .text
_start:
        xor %rcx, %rcx
loop:
        add $1, %rcx
        cmp $5, %rcx
        je done
        cmp $100, %rcx
        jl loop
done:
        mov %rcx, %rdi
        mov $60, %rax
        syscall
"#;
    let elf = build_elf("early-exit", source).ok_or("assembler unavailable")?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&elf)?;
    let arena = Arc::new(angryier_expr::ShardedExprArena::new(
        angryier_types::ExpressionNormalizationVersion(1),
    ));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    session.enable_loop_summaries();
    let report = session.run(512, 16, None, TIMEOUT, false)?;
    assert!(
        report.terminated >= 1,
        "must terminate through the early exit: {report:?}"
    );
    // 5 iterations x 4 insns + tail — the loop really stepped (a wrong
    // summary would finish in a handful of steps).
    assert!(report.steps >= 26, "must not summarize an early-exit body: {report:?}");
    // The real path exits at exactly 5. The counter lives in the symbolic
    // shadow (an Add chain), so fold it through the arena rather than
    // reading the stale concrete register; unsatisfiable phantom children
    // (kept because a solver-less fork enqueues both directions) may carry
    // other values, but the true path's 5 must be among them.
    assert!(
        session
            .dead
            .iter()
            .filter(|state| state.process.terminated)
            .filter_map(|state| state.registers.get(&RCX).map(|(expr, _)| *expr))
            .any(|expr| angryier_execution::constant_value(&*arena, expr).ok() == Some(5)),
        "the real path must exit at 5"
    );
    Ok(())
}
