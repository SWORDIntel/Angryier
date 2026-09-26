//! Differential proof tests for function summaries (roadmap §5 item 8,
//! Phase 10 remainder): pure-function call collapsing with template reuse.
//!
//! Same protocol as `loop_summaries.rs`: every fixture is a real static
//! ELF64 binary assembled at test time (`as` + `ld`, skipped when the
//! toolchain is unavailable); the plain stepping engine is the ground-truth
//! oracle, and summarized runs must reach the identical exit state with a
//! real step-count reduction. Template reuse is proven by counters: one
//! build per argument shape, one hit per collapsed call.

#![cfg(feature = "xed")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use angryier_arch_intel64::register_id;
use angryier_expr::ExprArena as _;
use angryier_runtime::{Runtime, StepOutcome, SymbolicSession};
use angryier_types::{SemanticVersion, TargetProfileId};

/// rbx register id (GPR_BASE + 3) — the symbolic argument in the z3 leg.
const RBX: u32 = register_id::GPR_BASE + 3;
/// rax register id — the summary's return register.
const RAX: u32 = register_id::GPR_BASE;
/// Solver budget per query. Generous on purpose: the differential runs
/// issue a feasibility query per concrete branch, and a timeout under
/// parallel test load reads as Unknown, which forks phantom directions and
/// destroys the step accounting.
const TIMEOUT: Duration = Duration::from_secs(120);

/// Serializes the solver-heavy differentials — parallel Z3 processes
/// starve each other into timeouts (see TIMEOUT).
static SOLVER_TESTS: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Runs `f` on a thread with a large stack: the solver FFI translates
/// expressions recursively, and a solver-gated 50-iteration symbolic loop
/// accumulates a flag-composition chain thousands of nodes deep (per-step
/// flag writes compose from the incoming flags — pre-existing engine
/// behavior, identical without function summaries). The engine work itself
/// is iterative; only the backend's translation recurses. `None` when the
/// thread could not be spawned or panicked.
fn on_deep_stack<R: Send + 'static>(f: impl FnOnce() -> R + Send + 'static) -> Option<R> {
    let handle = std::thread::Builder::new()
        .stack_size(512 * 1024 * 1024)
        .spawn(f)
        .ok()?;
    handle.join().ok()
}

fn temp_dir(name: &str) -> Option<PathBuf> {
    let dir = std::env::temp_dir().join(format!("angryier-fnsum-{name}-{}", std::process::id()));
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

/// Assembles and links `source` into a static ELF64 executable. `None` when
/// the binutils toolchain is unavailable or fails.
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

/// The summarized pure helper under test: `rax = ((rdi * 8) ^ (rdi + 3)) + rdi`
/// in nine register-only instructions. Mirrored here for expected values.
fn compute(value: u64) -> u64 {
    ((value.wrapping_mul(8)) ^ (value.wrapping_add(3))).wrapping_add(value)
}

const COMPUTE_SOURCE: &str = r#"
        .text
compute:
        mov %rdi, %rax
        add %rax, %rax
        add %rax, %rax
        add %rax, %rax
        mov %rdi, %rcx
        add $3, %rcx
        xor %rcx, %rax
        add %rdi, %rax
        ret
"#;

/// Runs a concrete process under the plain stepping engine until it
/// terminates or `budget` steps elapse. Returns the exit code (rdi at the
/// exit syscall) and the steps taken; the code is `None` when the budget
/// ran out first.
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

/// Loop driver calling `compute` once per iteration over `i in 1..=iters`,
/// accumulating into rbx and exiting with it. `indirect` selects the
/// `call *%rax` register-indirect dispatch (the DriverObject-style shape)
/// over the direct `call`.
fn caller_source(indirect: bool, iters: u64) -> String {
    let call = if indirect {
        "movabs $compute, %rax
	call *%rax"
    } else {
        "call compute"
    };
    format!(
        r#"
        .global _start
        .text
{COMPUTE_SOURCE}
_start:
        mov $1, %r12d
loop:
        mov %r12, %rdi
        {call}
        add %rax, %rbx
        inc %r12
        cmp ${iters_plus}, %r12
        jl loop
        mov %rbx, %rdi
        mov $60, %rax
        syscall
"#,
        iters_plus = iters + 1
    )
}

/// The loop's ground-truth exit value: the accumulated helper results.
fn expected_exit(iters: u64) -> u64 {
    (1..=iters).map(compute).sum()
}

/// Deep constant fold for accumulator chains: an Add per loop iteration
/// outgrows the shared folder's 16-depth cap while staying trivially
/// concrete (same rationale as the runtime's deep fold for loop counters).
fn deep_fold(arena: &angryier_expr::ShardedExprArena, expr: angryier_types::ExprId) -> Option<u64> {
    fn go(
        arena: &angryier_expr::ShardedExprArena,
        expr: angryier_types::ExprId,
        memo: &mut std::collections::BTreeMap<angryier_types::ExprId, Option<u64>>,
        depth: u32,
    ) -> Option<u64> {
        if depth > 100_000 {
            return None;
        }
        if let Some(seen) = memo.get(&expr) {
            return *seen;
        }
        memo.insert(expr, None);
        let node = arena.get(expr)?;
        let mask = match node.sort {
            angryier_expr::ExprSort::BitVec(bits) if bits < 64 => (1u64 << bits) - 1,
            _ => u64::MAX,
        };
        let mut child = |index: usize| go(arena, *node.operands.get(index)?, memo, depth + 1);
        let value = match node.op {
            angryier_expr::ExprOp::Constant => {
                let mut buffer = [0u8; 8];
                let len = node.immediate.len().min(8);
                buffer[..len].copy_from_slice(&node.immediate[..len]);
                u64::from_le_bytes(buffer)
            }
            angryier_expr::ExprOp::Add => child(0)?.wrapping_add(child(1)?) & mask,
            angryier_expr::ExprOp::Sub => child(0)?.wrapping_sub(child(1)?) & mask,
            angryier_expr::ExprOp::Mul => child(0)?.wrapping_mul(child(1)?) & mask,
            angryier_expr::ExprOp::And => child(0)? & child(1)?,
            angryier_expr::ExprOp::Or => child(0)? | child(1)?,
            angryier_expr::ExprOp::Xor => child(0)? ^ child(1)?,
            // Zero/sign extension from the child's own width — the sum
            // stays well inside 64 bits for these fixtures, but the sign
            // fill is computed properly anyway.
            angryier_expr::ExprOp::ZExt => child(0)?,
            angryier_expr::ExprOp::SExt => {
                let operand = *node.operands.first()?;
                let width = match arena.sort_of(operand) {
                    Some(angryier_expr::ExprSort::BitVec(bits)) => u32::from(bits),
                    _ => return None,
                };
                let value = child(0)?;
                if width > 0 && width < 64 && value & (1u64 << (width - 1)) != 0 {
                    value | (!u64::MAX << width)
                } else {
                    value
                }
            }
            _ => return None,
        };
        memo.insert(expr, Some(value));
        Some(value)
    }
    let mut memo = std::collections::BTreeMap::new();
    go(arena, expr, &mut memo, 0)
}

/// The folded rbx values of all terminated states — solver-less runs fork
/// phantom exits, so the ground-truth value is asserted by membership.
fn folded_values(
    session: &SymbolicSession<impl angryier_arch::Decoder>,
    arena: &angryier_expr::ShardedExprArena,
) -> Vec<u64> {
    session
        .dead
        .iter()
        .filter(|state| state.process.terminated)
        .filter_map(|state| state.registers.get(&(register_id::GPR_BASE + 3)).map(|(expr, _)| *expr))
        .filter_map(|expr| deep_fold(arena, expr))
        .collect()
}

/// Solver-gated symbolic run over the 50-iteration caller fixture:
/// concrete `jl` conditions have exactly one feasible direction, so the
/// real path runs alone (no phantom forks) and step counts are exact.
/// Returns (plain-run steps, report, summary hits, template builds, folded
/// exit values) — the plain stepping engine is the ground-truth oracle.
/// (plain-run steps, symbolic report, summary hits, template builds, folded
/// exit values of the terminated states.)
#[cfg(all(feature = "z3", target_arch = "x86_64"))]
type SummarizedRun = (u64, angryier_runtime::SymbolicRunReport, u64, u64, Vec<u64>);

#[cfg(all(feature = "z3", target_arch = "x86_64"))]
fn summarized_run(name: &str, indirect: bool) -> Result<SummarizedRun, Box<dyn std::error::Error>> {
    use angryier_expr::ExprReader;
    use angryier_solver_z3::Z3Backend;

    const ITERS: u64 = 50;
    let elf = build_elf(name, &caller_source(indirect, ITERS)).ok_or("assembler unavailable")?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));

    // Ground truth: the plain stepping engine.
    let mut plain = runtime.load_elf(&elf)?;
    let (plain_exit, plain_steps) = run_concrete(&runtime, &mut plain, 8192)?;
    assert_eq!(
        plain_exit,
        Some(expected_exit(ITERS)),
        "plain run must terminate with the accumulated sum"
    );
    assert!(plain_steps >= 550, "plain steps: {plain_steps}");

    let process = runtime.load_elf(&elf)?;
    let arena = Arc::new(angryier_expr::ShardedExprArena::new(
        angryier_types::ExpressionNormalizationVersion(1),
    ));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    session.enable_function_summaries();
    let mut backend = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
    let report = session.run(4096, 16, Some(&mut backend), TIMEOUT, false)?;
    let folded = folded_values(&session, &arena);
    Ok((
        plain_steps,
        report,
        session.function_summary_hits(),
        session.function_summary_builds(),
        folded,
    ))
}

/// The core differential (z3-gated): 50 direct calls to a pure helper
/// collapse into 50 one-step summary applications — same exit value as
/// plain stepping, ~2.5x fewer steps, one build, 50 hits.
#[cfg(all(feature = "z3", target_arch = "x86_64"))]
#[test]
fn repeated_pure_call_differential() -> Result<(), Box<dyn std::error::Error>> {
    let _serial = SOLVER_TESTS.lock().map_err(|e| e.to_string())?;
    let (plain_steps, report, hits, builds, folded) =
        on_deep_stack(|| summarized_run("fnsum-direct", false).map_err(|e| e.to_string()))
            .ok_or("deep-stack thread failed")??;
    assert!(report.terminated >= 1, "summarized run must terminate: {report:?}");
    assert_eq!(
        report.forks, 0,
        "concrete branches must not fork under the solver: {report:?}"
    );
    assert!(
        report.steps * 2 < plain_steps,
        "calls must collapse: summarized {} vs plain {plain_steps}",
        report.steps
    );
    assert!(
        folded.contains(&expected_exit(50)),
        "exit value must match plain stepping: {folded:?}"
    );
    assert_eq!(builds, 1, "one template per argument shape");
    assert_eq!(hits, 50, "one summary hit per collapsed call");
    Ok(())
}

/// The same workload through `call *%rax` — the indirect dispatch shape
/// DriverObject MajorFunction tables use. The folded constant target is
/// summarized exactly like a direct call.
#[cfg(all(feature = "z3", target_arch = "x86_64"))]
#[test]
fn indirect_pure_call_differential() -> Result<(), Box<dyn std::error::Error>> {
    let _serial = SOLVER_TESTS.lock().map_err(|e| e.to_string())?;
    let (plain_steps, report, hits, builds, folded) =
        on_deep_stack(|| summarized_run("fnsum-indirect", true).map_err(|e| e.to_string()))
            .ok_or("deep-stack thread failed")??;
    assert!(report.terminated >= 1, "summarized run must terminate: {report:?}");
    assert!(
        report.steps * 2 < plain_steps,
        "calls must collapse: summarized {} vs plain {plain_steps}",
        report.steps
    );
    assert!(folded.contains(&expected_exit(50)), "exit value: {folded:?}");
    assert_eq!(builds, 1);
    assert_eq!(hits, 50, "indirect calls must summarize too");
    Ok(())
}

/// Solver-less soundness leg: summaries still fire (hits == 50) and some
/// terminated state folds to the exact ground-truth value — correctness
/// never depends on the solver, only the step accounting gets noisy from
/// unsolved-fork phantom states.
#[test]
fn no_solver_run_stays_correct() -> Result<(), Box<dyn std::error::Error>> {
    const ITERS: u64 = 8;
    let elf = build_elf("fnsum-nosolver", &caller_source(false, ITERS)).ok_or("assembler unavailable")?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&elf)?;
    let arena = Arc::new(angryier_expr::ShardedExprArena::new(
        angryier_types::ExpressionNormalizationVersion(1),
    ));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    session.enable_function_summaries();
    // No solver: every `jl` forks (both directions stay enqueued). Eight
    // iterations keeps the fork tree inside the state cap so the real path
    // survives the depth-first drop policy and drains to termination.
    let report = session.run(8192, 16, None, TIMEOUT, false)?;
    assert!(report.terminated >= 1, "must terminate: {report:?}");
    assert_eq!(
        session.function_summary_builds(),
        1,
        "one shared template across all states"
    );
    assert!(
        session.function_summary_hits() >= ITERS,
        "summaries fire without a solver too: {}",
        session.function_summary_hits()
    );
    let values = folded_values(&session, &arena);
    assert!(
        values.contains(&expected_exit(ITERS)),
        "some terminated state must hold the exact ground-truth value: {values:?}"
    );
    Ok(())
}

/// Extraction is white-box checkable: the pure helper is a candidate with
/// the expected depth; the caller (calls, branches, a syscall) is not; a
/// helper that reads memory is not a candidate at all.
#[test]
fn extraction_purity_boundaries() -> Result<(), Box<dyn std::error::Error>> {
    let source = format!(
        r#"
        .global _start
        .text
{COMPUTE_SOURCE}
impure:
        mov %rdi, %rax
        mov snapshot(%rip), %rcx
        add %rcx, %rax
        ret
_start:
        mov $1, %r12d
loop:
        mov %r12, %rdi
        call compute
        add %rax, %rbx
        inc %r12
        cmp $6, %r12
        jl loop
        mov %rbx, %rdi
        mov $60, %rax
        syscall
        .data
snapshot:
        .quad 5
"#
    );
    let elf = build_elf("fnsum-extract", &source).ok_or("assembler unavailable")?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&elf)?;
    let summaries = runtime.function_summaries(&process);
    // Exactly one candidate: the pure helper. Both the caller (call/jcc/
    // syscall) and the memory-reading helper are rejected.
    assert_eq!(summaries.len(), 1, "candidates: {summaries:?}");
    let summary = &summaries[0];
    assert_eq!(summary.insns.len(), 9, "compute body plus ret: {summary:?}");
    assert_eq!(summary.depth, 9);
    assert_eq!(summary.width, 64);
    // The helper reads rdi and its internal rax/rcx chain (rax first as the
    // implicit return input, deduplicated).
    assert!(
        summary.reads.contains(&(register_id::GPR_BASE + 7)),
        "reads: {:?}",
        summary.reads
    );
    let args = summary.arg_registers();
    assert_eq!(args.first(), Some(&RAX), "rax is always argument slot 0");
    assert_eq!(args.iter().filter(|&&r| r == RAX).count(), 1, "rax deduplicated");
    Ok(())
}

/// A callee that reads memory is not summarized: hits stay zero, the run
/// stays exactly correct, and the step count proves the calls really
/// executed. (The helper adds a .data constant, so the ground-truth exit
/// value changes with it.)
#[test]
fn impure_callee_keeps_stepping() -> Result<(), Box<dyn std::error::Error>> {
    let source = r#"
        .global _start
        .text
impure:
        mov %rdi, %rax
        mov snapshot(%rip), %rcx
        add %rcx, %rax
        ret
_start:
        mov $1, %r12d
loop:
        mov %r12, %rdi
        call impure
        add %rax, %rbx
        inc %r12
        cmp $11, %r12
        jl loop
        mov %rbx, %rdi
        mov $60, %rax
        syscall
        .data
snapshot:
        .quad 5
"#;
    let elf = build_elf("fnsum-impure", source).ok_or("assembler unavailable")?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let expected: u64 = (1..=10u64).map(|i| i + 5).sum();

    let mut plain = runtime.load_elf(&elf)?;
    let (plain_exit, _) = run_concrete(&runtime, &mut plain, 8192)?;
    assert_eq!(plain_exit, Some(expected), "plain run ground truth");

    let process = runtime.load_elf(&elf)?;
    let arena = Arc::new(angryier_expr::ShardedExprArena::new(
        angryier_types::ExpressionNormalizationVersion(1),
    ));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    session.enable_function_summaries();
    let report = session.run(8192, 16, None, TIMEOUT, false)?;
    assert!(report.terminated >= 1, "must terminate: {report:?}");
    assert_eq!(
        session.function_summary_hits(),
        0,
        "impure callees must never summarize"
    );
    assert!(report.steps >= 40, "calls must really execute: {report:?}");
    let values: Vec<u64> = session
        .dead
        .iter()
        .filter(|state| state.process.terminated)
        .filter_map(|state| state.registers.get(&(register_id::GPR_BASE + 3)).map(|(expr, _)| *expr))
        .filter_map(|expr| angryier_execution::constant_value(&*arena, expr).ok())
        .collect();
    assert!(
        values.contains(&expected),
        "impure workload must compute the ground-truth result symbolically: {values:?}"
    );
    Ok(())
}

/// The placeholder merge-cost model: depth × width against a budget — small
/// pure helpers summarize, oversized bodies (or a zero budget) fall back to
/// stepping. The trait is the seam; this pins the default heuristic.
#[test]
fn cost_model_gates_by_depth_times_width() {
    use angryier_runtime::function_summaries::{DepthWidthCostModel, FunctionSummary, FunctionSummaryCostModel};

    let summary = |depth: u64| FunctionSummary {
        entry: 0,
        insns: Vec::new(),
        chain_jumps: std::collections::BTreeMap::new(),
        reads: Vec::new(),
        depth,
        width: 64,
    };
    let model = DepthWidthCostModel::default();
    assert!(
        model.should_summarize(&summary(9)),
        "the nine-instruction helper must summarize"
    );
    assert_eq!(model.summary_cost(&summary(9)), 9 * 64);
    assert!(
        model.should_summarize(&summary(64)),
        "64x64 sits exactly at the default budget"
    );
    assert!(!model.should_summarize(&summary(65)), "past the budget: keep stepping");
    let tight = DepthWidthCostModel { max_summary_cost: 0 };
    assert!(!tight.should_summarize(&summary(9)), "a zero budget never summarizes");
    let _ = &summary(1); // Debug bound sanity
}

/// Symbolic argument: the template substitutes the live symbolic expression,
/// the solved model replays to exactly the closed-form prediction, and the
/// symbolic run's own exit value folds to the same number.
#[cfg(all(feature = "z3", target_arch = "x86_64"))]
#[test]
fn symbolic_argument_proves_equivalent() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_expr::ExprReader;
    use angryier_solver_z3::Z3Backend;

    let source = format!(
        r#"
        .global _start
        .text
{COMPUTE_SOURCE}
_start:
        cmp $10, %rbx
        jb out
        cmp $1000, %rbx
        ja out
        mov %rbx, %rdi
        call compute
        mov %rax, %rdi
        mov $60, %rax
        syscall
out:
        xor %rdi, %rdi
        mov $60, %rax
        syscall
"#
    );
    let elf = build_elf("fnsum-symbolic", &source).ok_or("assembler unavailable")?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&elf)?;
    let arena = Arc::new(angryier_expr::ShardedExprArena::new(
        angryier_types::ExpressionNormalizationVersion(1),
    ));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    session.mark_symbolic(0, RBX, angryier_ir::IrType::Bits(64))?;
    session.enable_function_summaries();
    let _serial = SOLVER_TESTS.lock().map_err(|e| e.to_string())?;
    let mut backend = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
    let report = session.run(256, 16, Some(&mut backend), TIMEOUT, false)?;
    assert!(report.terminated >= 1, "must terminate: {report:?}");
    // The call collapsed: the two guard forks + mov + ONE summary step +
    // tail (an unsummarized call would walk the whole helper).
    assert!(report.steps < 24, "call must collapse: {report:?}");
    assert_eq!(session.function_summary_builds(), 1);
    assert_eq!(session.function_summary_hits(), 1);

    // Solve a model that takes the summarized path and replay it concretely.
    let mut model = None;
    for state in session.dead.iter().filter(|s| s.process.terminated) {
        session.states.push(state.clone());
        let index = session.states.len() - 1;
        let bindings = session.solve_state(index, &mut backend, TIMEOUT).unwrap_or_default();
        session.states.pop();
        if let Some(value) = bindings.iter().find(|(r, _)| *r == RBX).map(|(_, v)| *v)
            && (10..=1000).contains(&value)
        {
            model = Some(value);
            break;
        }
    }
    let value = model.ok_or("no model reaches the summarized call")?;

    // Ground truth: the plain engine running the same input.
    let mut replay = runtime.load_elf(&elf)?;
    replay.write_register(RBX, value)?;
    let (exit, replay_steps) = run_concrete(&runtime, &mut replay, 256)?;
    let exit = exit.ok_or("replay did not terminate")?;
    assert_eq!(
        exit,
        compute(value),
        "replayed exit must match the helper's closed form"
    );
    assert!(
        replay_steps >= 14,
        "the replay must really execute the call: {replay_steps}"
    );

    Ok(())
}
