//! GATE-A speed measurement: the concolic fast path (EXPLORE) versus the
//! full-symbolic interpreter (PROVE) on a real compiler-generated binary
//! with a long deterministic trace.
//!
//! The fixture is a static, no-libc C program compiled at test time with the
//! system toolchain: an arithmetic loop whose trip count is fixed by an
//! immediate constant (the trace length is input-independent and
//! deterministic) with one data-dependent branch per iteration, terminating
//! in the `exit` syscall. The same loaded image is then run three ways:
//!
//! 1. concrete — plain [`Runtime`] stepping (the speed floor),
//! 2. concolic — [`Runtime::concolic`] with the input register symbolic: the
//!    shadow evaluates every lowered block, branch conditions are recorded
//!    as path constraints, and the solver is never invoked,
//! 3. full symbolic — [`SymbolicSession`] with the same register symbolic,
//!    forking a new state at every conditional branch.
//!
//! The printed `GATE-A speed:` line carries the number the roadmap claims
//! (5-10x): the concolic-versus-full-symbolic multiplier. This is a
//! measurement, not a regression test — it is `#[ignore]`d and must be run
//! with `--ignored --nocapture`.
//!
//! Full symbolic explodes on loops by design (every back edge forks), so its
//! leg runs under a wall-clock cap; when the cap truncates it, the
//! multiplier is extrapolated from the measured prefix rate and labelled as
//! an estimate (conservatively: per-step cost grows with each state's path
//! constraint count, which linear extrapolation ignores).

#![cfg(feature = "xed")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use angryier_arch_intel64::register_id;
use angryier_expr::ShardedExprArena;
use angryier_ir::IrType;
use angryier_runtime::{Runtime, SymbolicSession};
use angryier_types::{ExpressionNormalizationVersion, SemanticVersion, TargetProfileId};

/// A loop-heavy static no-libc C program.
///
/// `_start` stashes the entry RAX into the volatile global `g_input` before
/// calling `run`, so marking RAX symbolic in either engine flows the symbol
/// through the loop arithmetic. The loop bound (`LOOPS`) is an immediate
/// constant, so the dynamic instruction count is the same for every input.
/// The loop body sticks to full-width 64-bit primitives the symbolic
/// evaluator supports (add/sub/xor/shl/shr/imul) — no rotates and no
/// sub-register arithmetic: 8/16/32-bit masks make the compiler emit
/// `movzbl`/32-bit forms the symbolic evaluator refuses. The one
/// data-dependent branch per iteration (`v & 1`) compiles to `test` + `jne`.
/// The exit code is always 0: the input only shapes the branch history,
/// never the result.
const FIXTURE_SOURCE: &str = r#"
#define LOOPS 3000

volatile unsigned long g_input;
volatile unsigned long g_sink;

static unsigned long mix(unsigned long x, unsigned long i) {
    unsigned long h = x ^ (i * 0x9E3779B97F4A7C15UL);
    h ^= h >> 29;
    h *= 0xBF58476D1CE4E5B9UL;
    h ^= h >> 32;
    return h;
}

// The counter starts at 2^32 so the compiler cannot use 32-bit zero-init
// (`xor %ecx,%ecx`), whose narrow symbolic write later poisons 64-bit flag
// expressions in the full-symbolic evaluator.
#define BASE 0x100000000UL

void run(void) {
    unsigned long x = g_input;
    unsigned long acc = x;
    for (unsigned long i = BASE; i < BASE + LOOPS; i++) {
        unsigned long v = mix(x, i);
        if (v & 1UL) {
            acc += (v << 17) ^ (v >> 13);
        } else {
            acc -= (v >> 7) ^ (v << 41);
        }
        acc ^= acc >> 23;
        acc += (v >> 3) + (i >> 1);
    }
    g_sink = acc;
    __asm__ volatile(
        "mov $60, %%rax\n\t"
        "xor %%rdi, %%rdi\n\t"
        "syscall\n\t"
        ::: "rax", "rdi", "memory");
}

__asm__(
    ".global _start\n"
    "_start:\n"
    "    movq %rax, g_input(%rip)\n"
    "    call run\n"
    "    mov $60, %rax\n"
    "    xor %rdi, %rdi\n"
    "    syscall\n");
"#;

/// Optimization level for the fixture build. `-O2` keeps the data-dependent
/// branch as `test` + `jne` on this toolchain (verified by disassembly);
/// the loop body stays free of rotates and other symbolic gaps.
const FIXTURE_OPT: &str = "-O2";

/// Step budget for the concrete and concolic legs — far above the expected
/// trace length so `StepLimitExceeded` only fires on a broken fixture.
const STEP_BUDGET: u64 = 2_000_000;

/// Wall-clock cap for the full-symbolic leg.
const SYMBOLIC_TIME_CAP: Duration = Duration::from_secs(20);

/// Full-symbolic chunk size: the session is run in budget slices so the
/// wall cap is checked between slices.
const SYMBOLIC_CHUNK: u64 = 4_096;

/// Live-state cap for the full-symbolic run (state economics: the engine
/// drops the highest-cost state whenever the cap is exceeded).
const SYMBOLIC_MAX_STATES: usize = 32;

/// Measurement floor: below this the trace is too short to be meaningful.
const MIN_STEPS: u64 = 50_000;

/// Concrete seed for the input register; shapes the branch history only.
const SEED: u64 = 0x00C0_FFEE_1234_5678;

/// Compiles [`FIXTURE_SOURCE`] into a static ELF64 executable.
///
/// Returns `None` when the C toolchain is unavailable or the build fails.
fn build_fixture() -> Option<(Vec<u8>, PathBuf)> {
    build_fixture_from(FIXTURE_SOURCE, "angryier-gatea-speed")
}

/// Compiles `source` into a static ELF64 executable under `name`.
fn build_fixture_from(source_text: &str, name: &str) -> Option<(Vec<u8>, PathBuf)> {
    let dir = temp_dir(name)?;
    let source = dir.join("looptrace.c");
    let binary = dir.join("looptrace.elf");
    std::fs::write(&source, source_text).ok()?;

    let compiled = Command::new("cc")
        .arg(FIXTURE_OPT)
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

/// Runs the fixture natively and returns its exit code.
fn native_exit(binary: &Path) -> Option<i32> {
    Command::new(binary).status().ok()?.code()
}

fn temp_dir(name: &str) -> Option<PathBuf> {
    let dir = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

/// GATE-A: measures concrete vs concolic (EXPLORE) vs full-symbolic (PROVE)
/// stepping speed on the same long real trace.
#[test]
#[ignore = "speed measurement (GATE-A): run with --ignored --nocapture"]
fn concolic_speed_vs_full_symbolic_on_long_trace() -> Result<(), Box<dyn std::error::Error>> {
    let Some((elf, native_path)) = build_fixture() else {
        eprintln!("skipping: C toolchain (cc/ld) unavailable");
        return Ok(());
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let input_register = register_id::GPR_BASE; // RAX — stashed to g_input by _start

    // A native control run: the fixture must exit 0 on real hardware before
    // any engine claim is made.
    match native_exit(&native_path) {
        Some(code) => assert_eq!(code, 0, "native run of the fixture must exit 0"),
        None => eprintln!("skipping native exit-code check: fixture could not be executed"),
    }

    // ------------------------------------------------------------------
    // Leg 1: concrete — the speed floor.
    // ------------------------------------------------------------------
    let mut concrete = runtime.load_elf(&elf)?;
    concrete.write_register(input_register, SEED)?;
    let concrete_start = Instant::now();
    runtime.run(&mut concrete, STEP_BUDGET)?;
    let concrete_elapsed = concrete_start.elapsed();
    let concrete_steps = concrete.step_count;
    let concrete_exit = concrete.syscalls.exit_code();

    // ------------------------------------------------------------------
    // Leg 2: concolic (EXPLORE) — shadow evaluation on every block, solver
    // never invoked during stepping.
    // ------------------------------------------------------------------
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut process = runtime.load_elf(&elf)?;
    process.write_register(input_register, SEED)?;
    let mut session = runtime.concolic(process, arena.as_ref());
    session.mark_input_register(input_register, IrType::Bits(64))?;
    let concolic_start = Instant::now();
    session.run(STEP_BUDGET)?;
    let concolic_elapsed = concolic_start.elapsed();
    let concolic_steps = session.process.step_count;
    let concolic_exit = session.process.syscalls.exit_code();
    let path_constraints = session.path_constraints().len();
    let shadow_debt = session.requires_prove();

    // ------------------------------------------------------------------
    // Leg 3: full symbolic (PROVE) — same input marked symbolic, one
    // instruction per step like the other legs, forking at every
    // conditional branch, run in slices under a wall-clock cap.
    // ------------------------------------------------------------------
    let sym_arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut process = runtime.load_elf(&elf)?;
    process.write_register(input_register, SEED)?;
    let mut symbolic = SymbolicSession::new(&runtime, sym_arena.as_ref(), process);
    symbolic.mark_symbolic(0, input_register, IrType::Bits(64))?;
    let symbolic_start = Instant::now();
    let mut sym_steps = 0u64;
    let mut forks = 0u64;
    let mut peak_states = 0u64;
    let mut terminated_states = 0u64;
    let mut failed_states = 0u64;
    let mut live_states = 1u64;
    while sym_steps < concolic_steps {
        if symbolic_start.elapsed() >= SYMBOLIC_TIME_CAP {
            break;
        }
        let budget = SYMBOLIC_CHUNK.min(concolic_steps - sym_steps);
        let report = symbolic.run(budget, SYMBOLIC_MAX_STATES, None, Duration::from_secs(1), false)?;
        sym_steps += report.steps;
        forks += report.forks;
        peak_states = peak_states.max(report.peak_states);
        terminated_states += report.terminated;
        failed_states += report.failed;
        live_states = report.live_states;
        if report.steps == 0 || symbolic.states.is_empty() {
            break;
        }
    }
    let symbolic_elapsed = symbolic_start.elapsed();

    // ------------------------------------------------------------------
    // Report.
    // ------------------------------------------------------------------
    let ms = |elapsed: Duration| elapsed.as_secs_f64() * 1_000.0;
    let rate = |steps: u64, elapsed: Duration| steps as f64 / ms(elapsed).max(1e-9);

    let concrete_ms = ms(concrete_elapsed);
    let concolic_ms = ms(concolic_elapsed);
    let symbolic_ms = ms(symbolic_elapsed);
    let trace = concolic_steps;
    let overhead = concolic_ms / concrete_ms.max(1e-9);

    // The multiplier the roadmap cares about. When the symbolic leg ran the
    // whole matched budget it is direct; otherwise extrapolate linearly
    // from the measured prefix rate and label it an estimate.
    let completed = sym_steps >= concolic_steps;
    let multiplier = if completed {
        symbolic_ms / concolic_ms.max(1e-9)
    } else {
        (trace as f64 / rate(sym_steps, symbolic_elapsed)) / concolic_ms.max(1e-9)
    };

    println!(
        "GATE-A speed: trace {trace} steps | concrete {concrete_ms:.1} ms ({:.1} steps/ms) | \
         concolic {concolic_ms:.1} ms ({:.1} steps/ms, {overhead:.2}x concrete) | \
         full-symbolic {symbolic_ms:.1} ms ({:.1} steps/ms) | \
         concolic-vs-symbolic multiplier {multiplier:.1}x",
        rate(concrete_steps, concrete_elapsed),
        rate(concolic_steps, concolic_elapsed),
        rate(sym_steps, symbolic_elapsed),
    );
    println!(
        "GATE-A fixture: cc {FIXTURE_OPT}, LOOPS=3000 immediate bound, seed RAX={SEED:#x}, \
         one data-dependent branch per iteration"
    );
    println!(
        "GATE-A concolic detail: {path_constraints} path constraints recorded, \
         shadow debt (requires_prove) = {shadow_debt}, solver calls during stepping = 0"
    );
    println!(
        "GATE-A full-symbolic detail: {sym_steps}/{trace} budget steps consumed, {forks} forks, \
         peak {peak_states} live states, {terminated_states} terminated, {failed_states} failed, \
         {live_states} live at stop, max_states cap = {SYMBOLIC_MAX_STATES}"
    );
    if completed {
        println!(
            "GATE-A multiplier basis: direct — full symbolic consumed the full {trace}-step \
             budget in {symbolic_ms:.1} ms vs concolic {concolic_ms:.1} ms"
        );
    } else {
        let reason = if symbolic.states.is_empty() {
            format!("all states died or terminated after {sym_steps} steps")
        } else {
            format!("wall cap of {}s reached", SYMBOLIC_TIME_CAP.as_secs())
        };
        println!(
            "GATE-A multiplier basis: ESTIMATE — full symbolic stopped early ({reason}); \
             extrapolated linearly from the {sym_steps}-step prefix rate ({:.1} steps/ms). \
             Conservative: per-step cost grows with each state's path-constraint count, \
             which linear extrapolation ignores.",
            rate(sym_steps, symbolic_elapsed)
        );
    }

    // ------------------------------------------------------------------
    // Sanity only: the measurement itself is reported, not asserted.
    // ------------------------------------------------------------------
    assert!(concrete.terminated, "concrete run must terminate via the exit syscall");
    assert!(
        session.process.terminated,
        "concolic run must terminate via the exit syscall"
    );
    assert_eq!(
        concrete_exit, concolic_exit,
        "concolic and concrete runs must agree on the exit code"
    );
    assert_eq!(concrete_exit, Some(0), "the fixture always exits 0");
    assert_eq!(
        concrete_steps, concolic_steps,
        "same seed must produce the same deterministic trace"
    );
    assert!(
        concrete_steps >= MIN_STEPS,
        "trace too short to measure: {concrete_steps} steps (floor {MIN_STEPS})"
    );
    assert!(concrete_elapsed.as_secs_f64() > 0.0, "concrete time must be nonzero");
    assert!(concolic_elapsed.as_secs_f64() > 0.0, "concolic time must be nonzero");
    assert!(
        symbolic_elapsed.as_secs_f64() > 0.0,
        "full-symbolic time must be nonzero"
    );
    assert!(sym_steps > 0, "full-symbolic leg must have stepped at least once");
    Ok(())
}

/// Sparse-influence counterpart to the dense fixture above: the input
/// register flows through exactly two operations (the `_start` stash and
/// one final xor) while thousands of loop iterations of constant-derived
/// arithmetic never touch it. This is the shape real target programs have
/// between input uses, and it is where the concolic fast path (skip shadow
/// evaluation of uninfluenced blocks) pays: the measurable is concolic
/// overhead versus the concrete floor, not the concolic-vs-symbolic
/// multiplier (full symbolic on this shape degenerates into fork
/// management, which the dense fixture already prices).
const SPARSE_SOURCE: &str = r#"
#define LOOPS 3000

volatile unsigned long g_input;
volatile unsigned long g_sink;

static unsigned long mix(unsigned long x, unsigned long i) {
    unsigned long h = x ^ (i * 0x9E3779B97F4A7C15UL);
    h ^= h >> 29;
    h *= 0xBF58476D1CE4E5B9UL;
    h ^= h >> 32;
    return h;
}

#define BASE 0x100000000UL

void run(void) {
    unsigned long acc = 7;
    for (unsigned long i = BASE; i < BASE + LOOPS; i++) {
        unsigned long v = mix(i, i);
        acc += (v << 3) ^ (v >> 5);
        acc ^= acc >> 17;
    }
    g_sink = acc ^ g_input;
    __asm__ volatile("mov $60, %%rax\n\txor %%rdi, %%rdi\n\tsyscall\n\t" ::: "rax", "rdi", "memory");
}

__asm__(
    ".global _start\n"
    "_start:\n"
    "    movq %rax, g_input(%rip)\n"
    "    call run\n"
    "    mov $60, %rax\n"
    "    xor %rdi, %rdi\n"
    "    syscall\n");
"#;

/// GATE-A sparse leg: concrete vs concolic on a trace the input barely
/// influences. The fast path should keep concolic near the concrete floor
/// and record zero path constraints (no symbolic branch exists).
#[test]
#[ignore = "speed measurement (GATE-A sparse): run with --ignored --nocapture"]
fn concolic_sparse_influence_tracks_concrete_floor() -> Result<(), Box<dyn std::error::Error>> {
    let Some((elf, native_path)) = build_fixture_from(SPARSE_SOURCE, "angryier-gatea-sparse") else {
        eprintln!("skipping: C toolchain (cc/ld) unavailable");
        return Ok(());
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let input_register = register_id::GPR_BASE; // RAX — stashed to g_input by _start

    match native_exit(&native_path) {
        Some(code) => assert_eq!(code, 0, "native run of the sparse fixture must exit 0"),
        None => eprintln!("skipping native exit-code check: fixture could not be executed"),
    }

    let mut concrete = runtime.load_elf(&elf)?;
    concrete.write_register(input_register, SEED)?;
    let concrete_start = Instant::now();
    runtime.run(&mut concrete, STEP_BUDGET)?;
    let concrete_elapsed = concrete_start.elapsed();
    let concrete_steps = concrete.step_count;

    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut process = runtime.load_elf(&elf)?;
    process.write_register(input_register, SEED)?;
    let mut session = runtime.concolic(process, arena.as_ref());
    session.mark_input_register(input_register, IrType::Bits(64))?;
    let concolic_start = Instant::now();
    session.run(STEP_BUDGET)?;
    let concolic_elapsed = concolic_start.elapsed();
    let concolic_steps = session.process.step_count;
    let path_constraints = session.path_constraints().len();

    let ms = |elapsed: Duration| elapsed.as_secs_f64() * 1_000.0;
    let rate = |steps: u64, elapsed: Duration| steps as f64 / ms(elapsed).max(1e-9);
    let overhead = ms(concolic_elapsed) / ms(concrete_elapsed).max(1e-9);

    println!(
        "GATE-A sparse: trace {concolic_steps} steps | concrete {:.1} ms ({:.1} steps/ms) | \
         concolic {:.1} ms ({:.1} steps/ms, {overhead:.2}x concrete) | \
         path constraints {path_constraints} | arena nodes {} (distinct folded constants only)",
        ms(concrete_elapsed),
        rate(concrete_steps, concrete_elapsed),
        ms(concolic_elapsed),
        rate(concolic_steps, concolic_elapsed),
        arena.stats().nodes,
    );
    println!(
        "GATE-A sparse fixture: cc {FIXTURE_OPT}, LOOPS=3000 constant-derived arithmetic, \
         input consulted once at the end (fast-path shape)"
    );

    assert!(concrete.terminated && session.process.terminated);
    assert_eq!(
        concrete.syscalls.exit_code(),
        session.process.syscalls.exit_code(),
        "concolic and concrete runs must agree on the exit code"
    );
    assert_eq!(concrete_steps, concolic_steps, "same seed must give the same trace");
    assert!(
        concrete_steps >= MIN_STEPS,
        "trace too short to measure: {concrete_steps} steps"
    );
    assert_eq!(
        path_constraints, 0,
        "no branch in this trace is input-derived; the shadow must record nothing"
    );
    Ok(())
}
