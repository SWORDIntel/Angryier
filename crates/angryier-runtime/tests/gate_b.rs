//! Gate B memory measurement: per-state footprint at 10,000 live states.
//!
//! Memory, not scheduling, is what kills parallel symbolic engines — a worker
//! pool only stays useful while its states stay resident. This benchmark
//! holds the two state regimes the dual-mode engine actually keeps live, at
//! 10,000 states each, and reports resident-set growth per state:
//!
//! * concrete EXPLORE states — the `Process` clones a
//!   [`Runtime::parallel_explore`] pool pins across its workers, forked as a
//!   chain where every descendant writes a distinct value to a distinct
//!   stack offset so copy-on-write pages genuinely diverge;
//! * symbolic PROVE states — a [`SymbolicSession`]'s state vector, each state
//!   a clone of the marked seed carrying its own constraint chain interned
//!   in the shared expression arena.
//!
//! The fixture is assembled and linked at test time with the system binutils
//! (`as` + `ld`). When the toolchain is unavailable the test reports a skip
//! instead of failing.

#![cfg(feature = "xed")]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use angryier_arch_intel64::register_id;
use angryier_expr::{ExprArena, ExprNode, ExprOp, ExprSort, ShardedExprArena};
use angryier_ir::IrType;
use angryier_memory::{ByteValue, LayeredMemory};
use angryier_runtime::{Process, Runtime, SymbolicSession, SymbolicState};
use angryier_types::{ExprId, ExpressionNormalizationVersion, SemanticVersion, TargetProfileId};

/// Live states per regime — the Gate B target.
const STATE_COUNT: usize = 10_000;
/// Path-constraint depth per symbolic state — a mid-depth path.
const CONSTRAINT_DEPTH: u64 = 32;

/// A real Intel 64 program: a compare, a branch, and both exits. Only its
/// load image and constructed stack matter here.
const FIXTURE_SOURCE: &str = r"
    .global _start
    .text
_start:
    cmp $42, %rax
    jne fail_path
    mov $60, %rax
    xor %rdi, %rdi
    syscall
fail_path:
    mov $60, %rax
    mov $1, %rdi
    syscall
";

struct Fixture {
    elf: Vec<u8>,
}

/// Builds the fixture once and shares it across test threads.
fn fixture() -> Option<&'static Fixture> {
    static FIXTURE: std::sync::OnceLock<Option<Fixture>> = std::sync::OnceLock::new();
    FIXTURE.get_or_init(build_fixture).as_ref()
}

/// Assembles and links the fixture into a static ELF64 executable.
///
/// Returns `None` when the binutils toolchain is unavailable or fails.
fn build_fixture() -> Option<Fixture> {
    let dir = temp_dir("angryier-gate-b-fixture")?;
    let source = dir.join("fixture.s");
    let object = dir.join("fixture.o");
    let binary = dir.join("fixture.elf");
    std::fs::write(&source, FIXTURE_SOURCE).ok()?;

    assemble(&source, &object)?;
    link(&binary, &[&object])?;
    let elf = std::fs::read(&binary).ok()?;
    Some(Fixture { elf })
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

/// Resident set size in bytes: the second `/proc/self/statm` field is the
/// resident page count.
fn resident_bytes() -> Result<u64, Box<dyn std::error::Error>> {
    let statm = std::fs::read_to_string("/proc/self/statm")?;
    let field = statm.split_whitespace().nth(1).ok_or("statm missing fields")?;
    let resident_pages: u64 = field.parse()?;
    Ok(resident_pages * 4096)
}

/// Base address of the stack region containing the process's RSP.
fn stack_region_base(process: &Process) -> Result<u64, Box<dyn std::error::Error>> {
    let rsp = process.read_register(register_id::GPR_BASE + 4)?;
    process
        .state
        .memory
        .regions()
        .iter()
        .find(|region| region.contains(rsp))
        .map(|region| region.base)
        .ok_or_else(|| "no mapped region contains rsp".into())
}

/// Builds `count` chained EXPLORE states: each is a clone of its parent with
/// one additional distinct stack write, so descendants diverge from every
/// ancestor (and from each other) instead of sharing pages through Arc alone.
/// This is the shape `parallel_explore` pins in its pool — children fork from
/// parents and keep executing.
///
/// Stride 6 bytes: the 64 KiB stack cannot hold 10,000 disjoint qwords, and
/// the overlapping writes stay inside each state's own page copies.
fn build_concrete_states(seed: &Process, count: usize) -> Result<(Vec<Process>, Duration), Box<dyn std::error::Error>> {
    let stack_base = stack_region_base(seed)?;
    let mut states = Vec::with_capacity(count);
    let started = Instant::now();
    let mut current = seed.clone();
    for i in 0..count {
        if i > 0 {
            let address = stack_base + 6 * i as u64;
            let bytes: Vec<ByteValue> = (i as u64)
                .to_le_bytes()
                .iter()
                .copied()
                .map(ByteValue::Concrete)
                .collect();
            current.state.memory = current.state.memory.write(address, &bytes)?;
        }
        states.push(current.clone());
    }
    let elapsed = started.elapsed();
    Ok((states, elapsed))
}

/// Interns a 64-bit constant into the shared arena.
fn intern_const(arena: &ShardedExprArena, value: u64) -> Result<ExprId, Box<dyn std::error::Error>> {
    arena
        .intern(ExprNode {
            sort: ExprSort::BitVec(64),
            op: ExprOp::Constant,
            operands: Vec::new(),
            immediate: value.to_le_bytes().to_vec(),
        })
        .map_err(Into::into)
}

/// Interns a two-operand node (`Ult` gets `Bool`, arithmetic keeps `BitVec`).
fn intern_binop(
    arena: &ShardedExprArena,
    op: ExprOp,
    sort: ExprSort,
    left: ExprId,
    right: ExprId,
) -> Result<ExprId, Box<dyn std::error::Error>> {
    arena
        .intern(ExprNode {
            sort,
            op,
            operands: vec![left, right],
            immediate: Vec::new(),
        })
        .map_err(Into::into)
}

/// One state's path-constraint chain over the symbolic input register: even
/// positions fold an `Ult` comparison over the running value, odd positions
/// advance it (`x + k == c`, mirroring a concrete loop counter). Constants
/// are keyed to `state_index` so every state interns its own nodes in the
/// shared arena — nothing is shared beyond the input symbol itself.
fn constraint_chain(
    arena: &ShardedExprArena,
    input: ExprId,
    state_index: u64,
    depth: u64,
) -> Result<Vec<ExprId>, Box<dyn std::error::Error>> {
    let mut chain = Vec::with_capacity(depth as usize);
    let mut value = input;
    let mut accumulator: u64 = 0;
    for step in 0..depth {
        let tag = state_index * depth + step;
        if step % 2 == 0 {
            let bound = intern_const(arena, accumulator + (1 << 40) + tag)?;
            let ult = intern_binop(arena, ExprOp::Ult, ExprSort::Bool, value, bound)?;
            chain.push(ult);
        } else {
            let increment = (tag % 97) + 1;
            let offset = intern_const(arena, increment)?;
            let next = intern_binop(arena, ExprOp::Add, ExprSort::BitVec(64), value, offset)?;
            accumulator += increment;
            let total = intern_const(arena, accumulator)?;
            let eq = intern_binop(arena, ExprOp::Eq, ExprSort::Bool, next, total)?;
            chain.push(eq);
            value = next;
        }
    }
    Ok(chain)
}

/// The symbolic input expression bound by `mark_symbolic`.
fn symbolic_input(state: &SymbolicState) -> Result<ExprId, Box<dyn std::error::Error>> {
    state
        .registers
        .get(&register_id::GPR_BASE)
        .map(|(expr, _)| *expr)
        .ok_or_else(|| "mark_symbolic must bind the input register".into())
}

/// Clones `seed` into `count` live PROVE states, each carrying its own
/// constraint chain (see [`constraint_chain`]).
fn build_symbolic_states(
    arena: &ShardedExprArena,
    seed: &SymbolicState,
    input: ExprId,
    count: usize,
) -> Result<(Vec<SymbolicState>, Duration), Box<dyn std::error::Error>> {
    let started = Instant::now();
    let mut states = Vec::with_capacity(count);
    for index in 0..count as u64 {
        let mut state = seed.clone();
        state.id = index;
        state.constraints = constraint_chain(arena, input, index, CONSTRAINT_DEPTH)?;
        states.push(state);
    }
    Ok((states, started.elapsed()))
}

/// Gate B footprint: 10,000 live states in each regime, measured as resident
/// set growth between drop-then-measure boundaries so the regimes cannot
/// contaminate each other. The concrete regime is measured first: since the
/// line-chunked COW rework it is by far the smaller of the two, and the
/// allocator retains the first regime's freed pages, so the second regime's
/// delta is only meaningful beyond that high-water mark. Fork (clone) cost
/// per state is timed for both regimes — the number a scheduler's steal
/// budget has to fit under.
#[test]
#[ignore = "Gate B measurement — run explicitly with --ignored"]
fn gate_b_footprint_10k_states() -> Result<(), Box<dyn std::error::Error>> {
    let Some(fixture) = fixture() else {
        eprintln!("skipping: binutils (as/ld) unavailable");
        return Ok(());
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&fixture.elf)?;
    assert!(
        process.read_register(register_id::GPR_BASE + 4).is_ok(),
        "fixture must load with a stack pointer"
    );

    // Warm the allocator with small rehearsals of both shapes so first-growth
    // page costs do not land on the measured regimes.
    let (rehearsal, _) = build_concrete_states(&process, 100)?;
    drop(rehearsal);
    {
        let warm_arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
        let mut warm = SymbolicSession::new(&runtime, warm_arena.as_ref(), process.clone());
        warm.mark_symbolic(0, register_id::GPR_BASE, IrType::Bits(64))?;
        let warm_seed = warm.states[0].clone();
        let (warm_states, _) =
            build_symbolic_states(warm_arena.as_ref(), &warm_seed, symbolic_input(&warm_seed)?, 100)?;
        warm.states = warm_states;
    }

    // Regime 1: concrete EXPLORE states — measured first because their
    // footprint is the smaller of the two regimes; the allocator retains
    // the first regime's freed pages, so the second regime's delta is only
    // meaningful beyond that high-water mark.
    let concrete_before = resident_bytes()?;
    let (concrete_states, concrete_elapsed) = build_concrete_states(&process, STATE_COUNT)?;
    let concrete_after = resident_bytes()?;
    assert_eq!(concrete_states.len(), STATE_COUNT, "all concrete states must be live");

    // COW divergence is real: a state's last write reads back its own value.
    let probe = 6 * (STATE_COUNT - 1) as u64;
    let base = stack_region_base(&concrete_states[0])?;
    let tail = LayeredMemory::read(&concrete_states[STATE_COUNT - 1].state.memory, base + probe, 8)?;
    let mut observed = 0u64;
    for (index, byte) in tail.iter().enumerate() {
        if let ByteValue::Concrete(byte) = byte {
            observed |= u64::from(*byte) << (8 * index);
        }
    }
    assert_eq!(
        observed,
        (STATE_COUNT - 1) as u64,
        "each state's write must survive in its own copy"
    );

    let concrete_delta = concrete_after.saturating_sub(concrete_before);
    assert!(concrete_delta > 0, "10,000 diverging states must grow the resident set");
    drop(concrete_states);

    // Regime 2: symbolic PROVE states — a SymbolicSession holding one clone
    // of the marked seed per state, each with its own constraint chain,
    // measured only after the concrete states are dropped. The symbolic
    // footprint (~112 MB) far exceeds the pages the allocator retains from
    // the concrete regime, so its delta stays meaningful.
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process.clone());
    session.mark_symbolic(0, register_id::GPR_BASE, IrType::Bits(64))?;
    let seed = session.states[0].clone();
    let input = symbolic_input(&seed)?;

    let symbolic_before = resident_bytes()?;
    let (symbolic_states, symbolic_elapsed) = build_symbolic_states(arena.as_ref(), &seed, input, STATE_COUNT)?;
    session.states = symbolic_states;
    assert_eq!(session.states.len(), STATE_COUNT, "all symbolic states must be live");
    for state in &session.states {
        assert_eq!(
            state.constraints.len(),
            CONSTRAINT_DEPTH as usize,
            "every state keeps a full chain"
        );
    }
    let symbolic_after = resident_bytes()?;
    let arena_nodes = arena.stats().nodes;

    let symbolic_delta = symbolic_after.saturating_sub(symbolic_before);
    assert!(symbolic_delta > 0, "10,000 symbolic states must grow the resident set");
    assert!(arena_nodes > 0, "constraint chains must intern arena nodes");
    drop(session);
    drop(arena);

    let concrete_mb = concrete_delta as f64 / (1024.0 * 1024.0);
    let symbolic_mb = symbolic_delta as f64 / (1024.0 * 1024.0);
    let concrete_per_state_kb = concrete_delta as f64 / (1024.0 * STATE_COUNT as f64);
    let symbolic_per_state_kb = symbolic_delta as f64 / (1024.0 * STATE_COUNT as f64);
    let concrete_fork_us = concrete_elapsed.as_secs_f64() * 1e6 / STATE_COUNT as f64;
    let symbolic_fork_us = symbolic_elapsed.as_secs_f64() * 1e6 / STATE_COUNT as f64;
    println!(
        "GATE-B footprint: concrete {STATE_COUNT} states, RSS +{concrete_mb:.1} MB ({concrete_per_state_kb:.1} KB/state), fork cost {concrete_fork_us:.1} us/state over {concrete_elapsed:.2?}"
    );
    println!(
        "GATE-B footprint: symbolic {STATE_COUNT} states, RSS +{symbolic_mb:.1} MB ({symbolic_per_state_kb:.1} KB/state), arena nodes {arena_nodes}, fork cost {symbolic_fork_us:.1} us/state over {symbolic_elapsed:.2?}"
    );
    println!(
        "GATE-B footprint: concrete {STATE_COUNT} states, RSS +{concrete_mb:.1} MB ({concrete_per_state_kb:.1} KB/state) | symbolic {STATE_COUNT} states, RSS +{symbolic_mb:.1} MB ({symbolic_per_state_kb:.1} KB/state), arena nodes {arena_nodes}"
    );
    Ok(())
}
