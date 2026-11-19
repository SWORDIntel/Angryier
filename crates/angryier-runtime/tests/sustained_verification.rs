//! Independent executable checks of lossless trace, replay ownership and unresolved outcomes.
#![cfg(all(feature = "xed", feature = "script", target_arch = "x86_64"))]
#![allow(clippy::expect_used)]
use angryier_arch_intel64::register_id;
use angryier_distribution::contracts::{CampaignArtifacts, CampaignManifest, CampaignSpec, Digest, ExplorationLimits};
use angryier_expr::ShardedExprArena;
use angryier_ir::IrType;
use angryier_runtime::{
    Runtime, SymbolicSession, SymbolicStepOutcome,
    sustained::{SustainedCampaign, SustainedError},
};
use angryier_solver::{SolverBackend, SolverOutcomeKind, SolverQuery, SolverResult};
use angryier_types::{ExpressionNormalizationVersion, FidelityProfile, SemanticVersion, TargetProfileId};
use std::{
    path::PathBuf,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

static NEXT: AtomicU64 = AtomicU64::new(0);
const BRANCH: &str = ".global _start\n.text\n_start:\n cmp $5, %rbx\n je equal\n mov $1, %rdi\n jmp exit\nequal:\n xor %rdi, %rdi\nexit:\n mov $60, %rax\n syscall\n";
const LONG_BRANCHES: &str = ".global _start\n.text\n_start:\n .rept 65\n cmp $5, %rbx\n je 1f\n nop\n1:\n .endr\n mov $60, %rax\n xor %rdi, %rdi\n syscall\n";
const LONG_TRACE: &str =
    ".global _start\n.text\n_start:\n .rept 4100\n nop\n .endr\n mov $60, %rax\n xor %rdi, %rdi\n syscall\n";
struct Fixture {
    dir: PathBuf,
    elf: Vec<u8>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
fn fixture(source: &str) -> Fixture {
    let dir = std::env::temp_dir().join(format!(
        "angryier-adversarial-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&dir).expect("create fixture");
    let asm = dir.join("test.s");
    let obj = dir.join("test.o");
    let elf = dir.join("test.elf");
    std::fs::write(&asm, source).expect("write assembler source");
    for (tool, args) in [
        (
            "as",
            vec![
                "--64",
                "-o",
                obj.to_str().expect("object"),
                asm.to_str().expect("assembly"),
            ],
        ),
        (
            "ld",
            vec!["-o", elf.to_str().expect("ELF"), obj.to_str().expect("object")],
        ),
    ] {
        let result = Command::new(tool)
            .args(args)
            .output()
            .expect("assembler/linker required for e2e verification");
        assert!(
            result.status.success(),
            "{tool}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    Fixture {
        elf: std::fs::read(elf).expect("read ELF"),
        dir,
    }
}
fn runtime() -> Runtime<angryier_runtime::XedFormTranslator<angryier_arch_xed_ffi::XedDecoder>> {
    Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1))
}
fn limits(cap: u64, steps: u64) -> ExplorationLimits {
    ExplorationLimits {
        max_steps: steps,
        max_path_steps: 128,
        max_active_states: cap,
        max_path_depth: 128,
        max_loop_visits: 128,
        max_solver_millis: 10_000,
        max_wall_millis: 30_000,
        max_ram_bytes: 64 * 1024 * 1024,
        max_disk_bytes: 1024 * 1024,
        max_trace_bytes: 1024 * 1024,
    }
}
fn artifacts(elf: &[u8]) -> CampaignArtifacts<'_> {
    CampaignArtifacts {
        binary: elf,
        semantic_profile: b"native-xed",
        script: b"driver",
        policy: b"policy",
        solver_policy: b"mock",
        inputs: vec![],
        stubs: vec![],
    }
}
fn manifest(elf: &[u8], pc: u64, cap: u64, steps: u64, backend: &str) -> CampaignManifest {
    CampaignManifest::seal(CampaignSpec {
        binary_digest: Digest::of(elf),
        architecture: "x86_64".into(),
        entry_pc: pc,
        semantic_version: "1".into(),
        semantic_profile_digest: Digest::of(b"native-xed"),
        script_digest: Digest::of(b"driver"),
        policy_digest: Digest::of(b"policy"),
        inputs: vec![],
        stubs: vec![],
        solver_version: backend.into(),
        solver_policy_digest: Digest::of(b"mock"),
        fidelity: FidelityProfile::Prove,
        limits: limits(cap, steps),
    })
    .expect("campaign")
}
struct Answers {
    outcomes: Vec<SolverOutcomeKind>,
    calls: usize,
}
impl Answers {
    fn new(outcomes: Vec<SolverOutcomeKind>) -> Self {
        Self { outcomes, calls: 0 }
    }
}
impl SolverBackend for Answers {
    fn name(&self) -> &'static str {
        "adversarial"
    }
    fn solve(&mut self, _: &SolverQuery) -> SolverResult {
        let outcome = self.outcomes.get(self.calls).copied().unwrap_or(SolverOutcomeKind::Sat);
        self.calls += 1;
        SolverResult {
            outcome,
            model: vec![],
            unsat_core: vec![],
            elapsed: Duration::ZERO,
        }
    }
    fn solve_batch(&mut self, _: &[angryier_types::ConstraintId], predicates: &[SolverQuery]) -> Vec<SolverResult> {
        predicates.iter().map(|q| self.solve(q)).collect()
    }
}

#[test]
fn executed_process_trace_remains_exact_past_4096() -> Result<(), Box<dyn std::error::Error>> {
    let f = fixture(LONG_TRACE);
    let runtime = runtime();
    let mut process = runtime.load_elf(&f.elf)?;
    let entry = process.pc()?;
    let result = runtime.run(&mut process, 4200)?;
    assert!(process.terminated, "execution did not reach exit: {result:?}");
    assert!(
        process.trace.len() >= 4100,
        "trace silently truncated: {}",
        process.trace.len()
    );
    assert_eq!(process.trace[0], entry);
    assert_eq!(process.trace[4096], entry + 4096);
    assert_eq!(process.trace[4099], entry + 4099);
    Ok(())
}

#[test]
fn symbolic_branch_history_retains_65_real_decisions() -> Result<(), Box<dyn std::error::Error>> {
    let f = fixture(LONG_BRANCHES);
    let runtime = runtime();
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), runtime.load_elf(&f.elf)?);
    session.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let mut forks = 0;
    for _ in 0..250 {
        if forks == 65 {
            break;
        }
        match session.step_state(0)? {
            SymbolicStepOutcome::Branched { .. } => {
                assert_eq!(session.states.len(), 2, "a symbolic fork must create both edges");
                session.states.pop(); // Keep the first branch direction on this one inspected path.
                forks += 1;
            }
            SymbolicStepOutcome::Terminated => return Err("terminated before all 65 branches".into()),
            SymbolicStepOutcome::Stepped { .. } => {}
        }
    }
    assert_eq!(forks, 65, "did not actually execute all symbolic branches");
    let state = &session.states[0];
    assert_eq!(
        state.branch_history.len(),
        65,
        "history must not silently discard the first fork"
    );
    assert_eq!(state.branch_history[0].prefix_constraints, 0);
    assert_eq!(state.branch_history[64].prefix_constraints, 64);
    assert!(state.branch_history.iter().all(|d| d.visit_index_exact));
    assert!(state.process.trace.len() >= 130);
    Ok(())
}

#[test]
fn mixed_unknown_and_active_cap_recover_without_double_ownership() -> Result<(), Box<dyn std::error::Error>> {
    let f = fixture(BRANCH);
    let runtime = runtime();
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), runtime.load_elf(&f.elf)?);
    session.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let initial = session.sustained_initial_digest()?;
    let pc = session.states[0].process.pc()?;
    let m = manifest(&f.elf, pc, 1, 64, "adversarial");
    let path = f.dir.join("mixed.ledger");
    let mut campaign = SustainedCampaign::open(&path, m.clone(), &artifacts(&f.elf), initial)?;
    let mut solver = Answers::new(vec![SolverOutcomeKind::Sat, SolverOutcomeKind::Unknown]);
    let first = session.run_sustained(&mut campaign, &mut solver, Duration::from_secs(10))?;
    assert_eq!(solver.calls, 2, "both fork directions must be queried");
    assert_eq!(first.ledger.retired_splits, 1);
    assert_eq!(
        (first.ledger.deferred, first.ledger.unknown, first.ledger.completed),
        (1, 1, 0)
    );
    assert!(!first.ledger.complete_within_declared_bounds);
    assert_eq!(first.evidence.report().summary.retained_frontier, 2);
    drop(campaign);
    let mut reopened = SustainedCampaign::open(&path, m.clone(), &artifacts(&f.elf), initial)?;
    assert_eq!(reopened.report().deferred, 1);
    assert_eq!(reopened.report().unknown, 1);
    reopened.retry_deferred()?;
    assert_eq!(reopened.report().queued, 2);
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), runtime.load_elf(&f.elf)?);
    session.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let resumed = session.run_sustained(&mut reopened, &mut Answers::new(vec![]), Duration::from_secs(10))?;
    assert_eq!(
        resumed.ledger.completed, 2,
        "both disjoint edges must replay and terminate"
    );
    assert_eq!(
        resumed.ledger.retired_splits, 1,
        "no duplicate fork ownership on resume"
    );
    assert!(resumed.ledger.complete_within_declared_bounds);
    Ok(())
}

#[test]
fn timeout_dirty_frontier_and_mismatched_or_corrupt_restart_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let f = fixture(BRANCH);
    let runtime = runtime();
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), runtime.load_elf(&f.elf)?);
    session.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let initial = session.sustained_initial_digest()?;
    let m = manifest(&f.elf, session.states[0].process.pc()?, 1, 64, "adversarial");
    let path = f.dir.join("timeout.ledger");
    let mut campaign = SustainedCampaign::open(&path, m.clone(), &artifacts(&f.elf), initial)?;
    let timed = session.run_sustained(&mut campaign, &mut Answers::new(vec![]), Duration::ZERO)?;
    assert_eq!((timed.ledger.deferred, timed.ledger.completed), (1, 0));
    assert_eq!(timed.evidence.report().summary.retained_frontier, 1);
    assert!(!timed.ledger.complete_within_declared_bounds);
    drop(campaign);
    let mut changed = m.clone();
    changed.spec.limits.max_active_states = 2;
    changed = CampaignManifest::seal(changed.spec)?;
    assert!(matches!(
        SustainedCampaign::open(&path, changed, &artifacts(&f.elf), initial),
        Err(SustainedError::Ledger(
            angryier_ledger::sustained::Error::MismatchedCampaign
        ))
    ));
    assert_eq!(
        SustainedCampaign::open(&path, m.clone(), &artifacts(&f.elf), initial)?
            .report()
            .deferred,
        1
    );
    std::fs::write(&path, b"corrupt frontier").expect("corrupt isolated fixture only");
    assert!(matches!(
        SustainedCampaign::open(&path, m, &artifacts(&f.elf), initial),
        Err(SustainedError::Ledger(angryier_ledger::sustained::Error::Corrupt))
    ));
    Ok(())
}

#[test]
fn preexisting_merge_is_rejected_before_reserving_root() -> Result<(), Box<dyn std::error::Error>> {
    let f = fixture(BRANCH);
    let runtime = runtime();
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), runtime.load_elf(&f.elf)?);
    let initial = session.sustained_initial_digest()?;
    let m = manifest(&f.elf, session.states[0].process.pc()?, 2, 64, "adversarial");
    let path = f.dir.join("merge.ledger");
    let mut campaign = SustainedCampaign::open(&path, m, &artifacts(&f.elf), initial)?;
    session.pending_merges.push((1, 2, 0));
    assert!(matches!(
        session.run_sustained(&mut campaign, &mut Answers::new(vec![]), Duration::from_secs(5)),
        Err(SustainedError::UnreplayableEnvironment(_))
    ));
    assert_eq!(campaign.report().queued, 1);
    assert_eq!(campaign.report().retired_splits, 0);
    Ok(())
}

#[test]
fn lua_rejects_mutated_root_and_unsupported_script_on_resume() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_runtime::mlua::{Lua, ObjectLike, Table};
    let f = fixture(BRANCH);
    let lua = Lua::new();
    angryier_runtime::script::register(&lua)?;
    let opts = lua.create_table()?;
    let ledger = f.dir.join("lua.ledger");
    opts.set("ledger", ledger.to_str().expect("ledger path"))?;
    opts.set("fidelity", "prove")?;
    let symbolic = lua.create_table()?;
    symbolic.set("rbx", 64)?;
    opts.set("symbolic", symbolic.clone())?;
    let artifacts = lua.create_table()?;
    artifacts.set("script", "angry.sustained/v1")?;
    artifacts.set("policy", "fork-all/v1")?;
    artifacts.set("solver_policy", "z3-default")?;
    opts.set("artifacts", artifacts.clone())?;
    let bounds = lua.create_table()?;
    for (key, value) in [
        ("max_steps", 64),
        ("max_path_steps", 64),
        ("max_active_states", 1),
        ("max_path_depth", 64),
        ("max_loop_visits", 64),
        ("max_solver_millis", 10_000),
        ("max_wall_millis", 30_000),
        ("max_ram_bytes", 64 * 1024 * 1024),
        ("max_disk_bytes", 1024 * 1024),
        ("max_trace_bytes", 1024 * 1024),
    ] {
        bounds.set(key, value)?;
    }
    opts.set("limits", bounds)?;
    let sustained: Table = lua.globals().get::<Table>("angry")?.get("sustained")?;
    let start: angryier_runtime::mlua::Function = sustained.get("start")?;
    let resume: angryier_runtime::mlua::Function = sustained.get("resume")?;
    let image = f.dir.join("test.elf");
    let image = image.to_str().expect("image path");
    assert!(
        format!(
            "{:?}",
            resume
                .call::<angryier_runtime::mlua::AnyUserData>((image, opts.clone()))
                .expect_err("missing ledger must not initialize on resume")
        )
        .contains("does not exist")
    );
    let handle: angryier_runtime::mlua::AnyUserData = start.call((image, opts.clone()))?;
    symbolic.set("rbx", angryier_runtime::mlua::Value::Nil)?;
    let changed_root = handle
        .call_method::<Table>("advance", ())
        .expect_err("changed root must not execute a pinned campaign");
    assert!(
        format!("{changed_root:?}").contains("sustained: options changed after start/resume"),
        "mutated options must be rejected before executing a pinned campaign: {changed_root:?}"
    );
    symbolic.set("rbx", 64)?;
    let report: Table = handle.call_method("report", ())?;
    assert_eq!(
        report.get::<usize>("queued")?,
        1,
        "rejected root must not consume ownership"
    );
    drop(handle);
    lua.gc_collect()?; // mlua userdata retains the ledger lock until GC.
    artifacts.set("script", "unimplemented-script-v2")?;
    let error = resume
        .call::<angryier_runtime::mlua::AnyUserData>((image, opts))
        .expect_err("unimplemented script cannot resume old campaign");
    assert!(
        format!("{error:?}").contains("script execution is unsupported"),
        "{error:?}"
    );
    Ok(())
}
