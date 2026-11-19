//! Real ELF64 sustained-campaign integration tests for disjoint subtree replay
//! and durable unresolved-work accounting.
#![cfg(all(feature = "xed", feature = "script", target_arch = "x86_64"))]
#![allow(clippy::expect_used)]

use std::{
    path::PathBuf,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use angryier_arch_intel64::register_id;
use angryier_distribution::contracts::{CampaignArtifacts, CampaignManifest, CampaignSpec, Digest, ExplorationLimits};
use angryier_expr::{ExprReader, ShardedExprArena};
use angryier_ir::IrType;
use angryier_runtime::{Runtime, SymbolicSession, sustained::SustainedCampaign};
use angryier_solver::{SolverBackend, SolverOutcomeKind, SolverQuery, SolverResult};
use angryier_solver_z3::Z3Backend;
use angryier_types::{ExpressionNormalizationVersion, FidelityProfile, SemanticVersion, TargetProfileId};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
const DOUBLE_SOURCE: &str = r#"
    .global _start
    .text
_start:
    cmp $5, %rbx
    je equal
    cmp $6, %rbx
    je other
    mov $1, %rdi
    jmp exit
other:
    mov $2, %rdi
    jmp exit
equal:
    xor %rdi, %rdi
exit:
    mov $60, %rax
    syscall
"#;
const SOURCE: &str = r#"
    .global _start
    .text
_start:
    cmp $5, %rbx
    je equal
    mov $60, %rax
    mov $1, %rdi
    syscall
equal:
    mov $60, %rax
    xor %rdi, %rdi
    syscall
"#;

struct Fixture {
    dir: PathBuf,
    elf: Vec<u8>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    fixture_with_source(SOURCE)
}

fn fixture_with_source(source_text: &str) -> Result<Fixture, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "angryier-sustained-{}-{}",
        std::process::id(),
        NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&dir).expect("create isolated fixture directory");
    let source = dir.join("branch.s");
    let object = dir.join("branch.o");
    let binary = dir.join("branch.elf");
    std::fs::write(&source, source_text).expect("write assembler fixture");
    for (program, args) in [
        (
            "as",
            vec![
                "--64",
                "-o",
                object.to_str().expect("object path"),
                source.to_str().expect("source path"),
            ],
        ),
        (
            "ld",
            vec![
                "-o",
                binary.to_str().expect("binary path"),
                object.to_str().expect("object path"),
            ],
        ),
    ] {
        let output = Command::new(program)
            .args(args)
            .output()
            .map_err(|error| std::io::Error::new(error.kind(), format!("failed to invoke {program}: {error}")))?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "{program} failed ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ))
            .into());
        }
    }
    Ok(Fixture {
        elf: std::fs::read(binary).expect("read linked executable"),
        dir,
    })
}

fn limits(max_steps: u64) -> ExplorationLimits {
    ExplorationLimits {
        max_steps,
        max_path_steps: 64,
        max_active_states: 2,
        max_path_depth: 64,
        max_loop_visits: 64,
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
        semantic_profile: b"native-xed-v1",
        script: b"no-script",
        policy: b"no-policy",
        solver_policy: b"z3-default",
        inputs: vec![],
        stubs: vec![],
    }
}

fn manifest(elf: &[u8], entry_pc: u64, max_steps: u64) -> CampaignManifest {
    CampaignManifest::seal(CampaignSpec {
        binary_digest: Digest::of(elf),
        architecture: "x86_64".into(),
        entry_pc,
        semantic_version: "1".into(),
        semantic_profile_digest: Digest::of(b"native-xed-v1"),
        script_digest: Digest::of(b"no-script"),
        policy_digest: Digest::of(b"no-policy"),
        inputs: vec![],
        stubs: vec![],
        solver_version: "z3".into(),
        solver_policy_digest: Digest::of(b"z3-default"),
        fidelity: FidelityProfile::Prove,
        limits: limits(max_steps),
    })
    .expect("valid campaign specification")
}

struct UnknownBackend;
impl SolverBackend for UnknownBackend {
    fn name(&self) -> &'static str {
        "unknown"
    }
    fn solve(&mut self, _: &SolverQuery) -> SolverResult {
        SolverResult {
            outcome: SolverOutcomeKind::Unknown,
            model: vec![],
            unsat_core: vec![],
            elapsed: Duration::ZERO,
        }
    }
    fn solve_batch(&mut self, _: &[angryier_types::ConstraintId], predicates: &[SolverQuery]) -> Vec<SolverResult> {
        predicates.iter().map(|query| self.solve(query)).collect()
    }
}

#[test]
fn symbolic_branch_splits_and_replays_both_children_across_reopen() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&fixture.elf)?;
    let entry = process.pc()?;
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    session.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let manifest = manifest(&fixture.elf, entry, 64);
    let initial = session.sustained_initial_digest()?;
    let path = fixture.dir.join("campaign.ledger");
    let mut campaign = SustainedCampaign::open(&path, manifest.clone(), &artifacts(&fixture.elf), initial)
        .expect("open pinned campaign");
    let mut solver = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
    let run = session
        .run_sustained(&mut campaign, &mut solver, Duration::from_secs(10))
        .expect("run pinned campaign");
    assert!(run.steps >= 2, "must execute cmp and the symbolic branch");
    assert_eq!(
        run.ledger.retired_splits, 1,
        "fork must publish both owned child prefixes: {:?}",
        run.ledger
    );
    assert_eq!(
        run.ledger.completed, 2,
        "both real executable paths must terminate: {:?}",
        run.ledger
    );
    assert_eq!(run.ledger.deferred + run.ledger.queued + run.ledger.unknown, 0);
    assert!(run.ledger.complete_within_declared_bounds);
    assert!(run.reason.is_none());
    assert_eq!(run.evidence.report().summary.terminal_paths, 2);
    assert_eq!(run.evidence.report().summary.retained_frontier, 0);
    drop(campaign);

    let mut reopened = SustainedCampaign::open(&path, manifest.clone(), &artifacts(&fixture.elf), initial)
        .expect("open pinned campaign");
    assert_eq!(
        reopened.report().completed,
        2,
        "both child leaves survive process-independent reopen"
    );
    assert!(reopened.report().complete_within_declared_bounds);
    reopened
        .retry_deferred()
        .expect("retry must not requeue completed subtrees");
    assert_eq!(reopened.report().queued, 0);
    drop(reopened);

    let mut reopened = SustainedCampaign::open(&path, manifest.clone(), &artifacts(&fixture.elf), initial)
        .expect("open pinned campaign");
    let fresh_arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut fresh = SymbolicSession::new(&runtime, fresh_arena.as_ref(), runtime.load_elf(&fixture.elf)?);
    fresh.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let mut fresh_solver = Z3Backend::native_ffi(fresh_arena.clone() as Arc<dyn ExprReader>)?;
    let retried = fresh
        .run_sustained(&mut reopened, &mut fresh_solver, Duration::from_secs(10))
        .expect("retry from fresh root");
    assert_eq!(retried.steps, 0, "a completed campaign has no replayable owned work");
    assert_eq!(retried.ledger.completed, 2);
    assert!(retried.ledger.complete_within_declared_bounds);
    Ok(())
}

#[test]
fn step_cap_is_durable_and_retry_cannot_fake_completion() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&fixture.elf)?;
    let entry = process.pc()?;
    let manifest = manifest(&fixture.elf, entry, 1);
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut initial_session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    initial_session.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let initial = initial_session.sustained_initial_digest()?;
    let path = fixture.dir.join("capped.ledger");
    for attempt in 0..2 {
        let mut campaign = SustainedCampaign::open(&path, manifest.clone(), &artifacts(&fixture.elf), initial)
            .expect("open pinned campaign");
        if attempt != 0 {
            assert_eq!(campaign.report().deferred, 1);
            campaign.retry_deferred().expect("requeue capped root");
            assert_eq!(campaign.report().queued, 1);
        }
        let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
        let mut session = SymbolicSession::new(&runtime, arena.as_ref(), runtime.load_elf(&fixture.elf)?);
        session.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
        let mut solver = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
        let run = session
            .run_sustained(&mut campaign, &mut solver, Duration::from_secs(10))
            .expect("run pinned campaign");
        assert_eq!(run.steps, 1, "step cap must be enforced on attempt {attempt}");
        assert_eq!(run.ledger.deferred, 1);
        assert_eq!(run.ledger.completed, 0);
        assert!(!run.ledger.complete_within_declared_bounds);
        assert!(
            run.reason
                .as_deref()
                .is_some_and(|reason| reason.contains("step budget"))
        );
        assert_eq!(run.evidence.report().summary.retained_frontier, 1);
    }
    Ok(())
}

#[test]
fn nested_branch_prefixes_replay_from_pinned_root() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture_with_source(DOUBLE_SOURCE)?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&fixture.elf)?;
    let entry = process.pc()?;
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    session.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let initial = session.sustained_initial_digest()?;
    let path = fixture.dir.join("nested.ledger");
    let mut campaign = SustainedCampaign::open(
        &path,
        manifest(&fixture.elf, entry, 128),
        &artifacts(&fixture.elf),
        initial,
    )?;
    let mut solver = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
    let run = session.run_sustained(&mut campaign, &mut solver, Duration::from_secs(20))?;
    assert_eq!(
        run.ledger.retired_splits, 2,
        "must fork again inside false child: {:?}, reason {:?}",
        run.ledger, run.reason
    );
    assert_eq!(
        run.ledger.completed, 3,
        "distinct root/false/true owned subtrees: {:?}",
        run.ledger
    );
    assert!(run.ledger.complete_within_declared_bounds);
    assert_eq!(run.evidence.report().summary.terminal_paths, 3);
    assert_eq!(run.evidence.report().summary.retained_frontier, 0);
    drop(campaign);
    let reopened = SustainedCampaign::open(
        &path,
        manifest(&fixture.elf, entry, 128),
        &artifacts(&fixture.elf),
        initial,
    )?;
    assert_eq!(reopened.report().completed, 3);
    Ok(())
}

#[test]
fn active_state_cap_defers_both_disjoint_children() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&fixture.elf)?;
    let entry = process.pc()?;
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    session.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let initial = session.sustained_initial_digest()?;
    let mut spec = manifest(&fixture.elf, entry, 64).spec;
    spec.limits.max_active_states = 1;
    let manifest = CampaignManifest::seal(spec)?;
    let path = fixture.dir.join("state-cap.ledger");
    let mut campaign = SustainedCampaign::open(&path, manifest.clone(), &artifacts(&fixture.elf), initial)?;
    let mut solver = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
    let run = session.run_sustained(&mut campaign, &mut solver, Duration::from_secs(10))?;
    assert_eq!(run.ledger.retired_splits, 1);
    assert_eq!(
        run.ledger.deferred, 2,
        "over-cap children must both remain owned: {:?}",
        run.ledger
    );
    assert_eq!(run.ledger.completed, 0);
    assert_eq!(run.evidence.report().summary.retained_frontier, 2);
    assert!(!run.ledger.complete_within_declared_bounds);
    drop(campaign);
    let mut reopened = SustainedCampaign::open(&path, manifest, &artifacts(&fixture.elf), initial)?;
    assert_eq!(reopened.report().deferred, 2);
    reopened.retry_deferred()?;
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut resumed = SymbolicSession::new(&runtime, arena.as_ref(), runtime.load_elf(&fixture.elf)?);
    resumed.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let mut solver = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
    let resumed_run = resumed.run_sustained(&mut reopened, &mut solver, Duration::from_secs(10))?;
    assert_eq!(
        resumed_run.ledger.completed, 2,
        "each deferred child must replay on resume: {:?}",
        resumed_run.ledger
    );
    assert_eq!(resumed_run.ledger.deferred, 0);
    assert!(resumed_run.ledger.complete_within_declared_bounds);
    Ok(())
}

#[test]
fn unknown_solver_retains_both_branches_without_completion() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&fixture.elf)?;
    let entry = process.pc()?;
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    session.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let initial = session.sustained_initial_digest()?;
    let mut spec = manifest(&fixture.elf, entry, 64).spec;
    spec.solver_version = "unknown".into();
    let manifest = CampaignManifest::seal(spec)?;
    let path = fixture.dir.join("solver-unknown.ledger");
    let mut campaign = SustainedCampaign::open(&path, manifest.clone(), &artifacts(&fixture.elf), initial)?;
    let run = session.run_sustained(&mut campaign, &mut UnknownBackend, Duration::from_secs(10))?;
    assert_eq!(run.ledger.retired_splits, 1);
    assert_eq!(run.ledger.unknown, 2);
    assert_eq!(run.ledger.completed, 0);
    assert!(!run.ledger.complete_within_declared_bounds);
    assert_eq!(run.evidence.report().summary.retained_frontier, 2);
    drop(campaign);
    let mut campaign = SustainedCampaign::open(&path, manifest, &artifacts(&fixture.elf), initial)?;
    assert_eq!(campaign.report().unknown, 2);
    campaign.retry_deferred()?;
    assert_eq!(campaign.report().queued, 2);
    Ok(())
}

#[test]
fn contradictory_nested_edge_has_explicit_unsat_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let source = DOUBLE_SOURCE.replace("cmp $6, %rbx", "cmp $5, %rbx");
    let fixture = fixture_with_source(&source)?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&fixture.elf)?;
    let entry = process.pc()?;
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    session.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let initial = session.sustained_initial_digest()?;
    let path = fixture.dir.join("unsat.ledger");
    let mut campaign = SustainedCampaign::open(
        &path,
        manifest(&fixture.elf, entry, 128),
        &artifacts(&fixture.elf),
        initial,
    )?;
    let mut solver = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
    let run = session.run_sustained(&mut campaign, &mut solver, Duration::from_secs(20))?;
    assert_eq!(
        run.ledger.retired_splits, 2,
        "nested split must be represented: {:?}",
        run.ledger
    );
    assert_eq!(
        run.ledger.infeasible, 1,
        "contradictory edge requires UNSAT proof: {:?}",
        run.ledger
    );
    assert_eq!(run.ledger.completed, 2);
    assert!(run.ledger.complete_within_declared_bounds);
    let summary = run.evidence.report().summary;
    assert_eq!(summary.infeasible_paths, 1);
    assert_eq!(summary.infeasible_edges, 1);
    assert_eq!(summary.terminal_paths, 2);
    Ok(())
}
