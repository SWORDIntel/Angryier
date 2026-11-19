//! Local pure-Rust parity tests for `SustainedCampaign` +
//! `SymbolicSession::run_sustained_ranked`, mirroring the Lua v1 (`fork-all`)
//! and v2 (`rank-targets`) find/avoid/exclude and explicit retry-deferred /
//! resume behavior exercised by `sustained_policy.rs`, without any Lua.
//!
//! The bounded fixture is the same single-branch static ELF64 image; no
//! claims are asserted beyond its two computed branch targets.
#![cfg(all(feature = "xed", feature = "z3", target_arch = "x86_64"))]
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
use angryier_ledger::sustained::Error as LedgerError;
use angryier_provenance::sustained::{EdgeBasis, PathDisposition, PendingReason, SolverDisposition};
use angryier_runtime::{
    Runtime, SymbolicSession,
    sustained::{SustainedCampaign, SustainedError, SustainedRanking},
};
use angryier_solver_z3::{Z3Backend, Z3FfiBridge};
use angryier_types::{ExpressionNormalizationVersion, FidelityProfile, SemanticVersion, TargetProfileId};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    dir: PathBuf,
    binary: PathBuf,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
fn fixture() -> Result<Option<Fixture>, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "angryier-local-policy-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&dir)?;
    let source = dir.join("branch.s");
    let object = dir.join("branch.o");
    let binary = dir.join("branch.elf");
    std::fs::write(
        &source,
        ".global _start\n.text\n_start:\n cmp $5, %rbx\n je equal\n mov $1, %rdi\n jmp exit\nequal:\n xor %rdi, %rdi\nexit:\n mov $60, %rax\n syscall\n",
    )?;
    for (program, args) in [
        (
            "as",
            vec![
                "--64",
                "-o",
                object.to_str().expect("object"),
                source.to_str().expect("source"),
            ],
        ),
        (
            "ld",
            vec!["-o", binary.to_str().expect("binary"), object.to_str().expect("object")],
        ),
    ] {
        let output = match Command::new(program).args(args).output() {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("{program}: {error}").into()),
        };
        assert!(
            output.status.success(),
            "{program}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(Some(Fixture { dir, binary }))
}

/// False (FIFO-first) and true successor targets of the fixture's only
/// dynamic branch, computed from the linked image, never assumed.
fn branch_targets(f: &Fixture) -> (u64, u64) {
    let binary = std::fs::read(&f.binary).expect("ELF");
    let entry = u64::from_le_bytes(binary[24..32].try_into().expect("entry"));
    let phoff = u64::from_le_bytes(binary[32..40].try_into().expect("phoff")) as usize;
    let phentsize = u16::from_le_bytes(binary[54..56].try_into().expect("phentsize")) as usize;
    let phnum = u16::from_le_bytes(binary[56..58].try_into().expect("phnum")) as usize;
    let offset = (0..phnum)
        .find_map(|i| {
            let ph = phoff + i * phentsize;
            let file = u64::from_le_bytes(binary[ph + 8..ph + 16].try_into().ok()?);
            let virtual_addr = u64::from_le_bytes(binary[ph + 16..ph + 24].try_into().ok()?);
            let len = u64::from_le_bytes(binary[ph + 32..ph + 40].try_into().ok()?);
            (entry >= virtual_addr && entry < virtual_addr + len).then_some((file + entry - virtual_addr) as usize)
        })
        .expect("entry segment");
    assert_eq!(&binary[offset..offset + 5], &[0x48, 0x83, 0xfb, 0x05, 0x74]);
    let false_target = entry + 6;
    let true_target = false_target.wrapping_add_signed(i8::from_ne_bytes([binary[offset + 5]]) as i64);
    (false_target, true_target)
}

/// The exploration objective is pinned into the manifest policy digest the way
/// the Lua layer pins it (label + sorted target lists [+ exclude flag]), so a
/// changed objective cannot resume the same durable campaign. Callers must
/// pass strictly ascending target lists, matching `SustainedRanking` itself.
fn policy_bytes(label: &[u8], find: &[u64], avoid: &[u64], exclude_avoid: bool) -> Vec<u8> {
    let mut policy = label.to_vec();
    policy.push(0);
    for list in [find, avoid] {
        policy.extend_from_slice(&(list.len() as u64).to_le_bytes());
        for address in list {
            policy.extend_from_slice(&address.to_le_bytes());
        }
    }
    policy.push(u8::from(exclude_avoid));
    policy
}

fn artifacts<'a>(elf: &'a [u8], policy: &'a [u8]) -> CampaignArtifacts<'a> {
    CampaignArtifacts {
        binary: elf,
        semantic_profile: b"native-xed-v1",
        script: b"no-script",
        policy,
        solver_policy: b"z3-default",
        inputs: vec![],
        stubs: vec![],
    }
}

fn seal_manifest(elf: &[u8], entry_pc: u64, max_steps: u64, max_active_states: u64, policy: &[u8]) -> CampaignManifest {
    CampaignManifest::seal(CampaignSpec {
        binary_digest: Digest::of(elf),
        architecture: "x86_64".into(),
        entry_pc,
        semantic_version: "1".into(),
        semantic_profile_digest: Digest::of(b"native-xed-v1"),
        script_digest: Digest::of(b"no-script"),
        policy_digest: Digest::of(policy),
        inputs: vec![],
        stubs: vec![],
        solver_version: "z3".into(),
        solver_policy_digest: Digest::of(b"z3-default"),
        fidelity: FidelityProfile::Prove,
        limits: ExplorationLimits {
            max_steps,
            max_path_steps: 64,
            max_active_states,
            max_path_depth: 64,
            max_loop_visits: 64,
            max_solver_millis: 10_000,
            max_wall_millis: 30_000,
            max_ram_bytes: 64 * 1024 * 1024,
            max_disk_bytes: 1024 * 1024,
            max_trace_bytes: 1024 * 1024,
        },
    })
    .expect("valid campaign specification")
}

fn open_campaign(
    f: &Fixture,
    ledger_name: &str,
    manifest: CampaignManifest,
    initial: Digest,
    policy: &[u8],
) -> Result<SustainedCampaign, SustainedError> {
    let elf = std::fs::read(&f.binary).expect("ELF");
    let campaign_artifacts = artifacts(&elf, policy);
    SustainedCampaign::open(f.dir.join(ledger_name), manifest, &campaign_artifacts, initial)
}

fn native_solver(arena: &Arc<ShardedExprArena>) -> Z3Backend<Z3FfiBridge> {
    Z3Backend::native_ffi(Arc::clone(arena) as Arc<dyn ExprReader>).expect("native z3 backend")
}

#[test]
fn v2_ranked_find_changes_the_first_accepted_child_vs_fifo() -> Result<(), Box<dyn std::error::Error>> {
    let Some(f) = fixture()? else { return Ok(()) };
    let elf = std::fs::read(&f.binary)?;
    // Engine BranchPoint semantics for a conditional jump are condition-
    // inverted (je models zf_not_set): branch_targets().0 (the fallthrough)
    // is the BranchPoint TRUE successor and .1 (the jump target) is FALSE.
    // The FIFO-first child is the FALSE-successor child, i.e. the jump target.
    let (find_target, fifo_target) = branch_targets(&f);
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));

    // v2 rank-targets: the child ranked by the find target is accepted first.
    let process = runtime.load_elf(&elf)?;
    let entry = process.pc()?;
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    session.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let policy = policy_bytes(b"rank-targets/v1", &[find_target], &[], false);
    let manifest = seal_manifest(&elf, entry, 4, 2, &policy);
    let initial = session.sustained_initial_digest()?;
    let mut campaign = open_campaign(&f, "ranked.ledger", manifest, initial, &policy)?;
    let mut solver = native_solver(&arena);
    let ranked = session.run_sustained_ranked(
        &mut campaign,
        &mut solver,
        Duration::from_secs(10),
        Some(SustainedRanking {
            find: &[find_target],
            avoid: &[],
            exclude_avoid: false,
        }),
    )?;
    assert_eq!(ranked.ledger.retired_splits, 1, "root split: {:?}", ranked.ledger);
    assert_eq!(campaign.report().queued, 1, "the sibling stays owned and queued");
    let ranked_events = campaign.accepted_events();
    assert_eq!(ranked_events.len(), 2, "root split plus first ranked child only");
    let ranked_child = &ranked_events[1].delta.path;
    assert_eq!(ranked_child.branches.len(), 1);
    assert_eq!(
        ranked_child.branches[0].tested_target,
        Some(find_target),
        "ranked run must accept the find-target child first"
    );
    assert_eq!(ranked_child.branches[0].disposition, SolverDisposition::Sat);
    assert!(ranked_child.branches[0].result_digest.is_some());
    drop(campaign);

    // v1 fork-all on an identical fresh fixture: FIFO child (false target) first.
    let Some(fifo_fixture) = fixture()? else { return Ok(()) };
    assert_eq!(
        branch_targets(&fifo_fixture),
        (find_target, fifo_target),
        "fixtures must be layout-identical"
    );
    let fifo_elf = std::fs::read(&fifo_fixture.binary)?;
    let fifo_process = runtime.load_elf(&fifo_elf)?;
    let fifo_entry = fifo_process.pc()?;
    let fifo_arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut fifo_session = SymbolicSession::new(&runtime, fifo_arena.as_ref(), fifo_process);
    fifo_session.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let fifo_policy = policy_bytes(b"fork-all/v1", &[], &[], false);
    let fifo_manifest = seal_manifest(&fifo_elf, fifo_entry, 4, 2, &fifo_policy);
    let fifo_initial = fifo_session.sustained_initial_digest()?;
    let mut fifo_campaign = open_campaign(&fifo_fixture, "fifo.ledger", fifo_manifest, fifo_initial, &fifo_policy)?;
    let mut fifo_solver = native_solver(&fifo_arena);
    let fifo = fifo_session.run_sustained(&mut fifo_campaign, &mut fifo_solver, Duration::from_secs(10))?;
    assert_eq!(fifo.ledger.retired_splits, 1, "root split: {:?}", fifo.ledger);
    assert_eq!(fifo_campaign.report().queued, 1);
    let fifo_events = fifo_campaign.accepted_events();
    assert_eq!(fifo_events.len(), 2, "root split plus first FIFO child only");
    let fifo_child = &fifo_events[1].delta.path;
    assert_eq!(fifo_child.branches.len(), 1);
    assert_eq!(
        fifo_child.branches[0].tested_target,
        Some(fifo_target),
        "fork-all must accept the FIFO (false-target) child first"
    );
    Ok(())
}

#[test]
fn v2_ranking_rejects_unsorted_targets_and_unproven_exclusion() -> Result<(), Box<dyn std::error::Error>> {
    let Some(f) = fixture()? else { return Ok(()) };
    let elf = std::fs::read(&f.binary)?;
    // See the engine-semantics note in the ranked/FIFO test: .0 is the
    // fallthrough (BranchPoint TRUE), .1 the jump target (BranchPoint FALSE).
    let (fallthrough_target, jump_target) = branch_targets(&f);
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&elf)?;
    let entry = process.pc()?;
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    session.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let initial = session.sustained_initial_digest()?;
    let mut solver = native_solver(&arena);

    // The raw Rust API requires strictly ascending targets (the Lua layer
    // sorts for its callers); unsorted find or avoid must fail closed.
    let policy = policy_bytes(b"rank-targets/v1", &[fallthrough_target, jump_target], &[], false);
    let manifest = seal_manifest(&elf, entry, 64, 2, &policy);
    let mut campaign = open_campaign(&f, "unsorted.ledger", manifest, initial, &policy)?;
    for (name, ranking) in [
        (
            "find",
            SustainedRanking {
                find: &[jump_target, fallthrough_target],
                avoid: &[],
                exclude_avoid: false,
            },
        ),
        (
            "avoid",
            SustainedRanking {
                find: &[],
                avoid: &[jump_target, fallthrough_target],
                exclude_avoid: false,
            },
        ),
    ] {
        let error = session
            .run_sustained_ranked(&mut campaign, &mut solver, Duration::from_secs(10), Some(ranking))
            .err()
            .expect("unsorted ranking targets must be rejected");
        assert!(
            matches!(error, SustainedError::Ledger(LedgerError::InvalidTransition)),
            "unsorted {name}: {error:?}"
        );
    }
    assert_eq!(campaign.report().active, 0, "failed ranking must not hold work");
    assert_eq!(campaign.report().queued, 1);
    drop(campaign);

    // exclude_avoid on the entry PC is rejected before any work is reserved
    // (mirrors Lua: avoid=exclude requires an exact dynamic branch target).
    let policy = policy_bytes(b"rank-targets/v1", &[], &[entry], true);
    let manifest = seal_manifest(&elf, entry, 64, 2, &policy);
    let mut campaign = open_campaign(&f, "entry-exclude.ledger", manifest, initial, &policy)?;
    let error = session
        .run_sustained_ranked(
            &mut campaign,
            &mut solver,
            Duration::from_secs(10),
            Some(SustainedRanking {
                find: &[],
                avoid: &[entry],
                exclude_avoid: true,
            }),
        )
        .err()
        .expect("the entry cannot be excluded");
    assert!(matches!(error, SustainedError::ExclusionUnproven), "{error:?}");
    let report = campaign.report();
    assert_eq!(report.retired_splits, 0);
    assert_eq!(report.queued, 1, "root stays queued; nothing was executed");
    drop(campaign);

    // Excluding a target that is never an observed dynamic successor cannot be
    // proven: the run fails closed after bounded work, and the committed work
    // is retained (never pruned to fake completeness).
    let unreachable = entry + 0x4000_0000;
    let policy = policy_bytes(b"rank-targets/v1", &[], &[unreachable], true);
    let manifest = seal_manifest(&elf, entry, 64, 2, &policy);
    let mut campaign = open_campaign(&f, "unobserved-exclude.ledger", manifest, initial, &policy)?;
    let error = session
        .run_sustained_ranked(
            &mut campaign,
            &mut solver,
            Duration::from_secs(10),
            Some(SustainedRanking {
                find: &[],
                avoid: &[unreachable],
                exclude_avoid: true,
            }),
        )
        .err()
        .expect("an unobserved exclude target cannot be validated");
    assert!(matches!(error, SustainedError::ExclusionUnproven), "{error:?}");
    let report = campaign.report();
    assert_eq!(report.completed, 2, "resolved children stay committed: {report:?}");
    assert_eq!(report.excluded, 0, "nothing was pruned to satisfy the objective");
    assert_eq!(report.retired_splits, 1);
    Ok(())
}

#[test]
fn v2_exclude_avoid_proves_sat_child_excluded_and_resume_preserves_identity() -> Result<(), Box<dyn std::error::Error>>
{
    let Some(f) = fixture()? else { return Ok(()) };
    let elf = std::fs::read(&f.binary)?;
    // See the engine-semantics note in the ranked/FIFO test: the Lua parity
    // case excludes the fallthrough child (BranchPoint TRUE successor).
    let (fallthrough_target, jump_target) = branch_targets(&f);
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&elf)?;
    let entry = process.pc()?;
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    session.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let policy = policy_bytes(b"rank-targets/v1", &[], &[fallthrough_target], true);
    let manifest = seal_manifest(&elf, entry, 64, 2, &policy);
    let campaign_digest = manifest.campaign_digest;
    let initial = session.sustained_initial_digest()?;
    let mut campaign = open_campaign(&f, "exclude.ledger", manifest.clone(), initial, &policy)?;
    let mut solver = native_solver(&arena);
    let run = session.run_sustained_ranked(
        &mut campaign,
        &mut solver,
        Duration::from_secs(10),
        Some(SustainedRanking {
            find: &[],
            avoid: &[fallthrough_target],
            exclude_avoid: true,
        }),
    )?;
    assert_eq!(run.evidence.report().summary.scope.campaign_digest, campaign_digest.0);
    let report = &run.ledger;
    assert_eq!(report.excluded, 1, "SAT avoided child excluded: {report:?}");
    assert_eq!(report.infeasible, 0, "avoid is not feasibility: {report:?}");
    assert_eq!(report.completed, 1, "the non-avoided child completes: {report:?}");
    assert_eq!(report.retired_splits, 1);
    assert!(report.complete_within_declared_bounds);
    assert!(run.reason.is_none());

    // Atomic policy evidence: the excluded child carries its own accepted
    // SAT proof, and the retired parent retains both fork proofs.
    let summary = run.evidence.report().summary;
    assert_eq!(summary.excluded_paths, 1);
    assert_eq!(summary.infeasible_paths, 0);
    assert_eq!(summary.terminal_paths, 1);
    let excluded = run
        .evidence
        .report()
        .paths
        .iter()
        .find(|path| path.disposition == PathDisposition::ExcludedByPolicy)
        .expect("excluded child path evidence");
    let branch = excluded
        .branches
        .iter()
        .find(|branch| branch.tested_target == Some(fallthrough_target))
        .expect("excluded child proves the avoided target");
    assert_eq!(branch.disposition, SolverDisposition::Sat);
    assert!(
        branch.result_digest.is_some(),
        "exclusion requires a solver result digest"
    );
    for edge in &excluded.edges {
        assert!(
            !matches!(edge.basis, EdgeBasis::SolverInfeasible { .. }),
            "exclusion must not be recorded as solver infeasibility"
        );
    }
    assert_eq!(run.accepted_splits.len(), 1);
    let mut parent_targets: Vec<_> = run.accepted_splits[0]
        .branches
        .iter()
        .map(|branch| branch.tested_target)
        .collect();
    parent_targets.sort_unstable();
    assert_eq!(
        parent_targets,
        vec![Some(fallthrough_target), Some(jump_target)],
        "the retired parent retains both fork proofs"
    );
    let excluded_id = excluded.path_id;
    drop(campaign);

    // A changed objective cannot resume the pinned campaign.
    let changed = policy_bytes(b"rank-targets/v1", &[], &[jump_target], true);
    let wrong = seal_manifest(&elf, entry, 64, 2, &changed);
    let error = open_campaign(&f, "exclude.ledger", wrong, initial, &changed)
        .err()
        .expect("a different objective cannot resume");
    assert!(
        matches!(error, SustainedError::Ledger(LedgerError::MismatchedCampaign)),
        "{error:?}"
    );

    // The same pinned objective reopens with identical identity and the
    // excluded child still present; no work remains to replay.
    let mut resumed = open_campaign(&f, "exclude.ledger", manifest, initial, &policy)?;
    assert_eq!(resumed.report().excluded, 1);
    let cumulative: Vec<_> = resumed.cumulative_evidence().collect();
    assert!(cumulative.len() >= 2);
    assert!(
        cumulative.iter().any(|event| event.delta.path.path_id == excluded_id
            && event.delta.path.disposition == PathDisposition::ExcludedByPolicy),
        "excluded child evidence survives reopen"
    );
    let resume_process = runtime.load_elf(&elf)?;
    let resume_arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut resumed_session = SymbolicSession::new(&runtime, resume_arena.as_ref(), resume_process);
    resumed_session.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let mut idle_solver = native_solver(&resume_arena);
    let idle = resumed_session.run_sustained_ranked(
        &mut resumed,
        &mut idle_solver,
        Duration::from_secs(10),
        Some(SustainedRanking {
            find: &[],
            avoid: &[fallthrough_target],
            exclude_avoid: true,
        }),
    )?;
    assert_eq!(idle.steps, 0, "a resolved campaign has no replayable work");
    assert_eq!(
        idle.evidence.report().summary.scope.campaign_digest,
        campaign_digest.0,
        "reopen keeps the pinned campaign identity"
    );
    Ok(())
}

#[test]
fn v1_avoid_is_observational_then_retry_deferred_completes_after_reopen() -> Result<(), Box<dyn std::error::Error>> {
    let Some(f) = fixture()? else { return Ok(()) };
    let elf = std::fs::read(&f.binary)?;
    let (_false_target, _true_target) = branch_targets(&f);
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&elf)?;
    let entry = process.pc()?;
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    session.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    // v1 has no ranking or exclusion: targets are observational only, and the
    // objective is still pinned so identity changes are detected on resume.
    let policy = policy_bytes(b"fork-all/v1", &[], &[], false);
    let manifest = seal_manifest(&elf, entry, 64, 1, &policy);
    let initial = session.sustained_initial_digest()?;
    let mut campaign = open_campaign(&f, "observational.ledger", manifest.clone(), initial, &policy)?;
    let mut solver = native_solver(&arena);
    let run = session.run_sustained(&mut campaign, &mut solver, Duration::from_secs(10))?;
    assert_eq!(run.ledger.retired_splits, 1);
    assert_eq!(
        run.ledger.deferred, 2,
        "both children deferred over the cap: {:?}",
        run.ledger
    );
    assert_eq!(run.ledger.excluded, 0, "v1 avoid is observational, never pruning");
    assert_eq!(run.ledger.completed, 0);
    assert_eq!(run.evidence.report().summary.retained_frontier, 2);
    assert!(!run.ledger.complete_within_declared_bounds);
    drop(campaign);

    // A changed campaign manifest (cap 2) cannot resume the pinned ledger.
    let changed = seal_manifest(&elf, entry, 64, 2, &policy);
    let error = open_campaign(&f, "observational.ledger", changed, initial, &policy)
        .err()
        .expect("changed cap changes manifest");
    assert!(
        matches!(error, SustainedError::Ledger(LedgerError::MismatchedCampaign)),
        "{error:?}"
    );

    // Explicit retry-deferred on the reopened campaign requeues both children.
    let mut reopened = open_campaign(&f, "observational.ledger", manifest, initial, &policy)?;
    assert_eq!(reopened.report().deferred, 2);
    reopened.retry_deferred()?;
    assert_eq!(reopened.report().queued, 2);

    let resume_process = runtime.load_elf(&elf)?;
    let resume_arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut resumed = SymbolicSession::new(&runtime, resume_arena.as_ref(), resume_process);
    resumed.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let mut resumed_solver = native_solver(&resume_arena);
    let retried = resumed.run_sustained(&mut reopened, &mut resumed_solver, Duration::from_secs(10))?;
    assert_eq!(
        retried.ledger.completed, 2,
        "each deferred child replays: {:?}",
        retried.ledger
    );
    assert_eq!(retried.ledger.deferred, 0);
    assert_eq!(retried.ledger.excluded, 0);
    assert!(retried.ledger.complete_within_declared_bounds);
    assert_eq!(retried.evidence.report().summary.terminal_paths, 2);
    assert_eq!(retried.evidence.report().summary.retained_frontier, 0);
    Ok(())
}

#[test]
fn v2_partial_ranked_resume_keeps_pinned_order_and_identity() -> Result<(), Box<dyn std::error::Error>> {
    let Some(f) = fixture()? else { return Ok(()) };
    let elf = std::fs::read(&f.binary)?;
    let (find_target, _) = branch_targets(&f);
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let process = runtime.load_elf(&elf)?;
    let entry = process.pc()?;
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    session.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let policy = policy_bytes(b"rank-targets/v1", &[find_target], &[], false);
    let manifest = seal_manifest(&elf, entry, 4, 2, &policy);
    let campaign_digest = manifest.campaign_digest;
    let initial = session.sustained_initial_digest()?;
    let mut campaign = open_campaign(&f, "partial-ranked.ledger", manifest.clone(), initial, &policy)?;
    let mut solver = native_solver(&arena);
    let partial = session.run_sustained_ranked(
        &mut campaign,
        &mut solver,
        Duration::from_secs(10),
        Some(SustainedRanking {
            find: &[find_target],
            avoid: &[],
            exclude_avoid: false,
        }),
    )?;
    assert_eq!(partial.ledger.retired_splits, 1);
    assert_eq!(
        partial.evidence.report().summary.scope.campaign_digest,
        campaign_digest.0
    );
    let events = campaign.accepted_events();
    assert_eq!(events.len(), 2, "partial batch: root plus first ranked child");
    let child_id = events[1].delta.path.path_id;
    drop(campaign);

    // A different objective cannot resume the pinned campaign.
    let wrong = policy_bytes(b"rank-targets/v1", &[entry], &[], false);
    let error = open_campaign(
        &f,
        "partial-ranked.ledger",
        seal_manifest(&elf, entry, 4, 2, &wrong),
        initial,
        &wrong,
    )
    .err()
    .expect("changed objective changes campaign identity");
    assert!(
        matches!(error, SustainedError::Ledger(LedgerError::MismatchedCampaign)),
        "{error:?}"
    );

    // The same objective resumes: identity, order and the accepted child
    // survive; the sibling stays queued in pinned order.
    let mut resumed = open_campaign(&f, "partial-ranked.ledger", manifest, initial, &policy)?;
    let resumed_events: Vec<_> = resumed.cumulative_evidence().collect();
    assert_eq!(resumed_events.len(), 2);
    assert_eq!(
        resumed_events[1].delta.path.path_id, child_id,
        "ranked child keeps its identity"
    );
    assert_eq!(resumed.report().queued, 1, "the sibling stays queued in pinned order");
    resumed.retry_deferred()?;
    assert_eq!(resumed.report().queued, 2);

    let resume_process = runtime.load_elf(&elf)?;
    let resume_arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut fresh = SymbolicSession::new(&runtime, resume_arena.as_ref(), resume_process);
    fresh.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let mut fresh_solver = native_solver(&resume_arena);
    let completed = fresh.run_sustained_ranked(
        &mut resumed,
        &mut fresh_solver,
        Duration::from_secs(10),
        Some(SustainedRanking {
            find: &[find_target],
            avoid: &[],
            exclude_avoid: false,
        }),
    )?;
    // The step budget is pinned in the manifest: the replayed child defers
    // again at the same bound, staying owned — resume must never fake
    // completion or drop the unresolved work.
    assert_eq!(completed.ledger.completed, 0);
    assert_eq!(
        completed.ledger.deferred, 1,
        "the requeued child defers at the same pinned step budget"
    );
    assert_eq!(completed.ledger.queued, 1, "the sibling stays queued");
    assert_eq!(
        completed.evidence.report().summary.scope.campaign_digest,
        campaign_digest.0,
        "retry keeps the pinned campaign identity"
    );
    let cumulative: Vec<_> = resumed.cumulative_evidence().collect();
    assert!(
        cumulative.iter().any(|event| event.delta.path.path_id == child_id
            && event.delta.path.disposition == PathDisposition::Pending(PendingReason::ResourceLimit)),
        "the first ranked child keeps its identity as owned, deferred work"
    );
    Ok(())
}

#[test]
fn distinct_register_marks_support_independent_solutions_and_stable_replay() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_expr::{ExprArena, ExprNode, ExprOp, ExprSort};
    use angryier_solver::{SolverBackend, SolverOutcomeKind, SolverQuery};
    use angryier_types::{ConstraintCanonicalizationVersion, DependencyKey, SolverQueryId};

    let Some(f) = fixture()? else { return Ok(()) };
    let elf = std::fs::read(&f.binary)?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut previous_root = None;
    for _ in 0..2 {
        let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
        let mut session = SymbolicSession::new(&runtime, arena.as_ref(), runtime.load_elf(&elf)?);
        let (rdi, rsi) = (register_id::GPR_BASE + 7, register_id::GPR_BASE + 6);
        session.mark_symbolic(0, rdi, IrType::Bits(64))?;
        session.mark_symbolic(0, rsi, IrType::Bits(64))?;
        let symbols = &session.states[0].symbols;
        assert_eq!(symbols.len(), 2);
        assert_eq!((symbols[0].register, symbols[1].register), (rdi, rsi));
        let (a, b) = (symbols[0].expression, symbols[1].expression);
        assert_ne!(a, b);
        assert_eq!(
            (session.states[0].registers[&rdi].0, session.states[0].registers[&rsi].0),
            (a, b)
        );
        assert_ne!(arena.get(a), arena.get(b));
        let root = session.sustained_initial_digest()?;
        if let Some(previous) = previous_root {
            assert_eq!(root, previous);
        }
        previous_root = Some(root);
        assert!(session.mark_symbolic(0, rdi, IrType::Bits(64)).is_err());
        assert_eq!(session.states[0].symbols.len(), 2);
        assert_eq!(session.sustained_initial_digest()?, root);

        let mut solver = native_solver(&arena);
        for (index, (x, y)) in [(0u64, 1u64), (1, 0)].into_iter().enumerate() {
            let eqs = [(a, x), (b, y)]
                .into_iter()
                .map(|(symbol, value)| {
                    let constant = arena.intern(ExprNode {
                        sort: ExprSort::BitVec(64),
                        op: ExprOp::Constant,
                        operands: vec![],
                        immediate: value.to_le_bytes().to_vec(),
                    })?;
                    arena.intern(ExprNode {
                        sort: ExprSort::Bool,
                        op: ExprOp::Eq,
                        operands: vec![symbol, constant],
                        immediate: vec![],
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            let predicate = arena.intern(ExprNode {
                sort: ExprSort::Bool,
                op: ExprOp::And,
                operands: eqs,
                immediate: vec![],
            })?;
            let query = SolverQuery::canonical(
                SolverQueryId(index as u64 + 1),
                &[],
                predicate,
                DependencyKey([index as u8 + 1; 32]),
                TargetProfileId(1),
                ConstraintCanonicalizationVersion(1),
                Duration::from_secs(5),
            )?;
            assert_eq!(solver.solve(&query).outcome, SolverOutcomeKind::Sat);
        }
    }
    Ok(())
}
