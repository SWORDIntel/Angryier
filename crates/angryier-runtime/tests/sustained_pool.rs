//! Real ELF fork replay on 1/2/4 native workers, with simultaneous child work.
#![cfg(all(feature = "xed", feature = "script", target_arch = "x86_64"))]
#![allow(clippy::expect_used)]
use std::{
    path::PathBuf,
    process::Command,
    sync::{
        Arc, Barrier,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use angryier_arch_intel64::register_id;
use angryier_distribution::contracts::{CampaignArtifacts, CampaignManifest, CampaignSpec, Digest, ExplorationLimits};
use angryier_expr::{ExprReader, ShardedExprArena};
use angryier_ir::IrType;
use angryier_runtime::{Runtime, SymbolicSession, sustained::SustainedCampaign};
use angryier_solver_z3::Z3Backend;
use angryier_types::{ExpressionNormalizationVersion, FidelityProfile, SemanticVersion, TargetProfileId};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);
const SOURCE: &str = r#"
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
fn fixture_with_source(assembly: &str) -> Result<Fixture, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "angryier-pool-{}-{}",
        std::process::id(),
        NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&dir).expect("fixture directory");
    let source = dir.join("branch.s");
    let object = dir.join("branch.o");
    let binary = dir.join("branch.elf");
    std::fs::write(&source, assembly).expect("assembly fixture");
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
        let result = Command::new(program)
            .args(args)
            .output()
            .map_err(|error| std::io::Error::new(error.kind(), format!("failed to invoke {program}: {error}")))?;
        if !result.status.success() {
            return Err(std::io::Error::other(format!(
                "{program} failed ({}): {}",
                result.status,
                String::from_utf8_lossy(&result.stderr)
            ))
            .into());
        }
    }
    Ok(Fixture {
        elf: std::fs::read(binary).expect("ELF fixture"),
        dir,
    })
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
fn manifest(elf: &[u8], entry: u64) -> CampaignManifest {
    CampaignManifest::seal(CampaignSpec {
        binary_digest: Digest::of(elf),
        architecture: "x86_64".into(),
        entry_pc: entry,
        semantic_version: "1".into(),
        semantic_profile_digest: Digest::of(b"native-xed-v1"),
        script_digest: Digest::of(b"no-script"),
        policy_digest: Digest::of(b"no-policy"),
        inputs: vec![],
        stubs: vec![],
        solver_version: "z3".into(),
        solver_policy_digest: Digest::of(b"z3-default"),
        fidelity: FidelityProfile::Prove,
        limits: ExplorationLimits {
            max_steps: 128,
            max_path_steps: 64,
            max_active_states: 2,
            max_path_depth: 64,
            max_loop_visits: 64,
            max_solver_millis: 10_000,
            max_wall_millis: 30_000,
            max_ram_bytes: 64 * 1024 * 1024,
            max_disk_bytes: 1024 * 1024,
            max_trace_bytes: 1024 * 1024,
        },
    })
    .expect("sealed campaign")
}
#[test]
fn real_elf_path_ids_match_across_one_two_four_workers() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let entry = runtime.load_elf(&fixture.elf)?.pc()?;
    let manifest = manifest(&fixture.elf, entry);
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut root = SymbolicSession::new(&runtime, arena.as_ref(), runtime.load_elf(&fixture.elf)?);
    root.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let initial = root.sustained_initial_digest()?;
    let mut baseline = None;
    for workers in [1, 2, 4] {
        let path = fixture.dir.join(format!("pool-{workers}.ledger"));
        let mut campaign = SustainedCampaign::open(&path, manifest.clone(), &artifacts(&fixture.elf), initial)?;
        let barrier = Arc::new(Barrier::new(2));
        let run = campaign.run_pool(workers, Duration::from_secs(20), |grant, manifest, timeout, steps| {
            // The two disjoint first-generation subtrees must be executing at
            // once; a serialized wrapper deadlocks here instead of passing.
            if workers != 1 && grant.reservation.unit.prefix.len() == 1 {
                barrier.wait();
            }
            let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
            let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
            let mut session = SymbolicSession::new(
                &runtime,
                arena.as_ref(),
                runtime
                    .load_elf(&fixture.elf)
                    .map_err(|_| angryier_runtime::sustained::SustainedError::InitialStateMismatch)?,
            );
            session
                .mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))
                .map_err(|_| angryier_runtime::sustained::SustainedError::InitialStateMismatch)?;
            let mut solver = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)
                .map_err(|_| angryier_runtime::sustained::SustainedError::InitialStateMismatch)?;
            session.advance_sustained(grant, manifest, &mut solver, timeout, steps)
        })?;
        assert_eq!(
            run.ledger.completed, 3,
            "{workers} workers: {:?}, {:?}",
            run.ledger, run.reason
        );
        assert_eq!(run.ledger.retired_splits, 2);
        assert!(run.ledger.complete_within_declared_bounds);
        assert_eq!(run.accepted_path_ids.len(), 5, "2 split parents + 3 terminal leaves");
        if workers != 1 {
            assert!(run.worker_threads.len() >= 2, "workers must run simultaneously");
        }
        if let Some(ref ids) = baseline {
            assert_eq!(ids, &run.accepted_path_ids);
        } else {
            baseline = Some(run.accepted_path_ids.clone());
        }
        drop(campaign);
        let reopened = SustainedCampaign::open(&path, manifest.clone(), &artifacts(&fixture.elf), initial)?;
        assert_eq!(reopened.report().completed, 3, "durable accepted leaves");
        drop(reopened);
        let ledger = angryier_ledger::sustained::SustainedLedger::open(&path, manifest.clone())?;
        let (records, evidence) = ledger.read_snapshot();
        assert_eq!(records.iter().filter(|record| record.retired).count(), 2);
        assert_eq!(evidence.len(), 5, "parent and leaf evidence committed with ownership");
        assert_eq!(
            evidence
                .iter()
                .filter(|event| event.delta.path.witness.as_ref().is_some_and(|w| matches!(
                    w.replay,
                    angryier_provenance::sustained::ReplayVerification::Verified { .. }
                )))
                .count(),
            3,
            "SAT-owned terminal leaves must retain concrete witnesses after reopen"
        );
        let mut persisted: Vec<_> = evidence.iter().map(|event| Digest(event.delta.path.path_id)).collect();
        persisted.sort_by_key(|digest| digest.0);
        assert_eq!(persisted, run.accepted_path_ids);
    }
    Ok(())
}

#[test]
fn invalid_worker_count_is_explicitly_unsupported() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture()?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let entry = runtime.load_elf(&fixture.elf)?.pc()?;
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut root = SymbolicSession::new(&runtime, arena.as_ref(), runtime.load_elf(&fixture.elf)?);
    root.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let mut campaign = SustainedCampaign::open(
        fixture.dir.join("invalid.ledger"),
        manifest(&fixture.elf, entry),
        &artifacts(&fixture.elf),
        root.sustained_initial_digest()?,
    )?;
    assert!(
        campaign
            .run_pool(3, Duration::from_secs(1), |_, _, _, _| unreachable!())
            .is_err()
    );
    assert_eq!(campaign.report().queued, 1);
    Ok(())
}

#[test]
fn unsat_child_cannot_claim_complete_without_atomic_proof() -> Result<(), Box<dyn std::error::Error>> {
    let source = SOURCE.replace("cmp $6, %rbx", "cmp $5, %rbx");
    let fixture = fixture_with_source(&source)?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let entry = runtime.load_elf(&fixture.elf)?.pc()?;
    let manifest = manifest(&fixture.elf, entry);
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut root = SymbolicSession::new(&runtime, arena.as_ref(), runtime.load_elf(&fixture.elf)?);
    root.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let mut campaign = SustainedCampaign::open(
        fixture.dir.join("unsat.ledger"),
        manifest,
        &artifacts(&fixture.elf),
        root.sustained_initial_digest()?,
    )?;
    let result = campaign.run_pool(1, Duration::from_secs(20), |grant, manifest, timeout, steps| {
        let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
        let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
        let mut session = SymbolicSession::new(
            &runtime,
            arena.as_ref(),
            runtime
                .load_elf(&fixture.elf)
                .map_err(|_| angryier_runtime::sustained::SustainedError::InitialStateMismatch)?,
        );
        session
            .mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))
            .map_err(|_| angryier_runtime::sustained::SustainedError::InitialStateMismatch)?;
        let mut solver = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)
            .map_err(|_| angryier_runtime::sustained::SustainedError::InitialStateMismatch)?;
        session.advance_sustained(grant, manifest, &mut solver, timeout, steps)
    });
    assert!(matches!(
        result,
        Err(angryier_runtime::sustained::SustainedError::UnreplayableEnvironment(
            "pool cannot durably commit infeasible child evidence"
        ))
    ));
    assert!(!campaign.report().complete_within_declared_bounds);
    assert_eq!(campaign.report().active, 0, "failed grant was revoked");
    Ok(())
}
