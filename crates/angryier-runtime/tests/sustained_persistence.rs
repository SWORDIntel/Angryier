//! Real ELF persistence checks for accepted sustained evidence and corrupt snapshots.
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
use angryier_provenance::sustained::{Completion, PathDisposition, SolverDisposition};
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
fn fixture() -> Result<Option<Fixture>, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "angryier-evidence-{}-{}",
        std::process::id(),
        NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&dir)?;
    let source = dir.join("branch.s");
    let object = dir.join("branch.o");
    let binary = dir.join("branch.elf");
    std::fs::write(&source, SOURCE)?;
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
        let output = match Command::new(program).args(args).output() {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("skipping ELF persistence test: {program} unavailable");
                let _ = std::fs::remove_dir_all(dir);
                return Ok(None);
            }
            Err(error) => return Err(format!("cannot invoke {program}: {error}").into()),
        };
        assert!(
            output.status.success(),
            "{program}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(Some(Fixture {
        elf: std::fs::read(binary)?,
        dir,
    }))
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
fn manifest(elf: &[u8], entry_pc: u64, disk: u64) -> CampaignManifest {
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
        limits: ExplorationLimits {
            max_steps: 64,
            max_path_steps: 64,
            max_active_states: 2,
            max_path_depth: 64,
            max_loop_visits: 64,
            max_solver_millis: 10_000,
            max_wall_millis: 30_000,
            max_ram_bytes: 64 * 1024 * 1024,
            max_disk_bytes: disk,
            max_trace_bytes: 1024 * 1024,
        },
    })
    .expect("sealed manifest")
}

#[test]
fn two_advances_reopen_report_only_cumulative_accepted_elf_paths() -> Result<(), Box<dyn std::error::Error>> {
    let Some(fixture) = fixture()? else {
        return Ok(());
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), runtime.load_elf(&fixture.elf)?);
    session.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let initial = session.sustained_initial_digest()?;
    let manifest = manifest(&fixture.elf, runtime.load_elf(&fixture.elf)?.pc()?, 1024 * 1024);
    let path = fixture.dir.join("accepted.ledger");
    let mut campaign = SustainedCampaign::open(&path, manifest.clone(), &artifacts(&fixture.elf), initial)?;
    let mut solver = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
    let first = session.run_sustained(&mut campaign, &mut solver, Duration::ZERO)?;
    assert_eq!(first.steps, 0);
    assert_eq!(first.ledger.deferred, 1);
    assert_eq!(first.evidence.report().summary.retained_frontier, 1);
    assert_eq!(first.evidence.report().summary.terminal_paths, 0);
    assert!(first.accepted_splits.is_empty());
    assert_eq!(
        first.evidence.report().paths.len(),
        1,
        "the deferred root was committed"
    );
    assert!(first.evidence.report().paths[0].blocks.is_empty());
    drop(campaign);

    let mut reopened = SustainedCampaign::open(&path, manifest.clone(), &artifacts(&fixture.elf), initial)?;
    reopened.retry_deferred()?;
    let fresh_arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut fresh = SymbolicSession::new(&runtime, fresh_arena.as_ref(), runtime.load_elf(&fixture.elf)?);
    fresh.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let mut solver = Z3Backend::native_ffi(fresh_arena.clone() as Arc<dyn ExprReader>)?;
    let second = fresh.run_sustained(&mut reopened, &mut solver, Duration::from_secs(10))?;
    assert_eq!(second.ledger.completed, 2);
    assert!(second.ledger.complete_within_declared_bounds);
    assert_eq!(
        second.evidence.report().summary.completion,
        Completion::CompleteWithinDeclaredBounds
    );
    assert_eq!(second.evidence.report().summary.terminal_paths, 2);
    assert_eq!(second.evidence.report().summary.retained_frontier, 0);
    assert_eq!(second.accepted_splits.len(), 1);
    assert_eq!(second.accepted_splits[0].branches.len(), 2);
    assert!(
        second.accepted_splits[0]
            .branches
            .iter()
            .all(|proof| proof.disposition == SolverDisposition::Sat)
    );
    assert!(second.evidence.report().paths.iter().all(|path| {
        path.disposition == PathDisposition::Terminal && !path.blocks.is_empty() && !path.edges.is_empty()
    }));
    drop(reopened);

    let mut reopened = SustainedCampaign::open(&path, manifest, &artifacts(&fixture.elf), initial)?;
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut fresh = SymbolicSession::new(&runtime, arena.as_ref(), runtime.load_elf(&fixture.elf)?);
    fresh.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let mut solver = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
    let third = fresh.run_sustained(&mut reopened, &mut solver, Duration::from_secs(10))?;
    assert_eq!(third.steps, 0);
    assert_eq!(third.evidence.report().summary.terminal_paths, 2);
    assert_eq!(third.accepted_splits, second.accepted_splits);
    assert_eq!(third.evidence.report().paths, second.evidence.report().paths);
    Ok(())
}

#[test]
fn tampered_accepted_snapshot_fails_closed_on_reopen() -> Result<(), Box<dyn std::error::Error>> {
    let Some(fixture) = fixture()? else {
        return Ok(());
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), runtime.load_elf(&fixture.elf)?);
    session.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let initial = session.sustained_initial_digest()?;
    let manifest = manifest(&fixture.elf, runtime.load_elf(&fixture.elf)?.pc()?, 1024 * 1024);
    let path = fixture.dir.join("tampered.ledger");
    let mut campaign = SustainedCampaign::open(&path, manifest.clone(), &artifacts(&fixture.elf), initial)?;
    let mut solver = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
    let run = session.run_sustained(&mut campaign, &mut solver, Duration::from_secs(10))?;
    assert!(run.ledger.complete_within_declared_bounds);
    drop(campaign);
    let mut bytes = std::fs::read(&path)?;
    let last = bytes.len() - 1;
    bytes[last] ^= 0x80;
    std::fs::write(&path, bytes)?;
    assert!(
        SustainedCampaign::open(&path, manifest, &artifacts(&fixture.elf), initial).is_err(),
        "a corrupted snapshot must never be counted as accepted evidence"
    );
    Ok(())
}

#[test]
fn publication_limit_never_completes_without_accepted_evidence() -> Result<(), Box<dyn std::error::Error>> {
    let Some(fixture) = fixture()? else {
        return Ok(());
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), runtime.load_elf(&fixture.elf)?);
    session.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let initial = session.sustained_initial_digest()?;
    // Measure the sealed checkpoint size with a generous throwaway campaign:
    // the snapshot only stores the fixed-width campaign digest, so its length
    // is independent of the declared cap. The ledger budget covers checkpoint
    // plus WAL (header, base frame, fsynced transactions). Measured for this
    // fixture: a reserve costs 2*checkpoint + 267 bytes (641 with checkpoint
    // 187), while publishing the split with accepted evidence costs
    // checkpoint + 1287 bytes (1474). Declare the measured window in between
    // so the first reserve and the fork succeed but accepted evidence is
    // refused before it can be published.
    let probe_path = fixture.dir.join("probe.ledger");
    let probe_manifest = manifest(&fixture.elf, runtime.load_elf(&fixture.elf)?.pc()?, 1024 * 1024);
    let probe = SustainedCampaign::open(&probe_path, probe_manifest, &artifacts(&fixture.elf), initial)?;
    let checkpoint_bytes = std::fs::metadata(&probe_path)?.len();
    drop(probe);
    let disk = checkpoint_bytes * 2 + 512;
    let manifest = manifest(&fixture.elf, runtime.load_elf(&fixture.elf)?.pc()?, disk);
    let path = fixture.dir.join("bounded.ledger");
    let mut campaign = SustainedCampaign::open(&path, manifest.clone(), &artifacts(&fixture.elf), initial)?;
    let mut solver = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
    assert!(
        session
            .run_sustained(&mut campaign, &mut solver, Duration::from_secs(10))
            .is_err()
    );
    assert_eq!(
        session.states.len(),
        2,
        "fork was executed before publication was refused"
    );
    assert_eq!(campaign.report().completed, 0);
    assert!(!campaign.report().complete_within_declared_bounds);
    drop(campaign);
    let reopened = SustainedCampaign::open(&path, manifest, &artifacts(&fixture.elf), initial)?;
    assert_eq!(reopened.report().completed, 0);
    assert!(!reopened.report().complete_within_declared_bounds);
    Ok(())
}
