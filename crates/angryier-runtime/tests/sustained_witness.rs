#![cfg(all(feature = "xed", feature = "script", target_arch = "x86_64"))]
use std::{process::Command, sync::Arc, time::Duration};

use angryier_arch_intel64::register_id;
use angryier_distribution::contracts::{CampaignArtifacts, CampaignManifest, CampaignSpec, Digest, ExplorationLimits};
use angryier_expr::{ExprReader, ShardedExprArena};
use angryier_ir::IrType;
use angryier_provenance::sustained::ReplayVerification;
use angryier_runtime::{Runtime, SymbolicSession, sustained::SustainedCampaign};
use angryier_solver::{SolverBackend, SolverQuery, SolverResult};
use angryier_solver_z3::Z3Backend;
use angryier_types::{ConstraintId, ExpressionNormalizationVersion, FidelityProfile, SemanticVersion, TargetProfileId};

struct Tampered<B> {
    native: B,
    mode: &'static str,
}
impl<B: SolverBackend> SolverBackend for Tampered<B> {
    fn name(&self) -> &'static str {
        "z3"
    }
    fn solve(&mut self, query: &SolverQuery) -> SolverResult {
        let mut result = self.native.solve(query);
        match self.mode {
            "missing" => result.model.clear(),
            "duplicate" if !result.model.is_empty() => {
                let mut bad = result.model[0].clone();
                bad.1[0] ^= 1;
                result.model.push(bad);
            }
            "wrong" if !result.model.is_empty() => result.model[0].1[0] = 0xff,
            _ => {}
        }
        result
    }
    fn solve_batch(&mut self, _: &[ConstraintId], predicates: &[SolverQuery]) -> Vec<SolverResult> {
        predicates.iter().map(|query| self.solve(query)).collect()
    }
}

#[test]
fn native_z3_register_model_has_independent_durable_replay() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!("angryier-witness-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let elf_path = dir.join("fixture.elf");
    let asm = dir.join("fixture.s");
    let obj = dir.join("fixture.o");
    std::fs::write(
        &asm,
        ".global _start\n.text\n_start:\n cmp $5, %rbx\n je equal\n mov $1, %rdi\n jmp exit\nequal:\n xor %rdi, %rdi\nexit:\n mov $60, %rax\n syscall\n",
    )?;
    assert!(
        Command::new("as")
            .args(["--64", "-o", obj.to_str().ok_or("obj")?, asm.to_str().ok_or("asm")?])
            .status()?
            .success()
    );
    assert!(
        Command::new("ld")
            .args(["-o", elf_path.to_str().ok_or("elf")?, obj.to_str().ok_or("obj")?])
            .status()?
            .success()
    );
    let elf = std::fs::read(&elf_path)?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), runtime.load_elf(&elf)?);
    session.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let initial = session.sustained_initial_digest()?;
    let manifest = CampaignManifest::seal(CampaignSpec {
        binary_digest: Digest::of(&elf),
        architecture: "x86_64".into(),
        entry_pc: session.states[0].process.pc()?,
        semantic_version: "1".into(),
        semantic_profile_digest: Digest::of(b"native-xed"),
        script_digest: Digest::of(b"driver"),
        policy_digest: Digest::of(b"policy"),
        inputs: vec![],
        stubs: vec![],
        solver_version: "z3".into(),
        solver_policy_digest: Digest::of(b"z3-default"),
        fidelity: FidelityProfile::Prove,
        limits: ExplorationLimits {
            max_steps: 100,
            max_path_steps: 100,
            max_active_states: 2,
            max_path_depth: 20,
            max_loop_visits: 20,
            max_solver_millis: 10_000,
            max_wall_millis: 30_000,
            max_ram_bytes: 64 * 1024 * 1024,
            max_disk_bytes: 1024 * 1024,
            max_trace_bytes: 1024 * 1024,
        },
    })?;
    let artifacts = CampaignArtifacts {
        binary: &elf,
        semantic_profile: b"native-xed",
        script: b"driver",
        policy: b"policy",
        solver_policy: b"z3-default",
        inputs: vec![],
        stubs: vec![],
    };
    let mut campaign = SustainedCampaign::open(dir.join("witness.ledger"), manifest.clone(), &artifacts, initial)?;
    let mut solver = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
    let run = session.run_sustained(&mut campaign, &mut solver, Duration::from_secs(15))?;
    assert_eq!(
        run.ledger.completed,
        2,
        "ledger: {:?}; paths: {:?}",
        run.ledger,
        run.evidence
            .report()
            .paths
            .iter()
            .map(|p| (
                p.blocks.len(),
                p.witness
                    .as_ref()
                    .map(|w| (&w.replay, w.replay_trace.len(), &w.replay_trace, &p.blocks))
            ))
            .collect::<Vec<_>>()
    );
    for path in run.evidence.report().paths {
        let witness = path.witness.as_ref().ok_or("missing witness")?;
        assert!(
            matches!(witness.replay, ReplayVerification::Verified { trace_digest } if trace_digest == path.provenance_digest),
            "{witness:?}"
        );
        assert_eq!(witness.replay_trace, path.blocks);
        assert!(witness.replay_input_provenance.is_some());
    }
    drop(campaign);
    let mut reopened = SustainedCampaign::open(dir.join("witness.ledger"), manifest.clone(), &artifacts, initial)?;
    assert_eq!(reopened.report().completed, 2);
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut fresh = SymbolicSession::new(&runtime, arena.as_ref(), runtime.load_elf(&elf)?);
    fresh.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let mut solver = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
    let persisted = fresh.run_sustained(&mut reopened, &mut solver, Duration::from_secs(5))?;
    assert_eq!(persisted.steps, 0);
    assert_eq!(persisted.evidence.report().summary.replay_verified_witnesses, 2);
    drop(reopened);
    for mode in ["missing", "duplicate", "wrong"] {
        let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
        let mut session = SymbolicSession::new(&runtime, arena.as_ref(), runtime.load_elf(&elf)?);
        session.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
        assert_eq!(session.sustained_initial_digest()?, initial);
        let path = dir.join(format!("{mode}.ledger"));
        let mut campaign = SustainedCampaign::open(&path, manifest.clone(), &artifacts, initial)?;
        let native = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
        let run = session.run_sustained(&mut campaign, &mut Tampered { native, mode }, Duration::from_secs(15))?;
        if mode != "wrong" {
            assert!(
                run.evidence.report().paths.iter().all(|path| !path
                    .witness
                    .as_ref()
                    .is_some_and(|w| matches!(w.replay, ReplayVerification::Verified { .. }))),
                "{mode}: ambiguous or absent model must never verify"
            );
        }
        assert!(
            run.evidence
                .report()
                .paths
                .iter()
                .all(|path| !path
                    .witness
                    .as_ref()
                    .is_some_and(
                        |w| matches!(w.replay, ReplayVerification::Verified { .. }) && w.replay_trace != path.blocks
                    ))
        );
        if mode == "missing" {
            assert_eq!(
                run.ledger.completed, 2,
                "legacy SAT-only terminal paths remain unverified"
            );
            assert!(run.evidence.report().paths.iter().all(|path| path.witness.is_none()));
        } else {
            assert!(
                run.ledger.deferred > 0,
                "{mode}: replay mismatch must retain the subtree"
            );
            assert!(!run.ledger.complete_within_declared_bounds);
        }
    }
    std::fs::remove_dir_all(dir)?;
    Ok(())
}
