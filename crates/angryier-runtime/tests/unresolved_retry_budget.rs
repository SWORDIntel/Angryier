//! Solver-assisted address-concretization budget, end to end: a block
//! computes a pointer through a scalar float primitive (a debt symbol in the
//! symbolic evaluator — xmm registers carry no concrete shadow) and
//! dereferences it. The address expression contains a fresh under-constrained
//! symbol: it cannot fold concretely, so the retry loop must solve
//! `address == free` under the mapped-region bounds, pin the model's value,
//! and re-run the block — which only converges because fresh symbols rebuild
//! identically across re-evaluations (block-local symbol ids). The budget
//! gates how many distinct unresolved addresses one step may pin.
//!
//! Requires the `xed` + `z3` features and system binutils; skipped (not
//! failed) when the toolchain is unavailable.

#![cfg(all(feature = "xed", feature = "z3"))]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use angryier_arch_intel64::register_id;
use angryier_expr::ShardedExprArena;
use angryier_runtime::{ExplorationPolicy, Runtime, UNRESOLVED_ADDRESS_RETRY_BUDGET};
use angryier_types::{ExpressionNormalizationVersion, SemanticVersion, TargetProfileId};

/// Computes a pointer through a scalar double add (xmm registers carry no
/// concrete shadow in the symbolic evaluator, so the result is a debt
/// symbol), dereferences it, then exits.
const FIXTURE_SOURCE: &str = r"
    .global _start
    .text
_start:
    addsd %xmm1, %xmm0
    movq %xmm0, %rax
    mov (%rax), %eax
    mov $60, %rax
    xor %rdi, %rdi
exit:
    syscall
";

fn temp_dir(name: &str) -> Option<PathBuf> {
    let dir = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

fn assemble(source: &Path, object: &Path) -> Option<()> {
    let output = Command::new("as").arg("--64").arg("-o").arg(object).arg(source).output().ok()?;
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

fn build_fixture() -> Option<Vec<u8>> {
    let dir = temp_dir("angryier-retry-budget")?;
    let source = dir.join("fixture.s");
    let object = dir.join("fixture.o");
    let binary = dir.join("fixture.elf");
    std::fs::write(&source, FIXTURE_SOURCE).ok()?;
    assemble(&source, &object)?;
    link(&binary, &[&object])?;
    std::fs::read(&binary).ok()
}

fn fixture() -> Option<&'static Vec<u8>> {
    static FIXTURE: std::sync::OnceLock<Option<Vec<u8>>> = std::sync::OnceLock::new();
    FIXTURE.get_or_init(build_fixture).as_ref()
}

fn symbolic_session<'a>(
    runtime: &'a Runtime<angryier_runtime::XedFormTranslator<angryier_arch_xed_ffi::XedDecoder>>,
    arena: &'a ShardedExprArena,
    elf: &[u8],
) -> angryier_runtime::SymbolicSession<'a, angryier_runtime::XedFormTranslator<angryier_arch_xed_ffi::XedDecoder>> {
    let process = runtime.load_elf(elf).expect("load elf");
    let mut session = angryier_runtime::SymbolicSession::new(runtime, arena, process);
    session
}

#[test]
fn default_retry_budget_pins_symbolic_load_and_counts_attempts() -> Result<(), Box<dyn std::error::Error>> {
    let Some(elf) = fixture() else {
        eprintln!("skipping: binutils (as/ld) unavailable");
        return Ok(());
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = symbolic_session(&runtime, arena.as_ref(), elf);

    // The default budget is the documented constant.
    assert_eq!(session.unresolved_retry_budget(), UNRESOLVED_ADDRESS_RETRY_BUDGET);
    assert_eq!(UNRESOLVED_ADDRESS_RETRY_BUDGET, 16);

    // The exit syscall is dispatched through the SimProc hook.
    let mut backend = angryier_solver_z3::Z3Backend::native_ffi(arena.clone() as Arc<dyn angryier_expr::ExprReader>)?;
    {
        let exit = session.states[0].process.symbol("exit").expect("missing exit symbol").address;
        session.states[0].process.hook_simproc(exit, "exit");
    }
    let policy = ExplorationPolicy::default();
    let report = session.run_with_policy(64, 4, Some(&mut backend), Duration::from_secs(60), true, &policy)?;

    assert_eq!(report.concretization_retries, session.concretization_retries_total());
    assert!(
        report.concretization_retries >= 1,
        "the symbolic-pointer dereference must have triggered at least one concretization attempt"
    );
    assert_eq!(
        report.failed, 0,
        "with budget available the pinned re-evaluation must converge (last_error: {:?})",
        report.last_error
    );
    assert!(
        report.terminated >= 1,
        "the state must progress past the load to the exit simproc"
    );
    Ok(())
}

#[test]
fn zero_retry_budget_keeps_the_unresolved_address_failure() -> Result<(), Box<dyn std::error::Error>> {
    let Some(elf) = fixture() else {
        eprintln!("skipping: binutils (as/ld) unavailable");
        return Ok(());
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = symbolic_session(&runtime, arena.as_ref(), elf);
    session.set_unresolved_retry_budget(0);

    let mut backend = angryier_solver_z3::Z3Backend::native_ffi(arena.clone() as Arc<dyn angryier_expr::ExprReader>)?;
    {
        let exit = session.states[0].process.symbol("exit").expect("missing exit symbol").address;
        session.states[0].process.hook_simproc(exit, "exit");
    }
    let policy = ExplorationPolicy::default();
    let report = session.run_with_policy(64, 4, Some(&mut backend), Duration::from_secs(60), true, &policy)?;

    assert_eq!(
        report.concretization_retries, 0,
        "a zero budget must gate every concretization attempt"
    );
    assert_eq!(report.failed, 1, "the load must stay unresolved");
    assert!(
        report.last_error.as_deref().is_some_and(|e| e.contains("UnresolvedAddress")),
        "last_error must name UnresolvedAddress, got {:?}",
        report.last_error
    );
    Ok(())
}
