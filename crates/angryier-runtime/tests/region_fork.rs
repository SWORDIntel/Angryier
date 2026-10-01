//! Region-forking fallback, end to end: a block computes a pointer through
//! a scalar float primitive (an under-constrained debt symbol — xmm
//! registers carry no concrete shadow) and dereferences it. With the
//! solver-assisted retry budget spent, the unresolved address expression
//! cannot fold concretely; in fork-aggressive mode (`fork_on_symbolic`)
//! with the region-fork cap armed, the state forks over its largest mapped
//! RW regions — one child per region under the cap, each pinning the
//! address to a deterministic representative address inside that region —
//! while the parent keeps its historical fallback behavior (fabricated UC
//! pin page when armed, state failure when not). Every pin is
//! debt-recorded on the session and surfaced through the run report.
//!
//! Requires the `xed` + `z3` features and system binutils; skipped (not
//! failed) when the toolchain is unavailable.

#![cfg(all(feature = "xed", feature = "z3"))]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use angryier_expr::ShardedExprArena;
use angryier_memory::LayeredMemory;
use angryier_runtime::{
    ExplorationPolicy, Runtime, SymbolicSession, region_fork_cap_from_env_value, region_fork_representative_address,
};
use angryier_types::{Address, ExpressionNormalizationVersion, SemanticVersion, TargetProfileId};

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

fn build_fixture() -> Option<Vec<u8>> {
    let dir = temp_dir("angryier-region-fork")?;
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

type Session<'a> = SymbolicSession<'a, angryier_runtime::XedFormTranslator<angryier_arch_xed_ffi::XedDecoder>>;

fn symbolic_session<'a>(
    runtime: &'a Runtime<angryier_runtime::XedFormTranslator<angryier_arch_xed_ffi::XedDecoder>>,
    arena: &'a ShardedExprArena,
    elf: &[u8],
) -> Session<'a> {
    let process = runtime.load_elf(elf).expect("load elf");
    SymbolicSession::new(runtime, arena, process)
}

/// The session's mapped RW regions (readable AND writable), largest first
/// then by base — the exact enumeration the fallback forks over.
fn rw_regions(session: &Session<'_>) -> Vec<(Address, u64)> {
    let mut regions: Vec<(Address, u64)> = session.states[0]
        .process
        .state
        .memory
        .regions()
        .iter()
        .filter(|region| region.readable && region.writable && region.size > 0)
        .map(|region| (region.base, region.size))
        .collect();
    regions.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    regions
}

/// Pins a hook for the exit syscall so terminated states are observable.
fn hook_exit(session: &mut Session<'_>) {
    let exit = session.states[0]
        .process
        .symbol("exit")
        .expect("missing exit symbol")
        .address;
    session.states[0].process.hook_simproc(exit, "exit");
}

/// The cap parser: unset, empty, non-numeric, zero, and overflowing values
/// disable region forking; positive values arm it with that cap.
#[test]
fn region_fork_cap_parsing() {
    assert_eq!(region_fork_cap_from_env_value(None), None, "unset disables");
    assert_eq!(
        region_fork_cap_from_env_value(Some("".as_ref())),
        None,
        "empty disables"
    );
    assert_eq!(
        region_fork_cap_from_env_value(Some("0".as_ref())),
        None,
        "zero disables"
    );
    assert_eq!(
        region_fork_cap_from_env_value(Some("garbage".as_ref())),
        None,
        "garbage disables"
    );
    assert_eq!(
        region_fork_cap_from_env_value(Some(" 8 ".as_ref())),
        Some(8),
        "trimmed 8 arms with cap 8"
    );
    assert_eq!(
        region_fork_cap_from_env_value(Some("1".as_ref())),
        Some(1),
        "1 arms with cap 1"
    );
    assert_eq!(
        region_fork_cap_from_env_value(Some("99999999999999999999".as_ref())),
        None,
        "overflow disables rather than wrapping"
    );
}

/// The representative-address derivation is deterministic, 16-byte
/// aligned, and stays inside its region for every (expr, region) pair.
#[test]
fn region_fork_representative_address_is_deterministic_and_inside_region() {
    let regions: [(Address, u64); 3] = [(0x1000, 0x2000), (0x1_0000, 16), (0x5000, 4097)];
    for (base, size) in regions {
        for expr in [
            angryier_types::ExprId(0),
            angryier_types::ExprId(1),
            angryier_types::ExprId(0xdead_beef),
        ] {
            let pin = region_fork_representative_address(base, size, expr);
            let again = region_fork_representative_address(base, size, expr);
            assert_eq!(pin, again, "derivation must be deterministic");
            assert!(pin >= base, "pin {pin:#x} below region base {base:#x}");
            assert!(
                pin.wrapping_add(16) <= base.saturating_add(size) || size < 16,
                "pin {pin:#x} lets a 16-byte access escape [{base:#x}, +{size:#x})"
            );
            assert_eq!(pin % 16, 0, "pin {pin:#x} must be 16-byte aligned");
        }
    }
    // Distinct expressions in one region pin distinct addresses often
    // enough to matter (hash spread): with 512 slots, 32 distinct
    // expressions must not all collide onto one slot.
    let base = 0x2000;
    let size = 0x2000u64;
    let distinct: std::collections::BTreeSet<Address> = (0u32..32)
        .map(|i| region_fork_representative_address(base, size, angryier_types::ExprId(i)))
        .collect();
    assert!(
        distinct.len() > 1,
        "representative addresses must spread across the region"
    );
}

/// Flag-off default: without the programmatic cap and without
/// `ANGRYIER_REGION_FORK_MAX`, an unresolved address behaves exactly as
/// before — no region children, the state fails with UnresolvedAddress.
#[test]
fn region_fork_disabled_by_default_keeps_failure() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var_os("ANGRYIER_REGION_FORK_MAX").is_some() {
        eprintln!("skipping: ANGRYIER_REGION_FORK_MAX is set in the environment");
        return Ok(());
    }
    let Some(elf) = fixture() else {
        eprintln!("skipping: binutils (as/ld) unavailable");
        return Ok(());
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = symbolic_session(&runtime, arena.as_ref(), elf);
    hook_exit(&mut session);
    // Fork-aggressive mode, cap NOT armed: the gate must hold.
    session.set_unresolved_retry_budget(0);
    assert_eq!(session.region_fork_max(), 0, "cap must default to off");

    let mut backend = angryier_solver_z3::Z3Backend::native_ffi(arena.clone() as Arc<dyn angryier_expr::ExprReader>)?;
    let policy = ExplorationPolicy {
        fork_on_symbolic: true,
        ..Default::default()
    };
    let report = session.run_with_policy(64, 16, Some(&mut backend), Duration::from_secs(60), true, &policy)?;

    assert_eq!(
        report.region_fork_children, 0,
        "no region children may be created flag-off"
    );
    assert_eq!(session.region_fork_children_total(), 0);
    assert!(session.region_fork_sites().is_empty());
    assert_eq!(report.failed, 1, "the unresolved load must still fail the state");
    assert!(
        report
            .last_error
            .as_deref()
            .is_some_and(|e| e.contains("UnresolvedAddress")),
        "last_error must name UnresolvedAddress, got {:?}",
        report.last_error
    );
    Ok(())
}

/// Armed cap in fork mode: the unresolved address forks one child per
/// mapped RW region under the cap, each pinned to a distinct region's
/// representative address; the parent (no UC pin fallback here) keeps the
/// historical failure.
#[test]
fn region_fork_forks_one_child_per_rw_region_under_cap() -> Result<(), Box<dyn std::error::Error>> {
    let Some(elf) = fixture() else {
        eprintln!("skipping: binutils (as/ld) unavailable");
        return Ok(());
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = symbolic_session(&runtime, arena.as_ref(), elf);
    hook_exit(&mut session);
    let expected_regions = rw_regions(&session);
    assert!(!expected_regions.is_empty(), "fixture must map at least one RW region");
    let expected = expected_regions.len().min(8);

    session.set_unresolved_retry_budget(0);
    session.set_region_fork_max(8);
    assert_eq!(session.region_fork_max(), 8);

    let mut backend = angryier_solver_z3::Z3Backend::native_ffi(arena.clone() as Arc<dyn angryier_expr::ExprReader>)?;
    let policy = ExplorationPolicy {
        fork_on_symbolic: true,
        dfs: true,
        ..Default::default()
    };
    let report = session.run_with_policy(256, 64, Some(&mut backend), Duration::from_secs(120), true, &policy)?;
    eprintln!("[dbg] report = {report:?}");
    eprintln!("[dbg] sites = {:?}", session.region_fork_sites());

    assert_eq!(
        report.region_fork_children, expected as u64,
        "one child per RW region under the cap (regions: {expected_regions:?})"
    );
    assert_eq!(session.region_fork_children_total(), report.region_fork_children);
    assert_eq!(
        session.region_fork_sites().len(),
        expected,
        "every pin is debt-recorded"
    );

    // Distinct pinned regions, pins inside their region, deterministic
    // representative addresses.
    let mut seen_bases: Vec<Address> = Vec::new();
    for site in session.region_fork_sites() {
        assert!(
            expected_regions
                .iter()
                .any(|&(base, size)| base == site.region_base && size == site.region_size),
            "forked region [{:#x}, +{:#x}) is not one of the mapped RW regions",
            site.region_base,
            site.region_size
        );
        assert!(
            site.pinned >= site.region_base && site.pinned < site.region_base.saturating_add(site.region_size),
            "pin {:#x} outside region [{:#x}, +{:#x})",
            site.pinned,
            site.region_base,
            site.region_size
        );
        assert_eq!(
            site.pinned,
            region_fork_representative_address(site.region_base, site.region_size, site.expr),
            "pins must use the documented derivation"
        );
        seen_bases.push(site.region_base);
    }
    seen_bases.dedup();
    assert_eq!(seen_bases.len(), expected, "children pin DISTINCT regions");

    // The parent keeps the historical behavior: no UC pin fallback armed,
    // so it failed on the unresolved load while every child ran to exit.
    assert_eq!(report.failed, 1, "parent must keep the unresolved failure");
    assert!(
        report
            .last_error
            .as_deref()
            .is_some_and(|e| e.contains("UnresolvedAddress")),
        "parent last_error must name UnresolvedAddress, got {:?}",
        report.last_error
    );
    // Children outlive the parent, but `merge_each_step` may fold them
    // together when they converge: here the loaded `eax` is immediately
    // overwritten by `mov $60, %rax`, so both children reach `exit` with
    // structurally identical register state and merge. Every child then
    // either terminated on its own or merged into a survivor — none failed
    // (`failed == 1` is the parent alone, asserted above).
    assert!(
        report.terminated + report.merges >= expected as u64,
        "children must outlive the parent's failure (terminated={}, merges={})",
        report.terminated,
        report.merges
    );
    Ok(())
}

/// Cap economics: a cap of 1 forks exactly one child, pinned into the
/// LARGEST mapped RW region.
#[test]
fn region_fork_cap_one_pins_largest_region() -> Result<(), Box<dyn std::error::Error>> {
    let Some(elf) = fixture() else {
        eprintln!("skipping: binutils (as/ld) unavailable");
        return Ok(());
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = symbolic_session(&runtime, arena.as_ref(), elf);
    hook_exit(&mut session);
    let largest = rw_regions(&session)[0];

    session.set_unresolved_retry_budget(0);
    session.set_region_fork_max(1);

    let mut backend = angryier_solver_z3::Z3Backend::native_ffi(arena.clone() as Arc<dyn angryier_expr::ExprReader>)?;
    let policy = ExplorationPolicy {
        fork_on_symbolic: true,
        ..Default::default()
    };
    let report = session.run_with_policy(64, 16, Some(&mut backend), Duration::from_secs(60), true, &policy)?;

    assert_eq!(report.region_fork_children, 1, "cap 1 bounds children to one");
    let site = session.region_fork_sites()[0];
    assert_eq!(
        (site.region_base, site.region_size),
        largest,
        "the single child takes the largest RW region"
    );
    Ok(())
}

/// Parent fallback unchanged: with the UC pin fallback armed alongside
/// region forking, the parent still pins its fabricated page (and
/// completes), while the region children pin inside real mapped regions.
///
/// The pin fallback pairs with the `uc_memory` policy, armed on the
/// process memory BEFORE the session is built — the same wiring as the
/// script surface (`script/mod.rs`): the fabricated pin page is only
/// zero-backed under that policy, and without it the parent's pinned load
/// faults `Unmapped` instead of completing.
#[test]
fn region_fork_parent_keeps_uc_pin_fallback() -> Result<(), Box<dyn std::error::Error>> {
    let Some(elf) = fixture() else {
        eprintln!("skipping: binutils (as/ld) unavailable");
        return Ok(());
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut process = runtime.load_elf(elf).expect("load elf");
    process.state.memory = process.state.memory.with_uc_memory();
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    hook_exit(&mut session);
    let expected = rw_regions(&session).len().min(8);

    session.set_unresolved_retry_budget(0);
    session.set_region_fork_max(8);
    session = session.with_uc_pin_fallback();

    let mut backend = angryier_solver_z3::Z3Backend::native_ffi(arena.clone() as Arc<dyn angryier_expr::ExprReader>)?;
    let policy = ExplorationPolicy {
        fork_on_symbolic: true,
        ..Default::default()
    };
    let report = session.run_with_policy(256, 64, Some(&mut backend), Duration::from_secs(120), true, &policy)?;

    assert_eq!(report.region_fork_children, expected as u64);
    assert_eq!(
        report.failed, 0,
        "the parent must keep its fabricated-page fallback (last_error: {:?})",
        report.last_error
    );
    // Every region child pinned into the REAL mapped RW region its site
    // recorded. Membership is the distinguishing property — NOT "below the
    // fabricated-page base": the linker places the stack region around
    // 0x7fff_0000_0000, numerically ABOVE the fabricated base
    // (0x5000_0000_0000), so a legitimate region child can pin above it.
    for site in session.region_fork_sites() {
        assert!(
            site.pinned >= site.region_base && site.pinned < site.region_base.saturating_add(site.region_size),
            "region child pin {:#x} outside its recorded region [{:#x}, +{:#x})",
            site.pinned,
            site.region_base,
            site.region_size
        );
    }
    // Parent and children all complete — but like the cap test above,
    // `merge_each_step` may fold converging children together (their
    // loaded `eax` is immediately overwritten), so count merges alongside
    // terminations. `failed == 0` above already proves nobody died.
    assert!(
        report.terminated + report.merges >= expected as u64 + 1,
        "parent and children all complete (terminated={}, merges={})",
        report.terminated,
        report.merges
    );
    Ok(())
}

/// Concolic default (fork mode OFF): even with the cap armed, no region
/// children — the fallback is a fork-aggressive-mode lever only.
#[test]
fn region_fork_requires_fork_mode() -> Result<(), Box<dyn std::error::Error>> {
    let Some(elf) = fixture() else {
        eprintln!("skipping: binutils (as/ld) unavailable");
        return Ok(());
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = symbolic_session(&runtime, arena.as_ref(), elf);
    hook_exit(&mut session);

    session.set_unresolved_retry_budget(0);
    session.set_region_fork_max(8);

    let mut backend = angryier_solver_z3::Z3Backend::native_ffi(arena.clone() as Arc<dyn angryier_expr::ExprReader>)?;
    let report = session.run_with_policy(
        64,
        16,
        Some(&mut backend),
        Duration::from_secs(60),
        true,
        &ExplorationPolicy::default(),
    )?;

    assert_eq!(report.region_fork_children, 0, "concolic default must not region-fork");
    assert_eq!(session.region_fork_children_total(), 0);
    Ok(())
}
