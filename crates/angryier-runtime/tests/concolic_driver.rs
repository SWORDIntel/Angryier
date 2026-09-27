//! Concolic-vs-concrete fidelity on REAL drivers: the EXPLORE fast path
//! must produce the same execution (step count, termination, exit value)
//! as the concrete interpreter on the same driver, and report its shadow
//! debt via `requires_prove` instead of silently diverging.
#![cfg(feature = "xed")]
use std::sync::Arc;

use angryier_expr::ShardedExprArena;
use angryier_runtime::Runtime;
use angryier_types::{ExpressionNormalizationVersion, SemanticVersion, TargetProfileId};

fn driver_image(name: &str) -> Option<Vec<u8>> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/home/john".to_string());
    let dir = format!("{home}/Documents/driver_analysis/drivers/sources/caledonia-drivers/bin-elastic");
    std::fs::read(format!("{dir}/{name}")).ok()
}

fn run_concrete(
    runtime: &Runtime<angryier_runtime::XedFormTranslator<angryier_arch_xed_ffi::XedDecoder>>,
    image: &[u8],
) -> Option<(u64, u64)> {
    let mut process = runtime.load_pe_driver(image).ok()?;
    let tracker = std::sync::Arc::new(angryier_models::KernelPoolTracker::new());
    let _ = runtime.attach_kernel_pool_model(&mut process, tracker.clone());
    let mut steps = 0u64;
    for _ in 0..5000 {
        if runtime.step(&mut process).is_err() {
            return None;
        }
        steps += 1;
        if process.terminated {
            break;
        }
    }
    let rax = process
        .read_register(angryier_arch_intel64::register_id::GPR_BASE)
        .ok()?;
    Some((steps, rax))
}

fn run_concolic(
    runtime: &Runtime<angryier_runtime::XedFormTranslator<angryier_arch_xed_ffi::XedDecoder>>,
    image: &[u8],
) -> Option<(u64, u64, bool)> {
    let mut process = runtime.load_pe_driver(image).ok()?;
    let tracker = std::sync::Arc::new(angryier_models::KernelPoolTracker::new());
    let _ = runtime.attach_kernel_pool_model(&mut process, tracker.clone());
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = runtime.concolic(process, arena.as_ref());
    let mut steps = 0u64;
    for _ in 0..5000 {
        if session.step().is_err() {
            return None;
        }
        steps += 1;
        if session.process.terminated {
            break;
        }
    }
    let rax = session
        .process
        .read_register(angryier_arch_intel64::register_id::GPR_BASE)
        .ok()?;
    Some((steps, rax, session.requires_prove()))
}

#[test]
fn concolic_matches_concrete_on_real_drivers() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut ran = 0;
    for name in ["GVCIDrv64.sys", "sandra_x64.sys"] {
        let Some(image) = driver_image(name) else {
            eprintln!("SKIP {name}: fixture absent");
            continue;
        };
        let Some((c_steps, c_rax)) = run_concrete(&runtime, &image) else {
            eprintln!("{name}: concrete run failed");
            continue;
        };
        let Some((x_steps, x_rax, debt)) = run_concolic(&runtime, &image) else {
            eprintln!("{name}: concolic run failed");
            continue;
        };
        ran += 1;
        eprintln!(
            "{name}: concrete={c_steps} steps rax={c_rax:#x} | concolic={x_steps} steps rax={x_rax:#x} requires_prove={debt}"
        );
        assert_eq!(
            (c_steps, c_rax),
            (x_steps, x_rax),
            "{name}: concolic diverged from concrete"
        );
    }
    assert!(ran > 0, "no drivers ran");
    Ok(())
}
