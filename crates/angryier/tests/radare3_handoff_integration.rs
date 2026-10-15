use std::path::PathBuf;
use std::process::Command;

use angryier::Engine;
use angryier::driver_ioctl::StaticHandoff;

fn find_radare3_binary() -> Option<PathBuf> {
    let candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../radare3/target/debug/radare3");
    if candidate.is_file() {
        return Some(candidate);
    }
    let release_candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../radare3/target/release/radare3");
    if release_candidate.is_file() {
        return Some(release_candidate);
    }
    None
}

fn harness_fixture(name: &str) -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../byovd-harness/ghidra_pipeline/fixtures/bin")
        .join(name);
    path.is_file().then_some(path)
}

#[test]
fn radare3_native_handoff_to_angryier_pipeline() {
    let Some(r3_bin) = find_radare3_binary() else {
        eprintln!("SKIP: radare3 binary not built yet");
        return;
    };
    let Some(driver_path) = harness_fixture("allocsize_overflow_vuln_O2.sys") else {
        eprintln!("SKIP: driver fixture not found");
        return;
    };

    // 1. Run radare3 export-handoff
    let output = Command::new(&r3_bin)
        .args(["export-handoff", driver_path.to_str().unwrap()])
        .output()
        .expect("radare3 export-handoff command failed");
    assert!(output.status.success(), "radare3 export-handoff exited non-zero");

    let stdout = String::from_utf8(output.stdout).expect("valid utf8 output from radare3");

    // 2. Ingest native handoff envelope into Angryier
    let handoff = StaticHandoff::from_json(&stdout).expect("Angryier failed to ingest native handoff");

    assert_eq!(handoff.arch, "x64");
    assert_eq!(handoff.producer.as_deref(), Some("radare3 0.0.1"));
    assert!(!handoff.targets.is_empty(), "expected targets extracted by radare3");

    // Find RtlCopyMemory target hint
    let rtl_target = handoff
        .targets
        .iter()
        .find(|t| t.sink_name == "RtlCopyMemory")
        .expect("RtlCopyMemory target must be extracted");
    assert_eq!(rtl_target.confidence.as_deref(), Some("HIGH"));
    assert_eq!(rtl_target.static_finding_rule.as_deref(), Some("driver_dispatch_sink"));

    // 3. Resolve execution targets against image base
    let driver_targets = handoff.to_driver_targets();
    assert!(!driver_targets.is_empty());

    let (_, ioctl_targets) = driver_targets
        .iter()
        .find(|(t, _)| t.sink_name == "RtlCopyMemory")
        .expect("driver targets must include RtlCopyMemory");
    assert!(!ioctl_targets.is_empty());

    let target = ioctl_targets[0];
    assert!(target.handler_va > handoff.image_base);
    assert!(target.sink_va > handoff.image_base);

    // 4. Test Engine loading the driver image
    let engine = Engine::new().expect("engine construction");
    let image = engine.load(&driver_path).expect("driver image load");
    assert_eq!(image.kind(), angryier::ImageKind::PeDriver);
}
