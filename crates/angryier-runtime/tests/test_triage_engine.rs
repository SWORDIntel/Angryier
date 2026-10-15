use angryier_runtime::triage::{PrimitiveKind, TriageEngine};
use std::process::Command;

#[test]
fn test_arbitrary_write_verification() {
    let proof = TriageEngine::verify_write_primitive(
        0x140001050,
        "mov qword ptr [rcx], rdx",
        true, // dest_symbolic
        true, // val_symbolic
        0x0,
        0xFFFF_FFFF_FFFF_FFFF,
        "[rcx] derived from user buffer offset 0x18",
        "rdx derived from user buffer offset 0x20",
    );

    assert_eq!(proof.kind, PrimitiveKind::ArbitraryWrite);
    assert!(proof.root_cause_explanation.contains("user-controlled pointer"));
    assert!(proof.remediation_guidance.contains("ProbeForWrite"));
}

#[test]
fn test_double_free_pool_violation_verification() {
    let proof = TriageEngine::verify_pool_violation(
        PrimitiveKind::DoubleFree,
        0x140002200,
        0xFFFF_A000_1234_5678,
        0x140002250,
        Some(0x140002100),
    );

    assert_eq!(proof.kind, PrimitiveKind::DoubleFree);
    assert!(proof.where_expr.contains("0xffffa00012345678"));
    assert!(proof.what_expr.contains("0x140002250"));
    assert!(proof.root_cause_explanation.contains("freed twice"));
}

#[test]
fn test_poc_triage_c_compilation_and_execution() {
    let proof = TriageEngine::verify_pool_violation(
        PrimitiveKind::DoubleFree,
        0x140002200,
        0xFFFF_A000_1234_5678,
        0x140002250,
        Some(0x140002100),
    );

    let poc_c = TriageEngine::generate_poc_triage_c(&proof, "VulnerableDriver.sys");
    assert!(poc_c.contains("KP15 Automated Triage & Patch Verification Harness"));
    assert!(poc_c.contains("run_triage_test"));
    assert!(poc_c.contains("signal_handler"));

    // Write to a temporary file and verify it compiles with gcc
    let tmp_dir = std::env::temp_dir();
    let src_path = tmp_dir.join("poc_triage_test.c");
    let bin_path = tmp_dir.join("poc_triage_test_bin");

    std::fs::write(&src_path, &poc_c).expect("write poc_triage_test.c");

    let compile_status = Command::new("gcc")
        .args([
            "-Wall",
            "-Wextra",
            "-Werror",
            src_path.to_str().unwrap(),
            "-o",
            bin_path.to_str().unwrap(),
        ])
        .status();

    if let Ok(status) = compile_status {
        assert!(status.success(), "gcc failed to compile generated poc_triage.c");

        // Run the compiled binary
        let run_status = Command::new(&bin_path).status().expect("execute poc_triage binary");
        assert!(run_status.success(), "poc_triage execution failed");

        // Cleanup
        let _ = std::fs::remove_file(&src_path);
        let _ = std::fs::remove_file(&bin_path);
    } else {
        eprintln!("gcc not available on host, skipped execution test");
    }
}
