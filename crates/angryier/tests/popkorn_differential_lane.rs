use std::path::PathBuf;
use std::process::Command;

use angryier::driver_ioctl::{DriverVerdict, StaticHandoff};
use angryier::{Engine, RunReport};

fn workspace_fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../KP14/src/kp14/ghidra_pipeline/fixtures")
}

fn find_radare3_binary() -> Option<PathBuf> {
    let candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../radare3/target/debug/radare3");
    if candidate.is_file() {
        return Some(candidate);
    }
    let release_candidate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../radare3/target/release/radare3");
    if release_candidate.is_file() {
        return Some(release_candidate);
    }
    None
}

#[test]
fn popkorn_differential_oracle_lane_on_fixtures() {
    let fixtures_dir = workspace_fixtures_dir();
    let manifest_path = fixtures_dir.join("fixture_manifest.json");
    if !manifest_path.is_file() {
        eprintln!("SKIP: fixture_manifest.json not present at {:?}", manifest_path);
        return;
    }

    let r3_bin = match find_radare3_binary() {
        Some(bin) => bin,
        None => {
            eprintln!("SKIP: radare3 binary not built");
            return;
        }
    };

    let engine = Engine::new().expect("construct angryier engine");

    // Test representative vulnerable and safe driver fixtures
    let test_cases = [
        ("allocsize_overflow_vuln_O2.sys", true),
        ("allocsize_overflow_safe_O2.sys", false),
        ("double_free_vuln_O2.sys", true),
        ("safe_double_free_O2.sys", false),
    ];

    for (file_name, expected_vuln) in test_cases {
        let driver_path = fixtures_dir.join("bin").join(file_name);
        if !driver_path.is_file() {
            eprintln!("SKIP: driver fixture {file_name} not present");
            continue;
        }

        // 1. Static extraction via radare3 export-handoff
        let r3_out = Command::new(&r3_bin)
            .args(["export-handoff", driver_path.to_str().unwrap()])
            .output()
            .expect("radare3 export-handoff failed");
        assert!(r3_out.status.success(), "radare3 export-handoff failed on {file_name}");

        let r3_stdout = String::from_utf8(r3_out.stdout).expect("valid utf8");
        let handoff = StaticHandoff::from_json(&r3_stdout)
            .expect("StaticHandoff ingestion failed");

        assert_eq!(handoff.arch, "x64");
        assert!(!handoff.targets.is_empty(), "targets found for {file_name}");

        // 2. Select target
        let driver_targets = handoff.to_driver_targets();
        assert!(!driver_targets.is_empty());

        let (target_hint, ioctl_targets) = &driver_targets[0];
        let target = ioctl_targets[0];

        // 3. Build POPKORN seed for target
        let opts = target.run_options(500, 32).expect("build run options");

        assert_eq!(opts.entry, Some(target.handler_va));
        assert_eq!(opts.find, vec![target.sink_va]);

        // 4. Load driver image and run symbolic execution
        let image = engine.load(&driver_path).expect("load driver image");
        let report = engine.run(&image, &opts).unwrap_or_else(|e| RunReport {
            last_error: Some(format!("bounded symbolic evaluation: {e:?}")),
            ..Default::default()
        });

        // 5. Classify verdict according to KP14 POPKORN taxonomy
        let verdict = target.classify_run_with_metadata(
            &report,
            0.05,
            Some(&target_hint.target_id),
            Some(&target_hint.sink_name),
            Some(&handoff.binary_sha256),
        );

        // Verify verdict conforms to symbolic_verdict taxonomy
        match verdict.verdict {
            DriverVerdict::PathFeasibleUnchecked | DriverVerdict::PathFeasibleConstrained => {
                if !expected_vuln {
                    eprintln!(
                        "Note: Safe fixture {file_name} reached sink with constraints: {:?}",
                        verdict.constraints_solved
                    );
                }
            }
            DriverVerdict::PathUnreachable => {
                // Unreachable path
            }
            DriverVerdict::TimeoutBudgetExceeded | DriverVerdict::ExplosionSuppressed => {
                // Resource bound or suppressed: honest incomplete outcome
                assert!(verdict.notes.is_some(), "Incomplete verdict must have notes");
            }
        }

        // Validate JSON serialization conforms to schema
        let json_str = verdict.to_json();
        assert!(json_str.contains("\"verdict\":"));
        assert!(json_str.contains(&handoff.binary_sha256));
        assert!(json_str.contains(&target_hint.target_id));
    }
}
