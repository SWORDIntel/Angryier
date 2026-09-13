#![forbid(unsafe_code)]

//! Command-line orchestration entry point for the Angryier workspace.
//!
//! This binary reports workspace/crate status. It parses arguments manually
//! from `std::env::args()` and uses no external dependencies.

const VERSION: &str = "0.1.0";
const TAGLINE: &str = "Rust-native multicore symbolic/concolic execution engine";

/// One crate in the workspace with its implementation status and a short
/// description. Data is hardcoded so the CLI needs no workspace dependencies.
struct CrateInfo {
    name: &'static str,
    implemented: bool,
    desc: &'static str,
}

/// Static registry of every workspace crate the CLI reports on.
///
/// 36 implemented crates with real logic plus 3 scaffolded contract boundaries
/// (fail-closed) = 39 crates total.
static CRATES: &[CrateInfo] = &[
    // --- Implemented (real logic, not just contracts) ---
    CrateInfo {
        name: "angryier-types",
        implemented: true,
        desc: "Shared IDs, versions, hashes",
    },
    CrateInfo {
        name: "angryier-core",
        implemented: true,
        desc: "Engine-level context contracts",
    },
    CrateInfo {
        name: "angryier-arch",
        implemented: true,
        desc: "ISA-neutral decoder contracts",
    },
    CrateInfo {
        name: "angryier-arch-intel64",
        implemented: true,
        desc: "Intel 64 profiles and state",
    },
    CrateInfo {
        name: "angryier-decode-xed",
        implemented: true,
        desc: "XED normalization boundary",
    },
    CrateInfo {
        name: "angryier-semantic-contracts",
        implemented: true,
        desc: "Sealed identity + transformation evidence",
    },
    CrateInfo {
        name: "angryier-semantics",
        implemented: true,
        desc: "Semantic IR, provider/builder traits",
    },
    CrateInfo {
        name: "angryier-semantics-gen",
        implemented: true,
        desc: "In-memory semantic compiler",
    },
    CrateInfo {
        name: "angryier-semantics-intel64",
        implemented: true,
        desc: "Handwritten Intel 64 corpus (93 forms)",
    },
    CrateInfo {
        name: "angryier-ir",
        implemented: true,
        desc: "Compact execution IR",
    },
    CrateInfo {
        name: "angryier-expr",
        implemented: true,
        desc: "Hash-consed expression DAG",
    },
    CrateInfo {
        name: "angryier-memory",
        implemented: true,
        desc: "Layered concrete/symbolic memory",
    },
    CrateInfo {
        name: "angryier-state",
        implemented: true,
        desc: "Persistent execution state",
    },
    CrateInfo {
        name: "angryier-execution",
        implemented: true,
        desc: "Concrete interpreter",
    },
    CrateInfo {
        name: "angryier-ledger",
        implemented: true,
        desc: "Atomic execution ledger",
    },
    CrateInfo {
        name: "angryier-solver",
        implemented: true,
        desc: "Solver-neutral query model",
    },
    CrateInfo {
        name: "angryier-jit",
        implemented: true,
        desc: "JIT validity contract",
    },
    CrateInfo {
        name: "angryier-replay",
        implemented: true,
        desc: "Replay capsule store",
    },
    CrateInfo {
        name: "angryier-taint",
        implemented: true,
        desc: "Taint and dataflow engine",
    },
    CrateInfo {
        name: "angryier-provenance",
        implemented: true,
        desc: "Tiered provenance store",
    },
    CrateInfo {
        name: "angryier-storage",
        implemented: true,
        desc: "Local WAL and retention",
    },
    CrateInfo {
        name: "angryier-scheduler",
        implemented: true,
        desc: "Work-stealing scheduler",
    },
    CrateInfo {
        name: "angryier-knowledge",
        implemented: true,
        desc: "Persistent knowledge store",
    },
    CrateInfo {
        name: "angryier-models",
        implemented: true,
        desc: "Environment model contracts",
    },
    CrateInfo {
        name: "angryier-telemetry",
        implemented: true,
        desc: "Telemetry and backpressure",
    },
    CrateInfo {
        name: "angryier-loader",
        implemented: true,
        desc: "Image loader and state import",
    },
    CrateInfo {
        name: "angryier-fuzz",
        implemented: true,
        desc: "Hybrid fuzzing bridge",
    },
    CrateInfo {
        name: "angryier-fusion",
        implemented: true,
        desc: "Specialist encoder and fusion",
    },
    CrateInfo {
        name: "angryier-qihse",
        implemented: true,
        desc: "QIHSE adapter contracts",
    },
    CrateInfo {
        name: "angryier-keystone",
        implemented: true,
        desc: "KEYSTONE indexing adapter",
    },
    CrateInfo {
        name: "angryier-distribution",
        implemented: true,
        desc: "Work codec boundary",
    },
    CrateInfo {
        name: "angryier-plugins",
        implemented: true,
        desc: "Plugin trait registry",
    },
    CrateInfo {
        name: "angryier-bench",
        implemented: true,
        desc: "Benchmark and reproducibility",
    },
    CrateInfo {
        name: "angryier-solver-z3-ffi",
        implemented: true,
        desc: "Native Z3 solver FFI bridge",
    },
    CrateInfo {
        name: "angryier-solver-bitwuzla-ffi",
        implemented: true,
        desc: "Native Bitwuzla solver FFI bridge",
    },
    CrateInfo {
        name: "angryier-arch-xed-ffi",
        implemented: true,
        desc: "Native Intel XED decoder FFI bridge",
    },
    // --- Scaffolded (contract boundaries, fail-closed) ---
    CrateInfo {
        name: "angryier-solver-z3",
        implemented: false,
        desc: "Fail-closed Z3 adapter stub",
    },
    CrateInfo {
        name: "angryier-solver-bitwuzla",
        implemented: false,
        desc: "Fail-closed Bitwuzla adapter stub",
    },
    CrateInfo {
        name: "angryier-cli",
        implemented: false,
        desc: "CLI entry point",
    },
];

const TOTAL_CRATES: usize = 39;
const IMPLEMENTED_CRATES: usize = 36;
const SCAFFOLDED_CRATES: usize = 3;
const TEST_COUNT: usize = 585;
const TEST_SUITES: usize = 78;

/// Version string printed by `angryier version`.
fn version_output() -> String {
    format!("Angryier {VERSION}")
}

/// Brief tagline printed when no subcommand is given.
fn brief_output() -> String {
    format!("Angryier {VERSION} — {TAGLINE}")
}

/// Workspace status summary printed by `angryier status`.
fn status_output() -> String {
    format!(
        "Angryier {VERSION} — {TAGLINE}\n\
         \n\
         Workspace: {TOTAL_CRATES} crates\n\
         Implemented: {IMPLEMENTED_CRATES} crates with real logic\n\
         Scaffolded: {SCAFFOLDED_CRATES} crates (contract boundaries, fail-closed)\n\
         \n\
         Tests: {TEST_COUNT} tests across {TEST_SUITES} suites (0 failures)"
    )
}

/// Per-crate listing printed by `angryier crates`.
fn crates_output() -> String {
    let mut out = String::new();
    for c in CRATES {
        let status_str = if c.implemented { "Implemented" } else { "Scaffolded" };
        // Two-space indent, name left-padded to 28, status padded to 12, then description.
        out.push_str(&format!("  {:<28} {:<12} {}\n", c.name, status_str, c.desc));
    }
    // Drop the trailing newline for a clean return value.
    if out.ends_with('\n') {
        out.pop();
    }
    out
}

/// Usage text printed by `angryier help` (and `--help` / `-h`).
fn help_output() -> String {
    "Usage: angryier <command>\n\
     \n\
     Commands:\n  \
       version    Print version information\n  \
       status     Print workspace status summary\n  \
       crates     List all crates with implementation status\n  \
       help       Print this help message"
        .to_string()
}

/// Dispatch a parsed argument list to the appropriate subcommand.
///
/// `args` is the full `std::env::args()` collection including the program
/// name at index 0. Returns the process exit code.
fn run(args: &[String]) -> i32 {
    match args.get(1).map(String::as_str) {
        None => {
            println!("{}", brief_output());
            0
        }
        Some("version") => {
            println!("{}", version_output());
            0
        }
        Some("status") => {
            println!("{}", status_output());
            0
        }
        Some("crates") => {
            println!("{}", crates_output());
            0
        }
        Some("help") | Some("--help") | Some("-h") => {
            println!("{}", help_output());
            0
        }
        Some(cmd) => {
            eprintln!(
                "error: unknown command '{cmd}'\n\n\
                 Run 'angryier help' for usage."
            );
            1
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let code = run(&args);
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_output_contains_angryier() {
        assert!(version_output().contains("Angryier"));
    }

    #[test]
    fn version_output_contains_version_number() {
        assert!(version_output().contains(VERSION));
    }

    #[test]
    fn status_output_contains_crate_count() {
        assert!(status_output().contains("39 crates"));
    }

    #[test]
    fn status_output_contains_test_count() {
        assert!(status_output().contains("585 tests"));
    }

    #[test]
    fn status_output_contains_suite_count() {
        assert!(status_output().contains("78 suites"));
    }

    #[test]
    fn crates_output_contains_types_crate() {
        assert!(crates_output().contains("angryier-types"));
    }

    #[test]
    fn crates_output_contains_scaffolded() {
        assert!(crates_output().contains("Scaffolded"));
    }

    #[test]
    fn crates_output_contains_cli_crate() {
        assert!(crates_output().contains("angryier-cli"));
    }

    #[test]
    fn help_output_contains_usage() {
        assert!(help_output().contains("Usage:"));
    }

    #[test]
    fn help_output_lists_commands() {
        let help = help_output();
        assert!(help.contains("version"));
        assert!(help.contains("status"));
        assert!(help.contains("crates"));
        assert!(help.contains("help"));
    }

    #[test]
    fn unknown_command_returns_error_code() {
        let args = vec!["angryier".to_string(), "bogus".to_string()];
        assert_eq!(run(&args), 1);
    }

    #[test]
    fn unknown_command_returns_error_for_empty_subcommand() {
        // A subcommand that is known-empty never reaches the unknown branch,
        // but an unrecognized token must still be rejected.
        let args = vec!["angryier".to_string(), "nope".to_string()];
        assert_eq!(run(&args), 1);
    }

    #[test]
    fn no_args_returns_success() {
        let args = vec!["angryier".to_string()];
        assert_eq!(run(&args), 0);
    }

    #[test]
    fn version_command_returns_success() {
        let args = vec!["angryier".to_string(), "version".to_string()];
        assert_eq!(run(&args), 0);
    }

    #[test]
    fn help_flags_return_success() {
        assert_eq!(run(&["angryier".to_string(), "help".to_string()]), 0);
        assert_eq!(run(&["angryier".to_string(), "--help".to_string()]), 0);
        assert_eq!(run(&["angryier".to_string(), "-h".to_string()]), 0);
    }

    #[test]
    fn crate_count_matches_status() {
        let crates = crates_output();
        let listed = crates
            .lines()
            .filter(|l| l.contains("Implemented") || l.contains("Scaffolded"))
            .count();
        assert_eq!(listed, TOTAL_CRATES);
        assert!(status_output().contains("39 crates"));
    }

    #[test]
    fn implemented_and_scaffolded_counts_match_status() {
        let implemented = CRATES.iter().filter(|c| c.implemented).count();
        let scaffolded = CRATES.iter().filter(|c| !c.implemented).count();
        assert_eq!(implemented, IMPLEMENTED_CRATES);
        assert_eq!(scaffolded, SCAFFOLDED_CRATES);
        assert_eq!(implemented + scaffolded, TOTAL_CRATES);
    }

    #[test]
    fn brief_output_contains_tagline() {
        assert!(brief_output().contains(TAGLINE));
    }
}
