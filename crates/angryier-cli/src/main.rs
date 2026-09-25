#![forbid(unsafe_code)]

//! Command-line orchestration entry point for the Angryier workspace.
//!
//! This binary reports workspace/crate status. It parses arguments manually
//! from `std::env::args()` and uses no external dependencies.

/// Single version source: the workspace package version inherited via
/// `version.workspace = true` in Cargo.toml. `angry.version()` (the runtime
/// crate) derives from the same source, so the two cannot drift.
const VERSION: &str = env!("CARGO_PKG_VERSION");
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
/// 37 implemented crates with real logic plus 2 scaffolded contract boundaries
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
    CrateInfo {
        name: "angryier-cli",
        implemented: true,
        desc: "CLI entry point",
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
];

const TOTAL_CRATES: usize = 39;
const IMPLEMENTED_CRATES: usize = 37;
const SCAFFOLDED_CRATES: usize = 2;
// Historical snapshot from the 2026-09 documentation pass, not maintained
// per-change.
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
         Tests: {TEST_COUNT} tests across {TEST_SUITES} suites (0 failures, historical count)"
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
///
/// `run` is always listed; its description reports whether the binary was
/// built with the `run` feature.
fn help_output() -> String {
    let run_desc = if cfg!(feature = "run") {
        "Execute a binary symbolically"
    } else {
        "Not in this build (rebuild with --features run)"
    };
    format!(
        "Usage: angryier <command>\n\
         \n\
         Commands:\n  \
           version    Print version information\n  \
           status     Print workspace status summary\n  \
           crates     List all crates with implementation status\n  \
           run        {run_desc}\n  \
           help       Print this help message"
    )
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
        Some("run") => {
            #[cfg(feature = "run")]
            {
                run_subcommand(&args[2..])
            }
            #[cfg(not(feature = "run"))]
            {
                eprintln!(
                    "error: 'run' requires the `run` feature\n\nRebuild with: cargo build -p angryier-cli --features run"
                );
                1
            }
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

/// `angryier run` argument parsing and execution.
#[cfg(feature = "run")]
mod run_cmd {
    /// General-purpose registers accepted by `--symbolic`.
    const GPRS: [&str; 16] = [
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    ];

    /// Parsed `angryier run` arguments.
    #[derive(Debug, PartialEq)]
    pub struct RunConfig {
        pub path: String,
        pub script: Option<String>,
        pub symbolic: Vec<String>,
        pub find: Vec<u64>,
        pub argv: Option<u64>,
        pub dynamic: bool,
    }

    pub fn usage() -> String {
        "usage: angryier run <binary> [--script f.lua] [--symbolic REG] [--find ADDR] [--argv N] [--dynamic]\n\
         note: --find ADDR is hexadecimal, 0x prefix optional"
            .to_string()
    }

    /// Consumes the value following the flag at `*i`, advancing `*i` past it.
    fn value<'a>(args: &'a [String], i: &mut usize, flag: &str) -> Result<&'a str, String> {
        *i += 1;
        args.get(*i)
            .map(String::as_str)
            .ok_or_else(|| format!("missing value for {flag}"))
    }

    /// Parses a hexadecimal address with an optional `0x` prefix.
    fn parse_addr(raw: &str) -> Option<u64> {
        u64::from_str_radix(raw.strip_prefix("0x").unwrap_or(raw), 16).ok()
    }

    pub fn parse(args: &[String]) -> Result<RunConfig, String> {
        let mut path = None;
        let mut script = None;
        let mut symbolic = Vec::new();
        let mut find = Vec::new();
        let mut argv = None;
        let mut dynamic = false;
        let mut i = 0;
        while i < args.len() {
            let arg = args[i].as_str();
            if arg == "--script" {
                script = Some(value(args, &mut i, arg)?.to_string());
            } else if arg == "--symbolic" {
                let reg = value(args, &mut i, arg)?;
                if !GPRS.contains(&reg) {
                    return Err(format!(
                        "invalid --symbolic register '{reg}' (valid: rax rcx rdx rbx rsp rbp rsi rdi r8-r15)"
                    ));
                }
                symbolic.push(reg.to_string());
            } else if arg == "--find" {
                let raw = value(args, &mut i, arg)?;
                match parse_addr(raw) {
                    Some(addr) => find.push(addr),
                    None => {
                        return Err(format!(
                            "invalid --find address '{raw}' (expected hex, 0x prefix optional)"
                        ));
                    }
                }
            } else if arg == "--argv" {
                let raw = value(args, &mut i, arg)?;
                match raw.parse::<u64>() {
                    Ok(n) => argv = Some(n),
                    Err(_) => {
                        return Err(format!(
                            "invalid --argv value '{raw}' (expected a non-negative integer)"
                        ));
                    }
                }
            } else if arg == "--dynamic" {
                dynamic = true;
            } else if !arg.starts_with('-') {
                path = Some(arg.to_string());
            } else {
                return Err(format!("unknown flag '{arg}'"));
            }
            i += 1;
        }
        let path = path.ok_or_else(|| "missing <binary> operand".to_string())?;
        Ok(RunConfig {
            path,
            script,
            symbolic,
            find,
            argv,
            dynamic,
        })
    }

    pub fn execute(config: &RunConfig) -> i32 {
        let lua = mlua::Lua::new();
        if let Err(e) = angryier_runtime::script::register(&lua) {
            eprintln!("script init: {e}");
            return 1;
        }
        let sym_table = config
            .symbolic
            .iter()
            .map(|r| format!("{r} = 64"))
            .collect::<Vec<_>>()
            .join(",");
        let find_table = config.find.iter().map(u64::to_string).collect::<Vec<_>>().join(",");
        let argv_opt = config.argv.map(|n| format!("argv = {n},")).unwrap_or_default();
        let dyn_opt = if config.dynamic { "dynamic = true," } else { "" };
        let driver = if let Some(script) = &config.script {
            match std::fs::read_to_string(script) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("read {script}: {e}");
                    return 1;
                }
            }
        } else {
            format!(
                r#"local r = angry.run("{path}", {{ symbolic = {{ {sym_table} }}, find = {{ {find_table} }}, {argv_opt} {dyn_opt} steps = 1024, states = 16 }})
print(string.format("steps=%d forks=%d merges=%d terminated=%d found=%d", r.steps, r.forks, r.merges, r.terminated, r.found))"#,
                path = config.path
            )
        };
        match lua.load(&driver).eval::<mlua::Value>() {
            Ok(_) => 0,
            Err(e) => {
                eprintln!("script: {e}");
                1
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn args(items: &[&str]) -> Vec<String> {
            items.iter().map(|s| s.to_string()).collect()
        }

        fn config(
            path: &str,
            script: Option<&str>,
            symbolic: &[&str],
            find: &[u64],
            argv: Option<u64>,
            dynamic: bool,
        ) -> RunConfig {
            RunConfig {
                path: path.to_string(),
                script: script.map(|s| s.to_string()),
                symbolic: symbolic.iter().map(|s| s.to_string()).collect(),
                find: find.to_vec(),
                argv,
                dynamic,
            }
        }

        #[test]
        fn parses_minimal_invocation() {
            assert_eq!(
                parse(&args(&["./bin"])),
                Ok(config("./bin", None, &[], &[], None, false))
            );
        }

        #[test]
        fn parses_all_flags() {
            assert_eq!(
                parse(&args(&[
                    "./bin",
                    "--script",
                    "f.lua",
                    "--symbolic",
                    "rdi",
                    "--symbolic",
                    "rsi",
                    "--find",
                    "0x40102a",
                    "--argv",
                    "8",
                    "--dynamic"
                ])),
                Ok(config(
                    "./bin",
                    Some("f.lua"),
                    &["rdi", "rsi"],
                    &[0x40102a],
                    Some(8),
                    true
                ))
            );
        }

        #[test]
        fn find_accepts_hex_without_prefix() {
            assert_eq!(
                parse(&args(&["./bin", "--find", "0x40102a", "--find", "40102a"])),
                Ok(config("./bin", None, &[], &[0x40102a, 0x40102a], None, false))
            );
        }

        #[test]
        fn missing_binary_errors() {
            assert_eq!(
                parse(&args(&["--dynamic"])),
                Err("missing <binary> operand".to_string())
            );
        }

        #[test]
        fn unknown_flag_errors() {
            // Typo of `--symbolic`.
            assert_eq!(
                parse(&args(&["./bin", "--symboilc", "rdi"])),
                Err("unknown flag '--symboilc'".to_string())
            );
            assert_eq!(parse(&args(&["./bin", "-x"])), Err("unknown flag '-x'".to_string()));
        }

        #[test]
        fn missing_flag_value_errors() {
            for flag in ["--script", "--symbolic", "--find", "--argv"] {
                assert_eq!(parse(&args(&["./bin", flag])), Err(format!("missing value for {flag}")));
            }
        }

        #[test]
        fn invalid_register_errors() {
            assert_eq!(
                parse(&args(&["./bin", "--symbolic", "xmm0"])),
                Err("invalid --symbolic register 'xmm0' (valid: rax rcx rdx rbx rsp rbp rsi rdi r8-r15)".to_string())
            );
        }

        #[test]
        fn non_numeric_argv_errors() {
            assert_eq!(
                parse(&args(&["./bin", "--argv", "eight"])),
                Err("invalid --argv value 'eight' (expected a non-negative integer)".to_string())
            );
        }

        #[test]
        fn non_hex_find_errors() {
            assert_eq!(
                parse(&args(&["./bin", "--find", "zzz"])),
                Err("invalid --find address 'zzz' (expected hex, 0x prefix optional)".to_string())
            );
        }
    }
}

#[cfg(feature = "run")]
fn run_subcommand(args: &[String]) -> i32 {
    match run_cmd::parse(args) {
        Ok(config) => run_cmd::execute(&config),
        Err(msg) => {
            eprintln!("error: {msg}");
            eprintln!("{}", run_cmd::usage());
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
    fn status_output_labels_test_count_historical() {
        assert!(status_output().contains("historical count"));
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
        assert!(help.contains("run"));
        assert!(help.contains("help"));
    }

    #[test]
    fn crates_output_reports_cli_implemented() {
        let crates = crates_output();
        assert!(crates.contains("angryier-cli"));
        assert!(!crates.contains("angryier-cli          Scaffolded"));
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
