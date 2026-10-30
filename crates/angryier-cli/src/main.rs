#![forbid(unsafe_code)]

//! Command-line orchestration entry point for the Angryier workspace.
//!
//! This binary reports workspace/crate status. It parses arguments manually
//! from `std::env::args()` and uses no external dependencies.

#[cfg(feature = "inspect")]
mod inspection;
#[cfg(feature = "inspect")]
mod provenance;

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
/// 41 implemented crates with real logic plus 2 scaffolded contract boundaries
/// (fail-closed) = 43 crates total.
static CRATES: &[CrateInfo] = &[
    // --- Implemented (real logic, not just contracts) ---
    CrateInfo {
        name: "angryier",
        implemented: true,
        desc: "Stable public API and stability harness",
    },
    CrateInfo {
        name: "angryier-cfg",
        implemented: true,
        desc: "CFG recovery, dominance, and loop analysis",
    },
    CrateInfo {
        name: "angryier-runtime",
        implemented: true,
        desc: "Dual-mode runtime and execution orchestration",
    },
    CrateInfo {
        name: "angryier-solver-fuzzy",
        implemented: true,
        desc: "Fuzzy-SAT mutation solver tier",
    },
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
        desc: "Handwritten Intel 64 semantic corpus",
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

const TOTAL_CRATES: usize = 43;
const IMPLEMENTED_CRATES: usize = 41;
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
    ) + if cfg!(feature = "inspect") {
        "\n  doctor [--show-paths]         Report executable hash/build source identity\n  pe-address <PE> <VA> [length]   Strict VA/RVA/file-offset lookup\n  pe-imports <PE> [substring]   List exact IAT slot addresses and import names\n  dump-read <DMP> <VA> <length>   Read captured minidump bytes\n  capture-coverage <DIR> [DMP]  Verify overlay captures and report dump gaps"
    } else {
        ""
    }
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
                    "error: 'run' requires the `run` feature\n\n\
                     Why: this build excludes the runtime/XED/Lua execution stack.\n\
                     Rebuild: cargo build -p angryier-cli --features run\n\
                     Or run directly: cargo run -p angryier-cli --features run -- run <binary>\n\
                     Hint: use 'angryier help' after rebuilding to inspect supported run flags."
                );
                1
            }
        }
        Some("doctor") => {
            #[cfg(feature = "inspect")]
            {
                match provenance::doctor(&args[2..]) {
                    Ok(report) => {
                        println!("{report}");
                        0
                    }
                    Err(error) => {
                        eprintln!("error: {error}");
                        1
                    }
                }
            }
            #[cfg(not(feature = "inspect"))]
            {
                eprintln!("error: doctor requires --features inspect");
                1
            }
        }
        Some("pe-address") | Some("pe-imports") | Some("dump-read") | Some("capture-coverage") => {
            #[cfg(feature = "inspect")]
            {
                let outcome = match args.get(1).map(String::as_str) {
                    Some("pe-address") => inspection::pe_address(&args[2..]),
                    Some("pe-imports") => inspection::pe_imports(&args[2..]),
                    Some("capture-coverage") => inspection::capture_coverage(&args[2..]),
                    _ => inspection::minidump_read(&args[2..]),
                };
                match outcome {
                    Ok(result) => {
                        println!("{result}");
                        0
                    }
                    Err(error) => {
                        eprintln!("error: {error}");
                        1
                    }
                }
            }
            #[cfg(not(feature = "inspect"))]
            {
                eprintln!("error: forensic inspection requires --features inspect");
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
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    const AI_ANALYSIS_MIN_STEPS: u64 = 1000;
    const AI_ANALYSIS_TIMEOUT: Duration = Duration::from_secs(180);
    const AI_ANALYSIS_TOTAL_TIMEOUT: Duration = Duration::from_secs(300);
    const AI_ANALYSIS_MAX_TOTAL_TIMEOUT_SECS: u64 = 3600;
    const AI_REPORT_MAX_BYTES: usize = 12 * 1024;
    const AI_MODELS: &[&str] = &[
        "orca/orcacyber-glm-5.3-flash-free",
        "deepseek/deepseek-v4.1-flash-free",
        "deepseek/deepseek-v4-flash-free",
        "z-ai/glm-5.3-flash-free",
        "tencent/hy3-free",
    ];

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
        /// Concrete GPR seeds supplied as repeatable --reg REG=VALUE.
        pub regs: Vec<(String, u64)>,
        pub find: Vec<u64>,
        /// PCs whose states are intentionally pruned before stepping.
        pub avoid: Vec<u64>,
        pub argv: Option<u64>,
        /// Instruction-step budget threaded into the synthesized driver.
        /// Defaults to the Lua API's own default so the two cannot drift.
        pub steps: u64,
        /// Maximum simultaneous live symbolic states.
        pub states: usize,
        /// Whole-run wall-clock budget for symbolic exploration.
        pub timeout_secs: u64,
        /// Per-query budget for post-run alternate-branch solving.
        pub branch_timeout_ms: u64,
        /// Extract concrete models for states that hit --find targets.
        pub solve: bool,
        /// Fork-aggressive symbolic exploration instead of concolic folding.
        pub fork: bool,
        /// Depth-first state selection.
        pub dfs: bool,
        pub dynamic: bool,
        /// PE driver mode: load via `load_pe_driver`, attach kernel models,
        /// execute DriverEntry, and report pool/kernel events.
        pub driver: bool,
        /// Function stubs: (address, return_value)
        pub stubs: Vec<(u64, u64)>,
        /// Control-flow redirects: (from_pc, to_pc)
        pub redirects: Vec<(u64, u64)>,
        /// Memory/instruction byte patches: (address, bytes)
        pub patches: Vec<(u64, Vec<u8>)>,
        /// Ingest static handoff JSON file (produced by METHRA or test fixtures).
        pub handoff: Option<String>,
        /// Target ID filter when using --handoff (e.g. `TGT-VBOXUSBMON-001`).
        pub handoff_target: Option<String>,
        /// Emit machine-readable line-delimited JSON verdicts conforming to `symbolic_verdict.schema.json`.
        pub json: bool,
        /// Run HAX-backed post-analysis on long generated symbolic reports.
        pub ai_analysis: bool,
        /// Minimum executed steps required before HAX post-analysis.
        pub ai_min_steps: u64,
        /// Total wall-clock budget for HAX post-analysis.
        pub ai_timeout_secs: u64,
        /// Ordered free OrcaRouter models used for HAX post-analysis.
        pub ai_models: Vec<String>,
        /// Kernel layout architecture ("x64", "x86").
        pub arch: Option<String>,
    }

    pub fn usage() -> String {
        "usage: angryier run <binary> [--script f.lua] [--symbolic REG] [--reg REG=VALUE] [--find ADDR] [--avoid ADDR] [--argv N] [--steps N] [--states N] [--timeout SECS] [--branch-timeout-ms N] [--solve] [--fork] [--dfs] [--dynamic] [--driver] [--stub ADDR=VAL] [--redirect FROM=TO] [--patch ADDR=HEX] [--handoff PATH] [--handoff-target ID] [--json] [--no-ai-analysis] [--ai-min-steps N] [--ai-timeout-secs SECS] [--ai-model MODEL]... [--arch ARCH]\n\
         note: --reg is repeatable; VALUE accepts decimal or 0x-prefixed hexadecimal\n\
         note: --find/--avoid ADDR are repeatable hexadecimal addresses, 0x prefix optional\n\
         note: --stub/--redirect/--patch are repeatable for function stubbing, execution diversion, and live memory patching\n\
         note: --handoff consumes METHRA static handoffs (symbolic_targets.schema.json) for targeted IOCTL exploration\n\
         note: --fork enables fork-aggressive symbolic exploration; --dfs prioritizes the newest/deepest state\n\
         note: --driver loads PE32+ drivers with kernel models and reports pool events\n\
         note: --ai-min-steps defaults to 1000; --ai-timeout-secs defaults to 300 and accepts 1..=3600\n\
         note: repeat --ai-model to set an ordered list from the free OrcaRouter allowlist; duplicate models are rejected"
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

    fn parse_u64_value(raw: &str) -> Option<u64> {
        if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
            u64::from_str_radix(hex, 16).ok()
        } else {
            raw.parse::<u64>().ok()
        }
    }

    fn parse_reg_seed(raw: &str) -> Result<(String, u64), String> {
        let (name, value) = raw
            .split_once('=')
            .ok_or_else(|| format!("invalid --reg value '{raw}' (expected REG=VALUE, e.g. rdi=42 or rdi=0x2a)"))?;
        if !GPRS.contains(&name) {
            return Err(format!(
                "invalid --reg register '{name}' (valid: rax rcx rdx rbx rsp rbp rsi rdi r8-r15)"
            ));
        }
        let value = parse_u64_value(value)
            .ok_or_else(|| format!("invalid --reg value '{raw}' (VALUE must be decimal or 0x-prefixed hexadecimal)"))?;
        Ok((name.to_string(), value))
    }

    fn parse_stub(raw: &str) -> Result<(u64, u64), String> {
        let (addr_str, val_str) = raw
            .split_once('=')
            .ok_or_else(|| format!("invalid --stub value '{raw}' (expected ADDR=VAL, e.g. 0x401000=0)"))?;
        let addr = parse_u64_value(addr_str)
            .ok_or_else(|| format!("invalid --stub address '{addr_str}' (expected decimal or 0x-prefixed hex)"))?;
        let val = parse_u64_value(val_str)
            .ok_or_else(|| format!("invalid --stub return value '{val_str}' (expected decimal or 0x-prefixed hex)"))?;
        Ok((addr, val))
    }

    fn parse_redirect(raw: &str) -> Result<(u64, u64), String> {
        let (from_str, to_str) = raw
            .split_once('=')
            .ok_or_else(|| format!("invalid --redirect value '{raw}' (expected FROM=TO, e.g. 0x401050=0x401080)"))?;
        let from = parse_u64_value(from_str).ok_or_else(|| {
            format!("invalid --redirect source address '{from_str}' (expected decimal or 0x-prefixed hex)")
        })?;
        let to = parse_u64_value(to_str).ok_or_else(|| {
            format!("invalid --redirect target address '{to_str}' (expected decimal or 0x-prefixed hex)")
        })?;
        Ok((from, to))
    }

    fn parse_patch(raw: &str) -> Result<(u64, Vec<u8>), String> {
        let (addr_str, bytes_str) = raw
            .split_once('=')
            .ok_or_else(|| format!("invalid --patch value '{raw}' (expected ADDR=HEX, e.g. 0x401000=9090)"))?;
        let addr = parse_u64_value(addr_str)
            .ok_or_else(|| format!("invalid --patch address '{addr_str}' (expected decimal or 0x-prefixed hex)"))?;
        let clean = bytes_str
            .trim()
            .strip_prefix("0x")
            .or_else(|| bytes_str.trim().strip_prefix("0X"))
            .unwrap_or(bytes_str.trim())
            .replace([' ', '\t'], "");
        if clean.is_empty() || clean.len() % 2 != 0 || !clean.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "invalid --patch hex bytes '{bytes_str}' (expected even number of hex characters)"
            ));
        }
        let mut bytes = Vec::with_capacity(clean.len() / 2);
        for chunk in clean.as_bytes().chunks(2) {
            let s = std::str::from_utf8(chunk).map_err(|e| format!("{e}"))?;
            let b = u8::from_str_radix(s, 16).map_err(|e| format!("{e}"))?;
            bytes.push(b);
        }
        Ok((addr, bytes))
    }

    pub fn parse(args: &[String]) -> Result<RunConfig, String> {
        let mut path = None;
        let mut script = None;
        let mut symbolic = Vec::new();
        let mut regs = Vec::new();
        let mut find = Vec::new();
        let mut avoid = Vec::new();
        let mut stubs = Vec::new();
        let mut redirects = Vec::new();
        let mut patches = Vec::new();
        let mut argv = None;
        let mut steps: Option<u64> = None;
        let mut states: Option<usize> = None;
        let mut timeout_secs: Option<u64> = None;
        let mut branch_timeout_ms: Option<u64> = None;
        let mut solve = false;
        let mut fork = false;
        let mut dfs = false;
        let mut dynamic = false;
        let mut driver = false;
        let mut handoff = None;
        let mut handoff_target = None;
        let mut json = false;
        let mut ai_analysis = true;
        let mut ai_analysis_flag = false;
        let mut ai_min_steps = None;
        let mut ai_timeout_secs = None;
        let mut ai_models = Vec::new();
        let mut ai_model_flag = false;
        let mut arch = None;
        let mut i = 0;
        while i < args.len() {
            let arg = args[i].as_str();
            if arg == "--script" {
                let raw = value(args, &mut i, arg)?;
                if script.replace(raw.to_string()).is_some() {
                    return Err(format!(
                        "duplicate --script value '{raw}' (flag may only be given once)"
                    ));
                }
            } else if arg == "--symbolic" {
                let reg = value(args, &mut i, arg)?;
                if !GPRS.contains(&reg) {
                    return Err(format!(
                        "invalid --symbolic register '{reg}' (valid: rax rcx rdx rbx rsp rbp rsi rdi r8-r15)"
                    ));
                }
                symbolic.push(reg.to_string());
            } else if arg == "--reg" {
                let raw = value(args, &mut i, arg)?;
                let seed = parse_reg_seed(raw)?;
                regs.push(seed);
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
            } else if arg == "--avoid" {
                let raw = value(args, &mut i, arg)?;
                match parse_addr(raw) {
                    Some(addr) => avoid.push(addr),
                    None => {
                        return Err(format!(
                            "invalid --avoid address '{raw}' (expected hex, 0x prefix optional)"
                        ));
                    }
                }
            } else if arg == "--argv" {
                let raw = value(args, &mut i, arg)?;
                match raw.parse::<u64>() {
                    Ok(n) => {
                        if argv.replace(n).is_some() {
                            return Err(format!("duplicate --argv value '{raw}' (flag may only be given once)"));
                        }
                    }
                    Err(_) => {
                        return Err(format!(
                            "invalid --argv value '{raw}' (expected a non-negative integer)"
                        ));
                    }
                }
            } else if arg == "--steps" {
                let raw = value(args, &mut i, arg)?;
                match raw.parse::<u64>() {
                    Ok(n) => {
                        if steps.replace(n).is_some() {
                            return Err(format!("duplicate --steps value '{raw}' (flag may only be given once)"));
                        }
                    }
                    Err(_) => {
                        return Err(format!(
                            "invalid --steps value '{raw}' (expected a non-negative integer)"
                        ));
                    }
                }
            } else if arg == "--states" {
                let raw = value(args, &mut i, arg)?;
                match raw.parse::<usize>() {
                    Ok(n) if n > 0 => {
                        if states.replace(n).is_some() {
                            return Err(format!(
                                "duplicate --states value '{raw}' (flag may only be given once)"
                            ));
                        }
                    }
                    _ => {
                        return Err(format!(
                            "invalid --states value '{raw}' (expected an integer greater than zero)"
                        ));
                    }
                }
            } else if arg == "--timeout" {
                let raw = value(args, &mut i, arg)?;
                match raw.parse::<u64>() {
                    Ok(n) if n > 0 => {
                        if timeout_secs.replace(n).is_some() {
                            return Err(format!(
                                "duplicate --timeout value '{raw}' (flag may only be given once)"
                            ));
                        }
                    }
                    _ => {
                        return Err(format!(
                            "invalid --timeout value '{raw}' (expected seconds greater than zero)"
                        ));
                    }
                }
            } else if arg == "--branch-timeout-ms" {
                let raw = value(args, &mut i, arg)?;
                match raw.parse::<u64>() {
                    Ok(n) if (1..=10_000).contains(&n) => {
                        if branch_timeout_ms.replace(n).is_some() {
                            return Err(format!(
                                "duplicate --branch-timeout-ms value '{raw}' (flag may only be given once)"
                            ));
                        }
                    }
                    _ => {
                        return Err(format!(
                            "invalid --branch-timeout-ms value '{raw}' (expected 1..=10000)"
                        ));
                    }
                }
            } else if arg == "--solve" {
                if solve {
                    return Err("duplicate --solve flag (may only be given once)".to_string());
                }
                solve = true;
            } else if arg == "--fork" {
                if fork {
                    return Err("duplicate --fork flag (may only be given once)".to_string());
                }
                fork = true;
            } else if arg == "--dfs" {
                if dfs {
                    return Err("duplicate --dfs flag (may only be given once)".to_string());
                }
                dfs = true;
            } else if arg == "--dynamic" {
                if dynamic {
                    return Err("duplicate --dynamic flag (may only be given once)".to_string());
                }
                dynamic = true;
            } else if arg == "--driver" {
                if driver {
                    return Err("duplicate --driver flag (may only be given once)".to_string());
                }
                driver = true;
            } else if arg == "--stub" {
                let raw = value(args, &mut i, arg)?;
                let stub = parse_stub(raw)?;
                stubs.push(stub);
            } else if arg == "--redirect" {
                let raw = value(args, &mut i, arg)?;
                let redirect = parse_redirect(raw)?;
                redirects.push(redirect);
            } else if arg == "--patch" {
                let raw = value(args, &mut i, arg)?;
                let patch = parse_patch(raw)?;
                patches.push(patch);
            } else if arg == "--handoff" {
                let raw = value(args, &mut i, arg)?;
                if handoff.replace(raw.to_string()).is_some() {
                    return Err(format!(
                        "duplicate --handoff value '{raw}' (flag may only be given once)"
                    ));
                }
            } else if arg == "--handoff-target" {
                let raw = value(args, &mut i, arg)?;
                if handoff_target.replace(raw.to_string()).is_some() {
                    return Err(format!(
                        "duplicate --handoff-target value '{raw}' (flag may only be given once)"
                    ));
                }
            } else if arg == "--json" {
                if json {
                    return Err("duplicate --json flag (may only be given once)".to_string());
                }
                json = true;
            } else if arg == "--no-ai-analysis" {
                if ai_analysis_flag {
                    return Err("duplicate --no-ai-analysis flag (may only be given once)".to_string());
                }
                ai_analysis = false;
                ai_analysis_flag = true;
            } else if arg == "--ai-min-steps" {
                let raw = value(args, &mut i, arg)?;
                match raw.parse::<u64>() {
                    Ok(n) if n > 0 => {
                        if ai_min_steps.replace(n).is_some() {
                            return Err(format!(
                                "duplicate --ai-min-steps value '{raw}' (flag may only be given once)"
                            ));
                        }
                    }
                    _ => {
                        return Err(format!(
                            "invalid --ai-min-steps value '{raw}' (expected an integer greater than zero)"
                        ));
                    }
                }
            } else if arg == "--ai-timeout-secs" {
                let raw = value(args, &mut i, arg)?;
                match raw.parse::<u64>() {
                    Ok(n) if (1..=AI_ANALYSIS_MAX_TOTAL_TIMEOUT_SECS).contains(&n) => {
                        if ai_timeout_secs.replace(n).is_some() {
                            return Err(format!(
                                "duplicate --ai-timeout-secs value '{raw}' (flag may only be given once)"
                            ));
                        }
                    }
                    _ => {
                        return Err(format!(
                            "invalid --ai-timeout-secs value '{raw}' (expected 1..={AI_ANALYSIS_MAX_TOTAL_TIMEOUT_SECS})"
                        ));
                    }
                }
            } else if arg == "--ai-model" {
                let model = value(args, &mut i, arg)?;
                if !AI_MODELS.contains(&model) {
                    return Err(format!(
                        "invalid --ai-model '{model}' (valid: {})",
                        AI_MODELS.join(", ")
                    ));
                }
                if ai_models.iter().any(|existing| existing == model) {
                    return Err(format!("duplicate --ai-model '{model}' (models must be unique)"));
                }
                ai_model_flag = true;
                ai_models.push(model.to_string());
            } else if arg == "--arch" {
                let raw = value(args, &mut i, arg)?;
                if arch.replace(raw.to_string()).is_some() {
                    return Err(format!("duplicate --arch value '{raw}' (flag may only be given once)"));
                }
            } else if !arg.starts_with('-') {
                if path.replace(arg.to_string()).is_some() {
                    return Err(format!(
                        "duplicate <binary> operand '{arg}' (only one binary path may be given)"
                    ));
                }
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
            regs,
            find,
            avoid,
            argv,
            // Defaults are shared with the Lua API so CLI and script runs do
            // not silently diverge.
            steps: steps.unwrap_or(angryier_runtime::script::DEFAULT_STEPS),
            states: states.unwrap_or(angryier_runtime::script::DEFAULT_MAX_STATES),
            timeout_secs: timeout_secs.unwrap_or(angryier_runtime::script::DEFAULT_TIMEOUT_SECS),
            branch_timeout_ms: branch_timeout_ms.unwrap_or(angryier_runtime::script::DEFAULT_BRANCH_TIMEOUT_MS),
            solve,
            fork,
            dfs,
            dynamic,
            driver,
            stubs,
            redirects,
            patches,
            handoff,
            handoff_target,
            json,
            ai_analysis,
            ai_min_steps: ai_min_steps.unwrap_or(AI_ANALYSIS_MIN_STEPS),
            ai_timeout_secs: ai_timeout_secs.unwrap_or(AI_ANALYSIS_TOTAL_TIMEOUT.as_secs()),
            ai_models: if ai_model_flag {
                ai_models
            } else {
                AI_MODELS.iter().map(|model| model.to_string()).collect()
            },
            arch,
        })
    }

    /// Human-readable execution plan printed before any runtime work starts.
    ///
    /// The CLI is an operator interface, not just a machine-readable wrapper:
    /// make effective mode, limits, symbolic inputs, targets, and ignored
    /// options explicit before execution so a surprising result can be
    /// diagnosed from the transcript alone.
    fn run_plan_output(config: &RunConfig) -> String {
        let frontend = match &config.script {
            Some(script) => format!("custom Lua script ({script})"),
            None => "generated Lua driver".to_string(),
        };
        let mode = if config.handoff.is_some() {
            "METHRA static-handoff driver verification (POPKORN targeted IOCTL exploration)"
        } else if config.driver {
            "PE32+ kernel-driver execution (direct Rust runtime + kernel models)"
        } else if config.dynamic {
            "symbolic/concolic execution with dynamic-linking environment model"
        } else {
            "symbolic/concolic execution with static image entry"
        };
        let handoff_desc = match (&config.handoff, &config.handoff_target) {
            (Some(path), Some(tgt)) => format!("{path} (target {tgt})"),
            (Some(path), None) => format!("{path} (all targets)"),
            (None, _) => "none".to_string(),
        };
        let symbolic = if config.symbolic.is_empty() {
            "none".to_string()
        } else {
            config.symbolic.join(", ")
        };
        let concrete_regs = if config.regs.is_empty() {
            "none".to_string()
        } else {
            config
                .regs
                .iter()
                .map(|(name, value)| format!("{name}={value:#x}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let find = if config.find.is_empty() {
            "none".to_string()
        } else {
            config
                .find
                .iter()
                .map(|address| format!("{address:#x}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let avoid = if config.avoid.is_empty() {
            "none".to_string()
        } else {
            config
                .avoid
                .iter()
                .map(|address| format!("{address:#x}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let argv = config
            .argv
            .map(|bytes| format!("{bytes} symbolic byte(s) in argv[0]"))
            .unwrap_or_else(|| "disabled".to_string());
        let stubs_desc = if config.stubs.is_empty() {
            "none".to_string()
        } else {
            config
                .stubs
                .iter()
                .map(|(addr, ret)| format!("{addr:#x}->ret {ret:#x}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let redirects_desc = if config.redirects.is_empty() {
            "none".to_string()
        } else {
            config
                .redirects
                .iter()
                .map(|(from, to)| format!("{from:#x}->{to:#x}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let patches_desc = if config.patches.is_empty() {
            "none".to_string()
        } else {
            config
                .patches
                .iter()
                .map(|(addr, bytes)| format!("{addr:#x} ({}B)", bytes.len()))
                .collect::<Vec<_>>()
                .join(", ")
        };
        let ai_analysis_desc = if !config.ai_analysis {
            "disabled"
        } else if config.handoff.is_some() {
            "bypassed in handoff mode"
        } else if config.driver {
            "bypassed in direct driver mode"
        } else if config.script.is_some() {
            "available to custom Lua scripts"
        } else {
            "enabled"
        };
        let note = if config.handoff.is_some() {
            "\n  note           : --handoff enables METHRA targeted IOCTL verification; targets, RVAs, and candidate IOCTL codes are driven by the static handoff specification"
        } else if config.driver {
            "\n  note           : --driver bypasses Lua; --reg, --stub, --redirect, --patch, and --steps apply directly, while symbolic search flags (--symbolic/--find/--avoid/--argv/--states/--timeout/--branch-timeout-ms/--solve/--fork/--dfs/--dynamic) are not applied"
        } else if config.script.is_some() {
            "\n  note           : a custom Lua script owns execution; parsed symbolic/reg/find/avoid/argv/stub/redirect/patch/budget/search flags are not injected automatically"
        } else {
            ""
        };

        format!(
            "[angryier][plan] execution configuration\n\
             \x20 target         : {}\n\
             \x20 frontend       : {}\n\
             \x20 mode           : {}\n\
             \x20 static handoff : {}\n\
             \x20 step budget    : {}\n\
             \x20 state budget   : {}\n\
             \x20 wall timeout   : {} s\n\
             \x20 AI post-analysis: {} (minimum {} executed steps)\n\
             \x20 branch timeout : {} ms\n\
             \x20 exploration    : {}\n\
             \x20 search order   : {}\n\
             \x20 solve targets  : {}\n\
             \x20 symbolic regs  : {}\n\
             \x20 concrete regs  : {}\n\
             \x20 find targets   : {}\n\
             \x20 avoid targets  : {}\n\
             \x20 symbolic argv  : {}\n\
             \x20 function stubs : {}\n\
             \x20 redirects      : {}\n\
             \x20 memory patches : {}{}",
            config.path,
            frontend,
            mode,
            handoff_desc,
            config.steps,
            config.states,
            config.timeout_secs,
            ai_analysis_desc,
            AI_ANALYSIS_MIN_STEPS,
            config.branch_timeout_ms,
            if config.fork {
                "fork-aggressive"
            } else {
                "concolic/default"
            },
            if config.dfs {
                "depth-first"
            } else {
                "round-robin/coverage policy"
            },
            if config.solve { "yes" } else { "no" },
            symbolic,
            concrete_regs,
            find,
            avoid,
            argv,
            stubs_desc,
            redirects_desc,
            patches_desc,
            note
        )
    }

    /// Format one PE-driver execution outcome so a trace line explains what
    /// happened rather than only reporting an opaque step number.
    fn driver_step_output(step_index: u64, outcome: &angryier_runtime::StepOutcome) -> String {
        match outcome {
            angryier_runtime::StepOutcome::Stepped {
                pc,
                next_pc,
                length,
                form_id,
            } => format!(
                "[angryier][trace] step {step_index}: instruction executed; pc={pc:#x} -> {next_pc:#x}, length={length} byte(s), semantic_form={form_id:#x}"
            ),
            angryier_runtime::StepOutcome::SimProcedure { address, name } => format!(
                "[angryier][trace] step {step_index}: modeled function dispatched; address={address:#x}, model={name}"
            ),
            angryier_runtime::StepOutcome::Syscall { pc, number } => format!(
                "[angryier][trace] step {step_index}: modeled syscall dispatched; pc={pc:#x}, syscall_number={number}"
            ),
            angryier_runtime::StepOutcome::Terminated { pc } => {
                format!("[angryier][trace] step {step_index}: execution terminated; final_pc={pc:#x}")
            }
            angryier_runtime::StepOutcome::Trap { pc, vector } => {
                format!("[angryier][trace] step {step_index}: trap raised; pc={pc:#x}, vector={vector:#x}")
            }
        }
    }

    /// The synthesized driver evaluated when `--script` is absent: the
    /// parsed flags mapped onto one `angry.run` call. Extracted from
    /// `execute` so the generated Lua is unit-testable.
    fn default_driver_lua(config: &RunConfig) -> String {
        let sym_table = config
            .symbolic
            .iter()
            .map(|r| format!("{r} = {}", angryier_runtime::script::SYMBOLIC_GPR_WIDTH))
            .collect::<Vec<_>>()
            .join(",");
        let find_table = config.find.iter().map(u64::to_string).collect::<Vec<_>>().join(",");
        let avoid_table = config.avoid.iter().map(u64::to_string).collect::<Vec<_>>().join(",");
        let regs_opt = if config.regs.is_empty() {
            String::new()
        } else {
            let entries = config
                .regs
                .iter()
                .map(|(name, value)| {
                    if *value <= i64::MAX as u64 {
                        format!("{name} = {value}")
                    } else {
                        format!("{name}_hex = \"{value:#018x}\"")
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("regs = {{ {entries} }},")
        };
        let stubs_opt = if config.stubs.is_empty() {
            String::new()
        } else {
            let entries = config
                .stubs
                .iter()
                .map(|(addr, ret)| format!("[{addr}] = {ret}"))
                .collect::<Vec<_>>()
                .join(", ");
            format!("stubs = {{ {entries} }},")
        };
        let redirects_opt = if config.redirects.is_empty() {
            String::new()
        } else {
            let entries = config
                .redirects
                .iter()
                .map(|(from, to)| format!("[{from}] = {to}"))
                .collect::<Vec<_>>()
                .join(", ");
            format!("redirects = {{ {entries} }},")
        };
        let patches_opt = if config.patches.is_empty() {
            String::new()
        } else {
            let entries = config
                .patches
                .iter()
                .map(|(addr, bytes)| {
                    let hex = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
                    format!("[{addr}] = \"{hex}\"")
                })
                .collect::<Vec<_>>()
                .join(", ");
            format!("patches = {{ {entries} }},")
        };
        let argv_opt = config.argv.map(|n| format!("argv = {n},")).unwrap_or_default();
        let dyn_opt = if config.dynamic { "dynamic = true," } else { "" };
        let solve_opt = if config.solve { "solve = true," } else { "" };
        let fork_opt = if config.fork { "exploration = \"fork\"," } else { "" };
        let dfs_opt = if config.dfs { "search = \"dfs\"," } else { "" };
        let escaped_path = config.path.replace('\\', "\\\\").replace('"', "\\\"");
        format!(
            r#"local r = angry.run("{path}", {{ symbolic = {{ {sym_table} }}, {regs_opt} {stubs_opt} {redirects_opt} {patches_opt} find = {{ {find_table} }}, avoid = {{ {avoid_table} }}, {argv_opt} {dyn_opt} {solve_opt} {fork_opt} {dfs_opt} steps = {steps}, states = {states}, timeout_secs = {timeout_secs}, branch_analysis = true, branch_timeout_ms = {branch_timeout_ms} }})

local function yn(v)
    if v then return "yes" end
    return "no"
end

local function count_table(t)
    if t == nil then return 0 end
    local n = 0
    for _ in pairs(t) do n = n + 1 end
    return n
end

print("[angryier][result] symbolic/concolic exploration completed")
print(string.format("  exploration steps      : %d (engine work units executed)", r.steps or 0))
print(string.format("  forks                  : %d (new execution states created at symbolic branches)", r.forks or 0))
print(string.format("  merges                 : %d (compatible execution states recombined)", r.merges or 0))
print(string.format("  terminated states      : %d (states that reached a modeled terminal condition)", r.terminated or 0))
print(string.format("  pruned states          : %d (states discarded by policy/state-cap economics)", r.pruned_states or 0))
print(string.format("  failed states          : %d (states stopped by execution/model/semantic failure)", r.failed or 0))
print(string.format("  live states            : %d (states still explorable when this run stopped)", r.live_states or 0))
print(string.format("  dead states            : %d (terminated/failed/pruned states retained for inspection)", r.dead_states or 0))
print(string.format("  peak live states       : %d (maximum simultaneous exploration frontier)", r.peak_states or 0))
print(string.format("  find hits              : %d (configured target-address states reached)", r.found or 0))
print(string.format("  timed out              : %s", yn(r.timed_out)))
print(string.format("  concretization retries : %d (solver-assisted unresolved-address recovery attempts)", r.concretization_retries or 0))
print(string.format("  region-fork children   : %d (guessed address-world states created to continue unresolved pointers)", r.region_fork_children or 0))
print(string.format("  trace blocks           : %d (blocks retained in the diagnostic execution trace)", count_table(r.trace_hex or r.trace)))

if r.last_error ~= nil then
    print(string.format("  last error              : %s", tostring(r.last_error)))
end
if r.unsupported_total ~= nil then
    print(string.format("  unsupported semantics   : %d fallback hit(s)", r.unsupported_total))
end
if r.unmapped_total ~= nil then
    print(string.format("  under-constrained mem   : %d relaxed access(es)", r.unmapped_total))
end
if r.ro_write_total ~= nil then
    print(string.format("  relaxed read-only writes: %d", r.ro_write_total))
end
if r.vector_debt_total ~= nil then
    print(string.format("  vector semantic debt    : %d under-constrained vector operation(s)", r.vector_debt_total))
end

if (r.found or 0) == 0 then
    print("  target status           : no configured find target was reached in this run")
else
    print("  target status           : one or more configured find targets were reached")
end

print("[angryier][analysis] evidence interpretation")
local trace = r.trace_hex or r.trace
local trace_count = count_table(trace)
if trace_count > 0 then
    local first = math.max(1, trace_count - 7)
    print(string.format("  retained path tail      : last %d block(s)", trace_count - first + 1))
    for i = first, trace_count do
        print(string.format("    [%04d] %s", i, tostring(trace[i])))
    end
    print(string.format("  frontier block          : %s (last retained block; not automatically the CFG-closest block to a missed target)", tostring(trace[trace_count])))
else
    print("  retained path tail      : unavailable")
end

if r.frontier ~= nil then
    local f = r.frontier
    print("[angryier][analysis] symbolic frontier")
    print(string.format("  state id                : %s", tostring(f.state_id or "?")))
    print(string.format("  pc                      : %s", tostring(f.pc_hex or f.pc or "?")))
    print(string.format("  path constraints        : %d", f.constraints or 0))
    print(string.format("  bound symbols           : %d", f.bound_symbols or 0))
    print(string.format("  symbolic registers      : %d", f.symbolic_registers or 0))
    local current_regs = f.registers
    local current_reg_count = count_table(current_regs)
    if current_reg_count > 0 then
        local labels = {{}}
        for i = 1, current_reg_count do
            local reg = current_regs[i]
            if reg ~= nil then
                labels[#labels + 1] = tostring(reg.name or reg.register or "?")
            end
        end
        print("  symbolic register set   : " .. table.concat(labels, ", "))
    end
    local deps = f.constraint_dependencies
    local dep_count = count_table(deps)
    print(string.format("  constraint dependencies : %d symbolic source(s) occur in retained path predicates", dep_count))
    if dep_count > 0 then
        local dep_reg_set = {{}}
        local dep_reg_labels = {{}}
        for i = 1, dep_count do
            local dep = deps[i]
            if dep ~= nil and dep.source_kind == "register" and dep.name ~= nil and not dep_reg_set[dep.name] then
                dep_reg_set[dep.name] = true
                dep_reg_labels[#dep_reg_labels + 1] = dep.name
            end
        end
        if #dep_reg_labels > 0 then
            print("  path-relevant registers : " .. table.concat(dep_reg_labels, ", "))
        end
        local irrelevant = {{}}
        for i = 1, current_reg_count do
            local reg = current_regs[i]
            local name = reg ~= nil and reg.name or nil
            if name ~= nil and not dep_reg_set[name] then
                irrelevant[#irrelevant + 1] = name
            end
        end
        if #irrelevant > 0 then
            print("  non-predicate symbolic  : " .. table.concat(irrelevant, ", ") .. " (candidates to concretize unless needed by later trace/taint evidence)")
        end
        local shown = math.min(dep_count, 12)
        for i = 1, shown do
            local dep = deps[i]
            if dep ~= nil and dep.source_kind == "register" then
                print(string.format(
                    "    source[%02d] %-5s width=%s expr=%s source_id=%s",
                    i,
                    tostring(dep.name or dep.register or "?"),
                    tostring(dep.width or "?"),
                    tostring(dep.expression or "?"),
                    tostring(dep.source_id or "?")
                ))
            elseif dep ~= nil then
                print(string.format(
                    "    source[%02d] unbound-symbol source_id=%s (memory/fallback/free symbolic leaf)",
                    i,
                    tostring(dep.source_id or "?")
                ))
            end
        end
        if dep_count > shown then
            print(string.format("    ... %d additional dependency source(s) omitted", dep_count - shown))
        end
    end
end

local approximation_debt =
    (r.unsupported_total or 0) +
    (r.unmapped_total or 0) +
    (r.ro_write_total or 0) +
    (r.vector_debt_total or 0) +
    (r.region_fork_children or 0)

local evidence_quality = "CLEANER"
local evidence_reason = "no approximation/fidelity debt was reported by the exposed ledgers"
if approximation_debt > 0 then
    evidence_quality = "DEGRADED"
    evidence_reason = "one or more semantic/memory/vector/address fallbacks altered fidelity"
elseif (r.failed or 0) > 0 or (r.pruned_states or 0) > 0 or (r.concretization_retries or 0) > 0 then
    evidence_quality = "MIXED"
    evidence_reason = "no approximation ledger fired, but failures/pruning/concretization mean exploration was incomplete or constrained"
end
print(string.format("  evidence quality        : %s — %s", evidence_quality, evidence_reason))

local limiter = "no single dominant limiter identified"
if r.timed_out then
    limiter = "wall-clock timeout"
elseif (r.pruned_states or 0) > 0 then
    limiter = "state-budget pressure / pruning"
elseif (r.failed or 0) > 0 then
    limiter = "execution, semantic, environment-model, or memory failure"
elseif (r.unsupported_total or 0) > 0 then
    limiter = "unsupported instruction semantics"
elseif (r.region_fork_children or 0) > 0 or (r.unmapped_total or 0) > 0 then
    limiter = "under-constrained address/memory modeling"
elseif (r.vector_debt_total or 0) > 0 then
    limiter = "vector semantic fidelity"
elseif (r.live_states or 0) > 0 and (r.steps or 0) >= {steps} then
    limiter = "step budget with unexplored live states remaining"
elseif (r.forks or 0) == 0 and ({symbolic_count} > 0 or {argv_enabled} > 0) then
    limiter = "configured symbolic source has not influenced a fork"
elseif {find_count} > 0 and (r.found or 0) == 0 then
    limiter = "target reachability remains unestablished"
end
print(string.format("  primary limiter         : %s", limiter))

if (r.region_fork_children or 0) > 0 then
    print(string.format("  address-world fidelity  : %d guessed child state(s); inspect region_fork_sites before treating reachability as real", r.region_fork_children))
end
if (r.pruned_states or 0) > 0 then
    print(string.format("  state economics         : %d state(s) were pruned; peak frontier=%d, configured cap=%d", r.pruned_states, r.peak_states or 0, {states}))
end

if r.branch_analysis ~= nil then
    local b = r.branch_analysis
    local history = b.history
    local history_count = count_table(history)
    if history_count > 0 then
        print("[angryier][branch-history] retained symbolic decisions")
        print(string.format("  retained decisions      : %d (bounded provenance ledger)", history_count))
        local first = math.max(1, history_count - 7)
        for i = first, history_count do
            local h = history[i]
            if h ~= nil then
                local marker = h.alternate_is_find_target and "  <-- alternate directly hits --find" or ""
                print(string.format(
                    "    [%02d] pc=%s condition=%s chosen_target=%s alternate=%s deps=%s%s",
                    i,
                    tostring(h.pc_hex or h.pc or "?"),
                    tostring(h.chosen_condition or h.chosen or "?"),
                    tostring(h.chosen_target_hex or h.chosen_target or "?"),
                    tostring(h.alternate_target_hex or h.alternate_target or "?"),
                    tostring(h.dependency_sources or "?"),
                    marker
                ))
            end
        end
        if b.history_exact_find_index ~= nil then
            print(string.format(
                "  earlier direct-target   : history[%s] pc=%s alternate=%s",
                tostring(b.history_exact_find_index),
                tostring(b.history_exact_find_pc_hex or b.history_exact_find_pc or "?"),
                tostring(b.history_exact_find_target_hex or b.history_exact_find_target or "?")
            ))
        end
        if b.history_candidate_index ~= nil then
            print(string.format(
                "  ranked older candidate  : history[%s] pc=%s target=%s",
                tostring(b.history_candidate_index),
                tostring(b.history_candidate_pc_hex or b.history_candidate_pc or "?"),
                tostring(b.history_candidate_find_target_hex or b.history_candidate_find_target or "?")
            ))
            print(string.format(
                "  candidate CFG distance  : chosen=%s alternate=%s",
                tostring(b.history_candidate_chosen_distance or "unreachable/in-window"),
                tostring(b.history_candidate_alternate_distance or "?")
            ))
            if b.history_candidate_reason ~= nil then
                print(string.format("  candidate rationale     : %s", tostring(b.history_candidate_reason)))
            end
        end
    end

    if b.history_candidate_analysis ~= nil then
        local hc = b.history_candidate_analysis
        print("[angryier][branch-history] ranked older candidate analysis")
        print(string.format("  history index           : %s", tostring(hc.index or "?")))
        print(string.format("  branch pc               : %s", tostring(hc.pc_hex or hc.pc or "?")))
        print(string.format("  ranked find target      : %s", tostring(hc.find_target_hex or hc.find_target or "?")))
        print(string.format("  alternate target        : %s", tostring(hc.alternate_target_hex or hc.alternate_target or "?")))
        print(string.format("  chosen -> target        : %s edge(s)", tostring(hc.cfg_chosen_distance or "unreachable/in-window")))
        print(string.format("  alternate -> target     : %s edge(s)", tostring(hc.cfg_alternate_distance or "?")))
        print(string.format("  solver status           : %s", tostring(hc.solver_status or "not-run")))
        if hc.solver_elapsed_us ~= nil then
            print(string.format("  solver elapsed          : %s us", tostring(hc.solver_elapsed_us)))
        end
        if hc.replay ~= nil then
            print(string.format("  replay status           : %s", tostring(hc.replay.status or "?")))
            print(string.format("  matched alternate       : %s", yn(hc.replay.matched_alternate)))
            if hc.replay.detail ~= nil then
                print(string.format("  replay detail           : %s", tostring(hc.replay.detail)))
            end
        end
        print(string.format("  steering action         : %s", tostring(hc.steering_action or "?")))
        print(string.format("  steering confidence     : %s", tostring(hc.steering_confidence or "?")))
        print(string.format("  steering reason         : %s", tostring(hc.steering_reason or "?")))
        local candidate_model = hc.model
        local candidate_model_count = count_table(candidate_model)
        if candidate_model_count > 0 then
            print(string.format("  alternate model         : %d assignment(s)", candidate_model_count))
            local seed_flags = {{}}
            for i = 1, math.min(candidate_model_count, 12) do
                local assignment = candidate_model[i]
                if assignment ~= nil and assignment.source_kind == "register" then
                    print(string.format(
                        "    model[%02d] %s = %s",
                        i,
                        tostring(assignment.name or assignment.register or "?"),
                        tostring(assignment.value_hex or ("0x" .. tostring(assignment.hex or "")))
                    ))
                    if assignment.name ~= nil and assignment.value_hex ~= nil then
                        seed_flags[#seed_flags + 1] = "--reg " .. assignment.name .. "=" .. assignment.value_hex
                    end
                elseif assignment ~= nil then
                    print(string.format(
                        "    model[%02d] kind=%s expr=%s bytes=0x%s",
                        i,
                        tostring(assignment.source_kind or "?"),
                        tostring(assignment.expression or "?"),
                        tostring(assignment.hex or "")
                    ))
                end
            end
            if #seed_flags > 0 then
                print("  candidate seed flags    : " .. table.concat(seed_flags, " "))
            end
        end
        if hc.error ~= nil then
            print(string.format("  candidate error         : %s", tostring(hc.error)))
        end
    end

    print("[angryier][branch-analysis] most recent symbolic branch")
    print(string.format("  status                  : %s", tostring(b.status or "?")))
    if b.status == "recorded" then
        print(string.format("  branch pc               : %s", tostring(b.pc_hex or b.pc or "?")))
        print(string.format("  dynamic visit           : %s", tostring(b.visit_index or "?")))
        print(string.format("  visit identity exact    : %s", yn(b.visit_index_exact)))
        print(string.format("  path fingerprint        : %s", tostring(b.trace_fingerprint_hex or "?")))
        print(string.format("  chosen condition value  : %s", tostring(b.chosen_condition or b.chosen or "?")))
        print(string.format("  condition=true target   : %s", tostring(b.condition_true_target_hex or b.taken_target_hex or b.taken_target or "?")))
        print(string.format("  condition=false target  : %s", tostring(b.condition_false_target_hex or b.not_taken_target_hex or b.not_taken_target or "?")))
        print(string.format("  chosen target           : %s", tostring(b.chosen_target_hex or b.chosen_target or "?")))
        print(string.format("  alternate target        : %s", tostring(b.alternate_target_hex or b.alternate_target or "?")))
        if b.chosen_is_find_target then
            print("  target relation         : chosen successor exactly matches a configured --find target")
        elseif b.alternate_is_find_target then
            print("  target relation         : alternate successor exactly matches a configured --find target")
        else
            print("  target relation         : neither immediate successor is an exact configured --find target")
        end
        print(string.format("  CFG target analysis     : %s", tostring(b.cfg_status or "not-run")))
        if b.cfg_source ~= nil then
            print(string.format("  CFG recovery source     : %s", tostring(b.cfg_source)))
        end
        if b.cfg_preference ~= nil and b.cfg_preference ~= "none" then
            print(string.format("  CFG preferred edge      : %s", tostring(b.cfg_preference)))
            print(string.format("  CFG ranked find target  : %s", tostring(b.cfg_find_target_hex or b.cfg_find_target or "?")))
            print(string.format("  chosen -> target        : %s edge(s)", tostring(b.cfg_chosen_distance or "unreachable/in-window")))
            print(string.format("  alternate -> target     : %s edge(s)", tostring(b.cfg_alternate_distance or "unreachable/in-window")))
        end
        if b.cfg_error ~= nil then
            print(string.format("  CFG analysis detail     : %s", tostring(b.cfg_error)))
        end
        if b.replay ~= nil then
            local replay = b.replay
            print("[angryier][branch-analysis] concrete alternate replay")
            print(string.format("  replay status           : %s", tostring(replay.status or "?")))
            print(string.format("  replay steps            : %s", tostring(replay.steps or 0)))
            print(string.format("  expected branch visit   : %s", tostring(replay.expected_visit or "?")))
            print(string.format("  observed branch visits  : %s", tostring(replay.observed_visits or 0)))
            print(string.format("  reached branch          : %s", yn(replay.reached_branch)))
            print(string.format("  matched alternate       : %s", yn(replay.matched_alternate)))
            print(string.format("  applied registers       : %s", tostring(replay.applied_registers or 0)))
            print(string.format("  applied memory bytes    : %s", tostring(replay.applied_memory_bytes or 0)))
            print(string.format("  applied stream bytes    : %s", tostring(replay.applied_stream_bytes or 0)))
            if replay.observed_target_hex ~= nil or replay.observed_target ~= nil then
                print(string.format("  observed successor      : %s", tostring(replay.observed_target_hex or replay.observed_target)))
            end
            if replay.detail ~= nil then
                print(string.format("  replay detail           : %s", tostring(replay.detail)))
            end
        end
        if b.steering_action ~= nil then
            print(string.format("  steering action         : %s", tostring(b.steering_action)))
            print(string.format("  steering confidence     : %s", tostring(b.steering_confidence or "?")))
            print(string.format("  steering reason         : %s", tostring(b.steering_reason or "?")))
        end
        print(string.format("  condition expression    : %s", tostring(b.condition or "?")))
        print(string.format("  common prefix constraints: %s", tostring(b.prefix_constraints or 0)))
        print(string.format("  alternate solver status : %s", tostring(b.solver_status or "not-run")))
        if b.solver_elapsed_us ~= nil then
            print(string.format("  solver elapsed          : %s us", tostring(b.solver_elapsed_us)))
        end
        local deps = b.dependencies
        local dep_count = count_table(deps)
        print(string.format("  predicate dependencies  : %d source(s)", dep_count))
        for i = 1, math.min(dep_count, 12) do
            local dep = deps[i]
            if dep ~= nil and dep.source_kind == "register" then
                print(string.format(
                    "    dep[%02d] register=%s width=%s expr=%s source_id=%s",
                    i,
                    tostring(dep.name or dep.register or "?"),
                    tostring(dep.width or "?"),
                    tostring(dep.expression or "?"),
                    tostring(dep.source_id or "?")
                ))
            elseif dep ~= nil then
                print(string.format(
                    "    dep[%02d] kind=%s width=%s expr=%s source_id=%s",
                    i,
                    tostring(dep.source_kind or "?"),
                    tostring(dep.width or "?"),
                    tostring(dep.expression or "?"),
                    tostring(dep.source_id or "?")
                ))
            end
        end
        local model = b.model
        local model_count = count_table(model)
        if model_count > 0 then
            print(string.format("  alternate model         : %d assignment(s)", model_count))
            for i = 1, math.min(model_count, 12) do
                local assignment = model[i]
                if assignment ~= nil and assignment.source_kind == "register" then
                    print(string.format(
                        "    model[%02d] %s = %s",
                        i,
                        tostring(assignment.name or assignment.register or "?"),
                        tostring(assignment.value_hex or ("0x" .. tostring(assignment.hex or "")))
                    ))
                elseif assignment ~= nil then
                    print(string.format(
                        "    model[%02d] kind=%s expr=%s bytes=0x%s",
                        i,
                        tostring(assignment.source_kind or "?"),
                        tostring(assignment.expression or "?"),
                        tostring(assignment.hex or "")
                    ))
                end
            end
            local seed_flags = {{}}
            for i = 1, model_count do
                local assignment = model[i]
                if assignment ~= nil and assignment.source_kind == "register"
                    and assignment.name ~= nil and assignment.value_hex ~= nil
                then
                    seed_flags[#seed_flags + 1] = "--reg " .. assignment.name .. "=" .. assignment.value_hex
                end
            end
            if #seed_flags > 0 then
                print("  candidate seed flags    : " .. table.concat(seed_flags, " "))
                print("  replay note             : omit matching --symbolic REG flags for a concrete replay; keep them for a seeded symbolic rerun")
            end
        end
        if b.error ~= nil then
            print(string.format("  branch analysis error   : %s", tostring(b.error)))
        end
    elseif b.error ~= nil then
        print(string.format("  detail                  : %s", tostring(b.error)))
    end
end

print("[angryier][ideas] next symbolic-analysis moves")
local ideas = 0
local function idea(text)
    ideas = ideas + 1
    print(string.format("  %02d. %s", ideas, text))
end

if {symbolic_count} == 0 and {argv_enabled} == 0 then
    idea("No symbolic source was configured. Start with ABI-controlled inputs instead of symbolizing everything: on SysV AMD64 try --symbolic rdi/rsi/rdx/rcx/r8/r9 according to the target function signature, or use --argv N when input naturally enters through argv[0].")
elseif {symbolic_count} == 1 then
    idea("Only one symbolic register is active. If control flow depends on a multi-argument predicate, add the next ABI argument register rather than widening the entire machine state.")
else
    idea("Multiple symbolic registers are active. If path growth becomes expensive, reduce the symbolic frontier to the arguments that actually influence the target and use taint/trace evidence to justify each additional source.")
end

if r.frontier ~= nil then
    local deps = r.frontier.constraint_dependencies
    local dep_count = count_table(deps)
    if dep_count == 0 and ({symbolic_count} > 0 or {argv_enabled} > 0) then
        idea("The selected frontier state's retained path constraints contain no identifiable symbolic source leaves. The configured input may not be steering control flow yet, or its influence may have been concretized/overwritten; use the frontier PC and trace tail to move symbolic introduction closer to the decision point.")
    elseif dep_count > 0 then
        local names = {{}}
        for i = 1, dep_count do
            local dep = deps[i]
            if dep ~= nil and dep.source_kind == "register" and dep.name ~= nil then
                names[#names + 1] = dep.name
            end
        end
        if #names > 0 then
            idea("Retained path predicates currently depend on register source(s): " .. table.concat(names, ", ") .. ". Preserve these as the first symbolic frontier in the next experiment; concretize unrelated inputs unless trace/taint evidence shows they are also needed.")
        else
            idea("Retained path predicates depend on symbolic leaves that are not mapped to architectural register bindings. Inspect the frontier dependency source IDs together with memory/under-constrained ledgers; these may be symbolic memory bytes or fallback-created free symbols.")
        end
    end
end

if r.branch_analysis ~= nil and r.branch_analysis.status == "recorded" then
    local b = r.branch_analysis
    if b.history_candidate_analysis ~= nil then
        local hc = b.history_candidate_analysis
        if hc.steering_action == "prioritize-alternate" then
            idea("RANKED OLDER BRANCH: history[" .. tostring(hc.index or "?") .. "] is structurally better than the current path toward " .. tostring(hc.find_target_hex or hc.find_target or "the configured target") .. ", and the bounded extra solver pass ranks its alternate edge for priority (" .. tostring(hc.steering_confidence or "?") .. " confidence). Prefer this seed over blindly flipping only the newest branch.")
        elseif hc.steering_action == "reject-alternate" then
            idea("RANKED OLDER BRANCH REJECTED: the best CFG-ranked older mutation point is UNSAT under its exact pre-branch prefix. Keep the structural ranking as context, but do not spend further budget on that flip unless an earlier constraint changes.")
        elseif hc.steering_action == "unresolved" then
            idea("RANKED OLDER BRANCH UNRESOLVED: CFG structure favors an earlier mutation point, but solver/replay evidence is insufficient. Treat it as a hypothesis, not a promoted seed.")
        end
    elseif b.history_candidate_index ~= nil then
        idea("An older symbolic branch is statically closer to a configured --find target, but no candidate solve result is available. Re-enable the solver or inspect history[" .. tostring(b.history_candidate_index) .. "] manually.")
    end
    local action = b.steering_action
    local replay_status = b.replay ~= nil and b.replay.status or nil
    if replay_status == "validated" then
        idea("CONCRETE BRANCH FLIP VALIDATED: replay from the clean entry snapshot reached the recorded branch and took the solver-predicted alternate successor. This validates the immediate branch mutation in the modeled environment; it does not by itself prove the later target is reachable.")
    elseif replay_status == "mismatch" then
        idea("MODEL/REPLAY DIVERGENCE: the solver produced a SAT alternate model, but concrete replay reached the branch and took a different successor. Treat this as a fidelity bug or environment/model mismatch; do not promote the seed until the divergence is explained.")
    elseif replay_status == "path-context-mismatch" then
        idea("PATH-CONTEXT MISMATCH: concrete replay reached the expected numbered visit of the branch, but through a different entry-to-branch PC sequence. Do not call this model validated; compare the symbolic and replay traces to find the earlier divergence.")
    elseif replay_status == "ambiguous-branch-visit" then
        idea("AMBIGUOUS DYNAMIC BRANCH: the retained symbolic trace rolled over before Angryier could prove the absolute visit number. Re-run from a nearer entry/waypoint or otherwise shorten the pre-branch path before attempting proof-quality replay; the current trace cap is fixed.")
    elseif replay_status == "ambiguous-model" then
        idea("AMBIGUOUS SOLVER MODEL: multiple model entries collapse onto the same architectural register with conflicting values. Treat this as backend/model-normalization debt; inspect the reported model rather than allowing iteration order to pick a replay value.")
    elseif replay_status == "unsupported-model" then
        idea("Concrete replay was skipped because the alternate model contains symbolic inputs without exact replay provenance. Entry-time symbolic argv and explicit symbolic-memory bytes are supported; runtime-generated stdin/file/free symbols remain fail-closed until their stream/object provenance is materialized.")
    elseif replay_status == "stateful-kernel-model" or replay_status == "stateful-environment" then
        idea("Concrete replay was deliberately skipped because stateful environment/model activity cannot yet be rewound with proof-quality fidelity. Keep the solver result as symbolic evidence only.")
    elseif replay_status == "budget-exhausted" then
        idea("Concrete replay exhausted the current --steps budget before returning to the recorded branch. Increase --steps only if validating this particular flip is worth the extra replay cost.")
    end
    if action == "prioritize-alternate" then
        idea("TARGET-DIRECTED NEXT RUN: Angryier ranks the alternate edge as the best next branch (" .. tostring(b.steering_confidence or "?") .. " confidence). " .. tostring(b.steering_reason or "") .. ". Replay the reported model first, then validate the resulting path concretely before treating target reachability as established.")
    elseif action == "keep-chosen" then
        idea("KEEP CURRENT DIRECTION: Angryier currently ranks the chosen edge above the alternate (" .. tostring(b.steering_confidence or "?") .. " confidence). " .. tostring(b.steering_reason or "") .. ". Preserve the alternate model as a coverage seed if it is SAT, but do not spend target-directed budget on it first.")
    elseif action == "reject-alternate" then
        idea("PRUNE THIS FLIP: Angryier proved the alternate edge UNSAT under the exact shared pre-branch prefix. Do not retry this branch inversion unless an earlier constraint or symbolic source changes.")
    elseif action == "explore-both" then
        idea("EXPLORE BOTH EDGES: solver feasibility is available but bounded CFG evidence does not distinguish the two successors. Keep both paths alive if budget allows, or use coverage novelty / later predicates to break the tie.")
    elseif action == "explore-alternate" then
        idea("COVERAGE CANDIDATE: the alternate edge is solver-feasible but lacks strong target-direction evidence. Use the model as a secondary seed and concretely replay it before promoting it to a target-directed path.")
    elseif action == "unresolved" then
        idea("BRANCH STEERING UNRESOLVED: " .. tostring(b.steering_reason or "insufficient evidence") .. ". Inspect solver status/error and increase --branch-timeout-ms only if the predicate is genuinely worth solving; otherwise simplify the symbolic frontier first.")
    elseif b.solver_status == "Unknown" or b.solver_status == "Timeout" or b.solver_status == "ResourceLimit" then
        idea("The alternate edge was not resolved within the branch-analysis solver budget. Treat it as unknown, not infeasible.")
    end
end

if {find_count} == 0 then
    idea("No --find target is configured. Add a semantically meaningful address such as an accept/success block, vulnerable call site, error bypass, allocator/free site, or post-validation block so exploration has a concrete objective.")
elseif (r.found or 0) == 0 then
    idea("The configured target was not reached. Inspect trace_hex and the final branch neighborhood, then add an intermediate --find waypoint to determine where reachability diverges before simply multiplying the budget.")
else
    idea("A target was reached. Re-run with a custom Lua script and solve=true to recover concrete satisfying inputs/models for the found state, then replay them concretely to validate the path.")
end

if (r.forks or 0) == 0 and ({symbolic_count} > 0 or {argv_enabled} > 0) then
    idea("Symbolic data produced no forks. That usually means the chosen source has not reached a conditional yet, was overwritten/concretized, or execution ended too early; inspect the trace and move the symbolic source closer to the decision point.")
elseif (r.forks or 0) > 0 and (r.live_states or 0) > 0 then
    idea("Forking is active and live states remain. A larger --steps budget may expose deeper branches; if the state cap is the limiter, raise --states selectively and pair it with target/avoid guidance rather than only widening breadth.")
end

if (r.live_states or 0) >= {states} then
    idea("Live-state count reached the configured state budget. Re-run with a larger --states value, but pair the extra capacity with tighter targets/search policy so it does not only preserve expensive duplicate paths.")
end

if r.timed_out then
    idea("The run timed out. Increasing --timeout alone is low-value: first narrow symbolic sources, add target/avoid guidance, use intermediate waypoints, --dfs for a deep target dive, or --fork when concolic folding is suppressing useful path diversity.")
end

if (r.failed or 0) > 0 then
    idea("At least one state failed. Use last_error plus trace_hex to classify the first failure as semantic coverage, environment-model debt, memory modeling, or solver/concretization trouble before increasing exploration limits.")
end

if (r.concretization_retries or 0) > 0 then
    idea("Symbolic-address concretization was required. Treat repeated retries as a signal to improve pointer provenance: symbolize the data feeding the address expression more precisely, constrain its region, or model the allocator/object layout.")
end

if (r.pruned_states or 0) > 0 then
    idea("States were pruned by exploration economics. Inspect peak_states versus the configured cap and decide whether to raise states, add avoid targets, prefer new coverage, switch DFS/BFS strategy, or reduce irrelevant symbolic sources. More capacity without policy changes may only preserve expensive duplicate paths.")
end

if (r.region_fork_children or 0) > 0 then
    idea("Region forking created guessed address worlds. Inspect region_fork_sites (pc, expression, pinned address, region base/size); validate any interesting path with a real object/allocator model or concrete replay before treating the result as evidence.")
end

if r.unsupported_total ~= nil and r.unsupported_total > 0 then
    idea("Unsupported semantic fallback was exercised. Prioritize the first unsupported_sites entries by reachability and frequency; implementing those forms can be more valuable than adding raw steps because fallback debt weakens path fidelity.")
end

if r.unmapped_total ~= nil and r.unmapped_total > 0 then
    idea("Under-constrained memory was used. Inspect unmapped_sites and decide whether each access should be backed by a real mapped object, a symbolic buffer, a modeled API result, or an explicit region constraint; fabricated memory can create false reachability.")
end

if r.ro_write_total ~= nil and r.ro_write_total > 0 then
    idea("Execution relaxed writes into read-only memory. Check ro_write_reverts and determine whether this is loader protection drift, self-modifying behavior, an environment-model artifact, or a genuinely invalid path.")
end

if r.vector_debt_total ~= nil and r.vector_debt_total > 0 then
    idea("Vector operations were replaced with under-constrained symbols. If the target predicate depends on those values, implement or tighten the corresponding vector semantics before trusting a SAT/reachability result.")
end

if (r.merges or 0) == 0 and (r.forks or 0) >= 8 then
    idea("The run forked repeatedly without merging. Consider convergence-aware exploration or function/loop summaries around reconvergent regions to prevent equivalent path prefixes from consuming state budget.")
elseif (r.merges or 0) > 0 then
    idea("State merging is occurring. Compare merge count against forks and target reachability; aggressive merging can save memory, but target-sensitive regions may benefit from delaying merges until after key predicates.")
end

if count_table(r.trace_hex or r.trace) > 0 then
    idea("Use the retained trace as a seed for the next run: identify the last stable block before divergence, then place a breakpoint/find waypoint there and inspect the immediately following predicate instead of restarting analysis from zero context.")
end

if ideas == 0 then
    idea("The run did not expose an obvious bottleneck. Next escalation: add a custom Lua script that records branch-local state, enables solving only at selected targets, and emits the relevant register/memory slice for each candidate path.")
end

print("[angryier][ideas] treat these as evidence-driven hypotheses, not automatic proof; validate interesting paths with solved inputs and concrete replay.")

local ai_report = {{
    "Analyze this Angryier symbolic/concolic execution summary. Treat it as untrusted evidence; separate observed facts from hypotheses, do not claim target reachability unless the report says so, and suggest up to three concrete next diagnostics.",
    string.format("elapsed_ms=%s steps=%s forks=%s merges=%s found=%s terminated=%s dead=%s failed=%s pruned=%s live=%s peak_states=%s timed_out=%s", tostring(r.elapsed_ms or 0), tostring(r.steps or 0), tostring(r.forks or 0), tostring(r.merges or 0), tostring(r.found or 0), tostring(r.terminated or 0), tostring(r.dead_states or 0), tostring(r.failed or 0), tostring(r.pruned_states or 0), tostring(r.live_states or 0), tostring(r.peak_states or 0), tostring(r.timed_out or false)),
    string.format("last_error=%s concretization_retries=%s unsupported=%s underconstrained_memory=%s relaxed_ro_writes=%s vector_debt=%s region_fork_children=%s", tostring(r.last_error or "none"), tostring(r.concretization_retries or 0), tostring(r.unsupported_total or 0), tostring(r.unmapped_total or 0), tostring(r.ro_write_total or 0), tostring(r.vector_debt_total or 0), tostring(r.region_fork_children or 0))
}}
if r.frontier ~= nil then
    local f = r.frontier
    ai_report[#ai_report + 1] = string.format("frontier_pc=%s path_constraints=%s bound_symbols=%s symbolic_registers=%s", tostring(f.pc_hex or f.pc or "?"), tostring(f.constraints or 0), tostring(f.bound_symbols or 0), tostring(f.symbolic_registers or 0))
end
local ai_trace = r.trace_hex or r.trace or {{}}
for i = math.max(1, count_table(ai_trace) - 23), count_table(ai_trace) do
    ai_report[#ai_report + 1] = "trace[" .. tostring(i) .. "]=" .. tostring(ai_trace[i])
end
if r.branch_analysis ~= nil and r.branch_analysis.history ~= nil then
    local history = r.branch_analysis.history
    for i = math.max(1, count_table(history) - 7), count_table(history) do
        local h = history[i]
        if h ~= nil then
            ai_report[#ai_report + 1] = string.format("branch[%d] pc=%s chosen=%s alternate=%s", i, tostring(h.pc_hex or h.pc or "?"), tostring(h.chosen_target_hex or h.chosen_target or "?"), tostring(h.alternate_target_hex or h.alternate_target or "?"))
        end
    end
end
angryier_ai_summary(r.steps or 0, table.concat(ai_report, "\n"))"#,
            path = escaped_path,
            regs_opt = regs_opt,
            avoid_table = avoid_table,
            solve_opt = solve_opt,
            fork_opt = fork_opt,
            dfs_opt = dfs_opt,
            steps = config.steps,
            states = config.states,
            timeout_secs = config.timeout_secs,
            branch_timeout_ms = config.branch_timeout_ms,
            symbolic_count = config.symbolic.len(),
            argv_enabled = usize::from(config.argv.is_some()),
            find_count = config.find.len()
        )
    }

    fn read_bounded<R: Read>(mut reader: R, limit: usize) -> std::io::Result<Vec<u8>> {
        let mut output = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            let remaining = limit.saturating_sub(output.len());
            output.extend_from_slice(&buffer[..count.min(remaining)]);
        }
        Ok(output)
    }

    fn call_hax_model(model: &str, prompt: &str, timeout: Duration) -> Result<String, &'static str> {
        let mut child = Command::new("hax")
            .args([
                "--print",
                "--no-session",
                "--raw",
                "--provider",
                "orcarouter",
                "--model",
                model,
                "--effort",
                "low",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|_| "could not start HAX")?;

        let mut stdin = child.stdin.take().ok_or("HAX stdin unavailable")?;
        if stdin.write_all(prompt.as_bytes()).is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return Err("could not send the bounded report to HAX");
        }
        drop(stdin);

        let stdout = child.stdout.take().ok_or("HAX stdout unavailable")?;
        let stderr = child.stderr.take().ok_or("HAX stderr unavailable")?;
        let stdout_reader = std::thread::spawn(move || read_bounded(stdout, 32 * 1024));
        let stderr_reader = std::thread::spawn(move || read_bounded(stderr, 8 * 1024));
        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break Some(status),
                Ok(None) if started.elapsed() < timeout => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                Err(_) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
            }
        };
        let stdout = stdout_reader
            .join()
            .map_err(|_| "HAX output reader failed")?
            .map_err(|_| "could not read HAX output")?;
        let _stderr = stderr_reader
            .join()
            .map_err(|_| "HAX error reader failed")?
            .map_err(|_| "could not read HAX status")?;
        let status = status.ok_or("HAX model request timed out")?;
        if !status.success() {
            return Err("HAX model request failed");
        }
        // Model output is untrusted terminal text; discard escape/control codes.
        let response = String::from_utf8_lossy(&stdout)
            .chars()
            .filter(|character| !character.is_control() || matches!(*character, '\n' | '\r' | '\t'))
            .collect::<String>()
            .trim()
            .to_string();
        if response.is_empty() {
            return Err("HAX returned an empty response");
        }
        Ok(response)
    }

    fn ai_analysis_eligible(enabled: bool, steps: u64, min_steps: u64) -> bool {
        enabled && steps >= min_steps
    }

    fn analyze_with_fallback<T, E>(
        prompt: &str,
        timeout_secs: u64,
        models: &[String],
        mut runner: impl FnMut(&str, &str, Duration) -> Result<T, E>,
    ) -> Result<(String, T), String>
    where
        E: std::fmt::Display,
    {
        let total_timeout = Duration::from_secs(timeout_secs.min(AI_ANALYSIS_MAX_TOTAL_TIMEOUT_SECS));
        let deadline = Instant::now() + total_timeout;
        for model in models {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            match runner(model, prompt, AI_ANALYSIS_TIMEOUT.min(remaining)) {
                Ok(response) => return Ok((model.clone(), response)),
                Err(reason) => eprintln!("[angryier][ai] {model} unavailable ({reason}); trying next free model"),
            }
        }
        Err(format!("all {} configured free OrcaRouter models failed", models.len()))
    }

    fn analyze_with_hax(prompt: &str, timeout_secs: u64, models: &[String]) -> Result<(String, String), String> {
        analyze_with_fallback(prompt, timeout_secs, models, |model, prompt, timeout| {
            call_hax_model(model, prompt, timeout)
        })
    }

    fn ai_analysis_output(
        enabled: bool,
        steps: u64,
        min_steps: u64,
        prompt: &str,
        timeout_secs: u64,
        models: &[String],
        analyze: impl FnOnce(&str, u64, &[String]) -> Result<(String, String), String>,
    ) -> Option<String> {
        if !ai_analysis_eligible(enabled, steps, min_steps) {
            return None;
        }
        Some(match analyze(prompt, timeout_secs, models) {
            Ok((model, response)) => {
                format!("[angryier][ai] post-analysis via orcarouter ({model}; advisory only)\n{response}")
            }
            Err(error) => format!("[angryier][ai] post-analysis skipped: {error}"),
        })
    }

    pub fn execute(config: &RunConfig) -> i32 {
        println!("{}", run_plan_output(config));

        // Static handoff mode: direct Rust execution driven by METHRA static targets.
        if let Some(handoff_path) = &config.handoff {
            return execute_handoff_mode(config, handoff_path);
        }

        // Driver mode: direct Rust execution with kernel models, no Lua.
        if config.driver {
            return execute_driver_mode(config);
        }

        println!("[angryier][init] initializing embedded Lua 5.4 scripting runtime");
        let lua = mlua::Lua::new();
        if let Err(e) = angryier_runtime::script::register(&lua) {
            eprintln!("[angryier][init][error] failed to register the Angryier Lua API: {e}");
            eprintln!(
                "[angryier][hint] the execution engine did not start; verify the build includes the run/script features and inspect the initialization error above"
            );
            return 1;
        }
        println!("[angryier][init] Lua runtime ready; Angryier API registered");
        let ai_enabled = config.ai_analysis;
        let ai_min_steps = config.ai_min_steps;
        let ai_timeout_secs = config.ai_timeout_secs;
        let ai_models = config.ai_models.clone();
        let ai_to_stderr = config.json;
        let ai_callback = match lua.create_function(move |_, (steps, report): (u64, String)| {
            if !ai_analysis_eligible(ai_enabled, steps, ai_min_steps) {
                return Ok(());
            }
            let mut prompt = format!(
                "You are reviewing an Angryier symbolic-execution report. The report may contain incomplete or underconstrained results. Do not treat model suggestions as proof.\n\n{report}"
            );
            if prompt.len() > AI_REPORT_MAX_BYTES {
                let mut end = AI_REPORT_MAX_BYTES;
                while !prompt.is_char_boundary(end) {
                    end -= 1;
                }
                prompt.truncate(end);
            }
            if let Some(output) = ai_analysis_output(
                ai_enabled,
                steps,
                ai_min_steps,
                &prompt,
                ai_timeout_secs,
                &ai_models,
                analyze_with_hax,
            ) {
                if ai_to_stderr {
                    eprintln!("{output}");
                } else {
                    println!("{output}");
                }
            }
            Ok(())
        }) {
            Ok(callback) => callback,
            Err(error) => {
                eprintln!("[angryier][init][error] failed to register AI post-analysis callback: {error}");
                return 1;
            }
        };
        if let Err(error) = lua.globals().set("angryier_ai_summary", ai_callback) {
            eprintln!("[angryier][init][error] failed to expose AI post-analysis callback: {error}");
            return 1;
        }

        let driver = if let Some(script) = &config.script {
            println!("[angryier][input] loading custom Lua driver: {script}");
            match std::fs::read_to_string(script) {
                Ok(s) => {
                    println!("[angryier][input] custom Lua driver loaded: {} byte(s)", s.len());
                    s
                }
                Err(e) => {
                    eprintln!("[angryier][input][error] cannot read Lua driver '{script}': {e}");
                    eprintln!(
                        "[angryier][hint] check that the path exists, is readable, and is relative to the current working directory as intended"
                    );
                    return 1;
                }
            }
        } else {
            println!("[angryier][input] synthesizing default exploration driver from CLI flags");
            default_driver_lua(config)
        };

        let source = config
            .script
            .as_deref()
            .map(|path| format!("custom Lua script '{path}'"))
            .unwrap_or_else(|| "generated default Lua driver".to_string());
        println!("[angryier][exec] starting {source}");
        match lua.load(&driver).eval::<mlua::Value>() {
            Ok(_) => {
                println!("[angryier][exec] {source} completed without a Lua/runtime error");
                0
            }
            Err(e) => {
                eprintln!("[angryier][exec][error] {source} failed: {e}");
                eprintln!(
                    "[angryier][hint] execution stopped at the reported Lua/runtime error; inspect the preceding plan and result lines to confirm mode, limits, and symbolic inputs"
                );
                1
            }
        }
    }

    /// Static handoff mode: load driver binary, ingest METHRA static targets
    /// from JSON, synthesize layout-aware driver states, and emit canonical
    /// verdicts matching `symbolic_verdict.schema.json`.
    fn execute_handoff_mode(config: &RunConfig, handoff_path: &str) -> i32 {
        use angryier::driver_ioctl::{KernelLayout, StaticHandoff, StaticHandoffTarget};
        use angryier::{Engine, RunReport};

        println!("[angryier][handoff] reading static handoff from: {handoff_path}");
        let handoff_json = match std::fs::read_to_string(handoff_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[angryier][handoff][error] cannot read handoff file '{handoff_path}': {e}");
                return 1;
            }
        };

        let handoff = match StaticHandoff::from_json(&handoff_json) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("[angryier][handoff][error] invalid static handoff JSON: {e}");
                return 1;
            }
        };

        let arch_str = config.arch.as_deref().unwrap_or(&handoff.arch);
        let layout = match KernelLayout::for_arch(arch_str) {
            Some(l) => l,
            None => {
                eprintln!("[angryier][handoff][error] unsupported architecture '{arch_str}'");
                return 1;
            }
        };

        println!(
            "[angryier][handoff] METHRA static handoff loaded: {} target(s), arch={}, image_base={:#x}",
            handoff.targets.len(),
            handoff.arch,
            handoff.image_base
        );
        if let Some(producer) = &handoff.producer {
            println!("  producer       : {producer}");
        }
        if let Some(name) = &handoff.binary_name {
            println!("  binary name    : {name}");
        }
        println!("  binary sha256  : {}", handoff.binary_sha256);

        let targets: Vec<&StaticHandoffTarget> = if let Some(target_id) = &config.handoff_target {
            let matched: Vec<_> = handoff.targets.iter().filter(|t| &t.target_id == target_id).collect();
            if matched.is_empty() {
                eprintln!("[angryier][handoff][error] target '{target_id}' not found in handoff");
                return 1;
            }
            matched
        } else {
            handoff.targets.iter().collect()
        };

        println!("[angryier][init] initializing Angryier engine for targeted exploration");
        let engine = match Engine::new() {
            Ok(e) => e,
            Err(e) => {
                eprintln!("[angryier][init][error] failed to initialize engine: {e}");
                return 1;
            }
        };

        println!("[angryier][load] loading target binary: {}", config.path);
        let image = match engine.load(&config.path) {
            Ok(img) => img,
            Err(e) => {
                eprintln!("[angryier][load][error] failed to load binary '{}': {e}", config.path);
                return 1;
            }
        };

        let mut total_verdicts = 0;
        let mut feasible_count = 0;

        for target in targets {
            println!(
                "[angryier][target] ID={} | sink={} | handler_rva={:#x} | sink_rva={:#x}",
                target.target_id, target.sink_name, target.handler_rva, target.sink_rva
            );

            let driver_targets = target.to_driver_targets(handoff.image_base);
            for driver_target in driver_targets {
                let start = std::time::Instant::now();
                let mut options = match driver_target.run_options_with_layout(layout, config.steps, config.states) {
                    Ok(opts) => opts,
                    Err(e) => {
                        eprintln!("[angryier][target][error] failed to construct run options: {e}");
                        continue;
                    }
                };

                // Propagate CLI stubs, redirects, and patches if any
                options.stubs.extend(config.stubs.iter().cloned());
                options.redirects.extend(config.redirects.iter().cloned());
                options.patches.extend(config.patches.iter().cloned());

                let report = match engine.run(&image, &options) {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("[angryier][exec][error] exploration error: {e}");
                        RunReport {
                            last_error: Some(format!("{e}")),
                            ..RunReport::default()
                        }
                    }
                };

                let elapsed_secs = start.elapsed().as_secs_f64();
                let verdict = driver_target.classify_run_with_metadata(
                    &report,
                    elapsed_secs,
                    Some(&target.target_id),
                    Some(&target.sink_name),
                    Some(&handoff.binary_sha256),
                );

                total_verdicts += 1;
                if verdict.verdict == angryier::driver_ioctl::DriverVerdict::PathFeasibleUnchecked
                    || verdict.verdict == angryier::driver_ioctl::DriverVerdict::PathFeasibleConstrained
                {
                    feasible_count += 1;
                }

                if config.json {
                    println!("{}", verdict.to_json());
                } else {
                    println!("{verdict}");
                    println!("[angryier][verdict][json] {}", verdict.to_json());
                }
            }
        }

        println!(
            "[angryier][summary] verification complete: {} verdict(s) emitted, {} feasible path(s)",
            total_verdicts, feasible_count
        );
        0
    }

    /// PE driver mode: load, attach kernel models, execute DriverEntry,
    /// and report pool/kernel events. No Lua — direct Rust execution.
    fn execute_driver_mode(config: &RunConfig) -> i32 {
        use angryier_runtime::Runtime;
        use angryier_types::{SemanticVersion, TargetProfileId};

        println!("[angryier][load] reading PE driver image: {}", config.path);
        let bytes = match std::fs::read(&config.path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!(
                    "[angryier][load][error] cannot read driver image '{}': {e}",
                    config.path
                );
                eprintln!(
                    "[angryier][hint] verify the path, permissions, and that the target is the intended PE32+ driver image"
                );
                return 1;
            }
        };
        println!("[angryier][load] input read successfully: {} byte(s)", bytes.len());

        println!("[angryier][init] constructing native-XED runtime (semantic_version=1, target_profile=1)");
        let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
        let mut process = match runtime.load_pe_driver(&bytes) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("[angryier][load][error] PE driver mapping/initialization failed: {e}");
                eprintln!(
                    "[angryier][hint] confirm the file is a supported PE32+ driver and inspect the loader error for the rejected structure or mapping"
                );
                return 1;
            }
        };

        let tracker = std::sync::Arc::new(angryier_models::KernelPoolTracker::new());
        if let Err(e) = runtime.attach_kernel_pool_model(&mut process, tracker.clone()) {
            eprintln!("[angryier][model][error] failed to attach the kernel pool model: {e}");
            eprintln!(
                "[angryier][hint] execution has not started; pool allocation/free events would be unreliable without this model, so Angryier stops fail-closed"
            );
            return 1;
        }
        println!(
            "[angryier][model] kernel pool model attached; allocations, frees, and double-free events will be tracked"
        );

        if !config.regs.is_empty() {
            println!(
                "[angryier][input] applying {} concrete register seed(s)",
                config.regs.len()
            );
            for (name, value) in &config.regs {
                let Some(register) = angryier_runtime::script::reg_by_name(name) else {
                    eprintln!("[angryier][input][error] validated register '{name}' could not be resolved");
                    return 1;
                };
                if let Err(error) = process.write_register(register, *value) {
                    eprintln!("[angryier][input][error] failed to seed {name}={value:#x}: {error}");
                    return 1;
                }
                println!("  {name:<4} = {value:#018x}");
            }
        }

        if !config.stubs.is_empty() {
            println!("[angryier][stub] applying {} function stub(s)", config.stubs.len());
            for (address, ret_val) in &config.stubs {
                process.stub_function(*address, *ret_val);
                println!("  {address:#x} -> ret {ret_val:#x}");
            }
        }

        if !config.redirects.is_empty() {
            println!(
                "[angryier][redirect] applying {} control-flow redirect(s)",
                config.redirects.len()
            );
            for (from_pc, to_pc) in &config.redirects {
                process.redirect_control_flow(*from_pc, *to_pc);
                println!("  {from_pc:#x} -> {to_pc:#x}");
            }
        }

        if !config.patches.is_empty() {
            println!(
                "[angryier][patch] applying {} memory/code patch(es)",
                config.patches.len()
            );
            for (address, bytes) in &config.patches {
                if let Err(error) = process.patch_bytes(*address, bytes) {
                    eprintln!("[angryier][patch][error] failed to patch {address:#x}: {error}");
                    return 1;
                }
                println!("  {address:#x} -> {} byte(s)", bytes.len());
            }
        }

        let imports: Vec<_> = process.pe_imports().collect();
        println!("[angryier][load] PE driver initialized");
        println!("  entry pc       : {:#x}", process.pc().unwrap_or(0));
        println!("  imports        : {}", imports.len());
        println!("  modeled hooks  : {}", imports.len());
        if imports.is_empty() {
            println!("  import preview : none");
        } else {
            println!(
                "  import preview : first {} entr{}",
                imports.len().min(12),
                if imports.len().min(12) == 1 { "y" } else { "ies" }
            );
            for (address, dll, name) in imports.iter().take(12) {
                println!("    {:#x} -> {}!{}", **address, dll, name);
            }
            if imports.len() > 12 {
                println!(
                    "    ... {} additional import(s) omitted from the preview",
                    imports.len() - 12
                );
            }
        }

        let budget = config.steps;
        let mut steps: u64 = 0;
        println!("[angryier][exec] entering DriverEntry execution loop; budget={budget} runtime step(s)");
        println!(
            "[angryier][trace] the first 12 ordinary instruction steps are shown in full; modeled calls/traps/termination remain visible afterwards"
        );

        let stop_reason = loop {
            if steps >= budget {
                println!("[angryier][exec] stop condition reached: step budget exhausted ({steps}/{budget})");
                break format!("step budget exhausted at {steps}/{budget}");
            }

            let outcome = match runtime.step(&mut process) {
                Ok(outcome) => outcome,
                Err(e) => {
                    let pc = process.pc().unwrap_or(0);
                    eprintln!(
                        "[angryier][exec][blocked] runtime could not execute the next step; completed_steps={steps}, pc={pc:#x}, reason={e}"
                    );
                    eprintln!(
                        "[angryier][hint] common causes are an unsupported instruction semantic, unresolved environment behavior, invalid memory/register state, or a model boundary; the PC above is the first place to inspect"
                    );
                    break format!("runtime blocked at pc={pc:#x}: {e}");
                }
            };
            steps += 1;

            let ordinary_instruction = matches!(&outcome, angryier_runtime::StepOutcome::Stepped { .. });
            if steps <= 12 || !ordinary_instruction {
                println!("{}", driver_step_output(steps, &outcome));
            } else if steps == 13 {
                println!(
                    "[angryier][trace] routine per-instruction lines suppressed after step 12 to avoid turning long analyses into I/O-bound runs; high-signal events are still printed"
                );
            }

            if steps > 12 && steps.is_multiple_of(1000) {
                println!(
                    "[angryier][progress] steps={steps}/{budget}, pc={:#x}, simproc_dispatches={}",
                    process.pc().unwrap_or(0),
                    process.simproc_dispatches
                );
            }

            if process.terminated {
                println!(
                    "[angryier][exec] process marked terminated after {steps} step(s); final_pc={:#x}",
                    process.pc().unwrap_or(0)
                );
                break format!("process terminated after {steps} step(s)");
            }
        };

        let report = tracker.snapshot();
        println!("[angryier][result] PE driver execution summary");
        println!("  stop reason         : {stop_reason}");
        println!("  steps completed     : {steps}");
        println!("  configured budget   : {budget}");
        println!("  final pc            : {:#x}", process.pc().unwrap_or(0));
        println!(
            "  process terminated  : {}",
            if process.terminated { "yes" } else { "no" }
        );
        println!("  simproc dispatches  : {}", process.simproc_dispatches);
        println!("  pool allocations    : {}", report.allocs);
        println!("  pool frees          : {}", report.frees);
        println!("  double-free events  : {}", report.double_frees.len());

        if report.double_frees.is_empty() {
            println!("[angryier][verdict] no double-free event was observed by the kernel pool model during this run");
        } else {
            println!(
                "[angryier][verdict][warning] {} double-free event(s) observed:",
                report.double_frees.len()
            );
            for (index, event) in report.double_frees.iter().enumerate() {
                println!(
                    "  event #{:02}: pointer={:#x}, caller={:#x}",
                    index + 1,
                    event.pointer,
                    event.caller
                );
            }
        }
        0
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
            steps: u64,
            dynamic: bool,
        ) -> RunConfig {
            RunConfig {
                path: path.to_string(),
                script: script.map(|s| s.to_string()),
                symbolic: symbolic.iter().map(|s| s.to_string()).collect(),
                regs: Vec::new(),
                find: find.to_vec(),
                avoid: Vec::new(),
                argv,
                steps,
                states: angryier_runtime::script::DEFAULT_MAX_STATES,
                timeout_secs: angryier_runtime::script::DEFAULT_TIMEOUT_SECS,
                branch_timeout_ms: angryier_runtime::script::DEFAULT_BRANCH_TIMEOUT_MS,
                solve: false,
                fork: false,
                dfs: false,
                dynamic,
                driver: false,
                stubs: Vec::new(),
                redirects: Vec::new(),
                patches: Vec::new(),
                handoff: None,
                handoff_target: None,
                json: false,
                ai_analysis: true,
                ai_min_steps: AI_ANALYSIS_MIN_STEPS,
                ai_timeout_secs: AI_ANALYSIS_TOTAL_TIMEOUT.as_secs(),
                ai_models: AI_MODELS.iter().map(|model| model.to_string()).collect(),
                arch: None,
            }
        }

        #[test]
        fn parses_minimal_invocation() {
            let parsed = parse(&args(&["./bin"])).expect("minimal invocation parses");
            assert_eq!(parsed, config("./bin", None, &[], &[], None, 256, false));
            assert!(parsed.ai_analysis);
        }

        #[test]
        fn ai_analysis_can_be_disabled_and_rejects_duplicate_flag() {
            let parsed = parse(&args(&["./bin", "--no-ai-analysis"])).expect("AI opt-out parses");
            assert!(!parsed.ai_analysis);
            assert!(parse(&args(&["./bin", "--no-ai-analysis", "--no-ai-analysis"])).is_err());
        }

        #[test]
        fn ai_analysis_defaults_and_configuration_bounds_are_stable() {
            let parsed = parse(&args(&["./bin"])).expect("default AI configuration parses");
            assert!(parsed.ai_analysis);
            assert_eq!(parsed.ai_min_steps, AI_ANALYSIS_MIN_STEPS);
            assert_eq!(parsed.ai_timeout_secs, AI_ANALYSIS_TOTAL_TIMEOUT.as_secs());
            assert_eq!(
                parsed.ai_models,
                AI_MODELS.iter().map(|model| model.to_string()).collect::<Vec<_>>()
            );

            let configured = parse(&args(&["./bin", "--ai-min-steps", "1", "--ai-timeout-secs", "3600"]))
                .expect("minimum and maximum supported values parse");
            assert_eq!(configured.ai_min_steps, 1);
            assert_eq!(configured.ai_timeout_secs, 3600);
            for invalid in ["0", "nope"] {
                assert!(parse(&args(&["./bin", "--ai-min-steps", invalid])).is_err());
            }
            for invalid in ["0", "3601", "nope"] {
                assert!(parse(&args(&["./bin", "--ai-timeout-secs", invalid])).is_err());
            }
        }

        #[test]
        fn ai_models_preserve_order_and_reject_unknown_or_duplicate_values() {
            let parsed = parse(&args(&[
                "./bin",
                "--ai-model",
                AI_MODELS[2],
                "--ai-model",
                AI_MODELS[0],
            ]))
            .expect("configured model order parses");
            assert_eq!(parsed.ai_models, vec![AI_MODELS[2], AI_MODELS[0]]);
            assert!(parse(&args(&["./bin", "--ai-model", "not/allowed"])).is_err());
            assert!(
                parse(&args(&[
                    "./bin",
                    "--ai-model",
                    AI_MODELS[0],
                    "--ai-model",
                    AI_MODELS[0]
                ]))
                .is_err()
            );
        }

        #[test]
        fn parses_handoff_flags() {
            let res = parse(&args(&[
                "./driver.sys",
                "--handoff",
                "targets.json",
                "--handoff-target",
                "TGT-VBOXUSBMON-001",
                "--json",
                "--arch",
                "x64",
            ]))
            .expect("valid handoff parse");
            assert_eq!(res.path, "./driver.sys");
            assert_eq!(res.handoff.as_deref(), Some("targets.json"));
            assert_eq!(res.handoff_target.as_deref(), Some("TGT-VBOXUSBMON-001"));
            assert!(res.json);
            assert_eq!(res.arch.as_deref(), Some("x64"));
        }

        #[test]
        fn rejects_duplicate_handoff_flags() {
            assert!(parse(&args(&["./driver.sys", "--handoff", "t1.json", "--handoff", "t2.json"])).is_err());
            assert!(
                parse(&args(&[
                    "./driver.sys",
                    "--handoff-target",
                    "T1",
                    "--handoff-target",
                    "T2"
                ]))
                .is_err()
            );
            assert!(parse(&args(&["./driver.sys", "--json", "--json"])).is_err());
            assert!(parse(&args(&["./driver.sys", "--arch", "x64", "--arch", "x86"])).is_err());
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
                    "--steps",
                    "512",
                    "--dynamic"
                ])),
                Ok(config(
                    "./bin",
                    Some("f.lua"),
                    &["rdi", "rsi"],
                    &[0x40102a],
                    Some(8),
                    512,
                    true
                ))
            );
        }

        #[test]
        fn steps_default_matches_lua_api_default() {
            // The CLI default must equal the Lua `angry.run` opts.steps
            // default so the synthesized driver cannot drift from scripts.
            assert_eq!(
                parse(&args(&["./bin"])),
                Ok(config(
                    "./bin",
                    None,
                    &[],
                    &[],
                    None,
                    angryier_runtime::script::DEFAULT_STEPS,
                    false
                ))
            );
            assert_eq!(angryier_runtime::script::DEFAULT_STEPS, 256);
        }

        #[test]
        fn steps_flag_overrides_default() {
            assert_eq!(
                parse(&args(&["./bin", "--steps", "4096"])),
                Ok(config("./bin", None, &[], &[], None, 4096, false))
            );
        }

        #[test]
        fn parses_repeatable_concrete_register_seeds() {
            let cfg = parse(&args(&[
                "./bin",
                "--reg",
                "rdi=42",
                "--reg",
                "rsi=0x1337",
                "--reg",
                "r15=0xffffffffffffffff",
            ]))
            .expect("valid register seeds");
            assert_eq!(
                cfg.regs,
                vec![
                    ("rdi".to_string(), 42),
                    ("rsi".to_string(), 0x1337),
                    ("r15".to_string(), u64::MAX),
                ]
            );
        }

        #[test]
        fn invalid_concrete_register_seed_is_descriptive() {
            let bad_shape = parse(&args(&["./bin", "--reg", "rdi"])).expect_err("missing equals must fail");
            assert!(bad_shape.contains("REG=VALUE"), "{bad_shape}");
            let bad_reg = parse(&args(&["./bin", "--reg", "xmm0=1"])).expect_err("unsupported register must fail");
            assert!(bad_reg.contains("invalid --reg register 'xmm0'"), "{bad_reg}");
            let bad_value = parse(&args(&["./bin", "--reg", "rdi=nope"])).expect_err("bad value must fail");
            assert!(bad_value.contains("decimal or 0x-prefixed hexadecimal"), "{bad_value}");
        }

        #[test]
        fn default_driver_threads_register_seeds_into_lua() {
            let mut cfg = config("./bin", None, &[], &[], None, 256, false);
            cfg.regs = vec![("rdi".to_string(), 42), ("r15".to_string(), u64::MAX)];
            let lua = default_driver_lua(&cfg);
            assert!(lua.contains("rdi = 42"), "{lua}");
            assert!(lua.contains(r#"r15_hex = "0xffffffffffffffff""#), "{lua}");
        }

        #[test]
        fn generated_driver_contains_syntactically_valid_ai_report_hook() {
            let cfg = config("./bin", None, &[], &[], None, 1000, false);
            let source = default_driver_lua(&cfg);
            assert!(source.contains("angryier_ai_summary(r.steps or 0"));
            assert!(source.contains("trace["));
            mlua::Lua::new()
                .load(&source)
                .into_function()
                .expect("generated Lua with AI report hook should parse");
        }

        #[test]
        fn parses_repeatable_avoid_targets() {
            let cfg =
                parse(&args(&["./bin", "--avoid", "0x401000", "--avoid", "402000"])).expect("valid avoid targets");
            assert_eq!(cfg.avoid, vec![0x401000, 0x402000]);
        }

        #[test]
        fn invalid_avoid_target_is_descriptive() {
            let error = parse(&args(&["./bin", "--avoid", "not-an-address"])).expect_err("bad avoid address must fail");
            assert!(error.contains("invalid --avoid address"), "{error}");
        }

        #[test]
        fn default_driver_threads_avoid_targets_into_lua() {
            let mut cfg = config("./bin", None, &[], &[], None, 256, false);
            cfg.avoid = vec![0x401000, 0x402000];
            let lua = default_driver_lua(&cfg);
            assert!(lua.contains("avoid = { 4198400,4202496 }"), "{lua}");
        }

        #[test]
        fn parses_symbolic_search_controls() {
            let cfg = parse(&args(&[
                "./bin",
                "--states",
                "64",
                "--timeout",
                "300",
                "--branch-timeout-ms",
                "5000",
                "--solve",
                "--fork",
                "--dfs",
            ]))
            .expect("valid search controls");
            assert_eq!(cfg.states, 64);
            assert_eq!(cfg.timeout_secs, 300);
            assert_eq!(cfg.branch_timeout_ms, 5000);
            assert!(cfg.solve);
            assert!(cfg.fork);
            assert!(cfg.dfs);
        }

        #[test]
        fn symbolic_search_controls_reject_bad_values() {
            assert!(parse(&args(&["./bin", "--states", "0"])).is_err());
            assert!(parse(&args(&["./bin", "--timeout", "0"])).is_err());
            assert!(parse(&args(&["./bin", "--branch-timeout-ms", "10001"])).is_err());
            assert!(parse(&args(&["./bin", "--solve", "--solve"])).is_err());
            assert!(parse(&args(&["./bin", "--fork", "--fork"])).is_err());
            assert!(parse(&args(&["./bin", "--dfs", "--dfs"])).is_err());
        }

        #[test]
        fn default_driver_threads_search_controls_into_lua() {
            let mut cfg = config("./bin", None, &["rdi"], &[0x401000], None, 4096, false);
            cfg.states = 64;
            cfg.timeout_secs = 300;
            cfg.branch_timeout_ms = 5000;
            cfg.solve = true;
            cfg.fork = true;
            cfg.dfs = true;
            let lua = default_driver_lua(&cfg);
            for expected in [
                "states = 64",
                "timeout_secs = 300",
                "branch_timeout_ms = 5000",
                "solve = true",
                "exploration = \"fork\"",
                "search = \"dfs\"",
            ] {
                assert!(lua.contains(expected), "missing search control {expected}: {lua}");
            }
        }

        #[test]
        fn repeated_steps_flag_errors() {
            assert_eq!(
                parse(&args(&["./bin", "--steps", "64", "--steps", "128"])),
                Err("duplicate --steps value '128' (flag may only be given once)".to_string())
            );
        }

        #[test]
        fn repeated_dynamic_flag_errors() {
            assert_eq!(
                parse(&args(&["./bin", "--dynamic", "--dynamic"])),
                Err("duplicate --dynamic flag (may only be given once)".to_string())
            );
        }

        #[test]
        fn non_numeric_steps_errors() {
            assert_eq!(
                parse(&args(&["./bin", "--steps", "many"])),
                Err("invalid --steps value 'many' (expected a non-negative integer)".to_string())
            );
        }

        #[test]
        fn default_driver_threads_steps_and_shared_constants() {
            let mut cfg = config("./bin", None, &[], &[], None, 256, false);
            let lua = default_driver_lua(&cfg);
            assert!(
                lua.contains(&format!("steps = {}", angryier_runtime::script::DEFAULT_STEPS)),
                "driver must default to the Lua API default, got: {lua}"
            );
            assert!(
                lua.contains(&format!("states = {}", angryier_runtime::script::DEFAULT_MAX_STATES)),
                "driver must keep the Lua API states default, got: {lua}"
            );
            assert!(!lua.contains("steps = 1024"), "stale 1024 default: {lua}");
            cfg.steps = 512;
            assert!(default_driver_lua(&cfg).contains("steps = 512"));
        }

        #[test]
        fn default_driver_emits_diagnostic_metrics_and_future_ideas() {
            let cfg = config("./bin", None, &["rdi"], &[0x401000], None, 512, false);
            let lua = default_driver_lua(&cfg);
            for expected in [
                "pruned states",
                "failed states",
                "live states",
                "dead states",
                "peak live states",
                "concretization retries",
                "region-fork children",
                "trace blocks",
                "[angryier][analysis] evidence interpretation",
                "evidence quality",
                "primary limiter",
                "frontier block",
                "[angryier][analysis] symbolic frontier",
                "[angryier][branch-history] retained symbolic decisions",
                "ranked older candidate",
                "[angryier][branch-history] ranked older candidate analysis",
                "RANKED OLDER BRANCH",
                "[angryier][branch-analysis] most recent symbolic branch",
                "alternate solver status",
                "target relation",
                "CFG target analysis",
                "CFG recovery source",
                "steering action",
                "steering confidence",
                "steering reason",
                "[angryier][branch-analysis] concrete alternate replay",
                "replay status",
                "CONCRETE BRANCH FLIP VALIDATED",
                "MODEL/REPLAY DIVERGENCE",
                "PATH-CONTEXT MISMATCH",
                "AMBIGUOUS DYNAMIC BRANCH",
                "AMBIGUOUS SOLVER MODEL",
                "path fingerprint",
                "expected branch visit",
                "TARGET-DIRECTED NEXT RUN",
                "branch_analysis = true",
                "constraint dependencies",
                "symbolic register set",
                "path-relevant registers",
                "non-predicate symbolic",
                "Retained path predicates currently depend on register source(s)",
                "[angryier][ideas] next symbolic-analysis moves",
                "ABI-controlled inputs",
                "intermediate --find waypoint",
                "solve=true",
                "Unsupported semantic fallback",
                "Under-constrained memory",
                "Vector operations were replaced with under-constrained symbols",
                "Use the retained trace as a seed for the next run",
            ] {
                assert!(lua.contains(expected), "missing diagnostic/advice text: {expected}");
            }
        }

        #[test]
        fn default_driver_escapes_binary_path() {
            let cfg = config(r#"./path/with\slash/and\"quote"#, None, &[], &[], None, 256, false);
            let lua = default_driver_lua(&cfg);
            assert!(lua.contains(r#"./path/with\\slash/and\\\"quote"#));
        }

        #[test]
        fn default_driver_marks_symbolic_registers() {
            let cfg = config("./bin", None, &["rdi", "rsi"], &[0x10], None, 256, false);
            let lua = default_driver_lua(&cfg);
            assert!(lua.contains(&format!("rdi = {}", angryier_runtime::script::SYMBOLIC_GPR_WIDTH)));
            assert!(lua.contains(&format!("rsi = {}", angryier_runtime::script::SYMBOLIC_GPR_WIDTH)));
            assert!(lua.contains("find = { 16 }"));
        }

        #[test]
        fn find_accepts_hex_without_prefix() {
            assert_eq!(
                parse(&args(&["./bin", "--find", "0x40102a", "--find", "40102a"])),
                Ok(config("./bin", None, &[], &[0x40102a, 0x40102a], None, 256, false))
            );
        }

        #[test]
        fn parses_stubs_redirects_and_patches() {
            let parsed = parse(&args(&[
                "./bin",
                "--stub",
                "0x401000=1",
                "--redirect",
                "0x401050=0x401080",
                "--patch",
                "0x401020=9090eb05",
            ]))
            .expect("parse should succeed");
            assert_eq!(parsed.stubs, vec![(0x401000, 1)]);
            assert_eq!(parsed.redirects, vec![(0x401050, 0x401080)]);
            assert_eq!(parsed.patches, vec![(0x401020, vec![0x90, 0x90, 0xeb, 0x05])]);
        }

        #[test]
        fn default_driver_threads_stubs_redirects_patches_into_lua() {
            let mut cfg = config("./bin", None, &[], &[], None, 256, false);
            cfg.stubs = vec![(0x401000, 0)];
            cfg.redirects = vec![(0x401050, 0x401080)];
            cfg.patches = vec![(0x401020, vec![0x90, 0x90])];
            let lua = default_driver_lua(&cfg);
            assert!(lua.contains("stubs = { [4198400] = 0 },"));
            assert!(lua.contains("redirects = { [4198480] = 4198528 },"));
            assert!(lua.contains("patches = { [4198432] = \"9090\" },"));
        }

        #[test]
        fn invalid_stub_is_descriptive() {
            assert!(parse(&args(&["./bin", "--stub", "invalid"])).is_err());
        }

        #[test]
        fn invalid_redirect_is_descriptive() {
            assert!(parse(&args(&["./bin", "--redirect", "invalid"])).is_err());
        }

        #[test]
        fn invalid_patch_is_descriptive() {
            assert!(parse(&args(&["./bin", "--patch", "0x1000=xyz"])).is_err());
        }

        #[test]
        fn repeated_binary_operand_errors() {
            // Strict parsing: a second positional is a usage error, not a
            // silent last-wins override.
            assert_eq!(
                parse(&args(&["./a", "./b"])),
                Err("duplicate <binary> operand './b' (only one binary path may be given)".to_string())
            );
        }

        #[test]
        fn repeated_script_flag_errors() {
            assert_eq!(
                parse(&args(&["./bin", "--script", "a.lua", "--script", "b.lua"])),
                Err("duplicate --script value 'b.lua' (flag may only be given once)".to_string())
            );
        }

        #[test]
        fn repeated_argv_flag_errors() {
            assert_eq!(
                parse(&args(&["./bin", "--argv", "8", "--argv", "9"])),
                Err("duplicate --argv value '9' (flag may only be given once)".to_string())
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
            for flag in ["--script", "--symbolic", "--find", "--argv", "--steps"] {
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

        #[test]
        fn run_plan_explains_effective_configuration() {
            let cfg = config(
                "./sample",
                None,
                &["rdi", "rsi"],
                &[0x401000, 0x402000],
                Some(8),
                4096,
                true,
            );
            let plan = run_plan_output(&cfg);
            assert!(plan.contains("target         : ./sample"));
            assert!(plan.contains("dynamic-linking environment model"));
            assert!(plan.contains("step budget    : 4096"));
            assert!(plan.contains("state budget   : 16"));
            assert!(plan.contains("wall timeout   : 120 s"));
            assert!(plan.contains("branch timeout : 1000 ms"));
            assert!(plan.contains("symbolic regs  : rdi, rsi"));
            assert!(plan.contains("find targets   : 0x401000, 0x402000"));
            assert!(plan.contains("8 symbolic byte(s) in argv[0]"));
        }

        #[test]
        fn ai_analysis_threshold_is_inclusive() {
            assert!(!ai_analysis_eligible(true, 999, 1000));
            assert!(ai_analysis_eligible(true, 1000, 1000));
            assert!(!ai_analysis_eligible(false, 1000, 1000));
        }

        #[test]
        fn ai_fallback_tries_models_in_order_with_bounded_timeouts() {
            let models = vec!["first".to_string(), "second".to_string()];
            let mut attempted = Vec::new();
            let result = analyze_with_fallback("prompt", 5, &models, |model, prompt, timeout| {
                assert_eq!(prompt, "prompt");
                assert!(!timeout.is_zero());
                assert!(timeout <= Duration::from_secs(5));
                attempted.push(model.to_string());
                if model == "first" {
                    Err("unavailable")
                } else {
                    Ok("response")
                }
            });
            assert_eq!(attempted, models);
            assert_eq!(result.unwrap(), ("second".to_string(), "response"));
        }

        #[test]
        fn ai_failure_is_reported_as_advisory_output() {
            let models = vec!["offline-model".to_string()];
            let output = ai_analysis_output(true, 1000, 1000, "report", 1, &models, |_, _, _| {
                Err("offline".to_string())
            })
            .expect("threshold is met");
            assert!(output.contains("post-analysis skipped"));
        }

        #[test]
        fn driver_step_output_explains_instruction_transition() {
            let line = driver_step_output(
                7,
                &angryier_runtime::StepOutcome::Stepped {
                    pc: 0x140001000,
                    next_pc: 0x140001005,
                    length: 5,
                    form_id: 0x1234,
                },
            );
            assert!(line.contains("step 7"));
            assert!(line.contains("instruction executed"));
            assert!(line.contains("0x140001000"));
            assert!(line.contains("0x140001005"));
            assert!(line.contains("length=5"));
            assert!(line.contains("semantic_form=0x1234"));
        }
    }
}

#[cfg(feature = "run")]
fn run_subcommand(args: &[String]) -> i32 {
    match run_cmd::parse(args) {
        Ok(config) => run_cmd::execute(&config),
        Err(msg) => {
            eprintln!("error: {msg}");
            eprintln!();
            eprintln!("{}", run_cmd::usage());
            eprintln!(
                "hint: fix the argument named above; repeatable flags are --symbolic, --reg, --find, and --avoid, while <binary>, --script, --argv, --steps, --states, --timeout, --branch-timeout-ms, --solve, --fork, --dfs, --dynamic, and --driver may only be supplied once"
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
        assert!(status_output().contains("43 crates"));
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
    fn crates_output_contains_all_previously_omitted_crates() {
        let crates = crates_output();
        for name in ["angryier", "angryier-cfg", "angryier-runtime", "angryier-solver-fuzzy"] {
            assert!(crates.contains(name), "missing workspace crate {name}");
        }
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
        assert!(status_output().contains("43 crates"));
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
