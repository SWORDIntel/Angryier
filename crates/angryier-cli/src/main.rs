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
                    "error: 'run' requires the `run` feature\n\n\
                     Why: this build excludes the runtime/XED/Lua execution stack.\n\
                     Rebuild: cargo build -p angryier-cli --features run\n\
                     Or run directly: cargo run -p angryier-cli --features run -- run <binary>\n\
                     Hint: use 'angryier help' after rebuilding to inspect supported run flags."
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
        /// Instruction-step budget threaded into the synthesized driver.
        /// Defaults to the Lua API's own default so the two cannot drift.
        pub steps: u64,
        pub dynamic: bool,
        /// PE driver mode: load via `load_pe_driver`, attach kernel models,
        /// execute DriverEntry, and report pool/kernel events.
        pub driver: bool,
    }

    pub fn usage() -> String {
        "usage: angryier run <binary> [--script f.lua] [--symbolic REG] [--find ADDR] [--argv N] [--steps N] [--dynamic] [--driver]\n\
         note: --find ADDR is hexadecimal, 0x prefix optional\n\
         note: --driver loads PE32+ drivers with kernel models and reports pool events"
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
        let mut steps: Option<u64> = None;
        let mut dynamic = false;
        let mut driver = false;
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
            find,
            argv,
            // Default shared with the Lua API (`angry.run` opts.steps).
            steps: steps.unwrap_or(angryier_runtime::script::DEFAULT_STEPS),
            dynamic,
            driver,
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
        let mode = if config.driver {
            "PE32+ kernel-driver execution (direct Rust runtime + kernel models)"
        } else if config.dynamic {
            "symbolic/concolic execution with dynamic-linking environment model"
        } else {
            "symbolic/concolic execution with static image entry"
        };
        let symbolic = if config.symbolic.is_empty() {
            "none".to_string()
        } else {
            config.symbolic.join(", ")
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
        let argv = config
            .argv
            .map(|bytes| format!("{bytes} symbolic byte(s) in argv[0]"))
            .unwrap_or_else(|| "disabled".to_string());
        let note = if config.driver {
            "\n  note           : --driver bypasses Lua; --script/--symbolic/--find/--argv/--dynamic are not applied"
        } else if config.script.is_some() {
            "\n  note           : a custom Lua script owns execution; parsed symbolic/find/argv/dynamic flags are not injected automatically"
        } else {
            ""
        };

        format!(
            "[angryier][plan] execution configuration\n\
             \x20 target         : {}\n\
             \x20 frontend       : {}\n\
             \x20 mode           : {}\n\
             \x20 step budget    : {}\n\
             \x20 state budget   : {}\n\
             \x20 symbolic regs  : {}\n\
             \x20 find targets   : {}\n\
             \x20 symbolic argv  : {}{}",
            config.path,
            frontend,
            mode,
            config.steps,
            angryier_runtime::script::DEFAULT_MAX_STATES,
            symbolic,
            find,
            argv,
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
        let argv_opt = config.argv.map(|n| format!("argv = {n},")).unwrap_or_default();
        let dyn_opt = if config.dynamic { "dynamic = true," } else { "" };
        let escaped_path = config.path.replace('\\', "\\\\").replace('"', "\\\"");
        format!(
            r#"local r = angry.run("{path}", {{ symbolic = {{ {sym_table} }}, find = {{ {find_table} }}, {argv_opt} {dyn_opt} steps = {steps}, states = {states} }})

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
print(string.format("  failed states          : %d (states stopped by execution/model/semantic failure)", r.failed or 0))
print(string.format("  live states            : %d (states still explorable when this run stopped)", r.live_states or 0))
print(string.format("  find hits              : %d (configured target-address states reached)", r.found or 0))
print(string.format("  timed out              : %s", yn(r.timed_out)))
print(string.format("  concretization retries : %d (solver-assisted unresolved-address recovery attempts)", r.concretization_retries or 0))
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
    idea("Forking is active and live states remain. A larger step budget may expose deeper branches; if the state cap is the limiter, switch to a custom Lua run and raise states selectively rather than globally.")
end

if (r.live_states or 0) >= {states} then
    idea("Live-state count reached the default state budget. The next useful experiment is a custom Lua driver with a larger states value, plus tighter find/avoid policy so extra capacity goes to promising branches instead of blind breadth.")
end

if r.timed_out then
    idea("The run timed out. Increasing wall time alone is low-value: first narrow symbolic sources, add target/avoid guidance, use intermediate waypoints, or solve only states near the interesting branch.")
end

if (r.failed or 0) > 0 then
    idea("At least one state failed. Use last_error plus trace_hex to classify the first failure as semantic coverage, environment-model debt, memory modeling, or solver/concretization trouble before increasing exploration limits.")
end

if (r.concretization_retries or 0) > 0 then
    idea("Symbolic-address concretization was required. Treat repeated retries as a signal to improve pointer provenance: symbolize the data feeding the address expression more precisely, constrain its region, or model the allocator/object layout.")
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

print("[angryier][ideas] treat these as evidence-driven hypotheses, not automatic proof; validate interesting paths with solved inputs and concrete replay.")"#,
            path = escaped_path,
            steps = config.steps,
            states = angryier_runtime::script::DEFAULT_MAX_STATES,
            symbolic_count = config.symbolic.len(),
            argv_enabled = usize::from(config.argv.is_some()),
            find_count = config.find.len()
        )
    }

    pub fn execute(config: &RunConfig) -> i32 {
        println!("{}", run_plan_output(config));

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

            if steps > 12 && steps % 1000 == 0 {
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
                find: find.to_vec(),
                argv,
                steps,
                dynamic,
                driver: false,
            }
        }

        #[test]
        fn parses_minimal_invocation() {
            assert_eq!(
                parse(&args(&["./bin"])),
                Ok(config("./bin", None, &[], &[], None, 256, false))
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
                "failed states",
                "live states",
                "concretization retries",
                "trace blocks",
                "[angryier][ideas] next symbolic-analysis moves",
                "ABI-controlled inputs",
                "intermediate --find waypoint",
                "solve=true",
                "unsupported semantic fallback",
                "under-constrained memory",
                "vector operations",
                "retained trace as a seed",
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
            assert!(plan.contains("symbolic regs  : rdi, rsi"));
            assert!(plan.contains("find targets   : 0x401000, 0x402000"));
            assert!(plan.contains("8 symbolic byte(s) in argv[0]"));
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
                "hint: fix the argument named above; repeatable flags are --symbolic and --find, while <binary>, --script, --argv, --steps, --dynamic, and --driver may only be supplied once"
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
