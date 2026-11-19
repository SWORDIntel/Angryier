# Angryier CLI Reference

> Binary: `angryier` (crate `angryier-cli`). The default build includes the `run` subcommand (symbolic/concolic execution, optionally driven by an embedded Lua script, plus PE driver mode) with native decoding (Intel XED) and solver (Z3) dependencies. A dependency-free metadata-only build (`version`, `status`, `crates`, `help`) is available via `--no-default-features` and works anywhere Rust compiles.
>
> This reference also covers the separate sustained-campaign binary `angryier-campaign` (crate `angryier-campaign`): the typed Rust campaign API, the local sustained-campaign controls, and the distributed worker/coordinator roles. Source of truth: `crates/angryier-campaign/src/main.rs` and `crates/angryier-campaign/src/lib.rs`.
>
> Source of truth: `crates/angryier-cli/src/main.rs` (argument parsing) and `crates/angryier-runtime/src/script/mod.rs` (the Lua surface).

---

## Build and install

The workspace builds with stable Rust (`rust-toolchain.toml` pins the channel). Build matrix:

| Build | Command | Native requirements |
|---|---|---|
| Full (default) | `cargo build -p angryier-cli` | C toolchain (mlua compiles vendored Lua 5.4; `xed-sys` builds Intel XED from source) and the system `libz3` (linked by `z3-sys`, e.g. `apt install libz3-dev`). |
| Metadata-only | `cargo build -p angryier-cli --no-default-features` | None. Pure `std`, zero dependencies. |

The `run` feature (on by default) enables `angryier-runtime/xed` (native Intel XED decoding) and `angryier-runtime/script` (Lua + the native Z3 backend). In `--no-default-features` builds, `angryier run` prints a rebuild hint and exits 1.

To run from a checkout without installing:

```bash
cargo run -p angryier-cli -- status
cargo run -p angryier-cli -- run ./target-fixture --symbolic rdi
```

The binary name is `angryier`; `cargo install --path crates/angryier-cli` installs the full (run-capable) binary into `~/.cargo/bin`.

---

## Commands

```
Usage: angryier <command>

Commands:
  version    Print version information
  status     Print workspace status summary
  crates     List all crates with implementation status
  run        Execute a binary symbolically
  help       Print this help message
```

`angryier` with no arguments prints a one-line brief and exits 0. `-h` and `--help` are aliases for `help`. An unknown command prints an error to stderr and exits 1.

| Command | Output | Exit |
|---|---|---|
| `version` | `Angryier 0.1.0` | 0 |
| `status` | Workspace summary: 43 crates (41 implemented, 2 scaffolded), historical test totals | 0 |
| `crates` | One line per workspace crate: name, `Implemented`/`Scaffolded`, short description | 0 |
| `help`, `-h`, `--help` | The usage text above | 0 |
| *(none)* | One-line brief (version + tagline) | 0 |
| `run ...` | See below; requires the `run` feature | 0/1 |
| anything else | `error: unknown command '<cmd>'` on stderr | 1 |

The default `inspect` feature also lists `doctor`, `pe-address`, `pe-imports`, `dump-read`, and `capture-coverage`. `help` always lists `run`. In builds without the feature its line reads `Not in this build (rebuild with --features run)`; in feature builds it reads `Execute a binary symbolically`.

---

## `angryier run` — execute a binary symbolically

```
usage: angryier run <binary> [--script f.lua] [--symbolic REG] [--reg REG=VALUE] [--find ADDR] [--avoid ADDR] [--argv N] [--steps N] [--states N] [--timeout SECS] [--branch-timeout-ms N] [--solve] [--fork] [--dfs] [--dynamic] [--driver] [--no-ai-analysis] [--ai-min-steps N] [--ai-timeout-secs SECS] [--ai-model MODEL]... [--arch ARCH]
note: --reg is repeatable; VALUE accepts decimal or 0x-prefixed hexadecimal
note: --find/--avoid ADDR are repeatable hexadecimal addresses, 0x prefix optional
note: --fork enables fork-aggressive symbolic exploration; --dfs prioritizes the newest/deepest state
```

Loads an ELF64 or PE32+ image into the engine and runs it concretely/symbolically. The loader is chosen by magic bytes: ELF loads statically by default (`load_elf`), with `--dynamic` the dynamic-linking environment model is used (`load_elf_dynamic`), and an `MZ` image loads in **driver mode** (`load_pe_driver`: sections mapped, IAT resolved to import stubs, DriverEntry entry state — `dynamic` is ignored for PE).

### ARM64 backend: runtime support, no CLI image loader

The CLI has no ARM64 image loader. In legacy (non-`--driver`) mode, `--arch arm64` is rejected before the embedded Lua runtime starts; that path supports x86-64 images only. In PE driver mode, `angryier run <image> --driver --arch arm64` selects the safe-Rust A64 decoder and constructs `Runtime::new_arm64`, then exits 1 because driver mode cannot load an A64 image. Static handoff mode retains its own architecture-specific error because ARM64 has no Windows kernel-layout metadata. `--arch arm64` is not a general ELF loader switch, and the distributed campaign binary does not supply an ARM64 execution path.

The Rust backend executes a subset of A64, not the whole ISA. Its integer semantics cover arithmetic and logical operations, NZCV flags, branches, addressing and loads/stores. The runtime tests use hand-assembled fixtures: `arm64_concrete` checks a counted loop and stack round-trip; `arm64_shifts` checks W/X variable shifts and rotates; `arm64_fp` and `arm64_simd` cover selected scalar FP arithmetic, conversions, conditional selection, vector arithmetic and lane duplication. `arm64_symbolic` checks that flag-dependent branches fork with distinct constraints; with `z3` it also checks solved path models. These tests do not establish application or OS compatibility.

From the checkout, run the fixtures with:

```sh
cargo test -p angryier-runtime --features z3 --test arm64_concrete --test arm64_shifts --test arm64_fp --test arm64_simd --test arm64_symbolic
```

For persistent x86-64 campaigns, use the sustained-campaign binary [`angryier-campaign`](#sustained-campaigns-angryier-campaign) or the [local Lua API](LUA_API.md#9-durable-sustained-exploration-opt-in-xed--script), not an `angryier run` subcommand. The [local campaign guide](guides/local-campaigns.md) covers the local sustained controls; the [distributed guide](guides/distributed-campaigns.md) covers the worker/coordinator roles.

### Flags

| Flag | Repeatable | Meaning |
|---|---|---|
| `<binary>` (positional) | — | Path to the ELF64 or PE32+ image to execute. Required, even when `--script` is given (the script chooses whether to reference it). A second positional operand exits 1 with an error. |
| `--script f.lua` | no | Lua driver script (see the Lua API below). When set, the script has full control; the other flags are still validated but their values are unused. |
| `--symbolic REG` | yes | Mark a general-purpose register symbolic before execution. `REG` is one of `rax rcx rdx rbx rsp rbp rsi rdi r8`–`r15`; other names exit 1 with an error. Always marked 64 bits wide. |
| `--reg REG=VALUE` | yes | Seed a concrete GPR. `VALUE` accepts decimal or `0x`-prefixed hexadecimal, including the full `u64` range. Useful for replaying alternate-branch models. |
| `--find ADDR` | yes | Add a target address (hexadecimal, `0x` prefix optional) to the exploration policy's find set. |
| `--avoid ADDR` | yes | Add an address to the exploration policy's avoid set; a state reaching it is pruned before further stepping. |
| `--argv N` | no | Symbolize `argv[0]` as `N` bytes (the model materializes `N` bytes, NUL-terminated, on the initial stack). |
| `--steps N` | no | Total symbolic instruction-step budget. Default `256` (`DEFAULT_STEPS`). |
| `--states N` | no | Maximum simultaneous live states. Must be > 0. Default `16` (`DEFAULT_MAX_STATES`). |
| `--timeout SECS` | no | Whole-run symbolic exploration wall budget. Must be > 0. Default `120` seconds (`DEFAULT_TIMEOUT_SECS`). |
| `--branch-timeout-ms N` | no | Post-run alternate-branch solver budget, 1–10000 ms. Default `1000` (`DEFAULT_BRANCH_TIMEOUT_MS`). |
| `--solve` | no | Extract concrete models for states that hit a `--find` target. Solver feasibility-gating during exploration remains enabled without this flag. |
| `--fork` | no | Fork-aggressive symbolic exploration: do not let concretization pins collapse a symbolic branch to one direction when both solver-checked directions are feasible. |
| `--dfs` | no | Select the newest/deepest live state first instead of the default scheduler, favoring deep target dives over breadth. |
| `--dynamic` | no | Load via the dynamic-linking path (`__libc_start_main` hook, `main(argc, argv)` entry) instead of static `_start`. |
| `--no-ai-analysis` | no | Disable HAX-backed post-analysis. Enabled by default for the generated CLI driver, subject to the minimum-work threshold. |
| `--driver` | no | Force direct PE32+ kernel-driver execution through the Rust runtime. Lua is bypassed; `--reg` seeds and `--steps` apply directly. Symbolic-search flags are parsed but not applied. |
| `--ai-min-steps N` | no | Minimum executed work units before the generated driver requests HAX post-analysis. Must be > 0; default `1000`. |
| `--ai-timeout-secs SECS` | no | Total timeout budget for trying the configured HAX models, in seconds. Range `1..=3600`; default `300`. |
| `--ai-model MODEL` | yes | Restrict/override the HAX model candidates and try them in the supplied order. Each value must be in the built-in allowlist listed below. |

`--symbolic`, `--reg`, `--find`, and `--avoid` are repeatable. Other option flags are single-use; duplicates fail explicitly instead of silently taking the last value.

Address parsing for `--find` and `--avoid` is hexadecimal with an optional `0x` prefix: `--find 0x40102a` and `--find 40102a` are equivalent, and `--find 1234` means address `0x1234`.

### The default driver

Without `--script`, the CLI synthesizes this Lua driver and evaluates it:

```lua
local r = angry.run("<binary>", {
    symbolic = { <regs marked 64-bit> },
    regs = { <optional concrete seeds> },
    find = { <find addresses> },
    avoid = { <avoid addresses> },
    [argv = N,] [dynamic = true,]
    [solve = true,] [exploration = "fork",] [search = "dfs",]
    steps = <steps>,
    states = <states>,
    timeout_secs = <timeout>,
    branch_analysis = true,
    branch_timeout_ms = <branch timeout>,
})
-- The generated driver then prints result, evidence-quality, frontier,
-- branch/CFG analysis, replay seeds, and evidence-driven next actions.
```

`steps`, `states`, and timeout values come directly from the CLI flags and share the runtime's default constants. Z3 feasibility-gating remains enabled during normal exploration even without `--solve`; `--solve` controls the additional post-run extraction of concrete models for found states. Alternate-branch analysis is enabled by the generated driver by default.

When a run reaches the configured minimum of **1,000 executed work units** (default), the generated driver submits a bounded metrics/frontier/trace-tail report to HAX for optional advisory analysis. Set `--ai-min-steps N` to change the positive-integer threshold. The total timeout for the model fallback sequence defaults to **300 seconds**; set `--ai-timeout-secs SECS` to a value from `1` through `3600`. Repeat `--ai-model MODEL` to select allowlisted candidates in the supplied order; without overrides, the allowlist and preference order are `orca/orcacyber-glm-5.3-flash-free`, `deepseek/deepseek-v4.1-flash-free`, `deepseek/deepseek-v4-flash-free`, `z-ai/glm-5.3-flash-free`, and `tencent/hy3-free`. The integration invokes `hax --raw --no-session` and uses credentials already saved for HAX, without requiring an interactive session. The bounded report contains selected run metrics/frontier data and a trace tail; it does not include the binary, arbitrary file contents, command-line arguments, credentials, or solved input models. The result is advisory only: it does not alter execution or solver results, and is not a proof or reachability verdict. `--no-ai-analysis` disables the request. With `--json`, only the AI output is routed to stderr; ordinary execution output may remain on stdout, so stdout is not guaranteed to contain only JSON. Custom Lua scripts can explicitly call the registered `angryier_ai_summary(steps, report)` function to request the same analysis; without that call, no automatic post-analysis is run.


### Operator-facing diagnostics

Before execution starts, the CLI now prints a structured **execution plan** containing the target, frontend, effective mode, step/state/wall/branch budgets, search mode, target-model extraction setting, symbolic/concrete registers, find/avoid targets, and symbolic argv settings. If a custom Lua script or `--driver` makes other CLI flags ineffective, that is stated explicitly rather than silently ignored.

PE driver mode additionally reports:

- image size, entry PC, import/hook counts, and a bounded import preview;
- the first 12 ordinary instruction transitions with PC, next PC, decoded length, and semantic form id;
- all high-signal modeled events after that point (SimProcedure dispatches, syscalls, traps, termination);
- progress every 1000 steps for long runs;
- the exact stop reason, final PC, termination status, SimProcedure count, pool allocation/free counts, and double-free verdict.

Routine per-instruction lines are intentionally suppressed after the first 12 driver steps so verbose diagnostics do not turn a long analysis into an I/O-bound workload.

### Evidence-driven next-step ideas

The generated driver now ends with an `[angryier][ideas]` section. These are conditional hypotheses derived from the run report rather than static tips.

Examples include:

- **No symbolic source:** suggest ABI-controlled argument registers (`rdi/rsi/rdx/rcx/r8/r9`) or symbolic argv instead of symbolizing the whole machine.
- **Symbolic source but zero forks:** flag likely overwrite/concretization, insufficient depth, or a source that never reaches a conditional.
- **No `--find` target:** suggest adding an accept/success block, vulnerable call site, allocator/free site, error bypass, or other semantically useful waypoint.
- **Target not reached:** recommend an intermediate waypoint near the last stable trace region instead of blindly multiplying the step budget.
- **Target reached:** recommend `--solve` to extract a concrete witness, followed by concrete replay.
- **Live-state saturation:** recommend selectively increasing `--states` and tightening find/avoid policy.
- **Timeout:** recommend reducing symbolic breadth, adding intermediate targets, or solver-gating only near interesting branches before increasing wall time.
- **Failed states:** direct the operator to `last_error` plus `trace_hex` to classify semantic, model, memory, or solver debt.
- **Concretization retries:** suggest tightening pointer provenance, symbolic source placement, region constraints, or object/allocator models.
- **Unsupported-form debt:** prioritize `unsupported_sites` by reachability/frequency because additional raw steps cannot recover semantic fidelity.
- **Under-constrained memory:** inspect `unmapped_sites` and replace fabricated memory with real mappings, symbolic buffers, modeled API results, or region constraints.
- **Read-only write relaxation:** inspect `ro_write_reverts` and classify loader-protection drift, self-modification, model error, or invalid paths.
- **Vector debt:** warn that SAT/reachability conclusions depending on under-constrained vector values need stronger semantics first.
- **Heavy forking with no merges:** suggest convergence-aware exploration, loop summaries, or function summaries.
- **Useful retained trace:** use the last stable block before divergence as the next breakpoint/find waypoint.

The CLI explicitly labels these as **hypotheses, not proof**. Interesting paths should be validated with solved inputs and concrete replay.

### Alternate-branch inversion

The generated CLI driver enables post-run branch analysis. Each symbolic state records its latest conditional decision as execution evidence: branch PC, canonical Boolean condition, taken/not-taken successors, selected edge, and the number of constraints that existed **before** that branch.

To test the opposite edge, Angryier asserts only that shared pre-branch prefix plus the opposite predicate. It intentionally excludes the chosen-edge constraint and every constraint accumulated after divergence. This prevents the common mistake of asking the solver to satisfy both sides of the same branch.

When the alternate edge is SAT, the CLI prints candidate model assignments and, for whole-register values, replay-ready `--reg REG=0x...` flags. For a concrete replay, omit the matching `--symbolic REG`; for a seeded symbolic rerun, keep it. SAT means the alternate edge is feasible under Angryier's current model and prefix—not that the remainder of that path reaches the analyst's target.

Branch analysis also performs a **bounded static CFG recovery** rooted at the recorded decision when one or more find targets exist. It reports the graph-edge distance from each successor to each statically reachable find target and whether the chosen or alternate successor is structurally closer. An alternate edge is promoted to a target-directed recommendation only when solver feasibility and CFG directionality agree. Indirect/unresolved control-flow remains a graph exit, so CFG ranking is guidance rather than proof.

### Search controls from the CLI

The normal CLI now exposes the exploration controls that previously required a custom Lua driver. This matters because Angryier's own diagnostics can recommend a directly executable next command:

- state pressure → raise `--states`;
- unfinished live frontier → raise `--steps`;
- wall timeout → adjust `--timeout` after first narrowing the symbolic frontier;
- solver UNKNOWN on a useful alternate edge → raise `--branch-timeout-ms`;
- concolic folding suppressing useful path diversity → add `--fork`;
- breadth explosion while a target lies deeper on one path → add `--dfs`;
- target reached and a concrete witness is needed → add `--solve`.

These switches are injected only by the generated driver. When `--script` is supplied, the script owns its own `angry.run` options.


The generated driver also prints an `[angryier][analysis]` section before the recommendation list. It includes the retained path tail, the last retained frontier block, a fidelity/evidence-quality classification, and a single primary limiter chosen from timeout, state pruning, state failure, unsupported semantics, under-constrained memory/address handling, vector semantic debt, step-budget exhaustion, absent symbolic influence, or unresolved target reachability.

The analysis layer deliberately does **not** call the last trace block “closest to target” unless CFG evidence exists. A final trace PC is only the last retained frontier observation; numeric address proximity is not meaningful reachability evidence.

The `[angryier][analysis] symbolic frontier` subsection reports which symbolic sources are present in the selected path's accumulated constraints. This is narrower than “all symbols created during execution”: a register source that does not appear in the retained constraint dependency union has not contributed to a retained path predicate on that diagnostic state. The CLI therefore recommends preserving path-relevant sources first and concretizing unrelated inputs unless trace/taint evidence justifies keeping them symbolic.

The subsection prints both the complete current symbolic-register set and the path-relevant register subset. Registers present in the first set but absent from the second are labeled **non-predicate symbolic** and treated as concretization candidates, not automatically discarded inputs: they may still matter to later code, memory addressing, or data-only effects that have not yet entered a branch predicate.

When region forking is active, the CLI reports the number of guessed child worlds and tells the operator to inspect `region_fork_sites` before trusting a reachable path. When state pruning occurs, it prints the peak frontier against the configured cap so the next decision can distinguish “raise capacity” from “improve search policy.”

Branch analysis now emits a **steering verdict** in addition to raw solver/CFG facts. The ranking policy is intentionally conservative:

- an exact configured target on the chosen edge → `keep-chosen/high`;
- alternate edge UNSAT under the exact shared prefix → `reject-alternate/high`;
- alternate edge SAT and its immediate successor is a configured target → `prioritize-alternate/high`;
- alternate edge SAT plus bounded-CFG preference → `prioritize-alternate/medium` or `keep-chosen/medium`;
- equal bounded-CFG distance → `explore-both/medium`;
- SAT without target-direction evidence → `explore-alternate/low`;
- timeout/unknown/resource-limit/backend failure/solver-off → `unresolved/low`.

CFG evidence never overrides solver infeasibility or uncertainty. This makes `branch_analysis.steering_action` suitable for external agents without requiring them to reproduce Angryier's safety/fidelity policy.

### Concrete alternate-branch replay

For a SAT alternate model whose leaves all map to 64-bit architectural register inputs, Angryier performs a concrete replay from the captured entry state. It resets mutable execution cursors (register/memory state, syscall capture, `brk`, `mmap`, fd state, symbolic-fd state, stdin cursor, PCI config selector, counters), applies the solver's register assignments, runs under the existing `steps` budget, and checks the exact recorded branch successor.

A `validated` replay means **the immediate branch flip was reproduced concretely in Angryier's modeled environment**. It does not prove that a later `find` target is reachable. Bounded CFG evidence remains structural guidance only.

Replay is deliberately refused when:

- the solver model contains memory/argv/file/free-symbol leaves that cannot yet be materialized as GPR seeds (`unsupported-model`);
- kernel pool state is attached and externally shared (`stateful-kernel-model`);
- a stateful SimProcedure has already executed on the diagnostic path (`stateful-environment`).

A `mismatch` is treated as a fidelity warning: SAT symbolic evidence exists, but concrete replay contradicted the predicted immediate successor. Steering is downgraded to `unresolved/low` until that divergence is explained.

### Bounded branch-history ranking

Branch analysis retains at most **64** symbolic decisions per state. Fork siblings inherit the same pre-branch history and append their own chosen edge. State merges clear branch history because merge rewriting invalidates the original per-decision constraint-prefix indices; Angryier fails closed rather than solving stale provenance.

The post-run target-directed analysis is deliberately bounded:

1. Recover **one** CFG window rooted at the earliest retained decision and reuse it for every retained branch.
2. Score older decisions only when their alternate successor has a structurally better bounded-CFG path to a configured `find` target.
3. Prefer an alternate that reaches a target when the chosen edge cannot; otherwise prefer larger edge-distance improvement, then shorter alternate distance.
4. Analyze the newest symbolic decision normally.
5. Issue **at most one additional solver query and one replay** for the highest-ranked older decision.

The older result is exposed as `branch_analysis.history_candidate_analysis`. It contains the history index, branch PC, ranked target, chosen/alternate CFG distances, solver status, model, replay result, and the same steering action/confidence/reason contract used by the newest branch.

For branch-edge naming, `taken_target`, `not_taken_target`, and `chosen = taken/not_taken` remain for backward compatibility. New integrations should prefer `condition_true_target`, `condition_false_target`, `chosen_condition`, `chosen_target`, and `alternate_target`. This keeps diagnostics correct even when an instruction family represents its source-level branch sense through an inverted predicate.

This cap is intentional: diagnostic output should improve the next experiment without turning every run into an unbounded retrospective SMT sweep.

Shared CFG recovery is an optimization, not a semantic dependency. If recovery from the earliest retained branch fails, Angryier disables older-branch CFG ranking for that run but performs one bounded recovery from the newest branch PC so the detailed newest-branch analysis keeps the behavior it had before branch-history ranking was added. The result exposes the source through `cfg_source`.

The branch-analysis solver **fails closed on incomplete constraint metadata**. Every pre-branch path constraint must have an arena dependency summary; a missing summary aborts the query with the failing constraint index/expression ID. The same guarantee applies to feasibility checks and found-state model extraction. This prevents reporting SAT from a weakened path prefix. A successful symbolic SAT result is still not equivalent to concrete validation; consult `branch_analysis.replay` and the fidelity-debt fields.

Concrete branch replay is **dynamic-visit aware**. A static PC is not a unique branch identity inside loops: replay therefore validates the recorded 1-based occurrence of that PC, not the first matching successor it sees. If the 4096-entry trace ring has already truncated the path from entry, the visit number is no longer provably absolute and replay returns `ambiguous-branch-visit` instead of risking a false validation.

Solver-assisted symbolic-address concretization follows the same rule: retained path constraints and generated region-bound predicates must be canonically keyed. Missing metadata aborts concretization rather than silently dropping a constraint.

Concrete branch replay uses **three-part dynamic identity**: branch PC, 1-based visit index, and an exact entry-to-branch trace fingerprint. Reaching the same static branch—or even the same numbered visit—through a different concrete route returns `path-context-mismatch` rather than a false validation. If the bounded symbolic trace has already rolled over, Angryier returns `ambiguous-branch-visit` and refuses to guess. Solver models are also normalized by architectural register; duplicate equal assignments are deduplicated, while conflicting values for the same register return `ambiguous-model` instead of relying on backend/model iteration order. Entry-time `symbolic_memory` and `argv` byte symbols carry expression→address provenance and are concretized into the reset entry snapshot before replay; runtime-generated stdin/file/free symbols remain unsupported rather than being silently dropped.

### Exit codes

| Code | Cause |
|---|---|
| 0 | Driver/script evaluated successfully. |
| 1 | Invalid/duplicate CLI arguments (including malformed `--reg`, find/avoid addresses, state/time budgets, or repeated single-use switches); unreadable script/binary; Lua/runtime/loader/model initialization error; or a build without the `run` feature. |

Argument errors are prefixed `error:` and followed by usage plus a corrective hint. Runtime diagnostics use structured prefixes such as `[angryier][plan]`, `[angryier][load]`, `[angryier][exec]`, `[angryier][trace]`, `[angryier][progress]`, `[angryier][result]`, `[angryier][verdict]`, and `[angryier][hint]` so logs remain readable and grep-friendly.

---

## Sustained campaigns: `angryier-campaign`

`angryier-campaign` (crate `angryier-campaign`) is a separate x86_64 Linux binary for durable, replay-verified sustained exploration of a pinned image. One compiled executable exposes two independent surfaces: the **local** sustained controls (one process, one durable frontier ledger, no network) and the distributed **worker/coordinator** roles (authenticated loopback TCP; 1, 2, or 4 workers). The same machinery is available as a typed Rust library API — `Config::defaults`, `serve`, `coordinate`, `coordinate_with_evidence`, `CampaignOutcome` (see [`examples/rust_api.rs`](../crates/angryier-campaign/examples/rust_api.rs)).

The [local campaign operator guide](guides/local-campaigns.md) is the operational reference for the local controls (`local-start`, `local-resume`, `local-status`, `local-advance`, `local-retry`, `local-run`) and the [typed Rust example](../crates/angryier-campaign/examples/local_campaign.rs); the [distributed campaign guide](guides/distributed-campaigns.md) covers the roles, keys, tunnels, WAL backup/restore, and resume semantics. This section records only what the committed parser enforces; exact local subcommand/flag spellings are pinned by `crates/angryier-campaign/src/main.rs`.

### Shared campaign options

Campaign options are accepted as indicated below; local controls reject distributed-only image-mode and entry overrides. Supported values are sealed into the campaign manifest:

| Flag | Repeatable | Meaning |
|---|---|---|
| `--binary PATH` | no | Target image to pin. Required. Its digest is sealed into the manifest; the actual bytes are re-checked before work. |
| `--build-id TOKEN` | no | Required operator label, 1–128 bytes of `[A-Za-z0-9._-]`. Labeling only — it does **not** replace byte identity. |
| `--image-mode MODE` | no | Distributed-only: `elf` (default) or `pe-driver`. Local controls reject this flag and use static ELF. `pe-driver` is a loader model, not Windows execution or Windows-fidelity evidence. |
| `--entry PC` | no | Distributed-only absolute mapped entry PC (decimal or `0x` hexadecimal). Default: the image header entry; local controls reject overrides. |
| `--symbolic-reg REG` | no | Legacy root selector: `rbx` (default) or `rcx`. Accepted by local and distributed roles; local controls cannot combine it with `--symbolic`. |
| `--max-steps N` | no | Exploration limits sealed into the manifest; all ten are required to be positive, zero is never an implicit ceiling. Defaults: 128, 64, 2, 64, 64, 10000 ms, 30000 ms, mode-default RAM (64 MiB ELF / 576 MiB `pe-driver`), 1 MiB disk, 1 MiB trace, in the order below. |
| `--max-path-steps N` / `--max-active-states N` / `--max-path-depth N` / `--max-loop-visits N` / `--max-solver-ms N` / `--max-wall-ms N` / `--max-ram-bytes N` / `--max-disk-bytes N` / `--max-trace-bytes N` | no | See defaults above; changing any limit changes the campaign digest, so a changed limit is a new campaign with a new ledger. |

Local root inputs: repeat `--symbolic REG` for one or more 64-bit symbolic GPRs and `--reg NAME=VALUE` for distinct concrete GPR seeds (decimal or `0x` hexadecimal u64). Both flags are **local-only**; the canonical lowercase names are `rax rcx rdx rbx rsp rbp rsi rdi r8`–`r15`. Duplicate marks or seeds, symbolic/seed overlap, and mixing `--symbolic` with `--symbolic-reg` are rejected. Without `--symbolic`, the root keeps the default single `rbx` (or the legacy `--symbolic-reg rcx`) and `--reg` must not seed that register. All root inputs are sealed into the ledger's identity and must match on resume; old Lua v1/v2 ledgers cannot be reopened by this Rust API/CLI without migration. The Lua compatibility API remains exported.

Static-image limit: local campaigns execute a **static ELF64 x86-64 executable at its image entry** under the `prove` fidelity profile with the native `z3-default` solver policy only. Unsupported options (entry override, mutable files/streams, hooks, under-constrained memory, fallthrough, dynamic loading, patches) fail closed rather than escaping the replay pin.

### Local controls (single process, no network)

The local controls run one process against one durable frontier ledger on this host: no loopback listener, no peers, no key files, no HMAC framing. For example, `angryier-campaign local-start --binary ./branch.elf --ledger ./branch.ledger --build-id local-v1 --symbolic rdi --symbolic rsi --reg rax=0x2a --policy rank-targets --find 0x401020` pins two symbolic inputs and one concrete seed; repeat those options unchanged for `local-resume`, `local-status`, `local-advance`, and `local-retry`. `local-start` creates the ledger from a complete explicit spec (fails on an existing ledger); `local-resume` reopens an existing ledger and validates the presented manifest and artifacts against the sealed campaign digest; `local-advance` reserves queued work, replays the pinned root, and commits one bounded transition; `local-status` reads counters without advancing; `local-retry` explicitly requeues `Deferred`/`Unknown`/`Failed` records (never automatic, never silent completion). Evidence is accepted only after concrete witness replay where a witness exists, and every report carries `complete_within_declared_bounds`. `local-run` starts if the ledger is absent, otherwise resumes it; with those same sealed options, run `angryier-campaign local-run --binary ./branch.elf --ledger ./branch.ledger --build-id local-v1 --symbolic rdi --symbolic rsi --reg rax=0x2a --policy rank-targets --find 0x401020 --max-wall-ms 30000 --batch-ms 5000 --run-ms 15000` (repeat unchanged to continue). The unsealed, positive `--batch-ms` defaults to 5000 ms, capped to the sealed wall limit; `--run-ms` defaults to that limit, and both must be at most `--max-wall-ms`. `--run-ms` bounds one process invocation, not an OS-wide cumulative budget; `--max-wall-ms` and all other sealed limits remain pinned. A report and newly accepted event IDs print **after each batch**, not as per-event streaming within it. `local-run` exits 0 for complete within declared bounds, 2 for partial, and 1 for hard errors. `local-status` takes the same single-writer lock and cannot observe a concurrent `local-run`. Run the independent typed Rust script with `cargo run -p angryier-campaign --example local_campaign -- --binary ./branch.elf --ledger ./example.ledger --build-id local-v1 --policy fork-all`; it pins its **own executable SHA-256**, so neither the CLI nor a recompiled example can reopen its ledger. Old Lua scripts and their archived ledgers remain available via the Lua compatibility interface, not the Rust CLI/API. See the [local campaign guide](guides/local-campaigns.md) for full pinned limits, walkthrough, backup/restore pairing, and capacity ceilings; bounded work does not prove exhaustive routes.

### Distributed worker/coordinator roles

```
usage: angryier-campaign worker --binary PATH --build-id TOKEN --key-file KEY
                                --listen ADDR [options]
usage: angryier-campaign coordinator --binary PATH --build-id TOKEN --ledger PATH
                                     [(--peer ID@ADDR@KEY)... | --connect ADDR] [options]
```

| Flag | Role | Meaning |
|---|---|---|
| `--listen ADDR` | worker | Loopback address to serve. Required for workers; only a coordinator may instead take the address from its first `--peer` entry. |
| `--connect ADDR` | coordinator | Legacy single-worker connection form. Cannot be mixed with the `--peer` pool. |
| `--peer ID@ADDR@KEY` | coordinator | Repeatable pool form; exactly 1, 2, or 4 entries. IDs, addresses, and key files must be distinct; worker `--worker-id` must exactly match its peer ID. Cannot be mixed with `--connect`/`--key-file`/`--worker-id`. |
| `--key-file KEY` | worker / legacy coordinator | Pairwise 32-byte raw key file (mode `0600`); a different key per coordinator/worker pair. |
| `--worker-id ID` | worker / legacy coordinator | Worker identity token; pool workers require it, legacy single-worker mode defaults to `worker`. |
| `--connections N` | worker | Finite cap on accepted worker sessions; `0` serves until stopped. There is no hidden reconnect/retry. |
| `--ledger PATH` | coordinator | Required durable campaign ledger (single writer; checkpoint + WAL sidecar). |
| `--progress-jsonl PATH` | coordinator | Live accepted-event projection; defaults to `<ledger>.progress.jsonl`. Not a second ledger. |

Validation is strict: a worker rejects `--peer`; the pool form rejects `--connect`/`--key-file`/`--worker-id`; an unknown option is an error; a coordinator exits nonzero (`campaign partial`) when unresolved owned work remains and `complete_within_declared_bounds` is false.

Campaign identity and evidence: the manifest seals the executable SHA-256 (the running executable is hashed, so worker and coordinator must run the same compiled bytes), the image digest, architecture, resolved entry, the `campaign-root-v2/...` policy marker, solver policy, and all ten limits. A worker result is only a claim: the coordinator independently replays each fenced subtree from a fresh local root before admission, and witness-bearing terminals are concretely replayed before their evidence is committed. `CampaignOutcome` exposes the committed report plus the latest accepted disposition per path identity — superseded attempts and transient worker claims are not evidence.

---

## Lua API (`angry` library)

Every driver script — the synthesized one or a `--script` file — runs in a fresh Lua 5.4 VM with a global `angry` table.

### `angry.run(path, opts) -> table`

Loads `path`, applies the symbolic-input configuration, explores, and returns a report table. The default whole-run wall budget is 120 seconds and is configurable with `timeout_secs` / CLI `--timeout`.

Options table (all fields optional):

| Field | Type | Default | Meaning |
|---|---|---|---|
| `symbolic` | table | `{}` | Registers to mark symbolic. Either `{ rdi = 64 }` or `{ "rdi" }`. The width value is validated: 64 (or omitted) is accepted, any other integer aborts the script with `symbolic register '<name>' width must be 64 bits (got N)` — narrower/wider GPR symbols would read as width-mismatched expressions. Unknown register names error (`bad reg <name>`) instead of being skipped. Valid names: the 16 GPRs listed above. |
| `find` | array of integer | `{}` | Target PCs; reaching one records a found state. |
| `avoid` | array of integer | `{}` | Avoid PCs for the exploration policy. |
| `regs` | table | `{}` | Concrete GPR seeds; full-width kernel pointers use the documented `<reg>_hex = "0x..."` form. |
| `steps` | integer | `256` | Instruction-step budget (`DEFAULT_STEPS`). |
| `states` | integer | `16` | Maximum live states (`DEFAULT_MAX_STATES`). |
| `timeout_secs` | integer | `120` | Whole-run wall-clock budget (`DEFAULT_TIMEOUT_SECS`). |
| `exploration` | string | default | `"fork"` enables fork-aggressive symbolic branch handling. |
| `search` | string | default | `"dfs"` selects the newest/deepest live state first. |
| `solve` | boolean | `false` | Extract concrete models for found states. Z3 still feasibility-checks symbolic branches when this is false. |
| `branch_analysis` | boolean | `false` | Solve the edge opposite the selected frontier state's most recent symbolic branch using only the constraints shared before that branch. The generated CLI driver enables this automatically. |
| `branch_timeout_ms` | integer | `1000` | Per-query budget for alternate-branch analysis, clamped to 1–10000 ms. |
| `dynamic` | boolean | `false` | Dynamic-linking load path instead of static (ELF only; PE images always load in driver mode). |
| `argv` | integer | — | Symbolize `argv[0]` as this many bytes. |
| `files` | table name → `true` | — | Paths whose opens are backed by symbolic bytes (reads yield symbols instead of hitting the host). |
| `contents` | table name → string | — | Concrete file contents to inject into the environment model. |

Result table:

| Field | Meaning |
|---|---|
| `steps`, `forks`, `merges`, `terminated`, `failed` | Core run counters. |
| `pruned_states` | States discarded by avoid policy or state-cap economics. |
| `live_states` | States still live when the budget/limits ended the run. |
| `dead_states` | Terminated/failed/pruned states retained by the session for inspection. |
| `peak_states` | Maximum simultaneous live-state frontier observed during the run. |
| `concretization_retries` | Solver-assisted unresolved-address recovery attempts. |
| `region_fork_children` | Guessed address-world child states created when unresolved pointers are forked across mapped RW regions. Non-zero is fidelity debt, not free coverage. |
| `region_fork_sites` | Capped ledger of region-fork sites with PC, expression id, pinned address, region base and size. |
| `frontier` | Diagnostic state selected from first found state, else first live state, else most recent dead state. Contains state id, PC/PC hex, path-constraint count, bound-symbol count, current symbolic-register set, and `constraint_dependencies`. |
| `frontier.constraint_dependencies` | Union of symbolic leaf IDs that actually occur in the selected state's retained path constraints. Register-backed leaves include register id/name, width and expression id; unbound leaves stay explicitly labeled and may represent symbolic memory or fallback/free symbols. |
| `branch_analysis` | Present when `branch_analysis = true`. Describes the selected state's most recent symbolic branch: exact branch PC, taken/not-taken successors, chosen edge, predicate expression, shared pre-branch constraint count, dependency sources, alternate target, solver outcome/time, and candidate model. |
| `branch_analysis.cfg_status` | Status of bounded static CFG recovery for target ranking (`ok`, `no-find-targets`, or `unavailable`). |
| `branch_analysis.cfg_targets` | Per-find-target taken/not-taken/chosen/alternate static edge distances and structural preference. Missing distance means not statically reachable inside the recovery window. |
| `branch_analysis.cfg_preference` | `chosen`, `alternate`, or `none` for the best bounded static target relation. Kept separate from solver SAT/UNSAT. |
| `branch_analysis.steering_action` | Stable machine-readable recommendation: `prioritize-alternate`, `keep-chosen`, `reject-alternate`, `explore-both`, `explore-alternate`, or `unresolved`. |
| `branch_analysis.steering_confidence` | `high`, `medium`, or `low`. High requires direct target/UNSAT evidence; bounded-CFG directionality is deliberately capped at medium. |
| `branch_analysis.steering_reason` | Stable human-readable rationale for the steering action. The policy requires solver feasibility before CFG evidence can prioritize an alternate edge. |
| `branch_analysis.replay` | Concrete validation result for SAT alternate models when model leaves can be materialized exactly as 64-bit GPR inputs or tracked entry-snapshot symbolic memory/argv bytes and the environment is rewind-safe. |
| `branch_analysis.error` | Diagnostic error when exact alternate-edge solver setup fails (including unavailable path-constraint metadata). The solver is not called with a reduced path; the steering action remains unresolved. |
| `branch_analysis.replay.status` | `validated`, `mismatch`, `path-context-mismatch`, `ambiguous-model`, `budget-exhausted`, `terminated-before-branch`, `ambiguous-branch-visit`, `unsupported-model`, `stateful-kernel-model`, `stateful-environment`, `not-sat`, or `error`. |
| `branch_analysis.visit_index` | 1-based dynamic visit number of the selected branch PC within the retained symbolic trace. |
| `branch_analysis.visit_index_exact` | True only when the retained trace still covers execution from entry; false makes concrete replay fail closed rather than guess which repeated branch visit was intended. |
| `branch_analysis.replay.expected_visit` | Dynamic branch occurrence the symbolic decision requires replay to validate. |
| `branch_analysis.replay.observed_visits` | Number of concrete visits to that PC seen before replay validated, terminated, or exhausted its budget. |
| `branch_analysis.replay.applied_registers` | Number of unique architectural register assignments concretized from the solver model. |
| `branch_analysis.replay.applied_memory_bytes` | Number of tracked entry-snapshot symbolic bytes (including symbolic `argv[0]` bytes) concretized from the solver model. |
| `branch_analysis.replay.matched_alternate` | True only when concrete execution restarted from entry, reached the recorded branch PC, and stepped to the solver-predicted alternate successor. |
| `branch_analysis.replay.observed_target_hex` | Exact successor observed after replaying the branch, when available. |
| `branch_analysis.replay.detail` | Human-readable explanation of validation, refusal, mismatch, or budget exhaustion. |
| `branch_analysis.trace_fingerprint_hex` | Deterministic fingerprint of the exact entry-to-branch PC sequence for this dynamic decision. Replay must match it, the branch PC, and the dynamic visit index before status can become `validated`. |
| `branch_analysis.history` | Bounded ordered branch-decision provenance for the selected diagnostic state (up to 64 decisions). |
| `branch_analysis.history_candidate_index` | Highest-ranked older decision whose alternate edge is structurally better toward a configured `find` target. |
| `branch_analysis.history_candidate_analysis` | At most one extra solver/replay analysis for that older decision, including CFG distances, model, replay, and steering verdict. |
| `branch_analysis.condition_true_target[_hex]` / `condition_false_target[_hex]` | Preferred aliases for the two predicate successors. These avoid implying how the original ISA mnemonic spells its architectural jump sense. |
| `branch_analysis.chosen_condition` | `true` or `false` for the predicate value followed by the selected diagnostic state. Prefer this over the legacy `chosen = taken/not_taken` label in operator-facing output. |
| `branch_analysis.cfg_source` | `shared-history-root` when newest-branch distances reuse the bounded CFG recovered for history ranking, or `latest-branch-fallback` when the shared recovery failed and Angryier retried from the newest branch PC. |
| `branch_analysis.model[*].value_hex` | For 64-bit register-backed solver assignments, canonical integer value suitable for replay (for example `0x000000000000002a`). Raw solver bytes remain available separately for byte-granular inputs. |
| `found` | Number of states that reached a `find` target. |
| `inputs` | Only with `solve = true`: one entry per solved found state, each an array of byte-strings (model bytes per symbol). Per-state model solving is capped at 10 seconds. |
| `regs` | Only when at least one state was found: the first found state's register bindings, keyed by engine register ID (rax = 0 … r15 = 15), values are integers for concretely-bound registers. |

### `angry.open(path) -> session`

REPL-style handle to a live symbolic session (static load). Methods:

| Call | Returns |
|---|---|
| `s:step()` | `"stepped"`, `"branched"`, or `"terminated"` (single step of state 0). |
| `s:pc()` | Current program counter of state 0. |
| `s:reg("rdi")` | Concrete register value, or `nil` when the register is symbolic. |
| `s:states()` | Number of live states. |
| `s:symbolic("rdi")` | Marks the register symbolic on state 0 (64-bit). An optional second argument sets the width — `s:symbolic("rdi", 64)` is accepted; any other width errors (`width must be 64 bits`), since GPR symbols are 64-bit only. |

### `angry.version()`

Returns the `angryier-runtime` crate version string.

---

## Examples

**Workspace status:**

```bash
$ cargo run -p angryier-cli -- status
Angryier 0.1.0 — Rust-native multicore symbolic/concolic execution engine

Workspace: 43 crates
Implemented: 41 crates with real logic
Scaffolded: 2 crates (contract boundaries, fail-closed)

Tests: 585 tests across 78 suites (0 failures, historical count)
```

**Symbolic run with a find target (CLI flags):** fork on symbolic `rdi`, hunt for the success branch at `0x40102a`, symbolize 8 bytes of `argv[0]`:

```bash
cargo run -p angryier-cli -- run ./crackme \
    --symbolic rdi --find 0x40102a --argv 8 --steps 1024
# steps=... forks=... merges=... terminated=... found=1
```

(`--steps` defaults to 256, the same default a bare `angry.run` opts table gets.)

**Lua-scripted run with solving** — `find.lua`:

```lua
local r = angry.run("./crackme", {
    symbolic = { rdi = 64 },
    find     = { 0x40102a },   -- success branch
    avoid    = { 0x40103b },   -- failure exit
    argv     = 8,              -- symbolize argv[0]
    solve    = true,           -- solve found states with Z3
    steps    = 512, states = 32,
})
print(string.format("found=%d forks=%d steps=%d", r.found, r.forks, r.steps))
for i, input in ipairs(r.inputs) do
    print(string.format("model %d: %q", i, input[1]))
end
```

```bash
cargo run -p angryier-cli -- run ./crackme --script find.lua
```

**Interactive stepping** (`angry.open`):

```lua
local s = angry.open("./demo")
s:symbolic("rdi")
while s:step() ~= "terminated" do
    print(string.format("pc=%#x states=%d", s:pc(), s:states()))
end
```

---

## Known quirks

- The `run` parser is strict: anything not listed in the usage line (including mistyped flags, flags without a value, repeated non-repeatable flags, and a second `<binary>` positional) exits 1 instead of being dropped or silently overridden.
- `--symbolic` width is 64 bits — from the CLI and from Lua alike. This is now enforced rather than silently ignored: the Lua opts table's width value is validated (`64` or omitted only) and `s:symbolic` takes an optional width with the same constraint. Supporting other GPR widths needs evaluator work (width-mismatched reads), not just a parser change.
- The CLI `version` string and Lua `angry.version()` both derive from the workspace package version (`version.workspace = true`), so they move together; they are only as granular as that single version.
- The `status` test figures are a historical snapshot from the 2026-09 documentation pass, not a live count.
- `regs` in the `angry.run` result is keyed by numeric register ID, not by name.
