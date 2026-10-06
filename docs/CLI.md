# Angryier CLI Reference

> Binary: `angryier` (crate `angryier-cli`). The default build includes the `run` subcommand (symbolic/concolic execution, optionally driven by an embedded Lua script, plus PE driver mode) with native decoding (Intel XED) and solver (Z3) dependencies. A dependency-free metadata-only build (`version`, `status`, `crates`, `help`) is available via `--no-default-features` and works anywhere Rust compiles.
>
> Source of truth: `crates/angryier-cli/src/main.rs` (argument parsing) and `crates/angryier-runtime/src/script.rs` (the Lua surface).

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
| `status` | Workspace summary: 39 crates (37 implemented, 2 scaffolded), historical test totals | 0 |
| `crates` | One line per workspace crate: name, `Implemented`/`Scaffolded`, short description | 0 |
| `help`, `-h`, `--help` | The usage text above | 0 |
| *(none)* | One-line brief (version + tagline) | 0 |
| `run ...` | See below; requires the `run` feature | 0/1 |
| anything else | `error: unknown command '<cmd>'` on stderr | 1 |

Note: `help` always lists `run`. In builds without the feature its line reads `Not in this build (rebuild with --features run)`; in feature builds it reads `Execute a binary symbolically`.

---

## `angryier run` — execute a binary symbolically

```
usage: angryier run <binary> [--script f.lua] [--symbolic REG] [--find ADDR] [--argv N] [--steps N] [--dynamic] [--driver]
note: --find ADDR is hexadecimal, 0x prefix optional
```

Loads an ELF64 or PE32+ image into the engine and runs it concretely/symbolically. The loader is chosen by magic bytes: ELF loads statically by default (`load_elf`), with `--dynamic` the dynamic-linking environment model is used (`load_elf_dynamic`), and an `MZ` image loads in **driver mode** (`load_pe_driver`: sections mapped, IAT resolved to import stubs, DriverEntry entry state — `dynamic` is ignored for PE).

### Flags

| Flag | Repeatable | Meaning |
|---|---|---|
| `<binary>` (positional) | — | Path to the ELF64 or PE32+ image to execute. Required, even when `--script` is given (the script chooses whether to reference it). A second positional operand exits 1 with an error. |
| `--script f.lua` | no | Lua driver script (see the Lua API below). When set, the script has full control; the other flags are still validated but their values are unused. |
| `--symbolic REG` | yes | Mark a general-purpose register symbolic before execution. `REG` is one of `rax rcx rdx rbx rsp rbp rsi rdi r8`–`r15`; other names exit 1 with an error. Always marked 64 bits wide. |
| `--find ADDR` | yes | Add a target address (hexadecimal, `0x` prefix optional) to the exploration policy's find set. Non-hex values exit 1 with an error. |
| `--argv N` | no | Symbolize `argv[0]` as `N` bytes (the model materializes `N` bytes, NUL-terminated, on the initial stack). Non-numeric values exit 1 with an error. |
| `--steps N` | no | Instruction-step budget for the synthesized driver. Defaults to `256` — the same value as the Lua API's `opts.steps` default (the two share one constant, `angryier_runtime::script::DEFAULT_STEPS`, so they cannot drift). Non-numeric values exit 1 with an error. |
| `--dynamic` | no | Load via the dynamic-linking path (`__libc_start_main` hook, `main(argc, argv)` entry) instead of static `_start`. |
| `--driver` | no | Force direct PE32+ kernel-driver execution through the Rust runtime. Lua is bypassed; kernel pool tracking is attached; `--script`, `--symbolic`, `--find`, `--argv`, and `--dynamic` are parsed but not applied in this mode. |

"Repeatable: no" is enforced: a repeated `<binary>` positional, `--script`, `--argv`, `--steps`, `--dynamic`, or `--driver` exits 1 with a `duplicate ...` error naming the second value instead of silently taking the last one.

Address parsing for `--find` is hexadecimal with an optional `0x` prefix: `--find 0x40102a` and `--find 40102a` are equivalent, and `--find 1234` means address `0x1234`.

### The default driver

Without `--script`, the CLI synthesizes this Lua driver and evaluates it:

```lua
local r = angry.run("<binary>", { symbolic = { <regs marked 64-bit> },
                                  find = { <find addresses> },
                                  [argv = N,] [dynamic = true,]
                                  steps = <steps>, states = 16 })
print("[angryier][result] symbolic/concolic exploration completed")
print(string.format("  exploration steps : %d (engine work units executed)", r.steps))
print(string.format("  forks             : %d (new execution states created at branches)", r.forks))
print(string.format("  merges            : %d (compatible states recombined)", r.merges))
print(string.format("  terminated states : %d (states that reached a terminal condition)", r.terminated))
print(string.format("  find hits         : %d (configured target-address hits)", r.found))
```

`steps` is the `--steps` value (default `256`, shared with the Lua API's own `opts.steps` default — previously the CLI hardcoded `1024`, silently overshooting scripts by 4×). `states = 16` likewise matches the Lua API default (`angryier_runtime::script::DEFAULT_MAX_STATES`). Solver stays off (found targets are counted, not solved — use `--script` with `solve = true` to get models).

### Operator-facing diagnostics

Before execution starts, the CLI now prints a structured **execution plan** containing the target, frontend, effective mode, step/state budgets, symbolic registers, find targets, and symbolic argv settings. If a custom Lua script or `--driver` makes other CLI flags ineffective, that is stated explicitly rather than silently ignored.

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
- **Target reached:** recommend a custom Lua rerun with `solve=true`, followed by concrete replay of the recovered satisfying input.
- **Live-state saturation:** recommend selectively increasing `states` and tightening find/avoid policy.
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


The generated driver also prints an `[angryier][analysis]` section before the recommendation list. It includes the retained path tail, the last retained frontier block, a fidelity/evidence-quality classification, and a single primary limiter chosen from timeout, state pruning, state failure, unsupported semantics, under-constrained memory/address handling, vector semantic debt, step-budget exhaustion, absent symbolic influence, or unresolved target reachability.

The analysis layer deliberately does **not** call the last trace block “closest to target” unless CFG evidence exists. A final trace PC is only the last retained frontier observation; numeric address proximity is not meaningful reachability evidence.

The `[angryier][analysis] symbolic frontier` subsection reports which symbolic sources are present in the selected path's accumulated constraints. This is narrower than “all symbols created during execution”: a register source that does not appear in the retained constraint dependency union has not contributed to a retained path predicate on that diagnostic state. The CLI therefore recommends preserving path-relevant sources first and concretizing unrelated inputs unless trace/taint evidence justifies keeping them symbolic.

The subsection prints both the complete current symbolic-register set and the path-relevant register subset. Registers present in the first set but absent from the second are labeled **non-predicate symbolic** and treated as concretization candidates, not automatically discarded inputs: they may still matter to later code, memory addressing, or data-only effects that have not yet entered a branch predicate.

When region forking is active, the CLI reports the number of guessed child worlds and tells the operator to inspect `region_fork_sites` before trusting a reachable path. When state pruning occurs, it prints the peak frontier against the configured cap so the next decision can distinguish “raise capacity” from “improve search policy.”

### Exit codes

| Code | Cause |
|---|---|
| 0 | Driver/script evaluated successfully. |
| 1 | Missing or duplicate `<binary>` positional; unknown flag (e.g. a typo); a flag missing its value; invalid `--symbolic` register; non-numeric `--argv`; non-numeric `--steps`; non-hex `--find`; a repeated non-repeatable flag (`--script`, `--argv`, `--steps`, `--dynamic`, `--driver`); `--script` file unreadable; Lua init/eval error (including an unsupported symbolic width in the opts table); driver load/model initialization failure; or the binary was built without the `run` feature. |

Argument errors are prefixed `error:` and followed by usage plus a corrective hint. Runtime diagnostics use structured prefixes such as `[angryier][plan]`, `[angryier][load]`, `[angryier][exec]`, `[angryier][trace]`, `[angryier][progress]`, `[angryier][result]`, `[angryier][verdict]`, and `[angryier][hint]` so logs remain readable and grep-friendly.

---

## Lua API (`angry` library)

Every driver script — the synthesized one or a `--script` file — runs in a fresh Lua 5.4 VM with a global `angry` table.

### `angry.run(path, opts) -> table`

Loads `path`, applies the symbolic-input configuration, explores, and returns a report table. The exploration itself is wall-clock capped at 30 seconds.

Options table (all fields optional):

| Field | Type | Default | Meaning |
|---|---|---|---|
| `symbolic` | table | `{}` | Registers to mark symbolic. Either `{ rdi = 64 }` or `{ "rdi" }`. The width value is validated: 64 (or omitted) is accepted, any other integer aborts the script with `symbolic register '<name>' width must be 64 bits (got N)` — narrower/wider GPR symbols would read as width-mismatched expressions. Unknown register names error (`bad reg <name>`) instead of being skipped. Valid names: the 16 GPRs listed above. |
| `find` | array of integer | `{}` | Target PCs; reaching one records a found state. |
| `avoid` | array of integer | `{}` | Avoid PCs for the exploration policy. |
| `steps` | integer | `256` | Instruction-step budget. The default is the shared constant `angryier_runtime::script::DEFAULT_STEPS`, which the CLI's `--steps` flag also uses. |
| `states` | integer | `16` | Maximum live states (`DEFAULT_MAX_STATES`). |
| `solve` | boolean | `false` | Solve each found state with the native Z3 backend and populate `inputs`. |
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

Workspace: 39 crates
Implemented: 37 crates with real logic
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
