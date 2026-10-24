# Angryier Lua Scripting API Reference

Angryier provides a high-performance embedded Lua 5.4 scripting environment (Phase 15 of [`docs/ROADMAP.md`](./ROADMAP.md)) designed for dynamic symbolic execution, binary inspection, interactive debugging, and automated vulnerability research.

---

## 1. Runtime Environment & Sandboxing

Angryier embeds Lua 5.4 using [`mlua`](https://github.com/khvzak/mlua). When authoring scripts, observe the following environment constraints:

### 1.1 Available Standard Libraries
- **`string`**: Full Lua 5.4 string manipulation (`format`, `sub`, `byte`, `char`, `pack`, `unpack`, `gmatch`, `gsub`, `find`, `match`).
- **`table`**: Full table library (`insert`, `remove`, `sort`, `concat`, `pack`, `unpack`).
- **`math`**: Full math library (`max`, `min`, `floor`, `ceil`, `type`, `tointeger`, `ult`, `maxinteger`, `mininteger`).
- **`os`**: Bounded subset: `os.getenv`, `os.clock`, `os.time`, `os.difftime`. *(System execution like `os.execute` is disabled for sandbox safety).*
- **`io`**: Bounded file I/O: `io.open`, `file:read`, `file:write`, `file:seek`, `file:close`.

### 1.2 Disabled / Unavailable Modules
- **`debug` is NOT loaded**: The `debug` library (including `debug.traceback`) is `nil`. Do **not** call `debug.traceback`. Use custom error formatting or standard `pcall`/`xpcall` with `tostring`.
- **`package` / `require` is disabled**: Scripts are self-contained standalone execution units.

### 1.3 Native Lua 5.4 Bitwise Operators
Lua 5.4 natively supports 64-bit integer bitwise operators:
- Bitwise AND: `a & b`
- Bitwise OR: `a | b`
- Bitwise XOR: `a ~ b`
- Bitwise NOT: `~a`
- Left Shift: `a << n`
- Right Shift: `a >> n`

---

## 2. Binary Analysis Utilities (`angry.*`)

The global `angry` table provides zero-overhead binary analysis and manipulation helpers:

### `angry.version() -> string`
Returns the Cargo package version of the running Angryier engine.

### `angry.hex(bytes: string) -> string`
Encodes a raw byte string into a lowercase hexadecimal string.
```lua
local hex = angry.hex("HELLO") -- "48454c4c4f"
```

### `angry.unhex(hex_str: string) -> string`
Decodes a hex string (ignoring spaces, underscores, and optional `0x` prefix) into raw bytes. Errors if length is odd or contains invalid characters.
```lua
local raw = angry.unhex("48 45 4c 4c 4f") -- "HELLO"
```

### `angry.pack64(integer: number) -> string`
Packs a 64-bit integer into 8 bytes in little-endian order.
```lua
local raw = angry.pack64(0xdeadbeef)
```

### `angry.unpack64(bytes: string) -> number`
Unpacks the first 8 bytes of a string into a 64-bit integer (little-endian).

### `angry.pack32(integer: number) -> string`
Packs a 32-bit unsigned integer into 4 bytes in little-endian order.

### `angry.unpack32(bytes: string) -> number`
Unpacks the first 4 bytes of a string into a 32-bit unsigned integer (little-endian).

### `angry.disasm(bytes: string, [base_pc: number]) -> table`
Disassembles raw x86_64 machine code using the native Intel XED engine. Returns an array of instruction tables:
```lua
local insns = angry.disasm("\x48\x31\xc0\xc3", 0x401000)
for i, insn in ipairs(insns) do
    print(string.format("0x%x: %s (%d bytes)", insn.pc, insn.hex, insn.len))
end
```
Each instruction entry contains:
- `pc`: 64-bit instruction virtual address.
- `len` / `length`: Instruction byte length.
- `bytes`: Raw instruction byte string.
- `hex`: Space-separated hex representation.
- `form_id`: Internal semantic form ID.
- `operands_count`: Number of decoded operands.
- `invalid`: Boolean present and true if decoding failed for this byte.

---

## 3. The 64-bit Machine Address Convention (`_hex` Fields)

Lua 5.4 integers are signed 64-bit (`-0x8000000000000000` to `0x7fffffffffffffff`).
A Rust unsigned `u64` that exceeds `i64::MAX` is delivered to Lua as a float (double), which is exact only up to 2^53.
Kernel pointers (e.g. `0xffff800000000000`) and upper-half memory addresses cannot round-trip through plain numeric fields without bit corruption.

**Mandatory Convention**: Every address-bearing value exposed by Angryier appears with an exact `<name>_hex` sibling:
- In `angry.run` result tables: `trace_hex[i]`, `entry_rsp_hex`, `regs_hex[reg_id]`, `unmapped_sites[i].address_hex`, `ro_write_reverts[i].address_hex`.
- In `LuaState` / `LuaSession` accessors: `st:pc_hex()`, `st:reg_hex(name)`, `st:regs_hex()`, `st:trace_hex()`.
- In register seeds: `regs = { rcx_hex = "0xffff800012345678", rdx = 0x1000 }`.

Always use the `_hex` strings when formatting, comparing, or masking memory addresses that may reside above `0x7fffffffffffffff`.

---

## 4. Headless Driver (`angry.run`)

`angry.run(binary_path, options)` executes an automated multi-state symbolic/concolic exploration campaign without manual state pumping and returns an aggregated result table.

### 4.1 Complete Options Schema (`options`)

| Option | Type | Default | Description |
|---|---|---|---|
| **`entry`** | `number` / `string` | *(image entry)* | Overrides initial PC. Pushes an exit sentinel frame (`0xDEADBEEF0000`) at `[rsp-8]`, adjusts `rsp`, and captures function return cleanly. |
| **`find`** | `table` | `{}` | Array of target addresses to reach. Execution flags a hit and records the state. |
| **`avoid`** | `table` | `{}` | Array of error/abort addresses. Paths reaching these are immediately pruned. |
| **`symbolic`** | `table` | `{}` | Map of 64-bit GPR names to width (e.g. `{ rdi = 64, rsi = 64 }`) or array of names (`{ "rdi", "rsi" }`). |
| **`regs`** | `table` | `{}` | Initial concrete register values. Supports numeric values or exact 64-bit strings via the `_hex` convention (e.g. `{ rax = 0, rcx_hex = "0xffff800000001000" }`). |
| **`poke`** | `table` | `{}` | Array of `{ addr = 0x..., value = 0x... }` 8-byte little-endian memory writes applied before execution starts. Auto-provisions scratch pages under `uc_memory`. |
| **`load_mem`** | `table` | `{}` | Array of `{ addr = 0x..., path = "..." }` file-backed memory loads (e.g. for supplementary sections or dump slices). Auto-provisions scratch pages under `uc_memory`. |
| **`symbolic_memory`** | `table` | `{}` | Array of `{ addr = 0x..., len = N }` regions initialized as fresh byte-granular symbolic variables. |
| **`stubs`** | `table` | `{}` | Map of address to return value (`{ [0x401000] = 0 }`) or array of `{ addr = 0x..., ret = 0 }` to force immediate returns. |
| **`redirects`** | `table` | `{}` | Map of from-address to to-address (`{ [0x401000] = 0x402000 }`) to patch control flow. |
| **`patches`** | `table` | `{}` | Map of address to raw hex string (`{ [0x401000] = "9090" }`) or array of `{ addr = 0x..., bytes = "..." }`. |
| **`steps`** | `number` | `256` | Maximum instruction work units to execute across the campaign. |
| **`states`** | `number` | `16` | Maximum concurrent live states pool size (enforces state-cap pruning). |
| **`timeout_secs`** | `number` | `60` | Whole-run wall-clock deadline in seconds. |
| **`branch_timeout_ms`** | `number` | `1000` | SMT budget for alternate branch feasibility exploration. |
| **`solve`** | `boolean` | `false` | When true, invokes the SMT backend to solve path constraints on find hits, populating `r.inputs`. |
| **`exploration`** | `string` | `"fork"` | Search strategy: `"fork"` (worklist) or `"dfs"`. |
| **`uc_memory`** | `boolean` | `false` | Under-constrained memory relaxation: unmapped reads return zero bytes; unmapped writes allocate a page; pre-session `poke`/`load_mem` auto-map scratch memory. |
| **`zero_low_pages`** | `boolean` | `false` | Maps the low 64 KiB (`0x0..0x10000`) as zeroed RAM to prevent NULL-dereference faults. |
| **`uc_write_ro`** | `boolean` | `false` | When `uc_memory` is enabled, relaxes writes into read-only sections, recording original bytes in `ro_write_reverts`. |
| **`unsupported`** | `string` | `nil` | Set to `"fallthrough"` to skip unmodeled privileged instructions (e.g. CLI, STI, HLT) with debt tracking. |
| **`memory_dump_out`** | `table` | `nil` | Table `{ addr = 0x..., len = N, path = "out.bin" }` to extract final memory bytes of the primary state to disk. |
| **`argv`** | `number` | `nil` | Seeds symbolic bytes into `argv[0]`. |
| **`files`** | `table` | `{}` | Table of `{ "flag.txt" = true }` where `openat` returns a descriptor reading symbolic bytes. |
| **`contents`** | `table` | `{}` | Table of `{ "file.txt" = "content" }` for in-memory virtual filesystem seeding. |
| **`pool_prealloc`** | `number` | `0` | Pre-allocates N tracked kernel pool blocks (in PE driver mode). |

---

### 4.2 Result Table Schema (`report`)

The table returned by `angry.run` contains exhaustive execution telemetry:

#### Campaign Status & Counters
- `report.steps`: Total instruction work units executed.
- `report.forks`: Number of new execution states spawned at symbolic branches.
- `report.merges`: Number of compatible execution paths recombined.
- `report.terminated`: States that reached modeled exit conditions.
- `report.pruned_states`: States discarded by policy or state-cap limits.
- `report.failed`: States terminated by execution/semantic errors.
- `report.live_states`: States still active when the run completed.
- `report.dead_states`: Retained terminated/pruned states.
- `report.peak_states`: Maximum simultaneous exploration frontier size.
- `report.found`: Number of states that successfully reached a `find` target.
- `report.timed_out`: Boolean indicating whether the wall-clock deadline expired.
- `report.last_error`: String message of the most recent execution failure (or `nil`).

#### Exit Telemetry (Function Override Mode)
When `entry` is overridden, `angry.run` monitors the exit state of the primary path:
- `report.rax_exit`: Numeric return value in RAX.
- `report.rax_exit_symbolic`: True if RAX held an unconstrained symbolic expression.
- `report.exit_pc`: Instruction address at termination.
- `report.exit_kind`: String classification:
  - `"sentinel_ret"`: Clean function return via the synthetic `[rsp]` sentinel frame (`0xDEADBEEF0000`).
  - `"other"`: Trapped, faulted, or stopped at an unmapped location.
- `report.rax_exit_hex` / `report.exit_pc_hex`: exact 16-digit `_hex`-convention strings for the same values — kernel-mode exits live above `i64::MAX`, where the numeric forms are float-lossy; scripts must prefer these.
- `report.entry_rsp` / `report.entry_rsp_hex`: Initial stack pointer after sentinel setup.
- `report.elapsed_ms`: Wall-clock milliseconds for the exploration phase of this campaign (load time is not included — see `img:stats()` for load-vs-run cost).

#### Traces & Solver Solutions
- `report.trace`: Array of 64-bit integer addresses representing executed basic blocks.
- `report.trace_hex`: Array of exact 16-digit hexadecimal strings (`_hex` convention).
- `report.inputs`: Array of solved models (when `solve = true`). Each model is an array of raw byte strings corresponding to symbolic variables.
- `report.regs` / `report.regs_hex`: Register map of the first found state.
- `report.memory_dump`: Path to the exported memory dump (if `memory_dump_out` was set).

#### Semantic Debt & Fidelity Records
Under-constrained relaxations are tracked honestly in the result table:
- `report.unmapped_total`: Count of unmapped memory reads/writes tolerated.
- `report.unmapped_sites`: Array of `{ op = "read"|"write"|"write_ro", address = 0x..., page = 0x... }`.
- `report.ro_write_total`: Count of relaxed writes into read-only pages.
- `report.ro_write_reverts`: Array of `{ address = 0x..., previous = 0x... }` recording overwritten bytes.
- `report.vector_debt_total`: Count of vector operations abstracted as symbolic unconstrained variables.
- `report.vector_debt_sites`: Array of `{ op, width, lane }`.
- `report.unsupported_total`: Count of unmodeled instructions bypassed via fallthrough.
- `report.unsupported_sites`: Array of `{ pc, form }`.

---

### 4.3 Prepared Image: Load-Once Bulk Campaigns (`angry.prepare`)

`angry.run` reads and parses the image on every call — for unpacked
multi-hundred-MB kernels that is minutes per job. `angry.prepare` performs
the load exactly once per process and hands back a `PreparedImage` whose
per-job campaigns start from a pristine copy-on-write clone of the template
(milliseconds, image pages `Arc`-shared and resident).

```lua
local img = angry.prepare("/path/driver.sys")  -- opts: dynamic, unsupported
local r1 = img:run({ entry = 0x140001000, regs = { rcx_hex = "0xffff800000001000" }, steps = 400 })
local r2 = img:run({ entry = 0x140002000, steps = 400 })  -- same image, fresh state
local s = img:stats()  -- { load_ms, jobs, run_ms_total, last_run_ms, avg_run_ms, is_pe, image_regions }
```

* `img:run(opts) -> report` accepts the **complete** `angry.run` option
  surface and returns the **same** report table shape. Isolation invariants:
  each job gets its own entry sentinel frame, register seeds, symbolic
  marks, kernel-pool tracker (alloc/free/double-free accounting never
  crosses campaigns), UC-memory debt ledger, and unsupported-form
  fallthrough debt. Nothing mutable survives between jobs.
* `img:run_batch(jobs, [batch_opts]) -> { { ok, report?, error? }, ... }`
  runs an array of per-job opts tables on a **native in-process worker
  pool** (`batch_opts.threads`, default logical CPUs). One image load, N
  worker threads, ordered results — the same isolation as sequential runs.
  Per-job `unsupported` fallthrough is batch-level (pass it to `prepare` or
  `batch_opts`); per-job debt then aggregates across the batch.
* `img:stats()` exposes load-vs-run cost so drivers can see where the wall
  clock goes (and measure the load-once win directly).

## 5. Interactive Session Controller (`angry.open` / `LuaSession`)

`angry.open(path, [opts])` returns a live `LuaSession` userdata handle for step-by-step interactive analysis, breakpoint debugging, and custom path scheduling.

### 5.1 Session Configuration Options (`opts`)
- `entry`: Override initial PC.
- `symbolic`: Table of GPR names to bit widths (`{ rdi = 64 }` or `{ "rdi" }`).
- `regs`: Initial register map (`{ rax = 0, rdi = 0x1000 }`).
- `poke`: Array of `{ addr = 0x..., value = 0x... }` memory writes. Under `uc_memory`, auto-maps scratch pages.
- `load_mem`: Array of `{ addr = 0x..., path = "..." }` file loads. Under `uc_memory`, auto-maps scratch pages.
- `symbolic_memory`: Array of `{ addr = 0x..., len = 16 }` regions.
- `zero_low_pages`: Boolean. Maps `0x0..0x10000` as zeroed RAM.
- `uc_memory`: Boolean. Enables under-constrained memory fallback.
- `uc_write_ro`: Boolean. Allows writes to read-only sections.

### 5.2 Stepping & Exploration
- `s:step([n]) -> string`: Advances the active state by up to `n` basic blocks (default 1). Returns outcome string:
  - `"stepped"`: Normal step completed.
  - `"branched"`: Execution branched into multiple paths.
  - `"terminated"`: Active state terminated.
  - `"breakpoint"`: Hit a registered breakpoint.
  - `"hook_terminated"`: Aborted by a Lua hook.
- `s:step_until(target_pc, [max_steps]) -> (string, number)`: Steps iteratively until the active state reaches `target_pc` or `max_steps` is exceeded. Returns `(outcome, steps_taken)`.

### 5.3 State Pool Management

- `s:reset([opts])` — rebuilds the **whole symbolic session** from the
  pristine post-load template (fresh states, constraints, ids, debt
  ledgers) and re-applies options. One image load serves arbitrarily many
  fresh campaigns per process; hook/breakpoint registrations persist, and
  stale `LuaState` handles from the previous generation fail lookup
  explicitly.
- `s:spawn_state(opts)` — alias of `s:reset` with a mandatory opts table.
- `s:states()` / `s:states_count() -> number`: Number of currently alive states.
- `s:dead_count() -> number`: Number of terminated / dead states.
- `s:active_index([new_idx]) -> number`: Gets or sets the 0-based index of the active state.
- `s:select_state(idx) -> boolean`: Selects the state at index `idx` as active.
- `s:spawn_state(opts) -> ()`: Rebuilds a fresh process + session from the retained image
  bytes (one image load per process). Accepts the per-job options `entry`, `uc_memory`,
  `uc_write_ro`, `uc_drop_exec_write`, `zero_low_pages`; an `entry` override also pushes
  the `EXIT_HOOK` sentinel frame so a returning function terminates cleanly. Replaces all
  live/dead states and resets the active index; hooks and breakpoints persist.
- `s:state([idx]) -> LuaState`: Returns a `LuaState` handle for state `idx` (defaults to active state).
- `s:dead_state(idx) -> LuaState`: Returns a `LuaState` handle for dead state `idx`.

### 5.4 Breakpoints & Hooks
- `s:add_breakpoint(addr)`: Adds a breakpoint at instruction address `addr`.
- `s:remove_breakpoint(addr) -> boolean`: Removes a breakpoint.
- `s:breakpoints() -> table`: Returns an array of active breakpoint addresses.
- `s:hook(addr, fn)`: Registers a callback `fn(state)` called immediately before executing `addr`. If `fn` returns `false` or `"terminate"`, the path is terminated immediately.
- `s:unhook(addr) -> boolean`: Removes a hook.

### 5.5 Active State Shortcuts
All `LuaState` inspection and mutation methods (`pc`, `pc_hex`, `reg`, `reg_hex`, `regs`, `regs_hex`, `read_bytes`, `write_bytes`, `poke`, `symbolic`, `symbolic_memory`, `trace`, `trace_hex`, `constraints_count`, `solve`, `eval`, `is_alive`) can be called directly on `s`, forwarding to the active state.

---

## 6. First-Class State Handle (`LuaState`)

A `LuaState` represents an individual execution path. Handles track their target by unique `state_id`, making them resilient against list reordering and branching.

### 6.1 State Inspection (Works on BOTH Alive and Dead States)
The following read accessors query the state's register file, process memory, constraints, and execution trace regardless of whether the state is still alive or terminated:
- `st:id() -> number`: Unique 64-bit state ID.
- `st:is_alive() -> boolean`: True if the state is still active in `s:states()`; false if dead/terminated.
- `st:pc() -> number`: Reads the instruction pointer (RIP).
- `st:pc_hex() -> string`: Exact 16-digit hex form of the PC (the `_hex` convention).
- `st:reg(name) -> number | nil`: Reads a register value (`"rax"`, `"rbx"`, `"rip"`, `"rflags"`, etc.).
- `st:reg_hex(name) -> string | nil`: Exact 16-digit hex form of one register value.
- `st:regs() -> table`: Map of register names to their current 64-bit concrete values.
- `st:regs_hex() -> table`: Same map with every value as an exact hex string.
- `st:read_bytes(addr, len) -> string`: Reads `len` bytes starting at `addr` as a Lua byte string.
- `st:trace() -> table`: Array of executed basic block PC addresses in this path's trace ring.
- `st:trace_hex() -> table`: Same trace as exact 16-digit hex strings.
- `st:constraints_count() -> number`: Number of accumulated path constraints.

### 6.2 State Mutation (Requires State to be Alive)
- `st:pc(new_pc)`: Sets the instruction pointer (RIP).
- `st:reg(name, new_val)`: Sets a register value.
- `st:write_bytes(addr, data)`: Writes raw bytes (`string` or array of byte numbers) to `addr`.
- `st:poke(addr, val)`: Writes a 64-bit little-endian integer `val` to `addr`.
- `st:symbolic(name, [width])`: Marks a register symbolic (64-bit GPR).
- `st:symbolic_memory(addr, len)`: Marks `len` bytes at `addr` as fresh symbolic variables.
- `st:terminate()`: Kills this execution path and moves it to the dead states pool.

### 6.3 SMT Solver Operations (Requires Active State)
- `st:solve() -> table`: Queries the native Z3 SMT solver for a satisfiable assignment to all symbolic variables on this path. Returns an array of byte strings.
- `st:eval(name) -> number`: Solves path constraints and evaluates the concrete 64-bit integer value for register `name`.

---

## 7. Architecture Guide: `angry.run` vs `angry.open`

| Decision Axis | Use `angry.run` | Use `angry.prepare` / `img:run` | Use `angry.open` |
|---|---|---|
| **Primary Goal** | Find target reachability, exploit solving, fuzzing handoff | Step-by-step tracing, function behavioral profiling |
| **Execution Control** | Automated exploration worklist (BFS/DFS) | Custom scheduling loop with manual `s:step()` |
| **Path Pruning** | Automatic via `avoid` targets and `states` cap | Explicit via hooks returning `"terminate"` or `st:terminate()` |
| **Function Probing** | Supported natively via `entry` override (returns `rax_exit`) | Supported via manual breakpoint at exit sentinel |
| **Memory Mocks** | Native `load_mem` and `poke` (auto-mapped scratch pages) | Native `load_mem`, `poke`, and dynamic `st:write_bytes` |
| **Fidelity Telemetry** | Full aggregated debt reports (`unmapped_sites`, etc.) | Per-state memory/constraint inspection |

---

## 8. Practical Recipes & Patterns

### 8.1 Headless Goal-Directed Exploration (`angry.run`)
```lua
local TARGET = os.getenv("ANGRY_TARGET") or "./target.exe"
local report = angry.run(TARGET, {
    entry = 0x1405e0ef0,
    find = { 0x1405e3bbc },
    avoid = { 0x1405e3b82 },
    symbolic = { rcx = 64 },
    steps = 10000,
    states = 32,
    solve = true,
    uc_memory = true,
    zero_low_pages = true,
})

if (report.found or 0) > 0 then
    print("[+] Reached target! Solved models:")
    for i, model in ipairs(report.inputs or {}) do
        print(string.format("  Model #%d: %s", i, angry.hex(model)))
    end
else
    print("[-] Target not reached. Steps: " .. tostring(report.steps))
end
```

### 8.2 Function Return Probe (`angry.run`)
```lua
local TARGET = os.getenv("ANGRY_TARGET") or "./target.exe"
local report = angry.run(TARGET, {
    entry = 0x1405e0ef0, -- Starts function with synthetic [rsp] sentinel
    regs = { rcx = 0x1000, rdx = 0 },
    steps = 5000,
    uc_memory = true,
    zero_low_pages = true,
})

print(string.format("Function Exit: kind=%s, rax=0x%x (%d), pc=0x%x",
    report.exit_kind or "none", report.rax_exit or 0, report.rax_exit or 0, report.exit_pc or 0))
```

### 8.3 In-Memory Mocking & Scratch Arenas (`state_mock_explorer.lua` Pattern)
```lua
local TARGET = os.getenv("ANGRY_TARGET") or "./target.exe"
local SCRATCH = 0x20000000

-- Auto-maps 0x20000000 under uc_memory:
local report = angry.run(TARGET, {
    entry = 0x1405e0ef0,
    find = { 0x1405e3bbc },
    uc_memory = true,
    zero_low_pages = true,
    poke = {
        -- Synthetic linked list head pointing to scratch node
        { addr = 0x1421de170, value = SCRATCH },
        -- Node: next=head, prev=head
        { addr = SCRATCH,     value = 0x1421de170 },
        { addr = SCRATCH + 8, value = 0x1421de170 },
    },
    steps = 5000,
})
```
