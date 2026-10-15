# Angryier Generalized Lua Script Suite

This directory contains production-grade, adaptable Lua 5.4 driver scripts for the Angryier symbolic execution engine (`angryier run <binary> --script scripts/lua/<script>.lua`).

All scripts adhere to Angryier API contracts (documented in [`docs/LUA_API.md`](../../docs/LUA_API.md)):
- **64-bit integer convention**: High-half machine addresses above `i64::MAX` use exact 16-character lowercase `0x`-prefixed `_hex` strings (e.g. `entry_rsp_hex`, `trace_hex`, `pc_hex`) to prevent IEEE 754 float precision loss.
- **Under-constrained execution**: Configurable relaxations (`uc_memory`, `zero_low_pages`, `uc_write_ro`) with honest semantic debt tracking (`unmapped_sites`, `ro_write_reverts`, `vector_debt_sites`).
- **Telemetry audit**: Structured reporting of execution metrics (`steps`, `forks`, `merges`, `terminated`, `failed`, `live_states`, `found`), exit telemetry (`rax_exit`, `exit_pc`, `exit_kind`), and SMT constraint solver models (`inputs`).

---

## Script Inventory

| Script | Purpose | Key Capabilities |
|---|---|---|
| **`symex_target.lua`** | Goal-directed symbolic exploration | `entry` override, `find` / `avoid` targets, symbolic register marks, memory pokes, file-backed `load_mem` slices, SMT model extraction, trace tail. |
| **`trace_transition.lua`** | Boundary & transition tracing | Identifies control-flow transfers crossing module/section boundaries (e.g. `.text` into unpackers, VMs, or libraries), computes 4 KiB page execution heatmaps to detect loops. |
| **`probe_function.lua`** | Isolated function & stub profiling | Round-robin state scheduler, synthetic return frame at `[rsp]`, exit breakpoint intercept, return-value auditing (`rax_exit` unsigned/signed/hex), step sample tails. |
| **`state_mock_explorer.lua`** | Synthetic state & object mock DSL | Scratch arena allocator, mock doubly-linked lists (sentinel/circular), synthetic C++ vtables, comparative scorecard (baseline unmocked vs mocked execution). |
| **`themida_dispatch_census.lua`** | Themida indirect dispatch census | ModRM/SIB classifier (`a`, `a_noidx`, `c`, `d`), backward linear provenance walk, Space-Saving heavy hitter histograms, embedded 18-vector self-test. |
| **`expert_initializations_driver.lua`** | Sarin EI TRUE-path hunter | Automated 6-tail memory load, GDI+ gate crossing detector, singleton wait tracker, machine-readable `VERDICT` output. |
| **`wait_site_prober.lua`** | Interactive singleton/wait prober | Hooks at singleton constructor, wait function (Windows x64 ABI), VM tail-transfer; real-time slot polling; dead-state post-mortem analysis. |
| **`singleton_wait_solver.lua`** | 5-minute wait state synthesizer | Parameterizes 96 bytes of singleton object memory at `0x094464C0` as symbolic; solves state unblocking `0x140404E10` without waiting; emits C-ready pokes. |
| **`gdi_success_steerer.lua`** | Post-GDI+ path steerer & solver | Stubs GdiplusStartup at `0x1405E1043`; steps post-GDI logic to `0x1405E3BBC` (`mov bl, 1`); traces diverging branches and emits patch recommendations. |

---

## 1. `symex_target.lua` (Symbolic Target Explorer)

Executes a goal-directed symbolic campaign looking for specific target addresses while avoiding error branches.

### Invocation
```bash
ANGRY_TARGET=./binary.elf ANGRY_STEPS=5000 angryier run ./binary.elf --script scripts/lua/symex_target.lua
```

### Configuration Options (`CONFIG` / Environment)
- `ANGRY_TARGET`: Path to target executable (ELF or PE32+).
- `ANGRY_STEPS`: Maximum instruction step budget (default: 5000).
- `ANGRY_STATES`: Maximum active exploration states (default: 32).
- `ANGRY_TIMEOUT`: Whole-run wall-clock timeout in seconds (default: 60).
- `find`: Array of target virtual addresses (hex or integers).
- `avoid`: Array of failure/abort virtual addresses to prune.
- `symbolic`: Map of register names to bit widths (e.g. `{ rdi = 64, rsi = 64 }`).
- `load_mem`: Array of `{ addr = 0x..., path = "slice.bin" }` file-backed memory loads.

---

## 2. `trace_transition.lua` (Boundary & Transition Tracer)

Tracks execution across memory boundaries to locate exactly where a program transitions outside its main code section (e.g. jumping into Themida/VMProtect virtual machines, CRT initialization loops, or external API wrappers).

### Invocation
```bash
MODULE_START=0x140001000 MODULE_END=0x1419A3000 angryier run ./target.exe --script scripts/lua/trace_transition.lua
```

### Output Highlights
- **Boundary Transitions**: Enumerates every transition step index, `from_pc`, `to_pc`, and direction (`LEAVING_MODULE` or `ENTERING_MODULE`).
- **Context Window**: Displays the 12-block execution window centered around the final in-module block (`[LAST]`).
- **Page Heatmap**: Sorted distribution of 4 KiB memory pages executed, highlighting potential spin loops or tight poll cycles.

---

## 3. `probe_function.lua` (Isolated Function & Stub Probe)

Tests an individual function, indirect dispatcher, or runtime wrapper in complete isolation using an interactive `angry.open` session.

### Invocation
```bash
ANGRY_TARGET=./target.exe ANGRY_ENTRY=0x1405E0EF0 angryier run ./target.exe --script scripts/lua/probe_function.lua
```

### Features
- **Synthetic Return Frame**: Automatically populates `[rsp]` with an exit sentinel address and installs a breakpoint to cleanly intercept function returns.
- **Return Audit**: Audits the concrete and solver-evaluated return register (`rax_exit`) in hex, unsigned decimal, and signed decimal forms.
- **Round-Robin Scheduling**: Dispatches active states by stable state ID while enforcing an active state pool cap (`state_cap_pruned`).
- **Memory Dump on Exit**: Optionally extracts memory regions (`memory_dump_out`) on sentinel-reaching paths.

---

## 4. `state_mock_explorer.lua` (Synthetic Environment & Object Mocker)

Constructs mock runtime data structures in scratch memory to satisfy path conditions when analyzing truncated dumps or image-only captures.

### Invocation
```bash
ANGRY_TARGET=./target.exe ANGRY_FIND=0x1405E3BBC angryier run ./target.exe --script scripts/lua/state_mock_explorer.lua
```

### Mock Builder DSL Highlights
```lua
-- Scratch allocation in user-defined arena
local buf = m:alloc(0x100, { arena = "scratch", alignment = 16 })

-- Synthetic C++ vtable pointing to return-0 stubs
local vt = m:vtable({
    m:return0("vfunc_0"),
    m:return0("vfunc_1"),
    0x140001234, -- Existing native function
})

-- Synthetic doubly-linked list
local list = m:list({
    { id = 0, payload = "config_payload" },
    { id = 1, payload = "provider_data" },
}, { mode = "sentinel", node_size = 0x20 })

-- Synthetic C++ object with embedded vptr and list root
local obj = m:object(0x40, vt, { vptr_offset = 0x00 })
m:fields(obj, {
    { offset = 0x08, type = "u64", value = list.head },
    { offset = 0x10, type = "u32", value = list.count },
})
```

### Comparative Scorecard
Runs baseline unmocked execution followed by mocked execution, outputting a side-by-side scorecard comparing:
- Steps taken, forks, merges, terminated states, and live states.
- Find hits (verifying whether synthetic state unlocked reachability).
- Semantic debt counts (`unmapped_sites`, `ro_write_reverts`, `vector_debt_sites`).

---

## 5. `themida_dispatch_census.lua` (Themida Indirect Dispatch Census)

Static, bounded-memory x86-64 indirect-dispatch census designed specifically for analyzing massive virtualized code sections (`.themida` and `.boot` in Sarin Advisor).

### Invocation
```bash
# Run self-tests:
ANGRY_CENSUS_SELFTEST=1 angryier run target.exe --script scripts/lua/themida_dispatch_census.lua

# Full census sweep over raw image:
ANGRY_CENSUS_IMAGE=./advisor_unpacked_state.exe \
ANGRY_CENSUS_REPORT=./census_report.md \
angryier run target.exe --script scripts/lua/themida_dispatch_census.lua
```

### Features
- **Encoding Classifier**: Pure-Lua ModRM/SIB decoder categorizes all near/far indirect control transfers:
  - `a`: Indexed memory `[base + idx*scale + disp]`.
  - `a_noidx`: Context-table memory `[base + disp]`.
  - `c`: RIP-relative memory `[rip + disp32]`.
  - `d`: Register direct (`jmp/call reg`).
- **Base Provenance Tracking**: Bounded backward linear window scans for RIP-relative LEA or MOV immediate base definitions, with write-invalidation tracking.
- **Bounded Memory**: Processes in 1 MiB overlapping windows and accumulates Space-Saving heavy-hitter histograms with mathematical error bounds.

---

## 6. `expert_initializations_driver.lua` (Sarin EI TRUE-Path Hunter)

Automated symbolic execution driver tailored to solving the `ExpertInitializations` (`0x1405E0EF0`) reachability path to `find = 0x1405E3BBC` (`bl = 1`).

### Invocation
```bash
ANGRY_TARGET=./advisor_unpacked_state.exe \
ANGRY_MEMLOADS_DIR=./memloads/ \
ANGRY_STEPS=20000 \
angryier run ./advisor_unpacked_state.exe --script scripts/lua/expert_initializations_driver.lua
```

### Features
- **Pre-flight Input Validation**: Validates the presence of the analysis image and all six memory tail slices (`tail_1_2142000.bin` through `tail_6_37E9E00.bin`).
- **Gate Crossing Verification**: Automatically detects whether execution crossed the `GdiplusStartup` call (`0x1405E1043`) into continuation `0x1405E1049`.
- **Subsystem Tracking**: Observes whether the bounded wait (`0x140404E10`), wait wrapper (`0x1407C89C0`), constructor (`0x140404B00`), or registration getter (`0x1405E3E90`) were executed.
- **Machine-Readable Verdict**: Emits a single-line summary:
  `VERDICT path=<true_path|status41|incomplete|stalled> found=<n> rax=<v> gdi=<crossed|not_reached> wait=<reached|not_reached>`

---

## 7. `wait_site_prober.lua` (Interactive Singleton & Wait Machinery Prober)

Interactive `angry.open` session prober specifically analyzing the processing singleton get-or-create site (`0x1407C89C0`) and the 5-minute bounded wait (`0x140404E10`).

### Invocation
```bash
ANGRY_TARGET=./advisor_unpacked_state.exe \
ANGRY_MEMLOADS_DIR=./memloads/ \
STEP_BUDGET=4000 \
angryier run ./advisor_unpacked_state.exe --script scripts/lua/wait_site_prober.lua
```

### Features
- **Windows x64 Calling Convention**: Accurately logs parameters across RCX, RDX, R8, and R9 on function entry hooks.
- **Real-Time Singleton Publication Polling**: Reads 8 bytes at slot `0x14221A4E8` after each basic block step, logging the exact step index where the singleton address transitions from NULL to populated.
- **Themida VM Spin Detection**: Tracks visits to the vicinity of the VM tail-transfer site (`0x140760100`), terminating with a `SPIN` verdict when an infinite loop threshold is reached.
- **Dead-State Post-Mortem**: Queries dead states (`s:dead_state()`) for final PC, RAX, and trace tails.

---

## 8. `singleton_wait_solver.lua` (5-Minute Wait State Synthesizer)

Symbolic state solver targeting the 5-minute bounded wait function `0x140404E10(obj, timeout_ms, expected_desc)`.

### Invocation
```bash
ANGRY_TARGET=./advisor_unpacked_state.exe \
ANGRY_MEMLOADS_DIR=./memloads/ \
ANGRY_STEPS=5000 \
angryier run ./advisor_unpacked_state.exe --script scripts/lua/singleton_wait_solver.lua
```

### Features
- **Symbolic Heap Parameterization**: Marks 96 bytes of the singleton object (`0x094464C0 .. 0x09446520`) as symbolic memory.
- **Immediate Return Solving**: Finds state configurations that satisfy internal preconditions to cause `0x140404E10` to return immediately to `0x1407C8A4B` (success) without looping through the 300,000 ms timeout.
- **C-Ready Patch Emission**: Automatically formats solved byte models into C struct definitions (`{ 0x094464c0 + offset, 0x... }`) ready for inclusion into `advisor_unified.c` `g_static` arrays.

---

## 9. `gdi_success_steerer.lua` (Post-GDI+ Path Steerer & Solver)

Symbolic path steerer navigating from GDI+ startup (`0x1405E1044` / `0x1405E1049`) down through subsystem initializations to reach the Gate 4 success target at `0x1405E3BBC` (`mov bl, 1`).

### Invocation
```bash
ANGRY_TARGET=./advisor_unpacked_state.exe \
ANGRY_MEMLOADS_DIR=./memloads/ \
ANGRY_ENTRY=0x1405E1044 \
ANGRY_STEPS=15000 \
angryier run ./advisor_unpacked_state.exe --script scripts/lua/gdi_success_steerer.lua
```

### Features
- **GDI+ Call Stubbing**: Emulates GdiplusStartup at `0x1405E1043` returning 0 (`Ok`) to cleanly resume at continuation `0x1405E1049`.
- **Divergence Detection**: Monitors branch execution to detect any deviation towards the failure block `0x1405E3B82` (`status 41`).
- **Patch Candidate Guidance**: Identifies the exact predecessor branch responsible for deviating from the TRUE path and recommends NOP or branch-inversion patch bytes.


