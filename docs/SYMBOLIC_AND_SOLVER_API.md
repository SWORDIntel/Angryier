# Symbolic and Solver API Architecture

This document specifies the SMT solver integration, bitvector formula translation, Windows kernel driver environment modeling, and bidirectional fuzzing exchange protocols in `Angryier`.

---

## 1. SMT Solver Backend Integration

`Angryier` provides a backend-agnostic symbolic constraint architecture (`angryier-solver`) backed by native FFI integrations for **Z3** (`angryier-solver-z3-ffi`) and **Bitwuzla** (`angryier-solver-bitwuzla-ffi`).

### 1.1 Backend Abstraction and Query Model

The solver abstraction enforces strict outcome typing. Solver queries never evaluate through shared mutable globals; each worker thread leases an isolated solver instance.

```rust
pub trait SolverBackend: Send {
    fn check_sat(&mut self, query: &SolverQuery) -> Result<SolverResult, SolverError>;
    fn check_sat_incremental(&mut self, query: &SolverQuery) -> Result<SolverResult, SolverError>;
    fn extract_model(&mut self) -> Result<Model, SolverError>;
    fn interrupt(&mut self);
}
```

#### Outcome Classification (`SolverOutcomeKind`):
- `SAT`: The constraint formula is satisfiable; a concrete model exists.
- `UNSAT`: The constraint formula is provably unsatisfiable under the asserted path prefix.
- `UNKNOWN`: The solver engine could not establish satisfiability (heuristic incompleteness or quantifier threshold).
- `TIMEOUT`: The solve deadline expired before decision.
- `RESOURCE_LIMIT`: Memory or conflict budget was exhausted.
- `BACKEND_ERROR`: Fatal adapter or FFI communication fault.

> **Invariance Rule**: `UNKNOWN`, `TIMEOUT`, `RESOURCE_LIMIT`, and `BACKEND_ERROR` must **never** be promoted to `UNSAT`. Treating a timeout as proof of unreachability is a fatal correctness violation.

---

### 1.2 Z3 Native FFI (`angryier-solver-z3-ffi`)

The Z3 FFI bridge interfaces directly with `libz3` using a stateful, incremental solver architecture:

- **AST Interning Cache (`ast_cache`)**:
  - Maps `ExprId -> Z3_ast` up to a capacity of $2^{20}$ entries (`AST_CACHE_CAP`).
  - Exploits Z3's internal hash-consing within `Z3_context`. Translating an already-seen subtree is an $O(1)$ pointer lookup.
- **Incremental Scoping & Assumption Literals**:
  - Maintains a vector of live scopes (`ScopeEntry { cid, expr, assumption }`).
  - When consecutive symbolic states share a path prefix of constraints, `Z3FfiBridge` preserves shared scopes via `Z3_solver_push` / `Z3_solver_pop`, avoiding redundant re-assertion.
  - Path constraints are guarded by unique boolean tracking literals (`assumption_i -> constraint_i`), enabling minimal UNSAT core extraction when paths conflict.
- **Preemption & Watchdog Deadline**:
  - A dedicated watchdog timer thread monitors each solve call.
  - If a solve exceeds the configured millisecond budget, the watchdog triggers `Z3_interrupt(context)`.

---

### 1.3 Bitwuzla Native FFI (`angryier-solver-bitwuzla-ffi`)

The Bitwuzla FFI bridge targets bit-precise satisfiability using `bitwuzla-sys`:

- **Bitvector Specialization**:
  - Optimized for QF_BV (Quantifier-Free Bitvectors) and QF_ABV (Bitvectors with Arrays).
  - Outperforms Z3 on nonlinear bit-manipulation, shifts, rotations, and cryptographic hashing primitives.
- **Term Management**:
  - Manages terms through `BitwuzlaTermManager` and `BitwuzlaTerm`.
  - Translates integer arithmetic into exact-width bitvector operators:
    - Arithmetic: `BITWUZLA_KIND_BV_ADD`, `BITWUZLA_KIND_BV_SUB`, `BITWUZLA_KIND_BV_MUL`, `BITWUZLA_KIND_BV_UDIV`.
    - Bitwise: `BITWUZLA_KIND_BV_AND`, `BITWUZLA_KIND_BV_OR`, `BITWUZLA_KIND_BV_XOR`, `BITWUZLA_KIND_BV_NOT`.
    - Shifts & Rotates: `BITWUZLA_KIND_BV_SHL`, `BITWUZLA_KIND_BV_SHR`, `BITWUZLA_KIND_BV_ASHR`, `BITWUZLA_KIND_BV_ROL`, `BITWUZLA_KIND_BV_ROR`.
    - Comparisons: `BITWUZLA_KIND_BV_ULT`, `BITWUZLA_KIND_BV_SLT`, `BITWUZLA_KIND_BV_UGE`, `BITWUZLA_KIND_BV_SGE`, `BITWUZLA_KIND_EQUAL`.

---

### 1.4 Bitvector Formula Translation Pipeline

`Angryier`'s intermediate representation (`angryier-expr`) separates mathematical logic from backend-specific AST generation:

```
    [AngryIR Instruction]
              │
              ▼
    [ExprNode / ExprOp]
    (BitVector, Bool sorts)
              │
      ┌───────┴───────┐
      ▼               ▼
[Z3 FFI Bridge]  [Bitwuzla Bridge]
  (Z3_ast)        (BitwuzlaTerm)
```

1. **Sort Preservation**:
   - Every `ExprNode` has an exact `ExprSort`: `ExprSort::BitVector(width)` (where `width` $\in [1, 64]$) or `ExprSort::Bool`.
   - Operations between mismatched sorts are rejected before reaching solver FFI boundaries.
2. **Wrapping Semantics**:
   - Machine registers model wrapping modulo $2^W$. Overflow flags are synthesized as explicit bit extraction expressions on extended bitvectors.
3. **Fail-Closed Constraint Validation**:
   - Every path constraint requires an unbroken dependency chain. If an expression references a missing dependency or unresolved free symbol, translation fails closed and aborts the query.

---

## 2. Windows Kernel Driver State Modeling

To execute driver dispatch routines symbolically without booting a complete operating system, `Angryier` (`crates/angryier/src/driver_ioctl.rs`) implements the POPKORN synthetic kernel memory model.

### 2.1 Synthetic Address Allocations

The execution environment initializes a deterministically mapped virtual address range for synthetic kernel structures:

| Structure | Synthetic Virtual Address | Byte Length | Description |
| :--- | :--- | :--- | :--- |
| `_DRIVER_OBJECT` | `0x444c_0000` (`DRIVER_OBJECT_ADDR`) | `0x200` | Driver object structure |
| `_DEVICE_OBJECT` | `0x444d_0000` (`DEVICE_OBJECT_ADDR`) | `0x100` | Target device object |
| `_DEVICE_EXTENSION`| `0x444e_0000` (`DEVICE_EXTENSION_ADDR`)| `0x200` | Driver-defined device context |
| `BUMP_ALLOC_BASE` | `0x444f_0000` (`BUMP_ALLOC_BASE`) | Unbounded | Heap allocator for driver memory allocations |
| `_IRP` | `0x0133_7000` (`IRP_ADDR`) | `0x200` | I/O Request Packet |
| `_IO_STACK_LOCATION`| `0x0600_0000` (`IRP_STACK_ADDR`) | `0x48` | Current IRP stack location |
| `INPUT_BUFFER` | `0x0700_0000` (`INPUT_BUFFER_ADDR`) | `0x200` | Attacker-controlled symbolic input buffer |

---

### 2.2 Kernel Structure Layout Offsets (`KernelLayout`)

Structure offsets are parameterized for x64 (`KernelLayout::X64`) and x86 (`KernelLayout::X86`):

```rust
pub struct KernelLayout {
    pub pointer_size: usize,
    pub irp_mdl_address: u64,
    pub irp_system_buffer: u64,
    pub irp_current_location: u64,
    pub irp_user_buffer: u64,
    pub irp_current_stack_location: u64,
    pub io_stack_output_buffer_length: u64,
    pub io_stack_input_buffer_length: u64,
    pub io_stack_io_control_code: u64,
    pub io_stack_type3_input_buffer: u64,
    pub io_stack_location_size: u64,
    pub device_object_device_extension: u64,
    pub driver_object_major_function: u64,
    pub driver_object_major_function_count: usize,
}
```

#### Exact Structure Offsets:
- **`_IRP` Layout (x64)**:
  - `+0x08`: `MdlAddress` $\rightarrow$ Points to null or mock MDL.
  - `+0x18`: `AssociatedIrp.SystemBuffer` $\rightarrow$ Points to `INPUT_BUFFER_ADDR` (`METHOD_BUFFERED`).
  - `+0x43`: `CurrentLocation` $\rightarrow$ Stack count index.
  - `+0x70`: `UserBuffer` $\rightarrow$ Points to `INPUT_BUFFER_ADDR` (`METHOD_NEITHER`).
  - `+0xb8`: `Tail.Overlay.CurrentStackLocation` $\rightarrow$ Points to `IRP_STACK_ADDR`.
- **`_IO_STACK_LOCATION` Layout (x64)**:
  - `+0x00`: `MajorFunction` $\rightarrow$ Pinned to `IRP_MJ_DEVICE_CONTROL` (`0x0e`).
  - `+0x08`: `Parameters.DeviceIoControl.OutputBufferLength` $\rightarrow$ Symbolic or bounded integer.
  - `+0x10`: `Parameters.DeviceIoControl.InputBufferLength` $\rightarrow$ Symbolic integer ($\le 0x200$).
  - `+0x18`: `Parameters.DeviceIoControl.IoControlCode` $\rightarrow$ Symbolic 32-bit bitvector or pinned IOCTL.
  - `+0x20`: `Parameters.DeviceIoControl.Type3InputBuffer` $\rightarrow$ Points to `INPUT_BUFFER_ADDR`.
- **`_DRIVER_OBJECT` Layout (x64)**:
  - `+0x70`: `MajorFunction[28]` $\rightarrow$ Array of 28 function pointers. Entry 14 is `IRP_MJ_DEVICE_CONTROL`.
- **`_DEVICE_OBJECT` Layout (x64)**:
  - `+0x40`: `DeviceExtension` $\rightarrow$ Points to `DEVICE_EXTENSION_ADDR`.

---

### 2.3 Initializing the IOCTL Dispatch Harness

To execute a driver dispatch routine:
1. `RCX` is initialized to `DEVICE_OBJECT_ADDR`.
2. `RDX` is initialized to `IRP_ADDR`.
3. Memory at `[IRP_ADDR + 0xb8]` is written with `IRP_STACK_ADDR`.
4. Memory at `[IRP_STACK_ADDR + 0x18]` is populated with the target IOCTL code.
5. The bytes at `INPUT_BUFFER_ADDR` are instantiated as unconstrained symbolic variables ($b_0, b_1, \dots, b_{511}$).
6. Execution starts at `handler_va` with stack pointer `RSP` pointing to a valid synthetic stack.

---

## 3. Targeted Reachability Queries and Input Generation

`Angryier` drives targeted exploration to find paths leading from dispatch handlers to critical sinks.

```rust
let target = DriverIoctlTarget {
    handler_va: 0x0001_4000_1000,
    sink_va: 0x0001_4000_1520,
    ioctl_code: Some(0x0022_2004),
};
let options = target.run_options(max_steps = 5000, max_states = 64)?;
let report = engine.run(&image, &options)?;
```

### 3.1 Path Exploration Algorithm
- **Frontier Management**: States are maintained in a worklist prioritized by static CFG distance to `sink_va`.
- **Branch Exploration**: At each conditional jump, both paths are checked for satisfiability against the SMT solver:
  - If only one edge is feasible, execution proceeds along that edge.
  - If both edges are feasible, the state forks into two children.
  - If an edge cannot be satisfied, it is pruned.
- **Sink Detection**: When a state's program counter reaches `sink_va`, the state is marked as `Found`.

### 3.2 Concrete Trigger Generation
Upon reaching `sink_va`, `Angryier` queries the solver backend to extract a concrete model:
1. **IOCTL Code**: Resolves the exact `IoControlCode` that reaches the branch.
2. **Buffer Lengths**: Resolves `InputBufferLength` and `OutputBufferLength`.
3. **Payload Bytes**: Evaluates all bytes in `INPUT_BUFFER_ADDR`.
4. **Trigger Value Formatting**: Emits concrete byte arrays and trigger values (such as integer overflows `0xFFFFFFFF` or specific magic headers) as reproduction artifacts.

---

## 4. Bidirectional Fuzzing Feedback

`Angryier` couples formal symbolic reasoning with empirical fuzz testing (such as **AFL++**) via `angryier-fuzz`.

### 4.1 Fuzz Integration Stages

The communication protocol defines three progressive stages:
1. `FuzzIntegrationStage::SeedsOnly`: One-way seed submission from solver to fuzzer.
2. `FuzzIntegrationStage::SeedsAndCoverage`: Bidirectional exchange of corpus seeds and edge coverage bitmaps.
3. `FuzzIntegrationStage::Bidirectional`: Full closed-loop feedback with fuzzer constraint hints and symbolic branch inversion.

```
       ┌────────────────────────────────────────────────────────┐
       │                     Angryier (SMT)                     │
       └───────┬────────────────────────────────────────▲───────┘
               │                                        │
    submit_seed(FuzzSeed)                    publish_hint(ConstraintHint)
    [Triggering payloads]                   [Branch comparisons / CRC]
               │                                        │
               ▼                                        │
       ┌────────────────────────────────────────────────┴───────┐
       │                      AFL++ Engine                      │
       └────────────────────────────────────────────────────────┘
```

### 4.2 Feeding Solver Inputs to AFL++

When `Angryier` reaches a target sink or uncovers previously unvisited basic blocks:
1. It packages the extracted SMT model into a `FuzzSeed`:
   ```rust
   pub struct FuzzSeed {
       pub bytes: Vec<u8>,
       pub origin_state: Option<StateId>,
       pub validity: DependencyKey,
   }
   ```
2. The seed is submitted via `FuzzBridge::submit_seed`.
3. AFL++ imports the seed into its active queue, allowing mutational fuzzing to explore the neighborhood around the formally verified path.

### 4.3 Converting Fuzzer Comparisons to Solver Tasks

When AFL++ gets stuck at hard comparison obstacles (e.g., 32-bit CRC checks, magic constants, or complex state guards):
1. Fuzzer instrumentation logs the failing comparison site and input bytes.
2. The fuzzer publishes a `ConstraintHint`:
   ```rust
   pub struct ConstraintHint {
       pub canonical_key: DependencyKey,
       pub target: Option<Address>,
   }
   ```
3. `Angryier` uses the hint to configure a targeted reachability query:
   - Replays execution concolically up to the comparison site.
   - Inverts the branch predicate: $\Phi_{\text{path}} \land \neg \text{Predicate}$.
   - Solves for the exact byte sequence that satisfies the condition.
   - Emits the resulting seed back to AFL++, immediately bypassing the hurdle.
