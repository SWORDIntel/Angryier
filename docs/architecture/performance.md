# Performance Architecture

This document describes the performance-oriented design decisions and optimizations
implemented in the Angryier engine. The architecture prioritizes correctness and
explicit fail-closed behavior first, then scales through structural sharing, sharding,
and lock-free reads where the hot path demands it.

## Design Principles

1. **Structural sharing over deep copy.** State fork, memory pages, register maps, and
   constraint lineages use `Arc`-based persistent data structures so fork is O(1).
2. **Shard contended state.** Hot shared structures (expression arena, solver cache) are
   sharded by key prefix to reduce lock contention across worker threads.
3. **Lock-free reads where possible.** The expression arena uses `RwLock` per shard so
   multiple workers can read existing expressions concurrently.
4. **Inline storage for small values.** The concrete interpreter stores all values
   (≤128 bits) in a fixed-size inline buffer, eliminating per-value heap allocations.
5. **Sparse representations.** Memory pages store only written bytes, not dense 4 KiB
   arrays, so sparse address spaces cost only the bytes actually touched.
6. **Cache lowered IR.** The lowering pass caches `IrBlock` results keyed by the sealed
   semantic block's `ContentId`, avoiding redundant re-lowering of identical blocks.

## Expression Arena

`crates/angryier-expr/src/lib.rs`

- **64 shards** keyed by the first byte of the dependency key.
- **`RwLock` per shard** — `get()` and `dependency_summary()` acquire read locks,
  allowing concurrent reads; only `intern()` acquires a write lock.
- **Hash-consing** with `BasicHotCanonicalizer` for commutative operand canonicalization.
- **Constant folding** for `Add/Sub/Mul/And/Or/Xor/Not/Eq/Ite` up to 128 bits.
- **Stable `ExprId`** encoding packs shard index and local index into a `u32`.

## Solver Cache

`crates/angryier-solver/src/lib.rs`

- **16 shards** keyed by `DependencyKey.0[0] % 16`.
- **`Arc<SolverResult>` storage** — `lookup()` returns `Option<Arc<SolverResult>>`,
  so cache hits are a cheap refcount bump instead of cloning the full result.
- **Stable-result admission** — only `Sat` and `Unsat` outcomes are cached;
  `Timeout`, `Unknown`, and `BackendError` are rejected.
- **Canonical identity validation** — tampered query keys fail closed before lookup.

## Memory Model

`crates/angryier-memory/src/lib.rs`

- **Sparse pages** — each `MemoryPage` stores `BTreeMap<usize, u8>` for concrete bytes
  and `BTreeMap<usize, ExprId>` for symbolic bytes. Unwritten offsets return
  `Concrete(0)` without allocation.
- **O(1) fork** — `PersistentMemory::fork()` is `self.clone()`, which clones only
  the `Arc` to the page table.
- **O(log n) region lookup** — `region_containing()` uses a `BTreeMap<u64, usize>`
  index keyed by region base address.
- **Page-segmented multi-byte reads** — `read()` pre-fills the output with zeros,
  then copies only the written bytes from each materialized page via `BTreeMap::range`.

## Concrete Interpreter

`crates/angryier-execution/src/interpreter.rs`

- **Inline value storage** — `ConcreteValue` uses a fixed `[u8; 16]` array plus a
  length byte, so all values up to 128 bits are stored inline with zero heap
  allocations. The struct is ≤ 32 bytes.
- **Reusable value vector** — `execute_block_with_arena()` accepts a caller-provided
  `&mut Vec<ConcreteValue>` that can be cleared and reused across blocks.
- **COW state** — register and memory writes produce new persistent structures via
  `Arc` cloning of unchanged pages/registers.

## IR Lowering

`crates/angryier-ir/src/lower.rs`

- **O(1) value lookup** — `lower_inner` builds a `BTreeMap<ValueId, &SemanticValue>`
  index before the lowering loop, replacing O(n) linear searches.
- **Lowered-block cache** — `CachedSemanticLowerer` wraps `BasicSemanticLowerer`
  with a `Mutex<HashMap<ContentId, Arc<IrBlock>>>` keyed by the sealed block's
  content ID. Cache hits return `Arc::clone`, avoiding redundant re-lowering.

## Remaining Performance Work

The following optimizations are documented in the roadmap but not yet implemented:

- **Lock-free Chase-Lev work-stealing deque** for the scheduler (Phase 5).
- **Per-NUMA-node queues** with OS topology awareness.
- **Native JIT compilation** of hot AngryIR blocks (Phase 8).
- **Per-worker provenance ring buffers** with background flush.
- **Real portfolio router** with query features and per-backend success history.
- **Native Z3/Bitwuzla solver backends** for actual constraint solving.
- **Native XED FFI** for production Intel 64 decode coverage.
