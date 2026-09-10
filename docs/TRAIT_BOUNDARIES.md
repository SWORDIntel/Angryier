# Angryier Trait Boundaries

This document defines the first concrete Rust interface boundaries implied by `Plan.md` and the locked architecture. It is intentionally a contract document, not an implementation plan for instruction semantics.

## Purpose

The primary failure mode being prevented is semantic/execution/provenance desynchronization during code-page mutation and JIT invalidation.

The architecture therefore enforces five separations:

1. **Decode is not semantics.** Intel XED-specific objects terminate at the decoder adapter boundary.
2. **Construction is not publication.** Rich semantic blocks may be mutable only while private to construction/normalization/validation.
3. **Rich semantics are not execution IR.** Semantic providers emit into a typed semantic builder; only a dedicated lowerer may create compact execution IR.
4. **Execution IR validity is versioned.** Every lowered block carries semantic-version, target-profile, content-identity, and code-page version guards.
5. **State, JIT validity, provenance, and replay publication are atomic.** They advance under one execution-ledger epoch or not at all.

The initial interfaces live in `crates/angryier-semantics/src/lib.rs`.

---

## Semantic Provider Hierarchy

All instruction semantics satisfy one common contract:

```text
SemanticProvider
├── GeneratedSemanticFamily
├── RustSemanticCombinator
└── SemanticOverride
```

This implements the locked hybrid design:

- regular instruction families may be produced from declarative definitions;
- non-trivial reusable behavior may be expressed through strongly typed Rust combinators;
- exceptional instructions may use explicit handwritten overrides.

The registry must resolve a decoded form to exactly one authoritative provider. Provider registration order is never semantic priority. Ambiguous resolution is an error.

### Why this matters

The semantic generator is allowed to be wrong during development. It is **not** allowed to silently shadow a handwritten override or produce nondeterministic provider selection.

Every successful semantic emission returns a `SemanticReceipt` containing:

- semantic rule ID;
- semantic origin;
- semantic version.

That receipt is part of the truth/provenance chain.

---

## Decoder Boundary

`DecodedInstructionView` is deliberately narrow.

The semantic layer may observe normalized information such as:

```text
address
form ID
length
feature IDs
operand descriptors
```

It may not depend on XED-owned pointers, opaque decoder state, or decoder-specific lifetimes.

This permits:

- XED replacement or differential decoder testing;
- deterministic serialization of decoded forms;
- semantic generation without linking the execution core directly to decoder internals;
- fuzzing the semantic layer with synthetic decoded forms.

---

## Rich Semantic Builder

Semantic definitions emit to `SemanticBuilder`.

The builder exposes typed operations for:

- constants;
- register and operand reads;
- typed primitive operations;
- floating-point operations;
- vector operations;
- tile operations;
- register/operand writes;
- explicit architectural side effects.

It does **not** expose JIT handles, machine code, executor state objects, solver ASTs, or database handles.

This is the central impedance barrier between the truth plane and execution plane.

---

# Semantic Block Lifecycle

Rich semantic blocks use a two-stage lifecycle.

```text
PRIVATE / MUTABLE
    |
    +-- construct
    +-- normalize
    +-- optimize
    +-- validate
    |
    v
SEAL
    |
    +-- canonical serialization
    +-- content digest
    +-- semantic version binding
    +-- provenance receipt
    |
    v
PUBLIC / IMMUTABLE / CONTENT-ADDRESSED
    |
    +-- lowering
    +-- cache insertion
    +-- JIT validity keys
    +-- provenance references
    +-- replay capsules
    +-- cross-run knowledge
```

A semantic block must not be observable by the execution, replay, or knowledge planes before sealing succeeds.

After sealing, in-place mutation is forbidden. Any transformation produces a new semantic block with:

- a new content identity;
- an explicit derivation link to the parent block;
- its own validation result;
- its own semantic receipt.

This prevents published semantics from changing underneath cached execution IR, JIT blocks, or replay capsules.

The seal operation is therefore the semantic equivalent of a commit boundary.

---

## Typed Domains

The initial contract recognizes:

```text
Scalar(BitVec / Float)
Vector
Opmask
Tile
```

Locked representation policies are represented explicitly:

```text
VectorRepresentation::HybridLazy
TileRepresentation::LazyChunked
TileRepresentation::DenseCellFallback
FloatingPointPolicy::SmtFpPreferred
FloatingPointPolicy::ControlledBitVectorFallback
```

### AMX fallback

`LazyChunked` is the preferred AMX symbolic representation.

If profiling shows pathological solver translation or synchronization behavior, the system may choose `DenseCellFallback` for a block/state/profile without changing architectural semantics. The chosen representation must be recorded in provenance and benchmark telemetry.

The fallback is therefore a policy transition, not a semantic approximation.

---

## Two-Level IR Boundary

The rich semantic IR and compact execution IR are separate layers.

```text
Decoded instruction
      |
      v
SemanticProvider
      |
      v
SemanticBuilder
      |
      v
Private rich semantic IR
      |
  normalize/validate
      |
      v
Sealed semantic block
      |
      v
SemanticLowerer
      |
      v
Compact execution IR / JIT candidate
```

`SemanticLowerer` accepts only sealed semantic blocks and receives a `BlockValidityKey` containing:

- image identity;
- block identity/address;
- sealed semantic content identity;
- semantic version;
- target CPU profile;
- all relevant code-page versions.

A block lowered under one validity key must never be reused under another merely because its virtual address matches.

---

# Atomic Execution State Ledger

The execution ledger is the mandatory publication boundary for operations that affect deterministic replay.

The relevant state is conceptually:

```text
ExecutionState
CodePageVersions
JIT/BlockValidity
ProvenanceSequence
ReplayCheckpoint
SemanticVersion
SemanticContentIdentity
```

These values must not become visible independently.

## Commit invariant

A successful ledger commit publishes one new epoch containing the complete mutation.

```text
begin(snapshot N)
    |
    +-- state mutation
    +-- code-page version change
    +-- JIT invalidation consequence
    +-- provenance events
    +-- replay checkpoint
    +-- sealed semantic identity references
    |
commit
    |
    v
snapshot N+1 becomes visible atomically
```

On failure:

```text
NO state publication
NO code-version publication
NO provenance advancement
NO replay-checkpoint publication
NO semantic-reference publication
```

This is stronger than merely writing the same timestamp into separate logs.

## Required rejection conditions

The initial ledger contract explicitly models rejection for:

- stale execution epoch;
- stale code-page version;
- semantic-version mismatch;
- semantic-content mismatch;
- provenance sequence gap;
- replay-checkpoint mismatch;
- conflicting concurrent commit.

Additional conditions may be added, but these may not be weakened.

---

## JIT and Self-Modifying Code

JIT/block-cache validity is guarded by `BlockValidityKey` and checked through `BlockValidityOracle`.

A JIT block is valid only if all of the following still match:

```text
image identity
block identity/address
sealed semantic content identity
semantic version
target profile
code-page versions
```

A write to executable memory increments the affected page version. Any block whose guard references the old version becomes invalid without requiring a global flush.

The resulting invalidation and the execution-state/provenance consequences must be published in the same ledger epoch when they affect replay-visible execution.

---

# Concurrency Rules

The locked concurrency model remains:

```text
immutable shared structures
+ worker-local mutable caches
+ NUMA-local worker groups
+ locality-aware work stealing
```

The semantic contracts are `Send + Sync`, but this does **not** imply that semantic evaluation should take shared locks.

Expected implementation pattern:

```text
read-only semantic registry         shared
sealed semantic blocks              shared immutable
semantic definition tables          shared immutable
construction builders               worker/private mutable
expression/semantic arenas          persistent or partitioned
worker hot caches                    worker-local
solver contexts                      worker-local
trace rings                          worker-local
state mutation                       owned by executing worker
ledger publication                   atomic serialized boundary per conflicting state/version domain
```

The ledger must not become a single global mutex for all states. Atomicity is required only across mutually dependent publication fields; independent states/pages should remain independently committable wherever correctness permits.

---

# Assumptions Are Not Invariants

`Plan.md` records two explicit assumptions verbatim. They are treated as stress-test hypotheses rather than architectural guarantees.

## Firmware/context-switch assumption

Correctness and acceptable scaling must not depend on custom firmware eliminating context-switch or cache-migration costs.

Benchmarking must separately expose:

```text
worker migrations
NUMA migrations
context-switch pressure
cache-locality loss
ledger conflict rate
state steal rate
```

## Solver robustness assumption

Portfolio fallback must be triggered by explicit solver policy and measured behavior, not by waiting for catastrophic failure.

The engine must distinguish:

```text
SAT
UNSAT
UNKNOWN
TIMEOUT
RESOURCE_LIMIT
BACKEND_ERROR
```

and may route or cross-check before a backend becomes pathological.

---

# Required Tests Before Implementing Broad Semantics

The trait layer is not considered stable until the following architecture tests exist:

1. A synthetic decoder can feed a semantic provider without XED linked.
2. Generated and handwritten providers cannot ambiguously resolve the same form.
3. A private rich semantic block cannot enter lowering/cache/provenance before sealing.
4. Sealing the same canonical semantic block twice yields the same persistent content identity.
5. Any post-seal transformation yields a distinct immutable object rather than mutating the original.
6. Rich semantic IR can be lowered under a version key and rejected after a code-page version change.
7. A failed ledger commit leaves state/provenance/replay visibility unchanged.
8. Two independent state commits can proceed without a global execution lock.
9. A JIT block referencing multiple code pages is invalidated if any referenced page version changes.
10. Lazy-chunked and dense-cell AMX representations produce equivalent concrete/solver-visible semantics on the same tests.
11. SMT-FP and controlled bitvector fallback agree on the designated cross-check corpus where both are applicable.
12. Deterministic replay rejects capsules whose semantic content, semantic version, or code-page validity keys do not match.
13. Provenance sequence gaps are detected rather than silently repaired.

---

# Current Scaffold Status

Implemented as interface scaffold only:

- workspace `Cargo.toml`;
- `angryier-semantics` crate;
- typed semantic domains and representation policies;
- decoder-view boundary;
- semantic builder;
- generated/combinator/override provider hierarchy;
- deterministic registry contract;
- rich-to-execution lowering boundary;
- code-page/block validity keys;
- atomic execution-ledger contract;
- JIT block validity oracle;
- stress-probe interface.

Architecturally locked, but not yet implemented in the Rust scaffold:

- private mutable semantic construction state;
- semantic sealing API;
- canonical semantic serialization;
- persistent semantic content identity;
- derivation/provenance linkage between transformed sealed blocks.

Not implemented yet:

- XED adapter;
- semantic IR storage;
- Intel instruction semantics;
- semantic generator;
- execution IR;
- solver adapters;
- concrete/symbolic executor;
- ledger backend;
- JIT;
- provenance transport;
- QIHSE/KEYSTONE bridge.

This is intentional. The present purpose is to freeze boundaries before implementation pressure makes them expensive to change.
