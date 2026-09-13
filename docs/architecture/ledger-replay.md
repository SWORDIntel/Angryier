# Atomic Execution Ledger and Replay

> **Implementation status:** Partially implemented. `angryier-ledger` (309 lines) provides the atomic ledger contract, epoch model, and rejection classes. `angryier-replay` is scaffolded — no replay capsule storage or verifier is implemented.

---

## Atomic Execution Ledger

The execution ledger is the central replay-consistency boundary.

Replay-visible state includes:

```text
execution state root
code-page versions
block/JIT validity consequences
provenance sequence
semantic ContentId/SemanticVersion references
replay checkpoint
ledger epoch
```

A worker performs private work, then attempts an atomic publication:

```text
snapshot N
    |
    +-- state mutation
    +-- executable-page version mutation
    +-- invalidation consequence
    +-- provenance events
    +-- semantic identity references
    +-- replay checkpoint
    |
  COMMIT
    |
    v
snapshot N+1 visible atomically
```

On failure, none of those fields become visible.

Required conflict classes include:

```text
stale ledger epoch
stale code-page version
semantic version/content mismatch
provenance sequence gap
replay checkpoint mismatch
conflicting concurrent commit
```

The ledger must not devolve into one global mutex. Atomicity is scoped to mutually dependent state/version domains so independent states can progress concurrently.

---

## Deterministic replay capsules

A replay capsule contains enough identity and environment information to reject incompatible replays rather than producing plausible nonsense.

It includes or references:

```text
binary/image hash
input(s)
initial state/import identity
target CPU profile
semantic ContentIds / SemanticVersion
code-page versions or mutation history
environment/model versions
solver policy/options where material
fidelity ledger
scheduler/replay decisions
random seeds
external assumptions
expected checkpoints/findings
```

Deterministic mode fixes or records scheduler decisions, seeds, solver options, event ordering, and other replay-relevant nondeterminism.

Production mode may use nondeterministic scheduling for throughput, but must be able to emit a record sufficient to reproduce important executions.

---

## Self-modifying code and block invalidation

Executable pages are versioned.

A lowered/JIT block carries a validity key containing:

```text
image identity
block/address identity
sealed semantic ContentId
SemanticVersion
TargetProfileId
all referenced CodePageVersion values
```

Writing executable memory increments the affected page version. Blocks referencing the previous version become invalid without requiring a global cache flush.

Invalidation consequences that affect replay-visible execution are published through the same execution-ledger transaction as the code-page change.
