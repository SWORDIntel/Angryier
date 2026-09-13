# Execution Plane: Memory, State, and Expressions

> **Implementation status:** Implemented. `angryier-memory` (539 lines), `angryier-state` (495 lines), and `angryier-expr` (701 lines) have real implementations. `angryier-execution` has a concrete interpreter (803 lines). `angryier-taint` is scaffolded only.

---

## Runtime value model

Values optimize for the common concrete case.

Conceptually:

```text
Concrete(value)
ConcreteTainted(value, TaintId)
Symbolic(ExprId)
StructuredSymbolic(ObjectId)
```

Data does not become symbolic merely because it is interesting. Cheap taint/dataflow propagation tracks influence first. Promotion occurs when:

- a branch requires symbolic feasibility;
- symbolic output is requested;
- an address requires symbolic reasoning;
- a summary/model requires symbolic form;
- an analyst explicitly requests it.

This concrete -> taint -> symbolic promotion policy is fundamental to the performance model.

---

## Expression DAG

> **Implementation status:** Implemented. `angryier-expr` provides arena-allocated `ExprId`, structural hashing/hash-consing, constant folding, and expression statistics (701 lines).

Symbolic expressions are immutable, interned, arena-backed objects referenced by compact `ExprId` values.

The expression subsystem provides:

- hash-consing;
- structural hashing;
- constant folding;
- width/type-aware simplification;
- deterministic canonical serialization;
- dependency summaries;
- depth/node metrics;
- theory-shape metadata;
- worker-local hot caches;
- stable fingerprints for persistent lookup.

### Layered canonicalization

Canonicalization is split into two costs:

**Hot-path canonicalization**

- cheap;
- deterministic;
- bounded;
- designed to improve local cache hit rates without dominating execution.

**Deep/offline canonicalization**

- more expensive;
- may perform alpha-normalization, structural rewriting, implication/subsumption preparation, and persistent reuse preparation;
- runs outside the latency-critical worker path.

A cache miss must not synchronously force the full deep normalization pipeline onto an execution worker.

---

## Layered memory model

> **Implementation status:** Implemented. `angryier-memory` provides layered COW memory with concrete backing, byte values, and symbolic overlay contracts (539 lines).

Memory combines concrete efficiency with symbolic precision.

```text
Virtual address space
        |
        +-- mapped regions / permissions / provenance
        |
        +-- concrete page backing
        |
        +-- COW page ownership/versioning
        |
        +-- taint bitmap/metadata
        |
        +-- sparse symbolic overlay
        |
        +-- structured vector/tile metadata where profitable
        |
        +-- symbolic-address resolution slow path
```

One symbolic byte must not convert an entire concrete page into symbolic AST objects.

### Fork behavior

Forking is close to O(1) in unchanged state size:

- immutable page roots are shared;
- modified pages use COW;
- symbolic overlays share persistent structure;
- register/path roots share immutable nodes;
- child state records lineage rather than duplicating history.

### Symbolic addresses

Address resolution is policy-based:

- range/alias reasoning first;
- bounded enumeration where appropriate;
- target/object metadata where available;
- profile-dependent concretization only when allowed;
- every concretization is fidelity/provenance-visible.

PROVE cannot silently choose one address from multiple feasible targets.

---

## Persistent State

> **Implementation status:** Implemented. `angryier-state` provides persistent state roots, register state, fork primitive, ownership transfer, constraint lineage, and fidelity ledger (495 lines).

A state contains or references:

```text
StateId
PC / architecture register root
Memory root
Constraint lineage/root
Taint/dataflow root
FidelityLedger
Environment/model context
TargetProfile
Code-page view
Replay/ledger epoch
Scheduler affinity metadata
State lineage metadata
```

State is conceptually immutable between publication epochs. A worker may build a private mutation, but visibility is controlled by the execution ledger.

---

## Fidelity profiles

All profiles use the same semantic engine.

### PROVE

- exact semantics only;
- no silent unsupported behavior;
- no silent concretization;
- generalized prior knowledge validated to policy requirements;
- UNKNOWN/TIMEOUT are preserved as uncertainty;
- insufficiently evidenced transformations are rejected.

### EXPLORE

- conservative approximations allowed with explicit provenance;
- seeks coverage/time-to-solution while preserving analysis debt;
- findings can be upgraded through exact replay/re-analysis.

### HUNT

- aggressive concretization/approximation policies allowed;
- optimized for discovery and reachability;
- approximate findings are never presented as proof.

### Analysis debt

Findings inherit categorical fidelity events such as:

```text
MODELLED
SUMMARY
CONCRETIZED
ASSUMED
UNSUPPORTED
TIMEOUT
```

Avoid fake precision such as arbitrary "92% exact" scores unless a rigorously justified metric is later defined.

---

## Environment and state-import architecture

> **Implementation status:** Scaffolded. `angryier-loader` and `angryier-models` are contract-only.

Execution entry is unified through one import abstraction rather than special-casing every source.

Supported directions include:

```text
static binary image
saved snapshot
Angryier checkpoint
core/process capture
live-process capture
```

All imports produce the same validated internal state form plus provenance describing what was known, synthesized, modeled, or unavailable.

### Environment models

Environment interaction is layered:

1. deterministic syscall/library summaries where available;
2. validated reusable function summaries;
3. controlled concrete passthrough/sandbox execution where safe and policy-permitted;
4. symbolic fallback/modeling where required.

Model identity/version is part of summary/cache/replay validity.

---

## Function and path summaries

> **Implementation status:** Scaffolded.

Summaries are cumulative acceleration artifacts.

Two classes exist:

- **exact/validated summaries** suitable for PROVE when all dependencies match;
- **approximate summaries** available to EXPLORE/HUNT with explicit fidelity effects.

Summary validity keys include at least, where relevant:

```text
code/canonical semantic identity
semantic version
calling convention / ABI
target profile
referenced global identities
memory/environment assumptions
environment-model version
summary schema/version
fidelity class
```

Dependency-aware invalidation invalidates only affected summaries rather than flushing an entire knowledge generation.

---

## State merging

> **Implementation status:** Scaffolded.

State merging is opt-in and cost-model driven.

The merge score can include:

```text
expression/AST growth
memory delta size
constraint divergence
solver-history cost
path divergence
future reuse likelihood
code locality
NUMA locality
solver-context affinity
```

Matching program counters are insufficient justification by themselves. The merge system must be able to decide that keeping two states separate is cheaper and clearer.
