# Knowledge Plane: QIHSE, KEYSTONE, and Learned Fusion

> **Status superseded (2026-09-24):** see [ROADMAP.md](../ROADMAP.md). In-memory indexing/retrieval/fusion encoders exist; only real persistence and the QIHSE/KEYSTONE submodules remain future work (Gate E).

> **Implementation status:** Scaffolded. `angryier-knowledge`, `angryier-qihse`, `angryier-keystone`, `angryier-fusion`, and `angryier-storage` are contract-only. No persistence, indexing, embedding, or retrieval is implemented.

---

## QIHSE and KEYSTONE

QIHSE is the persistent system of record. KEYSTONE is the preferred high-speed indexing, ingestion, and retrieval acceleration layer.

Neither is part of the synchronous execution dependency chain.

Suggested storage mapping:

| Artifact | Primary representation |
|---|---|
| exact identities / compatibility keys | KV / KEYSTONE index |
| run config / findings / summaries | Document |
| state/constraint/taint/dependency lineage | Graph |
| solver/runtime/coverage telemetry | Time-series |
| learned semantic similarity | Vector / quantum-inspired retrieval |
| large Tier-2 traces | chunk/archive store referenced by indexed metadata |

### Security context

Persistent events inherit analysis security context such as:

```text
RunId
principal
classification
compartment
retention policy
```

Classification changes require an authorized policy transition; descendants do not silently downgrade.

---

## Cumulative knowledge

Angryier queries prior knowledge before repeating expensive work where appropriate.

Potential reusable knowledge includes:

```text
exact solver results
UNSAT cores
models
constraint implications
branch invariants
function summaries
path feasibility
loop summaries
taint summaries
environment/library summaries
semantic discrepancies
solver routing history
search/scheduler performance history
analyst annotations
```

Knowledge is split into authoritative and advisory classes.

### Authoritative reuse

Authoritative reuse may replace work only when a validity key is satisfied.

Candidate key material includes:

```text
binary/code hash
canonical semantic hash
instruction semantic version
semantics-generator version
target architecture/profile
environment model version
syscall/library model versions
solver and solver version
fidelity profile
relevant engine configuration
assumptions
```

Not every artifact needs every field, but each artifact type must define its own validity contract.

An exact cache hit is not just `hash -> result`; it is:

```text
(validity domain, canonical identity) -> reusable fact
```

### Generalized solver knowledge

Persistent solver knowledge may contain generalized facts:

```text
UNSAT core
alpha-equivalent UNSAT fact
constraint subsumption relationship
implication
incompatible predicate set
branch invariant
query-theory performance profile
```

Each generalized fact records:

```text
origin queries
canonicalization method
semantic/version context
solver/version
proof/revalidation status
fidelity level
last verification time/version
```

PROVE policy may require machine revalidation before a generalized fact suppresses solver work.

### Advisory similarity retrieval

The similarity plane is used to answer:

```text
What have we seen before that looks structurally or behaviorally like this?
```

It may retrieve:

- similar functions;
- similar constraints;
- similar paths;
- similar taint flows;
- similar crashes/findings;
- similar solver difficulty profiles;
- related environment/model patterns.

A similarity result can change prioritization or identify candidates for exact reuse. It cannot itself establish semantic equivalence.

---

## Knowledge identity hierarchy

Cross-run function/artifact identity is hierarchical:

```text
exact code/content hash
        |
normalized IR/semantic hash
        |
SemanticFingerprint
        |
learned embedding similarity
```

Each lower layer increases recall and decreases authority. Exact validation determines whether a candidate may be reused.

---

## Dependency-aware invalidation graph

Knowledge artifacts declare the dependencies that make them valid.

Graph nodes may represent:

```text
semantic versions/content
code objects
constraints
summaries
environment models
solver facts
normalization schemas
target profiles
library/global dependencies
embedding/model versions
```

Edges express validity dependence. A changed dependency invalidates only affected descendants.

The graph must be compact enough for millions of micro-summaries and versioned artifacts. Implementations should favor interned dependency sets, compact IDs, immutable shared dependency descriptors, and batched invalidation rather than pointer-heavy per-edge objects.

### Knowledge invalidation states

Knowledge is not deleted merely because a dependency version changes. It may be marked stale for authoritative reuse while remaining useful for research/advisory comparison.

Example states:

```text
VALID
REVALIDATION_REQUIRED
ADVISORY_ONLY
SUPERSEDED
QUARANTINED
INVALID
```

This preserves historical knowledge while preventing stale facts from silently entering PROVE.

---

## Learned semantic fusion

The default fused embedding is **1024 dimensions**, with schema-supported profiles between 384 and 4096 dimensions when benchmarks justify them.

The system does not feed every raw signal into one undifferentiated encoder.

```text
IR/semantic encoder --------+
CFG/path encoder ------------+
constraint encoder ----------+
taint/dataflow encoder ------+--> masked/gated learned fusion --> 1024-D default
memory behavior encoder -----+
dynamic trace encoder -------+
solver-profile encoder ------+
provenance/fidelity encoder -+
analyst/context encoder -----+
```

Missing modalities are explicitly masked.

### Training objectives

Training may combine:

- contrastive/self-supervised objectives;
- exact-equivalence positive pairs;
- known non-equivalence/near-miss negatives;
- execution-behavior similarity;
- path/taint/constraint relationships;
- analyst feedback;
- cross-run retrieval success/failure.

### Embedding profiles

Default fused width: 1024 dimensions. Allowed profile range: 384..4096 dimensions.

Potential profiles:

```text
compact-384
standard-1024
rich-2048
experimental-4096
```

Dimension count is selected by benchmarked retrieval quality, memory cost, indexing cost, rerank cost, and downstream utility.

### Explainable retrieval

Retrieval returns more than one opaque similarity score. Where practical it exposes:

```text
fused similarity
per-modality contribution/similarity
model/schema version
source artifact identities
exact-validation status
```

Example interpretation:

```text
fusion          0.94
constraints     0.98
behavior        0.96
taint            0.91
CFG              0.71
exact validation: NOT YET PERFORMED
```

A high similarity score never upgrades an artifact into exact truth.

---

## Retrieval-to-reuse pipeline

```text
new artifact
    |
    v
canonical exact lookup
    |
    +--> valid exact hit ---------------------> reuse
    |
    v
specialist encoders
    |
learned fusion
    |
QIHSE/KEYSTONE similarity retrieval
    |
candidate prior artifacts
    |
exact structural/validity checks
    |
    +--> validated equivalence/general fact -> reuse
    |
    +--> not exact but useful ---------------> scheduler/analyst advisory
```

This separation is non-negotiable.

---

## Performance constraints

The knowledge plane must not erase execution-plane gains.

Rules:

- workers emit compact events to bounded local/batched channels;
- no synchronous deep-trace database writes from execution workers;
- backpressure is visible in metrics;
- persistence can degrade gracefully to local buffering/spooling;
- embedding generation is asynchronous/post-processing unless explicitly required online;
- expensive similarity lookup is used only where expected benefit exceeds cost;
- exact hot caches remain worker-local.
