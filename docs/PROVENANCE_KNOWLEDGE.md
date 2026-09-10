# Angryier Provenance and Knowledge Architecture

## Purpose

Angryier treats provenance and prior analysis as part of the analysis engine, not as optional logging.

The design must answer two different questions:

1. **What happened and why?**
2. **What can be reused safely from previous work?**

QIHSE is the persistent system of record. KEYSTONE is the preferred acceleration layer for ingestion, indexing, and retrieval. Neither is permitted to block the normal execution hot path.

---

# 1. Provenance Tiers

## Tier 0 — transient execution detail

Worker-local data required for immediate execution but not normally persisted.

Examples:

- current instruction;
- temporary register values;
- ephemeral expression intermediates;
- local block-dispatch detail.

Tier 0 exists for speed.

## Tier 1 — structural provenance

Always retained unless an explicit retention policy says otherwise.

Tier 1 includes:

```text
run identity
binary/content identity
state lineage
fork/merge relationships
branch decisions
constraint lineage
taint origins
important source-to-sink edges
coverage novelty
solver query/result identity
fidelity/approximation events
semantic uncertainty/disagreement
finding identity
replay status
cleanup decisions
analyst annotations
```

Tier 1 is designed to reconstruct causal structure without retaining every instruction event.

## Tier 2 — deep trace

Triggered around high-value events.

Potential contents:

- instruction stream slices;
- register deltas;
- memory deltas;
- expression evolution;
- taint propagation detail;
- solver-query construction detail;
- model/constraint snapshots;
- local call/branch history.

Tier 2 is a flight recorder, not a permanent all-instruction logging mode.

---

# 2. Flight Recorder

Every execution worker maintains a bounded circular pre-trigger trace.

```text
[pre-trigger history] -> INTEREST EVENT -> [post-trigger continuation]
```

When triggered:

1. freeze the relevant pre-trigger range;
2. continue capturing a configurable post-trigger range;
3. emit the slice to the provenance pipeline;
4. immediately replace the worker ring so execution continues.

The ring size is a benchmarked configuration parameter rather than a fixed universal constant.

---

# 3. Trace Governor

Tier 2 activation is driven by information value, not raw event volume.

Potential signals:

```text
new coverage
new constraint structure
new taint/source-to-sink relationship
symbolic address
symbolic control transfer
solver timeout/unknown
solver-cost spike
semantic uncertainty
approximation event
crash/exception
finding trigger
target proximity
new behavior fingerprint
analyst bookmark
```

Potential decay signals:

```text
repetition rate
event rate with low novelty
same loop behavior
same memory pattern
same branch outcome
same solver-query family
same taint propagation
bounded storage pressure
```

Use hysteresis so the system does not oscillate rapidly between tiers.

Conceptually:

```text
enter Tier 2 when interest >= HIGH_THRESHOLD
leave Tier 2 only after interest <= LOW_THRESHOLD for a sustained window
```

---

# 4. Structural Spam Summarization

Repeated events are summarized rather than merely dropped.

Example:

```text
RepeatedEvent {
    canonical_event_id,
    count,
    first_timestamp,
    last_timestamp,
    representative_samples,
    participating_state_ids,
    novelty_transitions
}
```

Summarizable classes include:

- repeated loop iterations;
- identical memory accesses;
- repeated branch outcomes;
- equivalent solver queries;
- equivalent taint propagation;
- repeated model calls;
- repeated environment interactions.

A new semantic/constraint/coverage event inside a repetitive region can re-enable Tier 2.

---

# 5. Post-Processing and Cleanup

Cleanup is not direct deletion.

```text
raw/deep trace
    |
    v
canonicalization
    |
deduplication
    |
structural summarization
    |
causal extraction
    |
importance scoring
    |
compact retained representation
    |
optional deletion proposal
```

## Human-in-the-loop cleanup

Ambiguous or high-value cleanup can require analyst approval.

A review record should show:

```text
bytes currently retained
bytes proposed for deletion
what classes of data are being removed
what canonical/summary representation replaces them
findings affected
replay status
estimated information loss
retention-policy reason
```

## Quarantine before purge

Destructive cleanup should support:

```text
ACTIVE -> QUARANTINED -> PURGED
```

The cleanup action itself is stored as Tier 1 provenance.

---

# 6. Retention Profiles

Suggested policies:

```text
forensic    # preserve raw/deep evidence aggressively
research    # retain semantic/solver anomalies and representative deep traces
standard    # adaptive tiering + compaction
benchmark   # preserve enough telemetry for reproducibility, suppress irrelevant deep detail
disposable  # retain Tier 1 + selected findings; aggressive post-run compaction
```

Retention policy never changes the fidelity semantics of a result. It only governs how much evidence is retained.

---

# 7. QIHSE / KEYSTONE Mapping

Suggested storage roles:

| Artifact | Preferred QIHSE/KEYSTONE surface |
|---|---|
| content hashes / exact identities | KV + KEYSTONE |
| run configuration | Document |
| findings | Document |
| state lineage | Graph |
| constraint lineage | Graph |
| taint/dataflow relationships | Graph |
| finding causality | Graph |
| fidelity/approximation relationships | Graph + Document |
| solver/runtime metrics | Time-series |
| coverage progression | Time-series |
| canonical solver facts | KV + graph metadata |
| semantic fingerprints | KV |
| learned similarity representations | Vector / quantum-inspired retrieval layer |
| raw Tier 2 chunks | chunk/archive storage referenced by indexed metadata |

The exact storage mapping may change with measured QIHSE access patterns, but the logical separation should remain.

---

# 8. Analysis Security Context

Every persisted artifact is associated with an analysis context conceptually containing:

```text
run_id
principal
classification
compartment
retention_policy
```

Derived artifacts inherit the source analysis security context unless an authorized policy explicitly changes it.

The persistence bridge must fail closed for protected data when the required authenticated security context is unavailable.

---

# 9. Cumulative Knowledge

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

---

# 10. Authoritative Reuse

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

---

# 11. Generalized Solver Knowledge

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

---

# 12. Advisory Similarity Retrieval

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

# 13. Specialist Encoders + Learned Fusion

The locked design is specialist modality encoders feeding a learned fusion layer.

```text
semantic/AngryIR encoder
CFG/path encoder
constraint-DAG encoder
taint/dataflow encoder
memory/dynamic-behavior encoder
solver-profile encoder
provenance/fidelity encoder
finding/context encoder
analyst/context encoder
        |
        v
masked/gated learned fusion
        |
        v
fused semantic representation
```

Missing modalities are explicitly masked.

All useful modalities may contribute to the learned fusion representation.

---

# 14. Embedding Profiles

Default fused width:

```text
1024 dimensions
```

Allowed profile range:

```text
384 .. 4096 dimensions
```

Potential profiles:

```text
compact-384
standard-1024
rich-2048
experimental-4096
```

Dimension count is selected by benchmarked retrieval quality, memory cost, indexing cost, rerank cost, and downstream utility.

The storage schema must record:

```text
embedding model/version
profile/dimension
artifact type
source validity metadata
training/encoder version
```

---

# 15. Explainable Similarity

Store or derive contribution information so a retrieved match can be explained.

Example:

```text
fused similarity:       0.94
constraint similarity:  0.98
CFG similarity:         0.72
taint similarity:       0.91
behavior similarity:    0.96
provenance similarity:  0.63
```

This supports analyst-facing statements such as:

> The match is driven by near-identical constraint and taint structure, while control-flow topology differs.

The explanation is advisory unless backed by exact semantic checks.

---

# 16. Retrieval-to-Reuse Pipeline

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

# 17. Knowledge Invalidation

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

# 18. Performance Constraints

The knowledge plane must not erase execution-plane gains.

Rules:

- workers emit compact events to bounded local/batched channels;
- no synchronous deep-trace database writes from execution workers;
- backpressure is visible in metrics;
- persistence can degrade gracefully to local buffering/spooling;
- embedding generation is asynchronous/post-processing unless explicitly required online;
- expensive similarity lookup is used only where expected benefit exceeds cost;
- exact hot caches remain worker-local.

---

# 19. Knowledge Metrics

Measure at least:

```text
Tier 1 events emitted
Tier 2 triggers
Tier 2 captured bytes
trace-governor enter/exit count
repetition compression ratio
post-processing compression ratio
persistence queue depth
persistence backpressure time
exact cross-run hits
exact reuse time saved
generalized fact hits
generalized fact revalidation rate
similarity retrieval queries
similarity candidate precision
validated-reuse conversion rate
embedding generation cost
QIHSE/KEYSTONE ingest/query time
cleanup/quarantine/purge volumes
```

The cumulative design succeeds only if reuse and insight gains justify their storage and compute cost.
