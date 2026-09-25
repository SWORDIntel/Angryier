# Provenance and Telemetry

> **Status superseded (2026-09-24):** see [ROADMAP.md](../ROADMAP.md). The tier schema, trace governor, and per-worker `FlightRecorder` ring are implemented.

> **Implementation status:** Scaffolded. `angryier-provenance` (55 lines), `angryier-telemetry` (32 lines), and `angryier-storage` (28 lines) are contract-only. No flight recorder, trace governor, WAL, or transport is implemented.

---

## Provenance tiers

Provenance is tiered by information value.

```text
Tier 0 -- transient execution detail
    |
    | interesting signal
    v
Tier 1 -- durable structural provenance
    |
    | significance trigger
    v
Tier 2 -- deep flight-recorder trace
    |
    | repetition / high rate / low novelty
    v
Tier 1
```

### Tier 0 — transient execution detail

Worker-local data required for immediate execution but not normally persisted.

Examples:

- current instruction;
- temporary register values;
- ephemeral expression intermediates;
- local block-dispatch detail.

Tier 0 exists for speed.

### Tier 1 — structural provenance

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

### Tier 2 — deep trace

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

## Flight recorder

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

## Trace governor

Tier 2 activation is driven by information value, not raw event volume.

Potential trigger signals:

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

## Structural spam summarization

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

## Post-processing and cleanup

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

### Human-in-the-loop cleanup

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

### Quarantine before purge

Destructive cleanup should support:

```text
ACTIVE -> QUARANTINED -> PURGED
```

The cleanup action itself is stored as Tier 1 provenance.

---

## Retention profiles

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

## Telemetry transport, bounded queues, and WAL

Execution workers emit compact events into bounded priority-aware worker-local or sharded buffers.

Event classes distinguish correctness-critical structural events from lossy/aggregatable telemetry.

When persistence falls behind:

1. aggregate low-value repetitive telemetry;
2. reduce Tier-2 verbosity through the trace governor;
3. spill durable events to a local WAL;
4. expose backpressure metrics;
5. apply profile-specific controlled pressure only if durability requirements demand it.

Correctness-critical Tier-1 events are never silently discarded.

### WAL requirements

The WAL must support:

- checksummed records;
- monotonic local sequence identity;
- crash recovery;
- idempotent downstream ingestion;
- bounded disk policy;
- observable saturation;
- retention/classification metadata;
- separation of durable truth events from disposable metrics.

Hardware I/O capacity is a benchmarked constraint, not an architectural assumption.

---

## Trace compaction and retention

Compaction is semantic first, compression second.

Pipeline:

```text
raw deep trace
    -> canonicalize event identities
    -> deduplicate/repetition summarize
    -> extract causal slices
    -> preserve representative samples
    -> build compact structural trace
    -> binary compression
```

Destructive cleanup occurs only after compact representation validation.

Pinned evidence, semantic discrepancies, compiler/solver-unsoundness evidence, and selected findings may be exempt from automated purge.

Deletion supports ACTIVE -> QUARANTINED -> PURGED lifecycle where policy requires it. Cleanup decisions are themselves provenance.
