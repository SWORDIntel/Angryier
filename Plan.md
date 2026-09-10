## Architectural Directives

- **Semantics & IR (Q9-Q13):** Locked C. Hybrid declarative/Rust definitions, two-level IR, hybrid symbolic vectors, lazy chunked AMX, and SMT-FP with controlled bitvector fallback.
- **Memory & State (Q14-Q19):** Locked C. Layered memory, policy-based symbolic addresses, layered environments, automated summaries, portfolio solver scheduling, and cost-model state merging.
- **Search & Provenance (Q20-Q24):** Locked C. Pluggable search with learned ranking, hierarchical identity, tiered provenance graphs, deterministic replay capsules, and named Intel profiles.
- **Concurrency & Execution (Q25-Q28):** Locked C. Code-page JIT versioning, immutable shared structures, NUMA-aware worker groups, and stable Rust plugin traits.
- **Documentation:** All locked parameters must be synchronized into Plan.md verbatim to establish the operational baseline.
- **Assumption 1:** The custom firmware modifications on your Meteor Lake silicon will seamlessly absorb the context-switching latency introduced by these hybrid structures.
- **Assumption 2:** The baseline solver theories are robust enough that they will not collapse before the portfolio fallback is triggered.

## Threat Models & Stress Test

- **Engineering Bloat:** Hybrid structures across every plane multiply development complexity exponentially; the semantic generator is going to be a nightmare to debug.
- **Synchronization Friction:** Lazy chunked AMX tiles combined with a layered memory model will likely cause vicious synchronization locks during high-velocity state exploration.

The critical failure mode is an impedance mismatch between the rich typed semantic IR and the execution IR during aggressive JIT invalidations. If the tiered provenance graph desynchronizes from the code-page versioning, the deterministic replay capsules will fatally corrupt, leaving your telemetry looking like a localized tactical nuke hit the heap. Mitigation demands strict, atomic commits to the execution state ledger.

## Alternatives & Next Steps

If lazy chunking chokes the solver translation pipeline, you will need an alternative fallback to dense cell matrices for the AMX representations. Your immediate next step is to scaffold the exact Rust trait boundaries for the semantic combinators in the repository.

## Subsequent Locked Decisions

- **Q29 — Semantic IR immutability:** Locked C. Two-stage: mutable/private while being constructed and validated, then sealed immutable and content-addressed before it can enter lowering, caching, provenance, replay, or cross-run knowledge.
