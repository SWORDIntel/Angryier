# Angryier Architecture

## Objective

Angryier is a native, parallel binary symbolic/concolic execution and program-analysis engine whose design target is not merely lower runtime than Python-heavy engines. It must improve three things simultaneously:

1. **Speed** — reduce execution, state, solver-orchestration, and scheduling overhead while scaling across physical cores.
2. **Correctness** — make semantic fidelity, approximation, solver uncertainty, and replay status explicit rather than silently conflating them.
3. **Insight** — preserve enough causal and structural provenance to explain why a path, branch, finding, solver result, or approximation exists, and accumulate reusable knowledge across runs.

Angryier is not an angr rewrite and does not target angr API compatibility.

The core rules are:

> Do not symbolically interpret work that can remain concrete.  
> Do not copy state that can be shared.  
> Do not serialize work that can execute independently.  
> Do not persist telemetry synchronously on the execution hot path.  
> Do not treat similarity as proof.  
> Do not claim semantic support that has not passed the declared validation gates.

## Locked Architectural Decisions

| Area | Decision |
|---|---|
| Core language | Rust |
| Core architecture | ISA-neutral traits; first production backend is **Intel 64** |
| AMD scope | AMD CPUs and AMD-specific extensions are not a validation target for the Intel 64 backend |
| Binary formats | ELF64 and PE32+ first |
| Decode | Intel XED for Intel 64 decode and feature/form classification |
| Host/target relationship | Target semantics are independent of host feature availability; native acceleration is optional and guarded |
| Semantics | Hybrid: representative handwritten corpus first, then generated normal semantics plus specialized handwritten overrides |
| Internal semantics | Canonical typed semantic representation before execution lowering |
| Execution model | Concrete + taint + concolic + symbolic |
| Runtime values | Bitvectors, floating point, vectors, opmasks, and tiles are first-class domains |
| Parallelism | Native worker pool with locality-aware work stealing |
| State model | Copy-on-write / persistent |
| Expression model | Arena allocated, interned DAG using compact IDs |
| Solver model | Per-worker incremental contexts plus persistent cross-run solver knowledge |
| Solvers | Z3 and Bitwuzla are first-class backends behind a common interface |
| Fidelity modes | **PROVE / EXPLORE / HUNT** with mandatory fidelity provenance |
| Provenance | Adaptive tiered provenance with structural Tier 1 and event-triggered Tier 2 flight-recorder traces |
| Persistence | QIHSE as system of record; KEYSTONE as high-speed indexing/ingestion/retrieval layer |
| Cross-run behavior | Cumulative knowledge reuse with exact validity keys and advisory similarity retrieval |
| Semantic retrieval | Specialist encoders + learned fusion; default 1024-D, profile range 384–4096 |
| JIT | Deferred until profiling proves concrete execution remains material |
| Python | Optional bindings only; never in the execution hot path |
| Distributed execution | Deferred until single-host multicore design proves itself |

The authoritative decision log is maintained in `DESIGN_DECISIONS.md`.

---

# Three-Plane Architecture

Angryier is split into three cooperating planes.

```text
                         ANGRYIER
                            |
          +-----------------+-----------------+
          |                 |                 |
          v                 v                 v
   EXECUTION PLANE      TRUTH PLANE      KNOWLEDGE PLANE

 concrete/taint        semantics model      QIHSE
 symbolic engine       validation           KEYSTONE
 COW state             fidelity ledger      graph lineage
 worker solvers        replay               exact reuse
 scheduler             support manifest     vector retrieval
 JIT/native fast path  differential tests   analyst knowledge
```

## Execution Plane

The execution plane owns the hot path:

- binary loading and mappings;
- Intel 64 decode;
- concrete, taint, concolic, and symbolic execution;
- expression construction;
- memory/state management;
- branch feasibility;
- solver interaction;
- state scheduling;
- local caches;
- optional native/JIT acceleration.

It must continue to function if QIHSE/KEYSTONE persistence is disabled or temporarily unavailable. Persistence is fed through bounded asynchronous/batched event channels rather than synchronous database calls from execution workers.

## Truth Plane

The truth plane establishes whether Angryier's answers are trustworthy:

- instruction semantic definitions;
- semantic generator and generator version;
- typed semantic IR validation;
- differential testing against hardware/reference implementations;
- fidelity and approximation ledger;
- solver outcome classification;
- target-feature assumptions;
- replay results;
- semantic coverage/support manifest.

A feature is not considered supported merely because XED can decode it.

## Knowledge Plane

The knowledge plane converts completed and in-progress analysis into cumulative reusable knowledge:

- exact canonical artifacts;
- state and constraint lineage;
- SAT/UNSAT results and models;
- generalized solver facts and UNSAT cores;
- historical solver performance;
- provenance/fidelity events;
- semantic discrepancies;
- path/function/constraint fingerprints;
- learned fused embeddings;
- analyst annotations and cleanup decisions;
- prior-run retrieval.

Similarity can propose candidates. Exact validation decides whether a previous result is reusable.

---

# Workspace Boundaries

The repository should converge on this layout:

```text
crates/
  angryier-cli/             # command-line frontend
  angryier-core/            # engine orchestration and public core traits
  angryier-loader/          # ELF64/PE32+ loading, relocations, mappings
  angryier-ir/              # compact execution IR (AngryIR)
  angryier-semantics/       # canonical typed semantic representation
  angryier-semantics-gen/   # semantics compiler/generator
  angryier-arch/            # ISA-neutral architecture traits
  angryier-arch-intel64/    # Intel 64 register/state/feature model
  angryier-decode-xed/      # XED FFI and decoded-form normalization
  angryier-exec/            # concrete/concolic/symbolic execution
  angryier-state/           # state, register files, constraints, lineage
  angryier-expr/            # symbolic expression DAG and simplifier
  angryier-memory/          # COW pages and symbolic overlays
  angryier-taint/           # cheap taint/dataflow domain
  angryier-solver/          # solver trait, query model, persistent fact schema
  angryier-solver-z3/       # Z3 backend
  angryier-solver-bitwuzla/ # Bitwuzla backend
  angryier-scheduler/       # worker pool, locality-aware work stealing
  angryier-provenance/      # fidelity ledger, trace governor, event schema
  angryier-knowledge/       # exact/advisory reuse and validity checks
  angryier-keystone/        # KEYSTONE ingestion/index bridge
  angryier-qihse/           # QIHSE storage/retrieval bridge
  angryier-models/          # syscall/libc/environment summaries
  angryier-bench/           # correctness/performance benchmark harness
  angryier-python/          # optional pyo3 API; never required by core
```

Dependency direction must remain acyclic. Database/storage adapters depend on stable engine event/data interfaces; the executor must not depend on QIHSE implementation details.

---

# Architecture Interface

The engine core is architecture-independent even though Intel 64 is the first production backend.

```rust
pub trait Architecture {
    type RegId;
    type Feature;

    fn decode(&self, pc: u64, bytes: &[u8]) -> Result<DecodedInstruction, DecodeError>;
    fn lower_semantics(
        &self,
        insn: &DecodedInstruction,
        out: &mut SemanticBuilder,
    ) -> Result<(), SemanticError>;
    fn initial_state(&self, profile: &TargetProfile) -> ArchState;
    fn target_features(&self, profile: &TargetProfile) -> FeatureSet<Self::Feature>;
}
```

Host and target capabilities are separate objects:

```text
HostFeatures   = what the analysis machine can execute natively
TargetFeatures = what the analyzed program is allowed/expected to use
```

Host feature absence must never make target semantics unavailable.

---

# Intel 64 Backend

The Intel 64 backend targets modern Intel instruction families, including:

```text
scalar Intel 64
SSE / SSE2 / SSE3 / SSSE3 / SSE4.x
AES-NI / SHA / BMI-class extensions
AVX
AVX2
AVX-512
AVX-VNNI
AVX10
AMX
CET
APX
future Intel extensions after validation
```

XED supplies decode/form/feature metadata. XED is **not** treated as an execution-semantics source.

AMD-specific CPU behavior, AMD SVM, AMD-specific MSRs, and AMD-only extension semantics are outside the Intel 64 validation target.

---

# Semantic Pipeline

The semantic pipeline is deliberately separated from decode and execution:

```text
Intel XED decoded form
        +
Angryier semantic definitions
        +
handwritten semantic overrides
        |
        v
Semantic compiler / generator
        |
        v
Canonical typed semantic representation
        |
        +--> AngryIR lowering
        +--> concrete evaluator
        +--> taint semantics
        +--> differential-test generation
        +--> support/coverage manifest
```

The generator is **not** the first milestone. A representative handwritten semantic corpus must first stabilize the semantic and execution IRs. Repetitive patterns are then migrated into declarative/generated semantics. Complex instruction families remain eligible for handwritten overrides.

Generated output must be deterministic, readable, versioned, and CI-regenerable.

See `SEMANTICS.md`.

---

# Typed Runtime and Symbolic Domains

Do not flatten every architectural object immediately into one monolithic solver bitvector.

The runtime should recognize at least:

```text
BitVec(bits)
Float(format)
Vector { lane_count, lane_type }
Opmask { lanes }
Tile { rows, cols, element/layout metadata }
```

AVX-512 masking, merge-vs-zero behavior, broadcasts, upper-lane behavior, embedded rounding/SAE, and mask registers are explicit semantics.

AMX TMM state and TILECFG are explicit architectural state. Tile data should support lazy/sparse symbolic materialization so one symbolic element does not automatically explode an entire tile into SMT nodes.

Vectors should support lane-aware representation and lazy pack/unpack to bitvectors when a solver/backend requires packed semantics.

---

# AngryIR

AngryIR is the compact execution representation consumed by the concrete, taint, concolic, and symbolic engines. It is downstream of the richer canonical semantic representation.

Requirements:

- SSA-like temporaries within a basic block;
- explicit register reads/writes;
- explicit memory loads/stores;
- explicit widths and endianness;
- typed scalar/vector/mask/tile operations where preserving structure benefits correctness or performance;
- explicit branches and targets;
- no heap allocation per operand in the normal hot path;
- compact IDs or inline immediates;
- cached blocks keyed by image/address/code identity and semantic version.

---

# Value Domain

Runtime values optimize the concrete case:

```text
Concrete(value)
ConcreteTainted(value, taint_id)
Symbolic(expr_id)
StructuredSymbolic(object_id)
```

A value should not become symbolic solely because it originated from interesting input. Cheap taint/dataflow propagation determines whether symbolic promotion is required.

Promotion occurs when path reasoning, symbolic output, symbolic addressing, or an explicitly requested observation requires it.

---

# Expression Engine

Symbolic expressions are immutable and referenced through compact `ExprId` values.

Required properties:

- arena allocation;
- structural hashing/hash-consing;
- constant folding;
- canonicalization where sound;
- width/type-aware simplification;
- dependency metadata;
- cheap depth/node accounting;
- solver-independent canonical serialization;
- worker-local hot caches;
- stable fingerprints for persistent knowledge lookup.

Canonicalization must preserve enough structure to support exact validity checks, alpha-equivalence analysis, constraint subsumption experiments, and cross-run solver reuse.

---

# State and Memory

A state consists conceptually of:

```rust
pub struct State {
    pub pc: u64,
    pub regs: RegisterFile,
    pub memory: Memory,
    pub constraints: ConstraintSet,
    pub fidelity: FidelityLedger,
    pub metadata: StateMetadata,
}
```

Forking must be close to O(1) in unchanged state size.

Memory is page based with:

- concrete backing;
- symbolic/taint bitmap;
- sparse symbolic overlay;
- permissions;
- copy-on-write ownership metadata;
- optional structured vector/tile cells where profitable.

One symbolic byte must not convert an otherwise concrete page into thousands of symbolic objects.

---

# Solver Architecture

Solver state has two levels.

## Level 1 — worker-local hot state

Each worker owns or leases its own incremental solver contexts and local query caches. No global solver mutex may appear on the normal query path.

## Level 2 — persistent solver knowledge

QIHSE/KEYSTONE stores reusable exact and generalized knowledge:

```text
canonical query fingerprint
SAT / UNSAT / UNKNOWN
model
UNSAT core
constraint ancestry
alpha-equivalence metadata
generalized implication/subsumption fact
solver/version
theory profile
solver timing
semantic/model validity key
proof/revalidation metadata
```

Persistent knowledge can short-circuit work only after the relevant validity rules are satisfied. PROVE may require revalidation for generalized or externally generated facts.

The query API should support **shared-context batched satisfiability**, not just one isolated expression at a time, because sibling states often share most of their path context.

Z3 and Bitwuzla remain isolated behind the solver trait; backend AST types never leak into execution state.

---

# Scheduler

V1 uses a native worker pool with local deques and work stealing.

Stealing must consider locality rather than only queue depth. A state may carry valuable affinity to:

- an incremental solver context;
- expression caches;
- block/code caches;
- COW memory locality;
- NUMA node;
- constraint ancestry.

Conceptually:

```text
steal benefit = load-balancing gain
              - solver rebuild cost
              - cache locality loss
              - NUMA migration cost
```

A deterministic single-thread mode is mandatory for debugging and differential testing.

---

# Fidelity Profiles

Every state carries a fidelity ledger. Three policy profiles are locked:

## PROVE

- exact semantics only;
- unsupported/unknown semantics terminate or explicitly suspend the state;
- no silent concretization;
- generalized prior knowledge is verified according to policy;
- results distinguish SAT, UNSAT, UNKNOWN, modeled, and replayed states.

## EXPLORE

- conservative approximations permitted when explicitly recorded;
- prioritizes coverage/time-to-solution while retaining causal provenance;
- findings can be upgraded by exact re-analysis/replay.

## HUNT

- aggressive but explicit concretization/approximation policies permitted;
- optimized for bug discovery and broad exploration;
- no approximate result is presented as proof.

Every finding inherits the complete fidelity lineage that made it possible.

---

# Adaptive Tiered Provenance

Provenance is governed by information value, not a fixed global verbosity level.

```text
Tier 0 — transient hot execution data
Tier 1 — always-retained structural provenance
Tier 2 — deep instruction/register/memory/expression trace around interesting events
```

Tier 1 includes at least:

- state lineage;
- branches and outcomes;
- constraint lineage;
- taint origins and important source-to-sink relationships;
- solver decisions;
- approximation/fidelity events;
- coverage novelty;
- findings;
- cleanup decisions.

Every worker maintains a bounded pre-trigger flight-recorder ring. Tier 2 activates around high-interest events such as crashes, new coverage, symbolic addressing, semantic uncertainty, solver anomalies, target proximity, and analyst bookmarks.

A trace governor decays Tier 2 when high-volume output becomes repetitive or low-novelty. Repetition is summarized structurally rather than silently discarded.

Post-processing performs canonicalization, deduplication, compaction, and causal extraction before destructive cleanup is considered. Ambiguous/high-value cleanup may require human approval. Deletion supports quarantine-before-purge and the cleanup decision itself is provenance.

See `PROVENANCE_KNOWLEDGE.md`.

---

# QIHSE / KEYSTONE Knowledge Plane

QIHSE is the persistent system of record. KEYSTONE is the preferred high-speed ingestion/index/retrieval acceleration layer.

The execution workers never synchronously write large provenance payloads to the database.

Suggested storage mapping:

| Angryier artifact | Preferred storage |
|---|---|
| stable identities, hashes, exact lookup keys | KV / KEYSTONE |
| run configuration and findings | Document |
| state/constraint/taint/finding lineage | Graph |
| coverage and solver/runtime telemetry | Time-series |
| learned semantic similarity | Vector / quantum-inspired retrieval layer |
| large raw deep traces | chunk/archive storage referenced by indexed metadata |

All persisted descendants inherit the analysis security context/classification unless an authorized policy changes it.

---

# Cumulative Cross-Run Knowledge

Angryier is cumulative by design.

## Authoritative reuse

Previous knowledge may directly replace work only when the relevant validity key matches. Inputs include, as applicable:

```text
code/content hash
canonical semantic hash
architecture/target profile
semantics generator/version
instruction semantic version
environment/syscall model version
solver + solver version
fidelity level
relevant configuration/assumptions
```

## Advisory reuse

Approximate retrieval may identify:

- semantically similar functions;
- similar constraints;
- similar paths;
- similar taint flows;
- prior analyst annotations;
- historically effective solver/search strategies.

Advisory matches guide exploration but cannot become proof without exact validation.

---

# Learned Fusion Retrieval

Option B is locked: **specialist encoders feed a learned fusion layer**.

```text
IR encoder
CFG/path encoder
constraint encoder
taint/dataflow encoder
memory/behavior encoder
solver-profile encoder
provenance/fidelity encoder
finding/context encoder
        |
        v
masked/gated learned fusion
        |
        v
semantic embedding
```

All useful modalities may contribute. Missing modalities are explicitly masked rather than represented as fabricated data.

The default fused width is **1024 dimensions**. Embedding profiles may range from 384 to 4096 dimensions, and dimensionality is benchmarked rather than assumed to correlate monotonically with retrieval quality.

Store sub-embedding/contribution information so Angryier can explain why two artifacts matched.

The vector is a retrieval aid, never the authoritative semantic representation.

---

# Concrete Fast Path and JIT

The executor remains concrete for as long as semantics permit, then uses taint to delay symbolic promotion.

JIT/native execution is introduced only after profiling demonstrates that concrete block execution is still a major wall-time component. Host acceleration is guarded by real host features and must always have a software semantic fallback for target instructions the host cannot execute.

Potential maturity path:

```text
cold block -> compact interpreter
warm block -> specialized cached executor
hot block  -> Cranelift/native translation if justified
```

---

# Correctness and Validation

Performance is invalid without semantic equivalence.

Validation layers include:

1. unit/property tests for semantic and IR operations;
2. generated instruction-form tests;
3. concrete differential tests against native Intel hardware and suitable reference engines;
4. symbolic equivalence checks for semantic rules;
5. cross-solver checks for selected high-value cases;
6. native replay of generated testcases/findings;
7. support-coverage manifests per instruction family;
8. semantic disagreement records persisted into the knowledge plane.

An optimization that changes reachable-state semantics is a correctness failure unless it is explicitly enabled by EXPLORE/HUNT policy and recorded in the fidelity ledger.

---

# Explicit Non-Goals Until Core Gates Pass

Do not allow these to replace proof of the core architecture:

- distributed execution;
- GUI-first development;
- angr API compatibility;
- broad multi-ISA implementation before Intel 64 gates pass;
- full operating-system emulation;
- decompiler as a prerequisite;
- GPU symbolic execution;
- LLM/agent logic in the trusted semantics path.

Optional AI/agent assistance may later advise search, triage, modeling suggestions, or analyst interaction, but its outputs are advisory and must not silently become semantic truth.
