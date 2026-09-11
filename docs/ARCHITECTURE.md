# Angryier Architecture

> **Status:** Architecture frozen. Implementation scaffold in progress.
>
> `Plan.md` is the operational decision baseline. This document is the complete system architecture derived from that baseline. Implementation may refine mechanics, layouts, thresholds, and algorithms, but it must not silently weaken a locked invariant. Any architectural change requires an explicit replacement decision and migration note.

---

## 1. Mission

Angryier is a native, parallel symbolic/concolic binary-analysis platform designed to exceed Python-heavy symbolic-execution systems not only in raw throughput, but in semantic fidelity, multicore scalability, replayability, cumulative cross-run learning, and analyst insight.

The project is not a source-compatible or API-compatible rewrite of angr. It is a new execution architecture with different internal economics:

- **Concrete work stays concrete.** Symbolic structures are created only when path reasoning, symbolic output, symbolic addressing, or an analyst request actually requires them.
- **State is persistent rather than copied wholesale.** Forks share immutable structure and use copy-on-write deltas.
- **Parallelism is native.** Workers own their hot caches and solver contexts; the design assumes true multicore execution rather than Python-thread orchestration.
- **Semantic truth is explicit.** Decode support, semantic support, solver certainty, approximation, environment assumptions, and replay status are separate concepts.
- **Provenance is a first-class product.** Angryier must be able to answer why a branch was reachable, why a sibling was pruned, which input bytes controlled a value, which assumption affected a finding, and where solver time was spent.
- **Knowledge is cumulative.** Prior analyses contribute exact reusable facts and advisory similarity knowledge through QIHSE and KEYSTONE.
- **Similarity is never proof.** Learned retrieval may prioritize work or propose reuse candidates, but authoritative correctness remains grounded in exact identities, validity keys, semantics, and solver/replay checks.

The intended end state is an analysis engine that becomes materially more useful as it accumulates validated analyses, while remaining capable of running without the persistent knowledge plane.

---

## 2. Non-goals

The initial architecture explicitly does **not** require:

- angr API compatibility;
- Python in the execution hot path;
- AMD-specific instruction/system behavior in the Intel 64 backend;
- immediate multi-host execution;
- immediate JIT compilation;
- a universal single solver;
- eager symbolic conversion of vectors, AMX tiles, memory pages, or tainted data;
- a learned model anywhere in the proof/truth path;
- synchronous database access from execution workers;
- architectural support claims based only on successful instruction decode.

Additional ISAs may be added later through architecture-neutral traits, but implementation resources remain focused on **Intel 64** until that backend is mature and validated.

---

## 3. Global invariants

These rules apply across the entire repository.

1. **Decode is not semantics.** Intel XED identifies and describes an instruction; Angryier owns its semantics.
2. **Host capability is not target capability.** An analyzer host without AVX-512 or AMX must still be able to analyze target code that uses them.
3. **Published semantics are immutable.** A rich semantic block is mutable only while private to construction/normalization/validation. Once sealed, it is immutable and content-addressed.
4. **Exact identity and semantic similarity are separate.** `ContentId` is authoritative. `SemanticFingerprint` and learned embeddings are candidate/retrieval identities.
5. **Post-seal transformations are derivations.** They create new immutable blocks with explicit parentage, transformation contracts, and equivalence evidence.
6. **Execution artifacts are validity-scoped.** Execution IR and JIT artifacts are bound to exact semantic identity, target profile, image/block identity, and relevant code-page versions.
7. **Replay-visible mutation is atomic.** State changes, code-page versions, invalidation consequences, Tier-1 provenance advancement, semantic references, and replay checkpoints are committed under one execution-ledger epoch or not published at all.
8. **Solver uncertainty is never silently converted to UNSAT.** SAT, UNSAT, UNKNOWN, TIMEOUT, RESOURCE_LIMIT, and BACKEND_ERROR are distinct outcomes.
9. **Persistent reuse is fail-closed.** A stored result may affect correctness only after all required compatibility/dependency keys validate.
10. **Workers do not block on QIHSE/KEYSTONE.** Persistence is asynchronous/batched with priority-aware queues and local WAL/spill.
11. **Correctness-critical Tier-1 provenance is not silently dropped.** Backpressure is observable and recoverable.
12. **PROVE never silently approximates.** EXPLORE and HUNT may relax policy only with explicit fidelity provenance.
13. **Learned and quantum-inspired ranking are advisory.** They may change priority or worker assignment, never truth.
14. **Deterministic mode is mandatory.** Scheduler decisions, seeds, solver configuration, event order, and replay-relevant nondeterminism must be recordable/replayable.
15. **JIT is evidence-driven.** It is introduced only when profiling demonstrates end-to-end value.

---

## 4. System planes

Angryier is organized into three cooperating planes.

```text
                                  ANGRYIER
                                     |
             +-----------------------+-----------------------+
             |                       |                       |
             v                       v                       v
      EXECUTION PLANE            TRUTH PLANE           KNOWLEDGE PLANE

  loader / state import       canonical semantics       QIHSE system of record
  Intel 64 decode             support manifest          KEYSTONE indexes/ingest
  concrete execution          differential testing      exact reusable facts
  taint/dataflow              equivalence evidence      dependency graph
  concolic/symbolic           fidelity ledger           semantic fingerprints
  COW state/memory            replay validation         fused embeddings
  expression DAG              solver classification     analyst annotations
  solver orchestration        target-profile truth      time-series telemetry
  scheduler / NUMA            semantic identities       retention/cleanup
  optional JIT
```

### 4.1 Execution Plane

Owns the latency-sensitive analysis path:

- loading and state import;
- normalized Intel 64 decode;
- concrete, taint, concolic, and symbolic execution;
- register and memory state;
- expression DAG construction;
- path constraints;
- solver dispatch;
- state forking/merging;
- search scheduling;
- code-page invalidation;
- replay checkpoints;
- optional JIT/native acceleration.

The Execution Plane must remain useful with persistence completely disabled.

### 4.2 Truth Plane

Owns claims of correctness and fidelity:

- semantic definitions and generator versions;
- canonical typed semantic IR;
- semantic sealing/identity;
- transformation contracts and equivalence evidence;
- semantic support manifests;
- differential tests against hardware/reference engines;
- solver outcome classification;
- approximation/fidelity accounting;
- deterministic replay verification;
- target feature/profile assumptions.

### 4.3 Knowledge Plane

Turns runs into reusable intelligence:

- exact query/result caches;
- UNSAT cores and generalized solver facts;
- dependency-aware invalidation;
- function summaries;
- state/constraint/taint lineage;
- historical solver performance;
- semantic discrepancy history;
- hierarchical function/artifact identity;
- semantic fingerprints;
- specialist modality embeddings and learned fusion;
- analyst labels;
- trace summaries and retention decisions.

The Knowledge Plane suggests; exact validation authorizes.

---

## 5. Repository and crate boundaries

The target workspace is deliberately decomposed around stable ownership boundaries rather than convenience modules.

```text
crates/
  angryier-types/             shared IDs, versions, hashes, small policy enums
  angryier-core/              orchestration contracts and engine-level context
  angryier-arch/              ISA-neutral architecture traits
  angryier-arch-intel64/      Intel 64 registers, features, CPU profiles
  angryier-decode-xed/        Intel XED adapter; no semantic truth
  angryier-loader/            ELF64/PE32+ loading and image mappings
  angryier-state-import/      static/snapshot/checkpoint/live state import

  angryier-semantics/         semantic provider/builder contracts
  angryier-semantic-contracts sealed identity + transformation/evidence contracts
  angryier-semantics-gen/     declarative semantics compiler/generator boundary
  angryier-ir/                compact AngryIR execution representation
  angryier-expr/              immutable symbolic expression DAG
  angryier-memory/            layered COW memory
  angryier-state/             persistent machine/path state
  angryier-taint/             cheap taint/dataflow domain
  angryier-exec/              concrete/taint/concolic/symbolic executor

  angryier-ledger/            atomic replay-visible publication boundary
  angryier-replay/            deterministic replay capsules and verifier
  angryier-solver/            solver-neutral queries, batching, portfolio policy
  angryier-solver-z3/         Z3 adapter
  angryier-solver-bitwuzla/   Bitwuzla adapter
  angryier-scheduler/         worker pool, NUMA groups, work stealing, search
  angryier-models/            syscall/libc/environment summaries/models
  angryier-summary/           function/path summary contracts and validity

  angryier-provenance/        fidelity ledger, Tier 0/1/2 event contracts
  angryier-telemetry/         bounded queues, WAL/spill, trace compaction
  angryier-knowledge/         exact/advisory reuse + invalidation graph
  angryier-qihse/             QIHSE storage adapter
  angryier-keystone/          KEYSTONE ingestion/index adapter
  angryier-fusion/            specialist encoders + masked/gated learned fusion

  angryier-fuzz/              bidirectional hybrid fuzzing boundary
  angryier-jit/               optional JIT validity/isolation boundary
  angryier-plugin-api/        stable internal Rust extension traits
  angryier-distributed/       future work-unit serialization/distribution seam
  angryier-bench/             benchmark/correctness harness contracts
  angryier-cli/               CLI frontend
```

### 5.1 Dependency direction

The workspace must remain acyclic and layered:

```text
                    angryier-types
                         |
       +-----------------+-------------------+
       |                 |                   |
      arch            semantics             provenance
       |                 |                   |
   intel64/xed     semantic-contracts        |
       |                 |                   |
       +---------> IR / expr / memory / state+
                         |
                        exec
                         |
               solver / ledger / replay
                         |
                    scheduler/models
                         |
          telemetry / knowledge / fuzz / JIT
                         |
               QIHSE / KEYSTONE / fusion
```

Adapters depend inward on stable contracts. Core execution code must not depend on database SDK details, XED-owned lifetimes, Z3 AST types, Bitwuzla AST types, or ML model representations.

---

## 6. Shared identity and version model

Identity-bearing objects use distinct newtypes. Cross-domain IDs must not be interchangeable primitive aliases in mature code.

Core identities include at least:

```text
RunId
ImageId
ModuleId
BlockId
StateId
ExprId
ConstraintId
CodePageId
SummaryId
ProvenanceNodeId
ReplayCapsuleId
TargetProfileId
SemanticRuleId
ContentId
SemanticFingerprint
DependencyKey
WorkUnitId
```

Version domains include:

```text
SemanticVersion
ContentIdentitySchemaVersion
SemanticFingerprintSchemaVersion
ExpressionNormalizationVersion
ConstraintCanonicalizationVersion
EnvironmentModelVersion
SummarySchemaVersion
ProvenanceSchemaVersion
ReplaySchemaVersion
EmbeddingModelVersion
EmbeddingSchemaVersion
KnowledgeSchemaVersion
CodePageVersion
LedgerEpoch
```

A cache key that omits a materially relevant version is a correctness defect.

---

## 7. Architecture abstraction

The engine is ISA-neutral at its core.

Conceptually:

```rust
pub trait Architecture {
    type Register;
    type Feature;
    type Decoded;
    type RegisterFile;

    fn decode(&self, pc: u64, bytes: &[u8], profile: &TargetProfile)
        -> Result<Self::Decoded, DecodeError>;

    fn initial_registers(&self, profile: &TargetProfile) -> Self::RegisterFile;

    fn validate_target_features(
        &self,
        decoded: &Self::Decoded,
        profile: &TargetProfile,
    ) -> Result<(), FeatureError>;
}
```

This is an architectural boundary, not a requirement that every backend expose identical internal details.

### 7.1 Intel 64 first

The first production backend is Intel 64. Validation scope includes modern Intel families such as:

```text
base Intel 64
SSE / SSE2 / SSE3 / SSSE3 / SSE4.x
AES-NI / SHA / BMI-class instructions
AVX
AVX2
AVX-512
AVX-VNNI
AVX10
AMX
CET
APX
future Intel extensions after explicit semantic validation
```

AMD-specific extensions, SVM behavior, and AMD-specific MSRs/system behavior are not part of the Intel 64 validation target.

### 7.2 Host and target separation

```text
HostFeatures   = analyzer machine CPUID/XCR0/OS enablement
TargetFeatures = virtual target CPU profile and allowed feature set
```

Execution policy chooses acceleration:

```text
decode -> semantic truth -> execution policy

if host safely supports accelerated form:
    optional native/JIT specialization
else:
    software semantic path
```

Target support must never disappear because the host lacks a feature.

### 7.3 Target profiles

Target profiles support:

- `native` convenience profile;
- named Intel microarchitecture profiles;
- custom CPUID/feature-set profiles;
- explicit XCR0/OS-state assumptions where relevant.

The profile identity participates in validity keys whenever feature availability changes semantics or legality.

---

## 8. Intel XED decode boundary

Intel XED is the canonical initial decoder/form classifier for Intel 64.

XED provides:

- instruction length;
- normalized form identity;
- operand metadata;
- register references;
- immediate/displacement metadata;
- encoding/form classification;
- Intel feature association.

XED does **not** provide Angryier semantic truth.

XED-owned pointers, opaque decoder state, and XED lifetimes terminate in `angryier-decode-xed`. Downstream crates consume a serializable, deterministic internal decoded representation.

The decoder must be independently fuzzable and replaceable. A synthetic decoder should be able to feed the semantic layer without linking XED.

---

## 9. Semantic-definition architecture

The semantic-definition strategy is hybrid.

```text
                    semantic source
                          |
          +---------------+----------------+
          |               |                |
          v               v                v
   declarative family   typed Rust       handwritten
      definitions       combinators       overrides
          |               |                |
          +---------------+----------------+
                          |
                    semantic compiler
                          |
                          v
               private rich semantic IR
                          |
               normalize / optimize / validate
                          |
                          v
                         SEAL
                          |
                          v
               immutable semantic block
```

### 9.1 Why hybrid

Regular instruction families contain enormous repetition in widths, lanes, masks, source/destination forms, and feature tags. These should be declarative/generated.

Complex behavior should not force the declarative format to become a hidden general-purpose programming language. Typed Rust combinators and explicit overrides remain available for:

- AMX;
- complex AVX-512 masking/gather/scatter;
- difficult floating-point behavior;
- system/state instructions;
- CET/APX corner cases;
- x87/string/REP families where appropriate;
- semantics that resist clean declarative factoring.

### 9.2 Provider resolution

A decoded form resolves to exactly one authoritative semantic provider. Registry order must never silently determine semantic priority. Multiple matching providers are a hard error.

Every emitted semantic definition yields a receipt containing at least rule identity, origin, and semantic version.

### 9.3 Generator discipline

The generator is built **after** a representative handwritten corpus stabilizes the semantic and execution IRs.

Generated outputs must be:

- deterministic;
- readable;
- checked into the repository when appropriate;
- reproducible by CI;
- covered by a support manifest;
- test-generated from the same semantic source where useful.

Unsupported forms are explicit errors, never silent no-ops.

---

## 10. Two-level IR architecture

Angryier uses two distinct IR levels.

### 10.1 Rich Canonical Semantic IR

The rich IR exists to express architectural meaning without premature lowering into solver bitvectors or JIT-friendly micro-ops.

First-class domains include:

```text
BitVec(width)
Float(format)
Vector { width, lane/view metadata }
Opmask { lanes }
Tile { rows, columns/bytes-per-row, element/layout metadata }
```

It represents:

- explicit register reads/writes;
- explicit memory effects;
- architectural flags;
- exceptions/fault conditions;
- floating-point rounding and MXCSR-sensitive behavior;
- SAE and embedded rounding;
- AVX-512 merge/zero masking;
- upper-lane behavior;
- broadcasts/permutations/shuffles;
- AMX TILECFG and tile state;
- memory ordering where modeled;
- control transfers;
- feature/privilege assumptions where required.

### 10.2 AngryIR execution IR

AngryIR is compact and hot-path oriented.

Requirements:

- SSA-like block temporaries;
- compact IDs and inline immediates;
- explicit widths/types;
- explicit register/memory effects;
- solver-independent representation;
- no decoder-specific objects;
- no database handles;
- no per-operand heap allocation in the normal path;
- structural vector/mask/tile operations retained where profitable;
- deterministic serialization where identity-bearing;
- block validity tied to exact semantic `ContentId` and code-page versions.

Rich semantics are truth; AngryIR is an execution artifact derived from that truth.

---

## 11. Semantic block lifecycle and identity

### 11.1 Two-stage lifecycle

```text
PRIVATE / MUTABLE
    |
    +-- construct
    +-- normalize
    +-- local optimize
    +-- validate
    |
    v
SEAL
    |
    +-- canonical serialization
    +-- exact ContentId
    +-- normalized SemanticFingerprint
    +-- semantic/schema version binding
    +-- provenance receipt
    |
    v
PUBLIC / IMMUTABLE
```

Only sealed blocks may enter:

- lowering;
- caches;
- JIT validity;
- replay capsules;
- provenance references;
- exact cross-run reuse;
- QIHSE exact-plane storage.

### 11.2 Dual identity

Every sealed block has two identities.

**`ContentId`**

- authoritative exact identity;
- computed from canonical sealed serialization;
- trusted by replay, JIT, provenance, exact caches, and exact reuse.

**`SemanticFingerprint`**

- normalized semantic/structural candidate identity;
- may normalize irrelevant temporary numbering, safe commutative ordering, structural naming, and equivalent representation artifacts;
- used for candidate equivalence, clustering, generalized lookup, and learned-fusion input;
- never sufficient to authorize exact reuse.

Fingerprint normalization must preserve semantically relevant distinctions such as widths, signedness where meaningful, rounding, MXCSR behavior, SAE, mask merge/zero behavior, exceptions, memory ordering, architectural side effects, and target-feature assumptions.

---

## 12. Semantic transformation trust

A sealed semantic block is never modified in place.

```text
sealed block A
      |
 transformation pass
      |
      v
candidate block B
      |
      +-- declared transformation contract
      +-- structural/type/effect checks
      +-- equivalence evidence
      +-- parent derivation link
      |
      v
sealed block B
```

Transformation contracts explicitly state preservation claims such as:

```text
values
architectural side effects
exception behavior
memory ordering
floating-point behavior
masking behavior
target-feature semantics
```

### 12.1 Evidence lattice

Equivalence evidence is layered rather than a single boolean:

```text
Structural
    -> SolverChecked
        -> DifferentiallyTested
            -> Composite
```

Different transformation classes may require different evidence. PROVE requires policy-sufficient evidence. EXPLORE/HUNT may permit explicitly weaker evidence, but such artifacts are marked and may not silently contaminate the authoritative semantic corpus.

Execution/JIT optimizations remain bound to the exact source `ContentId` even when their machine representation changes.

---

## 13. Structured vector, mask, and AMX representation

Wide architectural state is represented structurally and lowered lazily.

### 13.1 Vectors

Vectors use a hybrid packed/lane-aware representation:

- packed view for bitwise/reinterpretation-heavy operations;
- lane view for arithmetic, masks, taint, and partially symbolic data;
- lazy conversion between views;
- concrete lanes remain concrete;
- symbolic lanes reference compact expressions;
- view coherence is versioned/validated rather than protected by a global lock.

### 13.2 AVX-512 opmasks

`k0..k7` are first-class mask state. Semantics distinguish:

- merge masking;
- zero masking;
- mask lane width;
- broadcasts;
- upper-lane clearing/preservation as required;
- embedded rounding and SAE.

### 13.3 AMX

AMX state includes explicit TMM state and TILECFG.

Preferred representation:

```text
LazyChunked
```

with concrete backing and sparse/lazy symbolic chunks/cells.

Fallback:

```text
DenseCellFallback
```

may be selected when profiling demonstrates pathological translation/contention. Representation changes are policy transitions, not semantic approximations, and must be provenance-visible and differentially cross-checked.

---

## 14. Floating-point model

Floating-point semantics use native SMT floating-point theories where appropriate, with a controlled bitvector lowering/fallback path.

The model must account for, where architecturally relevant:

- F16/BF16/F32/F64/F80 and newer formats as Intel extensions require;
- rounding modes;
- NaN/sNaN behavior;
- infinities;
- signed zero;
- denormals;
- DAZ/FTZ;
- MXCSR;
- exception flags;
- SAE;
- embedded rounding;
- conversion corner cases.

Bitvector fallback is explicit and validity-scoped. Cross-check corpora should compare SMT-FP and bitvector formulations where both apply.

---

## 15. Runtime value model

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

## 16. Expression DAG

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

### 16.1 Layered canonicalization

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

## 17. Layered memory model

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

### 17.1 Fork behavior

Forking is close to O(1) in unchanged state size:

- immutable page roots are shared;
- modified pages use COW;
- symbolic overlays share persistent structure;
- register/path roots share immutable nodes;
- child state records lineage rather than duplicating history.

### 17.2 Symbolic addresses

Address resolution is policy-based:

- range/alias reasoning first;
- bounded enumeration where appropriate;
- target/object metadata where available;
- profile-dependent concretization only when allowed;
- every concretization is fidelity/provenance-visible.

PROVE cannot silently choose one address from multiple feasible targets.

---

## 18. Persistent State

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

## 19. Fidelity profiles

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

### 19.1 Analysis debt

Findings inherit categorical fidelity events such as:

```text
MODELLED
SUMMARY
CONCRETIZED
ASSUMED
UNSUPPORTED
TIMEOUT
```

Avoid fake precision such as arbitrary “92% exact” scores unless a rigorously justified metric is later defined.

---

## 20. Environment and state-import architecture

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

### 20.1 Environment models

Environment interaction is layered:

1. deterministic syscall/library summaries where available;
2. validated reusable function summaries;
3. controlled concrete passthrough/sandbox execution where safe and policy-permitted;
4. symbolic fallback/modeling where required.

Model identity/version is part of summary/cache/replay validity.

---

## 21. Function and path summaries

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

## 22. Solver architecture

Solver orchestration is deliberately separated from expression/state representation.

### 22.1 Worker-local solver state

Each worker owns or leases its own incremental contexts. Z3/Bitwuzla context objects are never shared across threads behind a global mutex.

### 22.2 Solver-neutral query model

Engine state stores solver-neutral constraints. Backend AST objects remain inside adapters.

Query results are explicitly classified:

```text
SAT
UNSAT
UNKNOWN
TIMEOUT
RESOURCE_LIMIT
BACKEND_ERROR
```

### 22.3 Shared-context batched satisfiability

The API supports a common context plus many predicates:

```text
Phi + {p1, p2, p3, ...}
```

This is a first-class primitive because sibling branches often share most path constraints.

### 22.4 Portfolio scheduling and adaptive preemption

Z3 and Bitwuzla are first-class initial backends. Solver selection combines:

- deterministic theory/profile rules;
- query-shape metadata;
- hard resource limits;
- historical backend performance;
- adaptive preemption before catastrophic timeout;
- deterministic fallback policy;
- optional cross-checks for high-value queries.

Historical routing is advisory; it cannot change semantics.

---

## 23. Persistent solver knowledge

Persistent solver knowledge has exact and generalized layers.

Stored artifacts may include:

```text
canonical query identity
compatibility/dependency key
SAT/UNSAT/UNKNOWN result
models
UNSAT cores
query theory/shape
alpha-equivalence metadata
implication/subsumption facts
incompatible predicate sets
branch invariants
solver/version/options
timing/resource metrics
proof/revalidation evidence
```

### 23.1 Reuse hierarchy

1. exact canonical query hit;
2. alpha-equivalent candidate;
3. validated UNSAT-core reuse;
4. implication/subsumption candidate;
5. generalized fact candidate;
6. similarity-guided advisory retrieval.

Every correctness-affecting hit validates all required dependency keys before authorization.

### 23.2 Poisoning resistance

High-entropy fuzz inputs are an explicit adversarial corpus for cache-validity testing. Structurally similar but logically distinct constraints must never be conflated because of fingerprint or subsumption mistakes.

---

## 24. State merging

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

---

## 25. Search and scheduler architecture

Search is pluggable and multi-objective.

Potential score dimensions include:

- coverage novelty;
- target/reachability distance;
- taint relevance;
- symbolic depth;
- solver cost;
- semantic uncertainty;
- approximation debt;
- crash/finding proximity;
- analyst goals;
- historical usefulness of similar states.

Deterministic baseline strategies remain available even when learned ranking exists.

### 25.1 Learned ranking

Learned models may reorder admissible work. They do not decide truth, SAT/UNSAT, semantic support, or proof validity.

### 25.2 Quantum-inspired batch scheduling

After the deterministic CPU scheduler is correct and benchmarked, an optional `QuantumInspiredScheduler` may optimize bounded batches of already-admissible states. The intended formulation is a classical QUBO-style or related combinatorial objective over:

- coverage and path diversity;
- target proximity and analyst priorities;
- estimated solver cost;
- solver-context and cache affinity;
- memory working-set and NUMA migration cost;
- semantic uncertainty and fidelity debt;
- historical outcomes supplied by the optional knowledge plane.

The optimizer selects and assigns work; it does not execute states, classify solver results, validate semantics, or authorize cache reuse. Every selected state is executed by the normal CPU execution plane and remains subject to the same exact validity and fidelity rules.

The scheduler owns a backend-neutral batch-optimizer contract with these implementations:

```text
compatible CUDA device/runtime    -> CUDA accelerator
otherwise compatible OpenCL       -> OpenCL accelerator
otherwise                         -> deterministic CPU reference
```

CUDA eligibility is capability-based, not vendor-name-based: the runtime, driver, device compute capability, available memory, and compiled kernel targets must all satisfy the backend manifest. An NVIDIA card that is too old for the supported CUDA kernel/toolchain automatically tries OpenCL when it exposes the required OpenCL device capabilities, then falls back to CPU. No GPU is rejected merely because another accelerator API is unavailable.

Accelerated planning has a strict wall-time budget. Device discovery, compilation, allocation, transfer, kernel, timeout, numerical, or validation failure follows the same CUDA -> OpenCL -> CPU fallback ladder without losing runnable work. Accelerator-specific APIs and memory never enter execution-state, semantic, solver, replay, or persistence types.

GPU use is justified only for sufficiently large batches whose measured scheduling benefit exceeds host/device transfer and launch overhead. Small queues remain on the CPU. CUDA/OpenCL kernels operate on compact feature matrices and assignment candidates, not COW pages, symbolic AST mutation, or arbitrary target execution.

Quantum-inspired and GPU decisions are replay-visible. Deterministic mode either uses the CPU reference optimizer or records the complete candidate batch, objective/schema version, backend identity, device capability, kernel compatibility manifest, seed, budget, result, attempted fallback chain, and fallback reason.

---

## 26. Native multicore and NUMA

The scheduler uses native worker threads with worker-local deques and work stealing.

Expected locality ownership:

```text
worker-local:
  solver contexts
  hot expression cache
  trace flight recorder
  local state deque
  temporary semantic builders

shared immutable/persistent:
  sealed semantic blocks
  decode/form tables
  expression/state roots
  code metadata
  target profiles

NUMA-local where profitable:
  worker groups
  block caches
  arenas/pages
  solver pools
  queue shards
```

State stealing is not based only on queue depth.

Conceptually:

```text
steal_value = load_imbalance_gain
            - solver_context_rebuild_cost
            - NUMA_migration_cost
            - cache_locality_loss
            - COW/materialization_cost
```

The implementation must expose migration and affinity telemetry so firmware or hardware behavior cannot hide poor software design.

---

## 27. Adaptive provenance

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

### 27.1 Tier 1 minimum

Tier 1 retains at least:

- state parent/child lineage;
- branch decisions;
- constraint lineage;
- taint origin and important source-to-sink relationships;
- solver query/result class and cost summary;
- semantic identity/version;
- fidelity/approximation events;
- code-page version/invalidation events relevant to replay;
- findings;
- cleanup/retention decisions.

### 27.2 Tier 2 triggers

Possible triggers include:

- crashes;
- novel coverage;
- symbolic addressing;
- semantic uncertainty/disagreement;
- solver anomalies;
- target proximity;
- expensive branches;
- analyst bookmarks;
- suspicious model/concretization transitions.

Each worker maintains a bounded circular pre-trigger recorder. Triggering freezes the useful pre-trigger slice and records a forward window while the worker receives a fresh ring.

### 27.3 Spam suppression

Suppression is semantic rather than textual. Repeated event identities are summarized with counts, first/last occurrence, representative states, and novelty information.

The governor uses hysteresis so Tier 2 does not oscillate rapidly around a threshold.

---

## 28. Atomic Execution Ledger

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

## 29. Deterministic replay capsules

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

## 30. Self-modifying code and block invalidation

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

---

## 31. JIT/native acceleration

JIT is optional and late-stage.

Potential progression:

```text
cold block -> compact AngryIR interpreter
warm block -> specialized cached executor
hot block  -> Cranelift/native translation
```

JIT must prove an end-to-end win after accounting for compilation cost, invalidation, symbolic hooks, cache pressure, and state management.

### 31.1 Isolation

- trusted Angryier-generated JIT code may execute in-process under strict validity guards;
- arbitrary/native target execution belongs in a restricted worker/sandbox boundary;
- privileged/system instructions are never blindly executed on the analyzer host.

---

## 32. Bidirectional fuzzing boundary

Fuzzing integration is staged.

### Stage 1

```text
seed exchange
coverage exchange
```

### Stage 2

After deterministic replay and cache-validity invariants are hardened:

```text
bidirectional seeds
coverage
constraint hints
target hints
testcase feedback
```

Fuzzer-provided information is advisory input. It cannot authorize exact cache reuse or bypass semantic validity.

---

## 33. Knowledge identity hierarchy

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

## 34. Dependency-aware invalidation graph

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

---

## 35. QIHSE and KEYSTONE

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

### 35.1 Security context

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

## 36. Learned semantic fusion

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

### 36.1 Training objectives

Training may combine:

- contrastive/self-supervised objectives;
- exact-equivalence positive pairs;
- known non-equivalence/near-miss negatives;
- execution-behavior similarity;
- path/taint/constraint relationships;
- analyst feedback;
- cross-run retrieval success/failure.

### 36.2 Explainable retrieval

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

## 37. Telemetry transport, bounded queues, and WAL

Execution workers emit compact events into bounded priority-aware worker-local or sharded buffers.

Event classes distinguish correctness-critical structural events from lossy/aggregatable telemetry.

When persistence falls behind:

1. aggregate low-value repetitive telemetry;
2. reduce Tier-2 verbosity through the trace governor;
3. spill durable events to a local WAL;
4. expose backpressure metrics;
5. apply profile-specific controlled pressure only if durability requirements demand it.

Correctness-critical Tier-1 events are never silently discarded.

### 37.1 WAL requirements

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

## 38. Trace compaction and retention

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

Retention profiles include:

```text
forensic
research
benchmark
disposable
```

Pinned evidence, semantic discrepancies, compiler/solver-unsoundness evidence, and selected findings may be exempt from automated purge.

Deletion supports ACTIVE -> QUARANTINED -> PURGED lifecycle where policy requires it. Cleanup decisions are themselves provenance.

---

## 39. Plugin and extension model

Internal extensibility uses versioned Rust traits rather than an unstable dynamic ABI in the execution hot path.

Extension seams include:

- architecture backends;
- decoders;
- semantic providers;
- environment models;
- solver backends;
- search policies;
- summary providers;
- provenance consumers;
- knowledge adapters;
- fuzzing adapters.

A stable C ABI may be introduced later for external binary plugins if a real interoperability requirement exists. It is not an initial constraint on internal Rust design.

---

## 40. Future multi-host boundary

Distributed execution is intentionally deferred until single-host NUMA scaling is proven, but serialization boundaries are defined early.

Serializable work units include or reference:

```text
WorkUnitId
TargetProfile
sealed semantic identities
state roots/deltas
expression/constraint identities
replay capsule context
fidelity/provenance context
solver-knowledge validity keys
required code/image content
scheduler objective metadata
```

No distributed scheduler is required for initial production readiness.

---

## 41. Security and trust boundaries

Angryier processes untrusted binaries and must assume hostile inputs.

Key boundaries:

- parsers/loaders and XED adapters validate lengths/ranges before use;
- target code is not granted arbitrary analyzer-process execution;
- native target execution is sandboxed/restricted;
- JIT memory follows W^X discipline when implemented;
- solver responses are classified and may be cross-checked for high-value claims;
- generated semantics cannot shadow overrides ambiguously;
- persistent knowledge cannot bypass compatibility validation;
- corrupted/stale replay capsules fail closed;
- QIHSE/KEYSTONE failures cannot corrupt local execution truth;
- event/WAL payloads are versioned and checksummed;
- plugins do not receive unrestricted hot-path mutation access by default.

Rust `unsafe` is forbidden in pure-Rust core crates unless a future exception is explicitly documented. FFI crates may require narrowly audited `unsafe` blocks once XED/solver/native APIs are implemented; those exceptions must remain encapsulated at adapter boundaries rather than leaking through the workspace.

---

## 42. Failure containment

The architecture is designed so subsystem failure degrades capability without silently corrupting truth.

| Failure | Required behavior |
|---|---|
| QIHSE unavailable | continue locally; queue/WAL durable events |
| KEYSTONE unavailable | fall back to exact local/persistent paths; no truth loss |
| learned model unavailable | deterministic search/retrieval paths remain usable |
| CUDA/OpenCL optimizer unavailable or fails | preserve the candidate batch and use the deterministic CPU scheduler |
| solver timeout | return TIMEOUT/UNKNOWN and apply policy; never UNSAT |
| one solver backend fails | portfolio fallback/cross-check according to policy |
| Tier-2 overload | reduce/summarize Tier-2, retain Tier-1 |
| WAL pressure | expose saturation, aggregate disposable telemetry, preserve required truth |
| semantic provider missing | explicit unsupported result |
| semantic disagreement | mark discrepancy and retain forensic evidence |
| JIT invalidated | fall back to valid execution IR/interpreter |
| replay mismatch | reject capsule/replay rather than repair silently |
| dependency mismatch | reject reuse and recompute |

---

## 43. Observability and analyst insight

Angryier should answer causal questions directly from deterministic/provenance structures rather than reconstructing them from flat logs.

Target queries include:

```text
Why can this branch be reached?
Why was the sibling state pruned?
Which input bytes control this comparison?
Where did this symbolic value originate?
Which constraints dominate solver time?
Which model/summary/concretization affected this finding?
Which previous run contributed this reusable fact?
Why did the scheduler prioritize this state?
Why did the solver portfolio preempt backend A for backend B?
Can this finding reproduce without approximations?
Which code-page mutation invalidated this block?
Why are two functions considered semantically similar?
```

The causal graph is a product feature, not merely diagnostic logging.

---

## 44. Benchmark and validation contract

No performance target is treated as achieved until measured against a reproducible corpus.

Benchmarks cover at least:

- mostly-concrete execution;
- concolic execution;
- moderate symbolic workloads;
- solver-bound workloads;
- memory-heavy workloads;
- AVX/AVX-512 symbolic behavior;
- AMX lazy-chunk vs dense fallback;
- floating-point semantics;
- state fork/merge costs;
- NUMA scaling;
- solver portfolio behavior;
- provenance Tier-1/Tier-2 overhead;
- WAL saturation/recovery;
- QIHSE/KEYSTONE outage behavior;
- canonicalization amplification;
- alpha-equivalence/near-miss cache safety;
- learned retrieval precision/recall/calibration;
- deterministic replay success/failure;
- code-page/JIT invalidation stress.

Proposed speedups over angr or other systems remain targets until independently measured.

Every performance result should include corresponding correctness/fidelity information so “faster” cannot mean “quietly did less work.”

---

## 45. Critical stress scenarios

The implementation must deliberately attack its own design assumptions.

### 45.1 Dependency graph scale

Generate millions of summaries/versioned artifacts and measure memory overhead, invalidation latency, and compaction behavior.

### 45.2 Fuzzer cache poisoning

Inject millions of structurally similar but logically distinct constraints. No alpha-equivalence/subsumption/fingerprint path may authorize an incorrect exact result.

### 45.3 Atomicity fault injection

Inject failure between every internal ledger step. No partially committed combination of state, page versions, provenance, or replay metadata may become visible.

### 45.4 AMX contention

Compare lazy-chunked and dense-cell representations under heavy state forking and symbolic translation. Detect lock contention, cache-line bouncing, solver AST amplification, and migration costs.

### 45.5 Solver preemption oscillation

Construct queries near policy thresholds to verify hysteresis/resource caps and deterministic replay of routing decisions.

### 45.6 Telemetry saturation

Saturate event queues and WAL I/O while fuzzing. Required Tier-1 provenance must survive and latency impact must be measurable rather than silent.

### 45.7 Emergent scheduler behavior

Record and replay multi-objective search + adaptive solver-preemption runs to isolate regressions caused by policy interactions.

### 45.8 Accelerated batch-planner instability

Compare CPU, CUDA, and OpenCL scheduling decisions on identical bounded candidate batches. Inject device loss, compilation failure, timeout, out-of-memory, and numerically unstable scores. Runnable work must remain intact, fallback must be deterministic, and accelerator overhead must be reported separately from execution gains.

---

## 46. Architectural assumptions are hypotheses

Two explicit planning assumptions exist, but they are **not invariants**.

1. Custom firmware/hardware behavior may reduce context-switching cost on a particular host.
2. Baseline solver theories may generally remain healthy until portfolio fallback engages.

The implementation must remain correct when both assumptions are false.

Software metrics must expose context switches, NUMA migrations, solver fallback pressure, ledger conflicts, state steals, cache locality, and WAL pressure rather than allowing favorable hardware to conceal structural inefficiency.

---

## 47. Implementation order

The frozen implementation sequence is intentionally dependency-driven.

```text
0  build / CI / validation skeleton
1  shared IDs + Execution Plane state/memory/ledger foundations
2  Intel XED decode boundary
3  rich semantic IR + sealing + dual identity
4  representative handwritten semantic corpus
5  AngryIR + concrete interpreter
6  atomic ledger + deterministic replay
7  expression DAG + taint + symbolic promotion
8  solver-neutral API + Z3/Bitwuzla
9  exact cache validity + generalized knowledge + invalidation graph
10 native multicore + NUMA scheduler
11 state merge/search/summaries/environment models/state import + optional quantum-inspired batch scheduling
12 provenance transport + WAL + QIHSE/KEYSTONE
13 staged hybrid fuzzing
14 specialist encoders + learned fusion
15 JIT/native acceleration if profiling justifies it
16 future distribution boundary
```

The first coding milestone is therefore **not XED**. XED plugs into stable internal IDs, target profiles, register/state representations, code-page identities, and semantic contracts rather than defining those types accidentally.

---

## 48. Scaffold completion criteria

The repository is considered architecturally scaffolded when:

- every major crate boundary named in Section 5 exists in the workspace;
- shared IDs/policies have one canonical home;
- crate documentation states ownership/non-ownership clearly;
- adapters are separated from core data structures;
- semantics, exact identity, transformation evidence, state/memory, ledger, solver, provenance, knowledge, fuzzing, JIT, and distribution seams compile as independent contracts;
- no placeholder claims to implement behavior that does not yet exist;
- `cargo metadata` can resolve the workspace without dependency cycles;
- future implementation can proceed phase-by-phase without reorganizing the entire crate graph.

---

## 49. Architecture freeze rule

The architectural Q&A phase is complete through Q54.

Implementation details may evolve, but the following require an explicit architecture-change record before modification:

- the three-plane separation;
- Intel 64 first / ISA-neutral core policy;
- XED decode-vs-semantics boundary;
- hybrid declarative/Rust semantic-definition model;
- rich semantic IR -> sealed identity -> AngryIR pipeline;
- structured vector/AMX and SMT-FP policies;
- PROVE/EXPLORE/HUNT fidelity model;
- atomic execution ledger and deterministic replay requirements;
- native worker/NUMA ownership model;
- layered canonicalization and validated cross-run reuse;
- QIHSE/KEYSTONE non-blocking knowledge plane;
- specialist encoder + learned fusion model;
- exact-vs-similarity trust separation;
- staged fuzzing and late JIT policy;
- deterministic replay/debug mode;
- optional CUDA/OpenCL quantum-inspired scheduling remains advisory, bounded, replay-visible, and removable;
- future distribution boundary without immediate distributed implementation.

`Plan.md`, `DESIGN_DECISIONS.md`, `TRAIT_BOUNDARIES.md`, `SEMANTICS.md`, `SEMANTIC_IDENTITY.md`, `PROVENANCE_KNOWLEDGE.md`, `BENCHMARKING.md`, and `IMPLEMENTATION_PLAN.md` provide narrower supporting contracts. This document is the complete top-level architecture that ties them together.
