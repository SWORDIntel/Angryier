# Solver Architecture

> **Implementation status:** Partially implemented. `angryier-solver` (375 lines) provides the backend-neutral query/result model, result classes (SAT/UNSAT/UNKNOWN/TIMEOUT/RESOURCE_LIMIT/BACKEND_ERROR), and canonical query identity. `angryier-solver-z3` and `angryier-solver-bitwuzla` are fail-closed stubs — no native FFI yet.

---

## Worker-local solver state

Each worker owns or leases its own incremental contexts. Z3/Bitwuzla context objects are never shared across threads behind a global mutex.

## Solver-neutral query model

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

UNKNOWN/TIMEOUT/RESOURCE_LIMIT/BACKEND_ERROR may never be silently promoted to UNSAT.

## Shared-context batched satisfiability

The API supports a common context plus many predicates:

```text
Phi + {p1, p2, p3, ...}
```

This is a first-class primitive because sibling branches often share most path constraints.

## Portfolio scheduling and adaptive preemption

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

## Persistent solver knowledge

> **Implementation status:** Scaffolded. The knowledge plane contracts exist but no persistent storage is implemented.

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

### Reuse hierarchy

1. exact canonical query hit;
2. alpha-equivalent candidate;
3. validated UNSAT-core reuse;
4. implication/subsumption candidate;
5. generalized fact candidate;
6. similarity-guided advisory retrieval.

Every correctness-affecting hit validates all required dependency keys before authorization.

### Poisoning resistance

High-entropy fuzz inputs are an explicit adversarial corpus for cache-validity testing. Structurally similar but logically distinct constraints must never be conflated because of fingerprint or subsumption mistakes.
