# Scaffold Status

## Meaning of `scaffolded`

`Scaffolded` means a crate has a manifest plus an owned Rust API/data-contract boundary. It does **not** mean the feature is implemented or validated.

## Present now

The repository has boundaries for shared identities, architecture/Intel 64, XED adaptation, semantics and generation, semantic identity/evidence, execution IR, expressions, memory, state, taint, execution, atomic ledger, replay, solvers, scheduling, provenance, knowledge, learned fusion, models, loading/state import, fuzzing, telemetry, local storage/WAL, JIT, QIHSE, KEYSTONE, plugins, benchmarks, CLI and future distribution.

## Intentionally not implemented

- native Intel XED FFI and XED library discovery;
- actual Intel instruction semantic definitions or generated semantic corpus;
- concrete/symbolic interpreter behavior;
- page-backed COW memory implementation;
- expression arena/hash-consing implementation;
- Z3 or Bitwuzla FFI/translation;
- work-stealing/NUMA scheduler implementation;
- replay engine or durable execution ledger backend;
- QIHSE/KEYSTONE SDK bindings and persistence workers;
- learned embedding models/training pipeline;
- Cranelift/native JIT;
- fuzzer-specific AFL++/libFuzzer adapters;
- live process capture;
- distributed execution scheduler.

No placeholder backend is permitted to pretend these features exist. Missing native integrations must fail explicitly until implemented.

## Validation contract

The repository-level `scripts/check.sh` and CI workflow establish the intended baseline: formatting, workspace compilation, Clippy with warnings denied, and tests. Passing CI is the criterion for calling the scaffold build-clean; repository structure alone is not.
