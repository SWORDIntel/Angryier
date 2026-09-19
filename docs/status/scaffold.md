# Scaffold Status

## Meaning of `scaffolded`

`Scaffolded` means a crate has a manifest plus an owned Rust API/data-contract boundary. It does **not** mean the feature is implemented or validated.

## Present now

The repository has boundaries for shared identities, architecture/Intel 64, XED adaptation, semantics and generation, semantic identity/evidence, execution IR, expressions, memory, state, taint, execution, atomic ledger, replay, solvers, scheduling, provenance, knowledge, learned fusion, models, loading/state import, fuzzing, telemetry, local storage/WAL, JIT, QIHSE, KEYSTONE, plugins, benchmarks, CLI and future distribution.

## Implemented (real logic, not just contracts)

| Crate | What's implemented | Lines |
|---|---|---|
| `angryier-types` | ContentId, SemanticFingerprint, all cross-plane IDs, versions, fidelity profiles, dependency keys | 234 |
| `angryier-core` | Engine-level context contracts | 78 |
| `angryier-arch` | ISA-neutral decoder traits, DecodedInstruction, operand model | 260 |
| `angryier-arch-intel64` | Intel 64 registers, features, CPU profiles, parent register map, segment IDs | 447 |
| `angryier-decode-xed` | XED normalization boundary, metadata, error types (no native FFI) | 453+205+72 |
| `angryier-semantics` | Semantic types, ops, provider/builder traits, sealed block builder | 403+561 |
| `angryier-ir` | AngryIR types, lowering, verification | 126+545+233 |
| `angryier-expr` | Expression DAG, hash-consing, arena, constant folding | 701 |
| `angryier-memory` | Layered COW memory, byte values, symbolic overlay contracts | 539 |
| `angryier-state` | Persistent state, register state, fork, fidelity ledger, ownership | 495 |
| `angryier-execution` | Concrete interpreter with AngryIR execution, plus single-block symbolic evaluation (`symbolic.rs`) for branch solving | 2820 + 644 |
| `angryier-ledger` | Atomic ledger contract, epoch model, rejection classes, concurrent commit validation | 503 |
| `angryier-solver` | Solver-neutral query/result model, result classes, canonical identity, portfolio router, batch solver, cache | 679 |
| `angryier-jit` | JIT validity contract, code-page versioning | 144 |
| `angryier-semantics-intel64` | Handwritten Intel 64 semantic corpus (357 forms: 93 foundational integer/control-flow + 94 Phase 4a partial-write/bit-scan/32-bit forms + 170 Phase 4b SSE/SSE2/SSSE3/SSE4.1/SSE4.2 SIMD forms including scalar/packed float with upper-lane preservation, packed integer, shifts, compares, min/max, shuffle, unpack, saturate, PMADDWD/PMADDUBSW, horizontal add/subtract, PABS/PSIGN, PMULHRSW, PCMPEQQ/PMULDQ/PBLENDVB, PMOV sign/zero extend, immediate blends, dot products, PEXTRB/PINSRB, scalar float compare with flags, packed/scalar rounding, PTEST, CRC32, dword/qword extract/insert, INSERTPS/EXTRACTPS, ROL/ROR r32 CL, CMPPS/CMPPD, MINPS/MAXPS, MOVMSKPS/PD, PMOVMSKB, HADDPS/PD/HSUBPS/PD, PMAXSQ/PMINSQ, MOVAPS/PD/UPS/UPD, MOVSS/SD, MPSADBW, PHMINPOSUW, PCMPGTQ, PSLLDQ/PSRLDQ, PANDN) | 592+370+666 |
| `angryier-replay` | Replay capsule store, validator, basic replay engine with monotonic sequence | ~250 |
| `angryier-taint` | In-memory taint engine with labels, states, promotion threshold, transform/merge/sink | ~567 |
| `angryier-provenance` | In-memory provenance store, adaptive trace governor, batching sink, tier-based eviction | ~570 |
| `angryier-storage` | In-memory WAL with checkpoint replay, priority-aware eviction, retention policy | ~420 |
| `angryier-scheduler` | In-memory work-stealing scheduler with per-worker queues, NUMA distance model, greedy scoring | ~834 |
| `angryier-knowledge` | In-memory knowledge store with exact-match cache, dependency graph with transitive invalidation | ~320 |
| `angryier-models` | In-memory environment model with operation table, fidelity enforcement, summary provider with exact lookup | ~440 |
| `angryier-telemetry` | In-memory telemetry sink with metric aggregation, time-series recording, backpressure tracking | ~400 |
| `angryier-loader` | ELF64 loader (headers, program headers, segments, entry point, static symbol table), in-memory image loader, state importer (rejects live capture) | 1147 |
| `angryier-runtime` | Pipeline glue: ELF64 load → decode → semantics → AngryIR lowering → concrete interpreter → SimProcedure dispatch, with lowered-block cache, XED instruction-class form mapping (`form_map.rs`, feature-gated), symbolic trace evaluation, and Z3-backed branch solving | 1047 (+583 form map) |
| `angryier-fuzz` | In-memory fuzz bridge with stage-gated seed/coverage/hint submission | ~290 |
| `angryier-fusion` | In-memory fusion model with identity/constant encoders, element-wise averaging | ~430 |
| `angryier-qihse` | In-memory QIHSE adapter with exact fetch, fingerprint vector query, duplicate rejection | ~280 |
| `angryier-keystone` | In-memory KEYSTONE adapter with inverted index, substring lookup, duplicate rejection | ~380 |
| `angryier-distribution` | In-memory work codec with deterministic binary frame encode/decode round-trip | ~560 |
| `angryier-plugins` | In-memory plugin registry with duplicate-name rejection, sorted lookup | ~150 |
| `angryier-bench` | In-memory benchmark sink with validation, sorted records, aggregate summary | ~435 |
| `angryier-semantics-gen` | In-memory semantic compiler with origin parsing, coverage manifest, duplicate form rejection | ~390 |
| `angryier-semantic-contracts` | In-memory sealed/derived blocks, identity transformation, fidelity acceptance policy | ~400 |
| `angryier-cli` | Basic CLI with version/status/crates/help subcommands (no external deps) | ~430 |

## Native integrations (implemented and tested)

- `angryier-solver-z3-ffi` — real Z3 FFI bridge using `z3-sys` against the system `libz3`. Translates Angryier expression trees (bit-vector constants, symbols, arithmetic, comparisons, Boolean ops, ITE, concat, extract, zero/sign-extend) to Z3 ASTs, asserts path constraints and predicate, returns real `Sat`/`Unsat`/`Unknown` outcomes with model extraction. 4 tests pass.
- `angryier-solver-bitwuzla-ffi` — real Bitwuzla FFI bridge using `bitwuzla-sys` (vendored CaDiCaL build). Translates Angryier expression trees to Bitwuzla terms, asserts path constraints and predicate, returns real `Sat`/`Unsat`/`Unknown` outcomes with binary-string model extraction. 4 tests pass.
- `angryier-arch-xed-ffi` — real Intel XED decoder via `xed-sys` (builds Intel XED from source). Decodes Intel 64 byte sequences through `angryier-decode-xed`'s safe normalization boundary, mapping iclass/ISA-set/operands/registers to Angryier's architecture-neutral `DecodedInstruction`. 11 tests pass covering MOV/ADD/NOP/RET/PUSH/POP, memory operands, batch sweep, empty input, and invalid bytes. The crate also re-exports the XED instruction-class namespace (`iclass`) used by the runtime's form mapping.

## Safe adapter wiring

The safe adapter crates connect to their native FFI bridges behind optional Cargo features:

- `angryier-solver-z3` — `ffi` feature. When enabled, depends on `angryier-solver-z3-ffi` and exposes `Z3Backend::native_ffi(reader) -> Result<Z3Backend<Z3FfiBridge>, Z3FfiError>`. The safe adapter validates query identity and converts native failures to `BackendError`, so callers never observe a false `Unsat` from a native translation/linking failure. 2 wiring tests pass (SAT + UNSAT).
- `angryier-solver-bitwuzla` — `ffi` feature. When enabled, depends on `angryier-solver-bitwuzla-ffi` and exposes `BitwuzlaBackend::native_ffi(reader) -> Result<BitwuzlaBackend<BitwuzlaFfiBridge>, BitwuzlaFfiError>`. Same safe-adapter guarantees. 2 wiring tests pass (SAT + UNSAT).
- `angryier-arch-xed-ffi` — already wired through `angryier-decode-xed`'s safe normalization boundary. The FFI crate's `XedDecoder` implements `angryier_arch::Decoder` and delegates to `BoundXedDecoder<NativeXedBackend>`, which validates and normalizes all native decode output. No additional wiring feature needed.

Without the `ffi` features, the adapter crates build and test normally (returning `BackendError` for any solve attempt), preserving the workspace's default zero-native-dependency build.

## Scaffolded only (contract boundaries, fail-closed)

- `angryier-solver-z3` — safe Z3 adapter; returns `BackendError` without the `ffi` feature (the real FFI lives in `angryier-solver-z3-ffi`)
- `angryier-solver-bitwuzla` — safe Bitwuzla adapter; returns `BackendError` without the `ffi` feature (the real FFI lives in `angryier-solver-bitwuzla-ffi`)

## Intentionally not implemented

- **partial**: a handwritten Intel 64 semantic corpus exists (357 forms) but does not cover the full ISA; the native XED decoder in `angryier-arch-xed-ffi` covers instruction decoding but not semantic lowering;
- page-backed COW memory implementation (contract exists, internals are scaffolded);
- expression arena/hash-consing implementation (contract exists, arena is scaffolded);
- **partial**: in-memory work-stealing scheduler exists; NUMA-aware OS-level scheduling remains future work;
- **partial**: in-memory replay engine, WAL, knowledge store, and telemetry exist; durable/persistent backends remain future work;
- **partial**: in-memory QIHSE/KEYSTONE adapters exist; native SDK bindings and persistence workers remain future work;
- **partial**: in-memory fusion model exists; learned embedding models/training pipeline remain future work;
- **partial**: in-memory fuzz bridge exists; AFL++/libFuzzer-specific adapters remain future work;
- **partial**: in-memory work codec exists; distributed execution scheduler remains future work;
- **partial**: in-memory image loader and state importer exist; live process capture remains future work;
- **partial**: in-memory semantic compiler exists; full declarative generator pipeline remains future work;
- Cranelift/native JIT;

No placeholder backend is permitted to pretend these features exist. Missing native integrations must fail explicitly until implemented.

## Test coverage

43 test binaries pass (0 failures) across the workspace, 819 tests total:

| Crate | Tests |
|---|---|
| angryier-arch | 2 |
| angryier-arch-intel64 | 7 |
| angryier-arch-xed-ffi | 11 |
| angryier-bench | 17 |
| angryier-cli | 18 |
| angryier-core | 1 |
| angryier-decode-xed | 6 |
| angryier-distribution | 15 |
| angryier-execution | 21 |
| angryier-expr | 30 |
| angryier-fusion | 14 |
| angryier-fuzz | 13 |
| angryier-ir | 11 |
| angryier-jit | 4 |
| angryier-keystone | 13 |
| angryier-knowledge | 23 |
| angryier-ledger | 18 |
| angryier-loader | 27 |
| angryier-runtime | 4 |
| angryier-memory | 41 |
| angryier-models | 27 |
| angryier-plugins | 9 |
| angryier-provenance | 15 |
| angryier-qihse | 14 |
| angryier-replay | 15 |
| angryier-scheduler | 17 |
| angryier-semantic-contracts | 15 |
| angryier-semantics | 5 |
| angryier-semantics-gen | 14 |
| angryier-semantics-intel64 | 9 (unit) + 258 (integration) |
| angryier-solver | 20 (unit) + 9 (portfolio integration) |
| angryier-solver-bitwuzla | 3 |
| angryier-solver-bitwuzla-ffi | 4 |
| angryier-solver-z3 | 3 |
| angryier-solver-z3-ffi | 4 |
| angryier-state | 25 |
| angryier-storage | 14 |
| angryier-taint | 23 |
| angryier-telemetry | 17 |
| angryier-types | 3 |

Feature-gated native-pipeline tests are not part of the default workspace run. `cargo test -p angryier-runtime --features xed,z3` adds 11 tests (3 test binaries) covering native XED decoding through the runtime, the XED instruction-class form mapping, real-binary end-to-end execution with SimProcedure dispatch, explicit failure for unmapped instructions, and Z3-backed branch solving that generates a new input and replays it.

## Validation contract

The repository-level `scripts/check.sh` and CI workflow establish the intended baseline: formatting, workspace compilation, Clippy with warnings denied, and tests. Passing CI is the criterion for calling the scaffold build-clean; repository structure alone is not.
