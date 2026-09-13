# Contributing to Angryier

Thank you for your interest in contributing to Angryier. This document covers the basics.

## Project status

Angryier is a native Rust symbolic/concolic execution engine for Intel 64. The architecture is frozen (54 locked decisions). Implementation is in progress — Phases 0–3 and Phase 5 foundations are complete; the handwritten semantic corpus (Phase 4) is the next active phase.

See [`docs/status/scaffold.md`](docs/status/scaffold.md) for per-crate implementation status and [`docs/status/implementation-plan.md`](docs/status/implementation-plan.md) for the phase order.

## Build and check

```bash
# Full check: format, compile, clippy, test
./scripts/check.sh

# Or individually:
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

The workspace enforces strict lints:
- `unsafe_code = "forbid"`
- `panic = "deny"`
- `unwrap_used = "deny"`
- `expect_used = "deny"`

No placeholder backend is permitted to pretend a feature exists. Missing native integrations must fail explicitly until implemented.

## Architecture rules

Before contributing code, read the relevant architecture documents:

- [`docs/architecture/overview.md`](docs/architecture/overview.md) — global invariants and three-plane architecture
- [`docs/architecture/crates.md`](docs/architecture/crates.md) — crate boundaries and dependency direction
- [`docs/design/decisions.md`](docs/design/decisions.md) — locked design decisions
- [`docs/design/trait-boundaries.md`](docs/design/trait-boundaries.md) — Rust trait and ownership boundaries

Key rules:
1. **Decode is not semantics.** XED identifies instructions; Angryier owns their semantics.
2. **Host capability is not target capability.** Target support must not disappear because the host lacks a feature.
3. **Published semantics are immutable.** Sealed blocks are content-addressed and never mutated in place.
4. **Exact identity and similarity are separate.** `ContentId` is authoritative; `SemanticFingerprint` is advisory.
5. **Solver uncertainty is never silently UNSAT.** UNKNOWN/TIMEOUT/RESOURCE_LIMIT/BACKEND_ERROR are distinct.
6. **Workers do not block on QIHSE/KEYSTONE.** Persistence is asynchronous.
7. **PROVE never silently approximates.** EXPLORE/HUNT relax policy only with explicit provenance.

## Code style

- Follow `rustfmt` with the project's `rustfmt.toml` (max_width = 120).
- No `unwrap()`, `expect()`, or `panic!()` in library crates — return `Result` instead.
- No `unsafe` in core crates. FFI crates (XED, Z3, Bitwuzla, JIT) may use narrowly audited `unsafe` at adapter boundaries only.
- Prefer compact code: collapse duplicate branches, avoid unnecessary nesting, share abstractions.
- Do not add or remove comments unless asked. Preserve existing comments.

## Commit messages

```
Summary of change in one line

Optional longer description of why, not what.

Generated with [Devin](https://devin.ai)

Co-Authored-By: Devin <158243242+devin-ai-integration[bot]@users.noreply.github.com>
```

Focus on **why** the change is needed, not **what** changed (the diff shows that).

## Pull requests

1. Fork the repository and create a feature branch.
2. Ensure `./scripts/check.sh` passes.
3. Write tests for new functionality.
4. If you change architecture-relevant code, update the corresponding docs in `docs/`.
5. Do not claim semantic support that has not passed validation gates.

## License

By contributing, you agree that your contributions are licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later), as specified in the [`LICENSE`](LICENSE) file and `Cargo.toml`.
