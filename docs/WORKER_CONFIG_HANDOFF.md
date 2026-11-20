# Angryier — worker-config handoff checkpoint

**Updated:** 2026-11-19
**Scope:** encrypted, pinned worker configuration handoff for distributed campaigns.
**Base and verified head:** `e3aa8dbc0f602b8f2fad5a2198d6423731cb5a9d` on `main`, pushed to `origin`.

This is a dated checkpoint, not a substitute for checking the current Git ref. It records local validation only; no cross-host deployment of this feature has been performed.

## Implemented

- `crates/angryier-campaign/src/main.rs`: `worker-config` generator with `--output`, coordinator-local `--sign-key PATH`, locally hashed image `--binary`, optional worker-side destination `--worker-binary`, and remote `--key-file` pathname. `worker --config FILE` is exclusive; raw-flag worker/coordinator and local roles are unchanged.
- `crates/angryier-campaign/src/worker_config.rs`: strict, versioned **v2 AEAD-encrypted TOML envelope**. XChaCha20-Poly1305 with a fresh 24-byte OS-random nonce and a SHA-256-domain-separated key derived from the separately provisioned per-worker 32-byte pairwise secret. Only version, worker-side bootstrap key-file path, nonce and ciphertext/tag are visible. Version and key path are authenticated as AAD; executable/image SHA-256 pins, identity, listen address, connection cap, image mode, entry, symbolic register and the ten campaign limits are encrypted and authenticated. No key bytes, local sign-key path or static in-binary secret are serialized. v1 signed plaintext is rejected. Private non-overwriting creation (0600), size, owner/mode and strict parsing checks apply where supported.
- `crates/angryier-campaign/src/lib.rs`: `serve_pinned` validates the image bytes actually read for execution **before** binding and printing `READY`, closing the earlier image path TOCTOU gap. Executable identity is checked at load. The coordinator remains the sole durable-ledger writer and independently verifies worker evidence.
- `crates/angryier-campaign/tests/worker_config.rs`: real-process confidentiality, tamper/wrong-key rejection before `READY`, private non-overwriting output, and a bounded worker/coordinator exchange requiring a coordinator-accepted `ReplayVerification::Verified` witness with ledger reopening. Module and CLI tests cover strict fields, path portability and pins.
- Operator documentation: `README.md`, `docs/CLI.md`, `docs/design/sustained-hpc-deployment.md`, `docs/guides/distributed-campaigns.md` (0700 config dir / 0600 file, separate key provisioning, loopback over an authenticated confidential tunnel).

## Validation on this revision

- `cargo test -p angryier-campaign --locked --offline`: passed across unit, integration and doc tests.
- `cargo clippy --workspace --all-targets --locked --offline -- -D warnings`: passed.
- `cargo fmt --all -- --check` and `git diff --check`: passed.
- Independent final AEAD review reported no actionable new defects.

## Deployment and trust boundaries

- Coordinator and worker must run byte-identical `angryier-campaign` binaries with matching target-image bytes. Generator `--sign-key` reads the coordinator's copy of the per-worker key; `--key-file` records the worker-side path. Provision the same 32-byte secret separately to that worker, distinct per worker.
- Config confidentiality and authenticity do not survive compromise of the worker's secret or account. The visible key path bootstraps decryption and is not independently pinned outside the envelope, so an attacker able to replace the TOML *and* supply a worker-readable key can forge a new envelope. Use private key provisioning and authenticated transfer.
- Application-frame HMAC authenticates distributed traffic but does not encrypt raw TCP. Cross-host endpoints must stay loopback through independently authenticated, confidential SSH or mTLS tunnels. Executable SHA-256 does not establish runtime library compatibility.
- Whole-binary exhaustion is not implied: campaigns cover one pinned root within finite declared bounds.

## Next

Cross-host smoke test, which has not happened: provision identical executable and image bytes plus the separate pairwise key on a worker, transfer a generated TOML, run `worker --config FILE` through the required tunnel, then run a small bounded coordinator campaign and confirm a replay-verified witness survives ledger reopen. Record binary/image hashes, toolchain and node versions with the result.
