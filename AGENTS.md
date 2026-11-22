# Angryier Agent Guidelines

Parent suite control panel (`../..`): [KP15-SUITE README](../../README.md) · [`kp15ctl`](../../bin/kp15ctl) · [Suite AGENTS](../../AGENTS.md) · [Appliance Operations](../../docs/APPLIANCE_OPERATIONS.md).

<!-- START: RELATIVE_PATHS_RULE -->
## Path Resolution Policy
- **Development & Design Phase**: Absolute paths (e.g., `/home/john/...`) and standard tool pathing are fully permitted.
- **Appliance Deployment Tooling**: Code and scripts intended for deployment inside the Proxmox VM (VM 9212 / appliance runtime) should use dynamic resolution (`Path(__file__).resolve().parent`, `$(dirname "$0")`, or relative paths) to ensure portability across VM environments.
<!-- END: RELATIVE_PATHS_RULE -->

## Distributed Campaigns & `ET_REL` (`.ko`) Invariants
- **Executable & image pinning:** `angryier-campaign` coordinator and workers must run byte-identical binaries (`--locked --offline` release builds) and byte-identical target images (`serve_pinned` hashes the exact loaded byte vector before listening). External `.ko` fixtures in tests use `ANGRYIER_KO_FIXTURE`, never hard-coded host paths.
- **Transport & worker config:** Distributed TCP must bind loopback behind an authenticated confidential tunnel (SSH `-L` or mTLS); wire HMAC (`WIRE_VERSION = 3`, masked prelude digest) authenticates frames only. `worker-config` emits a v2 XChaCha20-Poly1305 envelope containing only the worker key-file **path**, never key bytes; keep keys/configs mode `0600` in `0700` dirs.
- **State & replay soundness:** Keep `kernel_models` deterministic and path-local inside `Process.state.memory` (`0x2000_0000` heap slots/refcount metadata, `0x3000_0000` SysV ABI scratch) so forks and `verify_remote` stay isolated. Never prune `Unsat` forks inside `sustained_pool::advance_sustained` (`unsat_child_cannot_claim_complete_without_atomic_proof`), and never silently advance `unit.prefix` index `matched` on non-forked concrete branches (`history_len` tracks `branch_history` separately).
- **Witness & target scoring honesty:** Distinguish strict verified-terminal witnesses (`observed`: `Completed` + `Terminal` + `ReplayVerification::Verified`) from coordinator-replayed path hits (`trace_observed`: `path.blocks`), and keep `--find` / `--avoid` / `--find-symbol` / `--avoid-symbol` report-only outside campaign identity.
- **CLI shortcuts:** Prefer `--profile ko-handler` (`--symbolic-reg sysv --budget 256:256:45000`), `--budget S[:P[:W]]`, `--root-symbol NAME`, and `--find-symbol NAME[+OFFSET]`. Clean build trees with `cargo clean` when finished.
