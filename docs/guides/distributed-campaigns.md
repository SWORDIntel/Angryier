# Distributed sustained campaigns: operator guide

`angryier-campaign` is a bounded x86_64 Linux coordinator/worker for replaying a pinned image across 1, 2, or 4 worker processes. It is a loopback-only transport milestone—not a general cluster runtime. The same executable also provides an independent **local** campaign mode that uses no network at all (no listener, no peers, no worker transport); see [local-campaigns.md](local-campaigns.md). This guide is operational; see [deployment design](../design/sustained-hpc-deployment.md) for implementation and validation details, and [transport security](../design/sustained-transport-security.md) for protocol boundaries.

## Prerequisites and build identity

- Use x86_64 Linux on each participating host. The campaign builds with native XED and Z3 integrations; install the Rust toolchain and native build prerequisites required by the workspace (including a C/C++ toolchain, Python for XED generation, and Z3 development libraries). `cargo` must be able to resolve the locked dependencies.
- Build the campaign on every host from the same staged source revision:

  ```sh
  cargo build -p angryier-campaign --release --locked
  ```

  For a source tree whose dependencies are already cached, `cargo build -p angryier-campaign --offline` is also supported by the deployment procedure. The executable is `target/release/angryier-campaign` (or `target/debug/angryier-campaign` for an unoptimized build). One compiled executable provides **both roles**: `worker` and `coordinator` are invocation-time roles of the same binary, not separate programs, so the byte comparison below covers both roles by construction.
- Select one build procedure and environment for the entire run. Compare the **actual executable bytes** on every host, for example:

  ```sh
  sha256sum target/release/angryier-campaign
  ```

  Record the digest and require an exact match before starting. The sealed profile pins the executable SHA-256 as well as the image, semantic profile, resolved entry, policy, solver policy, and limits. A `--build-id` token is useful operator labeling, but it does not replace byte identity. Dynamically linked XED/Z3 libraries are not included in the executable hash; pin those and the host environment separately. Do not claim independent native-build reproducibility by copying one binary to every node.
- Stage the same target image on coordinator and workers and verify its digest out of band. All processes must use matching image mode, entry, symbolic register, build ID, executable, and campaign limits.

The deployment design records one reproducible release-build SHA-256 from a prior three-host fixture run. Treat it as historical evidence, not the expected hash of your current checkout; compute and compare the bytes you will actually run.

## Pairwise keys and worker identities

Every coordinator/worker pair needs a different unpredictable **32-byte raw key**. Keep the key out of arguments, logs, source control, and shell history. Provision it independently to both endpoints using your existing secret-distribution system, and require mode `0600` on each copy. For a disposable local test, a file can be created as follows; do not use a shared or committed location:

```sh
umask 077
head -c 32 /dev/urandom > /secure/path/worker-a.key
chmod 600 /secure/path/worker-a.key
```

Repeat with a fresh random key for each additional worker, then distribute each file securely to its matching worker. The program rejects keys with the wrong length, all-zero keys, group/world-readable Unix permissions, or duplicate pairwise contents in a pool. Key-file paths below are placeholders, not key values.

Give every worker a distinct ID token (1–128 ASCII letters, digits, `.`, `_`, or `-`); the ID used in its `--worker-id` must exactly match the ID in its coordinator `--peer` entry. Pool IDs, addresses, and key contents must all be distinct. Use exactly 1, 2, or 4 `--peer ID@LOOPBACK_ADDR@KEY_FILE` entries. Pool mode cannot be mixed with legacy coordinator `--connect`, `--key-file`, or `--worker-id` options.

## Start locally first

On one host, open two terminals. Start the worker and wait for its `READY` line before starting the coordinator. This example uses the supported defaults (ELF entry from the loader, symbolic RBX) and a finite worker connection count:

```sh
BIN=/absolute/path/to/pinned.elf
KEY=/secure/path/worker.key
BUILD_ID=campaign-v1

./target/release/angryier-campaign worker \
  --binary "$BIN" --key-file "$KEY" --build-id "$BUILD_ID" \
  --worker-id worker-a --listen 127.0.0.1:30031 --connections 8
```

In terminal two, use the same values and the single-worker legacy connection form:

```sh
./target/release/angryier-campaign coordinator \
  --binary "$BIN" --key-file "$KEY" --build-id "$BUILD_ID" \
  --worker-id worker-a --connect 127.0.0.1:30031 \
  --ledger /secure/path/campaign.ledger
```

For a repeated campaign, choose `--connections 0` so the worker serves until stopped. A finite cap counts accepted worker sessions; there is no hidden reconnect/retry. Pool workers require `--worker-id`; legacy single-worker mode defaults to `worker` if omitted. Stop the coordinator before stopping the workers.

## Pinned worker-config handoff

To prepare a remote worker without manually reproducing worker flags, use the **same compiled `angryier-campaign` executable** on the coordinator to generate a v2 AEAD-encrypted TOML envelope. `/srv/angryier/image.elf` must exist on the generator; `/remote/absolute/image.elf` is a normalized absolute image path on the worker and need not exist on the generator. Use an image already suitable for the campaign and match its image mode, entry, symbolic register and all ten sealed limits on the coordinator:

```sh
angryier-campaign worker-config --binary /srv/angryier/image.elf \
  --worker-binary /remote/absolute/image.elf --build-id release-v1 \
  --worker-id worker-a --sign-key /LOCAL/coordinator/worker-a.key \
  --key-file /remote/key/worker-a.key \
  --listen 127.0.0.1:30031 --connections 0 --output /staging/worker-a.toml
```

For non-default campaigns, append the **same** `--image-mode`, `--entry`, `--symbolic-reg` and `--max-steps`, `--max-path-steps`, `--max-active-states`, `--max-path-depth`, `--max-loop-visits`, `--max-solver-ms`, `--max-wall-ms`, `--max-ram-bytes`, `--max-disk-bytes`, `--max-trace-bytes` values that the coordinator will use. The generator creates a private mode-0600 TOML and refuses to overwrite the output path. The XChaCha20-Poly1305 ciphertext encrypts/authenticates all pinned campaign settings, including executable and image digests, worker-side image path, ID, listener, connection cap, and resolved numeric limits, using a fresh random 24-byte nonce. The v2 version, nonce and worker-side bootstrap key-file **path** remain visible in TOML; the version and key path are authenticated associated data (AAD). Raw key bytes and the coordinator-local `--sign-key` path are never placed in TOML, and no compiled static embedded secret is used. The worker-side pathname need not exist on the generator, but the coordinator-local signing key must.

Stage the **identical compiled executable bytes** on the worker and compare SHA-256 on both hosts; also stage matching native runtime dependencies (not covered by that hash). Copy the target image to `/remote/absolute/image.elf` and compare its SHA-256 against `/srv/angryier/image.elf`; the worker path must be canonical, not a symlink or `.`/`..` alias. Transfer the TOML using an authenticated confidential deployment channel, then, as the worker account, install it as a regular file owned by that account:

```sh
install -d -m 0700 "$HOME/.config/angryier"
install -m 0600 /staging/worker-a.toml "$HOME/.config/angryier/worker.toml"
angryier-campaign worker --config ~/.config/angryier/worker.toml
```

Before running the generator, provision the distinct raw 32-byte pairwise secret **separately** at `/LOCAL/coordinator/worker-a.key` with mode `0600`, and a matching copy at `/remote/key/worker-a.key` on the worker, also mode `0600`. The required `--sign-key` names the existing validated coordinator-local key used to encrypt/authenticate the payload; `--key-file` exposes the worker-side key pathname so the worker can locate its separately provisioned decryption key. Neither the coordinator-local key path nor the key bytes are serialized. Reuse the coordinator-local copy for its `--peer` entry. The worker authenticates/decrypts the envelope before honoring pinned settings or printing `READY`; tampering or a mismatched key fails closed. This does not protect against possession of the worker key or worker-account control, and the executable-hash pin does not eliminate binary-hash time-of-check/time-of-use risk. The worker's `--config` form accepts no extra flags. It fails closed on unknown TOML versions/fields, nonprivate or symlink TOML, noncanonical/aliased image paths, nonloopback listeners, and executable/image SHA-256 mismatches (including image changes before bind). The old direct `worker --binary ... --key-file ...` CLI remains supported. Generation does not deploy the worker, provide TLS, or encrypt application frames.

Set up the [authenticated confidential loopback tunnel](#remote-hosts-tunnel-only-never-plaintext) before connecting the coordinator. Its `--peer worker-a@127.0.0.1:31031@LOCAL_KEY` still refers to the **coordinator-side** local key file (`LOCAL_KEY` is a placeholder), while `127.0.0.1:31031` forwards to worker `127.0.0.1:30031`; use the same build ID, image and limits. This is a deployment procedure, not a claim that the current checkout has undergone a new cross-host test. See also the [CLI option reference](../CLI.md#distributed-workercoordinator-roles).

For multi-host fan-out (hundreds of one-worker campaigns, the dispatch pattern, `sshd` limits and measured failure clusters) see [cluster-operations.md](cluster-operations.md).

## Two and four workers

For two workers, run one worker command per host (or process), with unique IDs, loopback listen ports, and their corresponding key files:

```sh
./target/release/angryier-campaign worker --binary "$BIN" \
  --key-file /secure/path/worker-a.key --worker-id worker-a \
  --build-id "$BUILD_ID" --listen 127.0.0.1:30031 --connections 0

./target/release/angryier-campaign worker --binary "$BIN" \
  --key-file /secure/path/worker-b.key --worker-id worker-b \
  --build-id "$BUILD_ID" --listen 127.0.0.1:30032 --connections 0
```

The coordinator uses one `--peer` per worker and owns the only ledger writer:

```sh
./target/release/angryier-campaign coordinator --binary "$BIN" \
  --build-id "$BUILD_ID" \
  --peer worker-a@127.0.0.1:30031@/secure/path/worker-a.key \
  --peer worker-b@127.0.0.1:30032@/secure/path/worker-b.key \
  --ledger /secure/path/campaign.ledger
```

For four workers, add workers `worker-c` and `worker-d` on unique loopback ports with their own distinct keys, then add matching `--peer` entries. Do not start a second coordinator against the same ledger. Grants may run concurrently, but the coordinator reserves, independently replays and verifies, then admits and commits outcomes in reservation order.

## Remote hosts: tunnel only, never plaintext

The application transport authenticates frames with HMAC but does **not encrypt them**. It rejects non-loopback endpoints. Never expose its listener through a plaintext proxy or connect the raw protocol directly across a network. For remote workers, start SSH local forwards from the coordinator host to each worker's loopback listener. Authenticate SSH independently, pin/check the expected host keys (`StrictHostKeyChecking=yes` with a managed `known_hosts` file), and do not permit plaintext fallback. Protect the key files and the tunnel endpoints; HMAC is additional application authentication, not channel confidentiality or host authentication.

For example, after a remote worker listens on `127.0.0.1:30031`, run this on the coordinator host (use a correctly provisioned host-key file and authorized account):

```sh
ssh -N -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile=/secure/path/known_hosts \
  -L 127.0.0.1:31031:127.0.0.1:30031 operator@worker-a.example
```

Keep that tunnel running. The coordinator's peer then points to its **local** forwarded loopback port, for example:

```sh
./target/release/angryier-campaign coordinator --binary "$BIN" \
  --build-id "$BUILD_ID" \
  --peer worker-a@127.0.0.1:31031@/secure/path/worker-a.key \
  --ledger /secure/path/campaign.ledger
```

Create a second independently pinned SSH forward on local port `31032` for a second remote worker, and analogous forwards for workers three and four. Each remote SSH destination must resolve to the intended host identity; each remote forwarding target remains `127.0.0.1:<worker-listen-port>`. Do not bind tunnel endpoints to wildcard interfaces. The coordinator's peer address must remain loopback. mTLS is another possible independently authenticated confidential tunnel, but it is not implemented by Angryier.

## Bounds, partial outcomes, and resume

The coordinator runs within declared global `--max-steps` and `--max-wall-ms` bounds and seals the configured exploration limits into the campaign manifest. Supported integer options are `--max-steps`, `--max-path-steps`, `--max-active-states`, `--max-path-depth`, `--max-loop-visits`, `--max-solver-ms`, `--max-wall-ms`, `--max-ram-bytes`, `--max-disk-bytes`, and `--max-trace-bytes`. Defaults, in that order, are 128, 64, 2, 64, 64, 10000 ms, 30000 ms, 64 MiB for ELF / 576 MiB for `pe-driver`, 1 MiB, and 1 MiB. Set identical values on coordinator and every worker. `--max-ram-bytes` is a per-process/campaign mapping bound, **not** an aggregate RSS cap; use OS-level resource controls for aggregate memory and supervision. ELF files are capped at 32 MiB and raw PE files at 512 MiB.

The CLI prints its report, then exits nonzero if unresolved owned work remains (`campaign partial`). Deferred/unknown work is not silently retried. A run that stops at a declared limit can still have a useful durable partial ledger; report `complete_within_declared_bounds=false` accurately. Do not describe a partial ledger as complete.

To resume **queued work or interrupted active grants**, preserve the exact ledger and all pinned inputs. Confirm the prior coordinator has stopped, repair connectivity, and restart one coordinator with the identical executable, image, build ID, entry, mode, symbolic register, and limits. Interrupted active grants are requeued on reopen; failed connections revoke their grant and advance its generation. Execution can repeat, so this is not physically exactly-once execution. **Deferred, unknown and failed records are not automatically requeued by restart**; the distributed CLI and this high-level Rust wrapper currently expose no retry option for them. Lower-level `SustainedCampaign::retry_deferred` exists for a separately engineered pinned-root workflow—do not claim a simple CLI restart resolves these records. Changed binary, executable build, semantic version, limits, or pinned input cannot resume the old manifest. To change budgets, start a separately identified campaign/ledger. Never concurrently share-write or manually edit the ledger.

## Quiescent backup and restart

Stop the coordinator and confirm no writer remains. For a WAL-backed ledger, copy the checkpoint and its matching sidecar from that same stopped generation. Keep the pinned executable, image, keys and launch arguments separately. This example uses fresh directories so a stale sidecar cannot be paired with a restored checkpoint:

```sh
# Run with the coordinator stopped; the backup parent must already exist.
(
  set -eu
  umask 077
  ledger=/secure/path/campaign.ledger
  backup=$(mktemp -d /secure/backups/campaign.XXXXXX)
  cp -- "$ledger" "$backup/campaign.ledger"
  cp -- "$ledger.wal" "$backup/campaign.ledger.wal"
  (cd "$backup" && sha256sum campaign.ledger campaign.ledger.wal > SHA256SUMS)
  printf 'Backup directory: %s\n' "$backup"
)
```

For an unmigrated snapshot-only ledger, confirm it is genuinely pre-WAL before taking a checkpoint-only backup; a missing sidecar after migration is not a legacy backup. Do not copy a live lock or use JSONL as a replacement for either authoritative file.

```sh
# Set BACKUP to the completed WAL-backed backup directory above.
(
  set -eu
  umask 077
  restore=$(mktemp -d /secure/path/restore.XXXXXX)
  (cd "$BACKUP" && sha256sum -c SHA256SUMS)
  cp -- "$BACKUP/campaign.ledger" "$BACKUP/campaign.ledger.wal" "$restore/"
  printf 'Restored ledger: %s/campaign.ledger\n' "$restore"
)
```

Restart the same workers/tunnels, wait for `READY`, then repeat the original coordinator command. For the [single-worker example](#start-locally-first), set `LEDGER` to the printed restored ledger (or the original ledger for in-place restart):

```sh
./target/release/angryier-campaign coordinator --binary "$BIN" --build-id "$BUILD_ID" \
  --peer worker-a@127.0.0.1:30031@/secure/path/worker-a.key --ledger "$LEDGER"
```

For non-default campaigns, repeat all original sealed options and peer entries instead. Reopen reads the WAL into memory; budget RAM accordingly. Recovery relies on fsync and cannot distinguish certain damaged final lengths from torn unsynced appends. Retain a known-good backup before investigating unexpected tail loss.

## Live progress and durable storage

The coordinator accepts `--progress-jsonl PATH`; if omitted, it writes `<ledger>.progress.jsonl` (for `/secure/path/campaign.ledger`, `/secure/path/campaign.ledger.progress.jsonl`). This is a **live, human-readable projection**, not a second ledger or proof of completion. On startup stdout reports the progress path, whether it was validated or recovered/rebuilt, and the number of ledger-accepted events. During work stdout reports dispatched grants (`active is not accepted`) and prints `accepted {JSON}` for each newly committed event; the JSONL file contains those accepted events without the `accepted ` prefix. On reopen, the coordinator compares the entire projection against accepted ledger history and atomically rebuilds it if missing, truncated, stale, or corrupt **before dispatch**. Historical accepted rows are replayed into the rebuilt JSONL projection, **not** printed again as `accepted` stdout lines. Watch with `tail -F /secure/path/campaign.ledger.progress.jsonl`, not `tail -f`: repair may replace the file by rename. A watcher must deduplicate `event_id` (`<campaign-digest>:<accepted-event-index>`) across startup rebuilds and repeated stdout delivery; `path_id` can recur when a later attempt supersedes earlier evidence. JSONL includes status, attempt, sequence, disposition/reason, bounded PC samples, truncation, witness replay verification and semantic debt count. Inspect the authoritative ledger and final report for the actual result, not a count of JSONL lines or dispatched grants.

If progress append, sync, or rebuild fails, the coordinator stops with an error; an already committed result remains in the ledger and will be reconstructed in the projection on restart after fixing the write failure. Do not delete or edit the authoritative ledger to repair progress. Never set `--progress-jsonl` to the ledger, its lock, or the `<ledger>.wal` sidecar, even via an alternate spelling or symlink. Keep separate storage and permissions for the projection. Preserve **both checkpoint and WAL sidecar** on backup/restore; restoring only one can reject recovery or lose accepted history. Once WAL migration occurs the checkpoint is tombstoned, so old pre-WAL binaries fail closed rather than reading stale state. Legacy snapshot-only ledgers migrate on their first transition; do not downgrade the executable.

The durable ledger targets **65,536 work records and 65,536 accepted evidence events**, subject also to the physical limit: checkpoint **plus** WAL cannot exceed 1 GiB, the WAL itself cannot exceed 1 GiB, and there is **no compaction**. The sealed `--max-disk-bytes` default is only **1 MiB** and must explicitly be raised on all roles for a larger campaign; raising it never overrides the 1 GiB hard ceiling. The progress projection has its **own 64 MiB cap** outside the ledger budget; filling it stops the coordinator without losing ledger-accepted events. Size actual checkpoint + WAL + progress projection, temporary files and logs for filesystem planning, and monitor free bytes and RAM/RSS on every host; `--max-disk-bytes` is a ledger limit, not a global disk-quota or an OS RSS limit. The counters are capacity targets, not guaranteed achievable path counts at any particular event size.

## Illustrative finite 48-hour ELF budget (four peers)

Only use an **already-valid pinned x86_64 ELF root** and four separately keyed loopback workers (or four encrypted loopback tunnels as above). This is a bounded illustration, not a 48-hour runtime guarantee, whole-binary coverage, or permission to treat a single root as the whole image. The same sealed options go to **each worker and coordinator**; choose a new ledger/campaign if any limit changes. In a Bash shell set:

```bash
BIN=/absolute/path/to/already-valid-root.elf
BUILD_ID=campaign-48h-v1
LIMITS=(--max-steps 100000000 --max-path-steps 4096 --max-active-states 4 \
  --max-path-depth 256 --max-loop-visits 256 --max-solver-ms 60000 \
  --max-wall-ms 172800000 --max-ram-bytes 1073741824 \
  --max-disk-bytes 536870912 --max-trace-bytes 1048576)
```

Start **four** worker processes, one per `worker-a/b/c/d`, ports `30031/30032/30033/30034` and distinct `/secure/path/worker-a/b/c/d.key` files; for each process set `ID`, `PORT`, `KEY` to its corresponding values before running:

```bash
./target/release/angryier-campaign worker --binary "$BIN" --build-id "$BUILD_ID" \
  --worker-id "$ID" --key-file "$KEY" --listen "127.0.0.1:$PORT" \
  --connections 65536 "${LIMITS[@]}"
```

Once all four report `READY`, start **one** coordinator using the same `BIN`, `BUILD_ID` and `LIMITS`:

```bash
./target/release/angryier-campaign coordinator --binary "$BIN" --build-id "$BUILD_ID" \
  --peer worker-a@127.0.0.1:30031@/secure/path/worker-a.key \
  --peer worker-b@127.0.0.1:30032@/secure/path/worker-b.key \
  --peer worker-c@127.0.0.1:30033@/secure/path/worker-c.key \
  --peer worker-d@127.0.0.1:30034@/secure/path/worker-d.key \
  --ledger /secure/path/campaign-48h.ledger \
  --progress-jsonl /secure/path/campaign-48h.progress.jsonl "${LIMITS[@]}"
```

Check disk and per-process/aggregate memory before and during the run; the coordinator independently repeats symbolic work for verification, and the worker connection cap is finite. A wall or step limit can leave unresolved work and a partial exit. For a **1- or 2-worker** run, use only the matching 1 or 2 worker commands and peer entries, never 3; keep the same sealed options on every participating process. Raw Advisor GUI PE remains **deferred** at `fork lacks complementary solver proof`: raising these caps alone cannot repair missing execution modeling or solver proof, and replaying one root is not whole-image coverage. This example asserts no new Advisor findings.

## Interpreting accepted evidence

A worker result is only a claim. Before admission, the coordinator independently executes the same fenced subtree from a fresh local root with its own arena and solver and compares the bounded trace, solver evidence, split, disposition, reason, and step count. **Where a witness is present**, the witness is concretely replayed before coordinator-recomputed evidence is committed; a root terminal may be recorded without a witness and must not be counted as a replay-verified witnessed path. Mismatches and unsupported/nonverified result shapes fail closed. This is a replay check, not a mathematical proof of solver correctness or equivalence of host toolchains.

The `CampaignOutcome` API exposes the committed ledger `report` and `accepted_evidence`: the coordinator's latest accepted disposition per path, including deferred events, not transient worker claims or every superseded attempt. A terminal path counts as a replay-verified witness only when the accepted path disposition is `Terminal` and its witness replay status is `Verified`. Deferred/unknown events remain unresolved. Witness interpretation inherits the chosen image model: PE driver-mode replay is not evidence of real Windows behavior.

## Rust API example

The compiling [Rust example](../../crates/angryier-campaign/examples/rust_api.rs) uses `Config::defaults`, `serve`, typed `Peer` values, and `coordinate_with_evidence` to read the coordinator's latest accepted evidence per path. **The worker and coordinator must run the same executable bytes**: the campaign hashes its executable into the manifest. Do not mix this example with `target/release/angryier-campaign worker`. Build the example on each host from the same pinned source/build environment and verify matching SHA-256. Start its worker role in terminal one:

```sh
cargo run -p angryier-campaign --example rust_api -- \
  --role worker --binary "$BIN" --key-file "$KEY" \
  --worker-id worker-a --addr 127.0.0.1:30031 --build-id "$BUILD_ID"
```

After `READY`, run the **same example executable** as coordinator in terminal two:

```sh
cargo run -p angryier-campaign --example rust_api -- \
  --role coordinator --binary "$BIN" --ledger /secure/path/campaign.ledger \
  --build-id "$BUILD_ID" \
  --peer worker-a@127.0.0.1:30031@/secure/path/worker-a.key
```

Repeat `--peer` with distinct worker identities/keys for a 2- or 4-worker pool. Across hosts, use the pinned tunnel addresses described above. Programmatic PE selection requires the same `config.image_mode = ImageMode::PeDriver`, entry, and symbolic register in **both** roles; this remains model-level evidence.

## Lua and PE tooling are separate

The distributed command has no generic `find` / `avoid` policy wired into it, no arbitrary input or user-supplied stub interface, and does not expose a Lua campaign API. The production CLI accepts only the campaign options shown above; do not pass symbolic-execution `run` flags such as `--find` or `--avoid` to it.

The separate `angry.sustained` Lua API is local: v1 `fork-all/v1` treats find/avoid as observations; v2 `rank-targets/v1` ranks queued work and can exclude only proof-bound exact avoid-target children. Neither Lua policy is wired into the distributed CLI or the `coordinate_with_evidence` wrapper. See the [Lua script guide](../../scripts/lua/README.md) for `bulk_resolve.lua`, which uses load-once image preparation, per-job fresh clones or an in-process batch pool, and tombstone/result records. PE `bulk_resolve` is not distributed campaign policy and does not produce coordinator-accepted replay-verified witnesses. Similarly, `pe-driver` is a PE loader/model replay, not Windows GUI execution and not full Windows semantics.

## Current scope

There is no full HPC scheduler, remote provisioning layer, built-in encrypted transport, or general cross-host runtime. Current performance evidence is limited to small fixtures and does not establish general scaling or cluster saturation. Use independently secured host orchestration, pinned environments, encrypted loopback tunnels, and external resource supervision.

To run the fixture-level separate-process campaign checks from the repository root:

```sh
cargo test -p angryier-campaign --offline --test coordinator_worker
```
