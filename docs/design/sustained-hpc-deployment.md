# Sustained host-native coordinator / worker (loopback milestone)

The `angryier-campaign` executable runs a worker that replays a pinned ELF or PE image from its initial state with a process-local XED decoder, expression arena and native Z3 backend. The single coordinator owns the sustained ledger; it reserves disjoint fenced coarse subtrees and sends concurrent grants to 1, 2 or 4 distinct worker processes. Results are admitted in reservation order. Before publishing any result it independently executes the same subtree on a fresh local root with a separate solver, compares the full bounded trace, branch/query/result evidence, split, disposition, reason and step count against the authenticated worker claim, then commits **only its own recomputed evidence** and concrete-verified SAT witness. A mismatch revokes the grant; no RPC occurs at each symbolic fork. Restarting the coordinator opens the same ledger and requeues interrupted active grants. A failed connection revokes its grant and increments its generation; retries recompute, rather than claiming physically exactly-once execution. A changed binary, executable build, semantic version, limits or pinned input cannot resume the old ledger.

This is an **x86_64 Linux host-native loopback** capability, not an HPC scheduler, built-in cross-host transport, ARM64 emulation, TLS server, or general Lua campaign interface. The defaults are `--image-mode elf`, the loader entry and `--symbolic-reg rbx`. For a raw x86_64 PE32+ file, select `--image-mode pe-driver` explicitly. In either mode, `--entry VA` overrides the entry with an absolute virtual address in mapped executable memory (decimal or `0x` hexadecimal, not an RVA), and `--symbolic-reg rcx` selects RCX instead of RBX as the single symbolic input. Neither mode accepts custom inputs, user-supplied stubs or Lua policy. An infeasible fork direction cannot yet be durably proved via the remote outcome codec, and the worker rejects that result rather than silently marking it complete. The bounded v1 result codec carries trace, solver evidence and disposition. Independently concrete-verified witnesses are re-derived on the coordinator and committed, not transmitted; nonverified witness or nonempty semantic debt shapes are rejected rather than dropped. Deferred/unknown work remains unresolved and the CLI exits nonzero rather than reporting completion. Coordinator verification is a **second complete symbolic execution and solver run per accepted subtree** (plus concrete witness replay), so this mode makes no cluster-speedup claim. Solver agreement and deterministic execution are required; timeout or differing answers fail closed. It is not an independent mathematical proof of solver correctness or of equivalence between native XED/Z3 installations.

## Local invocation

Build on the intended native host with `cargo build -p angryier-campaign --offline`. Provision a **distinct, random 32-byte raw** pairwise key per worker/coordinator pair as a mode-0600 file on both endpoints through your existing secret-distribution system (never pass the key itself on the command line). On the same host:

```text
angryier-campaign worker --binary /path/to/pinned.elf --key-file /path/to/pairwise.key --build-id release-v1 --listen 127.0.0.1:30031
angryier-campaign coordinator --binary /path/to/pinned.elf --key-file /path/to/pairwise.key --build-id release-v1 --connect 127.0.0.1:30031 --ledger /path/to/campaign.ledger
```

For a bounded PE example, use a synthetic AMD64 PE32+ fixture with code at `0x140001020` (as in [the PE replay test](../../crates/angryier-campaign/tests/pe_replay.rs)). Start the worker in one terminal, then the coordinator in another after `READY`:

```sh
angryier-campaign worker --binary /path/to/branch.sys --image-mode pe-driver \
  --entry 0x140001020 --symbolic-reg rcx --max-steps 128 --connections 8 \
  --key-file /path/to/pairwise.key --build-id pe-test-v1 --listen 127.0.0.1:30031

angryier-campaign coordinator --binary /path/to/branch.sys --image-mode pe-driver \
  --entry 0x140001020 --symbolic-reg rcx --max-steps 128 \
  --key-file /path/to/pairwise.key --build-id pe-test-v1 --connect 127.0.0.1:30031 \
  --ledger /path/to/pe-fixture.ledger
```

**What PE replay verifies:** A concrete witness reproduces a path in the driver's loader model. That model supplies synthetic import stubs, scratch memory for a driver object, a mapped low page and a synthetic return target. Changing the entry PC does not initialize a Windows process or recreate the caller's state. In particular, the raw Advisor GUI binary lacks the 31 MB of live globals. Without a model of that state and the Windows behavior the path depends on, a matching replay is not proof that Advisor would take the path. The cross-host results below are ELF fixture results, not a production cross-host PE run or a demonstration of full Windows fidelity.

For a two-process pool (repeat the `--peer` option and worker process for four; one `--peer` is also accepted):

```text
angryier-campaign worker --binary /path/to/pinned.elf --key-file /keys/a.key --worker-id worker-a --build-id release-v1 --listen 127.0.0.1:30031
angryier-campaign worker --binary /path/to/pinned.elf --key-file /keys/b.key --worker-id worker-b --build-id release-v1 --listen 127.0.0.1:30032
angryier-campaign coordinator --binary /path/to/pinned.elf --build-id release-v1 --peer worker-a@127.0.0.1:30031@/keys/a.key --peer worker-b@127.0.0.1:30032@/keys/b.key --ledger /path/to/campaign.ledger
```

Pool mode requires exactly 1, 2 or 4 `--peer ID@LOOPBACK_ADDR@KEY_FILE` entries, unique worker IDs, addresses and distinct 32-byte key **contents**; it cannot be mixed with legacy `--connect`, `--key-file` or `--worker-id`. Legacy single worker defaults to identity `worker`; workers in pool mode require matching `--worker-id` values. Pool grants concurrently contact separate processes; the coordinator alone reserves and replays every result with `SustainedCampaign::verify_remote`, then commits in reservation order. A failed network/auth/result/verification/commit round revokes every uncommitted grant, returns nonzero and can be resumed from the same ledger after fixing the peer. A stale revoked fence cannot publish evidence.

The worker prints `READY <loopback-address>` to stdout; `--listen 127.0.0.1:0` selects an ephemeral local port for tests. `--connections N` bounds worker sessions, where zero means serve until stopped. A worker configured with `--connections 8` exhausted its sessions during a repeated two-path benchmark (the fourth run failed); use `--connections 0` for repeated campaigns, with no hidden automatic retry. Both processes must use the same explicit build-id and options. The sealed profile also includes the SHA-256 of the *actual executable bytes*, so a different build cannot silently join even with the same build-id. Do **not** disable this byte-identity check: copying one canonical executable to every host could satisfy it, but would not demonstrate equality of independent native builds. Pin native XED/Z3 libraries and the deployment environment externally: dynamically linked library versions are **not** hashed into this profile. Each worker and the coordinator independently load the same image bytes and reproduce the same fresh symbolic initial-state digest.

For the ELF milestone, independent native release builds on T420, T320 and 730xd produced byte-identical `angryier-campaign` executables: SHA-256 `8e7473c23cfff9a38536e55fc765074ee233be28a3bc32b966cef7b954ab9e12` on each host (not copies of one executable). For reproducibility, stage the same source on each node and use a separate isolated cache (never default `~/.cargo`) and a **fresh, previously nonexistent target directory for each full build**, with the **same canonical absolute cache and target paths** on all nodes for that build. On each node run `scripts/build-sustained-native.sh [--patch-only] ABS_CARGO_HOME ABS_TARGET_DIR ABS_RUSTC ABS_CARGO` (omit the bracketed option for a full build); supply canonical absolute Rust 1.98.0 executable paths. The script pins tool bytes/versions, GCC 14.2.0 and GNU ld 2.44, validates and backs up the original isolated `xed-sys` source, applies `scripts/sustained-xed-repro.patch` with zero fuzz only to the pinned original, and fails closed on missing or altered backups/source or patched-hash mismatch. Its three sorts make private-symbol iteration, `_get_src` inputs and generated-library glob order deterministic; the original shared dependency source remains untouched. The full build uses `--locked --offline --release --jobs 2`, `RUSTFLAGS=-Cdebuginfo=0` and `PYTHONHASHSEED=0`; compare executable SHA-256 digests before using them as peers. `--patch-only` validation was performed; first-run clean builds with the equivalent manual recipe produced the matching hashes on all three hosts, but the script's full end-to-end build was not separately repeated.

Configurable integer limits (same values on both hosts): `--max-steps`, `--max-path-steps`, `--max-active-states`, `--max-path-depth`, `--max-loop-visits`, `--max-solver-ms`, `--max-wall-ms`, `--max-ram-bytes`, `--max-disk-bytes`, `--max-trace-bytes`. Defaults are respectively 128, 64, 2, 64, 64, 10000, 30000, 67108864 for ELF or 603979776 for PE-driver, 1048576, 1048576. An explicit `--max-ram-bytes` overrides either mode's default. Raw PE input is capped at 512 MiB; the ELF input cap remains 32 MiB. The executable build hash is capped at 512 MiB, authenticated frames at 1 MiB, and typed results at 64 KiB. The coordinator partitions the remaining total step budget among concurrent grants each round. Each process enforces the sealed per-path RAM/trace constraints and the ledger bounds storage; aggregate RSS across 1/2/4 processes and coordinator replay is **not** capped by `--max-ram-bytes`. Wall time is checked between rounds and before each verified commit; expiration revokes uncommitted grants and fails the invocation. TCP receive and independent verification can still run past the deadline before that check. These bounds describe campaign work and codec storage, not an OS-enforced per-process RSS or wall-time sandbox; use cgroups and process supervision for untrusted workloads. A deferred work unit is not automatically retried; an operator must intentionally increase limits under a **new manifest** or use an appropriate runtime retry policy.

## Pinned worker configuration handoff

The coordinator can generate a v2 AEAD-encrypted TOML envelope using its **same compiled `angryier-campaign` executable** (not a separate worker build):

```sh
angryier-campaign worker-config --binary /srv/angryier/image.elf \
  --worker-binary /remote/absolute/image.elf --build-id release-v1 \
  --worker-id worker-a --sign-key /LOCAL/coordinator/worker-a.key \
  --key-file /remote/key/worker-a.key \
  --listen 127.0.0.1:30031 --connections 0 --output /staging/worker-a.toml
```

`--binary` must exist on the generator and is hashed there. The normalized absolute `--worker-binary` is the worker-side image pathname; it need not exist on the generator, but the worker requires it to be canonical and to match the sealed image SHA-256. Supply identical `--image-mode`, `--entry`, `--symbolic-reg`, and all ten sealed `--max-*` limits to generator and coordinator. The generator creates a new mode-0600 file and will not overwrite an existing one. The envelope leaves the **worker-side bootstrap key pathname**, version and fresh random 24-byte nonce visible alongside ciphertext; all pinned campaign settings are encrypted and authenticated with XChaCha20-Poly1305. The version and key path are authenticated associated data (AAD). Key bytes and the coordinator-local signing-key path are never serialized; there is no compiled static embedded secret. Stage the same compiled executable bytes (compare SHA-256), native runtime dependencies, and image bytes (compare SHA-256) on the worker. Install TOML at `~/.config/angryier/worker.toml` under a mode-`0700` directory, owned by the worker user with file mode `0600`; independently provision the raw 32-byte key at `/remote/key/worker-a.key`, mode `0600`. Run `angryier-campaign worker --config ~/.config/angryier/worker.toml` without extra flags. Unknown TOML fields/version, symlink or nonprivate config, image path aliases, and changed executable/image pins fail closed before serving. The legacy `worker --binary ...` form remains available. No host deployment or TLS is provided: the coordinator still uses `--peer worker-a@127.0.0.1:31031@LOCAL_KEY` over an independently authenticated confidential loopback tunnel (`LOCAL_KEY` is its local key-file pathname). See the [operator handoff](../guides/distributed-campaigns.md#pinned-worker-config-handoff) and [CLI reference](../CLI.md#distributed-workercoordinator-roles).

The required `--sign-key` must name an existing validated raw 32-byte pairwise key on the coordinator; the generator uses it to encrypt/authenticate the payload, but serializes neither its bytes nor its coordinator-local pathname. `--key-file` names the visible worker-side bootstrap key pathname: the worker must read this metadata to find its decryption key before it can authenticate/decrypt campaign settings. Provision a distinct matching key for each worker independently on both endpoints, and transfer the handoff using an authenticated confidential channel. The worker authenticates/decrypts the envelope before honoring pinned settings or reporting `READY`, so tampering or a mismatched key fails closed. This boundary does not protect against anyone with the worker key or control of its account, nor resolve executable-hash time-of-check/time-of-use races. Preserve identical executable and image SHA-256 pins and use an authenticated confidential loopback tunnel for cross-host transport: application transport HMAC does **not** encrypt frames. This handoff has not been validated across hosts.

## Progress projection and capacity boundary

    The 64 MiB JSONL projection cap is separate from the ledger budget. Deleting a full projection does not create capacity: startup rebuilds the accepted history. For quiescent backup and restart commands, see [the operator procedure](../guides/distributed-campaigns.md#quiescent-backup-and-restart).

The coordinator CLI exposes live `--progress-jsonl PATH` (default `<ledger>.progress.jsonl`), with stdout startup validated/rebuilt, active grant dispatch, and `accepted {JSON}` records. JSONL is a projection of durable accepted ledger events, not a second acceptance store. At startup, missing/lagging/corrupt/truncated projection rows are checked against the complete accepted ledger history and rebuilt by atomic rename before new dispatch. Watch with `tail -F` rather than `tail -f`, and deduplicate stable `event_id` values (campaign digest plus accepted-event index); `path_id` may have multiple accepted events. On progress write error the coordinator stops; committed results remain in the ledger and repair on resume. Never point the projection at the ledger, its lock, or WAL sidecar.

The hard target is 65,536 work records and 65,536 accepted events, with a 1 GiB physical WAL ceiling and 1 GiB aggregate checkpoint-plus-WAL ceiling; there is **no WAL compaction**. The sealed `--max-disk-bytes` default (1 MiB) must explicitly be raised for larger runs on **every** role, and may still halt before those record limits. Budget actual checkpoint + WAL + progress and temporary/log bytes, as well as per-process and aggregate RAM/RSS; the sealed limits are not an OS resource quota. WAL migration tombstones the old checkpoint to fail pre-WAL readers closed; preserve both checkpoint and WAL sidecar together for backup/restore. See the [operator guide](../guides/distributed-campaigns.md#illustrative-finite-48-hour-elf-budget-four-peers) for a finite 48-hour budget example on one already-valid ELF root with four workers (1/2/4 peers only), not a claim of whole-binary coverage or general scaling. Raw Advisor GUI PE remains deferred at `fork lacks complementary solver proof`: merely increasing caps cannot supply missing modeling or solver proof, and one root does not cover the full image. No new Advisor finding is asserted.

Raw transport is HMAC-authenticated but **plaintext**, rekeys each TCP connection, and rejects non-loopback endpoints. Cross-host operation is permitted only through independently authenticated, encrypted and pinned loopback SSH or mTLS tunnels; never expose this endpoint via a plaintext proxy. A tunnel must preserve loopback endpoints on both sides. In the cross-host run, encrypted `ssh -L` localhost forwards connected the coordinator's loopback peer endpoints to worker loopback listeners on T320 and 730xd, with distinct mode-0600 pairwise key files per worker/coordinator pair; no plaintext cross-host listener or hop was used. Connections authenticate campaign digest, epoch and peer identity before a grant is processed. There is no built-in TLS, machine provisioning, job scheduler, shared filesystem protocol, or cross-host proof of library/OS equivalence.

## Multi-host deployment model

The loopback milestone above is the *substrate*. Deploying it across machines is a placement problem, and the design choices that matter are these:

- **One coordinator, N worker hosts.** The coordinator is the only ledger writer and the only admission authority: it reserves disjoint fenced subtrees, sends concurrent grants to distinct worker processes, and re-executes each claimed subtree on a fresh local root before publishing anything. A worker never modifies the ledger, so a lost or restarted worker cannot corrupt a campaign.
- **One campaign per worker process.** Each campaign has its own ledger, its own sealed limits, and its own worker configuration. Because the worker serves one pinned image at a time, identity stays simple: one campaign ↔ one image digest ↔ one worker process ↔ one ledger. Do not multiplex several images through one worker process or share a ledger between campaigns.
- **Identity is cryptographic, not positional.** The coordinator seals the executable digest into the campaign manifest, so every worker must run byte-identical bytes of the same build; the image digest is pinned and re-checked against the bytes actually loaded before the listener starts; worker settings are sealed in the AEAD envelope and must match on both sides. A host that is merely "a fast box" is not interchangeable — its binary and image must match exactly.
- **Keys are per worker, not global.** Each coordinator/worker pair gets its own random 32-byte pairwise key, provisioned independently on both endpoints. A compromised worker cannot authenticate as another worker, and a rejected peer fails closed rather than falling back.
- **Network is a tunnel boundary, not a cluster fabric.** Listeners bind loopback only. Cross-host reachability is provided by an independently authenticated, confidential channel whose local end terminates on loopback (SSH local forward, or an mTLS adapter). The frame HMAC is additional application authentication and never a substitute for the encrypted channel.
- **Campaigns are independent failure domains.** A dead worker stalls only its own campaign; the coordinator reports a partial outcome and keeps the durable accepted evidence. Recovery is re-running the same coordinator command with the same ledger, which validates and rebuilds the progress projection from accepted history.

Capacity follows from those choices: a worker process is single-campaign, so concurrency across a fleet equals the number of campaigns you choose to run, bounded by each host's cores and memory. Keep the coordinator host lightly loaded — it runs a solver and a verifier for every admitted subtree — and place the bulk of campaigns on worker hosts.

## Using it across hosts

Build once, deploy identical bytes, provision keys, then run one campaign per worker. The commands below are the deployment runbook; `docs/guides/distributed-campaigns.md` covers the flag-level detail and `docs/CLI.md` the full reference.

```sh
# 1) One release build, deployed to every host; compare the digest on each
cargo build -p angryier-campaign --release --locked --offline
sha256sum target/release/angryier-campaign

# 2) Stage the image on the worker at a stable absolute path (may differ from the
#    coordinator's path), plus the same executable bytes
install -m 0755 angryier-campaign /opt/angryier/angryier-campaign
install -m 0644 image.elf        /opt/angryier/image.elf

# 3) Provision this worker's own key, twice (once per endpoint), mode 0600
(umask 077; head -c 32 /dev/urandom > /secure/worker-a.key)

# 4) Generate the sealed worker envelope on the coordinator, using the local copy
#    of the key; --worker-binary names the worker-side path, --key-file is the
#    worker-side key pathname recorded inside the envelope
angryier-campaign worker-config --profile ko-handler \
  --binary ./image.elf --worker-binary /opt/angryier/image.elf \
  --root-symbol my_handler --build-id run-1 --worker-id worker-a \
  --sign-key /secure/worker-a.key --key-file /secure/worker-a.key \
  --listen 127.0.0.1:30031 --output worker-a.toml

# 5) On the worker: install the envelope privately and start it
install -d -m 0700 ~/.config/angryier
install -m 0600 worker-a.toml ~/.config/angryier/worker.toml
angryier-campaign worker --config ~/.config/angryier/worker.toml
#    ... wait for `READY 127.0.0.1:30031`

# 6) On the coordinator: publish the tunnel, then run the campaign
ssh -N -L 127.0.0.1:31031:127.0.0.1:30031 worker-a &
angryier-campaign coordinator --profile ko-handler \
  --binary ./image.elf --root-symbol my_handler --build-id run-1 \
  --peer worker-a@127.0.0.1:31031@/secure/worker-a.key \
  --ledger ./run-1.ledger
```

Operational rules that follow from the design model:

- **One port per campaign** on each worker host, so a stale process cannot answer for a new campaign; stop workers by PID resolved from the listening socket rather than by pattern.
- **One ledger per campaign**, never shared, and never written by a worker.
- **The sealed limits are campaign identity**: changing `--max-steps`, `--max-wall-ms` or any other sealed limit on one side turns the run into a different campaign, and the handshake rejects the mismatch by name rather than proceeding.
- **Repeat runs are resume runs**: re-issuing the same coordinator command against an existing ledger validates accepted history and continues from it.
- **Fan-out is an operator concern.** For many images, drive one campaign per image with whatever scheduler you already trust, keeping one worker process and one port per campaign. The engine intentionally contains no scheduler.

## Validation

`cargo test -p angryier-campaign --offline --test coordinator_worker` runs actual separate-process 1/2/4-worker finite ELF campaigns with equal accepted unique path evidence and independently verified witnesses at equal configured budgets; changed-version/ELF rejection, distinct-key/auth failure and recovery, disconnect/reconnect, stale-fence rejection and forged evidence fail-closed are covered. The three independently built host executables matched the SHA-256 above; a cross-host two-path campaign completed through encrypted SSH loopback forwards, and remote reconnect passed. On the eight-path fixture, five interleaved repetitions of 1-local versus four workers across three hosts measured mean 6.944 s versus 5.100 s (1.362× on this fixture). All 8 terminal paths and 15 unique accepted event paths/8 witnesses were verified, with typed equality and the same 22,504-byte ledger hash; remote host worker processes performed work. This does **not** establish general throughput, saturation scaling or a cluster scheduler. `cargo test -p angryier-distribution --offline --test sustained_transport` covers bounded authenticated payloads, replay/MAC rejection, and handshake rekey. `cargo test -p angryier-runtime --features xed,script --offline --test sustained_pool` checks native local baseline replay and unsatisfiable child fail-closed behavior. Final bounded eight-path campaign validation measured SSH tunnel lifetime byte counters (sent/received) of 6,828/8,020 for T320 and 6,864/8,908 for 730xd. These include SSH handshake and idle traffic over approximately 60–69 seconds, not precise application traffic. Four worker per-process user CPU tick deltas were positive: T420a 100, t420b 83, T320 119 and 730xd 87. This establishes use of each process, not simultaneous saturation. The five-run 1.362× result above remains scoped to the small fixture, and cross-host operation still requires encrypted loopback tunnels.
