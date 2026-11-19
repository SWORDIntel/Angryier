# Local sustained campaigns: operator guide

`angryier-campaign` is a single x86_64 Linux executable with two independent surfaces: the distributed coordinator/worker roles documented in [distributed-campaigns.md](distributed-campaigns.md), and the **local** sustained-campaign controls documented here. The local controls run one process against one durable frontier ledger on this host. They do **not** use the worker network: no loopback listener, no peer connections, no key files, no HMAC framing. The distributed roles and the local controls happen to be compiled into the same executable; they are otherwise independent — neither reads the other's configuration, and a local campaign never opens a worker transport.

The local controls drive the same runtime machinery as the local Lua API (`angry.sustained` in [LUA_API.md](../LUA_API.md)): a pinned root, a sealed campaign manifest, a single-writer ledger with a checkpoint and append-only WAL, bounded advances, and evidence that is accepted only after concrete witness replay. This guide is operational. For design boundaries see [sustained-rest-seam](../design/sustained-rest-seam.md); for measured fixture evidence see [sustained-exploration-verification](../design/sustained-exploration-verification.md).

## Image and sealed manifest requirements

- The campaign target must be a **static ELF64 x86-64 executable**, and execution starts at the **image entry**: no entry override, no PE, no scripts, no patches. Unsupported options (mutable files or streams, hooks, under-constrained memory, fallthrough, dynamic loading) fail closed rather than silently escaping the replay pin.
- `local-start` seals a `CampaignManifest` from a complete `CampaignSpec`: the target binary digest, architecture, entry PC, semantic version and profile digest, script and policy digests, solver version and solver-policy digest, the `prove` fidelity profile, and **all ten exploration limits, each positive** — zero is never an implicit ceiling. The CLI supplies positive defaults for omitted limits; the resolved values are sealed. Changing the image, build ID, policy, targets, symbolic marks, concrete seeds, or budget requires a new campaign.
- Every later `local-resume`, `local-status`, `local-advance`, or `local-retry` must present the same pinned options (including `--binary`, `--ledger`, `--build-id`, policy, targets, symbolic marks, concrete register seeds, and limits). A changed specification cannot reopen the old ledger; start a new campaign with a new ledger instead.
- Only the native `z3-default` solver policy is supported in local campaigns.

## One executable, three command families

The same compiled `angryier-campaign` executable dispatches:

| Family | Invoked as | Network |
| --- | --- | --- |
| Distributed roles | `angryier-campaign worker`, `angryier-campaign coordinator` | Authenticated loopback TCP only (see [distributed guide](distributed-campaigns.md)) |
| Local controls | `angryier-campaign local-start`, `local-resume`, `local-status`, `local-advance`, `local-retry`, `local-run` | **None.** Never listens, never dials |

Do not pass worker flags (`--listen`, `--connect`, `--peer`, `--key-file`, `--worker-id`) or `--progress-jsonl`, `--image-mode`, or `--entry` to local subcommands; they are not local options. Conversely, the distributed roles do not accept local policy/target flags. The two surfaces have distinct operational and identity contracts.

## Policies: fork-all/v1 and rank-targets/v1

Local campaigns support two versioned policies; the CLI spells their `--policy` values `fork-all` and `rank-targets` (default: `fork-all`):

- **v1 — `fork-all/v1`**: reservation is FIFO. `find` and `avoid` target lists are **observations only**; they never prune or reorder work.
- **v2 — `angry.sustained/v2` + `rank-targets/v1`**: the scheduler ranks queued work by its last dynamic branch successor — exact find matches first, neutral successors next, avoid matches last. Ties break by target PC, predicate digest, and path identity, and that order is pinned across partial resume: a resumed campaign accepts children in the same order with the same path identities. Ranking orders work; it does **not** predict reachability.
- v2's only policy option is `exclude_avoid` (default false). When enabled, only an **exact, validated dynamic branch target** may be excluded — not the entry PC and not an arbitrary visited block. An excluded satisfiable child is recorded as `ExcludedByPolicy`, which is distinct from solver-infeasible; false/absent targets are never treated as infeasible.
- Target lists are duplicate-free arrays of at most 4,096 addresses each. The typed local surface **canonicalizes them for you** — lists are sorted before pinning, so input order does not change campaign identity — while duplicates and oversized lists are rejected. Resume requires the same pinned targets and policy; a changed policy or target set is rejected because the options digest is part of the campaign identity.

On the typed local surface these policies are sealed under their own artifact labels — `angryier.local/sustained/v1` / `angryier.local/sustained/v2` with `observational-targets/v1` / `rank-targets/v1` policy tags — not the Lua script labels. Because those sealed bytes differ, **a ledger created by the Lua `angry.sustained` API cannot be resumed by the local CLI/API, and vice versa**; each surface rejects the other's ledgers as a mismatched campaign instead of reopening foreign work.

## Starting, resuming, and advancing

A local campaign is a durable ledger file plus its WAL sidecar. `local-start` creates it; `local-resume` reopens it; `local-advance` runs a bounded batch; `local-run` starts or resumes and repeatedly advances bounded batches; `local-status` reports counters and ledger-derived accepted evidence; `local-retry` requeues stalled owned work. Each command starts a new process and must receive the same pinned specification. For example, in Bash, define these arguments again with the **same values** in each new shell:

```bash
PINNED=(--binary ./branch.elf --ledger /secure/path/local.ledger \
  --build-id local-v1 --symbolic rdi --symbolic rsi --reg rax=0x2a --policy rank-targets \
  --find 0x401020 --avoid 0x401080 \
  --max-steps 64 --max-path-steps 64 --max-active-states 1 --max-path-depth 64 \
  --max-loop-visits 64 --max-solver-ms 10000 --max-wall-ms 30000 \
  --max-ram-bytes 67108864 --max-disk-bytes 1048576 --max-trace-bytes 1048576)

./target/release/angryier-campaign local-start "${PINNED[@]}"   # new ledger only
./target/release/angryier-campaign local-resume "${PINNED[@]}"  # existing ledger
./target/release/angryier-campaign local-status "${PINNED[@]}"  # counters and accepted evidence
./target/release/angryier-campaign local-advance "${PINNED[@]}" # bounded batch
./target/release/angryier-campaign local-retry "${PINNED[@]}"   # requeue unresolved work
```

For FIFO instead, use `--policy fork-all`; omit find/avoid if unneeded. `--find PC` and `--avoid PC` repeat for each target (decimal or `0x` hexadecimal), and `--exclude-avoid` is allowed only with `--policy rank-targets`. Repeat `--symbolic REG` for each 64-bit symbolic GPR and `--reg NAME=VALUE` for each distinct concrete GPR seed (decimal or `0x` hexadecimal u64). Names must be canonical lowercase x86-64 GPRs (`rax`, `rcx`, `rdx`, `rbx`, `rsp`, `rbp`, `rsi`, `rdi`, `r8`–`r15`); a register cannot be both symbolic and seeded. Omitting `--symbolic` retains the single `rbx` default (or `rcx` with the legacy `--symbolic-reg rcx`); `--symbolic` and `--symbolic-reg` cannot be mixed. Pinned choices cannot change between the commands above. The CLI accepts positive defaults for omitted limits, but an explicit, repeated set makes resume unambiguous.

- **local-start** never overwrites an existing ledger; `local-resume` requires one and validates the presented manifest and artifacts against the sealed campaign digest. All other local commands also reopen and validate that ledger. The pinned binary must be presented on every command; the root digest is independently rechecked before each advance.
- **local-advance** reserves queued work, replays the pinned root, and commits a bounded batch. A fork cap retains children as **deferred** work, not completed paths. Solver SAT alone is not a terminal result; where a witness exists it is concretely replayed before the evidence is accepted. The CLI prints the report and ledger-derived evidence **after the bounded batch**, then exits nonzero if unresolved owned work remains (`campaign partial`); a partial ledger can still contain accepted work.
- **local-status** reports ledger counters and prints individual accepted evidence records without advancing execution. It reopens the ledger under the single-writer lock; it cannot concurrently view progress while `local-run` or `local-advance` holds that lock. The typed API additionally exposes latest-per-path `cumulative_evidence()` and full `accepted_events()` history.
- **local-retry** explicitly requeues records in `Deferred`, `Unknown`, or `Failed` state. Neither restart nor resume requeues them automatically. Retried work re-executes; accepted evidence is deduplicated by event identity and never double-counted.
- A mismatch, corrupt ledger, or changed binary fails the command with a nonzero exit; do not interpret a failure as completion.

## Typed Rust API

For programmatic use the campaign crate exposes the typed local-campaign surface directly:

- `LocalConfig { campaign: Config, ledger: PathBuf, policy: LocalPolicy, find: Vec<u64>, avoid: Vec<u64>, symbolic: Option<Vec<(LocalRegister, u16)>>, regs: Vec<(LocalRegister, u64)> }` — a `Config` narrowed to the local contract plus the ledger path, typed policy, targets, optional explicit 64-bit symbolic GPR marks, and concrete u64 GPR seeds. Parse names with `LocalRegister`'s `FromStr` implementation (for example, `"rdi".parse()?`). `symbolic: None` retains `Config::symbolic_reg` (`rbx` by default, or `rcx`); `Some` replaces it with a nonempty set of 64-bit GPR marks. Concrete seeds must be distinct and disjoint from the effective symbolic marks; duplicate marks, unsupported widths, or duplicate seeds are rejected.
- `LocalPolicy` — `ForkAll` (the v1 FIFO contract) or `RankTargets { exclude_avoid: bool }` (the v2 ranked contract).
- `LocalCampaign` — `start(config)` (creates the ledger; fails if it exists), `resume(config)` (reopens; fails if absent or the sealed specification differs), `report()`, `retry_deferred()`, and `advance(timeout) -> LocalOutcome { report, steps, reason, accepted_evidence }`. `advance` rebuilds the pinned root from the image file, revalidates the image bytes against the sealed digest and the rebuilt root digest against the pinned ledger root, and returns the committed report plus the latest accepted evidence per path. On non-x86_64 hosts `start`/`resume`/`advance` return errors; local campaigns require native XED and Z3.

The typed API supports arbitrary canonical x86-64 GPR symbolic marks (64-bit) and disjoint concrete u64 seeds; these root inputs are sealed and must match on resume. The Lua `angry.sustained` v1/v2 API remains exported as a compatibility surface, **not removed**; its previously persisted ledgers cannot be opened by the typed local CLI/API without a migration, which is not currently provided. `Config::defaults` provides positive limit defaults, and unsupported `Config` fields (PE mode, entry overrides, network peers, a progress journal) are rejected explicitly instead of being ignored.

## Status output and evidence interpretation

The report exposes the durable ledger counters — `queued`, `active`, `deferred`, `completed`, `infeasible`, `unknown`, `excluded`, `failed`, `retired_splits` — plus `complete_within_declared_bounds`. The CLI emits JSON lines with `type: evidence_latest` for the latest accepted disposition per path identity, `type: evidence_event` for every accepted historical event, and `type: target` for each find/avoid address; `observed: true` requires a replay-verified terminal witness covering that PC. Do not double-count latest rows and event rows. These are reconstructed from the ledger on each invocation, not a streaming JSONL projection while a long advance runs. Status and reports are ledger-derived; neither command output nor a progress file is a second authority. Key reading rules:

- A path counts as a replay-verified witness only when its accepted disposition is terminal **and** its witness replay status is `Verified`. A root terminal without a witness is recorded but is not a witnessed path.
- `evidence.frontier` holds pending work identities, not terminal paths. Do not infer completion from an empty cumulative frontier; use the `queued`/`active`/`deferred`/`unknown`/`failed` counters for pending ownership.
- Branch predicates appear as canonical digests, never as condition source text. An absent witness implies no solved input.
- Find/avoid observations report `observed` only for a retained accepted executed path — including earlier advances — never for solver-infeasible children.

## Backups: ledger checkpoint and WAL are one unit

The durable store is an immutable `ANGFRNT3` checkpoint plus a checksummed, generation-bound append-only WAL sidecar `<checkpoint>.wal`. On the first transition after a legacy snapshot-only ledger opens, the checkpoint is replaced by an `ANGFRNT9` tombstone and the WAL becomes the source of truth; pre-WAL binaries then fail closed instead of accepting stale state. There is **no compaction**: the WAL grows monotonically and the writer fails closed at a 1 GiB aggregate store ceiling (checkpoint plus WAL), targeting at most 65,536 work records and 65,536 accepted evidence events. Local mode has **no progress journal at all**: the distributed coordinator's `--progress-jsonl` projection is a distributed option, and the local surface rejects it rather than writing one.

Back up **both files together, from a quiescent writer**, exactly as in the distributed guide's [backup procedure](distributed-campaigns.md#quiescent-backup-and-restart): stop the local process (the ledger is guarded by a single-writer advisory lock on a `<ledger>.frontier.lock` sidecar; another process holding it is an error, not a queue), copy checkpoint and matching WAL into a fresh directory, and record `SHA256SUMS`. Restoring only one of the pair can reject recovery or lose accepted history. Never copy a live lock file, never edit the ledger by hand, and never substitute any JSONL file for either authoritative file. Recovery reads the bounded WAL into memory on reopen and relies on fsync; checksum-invalid frames are rejected, but a damaged final length with no later valid frame can look exactly like an incomplete append — retain the known-good backup while investigating unexpected tail loss.

Progress/audit JSONL files are a **distributed-coordinator feature only**. A local campaign never writes one: the local surface rejects the progress-journal option outright, so there is no local projection to rebuild, watch, or confuse with the ledger. Everything an operator needs lives in the authoritative checkpoint + WAL pair and the command output.

## Bounds, partial exits, and known limitations

- The ten sealed limits are hard bounds, not hints. A campaign that stops at a declared bound exits with unresolved owned work and `complete_within_declared_bounds = false`; report partials as partials. **No local run exhausts the whole binary**: the bounded frontier explores what the budgets allow, and nothing in the report licenses a whole-binary coverage claim. Raising limits later is a new campaign with a new digest and a new ledger.
- Local campaigns support exactly the pinned model described above: static ELF64 x86-64 at the image entry, `prove` fidelity, `z3-default`, no hooks/patches/UC/dynamic loads, no entry override. PE images and Windows semantics are out of scope; witness replay proves behavior in the pinned ELF model only. v2 exclusion is proven only for exact dynamic branch-target bounds on finite fixtures — arbitrary avoid-target reachability is not established by any current evidence.
- Execution can repeat across retries and resume (this is not exactly-once execution), but accepted evidence is idempotent by event identity.
- Capacity is bounded: 65,536 records, 65,536 evidence events, 1 GiB store, no compaction. Plan disk and RAM accordingly; `--max-disk-bytes` bounds the ledger, not your filesystem.

### Bounded `local-run` invocation

With the `PINNED` array above, use the same compiled CLI and options to start or resume the ledger:

```bash
./target/release/angryier-campaign local-run "${PINNED[@]}" --batch-ms 5000 --run-ms 15000
# Repeat the identical command to resume partial work; do not run local-start again.
```

`--batch-ms` and `--run-ms` are positive, unsealed **process-control** bounds at most the sealed `--max-wall-ms` (30,000 ms above). The default batch is 5,000 ms, capped to the wall limit; omitting `--run-ms` uses the wall limit for this invocation. Each batch requests the smaller of its batch bound and invocation time remaining. These are cooperative deadlines, **not hard process timeouts**: an in-flight solver or replay may make a batch finish later. The CLI flushes a ledger-derived report and newly accepted event **IDs after each completed batch**, not live events during a batch. Exit **0** means `complete_within_declared_bounds`, **2** means partial (including elapsed invocation time, no-progress batches, or unresolved owned work), and **1** means a hard usage/execution error. Partial is not exhaustive binary coverage. `--run-ms` is not sealed and is **not an OS-wide cumulative budget** across processes or restarts; the sealed campaign wall limit stays pinned, and changing it requires a new ledger. `local-status` cannot run concurrently while `local-run` holds the single-writer ledger lock.

On each `local-run` invocation, before its first advance, the CLI emits every historical accepted event ID from the ledger once as `replayed_event_id`. Events newly committed in that invocation appear as `accepted_event_id` after their completed batch, not again as replayed IDs until a later invocation. Both records carry the stable `work_index`, `attempt`, `sequence`, `path_id`, and `replay_digest` fields so consumers can de-duplicate across invocations by event identity. After a crash, stdout progress may be replayed or lost, but ledger acceptance is not duplicated; use the reopened ledger/status as the source of truth.

### Typed standalone Rust example

[`local_campaign.rs`](../../crates/angryier-campaign/examples/local_campaign.rs) runs the typed `LocalCampaign` API without Lua or a worker pool:

```bash
cargo run -p angryier-campaign --example local_campaign -- \
  --binary ./branch.elf --ledger /secure/path/rust-example.ledger \
  --build-id local-v1 --policy rank-targets --symbolic rdi --symbolic rsi --reg rax=0x2a \
  --find 0x401020 --avoid 0x401080 \
  --max-steps 64 --max-path-steps 64 --max-active-states 1 --max-path-depth 64 \
  --max-loop-visits 64 --max-solver-ms 10000 --max-wall-ms 30000 \
  --max-ram-bytes 67108864 --max-disk-bytes 1048576 --max-trace-bytes 1048576 \
  --batch-ms 1000 --total-ms 15000
# To resume this example's ledger, repeat the same command with --resume.
```

The example seals its **own running executable SHA-256** in the manifest. The `angryier-campaign` CLI cannot resume a ledger made by the example; recompiling either executable also changes its identity and prevents reopening its old ledger. Keep executable bytes and every sealed option unchanged on resume; `--batch-ms`/`--total-ms` control only this example invocation. On `--resume`, the example likewise prints ledger-derived historical events as `replayed` once before advancing, then newly accepted events as `accepted` after each batch; its stable identity fields support the same consumer de-duplication. It stops when a batch makes no progress and exits **2** if the report remains partial (including unresolved work), rather than spinning indefinitely. Existing Lua scripts need no rewriting: keep legacy Lua ledger originals archived read-only; the old Lua compatibility interface can inspect them or resume from a writable copy, but the Rust CLI/API cannot open them.

## Relationship to the distributed campaign

The distributed roles reuse the same ledger family, manifest sealing, and evidence rules, but add a coordinator that reserves work for worker processes over authenticated loopback TCP and independently re-verifies every worker claim. That is a different operational model with its own identity requirements — in distributed mode, **worker and coordinator must run the same compiled executable bytes**, and the executable itself is hashed into the campaign manifest. The local controls never connect, but they still pin their own running executable bytes in the sealed manifest, so a recompiled CLI or the separate Rust example cannot resume their ledger. Do not mix the two surfaces' flags, ledgers, or expectations; each guide documents exactly one surface, and neither claims parity with the other until its own tests say so.
