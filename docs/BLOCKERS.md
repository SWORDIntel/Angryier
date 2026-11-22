# Angryier — open blockers from the 2026-11-22/23 driver campaigns

Evidence base: the 140-module Linux census, the mixed 1,000-driver run (985 events), the random 60-driver sample, and the classification of all 296 Windows `Unknown` stops. Every row below is measured, not inferred.

## 1. Windows depth is bounded by call/return bookkeeping — the top blocker

**Evidence.** Of 296 Windows `Unknown` stops: 189 resume at `DriverEntry+0x15` (immediately after a module-local `call`), 44 stop *on* a `ret`, 32 on the epilogue `add rsp,·`, 31 elsewhere in code. **Zero** stop at an import stub; raising `--budget` from `256:256` to `1024:512:120000` left the block distribution identical (median/max 16, only 12 `ResourceLimit` in 852 runs).

**Root cause direction.** The deferred step is the return from a module-local call: the return address or post-call state is not concrete, so the path is abandoned with the pre-call PC as its last block. Linux `.ko` has the same shape and was fixed by modelling `__fentry__`/`__x86_return_thunk` and by keeping the `Return` handler's `rsp` bookkeeping concrete; the PE path lacks the equivalent.

**Next action.** Reproduce with `ANGRYIER_DEBUG_RET=1` on `0156_win_…PrecisionWS12ADL…` at budget `1024:512`, capture `RET-DEBUG pc=<callee ret>` and the `rsp`/`ret_expr` constness, then make the return address concrete (or fall back to the concrete register file when the symbolic stack read is not a constant). Files: `crates/angryier-runtime/src/lib.rs` (`IrOp::Return` handler), `crates/angryier-runtime/src/kernel_models.rs` (stateful hooks as the model for a `ret`-thunk equivalent).

## 2. `vm3dmp*` cannot be pinned in `pe-driver`

**Evidence.** 9 of 1,000 (plus 1 of 60): `campaign: root cannot be pinned for sustained replay (PeDriver; pe-driver is a loader model…)`. Every affected file is from the `vm3dmp*` family (`vm3dmp_stats`, `vm3dmp_debug`, `vm3dmp_loader`).

**Cause.** `sustained_initial_digest` refuses the environment for these images — the loader model leaves state the digest cannot pin (import-stub set or scratch region varies with image content).

**Next action.** Print the specific `UnreplayableEnvironment` sub-reason for one `vm3dmp` file, then either pin the differing state or document the family as unsupported in `pe-driver`.

## 3. Windows `Queued` dominates terminal outcomes

**Evidence.** 507 of 852 Windows rows in the 1,000-run and 15 of 30 in the 60-sample report `Queued`: the run *completed* with a frontier of forked children that never resolved before the wall bound. Decompiling shows these are real splits, not errors.

**Cause.** Wall budget closes while children are still resolving; the parent commits `Completed` with a `Queued` frontier. Not a bug, but it means "Completed" overstates progress on Windows.

**Next action.** Report `queued` per row alongside `completed` in the census summaries (already in the ledger `Report`), and consider a `--max-wall-ms` sized to child resolution for PE runs.

## 4. Linux stub stops (15 of 100) are unmodeled imports

**Evidence.** In the 100-driver run, 15 Linux modules stopped in the stub region `0x1000_0000..0x1000_1000`; three were `cleanup_module` roots (`rc-ct-90405`, `speakup_spkout`, `rc-delock-61959`).

**Next action.** Extend the classifier for the exact symbols at `0x10000008`/`0x10`/`0x18`/`0x20`/`0x78` (the census already records the stopping PC per module, so a short list of new names is derivable). Keep capability predicates (`kvm_para_available`, `ccp_present`, `dmi_check_system`) unmodeled — their return value drives control flow.

## 5. Infeasible child splits are rejected on the distributed wire

**Evidence.** `ad7380`, `cxd2880`, and `capsule-loader`/`gnss` reach a second branch where one direction is `Unsat`, then the worker refuses: `UnreplayableEnvironment("remote split cannot durably commit infeasible child evidence")` (`crates/angryier-runtime/src/sustained_pool.rs:795`). Local `split_with_evidence` supports atomic infeasible children; the wire encoding does not.

**Next action.** Encode `ChildDisposition::Infeasible` (with its solver proof) in `encode_child`/`decode_child` and accept it in the coordinator's `commit_remote_split`, matching the local path. This currently discards multi-branch handler analysis.

## 6. Fixed: evidence-size cap was reported as `InvalidTransition`

`MAX_EVENT_BYTES` was 64 KiB; a 512-block `DriverEntry` path needs 69,840 bytes. Ten drivers were dropped per run with a misleading error. Now 192 KiB with `Error::EvidenceTooLarge { blocks, edges }` (commit `d7aed1a`); 977 → 985 events, 406 → 414 targets.

## 7. Minor: transport truncations

`lan9252.esc_read` (0 blocks) and 2 further PE runs report `transport: Truncated`. Not yet attributed — the worker drops the connection before the grant round.

## Ordering

1. **#1** — it is 296 of 296 Windows `Unknown`s and the only lever that moves the Windows number.
2. **#5** — unblocks multi-branch handler analysis that is already being computed and then discarded.
3. **#2/#3** — honest reporting; low risk, low effort.
4. **#4** — extends Linux reach; the target list is already derivable from the census.
5. **#7** — needs a repro with connection logging.
