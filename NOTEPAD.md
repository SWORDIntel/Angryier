# Angryier NOTEPAD — "this would've helped" notes from hands-on use

Strictly Angryier-internal gotchas and gaps surfaced while driving the engine.
Not task notes; not Advisor notes. Update as new ones surface.

## Lua 5.4 scripting

- `tonumber("0x1180", 16)` returns **nil** in Lua 5.4 — the `0x` prefix is not accepted
  with an explicit base. Every script parsing hex needs a helper (`v:match("^0[xX]")` →
  `tonumber(v:sub(3), 16)`). Consider exposing `angry.hex(s)` in the API so scripts don't
  keep rediscovering this.
- `string.format("%016x", x)` **errors** for values ≥ 2^63 (Lua numbers are doubles) and
  for negatives. Engine reports u64 addresses that can arrive as negative doubles
  (e.g. exit_pc `0xffff4c2a1e0da000`). The session API's `*_hex()` helpers cover interactive
  use, but bulk/report scripts need a safe 64-bit formatter — expose one
  (`angry.hex64(n)`?) or document the manual pattern.
- mlua error locations point at the Rust call-site line (main.rs), which is fine, but the
  "local 'job'" style errors do not name the script line. A script-level `debug.traceback`
  wrapper would save minutes per bug.

## API gaps

- **No state spawn/reset on `LuaSession`** — ADDED: `s:spawn_state(opts)` (2026-10-22,
  `script/session.rs` + `script/mod.rs::prep_process_for_session`). Session path;
  for bulk throughput prefer `angry.prepare` + `img:run_batch` (see harness notes).
  Entry override now always pushes the `EXIT_HOOK` sentinel in session mode.
  Remaining gap: the `'static` expression arena is never reset between spawns.
- `report.exit_pc`/`rax_exit` can exceed 2^63 — decide and document whether the API returns
  u64 as strings (`_hex` convention) in reports too, not just in session accessors.

## Engine / runner

- Session `step` **errors hard** on unmodeled user-mode imports
  (`Environment("unmodeled user-mode import user32.dll!PostThreadMessageA at synthetic
  stub 0x700000007050 …")`), while `angry.run` mode reports the same situation as a
  plain low-address exit. The error text is *better* intel (names the import), but a
  census script has to pcall it and record the message. Consider an
  `unmodeled_import = "treat_as_exit"` opt so the step loop can continue.

- Whole-image load of a big PE is slow but works; a keep-alive or `--reuse-image` mode for
  back-to-back campaigns would help.
- Memory-dump targets (unpacked images) have re-homed import/vtable pointers: control flow
  exits at low unmapped addresses. A built-in "module base map" option (feed guest module
  bases) would let the harness resolve those exits to import names instead of raw low VAs.
- Misaligned `entry` addresses (mid-function sites) are detectable post-hoc: execution falls
  into ASCII strings / non-code (e.g. exit_pc decodes to "jriyre"). A cheap pre-check
  (decode-at-entry + entropy of the exit stream) could tag such jobs automatically.

## bulk_resolve harness (scripts/lua/bulk_resolve.lua + tools/bulk_resolve_driver.py)

- Canonical bulk path is now `angry.prepare` + `img:run_batch(jobs, {threads})`
  (prepared.rs): one image load per process, per-job COW clones on a native worker
  pool, ordered `{ok,error,report}` results, `img:stats()` (load_ms/run_ms). Driver
  `--batch-threads N` runs a single process with N workers. Measured: 24 small
  jobs in 0.86 s (8 threads); the 50-job 288 MB Advisor census in **3m22s**
  (40 threads) vs 13 min run-mode shards and 11 min session-mode — run_batch is
  the default for census work; spawn_state/session mode stays for interactive
  exploration.
- Session variant (`bulk_resolve_session.lua`, `s:spawn_state`) remains: same
  results, and session `step` errors NAME unmodeled imports where batch/run
  reports show only the synthetic stub address — use session mode when the
  import name matters.
- Tombstones are implemented (per-job `tombstone` record before execution;
  driver pairs by line and counts `lost`) — campaign #1's silent loss mode is
  closed.
- Report tables now expose `exit_pc_hex`/`rax_exit_hex` (the `_hex` convention
  reached reports) — the 2^63 formatter gap in this file is resolved for
  `angry.run`/`run_batch`; the session `pc_hex()`/`reg_hex()` still return a
  `0x` prefix, unlike those fields — normalize.
- `run_batch` clones share one `'static` expression arena (and one fallback
  provider per batch) — long batches should watch arena growth; per-job
  `unsupported` fallthrough must be a batch-level opt.
- Job-file format (`key=value` lines) is adequate; `find`/`avoid` are unused in
  census jobs but parse fine.
- Census analysis suite added (`scripts/census/`): host-side Lua 5.4, engine-free —
  `census_summary.lua` (classification + top exits), `census_xref.lua` (reverse xref to a
  target/range — the managed-boundary map), `census_join.lua` (census × METHRA index →
  SQLite-ready TSV), `census_sentinels.lua` (cluster normal-returns by rax). Shared
  `census_json.lua` carries the 0x-prefix hex helper. Validated on the 50-row batch
  results: the `0x700000004080` import-stub family = 12 functions including the SDD gate
  (`sub_67e540`) — exactly the stub-usage map the full census will generalize.
