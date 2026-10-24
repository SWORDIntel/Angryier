//! Prepared-image bulk campaign support (`angry.prepare`).
//!
//! The single biggest per-job cost in bulk drivers was whole-image loading:
//! `angry.run` reads and parses the full image (hundreds of MB for unpacked
//! kernels) on every call. [`PreparedImage`] performs that work once:
//!
//! * `runtime` — the XED-backed runtime (decoder, corpus registry, lowerer,
//!   interpreter) is constructed once per process instead of per job.
//! * `arena` — the sharded expression arena is shared across jobs, exactly
//!   like an `angry.open` session.
//! * `template` — the pristine loaded [`crate::Process`]. Per-job runs clone
//!   it: the clone shares every memory page behind `Arc` (copy-on-write),
//!   so constructing a campaign costs milliseconds and the image pages stay
//!   hot in one resident copy no matter how many jobs run.
//! * `kernel_pool_bindings` — export-name → VA cache extracted from the PE
//!   once, so each job can bind and attach a *fresh* [`KernelPoolTracker`]
//!   without re-parsing the image (and without sharing alloc/free
//!   accounting across jobs).
//!
//! Everything mutable per campaign (entry sentinel, register seeds,
//! symbolic marks, UC debt ledger, kernel pool accounting, fallthrough
//! debt) is applied to the per-job clone, never to the template.

use std::sync::Arc;

use mlua::{Lua, Table, UserData, UserDataMethods, Value};

use angryier_loader::ImageLoader;
use angryier_memory::{ByteValue, LayeredMemory};
use angryier_semantics_intel64::UnsupportedFallthrough;
use angryier_types::{ExpressionNormalizationVersion, SemanticVersion, TargetProfileId};

use super::utils::{parse_lua_u64, parse_patch_bytes, reg_by_name};
use super::{reg_seed_from_pair, symbolic_mark_from_pair, Campaign};
use crate::{PE_DRIVER_STUB_BASE, PE_DRIVER_STUB_SIZE};

/// The concrete runtime flavor backing prepared images and campaigns.
pub type XedRuntime = crate::Runtime<crate::XedFormTranslator<angryier_arch_xed_ffi::XedDecoder>>;

/// A symbolic session over the native-XED decoder (the `D` parameter of
/// [`crate::SymbolicSession`] is the decoder type, not the runtime).
pub type XedSession<'a> = crate::SymbolicSession<'a, crate::XedFormTranslator<angryier_arch_xed_ffi::XedDecoder>>;

/// A loaded-once image plus the reusable execution infrastructure, exposed
/// to Lua as `angry.prepare(path, opts)` with `img:run(opts)` per job.
pub struct PreparedImage {
    runtime: XedRuntime,
    arena: Arc<angryier_expr::ShardedExprArena>,
    /// Pristine post-load process. Never mutated by a job: every run clones
    /// it first, so no entry sentinel, seed, patch, or tracker state can
    /// leak from one campaign into the next.
    template: crate::Process,
    is_pe: bool,
    /// Export-name → VA cache for per-job pool tracker binding (alloc/free
    /// families only; populated once at prepare, when the image bytes are
    /// still in hand).
    kernel_pool_bindings: Vec<(angryier_models::PoolRoutine, u64)>,
    stats_load_ms: u64,
    stats_jobs: u64,
    stats_run_ms_total: u64,
    stats_last_run_ms: u64,
}

impl PreparedImage {
    /// Reads and loads the image once, constructing the runtime, the arena,
    /// and the pristine process template. `opts` carries the load-time
    /// options (`dynamic`, `unsupported`); everything else is applied per
    /// job in [`Self::run`].
    pub fn load(path: &str, opts: Option<&Table>) -> mlua::Result<Self> {
        let t0 = std::time::Instant::now();
        let bytes = std::fs::read(path).map_err(|e| mlua::Error::external(format!("read {path}: {e}")))?;
        let mut runtime = crate::Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
        if opts
            .and_then(|o| o.get::<String>("unsupported").ok())
            .is_some_and(|v| v == "fallthrough")
        {
            let fallback = Arc::new(UnsupportedFallthrough::new());
            runtime.registry.set_unsupported_fallback(
                Arc::clone(&fallback) as Arc<dyn angryier_semantics::SemanticProvider>
            );
        }
        let use_dynamic = opts
            .and_then(|o| o.get::<bool>("dynamic").ok())
            .unwrap_or(false);
        let is_pe = bytes.len() > 1 && bytes[0] == b'M' && bytes[1] == b'Z';
        let process = if is_pe {
            runtime
                .load_pe_driver(&bytes)
                .map_err(|e| mlua::Error::external(format!("load_pe_driver: {e:?}")))?
        } else if use_dynamic {
            runtime
                .load_elf_dynamic(&bytes, &[])
                .map_err(|e| mlua::Error::external(format!("load_elf_dynamic: {e:?}")))?
        } else {
            runtime
                .load_elf(&bytes)
                .map_err(|e| mlua::Error::external(format!("load_elf: {e:?}")))?
        };
        // Cache the pool-routine export VAs once so per-job trackers bind
        // without re-parsing the image. Driver-mode PE loads only.
        let kernel_pool_bindings = if is_pe {
            let mut bindings = Vec::new();
            if let Ok(image) = angryier_loader::Pe32Loader::new().load(&bytes) {
                for name in crate::KERNEL_POOL_ALLOC_NAMES {
                    if let Some(va) = image.export_address(name) {
                        bindings.push((angryier_models::PoolRoutine::Alloc, va));
                    }
                }
                for name in crate::KERNEL_POOL_FREE_NAMES {
                    if let Some(va) = image.export_address(name) {
                        bindings.push((angryier_models::PoolRoutine::Free, va));
                    }
                }
            }
            bindings
        } else {
            Vec::new()
        };
        let arena = Arc::new(angryier_expr::ShardedExprArena::new(ExpressionNormalizationVersion(1)));
        Ok(Self {
            runtime,
            arena,
            template: process,
            is_pe,
            kernel_pool_bindings,
            stats_load_ms: t0.elapsed().as_millis() as u64,
            stats_jobs: 0,
            stats_run_ms_total: 0,
            stats_last_run_ms: 0,
        })
    }

    /// Runs one full campaign on a fresh clone of the prepared template.
    /// `opts` carries the complete per-campaign option surface of
    /// `angry.run` (entry, regs, symbolic, find/avoid, steps, uc_memory,
    /// stubs, ...); the returned table is the same report shape.
    pub fn run(&mut self, lua: &Lua, opts: &Table) -> mlua::Result<Table> {
        let t0 = std::time::Instant::now();
        let unsupported_fallback = self.arm_registry_fallback(opts);
        let mut campaign = self.build_campaign(opts, unsupported_fallback)?;
        let out = super::run_campaign(lua, &mut campaign, opts)?;

        let elapsed_ms = t0.elapsed().as_millis() as u64;
        self.stats_jobs += 1;
        self.stats_run_ms_total += elapsed_ms;
        self.stats_last_run_ms = elapsed_ms;
        Ok(out)
    }

    /// Arms (or clears) the shared registry's unsupported-form fallback for
    /// one campaign. The runtime (and its registry) is shared, so a fresh
    /// fallthrough provider per campaign keeps each run's
    /// `unsupported_total` / `unsupported_sites` debt snapshot honest and a
    /// previous job's fallback never leaks into a job that did not request
    /// it. In batch mode the batch's common opts arm one provider for the
    /// whole batch (the shared registry cannot carry per-job fallbacks
    /// concurrently; per-job `unsupported` debt then aggregates).
    fn arm_registry_fallback(&mut self, opts: &Table) -> Option<Arc<UnsupportedFallthrough>> {
        if opts.get::<String>("unsupported").ok().as_deref() == Some("fallthrough") {
            let fallback = Arc::new(UnsupportedFallthrough::new());
            self.runtime.registry.set_unsupported_fallback(
                Arc::clone(&fallback) as Arc<dyn angryier_semantics::SemanticProvider>
            );
            Some(fallback)
        } else {
            self.runtime.registry.clear_unsupported_fallback();
            None
        }
    }

    /// Builds one per-job [`super::Campaign`]: fresh copy-on-write clone of
    /// the template plus every per-campaign option applied (entry sentinel,
    /// kernel pool model, UC policies, seeds, pokes, stubs, redirects,
    /// patches). Lua-thread only (it parses opts tables); the returned
    /// campaign is worker-executable.
    fn build_campaign(
        &self,
        opts: &Table,
        unsupported_fallback: Option<Arc<UnsupportedFallthrough>>,
    ) -> mlua::Result<Campaign<'_>> {
        let mut process = self.template.clone();

        // Kernel pool model (driver-mode PE loads): fresh tracker per job,
        // bound from the cached export map and attached to THIS clone —
        // alloc/free/double-free accounting never crosses campaigns.
        let (kernel_pool, pool_prealloc) = if self.is_pe {
            let tracker = Arc::new(angryier_models::KernelPoolTracker::new());
            for (routine, va) in &self.kernel_pool_bindings {
                tracker.bind_internal_address(*va, *routine);
            }
            self.runtime
                .attach_kernel_pool_model(&mut process, tracker.clone())
                .map_err(|e| mlua::Error::external(format!("attach_kernel_pool_model: {e:?}")))?;
            let mut pool_prealloc = Vec::new();
            if let Ok(n) = opts.get::<usize>("pool_prealloc") {
                for _ in 0..n.min(super::POOL_PREALLOC_CAP) {
                    let ptr = tracker.fresh_pointer();
                    tracker.record_alloc();
                    pool_prealloc.push(ptr);
                }
            }
            (Some(tracker), pool_prealloc)
        } else {
            (None, Vec::new())
        };

        // Entry override: start execution at an arbitrary address instead of
        // the image entry (DriverEntry). Driver-campaign requests target
        // dispatch routines, which DriverEntry never calls — analysis of those
        // paths requires entering the handler directly (under-constrained
        // execution; the caller seeds IRP-shaped symbolic arguments).
        if let Ok(entry) = opts.get::<i64>("entry")
            && entry > 0
        {
            process
                .write_pc(entry as u64)
                .map_err(|e| mlua::Error::external(format!("entry override: {e:?}")))?;
            // Push the exit sentinel: an entry-overridden function has no
            // caller frame, so its `ret` (and a SimProcedure's pop) would
            // otherwise read stale stack and land in unmapped padding.
            let rsp = process
                .read_register(crate::register_id::GPR_BASE + 4)
                .map_err(|e| mlua::Error::external(format!("entry rsp: {e:?}")))?;
            process.state.memory = process
                .state
                .memory
                .load_concrete(rsp.wrapping_sub(8), &crate::EXIT_HOOK.to_le_bytes())
                .map_err(|e| mlua::Error::external(format!("entry frame: {e:?}")))?;
            process
                .write_register(crate::register_id::GPR_BASE + 4, rsp.wrapping_sub(8))
                .map_err(|e| mlua::Error::external(format!("entry rsp set: {e:?}")))?;
            process.hook_simproc(crate::EXIT_HOOK, "exit");
        }

        // Function-entry RSP after the override (sentinel retaddr at [rsp]):
        // stack-passed args live at [rsp+8], [rsp+0x10], ... — surfaced so
        // structured-entry scripts can poke/symbolize exact argument slots.
        let entry_rsp = process
            .read_register(crate::register_id::GPR_BASE + 4)
            .map_err(|e| mlua::Error::external(format!("entry rsp probe: {e:?}")))?;
        // Under-constrained memory guard (opt-in, debt-recorded): map the low
        // 64 KiB as zeroed RAM so reads/writes through NULL-adjacent garbage
        // pointers behave as zero pages instead of faulting. Standard UC-SymEX
        // relaxation — paths taken under zeroed guesses are candidates for
        // review, and callers must surface the relaxation in verdict
        // provenance. Never changes executable mappings.
        if opts.get::<bool>("zero_low_pages").unwrap_or(false) {
            let region = angryier_memory::MemoryRegion {
                object: angryier_types::ObjectId(0),
                base: 0,
                size: 0x1_0000,
                readable: true,
                writable: true,
                executable: false,
            };
            if let Ok(m) = process.state.memory.with_region(region) {
                process.state.memory = m.load_concrete(0, &vec![0u8; 0x1_0000]).unwrap_or(m);
            }
        }

        // Opt-in under-constrained memory (`uc_memory = true`, default OFF —
        // exact current behavior): unmapped reads return zero bytes and unmapped
        // writes allocate the page zero-backed on demand, so reads/writes
        // through under-constrained pointers (uninitialized caller frames,
        // garbage RBP chains) stop killing the state. Every relaxed hit is
        // debt-recorded (capped + deduplicated, shared across all forks) and
        // surfaced in the result as `unmapped_total` / `unmapped_sites`; both
        // the concrete interpreter and the symbolic byte store honor the policy
        // through the memory layer they share. Mirrors `zero_low_pages` /
        // `unsupported = "fallthrough"`: relaxation is a deliberate, reported
        // fidelity debt, never silent.
        //
        // `uc_write_ro = true` (default OFF, only meaningful together with
        // `uc_memory`) additionally relaxes writes into mapped read-only DATA
        // pages whose current bytes are concrete: the previous bytes land in the
        // ledger's revert log, the hit is surfaced with `op = "write_ro"` in
        // `unmapped_sites` and counted in the parallel `ro_write_total`, and
        // executable pages are never relaxed.
        let uc_memory_armed = opts.get::<bool>("uc_memory").unwrap_or(false);
        let uc_write_ro = opts.get::<bool>("uc_write_ro").unwrap_or(false);
        let uc_drop_exec = opts.get::<bool>("uc_drop_exec_write").unwrap_or(true);
        if uc_memory_armed {
            process.state.memory = process
                .state
                .memory
                .with_uc_memory()
                .with_uc_write_ro(uc_write_ro)
                .with_uc_drop_exec_write(uc_drop_exec);
        }
        // Every clone/fork of the armed memory shares one debt ledger, so this
        // probe — cloned before the process moves into the session — reports the
        // whole run's debt even if every state dies.
        let uc_memory_probe = uc_memory_armed.then(|| process.state.memory.clone());

        // Bulk memory loads from files: `load_mem = { { addr = 0x..., path =
        // "..." }, ... }` — writes the file's bytes at `addr` (PE virtual-tail
        // sections, live globals, heap snapshots). Pre-session like `poke`.
        if let Ok(tbl) = opts.get::<Table>("load_mem") {
            for pair in tbl.pairs::<Value, Table>() {
                let (_, entry) = pair?;
                let addr = entry.get::<i64>("addr")? as u64;
                let path: String = entry.get("path")?;
                let bytes = std::fs::read(&path).map_err(|e| mlua::Error::external(format!("load_mem {path}: {e}")))?;
                let mem = &process.state.memory;
                process.state.memory = match mem.load_concrete(addr, &bytes) {
                    Ok(m) => m,
                    Err(angryier_memory::MemoryError::Unmapped(_)) if uc_memory_armed => {
                        let page_base = addr & !0xfff;
                        let size = ((addr + bytes.len() as u64 + 0xfff) & !0xfff) - page_base;
                        let region = angryier_memory::MemoryRegion {
                            object: angryier_types::ObjectId(0),
                            base: page_base,
                            size: size as u64,
                            readable: true,
                            writable: true,
                            executable: true,
                        };
                        let m = mem.with_region(region).unwrap_or_else(|_| mem.clone());
                        m.load_concrete(addr, &bytes)
                            .map_err(|e| mlua::Error::external(format!("load_mem {path}: {e:?}")))?
                    }
                    Err(e) => return Err(mlua::Error::external(format!("load_mem {path}: {e:?}"))),
                };
            }
        }

        // The Z3 backend needs a shared arena reader — keep the arena in Arc.
        let mut session = crate::SymbolicSession::new(&self.runtime, self.arena.as_ref(), process);
        // UC pin fallback rides the same opt as the memory policy: an address
        // the solver cannot concretize in budget pins to a fabricated page
        // instead of failing the state.
        if uc_memory_armed {
            session = session.with_uc_pin_fallback();
        }

        // Symbolic register marks: `symbolic = { rdi = 64 }` or `{ "rdi" }`.
        // The width value is validated — only 64-bit GPR symbols are
        // supported (see [`super::SYMBOLIC_GPR_WIDTH`]) — and unknown register names
        // error instead of being silently skipped.
        if let Ok(sym) = opts.get::<Table>("symbolic") {
            for pair in sym.pairs::<Value, Value>() {
                let (k, v) = pair?;
                let Some((name, width)) = symbolic_mark_from_pair(&k, &v)? else {
                    continue;
                };
                let reg = reg_by_name(&name).ok_or_else(|| mlua::Error::external(format!("bad reg {name}")))?;
                session
                    .mark_symbolic(0, reg, angryier_ir::IrType::Bits(width))
                    .map_err(|e| mlua::Error::external(format!("mark_symbolic: {e:?}")))?;
            }
        }
        // Concrete register seeds: `regs = { rcx = 0x..., rdx = 0x... }` —
        // dispatch-entry drivers get IRP-shaped pointer arguments. Kernel
        // pointers above i64::MAX travel in the `_hex` string form:
        // `regs = { rcx_hex = "0xffff8000..." }` (see [`reg_seed_from_pair`]).
        if let Ok(tbl) = opts.get::<Table>("regs") {
            for pair in tbl.pairs::<Value, Value>() {
                let (k, v) = pair?;
                let Some((reg, value)) = reg_seed_from_pair(&k, &v)? else {
                    continue;
                };
                session.states[0]
                    .process
                    .write_register(reg, value)
                    .map_err(|e| mlua::Error::external(format!("regs seed: {e:?}")))?;
                // The evaluator's execution shadow was seeded from the state's
                // register file at session construction — a seed that only
                // touches the process store is erased on the first step (the
                // shadow re-derives the concrete value). `concrete_registers`
                // is the seed surface the shadow consults; the session-level
                // (`open_session`) regs path has always written it.
                session.states[0].concrete_registers.insert(reg, value);
            }
        }

        // Concrete memory pokes: `poke = { { addr = 0x..., value = 0x... }, ... }`
        // — 8-byte little-endian writes (e.g. IRP.CurrentStackLocation pointing
        // at a symbolic IO_STACK_LOCATION block).
        if let Ok(tbl) = opts.get::<Table>("poke") {
            for pair in tbl.pairs::<Value, Table>() {
                let (_, entry) = pair?;
                let addr = entry.get::<i64>("addr")? as u64;
                let value = entry.get::<i64>("value")? as u64;
                let bytes = value.to_le_bytes();
                let mem = &session.states[0].process.state.memory;
                session.states[0].process.state.memory = match mem.load_concrete(addr, &bytes) {
                    Ok(m) => m,
                    Err(angryier_memory::MemoryError::Unmapped(_)) if uc_memory_armed => {
                        let page_base = addr & !0xfff;
                        let region = angryier_memory::MemoryRegion {
                            object: angryier_types::ObjectId(0),
                            base: page_base,
                            size: 0x1000,
                            readable: true,
                            writable: true,
                            executable: true,
                        };
                        let m = mem.with_region(region).unwrap_or_else(|_| mem.clone());
                        m.load_concrete(addr, &bytes)
                            .map_err(|e| mlua::Error::external(format!("poke: {e:?}")))?
                    }
                    Err(e) => return Err(mlua::Error::external(format!("poke: {e:?}"))),
                };
            }
            session.states[0].memory =
                angryier_execution::SymbolicSessionMemory::new(session.states[0].process.state.memory.clone());
        }

        // Symbolic memory: `symbolic_memory = { { addr = 0x..., len = 48 }, ... }`
        // — byte-granular input symbols (IRP/IO_STACK_LOCATION contents).
        if let Ok(tbl) = opts.get::<Table>("symbolic_memory") {
            for pair in tbl.pairs::<Value, Table>() {
                let (_, entry) = pair?;
                let addr = entry.get::<i64>("addr")? as u64;
                let len = entry.get::<i64>("len")? as usize;
                session
                    .mark_memory_symbolic(0, addr, len)
                    .map_err(|e| mlua::Error::external(format!("symbolic_memory: {e:?}")))?;
            }
        }

        // Symbolic argv: `argv = 8` materializes 8 bytes (7 + NUL) into
        // argv[0]'s stack string.
        if let Ok(argv_len) = opts.get::<u64>("argv") {
            session
                .symbolize_argv0(0, argv_len)
                .map_err(|e| mlua::Error::external(format!("symbolize_argv0: {e:?}")))?;
        }
        // Symbolic files: `files = { "flag.txt" = true }` — openat on those
        // paths returns a fd whose reads materialize symbolic bytes.
        if let Ok(files) = opts.get::<Table>("files") {
            for pair in files.pairs::<Value, Value>() {
                if let (Value::String(name), Value::Boolean(true)) = pair?
                    && let Ok(p) = name.to_str()
                {
                    session.states[0].process.symbolic_files.insert(p.to_string());
                }
            }
        }
        // Concrete files: `contents = { "flag.txt" = "bytes" }`.
        if let Ok(files) = opts.get::<Table>("contents") {
            for pair in files.pairs::<String, String>() {
                let (name, data) = pair?;
                session.states[0].process.files.insert(name, data.into_bytes());
            }
        }

        if let Ok(tbl) = opts.get::<Table>("stubs") {
            for pair in tbl.pairs::<Value, Value>() {
                let (k, v) = pair?;
                let ret_val = match &v {
                    Value::Table(entry) => entry
                        .get::<Value>("ret")
                        .or_else(|_| entry.get::<Value>("value"))
                        .ok()
                        .and_then(|v| parse_lua_u64(&v))
                        .unwrap_or(0),
                    _ => parse_lua_u64(&v).unwrap_or(0),
                };

                let addrs = if let Some(addr) = parse_lua_u64(&k) {
                    let mut list = vec![addr];
                    if let Ok(bytes) = session.states[0].process.state.memory.read(addr, 8) {
                        let mut buf = [0u8; 8];
                        for (i, b) in bytes.iter().enumerate() {
                            if let ByteValue::Concrete(val) = b {
                                buf[i] = *val;
                            }
                        }
                        let ptr = u64::from_le_bytes(buf);
                        if ptr >= PE_DRIVER_STUB_BASE && ptr < PE_DRIVER_STUB_BASE + PE_DRIVER_STUB_SIZE {
                            list.push(ptr);
                        }
                    }
                    list
                } else if let Value::String(s) = &k
                    && let Ok(name) = s.to_str()
                {
                    let mut list = Vec::new();
                    for (stub_addr, (dll, export)) in &session.states[0].process.pe_import_stubs {
                        if export.eq_ignore_ascii_case(name.as_ref()) || format!("{dll}!{export}").eq_ignore_ascii_case(name.as_ref()) {
                            list.push(*stub_addr);
                        }
                    }
                    list
                } else if let Value::Table(entry) = &v
                    && let Ok(a) = entry.get::<Value>("addr")
                    && let Some(addr) = parse_lua_u64(&a)
                {
                    vec![addr]
                } else {
                    continue;
                };

                for a in addrs {
                    session.states[0].process.stub_function(a, ret_val);
                }
            }
        }
        if let Ok(tbl) = opts.get::<Table>("redirects") {
            for pair in tbl.pairs::<Value, Value>() {
                let (k, v) = pair?;
                let (from_pc, to_pc) = if let Some(from) = parse_lua_u64(&k) {
                    let to = match v {
                        Value::Table(entry) => entry
                            .get::<Value>("to")
                            .or_else(|_| entry.get::<Value>("target"))
                            .ok()
                            .and_then(|v| parse_lua_u64(&v)),
                        _ => parse_lua_u64(&v),
                    };
                    if let Some(target) = to {
                        (from, target)
                    } else {
                        continue;
                    }
                } else if let Value::Table(entry) = v {
                    let from = entry
                        .get::<Value>("from")
                        .or_else(|_| entry.get::<Value>("addr"))
                        .ok()
                        .and_then(|v| parse_lua_u64(&v));
                    let to = entry
                        .get::<Value>("to")
                        .or_else(|_| entry.get::<Value>("target"))
                        .ok()
                        .and_then(|v| parse_lua_u64(&v));
                    if let (Some(f), Some(t)) = (from, to) {
                        (f, t)
                    } else {
                        continue;
                    }
                } else {
                    continue;
                };
                session.states[0].process.redirect_control_flow(from_pc, to_pc);
            }
        }
        if let Ok(tbl) = opts.get::<Table>("patches") {
            for pair in tbl.pairs::<Value, Value>() {
                let (k, v) = pair?;
                let (addr, data) = if let Some(addr) = parse_lua_u64(&k) {
                    (addr, v)
                } else if let Value::Table(entry) = &v {
                    let a = entry
                        .get::<Value>("addr")
                        .ok()
                        .and_then(|v| parse_lua_u64(&v));
                    let val = entry.get::<Value>("bytes").or_else(|_| entry.get::<Value>("data")).ok();
                    if let (Some(addr), Some(val)) = (a, val) {
                        (addr, val)
                    } else {
                        continue;
                    }
                } else {
                    continue;
                };
                let raw = parse_patch_bytes(data)?;
                session.states[0]
                    .process
                    .patch_bytes(addr, &raw)
                    .map_err(|e| mlua::Error::external(format!("patch_bytes: {e:?}")))?;
                session.states[0].memory =
                    angryier_execution::SymbolicSessionMemory::new(session.states[0].process.state.memory.clone());
            }
        }

        Ok(Campaign {
            runtime: &self.runtime,
            arena: self.arena.clone(),
            session,
            kernel_pool,
            pool_prealloc,
            unsupported_fallback,
            uc_memory_probe,
            entry_rsp,
            outcome: None,
        })
    }

    /// Runs a batch of campaigns (`jobs` = array of `angry.run`-style opts
    /// tables) across a native worker pool: the prepared image is loaded
    /// once, every job executes on a fresh copy-on-write clone of the
    /// template against the shared (Sync) runtime and arena, and the Lua
    /// thread serializes the ordered report tables afterwards. This is the
    /// in-process equivalent of the bulk driver's shard processes — same
    /// isolation (per-job session/tracker/debt), one image load.
    ///
    /// `batch_opts.threads` caps the worker count (default: logical CPUs).
    /// Per-job `unsupported` fallthrough is a batch-level option: pass it
    /// through `batch_opts` (or the `angry.prepare` options) — the shared
    /// registry cannot carry per-job fallbacks concurrently, and the
    /// fallthrough debt then aggregates across the batch.
    pub fn run_batch(&mut self, lua: &Lua, jobs: &Table, batch_opts: Option<&Table>) -> mlua::Result<Table> {
        let t0 = std::time::Instant::now();
        let job_tables: Vec<Table> = jobs.sequence_values().collect::<mlua::Result<_>>()?;
        if job_tables.is_empty() {
            return Ok(lua.create_table()?);
        }
        let threads = batch_opts
            .and_then(|t| t.get::<usize>("threads").ok())
            .filter(|&n| n > 0)
            .unwrap_or_else(|| std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1))
            .min(job_tables.len());

        // One fallback provider for the whole batch (see the arm_registry
        // doc above).
        let fallback = match batch_opts {
            Some(opts) => self.arm_registry_fallback(opts),
            None => None,
        };

        // Parse plans and build campaigns on the Lua thread (opts tables
        // are Lua-bound; everything downstream is worker-safe).
        let mut campaigns: Vec<Campaign<'_>> = Vec::with_capacity(job_tables.len());
        let mut plans: Vec<super::CampaignPlan> = Vec::with_capacity(job_tables.len());
        for opts in &job_tables {
            plans.push(super::parse_campaign_plan(opts)?);
            campaigns.push(self.build_campaign(opts, fallback.clone())?);
        }

        // Execute on scoped worker threads over statically disjoint
        // chunks: one campaign per (worker, chunk-slot). Each campaign owns
        // its session, kernel tracker, and debt probes; the shared
        // runtime/arena are Sync.
        let jobs_per_thread = job_tables.len().div_ceil(threads);
        std::thread::scope(|scope| {
            for (camp_chunk, plan_chunk) in campaigns.chunks_mut(jobs_per_thread).zip(plans.chunks(jobs_per_thread)) {
                scope.spawn(move || {
                    for (campaign, plan) in camp_chunk.iter_mut().zip(plan_chunk.iter()) {
                        super::campaign_execute(campaign, plan);
                    }
                });
            }
        });

        // Serialize the ordered results on the Lua thread.
        let out = lua.create_table()?;
        for (i, (campaign, job_opts)) in campaigns.iter_mut().zip(job_tables.iter()).enumerate() {
            let entry = lua.create_table()?;
            let error = campaign.outcome.as_ref().and_then(|outcome| outcome.error.clone());
            if let Some(error) = error {
                entry.set("ok", false)?;
                entry.set("error", error)?;
            } else {
                entry.set("ok", true)?;
                entry.set("report", super::campaign_report(lua, campaign, &plans[i], job_opts)?)?;
            }
            out.set(i + 1, entry)?;
        }

        let elapsed_ms = t0.elapsed().as_millis() as u64;
        self.stats_jobs += campaigns.len() as u64;
        self.stats_run_ms_total += elapsed_ms;
        self.stats_last_run_ms = elapsed_ms;
        Ok(out)
    }

    /// Load-time and cumulative run-time statistics (Lua table): where the
    /// wall-clock cost actually goes, one image load vs. many jobs.
    fn stats_table(&self, lua: &Lua) -> mlua::Result<Table> {
        let t = lua.create_table()?;
        t.set("load_ms", self.stats_load_ms)?;
        t.set("jobs", self.stats_jobs)?;
        t.set("run_ms_total", self.stats_run_ms_total)?;
        t.set("last_run_ms", self.stats_last_run_ms)?;
        t.set("avg_run_ms", if self.stats_jobs > 0 {
            self.stats_run_ms_total / self.stats_jobs
        } else {
            0
        })?;
        t.set("is_pe", self.is_pe)?;
        t.set("image_regions", self.template.state.memory.regions().len())?;
        Ok(t)
    }

    /// Compile-time Send/Sync evidence for the native worker-pool stage:
    /// every piece a per-worker campaign would need to move across threads.
    /// If these lines fail to compile, the type system has found shared
    /// mutable state that parallel workers would race on.
    #[allow(dead_code)]
    fn assert_worker_shareable() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<XedRuntime>();
        send_sync::<angryier_expr::ShardedExprArena>();
        send_sync::<crate::Process>();
        send_sync::<crate::SymbolicState>();
        send_sync::<crate::SymbolicRunReport>();
        send_sync::<crate::ExplorationPolicy>();
        // The whole worker payload: everything a batch job moves across
        // threads (borrowed runtime/arena, per-job session and probes).
        // Z3 backends are deliberately absent: their contexts are not
        // `Send`, so workers create them thread-locally (see
        // `campaign_execute`).
        send_sync::<super::Campaign<'static>>();
    }
}

impl UserData for PreparedImage {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        // img:run(opts) -> report table — the full `angry.run` option
        // surface, executed on a fresh clone of the prepared template.
        methods.add_method_mut("run", |lua, this, opts: Option<Table>| {
            let default = lua.create_table()?;
            let opts = opts.as_ref().unwrap_or(&default);
            this.run(lua, opts)
        });

        // img:run_batch(jobs[, batch_opts]) -> array of {{ ok, error?,
        // report? }} — native worker pool over one prepared image
        // (`batch_opts.threads` caps the pool; default logical CPUs).
        methods.add_method_mut("run_batch", |lua, this, (jobs, batch_opts): (Table, Option<Table>)| {
            this.run_batch(lua, &jobs, batch_opts.as_ref())
        });

        // img:stats() -> { load_ms, jobs, run_ms_total, last_run_ms,
        // avg_run_ms, is_pe, image_regions } — load-vs-run cost evidence.
        methods.add_method("stats", |lua, this, ()| this.stats_table(lua));
    }
}
