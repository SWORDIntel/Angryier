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
use super::{Campaign, reg_seed_from_pair, symbolic_mark_from_pair};
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
        // PE32 (IA-32) images decode in legacy-32 mode against the IA-32
        // execution profile; the loader tags them TargetProfileId(2).
        let pe32_image = super::is_pe32_image(&bytes);
        let mut runtime = if pe32_image {
            crate::Runtime::with_native_xed_mode(
                SemanticVersion(1),
                TargetProfileId(2),
                angryier_arch_xed_ffi::XedMachineMode::Legacy32,
            )
        } else {
            crate::Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1))
        };
        if opts
            .and_then(|o| o.get::<String>("unsupported").ok())
            .is_some_and(|v| v == "fallthrough")
        {
            let fallback = Arc::new(UnsupportedFallthrough::new());
            runtime
                .registry
                .set_unsupported_fallback(Arc::clone(&fallback) as Arc<dyn angryier_semantics::SemanticProvider>);
        }
        let use_dynamic = opts.and_then(|o| o.get::<bool>("dynamic").ok()).unwrap_or(false);
        let is_pe = bytes.len() > 1 && bytes[0] == b'M' && bytes[1] == b'Z';
        let process = if is_pe {
            if pe32_image {
                runtime
                    .load_pe32_user(&bytes)
                    .map_err(|e| mlua::Error::external(format!("load_pe32_user: {e:?}")))?
            } else {
                runtime
                    .load_pe_driver(&bytes)
                    .map_err(|e| mlua::Error::external(format!("load_pe_driver: {e:?}")))?
            }
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
            self.runtime
                .registry
                .set_unsupported_fallback(Arc::clone(&fallback) as Arc<dyn angryier_semantics::SemanticProvider>);
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
            // otherwise read stale stack and land in unmapped padding. The
            // frame width follows the image profile: a PE32 (IA-32) `ret`
            // pops 4 bytes, PE32+ pops 8.
            let is_pe32 = process.target_profile == angryier_types::TargetProfileId(2);
            let rsp = process
                .read_register(crate::register_id::GPR_BASE + 4)
                .map_err(|e| mlua::Error::external(format!("entry rsp: {e:?}")))?;
            let (hook, sentinel_addr, sentinel_bytes) = if is_pe32 {
                (
                    crate::PE32_EXIT_HOOK,
                    rsp.wrapping_sub(4),
                    crate::PE32_EXIT_HOOK.to_le_bytes().to_vec(),
                )
            } else {
                (
                    crate::EXIT_HOOK,
                    rsp.wrapping_sub(8),
                    crate::EXIT_HOOK.to_le_bytes().to_vec(),
                )
            };
            process.state.memory = process
                .state
                .memory
                .load_concrete(sentinel_addr, &sentinel_bytes)
                .map_err(|e| mlua::Error::external(format!("entry frame: {e:?}")))?;
            process
                .write_register(crate::register_id::GPR_BASE + 4, sentinel_addr)
                .map_err(|e| mlua::Error::external(format!("entry rsp set: {e:?}")))?;
            process.hook_simproc(hook, "exit");
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
                        if (PE_DRIVER_STUB_BASE..PE_DRIVER_STUB_BASE + PE_DRIVER_STUB_SIZE).contains(&ptr) {
                            list.push(ptr);
                        }
                    }
                    list
                } else if let Value::String(s) = &k
                    && let Ok(name) = s.to_str()
                {
                    let mut list = Vec::new();
                    for (stub_addr, (dll, export)) in &session.states[0].process.pe_import_stubs {
                        if export.eq_ignore_ascii_case(name.as_ref())
                            || format!("{dll}!{export}").eq_ignore_ascii_case(name.as_ref())
                        {
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
                    let a = entry.get::<Value>("addr").ok().and_then(|v| parse_lua_u64(&v));
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
            return lua.create_table();
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
        t.set(
            "avg_run_ms",
            self.stats_run_ms_total.checked_div(self.stats_jobs).unwrap_or(0),
        )?;
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

/// Canonical, applied root seed options. The root snapshot digest also pins the
/// loaded image and effective state; these bytes bind the accepted Lua options
/// themselves to the manifest rather than trusting caller-supplied labels.
fn sustained_seed_bytes(opts: &Table) -> mlua::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for key in ["symbolic", "regs"] {
        let mut seeds = std::collections::BTreeMap::new();
        if let Some(table) = opts.get::<Option<Table>>(key)? {
            for pair in table.pairs::<Value, Value>() {
                let (name, value) = pair?;
                let (reg, seed) = if key == "symbolic" {
                    let (name, width) = symbolic_mark_from_pair(&name, &value)?
                        .ok_or_else(|| mlua::Error::external("sustained: invalid symbolic seed"))?;
                    (
                        reg_by_name(&name).ok_or_else(|| mlua::Error::external(format!("bad reg {name}")))?,
                        u64::from(width),
                    )
                } else {
                    reg_seed_from_pair(&name, &value)?
                        .ok_or_else(|| mlua::Error::external("sustained: invalid regs seed"))?
                };
                if seeds.insert(reg, seed).is_some() {
                    return Err(mlua::Error::external(format!(
                        "sustained: duplicate {key} register seed"
                    )));
                }
            }
        }
        bytes.extend_from_slice(&(seeds.len() as u64).to_le_bytes());
        for (reg, seed) in seeds {
            bytes.extend_from_slice(&reg.to_le_bytes());
            bytes.extend_from_slice(&seed.to_le_bytes());
        }
    }
    Ok(bytes)
}

fn sustained_digest_hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sustained_targets(opts: &Table) -> mlua::Result<(Vec<u64>, Vec<u64>)> {
    let Some(targets) = opts.get::<Option<Table>>("targets")? else {
        return Ok((Vec::new(), Vec::new()));
    };
    if targets.metatable().is_some() {
        return Err(mlua::Error::external("sustained: targets metatables are unsupported"));
    }
    for pair in targets.clone().pairs::<Value, Value>() {
        let (key, _) = pair?;
        let Value::String(key) = key else {
            return Err(mlua::Error::external("sustained: target keys must be find or avoid"));
        };
        if !matches!(key.to_str()?.as_ref(), "find" | "avoid") {
            return Err(mlua::Error::external("sustained: unknown targets field"));
        }
    }
    let parse = |name: &str| -> mlua::Result<Vec<u64>> {
        let Some(list) = targets.get::<Option<Table>>(name)? else {
            return Ok(Vec::new());
        };
        if list.metatable().is_some() {
            return Err(mlua::Error::external(format!(
                "sustained: targets.{name} metatables are unsupported"
            )));
        }
        let mut addresses = Vec::new();
        for pair in list.clone().pairs::<Value, Value>() {
            let (key, value) = pair?;
            if !matches!(key, Value::Integer(n) if (1..=4096).contains(&n)) {
                return Err(mlua::Error::external(format!(
                    "sustained: targets.{name} must be a dense array of at most 4096 addresses"
                )));
            }
            let addr = match value {
                Value::Integer(_) | Value::String(_) => parse_lua_u64(&value),
                _ => None,
            }
            .ok_or_else(|| {
                mlua::Error::external(format!(
                    "sustained: invalid targets.{name} address (use an integer or exact hex string)"
                ))
            })?;
            addresses.push(addr);
        }
        if addresses.len() != list.raw_len() || addresses.len() > 4096 {
            return Err(mlua::Error::external(format!(
                "sustained: targets.{name} must be a dense array of at most 4096 addresses"
            )));
        }
        addresses.sort_unstable();
        if addresses.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(mlua::Error::external(format!(
                "sustained: duplicate targets.{name} address"
            )));
        }
        Ok(addresses)
    };
    Ok((parse("find")?, parse("avoid")?))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SustainedPolicy {
    ForkAll,
    RankTargets { exclude_avoid: bool },
}

fn sustained_policy(opts: &Table) -> mlua::Result<SustainedPolicy> {
    let artifacts: Table = opts.get("artifacts")?;
    let script: mlua::LuaString = artifacts.get("script")?;
    let label: mlua::LuaString = artifacts.get("policy")?;
    let policy = match (script.as_bytes().as_ref(), label.as_bytes().as_ref()) {
        (b"angry.sustained/v1", b"fork-all/v1") => SustainedPolicy::ForkAll,
        (b"angry.sustained/v2", b"rank-targets/v1") => {
            let table = opts.get::<Option<Table>>("policy")?;
            let mut exclude_avoid = false;
            if let Some(table) = table {
                if table.metatable().is_some() {
                    return Err(mlua::Error::external("sustained: policy metatables are unsupported"));
                }
                for pair in table.pairs::<Value, Value>() {
                    let (key, value) = pair?;
                    let Value::String(key) = key else {
                        return Err(mlua::Error::external("sustained: policy keys must be strings"));
                    };
                    if key.to_str()?.as_ref() != "exclude_avoid" {
                        return Err(mlua::Error::external("sustained: unsupported policy field"));
                    }
                    let Value::Boolean(value) = value else {
                        return Err(mlua::Error::external("sustained: policy.exclude_avoid must be boolean"));
                    };
                    exclude_avoid = value;
                }
            }
            SustainedPolicy::RankTargets { exclude_avoid }
        }
        (b"angry.sustained/v1", _) | (b"angry.sustained/v2", _) => {
            return Err(mlua::Error::external(
                "sustained: custom exploration policy is unsupported",
            ));
        }
        _ => {
            return Err(mlua::Error::external(
                "sustained: analyst script execution is unsupported",
            ));
        }
    };
    if policy == SustainedPolicy::ForkAll && opts.contains_key("policy")? {
        return Err(mlua::Error::external(
            "sustained: policy options require angry.sustained/v2",
        ));
    }
    Ok(policy)
}

/// Snapshot the effective, parsed options rather than retaining mutable Lua tables.
fn sustained_options_digest(opts: &Table) -> mlua::Result<angryier_distribution::contracts::Digest> {
    use angryier_distribution::contracts::Digest;
    let mut bytes = b"angry.sustained/options/v2\0".to_vec();
    let path: String = opts.get("ledger")?;
    bytes.extend_from_slice(path.as_bytes());
    bytes.push(0);
    for pair in opts.clone().pairs::<Value, Value>() {
        let (key, _) = pair?;
        let Value::String(key) = key else {
            return Err(mlua::Error::external("sustained: option keys must be strings"));
        };
        if !matches!(
            key.to_str()?.as_ref(),
            "ledger" | "artifacts" | "limits" | "fidelity" | "symbolic" | "regs" | "targets" | "policy"
        ) {
            return Err(mlua::Error::external(format!(
                "sustained: unsupported option {}",
                key.to_str()?
            )));
        }
    }
    for (name, table) in [
        ("options", opts.clone()),
        ("artifacts", opts.get::<Table>("artifacts")?),
        ("limits", opts.get::<Table>("limits")?),
    ] {
        if table.metatable().is_some() {
            return Err(mlua::Error::external(format!(
                "sustained: {name} metatables are unsupported"
            )));
        }
    }
    for name in ["symbolic", "regs", "targets"] {
        if let Some(table) = opts.get::<Option<Table>>(name)?
            && table.metatable().is_some()
        {
            return Err(mlua::Error::external(format!(
                "sustained: {name} metatables are unsupported"
            )));
        }
    }
    let artifacts: Table = opts.get("artifacts")?;
    for pair in artifacts.clone().pairs::<Value, Value>() {
        let (key, _) = pair?;
        let Value::String(key) = key else {
            return Err(mlua::Error::external("sustained: artifact keys must be strings"));
        };
        if !matches!(
            key.to_str()?.as_ref(),
            "script" | "policy" | "solver_policy" | "inputs" | "stubs"
        ) {
            return Err(mlua::Error::external(format!(
                "sustained: unsupported artifact {}",
                key.to_str()?
            )));
        }
    }
    for name in ["script", "policy", "solver_policy"] {
        let value: mlua::LuaString = artifacts.get(name)?;
        bytes.extend_from_slice(&(value.as_bytes().len() as u64).to_le_bytes());
        bytes.extend_from_slice(&value.as_bytes());
    }
    for name in ["inputs", "stubs"] {
        if let Some(table) = artifacts.get::<Option<Table>>(name)?
            && (table.metatable().is_some() || table.pairs::<Value, Value>().next().is_some())
        {
            return Err(mlua::Error::external(format!(
                "sustained: {name} artifacts are not applied or replay-validated"
            )));
        }
    }
    bytes.extend_from_slice(&sustained_seed_bytes(opts)?);
    let (find, avoid) = sustained_targets(opts)?;
    bytes.push(match sustained_policy(opts)? {
        SustainedPolicy::ForkAll => 0,
        SustainedPolicy::RankTargets { exclude_avoid: false } => 1,
        SustainedPolicy::RankTargets { exclude_avoid: true } => 2,
    });
    for addresses in [find, avoid] {
        bytes.extend_from_slice(&(addresses.len() as u64).to_le_bytes());
        for address in addresses {
            bytes.extend_from_slice(&address.to_le_bytes());
        }
    }
    let limits: Table = opts.get("limits")?;
    for pair in limits.clone().pairs::<Value, Value>() {
        let (key, _) = pair?;
        let Value::String(key) = key else {
            return Err(mlua::Error::external("sustained: limit keys must be strings"));
        };
        if !matches!(
            key.to_str()?.as_ref(),
            "max_steps"
                | "max_path_steps"
                | "max_active_states"
                | "max_path_depth"
                | "max_loop_visits"
                | "max_solver_millis"
                | "max_wall_millis"
                | "max_ram_bytes"
                | "max_disk_bytes"
                | "max_trace_bytes"
        ) {
            return Err(mlua::Error::external(format!(
                "sustained: unsupported limit {}",
                key.to_str()?
            )));
        }
    }
    for name in [
        "max_steps",
        "max_path_steps",
        "max_active_states",
        "max_path_depth",
        "max_loop_visits",
        "max_solver_millis",
        "max_wall_millis",
        "max_ram_bytes",
        "max_disk_bytes",
        "max_trace_bytes",
    ] {
        let n: u64 = limits.get(name)?;
        bytes.extend_from_slice(&n.to_le_bytes());
    }
    let fidelity: String = opts.get("fidelity")?;
    bytes.extend_from_slice(fidelity.as_bytes());
    Ok(Digest::of(&bytes))
}
fn sustained_evidence_table(
    lua: &Lua,
    report: angryier_provenance::sustained::EvidenceReport<'_>,
) -> mlua::Result<Table> {
    use angryier_provenance::sustained::{EdgeBasis, PathDisposition, ReplayVerification};
    let summary = report.summary;
    let evidence = lua.create_table()?;
    evidence.set("schema_version", summary.schema_version)?;
    evidence.set("completion", format!("{:?}", summary.completion))?;
    evidence.set("campaign_digest", sustained_digest_hex(&summary.scope.campaign_digest))?;
    evidence.set("bounds_digest", sustained_digest_hex(&summary.scope.bounds_digest))?;
    evidence.set("contract_epoch", summary.scope.contract_epoch)?;
    evidence.set("fidelity", format!("{:?}", summary.scope.fidelity))?;
    evidence.set("closure_attested", summary.closure.is_some())?;
    for (key, count) in [
        ("terminal_paths", summary.terminal_paths),
        ("excluded_paths", summary.excluded_paths),
        ("infeasible_paths", summary.infeasible_paths),
        ("pending_paths", summary.pending_paths),
        ("failed_paths", summary.failed_paths),
        ("retained_frontier", summary.retained_frontier),
        ("observed_edges", summary.observed_edges),
        ("inferred_edges", summary.inferred_edges),
        ("infeasible_edges", summary.infeasible_edges),
        ("dynamic_blocks", summary.dynamic_blocks),
        ("replay_verified_witnesses", summary.replay_verified_witnesses),
        ("semantic_debt_records", summary.semantic_debt_records),
        ("storage_rejections", summary.storage_rejections),
    ] {
        evidence.set(key, count)?;
    }
    let paths = lua.create_table()?;
    for (index, path) in report.paths.iter().enumerate() {
        let item = lua.create_table()?;
        item.set("path_id", sustained_digest_hex(&path.path_id))?;
        item.set("provenance_digest", sustained_digest_hex(&path.provenance_digest))?;
        item.set("fidelity", format!("{:?}", path.fidelity))?;
        item.set("disposition", format!("{:?}", path.disposition))?;
        if let PathDisposition::Pending(reason) = path.disposition {
            item.set("pending_reason", format!("{reason:?}"))?;
        }
        let blocks = lua.create_table()?;
        for (i, block) in path.blocks.iter().enumerate() {
            let t = lua.create_table()?;
            t.set("pc", block.pc)?;
            t.set("pc_hex", super::hex64(block.pc))?;
            t.set("visit_index", block.visit_index)?;
            blocks.set(i + 1, t)?;
        }
        item.set("blocks", blocks)?;
        let edges = lua.create_table()?;
        for (i, edge) in path.edges.iter().enumerate() {
            let t = lua.create_table()?;
            t.set("from_pc", edge.from_pc)?;
            t.set("from_pc_hex", super::hex64(edge.from_pc))?;
            t.set("to_pc", edge.to_pc)?;
            t.set("to_pc_hex", super::hex64(edge.to_pc))?;
            match edge.basis {
                EdgeBasis::Observed { trace_digest } => {
                    t.set("basis", "observed")?;
                    t.set("trace_digest", sustained_digest_hex(&trace_digest))?;
                }
                EdgeBasis::StaticInference { analysis_digest } => {
                    t.set("basis", "static_inference")?;
                    t.set("analysis_digest", sustained_digest_hex(&analysis_digest))?;
                }
                EdgeBasis::SolverInfeasible {
                    predicate_digest,
                    query_digest,
                    result_digest,
                } => {
                    t.set("basis", "solver_infeasible")?;
                    t.set("predicate_digest", sustained_digest_hex(&predicate_digest))?;
                    t.set("query_digest", sustained_digest_hex(&query_digest))?;
                    t.set("result_digest", sustained_digest_hex(&result_digest))?;
                }
            }
            edges.set(i + 1, t)?;
        }
        item.set("edges", edges)?;
        let branches = lua.create_table()?;
        for (i, branch) in path.branches.iter().enumerate() {
            let t = lua.create_table()?;
            t.set("pc", branch.pc)?;
            t.set("pc_hex", super::hex64(branch.pc))?;
            t.set("visit_index", branch.visit_index)?;
            t.set("predicate_digest", sustained_digest_hex(&branch.predicate_digest))?;
            t.set("query_digest", sustained_digest_hex(&branch.query_digest))?;
            t.set("result_digest", branch.result_digest.map(|d| sustained_digest_hex(&d)))?;
            t.set("tested_target", branch.tested_target)?;
            t.set("tested_target_hex", branch.tested_target.map(super::hex64))?;
            t.set("solver_status", format!("{:?}", branch.disposition))?;
            branches.set(i + 1, t)?;
        }
        item.set("branches", branches)?;
        item.set("witness_present", path.witness.is_some())?;
        item.set(
            "replay_verified",
            path.witness
                .as_ref()
                .is_some_and(|w| matches!(w.replay, ReplayVerification::Verified { .. })),
        )?;
        if let Some(witness) = path.witness.as_ref() {
            let t = lua.create_table()?;
            t.set("input_digest", sustained_digest_hex(&witness.input_digest))?;
            t.set("replay_status", format!("{:?}", witness.replay))?;
            if let ReplayVerification::Verified { trace_digest } = witness.replay {
                t.set("trace_digest", sustained_digest_hex(&trace_digest))?;
            }
            item.set("witness", t)?;
        }
        let debt = lua.create_table()?;
        for (i, record) in path.semantic_debt.iter().enumerate() {
            let t = lua.create_table()?;
            t.set("pc", record.pc)?;
            t.set("pc_hex", super::hex64(record.pc))?;
            t.set("kind", format!("{:?}", record.kind))?;
            debt.set(i + 1, t)?;
        }
        item.set("semantic_debt", debt)?;
        paths.set(index + 1, item)?;
    }
    evidence.set("paths", paths)?;
    let frontier = lua.create_table()?;
    for (i, work) in report.frontier.iter().enumerate() {
        let t = lua.create_table()?;
        t.set("path_id", sustained_digest_hex(&work.path_id))?;
        t.set("reason", format!("{:?}", work.reason))?;
        frontier.set(i + 1, t)?;
    }
    evidence.set("frontier", frontier)?;
    Ok(evidence)
}

/// Opt-in durable campaign: every advance reconstructs a fresh pinned root.
pub struct LuaSustained {
    image: PreparedImage,
    image_path: String,
    opts: Table,
    options_digest: angryier_distribution::contracts::Digest,
    manifest: angryier_distribution::contracts::CampaignManifest,
    campaign: crate::sustained::SustainedCampaign,
    find: Vec<u64>,
    avoid: Vec<u64>,
    policy_mode: SustainedPolicy,
    last_steps: u64,
    last_reason: Option<String>,
}

impl LuaSustained {
    pub fn open(image_path: String, opts: Table, resume: bool) -> mlua::Result<Self> {
        use angryier_distribution::contracts::{
            CampaignArtifacts, CampaignManifest, CampaignSpec, Digest, ExplorationLimits,
        };
        use angryier_types::FidelityProfile;
        for pair in opts.clone().pairs::<Value, Value>() {
            let (key, _) = pair?;
            let Value::String(key) = key else {
                return Err(mlua::Error::external("sustained: option keys must be strings"));
            };
            if !matches!(
                key.to_str()?.as_ref(),
                "ledger" | "artifacts" | "limits" | "fidelity" | "symbolic" | "regs" | "targets" | "policy"
            ) {
                return Err(mlua::Error::external(format!(
                    "sustained: unsupported option {}",
                    key.to_str()?
                )));
            }
        }
        let path: String = opts.get("ledger")?;
        if path.is_empty() {
            return Err(mlua::Error::external("sustained: empty ledger path"));
        }
        if std::path::Path::new(&path).exists() != resume {
            return Err(mlua::Error::external(if resume {
                "sustained: ledger does not exist"
            } else {
                "sustained: ledger exists (use resume)"
            }));
        }
        let artifacts: Table = opts.get("artifacts")?;
        let required = |key: &str| -> mlua::Result<Vec<u8>> {
            let bytes: mlua::LuaString = artifacts.get(key)?;
            if bytes.as_bytes().is_empty() {
                return Err(mlua::Error::external(format!("sustained: empty {key} artifact")));
            }
            Ok(bytes.as_bytes().to_vec())
        };
        let script = required("script")?;
        let policy_label = required("policy")?;
        let policy_mode = sustained_policy(&opts)?;
        let solver_policy = required("solver_policy")?;
        if solver_policy != b"z3-default" {
            return Err(mlua::Error::external(
                "sustained: only native z3-default solver policy is supported",
            ));
        }
        for pair in artifacts.clone().pairs::<Value, Value>() {
            let (key, _) = pair?;
            let Value::String(key) = key else {
                return Err(mlua::Error::external("sustained: artifact keys must be strings"));
            };
            if !matches!(
                key.to_str()?.as_ref(),
                "script" | "policy" | "solver_policy" | "inputs" | "stubs"
            ) {
                return Err(mlua::Error::external(format!(
                    "sustained: unsupported artifact {}",
                    key.to_str()?
                )));
            }
        }
        for key in ["inputs", "stubs"] {
            if let Some(table) = artifacts.get::<Option<Table>>(key)?
                && table.clone().pairs::<Value, Value>().next().is_some()
            {
                return Err(mlua::Error::external(format!(
                    "sustained: {key} artifacts are not applied or replay-validated"
                )));
            }
        }
        let seeds = sustained_seed_bytes(&opts)?;
        let (find, avoid) = sustained_targets(&opts)?;
        let limits: Table = opts.get("limits")?;
        let limits = ExplorationLimits {
            max_steps: limits.get("max_steps")?,
            max_path_steps: limits.get("max_path_steps")?,
            max_active_states: limits.get("max_active_states")?,
            max_path_depth: limits.get("max_path_depth")?,
            max_loop_visits: limits.get("max_loop_visits")?,
            max_solver_millis: limits.get("max_solver_millis")?,
            max_wall_millis: limits.get("max_wall_millis")?,
            max_ram_bytes: limits.get("max_ram_bytes")?,
            max_disk_bytes: limits.get("max_disk_bytes")?,
            max_trace_bytes: limits.get("max_trace_bytes")?,
        };
        let fidelity = match opts.get::<String>("fidelity")?.as_str() {
            "prove" => FidelityProfile::Prove,
            _ => return Err(mlua::Error::external("sustained: only prove fidelity is supported")),
        };
        let binary =
            std::fs::read(&image_path).map_err(|e| mlua::Error::external(format!("sustained: read image: {e}")))?;
        if binary.get(..5) != Some(&b"\x7fELF\x02"[..]) || binary.get(16..20) != Some(&[2, 0, 62, 0][..]) {
            return Err(mlua::Error::external(
                "sustained: only static ELF64 x86-64 images are supported",
            ));
        }
        let image = PreparedImage::load(&image_path, None)?;
        let loaded_bytes = std::fs::read(&image_path).map_err(mlua::Error::external)?;
        if loaded_bytes != binary {
            return Err(mlua::Error::external("sustained: binary changed while loading"));
        }
        if image.template.target_profile != TargetProfileId(1) {
            return Err(mlua::Error::external(
                "sustained: only static ELF64 x86-64 images are supported",
            ));
        }
        let root = image.build_campaign(&opts, None)?;
        let entry = root.session.states[0].process.pc().map_err(mlua::Error::external)?;
        let initial = root.session.sustained_initial_digest().map_err(mlua::Error::external)?;
        if matches!(policy_mode, SustainedPolicy::RankTargets { exclude_avoid: true })
            && avoid.binary_search(&entry).is_ok()
        {
            return Err(mlua::Error::external(
                "sustained: avoid=exclude requires an exact dynamic branch target, not entry",
            ));
        }
        drop(root);
        let options_digest = sustained_options_digest(&opts)?;
        let mut policy = policy_label;
        policy.extend_from_slice(&initial.0);
        policy.extend_from_slice(&seeds);
        if policy_mode != SustainedPolicy::ForkAll || !find.is_empty() || !avoid.is_empty() {
            policy.extend_from_slice(match policy_mode {
                SustainedPolicy::ForkAll => b"\0observational-targets/v1",
                SustainedPolicy::RankTargets { .. } => b"\0rank-targets/v1",
            });
            for list in [&find, &avoid] {
                policy.extend_from_slice(&(list.len() as u64).to_le_bytes());
                for address in list {
                    policy.extend_from_slice(&address.to_le_bytes());
                }
            }
            if let SustainedPolicy::RankTargets { exclude_avoid } = policy_mode {
                policy.push(u8::from(exclude_avoid));
                policy.extend_from_slice(&options_digest.0);
            }
        }
        let semantic_profile = b"native-xed-v1";
        let manifest = CampaignManifest::seal(CampaignSpec {
            binary_digest: Digest::of(&binary),
            architecture: "x86_64".into(),
            entry_pc: entry,
            semantic_version: "1".into(),
            semantic_profile_digest: Digest::of(semantic_profile),
            script_digest: Digest::of(&script),
            policy_digest: Digest::of(&policy),
            inputs: Vec::new(),
            stubs: Vec::new(),
            solver_version: "z3".into(),
            solver_policy_digest: Digest::of(&solver_policy),
            fidelity,
            limits,
        })
        .map_err(mlua::Error::external)?;
        let artifact_bytes = CampaignArtifacts {
            binary: &binary,
            semantic_profile,
            script: &script,
            policy: &policy,
            solver_policy: &solver_policy,
            inputs: Vec::new(),
            stubs: Vec::new(),
        };
        let campaign = crate::sustained::SustainedCampaign::open(&path, manifest.clone(), &artifact_bytes, initial)
            .map_err(mlua::Error::external)?;
        Ok(Self {
            image,
            image_path,
            opts,
            options_digest,
            manifest,
            campaign,
            find,
            avoid,
            policy_mode,
            last_steps: 0,
            last_reason: None,
        })
    }

    fn check_options(&self) -> mlua::Result<()> {
        if sustained_options_digest(&self.opts)? != self.options_digest {
            return Err(mlua::Error::external("sustained: options changed after start/resume"));
        }
        Ok(())
    }

    fn report(&self, lua: &Lua) -> mlua::Result<Table> {
        self.check_options()?;
        let ledger = self.campaign.report();
        if matches!(self.policy_mode, SustainedPolicy::RankTargets { exclude_avoid: true })
            && ledger.complete_within_declared_bounds
            && self.avoid.iter().any(|target| {
                !self.campaign.ledger.records().iter().any(|record| {
                    matches!(
                        record.status,
                        angryier_ledger::sustained::Status::Excluded | angryier_ledger::sustained::Status::Infeasible
                    ) && record
                        .unit
                        .prefix
                        .last()
                        .is_some_and(|decision| decision.target() == *target)
                })
            })
        {
            return Err(mlua::Error::external(
                "sustained: avoid=exclude requires an exact validated dynamic branch target",
            ));
        }
        let accepted: Vec<_> = self.campaign.ledger.cumulative_evidence().collect();
        let mut evidence = angryier_provenance::sustained::EvidenceBuilder::new(
            crate::sustained::scope(&self.manifest, self.campaign.ledger.epoch()),
            angryier_provenance::sustained::EvidenceLimits {
                max_paths: angryier_ledger::evidence::MAX_EVENTS,
                max_frontier: 1,
                max_items_per_path: angryier_ledger::evidence::MAX_ITEMS,
                max_bytes: angryier_ledger::evidence::MAX_EVENTS * angryier_ledger::evidence::MAX_EVENT_BYTES,
            },
        )
        .map_err(|error| mlua::Error::external(format!("sustained: evidence scope: {error:?}")))?;
        for event in accepted {
            evidence
                .add_path(event.delta.path.clone())
                .map_err(|error| mlua::Error::external(format!("sustained: persisted evidence: {error:?}")))?;
        }
        let observations = evidence.report();
        let observed: std::collections::BTreeSet<u64> = observations
            .paths
            .iter()
            .filter(|path| {
                !matches!(
                    path.disposition,
                    angryier_provenance::sustained::PathDisposition::SolverInfeasible
                )
            })
            .flat_map(|path| path.blocks.iter().map(|block| block.pc))
            .collect();
        let t = lua.create_table()?;
        t.set(
            "campaign_digest",
            self.manifest
                .campaign_digest
                .0
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        )?;
        t.set("entry", self.manifest.spec.entry_pc)?;
        t.set("entry_hex", super::hex64(self.manifest.spec.entry_pc))?;
        for (key, count) in [
            ("queued", ledger.queued),
            ("active", ledger.active),
            ("deferred", ledger.deferred),
            ("completed", ledger.completed),
            ("infeasible", ledger.infeasible),
            ("unknown", ledger.unknown),
            ("excluded", ledger.excluded),
            ("failed", ledger.failed),
            ("retired_splits", ledger.retired_splits),
        ] {
            t.set(key, count)?;
        }
        t.set(
            "complete_within_declared_bounds",
            ledger.complete_within_declared_bounds,
        )?;
        t.set("steps", self.last_steps)?;
        t.set("reason", self.last_reason.clone())?;
        let targets = lua.create_table()?;
        for (name, addresses) in [("find", &self.find), ("avoid", &self.avoid)] {
            let list = lua.create_table()?;
            for (index, &pc) in addresses.iter().enumerate() {
                let item = lua.create_table()?;
                item.set("pc", pc)?;
                item.set("pc_hex", super::hex64(pc))?;
                item.set("observed", observed.contains(&pc))?;
                list.set(index + 1, item)?;
            }
            targets.set(name, list)?;
        }
        t.set("targets", targets.clone())?;
        t.set("cumulative_targets", targets)?;
        let persisted = sustained_evidence_table(lua, observations)?;
        t.set("evidence", persisted.clone())?;
        t.set("cumulative_evidence", persisted)?;
        Ok(t)
    }

    fn advance(&mut self, lua: &Lua, timeout_ms: Option<u64>) -> mlua::Result<Table> {
        self.check_options()?;
        use angryier_distribution::contracts::Digest;
        let bytes = std::fs::read(&self.image_path)
            .map_err(|e| mlua::Error::external(format!("sustained: read image: {e}")))?;
        if Digest::of(&bytes) != self.manifest.spec.binary_digest {
            return Err(mlua::Error::external("sustained: binary artifact mismatch"));
        }
        let timeout = timeout_ms.unwrap_or(self.manifest.spec.limits.max_wall_millis);
        if timeout == 0 {
            return Err(mlua::Error::external("sustained: timeout_ms must be positive"));
        }
        let mut root = self.image.build_campaign(&self.opts, None)?;
        let arena = root.arena.clone();
        let mut backend = angryier_solver_z3::Z3Backend::native_ffi(arena as Arc<dyn angryier_expr::ExprReader>)
            .map_err(mlua::Error::external)?;
        let ranking = match self.policy_mode {
            SustainedPolicy::ForkAll => None,
            SustainedPolicy::RankTargets { exclude_avoid } => Some(crate::sustained::SustainedRanking {
                find: &self.find,
                avoid: &self.avoid,
                exclude_avoid,
            }),
        };
        let run = root
            .session
            .run_sustained_ranked(
                &mut self.campaign,
                &mut backend,
                std::time::Duration::from_millis(timeout),
                ranking,
            )
            .map_err(mlua::Error::external)?;
        self.last_steps = run.steps;
        self.last_reason = run.reason;
        let report = self.report(lua)?;
        let observations = run.evidence.report();
        let observed: std::collections::BTreeSet<u64> = observations
            .paths
            .iter()
            .filter(|path| {
                !matches!(
                    path.disposition,
                    angryier_provenance::sustained::PathDisposition::SolverInfeasible
                )
            })
            .flat_map(|path| path.blocks.iter().map(|block| block.pc))
            .collect();
        let targets = lua.create_table()?;
        for (name, addresses) in [("find", &self.find), ("avoid", &self.avoid)] {
            let list = lua.create_table()?;
            for (index, &pc) in addresses.iter().enumerate() {
                let item = lua.create_table()?;
                item.set("pc", pc)?;
                item.set("pc_hex", super::hex64(pc))?;
                item.set("observed", observed.contains(&pc))?;
                list.set(index + 1, item)?;
            }
            targets.set(name, list)?;
        }
        report.set("targets", targets)?;
        report.set("evidence", sustained_evidence_table(lua, observations)?)?;
        Ok(report)
    }
}

impl UserData for LuaSustained {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("report", |lua, this, ()| this.report(lua));
        methods.add_method_mut("advance", |lua, this, timeout_ms: Option<u64>| {
            this.advance(lua, timeout_ms)
        });
        methods.add_method_mut("retry_deferred", |lua, this, ()| {
            this.check_options()?;
            this.campaign.retry_deferred().map_err(mlua::Error::external)?;
            this.report(lua)
        });
    }
}
