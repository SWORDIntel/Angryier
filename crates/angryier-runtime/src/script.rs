//! Embedded Lua scripting surface (Phase 15) — drives a symbolic session
//! without recompiling. Scripts call `angry.run(path, opts)` which builds
//! the runtime internally and returns a report table:
//!
//! ```lua
//! local r = angry.run("/tmp/hello", {
//!     symbolic = { rdi = 64 },          -- register name -> bit width (64 only)
//!     find = { 0x40102a },
//!     avoid = { 0x40103b },
//!     steps = 512, states = 32,
//!     solve = true,                     -- solve found states
//! })
//! print(r.steps, r.forks, r.merges)
//! for i, input in ipairs(r.inputs) do print(input) end
//! ```

use angryier_expr::ExprArena;
use angryier_loader::ImageLoader;
use mlua::{Lua, Table, Value};

/// Default instruction-step budget for `angry.run` (`opts.steps`). Shared
/// with the `angryier run --steps` CLI default so the two cannot drift.
pub const DEFAULT_STEPS: u64 = 256;
/// Default maximum live states for `angry.run` (`opts.states`). Shared with
/// the states value the CLI's synthesized driver passes explicitly.
pub const DEFAULT_MAX_STATES: usize = 16;
/// Bit width of GPR symbolic marks. Intel 64 GPR storage is 64-bit and the
/// evaluator returns a register's stored expression regardless of the read
/// width, so sub-64-bit GPR symbols would surface as width-mismatched
/// expressions. Widths other than this are rejected with an explicit error
/// instead of being silently coerced or ignored.
pub const SYMBOLIC_GPR_WIDTH: u16 = 64;

/// Validates a symbolic-register width from the opts table / session
/// method. `None` (the `{ "rdi" }` list form or `s:symbolic("rdi")`)
/// defaults to [`SYMBOLIC_GPR_WIDTH`]; 64 is accepted; anything else is an
/// honest error naming the register and the offending width.
fn validate_symbolic_width(name: &str, width: Option<i64>) -> Result<u16, mlua::Error> {
    let requested = width.unwrap_or(i64::from(SYMBOLIC_GPR_WIDTH));
    if requested == i64::from(SYMBOLIC_GPR_WIDTH) {
        Ok(SYMBOLIC_GPR_WIDTH)
    } else {
        Err(mlua::Error::external(format!(
            "symbolic register '{name}' width must be {SYMBOLIC_GPR_WIDTH} bits (got {requested}); other GPR widths are not supported yet"
        )))
    }
}

/// Extracts `(register name, bit width)` from one `symbolic` opts-table
/// pair. Accepts both documented forms — `{ rdi = 64 }` (key form, width
/// value honored and validated) and `{ "rdi" }` (list form, default
/// width). Pairs with no string component are skipped (`Ok(None)`).
fn symbolic_mark_from_pair(k: &Value, v: &Value) -> Result<Option<(String, u16)>, mlua::Error> {
    let (name, width) = match (k, v) {
        (Value::String(s), Value::Integer(w)) => (s.to_str()?.to_string(), Some(*w)),
        (Value::String(s), _) => (s.to_str()?.to_string(), None),
        (_, Value::String(s)) => (s.to_str()?.to_string(), None),
        _ => return Ok(None),
    };
    let width = validate_symbolic_width(&name, width)?;
    Ok(Some((name, width)))
}

/// A live symbolic session exposed to Lua as a userdata handle. The
/// runtime and arena are `Box::leak`'d so the session's borrows are
/// 'static — acceptable for a CLI driver (one VM per process run).
#[cfg(feature = "xed")]
pub struct LuaSession {
    session: crate::SymbolicSession<'static, crate::XedFormTranslator<angryier_arch_xed_ffi::XedDecoder>>,
}

#[cfg(feature = "xed")]
impl mlua::UserData for LuaSession {
    fn add_methods<M: mlua::UserDataMethods<Self>>(methods: &mut M) {
        // s:step() → outcome string ("stepped"|"branched"|"terminated")
        methods.add_method_mut("step", |_, this, ()| match this.session.step_state(0) {
            Ok(crate::SymbolicStepOutcome::Stepped { .. }) => Ok("stepped"),
            Ok(crate::SymbolicStepOutcome::Branched { .. }) => Ok("branched"),
            Ok(crate::SymbolicStepOutcome::Terminated) => Ok("terminated"),
            Err(e) => Err(mlua::Error::external(format!("step: {e:?}"))),
        });
        // s:pc() → current pc of state 0
        methods.add_method("pc", |_, this, ()| {
            this.session.states[0]
                .process
                .pc()
                .map_err(|e| mlua::Error::external(format!("{e:?}")))
        });
        // s:reg("rdi") → concrete value (or nil when symbolic)
        methods.add_method("reg", |_, this, name: String| {
            let reg = reg_by_name(&name).ok_or_else(|| mlua::Error::external(format!("bad reg {name}")))?;
            match this.session.states[0].process.read_register(reg) {
                Ok(v) => Ok(mlua::Value::Integer(v as i64)),
                Err(_) => Ok(mlua::Value::Nil),
            }
        });
        methods.add_method("states", |_, this, ()| Ok(this.session.states.len()));
        // s:symbolic("rdi") or s:symbolic("rdi", 64) — mark a register
        // symbolic on state 0. The optional width is validated: only
        // 64-bit GPR symbols are supported (see SYMBOLIC_GPR_WIDTH).
        methods.add_method_mut("symbolic", |_, this, (name, width): (String, Option<i64>)| {
            let reg = reg_by_name(&name).ok_or_else(|| mlua::Error::external(format!("bad reg {name}")))?;
            let width = validate_symbolic_width(&name, width)?;
            this.session
                .mark_symbolic(0, reg, angryier_ir::IrType::Bits(width))
                .map_err(|e| mlua::Error::external(format!("{e:?}")))
        });
    }
}

/// The `angry` library installed into each script VM.
pub fn register(lua: &Lua) -> mlua::Result<()> {
    let lib = lua.create_table()?;
    lib.set(
        "run",
        lua.create_function(|lua, (path, opts): (String, Table)| run_driver(lua, &path, &opts))?,
    )?;
    #[cfg(feature = "xed")]
    lib.set("open", lua.create_function(|_, path: String| open_session(&path))?)?;
    lib.set("version", lua.create_function(|_, ()| Ok(env!("CARGO_PKG_VERSION")))?)?;
    lua.globals().set("angry", lib)?;
    Ok(())
}

/// Registers by name → symbolic input marks.
fn reg_by_name(name: &str) -> Option<u32> {
    let gprs = [
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    ];
    gprs.iter()
        .position(|n| *n == name)
        .map(|i| crate::register_id::GPR_BASE + i as u32)
}

fn run_driver(lua: &Lua, path: &str, opts: &Table) -> mlua::Result<Table> {
    let bytes = std::fs::read(path).map_err(|e| mlua::Error::external(format!("read {path}: {e}")))?;
    let mut runtime =
        crate::Runtime::with_native_xed(angryier_types::SemanticVersion(1), angryier_types::TargetProfileId(1));
    // Opt-in unsupported-form fallback: `unsupported = "fallthrough"` trades
    // exactness on unmodeled forms (privileged hints like CLI/STI, RDMSR,
    // HLT — dense in kernel images) for reachability, with every fallback
    // hit reported back in the result table as fidelity debt.
    let unsupported_fallback =
        if opts.get::<String>("unsupported").ok().as_deref() == Some("fallthrough") {
            let fallback =
                std::sync::Arc::new(angryier_semantics_intel64::UnsupportedFallthrough::new());
            runtime.registry.set_unsupported_fallback(std::sync::Arc::clone(
                &fallback,
            ) as std::sync::Arc<dyn angryier_semantics::SemanticProvider>);
            Some(fallback)
        } else {
            None
        };
    let use_dynamic = opts.get::<bool>("dynamic").unwrap_or(false);
    // Format dispatch: an MZ magic means PE32+, which loads in driver mode
    // (sections mapped, IAT resolved to import stubs, DriverEntry entry
    // state) — the driver-campaign path. `dynamic` is an ELF-only option.
    let is_pe = bytes.len() > 1 && bytes[0] == b'M' && bytes[1] == b'Z';
    // Driver-mode PE loads get the kernel pool model: allocators hand out
    // fresh pointers, frees are tracked with caller capture, and
    // double-free events surface in `r.kernel`.
    let kernel_pool = if is_pe {
        Some(std::sync::Arc::new(angryier_models::KernelPoolTracker::new()))
    } else {
        None
    };
    let mut process = if is_pe {
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
    if let (Some(tracker), runtime_any) = (&kernel_pool, &runtime) {
        // Bind INTERNAL pool routines before attach: a kernel image calls
        // its own ExAllocatePool*/ExFreePool* exports via direct calls, not
        // imports — resolve the export table and hand the addresses to the
        // tracker so attach installs per-address hooks. Export VAs are
        // preferred-base VAs; driver-mode PE loads map at the preferred
        // base (no relocations applied).
        if let Ok(image) = angryier_loader::Pe32Loader::new().load(&bytes) {
            for name in crate::KERNEL_POOL_ALLOC_NAMES {
                if let Some(va) = image.export_address(name) {
                    tracker.bind_internal_address(va, angryier_models::PoolRoutine::Alloc);
                }
            }
            for name in crate::KERNEL_POOL_FREE_NAMES {
                if let Some(va) = image.export_address(name) {
                    tracker.bind_internal_address(va, angryier_models::PoolRoutine::Free);
                }
            }
        }
        if let Err(e) = runtime_any.attach_kernel_pool_model(&mut process, tracker.clone()) {
            return Err(mlua::Error::external(format!("attach_kernel_pool_model: {e:?}")));
        }
    }

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
        let _ = process.state.memory.load_concrete(0, &vec![0u8; 0x1_0000]);
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
    if uc_memory_armed {
        process.state.memory = process.state.memory.with_uc_memory().with_uc_write_ro(uc_write_ro);
    }
    // Every clone/fork of the armed memory shares one debt ledger, so this
    // probe — cloned before the process moves into the session — reports the
    // whole run's debt even if every state dies.
    let uc_memory_probe = uc_memory_armed.then(|| process.state.memory.clone());

    // The Z3 backend needs a shared arena reader — keep the arena in Arc.
    let arena = std::sync::Arc::new(angryier_expr::ShardedExprArena::new(
        angryier_types::ExpressionNormalizationVersion(1),
    ));
    let mut session = crate::SymbolicSession::new(&runtime, arena.as_ref(), process);

    // Symbolic register marks: `symbolic = { rdi = 64 }` or `{ "rdi" }`.
    // The width value is validated — only 64-bit GPR symbols are
    // supported (see [`SYMBOLIC_GPR_WIDTH`]) — and unknown register names
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
    // dispatch-entry drivers get IRP-shaped pointer arguments.
    if let Ok(tbl) = opts.get::<Table>("regs") {
        for pair in tbl.pairs::<String, i64>() {
            let (name, value) = pair?;
            let reg = reg_by_name(&name).ok_or_else(|| mlua::Error::external(format!("bad reg {name}")))?;
            session.states[0]
                .process
                .write_register(reg, value as u64)
                .map_err(|e| mlua::Error::external(format!("regs[{name}]: {e:?}")))?;
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
            session.states[0].process.state.memory = session.states[0]
                .process
                .state
                .memory
                .load_concrete(addr, &value.to_le_bytes())
                .map_err(|e| mlua::Error::external(format!("poke: {e:?}")))?;
        }
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

    let find: Vec<u64> = opts
        .get::<Table>("find")
        .map(|t| t.sequence_values::<u64>().flatten().collect())
        .unwrap_or_default();
    let avoid: Vec<u64> = opts
        .get::<Table>("avoid")
        .map(|t| t.sequence_values::<u64>().flatten().collect())
        .unwrap_or_default();
    let steps = opts.get::<u64>("steps").unwrap_or(DEFAULT_STEPS);
    let max_states = opts.get::<usize>("states").unwrap_or(DEFAULT_MAX_STATES);

    let policy = crate::ExplorationPolicy {
        find,
        avoid,
        ..Default::default()
    };
    // The solver ALWAYS gates forks (`step_state_checked` prunes
    // concretely-infeasible directions as UNSAT). Without it the explorer
    // follows phantom paths — e.g. a NULL-check's impossible side — and
    // crashes deep in driver code that real execution could never reach.
    // `solve = true` only controls model extraction of found states.
    let mut backend = Some(
        angryier_solver_z3::Z3Backend::native_ffi(arena.clone() as std::sync::Arc<dyn angryier_expr::ExprReader>)
            .map_err(|e| mlua::Error::external(format!("z3: {e:?}")))?,
    );
    // Wall budget per run: `timeout_secs` (default 120) bounds the whole
    // exploration; the report's `timed_out` flag says when it fired.
    let timeout_secs = opts.get::<u64>("timeout_secs").unwrap_or(120);
    let report = session
        .run_with_policy(
            steps,
            max_states,
            backend.as_mut().map(|b| b as &mut dyn angryier_solver::SolverBackend),
            std::time::Duration::from_secs(timeout_secs),
            true,
            &policy,
        )
        .map_err(|e| mlua::Error::external(format!("run: {e:?}")))?;

    let out = lua.create_table()?;
    out.set("steps", report.steps)?;
    out.set("forks", report.forks)?;
    out.set("merges", report.merges)?;
    out.set("terminated", report.terminated)?;
    out.set("failed", report.failed)?;
    if let Some(error) = report.last_error.as_deref() {
        out.set("last_error", error)?;
    }
    out.set("live_states", report.live_states)?;
    out.set("found", report.found.len())?;
    out.set("timed_out", report.timed_out)?;
    out.set("entry_rsp", entry_rsp)?;
    // Solver-assisted address-concretization attempts (each attempt solves
    // one unresolved address, pins the model's value, and re-runs the
    // block) — visible budget diagnostics for under-constrained runs.
    out.set("concretization_retries", report.concretization_retries)?;
    // Executed-path trace: last PCs of the most relevant dead state (the
    // failed path), else the first live state. Diagnosis aid for model
    // iteration — every block address the state actually executed.
    {
        let candidate = session
            .dead
            .last()
            .or_else(|| session.states.first())
            .or_else(|| session.dead.first());
        if let Some(state) = candidate {
            let trace = lua.create_table()?;
            for (index, pc) in state.process.trace.iter().enumerate() {
                trace.set(index + 1, *pc)?;
            }
            out.set("trace", trace)?;
        }
    }

    // Kernel pool model report (driver-mode PE loads only): allocation /
    // free counters and the double-free event list.
    if let Some(tracker) = kernel_pool.as_ref() {
        let snap = tracker.snapshot();
        let kernel = lua.create_table()?;
        kernel.set("allocs", snap.allocs)?;
        kernel.set("frees", snap.frees)?;
        let dfs = lua.create_table()?;
        for (index, event) in snap.double_frees.iter().enumerate() {
            let entry = lua.create_table()?;
            entry.set("pointer", event.pointer)?;
            entry.set("caller", event.caller)?;
            dfs.set(index + 1, entry)?;
        }
        kernel.set("double_frees", dfs)?;
        out.set("kernel", kernel)?;
    }
    // Unsupported-form fallback debt: only present when the run armed the
    // fallback — `unsupported_total` counts fall-through steps and
    // `unsupported_sites` lists the first-seen (pc, form) pairs.
    if let Some(fallback) = &unsupported_fallback {
        let (total, sites) = fallback.snapshot();
        out.set("unsupported_total", total)?;
        let site_tbl = lua.create_table()?;
        for (index, (pc, form)) in sites.iter().enumerate() {
            let entry = lua.create_table()?;
            entry.set("pc", *pc)?;
            entry.set("form", *form)?;
            site_tbl.set(index + 1, entry)?;
        }
        out.set("unsupported_sites", site_tbl)?;
    }
    // Under-constrained memory debt: only present when the run armed
    // `uc_memory` — `unmapped_total` counts relaxed accesses (reads that
    // returned fabricated zeros, writes that fabricated a page, and — under
    // `uc_write_ro` — writes relaxed into read-only data pages, surfaced
    // with `op = "write_ro"`), `unmapped_sites` lists the first-seen
    // (op, address, page) sites, `ro_write_total` counts the read-only
    // relaxations in parallel, and `ro_write_reverts` lists the previous
    // bytes the relaxed writes overwrote (first-come, capped — the ledger
    // owns the cap).
    if let Some(probe) = &uc_memory_probe {
        out.set("unmapped_total", probe.uc_memory_total())?;
        let site_tbl = lua.create_table()?;
        for (index, site) in probe.uc_memory_sites().iter().enumerate() {
            let entry = lua.create_table()?;
            entry.set("op", site.op.as_str())?;
            entry.set("address", site.address)?;
            entry.set("page", site.page)?;
            site_tbl.set(index + 1, entry)?;
        }
        out.set("unmapped_sites", site_tbl)?;
        out.set("ro_write_total", probe.uc_memory_ro_write_total())?;
        let revert_tbl = lua.create_table()?;
        for (index, revert) in probe.uc_memory_ro_reverts().iter().enumerate() {
            let entry = lua.create_table()?;
            entry.set("address", revert.address)?;
            entry.set("previous", revert.previous)?;
            revert_tbl.set(index + 1, entry)?;
        }
        out.set("ro_write_reverts", revert_tbl)?;
    }
    // Vector debt: per-step evaluators are locals of the symbolic stepper,
    // so the session accumulates their ledger — `vector_debt_total` counts
    // vector primitives replaced with under-constrained symbols and
    // `vector_debt_sites` lists the first-seen (op, width, lane) sites.
    out.set("vector_debt_total", session.vector_debt_total())?;
    {
        let vector_tbl = lua.create_table()?;
        for (index, site) in session.vector_debt_sites().iter().enumerate() {
            let entry = lua.create_table()?;
            entry.set("op", format!("{:?}", site.op))?;
            entry.set("width", site.width_bits)?;
            entry.set("lane", site.lane_bits)?;
            vector_tbl.set(index + 1, entry)?;
        }
        out.set("vector_debt_sites", vector_tbl)?;
    }
    // `solve = true`: solve each found state; `inputs` is an array of
    // per-state tables mapping symbol index → byte-string.
    if let Some(backend) = backend.as_mut() {
        let inputs = lua.create_table()?;
        for found in report.found.iter() {
            session.states.push(found.clone());
            let idx = session.states.len() - 1;
            if let Ok(model) = session.solve_state_symbols(idx, backend, std::time::Duration::from_secs(10)) {
                let entry = lua.create_table()?;
                for (i, (_eid, bytes)) in model.iter().enumerate() {
                    entry.set(i + 1, lua.create_string(bytes)?)?;
                }
                inputs.set(inputs.len()? + 1, entry)?;
            }
            session.states.pop();
        }
        out.set("inputs", inputs)?;
    }
    // Register bindings of the first found state as `regs`.
    if let Some(found) = report.found.first() {
        let regs = lua.create_table()?;
        for (reg, (expr, _ty)) in &found.registers {
            if let Some(node) = arena.get(*expr)
                && node.op == angryier_expr::ExprOp::Constant
                && node.immediate.len() >= 8
            {
                regs.set(
                    *reg,
                    u64::from_le_bytes(node.immediate[..8].try_into().unwrap_or([0; 8])),
                )?;
            }
        }
        out.set("regs", regs)?;
    }
    Ok(out)
}

/// `angry.open(path)` → a live session handle with :step()/:pc()/:reg()/
/// :states()/:symbolic() — REPL-style control.
#[cfg(feature = "xed")]
fn open_session(path: &str) -> mlua::Result<LuaSession> {
    let bytes = std::fs::read(path).map_err(|e| mlua::Error::external(format!("read {path}: {e}")))?;
    let runtime: &'static crate::Runtime<crate::XedFormTranslator<angryier_arch_xed_ffi::XedDecoder>> =
        Box::leak(Box::new(crate::Runtime::with_native_xed(
            angryier_types::SemanticVersion(1),
            angryier_types::TargetProfileId(1),
        )));
    let arena: &'static angryier_expr::ShardedExprArena = Box::leak(Box::new(angryier_expr::ShardedExprArena::new(
        angryier_types::ExpressionNormalizationVersion(1),
    )));
    let is_pe = bytes.len() > 1 && bytes[0] == b'M' && bytes[1] == b'Z';
    let process = if is_pe {
        runtime
            .load_pe(&bytes)
            .map_err(|e| mlua::Error::external(format!("load_pe: {e:?}")))?
    } else {
        runtime
            .load_elf(&bytes)
            .map_err(|e| mlua::Error::external(format!("load_elf: {e:?}")))?
    };
    Ok(LuaSession {
        session: crate::SymbolicSession::new(runtime, arena, process),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mlua::Lua;

    /// The shared defaults must stay equal to the values documented in
    /// `docs/CLI.md` (and historically hardcoded in the CLI's synthesized
    /// driver — 1024 was the drift this pinned shut).
    #[test]
    fn shared_defaults_have_the_documented_values() {
        assert_eq!(DEFAULT_STEPS, 256);
        assert_eq!(DEFAULT_MAX_STATES, 16);
        assert_eq!(SYMBOLIC_GPR_WIDTH, 64);
    }

    #[test]
    fn width_implicit_or_explicit_64_is_accepted() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(validate_symbolic_width("rdi", None)?, 64);
        assert_eq!(validate_symbolic_width("rdi", Some(64))?, 64);
        Ok(())
    }

    #[test]
    fn width_other_than_64_is_an_honest_error() {
        for bad in [32, 16, 8, 128, 0, -1] {
            let msg = match validate_symbolic_width("rdi", Some(bad)) {
                Err(e) => e.to_string(),
                Ok(_) => String::new(),
            };
            assert!(!msg.is_empty(), "width {bad} must be rejected");
            assert!(msg.contains("'rdi'"), "message must name the register: {msg}");
            assert!(
                msg.contains("must be 64 bits"),
                "message must state the constraint: {msg}"
            );
            assert!(
                msg.contains(&format!("got {bad}")),
                "message must echo the width: {msg}"
            );
        }
    }

    #[test]
    fn symbolic_table_pairs_parse_both_documented_forms() -> Result<(), Box<dyn std::error::Error>> {
        let lua = Lua::new();
        // Key form with explicit 64 and list form with implicit width.
        let table = lua.load(r#"return { rdi = 64, "rsi" }"#).eval::<Table>()?;
        let mut marks = Vec::new();
        for pair in table.pairs::<Value, Value>() {
            let (k, v) = pair?;
            if let Some(mark) = symbolic_mark_from_pair(&k, &v)? {
                marks.push(mark);
            }
        }
        assert!(
            marks.contains(&("rdi".to_string(), SYMBOLIC_GPR_WIDTH)),
            "marks: {marks:?}"
        );
        assert!(
            marks.contains(&("rsi".to_string(), SYMBOLIC_GPR_WIDTH)),
            "marks: {marks:?}"
        );
        assert_eq!(marks.len(), 2);
        Ok(())
    }

    #[test]
    fn symbolic_table_pair_with_non_64_width_errors() -> Result<(), Box<dyn std::error::Error>> {
        let lua = Lua::new();
        let table = lua.load(r#"return { rdi = 32 }"#).eval::<Table>()?;
        for pair in table.pairs::<Value, Value>() {
            let (k, v) = pair?;
            let msg = match symbolic_mark_from_pair(&k, &v) {
                Err(e) => e.to_string(),
                Ok(_) => String::new(),
            };
            assert!(!msg.is_empty(), "width 32 must be rejected, not silently coerced");
            assert!(msg.contains("'rdi'") && msg.contains("got 32"), "{msg}");
        }
        Ok(())
    }

    #[test]
    fn symbolic_table_pairs_without_strings_are_skipped() -> Result<(), Box<dyn std::error::Error>> {
        let (k, v) = (Value::Integer(1), Value::Boolean(true));
        assert_eq!(symbolic_mark_from_pair(&k, &v)?, None);
        Ok(())
    }

    #[test]
    fn registers_resolve_by_gpr_name() {
        let base = angryier_arch_intel64::register_id::GPR_BASE;
        assert_eq!(reg_by_name("rdi"), Some(base + 7));
        assert_eq!(reg_by_name("r15"), Some(base + 15));
        assert_eq!(reg_by_name("xmm0"), None);
    }
}
