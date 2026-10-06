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
//!
//! # 64-bit values: the `_hex` convention
//!
//! Lua 5.4 integers are signed 64-bit. mlua pushes a Rust `u64` that
//! exceeds `i64::MAX` as a Lua *float* (double), so kernel pointers such
//! as `0xffff800000000000` arrive float-lossy — exact only up to 2^53 —
//! and `&` masks / `string.format("%x", ...)` both fail on them. Every
//! value the result table (and the `LuaState` accessors) exposes that can
//! carry a full machine address therefore ALSO appears as a `<name>_hex`
//! sibling: a Lua string, lowercase, `0x`-prefixed, zero-padded to 16 hex
//! digits, exact for all 64 bits ([`hex64`]). The plain numeric fields
//! stay for backward compatibility and are exact Lua integers up to
//! `i64::MAX`; above that they are delivered as doubles and must be
//! treated as lossy. Scripts formatting or comparing kernel addresses use
//! the `_hex` form. Documented for downstream hosts in `docs/DEPLOYMENT.md`.

use angryier_expr::ExprArena;
use angryier_loader::ImageLoader;
use mlua::{Lua, Table, Value};

/// Default instruction-step budget for `angry.run` (`opts.steps`). Shared
/// with the `angryier run --steps` CLI default so the two cannot drift.
pub const DEFAULT_STEPS: u64 = 256;
/// Default maximum live states for `angry.run` (`opts.states`). Shared with
/// the states value the CLI's synthesized driver passes explicitly.
pub const DEFAULT_MAX_STATES: usize = 16;
/// Default whole-run wall-clock budget for `angry.run`.
pub const DEFAULT_TIMEOUT_SECS: u64 = crate::DEFAULT_RUN_TIMEOUT_SECS;
/// Default post-run alternate-branch solver budget.
pub const DEFAULT_BRANCH_TIMEOUT_MS: u64 = 1000;

/// Machine-readable recommendation derived from branch solver evidence and
/// bounded CFG target directionality. The strings are intentionally stable:
/// external scripts/agents may consume them without reimplementing Angryier's
/// steering policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BranchSteeringVerdict {
    action: &'static str,
    confidence: &'static str,
    reason: &'static str,
}

fn branch_steering_verdict(
    solver_status: &str,
    chosen_is_find_target: bool,
    alternate_is_find_target: bool,
    cfg_preference: Option<&str>,
    replay_status: Option<&str>,
) -> BranchSteeringVerdict {
    if chosen_is_find_target {
        return BranchSteeringVerdict {
            action: "keep-chosen",
            confidence: "high",
            reason: "the chosen successor exactly matches a configured find target",
        };
    }

    match solver_status {
        "Unsat" => BranchSteeringVerdict {
            action: "reject-alternate",
            confidence: "high",
            reason: "the alternate edge is UNSAT under the exact shared pre-branch constraint prefix",
        },
        "Sat" if replay_status == Some("mismatch") => BranchSteeringVerdict {
            action: "unresolved",
            confidence: "low",
            reason: "the symbolic alternate model was SAT but concrete replay reached the branch and did not take the predicted successor",
        },
        "Sat" if alternate_is_find_target => BranchSteeringVerdict {
            action: "prioritize-alternate",
            confidence: "high",
            reason: "the alternate edge is SAT and its immediate successor exactly matches a configured find target",
        },
        "Sat" if cfg_preference == Some("alternate") => BranchSteeringVerdict {
            action: "prioritize-alternate",
            confidence: "medium",
            reason: if replay_status == Some("validated") {
                "the alternate edge is SAT, concrete replay validates the branch flip, and bounded CFG recovery ranks it closer to a configured find target"
            } else {
                "the alternate edge is SAT and bounded CFG recovery ranks it closer to a configured find target"
            },
        },
        "Sat" if cfg_preference == Some("chosen") => BranchSteeringVerdict {
            action: "keep-chosen",
            confidence: "medium",
            reason: "the alternate edge is SAT but bounded CFG recovery ranks the chosen edge closer to a configured find target",
        },
        "Sat" if cfg_preference == Some("equal") => BranchSteeringVerdict {
            action: "explore-both",
            confidence: "medium",
            reason: "both successors have equal bounded-CFG distance to the best configured find target",
        },
        "Sat" if replay_status == Some("validated") => BranchSteeringVerdict {
            action: "explore-alternate",
            confidence: "medium",
            reason: "the alternate edge is solver-feasible and concrete replay validates the predicted branch flip, but no target-direction evidence is available",
        },
        "Sat" => BranchSteeringVerdict {
            action: "explore-alternate",
            confidence: "low",
            reason: "the alternate edge is solver-feasible but no stronger target-direction evidence is available",
        },
        "Unknown" | "Timeout" | "ResourceLimit" => BranchSteeringVerdict {
            action: "unresolved",
            confidence: "low",
            reason: "alternate-edge satisfiability was not resolved within the solver budget",
        },
        "BackendError" | "Error" => BranchSteeringVerdict {
            action: "unresolved",
            confidence: "low",
            reason: "alternate-edge solving failed in the solver/backend path",
        },
        "Unavailable" => BranchSteeringVerdict {
            action: "unresolved",
            confidence: "low",
            reason: "alternate-edge solving is unavailable because the solver is disabled",
        },
        _ => BranchSteeringVerdict {
            action: "unresolved",
            confidence: "low",
            reason: "insufficient solver evidence is available to rank this branch",
        },
    }
}
/// Bit width of GPR symbolic marks. Intel 64 GPR storage is 64-bit and the
/// evaluator returns a register's stored expression regardless of the read
/// width, so sub-64-bit GPR symbols would surface as width-mismatched
/// expressions. Widths other than this are rejected with an explicit error
/// instead of being silently coerced or ignored.
pub const SYMBOLIC_GPR_WIDTH: u16 = 64;

/// Canonical exact form for a 64-bit machine value exposed to Lua:
/// lowercase, `0x`-prefixed, zero-padded to 16 hex digits. One value maps
/// to exactly one string, so `_hex` fields are directly comparable.
///
/// This is the integer-safe side of the module's `_hex` convention: Lua
/// 5.4 integers are signed 64-bit, and mlua pushes a `u64` above
/// `i64::MAX` as a double (float-lossy beyond 2^53), so kernel pointers
/// like `0xffff800000000000` cannot round-trip through the numeric field.
pub(crate) fn hex64(value: u64) -> String {
    format!("{value:#018x}")
}

/// Stores one machine-address pair on a Lua table: `key` keeps the raw
/// numeric `u64` (backward compatible; float-lossy above `i64::MAX`) and
/// `key_hex` carries the exact [`hex64`] form scripts must use for
/// formatting, masking, or comparing addresses that may exceed `i64::MAX`.
pub(crate) fn set_addr64(table: &Table, key: &str, value: u64) -> mlua::Result<()> {
    table.set(key, value)?;
    table.set(format!("{key}_hex"), hex64(value))
}

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

/// Parses one `regs` opts-table pair into a `(register id, value)` seed.
/// Two documented forms: the numeric form `rcx = 64` (Lua integer, exact
/// up to `i64::MAX`) and the `_hex` string form `rcx_hex = "0xffff8000…"`
/// — exact for all 64 bits, which is how kernel-pointer seeds travel
/// (pool addresses live above `i64::MAX`, where Lua integers wrap and
/// doubles go lossy). Returns `Ok(None)` for pairs with no string or
/// numeric payload (skipped, mirroring [`symbolic_mark_from_pair`]); a
/// malformed value or unknown register is an honest error naming both.
fn reg_seed_from_pair(k: &Value, v: &Value) -> Result<Option<(u32, u64)>, mlua::Error> {
    let name = match k {
        Value::String(s) => s.to_str()?.to_string(),
        _ => return Ok(None),
    };
    // `_hex` string form: `rcx_hex = "0xffff800000000000"`.
    if let Some(base) = name.strip_suffix("_hex") {
        let Value::String(s) = v else {
            return Err(mlua::Error::external(format!(
                "regs[{name}]: _hex form takes a 0x-prefixed hex string"
            )));
        };
        let text = s.to_str()?.to_string();
        let digits = text
            .strip_prefix("0x")
            .or_else(|| text.strip_prefix("0X"))
            .unwrap_or(text.as_str());
        let value = u64::from_str_radix(digits, 16)
            .map_err(|e| mlua::Error::external(format!("regs[{name}]: bad hex value {text:?}: {e}")))?;
        let reg = reg_by_name(base).ok_or_else(|| mlua::Error::external(format!("bad reg {base}")))?;
        return Ok(Some((reg, value)));
    }
    // Numeric form: Lua integers directly; exact whole-number floats are
    // accepted the way mlua's i64 conversion did (64.0 behaves as 64).
    let value = match v {
        Value::Integer(i) => *i as u64,
        Value::Number(f) if f.fract() == 0.0 && (i64::MIN as f64..=i64::MAX as f64).contains(f) => *f as i64 as u64,
        _ => {
            return Err(mlua::Error::external(format!(
                "regs[{name}]: integer or _hex string required — kernel pointers above i64::MAX must use the {name}_hex string form"
            )));
        }
    };
    let reg = reg_by_name(&name).ok_or_else(|| mlua::Error::external(format!("bad reg {name}")))?;
    Ok(Some((reg, value)))
}

/// Upper bound for `pool_prealloc`: pre-seeded tracked pool blocks per
/// run. The pool shadow region maps 1 MiB of 0x1000-strided blocks, and
/// probe drivers seed single-digit counts; the cap only stops a script
/// from exhausting the shadow with one call.
pub const POOL_PREALLOC_CAP: usize = 64;

#[cfg(feature = "xed")]
pub mod session;
#[cfg(feature = "xed")]
pub mod state;
pub mod utils;

#[cfg(feature = "xed")]
pub use session::{LuaSession, open_session};
#[cfg(feature = "xed")]
pub use state::LuaState;
pub use utils::{name_by_reg, reg_by_name};

/// The `angry` library installed into each script VM.
pub fn register(lua: &Lua) -> mlua::Result<()> {
    let lib = lua.create_table()?;
    utils::register_utils(lua, &lib)?;
    lib.set(
        "run",
        lua.create_function(|lua, (path, opts): (String, Table)| run_driver(lua, &path, &opts))?,
    )?;
    #[cfg(feature = "xed")]
    lib.set(
        "open",
        lua.create_function(|_, (path, opts): (String, Option<Table>)| open_session(&path, opts.as_ref()))?,
    )?;
    lib.set("version", lua.create_function(|_, ()| Ok(env!("CARGO_PKG_VERSION")))?)?;
    lua.globals().set("angry", lib)?;
    Ok(())
}

fn run_driver(lua: &Lua, path: &str, opts: &Table) -> mlua::Result<Table> {
    let bytes = std::fs::read(path).map_err(|e| mlua::Error::external(format!("read {path}: {e}")))?;
    let mut runtime =
        crate::Runtime::with_native_xed(angryier_types::SemanticVersion(1), angryier_types::TargetProfileId(1));
    // Opt-in unsupported-form fallback: `unsupported = "fallthrough"` trades
    // exactness on unmodeled forms (privileged hints like CLI/STI, RDMSR,
    // HLT — dense in kernel images) for reachability, with every fallback
    // hit reported back in the result table as fidelity debt.
    let unsupported_fallback = if opts.get::<String>("unsupported").ok().as_deref() == Some("fallthrough") {
        let fallback = std::sync::Arc::new(angryier_semantics_intel64::UnsupportedFallthrough::new());
        runtime.registry.set_unsupported_fallback(
            std::sync::Arc::clone(&fallback) as std::sync::Arc<dyn angryier_semantics::SemanticProvider>
        );
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
    // Exact addresses of `pool_prealloc` seeded blocks, hoisted so the
    // result-table emission below can surface them after the run.
    let mut pool_prealloc: Vec<u64> = Vec::new();
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
        // Pool pre-seeding (`pool_prealloc = n`): mint n tracked pool
        // blocks through the SAME fresh-pointer path the allocator
        // SimProcedure uses, BEFORE the run. A structured-entry probe can
        // then pin a symbolic pointer argument to one of these exact
        // addresses (`regs = { rcx_hex = ... }`), so the pool tracker sees
        // a tracked allocation instead of a uc-fabricated zero page and a
        // genuine double-free validates against a real block. Each seeded
        // block is recorded as an allocation (honest `allocs` count) and
        // the exact addresses surface in the result's `pool_prealloc`
        // table as `_hex`-convention strings (the pool base is above
        // i64::MAX — numeric forms would be float-lossy there).
        if let Ok(n) = opts.get::<usize>("pool_prealloc") {
            for _ in 0..n.min(POOL_PREALLOC_CAP) {
                let ptr = tracker.fresh_pointer();
                tracker.record_alloc();
                pool_prealloc.push(ptr);
            }
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
    // UC pin fallback rides the same opt as the memory policy: an address
    // the solver cannot concretize in budget pins to a fabricated page
    // instead of failing the state.
    if uc_memory_armed {
        session = session.with_uc_pin_fallback();
    }

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
    // Expensive post-run work stays explicit on the scripting surface.
    // The generated CLI driver opts into branch analysis by default, while
    // arbitrary Lua scripts keep their historical cost profile unless they
    // request it.
    let solve_models = opts.get::<bool>("solve").unwrap_or(false);
    let branch_analysis = opts.get::<bool>("branch_analysis").unwrap_or(false);
    let branch_timeout_ms = opts
        .get::<u64>("branch_timeout_ms")
        .unwrap_or(DEFAULT_BRANCH_TIMEOUT_MS)
        .clamp(1, 10_000);

    // exploration = "fork": branch folding trusts hard constants only, so
    // symbolic-condition branches fork both directions (solver-checked) —
    // path diversity over the concolic default's single determinized path.
    // search = "dfs": step the newest (deepest) state first — reach-a-site
    // dives instead of breadth-first.
    let fork_on_symbolic = opts.get::<String>("exploration").ok().as_deref() == Some("fork");
    let dfs = opts.get::<String>("search").ok().as_deref() == Some("dfs");
    let policy = crate::ExplorationPolicy {
        find,
        avoid,
        fork_on_symbolic,
        dfs,
        ..Default::default()
    };
    // The solver ALWAYS gates forks (`step_state_checked` prunes
    // concretely-infeasible directions as UNSAT). Without it the explorer
    // follows phantom paths — e.g. a NULL-check's impossible side — and
    // crashes deep in driver code that real execution could never reach.
    // `solve = true` only controls model extraction of found states.
    let mut backend = if opts.get::<String>("solver").ok().as_deref() == Some("off") {
        // Diagnostic escape hatch: exploration without feasibility gates —
        // forks are not pruned and addresses fall back to zero-page pins.
        None
    } else {
        Some(
            angryier_solver_z3::Z3Backend::native_ffi(arena.clone() as std::sync::Arc<dyn angryier_expr::ExprReader>)
                .map_err(|e| mlua::Error::external(format!("z3: {e:?}")))?,
        )
    };
    // Wall budget per run: `timeout_secs` (default 120) bounds the whole
    // exploration; the report's `timed_out` flag says when it fired.
    let timeout_secs = opts.get::<u64>("timeout_secs").unwrap_or(DEFAULT_TIMEOUT_SECS);
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
    out.set("pruned_states", report.pruned_states)?;
    out.set("failed", report.failed)?;
    if let Some(error) = report.last_error.as_deref() {
        out.set("last_error", error)?;
    }
    out.set("live_states", report.live_states)?;
    out.set("dead_states", report.dead_states)?;
    out.set("peak_states", report.peak_states)?;
    out.set("found", report.found.len())?;
    out.set("timed_out", report.timed_out)?;
    // Function-entry RSP: kernel stacks live above i64::MAX, so the numeric
    // form is float-lossy there — `entry_rsp_hex` is the exact value.
    set_addr64(&out, "entry_rsp", entry_rsp)?;
    // Solver-assisted address-concretization attempts (each attempt solves
    // one unresolved address, pins the model's value, and re-runs the
    // block) — visible budget diagnostics for under-constrained runs.
    out.set("concretization_retries", report.concretization_retries)?;
    out.set("region_fork_children", report.region_fork_children)?;
    // Every region-fork child is a guessed address world. Keep the capped
    // site ledger machine-readable so frontends can explain exactly where
    // fidelity was traded for continued exploration.
    {
        let sites = lua.create_table()?;
        for (index, site) in session.region_fork_sites().iter().enumerate() {
            let entry = lua.create_table()?;
            set_addr64(&entry, "pc", site.pc)?;
            entry.set("expr", site.expr.0)?;
            set_addr64(&entry, "pinned", site.pinned)?;
            set_addr64(&entry, "region_base", site.region_base)?;
            entry.set("region_size", site.region_size)?;
            sites.set(index + 1, entry)?;
        }
        out.set("region_fork_sites", sites)?;
    }
    // Diagnostic frontier: prefer a found state (best evidence), then a
    // still-live state (next work frontier), then the most recent dead state.
    // This same state feeds the trace and dependency view so frontends do not
    // accidentally combine evidence from unrelated paths.
    {
        let candidate = report
            .found
            .first()
            .or_else(|| session.states.first())
            .or_else(|| session.dead.last())
            .or_else(|| session.dead.first());
        if let Some(state) = candidate {
            let trace = lua.create_table()?;
            // Parallel `trace_hex`: block PCs are normally image VAs, but an
            // entry override (or a hook at a kernel address) can push them
            // past i64::MAX, where the numeric array turns into floats.
            let trace_hex = lua.create_table()?;
            for (index, pc) in state.process.trace.iter().enumerate() {
                trace.set(index + 1, *pc)?;
                trace_hex.set(index + 1, hex64(*pc))?;
            }
            out.set("trace", trace)?;
            out.set("trace_hex", trace_hex)?;

            let frontier = lua.create_table()?;
            frontier.set("state_id", state.id)?;
            if let Ok(pc) = state.process.pc() {
                set_addr64(&frontier, "pc", pc)?;
            }
            frontier.set("constraints", state.constraints.len())?;
            frontier.set("bound_symbols", state.symbols.len())?;
            frontier.set("symbolic_registers", state.registers.len())?;

            let regs = lua.create_table()?;
            for (index, (reg, (expr, _ty))) in state.registers.iter().enumerate() {
                let entry = lua.create_table()?;
                entry.set("register", *reg)?;
                if let Some(name) = name_by_reg(*reg) {
                    entry.set("name", name)?;
                }
                entry.set("expression", expr.0)?;
                regs.set(index + 1, entry)?;
            }
            frontier.set("registers", regs)?;

            // Union the symbolic leaf ids that actually occur in this
            // state's accumulated path constraints. Unlike the broader
            // `state.symbols` list, this is path-relevance evidence: a source
            // absent here has not contributed to any retained path predicate.
            let mut dependency_sources = Vec::<u64>::new();
            for constraint in &state.constraints {
                if let Some(summary) = arena.dependency_summary(*constraint) {
                    dependency_sources.extend(summary.symbolic_sources);
                }
            }
            dependency_sources.sort_unstable();
            dependency_sources.dedup();

            let deps = lua.create_table()?;
            for (index, source_id) in dependency_sources.iter().enumerate() {
                let entry = lua.create_table()?;
                entry.set("source_id", *source_id)?;
                let binding = state.symbols.iter().find(|binding| {
                    arena
                        .get(binding.expression)
                        .filter(|node| node.op == angryier_expr::ExprOp::Symbol)
                        .and_then(|node| node.immediate.get(..8).map(|bytes| bytes.to_vec()))
                        .and_then(|bytes| <[u8; 8]>::try_from(bytes.as_slice()).ok())
                        .map(u64::from_le_bytes)
                        == Some(*source_id)
                });
                if let Some(binding) = binding {
                    entry.set("source_kind", "register")?;
                    entry.set("register", binding.register)?;
                    if let Some(name) = name_by_reg(binding.register) {
                        entry.set("name", name)?;
                    }
                    entry.set("width", binding.width)?;
                    entry.set("expression", binding.expression.0)?;
                } else {
                    entry.set("source_kind", "unbound-symbol")?;
                }
                deps.set(index + 1, entry)?;
            }
            frontier.set("constraint_dependencies", deps)?;
            out.set("frontier", frontier)?;

            if branch_analysis {
                let branch_out = lua.create_table()?;

                // Recover one bounded CFG rooted at the earliest retained
                // branch. Reuse it for the entire history + latest-branch
                // analysis so multi-candidate ranking does not multiply CFG
                // recovery cost.
                let analysis_cfg = if policy.find.is_empty() {
                    None
                } else {
                    state
                        .branch_history
                        .first()
                        .map(|decision| runtime.recover_cfg_window(&state.process, decision.pc, 16 * 1024 * 1024))
                        .or_else(|| {
                            state
                                .last_branch
                                .map(|decision| runtime.recover_cfg_window(&state.process, decision.pc, 16 * 1024 * 1024))
                        })
                };
                // (history index, decision, target, alternate distance,
                // chosen distance, class, improvement). Class 2 means the
                // alternate reaches the target while the chosen edge does
                // not; class 1 means both reach it but alternate is shorter.
                let mut history_candidate: Option<(
                    usize,
                    crate::SymbolicBranchDecision,
                    u64,
                    usize,
                    Option<usize>,
                    u8,
                    usize,
                )> = None;

                // Bounded branch provenance for multi-candidate follow-up.
                // Entries preserve execution order; the last entry is the
                // decision analyzed in detail below unless a merge cleared
                // provenance. Exact alternate->find edges are highlighted so
                // frontends can surface older high-value flip points.
                branch_out.set("history_count", state.branch_history.len())?;
                let history = lua.create_table()?;
                let mut latest_exact_find: Option<(usize, crate::SymbolicBranchDecision, u64)> = None;
                for (index, recorded) in state.branch_history.iter().copied().enumerate() {
                    let entry = lua.create_table()?;
                    entry.set("index", index + 1)?;
                    set_addr64(&entry, "pc", recorded.pc)?;
                    entry.set("condition", recorded.condition.0)?;
                    entry.set("prefix_constraints", recorded.prefix_constraints)?;
                    entry.set("chosen", if recorded.chose_taken { "taken" } else { "not_taken" })?;
                    let chosen = if recorded.chose_taken {
                        recorded.taken
                    } else {
                        recorded.not_taken
                    };
                    let alternate = if recorded.chose_taken {
                        recorded.not_taken
                    } else {
                        recorded.taken
                    };
                    set_addr64(&entry, "chosen_target", chosen)?;
                    set_addr64(&entry, "alternate_target", alternate)?;
                    let chosen_find = policy.find.contains(&chosen);
                    let alternate_find = policy.find.contains(&alternate);
                    entry.set("chosen_is_find_target", chosen_find)?;
                    entry.set("alternate_is_find_target", alternate_find)?;
                    if let Some(summary) = arena.dependency_summary(recorded.condition) {
                        entry.set("dependency_sources", summary.symbolic_sources.len())?;
                    }

                    if let Some(Ok(cfg)) = analysis_cfg.as_ref() {
                        let mut best_for_decision: Option<(u64, usize, Option<usize>, u8, usize)> = None;
                        for target in policy.find.iter().copied() {
                            let chosen_distance = cfg.shortest_static_distance(chosen, target, 128);
                            let alternate_distance = cfg.shortest_static_distance(alternate, target, 128);
                            let Some(alternate_distance) = alternate_distance else {
                                continue;
                            };
                            let (class, improvement) = match chosen_distance {
                                None => (2u8, usize::MAX),
                                Some(chosen_distance) if alternate_distance < chosen_distance => {
                                    (1u8, chosen_distance - alternate_distance)
                                }
                                _ => continue,
                            };
                            let replace = best_for_decision.as_ref().is_none_or(
                                |(_, best_alt, _, best_class, best_improvement)| {
                                    class > *best_class
                                        || (class == *best_class
                                            && (improvement > *best_improvement
                                                || (improvement == *best_improvement
                                                    && alternate_distance < *best_alt)))
                                },
                            );
                            if replace {
                                best_for_decision =
                                    Some((target, alternate_distance, chosen_distance, class, improvement));
                            }
                        }
                        if let Some((target, alt_distance, chosen_distance, class, improvement)) = best_for_decision {
                            entry.set("cfg_preference", "alternate")?;
                            set_addr64(&entry, "cfg_find_target", target)?;
                            entry.set("cfg_alternate_distance", alt_distance)?;
                            if let Some(chosen_distance) = chosen_distance {
                                entry.set("cfg_chosen_distance", chosen_distance)?;
                            }

                            // Do not auto-select the newest branch here: it
                            // already receives the full detailed analysis
                            // below. This candidate is specifically the best
                            // OLDER mutation point.
                            if index + 1 < state.branch_history.len() {
                                let replace = history_candidate.as_ref().is_none_or(
                                    |(_, _, _, best_alt, _, best_class, best_improvement)| {
                                        class > *best_class
                                            || (class == *best_class
                                                && (improvement > *best_improvement
                                                    || (improvement == *best_improvement
                                                        && alt_distance < *best_alt)))
                                    },
                                );
                                if replace {
                                    history_candidate = Some((
                                        index + 1,
                                        recorded,
                                        target,
                                        alt_distance,
                                        chosen_distance,
                                        class,
                                        improvement,
                                    ));
                                }
                            }
                        }
                    }

                    if alternate_find {
                        latest_exact_find = Some((index + 1, recorded, alternate));
                    }
                    history.set(index + 1, entry)?;
                }
                branch_out.set("history", history)?;
                if let Some((index, recorded, target)) = latest_exact_find {
                    branch_out.set("history_exact_find_index", index)?;
                    set_addr64(&branch_out, "history_exact_find_pc", recorded.pc)?;
                    set_addr64(&branch_out, "history_exact_find_target", target)?;
                }
                if let Some((index, recorded, target, alt_distance, chosen_distance, class, improvement)) =
                    history_candidate
                {
                    branch_out.set("history_candidate_index", index)?;
                    set_addr64(&branch_out, "history_candidate_pc", recorded.pc)?;
                    set_addr64(&branch_out, "history_candidate_find_target", target)?;
                    branch_out.set("history_candidate_alternate_distance", alt_distance)?;
                    if let Some(chosen_distance) = chosen_distance {
                        branch_out.set("history_candidate_chosen_distance", chosen_distance)?;
                    }
                    branch_out.set(
                        "history_candidate_reason",
                        if class == 2 {
                            "alternate reaches target in bounded CFG while chosen edge does not"
                        } else {
                            "alternate is shorter than chosen edge in bounded CFG"
                        },
                    )?;
                    if improvement != usize::MAX {
                        branch_out.set("history_candidate_improvement", improvement)?;
                    }
                }

                if let Some(decision) = state.last_branch {
                    branch_out.set("status", "recorded")?;
                    set_addr64(&branch_out, "pc", decision.pc)?;
                    set_addr64(&branch_out, "taken_target", decision.taken)?;
                    set_addr64(&branch_out, "not_taken_target", decision.not_taken)?;
                    branch_out.set("chosen", if decision.chose_taken { "taken" } else { "not_taken" })?;
                    branch_out.set("condition", decision.condition.0)?;
                    branch_out.set("prefix_constraints", decision.prefix_constraints)?;
                    let chosen_target = if decision.chose_taken {
                        decision.taken
                    } else {
                        decision.not_taken
                    };
                    let alternate_target = if decision.chose_taken {
                        decision.not_taken
                    } else {
                        decision.taken
                    };
                    set_addr64(&branch_out, "chosen_target", chosen_target)?;
                    set_addr64(&branch_out, "alternate_target", alternate_target)?;
                    branch_out.set("chosen_is_find_target", policy.find.contains(&chosen_target))?;
                    branch_out.set("alternate_is_find_target", policy.find.contains(&alternate_target))?;

                    // Static target directionality: recover only a bounded
                    // executable window rooted at this branch and compare
                    // graph-edge distances from each successor to configured
                    // find targets. This is structural guidance, never raw
                    // numeric address proximity.
                    if policy.find.is_empty() {
                        branch_out.set("cfg_status", "no-find-targets")?;
                    } else {
                        match analysis_cfg.as_ref() {
                            Some(Ok(cfg)) => {
                                branch_out.set("cfg_status", "ok")?;
                                let target_tbl = lua.create_table()?;
                                let mut best_alternate: Option<(u64, usize, Option<usize>)> = None;
                                let mut best_chosen: Option<(u64, usize, Option<usize>)> = None;
                                for (index, target) in policy.find.iter().copied().enumerate() {
                                    let taken_distance = cfg.shortest_static_distance(decision.taken, target, 128);
                                    let not_taken_distance =
                                        cfg.shortest_static_distance(decision.not_taken, target, 128);
                                    let chosen_distance = if decision.chose_taken {
                                        taken_distance
                                    } else {
                                        not_taken_distance
                                    };
                                    let alternate_distance = if decision.chose_taken {
                                        not_taken_distance
                                    } else {
                                        taken_distance
                                    };

                                    let entry = lua.create_table()?;
                                    set_addr64(&entry, "target", target)?;
                                    if let Some(distance) = taken_distance {
                                        entry.set("taken_distance", distance)?;
                                    }
                                    if let Some(distance) = not_taken_distance {
                                        entry.set("not_taken_distance", distance)?;
                                    }
                                    if let Some(distance) = chosen_distance {
                                        entry.set("chosen_distance", distance)?;
                                    }
                                    if let Some(distance) = alternate_distance {
                                        entry.set("alternate_distance", distance)?;
                                    }
                                    let preference = match (chosen_distance, alternate_distance) {
                                        (None, Some(_)) => "alternate",
                                        (Some(chosen), Some(alternate)) if alternate < chosen => "alternate",
                                        (Some(_), None) => "chosen",
                                        (Some(chosen), Some(alternate)) if chosen < alternate => "chosen",
                                        (Some(_), Some(_)) => "equal",
                                        (None, None) => "unreachable-in-window",
                                    };
                                    entry.set("preference", preference)?;
                                    target_tbl.set(index + 1, entry)?;

                                    if preference == "alternate"
                                        && let Some(alternate) = alternate_distance
                                        && best_alternate.as_ref().is_none_or(|(_, best, _)| alternate < *best)
                                    {
                                        best_alternate = Some((target, alternate, chosen_distance));
                                    } else if preference == "chosen"
                                        && let Some(chosen) = chosen_distance
                                        && best_chosen.as_ref().is_none_or(|(_, best, _)| chosen < *best)
                                    {
                                        best_chosen = Some((target, chosen, alternate_distance));
                                    }
                                }
                                branch_out.set("cfg_targets", target_tbl)?;
                                if let Some((target, alternate, chosen)) = best_alternate {
                                    branch_out.set("cfg_preference", "alternate")?;
                                    set_addr64(&branch_out, "cfg_find_target", target)?;
                                    branch_out.set("cfg_alternate_distance", alternate)?;
                                    if let Some(chosen) = chosen {
                                        branch_out.set("cfg_chosen_distance", chosen)?;
                                    }
                                } else if let Some((target, chosen, alternate)) = best_chosen {
                                    branch_out.set("cfg_preference", "chosen")?;
                                    set_addr64(&branch_out, "cfg_find_target", target)?;
                                    branch_out.set("cfg_chosen_distance", chosen)?;
                                    if let Some(alternate) = alternate {
                                        branch_out.set("cfg_alternate_distance", alternate)?;
                                    }
                                } else {
                                    branch_out.set("cfg_preference", "none")?;
                                }
                            }
                            Some(Err(error)) => {
                                branch_out.set("cfg_status", "unavailable")?;
                                branch_out.set("cfg_error", error.to_string())?;
                            }
                            None => {
                                branch_out.set("cfg_status", "unavailable")?;
                                branch_out.set("cfg_error", "no retained branch root was available for CFG recovery")?;
                            }
                        }
                    }

                    let dep_tbl = lua.create_table()?;
                    if let Some(summary) = arena.dependency_summary(decision.condition) {
                        for (index, source_id) in summary.symbolic_sources.iter().enumerate() {
                            let entry = lua.create_table()?;
                            entry.set("source_id", *source_id)?;
                            let binding = state.symbols.iter().find(|binding| {
                                arena
                                    .get(binding.expression)
                                    .filter(|node| node.op == angryier_expr::ExprOp::Symbol)
                                    .and_then(|node| node.immediate.get(..8).map(|bytes| bytes.to_vec()))
                                    .and_then(|bytes| <[u8; 8]>::try_from(bytes.as_slice()).ok())
                                    .map(u64::from_le_bytes)
                                    == Some(*source_id)
                            });
                            if let Some(binding) = binding {
                                entry.set("width", binding.width)?;
                                entry.set("expression", binding.expression.0)?;
                                if binding.width == 64 {
                                    entry.set("source_kind", "register")?;
                                    entry.set("register", binding.register)?;
                                    if let Some(name) = name_by_reg(binding.register) {
                                        entry.set("name", name)?;
                                    }
                                } else {
                                    entry.set("source_kind", "byte-symbol")?;
                                }
                            } else {
                                entry.set("source_kind", "unbound-symbol")?;
                            }
                            dep_tbl.set(index + 1, entry)?;
                        }
                    }
                    branch_out.set("dependencies", dep_tbl)?;

                    if let Some(backend) = backend.as_mut() {
                        match session.solve_alternate_branch(
                            state,
                            backend,
                            std::time::Duration::from_millis(branch_timeout_ms),
                        ) {
                            Ok(solution) => {
                                branch_out.set("solver_status", format!("{:?}", solution.outcome))?;
                                debug_assert_eq!(solution.alternate_target, alternate_target);
                                branch_out.set("solver_elapsed_us", solution.solver_elapsed.as_micros() as u64)?;
                                let model = lua.create_table()?;
                                for (index, (expression, bytes)) in solution.model.iter().enumerate() {
                                    let entry = lua.create_table()?;
                                    entry.set("expression", *expression)?;
                                    entry.set("bytes", lua.create_string(bytes)?)?;
                                    let hex = bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
                                    entry.set("hex", hex)?;
                                    if let Some(binding) = state
                                        .symbols
                                        .iter()
                                        .find(|binding| u64::from(binding.expression.0) == *expression)
                                    {
                                        entry.set("width", binding.width)?;
                                        if binding.width == 64 {
                                            entry.set("source_kind", "register")?;
                                            entry.set("register", binding.register)?;
                                            if let Some(name) = name_by_reg(binding.register) {
                                                entry.set("name", name)?;
                                            }
                                            let mut value_bytes = [0u8; 8];
                                            let len = bytes.len().min(8);
                                            value_bytes[..len].copy_from_slice(&bytes[..len]);
                                            let value = u64::from_le_bytes(value_bytes);
                                            set_addr64(&entry, "value", value)?;
                                        } else {
                                            entry.set("source_kind", "byte-symbol")?;
                                        }
                                    } else {
                                        entry.set("source_kind", "unbound-symbol")?;
                                    }
                                    model.set(index + 1, entry)?;
                                }
                                branch_out.set("model", model)?;

                                let replay_out = lua.create_table()?;
                                match session.replay_alternate_branch_model(state, &solution, steps) {
                                    Ok(replay) => {
                                        replay_out.set("status", replay.status)?;
                                        replay_out.set("steps", replay.steps)?;
                                        replay_out.set("reached_branch", replay.reached_branch)?;
                                        replay_out.set("matched_alternate", replay.matched_alternate)?;
                                        replay_out.set("applied_registers", replay.applied_registers)?;
                                        replay_out.set("detail", replay.detail)?;
                                        if let Some(observed) = replay.observed_target {
                                            set_addr64(&replay_out, "observed_target", observed)?;
                                        }
                                    }
                                    Err(error) => {
                                        replay_out.set("status", "error")?;
                                        replay_out.set("detail", error.to_string())?;
                                    }
                                }
                                branch_out.set("replay", replay_out)?;
                            }
                            Err(error) => {
                                branch_out.set("solver_status", "Error")?;
                                branch_out.set("error", error.to_string())?;
                            }
                        }
                    } else {
                        branch_out.set("solver_status", "Unavailable")?;
                        branch_out.set("error", "solver=off; alternate-edge satisfiability was not checked")?;
                    }

                    let solver_status = branch_out
                        .get::<String>("solver_status")
                        .unwrap_or_else(|_| "Unavailable".to_string());
                    let cfg_preference = branch_out.get::<String>("cfg_preference").ok();
                    let replay_status = branch_out
                        .get::<Table>("replay")
                        .ok()
                        .and_then(|table| table.get::<String>("status").ok());
                    let verdict = branch_steering_verdict(
                        &solver_status,
                        policy.find.contains(&chosen_target),
                        policy.find.contains(&alternate_target),
                        cfg_preference.as_deref(),
                        replay_status.as_deref(),
                    );
                    branch_out.set("steering_action", verdict.action)?;
                    branch_out.set("steering_confidence", verdict.confidence)?;
                    branch_out.set("steering_reason", verdict.reason)?;

                    // At most one older branch receives a solver query. The
                    // candidate has already been ranked by the shared bounded
                    // CFG as a strictly better alternate route to --find.
                    if let Some((
                        candidate_index,
                        candidate_decision,
                        candidate_target,
                        candidate_alt_distance,
                        candidate_chosen_distance,
                        _,
                        _,
                    )) = history_candidate
                    {
                        let candidate_out = lua.create_table()?;
                        candidate_out.set("index", candidate_index)?;
                        set_addr64(&candidate_out, "pc", candidate_decision.pc)?;
                        set_addr64(&candidate_out, "find_target", candidate_target)?;
                        candidate_out.set("cfg_preference", "alternate")?;
                        candidate_out.set("cfg_alternate_distance", candidate_alt_distance)?;
                        if let Some(chosen_distance) = candidate_chosen_distance {
                            candidate_out.set("cfg_chosen_distance", chosen_distance)?;
                        }
                        let candidate_chosen_target = if candidate_decision.chose_taken {
                            candidate_decision.taken
                        } else {
                            candidate_decision.not_taken
                        };
                        let candidate_alternate_target = if candidate_decision.chose_taken {
                            candidate_decision.not_taken
                        } else {
                            candidate_decision.taken
                        };
                        set_addr64(&candidate_out, "chosen_target", candidate_chosen_target)?;
                        set_addr64(&candidate_out, "alternate_target", candidate_alternate_target)?;
                        candidate_out.set("prefix_constraints", candidate_decision.prefix_constraints)?;

                        if let Some(backend) = backend.as_mut() {
                            match session.solve_alternate_branch_decision(
                                state,
                                candidate_decision,
                                backend,
                                std::time::Duration::from_millis(branch_timeout_ms),
                            ) {
                                Ok(solution) => {
                                    let solver_status = format!("{:?}", solution.outcome);
                                    candidate_out.set("solver_status", solver_status.as_str())?;
                                    candidate_out
                                        .set("solver_elapsed_us", solution.solver_elapsed.as_micros() as u64)?;

                                    let model = lua.create_table()?;
                                    for (index, (expression, bytes)) in solution.model.iter().enumerate() {
                                        let entry = lua.create_table()?;
                                        entry.set("expression", *expression)?;
                                        entry.set("bytes", lua.create_string(bytes)?)?;
                                        entry.set(
                                            "hex",
                                            bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
                                        )?;
                                        if let Some(binding) = state
                                            .symbols
                                            .iter()
                                            .find(|binding| u64::from(binding.expression.0) == *expression)
                                        {
                                            entry.set("width", binding.width)?;
                                            if binding.width == 64 {
                                                entry.set("source_kind", "register")?;
                                                entry.set("register", binding.register)?;
                                                if let Some(name) = name_by_reg(binding.register) {
                                                    entry.set("name", name)?;
                                                }
                                                let mut value_bytes = [0u8; 8];
                                                let len = bytes.len().min(8);
                                                value_bytes[..len].copy_from_slice(&bytes[..len]);
                                                set_addr64(&entry, "value", u64::from_le_bytes(value_bytes))?;
                                            } else {
                                                entry.set("source_kind", "byte-symbol")?;
                                            }
                                        } else {
                                            entry.set("source_kind", "unbound-symbol")?;
                                        }
                                        model.set(index + 1, entry)?;
                                    }
                                    candidate_out.set("model", model)?;

                                    let replay_out = lua.create_table()?;
                                    let replay_status = match session.replay_alternate_branch_model(state, &solution, steps)
                                    {
                                        Ok(replay) => {
                                            replay_out.set("status", replay.status)?;
                                            replay_out.set("steps", replay.steps)?;
                                            replay_out.set("reached_branch", replay.reached_branch)?;
                                            replay_out.set("matched_alternate", replay.matched_alternate)?;
                                            replay_out.set("applied_registers", replay.applied_registers)?;
                                            replay_out.set("detail", replay.detail)?;
                                            if let Some(observed) = replay.observed_target {
                                                set_addr64(&replay_out, "observed_target", observed)?;
                                            }
                                            Some(replay.status)
                                        }
                                        Err(error) => {
                                            replay_out.set("status", "error")?;
                                            replay_out.set("detail", error.to_string())?;
                                            Some("error")
                                        }
                                    };
                                    candidate_out.set("replay", replay_out)?;

                                    let candidate_verdict = branch_steering_verdict(
                                        &solver_status,
                                        policy.find.contains(&candidate_chosen_target),
                                        policy.find.contains(&candidate_alternate_target),
                                        Some("alternate"),
                                        replay_status,
                                    );
                                    candidate_out.set("steering_action", candidate_verdict.action)?;
                                    candidate_out.set("steering_confidence", candidate_verdict.confidence)?;
                                    candidate_out.set("steering_reason", candidate_verdict.reason)?;
                                }
                                Err(error) => {
                                    candidate_out.set("solver_status", "Error")?;
                                    candidate_out.set("error", error.to_string())?;
                                    candidate_out.set("steering_action", "unresolved")?;
                                    candidate_out.set("steering_confidence", "low")?;
                                    candidate_out.set(
                                        "steering_reason",
                                        "older candidate alternate-edge solving failed",
                                    )?;
                                }
                            }
                        } else {
                            candidate_out.set("solver_status", "Unavailable")?;
                            candidate_out.set("steering_action", "unresolved")?;
                            candidate_out.set("steering_confidence", "low")?;
                            candidate_out.set(
                                "steering_reason",
                                "solver is disabled; CFG ranking is structural evidence only",
                            )?;
                        }
                        branch_out.set("history_candidate_analysis", candidate_out)?;
                    }
                } else {
                    branch_out.set("status", "no-symbolic-branch")?;
                    branch_out.set(
                        "error",
                        "the selected diagnostic frontier has no recorded symbolic branch decision",
                    )?;
                }
                out.set("branch_analysis", branch_out)?;
            }
        }
    }

    // Kernel pool model report (driver-mode PE loads only): allocation /
    // free counters and the double-free event list. Pool pointers are
    // kernel addresses (`0xffff8000...` base) — always above i64::MAX — so
    // each event carries exact `pointer_hex` / `caller_hex` strings; the
    // numeric `pointer` / `caller` fields are float-lossy doubles there.
    if let Some(tracker) = kernel_pool.as_ref() {
        let snap = tracker.snapshot();
        let kernel = lua.create_table()?;
        kernel.set("allocs", snap.allocs)?;
        kernel.set("frees", snap.frees)?;
        let dfs = lua.create_table()?;
        for (index, event) in snap.double_frees.iter().enumerate() {
            let entry = lua.create_table()?;
            set_addr64(&entry, "pointer", event.pointer)?;
            set_addr64(&entry, "caller", event.caller)?;
            dfs.set(index + 1, entry)?;
        }
        kernel.set("double_frees", dfs)?;
        out.set("kernel", kernel)?;
    }
    // Pool pre-seed addresses (`pool_prealloc = n`): exact `_hex` strings,
    // one per pre-minted tracked block, in mint order — the addresses a
    // structured-entry probe pins a symbolic pointer argument to.
    if !pool_prealloc.is_empty() {
        let tbl = lua.create_table()?;
        for (index, ptr) in pool_prealloc.iter().enumerate() {
            tbl.set(index + 1, hex64(*ptr))?;
        }
        out.set("pool_prealloc", tbl)?;
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
            set_addr64(&entry, "pc", *pc)?;
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
            set_addr64(&entry, "address", site.address)?;
            set_addr64(&entry, "page", site.page)?;
            site_tbl.set(index + 1, entry)?;
        }
        out.set("unmapped_sites", site_tbl)?;
        out.set("ro_write_total", probe.uc_memory_ro_write_total())?;
        let revert_tbl = lua.create_table()?;
        for (index, revert) in probe.uc_memory_ro_reverts().iter().enumerate() {
            let entry = lua.create_table()?;
            set_addr64(&entry, "address", revert.address)?;
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
    // per-state tables mapping symbol index → byte-string. Feasibility
    // checking during exploration still uses the backend regardless of this
    // flag; model extraction is the expensive optional post-run operation.
    if solve_models && let Some(backend) = backend.as_mut() {
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
    // Register bindings of the first found state as `regs` (keyed by
    // register id), with the exact `regs_hex` sibling — a found state can
    // hold a kernel pointer above i64::MAX in driver mode.
    if let Some(found) = report.found.first() {
        let regs = lua.create_table()?;
        let regs_hex = lua.create_table()?;
        for (reg, (expr, _ty)) in &found.registers {
            if let Some(node) = arena.get(*expr)
                && node.op == angryier_expr::ExprOp::Constant
                && node.immediate.len() >= 8
            {
                let value = u64::from_le_bytes(node.immediate[..8].try_into().unwrap_or([0; 8]));
                regs.set(*reg, value)?;
                regs_hex.set(*reg, hex64(value))?;
            }
        }
        out.set("regs", regs)?;
        out.set("regs_hex", regs_hex)?;
    }
    Ok(out)
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
        assert_eq!(DEFAULT_TIMEOUT_SECS, 120);
        assert_eq!(DEFAULT_BRANCH_TIMEOUT_MS, 1000);
        assert_eq!(SYMBOLIC_GPR_WIDTH, 64);
    }

    #[test]
    fn branch_steering_prefers_direct_sat_target_edge() {
        let verdict = branch_steering_verdict("Sat", false, true, Some("alternate"), Some("validated"));
        assert_eq!(verdict.action, "prioritize-alternate");
        assert_eq!(verdict.confidence, "high");
    }

    #[test]
    fn branch_steering_rejects_unsat_alternate() {
        let verdict = branch_steering_verdict("Unsat", false, false, Some("alternate"), None);
        assert_eq!(verdict.action, "reject-alternate");
        assert_eq!(verdict.confidence, "high");
    }

    #[test]
    fn branch_steering_keeps_exact_chosen_target() {
        let verdict = branch_steering_verdict("Sat", true, false, Some("alternate"), Some("validated"));
        assert_eq!(verdict.action, "keep-chosen");
        assert_eq!(verdict.confidence, "high");
    }

    #[test]
    fn branch_steering_uses_cfg_only_after_sat() {
        let sat = branch_steering_verdict("Sat", false, false, Some("alternate"), None);
        assert_eq!(sat.action, "prioritize-alternate");
        assert_eq!(sat.confidence, "medium");

        let unknown = branch_steering_verdict("Unknown", false, false, Some("alternate"), None);
        assert_eq!(unknown.action, "unresolved");
        assert_eq!(unknown.confidence, "low");
    }

    #[test]
    fn branch_steering_equal_cfg_keeps_both_paths_interesting() {
        let verdict = branch_steering_verdict("Sat", false, false, Some("equal"), None);
        assert_eq!(verdict.action, "explore-both");
        assert_eq!(verdict.confidence, "medium");
    }

    #[test]
    fn branch_steering_replay_validation_upgrades_solver_only_flip() {
        let verdict = branch_steering_verdict("Sat", false, false, None, Some("validated"));
        assert_eq!(verdict.action, "explore-alternate");
        assert_eq!(verdict.confidence, "medium");
        assert!(verdict.reason.contains("concrete replay"));
    }

    #[test]
    fn branch_steering_replay_mismatch_vetoes_sat_alternate() {
        let verdict = branch_steering_verdict("Sat", false, true, Some("alternate"), Some("mismatch"));
        assert_eq!(verdict.action, "unresolved");
        assert_eq!(verdict.confidence, "low");
        assert!(verdict.reason.contains("did not take the predicted successor"));
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

    /// Numeric `regs` seeds stay exact and unknown registers error — the
    /// pre-existing contract, now routed through [`reg_seed_from_pair`].
    #[test]
    fn reg_seed_numeric_form_and_errors() -> Result<(), Box<dyn std::error::Error>> {
        let lua = Lua::new();
        let s = |v: &str| -> Result<Value, mlua::Error> { Ok(Value::String(lua.create_string(v)?)) };
        let pair = reg_seed_from_pair(&s("rcx")?, &Value::Integer(64))?;
        assert_eq!(pair, Some((reg_by_name("rcx").unwrap(), 64)));
        // Exact whole-number float behaves like mlua's old i64 conversion.
        let pair = reg_seed_from_pair(&s("rdx")?, &Value::Number(64.0))?;
        assert_eq!(pair, Some((reg_by_name("rdx").unwrap(), 64)));
        // Kernel pointer as a float is lossy > i64::MAX: honest error, not a
        // silently truncated seed.
        let err = reg_seed_from_pair(&s("rcx")?, &Value::Number(1.8446603336221197e19))
            .expect_err("lossy float must be rejected");
        assert!(err.to_string().contains("_hex"), "{err}");
        // Unknown register and non-numeric payloads are honest errors too.
        assert!(reg_seed_from_pair(&s("xmm0")?, &Value::Integer(1)).is_err());
        assert!(reg_seed_from_pair(&s("rcx")?, &Value::Boolean(true)).is_err());
        // Non-string keys are skipped (mirrors symbolic_mark_from_pair).
        assert_eq!(reg_seed_from_pair(&Value::Integer(1), &Value::Integer(1))?, None);
        Ok(())
    }

    /// The `_hex` string form carries kernel pointers above i64::MAX
    /// exactly — the shape pool pre-seeding (`pool_prealloc`) hands to
    /// structured-entry probes to pin a symbolic argument at a tracked
    /// block.
    #[test]
    fn reg_seed_hex_form_is_exact_for_kernel_pointers() -> Result<(), Box<dyn std::error::Error>> {
        let lua = Lua::new();
        let s = |v: &str| -> Result<Value, mlua::Error> { Ok(Value::String(lua.create_string(v)?)) };
        let kernel_ptr = 0xffff_8000_0000_1234u64;
        let pair = reg_seed_from_pair(&s("rcx_hex")?, &s("0xffff800000001234")?)?;
        assert_eq!(pair, Some((reg_by_name("rcx").unwrap(), kernel_ptr)));
        // `0X` prefix and bare digits are accepted; wrong register or
        // garbage digits are honest errors naming the key.
        let pair = reg_seed_from_pair(&s("r9_hex")?, &s("0XFF")?)?;
        assert_eq!(pair, Some((reg_by_name("r9").unwrap(), 0xff)));
        let err = reg_seed_from_pair(&s("nope_hex")?, &s("0x10")?).expect_err("bad reg");
        assert!(err.to_string().contains("nope"), "{err}");
        let err = reg_seed_from_pair(&s("rcx_hex")?, &s("zzz")?).expect_err("bad hex");
        assert!(err.to_string().contains("rcx_hex"), "{err}");
        // _hex with a non-string payload is an error, not a skip.
        assert!(reg_seed_from_pair(&s("rcx_hex")?, &Value::Integer(7)).is_err());
        Ok(())
    }

    #[test]
    fn registers_resolve_by_gpr_name() {
        let base = angryier_arch_intel64::register_id::GPR_BASE;
        assert_eq!(reg_by_name("rdi"), Some(base + 7));
        assert_eq!(reg_by_name("r15"), Some(base + 15));
        assert_eq!(reg_by_name("xmm0"), None);
    }

    /// The `_hex` form is one canonical string per value: lowercase,
    /// `0x`-prefixed, always 16 hex digits.
    #[test]
    fn hex64_is_canonical_sixteen_digit_lowercase() {
        assert_eq!(hex64(0), "0x0000000000000000");
        assert_eq!(hex64(0x401000), "0x0000000000401000");
        assert_eq!(hex64(i64::MAX as u64), "0x7fffffffffffffff");
        assert_eq!(hex64(0xffff_8000_0000_0000), "0xffff800000000000");
        assert_eq!(hex64(0xffff_8000_dead_beef), "0xffff8000deadbeef");
        assert_eq!(hex64(u64::MAX), "0xffffffffffffffff");
        for value in [hex64(1), hex64(0xdead_beef), hex64(u64::MAX)] {
            assert_eq!(value.len(), 18, "width must be fixed: {value}");
        }
    }

    /// Regression (downstream 730xd buildout, 2026-10-01): a kernel
    /// pointer above i64::MAX — exactly what the pool model's double-free
    /// events carry — must survive the trip into Lua. mlua pushes such a
    /// u64 as a Lua float, so the numeric field is a lossy double (and
    /// `string.format("%x", ...)` rejects it); the `_hex` sibling set by
    /// the same [`set_addr64`] call the result table uses is exact.
    #[test]
    fn kernel_pointer_hex_fields_round_trip_exactly() -> Result<(), Box<dyn std::error::Error>> {
        let lua = Lua::new();
        let event = lua.create_table()?;
        // Two shapes: the even pool base (exactly a double, still > i64::MAX
        // so `%x` refuses it) and a pointer with nonzero low bits (not even
        // exactly representable as a double).
        set_addr64(&event, "pointer", 0xffff_8000_0000_0000)?;
        set_addr64(&event, "caller", 0xffff_8000_dead_beef)?;
        lua.globals().set("event", event)?;
        lua.load(
            r#"
local ev = event
-- The defect, pinned: u64 > i64::MAX arrives as a Lua float, not an integer.
assert(math.type(ev.pointer) == "float",
       "pointer must arrive as float, got " .. math.type(ev.pointer))
assert(math.type(ev.caller) == "float",
       "caller must arrive as float, got " .. math.type(ev.caller))
-- That float is what breaks downstream formatting: %x rejects it.
assert(not pcall(string.format, "%x", ev.pointer),
       "lossy float must not be %x-formattable")
assert(not pcall(string.format, "%x", ev.caller))
-- The _hex sibling is exact for all 64 bits.
assert(ev.pointer_hex == "0xffff800000000000", ev.pointer_hex)
assert(ev.caller_hex == "0xffff8000deadbeef", ev.caller_hex)
assert(type(ev.pointer_hex) == "string" and type(ev.caller_hex) == "string")
-- Consistency: the numeric field and the _hex field describe the SAME
-- address. This Lua build (5.4.3+) parses an out-of-range hex string as
-- a WRAPPED (negative) integer rather than a float, so unwrapping by
-- 2^64 recovers the value mlua delivered as a float; a float parse
-- rounds exactly like the push itself, so it compares directly.
local function same_address(num, hex)
  local back = tonumber(hex)
  if math.type(back) == "integer" and back < 0 then
    return num == back + 2^64
  end
  return num == back
end
assert(same_address(ev.pointer, ev.pointer_hex), "pointer fields disagree")
assert(same_address(ev.caller, ev.caller_hex), "caller fields disagree")
return true
"#,
        )
        .eval::<bool>()?;
        Ok(())
    }

    /// Small image-VAs keep their exact integer numeric field alongside the
    /// `_hex` sibling — backward compatibility for user-mode-scale values.
    #[test]
    fn small_addresses_stay_exact_integers_with_hex_siblings() -> Result<(), Box<dyn std::error::Error>> {
        let lua = Lua::new();
        let event = lua.create_table()?;
        set_addr64(&event, "pointer", 0x40102a)?;
        lua.globals().set("event", event)?;
        lua.load(
            r#"
local ev = event
assert(math.type(ev.pointer) == "integer")
assert(ev.pointer == 0x40102a)
assert(ev.pointer_hex == "0x000000000040102a")
assert(string.format("%x", ev.pointer) == "40102a")
return true
"#,
        )
        .eval::<bool>()?;
        Ok(())
    }
}
