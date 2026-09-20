//! Embedded Lua scripting surface (Phase 15) — drives a symbolic session
//! without recompiling. Scripts call `angry.run(path, opts)` which builds
//! the runtime internally and returns a report table:
//!
//! ```lua
//! local r = angry.run("/tmp/hello", {
//!     symbolic = { rdi = 64 },          -- register name -> bit width
//!     find = { 0x40102a },              -- target pcs
//!     avoid = { 0x40103b },
//!     steps = 512, states = 32,
//!     solve = true,                     -- solve found states
//! })
//! print(r.steps, r.forks, r.merges)
//! for i, input in ipairs(r.inputs) do print(input) end
//! ```

use angryier_expr::ExprArena;
use mlua::{Lua, Table, Value};

/// The `angry` library installed into each script VM.
pub fn register(lua: &Lua) -> mlua::Result<()> {
    let lib = lua.create_table()?;
    lib.set(
        "run",
        lua.create_function(|lua, (path, opts): (String, Table)| run_driver(lua, &path, &opts))?,
    )?;
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
    let runtime =
        crate::Runtime::with_native_xed(angryier_types::SemanticVersion(1), angryier_types::TargetProfileId(1));
    let process = runtime
        .load_elf(&bytes)
        .map_err(|e| mlua::Error::external(format!("load_elf: {e:?}")))?;
    // The Z3 backend needs a shared arena reader — keep the arena in Arc.
    let arena = std::sync::Arc::new(angryier_expr::ShardedExprArena::new(
        angryier_types::ExpressionNormalizationVersion(1),
    ));
    let mut session = crate::SymbolicSession::new(&runtime, arena.as_ref(), process);

    // Symbolic register marks: `symbolic = { rdi = 64 }` or `{ "rdi" }`.
    if let Ok(sym) = opts.get::<Table>("symbolic") {
        for pair in sym.pairs::<Value, Value>() {
            let (k, v) = pair?;
            let name = match (&k, &v) {
                (Value::String(s), _) => s.to_str()?.to_string(),
                (_, Value::String(s)) => s.to_str()?.to_string(),
                _ => continue,
            };
            if let Some(reg) = reg_by_name(&name) {
                session
                    .mark_symbolic(0, reg, angryier_ir::IrType::Bits(64))
                    .map_err(|e| mlua::Error::external(format!("mark_symbolic: {e:?}")))?;
            }
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
    let steps = opts.get::<u64>("steps").unwrap_or(256);
    let max_states = opts.get::<usize>("states").unwrap_or(16);
    let use_solver = opts.get::<bool>("solve").unwrap_or(false);

    let policy = crate::ExplorationPolicy {
        find,
        avoid,
        ..Default::default()
    };
    let mut backend = if use_solver {
        Some(
            angryier_solver_z3::Z3Backend::native_ffi(arena.clone() as std::sync::Arc<dyn angryier_expr::ExprReader>)
                .map_err(|e| mlua::Error::external(format!("z3: {e:?}")))?,
        )
    } else {
        None
    };
    let report = session
        .run_with_policy(
            steps,
            max_states,
            backend.as_mut().map(|b| b as &mut dyn angryier_solver::SolverBackend),
            std::time::Duration::from_secs(30),
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
    out.set("live_states", report.live_states)?;
    out.set("found", report.found.len())?;
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
