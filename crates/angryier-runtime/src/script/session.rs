//! Session controller and execution engine for the Lua scripting API.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap};
use std::rc::Rc;
use std::sync::Arc;

use mlua::{Lua, RegistryKey, Table, UserData, UserDataMethods, Value};

use super::state::LuaState;
use super::utils::reg_by_name;

/// Safe adapter exposing a `&'static ShardedExprArena` as an [`angryier_expr::ExprReader`].
pub struct StaticArenaReader(pub &'static angryier_expr::ShardedExprArena);

impl angryier_expr::ExprReader for StaticArenaReader {
    fn read(&self, id: angryier_types::ExprId) -> Option<angryier_expr::ExprNode> {
        self.0.read(id)
    }
}

/// Internal state shared by [`LuaSession`] and all descendant [`LuaState`] handles.
#[cfg(feature = "xed")]
pub struct SessionInner {
    pub session: crate::SymbolicSession<'static, crate::XedFormTranslator<angryier_arch_xed_ffi::XedDecoder>>,
    pub arena: Arc<StaticArenaReader>,
    pub backend: Option<angryier_solver_z3::Z3Backend<angryier_solver_z3::Z3FfiBridge>>,
    pub active_state_idx: usize,
    pub breakpoints: BTreeSet<u64>,
    pub hooks: HashMap<u64, RegistryKey>,
}

/// A live symbolic session exposed to Lua as a userdata handle.
#[cfg(feature = "xed")]
#[derive(Clone)]
pub struct LuaSession {
    pub(crate) inner: Rc<RefCell<SessionInner>>,
}

#[cfg(feature = "xed")]
impl LuaSession {
    /// Returns a [`LuaState`] handle pointing to the currently active execution path.
    pub fn active_state(&self) -> Result<LuaState, mlua::Error> {
        let inner = self.inner.borrow();
        if inner.session.states.is_empty() {
            return Err(mlua::Error::external("no active states in session"));
        }
        let idx = if inner.active_state_idx < inner.session.states.len() {
            inner.active_state_idx
        } else {
            0
        };
        let state_id = inner.session.states[idx].id;
        Ok(LuaState::new(Rc::clone(&self.inner), state_id))
    }

    /// Advances the active state by up to `count` instructions.
    pub fn step_n(&self, lua: &Lua, count: usize) -> Result<&'static str, mlua::Error> {
        let mut last_outcome = "stepped";

        for _ in 0..count {
            let mut inner = self.inner.borrow_mut();
            if inner.session.states.is_empty() {
                return Ok("terminated");
            }
            let idx = if inner.active_state_idx < inner.session.states.len() {
                inner.active_state_idx
            } else {
                inner.active_state_idx = 0;
                0
            };

            let state = &inner.session.states[idx];
            let pc = match state.process.pc() {
                Ok(p) => p,
                Err(_) => {
                    let mut dead_state = inner.session.states.remove(idx);
                    dead_state.process.terminated = true;
                    inner.session.dead.push(dead_state);
                    return Ok("terminated");
                }
            };

            // Check hooks
            if let Some(key) = inner.hooks.get(&pc) {
                let state_id = state.id;
                let hook_fn: mlua::Function = lua.registry_value(key)?;
                let state_handle = LuaState::new(Rc::clone(&self.inner), state_id);
                drop(inner); // release borrow before calling Lua hook

                let hook_result = hook_fn.call::<Option<Value>>(state_handle)?;
                if let Some(val) = hook_result {
                    match val {
                        Value::Boolean(false) => {
                            let mut inner = self.inner.borrow_mut();
                            if let Some(i) = inner.session.states.iter().position(|s| s.id == state_id) {
                                let mut s = inner.session.states.remove(i);
                                s.process.terminated = true;
                                inner.session.dead.push(s);
                            }
                            return Ok("hook_terminated");
                        }
                        Value::String(s) if s.as_bytes() == b"terminate" => {
                            let mut inner = self.inner.borrow_mut();
                            if let Some(i) = inner.session.states.iter().position(|s| s.id == state_id) {
                                let mut s = inner.session.states.remove(i);
                                s.process.terminated = true;
                                inner.session.dead.push(s);
                            }
                            return Ok("hook_terminated");
                        }
                        _ => {}
                    }
                }
                inner = self.inner.borrow_mut();
            }

            // Check breakpoints
            if inner.breakpoints.contains(&pc) {
                return Ok("breakpoint");
            }

            let outcome = inner.session.step_state(idx);
            match outcome {
                Ok(crate::SymbolicStepOutcome::Stepped { .. }) => {
                    last_outcome = "stepped";
                }
                Ok(crate::SymbolicStepOutcome::Branched { .. }) => {
                    last_outcome = "branched";
                }
                Ok(crate::SymbolicStepOutcome::Terminated) => {
                    if idx < inner.session.states.len() {
                        let mut dead_state = inner.session.states.remove(idx);
                        dead_state.process.terminated = true;
                        inner.session.dead.push(dead_state);
                    }
                    last_outcome = "terminated";
                    if inner.session.states.is_empty() {
                        return Ok("terminated");
                    }
                }
                Err(e) => {
                    if idx < inner.session.states.len() {
                        let mut dead_state = inner.session.states.remove(idx);
                        dead_state.process.terminated = true;
                        inner.session.dead.push(dead_state);
                    }
                    return Err(mlua::Error::external(format!("step: {e:?}")));
                }
            }
        }
        Ok(last_outcome)
    }
}

#[cfg(feature = "xed")]
impl UserData for LuaSession {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        // s:states() or s:states_count() -> integer
        methods.add_method("states", |_, this, ()| {
            Ok(this.inner.borrow().session.states.len())
        });
        methods.add_method("states_count", |_, this, ()| {
            Ok(this.inner.borrow().session.states.len())
        });

        // s:dead_count() -> integer
        methods.add_method("dead_count", |_, this, ()| {
            Ok(this.inner.borrow().session.dead.len())
        });

        // s:active_index([new_idx]) -> integer (0-based)
        methods.add_method("active_index", |_, this, new_idx: Option<usize>| {
            let mut inner = this.inner.borrow_mut();
            if let Some(idx) = new_idx {
                if idx < inner.session.states.len() {
                    inner.active_state_idx = idx;
                } else if !inner.session.states.is_empty() {
                    return Err(mlua::Error::external(format!(
                        "invalid state index {idx} (max is {})",
                        inner.session.states.len() - 1
                    )));
                }
            }
            Ok(inner.active_state_idx)
        });

        // s:select_state(idx) -> boolean
        methods.add_method("select_state", |_, this, idx: usize| {
            let mut inner = this.inner.borrow_mut();
            if idx < inner.session.states.len() {
                inner.active_state_idx = idx;
                Ok(true)
            } else {
                Ok(false)
            }
        });

        // s:state([idx]) -> LuaState handle
        methods.add_method("state", |_, this, idx: Option<usize>| {
            let inner = this.inner.borrow();
            let target_idx = idx.unwrap_or(inner.active_state_idx);
            let state = inner.session.states.get(target_idx).ok_or_else(|| {
                mlua::Error::external(format!("no active state at index {target_idx}"))
            })?;
            Ok(LuaState::new(Rc::clone(&this.inner), state.id))
        });

        // s:dead_state(idx) -> LuaState handle
        methods.add_method("dead_state", |_, this, idx: usize| {
            let inner = this.inner.borrow();
            let state = inner.session.dead.get(idx).ok_or_else(|| {
                mlua::Error::external(format!("no dead state at index {idx}"))
            })?;
            Ok(LuaState::new(Rc::clone(&this.inner), state.id))
        });

        // s:hook(addr, fn) -> registers a Lua callback before executing addr
        methods.add_method("hook", |lua, this, (addr, func): (u64, mlua::Function)| {
            let key = lua.create_registry_value(func)?;
            this.inner.borrow_mut().hooks.insert(addr, key);
            Ok(())
        });

        // s:unhook(addr) -> removes hook at addr
        methods.add_method("unhook", |lua, this, addr: u64| {
            if let Some(key) = this.inner.borrow_mut().hooks.remove(&addr) {
                let _ = lua.remove_registry_value(key);
                Ok(true)
            } else {
                Ok(false)
            }
        });

        // s:add_breakpoint(addr)
        methods.add_method("add_breakpoint", |_, this, addr: u64| {
            this.inner.borrow_mut().breakpoints.insert(addr);
            Ok(())
        });

        // s:remove_breakpoint(addr)
        methods.add_method("remove_breakpoint", |_, this, addr: u64| {
            Ok(this.inner.borrow_mut().breakpoints.remove(&addr))
        });

        // s:breakpoints() -> table array of breakpoint addresses
        methods.add_method("breakpoints", |lua, this, ()| {
            let inner = this.inner.borrow();
            let tbl = lua.create_table()?;
            for (i, &bp) in inner.breakpoints.iter().enumerate() {
                tbl.set(i + 1, bp)?;
            }
            Ok(tbl)
        });

        // s:step([n]) -> outcome string ("stepped", "branched", "terminated", "breakpoint", "hook_terminated")
        methods.add_method("step", |lua, this, count: Option<usize>| {
            this.step_n(lua, count.unwrap_or(1))
        });

        // s:step_until(target_pc, [max_steps]) -> (outcome, steps_taken)
        methods.add_method("step_until", |lua, this, (target_pc, max_steps): (u64, Option<usize>)| {
            let limit = max_steps.unwrap_or(10_000);
            let mut steps_taken = 0;

            loop {
                if steps_taken >= limit {
                    return Ok(("budget_exceeded", steps_taken));
                }
                {
                    let inner = this.inner.borrow();
                    if inner.session.states.is_empty() {
                        return Ok(("terminated", steps_taken));
                    }
                    let idx = inner.active_state_idx.min(inner.session.states.len().saturating_sub(1));
                    if let Ok(pc) = inner.session.states[idx].process.pc() {
                        if pc == target_pc {
                            return Ok(("reached", steps_taken));
                        }
                    } else {
                        return Ok(("terminated", steps_taken));
                    }
                }

                let outcome = this.step_n(lua, 1)?;
                steps_taken += 1;

                if outcome == "terminated" || outcome == "breakpoint" || outcome == "hook_terminated" {
                    return Ok((outcome, steps_taken));
                }
            }
        });

        // Shortcuts forwarding directly to the active state:
        methods.add_method("pc", |_, this, new_pc: Option<u64>| {
            let st = this.active_state()?;
            if let Some(target) = new_pc {
                st.set_pc(target)?;
                Ok(target)
            } else {
                st.get_pc()
            }
        });

        methods.add_method("reg", |_, this, (name, new_val): (String, Option<u64>)| {
            let st = this.active_state()?;
            if let Some(val) = new_val {
                st.set_reg(&name, val)?;
                Ok(Value::Integer(val as i64))
            } else {
                match st.get_reg(&name)? {
                    Some(v) => Ok(Value::Integer(v as i64)),
                    None => Ok(Value::Nil),
                }
            }
        });

        methods.add_method("regs", |lua, this, ()| {
            let st = this.active_state()?;
            st.get_regs(lua)
        });

        methods.add_method("read_bytes", |lua, this, (addr, len): (u64, usize)| {
            let st = this.active_state()?;
            st.read_bytes_lua(lua, addr, len)
        });

        methods.add_method("write_bytes", |_, this, (addr, data): (u64, Value)| {
            let st = this.active_state()?;
            let raw: Vec<u8> = match data {
                Value::String(s) => s.as_bytes().to_vec(),
                Value::Table(t) => {
                    let mut vec = Vec::new();
                    for b in t.sequence_values::<u8>() {
                        vec.push(b?);
                    }
                    vec
                }
                _ => return Err(mlua::Error::external("write_bytes: data must be a string or table of bytes")),
            };
            st.write_bytes_slice(addr, &raw)
        });

        methods.add_method("poke", |_, this, (addr, val): (u64, u64)| {
            let st = this.active_state()?;
            st.poke(addr, val)
        });

        methods.add_method("symbolic", |_, this, (name, width): (String, Option<i64>)| {
            let st = this.active_state()?;
            st.mark_symbolic(&name, width)
        });

        methods.add_method("symbolic_memory", |_, this, (addr, len): (u64, usize)| {
            let st = this.active_state()?;
            st.mark_memory_symbolic(addr, len)
        });

        methods.add_method("trace", |lua, this, ()| {
            let st = this.active_state()?;
            st.get_trace(lua)
        });

        methods.add_method("constraints_count", |_, this, ()| {
            let st = this.active_state()?;
            st.constraints_count()
        });

        methods.add_method("solve", |lua, this, ()| {
            let st = this.active_state()?;
            st.solve(lua)
        });

        methods.add_method("eval", |_, this, name: String| {
            let st = this.active_state()?;
            st.eval(&name)
        });

        methods.add_method("is_alive", |_, this, ()| {
            Ok(this.active_state().map(|st| st.is_alive()).unwrap_or(false))
        });
    }
}

/// Opens a live symbolic session with optional initial options table.
#[cfg(feature = "xed")]
pub fn open_session(path: &str, opts: Option<&Table>) -> mlua::Result<LuaSession> {
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
    let mut process = if is_pe {
        runtime
            .load_pe_driver(&bytes)
            .or_else(|_| runtime.load_pe(&bytes))
            .map_err(|e| mlua::Error::external(format!("load_pe: {e:?}")))?
    } else {
        runtime
            .load_elf(&bytes)
            .map_err(|e| mlua::Error::external(format!("load_elf: {e:?}")))?
    };

    if let Some(opts) = opts {
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
        if opts.get::<bool>("uc_memory").unwrap_or(false) {
            let uc_write_ro = opts.get::<bool>("uc_write_ro").unwrap_or(false);
            process.state.memory = process.state.memory.with_uc_memory().with_uc_write_ro(uc_write_ro);
        }
        if let Ok(entry) = opts.get::<i64>("entry")
            && entry > 0
        {
            process.write_pc(entry as u64).map_err(|e| mlua::Error::external(format!("entry: {e:?}")))?;
        }
    }

    let mut session = crate::SymbolicSession::new(runtime, arena, process);

    if let Some(opts) = opts {
        if opts.get::<bool>("uc_memory").unwrap_or(false) {
            session = session.with_uc_pin_fallback();
        }
        if let Ok(sym) = opts.get::<Table>("symbolic") {
            for pair in sym.pairs::<Value, Value>() {
                let (k, v) = pair?;
                if let Some((name, width)) = super::symbolic_mark_from_pair(&k, &v)? {
                    let reg = reg_by_name(&name).ok_or_else(|| mlua::Error::external(format!("bad reg {name}")))?;
                    session.mark_symbolic(0, reg, angryier_ir::IrType::Bits(width))
                        .map_err(|e| mlua::Error::external(format!("mark_symbolic: {e:?}")))?;
                }
            }
        }
        if let Ok(tbl) = opts.get::<Table>("regs") {
            for pair in tbl.pairs::<String, i64>() {
                let (name, value) = pair?;
                let reg = reg_by_name(&name).ok_or_else(|| mlua::Error::external(format!("bad reg {name}")))?;
                session.states[0].process.write_register(reg, value as u64)
                    .map_err(|e| mlua::Error::external(format!("regs[{name}]: {e:?}")))?;
                session.states[0].concrete_registers.insert(reg, value as u64);
            }
        }
        if let Ok(tbl) = opts.get::<Table>("poke") {
            for pair in tbl.pairs::<Value, Table>() {
                let (_, entry) = pair?;
                let addr = entry.get::<i64>("addr")? as u64;
                let value = entry.get::<i64>("value")? as u64;
                session.states[0].process.state.memory = session.states[0]
                    .process.state.memory.load_concrete(addr, &value.to_le_bytes())
                    .map_err(|e| mlua::Error::external(format!("poke: {e:?}")))?;
            }
        }
        if let Ok(tbl) = opts.get::<Table>("symbolic_memory") {
            for pair in tbl.pairs::<Value, Table>() {
                let (_, entry) = pair?;
                let addr = entry.get::<i64>("addr")? as u64;
                let len = entry.get::<i64>("len")? as usize;
                session.mark_memory_symbolic(0, addr, len)
                    .map_err(|e| mlua::Error::external(format!("symbolic_memory: {e:?}")))?;
            }
        }
    }

    let arena_reader = Arc::new(StaticArenaReader(arena));

    let backend = angryier_solver_z3::Z3Backend::native_ffi(
        arena_reader.clone() as Arc<dyn angryier_expr::ExprReader>,
    ).ok();

    Ok(LuaSession {
        inner: Rc::new(RefCell::new(SessionInner {
            session,
            arena: arena_reader,
            backend,
            active_state_idx: 0,
            breakpoints: BTreeSet::new(),
            hooks: HashMap::new(),
        })),
    })
}
