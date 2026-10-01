//! First-class `LuaState` UserData handle representing an individual execution path.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use angryier_memory::{ByteValue, LayeredMemory};
use mlua::{Lua, Table, UserData, UserDataMethods, Value};

use super::session::SessionInner;
use super::utils::{name_by_reg, reg_by_name};

/// A first-class handle to a single symbolic/concrete state within a [`super::LuaSession`].
///
/// States are identified by their immutable `state_id`, making handles safe against
/// insertions, removals, and state reordering.
#[cfg(feature = "xed")]
#[derive(Clone)]
pub struct LuaState {
    pub(crate) inner: Rc<RefCell<SessionInner>>,
    pub(crate) state_id: u64,
}

#[cfg(feature = "xed")]
impl LuaState {
    pub(crate) fn new(inner: Rc<RefCell<SessionInner>>, state_id: u64) -> Self {
        Self { inner, state_id }
    }

    /// Finds the index of this state in the active states list.
    pub(crate) fn active_index(inner: &SessionInner, state_id: u64) -> Option<usize> {
        inner.session.states.iter().position(|s| s.id == state_id)
    }

    pub fn is_alive(&self) -> bool {
        let inner = this_inner(&self.inner);
        Self::active_index(&inner, self.state_id).is_some()
    }

    pub fn get_pc(&self) -> Result<u64, mlua::Error> {
        let inner = this_inner(&self.inner);
        let idx = Self::active_index(&inner, self.state_id)
            .ok_or_else(|| mlua::Error::external("state is dead or terminated"))?;
        inner.session.states[idx].process.pc().map_err(|e| mlua::Error::external(format!("{e:?}")))
    }

    pub fn set_pc(&self, target: u64) -> Result<(), mlua::Error> {
        let mut inner = this_inner_mut(&self.inner);
        let idx = Self::active_index(&inner, self.state_id)
            .ok_or_else(|| mlua::Error::external("state is dead or terminated"))?;
        let state = &mut inner.session.states[idx];
        state.process.write_pc(target).map_err(|e| mlua::Error::external(format!("{e:?}")))?;
        state.concrete_registers.insert(angryier_arch_intel64::register_id::RIP.0, target);
        Ok(())
    }

    pub fn get_reg(&self, name: &str) -> Result<Option<u64>, mlua::Error> {
        let reg = reg_by_name(name)
            .ok_or_else(|| mlua::Error::external(format!("unknown register '{name}'")))?;
        let inner = this_inner(&self.inner);
        let idx = Self::active_index(&inner, self.state_id)
            .ok_or_else(|| mlua::Error::external("state is dead or terminated"))?;
        let state = &inner.session.states[idx];

        if let Some(&c) = state.concrete_registers.get(&reg) {
            Ok(Some(c))
        } else {
            Ok(state.process.read_register(reg).ok())
        }
    }

    pub fn set_reg(&self, name: &str, val: u64) -> Result<(), mlua::Error> {
        let reg = reg_by_name(name)
            .ok_or_else(|| mlua::Error::external(format!("unknown register '{name}'")))?;
        let mut inner = this_inner_mut(&self.inner);
        let idx = Self::active_index(&inner, self.state_id)
            .ok_or_else(|| mlua::Error::external("state is dead or terminated"))?;
        let state = &mut inner.session.states[idx];
        state.process.write_register(reg, val).map_err(|e| mlua::Error::external(format!("{e:?}")))?;
        state.concrete_registers.insert(reg, val);
        state.registers.remove(&reg);
        Ok(())
    }

    pub fn get_regs(&self, lua: &Lua) -> Result<Table, mlua::Error> {
        let inner = this_inner(&self.inner);
        let idx = Self::active_index(&inner, self.state_id)
            .ok_or_else(|| mlua::Error::external("state is dead or terminated"))?;
        let state = &inner.session.states[idx];
        let tbl = lua.create_table()?;

        let base = angryier_arch_intel64::register_id::GPR_BASE;
        for i in 0..16u32 {
            let reg = base + i;
            if let Some(name) = name_by_reg(reg) {
                let val = state.concrete_registers.get(&reg).copied()
                    .or_else(|| state.process.read_register(reg).ok());
                if let Some(v) = val {
                    tbl.set(name, v)?;
                }
            }
        }
        if let Ok(rip) = state.process.pc() {
            tbl.set("rip", rip)?;
        }
        Ok(tbl)
    }

    pub fn read_bytes_lua(&self, lua: &Lua, addr: u64, len: usize) -> Result<mlua::LuaString, mlua::Error> {
        let inner = this_inner(&self.inner);
        let idx = Self::active_index(&inner, self.state_id)
            .ok_or_else(|| mlua::Error::external("state is dead or terminated"))?;
        let state = &inner.session.states[idx];

        let bytes = state
            .process
            .state
            .memory
            .read(addr, len)
            .map_err(|e| mlua::Error::external(format!("read_bytes: {e:?}")))?;

        let raw: Vec<u8> = bytes
            .iter()
            .map(|b| match b {
                ByteValue::Concrete(v) => *v,
                ByteValue::Symbolic(_) => 0,
            })
            .collect();
        lua.create_string(&raw)
    }

    pub fn write_bytes_slice(&self, addr: u64, raw: &[u8]) -> Result<(), mlua::Error> {
        let mut inner = this_inner_mut(&self.inner);
        let idx = Self::active_index(&inner, self.state_id)
            .ok_or_else(|| mlua::Error::external("state is dead or terminated"))?;
        let state = &mut inner.session.states[idx];

        state.process.state.memory = state
            .process
            .state
            .memory
            .load_concrete(addr, raw)
            .map_err(|e| mlua::Error::external(format!("write_bytes: {e:?}")))?;
        Ok(())
    }

    pub fn poke(&self, addr: u64, val: u64) -> Result<(), mlua::Error> {
        self.write_bytes_slice(addr, &val.to_le_bytes())
    }

    pub fn mark_symbolic(&self, name: &str, width: Option<i64>) -> Result<(), mlua::Error> {
        let reg = reg_by_name(name)
            .ok_or_else(|| mlua::Error::external(format!("unknown register '{name}'")))?;
        let width = super::validate_symbolic_width(name, width)?;

        let mut inner = this_inner_mut(&self.inner);
        let idx = Self::active_index(&inner, self.state_id)
            .ok_or_else(|| mlua::Error::external("state is dead or terminated"))?;

        inner
            .session
            .mark_symbolic(idx, reg, angryier_ir::IrType::Bits(width))
            .map_err(|e| mlua::Error::external(format!("mark_symbolic: {e:?}")))?;
        Ok(())
    }

    pub fn mark_memory_symbolic(&self, addr: u64, len: usize) -> Result<(), mlua::Error> {
        let mut inner = this_inner_mut(&self.inner);
        let idx = Self::active_index(&inner, self.state_id)
            .ok_or_else(|| mlua::Error::external("state is dead or terminated"))?;

        inner
            .session
            .mark_memory_symbolic(idx, addr, len)
            .map_err(|e| mlua::Error::external(format!("symbolic_memory: {e:?}")))?;
        Ok(())
    }

    pub fn get_trace(&self, lua: &Lua) -> Result<Table, mlua::Error> {
        let inner = this_inner(&self.inner);
        let idx = Self::active_index(&inner, self.state_id)
            .ok_or_else(|| mlua::Error::external("state is dead or terminated"))?;
        let state = &inner.session.states[idx];

        let tbl = lua.create_table()?;
        for (i, pc) in state.process.trace.iter().enumerate() {
            tbl.set(i + 1, *pc)?;
        }
        Ok(tbl)
    }

    pub fn constraints_count(&self) -> Result<usize, mlua::Error> {
        let inner = this_inner(&self.inner);
        let idx = Self::active_index(&inner, self.state_id)
            .ok_or_else(|| mlua::Error::external("state is dead or terminated"))?;
        Ok(inner.session.states[idx].constraints.len())
    }

    pub fn solve(&self, lua: &Lua) -> Result<Table, mlua::Error> {
        let mut inner = this_inner_mut(&self.inner);
        let idx = Self::active_index(&inner, self.state_id)
            .ok_or_else(|| mlua::Error::external("state is dead or terminated"))?;

        let arena = inner.arena.clone();
        if inner.backend.is_none() {
            let b = angryier_solver_z3::Z3Backend::native_ffi(
                arena as std::sync::Arc<dyn angryier_expr::ExprReader>,
            )
            .map_err(|e| mlua::Error::external(format!("z3 initialization: {e:?}")))?;
            inner.backend = Some(b);
        }
        let SessionInner { session, backend, .. } = &mut *inner;
        let backend = backend.as_mut().ok_or_else(|| mlua::Error::external("backend not available"))?;

        let model = session
            .solve_state_symbols(idx, backend, Duration::from_secs(10))
            .map_err(|e| mlua::Error::external(format!("solve: {e:?}")))?;

        let tbl = lua.create_table()?;
        for (i, (_eid, bytes)) in model.iter().enumerate() {
            tbl.set(i + 1, lua.create_string(bytes)?)?;
        }
        Ok(tbl)
    }

    pub fn eval(&self, name: &str) -> Result<u64, mlua::Error> {
        let reg = reg_by_name(name)
            .ok_or_else(|| mlua::Error::external(format!("unknown register '{name}'")))?;
        let mut inner = this_inner_mut(&self.inner);
        let idx = Self::active_index(&inner, self.state_id)
            .ok_or_else(|| mlua::Error::external("state is dead or terminated"))?;

        if let Some(&val) = inner.session.states[idx].concrete_registers.get(&reg) {
            return Ok(val);
        }

        let arena = inner.arena.clone();
        if inner.backend.is_none() {
            let b = angryier_solver_z3::Z3Backend::native_ffi(
                arena as std::sync::Arc<dyn angryier_expr::ExprReader>,
            )
            .map_err(|e| mlua::Error::external(format!("z3 initialization: {e:?}")))?;
            inner.backend = Some(b);
        }
        let SessionInner { session, backend, .. } = &mut *inner;
        let backend = backend.as_mut().ok_or_else(|| mlua::Error::external("backend not available"))?;

        let solved = session
            .solve_state(idx, backend, Duration::from_secs(10))
            .map_err(|e| mlua::Error::external(format!("eval: {e:?}")))?;

        for (r, val) in solved {
            if r == reg {
                return Ok(val);
            }
        }

        session.states[idx]
            .process
            .read_register(reg)
            .map_err(|e| mlua::Error::external(format!("eval fallback: {e:?}")))
    }
}

fn this_inner(cell: &Rc<RefCell<SessionInner>>) -> std::cell::Ref<'_, SessionInner> {
    cell.borrow()
}

fn this_inner_mut(cell: &Rc<RefCell<SessionInner>>) -> std::cell::RefMut<'_, SessionInner> {
    cell.borrow_mut()
}

#[cfg(feature = "xed")]
impl UserData for LuaState {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        // st:id() -> integer
        methods.add_method("id", |_, this, ()| Ok(this.state_id));

        // st:is_alive() -> bool
        methods.add_method("is_alive", |_, this, ()| Ok(this.is_alive()));

        // st:pc([new_pc]) -> integer
        methods.add_method("pc", |_, this, new_pc: Option<u64>| {
            if let Some(target) = new_pc {
                this.set_pc(target)?;
                Ok(target)
            } else {
                this.get_pc()
            }
        });

        // st:reg(name, [new_val]) -> integer or nil
        methods.add_method("reg", |_, this, (name, new_val): (String, Option<u64>)| {
            if let Some(val) = new_val {
                this.set_reg(&name, val)?;
                Ok(Value::Integer(val as i64))
            } else {
                match this.get_reg(&name)? {
                    Some(v) => Ok(Value::Integer(v as i64)),
                    None => Ok(Value::Nil),
                }
            }
        });

        // st:regs() -> table { rax = 0x..., rbx = 0x..., ... }
        methods.add_method("regs", |lua, this, ()| this.get_regs(lua));

        // st:read_bytes(addr, len) -> string
        methods.add_method("read_bytes", |lua, this, (addr, len): (u64, usize)| {
            this.read_bytes_lua(lua, addr, len)
        });

        // st:write_bytes(addr, data)
        methods.add_method("write_bytes", |_, this, (addr, data): (u64, Value)| {
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
            this.write_bytes_slice(addr, &raw)
        });

        // st:poke(addr, val)
        methods.add_method("poke", |_, this, (addr, val): (u64, u64)| {
            this.poke(addr, val)
        });

        // st:symbolic(name, [width])
        methods.add_method("symbolic", |_, this, (name, width): (String, Option<i64>)| {
            this.mark_symbolic(&name, width)
        });

        // st:symbolic_memory(addr, len)
        methods.add_method("symbolic_memory", |_, this, (addr, len): (u64, usize)| {
            this.mark_memory_symbolic(addr, len)
        });

        // st:trace()
        methods.add_method("trace", |lua, this, ()| this.get_trace(lua));

        // st:constraints_count()
        methods.add_method("constraints_count", |_, this, ()| this.constraints_count());

        // st:solve() -> table of symbol values
        methods.add_method("solve", |lua, this, ()| this.solve(lua));

        // st:eval(reg_name) -> integer
        methods.add_method("eval", |_, this, name: String| this.eval(&name));

        // st:terminate() -> kills state
        methods.add_method("terminate", |_, this, ()| {
            let mut inner = this.inner.borrow_mut();
            if let Some(idx) = Self::active_index(&inner, this.state_id) {
                let mut state = inner.session.states.remove(idx);
                state.process.terminated = true;
                inner.session.dead.push(state);
            }
            Ok(())
        });
    }
}
