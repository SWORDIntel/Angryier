//! Speculative Concolic Fast-Path Batching (speculative concolic tier).
//!
//! Generalizes single-block concrete speculation (`try_concrete_block`) to
//! chunks of K basic blocks / N instructions executed in bulk.
//!
//! # Architecture
//!
//! In concolic exploration, execution traces are heavily dominated by code
//! regions unaffected by symbolic inputs. Step-by-step concolic shadow evaluation
//! builds expression trees, checks constants, and interns arena nodes on every
//! instruction.
//!
//! `SpeculativeConcolicBatcher` captures a lightweight checkpoint of the concolic
//! state (registers and memory delta mark) at chunk entry. It then speculatively
//! executes instructions in bulk using fast-path concrete operations guarded by
//! taint barriers.
//!
//! - **Zero symbolic taint throughout the chunk**:
//!   The entire chunk commits in bulk in $O(1)$, updating the architectural PC
//!   and concrete state without constructing intermediate shadow expressions or
//!   touching the symbolic arena.
//!
//! - **Symbolic taint encountered mid-chunk**:
//!   Speculative execution halts immediately. The state rolls back to the exact
//!   instruction that touched tainted state, and control is handed back to the
//!   fine-grained concolic shadow evaluator to construct proper symbolic
//!   expressions and track path constraints.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

/// Arithmetic and logical operations supported on the concrete fast path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FastPathOp {
    Add,
    Sub,
    Mul,
    And,
    Or,
    Xor,
    Shl,
    Shr,
    Sar,
    Eq,
    Ne,
    Lt,
    Gt,
    Le,
    Ge,
}

impl FastPathOp {
    /// Evaluates the operation concretely over 64-bit unsigned integers.
    #[must_use]
    pub fn eval(self, a: u64, b: u64) -> u64 {
        match self {
            Self::Add => a.wrapping_add(b),
            Self::Sub => a.wrapping_sub(b),
            Self::Mul => a.wrapping_mul(b),
            Self::And => a & b,
            Self::Or => a | b,
            Self::Xor => a ^ b,
            Self::Shl => a.wrapping_shl((b & 63) as u32),
            Self::Shr => a.wrapping_shr((b & 63) as u32),
            Self::Sar => (a as i64).wrapping_shr((b & 63) as u32) as u64,
            Self::Eq => u64::from(a == b),
            Self::Ne => u64::from(a != b),
            Self::Lt => u64::from(a < b),
            Self::Gt => u64::from(a > b),
            Self::Le => u64::from(a <= b),
            Self::Ge => u64::from(a >= b),
        }
    }
}

/// An instruction representation for the concolic fast-path batcher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FastPathInsn {
    /// Register copy: `dst = src`.
    MovReg { dst: u32, src: u32 },
    /// Set register to immediate constant: `dst = val`.
    SetImm { dst: u32, val: u64 },
    /// Binary register operation: `dst = op(src1, src2)`.
    BinOp {
        op: FastPathOp,
        dst: u32,
        src1: u32,
        src2: u32,
    },
    /// Binary register-immediate operation: `dst = op(src, imm)`.
    BinOpImm {
        op: FastPathOp,
        dst: u32,
        src: u32,
        imm: u64,
    },
    /// Memory load: `dst = [addr_reg + offset]`.
    Load {
        dst: u32,
        addr_reg: u32,
        offset: i64,
        size: usize,
    },
    /// Memory store: `[addr_reg + offset] = src`.
    Store {
        addr_reg: u32,
        offset: i64,
        src: u32,
        size: usize,
    },
    /// Unconditional jump to `target`.
    Jump { target: u64 },
    /// Conditional branch based on `cond_reg`: if `!= 0` branch to `taken`, else `not_taken`.
    Branch {
        cond_reg: u32,
        taken: u64,
        not_taken: u64,
    },
    /// No operation.
    Nop,
}

/// Identifies which operand or condition triggered a taint barrier during speculative batching.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaintedOperand {
    /// A register operand carried symbolic taint.
    Register(u32),
    /// A memory load accessed tainted symbolic memory bytes.
    MemoryAddress { address: u64, size: usize },
    /// A branch condition evaluated over symbolic input.
    Condition(u32),
    /// An operation not supported by concrete fast path.
    UnsupportedOp(&'static str),
}

/// Lightweight rollback checkpoint captured at the start of a speculative chunk.
///
/// Contains the register file snapshot and memory journal mark, enabling $O(1)$
/// delta rollback if symbolic taint is encountered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpeculativeConcolicCheckpoint {
    /// Concrete register values at checkpoint time.
    pub saved_registers: BTreeMap<u32, u64>,
    /// Index into the memory delta journal marking the start of this chunk.
    pub memory_delta_mark: usize,
    /// Program counter at checkpoint time.
    pub saved_pc: u64,
    /// Instruction step count at checkpoint time.
    pub saved_step_count: u64,
}

/// Outcome of executing a speculative concolic chunk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpeculativeChunkResult {
    /// Entire chunk executed cleanly with zero symbolic taint and was committed in bulk.
    Committed {
        /// Number of instructions executed in the chunk.
        instructions_executed: usize,
        /// Final program counter after chunk commit.
        final_pc: u64,
    },
    /// Symbolic taint was encountered mid-chunk. State was rolled back to the exact
    /// instruction that touched tainted state.
    Aborted {
        /// Number of clean instructions executed prior to the tainted instruction.
        instructions_executed: usize,
        /// Program counter of the exact instruction that touched tainted state.
        rollback_pc: u64,
        /// The tainted operand that triggered the abort.
        tainted_operand: TaintedOperand,
    },
    /// Execution terminated cleanly because no further instructions were present at PC.
    EndOfCode {
        /// Number of instructions executed.
        instructions_executed: usize,
        /// Final program counter.
        final_pc: u64,
    },
}

/// Operational metrics emitted by [`SpeculativeConcolicBatcher`].
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct SpeculativeBatcherMetrics {
    /// Number of speculative chunks started.
    pub chunks_attempted: u64,
    /// Number of speculative chunks successfully committed in bulk.
    pub chunks_committed: u64,
    /// Number of speculative chunks aborted due to symbolic taint.
    pub chunks_aborted: u64,
    /// Total number of instructions successfully executed on the fast path.
    pub instructions_fast_pathed: u64,
    /// Estimated speedup ratio over pure fine-grained concolic shadow evaluation.
    pub speedup_ratio: f64,
}

/// Concolic execution state supporting fast-path concrete batching, taint tracking,
/// lightweight delta checkpointing, and fine-grained shadow stepping.
#[derive(Clone, Debug, Default)]
pub struct SpeculativeConcolicState {
    /// Concrete architectural register values: `reg_id -> u64`.
    pub registers: BTreeMap<u32, u64>,
    /// Concrete memory image: `address -> byte`.
    pub memory: BTreeMap<u64, u8>,
    /// Set of registers carrying symbolic taint (derived from inputs).
    pub tainted_registers: BTreeSet<u32>,
    /// Set of memory addresses carrying symbolic taint (input bytes).
    pub tainted_memory: BTreeSet<u64>,
    /// Current program counter.
    pub pc: u64,
    /// Total instructions executed.
    pub step_count: u64,
    /// Memory delta journal: records `(address, previous_byte_value)` for rollbacks.
    pub memory_journal: Vec<(u64, Option<u8>)>,
    /// Program code: `pc -> (instruction, instruction_byte_length)`.
    pub code: BTreeMap<u64, (FastPathInsn, usize)>,
}

impl SpeculativeConcolicState {
    /// Creates a new state starting at `entry_pc`.
    #[must_use]
    pub fn new(entry_pc: u64) -> Self {
        Self {
            registers: BTreeMap::new(),
            memory: BTreeMap::new(),
            tainted_registers: BTreeSet::new(),
            tainted_memory: BTreeSet::new(),
            pc: entry_pc,
            step_count: 0,
            memory_journal: Vec::new(),
            code: BTreeMap::new(),
        }
    }

    /// Sets concrete value for `reg`.
    pub fn set_register(&mut self, reg: u32, val: u64) {
        self.registers.insert(reg, val);
    }

    /// Reads concrete value for `reg` (defaults to 0 if unset).
    #[must_use]
    pub fn read_register(&self, reg: u32) -> u64 {
        self.registers.get(&reg).copied().unwrap_or(0)
    }

    /// Marks `reg` as carrying symbolic taint.
    pub fn mark_register_tainted(&mut self, reg: u32) {
        self.tainted_registers.insert(reg);
    }

    /// Clears symbolic taint on `reg`.
    pub fn clear_register_tainted(&mut self, reg: u32) {
        self.tainted_registers.remove(&reg);
    }

    /// Returns `true` if `reg` carries symbolic taint.
    #[must_use]
    pub fn is_register_tainted(&self, reg: u32) -> bool {
        self.tainted_registers.contains(&reg)
    }

    /// Writes concrete bytes into memory, recording changes in the memory delta journal.
    pub fn write_memory(&mut self, addr: u64, bytes: &[u8]) {
        for (i, &b) in bytes.iter().enumerate() {
            let target = addr.wrapping_add(i as u64);
            let prev = self.memory.get(&target).copied();
            self.memory_journal.push((target, prev));
            self.memory.insert(target, b);
        }
    }

    /// Writes a little-endian unsigned integer of `size` bytes (1..=8) into memory.
    pub fn write_memory_u64(&mut self, addr: u64, val: u64, size: usize) {
        let bytes = val.to_le_bytes();
        let len = size.min(8);
        self.write_memory(addr, &bytes[..len]);
    }

    /// Reads `len` bytes from memory starting at `addr`.
    #[must_use]
    pub fn read_memory(&self, addr: u64, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        for i in 0..len {
            let target = addr.wrapping_add(i as u64);
            out.push(self.memory.get(&target).copied().unwrap_or(0));
        }
        out
    }

    /// Reads up to 8 bytes as a little-endian `u64`.
    #[must_use]
    pub fn read_memory_u64(&self, addr: u64, size: usize) -> u64 {
        let len = size.min(8);
        let mut buf = [0u8; 8];
        for (i, byte) in buf.iter_mut().enumerate().take(len) {
            let target = addr.wrapping_add(i as u64);
            *byte = self.memory.get(&target).copied().unwrap_or(0);
        }
        u64::from_le_bytes(buf)
    }

    /// Marks `len` bytes at `addr` as carrying symbolic taint.
    pub fn mark_memory_tainted(&mut self, addr: u64, len: usize) {
        for i in 0..len {
            self.tainted_memory.insert(addr.wrapping_add(i as u64));
        }
    }

    /// Clears symbolic taint for `len` bytes at `addr`.
    pub fn clear_memory_tainted(&mut self, addr: u64, len: usize) {
        for i in 0..len {
            self.tainted_memory.remove(&addr.wrapping_add(i as u64));
        }
    }

    /// Returns `true` if any byte in `addr..addr+len` carries symbolic taint.
    #[must_use]
    pub fn is_memory_tainted(&self, addr: u64, len: usize) -> bool {
        for i in 0..len {
            if self.tainted_memory.contains(&addr.wrapping_add(i as u64)) {
                return true;
            }
        }
        false
    }

    /// Adds an instruction to the state's program at `addr`.
    pub fn add_instruction(&mut self, addr: u64, insn: FastPathInsn, length: usize) {
        self.code.insert(addr, (insn, length));
    }

    /// Captures a lightweight checkpoint of the concolic state.
    #[must_use]
    pub fn checkpoint(&self) -> SpeculativeConcolicCheckpoint {
        SpeculativeConcolicCheckpoint {
            saved_registers: self.registers.clone(),
            memory_delta_mark: self.memory_journal.len(),
            saved_pc: self.pc,
            saved_step_count: self.step_count,
        }
    }

    /// Rolls back memory mutations to `mark` in the memory journal.
    pub fn rollback_memory_to(&mut self, mark: usize) {
        while self.memory_journal.len() > mark {
            if let Some((addr, prev)) = self.memory_journal.pop() {
                match prev {
                    Some(b) => {
                        self.memory.insert(addr, b);
                    }
                    None => {
                        self.memory.remove(&addr);
                    }
                }
            }
        }
    }

    /// Restores full state to a previously captured checkpoint.
    pub fn restore_checkpoint(&mut self, cp: &SpeculativeConcolicCheckpoint) {
        self.registers = cp.saved_registers.clone();
        self.rollback_memory_to(cp.memory_delta_mark);
        self.pc = cp.saved_pc;
        self.step_count = cp.saved_step_count;
    }

    /// Fine-grained concolic shadow evaluator step: executes one instruction at `self.pc`
    /// while tracking and propagating symbolic taint.
    ///
    /// Returns `Ok(true)` if an instruction was executed, or `Ok(false)` if at end of code.
    pub fn step_concolic_fine_grained(&mut self) -> Result<bool, &'static str> {
        let (insn, len) = match self.code.get(&self.pc).cloned() {
            Some(entry) => entry,
            None => return Ok(false),
        };
        let current_pc = self.pc;
        let next_sequential_pc = current_pc.wrapping_add(len as u64);

        match insn {
            FastPathInsn::MovReg { dst, src } => {
                let val = self.read_register(src);
                self.set_register(dst, val);
                if self.is_register_tainted(src) {
                    self.mark_register_tainted(dst);
                } else {
                    self.clear_register_tainted(dst);
                }
                self.pc = next_sequential_pc;
            }
            FastPathInsn::SetImm { dst, val } => {
                self.set_register(dst, val);
                self.clear_register_tainted(dst);
                self.pc = next_sequential_pc;
            }
            FastPathInsn::BinOp { op, dst, src1, src2 } => {
                let v1 = self.read_register(src1);
                let v2 = self.read_register(src2);
                let res = op.eval(v1, v2);
                self.set_register(dst, res);
                if self.is_register_tainted(src1) || self.is_register_tainted(src2) {
                    self.mark_register_tainted(dst);
                } else {
                    self.clear_register_tainted(dst);
                }
                self.pc = next_sequential_pc;
            }
            FastPathInsn::BinOpImm { op, dst, src, imm } => {
                let v1 = self.read_register(src);
                let res = op.eval(v1, imm);
                self.set_register(dst, res);
                if self.is_register_tainted(src) {
                    self.mark_register_tainted(dst);
                } else {
                    self.clear_register_tainted(dst);
                }
                self.pc = next_sequential_pc;
            }
            FastPathInsn::Load { dst, addr_reg, offset, size } => {
                let base = self.read_register(addr_reg);
                let addr = base.wrapping_add(offset as u64);
                let val = self.read_memory_u64(addr, size);
                self.set_register(dst, val);
                if self.is_register_tainted(addr_reg) || self.is_memory_tainted(addr, size) {
                    self.mark_register_tainted(dst);
                } else {
                    self.clear_register_tainted(dst);
                }
                self.pc = next_sequential_pc;
            }
            FastPathInsn::Store { addr_reg, offset, src, size } => {
                let base = self.read_register(addr_reg);
                let addr = base.wrapping_add(offset as u64);
                let val = self.read_register(src);
                self.write_memory_u64(addr, val, size);
                if self.is_register_tainted(src) {
                    self.mark_memory_tainted(addr, size);
                } else {
                    self.clear_memory_tainted(addr, size);
                }
                self.pc = next_sequential_pc;
            }
            FastPathInsn::Jump { target } => {
                self.pc = target;
            }
            FastPathInsn::Branch { cond_reg, taken, not_taken } => {
                let cond = self.read_register(cond_reg);
                self.pc = if cond != 0 { taken } else { not_taken };
            }
            FastPathInsn::Nop => {
                self.pc = next_sequential_pc;
            }
        }

        self.step_count += 1;
        Ok(true)
    }
}

/// Speculative Concolic Fast-Path Batcher.
///
/// Executes chunks of basic blocks / instructions concretely in bulk.
/// When no symbolic taint is touched, the entire chunk is committed in $O(1)$.
/// If symbolic taint is encountered mid-chunk, state rolls back to the exact
/// instruction touching tainted state.
#[derive(Debug, Default)]
pub struct SpeculativeConcolicBatcher {
    chunks_attempted: u64,
    chunks_committed: u64,
    chunks_aborted: u64,
    instructions_fast_pathed: u64,
    instructions_aborted: u64,
    active_checkpoint: Option<SpeculativeConcolicCheckpoint>,
}

impl SpeculativeConcolicBatcher {
    /// Creates a new, uninitialized batcher.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Captures a lightweight checkpoint of the concolic state (registers and memory delta mark).
    pub fn begin_chunk(&mut self, state: &SpeculativeConcolicState) -> SpeculativeConcolicCheckpoint {
        self.chunks_attempted += 1;
        let cp = state.checkpoint();
        self.active_checkpoint = Some(cp.clone());
        cp
    }

    /// Executes a speculative chunk of up to `max_instructions` concretely with
    /// fast-path taint-barrier checks.
    ///
    /// - If the entire chunk has zero symbolic taint: commits in bulk ($O(1)$),
    ///   updating PC and concrete state without intermediate shadow expressions.
    /// - If symbolic taint is encountered mid-chunk: rolls back to the exact
    ///   instruction that touched tainted state and hands control back to the caller.
    pub fn step_speculative_chunk(
        &mut self,
        state: &mut SpeculativeConcolicState,
        max_instructions: usize,
    ) -> SpeculativeChunkResult {
        if max_instructions == 0 {
            return SpeculativeChunkResult::Committed {
                instructions_executed: 0,
                final_pc: state.pc,
            };
        }

        // Establish chunk checkpoint if not already captured.
        let _chunk_cp = match self.active_checkpoint.take() {
            Some(cp) => cp,
            None => {
                let cp = self.begin_chunk(state);
                self.active_checkpoint = None;
                cp
            }
        };

        let mut executed_in_chunk = 0usize;

        while executed_in_chunk < max_instructions {
            let current_pc = state.pc;
            let (insn, len) = match state.code.get(&current_pc).cloned() {
                Some(entry) => entry,
                None => {
                    // Reached end of available code: commit what ran so far in bulk.
                    self.chunks_committed += 1;
                    self.instructions_fast_pathed += executed_in_chunk as u64;
                    return SpeculativeChunkResult::EndOfCode {
                        instructions_executed: executed_in_chunk,
                        final_pc: current_pc,
                    };
                }
            };

            let next_seq_pc = current_pc.wrapping_add(len as u64);
            let pre_insn_journal_mark = state.memory_journal.len();
            let pre_insn_registers = state.registers.clone();

            // ── Fast-path taint barrier check ──────────────────────────────────
            let taint_hit = match &insn {
                FastPathInsn::MovReg { src, .. } => {
                    if state.is_register_tainted(*src) {
                        Some(TaintedOperand::Register(*src))
                    } else {
                        None
                    }
                }
                FastPathInsn::SetImm { .. } | FastPathInsn::Nop | FastPathInsn::Jump { .. } => None,
                FastPathInsn::BinOp { src1, src2, .. } => {
                    if state.is_register_tainted(*src1) {
                        Some(TaintedOperand::Register(*src1))
                    } else if state.is_register_tainted(*src2) {
                        Some(TaintedOperand::Register(*src2))
                    } else {
                        None
                    }
                }
                FastPathInsn::BinOpImm { src, .. } => {
                    if state.is_register_tainted(*src) {
                        Some(TaintedOperand::Register(*src))
                    } else {
                        None
                    }
                }
                FastPathInsn::Load { addr_reg, offset, size, .. } => {
                    if state.is_register_tainted(*addr_reg) {
                        Some(TaintedOperand::Register(*addr_reg))
                    } else {
                        let base = state.read_register(*addr_reg);
                        let addr = base.wrapping_add(*offset as u64);
                        if state.is_memory_tainted(addr, *size) {
                            Some(TaintedOperand::MemoryAddress { address: addr, size: *size })
                        } else {
                            None
                        }
                    }
                }
                FastPathInsn::Store { addr_reg, offset, src, size } => {
                    if state.is_register_tainted(*addr_reg) {
                        Some(TaintedOperand::Register(*addr_reg))
                    } else if state.is_register_tainted(*src) {
                        Some(TaintedOperand::Register(*src))
                    } else {
                        let base = state.read_register(*addr_reg);
                        let addr = base.wrapping_add(*offset as u64);
                        if state.is_memory_tainted(addr, *size) {
                            Some(TaintedOperand::MemoryAddress { address: addr, size: *size })
                        } else {
                            None
                        }
                    }
                }
                FastPathInsn::Branch { cond_reg, .. } => {
                    if state.is_register_tainted(*cond_reg) {
                        Some(TaintedOperand::Condition(*cond_reg))
                    } else {
                        None
                    }
                }
            };

            // ── Mid-chunk taint encountered: exact rollback ────────────────────
            if let Some(tainted_operand) = taint_hit {
                // Roll back any partial mutations of this instruction so state matches
                // the exact start of the tainted instruction.
                state.pc = current_pc;
                state.registers = pre_insn_registers;
                state.rollback_memory_to(pre_insn_journal_mark);

                self.chunks_aborted += 1;
                self.instructions_aborted += 1;

                return SpeculativeChunkResult::Aborted {
                    instructions_executed: executed_in_chunk,
                    rollback_pc: current_pc,
                    tainted_operand,
                };
            }

            // ── Clean instruction execution (pure concrete fast-path) ──────────
            match insn {
                FastPathInsn::MovReg { dst, src } => {
                    let val = state.read_register(src);
                    state.set_register(dst, val);
                    state.pc = next_seq_pc;
                }
                FastPathInsn::SetImm { dst, val } => {
                    state.set_register(dst, val);
                    state.pc = next_seq_pc;
                }
                FastPathInsn::BinOp { op, dst, src1, src2 } => {
                    let v1 = state.read_register(src1);
                    let v2 = state.read_register(src2);
                    let res = op.eval(v1, v2);
                    state.set_register(dst, res);
                    state.pc = next_seq_pc;
                }
                FastPathInsn::BinOpImm { op, dst, src, imm } => {
                    let v1 = state.read_register(src);
                    let res = op.eval(v1, imm);
                    state.set_register(dst, res);
                    state.pc = next_seq_pc;
                }
                FastPathInsn::Load { dst, addr_reg, offset, size } => {
                    let base = state.read_register(addr_reg);
                    let addr = base.wrapping_add(offset as u64);
                    let val = state.read_memory_u64(addr, size);
                    state.set_register(dst, val);
                    state.pc = next_seq_pc;
                }
                FastPathInsn::Store { addr_reg, offset, src, size } => {
                    let base = state.read_register(addr_reg);
                    let addr = base.wrapping_add(offset as u64);
                    let val = state.read_register(src);
                    state.write_memory_u64(addr, val, size);
                    state.pc = next_seq_pc;
                }
                FastPathInsn::Jump { target } => {
                    state.pc = target;
                }
                FastPathInsn::Branch { cond_reg, taken, not_taken } => {
                    let cond = state.read_register(cond_reg);
                    state.pc = if cond != 0 { taken } else { not_taken };
                }
                FastPathInsn::Nop => {
                    state.pc = next_seq_pc;
                }
            }

            state.step_count += 1;
            executed_in_chunk += 1;
        }

        // ── Entire chunk clean: commit in bulk O(1) ───────────────────────────
        self.chunks_committed += 1;
        self.instructions_fast_pathed += executed_in_chunk as u64;

        SpeculativeChunkResult::Committed {
            instructions_executed: executed_in_chunk,
            final_pc: state.pc,
        }
    }

    /// Read-out of all operational metrics.
    #[must_use]
    pub fn metrics(&self) -> SpeculativeBatcherMetrics {
        SpeculativeBatcherMetrics {
            chunks_attempted: self.chunks_attempted,
            chunks_committed: self.chunks_committed,
            chunks_aborted: self.chunks_aborted,
            instructions_fast_pathed: self.instructions_fast_pathed,
            speedup_ratio: self.speedup_ratio(),
        }
    }

    /// Number of chunks attempted.
    #[must_use]
    pub fn chunks_attempted(&self) -> u64 {
        self.chunks_attempted
    }

    /// Number of chunks committed in bulk.
    #[must_use]
    pub fn chunks_committed(&self) -> u64 {
        self.chunks_committed
    }

    /// Number of chunks aborted mid-stream.
    #[must_use]
    pub fn chunks_aborted(&self) -> u64 {
        self.chunks_aborted
    }

    /// Number of instructions executed via fast path.
    #[must_use]
    pub fn instructions_fast_pathed(&self) -> u64 {
        self.instructions_fast_pathed
    }

    /// Estimated speedup ratio over pure fine-grained concolic shadow evaluation.
    ///
    /// Fast-path instructions execute at concrete speed (cost 1.0), whereas
    /// shadow evaluation carries an estimated 5.0x overhead for expression
    /// building and arena interning. Speculatively wasted work from aborted chunks
    /// is penalized.
    #[must_use]
    pub fn speedup_ratio(&self) -> f64 {
        let total = self.instructions_fast_pathed + self.instructions_aborted;
        if total == 0 {
            return 1.0;
        }
        const SHADOW_OVERHEAD: f64 = 5.0;
        let baseline_cost = (total as f64) * SHADOW_OVERHEAD;
        let actual_cost = (self.instructions_fast_pathed as f64) * 1.0
            + (self.instructions_aborted as f64) * (1.0 + SHADOW_OVERHEAD);
        baseline_cost / actual_cost
    }
}

// ── Unit Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Test 1: Clean chunk committed in bulk.
    ///
    /// A chunk of 5 clean instructions executes in bulk, updating PC and concrete
    /// state in O(1) without intermediate shadow expressions.
    #[test]
    fn test_clean_chunk_committed_in_bulk() {
        let mut state = SpeculativeConcolicState::new(0x1000);
        state.set_register(1, 10);
        state.set_register(2, 20);

        // Sequence of 5 clean instructions:
        // 0x1000: r1 = 42
        // 0x1004: r2 = r1 + 8 (50)
        // 0x1008: [0x2000] = r1 (42)
        // 0x100C: r3 = [0x2000] (42)
        // 0x1010: r4 = r1 * r3 (42 * 42 = 1764)
        state.add_instruction(0x1000, FastPathInsn::SetImm { dst: 1, val: 42 }, 4);
        state.add_instruction(
            0x1004,
            FastPathInsn::BinOpImm {
                op: FastPathOp::Add,
                dst: 2,
                src: 1,
                imm: 8,
            },
            4,
        );
        state.set_register(10, 0x2000); // pointer reg
        state.add_instruction(
            0x1008,
            FastPathInsn::Store {
                addr_reg: 10,
                offset: 0,
                src: 1,
                size: 4,
            },
            4,
        );
        state.add_instruction(
            0x100C,
            FastPathInsn::Load {
                dst: 3,
                addr_reg: 10,
                offset: 0,
                size: 4,
            },
            4,
        );
        state.add_instruction(
            0x1010,
            FastPathInsn::BinOp {
                op: FastPathOp::Mul,
                dst: 4,
                src1: 1,
                src2: 3,
            },
            4,
        );

        let mut batcher = SpeculativeConcolicBatcher::new();
        let result = batcher.step_speculative_chunk(&mut state, 5);

        assert_eq!(
            result,
            SpeculativeChunkResult::Committed {
                instructions_executed: 5,
                final_pc: 0x1014,
            }
        );
        assert_eq!(state.pc, 0x1014, "PC advanced past the full chunk");
        assert_eq!(state.read_register(1), 42, "r1 committed");
        assert_eq!(state.read_register(2), 50, "r2 committed");
        assert_eq!(state.read_register(3), 42, "r3 loaded from memory committed");
        assert_eq!(state.read_register(4), 1764, "r4 multiplication committed");
        assert_eq!(state.read_memory_u64(0x2000, 4), 42, "memory store committed");
        assert_eq!(state.step_count, 5);

        // Verify metrics
        let m = batcher.metrics();
        assert_eq!(m.chunks_attempted, 1);
        assert_eq!(m.chunks_committed, 1);
        assert_eq!(m.chunks_aborted, 0);
        assert_eq!(m.instructions_fast_pathed, 5);
        assert!(m.speedup_ratio > 1.0, "speedup achieved on clean batch");
    }

    /// Test 2: Tainted access mid-chunk triggering exact rollback.
    ///
    /// Instruction 0 and 1 are clean. Instruction 2 touches tainted register r4.
    /// State must roll back exactly to instruction 2 (PC=0x1008), leaving
    /// instructions 0 and 1 preserved, and instruction 2 uncommitted.
    #[test]
    fn test_tainted_access_mid_chunk_triggering_exact_rollback() {
        let mut state = SpeculativeConcolicState::new(0x1000);
        state.set_register(1, 5);
        state.set_register(2, 10);
        state.set_register(3, 0);
        state.set_register(4, 999);
        state.mark_register_tainted(4); // r4 carries symbolic taint!

        // Instructions:
        // 0x1000: r1 = 100
        // 0x1004: r2 = r1 + 20 (120)
        // 0x1008: r3 = r2 + r4 (TOUCHES TAINTED r4!)
        // 0x100C: r1 = 999
        state.add_instruction(0x1000, FastPathInsn::SetImm { dst: 1, val: 100 }, 4);
        state.add_instruction(
            0x1004,
            FastPathInsn::BinOpImm {
                op: FastPathOp::Add,
                dst: 2,
                src: 1,
                imm: 20,
            },
            4,
        );
        state.add_instruction(
            0x1008,
            FastPathInsn::BinOp {
                op: FastPathOp::Add,
                dst: 3,
                src1: 2,
                src2: 4,
            },
            4,
        );
        state.add_instruction(0x100C, FastPathInsn::SetImm { dst: 1, val: 999 }, 4);

        let mut batcher = SpeculativeConcolicBatcher::new();
        let result = batcher.step_speculative_chunk(&mut state, 4);

        // Abort must report exact instruction 0x1008
        assert_eq!(
            result,
            SpeculativeChunkResult::Aborted {
                instructions_executed: 2,
                rollback_pc: 0x1008,
                tainted_operand: TaintedOperand::Register(4),
            }
        );

        // Exact rollback verification
        assert_eq!(state.pc, 0x1008, "PC rolled back to exact tainted instruction");
        assert_eq!(state.read_register(1), 100, "Insn 0 effect preserved");
        assert_eq!(state.read_register(2), 120, "Insn 1 effect preserved");
        assert_eq!(state.read_register(3), 0, "Insn 2 uncommitted / rolled back");
        assert_eq!(state.step_count, 2, "Only 2 clean steps preserved");

        // Verify metrics
        let m = batcher.metrics();
        assert_eq!(m.chunks_attempted, 1);
        assert_eq!(m.chunks_committed, 0);
        assert_eq!(m.chunks_aborted, 1);
        assert_eq!(m.instructions_fast_pathed, 0);

        // Hand control to fine-grained shadow evaluator for 0x1008
        let stepped = state.step_concolic_fine_grained().expect("fine-grained step succeeds");
        assert!(stepped);
        assert_eq!(state.pc, 0x100C, "Fine-grained step advanced past tainted insn");
        assert_eq!(state.read_register(3), 120 + 999, "r3 evaluated");
        assert!(state.is_register_tainted(3), "r3 is now marked tainted due to r4");
    }

    /// Test 3: Tainted memory load mid-chunk triggering exact rollback.
    ///
    /// Instruction 0 stores clean value. Instruction 1 loads from tainted memory.
    /// Must roll back to instruction 1 (PC=0x1004).
    #[test]
    fn test_tainted_memory_mid_chunk_triggering_exact_rollback() {
        let mut state = SpeculativeConcolicState::new(0x1000);
        state.set_register(1, 0x5000);
        state.set_register(2, 0x6000);
        state.mark_memory_tainted(0x6000, 4); // memory at 0x6000 is tainted

        // 0x1000: [0x5000] = 77
        // 0x1004: r3 = [0x6000] (TAINTED MEMORY LOAD!)
        state.set_register(5, 77);
        state.add_instruction(
            0x1000,
            FastPathInsn::Store {
                addr_reg: 1,
                offset: 0,
                src: 5,
                size: 4,
            },
            4,
        );
        state.add_instruction(
            0x1004,
            FastPathInsn::Load {
                dst: 3,
                addr_reg: 2,
                offset: 0,
                size: 4,
            },
            4,
        );

        let mut batcher = SpeculativeConcolicBatcher::new();
        let result = batcher.step_speculative_chunk(&mut state, 2);

        assert_eq!(
            result,
            SpeculativeChunkResult::Aborted {
                instructions_executed: 1,
                rollback_pc: 0x1004,
                tainted_operand: TaintedOperand::MemoryAddress {
                    address: 0x6000,
                    size: 4,
                },
            }
        );
        assert_eq!(state.pc, 0x1004);
        assert_eq!(state.read_memory_u64(0x5000, 4), 77, "Insn 0 memory write preserved");
    }

    /// Test 4: State consistency between bulk commit and step-by-step concolic execution.
    ///
    /// Running K clean instructions via batch commit must produce the exact same
    /// architectural state (registers, memory, PC, step count) as running them
    /// step-by-step through the fine-grained concolic engine.
    #[test]
    fn test_state_consistency_between_bulk_commit_and_step_by_step_concolic() {
        fn build_program(entry: u64) -> SpeculativeConcolicState {
            let mut s = SpeculativeConcolicState::new(entry);
            s.set_register(1, 100);
            s.set_register(2, 200);
            s.set_register(10, 0x4000); // base pointer

            // 8 clean instructions mixing arithmetic, stores, loads, branches
            s.add_instruction(0x2000, FastPathInsn::BinOpImm { op: FastPathOp::Add, dst: 1, src: 1, imm: 50 }, 4); // r1 = 150
            s.add_instruction(0x2004, FastPathInsn::BinOp { op: FastPathOp::Sub, dst: 3, src1: 2, src2: 1 }, 4); // r3 = 200 - 150 = 50
            s.add_instruction(0x2008, FastPathInsn::Store { addr_reg: 10, offset: 0, src: 3, size: 4 }, 4); // [0x4000] = 50
            s.add_instruction(0x200C, FastPathInsn::Store { addr_reg: 10, offset: 8, src: 1, size: 4 }, 4); // [0x4008] = 150
            s.add_instruction(0x2010, FastPathInsn::Load { dst: 4, addr_reg: 10, offset: 0, size: 4 }, 4); // r4 = 50
            s.add_instruction(0x2014, FastPathInsn::Load { dst: 5, addr_reg: 10, offset: 8, size: 4 }, 4); // r5 = 150
            s.add_instruction(0x2018, FastPathInsn::BinOp { op: FastPathOp::Mul, dst: 6, src1: 4, src2: 5 }, 4); // r6 = 50 * 150 = 7500
            s.add_instruction(0x201C, FastPathInsn::BinOpImm { op: FastPathOp::Xor, dst: 7, src: 6, imm: 0xFF }, 4); // r7 = 7500 ^ 255 = 7435
            s
        }

        // Method A: Speculative bulk commit
        let mut state_bulk = build_program(0x2000);
        let mut batcher = SpeculativeConcolicBatcher::new();
        let res = batcher.step_speculative_chunk(&mut state_bulk, 8);
        assert!(matches!(res, SpeculativeChunkResult::Committed { .. }));

        // Method B: Step-by-step concolic execution
        let mut state_step = build_program(0x2000);
        for _ in 0..8 {
            let ran = state_step.step_concolic_fine_grained().expect("step succeeds");
            assert!(ran);
        }

        // Assert exact, bit-for-bit architectural state equivalence
        assert_eq!(state_bulk.registers, state_step.registers, "Registers must match identically");
        assert_eq!(state_bulk.memory, state_step.memory, "Memory must match identically");
        assert_eq!(state_bulk.pc, state_step.pc, "PC must match identically");
        assert_eq!(state_bulk.step_count, state_step.step_count, "Step count must match identically");
    }

    /// Test 5: Metrics accumulate correctly across multiple chunks.
    #[test]
    fn test_metrics_accumulation() {
        let mut batcher = SpeculativeConcolicBatcher::new();

        // 1. First chunk: clean 3 instructions
        let mut s1 = SpeculativeConcolicState::new(0x1000);
        s1.add_instruction(0x1000, FastPathInsn::SetImm { dst: 1, val: 1 }, 4);
        s1.add_instruction(0x1004, FastPathInsn::SetImm { dst: 2, val: 2 }, 4);
        s1.add_instruction(0x1008, FastPathInsn::SetImm { dst: 3, val: 3 }, 4);
        let res1 = batcher.step_speculative_chunk(&mut s1, 3);
        assert!(matches!(res1, SpeculativeChunkResult::Committed { .. }));

        // 2. Second chunk: abort on 2nd instruction
        let mut s2 = SpeculativeConcolicState::new(0x2000);
        s2.mark_register_tainted(9);
        s2.add_instruction(0x2000, FastPathInsn::SetImm { dst: 1, val: 1 }, 4);
        s2.add_instruction(0x2004, FastPathInsn::MovReg { dst: 2, src: 9 }, 4); // tainted
        let res2 = batcher.step_speculative_chunk(&mut s2, 2);
        assert!(matches!(res2, SpeculativeChunkResult::Aborted { .. }));

        let m = batcher.metrics();
        assert_eq!(m.chunks_attempted, 2);
        assert_eq!(m.chunks_committed, 1);
        assert_eq!(m.chunks_aborted, 1);
        assert_eq!(m.instructions_fast_pathed, 3);
        assert!(m.speedup_ratio > 0.0);
    }
}
