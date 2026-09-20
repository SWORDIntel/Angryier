#![forbid(unsafe_code)]

//! End-to-end pipeline glue wiring loader, decoder, semantics, IR lowering,
//! concrete interpreter, and SimProcedure dispatch.
//!
//! This crate owns the orchestration that connects previously-isolated
//! components into a single execution pipeline:
//!
//! ```text
//! Elf64Loader → Decoder → SemanticRegistry → SemanticBlockBuilder
//!             → SealedRichSemanticBlock → BasicSemanticLowerer → IrBlock
//!             → ConcreteInterpreter → SimProcedureRegistry
//! ```
//!
//! The runtime is generic over the decoder backend so it works with both
//! native XED (behind feature gates) and synthetic decoders for testing.

use std::collections::BTreeMap;
use std::time::Duration;

use angryier_arch::{DecodedInstruction, Decoder};
use angryier_arch_intel64::{Intel64RegisterFile, register_id};
use angryier_execution::{
    ConcolicEvaluator, ConcolicImage, ConcolicSource, ConcreteInterpreter, ExecutionEngine, ExecutionMode,
    ExecutionOutcome, PathConstraint, SymbolBinding, SymbolicArena, SymbolicBranch, SymbolicEvaluator,
};
use angryier_expr::{ExprNode, ExprOp, ExprSort};
use angryier_ir::{BasicSemanticLowerer, IrBlock, IrInstruction, IrOp};
use angryier_loader::{Elf64Loader, ImageLoader, LoadedImage, Symbol};
use angryier_memory::{ByteValue, LayeredMemory, MemoryRegion, PersistentMemory};
use angryier_models::{
    SimProcedureRegistry, SimResult, SimState,
    syscall::{self, SyscallModel},
};
use angryier_scheduler::{OsWorkerPool, PoolStats};
use angryier_semantics::{
    BlockValidityKey, FloatingPointPolicy, SemanticBlockBuilder, SemanticContext, SemanticRegistry, TileRepresentation,
    VectorRepresentation,
};
use angryier_semantics_intel64::Intel64CorpusRegistry;
use angryier_solver::{CanonicalConstraint, SolverBackend, SolverOutcomeKind, SolverQuery};
use angryier_state::{
    ExecutionState, FidelityLedger, PersistentConstraintLineage, PersistentRegisters, RegisterState, StateOwnership,
};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use angryier_types::{
    Address, AnalysisDebtKind, BlockId, ConstraintCanonicalizationVersion, ConstraintId, ContentIdentitySchemaVersion,
    ExprId, FidelityProfile, ImageId, SemanticFingerprintSchemaVersion, SemanticVersion, SolverQueryId, StateId,
    TargetProfileId,
};

#[cfg(feature = "xed")]
pub mod form_map;

/// Default stack size in bytes (64 KiB).
const STACK_SIZE: u64 = 0x1_0000;

/// Default stack base address (grows down from here).
const STACK_BASE: Address = 0x7fff_0000_0000;
/// Default heap base when the image has no segments.
const HEAP_BASE: u64 = 0x5000_0000;
/// Size of the mapped heap region managed by `brk`.
const HEAP_SIZE: u64 = 0x40_0000;

/// Maximum x86-64 instruction length in bytes.
const MAX_INSN_LEN: usize = 15;

/// Maximum number of executed block addresses retained for branch solving.
const MAX_TRACE: usize = 4096;

/// Form id reserved for instructions executed by the environment model rather
/// than the semantic corpus (`syscall`). No corpus form uses this id.
pub const SYSCALL_FORM_ID: u32 = 0xFFFF_0100;
/// Reserved form id for `cpuid`, which is modeled as a direct register
/// assignment rather than straight-line corpus semantics.
pub const CPUID_FORM_ID: u32 = 0xFFFF_0101;

/// Errors produced by the runtime pipeline.
#[derive(Debug)]
pub enum RuntimeError {
    /// Loader failed to parse the image.
    Loader(angryier_loader::LoaderError),
    /// Decoder failed to decode instruction bytes.
    Decode(String),
    /// No semantic provider matched the decoded instruction.
    UnsupportedForm(u32),
    /// Semantic provider failed to emit a block.
    Semantic(String),
    /// IR lowering failed.
    Lowering(String),
    /// Concrete interpreter failed.
    Execution(String),
    /// Memory operation failed.
    Memory(String),
    /// Register operation failed.
    Register(String),
    /// SimProcedure dispatch failed.
    SimProcedure(String),
    /// Symbolic evaluation failed.
    Symbolic(String),
    /// Solver query failed.
    Solver(String),
    /// Execution exceeded the step budget.
    StepLimitExceeded,
    /// Forking is not supported in concrete mode.
    ForkInConcreteMode,
    /// No executable segment was found in the loaded image.
    NoExecutableSegment,
    /// The execution trace references a block that was never cached.
    NoCachedBlock(Address),
    /// The execution trace contains no conditional branch.
    NoBranchInTrace,
    /// The environment model does not implement this syscall number.
    UnsupportedSyscall(u64),
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Loader(e) => write!(f, "loader error: {e:?}"),
            Self::Decode(e) => write!(f, "decode error: {e}"),
            Self::UnsupportedForm(form) => write!(f, "no semantic provider for form {form:#x}"),
            Self::Semantic(e) => write!(f, "semantic error: {e}"),
            Self::Lowering(e) => write!(f, "lowering error: {e}"),
            Self::Execution(e) => write!(f, "execution error: {e}"),
            Self::Memory(e) => write!(f, "memory error: {e}"),
            Self::Register(e) => write!(f, "register error: {e}"),
            Self::SimProcedure(e) => write!(f, "simproc error: {e}"),
            Self::Symbolic(e) => write!(f, "symbolic error: {e}"),
            Self::Solver(e) => write!(f, "solver error: {e}"),
            Self::StepLimitExceeded => write!(f, "step limit exceeded"),
            Self::ForkInConcreteMode => write!(f, "fork encountered in concrete mode"),
            Self::NoExecutableSegment => write!(f, "no executable segment in image"),
            Self::NoCachedBlock(address) => write!(f, "no cached block for address {address:#x}"),
            Self::NoBranchInTrace => write!(f, "execution trace contains no conditional branch"),
            Self::UnsupportedSyscall(number) => write!(f, "unsupported syscall number {number}"),
        }
    }
}

impl std::error::Error for RuntimeError {}

/// Outcome of a single execution step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StepOutcome {
    /// One instruction was decoded, lowered, and executed.
    Stepped {
        pc: Address,
        next_pc: Address,
        length: u8,
        form_id: u32,
    },
    /// A SimProcedure was dispatched at this address.
    SimProcedure { address: Address, name: String },
    /// A modeled syscall was executed.
    Syscall { pc: Address, number: u64 },
    /// Execution terminated (return instruction or exit).
    Terminated { pc: Address },
    /// A trap was raised.
    Trap { pc: Address, vector: u32 },
}

/// Summary of a completed run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunSummary {
    pub steps: u64,
    pub final_pc: Address,
    pub simproc_dispatches: u64,
    pub terminated: bool,
}

/// Direction of a conditional branch to solve for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BranchDirection {
    /// Ask for an input that takes the branch.
    Taken,
    /// Ask for an input that falls through.
    NotTaken,
}

/// A solved input register value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterAssignment {
    pub register: u32,
    pub width: u16,
    pub value: u64,
}

/// Result of solving a conditional branch over the executed trace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchSolution {
    /// Solver outcome for the requested direction.
    pub outcome: SolverOutcomeKind,
    /// The branch that was solved.
    pub branch: SymbolicBranch,
    /// Input register values that satisfy the requested direction (empty for
    /// `Unsat`/`Unknown`/`BackendError`).
    pub assignments: Vec<RegisterAssignment>,
    /// Entry-state symbols the branch condition depends on.
    pub symbols: Vec<SymbolBinding>,
    /// Solver wall time as reported by the backend.
    pub solver_elapsed: Duration,
}

impl BranchSolution {
    /// Returns `true` when a satisfying input was found.
    pub fn is_sat(&self) -> bool {
        self.outcome == SolverOutcomeKind::Sat
    }
}

/// A loaded process with execution state.
///
/// `Clone` shares the persistent register/memory structures (copy-on-write),
/// so forking a state at a branch is cheap — used by the parallel explorers.
#[derive(Clone)]
pub struct Process {
    pub image_id: ImageId,
    pub target_profile: TargetProfileId,
    pub entry: Address,
    pub state: ExecutionState<PersistentRegisters, PersistentMemory>,
    /// Initial state captured at load time, used to restart with new inputs.
    pub entry_state: ExecutionState<PersistentRegisters, PersistentMemory>,
    pub block_cache: BTreeMap<Address, IrBlock>,
    pub simproc_hooks: BTreeMap<Address, String>,
    /// Static symbol table of the loaded image (empty when absent).
    pub symbols: Vec<Symbol>,
    /// Addresses of executed blocks, in execution order (bounded by
    /// [`MAX_TRACE`]); used to build symbolic traces for branch solving.
    pub trace: Vec<Address>,
    /// Observable effects of modeled syscalls (captured output, exit code).
    pub syscalls: SyscallModel,
    /// Current program break for `brk` (initialized at the image end).
    pub program_break: u64,
    /// End of the mapped heap region; `brk` requests beyond it fail.
    pub heap_end: u64,
    pub next_block_id: u64,
    pub step_count: u64,
    pub simproc_dispatches: u64,
    pub terminated: bool,
}

impl Process {
    /// Registers a SimProcedure hook at a specific address.
    pub fn hook_simproc(&mut self, address: Address, name: &str) {
        self.simproc_hooks.insert(address, name.to_string());
    }

    /// Looks up a symbol by name in the loaded image.
    pub fn symbol(&self, name: &str) -> Option<&Symbol> {
        self.symbols.iter().find(|symbol| symbol.name == name)
    }

    /// Applies solved register assignments as a new input state.
    pub fn apply_inputs(&mut self, assignments: &[RegisterAssignment]) -> Result<(), RuntimeError> {
        for assignment in assignments {
            self.write_register(assignment.register, assignment.value)?;
        }
        Ok(())
    }

    /// Restarts execution from the entry state captured at load time.
    ///
    /// The lowered-block cache and SimProcedure hooks are preserved; captured
    /// syscall effects are cleared.
    pub fn reset_to_entry(&mut self) {
        self.state = self.entry_state.clone();
        self.trace.clear();
        self.syscalls.reset();
        self.step_count = 0;
        self.simproc_dispatches = 0;
        self.terminated = false;
    }

    /// Reads the current program counter (RIP).
    pub fn pc(&self) -> Result<Address, RuntimeError> {
        let bytes = self
            .state
            .registers
            .read(register_id::RIP.0)
            .map_err(|e| RuntimeError::Register(format!("{e:?}")))?;
        let mut buf = [0u8; 8];
        let len = bytes.len().min(8);
        buf[..len].copy_from_slice(&bytes[..len]);
        Ok(u64::from_le_bytes(buf))
    }

    /// Writes the program counter (RIP).
    fn write_pc(&mut self, pc: Address) -> Result<(), RuntimeError> {
        self.state.registers = self
            .state
            .registers
            .write(register_id::RIP.0, &pc.to_le_bytes())
            .map_err(|e| RuntimeError::Register(format!("{e:?}")))?;
        Ok(())
    }

    /// Reads a register as u64.
    pub fn read_register(&self, register: u32) -> Result<u64, RuntimeError> {
        let bytes = self
            .state
            .registers
            .read(register)
            .map_err(|e| RuntimeError::Register(format!("{e:?}")))?;
        let mut buf = [0u8; 8];
        let len = bytes.len().min(8);
        buf[..len].copy_from_slice(&bytes[..len]);
        Ok(u64::from_le_bytes(buf))
    }

    /// Writes a 64-bit value into an architectural register.
    pub fn write_register(&mut self, register: u32, value: u64) -> Result<(), RuntimeError> {
        self.state.registers = self
            .state
            .registers
            .write(register, &value.to_le_bytes())
            .map_err(|e| RuntimeError::Register(format!("{e:?}")))?;
        Ok(())
    }
}

/// The end-to-end execution pipeline, generic over the decoder backend.
pub struct Runtime<D: Decoder> {
    pub decoder: D,
    pub registry: Intel64CorpusRegistry,
    pub lowerer: BasicSemanticLowerer,
    pub interpreter: ConcreteInterpreter<PersistentRegisters, PersistentMemory>,
    pub simprocs: SimProcedureRegistry,
    pub semantic_version: SemanticVersion,
    pub target_profile: TargetProfileId,
    pub context: SemanticContext,
}

impl<D: Decoder> Runtime<D> {
    /// Creates a new runtime with the given decoder, semantic version, and target profile.
    pub fn new(decoder: D, semantic_version: SemanticVersion, target_profile: TargetProfileId) -> Self {
        Self {
            decoder,
            registry: Intel64CorpusRegistry::new(semantic_version),
            lowerer: BasicSemanticLowerer,
            interpreter: ConcreteInterpreter::new(),
            simprocs: SimProcedureRegistry::with_stubs(),
            semantic_version,
            target_profile,
            context: SemanticContext {
                semantic_version,
                target_profile,
                fidelity: FidelityProfile::Prove,
                vector_representation: VectorRepresentation::HybridLazy,
                tile_representation: TileRepresentation::LazyChunked,
                floating_point_policy: FloatingPointPolicy::SmtFpPreferred,
            },
        }
    }

    /// Writes the initial process stack image (argc/argv/envp/auxv) below the
    /// top of the stack region and returns the resulting stack pointer.
    ///
    /// The layout mirrors what the Linux kernel builds for a real exec: a
    /// small argv string and `AT_RANDOM` data above an argv/envp/auxv slot
    /// array, with `argc` at the new stack pointer.
    fn initial_stack_pointer(&self, image: &LoadedImage, memory: &mut PersistentMemory) -> Result<u64, RuntimeError> {
        const AT_NULL: u64 = 0;
        const AT_PHDR: u64 = 3;
        const AT_PHENT: u64 = 4;
        const AT_PHNUM: u64 = 5;
        const AT_PAGESZ: u64 = 6;
        const AT_ENTRY: u64 = 9;
        const AT_UID: u64 = 11;
        const AT_EUID: u64 = 12;
        const AT_GID: u64 = 13;
        const AT_EGID: u64 = 14;
        const AT_HWCAP: u64 = 16;
        const AT_CLKTCK: u64 = 17;
        const AT_SECURE: u64 = 23;
        const AT_RANDOM: u64 = 25;

        let mut cursor = STACK_BASE - 16;
        let argv0: &[u8] = b"angryier\0";
        cursor -= argv0.len() as u64;
        let argv0_addr = cursor;
        cursor -= 16; // AT_RANDOM data
        let random_addr = cursor;
        cursor &= !0xF;

        let mut auxv: Vec<(u64, u64)> = vec![(AT_PAGESZ, 4096), (AT_CLKTCK, 100), (AT_HWCAP, 0)];
        if let Some(headers) = &image.program_headers {
            auxv.push((AT_PHDR, headers.address));
            auxv.push((AT_PHENT, u64::from(headers.entry_size)));
            auxv.push((AT_PHNUM, u64::from(headers.count)));
        }
        auxv.extend_from_slice(&[
            (AT_ENTRY, image.entry),
            (AT_UID, 0),
            (AT_EUID, 0),
            (AT_GID, 0),
            (AT_EGID, 0),
            (AT_SECURE, 0),
            (AT_RANDOM, random_addr),
            (AT_NULL, 0),
        ]);

        // Slot array below the cursor: argc, argv[0], argv NULL, envp NULL, auxv.
        let mut slots = vec![1u64, argv0_addr, 0, 0];
        for (key, value) in &auxv {
            slots.push(*key);
            slots.push(*value);
        }
        let rsp = cursor
            .saturating_sub((slots.len() as u64) * 8)
            .saturating_sub((slots.len() as u64) * 8 % 16)
            & !0xF;

        let span = usize::try_from(STACK_BASE - rsp).map_err(|_| RuntimeError::Memory("stack span overflow".into()))?;
        let mut bytes = vec![ByteValue::Concrete(0u8); span];
        let put = |bytes: &mut [ByteValue], address: u64, data: &[u8]| {
            let start = usize::try_from(address - rsp).map_err(|_| ())?;
            let end = start.checked_add(data.len()).ok_or(())?;
            if end > bytes.len() {
                return Err(());
            }
            for (index, byte) in data.iter().enumerate() {
                bytes[start + index] = ByteValue::Concrete(*byte);
            }
            Ok::<(), ()>(())
        };
        for (index, slot) in slots.iter().enumerate() {
            put(&mut bytes, rsp + (index as u64) * 8, &slot.to_le_bytes())
                .map_err(|_| RuntimeError::Memory("stack image overflow".into()))?;
        }
        put(&mut bytes, argv0_addr, argv0).map_err(|_| RuntimeError::Memory("stack image overflow".into()))?;
        put(&mut bytes, random_addr, &[0xA5; 16]).map_err(|_| RuntimeError::Memory("stack image overflow".into()))?;

        *memory = memory
            .write(rsp, &bytes)
            .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
        Ok(rsp)
    }

    /// Executes a `rep`-prefixed string instruction directly against the
    /// process state.
    ///
    /// String instructions encode an internal loop, so they cannot be
    /// straight-line corpus semantics. Concrete and symbolic bytes propagate
    /// through `rep movs` unchanged; `rep stos` writes concrete bytes.
    #[cfg(feature = "xed")]
    fn execute_string_instruction(
        &self,
        process: &mut Process,
        pc: Address,
        decoded: &DecodedInstruction,
    ) -> Result<Option<StepOutcome>, RuntimeError> {
        use crate::form_map::{
            LODSB_FORM_ID, LODSD_FORM_ID, LODSQ_FORM_ID, LODSW_FORM_ID, MOVSB_FORM_ID, MOVSD_FORM_ID, MOVSQ_FORM_ID,
            MOVSW_FORM_ID, REP_MOVSB_FORM_ID, REP_MOVSD_FORM_ID, REP_MOVSQ_FORM_ID, REP_MOVSW_FORM_ID,
            REP_STOSB_FORM_ID, REP_STOSD_FORM_ID, REP_STOSQ_FORM_ID, REP_STOSW_FORM_ID, STOSB_FORM_ID, STOSD_FORM_ID,
            STOSQ_FORM_ID, STOSW_FORM_ID,
        };

        // The REP_/plain iclasses encode whether the prefix is present, so the
        // sentinel determines the count loop.
        // LODSB family: load [RSI] into AL/AX/EAX/RAX, advance RSI.
        let lod_size = match decoded.form_id {
            LODSB_FORM_ID => 1usize,
            LODSW_FORM_ID => 2,
            LODSD_FORM_ID => 4,
            LODSQ_FORM_ID => 8,
            _ => 0,
        };
        if lod_size > 0 {
            let rsi = process.read_register(register_id::GPR_BASE + 6)?;
            let data = process
                .state
                .memory
                .read(rsi, lod_size)
                .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
            let mut value = 0u64;
            for (i, byte) in data.iter().enumerate() {
                let b = match byte {
                    ByteValue::Concrete(b) => *b,
                    ByteValue::Symbolic(_) => 0,
                };
                value |= u64::from(b) << (i * 8);
            }
            let rax = process.read_register(register_id::GPR_BASE)?;
            // LODSB replaces AL, LODSW replaces AX, LODSD zero-extends into
            // RAX like every 32-bit register write, LODSQ writes all of RAX.
            let preserved = match lod_size {
                8 => 0,
                4 => 0,
                2 => rax & !0xFFFF,
                _ => rax & !0xFF,
            };
            process.write_register(register_id::GPR_BASE, preserved | value)?;
            process.write_register(register_id::GPR_BASE + 6, rsi.wrapping_add(lod_size as u64))?;
            let next_pc = pc.wrapping_add(u64::from(decoded.length));
            process.write_pc(next_pc)?;
            process.step_count += 1;
            return Ok(Some(StepOutcome::Stepped {
                pc,
                form_id: decoded.form_id,
                next_pc,
                length: decoded.length,
            }));
        }

        let (is_move, size, rep) = match decoded.form_id {
            STOSB_FORM_ID | REP_STOSB_FORM_ID => (false, 1usize, decoded.form_id == REP_STOSB_FORM_ID),
            STOSW_FORM_ID | REP_STOSW_FORM_ID => (false, 2, decoded.form_id == REP_STOSW_FORM_ID),
            STOSD_FORM_ID | REP_STOSD_FORM_ID => (false, 4, decoded.form_id == REP_STOSD_FORM_ID),
            STOSQ_FORM_ID | REP_STOSQ_FORM_ID => (false, 8, decoded.form_id == REP_STOSQ_FORM_ID),
            MOVSB_FORM_ID | REP_MOVSB_FORM_ID => (true, 1, decoded.form_id == REP_MOVSB_FORM_ID),
            MOVSW_FORM_ID | REP_MOVSW_FORM_ID => (true, 2, decoded.form_id == REP_MOVSW_FORM_ID),
            MOVSD_FORM_ID | REP_MOVSD_FORM_ID => (true, 4, decoded.form_id == REP_MOVSD_FORM_ID),
            MOVSQ_FORM_ID | REP_MOVSQ_FORM_ID => (true, 8, decoded.form_id == REP_MOVSQ_FORM_ID),
            _ => return Ok(None),
        };

        let mut rcx = process.read_register(register_id::GPR_BASE + 1)?; // RCX
        let mut rsi = process.read_register(register_id::GPR_BASE + 6)?; // RSI
        let mut rdi = process.read_register(register_id::GPR_BASE + 7)?; // RDI
        let rax = process.read_register(register_id::GPR_BASE)?; // RAX
        let store_bytes = rax.to_le_bytes();

        let mut count = if rep { rcx } else { 1 };
        while count > 0 {
            let data: Vec<ByteValue> = if is_move {
                process
                    .state
                    .memory
                    .read(rsi, size)
                    .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?
                    .to_vec()
            } else {
                store_bytes[..size].iter().map(|b| ByteValue::Concrete(*b)).collect()
            };
            process.state.memory = process
                .state
                .memory
                .write(rdi, &data)
                .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
            rdi = rdi.wrapping_add(size as u64);
            if is_move {
                rsi = rsi.wrapping_add(size as u64);
            }
            count -= 1;
        }
        process.write_register(register_id::GPR_BASE + 7, rdi)?;
        if is_move {
            process.write_register(register_id::GPR_BASE + 6, rsi)?;
        }
        if rep {
            rcx = 0;
            process.write_register(register_id::GPR_BASE + 1, rcx)?;
        }
        let next_pc = pc.wrapping_add(u64::from(decoded.length));
        process.write_pc(next_pc)?;
        process.step_count += 1;
        Ok(Some(StepOutcome::Stepped {
            pc,
            form_id: decoded.form_id,
            next_pc,
            length: decoded.length,
        }))
    }

    /// Loads an ELF64 image from raw bytes and creates a Process.
    pub fn load_elf(&self, bytes: &[u8]) -> Result<Process, RuntimeError> {
        let loader = Elf64Loader::new();
        let image = loader.load(bytes).map_err(RuntimeError::Loader)?;
        self.load_image(image)
    }

    /// Creates a Process from an already-loaded image.
    pub fn load_image(&self, image: LoadedImage) -> Result<Process, RuntimeError> {
        if image.target_profile != self.target_profile {
            return Err(RuntimeError::Loader(angryier_loader::LoaderError::InvalidFormat));
        }

        // Convert loader segments to memory regions.
        let mut regions: Vec<MemoryRegion> = Vec::with_capacity(image.segments.len() + 1);
        for seg in &image.segments {
            let size = u64::try_from(seg.bytes.len())
                .map_err(|_| RuntimeError::Loader(angryier_loader::LoaderError::InvalidFormat))?;
            regions.push(MemoryRegion {
                object: angryier_types::ObjectId(0),
                base: seg.address,
                size,
                readable: seg.readable,
                writable: seg.writable,
                executable: seg.executable,
            });
        }

        // Add a heap region immediately after the highest mapped image
        // segment; `brk` manages the program break inside it.
        let brk_base = image
            .segments
            .iter()
            .map(|seg| seg.address.wrapping_add(u64::try_from(seg.bytes.len()).unwrap_or(0)))
            .max()
            .map(|end| end.wrapping_add(0xFFF) & !0xFFF)
            .unwrap_or(HEAP_BASE);
        regions.push(MemoryRegion {
            object: angryier_types::ObjectId(2),
            base: brk_base,
            size: HEAP_SIZE,
            readable: true,
            writable: true,
            executable: false,
        });

        // Add a stack region.
        regions.push(MemoryRegion {
            object: angryier_types::ObjectId(1),
            base: STACK_BASE - STACK_SIZE,
            size: STACK_SIZE,
            readable: true,
            writable: true,
            executable: false,
        });

        let mut memory = PersistentMemory::new(regions).map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;

        // Load segment bytes into memory.
        for seg in &image.segments {
            if seg.bytes.is_empty() {
                continue;
            }
            memory = memory
                .load_concrete(seg.address, &seg.bytes)
                .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
        }

        // Lay out the initial process stack the way the Linux kernel does for
        // a real exec: argc/argv/envp/auxv. libc `_start` code reads argc from
        // `[rsp]`, so the stack pointer must land on a populated image rather
        // than the top of the mapped region.
        let stack_pointer = self.initial_stack_pointer(&image, &mut memory)?;

        // Initialize registers with Intel64 canonical widths.
        let reg_file = Intel64RegisterFile::canonical();
        let widths: Vec<(u32, usize)> = reg_file
            .architectural_registers
            .iter()
            .map(|(reg, bits)| {
                let bytes = usize::from(*bits).div_ceil(8);
                (reg.0, bytes)
            })
            .collect();
        let mut registers =
            PersistentRegisters::from_widths(widths).map_err(|e| RuntimeError::Register(format!("{e:?}")))?;

        // Set RIP to entry point.
        registers = registers
            .write(register_id::RIP.0, &image.entry.to_le_bytes())
            .map_err(|e| RuntimeError::Register(format!("{e:?}")))?;

        // Set RSP to the initial process stack image.
        registers = registers
            .write(register_id::GPR_BASE + 4, &stack_pointer.to_le_bytes()) // RSP = GPR 4
            .map_err(|e| RuntimeError::Register(format!("{e:?}")))?;

        // Initial RFLAGS: reserved bit 1 and IF set, matching a real
        // userspace entry state (0x202).
        registers = registers
            .write(register_id::RFLAGS.0, &0x202u64.to_le_bytes())
            .map_err(|e| RuntimeError::Register(format!("{e:?}")))?;

        let state = ExecutionState {
            id: StateId(0),
            parent: None,
            target_profile: image.target_profile,
            registers,
            memory,
            constraints: PersistentConstraintLineage::new(),
            ownership: StateOwnership::default(),
            fidelity: FidelityLedger::new(FidelityProfile::Prove),
        };

        Ok(Process {
            image_id: image.id,
            target_profile: image.target_profile,
            entry: image.entry,
            entry_state: state.clone(),
            state,
            block_cache: BTreeMap::new(),
            simproc_hooks: BTreeMap::new(),
            symbols: image.symbols,
            trace: Vec::new(),
            syscalls: SyscallModel::new(),
            program_break: brk_base,
            heap_end: brk_base + HEAP_SIZE,
            next_block_id: 0,
            step_count: 0,
            simproc_dispatches: 0,
            terminated: false,
        })
    }

    /// Executes a single instruction at the current PC.
    pub fn step(&self, process: &mut Process) -> Result<StepOutcome, RuntimeError> {
        self.step_with(process, |_, _| Ok(()))
    }

    /// Executes a single instruction, invoking `observe` with the pre-execution
    /// process state and the freshly lowered block just before interpretation.
    /// The concolic path uses this hook to shadow each block with the same
    /// lowered semantics the concrete interpreter then runs.
    pub fn step_with(
        &self,
        process: &mut Process,
        mut observe: impl FnMut(&Process, &IrBlock) -> Result<(), RuntimeError>,
    ) -> Result<StepOutcome, RuntimeError> {
        if process.terminated {
            return Ok(StepOutcome::Terminated { pc: process.pc()? });
        }

        let pc = process.pc()?;

        // Check for SimProcedure hooks.
        if let Some(name) = process.simproc_hooks.get(&pc).cloned() {
            return self.dispatch_simproc(process, pc, &name);
        }

        // Read instruction bytes from memory, bounded by the containing region
        // so that instructions near the end of a segment do not fail the read.
        let available = process
            .state
            .memory
            .regions()
            .iter()
            .find(|region| pc >= region.base && pc < region.base.saturating_add(region.size))
            .map_or(MAX_INSN_LEN, |region| {
                usize::try_from(region.base.saturating_add(region.size).saturating_sub(pc)).unwrap_or(MAX_INSN_LEN)
            });
        let read_len = available.min(MAX_INSN_LEN);
        let bytes = process
            .state
            .memory
            .read(pc, read_len)
            .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
        let raw: Vec<u8> = bytes
            .iter()
            .map(|b| match b {
                ByteValue::Concrete(v) => *v,
                ByteValue::Symbolic(_) => 0,
            })
            .collect();
        if raw.is_empty() {
            return Err(RuntimeError::Decode("no bytes at PC".into()));
        }

        // Decode.
        let decoded = self
            .decoder
            .decode(pc, &raw)
            .map_err(|e| RuntimeError::Decode(format!("{e:?}")))?;

        // Modeled syscalls are environment interactions, not corpus semantics.
        if decoded.form_id == SYSCALL_FORM_ID {
            return self.dispatch_syscall(process, pc, decoded.length);
        }

        // `cpuid` queries the environment's processor model; it is executed
        // directly like a syscall since it has no corpus semantic provider.
        if decoded.form_id == CPUID_FORM_ID {
            return self.execute_cpuid(process, pc, decoded.length);
        }

        // String instructions encode an internal loop, so they run directly
        // against the process state rather than through straight-line corpus
        // semantics.
        #[cfg(feature = "xed")]
        if let Some(outcome) = self.execute_string_instruction(process, pc, &decoded)? {
            return Ok(outcome);
        }

        let (ir_block, decoded) = self.lower_at(process, pc, &decoded)?;

        // Observers see the lowered block against the pre-execution state.
        observe(process, &ir_block)?;

        // Execute.
        let (new_state, outcome) = self
            .interpreter
            .execute_block(&process.state, &ir_block, ExecutionMode::Concrete)
            .map_err(|e| RuntimeError::Execution(format!("{e:?}")))?;

        process.state = new_state;
        process.step_count += 1;

        let length = decoded.length;
        let form_id = decoded.form_id;

        // Cache the block.
        process.block_cache.insert(pc, ir_block.clone());

        match outcome {
            ExecutionOutcome::Continue { next_pc, .. } => {
                process.write_pc(next_pc)?;
                if process.trace.len() >= MAX_TRACE {
                    process.trace.remove(0);
                }
                process.trace.push(pc);
                Ok(StepOutcome::Stepped {
                    pc,
                    next_pc,
                    length,
                    form_id,
                })
            }
            ExecutionOutcome::Fork { .. } => Err(RuntimeError::ForkInConcreteMode),
            ExecutionOutcome::Terminated { .. } => {
                process.terminated = true;
                Ok(StepOutcome::Terminated { pc })
            }
            ExecutionOutcome::Trap { vector, .. } => {
                process.terminated = true;
                Ok(StepOutcome::Trap { pc, vector })
            }
        }
    }

    /// Decodes `decoded` (at `pc`) through the semantic registry, seals the
    /// emitted block, and lowers it to AngryIR — the shared front half of
    /// [`Runtime::step_with`], reused by the symbolic session so both engines
    /// consume identical blocks.
    pub fn lower_at(
        &self,
        process: &mut Process,
        pc: Address,
        decoded: &DecodedInstruction,
    ) -> Result<(IrBlock, DecodedInstruction), RuntimeError> {
        // Resolve semantic provider.
        self.registry
            .resolve(decoded, self.semantic_version)
            .map_err(|e| RuntimeError::Semantic(format!("{e:?}")))?;

        // Look the provider up by its positional form index: resolution is
        // positional, and a duplicated hand-picked rule offset would silently
        // route the form to a different provider if we searched by rule_id.
        let provider = self
            .registry
            .provider_for_form(decoded.form_id)
            .ok_or(RuntimeError::UnsupportedForm(decoded.form_id))?;

        // Emit semantic block.
        let mut builder = SemanticBlockBuilder::new(self.semantic_version);
        provider
            .emit(&self.context, decoded, &mut builder)
            .map_err(|e| RuntimeError::Semantic(format!("{e:?}")))?;

        // Seal the block.
        let sealed = builder
            .seal(ContentIdentitySchemaVersion(1), SemanticFingerprintSchemaVersion(1))
            .map_err(|e| RuntimeError::Semantic(format!("{e:?}")))?;

        // Build BlockValidityKey.
        let block_id = BlockId(process.next_block_id);
        process.next_block_id += 1;

        let code_versions = process
            .state
            .memory
            .code_version_guards_for_range(pc, usize::from(decoded.length))
            .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;

        let validity_key = BlockValidityKey {
            image: process.image_id,
            block: block_id,
            address: pc,
            semantic_version: self.semantic_version,
            target_profile: self.target_profile,
            code_versions,
        };

        // Lower to IR.
        let ir_block = self
            .lowerer
            .lower_with_decode(&sealed, &validity_key, decoded)
            .map_err(|e| RuntimeError::Lowering(format!("{e:?}")))?;

        process.block_cache.insert(pc, ir_block.clone());
        Ok((ir_block, decoded.clone()))
    }

    /// Runs execution for up to `max_steps` instructions.
    pub fn run(&self, process: &mut Process, max_steps: u64) -> Result<RunSummary, RuntimeError> {
        while !process.terminated && process.step_count < max_steps {
            let _ = self.step(process)?;
        }
        if !process.terminated && process.step_count >= max_steps {
            return Err(RuntimeError::StepLimitExceeded);
        }
        Ok(RunSummary {
            steps: process.step_count,
            final_pc: process.pc()?,
            simproc_dispatches: process.simproc_dispatches,
            terminated: process.terminated,
        })
    }

    /// Opens a concolic session over `process`: the concrete interpreter
    /// drives control flow while a symbolic shadow tracks input-derived
    /// expressions — the EXPLORE-mode fast path sharing the same decode,
    /// lowering, and AngryIR semantics as PROVE mode.
    pub fn concolic<'a>(&'a self, process: Process, arena: &'a SymbolicArena) -> ConcolicSession<'a, D> {
        self.concolic_with_profile(process, arena, FidelityProfile::Explore)
    }

    /// Opens a concolic session under an explicit fidelity profile.
    ///
    /// - **EXPLORE**: concolic fast path; shadow debt is recorded and reported
    ///   through [`ConcolicSession::requires_prove`].
    /// - **HUNT**: concolic fast path with maximum pruning tolerance — debt
    ///   accumulates without tripping `requires_prove` (explicitly unsound by
    ///   design); pair with the Fuzzy-SAT tier for cheap inversions.
    /// - **PROVE** is not a concolic profile: `concolic_with_profile` maps it
    ///   to EXPLORE bookkeeping so a misrouted state still records debt; use
    ///   [`Runtime::solve_branch`] for the sound path.
    pub fn concolic_with_profile<'a>(
        &'a self,
        mut process: Process,
        arena: &'a SymbolicArena,
        profile: FidelityProfile,
    ) -> ConcolicSession<'a, D> {
        let profile = if profile == FidelityProfile::Prove {
            FidelityProfile::Explore
        } else {
            profile
        };
        process.state.fidelity = FidelityLedger::new(profile);
        ConcolicSession {
            process,
            runtime: self,
            evaluator: ConcolicEvaluator::new(arena),
            arena,
            path: Vec::new(),
            hunt: profile == FidelityProfile::Hunt,
            last_branch: SymbolicBranch {
                condition: ExprId(0),
                taken: 0,
                not_taken: 0,
            },
        }
    }

    /// Symbolically evaluates the executed trace and asks the solver for an
    /// input that forces the last conditional branch in the requested
    /// direction.
    ///
    /// The trace is interpreted as a straight-line path: blocks are evaluated
    /// in execution order with a shared symbolic register file, so the branch
    /// condition is expressed in terms of the entry-state registers. Blocks
    /// containing memory accesses or operations outside the scalar integer
    /// subset are refused explicitly rather than approximated.
    pub fn solve_branch(
        &self,
        process: &Process,
        direction: BranchDirection,
        arena: &SymbolicArena,
        backend: &mut dyn SolverBackend,
        timeout: Duration,
    ) -> Result<BranchSolution, RuntimeError> {
        let mut evaluator = SymbolicEvaluator::new(arena);
        let mut branch = None;
        // Blocks that do not branch end in a fall-through jump, so evaluate
        // every block in the trace and keep the last conditional branch: that
        // is the branch that determined the current path.
        for address in &process.trace {
            let block = process
                .block_cache
                .get(address)
                .ok_or(RuntimeError::NoCachedBlock(*address))?;
            let summary = evaluator
                .eval_block(block)
                .map_err(|error| RuntimeError::Symbolic(error.to_string()))?;
            if let Some(found) = summary.branch {
                branch = Some(found);
            }
        }
        let branch = branch.ok_or(RuntimeError::NoBranchInTrace)?;

        // Predicate: condition == 1 for Taken, condition == 0 for NotTaken.
        let target_bit = match direction {
            BranchDirection::Taken => 1u8,
            BranchDirection::NotTaken => 0u8,
        };
        let bit = arena
            .intern(ExprNode {
                sort: ExprSort::BitVec(1),
                op: ExprOp::Constant,
                operands: Vec::new(),
                immediate: vec![target_bit],
            })
            .map_err(|error| RuntimeError::Symbolic(format!("{error:?}")))?;
        let predicate = arena
            .intern(ExprNode {
                sort: ExprSort::Bool,
                op: ExprOp::Eq,
                operands: vec![branch.condition, bit],
                immediate: Vec::new(),
            })
            .map_err(|error| RuntimeError::Symbolic(format!("{error:?}")))?;
        let predicate_key = arena
            .dependency_summary(predicate)
            .map(|summary| summary.key)
            .ok_or_else(|| RuntimeError::Symbolic("missing predicate dependency summary".into()))?;

        let query = SolverQuery::canonical(
            SolverQueryId(process.step_count),
            &[],
            predicate,
            predicate_key,
            process.target_profile,
            ConstraintCanonicalizationVersion(1),
            timeout,
        )
        .map_err(|error| RuntimeError::Solver(format!("{error:?}")))?;

        let result = backend.solve(&query);

        let mut assignments = Vec::new();
        for (key, bytes) in &result.model {
            let Ok(key) = u32::try_from(*key) else {
                continue;
            };
            let expression = ExprId(key);
            let Some(binding) = evaluator
                .symbols()
                .iter()
                .find(|binding| binding.expression == expression)
            else {
                continue;
            };
            let mut buffer = [0u8; 8];
            let len = bytes.len().min(8);
            buffer[..len].copy_from_slice(&bytes[..len]);
            assignments.push(RegisterAssignment {
                register: binding.register,
                width: binding.width,
                value: u64::from_le_bytes(buffer),
            });
        }

        Ok(BranchSolution {
            outcome: result.outcome,
            branch,
            assignments,
            symbols: evaluator.symbols().to_vec(),
            solver_elapsed: result.elapsed,
        })
    }

    /// Executes a modeled syscall.
    ///
    /// The environment model owns the observable effects (captured output,
    /// exit code); the runtime performs the memory reads a syscall needs.
    /// Unmodeled syscall numbers fail explicitly instead of fabricating a
    /// result.
    fn dispatch_syscall(&self, process: &mut Process, pc: Address, length: u8) -> Result<StepOutcome, RuntimeError> {
        let number = process.read_register(register_id::GPR_BASE)?;
        let arg0 = process.read_register(register_id::GPR_BASE + 7)?; // RDI
        let arg1 = process.read_register(register_id::GPR_BASE + 6)?; // RSI
        let arg2 = process.read_register(register_id::GPR_BASE + 2)?; // RDX
        let arg3 = process.read_register(register_id::GPR_BASE + 10)?; // R10
        let next_pc = pc.wrapping_add(u64::from(length));

        let outcome: Result<StepOutcome, RuntimeError> = match number {
            syscall::EXIT => {
                process.syscalls.record_exit(arg0);
                process.terminated = true;
                process.step_count += 1;
                Ok(StepOutcome::Terminated { pc })
            }
            syscall::WRITE => {
                let bytes = read_concrete_bytes(process, arg1, arg2)?;
                let written = process.syscalls.record_write(&bytes);
                process.write_register(register_id::GPR_BASE, written)?;
                process.write_pc(next_pc)?;
                process.step_count += 1;
                Ok(StepOutcome::Syscall { pc, number })
            }
            syscall::ARCH_PRCTL => {
                use angryier_models::syscall::arch_prctl_op;
                let value = match arg0 {
                    arch_prctl_op::SET_FS => {
                        process.write_register(register_id::FS_BASE.0, arg1)?;
                        0
                    }
                    arch_prctl_op::SET_GS => {
                        process.write_register(register_id::GS_BASE.0, arg1)?;
                        0
                    }
                    arch_prctl_op::GET_FS => {
                        let base = process.read_register(register_id::FS_BASE.0)?;
                        let bytes: Vec<ByteValue> =
                            base.to_le_bytes().iter().map(|b| ByteValue::Concrete(*b)).collect();
                        process.state.memory = process
                            .state
                            .memory
                            .write(arg1, &bytes)
                            .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
                        0
                    }
                    arch_prctl_op::GET_GS => {
                        let base = process.read_register(register_id::GS_BASE.0)?;
                        let bytes: Vec<ByteValue> =
                            base.to_le_bytes().iter().map(|b| ByteValue::Concrete(*b)).collect();
                        process.state.memory = process
                            .state
                            .memory
                            .write(arg1, &bytes)
                            .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
                        0
                    }
                    // Unknown arch_prctl op: report -EINVAL like Linux does.
                    _ => 0u64.wrapping_sub(22),
                };
                process.write_register(register_id::GPR_BASE, value)?;
                process.write_pc(next_pc)?;
                process.step_count += 1;
                Ok(StepOutcome::Syscall { pc, number })
            }
            syscall::BRK => {
                // Linux brk semantics: `brk(0)` returns the current break;
                // a request inside the heap region moves the break and
                // returns the new value, anything else returns the old break.
                let result = if arg0 == 0 || arg0 < process.program_break || arg0 > process.heap_end {
                    process.program_break
                } else {
                    process.program_break = arg0;
                    arg0
                };
                process.write_register(register_id::GPR_BASE, result)?;
                process.write_pc(next_pc)?;
                process.step_count += 1;
                Ok(StepOutcome::Syscall { pc, number })
            }
            syscall::PRLIMIT64 => {
                // prlimit64(pid, resource, new, old): report a plausible
                // rlimit (8 MiB soft, infinite hard) when `old` is non-null.
                if arg3 != 0 {
                    let rlim: Vec<ByteValue> = 0x80_0000u64
                        .to_le_bytes()
                        .iter()
                        .chain(u64::MAX.to_le_bytes().iter())
                        .map(|b| ByteValue::Concrete(*b))
                        .collect();
                    process.state.memory = process
                        .state
                        .memory
                        .write(arg3, &rlim)
                        .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
                }
                process.write_register(register_id::GPR_BASE, 0)?;
                process.write_pc(next_pc)?;
                process.step_count += 1;
                Ok(StepOutcome::Syscall { pc, number })
            }
            syscall::READLINKAT => {
                // readlinkat(dirfd, path, buf, bufsiz): report a fixed
                // executable path so glibc's /proc/self/exe resolution
                // produces a name; -ENOENT would abort some startup paths.
                let path = b"/angryier";
                let n = (path.len() as u64).min(arg3);
                let bytes: Vec<ByteValue> = path[..usize::try_from(n).unwrap_or(0)]
                    .iter()
                    .map(|b| ByteValue::Concrete(*b))
                    .collect();
                process.state.memory = process
                    .state
                    .memory
                    .write(arg2, &bytes)
                    .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
                process.write_register(register_id::GPR_BASE, n)?;
                process.write_pc(next_pc)?;
                process.step_count += 1;
                Ok(StepOutcome::Syscall { pc, number })
            }
            syscall::SET_TID_ADDRESS | syscall::GETTID | syscall::GETPID => {
                // Single-threaded process: report a fixed, nonzero tid/pid.
                process.write_register(register_id::GPR_BASE, 1)?;
                process.write_pc(next_pc)?;
                process.step_count += 1;
                Ok(StepOutcome::Syscall { pc, number })
            }
            syscall::SET_ROBUST_LIST | syscall::MPROTECT => {
                // No-op models: robust lists and permission changes are not
                // observable in the current single-process model.
                process.write_register(register_id::GPR_BASE, 0)?;
                process.write_pc(next_pc)?;
                process.step_count += 1;
                Ok(StepOutcome::Syscall { pc, number })
            }
            syscall::RSEQ => {
                // Report -ENOSYS: callers treat rseq as absent.
                process.write_register(register_id::GPR_BASE, 0u64.wrapping_sub(38))?;
                process.write_pc(next_pc)?;
                process.step_count += 1;
                Ok(StepOutcome::Syscall { pc, number })
            }
            syscall::GETRANDOM => {
                // Deterministic pseudo-random fill (repeatable by seed 0xa5).
                // getrandom(buf=rdi, buflen=rsi, flags=rdx).
                let mut byte = 0xa5u8;
                let data: Vec<ByteValue> = (0..arg1)
                    .map(|i| {
                        byte = byte.wrapping_mul(31).wrapping_add(i as u8);
                        ByteValue::Concrete(byte)
                    })
                    .collect();
                process.state.memory = process
                    .state
                    .memory
                    .write(arg0, &data)
                    .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
                process.write_register(register_id::GPR_BASE, arg1)?;
                process.write_pc(next_pc)?;
                process.step_count += 1;
                Ok(StepOutcome::Syscall { pc, number })
            }
            syscall::EXIT_GROUP => {
                process.syscalls.record_exit(arg0);
                process.terminated = true;
                process.step_count += 1;
                Ok(StepOutcome::Terminated { pc })
            }
            other => Err(RuntimeError::UnsupportedSyscall(other)),
        };
        outcome.map_err(|e| match e {
            // Attach syscall-argument context to memory/access faults; typed
            // errors like UnsupportedSyscall keep their variant for callers.
            RuntimeError::Memory(inner) => RuntimeError::Memory(format!(
                "syscall {number} rdi={arg0:#x} rsi={arg1:#x} rdx={arg2:#x} r10={arg3:#x}: {inner}"
            )),
            other => other,
        })
    }

    /// Executes `cpuid` by writing a conservative modern x86-64 feature model
    /// into RAX/RBX/RCX/RDX based on the leaf in EAX and subleaf in ECX.
    fn execute_cpuid(&self, process: &mut Process, pc: Address, length: u8) -> Result<StepOutcome, RuntimeError> {
        let leaf = process.read_register(register_id::GPR_BASE)? as u32; // EAX
        let subleaf = process.read_register(register_id::GPR_BASE + 1)? as u32; // ECX
        let (a, b, c, d) = cpuid_model(leaf, subleaf);
        for (reg, value) in [
            (register_id::GPR_BASE, a),     // RAX
            (register_id::GPR_BASE + 3, b), // RBX
            (register_id::GPR_BASE + 1, c), // RCX
            (register_id::GPR_BASE + 2, d), // RDX
        ] {
            process.write_register(reg, u64::from(value))?;
        }
        process.write_pc(pc.wrapping_add(u64::from(length)))?;
        process.step_count += 1;
        Ok(StepOutcome::Stepped {
            pc,
            next_pc: pc.wrapping_add(u64::from(length)),
            length,
            form_id: CPUID_FORM_ID,
        })
    }

    /// Dispatches a SimProcedure at the given address.
    fn dispatch_simproc(
        &self,
        process: &mut Process,
        address: Address,
        name: &str,
    ) -> Result<StepOutcome, RuntimeError> {
        // Bridge ExecutionState → SimState.
        let mut sim_state = SimState::new();

        // Copy GPRs (RAX=0, RCX=1, RDX=2, RBX=3, RSP=4, RBP=5, RSI=6, RDI=7).
        for index in 0u32..8 {
            let reg_id = register_id::GPR_BASE + index;
            if let Ok(val) = process.state.registers.read(reg_id) {
                let mut buf = [0u8; 8];
                let len = val.len().min(8);
                buf[..len].copy_from_slice(&val[..len]);
                sim_state.set_reg(u64::from(index), u64::from_le_bytes(buf));
            }
        }

        let result = self
            .simprocs
            .apply_by_name(name, &sim_state)
            .ok_or_else(|| RuntimeError::SimProcedure(format!("unknown procedure: {name}")))?;

        process.simproc_dispatches += 1;

        match result {
            SimResult::Return(val) => {
                // Write return value to RAX (GPR 0).
                process.state.registers = process
                    .state
                    .registers
                    .write(register_id::GPR_BASE, &val.to_le_bytes())
                    .map_err(|e| RuntimeError::Register(format!("{e:?}")))?;

                // Advance PC past the call instruction (simulate return).
                // For hooked stubs, we advance by 1 byte as a minimal convention.
                let next_pc = address.wrapping_add(1);
                process.write_pc(next_pc)?;
                Ok(StepOutcome::SimProcedure {
                    address,
                    name: name.to_string(),
                })
            }
            SimResult::Exit => {
                process.terminated = true;
                Ok(StepOutcome::SimProcedure {
                    address,
                    name: name.to_string(),
                })
            }
            SimResult::Continue(_) => {
                // For continue results, advance PC by 1.
                let next_pc = address.wrapping_add(1);
                process.write_pc(next_pc)?;
                Ok(StepOutcome::SimProcedure {
                    address,
                    name: name.to_string(),
                })
            }
        }
    }
}

/// Decoder wrapper that translates raw XED instruction classes into
/// engine-owned semantic form ids.
///
/// The native XED bridge reports XED instruction classes as `form_id`; the
/// handwritten corpus matches on Angryier form ids. Instructions without exact
/// corpus semantics are reported as [`form_map::UNMAPPED_FORM_ID`], which no
/// registered form uses, so semantic resolution fails explicitly instead of
/// matching an unrelated form.
#[cfg(feature = "xed")]
#[derive(Debug)]
pub struct XedFormTranslator<D> {
    inner: D,
}

#[cfg(feature = "xed")]
impl<D> XedFormTranslator<D> {
    /// Wraps a decoder that reports raw XED instruction classes as form ids.
    pub fn new(inner: D) -> Self {
        Self { inner }
    }
}

#[cfg(feature = "xed")]
impl<D: Decoder> Decoder for XedFormTranslator<D> {
    type Error = D::Error;

    fn decode(&self, address: Address, bytes: &[u8]) -> Result<angryier_arch::DecodedInstruction, Self::Error> {
        let mut decoded = self.inner.decode(address, bytes)?;
        decoded.form_id = form_map::map_form(&decoded).unwrap_or(form_map::UNMAPPED_FORM_ID);
        Ok(decoded)
    }
}

#[cfg(feature = "xed")]
impl Runtime<XedFormTranslator<angryier_arch_xed_ffi::XedDecoder>> {
    /// Creates a runtime backed by the native Intel XED decoder, with XED
    /// instruction classes translated into engine-owned semantic form ids.
    pub fn with_native_xed(semantic_version: SemanticVersion, target_profile: TargetProfileId) -> Self {
        let decoder = angryier_arch_xed_ffi::XedDecoder::with_profile_id(target_profile);
        Runtime::new(XedFormTranslator::new(decoder), semantic_version, target_profile)
    }
}

/// Loads an ELF64 file from disk.
pub fn load_elf_file(path: &str) -> Result<Vec<u8>, RuntimeError> {
    std::fs::read(path).map_err(|_| RuntimeError::Loader(angryier_loader::LoaderError::InvalidFormat))
}

/// Reads `len` concrete bytes from process memory for a syscall buffer.
/// A conservative CPUID model reporting a modern x86-64 baseline: SSE/SSE2
/// through AVX2 plus the features a generic 2015-era Skylake-class processor
/// exposes. Feature bits drive glibc/musl hardware-capability dispatch; the
/// model keeps them deterministic and replay-stable.
fn cpuid_model(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    match (leaf, subleaf) {
        // Leaf 0: maximum basic leaf + "GenuineIntel" vendor string.
        (0, _) => (0x16, 0x756e6547, 0x6c65746e, 0x49656e69),
        // Leaf 1: signature (Skylake 06_5E), APIC id, ECX/EDX feature bits.
        //   ECX: SSE3 SSSE3 SSE4.1 SSE4.2 MOVBE POPCNT RDRND — the model
        //   deliberately omits AVX/AVX512/XSAVE so hardware dispatch picks
        //   the 128-bit SSE code paths the concrete interpreter supports.
        //   EDX: FPU TSC MSR MTRR CMOV MMX FXSR SSE SSE2 HTT CLFSH SEP
        (1, _) => (0x506e3, 0, 0b0100_0000_1101_1000_0000_0010_0000_0001, 0x1f8bfbff),
        // Leaf 7 subleaf 0: EBX feature bits — FSGSBASE ERMS INVPCID RDSEED
        // only; BMI/AVX2/AVX512 are omitted for the same reason.
        (7, 0) => (0, 0b0000_0000_0000_0100_0000_0110_0000_0001, 0, 0),
        // Extended leaf 0x80000000: max extended leaf + vendor.
        (0x8000_0000, _) => (0x8000_0008, 0, 0, 0),
        // Extended leaf 0x80000001: NX + LM in EDX.
        (0x8000_0001, _) => (0, 0, 0, 0x2010_0000),
        // Brand string "Generic x86-64 CPU    " across leaves 0x80000002-4.
        (0x8000_0002, _) => (
            u32::from_le_bytes(*b"Gene"),
            u32::from_le_bytes(*b"ric "),
            u32::from_le_bytes(*b"x86-"),
            u32::from_le_bytes(*b"64 C"),
        ),
        (0x8000_0003, _) => (
            u32::from_le_bytes(*b"PU  "),
            u32::from_le_bytes(*b"    "),
            u32::from_le_bytes(*b"    "),
            u32::from_le_bytes(*b"    "),
        ),
        (0x8000_0004, _) => (0, 0, 0, 0),
        // Physical/virtual address width: 48-bit linear, 48-bit physical.
        (0x8000_0008, _) => (0x3030, 0, 0, 0),
        // Any other leaf: report zeros (feature absent).
        _ => (0, 0, 0, 0),
    }
}

fn read_concrete_bytes(process: &Process, address: Address, len: u64) -> Result<Vec<u8>, RuntimeError> {
    let len = usize::try_from(len).map_err(|_| RuntimeError::Memory("syscall buffer too large".into()))?;
    if len == 0 {
        return Ok(Vec::new());
    }
    let bytes = process
        .state
        .memory
        .read(address, len)
        .map_err(|error| RuntimeError::Memory(format!("{error:?}")))?;
    let mut out = Vec::with_capacity(len);
    for (offset, byte) in bytes.into_iter().enumerate() {
        match byte {
            ByteValue::Concrete(value) => out.push(value),
            ByteValue::Symbolic(_) => {
                let at = address.wrapping_add(u64::try_from(offset).unwrap_or(0));
                return Err(RuntimeError::Memory(format!(
                    "symbolic byte at {at:#x} in syscall buffer"
                )));
            }
        }
    }
    Ok(out)
}

/// Concrete-state view of a [`Process`] for the concolic shadow: registers
/// read their live values; memory reads expose concrete/symbolic bytes.
impl ConcolicImage for Process {
    fn read_register(&self, register: u32) -> Option<Vec<u8>> {
        self.state.registers.read(register).ok()
    }

    fn read_bytes(&self, address: u64, length: usize) -> Option<Vec<ByteValue>> {
        self.state.memory.read(address, length).ok()
    }
}

/// The result of solving a concolic path constraint: a concrete value for each
/// input symbol, keyed by its architectural source.
#[derive(Clone, Debug)]
pub struct ConcolicSolution {
    /// Whether the solver found a satisfying model.
    pub outcome: SolverOutcomeKind,
    /// Concrete value for each binding (register symbols get full-width
    /// values; memory symbols get one byte).
    pub assignments: Vec<ConcolicAssignment>,
    /// The branch that was inverted.
    pub branch: SymbolicBranch,
    /// Wall time inside the solver.
    pub solver_elapsed: Duration,
}

/// A solver-assigned value for one input symbol.
#[derive(Clone, Debug)]
pub struct ConcolicAssignment {
    pub source: ConcolicSource,
    /// Concrete bytes for the source (8 bytes for registers, 1 for memory).
    pub value: u64,
}

impl ConcolicSolution {
    pub fn is_sat(&self) -> bool {
        self.outcome == SolverOutcomeKind::Sat
    }
}

/// Concolic execution session: the concrete interpreter drives control flow
/// A concrete input seed for [`Runtime::parallel_concolic`].
///
/// The worker clones the loaded process, applies `registers` before opening
/// the concolic session, then marks `symbol_registers`/`symbol_memory` as
/// input symbols — mirroring [`ConcolicSession::mark_input_register`].
#[derive(Clone, Debug, Default)]
pub struct ConcolicInput {
    /// Concrete register writes applied before the session opens.
    pub registers: Vec<(u32, u64)>,
    /// Registers to mark as symbolic input (register, view type).
    pub symbol_registers: Vec<(u32, angryier_ir::IrType)>,
    /// Memory ranges to mark as symbolic input (address, byte length).
    pub symbol_memory: Vec<(u64, usize)>,
}

/// Per-run instrumentation for [`Runtime::parallel_concolic`].
#[derive(Clone, Debug)]
pub struct ConcolicRunReport {
    /// Index into the submitted input batch.
    pub input_index: usize,
    /// Worker that ran the input.
    pub worker: u32,
    /// Instructions stepped.
    pub steps: u64,
    /// Path constraints recorded.
    pub path_constraints: usize,
    /// Unique stepped PCs observed (basic coverage signal).
    pub coverage: usize,
    /// Fidelity-ledger debt entries accrued by the shadow.
    pub debt_entries: usize,
    /// SimProcedure dispatches observed.
    pub simproc_dispatches: u64,
    /// Wall time of this run.
    pub elapsed: Duration,
}

/// Aggregate report for [`Runtime::parallel_explore`].
#[derive(Clone, Debug)]
pub struct ExploreReport {
    /// States that ran to termination or budget.
    pub states_completed: u64,
    /// Conditional branches that produced a child state.
    pub branches_forked: u64,
    /// Unique stepped PCs across all workers.
    pub coverage: BTreeSet<Address>,
    /// Pool-level statistics (per-worker load balance, elapsed).
    pub pool: PoolStats,
}

impl<D: Decoder> Runtime<D> {
    /// Runs a batch of concolic inputs across an OS-thread worker pool — the
    /// QSYM parallelism model: workers parallelize over inputs, each running
    /// an independent concolic session from a clone of `process`.
    ///
    /// `step_budget` caps instructions per input. Returns one report per
    /// input plus pool statistics in submission order of `inputs`.
    pub fn parallel_concolic<'a>(
        &'a self,
        process: &Process,
        arena: &'a SymbolicArena,
        inputs: &[ConcolicInput],
        workers: u32,
        step_budget: u64,
    ) -> Result<(Vec<ConcolicRunReport>, PoolStats), RuntimeError> {
        let pool = Arc::new(OsWorkerPool::<usize>::new(workers));
        for index in 0..inputs.len() {
            pool.push((index as u32) % workers, index);
        }
        let reports = Mutex::new(Vec::with_capacity(inputs.len()));
        let stats = pool.run(|worker, index, _enqueue| {
            let started = Instant::now();
            let input = &inputs[index];
            let mut clone = process.clone();
            let mut coverage = BTreeSet::new();
            let mut report = ConcolicRunReport {
                input_index: index,
                worker,
                steps: 0,
                path_constraints: 0,
                coverage: 0,
                debt_entries: 0,
                simproc_dispatches: 0,
                elapsed: Duration::ZERO,
            };
            let result = (|| -> Result<(), RuntimeError> {
                for (register, value) in &input.registers {
                    clone.write_register(*register, *value)?;
                }
                let mut session = self.concolic(clone, arena);
                for (register, ty) in &input.symbol_registers {
                    session.mark_input_register(*register, *ty)?;
                }
                for (address, len) in &input.symbol_memory {
                    session.mark_input_memory(*address, *len)?;
                }
                for _ in 0..step_budget {
                    match session.step()? {
                        StepOutcome::Stepped { pc, .. } => {
                            coverage.insert(pc);
                        }
                        StepOutcome::Terminated { .. } | StepOutcome::Trap { .. } => break,
                        StepOutcome::SimProcedure { .. } => break,
                        _ => {}
                    }
                }
                report.steps = session.process.step_count;
                report.path_constraints = session.path_constraints().len();
                report.debt_entries = session.process.state.fidelity.entries.len();
                report.simproc_dispatches = session.process.simproc_dispatches;
                Ok(())
            })();
            if let Err(error) = result {
                eprintln!("parallel concolic input {index} failed: {error}");
            }
            report.coverage = coverage.len();
            report.elapsed = started.elapsed();
            if let Ok(mut reports) = reports.lock() {
                reports.push(report);
            }
        });
        let mut reports = reports.into_inner().unwrap_or_default();
        reports.sort_by_key(|report| report.input_index);
        Ok((reports, stats))
    }

    /// Explores states in parallel — the angr parallelism model: workers
    /// parallelize over states. Each state runs concretely until termination
    /// or `step_budget`; at every conditional branch the state forks: the
    /// current state keeps its concrete direction and a clone is enqueued
    /// starting at the other branch target.
    ///
    /// This is the EXPLORE-unsound state graph: no solver feasibility check
    /// gates forks (a PROVE variant would consult the solver before
    /// enqueueing). `max_states` bounds total explored states.
    pub fn parallel_explore(
        &self,
        process: &Process,
        workers: u32,
        step_budget: u64,
        max_states: u64,
    ) -> Result<ExploreReport, RuntimeError> {
        let pool = Arc::new(OsWorkerPool::<Process>::new(workers));
        let state_count = AtomicU64::new(1);
        let forked = AtomicU64::new(0);
        let coverage = Mutex::new(BTreeSet::new());
        pool.push(0, process.clone());
        let stats = pool.run(|worker, mut state, enqueue| {
            let mut pending: Option<(Process, Address, Address)> = None;
            for _ in 0..step_budget {
                if state.terminated {
                    break;
                }
                let outcome = match self.step_with(&mut state, |pre, block| {
                    if let Some(IrInstruction {
                        op: IrOp::Branch { taken, not_taken, .. },
                        ..
                    }) = block.instructions.last()
                    {
                        pending = Some((pre.clone(), *taken, *not_taken));
                    }
                    Ok(())
                }) {
                    Ok(outcome) => outcome,
                    Err(error) => {
                        eprintln!("explore state on worker {worker} failed: {error}");
                        break;
                    }
                };
                if let StepOutcome::Stepped { pc, .. } = outcome
                    && let Ok(mut coverage) = coverage.lock()
                {
                    coverage.insert(pc);
                }
                if let Some((mut child, taken, not_taken)) = pending.take() {
                    // The concrete step already resolved one direction; the
                    // child explores the other target.
                    if let Ok(pc) = state.pc() {
                        let other = if pc == taken { not_taken } else { taken };
                        if state_count.fetch_add(1, Ordering::Relaxed) < max_states && child.write_pc(other).is_ok() {
                            forked.fetch_add(1, Ordering::Relaxed);
                            enqueue(child);
                        }
                    }
                }
                if matches!(
                    outcome,
                    StepOutcome::Terminated { .. } | StepOutcome::Trap { .. } | StepOutcome::SimProcedure { .. }
                ) {
                    break;
                }
            }
        });
        Ok(ExploreReport {
            states_completed: stats.completed,
            branches_forked: forked.load(Ordering::Relaxed),
            coverage: coverage.into_inner().unwrap_or_default(),
            pool: stats,
        })
    }
}

/// while [`ConcolicEvaluator`] shadows the same lowered blocks, keeping
/// expressions bounded to input-derived data. Branch conditions are recorded
/// as path constraints; inverting one yields a new concrete input through the
/// solver portfolio. This is the EXPLORE-mode engine — same AngryIR
/// semantics, same decode and lowering as PROVE, bounded expression cost.
pub struct ConcolicSession<'a, D: Decoder> {
    /// The process under concolic execution.
    pub process: Process,
    runtime: &'a Runtime<D>,
    evaluator: ConcolicEvaluator<'a>,
    arena: &'a SymbolicArena,
    path: Vec<PathConstraint>,
    /// HUNT mode tolerates unlimited shadow debt before signaling PROVE.
    hunt: bool,
    last_branch: SymbolicBranch,
}

impl<'a, D: Decoder> ConcolicSession<'a, D> {
    /// Marks `register` as an input symbol.
    pub fn mark_input_register(&mut self, register: u32, ty: angryier_ir::IrType) -> Result<(), RuntimeError> {
        self.evaluator
            .mark_register(register, ty)
            .map_err(|e| RuntimeError::Symbolic(e.to_string()))?;
        Ok(())
    }

    /// Marks `length` bytes at `address` as input symbols.
    pub fn mark_input_memory(&mut self, address: u64, length: usize) -> Result<(), RuntimeError> {
        self.evaluator
            .mark_memory(address, length)
            .map_err(|e| RuntimeError::Symbolic(e.to_string()))?;
        Ok(())
    }

    /// Path constraints recorded so far, in execution order.
    pub fn path_constraints(&self) -> &[PathConstraint] {
        &self.path
    }

    /// Registers currently carrying non-constant shadow expressions — the
    /// input-derived set, for diagnostics.
    pub fn symbolic_registers(&self) -> Vec<(u32, ExprId)> {
        self.evaluator.symbolic_registers()
    }

    /// True when the shadow accumulated analysis debt beyond the profile's
    /// tolerance — the mode-switching signal for the driver to hand this
    /// state to the PROVE-mode engine. HUNT tolerates unlimited debt (it is
    /// unsound by design and never asks for PROVE).
    pub fn requires_prove(&self) -> bool {
        !self.hunt && !self.process.state.fidelity.is_exact()
    }

    /// Executes one instruction concretely and shadows the lowered block.
    /// Branch conditions are recorded as path constraints. A block the shadow
    /// cannot evaluate (symbolic addresses, unsupported ops) records analysis
    /// debt on the fidelity ledger and the step proceeds concretely — the
    /// EXPLORE contract is explicitly unsound; [`Self::requires_prove`]
    /// reports when the accumulated debt warrants a PROVE-mode handoff.
    pub fn step(&mut self) -> Result<StepOutcome, RuntimeError> {
        let mut branch = None;
        let mut debt = false;
        let outcome = self.runtime.step_with(&mut self.process, |process, block| {
            match self.evaluator.eval_block(process, block) {
                Ok(summary) => branch = summary.branch,
                Err(e) => {
                    debt = true;
                    if std::env::var_os("ANGRYIER_DEBUG_CONCOLIC").is_some() {
                        eprintln!("concolic eval debt at {:#x}: {e}", process.pc().unwrap_or(0));
                    }
                }
            }
            Ok(())
        })?;
        if debt {
            let pc = self.process.pc().unwrap_or(0);
            self.process.state.fidelity = self.process.state.fidelity.record(AnalysisDebtKind::Unsupported, pc);
        }
        if let (Some(branch), Some(next_pc)) = (branch, stepped_next_pc(&outcome)) {
            self.last_branch = branch;
            self.path.push(PathConstraint {
                condition: branch.condition,
                taken: next_pc == branch.taken,
            });
        }
        Ok(outcome)
    }

    /// Runs until termination or `max_steps`.
    pub fn run(&mut self, max_steps: u64) -> Result<RunSummary, RuntimeError> {
        while !self.process.terminated && self.process.step_count < max_steps {
            self.step()?;
        }
        if !self.process.terminated && self.process.step_count >= max_steps {
            return Err(RuntimeError::StepLimitExceeded);
        }
        Ok(RunSummary {
            steps: self.process.step_count,
            final_pc: self.process.pc()?,
            simproc_dispatches: self.process.simproc_dispatches,
            terminated: self.process.terminated,
        })
    }

    /// Inverts the last recorded path constraint and asks `backend` for an
    /// input that steers the branch the other way. Prior constraints are
    /// conjoined so the model stays on the recorded path.
    pub fn solve_last_branch(
        &self,
        backend: &mut dyn SolverBackend,
        timeout: Duration,
    ) -> Result<ConcolicSolution, RuntimeError> {
        let (last, prefix) = self.path.split_last().ok_or(RuntimeError::NoBranchInTrace)?;
        let predicate = self.direction_predicate(last.condition, !last.taken)?;
        let mut constraints = Vec::with_capacity(prefix.len());
        for (index, entry) in prefix.iter().enumerate() {
            let expr = self.direction_predicate(entry.condition, entry.taken)?;
            let key = self
                .arena
                .dependency_summary(expr)
                .map(|summary| summary.key)
                .ok_or_else(|| RuntimeError::Symbolic("missing constraint dependency summary".into()))?;
            constraints.push(CanonicalConstraint {
                id: ConstraintId(index as u64),
                key,
                expr,
            });
        }
        let predicate_key = self
            .arena
            .dependency_summary(predicate)
            .map(|summary| summary.key)
            .ok_or_else(|| RuntimeError::Symbolic("missing predicate dependency summary".into()))?;

        // Constraint slicing: only constraints in the predicate's symbolic
        // dependency cone are sent. Two queries differing only in
        // unrelated constraints canonicalize to the same key — slicing
        // both speeds the solver and raises the exact-reuse hit rate.
        let mut relevant: BTreeSet<u64> = self
            .arena
            .dependency_summary(predicate)
            .map(|summary| summary.symbolic_sources.iter().copied().collect())
            .unwrap_or_default();
        let mut keep = vec![false; constraints.len()];
        let mut changed = true;
        while changed {
            changed = false;
            for (index, constraint) in constraints.iter().enumerate() {
                if keep[index] {
                    continue;
                }
                let Some(summary) = self.arena.dependency_summary(constraint.expr) else {
                    continue;
                };
                if summary.symbolic_sources.iter().any(|source| relevant.contains(source)) {
                    keep[index] = true;
                    relevant.extend(summary.symbolic_sources.iter().copied());
                    changed = true;
                }
            }
        }
        let sliced: Vec<CanonicalConstraint> = constraints
            .into_iter()
            .zip(keep.iter())
            .filter_map(|(constraint, keep)| keep.then_some(constraint))
            .collect();

        let query = SolverQuery::canonical(
            SolverQueryId(self.process.step_count),
            &sliced,
            predicate,
            predicate_key,
            self.process.target_profile,
            ConstraintCanonicalizationVersion(1),
            timeout,
        )
        .map_err(|e| RuntimeError::Solver(format!("{e:?}")))?;

        let result = backend.solve(&query);

        let mut assignments = Vec::new();
        for (key, bytes) in &result.model {
            let Ok(key) = u32::try_from(*key) else {
                continue;
            };
            let expression = ExprId(key);
            let Some(binding) = self
                .evaluator
                .bindings()
                .iter()
                .find(|binding| binding.expression == expression)
            else {
                continue;
            };
            let mut buffer = [0u8; 8];
            let len = bytes.len().min(8);
            buffer[..len].copy_from_slice(&bytes[..len]);
            assignments.push(ConcolicAssignment {
                source: binding.source,
                value: u64::from_le_bytes(buffer),
            });
        }

        Ok(ConcolicSolution {
            outcome: result.outcome,
            assignments,
            branch: self.last_branch,
            solver_elapsed: result.elapsed,
        })
    }

    /// `condition == 1` when `taken`, `== 0` otherwise — the boolean form the
    /// solver consumes.
    fn direction_predicate(&self, condition: ExprId, taken: bool) -> Result<ExprId, RuntimeError> {
        let bit = self
            .arena
            .intern(ExprNode {
                sort: ExprSort::BitVec(1),
                op: ExprOp::Constant,
                operands: Vec::new(),
                immediate: vec![u8::from(taken)],
            })
            .map_err(|e| RuntimeError::Symbolic(format!("{e:?}")))?;
        self.arena
            .intern(ExprNode {
                sort: ExprSort::Bool,
                op: ExprOp::Eq,
                operands: vec![condition, bit],
                immediate: Vec::new(),
            })
            .map_err(|e| RuntimeError::Symbolic(format!("{e:?}")))
    }
}

/// The next PC a stepped outcome jumped to, when it continued.
fn stepped_next_pc(outcome: &StepOutcome) -> Option<u64> {
    match outcome {
        StepOutcome::Stepped { next_pc, .. } => Some(*next_pc),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_arch::{
        AccessKind, DecodedInstruction, InstructionModifiers, MemoryBase, MemoryOperand, Operand, OperandKind,
        OperandVisibility, RegisterId, RegisterView,
    };

    /// A synthetic decoder that maps byte patterns to known instructions.
    /// This lets us test the full pipeline without requiring native XED.
    #[derive(Debug, Clone)]
    struct SyntheticDecoder {
        forms: BTreeMap<u8, (u32, u8)>,
    }

    impl SyntheticDecoder {
        fn new() -> Self {
            let mut forms = BTreeMap::new();
            // Map specific opcodes to (form_id, length).
            // 0x90 = NOP (form NOP2, length 1)
            // 0xC3 = RET (form RET, length 1)
            forms.insert(0x90, (angryier_semantics_intel64::forms::NOP2, 1));
            forms.insert(0xC3, (angryier_semantics_intel64::forms::RET, 1));
            Self { forms }
        }
    }

    impl Decoder for SyntheticDecoder {
        type Error = String;

        fn decode(&self, address: Address, bytes: &[u8]) -> Result<DecodedInstruction, Self::Error> {
            if bytes.is_empty() {
                return Err("empty input".into());
            }
            let opcode = bytes[0];
            let (form_id, length) = self
                .forms
                .get(&opcode)
                .copied()
                .ok_or_else(|| format!("unknown opcode: {opcode:#x}"))?;

            Ok(DecodedInstruction {
                address,
                length,
                form_id,
                features: Vec::new(),
                operands: synthetic_operands(form_id),
                modifiers: InstructionModifiers::default(),
            })
        }
    }

    /// Operands the synthetic decoder reports for the forms it emulates.
    ///
    /// `ret` reads its return address from the stack, so the decoded operand
    /// list mirrors what a real decoder reports for `[rsp]`.
    fn synthetic_operands(form_id: u32) -> Vec<Operand> {
        if form_id != angryier_semantics_intel64::forms::RET {
            return Vec::new();
        }
        vec![
            Operand {
                index: 0,
                width_bits: 64,
                access: AccessKind::Write,
                visibility: OperandVisibility::Suppressed,
                kind: OperandKind::Register(RegisterView::full(RegisterId(0x20), 64)),
            },
            Operand {
                index: 1,
                width_bits: 64,
                access: AccessKind::Read,
                visibility: OperandVisibility::Suppressed,
                kind: OperandKind::Memory(MemoryOperand {
                    memory_index: 0,
                    address_width_bits: 64,
                    segment: None,
                    segment_base: None,
                    base: Some(MemoryBase::Register(RegisterView::full(RegisterId(4), 64))),
                    index: None,
                    scale: 1,
                    displacement: 0,
                    displacement_width_bits: 0,
                }),
            },
        ]
    }

    /// Builds a minimal synthetic ELF64 image with given code bytes.
    fn build_elf(code: &[u8]) -> Vec<u8> {
        // We use the real Elf64Loader, so we need a valid ELF64 header.
        // Build a minimal statically-linked ELF64 with one executable segment.
        use angryier_loader::INTEL64_TARGET_PROFILE;

        let segment_base = 0x400000u64;

        // ELF64 header (64 bytes) + program header (56 bytes) = 120 bytes.
        // Code starts at offset 120.
        let header_len = 64usize;
        let phdr_len = 56usize;
        let code_offset = header_len + phdr_len;
        // Pad to page boundary so instruction reads (up to 15 bytes) don't
        // run past the mapped segment.
        let min_size = code_offset + code.len() + MAX_INSN_LEN;
        let total_size = min_size.next_multiple_of(0x1000);

        // Entry point is at the code, not the ELF header.
        let entry = segment_base + code_offset as u64;

        let mut buf = vec![0u8; total_size];

        // ELF header.
        buf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']); // magic
        buf[4] = 2; // ELFCLASS64
        buf[5] = 1; // little-endian
        buf[6] = 1; // EV_CURRENT
        buf[7] = 0; // SYSV ABI
        buf[8..16].copy_from_slice(&[0u8; 8]); // padding

        // e_type = ET_EXEC (2)
        buf[16..18].copy_from_slice(&2u16.to_le_bytes());
        // e_machine = EM_X86_64 (62)
        buf[18..20].copy_from_slice(&62u16.to_le_bytes());
        // e_version = 1
        buf[20..24].copy_from_slice(&1u32.to_le_bytes());
        // e_entry
        buf[24..32].copy_from_slice(&entry.to_le_bytes());
        // e_phoff = 64
        buf[32..40].copy_from_slice(&(64u64).to_le_bytes());
        // e_shoff = 0
        buf[40..48].copy_from_slice(&0u64.to_le_bytes());
        // e_flags = 0
        buf[48..52].copy_from_slice(&0u32.to_le_bytes());
        // e_ehsize = 64
        buf[52..54].copy_from_slice(&64u16.to_le_bytes());
        // e_phentsize = 56
        buf[54..56].copy_from_slice(&56u16.to_le_bytes());
        // e_phnum = 1
        buf[56..58].copy_from_slice(&1u16.to_le_bytes());
        // e_shentsize = 0
        buf[58..60].copy_from_slice(&0u16.to_le_bytes());
        // e_shnum = 0
        buf[60..62].copy_from_slice(&0u16.to_le_bytes());
        // e_shstrndx = 0
        buf[62..64].copy_from_slice(&0u16.to_le_bytes());

        // Program header (PT_LOAD).
        // p_type = PT_LOAD (1)
        buf[64..68].copy_from_slice(&1u32.to_le_bytes());
        // p_flags = R|X (5)
        buf[68..72].copy_from_slice(&5u32.to_le_bytes());
        // p_offset = 0
        buf[72..80].copy_from_slice(&0u64.to_le_bytes());
        // p_vaddr = segment_base
        buf[80..88].copy_from_slice(&segment_base.to_le_bytes());
        // p_paddr = segment_base
        buf[88..96].copy_from_slice(&segment_base.to_le_bytes());
        // p_filesz = total_size
        buf[96..104].copy_from_slice(&(total_size as u64).to_le_bytes());
        // p_memsz = total_size
        buf[104..112].copy_from_slice(&(total_size as u64).to_le_bytes());
        // p_align = 0x1000
        buf[112..120].copy_from_slice(&0x1000u64.to_le_bytes());

        // Code bytes.
        buf[code_offset..code_offset + code.len()].copy_from_slice(code);

        let _ = INTEL64_TARGET_PROFILE;
        buf
    }

    #[test]
    fn runtime_loads_and_executes_nop_ret() -> Result<(), RuntimeError> {
        // Code: NOP; NOP; RET
        let code = [0x90, 0x90, 0xC3];
        let elf = build_elf(&code);

        let decoder = SyntheticDecoder::new();
        let runtime = Runtime::new(decoder, SemanticVersion(1), TargetProfileId(1));

        let mut process = runtime.load_elf(&elf)?;
        let entry = process.entry;
        assert_eq!(entry, 0x400078);
        assert_eq!(process.pc()?, entry);

        // Step 1: NOP at entry
        let outcome = runtime.step(&mut process)?;
        assert!(matches!(outcome, StepOutcome::Stepped { pc, next_pc, .. } if pc == entry && next_pc == entry + 1));
        assert_eq!(process.pc()?, entry + 1);

        // Step 2: NOP at entry+1
        let outcome = runtime.step(&mut process)?;
        assert!(matches!(outcome, StepOutcome::Stepped { pc, next_pc, .. } if pc == entry + 1 && next_pc == entry + 2));
        assert_eq!(process.pc()?, entry + 2);

        // Push a return address so the indirect jump has a target (the stack
        // pointer starts one past the end of the stack region).
        let return_target = 0x400100_u64;
        let stack_pointer = process.read_register(register_id::GPR_BASE + 4)? - 8;
        process.write_register(register_id::GPR_BASE + 4, stack_pointer)?;
        process.state.memory = process
            .state
            .memory
            .write(stack_pointer, &return_target.to_le_bytes().map(ByteValue::Concrete))
            .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;

        // Step 3: RET at entry+2 pops the return address and jumps to it.
        let outcome = runtime.step(&mut process)?;
        assert!(
            matches!(outcome, StepOutcome::Stepped { pc, next_pc, .. } if pc == entry + 2 && next_pc == return_target)
        );
        assert_eq!(process.pc()?, return_target);
        assert_eq!(process.read_register(register_id::GPR_BASE + 4)?, stack_pointer + 8);

        // Run summary.
        let summary = RunSummary {
            steps: process.step_count,
            final_pc: process.pc()?,
            simproc_dispatches: process.simproc_dispatches,
            terminated: process.terminated,
        };
        assert_eq!(summary.steps, 3);
        assert!(!summary.terminated);

        Ok(())
    }

    #[test]
    fn runtime_caches_lowered_blocks() -> Result<(), RuntimeError> {
        let code = [0x90, 0xC3];
        let elf = build_elf(&code);

        let decoder = SyntheticDecoder::new();
        let runtime = Runtime::new(decoder, SemanticVersion(1), TargetProfileId(1));

        let mut process = runtime.load_elf(&elf)?;
        let entry = process.entry;

        // Execute NOP.
        runtime.step(&mut process)?;

        // Block cache should contain the lowered block at entry.
        assert!(process.block_cache.contains_key(&entry));
        let block = &process.block_cache[&entry];
        assert!(!block.instructions.is_empty());

        Ok(())
    }

    #[test]
    fn runtime_dispatches_simproc_exit() -> Result<(), RuntimeError> {
        // Code: NOP; RET (but we hook the NOP address as exit)
        let code = [0x90, 0xC3];
        let elf = build_elf(&code);

        let decoder = SyntheticDecoder::new();
        let runtime = Runtime::new(decoder, SemanticVersion(1), TargetProfileId(1));

        let mut process = runtime.load_elf(&elf)?;
        let entry = process.entry;

        // Hook the entry address as "exit".
        process.hook_simproc(entry, "exit");

        // Step should dispatch the exit SimProcedure.
        let outcome = runtime.step(&mut process)?;
        assert!(
            matches!(outcome, StepOutcome::SimProcedure { address, ref name } if address == entry && name == "exit")
        );
        assert!(process.terminated);
        assert_eq!(process.simproc_dispatches, 1);

        Ok(())
    }

    #[test]
    fn runtime_run_respects_step_limit() -> Result<(), RuntimeError> {
        // Code: NOP; NOP; NOP; RET
        let code = [0x90, 0x90, 0x90, 0xC3];
        let elf = build_elf(&code);

        let decoder = SyntheticDecoder::new();
        let runtime = Runtime::new(decoder, SemanticVersion(1), TargetProfileId(1));

        let mut process = runtime.load_elf(&elf)?;

        // Run with step limit of 2 (should hit limit before RET).
        let result = runtime.run(&mut process, 2);
        assert!(matches!(result, Err(RuntimeError::StepLimitExceeded)));
        assert_eq!(process.step_count, 2);
        assert!(!process.terminated);

        Ok(())
    }
}

/// A symbolic execution state: the concrete [`Process`] (decode source,
/// concrete fallbacks, environment model) plus the symbolic register
/// bindings, path constraints, and symbolic byte store that make this the
/// PROVE-mode engine — control flow is symbolic, branches fork states.
#[derive(Clone)]
pub struct SymbolicState {
    /// The concrete substrate (registers hold concrete views; the symbolic
    /// bindings in `registers` shadow them).
    pub process: Process,
    /// Symbolic register expressions by register id.
    pub registers: BTreeMap<u32, (ExprId, angryier_ir::IrType)>,
    /// Path constraints (Bool expressions) accumulated on this path.
    pub constraints: Vec<ExprId>,
    /// Symbolic byte memory seeded from the process image.
    pub memory: angryier_execution::SymbolicSessionMemory,
    /// Symbols bound during this state's execution.
    pub symbols: Vec<angryier_execution::SymbolBinding>,
    /// Concrete values for registers with no symbolic binding — untouched
    /// registers (rsp, rip, startup GPRs) read concrete instead of
    /// auto-symboling; a register that was *written* symbolically has a
    /// `registers` entry which shadows this.
    pub concrete_registers: BTreeMap<u32, u64>,
    /// Stable identity — indices shift as states are added/removed, so
    /// merge schedules and external bookkeeping key on `id`.
    pub id: u64,
    /// Concrete value each load-derived expression stands for (pointer
    /// provenance for address concretization).
    pub expr_concrete: BTreeMap<ExprId, u64>,
}

/// What one symbolic step did to a state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymbolicStepOutcome {
    /// The block fell through or jumped to a single successor.
    Stepped {
        /// Next program counter.
        next_pc: Address,
    },
    /// A conditional branch forked the state — the child was pushed.
    Branched {
        /// Index of the child state in `SymbolicSession::states`.
        child: usize,
    },
    /// The state terminated (ret with concrete return address, exit, trap).
    Terminated,
}

/// Symbolic exploration session — the full-symbolic counterpart of
/// [`ConcolicSession`]. Each state carries symbolic register expressions and
/// path constraints; conditional branches fork the state into both
/// directions (taken gets the constraint, not-taken its negation), and
/// [`SymbolicSession::merge_at`] can reconverge sibling states via
/// [`merge_snapshots`]. States that hit unsupported symbolic operations fail
/// that state only — sibling states keep exploring (per-state isolation).
pub struct SymbolicSession<'a, D: Decoder> {
    runtime: &'a Runtime<D>,
    arena: &'a SymbolicArena,
    /// Live states awaiting exploration.
    pub states: Vec<SymbolicState>,
    /// States that terminated or errored, kept for inspection.
    pub dead: Vec<SymbolicState>,
    /// Optional CFG for reconvergence-aware merging.
    cfg: Option<&'a angryier_cfg::Cfg>,
    /// Next state id (monotonic).
    next_state_id: u64,
    /// Pairs scheduled to merge at a reconvergence pc: (state_a_id,
    /// state_b_id, target_pc). A state parked at `target_pc` while its sibling hasn't
    /// arrived is held rather than stepped — the CFG-scheduled merge.
    pub pending_merges: Vec<(u64, u64, Address)>,
}

impl<'a, D: Decoder> SymbolicSession<'a, D> {
    /// Opens a session from `process` — its memory seeds every state's
    /// symbolic byte store; registers start concrete (mark input registers
    /// via [`SymbolicSession::mark_symbolic`]).
    pub fn new(runtime: &'a Runtime<D>, arena: &'a SymbolicArena, process: Process) -> Self {
        let memory = angryier_execution::SymbolicSessionMemory::new(process.state.memory.clone());
        let mut concrete_registers = BTreeMap::new();
        for i in 0..16u32 {
            if let Ok(value) = process.read_register(register_id::GPR_BASE + i) {
                concrete_registers.insert(register_id::GPR_BASE + i, value);
            }
        }
        if let Ok(value) = process.read_register(register_id::RIP.0) {
            concrete_registers.insert(register_id::RIP.0, value);
        }
        if let Ok(value) = process.read_register(register_id::RFLAGS.0) {
            concrete_registers.insert(register_id::RFLAGS.0, value);
        }
        let state = SymbolicState {
            process,
            registers: BTreeMap::new(),
            constraints: Vec::new(),
            memory,
            symbols: Vec::new(),
            concrete_registers,
            id: 0,
            expr_concrete: BTreeMap::new(),
        };
        Self {
            runtime,
            arena,
            states: vec![state],
            dead: Vec::new(),
            cfg: None,
            next_state_id: 1,
            pending_merges: Vec::new(),
        }
    }

    /// Attaches a CFG so `run_with_policy` merges reconverging states at
    /// static merge points (Veritesting-style) rather than only when two
    /// states happen to park at the same pc.
    pub fn with_cfg(mut self, cfg: &'a angryier_cfg::Cfg) -> Self {
        self.cfg = Some(cfg);
        self
    }

    /// Marks `register` symbolic with `ty` in state `index` — the input
    /// binding entry point.
    pub fn mark_symbolic(&mut self, index: usize, register: u32, ty: angryier_ir::IrType) -> Result<(), RuntimeError> {
        let state = self
            .states
            .get_mut(index)
            .ok_or_else(|| RuntimeError::Execution("no such state".into()))?;
        let mut evaluator = SymbolicEvaluator::new(self.arena);
        let expr = evaluator
            .mark_register(register, ty)
            .map_err(|e| RuntimeError::Execution(format!("{e:?}")))?;
        state.registers.insert(register, (expr, ty));
        state.symbols.extend(evaluator.symbols().iter().copied());
        Ok(())
    }

    /// Steps state `index` through one instruction: decode → lower → symbolic
    /// eval. Conditional branches fork the state (taken gets the condition,
    /// not-taken its negation); unconditional jumps and direct calls follow
    /// their static target.
    pub fn step_state(&mut self, index: usize) -> Result<SymbolicStepOutcome, RuntimeError> {
        self.step_state_inner(index, None)
    }

    /// Like [`SymbolicSession::step_state`], but each fork direction is
    /// feasibility-checked through `backend` first — an UNSAT direction is
    /// pruned instead of enqueued (the state-space lever Phase 10 requires).
    /// `Unknown`/`Sat` both keep the direction.
    pub fn step_state_checked(
        &mut self,
        index: usize,
        backend: &mut dyn SolverBackend,
        timeout: Duration,
    ) -> Result<SymbolicStepOutcome, RuntimeError> {
        self.step_state_inner(index, Some((backend, timeout)))
    }

    fn step_state_inner(
        &mut self,
        index: usize,
        mut solver: Option<(&mut dyn SolverBackend, Duration)>,
    ) -> Result<SymbolicStepOutcome, RuntimeError> {
        let state = self
            .states
            .get(index)
            .ok_or_else(|| RuntimeError::Execution("no such state".into()))?;
        if state.process.terminated {
            return Ok(SymbolicStepOutcome::Terminated);
        }
        let pc = state
            .process
            .pc()
            .map_err(|e| RuntimeError::Execution(format!("{e:?}")))?;

        // SimProcedure hooks dispatch like they do in concrete mode.
        if state.process.simproc_hooks.contains_key(&pc) {
            let state = &mut self.states[index];
            let outcome = self.runtime.step(&mut state.process)?;
            return Ok(match outcome {
                StepOutcome::Terminated { .. } => SymbolicStepOutcome::Terminated,
                _ => SymbolicStepOutcome::Stepped {
                    next_pc: state.process.pc().unwrap_or(0),
                },
            });
        }

        // Decode at pc from the state's concrete memory, bounded to the
        // containing region so tail instructions don't overrun.
        let raw = {
            let available = state
                .process
                .state
                .memory
                .regions()
                .iter()
                .find(|region| pc >= region.base && pc < region.base.saturating_add(region.size))
                .map_or(MAX_INSN_LEN, |region| {
                    usize::try_from(region.base.saturating_add(region.size).saturating_sub(pc)).unwrap_or(MAX_INSN_LEN)
                });
            let bytes = state
                .process
                .state
                .memory
                .read(pc, available.min(MAX_INSN_LEN))
                .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
            bytes
                .iter()
                .map(|b| match b {
                    ByteValue::Concrete(v) => *v,
                    ByteValue::Symbolic(_) => 0,
                })
                .collect::<Vec<u8>>()
        };
        if raw.is_empty() {
            return Err(RuntimeError::Decode("no bytes at PC".into()));
        }
        let decoded = self
            .runtime
            .decoder
            .decode(pc, &raw)
            .map_err(|e| RuntimeError::Decode(format!("{e:?}")))?;

        // REP string ops: the concrete engine intercepts them before the
        // semantic registry; the symbolic path needs the same fast path,
        // writing symbolic bytes into the state's store when the fill value
        // or source is symbolic.
        #[cfg(feature = "xed")]
        if let Some(outcome) = self.step_state_string_op(index, &decoded)? {
            return Ok(outcome);
        }

        if decoded.form_id == SYSCALL_FORM_ID || decoded.form_id == CPUID_FORM_ID {
            // Environment interactions run concretely — but the syscall
            // number/args may be symbolic in this state. Concretize them:
            // constant symbolic bindings are materialized into the concrete
            // register file before dispatch (non-constant symbolic args are
            // EXPLORE-level: the concrete value stands and the state records
            // the concretization debt upstream).
            let state = &mut self.states[index];
            for reg in [
                register_id::GPR_BASE,      // rax — syscall number
                register_id::GPR_BASE + 7,  // rdi
                register_id::GPR_BASE + 6,  // rsi
                register_id::GPR_BASE + 2,  // rdx
                register_id::GPR_BASE + 10, // r10
                register_id::GPR_BASE + 8,  // r8
                register_id::GPR_BASE + 9,  // r9
            ] {
                if let Some((expr, _)) = state.registers.get(&reg)
                    && let Some(node) = self.arena.get(*expr)
                    && node.op == angryier_expr::ExprOp::Constant
                    && node.immediate.len() >= 8
                {
                    let value = u64::from_le_bytes(node.immediate[..8].try_into().unwrap_or([0; 8]));
                    let _ = state.process.write_register(reg, value);
                }
            }
            let outcome = self.runtime.step(&mut state.process)?;
            return Ok(match outcome {
                StepOutcome::Terminated { .. } => SymbolicStepOutcome::Terminated,
                _ => SymbolicStepOutcome::Stepped {
                    next_pc: state.process.pc().unwrap_or(0),
                },
            });
        }

        let (ir_block, _decoded) = self.runtime.lower_at(&mut self.states[index].process, pc, &decoded)?;

        let mut evaluator = SymbolicEvaluator::new(self.arena);
        {
            let state = &self.states[index];
            evaluator.restore(&angryier_execution::SymbolicStateSnapshot {
                registers: state.registers.clone(),
                concrete_registers: state.concrete_registers.clone(),
                constraints: state.constraints.clone(),
                symbols: state.symbols.clone(),
                expr_concrete: state.expr_concrete.clone(),
            });
        }
        let mut summary = evaluator.eval_block_with_memory(&ir_block, &mut self.states[index].memory);
        // Solver-assisted address concretization: when an address expr
        // can't fold concretely, ask the solver for a satisfying value
        // under this state's constraints, pin it, and re-run the block.
        eprintln!("solver={} summary_err={}", solver.is_some(), summary.is_err());
        if let Some((backend, timeout)) = solver.as_mut().map(|(b, t)| (&mut **b, *t)) {
            let mut retries = 0;
            while let Err(angryier_execution::SymbolicEvalError::UnresolvedAddress(expr)) = summary {
                retries += 1;
                if retries > 4 {
                    break;
                }
                // expr == a fresh free variable, under the state's path
                // constraints — the model gives a concrete address.
                let free = self
                    .arena
                    .intern(angryier_expr::ExprNode {
                        sort: angryier_expr::ExprSort::BitVec(64),
                        op: angryier_expr::ExprOp::Symbol,
                        operands: Vec::new(),
                        immediate: u64::MAX.to_le_bytes().to_vec(),
                    })
                    .map_err(|e| RuntimeError::Execution(format!("{e:?}")))?;
                // The concretized address must land inside a mapped region
                // — disjoin `base <= free < base+size` over regions.
                let eq = self
                    .arena
                    .intern(angryier_expr::ExprNode {
                        sort: angryier_expr::ExprSort::Bool,
                        op: angryier_expr::ExprOp::Eq,
                        operands: vec![expr, free],
                        immediate: Vec::new(),
                    })
                    .map_err(|e| RuntimeError::Execution(format!("{e:?}")))?;
                let mut region_pred = eq;
                {
                    let regions: Vec<(u64, u64)> = self.states[index]
                        .process
                        .state
                        .memory
                        .regions()
                        .iter()
                        .map(|r| (r.base, r.base.saturating_add(r.size)))
                        .collect();
                    let mut bounds = Vec::new();
                    for (base, end) in regions {
                        let lo = self
                            .arena
                            .intern(angryier_expr::ExprNode {
                                sort: angryier_expr::ExprSort::BitVec(64),
                                op: angryier_expr::ExprOp::Constant,
                                operands: Vec::new(),
                                immediate: base.to_le_bytes().to_vec(),
                            })
                            .map_err(|e| RuntimeError::Execution(format!("{e:?}")))?;
                        let hi = self
                            .arena
                            .intern(angryier_expr::ExprNode {
                                sort: angryier_expr::ExprSort::BitVec(64),
                                op: angryier_expr::ExprOp::Constant,
                                operands: Vec::new(),
                                immediate: end.to_le_bytes().to_vec(),
                            })
                            .map_err(|e| RuntimeError::Execution(format!("{e:?}")))?;
                        let ge = self
                            .arena
                            .intern(angryier_expr::ExprNode {
                                sort: angryier_expr::ExprSort::Bool,
                                op: angryier_expr::ExprOp::Ule,
                                operands: vec![lo, free],
                                immediate: Vec::new(),
                            })
                            .map_err(|e| RuntimeError::Execution(format!("{e:?}")))?;
                        let lt = self
                            .arena
                            .intern(angryier_expr::ExprNode {
                                sort: angryier_expr::ExprSort::Bool,
                                op: angryier_expr::ExprOp::Ult,
                                operands: vec![free, hi],
                                immediate: Vec::new(),
                            })
                            .map_err(|e| RuntimeError::Execution(format!("{e:?}")))?;
                        let band = self
                            .arena
                            .intern(angryier_expr::ExprNode {
                                sort: angryier_expr::ExprSort::Bool,
                                op: angryier_expr::ExprOp::And,
                                operands: vec![ge, lt],
                                immediate: Vec::new(),
                            })
                            .map_err(|e| RuntimeError::Execution(format!("{e:?}")))?;
                        bounds.push(band);
                    }
                    if !bounds.is_empty() {
                        let mut disj = bounds[0];
                        for b in &bounds[1..] {
                            disj = self
                                .arena
                                .intern(angryier_expr::ExprNode {
                                    sort: angryier_expr::ExprSort::Bool,
                                    op: angryier_expr::ExprOp::Or,
                                    operands: vec![disj, *b],
                                    immediate: Vec::new(),
                                })
                                .map_err(|e| RuntimeError::Execution(format!("{e:?}")))?;
                        }
                        region_pred = self
                            .arena
                            .intern(angryier_expr::ExprNode {
                                sort: angryier_expr::ExprSort::Bool,
                                op: angryier_expr::ExprOp::And,
                                operands: vec![eq, disj],
                                immediate: Vec::new(),
                            })
                            .map_err(|e| RuntimeError::Execution(format!("{e:?}")))?;
                    }
                }
                let eq = region_pred;
                let state_ref = &self.states[index];
                let constraints: Vec<CanonicalConstraint> = state_ref
                    .constraints
                    .iter()
                    .enumerate()
                    .filter_map(|(i, c)| {
                        self.arena.dependency_summary(*c).map(|s| CanonicalConstraint {
                            id: ConstraintId(i as u64),
                            key: s.key,
                            expr: *c,
                        })
                    })
                    .collect();
                let profile = state_ref.process.target_profile;
                let key = self
                    .arena
                    .dependency_summary(eq)
                    .map(|s| s.key)
                    .ok_or_else(|| RuntimeError::Symbolic("missing key".into()))?;
                let query = SolverQuery::canonical(
                    SolverQueryId(index as u64),
                    &constraints,
                    eq,
                    key,
                    profile,
                    ConstraintCanonicalizationVersion(1),
                    timeout,
                )
                .map_err(|e| RuntimeError::Solver(format!("{e:?}")))?;
                let result = backend.solve(&query);
                eprintln!(
                    "concretize expr {}: {:?} model={} entries",
                    expr.0,
                    result.outcome,
                    result.model.len()
                );
                let value = result
                    .model
                    .iter()
                    .find(|(k, _)| *k == u64::from(free.0))
                    .and_then(|(_, b)| {
                        let mut buf = [0u8; 8];
                        let n = b.len().min(8);
                        buf[..n].copy_from_slice(&b[..n]);
                        Some(u64::from_le_bytes(buf))
                    });
                let Some(value) = value else { break };
                self.states[index].expr_concrete.insert(expr, value);
                evaluator.restore(&angryier_execution::SymbolicStateSnapshot {
                    registers: self.states[index].registers.clone(),
                    concrete_registers: self.states[index].concrete_registers.clone(),
                    constraints: self.states[index].constraints.clone(),
                    symbols: self.states[index].symbols.clone(),
                    expr_concrete: self.states[index].expr_concrete.clone(),
                });
                summary = evaluator.eval_block_with_memory(&ir_block, &mut self.states[index].memory);
            }
        }
        let summary = summary.map_err(|e| RuntimeError::Execution(format!("{e:?}")))?;
        let post = evaluator.snapshot();
        let state = &mut self.states[index];
        state.registers = post.registers;
        state.expr_concrete = post.expr_concrete;
        state.symbols = evaluator.symbols().to_vec();

        if let Some(branch) = summary.branch {
            // Fork: this state takes `taken` under `condition`; the child
            // takes `not_taken` under its negation.
            let condition = angryier_execution::bit_to_bool(self.arena, branch.condition)
                .map_err(|e| RuntimeError::Execution(format!("{e:?}")))?;
            let not_cond = self
                .arena
                .intern(angryier_expr::ExprNode {
                    sort: angryier_expr::ExprSort::Bool,
                    op: angryier_expr::ExprOp::Not,
                    operands: vec![condition],
                    immediate: Vec::new(),
                })
                .map_err(|e| RuntimeError::Execution(format!("{e:?}")))?;

            // Feasibility gates: taken under `condition`, not_taken under
            // `!condition` — each checked against the state's constraints.
            let (taken_feasible, other_feasible) = if let Some((backend, timeout)) = solver {
                let taken = self.direction_feasible(index, condition, backend, timeout)?;
                let other = self.direction_feasible(index, not_cond, backend, timeout)?;
                (taken, other)
            } else {
                (true, true)
            };
            if !taken_feasible && !other_feasible {
                // Both directions infeasible — the path is dead.
                let state = self.states.remove(index);
                self.dead.push(state);
                return Ok(SymbolicStepOutcome::Terminated);
            }

            let child_index = self.states.len();
            let state = &mut self.states[index];
            if taken_feasible && other_feasible {
                state.constraints.push(condition);
                let _ = state.process.write_pc(branch.taken);
                let mut child = state.clone();
                child.constraints.pop();
                child.constraints.push(not_cond);
                let _ = child.process.write_pc(branch.not_taken);
                child.id = self.next_state_id;
                self.next_state_id += 1;
                self.states.push(child);
                // Veritesting schedule: if the CFG knows where these two
                // reconverge, park the first arrival until its sibling gets
                // there instead of letting it run ahead.
                if let Some(cfg) = self.cfg
                    // blocks are keyed by start address — the branch's pc is
                    // the *terminating instruction*, so find the containing
                    // block (greatest start <= pc).
                    && let Some((_, block)) = cfg.blocks.range(..=pc).next_back()
                    && block.instructions.iter().any(|i| i.address == pc)
                    && let Some(target) = cfg.reconvergence_target(block, 16)
                {
                    let (a_id, b_id) = (self.states[index].id, self.states[child_index].id);
                    self.pending_merges.push((a_id, b_id, target));
                }
                return Ok(SymbolicStepOutcome::Branched { child: child_index });
            }
            // Exactly one direction is feasible — continue without forking.
            let (constraint, next_pc) = if taken_feasible {
                (condition, branch.taken)
            } else {
                (not_cond, branch.not_taken)
            };
            state.constraints.push(constraint);
            let _ = state.process.write_pc(next_pc);
            return Ok(SymbolicStepOutcome::Stepped { next_pc });
        }

        // Unconditional / call / fall-through — the block's terminator op
        // carries the successor.
        let state = &mut self.states[index];
        let terminator = ir_block.instructions.last().map(|insn| &insn.op);
        match terminator {
            Some(angryier_ir::IrOp::Jump { target }) | Some(angryier_ir::IrOp::Call { target }) => {
                let _ = state.process.write_pc(*target);
                Ok(SymbolicStepOutcome::Stepped { next_pc: *target })
            }
            Some(angryier_ir::IrOp::JumpIndirect { .. }) | Some(angryier_ir::IrOp::Return) => {
                // ret/indirect — read the return address off the state's
                // symbolic stack (rsp points at the pushed return target).
                let rsp = state
                    .registers
                    .get(&(register_id::GPR_BASE + 4))
                    .and_then(|(expr, _)| {
                        self.arena
                            .get(*expr)
                            .filter(|n| n.op == angryier_expr::ExprOp::Constant)
                            .and_then(|n| {
                                n.immediate
                                    .get(..8)
                                    .map(|b| u64::from_le_bytes(b.try_into().unwrap_or([0; 8])))
                            })
                    })
                    .or_else(|| state.process.read_register(register_id::GPR_BASE + 4).ok());
                if let Some(rsp) = rsp
                    && let Ok(ret_expr) = state.memory.read(self.arena, rsp, 64)
                    && let Some(node) = self.arena.get(ret_expr)
                    && node.op == angryier_expr::ExprOp::Constant
                    && let Some(b) = node.immediate.get(..8)
                {
                    let target = u64::from_le_bytes(b.try_into().unwrap_or([0; 8]));
                    let _ = state.process.write_pc(target);
                    return Ok(SymbolicStepOutcome::Stepped { next_pc: target });
                }
                Ok(SymbolicStepOutcome::Terminated)
            }
            Some(angryier_ir::IrOp::Trap { .. }) => Ok(SymbolicStepOutcome::Terminated),
            _ => {
                let next_pc = pc.wrapping_add(u64::from(decoded.length));
                let _ = state.process.write_pc(next_pc);
                Ok(SymbolicStepOutcome::Stepped { next_pc })
            }
        }
    }

    /// Queries `backend` whether `direction` is satisfiable under the
    /// state's accumulated path constraints.
    fn direction_feasible(
        &self,
        index: usize,
        direction: ExprId,
        backend: &mut dyn SolverBackend,
        timeout: Duration,
    ) -> Result<bool, RuntimeError> {
        let state = &self.states[index];
        let constraints: Vec<CanonicalConstraint> = state
            .constraints
            .iter()
            .enumerate()
            .filter_map(|(i, expr)| {
                self.arena.dependency_summary(*expr).map(|s| CanonicalConstraint {
                    id: ConstraintId(i as u64),
                    key: s.key,
                    expr: *expr,
                })
            })
            .collect();
        let key = self
            .arena
            .dependency_summary(direction)
            .map(|s| s.key)
            .ok_or_else(|| RuntimeError::Symbolic("missing direction summary".into()))?;
        let query = SolverQuery::canonical(
            SolverQueryId(index as u64),
            &constraints,
            direction,
            key,
            state.process.target_profile,
            ConstraintCanonicalizationVersion(1),
            timeout,
        )
        .map_err(|e| RuntimeError::Solver(format!("{e:?}")))?;
        let result = backend.solve(&query);
        Ok(!matches!(result.outcome, SolverOutcomeKind::Unsat))
    }

    /// Merges every group of live states sharing the same pc via
    /// [`merge_snapshots`] — the Veritesting reconvergence primitive.
    /// Divergent registers become `Ite(left_guard, l, r)` under each state's
    /// accumulated constraints; states that fail the merge (type mismatch)
    /// stay separate. The merge parent is the empty snapshot, so registers
    /// touched on only one side keep that side's binding (documented
    /// EXPLORE-level approximation for absent parents).
    pub fn merge_at(&mut self) -> Result<u64, RuntimeError> {
        let mut by_pc: BTreeMap<u64, Vec<usize>> = BTreeMap::new();
        for (index, state) in self.states.iter().enumerate() {
            if let Ok(pc) = state.process.pc() {
                by_pc.entry(pc).or_default().push(index);
            }
        }
        let mut merged = 0u64;
        // Merge groups largest-first so indices stay valid when draining.
        for (_pc, mut indices) in by_pc {
            while indices.len() > 1 {
                let b = indices.pop().unwrap_or(0);
                let a = indices.pop().unwrap_or(0);
                // Keep `a` as the lower index; drain `b` first (larger index
                // order) to preserve `a`'s position.
                let (a, b) = if a < b { (a, b) } else { (b, a) };
                let right = self.states.remove(b);
                let left = self.states.remove(a);
                let empty_parent = angryier_execution::SymbolicStateSnapshot::default();
                let snapshot = angryier_execution::merge_snapshots(
                    self.arena,
                    &empty_parent,
                    &angryier_execution::SymbolicStateSnapshot {
                        registers: left.registers.clone(),
                        concrete_registers: left.concrete_registers.clone(),
                        constraints: left.constraints.clone(),
                        symbols: left.symbols.clone(),
                        expr_concrete: left.expr_concrete.clone(),
                    },
                    &angryier_execution::SymbolicStateSnapshot {
                        registers: right.registers.clone(),
                        concrete_registers: right.concrete_registers.clone(),
                        constraints: right.constraints.clone(),
                        symbols: right.symbols.clone(),
                        expr_concrete: right.expr_concrete.clone(),
                    },
                )
                .map_err(|e| RuntimeError::Execution(format!("{e:?}")))?;
                let merged_state = SymbolicState {
                    process: left.process,
                    registers: snapshot.registers,
                    constraints: snapshot.constraints,
                    memory: left.memory,
                    symbols: snapshot.symbols,
                    concrete_registers: left.concrete_registers.clone(),
                    id: left.id,
                    expr_concrete: snapshot.expr_concrete.clone(),
                };
                self.states.insert(a, merged_state);
                merged += 1;
                // Re-collect indices at this pc — `remove` shifted them.
                indices = self
                    .states
                    .iter()
                    .enumerate()
                    .filter_map(|(i, s)| s.process.pc().ok().filter(|p| *p == _pc).map(|_| i))
                    .collect();
            }
        }
        Ok(merged)
    }
}

impl<'a, D: Decoder> SymbolicSession<'a, D> {
    /// Explores until all live states terminate, `max_steps` total steps are
    /// taken, or `max_states` live states are in flight — the angr-style
    /// simulation loop. States that error are moved to `dead` rather than
    /// aborting the exploration. When `backend` is provided, fork directions
    /// are feasibility-checked; when `merge_each_step` is set, same-PC states
    /// merge after every round (Veritesting-lite reconvergence).
    pub fn run(
        &mut self,
        max_steps: u64,
        max_states: usize,
        backend: Option<&mut dyn SolverBackend>,
        timeout: Duration,
        merge_each_step: bool,
    ) -> Result<SymbolicRunReport, RuntimeError> {
        self.run_with_policy(
            max_steps,
            max_states,
            backend,
            timeout,
            merge_each_step,
            &ExplorationPolicy::default(),
        )
    }

    /// `run` under an [`ExplorationPolicy`]: find-targeted states are
    /// collected into the report (and left unstepped), avoid-targeted states
    /// are dropped, and `prefer_new_coverage` picks the least-visited-PC
    /// state each iteration.
    pub fn run_with_policy(
        &mut self,
        max_steps: u64,
        max_states: usize,
        mut backend: Option<&mut dyn SolverBackend>,
        timeout: Duration,
        merge_each_step: bool,
        policy: &ExplorationPolicy,
    ) -> Result<SymbolicRunReport, RuntimeError> {
        let mut report = SymbolicRunReport::default();
        let mut steps = 0u64;
        let mut pc_visits: BTreeMap<u64, u64> = BTreeMap::new();
        while steps < max_steps && !self.states.is_empty() {
            // Apply find/avoid before stepping.
            let mut i = 0;
            while i < self.states.len() {
                let pc = self.states[i].process.pc().unwrap_or(0);
                if policy.avoid.contains(&pc) {
                    let state = self.states.remove(i);
                    self.dead.push(state);
                    report.pruned_states += 1;
                } else if policy.find.contains(&pc) {
                    let state = self.states.remove(i);
                    report.found.push(state);
                } else {
                    i += 1;
                }
            }
            if self.states.is_empty() {
                break;
            }
            if self.states.len() > max_states {
                // State economics: drop the lowest-scoring state — score =
                // constraint count (deep states are expensive to solve and
                // well-explored) minus coverage novelty. Keeps the states
                // that are cheap to continue and reach new code.
                let mut scored: Vec<(usize, u64)> = self
                    .states
                    .iter()
                    .enumerate()
                    .map(|(i, s)| {
                        let novelty = self
                            .states
                            .iter()
                            .filter(|o| o.process.pc().ok() == s.process.pc().ok())
                            .count() as u64;
                        // Fewer constraints + fewer same-pc siblings = higher
                        // priority — score is the drop-cost (highest drops).
                        let cost = s.constraints.len() as u64 * 16 + novelty * 4;
                        (i, cost)
                    })
                    .collect();
                // Highest cost drops first.
                scored.sort_by_key(|(_, cost)| std::cmp::Reverse(*cost));
                let drop_count = self.states.len() - max_states;
                // Remove highest-index first so indices stay valid.
                let mut drop_indices: Vec<usize> = scored.iter().take(drop_count).map(|(i, _)| *i).collect();
                drop_indices.sort_unstable_by_key(|i| std::cmp::Reverse(*i));
                drop_indices.dedup();
                for idx in drop_indices {
                    let state = self.states.remove(idx);
                    self.dead.push(state);
                    report.pruned_states += 1;
                }
            }
            // CFG-scheduled merges: pairs whose pcs both reached the
            // reconvergence target merge now; a state parked there while its
            // sibling is in flight is held (skipped) rather than stepped.
            let mut held: BTreeMap<usize, ()> = BTreeMap::new();
            if !self.pending_merges.is_empty() {
                self.pending_merges.retain(|(a, b, _)| {
                    self.states.iter().any(|s| s.id == *a) && self.states.iter().any(|s| s.id == *b)
                });
                let mut completed = Vec::new();
                for (pi, &(a, b, target)) in self.pending_merges.iter().enumerate() {
                    let a_idx = self.states.iter().position(|s| s.id == a);
                    let b_idx = self.states.iter().position(|s| s.id == b);
                    let (Some(a_idx), Some(b_idx)) = (a_idx, b_idx) else {
                        continue;
                    };
                    let a_at = self.states[a_idx].process.pc().ok() == Some(target);
                    let b_at = self.states[b_idx].process.pc().ok() == Some(target);
                    if a_at && b_at {
                        completed.push((pi, a_idx, b_idx));
                    } else if a_at {
                        held.insert(a_idx, ());
                    } else if b_at {
                        held.insert(b_idx, ());
                    }
                }
                for (pi, a_idx, b_idx) in completed.into_iter().rev() {
                    self.pending_merges.remove(pi);
                    let (lo, hi) = if a_idx < b_idx { (a_idx, b_idx) } else { (b_idx, a_idx) };
                    let right = self.states.remove(hi);
                    let left = self.states.remove(lo);
                    let empty_parent = angryier_execution::SymbolicStateSnapshot::default();
                    let snapshot = angryier_execution::merge_snapshots(
                        self.arena,
                        &empty_parent,
                        &angryier_execution::SymbolicStateSnapshot {
                            registers: left.registers.clone(),
                            concrete_registers: left.concrete_registers.clone(),
                            constraints: left.constraints.clone(),
                            symbols: left.symbols.clone(),
                            expr_concrete: left.expr_concrete.clone(),
                        },
                        &angryier_execution::SymbolicStateSnapshot {
                            registers: right.registers.clone(),
                            concrete_registers: right.concrete_registers.clone(),
                            constraints: right.constraints.clone(),
                            symbols: right.symbols.clone(),
                            expr_concrete: right.expr_concrete.clone(),
                        },
                    )
                    .map_err(|e| RuntimeError::Execution(format!("{e:?}")))?;
                    self.states.insert(
                        lo,
                        SymbolicState {
                            process: left.process,
                            registers: snapshot.registers,
                            constraints: snapshot.constraints,
                            memory: left.memory,
                            symbols: snapshot.symbols,
                            concrete_registers: left.concrete_registers,
                            id: left.id,
                            expr_concrete: snapshot.expr_concrete.clone(),
                        },
                    );
                    report.merges += 1;
                }
            }
            // Round-robin: one state steps per iteration so a state that
            // reaches a pc where a sibling is parked merges before either
            // advances past the reconvergence point. Under
            // `prefer_new_coverage` the index is the state whose pc has been
            // visited least across the run.
            let index = if policy.prefer_new_coverage {
                self.states
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| !held.contains_key(i))
                    .min_by_key(|(_, s)| pc_visits.get(&s.process.pc().unwrap_or(0)).copied().unwrap_or(0))
                    .map(|(i, _)| i)
                    .unwrap_or(0)
            } else {
                // Round-robin over non-held states — a state parked at its
                // merge target waits for its sibling.
                let mut pick = (steps as usize) % self.states.len();
                if held.contains_key(&pick) {
                    pick = (0..self.states.len()).find(|i| !held.contains_key(i)).unwrap_or(pick);
                }
                pick
            };
            if held.contains_key(&index) && held.len() == self.states.len() {
                // Deadlock: every state is parked on a sibling that never
                // arrives — release the holds.
                held.clear();
            }
            let pc = self.states.get(index).and_then(|s| s.process.pc().ok()).unwrap_or(0);
            *pc_visits.entry(pc).or_default() += 1;
            let outcome = match backend.as_deref_mut() {
                Some(backend) => self.step_state_checked(index, backend, timeout),
                None => self.step_state(index),
            };
            steps += 1;
            match outcome {
                Ok(SymbolicStepOutcome::Terminated) => {
                    if index < self.states.len() {
                        let state = self.states.remove(index);
                        self.dead.push(state);
                        report.terminated += 1;
                    }
                }
                Ok(SymbolicStepOutcome::Branched { .. }) => {
                    report.forks += 1;
                }
                Ok(SymbolicStepOutcome::Stepped { .. }) => {}
                Err(error) => {
                    eprintln!(
                        "state {index} @ {:#x}: {error:?}",
                        self.states.get(index).and_then(|s| s.process.pc().ok()).unwrap_or(0)
                    );
                    if index < self.states.len() {
                        let state = self.states.remove(index);
                        self.dead.push(state);
                        report.failed += 1;
                    }
                }
            }
            if merge_each_step {
                report.merges += self.merge_at().unwrap_or(0);
            }
            report.peak_states = report.peak_states.max(self.states.len() as u64);
        }
        report.steps = steps;
        report.live_states = self.states.len() as u64;
        report.dead_states = self.dead.len() as u64;
        Ok(report)
    }
}

/// Search policy for [`SymbolicSession::run`]: analyst-specified find/avoid
/// targets plus coverage-novelty ordering — the `simgr.explore(find=…,
/// avoid=…)` equivalent.
#[derive(Clone, Debug, Default)]
pub struct ExplorationPolicy {
    /// PCs whose states are reported as `found` and not stepped further.
    pub find: Vec<Address>,
    /// PCs whose states are moved to `dead` immediately.
    pub avoid: Vec<Address>,
    /// When set, the round-robin picks the state whose PC is the least
    /// visited so far — coverage-novelty ordering.
    pub prefer_new_coverage: bool,
}

/// Aggregate report for [`SymbolicSession::run`].
#[derive(Clone, Debug, Default)]
pub struct SymbolicRunReport {
    /// Total symbolic steps taken.
    pub steps: u64,
    /// Forks produced.
    pub forks: u64,
    /// States merged by `merge_at`.
    pub merges: u64,
    /// States that terminated cleanly.
    pub terminated: u64,
    /// States dropped by the max_states cap.
    pub pruned_states: u64,
    /// States that failed and were moved to `dead`.
    pub failed: u64,
    /// Live states at return.
    pub live_states: u64,
    /// Dead/terminated states accumulated.
    pub dead_states: u64,
    /// Peak live-state count.
    pub peak_states: u64,
    /// States that reached a `find` pc.
    pub found: Vec<SymbolicState>,
}

impl std::fmt::Debug for SymbolicState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SymbolicState")
            .field("pc", &self.process.pc())
            .field("registers", &self.registers.len())
            .field("constraints", &self.constraints.len())
            .field("symbols", &self.symbols.len())
            .finish()
    }
}

impl<'a, D: Decoder> SymbolicSession<'a, D> {
    /// Symbolic REP_/string-op fast path: STOS*/MOVS* with a concrete
    /// count/dest executes the byte loop against the state's symbolic
    /// memory — a symbolic fill value writes `ByteValue::Symbolic` bytes.
    /// Returns `None` when the decoded form isn't a string op.
    #[cfg(feature = "xed")]
    fn step_state_string_op(
        &mut self,
        index: usize,
        decoded: &angryier_arch::DecodedInstruction,
    ) -> Result<Option<SymbolicStepOutcome>, RuntimeError> {
        use crate::form_map::*;
        let (is_move, size, rep) = match decoded.form_id {
            STOSB_FORM_ID | REP_STOSB_FORM_ID => (false, 1usize, decoded.form_id == REP_STOSB_FORM_ID),
            STOSW_FORM_ID | REP_STOSW_FORM_ID => (false, 2, decoded.form_id == REP_STOSW_FORM_ID),
            STOSD_FORM_ID | REP_STOSD_FORM_ID => (false, 4, decoded.form_id == REP_STOSD_FORM_ID),
            STOSQ_FORM_ID | REP_STOSQ_FORM_ID => (false, 8, decoded.form_id == REP_STOSQ_FORM_ID),
            MOVSB_FORM_ID | REP_MOVSB_FORM_ID => (true, 1, decoded.form_id == REP_MOVSB_FORM_ID),
            MOVSW_FORM_ID | REP_MOVSW_FORM_ID => (true, 2, decoded.form_id == REP_MOVSW_FORM_ID),
            MOVSD_FORM_ID | REP_MOVSD_FORM_ID => (true, 4, decoded.form_id == REP_MOVSD_FORM_ID),
            MOVSQ_FORM_ID | REP_MOVSQ_FORM_ID => (true, 8, decoded.form_id == REP_MOVSQ_FORM_ID),
            _ => return Ok(None),
        };
        let state = &mut self.states[index];
        let mut rcx = state.process.read_register(register_id::GPR_BASE + 1)?;
        let mut rsi = state.process.read_register(register_id::GPR_BASE + 6)?;
        let mut rdi = state.process.read_register(register_id::GPR_BASE + 7)?;
        let rax = state.process.read_register(register_id::GPR_BASE)?;
        let store_bytes = rax.to_le_bytes();
        // A symbolic rax fills with symbolic bytes (the same byte expr in
        // every byte position for now — byte-exact slicing is a refinement).
        let rax_symbolic = state.registers.get(&register_id::GPR_BASE).map(|(e, _)| *e);

        let mut count = if rep { rcx } else { 1 };
        while count > 0 {
            let data: Vec<angryier_memory::ByteValue> = if is_move {
                // MOVS copies the source bytes — symbolic source bytes
                // carry through.
                state
                    .memory
                    .read_bytes(rsi, size)
                    .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?
            } else if let Some(expr) = rax_symbolic {
                vec![angryier_memory::ByteValue::Symbolic(expr); size]
            } else {
                store_bytes[..size]
                    .iter()
                    .map(|b| angryier_memory::ByteValue::Concrete(*b))
                    .collect()
            };
            state
                .memory
                .write_bytes(rdi, &data)
                .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
            if is_move {
                rsi = rsi.wrapping_add(size as u64);
            }
            rdi = rdi.wrapping_add(size as u64);
            count -= 1;
        }
        if rep {
            rcx = 0;
        }
        state.process.write_register(register_id::GPR_BASE + 1, rcx)?;
        state.process.write_register(register_id::GPR_BASE + 6, rsi)?;
        state.process.write_register(register_id::GPR_BASE + 7, rdi)?;
        let next_pc = decoded.address.wrapping_add(u64::from(decoded.length));
        state.process.write_pc(next_pc)?;
        state.process.step_count += 1;
        Ok(Some(SymbolicStepOutcome::Stepped { next_pc }))
    }

    /// Solves state `index`'s path constraints and returns a concrete value
    /// for each of its symbolic input registers — the "generate an input
    /// that reaches this state" primitive.
    pub fn solve_state(
        &self,
        index: usize,
        backend: &mut dyn SolverBackend,
        timeout: Duration,
    ) -> Result<Vec<(u32, u64)>, RuntimeError> {
        let state = self
            .states
            .get(index)
            .ok_or_else(|| RuntimeError::Execution("no such state".into()))?;
        let constraints: Vec<CanonicalConstraint> = state
            .constraints
            .iter()
            .enumerate()
            .filter_map(|(i, expr)| {
                self.arena.dependency_summary(*expr).map(|s| CanonicalConstraint {
                    id: ConstraintId(i as u64),
                    key: s.key,
                    expr: *expr,
                })
            })
            .collect();
        // Trivially-satisfiable predicate: the constraints themselves carry
        // the path; a literal `true` predicate asks for any model.
        let true_expr = self
            .arena
            .intern(angryier_expr::ExprNode {
                sort: angryier_expr::ExprSort::Bool,
                op: angryier_expr::ExprOp::Constant,
                operands: Vec::new(),
                immediate: vec![1],
            })
            .map_err(|e| RuntimeError::Execution(format!("{e:?}")))?;
        let key = self
            .arena
            .dependency_summary(true_expr)
            .map(|s| s.key)
            .ok_or_else(|| RuntimeError::Symbolic("missing predicate summary".into()))?;
        let query = SolverQuery::canonical(
            SolverQueryId(index as u64),
            &constraints,
            true_expr,
            key,
            state.process.target_profile,
            ConstraintCanonicalizationVersion(1),
            timeout,
        )
        .map_err(|e| RuntimeError::Solver(format!("{e:?}")))?;
        let result = backend.solve(&query);
        if !matches!(result.outcome, SolverOutcomeKind::Sat) {
            return Ok(Vec::new());
        }
        let mut bindings = Vec::new();
        for binding in &state.symbols {
            let expr_key = u64::from(binding.expression.0);
            let Some((_, bytes)) = result.model.iter().find(|(key, _)| *key == expr_key) else {
                continue;
            };
            let mut buffer = [0u8; 8];
            let len = bytes.len().min(8);
            buffer[..len].copy_from_slice(&bytes[..len]);
            bindings.push((binding.register, u64::from_le_bytes(buffer)));
        }
        Ok(bindings)
    }
}

impl<'a, D: Decoder> SymbolicSession<'a, D>
where
    D: Sync,
{
    /// Parallel symbolic exploration: partitions the live states across
    /// `workers` OS threads, each stepping its own subset privately (branch
    /// forks push to the worker's own queue — no shared work list), then
    /// concatenates the survivors back. The arena is shared read-mostly
    /// (ShardedExprArena is Sync), and each worker keeps its own evaluator
    /// — so per-worker states stay cache-local like the concolic pool.
    ///
    /// Returns the per-worker reports; `self.states` is refilled with all
    /// surviving states and `self.dead` accumulates their dead.
    pub fn run_parallel(
        &mut self,
        max_steps: u64,
        max_states: usize,
        workers: usize,
        timeout: Duration,
    ) -> Result<Vec<SymbolicRunReport>, RuntimeError> {
        let workers = workers.max(1);
        // Warm-up: step serially until we have at least `workers` live
        // states or the exploration stalls — the deal must see forked
        // states to be parallel.
        let mut warmup = 0u64;
        while self.states.len() < workers && warmup < max_steps && !self.states.is_empty() {
            if self.step_state(0).is_err() {
                break;
            }
            warmup += 1;
        }
        // Round-robin deal the states out.
        let mut shards: Vec<Vec<SymbolicState>> = (0..workers).map(|_| Vec::new()).collect();
        for (i, state) in self.states.drain(..).enumerate() {
            shards[i % workers].push(state);
        }

        let arena = self.arena;
        let runtime = self.runtime;
        let cfg = self.cfg;
        type ShardResult = Result<(SymbolicRunReport, Vec<SymbolicState>, Vec<SymbolicState>), RuntimeError>;
        let results: Vec<ShardResult> = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(workers);
            for shard in shards {
                if shard.is_empty() {
                    continue;
                }
                handles.push(scope.spawn(move || {
                    let mut sub = SymbolicSession {
                        runtime,
                        arena,
                        states: shard,
                        dead: Vec::new(),
                        cfg,
                        next_state_id: 1,
                        pending_merges: Vec::new(),
                    };
                    let report = sub.run(max_steps, max_states, None, timeout, false)?;
                    Ok((report, sub.states, sub.dead))
                }));
            }
            handles
                .into_iter()
                .map(|h| {
                    h.join()
                        .unwrap_or_else(|_| Err(RuntimeError::Execution("worker panicked".into())))
                })
                .collect()
        });

        let mut reports = Vec::new();
        for result in results {
            let (report, states, dead) = result?;
            self.states.extend(states);
            self.dead.extend(dead);
            reports.push(report);
        }
        Ok(reports)
    }
}
