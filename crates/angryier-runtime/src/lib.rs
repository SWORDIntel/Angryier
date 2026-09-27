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

use angryier_arch::{DecodedInstruction, Decoder, Operand, OperandKind};
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
    KernelReturnStub, SimProcedure, SimProcedureRegistry, SimResult, SimState,
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
    ExecutionState, FidelityLedger, PersistentConstraintLineage, PersistentRegisters, RegisterState, RegisterValue,
    StateOwnership, SymbolicRegisterState,
};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use angryier_types::{
    Address, AnalysisDebtKind, BlockId, CodeVersionGuard, ConstraintCanonicalizationVersion, ConstraintId,
    ContentIdentitySchemaVersion, ExprId, FidelityProfile, ImageId, SemanticFingerprintSchemaVersion, SemanticVersion,
    SolverQueryId, StateId, TargetProfileId,
};

#[cfg(feature = "xed")]
pub mod form_map;

#[cfg(feature = "script")]
pub mod script;

pub mod function_summaries;

/// Default stack size in bytes (64 KiB).
const STACK_SIZE: u64 = 0x1_0000;

/// Default stack base address (grows down from here).
const STACK_BASE: Address = 0x7fff_0000_0000;
/// Default heap base when the image has no segments.
const HEAP_BASE: u64 = 0x5000_0000;
/// Anonymous mmap arena starts here and grows downward (Linux-style).
const MMAP_BASE: u64 = 0x7f00_0000_0000;
/// Size of the mapped heap region managed by `brk`.
const HEAP_SIZE: u64 = 0x40_0000;

/// Base of the PE-driver import-stub region (see [`Runtime::load_pe_driver`]):
/// one 16-byte cell per import, whose first byte is a bare `ret` (`0xC3`) so
/// unhooked imports execute natively — `call` → `ret` returns to the caller
/// with RAX holding the caller's leftover value: defined, deterministic, zero
/// modeling.
pub const PE_DRIVER_STUB_BASE: u64 = 0x0000_7000_0000_0000;
/// Size of the PE-driver import-stub region. 1 MiB = 65,536 stubs at the
/// 16-byte stride — real drivers import in the hundreds (vhdmp.sys: 272),
/// and the region has the address space to the scratch block
/// (`PE_DRIVER_SCRATCH_BASE`) entirely free for growth.
const PE_DRIVER_STUB_SIZE: u64 = 0x0010_0000;
/// Stride of one import-stub cell.
const PE_DRIVER_STUB_STRIDE: u64 = 16;
/// Base of the PE-driver scratch region: the zeroed writable block standing
/// in for the kernel `DRIVER_OBJECT` handed to `DriverEntry` in RCX. RDX
/// points `0x200` into it as a `UNICODE_STRING`-shaped zeroed registry path
/// — drivers that only store the pointer work; contents are not modeled.
pub const PE_DRIVER_SCRATCH_BASE: u64 = 0x0000_7000_1000_0000;
/// Base of the PE-driver universal callback page: one `xor eax, eax; ret`
/// stub (STATUS_SUCCESS) that every unknown kernel callback/table entry
/// points at. DriverExtension->AddDevice, DriverStartIo, DriverUnload, and
/// all 28 MajorFunction dispatch slots land here, so a DriverEntry that
/// walks `DriverObject->DriverExtension->AddDevice` (the null-dereference
/// that killed real drivers at step ~10-24) calls a real stub and continues.
pub const PE_DRIVER_CALLBACK_BASE: u64 = angryier_models::KERNEL_UNIVERSAL_CALLBACK;
/// Size of the universal callback page.
const PE_DRIVER_CALLBACK_SIZE: u64 = 0x1000;
/// x64 `DRIVER_OBJECT` layout offsets used by the model (WDK wdm.h):
pub const DRIVER_OBJECT_OFFSET_DRIVER_EXTENSION: u64 = 0x30;
pub const DRIVER_OBJECT_OFFSET_DRIVER_NAME: u64 = 0x38;
pub const DRIVER_OBJECT_OFFSET_MAJOR_FUNCTION0: u64 = 0x70;
/// `IRP_MJ_MAXIMUM_FUNCTION + 1` dispatch slots.
const DRIVER_OBJECT_MAJOR_FUNCTION_COUNT: usize = 28;
/// `DRIVER_EXTENSION` block base inside the scratch region.
const PE_DRIVER_EXTENSION_OFF: u64 = 0x300;
/// Shared empty string buffer inside the scratch region (UNICODE_STRING
/// targets for DriverName / RegistryPath / ServiceKeyName: length 0).
const PE_DRIVER_STRING_BUF_OFF: u64 = 0x500;
/// Size of the PE-driver scratch region.
const PE_DRIVER_SCRATCH_SIZE: u64 = 0x10000; // 64KB: DRIVER_OBJECT + GS segment
/// Sentinel return address pushed for `DriverEntry`: returning from the
/// driver entry lands on the shared `exit` SimProcedure hook and terminates
/// cleanly — the same pattern `libc_start_main` uses.
pub const EXIT_HOOK: u64 = 0xdead_beef_0000;

/// The MSVC linker's DEFAULT `__security_cookie` value (`/GS` builds that
/// never ran `__security_init_cookie` ship this in `.data`).
const PE_DRIVER_DEFAULT_COOKIE: u64 = 0x0000_2B99_2DDF_A232;
/// Deterministic replacement cookie applied at driver load time. The real
/// Windows loader (Win10+) randomizes `__security_cookie` before running
/// any driver code, so `__security_init_cookie` never observes zero or the
/// DEFAULT value; without the same load-time patch, drivers whose init
/// fastfails on `cookie == 0 || cookie == DEFAULT` (`int 29h`) terminate
/// after ~15 steps. Non-zero, non-DEFAULT, and constant for replay.
///
/// The top 16 bits are ZERO because some driver builds' `__security_check_cookie`
/// is the old-CRT shape that succeeds only when `(cookie >> 48) == 0`
/// (`rol rcx,16; test cx,0xFFFF; jnz fastfail`) — real Windows init cookies
/// are 48-bit random values. TbtBusDrv's epilogue proved the requirement.
const PE_DRIVER_SECURITY_COOKIE: u64 = 0x0000_B3D5_E1F2_603C;
/// GS-relative cookie slot offset (`gs:[0x30]`): the x64 kernel-mode frame
/// check reads and compares this slot.
const PE_DRIVER_GS_COOKIE_OFF: u64 = 0x30;

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

/// A cached decode+lowering for one PC, so revisiting a PC whose instruction
/// bytes and code-page versions are unchanged skips decode, semantic emission,
/// sealing, and lowering. The block is shared (cheap `Process` clones); the
/// cached bytes and guards are the staleness key — a hit requires the exact
/// instruction bytes and covering code-page guards to still match, which is
/// precisely the condition under which re-decoding and re-lowering would
/// reproduce this block bit for bit.
#[derive(Clone)]
struct CachedStep {
    /// The lowered block (also mirrored in `Process::block_cache`).
    block: Arc<IrBlock>,
    /// Decoded instruction length.
    length: u8,
    /// Decoded form id.
    form_id: u32,
    /// Instruction bytes (padded to the containing region bound) at the time
    /// of caching.
    bytes: Vec<u8>,
    /// Code-page guards covering the instruction at the time of caching.
    guards: Vec<CodeVersionGuard>,
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
    /// Decode+lowering reuse cache for stepping, keyed by PC. Hits require
    /// unchanged instruction bytes and code-page guards, so self-modifying
    /// code falls back to a fresh decode+lower.
    step_cache: BTreeMap<Address, CachedStep>,
    pub simproc_hooks: BTreeMap<Address, String>,
    /// PE-driver import stubs (see [`Runtime::load_pe_driver`]): stub
    /// address → (dll, export name or `#ordinal`). Set by `load_pe_driver`.
    pub pe_import_stubs: BTreeMap<Address, (String, String)>,
    /// Instance SimProcedure hooks keyed by call-target address. Checked
    /// before the name-keyed `simproc_hooks` in `step_with`, with
    /// call-correct return semantics (RIP = `[RSP]`; RSP += 8).
    pub simproc_instances: BTreeMap<Address, Arc<dyn SimProcedure>>,
    /// Windows kernel pool model state when attached
    /// ([`Runtime::attach_kernel_pool_model`]); the dispatch loop records
    /// modeled alloc/free events (pointer + caller) into it.
    pub kernel_pool: Option<std::sync::Arc<angryier_models::KernelPoolTracker>>,
    /// PCI configuration-address register (port 0xCF8 write value): the
    /// runtime's port-I/O model consults it for config reads at 0xCFC-0xCFF
    /// (see `execute_port_in`/`execute_port_out`).
    pub pci_config_address: u32,
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
    /// Next anonymous `mmap` base — grows downward from [`MMAP_BASE`].
    pub mmap_next: u64,
    /// Named file contents the process may `openat` — seeded by the
    /// caller for concrete input files (path → bytes).
    pub files: BTreeMap<String, Vec<u8>>,
    /// Open file descriptors: fd → (bytes, read position).
    pub open_fds: BTreeMap<u64, (Vec<u8>, usize)>,
    /// File paths whose contents should materialize as symbolic bytes in
    /// symbolic sessions (concrete sessions serve `files` bytes).
    pub symbolic_files: std::collections::BTreeSet<String>,
    /// fds opened on symbolic paths — symbolic `read` materializes bytes.
    pub symbolic_fds: std::collections::BTreeSet<u64>,
    /// Where `argv[0]`'s NUL-terminated string landed on the stack —
    /// `symbolize_argv0` overwrites it with symbolic bytes.
    pub argv0_addr: Option<u64>,
    /// Concrete stdin the `read(0)` model serves — seeded for input
    /// replay/fuzzing.
    pub stdin: Vec<u8>,
    /// stdin read position.
    pub stdin_pos: usize,
    /// Next fd to allocate (3+ — 0/1/2 are std streams).
    pub next_fd: u64,
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

    /// Hooks a PE-driver import to a kernel-return stub: calls routed through
    /// the import's IAT slot land on [`KernelReturnStub { value }`] instead
    /// of executing the native stub.
    ///
    /// The dll matches case-insensitively (Windows export resolution is
    /// case-insensitive); the export name matches exactly. Fails when the
    /// process carries no such import — e.g. for non-driver processes.
    pub fn hook_export_return(&mut self, dll: &str, export_name: &str, value: u64) -> Result<(), RuntimeError> {
        let dll_lower = dll.to_ascii_lowercase();
        let address = self
            .pe_import_stubs
            .iter()
            .find(|(_, (stub_dll, stub_export))| {
                stub_dll.to_ascii_lowercase() == dll_lower && stub_export == export_name
            })
            .map(|(address, _)| *address)
            .ok_or_else(|| RuntimeError::SimProcedure(format!("unknown PE import: {dll}!{export_name}")))?;
        self.simproc_instances
            .insert(address, Arc::new(KernelReturnStub { value }));
        Ok(())
    }

    /// Iterates the PE-driver import stubs as (stub address, dll, export
    /// name or `#ordinal`) — diagnostics and scripting hooks. Empty for
    /// processes not loaded through [`Runtime::load_pe_driver`].
    pub fn pe_imports(&self) -> impl Iterator<Item = (&Address, &str, &str)> {
        self.pe_import_stubs
            .iter()
            .map(|(address, (dll, name))| (address, dll.as_str(), name.as_str()))
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
        read_register_u64(&self.state.registers, register_id::RIP.0)
    }

    /// Writes the program counter (RIP).
    ///
    /// In-place COW write: the base map mutates directly while uniquely held
    /// and is cloned exactly once when a snapshot shares it (the entry state
    /// captured at load time, or a forked sibling `Process`), so sequential
    /// stepping pays no per-write overlay copy.
    fn write_pc(&mut self, pc: Address) -> Result<(), RuntimeError> {
        self.state
            .registers
            .write_in_place(register_id::RIP.0, &pc.to_le_bytes())
            .map_err(|e| RuntimeError::Register(format!("{e:?}")))
    }

    /// Reads a register as u64.
    pub fn read_register(&self, register: u32) -> Result<u64, RuntimeError> {
        read_register_u64(&self.state.registers, register)
    }

    /// Writes a 64-bit value into an architectural register.
    ///
    /// In-place COW write; see [`write_pc`](Self::write_pc) for the snapshot
    /// contract.
    pub fn write_register(&mut self, register: u32, value: u64) -> Result<(), RuntimeError> {
        self.state
            .registers
            .write_in_place(register, &value.to_le_bytes())
            .map_err(|e| RuntimeError::Register(format!("{e:?}")))
    }
}

/// Reads a register as u64 without allocating: `RegisterState::read` copies
/// the value into a fresh `Vec<u8>` per call, while `read_value` hands back
/// an `Arc` clone for concrete values. Symbolic registers surface the same
/// error `read` would produce.
fn read_register_u64(registers: &PersistentRegisters, register: u32) -> Result<u64, RuntimeError> {
    match registers.read_value(register) {
        Ok(RegisterValue::Concrete(bytes)) => {
            let mut buf = [0u8; 8];
            let len = bytes.len().min(8);
            buf[..len].copy_from_slice(&bytes[..len]);
            Ok(u64::from_le_bytes(buf))
        }
        Ok(RegisterValue::Symbolic { .. }) => Err(RuntimeError::Register(format!(
            "{:?}",
            angryier_state::RegisterError::SymbolicValue(register)
        ))),
        Err(e) => Err(RuntimeError::Register(format!("{e:?}"))),
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
    /// Attaches the Windows kernel pool model to a PE-driver process:
    /// binds `ExAllocatePool*` imports to a fresh-pointer allocator and
    /// `ExFreePool*` to a free stub (both sharing `tracker`), and stores
    /// the tracker so the dispatch loop records (pointer, caller) events —
    /// a pointer freed twice lands in
    /// [`angryier_models::KernelPoolReport::double_frees`].
    ///
    /// Matching is case-insensitive on the DLL (Windows export resolution
    /// is case-insensitive) and exact on the export name. Imports that
    /// match nothing keep their existing bindings.
    pub fn attach_kernel_pool_model(
        &self,
        process: &mut Process,
        tracker: std::sync::Arc<angryier_models::KernelPoolTracker>,
    ) -> Result<(), RuntimeError> {
        const ALLOC_NAMES: [&str; 5] = [
            "ExAllocatePool",
            "ExAllocatePoolWithTag",
            "ExAllocatePoolWithQuota",
            "ExAllocatePoolWithTagPriority",
            "ExAllocatePool2",
        ];
        const FREE_NAMES: [&str; 3] = ["ExFreePool", "ExFreePoolWithTag", "ExFreePoolWithQuota"];
        let alloc: Arc<dyn SimProcedure> = Arc::new(angryier_models::KernelAllocProcedure {
            tracker: tracker.clone(),
        });
        let free: Arc<dyn SimProcedure> = Arc::new(angryier_models::KernelFreeProcedure {
            tracker: tracker.clone(),
        });
        let create_device: Arc<dyn SimProcedure> = Arc::new(angryier_models::KernelCreateDeviceProcedure {
            tracker: tracker.clone(),
        });
        let attach_device: Arc<dyn SimProcedure> = Arc::new(angryier_models::KernelAttachDeviceProcedure {
            tracker: tracker.clone(),
        });
        let resolve: Arc<dyn SimProcedure> = Arc::new(angryier_models::KernelResolveRoutineProcedure);
        let init_unicode: Arc<dyn SimProcedure> = Arc::new(angryier_models::KernelInitUnicodeStringProcedure);
        let create_thread: Arc<dyn SimProcedure> = Arc::new(angryier_models::KernelCreateSystemThreadProcedure);
        let build_irp: Arc<dyn SimProcedure> = Arc::new(angryier_models::KernelBuildIrpProcedure {
            tracker: tracker.clone(),
        });
        let get_version: Arc<dyn SimProcedure> = Arc::new(angryier_models::KernelGetVersionProcedure);
        let get_device_pointer: Arc<dyn SimProcedure> =
            Arc::new(angryier_models::KernelGetDeviceObjectPointerProcedure {
                tracker: tracker.clone(),
            });
        let query_perf: Arc<dyn SimProcedure> = Arc::new(angryier_models::KernelQueryPerformanceCounterProcedure);
        const CREATE_DEVICE_NAMES: [&str; 1] = ["IoCreateDevice"];
        const ATTACH_DEVICE_NAMES: [&str; 1] = ["IoAttachDevice"];
        const RESOLVE_NAMES: [&str; 1] = ["MmGetSystemRoutineAddress"];
        const INIT_UNICODE_NAMES: [&str; 1] = ["RtlInitUnicodeString"];
        const CREATE_THREAD_NAMES: [&str; 1] = ["PsCreateSystemThread"];
        const BUILD_IRP_NAMES: [&str; 1] = ["IoBuildDeviceIoControlRequest"];
        const GET_VERSION_NAMES: [&str; 1] = ["RtlGetVersion"];
        const GET_DEVICE_POINTER_NAMES: [&str; 1] = ["IoGetDeviceObjectPointer"];
        const QUERY_PERF_NAMES: [&str; 1] = ["KeQueryPerformanceCounter"];
        let stubs: Vec<(Address, String, String)> = process
            .pe_imports()
            .map(|(address, dll, export)| (*address, dll.to_string(), export.to_string()))
            .collect();
        for (address, dll, export) in stubs {
            let dll_lower = dll.to_ascii_lowercase();
            let is_nt = dll_lower == "ntoskrnl.exe" || dll_lower == "hal.dll";
            if !is_nt {
                continue;
            }
            if ALLOC_NAMES.contains(&export.as_str()) {
                process.simproc_instances.insert(address, alloc.clone());
            } else if FREE_NAMES.contains(&export.as_str()) {
                process.simproc_instances.insert(address, free.clone());
            } else if CREATE_DEVICE_NAMES.contains(&export.as_str()) {
                process.simproc_instances.insert(address, create_device.clone());
            } else if ATTACH_DEVICE_NAMES.contains(&export.as_str()) {
                process.simproc_instances.insert(address, attach_device.clone());
            } else if RESOLVE_NAMES.contains(&export.as_str()) {
                process.simproc_instances.insert(address, resolve.clone());
            } else if INIT_UNICODE_NAMES.contains(&export.as_str()) {
                process.simproc_instances.insert(address, init_unicode.clone());
            } else if CREATE_THREAD_NAMES.contains(&export.as_str()) {
                process.simproc_instances.insert(address, create_thread.clone());
            } else if BUILD_IRP_NAMES.contains(&export.as_str()) {
                process.simproc_instances.insert(address, build_irp.clone());
            } else if GET_VERSION_NAMES.contains(&export.as_str()) {
                process.simproc_instances.insert(address, get_version.clone());
            } else if GET_DEVICE_POINTER_NAMES.contains(&export.as_str()) {
                process.simproc_instances.insert(address, get_device_pointer.clone());
            } else if QUERY_PERF_NAMES.contains(&export.as_str()) {
                process.simproc_instances.insert(address, query_perf.clone());
            } else {
                // Deterministic default: STATUS_SUCCESS instead of whatever
                // garbage RAX carries into a naked `ret` stub. Debt-recorded
                // (manifest tier-2/tier-3): failure paths are unexplored
                // until symbolic NTSTATUS sets exist.
                process
                    .simproc_instances
                    .insert(address, Arc::new(KernelReturnStub { value: 0 }));
            }
        }
        process.kernel_pool = Some(tracker);
        Ok(())
    }

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
    /// Returns (rsp, argv0 string address).
    fn initial_stack_pointer(
        &self,
        image: &LoadedImage,
        memory: &mut PersistentMemory,
    ) -> Result<(u64, u64), RuntimeError> {
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
        Ok((rsp, argv0_addr))
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
            CMPSB_FORM_ID, CMPSD_FORM_ID, CMPSQ_FORM_ID, CMPSW_FORM_ID, LODSB_FORM_ID, LODSD_FORM_ID, LODSQ_FORM_ID,
            LODSW_FORM_ID, MOVSB_FORM_ID, MOVSD_FORM_ID, MOVSQ_FORM_ID, MOVSW_FORM_ID, REP_INSB_FORM_ID,
            REP_INSD_FORM_ID, REP_INSW_FORM_ID, REP_MOVSB_FORM_ID, REP_MOVSD_FORM_ID, REP_MOVSQ_FORM_ID,
            REP_MOVSW_FORM_ID, REP_OUTSB_FORM_ID, REP_OUTSD_FORM_ID, REP_OUTSW_FORM_ID, REP_STOSB_FORM_ID,
            REP_STOSD_FORM_ID, REP_STOSQ_FORM_ID, REP_STOSW_FORM_ID, REPE_CMPSB_FORM_ID, REPE_CMPSD_FORM_ID,
            REPE_CMPSQ_FORM_ID, REPE_CMPSW_FORM_ID, REPE_SCASB_FORM_ID, REPE_SCASD_FORM_ID, REPE_SCASQ_FORM_ID,
            REPE_SCASW_FORM_ID, REPNE_CMPSB_FORM_ID, REPNE_CMPSD_FORM_ID, REPNE_CMPSQ_FORM_ID, REPNE_CMPSW_FORM_ID,
            REPNE_SCASB_FORM_ID, REPNE_SCASD_FORM_ID, REPNE_SCASQ_FORM_ID, REPNE_SCASW_FORM_ID, SCASB_FORM_ID,
            SCASD_FORM_ID, SCASQ_FORM_ID, SCASW_FORM_ID, STOSB_FORM_ID, STOSD_FORM_ID, STOSQ_FORM_ID, STOSW_FORM_ID,
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
            let mut data = [ByteValue::Concrete(0); 8];
            process
                .state
                .memory
                .read_into(rsi, &mut data[..lod_size])
                .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
            let mut value = 0u64;
            for (i, byte) in data[..lod_size].iter().enumerate() {
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

        let rep_in_size = match decoded.form_id {
            REP_INSB_FORM_ID => 1usize,
            REP_INSW_FORM_ID => 2,
            REP_INSD_FORM_ID => 4,
            _ => 0,
        };
        if rep_in_size > 0 {
            let mut rcx = process.read_register(register_id::GPR_BASE + 1)?;
            let mut rdi = process.read_register(register_id::GPR_BASE + 7)?;
            let rflags = process.read_register(register_id::RFLAGS.0)?;
            let df = (rflags & (1 << 10)) != 0;
            let delta = if df {
                (rep_in_size as u64).wrapping_neg()
            } else {
                rep_in_size as u64
            };
            let zeros = [ByteValue::Concrete(0); 4];
            while rcx > 0 {
                process.state.memory = process
                    .state
                    .memory
                    .write(rdi, &zeros[..rep_in_size])
                    .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
                rdi = rdi.wrapping_add(delta);
                rcx -= 1;
            }
            process.write_register(register_id::GPR_BASE + 7, rdi)?;
            process.write_register(register_id::GPR_BASE + 1, 0)?;
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

        let rep_out_size = match decoded.form_id {
            REP_OUTSB_FORM_ID => 1usize,
            REP_OUTSW_FORM_ID => 2,
            REP_OUTSD_FORM_ID => 4,
            _ => 0,
        };
        if rep_out_size > 0 {
            let mut rcx = process.read_register(register_id::GPR_BASE + 1)?;
            let mut rsi = process.read_register(register_id::GPR_BASE + 6)?;
            let rflags = process.read_register(register_id::RFLAGS.0)?;
            let df = (rflags & (1 << 10)) != 0;
            let delta = if df {
                (rep_out_size as u64).wrapping_neg()
            } else {
                rep_out_size as u64
            };
            let mut buf = [ByteValue::Concrete(0); 4];
            while rcx > 0 {
                process
                    .state
                    .memory
                    .read_into(rsi, &mut buf[..rep_out_size])
                    .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
                rsi = rsi.wrapping_add(delta);
                rcx -= 1;
            }
            process.write_register(register_id::GPR_BASE + 6, rsi)?;
            process.write_register(register_id::GPR_BASE + 1, 0)?;
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

        #[derive(Clone, Copy, PartialEq, Eq)]
        enum RepCondition {
            None,
            Repe,
            Repne,
        }

        let cmps_scas_info = match decoded.form_id {
            CMPSB_FORM_ID => Some((true, 1usize, RepCondition::None)),
            CMPSW_FORM_ID => Some((true, 2, RepCondition::None)),
            CMPSD_FORM_ID => Some((true, 4, RepCondition::None)),
            CMPSQ_FORM_ID => Some((true, 8, RepCondition::None)),
            REPE_CMPSB_FORM_ID => Some((true, 1, RepCondition::Repe)),
            REPE_CMPSW_FORM_ID => Some((true, 2, RepCondition::Repe)),
            REPE_CMPSD_FORM_ID => Some((true, 4, RepCondition::Repe)),
            REPE_CMPSQ_FORM_ID => Some((true, 8, RepCondition::Repe)),
            REPNE_CMPSB_FORM_ID => Some((true, 1, RepCondition::Repne)),
            REPNE_CMPSW_FORM_ID => Some((true, 2, RepCondition::Repne)),
            REPNE_CMPSD_FORM_ID => Some((true, 4, RepCondition::Repne)),
            REPNE_CMPSQ_FORM_ID => Some((true, 8, RepCondition::Repne)),
            SCASB_FORM_ID => Some((false, 1, RepCondition::None)),
            SCASW_FORM_ID => Some((false, 2, RepCondition::None)),
            SCASD_FORM_ID => Some((false, 4, RepCondition::None)),
            SCASQ_FORM_ID => Some((false, 8, RepCondition::None)),
            REPE_SCASB_FORM_ID => Some((false, 1, RepCondition::Repe)),
            REPE_SCASW_FORM_ID => Some((false, 2, RepCondition::Repe)),
            REPE_SCASD_FORM_ID => Some((false, 4, RepCondition::Repe)),
            REPE_SCASQ_FORM_ID => Some((false, 8, RepCondition::Repe)),
            REPNE_SCASB_FORM_ID => Some((false, 1, RepCondition::Repne)),
            REPNE_SCASW_FORM_ID => Some((false, 2, RepCondition::Repne)),
            REPNE_SCASD_FORM_ID => Some((false, 4, RepCondition::Repne)),
            REPNE_SCASQ_FORM_ID => Some((false, 8, RepCondition::Repne)),
            _ => None,
        };

        if let Some((is_cmps, size, rep_cond)) = cmps_scas_info {
            let mut rcx = process.read_register(register_id::GPR_BASE + 1)?;
            let mut rsi = process.read_register(register_id::GPR_BASE + 6)?;
            let mut rdi = process.read_register(register_id::GPR_BASE + 7)?;
            let rax = process.read_register(register_id::GPR_BASE)?;
            let rflags = process.read_register(register_id::RFLAGS.0)?;
            let df = (rflags & (1 << 10)) != 0;
            let delta = if df { (size as u64).wrapping_neg() } else { size as u64 };

            let is_rep = rep_cond != RepCondition::None;
            let mut count = if is_rep { rcx } else { 1 };

            while count > 0 {
                let (val1, val2) = if is_cmps {
                    let mut data_rsi = [ByteValue::Concrete(0); 8];
                    let mut data_rdi = [ByteValue::Concrete(0); 8];
                    process
                        .state
                        .memory
                        .read_into(rsi, &mut data_rsi[..size])
                        .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
                    process
                        .state
                        .memory
                        .read_into(rdi, &mut data_rdi[..size])
                        .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
                    let mut v1 = 0u64;
                    let mut v2 = 0u64;
                    for (i, byte) in data_rsi[..size].iter().enumerate() {
                        let b = match byte {
                            ByteValue::Concrete(b) => *b,
                            ByteValue::Symbolic(_) => 0,
                        };
                        v1 |= u64::from(b) << (i * 8);
                    }
                    for (i, byte) in data_rdi[..size].iter().enumerate() {
                        let b = match byte {
                            ByteValue::Concrete(b) => *b,
                            ByteValue::Symbolic(_) => 0,
                        };
                        v2 |= u64::from(b) << (i * 8);
                    }
                    (v1, v2)
                } else {
                    let mut data_rdi = [ByteValue::Concrete(0); 8];
                    process
                        .state
                        .memory
                        .read_into(rdi, &mut data_rdi[..size])
                        .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
                    let mut v2 = 0u64;
                    for (i, byte) in data_rdi[..size].iter().enumerate() {
                        let b = match byte {
                            ByteValue::Concrete(b) => *b,
                            ByteValue::Symbolic(_) => 0,
                        };
                        v2 |= u64::from(b) << (i * 8);
                    }
                    let v1 = match size {
                        1 => rax & 0xFF,
                        2 => rax & 0xFFFF,
                        4 => rax & 0xFFFF_FFFF,
                        _ => rax,
                    };
                    (v1, v2)
                };

                let bits = size * 8;
                let mask = if bits == 64 { !0u64 } else { (1u64 << bits) - 1 };
                let sign_bit = 1u64 << (bits - 1);
                let a = val1 & mask;
                let b = val2 & mask;
                let res = a.wrapping_sub(b) & mask;

                let cf = a < b;
                let pf = (res as u8).count_ones() % 2 == 0;
                let af = ((a ^ b ^ res) & 0x10) != 0;
                let zf = res == 0;
                let sf = (res & sign_bit) != 0;
                let of = ((a ^ b) & (a ^ res) & sign_bit) != 0;

                let mut new_flags = 0u64;
                if cf {
                    new_flags |= 1 << 0;
                }
                if pf {
                    new_flags |= 1 << 2;
                }
                if af {
                    new_flags |= 1 << 4;
                }
                if zf {
                    new_flags |= 1 << 6;
                }
                if sf {
                    new_flags |= 1 << 7;
                }
                if of {
                    new_flags |= 1 << 11;
                }

                let cur_rflags = process.read_register(register_id::RFLAGS.0)?;
                let updated_rflags = (cur_rflags & !0x8D5) | (new_flags & 0x8D5);
                process.write_register(register_id::RFLAGS.0, updated_rflags)?;

                if is_cmps {
                    rsi = rsi.wrapping_add(delta);
                }
                rdi = rdi.wrapping_add(delta);

                count -= 1;

                if is_rep {
                    rcx -= 1;
                    match rep_cond {
                        RepCondition::Repe if !zf => break,
                        RepCondition::Repne if zf => break,
                        _ => {}
                    }
                }
            }

            if is_cmps {
                process.write_register(register_id::GPR_BASE + 6, rsi)?;
            }
            process.write_register(register_id::GPR_BASE + 7, rdi)?;
            if is_rep {
                process.write_register(register_id::GPR_BASE + 1, rcx)?;
            }

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
        let mut data = [ByteValue::Concrete(0); 8];
        while count > 0 {
            if is_move {
                process
                    .state
                    .memory
                    .read_into(rsi, &mut data[..size])
                    .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
            } else {
                for (slot, byte) in data[..size].iter_mut().zip(store_bytes[..size].iter()) {
                    *slot = ByteValue::Concrete(*byte);
                }
            }
            process.state.memory = process
                .state
                .memory
                .write(rdi, &data[..size])
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

    /// Loads a dynamically-linked ELF: maps the main image plus every
    /// `DT_NEEDED` library found under `lib_dirs` (or the default system
    /// paths), applies `R_X86_64_RELATIVE`/`GLOB_DAT`/`JUMP_SLOT`/`64`
    /// relocations eagerly (BIND_NOW), and starts at the main image's
    /// entry — an angr-style static linker, no `ld.so` process.
    pub fn load_elf_dynamic(&self, bytes: &[u8], lib_dirs: &[&str]) -> Result<Process, RuntimeError> {
        let loader = Elf64Loader::new();
        let main = loader.load(bytes).map_err(RuntimeError::Loader)?;
        const DYN_BASE: u64 = 0x400000;
        const LIB_BASE: u64 = 0x7f00_0000_0000;
        // Main image bias: ET_EXEC keeps its VAs; ET_DYN slides to DYN_BASE.
        let is_dyn = main.dynamic.is_some();
        let main_bias = if is_dyn { DYN_BASE } else { 0 };
        let mut images: Vec<(LoadedImage, u64)> = Vec::new();
        // Resolve needed libs breadth-first (name → file under lib_dirs).
        let mut needed: Vec<String> = main.dynamic.as_ref().map(|d| d.needed.clone()).unwrap_or_default();
        let mut seen: std::collections::BTreeSet<String> = needed.iter().cloned().collect();
        let mut lib_next = LIB_BASE;
        while let Some(name) = needed.pop() {
            let path = lib_dirs
                .iter()
                .map(|d| format!("{d}/{name}"))
                .chain([
                    format!("/lib/x86_64-linux-gnu/{name}"),
                    format!("/usr/lib/x86_64-linux-gnu/{name}"),
                    format!("/lib64/{name}"),
                ])
                .find_map(|p| std::fs::read(&p).ok());
            let Some(lib_bytes) = path else { continue };
            let lib = match loader.load(&lib_bytes) {
                Ok(l) => l,
                Err(_) => continue,
            };
            // Newly-needed libs (transitive deps).
            if let Some(dyn_) = &lib.dynamic {
                for n in &dyn_.needed {
                    if seen.insert(n.clone()) {
                        needed.push(n.clone());
                    }
                }
            }
            let bias = lib_next;
            let top = lib
                .segments
                .iter()
                .map(|s| s.address + s.bytes.len() as u64)
                .max()
                .unwrap_or(0);
            lib_next = lib_next.wrapping_sub(top + 0x1000);
            images.push((lib, bias));
        }
        images.insert(0, (main, main_bias));

        // Merge all images' segments (biased) into one memory, apply relocs.
        let mut all_segments: Vec<MemoryRegion> = Vec::new();
        let mut loaded: Vec<(u64, u64, Vec<u8>, bool, bool, bool)> = Vec::new(); // (base, len, bytes, rwx)
        for (image, bias) in &images {
            for seg in &image.segments {
                let base = seg.address + bias;
                let size = seg.bytes.len() as u64;
                if size == 0 {
                    continue;
                }
                all_segments.push(MemoryRegion {
                    object: angryier_types::ObjectId(0),
                    base,
                    size,
                    readable: seg.readable,
                    writable: seg.writable,
                    executable: seg.executable,
                });
                loaded.push((
                    base,
                    size,
                    seg.bytes.clone(),
                    seg.readable,
                    seg.writable,
                    seg.executable,
                ));
            }
        }
        all_segments.push(MemoryRegion {
            object: angryier_types::ObjectId(2),
            base: HEAP_BASE,
            size: HEAP_SIZE,
            readable: true,
            writable: true,
            executable: false,
        });
        all_segments.push(MemoryRegion {
            object: angryier_types::ObjectId(1),
            base: STACK_BASE - STACK_SIZE,
            size: STACK_SIZE,
            readable: true,
            writable: true,
            executable: false,
        });
        all_segments.sort_by_key(|r| r.base);
        let mut memory = PersistentMemory::new(all_segments).map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
        for (base, _, bytes, _, _, _) in &loaded {
            memory = memory
                .load_concrete(*base, bytes)
                .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
        }

        // Apply relocations across all images.
        for (image, bias) in &images {
            let Some(dyn_) = &image.dynamic else { continue };
            let rela = dyn_.rela.iter().chain(dyn_.jmprel.iter());
            for r in rela {
                let addr = r.offset + bias;
                let value: u64 = match r.r#type {
                    8 => bias.wrapping_add(r.addend as u64), // R_X86_64_RELATIVE
                    37 => {
                        // IRELATIVE: call the resolver (bias+addend) with a
                        // sentinel return address; its rax is the GOT value.
                        match self.run_resolver(&memory, bias.wrapping_add(r.addend as u64)) {
                            Some(v) => v,
                            None => bias.wrapping_add(r.addend as u64), // resolver itself
                        }
                    }
                    6 | 7 | 1 => {
                        // GLOB_DAT / JUMP_SLOT / 64 — resolve the symbol
                        // across every image's dynamic symtab.
                        self.resolve_dyn_symbol(&images, dyn_, r.symbol).unwrap_or(0)
                    }
                    _ => continue,
                };
                memory = memory
                    .load_concrete(addr, &value.to_le_bytes())
                    .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
            }
        }

        // Seed a minimal TLS block (ld.so would normally do this): the
        // TCB's first qword is its own address; fs base points at it so
        // TPOFF64 slots resolve to mapped memory.
        const TLS_BASE: u64 = 0x7f00_1000_0000;
        memory = memory
            .with_region(MemoryRegion {
                object: angryier_types::ObjectId(4),
                base: TLS_BASE,
                size: 0x1000,
                readable: true,
                writable: true,
                executable: false,
            })
            .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
        memory = memory
            .load_concrete(TLS_BASE, &TLS_BASE.to_le_bytes())
            .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
        let main_entry = images[0].0.entry + images[0].1;
        let mut process = self.load_image_with_memory(images.remove(0).0, memory, main_entry, main_bias)?;
        process.write_register(register_id::FS_BASE.0, TLS_BASE)?;
        // Hook libc entry glue: `__libc_start_main` tail-calls into `main`.
        if let Some(addr) = self.find_dyn_symbol(&images, "__libc_start_main") {
            process.hook_simproc(addr, "libc_start_main");
        }
        Ok(process)
    }

    /// Evaluates an IRELATIVE resolver: a leaf function at `resolver` that
    /// returns the chosen implementation in rax. Runs on a sentinel-framed
    /// throwaway process over the loaded memory; bounded to 512 steps.
    fn run_resolver(&self, memory: &PersistentMemory, resolver: u64) -> Option<u64> {
        const SENTINEL: u64 = 0xdead_0000;
        let mut memory = memory.clone();
        // Sentinel stack: a tiny region whose top holds the return address.
        let sentinel_stack = MemoryRegion {
            object: angryier_types::ObjectId(9),
            base: SENTINEL - 0x1000,
            size: 0x1000,
            readable: true,
            writable: true,
            executable: false,
        };
        memory = memory.with_region(sentinel_stack).ok()?;
        memory = memory.load_concrete(SENTINEL - 8, &SENTINEL.to_le_bytes()).ok()?;
        let reg_file = Intel64RegisterFile::canonical();
        let widths: Vec<(u32, usize)> = reg_file
            .architectural_registers
            .iter()
            .map(|(reg, bits)| (reg.0, usize::from(*bits).div_ceil(8)))
            .collect();
        let mut registers = PersistentRegisters::from_widths(widths).ok()?;
        registers = registers.write(register_id::RIP.0, &resolver.to_le_bytes()).ok()?;
        registers = registers
            .write(register_id::GPR_BASE + 4, &(SENTINEL - 8).to_le_bytes())
            .ok()?;
        registers = registers.write(register_id::RFLAGS.0, &0x202u64.to_le_bytes()).ok()?;
        let state = ExecutionState {
            id: StateId(0),
            parent: None,
            target_profile: self.target_profile,
            registers,
            memory,
            constraints: PersistentConstraintLineage::new(),
            ownership: StateOwnership::default(),
            fidelity: FidelityLedger::new(FidelityProfile::Prove),
        };
        let mut process = Process {
            image_id: angryier_types::ImageId(0),
            target_profile: self.target_profile,
            entry: resolver,
            entry_state: state.clone(),
            state,
            block_cache: BTreeMap::new(),
            step_cache: BTreeMap::new(),
            simproc_hooks: BTreeMap::new(),
            pe_import_stubs: BTreeMap::new(),
            simproc_instances: BTreeMap::new(),
            kernel_pool: None,
            pci_config_address: 0,
            symbols: Vec::new(),
            trace: Vec::new(),
            syscalls: SyscallModel::new(),
            program_break: 0,
            heap_end: 0,
            mmap_next: MMAP_BASE,
            files: BTreeMap::new(),
            open_fds: BTreeMap::new(),
            symbolic_files: std::collections::BTreeSet::new(),
            symbolic_fds: std::collections::BTreeSet::new(),
            argv0_addr: None,
            stdin: Vec::new(),
            stdin_pos: 0,
            next_fd: 3,
            next_block_id: 0,
            step_count: 0,
            simproc_dispatches: 0,
            terminated: false,
        };
        for _ in 0..512 {
            if process.pc().ok()? == SENTINEL {
                return process.read_register(register_id::GPR_BASE).ok();
            }
            if self.step(&mut process).is_err() {
                return None;
            }
        }
        None
    }

    /// Finds a dynamic symbol by name across all loaded images.
    fn find_dyn_symbol(&self, images: &[(LoadedImage, u64)], name: &str) -> Option<u64> {
        for (lib, lib_bias) in images {
            let Some(ld) = &lib.dynamic else { continue };
            for i in 0..4096u64 {
                let sym_va = ld.symtab + i * 24;
                let Some(raw) = read_u64_va(lib, sym_va) else { break };
                let st_name = raw as u32;
                let st_value = read_u64_va(lib, sym_va + 8).unwrap_or(0);
                if st_name == 0 && st_value == 0 {
                    if i == 0 { continue } else { break }
                }
                if st_name == 0 {
                    continue;
                }
                let Some(sname) = read_cstr_va(lib, ld.strtab + u64::from(st_name)) else {
                    continue;
                };
                if sname == name && st_value != 0 {
                    return Some(st_value + lib_bias);
                }
            }
        }
        None
    }

    /// Looks up a dynamic symbol by index in `dyn_`'s symtab across all
    /// loaded images, returning the biased VA.
    fn resolve_dyn_symbol(
        &self,
        images: &[(LoadedImage, u64)],
        dyn_: &angryier_loader::DynamicInfo,
        sym_index: u32,
    ) -> Option<u64> {
        // Read the symbol's st_name from the defining image's symtab — we
        // need the image's own memory view; reconstruct via segments.
        // `sym_index` indexes `dyn_`'s symtab — which belongs to the image
        // that owns dyn_; caller passes that image's bias implicitly via
        // the dyn_ slice. Find the owner image:
        for (owner, _bias) in images {
            if owner.dynamic.as_ref().map(|d| (d.symtab, d.strtab)) != Some((dyn_.symtab, dyn_.strtab)) {
                continue;
            }
            let sym_entry_va = dyn_.symtab + u64::from(sym_index) * 24;
            let name_off = read_u64_va(owner, sym_entry_va)? as u32;
            let name = read_cstr_va(owner, dyn_.strtab + u64::from(name_off))?;
            // Now find `name` in every image's dynsym.
            for (lib, lib_bias) in images {
                let Some(ld) = &lib.dynamic else { continue };
                let str_base = ld.strtab;
                // Bounded scan — dynsym[0] is the null entry (st_name==0,
                // st_value==0), not a terminator; skip it explicitly.
                for i in 0..4096u64 {
                    let sym_va = ld.symtab + i * 24;
                    let Some(raw) = read_u64_va(lib, sym_va) else { break };
                    let st_name = raw as u32;
                    let st_value = read_u64_va(lib, sym_va + 8).unwrap_or(0);
                    if st_name == 0 && st_value == 0 {
                        if i == 0 { continue } else { break }
                    }
                    if st_name == 0 {
                        continue;
                    }
                    let Some(sname) = read_cstr_va(lib, str_base + u64::from(st_name)) else {
                        continue;
                    };
                    if sname == name && st_value != 0 {
                        return Some(st_value + lib_bias);
                    }
                }
            }
        }
        None
    }

    /// Builds a process from a pre-populated memory (multi-image load).
    fn load_image_with_memory(
        &self,
        image: LoadedImage,
        mut memory: PersistentMemory,
        entry: u64,
        bias: u64,
    ) -> Result<Process, RuntimeError> {
        // Stack + registers as in load_image, with entry biased.
        let mut biased = image.clone();
        biased.entry += bias;
        let image = biased;
        let (stack_pointer, argv0_addr) = self.initial_stack_pointer(&image, &mut memory)?;
        let reg_file = Intel64RegisterFile::canonical();
        let widths: Vec<(u32, usize)> = reg_file
            .architectural_registers
            .iter()
            .map(|(reg, bits)| (reg.0, usize::from(*bits).div_ceil(8)))
            .collect();
        let mut registers =
            PersistentRegisters::from_widths(widths).map_err(|e| RuntimeError::Register(format!("{e:?}")))?;
        registers = registers
            .write(register_id::RIP.0, &entry.to_le_bytes())
            .map_err(|e| RuntimeError::Register(format!("{e:?}")))?;
        registers = registers
            .write(register_id::GPR_BASE + 4, &stack_pointer.to_le_bytes())
            .map_err(|e| RuntimeError::Register(format!("{e:?}")))?;
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
            entry,
            entry_state: state.clone(),
            state,
            block_cache: BTreeMap::new(),
            step_cache: BTreeMap::new(),
            simproc_hooks: BTreeMap::new(),
            pe_import_stubs: BTreeMap::new(),
            simproc_instances: BTreeMap::new(),
            kernel_pool: None,
            pci_config_address: 0,
            symbols: image.symbols.clone(),
            trace: Vec::new(),
            syscalls: SyscallModel::new(),
            program_break: HEAP_BASE,
            heap_end: HEAP_BASE + HEAP_SIZE,
            mmap_next: MMAP_BASE,
            files: BTreeMap::new(),
            open_fds: BTreeMap::new(),
            symbolic_files: std::collections::BTreeSet::new(),
            symbolic_fds: std::collections::BTreeSet::new(),
            argv0_addr: Some(argv0_addr),
            stdin: Vec::new(),
            stdin_pos: 0,
            next_fd: 3,
            next_block_id: 0,
            step_count: 0,
            simproc_dispatches: 0,
            terminated: false,
        })
    }

    /// Recovers the image CFG and extracts pure induction loops — a
    /// straight-line body (one block, or a chain of blocks linked only by
    /// unconditional jumps or adjacency) whose only state effects are
    /// `counter += step` and a `cmp counter, bound` feeding the back-edge
    /// branch. Summaries let the session collapse the trip count in O(1),
    /// concretely or over symbolic counter/bound expressions.
    pub fn loop_summaries(&self, process: &Process) -> Vec<LoopSummary> {
        use angryier_cfg::recover;
        let mut out = Vec::new();
        let regions: Vec<(u64, Vec<u8>)> = process
            .state
            .memory
            .regions()
            .iter()
            .filter(|r| r.executable)
            .filter_map(|r| {
                let bytes = read_concrete_bytes(process, r.base, r.size.min(1 << 22)).ok()?;
                Some((r.base, bytes))
            })
            .collect();
        for (base, bytes) in &regions {
            let Ok(cfg) = recover(&self.decoder, *base, bytes, process.entry, |i| i.form_id) else {
                continue;
            };
            for lp in cfg.loops() {
                let Some(summary) = summarize_induction_loop(&cfg, &lp) else {
                    continue;
                };
                out.push(summary);
            }
        }
        out
    }

    /// Coverage-guided input generation: run the symbolic session with the
    /// solver, collect models for `find` states, then replay each input
    /// concretely (stdin = model bytes) — returns `(inputs, coverage)` as
    /// the set of block addresses each input reaches.
    ///
    /// The returned inputs satisfy the *symbolic* path; the replayed
    /// coverage is ground truth for what the input actually executes.
    #[cfg(feature = "z3")]
    pub fn fuzz_generate(
        &self,
        bytes: &[u8],
        find: &[Address],
        steps: u64,
        timeout: std::time::Duration,
    ) -> Result<Vec<FuzzedInput>, RuntimeError> {
        let arena = std::sync::Arc::new(angryier_expr::ShardedExprArena::new(
            angryier_types::ExpressionNormalizationVersion(1),
        ));
        let process = self.load_elf(bytes)?;
        let mut session = SymbolicSession::new(self, arena.as_ref(), process);
        let mut backend =
            angryier_solver_z3::Z3Backend::native_ffi(arena.clone() as std::sync::Arc<dyn angryier_expr::ExprReader>)
                .map_err(|e| RuntimeError::Solver(format!("{e:?}")))?;
        let policy = ExplorationPolicy {
            find: find.to_vec(),
            ..Default::default()
        };
        let report = session.run_with_policy(steps, 16, Some(&mut backend), timeout, true, &policy)?;
        let mut out = Vec::new();
        for found in report.found.iter() {
            session.states.push(found.clone());
            let idx = session.states.len() - 1;
            let Ok(model) = session.solve_state_symbols(idx, &mut backend, timeout) else {
                session.states.pop();
                continue;
            };
            session.states.pop();
            // Model bytes are keyed by ExprId — for stdin models the byte
            // vectors ARE the input. Concatenate sorted by id for a stable
            // seed (the session's stdin materialization assigns sequential
            // ids).
            let mut sorted: Vec<(u64, Vec<u8>)> = model.clone();
            sorted.sort_by_key(|(k, _)| *k);
            let input: Vec<u8> = sorted.iter().flat_map(|(_, b)| b.clone()).collect();
            // Replay: concrete run with stdin=input, collect coverage.
            let mut proc = self.load_elf(bytes)?;
            proc.stdin = input.clone();
            let mut coverage = Vec::new();
            for _ in 0..steps.min(10_000) {
                match self.step(&mut proc) {
                    Ok(o) => {
                        if let Some(pc) = stepped_next_pc(&o) {
                            coverage.push(pc);
                        }
                        if matches!(o, StepOutcome::Terminated { .. }) {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            out.push((input, coverage));
        }
        Ok(out)
    }

    /// Loads a PE32+ image (statically-linked x86-64 PE — sections become
    /// segments, entry = image_base + AddressOfEntryPoint).
    pub fn load_pe(&self, bytes: &[u8]) -> Result<Process, RuntimeError> {
        let loader = angryier_loader::Pe32Loader::new();
        let image = loader.load(bytes).map_err(RuntimeError::Loader)?;
        self.load_image(image)
    }

    /// Loads a PE32+ Windows driver for execution from `DriverEntry`.
    ///
    /// Sections map like [`Runtime::load_pe`]; then the import table is
    /// linked angr-style: every import gets a 16-byte stub cell in a
    /// dedicated region ([`PE_DRIVER_STUB_BASE`]), the first byte of which is
    /// a bare `ret` (`0xC3`), and the IAT slot is patched to the stub
    /// address. Unhooked imports therefore execute natively — `call` → `ret`
    /// returns to the caller with RAX holding the caller's leftover value:
    /// defined, deterministic, zero modeling. Hooked imports (see
    /// [`Process::hook_export_return`]) dispatch a [`KernelReturnStub`]
    /// instead.
    ///
    /// Entry state matches a kernel `DriverEntry` call (Windows x86-64
    /// convention): RCX = a zeroed writable `DRIVER_OBJECT` scratch
    /// ([`PE_DRIVER_SCRATCH_BASE`]), RDX = a `UNICODE_STRING`-shaped zeroed
    /// scratch `0x200` into the same region, and a sentinel return address
    /// ([`EXIT_HOOK`]) so a `DriverEntry` that returns terminates cleanly
    /// through the shared `exit` hook.
    pub fn load_pe_driver(&self, bytes: &[u8]) -> Result<Process, RuntimeError> {
        let loader = angryier_loader::Pe32Loader::new();
        let image = loader.load(bytes).map_err(RuntimeError::Loader)?;
        let imports: Vec<angryier_loader::PeImport> = image
            .pe_imports()
            .map(<[angryier_loader::PeImport]>::to_vec)
            .unwrap_or_default();

        let extra_regions = vec![
            MemoryRegion {
                object: angryier_types::ObjectId(5),
                base: PE_DRIVER_STUB_BASE,
                size: PE_DRIVER_STUB_SIZE,
                readable: true,
                writable: false,
                executable: true,
            },
            MemoryRegion {
                object: angryier_types::ObjectId(6),
                base: PE_DRIVER_SCRATCH_BASE,
                size: PE_DRIVER_SCRATCH_SIZE,
                readable: true,
                writable: true,
                executable: false,
            },
            MemoryRegion {
                object: angryier_types::ObjectId(7),
                base: PE_DRIVER_CALLBACK_BASE,
                size: PE_DRIVER_CALLBACK_SIZE,
                readable: true,
                writable: false,
                executable: true,
            },
            // Zero-backed shadow for the kernel pool model's fresh pointers
            // (declared lazily-sparse; untouched pages cost nothing). Reads
            // through an allocation see zeros until the driver writes.
            MemoryRegion {
                object: angryier_types::ObjectId(8),
                base: angryier_models::KERNEL_POOL_FRESH_BASE,
                size: 0x0010_0000, // 1 MiB = 256 model allocations
                readable: true,
                writable: true,
                executable: false,
            },
            // Under-constrained memory guard: low 64 KiB as zeroed RAM.
            // UC-SymEX relaxation — reads/writes through NULL-adjacent
            // garbage pointers behave as zero pages instead of faulting.
            // Paths taken under zeroed guesses are review candidates;
            // callers surface this relaxation in verdict provenance.
            MemoryRegion {
                object: angryier_types::ObjectId(9),
                base: 0,
                size: 0x0001_0000,
                readable: true,
                writable: true,
                executable: false,
            },
        ];
        let mut process = self.load_image_with_extra_regions(image, extra_regions)?;

        // Security-cookie randomization (Windows loader behavior since
        // Win10): scan the mapped writable regions for the linker's DEFAULT
        // `__security_cookie` and its complement, and overwrite both with a
        // deterministic engine cookie. MSVC-built drivers ship the DEFAULT
        // value in `.data`; their `__security_init_cookie` fastfails
        // (`int 29h`, ~15 steps into DriverEntry) unless the loader has
        // replaced it first. Per-build random cookies (already non-zero and
        // non-DEFAULT) are untouched and pass the init check as-is.
        let security_cookie_le = PE_DRIVER_SECURITY_COOKIE.to_le_bytes();
        let security_complement_le = (!PE_DRIVER_SECURITY_COOKIE).to_le_bytes();
        let mapped_regions: Vec<MemoryRegion> = process.state.memory.regions().to_vec();
        for region in mapped_regions {
            if !region.readable || !region.writable {
                continue;
            }
            let mut addr = region.base;
            let end = region.base.saturating_add(region.size);
            while addr + 8 <= end {
                let Ok(slot) = process.state.memory.read(addr, 8) else {
                    break;
                };
                let mut bytes = [0u8; 8];
                let mut is_cookie = true;
                for (offset, byte) in slot.iter().enumerate() {
                    match byte {
                        ByteValue::Concrete(value) => bytes[offset] = *value,
                        ByteValue::Symbolic(_) => {
                            is_cookie = false;
                            break;
                        }
                    }
                }
                if !is_cookie {
                    break;
                }
                let value = u64::from_le_bytes(bytes);
                if value == PE_DRIVER_DEFAULT_COOKIE {
                    process.state.memory = process
                        .state
                        .memory
                        .load_concrete(addr, &security_cookie_le)
                        .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
                } else if value == !PE_DRIVER_DEFAULT_COOKIE {
                    process.state.memory = process
                        .state
                        .memory
                        .load_concrete(addr, &security_complement_le)
                        .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
                }
                addr += 8;
            }
        }

        // IAT patching: stub i lives at STUB_BASE + 16*i and holds a single
        // `ret` byte. Skipped wholesale for images without imports.
        if !imports.is_empty() {
            let image_base = pe_image_base(bytes)?;
            let capacity = usize::try_from(PE_DRIVER_STUB_SIZE / PE_DRIVER_STUB_STRIDE)
                .map_err(|_| RuntimeError::Memory("import stub capacity overflow".into()))?;
            if imports.len() > capacity {
                return Err(RuntimeError::Memory(format!(
                    "PE import stub region exhausted: {} imports, capacity {capacity}",
                    imports.len()
                )));
            }
            for (index, import) in imports.iter().enumerate() {
                let export = match &import.kind {
                    angryier_loader::PeImportKind::Name(name) => name.clone(),
                    angryier_loader::PeImportKind::Ordinal(ordinal) => format!("#{ordinal}"),
                };
                let stub = PE_DRIVER_STUB_BASE + PE_DRIVER_STUB_STRIDE * index as u64;
                process.state.memory = process
                    .state
                    .memory
                    .load_concrete(stub, &[0xC3])
                    .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
                // The IAT slot's absolute VA is image_base + iat_rva.
                // LoadedImage keeps only the biased segment addresses (the
                // section RVAs are not retained), so the base is recovered
                // from the optional header directly.
                let slot = image_base.wrapping_add(u64::from(import.iat_rva));
                let mapped = process.state.memory.regions().iter().any(|region| {
                    slot >= region.base
                        && slot
                            .checked_add(8)
                            .is_some_and(|end| end <= region.base.saturating_add(region.size))
                        && (region.readable || region.writable)
                });
                if !mapped {
                    return Err(RuntimeError::Memory(format!(
                        "IAT slot {slot:#x} for import {}!{export} is outside a mapped writable-or-readable segment",
                        import.dll
                    )));
                }
                process.state.memory = process
                    .state
                    .memory
                    .load_concrete(slot, &stub.to_le_bytes())
                    .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
                process.pe_import_stubs.insert(stub, (import.dll.clone(), export));
            }
        }

        // Self-consistent DRIVER_OBJECT model (see the offset consts): the
        // universal success callback backs every function-pointer slot, the
        // extension block is reachable, and the name strings are well-formed
        // empty UNICODE_STRINGs. Zero pointers (DeviceObject,
        // FastIoDispatch, HardwareDatabase) stay null — drivers check those
        // before use, and a null device walk terminates cleanly.
        let callback: &[u8] = &[0x33, 0xC0, 0xC3]; // xor eax,eax; ret
        process.state.memory = process
            .state
            .memory
            .load_concrete(PE_DRIVER_CALLBACK_BASE, callback)
            .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;

        let write_u64 = |process: &mut Process, address: u64, value: u64| -> Result<(), RuntimeError> {
            process.state.memory = process
                .state
                .memory
                .load_concrete(address, &value.to_le_bytes())
                .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
            Ok(())
        };
        let scratch = PE_DRIVER_SCRATCH_BASE;
        // DRIVER_OBJECT.
        write_u64(
            &mut process,
            scratch + DRIVER_OBJECT_OFFSET_DRIVER_EXTENSION,
            scratch + PE_DRIVER_EXTENSION_OFF,
        )?;
        // DriverName UNICODE_STRING {Length=0, MaximumLength=0, _pad, Buffer}.
        write_u64(
            &mut process,
            scratch + DRIVER_OBJECT_OFFSET_DRIVER_NAME + 8,
            scratch + PE_DRIVER_STRING_BUF_OFF,
        )?;
        // DriverInit / DriverStartIo / DriverUnload.
        write_u64(&mut process, scratch + 0x58, PE_DRIVER_CALLBACK_BASE)?;
        write_u64(&mut process, scratch + 0x60, PE_DRIVER_CALLBACK_BASE)?;
        write_u64(&mut process, scratch + 0x68, PE_DRIVER_CALLBACK_BASE)?;
        // MajorFunction[0..28].
        for index in 0..DRIVER_OBJECT_MAJOR_FUNCTION_COUNT {
            write_u64(
                &mut process,
                scratch + DRIVER_OBJECT_OFFSET_MAJOR_FUNCTION0 + 8 * index as u64,
                PE_DRIVER_CALLBACK_BASE,
            )?;
        }
        // DRIVER_EXTENSION at scratch+0x300: DriverObject, AddDevice, Count,
        // ServiceKeyName {0, 0, _pad, Buffer}.
        write_u64(&mut process, scratch + PE_DRIVER_EXTENSION_OFF, scratch)?;
        write_u64(
            &mut process,
            scratch + PE_DRIVER_EXTENSION_OFF + 0x08,
            PE_DRIVER_CALLBACK_BASE,
        )?;
        write_u64(
            &mut process,
            scratch + PE_DRIVER_EXTENSION_OFF + 0x18 + 8,
            scratch + PE_DRIVER_STRING_BUF_OFF,
        )?;
        // RegistryPath UNICODE_STRING at scratch+0x200 (RDX target): Buffer.
        write_u64(&mut process, scratch + 0x200 + 8, scratch + PE_DRIVER_STRING_BUF_OFF)?;

        // DriverEntry register state (after load_image's register init):
        // RCX = pDriverObject, RDX = pRegistryPath.
        process.write_register(register_id::GPR_BASE + 1, PE_DRIVER_SCRATCH_BASE)?;
        process.write_register(register_id::GPR_BASE + 2, PE_DRIVER_SCRATCH_BASE + 0x200)?;

        // Sentinel return address: a DriverEntry that returns lands on the
        // shared `exit` hook and terminates cleanly.
        let rsp = process.read_register(register_id::GPR_BASE + 4)?.wrapping_sub(8);
        let hook: Vec<ByteValue> = EXIT_HOOK
            .to_le_bytes()
            .iter()
            .map(|b| ByteValue::Concrete(*b))
            .collect();
        process.state.memory = process
            .state
            .memory
            .write(rsp, &hook)
            .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
        process.write_register(register_id::GPR_BASE + 4, rsp)?;
        process.hook_simproc(EXIT_HOOK, "exit");

        // GS segment base for kernel-mode drivers: MSVC security cookies
        // read from gs:[offset]. Pointing GS_BASE at the zeroed scratch
        // (well past the DRIVER_OBJECT at +0x000 and RegistryPath at +0x200)
        // and seeding gs:[0x30] with the deterministic security cookie makes
        // the /GS frame check read a stable non-zero value: the prologue
        // saves cookie^RSP, the epilogue un-xors and compares against the
        // same slot — consistent by construction, and `cookie == 0` guards
        // (some inits fastfail on a zero GS cookie) pass.
        process.write_register(register_id::GS_BASE.0, PE_DRIVER_SCRATCH_BASE + 0x8000)?;
        let gs_cookie: Vec<ByteValue> = PE_DRIVER_SECURITY_COOKIE
            .to_le_bytes()
            .iter()
            .map(|b| ByteValue::Concrete(*b))
            .collect();
        process.state.memory = process
            .state
            .memory
            .write(PE_DRIVER_SCRATCH_BASE + 0x8000 + PE_DRIVER_GS_COOKIE_OFF, &gs_cookie)
            .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;

        // The patches above are load-time state: keep restart-from-entry
        // (`reset_to_entry`) meaningful for drivers too.
        process.entry_state = process.state.clone();
        Ok(process)
    }

    /// Creates a Process from an already-loaded image.
    pub fn load_image(&self, image: LoadedImage) -> Result<Process, RuntimeError> {
        self.load_image_with_extra_regions(image, Vec::new())
    }

    /// [`Runtime::load_image`] with additional memory regions joined into the
    /// map before it is built — used by [`Runtime::load_pe_driver`] for the
    /// import-stub and scratch regions.
    fn load_image_with_extra_regions(
        &self,
        image: LoadedImage,
        extra_regions: Vec<MemoryRegion>,
    ) -> Result<Process, RuntimeError> {
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

        for region in extra_regions {
            regions.push(region);
        }

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
        let (stack_pointer, argv0_addr) = self.initial_stack_pointer(&image, &mut memory)?;

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
            step_cache: BTreeMap::new(),
            simproc_hooks: BTreeMap::new(),
            pe_import_stubs: BTreeMap::new(),
            simproc_instances: BTreeMap::new(),
            kernel_pool: None,
            pci_config_address: 0,
            symbols: image.symbols,
            trace: Vec::new(),
            syscalls: SyscallModel::new(),
            program_break: brk_base,
            heap_end: brk_base + HEAP_SIZE,
            mmap_next: MMAP_BASE,
            files: BTreeMap::new(),
            open_fds: BTreeMap::new(),
            symbolic_files: std::collections::BTreeSet::new(),
            symbolic_fds: std::collections::BTreeSet::new(),
            argv0_addr: Some(argv0_addr),
            stdin: Vec::new(),
            stdin_pos: 0,
            next_fd: 3,
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

        // Instance SimProcedure hooks (call-target stubs) take priority over
        // the name-keyed hooks.
        if let Some(model) = process.simproc_instances.get(&pc).cloned() {
            return self.dispatch_simproc_instance(process, pc, &model);
        }

        // Check for SimProcedure hooks.
        if let Some(name) = process.simproc_hooks.get(&pc).cloned() {
            return self.dispatch_simproc(process, pc, &name);
        }

        // Read instruction bytes from memory, bounded by the containing region
        // so that instructions near the end of a segment do not fail the read.
        // The fetch runs every step, so it fills a stack buffer through
        // `read_into` instead of materializing a fresh `Vec<ByteValue>`.
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
        let mut buffer = [ByteValue::Concrete(0); MAX_INSN_LEN];
        process
            .state
            .memory
            .read_into(pc, &mut buffer[..read_len])
            .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
        let bytes: &[ByteValue] = &buffer[..read_len];

        // Fast path: a previously decoded+lowered step at this PC is reusable
        // while the instruction bytes and the covering code-page guards are
        // unchanged — under exactly those conditions a fresh decode, semantic
        // emission, seal, and lowering would reproduce the cached block (the
        // decoder and registry are deterministic per (pc, bytes), and equal
        // guards mean no write touched the pages since). This turns loop
        // revisits into execute-only steps. The byte check compares straight
        // against the read so the raw byte vector is only materialized on a
        // miss.
        if let Some(hit) = process.step_cache.get(&pc)
            && hit.bytes.len() == bytes.len()
            && hit
                .bytes
                .iter()
                .zip(bytes.iter())
                .all(|(cached, read)| matches!(read, ByteValue::Concrete(value) if value == cached))
            && process
                .state
                .memory
                .code_version_guards_for_range(pc, usize::from(hit.length))
                .map(|guards| guards == hit.guards)
                .unwrap_or(false)
        {
            let block = Arc::clone(&hit.block);
            let length = hit.length;
            let form_id = hit.form_id;

            // Observers see the lowered block against the pre-execution state.
            observe(process, &block)?;

            // Execute.
            let (new_state, outcome) = self
                .interpreter
                .execute_block(&process.state, &block, ExecutionMode::Concrete)
                .map_err(|e| RuntimeError::Execution(format!("{e:?}")))?;

            process.state = new_state;
            process.step_count += 1;
            return finish_step(process, pc, length, form_id, outcome);
        }

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

        // Port I/O is an environment interaction: the corpus providers model
        // the generic zero-read/drop-write, but the runtime intercepts the
        // forms to implement the PCI configuration-space model (0xCF8/0xCFC)
        // that real drivers probe. The corpus forms remain for other
        // consumers (symbolic mode reads ports as zero, consistent with the
        // "no device" direction).
        use angryier_semantics_intel64::forms as port_forms;
        match decoded.form_id {
            port_forms::IN_AL_DX
            | port_forms::IN_AX_DX
            | port_forms::IN_EAX_DX
            | port_forms::IN_AL_IMM8
            | port_forms::IN_AX_IMM8
            | port_forms::IN_EAX_IMM8 => {
                return self.execute_port_in(process, pc, decoded.length, &decoded);
            }
            port_forms::OUT_DX_AL
            | port_forms::OUT_DX_AX
            | port_forms::OUT_DX_EAX
            | port_forms::OUT_IMM8_AL
            | port_forms::OUT_IMM8_AX
            | port_forms::OUT_IMM8_EAX => {
                return self.execute_port_out(process, pc, decoded.length, &decoded);
            }
            _ => {}
        }

        // String instructions encode an internal loop, so they run directly
        // against the process state rather than through straight-line corpus
        // semantics.
        #[cfg(feature = "xed")]
        if let Some(outcome) = self.execute_string_instruction(process, pc, &decoded)? {
            return Ok(outcome);
        }

        let (ir_block, decoded) = self.lower_at(process, pc, &decoded)?;

        // The block's key carries the pre-execution code-page guards; reuse
        // must compare against those (an instruction writing its own page
        // makes current guards differ, forcing a fresh decode next visit).
        let guards = ir_block.key.code_versions.clone();

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

        // Cache the decode+lowering for reuse on the next visit (the lowered
        // block itself is already mirrored in `block_cache` by `lower_at`).
        process.step_cache.insert(
            pc,
            CachedStep {
                block: Arc::new(ir_block),
                length,
                form_id,
                bytes: raw,
                guards,
            },
        );

        finish_step(process, pc, length, form_id, outcome)
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
            syscall::READ => {
                // stdin serves `process.stdin` (EOF at exhaustion). Open
                // file descriptors serve their bytes. Unknown fds: -EBADF.
                let ret = if arg0 == 0 {
                    let avail = process.stdin.len().saturating_sub(process.stdin_pos);
                    let n = (arg2 as usize).min(avail);
                    if n > 0 {
                        let slice = process.stdin[process.stdin_pos..process.stdin_pos + n].to_vec();
                        process.stdin_pos += n;
                        let bytes: Vec<ByteValue> = slice.iter().map(|b| ByteValue::Concrete(*b)).collect();
                        process.state.memory = process
                            .state
                            .memory
                            .write(arg1, &bytes)
                            .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
                    }
                    n as u64
                } else if let Some((data, pos)) = process.open_fds.get_mut(&arg0) {
                    let n = (*pos + arg2 as usize).min(data.len()) - *pos;
                    let slice = data[*pos..*pos + n].to_vec();
                    *pos += n;
                    let bytes: Vec<ByteValue> = slice.iter().map(|b| ByteValue::Concrete(*b)).collect();
                    process.state.memory = process
                        .state
                        .memory
                        .write(arg1, &bytes)
                        .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
                    n as u64
                } else {
                    0u64.wrapping_sub(9)
                };
                process.write_register(register_id::GPR_BASE, ret)?;
                process.write_pc(next_pc)?;
                process.step_count += 1;
                Ok(StepOutcome::Syscall { pc, number })
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
            syscall::MMAP => {
                // mmap(addr=rdi, len=rsi, prot=rdx, flags=r10, fd=r8,
                // off=r9) — anonymous maps bump-allocate downward from
                // MMAP_BASE; file-backed mmap is unmodeled (-ENOSYS).
                let (addr, flags) = (arg0, arg3);
                const MAP_ANONYMOUS: u64 = 0x20;
                let result = if flags & MAP_ANONYMOUS != 0 {
                    let len = (arg1 + 0xFFF) & !0xFFF;
                    let base = if addr == 0 {
                        let base = process.mmap_next.wrapping_sub(len);
                        process.mmap_next = base;
                        base
                    } else {
                        addr
                    };
                    let region = MemoryRegion {
                        object: angryier_types::ObjectId(3),
                        base,
                        size: len,
                        readable: true,
                        writable: true,
                        executable: false,
                    };
                    match process.state.memory.with_region(region) {
                        Ok(m) => {
                            process.state.memory = m;
                            base
                        }
                        Err(_) => 0u64.wrapping_sub(12), // -ENOMEM
                    }
                } else {
                    0u64.wrapping_sub(38) // -ENOSYS: file-backed unmodeled
                };
                process.write_register(register_id::GPR_BASE, result)?;
                process.write_pc(next_pc)?;
                process.step_count += 1;
                Ok(StepOutcome::Syscall { pc, number })
            }
            syscall::MUNMAP => {
                // Keep the region mapped — freeing pages is a refinement.
                process.write_register(register_id::GPR_BASE, 0)?;
                process.write_pc(next_pc)?;
                process.step_count += 1;
                Ok(StepOutcome::Syscall { pc, number })
            }
            syscall::OPENAT => {
                // openat(dirfd, path, flags, mode) — the path is read as a
                // NUL-terminated string and resolved against the process's
                // `files` map; unknown paths report -ENOENT.
                let path_bytes = {
                    let mut buf = Vec::with_capacity(64);
                    for i in 0..256u64 {
                        let b = read_concrete_bytes(process, arg1 + i, 1)?;
                        if b[0] == 0 {
                            break;
                        }
                        buf.push(b[0]);
                    }
                    buf
                };
                let path = String::from_utf8_lossy(&path_bytes).to_string();
                let ret = if let Some(data) = process
                    .files
                    .get(&path)
                    .cloned()
                    .or_else(|| process.symbolic_files.contains(&path).then(Vec::new))
                {
                    let fd = process.next_fd;
                    process.next_fd += 1;
                    process.open_fds.insert(fd, (data, 0));
                    if process.symbolic_files.contains(&path) {
                        process.symbolic_fds.insert(fd);
                    }
                    fd
                } else {
                    0u64.wrapping_sub(2) // -ENOENT
                };
                process.write_register(register_id::GPR_BASE, ret)?;
                process.write_pc(next_pc)?;
                process.step_count += 1;
                Ok(StepOutcome::Syscall { pc, number })
            }
            syscall::CLOSE => {
                process.open_fds.remove(&arg0);
                process.write_register(register_id::GPR_BASE, 0)?;
                process.write_pc(next_pc)?;
                process.step_count += 1;
                Ok(StepOutcome::Syscall { pc, number })
            }
            syscall::FSTAT => {
                // Zeroed struct stat with S_IFREG — enough for size/mode
                // checks in callers that tolerate an empty file.
                let stat: Vec<ByteValue> = vec![ByteValue::Concrete(0); 144];
                process.state.memory = process
                    .state
                    .memory
                    .write(arg1, &stat)
                    .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
                process.write_register(register_id::GPR_BASE, 0)?;
                process.write_pc(next_pc)?;
                process.step_count += 1;
                Ok(StepOutcome::Syscall { pc, number })
            }
            syscall::ACCESS => {
                // Report -ENOENT for paths the model doesn't carry.
                process.write_register(register_id::GPR_BASE, 0u64.wrapping_sub(2))?;
                process.write_pc(next_pc)?;
                process.step_count += 1;
                Ok(StepOutcome::Syscall { pc, number })
            }
            syscall::IOCTL => {
                // -ENOTTY: callers treat the fd as a plain file.
                process.write_register(register_id::GPR_BASE, 0u64.wrapping_sub(25))?;
                process.write_pc(next_pc)?;
                process.step_count += 1;
                Ok(StepOutcome::Syscall { pc, number })
            }
            syscall::WRITEV => {
                // writev(fd, iov, iovcnt): consume the iovec lengths.
                let mut total = 0u64;
                for i in 0..arg2.min(16) {
                    let base = arg1.wrapping_add(i * 16);
                    let len_bytes = read_concrete_bytes(process, base + 8, 8)?;
                    let len = u64::from_le_bytes(len_bytes[..8].try_into().unwrap_or([0; 8]));
                    let buf_bytes = read_concrete_bytes(process, base, 8)?;
                    let buf = u64::from_le_bytes(buf_bytes[..8].try_into().unwrap_or([0; 8]));
                    let data = read_concrete_bytes(process, buf, len)?;
                    total = total.wrapping_add(process.syscalls.record_write(&data));
                }
                process.write_register(register_id::GPR_BASE, total)?;
                process.write_pc(next_pc)?;
                process.step_count += 1;
                Ok(StepOutcome::Syscall { pc, number })
            }
            syscall::GETUID | syscall::GETEUID | syscall::GETGID | syscall::GETEGID => {
                process.write_register(register_id::GPR_BASE, 1000)?;
                process.write_pc(next_pc)?;
                process.step_count += 1;
                Ok(StepOutcome::Syscall { pc, number })
            }
            syscall::FUTEX => {
                // Single-threaded model: futex wakes are no-ops.
                process.write_register(register_id::GPR_BASE, 0)?;
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

    /// Resolves the port number of a decoded IN/OUT instruction: operand 1
    /// (IN) or operand 0 (OUT) is either DX or an imm8 immediate.
    fn port_operand_value(&self, process: &Process, operand: &Operand) -> Option<u16> {
        match &operand.kind {
            OperandKind::Register(view) => process.read_register(view.parent.0).ok().map(|v| (v & 0xFFFF) as u16),
            OperandKind::Immediate(imm) => Some((imm.value & 0xFF) as u16),
            _ => None,
        }
    }

    /// `OUT port, r8/16/32`: writes to port 0xCF8 latch the PCI
    /// configuration-address register (all other port writes are dropped —
    /// no device model). The latch is consulted by config reads at
    /// 0xCFC-0xCFF.
    fn execute_port_out(
        &self,
        process: &mut Process,
        pc: Address,
        length: u8,
        decoded: &DecodedInstruction,
    ) -> Result<StepOutcome, RuntimeError> {
        // OUT operands: [port, value].
        if let Some(port) = decoded
            .operands
            .first()
            .and_then(|o| self.port_operand_value(process, o))
            && port == 0xCF8
            && let Some(value) = decoded.operands.get(1).and_then(|o| match &o.kind {
                OperandKind::Register(view) => process.read_register(view.parent.0).ok(),
                _ => None,
            })
        {
            process.pci_config_address = value as u32;
        }
        process.write_pc(pc.wrapping_add(u64::from(length)))?;
        process.step_count += 1;
        Ok(StepOutcome::Stepped {
            pc,
            next_pc: pc.wrapping_add(u64::from(length)),
            length,
            form_id: decoded.form_id,
        })
    }

    /// `IN r8/16/32, port`: ports 0xCFC-0xCFF read the PCI configuration
    /// space at the latched 0xCF8 address (byte-offset addressing: a read
    /// at 0xCFC+`k` returns the config dword shifted by 8*k); every other
    /// port reads zero ("device absent"). The config space model exposes a
    /// minimal AMD FCH: the host bridge (bus 0, device 0, function 0) and
    /// the SMBus/GPIO controllers at their standard bus-0 slots.
    fn execute_port_in(
        &self,
        process: &mut Process,
        pc: Address,
        length: u8,
        decoded: &DecodedInstruction,
    ) -> Result<StepOutcome, RuntimeError> {
        let dest = decoded.operands.first();
        let width = dest.map(|o| usize::from(o.width_bits)).unwrap_or(32);
        let port = decoded
            .operands
            .get(1)
            .and_then(|o| self.port_operand_value(process, o));
        let value = match port {
            Some(p @ 0xCFC..=0xCFF) => {
                let addr = process.pci_config_address;
                let bus = ((addr >> 16) & 0xFF) as u8;
                let device = ((addr >> 11) & 0x1F) as u8;
                let function = ((addr >> 8) & 0x07) as u8;
                let dword_offset = (addr & 0xFC) as u8;
                let dword = pci_config_read(bus, device, function, dword_offset);
                (dword >> (8 * (p - 0xCFC))) as u64
            }
            _ => 0,
        };
        let value = match width {
            8 => value & 0xFF,
            16 => value & 0xFFFF,
            _ => value & 0xFFFF_FFFF,
        };
        // Write the destination accumulator: 8/16-bit writes preserve the
        // upper bits of RAX; 32-bit writes zero-extend (x86 semantics).
        let rax = process.read_register(register_id::GPR_BASE)?;
        let merged = match width {
            8 => (rax & !0xFF) | value,
            16 => (rax & !0xFFFF) | value,
            _ => value,
        };
        process.write_register(register_id::GPR_BASE, merged)?;
        process.write_pc(pc.wrapping_add(u64::from(length)))?;
        process.step_count += 1;
        Ok(StepOutcome::Stepped {
            pc,
            next_pc: pc.wrapping_add(u64::from(length)),
            length,
            form_id: decoded.form_id,
        })
    }

    /// Dispatches a SimProcedure at the given address.
    fn dispatch_simproc(
        &self,
        process: &mut Process,
        address: Address,
        name: &str,
    ) -> Result<StepOutcome, RuntimeError> {
        // `__libc_start_main(main, argc, argv, ...)`: model it as a direct
        // tail-call into `main` with a return address that exits the
        // process — the angr-style shortcut past ld.so/libc init.
        if name == "libc_start_main" {
            let main_fn = process.read_register(register_id::GPR_BASE + 7)?; // rdi = main
            let argc = process.read_register(register_id::GPR_BASE + 6)?; // rsi
            let argv = process.read_register(register_id::GPR_BASE + 2)?; // rdx
            let rsp = process.read_register(register_id::GPR_BASE + 4)?.wrapping_sub(8);
            // Return address → a synthetic `exit` hook address ([`EXIT_HOOK`]).
            let bytes: Vec<ByteValue> = EXIT_HOOK
                .to_le_bytes()
                .iter()
                .map(|b| ByteValue::Concrete(*b))
                .collect();
            process.state.memory = process
                .state
                .memory
                .write(rsp, &bytes)
                .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
            process.write_register(register_id::GPR_BASE + 4, rsp)?;
            process.hook_simproc(EXIT_HOOK, "exit");
            process.write_register(register_id::GPR_BASE + 7, argc)?; // rdi = argc
            process.write_register(register_id::GPR_BASE + 6, argv)?; // rsi = argv
            process.write_pc(main_fn)?;
            process.simproc_dispatches += 1;
            return Ok(StepOutcome::SimProcedure {
                address,
                name: name.to_string(),
            });
        }

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

    /// Dispatches an instance SimProcedure hook (see
    /// [`Process::simproc_instances`]) at a call target.
    ///
    /// Unlike the name-keyed hooks — which patch at instruction sites and
    /// advance PC by the +1-byte convention — instance hooks sit at call
    /// targets reached by a real `call`, so the return address the call
    /// pushed is authoritative: a return pops `[RSP]` into RIP and adds 8 to
    /// RSP (the call-correct convention).
    fn dispatch_simproc_instance(
        &self,
        process: &mut Process,
        address: Address,
        model: &Arc<dyn SimProcedure>,
    ) -> Result<StepOutcome, RuntimeError> {
        // Bridge ExecutionState → SimState (GPR bridging mirrors
        // `dispatch_simproc`: RAX=0, RCX=1, RDX=2, RBX=3, RSP=4, RBP=5,
        // RSI=6, RDI=7).
        let mut sim_state = SimState::new();
        for index in 0u32..8 {
            let reg_id = register_id::GPR_BASE + index;
            if let Ok(val) = process.state.registers.read(reg_id) {
                let mut buf = [0u8; 8];
                let len = val.len().min(8);
                buf[..len].copy_from_slice(&val[..len]);
                sim_state.set_reg(u64::from(index), u64::from_le_bytes(buf));
            }
        }
        // Stack-argument shadowing: mirror [rsp .. rsp+0x40) (return
        // address + 7 stack-argument slots) into the SimState shadow so
        // stack-passed OUT/IN parameters (5th argument and beyond, e.g.
        // IoCreateDevice's pptrDeviceObject at [rsp+0x38]) are readable
        // through SimState::read_bytes. 5th arg = [rsp+0x08] ... 11th =
        // [rsp+0x38]; slot 0 is the return address, also useful.
        {
            let rsp = sim_state.get_reg(4);
            if rsp != 0 {
                if let Ok(bytes) = process.state.memory.read(rsp, 0x40) {
                    let concrete: Vec<u8> = bytes
                        .iter()
                        .map(|b| match b {
                            ByteValue::Concrete(v) => *v,
                            ByteValue::Symbolic(_) => 0,
                        })
                        .collect();
                    sim_state.write_memory(rsp, concrete);
                }
            }
        }

        let name = model.name().to_string();
        // Kernel pool model: record (pointer, caller) for modeled
        // alloc/free dispatches. The return address is still on the stack
        // here — `pop_call_return` runs only after `apply`.
        if let Some(tracker) = process.kernel_pool.as_ref()
            && (name == "kernel_alloc_pool" || name == "kernel_free_pool")
        {
            let pointer = sim_state.get_reg(1); // RCX = first argument
            let caller = peek_call_return(process).unwrap_or(0);
            if name == "kernel_alloc_pool" {
                tracker.record_alloc();
            } else {
                tracker.record_free(pointer, caller);
            }
        }

        let result = model.apply(&sim_state);
        process.simproc_dispatches += 1;

        match result {
            SimResult::Exit => {
                process.terminated = true;
                Ok(StepOutcome::SimProcedure { address, name })
            }
            SimResult::Return(value) => {
                pop_call_return(process)?;
                process.write_register(register_id::GPR_BASE, value)?;
                Ok(StepOutcome::SimProcedure { address, name })
            }
            SimResult::Continue(next) => {
                // Apply the continued state's effects through the persistent
                // write APIs, then pop the return — a kernel stub
                // conceptually returns to its caller.
                for (base, bytes) in &next.memory_writes {
                    let values: Vec<ByteValue> = bytes.iter().map(|b| ByteValue::Concrete(*b)).collect();
                    process.state.memory = process
                        .state
                        .memory
                        .write(*base, &values)
                        .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
                }
                for (index, value) in &next.registers {
                    if *index < 8 {
                        process.write_register(register_id::GPR_BASE + (*index as u32), *value)?;
                    }
                }
                pop_call_return(process)?;
                Ok(StepOutcome::SimProcedure { address, name })
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

/// Minimal PCI configuration-space model for AMD FCH devices (the surface
/// real Ryzen-chipset drivers probe via ports 0xCF8/0xCFC). Exposed slots:
/// the host bridge (bus 0, device 0, function 0; vendor 0x1022, device
/// 0x1450, class 06/00/00) and the SMBus controller (bus 0, device 0x14,
/// function 0; device 0x790B, class 0C/05/00). Everything else reads
/// 0xFFFFFFFF ("no device") so enumeration scans terminate. Deterministic
/// for replay; debt-recorded (no full config-space or MMIO BAR model).
fn pci_config_read(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let present = match (bus, device, function) {
        (0, 0, 0) => true,    // host bridge
        (0, 0x14, 0) => true, // SMBus
        _ => false,
    };
    if !present {
        return 0xFFFF_FFFF;
    }
    let (vendor_device, class) = match (bus, device, function) {
        (0, 0, 0) => (0x1450_1022u32, 0x0600_0000u32), // host bridge class 06/00/00
        _ => (0x790B_1022u32, 0x0C05_0000u32),         // SMBus class 0C/05/00
    };
    match offset & 0xFC {
        0x00 => vendor_device,
        0x04 => 0x0010_0006, // status/command (bus mastering on)
        0x08 => class,
        _ => 0,
    }
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

/// Reads 8 bytes at `va` from an image's loaded segments (VA → the
/// segment whose `address <= va < address+len`).
fn read_u64_va(image: &LoadedImage, va: u64) -> Option<u64> {
    let seg = image
        .segments
        .iter()
        .find(|s| va >= s.address && va + 8 <= s.address + s.bytes.len() as u64)?;
    let off = usize::try_from(va - seg.address).ok()?;
    Some(u64::from_le_bytes(seg.bytes[off..off + 8].try_into().ok()?))
}

/// Recovers the PE32+ `ImageBase` from raw file bytes: DOS `e_lfanew` at
/// `0x3C`, PE signature at `e_lfanew`, COFF header at `+4`, optional header
/// at `+24`; the magic must be PE32+ (`0x20B`) and `ImageBase` is the `u64`
/// at optional-header offset 24.
///
/// [`LoadedImage`] keeps the biased segment addresses (image_base + section
/// VA) but neither the section RVAs nor the base itself, and `PeImport::
/// iat_rva` is base-relative — so `load_pe_driver` re-reads the base from
/// the file, mirroring the layout the loader already validated.
fn pe_image_base(bytes: &[u8]) -> Result<u64, RuntimeError> {
    let invalid = || RuntimeError::Loader(angryier_loader::LoaderError::InvalidFormat);
    let u16_at = |off: usize| -> Result<u16, RuntimeError> {
        let slice = bytes
            .get(off..off.checked_add(2).ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        Ok(u16::from_le_bytes([slice[0], slice[1]]))
    };
    let u32_at = |off: usize| -> Result<u32, RuntimeError> {
        let slice = bytes
            .get(off..off.checked_add(4).ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
    };
    let u64_at = |off: usize| -> Result<u64, RuntimeError> {
        let slice = bytes
            .get(off..off.checked_add(8).ok_or_else(invalid)?)
            .ok_or_else(invalid)?;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(slice);
        Ok(u64::from_le_bytes(buf))
    };

    let e_lfanew = usize::try_from(u32_at(0x3C)?).map_err(|_| invalid())?;
    // 'PE\0\0' signature, then the COFF header; the optional header follows.
    let coff = e_lfanew.checked_add(4).ok_or_else(invalid)?;
    let opt = coff.checked_add(20).ok_or_else(invalid)?;
    let opt_size = usize::from(u16_at(coff.checked_add(16).ok_or_else(invalid)?)?);
    match opt.checked_add(opt_size) {
        Some(end) if end <= bytes.len() => {}
        _ => return Err(invalid()),
    }
    if u16_at(opt)? != 0x020B {
        return Err(invalid()); // PE32 (32-bit) unsupported — same as the loader
    }
    u64_at(opt.checked_add(24).ok_or_else(invalid)?)
}

/// Reads a NUL-terminated string at `va` from an image's segments.
fn read_cstr_va(image: &LoadedImage, va: u64) -> Option<String> {
    let seg = image
        .segments
        .iter()
        .find(|s| va >= s.address && va < s.address + s.bytes.len() as u64)?;
    let off = usize::try_from(va - seg.address).ok()?;
    let end = seg.bytes[off..]
        .iter()
        .position(|b| *b == 0)
        .map(|p| off + p)
        .unwrap_or(seg.bytes.len());
    Some(String::from_utf8_lossy(&seg.bytes[off..end]).to_string())
}

/// A generated input together with the concrete coverage it reaches.
pub type FuzzedInput = (Vec<u8>, Vec<Address>);

/// Trip-count bound for a loop summary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bound {
    /// `cmp counter, imm`.
    Imm(u64),
    /// `cmp counter, reg`.
    Reg(u32),
    /// Couldn't be determined.
    None,
}

/// Exit condition of a summarized loop (how `cmp` maps to the taken edge).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoopCond {
    /// `jcc header` exits when `counter >= bound` (jl/jb back edge).
    Lt,
    /// Exits when `counter > bound` (jle/jbe back edge).
    Le,
    /// Exits when `counter <= bound` (jg/ja back edge).
    Gt,
    /// Exits when `counter < bound` (jge/jae back edge).
    Ge,
    /// Exits when `counter != bound` (je back edge).
    Eq,
    /// Exits when `counter == bound` (jne back edge).
    Ne,
}

/// A pure straight-line induction loop — the session can collapse its
/// remaining iterations into one counter write, concretely (closed-form trip
/// count) or symbolically (closed-form exit-counter expression over the
/// counter/bound expressions, plus the exit-condition constraint).
///
/// The body may span several CFG blocks when they form an unconditional
/// chain (jumps or adjacency) with no inner branches or merges; anything
/// beyond that shape is not extracted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoopSummary {
    /// Loop header (and back-edge target).
    pub header: Address,
    /// Fall-through past the back-edge branch.
    pub exit: Address,
    /// The induction register (canonical parent id).
    pub counter: u32,
    /// Signed per-iteration change.
    pub step: i64,
    /// Compare bound.
    pub bound: Bound,
    /// Exit condition.
    pub cond: LoopCond,
    /// Comparison flavor of the back-edge jcc: signed (jl/jle/jg/jge) or
    /// unsigned (jb/jbe/ja/jae). Equality exits are width-only.
    pub signed: bool,
    /// Effective compare/update width in bits (32 or 64) — the loop's
    /// arithmetic lives in a `width`-bit slice of the parent register.
    pub width: u16,
}

fn is_jcc(form: u32) -> bool {
    use angryier_semantics_intel64::forms as f;
    matches!(
        form,
        f::JZ_REL32
            | f::JNZ_REL32
            | f::JC_REL32
            | f::JNC_REL32
            | f::JS_REL32
            | f::JNS_REL32
            | f::JL_REL32
            | f::JGE_REL32
            | f::JLE_REL32
            | f::JG_REL32
            | f::JA_REL32
            | f::JB_REL32
            | f::JBE_REL32
            | f::JAE_REL32
            | f::JO_REL32
            | f::JNO_REL32
            | f::JPE_REL32
            | f::JPO_REL32
    )
}

fn jcc_cond(form: u32) -> Option<LoopCond> {
    use angryier_semantics_intel64::forms as f;
    Some(match form {
        f::JL_REL32 | f::JB_REL32 => LoopCond::Lt,
        f::JLE_REL32 | f::JBE_REL32 => LoopCond::Le,
        f::JG_REL32 | f::JA_REL32 => LoopCond::Gt,
        f::JGE_REL32 | f::JAE_REL32 => LoopCond::Ge,
        f::JZ_REL32 | f::JPE_REL32 => LoopCond::Eq,
        f::JNZ_REL32 | f::JPO_REL32 => LoopCond::Ne,
        _ => return None,
    })
}

fn is_cmp_reg(form: u32) -> bool {
    use angryier_semantics_intel64::forms as f;
    matches!(
        form,
        f::CMP_R64_IMM32 | f::CMP_R32_IMM8 | f::CMP_R8_IMM8 | f::CMP_R64_R64 | f::CMP_R32_R32
    )
}

fn is_counter_update(form: u32) -> bool {
    use angryier_semantics_intel64::forms as f;
    matches!(
        form,
        f::ADD_R64_IMM32
            | f::ADD_R32_IMM8
            | f::SUB_R64_IMM32
            | f::SUB_R32_IMM8
            | f::INC_R64
            | f::INC_R32
            | f::DEC_R64
            | f::DEC_R32
            | f::ADD_R64_R64
            | f::SUB_R64_R64
    )
}

fn is_sub_form(form: u32) -> bool {
    use angryier_semantics_intel64::forms as f;
    matches!(
        form,
        f::SUB_R64_IMM32 | f::SUB_R32_IMM8 | f::DEC_R64 | f::DEC_R32 | f::SUB_R64_R64
    )
}

fn is_nop(form: u32) -> bool {
    use angryier_semantics_intel64::forms as f;
    form == f::NOP
}

/// Folds a fully-concrete expression with a much deeper budget than
/// [`angryier_execution::constant_value`]: a stepped counter grows one Add
/// node per loop iteration and outruns the shared folder's depth cap while
/// staying trivially concrete. Covers the value-preserving ops a counter
/// chain is built from; `None` on anything else or on a non-constant leaf.
fn deep_constant_value(arena: &SymbolicArena, expression: ExprId) -> Option<u64> {
    fn eval(arena: &SymbolicArena, expression: ExprId, depth: u32) -> Option<u64> {
        if depth > 1024 {
            return None;
        }
        let node = arena.get(expression)?;
        // Arithmetic wraps at the node's own width.
        let mask = match node.sort {
            angryier_expr::ExprSort::BitVec(bits) if bits < 64 => (1u64 << bits) - 1,
            _ => u64::MAX,
        };
        let operand = |index: usize| eval(arena, node.operands.get(index).copied()?, depth + 1);
        match node.op {
            ExprOp::Constant => {
                let mut buffer = [0u8; 8];
                let len = node.immediate.len().min(8);
                buffer[..len].copy_from_slice(&node.immediate[..len]);
                Some(u64::from_le_bytes(buffer))
            }
            ExprOp::Add => Some(operand(0)?.wrapping_add(operand(1)?) & mask),
            ExprOp::Sub => Some(operand(0)?.wrapping_sub(operand(1)?) & mask),
            ExprOp::Mul => Some(operand(0)?.wrapping_mul(operand(1)?) & mask),
            ExprOp::And => Some(operand(0)? & operand(1)?),
            ExprOp::Or => Some(operand(0)? | operand(1)?),
            ExprOp::Xor => Some(operand(0)? ^ operand(1)?),
            ExprOp::Not => Some(!operand(0)? & mask),
            _ => None,
        }
    }
    eval(arena, expression, 0)
}

/// Whether the back-edge jcc compares signed (jl/jle/jg/jge) rather than
/// unsigned (jb/jbe/ja/jae).
fn jcc_signed(form: u32) -> bool {
    use angryier_semantics_intel64::forms as f;
    matches!(form, f::JL_REL32 | f::JLE_REL32 | f::JG_REL32 | f::JGE_REL32)
}

/// Longest straight-line body chain we will scan for induction patterns.
const MAX_LOOP_BODY_BLOCKS: usize = 8;
/// Instruction budget for one loop body scan.
const MAX_LOOP_BODY_INSNS: usize = 16;

/// The straight-line block chain of a natural loop: header → … → latch,
/// where every non-latch block has exactly one static successor (an
/// unconditional jump or plain fall-through into the next body block) and
/// the chain covers the whole body. Anything else — an inner branch (early
/// exit, inner loop), a call, a merge from within the body — is not
/// straight-line and returns `None`.
fn straight_line_body(cfg: &angryier_cfg::Cfg, lp: &angryier_cfg::Loop) -> Option<Vec<Address>> {
    use angryier_cfg::EdgeKind;
    let body: BTreeSet<Address> = lp.body.iter().copied().collect();
    if body.len() > MAX_LOOP_BODY_BLOCKS {
        return None;
    }
    let latch = lp.back_edge.0;
    let mut chain = vec![lp.header];
    let mut current = lp.header;
    while current != latch {
        let block = cfg.blocks.get(&current)?;
        let last = block.instructions.last()?.address;
        let successors: Vec<&angryier_cfg::CfgEdge> = cfg
            .edges
            .iter()
            .filter(|edge| edge.from == last && edge.to.is_some())
            .collect();
        // Exactly one static successor, reachable by an unconditional link
        // or plain fall-through — a conditional inside the body is an inner
        // branch (its two edges would both appear), and calls/returns/
        // indirect edges are not straight-line.
        if successors.len() != 1 {
            return None;
        }
        let edge = successors.first()?;
        if !matches!(edge.kind, EdgeKind::FallThrough | EdgeKind::Unconditional) {
            return None;
        }
        let next = edge.to?;
        if !body.contains(&next) {
            return None;
        }
        chain.push(next);
        current = next;
    }
    if chain.len() != body.len() {
        return None;
    }
    Some(chain)
}

/// Extracts the induction pattern of a natural loop whose body is a
/// straight-line block chain: the concatenated instructions (minus the
/// chain-link jumps, which have no state effect) must be nothing but
/// counter updates and a final `cmp counter, bound` feeding the back-edge
/// jcc. `None` when the shape does not match — the loop keeps stepping.
fn summarize_induction_loop(cfg: &angryier_cfg::Cfg, lp: &angryier_cfg::Loop) -> Option<LoopSummary> {
    use angryier_arch::OperandKind;
    use angryier_semantics_intel64::forms as f;
    let chain = straight_line_body(cfg, lp)?;
    // Concatenate the body instructions in execution order, dropping the
    // unconditional jumps that chain blocks together.
    let mut insns: Vec<angryier_arch::DecodedInstruction> = Vec::new();
    for (i, &start) in chain.iter().enumerate() {
        let block = cfg.blocks.get(&start)?;
        let count = block.instructions.len();
        for (j, insn) in block.instructions.iter().enumerate() {
            let links_next = j + 1 == count && i + 1 < chain.len() && insn.form_id == f::JMP_REL32;
            if !links_next {
                insns.push(insn.clone());
            }
        }
        if insns.len() > MAX_LOOP_BODY_INSNS {
            return None;
        }
    }
    if insns.len() < 2 {
        return None;
    }
    // Last insn must be a conditional branch back to the header; its
    // fall-through is the loop exit.
    let term = insns.last()?.clone();
    if !is_jcc(term.form_id) {
        return None;
    }
    let back = term.operands.iter().find_map(|o| {
        if let OperandKind::RelativeBranch(rb) = &o.kind {
            Some(term.relative_target(*rb))
        } else {
            None
        }
    })?;
    if back != lp.header {
        return None;
    }
    let exit = term.address + u64::from(term.length);
    // Scan the body: counter updates first, then the compare that feeds the
    // back edge. The closed forms model update-then-test, so a compare seen
    // before an update (test-then-increment shapes) is not summarized.
    let mut counter: Option<u32> = None;
    let mut bound = Bound::None;
    let mut step: i64 = 0;
    let mut width: u16 = 0;
    let mut update_reg: Option<u32> = None;
    let mut pure = true;
    for insn in &insns[..insns.len() - 1] {
        let reg_operand = insn.operands.iter().find_map(|o| {
            if let OperandKind::Register(rv) = &o.kind {
                Some((rv.parent.0, o.width_bits))
            } else {
                None
            }
        });
        match insn.form_id {
            form if is_cmp_reg(form) => {
                let imm = insn.operands.iter().find_map(|o| {
                    if let OperandKind::Immediate(i) = &o.kind {
                        Some(i.value)
                    } else {
                        None
                    }
                });
                let Some((reg, reg_width)) = reg_operand else {
                    pure = false;
                    continue;
                };
                if counter.is_some() {
                    pure = false; // one compare only
                    continue;
                }
                counter = Some(reg);
                if width == 0 {
                    width = reg_width;
                } else if width != reg_width {
                    pure = false;
                }
                bound = match imm {
                    Some(v) => Bound::Imm(v),
                    None => match insn.operands.get(1).map(|o| &o.kind) {
                        Some(OperandKind::Register(rv)) => Bound::Reg(rv.parent.0),
                        _ => Bound::None,
                    },
                };
                if bound == Bound::Reg(reg) {
                    pure = false; // `cmp counter, counter` carries no bound
                }
            }
            form if is_counter_update(form) => {
                // Register-register add/sub steps through a variable — not a
                // concrete induction step.
                if matches!(form, f::ADD_R64_R64 | f::SUB_R64_R64) {
                    pure = false;
                    continue;
                }
                if counter.is_some() {
                    pure = false; // update after the compare: test-then-inc
                    continue;
                }
                let imm = insn.operands.iter().find_map(|o| {
                    if let OperandKind::Immediate(i) = &o.kind {
                        Some(i.value as i64)
                    } else {
                        None
                    }
                });
                let Some((reg, reg_width)) = reg_operand else {
                    pure = false;
                    continue;
                };
                if update_reg.is_some_and(|r| r != reg) {
                    pure = false; // two different counters
                    continue;
                }
                update_reg = Some(reg);
                if width == 0 {
                    width = reg_width;
                } else if width != reg_width {
                    pure = false;
                }
                step += match imm {
                    Some(v) if is_sub_form(form) => -v,
                    Some(v) => v,
                    None if is_sub_form(form) => -1, // dec
                    None => 1,                       // inc
                };
            }
            form if is_nop(form) => {}
            _ => pure = false,
        }
    }
    let counter = counter?;
    let cond = jcc_cond(term.form_id)?;
    if !pure || step == 0 || update_reg != Some(counter) || !matches!(width, 32 | 64) {
        return None;
    }
    Some(LoopSummary {
        header: lp.header,
        exit,
        counter,
        step,
        bound,
        cond,
        signed: jcc_signed(term.form_id),
        width,
    })
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
        match self.state.registers.read_value(register) {
            // Concrete values copy out of the shared `Arc`; symbolic
            // registers read as unknown, exactly like `RegisterState::read`.
            Ok(RegisterValue::Concrete(bytes)) => Some(bytes.as_ref().to_vec()),
            _ => None,
        }
    }

    fn register_width(&self, register: u32) -> Option<u16> {
        self.state
            .registers
            .register_width(register)
            .and_then(|bytes| u16::try_from(bytes * 8).ok())
    }

    fn read_register_into(&self, register: u32, out: &mut [u8]) -> bool {
        match self.state.registers.read_value(register) {
            // An Arc bump and a copy — no heap allocation on the shadow's
            // per-register hot path.
            Ok(RegisterValue::Concrete(bytes)) if bytes.len() >= out.len() => {
                out.copy_from_slice(&bytes[..out.len()]);
                true
            }
            _ => false,
        }
    }

    fn read_bytes(&self, address: u64, length: usize) -> Option<Vec<ByteValue>> {
        self.state.memory.read(address, length).ok()
    }

    fn read_bytes_into(&self, address: u64, out: &mut [ByteValue]) -> bool {
        LayeredMemory::read_into(&self.state.memory, address, out).is_ok()
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

    /// Promotes this concolic state into a PROVE-mode `SymbolicState`: the
    /// shadow registers/memory become symbolic bindings, the recorded path
    /// becomes initial constraints, and the concrete process carries over.
    /// The driver can seed a `SymbolicSession` with the result.
    pub fn promote_to_symbolic(&self, id: u64) -> SymbolicState {
        let mut registers = BTreeMap::new();
        let mut symbols = Vec::new();
        let mut concrete_registers = BTreeMap::new();
        let mut expr_concrete = BTreeMap::new();
        for (reg, (expr, ty)) in self.evaluator.shadow_registers() {
            registers.insert(*reg, (*expr, *ty));
        }
        for (reg, v) in self.evaluator.register_concretes() {
            if let Some(c) = v {
                concrete_registers.insert(*reg, u64::try_from(*c).unwrap_or(*c as u64));
                if let Some((expr, _)) = self.evaluator.shadow_registers().get(reg) {
                    expr_concrete.insert(*expr, u64::try_from(*c).unwrap_or(*c as u64));
                }
            }
        }
        for b in self.evaluator.bindings() {
            let (register, width) = match b.source {
                angryier_execution::ConcolicSource::Register { register, width } => (register, width),
                // Memory-sourced symbols bind to a synthetic id past the GPR
                // bank — the solver keys on `expression`, not `register`.
                angryier_execution::ConcolicSource::Memory { .. } => (u32::MAX, 8),
            };
            symbols.push(angryier_execution::SymbolBinding {
                register,
                width,
                expression: b.expression,
            });
        }
        // Seed symbolic memory from the concrete image, then overlay the
        // shadow's bytes (marked input regions included).
        let mut memory = angryier_execution::SymbolicSessionMemory::new(self.process.state.memory.clone());
        for (addr, byte) in self.evaluator.shadow_memory() {
            if let Ok(m) = memory.memory.write_at_address(*addr, &[*byte]) {
                memory.memory = m;
            }
        }
        // Path conditions become constraints: `taken` branches keep the
        // predicate, untaken get its negation.
        let mut constraints = Vec::with_capacity(self.path.len());
        for pc in &self.path {
            // Branch predicates are BitVec(1) — coerce to Bool, then negate
            // when the concrete run took the not-taken edge.
            let cond = angryier_execution::bit_to_bool(self.arena, pc.condition).unwrap_or(pc.condition);
            let expr = if pc.taken {
                cond
            } else {
                self.arena
                    .intern(angryier_expr::ExprNode {
                        sort: angryier_expr::ExprSort::Bool,
                        op: angryier_expr::ExprOp::Not,
                        operands: vec![cond],
                        immediate: Vec::new(),
                    })
                    .unwrap_or(cond)
            };
            constraints.push(expr);
        }
        SymbolicState {
            process: self.process.clone(),
            registers,
            constraints,
            memory,
            symbols,
            concrete_registers,
            id,
            expr_concrete,
        }
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

/// Applies a block-execution outcome to the process — the shared tail of the
/// cached and freshly lowered paths through [`Runtime::step_with`].
/// Pops a call frame: RIP = `[RSP]`; RSP += 8 — the return convention for
/// instance SimProcedure hooks at call targets (see
/// `Runtime::dispatch_simproc_instance`). Symbolic bytes in the return slot
/// concretize to 0, matching the fetch path's concrete read.
/// Reads the return address at RSP WITHOUT advancing the stack — the
/// caller-site capture for kernel-model events (the modeled stub
/// terminates the call itself, so the address is the call's return site in
/// the driver image).
fn peek_call_return(process: &Process) -> Result<u64, RuntimeError> {
    let rsp = process.read_register(register_id::GPR_BASE + 4)?;
    let mut frame = [ByteValue::Concrete(0); 8];
    process
        .state
        .memory
        .read_into(rsp, &mut frame)
        .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
    let mut target = 0u64;
    for (i, byte) in frame.iter().enumerate() {
        let value = match byte {
            ByteValue::Concrete(b) => *b,
            ByteValue::Symbolic(_) => 0,
        };
        target |= u64::from(value) << (i * 8);
    }
    Ok(target)
}

fn pop_call_return(process: &mut Process) -> Result<u64, RuntimeError> {
    let rsp = process.read_register(register_id::GPR_BASE + 4)?;
    let mut frame = [ByteValue::Concrete(0); 8];
    process
        .state
        .memory
        .read_into(rsp, &mut frame)
        .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
    let mut target = 0u64;
    for (i, byte) in frame.iter().enumerate() {
        let value = match byte {
            ByteValue::Concrete(b) => *b,
            ByteValue::Symbolic(_) => 0,
        };
        target |= u64::from(value) << (i * 8);
    }
    process.write_register(register_id::GPR_BASE + 4, rsp.wrapping_add(8))?;
    process.write_pc(target)?;
    Ok(target)
}

fn finish_step(
    process: &mut Process,
    pc: Address,
    length: u8,
    form_id: u32,
    outcome: ExecutionOutcome,
) -> Result<StepOutcome, RuntimeError> {
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

    #[test]
    fn pci_config_read_model() {
        // Host bridge: vendor/device at offset 0, class at 8.
        assert_eq!(pci_config_read(0, 0, 0, 0x00), 0x1450_1022);
        assert_eq!(pci_config_read(0, 0, 0, 0x08), 0x0600_0000);
        // SMBus at its standard slot.
        assert_eq!(pci_config_read(0, 0x14, 0, 0x00), 0x790B_1022);
        assert_eq!(pci_config_read(0, 0x14, 0, 0x08), 0x0C05_0000);
        // Every other slot reads "no device" so scans terminate.
        assert_eq!(pci_config_read(0, 1, 0, 0x00), 0xFFFF_FFFF);
        assert_eq!(pci_config_read(0, 0, 1, 0x00), 0xFFFF_FFFF);
        assert_eq!(pci_config_read(1, 0, 0, 0x00), 0xFFFF_FFFF);
        assert_eq!(pci_config_read(0, 0, 0, 0x10), 0); // BAR reads zero
    }

    /// IN/OUT port dispatch: 0xCF8 latch, 0xCFC config reads with
    /// byte-offset addressing, other ports read zero.
    #[test]
    fn port_io_pci_latch() -> Result<(), RuntimeError> {
        let runtime = Runtime::new(SyntheticDecoder::new(), SemanticVersion(1), TargetProfileId(1));
        let mut process = minimal_process()?;
        let rax = register_id::GPR_BASE;
        // Build OUT DX, EAX / IN EAX, DX decoded operands by hand.
        let port_reg = |index: u8| Operand {
            index,
            width_bits: 16,
            access: AccessKind::Read,
            visibility: OperandVisibility::Explicit,
            kind: OperandKind::Register(RegisterView {
                parent: RegisterId(register_id::GPR_BASE + 2),
                bit_offset: 0,
                width_bits: 16,
                write_behavior: angryier_arch::RegisterWriteBehavior::PreserveParent,
            }),
        };
        let out_decoded = DecodedInstruction {
            address: 0x1000,
            length: 1,
            form_id: angryier_semantics_intel64::forms::OUT_DX_EAX,
            features: vec![],
            operands: vec![
                port_reg(0),
                Operand {
                    index: 1,
                    width_bits: 32,
                    access: AccessKind::Read,
                    visibility: OperandVisibility::Explicit,
                    kind: OperandKind::Register(RegisterView {
                        parent: RegisterId(rax),
                        bit_offset: 0,
                        width_bits: 32,
                        write_behavior: angryier_arch::RegisterWriteBehavior::ZeroExtendParent,
                    }),
                },
            ],
            modifiers: InstructionModifiers::default(),
        };
        let in_decoded = DecodedInstruction {
            address: 0x1001,
            length: 1,
            form_id: angryier_semantics_intel64::forms::IN_EAX_DX,
            features: vec![],
            operands: vec![
                Operand {
                    index: 0,
                    width_bits: 32,
                    access: AccessKind::Write,
                    visibility: OperandVisibility::Explicit,
                    kind: OperandKind::Register(RegisterView {
                        parent: RegisterId(rax),
                        bit_offset: 0,
                        width_bits: 32,
                        write_behavior: angryier_arch::RegisterWriteBehavior::ZeroExtendParent,
                    }),
                },
                port_reg(1),
            ],
            modifiers: InstructionModifiers::default(),
        };
        // Write the config address for the host bridge offset 0.
        process.write_register(rax, 0x8000_0000)?; // EAX = addr (enable | bus0 dev0 fn0 off0)
        process.write_register(register_id::GPR_BASE + 2, 0xCF8)?; // DX
        let _ = runtime.execute_port_out(&mut process, 0x1000, 1, &out_decoded)?;
        assert_eq!(process.pci_config_address, 0x8000_0000);
        // Read vendor/device at 0xCFC.
        process.write_register(register_id::GPR_BASE + 2, 0xCFC)?; // DX
        let _ = runtime.execute_port_in(&mut process, 0x1001, 1, &in_decoded)?;
        assert_eq!(process.read_register(rax)?, 0x1450_1022);
        // Byte-offset read: 0xCFE returns the high word (class low half).
        process.write_register(register_id::GPR_BASE + 2, 0xCFE)?;
        let _ = runtime.execute_port_in(&mut process, 0x1001, 1, &in_decoded)?;
        assert_eq!(process.read_register(rax)?, 0x1450_1022 >> 16);
        // Non-PCI port reads zero.
        process.write_register(register_id::GPR_BASE + 2, 0x80)?;
        let _ = runtime.execute_port_in(&mut process, 0x1001, 1, &in_decoded)?;
        assert_eq!(process.read_register(rax)?, 0);
        Ok(())
    }

    /// A minimal process with canonical register widths and empty memory,
    /// sufficient for register-only handler tests.
    fn minimal_process() -> Result<Process, RuntimeError> {
        let reg_file = Intel64RegisterFile::canonical();
        let registers = PersistentRegisters::from_widths(
            reg_file
                .architectural_registers
                .iter()
                .map(|(id, bits)| (id.0, usize::from(*bits).div_ceil(8))),
        )
        .map_err(|e| RuntimeError::Register(format!("{e:?}")))?;
        let memory = PersistentMemory::new(Vec::new()).map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
        Ok(Process {
            image_id: ImageId(1),
            target_profile: TargetProfileId(1),
            entry: 0x1000,
            entry_state: ExecutionState {
                id: StateId(1),
                parent: None,
                target_profile: TargetProfileId(1),
                registers: registers.clone(),
                memory: memory.clone(),
                constraints: PersistentConstraintLineage::new(),
                ownership: StateOwnership::default(),
                fidelity: FidelityLedger::new(FidelityProfile::Prove),
            },
            state: ExecutionState {
                id: StateId(1),
                parent: None,
                target_profile: TargetProfileId(1),
                registers,
                memory,
                constraints: PersistentConstraintLineage::new(),
                ownership: StateOwnership::default(),
                fidelity: FidelityLedger::new(FidelityProfile::Prove),
            },
            block_cache: BTreeMap::new(),
            step_cache: BTreeMap::new(),
            simproc_hooks: BTreeMap::new(),
            pe_import_stubs: BTreeMap::new(),
            simproc_instances: BTreeMap::new(),
            kernel_pool: None,
            pci_config_address: 0,
            symbols: Vec::new(),
            trace: Vec::new(),
            syscalls: SyscallModel::new(),
            program_break: 0,
            heap_end: 0,
            mmap_next: MMAP_BASE,
            files: BTreeMap::new(),
            open_fds: BTreeMap::new(),
            symbolic_files: std::collections::BTreeSet::new(),
            symbolic_fds: std::collections::BTreeSet::new(),
            argv0_addr: None,
            stdin: Vec::new(),
            stdin_pos: 0,
            next_fd: 3,
            next_block_id: 0,
            step_count: 0,
            simproc_dispatches: 0,
            terminated: false,
        })
    }

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

/// A summarized loop's operand (counter or bound) as resolved in one state:
/// folded to a constant, or the symbolic expression behind it.
#[derive(Clone, Copy, Debug)]
enum LoopValue {
    /// The register folds to this constant.
    Concrete(u64),
    /// The register holds this symbolic expression of `width` bits.
    Symbolic(ExprId, u16),
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
    /// Per-session flight recorder (Phase 12) — bounded provenance ring.
    pub recorder: angryier_provenance::FlightRecorder,
    /// Next provenance node id.
    next_prov_node: u64,
    /// Loop summaries keyed by header — populated by
    /// [`Self::enable_loop_summaries`]; a state landing on a summarized
    /// header with a concrete counter/bound collapses the remaining
    /// iterations into one step.
    loop_summaries: BTreeMap<Address, LoopSummary>,
    /// Pure-function summaries keyed by callee entry — populated by
    /// [`Self::enable_function_summaries`]; a call whose callee qualifies
    /// collapses into one step via a cached expression template
    /// (see [`function_summaries`]). `Arc`-shared so parallel shards clone
    /// the map by reference count.
    function_summaries: BTreeMap<Address, std::sync::Arc<function_summaries::FunctionSummary>>,
    /// Built summary templates keyed by (callee entry, argument widths).
    function_templates: BTreeMap<(Address, Vec<u16>), function_summaries::FunctionTemplate>,
    /// Shapes whose template build failed — remembered so the cost is paid
    /// once per shape (that shape keeps stepping forever after).
    failed_templates: BTreeSet<(Address, Vec<u16>)>,
    /// Indirect-call targets whose lazy per-target extraction already ran
    /// and failed — never retried (the static call-edge pass cannot see
    /// indirect-only callees, so this is the negative cache for them).
    lazy_summary_targets: BTreeSet<Address>,
    /// Placeholder merge-cost model — the summarize-vs-inline seam.
    /// `Arc`-shared with parallel shards.
    summary_cost_model: std::sync::Arc<dyn function_summaries::FunctionSummaryCostModel>,
    /// Evidence counters: template applications and builds.
    function_summary_hits: u64,
    function_summary_builds: u64,
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
            recorder: angryier_provenance::FlightRecorder::new(4096),
            next_prov_node: 0,
            loop_summaries: BTreeMap::new(),
            function_summaries: BTreeMap::new(),
            function_templates: BTreeMap::new(),
            failed_templates: BTreeSet::new(),
            lazy_summary_targets: BTreeSet::new(),
            summary_cost_model: std::sync::Arc::new(function_summaries::DepthWidthCostModel::default()),
            function_summary_hits: 0,
            function_summary_builds: 0,
        }
    }

    /// Emits a provenance event into the flight recorder.
    fn record_event(
        &mut self,
        state: u64,
        kind: angryier_provenance::ProvenanceEventKind,
        tier: angryier_types::ProvenanceTier,
        parents: Vec<angryier_types::ProvenanceNodeId>,
    ) {
        let node = angryier_types::ProvenanceNodeId(self.next_prov_node);
        self.next_prov_node += 1;
        let event = angryier_provenance::ProvenanceEvent {
            id: node,
            sequence: angryier_types::ProvenanceSeq(self.next_prov_node),
            state: angryier_types::StateId(state),
            tier,
            kind,
            semantic_content: None,
            parents,
        };
        let _ = self.recorder.record(event);
    }

    /// Attaches a CFG so `run_with_policy` merges reconverging states at
    /// static merge points (Veritesting-style) rather than only when two
    /// states happen to park at the same pc.
    pub fn with_cfg(mut self, cfg: &'a angryier_cfg::Cfg) -> Self {
        self.cfg = Some(cfg);
        self
    }

    /// Computes loop summaries for the loaded image and enables collapsing:
    /// pure induction loops (straight-line bodies, concrete counter update,
    /// compare feeding the back edge) then run in O(1) — concretely through
    /// the closed-form trip count, and with symbolic counters/bounds through
    /// the closed-form exit-counter expression plus the exit-condition
    /// constraint. Eq/Ne exits included; everything else keeps stepping.
    pub fn enable_loop_summaries(&mut self) {
        if let Some(state) = self.states.first() {
            self.loop_summaries = self
                .runtime
                .loop_summaries(&state.process)
                .into_iter()
                .map(|s| (s.header, s))
                .collect();
        }
    }

    /// Collapses a summarized loop in one step. Concrete counter and bound
    /// take the closed-form trip count; a symbolic counter and/or bound gets
    /// a closed-form exit-counter expression (built over the machine's
    /// wrapping bitvector semantics, merging the loop-more and exit-now
    /// futures exactly the way stepping-then-merging would) plus the
    /// exit-condition constraint, so downstream solving sees precisely the
    /// summarized path. Returns `None` whenever the shape is not
    /// expressible — the state then executes normally, because a wrong
    /// summary is worse than no summary.
    fn try_loop_summary(&mut self, index: usize, summary: LoopSummary) -> Option<SymbolicStepOutcome> {
        let counter = self.resolve_loop_value(index, summary.counter)?;
        let bound = match summary.bound {
            Bound::Imm(v) => LoopValue::Concrete(v),
            Bound::Reg(r) => self.resolve_loop_value(index, r)?,
            Bound::None => return None,
        };
        match (counter, bound) {
            (LoopValue::Concrete(c), LoopValue::Concrete(b)) => self.apply_concrete_loop_summary(index, &summary, c, b),
            (counter, bound) => self.apply_symbolic_loop_summary(index, &summary, counter, bound),
        }
    }

    /// Resolves `register` in state `index` for summarization: the symbolic
    /// binding when one exists (folding it when it is constant), else the
    /// concrete shadow. `None` when nothing is known.
    fn resolve_loop_value(&self, index: usize, register: u32) -> Option<LoopValue> {
        let state = self.states.get(index)?;
        if let Some((expr, ty)) = state.registers.get(&register) {
            let width = match ty {
                angryier_ir::IrType::Bits(w) => *w,
                _ => 64,
            };
            if let Ok(value) = angryier_execution::constant_value(self.arena, *expr) {
                return Some(LoopValue::Concrete(value));
            }
            // A counter the state has stepped grows one Add node per loop
            // iteration, outgrowing the shared folder's depth cap — but a
            // symbol-free expression still has a definite value. Fold deeper
            // before calling it symbolic: misclassifying a constant would
            // let the Ne divisibility constraint prune the real future (a
            // wrong summary), so unfoldable symbol-free values get no
            // summary at all.
            let symbolic = self
                .arena
                .dependency_summary(*expr)
                .map(|summary| !summary.symbolic_sources.is_empty())
                .unwrap_or(true);
            if !symbolic {
                return deep_constant_value(self.arena, *expr).map(LoopValue::Concrete);
            }
            return Some(LoopValue::Symbolic(*expr, width));
        }
        let value = state
            .concrete_registers
            .get(&register)
            .copied()
            .or_else(|| state.process.read_register(register).ok())?;
        Some(LoopValue::Concrete(value))
    }

    /// Concrete trip count: computes the remaining iterations in closed
    /// form — flavor- and width-exact over the compare's domain — and
    /// writes the exit counter. `None` (fall through to stepping) whenever
    /// the arithmetic could wrap out of that domain, the distance is not
    /// reachable (Ne exits), or the trip count is absurd.
    fn apply_concrete_loop_summary(
        &mut self,
        index: usize,
        summary: &LoopSummary,
        counter: u64,
        bound: u64,
    ) -> Option<SymbolicStepOutcome> {
        let width = u32::from(summary.width.min(64));
        let mask = if width >= 64 { u64::MAX } else { (1u64 << width) - 1 };
        let c = counter & mask;
        let b = bound & mask;
        let s = i128::from(summary.step); // nonzero by construction
        // Interpret at the compare's width: signed comparisons sign-extend
        // from `width` bits, unsigned use the plain pattern.
        let extend = |v: u64| -> i128 {
            if !summary.signed || width >= 64 {
                i128::from(v)
            } else if (v >> (width - 1)) & 1 == 1 {
                i128::from(v) - (1i128 << width)
            } else {
                i128::from(v)
            }
        };
        let sc = extend(c);
        let sb = extend(b);
        // Inclusive domain bounds in extended units.
        let (bottom, top): (i128, i128) = if summary.signed {
            (-(1i128 << (width - 1)), (1i128 << (width - 1)) - 1)
        } else {
            (0, (1i128 << width) - 1)
        };
        let trip_limit = 1i128 << 40;
        // Inequality exits: only the natural direction (count-up for Lt/Le,
        // count-down for Gt/Ge) has a finite closed form.
        let natural = matches!(
            (summary.cond, s > 0),
            (LoopCond::Lt, true) | (LoopCond::Le, true) | (LoopCond::Gt, false) | (LoopCond::Ge, false)
        );
        let (n, final_counter): (i128, u64) = match summary.cond {
            LoopCond::Lt | LoopCond::Le | LoopCond::Gt | LoopCond::Ge if natural => {
                // Does the first body execution (counter + step) already
                // satisfy the exit test? Otherwise iterate until it does.
                let first = sc + s;
                let exit_now = match summary.cond {
                    LoopCond::Lt => first >= sb,
                    LoopCond::Le => first > sb,
                    LoopCond::Gt => first <= sb,
                    LoopCond::Ge => first < sb,
                    _ => return None,
                };
                let (iterations, exit_ext) = if exit_now {
                    (1, sc + s)
                } else {
                    let distance = match summary.cond {
                        // steps until the counter is past (or at) the bound
                        LoopCond::Lt => sb - sc,
                        LoopCond::Le => sb + 1 - sc,
                        LoopCond::Gt => sc - sb,
                        LoopCond::Ge => sc + 1 - sb,
                        _ => return None,
                    };
                    let magnitude = s.abs();
                    let steps = (distance + magnitude - 1) / magnitude;
                    (steps, sc + steps * s)
                };
                if !(1..=trip_limit).contains(&iterations) {
                    return None;
                }
                // The whole walk must stay inside the compare's domain — an
                // exit value (or any intermediate one) that wraps out of it
                // means the closed form no longer matches the machine, so
                // keep stepping.
                if !(bottom..=top).contains(&exit_ext) {
                    return None;
                }
                (iterations, (exit_ext as u64) & mask)
            }
            // je back edge: exit when the counter differs from the bound.
            // The body always runs once; if that value lands exactly on the
            // bound the back edge is taken exactly once more. Wrapping here
            // is the machine's own semantics — no domain check.
            LoopCond::Eq => {
                let step = summary.step as u64;
                let e1 = c.wrapping_add(step) & mask;
                if e1 == b {
                    (2, b.wrapping_add(step) & mask)
                } else {
                    (1, e1)
                }
            }
            // jne back edge: exit when the counter reaches the bound — the
            // step must divide the distance cleanly, otherwise the bound is
            // unreachable and the loop keeps stepping.
            LoopCond::Ne => {
                let distance = b.wrapping_sub(c);
                let magnitude = summary.step.unsigned_abs();
                if distance == 0 || !distance.is_multiple_of(magnitude) {
                    return None;
                }
                (i128::from(distance / magnitude), b)
            }
            _ => return None,
        };
        if !(1..=trip_limit).contains(&n) {
            return None;
        }
        self.write_summary_result(index, summary, final_counter, None)
    }

    /// Symbolic trip count: counter and/or bound are expressions, the step a
    /// concrete nonzero constant. The exit counter is built as a closed-form
    /// expression over the machine's wrapping bitvector semantics — an `ite`
    /// that merges the loop-more and exit-now futures (the merge stepping
    /// would produce), with corner arms covering the wraparound entries —
    /// and the exit-condition constraint is appended so downstream solving
    /// sees exactly the summarized path. `None` keeps the state stepping.
    #[allow(clippy::too_many_lines)]
    fn apply_symbolic_loop_summary(
        &mut self,
        index: usize,
        summary: &LoopSummary,
        counter: LoopValue,
        bound: LoopValue,
    ) -> Option<SymbolicStepOutcome> {
        let w = summary.width.min(64);
        let s = summary.step;
        let signed = summary.signed;
        let inequality = matches!(summary.cond, LoopCond::Lt | LoopCond::Le | LoopCond::Gt | LoopCond::Ge);
        // Inequality summaries need a unit step (clean closed forms) in the
        // natural direction; anything else keeps stepping.
        if inequality
            && !matches!(
                (summary.cond, s),
                (LoopCond::Lt, 1) | (LoopCond::Le, 1) | (LoopCond::Gt, -1) | (LoopCond::Ge, -1)
            )
        {
            return None;
        }
        let bits = usize::from(w);
        let mask: u64 = if w >= 64 { u64::MAX } else { (1u64 << w) - 1 };
        // Domain corners as bit patterns: where a +1/-1 wraps.
        let (bottom, top): (u64, u64) = if signed {
            (1u64 << (w - 1), (1u64 << (w - 1)) - 1)
        } else {
            (0, mask)
        };

        let arena = self.arena;
        let bv = angryier_expr::ExprSort::BitVec(w);
        let boolean = angryier_expr::ExprSort::Bool;
        let konst = |value: u64| -> Option<ExprId> {
            let mut pattern = (value & mask).to_le_bytes().to_vec();
            pattern.truncate(bits.div_ceil(8));
            arena
                .intern(angryier_expr::ExprNode {
                    sort: bv,
                    op: ExprOp::Constant,
                    operands: Vec::new(),
                    immediate: pattern,
                })
                .ok()
        };
        let node = |op: ExprOp, operands: Vec<ExprId>, sort: angryier_expr::ExprSort| -> Option<ExprId> {
            arena
                .intern(angryier_expr::ExprNode {
                    sort,
                    op,
                    operands,
                    immediate: Vec::new(),
                })
                .ok()
        };
        // Coerce one side to the loop's compare width (sign-extend for
        // signed flavors so the wider compare matches the architectural
        // one), constants truncate to the width-bit slice.
        let coerce = |value: LoopValue| -> Option<ExprId> {
            match value {
                LoopValue::Concrete(v) => konst(v),
                LoopValue::Symbolic(expr, expr_width) => {
                    if expr_width == w {
                        Some(expr)
                    } else if expr_width < w {
                        let op = if signed { ExprOp::SExt } else { ExprOp::ZExt };
                        node(op, vec![expr], bv)
                    } else {
                        let mut immediate = Vec::with_capacity(4);
                        immediate.extend_from_slice(&0u16.to_le_bytes());
                        immediate.extend_from_slice(&w.to_le_bytes());
                        arena
                            .intern(angryier_expr::ExprNode {
                                sort: bv,
                                op: ExprOp::Extract,
                                operands: vec![expr],
                                immediate,
                            })
                            .ok()
                    }
                }
            }
        };
        let c = coerce(counter)?;
        let b = coerce(bound)?;
        let step_const = konst(s as u64)?;
        let add_step = |x: ExprId| node(ExprOp::Add, vec![x, step_const], bv);
        let eq = |x: ExprId, y: ExprId| node(ExprOp::Eq, vec![x, y], boolean);
        let lt = |x: ExprId, y: ExprId| node(if signed { ExprOp::Slt } else { ExprOp::Ult }, vec![x, y], boolean);
        let le = |x: ExprId, y: ExprId| node(if signed { ExprOp::Sle } else { ExprOp::Ule }, vec![x, y], boolean);
        let ite = |guard: ExprId, then: ExprId, else_: ExprId| node(ExprOp::Ite, vec![guard, then, else_], bv);
        let bool_konst = |value: bool| -> Option<ExprId> {
            arena
                .intern(angryier_expr::ExprNode {
                    sort: boolean,
                    op: ExprOp::Constant,
                    operands: Vec::new(),
                    immediate: vec![u8::from(value)],
                })
                .ok()
        };
        // Boolean disjunction/conjunction encoded through Ite: the native
        // FFI bridge only maps And/Or onto bitvector ops, while Ite is
        // sort-generic there — `a || b` as `ite(a, true, b)`, `a && b` as
        // `ite(a, b, false)`.
        let or = |x: ExprId, y: ExprId| -> Option<ExprId> { node(ExprOp::Ite, vec![x, bool_konst(true)?, y], boolean) };
        let and =
            |x: ExprId, y: ExprId| -> Option<ExprId> { node(ExprOp::Ite, vec![x, y, bool_konst(false)?], boolean) };
        let not = |x: ExprId| node(ExprOp::Not, vec![x], boolean);
        // Can this side's value be the wrap corner? Concrete values compare
        // directly; a symbolic one might be anything.
        let hits = |value: LoopValue, corner: u64| match value {
            LoopValue::Concrete(v) => (v & mask) == corner,
            LoopValue::Symbolic(..) => true,
        };

        let e_expr: ExprId;
        let mut constraints: Vec<ExprId> = Vec::new();
        match summary.cond {
            // Exit when counter >= bound: count up to the bound, or fall
            // out after one body when already past it. A counter at the top
            // wraps to the bottom and climbs back to the bound — unless the
            // bound is the bottom itself, where it exits immediately.
            LoopCond::Lt => {
                let mut guard = lt(c, b)?;
                if hits(counter, top) {
                    let corner = and(eq(c, konst(top)?)?, not(eq(b, konst(bottom)?)?)?)?;
                    guard = or(guard, corner)?;
                }
                e_expr = ite(guard, b, add_step(c)?)?;
                constraints.push(le(b, e_expr)?);
            }
            // Exit when counter > bound: count up past the bound.
            LoopCond::Le => {
                // A bound at the top never satisfies e > b — that future
                // never terminates, so it is constrained away.
                if hits(bound, top) {
                    match bound {
                        LoopValue::Concrete(_) => return None,
                        LoopValue::Symbolic(..) => constraints.push(not(eq(b, konst(top)?)?)?),
                    }
                }
                let mut guard = le(c, b)?;
                if hits(counter, top) {
                    guard = or(guard, eq(c, konst(top)?)?)?;
                }
                e_expr = ite(guard, add_step(b)?, add_step(c)?)?;
                constraints.push(lt(b, e_expr)?);
            }
            // Exit when counter <= bound: count down to the bound. A
            // counter at the bottom wraps to the top and descends back —
            // unless the bound is the top itself.
            LoopCond::Gt => {
                let mut immediate = add_step(c)?;
                if hits(counter, bottom) {
                    // Wrapped top: exits at the bound (or stays at the top
                    // when the bound is the top, which is the unwrapped
                    // value anyway).
                    let corner = ite(eq(b, konst(top)?)?, immediate, b)?;
                    immediate = ite(eq(c, konst(bottom)?)?, corner, immediate)?;
                }
                e_expr = ite(lt(b, c)?, b, immediate)?;
                constraints.push(le(e_expr, b)?);
            }
            // Exit when counter < bound: count down past the bound.
            LoopCond::Ge => {
                // A bound at the bottom never satisfies e < b — that future
                // never terminates, so it is constrained away.
                if hits(bound, bottom) {
                    match bound {
                        LoopValue::Concrete(_) => return None,
                        LoopValue::Symbolic(..) => constraints.push(not(eq(b, konst(bottom)?)?)?),
                    }
                }
                let mut guard = le(b, c)?;
                if hits(counter, bottom) {
                    guard = or(guard, eq(c, konst(bottom)?)?)?;
                }
                e_expr = ite(guard, add_step(b)?, add_step(c)?)?;
                constraints.push(lt(e_expr, b)?);
            }
            // je back edge — exit when the counter differs from the bound:
            // one body unless the first value lands exactly on the bound,
            // in which case exactly two. Wrapping here is the machine's own
            // semantics, so the formula is exact for any step size.
            LoopCond::Eq => {
                let first = add_step(c)?;
                e_expr = ite(eq(first, b)?, add_step(b)?, first)?;
                constraints.push(not(eq(e_expr, b)?)?);
            }
            // jne back edge — exit when the counter reaches the bound: the
            // exit counter IS the bound. Reaching it at all requires the
            // step to divide the distance cleanly; the divisibility
            // constraint carries that (a unit step always divides).
            LoopCond::Ne => {
                e_expr = b;
                if s != 1 && s != -1 {
                    let magnitude = s.unsigned_abs();
                    let distance = node(ExprOp::Sub, vec![b, c], bv)?;
                    let quotient = node(ExprOp::UDiv, vec![distance, konst(magnitude)?], bv)?;
                    let scaled = node(ExprOp::Mul, vec![quotient, konst(magnitude)?], bv)?;
                    let remainder = node(ExprOp::Sub, vec![distance, scaled], bv)?;
                    constraints.push(eq(remainder, konst(0)?)?);
                }
            }
        }
        self.write_summary_result(index, summary, 0, Some((e_expr, w, constraints)))
    }

    /// Commits a summarization: writes the exit counter (a constant, or the
    /// symbolic exit expression plus its constraints) and moves the state
    /// to the loop exit.
    fn write_summary_result(
        &mut self,
        index: usize,
        summary: &LoopSummary,
        final_counter: u64,
        symbolic: Option<(ExprId, u16, Vec<ExprId>)>,
    ) -> Option<SymbolicStepOutcome> {
        let width = summary.width.min(64);
        let bits = usize::from(width);
        let symbolic_fold = symbolic.is_some();
        let (expr, constraints) = match symbolic {
            Some((e_expr, _, constraints)) => (e_expr, constraints),
            None => {
                // Exactly `width/8` bytes of the width-masked value.
                let mask = if width >= 64 { u64::MAX } else { (1u64 << width) - 1 };
                let mut pattern = (final_counter & mask).to_le_bytes().to_vec();
                pattern.truncate(bits.div_ceil(8));
                let expr = self
                    .arena
                    .intern(angryier_expr::ExprNode {
                        sort: angryier_expr::ExprSort::BitVec(width),
                        op: ExprOp::Constant,
                        operands: Vec::new(),
                        immediate: pattern,
                    })
                    .ok()?;
                (expr, Vec::new())
            }
        };
        // The concrete shadow only takes a value when the expression folds
        // (it always does on the concrete path); a symbolic exit value
        // shadows the stale concrete register exactly like a normal
        // symbolic register write would.
        let folded = if symbolic_fold {
            angryier_execution::constant_value(self.arena, expr).ok()
        } else {
            Some(final_counter)
        };
        let state = &mut self.states[index];
        state
            .registers
            .insert(summary.counter, (expr, angryier_ir::IrType::Bits(width)));
        if let Some(value) = folded {
            state.concrete_registers.insert(summary.counter, value);
            let _ = state.process.write_register(summary.counter, value);
        }
        for constraint in constraints {
            state.constraints.push(constraint);
        }
        let _ = state.process.write_pc(summary.exit);
        Some(SymbolicStepOutcome::Stepped { next_pc: summary.exit })
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

    /// Marks `length` bytes at `address` as input symbols (one symbolic
    /// byte each) — under-constrained dispatch-entry analysis seeds
    /// IRP/IO_STACK_LOCATION blocks this way so handler branches fork on
    /// request contents instead of zeroed memory.
    pub fn mark_memory_symbolic(&mut self, index: usize, address: u64, length: usize) -> Result<(), RuntimeError> {
        let state = self
            .states
            .get_mut(index)
            .ok_or_else(|| RuntimeError::Execution("no such state".into()))?;
        let next_symbol = state
            .symbols
            .iter()
            .filter_map(|s| {
                self.arena.get(s.expression).and_then(|n| {
                    n.immediate
                        .get(..8)
                        .map(|b| u64::from_le_bytes(b.try_into().unwrap_or([0; 8])))
                })
            })
            .max()
            .map(|m| m + 1)
            .unwrap_or(0);
        let mut bytes = Vec::with_capacity(length);
        for i in 0..length as u64 {
            let expr = self
                .arena
                .intern(angryier_expr::ExprNode {
                    sort: angryier_expr::ExprSort::BitVec(8),
                    op: angryier_expr::ExprOp::Symbol,
                    operands: Vec::new(),
                    immediate: (next_symbol + i).to_le_bytes().to_vec(),
                })
                .map_err(|e| RuntimeError::Symbolic(format!("{e:?}")))?;
            state.symbols.push(angryier_execution::SymbolBinding {
                register: register_id::GPR_BASE + 2, // provenance: rdx-ish input
                expression: expr,
                width: 8,
            });
            bytes.push(ByteValue::Symbolic(expr));
        }
        state
            .memory
            .write_bytes(address, &bytes)
            .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
        if std::env::var("ANGRYIER_DBG_MEM").is_ok() {
            eprintln!(
                "DBG mark_memory_symbolic idx={index} addr={address:#x} len={length} first={:?}",
                bytes.first()
            );
        }
        Ok(())
    }

    /// Overwrites `argv[0]`'s stack string with `len` symbolic bytes (the
    /// trailing NUL stays concrete) — symbolic argv input for `main(argc,
    /// argv)` programs. `len` includes the NUL: `symbolize_argv0(0, 8)`
    /// gives 7 symbolic bytes.
    pub fn symbolize_argv0(&mut self, index: usize, len: u64) -> Result<(), RuntimeError> {
        let state = self
            .states
            .get_mut(index)
            .ok_or_else(|| RuntimeError::Execution("no such state".into()))?;
        let argv0 = state
            .process
            .argv0_addr
            .ok_or_else(|| RuntimeError::Execution("no argv0 address".into()))?;
        let next_symbol = state
            .symbols
            .iter()
            .filter_map(|s| {
                self.arena.get(s.expression).and_then(|n| {
                    n.immediate
                        .get(..8)
                        .map(|b| u64::from_le_bytes(b.try_into().unwrap_or([0; 8])))
                })
            })
            .max()
            .map(|m| m + 1)
            .unwrap_or(0);
        let mut bytes = Vec::with_capacity(len as usize);
        for i in 0..len {
            let byte = if i + 1 == len {
                ByteValue::Concrete(0) // trailing NUL
            } else {
                let expr = self
                    .arena
                    .intern(angryier_expr::ExprNode {
                        sort: angryier_expr::ExprSort::BitVec(8),
                        op: angryier_expr::ExprOp::Symbol,
                        operands: Vec::new(),
                        immediate: (next_symbol + i).to_le_bytes().to_vec(),
                    })
                    .map_err(|e| RuntimeError::Symbolic(format!("{e:?}")))?;
                state.symbols.push(angryier_execution::SymbolBinding {
                    register: register_id::GPR_BASE + 7, // provenance: argv bytes (rdi-ish)
                    expression: expr,
                    width: 8,
                });
                ByteValue::Symbolic(expr)
            };
            bytes.push(byte);
        }
        state
            .memory
            .write_bytes(argv0, &bytes)
            .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
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
        let (terminated, pc) = {
            let state = self
                .states
                .get(index)
                .ok_or_else(|| RuntimeError::Execution("no such state".into()))?;
            (
                state.process.terminated,
                state
                    .process
                    .pc()
                    .map_err(|e| RuntimeError::Execution(format!("{e:?}")))?,
            )
        };
        if terminated {
            return Ok(SymbolicStepOutcome::Terminated);
        }
        // Executed-block trace (bounded ring on the state's process): the
        // symbolic path exits this function from many sites, so the record
        // happens at the top — every stepped block lands in the state's
        // history for diagnosis and replay.
        {
            if let Some(state) = self.states.get_mut(index) {
                if state.process.trace.len() >= MAX_TRACE {
                    state.process.trace.remove(0);
                }
                state.process.trace.push(pc);
            }
        }

        // Loop summarization: a summarized header with concrete inputs
        // collapses its remaining iterations into one step.
        if let Some(&summary) = self.loop_summaries.get(&pc)
            && let Some(outcome) = self.try_loop_summary(index, summary)
        {
            return Ok(outcome);
        }
        let state = &mut self.states[index];

        // SimProcedure hooks dispatch like they do in concrete mode —
        // BOTH the name-keyed hooks and the instance map (bound by
        // attach_kernel_pool_model / hook_export_return). Without the
        // instance check the symbolic stepper decoded the import stub's
        // bare `ret` and kernel models never fired.
        if state.process.simproc_hooks.contains_key(&pc) || state.process.simproc_instances.contains_key(&pc) {
            let state = &mut self.states[index];
            let outcome = if let Some(model) = state.process.simproc_instances.get(&pc).cloned() {
                self.runtime.dispatch_simproc_instance(&mut state.process, pc, &model)?
            } else {
                self.runtime.step(&mut state.process)?
            };
            return Ok(match outcome {
                StepOutcome::Terminated { .. } => SymbolicStepOutcome::Terminated,
                _ => SymbolicStepOutcome::Stepped {
                    next_pc: state.process.pc().unwrap_or(0),
                },
            });
        }

        // Decode at pc from the state's concrete memory, bounded to the
        // containing region so tail instructions don't overrun. Both the
        // `ByteValue` read and the concrete-byte view live in stack buffers.
        let mut raw = [0u8; MAX_INSN_LEN];
        let raw_len = {
            let available = state
                .process
                .state
                .memory
                .regions()
                .iter()
                .find(|region| pc >= region.base && pc < region.base.saturating_add(region.size))
                .map_or(MAX_INSN_LEN, |region| {
                    usize::try_from(region.base.saturating_add(region.size).saturating_sub(pc)).unwrap_or(MAX_INSN_LEN)
                })
                .min(MAX_INSN_LEN);
            let mut buffer = [ByteValue::Concrete(0); MAX_INSN_LEN];
            state
                .process
                .state
                .memory
                .read_into(pc, &mut buffer[..available])
                .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
            for (slot, byte) in raw.iter_mut().zip(buffer[..available].iter()) {
                *slot = match byte {
                    ByteValue::Concrete(value) => *value,
                    ByteValue::Symbolic(_) => 0,
                };
            }
            available
        };
        if raw_len == 0 {
            return Err(RuntimeError::Decode("no bytes at PC".into()));
        }
        let raw = &raw[..raw_len];
        let decoded = self
            .runtime
            .decoder
            .decode(pc, raw)
            .map_err(|e| RuntimeError::Decode(format!("{e:?}")))?;

        // Function summarization: a direct call whose callee qualifies as a
        // pure function of its arguments collapses the whole callee into one
        // symbolic step (cached template keyed by entry + argument shape).
        // `None` keeps stepping — a rejected shape is never approximated.
        // (The map may be empty: unseen indirect targets earn a lazy
        // per-target extraction inside `try_function_summary`.)
        if decoded.form_id == angryier_semantics_intel64::forms::CALL_REL32
            && let Some(target) = decoded.operands.iter().find_map(|o| {
                if let angryier_arch::OperandKind::RelativeBranch(rb) = &o.kind {
                    Some(decoded.relative_target(*rb))
                } else {
                    None
                }
            })
            && let Some(outcome) = self.try_function_summary(index, target, pc.wrapping_add(u64::from(decoded.length)))
        {
            return Ok(outcome);
        }

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
            // Symbolic stdin: `read(0, buf, n)` materializes `n` fresh
            // symbolic bytes into the state's memory — the bytes are the
            // input the solver can shape.
            let number = state.process.read_register(register_id::GPR_BASE).unwrap_or(0);
            if number == angryier_models::syscall::READ {
                // Resolve args through the symbolic register file first —
                // `mov %rsp,%rsi` updates the symbolic slot, not the
                // concrete register.
                // Fully foldable exprs (Sub(rsp,16) etc.) resolve; a
                // truly symbolic arg falls back to the concrete register.
                let arg = |state: &SymbolicState, reg: u32| -> u64 {
                    state
                        .registers
                        .get(&reg)
                        .and_then(|(e, _)| angryier_execution::constant_value(self.arena, *e).ok())
                        .unwrap_or_else(|| state.process.read_register(reg).unwrap_or(0))
                };
                let fd = arg(state, register_id::GPR_BASE + 7);
                let buf = arg(state, register_id::GPR_BASE + 6);
                let count = arg(state, register_id::GPR_BASE + 2);
                if (fd == 0 || state.process.symbolic_fds.contains(&fd)) && count > 0 && count <= 4096 {
                    let next_symbol = state
                        .symbols
                        .iter()
                        .filter_map(|s| {
                            self.arena.get(s.expression).and_then(|n| {
                                n.immediate
                                    .get(..8)
                                    .map(|b| u64::from_le_bytes(b.try_into().unwrap_or([0; 8])))
                            })
                        })
                        .max()
                        .map(|m| m + 1)
                        .unwrap_or(0);
                    let mut bytes = Vec::with_capacity(count as usize);
                    for i in 0..count {
                        let expr = self
                            .arena
                            .intern(angryier_expr::ExprNode {
                                sort: angryier_expr::ExprSort::BitVec(8),
                                op: angryier_expr::ExprOp::Symbol,
                                operands: Vec::new(),
                                immediate: (next_symbol + i).to_le_bytes().to_vec(),
                            })
                            .map_err(|e| RuntimeError::Symbolic(format!("{e:?}")))?;
                        bytes.push(ByteValue::Symbolic(expr));
                        state.symbols.push(angryier_execution::SymbolBinding {
                            register: register_id::GPR_BASE + 6, // provenance: buffer bytes
                            expression: expr,
                            width: 8,
                        });
                    }
                    state
                        .memory
                        .write_bytes(buf, &bytes)
                        .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
                    state.process.write_register(register_id::GPR_BASE, count)?;
                    let next_pc = pc.wrapping_add(u64::from(decoded.length));
                    state.process.write_pc(next_pc)?;
                    state.process.step_count += 1;
                    return Ok(SymbolicStepOutcome::Stepped { next_pc });
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
                let value = result
                    .model
                    .iter()
                    .find(|(k, _)| *k == u64::from(free.0))
                    .map(|(_, b)| {
                        let mut buf = [0u8; 8];
                        let n = b.len().min(8);
                        buf[..n].copy_from_slice(&b[..n]);
                        u64::from_le_bytes(buf)
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
        {
            let state = &mut self.states[index];
            state.registers = post.registers;
            state.expr_concrete = post.expr_concrete;
            state.symbols = evaluator.symbols().to_vec();
        }

        // Function summarization for resolved indirect calls — the
        // DriverObject-style dispatch shape. Gated on the decoded form being
        // a call (the IR op conflates `call reg`/`jmp reg`; a jump must not
        // consume a summary). Sits before the long-lived `state` borrow below
        // so the &mut session borrow is exclusive; `jump_target` is only set
        // for JumpIndirect terminators, so this cannot fire on branch blocks.
        if matches!(
            decoded.form_id,
            angryier_semantics_intel64::forms::CALL_INDIRECT_R64
                | angryier_semantics_intel64::forms::CALL_INDIRECT_MEM64
        ) && let Some(target_expr) = summary.jump_target
            && let Some(node) = self.arena.get(target_expr)
            && node.op == angryier_expr::ExprOp::Constant
            && let Some(b) = node.immediate.get(..8)
        {
            let target = u64::from_le_bytes(b.try_into().unwrap_or([0; 8]));
            if let Some(outcome) = self.try_function_summary(index, target, pc.wrapping_add(u64::from(decoded.length)))
            {
                return Ok(outcome);
            }
        }

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
                let (parent_id, child_id) = (self.states[index].id, self.states[child_index].id);
                self.record_event(
                    parent_id,
                    angryier_provenance::ProvenanceEventKind::StateFork,
                    angryier_types::ProvenanceTier::Tier1,
                    Vec::new(),
                );
                self.record_event(
                    child_id,
                    angryier_provenance::ProvenanceEventKind::StateFork,
                    angryier_types::ProvenanceTier::Tier1,
                    Vec::new(),
                );
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
            Some(angryier_ir::IrOp::Jump { target }) => {
                let _ = state.process.write_pc(*target);
                Ok(SymbolicStepOutcome::Stepped { next_pc: *target })
            }
            Some(angryier_ir::IrOp::Call { target }) => {
                // Push the return frame: a symbolic-mode call must behave
                // like a call — the callee's `ret` (and a SimProcedure's
                // pop) reads the pushed address. Without this, every
                // symbolic call leaked the loader's exit sentinel and the
                // callee "returned" into termination.
                let ret_addr = pc.wrapping_add(u64::from(decoded.length));
                if let Some(rsp) = state.process.read_register(register_id::GPR_BASE + 4).ok() {
                    let frame: Vec<ByteValue> =
                        ret_addr.to_le_bytes().iter().map(|b| ByteValue::Concrete(*b)).collect();
                    state.process.state.memory = state
                        .process
                        .state
                        .memory
                        .write(rsp.wrapping_sub(8), &frame)
                        .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
                    let _ = state
                        .process
                        .write_register(register_id::GPR_BASE + 4, rsp.wrapping_sub(8));
                }
                let _ = state.process.write_pc(*target);
                Ok(SymbolicStepOutcome::Stepped { next_pc: *target })
            }
            Some(angryier_ir::IrOp::JumpIndirect { .. }) => {
                // Indirect jump/call: the evaluator resolved the target
                // expression (e.g. `call rax` — rax, not [rsp]; `ret` — the
                // popped [rsp]). Jump when it folds to a constant; a
                // symbolic target is an under-constrained exit (honest
                // termination), never the return-address misread this arm
                // used to do. The fold accepts both a bare Constant and a
                // composed-but-concrete expression — the `ret` path's target
                // is a Concat of per-byte frame reads, which the session
                // byte store materializes as constant extracts, so folding
                // (not just the Constant shape test) is what makes an
                // internal call return.
                if let Some(target_expr) = summary.jump_target {
                    let direct = self
                        .arena
                        .get(target_expr)
                        .filter(|n| n.op == angryier_expr::ExprOp::Constant)
                        .map(|n| {
                            let mut buffer = [0u8; 8];
                            let len = n.immediate.len().min(8);
                            buffer[..len].copy_from_slice(&n.immediate[..len]);
                            u64::from_le_bytes(buffer)
                        });
                    let target = direct.or_else(|| angryier_execution::constant_value(self.arena, target_expr).ok());
                    if let Some(target) = target {
                        // CALL-biased stack semantics: the IR conflates
                        // `call reg` and `jmp reg` into one op, and the
                        // driver campaign's indirect calls (IAT thunks) need
                        // the return frame pushed so the callee's ret (and a
                        // SimProcedure's pop) lands back here. Debt-recorded:
                        // a true `jmp reg` (jump table) pushes a spurious
                        // frame — rare on these paths, revisit with a
                        // distinct CallIndirect op.
                        let ret_addr = pc.wrapping_add(u64::from(decoded.length));
                        if let Ok(rsp) = state.process.read_register(register_id::GPR_BASE + 4) {
                            let frame: Vec<ByteValue> =
                                ret_addr.to_le_bytes().iter().map(|b| ByteValue::Concrete(*b)).collect();
                            state.process.state.memory = state
                                .process
                                .state
                                .memory
                                .write(rsp.wrapping_sub(8), &frame)
                                .map_err(|e| RuntimeError::Memory(format!("{e:?}")))?;
                            let _ = state
                                .process
                                .write_register(register_id::GPR_BASE + 4, rsp.wrapping_sub(8));
                        }
                        let _ = state.process.write_pc(target);
                        return Ok(SymbolicStepOutcome::Stepped { next_pc: target });
                    }
                }
                Ok(SymbolicStepOutcome::Terminated)
            }
            Some(angryier_ir::IrOp::Return) => {
                // ret — read the return address off the state's
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
                    self.record_event(
                        left.id,
                        angryier_provenance::ProvenanceEventKind::StateMerge,
                        angryier_types::ProvenanceTier::Tier1,
                        Vec::new(),
                    );
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
                    let dead_id = self.states.get(index).map(|s| s.id).unwrap_or(0);
                    self.record_event(
                        dead_id,
                        angryier_provenance::ProvenanceEventKind::StateTerminate,
                        angryier_types::ProvenanceTier::Tier2,
                        Vec::new(),
                    );
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
                    report.last_error = Some(match self.states.get(index) {
                        Some(state) => match state.process.pc() {
                            Ok(pc) => format!("{error} at pc={pc:#x}"),
                            Err(_) => error.to_string(),
                        },
                        None => error.to_string(),
                    });
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
    /// Description of the most recent step error, if any (errors are
    /// otherwise counted into `failed` and discarded).
    pub last_error: Option<String>,
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

    /// Like [`SymbolicSession::solve_state`], but returns the raw model:
    /// every symbol's `(ExprId, bytes)` — memory-materialized symbols
    /// (stdin bytes) appear here while `solve_state` only reports
    /// register bindings.
    pub fn solve_state_symbols(
        &self,
        index: usize,
        backend: &mut dyn SolverBackend,
        timeout: Duration,
    ) -> Result<Vec<(u64, Vec<u8>)>, RuntimeError> {
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
        match result.outcome {
            SolverOutcomeKind::Sat => Ok(result.model),
            other => Err(RuntimeError::Symbolic(format!("state unsatisfiable: {other:?}"))),
        }
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
        // Summaries and the cost model are Arc-shared with every shard —
        // workers reuse the parent's pure-function summaries, and each shard
        // grows its own template cache (shard hit counters are per-shard and
        // dropped with the worker; the parent's counters cover the
        // single-threaded exploration path).
        let function_summaries = self.function_summaries.clone();
        let summary_cost_model = std::sync::Arc::clone(&self.summary_cost_model);
        type ShardResult = Result<(SymbolicRunReport, Vec<SymbolicState>, Vec<SymbolicState>), RuntimeError>;
        let results: Vec<ShardResult> = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(workers);
            for shard in shards {
                if shard.is_empty() {
                    continue;
                }
                let function_summaries = function_summaries.clone();
                let summary_cost_model = std::sync::Arc::clone(&summary_cost_model);
                handles.push(scope.spawn(move || {
                    let mut sub = SymbolicSession {
                        runtime,
                        arena,
                        states: shard,
                        dead: Vec::new(),
                        cfg,
                        next_state_id: 1,
                        pending_merges: Vec::new(),
                        recorder: angryier_provenance::FlightRecorder::new(4096),
                        next_prov_node: 0,
                        loop_summaries: BTreeMap::new(),
                        function_summaries,
                        function_templates: BTreeMap::new(),
                        failed_templates: BTreeSet::new(),
                        lazy_summary_targets: BTreeSet::new(),
                        summary_cost_model,
                        function_summary_hits: 0,
                        function_summary_builds: 0,
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

// ---------------------------------------------------------------------------
// Replay capsules (roadmap item 9, Gate 0 remainder): record a concrete
// native run into a fail-closed replay capsule, and re-execute it later from
// the capsule's recorded inputs.
// ---------------------------------------------------------------------------

/// Opt-in replay-capsule recording and fail-closed replay for recorded
/// native runs.
///
/// Recording is an explicit, caller-owned [`ReplayRecorder`] — the runtime's
/// hot path carries no always-on instrumentation. A recorded capsule carries
/// the identity frame (image hash, semantic version, target profile,
/// environment-model key, code-page guards) plus the run payload (input
/// registers/stdin and the expected exit-code/`write`-output checkpoints).
/// Replaying validates the capsule against the host BEFORE any re-execution
/// — a mismatched image hash or version rejects fail-closed — then
/// re-executes deterministically through the normal `Runtime` path from the
/// capsule's recorded inputs (the `angryier_replay` engine validates and
/// logs capsules but does not drive concrete execution; this module IS the
/// deterministic replay) and asserts the outcome checkpoints.
pub mod replay {
    use super::{Runtime, RuntimeError};
    use angryier_arch::Decoder;
    use angryier_loader::{Elf64Loader, ImageLoader, LoadedImage};
    use angryier_replay::{
        BasicReplayValidator, ExpectedCheckpoints, FileReplayStore, RecordedInputs, ReplayCapsule, ReplayError,
        ReplayValidator, capsule_domain_id, image_hash,
    };
    use angryier_types::{
        AnalysisContext, CodePageId, CodePageVersion, CodeVersionGuard, ContentId, DependencyKey, FidelityProfile,
        ReplayCapsuleId, ReplaySchemaVersion, RetentionProfile, RunId, SecurityContext,
    };
    use std::collections::BTreeMap;

    /// Capsule schema produced by this runtime's recorder.
    pub const CAPSULE_SCHEMA: ReplaySchemaVersion = ReplaySchemaVersion(2);
    /// Identity of the environment model whose observable effects the
    /// checkpoints capture (the modeled Linux x86-64 syscall layer).
    const ENVIRONMENT_DESCRIPTOR: &[u8] = b"angryier:environment:linux-x86_64-syscall-model:1";
    /// Deterministic-mode scheduler seed used unless overridden.
    const DEFAULT_SCHEDULER_SEED: u64 = 0x5EED_0000_0000_0001;
    const PAGE_SIZE: u64 = 4096;

    /// Failures of capsule recording, validation, or replay.
    #[derive(Debug)]
    pub enum ReplayRuntimeError {
        /// Capsule validation or checkpoint comparison failed.
        Replay(ReplayError),
        /// Loading or re-execution through the runtime failed.
        Runtime(RuntimeError),
    }

    impl std::fmt::Display for ReplayRuntimeError {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::Replay(e) => write!(formatter, "replay capsule rejected: {e}"),
                Self::Runtime(e) => write!(formatter, "replay execution failed: {e}"),
            }
        }
    }

    impl std::error::Error for ReplayRuntimeError {}

    impl From<ReplayError> for ReplayRuntimeError {
        fn from(error: ReplayError) -> Self {
            Self::Replay(error)
        }
    }

    impl From<RuntimeError> for ReplayRuntimeError {
        fn from(error: RuntimeError) -> Self {
            Self::Runtime(error)
        }
    }

    /// A recorded concrete run: the published capsule plus the observed
    /// outcome it captured.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct RecordedRun {
        pub capsule: ReplayCapsule,
        pub exit_code: u64,
        pub write_output: Vec<u8>,
        pub steps: u64,
    }

    /// The outcome of a validated, checkpoint-matched replay.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct ReplayOutcome {
        pub capsule_id: ReplayCapsuleId,
        pub exit_code: u64,
        pub write_output: Vec<u8>,
        pub steps: u64,
    }

    /// Environment-model identity recorded in capsules: a domain-separated
    /// content id of the environment descriptor, so record and replay hosts
    /// agree byte-for-byte.
    fn environment_key() -> DependencyKey {
        DependencyKey(capsule_domain_id(ENVIRONMENT_DESCRIPTOR).0)
    }

    /// Deterministic capsule id derived from the image identity, the
    /// recorded inputs, and the scheduler seed: the same recorded session
    /// always yields the same id.
    fn derive_capsule_id(image: ContentId, inputs: &RecordedInputs, scheduler_seed: u64) -> ReplayCapsuleId {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(&image.0);
        canonical.extend_from_slice(&(inputs.registers.len() as u64).to_le_bytes());
        for (register, value) in &inputs.registers {
            canonical.extend_from_slice(&register.to_le_bytes());
            canonical.extend_from_slice(&value.to_le_bytes());
        }
        canonical.extend_from_slice(&(inputs.stdin.len() as u64).to_le_bytes());
        canonical.extend_from_slice(&inputs.stdin);
        canonical.extend_from_slice(&scheduler_seed.to_le_bytes());
        let derived = u64::from_le_bytes(capsule_domain_id(&canonical).0[..8].try_into().unwrap_or([0; 8]));
        ReplayCapsuleId(if derived == 0 { 1 } else { derived })
    }

    /// Code-version guards covering the image's executable pages at load
    /// time (pages start at version 0: the runtime's page-version machinery
    /// has not mutated them).
    fn code_version_guards(image: &LoadedImage) -> Vec<CodeVersionGuard> {
        let mut pages: BTreeMap<u64, CodePageVersion> = BTreeMap::new();
        for segment in &image.segments {
            if !segment.executable {
                continue;
            }
            let start = segment.address / PAGE_SIZE;
            let end = segment.address.saturating_add(segment.bytes.len() as u64) / PAGE_SIZE;
            for page in start..=end {
                pages.entry(page).or_insert(CodePageVersion(0));
            }
        }
        pages
            .into_iter()
            .map(|(page, version)| CodeVersionGuard {
                page: CodePageId(page),
                version,
            })
            .collect()
    }

    fn host_validator<D: Decoder>(runtime: &Runtime<D>, host_image_hash: ContentId) -> BasicReplayValidator {
        let mut validator =
            BasicReplayValidator::for_replay_host(CAPSULE_SCHEMA, runtime.target_profile, host_image_hash);
        validator.admit(runtime.semantic_version);
        validator
    }

    /// Opt-in recorder for replay capsules. Carries only the deterministic
    /// scheduler seed; identity fields are captured from the runtime and
    /// image at record time. Costs nothing unless explicitly constructed.
    #[derive(Clone, Debug)]
    pub struct ReplayRecorder {
        scheduler_seed: u64,
    }

    impl ReplayRecorder {
        pub fn new() -> Self {
            Self {
                scheduler_seed: DEFAULT_SCHEDULER_SEED,
            }
        }

        /// A recorder with an explicit deterministic scheduler seed.
        pub fn with_scheduler_seed(scheduler_seed: u64) -> Self {
            Self { scheduler_seed }
        }

        pub fn scheduler_seed(&self) -> u64 {
            self.scheduler_seed
        }

        /// Runs `image_bytes` concretely through the runtime with the given
        /// input registers (applied after load, last write wins) and stdin,
        /// capturing a self-validated replay capsule plus the observed
        /// outcome. Fails when the run does not terminate via the modeled
        /// `exit` syscall: a capsule without an exit-code checkpoint is
        /// never emitted.
        pub fn record<D: Decoder>(
            &self,
            runtime: &Runtime<D>,
            image_bytes: &[u8],
            registers: &[(u32, u64)],
            stdin: &[u8],
            max_steps: u64,
        ) -> Result<RecordedRun, ReplayRuntimeError> {
            let loader = Elf64Loader::new();
            let image = loader
                .load(image_bytes)
                .map_err(|e| ReplayRuntimeError::Runtime(RuntimeError::Loader(e)))?;
            let image_hash = image_hash(image_bytes);
            let mut process = runtime.load_image(image.clone())?;

            let inputs = RecordedInputs {
                registers: BTreeMap::from_iter(registers.iter().copied()).into_iter().collect(),
                stdin: stdin.to_vec(),
            };
            for (register, value) in &inputs.registers {
                process.write_register(*register, *value)?;
            }
            process.stdin = inputs.stdin.clone();
            runtime.run(&mut process, max_steps)?;

            let Some(exit_code) = process.syscalls.exit_code() else {
                return Err(ReplayRuntimeError::Replay(ReplayError::CapsuleIncomplete));
            };
            let write_output = process.syscalls.output();
            let capsule = ReplayCapsule {
                id: derive_capsule_id(image_hash, &inputs, self.scheduler_seed),
                schema: CAPSULE_SCHEMA,
                context: AnalysisContext {
                    run_id: RunId(0),
                    target_profile: runtime.target_profile,
                    fidelity: FidelityProfile::Prove,
                    retention: RetentionProfile::Forensic,
                    security: SecurityContext {
                        classification: 0,
                        compartment: 0,
                    },
                },
                initial_state: process.state.id,
                semantic_version: runtime.semantic_version,
                semantic_content: ContentId::default(),
                code_versions: code_version_guards(&image),
                environment_key: environment_key(),
                scheduler_seed: self.scheduler_seed,
                image_hash,
                inputs,
                expected: ExpectedCheckpoints {
                    exit_code: Some(exit_code),
                    write_output: write_output.clone(),
                },
            };
            // A recorder must never emit an invalid capsule.
            host_validator(runtime, image_hash)
                .validate(&capsule)
                .map_err(ReplayRuntimeError::Replay)?;
            Ok(RecordedRun {
                capsule,
                exit_code,
                write_output,
                steps: process.step_count,
            })
        }

        /// Loads a capsule from a durable [`FileReplayStore`], validates it
        /// against `runtime` and `image_bytes`, re-executes it
        /// deterministically, and asserts the outcome checkpoints.
        pub fn replay<D: Decoder>(
            &self,
            runtime: &Runtime<D>,
            store: &FileReplayStore,
            capsule_id: ReplayCapsuleId,
            image_bytes: &[u8],
            max_steps: u64,
        ) -> Result<ReplayOutcome, ReplayRuntimeError> {
            let capsule = store.retrieve(capsule_id).map_err(ReplayRuntimeError::Replay)?;
            runtime.replay_capsule(image_bytes, &capsule, max_steps)
        }
    }

    impl Default for ReplayRecorder {
        fn default() -> Self {
            Self::new()
        }
    }

    impl<D: Decoder> Runtime<D> {
        /// Fail-closed capsule replay.
        ///
        /// Identity and version checks (schema, image hash vs `image_bytes`,
        /// semantic version, target profile, environment key, guards) run
        /// BEFORE any re-execution: a mismatch rejects with an explicit
        /// [`ReplayError`] and the engine never starts. Validated capsules
        /// are re-executed deterministically through the normal `Runtime`
        /// path from the capsule's recorded inputs; the exit code and
        /// captured `write` output must match the capsule's checkpoints or
        /// the replay fails with [`ReplayError::CheckpointMismatch`].
        pub fn replay_capsule(
            &self,
            image_bytes: &[u8],
            capsule: &ReplayCapsule,
            max_steps: u64,
        ) -> Result<ReplayOutcome, ReplayRuntimeError> {
            host_validator(self, image_hash(image_bytes))
                .validate(capsule)
                .map_err(ReplayRuntimeError::Replay)?;

            let mut process = self.load_elf(image_bytes)?;
            for (register, value) in &capsule.inputs.registers {
                process.write_register(*register, *value)?;
            }
            process.stdin = capsule.inputs.stdin.clone();
            self.run(&mut process, max_steps)?;

            let Some(exit_code) = process.syscalls.exit_code() else {
                return Err(ReplayRuntimeError::Replay(ReplayError::CapsuleIncomplete));
            };
            let write_output = process.syscalls.output();
            let expected_exit = capsule
                .expected
                .exit_code
                .ok_or(ReplayRuntimeError::Replay(ReplayError::CapsuleIncomplete))?;
            if exit_code != expected_exit || write_output != capsule.expected.write_output {
                return Err(ReplayRuntimeError::Replay(ReplayError::CheckpointMismatch));
            }
            Ok(ReplayOutcome {
                capsule_id: capsule.id,
                exit_code,
                write_output,
                steps: process.step_count,
            })
        }
    }
}
