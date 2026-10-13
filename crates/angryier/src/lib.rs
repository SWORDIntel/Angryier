#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Stable public library API for the Angryier dual-mode analysis engine
//! (Phase 15 — the no-recompile surface beside the Lua scripting layer).
//!
//! One entry point: [`Engine`]. Load an image (ELF64 or PE32+ driver) with
//! magic-byte dispatch, run it symbolically with find/avoid policies and
//! optional input solving, and inspect kernel-pool verdict evidence
//! (double-free / use-after-free witnesses) for driver-mode PE loads.
//!
//! ```no_run
//! # use angryier::{Engine, RunOptions};
//! # fn demo() -> Result<(), angryier::ApiError> {
//! let engine = Engine::new()?;
//! let image = engine.load("target/debug/hello")?;
//! let report = engine.run(&image, &RunOptions { steps: 512, ..RunOptions::default() })?;
//! println!("steps={} found={}", report.steps, report.found_pcs.len());
//! # Ok(())
//! # }
//! ```
//!
//! The surface mirrors `angry.run` / `angry.open` from the embedded Lua
//! layer: `RunOptions` maps to the `opts` table, [`RunReport`] maps to the
//! report table, and [`Session`] maps to a live `angry.open` handle.
//! Symbolic GPR marks are 64-bit only, exactly like the Lua surface.

use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use angryier_arch_xed_ffi::XedDecoder;
use angryier_expr::{ExprReader, ShardedExprArena};
use angryier_runtime::{
    EXIT_HOOK, ExplorationPolicy, Process, Runtime, SymbolicSession, SymbolicStepOutcome, XedFormTranslator,
};
use angryier_types::{ExpressionNormalizationVersion, SemanticVersion, TargetProfileId};

/// Targeted Windows driver state seeding for IOCTL handler exploration.
pub mod driver_ioctl;

/// Default instruction-step budget for one-shot runs. Must stay equal to
/// the Lua surface's `angry.run` default (`DEFAULT_STEPS` in
/// `angryier-runtime::script`).
pub const DEFAULT_STEPS: u64 = 256;

/// Default maximum live states for one-shot runs. Must stay equal to the
/// Lua surface's `angry.run` default (`DEFAULT_MAX_STATES`).
pub const DEFAULT_MAX_STATES: usize = 16;

/// Default whole-run wall-clock budget. Shared with the runtime/CLI/Lua
/// surfaces without adding a field to the stable 1.0 `RunOptions` layout.
pub const DEFAULT_TIMEOUT_SECS: u64 = angryier_runtime::DEFAULT_RUN_TIMEOUT_SECS;

/// Bit width of GPR symbolic marks. Sub-64-bit GPR symbols are rejected
/// with an explicit error (the evaluator stores registers at 64 bits).
pub const SYMBOLIC_GPR_WIDTH: u16 = 64;

/// General-purpose registers accepted by [`RunOptions::symbolic`] and
/// [`Session::symbolic`] — the same set as the Lua/CLI surface.
pub const GPRS: [&str; 16] = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
];

/// Error type for the stable API.
#[derive(Debug)]
pub enum ApiError {
    /// Filesystem-level failure (read/load).
    Io(std::io::Error),
    /// Image loading failed.
    Load(String),
    /// Execution failed.
    Run(String),
    /// Solver construction or solving failed.
    Solver(String),
    /// A caller-supplied argument is invalid.
    InvalidArgument(String),
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::Io(e) => write!(f, "io: {e}"),
            ApiError::Load(m) => write!(f, "load: {m}"),
            ApiError::Run(m) => write!(f, "run: {m}"),
            ApiError::Solver(m) => write!(f, "solver: {m}"),
            ApiError::InvalidArgument(m) => write!(f, "invalid argument: {m}"),
        }
    }
}

impl std::error::Error for ApiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ApiError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ApiError {
    fn from(value: std::io::Error) -> Self {
        ApiError::Io(value)
    }
}

/// Kernel pool verdict evidence from a driver-mode run.
///
/// Populated only for PE32+ driver loads (the kernel pool model attaches
/// automatically there, exactly like `angry.run`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KernelReport {
    /// Pool allocations served.
    pub allocs: u64,
    /// Pool frees recorded.
    pub frees: u64,
    /// Frees of an already-freed pointer, chronological.
    pub double_frees: Vec<angryier_models::PoolEvent>,
    /// Writes into freed pool pages (use-after-free witnesses).
    pub uaf_writes: Vec<angryier_models::PoolEvent>,
}

impl From<angryier_models::KernelPoolReport> for KernelReport {
    fn from(value: angryier_models::KernelPoolReport) -> Self {
        KernelReport {
            allocs: value.allocs,
            frees: value.frees,
            double_frees: value.double_frees,
            uaf_writes: value.uaf_writes,
        }
    }
}

/// One-shot run report — mirrors the Lua `angry.run` report table.
#[derive(Clone, Debug, Default)]
pub struct RunReport {
    /// Total symbolic steps taken.
    pub steps: u64,
    /// Forks produced.
    pub forks: u64,
    /// States merged at reconvergence points.
    pub merges: u64,
    /// States that terminated cleanly.
    pub terminated: u64,
    /// States that failed and were moved to `dead`.
    pub failed: u64,
    /// States dropped by the `max_states` cap.
    pub pruned_states: u64,
    /// Live states at return.
    pub live_states: u64,
    /// Peak live-state count.
    pub peak_states: u64,
    /// Dead/terminated states accumulated.
    pub dead_states: u64,
    /// The wall-clock deadline elapsed before the step budget ran out.
    pub timed_out: bool,
    /// PCs of states that reached a `find` address.
    pub found_pcs: Vec<u64>,
    /// Per-found-state input models: symbol index → bytes (only when
    /// `RunOptions::solve` is set).
    pub inputs: Vec<Vec<Vec<u8>>>,
    /// Whether attacker inputs were evaluated as unconstrained (multiple satisfying assignments).
    pub unconstrained_inputs: bool,
    /// Description of the most recent step error, if any.
    pub last_error: Option<String>,
    /// Kernel pool evidence (driver-mode PE loads only).
    pub kernel: KernelReport,
}

impl fmt::Display for RunReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Angryier Symbolic Run Report:")?;
        writeln!(f, "  Steps consumed      : {}", self.steps)?;
        writeln!(f, "  Forks produced      : {}", self.forks)?;
        writeln!(f, "  States merged       : {}", self.merges)?;
        writeln!(f, "  Terminated states   : {}", self.terminated)?;
        writeln!(f, "  Failed states       : {}", self.failed)?;
        writeln!(f, "  Pruned states (cap) : {}", self.pruned_states)?;
        writeln!(f, "  Live states         : {}", self.live_states)?;
        writeln!(f, "  Peak live states    : {}", self.peak_states)?;
        writeln!(f, "  Dead states total   : {}", self.dead_states)?;
        writeln!(
            f,
            "  Timed out           : {}",
            if self.timed_out {
                "yes (wall-clock deadline)"
            } else {
                "no"
            }
        )?;
        if self.found_pcs.is_empty() {
            writeln!(f, "  Found target PCs    : none")?;
        } else {
            let pcs: Vec<String> = self.found_pcs.iter().map(|pc| format!("{pc:#x}")).collect();
            writeln!(f, "  Found target PCs    : {} ({})", self.found_pcs.len(), pcs.join(", "))?;
        }
        if !self.inputs.is_empty() {
            writeln!(f, "  Solved input models : {}", self.inputs.len())?;
            for (idx, model) in self.inputs.iter().enumerate() {
                let byte_counts: Vec<String> = model
                    .iter()
                    .enumerate()
                    .map(|(i, b)| format!("sym{i}: {}B", b.len()))
                    .collect();
                writeln!(f, "    model #{idx} : {}", byte_counts.join(", "))?;
            }
        }
        writeln!(
            f,
            "  Unconstrained inputs: {}",
            if self.unconstrained_inputs {
                "yes (multiple solutions)"
            } else {
                "no"
            }
        )?;
        if self.kernel.allocs > 0
            || self.kernel.frees > 0
            || !self.kernel.double_frees.is_empty()
            || !self.kernel.uaf_writes.is_empty()
        {
            writeln!(f, "  Kernel pool allocs  : {}", self.kernel.allocs)?;
            writeln!(f, "  Kernel pool frees   : {}", self.kernel.frees)?;
            writeln!(f, "  Double-free events  : {}", self.kernel.double_frees.len())?;
            for (i, df) in self.kernel.double_frees.iter().enumerate() {
                writeln!(f, "    double-free #{i} : ptr={:#x}, caller={:#x}", df.pointer, df.caller)?;
            }
            writeln!(f, "  UAF write witnesses : {}", self.kernel.uaf_writes.len())?;
            for (i, uaf) in self.kernel.uaf_writes.iter().enumerate() {
                writeln!(f, "    uaf-write #{i}   : ptr={:#x}, caller={:#x}", uaf.pointer, uaf.caller)?;
            }
        }
        if let Some(ref err) = self.last_error {
            writeln!(f, "  Last error          : {err}")?;
        }
        Ok(())
    }
}

/// Stable core options for one-shot runs. The Lua/CLI surfaces expose additional search-policy controls without changing this 1.0 struct layout.
#[derive(Clone, Debug)]
pub struct RunOptions {
    /// Symbolic register marks: `(register name, bit width)`. Only 64-bit
    /// GPR symbols are supported; other widths error explicitly.
    pub symbolic: Vec<(String, u16)>,
    /// Concrete register seeds: `(register name, value)`.
    pub regs: Vec<(String, u64)>,
    /// 8-byte little-endian memory pokes: `(address, value)`. Applied after
    /// symbolic memory marks, so explicit fields remain concrete.
    pub poke: Vec<(u64, u64)>,
    /// Byte-granular symbolic memory ranges: `(address, length)`. Applied
    /// before concrete memory pokes.
    pub symbolic_memory: Vec<(u64, usize)>,
    /// PCs whose states are reported as `found` and not stepped further.
    pub find: Vec<u64>,
    /// PCs whose states are moved to `dead` immediately.
    pub avoid: Vec<u64>,
    /// Instruction-step budget.
    pub steps: u64,
    /// Maximum live states.
    pub max_states: usize,
    /// Solve found states into concrete input bytes (`report.inputs`).
    pub solve: bool,
    /// ELF-only: load through the dynamic linker model
    /// (`load_elf_dynamic`) instead of the static image.
    pub dynamic: bool,
    /// Entry override: start execution at `entry` instead of the image
    /// entry (dispatch routines, IRP handlers). The return slot is seeded
    /// with the exit sentinel.
    pub entry: Option<u64>,
    /// Materialize `n` bytes (n-1 + NUL) as symbolic argv[0].
    pub argv0: Option<u64>,
    /// Paths whose `openat` returns a symbolic-content fd.
    pub files: Vec<String>,
    /// Path → concrete file contents.
    pub contents: Vec<(String, Vec<u8>)>,
    /// Map the low 64 KiB as zeroed RAM (under-constrained memory
    /// relaxation; never changes executable mappings).
    pub zero_low_pages: bool,
    /// Function stubs: `(address, return_value)`. Automatically pops RSP and returns RAX.
    pub stubs: Vec<(u64, u64)>,
    /// Control-flow redirects: `(from_pc, to_pc)`. Diverts execution without executing from_pc.
    pub redirects: Vec<(u64, u64)>,
    /// Byte patches: `(address, bytes)`. Overwrites concrete memory and clears instruction cache.
    pub patches: Vec<(u64, Vec<u8>)>,
}

impl Default for RunOptions {
    fn default() -> Self {
        RunOptions {
            symbolic: Vec::new(),
            regs: Vec::new(),
            poke: Vec::new(),
            symbolic_memory: Vec::new(),
            find: Vec::new(),
            avoid: Vec::new(),
            steps: DEFAULT_STEPS,
            max_states: DEFAULT_MAX_STATES,
            solve: false,
            dynamic: false,
            entry: None,
            argv0: None,
            files: Vec::new(),
            contents: Vec::new(),
            zero_low_pages: false,
            stubs: Vec::new(),
            redirects: Vec::new(),
            patches: Vec::new(),
        }
    }
}

/// The loaded-image kind, selected by magic bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageKind {
    /// PE32+ loaded through the driver path (kernel models attach).
    PeDriver,
    /// ELF64 statically linked image.
    Elf,
    /// ELF64 loaded through the dynamic-linker model.
    ElfDynamic,
}

/// A loaded image, ready for [`Engine::run`] or [`Engine::open`].
#[derive(Clone)]
pub struct Image {
    process: Process,
    kind: ImageKind,
}

impl fmt::Debug for Image {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Image")
            .field("kind", &self.kind)
            .field("pc", &self.process.pc().unwrap_or(0))
            .finish()
    }
}

impl Image {
    /// The kind selected at load time.
    pub fn kind(&self) -> ImageKind {
        self.kind
    }
}

/// Outcome of one [`Session::step`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StepKind {
    /// The block fell through or jumped to a single successor.
    Stepped,
    /// A conditional branch forked the state.
    Branched,
    /// The state terminated (ret with concrete return address, exit, trap).
    Terminated,
}

/// The dual-mode engine entry point.
///
/// One engine owns one native-XED runtime; images load and run against it.
/// Engines are cheap to construct and `Send`-safe to share.
pub struct Engine {
    runtime: Runtime<XedFormTranslator<XedDecoder>>,
}

impl Engine {
    /// Creates an engine backed by the native Intel XED decoder
    /// (semantic version 1, target profile 1 — the engine's defaults).
    pub fn new() -> Result<Self, ApiError> {
        Ok(Engine {
            runtime: Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1)),
        })
    }

    /// Loads an image from disk with magic-byte dispatch: `MZ` → PE32+
    /// driver (kernel pool model attaches at run time), `\x7fELF` →
    /// static ELF64. Other formats fail with an explicit error.
    pub fn load(&self, path: impl AsRef<Path>) -> Result<Image, ApiError> {
        let bytes = std::fs::read(path.as_ref())?;
        if bytes.len() > 1 && bytes[0] == b'M' && bytes[1] == b'Z' {
            let process = self
                .runtime
                .load_pe_driver(&bytes)
                .map_err(|e| ApiError::Load(format!("load_pe_driver: {e:?}")))?;
            Ok(Image {
                process,
                kind: ImageKind::PeDriver,
            })
        } else {
            let process = self
                .runtime
                .load_elf(&bytes)
                .map_err(|e| ApiError::Load(format!("load_elf: {e:?}")))?;
            Ok(Image {
                process,
                kind: ImageKind::Elf,
            })
        }
    }

    /// Loads an ELF64 image through the dynamic-linker model (`DT_NEEDED`
    /// mapping, relocations, `__libc_start_main` hook). PE inputs are
    /// rejected explicitly.
    pub fn load_dynamic(&self, path: impl AsRef<Path>) -> Result<Image, ApiError> {
        let bytes = std::fs::read(path.as_ref())?;
        if bytes.len() > 1 && bytes[0] == b'M' && bytes[1] == b'Z' {
            return Err(ApiError::InvalidArgument(
                "load_dynamic: PE images use the driver path (Engine::load)".to_string(),
            ));
        }
        let process = self
            .runtime
            .load_elf_dynamic(&bytes, &[])
            .map_err(|e| ApiError::Load(format!("load_elf_dynamic: {e:?}")))?;
        Ok(Image {
            process,
            kind: ImageKind::ElfDynamic,
        })
    }

    /// Runs the image to `options.steps` (or termination) under the full
    /// symbolic session with solver-gated forking, and returns the report.
    ///
    /// The solver ALWAYS gates forks (`step_state_checked` prunes
    /// concretely-infeasible directions as UNSAT); `options.solve` only
    /// controls model extraction of found states.
    pub fn run(&self, image: &Image, options: &RunOptions) -> Result<RunReport, ApiError> {
        let mut process = image.process.clone();
        let kernel_pool = if image.kind == ImageKind::PeDriver {
            let tracker = Arc::new(angryier_models::KernelPoolTracker::new());
            self.runtime
                .attach_kernel_pool_model(&mut process, tracker.clone())
                .map_err(|e| ApiError::Run(format!("attach_kernel_pool_model: {e:?}")))?;
            Some(tracker)
        } else {
            None
        };

        apply_entry_override(&self.runtime, &mut process, options)?;
        if options.zero_low_pages {
            let _ = process.state.memory.load_concrete(0, &vec![0u8; 0x1_0000]);
        }

        let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
        let mut session = SymbolicSession::new(&self.runtime, arena.as_ref(), process);
        apply_inputs(&mut session, options)?;

        let policy = ExplorationPolicy {
            find: options.find.clone(),
            avoid: options.avoid.clone(),
            ..ExplorationPolicy::default()
        };
        let mut backend = Some(new_backend(arena.clone())?);
        let report = session
            .run_with_policy(
                options.steps,
                options.max_states,
                backend.as_mut().map(|b| b as &mut dyn angryier_solver::SolverBackend),
                Duration::from_secs(DEFAULT_TIMEOUT_SECS),
                true,
                &policy,
            )
            .map_err(|e| ApiError::Run(format!("run: {e:?}")))?;

        let mut out = RunReport {
            steps: report.steps,
            forks: report.forks,
            merges: report.merges,
            terminated: report.terminated,
            failed: report.failed,
            pruned_states: report.pruned_states,
            live_states: report.live_states,
            peak_states: report.peak_states,
            dead_states: report.dead_states,
            timed_out: report.timed_out,
            last_error: report.last_error.clone(),
            found_pcs: Vec::new(),
            inputs: Vec::new(),
            unconstrained_inputs: false,
            kernel: KernelReport::default(),
        };
        out.found_pcs = report.found.iter().map(|s| s.process.pc().unwrap_or(0)).collect();

        if options.solve
            && let Some(backend) = backend.as_mut()
        {
            for found in report.found.iter() {
                session.states.push(found.clone());
                let idx = session.states.len() - 1;
                match session.solve_state_symbols(idx, backend, Duration::from_secs(10)) {
                    Ok(model) => {
                        out.inputs.push(model.into_iter().map(|(_i, bytes)| bytes).collect());
                    }
                    Err(e) => {
                        out.last_error = Some(format!("solve: {e:?}"));
                    }
                }
                session.states.pop();
            }
        }

        if let Some(tracker) = kernel_pool.as_ref() {
            out.kernel = KernelReport::from(tracker.snapshot());
        }
        Ok(out)
    }

    /// Opens a live session handle (`angry.open` equivalent): step, read
    /// registers, mark registers symbolic, or run to a report — without
    /// recompiling callers.
    pub fn open(&self, image: &Image) -> Result<Session, ApiError> {
        Session::open(self, image)
    }
}

/// A live analysis session over one image.
///
/// State-level data (constraints, symbolic memory, register bindings)
/// persists across [`Session::step`] calls; session-level caches (loop /
/// function summaries, flight recorder) are rebuilt per call — the v0.1
/// documented limitation of the safe, borrow-free handle.
pub struct Session {
    runtime: Box<Runtime<XedFormTranslator<XedDecoder>>>,
    arena: Arc<ShardedExprArena>,
    states: Vec<angryier_runtime::SymbolicState>,
}

impl Session {
    fn open(_engine: &Engine, image: &Image) -> Result<Self, ApiError> {
        // The runtime is not Clone, so the handle owns a fresh one; the
        // decoder is stateless beyond its profile, so the session sees the
        // same semantics.
        let runtime = Box::new(Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1)));
        let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
        let mut process = image.process.clone();
        if image.kind == ImageKind::PeDriver {
            let tracker = Arc::new(angryier_models::KernelPoolTracker::new());
            runtime
                .attach_kernel_pool_model(&mut process, tracker)
                .map_err(|e| ApiError::Run(format!("attach_kernel_pool_model: {e:?}")))?;
        }
        let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
        let states = std::mem::take(&mut session.states);
        Ok(Session { runtime, arena, states })
    }

    /// Materializes the symbolic session around the owned states.
    fn session(&mut self) -> SymbolicSession<'_, XedFormTranslator<XedDecoder>> {
        let seed = self.states[0].process.clone();
        let mut session = SymbolicSession::new(&self.runtime, self.arena.as_ref(), seed);
        session.states = std::mem::take(&mut self.states);
        session
    }

    /// Steps state 0 once and returns the outcome kind.
    pub fn step(&mut self) -> Result<StepKind, ApiError> {
        let mut session = self.session();
        let outcome = session
            .step_state(0)
            .map_err(|e| ApiError::Run(format!("step: {e:?}")))?;
        self.states = std::mem::take(&mut session.states);
        Ok(match outcome {
            SymbolicStepOutcome::Stepped { .. } => StepKind::Stepped,
            SymbolicStepOutcome::Branched { .. } => StepKind::Branched,
            SymbolicStepOutcome::Terminated => StepKind::Terminated,
        })
    }

    /// Current pc of state 0.
    pub fn pc(&self) -> Result<u64, ApiError> {
        self.states[0]
            .process
            .pc()
            .map_err(|e| ApiError::Run(format!("pc: {e:?}")))
    }

    /// Concrete value of a GPR on state 0; `None` when the register is
    /// symbolic or unknown.
    pub fn reg(&self, name: &str) -> Option<u64> {
        let reg = reg_by_name(name)?;
        self.states[0].process.read_register(reg).ok()
    }

    /// Number of live states.
    pub fn states(&self) -> usize {
        self.states.len()
    }

    /// Marks a GPR symbolic on state 0 (64-bit only; other widths error
    /// explicitly, matching the Lua surface).
    pub fn symbolic(&mut self, name: &str, width: u16) -> Result<(), ApiError> {
        let reg = reg_by_name(name).ok_or_else(|| ApiError::InvalidArgument(format!("bad register '{name}'")))?;
        if width != SYMBOLIC_GPR_WIDTH {
            return Err(ApiError::InvalidArgument(format!(
                "symbolic register '{name}' width must be {SYMBOLIC_GPR_WIDTH} bits (got {width})"
            )));
        }
        let mut session = self.session();
        let result = session.mark_symbolic(0, reg, angryier_ir::IrType::Bits(width));
        self.states = std::mem::take(&mut session.states);
        result.map_err(|e| ApiError::Run(format!("mark_symbolic: {e:?}")))
    }

    /// Stubs a function at `address` to immediately return `return_value` in RAX
    /// and pop the call return address from RSP across all active states.
    pub fn stub_function(&mut self, address: u64, return_value: u64) {
        for state in &mut self.states {
            state.process.stub_function(address, return_value);
        }
    }

    /// Redirects control flow from `from_pc` to `to_pc` across all active states.
    pub fn redirect_control_flow(&mut self, from_pc: u64, to_pc: u64) {
        for state in &mut self.states {
            state.process.redirect_control_flow(from_pc, to_pc);
        }
    }

    /// Patches memory bytes at `address` and invalidates cached instruction blocks
    /// across all active states.
    pub fn patch_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), ApiError> {
        for state in &mut self.states {
            state
                .process
                .patch_bytes(address, bytes)
                .map_err(|e| ApiError::Run(format!("patch_bytes: {e:?}")))?;
            state.memory = angryier_runtime::SymbolicSessionMemory::new(state.process.state.memory.clone());
        }
        Ok(())
    }

    /// Runs the session to `options.steps` (or termination) and returns a
    /// report; the handle keeps the final states for inspection.
    pub fn run(&mut self, options: &RunOptions) -> Result<RunReport, ApiError> {
        let arena = self.arena.clone();
        let mut session = self.session();
        if let Err(e) = apply_inputs(&mut session, options) {
            self.states = std::mem::take(&mut session.states);
            return Err(e);
        }
        let policy = ExplorationPolicy {
            find: options.find.clone(),
            avoid: options.avoid.clone(),
            ..ExplorationPolicy::default()
        };
        let mut backend = match new_backend(arena) {
            Ok(b) => Some(b),
            Err(e) => {
                self.states = std::mem::take(&mut session.states);
                return Err(e);
            }
        };
        let report = match session.run_with_policy(
            options.steps,
            options.max_states,
            backend.as_mut().map(|b| b as &mut dyn angryier_solver::SolverBackend),
            Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            true,
            &policy,
        ) {
            Ok(r) => r,
            Err(e) => {
                self.states = std::mem::take(&mut session.states);
                return Err(ApiError::Run(format!("run: {e:?}")));
            }
        };
        let mut out = RunReport {
            steps: report.steps,
            forks: report.forks,
            merges: report.merges,
            terminated: report.terminated,
            failed: report.failed,
            pruned_states: report.pruned_states,
            live_states: report.live_states,
            peak_states: report.peak_states,
            dead_states: report.dead_states,
            timed_out: report.timed_out,
            last_error: report.last_error.clone(),
            found_pcs: report.found.iter().map(|s| s.process.pc().unwrap_or(0)).collect(),
            inputs: Vec::new(),
            unconstrained_inputs: false,
            kernel: KernelReport::default(),
        };
        if options.solve
            && let Some(backend) = backend.as_mut()
        {
            for found in report.found.iter() {
                session.states.push(found.clone());
                let idx = session.states.len() - 1;
                match session.solve_state_symbols(idx, backend, Duration::from_secs(10)) {
                    Ok(model) => {
                        out.inputs.push(model.into_iter().map(|(_i, bytes)| bytes).collect());
                    }
                    Err(e) => {
                        out.last_error = Some(format!("solve: {e:?}"));
                    }
                }
                session.states.pop();
            }
        }
        self.states = std::mem::take(&mut session.states);
        Ok(out)
    }
}

/// Maps a GPR name to its engine register id (the same table as the
/// Lua/CLI surface).
fn reg_by_name(name: &str) -> Option<u32> {
    GPRS.iter()
        .position(|n| *n == name)
        .map(|i| angryier_arch_intel64::register_id::GPR_BASE + i as u32)
}

/// Constructs the Z3 backend shared by one-shot runs and sessions.
fn new_backend(
    arena: Arc<ShardedExprArena>,
) -> Result<angryier_solver_z3::Z3Backend<angryier_solver_z3::Z3FfiBridge>, ApiError> {
    angryier_solver_z3::Z3Backend::native_ffi(arena as Arc<dyn ExprReader>)
        .map_err(|e| ApiError::Solver(format!("z3: {e:?}")))
}

/// Applies the `entry` override exactly like the Lua surface: write the
/// pc, seed the return slot with the exit sentinel, hook the sentinel.
fn apply_entry_override(
    runtime: &Runtime<XedFormTranslator<XedDecoder>>,
    process: &mut Process,
    options: &RunOptions,
) -> Result<(), ApiError> {
    let Some(entry) = options.entry.filter(|&e| e != 0) else {
        return Ok(());
    };
    process
        .write_pc(entry)
        .map_err(|e| ApiError::Run(format!("entry override: {e:?}")))?;
    let rsp = process
        .read_register(angryier_arch_intel64::register_id::GPR_BASE + 4)
        .map_err(|e| ApiError::Run(format!("entry rsp: {e:?}")))?;
    process.state.memory = process
        .state
        .memory
        .load_concrete(rsp.wrapping_sub(8), &EXIT_HOOK.to_le_bytes())
        .map_err(|e| ApiError::Run(format!("entry frame: {e:?}")))?;
    process
        .write_register(angryier_arch_intel64::register_id::GPR_BASE + 4, rsp.wrapping_sub(8))
        .map_err(|e| ApiError::Run(format!("entry rsp set: {e:?}")))?;
    process.hook_simproc(EXIT_HOOK, "exit");
    let _ = runtime;
    Ok(())
}

/// Applies input options (symbolic regs, seeds, pokes, symbolic memory,
/// argv, files) to state 0 of the session.
fn apply_inputs(
    session: &mut SymbolicSession<'_, XedFormTranslator<XedDecoder>>,
    options: &RunOptions,
) -> Result<(), ApiError> {
    for (name, width) in &options.symbolic {
        let reg = reg_by_name(name).ok_or_else(|| ApiError::InvalidArgument(format!("bad register '{name}'")))?;
        if *width != SYMBOLIC_GPR_WIDTH {
            return Err(ApiError::InvalidArgument(format!(
                "symbolic register '{name}' width must be {SYMBOLIC_GPR_WIDTH} bits (got {width})"
            )));
        }
        session
            .mark_symbolic(0, reg, angryier_ir::IrType::Bits(*width))
            .map_err(|e| ApiError::Run(format!("mark_symbolic: {e:?}")))?;
    }
    for (name, value) in &options.regs {
        let reg = reg_by_name(name).ok_or_else(|| ApiError::InvalidArgument(format!("bad register '{name}'")))?;
        session.states[0]
            .process
            .write_register(reg, *value)
            .map_err(|e| ApiError::Run(format!("regs[{name}]: {e:?}")))?;
        session.states[0].concrete_registers.insert(reg, *value);
    }
    // Materialize broad symbolic regions before applying concrete structure
    // pointers and pinned fields. Otherwise the symbolic mark would erase a
    // caller's explicit poke inside an IRP or IO_STACK_LOCATION region.
    for (addr, len) in &options.symbolic_memory {
        session
            .mark_memory_symbolic(0, *addr, *len)
            .map_err(|e| ApiError::Run(format!("symbolic_memory: {e:?}")))?;
    }
    for (addr, value) in &options.poke {
        session.states[0].process.state.memory = session.states[0]
            .process
            .state
            .memory
            .load_concrete(*addr, &value.to_le_bytes())
            .map_err(|e| ApiError::Run(format!("poke: {e:?}")))?;
        let byte_vals: Vec<_> = value
            .to_le_bytes()
            .iter()
            .copied()
            .map(angryier_memory::ByteValue::Concrete)
            .collect();
        session.states[0]
            .memory
            .write_bytes(*addr, &byte_vals)
            .map_err(|e| ApiError::Run(format!("poke session: {e:?}")))?;
    }
    if let Some(len) = options.argv0 {
        session
            .symbolize_argv0(0, len)
            .map_err(|e| ApiError::Run(format!("symbolize_argv0: {e:?}")))?;
    }
    for name in &options.files {
        session.states[0].process.symbolic_files.insert(name.clone());
    }
    for (name, data) in &options.contents {
        session.states[0].process.files.insert(name.clone(), data.clone());
    }
    for (addr, ret_val) in &options.stubs {
        session.states[0].process.stub_function(*addr, *ret_val);
    }
    for (from_pc, to_pc) in &options.redirects {
        session.states[0].process.redirect_control_flow(*from_pc, *to_pc);
    }
    for (addr, bytes) in &options.patches {
        session.states[0]
            .process
            .patch_bytes(*addr, bytes)
            .map_err(|e| ApiError::Run(format!("patch_bytes: {e:?}")))?;
        session.states[0].memory =
            angryier_runtime::SymbolicSessionMemory::new(session.states[0].process.state.memory.clone());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_report_display_is_informative() {
        let report = RunReport {
            steps: 512,
            forks: 4,
            merges: 2,
            terminated: 3,
            failed: 1,
            pruned_states: 0,
            live_states: 2,
            peak_states: 6,
            dead_states: 4,
            timed_out: false,
            found_pcs: vec![0x140002000, 0x140002010],
            inputs: vec![vec![vec![0x41, 0x42, 0x43, 0x00]]],
            unconstrained_inputs: false,
            last_error: Some("test error annotation".to_string()),
            kernel: KernelReport {
                allocs: 5,
                frees: 3,
                double_frees: vec![angryier_models::PoolEvent {
                    pointer: 0xffff_8000_1000,
                    caller: 0x140001050,
                }],
                uaf_writes: Vec::new(),
            },
        };

        let s = format!("{report}");
        assert!(s.contains("Angryier Symbolic Run Report:"));
        assert!(s.contains("Steps consumed      : 512"));
        assert!(s.contains("Forks produced      : 4"));
        assert!(s.contains("0x140002000"));
        assert!(s.contains("0x140002010"));
        assert!(s.contains("sym0: 4B"));
        assert!(s.contains("Kernel pool allocs  : 5"));
        assert!(s.contains("Double-free events  : 1"));
        assert!(s.contains("0xffff80001000"));
        assert!(s.contains("test error annotation"));
    }

    #[test]
    fn run_options_defaults_and_fields() {
        let opts = RunOptions {
            stubs: vec![(0x401000, 42)],
            redirects: vec![(0x401050, 0x401080)],
            patches: vec![(0x401020, vec![0x90, 0x90])],
            ..RunOptions::default()
        };
        assert_eq!(opts.stubs, vec![(0x401000, 42)]);
        assert_eq!(opts.redirects, vec![(0x401050, 0x401080)]);
        assert_eq!(opts.patches, vec![(0x401020, vec![0x90, 0x90])]);
    }
}
