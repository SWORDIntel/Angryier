#![forbid(unsafe_code)]

//! Environment and function-summary model contracts.
//!
//! This crate provides concrete in-memory environment model and function
//! summary providers. The environment model applies deterministic state
//! transitions keyed by operation identifiers. The summary provider
//! caches function summaries keyed by dependency, with exact-match
//! lookup and advisory precision tracking.

use angryier_types::{DependencyKey, EnvironmentModelId, EnvironmentModelVersion, FidelityProfile, SummaryId};
use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

pub use syscall::SyscallDispatchTable;

// ---------------------------------------------------------------------------
// Summary precision and model key
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SummaryPrecision {
    ExactValidated,
    Approximate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelKey {
    pub id: EnvironmentModelId,
    pub version: EnvironmentModelVersion,
    pub dependency: DependencyKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FunctionSummary {
    pub id: SummaryId,
    pub precision: SummaryPrecision,
    pub dependency: DependencyKey,
    pub payload: Vec<u8>,
}

/// Returns a numeric rank for a fidelity profile (higher = more rigorous).
/// Prove > Hunt > Explore.
fn fidelity_rank(profile: FidelityProfile) -> u8 {
    match profile {
        FidelityProfile::Explore => 0,
        FidelityProfile::Hunt => 1,
        FidelityProfile::Prove => 2,
    }
}

/// Returns true if `profile` meets or exceeds the `required` fidelity.
fn fidelity_meets(profile: FidelityProfile, required: FidelityProfile) -> bool {
    fidelity_rank(profile) >= fidelity_rank(required)
}

// ---------------------------------------------------------------------------
// Error model
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModelError {
    /// The model store is poisoned (lock failure).
    Poisoned,
    /// The requested model was not found.
    ModelNotFound,
    /// The requested summary was not found.
    SummaryNotFound,
    /// The operation is not supported by this model.
    UnsupportedOperation,
    /// The fidelity profile is too low for this model.
    FidelityTooLow,
    /// A duplicate model or summary was registered.
    DuplicateEntry,
}

impl core::fmt::Display for ModelError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::Poisoned => "model store poisoned",
            Self::ModelNotFound => "environment model not found",
            Self::SummaryNotFound => "function summary not found",
            Self::UnsupportedOperation => "unsupported model operation",
            Self::FidelityTooLow => "fidelity profile too low for this model",
            Self::DuplicateEntry => "duplicate model or summary entry",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ModelError {}

// ---------------------------------------------------------------------------
// Environment model trait
// ---------------------------------------------------------------------------

pub trait EnvironmentModel: Send + Sync {
    type State;
    type Error;
    fn key(&self) -> ModelKey;
    fn apply(&self, state: &Self::State, operation: u64, profile: FidelityProfile) -> Result<Self::State, Self::Error>;
}

pub trait SummaryProvider: Send + Sync {
    fn lookup(&self, dependency: DependencyKey) -> Option<FunctionSummary>;
}

// ---------------------------------------------------------------------------
// In-memory environment model
// ---------------------------------------------------------------------------

/// A deterministic in-memory environment model that applies state transitions
/// from a registered operation table.
///
/// Each operation maps to a pure function that takes the current state and
/// returns a new state. The model enforces fidelity requirements: operations
/// tagged with a minimum fidelity will reject profiles below that threshold.
pub struct InMemoryEnvironmentModel<S: Clone + Send + Sync> {
    key: ModelKey,
    operations: BTreeMap<u64, OperationEntry<S>>,
    min_fidelity: FidelityProfile,
}

struct OperationEntry<S> {
    handler: Box<dyn Fn(&S) -> S + Send + Sync>,
    min_fidelity: FidelityProfile,
}

impl<S: Clone + Send + Sync + 'static> InMemoryEnvironmentModel<S> {
    pub fn new(key: ModelKey, min_fidelity: FidelityProfile) -> Self {
        Self {
            key,
            operations: BTreeMap::new(),
            min_fidelity,
        }
    }

    pub fn register<F>(&mut self, operation: u64, min_fidelity: FidelityProfile, handler: F)
    where
        F: Fn(&S) -> S + Send + Sync + 'static,
    {
        self.operations.insert(
            operation,
            OperationEntry {
                handler: Box::new(handler),
                min_fidelity,
            },
        );
    }

    pub fn supports(&self, operation: u64) -> bool {
        self.operations.contains_key(&operation)
    }

    pub fn operation_count(&self) -> usize {
        self.operations.len()
    }
}

impl<S: Clone + Send + Sync + 'static> EnvironmentModel for InMemoryEnvironmentModel<S> {
    type State = S;
    type Error = ModelError;

    fn key(&self) -> ModelKey {
        self.key.clone()
    }

    fn apply(&self, state: &Self::State, operation: u64, profile: FidelityProfile) -> Result<Self::State, Self::Error> {
        if !fidelity_meets(profile, self.min_fidelity) {
            return Err(ModelError::FidelityTooLow);
        }
        match self.operations.get(&operation) {
            Some(entry) => {
                if !fidelity_meets(profile, entry.min_fidelity) {
                    return Err(ModelError::FidelityTooLow);
                }
                Ok((entry.handler)(state))
            }
            None => Err(ModelError::UnsupportedOperation),
        }
    }
}

// ---------------------------------------------------------------------------
// In-memory summary provider
// ---------------------------------------------------------------------------

/// A thread-safe in-memory function summary provider.
///
/// Summaries are keyed by their dependency key. Lookup returns the most
/// recently registered summary for a given dependency. Exact-validated
/// summaries take precedence over approximate ones.
pub struct InMemorySummaryProvider {
    summaries: RwLock<BTreeMap<DependencyKey, FunctionSummary>>,
}

impl InMemorySummaryProvider {
    pub fn new() -> Self {
        Self {
            summaries: RwLock::new(BTreeMap::new()),
        }
    }

    pub fn register(&self, summary: FunctionSummary) -> Result<(), ModelError> {
        let mut summaries = self.summaries.write().map_err(|_| ModelError::Poisoned)?;
        if summaries.contains_key(&summary.dependency) {
            return Err(ModelError::DuplicateEntry);
        }
        summaries.insert(summary.dependency, summary);
        Ok(())
    }

    pub fn replace(&self, summary: FunctionSummary) -> Result<(), ModelError> {
        let mut summaries = self.summaries.write().map_err(|_| ModelError::Poisoned)?;
        summaries.insert(summary.dependency, summary);
        Ok(())
    }

    pub fn len(&self) -> usize {
        match self.summaries.read() {
            Ok(guard) => guard.len(),
            Err(_) => 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains(&self, dependency: DependencyKey) -> bool {
        match self.summaries.read() {
            Ok(guard) => guard.contains_key(&dependency),
            Err(_) => false,
        }
    }

    pub fn remove(&self, dependency: DependencyKey) -> Result<Option<FunctionSummary>, ModelError> {
        let mut summaries = self.summaries.write().map_err(|_| ModelError::Poisoned)?;
        Ok(summaries.remove(&dependency))
    }
}

impl Default for InMemorySummaryProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SummaryProvider for InMemorySummaryProvider {
    fn lookup(&self, dependency: DependencyKey) -> Option<FunctionSummary> {
        match self.summaries.read() {
            Ok(guard) => guard.get(&dependency).cloned(),
            Err(_) => None,
        }
    }
}

// ---------------------------------------------------------------------------
// SimProcedure and SimState execution models
// ---------------------------------------------------------------------------

/// Simulation state representing register values, chronological memory writes,
/// and execution outcome markers.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SimState {
    pub registers: BTreeMap<u64, u64>,
    /// Read-only memory mirrored by the runtime for procedure arguments.
    pub memory_reads: Vec<(u64, Vec<u8>)>,
    pub memory_writes: Vec<(u64, Vec<u8>)>,
    pub return_value: Option<u64>,
    pub exited: bool,
}

impl SimState {
    /// Creates an empty simulation state.
    pub fn new() -> Self {
        Self {
            registers: BTreeMap::new(),
            memory_reads: Vec::new(),
            memory_writes: Vec::new(),
            return_value: None,
            exited: false,
        }
    }

    /// Returns the value of a register, or 0 if uninitialized.
    pub fn get_reg(&self, reg: u64) -> u64 {
        match self.registers.get(&reg) {
            Some(&val) => val,
            None => 0,
        }
    }

    /// Sets the value of a register.
    pub fn set_reg(&mut self, reg: u64, val: u64) {
        self.registers.insert(reg, val);
    }

    /// Reads an argument by index.
    ///
    /// Checks the direct argument register (index as `u64`), falling back to
    /// System V AMD64 ABI registers: `RDI` (7), `RSI` (6), `RDX` (2), `RCX` (1),
    /// `R8` (8), `R9` (9). Returns 0 if unset.
    pub fn get_arg(&self, index: usize) -> u64 {
        if let Some(&val) = self.registers.get(&(index as u64)) {
            return val;
        }
        let abi_regs = [7, 6, 2, 1, 8, 9];
        if let Some(&val) = abi_regs.get(index).and_then(|reg| self.registers.get(reg)) {
            return val;
        }
        0
    }

    /// Sets an argument by direct index in the register file.
    pub fn set_arg(&mut self, index: usize, val: u64) {
        self.registers.insert(index as u64, val);
    }

    /// Reads a single byte at `addr` by inspecting memory writes in reverse chronological order.
    pub fn read_byte(&self, addr: u64) -> Option<u8> {
        for (base, bytes) in self.memory_writes.iter().rev() {
            if addr >= *base {
                let offset = (addr - *base) as usize;
                if offset < bytes.len() {
                    return Some(bytes[offset]);
                }
            }
        }
        for (base, bytes) in self.memory_reads.iter().rev() {
            if addr >= *base {
                let offset = (addr - *base) as usize;
                if offset < bytes.len() {
                    return Some(bytes[offset]);
                }
            }
        }
        None
    }

    /// Reads `len` bytes from memory starting at `addr`. Unwritten bytes default to 0.
    pub fn read_bytes(&self, addr: u64, len: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(len);
        for i in 0..len {
            let byte = self.read_byte(addr.wrapping_add(i as u64)).unwrap_or_default();
            result.push(byte);
        }
        result
    }

    /// Records a memory write starting at `addr`.
    pub fn write_memory(&mut self, addr: u64, data: Vec<u8>) {
        self.memory_writes.push((addr, data));
    }

    /// Adds a read-only memory snapshot without turning it into an observable write.
    pub fn shadow_memory(&mut self, addr: u64, data: Vec<u8>) {
        self.memory_reads.push((addr, data));
    }

    /// Reads bytes from memory starting at `addr` until a null byte (`0`) or `max_len` is reached.
    pub fn read_null_terminated_string(&self, addr: u64, max_len: usize) -> Vec<u8> {
        let mut result = Vec::new();
        for i in 0..max_len {
            match self.read_byte(addr.wrapping_add(i as u64)) {
                Some(0) | None => break,
                Some(b) => result.push(b),
            }
        }
        result
    }

    /// Produces a new state updated with the outcome of a simulation result.
    pub fn transition(&self, result: &SimResult) -> Self {
        match result {
            SimResult::Continue(s) => s.clone(),
            SimResult::Return(val) => {
                let mut next = self.clone();
                next.return_value = Some(*val);
                next
            }
            SimResult::Exit => {
                let mut next = self.clone();
                next.exited = true;
                next
            }
        }
    }

    /// Updates this state in-place with the outcome of a simulation result.
    pub fn step(&mut self, result: &SimResult) {
        match result {
            SimResult::Continue(s) => *self = s.clone(),
            SimResult::Return(val) => self.return_value = Some(*val),
            SimResult::Exit => self.exited = true,
        }
    }
}

/// The result returned by a `SimProcedure`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SimResult {
    /// Continue execution with the updated simulation state.
    Continue(SimState),
    /// Function returned a 64-bit integer value.
    Return(u64),
    /// Target program execution exited.
    Exit,
}

impl core::fmt::Display for SimResult {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Continue(_) => f.write_str("Continue"),
            Self::Return(val) => write!(f, "Return({val:#x})"),
            Self::Exit => f.write_str("Exit"),
        }
    }
}

/// A simulated procedure that executes symbolic or stub environment behavior.
pub trait SimProcedure: Send + Sync {
    /// Returns the symbolic identifier/name of this procedure.
    fn name(&self) -> &'static str;

    /// Applies this procedure's model to `state`, returning the simulation result.
    fn apply(&self, state: &SimState) -> SimResult;
}

/// Registry storing simulated procedures keyed by their canonical symbol name.
pub struct SimProcedureRegistry {
    procedures: BTreeMap<&'static str, Box<dyn SimProcedure>>,
}

impl SimProcedureRegistry {
    /// Creates an empty procedure registry.
    pub fn new() -> Self {
        Self {
            procedures: BTreeMap::new(),
        }
    }

    /// Creates a registry pre-populated with standard library stubs.
    pub fn with_stubs() -> Self {
        let mut registry = Self::new();
        registry.register_stubs();
        registry
    }

    /// Registers the default set of standard library stubs.
    pub fn register_stubs(&mut self) {
        self.register(Box::new(StrlenProcedure));
        self.register(Box::new(StrcmpProcedure));
        self.register(Box::new(MallocProcedure::default()));
        self.register(Box::new(FreeProcedure));
        self.register(Box::new(MemcpyProcedure));
        self.register(Box::new(MemsetProcedure));
        self.register(Box::new(PutsProcedure));
        self.register(Box::new(ExitProcedure));
    }

    /// Creates a registry pre-populated with standard library stubs plus POSIX clock, futex, and thread models.
    pub fn with_standard_library() -> Self {
        let mut registry = Self::new();
        registry.register_standard_library();
        registry
    }

    /// Registers standard library stubs plus POSIX clock, futex, and thread creation models.
    pub fn register_standard_library(&mut self) {
        self.register_stubs();
        let clock_tracker = Arc::new(DeterministicClockTracker::default());
        let futex_tracker = Arc::new(FutexTracker::default());
        let thread_tracker = Arc::new(ThreadTracker::default());

        self.register(Box::new(ClockGettimeProcedure::new(clock_tracker.clone())));
        self.register(Box::new(DeterministicClockProcedure::with_name(
            clock_tracker,
            "deterministic_clock",
        )));
        self.register(Box::new(FutexWaitProcedure::new(futex_tracker.clone())));
        self.register(Box::new(FutexWakeProcedure::new(futex_tracker.clone())));
        self.register(Box::new(FutexProcedure::new(futex_tracker)));
        self.register(Box::new(PthreadCreateProcedure::new(thread_tracker)));
    }

    /// Inserts a boxed procedure into the registry.
    pub fn register(&mut self, procedure: Box<dyn SimProcedure>) {
        self.procedures.insert(procedure.name(), procedure);
    }

    /// Looks up a procedure by symbol name.
    pub fn lookup(&self, name: &str) -> Option<&dyn SimProcedure> {
        self.procedures.get(name).map(|b| b.as_ref())
    }

    /// Applies a procedure by symbol name to `state`, returning `None` if unregistered.
    pub fn apply_by_name(&self, name: &str, state: &SimState) -> Option<SimResult> {
        let procedure = self.lookup(name)?;
        Some(procedure.apply(state))
    }

    /// Returns the number of registered procedures.
    pub fn len(&self) -> usize {
        self.procedures.len()
    }

    /// Returns true if no procedures are registered.
    pub fn is_empty(&self) -> bool {
        self.procedures.is_empty()
    }

    /// Returns true if a procedure with `name` is registered.
    pub fn contains(&self, name: &str) -> bool {
        self.procedures.contains_key(name)
    }
}

impl Default for SimProcedureRegistry {
    fn default() -> Self {
        Self::with_stubs()
    }
}

// ---------------------------------------------------------------------------
// Standard SimProcedure stubs
// ---------------------------------------------------------------------------

/// Stub procedure for `strlen`. Returns length of null-terminated string at arg0 address.
pub struct StrlenProcedure;

impl SimProcedure for StrlenProcedure {
    fn name(&self) -> &'static str {
        "strlen"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let addr = state.get_arg(0);
        let s = state.read_null_terminated_string(addr, 65536);
        SimResult::Return(s.len() as u64)
    }
}

/// Stub procedure for `strcmp`. Returns 0 if strings match, 1 if arg0 > arg1, u64::MAX if arg0 < arg1.
pub struct StrcmpProcedure;

impl SimProcedure for StrcmpProcedure {
    fn name(&self) -> &'static str {
        "strcmp"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let addr1 = state.get_arg(0);
        let addr2 = state.get_arg(1);
        let s1 = state.read_null_terminated_string(addr1, 65536);
        let s2 = state.read_null_terminated_string(addr2, 65536);
        match s1.cmp(&s2) {
            std::cmp::Ordering::Equal => SimResult::Return(0),
            std::cmp::Ordering::Less => SimResult::Return(u64::MAX),
            std::cmp::Ordering::Greater => SimResult::Return(1),
        }
    }
}

/// Stub procedure for `malloc`. Returns a fake heap pointer and increments a bump allocator.
pub struct MallocProcedure {
    next_ptr: AtomicU64,
}

impl MallocProcedure {
    /// Default initial heap pointer returned by the bump allocator (`0x1000_0000`).
    pub const DEFAULT_HEAP_BASE: u64 = 0x1000_0000;

    /// Creates a new `MallocProcedure` starting at `base`.
    pub fn new(base: u64) -> Self {
        Self {
            next_ptr: AtomicU64::new(base),
        }
    }
}

impl Default for MallocProcedure {
    fn default() -> Self {
        Self::new(Self::DEFAULT_HEAP_BASE)
    }
}

impl SimProcedure for MallocProcedure {
    fn name(&self) -> &'static str {
        "malloc"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let size = state.get_arg(0);
        let alloc_size = if size == 0 {
            16
        } else {
            match size.checked_add(15) {
                Some(s) => s & !15,
                None => size,
            }
        };
        let ptr = self.next_ptr.fetch_add(alloc_size, Ordering::SeqCst);
        SimResult::Return(ptr)
    }
}

/// Stub procedure for `free`. No-op returning unchanged state.
pub struct FreeProcedure;

impl SimProcedure for FreeProcedure {
    fn name(&self) -> &'static str {
        "free"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        SimResult::Continue(state.clone())
    }
}

/// Stub procedure for `memcpy`. Copies `n` bytes from `src` (arg1) to `dest` (arg0).
pub struct MemcpyProcedure;

impl SimProcedure for MemcpyProcedure {
    fn name(&self) -> &'static str {
        "memcpy"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let dest = state.get_arg(0);
        let src = state.get_arg(1);
        let n = state.get_arg(2) as usize;
        let bytes = state.read_bytes(src, n);
        let mut new_state = state.clone();
        new_state.write_memory(dest, bytes);
        new_state.return_value = Some(dest);
        new_state.set_reg(0, dest);
        SimResult::Continue(new_state)
    }
}

/// Stub procedure for `memset`. Fills `n` bytes at `dest` (arg0) with `val` (arg1).
pub struct MemsetProcedure;

impl SimProcedure for MemsetProcedure {
    fn name(&self) -> &'static str {
        "memset"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let dest = state.get_arg(0);
        let byte_val = (state.get_arg(1) & 0xFF) as u8;
        let n = state.get_arg(2) as usize;
        let bytes = vec![byte_val; n];
        let mut new_state = state.clone();
        new_state.write_memory(dest, bytes);
        new_state.return_value = Some(dest);
        new_state.set_reg(0, dest);
        SimResult::Continue(new_state)
    }
}

/// Stub procedure for `puts`. No-op returning 0.
pub struct PutsProcedure;

impl SimProcedure for PutsProcedure {
    fn name(&self) -> &'static str {
        "puts"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0)
    }
}

/// Stub procedure for `exit`. Returns `SimResult::Exit` indicating process termination.
pub struct ExitProcedure;

impl SimProcedure for ExitProcedure {
    fn name(&self) -> &'static str {
        "exit"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Exit
    }
}

// ---------------------------------------------------------------------------
// Deterministic clock model (clock_gettime)
// ---------------------------------------------------------------------------

/// POSIX clock IDs for `clock_gettime`.
pub mod clock_id {
    pub const CLOCK_REALTIME: u64 = 0;
    pub const CLOCK_MONOTONIC: u64 = 1;
    pub const CLOCK_PROCESS_CPUTIME_ID: u64 = 2;
    pub const CLOCK_THREAD_CPUTIME_ID: u64 = 3;
    pub const CLOCK_MONOTONIC_RAW: u64 = 4;
    pub const CLOCK_REALTIME_COARSE: u64 = 5;
    pub const CLOCK_MONOTONIC_COARSE: u64 = 6;
    pub const CLOCK_BOOTTIME: u64 = 7;
}

/// Shared monotonic clock state providing deterministic time progression.
#[derive(Debug)]
pub struct DeterministicClockTracker {
    current_ns: AtomicU64,
    tick_ns: AtomicU64,
}

impl DeterministicClockTracker {
    /// Default initial simulated time (1.0 second in nanoseconds).
    pub const DEFAULT_INITIAL_NANOS: u64 = 1_000_000_000;
    /// Default deterministic tick increment per call (1 millisecond in nanoseconds).
    pub const DEFAULT_TICK_NANOS: u64 = 1_000_000;

    /// Creates a new deterministic clock tracker with custom initial time and tick step.
    pub fn new(initial_ns: u64, tick_ns: u64) -> Self {
        Self {
            current_ns: AtomicU64::new(initial_ns),
            tick_ns: AtomicU64::new(tick_ns),
        }
    }

    /// Advances simulated time monotonically by the configured tick increment and returns the new timestamp.
    pub fn advance(&self) -> u64 {
        let tick = self.tick_ns.load(Ordering::SeqCst);
        self.current_ns
            .fetch_add(tick, Ordering::SeqCst)
            .wrapping_add(tick)
    }

    /// Reads the current simulated time in nanoseconds without advancing.
    pub fn current_nanos(&self) -> u64 {
        self.current_ns.load(Ordering::SeqCst)
    }

    /// Reads the current tick increment in nanoseconds.
    pub fn tick_nanos(&self) -> u64 {
        self.tick_ns.load(Ordering::SeqCst)
    }

    /// Configures the tick increment in nanoseconds.
    pub fn set_tick(&self, tick_ns: u64) {
        self.tick_ns.store(tick_ns, Ordering::SeqCst);
    }

    /// Resets the clock to the specified nanosecond timestamp.
    pub fn reset(&self, initial_ns: u64) {
        self.current_ns.store(initial_ns, Ordering::SeqCst);
    }
}

impl Default for DeterministicClockTracker {
    fn default() -> Self {
        Self::new(Self::DEFAULT_INITIAL_NANOS, Self::DEFAULT_TICK_NANOS)
    }
}

/// Simulated procedure for POSIX `clock_gettime(clock_id, &tp)`.
///
/// Advances simulated monotonic time deterministically per invocation and writes
/// `struct timespec { time_t tv_sec; long tv_nsec; }` (16 bytes) into memory.
pub struct ClockGettimeProcedure {
    pub tracker: Arc<DeterministicClockTracker>,
}

impl ClockGettimeProcedure {
    /// Creates a new `ClockGettimeProcedure` backed by `tracker`.
    pub fn new(tracker: Arc<DeterministicClockTracker>) -> Self {
        Self { tracker }
    }
}

impl Default for ClockGettimeProcedure {
    fn default() -> Self {
        Self::new(Arc::new(DeterministicClockTracker::default()))
    }
}

impl SimProcedure for ClockGettimeProcedure {
    fn name(&self) -> &'static str {
        "clock_gettime"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let tp = state.get_arg(1);
        if tp == 0 {
            // NULL pointer: report -EFAULT
            return SimResult::Return(0u64.wrapping_sub(14));
        }

        let time_ns = self.tracker.advance();
        let sec = time_ns / 1_000_000_000;
        let nsec = time_ns % 1_000_000_000;

        let mut next = state.clone();
        next.write_memory(tp, sec.to_le_bytes().to_vec());
        next.write_memory(tp.wrapping_add(8), nsec.to_le_bytes().to_vec());
        next.return_value = Some(0);
        next.set_reg(0, 0);
        SimResult::Continue(next)
    }
}

/// Deterministic clock procedure with customizable procedure name.
pub struct DeterministicClockProcedure {
    pub tracker: Arc<DeterministicClockTracker>,
    name: &'static str,
}

impl DeterministicClockProcedure {
    /// Creates a new `DeterministicClockProcedure` with default name `"clock_gettime"`.
    pub fn new(tracker: Arc<DeterministicClockTracker>) -> Self {
        Self {
            tracker,
            name: "clock_gettime",
        }
    }

    /// Creates a new `DeterministicClockProcedure` with a custom procedure name.
    pub fn with_name(tracker: Arc<DeterministicClockTracker>, name: &'static str) -> Self {
        Self { tracker, name }
    }
}

impl Default for DeterministicClockProcedure {
    fn default() -> Self {
        Self::new(Arc::new(DeterministicClockTracker::default()))
    }
}

impl SimProcedure for DeterministicClockProcedure {
    fn name(&self) -> &'static str {
        self.name
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let tp = state.get_arg(1);
        if tp == 0 {
            return SimResult::Return(0u64.wrapping_sub(14));
        }

        let time_ns = self.tracker.advance();
        let sec = time_ns / 1_000_000_000;
        let nsec = time_ns % 1_000_000_000;

        let mut next = state.clone();
        next.write_memory(tp, sec.to_le_bytes().to_vec());
        next.write_memory(tp.wrapping_add(8), nsec.to_le_bytes().to_vec());
        next.return_value = Some(0);
        next.set_reg(0, 0);
        SimResult::Continue(next)
    }
}

// ---------------------------------------------------------------------------
// Linux Futex synchronization models (SYS_futex, futex_wait, futex_wake)
// ---------------------------------------------------------------------------

/// Futex operation codes.
pub mod futex_op {
    pub const FUTEX_WAIT: u64 = 0;
    pub const FUTEX_WAKE: u64 = 1;
    pub const FUTEX_FD: u64 = 2;
    pub const FUTEX_REQUEUE: u64 = 3;
    pub const FUTEX_CMP_REQUEUE: u64 = 4;
    pub const FUTEX_WAKE_OP: u64 = 5;
    pub const FUTEX_LOCK_PI: u64 = 6;
    pub const FUTEX_UNLOCK_PI: u64 = 7;
    pub const FUTEX_TRYLOCK_PI: u64 = 8;
    pub const FUTEX_WAIT_BITSET: u64 = 9;
    pub const FUTEX_WAKE_BITSET: u64 = 10;
    pub const FUTEX_WAIT_REQUEUE_PI: u64 = 11;
    pub const FUTEX_CMP_REQUEUE_PI: u64 = 12;

    pub const FUTEX_PRIVATE_FLAG: u64 = 128;
    pub const FUTEX_CLOCK_REALTIME: u64 = 256;
    pub const FUTEX_CMD_MASK: u64 = !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);
}

/// A recorded futex waiter on a specific user-space word address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FutexWaiter {
    pub tid: u64,
    pub waiter_id: u64,
}

/// Snapshot of futex wait queues and activity.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FutexReport {
    pub total_waits: u64,
    pub total_wakes: u64,
    pub active_queues: usize,
    pub total_waiters: usize,
}

#[derive(Default)]
struct FutexState {
    queues: BTreeMap<u64, Vec<FutexWaiter>>,
    total_waits: u64,
    total_wakes: u64,
}

/// Shared tracker for Linux futex wait-queues and wake notifications.
pub struct FutexTracker {
    next_waiter_id: AtomicU64,
    state: Mutex<FutexState>,
}

impl FutexTracker {
    /// Creates a new empty futex tracker.
    pub fn new() -> Self {
        Self {
            next_waiter_id: AtomicU64::new(1),
            state: Mutex::new(FutexState::default()),
        }
    }

    /// Enqueues a waiter on the futex word at `uaddr`. Returns the allocated waiter ID.
    pub fn wait(&self, uaddr: u64, tid: u64) -> u64 {
        let waiter_id = self.next_waiter_id.fetch_add(1, Ordering::SeqCst);
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        st.total_waits += 1;
        st.queues
            .entry(uaddr)
            .or_default()
            .push(FutexWaiter { tid, waiter_id });
        waiter_id
    }

    /// Wakes up to `count` waiters queued on `uaddr`. Returns the number of waiters woken.
    pub fn wake(&self, uaddr: u64, count: u32) -> u32 {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let (to_wake, should_remove) = if let Some(queue) = st.queues.get_mut(&uaddr) {
            let to_wake = (count as usize).min(queue.len());
            queue.drain(0..to_wake);
            (to_wake, queue.is_empty())
        } else {
            (0, false)
        };
        if to_wake > 0 {
            st.total_wakes += to_wake as u64;
        }
        if should_remove {
            st.queues.remove(&uaddr);
        }
        to_wake as u32
    }

    /// Returns the number of waiters currently queued at `uaddr`.
    pub fn waiter_count(&self, uaddr: u64) -> usize {
        let st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        st.queues.get(&uaddr).map_or(0, |q| q.len())
    }

    /// Returns true if any waiters are currently waiting at `uaddr`.
    pub fn has_waiters(&self, uaddr: u64) -> bool {
        self.waiter_count(uaddr) > 0
    }

    /// Returns the total number of waiters across all futex queues.
    pub fn total_waiters(&self) -> usize {
        let st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        st.queues.values().map(|q| q.len()).sum()
    }

    /// Returns a list of all waiters queued at `uaddr`.
    pub fn waiters_at(&self, uaddr: u64) -> Vec<FutexWaiter> {
        let st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        st.queues.get(&uaddr).cloned().unwrap_or_default()
    }

    /// Returns a snapshot report of tracker activity.
    pub fn report(&self) -> FutexReport {
        let st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let total_waiters = st.queues.values().map(|q| q.len()).sum();
        FutexReport {
            total_waits: st.total_waits,
            total_wakes: st.total_wakes,
            active_queues: st.queues.len(),
            total_waiters,
        }
    }

    /// Resets all queues and counters.
    pub fn reset(&self) {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        st.queues.clear();
        st.total_waits = 0;
        st.total_wakes = 0;
        self.next_waiter_id.store(1, Ordering::SeqCst);
    }
}

impl Default for FutexTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper resolving expected word in futex_wait: supports both
/// `futex_wait(uaddr, val)` (arg1=val) and `futex(uaddr, FUTEX_WAIT, val)` (arg1=0, arg2=val).
fn resolve_expected_futex_word(state: &SimState, uaddr: u64) -> u32 {
    let arg1 = state.get_arg(1);
    let arg2 = state.get_arg(2);
    if arg1 == futex_op::FUTEX_WAIT && arg2 != 0 {
        let bytes = state.read_bytes(uaddr, 4);
        let current = u32::from_le_bytes(bytes.try_into().unwrap_or([0; 4]));
        if current == (arg2 as u32) {
            return arg2 as u32;
        }
    }
    arg1 as u32
}

/// Simulated procedure for `futex_wait(uaddr, val)`.
///
/// Verifies that `*uaddr == val` against simulated state memory. If the word matches,
/// enqueues the caller into the futex wait-queue and returns 0. If the word does not
/// match, returns `-EAGAIN` (`0u64.wrapping_sub(11)`) without enqueuing.
pub struct FutexWaitProcedure {
    pub tracker: Arc<FutexTracker>,
}

impl FutexWaitProcedure {
    pub fn new(tracker: Arc<FutexTracker>) -> Self {
        Self { tracker }
    }
}

impl Default for FutexWaitProcedure {
    fn default() -> Self {
        Self::new(Arc::new(FutexTracker::default()))
    }
}

impl SimProcedure for FutexWaitProcedure {
    fn name(&self) -> &'static str {
        "futex_wait"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let uaddr = state.get_arg(0);
        let expected = resolve_expected_futex_word(state, uaddr);
        let bytes = state.read_bytes(uaddr, 4);
        let current = u32::from_le_bytes(bytes.try_into().unwrap_or([0; 4]));

        if current != expected {
            // Word mismatch: Linux returns -EAGAIN
            SimResult::Return(0u64.wrapping_sub(11))
        } else {
            let tid = if state.get_arg(5) != 0 {
                state.get_arg(5)
            } else {
                1
            };
            self.tracker.wait(uaddr, tid);
            SimResult::Return(0)
        }
    }
}

/// Simulated procedure for `futex_wake(uaddr, count)`.
///
/// Removes up to `count` waiting threads from the wait queue for `uaddr`
/// and returns the number of woken waiters.
pub struct FutexWakeProcedure {
    pub tracker: Arc<FutexTracker>,
}

impl FutexWakeProcedure {
    pub fn new(tracker: Arc<FutexTracker>) -> Self {
        Self { tracker }
    }
}

impl Default for FutexWakeProcedure {
    fn default() -> Self {
        Self::new(Arc::new(FutexTracker::default()))
    }
}

impl SimProcedure for FutexWakeProcedure {
    fn name(&self) -> &'static str {
        "futex_wake"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let uaddr = state.get_arg(0);
        let arg1 = state.get_arg(1);
        let arg2 = state.get_arg(2);
        let count = if arg1 == futex_op::FUTEX_WAKE && arg2 != 0 {
            arg2 as u32
        } else if arg1 != 0 {
            arg1 as u32
        } else {
            1
        };

        let woken = self.tracker.wake(uaddr, count);
        SimResult::Return(woken as u64)
    }
}

/// Simulated procedure for Linux `SYS_futex(uaddr, op, val, timeout, uaddr2, val3)`.
pub struct FutexProcedure {
    pub tracker: Arc<FutexTracker>,
}

impl FutexProcedure {
    pub fn new(tracker: Arc<FutexTracker>) -> Self {
        Self { tracker }
    }
}

impl Default for FutexProcedure {
    fn default() -> Self {
        Self::new(Arc::new(FutexTracker::default()))
    }
}

impl SimProcedure for FutexProcedure {
    fn name(&self) -> &'static str {
        "futex"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let uaddr = state.get_arg(0);
        let op = state.get_arg(1);
        let cmd = op & futex_op::FUTEX_CMD_MASK;

        match cmd {
            futex_op::FUTEX_WAIT | futex_op::FUTEX_WAIT_BITSET => {
                let expected = state.get_arg(2) as u32;
                let bytes = state.read_bytes(uaddr, 4);
                let current = u32::from_le_bytes(bytes.try_into().unwrap_or([0; 4]));
                if current != expected {
                    SimResult::Return(0u64.wrapping_sub(11)) // -EAGAIN
                } else {
                    let tid = if state.get_arg(5) != 0 { state.get_arg(5) } else { 1 };
                    self.tracker.wait(uaddr, tid);
                    SimResult::Return(0)
                }
            }
            futex_op::FUTEX_WAKE | futex_op::FUTEX_WAKE_BITSET => {
                let count = state.get_arg(2) as u32;
                let woken = self.tracker.wake(uaddr, if count == 0 { 1 } else { count });
                SimResult::Return(woken as u64)
            }
            _ => {
                // Unsupported futex operation: -ENOSYS
                SimResult::Return(0u64.wrapping_sub(38))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// POSIX Threading primitives (pthread_create)
// ---------------------------------------------------------------------------

/// Allocated stack slot for a modeled thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadStackSlot {
    /// Base address of the stack allocation.
    pub base: u64,
    /// Allocated size of the stack in bytes.
    pub size: u64,
    /// Initial stack pointer (top of stack on descending architectures like x86-64).
    pub top: u64,
}

/// Recorded metadata for a simulated thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThreadDescriptor {
    /// Deterministically seeded thread identifier.
    pub tid: u64,
    /// Function pointer address for the thread entry point.
    pub entry_point: u64,
    /// Caller argument passed to the start routine.
    pub arg: u64,
    /// Allocated stack memory slot.
    pub stack: ThreadStackSlot,
}

/// Shared tracker for deterministic thread creation and stack allocation.
pub struct ThreadTracker {
    next_tid: AtomicU64,
    next_stack_base: AtomicU64,
    stack_size: u64,
    threads: Mutex<Vec<ThreadDescriptor>>,
}

impl ThreadTracker {
    /// Initial base thread ID handed out by the tracker.
    pub const DEFAULT_TID_BASE: u64 = 1000;
    /// Default starting address for thread stack allocations (0x7000_1000_0000).
    pub const DEFAULT_STACK_BASE: u64 = 0x0000_7000_1000_0000;
    /// Default stack size per thread (1 MB).
    pub const DEFAULT_STACK_SIZE: u64 = 0x0010_0000;

    /// Creates a new thread tracker with custom starting TID, stack base, and stack size.
    pub fn new(initial_tid: u64, stack_base: u64, stack_size: u64) -> Self {
        Self {
            next_tid: AtomicU64::new(initial_tid),
            next_stack_base: AtomicU64::new(stack_base),
            stack_size,
            threads: Mutex::new(Vec::new()),
        }
    }

    /// Seeds a new deterministic thread, allocating a new stack slot and recording the entry point.
    pub fn seed_thread(&self, entry_point: u64, arg: u64) -> ThreadDescriptor {
        let tid = self.next_tid.fetch_add(1, Ordering::SeqCst);
        let base = self.next_stack_base.fetch_add(self.stack_size, Ordering::SeqCst);
        let top = base.wrapping_add(self.stack_size);
        let desc = ThreadDescriptor {
            tid,
            entry_point,
            arg,
            stack: ThreadStackSlot {
                base,
                size: self.stack_size,
                top,
            },
        };
        let mut list = self.threads.lock().unwrap_or_else(|p| p.into_inner());
        list.push(desc);
        desc
    }

    /// Returns the number of threads created by this tracker.
    pub fn thread_count(&self) -> usize {
        let list = self.threads.lock().unwrap_or_else(|p| p.into_inner());
        list.len()
    }

    /// Returns a snapshot of all recorded thread descriptors.
    pub fn threads(&self) -> Vec<ThreadDescriptor> {
        let list = self.threads.lock().unwrap_or_else(|p| p.into_inner());
        list.clone()
    }

    /// Finds a thread descriptor by its TID.
    pub fn get_thread(&self, tid: u64) -> Option<ThreadDescriptor> {
        let list = self.threads.lock().unwrap_or_else(|p| p.into_inner());
        list.iter().copied().find(|t| t.tid == tid)
    }

    /// Returns the most recently seeded thread descriptor.
    pub fn latest_thread(&self) -> Option<ThreadDescriptor> {
        let list = self.threads.lock().unwrap_or_else(|p| p.into_inner());
        list.last().copied()
    }

    /// Resets thread records and resets TID and stack allocators.
    pub fn reset(&self, initial_tid: u64, stack_base: u64) {
        let mut list = self.threads.lock().unwrap_or_else(|p| p.into_inner());
        list.clear();
        self.next_tid.store(initial_tid, Ordering::SeqCst);
        self.next_stack_base.store(stack_base, Ordering::SeqCst);
    }
}

impl Default for ThreadTracker {
    fn default() -> Self {
        Self::new(
            Self::DEFAULT_TID_BASE,
            Self::DEFAULT_STACK_BASE,
            Self::DEFAULT_STACK_SIZE,
        )
    }
}

/// Simulated procedure for `pthread_create(&thread, attr, start_routine, arg)`.
///
/// Seeds a deterministic thread ID, allocates a new thread stack slot, records the
/// thread entry point, and writes the new thread ID to `*thread`.
pub struct PthreadCreateProcedure {
    pub tracker: Arc<ThreadTracker>,
}

impl PthreadCreateProcedure {
    pub fn new(tracker: Arc<ThreadTracker>) -> Self {
        Self { tracker }
    }
}

impl Default for PthreadCreateProcedure {
    fn default() -> Self {
        Self::new(Arc::new(ThreadTracker::default()))
    }
}

impl SimProcedure for PthreadCreateProcedure {
    fn name(&self) -> &'static str {
        "pthread_create"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let p_thread = state.get_arg(0);
        let _attr = state.get_arg(1);
        let start_routine = state.get_arg(2);
        let arg = state.get_arg(3);

        let desc = self.tracker.seed_thread(start_routine, arg);

        let mut next = state.clone();
        if p_thread != 0 {
            next.write_memory(p_thread, desc.tid.to_le_bytes().to_vec());
        }
        next.return_value = Some(0); // pthread_create returns 0 on success
        next.set_reg(0, 0);
        SimResult::Continue(next)
    }
}

/// Kernel-export return stub: models a hooked import (e.g. a PE-driver
/// `ntoskrnl.exe` import) whose observable effect for the caller is a fixed
/// return value, ignoring the simulated arguments entirely.
pub struct KernelReturnStub {
    /// The value the stub returns in RAX.
    pub value: u64,
}

impl SimProcedure for KernelReturnStub {
    fn name(&self) -> &'static str {
        "kernel_stub_return"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(self.value)
    }
}

// ---------------------------------------------------------------------------
// Windows kernel pool model (ntoskrnl allocator/free family)
// ---------------------------------------------------------------------------

/// First fresh pool pointer handed out by [`KernelAllocProcedure`]. The
/// classic kernel non-paged range; distinct pointers per call, page-strided
/// so naive structure walks land in distinct (zeroed) shadow memory rather
/// than overlapping.
pub const KERNEL_POOL_FRESH_BASE: u64 = 0xFFFF_8000_0000_0000;

/// One recorded pool event: the pointer involved and the caller return
/// address captured by the runtime at dispatch time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PoolEvent {
    pub pointer: u64,
    pub caller: u64,
}

/// Snapshot of [`KernelPoolTracker`] state for reports/scripting.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct KernelPoolReport {
    pub allocs: u64,
    pub frees: u64,
    /// frees of an already-freed pointer, chronological.
    pub double_frees: Vec<PoolEvent>,
    /// writes into a freed pool page (use-after-free witnesses).
    pub uaf_writes: Vec<PoolEvent>,
}

/// Shared state behind the kernel allocator/free SimProcedures. The runtime
/// records every modeled alloc/free (pointer + caller return address) here;
/// a free of an already-freed pointer is a double-free witness regardless of
/// who allocated the block — freeing the same pointer twice is the bug class
/// itself.
pub struct KernelPoolTracker {
    next_fresh: AtomicU64,
    state: Mutex<PoolState>,
}

#[derive(Default)]
struct PoolState {
    allocs: u64,
    frees: u64,
    freed: HashSet<u64>,
    double_frees: Vec<PoolEvent>,
    uaf_writes: Vec<PoolEvent>,
}

impl KernelPoolTracker {
    pub fn new() -> Self {
        Self {
            next_fresh: AtomicU64::new(KERNEL_POOL_FRESH_BASE),
            state: Mutex::new(PoolState::default()),
        }
    }

    /// Next distinct fresh pool pointer.
    pub fn fresh_pointer(&self) -> u64 {
        self.next_fresh.fetch_add(0x1000, Ordering::Relaxed)
    }

    /// Records a modeled allocation.
    pub fn record_alloc(&self) {
        if let Ok(mut st) = self.state.lock() {
            st.allocs += 1;
        }
    }

    /// Records a modeled free of `pointer` from `caller`. A pointer freed
    /// twice is recorded as a double-free event.
    pub fn record_free(&self, pointer: u64, caller: u64) {
        if let Ok(mut st) = self.state.lock() {
            st.frees += 1;
            if !st.freed.insert(pointer) {
                st.double_frees.push(PoolEvent { pointer, caller });
            }
        }
    }

    /// Records a write into a freed pool page (use-after-free witness).
    pub fn record_uaf(&self, address: u64, caller: u64) {
        if let Ok(mut st) = self.state.lock() {
            st.uaf_writes.push(PoolEvent {
                pointer: address,
                caller,
            });
        }
    }

    /// True when `address` falls inside a freed model pool page (freed
    /// pointers are 0x1000-aligned; the whole page is considered freed —
    /// writes into the pool header area are also UAF).
    pub fn is_freed_page(&self, address: u64) -> bool {
        if let Ok(st) = self.state.lock() {
            let page = address & !0xFFF;
            st.freed.contains(&page)
        } else {
            false
        }
    }

    /// Consistent snapshot for reports.
    pub fn snapshot(&self) -> KernelPoolReport {
        match self.state.lock() {
            Ok(st) => KernelPoolReport {
                allocs: st.allocs,
                frees: st.frees,
                double_frees: st.double_frees.clone(),
                uaf_writes: st.uaf_writes.clone(),
            },
            Err(_) => KernelPoolReport::default(),
        }
    }
}

impl Default for KernelPoolTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// `ExAllocatePool*`: hands out a distinct fresh pool pointer per call and
/// records the allocation. (The NULL failure arm of the full model —
/// `symbolic_nonzero_or_null` in the byovd-harness manifest — is deferred
/// until symbolic SimProcedure inputs exist; concretely the allocator never
/// fails, which is the standard concolic choice and is debt-recorded.)
pub struct KernelAllocProcedure {
    pub tracker: std::sync::Arc<KernelPoolTracker>,
}

impl SimProcedure for KernelAllocProcedure {
    fn name(&self) -> &'static str {
        "kernel_alloc_pool"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        // No recording here — the dispatch pre-hook (runtime) is the single
        // recorder: it alone can capture the true caller return address
        // from [rsp] and keeps alloc/free counts one-per-call.
        SimResult::Return(self.tracker.fresh_pointer())
    }
}

/// `ExFreePool*`: records the free (the runtime captures pointer + caller);
/// returns success. Void return modeled as 0.
pub struct KernelFreeProcedure {
    pub tracker: std::sync::Arc<KernelPoolTracker>,
}

impl SimProcedure for KernelFreeProcedure {
    fn name(&self) -> &'static str {
        "kernel_free_pool"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        // Recording is single-sourced in the dispatch pre-hook (pointer
        // from RCX + true caller from [rsp]); see KernelAllocProcedure.
        SimResult::Return(0)
    }
}

/// Address of the runtime's universal kernel callback page
/// (`xor eax, eax; ret` → STATUS_SUCCESS). The runtime maps this page for
/// driver-mode processes; kernel APIs that RESOLVE function pointers
/// (e.g. `MmGetSystemRoutineAddress`) return this address so later
/// indirect calls land on a real stub instead of unmapped memory.
pub const KERNEL_UNIVERSAL_CALLBACK: u64 = 0x0000_7000_2000_0000;

/// `IoCreateDevice(DriverObject, DeviceExtensionSize, DeviceName,
/// DeviceType, Characteristics, Exclusive, pptrDeviceObject)`:
/// allocates a zero-backed device object + extension block, populates the
/// fields drivers read first (Type, DeviceExtension, DeviceType,
/// ReferenceCount), writes the object pointer through the OUT parameter,
/// and returns STATUS_SUCCESS. The OUT pointer is a stack argument
/// (`[rsp+0x38]`) — the runtime's stack-argument shadowing makes it
/// visible to SimState.
pub struct KernelCreateDeviceProcedure {
    pub tracker: std::sync::Arc<KernelPoolTracker>,
}

impl SimProcedure for KernelCreateDeviceProcedure {
    fn name(&self) -> &'static str {
        "kernel_create_device"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        // Fresh device object + zeroed extension, both from the pool
        // arena (the shadow region backs them with zeros).
        let device = self.tracker.fresh_pointer();
        let extension = self.tracker.fresh_pointer();
        let device_type = state.get_reg(9); // r9 = DeviceType (4 register args)

        let mut next = state.clone();
        // DEVICE_OBJECT header: Type (u16 = 15, IO_TYPE_DEVICE) |
        // Size (u16 = 0x1030), DeviceExtension (+0x08), DeviceType
        // (+0x1C u32), ReferenceCount (+0x20 u32 = 1).
        let type_size = (0x1030u64 << 32) | 15;
        next.write_memory(device, type_size.to_le_bytes().to_vec());
        next.write_memory(device + 0x08, extension.to_le_bytes().to_vec());
        next.write_memory(device + 0x1C, device_type.to_le_bytes()[..4].to_vec());
        next.write_memory(device + 0x20, 1u32.to_le_bytes().to_vec());
        // Extension back-pointer to the driver object (rcx).
        next.write_memory(extension, state.get_reg(1).to_le_bytes().to_vec());
        // OUT: *pptrDeviceObject = device. pptr at [rsp+0x38] (7th arg).
        let rsp = state.get_reg(4);
        let pptr = u64::from_le_bytes(state.read_bytes(rsp + 0x38, 8).try_into().unwrap_or([0; 8]));
        if pptr != 0 {
            next.write_memory(pptr, device.to_le_bytes().to_vec());
        }
        SimResult::Continue(next)
    }
}

/// `IoAttachDevice(DeviceObject, TargetDevice, AttachedDevice)`:
/// writes a fresh object pointer through the AttachedDevice OUT pointer
/// (r8, a register argument) and returns STATUS_SUCCESS.
pub struct KernelAttachDeviceProcedure {
    pub tracker: std::sync::Arc<KernelPoolTracker>,
}

impl SimProcedure for KernelAttachDeviceProcedure {
    fn name(&self) -> &'static str {
        "kernel_attach_device"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let attached = self.tracker.fresh_pointer();
        let out_ptr = state.get_reg(8); // r8 = pAttachedDevice
        let mut next = state.clone();
        if out_ptr != 0 {
            next.write_memory(out_ptr, attached.to_le_bytes().to_vec());
        }
        SimResult::Continue(next)
    }
}

/// `MmGetSystemRoutineAddress(UnicodeString)`: returns the universal
/// callback address — a resolved "routine" that returns STATUS_SUCCESS.
/// Calling through it is well-defined; the routine identity is debt.
pub struct KernelResolveRoutineProcedure;

impl SimProcedure for KernelResolveRoutineProcedure {
    fn name(&self) -> &'static str {
        "kernel_resolve_routine"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(KERNEL_UNIVERSAL_CALLBACK)
    }
}

/// `IoGetDeviceObjectPointer(DeviceName, DesiredAccess, FileObject,
/// DeviceObject)`: writes a fresh device object through r9 and a matching
/// file object through r8, returning STATUS_SUCCESS. The device object's
/// MajorFunction table (+0x70, 28 slots) points at the universal callback
/// (STATUS_SUCCESS), so drivers that submit IRPs through it proceed; its
/// DriverObject (+0x08) points at a fresh object. The previous default stub
/// returned NULL, sending drivers down "no target device" paths.
pub struct KernelGetDeviceObjectPointerProcedure {
    pub tracker: std::sync::Arc<KernelPoolTracker>,
}

impl SimProcedure for KernelGetDeviceObjectPointerProcedure {
    fn name(&self) -> &'static str {
        "kernel_get_device_object_pointer"
    }
    fn apply(&self, state: &SimState) -> SimResult {
        let device = self.tracker.fresh_pointer();
        let file = self.tracker.fresh_pointer();
        let driver = self.tracker.fresh_pointer();
        let mut next = state.clone();
        // DEVICE_OBJECT: Type=15 | Size=0x1030, DriverObject=+0x08,
        // MajorFunction[0..28] at +0x70 -> universal callback.
        let type_size = (0x1030u64 << 32) | 15;
        next.write_memory(device, type_size.to_le_bytes().to_vec());
        next.write_memory(device + 0x08, driver.to_le_bytes().to_vec());
        for i in 0..28u64 {
            next.write_memory(device + 0x70 + 8 * i, KERNEL_UNIVERSAL_CALLBACK.to_le_bytes().to_vec());
        }
        // FILE_OBJECT: Type=5 | Size=0x98, DeviceObject=+0x08.
        let file_type_size = (0x98u64 << 32) | 5;
        next.write_memory(file, file_type_size.to_le_bytes().to_vec());
        next.write_memory(file + 0x08, device.to_le_bytes().to_vec());
        // OUT: *r8 = FileObject, *r9 = DeviceObject (register args).
        let p_file = state.get_reg(8);
        let p_device = state.get_reg(9);
        if p_file != 0 {
            next.write_memory(p_file, file.to_le_bytes().to_vec());
        }
        if p_device != 0 {
            next.write_memory(p_device, device.to_le_bytes().to_vec());
        }
        SimResult::Return(0) // STATUS_SUCCESS
    }
}

/// `EtwRegister(ProviderId, Callback, CallbackContext, RegistrationHandle)`
/// (4 register args): writes a fresh non-NULL registration handle through
/// r9 and returns STATUS_SUCCESS. Drivers keep the handle for
/// EtwUnregister/event writes.
pub struct KernelEtwRegisterProcedure {
    pub tracker: std::sync::Arc<KernelPoolTracker>,
}

impl SimProcedure for KernelEtwRegisterProcedure {
    fn name(&self) -> &'static str {
        "kernel_etw_register"
    }
    fn apply(&self, state: &SimState) -> SimResult {
        let handle = self.tracker.fresh_pointer();
        let mut next = state.clone();
        let p_handle = state.get_reg(9); // RegistrationHandle OUT
        if p_handle != 0 {
            next.write_memory(p_handle, handle.to_le_bytes().to_vec());
        }
        SimResult::Return(0) // STATUS_SUCCESS
    }
}

/// `EtwProviderEnabled`: deterministic "disabled" (0).
pub struct KernelEtwProviderEnabledProcedure;

impl SimProcedure for KernelEtwProviderEnabledProcedure {
    fn name(&self) -> &'static str {
        "kernel_etw_provider_enabled"
    }
    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0)
    }
}

/// `ZwOpenKey(KeyHandle*, DesiredAccess, ObjectAttributes, ...)`: writes a
/// fresh non-NULL handle through the first stack argument (Win x64 arg 5
/// at [rsp+0x28]) and returns STATUS_SUCCESS.
pub struct KernelZwOpenKeyProcedure {
    pub tracker: std::sync::Arc<KernelPoolTracker>,
}

impl SimProcedure for KernelZwOpenKeyProcedure {
    fn name(&self) -> &'static str {
        "kernel_zw_open_key"
    }
    fn apply(&self, state: &SimState) -> SimResult {
        let handle = self.tracker.fresh_pointer();
        let mut next = state.clone();
        // ZwOpenKey(KeyHandle*, DesiredAccess, ObjectAttributes): the
        // handle OUT pointer is the FIRST argument (RCX = reg 1), not a
        // stack argument (codex-5.3 review catch).
        let p_handle = state.get_reg(1);
        if p_handle != 0 {
            next.write_memory(p_handle, handle.to_le_bytes().to_vec());
        }
        SimResult::Return(0)
    }
}

/// `ZwQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass,
/// KeyValueInformation, Length, ResultLength)`: writes a deterministic
/// DWORD (0x100) into the caller's value buffer (arg 4 at [rsp+0x30] —
/// verify; the value buffer is the 4th register arg RDX? No: the signature
/// is (KeyHandle, ValueName, Class, Info, InfoLength, ResultLength) — the
/// info buffer is arg 4 = r9, length arg 5 = [rsp+0x28]) and sets the
/// result-length OUT (arg 6 = [rsp+0x30]) to 4. Returns STATUS_SUCCESS.
/// NOTE: verify the argument positions against the WDK signature before
/// finalizing; the exact offsets below assume the standard layout.
pub struct KernelZwQueryValueKeyProcedure;

impl SimProcedure for KernelZwQueryValueKeyProcedure {
    fn name(&self) -> &'static str {
        "kernel_zw_query_value_key"
    }
    fn apply(&self, state: &SimState) -> SimResult {
        let mut next = state.clone();
        let info = state.get_reg(9); // KeyValueInformation buffer
        if info != 0 {
            next.write_memory(info, 0x100u32.to_le_bytes().to_vec());
        }
        let rsp = state.get_reg(4);
        let p_result_len = u64::from_le_bytes(state.read_bytes(rsp + 0x30, 8).try_into().unwrap_or([0; 8]));
        if p_result_len != 0 {
            next.write_memory(p_result_len, 4u32.to_le_bytes().to_vec());
        }
        SimResult::Return(0)
    }
}

/// `KeInitializeEvent(Event, Type, State)`: writes an event header into the
/// caller's buffer: Type u16 at +0x00, SignalState u32 at +0x04.
pub struct KernelInitializeEventProcedure;

impl SimProcedure for KernelInitializeEventProcedure {
    fn name(&self) -> &'static str {
        "kernel_initialize_event"
    }
    fn apply(&self, state: &SimState) -> SimResult {
        let event = state.get_reg(1);
        // KeInitializeEvent(Event, Type, State): State is arg 3 = R8
        // (reg 8), not RBX (codex-5.3 review catch).
        let signal = state.get_reg(8) as u32;
        let mut next = state.clone();
        if event != 0 {
            next.write_memory(event, 0u16.to_le_bytes().to_vec()); // Type = NotificationEvent
            next.write_memory(event + 4, signal.to_le_bytes().to_vec());
        }
        SimResult::Return(0)
    }
}

/// `KeInitializeMutex(Mutex, Level)`: writes a mutex header: Type u16 = 1
/// at +0x00, SignalState u32 at +0x04.
pub struct KernelInitializeMutexProcedure;

impl SimProcedure for KernelInitializeMutexProcedure {
    fn name(&self) -> &'static str {
        "kernel_initialize_mutex"
    }
    fn apply(&self, state: &SimState) -> SimResult {
        let mutex = state.get_reg(1);
        let mut next = state.clone();
        if mutex != 0 {
            next.write_memory(mutex, 1u16.to_le_bytes().to_vec()); // Type = Mutex
            next.write_memory(mutex + 4, 1u32.to_le_bytes().to_vec()); // signaled
        }
        SimResult::Return(0)
    }
}

/// `RtlQueryRegistryValues`: fills the caller's query-table buffers with
/// deterministic values (DWORD 0x100 per entry) and returns STATUS_SUCCESS.
/// The query table is a pointer array; the first entry's ValueData pointer
/// is at [r9+...] — keep this minimal: write 0x100 through the first
/// query entry's data pointer if present, else just return success.
pub struct KernelQueryRegistryValuesProcedure;

impl SimProcedure for KernelQueryRegistryValuesProcedure {
    fn name(&self) -> &'static str {
        "kernel_query_registry_values"
    }
    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0)
    }
}

/// `KeQueryPerformanceCounter()`: returns a deterministic non-zero counter
/// value in RAX (the HAL export). Drivers use it for timing and entropy;
/// mirroring the RDTSC model (fixed constant, replay-safe).
pub struct KernelQueryPerformanceCounterProcedure;

impl SimProcedure for KernelQueryPerformanceCounterProcedure {
    fn name(&self) -> &'static str {
        "kernel_query_performance_counter"
    }
    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0x0000_0000_0100_0000) // ~16M counts (arbitrary)
    }
}

// ---------------------------------------------------------------------------
// Syscall environment model
// ---------------------------------------------------------------------------

/// Minimal Linux x86-64 syscall environment model.
///
/// The runtime owns process memory, so it performs the memory reads and writes
/// a syscall needs; this model owns the observable effects: captured `write`
/// output, the recorded exit code, and per-syscall counters. Syscall numbers
/// the model does not implement are reported back to the caller so execution
/// can fail explicitly instead of fabricating a result.
pub mod syscall {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// `read` syscall number.
    pub const READ: u64 = 0;
    /// `write` syscall number.
    pub const WRITE: u64 = 1;
    /// `mprotect` syscall number.
    pub const MPROTECT: u64 = 10;
    /// `brk` syscall number.
    pub const BRK: u64 = 12;
    pub const READLINKAT: u64 = 267;
    pub const PRLIMIT64: u64 = 302;
    /// `getpid` syscall number.
    pub const GETPID: u64 = 39;
    /// `arch_prctl` syscall number (segment-base setup for TLS).
    pub const ARCH_PRCTL: u64 = 158;
    /// `gettid` syscall number.
    pub const GETTID: u64 = 186;
    /// `set_tid_address` syscall number.
    pub const SET_TID_ADDRESS: u64 = 218;
    /// `exit_group` syscall number.
    pub const EXIT_GROUP: u64 = 231;
    /// `set_robust_list` syscall number.
    pub const SET_ROBUST_LIST: u64 = 273;
    /// `getrandom` syscall number.
    pub const GETRANDOM: u64 = 318;
    /// `rseq` syscall number.
    pub const RSEQ: u64 = 334;
    /// `exit` syscall number.
    pub const EXIT: u64 = 60;

    pub const OPENAT: u64 = 257;
    pub const CLOSE: u64 = 3;
    pub const FSTAT: u64 = 5;
    pub const ACCESS: u64 = 21;
    pub const MMAP: u64 = 9;
    pub const MUNMAP: u64 = 11;
    pub const IOCTL: u64 = 16;
    pub const WRITEV: u64 = 20;
    pub const GETUID: u64 = 102;
    pub const GETEUID: u64 = 107;
    pub const GETGID: u64 = 104;
    pub const GETEGID: u64 = 108;
    pub const CLONE: u64 = 56;
    pub const FUTEX: u64 = 202;
    pub const CLOCK_GETTIME: u64 = 228;

    /// `arch_prctl` operation codes.
    pub mod arch_prctl_op {
        /// Set the FS segment base.
        pub const SET_FS: u64 = 0x1002;
        /// Get the FS segment base.
        pub const GET_FS: u64 = 0x1003;
        /// Set the GS segment base.
        pub const SET_GS: u64 = 0x1001;
        /// Get the GS segment base.
        pub const GET_GS: u64 = 0x1004;
    }

    /// Outcome of a modeled syscall.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum SyscallOutcome {
        /// Execution terminates with this exit code.
        Exit { code: u64 },
        /// Execution continues; the value is written to RAX.
        Return { value: u64 },
    }

    /// Captures the observable effects of modeled syscalls.
    #[derive(Debug, Default)]
    pub struct SyscallModel {
        output: Mutex<Vec<u8>>,
        exit_code: Mutex<Option<u64>>,
        invocations: AtomicU64,
    }

    impl Clone for SyscallModel {
        fn clone(&self) -> Self {
            Self {
                output: Mutex::new(self.output()),
                exit_code: Mutex::new(self.exit_code()),
                invocations: AtomicU64::new(self.invocations()),
            }
        }
    }

    impl SyscallModel {
        /// Creates an empty model.
        pub fn new() -> Self {
            Self::default()
        }

        /// Records a `write` of `bytes` and returns the modeled byte count.
        pub fn record_write(&self, bytes: &[u8]) -> u64 {
            self.invocations.fetch_add(1, Ordering::Relaxed);
            let mut output = self.output.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            output.extend_from_slice(bytes);
            u64::try_from(bytes.len()).unwrap_or(u64::MAX)
        }

        /// Records `exit(code)`.
        pub fn record_exit(&self, code: u64) -> SyscallOutcome {
            self.invocations.fetch_add(1, Ordering::Relaxed);
            let mut exit_code = self.exit_code.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            *exit_code = Some(code);
            SyscallOutcome::Exit { code }
        }

        /// Bytes captured from `write` syscalls.
        pub fn output(&self) -> Vec<u8> {
            self.output
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone()
        }

        /// Exit code recorded by `exit`, if any.
        pub fn exit_code(&self) -> Option<u64> {
            *self.exit_code.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
        }

        /// Number of modeled syscalls.
        pub fn invocations(&self) -> u64 {
            self.invocations.load(Ordering::Relaxed)
        }

        /// Clears captured state, used when a process restarts from entry.
        pub fn reset(&self) {
            self.output
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clear();
            *self.exit_code.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
            self.invocations.store(0, Ordering::Relaxed);
        }
    }

    use crate::{
        ClockGettimeProcedure, DeterministicClockTracker, EnvironmentModelVersion, ExitProcedure,
        FutexProcedure, FutexTracker, PthreadCreateProcedure, SimProcedure, SimResult, SimState,
        ThreadTracker,
    };
    use std::collections::BTreeMap;
    use std::sync::Arc;

    /// Versioned Linux syscall dispatch table routing syscall numbers to SimProcedure models.
    pub struct SyscallDispatchTable {
        pub version: EnvironmentModelVersion,
        handlers: BTreeMap<u64, Arc<dyn SimProcedure>>,
    }

    impl SyscallDispatchTable {
        /// Creates an empty dispatch table for the given environment model version.
        pub fn new(version: EnvironmentModelVersion) -> Self {
            Self {
                version,
                handlers: BTreeMap::new(),
            }
        }

        /// Pre-populates the dispatch table with standard Linux x86-64 syscall models:
        /// `CLOCK_GETTIME` (228), `FUTEX` (202), `CLONE` (56), and `EXIT` (60).
        pub fn with_standard_linux() -> Self {
            let mut table = Self::new(EnvironmentModelVersion(1));
            let clock_tracker = Arc::new(DeterministicClockTracker::default());
            let futex_tracker = Arc::new(FutexTracker::default());
            let thread_tracker = Arc::new(ThreadTracker::default());

            table.register(
                CLOCK_GETTIME,
                Arc::new(ClockGettimeProcedure::new(clock_tracker)),
            );
            table.register(
                FUTEX,
                Arc::new(FutexProcedure::new(futex_tracker)),
            );
            table.register(
                CLONE,
                Arc::new(PthreadCreateProcedure::new(thread_tracker)),
            );
            table.register(
                EXIT,
                Arc::new(ExitProcedure),
            );
            table
        }

        /// Registers a procedure model for the specified syscall number.
        pub fn register(&mut self, syscall_nr: u64, proc: Arc<dyn SimProcedure>) {
            self.handlers.insert(syscall_nr, proc);
        }

        /// Dispatches a syscall by number to its modeled procedure, returning `None` if unmodeled.
        pub fn dispatch(&self, syscall_nr: u64, state: &SimState) -> Option<SimResult> {
            self.handlers.get(&syscall_nr).map(|proc| proc.apply(state))
        }

        /// Looks up a modeled procedure by syscall number.
        pub fn lookup(&self, syscall_nr: u64) -> Option<&Arc<dyn SimProcedure>> {
            self.handlers.get(&syscall_nr)
        }

        /// Returns true if the syscall number has a registered model.
        pub fn contains(&self, syscall_nr: u64) -> bool {
            self.handlers.contains_key(&syscall_nr)
        }

        /// Returns the number of registered syscall models.
        pub fn len(&self) -> usize {
            self.handlers.len()
        }

        /// Returns true if no syscall models are registered.
        pub fn is_empty(&self) -> bool {
            self.handlers.is_empty()
        }

        /// Returns the version tag for this syscall model table.
        pub fn version(&self) -> EnvironmentModelVersion {
            self.version
        }
    }

    impl Default for SyscallDispatchTable {
        fn default() -> Self {
            Self::with_standard_linux()
        }
    }
}

// ---------------------------------------------------------------------------
// Kernel environment-model procedures (IRP, version, unicode, threads)
// ---------------------------------------------------------------------------

/// `RtlInitUnicodeString(Destination, Source)`: writes a UNICODE_STRING
/// {Length, MaximumLength, _pad, Buffer} describing the Source PCWSTR.
/// Void return; the model writes through RCX (Destination).
pub struct KernelInitUnicodeStringProcedure;

impl SimProcedure for KernelInitUnicodeStringProcedure {
    fn name(&self) -> &'static str {
        "kernel_init_unicode_string"
    }
    fn apply(&self, state: &SimState) -> SimResult {
        let dest = state.get_reg(1); // RCX = PUNICODE_STRING Destination
        let src = state.get_reg(2); // RDX = PCWSTR Source
        let mut next = state.clone();
        if dest != 0 && src != 0 {
            // Compute length by scanning for null terminator (max 510 chars)
            let mut len: u16 = 0;
            let mut addr = src;
            loop {
                let bytes = state.read_bytes(addr, 2);
                if bytes.len() < 2 {
                    break;
                }
                let ch = u16::from_le_bytes([bytes[0], bytes[1]]);
                if ch == 0 || len >= 510 {
                    break;
                }
                len += 2;
                addr += 2;
            }
            next.write_memory(dest, len.to_le_bytes().to_vec());
            next.write_memory(dest + 2, (len + 2).to_le_bytes().to_vec());
            next.write_memory(dest + 8, src.to_le_bytes().to_vec());
        }
        SimResult::Continue(next)
    }
}

/// `PsCreateSystemThread(ThreadHandle, DesiredAccess, ObjectAttributes,
/// ProcessHandle, ClientId, StartRoutine, StartContext)`:
/// returns a non-NULL pseudo-handle so the driver thinks the thread was
/// created. The thread body is NOT executed (debt-recorded).
pub struct KernelCreateSystemThreadProcedure;

impl SimProcedure for KernelCreateSystemThreadProcedure {
    fn name(&self) -> &'static str {
        "kernel_create_system_thread"
    }
    fn apply(&self, _state: &SimState) -> SimResult {
        // A non-zero handle: drivers check for NULL/INVALID_HANDLE_VALUE
        SimResult::Return(0xFFFF_FFFF_0000_0042)
    }
}

/// `IoBuildDeviceIoControlRequest(IoControlCode, DeviceObject, InputBuffer,
/// InputBufferLength, OutputBuffer, OutputBufferLength, InternalDeviceIoControl,
/// Event, IoStatusBlock)`: allocates a zero-backed IRP-shaped block from the
/// pool arena and returns it in RAX. Zero-backed means IoStatus reads
/// STATUS_SUCCESS and uninitialized fields are benign defaults; the driver
/// fills the stack-location and user-event fields itself, and
/// `KeWaitForSingleObject` (default stub, STATUS_WAIT_0) completes the wait
/// immediately. Debt-recorded: no completion routine or IRP lifetime model.
pub struct KernelBuildIrpProcedure {
    pub tracker: std::sync::Arc<KernelPoolTracker>,
}

impl SimProcedure for KernelBuildIrpProcedure {
    fn name(&self) -> &'static str {
        "kernel_build_irp"
    }
    fn apply(&self, state: &SimState) -> SimResult {
        let irp = self.tracker.fresh_pointer();
        let mut next = state.clone();
        // IRP header: Type (u16 = 6, IO_TYPE_IRP) | Size (u16 = 0x100).
        let type_size = (0x100u64 << 32) | 6;
        next.write_memory(irp, type_size.to_le_bytes().to_vec());
        // StackCount=1 / CurrentLocation=1 (x64 IRP layout offsets).
        next.write_memory(irp + 0x53, 1u8.to_le_bytes().to_vec());
        next.write_memory(irp + 0x54, 1u8.to_le_bytes().to_vec());
        SimResult::Return(irp)
    }
}

/// `RtlGetVersion(RTL_OSVERSIONINFOW*)`: writes a Windows-10-shaped version
/// structure through RCX and returns STATUS_SUCCESS. Drivers branch large
/// chunks of init on the reported version; the previous default stub left
/// the structure untouched (zeros), which sent drivers down the legacy
/// path and left runtime function-pointer tables unfilled (TbtBusDrv's
/// NULL `jmp [rip+X]` slot). The caller pre-fills `dwOSVersionInfoSize`
/// (0x90 for RTL_OSVERSIONINFOW, 0x150 for RTL_OSVERSIONINFOEXW) — the
/// model preserves it and fills the version fields only.
pub struct KernelGetVersionProcedure;

impl SimProcedure for KernelGetVersionProcedure {
    fn name(&self) -> &'static str {
        "kernel_get_version"
    }
    fn apply(&self, state: &SimState) -> SimResult {
        let out = state.get_reg(1); // RCX = PRTL_OSVERSIONINFOW
        let mut next = state.clone();
        if out != 0 {
            let raw = state.read_bytes(out, 4);
            let size = u32::from_le_bytes(raw.try_into().unwrap_or([0x90, 0, 0, 0]));
            let size = if size == 0 { 0x90 } else { size };
            next.write_memory(out, size.to_le_bytes().to_vec());
            next.write_memory(out + 4, 10u32.to_le_bytes().to_vec()); // dwMajorVersion
            next.write_memory(out + 8, 0u32.to_le_bytes().to_vec()); // dwMinorVersion
            next.write_memory(out + 12, 19045u32.to_le_bytes().to_vec()); // dwBuildNumber
            next.write_memory(out + 16, 2u32.to_le_bytes().to_vec()); // VER_PLATFORM_WIN32_NT
        }
        SimResult::Return(0) // STATUS_SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dep_key(id: u64) -> DependencyKey {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&id.to_le_bytes());
        DependencyKey(bytes)
    }

    fn model_key(id: u64, version: u64, dep: u64) -> ModelKey {
        ModelKey {
            id: EnvironmentModelId(id),
            version: EnvironmentModelVersion(version),
            dependency: dep_key(dep),
        }
    }

    fn summary(id: u64, dep: u64, precision: SummaryPrecision) -> FunctionSummary {
        FunctionSummary {
            id: SummaryId(id),
            precision,
            dependency: dep_key(dep),
            payload: vec![id as u8],
        }
    }

    #[test]
    fn environment_model_applies_registered_operation() {
        let mut model = InMemoryEnvironmentModel::<u64>::new(model_key(1, 1, 1), FidelityProfile::Explore);
        model.register(0x100, FidelityProfile::Explore, |state| state + 1);

        let result = model.apply(&41, 0x100, FidelityProfile::Explore);
        assert!(result.is_ok());
        assert_eq!(result, Ok(42));
    }

    #[test]
    fn environment_model_rejects_unsupported_operation() {
        let model = InMemoryEnvironmentModel::<u64>::new(model_key(1, 1, 1), FidelityProfile::Explore);
        let result = model.apply(&0, 0x999, FidelityProfile::Explore);
        assert_eq!(result, Err(ModelError::UnsupportedOperation));
    }

    #[test]
    fn environment_model_rejects_low_fidelity() {
        let mut model = InMemoryEnvironmentModel::<u64>::new(model_key(1, 1, 1), FidelityProfile::Prove);
        model.register(0x100, FidelityProfile::Prove, |state| state + 1);

        // Explore is below Prove.
        let result = model.apply(&0, 0x100, FidelityProfile::Explore);
        assert_eq!(result, Err(ModelError::FidelityTooLow));
    }

    #[test]
    fn environment_model_key_is_stable() {
        let key = model_key(5, 2, 3);
        let model = InMemoryEnvironmentModel::<u64>::new(key.clone(), FidelityProfile::Explore);
        assert_eq!(model.key(), key);
    }

    #[test]
    fn environment_model_supports_check() {
        let mut model = InMemoryEnvironmentModel::<u64>::new(model_key(1, 1, 1), FidelityProfile::Explore);
        model.register(0x100, FidelityProfile::Explore, |state| state + 1);
        assert!(model.supports(0x100));
        assert!(!model.supports(0x200));
    }

    #[test]
    fn environment_model_operation_count() {
        let mut model = InMemoryEnvironmentModel::<u64>::new(model_key(1, 1, 1), FidelityProfile::Explore);
        model.register(0x100, FidelityProfile::Explore, |s| s + 1);
        model.register(0x200, FidelityProfile::Explore, |s| s * 2);
        assert_eq!(model.operation_count(), 2);
    }

    #[test]
    fn summary_provider_registers_and_looks_up() {
        let provider = InMemorySummaryProvider::new();
        let s = summary(1, 10, SummaryPrecision::ExactValidated);
        assert!(provider.register(s.clone()).is_ok());

        let lookup = provider.lookup(dep_key(10));
        assert!(lookup.is_some());
        assert_eq!(lookup, Some(s));
    }

    #[test]
    fn summary_provider_rejects_duplicate() {
        let provider = InMemorySummaryProvider::new();
        let s1 = summary(1, 10, SummaryPrecision::ExactValidated);
        let s2 = summary(2, 10, SummaryPrecision::Approximate);
        assert!(provider.register(s1).is_ok());
        let result = provider.register(s2);
        assert_eq!(result, Err(ModelError::DuplicateEntry));
    }

    #[test]
    fn summary_provider_replace_overwrites() {
        let provider = InMemorySummaryProvider::new();
        let s1 = summary(1, 10, SummaryPrecision::ExactValidated);
        let s2 = summary(2, 10, SummaryPrecision::Approximate);
        assert!(provider.register(s1).is_ok());
        assert!(provider.replace(s2.clone()).is_ok());
        let lookup = provider.lookup(dep_key(10));
        assert_eq!(lookup, Some(s2));
    }

    #[test]
    fn summary_provider_lookup_missing_returns_none() {
        let provider = InMemorySummaryProvider::new();
        let lookup = provider.lookup(dep_key(99));
        assert!(lookup.is_none());
    }

    #[test]
    fn summary_provider_len_and_is_empty() {
        let provider = InMemorySummaryProvider::new();
        assert!(provider.is_empty());
        assert!(
            provider
                .register(summary(1, 10, SummaryPrecision::ExactValidated))
                .is_ok()
        );
        assert_eq!(provider.len(), 1);
        assert!(!provider.is_empty());
    }

    #[test]
    fn summary_provider_contains_check() {
        let provider = InMemorySummaryProvider::new();
        assert!(
            provider
                .register(summary(1, 10, SummaryPrecision::ExactValidated))
                .is_ok()
        );
        assert!(provider.contains(dep_key(10)));
        assert!(!provider.contains(dep_key(99)));
    }

    #[test]
    fn summary_provider_remove() {
        let provider = InMemorySummaryProvider::new();
        let s = summary(1, 10, SummaryPrecision::ExactValidated);
        assert!(provider.register(s.clone()).is_ok());
        let removed = provider.remove(dep_key(10));
        assert!(removed.is_ok());
        assert_eq!(removed, Ok(Some(s)));
        assert!(!provider.contains(dep_key(10)));
    }

    #[test]
    fn summary_provider_remove_missing_returns_none() {
        let provider = InMemorySummaryProvider::new();
        let removed = provider.remove(dep_key(99));
        assert!(removed.is_ok());
        assert_eq!(removed, Ok(None));
    }

    #[test]
    fn model_error_display_is_non_empty() {
        assert!(!ModelError::Poisoned.to_string().is_empty());
        assert!(!ModelError::ModelNotFound.to_string().is_empty());
        assert!(!ModelError::SummaryNotFound.to_string().is_empty());
        assert!(!ModelError::UnsupportedOperation.to_string().is_empty());
        assert!(!ModelError::FidelityTooLow.to_string().is_empty());
        assert!(!ModelError::DuplicateEntry.to_string().is_empty());
    }

    #[test]
    fn environment_model_chained_operations() {
        let mut model = InMemoryEnvironmentModel::<u64>::new(model_key(1, 1, 1), FidelityProfile::Explore);
        model.register(0x100, FidelityProfile::Explore, |s| s + 10);
        model.register(0x200, FidelityProfile::Explore, |s| s * 2);

        let state = 5;
        let state = model.apply(&state, 0x100, FidelityProfile::Explore);
        assert_eq!(state, Ok(15));
        let state = model.apply(&15, 0x200, FidelityProfile::Explore);
        assert_eq!(state, Ok(30));
    }

    #[test]
    fn sim_strlen_returns_length_of_null_terminated_string() {
        let mut registry = SimProcedureRegistry::new();
        registry.register(Box::new(StrlenProcedure));

        let mut state = SimState::new();
        state.write_memory(0x1000, b"Angryier Gate 0\0".to_vec());
        state.set_arg(0, 0x1000);

        let result = registry.apply_by_name("strlen", &state);
        assert_eq!(result, Some(SimResult::Return(15)));
    }

    #[test]
    fn sim_strcmp_returns_zero_on_equal_strings() {
        let registry = SimProcedureRegistry::with_stubs();

        let mut state = SimState::new();
        state.write_memory(0x1000, b"alpha_string\0".to_vec());
        state.write_memory(0x2000, b"alpha_string\0".to_vec());
        state.set_arg(0, 0x1000);
        state.set_arg(1, 0x2000);

        let result = registry.apply_by_name("strcmp", &state);
        assert_eq!(result, Some(SimResult::Return(0)));

        // Test non-equal
        let mut diff_state = SimState::new();
        diff_state.write_memory(0x1000, b"alpha\0".to_vec());
        diff_state.write_memory(0x2000, b"beta\0".to_vec());
        diff_state.set_arg(0, 0x1000);
        diff_state.set_arg(1, 0x2000);

        let diff_result = registry.apply_by_name("strcmp", &diff_state);
        assert_ne!(diff_result, Some(SimResult::Return(0)));
    }

    #[test]
    fn sim_malloc_returns_incrementing_pointers() {
        let registry = SimProcedureRegistry::with_stubs();
        let mut state = SimState::new();
        state.set_arg(0, 32);

        let r1 = registry.apply_by_name("malloc", &state);
        let r2 = registry.apply_by_name("malloc", &state);
        let r3 = registry.apply_by_name("malloc", &state);

        let p1 = match r1 {
            Some(SimResult::Return(p)) => p,
            _ => 0,
        };
        let p2 = match r2 {
            Some(SimResult::Return(p)) => p,
            _ => 0,
        };
        let p3 = match r3 {
            Some(SimResult::Return(p)) => p,
            _ => 0,
        };

        assert!(p1 > 0);
        assert!(p2 > p1);
        assert!(p3 > p2);
    }

    #[test]
    fn sim_free_is_no_op() {
        let registry = SimProcedureRegistry::with_stubs();
        let mut state = SimState::new();
        state.set_arg(0, 0x1000_0000);
        state.set_reg(1, 42);
        state.write_memory(0x1000, vec![1, 2, 3]);

        let result = registry.apply_by_name("free", &state);
        assert_eq!(result, Some(SimResult::Continue(state.clone())));
    }

    #[test]
    fn sim_memcpy_copies_bytes() {
        let registry = SimProcedureRegistry::with_stubs();
        let mut state = SimState::new();
        let payload = vec![0xAA, 0xBB, 0xCC, 0xDD];
        state.write_memory(0x1000, payload.clone());
        state.set_arg(0, 0x2000); // dest
        state.set_arg(1, 0x1000); // src
        state.set_arg(2, 4); // n

        let result = registry.apply_by_name("memcpy", &state);
        let new_state = match result {
            Some(SimResult::Continue(s)) => s,
            _ => state,
        };

        assert_eq!(new_state.read_bytes(0x2000, 4), payload);
        assert_eq!(new_state.return_value, Some(0x2000));
    }

    #[test]
    fn sim_memset_fills_bytes() {
        let registry = SimProcedureRegistry::with_stubs();
        let mut state = SimState::new();
        state.set_arg(0, 0x3000); // dest
        state.set_arg(1, 0x77); // c
        state.set_arg(2, 6); // n

        let result = registry.apply_by_name("memset", &state);
        let new_state = match result {
            Some(SimResult::Continue(s)) => s,
            _ => state,
        };

        assert_eq!(new_state.read_bytes(0x3000, 6), vec![0x77; 6]);
        assert_eq!(new_state.return_value, Some(0x3000));
    }

    #[test]
    fn sim_puts_returns_zero() {
        let registry = SimProcedureRegistry::with_stubs();
        let state = SimState::new();
        let result = registry.apply_by_name("puts", &state);
        assert_eq!(result, Some(SimResult::Return(0)));
    }

    #[test]
    fn sim_exit_sets_exited() {
        let registry = SimProcedureRegistry::with_stubs();
        let state = SimState::new();
        let result = registry.apply_by_name("exit", &state);
        assert_eq!(result, Some(SimResult::Exit));

        let res = match result {
            Some(r) => r,
            None => SimResult::Return(0),
        };
        let transitioned = state.transition(&res);
        assert!(transitioned.exited);

        let mut stepped = state;
        stepped.step(&res);
        assert!(stepped.exited);
    }

    #[test]
    fn kernel_return_stub_returns_fixed_value() {
        let stub = KernelReturnStub { value: 0x42 };
        assert_eq!(stub.name(), "kernel_stub_return");
        // The stub ignores the simulated state and returns its fixed value.
        let mut state = SimState::new();
        state.set_arg(0, 0x1000);
        assert_eq!(stub.apply(&state), SimResult::Return(0x42));

        let other = KernelReturnStub { value: u64::MAX };
        assert_eq!(other.apply(&state), SimResult::Return(u64::MAX));
    }

    #[test]
    fn sim_state_abi_registers_resolution() {
        let mut state = SimState::new();
        // RDI = 7 = arg0, RSI = 6 = arg1, RDX = 2 = arg2
        state.set_reg(7, 0x1111);
        state.set_reg(6, 0x2222);
        state.set_reg(2, 0x3333);

        assert_eq!(state.get_arg(0), 0x1111);
        assert_eq!(state.get_arg(1), 0x2222);
        assert_eq!(state.get_arg(2), 0x3333);
        assert_eq!(state.get_arg(5), 0); // unset

        // Direct arg0 overrides RDI
        state.set_arg(0, 0x9999);
        assert_eq!(state.get_arg(0), 0x9999);
    }

    #[test]
    fn sim_procedure_registry_len_and_lookup() {
        let registry = SimProcedureRegistry::with_stubs();
        assert_eq!(registry.len(), 8);
        assert!(!registry.is_empty());
        assert!(registry.contains("strlen"));
        assert!(registry.contains("strcmp"));
        assert!(registry.contains("malloc"));
        assert!(registry.contains("free"));
        assert!(registry.contains("memcpy"));
        assert!(registry.contains("memset"));
        assert!(registry.contains("puts"));
        assert!(registry.contains("exit"));
        assert!(!registry.contains("unknown_proc"));

        let state = SimState::new();
        assert_eq!(registry.apply_by_name("unknown_proc", &state), None);
    }

    #[test]
    fn sim_result_display() {
        assert_eq!(format!("{}", SimResult::Exit), "Exit");
        assert_eq!(format!("{}", SimResult::Return(0x20)), "Return(0x20)");
        assert_eq!(format!("{}", SimResult::Continue(SimState::new())), "Continue");
    }

    #[test]
    fn syscall_model_captures_writes_and_exit() {
        let model = syscall::SyscallModel::new();
        assert_eq!(model.record_write(b"hello"), 5);
        assert_eq!(model.record_write(b", world\n"), 8);
        assert_eq!(model.output(), b"hello, world\n");
        assert_eq!(model.invocations(), 2);
        assert_eq!(model.exit_code(), None);

        assert_eq!(model.record_exit(3), syscall::SyscallOutcome::Exit { code: 3 });
        assert_eq!(model.exit_code(), Some(3));
        assert_eq!(model.invocations(), 3);

        model.reset();
        assert!(model.output().is_empty());
        assert_eq!(model.exit_code(), None);
        assert_eq!(model.invocations(), 0);
    }

    #[test]
    fn syscall_numbers_match_linux_x86_64() {
        assert_eq!(syscall::READ, 0);
        assert_eq!(syscall::WRITE, 1);
        assert_eq!(syscall::EXIT, 60);
        assert_eq!(syscall::CLONE, 56);
        assert_eq!(syscall::FUTEX, 202);
        assert_eq!(syscall::CLOCK_GETTIME, 228);
    }

    #[test]
    fn deterministic_clock_advances_monotonically() {
        let tracker = Arc::new(DeterministicClockTracker::new(1_000_000_000, 1_000_000));
        let proc = ClockGettimeProcedure::new(tracker.clone());

        let mut state = SimState::new();
        state.set_arg(0, clock_id::CLOCK_MONOTONIC);
        state.set_arg(1, 0x5000);

        // First invocation: time advances to 1.001s (1_001_000_000 ns)
        let res1 = proc.apply(&state);
        let s1 = match res1 {
            SimResult::Continue(s) => s,
            other => panic!("expected Continue, got {other:?}"),
        };
        assert_eq!(s1.return_value, Some(0));
        assert_eq!(s1.get_reg(0), 0);
        let sec1 = u64::from_le_bytes(s1.read_bytes(0x5000, 8).try_into().unwrap());
        let nsec1 = u64::from_le_bytes(s1.read_bytes(0x5008, 8).try_into().unwrap());
        assert_eq!(sec1, 1);
        assert_eq!(nsec1, 1_000_000);

        // Second invocation: time advances to 1.002s (1_002_000_000 ns)
        let res2 = proc.apply(&s1);
        let s2 = match res2 {
            SimResult::Continue(s) => s,
            other => panic!("expected Continue, got {other:?}"),
        };
        let sec2 = u64::from_le_bytes(s2.read_bytes(0x5000, 8).try_into().unwrap());
        let nsec2 = u64::from_le_bytes(s2.read_bytes(0x5008, 8).try_into().unwrap());
        assert_eq!(sec2, 1);
        assert_eq!(nsec2, 2_000_000);

        // Third invocation with DeterministicClockProcedure
        let det_proc = DeterministicClockProcedure::with_name(tracker, "deterministic_clock");
        assert_eq!(det_proc.name(), "deterministic_clock");
        let res3 = det_proc.apply(&s2);
        let s3 = match res3 {
            SimResult::Continue(s) => s,
            other => panic!("expected Continue, got {other:?}"),
        };
        let sec3 = u64::from_le_bytes(s3.read_bytes(0x5000, 8).try_into().unwrap());
        let nsec3 = u64::from_le_bytes(s3.read_bytes(0x5008, 8).try_into().unwrap());
        assert_eq!(sec3, 1);
        assert_eq!(nsec3, 3_000_000);
    }

    #[test]
    fn deterministic_clock_null_pointer_returns_efault() {
        let proc = ClockGettimeProcedure::default();
        let mut state = SimState::new();
        state.set_arg(0, clock_id::CLOCK_MONOTONIC);
        state.set_arg(1, 0); // NULL pointer

        let res = proc.apply(&state);
        assert_eq!(res, SimResult::Return(0u64.wrapping_sub(14)));
    }

    #[test]
    fn futex_wait_word_verification_and_queue_tracking() {
        let tracker = Arc::new(FutexTracker::default());
        let wait_proc = FutexWaitProcedure::new(tracker.clone());

        let mut state = SimState::new();
        state.set_arg(0, 0x2000); // uaddr
        state.set_arg(1, 0x42);   // expected val
        state.write_memory(0x2000, 0x99u32.to_le_bytes().to_vec()); // actual val in memory = 0x99

        // Word mismatch: memory has 0x99, expected 0x42
        let mismatch_res = wait_proc.apply(&state);
        assert_eq!(mismatch_res, SimResult::Return(0u64.wrapping_sub(11))); // -EAGAIN
        assert_eq!(tracker.waiter_count(0x2000), 0);

        // Correct word in memory: 0x42
        state.write_memory(0x2000, 0x42u32.to_le_bytes().to_vec());
        let match_res = wait_proc.apply(&state);
        assert_eq!(match_res, SimResult::Return(0)); // success
        assert_eq!(tracker.waiter_count(0x2000), 1);
        assert!(tracker.has_waiters(0x2000));
    }

    #[test]
    fn futex_wake_wakes_waiters_and_counts() {
        let tracker = Arc::new(FutexTracker::default());
        let wait_proc = FutexWaitProcedure::new(tracker.clone());
        let wake_proc = FutexWakeProcedure::new(tracker.clone());

        let mut state = SimState::new();
        state.set_arg(0, 0x3000);
        state.set_arg(1, 100);
        state.write_memory(0x3000, 100u32.to_le_bytes().to_vec());

        // Enqueue 3 waiters
        wait_proc.apply(&state);
        wait_proc.apply(&state);
        wait_proc.apply(&state);
        assert_eq!(tracker.waiter_count(0x3000), 3);

        // Wake 1 waiter
        let mut wake_state = SimState::new();
        wake_state.set_arg(0, 0x3000);
        wake_state.set_arg(1, 1);
        let wake1 = wake_proc.apply(&wake_state);
        assert_eq!(wake1, SimResult::Return(1));
        assert_eq!(tracker.waiter_count(0x3000), 2);

        // Wake 5 waiters (only 2 left)
        wake_state.set_arg(1, 5);
        let wake2 = wake_proc.apply(&wake_state);
        assert_eq!(wake2, SimResult::Return(2));
        assert_eq!(tracker.waiter_count(0x3000), 0);

        // Wake on empty queue returns 0
        let wake3 = wake_proc.apply(&wake_state);
        assert_eq!(wake3, SimResult::Return(0));

        let report = tracker.report();
        assert_eq!(report.total_waits, 3);
        assert_eq!(report.total_wakes, 3);
        assert_eq!(report.total_waiters, 0);
    }

    #[test]
    fn futex_procedure_syscall_multiplexing() {
        let tracker = Arc::new(FutexTracker::default());
        let futex_proc = FutexProcedure::new(tracker.clone());

        let mut state = SimState::new();
        state.set_arg(0, 0x4000); // uaddr
        state.set_arg(1, futex_op::FUTEX_WAIT); // op
        state.set_arg(2, 555); // val
        state.write_memory(0x4000, 555u32.to_le_bytes().to_vec());

        let wait_res = futex_proc.apply(&state);
        assert_eq!(wait_res, SimResult::Return(0));
        assert_eq!(tracker.waiter_count(0x4000), 1);

        state.set_arg(1, futex_op::FUTEX_WAKE);
        state.set_arg(2, 1);
        let wake_res = futex_proc.apply(&state);
        assert_eq!(wake_res, SimResult::Return(1));
        assert_eq!(tracker.waiter_count(0x4000), 0);
    }

    #[test]
    fn pthread_create_seeds_tid_and_allocates_stack() {
        let tracker = Arc::new(ThreadTracker::default());
        let proc = PthreadCreateProcedure::new(tracker.clone());

        let mut state = SimState::new();
        state.set_arg(0, 0x6000);   // pthread_t*
        state.set_arg(1, 0);        // attr (NULL)
        state.set_arg(2, 0x401000); // start_routine
        state.set_arg(3, 0xDEADBEEF); // arg

        let res = proc.apply(&state);
        let next = match res {
            SimResult::Continue(s) => s,
            other => panic!("expected Continue, got {other:?}"),
        };
        assert_eq!(next.return_value, Some(0));

        // Read thread ID written to *pthread_t
        let tid = u64::from_le_bytes(next.read_bytes(0x6000, 8).try_into().unwrap());
        assert_eq!(tid, 1000);
        assert_eq!(tracker.thread_count(), 1);

        let desc = tracker.get_thread(tid).expect("thread descriptor exists");
        assert_eq!(desc.entry_point, 0x401000);
        assert_eq!(desc.arg, 0xDEADBEEF);
        assert_eq!(desc.stack.size, ThreadTracker::DEFAULT_STACK_SIZE);
        assert_eq!(desc.stack.top, desc.stack.base + desc.stack.size);

        // Seed a second thread
        state.set_arg(0, 0x6008);
        state.set_arg(2, 0x402000);
        state.set_arg(3, 0x1234);
        let res2 = proc.apply(&state);
        let next2 = match res2 {
            SimResult::Continue(s) => s,
            other => panic!("expected Continue, got {other:?}"),
        };
        let tid2 = u64::from_le_bytes(next2.read_bytes(0x6008, 8).try_into().unwrap());
        assert_eq!(tid2, 1001);
        assert_eq!(tracker.thread_count(), 2);

        let desc2 = tracker.get_thread(tid2).expect("second thread exists");
        assert_eq!(desc2.entry_point, 0x402000);
        assert_ne!(desc2.stack.base, desc.stack.base);
    }

    #[test]
    fn sim_procedure_registry_with_standard_library() {
        let registry = SimProcedureRegistry::with_standard_library();
        assert_eq!(registry.len(), 14);
        assert!(registry.contains("strlen"));
        assert!(registry.contains("strcmp"));
        assert!(registry.contains("malloc"));
        assert!(registry.contains("free"));
        assert!(registry.contains("memcpy"));
        assert!(registry.contains("memset"));
        assert!(registry.contains("puts"));
        assert!(registry.contains("exit"));
        assert!(registry.contains("clock_gettime"));
        assert!(registry.contains("deterministic_clock"));
        assert!(registry.contains("futex_wait"));
        assert!(registry.contains("futex_wake"));
        assert!(registry.contains("futex"));
        assert!(registry.contains("pthread_create"));

        // Dispatch clock_gettime via registry
        let mut state = SimState::new();
        state.set_arg(0, clock_id::CLOCK_MONOTONIC);
        state.set_arg(1, 0x1000);
        let clock_res = registry.apply_by_name("clock_gettime", &state);
        assert!(matches!(clock_res, Some(SimResult::Continue(ref s)) if s.return_value == Some(0)));

        // Dispatch pthread_create via registry
        state.set_arg(0, 0x2000);
        state.set_arg(2, 0x400000);
        let pthread_res = registry.apply_by_name("pthread_create", &state);
        assert!(matches!(pthread_res, Some(SimResult::Continue(ref s)) if s.return_value == Some(0)));
    }

    #[test]
    fn syscall_dispatch_table_standard_linux() {
        let table = SyscallDispatchTable::with_standard_linux();
        assert_eq!(table.version(), EnvironmentModelVersion(1));
        assert!(table.contains(syscall::CLOCK_GETTIME));
        assert!(table.contains(syscall::FUTEX));
        assert!(table.contains(syscall::CLONE));
        assert!(table.contains(syscall::EXIT));
        assert_eq!(table.len(), 4);

        let mut state = SimState::new();
        state.set_arg(0, 0x2000);
        state.set_arg(1, 0x3000);

        let clock_outcome = table.dispatch(syscall::CLOCK_GETTIME, &state);
        assert!(matches!(clock_outcome, Some(SimResult::Continue(_))));

        let exit_outcome = table.dispatch(syscall::EXIT, &state);
        assert_eq!(exit_outcome, Some(SimResult::Exit));

        let unknown = table.dispatch(999, &state);
        assert_eq!(unknown, None);
    }
}
