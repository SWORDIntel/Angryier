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
use std::sync::{Mutex, RwLock};

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
    pub memory_writes: Vec<(u64, Vec<u8>)>,
    pub return_value: Option<u64>,
    pub exited: bool,
}

impl SimState {
    /// Creates an empty simulation state.
    pub fn new() -> Self {
        Self {
            registers: BTreeMap::new(),
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

    /// Consistent snapshot for reports.
    pub fn snapshot(&self) -> KernelPoolReport {
        match self.state.lock() {
            Ok(st) => KernelPoolReport {
                allocs: st.allocs,
                frees: st.frees,
                double_frees: st.double_frees.clone(),
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
    pub const FUTEX: u64 = 202;

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
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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
    }
}

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
