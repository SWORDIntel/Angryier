#![forbid(unsafe_code)]

//! Tracked symbolic heap manager for POSIX Libc models.
//!
//! Provides deterministic heap allocations, block tracking, and runtime
//! detection of Double-Free, Invalid-Free, and Use-After-Free (UAF) violations.

use crate::{SimProcedure, SimResult, SimState};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// A recorded allocation block within the tracked heap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeapBlock {
    pub addr: u64,
    pub size: u64,
    pub is_freed: bool,
    pub alloc_id: u64,
}

/// A heap memory safety violation detected during execution.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeapViolation {
    /// An attempt to free a block that has already been deallocated.
    DoubleFree { ptr: u64, size: u64, alloc_id: u64 },
    /// An attempt to free an unallocated or interior pointer.
    InvalidFree { ptr: u64 },
    /// Memory read/write attempted on a deallocated block.
    UseAfterFree { ptr: u64, accessed_addr: u64, size: u64 },
}

impl core::fmt::Display for HeapViolation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DoubleFree { ptr, size, alloc_id } => {
                write!(
                    f,
                    "DoubleFree: block at {ptr:#x} (size {size}, alloc #{alloc_id}) freed multiple times"
                )
            }
            Self::InvalidFree { ptr } => {
                write!(
                    f,
                    "InvalidFree: pointer {ptr:#x} was not allocated or is an interior pointer"
                )
            }
            Self::UseAfterFree {
                ptr,
                accessed_addr,
                size,
            } => {
                write!(
                    f,
                    "UseAfterFree: access at {accessed_addr:#x} within freed block {ptr:#x} (size {size})"
                )
            }
        }
    }
}

/// Inner state of the tracked heap.
#[derive(Clone, Debug)]
pub struct TrackedHeapState {
    pub blocks: BTreeMap<u64, HeapBlock>,
    pub violations: Vec<HeapViolation>,
    pub next_addr: u64,
    pub next_alloc_id: u64,
    pub current_brk: u64,
}

impl Default for TrackedHeapState {
    fn default() -> Self {
        Self {
            blocks: BTreeMap::new(),
            violations: Vec::new(),
            next_addr: 0x1000_0000,
            next_alloc_id: 1,
            current_brk: 0x4000_0000,
        }
    }
}

/// Thread-safe tracked heap with explicit safety verification.
#[derive(Clone, Debug, Default)]
pub struct TrackedHeap {
    inner: Arc<Mutex<TrackedHeapState>>,
}

impl TrackedHeap {
    /// Creates a new tracked heap with the default base address (`0x1000_0000`).
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new tracked heap with a custom base address.
    pub fn with_base(base: u64) -> Self {
        Self {
            inner: Arc::new(Mutex::new(TrackedHeapState {
                blocks: BTreeMap::new(),
                violations: Vec::new(),
                next_addr: base,
                next_alloc_id: 1,
                current_brk: 0x4000_0000,
            })),
        }
    }

    /// Allocates `size` bytes aligned to 16 bytes.
    pub fn allocate(&self, size: u64) -> u64 {
        let mut state = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };

        let alloc_size = if size == 0 {
            16
        } else {
            match size.checked_add(15) {
                Some(s) => s & !15,
                None => size,
            }
        };

        let ptr = state.next_addr;
        state.next_addr = state.next_addr.saturating_add(alloc_size);
        let id = state.next_alloc_id;
        state.next_alloc_id = state.next_alloc_id.saturating_add(1);

        state.blocks.insert(
            ptr,
            HeapBlock {
                addr: ptr,
                size: alloc_size,
                is_freed: false,
                alloc_id: id,
            },
        );

        ptr
    }

    /// Deallocates `ptr`, returning a violation if invalid or already freed.
    pub fn deallocate(&self, ptr: u64) -> Result<(), HeapViolation> {
        if ptr == 0 {
            return Ok(());
        }

        let mut state = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };

        if let Some(block) = state.blocks.get_mut(&ptr) {
            if block.is_freed {
                let violation = HeapViolation::DoubleFree {
                    ptr,
                    size: block.size,
                    alloc_id: block.alloc_id,
                };
                state.violations.push(violation.clone());
                return Err(violation);
            }
            block.is_freed = true;
            Ok(())
        } else {
            let violation = HeapViolation::InvalidFree { ptr };
            state.violations.push(violation.clone());
            Err(violation)
        }
    }

    /// Reallocates a pointer to `new_size` bytes.
    pub fn reallocate(&self, ptr: u64, new_size: u64) -> (u64, Option<u64>) {
        if ptr == 0 {
            return (self.allocate(new_size), None);
        }
        if new_size == 0 {
            let _ = self.deallocate(ptr);
            return (0, None);
        }

        let old_size = {
            let state = match self.inner.lock() {
                Ok(g) => g,
                Err(p) => p.into_inner(),
            };
            state.blocks.get(&ptr).map(|b| b.size)
        };

        let new_ptr = self.allocate(new_size);
        let _ = self.deallocate(ptr);
        (new_ptr, old_size)
    }

    /// Verifies whether `addr` falls within any previously deallocated block.
    pub fn check_use_after_free(&self, addr: u64) -> Option<HeapViolation> {
        let mut state = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };

        for block in state.blocks.values() {
            if block.is_freed && addr >= block.addr && addr < block.addr.saturating_add(block.size) {
                let violation = HeapViolation::UseAfterFree {
                    ptr: block.addr,
                    accessed_addr: addr,
                    size: block.size,
                };
                state.violations.push(violation.clone());
                return Some(violation);
            }
        }
        None
    }

    /// Returns a copy of all detected heap violations.
    pub fn violations(&self) -> Vec<HeapViolation> {
        let state = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        state.violations.clone()
    }

    /// Returns true if at least one Double-Free violation was detected.
    pub fn has_double_free(&self) -> bool {
        let state = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        state
            .violations
            .iter()
            .any(|v| matches!(v, HeapViolation::DoubleFree { .. }))
    }

    /// Clears recorded violations.
    pub fn clear_violations(&self) {
        let mut state = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        state.violations.clear();
    }
}

// ---------------------------------------------------------------------------
// SimProcedures
// ---------------------------------------------------------------------------

/// Tracked `malloc` procedure.
pub struct TrackedMallocProcedure {
    heap: TrackedHeap,
}

impl TrackedMallocProcedure {
    pub fn new(heap: TrackedHeap) -> Self {
        Self { heap }
    }
}

impl SimProcedure for TrackedMallocProcedure {
    fn name(&self) -> &'static str {
        "malloc"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let size = state.get_arg(0);
        let ptr = self.heap.allocate(size);
        SimResult::Return(ptr)
    }
}

/// Tracked `calloc` procedure: allocates zero-initialized memory.
pub struct CallocProcedure {
    heap: TrackedHeap,
}

impl CallocProcedure {
    pub fn new(heap: TrackedHeap) -> Self {
        Self { heap }
    }
}

impl SimProcedure for CallocProcedure {
    fn name(&self) -> &'static str {
        "calloc"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let nmemb = state.get_arg(0);
        let size = state.get_arg(1);
        let total = match nmemb.checked_mul(size) {
            Some(t) => t,
            None => return SimResult::Return(0),
        };

        let ptr = self.heap.allocate(total);
        let zero_len = (total as usize).min(1024 * 1024);
        let zeros = vec![0u8; zero_len];

        let mut next = state.clone();
        next.write_memory(ptr, zeros);
        next.return_value = Some(ptr);
        next.set_reg(0, ptr);
        SimResult::Continue(next)
    }
}

/// Tracked `realloc` procedure: resizes or moves a memory block.
pub struct ReallocProcedure {
    heap: TrackedHeap,
}

impl ReallocProcedure {
    pub fn new(heap: TrackedHeap) -> Self {
        Self { heap }
    }
}

impl SimProcedure for ReallocProcedure {
    fn name(&self) -> &'static str {
        "realloc"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let ptr = state.get_arg(0);
        let new_size = state.get_arg(1);

        let (new_ptr, old_size) = self.heap.reallocate(ptr, new_size);
        if new_ptr == 0 || ptr == 0 {
            return SimResult::Return(new_ptr);
        }

        let copy_len = match old_size {
            Some(s) => (s.min(new_size) as usize).min(1024 * 1024),
            None => 0,
        };

        let mut next = state.clone();
        if copy_len > 0 {
            let data = state.read_bytes(ptr, copy_len);
            next.write_memory(new_ptr, data);
        }
        next.return_value = Some(new_ptr);
        next.set_reg(0, new_ptr);
        SimResult::Continue(next)
    }
}

/// Tracked `free` procedure: records deallocation and detects double-free.
pub struct TrackedFreeProcedure {
    heap: TrackedHeap,
}

impl TrackedFreeProcedure {
    pub fn new(heap: TrackedHeap) -> Self {
        Self { heap }
    }
}

impl SimProcedure for TrackedFreeProcedure {
    fn name(&self) -> &'static str {
        "free"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let ptr = state.get_arg(0);
        let _ = self.heap.deallocate(ptr);
        SimResult::Continue(state.clone())
    }
}

/// `posix_memalign` procedure: `int posix_memalign(void **memptr, size_t alignment, size_t size)`
pub struct PosixMemalignProcedure {
    heap: TrackedHeap,
}

impl PosixMemalignProcedure {
    pub fn new(heap: TrackedHeap) -> Self {
        Self { heap }
    }
}

impl SimProcedure for PosixMemalignProcedure {
    fn name(&self) -> &'static str {
        "posix_memalign"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let memptr = state.get_arg(0);
        let alignment = state.get_arg(1);
        let size = state.get_arg(2);

        // Alignment must be a power of two and a multiple of sizeof(void *).
        if alignment < 8 || (alignment & (alignment - 1)) != 0 {
            return SimResult::Return(22); // EINVAL
        }

        let ptr = self.heap.allocate(size);
        let aligned_ptr = match ptr.checked_add(alignment - 1) {
            Some(p) => p & !(alignment - 1),
            None => ptr,
        };

        let mut next = state.clone();
        next.write_memory(memptr, aligned_ptr.to_le_bytes().to_vec());
        next.return_value = Some(0);
        next.set_reg(0, 0);
        SimResult::Continue(next)
    }
}

/// `brk` / `sbrk` procedure for heap break manipulation.
pub struct BrkProcedure {
    heap: TrackedHeap,
}

impl BrkProcedure {
    pub fn new(heap: TrackedHeap) -> Self {
        Self { heap }
    }
}

impl SimProcedure for BrkProcedure {
    fn name(&self) -> &'static str {
        "brk"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let new_brk = state.get_arg(0);
        let mut inner = match self.heap.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };

        if new_brk != 0 && new_brk >= 0x4000_0000 {
            inner.current_brk = new_brk;
            SimResult::Return(0)
        } else {
            SimResult::Return(inner.current_brk)
        }
    }
}
