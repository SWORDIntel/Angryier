#![forbid(unsafe_code)]

//! Win32 VirtualAlloc and Heap simulation models.

use crate::{SimProcedure, SimResult, SimState};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// Win32 memory page allocation entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VirtualPage {
    pub base: u64,
    pub size: u64,
    pub allocation_type: u32,
    pub protect: u32,
}

#[derive(Clone, Debug)]
pub struct VirtualMemoryState {
    pub pages: BTreeMap<u64, VirtualPage>,
    pub next_virtual_addr: u64,
    pub process_heap: u64,
}

impl Default for VirtualMemoryState {
    fn default() -> Self {
        Self {
            pages: BTreeMap::new(),
            next_virtual_addr: 0x0000_0001_0000_0000, // 4GB virtual boundary
            process_heap: 0x0000_0002_0000_0000,
        }
    }
}

/// Thread-safe tracker for Win32 virtual memory allocations.
#[derive(Clone, Debug, Default)]
pub struct VirtualMemoryTracker {
    inner: Arc<Mutex<VirtualMemoryState>>,
}

impl VirtualMemoryTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocates virtual memory according to Win32 `VirtualAlloc` semantics.
    pub fn virtual_alloc(&self, lp_address: u64, dw_size: u64, fl_allocation_type: u32, fl_protect: u32) -> u64 {
        let mut state = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };

        // Align size to 4KB page boundary
        let page_size = 4096u64;
        let aligned_size = if dw_size == 0 {
            page_size
        } else {
            match dw_size.checked_add(page_size - 1) {
                Some(s) => s & !(page_size - 1),
                None => dw_size,
            }
        };

        let base = if lp_address != 0 {
            lp_address
        } else {
            let addr = state.next_virtual_addr;
            state.next_virtual_addr = state.next_virtual_addr.saturating_add(aligned_size);
            addr
        };

        state.pages.insert(
            base,
            VirtualPage {
                base,
                size: aligned_size,
                allocation_type: fl_allocation_type,
                protect: fl_protect,
            },
        );

        base
    }

    /// Frees virtual memory according to Win32 `VirtualFree` semantics.
    pub fn virtual_free(&self, lp_address: u64) -> bool {
        let mut state = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        state.pages.remove(&lp_address).is_some()
    }

    /// Modifies virtual memory protection according to Win32 `VirtualProtect`.
    pub fn virtual_protect(&self, lp_address: u64, fl_new_protect: u32) -> Option<u32> {
        let mut state = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if let Some(page) = state.pages.get_mut(&lp_address) {
            let old = page.protect;
            page.protect = fl_new_protect;
            Some(old)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// SimProcedures
// ---------------------------------------------------------------------------

/// `LPVOID VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)`
pub struct VirtualAllocProcedure {
    tracker: VirtualMemoryTracker,
}

impl VirtualAllocProcedure {
    pub fn new(tracker: VirtualMemoryTracker) -> Self {
        Self { tracker }
    }
}

impl SimProcedure for VirtualAllocProcedure {
    fn name(&self) -> &'static str {
        "VirtualAlloc"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let lp_address = state.get_win64_arg(0);
        let dw_size = state.get_win64_arg(1);
        let fl_alloc = state.get_win64_arg(2) as u32;
        let fl_protect = state.get_win64_arg(3) as u32;

        let ptr = self.tracker.virtual_alloc(lp_address, dw_size, fl_alloc, fl_protect);
        SimResult::Return(ptr)
    }
}

/// `LPVOID VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)`
pub struct VirtualAllocExProcedure {
    tracker: VirtualMemoryTracker,
}

impl VirtualAllocExProcedure {
    pub fn new(tracker: VirtualMemoryTracker) -> Self {
        Self { tracker }
    }
}

impl SimProcedure for VirtualAllocExProcedure {
    fn name(&self) -> &'static str {
        "VirtualAllocEx"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let lp_address = state.get_win64_arg(1);
        let dw_size = state.get_win64_arg(2);
        let fl_alloc = state.get_win64_arg(3) as u32;
        let fl_protect = state.get_win64_arg(4) as u32;

        let ptr = self.tracker.virtual_alloc(lp_address, dw_size, fl_alloc, fl_protect);
        SimResult::Return(ptr)
    }
}

/// `BOOL VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)`
pub struct VirtualProtectProcedure {
    tracker: VirtualMemoryTracker,
}

impl VirtualProtectProcedure {
    pub fn new(tracker: VirtualMemoryTracker) -> Self {
        Self { tracker }
    }
}

impl SimProcedure for VirtualProtectProcedure {
    fn name(&self) -> &'static str {
        "VirtualProtect"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let lp_address = state.get_win64_arg(0);
        let fl_new_protect = state.get_win64_arg(2) as u32;
        let lpfl_old_protect = state.get_win64_arg(3);

        let old = self.tracker.virtual_protect(lp_address, fl_new_protect).unwrap_or(0x04); // PAGE_READWRITE

        if lpfl_old_protect != 0 {
            let mut next = state.clone();
            next.write_memory(lpfl_old_protect, old.to_le_bytes().to_vec());
            next.return_value = Some(1); // TRUE
            next.set_reg(0, 1);
            SimResult::Continue(next)
        } else {
            SimResult::Return(1)
        }
    }
}

/// `BOOL VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)`
pub struct VirtualFreeProcedure {
    tracker: VirtualMemoryTracker,
}

impl VirtualFreeProcedure {
    pub fn new(tracker: VirtualMemoryTracker) -> Self {
        Self { tracker }
    }
}

impl SimProcedure for VirtualFreeProcedure {
    fn name(&self) -> &'static str {
        "VirtualFree"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let lp_address = state.get_win64_arg(0);
        let _ = self.tracker.virtual_free(lp_address);
        SimResult::Return(1) // TRUE
    }
}

/// `HANDLE GetProcessHeap(VOID)`
pub struct GetProcessHeapProcedure {
    tracker: VirtualMemoryTracker,
}

impl GetProcessHeapProcedure {
    pub fn new(tracker: VirtualMemoryTracker) -> Self {
        Self { tracker }
    }
}

impl SimProcedure for GetProcessHeapProcedure {
    fn name(&self) -> &'static str {
        "GetProcessHeap"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        let state = match self.tracker.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        SimResult::Return(state.process_heap)
    }
}

/// `LPVOID HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)`
pub struct HeapAllocProcedure {
    tracker: VirtualMemoryTracker,
}

impl HeapAllocProcedure {
    pub fn new(tracker: VirtualMemoryTracker) -> Self {
        Self { tracker }
    }
}

impl SimProcedure for HeapAllocProcedure {
    fn name(&self) -> &'static str {
        "HeapAlloc"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let dw_bytes = state.get_win64_arg(2);
        let ptr = self.tracker.virtual_alloc(0, dw_bytes, 0x1000, 0x04);
        SimResult::Return(ptr)
    }
}

/// `BOOL HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)`
pub struct HeapFreeProcedure {
    tracker: VirtualMemoryTracker,
}

impl HeapFreeProcedure {
    pub fn new(tracker: VirtualMemoryTracker) -> Self {
        Self { tracker }
    }
}

impl SimProcedure for HeapFreeProcedure {
    fn name(&self) -> &'static str {
        "HeapFree"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let lp_mem = state.get_win64_arg(2);
        let _ = self.tracker.virtual_free(lp_mem);
        SimResult::Return(1) // TRUE
    }
}

/// `SIZE_T HeapSize(HANDLE hHeap, DWORD dwFlags, LPCVOID lpMem)`
pub struct HeapSizeProcedure;

impl SimProcedure for HeapSizeProcedure {
    fn name(&self) -> &'static str {
        "HeapSize"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(4096)
    }
}

/// `HANDLE HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize)`
pub struct HeapCreateProcedure {
    tracker: VirtualMemoryTracker,
}

impl HeapCreateProcedure {
    pub fn new(tracker: VirtualMemoryTracker) -> Self {
        Self { tracker }
    }
}

impl SimProcedure for HeapCreateProcedure {
    fn name(&self) -> &'static str {
        "HeapCreate"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        let heap_handle = self.tracker.virtual_alloc(0, 65536, 0x1000, 0x04);
        SimResult::Return(heap_handle)
    }
}

/// `BOOL HeapDestroy(HANDLE hHeap)`
pub struct HeapDestroyProcedure {
    tracker: VirtualMemoryTracker,
}

impl HeapDestroyProcedure {
    pub fn new(tracker: VirtualMemoryTracker) -> Self {
        Self { tracker }
    }
}

impl SimProcedure for HeapDestroyProcedure {
    fn name(&self) -> &'static str {
        "HeapDestroy"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let h_heap = state.get_win64_arg(0);
        let _ = self.tracker.virtual_free(h_heap);
        SimResult::Return(1)
    }
}

/// `HGLOBAL GlobalAlloc(UINT uFlags, SIZE_T dwBytes)`
pub struct GlobalAllocProcedure {
    tracker: VirtualMemoryTracker,
}

impl GlobalAllocProcedure {
    pub fn new(tracker: VirtualMemoryTracker) -> Self {
        Self { tracker }
    }
}

impl SimProcedure for GlobalAllocProcedure {
    fn name(&self) -> &'static str {
        "GlobalAlloc"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let dw_bytes = state.get_win64_arg(1);
        let ptr = self.tracker.virtual_alloc(0, dw_bytes, 0x1000, 0x04);
        SimResult::Return(ptr)
    }
}

/// `HGLOBAL GlobalFree(HGLOBAL hMem)`
pub struct GlobalFreeProcedure {
    tracker: VirtualMemoryTracker,
}

impl GlobalFreeProcedure {
    pub fn new(tracker: VirtualMemoryTracker) -> Self {
        Self { tracker }
    }
}

impl SimProcedure for GlobalFreeProcedure {
    fn name(&self) -> &'static str {
        "GlobalFree"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let h_mem = state.get_win64_arg(0);
        let _ = self.tracker.virtual_free(h_mem);
        SimResult::Return(0) // NULL indicates success
    }
}
