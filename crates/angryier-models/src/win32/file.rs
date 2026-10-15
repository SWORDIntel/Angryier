#![forbid(unsafe_code)]

//! Win32 handle table and file subsystem simulation models.

use crate::{SimProcedure, SimResult, SimState};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// Object kind referenced by an opaque Win32 handle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Win32HandleKind {
    File { path: String, offset: u64 },
    Device { name: String },
    Event { signaled: bool, manual_reset: bool },
    RegKey { path: String },
    Process { pid: u32 },
    Thread { tid: u32 },
}

#[derive(Clone, Debug)]
pub struct Win32HandleTableState {
    pub handles: BTreeMap<u64, Win32HandleKind>,
    pub next_handle: u64,
}

impl Default for Win32HandleTableState {
    fn default() -> Self {
        Self {
            handles: BTreeMap::new(),
            next_handle: 0x100,
        }
    }
}

/// A nonblocking readiness probe. The runtime must schedule actual waits
/// instead of pretending all pending handles were signaled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Win32WaitStatus {
    Signaled(u32),
    Pending,
    Invalid,
}

/// Thread-safe Win32 handle registry.
#[derive(Clone, Debug, Default)]
pub struct Win32HandleTable {
    inner: Arc<Mutex<Win32HandleTableState>>,
}

impl Win32HandleTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocates a new handle for an object.
    pub fn alloc_handle(&self, kind: Win32HandleKind) -> u64 {
        let mut state = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let handle = state.next_handle;
        state.next_handle = state.next_handle.saturating_add(4);
        state.handles.insert(handle, kind);
        handle
    }

    /// Closes an existing handle.
    pub fn close_handle(&self, handle: u64) -> bool {
        let mut state = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        state.handles.remove(&handle).is_some()
    }

    /// Checks if a handle is valid.
    pub fn is_valid(&self, handle: u64) -> bool {
        let state = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        state.handles.contains_key(&handle)
    }

    /// Mutate only a real event handle. Returning false distinguishes an
    /// invalid/non-event handle from a successful Win32 API operation.
    pub fn set_event_signal(&self, handle: u64, signaled: bool) -> bool {
        let mut state = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        match state.handles.get_mut(&handle) {
            Some(Win32HandleKind::Event { signaled: value, .. }) => {
                *value = signaled;
                true
            }
            _ => false,
        }
    }

    /// Atomic try-wait on a tracked event. An auto-reset event consumes its
    /// signal when a waiter actually succeeds.
    pub fn wait_event(&self, handle: u64) -> Win32WaitStatus {
        let mut state = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        match state.handles.get_mut(&handle) {
            Some(Win32HandleKind::Event { signaled, manual_reset }) => {
                if !*signaled {
                    Win32WaitStatus::Pending
                } else {
                    if !*manual_reset {
                        *signaled = false;
                    }
                    Win32WaitStatus::Signaled(0)
                }
            }
            Some(Win32HandleKind::Thread { .. }) | Some(Win32HandleKind::Process { .. }) => {
                // Thread/process completion is not emulated yet.
                Win32WaitStatus::Pending
            }
            _ => Win32WaitStatus::Invalid,
        }
    }

    /// Windows WaitForMultipleObjects result selection. An all-wait consumes
    /// auto-reset signals only if every requested event is ready. Wait-any
    /// selects the lowest signaled index, matching Windows return indexing.
    pub fn wait_events(&self, handles: &[u64], all: bool) -> Win32WaitStatus {
        if handles.is_empty() || handles.len() > 64 {
            return Win32WaitStatus::Invalid;
        }
        let mut state = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if handles.iter().collect::<std::collections::BTreeSet<_>>().len() != handles.len() {
            return Win32WaitStatus::Invalid;
        }
        let mut ready = Vec::new();
        for (index, handle) in handles.iter().enumerate() {
            match state.handles.get(handle) {
                Some(Win32HandleKind::Event { signaled, .. }) => {
                    if *signaled {
                        ready.push(index);
                    }
                }
                Some(Win32HandleKind::Thread { .. }) | Some(Win32HandleKind::Process { .. }) => {}
                _ => return Win32WaitStatus::Invalid,
            }
        }
        if (all && ready.len() != handles.len()) || (!all && ready.is_empty()) {
            return Win32WaitStatus::Pending;
        }
        if all {
            for handle in handles {
                if let Some(Win32HandleKind::Event { signaled, manual_reset }) = state.handles.get_mut(handle)
                    && !*manual_reset
                {
                    *signaled = false;
                }
            }
            Win32WaitStatus::Signaled(0)
        } else {
            let index = ready[0];
            if let Some(Win32HandleKind::Event { signaled, manual_reset }) = state.handles.get_mut(&handles[index])
                && !*manual_reset
            {
                *signaled = false;
            }
            Win32WaitStatus::Signaled(index as u32)
        }
    }

    /// Retrieves the object kind for a handle.
    pub fn get_kind(&self, handle: u64) -> Option<Win32HandleKind> {
        let state = match self.inner.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        state.handles.get(&handle).cloned()
    }
}

// ---------------------------------------------------------------------------
// SimProcedures
// ---------------------------------------------------------------------------

/// `HANDLE CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, ...)`
pub struct CreateFileAProcedure {
    handles: Win32HandleTable,
}

impl CreateFileAProcedure {
    pub fn new(handles: Win32HandleTable) -> Self {
        Self { handles }
    }
}

impl SimProcedure for CreateFileAProcedure {
    fn name(&self) -> &'static str {
        "CreateFileA"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let name_addr = state.get_win64_arg(0);
        let bytes = state.read_null_terminated_string(name_addr, 4096);
        let path = String::from_utf8_lossy(&bytes).into_owned();

        let kind = if path.starts_with(r"\\.\") {
            Win32HandleKind::Device { name: path }
        } else {
            Win32HandleKind::File { path, offset: 0 }
        };

        let handle = self.handles.alloc_handle(kind);
        SimResult::Return(handle)
    }
}

/// `HANDLE CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, ...)`
pub struct CreateFileWProcedure {
    handles: Win32HandleTable,
}

impl CreateFileWProcedure {
    pub fn new(handles: Win32HandleTable) -> Self {
        Self { handles }
    }
}

impl SimProcedure for CreateFileWProcedure {
    fn name(&self) -> &'static str {
        "CreateFileW"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let name_addr = state.get_win64_arg(0);
        let bytes = state.read_bytes(name_addr, 512);

        // Decode UTF-16LE characters up to null terminator
        let mut u16_chars = Vec::new();
        for chunk in bytes.chunks_exact(2) {
            let ch = u16::from_le_bytes([chunk[0], chunk[1]]);
            if ch == 0 {
                break;
            }
            u16_chars.push(ch);
        }
        let path = String::from_utf16_lossy(&u16_chars);

        let kind = if path.starts_with(r"\\.\") {
            Win32HandleKind::Device { name: path }
        } else {
            Win32HandleKind::File { path, offset: 0 }
        };

        let handle = self.handles.alloc_handle(kind);
        SimResult::Return(handle)
    }
}

/// `BOOL ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)`
pub struct ReadFileProcedure {
    handles: Win32HandleTable,
}

impl ReadFileProcedure {
    pub fn new(handles: Win32HandleTable) -> Self {
        Self { handles }
    }
}

impl SimProcedure for ReadFileProcedure {
    fn name(&self) -> &'static str {
        "ReadFile"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let handle = state.get_win64_arg(0);
        let buffer = state.get_win64_arg(1);
        let count = (state.get_win64_arg(2) as usize).min(65536);
        let read_ptr = state.get_win64_arg(3);

        if !self.handles.is_valid(handle) {
            return SimResult::Return(0); // FALSE
        }

        let zeros = vec![0u8; count];
        let mut next = state.clone();
        next.write_memory(buffer, zeros);
        if read_ptr != 0 {
            next.write_memory(read_ptr, (count as u32).to_le_bytes().to_vec());
        }
        next.return_value = Some(1); // TRUE
        next.set_reg(0, 1);
        SimResult::Continue(next)
    }
}

/// `BOOL WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)`
pub struct WriteFileProcedure {
    handles: Win32HandleTable,
}

impl WriteFileProcedure {
    pub fn new(handles: Win32HandleTable) -> Self {
        Self { handles }
    }
}

impl SimProcedure for WriteFileProcedure {
    fn name(&self) -> &'static str {
        "WriteFile"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let handle = state.get_win64_arg(0);
        let count = state.get_win64_arg(2) as u32;
        let written_ptr = state.get_win64_arg(3);

        if !self.handles.is_valid(handle) {
            return SimResult::Return(0); // FALSE
        }

        if written_ptr != 0 {
            let mut next = state.clone();
            next.write_memory(written_ptr, count.to_le_bytes().to_vec());
            next.return_value = Some(1); // TRUE
            next.set_reg(0, 1);
            SimResult::Continue(next)
        } else {
            SimResult::Return(1)
        }
    }
}

/// `BOOL CloseHandle(HANDLE hObject)`
pub struct CloseHandleProcedure {
    handles: Win32HandleTable,
}

impl CloseHandleProcedure {
    pub fn new(handles: Win32HandleTable) -> Self {
        Self { handles }
    }
}

impl SimProcedure for CloseHandleProcedure {
    fn name(&self) -> &'static str {
        "CloseHandle"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let handle = state.get_win64_arg(0);
        let res = self.handles.close_handle(handle);
        SimResult::Return(if res { 1 } else { 0 })
    }
}

/// `DWORD GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh)`
pub struct GetFileSizeProcedure;

impl SimProcedure for GetFileSizeProcedure {
    fn name(&self) -> &'static str {
        "GetFileSize"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let high_ptr = state.get_win64_arg(1);
        if high_ptr != 0 {
            let mut next = state.clone();
            next.write_memory(high_ptr, 0u32.to_le_bytes().to_vec());
            next.return_value = Some(4096);
            next.set_reg(0, 4096);
            SimResult::Continue(next)
        } else {
            SimResult::Return(4096)
        }
    }
}

/// `BOOL GetFileSizeEx(HANDLE hFile, PLARGE_INTEGER lpFileSize)`
pub struct GetFileSizeExProcedure;

impl SimProcedure for GetFileSizeExProcedure {
    fn name(&self) -> &'static str {
        "GetFileSizeEx"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let size_ptr = state.get_win64_arg(1);
        if size_ptr != 0 {
            let mut next = state.clone();
            next.write_memory(size_ptr, 4096u64.to_le_bytes().to_vec());
            next.return_value = Some(1);
            next.set_reg(0, 1);
            SimResult::Continue(next)
        } else {
            SimResult::Return(1)
        }
    }
}

/// `DWORD SetFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod)`
pub struct SetFilePointerProcedure;

impl SimProcedure for SetFilePointerProcedure {
    fn name(&self) -> &'static str {
        "SetFilePointer"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let dist = state.get_win64_arg(1);
        SimResult::Return(dist)
    }
}

/// `BOOL FlushFileBuffers(HANDLE hFile)`
pub struct FlushFileBuffersProcedure;

impl SimProcedure for FlushFileBuffersProcedure {
    fn name(&self) -> &'static str {
        "FlushFileBuffers"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(1)
    }
}

/// `BOOL DeleteFileA(LPCSTR lpFileName)`
pub struct DeleteFileAProcedure;

impl SimProcedure for DeleteFileAProcedure {
    fn name(&self) -> &'static str {
        "DeleteFileA"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(1)
    }
}

/// `BOOL DeleteFileW(LPCWSTR lpFileName)`
pub struct DeleteFileWProcedure;

impl SimProcedure for DeleteFileWProcedure {
    fn name(&self) -> &'static str {
        "DeleteFileW"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(1)
    }
}

/// `DWORD GetFileAttributesA(LPCSTR lpFileName)`
pub struct GetFileAttributesAProcedure;

impl SimProcedure for GetFileAttributesAProcedure {
    fn name(&self) -> &'static str {
        "GetFileAttributesA"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0x80) // FILE_ATTRIBUTE_NORMAL
    }
}

/// `DWORD GetFileAttributesW(LPCWSTR lpFileName)`
pub struct GetFileAttributesWProcedure;

impl SimProcedure for GetFileAttributesWProcedure {
    fn name(&self) -> &'static str {
        "GetFileAttributesW"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0x80) // FILE_ATTRIBUTE_NORMAL
    }
}

/// `DWORD GetCurrentDirectoryA(DWORD nBufferLength, LPSTR lpBuffer)`
pub struct GetCurrentDirectoryAProcedure;

impl SimProcedure for GetCurrentDirectoryAProcedure {
    fn name(&self) -> &'static str {
        "GetCurrentDirectoryA"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let _len = state.get_win64_arg(0) as usize;
        let buf = state.get_win64_arg(1);
        let path = b"C:\\Windows\\System32\0";

        let mut next = state.clone();
        next.write_memory(buf, path.to_vec());
        next.return_value = Some((path.len() - 1) as u64);
        next.set_reg(0, (path.len() - 1) as u64);
        SimResult::Continue(next)
    }
}
