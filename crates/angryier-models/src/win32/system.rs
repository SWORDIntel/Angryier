#![forbid(unsafe_code)]

//! Win32 system information, timing, synchronization, and process control procedures.

use super::file::{Win32HandleKind, Win32HandleTable};
use crate::{SimProcedure, SimResult, SimState};

// ---------------------------------------------------------------------------
// System Information
// ---------------------------------------------------------------------------

/// `VOID GetSystemInfo(LPSYSTEM_INFO lpSystemInfo)`
pub struct GetSystemInfoProcedure;

impl SimProcedure for GetSystemInfoProcedure {
    fn name(&self) -> &'static str {
        "GetSystemInfo"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let info_ptr = state.get_win64_arg(0);
        let mut sys_info = vec![0u8; 48];

        // wProcessorArchitecture: 9 (PROCESSOR_ARCHITECTURE_AMD64)
        sys_info[0..2].copy_from_slice(&9u16.to_le_bytes());
        // dwPageSize: 4096
        sys_info[4..8].copy_from_slice(&4096u32.to_le_bytes());
        // lpMinimumApplicationAddress: 0x10000
        sys_info[8..16].copy_from_slice(&0x10000u64.to_le_bytes());
        // lpMaximumApplicationAddress: 0x7FFFFFFEFFFF
        sys_info[16..24].copy_from_slice(&0x7FFFFFFEFFFFu64.to_le_bytes());
        // dwNumberOfProcessors: 8
        sys_info[32..36].copy_from_slice(&8u32.to_le_bytes());
        // dwProcessorType: 8664 (PROCESSOR_AMD_X8664)
        sys_info[36..40].copy_from_slice(&8664u32.to_le_bytes());

        let mut next = state.clone();
        next.write_memory(info_ptr, sys_info);
        next.return_value = Some(0);
        next.set_reg(0, 0);
        SimResult::Continue(next)
    }
}

/// `VOID GetNativeSystemInfo(LPSYSTEM_INFO lpSystemInfo)`
pub struct GetNativeSystemInfoProcedure;

impl SimProcedure for GetNativeSystemInfoProcedure {
    fn name(&self) -> &'static str {
        "GetNativeSystemInfo"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        GetSystemInfoProcedure.apply(state)
    }
}

/// `BOOL GetVersionExA(LPOSVERSIONINFOA lpVersionInformation)`
pub struct GetVersionExAProcedure;

impl SimProcedure for GetVersionExAProcedure {
    fn name(&self) -> &'static str {
        "GetVersionExA"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let ver_ptr = state.get_win64_arg(0);
        let mut ver = vec![0u8; 148];

        // dwOSVersionInfoSize: 148
        ver[0..4].copy_from_slice(&148u32.to_le_bytes());
        // dwMajorVersion: 10
        ver[4..8].copy_from_slice(&10u32.to_le_bytes());
        // dwMinorVersion: 0
        ver[8..12].copy_from_slice(&0u32.to_le_bytes());
        // dwBuildNumber: 19045
        ver[12..16].copy_from_slice(&19045u32.to_le_bytes());
        // dwPlatformId: 2 (VER_PLATFORM_WIN32_NT)
        ver[16..20].copy_from_slice(&2u32.to_le_bytes());

        let mut next = state.clone();
        next.write_memory(ver_ptr, ver);
        next.return_value = Some(1); // TRUE
        next.set_reg(0, 1);
        SimResult::Continue(next)
    }
}

/// `BOOL GetVersionExW(LPOSVERSIONINFOW lpVersionInformation)`
pub struct GetVersionExWProcedure;

impl SimProcedure for GetVersionExWProcedure {
    fn name(&self) -> &'static str {
        "GetVersionExW"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let ver_ptr = state.get_win64_arg(0);
        let mut ver = vec![0u8; 276];

        ver[0..4].copy_from_slice(&276u32.to_le_bytes());
        ver[4..8].copy_from_slice(&10u32.to_le_bytes());
        ver[8..12].copy_from_slice(&0u32.to_le_bytes());
        ver[12..16].copy_from_slice(&19045u32.to_le_bytes());
        ver[16..20].copy_from_slice(&2u32.to_le_bytes());

        let mut next = state.clone();
        next.write_memory(ver_ptr, ver);
        next.return_value = Some(1);
        next.set_reg(0, 1);
        SimResult::Continue(next)
    }
}

// ---------------------------------------------------------------------------
// Process & Thread IDs
// ---------------------------------------------------------------------------

/// `HANDLE GetCurrentProcess(VOID)`
pub struct GetCurrentProcessProcedure;

impl SimProcedure for GetCurrentProcessProcedure {
    fn name(&self) -> &'static str {
        "GetCurrentProcess"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(u64::MAX) // -1 pseudo-handle
    }
}

/// `DWORD GetCurrentProcessId(VOID)`
pub struct GetCurrentProcessIdProcedure;

impl SimProcedure for GetCurrentProcessIdProcedure {
    fn name(&self) -> &'static str {
        "GetCurrentProcessId"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(4120)
    }
}

/// `HANDLE GetCurrentThread(VOID)`
pub struct GetCurrentThreadProcedure;

impl SimProcedure for GetCurrentThreadProcedure {
    fn name(&self) -> &'static str {
        "GetCurrentThread"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(u64::MAX - 1) // -2 pseudo-handle
    }
}

/// `DWORD GetCurrentThreadId(VOID)`
pub struct GetCurrentThreadIdProcedure;

impl SimProcedure for GetCurrentThreadIdProcedure {
    fn name(&self) -> &'static str {
        "GetCurrentThreadId"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(4124)
    }
}

// ---------------------------------------------------------------------------
// Time & Counters
// ---------------------------------------------------------------------------

/// `DWORD GetTickCount(VOID)`
pub struct GetTickCountProcedure;

impl SimProcedure for GetTickCountProcedure {
    fn name(&self) -> &'static str {
        "GetTickCount"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(100000)
    }
}

/// `ULONGLONG GetTickCount64(VOID)`
pub struct GetTickCount64Procedure;

impl SimProcedure for GetTickCount64Procedure {
    fn name(&self) -> &'static str {
        "GetTickCount64"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(100000)
    }
}

/// `BOOL QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount)`
pub struct QueryPerformanceCounterWin32Procedure;

impl SimProcedure for QueryPerformanceCounterWin32Procedure {
    fn name(&self) -> &'static str {
        "QueryPerformanceCounter"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let count_ptr = state.get_win64_arg(0);
        if count_ptr != 0 {
            let mut next = state.clone();
            next.write_memory(count_ptr, 10000000u64.to_le_bytes().to_vec());
            next.return_value = Some(1);
            next.set_reg(0, 1);
            SimResult::Continue(next)
        } else {
            SimResult::Return(1)
        }
    }
}

/// `BOOL QueryPerformanceFrequency(LARGE_INTEGER *lpFrequency)`
pub struct QueryPerformanceFrequencyWin32Procedure;

impl SimProcedure for QueryPerformanceFrequencyWin32Procedure {
    fn name(&self) -> &'static str {
        "QueryPerformanceFrequency"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let freq_ptr = state.get_win64_arg(0);
        if freq_ptr != 0 {
            let mut next = state.clone();
            next.write_memory(freq_ptr, 10000000u64.to_le_bytes().to_vec()); // 10 MHz
            next.return_value = Some(1);
            next.set_reg(0, 1);
            SimResult::Continue(next)
        } else {
            SimResult::Return(1)
        }
    }
}

// ---------------------------------------------------------------------------
// Error Handling
// ---------------------------------------------------------------------------

/// `DWORD GetLastError(VOID)`
pub struct GetLastErrorProcedure;

impl SimProcedure for GetLastErrorProcedure {
    fn name(&self) -> &'static str {
        "GetLastError"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0) // ERROR_SUCCESS
    }
}

/// `VOID SetLastError(DWORD dwErrCode)`
pub struct SetLastErrorProcedure;

impl SimProcedure for SetLastErrorProcedure {
    fn name(&self) -> &'static str {
        "SetLastError"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0)
    }
}

// ---------------------------------------------------------------------------
// Process Lifecycle & Sleep
// ---------------------------------------------------------------------------

/// `VOID Sleep(DWORD dwMilliseconds)`
pub struct SleepWin32Procedure;

impl SimProcedure for SleepWin32Procedure {
    fn name(&self) -> &'static str {
        "Sleep"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0)
    }
}

/// `VOID ExitProcess(UINT uExitCode)`
pub struct ExitProcessProcedure;

impl SimProcedure for ExitProcessProcedure {
    fn name(&self) -> &'static str {
        "ExitProcess"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Exit
    }
}

/// `BOOL TerminateProcess(HANDLE hProcess, UINT uExitCode)`
pub struct TerminateProcessProcedure;

impl SimProcedure for TerminateProcessProcedure {
    fn name(&self) -> &'static str {
        "TerminateProcess"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Exit
    }
}

// ---------------------------------------------------------------------------
// Synchronization & Events
// ---------------------------------------------------------------------------

/// `HANDLE CreateEventA/W(attributes, manual_reset, initial_state, name)`
/// Both variants share the same kernel-style handle tracker.
pub struct CreateEventAProcedure {
    handles: Win32HandleTable,
}
impl CreateEventAProcedure {
    pub fn new(handles: Win32HandleTable) -> Self {
        Self { handles }
    }
}
impl SimProcedure for CreateEventAProcedure {
    fn name(&self) -> &'static str {
        "CreateEventA"
    }
    fn apply(&self, state: &SimState) -> SimResult {
        let Some(manual_reset) = state.try_win64_arg(1) else {
            return SimResult::Unsupported("CreateEventA missing bManualReset");
        };
        let Some(initial_state) = state.try_win64_arg(2) else {
            return SimResult::Unsupported("CreateEventA missing bInitialState");
        };
        SimResult::Return(self.handles.alloc_handle(Win32HandleKind::Event {
            signaled: initial_state != 0,
            manual_reset: manual_reset != 0,
        }))
    }
}

pub struct CreateEventWProcedure {
    handles: Win32HandleTable,
}
impl CreateEventWProcedure {
    pub fn new(handles: Win32HandleTable) -> Self {
        Self { handles }
    }
}
impl SimProcedure for CreateEventWProcedure {
    fn name(&self) -> &'static str {
        "CreateEventW"
    }
    fn apply(&self, state: &SimState) -> SimResult {
        let Some(manual_reset) = state.try_win64_arg(1) else {
            return SimResult::Unsupported("CreateEventW missing bManualReset");
        };
        let Some(initial_state) = state.try_win64_arg(2) else {
            return SimResult::Unsupported("CreateEventW missing bInitialState");
        };
        SimResult::Return(self.handles.alloc_handle(Win32HandleKind::Event {
            signaled: initial_state != 0,
            manual_reset: manual_reset != 0,
        }))
    }
}

/// `BOOL SetEvent(HANDLE hEvent)`
pub struct SetEventProcedure {
    handles: Win32HandleTable,
}
impl SetEventProcedure {
    pub fn new(handles: Win32HandleTable) -> Self {
        Self { handles }
    }
}
impl SimProcedure for SetEventProcedure {
    fn name(&self) -> &'static str {
        "SetEvent"
    }
    fn apply(&self, state: &SimState) -> SimResult {
        match state.try_win64_arg(0) {
            Some(handle) => SimResult::Return(u64::from(self.handles.set_event_signal(handle, true))),
            None => SimResult::Unsupported("SetEvent missing event HANDLE"),
        }
    }
}

/// `BOOL ResetEvent(HANDLE hEvent)`
pub struct ResetEventProcedure {
    handles: Win32HandleTable,
}
impl ResetEventProcedure {
    pub fn new(handles: Win32HandleTable) -> Self {
        Self { handles }
    }
}
impl SimProcedure for ResetEventProcedure {
    fn name(&self) -> &'static str {
        "ResetEvent"
    }
    fn apply(&self, state: &SimState) -> SimResult {
        match state.try_win64_arg(0) {
            Some(handle) => SimResult::Return(u64::from(self.handles.set_event_signal(handle, false))),
            None => SimResult::Unsupported("ResetEvent missing event HANDLE"),
        }
    }
}

/// `DWORD WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds)`
pub struct WaitForSingleObjectProcedure {
    handles: Win32HandleTable,
}
impl WaitForSingleObjectProcedure {
    pub fn new(handles: Win32HandleTable) -> Self {
        Self { handles }
    }
}
impl SimProcedure for WaitForSingleObjectProcedure {
    fn name(&self) -> &'static str {
        "WaitForSingleObject"
    }
    fn apply(&self, state: &SimState) -> SimResult {
        let (Some(handle), Some(timeout)) = (state.try_win64_arg(0), state.try_win64_arg(1)) else {
            return SimResult::Unsupported("WaitForSingleObject missing HANDLE/timeout");
        };
        let timeout = timeout as u32;
        match self.handles.wait_event(handle) {
            super::file::Win32WaitStatus::Signaled(index) => SimResult::Return(u64::from(index)),
            super::file::Win32WaitStatus::Invalid => SimResult::Return(0xFFFF_FFFF), // WAIT_FAILED
            super::file::Win32WaitStatus::Pending if timeout == 0 => SimResult::Return(258), // WAIT_TIMEOUT
            super::file::Win32WaitStatus::Pending => SimResult::Blocked {
                handle,
                timeout_ms: timeout,
            },
        }
    }
}

/// `DWORD WaitForMultipleObjects(DWORD nCount, const HANDLE*, BOOL all, DWORD timeout)`
pub struct WaitForMultipleObjectsProcedure {
    handles: Win32HandleTable,
}
impl WaitForMultipleObjectsProcedure {
    pub fn new(handles: Win32HandleTable) -> Self {
        Self { handles }
    }
}
impl SimProcedure for WaitForMultipleObjectsProcedure {
    fn name(&self) -> &'static str {
        "WaitForMultipleObjects"
    }
    fn apply(&self, state: &SimState) -> SimResult {
        let (Some(count), Some(ptr), Some(all), Some(timeout)) = (
            state.try_win64_arg(0),
            state.try_win64_arg(1),
            state.try_win64_arg(2),
            state.try_win64_arg(3),
        ) else {
            return SimResult::Unsupported("WaitForMultipleObjects missing arguments");
        };
        if count == 0 || count > 64 {
            return SimResult::Return(0xFFFF_FFFF); // WAIT_FAILED
        }
        let Some(bytes) = state.try_read_bytes(ptr, count as usize * 8) else {
            return SimResult::Unsupported("WaitForMultipleObjects handle array not captured");
        };
        let handles: Vec<u64> = bytes
            .chunks_exact(8)
            .filter_map(|chunk| {
                let raw: [u8; 8] = chunk.try_into().ok()?;
                Some(u64::from_le_bytes(raw))
            })
            .collect();
        if handles.len() != count as usize {
            return SimResult::Unsupported("incomplete HANDLE array");
        }
        let timeout = timeout as u32;
        match self.handles.wait_events(&handles, all != 0) {
            super::file::Win32WaitStatus::Signaled(index) => SimResult::Return(u64::from(index)),
            super::file::Win32WaitStatus::Invalid => SimResult::Return(0xFFFF_FFFF),
            super::file::Win32WaitStatus::Pending if timeout == 0 => SimResult::Return(258),
            super::file::Win32WaitStatus::Pending => SimResult::Blocked {
                handle: ptr,
                timeout_ms: timeout,
            },
        }
    }
}

/// `VOID InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection)`
pub struct InitializeCriticalSectionProcedure;

impl SimProcedure for InitializeCriticalSectionProcedure {
    fn name(&self) -> &'static str {
        "InitializeCriticalSection"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0)
    }
}

/// `VOID EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection)`
pub struct EnterCriticalSectionProcedure;

impl SimProcedure for EnterCriticalSectionProcedure {
    fn name(&self) -> &'static str {
        "EnterCriticalSection"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0)
    }
}

/// `VOID LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection)`
pub struct LeaveCriticalSectionProcedure;

impl SimProcedure for LeaveCriticalSectionProcedure {
    fn name(&self) -> &'static str {
        "LeaveCriticalSection"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0)
    }
}

/// `VOID DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection)`
pub struct DeleteCriticalSectionProcedure;

impl SimProcedure for DeleteCriticalSectionProcedure {
    fn name(&self) -> &'static str {
        "DeleteCriticalSection"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0)
    }
}

// ---------------------------------------------------------------------------
// Debugging & TLS
// ---------------------------------------------------------------------------

/// `BOOL IsDebuggerPresent(VOID)`
pub struct IsDebuggerPresentProcedure;

impl SimProcedure for IsDebuggerPresentProcedure {
    fn name(&self) -> &'static str {
        "IsDebuggerPresent"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0) // FALSE
    }
}

/// `VOID OutputDebugStringA(LPCSTR lpOutputString)`
pub struct OutputDebugStringAProcedure;

impl SimProcedure for OutputDebugStringAProcedure {
    fn name(&self) -> &'static str {
        "OutputDebugStringA"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0)
    }
}

/// `VOID OutputDebugStringW(LPCWSTR lpOutputString)`
pub struct OutputDebugStringWProcedure;

impl SimProcedure for OutputDebugStringWProcedure {
    fn name(&self) -> &'static str {
        "OutputDebugStringW"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0)
    }
}

/// `DWORD TlsAlloc(VOID)`
pub struct TlsAllocProcedure;

impl SimProcedure for TlsAllocProcedure {
    fn name(&self) -> &'static str {
        "TlsAlloc"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(1)
    }
}

/// `LPVOID TlsGetValue(DWORD dwTlsIndex)`
pub struct TlsGetValueProcedure;

impl SimProcedure for TlsGetValueProcedure {
    fn name(&self) -> &'static str {
        "TlsGetValue"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0)
    }
}

/// `BOOL TlsSetValue(DWORD dwTlsIndex, LPVOID lpTlsValue)`
pub struct TlsSetValueProcedure;

impl SimProcedure for TlsSetValueProcedure {
    fn name(&self) -> &'static str {
        "TlsSetValue"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(1)
    }
}

/// `BOOL TlsFree(DWORD dwTlsIndex)`
pub struct TlsFreeProcedure;

impl SimProcedure for TlsFreeProcedure {
    fn name(&self) -> &'static str {
        "TlsFree"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(1)
    }
}
