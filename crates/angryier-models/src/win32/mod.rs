#![forbid(unsafe_code)]

//! Aggregated Win32 userland API environment simulation procedures.

pub mod device;
pub mod file;
pub mod memory;
pub mod module;
pub mod registry;
pub mod system;

pub use device::{CancelIoProcedure, DeviceIoControlProcedure, GetOverlappedResultProcedure};
pub use file::{
    CloseHandleProcedure, CreateFileAProcedure, CreateFileWProcedure, DeleteFileAProcedure, DeleteFileWProcedure,
    FlushFileBuffersProcedure, GetCurrentDirectoryAProcedure, GetFileAttributesAProcedure, GetFileAttributesWProcedure,
    GetFileSizeExProcedure, GetFileSizeProcedure, ReadFileProcedure, SetFilePointerProcedure, Win32HandleKind,
    Win32HandleTable, WriteFileProcedure,
};
pub use memory::{
    GetProcessHeapProcedure, GlobalAllocProcedure, GlobalFreeProcedure, HeapAllocProcedure, HeapCreateProcedure,
    HeapDestroyProcedure, HeapFreeProcedure, HeapSizeProcedure, VirtualAllocExProcedure, VirtualAllocProcedure,
    VirtualFreeProcedure, VirtualMemoryTracker, VirtualProtectProcedure,
};
pub use module::{
    FreeLibraryProcedure, GetModuleFileNameAProcedure, GetModuleFileNameWProcedure, GetModuleHandleAProcedure,
    GetModuleHandleWProcedure, GetProcAddressProcedure, LoadLibraryAProcedure, LoadLibraryExAProcedure,
    LoadLibraryExWProcedure, LoadLibraryWProcedure,
};
pub use registry::{
    RegCloseKeyProcedure, RegOpenKeyExAProcedure, RegOpenKeyExWProcedure, RegQueryValueExAProcedure,
    RegQueryValueExWProcedure, RegSetValueExAProcedure, RegSetValueExWProcedure,
};
pub use system::{
    CreateEventAProcedure, CreateEventWProcedure, DeleteCriticalSectionProcedure, EnterCriticalSectionProcedure,
    ExitProcessProcedure, GetCurrentProcessIdProcedure, GetCurrentProcessProcedure, GetCurrentThreadIdProcedure,
    GetCurrentThreadProcedure, GetLastErrorProcedure, GetNativeSystemInfoProcedure, GetSystemInfoProcedure,
    GetTickCount64Procedure, GetTickCountProcedure, GetVersionExAProcedure, GetVersionExWProcedure,
    InitializeCriticalSectionProcedure, IsDebuggerPresentProcedure, LeaveCriticalSectionProcedure,
    OutputDebugStringAProcedure, OutputDebugStringWProcedure, QueryPerformanceCounterWin32Procedure,
    QueryPerformanceFrequencyWin32Procedure, ResetEventProcedure, SetEventProcedure, SetLastErrorProcedure,
    SleepWin32Procedure, TerminateProcessProcedure, TlsAllocProcedure, TlsFreeProcedure, TlsGetValueProcedure,
    TlsSetValueProcedure, WaitForMultipleObjectsProcedure, WaitForSingleObjectProcedure,
};

use crate::SimProcedureRegistry;

/// Registers all Win32 API models into the target procedure registry.
pub fn register_win32_procedures(
    registry: &mut SimProcedureRegistry,
    vm: VirtualMemoryTracker,
    handles: Win32HandleTable,
) {
    // Memory & Heap
    registry.register(Box::new(VirtualAllocProcedure::new(vm.clone())));
    registry.register(Box::new(VirtualAllocExProcedure::new(vm.clone())));
    registry.register(Box::new(VirtualProtectProcedure::new(vm.clone())));
    registry.register(Box::new(VirtualFreeProcedure::new(vm.clone())));
    registry.register(Box::new(GetProcessHeapProcedure::new(vm.clone())));
    registry.register(Box::new(HeapAllocProcedure::new(vm.clone())));
    registry.register(Box::new(HeapFreeProcedure::new(vm.clone())));
    registry.register(Box::new(HeapSizeProcedure));
    registry.register(Box::new(HeapCreateProcedure::new(vm.clone())));
    registry.register(Box::new(HeapDestroyProcedure::new(vm.clone())));
    registry.register(Box::new(GlobalAllocProcedure::new(vm.clone())));
    registry.register(Box::new(GlobalFreeProcedure::new(vm)));

    // File & Handles
    registry.register(Box::new(CreateFileAProcedure::new(handles.clone())));
    registry.register(Box::new(CreateFileWProcedure::new(handles.clone())));
    registry.register(Box::new(ReadFileProcedure::new(handles.clone())));
    registry.register(Box::new(WriteFileProcedure::new(handles.clone())));
    registry.register(Box::new(CloseHandleProcedure::new(handles.clone())));
    registry.register(Box::new(GetFileSizeProcedure));
    registry.register(Box::new(GetFileSizeExProcedure));
    registry.register(Box::new(SetFilePointerProcedure));
    registry.register(Box::new(FlushFileBuffersProcedure));
    registry.register(Box::new(DeleteFileAProcedure));
    registry.register(Box::new(DeleteFileWProcedure));
    registry.register(Box::new(GetFileAttributesAProcedure));
    registry.register(Box::new(GetFileAttributesWProcedure));
    registry.register(Box::new(GetCurrentDirectoryAProcedure));

    // Device IOCTL & Overlapped IO
    registry.register(Box::new(DeviceIoControlProcedure::new(handles.clone())));
    registry.register(Box::new(GetOverlappedResultProcedure));
    registry.register(Box::new(CancelIoProcedure));

    // Registry
    registry.register(Box::new(RegOpenKeyExAProcedure::new(handles.clone())));
    registry.register(Box::new(RegOpenKeyExWProcedure::new(handles.clone())));
    registry.register(Box::new(RegQueryValueExAProcedure));
    registry.register(Box::new(RegQueryValueExWProcedure));
    registry.register(Box::new(RegSetValueExAProcedure));
    registry.register(Box::new(RegSetValueExWProcedure));
    registry.register(Box::new(RegCloseKeyProcedure::new(handles.clone())));

    // System Information & Time
    registry.register(Box::new(GetSystemInfoProcedure));
    registry.register(Box::new(GetNativeSystemInfoProcedure));
    registry.register(Box::new(GetVersionExAProcedure));
    registry.register(Box::new(GetVersionExWProcedure));
    registry.register(Box::new(GetCurrentProcessProcedure));
    registry.register(Box::new(GetCurrentProcessIdProcedure));
    registry.register(Box::new(GetCurrentThreadProcedure));
    registry.register(Box::new(GetCurrentThreadIdProcedure));
    registry.register(Box::new(GetTickCountProcedure));
    registry.register(Box::new(GetTickCount64Procedure));
    registry.register(Box::new(QueryPerformanceCounterWin32Procedure));
    registry.register(Box::new(QueryPerformanceFrequencyWin32Procedure));
    registry.register(Box::new(GetLastErrorProcedure));
    registry.register(Box::new(SetLastErrorProcedure));
    registry.register(Box::new(system::SleepWin32Procedure));
    registry.register(Box::new(ExitProcessProcedure));
    registry.register(Box::new(TerminateProcessProcedure));

    // Synchronization & Events
    registry.register(Box::new(CreateEventAProcedure::new(handles.clone())));
    registry.register(Box::new(CreateEventWProcedure::new(handles.clone())));
    registry.register(Box::new(SetEventProcedure::new(handles.clone())));
    registry.register(Box::new(ResetEventProcedure::new(handles.clone())));
    registry.register(Box::new(WaitForSingleObjectProcedure::new(handles.clone())));
    registry.register(Box::new(WaitForMultipleObjectsProcedure::new(handles)));
    registry.register(Box::new(InitializeCriticalSectionProcedure));
    registry.register(Box::new(EnterCriticalSectionProcedure));
    registry.register(Box::new(LeaveCriticalSectionProcedure));
    registry.register(Box::new(DeleteCriticalSectionProcedure));

    // Debugging & TLS
    registry.register(Box::new(IsDebuggerPresentProcedure));
    registry.register(Box::new(OutputDebugStringAProcedure));
    registry.register(Box::new(OutputDebugStringWProcedure));
    registry.register(Box::new(TlsAllocProcedure));
    registry.register(Box::new(TlsGetValueProcedure));
    registry.register(Box::new(TlsSetValueProcedure));
    registry.register(Box::new(TlsFreeProcedure));

    // Dynamic Linking & Modules
    registry.register(Box::new(LoadLibraryAProcedure));
    registry.register(Box::new(LoadLibraryWProcedure));
    registry.register(Box::new(LoadLibraryExAProcedure));
    registry.register(Box::new(LoadLibraryExWProcedure));
    registry.register(Box::new(GetProcAddressProcedure));
    registry.register(Box::new(FreeLibraryProcedure));
    registry.register(Box::new(GetModuleHandleAProcedure));
    registry.register(Box::new(GetModuleHandleWProcedure));
    registry.register(Box::new(GetModuleFileNameAProcedure));
    registry.register(Box::new(GetModuleFileNameWProcedure));
}
