#![forbid(unsafe_code)]

//! Win32 dynamic module loading and symbol resolution simulation models.

use crate::{SimProcedure, SimResult, SimState};

/// Default simulated base address for loaded DLLs (`0x7ff8_1000_0000`).
pub const DEFAULT_HMODULE_BASE: u64 = 0x7ff8_1000_0000;

/// `HMODULE LoadLibraryA(LPCSTR lpLibFileName)`
pub struct LoadLibraryAProcedure;

impl SimProcedure for LoadLibraryAProcedure {
    fn name(&self) -> &'static str {
        "LoadLibraryA"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(DEFAULT_HMODULE_BASE)
    }
}

/// `HMODULE LoadLibraryW(LPCWSTR lpLibFileName)`
pub struct LoadLibraryWProcedure;

impl SimProcedure for LoadLibraryWProcedure {
    fn name(&self) -> &'static str {
        "LoadLibraryW"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(DEFAULT_HMODULE_BASE)
    }
}

/// `HMODULE LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)`
pub struct LoadLibraryExAProcedure;

impl SimProcedure for LoadLibraryExAProcedure {
    fn name(&self) -> &'static str {
        "LoadLibraryExA"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(DEFAULT_HMODULE_BASE)
    }
}

/// `HMODULE LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)`
pub struct LoadLibraryExWProcedure;

impl SimProcedure for LoadLibraryExWProcedure {
    fn name(&self) -> &'static str {
        "LoadLibraryExW"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(DEFAULT_HMODULE_BASE)
    }
}

/// `FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName)`
pub struct GetProcAddressProcedure;

impl SimProcedure for GetProcAddressProcedure {
    fn name(&self) -> &'static str {
        "GetProcAddress"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let h_module = state.get_arg(0);
        let base = if h_module != 0 { h_module } else { DEFAULT_HMODULE_BASE };
        // Deterministic export address: base + 0x1000
        SimResult::Return(base.saturating_add(0x1000))
    }
}

/// `BOOL FreeLibrary(HMODULE hLibModule)`
pub struct FreeLibraryProcedure;

impl SimProcedure for FreeLibraryProcedure {
    fn name(&self) -> &'static str {
        "FreeLibrary"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(1) // TRUE
    }
}

/// `HMODULE GetModuleHandleA(LPCSTR lpModuleName)`
pub struct GetModuleHandleAProcedure;

impl SimProcedure for GetModuleHandleAProcedure {
    fn name(&self) -> &'static str {
        "GetModuleHandleA"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let mod_name_ptr = state.get_arg(0);
        if mod_name_ptr == 0 {
            SimResult::Return(0x140000000) // Default base of main image
        } else {
            SimResult::Return(DEFAULT_HMODULE_BASE)
        }
    }
}

/// `HMODULE GetModuleHandleW(LPCWSTR lpModuleName)`
pub struct GetModuleHandleWProcedure;

impl SimProcedure for GetModuleHandleWProcedure {
    fn name(&self) -> &'static str {
        "GetModuleHandleW"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let mod_name_ptr = state.get_arg(0);
        if mod_name_ptr == 0 {
            SimResult::Return(0x140000000)
        } else {
            SimResult::Return(DEFAULT_HMODULE_BASE)
        }
    }
}

/// `DWORD GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize)`
pub struct GetModuleFileNameAProcedure;

impl SimProcedure for GetModuleFileNameAProcedure {
    fn name(&self) -> &'static str {
        "GetModuleFileNameA"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let filename_ptr = state.get_arg(1);
        let path = b"C:\\Windows\\System32\\target.exe\0";

        let mut next = state.clone();
        next.write_memory(filename_ptr, path.to_vec());
        next.return_value = Some((path.len() - 1) as u64);
        next.set_reg(0, (path.len() - 1) as u64);
        SimResult::Continue(next)
    }
}

/// `DWORD GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize)`
pub struct GetModuleFileNameWProcedure;

impl SimProcedure for GetModuleFileNameWProcedure {
    fn name(&self) -> &'static str {
        "GetModuleFileNameW"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let filename_ptr = state.get_arg(1);
        let path_utf16: Vec<u8> = "C:\\Windows\\System32\\target.exe\0"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();

        let mut next = state.clone();
        next.write_memory(filename_ptr, path_utf16);
        next.return_value = Some(30);
        next.set_reg(0, 30);
        SimResult::Continue(next)
    }
}
