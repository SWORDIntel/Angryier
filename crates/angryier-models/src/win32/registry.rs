#![forbid(unsafe_code)]

//! Win32 registry subsystem simulation models.

use crate::{SimProcedure, SimResult, SimState};
use super::file::{Win32HandleKind, Win32HandleTable};

/// `LSTATUS RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)`
pub struct RegOpenKeyExAProcedure {
    handles: Win32HandleTable,
}

impl RegOpenKeyExAProcedure {
    pub fn new(handles: Win32HandleTable) -> Self {
        Self { handles }
    }
}

impl SimProcedure for RegOpenKeyExAProcedure {
    fn name(&self) -> &'static str {
        "RegOpenKeyExA"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let subkey_addr = state.get_win64_arg(1);
        let phk_result = state.get_win64_arg(4);

        let subkey_bytes = state.read_null_terminated_string(subkey_addr, 512);
        let subkey = String::from_utf8_lossy(&subkey_bytes).into_owned();

        let handle = self.handles.alloc_handle(Win32HandleKind::RegKey { path: subkey });

        if phk_result != 0 {
            let mut next = state.clone();
            next.write_memory(phk_result, handle.to_le_bytes().to_vec());
            next.return_value = Some(0); // ERROR_SUCCESS
            next.set_reg(0, 0);
            SimResult::Continue(next)
        } else {
            SimResult::Return(0)
        }
    }
}

/// `LSTATUS RegOpenKeyExW(HKEY hKey, LPCWSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult)`
pub struct RegOpenKeyExWProcedure {
    handles: Win32HandleTable,
}

impl RegOpenKeyExWProcedure {
    pub fn new(handles: Win32HandleTable) -> Self {
        Self { handles }
    }
}

impl SimProcedure for RegOpenKeyExWProcedure {
    fn name(&self) -> &'static str {
        "RegOpenKeyExW"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let phk_result = state.get_win64_arg(4);
        let handle = self.handles.alloc_handle(Win32HandleKind::RegKey {
            path: "<wide_reg_key>".into(),
        });

        if phk_result != 0 {
            let mut next = state.clone();
            next.write_memory(phk_result, handle.to_le_bytes().to_vec());
            next.return_value = Some(0); // ERROR_SUCCESS
            next.set_reg(0, 0);
            SimResult::Continue(next)
        } else {
            SimResult::Return(0)
        }
    }
}

/// `LSTATUS RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)`
pub struct RegQueryValueExAProcedure;

impl SimProcedure for RegQueryValueExAProcedure {
    fn name(&self) -> &'static str {
        "RegQueryValueExA"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let type_ptr = state.get_win64_arg(3);
        let data_ptr = state.get_win64_arg(4);
        let cb_data_ptr = state.get_win64_arg(5);

        let mut next = state.clone();

        // REG_DWORD = 4
        if type_ptr != 0 {
            next.write_memory(type_ptr, 4u32.to_le_bytes().to_vec());
        }
        if data_ptr != 0 {
            next.write_memory(data_ptr, 1u32.to_le_bytes().to_vec());
        }
        if cb_data_ptr != 0 {
            next.write_memory(cb_data_ptr, 4u32.to_le_bytes().to_vec());
        }

        next.return_value = Some(0); // ERROR_SUCCESS
        next.set_reg(0, 0);
        SimResult::Continue(next)
    }
}

/// `LSTATUS RegQueryValueExW(HKEY hKey, LPCWSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, LPBYTE lpData, LPDWORD lpcbData)`
pub struct RegQueryValueExWProcedure;

impl SimProcedure for RegQueryValueExWProcedure {
    fn name(&self) -> &'static str {
        "RegQueryValueExW"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let type_ptr = state.get_win64_arg(3);
        let data_ptr = state.get_win64_arg(4);
        let cb_data_ptr = state.get_win64_arg(5);

        let mut next = state.clone();

        if type_ptr != 0 {
            next.write_memory(type_ptr, 4u32.to_le_bytes().to_vec());
        }
        if data_ptr != 0 {
            next.write_memory(data_ptr, 1u32.to_le_bytes().to_vec());
        }
        if cb_data_ptr != 0 {
            next.write_memory(cb_data_ptr, 4u32.to_le_bytes().to_vec());
        }

        next.return_value = Some(0); // ERROR_SUCCESS
        next.set_reg(0, 0);
        SimResult::Continue(next)
    }
}

/// `LSTATUS RegSetValueExA(HKEY hKey, LPCSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData)`
pub struct RegSetValueExAProcedure;

impl SimProcedure for RegSetValueExAProcedure {
    fn name(&self) -> &'static str {
        "RegSetValueExA"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0) // ERROR_SUCCESS
    }
}

/// `LSTATUS RegSetValueExW(HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, const BYTE *lpData, DWORD cbData)`
pub struct RegSetValueExWProcedure;

impl SimProcedure for RegSetValueExWProcedure {
    fn name(&self) -> &'static str {
        "RegSetValueExW"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(0) // ERROR_SUCCESS
    }
}

/// `LSTATUS RegCloseKey(HKEY hKey)`
pub struct RegCloseKeyProcedure {
    handles: Win32HandleTable,
}

impl RegCloseKeyProcedure {
    pub fn new(handles: Win32HandleTable) -> Self {
        Self { handles }
    }
}

impl SimProcedure for RegCloseKeyProcedure {
    fn name(&self) -> &'static str {
        "RegCloseKey"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let h_key = state.get_win64_arg(0);
        let _ = self.handles.close_handle(h_key);
        SimResult::Return(0)
    }
}
