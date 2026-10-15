#![forbid(unsafe_code)]

//! Win32 DeviceIoControl and asynchronous I/O simulation models.

use crate::{SimProcedure, SimResult, SimState};
use super::file::Win32HandleTable;

/// `BOOL DeviceIoControl(HANDLE hDevice, DWORD dwIoControlCode, LPVOID lpInBuffer, DWORD nInBufferSize, LPVOID lpOutBuffer, DWORD nOutBufferSize, LPDWORD lpBytesReturned, LPOVERLAPPED lpOverlapped)`
pub struct DeviceIoControlProcedure {
    handles: Win32HandleTable,
}

impl DeviceIoControlProcedure {
    pub fn new(handles: Win32HandleTable) -> Self {
        Self { handles }
    }
}

impl SimProcedure for DeviceIoControlProcedure {
    fn name(&self) -> &'static str {
        "DeviceIoControl"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let h_device = state.get_arg(0);
        let _ioctl_code = state.get_arg(1) as u32;
        let _in_buf = state.get_arg(2);
        let in_size = state.get_arg(3) as usize;
        let out_buf = state.get_arg(4);
        let out_size = (state.get_arg(5) as usize).min(65536);
        let ret_bytes_ptr = state.get_arg(6);

        if !self.handles.is_valid(h_device) {
            return SimResult::Return(0); // FALSE
        }

        let mut next = state.clone();

        // If output buffer is provided, provide deterministic zeroed response
        if out_buf != 0 && out_size > 0 {
            let resp = vec![0u8; out_size];
            next.write_memory(out_buf, resp);
        }

        // Write returned byte count
        if ret_bytes_ptr != 0 {
            let written_count = (out_size as u32).min(in_size as u32);
            next.write_memory(ret_bytes_ptr, written_count.to_le_bytes().to_vec());
        }

        next.return_value = Some(1); // TRUE
        next.set_reg(0, 1);
        SimResult::Continue(next)
    }
}

/// `BOOL GetOverlappedResult(HANDLE hFile, LPOVERLAPPED lpOverlapped, LPDWORD lpNumberOfBytesTransferred, BOOL bWait)`
pub struct GetOverlappedResultProcedure;

impl SimProcedure for GetOverlappedResultProcedure {
    fn name(&self) -> &'static str {
        "GetOverlappedResult"
    }

    fn apply(&self, state: &SimState) -> SimResult {
        let transferred_ptr = state.get_arg(2);
        if transferred_ptr != 0 {
            let mut next = state.clone();
            next.write_memory(transferred_ptr, 1024u32.to_le_bytes().to_vec());
            next.return_value = Some(1);
            next.set_reg(0, 1);
            SimResult::Continue(next)
        } else {
            SimResult::Return(1)
        }
    }
}

/// `BOOL CancelIo(HANDLE hFile)`
pub struct CancelIoProcedure;

impl SimProcedure for CancelIoProcedure {
    fn name(&self) -> &'static str {
        "CancelIo"
    }

    fn apply(&self, _state: &SimState) -> SimResult {
        SimResult::Return(1)
    }
}
