//! Form-id range for the variable-shift extension group (LSLV/LSRV/ASRV/RORV).
//! Owned by a parallel work stream.

use crate::forms::FORM_BASE;

pub const LSLV_W: u32 = FORM_BASE + 0x130;
pub const LSLV_X: u32 = FORM_BASE + 0x131;
pub const LSRV_W: u32 = FORM_BASE + 0x132;
pub const LSRV_X: u32 = FORM_BASE + 0x133;
pub const ASRV_W: u32 = FORM_BASE + 0x134;
pub const ASRV_X: u32 = FORM_BASE + 0x135;
pub const RORV_W: u32 = FORM_BASE + 0x136;
pub const RORV_X: u32 = FORM_BASE + 0x137;
