//! Form-id range for the FP/SIMD memory extension group. Owned by a parallel
//! work stream.

use crate::forms::FORM_BASE;

pub const LDR_S: u32 = FORM_BASE + 0x190;
pub const LDR_D: u32 = FORM_BASE + 0x191;
pub const LDR_Q: u32 = FORM_BASE + 0x192;
pub const STR_S: u32 = FORM_BASE + 0x193;
pub const STR_D: u32 = FORM_BASE + 0x194;
pub const STR_Q: u32 = FORM_BASE + 0x195;
pub const LDUR_S: u32 = FORM_BASE + 0x196;
pub const LDUR_D: u32 = FORM_BASE + 0x197;
pub const LDUR_Q: u32 = FORM_BASE + 0x198;
pub const STUR_S: u32 = FORM_BASE + 0x199;
pub const STUR_D: u32 = FORM_BASE + 0x19A;
pub const STUR_Q: u32 = FORM_BASE + 0x19B;
pub const LDR_S_LIT: u32 = FORM_BASE + 0x19C;
pub const LDR_D_LIT: u32 = FORM_BASE + 0x19D;
pub const LDR_S_REG: u32 = FORM_BASE + 0x19E;
pub const LDR_D_REG: u32 = FORM_BASE + 0x19F;
pub const LDR_Q_REG: u32 = FORM_BASE + 0x1A0;
pub const STR_S_REG: u32 = FORM_BASE + 0x1A1;
pub const STR_D_REG: u32 = FORM_BASE + 0x1A2;
pub const STR_Q_REG: u32 = FORM_BASE + 0x1A3;
pub const LDP_S: u32 = FORM_BASE + 0x1A4;
pub const LDP_D: u32 = FORM_BASE + 0x1A5;
pub const STP_S: u32 = FORM_BASE + 0x1A6;
pub const STP_D: u32 = FORM_BASE + 0x1A7;
pub const LDR_S_POST: u32 = FORM_BASE + 0x1A8;
pub const LDR_D_POST: u32 = FORM_BASE + 0x1A9;
pub const STR_S_POST: u32 = FORM_BASE + 0x1AA;
pub const STR_D_POST: u32 = FORM_BASE + 0x1AB;
pub const LDR_S_PRE: u32 = FORM_BASE + 0x1AC;
pub const LDR_D_PRE: u32 = FORM_BASE + 0x1AD;
pub const STR_S_PRE: u32 = FORM_BASE + 0x1AE;
pub const STR_D_PRE: u32 = FORM_BASE + 0x1AF;

// Second wave: Q pairs and acquire/release single-element accesses.
pub const LDP_Q: u32 = 0x20000 + 0x1B0;
pub const STP_Q: u32 = 0x20000 + 0x1B1;
pub const LDAR_B: u32 = 0x20000 + 0x1B2;
pub const LDAR_H: u32 = 0x20000 + 0x1B3;
pub const LDAR_X: u32 = 0x20000 + 0x1B4;
pub const STLR_B: u32 = 0x20000 + 0x1B5;
pub const STLR_H: u32 = 0x20000 + 0x1B6;
pub const STLR_X: u32 = 0x20000 + 0x1B7;
pub const LDAR_W: u32 = 0x20000 + 0x1B8;
pub const STLR_W: u32 = 0x20000 + 0x1B9;

// Third wave: SIMD integer/FP arithmetic (lane-wise).
pub const MOV_V: u32 = 0x20000 + 0x1C0;
pub const ADD_V16B: u32 = 0x20000 + 0x1C1;
pub const ADD_V8H: u32 = 0x20000 + 0x1C2;
pub const ADD_V4S: u32 = 0x20000 + 0x1C3;
pub const ADD_V2D: u32 = 0x20000 + 0x1C4;
pub const SUB_V16B: u32 = 0x20000 + 0x1C5;
pub const SUB_V8H: u32 = 0x20000 + 0x1C6;
pub const SUB_V4S: u32 = 0x20000 + 0x1C7;
pub const SUB_V2D: u32 = 0x20000 + 0x1C8;
pub const AND_V16B: u32 = 0x20000 + 0x1C9;
pub const ORR_V16B: u32 = 0x20000 + 0x1CA;
pub const EOR_V16B: u32 = 0x20000 + 0x1CB;
pub const FADD_V2S: u32 = 0x20000 + 0x1CC;
pub const FADD_V4S: u32 = 0x20000 + 0x1CD;
pub const FADD_V2D: u32 = 0x20000 + 0x1CE;
pub const FSUB_V4S: u32 = 0x20000 + 0x1CF;
pub const FSUB_V2D: u32 = 0x20000 + 0x1D0;
pub const FMUL_V4S: u32 = 0x20000 + 0x1D1;
pub const FMUL_V2D: u32 = 0x20000 + 0x1D2;
pub const FDIV_V4S: u32 = 0x20000 + 0x1D3;
pub const FDIV_V2D: u32 = 0x20000 + 0x1D4;

pub const DUP_ELEMENT: u32 = FORM_BASE + 0x1E0;
pub const DUP_SCALAR: u32 = FORM_BASE + 0x1E1;
pub const DUP_GPR_B: u32 = FORM_BASE + 0x1E2;
pub const DUP_GPR_H: u32 = FORM_BASE + 0x1E3;
pub const DUP_GPR_S: u32 = FORM_BASE + 0x1E4;
pub const DUP_GPR_D: u32 = FORM_BASE + 0x1E5;
