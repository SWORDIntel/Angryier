//! Stable A64 instruction form identifiers for Angryier-internal semantics.
//!
//! The A64 corpus uses the 0x20000 form-id space. A form distinguishes the
//! semantic shape (operation, size, flag side-effects, operand pattern), not
//! every encoding alias: `CMP` decodes to `ADDS`-with-ZR-destination forms'
//! encodings are normalized by the decoder into their base form.

pub const FORM_BASE: u32 = 0x20000;

pub const ADR: u32 = FORM_BASE + 0x01;
pub const ADRP: u32 = FORM_BASE + 0x02;

pub const B: u32 = FORM_BASE + 0x10;
pub const BL: u32 = FORM_BASE + 0x11;
pub const BR: u32 = FORM_BASE + 0x12;
pub const BLR: u32 = FORM_BASE + 0x13;
pub const RET: u32 = FORM_BASE + 0x14;
pub const B_COND_BASE: u32 = FORM_BASE + 0x20; // + cond (0..=14)
pub const CBZ_W: u32 = FORM_BASE + 0x30;
pub const CBZ_X: u32 = FORM_BASE + 0x31;
pub const CBNZ_W: u32 = FORM_BASE + 0x32;
pub const CBNZ_X: u32 = FORM_BASE + 0x33;
pub const TBZ: u32 = FORM_BASE + 0x34;
pub const TBNZ: u32 = FORM_BASE + 0x35;

pub const ADD_W_IMM: u32 = FORM_BASE + 0x40;
pub const ADD_X_IMM: u32 = FORM_BASE + 0x41;
pub const ADDS_W_IMM: u32 = FORM_BASE + 0x42;
pub const ADDS_X_IMM: u32 = FORM_BASE + 0x43;
pub const SUB_W_IMM: u32 = FORM_BASE + 0x44;
pub const SUB_X_IMM: u32 = FORM_BASE + 0x45;
pub const SUBS_W_IMM: u32 = FORM_BASE + 0x46;
pub const SUBS_X_IMM: u32 = FORM_BASE + 0x47;

pub const ADD_W_REG: u32 = FORM_BASE + 0x50;
pub const ADD_X_REG: u32 = FORM_BASE + 0x51;
pub const ADDS_W_REG: u32 = FORM_BASE + 0x52;
pub const ADDS_X_REG: u32 = FORM_BASE + 0x53;
pub const SUB_W_REG: u32 = FORM_BASE + 0x54;
pub const SUB_X_REG: u32 = FORM_BASE + 0x55;
pub const SUBS_W_REG: u32 = FORM_BASE + 0x56;
pub const SUBS_X_REG: u32 = FORM_BASE + 0x57;

pub const AND_W_IMM: u32 = FORM_BASE + 0x60;
pub const AND_X_IMM: u32 = FORM_BASE + 0x61;
pub const ORR_W_IMM: u32 = FORM_BASE + 0x62;
pub const ORR_X_IMM: u32 = FORM_BASE + 0x63;
pub const EOR_W_IMM: u32 = FORM_BASE + 0x64;
pub const EOR_X_IMM: u32 = FORM_BASE + 0x65;
pub const ANDS_W_IMM: u32 = FORM_BASE + 0x66;
pub const ANDS_X_IMM: u32 = FORM_BASE + 0x67;

pub const AND_W_REG: u32 = FORM_BASE + 0x70;
pub const AND_X_REG: u32 = FORM_BASE + 0x71;
pub const ORR_W_REG: u32 = FORM_BASE + 0x72;
pub const ORR_X_REG: u32 = FORM_BASE + 0x73;
pub const EOR_W_REG: u32 = FORM_BASE + 0x74;
pub const EOR_X_REG: u32 = FORM_BASE + 0x75;
pub const ANDS_W_REG: u32 = FORM_BASE + 0x76;
pub const ANDS_X_REG: u32 = FORM_BASE + 0x77;

pub const MOVZ_W: u32 = FORM_BASE + 0x80;
pub const MOVZ_X: u32 = FORM_BASE + 0x81;
pub const MOVN_W: u32 = FORM_BASE + 0x82;
pub const MOVN_X: u32 = FORM_BASE + 0x83;
pub const MOVK_W: u32 = FORM_BASE + 0x84;
pub const MOVK_X: u32 = FORM_BASE + 0x85;

pub const UBFM_W: u32 = FORM_BASE + 0x90;
pub const UBFM_X: u32 = FORM_BASE + 0x91;
pub const SBFM_W: u32 = FORM_BASE + 0x92;
pub const SBFM_X: u32 = FORM_BASE + 0x93;
pub const EXTR_W: u32 = FORM_BASE + 0x94;
pub const EXTR_X: u32 = FORM_BASE + 0x95;

pub const CSEL_W: u32 = FORM_BASE + 0xA0;
pub const CSEL_X: u32 = FORM_BASE + 0xA1;
pub const CSINC_W: u32 = FORM_BASE + 0xA2;
pub const CSINC_X: u32 = FORM_BASE + 0xA3;
pub const CSINV_W: u32 = FORM_BASE + 0xA4;
pub const CSINV_X: u32 = FORM_BASE + 0xA5;
pub const CSNEG_W: u32 = FORM_BASE + 0xA6;
pub const CSNEG_X: u32 = FORM_BASE + 0xA7;

pub const MADD_W: u32 = FORM_BASE + 0xB0;
pub const MADD_X: u32 = FORM_BASE + 0xB1;
pub const MSUB_W: u32 = FORM_BASE + 0xB2;
pub const MSUB_X: u32 = FORM_BASE + 0xB3;

pub const LDR_B: u32 = FORM_BASE + 0xC0;
pub const LDR_H: u32 = FORM_BASE + 0xC1;
pub const LDR_W: u32 = FORM_BASE + 0xC2;
pub const LDR_X: u32 = FORM_BASE + 0xC3;
pub const LDRSW: u32 = FORM_BASE + 0xC4;
pub const STR_B: u32 = FORM_BASE + 0xC5;
pub const STR_H: u32 = FORM_BASE + 0xC6;
pub const STR_W: u32 = FORM_BASE + 0xC7;
pub const STR_X: u32 = FORM_BASE + 0xC8;

pub const LDUR_B: u32 = FORM_BASE + 0xD0;
pub const LDUR_H: u32 = FORM_BASE + 0xD1;
pub const LDUR_W: u32 = FORM_BASE + 0xD2;
pub const LDUR_X: u32 = FORM_BASE + 0xD3;
pub const STUR_B: u32 = FORM_BASE + 0xD4;
pub const STUR_H: u32 = FORM_BASE + 0xD5;
pub const STUR_W: u32 = FORM_BASE + 0xD6;
pub const STUR_X: u32 = FORM_BASE + 0xD7;

pub const LDR_B_REG: u32 = FORM_BASE + 0xE0;
pub const LDR_H_REG: u32 = FORM_BASE + 0xE1;
pub const LDR_W_REG: u32 = FORM_BASE + 0xE2;
pub const LDR_X_REG: u32 = FORM_BASE + 0xE3;
pub const STR_B_REG: u32 = FORM_BASE + 0xE4;
pub const STR_H_REG: u32 = FORM_BASE + 0xE5;
pub const STR_W_REG: u32 = FORM_BASE + 0xE6;
pub const STR_X_REG: u32 = FORM_BASE + 0xE7;

pub const LDP_W: u32 = FORM_BASE + 0xF0;
pub const LDP_X: u32 = FORM_BASE + 0xF1;
pub const STP_W: u32 = FORM_BASE + 0xF2;
pub const STP_X: u32 = FORM_BASE + 0xF3;

pub const ADC_W: u32 = FORM_BASE + 0x103;
pub const ADC_X: u32 = FORM_BASE + 0x104;
pub const ADCS_W: u32 = FORM_BASE + 0x105;
pub const ADCS_X: u32 = FORM_BASE + 0x106;
pub const SBC_W: u32 = FORM_BASE + 0x107;
pub const SBC_X: u32 = FORM_BASE + 0x108;
pub const SBCS_W: u32 = FORM_BASE + 0x109;
pub const SBCS_X: u32 = FORM_BASE + 0x10A;
pub const CCMN_W: u32 = FORM_BASE + 0x10B;
pub const CCMN_X: u32 = FORM_BASE + 0x10C;
pub const CCMP_W: u32 = FORM_BASE + 0x10D;
pub const CCMP_X: u32 = FORM_BASE + 0x10E;

pub const UDIV_W: u32 = FORM_BASE + 0x10F;
pub const UDIV_X: u32 = FORM_BASE + 0x110;
pub const SDIV_W: u32 = FORM_BASE + 0x111;
pub const SDIV_X: u32 = FORM_BASE + 0x112;

pub const UMULL_X: u32 = FORM_BASE + 0x113;
pub const SMULL_X: u32 = FORM_BASE + 0x114;
pub const UMADDL_X: u32 = FORM_BASE + 0x115;
pub const UMSUBL_X: u32 = FORM_BASE + 0x116;
pub const SMADDL_X: u32 = FORM_BASE + 0x117;
pub const SMSUBL_X: u32 = FORM_BASE + 0x118;

pub const LDR_B_POST: u32 = FORM_BASE + 0x119;
pub const LDR_H_POST: u32 = FORM_BASE + 0x11A;
pub const LDR_W_POST: u32 = FORM_BASE + 0x11B;
pub const LDR_X_POST: u32 = FORM_BASE + 0x11C;
pub const STR_B_POST: u32 = FORM_BASE + 0x11D;
pub const STR_H_POST: u32 = FORM_BASE + 0x11E;
pub const STR_W_POST: u32 = FORM_BASE + 0x11F;
pub const STR_X_POST: u32 = FORM_BASE + 0x120;
pub const LDR_W_PRE: u32 = FORM_BASE + 0x121;
pub const LDR_X_PRE: u32 = FORM_BASE + 0x122;
pub const STR_W_PRE: u32 = FORM_BASE + 0x123;
pub const STR_X_PRE: u32 = FORM_BASE + 0x124;

pub const LDURSB_W: u32 = FORM_BASE + 0x125;
pub const LDURSB_X: u32 = FORM_BASE + 0x126;
pub const LDURSH_W: u32 = FORM_BASE + 0x127;
pub const LDURSH_X: u32 = FORM_BASE + 0x128;
pub const LDURSW: u32 = FORM_BASE + 0x129;
pub const LDPSW: u32 = FORM_BASE + 0x12A;
pub const LDR_B_PRE: u32 = FORM_BASE + 0x12B;
pub const LDR_H_PRE: u32 = FORM_BASE + 0x12C;
pub const STR_B_PRE: u32 = FORM_BASE + 0x12D;
pub const STR_H_PRE: u32 = FORM_BASE + 0x12E;

pub const NOP: u32 = FORM_BASE + 0x100;
pub const HINT: u32 = FORM_BASE + 0x101;
pub const SVC: u32 = FORM_BASE + 0x102;
