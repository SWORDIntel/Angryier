//! Form ids for the scalar-FP arithmetic extension group.

pub const BASE: u32 = 0x20000;

pub const FADD_S: u32 = BASE + 0x160;
pub const FADD_D: u32 = BASE + 0x161;
pub const FSUB_S: u32 = BASE + 0x162;
pub const FSUB_D: u32 = BASE + 0x163;
pub const FMUL_S: u32 = BASE + 0x164;
pub const FMUL_D: u32 = BASE + 0x165;
pub const FDIV_S: u32 = BASE + 0x166;
pub const FDIV_D: u32 = BASE + 0x167;
pub const FNEG_S: u32 = BASE + 0x168;
pub const FNEG_D: u32 = BASE + 0x169;
pub const FSQRT_S: u32 = BASE + 0x16A;
pub const FSQRT_D: u32 = BASE + 0x16B;
pub const FABS_S: u32 = BASE + 0x16C;
pub const FABS_D: u32 = BASE + 0x16D;
pub const FCMP_S: u32 = BASE + 0x16E;
pub const FCMP_D: u32 = BASE + 0x16F;

// Second wave: general<->FP bit moves.
pub const FMOV_S_W: u32 = 0x20000 + 0x170;
pub const FMOV_W_S: u32 = 0x20000 + 0x171;
pub const FMOV_D_X: u32 = 0x20000 + 0x172;
pub const FMOV_X_D: u32 = 0x20000 + 0x173;

pub const FMOV_IS: u32 = 0x20000 + 0x174;
pub const FMOV_ID: u32 = 0x20000 + 0x175;

pub const FCVT_D_S: u32 = 0x20000 + 0x176; // fcvt d0, s1
pub const FCVT_S_D: u32 = 0x20000 + 0x177; // fcvt s0, d1
pub const FCSEL_S: u32 = 0x20000 + 0x178;
pub const FCSEL_D: u32 = 0x20000 + 0x179;

pub const FCVTZS_W_S: u32 = 0x20000 + 0x17A;
pub const FCVTZS_W_D: u32 = 0x20000 + 0x17B;
pub const FCVTZS_X_S: u32 = 0x20000 + 0x17C;
pub const FCVTZS_X_D: u32 = 0x20000 + 0x17D;
pub const FCVTZU_W_S: u32 = 0x20000 + 0x17E;
pub const FCVTZU_W_D: u32 = 0x20000 + 0x17F;
pub const FCVTZU_X_S: u32 = 0x20000 + 0x180;
pub const FCVTZU_X_D: u32 = 0x20000 + 0x181;

// Signed integer -> float, no fixed-point scaling.
pub const SCVTF_S_W: u32 = BASE + 0x182;
pub const SCVTF_D_W: u32 = BASE + 0x183;
pub const SCVTF_S_X: u32 = BASE + 0x184;
pub const SCVTF_D_X: u32 = BASE + 0x185;
pub const SCVTF_S_S: u32 = BASE + 0x186;
pub const SCVTF_D_D: u32 = BASE + 0x187;
pub const SCVTF_V2S: u32 = BASE + 0x188;
pub const SCVTF_V4S: u32 = BASE + 0x189;
pub const SCVTF_V2D: u32 = BASE + 0x18A;
