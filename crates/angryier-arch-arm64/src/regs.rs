//! AArch64 architectural register model: canonical 64/128-bit parents plus
//! zero-extending 32-bit views, matching AAPCS64 behaviour.

use angryier_arch::{RegisterId, RegisterView, RegisterWriteBehavior};

/// Canonical parent registers.
pub mod register_id {
    use angryier_arch::RegisterId;

    pub const X0: RegisterId = RegisterId(0);
    pub const X1: RegisterId = RegisterId(1);
    pub const X2: RegisterId = RegisterId(2);
    pub const X3: RegisterId = RegisterId(3);
    pub const X4: RegisterId = RegisterId(4);
    pub const X5: RegisterId = RegisterId(5);
    pub const X6: RegisterId = RegisterId(6);
    pub const X7: RegisterId = RegisterId(7);
    pub const X8: RegisterId = RegisterId(8);
    pub const X9: RegisterId = RegisterId(9);
    pub const X10: RegisterId = RegisterId(10);
    pub const X11: RegisterId = RegisterId(11);
    pub const X12: RegisterId = RegisterId(12);
    pub const X13: RegisterId = RegisterId(13);
    pub const X14: RegisterId = RegisterId(14);
    pub const X15: RegisterId = RegisterId(15);
    pub const X16: RegisterId = RegisterId(16);
    pub const X17: RegisterId = RegisterId(17);
    pub const X18: RegisterId = RegisterId(18);
    pub const X19: RegisterId = RegisterId(19);
    pub const X20: RegisterId = RegisterId(20);
    pub const X21: RegisterId = RegisterId(21);
    pub const X22: RegisterId = RegisterId(22);
    pub const X23: RegisterId = RegisterId(23);
    pub const X24: RegisterId = RegisterId(24);
    pub const X25: RegisterId = RegisterId(25);
    pub const X26: RegisterId = RegisterId(26);
    pub const X27: RegisterId = RegisterId(27);
    pub const X28: RegisterId = RegisterId(28);
    pub const X29: RegisterId = RegisterId(29);
    pub const X30: RegisterId = RegisterId(30);
    /// XZR: reads as zero; writes are discarded (SemanticDefined).
    pub const ZR: RegisterId = RegisterId(31);
    pub const PC: RegisterId = RegisterId(32);
    /// NZCV: bits 31=N, 30=Z, 29=C, 28=V; lower bits zero.
    pub const NZCV: RegisterId = RegisterId(33);
    pub const FPCR: RegisterId = RegisterId(34);
    pub const FPSR: RegisterId = RegisterId(35);
    /// First SIMD&FP parent; V0..V31 occupy ids 36..=67.
    pub const V0: RegisterId = RegisterId(36);
    /// Stack pointer: separate storage from ZR so that SP-based memory
    /// addressing works without conflating XZR semantics.
    pub const SP: RegisterId = RegisterId(68);

    pub const GPR_BASE: u32 = 0;
    pub const GPR_COUNT: u32 = 32;
    pub const V_BASE: u32 = 36;
    pub const V_COUNT: u32 = 32;

    pub fn x(n: u32) -> RegisterId {
        RegisterId(n.min(GPR_COUNT - 1))
    }
    pub fn v(n: u32) -> RegisterId {
        RegisterId(V_BASE + n.min(V_COUNT - 1))
    }
}

/// 32-bit Wn view ids: W0..W30 at 128..=158, WZR at 159.
const W_VIEW_BASE: u32 = 128;
/// Vn lane views: B at 256, H at 288, S at 320, D at 352.
const V_B_VIEW_BASE: u32 = 256;
const V_H_VIEW_BASE: u32 = 288;
const V_S_VIEW_BASE: u32 = 320;
const V_D_VIEW_BASE: u32 = 352;

/// Returns the canonical parent RegisterId owning storage for a register id.
pub fn canonical_parent(register: RegisterId) -> RegisterId {
    let raw = register.0;
    match raw {
        0..=31 => RegisterId(raw),
        32..=35 => RegisterId(raw),
        36..=67 => RegisterId(raw),
        68 => RegisterId(68),
        128..=158 => RegisterId(raw - W_VIEW_BASE),
        159 => register_id::ZR,
        256..=287 => register_id::v(raw - V_B_VIEW_BASE),
        288..=319 => register_id::v(raw - V_H_VIEW_BASE),
        320..=351 => register_id::v(raw - V_S_VIEW_BASE),
        352..=383 => register_id::v(raw - V_D_VIEW_BASE),
        _ => register,
    }
}

/// Bit width of the canonical parent register.
pub fn canonical_parent_width(register: RegisterId) -> Option<u16> {
    match canonical_parent(register).0 {
        0..=30 | 68 => Some(64),
        31 => Some(64),
        32 => Some(64),
        33..=35 => Some(32),
        36..=67 => Some(128),
        _ => None,
    }
}

/// True when the register id is a 32-bit view of a 64-bit parent.
pub fn is_w_view(register: RegisterId) -> bool {
    (128..=159).contains(&register.0)
}

/// Builds the register view for a decoded operand. `size` selects 32/64-bit
/// for GPRs (`0` = W, `1` = X); ZR/SP are special-cased by the caller.
pub fn gpr_view(n: u32, size: u32, is_sp: bool) -> RegisterView {
    if is_sp {
        return RegisterView {
            parent: register_id::SP,
            bit_offset: 0,
            width_bits: 64,
            write_behavior: RegisterWriteBehavior::ReplaceParent,
        };
    }
    if size == 0 {
        RegisterView {
            parent: RegisterId(n),
            bit_offset: 0,
            width_bits: 32,
            write_behavior: RegisterWriteBehavior::ZeroExtendParent,
        }
    } else {
        RegisterView {
            parent: RegisterId(n),
            bit_offset: 0,
            width_bits: 64,
            write_behavior: RegisterWriteBehavior::ReplaceParent,
        }
    }
}

/// Wn view (32-bit, zero-extending write).
pub fn w_view(n: u32) -> RegisterView {
    RegisterView {
        parent: RegisterId(n),
        bit_offset: 0,
        width_bits: 32,
        write_behavior: RegisterWriteBehavior::ZeroExtendParent,
    }
}

/// FP/SIMD vector view for a given element size (`0`=B, `1`=H, `2`=S, `3`=D).
pub fn v_view(n: u32, element_size: u32) -> RegisterView {
    let width_bits = match element_size {
        0 => 8,
        1 => 16,
        2 => 32,
        _ => 64,
    };
    RegisterView {
        parent: register_id::v(n),
        bit_offset: 0,
        width_bits,
        write_behavior: RegisterWriteBehavior::ZeroExtendParent,
    }
}

/// Full 128-bit Q view of Vn.
pub fn q_view(n: u32) -> RegisterView {
    RegisterView {
        parent: register_id::v(n),
        bit_offset: 0,
        width_bits: 128,
        write_behavior: RegisterWriteBehavior::ReplaceParent,
    }
}

/// Canonical register file: one 64-bit slot per GPR + ZR + PC + SP, 32-bit
/// slots for NZCV/FPCR/FPSR, 128-bit slots for V0..V31. Views share parent
/// storage and are never stored independently.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Arm64RegisterFile {
    pub gprs: [u64; 32],
    pub zr: u64,
    pub pc: u64,
    pub nzcv: u32,
    pub fpcr: u32,
    pub fpsr: u32,
    pub sp: u64,
    pub vectors: [u128; 32],
}

impl Arm64RegisterFile {
    pub fn canonical() -> Self {
        Self {
            gprs: [0; 32],
            zr: 0,
            pc: 0,
            nzcv: 0,
            fpcr: 0,
            fpsr: 0,
            sp: 0,
            vectors: [0; 32],
        }
    }

    /// Returns every canonical parent register and its width in bits, in
    /// register-id order.
    ///
    /// This is the authoritative A64 register-file shape consumed by the
    /// runtime to size the concrete register store (ANG-090); it mirrors the
    /// `Intel64RegisterFile::architectural_registers` contract. Widths match
    /// [`canonical_parent_width`]: GPRs/ZR/PC/SP are 64-bit, NZCV/FPCR/FPSR
    /// are 32-bit, and V0..V31 are 128-bit.
    pub fn architectural_registers() -> Vec<(RegisterId, u16)> {
        let mut registers = Vec::with_capacity(69);
        // X0..X30 (64-bit general-purpose registers).
        for n in 0..31 {
            registers.push((register_id::x(n), 64));
        }
        // ZR (XZR) and PC.
        registers.push((register_id::ZR, 64));
        registers.push((register_id::PC, 64));
        // 32-bit status/control registers.
        registers.push((register_id::NZCV, 32));
        registers.push((register_id::FPCR, 32));
        registers.push((register_id::FPSR, 32));
        // V0..V31 (128-bit SIMD&FP parents).
        for n in 0..32 {
            registers.push((register_id::v(n), 128));
        }
        // SP (64-bit stack pointer, separate storage from ZR).
        registers.push((register_id::SP, 64));
        registers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn architectural_registers_lists_all_canonical_parents() {
        let registers = Arm64RegisterFile::architectural_registers();
        assert_eq!(registers.len(), 69);

        let width_of = |id: u32| {
            registers
                .iter()
                .find(|(register, _)| register.0 == id)
                .map(|(_, width)| *width)
        };

        // GPRs (X0 and X30) are 64-bit.
        assert_eq!(width_of(register_id::X0.0), Some(64));
        assert_eq!(width_of(register_id::X30.0), Some(64));
        // ZR, PC, and SP are 64-bit.
        assert_eq!(width_of(register_id::ZR.0), Some(64));
        assert_eq!(width_of(register_id::PC.0), Some(64));
        assert_eq!(width_of(register_id::SP.0), Some(64));
        // Status/control registers are 32-bit.
        assert_eq!(width_of(register_id::NZCV.0), Some(32));
        assert_eq!(width_of(register_id::FPCR.0), Some(32));
        assert_eq!(width_of(register_id::FPSR.0), Some(32));
        // Vectors are 128-bit (V0 and V31).
        assert_eq!(width_of(register_id::v(0).0), Some(128));
        assert_eq!(width_of(register_id::v(31).0), Some(128));
    }
}
