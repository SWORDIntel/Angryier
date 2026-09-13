//! Mapping from raw `xed_sys` register enumerants to Angryier's value-only
//! `XedRegisterRef` description.
//!
//! Raw `xed_reg_enum_t` discriminants never cross the public API of this crate.
//! Every register is translated to a semantic family (`Gpr`, `Vector`, `Opmask`,
//! ...) plus a view width before being placed in `XedDecodedMetadata`.

use angryier_decode_xed::metadata::{XedGprView, XedRegisterRef, XedVectorView};
use xed_sys::xed_reg_enum_t;

/// Result of mapping a raw XED register: the semantic reference. The
/// architectural width is derived from the reference via [`register_width`].
pub(crate) struct MappedRegister {
    pub reference: XedRegisterRef,
}

/// Returns the architectural width in bits of a semantic register reference.
pub(crate) fn register_width(reference: &XedRegisterRef) -> u16 {
    match reference {
        XedRegisterRef::Gpr { view, .. } => match view {
            XedGprView::Qword => 64,
            XedGprView::Dword => 32,
            XedGprView::Word => 16,
            XedGprView::LowByte | XedGprView::HighByte => 8,
        },
        XedRegisterRef::InstructionPointer => 64,
        XedRegisterRef::Flags => 64,
        XedRegisterRef::Vector { view, .. } => match view {
            XedVectorView::Xmm128 => 128,
            XedVectorView::Ymm256 => 256,
            XedVectorView::Zmm512 => 512,
        },
        XedRegisterRef::Opmask { .. } => 64,
        XedRegisterRef::X87 { .. } => 80,
        XedRegisterRef::Mmx { .. } => 64,
        XedRegisterRef::Tile { .. } => 8192,
        XedRegisterRef::TileConfig => 512,
        XedRegisterRef::Mxcsr => 32,
    }
}

// GPR enum ranges (from the vendored XED bindings).
const REG_AX: xed_reg_enum_t = 34; // AX .. DI  (word views, 16b)
const REG_EAX: xed_reg_enum_t = 66; // EAX .. EDI (dword views, 32b)
const REG_RAX: xed_reg_enum_t = 98; // RAX .. R31 (qword views, 64b)
const REG_AL: xed_reg_enum_t = 130; // AL .. R31B (low-byte views, 8b)
const REG_AH: xed_reg_enum_t = 162; // AH .. BH   (high-byte views, 8b)

const REG_RIP: xed_reg_enum_t = 167;
const REG_FLAGS: xed_reg_enum_t = 31;
const REG_EFLAGS: xed_reg_enum_t = 32;
const REG_RFLAGS: xed_reg_enum_t = 33;

const REG_K0: xed_reg_enum_t = 170; // K0 .. K7 (opmask, 64b)
const REG_TMM0: xed_reg_enum_t = 251; // TMM0 .. TMM7 (AMX tile, 8192b)
const REG_ST0: xed_reg_enum_t = 260; // ST0 .. ST7 (x87, 80b)
const REG_XMM0: xed_reg_enum_t = 269; // XMM0 .. XMM31 (128b)
const REG_YMM0: xed_reg_enum_t = 301; // YMM0 .. YMM31 (256b)
const REG_ZMM0: xed_reg_enum_t = 333; // ZMM0 .. ZMM31 (512b)
const REG_MXCSR: xed_reg_enum_t = 188;

const REG_ES: xed_reg_enum_t = 229;
const REG_CS: xed_reg_enum_t = 230;
const REG_SS: xed_reg_enum_t = 231;
const REG_DS: xed_reg_enum_t = 232;
const REG_FS: xed_reg_enum_t = 233;
const REG_GS: xed_reg_enum_t = 234;

const REG_INVALID: xed_reg_enum_t = 0;

/// Maps a raw XED register enumerant to Angryier's semantic register reference.
///
/// Returns `None` for `XED_REG_INVALID` and for pseudo-registers (e.g.
/// `STACKPUSH`/`STACKPOP`) that have no canonical Angryier representation.
pub(crate) fn map_register(reg: xed_reg_enum_t) -> Option<MappedRegister> {
    if reg == REG_INVALID {
        return None;
    }

    // 64-bit qword GPR views: RAX..R31
    if (REG_RAX..=REG_RAX + 31).contains(&reg) {
        return Some(MappedRegister {
            reference: XedRegisterRef::Gpr {
                index: (reg - REG_RAX) as u8,
                view: XedGprView::Qword,
            },
        });
    }
    // 32-bit dword GPR views: EAX..R31D
    if (REG_EAX..=REG_EAX + 31).contains(&reg) {
        return Some(MappedRegister {
            reference: XedRegisterRef::Gpr {
                index: (reg - REG_EAX) as u8,
                view: XedGprView::Dword,
            },
        });
    }
    // 16-bit word GPR views: AX..R31W
    if (REG_AX..=REG_AX + 31).contains(&reg) {
        return Some(MappedRegister {
            reference: XedRegisterRef::Gpr {
                index: (reg - REG_AX) as u8,
                view: XedGprView::Word,
            },
        });
    }
    // 8-bit low-byte GPR views: AL..R31B
    if (REG_AL..=REG_AL + 31).contains(&reg) {
        return Some(MappedRegister {
            reference: XedRegisterRef::Gpr {
                index: (reg - REG_AL) as u8,
                view: XedGprView::LowByte,
            },
        });
    }
    // 8-bit high-byte GPR views: AH..BH (only indices 0..=3)
    if (REG_AH..=REG_AH + 3).contains(&reg) {
        return Some(MappedRegister {
            reference: XedRegisterRef::Gpr {
                index: (reg - REG_AH) as u8,
                view: XedGprView::HighByte,
            },
        });
    }

    if reg == REG_RIP {
        return Some(MappedRegister {
            reference: XedRegisterRef::InstructionPointer,
        });
    }
    if reg == REG_FLAGS || reg == REG_EFLAGS || reg == REG_RFLAGS {
        return Some(MappedRegister {
            reference: XedRegisterRef::Flags,
        });
    }

    // Opmask registers K0..K7
    if (REG_K0..=REG_K0 + 7).contains(&reg) {
        return Some(MappedRegister {
            reference: XedRegisterRef::Opmask {
                index: (reg - REG_K0) as u8,
            },
        });
    }

    // AMX tile registers TMM0..TMM7
    if (REG_TMM0..=REG_TMM0 + 7).contains(&reg) {
        return Some(MappedRegister {
            reference: XedRegisterRef::Tile {
                index: (reg - REG_TMM0) as u8,
            },
        });
    }

    // x87 registers ST0..ST7
    if (REG_ST0..=REG_ST0 + 7).contains(&reg) {
        return Some(MappedRegister {
            reference: XedRegisterRef::X87 {
                index: (reg - REG_ST0) as u8,
            },
        });
    }

    // Vector XMM0..XMM31
    if (REG_XMM0..=REG_XMM0 + 31).contains(&reg) {
        return Some(MappedRegister {
            reference: XedRegisterRef::Vector {
                index: (reg - REG_XMM0) as u8,
                view: XedVectorView::Xmm128,
            },
        });
    }
    // Vector YMM0..YMM31
    if (REG_YMM0..=REG_YMM0 + 31).contains(&reg) {
        return Some(MappedRegister {
            reference: XedRegisterRef::Vector {
                index: (reg - REG_YMM0) as u8,
                view: XedVectorView::Ymm256,
            },
        });
    }
    // Vector ZMM0..ZMM31
    if (REG_ZMM0..=REG_ZMM0 + 31).contains(&reg) {
        return Some(MappedRegister {
            reference: XedRegisterRef::Vector {
                index: (reg - REG_ZMM0) as u8,
                view: XedVectorView::Zmm512,
            },
        });
    }

    if reg == REG_MXCSR {
        return Some(MappedRegister {
            reference: XedRegisterRef::Mxcsr,
        });
    }

    // Unmapped register (e.g. STACKPUSH, STACKPOP, segment regs as operands,
    // control/debug registers). These are skipped at the operand level.
    None
}

/// Maps a raw XED segment register enumerant to Angryier's `XedSegment`.
///
/// Returns `None` for `XED_REG_INVALID`, indicating the default segment should
/// be used.
pub(crate) fn map_segment(reg: xed_reg_enum_t) -> Option<angryier_decode_xed::metadata::XedSegment> {
    use angryier_decode_xed::metadata::XedSegment;
    match reg {
        REG_ES => Some(XedSegment::Es),
        REG_CS => Some(XedSegment::Cs),
        REG_SS => Some(XedSegment::Ss),
        REG_DS => Some(XedSegment::Ds),
        REG_FS => Some(XedSegment::Fs),
        REG_GS => Some(XedSegment::Gs),
        _ => None,
    }
}
