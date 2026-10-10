use angryier_arch_intel64::IntelFeature;

/// Engine-side Intel machine mode selection.
///
/// Each variant maps to exactly one raw `xed_machine_mode_enum_t` plus the
/// `xed_address_width_enum_t` stack addressing width the native bridge passes
/// to `xed_decoded_inst_set_mode`. Raw discriminants never cross this crate's
/// API.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XedMachineMode {
    /// 64-bit long mode (`XED_MACHINE_MODE_LONG_64`, 64-bit stack addressing).
    Intel64,
    /// 32-bit legacy/protected mode (`XED_MACHINE_MODE_LEGACY_32`, 32-bit
    /// stack addressing).
    Legacy32,
    /// 16-bit legacy/protected mode (`XED_MACHINE_MODE_LEGACY_16`, 16-bit
    /// stack addressing).
    Legacy16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XedEncoding {
    Legacy,
    Vex,
    Evex,
    Rex2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XedAccess {
    Read,
    Write,
    ReadWrite,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XedOperandVisibility {
    Explicit,
    Implicit,
    Suppressed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XedGprView {
    Qword,
    Dword,
    Word,
    LowByte,
    HighByte,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XedVectorView {
    Xmm128,
    Ymm256,
    Zmm512,
}

/// Stable value-only register description produced by the native XED bridge.
///
/// Raw `xed_reg_enum_t` discriminants must never cross into this crate. The
/// bridge translates them to these semantic register families first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XedRegisterRef {
    Gpr { index: u8, view: XedGprView },
    InstructionPointer,
    Flags,
    Vector { index: u8, view: XedVectorView },
    Opmask { index: u8 },
    X87 { index: u8 },
    Mmx { index: u8 },
    Tile { index: u8 },
    TileConfig,
    Mxcsr,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XedSegment {
    Es,
    Cs,
    Ss,
    Ds,
    Fs,
    Gs,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XedMemoryBase {
    Register(XedRegisterRef),
    InstructionPointer { width_bits: u16 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XedMemoryIndex {
    Register(XedRegisterRef),
    Vsib {
        register: XedRegisterRef,
        element_width_bits: u16,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct XedMemoryOperand {
    pub memory_index: u8,
    pub address_width_bits: u16,
    pub segment: Option<XedSegment>,
    pub base: Option<XedMemoryBase>,
    pub index: Option<XedMemoryIndex>,
    pub scale: u8,
    pub displacement: i64,
    pub displacement_width_bits: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct XedImmediateOperand {
    pub value: u64,
    pub signed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct XedRelativeBranchOperand {
    pub displacement: i64,
    pub displacement_width_bits: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct XedFarPointerOperand {
    pub segment: u16,
    pub offset: u64,
    pub offset_width_bits: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XedOperandKind {
    Register(XedRegisterRef),
    Memory(XedMemoryOperand),
    AddressGeneration(XedMemoryOperand),
    Immediate(XedImmediateOperand),
    RelativeBranch(XedRelativeBranchOperand),
    FarPointer(XedFarPointerOperand),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct XedOperand {
    pub index: u8,
    pub width_bits: u16,
    pub access: XedAccess,
    pub visibility: XedOperandVisibility,
    pub kind: XedOperandKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XedRepetition {
    Rep,
    Repe,
    Repne,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XedRoundingMode {
    NearestEven,
    Down,
    Up,
    TowardZero,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct XedPredicateMask {
    pub register: XedRegisterRef,
    pub zeroing: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct XedBroadcast {
    pub copies: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct XedInstructionModifiers {
    pub encoding: XedEncoding,
    pub lock: bool,
    pub repetition: Option<XedRepetition>,
    pub predicate: Option<XedPredicateMask>,
    pub rounding: Option<XedRoundingMode>,
    pub suppress_all_exceptions: bool,
    pub no_flags: bool,
    pub broadcast: Option<XedBroadcast>,
}

impl Default for XedInstructionModifiers {
    fn default() -> Self {
        Self {
            encoding: XedEncoding::Legacy,
            lock: false,
            repetition: None,
            predicate: None,
            rounding: None,
            suppress_all_exceptions: false,
            no_flags: false,
            broadcast: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XedIformMetadata {
    /// Exact XED package/table release that defines `value` and `name`.
    /// Discriminants are not stable across XED releases and are not ISANITY IDs.
    pub xed_sys_version: &'static str,
    /// Exact symbolic spelling for this enumerant.
    pub name: String,
    /// Raw `xed_iform_enum_t` discriminant for `xed_sys_version` only.
    pub value: u32,
}

impl Default for XedIformMetadata {
    fn default() -> Self {
        Self {
            xed_sys_version: "xed-sys 0.6.0+xed-2024.05.20",
            name: "XED_IFORM_INVALID".to_owned(),
            value: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XedDecodedMetadata {
    /// Decoded instruction length. Must be in the Intel architectural range 1..=15.
    pub length: u8,
    /// Stable Angryier semantic-form identifier. This must not be a raw
    /// `xed_iform_enum_t` discriminant. The native bridge owns the mapping from
    /// XED's generated form namespace to this engine-owned identifier.
    pub form_id: u32,
    /// Source-level XED iform evidence, separate from engine `form_id` and
    /// explicitly scoped to the XED release defining the raw discriminant.
    pub xed_iform: XedIformMetadata,
    /// Stable architecture feature families. Raw XED ISA-set discriminants are
    /// translated by the native bridge before crossing this boundary.
    pub features: Vec<IntelFeature>,
    pub operands: Vec<XedOperand>,
    pub modifiers: XedInstructionModifiers,
}
