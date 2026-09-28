#![forbid(unsafe_code)]

use angryier_arch::{Architecture, RegisterId, RegisterView, RegisterWriteBehavior};
use angryier_types::TargetProfileId;
use core::fmt;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IntelFeature {
    Sse,
    Sse2,
    Sse3,
    Ssse3,
    Sse41,
    Sse42,
    AesNi,
    Sha,
    Bmi1,
    Bmi2,
    Avx,
    Avx2,
    Avx512,
    AvxVnni,
    Avx10,
    Amx,
    Cet,
    Apx,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeatureSet {
    pub features: Vec<IntelFeature>,
    pub xcr0: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Intel64ProfileKind {
    Native,
    Named(String),
    Custom,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intel64TargetProfile {
    pub id: TargetProfileId,
    pub kind: Intel64ProfileKind,
    pub features: FeatureSet,
}

/// Stable encoding classes consumed by Intel 64 semantics. Raw/generated XED
/// encoding discriminants must be translated to these values at the adapter boundary.
pub mod encoding_class {
    use angryier_arch::EncodingClass;

    pub const LEGACY: EncodingClass = EncodingClass(1);
    pub const VEX: EncodingClass = EncodingClass(2);
    pub const EVEX: EncodingClass = EncodingClass(3);
    pub const REX2: EncodingClass = EncodingClass(4);
}

/// Intel 64 segment selectors used by normalized memory operands.
pub mod segment_id {
    use angryier_arch::SegmentId;

    pub const ES: SegmentId = SegmentId(0);
    pub const CS: SegmentId = SegmentId(1);
    pub const SS: SegmentId = SegmentId(2);
    pub const DS: SegmentId = SegmentId(3);
    pub const FS: SegmentId = SegmentId(4);
    pub const GS: SegmentId = SegmentId(5);
}

/// Returns the segment-base register for FS/GS overrides, or `None` for
/// segments whose base is architecturally zero in long mode.
pub fn segment_base_register(segment: angryier_arch::SegmentId) -> Option<angryier_arch::RegisterId> {
    if segment == segment_id::FS {
        Some(register_id::FS_BASE)
    } else if segment == segment_id::GS {
        Some(register_id::GS_BASE)
    } else {
        None
    }
}

/// Stable parent-register identifier ranges. These values are persistence and
/// replay identifiers and must not be renumbered when new aliases are added.
pub mod register_id {
    use angryier_arch::RegisterId;

    pub const GPR_BASE: u32 = 0x0000;
    pub const RIP: RegisterId = RegisterId(0x0020);
    pub const RFLAGS: RegisterId = RegisterId(0x0021);
    /// FS segment base address (TLS pointer under Linux).
    pub const FS_BASE: RegisterId = RegisterId(0x0022);
    /// GS segment base address.
    pub const GS_BASE: RegisterId = RegisterId(0x0023);
    pub const ZMM_BASE: u32 = 0x0100;
    pub const OPMASK_BASE: u32 = 0x0140;
    pub const X87_BASE: u32 = 0x0180;
    pub const TILE_BASE: u32 = 0x0200;
    pub const TILECFG: RegisterId = RegisterId(0x0208);
    pub const MXCSR: RegisterId = RegisterId(0x0210);
    /// x87 FPU status word: TOP (bits 11..=13) and condition codes
    /// C0/C1/C2/C3 (bits 8/9/10/14). Exception and summary flags stay 0 in
    /// the masked-exceptions model.
    pub const X87_SW: RegisterId = RegisterId(0x0211);
}

pub const GPR_COUNT: u8 = 32;
pub const VECTOR_COUNT: u8 = 32;
pub const OPMASK_COUNT: u8 = 8;
pub const X87_COUNT: u8 = 8;
pub const TILE_COUNT: u8 = 8;
pub const TMM_MAX_BITS: u16 = 8192;
pub const INTEL64_PARENT_REGISTER_COUNT: usize = 95;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GprViewKind {
    Qword,
    Dword,
    Word,
    LowByte,
    HighByte,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VectorViewKind {
    Xmm128,
    Ymm256,
    Zmm512,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Intel64RegisterError {
    InvalidGprIndex(u8),
    InvalidHighByteRegister(u8),
    InvalidVectorIndex(u8),
    InvalidOpmaskIndex(u8),
    InvalidX87Index(u8),
    InvalidTileIndex(u8),
}

impl fmt::Display for Intel64RegisterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidGprIndex(index) => write!(formatter, "invalid Intel 64 GPR index: {index}"),
            Self::InvalidHighByteRegister(index) => {
                write!(formatter, "GPR index {index} has no high-byte register view")
            }
            Self::InvalidVectorIndex(index) => {
                write!(formatter, "invalid Intel 64 vector register index: {index}")
            }
            Self::InvalidOpmaskIndex(index) => {
                write!(formatter, "invalid Intel 64 opmask register index: {index}")
            }
            Self::InvalidX87Index(index) => {
                write!(formatter, "invalid Intel 64 x87 register index: {index}")
            }
            Self::InvalidTileIndex(index) => {
                write!(formatter, "invalid Intel 64 tile register index: {index}")
            }
        }
    }
}

impl std::error::Error for Intel64RegisterError {}

pub const fn gpr_parent(index: u8) -> Result<RegisterId, Intel64RegisterError> {
    if index < GPR_COUNT {
        Ok(RegisterId(register_id::GPR_BASE + index as u32))
    } else {
        Err(Intel64RegisterError::InvalidGprIndex(index))
    }
}

pub const fn gpr_view(index: u8, kind: GprViewKind) -> Result<RegisterView, Intel64RegisterError> {
    let parent = match gpr_parent(index) {
        Ok(parent) => parent,
        Err(error) => return Err(error),
    };

    match kind {
        GprViewKind::Qword => Ok(RegisterView::full(parent, 64)),
        GprViewKind::Dword => Ok(RegisterView::partial(
            parent,
            0,
            32,
            RegisterWriteBehavior::ZeroExtendParent,
        )),
        GprViewKind::Word => Ok(RegisterView::partial(
            parent,
            0,
            16,
            RegisterWriteBehavior::PreserveParent,
        )),
        GprViewKind::LowByte => Ok(RegisterView::partial(
            parent,
            0,
            8,
            RegisterWriteBehavior::PreserveParent,
        )),
        GprViewKind::HighByte if index < 4 => Ok(RegisterView::partial(
            parent,
            8,
            8,
            RegisterWriteBehavior::PreserveParent,
        )),
        GprViewKind::HighByte => Err(Intel64RegisterError::InvalidHighByteRegister(index)),
    }
}

pub const fn vector_parent(index: u8) -> Result<RegisterId, Intel64RegisterError> {
    if index < VECTOR_COUNT {
        Ok(RegisterId(register_id::ZMM_BASE + index as u32))
    } else {
        Err(Intel64RegisterError::InvalidVectorIndex(index))
    }
}

pub const fn vector_view(index: u8, kind: VectorViewKind) -> Result<RegisterView, Intel64RegisterError> {
    let parent = match vector_parent(index) {
        Ok(parent) => parent,
        Err(error) => return Err(error),
    };

    // VEX/EVEX upper-lane clearing is instruction semantics, not an intrinsic
    // property of the architectural XMM/YMM register view.
    Ok(match kind {
        VectorViewKind::Xmm128 => RegisterView::partial(parent, 0, 128, RegisterWriteBehavior::SemanticDefined),
        VectorViewKind::Ymm256 => RegisterView::partial(parent, 0, 256, RegisterWriteBehavior::SemanticDefined),
        VectorViewKind::Zmm512 => RegisterView::full(parent, 512),
    })
}

pub const fn opmask_view(index: u8) -> Result<RegisterView, Intel64RegisterError> {
    if index < OPMASK_COUNT {
        Ok(RegisterView::partial(
            RegisterId(register_id::OPMASK_BASE + index as u32),
            0,
            64,
            RegisterWriteBehavior::SemanticDefined,
        ))
    } else {
        Err(Intel64RegisterError::InvalidOpmaskIndex(index))
    }
}

pub const fn x87_view(index: u8) -> Result<RegisterView, Intel64RegisterError> {
    if index < X87_COUNT {
        Ok(RegisterView::full(RegisterId(register_id::X87_BASE + index as u32), 80))
    } else {
        Err(Intel64RegisterError::InvalidX87Index(index))
    }
}

pub const fn mmx_view(index: u8) -> Result<RegisterView, Intel64RegisterError> {
    if index < X87_COUNT {
        Ok(RegisterView::partial(
            RegisterId(register_id::X87_BASE + index as u32),
            0,
            64,
            RegisterWriteBehavior::SemanticDefined,
        ))
    } else {
        Err(Intel64RegisterError::InvalidX87Index(index))
    }
}

pub const fn tile_view(index: u8) -> Result<RegisterView, Intel64RegisterError> {
    if index < TILE_COUNT {
        Ok(RegisterView::partial(
            RegisterId(register_id::TILE_BASE + index as u32),
            0,
            TMM_MAX_BITS,
            RegisterWriteBehavior::SemanticDefined,
        ))
    } else {
        Err(Intel64RegisterError::InvalidTileIndex(index))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intel64RegisterFile {
    /// Canonical parents only; aliases are represented by `RegisterView` and
    /// never receive independent state storage.
    pub architectural_registers: Vec<(RegisterId, u16)>,
}

impl Intel64RegisterFile {
    pub fn canonical() -> Self {
        let mut registers = Vec::with_capacity(INTEL64_PARENT_REGISTER_COUNT);

        for index in 0..GPR_COUNT {
            registers.push((RegisterId(register_id::GPR_BASE + u32::from(index)), 64));
        }
        registers.push((register_id::RIP, 64));
        registers.push((register_id::RFLAGS, 64));
        registers.push((register_id::FS_BASE, 64));
        registers.push((register_id::GS_BASE, 64));

        for index in 0..VECTOR_COUNT {
            registers.push((RegisterId(register_id::ZMM_BASE + u32::from(index)), 512));
        }
        for index in 0..OPMASK_COUNT {
            registers.push((RegisterId(register_id::OPMASK_BASE + u32::from(index)), 64));
        }
        for index in 0..X87_COUNT {
            registers.push((RegisterId(register_id::X87_BASE + u32::from(index)), 80));
        }
        for index in 0..TILE_COUNT {
            registers.push((RegisterId(register_id::TILE_BASE + u32::from(index)), TMM_MAX_BITS));
        }

        registers.push((register_id::TILECFG, 512));
        registers.push((register_id::MXCSR, 32));
        registers.push((register_id::X87_SW, 16));

        Self {
            architectural_registers: registers,
        }
    }

    pub fn has_unique_parent_ids(&self) -> bool {
        let ids: BTreeSet<_> = self
            .architectural_registers
            .iter()
            .map(|(register, _)| *register)
            .collect();
        ids.len() == self.architectural_registers.len()
    }
}

pub const fn canonical_parent_width(register: RegisterId) -> Option<u16> {
    let raw = register.0;

    if raw < register_id::GPR_BASE + GPR_COUNT as u32 || raw == register_id::RIP.0 || raw == register_id::RFLAGS.0 {
        Some(64)
    } else if raw >= register_id::ZMM_BASE && raw < register_id::ZMM_BASE + VECTOR_COUNT as u32 {
        Some(512)
    } else if raw >= register_id::OPMASK_BASE && raw < register_id::OPMASK_BASE + OPMASK_COUNT as u32 {
        Some(64)
    } else if raw >= register_id::X87_BASE && raw < register_id::X87_BASE + X87_COUNT as u32 {
        Some(80)
    } else if raw >= register_id::TILE_BASE && raw < register_id::TILE_BASE + TILE_COUNT as u32 {
        Some(TMM_MAX_BITS)
    } else if raw == register_id::TILECFG.0 {
        Some(512)
    } else if raw == register_id::MXCSR.0 {
        Some(32)
    } else if raw == register_id::X87_SW.0 {
        Some(16)
    } else {
        None
    }
}

#[derive(Clone, Debug)]
pub struct Intel64Architecture {
    pub profile: Intel64TargetProfile,
}

impl Architecture for Intel64Architecture {
    type RegisterFile = Intel64RegisterFile;

    fn name(&self) -> &'static str {
        "intel64"
    }

    fn target_profile(&self) -> TargetProfileId {
        self.profile.id
    }

    fn register_width(&self, register: RegisterId) -> Option<u16> {
        canonical_parent_width(register)
    }

    fn initial_registers(&self) -> Self::RegisterFile {
        Intel64RegisterFile::canonical()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eax_is_zero_extending_view_of_rax() -> Result<(), Intel64RegisterError> {
        let rax = gpr_parent(0)?;
        let eax = gpr_view(0, GprViewKind::Dword)?;

        assert_eq!(eax.parent, rax);
        assert_eq!(eax.bit_offset, 0);
        assert_eq!(eax.width_bits, 32);
        assert_eq!(eax.write_behavior, RegisterWriteBehavior::ZeroExtendParent);
        Ok(())
    }

    #[test]
    fn ah_is_high_byte_view_of_rax() -> Result<(), Intel64RegisterError> {
        let rax = gpr_parent(0)?;
        let ah = gpr_view(0, GprViewKind::HighByte)?;

        assert_eq!(ah.parent, rax);
        assert_eq!(ah.bit_offset, 8);
        assert_eq!(ah.width_bits, 8);
        assert_eq!(ah.write_behavior, RegisterWriteBehavior::PreserveParent);
        Ok(())
    }

    #[test]
    fn xmm_ymm_zmm_share_one_parent() -> Result<(), Intel64RegisterError> {
        let xmm = vector_view(17, VectorViewKind::Xmm128)?;
        let ymm = vector_view(17, VectorViewKind::Ymm256)?;
        let zmm = vector_view(17, VectorViewKind::Zmm512)?;

        assert_eq!(xmm.parent, ymm.parent);
        assert_eq!(ymm.parent, zmm.parent);
        assert_eq!(xmm.width_bits, 128);
        assert_eq!(ymm.width_bits, 256);
        assert_eq!(zmm.width_bits, 512);
        assert_eq!(xmm.write_behavior, RegisterWriteBehavior::SemanticDefined);
        assert_eq!(ymm.write_behavior, RegisterWriteBehavior::SemanticDefined);
        Ok(())
    }

    #[test]
    fn mmx_aliases_x87_parent() -> Result<(), Intel64RegisterError> {
        let st = x87_view(3)?;
        let mm = mmx_view(3)?;

        assert_eq!(st.parent, mm.parent);
        assert_eq!(st.width_bits, 80);
        assert_eq!(mm.width_bits, 64);
        assert_eq!(mm.write_behavior, RegisterWriteBehavior::SemanticDefined);
        Ok(())
    }

    #[test]
    fn parent_widths_cover_apx_vector_mask_and_amx() -> Result<(), Intel64RegisterError> {
        let profile = Intel64TargetProfile {
            id: TargetProfileId(1),
            kind: Intel64ProfileKind::Custom,
            features: FeatureSet {
                features: Vec::new(),
                xcr0: 0,
            },
        };
        let architecture = Intel64Architecture { profile };

        assert_eq!(architecture.register_width(gpr_parent(31)?), Some(64));
        assert_eq!(architecture.register_width(vector_parent(31)?), Some(512));
        assert_eq!(architecture.register_width(opmask_view(7)?.parent), Some(64));
        assert_eq!(architecture.register_width(tile_view(7)?.parent), Some(TMM_MAX_BITS));
        Ok(())
    }

    #[test]
    fn canonical_register_file_has_exactly_unique_parents() {
        let registers = Intel64RegisterFile::canonical();

        assert_eq!(registers.architectural_registers.len(), INTEL64_PARENT_REGISTER_COUNT);
        assert!(registers.has_unique_parent_ids());
    }

    #[test]
    fn invalid_high_byte_alias_fails_closed() {
        assert_eq!(
            gpr_view(4, GprViewKind::HighByte),
            Err(Intel64RegisterError::InvalidHighByteRegister(4))
        );
    }
}
