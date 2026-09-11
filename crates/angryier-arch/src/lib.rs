#![forbid(unsafe_code)]

use angryier_types::{Address, TargetProfileId};
use core::fmt::Debug;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RegisterId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FeatureId(pub u32);

/// Architecture-owned encoding-family identifier. Values are defined by the
/// concrete architecture crate and are not decoder-generated enum values.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct EncodingClass(pub u16);

/// Architecture-owned segment/address-space selector identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SegmentId(pub u16);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AccessKind {
    Read,
    Write,
    ReadWrite,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OperandVisibility {
    Explicit,
    Implicit,
    Suppressed,
}

/// Describes how a write through an architectural register view affects the
/// canonical parent register that owns the storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RegisterWriteBehavior {
    /// The view spans the parent register and replaces it completely.
    ReplaceParent,
    /// Bits outside the view are preserved.
    PreserveParent,
    /// Bits above the view are architecturally cleared on write.
    ZeroExtendParent,
    /// The view identifies the parent and bit range, but the instruction
    /// semantics must define the full parent-register write effect.
    SemanticDefined,
}

/// A decoded architectural register is represented as a view onto one stable
/// parent register. This prevents aliases such as AL/AH/EAX/RAX and
/// XMM/YMM/ZMM from becoming independent symbolic storage locations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RegisterView {
    pub parent: RegisterId,
    pub bit_offset: u16,
    pub width_bits: u16,
    pub write_behavior: RegisterWriteBehavior,
}

impl RegisterView {
    pub const fn full(parent: RegisterId, width_bits: u16) -> Self {
        Self {
            parent,
            bit_offset: 0,
            width_bits,
            write_behavior: RegisterWriteBehavior::ReplaceParent,
        }
    }

    pub const fn partial(
        parent: RegisterId,
        bit_offset: u16,
        width_bits: u16,
        write_behavior: RegisterWriteBehavior,
    ) -> Self {
        Self {
            parent,
            bit_offset,
            width_bits,
            write_behavior,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MemoryBase {
    Register(RegisterView),
    InstructionPointer { width_bits: u16 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MemoryOperand {
    pub memory_index: u8,
    pub address_width_bits: u16,
    pub segment: Option<SegmentId>,
    pub base: Option<MemoryBase>,
    pub index: Option<RegisterView>,
    pub scale: u8,
    pub displacement: i64,
    pub displacement_width_bits: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ImmediateOperand {
    pub value: u64,
    pub signed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RelativeBranchOperand {
    pub displacement: i64,
    pub displacement_width_bits: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FarPointerOperand {
    pub segment: u16,
    pub offset: u64,
    pub offset_width_bits: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OperandKind {
    Register(RegisterView),
    Memory(MemoryOperand),
    AddressGeneration(MemoryOperand),
    Immediate(ImmediateOperand),
    RelativeBranch(RelativeBranchOperand),
    FarPointer(FarPointerOperand),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operand {
    pub index: u8,
    pub width_bits: u16,
    pub access: AccessKind,
    pub visibility: OperandVisibility,
    pub kind: OperandKind,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RepetitionKind {
    Rep,
    Repe,
    Repne,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PredicateMode {
    Merge,
    Zero,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PredicateMask {
    pub register: RegisterView,
    pub mode: PredicateMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RoundingMode {
    NearestEven,
    Down,
    Up,
    TowardZero,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Broadcast {
    pub copies: u16,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct InstructionModifiers {
    pub encoding: EncodingClass,
    pub lock: bool,
    pub repetition: Option<RepetitionKind>,
    pub predicate: Option<PredicateMask>,
    pub rounding: Option<RoundingMode>,
    pub suppress_all_exceptions: bool,
    pub broadcast: Option<Broadcast>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedInstruction {
    pub address: Address,
    pub length: u8,
    pub form_id: u32,
    pub features: Vec<FeatureId>,
    pub operands: Vec<Operand>,
    pub modifiers: InstructionModifiers,
}

impl DecodedInstruction {
    pub fn relative_target(&self, branch: RelativeBranchOperand) -> Address {
        self.address
            .wrapping_add(u64::from(self.length))
            .wrapping_add_signed(branch.displacement)
    }
}

pub trait Architecture: Debug + Send + Sync {
    type RegisterFile: Debug + Send + Sync;

    fn name(&self) -> &'static str;
    fn target_profile(&self) -> TargetProfileId;
    fn register_width(&self, register: RegisterId) -> Option<u16>;
    fn initial_registers(&self) -> Self::RegisterFile;
}

pub trait Decoder: Debug + Send + Sync {
    type Error: Debug + Send + Sync;

    fn decode(&self, address: Address, bytes: &[u8]) -> Result<DecodedInstruction, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_views_preserve_alias_identity() {
        let parent = RegisterId(7);
        let low = RegisterView::partial(parent, 0, 8, RegisterWriteBehavior::PreserveParent);
        let high = RegisterView::partial(parent, 8, 8, RegisterWriteBehavior::PreserveParent);

        assert_eq!(low.parent, high.parent);
        assert_ne!(low.bit_offset, high.bit_offset);
    }

    #[test]
    fn relative_target_uses_end_of_instruction() {
        let instruction = DecodedInstruction {
            address: 0x1000,
            length: 5,
            form_id: 1,
            features: Vec::new(),
            operands: Vec::new(),
            modifiers: InstructionModifiers::default(),
        };
        let branch = RelativeBranchOperand {
            displacement: -5,
            displacement_width_bits: 32,
        };

        assert_eq!(instruction.relative_target(branch), 0x1000);
    }
}
