#![forbid(unsafe_code)]

use angryier_types::{Address, TargetProfileId};
use core::fmt::Debug;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RegisterId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FeatureId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AccessKind {
    Read,
    Write,
    ReadWrite,
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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operand {
    pub index: u8,
    pub width_bits: u16,
    pub access: AccessKind,
    pub register: Option<RegisterView>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedInstruction {
    pub address: Address,
    pub length: u8,
    pub form_id: u32,
    pub features: Vec<FeatureId>,
    pub operands: Vec<Operand>,
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
}
