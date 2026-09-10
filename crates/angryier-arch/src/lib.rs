#![forbid(unsafe_code)]

use angryier_types::{Address, TargetProfileId};
use core::fmt::Debug;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RegisterId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FeatureId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AccessKind {
    Read,
    Write,
    ReadWrite,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operand {
    pub index: u8,
    pub width_bits: u16,
    pub access: AccessKind,
    pub register: Option<RegisterId>,
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
