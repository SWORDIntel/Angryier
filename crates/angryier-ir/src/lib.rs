#![forbid(unsafe_code)]

mod lower;
mod verify;

pub use lower::{BasicSemanticLowerer, CachedSemanticLowerer, IrLoweringError};
pub use verify::{BasicIrVerifier, IrVerificationError};

use angryier_types::{Address, BlockId, CodeVersionGuard, ContentId, ExprId, ImageId, TargetProfileId};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IrValueId(pub u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IrType {
    Bits(u16),
    Float16,
    BFloat16,
    Float32,
    Float64,
    Float80,
    Vector { width_bits: u16 },
    Opmask { width_bits: u16 },
    Tile,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IrPrimitive {
    Add,
    Sub,
    Mul,
    UDiv,
    SDiv,
    And,
    Or,
    Xor,
    Not,
    Shl,
    LShr,
    AShr,
    Eq,
    Ult,
    Ule,
    Slt,
    Sle,
    Select,
    Concat,
    Extract,
    ZExt,
    SExt,
    RotL,
    RotR,
    Popcnt,
    Clz,
    Ctz,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IrOp {
    Constant {
        ty: IrType,
        bytes_le: Vec<u8>,
    },
    ExprRef {
        expression: ExprId,
        ty: IrType,
    },
    Primitive {
        op: IrPrimitive,
        ty: IrType,
        inputs: Vec<IrValueId>,
    },
    ReadRegister {
        register: u32,
        ty: IrType,
    },
    WriteRegister {
        register: u32,
        value: IrValueId,
    },
    Load {
        address: IrValueId,
        ty: IrType,
    },
    Store {
        address: IrValueId,
        value: IrValueId,
    },
    Branch {
        condition: IrValueId,
        taken: Address,
        not_taken: Address,
    },
    Jump {
        target: Address,
    },
    Call {
        target: Address,
    },
    Return,
    Trap {
        vector: u32,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrInstruction {
    pub result: Option<IrValueId>,
    pub op: IrOp,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrBlockKey {
    pub image: ImageId,
    pub block: BlockId,
    pub address: Address,
    pub semantic_content: ContentId,
    pub target_profile: TargetProfileId,
    pub code_versions: Vec<CodeVersionGuard>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrBlock {
    pub key: IrBlockKey,
    pub instructions: Vec<IrInstruction>,
}

pub trait IrVerifier {
    type Error;
    fn verify(&self, block: &IrBlock) -> Result<(), Self::Error>;
}
