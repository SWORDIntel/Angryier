#![forbid(unsafe_code)]

mod lower;
mod verify;

pub use lower::{BasicSemanticLowerer, CachedSemanticLowerer, IrLoweringError};
pub use verify::{BasicIrVerifier, IrVerificationError};

use angryier_types::{Address, BlockId, CodeVersionGuard, ContentId, ExprId, ImageId, TargetProfileId};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IrValueId(pub u32);

/// How a register write relates to the register's parent width.
///
/// The decoder reports the architecture's write behavior; the execution plane
/// applies it against whatever width the register file declares.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RegisterWriteKind {
    /// The value defines the full parent register.
    ReplaceParent,
    /// The value defines the low bits and the remaining bits are zeroed
    /// (for example x86-64 32-bit writes).
    ZeroExtendParent,
    /// The value defines `width_bits` bits starting at `bit_offset` inside the
    /// parent; all other bits are preserved (for example x86-64 `setcc`).
    PreserveParent { bit_offset: u16, width_bits: u16 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IrType {
    Bits(u16),
    Float16,
    BFloat16,
    Float32,
    Float64,
    Float80,
    Vector { width_bits: u16, lane_bits: u16 },
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
    FAdd,
    FSub,
    FMul,
    FDiv,
    FSqrt,
    FSin,
    FCos,
    FTan,
    FAtan2,
    FExp2,
    FLog2,
    FScale,
    FConvert,
    VecLaneAdd,
    VecLaneSub,
    VecLaneMul,
    VecLaneAnd,
    VecLaneOr,
    VecLaneXor,
    VecLaneFAdd,
    VecLaneFSub,
    VecLaneFMul,
    VecLaneFDiv,
    VecLaneFSqrt,
    VecLaneShl,
    VecLaneLShr,
    VecLaneAShr,
    VecLaneMaskEq,
    VecLaneMaskSgt,
    VecLaneMaxU,
    VecLaneMinU,
    VecLaneMaxS,
    VecLaneMinS,
    VecLaneMulHiS,
    VecLaneMulHiU,
    VecLaneAbs,
    VecLaneSign,
    VecLaneMulHiRS,
    VecHAddS,
    VecHSubS,
    VecLaneMulDq,
    VecBlendV,
    VecShuffleBytes,
    VecInterleaveLow,
    VecInterleaveHigh,
    VecPackSaturate,
    VecPackSaturateU,
    VecMadd16,
    VecSad8,
    VecShuffle32,
    VecShuffle16,
    VecMaddubs,
    VecShiftRegL,
    VecShiftRegR,
    VecShiftRegRA,
    VecHAdd,
    VecHSub,
    VecLaneSignExtend,
    VecLaneZeroExtend,
    VecLaneSatAddU,
    VecLaneSatSubU,
    VecLaneSatAddS,
    VecDotU8S8,
    VecLaneAvg,
    VecBlendImm,
    VecDotF,
    FCompareFlags,
    FRound,
    VecFRound,
    VecTest,
    Crc32,
    VecCmpF,
    VecFMin,
    VecFMax,
    VecMovMask,
    VecHFAdd,
    VecHFSub,
    VecMpsadbw,
    VecHMinUW,
    VecShiftLeftBytes,
    VecShiftRightBytes,
    VecPermute32,
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
        kind: RegisterWriteKind,
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
    /// Jump to a computed address (for example `ret` popping its return
    /// address from the stack).
    JumpIndirect {
        target: IrValueId,
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
