#![forbid(unsafe_code)]

//! Architectural contracts for Angryier semantic definition and lowering.
//!
//! This crate owns semantic construction/provider interfaces only. Cross-plane
//! identity and version types come from `angryier-types`; execution-ledger and
//! replay publication contracts live in their dedicated crates.

mod block;

pub use block::{
    SealedRichSemanticBlock, SemanticBlockBuilder, SemanticEffect, SemanticEffectDefinition, SemanticValue,
    SemanticValueDefinition,
};

use angryier_arch::{AccessKind, DecodedInstruction};
pub use angryier_arch::{
    FarPointerOperand, FeatureId, ImmediateOperand, MemoryOperand, OperandKind, RegisterId, RegisterView,
    RegisterWriteBehavior, RelativeBranchOperand,
};
use angryier_types::{
    Address, BlockId, CodeVersionGuard, FidelityProfile, ImageId, SemanticRuleId, SemanticVersion, TargetProfileId,
};
use core::fmt::Debug;

pub type FormId = u32;
pub type ValueId = u32;
pub type EffectId = u32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FloatFormat {
    F16,
    Bf16,
    F32,
    F64,
    F80,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ScalarType {
    BitVec(u16),
    Float(FloatFormat),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SemanticType {
    Scalar(ScalarType),
    Vector {
        lanes: u16,
        lane: ScalarType,
    },
    Opmask {
        lanes: u16,
    },
    Tile {
        rows: u8,
        bytes_per_row: u16,
        element: ScalarType,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VectorRepresentation {
    Packed,
    Lanes,
    HybridLazy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TileRepresentation {
    LazyChunked,
    DenseCellFallback,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FloatingPointPolicy {
    SmtFpPreferred,
    ControlledBitVectorFallback,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SemanticOrigin {
    DeclarativeGenerated,
    RustCombinator,
    HandwrittenOverride,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MemoryOrdering {
    Unspecified,
    Acquire,
    Release,
    AcquireRelease,
    SequentiallyConsistent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PrimitiveOp {
    Add,
    Sub,
    Mul,
    UnsignedDiv,
    SignedDiv,
    And,
    Or,
    Xor,
    Not,
    ShiftLeft,
    LogicalShiftRight,
    ArithmeticShiftRight,
    Eq,
    Ult,
    Ule,
    Slt,
    Sle,
    Select,
    Concat,
    Extract,
    ZeroExtend,
    SignExtend,
    RotateLeft,
    RotateRight,
    Popcount,
    CountLeadingZeros,
    CountTrailingZeros,
    MaskEq,
    MaskSgt,
    MaxU,
    MinU,
    MaxS,
    MinS,
    MulHighS,
    MulHighU,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FloatingOp {
    Add,
    Sub,
    Mul,
    Div,
    Sqrt,
    Compare,
    Convert,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum VectorOp {
    LaneWise(PrimitiveOp),
    LaneWiseFloat(FloatingOp),
    Shuffle,
    Permute,
    Broadcast,
    Blend,
    MaskMerge,
    MaskZero,
    Pack,
    Unpack,
    UnpackHigh,
    PackUnsigned,
    Madd16,
    Sad8,
    Shuffle32,
    Shuffle16,
    Maddubs,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TileOp {
    Load,
    Store,
    Zero,
    DotProduct,
    Transform,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SemanticOp {
    Primitive(PrimitiveOp),
    Float(FloatingOp),
    Vector(VectorOp),
    Tile(TileOp),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SideEffect {
    WriteRegister(RegisterId),
    MemoryRead,
    MemoryWrite,
    ControlTransfer,
    RaiseException(u32),
    UpdateFlags,
    UpdateMxcsr,
    UpdateTileConfig,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OperandClass {
    Register,
    Memory,
    AddressGeneration,
    Immediate,
    RelativeBranch,
    FarPointer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OperandDescriptor {
    pub index: u8,
    pub width_bits: u16,
    pub read: bool,
    pub written: bool,
    pub class: OperandClass,
    pub kind: OperandKind,
}

/// Decoder-facing view. XED-specific objects must not cross this boundary.
pub trait DecodedInstructionView: Debug + Send + Sync {
    fn address(&self) -> Address;
    fn form_id(&self) -> FormId;
    fn length(&self) -> u8;
    fn feature_ids(&self) -> &[FeatureId];
    fn operand_count(&self) -> usize;
    fn operand(&self, index: u8) -> Option<OperandDescriptor>;
}

impl DecodedInstructionView for DecodedInstruction {
    fn address(&self) -> Address {
        self.address
    }

    fn form_id(&self) -> FormId {
        self.form_id
    }

    fn length(&self) -> u8 {
        self.length
    }

    fn feature_ids(&self) -> &[FeatureId] {
        &self.features
    }

    fn operand_count(&self) -> usize {
        self.operands.len()
    }

    fn operand(&self, index: u8) -> Option<OperandDescriptor> {
        self.operands
            .iter()
            .find(|operand| operand.index == index)
            .map(|operand| OperandDescriptor {
                index: operand.index,
                width_bits: operand.width_bits,
                read: matches!(operand.access, AccessKind::Read | AccessKind::ReadWrite),
                written: matches!(operand.access, AccessKind::Write | AccessKind::ReadWrite),
                class: match operand.kind {
                    OperandKind::Register(_) => OperandClass::Register,
                    OperandKind::Memory(_) => OperandClass::Memory,
                    OperandKind::AddressGeneration(_) => OperandClass::AddressGeneration,
                    OperandKind::Immediate(_) => OperandClass::Immediate,
                    OperandKind::RelativeBranch(_) => OperandClass::RelativeBranch,
                    OperandKind::FarPointer(_) => OperandClass::FarPointer,
                },
                kind: operand.kind,
            })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SemanticContext {
    pub semantic_version: SemanticVersion,
    pub target_profile: TargetProfileId,
    pub fidelity: FidelityProfile,
    pub vector_representation: VectorRepresentation,
    pub tile_representation: TileRepresentation,
    pub floating_point_policy: FloatingPointPolicy,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SemanticError {
    UnsupportedForm(FormId),
    UnsupportedType(SemanticType),
    InvalidOperand,
    InvalidWidth,
    InvalidSemanticDefinition,
    BuilderRejected,
    LoweringRejected,
    VersionMismatch,
}

/// Builder for the rich canonical semantic IR.
///
/// Semantic definitions emit into this interface. They do not construct compact
/// execution IR, solver ASTs, JIT objects, or persistence records directly.
pub trait SemanticBuilder {
    fn constant(&mut self, ty: SemanticType, bytes_le: &[u8]) -> Result<ValueId, SemanticError>;
    fn read_register(&mut self, reg: RegisterId, ty: SemanticType) -> Result<ValueId, SemanticError>;
    fn read_operand(&mut self, operand_index: u8, ty: SemanticType) -> Result<ValueId, SemanticError>;
    fn emit(&mut self, op: SemanticOp, ty: SemanticType, inputs: &[ValueId]) -> Result<ValueId, SemanticError>;
    fn write_register(&mut self, reg: RegisterId, value: ValueId) -> Result<EffectId, SemanticError>;
    fn write_operand(&mut self, operand_index: u8, value: ValueId) -> Result<EffectId, SemanticError>;
    fn side_effect(&mut self, effect: SideEffect, inputs: &[ValueId]) -> Result<EffectId, SemanticError>;
    fn jump(&mut self, target: ValueId) -> Result<EffectId, SemanticError>;
    fn branch(&mut self, condition: ValueId, taken: ValueId, not_taken: ValueId) -> Result<EffectId, SemanticError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SemanticReceipt {
    pub rule_id: SemanticRuleId,
    pub origin: SemanticOrigin,
    pub semantic_version: SemanticVersion,
}

/// Shared contract implemented by every semantic provider.
pub trait SemanticProvider: Debug + Send + Sync {
    fn rule_id(&self) -> SemanticRuleId;
    fn origin(&self) -> SemanticOrigin;
    fn matches(&self, insn: &dyn DecodedInstructionView) -> bool;
    fn emit(
        &self,
        context: &SemanticContext,
        insn: &dyn DecodedInstructionView,
        out: &mut dyn SemanticBuilder,
    ) -> Result<SemanticReceipt, SemanticError>;
}

pub trait GeneratedSemanticFamily: SemanticProvider {}
pub trait RustSemanticCombinator: SemanticProvider {}
pub trait SemanticOverride: SemanticProvider {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResolutionKind {
    Generated,
    RustCombinator,
    Override,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SemanticResolution {
    pub kind: ResolutionKind,
    pub rule_id: SemanticRuleId,
    pub semantic_version: SemanticVersion,
}

/// Resolves a decoded form to exactly one authoritative semantic provider.
/// Ambiguous resolution is always an error; registration order is not priority.
pub trait SemanticRegistry: Send + Sync {
    fn resolve(
        &self,
        insn: &dyn DecodedInstructionView,
        version: SemanticVersion,
    ) -> Result<SemanticResolution, SemanticError>;
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BlockValidityKey {
    pub image: ImageId,
    pub block: BlockId,
    pub address: Address,
    pub semantic_version: SemanticVersion,
    pub target_profile: TargetProfileId,
    pub code_versions: Vec<CodeVersionGuard>,
}

/// Sink for compact execution IR. Semantic code intentionally knows nothing
/// about concrete JIT/compiler backend objects.
pub trait ExecutionIrSink {
    type Output;

    fn begin_block(&mut self, key: &BlockValidityKey) -> Result<(), SemanticError>;
    fn lower_value(&mut self, value: ValueId) -> Result<(), SemanticError>;
    fn lower_effect(&mut self, effect: EffectId) -> Result<(), SemanticError>;
    fn finish_block(&mut self) -> Result<Self::Output, SemanticError>;
}

/// Boundary between sealed rich semantic IR and compact execution IR.
pub trait SemanticLowerer: Send + Sync {
    type RichBlock;
    type Output;
    type Error;

    fn lower(&self, rich: &Self::RichBlock, key: &BlockValidityKey) -> Result<Self::Output, Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_arch::{InstructionModifiers, Operand, OperandVisibility, RegisterView};

    #[test]
    fn normalized_decode_is_directly_visible_to_semantics() {
        let decoded = DecodedInstruction {
            address: 0x401000,
            length: 3,
            form_id: 42,
            features: vec![FeatureId(7)],
            operands: vec![Operand {
                index: 2,
                width_bits: 64,
                access: AccessKind::ReadWrite,
                visibility: OperandVisibility::Explicit,
                kind: OperandKind::Register(RegisterView::full(RegisterId(3), 64)),
            }],
            modifiers: InstructionModifiers::default(),
        };

        assert_eq!(DecodedInstructionView::address(&decoded), 0x401000);
        assert_eq!(DecodedInstructionView::form_id(&decoded), 42);
        assert_eq!(DecodedInstructionView::feature_ids(&decoded), &[FeatureId(7)]);
        assert_eq!(DecodedInstructionView::operand_count(&decoded), 1);
        assert_eq!(
            DecodedInstructionView::operand(&decoded, 2),
            Some(OperandDescriptor {
                index: 2,
                width_bits: 64,
                read: true,
                written: true,
                class: OperandClass::Register,
                kind: OperandKind::Register(RegisterView::full(RegisterId(3), 64)),
            })
        );
        assert_eq!(DecodedInstructionView::operand(&decoded, 0), None);
    }
}
