#![forbid(unsafe_code)]

//! Architectural contracts for Angryier semantic definition, lowering, and atomic execution publication.
//!
//! This crate intentionally contains interfaces and data contracts only. It does not implement Intel XED
//! decoding, instruction semantics, solver translation, JIT compilation, or execution.

use core::fmt::Debug;

pub type Address = u64;
pub type FormId = u32;
pub type FeatureId = u32;
pub type RegisterId = u16;
pub type SemanticRuleId = u32;
pub type ValueId = u32;
pub type EffectId = u32;
pub type TargetProfileId = u64;
pub type ImageId = u64;
pub type CodePageId = u64;
pub type StateId = u64;
pub type ProvenanceSeq = u64;
pub type LedgerEpoch = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SemanticVersion(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CodePageVersion(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlockId(pub u64);

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
pub enum FidelityProfile {
    Prove,
    Explore,
    Hunt,
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
pub struct OperandDescriptor {
    pub index: u8,
    pub ty: SemanticType,
    pub read: bool,
    pub written: bool,
}

/// Decoder-facing view. XED-specific objects must not cross this boundary.
pub trait DecodedInstructionView: Debug + Send + Sync {
    fn address(&self) -> Address;
    fn form_id(&self) -> FormId;
    fn length(&self) -> u8;
    fn feature_ids(&self) -> &[FeatureId];
    fn operands(&self) -> &[OperandDescriptor];
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
/// Semantic definitions emit into this interface. They do not construct the compact execution IR directly.
pub trait SemanticBuilder {
    fn constant(&mut self, ty: SemanticType, bytes_le: &[u8]) -> Result<ValueId, SemanticError>;
    fn read_register(&mut self, reg: RegisterId, ty: SemanticType) -> Result<ValueId, SemanticError>;
    fn read_operand(&mut self, operand_index: u8) -> Result<ValueId, SemanticError>;
    fn emit(
        &mut self,
        op: SemanticOp,
        ty: SemanticType,
        inputs: &[ValueId],
    ) -> Result<ValueId, SemanticError>;
    fn write_register(&mut self, reg: RegisterId, value: ValueId) -> Result<EffectId, SemanticError>;
    fn write_operand(&mut self, operand_index: u8, value: ValueId) -> Result<EffectId, SemanticError>;
    fn side_effect(&mut self, effect: SideEffect, inputs: &[ValueId]) -> Result<EffectId, SemanticError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SemanticReceipt {
    pub rule_id: SemanticRuleId,
    pub origin: SemanticOrigin,
    pub semantic_version: SemanticVersion,
}

/// Shared contract implemented by any semantic provider.
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

/// Marker for machine-generated, declarative instruction-family semantics.
pub trait GeneratedSemanticFamily: SemanticProvider {}

/// Marker for typed Rust combinators used by regular but non-trivial semantic families.
pub trait RustSemanticCombinator: SemanticProvider {}

/// Marker for exceptional handwritten semantics such as difficult AMX, gather/scatter,
/// floating-point, CET, or other instructions that do not fit the declarative generator cleanly.
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

/// Resolves one decoded form to exactly one authoritative semantic provider.
/// Ambiguous resolution is an error and must never be handled by provider ordering alone.
pub trait SemanticRegistry: Send + Sync {
    fn resolve(
        &self,
        insn: &dyn DecodedInstructionView,
        version: SemanticVersion,
    ) -> Result<SemanticResolution, SemanticError>;
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CodeVersionGuard {
    pub page: CodePageId,
    pub version: CodePageVersion,
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

/// Sink for compact execution IR. The semantic layer intentionally knows nothing about concrete JIT objects.
pub trait ExecutionIrSink {
    type Output;

    fn begin_block(&mut self, key: &BlockValidityKey) -> Result<(), SemanticError>;
    fn lower_value(&mut self, value: ValueId) -> Result<(), SemanticError>;
    fn lower_effect(&mut self, effect: EffectId) -> Result<(), SemanticError>;
    fn finish_block(&mut self) -> Result<Self::Output, SemanticError>;
}

/// Boundary between rich semantic IR and compact execution IR.
///
/// Any lowering result is valid only for the supplied semantic version, target profile, and code-page versions.
pub trait SemanticLowerer: Send + Sync {
    type RichBlock;
    type Output;

    fn lower(
        &self,
        rich: &Self::RichBlock,
        key: &BlockValidityKey,
    ) -> Result<Self::Output, SemanticError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LedgerSnapshot {
    pub epoch: LedgerEpoch,
    pub state_id: StateId,
    pub provenance_seq: ProvenanceSeq,
    pub semantic_version: SemanticVersion,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct LedgerMutation {
    pub state_id: StateId,
    pub semantic_version: SemanticVersion,
    pub code_versions: Vec<CodeVersionGuard>,
    pub provenance_from: ProvenanceSeq,
    pub provenance_to: ProvenanceSeq,
    pub replay_checkpoint: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CommitStamp {
    pub epoch: LedgerEpoch,
    pub state_id: StateId,
    pub provenance_seq: ProvenanceSeq,
    pub semantic_version: SemanticVersion,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerError {
    StaleEpoch,
    StaleCodeVersion,
    SemanticVersionMismatch,
    ProvenanceGap,
    ReplayCheckpointMismatch,
    Conflict,
}

/// Atomic publication boundary for execution state, code-page versions, provenance, and replay metadata.
///
/// Contract: a successful commit makes all fields in `LedgerMutation` visible under one new epoch.
/// A failed commit publishes none of them. JIT invalidation, state mutation, provenance advancement, and replay
/// checkpoint visibility must never be committed independently.
pub trait ExecutionLedger: Send + Sync {
    type Transaction;

    fn begin(&self, base: LedgerSnapshot) -> Result<Self::Transaction, LedgerError>;
    fn commit(
        &self,
        transaction: Self::Transaction,
        mutation: LedgerMutation,
    ) -> Result<CommitStamp, LedgerError>;
    fn abort(&self, transaction: Self::Transaction);
}

/// JIT/block-cache validity must be tested against the same ledger-visible code versions used by replay/provenance.
pub trait BlockValidityOracle: Send + Sync {
    fn is_valid(&self, key: &BlockValidityKey, snapshot: LedgerSnapshot) -> bool;
}

/// Architectural stress-test hook. These assumptions are hypotheses, not correctness dependencies.
pub trait ArchitectureStressProbe: Send + Sync {
    fn context_switch_pressure(&self) -> u64;
    fn solver_fallback_pressure(&self) -> u64;
    fn ledger_conflict_rate_ppm(&self) -> u64;
}
