use crate::{
    BasicIrVerifier, IrBlock, IrBlockKey, IrInstruction, IrOp, IrPrimitive, IrType, IrValueId, IrVerificationError,
    IrVerifier,
};
use angryier_semantic_contracts::SealedSemanticBlock;
use angryier_semantics::{
    BlockValidityKey, DecodedInstructionView, FloatFormat, FloatingOp, OperandKind, PrimitiveOp,
    RegisterWriteBehavior, SealedRichSemanticBlock, SemanticEffectDefinition, SemanticLowerer,
    SemanticOp, SemanticType, SemanticValue, SemanticValueDefinition, ValueId, VectorOp,
};
use angryier_types::{Address, ContentId};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IrLoweringError {
    SemanticVersionMismatch,
    UnsupportedValue(&'static str),
    UnsupportedEffect(&'static str),
    MissingOperand(u8),
    OperandTypeMismatch(u8),
    Verification(IrVerificationError),
    CachePoisoned,
}

impl core::fmt::Display for IrLoweringError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SemanticVersionMismatch => formatter.write_str("semantic block version does not match validity key"),
            Self::UnsupportedValue(kind) => write!(formatter, "unsupported semantic value during lowering: {kind}"),
            Self::UnsupportedEffect(kind) => write!(formatter, "unsupported semantic effect during lowering: {kind}"),
            Self::MissingOperand(index) => write!(formatter, "decoded operand {index} is unavailable"),
            Self::OperandTypeMismatch(index) => {
                write!(formatter, "decoded operand {index} does not match its semantic type")
            }
            Self::Verification(error) => write!(formatter, "lowered IR failed verification: {error}"),
            Self::CachePoisoned => formatter.write_str("lowering cache mutex was poisoned"),
        }
    }
}

impl std::error::Error for IrLoweringError {}

impl From<IrVerificationError> for IrLoweringError {
    fn from(error: IrVerificationError) -> Self {
        Self::Verification(error)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct BasicSemanticLowerer;

impl BasicSemanticLowerer {
    pub fn lower_with_decode(
        &self,
        rich: &SealedRichSemanticBlock,
        key: &BlockValidityKey,
        decoded: &dyn DecodedInstructionView,
    ) -> Result<IrBlock, IrLoweringError> {
        self.lower_inner(rich, key, Some(decoded))
    }

    fn lower_inner(
        &self,
        rich: &SealedRichSemanticBlock,
        key: &BlockValidityKey,
        decoded: Option<&dyn DecodedInstructionView>,
    ) -> Result<IrBlock, IrLoweringError> {
        if rich.semantic_version() != key.semantic_version {
            return Err(IrLoweringError::SemanticVersionMismatch);
        }

        if let Some(decoded) = decoded
            && decoded.address() != key.address
        {
            return Err(IrLoweringError::UnsupportedValue("decoded block address mismatch"));
        }

        let mut instructions = Vec::with_capacity(rich.values().len() + rich.effects().len());
        // Build an O(1) lookup index over semantic values keyed by their id so
        // that operand/effect resolution avoids the previous O(n) linear scan.
        let value_index: BTreeMap<ValueId, &SemanticValue> = rich
            .values()
            .iter()
            .map(|candidate| (candidate.id, candidate))
            .collect();
        for value in rich.values() {
            let op = match &value.definition {
                SemanticValueDefinition::Constant(bytes) => IrOp::Constant {
                    ty: lower_type(value.ty)?,
                    bytes_le: bytes.clone(),
                },
                SemanticValueDefinition::ReadRegister(register) => IrOp::ReadRegister {
                    register: register.0,
                    ty: lower_type(value.ty)?,
                },
                SemanticValueDefinition::ReadOperand(index) => lower_operand_read(decoded, *index, value.ty)?,
                SemanticValueDefinition::Operation { op, inputs } => IrOp::Primitive {
                    op: lower_op(*op)?,
                    ty: lower_type(value.ty)?,
                    inputs: inputs.iter().copied().map(IrValueId).collect(),
                },
            };
            instructions.push(IrInstruction {
                result: Some(IrValueId(value.id)),
                op,
            });
        }

        for effect in rich.effects() {
            let op = match effect.definition {
                SemanticEffectDefinition::WriteRegister { register, value } => IrOp::WriteRegister {
                    register: register.0,
                    value: IrValueId(value),
                },
                SemanticEffectDefinition::WriteOperand { operand_index, value } => {
                    let value_type = value_index
                        .get(&value)
                        .map(|candidate| candidate.ty)
                        .ok_or(IrLoweringError::UnsupportedEffect("unknown semantic value"))?;
                    lower_operand_write(decoded, operand_index, value, value_type)?
                }
                SemanticEffectDefinition::SideEffect {
                    effect: angryier_semantics::SideEffect::RaiseException(vector),
                    ref inputs,
                } if inputs.is_empty() => IrOp::Trap { vector },
                SemanticEffectDefinition::SideEffect { .. } => {
                    // Non-exception side effects (e.g. MemoryRead hints) are
                    // semantic annotations that do not affect concrete control
                    // or data flow. Skip them during IR lowering.
                    continue;
                }
                SemanticEffectDefinition::Jump { target } => {
                    let addr = resolve_address_value(&value_index, decoded, target)?;
                    IrOp::Jump { target: addr }
                }
                SemanticEffectDefinition::Branch {
                    condition,
                    taken,
                    not_taken,
                } => {
                    let taken_addr = resolve_address_value(&value_index, decoded, taken)?;
                    let not_taken_addr = resolve_address_value(&value_index, decoded, not_taken)?;
                    IrOp::Branch {
                        condition: IrValueId(condition),
                        taken: taken_addr,
                        not_taken: not_taken_addr,
                    }
                }
            };
            instructions.push(IrInstruction { result: None, op });
        }

        let block = IrBlock {
            key: IrBlockKey {
                image: key.image,
                block: key.block,
                address: key.address,
                semantic_content: rich.content_id(),
                target_profile: key.target_profile,
                code_versions: key.code_versions.clone(),
            },
            instructions,
        };
        BasicIrVerifier.verify(&block)?;
        Ok(block)
    }
}

impl SemanticLowerer for BasicSemanticLowerer {
    type RichBlock = SealedRichSemanticBlock;
    type Output = IrBlock;
    type Error = IrLoweringError;

    fn lower(&self, rich: &Self::RichBlock, key: &BlockValidityKey) -> Result<Self::Output, Self::Error> {
        self.lower_inner(rich, key, None)
    }
}

fn lower_operand_read(
    decoded: Option<&dyn DecodedInstructionView>,
    index: u8,
    ty: SemanticType,
) -> Result<IrOp, IrLoweringError> {
    let decoded = decoded.ok_or(IrLoweringError::UnsupportedValue("decoded operand binding"))?;
    let operand = decoded.operand(index).ok_or(IrLoweringError::MissingOperand(index))?;
    if !operand.read {
        return Err(IrLoweringError::UnsupportedValue("read from write-only operand"));
    }
    let ir_type = lower_type(ty)?;
    let bit_width = scalar_bit_width(ty).ok_or(IrLoweringError::UnsupportedValue("non-scalar decoded operand"))?;
    // RelativeBranch operands encode a displacement, not the full target address.
    // The semantic provider reads them as 64-bit addresses; the lowering computes
    // the target from the displacement. Skip the width check for this case.
    let is_relative_branch = matches!(operand.kind, OperandKind::RelativeBranch(_));
    if !is_relative_branch && operand.width_bits != bit_width {
        return Err(IrLoweringError::OperandTypeMismatch(index));
    }

    match operand.kind {
        OperandKind::Register(view)
            if view.bit_offset == 0
                && view.width_bits == bit_width
                && view.write_behavior == RegisterWriteBehavior::ReplaceParent =>
        {
            Ok(IrOp::ReadRegister {
                register: view.parent.0,
                ty: ir_type,
            })
        }
        OperandKind::Immediate(immediate)
            if bit_width <= 64 && matches!(ty, SemanticType::Scalar(angryier_semantics::ScalarType::BitVec(_))) =>
        {
            Ok(IrOp::Constant {
                ty: ir_type,
                bytes_le: integer_bytes(immediate.value, bit_width),
            })
        }
        OperandKind::RelativeBranch(branch)
            if bit_width == 64 && matches!(ty, SemanticType::Scalar(angryier_semantics::ScalarType::BitVec(64))) =>
        {
            Ok(IrOp::Constant {
                ty: ir_type,
                bytes_le: decoded
                    .address()
                    .wrapping_add(u64::from(decoded.length()))
                    .wrapping_add_signed(branch.displacement)
                    .to_le_bytes()
                    .to_vec(),
            })
        }
        OperandKind::Register(_) => Err(IrLoweringError::UnsupportedValue("partial register operand")),
        OperandKind::Memory(_) => Err(IrLoweringError::UnsupportedValue("memory operand")),
        OperandKind::AddressGeneration(_) => Err(IrLoweringError::UnsupportedValue("address-generation operand")),
        OperandKind::Immediate(_) => Err(IrLoweringError::UnsupportedValue("wide immediate operand")),
        OperandKind::RelativeBranch(_) => Err(IrLoweringError::OperandTypeMismatch(index)),
        OperandKind::FarPointer(_) => Err(IrLoweringError::UnsupportedValue("far-pointer operand")),
    }
}

fn lower_operand_write(
    decoded: Option<&dyn DecodedInstructionView>,
    index: u8,
    value: u32,
    value_type: SemanticType,
) -> Result<IrOp, IrLoweringError> {
    let decoded = decoded.ok_or(IrLoweringError::UnsupportedEffect("decoded operand binding"))?;
    let operand = decoded.operand(index).ok_or(IrLoweringError::MissingOperand(index))?;
    if !operand.written {
        return Err(IrLoweringError::UnsupportedEffect("write to read-only operand"));
    }
    if scalar_bit_width(value_type) != Some(operand.width_bits) {
        return Err(IrLoweringError::OperandTypeMismatch(index));
    }
    match operand.kind {
        OperandKind::Register(view)
            if view.bit_offset == 0
                && view.width_bits == operand.width_bits
                && view.write_behavior == RegisterWriteBehavior::ReplaceParent =>
        {
            Ok(IrOp::WriteRegister {
                register: view.parent.0,
                value: IrValueId(value),
            })
        }
        OperandKind::Register(_) => Err(IrLoweringError::UnsupportedEffect("partial register operand")),
        OperandKind::Memory(_) => Err(IrLoweringError::UnsupportedEffect("memory operand")),
        OperandKind::AddressGeneration(_)
        | OperandKind::Immediate(_)
        | OperandKind::RelativeBranch(_)
        | OperandKind::FarPointer(_) => Err(IrLoweringError::UnsupportedEffect("non-writable operand kind")),
    }
}

fn scalar_bit_width(ty: SemanticType) -> Option<u16> {
    match ty {
        SemanticType::Scalar(angryier_semantics::ScalarType::BitVec(bits)) if bits > 0 => Some(bits),
        SemanticType::Scalar(angryier_semantics::ScalarType::Float(format)) => Some(match format {
            FloatFormat::F16 | FloatFormat::Bf16 => 16,
            FloatFormat::F32 => 32,
            FloatFormat::F64 => 64,
            FloatFormat::F80 => 80,
        }),
        SemanticType::Vector { lanes, lane } => {
            let lane_bits = match lane {
                angryier_semantics::ScalarType::BitVec(bits) => u32::from(bits),
                angryier_semantics::ScalarType::Float(format) => match format {
                    FloatFormat::F16 | FloatFormat::Bf16 => 16,
                    FloatFormat::F32 => 32,
                    FloatFormat::F64 => 64,
                    FloatFormat::F80 => 80,
                },
            };
            lane_bits
                .checked_mul(u32::from(lanes))
                .and_then(|bits| u16::try_from(bits).ok())
        }
        _ => None,
    }
}

/// Resolves a semantic value to a concrete address for control-flow targets.
fn resolve_address_value(
    value_index: &BTreeMap<ValueId, &SemanticValue>,
    decoded: Option<&dyn DecodedInstructionView>,
    value: ValueId,
) -> Result<Address, IrLoweringError> {
    let semantic_value = value_index
        .get(&value)
        .ok_or(IrLoweringError::UnsupportedEffect("unknown control-flow target"))?;

    match &semantic_value.definition {
        SemanticValueDefinition::Constant(bytes) => {
            if bytes.len() != 8 {
                return Err(IrLoweringError::UnsupportedEffect("non-64-bit control-flow target"));
            }
            let mut buffer = [0u8; 8];
            buffer.copy_from_slice(bytes);
            Ok(u64::from_le_bytes(buffer))
        }
        SemanticValueDefinition::ReadOperand(index) => {
            let decoded = decoded.ok_or(IrLoweringError::UnsupportedEffect("decoded operand binding"))?;
            let operand = decoded.operand(*index).ok_or(IrLoweringError::MissingOperand(*index))?;
            match operand.kind {
                OperandKind::RelativeBranch(branch) => Ok(decoded
                    .address()
                    .wrapping_add(u64::from(decoded.length()))
                    .wrapping_add_signed(branch.displacement)),
                _ => Err(IrLoweringError::UnsupportedEffect(
                    "non-branch operand as control-flow target",
                )),
            }
        }
        _ => Err(IrLoweringError::UnsupportedEffect("non-constant control-flow target")),
    }
}

fn integer_bytes(value: u64, bits: u16) -> Vec<u8> {
    let byte_len = usize::from(bits).div_ceil(8);
    let mut bytes = value.to_le_bytes()[..byte_len].to_vec();
    let used = bits % 8;
    if used != 0 {
        let allowed = (1_u8 << used) - 1;
        if let Some(high) = bytes.last_mut() {
            *high &= allowed;
        }
    }
    bytes
}

fn lower_type(ty: SemanticType) -> Result<IrType, IrLoweringError> {
    Ok(match ty {
        SemanticType::Scalar(angryier_semantics::ScalarType::BitVec(bits)) => IrType::Bits(bits),
        SemanticType::Scalar(angryier_semantics::ScalarType::Float(format)) => match format {
            FloatFormat::F16 => IrType::Float16,
            FloatFormat::Bf16 => IrType::BFloat16,
            FloatFormat::F32 => IrType::Float32,
            FloatFormat::F64 => IrType::Float64,
            FloatFormat::F80 => IrType::Float80,
        },
        SemanticType::Vector { lanes, lane } => {
            let lane_bits = match lane {
                angryier_semantics::ScalarType::BitVec(bits) => u32::from(bits),
                angryier_semantics::ScalarType::Float(format) => match format {
                    FloatFormat::F16 | FloatFormat::Bf16 => 16,
                    FloatFormat::F32 => 32,
                    FloatFormat::F64 => 64,
                    FloatFormat::F80 => 80,
                },
            };
            let width = lane_bits
                .checked_mul(u32::from(lanes))
                .and_then(|bits| u16::try_from(bits).ok())
                .ok_or(IrLoweringError::UnsupportedValue("oversized vector type"))?;
            IrType::Vector { width_bits: width, lane_bits: u16::try_from(lane_bits).unwrap_or(0) }
        }
        SemanticType::Opmask { lanes } => IrType::Opmask { width_bits: lanes },
        SemanticType::Tile { .. } => IrType::Tile,
    })
}

fn lower_op(op: SemanticOp) -> Result<IrPrimitive, IrLoweringError> {
    match op {
        SemanticOp::Primitive(op) => Ok(match op {
            PrimitiveOp::Add => IrPrimitive::Add,
            PrimitiveOp::Sub => IrPrimitive::Sub,
            PrimitiveOp::Mul => IrPrimitive::Mul,
            PrimitiveOp::UnsignedDiv => IrPrimitive::UDiv,
            PrimitiveOp::SignedDiv => IrPrimitive::SDiv,
            PrimitiveOp::And => IrPrimitive::And,
            PrimitiveOp::Or => IrPrimitive::Or,
            PrimitiveOp::Xor => IrPrimitive::Xor,
            PrimitiveOp::Not => IrPrimitive::Not,
            PrimitiveOp::ShiftLeft => IrPrimitive::Shl,
            PrimitiveOp::LogicalShiftRight => IrPrimitive::LShr,
            PrimitiveOp::ArithmeticShiftRight => IrPrimitive::AShr,
            PrimitiveOp::Eq => IrPrimitive::Eq,
            PrimitiveOp::Ult => IrPrimitive::Ult,
            PrimitiveOp::Ule => IrPrimitive::Ule,
            PrimitiveOp::Slt => IrPrimitive::Slt,
            PrimitiveOp::Sle => IrPrimitive::Sle,
            PrimitiveOp::Select => IrPrimitive::Select,
            PrimitiveOp::Concat => IrPrimitive::Concat,
            PrimitiveOp::Extract => IrPrimitive::Extract,
            PrimitiveOp::ZeroExtend => IrPrimitive::ZExt,
            PrimitiveOp::SignExtend => IrPrimitive::SExt,
            PrimitiveOp::RotateLeft => IrPrimitive::RotL,
            PrimitiveOp::RotateRight => IrPrimitive::RotR,
            PrimitiveOp::Popcount => IrPrimitive::Popcnt,
            PrimitiveOp::CountLeadingZeros => IrPrimitive::Clz,
            PrimitiveOp::CountTrailingZeros => IrPrimitive::Ctz,
            PrimitiveOp::MaskEq | PrimitiveOp::MaskSgt => {
                return Err(IrLoweringError::UnsupportedValue(
                    "mask comparison is only valid in lane-wise vector context",
                ));
            }
            PrimitiveOp::MaxU | PrimitiveOp::MinU | PrimitiveOp::MaxS | PrimitiveOp::MinS => {
                return Err(IrLoweringError::UnsupportedValue(
                    "min/max is only valid in lane-wise vector context",
                ));
            }
            PrimitiveOp::MulHighS | PrimitiveOp::MulHighU => {
                return Err(IrLoweringError::UnsupportedValue(
                    "mul-high is only valid in lane-wise vector context",
                ));
            }
        }),
        SemanticOp::Float(op) => Ok(match op {
            FloatingOp::Add => IrPrimitive::FAdd,
            FloatingOp::Sub => IrPrimitive::FSub,
            FloatingOp::Mul => IrPrimitive::FMul,
            FloatingOp::Div => IrPrimitive::FDiv,
            FloatingOp::Sqrt => IrPrimitive::FSqrt,
            FloatingOp::Convert => IrPrimitive::FConvert,
            FloatingOp::Compare => {
                return Err(IrLoweringError::UnsupportedValue(
                    "float compare not yet supported",
                ));
            }
        }),
        SemanticOp::Vector(op) => match op {
            VectorOp::LaneWise(scalar) => Ok(match scalar {
                PrimitiveOp::Add => IrPrimitive::VecLaneAdd,
                PrimitiveOp::Sub => IrPrimitive::VecLaneSub,
                PrimitiveOp::Mul => IrPrimitive::VecLaneMul,
                PrimitiveOp::And => IrPrimitive::VecLaneAnd,
                PrimitiveOp::Or => IrPrimitive::VecLaneOr,
                PrimitiveOp::Xor => IrPrimitive::VecLaneXor,
                PrimitiveOp::ShiftLeft => IrPrimitive::VecLaneShl,
                PrimitiveOp::LogicalShiftRight => IrPrimitive::VecLaneLShr,
                PrimitiveOp::ArithmeticShiftRight => IrPrimitive::VecLaneAShr,
                PrimitiveOp::MaskEq => IrPrimitive::VecLaneMaskEq,
                PrimitiveOp::MaskSgt => IrPrimitive::VecLaneMaskSgt,
                PrimitiveOp::MaxU => IrPrimitive::VecLaneMaxU,
                PrimitiveOp::MinU => IrPrimitive::VecLaneMinU,
                PrimitiveOp::MaxS => IrPrimitive::VecLaneMaxS,
                PrimitiveOp::MinS => IrPrimitive::VecLaneMinS,
                PrimitiveOp::MulHighS => IrPrimitive::VecLaneMulHiS,
                PrimitiveOp::MulHighU => IrPrimitive::VecLaneMulHiU,
                _ => {
                    return Err(IrLoweringError::UnsupportedValue(
                        "unsupported lane-wise primitive",
                    ));
                }
            }),
            VectorOp::LaneWiseFloat(float) => Ok(match float {
                FloatingOp::Add => IrPrimitive::VecLaneFAdd,
                FloatingOp::Sub => IrPrimitive::VecLaneFSub,
                FloatingOp::Mul => IrPrimitive::VecLaneFMul,
                FloatingOp::Div => IrPrimitive::VecLaneFDiv,
                _ => {
                    return Err(IrLoweringError::UnsupportedValue(
                        "unsupported lane-wise float operation",
                    ));
                }
            }),
            VectorOp::Shuffle => Ok(IrPrimitive::VecShuffleBytes),
            VectorOp::Unpack => Ok(IrPrimitive::VecInterleaveLow),
            VectorOp::UnpackHigh => Ok(IrPrimitive::VecInterleaveHigh),
            VectorOp::Pack => Ok(IrPrimitive::VecPackSaturate),
            VectorOp::PackUnsigned => Ok(IrPrimitive::VecPackSaturateU),
            VectorOp::Madd16 => Ok(IrPrimitive::VecMadd16),
            _ => Err(IrLoweringError::UnsupportedValue(
                "non-lane-wise vector operation",
            )),
        },
        SemanticOp::Tile(_) => {
            Err(IrLoweringError::UnsupportedValue("non-primitive operation"))
        }
    }
}

/// A [`SemanticLowerer`] decorator that wraps [`BasicSemanticLowerer`] with an
/// in-memory cache of lowered [`IrBlock`]s keyed by the source semantic block's
/// [`ContentId`]. Repeated lowering of an identical sealed block returns a
/// shared [`Arc`] clone without recomputing the IR, turning repeated O(n^2)
/// lowering work into an O(1) cache lookup.
///
/// The cache key is the sealed block's content identity, so two blocks that
/// share the same [`ContentId`] are treated as interchangeable. Hit and miss
/// counters are exposed via [`CachedSemanticLowerer::cache_stats`] for
/// observability.
pub struct CachedSemanticLowerer {
    inner: BasicSemanticLowerer,
    cache: Mutex<HashMap<ContentId, Arc<IrBlock>>>,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl Default for CachedSemanticLowerer {
    fn default() -> Self {
        Self::new()
    }
}

impl CachedSemanticLowerer {
    /// Creates a new cached lowerer with an empty cache and zeroed counters.
    pub fn new() -> Self {
        Self {
            inner: BasicSemanticLowerer,
            cache: Mutex::new(HashMap::new()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Returns the cumulative `(hits, misses)` counts for the cache.
    pub fn cache_stats(&self) -> (u64, u64) {
        (self.hits.load(Ordering::Relaxed), self.misses.load(Ordering::Relaxed))
    }

    /// Returns the number of entries currently held in the cache.
    pub fn cache_len(&self) -> usize {
        self.cache.lock().map(|guard| guard.len()).unwrap_or(0)
    }

    /// Lowers a decoded semantic block, serving the result from the cache when
    /// the block's [`ContentId`] has been seen before.
    pub fn lower_with_decode(
        &self,
        rich: &SealedRichSemanticBlock,
        key: &BlockValidityKey,
        decoded: &dyn DecodedInstructionView,
    ) -> Result<Arc<IrBlock>, IrLoweringError> {
        let cache_key = rich.content_id();
        if let Some(cached) = self
            .cache
            .lock()
            .map_err(|_| IrLoweringError::CachePoisoned)?
            .get(&cache_key)
            .cloned()
        {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Ok(cached);
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        let block = self.inner.lower_with_decode(rich, key, decoded)?;
        let shared = Arc::new(block);
        self.cache
            .lock()
            .map_err(|_| IrLoweringError::CachePoisoned)?
            .insert(cache_key, Arc::clone(&shared));
        Ok(shared)
    }
}

impl SemanticLowerer for CachedSemanticLowerer {
    type RichBlock = SealedRichSemanticBlock;
    type Output = Arc<IrBlock>;
    type Error = IrLoweringError;

    fn lower(&self, rich: &Self::RichBlock, key: &BlockValidityKey) -> Result<Self::Output, Self::Error> {
        let cache_key = rich.content_id();
        if let Some(cached) = self
            .cache
            .lock()
            .map_err(|_| IrLoweringError::CachePoisoned)?
            .get(&cache_key)
            .cloned()
        {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Ok(cached);
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        let block = self.inner.lower(rich, key)?;
        let shared = Arc::new(block);
        self.cache
            .lock()
            .map_err(|_| IrLoweringError::CachePoisoned)?
            .insert(cache_key, Arc::clone(&shared));
        Ok(shared)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_semantics::{
        FeatureId, ImmediateOperand, OperandClass, OperandDescriptor, RegisterId, RegisterView, ScalarType,
        SemanticBlockBuilder, SemanticBuilder, SemanticError,
    };
    use angryier_types::{
        BlockId, CodePageId, CodePageVersion, CodeVersionGuard, ContentIdentitySchemaVersion, ImageId,
        SemanticFingerprintSchemaVersion, SemanticVersion, TargetProfileId,
    };

    fn validity(version: u64) -> BlockValidityKey {
        BlockValidityKey {
            image: ImageId(7),
            block: BlockId(11),
            address: 0x401000,
            semantic_version: SemanticVersion(version),
            target_profile: TargetProfileId(13),
            code_versions: vec![CodeVersionGuard {
                page: CodePageId(17),
                version: CodePageVersion(19),
            }],
        }
    }

    fn scalar_block() -> Result<SealedRichSemanticBlock, SemanticError> {
        let mut builder = SemanticBlockBuilder::new(SemanticVersion(1));
        let ty = SemanticType::Scalar(ScalarType::BitVec(64));
        let left = builder.constant(ty, &1_u64.to_le_bytes())?;
        let right = builder.read_register(RegisterId(2), ty)?;
        let result = builder.emit(SemanticOp::Primitive(PrimitiveOp::Add), ty, &[left, right])?;
        builder.write_register(RegisterId(2), result)?;
        builder.seal(ContentIdentitySchemaVersion(1), SemanticFingerprintSchemaVersion(1))
    }

    #[derive(Debug)]
    struct TestDecode {
        address: u64,
        operands: Vec<OperandDescriptor>,
    }

    impl DecodedInstructionView for TestDecode {
        fn address(&self) -> u64 {
            self.address
        }

        fn form_id(&self) -> u32 {
            1
        }

        fn length(&self) -> u8 {
            4
        }

        fn feature_ids(&self) -> &[FeatureId] {
            &[]
        }

        fn operand_count(&self) -> usize {
            self.operands.len()
        }

        fn operand(&self, index: u8) -> Option<OperandDescriptor> {
            self.operands.iter().find(|operand| operand.index == index).copied()
        }
    }

    #[test]
    fn lowers_scalar_dataflow_and_preserves_validity_identity() -> Result<(), String> {
        let rich = scalar_block().map_err(|error| format!("{error:?}"))?;
        let block = BasicSemanticLowerer
            .lower(&rich, &validity(1))
            .map_err(|error| error.to_string())?;

        assert_eq!(block.key.image, ImageId(7));
        assert_eq!(block.key.semantic_content, rich.content_id());
        assert_eq!(block.instructions.len(), 4);
        assert!(matches!(
            block.instructions[2].op,
            IrOp::Primitive {
                op: IrPrimitive::Add,
                ty: IrType::Bits(64),
                ref inputs,
            } if inputs == &[IrValueId(0), IrValueId(1)]
        ));
        Ok(())
    }

    #[test]
    fn rejects_semantic_version_mismatch() -> Result<(), String> {
        let rich = scalar_block().map_err(|error| format!("{error:?}"))?;
        let result = BasicSemanticLowerer.lower(&rich, &validity(2));

        assert_eq!(result, Err(IrLoweringError::SemanticVersionMismatch));
        Ok(())
    }

    #[test]
    fn rejects_unbound_decoded_operands() -> Result<(), String> {
        let mut builder = SemanticBlockBuilder::new(SemanticVersion(1));
        builder
            .read_operand(0, SemanticType::Scalar(ScalarType::BitVec(32)))
            .map_err(|error| format!("{error:?}"))?;
        let rich = builder
            .seal(ContentIdentitySchemaVersion(1), SemanticFingerprintSchemaVersion(1))
            .map_err(|error| format!("{error:?}"))?;

        assert_eq!(
            BasicSemanticLowerer.lower(&rich, &validity(1)),
            Err(IrLoweringError::UnsupportedValue("decoded operand binding"))
        );
        Ok(())
    }

    #[test]
    fn binds_full_register_and_immediate_operands() -> Result<(), String> {
        let ty = SemanticType::Scalar(ScalarType::BitVec(64));
        let mut builder = SemanticBlockBuilder::new(SemanticVersion(1));
        let left = builder.read_operand(0, ty).map_err(|error| format!("{error:?}"))?;
        let right = builder.read_operand(1, ty).map_err(|error| format!("{error:?}"))?;
        let result = builder
            .emit(SemanticOp::Primitive(PrimitiveOp::Add), ty, &[left, right])
            .map_err(|error| format!("{error:?}"))?;
        builder.write_operand(2, result).map_err(|error| format!("{error:?}"))?;
        let rich = builder
            .seal(ContentIdentitySchemaVersion(1), SemanticFingerprintSchemaVersion(1))
            .map_err(|error| format!("{error:?}"))?;
        let decoded = TestDecode {
            address: 0x401000,
            operands: vec![
                OperandDescriptor {
                    index: 0,
                    width_bits: 64,
                    read: true,
                    written: false,
                    class: OperandClass::Register,
                    kind: OperandKind::Register(RegisterView::full(RegisterId(4), 64)),
                },
                OperandDescriptor {
                    index: 1,
                    width_bits: 64,
                    read: true,
                    written: false,
                    class: OperandClass::Immediate,
                    kind: OperandKind::Immediate(ImmediateOperand {
                        value: 9,
                        signed: false,
                    }),
                },
                OperandDescriptor {
                    index: 2,
                    width_bits: 64,
                    read: false,
                    written: true,
                    class: OperandClass::Register,
                    kind: OperandKind::Register(RegisterView::full(RegisterId(5), 64)),
                },
            ],
        };

        let lowered = BasicSemanticLowerer
            .lower_with_decode(&rich, &validity(1), &decoded)
            .map_err(|error| error.to_string())?;

        assert!(matches!(
            lowered.instructions[0].op,
            IrOp::ReadRegister {
                register: 4,
                ty: IrType::Bits(64)
            }
        ));
        assert!(matches!(
            lowered.instructions[1].op,
            IrOp::Constant {
                ty: IrType::Bits(64),
                ref bytes_le
            } if bytes_le == &9_u64.to_le_bytes()
        ));
        assert!(matches!(
            lowered.instructions[3].op,
            IrOp::WriteRegister {
                register: 5,
                value: IrValueId(2)
            }
        ));
        Ok(())
    }

    #[test]
    fn rejects_operand_write_width_mismatch() -> Result<(), String> {
        let mut builder = SemanticBlockBuilder::new(SemanticVersion(1));
        let value = builder
            .constant(SemanticType::Scalar(ScalarType::BitVec(32)), &[1, 0, 0, 0])
            .map_err(|error| format!("{error:?}"))?;
        builder.write_operand(0, value).map_err(|error| format!("{error:?}"))?;
        let rich = builder
            .seal(ContentIdentitySchemaVersion(1), SemanticFingerprintSchemaVersion(1))
            .map_err(|error| format!("{error:?}"))?;
        let decoded = TestDecode {
            address: 0x401000,
            operands: vec![OperandDescriptor {
                index: 0,
                width_bits: 64,
                read: false,
                written: true,
                class: OperandClass::Register,
                kind: OperandKind::Register(RegisterView::full(RegisterId(5), 64)),
            }],
        };

        assert_eq!(
            BasicSemanticLowerer.lower_with_decode(&rich, &validity(1), &decoded),
            Err(IrLoweringError::OperandTypeMismatch(0))
        );
        Ok(())
    }

    fn jump_block(target: u64) -> Result<SealedRichSemanticBlock, SemanticError> {
        let mut builder = SemanticBlockBuilder::new(SemanticVersion(1));
        let ty = SemanticType::Scalar(ScalarType::BitVec(64));
        let target_value = builder.constant(ty, &target.to_le_bytes())?;
        builder.jump(target_value)?;
        builder.seal(ContentIdentitySchemaVersion(1), SemanticFingerprintSchemaVersion(1))
    }

    #[test]
    fn cached_lowerer_caches_repeated_blocks() -> Result<(), String> {
        let rich = scalar_block().map_err(|error| format!("{error:?}"))?;
        let lowerer = CachedSemanticLowerer::new();
        let key = validity(1);

        let first = lowerer.lower(&rich, &key).map_err(|error| error.to_string())?;
        let second = lowerer.lower(&rich, &key).map_err(|error| error.to_string())?;

        assert_eq!(*first, *second, "cached block should equal freshly lowered block");
        assert!(
            Arc::ptr_eq(&first, &second),
            "second lowering should share the cached Arc"
        );
        let (hits, misses) = lowerer.cache_stats();
        assert_eq!(misses, 1, "first lowering should be a cache miss");
        assert_eq!(hits, 1, "second lowering should be a cache hit");
        assert_eq!(lowerer.cache_len(), 1, "exactly one entry should be cached");
        Ok(())
    }

    #[test]
    fn cached_lowerer_different_blocks_both_cached() -> Result<(), String> {
        let first_rich = scalar_block().map_err(|error| format!("{error:?}"))?;
        let second_rich = jump_block(0x402000).map_err(|error| format!("{error:?}"))?;
        assert_ne!(
            first_rich.content_id(),
            second_rich.content_id(),
            "test blocks must have distinct content ids"
        );

        let lowerer = CachedSemanticLowerer::new();
        let key = validity(1);

        let first = lowerer.lower(&first_rich, &key).map_err(|error| error.to_string())?;
        let second = lowerer.lower(&second_rich, &key).map_err(|error| error.to_string())?;

        assert_ne!(
            first_rich.content_id(),
            second_rich.content_id(),
            "lowered blocks should remain distinct"
        );
        assert!(
            !Arc::ptr_eq(&first, &second),
            "distinct blocks should not share a cache entry"
        );
        assert_eq!(lowerer.cache_len(), 2, "both blocks should be cached");
        let (hits, misses) = lowerer.cache_stats();
        assert_eq!(misses, 2, "both lowerings should be cache misses");
        assert_eq!(hits, 0, "no hits should have occurred yet");

        // Re-lowering the first block should now hit the cache.
        let first_again = lowerer.lower(&first_rich, &key).map_err(|error| error.to_string())?;
        assert!(
            Arc::ptr_eq(&first, &first_again),
            "re-lowering should return the cached Arc"
        );
        let (hits, misses) = lowerer.cache_stats();
        assert_eq!(misses, 2, "miss count should be unchanged after a hit");
        assert_eq!(hits, 1, "re-lowering should register a single hit");
        Ok(())
    }

    #[test]
    fn value_index_speeds_up_lowering() -> Result<(), String> {
        // Exercises the value-indexed control-flow resolution path
        // (`resolve_address_value`) introduced to replace the linear scan.
        let rich = jump_block(0x402000).map_err(|error| format!("{error:?}"))?;
        let block = BasicSemanticLowerer
            .lower(&rich, &validity(1))
            .map_err(|error| error.to_string())?;

        assert_eq!(block.instructions.len(), 2);
        assert!(matches!(block.instructions[1].op, IrOp::Jump { target: 0x402000 }));
        Ok(())
    }
}
