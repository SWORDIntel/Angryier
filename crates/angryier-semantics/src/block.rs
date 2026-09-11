use crate::{
    EffectId, FloatFormat, FloatingOp, PrimitiveOp, RegisterId, SemanticBuilder, SemanticError, SemanticOp,
    SemanticType, SideEffect, TileOp, ValueId, VectorOp,
};
use angryier_semantic_contracts::SealedSemanticBlock;
use angryier_types::{
    ContentDomain, ContentId, ContentIdentitySchemaVersion, SemanticFingerprint, SemanticFingerprintSchemaVersion,
    SemanticVersion,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SemanticValueDefinition {
    Constant(Vec<u8>),
    ReadRegister(RegisterId),
    ReadOperand(u8),
    Operation { op: SemanticOp, inputs: Vec<ValueId> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticValue {
    pub id: ValueId,
    pub ty: SemanticType,
    pub definition: SemanticValueDefinition,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SemanticEffectDefinition {
    WriteRegister { register: RegisterId, value: ValueId },
    WriteOperand { operand_index: u8, value: ValueId },
    SideEffect { effect: SideEffect, inputs: Vec<ValueId> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticEffect {
    pub id: EffectId,
    pub definition: SemanticEffectDefinition,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticBlockBuilder {
    semantic_version: SemanticVersion,
    values: Vec<SemanticValue>,
    effects: Vec<SemanticEffect>,
}

impl SemanticBlockBuilder {
    pub fn new(semantic_version: SemanticVersion) -> Self {
        Self {
            semantic_version,
            values: Vec::new(),
            effects: Vec::new(),
        }
    }

    pub fn values(&self) -> &[SemanticValue] {
        &self.values
    }

    pub fn effects(&self) -> &[SemanticEffect] {
        &self.effects
    }

    pub fn seal(
        self,
        content_schema: ContentIdentitySchemaVersion,
        fingerprint_schema: SemanticFingerprintSchemaVersion,
    ) -> Result<SealedRichSemanticBlock, SemanticError> {
        let normalized = encode_block(&self.values, &self.effects, None);
        let canonical = encode_block(&self.values, &self.effects, Some(self.semantic_version));
        let content_id = ContentId::derive(ContentDomain::SemanticBlock, content_schema, &canonical);
        let semantic_fingerprint = SemanticFingerprint::derive(fingerprint_schema, &normalized);

        Ok(SealedRichSemanticBlock {
            semantic_version: self.semantic_version,
            content_id,
            semantic_fingerprint,
            canonical_bytes: canonical,
            values: self.values,
            effects: self.effects,
        })
    }

    fn next_value_id(&self) -> Result<ValueId, SemanticError> {
        u32::try_from(self.values.len()).map_err(|_| SemanticError::BuilderRejected)
    }

    fn next_effect_id(&self) -> Result<EffectId, SemanticError> {
        u32::try_from(self.effects.len()).map_err(|_| SemanticError::BuilderRejected)
    }

    fn value_exists(&self, id: ValueId) -> bool {
        usize::try_from(id).is_ok_and(|index| self.values.get(index).is_some_and(|value| value.id == id))
    }

    fn values_exist(&self, ids: &[ValueId]) -> bool {
        ids.iter().copied().all(|id| self.value_exists(id))
    }

    fn push_value(&mut self, ty: SemanticType, definition: SemanticValueDefinition) -> Result<ValueId, SemanticError> {
        if semantic_type_bytes(ty).is_none() {
            return Err(SemanticError::InvalidWidth);
        }
        let id = self.next_value_id()?;
        self.values.push(SemanticValue { id, ty, definition });
        Ok(id)
    }

    fn push_effect(&mut self, definition: SemanticEffectDefinition) -> Result<EffectId, SemanticError> {
        let id = self.next_effect_id()?;
        self.effects.push(SemanticEffect { id, definition });
        Ok(id)
    }
}

impl SemanticBuilder for SemanticBlockBuilder {
    fn constant(&mut self, ty: SemanticType, bytes_le: &[u8]) -> Result<ValueId, SemanticError> {
        if semantic_type_bytes(ty) != Some(bytes_le.len()) {
            return Err(SemanticError::InvalidWidth);
        }
        if let Some(bits) = semantic_type_bit_width(ty) {
            let used_high_bits = bits % 8;
            if used_high_bits != 0 {
                let allowed = (1_u8 << used_high_bits) - 1;
                if bytes_le.last().is_some_and(|byte| byte & !allowed != 0) {
                    return Err(SemanticError::InvalidSemanticDefinition);
                }
            }
        }
        self.push_value(ty, SemanticValueDefinition::Constant(bytes_le.to_vec()))
    }

    fn read_register(&mut self, reg: RegisterId, ty: SemanticType) -> Result<ValueId, SemanticError> {
        self.push_value(ty, SemanticValueDefinition::ReadRegister(reg))
    }

    fn read_operand(&mut self, operand_index: u8, ty: SemanticType) -> Result<ValueId, SemanticError> {
        self.push_value(ty, SemanticValueDefinition::ReadOperand(operand_index))
    }

    fn emit(&mut self, op: SemanticOp, ty: SemanticType, inputs: &[ValueId]) -> Result<ValueId, SemanticError> {
        if !self.values_exist(inputs) {
            return Err(SemanticError::InvalidSemanticDefinition);
        }
        self.push_value(
            ty,
            SemanticValueDefinition::Operation {
                op,
                inputs: inputs.to_vec(),
            },
        )
    }

    fn write_register(&mut self, reg: RegisterId, value: ValueId) -> Result<EffectId, SemanticError> {
        if !self.value_exists(value) {
            return Err(SemanticError::InvalidSemanticDefinition);
        }
        self.push_effect(SemanticEffectDefinition::WriteRegister { register: reg, value })
    }

    fn write_operand(&mut self, operand_index: u8, value: ValueId) -> Result<EffectId, SemanticError> {
        if !self.value_exists(value) {
            return Err(SemanticError::InvalidSemanticDefinition);
        }
        self.push_effect(SemanticEffectDefinition::WriteOperand { operand_index, value })
    }

    fn side_effect(&mut self, effect: SideEffect, inputs: &[ValueId]) -> Result<EffectId, SemanticError> {
        if !self.values_exist(inputs) {
            return Err(SemanticError::InvalidSemanticDefinition);
        }
        self.push_effect(SemanticEffectDefinition::SideEffect {
            effect,
            inputs: inputs.to_vec(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedRichSemanticBlock {
    semantic_version: SemanticVersion,
    content_id: ContentId,
    semantic_fingerprint: SemanticFingerprint,
    canonical_bytes: Vec<u8>,
    values: Vec<SemanticValue>,
    effects: Vec<SemanticEffect>,
}

impl SealedRichSemanticBlock {
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn values(&self) -> &[SemanticValue] {
        &self.values
    }

    pub fn effects(&self) -> &[SemanticEffect] {
        &self.effects
    }
}

impl SealedSemanticBlock for SealedRichSemanticBlock {
    fn content_id(&self) -> ContentId {
        self.content_id
    }

    fn semantic_fingerprint(&self) -> SemanticFingerprint {
        self.semantic_fingerprint
    }

    fn semantic_version(&self) -> SemanticVersion {
        self.semantic_version
    }
}

fn scalar_bits(ty: crate::ScalarType) -> Option<usize> {
    match ty {
        crate::ScalarType::BitVec(bits) if bits > 0 => Some(usize::from(bits)),
        crate::ScalarType::BitVec(_) => None,
        crate::ScalarType::Float(format) => Some(match format {
            FloatFormat::F16 | FloatFormat::Bf16 => 16,
            FloatFormat::F32 => 32,
            FloatFormat::F64 => 64,
            FloatFormat::F80 => 80,
        }),
    }
}

fn semantic_type_bytes(ty: SemanticType) -> Option<usize> {
    match ty {
        SemanticType::Tile {
            rows,
            bytes_per_row,
            element,
        } if rows > 0 && bytes_per_row > 0 => {
            scalar_bits(element)?;
            return usize::from(rows).checked_mul(usize::from(bytes_per_row));
        }
        SemanticType::Tile { .. } => return None,
        _ => {}
    }
    semantic_type_bit_width(ty)?.checked_add(7)?.checked_div(8)
}

fn semantic_type_bit_width(ty: SemanticType) -> Option<usize> {
    match ty {
        SemanticType::Scalar(scalar) => scalar_bits(scalar),
        SemanticType::Vector { lanes, lane } if lanes > 0 => scalar_bits(lane)?.checked_mul(usize::from(lanes)),
        SemanticType::Vector { .. } | SemanticType::Opmask { lanes: 0 } => None,
        SemanticType::Opmask { lanes } => Some(usize::from(lanes)),
        SemanticType::Tile { .. } => None,
    }
}

#[derive(Default)]
struct CanonicalWriter(Vec<u8>);

impl CanonicalWriter {
    fn byte(&mut self, value: u8) {
        self.0.push(value);
    }

    fn u16(&mut self, value: u16) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_le_bytes());
    }

    fn bytes(&mut self, value: &[u8]) {
        self.u64(value.len() as u64);
        self.0.extend_from_slice(value);
    }
}

fn encode_block(
    values: &[SemanticValue],
    effects: &[SemanticEffect],
    semantic_version: Option<SemanticVersion>,
) -> Vec<u8> {
    let mut out = CanonicalWriter::default();
    out.0.extend_from_slice(b"ANGRYIER-SEMA\0");
    match semantic_version {
        Some(version) => {
            out.byte(1);
            out.u64(version.0);
        }
        None => out.byte(0),
    }
    out.u64(values.len() as u64);
    for value in values {
        out.u32(value.id);
        encode_type(&mut out, value.ty);
        match &value.definition {
            SemanticValueDefinition::Constant(bytes) => {
                out.byte(0);
                out.bytes(bytes);
            }
            SemanticValueDefinition::ReadRegister(register) => {
                out.byte(1);
                out.u32(register.0);
            }
            SemanticValueDefinition::ReadOperand(index) => {
                out.byte(2);
                out.byte(*index);
            }
            SemanticValueDefinition::Operation { op, inputs } => {
                out.byte(3);
                encode_op(&mut out, *op);
                encode_value_ids(&mut out, inputs);
            }
        }
    }
    out.u64(effects.len() as u64);
    for effect in effects {
        out.u32(effect.id);
        match &effect.definition {
            SemanticEffectDefinition::WriteRegister { register, value } => {
                out.byte(0);
                out.u32(register.0);
                out.u32(*value);
            }
            SemanticEffectDefinition::WriteOperand { operand_index, value } => {
                out.byte(1);
                out.byte(*operand_index);
                out.u32(*value);
            }
            SemanticEffectDefinition::SideEffect { effect, inputs } => {
                out.byte(2);
                encode_side_effect(&mut out, *effect);
                encode_value_ids(&mut out, inputs);
            }
        }
    }
    out.0
}

fn encode_value_ids(out: &mut CanonicalWriter, values: &[ValueId]) {
    out.u64(values.len() as u64);
    for value in values {
        out.u32(*value);
    }
}

fn encode_scalar(out: &mut CanonicalWriter, scalar: crate::ScalarType) {
    match scalar {
        crate::ScalarType::BitVec(bits) => {
            out.byte(0);
            out.u16(bits);
        }
        crate::ScalarType::Float(format) => {
            out.byte(1);
            out.byte(match format {
                FloatFormat::F16 => 0,
                FloatFormat::Bf16 => 1,
                FloatFormat::F32 => 2,
                FloatFormat::F64 => 3,
                FloatFormat::F80 => 4,
            });
        }
    }
}

fn encode_type(out: &mut CanonicalWriter, ty: SemanticType) {
    match ty {
        SemanticType::Scalar(scalar) => {
            out.byte(0);
            encode_scalar(out, scalar);
        }
        SemanticType::Vector { lanes, lane } => {
            out.byte(1);
            out.u16(lanes);
            encode_scalar(out, lane);
        }
        SemanticType::Opmask { lanes } => {
            out.byte(2);
            out.u16(lanes);
        }
        SemanticType::Tile {
            rows,
            bytes_per_row,
            element,
        } => {
            out.byte(3);
            out.byte(rows);
            out.u16(bytes_per_row);
            encode_scalar(out, element);
        }
    }
}

fn encode_op(out: &mut CanonicalWriter, op: SemanticOp) {
    match op {
        SemanticOp::Primitive(op) => {
            out.byte(0);
            out.byte(primitive_tag(op));
        }
        SemanticOp::Float(op) => {
            out.byte(1);
            out.byte(float_tag(op));
        }
        SemanticOp::Vector(op) => {
            out.byte(2);
            match op {
                VectorOp::LaneWise(op) => {
                    out.byte(0);
                    out.byte(primitive_tag(op));
                }
                VectorOp::LaneWiseFloat(op) => {
                    out.byte(1);
                    out.byte(float_tag(op));
                }
                VectorOp::Shuffle => out.byte(2),
                VectorOp::Permute => out.byte(3),
                VectorOp::Broadcast => out.byte(4),
                VectorOp::Blend => out.byte(5),
                VectorOp::MaskMerge => out.byte(6),
                VectorOp::MaskZero => out.byte(7),
                VectorOp::Pack => out.byte(8),
                VectorOp::Unpack => out.byte(9),
            }
        }
        SemanticOp::Tile(op) => {
            out.byte(3);
            out.byte(match op {
                TileOp::Load => 0,
                TileOp::Store => 1,
                TileOp::Zero => 2,
                TileOp::DotProduct => 3,
                TileOp::Transform => 4,
            });
        }
    }
}

fn primitive_tag(op: PrimitiveOp) -> u8 {
    match op {
        PrimitiveOp::Add => 0,
        PrimitiveOp::Sub => 1,
        PrimitiveOp::Mul => 2,
        PrimitiveOp::UnsignedDiv => 3,
        PrimitiveOp::SignedDiv => 4,
        PrimitiveOp::And => 5,
        PrimitiveOp::Or => 6,
        PrimitiveOp::Xor => 7,
        PrimitiveOp::Not => 8,
        PrimitiveOp::ShiftLeft => 9,
        PrimitiveOp::LogicalShiftRight => 10,
        PrimitiveOp::ArithmeticShiftRight => 11,
        PrimitiveOp::Eq => 12,
        PrimitiveOp::Ult => 13,
        PrimitiveOp::Ule => 14,
        PrimitiveOp::Slt => 15,
        PrimitiveOp::Sle => 16,
        PrimitiveOp::Select => 17,
        PrimitiveOp::Concat => 18,
        PrimitiveOp::Extract => 19,
        PrimitiveOp::ZeroExtend => 20,
        PrimitiveOp::SignExtend => 21,
    }
}

fn float_tag(op: FloatingOp) -> u8 {
    match op {
        FloatingOp::Add => 0,
        FloatingOp::Sub => 1,
        FloatingOp::Mul => 2,
        FloatingOp::Div => 3,
        FloatingOp::Sqrt => 4,
        FloatingOp::Compare => 5,
        FloatingOp::Convert => 6,
    }
}

fn encode_side_effect(out: &mut CanonicalWriter, effect: SideEffect) {
    match effect {
        SideEffect::WriteRegister(register) => {
            out.byte(0);
            out.u32(register.0);
        }
        SideEffect::MemoryRead => out.byte(1),
        SideEffect::MemoryWrite => out.byte(2),
        SideEffect::ControlTransfer => out.byte(3),
        SideEffect::RaiseException(vector) => {
            out.byte(4);
            out.u32(vector);
        }
        SideEffect::UpdateFlags => out.byte(5),
        SideEffect::UpdateMxcsr => out.byte(6),
        SideEffect::UpdateTileConfig => out.byte(7),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PrimitiveOp, ScalarType};

    fn build(version: u64, operation: PrimitiveOp) -> Result<SealedRichSemanticBlock, SemanticError> {
        let mut builder = SemanticBlockBuilder::new(SemanticVersion(version));
        let ty = SemanticType::Scalar(ScalarType::BitVec(64));
        let left = builder.constant(ty, &1_u64.to_le_bytes())?;
        let right = builder.read_register(RegisterId(2), ty)?;
        let result = builder.emit(SemanticOp::Primitive(operation), ty, &[left, right])?;
        builder.write_register(RegisterId(2), result)?;
        builder.seal(ContentIdentitySchemaVersion(1), SemanticFingerprintSchemaVersion(1))
    }

    #[test]
    fn sealing_is_deterministic_and_version_scoped() -> Result<(), SemanticError> {
        let first = build(1, PrimitiveOp::Add)?;
        let repeated = build(1, PrimitiveOp::Add)?;
        let new_version = build(2, PrimitiveOp::Add)?;

        assert_eq!(first.content_id(), repeated.content_id());
        assert_eq!(first.canonical_bytes(), repeated.canonical_bytes());
        assert_ne!(first.content_id(), new_version.content_id());
        assert_eq!(first.semantic_fingerprint(), new_version.semantic_fingerprint());
        Ok(())
    }

    #[test]
    fn semantic_changes_alter_exact_and_advisory_identity() -> Result<(), SemanticError> {
        let add = build(1, PrimitiveOp::Add)?;
        let subtract = build(1, PrimitiveOp::Sub)?;

        assert_ne!(add.content_id(), subtract.content_id());
        assert_ne!(add.semantic_fingerprint(), subtract.semantic_fingerprint());
        Ok(())
    }

    #[test]
    fn references_to_unknown_values_fail_closed() {
        let mut builder = SemanticBlockBuilder::new(SemanticVersion(1));
        let result = builder.emit(
            SemanticOp::Primitive(PrimitiveOp::Add),
            SemanticType::Scalar(ScalarType::BitVec(64)),
            &[99],
        );

        assert_eq!(result, Err(SemanticError::InvalidSemanticDefinition));
    }

    #[test]
    fn non_byte_aligned_constants_have_one_canonical_encoding() -> Result<(), SemanticError> {
        let mut builder = SemanticBlockBuilder::new(SemanticVersion(1));
        let ty = SemanticType::Scalar(ScalarType::BitVec(1));

        assert_eq!(
            builder.constant(ty, &[0x81]),
            Err(SemanticError::InvalidSemanticDefinition)
        );
        assert_eq!(builder.constant(ty, &[0x01])?, 0);
        Ok(())
    }
}
