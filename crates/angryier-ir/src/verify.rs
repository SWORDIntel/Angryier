use crate::{IrBlock, IrInstruction, IrOp, IrType, IrValueId};
use angryier_types::CodePageId;
use std::collections::BTreeSet;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IrVerificationError {
    DuplicateCodeGuard(CodePageId),
    NonSequentialValue { expected: IrValueId, actual: IrValueId },
    MissingResult,
    UnexpectedResult,
    UndefinedValue(IrValueId),
    InvalidType(IrType),
    InvalidConstantWidth,
    InstructionAfterTerminator,
}

impl core::fmt::Display for IrVerificationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DuplicateCodeGuard(page) => write!(formatter, "duplicate code-page guard: {}", page.0),
            Self::NonSequentialValue { expected, actual } => {
                write!(
                    formatter,
                    "non-sequential IR value: expected {}, got {}",
                    expected.0, actual.0
                )
            }
            Self::MissingResult => formatter.write_str("value-producing IR instruction has no result"),
            Self::UnexpectedResult => formatter.write_str("effect-only IR instruction has a result"),
            Self::UndefinedValue(value) => write!(formatter, "IR references undefined value {}", value.0),
            Self::InvalidType(ty) => write!(formatter, "invalid IR type: {ty:?}"),
            Self::InvalidConstantWidth => formatter.write_str("IR constant byte width does not match its type"),
            Self::InstructionAfterTerminator => formatter.write_str("IR instruction appears after a terminator"),
        }
    }
}

impl std::error::Error for IrVerificationError {}

#[derive(Clone, Copy, Debug, Default)]
pub struct BasicIrVerifier;

impl crate::IrVerifier for BasicIrVerifier {
    type Error = IrVerificationError;

    fn verify(&self, block: &IrBlock) -> Result<(), Self::Error> {
        let mut guarded_pages = BTreeSet::new();
        for guard in &block.key.code_versions {
            if !guarded_pages.insert(guard.page) {
                return Err(IrVerificationError::DuplicateCodeGuard(guard.page));
            }
        }

        let mut value_types = Vec::new();
        let mut terminated = false;
        for instruction in &block.instructions {
            if terminated {
                return Err(IrVerificationError::InstructionAfterTerminator);
            }
            verify_inputs(instruction, &value_types)?;

            match produced_type(&instruction.op) {
                Some(ty) => {
                    validate_type(ty)?;
                    let result = instruction.result.ok_or(IrVerificationError::MissingResult)?;
                    let expected =
                        IrValueId(u32::try_from(value_types.len()).map_err(|_| IrVerificationError::MissingResult)?);
                    if result != expected {
                        return Err(IrVerificationError::NonSequentialValue {
                            expected,
                            actual: result,
                        });
                    }
                    if let IrOp::Constant { bytes_le, .. } = &instruction.op
                        && expected_bytes(ty) != Some(bytes_le.len())
                    {
                        return Err(IrVerificationError::InvalidConstantWidth);
                    }
                    value_types.push(ty);
                }
                None if instruction.result.is_some() => return Err(IrVerificationError::UnexpectedResult),
                None => {}
            }
            terminated = is_terminator(&instruction.op);
        }
        Ok(())
    }
}

fn verify_inputs(instruction: &IrInstruction, values: &[IrType]) -> Result<(), IrVerificationError> {
    let mut require = |value: IrValueId| {
        usize::try_from(value.0)
            .ok()
            .filter(|index| *index < values.len())
            .map(|_| ())
            .ok_or(IrVerificationError::UndefinedValue(value))
    };

    match &instruction.op {
        IrOp::Primitive { inputs, .. } => inputs.iter().copied().try_for_each(&mut require),
        IrOp::WriteRegister { value, .. } => require(*value),
        IrOp::Load { address, .. } => require(*address),
        IrOp::Store { address, value } => {
            require(*address)?;
            require(*value)
        }
        IrOp::Branch { condition, .. } => require(*condition),
        IrOp::JumpIndirect { target } => require(*target),
        IrOp::Constant { .. }
        | IrOp::ExprRef { .. }
        | IrOp::ReadRegister { .. }
        | IrOp::Jump { .. }
        | IrOp::Call { .. }
        | IrOp::Return
        | IrOp::Trap { .. } => Ok(()),
    }
}

fn produced_type(op: &IrOp) -> Option<IrType> {
    match op {
        IrOp::Constant { ty, .. }
        | IrOp::ExprRef { ty, .. }
        | IrOp::Primitive { ty, .. }
        | IrOp::ReadRegister { ty, .. }
        | IrOp::Load { ty, .. } => Some(*ty),
        _ => None,
    }
}

fn validate_type(ty: IrType) -> Result<(), IrVerificationError> {
    match ty {
        IrType::Bits(0) | IrType::Vector { width_bits: 0, .. } | IrType::Opmask { width_bits: 0 } => {
            Err(IrVerificationError::InvalidType(ty))
        }
        _ => Ok(()),
    }
}

fn expected_bytes(ty: IrType) -> Option<usize> {
    let bits = match ty {
        IrType::Bits(bits) | IrType::Vector { width_bits: bits, .. } | IrType::Opmask { width_bits: bits } => {
            usize::from(bits)
        }
        IrType::Float16 | IrType::BFloat16 => 16,
        IrType::Float32 => 32,
        IrType::Float64 => 64,
        IrType::Float80 => 80,
        IrType::Tile => return None,
    };
    bits.checked_add(7)?.checked_div(8)
}

fn is_terminator(op: &IrOp) -> bool {
    matches!(
        op,
        IrOp::Branch { .. }
            | IrOp::Jump { .. }
            | IrOp::JumpIndirect { .. }
            | IrOp::Call { .. }
            | IrOp::Return
            | IrOp::Trap { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IrBlockKey, IrVerifier, RegisterWriteKind};
    use angryier_types::{BlockId, CodePageVersion, CodeVersionGuard, ContentId, ImageId, TargetProfileId};

    fn block(instructions: Vec<IrInstruction>) -> IrBlock {
        IrBlock {
            key: IrBlockKey {
                image: ImageId(1),
                block: BlockId(2),
                address: 0x1000,
                semantic_content: ContentId([3; 32]),
                target_profile: TargetProfileId(4),
                code_versions: vec![CodeVersionGuard {
                    page: CodePageId(5),
                    version: CodePageVersion(6),
                }],
            },
            instructions,
        }
    }

    #[test]
    fn rejects_undefined_ssa_input() {
        let candidate = block(vec![IrInstruction {
            result: None,
            op: IrOp::WriteRegister {
                register: 1,
                value: IrValueId(0),
                kind: RegisterWriteKind::ReplaceParent,
            },
        }]);

        assert_eq!(
            BasicIrVerifier.verify(&candidate),
            Err(IrVerificationError::UndefinedValue(IrValueId(0)))
        );
    }

    #[test]
    fn rejects_instruction_after_terminator() {
        let candidate = block(vec![
            IrInstruction {
                result: None,
                op: IrOp::Return,
            },
            IrInstruction {
                result: Some(IrValueId(0)),
                op: IrOp::Constant {
                    ty: IrType::Bits(8),
                    bytes_le: vec![1],
                },
            },
        ]);

        assert_eq!(
            BasicIrVerifier.verify(&candidate),
            Err(IrVerificationError::InstructionAfterTerminator)
        );
    }

    #[test]
    fn rejects_duplicate_code_guards() {
        let mut candidate = block(Vec::new());
        candidate.key.code_versions.push(CodeVersionGuard {
            page: CodePageId(5),
            version: CodePageVersion(7),
        });

        assert_eq!(
            BasicIrVerifier.verify(&candidate),
            Err(IrVerificationError::DuplicateCodeGuard(CodePageId(5)))
        );
    }
}
