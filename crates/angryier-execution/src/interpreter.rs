use crate::{ExecutionEngine, ExecutionMode, ExecutionOutcome};
use angryier_ir::{
    BasicIrVerifier, IrBlock, IrInstruction, IrOp, IrPrimitive, IrType, IrValueId, IrVerificationError, IrVerifier,
};
use angryier_memory::{ByteValue, LayeredMemory};
use angryier_state::{ExecutionState, RegisterState};
use angryier_types::{Address, CodePageId, CodePageVersion, TargetProfileId};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConcreteExecutionError<RegisterError, MemoryError> {
    UnsupportedMode(ExecutionMode),
    InvalidIr(IrVerificationError),
    TargetProfileMismatch {
        state: TargetProfileId,
        block: TargetProfileId,
    },
    MissingCodeGuards,
    StaleCodePage {
        page: CodePageId,
        expected: CodePageVersion,
        actual: Option<CodePageVersion>,
    },
    MissingTerminator,
    UndefinedValue(IrValueId),
    TypeMismatch,
    InvalidArity {
        operation: IrPrimitive,
        expected: usize,
        actual: usize,
    },
    UnsupportedType(IrType),
    UnsupportedOperation(IrPrimitive),
    SymbolicExpression,
    SymbolicMemory(Address),
    InvalidAddress,
    DivisionByZero,
    Register(RegisterError),
    Memory(MemoryError),
}

impl<R: core::fmt::Display, M: core::fmt::Display> core::fmt::Display for ConcreteExecutionError<R, M> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnsupportedMode(mode) => write!(formatter, "concrete interpreter cannot execute in {mode:?} mode"),
            Self::InvalidIr(error) => write!(formatter, "invalid AngryIR: {error}"),
            Self::TargetProfileMismatch { state, block } => write!(
                formatter,
                "target profile mismatch: state {}, block {}",
                state.0, block.0
            ),
            Self::MissingCodeGuards => formatter.write_str("IR block has no code-version guards"),
            Self::StaleCodePage { page, expected, actual } => write!(
                formatter,
                "stale code page {}: expected {}, found {:?}",
                page.0,
                expected.0,
                actual.map(|version| version.0)
            ),
            Self::MissingTerminator => formatter.write_str("IR block completed without a control-flow terminator"),
            Self::UndefinedValue(value) => write!(formatter, "IR value {} is unavailable", value.0),
            Self::TypeMismatch => formatter.write_str("IR value types do not match the operation"),
            Self::InvalidArity {
                operation,
                expected,
                actual,
            } => write!(formatter, "{operation:?} expects {expected} inputs, received {actual}"),
            Self::UnsupportedType(ty) => write!(formatter, "unsupported concrete IR type: {ty:?}"),
            Self::UnsupportedOperation(operation) => {
                write!(formatter, "unsupported concrete IR operation: {operation:?}")
            }
            Self::SymbolicExpression => formatter.write_str("symbolic expression reached the concrete interpreter"),
            Self::SymbolicMemory(address) => {
                write!(formatter, "symbolic byte encountered at concrete address {address:#x}")
            }
            Self::InvalidAddress => formatter.write_str("IR value cannot be represented as an address"),
            Self::DivisionByZero => formatter.write_str("integer division by zero"),
            Self::Register(error) => write!(formatter, "register access failed: {error}"),
            Self::Memory(error) => write!(formatter, "memory access failed: {error}"),
        }
    }
}

impl<R, M> std::error::Error for ConcreteExecutionError<R, M>
where
    R: std::error::Error + 'static,
    M: std::error::Error + 'static,
{
}

#[derive(Clone, Copy, Debug)]
pub struct ConcreteInterpreter<R, M> {
    marker: core::marker::PhantomData<fn() -> (R, M)>,
}

impl<R, M> ConcreteInterpreter<R, M> {
    pub const fn new() -> Self {
        Self {
            marker: core::marker::PhantomData,
        }
    }
}

impl<R, M> Default for ConcreteInterpreter<R, M> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ConcreteValue {
    ty: IrType,
    bytes_le: Vec<u8>,
}

impl<R, M> ExecutionEngine for ConcreteInterpreter<R, M>
where
    R: RegisterState,
    M: LayeredMemory,
{
    type State = ExecutionState<R, M>;
    type Error = ConcreteExecutionError<R::Error, M::Error>;

    fn execute_block(
        &self,
        state: &Self::State,
        block: &IrBlock,
        mode: ExecutionMode,
    ) -> Result<(Self::State, ExecutionOutcome), Self::Error> {
        if mode != ExecutionMode::Concrete {
            return Err(ConcreteExecutionError::UnsupportedMode(mode));
        }
        BasicIrVerifier
            .verify(block)
            .map_err(ConcreteExecutionError::InvalidIr)?;
        if state.target_profile != block.key.target_profile {
            return Err(ConcreteExecutionError::TargetProfileMismatch {
                state: state.target_profile,
                block: block.key.target_profile,
            });
        }
        if block.key.code_versions.is_empty() {
            return Err(ConcreteExecutionError::MissingCodeGuards);
        }
        for guard in &block.key.code_versions {
            let actual = state.memory.page_version(guard.page);
            if actual != Some(guard.version) {
                return Err(ConcreteExecutionError::StaleCodePage {
                    page: guard.page,
                    expected: guard.version,
                    actual,
                });
            }
        }

        let mut current = state.clone();
        let mut values = Vec::new();
        for instruction in &block.instructions {
            if let Some(outcome) = execute_instruction(&mut current, instruction, &mut values)? {
                return Ok((current, outcome));
            }
        }
        Err(ConcreteExecutionError::MissingTerminator)
    }
}

fn execute_instruction<R, M>(
    state: &mut ExecutionState<R, M>,
    instruction: &IrInstruction,
    values: &mut Vec<ConcreteValue>,
) -> Result<Option<ExecutionOutcome>, ConcreteExecutionError<R::Error, M::Error>>
where
    R: RegisterState,
    M: LayeredMemory,
{
    let produced = match &instruction.op {
        IrOp::Constant { ty, bytes_le } => Some(ConcreteValue {
            ty: *ty,
            bytes_le: bytes_le.clone(),
        }),
        IrOp::ExprRef { .. } => return Err(ConcreteExecutionError::SymbolicExpression),
        IrOp::Primitive { op, ty, inputs } => Some(evaluate_primitive(*op, *ty, inputs, values)?),
        IrOp::ReadRegister { register, ty } => {
            let bytes_le = state
                .registers
                .read(*register)
                .map_err(ConcreteExecutionError::Register)?;
            ensure_value_width(*ty, &bytes_le)?;
            Some(ConcreteValue { ty: *ty, bytes_le })
        }
        IrOp::WriteRegister { register, value } => {
            let value = get_value(values, *value)?;
            *state = state
                .write_register(*register, &value.bytes_le)
                .map_err(ConcreteExecutionError::Register)?;
            None
        }
        IrOp::Load { address, ty } => {
            let address = value_address(get_value(values, *address)?)?;
            let width = type_bytes(*ty)?;
            let bytes = state
                .memory
                .read(address, width)
                .map_err(ConcreteExecutionError::Memory)?;
            let mut concrete = Vec::with_capacity(bytes.len());
            for (offset, byte) in bytes.into_iter().enumerate() {
                match byte {
                    ByteValue::Concrete(byte) => concrete.push(byte),
                    ByteValue::Symbolic(_) => {
                        let offset = u64::try_from(offset).map_err(|_| ConcreteExecutionError::InvalidAddress)?;
                        let symbolic_address = address
                            .checked_add(offset)
                            .ok_or(ConcreteExecutionError::InvalidAddress)?;
                        return Err(ConcreteExecutionError::SymbolicMemory(symbolic_address));
                    }
                }
            }
            Some(ConcreteValue {
                ty: *ty,
                bytes_le: concrete,
            })
        }
        IrOp::Store { address, value } => {
            let address = value_address(get_value(values, *address)?)?;
            let value = get_value(values, *value)?;
            let concrete: Vec<_> = value.bytes_le.iter().copied().map(ByteValue::Concrete).collect();
            *state = state
                .write_memory(address, &concrete)
                .map_err(ConcreteExecutionError::Memory)?;
            None
        }
        IrOp::Branch {
            condition,
            taken,
            not_taken,
        } => {
            let condition = get_value(values, *condition)?;
            if condition.ty != IrType::Bits(1) || condition.bytes_le.len() != 1 {
                return Err(ConcreteExecutionError::TypeMismatch);
            }
            let next_pc = if condition.bytes_le[0] & 1 == 1 {
                *taken
            } else {
                *not_taken
            };
            return Ok(Some(ExecutionOutcome::Continue {
                state: state.id,
                next_pc,
            }));
        }
        IrOp::Jump { target } | IrOp::Call { target } => {
            return Ok(Some(ExecutionOutcome::Continue {
                state: state.id,
                next_pc: *target,
            }));
        }
        IrOp::Return => {
            return Ok(Some(ExecutionOutcome::Terminated { state: state.id }));
        }
        IrOp::Trap { vector } => {
            return Ok(Some(ExecutionOutcome::Trap {
                state: state.id,
                vector: *vector,
            }));
        }
    };

    if let Some(value) = produced {
        ensure_value_width(value.ty, &value.bytes_le)?;
        values.push(value);
    }
    Ok(None)
}

fn get_value<R, M>(values: &[ConcreteValue], id: IrValueId) -> Result<&ConcreteValue, ConcreteExecutionError<R, M>> {
    usize::try_from(id.0)
        .ok()
        .and_then(|index| values.get(index))
        .ok_or(ConcreteExecutionError::UndefinedValue(id))
}

fn type_bytes<R, M>(ty: IrType) -> Result<usize, ConcreteExecutionError<R, M>> {
    let bits = match ty {
        IrType::Bits(bits) => bits,
        _ => return Err(ConcreteExecutionError::UnsupportedType(ty)),
    };
    usize::from(bits)
        .checked_add(7)
        .and_then(|bits| bits.checked_div(8))
        .filter(|bytes| *bytes > 0 && *bytes <= 16)
        .ok_or(ConcreteExecutionError::UnsupportedType(ty))
}

fn ensure_value_width<R, M>(ty: IrType, bytes: &[u8]) -> Result<(), ConcreteExecutionError<R, M>> {
    if type_bytes(ty)? != bytes.len() {
        return Err(ConcreteExecutionError::TypeMismatch);
    }
    if let IrType::Bits(bits) = ty {
        let used = bits % 8;
        if used != 0 {
            let allowed = (1_u8 << used) - 1;
            if bytes.last().is_some_and(|byte| byte & !allowed != 0) {
                return Err(ConcreteExecutionError::TypeMismatch);
            }
        }
    }
    Ok(())
}

fn value_address<R, M>(value: &ConcreteValue) -> Result<Address, ConcreteExecutionError<R, M>> {
    let IrType::Bits(bits) = value.ty else {
        return Err(ConcreteExecutionError::InvalidAddress);
    };
    if bits > 64 {
        return Err(ConcreteExecutionError::InvalidAddress);
    }
    let mut bytes = [0_u8; 8];
    bytes[..value.bytes_le.len()].copy_from_slice(&value.bytes_le);
    Ok(u64::from_le_bytes(bytes))
}

fn evaluate_primitive<R, M>(
    operation: IrPrimitive,
    ty: IrType,
    inputs: &[IrValueId],
    values: &[ConcreteValue],
) -> Result<ConcreteValue, ConcreteExecutionError<R, M>> {
    let output_bits = scalar_bits(ty)?;
    let resolved: Vec<_> = inputs
        .iter()
        .copied()
        .map(|id| get_value(values, id))
        .collect::<Result<_, _>>()?;

    let value = match operation {
        IrPrimitive::Add
        | IrPrimitive::Sub
        | IrPrimitive::Mul
        | IrPrimitive::UDiv
        | IrPrimitive::SDiv
        | IrPrimitive::And
        | IrPrimitive::Or
        | IrPrimitive::Xor => {
            require_arity(operation, &resolved, 2)?;
            require_types(&resolved, ty)?;
            let left = as_u128(resolved[0]);
            let right = as_u128(resolved[1]);
            match operation {
                IrPrimitive::Add => left.wrapping_add(right),
                IrPrimitive::Sub => left.wrapping_sub(right),
                IrPrimitive::Mul => left.wrapping_mul(right),
                IrPrimitive::UDiv => {
                    if right == 0 {
                        return Err(ConcreteExecutionError::DivisionByZero);
                    }
                    left / right
                }
                IrPrimitive::SDiv => signed_div(left, right, output_bits)?,
                IrPrimitive::And => left & right,
                IrPrimitive::Or => left | right,
                IrPrimitive::Xor => left ^ right,
                _ => return Err(ConcreteExecutionError::UnsupportedOperation(operation)),
            }
        }
        IrPrimitive::Not => {
            require_arity(operation, &resolved, 1)?;
            require_types(&resolved, ty)?;
            !as_u128(resolved[0])
        }
        IrPrimitive::Shl | IrPrimitive::LShr | IrPrimitive::AShr => {
            require_arity(operation, &resolved, 2)?;
            if resolved[0].ty != ty || !matches!(resolved[1].ty, IrType::Bits(_)) {
                return Err(ConcreteExecutionError::TypeMismatch);
            }
            let input = as_u128(resolved[0]);
            let shift = as_u128(resolved[1]);
            if shift >= u128::from(output_bits) {
                if operation == IrPrimitive::AShr && sign_bit(input, output_bits) {
                    bit_mask(output_bits)
                } else {
                    0
                }
            } else {
                let shift = u32::try_from(shift).map_err(|_| ConcreteExecutionError::TypeMismatch)?;
                match operation {
                    IrPrimitive::Shl => input << shift,
                    IrPrimitive::LShr => input >> shift,
                    IrPrimitive::AShr => arithmetic_shift_right(input, shift, output_bits),
                    _ => return Err(ConcreteExecutionError::UnsupportedOperation(operation)),
                }
            }
        }
        IrPrimitive::Eq | IrPrimitive::Ult | IrPrimitive::Ule | IrPrimitive::Slt | IrPrimitive::Sle => {
            require_arity(operation, &resolved, 2)?;
            if ty != IrType::Bits(1) || resolved[0].ty != resolved[1].ty {
                return Err(ConcreteExecutionError::TypeMismatch);
            }
            let input_bits = scalar_bits(resolved[0].ty)?;
            let left = as_u128(resolved[0]);
            let right = as_u128(resolved[1]);
            u128::from(match operation {
                IrPrimitive::Eq => left == right,
                IrPrimitive::Ult => left < right,
                IrPrimitive::Ule => left <= right,
                IrPrimitive::Slt => signed_order_key(left, input_bits) < signed_order_key(right, input_bits),
                IrPrimitive::Sle => signed_order_key(left, input_bits) <= signed_order_key(right, input_bits),
                _ => return Err(ConcreteExecutionError::UnsupportedOperation(operation)),
            })
        }
        IrPrimitive::Select => {
            require_arity(operation, &resolved, 3)?;
            if resolved[0].ty != IrType::Bits(1) || resolved[1].ty != ty || resolved[2].ty != ty {
                return Err(ConcreteExecutionError::TypeMismatch);
            }
            if as_u128(resolved[0]) == 0 {
                as_u128(resolved[2])
            } else {
                as_u128(resolved[1])
            }
        }
        IrPrimitive::Concat | IrPrimitive::Extract | IrPrimitive::ZExt | IrPrimitive::SExt => {
            return Err(ConcreteExecutionError::UnsupportedOperation(operation));
        }
    };

    Ok(ConcreteValue {
        ty,
        bytes_le: to_bytes(value & bit_mask(output_bits), output_bits),
    })
}

fn scalar_bits<R, M>(ty: IrType) -> Result<u16, ConcreteExecutionError<R, M>> {
    match ty {
        IrType::Bits(bits) if bits > 0 && bits <= 128 => Ok(bits),
        _ => Err(ConcreteExecutionError::UnsupportedType(ty)),
    }
}

fn require_arity<R, M>(
    operation: IrPrimitive,
    values: &[&ConcreteValue],
    expected: usize,
) -> Result<(), ConcreteExecutionError<R, M>> {
    if values.len() != expected {
        return Err(ConcreteExecutionError::InvalidArity {
            operation,
            expected,
            actual: values.len(),
        });
    }
    Ok(())
}

fn require_types<R, M>(values: &[&ConcreteValue], expected: IrType) -> Result<(), ConcreteExecutionError<R, M>> {
    if values.iter().any(|value| value.ty != expected) {
        return Err(ConcreteExecutionError::TypeMismatch);
    }
    Ok(())
}

fn as_u128(value: &ConcreteValue) -> u128 {
    let mut bytes = [0_u8; 16];
    bytes[..value.bytes_le.len()].copy_from_slice(&value.bytes_le);
    u128::from_le_bytes(bytes)
}

fn to_bytes(value: u128, bits: u16) -> Vec<u8> {
    let len = usize::from(bits).div_ceil(8);
    value.to_le_bytes()[..len].to_vec()
}

fn bit_mask(bits: u16) -> u128 {
    if bits == 128 { u128::MAX } else { (1_u128 << bits) - 1 }
}

fn sign_bit(value: u128, bits: u16) -> bool {
    value & (1_u128 << (bits - 1)) != 0
}

fn signed_order_key(value: u128, bits: u16) -> u128 {
    value ^ (1_u128 << (bits - 1))
}

fn arithmetic_shift_right(value: u128, shift: u32, bits: u16) -> u128 {
    let shifted = value >> shift;
    if shift == 0 || !sign_bit(value, bits) {
        return shifted;
    }
    let fill = bit_mask(bits) ^ bit_mask(bits - u16::try_from(shift).unwrap_or(bits));
    shifted | fill
}

fn signed_div<R, M>(left: u128, right: u128, bits: u16) -> Result<u128, ConcreteExecutionError<R, M>> {
    if right == 0 {
        return Err(ConcreteExecutionError::DivisionByZero);
    }
    let left_negative = sign_bit(left, bits);
    let right_negative = sign_bit(right, bits);
    let left_magnitude = if left_negative {
        (!left).wrapping_add(1) & bit_mask(bits)
    } else {
        left
    };
    let right_magnitude = if right_negative {
        (!right).wrapping_add(1) & bit_mask(bits)
    } else {
        right
    };
    let quotient = left_magnitude / right_magnitude;
    Ok(if left_negative ^ right_negative {
        (!quotient).wrapping_add(1) & bit_mask(bits)
    } else {
        quotient
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_ir::{IrBlockKey, IrInstruction};
    use angryier_memory::{MemoryError, MemoryRegion, PersistentMemory};
    use angryier_state::{
        FidelityLedger, PersistentConstraintLineage, PersistentRegisters, RegisterError, StateOwnership,
    };
    use angryier_types::{BlockId, ContentId, ExprId, FidelityProfile, ImageId, ObjectId, StateId};

    type TestError = ConcreteExecutionError<RegisterError, MemoryError>;

    fn interpreter() -> ConcreteInterpreter<PersistentRegisters, PersistentMemory> {
        ConcreteInterpreter::new()
    }

    fn state() -> Result<ExecutionState<PersistentRegisters, PersistentMemory>, Box<dyn std::error::Error>> {
        let memory = PersistentMemory::new(vec![
            MemoryRegion {
                object: ObjectId(1),
                base: 0x1000,
                size: 0x1000,
                readable: true,
                writable: true,
                executable: true,
            },
            MemoryRegion {
                object: ObjectId(2),
                base: 0x3000,
                size: 0x1000,
                readable: true,
                writable: true,
                executable: false,
            },
        ])?;
        Ok(ExecutionState {
            id: StateId(7),
            parent: None,
            target_profile: TargetProfileId(3),
            registers: PersistentRegisters::from_widths([(1, 8)])?,
            memory,
            constraints: PersistentConstraintLineage::new(),
            ownership: StateOwnership::default(),
            fidelity: FidelityLedger::new(FidelityProfile::Prove),
        })
    }

    fn block(memory: &PersistentMemory, instructions: Vec<IrInstruction>) -> Result<IrBlock, MemoryError> {
        Ok(IrBlock {
            key: IrBlockKey {
                image: ImageId(1),
                block: BlockId(2),
                address: 0x1000,
                semantic_content: ContentId([4; 32]),
                target_profile: TargetProfileId(3),
                code_versions: memory.code_version_guards_for_range(0x1000, 1)?,
            },
            instructions,
        })
    }

    #[test]
    fn executes_scalar_dataflow_and_register_write() -> Result<(), Box<dyn std::error::Error>> {
        let initial = state()?;
        let candidate = block(
            &initial.memory,
            vec![
                constant(0, 40),
                constant(1, 2),
                IrInstruction {
                    result: Some(IrValueId(2)),
                    op: IrOp::Primitive {
                        op: IrPrimitive::Add,
                        ty: IrType::Bits(64),
                        inputs: vec![IrValueId(0), IrValueId(1)],
                    },
                },
                IrInstruction {
                    result: None,
                    op: IrOp::WriteRegister {
                        register: 1,
                        value: IrValueId(2),
                    },
                },
                IrInstruction {
                    result: None,
                    op: IrOp::Jump { target: 0x2000 },
                },
            ],
        )?;

        let (executed, outcome) = interpreter().execute_block(&initial, &candidate, ExecutionMode::Concrete)?;

        assert_eq!(executed.registers.read(1)?, 42_u64.to_le_bytes());
        assert_eq!(initial.registers.read(1)?, vec![0; 8]);
        assert_eq!(
            outcome,
            ExecutionOutcome::Continue {
                state: StateId(7),
                next_pc: 0x2000
            }
        );
        Ok(())
    }

    #[test]
    fn branches_on_one_bit_condition() -> Result<(), Box<dyn std::error::Error>> {
        let initial = state()?;
        let candidate = block(
            &initial.memory,
            vec![
                IrInstruction {
                    result: Some(IrValueId(0)),
                    op: IrOp::Constant {
                        ty: IrType::Bits(1),
                        bytes_le: vec![1],
                    },
                },
                IrInstruction {
                    result: None,
                    op: IrOp::Branch {
                        condition: IrValueId(0),
                        taken: 0x3000,
                        not_taken: 0x4000,
                    },
                },
            ],
        )?;

        let (_, outcome) = interpreter().execute_block(&initial, &candidate, ExecutionMode::Concrete)?;
        assert_eq!(
            outcome,
            ExecutionOutcome::Continue {
                state: StateId(7),
                next_pc: 0x3000
            }
        );
        Ok(())
    }

    #[test]
    fn concrete_store_and_load_preserve_parent_memory() -> Result<(), Box<dyn std::error::Error>> {
        let initial = state()?;
        let candidate = block(
            &initial.memory,
            vec![
                constant(0, 0x3080),
                constant(1, 0xfeed_face_cafe_beef),
                IrInstruction {
                    result: None,
                    op: IrOp::Store {
                        address: IrValueId(0),
                        value: IrValueId(1),
                    },
                },
                IrInstruction {
                    result: Some(IrValueId(2)),
                    op: IrOp::Load {
                        address: IrValueId(0),
                        ty: IrType::Bits(64),
                    },
                },
                IrInstruction {
                    result: None,
                    op: IrOp::WriteRegister {
                        register: 1,
                        value: IrValueId(2),
                    },
                },
                IrInstruction {
                    result: None,
                    op: IrOp::Return,
                },
            ],
        )?;

        let (executed, outcome) = interpreter().execute_block(&initial, &candidate, ExecutionMode::Concrete)?;

        assert_eq!(executed.registers.read(1)?, 0xfeed_face_cafe_beef_u64.to_le_bytes());
        assert_eq!(initial.memory.read(0x3080, 8)?, vec![ByteValue::Concrete(0); 8]);
        assert_eq!(outcome, ExecutionOutcome::Terminated { state: StateId(7) });
        Ok(())
    }

    #[test]
    fn division_by_zero_fails_without_publishing_state() -> Result<(), Box<dyn std::error::Error>> {
        let initial = state()?;
        let candidate = block(
            &initial.memory,
            vec![
                constant(0, 10),
                constant(1, 0),
                IrInstruction {
                    result: Some(IrValueId(2)),
                    op: IrOp::Primitive {
                        op: IrPrimitive::UDiv,
                        ty: IrType::Bits(64),
                        inputs: vec![IrValueId(0), IrValueId(1)],
                    },
                },
                IrInstruction {
                    result: None,
                    op: IrOp::Return,
                },
            ],
        )?;

        assert!(matches!(
            interpreter().execute_block(&initial, &candidate, ExecutionMode::Concrete),
            Err(TestError::DivisionByZero)
        ));
        assert_eq!(initial.registers.read(1)?, vec![0; 8]);
        Ok(())
    }

    #[test]
    fn rejects_stale_code_guard_before_execution() -> Result<(), Box<dyn std::error::Error>> {
        let initial = state()?;
        let candidate = block(
            &initial.memory,
            vec![IrInstruction {
                result: None,
                op: IrOp::Return,
            }],
        )?;
        let changed = initial.write_memory(0x1000, &[ByteValue::Concrete(0xcc)])?;

        assert!(matches!(
            interpreter().execute_block(&changed, &candidate, ExecutionMode::Concrete),
            Err(TestError::StaleCodePage {
                page: CodePageId(1),
                expected: CodePageVersion(0),
                actual: Some(CodePageVersion(1)),
            })
        ));
        Ok(())
    }

    #[test]
    fn rejects_symbolic_memory_in_concrete_mode() -> Result<(), Box<dyn std::error::Error>> {
        let initial = state()?.write_memory(0x1080, &[ByteValue::Symbolic(ExprId(9))])?;
        let candidate = block(
            &initial.memory,
            vec![
                constant(0, 0x1080),
                IrInstruction {
                    result: Some(IrValueId(1)),
                    op: IrOp::Load {
                        address: IrValueId(0),
                        ty: IrType::Bits(8),
                    },
                },
                IrInstruction {
                    result: None,
                    op: IrOp::Return,
                },
            ],
        )?;

        assert!(matches!(
            interpreter().execute_block(&initial, &candidate, ExecutionMode::Concrete),
            Err(TestError::SymbolicMemory(0x1080))
        ));
        Ok(())
    }

    #[test]
    fn rejects_non_concrete_mode() -> Result<(), Box<dyn std::error::Error>> {
        let initial = state()?;
        let candidate = block(&initial.memory, Vec::new())?;

        assert!(matches!(
            interpreter().execute_block(&initial, &candidate, ExecutionMode::Symbolic),
            Err(TestError::UnsupportedMode(ExecutionMode::Symbolic))
        ));
        Ok(())
    }

    fn constant(id: u32, value: u64) -> IrInstruction {
        IrInstruction {
            result: Some(IrValueId(id)),
            op: IrOp::Constant {
                ty: IrType::Bits(64),
                bytes_le: value.to_le_bytes().to_vec(),
            },
        }
    }
}
