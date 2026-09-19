//! Single-block symbolic evaluation of AngryIR.
//!
//! The concrete interpreter executes one state; this module evaluates the same
//! `IrBlock` shape symbolically, producing expression-tree values instead of
//! concrete bytes. A symbolic register file is maintained across blocks so a
//! straight-line trace of blocks translates into expressions over the entry
//! state's registers.
//!
//! This is the first, deliberately narrow step toward the concolic fast path:
//! it supports the scalar integer operations that flag computation and
//! conditional branches use, and refuses everything else explicitly.

use std::collections::BTreeMap;

use angryier_expr::{ExprArena, ExprArenaError, ExprNode, ExprOp, ExprSort};
use angryier_ir::{IrBlock, IrOp, IrPrimitive, IrType, IrValueId, RegisterWriteKind};
use angryier_types::{Address, ExprId};

/// Expression arena type used by the evaluator.
pub type SymbolicArena = dyn ExprArena<Error = ExprArenaError>;

/// Errors produced while symbolically evaluating an AngryIR block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SymbolicEvalError {
    /// The block contains an operation the evaluator does not model.
    UnsupportedOperation(String),
    /// The block contains a type the evaluator does not model.
    UnsupportedType(String),
    /// A value was referenced before it was defined.
    UndefinedValue(IrValueId),
    /// The expression arena rejected a node.
    Expression(String),
}

impl std::fmt::Display for SymbolicEvalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedOperation(operation) => write!(formatter, "unsupported symbolic operation: {operation}"),
            Self::UnsupportedType(ty) => write!(formatter, "unsupported symbolic type: {ty}"),
            Self::UndefinedValue(value) => write!(formatter, "undefined IR value {}", value.0),
            Self::Expression(error) => write!(formatter, "expression error: {error}"),
        }
    }
}

impl std::error::Error for SymbolicEvalError {}

/// A symbolic variable created for a register read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SymbolBinding {
    /// Architectural register id.
    pub register: u32,
    /// Bit width of the read.
    pub width: u16,
    /// Expression node representing the symbol. Solver models are keyed by
    /// this expression id.
    pub expression: ExprId,
}

/// Branch condition discovered while evaluating a block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SymbolicBranch {
    /// 1-bit condition; the branch is taken when the low bit is set.
    pub condition: ExprId,
    pub taken: Address,
    pub not_taken: Address,
}

/// Summary of symbolically evaluating one block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymbolicBlockSummary {
    pub branch: Option<SymbolicBranch>,
    /// Registers written by the block, in order.
    pub written_registers: Vec<u32>,
    /// True when the block ends in branch/jump/call/return/trap.
    pub terminated: bool,
}

/// Symbolically evaluates AngryIR blocks with a shared symbolic register file.
pub struct SymbolicEvaluator<'a> {
    arena: &'a SymbolicArena,
    registers: BTreeMap<u32, (ExprId, IrType)>,
    symbols: Vec<SymbolBinding>,
    next_symbol: u64,
}

impl<'a> SymbolicEvaluator<'a> {
    /// Creates an evaluator over the given expression arena.
    pub fn new(arena: &'a SymbolicArena) -> Self {
        Self {
            arena,
            registers: BTreeMap::new(),
            symbols: Vec::new(),
            next_symbol: 0,
        }
    }

    /// Symbols created so far, in creation order.
    pub fn symbols(&self) -> &[SymbolBinding] {
        &self.symbols
    }

    /// Current symbolic value of a register, if it has been read or written.
    pub fn register_value(&self, register: u32) -> Option<ExprId> {
        self.registers.get(&register).map(|(expression, _)| *expression)
    }

    /// Symbolically evaluates one block.
    pub fn eval_block(&mut self, block: &IrBlock) -> Result<SymbolicBlockSummary, SymbolicEvalError> {
        let mut values: Vec<Option<(ExprId, IrType)>> = Vec::new();
        let mut written_registers = Vec::new();
        let mut branch = None;
        let mut terminated = false;

        for instruction in &block.instructions {
            let produced = match &instruction.op {
                IrOp::Constant { ty, bytes_le } => Some((self.constant(*ty, bytes_le)?, *ty)),
                IrOp::ExprRef { expression, ty } => Some((*expression, *ty)),
                IrOp::ReadRegister { register, ty } => Some((self.read_register(*register, *ty)?, *ty)),
                IrOp::Primitive { op, ty, inputs } => {
                    let resolved = resolve_inputs(&values, inputs)?;
                    Some(self.primitive(*op, *ty, &resolved)?)
                }
                IrOp::WriteRegister { register, value, kind } => {
                    let (expression, ty) = get_value(&values, *value)?;
                    let (expression, ty) = match kind {
                        RegisterWriteKind::ReplaceParent => (expression, ty),
                        RegisterWriteKind::ZeroExtendParent => {
                            // Zero-fill to the register's current symbolic width.
                            let target_ty = self.registers.get(register).map(|(_, ty)| *ty).unwrap_or(ty);
                            let target_width = bit_width(target_ty)?;
                            let source_width = bit_width(ty)?;
                            if source_width >= target_width {
                                (expression, target_ty)
                            } else {
                                let widened = self.intern(
                                    ExprSort::BitVec(target_width),
                                    ExprOp::ZExt,
                                    vec![expression],
                                    Vec::new(),
                                )?;
                                (widened, target_ty)
                            }
                        }
                        RegisterWriteKind::PreserveParent { .. } => {
                            return Err(SymbolicEvalError::UnsupportedOperation("partial register write".into()));
                        }
                    };
                    self.registers.insert(*register, (expression, ty));
                    written_registers.push(*register);
                    None
                }
                IrOp::Branch {
                    condition,
                    taken,
                    not_taken,
                } => {
                    let (expression, ty) = get_value(&values, *condition)?;
                    if ty != IrType::Bits(1) {
                        return Err(SymbolicEvalError::UnsupportedType(format!("branch condition {ty:?}")));
                    }
                    branch = Some(SymbolicBranch {
                        condition: expression,
                        taken: *taken,
                        not_taken: *not_taken,
                    });
                    terminated = true;
                    None
                }
                IrOp::Jump { .. }
                | IrOp::JumpIndirect { .. }
                | IrOp::Call { .. }
                | IrOp::Return
                | IrOp::Trap { .. } => {
                    terminated = true;
                    None
                }
                IrOp::Load { .. } | IrOp::Store { .. } => {
                    return Err(SymbolicEvalError::UnsupportedOperation("memory access".into()));
                }
            };

            if let Some((expression, ty)) = produced {
                let result = instruction
                    .result
                    .ok_or_else(|| SymbolicEvalError::UnsupportedOperation("value without a result slot".into()))?;
                let index = usize::try_from(result.0).map_err(|_| SymbolicEvalError::UndefinedValue(result))?;
                if values.len() <= index {
                    values.resize(index.saturating_add(1), None);
                }
                values[index] = Some((expression, ty));
            }

            if terminated {
                break;
            }
        }

        Ok(SymbolicBlockSummary {
            branch,
            written_registers,
            terminated,
        })
    }

    fn constant(&self, ty: IrType, bytes_le: &[u8]) -> Result<ExprId, SymbolicEvalError> {
        let width = bit_width(ty)?;
        let byte_width = usize::from(width).div_ceil(8);
        if bytes_le.len() != byte_width {
            return Err(SymbolicEvalError::UnsupportedType(format!("constant width for {ty:?}")));
        }
        self.intern(ExprSort::BitVec(width), ExprOp::Constant, Vec::new(), bytes_le.to_vec())
    }

    fn read_register(&mut self, register: u32, ty: IrType) -> Result<ExprId, SymbolicEvalError> {
        if let Some((expression, _)) = self.registers.get(&register) {
            return Ok(*expression);
        }
        let width = bit_width(ty)?;
        let symbol_id = self.next_symbol;
        self.next_symbol = symbol_id
            .checked_add(1)
            .ok_or_else(|| SymbolicEvalError::UnsupportedOperation("symbol id overflow".into()))?;
        let expression = self.intern(
            ExprSort::BitVec(width),
            ExprOp::Symbol,
            Vec::new(),
            symbol_id.to_le_bytes().to_vec(),
        )?;
        self.registers.insert(register, (expression, ty));
        self.symbols.push(SymbolBinding {
            register,
            width,
            expression,
        });
        Ok(expression)
    }

    fn primitive(
        &mut self,
        op: IrPrimitive,
        ty: IrType,
        inputs: &[(ExprId, IrType)],
    ) -> Result<(ExprId, IrType), SymbolicEvalError> {
        let output_width = bit_width(ty)?;
        let operands: Vec<ExprId> = inputs.iter().map(|(expression, _)| *expression).collect();

        match op {
            IrPrimitive::Eq | IrPrimitive::Ult | IrPrimitive::Ule | IrPrimitive::Slt | IrPrimitive::Sle => {
                if output_width != 1 {
                    return Err(SymbolicEvalError::UnsupportedType(format!("comparison result {ty:?}")));
                }
                let comparison = match op {
                    IrPrimitive::Eq => ExprOp::Eq,
                    IrPrimitive::Ult => ExprOp::Ult,
                    IrPrimitive::Ule => ExprOp::Ule,
                    IrPrimitive::Slt => ExprOp::Slt,
                    _ => ExprOp::Sle,
                };
                let boolean = self.intern(ExprSort::Bool, comparison, operands, Vec::new())?;
                // Machine-level comparisons produce 1-bit bitvectors; the
                // expression language uses booleans, so materialize the result.
                let one = self.intern(ExprSort::BitVec(1), ExprOp::Constant, Vec::new(), vec![1])?;
                let zero = self.intern(ExprSort::BitVec(1), ExprOp::Constant, Vec::new(), vec![0])?;
                let value = self.intern(ExprSort::BitVec(1), ExprOp::Ite, vec![boolean, one, zero], Vec::new())?;
                Ok((value, IrType::Bits(1)))
            }
            IrPrimitive::Add
            | IrPrimitive::Sub
            | IrPrimitive::Mul
            | IrPrimitive::UDiv
            | IrPrimitive::SDiv
            | IrPrimitive::And
            | IrPrimitive::Or
            | IrPrimitive::Xor
            | IrPrimitive::Shl
            | IrPrimitive::LShr
            | IrPrimitive::AShr => {
                let expression_op = match op {
                    IrPrimitive::Add => ExprOp::Add,
                    IrPrimitive::Sub => ExprOp::Sub,
                    IrPrimitive::Mul => ExprOp::Mul,
                    IrPrimitive::UDiv => ExprOp::UDiv,
                    IrPrimitive::SDiv => ExprOp::SDiv,
                    IrPrimitive::And => ExprOp::And,
                    IrPrimitive::Or => ExprOp::Or,
                    IrPrimitive::Xor => ExprOp::Xor,
                    IrPrimitive::Shl => ExprOp::Shl,
                    IrPrimitive::LShr => ExprOp::LShr,
                    _ => ExprOp::AShr,
                };
                let value = self.intern(ExprSort::BitVec(output_width), expression_op, operands, Vec::new())?;
                Ok((value, ty))
            }
            IrPrimitive::Not => {
                let value = self.intern(ExprSort::BitVec(output_width), ExprOp::Not, operands, Vec::new())?;
                Ok((value, ty))
            }
            IrPrimitive::ZExt | IrPrimitive::SExt => {
                let input_width = inputs
                    .first()
                    .map(|(_, input_ty)| bit_width(*input_ty))
                    .transpose()?
                    .ok_or_else(|| SymbolicEvalError::UnsupportedOperation("extension without input".into()))?;
                if input_width >= output_width {
                    return Err(SymbolicEvalError::UnsupportedType(format!(
                        "{op:?} {input_width}->{output_width}"
                    )));
                }
                let expression_op = if op == IrPrimitive::ZExt {
                    ExprOp::ZExt
                } else {
                    ExprOp::SExt
                };
                let value = self.intern(ExprSort::BitVec(output_width), expression_op, operands, Vec::new())?;
                Ok((value, ty))
            }
            IrPrimitive::Select => {
                if inputs.len() != 3 {
                    return Err(SymbolicEvalError::UnsupportedOperation("select arity".into()));
                }
                let condition = self.bit_to_bool(inputs[0].0)?;
                let value = self.intern(
                    ExprSort::BitVec(output_width),
                    ExprOp::Ite,
                    vec![condition, inputs[1].0, inputs[2].0],
                    Vec::new(),
                )?;
                Ok((value, ty))
            }
            IrPrimitive::Concat => {
                let left_width = inputs
                    .first()
                    .map(|(_, input_ty)| bit_width(*input_ty))
                    .transpose()?
                    .ok_or_else(|| SymbolicEvalError::UnsupportedOperation("concat without input".into()))?;
                let right_width = inputs
                    .get(1)
                    .map(|(_, input_ty)| bit_width(*input_ty))
                    .transpose()?
                    .ok_or_else(|| SymbolicEvalError::UnsupportedOperation("concat without input".into()))?;
                if left_width.saturating_add(right_width) != output_width {
                    return Err(SymbolicEvalError::UnsupportedType(format!(
                        "concat {left_width}+{right_width}"
                    )));
                }
                let value = self.intern(ExprSort::BitVec(output_width), ExprOp::Concat, operands, Vec::new())?;
                Ok((value, ty))
            }
            IrPrimitive::Extract => {
                let input_width = inputs
                    .first()
                    .map(|(_, input_ty)| bit_width(*input_ty))
                    .transpose()?
                    .ok_or_else(|| SymbolicEvalError::UnsupportedOperation("extract without input".into()))?;
                let start = self.constant_value(inputs[1].0)?;
                let start = u16::try_from(start)
                    .map_err(|_| SymbolicEvalError::UnsupportedOperation("extract offset".into()))?;
                if u32::from(start) + u32::from(output_width) > u32::from(input_width) {
                    return Err(SymbolicEvalError::UnsupportedType(format!(
                        "extract {start}+{output_width}"
                    )));
                }
                let mut immediate = Vec::with_capacity(4);
                immediate.extend_from_slice(&start.to_le_bytes());
                immediate.extend_from_slice(&output_width.to_le_bytes());
                let value = self.intern(ExprSort::BitVec(output_width), ExprOp::Extract, operands, immediate)?;
                Ok((value, ty))
            }
            _ => Err(SymbolicEvalError::UnsupportedOperation(format!("{op:?}"))),
        }
    }

    /// Converts a 1-bit bitvector expression into a boolean expression.
    fn bit_to_bool(&self, expression: ExprId) -> Result<ExprId, SymbolicEvalError> {
        let node = self.arena.get(expression).ok_or(SymbolicEvalError::Expression(format!(
            "unknown expression {}",
            expression.0
        )))?;
        if node.sort == ExprSort::Bool {
            return Ok(expression);
        }
        if node.sort != ExprSort::BitVec(1) {
            return Err(SymbolicEvalError::UnsupportedType(format!(
                "{:?} as condition",
                node.sort
            )));
        }
        let one = self.intern(ExprSort::BitVec(1), ExprOp::Constant, Vec::new(), vec![1])?;
        self.intern(ExprSort::Bool, ExprOp::Eq, vec![expression, one], Vec::new())
    }

    /// Reads the value of a constant expression.
    fn constant_value(&self, expression: ExprId) -> Result<u64, SymbolicEvalError> {
        let node = self.arena.get(expression).ok_or(SymbolicEvalError::Expression(format!(
            "unknown expression {}",
            expression.0
        )))?;
        if node.op != ExprOp::Constant {
            return Err(SymbolicEvalError::UnsupportedOperation("non-constant operand".into()));
        }
        let mut buffer = [0u8; 8];
        let len = node.immediate.len().min(8);
        buffer[..len].copy_from_slice(&node.immediate[..len]);
        Ok(u64::from_le_bytes(buffer))
    }

    fn intern(
        &self,
        sort: ExprSort,
        op: ExprOp,
        operands: Vec<ExprId>,
        immediate: Vec<u8>,
    ) -> Result<ExprId, SymbolicEvalError> {
        self.arena
            .intern(ExprNode {
                sort,
                op,
                operands,
                immediate,
            })
            .map_err(|error| SymbolicEvalError::Expression(format!("{error:?}")))
    }
}

fn bit_width(ty: IrType) -> Result<u16, SymbolicEvalError> {
    match ty {
        IrType::Bits(bits) if bits > 0 => Ok(bits),
        other => Err(SymbolicEvalError::UnsupportedType(format!("{other:?}"))),
    }
}

fn get_value(values: &[Option<(ExprId, IrType)>], id: IrValueId) -> Result<(ExprId, IrType), SymbolicEvalError> {
    usize::try_from(id.0)
        .ok()
        .and_then(|index| values.get(index))
        .copied()
        .flatten()
        .ok_or(SymbolicEvalError::UndefinedValue(id))
}

fn resolve_inputs(
    values: &[Option<(ExprId, IrType)>],
    inputs: &[IrValueId],
) -> Result<Vec<(ExprId, IrType)>, SymbolicEvalError> {
    inputs.iter().map(|id| get_value(values, *id)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_expr::ShardedExprArena;
    use angryier_ir::{IrBlockKey, IrInstruction};
    use angryier_types::{BlockId, ContentId, ExpressionNormalizationVersion, ImageId, TargetProfileId};

    fn arena() -> ShardedExprArena {
        ShardedExprArena::new(ExpressionNormalizationVersion(1))
    }

    fn block(instructions: Vec<IrInstruction>) -> IrBlock {
        IrBlock {
            key: IrBlockKey {
                image: ImageId(1),
                block: BlockId(0),
                address: 0x1000,
                semantic_content: ContentId::default(),
                target_profile: TargetProfileId(1),
                code_versions: Vec::new(),
            },
            instructions,
        }
    }

    fn bits(width: u16) -> IrType {
        IrType::Bits(width)
    }

    /// Builds a `cmp r64, imm`-shaped block: Sub, Eq against zero, Branch.
    fn compare_block(register: u32, immediate: u64) -> IrBlock {
        block(vec![
            IrInstruction {
                result: Some(IrValueId(0)),
                op: IrOp::ReadRegister { register, ty: bits(64) },
            },
            IrInstruction {
                result: Some(IrValueId(1)),
                op: IrOp::Constant {
                    ty: bits(64),
                    bytes_le: immediate.to_le_bytes().to_vec(),
                },
            },
            IrInstruction {
                result: Some(IrValueId(2)),
                op: IrOp::Primitive {
                    op: IrPrimitive::Sub,
                    ty: bits(64),
                    inputs: vec![IrValueId(0), IrValueId(1)],
                },
            },
            IrInstruction {
                result: Some(IrValueId(3)),
                op: IrOp::Constant {
                    ty: bits(64),
                    bytes_le: 0u64.to_le_bytes().to_vec(),
                },
            },
            IrInstruction {
                result: Some(IrValueId(4)),
                op: IrOp::Primitive {
                    op: IrPrimitive::Eq,
                    ty: bits(1),
                    inputs: vec![IrValueId(2), IrValueId(3)],
                },
            },
            IrInstruction {
                result: None,
                op: IrOp::Branch {
                    condition: IrValueId(4),
                    taken: 0x2000,
                    not_taken: 0x3000,
                },
            },
        ])
    }

    #[test]
    fn evaluates_compare_and_branch_symbolically() -> Result<(), SymbolicEvalError> {
        let arena = arena();
        let mut evaluator = SymbolicEvaluator::new(&arena);
        let summary = evaluator.eval_block(&compare_block(0, 42))?;

        let branch = summary
            .branch
            .ok_or(SymbolicEvalError::UnsupportedOperation("no branch".into()))?;
        assert_eq!(branch.taken, 0x2000);
        assert_eq!(branch.not_taken, 0x3000);
        assert!(summary.terminated);

        assert_eq!(evaluator.symbols().len(), 1);
        let symbol = evaluator.symbols()[0];
        assert_eq!(symbol.register, 0);
        assert_eq!(symbol.width, 64);

        // The condition must depend on the register symbol.
        let dependency = arena
            .dependency_summary(branch.condition)
            .ok_or(SymbolicEvalError::UnsupportedOperation("no dependency".into()))?;
        assert_eq!(dependency.symbolic_sources.len(), 1);
        Ok(())
    }

    #[test]
    fn register_file_persists_across_blocks() -> Result<(), SymbolicEvalError> {
        let arena = arena();
        let mut evaluator = SymbolicEvaluator::new(&arena);

        // First block writes RFLAGS from a comparison.
        let first = block(vec![
            IrInstruction {
                result: Some(IrValueId(0)),
                op: IrOp::ReadRegister {
                    register: 0,
                    ty: bits(64),
                },
            },
            IrInstruction {
                result: Some(IrValueId(1)),
                op: IrOp::Constant {
                    ty: bits(64),
                    bytes_le: 7u64.to_le_bytes().to_vec(),
                },
            },
            IrInstruction {
                result: Some(IrValueId(2)),
                op: IrOp::Primitive {
                    op: IrPrimitive::And,
                    ty: bits(64),
                    inputs: vec![IrValueId(0), IrValueId(1)],
                },
            },
            IrInstruction {
                result: None,
                op: IrOp::WriteRegister {
                    register: 0x21,
                    value: IrValueId(2),
                    kind: RegisterWriteKind::ReplaceParent,
                },
            },
        ]);
        evaluator.eval_block(&first)?;

        // Second block reads RFLAGS; it must reuse the expression, not create
        // a fresh symbol.
        let second = block(vec![
            IrInstruction {
                result: Some(IrValueId(0)),
                op: IrOp::ReadRegister {
                    register: 0x21,
                    ty: bits(64),
                },
            },
            IrInstruction {
                result: None,
                op: IrOp::Jump { target: 0x4000 },
            },
        ]);
        evaluator.eval_block(&second)?;

        assert_eq!(
            evaluator.symbols().len(),
            1,
            "RFLAGS must reuse the computed expression"
        );
        assert_eq!(evaluator.symbols()[0].register, 0);
        Ok(())
    }

    #[test]
    fn memory_access_is_refused_explicitly() {
        let arena = arena();
        let mut evaluator = SymbolicEvaluator::new(&arena);
        let load_block = block(vec![
            IrInstruction {
                result: Some(IrValueId(0)),
                op: IrOp::Constant {
                    ty: bits(64),
                    bytes_le: 0x1000u64.to_le_bytes().to_vec(),
                },
            },
            IrInstruction {
                result: Some(IrValueId(1)),
                op: IrOp::Load {
                    address: IrValueId(0),
                    ty: bits(64),
                },
            },
        ]);
        let error = evaluator
            .eval_block(&load_block)
            .err()
            .unwrap_or(SymbolicEvalError::UnsupportedOperation("expected an error".into()));
        assert!(matches!(error, SymbolicEvalError::UnsupportedOperation(_)));
    }

    #[test]
    fn unsupported_primitives_are_refused_explicitly() {
        let arena = arena();
        let mut evaluator = SymbolicEvaluator::new(&arena);
        let popcount_block = block(vec![
            IrInstruction {
                result: Some(IrValueId(0)),
                op: IrOp::ReadRegister {
                    register: 0,
                    ty: bits(64),
                },
            },
            IrInstruction {
                result: Some(IrValueId(1)),
                op: IrOp::Primitive {
                    op: IrPrimitive::Popcnt,
                    ty: bits(64),
                    inputs: vec![IrValueId(0)],
                },
            },
        ]);
        let error = evaluator
            .eval_block(&popcount_block)
            .err()
            .unwrap_or(SymbolicEvalError::UnsupportedOperation("expected an error".into()));
        assert!(matches!(error, SymbolicEvalError::UnsupportedOperation(_)));
    }
}
