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
use angryier_memory::ByteValue;
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
        primitive_expr(self.arena, op, ty, inputs)
    }

    fn intern(
        &self,
        sort: ExprSort,
        op: ExprOp,
        operands: Vec<ExprId>,
        immediate: Vec<u8>,
    ) -> Result<ExprId, SymbolicEvalError> {
        intern(self.arena, sort, op, operands, immediate)
    }
}

fn intern(
    arena: &SymbolicArena,
    sort: ExprSort,
    op: ExprOp,
    operands: Vec<ExprId>,
    immediate: Vec<u8>,
) -> Result<ExprId, SymbolicEvalError> {
    arena
        .intern(ExprNode {
            sort,
            op,
            operands,
            immediate,
        })
        .map_err(|error| SymbolicEvalError::Expression(format!("{error:?}")))
}

/// Converts a 1-bit bitvector expression into a boolean expression.
fn bit_to_bool(arena: &SymbolicArena, expression: ExprId) -> Result<ExprId, SymbolicEvalError> {
    let node = arena.get(expression).ok_or(SymbolicEvalError::Expression(format!(
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
    let one = intern(arena, ExprSort::BitVec(1), ExprOp::Constant, Vec::new(), vec![1])?;
    intern(arena, ExprSort::Bool, ExprOp::Eq, vec![expression, one], Vec::new())
}

/// Reads the value of a constant expression.
fn constant_value(arena: &SymbolicArena, expression: ExprId) -> Result<u64, SymbolicEvalError> {
    let node = arena.get(expression).ok_or(SymbolicEvalError::Expression(format!(
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

/// Builds the expression for an IR primitive. Shared by the fully symbolic
/// evaluator and the concolic shadow.
fn primitive_expr(
    arena: &SymbolicArena,
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
            let boolean = intern(arena, ExprSort::Bool, comparison, operands, Vec::new())?;
            // Machine-level comparisons produce 1-bit bitvectors; the
            // expression language uses booleans, so materialize the result.
            let one = intern(arena, ExprSort::BitVec(1), ExprOp::Constant, Vec::new(), vec![1])?;
            let zero = intern(arena, ExprSort::BitVec(1), ExprOp::Constant, Vec::new(), vec![0])?;
            let value = intern(
                arena,
                ExprSort::BitVec(1),
                ExprOp::Ite,
                vec![boolean, one, zero],
                Vec::new(),
            )?;
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
            let value = intern(
                arena,
                ExprSort::BitVec(output_width),
                expression_op,
                operands,
                Vec::new(),
            )?;
            Ok((value, ty))
        }
        IrPrimitive::Not => {
            let value = intern(arena, ExprSort::BitVec(output_width), ExprOp::Not, operands, Vec::new())?;
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
            let value = intern(
                arena,
                ExprSort::BitVec(output_width),
                expression_op,
                operands,
                Vec::new(),
            )?;
            Ok((value, ty))
        }
        IrPrimitive::Select => {
            if inputs.len() != 3 {
                return Err(SymbolicEvalError::UnsupportedOperation("select arity".into()));
            }
            let condition = bit_to_bool(arena, inputs[0].0)?;
            let value = intern(
                arena,
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
            let value = intern(
                arena,
                ExprSort::BitVec(output_width),
                ExprOp::Concat,
                operands,
                Vec::new(),
            )?;
            Ok((value, ty))
        }
        IrPrimitive::Extract => {
            let input_width = inputs
                .first()
                .map(|(_, input_ty)| bit_width(*input_ty))
                .transpose()?
                .ok_or_else(|| SymbolicEvalError::UnsupportedOperation("extract without input".into()))?;
            let start = constant_value(arena, inputs[1].0)?;
            let start =
                u16::try_from(start).map_err(|_| SymbolicEvalError::UnsupportedOperation("extract offset".into()))?;
            if u32::from(start) + u32::from(output_width) > u32::from(input_width) {
                return Err(SymbolicEvalError::UnsupportedType(format!(
                    "extract {start}+{output_width}"
                )));
            }
            let mut immediate = Vec::with_capacity(4);
            immediate.extend_from_slice(&start.to_le_bytes());
            immediate.extend_from_slice(&output_width.to_le_bytes());
            // The arena encodes the extract offset in the immediate; the
            // operand list carries only the value being extracted.
            let value = intern(
                arena,
                ExprSort::BitVec(output_width),
                ExprOp::Extract,
                vec![operands[0]],
                immediate,
            )?;
            Ok((value, ty))
        }
        _ => Err(SymbolicEvalError::UnsupportedOperation(format!("{op:?}"))),
    }
}

/// Architectural source a concolic symbol is bound to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConcolicSource {
    /// A register read seeded as an input symbol.
    Register { register: u32, width: u16 },
    /// A memory byte seeded as an input symbol.
    Memory { address: u64 },
}

/// A concolic input symbol together with its architectural source. Solver
/// models are keyed by `expression`; `source` maps the model back onto input
/// bytes or registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConcolicBinding {
    pub source: ConcolicSource,
    pub expression: ExprId,
}

/// Supplies the concrete state a concolic shadow falls back to: registers and
/// memory bytes the shadow has not diverged from.
pub trait ConcolicImage {
    /// Concrete bytes of `register` (little-endian), or `None` when unknown.
    fn read_register(&self, register: u32) -> Option<Vec<u8>>;
    /// Concrete/symbolic bytes at `address`, or `None` when unmapped.
    fn read_bytes(&self, address: u64, length: usize) -> Option<Vec<ByteValue>>;
}

/// One recorded branch constraint: the 1-bit condition expression and the
/// direction concrete execution took.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathConstraint {
    pub condition: ExprId,
    pub taken: bool,
}

/// Evaluates AngryIR blocks concolically: untainted registers and memory read
/// as concrete constants from the image, while input-seeded symbols propagate
/// expressions through the same lowered semantics the concrete interpreter
/// executes. This is the EXPLORE-mode shadow — expressions stay bounded to
/// input-derived data instead of starting every register unconstrained.
pub struct ConcolicEvaluator<'a> {
    arena: &'a SymbolicArena,
    registers: BTreeMap<u32, (ExprId, IrType)>,
    /// Concrete shadow value per register — `Some` when the register's value
    /// is fully determined (constants propagate so computed addresses stay
    /// concrete).
    register_concretes: BTreeMap<u32, Option<u128>>,
    memory: BTreeMap<u64, ByteValue>,
    bindings: Vec<ConcolicBinding>,
    next_symbol: u64,
}

impl<'a> ConcolicEvaluator<'a> {
    /// Creates a concolic evaluator over `arena`.
    pub fn new(arena: &'a SymbolicArena) -> Self {
        Self {
            arena,
            registers: BTreeMap::new(),
            register_concretes: BTreeMap::new(),
            memory: BTreeMap::new(),
            bindings: Vec::new(),
            next_symbol: 0,
        }
    }

    /// Symbols created so far, in creation order.
    pub fn bindings(&self) -> &[ConcolicBinding] {
        &self.bindings
    }

    /// Current shadow value of a register, if divergent from concrete.
    pub fn register_value(&self, register: u32) -> Option<ExprId> {
        self.registers.get(&register).map(|(expression, _)| *expression)
    }

    /// Registers whose shadow expression is not a plain constant — the
    /// input-derived set, for diagnostics.
    pub fn symbolic_registers(&self) -> Vec<(u32, ExprId)> {
        self.registers
            .iter()
            .filter(|(register, _)| {
                self.register_concretes
                    .get(register)
                    .map(|concrete| concrete.is_none())
                    .unwrap_or(false)
            })
            .map(|(register, (expression, _))| (*register, *expression))
            .collect()
    }

    /// Seeds `register` as an input symbol.
    pub fn mark_register(&mut self, register: u32, ty: IrType) -> Result<ExprId, SymbolicEvalError> {
        let width = bit_width(ty)?;
        let expression = self.fresh_symbol(width)?;
        self.registers.insert(register, (expression, ty));
        self.register_concretes.insert(register, None);
        self.bindings.push(ConcolicBinding {
            source: ConcolicSource::Register { register, width },
            expression,
        });
        Ok(expression)
    }

    /// Seeds `length` bytes at `address` as input symbols, one symbol per byte.
    pub fn mark_memory(&mut self, address: u64, length: usize) -> Result<(), SymbolicEvalError> {
        for offset in 0..length as u64 {
            let expression = self.fresh_symbol(8)?;
            self.memory.insert(address + offset, ByteValue::Symbolic(expression));
            self.bindings.push(ConcolicBinding {
                source: ConcolicSource::Memory {
                    address: address + offset,
                },
                expression,
            });
        }
        Ok(())
    }

    fn fresh_symbol(&mut self, width: u16) -> Result<ExprId, SymbolicEvalError> {
        let symbol_id = self.next_symbol;
        self.next_symbol = symbol_id
            .checked_add(1)
            .ok_or_else(|| SymbolicEvalError::UnsupportedOperation("symbol id overflow".into()))?;
        intern(
            self.arena,
            ExprSort::BitVec(width),
            ExprOp::Symbol,
            Vec::new(),
            symbol_id.to_le_bytes().to_vec(),
        )
    }

    /// Symbolically evaluates one block against `image`, concretizing any
    /// register or memory byte not carrying a symbol.
    pub fn eval_block(
        &mut self,
        image: &dyn ConcolicImage,
        block: &IrBlock,
    ) -> Result<SymbolicBlockSummary, SymbolicEvalError> {
        let mut values: Vec<Option<(ExprId, Option<u128>, IrType)>> = Vec::new();
        let mut written_registers = Vec::new();
        let mut branch = None;
        let mut terminated = false;

        for instruction in &block.instructions {
            let produced = match &instruction.op {
                IrOp::Constant { ty, bytes_le } => {
                    let concrete = bytes_le
                        .iter()
                        .enumerate()
                        .take(16)
                        .fold(0u128, |acc, (index, byte)| acc | (u128::from(*byte) << (8 * index)));
                    Some((self.constant(*ty, bytes_le)?, Some(concrete), *ty))
                }
                IrOp::ExprRef { expression, ty } => Some((*expression, None, *ty)),
                IrOp::ReadRegister { register, ty } => {
                    let (expression, concrete) = self.read_register(image, *register, *ty)?;
                    Some((expression, concrete, *ty))
                }
                IrOp::Primitive { op, ty, inputs } => {
                    let resolved = resolve_inputs_c(&values, inputs)?;
                    let (expression, concrete) = self.primitive_concolic(*op, *ty, &resolved)?;
                    Some((expression, concrete, *ty))
                }
                IrOp::WriteRegister { register, value, kind } => {
                    let (expression, mut concrete, ty) = get_value_c(&values, *value)?;
                    let (expression, ty) = match kind {
                        RegisterWriteKind::ReplaceParent => (expression, ty),
                        RegisterWriteKind::ZeroExtendParent => {
                            let target_ty = self.register_ty(image, *register)?;
                            let target_width = bit_width(target_ty)?;
                            let source_width = bit_width(ty)?;
                            if source_width >= target_width {
                                (expression, target_ty)
                            } else {
                                let widened = intern(
                                    self.arena,
                                    ExprSort::BitVec(target_width),
                                    ExprOp::ZExt,
                                    vec![expression],
                                    Vec::new(),
                                )?;
                                (widened, target_ty)
                            }
                        }
                        RegisterWriteKind::PreserveParent { bit_offset, .. } => {
                            let parent_ty = self.register_ty(image, *register)?;
                            let parent_width = bit_width(parent_ty)?;
                            let source_width = bit_width(ty)?;
                            if source_width >= parent_width {
                                (expression, parent_ty)
                            } else {
                                let (parent, parent_concrete) = self.read_register(image, *register, parent_ty)?;
                                let merged =
                                    self.splice_bits(parent, parent_width, expression, *bit_offset, source_width)?;
                                concrete = concrete.and_then(|value| {
                                    parent_concrete.map(|parent| {
                                        splice_concrete(parent, parent_width, value, *bit_offset, source_width)
                                    })
                                });
                                (merged, parent_ty)
                            }
                        }
                    };
                    // Fold the stored value when its expression is a constant.
                    if concrete.is_none() {
                        concrete = constant_value(self.arena, expression).ok().map(u128::from);
                    }
                    self.registers.insert(*register, (expression, ty));
                    self.register_concretes.insert(*register, concrete);
                    written_registers.push(*register);
                    None
                }
                IrOp::Branch {
                    condition,
                    taken,
                    not_taken,
                } => {
                    let (expression, _, ty) = get_value_c(&values, *condition)?;
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
                IrOp::Load { address, ty } => {
                    let (address, concrete_address, _) = get_value_c(&values, *address)?;
                    let (expression, concrete) = self.load(image, address, concrete_address, *ty)?;
                    Some((expression, concrete, *ty))
                }
                IrOp::Store { address, value } => {
                    let (address, concrete_address, _) = get_value_c(&values, *address)?;
                    let (value, _, ty) = get_value_c(&values, *value)?;
                    self.store(address, concrete_address, value, ty)?;
                    None
                }
            };

            if produced.is_some() {
                let result = instruction
                    .result
                    .ok_or_else(|| SymbolicEvalError::UnsupportedOperation("value without a result slot".into()))?;
                let index = usize::try_from(result.0).map_err(|_| SymbolicEvalError::UndefinedValue(result))?;
                if values.len() <= index {
                    values.resize(index.saturating_add(1), None);
                }
                values[index] = produced;
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

    /// Evaluates a primitive concolically: when every input carries a
    /// concrete value the result folds to a constant (keeping addresses and
    /// flag computations concrete); otherwise it builds the expression.
    fn primitive_concolic(
        &mut self,
        op: IrPrimitive,
        ty: IrType,
        inputs: &[(ExprId, Option<u128>, IrType)],
    ) -> Result<(ExprId, Option<u128>), SymbolicEvalError> {
        let output_width = bit_width(ty)?;
        let concretes: Option<Vec<u128>> = inputs.iter().map(|(_, concrete, _)| *concrete).collect();
        if let Some(concretes) = concretes
            && output_width <= 128
        {
            let typed: Vec<(u128, u16)> = inputs
                .iter()
                .zip(concretes.iter())
                .map(|((_, _, input_ty), value)| (*value, bit_width(*input_ty).unwrap_or(64)))
                .collect();
            if typed.iter().all(|(_, width)| *width <= 128)
                && let Some(result) = eval_primitive_concrete(op, output_width, &typed)
            {
                let byte_width = usize::from(output_width).div_ceil(8);
                let mut bytes = result.to_le_bytes().to_vec();
                bytes.resize(byte_width, 0);
                let expression = intern(
                    self.arena,
                    ExprSort::BitVec(output_width),
                    ExprOp::Constant,
                    Vec::new(),
                    bytes,
                )?;
                return Ok((expression, Some(result)));
            }
        }
        let resolved: Vec<(ExprId, IrType)> = inputs
            .iter()
            .map(|(expression, _, input_ty)| (*expression, *input_ty))
            .collect();
        let (expression, _) = primitive_expr(self.arena, op, ty, &resolved)?;
        Ok((expression, None))
    }

    /// Replaces `source_width` bits at `bit_offset` inside `parent` with
    /// `value`, producing `concat(high, value, low)`.
    fn splice_bits(
        &mut self,
        parent: ExprId,
        parent_width: u16,
        value: ExprId,
        bit_offset: u16,
        source_width: u16,
    ) -> Result<ExprId, SymbolicEvalError> {
        let high_width = parent_width - bit_offset - source_width;
        let mut parts = Vec::new();
        if high_width > 0 {
            parts.push(self.extract(parent, bit_offset + source_width, high_width)?);
        }
        parts.push(value);
        if bit_offset > 0 {
            parts.push(self.extract(parent, 0, bit_offset)?);
        }
        let mut acc = parts[0];
        let mut acc_width = if high_width > 0 { high_width } else { source_width };
        for (index, part) in parts.iter().enumerate().skip(1) {
            let part_width = if index == parts.len() - 1 && bit_offset > 0 {
                bit_offset
            } else {
                source_width
            };
            acc = intern(
                self.arena,
                ExprSort::BitVec(acc_width + part_width),
                ExprOp::Concat,
                vec![acc, *part],
                Vec::new(),
            )?;
            acc_width += part_width;
        }
        Ok(acc)
    }

    fn extract(&self, expr: ExprId, start: u16, width: u16) -> Result<ExprId, SymbolicEvalError> {
        let mut immediate = Vec::with_capacity(4);
        immediate.extend_from_slice(&start.to_le_bytes());
        immediate.extend_from_slice(&width.to_le_bytes());
        intern(
            self.arena,
            ExprSort::BitVec(width),
            ExprOp::Extract,
            vec![expr],
            immediate,
        )
    }

    /// Shadow register read: returns the tracked expression, or a constant of
    /// the register's concrete value from `image`.
    fn read_register(
        &mut self,
        image: &dyn ConcolicImage,
        register: u32,
        ty: IrType,
    ) -> Result<(ExprId, Option<u128>), SymbolicEvalError> {
        if let Some((expression, stored_ty)) = self.registers.get(&register) {
            let stored_width = bit_width(*stored_ty)?;
            let requested = bit_width(ty)?;
            let expression = *expression;
            let concrete = self.register_concretes.get(&register).copied().flatten();
            // Normalize the stored expression to the requested view width:
            // a register shadowed at one width may be read through a narrower
            // or wider view (al vs rax).
            if stored_width == requested {
                return Ok((expression, concrete));
            }
            return if stored_width > requested {
                let narrowed = concrete.map(|value| value & mask_u128(requested));
                Ok((self.extract(expression, 0, requested)?, narrowed))
            } else {
                let widened = intern(
                    self.arena,
                    ExprSort::BitVec(requested),
                    ExprOp::ZExt,
                    vec![expression],
                    Vec::new(),
                )?;
                // Zero-extension preserves the concrete prefix unchanged.
                Ok((widened, concrete))
            };
        }
        let width = bit_width(ty)?;
        let bytes = image
            .read_register(register)
            .ok_or(SymbolicEvalError::UnsupportedOperation(format!(
                "no concrete value for register {register}"
            )))?;
        let byte_width = usize::from(width).div_ceil(8);
        if bytes.len() < byte_width {
            return Err(SymbolicEvalError::UnsupportedType(format!(
                "register {register} value {} < {byte_width} bytes",
                bytes.len()
            )));
        }
        let expression = self.constant(ty, &bytes[..byte_width])?;
        self.registers.insert(register, (expression, ty));
        let concrete = bytes[..byte_width.min(16)]
            .iter()
            .enumerate()
            .fold(0u128, |acc, (index, byte)| acc | (u128::from(*byte) << (8 * index)));
        self.register_concretes.insert(register, Some(concrete));
        Ok((expression, Some(concrete)))
    }

    /// The declared width of a register: the shadowed type when tracked, else
    /// the image's byte width.
    fn register_ty(&self, image: &dyn ConcolicImage, register: u32) -> Result<IrType, SymbolicEvalError> {
        if let Some((_, ty)) = self.registers.get(&register) {
            return Ok(*ty);
        }
        let bytes = image
            .read_register(register)
            .ok_or(SymbolicEvalError::UnsupportedOperation(format!(
                "no concrete value for register {register}"
            )))?;
        let bits = u16::try_from(bytes.len() * 8)
            .map_err(|_| SymbolicEvalError::UnsupportedType(format!("register {register} width")))?;
        Ok(IrType::Bits(bits))
    }

    /// Loads `ty` bytes: symbolic bytes contribute their expressions,
    /// concrete bytes become constants. All-concrete loads fold to one
    /// constant; mixed loads concatenate per-byte extracts.
    fn load(
        &mut self,
        image: &dyn ConcolicImage,
        address: ExprId,
        concrete_address: Option<u128>,
        ty: IrType,
    ) -> Result<(ExprId, Option<u128>), SymbolicEvalError> {
        let width = bit_width(ty)?;
        let byte_width = usize::from(width).div_ceil(8);
        let base = match concrete_address.and_then(|value| u64::try_from(value).ok()) {
            Some(base) => base,
            None => constant_value(self.arena, address)
                .map_err(|_| SymbolicEvalError::UnsupportedOperation("load with symbolic address".into()))?,
        };

        let mut bytes = Vec::with_capacity(byte_width);
        for offset in 0..byte_width as u64 {
            let byte = match self.memory.get(&(base + offset)) {
                Some(value) => *value,
                None => {
                    let read = image
                        .read_bytes(base + offset, 1)
                        .ok_or(SymbolicEvalError::UnsupportedOperation(format!(
                            "load of unmapped byte {:#x}",
                            base + offset
                        )))?;
                    read.first().copied().unwrap_or(ByteValue::Concrete(0))
                }
            };
            bytes.push(byte);
        }

        if bytes.iter().all(|byte| matches!(byte, ByteValue::Concrete(_))) {
            let data: Vec<u8> = bytes
                .iter()
                .map(|byte| match byte {
                    ByteValue::Concrete(b) => *b,
                    ByteValue::Symbolic(_) => unreachable!(),
                })
                .collect();
            let concrete = data
                .iter()
                .enumerate()
                .take(16)
                .fold(0u128, |acc, (index, byte)| acc | (u128::from(*byte) << (8 * index)));
            return Ok((self.constant(ty, &data)?, Some(concrete)));
        }

        // Little-endian: byte 0 is the least significant. Concatenate from
        // the most significant byte down so byte_width-1 is the high half.
        let mut acc: Option<ExprId> = None;
        for (index, byte) in bytes.iter().enumerate().rev() {
            let byte_expr = match byte {
                ByteValue::Concrete(b) => {
                    intern(self.arena, ExprSort::BitVec(8), ExprOp::Constant, Vec::new(), vec![*b])?
                }
                ByteValue::Symbolic(expression) => *expression,
            };
            acc = Some(match acc {
                None => byte_expr,
                Some(high) => intern(
                    self.arena,
                    ExprSort::BitVec(8 * ((byte_width - index) as u16)),
                    ExprOp::Concat,
                    vec![high, byte_expr],
                    Vec::new(),
                )?,
            });
        }
        let expression = acc.ok_or_else(|| SymbolicEvalError::UnsupportedOperation("empty load".into()))?;
        Ok((expression, None))
    }

    /// Stores `value`: constant values land as concrete bytes; symbolic values
    /// split into per-byte extracts stored as symbolic bytes.
    fn store(
        &mut self,
        address: ExprId,
        concrete_address: Option<u128>,
        value: ExprId,
        ty: IrType,
    ) -> Result<(), SymbolicEvalError> {
        let width = bit_width(ty)?;
        let byte_width = usize::from(width).div_ceil(8);
        let base = match concrete_address.and_then(|value| u64::try_from(value).ok()) {
            Some(base) => base,
            None => constant_value(self.arena, address)
                .map_err(|_| SymbolicEvalError::UnsupportedOperation("store with symbolic address".into()))?,
        };

        let node = self
            .arena
            .get(value)
            .ok_or_else(|| SymbolicEvalError::Expression(format!("unknown expression {}", value.0)))?;
        if node.op == ExprOp::Constant {
            for (offset, byte) in node.immediate.iter().enumerate().take(byte_width) {
                self.memory.insert(base + offset as u64, ByteValue::Concrete(*byte));
            }
            return Ok(());
        }
        for offset in 0..byte_width {
            let byte_expr = self.extract(value, offset as u16 * 8, 8)?;
            self.memory.insert(base + offset as u64, ByteValue::Symbolic(byte_expr));
        }
        Ok(())
    }

    fn constant(&self, ty: IrType, bytes_le: &[u8]) -> Result<ExprId, SymbolicEvalError> {
        let width = bit_width(ty)?;
        let byte_width = usize::from(width).div_ceil(8);
        if bytes_le.len() != byte_width {
            return Err(SymbolicEvalError::UnsupportedType(format!("constant width for {ty:?}")));
        }
        intern(
            self.arena,
            ExprSort::BitVec(width),
            ExprOp::Constant,
            Vec::new(),
            bytes_le.to_vec(),
        )
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

/// Concrete u128 evaluation of a primitive — the concolic constant folder.
/// Each input is `(value, bit_width)`. Returns `None` for ops outside the
/// foldable subset (the caller then keeps the expression).
fn eval_primitive_concrete(op: IrPrimitive, output_width: u16, inputs: &[(u128, u16)]) -> Option<u128> {
    let mask = mask_u128(output_width);
    let signed = |value: u128, width: u16| -> i128 {
        let value = value & mask_u128(width);
        if width > 0 && width < 128 && value & (1u128 << (width - 1)) != 0 {
            (value | !mask_u128(width)) as i128
        } else {
            value as i128
        }
    };
    let result = match op {
        IrPrimitive::Add => inputs[0].0.wrapping_add(inputs[1].0),
        IrPrimitive::Sub => inputs[0].0.wrapping_sub(inputs[1].0),
        IrPrimitive::Mul => inputs[0].0.wrapping_mul(inputs[1].0),
        IrPrimitive::UDiv => {
            if inputs[1].0 == 0 {
                return None;
            }
            inputs[0].0 / inputs[1].0
        }
        IrPrimitive::SDiv => {
            if inputs[1].0 == 0 {
                return None;
            }
            signed(inputs[0].0, inputs[0].1).wrapping_div(signed(inputs[1].0, inputs[1].1)) as u128
        }
        IrPrimitive::And => inputs[0].0 & inputs[1].0,
        IrPrimitive::Or => inputs[0].0 | inputs[1].0,
        IrPrimitive::Xor => inputs[0].0 ^ inputs[1].0,
        IrPrimitive::Not => !inputs[0].0,
        IrPrimitive::Shl => inputs[0].0.wrapping_shl(inputs[1].0 as u32),
        IrPrimitive::LShr => (inputs[0].0 & mask_u128(inputs[0].1)).wrapping_shr(inputs[1].0 as u32),
        IrPrimitive::AShr => {
            let shift = u16::try_from(inputs[1].0).unwrap_or(output_width).min(output_width);
            let extended = signed(inputs[0].0, inputs[0].1);
            (extended >> shift) as u128
        }
        IrPrimitive::Eq => {
            let width = inputs[0].1;
            u128::from(inputs[0].0 & mask_u128(width) == inputs[1].0 & mask_u128(width))
        }
        IrPrimitive::Ult => {
            let width = inputs[0].1;
            u128::from(inputs[0].0 & mask_u128(width) < inputs[1].0 & mask_u128(width))
        }
        IrPrimitive::Ule => {
            let width = inputs[0].1;
            u128::from(inputs[0].0 & mask_u128(width) <= inputs[1].0 & mask_u128(width))
        }
        IrPrimitive::Slt => {
            let width = inputs[0].1;
            u128::from(signed(inputs[0].0, width) < signed(inputs[1].0, width))
        }
        IrPrimitive::Sle => {
            let width = inputs[0].1;
            u128::from(signed(inputs[0].0, width) <= signed(inputs[1].0, width))
        }
        IrPrimitive::Select => {
            if inputs[0].0 != 0 {
                inputs[1].0
            } else {
                inputs[2].0
            }
        }
        IrPrimitive::Concat => {
            // Operand order matches the expression language: (low, high).
            let low_width = inputs[0].1;
            (inputs[1].0 << low_width) | (inputs[0].0 & mask_u128(low_width))
        }
        IrPrimitive::Extract => {
            let start = inputs[1].0;
            (inputs[0].0 >> start) & mask_u128(output_width)
        }
        IrPrimitive::ZExt => inputs[0].0 & mask_u128(inputs[0].1),
        IrPrimitive::SExt => signed(inputs[0].0, inputs[0].1) as u128,
        _ => return None,
    };
    Some(result & mask)
}

fn get_value_c(
    values: &[Option<(ExprId, Option<u128>, IrType)>],
    id: IrValueId,
) -> Result<(ExprId, Option<u128>, IrType), SymbolicEvalError> {
    usize::try_from(id.0)
        .ok()
        .and_then(|index| values.get(index))
        .copied()
        .flatten()
        .ok_or(SymbolicEvalError::UndefinedValue(id))
}

fn resolve_inputs_c(
    values: &[Option<(ExprId, Option<u128>, IrType)>],
    inputs: &[IrValueId],
) -> Result<Vec<(ExprId, Option<u128>, IrType)>, SymbolicEvalError> {
    inputs.iter().map(|id| get_value_c(values, *id)).collect()
}

fn mask_u128(width: u16) -> u128 {
    if width >= 128 { u128::MAX } else { (1u128 << width) - 1 }
}

/// Concrete splice for `PreserveParent` writes.
fn splice_concrete(parent: u128, parent_width: u16, value: u128, bit_offset: u16, source_width: u16) -> u128 {
    let low_mask = mask_u128(bit_offset);
    let high_mask = mask_u128(parent_width - bit_offset - source_width);
    let high = (parent >> (bit_offset + source_width)) & high_mask;
    (high << (bit_offset + source_width)) | ((value & mask_u128(source_width)) << bit_offset) | (parent & low_mask)
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
