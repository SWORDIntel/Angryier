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

use std::collections::{BTreeMap, HashMap, HashSet};

use angryier_expr::{ExprArena, ExprArenaError, ExprNode, ExprOp, ExprSort};
use angryier_ir::{IrBlock, IrOp, IrPrimitive, IrType, IrValueId, RegisterWriteKind};
use angryier_memory::ByteValue;
use angryier_types::{Address, ExprId};

/// Expression arena type used by the evaluator.
pub type SymbolicArena = dyn ExprArena<Error = ExprArenaError>;

/// Errors produced while symbolically evaluating an AngryIR block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SymbolicEvalError {
    /// A memory address expression could not be concretized — the session
    /// can solve it and retry (solver-assisted concretization).
    UnresolvedAddress(ExprId),
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
            Self::UnresolvedAddress(expr) => write!(formatter, "unresolved address expr {}", expr.0),
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
    /// For `JumpIndirect`, the evaluated target expression.
    pub jump_target: Option<ExprId>,
}

/// Symbolically evaluates AngryIR blocks with a shared symbolic register file.
pub struct SymbolicEvaluator<'a> {
    arena: &'a SymbolicArena,
    registers: BTreeMap<u32, (ExprId, IrType)>,
    concrete_registers: BTreeMap<u32, u64>,
    /// Concrete value a load's result expression stands for — memory-
    /// derived pointers resolve through this when they have no register
    /// binding.
    expr_concrete: BTreeMap<ExprId, u64>,
    symbols: Vec<SymbolBinding>,
    next_symbol: u64,
}

impl<'a> SymbolicEvaluator<'a> {
    /// Creates an evaluator over the given expression arena.
    pub fn new(arena: &'a SymbolicArena) -> Self {
        Self {
            arena,
            registers: BTreeMap::new(),
            concrete_registers: BTreeMap::new(),
            expr_concrete: BTreeMap::new(),
            symbols: Vec::new(),
            next_symbol: 0,
        }
    }

    /// Symbols created so far, in creation order.
    pub fn symbols(&self) -> &[SymbolBinding] {
        &self.symbols
    }

    /// Resolves a memory address expression: constants evaluate directly;
    /// symbolic expressions resolve via each Symbol leaf's concrete register
    /// value — the concretize-at-boundary policy (the concrete values are
    /// the state's, so `rsp`-derived addresses stay exact).
    fn resolve_address(&self, expression: ExprId) -> Result<u64, SymbolicEvalError> {
        constant_value_resolved(self.arena, expression, &|expr| {
            // A bare register Symbol resolves through its concrete register
            // value; a memory-derived expression resolves through the
            // concrete bytes it was loaded from.
            self.expr_concrete.get(&expr).copied().or_else(|| {
                let node = self.arena.get(expr)?;
                if node.op != ExprOp::Symbol {
                    return None;
                }
                let symbol_id = u64::from_le_bytes(node.immediate.get(..8)?.try_into().ok()?);
                self.symbols
                    .iter()
                    .find(|binding| {
                        binding.expression == expr
                            || self.arena.get(binding.expression).and_then(|n| {
                                n.immediate
                                    .get(..8)
                                    .map(|b| u64::from_le_bytes(b.try_into().unwrap_or([0; 8])))
                            }) == Some(symbol_id)
                    })
                    .and_then(|binding| self.concrete_registers.get(&binding.register).copied())
            })
        })
        .or_else(|_| {
            self.expr_concrete
                .get(&expression)
                .copied()
                .ok_or(SymbolicEvalError::UnresolvedAddress(expression))
        })
    }

    /// Seeds `register` as a fresh input symbol of `ty`.
    pub fn mark_register(&mut self, register: u32, ty: IrType) -> Result<ExprId, SymbolicEvalError> {
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

    /// Current symbolic value of a register, if it has been read or written.
    pub fn register_value(&self, register: u32) -> Option<ExprId> {
        self.registers.get(&register).map(|(expression, _)| *expression)
    }

    /// Snapshot the register file for state merging.
    pub fn snapshot(&self) -> SymbolicStateSnapshot {
        SymbolicStateSnapshot {
            registers: self.registers.clone(),
            concrete_registers: BTreeMap::new(),
            constraints: Vec::new(),
            symbols: self.symbols.clone(),
            expr_concrete: self.expr_concrete.clone(),
        }
    }

    /// Seeds the register file from a snapshot (the restore half of
    /// [`SymbolicEvaluator::snapshot`]) — used by the symbolic session to
    /// run a state across blocks.
    pub fn restore(&mut self, snapshot: &SymbolicStateSnapshot) {
        self.registers = snapshot.registers.clone();
        self.concrete_registers = snapshot.concrete_registers.clone();
        self.expr_concrete = snapshot.expr_concrete.clone();
        self.symbols = snapshot.symbols.clone();
    }

    /// Symbolically evaluates one block.
    pub fn eval_block(&mut self, block: &IrBlock) -> Result<SymbolicBlockSummary, SymbolicEvalError> {
        let mut memory = SymbolicSessionMemory::new(
            angryier_memory::PersistentMemory::new(Vec::new())
                .map_err(|e| SymbolicEvalError::UnsupportedOperation(format!("memory init: {e:?}")))?,
        );
        self.eval_block_with_memory(block, &mut memory)
    }

    /// Symbolically evaluates one block, routing Load/Store through
    /// `memory` — the per-state symbolic byte map.
    pub fn eval_block_with_memory(
        &mut self,
        block: &IrBlock,
        memory: &mut SymbolicSessionMemory,
    ) -> Result<SymbolicBlockSummary, SymbolicEvalError> {
        let mut values: Vec<Option<(ExprId, IrType)>> = Vec::new();
        let mut written_registers = Vec::new();
        let mut branch = None;
        let mut terminated = false;
        let mut jump_target = None;

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
                IrOp::Jump { .. } | IrOp::Call { .. } | IrOp::Return | IrOp::Trap { .. } => {
                    terminated = true;
                    None
                }
                IrOp::JumpIndirect { target } => {
                    terminated = true;
                    jump_target = Some(get_value(&values, *target)?.0);
                    None
                }
                IrOp::Load { address, ty } => {
                    let (addr_expr, _) = get_value(&values, *address)?;
                    let addr = self.resolve_address(addr_expr)?;
                    let width = bit_width(*ty)?;
                    let expr = memory.read(self.arena, addr, width)?;
                    // Record the load's concrete value so pointer-chasing
                    // addresses (loaded pointers feeding later loads)
                    // resolve through this map.
                    if let Ok(bytes) = memory.read_bytes(addr, usize::from(width).div_ceil(8)) {
                        let mut concrete = 0u64;
                        let mut all_concrete = true;
                        for (i, byte) in bytes.iter().enumerate().take(8) {
                            match byte {
                                angryier_memory::ByteValue::Concrete(v) => {
                                    concrete |= u64::from(*v) << (i * 8);
                                }
                                angryier_memory::ByteValue::Symbolic(_) => {
                                    all_concrete = false;
                                }
                            }
                        }
                        if all_concrete {
                            self.expr_concrete.insert(expr, concrete);
                        }
                    }
                    Some((expr, *ty))
                }
                IrOp::Store { address, value } => {
                    let (addr_expr, _) = get_value(&values, *address)?;
                    let addr = self.resolve_address(addr_expr)?;
                    let (expr, ty) = get_value(&values, *value)?;
                    memory.write(self.arena, addr, expr, bit_width(ty)?)?;
                    None
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
            jump_target,
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
            // Normalize the stored expression to the requested view width —
            // the register file may hold the parent-width expression (a
            // 64-bit-tracked rcx read as CL) or a narrowed sub-view write.
            // Without this, operations that do not self-coerce (comparisons)
            // intern ill-sorted nodes; a wider read zero-extends, matching
            // the ZeroExtendParent semantics of 32-bit x86-64 writes.
            let stored = *expression;
            let requested = bit_width(ty)?;
            let coerced = coerce_width(self.arena, stored, requested)?;
            return Ok(coerced);
        }
        let width = bit_width(ty)?;
        // Concrete fallback: untouched registers read their concrete value
        // from the state's snapshot instead of materializing a free symbol —
        // keeps stack pointers and startup registers concrete.
        if let Some(&value) = self.concrete_registers.get(&register) {
            let byte_len = usize::from(width).div_ceil(8);
            let mut bytes = value.to_le_bytes().to_vec();
            bytes.truncate(byte_len.clamp(1, 8));
            let expression = self.intern(ExprSort::BitVec(width), ExprOp::Constant, Vec::new(), bytes)?;
            self.registers.insert(register, (expression, ty));
            return Ok(expression);
        }
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
    let node = ExprNode {
        sort,
        op,
        operands,
        immediate,
    };
    // Formatting the full node here is prohibitively expensive on the hot
    // shadow path (one Debug render per interned node); the arena error plus
    // the op under construction is enough context to diagnose a rejection.
    arena
        .intern(node)
        .map_err(|error| SymbolicEvalError::Expression(format!("{error:?} while interning {op:?} node")))
}

/// Converts a 1-bit bitvector expression into a boolean expression.
/// Converts a Bits(1) branch condition into a Bool expression — Bool when
/// already sorted, otherwise `ite(bit, true, false)` as a Bool node.
pub fn bit_to_bool(arena: &SymbolicArena, expression: ExprId) -> Result<ExprId, SymbolicEvalError> {
    let sort = arena.sort_of(expression).ok_or(SymbolicEvalError::Expression(format!(
        "unknown expression {}",
        expression.0
    )))?;
    if sort == ExprSort::Bool {
        return Ok(expression);
    }
    if sort != ExprSort::BitVec(1) {
        return Err(SymbolicEvalError::UnsupportedType(format!("{sort:?} as condition")));
    }
    let one = intern(arena, ExprSort::BitVec(1), ExprOp::Constant, Vec::new(), vec![1])?;
    intern(arena, ExprSort::Bool, ExprOp::Eq, vec![expression, one], Vec::new())
}

/// Coerces `expr` to `width` bits — ZExt when narrower, Extract the low
/// bits when wider, identity when equal. Shadow types can disagree with a
/// register's declared IR width when a sub-view write left a narrower
/// expression behind; coercion keeps binary ops well-sorted without
/// concretizing.
fn coerce_width(arena: &SymbolicArena, expr: ExprId, width: u16) -> Result<ExprId, SymbolicEvalError> {
    let current = expr_width(arena, expr)?;
    if current == width {
        return Ok(expr);
    }
    if current < width {
        return intern(arena, ExprSort::BitVec(width), ExprOp::ZExt, vec![expr], Vec::new());
    }
    let mut imm = Vec::with_capacity(4);
    imm.extend_from_slice(&0u16.to_le_bytes());
    imm.extend_from_slice(&width.to_le_bytes());
    intern(arena, ExprSort::BitVec(width), ExprOp::Extract, vec![expr], imm)
}

/// Widens the narrower comparison operand to the other's width so the
/// comparison interns well-sorted. Zero-extension preserves equality and
/// unsigned order; signed comparisons sign-widen so a negative narrower
/// value still orders below positive wider ones.
fn comparison_operands(
    arena: &SymbolicArena,
    op: IrPrimitive,
    left: ExprId,
    right: ExprId,
) -> Result<(ExprId, ExprId), SymbolicEvalError> {
    let left_width = expr_width(arena, left)?;
    let right_width = expr_width(arena, right)?;
    if left_width == right_width {
        return Ok((left, right));
    }
    let signed = matches!(op, IrPrimitive::Slt | IrPrimitive::Sle);
    let extension = if signed { ExprOp::SExt } else { ExprOp::ZExt };
    let (narrow, target) = if left_width < right_width {
        (left, right_width)
    } else {
        (right, left_width)
    };
    let widened = intern(arena, ExprSort::BitVec(target), extension, vec![narrow], Vec::new())?;
    if left_width < right_width {
        Ok((widened, right))
    } else {
        Ok((left, widened))
    }
}

/// Reads an expression's bit-width through the arena's lightweight sort probe
/// (a copy of the small sort enum, not a full node clone).
fn expr_width(arena: &SymbolicArena, expr: ExprId) -> Result<u16, SymbolicEvalError> {
    arena
        .sort_of(expr)
        .and_then(|sort| match sort {
            ExprSort::BitVec(w) => Some(w),
            ExprSort::Bool => Some(1),
            _ => None,
        })
        .ok_or_else(|| SymbolicEvalError::UnsupportedType("non-bitvector operand".into()))
}

/// Reads the value of a constant expression — recursively evaluating
/// arithmetic over literal leaves so `Add(Const, Const)`-shaped addresses
/// (from rip-relative or rsp-offset computations) resolve without a solver.
/// Folds a fully-concrete expression to its u64 value — Add/Sub/And/Or/
/// Xor/Shl/LShr/Concat/Extract/ZExt/SExt over Constants; `Not`/`Eq`/`Ite`
/// fold as truth values. Returns `UnsupportedOperation` when a non-
/// constant leaf remains.
pub fn constant_value(arena: &SymbolicArena, expression: ExprId) -> Result<u64, SymbolicEvalError> {
    fold_eval(arena, expression, 0, None, None)
        .ok()
        .ok_or_else(|| SymbolicEvalError::UnsupportedOperation("non-constant operand".into()))
}

/// [`constant_value`] through a caller-owned negative memo shared across
/// calls. Arena nodes are immutable, so a node proven non-constant (a Symbol
/// sits beneath it, or its operator is outside the foldable subset) can never
/// fold later; caching those verdicts turns a loop-carried value's re-fold —
/// one node deeper every iteration — into a memo probe plus one node walk.
/// Depth-capped failures are never cached: a node that merely ran out of
/// recursion budget may fold from a shallower root.
pub fn constant_value_with_memo(
    arena: &SymbolicArena,
    memo: &mut HashSet<ExprId>,
    expression: ExprId,
) -> Result<u64, SymbolicEvalError> {
    fold_eval(arena, expression, 0, None, Some(memo))
        .ok()
        .ok_or_else(|| SymbolicEvalError::UnsupportedOperation("non-constant operand".into()))
}

/// Why a fold produced no value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FoldFail {
    /// The subtree can never fold (Symbol leaf, non-foldable operator, or an
    /// operand that is absolutely non-constant). Memoizable.
    Absolute,
    /// The depth budget ran out; from a shallower root the subtree may still
    /// fold. Not memoizable.
    Depth,
}

/// Shared fold core: `resolve_expr` optionally binds leaves to concrete
/// values, `memo` optionally caches absolute non-constant verdicts (only
/// safe without a resolver, which is stateful between calls). The failure
/// mode distinguishes absolutely non-constant subtrees from depth-capped
/// ones so the memo never records a budget artifact.
#[allow(clippy::type_complexity)]
fn fold_eval(
    arena: &SymbolicArena,
    expression: ExprId,
    depth: u8,
    resolve_expr: Option<&dyn Fn(ExprId) -> Option<u64>>,
    mut memo: Option<&mut HashSet<ExprId>>,
) -> Result<u64, FoldFail> {
    if depth > 16 {
        return Err(FoldFail::Depth);
    }
    // A recorded concrete value (memory-derived pointer) short-circuits
    // structural evaluation.
    if let Some(value) = resolve_expr.and_then(|resolve| resolve(expression)) {
        return Ok(value);
    }
    if memo.as_deref().is_some_and(|set| set.contains(&expression)) {
        return Err(FoldFail::Absolute);
    }
    // Probe the operator first (one small enum copy): Symbol leaves have no
    // value once any resolver declined, so they return without the full node
    // clone `get` performs.
    let op = arena.op_of(expression).ok_or(FoldFail::Absolute)?;
    let folded = match op {
        ExprOp::Symbol => Err(FoldFail::Absolute),
        ExprOp::Constant => {
            let node = arena.get(expression).ok_or(FoldFail::Absolute)?;
            let mut buffer = [0u8; 8];
            let len = node.immediate.len().min(8);
            buffer[..len].copy_from_slice(&node.immediate[..len]);
            Ok(u64::from_le_bytes(buffer))
        }
        _ => fold_node(arena, expression, op, depth, resolve_expr, memo.as_deref_mut()),
    };
    if let Err(FoldFail::Absolute) = folded
        && let Some(set) = memo
    {
        if set.len() >= NONCONSTANT_CACHE_CAP {
            set.clear();
        }
        set.insert(expression);
    }
    folded
}

/// One operand's fold, preserving the child's own failure mode (a depth-capped
/// child must not be promoted to an absolute verdict).
fn fold_child(
    arena: &SymbolicArena,
    operand: Option<&ExprId>,
    depth: u8,
    resolve_expr: Option<&dyn Fn(ExprId) -> Option<u64>>,
    memo: &mut Option<&mut HashSet<ExprId>>,
) -> Result<u64, FoldFail> {
    let operand = operand.copied().ok_or(FoldFail::Absolute)?;
    fold_eval(arena, operand, depth + 1, resolve_expr, memo.as_deref_mut())
}

fn fold_node(
    arena: &SymbolicArena,
    expression: ExprId,
    op: ExprOp,
    depth: u8,
    resolve_expr: Option<&dyn Fn(ExprId) -> Option<u64>>,
    mut memo: Option<&mut HashSet<ExprId>>,
) -> Result<u64, FoldFail> {
    let node = arena.get(expression).ok_or(FoldFail::Absolute)?;
    // Sequential child folds share the memo through reborrows.
    macro_rules! child {
        ($operand:expr) => {
            fold_child(arena, $operand, depth, resolve_expr, &mut memo)
        };
    }
    match op {
        ExprOp::Add => Ok(child!(node.operands.first())?.wrapping_add(child!(node.operands.get(1))?)),
        ExprOp::Sub => Ok(child!(node.operands.first())?.wrapping_sub(child!(node.operands.get(1))?)),
        ExprOp::And => Ok(child!(node.operands.first())? & child!(node.operands.get(1))?),
        ExprOp::Or => Ok(child!(node.operands.first())? | child!(node.operands.get(1))?),
        ExprOp::Xor => Ok(child!(node.operands.first())? ^ child!(node.operands.get(1))?),
        ExprOp::Shl => Ok(child!(node.operands.first())?.wrapping_shl(child!(node.operands.get(1))? as u32)),
        ExprOp::LShr => Ok(child!(node.operands.first())?.wrapping_shr(child!(node.operands.get(1))? as u32)),
        ExprOp::ZExt => child!(node.operands.first()),
        ExprOp::SExt => {
            // Sign-extend from the operand's own width — a canonical
            // constant already fits it, so the extension is purely the sign
            // fill.
            let operand_id = *node.operands.first().ok_or(FoldFail::Absolute)?;
            let width = arena
                .sort_of(operand_id)
                .and_then(|sort| match sort {
                    ExprSort::BitVec(w) => Some(u32::from(w)),
                    _ => None,
                })
                .ok_or(FoldFail::Absolute)?;
            let value = child!(node.operands.first())?;
            if width > 0 && width < 64 && value & (1u64 << (width - 1)) != 0 {
                Ok(value | (!u64::MAX << width))
            } else {
                Ok(value)
            }
        }
        ExprOp::Extract => {
            // The window lives in the immediate: [start:u16, width:u16].
            // Folding must honor it — the degenerate ZExt path lowers width
            // coercions into low-bit extracts whose values feed addresses
            // and shift counts.
            let start = node
                .immediate
                .get(..2)
                .map(|bytes| u16::from_le_bytes(bytes.try_into().unwrap_or([0; 2])))
                .unwrap_or(0);
            let width = match node.sort {
                ExprSort::BitVec(w) => u32::from(w),
                _ => return Err(FoldFail::Absolute),
            };
            let mask = if width >= 64 { u64::MAX } else { (1u64 << width) - 1 };
            Ok((child!(node.operands.first())? >> start) & mask)
        }
        ExprOp::RotL | ExprOp::RotR => {
            // Rotate by the count modulo the node's width, composed from
            // shifts scoped to that width (the u64 carrier would otherwise
            // swallow the wrapped bits). For widths above the 64-bit carrier
            // the result is approximate, matching the fold's existing
            // treatment of wider-than-carrier values.
            let width = match node.sort {
                ExprSort::BitVec(bits) => u64::from(bits),
                _ => return Err(FoldFail::Absolute),
            };
            let mask = if width >= 64 { u64::MAX } else { (1u64 << width) - 1 };
            let value = child!(node.operands.first())? & mask;
            let amount = (child!(node.operands.get(1))? % width.max(1)) as u32;
            if amount == 0 {
                Ok(value)
            } else {
                let counter = u32::try_from(width).unwrap_or(u32::MAX) - amount;
                if op == ExprOp::RotL {
                    Ok(value.wrapping_shl(amount) | value.wrapping_shr(counter))
                } else {
                    Ok(value.wrapping_shr(amount) | value.wrapping_shl(counter))
                }
            }
        }
        ExprOp::Concat => {
            // Concat(hi, lo) — value = (hi << lo_bits) | lo.
            let hi = child!(node.operands.first())?;
            let lo_id = *node.operands.get(1).ok_or(FoldFail::Absolute)?;
            let lo = child!(Some(&lo_id))?;
            let lo_bits = arena
                .sort_of(lo_id)
                .and_then(|sort| match sort {
                    ExprSort::BitVec(w) => Some(u32::from(w)),
                    _ => None,
                })
                .unwrap_or(8);
            Ok((hi << lo_bits.min(63)) | lo)
        }
        ExprOp::Not => Ok(1_u64.wrapping_sub(child!(node.operands.first())?)),
        ExprOp::Eq => Ok(u64::from(
            child!(node.operands.first())? == child!(node.operands.get(1))?,
        )),
        ExprOp::Ite => {
            // Fold the guard; if it doesn't reduce, both branches agreeing
            // still yields a concrete value.
            let guard = child!(node.operands.first());
            let lhs = child!(node.operands.get(1));
            let rhs = child!(node.operands.get(2));
            let selected = match guard {
                Ok(1) => Some(lhs),
                Ok(0) => Some(rhs),
                Ok(_) | Err(_) => None,
            };
            match selected {
                Some(branch) => branch,
                None => {
                    let agreeing = match (lhs, rhs) {
                        (Ok(left), Ok(right)) if left == right => Ok(left),
                        _ => Err(FoldFail::Absolute),
                    };
                    match agreeing {
                        Ok(value) => Ok(value),
                        // The guard never resolves (a Symbol sits beneath
                        // it): the fold's fate is sealed by the branches.
                        Err(_) if matches!(guard, Err(FoldFail::Absolute)) => Err(FoldFail::Absolute),
                        // The guard only hit the depth cap or folded to a
                        // non-selecting value: from a shallower root it may
                        // still select, so nothing here is absolute.
                        Err(_) => Err(FoldFail::Depth),
                    }
                }
            }
        }
        // Operators outside the foldable subset never fold regardless of
        // budget: an absolute verdict, memoizable.
        _ => Err(FoldFail::Absolute),
    }
}

/// Like [`constant_value`], but `resolve_expr(symbol_id)` can bind Symbol
/// leaves to concrete values — the session passes each symbol's concrete
/// register value so `rsp-symbolic` addresses still resolve.
fn constant_value_resolved(
    arena: &SymbolicArena,
    expression: ExprId,
    resolve_expr: &dyn Fn(ExprId) -> Option<u64>,
) -> Result<u64, SymbolicEvalError> {
    fold_eval(arena, expression, 0, Some(resolve_expr), None)
        .ok()
        .ok_or_else(|| SymbolicEvalError::UnsupportedOperation("non-constant operand".into()))
}

/// Builds the expression for an IR primitive. Shared by the fully symbolic
/// evaluator and the concolic shadow. Widths resolve through the arena's
/// `sort_of` probe (no node clones, no memo to maintain).
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
            // Well-sortedness guard: shadow expression widths can drift from
            // the declared IR types (ExprRef inputs, sub-view register
            // writes), and a 32-bit induction variable initialized through a
            // 64-bit-tracked register arrives here width-mismatched. Widen
            // the narrower operand to the wider one — zero-widening
            // preserves equality and unsigned order; signed comparisons
            // sign-widen instead so negative narrower values still order
            // correctly.
            let (left, right) = comparison_operands(arena, op, operands[0], operands[1])?;
            let boolean = intern(arena, ExprSort::Bool, comparison, vec![left, right], Vec::new())?;
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
        | IrPrimitive::AShr
        | IrPrimitive::RotL
        | IrPrimitive::RotR => {
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
                IrPrimitive::RotL => ExprOp::RotL,
                IrPrimitive::RotR => ExprOp::RotR,
                _ => ExprOp::AShr,
            };
            let coerced = operands
                .iter()
                .map(|operand| coerce_width(arena, *operand, output_width))
                .collect::<Result<Vec<_>, _>>()?;
            let value = intern(
                arena,
                ExprSort::BitVec(output_width),
                expression_op,
                coerced,
                Vec::new(),
            )?;
            Ok((value, ty))
        }
        IrPrimitive::Not => {
            let value = intern(arena, ExprSort::BitVec(output_width), ExprOp::Not, operands, Vec::new())?;
            Ok((value, ty))
        }
        IrPrimitive::ZExt | IrPrimitive::SExt => {
            // Reconcile on the operand's *expression* width — a Bool flag or
            // a widened sub-view may disagree with the declared IR type.
            let operand_expr = operands[0];
            let operand_width = u32::from(expr_width(arena, operand_expr)?);
            if operand_width == u32::from(output_width) {
                return Ok((operand_expr, ty));
            }
            if operand_width > u32::from(output_width) {
                // A degenerate extension whose source expression is wider
                // than the target is a truncation of the low bits: some
                // 32-bit forms lower a ZeroExtend over a count operand whose
                // register the shadow tracks at the parent (64-bit) width
                // (for example `shl r32, cl` reading CL through rcx).
                let mut immediate = Vec::with_capacity(4);
                immediate.extend_from_slice(&0u16.to_le_bytes());
                immediate.extend_from_slice(&output_width.to_le_bytes());
                let value = intern(
                    arena,
                    ExprSort::BitVec(output_width),
                    ExprOp::Extract,
                    vec![operand_expr],
                    immediate,
                )?;
                return Ok((value, ty));
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
            // Reconcile on the operand's *expression* width — a widened or
            // narrowed value may disagree with the declared IR type.
            let operand_width = u32::from(expr_width(arena, operands[0])?);
            if u32::from(start) + u32::from(output_width) > operand_width {
                // Zero-extend the operand to cover the extract window.
                let zext = intern(
                    arena,
                    ExprSort::BitVec((u32::from(start) + u32::from(output_width)) as u16),
                    ExprOp::ZExt,
                    vec![operands[0]],
                    Vec::new(),
                )?;
                let mut immediate = Vec::with_capacity(4);
                immediate.extend_from_slice(&start.to_le_bytes());
                immediate.extend_from_slice(&output_width.to_le_bytes());
                let value = intern(
                    arena,
                    ExprSort::BitVec(output_width),
                    ExprOp::Extract,
                    vec![zext],
                    immediate,
                )?;
                return Ok((value, ty));
            }
            let _ = input_width;
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
    /// Allocation-free [`read_bytes`](Self::read_bytes): fills `out` (whose
    /// length is the read length) instead of returning a fresh `Vec`. Returns
    /// `false` exactly when `read_bytes` would return `None`. The default
    /// wraps `read_bytes`; images backed by a [`LayeredMemory`](angryier_memory::LayeredMemory)
    /// override it with the memory's own buffer-filling read.
    fn read_bytes_into(&self, address: u64, out: &mut [ByteValue]) -> bool {
        match self.read_bytes(address, out.len()) {
            Some(bytes) => {
                out.clone_from_slice(&bytes);
                true
            }
            None => false,
        }
    }
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
    /// Interned constant expressions keyed by (width, value). The shadow
    /// re-evaluates the same blocks step after step; re-interning their
    /// (identical) constants every visit makes the arena hash each one again
    /// and again. Widths above 128 bits bypass the cache.
    constants: HashMap<(u16, u128), ExprId>,
    /// Negative fold memo: expressions proven non-constant by
    /// [`constant_value`]. Arena nodes are immutable, so a failure is valid
    /// forever; without it every symbolic register write would re-walk the
    /// top of a value chain that grows one node per iteration.
    non_constants: HashSet<ExprId>,
    /// Scratch value table reused across block evaluations: the shadow
    /// evaluates one block per step, and regrowing this table from empty
    /// each time costs several reallocations per step.
    values_scratch: Vec<Option<(ExprId, Option<u128>, IrType)>>,
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
            constants: HashMap::new(),
            non_constants: HashSet::new(),
            values_scratch: Vec::new(),
        }
    }

    /// Symbols created so far, in creation order.
    /// All register shadows (symbolic expr + type per register).
    pub fn shadow_registers(&self) -> &BTreeMap<u32, (ExprId, IrType)> {
        &self.registers
    }

    /// All memory shadow bytes (symbolic/concrete per address).
    pub fn shadow_memory(&self) -> &BTreeMap<u64, ByteValue> {
        &self.memory
    }

    /// Concrete value per register when the shadow is fully determined.
    pub fn register_concretes(&self) -> &BTreeMap<u32, Option<u128>> {
        &self.register_concretes
    }

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
        // Reuse the value table across steps (same instruction count per
        // revisited block); on error the scratch is simply re-grown.
        let mut values = std::mem::take(&mut self.values_scratch);
        values.clear();
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
                    // Resolve operands into a stack buffer: the shadow
                    // evaluates every block on every step, and a heap `Vec`
                    // per operation is measurable at that rate.
                    const MAX_INLINE: usize = 4;
                    let (expression, concrete) = if inputs.len() <= MAX_INLINE {
                        let mut inline = [(ExprId(0), None, IrType::Bits(1)); MAX_INLINE];
                        for (slot, id) in inline.iter_mut().zip(inputs) {
                            *slot = get_value_c(&values, *id)?;
                        }
                        self.primitive_concolic(*op, *ty, &inline[..inputs.len()])?
                    } else {
                        let resolved = resolve_inputs_c(&values, inputs)?;
                        self.primitive_concolic(*op, *ty, &resolved)?
                    };
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
                        concrete = self.constant_value_memo(expression).map(u128::from);
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

        self.values_scratch = values;
        Ok(SymbolicBlockSummary {
            branch,
            written_registers,
            terminated,
            jump_target: None,
        })
    }

    /// Evaluates a primitive concolically: when every input carries a
    /// concrete value the result folds to a constant (keeping addresses and
    /// flag computations concrete); otherwise it builds the expression.
    /// Machine primitives have at most a handful of operands and the shadow
    /// evaluates them on every step, so both paths resolve through a stack
    /// buffer instead of a fresh heap `Vec` per operation.
    fn primitive_concolic(
        &mut self,
        op: IrPrimitive,
        ty: IrType,
        inputs: &[(ExprId, Option<u128>, IrType)],
    ) -> Result<(ExprId, Option<u128>), SymbolicEvalError> {
        const MAX_INLINE: usize = 4;
        let output_width = bit_width(ty)?;

        // Constant folding: every input concrete and every width foldable.
        if inputs.len() <= MAX_INLINE
            && output_width <= 128
            && inputs
                .iter()
                .all(|(_, concrete, input_ty)| concrete.is_some() && bit_width(*input_ty).unwrap_or(64) <= 128)
        {
            let mut typed = [(0u128, 0u16); MAX_INLINE];
            for (slot, (_, concrete, input_ty)) in typed.iter_mut().zip(inputs) {
                *slot = (concrete.unwrap_or(0), bit_width(*input_ty).unwrap_or(64));
            }
            if let Some(result) = eval_primitive_concrete(op, output_width, &typed[..inputs.len()]) {
                let byte_width = usize::from(output_width).div_ceil(8);
                let bytes = &result.to_le_bytes()[..byte_width];
                let expression = self.constant(ty, bytes)?;
                return Ok((expression, Some(result)));
            }
        }

        // Symbolic path: the (expression, type) view of each input, resolved
        // through a stack buffer for the machine-primitive arities.
        let (expression, _) = if inputs.len() <= MAX_INLINE {
            let mut inline = [(ExprId(0), IrType::Bits(1)); MAX_INLINE];
            for (slot, (expression, _, input_ty)) in inline.iter_mut().zip(inputs) {
                *slot = (*expression, *input_ty);
            }
            primitive_expr(self.arena, op, ty, &inline[..inputs.len()])?
        } else {
            let expression_of = inputs
                .iter()
                .map(|(expression, _, input_ty)| (*expression, *input_ty))
                .collect::<Vec<(ExprId, IrType)>>();
            primitive_expr(self.arena, op, ty, &expression_of)?
        };
        // The arena folds an all-constant operand set into one Constant node
        // even when the concolic folder above declined (some input was a
        // constant expression whose concrete tag was unknown). One operator
        // probe re-tags those results here, so downstream writes keep their
        // concrete value without the recursive `constant_value` re-fold.
        let concrete = match self.arena.op_of(expression) {
            Some(ExprOp::Constant) if output_width <= 128 => self.arena.get(expression).map(|node| {
                node.immediate
                    .iter()
                    .enumerate()
                    .take(16)
                    .fold(0u128, |acc, (index, byte)| acc | (u128::from(*byte) << (8 * index)))
                    & mask_u128(output_width)
            }),
            _ => None,
        };
        Ok((expression, concrete))
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
        /// Widest load filled through the stack buffer; wider (non-machine)
        /// types take the owned path.
        const MAX_INLINE_LOAD: usize = 64;

        let width = bit_width(ty)?;
        let byte_width = usize::from(width).div_ceil(8);
        let base = match concrete_address.and_then(|value| u64::try_from(value).ok()) {
            Some(base) => base,
            None => constant_value(self.arena, address)
                .map_err(|_| SymbolicEvalError::UnsupportedOperation("load with symbolic address".into()))?,
        };

        // One bulk image read fills the whole span (no per-byte `Vec`), the
        // shadow overlay then rewrites its own bytes on top. When the span
        // read fails, resolve byte-at-a-time so shadow-covered bytes at the
        // span's edge still load and unmapped errors name the exact offset.
        let mut owned: Vec<ByteValue>;
        let mut inline = [ByteValue::Concrete(0); MAX_INLINE_LOAD];
        let bytes: &mut [ByteValue] = if byte_width <= MAX_INLINE_LOAD {
            &mut inline[..byte_width]
        } else {
            owned = vec![ByteValue::Concrete(0); byte_width];
            &mut owned[..]
        };
        if image.read_bytes_into(base, bytes) {
            for (offset, slot) in bytes.iter_mut().enumerate() {
                if let Some(value) = self.memory.get(&(base + offset as u64)) {
                    *slot = *value;
                }
            }
        } else {
            for (offset, slot) in bytes.iter_mut().enumerate() {
                let at = base + offset as u64;
                *slot = match self.memory.get(&at) {
                    Some(value) => *value,
                    None => {
                        let read = image
                            .read_bytes(at, 1)
                            .ok_or(SymbolicEvalError::UnsupportedOperation(format!(
                                "load of unmapped byte {at:#x}"
                            )))?;
                        read.first().copied().unwrap_or(ByteValue::Concrete(0))
                    }
                };
            }
        }

        if bytes.iter().all(|byte| matches!(byte, ByteValue::Concrete(_))) {
            let mut inline_data = [0u8; MAX_INLINE_LOAD];
            let owned_data: Vec<u8>;
            let data: &[u8] = if byte_width <= MAX_INLINE_LOAD {
                for (index, byte) in bytes.iter().enumerate() {
                    if let ByteValue::Concrete(value) = byte {
                        inline_data[index] = *value;
                    }
                }
                &inline_data[..byte_width]
            } else {
                owned_data = bytes
                    .iter()
                    .map(|byte| match byte {
                        ByteValue::Concrete(value) => *value,
                        ByteValue::Symbolic(_) => 0,
                    })
                    .collect();
                &owned_data[..]
            };
            let concrete = data
                .iter()
                .enumerate()
                .take(16)
                .fold(0u128, |acc, (index, byte)| acc | (u128::from(*byte) << (8 * index)));
            return Ok((self.constant(ty, data)?, Some(concrete)));
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

        // Probe the operator first: the constant fast path needs the node's
        // immediate, while the (hot) symbolic path must not clone the node at
        // all.
        let op = self
            .arena
            .op_of(value)
            .ok_or_else(|| SymbolicEvalError::Expression(format!("unknown expression {}", value.0)))?;
        if op == ExprOp::Constant {
            if let Some(node) = self.arena.get(value) {
                for (offset, byte) in node.immediate.iter().enumerate().take(byte_width) {
                    self.memory.insert(base + offset as u64, ByteValue::Concrete(*byte));
                }
                return Ok(());
            }
            return Err(SymbolicEvalError::Expression(format!("unknown expression {}", value.0)));
        }
        for offset in 0..byte_width {
            let byte_expr = self.extract(value, offset as u16 * 8, 8)?;
            self.memory.insert(base + offset as u64, ByteValue::Symbolic(byte_expr));
        }
        Ok(())
    }

    /// [`constant_value`] through the negative fold memo: expressions already
    /// proven non-constant skip the recursive node walk. A loop-carried
    /// value's expression grows one node per iteration, and every register
    /// write would otherwise re-walk its top levels.
    fn constant_value_memo(&mut self, expression: ExprId) -> Option<u64> {
        constant_value_with_memo(self.arena, &mut self.non_constants, expression).ok()
    }

    /// Interns a constant, memoized by (width, value): the shadow evaluates
    /// the same block on every visit, so repeated constants resolve without
    /// touching the arena.
    fn constant(&mut self, ty: IrType, bytes_le: &[u8]) -> Result<ExprId, SymbolicEvalError> {
        let width = bit_width(ty)?;
        let byte_width = usize::from(width).div_ceil(8);
        if bytes_le.len() != byte_width {
            return Err(SymbolicEvalError::UnsupportedType(format!("constant width for {ty:?}")));
        }
        if byte_width <= 16 {
            let mut value = 0u128;
            for (index, byte) in bytes_le.iter().enumerate() {
                value |= u128::from(*byte) << (8 * index);
            }
            if let Some(expression) = self.constants.get(&(width, value)) {
                return Ok(*expression);
            }
            let expression = intern(
                self.arena,
                ExprSort::BitVec(width),
                ExprOp::Constant,
                Vec::new(),
                bytes_le.to_vec(),
            )?;
            self.constants.insert((width, value), expression);
            return Ok(expression);
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

/// Eviction threshold for the negative fold memo: bounded like the constant
/// cache — cleared rather than grown once long traces would overflow it.
const NONCONSTANT_CACHE_CAP: usize = 1 << 20;

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
        IrPrimitive::RotL | IrPrimitive::RotR => {
            // x86 rotate semantics: the count is taken modulo the operand
            // width. The rotation is composed from shifts scoped to the
            // width (a u128 rotate would wrap within the carrier).
            if output_width == 0 {
                0
            } else {
                let value = inputs[0].0 & mask_u128(output_width);
                let amount = (inputs[1].0 % u128::from(output_width)) as u32;
                if amount == 0 {
                    value
                } else {
                    let counter = u32::from(output_width) - amount;
                    if op == IrPrimitive::RotL {
                        (value << amount) | (value >> counter)
                    } else {
                        (value >> amount) | (value << counter)
                    }
                }
            }
        }
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
    let high_bits = parent_width.saturating_sub(bit_offset).saturating_sub(source_width);
    let high_mask = mask_u128(high_bits);
    let shift = (bit_offset + source_width).min(127);
    let high = if bit_offset + source_width >= parent_width || bit_offset + source_width >= 128 {
        0
    } else {
        (parent >> shift) & high_mask
    };
    (high << shift) | ((value & mask_u128(source_width)) << bit_offset.min(127)) | (parent & low_mask)
}

/// Byte-addressable symbolic memory over [`PersistentMemory`]: concrete
/// bytes come from the process image, and `ByteValue::Symbolic(ExprId)`
/// bindings are stored per byte. Reads concatenate byte expressions
/// little-endian; writes split the expression into bytes. Symbolic
/// *addresses* are not dereferenceable here — the caller applies its
/// concretization policy upstream.
/// Session-level symbolic byte store over [`PersistentMemory`].
#[derive(Clone, Debug)]
pub struct SymbolicSessionMemory {
    /// The persistent byte store (may itself hold symbolic bytes).
    pub memory: angryier_memory::SymbolicMemory,
}

impl SymbolicSessionMemory {
    /// Wraps a persistent memory snapshot as the session's byte store.
    pub fn new(memory: angryier_memory::PersistentMemory) -> Self {
        Self {
            memory: angryier_memory::SymbolicMemory::new(memory),
        }
    }

    /// Byte-level read for the session's string-op fast path — returns raw
    /// `ByteValue`s, preserving symbolic bytes.
    pub fn read_bytes(
        &self,
        address: u64,
        length: usize,
    ) -> Result<Vec<angryier_memory::ByteValue>, SymbolicEvalError> {
        self.memory
            .read_at_address(address, length)
            .map(|s| s.to_vec())
            .map_err(|e| SymbolicEvalError::UnsupportedOperation(format!("memory read: {e:?}")))
    }

    /// Byte-level write for the session's string-op fast path.
    pub fn write_bytes(&mut self, address: u64, bytes: &[angryier_memory::ByteValue]) -> Result<(), SymbolicEvalError> {
        let next = self
            .memory
            .write_at_address(address, bytes)
            .map_err(|e| SymbolicEvalError::UnsupportedOperation(format!("memory write: {e:?}")))?;
        self.memory = next;
        Ok(())
    }

    /// Reads `width`-many bytes at `address`, concatenating byte values
    /// little-endian. Concrete bytes become constant expressions.
    pub fn read(&self, arena: &SymbolicArena, address: u64, width: u16) -> Result<ExprId, SymbolicEvalError> {
        let byte_count = usize::from(width).div_ceil(8);
        let bytes = self
            .memory
            .read_at_address(address, byte_count)
            .map_err(|e| SymbolicEvalError::UnsupportedOperation(format!("memory read: {e:?}")))?;
        let mut parts = Vec::with_capacity(byte_count);
        let mut all_concrete = true;
        let mut concrete_bytes = Vec::with_capacity(byte_count);
        for byte in bytes {
            match byte {
                angryier_memory::ByteValue::Concrete(value) => {
                    concrete_bytes.push(value);
                    parts.push(intern(
                        arena,
                        ExprSort::BitVec(8),
                        ExprOp::Constant,
                        Vec::new(),
                        vec![value],
                    )?);
                }
                angryier_memory::ByteValue::Symbolic(expr) => {
                    all_concrete = false;
                    concrete_bytes.push(0);
                    parts.push(expr);
                }
            }
        }
        // Fold all-concrete reads into one Constant so downstream
        // `constant_value` resolution (indirect targets, addresses) sees a
        // literal rather than a Concat of literal bytes.
        if all_concrete {
            let width_bits = usize::from(width).div_ceil(8);
            concrete_bytes.truncate(width_bits);
            return intern(
                arena,
                ExprSort::BitVec(width),
                ExprOp::Constant,
                Vec::new(),
                concrete_bytes,
            );
        }
        let mut acc = parts[byte_count - 1];
        let mut acc_bits = 8u16;
        for i in (0..byte_count - 1).rev() {
            acc = intern(
                arena,
                ExprSort::BitVec(acc_bits + 8),
                ExprOp::Concat,
                vec![acc, parts[i]],
                Vec::new(),
            )?;
            acc_bits += 8;
        }
        if acc_bits != width {
            let mut imm = Vec::with_capacity(4);
            imm.extend_from_slice(&0u16.to_le_bytes());
            imm.extend_from_slice(&width.to_le_bytes());
            acc = intern(arena, ExprSort::BitVec(width), ExprOp::Extract, vec![acc], imm)?;
        }
        Ok(acc)
    }

    /// Writes the low `width` bits of `expression` at `address`, split
    /// little-endian into symbolic bytes.
    pub fn write(
        &mut self,
        arena: &SymbolicArena,
        address: u64,
        expression: ExprId,
        width: u16,
    ) -> Result<(), SymbolicEvalError> {
        let byte_count = usize::from(width).div_ceil(8);
        // The expression's own width may be narrower than the declared
        // store width (widened sub-view) — extend to cover the split.
        let expression = match arena.sort_of(expression) {
            Some(ExprSort::BitVec(w)) if w < width => intern(
                arena,
                ExprSort::BitVec(width),
                ExprOp::ZExt,
                vec![expression],
                Vec::new(),
            )?,
            Some(ExprSort::Bool) if width > 1 => intern(
                arena,
                ExprSort::BitVec(width),
                ExprOp::ZExt,
                vec![expression],
                Vec::new(),
            )?,
            _ => expression,
        };
        let mut bytes = Vec::with_capacity(byte_count);
        for i in 0..byte_count {
            let byte = if byte_count == 1 && width == 8 {
                expression
            } else {
                // Extract immediate = [start:u16][width:u16].
                let start = (i * 8) as u16;
                let mut imm = Vec::with_capacity(4);
                imm.extend_from_slice(&start.to_le_bytes());
                imm.extend_from_slice(&8u16.to_le_bytes());
                intern(arena, ExprSort::BitVec(8), ExprOp::Extract, vec![expression], imm)?
            };
            bytes.push(angryier_memory::ByteValue::Symbolic(byte));
        }
        self.memory = self
            .memory
            .write_at_address(address, &bytes)
            .map_err(|e| SymbolicEvalError::UnsupportedOperation(format!("memory write: {e:?}")))?;
        Ok(())
    }
}

/// A mergeable snapshot of a symbolic state: the register bindings plus the
/// path constraints accumulated since the last fork.
///
/// Snapshots are produced by [`SymbolicEvaluator::snapshot`] (registers only —
/// constraints come from the enclosing session) and consumed by
/// [`merge_snapshots`].
#[derive(Clone, Debug, Default)]
pub struct SymbolicStateSnapshot {
    /// Register id → (symbolic expression, its IR type) for touched registers.
    pub registers: BTreeMap<u32, (ExprId, IrType)>,
    /// Concrete values for registers with no symbolic binding — a register
    /// read with no symbolic entry falls back to this so untouched state
    /// (rsp, rip, startup GPRs) stays concrete instead of auto-symboling.
    pub concrete_registers: BTreeMap<u32, u64>,
    /// Path constraints guarding this state (Bool-sorted expressions).
    pub constraints: Vec<ExprId>,
    /// Symbols bound during this state's execution, for lineage.
    pub symbols: Vec<SymbolBinding>,
    /// Concrete value each load-derived expression stands for — lets
    /// pointer-chasing addresses resolve without a register binding.
    pub expr_concrete: BTreeMap<ExprId, u64>,
}

/// Merges two sibling symbolic states that reconverge at the same program
/// point — the primitive Phase 10's state merging and Veritesting both reduce
/// to.
///
/// `parent` is the snapshot at the fork point: registers touched on only one
/// side inherit the parent's value on the other. The merge rule:
///
/// - `merged_pc = left_guard ∨ right_guard` where each guard is the
///   conjunction of that side's path constraints;
/// - registers equal on both sides keep their expression;
/// - registers diverging with matching types become
///   `Ite(left_guard, left_expr, right_expr)`;
/// - type-mismatched bindings fail — a sound merge cannot synthesize a
///   common sort, so the caller must keep the states separate.
///
/// The result's `symbols` are the union of both sides' (order-stable).
pub fn merge_snapshots(
    arena: &SymbolicArena,
    parent: &SymbolicStateSnapshot,
    left: &SymbolicStateSnapshot,
    right: &SymbolicStateSnapshot,
) -> Result<SymbolicStateSnapshot, SymbolicEvalError> {
    let left_guard = bool_and_chain(arena, &left.constraints)?;
    let right_guard = bool_and_chain(arena, &right.constraints)?;
    let merged_pc = intern(
        arena,
        ExprSort::Bool,
        ExprOp::Or,
        vec![left_guard, right_guard],
        Vec::new(),
    )?;

    let mut registers = BTreeMap::new();
    for (&register, &(left_expr, left_ty)) in &left.registers {
        let right_binding = right
            .registers
            .get(&register)
            .copied()
            .or_else(|| parent.registers.get(&register).copied());
        match right_binding {
            Some((right_expr, right_ty)) => {
                if right_expr == left_expr {
                    registers.insert(register, (left_expr, left_ty));
                } else {
                    if right_ty != left_ty {
                        return Err(SymbolicEvalError::UnsupportedOperation(format!(
                            "merge type mismatch on register {register}: {left_ty:?} vs {right_ty:?}"
                        )));
                    }
                    let sort = sort_of(left_ty)?;
                    let merged = intern(
                        arena,
                        sort,
                        ExprOp::Ite,
                        vec![left_guard, left_expr, right_expr],
                        Vec::new(),
                    )?;
                    registers.insert(register, (merged, left_ty));
                }
            }
            // Touched only on the left and absent in the parent — keep the
            // left binding (the other side never defined it).
            None => {
                registers.insert(register, (left_expr, left_ty));
            }
        }
    }
    // Registers touched only on the right (or only in the parent).
    for (&register, &(right_expr, right_ty)) in right.registers.iter().chain(parent.registers.iter()) {
        registers.entry(register).or_insert((right_expr, right_ty));
    }

    let mut symbols = left.symbols.clone();
    for symbol in &right.symbols {
        if !symbols.contains(symbol) {
            symbols.push(*symbol);
        }
    }

    let mut expr_concrete = left.expr_concrete.clone();
    expr_concrete.extend(right.expr_concrete.iter().map(|(k, v)| (*k, *v)));
    Ok(SymbolicStateSnapshot {
        registers,
        concrete_registers: left.concrete_registers.clone(),
        constraints: vec![merged_pc],
        symbols,
        expr_concrete,
    })
}

/// `a ∧ b ∧ ...` as a Bool expression; an empty slice yields `true`.
fn bool_and_chain(arena: &SymbolicArena, constraints: &[ExprId]) -> Result<ExprId, SymbolicEvalError> {
    let mut acc = intern(arena, ExprSort::Bool, ExprOp::Constant, Vec::new(), vec![1])?;
    for &constraint in constraints {
        acc = intern(arena, ExprSort::Bool, ExprOp::And, vec![acc, constraint], Vec::new())?;
    }
    Ok(acc)
}

/// IR type → expression sort for mergeable bindings.
fn sort_of(ty: IrType) -> Result<ExprSort, SymbolicEvalError> {
    match ty {
        IrType::Bits(bits) => Ok(ExprSort::BitVec(bits)),
        IrType::Vector { width_bits, lane_bits } => Ok(ExprSort::Vector {
            lanes: width_bits / lane_bits.max(1),
            lane_bits,
        }),
        IrType::Float32 => Ok(ExprSort::Float {
            exponent_bits: 8,
            significand_bits: 24,
        }),
        IrType::Float64 => Ok(ExprSort::Float {
            exponent_bits: 11,
            significand_bits: 53,
        }),
        other => Err(SymbolicEvalError::UnsupportedType(format!("{other:?}"))),
    }
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

    fn symbol(arena: &ShardedExprArena, width: u16) -> Result<ExprId, String> {
        arena
            .intern(ExprNode {
                sort: ExprSort::BitVec(width),
                op: ExprOp::Symbol,
                operands: Vec::new(),
                immediate: 7u64.to_le_bytes().to_vec(),
            })
            .map_err(|e| format!("{e:?}"))
    }

    fn constant(arena: &ShardedExprArena, width: u16, value: u64) -> Result<ExprId, String> {
        arena
            .intern(ExprNode {
                sort: ExprSort::BitVec(width),
                op: ExprOp::Constant,
                operands: Vec::new(),
                immediate: value.to_le_bytes().to_vec(),
            })
            .map_err(|e| format!("{e:?}"))
    }

    fn eq(arena: &ShardedExprArena, width: u16, a: ExprId, b: ExprId) -> Result<ExprId, String> {
        let _ = width;
        arena
            .intern(ExprNode {
                sort: ExprSort::Bool,
                op: ExprOp::Eq,
                operands: vec![a, b],
                immediate: Vec::new(),
            })
            .map_err(|e| format!("{e:?}"))
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

    #[test]
    fn merge_snapshots_ite_on_divergent_register() -> Result<(), String> {
        // parent: rax = sym0; left branch took `rax > 0` and wrote rax=1;
        // right fell through, rax=2. Merged rax = Ite(left_guard, 1, 2).
        let arena = arena();
        let sym = symbol(&arena, 64)?;
        let one = constant(&arena, 64, 1)?;
        let two = constant(&arena, 64, 2)?;

        let parent = SymbolicStateSnapshot {
            registers: BTreeMap::from([(0u32, (sym, IrType::Bits(64)))]),
            concrete_registers: BTreeMap::new(),
            constraints: Vec::new(),
            symbols: Vec::new(),
            expr_concrete: BTreeMap::new(),
        };
        let gt = eq(&arena, 64, sym, one)?; // any Bool constraint
        let left = SymbolicStateSnapshot {
            registers: BTreeMap::from([(0u32, (one, IrType::Bits(64)))]),
            concrete_registers: BTreeMap::new(),
            constraints: vec![gt],
            symbols: Vec::new(),
            expr_concrete: BTreeMap::new(),
        };
        let right = SymbolicStateSnapshot {
            registers: BTreeMap::from([(0u32, (two, IrType::Bits(64)))]),
            concrete_registers: BTreeMap::new(),
            constraints: Vec::new(),
            symbols: Vec::new(),
            expr_concrete: BTreeMap::new(),
        };

        let merged = merge_snapshots(&arena, &parent, &left, &right).map_err(|e| format!("{e:?}"))?;
        let (expr, _) = *merged.registers.get(&0u32).ok_or("rax")?;
        let node = arena.get(expr).ok_or("merged node")?;
        assert_eq!(node.op, ExprOp::Ite);
        // Operands: [left_guard, 1, 2].
        assert_eq!(node.operands[1], one);
        assert_eq!(node.operands[2], two);
        // Merged constraint = Or(guard_left, guard_right).
        assert_eq!(merged.constraints.len(), 1);
        let pc = arena.get(merged.constraints[0]).ok_or("pc node")?;
        assert_eq!(pc.op, ExprOp::Or);
        Ok(())
    }

    #[test]
    fn merge_snapshots_keeps_equal_registers() -> Result<(), String> {
        let arena = arena();
        let sym = symbol(&arena, 64)?;
        let parent = SymbolicStateSnapshot::default();
        let left = SymbolicStateSnapshot {
            registers: BTreeMap::from([(0u32, (sym, IrType::Bits(64)))]),
            concrete_registers: BTreeMap::new(),
            constraints: Vec::new(),
            symbols: Vec::new(),
            expr_concrete: BTreeMap::new(),
        };
        let right = left.clone();
        let merged = merge_snapshots(&arena, &parent, &left, &right).map_err(|e| format!("{e:?}"))?;
        assert_eq!(merged.registers.get(&0u32).map(|(e, _)| *e), Some(sym));
        Ok(())
    }

    #[test]
    fn merge_snapshots_one_sided_register_uses_parent() -> Result<(), String> {
        // rbx written only on the left; the right inherits the parent's
        // binding — the merge records rbx = Ite(guard, new, parent_val).
        let arena = arena();
        let parent_sym = symbol(&arena, 64)?;
        let new_val = constant(&arena, 64, 9)?;
        let parent = SymbolicStateSnapshot {
            registers: BTreeMap::from([(1u32, (parent_sym, IrType::Bits(64)))]),
            concrete_registers: BTreeMap::new(),
            constraints: Vec::new(),
            symbols: Vec::new(),
            expr_concrete: BTreeMap::new(),
        };
        let cond = eq(&arena, 64, parent_sym, parent_sym)?;
        let left = SymbolicStateSnapshot {
            registers: BTreeMap::from([(1u32, (new_val, IrType::Bits(64)))]),
            concrete_registers: BTreeMap::new(),
            constraints: vec![cond],
            symbols: Vec::new(),
            expr_concrete: BTreeMap::new(),
        };
        let right = SymbolicStateSnapshot::default();
        let merged = merge_snapshots(&arena, &parent, &left, &right).map_err(|e| format!("{e:?}"))?;
        let (expr, _) = *merged.registers.get(&1u32).ok_or("rbx")?;
        let node = arena.get(expr).ok_or("node")?;
        assert_eq!(node.op, ExprOp::Ite);
        assert_eq!(node.operands[1], new_val);
        assert_eq!(node.operands[2], parent_sym);
        Ok(())
    }

    #[test]
    fn merge_snapshots_type_mismatch_fails() -> Result<(), String> {
        let arena = arena();
        let a64 = symbol(&arena, 64)?;
        let a32 = symbol(&arena, 32)?;
        let parent = SymbolicStateSnapshot::default();
        let left = SymbolicStateSnapshot {
            registers: BTreeMap::from([(0u32, (a64, IrType::Bits(64)))]),
            concrete_registers: BTreeMap::new(),
            constraints: Vec::new(),
            symbols: Vec::new(),
            expr_concrete: BTreeMap::new(),
        };
        let right = SymbolicStateSnapshot {
            registers: BTreeMap::from([(0u32, (a32, IrType::Bits(32)))]),
            concrete_registers: BTreeMap::new(),
            constraints: Vec::new(),
            symbols: Vec::new(),
            expr_concrete: BTreeMap::new(),
        };
        assert!(merge_snapshots(&arena, &parent, &left, &right).is_err());
        Ok(())
    }
}
