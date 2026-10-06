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

use angryier_types::fx::{FxHashMap, FxHashSet};
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

/// Site cap for the evaluators' debt logs — mirrors
/// `UnsupportedFallthrough::snapshot` in the semantics layer: first-seen
/// sites are kept, the total keeps counting, and a pathological image cannot
/// grow the log unbounded.
pub const SYMBOLIC_DEBT_SITE_CAP: usize = 128;

/// One operation the shadow could not express and replaced with a fresh
/// under-constrained symbol. Recorded, never silent: callers surface these
/// sites as fidelity debt exactly like unsupported-form fallthroughs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SymbolicDebtSite {
    /// The primitive that was replaced.
    pub op: IrPrimitive,
    /// Output width in bits.
    pub width_bits: u16,
    /// Lane width when the output type is a vector, else 0.
    pub lane_bits: u16,
}

/// The vector-family primitives the flat expression language cannot express:
/// lane-wise arithmetic, shuffles, packs, blends, dot products and tile ops
/// need per-lane decomposition the `ExprOp` set (scalar bitvector ops only)
/// has no vocabulary for. The shadow replaces each result with a fresh
/// under-constrained symbol of the output width and records a
/// [`SymbolicDebtSite`] — sound (never a wrong value), visible (always
/// counted), and strictly more reachable than refusing the block.
///
/// Everything else about vectors is exact: whole-vector moves, loads, stores
/// and register traffic lower through the existing Concat/Extract/ZExt
/// machinery over a flat `BitVec(width_bits)` (the engine's `ExprOp::Concat`
/// is binary little-endian, operands[0] = low bits, and `Extract` immediates
/// encode `[start:u16 LE, width:u16 LE]`), and scalar bitvector primitives
/// applied to whole-vector values stay exact flat 128-bit arithmetic.
fn is_vector_debt_primitive(op: IrPrimitive) -> bool {
    use IrPrimitive as P;
    matches!(
        op,
        P::VecLaneAdd
            | P::VecLaneSub
            | P::VecLaneMul
            | P::VecLaneAnd
            | P::VecLaneOr
            | P::VecLaneXor
            | P::VecLaneFAdd
            | P::VecLaneFSub
            | P::VecLaneFMul
            | P::VecLaneFDiv
            | P::VecLaneFSqrt
            | P::VecLaneShl
            | P::VecLaneLShr
            | P::VecLaneAShr
            | P::VecLaneMaskEq
            | P::VecLaneMaskSgt
            | P::VecLaneMaxU
            | P::VecLaneMinU
            | P::VecLaneMaxS
            | P::VecLaneMinS
            | P::VecLaneMulHiS
            | P::VecLaneMulHiU
            | P::VecLaneAbs
            | P::VecLaneSign
            | P::VecLaneMulHiRS
            | P::VecHAddS
            | P::VecHSubS
            | P::VecLaneMulDq
            | P::VecBlendV
            | P::VecShuffleBytes
            | P::VecInterleaveLow
            | P::VecInterleaveHigh
            | P::VecPackSaturate
            | P::VecPackSaturateU
            | P::VecMadd16
            | P::VecSad8
            | P::VecShuffle32
            | P::VecShuffle16
            | P::VecMaddubs
            | P::VecShiftRegL
            | P::VecShiftRegR
            | P::VecShiftRegRA
            | P::VecHAdd
            | P::VecHSub
            | P::VecLaneSignExtend
            | P::VecLaneZeroExtend
            | P::VecLaneSatAddU
            | P::VecLaneSatSubU
            | P::VecLaneSatAddS
            | P::VecDotU8S8
            | P::VecDotS8S8
            | P::VecDotS8U8
            | P::VecLaneAvg
            | P::VecBlendImm
            | P::VecMaskMerge
            | P::VecMaskZero
            | P::VecDotF
            | P::VecFRound
            | P::VecTest
            | P::VecCmpF
            | P::VecFMin
            | P::VecFMax
            | P::VecMovMask
            | P::VecHFAdd
            | P::VecHFSub
            | P::VecMpsadbw
            | P::VecHMinUW
            | P::VecShiftLeftBytes
            | P::VecShiftRightBytes
            | P::VecPermute32
            | P::TileZero
            | P::TileDotS8S8
            | P::TileDotS8U8
            | P::TileDotU8S8
            | P::TileDotU8U8
            | P::TileDotBf16
            | P::TileDotFp16
    )
}

/// The scalar float primitives the flat expression language cannot express:
/// the `ExprOp` set has bitvector operators only (the arena's `ExprSort`
/// carries a Float sort, but no FP operator exists to build on it, so no
/// well-sorted FP node can be interned). Each of these either computes its
/// exact concrete result when every operand resolves to a concrete value
/// (mirroring the concrete interpreter bit-for-bit), or — when an operand is
/// genuinely symbolic — becomes a fresh under-constrained symbol with a
/// recorded debt site, exactly like the vector family. Ill-sorted FP nodes
/// are never emitted.
fn is_float_debt_primitive(op: IrPrimitive) -> bool {
    use IrPrimitive as P;
    matches!(op, P::FAdd | P::FSub | P::FMul | P::FDiv | P::FCompareFlags)
}

/// Width of a scalar float IR type, for float-primitive result symbols.
fn float_width(ty: IrType) -> Option<u16> {
    match ty {
        IrType::Float32 | IrType::Bits(32) => Some(32),
        IrType::Float64 | IrType::Bits(64) => Some(64),
        _ => None,
    }
}

/// Decodes a raw bit pattern as an f64 the way the concrete interpreter's
/// `read_float` does — `Float32` widens through `f32`, `Float64` decodes
/// directly; any other declared type refuses (mirroring the interpreter,
/// which errors rather than guessing).
fn decode_float(ty: IrType, raw: u64) -> Option<f64> {
    match ty {
        IrType::Float32 => Some(f64::from(f32::from_le_bytes(raw.to_le_bytes()[..4].try_into().ok()?))),
        IrType::Float64 => Some(f64::from_le_bytes(raw.to_le_bytes())),
        _ => None,
    }
}

/// Encodes an f64 result back into the operation's declared float type the
/// way the concrete interpreter's `write_float` does.
fn encode_float(ty: IrType, value: f64) -> Option<u64> {
    match ty {
        IrType::Float32 => Some(u64::from((value as f32).to_bits())),
        IrType::Float64 | IrType::Bits(_) => Some(value.to_bits()),
        _ => None,
    }
}

/// [`SymbolicEvaluator::exact_float_result`] for the concolic walk's
/// `(expression, concrete tag, type)` inputs: computes the exact result
/// when every operand carries a concrete tag, `None` otherwise.
fn exact_float_concolic(op: IrPrimitive, ty: IrType, inputs: &[(ExprId, Option<u128>, IrType)]) -> Option<u64> {
    let raws: Option<Vec<u64>> = inputs
        .iter()
        .map(|(_, concrete, _)| concrete.map(|value| value as u64))
        .collect();
    let operands = raws?;
    match op {
        IrPrimitive::FAdd | IrPrimitive::FSub | IrPrimitive::FMul | IrPrimitive::FDiv => {
            let left_raw = *operands.first()?;
            let right_raw = *operands.get(1)?;
            let left = decode_float(ty, left_raw)?;
            let right = decode_float(ty, right_raw)?;
            let value = match op {
                IrPrimitive::FAdd => left + right,
                IrPrimitive::FSub => left - right,
                IrPrimitive::FMul => left * right,
                IrPrimitive::FDiv => left / right,
                _ => unreachable!(),
            };
            encode_float(ty, value)
        }
        IrPrimitive::FCompareFlags => {
            let left_raw = *operands.first()?;
            let right_raw = *operands.get(1)?;
            let left = decode_float(inputs.first()?.2, left_raw)?;
            let right = decode_float(inputs.get(1)?.2, right_raw)?;
            // RFLAGS bit positions: CF=0, PF=2, ZF=6 — the exact layout the
            // concrete interpreter encodes (NaN yields the ZF|PF|CF triple).
            let mut flags: u64 = 0;
            if left.is_nan() || right.is_nan() {
                flags |= 1u64 << 6;
                flags |= 1u64 << 0;
                flags |= 1u64 << 2;
            } else if left > right {
            } else if left < right {
                flags |= 1u64 << 0;
            } else {
                flags |= 1u64 << 6;
            }
            Some(flags)
        }
        _ => None,
    }
}

/// Architectural width of a parent register for `PreserveParent` splices,
/// by register id. Mirrors the stable identifier ranges of
/// `angryier-arch-intel64::register_id` (persistence ids, documented as
/// never renumbered); mirrored here so the execution contracts crate keeps
/// its dependency graph free of an arch-crate edge. Only used when the
/// shadow holds no wider tracked binding for the register.
fn arch_parent_bits(register: u32) -> u16 {
    const ZMM_BASE: u32 = 0x0100;
    const OPMASK_BASE: u32 = 0x0140;
    const X87_BASE: u32 = 0x0180;
    const TILE_BASE: u32 = 0x0200;
    const TILE_END: u32 = 0x0208; // TILE_BASE + 8 tile registers.
    match register {
        ZMM_BASE..OPMASK_BASE => 512,
        OPMASK_BASE..X87_BASE => 64,
        X87_BASE..TILE_BASE => 80,
        TILE_BASE..TILE_END => 8192,
        // GPRs, RIP/RFLAGS/FS/GS/SSP, TILECFG, MXCSR, x87 control/status.
        _ => 64,
    }
}

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
    /// First-seen vector-primitive fallback sites (capped at
    /// [`SYMBOLIC_DEBT_SITE_CAP`]); the total keeps counting in
    /// `debt_total`.
    debt_sites: Vec<SymbolicDebtSite>,
    debt_total: u64,
    /// When set, every [`Self::eval_block_with_memory`] call restarts the
    /// fresh-symbol counter at 0, so re-evaluating the same block interns
    /// byte-identical expressions (the arena hash-conses them to the same
    /// `ExprId`s). Solver-assisted address concretization needs this: it
    /// pins a value for the failing address expression and re-runs the
    /// block, and a pin keyed by `ExprId` can only hit when the re-run
    /// rebuilds the very same `ExprId` — with a monotonically advancing
    /// counter, every retry re-materializes the address under a NEW fresh
    /// symbol and the retries can never converge.
    block_local_symbols: bool,
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
            debt_sites: Vec::new(),
            debt_total: 0,
            block_local_symbols: false,
        }
    }

    /// Opts into block-local fresh-symbol ids (see the field's docs). The
    /// first evaluation of a block is unaffected — a fresh evaluator starts
    /// at 0 regardless — so this only changes re-evaluation behavior, which
    /// is exactly the retry-pinning surface.
    pub fn with_block_local_symbols(mut self) -> Self {
        self.block_local_symbols = true;
        self
    }

    /// Symbols created so far, in creation order.
    pub fn symbols(&self) -> &[SymbolBinding] {
        &self.symbols
    }

    /// First-seen sites where a vector-family primitive was replaced with an
    /// under-constrained symbol (capped; see [`SYMBOLIC_DEBT_SITE_CAP`]).
    pub fn debt_sites(&self) -> &[SymbolicDebtSite] {
        &self.debt_sites
    }

    /// Total count of vector-primitive fallbacks, uncapped — the fidelity
    /// ledger signal. Never silent: a caller that ignores this is running
    /// under-constrained on every listed site.
    pub fn debt_total(&self) -> u64 {
        self.debt_total
    }

    /// Interns a fresh free symbol of `width` bits and advances the symbol
    /// counter. Debt symbols deliberately stay out of [`Self::symbols`]:
    /// they have no architectural input source, and a solver model keyed on
    /// one must not be mapped back onto a register as an input assignment.
    fn fresh_symbol(&mut self, width: u16) -> Result<ExprId, SymbolicEvalError> {
        let symbol_id = self.next_symbol;
        self.next_symbol = symbol_id
            .checked_add(1)
            .ok_or_else(|| SymbolicEvalError::UnsupportedOperation("symbol id overflow".into()))?;
        self.intern(
            ExprSort::BitVec(width),
            ExprOp::Symbol,
            Vec::new(),
            symbol_id.to_le_bytes().to_vec(),
        )
    }

    /// Records a vector-primitive fallback site (deduplicated, capped).
    fn record_debt(&mut self, op: IrPrimitive, ty: IrType) {
        self.debt_total += 1;
        let site = SymbolicDebtSite {
            op,
            width_bits: bit_width(ty).unwrap_or(0),
            lane_bits: match ty {
                IrType::Vector { lane_bits, .. } => lane_bits,
                _ => 0,
            },
        };
        if self.debt_sites.len() < SYMBOLIC_DEBT_SITE_CAP && !self.debt_sites.contains(&site) {
            self.debt_sites.push(site);
        }
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
        let expression = self.fresh_symbol(width)?;
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
        // Block-local fresh-symbol ids: re-evaluations rebuild identical
        // expressions (see `block_local_symbols`). Fresh symbols stay
        // distinct WITHIN one evaluation — the counter still advances — so
        // no two under-constrained values created by the same block ever
        // alias.
        if self.block_local_symbols {
            self.next_symbol = 0;
        }
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
                        RegisterWriteKind::PreserveParent { bit_offset, width_bits } => {
                            // Symbolic splice of the concrete interpreter's
                            // byte-granular merge: result = concat(parent
                            // high bits, value, parent low bits). The parent
                            // view comes from the shadow when the register is
                            // tracked, else from the concrete snapshot (GPR-
                            // sized values only) or a fresh under-constrained
                            // symbol via read_register. The parent width is
                            // the tracked binding's width when it covers the
                            // write, else the register family's architectural
                            // width — 512 for zmm parents (an xmm write
                            // preserves bits 128..512), 80 for x87, 64 for
                            // GPRs.
                            let (lo, w) = (*bit_offset, *width_bits);
                            let span = lo.saturating_add(w);
                            if lo % 8 != 0 || w % 8 != 0 || w == 0 || bit_width(ty)? != w {
                                return Err(SymbolicEvalError::UnsupportedOperation("partial register write".into()));
                            }
                            let tracked_width = self
                                .registers
                                .get(register)
                                .and_then(|(_, tracked_ty)| bit_width(*tracked_ty).ok());
                            let parent_width = match tracked_width {
                                Some(tracked) if tracked >= span => tracked,
                                _ => arch_parent_bits(*register).max(span),
                            };
                            if lo == 0 && w == parent_width {
                                (expression, ty)
                            } else {
                                let parent = self.read_register(*register, IrType::Bits(parent_width))?;
                                let mut spliced = None;
                                let mut spliced_width = 0u16;
                                for part in [
                                    (lo > 0).then(|| {
                                        let mut imm = Vec::with_capacity(4);
                                        imm.extend_from_slice(&0u16.to_le_bytes());
                                        imm.extend_from_slice(&lo.to_le_bytes());
                                        Ok((
                                            self.intern(ExprSort::BitVec(lo), ExprOp::Extract, vec![parent], imm)?,
                                            lo,
                                        ))
                                    }),
                                    Some(Ok((expression, w))),
                                    (span < parent_width).then(|| {
                                        let high_width = parent_width - span;
                                        let mut imm = Vec::with_capacity(4);
                                        imm.extend_from_slice(&span.to_le_bytes());
                                        imm.extend_from_slice(&high_width.to_le_bytes());
                                        Ok((
                                            self.intern(
                                                ExprSort::BitVec(high_width),
                                                ExprOp::Extract,
                                                vec![parent],
                                                imm,
                                            )?,
                                            high_width,
                                        ))
                                    }),
                                ]
                                .into_iter()
                                .flatten()
                                {
                                    let (part, part_width) = part?;
                                    spliced = Some(match spliced {
                                        None => part,
                                        Some(prev) => self.intern(
                                            ExprSort::BitVec(spliced_width + part_width),
                                            ExprOp::Concat,
                                            vec![prev, part],
                                            Vec::new(),
                                        )?,
                                    });
                                    spliced_width += part_width;
                                }
                                let result = spliced.ok_or_else(|| {
                                    SymbolicEvalError::UnsupportedOperation("partial register write".into())
                                })?;
                                (result, IrType::Bits(parent_width))
                            }
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
                    // resolve through this map. The map's carrier is u64, so
                    // only address-sized (≤64-bit) loads qualify — a wider
                    // (vector) load must not masquerade as a known u64.
                    if width <= 64
                        && let Ok(bytes) = memory.read_bytes(addr, usize::from(width).div_ceil(8))
                    {
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
            // 64-bit-tracked rcx read as CL, a 512-bit-tracked zmm read as
            // its xmm view) or a narrowed sub-view write. Without this,
            // operations that do not self-coerce (comparisons) intern
            // ill-sorted nodes; a wider read zero-extends, matching the
            // ZeroExtendParent semantics of 32-bit x86-64 writes.
            let stored = *expression;
            let requested = bit_width(ty)?;
            let coerced = coerce_width(self.arena, stored, requested)?;
            return Ok(coerced);
        }
        let width = bit_width(ty)?;
        // Concrete fallback: untouched registers read their concrete value
        // from the state's snapshot instead of materializing a free symbol —
        // keeps stack pointers and startup registers concrete. The snapshot
        // carries u64 values only, so it cannot answer wider (vector) reads;
        // those fall through to a fresh under-constrained symbol rather than
        // pretending the unknown high bytes are zero.
        if width <= 64
            && let Some(&value) = self.concrete_registers.get(&register)
        {
            let byte_len = usize::from(width).div_ceil(8);
            let mut bytes = value.to_le_bytes().to_vec();
            bytes.truncate(byte_len.clamp(1, 8));
            let expression = self.intern(ExprSort::BitVec(width), ExprOp::Constant, Vec::new(), bytes)?;
            self.registers.insert(register, (expression, ty));
            return Ok(expression);
        }
        let expression = self.fresh_symbol(width)?;
        self.registers.insert(register, (expression, ty));
        // Wide (vector-file) symbols stay out of the input-symbol list: the
        // session maps solver models back onto registers through that list,
        // and a 512-bit free variable has no u64 input slot to assign. The
        // expression still flows into queries as an unconstrained leaf.
        if width <= 64 {
            self.symbols.push(SymbolBinding {
                register,
                width,
                expression,
            });
        }
        Ok(expression)
    }

    fn primitive(
        &mut self,
        op: IrPrimitive,
        ty: IrType,
        inputs: &[(ExprId, IrType)],
    ) -> Result<(ExprId, IrType), SymbolicEvalError> {
        // Vector-family lane primitives have no flat-expression lowering:
        // concretize-with-debt — the result becomes a fresh under-constrained
        // symbol and the site is recorded (see [`is_vector_debt_primitive`]).
        // Declared before the arena walk so the inputs stay untouched.
        if is_vector_debt_primitive(op) {
            let width = bit_width(ty)?;
            let expression = self.fresh_symbol(width)?;
            self.record_debt(op, ty);
            return Ok((expression, ty));
        }
        // Scalar float primitives: no FP operator exists in the expression
        // language (see [`is_float_debt_primitive`]). When every operand
        // resolves to a concrete value the result is computed exactly,
        // mirroring the concrete interpreter; otherwise the result
        // concretizes with debt like the vector family. All derived flag
        // sites in the block read from the ONE value a compare produces, so
        // consistency within the block holds either way.
        if is_float_debt_primitive(op) {
            return self.float_primitive(op, ty, inputs);
        }
        primitive_expr(self.arena, op, ty, inputs)
    }

    /// Scalar float primitive: exact concrete mirroring when every operand
    /// resolves, otherwise a fresh under-constrained symbol + debt site.
    fn float_primitive(
        &mut self,
        op: IrPrimitive,
        ty: IrType,
        inputs: &[(ExprId, IrType)],
    ) -> Result<(ExprId, IrType), SymbolicEvalError> {
        if let Some(exact) = self.exact_float_result(op, ty, inputs)? {
            return Ok((exact, ty));
        }
        let width = float_width(ty)
            .or_else(|| bit_width(ty).ok())
            .ok_or_else(|| SymbolicEvalError::UnsupportedType(format!("float primitive result {ty:?}")))?;
        let expression = self.fresh_symbol(width)?;
        self.record_debt(op, ty);
        Ok((expression, ty))
    }

    /// Computes a float primitive's exact result when every operand carries
    /// a concrete value — the same decode/compute/encode the concrete
    /// interpreter performs (`read_float`, the IEEE arithmetic, the
    /// RFLAGS-shaped compare layout with CF=0/PF=2/ZF=6 and the unordered
    /// NaN triple). `None` means any operand stayed symbolic.
    fn exact_float_result(
        &self,
        op: IrPrimitive,
        ty: IrType,
        inputs: &[(ExprId, IrType)],
    ) -> Result<Option<ExprId>, SymbolicEvalError> {
        let resolved: Option<Vec<u64>> = inputs
            .iter()
            .map(|(expression, _)| {
                constant_value(self.arena, *expression)
                    .ok()
                    .or_else(|| self.expr_concrete.get(expression).copied())
            })
            .collect();
        let Some(operands) = resolved else {
            return Ok(None);
        };
        let result: Option<u64> = match op {
            IrPrimitive::FAdd | IrPrimitive::FSub | IrPrimitive::FMul | IrPrimitive::FDiv => {
                let (Some(left_raw), Some(right_raw)) = (operands.first().copied(), operands.get(1).copied()) else {
                    return Ok(None);
                };
                let (Some(left), Some(right)) = (decode_float(ty, left_raw), decode_float(ty, right_raw)) else {
                    return Ok(None);
                };
                let value = match op {
                    // Rust's f64 arithmetic yields the IEEE-754 bit patterns
                    // the concrete interpreter relies on (x/0 is +-Inf).
                    IrPrimitive::FAdd => left + right,
                    IrPrimitive::FSub => left - right,
                    IrPrimitive::FMul => left * right,
                    IrPrimitive::FDiv => left / right,
                    _ => unreachable!(),
                };
                encode_float(ty, value)
            }
            IrPrimitive::FCompareFlags => {
                let (Some(left_raw), Some(right_raw)) = (operands.first().copied(), operands.get(1).copied()) else {
                    return Ok(None);
                };
                let (Some(left), Some(right)) = (
                    inputs
                        .first()
                        .and_then(|(_, input_ty)| decode_float(*input_ty, left_raw)),
                    inputs
                        .get(1)
                        .and_then(|(_, input_ty)| decode_float(*input_ty, right_raw)),
                ) else {
                    return Ok(None);
                };
                // RFLAGS bit positions: CF=0, PF=2, ZF=6 — the exact layout
                // the concrete interpreter encodes.
                let mut flags: u64 = 0;
                if left.is_nan() || right.is_nan() {
                    flags |= 1u64 << 6; // ZF
                    flags |= 1u64 << 0; // CF
                    flags |= 1u64 << 2; // PF
                } else if left > right {
                    // ZF=0, CF=0, PF=0
                } else if left < right {
                    flags |= 1u64 << 0; // CF
                } else {
                    flags |= 1u64 << 6; // ZF
                }
                Some(flags)
            }
            _ => None,
        };
        let Some(value) = result else {
            return Ok(None);
        };
        let width = float_width(ty)
            .or_else(|| bit_width(ty).ok())
            .ok_or_else(|| SymbolicEvalError::UnsupportedType(format!("float primitive result {ty:?}")))?;
        let byte_width = usize::from(width).div_ceil(8);
        let expression = self.intern(
            ExprSort::BitVec(width),
            ExprOp::Constant,
            Vec::new(),
            value.to_le_bytes()[..byte_width].to_vec(),
        )?;
        Ok(Some(expression))
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
    memo: &mut FxHashSet<ExprId>,
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
    mut memo: Option<&mut FxHashSet<ExprId>>,
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
    memo: &mut Option<&mut FxHashSet<ExprId>>,
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
    mut memo: Option<&mut FxHashSet<ExprId>>,
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
            // The carrier is the operand's low 64 bits; an extract window
            // starting at or above 64 lies entirely outside it. Wide
            // (128/256/512-bit) constants fold approximately through this
            // u64 view throughout — return 0 rather than shift-overflow
            // (a debug panic, a silent wrap in release).
            if u32::from(start) >= 64 {
                return Ok(0);
            }
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
        ExprOp::Mul => Ok(child!(node.operands.first())?.wrapping_mul(child!(node.operands.get(1))?)),
        ExprOp::UDiv => {
            let rhs = child!(node.operands.get(1))?;
            if rhs == 0 {
                return Err(FoldFail::Absolute);
            }
            Ok(child!(node.operands.first())? / rhs)
        }
        ExprOp::SDiv => {
            let rhs = child!(node.operands.get(1))? as i64;
            if rhs == 0 {
                return Err(FoldFail::Absolute);
            }
            let lhs = child!(node.operands.first())? as i64;
            Ok(lhs.wrapping_div(rhs) as u64)
        }
        ExprOp::AShr => {
            let lhs = child!(node.operands.first())? as i64;
            let shift = (child!(node.operands.get(1))? & 63) as u32;
            Ok((lhs >> shift) as u64)
        }
        ExprOp::Ult => Ok(u64::from(
            child!(node.operands.first())? < child!(node.operands.get(1))?,
        )),
        ExprOp::Ule => Ok(u64::from(
            child!(node.operands.first())? <= child!(node.operands.get(1))?,
        )),
        ExprOp::Slt | ExprOp::Sle => {
            let op0 = *node.operands.first().ok_or(FoldFail::Absolute)?;
            let width = arena
                .sort_of(op0)
                .and_then(|sort| match sort {
                    ExprSort::BitVec(w) => Some(u32::from(w)),
                    _ => None,
                })
                .unwrap_or(64);
            let sign_extend = |val: u64| -> i64 {
                if width > 0 && width < 64 && (val & (1u64 << (width - 1))) != 0 {
                    (val | (!0u64 << width)) as i64
                } else {
                    val as i64
                }
            };
            let lhs = sign_extend(child!(node.operands.first())?);
            let rhs = sign_extend(child!(node.operands.get(1))?);
            if op == ExprOp::Slt {
                Ok(u64::from(lhs < rhs))
            } else {
                Ok(u64::from(lhs <= rhs))
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
pub fn constant_value_resolved(
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
/// Interns a `width`-bit constant expression from a `u64` value.
fn bv_constant(arena: &SymbolicArena, width: u16, value: u64) -> Result<ExprId, SymbolicEvalError> {
    let byte_width = usize::from(width).div_ceil(8);
    intern(
        arena,
        ExprSort::BitVec(width),
        ExprOp::Constant,
        Vec::new(),
        value.to_le_bytes()[..byte_width].to_vec(),
    )
}

/// One binary bitvector operation over already-width-coerced operands.
fn bv_binop(
    arena: &SymbolicArena,
    op: ExprOp,
    width: u16,
    left: ExprId,
    right: ExprId,
) -> Result<ExprId, SymbolicEvalError> {
    intern(arena, ExprSort::BitVec(width), op, vec![left, right], Vec::new())
}

/// The popcount masks for the supported operand widths, plus the final
/// result mask (a popcount of `width` bits needs `ceil(log2(width + 1))`
/// bits: 64 → 0x7f, 32 → 0x3f, 16 → 0x1f, 8 → 0x0f).
fn popcount_masks(width: u16) -> Option<(u64, u64, u64, u64, u64)> {
    match width {
        8 => Some((0x55, 0x33, 0x0f, 0, 0x0f)),
        16 => Some((0x5555, 0x3333, 0x0f0f, 0, 0x1f)),
        32 => Some((0x5555_5555, 0x3333_3333, 0x0f0f_0f0f, 0, 0x3f)),
        64 => Some((
            0x5555_5555_5555_5555,
            0x3333_3333_3333_3333,
            0x0f0f_0f0f_0f0f_0f0f,
            0,
            0x7f,
        )),
        _ => None,
    }
}

/// Bit-precise symbolic popcount over the flat bitvec — the classic SWAR
/// decomposition (subtract-mask, pairwise sums, nibble fold, then the
/// byte/half/word folds), which is exact for every input and needs only
/// And/LShr/Sub/Add over constants. Concrete inputs fold to constants in
/// the arena bottom-up, so the all-concrete case stays cheap and hash-
/// consed.
fn lower_popcount(arena: &SymbolicArena, input: ExprId, width: u16) -> Result<ExprId, SymbolicEvalError> {
    let Some((m1, m2, m4, _, final_mask)) = popcount_masks(width) else {
        return Err(SymbolicEvalError::UnsupportedOperation(format!(
            "popcount width {width}"
        )));
    };
    let c = |value: u64| bv_constant(arena, width, value);
    let x = input;
    // x = x - ((x >> 1) & m1): each 2-bit field now holds its bit count.
    let x = bv_binop(
        arena,
        ExprOp::Sub,
        width,
        x,
        bv_binop(
            arena,
            ExprOp::And,
            width,
            bv_binop(arena, ExprOp::LShr, width, x, c(1)?)?,
            c(m1)?,
        )?,
    )?;
    // x = (x & m2) + ((x >> 2) & m2): each 4-bit field holds its bit count.
    let low = bv_binop(arena, ExprOp::And, width, x, c(m2)?)?;
    let high = bv_binop(
        arena,
        ExprOp::And,
        width,
        bv_binop(arena, ExprOp::LShr, width, x, c(2)?)?,
        c(m2)?,
    )?;
    let x = bv_binop(arena, ExprOp::Add, width, low, high)?;
    // Nibble fold: (x + (x >> 4)) & m4 — each byte holds its bit count.
    let x = bv_binop(
        arena,
        ExprOp::And,
        width,
        bv_binop(
            arena,
            ExprOp::Add,
            width,
            x,
            bv_binop(arena, ExprOp::LShr, width, x, c(4)?)?,
        )?,
        c(m4)?,
    )?;
    // Cumulative folds so the low byte/half/word accumulates the full
    // count, then the final result mask.
    let mut x = x;
    for shift in [8u64, 16, 32] {
        if shift < u64::from(width) {
            x = bv_binop(
                arena,
                ExprOp::Add,
                width,
                x,
                bv_binop(arena, ExprOp::LShr, width, x, c(shift)?)?,
            )?;
        }
    }
    bv_binop(arena, ExprOp::And, width, x, c(final_mask)?)
}

/// Bit-precise symbolic count-leading-zeros. Smearing the highest set bit
/// down (`y |= y >> s` for s = 1,2,4,... below the width) yields a value
/// whose popcount is `position_of_highest_set_bit + 1`, and `width - that`
/// is the leading-zero count — including `x = 0`, where the smear stays 0
/// and the result is `width` (the concrete interpreter's convention).
fn lower_clz(arena: &SymbolicArena, input: ExprId, width: u16) -> Result<ExprId, SymbolicEvalError> {
    if popcount_masks(width).is_none() {
        return Err(SymbolicEvalError::UnsupportedOperation(format!("clz width {width}")));
    }
    let c = |value: u64| bv_constant(arena, width, value);
    let mut y = input;
    for shift in [1u64, 2, 4, 8, 16, 32] {
        if shift < u64::from(width) {
            let shifted = bv_binop(arena, ExprOp::LShr, width, y, c(shift)?)?;
            y = bv_binop(arena, ExprOp::Or, width, y, shifted)?;
        }
    }
    let counted = lower_popcount(arena, y, width)?;
    bv_binop(arena, ExprOp::Sub, width, c(u64::from(width))?, counted)
}

/// Bit-precise symbolic count-trailing-zeros. Isolating the lowest set bit
/// (`x & -x`) and subtracting one leaves exactly `ctz` low ones set; for
/// `x = 0` the isolate is 0 and `0 - 1` wraps to all ones, so the popcount
/// is `width` (the concrete interpreter's convention for zero).
fn lower_ctz(arena: &SymbolicArena, input: ExprId, width: u16) -> Result<ExprId, SymbolicEvalError> {
    if popcount_masks(width).is_none() {
        return Err(SymbolicEvalError::UnsupportedOperation(format!("ctz width {width}")));
    }
    let c = |value: u64| bv_constant(arena, width, value);
    let negated = bv_binop(arena, ExprOp::Sub, width, c(0)?, input)?;
    let isolated = bv_binop(arena, ExprOp::And, width, input, negated)?;
    let minus_one = bv_binop(arena, ExprOp::Sub, width, isolated, c(1)?)?;
    lower_popcount(arena, minus_one, width)
}

/// Bit-precise symbolic CRC-32C (SSE4.2 `crc32`): the bitwise round loop
/// the concrete interpreter runs, expressed with Extract/ZExt/Xor over the
/// flat bitvec. One feedback round is `crc = (crc >> 1) ^ (POLY & (0 - lsb))`
/// — the `(0 - lsb)` mask trick replaces the branch, since `0 - 1` is the
/// all-ones mask and `0 - 0` is zero. Concrete inputs fold bottom-up into a
/// single constant.
fn lower_crc32(
    arena: &SymbolicArena,
    crc_input: ExprId,
    data: ExprId,
    data_bits: u16,
    output_width: u16,
) -> Result<ExprId, SymbolicEvalError> {
    const POLY: u32 = 0x82F63B78;
    if !data_bits.is_multiple_of(8) || data_bits == 0 || data_bits > 64 {
        return Err(SymbolicEvalError::UnsupportedOperation(format!(
            "crc32 input width {data_bits}"
        )));
    }
    let poly = bv_constant(arena, 32, u64::from(POLY))?;
    let zero = bv_constant(arena, 32, 0)?;
    let one = bv_constant(arena, 32, 1)?;
    // The running CRC state is 32-bit regardless of the destination
    // register width (the interpreter casts the accumulator to u32).
    let mut crc = coerce_width(arena, crc_input, 32)?;
    for byte_index in 0..(data_bits / 8) {
        // Extract immediate = [start:u16][width:u16] — byte `i` lives at
        // bit offset `i * 8` (little-endian, matching the interpreter's
        // `(data >> byte_idx * 8) & 0xFF`).
        let mut imm = Vec::with_capacity(4);
        imm.extend_from_slice(&(byte_index * 8).to_le_bytes());
        imm.extend_from_slice(&8u16.to_le_bytes());
        let byte = intern(arena, ExprSort::BitVec(8), ExprOp::Extract, vec![data], imm)?;
        let byte32 = intern(arena, ExprSort::BitVec(32), ExprOp::ZExt, vec![byte], Vec::new())?;
        crc = bv_binop(arena, ExprOp::Xor, 32, crc, byte32)?;
        for _ in 0..8 {
            // Extract immediate = [start:u16][width:u16] — the low bit.
            let mut start_imm = Vec::with_capacity(4);
            start_imm.extend_from_slice(&0u16.to_le_bytes());
            start_imm.extend_from_slice(&1u16.to_le_bytes());
            let lsb = intern(arena, ExprSort::BitVec(1), ExprOp::Extract, vec![crc], start_imm)?;
            let lsb32 = intern(arena, ExprSort::BitVec(32), ExprOp::ZExt, vec![lsb], Vec::new())?;
            // (0 - lsb): 0x00000000 or 0xFFFFFFFF — the branchless feedback.
            let mask = bv_binop(arena, ExprOp::Sub, 32, zero, lsb32)?;
            let feedback = bv_binop(arena, ExprOp::And, 32, poly, mask)?;
            let shifted = bv_binop(arena, ExprOp::LShr, 32, crc, one)?;
            crc = bv_binop(arena, ExprOp::Xor, 32, shifted, feedback)?;
        }
    }
    coerce_width(arena, crc, output_width)
}

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
        IrPrimitive::Popcnt => {
            // Input coerced to the declared output width first (shadow
            // widths can drift from the declared IR types), then the exact
            // SWAR decomposition.
            let operand = coerce_width(arena, operands[0], output_width)?;
            let value = lower_popcount(arena, operand, output_width)?;
            Ok((value, ty))
        }
        IrPrimitive::Clz => {
            let operand = coerce_width(arena, operands[0], output_width)?;
            let value = lower_clz(arena, operand, output_width)?;
            Ok((value, ty))
        }
        IrPrimitive::Ctz => {
            let operand = coerce_width(arena, operands[0], output_width)?;
            let value = lower_ctz(arena, operand, output_width)?;
            Ok((value, ty))
        }
        IrPrimitive::Crc32 => {
            if inputs.len() != 2 {
                return Err(SymbolicEvalError::UnsupportedOperation("crc32 arity".into()));
            }
            let data_bits = bit_width(inputs[1].1)?;
            let value = lower_crc32(arena, operands[0], operands[1], data_bits, output_width)?;
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
    /// Declared bit width of `register`, or `None` when unknown. Defaults
    /// to the allocating [`read_register`](Self::read_register) read; images
    /// with a width table override it.
    fn register_width(&self, register: u32) -> Option<u16> {
        let bytes = self.read_register(register)?;
        u16::try_from(bytes.len() * 8).ok()
    }
    /// Allocation-free register read: fills `out` (whose length is the
    /// requested byte width) with the register's concrete little-endian
    /// bytes. Returns `false` when the register is unknown or narrower
    /// than requested. The default wraps
    /// [`read_register`](Self::read_register).
    fn read_register_into(&self, register: u32, out: &mut [u8]) -> bool {
        match self.read_register(register) {
            Some(bytes) if bytes.len() >= out.len() => {
                out.copy_from_slice(&bytes[..out.len()]);
                true
            }
            _ => false,
        }
    }
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
    constants: FxHashMap<(u16, u128), ExprId>,
    /// Negative fold memo: expressions proven non-constant by
    /// [`constant_value`]. Arena nodes are immutable, so a failure is valid
    /// forever; without it every register write would re-walk the top of a
    /// value chain that grows one node per iteration.
    non_constants: FxHashSet<ExprId>,
    /// First-seen vector-primitive fallback sites (capped at
    /// [`SYMBOLIC_DEBT_SITE_CAP`]); the total keeps counting in
    /// `debt_total`.
    debt_sites: Vec<SymbolicDebtSite>,
    debt_total: u64,
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
            constants: FxHashMap::default(),
            non_constants: FxHashSet::default(),
            debt_sites: Vec::new(),
            debt_total: 0,
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

    /// First-seen sites where a vector-family primitive was replaced with an
    /// under-constrained symbol (capped; see [`SYMBOLIC_DEBT_SITE_CAP`]).
    pub fn debt_sites(&self) -> &[SymbolicDebtSite] {
        &self.debt_sites
    }

    /// Total count of vector-primitive fallbacks, uncapped — the fidelity
    /// ledger signal. Never silent: a caller that ignores this is running
    /// under-constrained on every listed site.
    pub fn debt_total(&self) -> u64 {
        self.debt_total
    }

    /// Records a vector-primitive fallback site (deduplicated, capped).
    fn record_debt(&mut self, op: IrPrimitive, ty: IrType) {
        self.debt_total += 1;
        let site = SymbolicDebtSite {
            op,
            width_bits: bit_width(ty).unwrap_or(0),
            lane_bits: match ty {
                IrType::Vector { lane_bits, .. } => lane_bits,
                _ => 0,
            },
        };
        if self.debt_sites.len() < SYMBOLIC_DEBT_SITE_CAP && !self.debt_sites.contains(&site) {
            self.debt_sites.push(site);
        }
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
        // QSYM-style concrete-first fast path: blocks with no symbolic
        // influence evaluate without expression construction or interning;
        // the first sign of influence falls through to the full walk.
        if let Some(summary) = self.try_concrete_block(image, block) {
            return Ok(summary);
        }
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
                    // The concrete tag's carrier is u128 — wider (256/512-bit
                    // vector) constants keep the exact expression but no tag,
                    // so downstream fast paths never mistake a truncated
                    // prefix for the whole value.
                    let width = bit_width(*ty)?;
                    let concrete = (width <= 128).then(|| {
                        bytes_le
                            .iter()
                            .enumerate()
                            .take(16)
                            .fold(0u128, |acc, (index, byte)| acc | (u128::from(*byte) << (8 * index)))
                    });
                    Some((self.constant(*ty, bytes_le)?, concrete, *ty))
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
                    // The tag carrier is u128 — wider (vector-file) writes
                    // keep the exact constant expression but no truncated
                    // tag.
                    if concrete.is_none() && bit_width(ty)? <= 128 {
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

    /// Concrete-first block evaluation: walks `block` with concrete values
    /// only — no expression construction for intermediates, no interning
    /// per value — and returns `None` the moment any symbolic influence
    /// appears (a symbolic register shadow, a symbolic memory byte in a
    /// load, an unconcrete [`IrOp::ExprRef`], or anything the concrete
    /// folder does not cover). The caller falls back to the full symbolic
    /// walk.
    ///
    /// Real traces are dominated by blocks no input reaches; skipping
    /// expression building for them is the QSYM-style concolic win. All
    /// shadow mutations are buffered and committed only on success, so a
    /// fallback observes untouched state. The committed state matches the
    /// full walk's for everything it wrote:
    /// - written registers land as cached constants (expression + concrete
    ///   pair) exactly as the full walk stores its folded results — the
    ///   shadow must keep serving reads of registers the image may not
    ///   know, and diagnostics must stay indistinguishable — and
    /// - concrete stores land as concrete shadow bytes so later loads in
    ///   either path read fresh values, never stale ones.
    ///
    /// Branch conditions on this path are necessarily concrete, so no
    /// `SymbolicBranch` is recorded: a concrete condition cannot be
    /// inverted by any input, and the recorded constraint would be sliced
    /// out of every solver query anyway (empty dependency cone).
    ///
    /// Widths above 128 bits fall back: the concrete carrier is `u128`,
    /// and folding only its low half would diverge from the full walk.
    fn try_concrete_block(&mut self, image: &dyn ConcolicImage, block: &IrBlock) -> Option<SymbolicBlockSummary> {
        // Value slots mirror the full walk's indexing; every stored slot is
        // concrete by construction (non-concrete production falls back).
        let mut values: Vec<Option<(u128, IrType)>> = Vec::new();
        let mut written_registers: Vec<u32> = Vec::new();
        // (register, stored type, folded value): the constant expression
        // is interned at commit, through the constants cache.
        let mut pending_registers: Vec<(u32, IrType, u128)> = Vec::new();
        let mut pending_memory: Vec<(u64, u8)> = Vec::new();
        let mut terminated = false;

        for instruction in &block.instructions {
            let produced: Option<(u128, IrType)> = match &instruction.op {
                IrOp::Constant { ty, bytes_le } => {
                    let width = bit_width(*ty).ok()?;
                    if width > 128 {
                        return None;
                    }
                    let concrete = bytes_le
                        .iter()
                        .enumerate()
                        .take(16)
                        .fold(0u128, |acc, (index, byte)| acc | (u128::from(*byte) << (8 * index)));
                    Some((concrete, *ty))
                }
                IrOp::ExprRef { expression, ty } => {
                    // The arena folds constants at intern time, so a
                    // foldable ExprRef is a Constant node; the negative
                    // memo keeps repeated probes of the same symbol cheap.
                    let value = self.constant_value_memo(*expression)?;
                    Some((u128::from(value), *ty))
                }
                IrOp::ReadRegister { register, ty } => {
                    let width = bit_width(*ty).ok()?;
                    if width > 128 {
                        return None;
                    }
                    Some((self.concrete_register(image, *register, *ty)?, *ty))
                }
                IrOp::Primitive { op, ty, inputs } => {
                    let output_width = bit_width(*ty).ok()?;
                    const MAX_INLINE: usize = 4;
                    if inputs.len() > MAX_INLINE || output_width > 128 {
                        return None;
                    }
                    let mut typed = [(0u128, 0u16); MAX_INLINE];
                    for (slot, id) in typed.iter_mut().zip(inputs) {
                        let (value, input_ty) = concrete_value(&values, *id)?;
                        let input_width = bit_width(input_ty).ok()?;
                        if input_width > 128 {
                            return None;
                        }
                        *slot = (value, input_width);
                    }
                    let result = eval_primitive_concrete(*op, output_width, &typed[..inputs.len()])?;
                    Some((result, *ty))
                }
                IrOp::WriteRegister { register, value, kind } => {
                    let (concrete, source_ty) = concrete_value(&values, *value)?;
                    let source_width = bit_width(source_ty).ok()?;
                    if source_width > 128 {
                        return None;
                    }
                    match kind {
                        RegisterWriteKind::ReplaceParent => {
                            pending_registers.push((*register, source_ty, concrete));
                        }
                        RegisterWriteKind::ZeroExtendParent => {
                            let target_ty = self.concrete_register_ty(image, *register)?;
                            let target_width = bit_width(target_ty).ok()?;
                            if target_width > 128 {
                                return None;
                            }
                            // Zero-extension leaves the folded value
                            // unchanged (a degenerate extension relabels
                            // without narrowing, exactly like the full
                            // walk; readers normalize on read).
                            pending_registers.push((*register, target_ty, concrete));
                        }
                        RegisterWriteKind::PreserveParent { bit_offset, .. } => {
                            let parent_ty = self.concrete_register_ty(image, *register)?;
                            let parent_width = bit_width(parent_ty).ok()?;
                            if parent_width > 128 {
                                return None;
                            }
                            let parent = self.concrete_register(image, *register, parent_ty)?;
                            let merged = splice_concrete(parent, parent_width, concrete, *bit_offset, source_width);
                            pending_registers.push((*register, parent_ty, merged));
                        }
                    }
                    written_registers.push(*register);
                    None
                }
                IrOp::Branch { condition, .. } => {
                    // All stored slots are concrete; an undefined (never
                    // produced) condition slot falls back. A concrete
                    // condition contributes no invertible constraint.
                    concrete_value(&values, *condition)?;
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
                    let width = bit_width(*ty).ok()?;
                    if width > 128 {
                        return None;
                    }
                    let byte_width = usize::from(width).div_ceil(8);
                    let (address, _) = concrete_value(&values, *address)?;
                    let base = u64::try_from(address).ok()?;
                    const MAX_INLINE_LOAD: usize = 16;
                    let mut inline = [ByteValue::Concrete(0); MAX_INLINE_LOAD];
                    let bytes: &mut [ByteValue] = if byte_width <= MAX_INLINE_LOAD {
                        &mut inline[..byte_width]
                    } else {
                        return None;
                    };
                    if !image.read_bytes_into(base, bytes) {
                        // The full walk has a byte-at-a-time fallback for
                        // span-edge shadow coverage; let it handle it.
                        return None;
                    }
                    let mut concrete = 0u128;
                    for (offset, slot) in bytes.iter_mut().enumerate() {
                        let value = match self.memory.get(&(base.wrapping_add(offset as u64))) {
                            Some(ByteValue::Concrete(byte)) => ByteValue::Concrete(*byte),
                            Some(ByteValue::Symbolic(_)) => return None,
                            None => *slot,
                        };
                        *slot = value;
                        if offset < 16
                            && let ByteValue::Concrete(byte) = value
                        {
                            concrete |= u128::from(byte) << (8 * offset);
                        }
                    }
                    Some((concrete, *ty))
                }
                IrOp::Store { address, value } => {
                    let (address, _) = concrete_value(&values, *address)?;
                    let base = u64::try_from(address).ok()?;
                    let (value, value_ty) = concrete_value(&values, *value)?;
                    let width = bit_width(value_ty).ok()?;
                    if width > 128 {
                        return None;
                    }
                    let byte_width = usize::from(width).div_ceil(8);
                    for offset in 0..byte_width {
                        let byte = (value >> (8 * offset)) as u8;
                        pending_memory.push((base.wrapping_add(offset as u64), byte));
                    }
                    None
                }
            };

            if let Some((concrete, ty)) = produced {
                let result = instruction.result?;
                let index = usize::try_from(result.0).ok()?;
                if values.len() <= index {
                    values.resize(index + 1, None);
                }
                values[index] = Some((concrete, ty));
            }

            if terminated {
                break;
            }
        }

        // Commit phase one — intern the folded constants (cache-backed;
        // the cache itself stays valid even if a later step falls back).
        // An intern error here falls back to the full walk untouched.
        let mut committed = Vec::with_capacity(pending_registers.len());
        for (register, stored_ty, value) in pending_registers {
            let width = bit_width(stored_ty).ok()?;
            let byte_width = usize::from(width).div_ceil(8);
            let expression = self.constant(stored_ty, &value.to_le_bytes()[..byte_width]).ok()?;
            committed.push((register, expression, stored_ty, value));
        }
        // Commit phase two — infallible map updates.
        for (register, expression, stored_ty, value) in committed {
            self.registers.insert(register, (expression, stored_ty));
            self.register_concretes.insert(register, Some(value));
        }
        for (address, byte) in pending_memory {
            self.memory.insert(address, ByteValue::Concrete(byte));
        }
        Some(SymbolicBlockSummary {
            branch: None,
            written_registers,
            terminated,
            jump_target: None,
        })
    }

    /// Concrete view of `register` at `ty` width: the tracked shadow when
    /// concrete (width-normalized exactly like the full walk's
    /// `read_register`), else the image's live bytes. `None` means
    /// symbolic-or-unknown — the caller falls back. Never mutates, so a
    /// subsequent full walk starts from identical state.
    fn concrete_register(&self, image: &dyn ConcolicImage, register: u32, ty: IrType) -> Option<u128> {
        let requested = bit_width(ty).ok()?;
        if let Some((_, stored_ty)) = self.registers.get(&register) {
            let concrete = self.register_concretes.get(&register).copied().flatten()?;
            let stored_width = bit_width(*stored_ty).ok()?;
            if stored_width > requested {
                return Some(concrete & mask_u128(requested));
            }
            return Some(concrete);
        }
        let byte_width = usize::from(requested).div_ceil(8);
        let mut buffer = [0u8; 16];
        if byte_width > buffer.len() || !image.read_register_into(register, &mut buffer[..byte_width]) {
            return None;
        }
        Some(
            buffer[..byte_width]
                .iter()
                .enumerate()
                .fold(0u128, |acc, (index, byte)| acc | (u128::from(*byte) << (8 * index))),
        )
    }

    /// Declared width of `register`: the shadowed type when tracked, else
    /// the image's declared register width. `None` means unknown — fall
    /// back.
    fn concrete_register_ty(&self, image: &dyn ConcolicImage, register: u32) -> Option<IrType> {
        if let Some((_, ty)) = self.registers.get(&register) {
            return Some(*ty);
        }
        let bits = image.register_width(register)?;
        Some(IrType::Bits(bits))
    }

    fn primitive_concolic(
        &mut self,
        op: IrPrimitive,
        ty: IrType,
        inputs: &[(ExprId, Option<u128>, IrType)],
    ) -> Result<(ExprId, Option<u128>), SymbolicEvalError> {
        const MAX_INLINE: usize = 4;
        let output_width = bit_width(ty)?;

        // Vector-family lane primitives: concretize-with-debt before any
        // folding — the concrete folder has no lane semantics and the flat
        // expression language has no lane ops. The result is a fresh
        // under-constrained symbol with no concrete tag, and the site lands
        // in the debt log (visible, never silent).
        if is_vector_debt_primitive(op) {
            let expression = self.fresh_symbol(output_width)?;
            self.record_debt(op, ty);
            return Ok((expression, None));
        }

        // Scalar float primitives: no FP operator exists in the expression
        // language (see [`is_float_debt_primitive`]). Exact when every
        // operand carries a concrete tag — the same decode/compute/encode
        // the concrete interpreter performs — otherwise a fresh
        // under-constrained symbol with no concrete tag.
        if is_float_debt_primitive(op) {
            if let Some(value) = exact_float_concolic(op, ty, inputs) {
                let byte_width = usize::from(output_width).div_ceil(8);
                let expression = self.constant(ty, &value.to_le_bytes()[..byte_width])?;
                return Ok((expression, Some(u128::from(value))));
            }
            let width = float_width(ty).unwrap_or(output_width);
            let expression = self.fresh_symbol(width)?;
            return Ok((expression, None));
        }

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
        // The concrete tag's carrier is u128: only register widths that fit
        // it exactly (≤128 bits) get a tag. A 512-bit zmm parent read keeps
        // its exact expression but no tag, so width normalization and the
        // concrete-first walk never treat a truncated low-128 prefix as the
        // whole register's value.
        let concrete = (byte_width <= 16).then(|| {
            bytes[..byte_width.min(16)]
                .iter()
                .enumerate()
                .fold(0u128, |acc, (index, byte)| acc | (u128::from(*byte) << (8 * index)))
        });
        self.register_concretes.insert(register, concrete);
        Ok((expression, concrete))
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
                if let Some(value) = self.memory.get(&(base.wrapping_add(offset as u64))) {
                    *slot = *value;
                }
            }
        } else {
            for (offset, slot) in bytes.iter_mut().enumerate() {
                let at = base.wrapping_add(offset as u64);
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
            // The tag carrier is u128: only loads up to 128 bits are tagged;
            // wider (256/512-bit) all-concrete loads keep the exact constant
            // expression but no truncated tag.
            let concrete = (width <= 128).then(|| {
                data.iter()
                    .enumerate()
                    .take(16)
                    .fold(0u128, |acc, (index, byte)| acc | (u128::from(*byte) << (8 * index)))
            });
            return Ok((self.constant(ty, data)?, concrete));
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
                    self.memory
                        .insert(base.wrapping_add(offset as u64), ByteValue::Concrete(*byte));
                }
                return Ok(());
            }
            return Err(SymbolicEvalError::Expression(format!("unknown expression {}", value.0)));
        }
        for offset in 0..byte_width {
            let byte_expr = self.extract(value, offset as u16 * 8, 8)?;
            self.memory
                .insert(base.wrapping_add(offset as u64), ByteValue::Symbolic(byte_expr));
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
        // Scalar floats live in the shadow as flat bitvectors of their IEEE
        // encoding width (the float primitives concretize-with-debt; see
        // [`is_float_debt_primitive`]) — no Float-sorted expression node can
        // be interned, so the flat width is the only representation.
        IrType::Float32 => Ok(32),
        IrType::Float64 => Ok(64),
        // Vectors and opmasks live in the shadow as flat bitvectors of their
        // full width (see the module-level vector representation notes on
        // [`is_vector_debt_primitive`]): lane structure only matters to the
        // lane-primitive family, which concretizes with debt instead of
        // lowering. The lane count is therefore irrelevant here.
        IrType::Vector { width_bits, .. } if width_bits > 0 => Ok(width_bits),
        IrType::Opmask { width_bits } if width_bits > 0 => Ok(width_bits),
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

/// [`get_value_c`](self) for the concrete-first walk's value table: every
/// stored slot is concrete by construction, so the expression component
/// does not exist.
fn concrete_value(values: &[Option<(u128, IrType)>], id: IrValueId) -> Option<(u128, IrType)> {
    usize::try_from(id.0)
        .ok()
        .and_then(|index| values.get(index))
        .copied()
        .flatten()
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
            let concrete_val = if let Some(node) = arena.get(byte)
                && node.op == ExprOp::Constant
                && let Some(&b) = node.immediate.first()
            {
                Some(b)
            } else {
                constant_value(arena, byte).ok().map(|v| v as u8)
            };
            if let Some(b) = concrete_val {
                bytes.push(angryier_memory::ByteValue::Concrete(b));
            } else {
                bytes.push(angryier_memory::ByteValue::Symbolic(byte));
            }
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
                    // Types must agree on the flat width — the Ite sort is
                    // derived from it and every Bits/Vector/Opmask binding
                    // lives as a flat BitVec of that width. A Bits(128)
                    // binding and a Vector{128,8} binding for the same
                    // register (movq's zero-extended write vs a whole-vector
                    // move) are the same sort and merge cleanly under the
                    // left side's type.
                    let same_width = match (bit_width(left_ty), bit_width(right_ty)) {
                        (Ok(left_width), Ok(right_width)) => left_width == right_width,
                        (Err(_), Err(_)) => left_ty == right_ty,
                        _ => false,
                    };
                    if !same_width {
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
///
/// Vectors and opmasks merge as flat bitvectors of their full width — the
/// same representation the evaluators use. [`ExprSort::Vector`] is never
/// interned: the solver FFI lowers only bitvector sorts, and an `Ite` over a
/// Vector sort would be un-lowerable at query time.
fn sort_of(ty: IrType) -> Result<ExprSort, SymbolicEvalError> {
    match ty {
        IrType::Bits(bits) => Ok(ExprSort::BitVec(bits)),
        IrType::Vector { width_bits, .. } if width_bits > 0 => Ok(ExprSort::BitVec(width_bits)),
        IrType::Opmask { width_bits } if width_bits > 0 => Ok(ExprSort::BitVec(width_bits)),
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

    // ------------------------------------------------------------------
    // Vector (flat-BitVec) shadow support
    // ------------------------------------------------------------------

    const ZMM0: u32 = 0x0100;

    fn vec_ty(width: u16, lane: u16) -> IrType {
        IrType::Vector {
            width_bits: width,
            lane_bits: lane,
        }
    }

    fn const_bytes(ty: IrType, bytes: Vec<u8>) -> IrInstruction {
        IrInstruction {
            result: None,
            op: IrOp::Constant { ty, bytes_le: bytes },
        }
    }

    fn with_result(result: u32, mut instruction: IrInstruction) -> IrInstruction {
        instruction.result = Some(IrValueId(result));
        instruction
    }

    #[test]
    fn vector_register_write_read_stays_flat() -> Result<(), SymbolicEvalError> {
        let arena = arena();
        let mut evaluator = SymbolicEvaluator::new(&arena);
        let payload: Vec<u8> = (0u8..16).collect();

        // Whole-vector move into xmm0: Constant(Vector128) -> zmm0.
        let first = block(vec![
            with_result(0, const_bytes(vec_ty(128, 8), payload.clone())),
            IrInstruction {
                result: None,
                op: IrOp::WriteRegister {
                    register: ZMM0,
                    value: IrValueId(0),
                    kind: RegisterWriteKind::ReplaceParent,
                },
            },
        ]);
        evaluator.eval_block(&first)?;

        let expr = evaluator
            .register_value(ZMM0)
            .ok_or(SymbolicEvalError::UndefinedValue(IrValueId(0)))?;
        assert_eq!(arena.sort_of(expr), Some(ExprSort::BitVec(128)));
        let node = arena.get(expr).ok_or(SymbolicEvalError::UndefinedValue(IrValueId(0)))?;
        assert_eq!(node.op, ExprOp::Constant);
        assert_eq!(node.immediate, payload, "vector constant keeps all 16 bytes");

        // Reading the xmm view of the same parent reuses the expression —
        // no fresh symbol, no re-lowering.
        let second = block(vec![
            with_result(
                0,
                IrInstruction {
                    result: None,
                    op: IrOp::ReadRegister {
                        register: ZMM0,
                        ty: vec_ty(128, 8),
                    },
                },
            ),
            IrInstruction {
                result: None,
                op: IrOp::WriteRegister {
                    register: ZMM0 + 1,
                    value: IrValueId(0),
                    kind: RegisterWriteKind::ReplaceParent,
                },
            },
        ]);
        evaluator.eval_block(&second)?;
        assert_eq!(evaluator.register_value(ZMM0 + 1), Some(expr));
        assert!(
            evaluator.symbols().is_empty(),
            "a fully concrete vector move creates no input symbols"
        );
        assert_eq!(evaluator.debt_total(), 0);
        Ok(())
    }

    #[test]
    fn vector_load_store_through_shadow_memory() -> Result<(), SymbolicEvalError> {
        let arena = arena();
        let mut evaluator = SymbolicEvaluator::new(&arena);
        let mut memory = SymbolicSessionMemory::new(
            angryier_memory::PersistentMemory::new(vec![angryier_memory::MemoryRegion {
                object: angryier_types::ObjectId(1),
                base: 0x2000,
                size: 0x2000,
                readable: true,
                writable: true,
                executable: false,
            }])
            .map_err(|e| SymbolicEvalError::UnsupportedOperation(format!("memory init: {e:?}")))?,
        );
        let payload: Vec<u8> = (0x10u8..0x20).collect();
        let concrete_bytes: Vec<angryier_memory::ByteValue> = payload
            .iter()
            .map(|byte| angryier_memory::ByteValue::Concrete(*byte))
            .collect();
        memory.write_bytes(0x2000, &concrete_bytes)?;

        // MOVDQU-shaped load: 16 bytes into xmm0 through the shadow.
        let load_block = block(vec![
            with_result(0, const_bytes(bits(64), 0x2000u64.to_le_bytes().to_vec())),
            with_result(
                1,
                IrInstruction {
                    result: None,
                    op: IrOp::Load {
                        address: IrValueId(0),
                        ty: vec_ty(128, 8),
                    },
                },
            ),
            IrInstruction {
                result: None,
                op: IrOp::WriteRegister {
                    register: ZMM0,
                    value: IrValueId(1),
                    kind: RegisterWriteKind::ReplaceParent,
                },
            },
        ]);
        evaluator.eval_block_with_memory(&load_block, &mut memory)?;

        let loaded = evaluator
            .register_value(ZMM0)
            .ok_or(SymbolicEvalError::UndefinedValue(IrValueId(1)))?;
        assert_eq!(arena.sort_of(loaded), Some(ExprSort::BitVec(128)));
        let node = arena
            .get(loaded)
            .ok_or(SymbolicEvalError::UndefinedValue(IrValueId(1)))?;
        assert_eq!(
            node.op,
            ExprOp::Constant,
            "all-concrete vector load folds to one constant"
        );
        assert_eq!(node.immediate, payload);

        // Store it back out (MOVUPS-shaped) and verify byte-exact round-trip.
        let store_block = block(vec![
            with_result(0, const_bytes(bits(64), 0x3000u64.to_le_bytes().to_vec())),
            with_result(
                1,
                IrInstruction {
                    result: None,
                    op: IrOp::ReadRegister {
                        register: ZMM0,
                        ty: vec_ty(128, 8),
                    },
                },
            ),
            IrInstruction {
                result: None,
                op: IrOp::Store {
                    address: IrValueId(0),
                    value: IrValueId(1),
                },
            },
        ]);
        evaluator.eval_block_with_memory(&store_block, &mut memory)?;
        let readback = memory.read_bytes(0x3000, 16)?;
        let moved: Option<Vec<u8>> = readback
            .iter()
            .map(|byte| match byte {
                angryier_memory::ByteValue::Concrete(value) => Some(*value),
                angryier_memory::ByteValue::Symbolic(_) => None,
            })
            .collect();
        assert_eq!(moved.as_deref(), Some(payload.as_slice()), "store must land byte-exact");

        // One symbolic source byte: the reload must stay a symbolic 128-bit
        // expression, not fold.
        let sym = symbol(&arena, 8).map_err(SymbolicEvalError::UnsupportedOperation)?;
        memory.write_bytes(0x2008, &[angryier_memory::ByteValue::Symbolic(sym)])?;
        let reload_block = block(vec![
            with_result(0, const_bytes(bits(64), 0x2000u64.to_le_bytes().to_vec())),
            with_result(
                1,
                IrInstruction {
                    result: None,
                    op: IrOp::Load {
                        address: IrValueId(0),
                        ty: vec_ty(128, 8),
                    },
                },
            ),
            IrInstruction {
                result: None,
                op: IrOp::WriteRegister {
                    register: ZMM0 + 2,
                    value: IrValueId(1),
                    kind: RegisterWriteKind::ReplaceParent,
                },
            },
        ]);
        evaluator.eval_block_with_memory(&reload_block, &mut memory)?;
        let mixed = evaluator
            .register_value(ZMM0 + 2)
            .ok_or(SymbolicEvalError::UndefinedValue(IrValueId(1)))?;
        assert_eq!(arena.sort_of(mixed), Some(ExprSort::BitVec(128)));
        assert_ne!(
            arena.op_of(mixed),
            Some(ExprOp::Constant),
            "symbolic byte must keep the load symbolic"
        );
        Ok(())
    }

    #[test]
    fn xmm_partial_write_splices_into_zmm_parent() -> Result<(), SymbolicEvalError> {
        let arena = arena();
        let mut evaluator = SymbolicEvaluator::new(&arena);

        // MOVQ-shaped write: a 64-bit value into the low half of an
        // untouched xmm — the parent is the 512-bit zmm slot and bits
        // 64..512 must be preserved (as a fresh under-constrained view).
        let first = block(vec![
            with_result(0, const_bytes(bits(64), 0x42u64.to_le_bytes().to_vec())),
            IrInstruction {
                result: None,
                op: IrOp::WriteRegister {
                    register: ZMM0 + 2,
                    value: IrValueId(0),
                    kind: RegisterWriteKind::PreserveParent {
                        bit_offset: 0,
                        width_bits: 64,
                    },
                },
            },
        ]);
        evaluator.eval_block(&first)?;

        let expr = evaluator
            .register_value(ZMM0 + 2)
            .ok_or(SymbolicEvalError::UndefinedValue(IrValueId(0)))?;
        assert_eq!(arena.sort_of(expr), Some(ExprSort::BitVec(512)));
        let node = arena.get(expr).ok_or(SymbolicEvalError::UndefinedValue(IrValueId(0)))?;
        assert_eq!(node.op, ExprOp::Concat);
        // Little-endian concat: operands[0] is the written low 64 bits,
        // operands[1] the preserved high 448 bits.
        let low = arena
            .get(node.operands[0])
            .ok_or(SymbolicEvalError::UndefinedValue(IrValueId(0)))?;
        assert_eq!(low.op, ExprOp::Constant);
        assert_eq!(low.immediate, 0x42u64.to_le_bytes().to_vec());
        let high = arena
            .get(node.operands[1])
            .ok_or(SymbolicEvalError::UndefinedValue(IrValueId(0)))?;
        assert_eq!(high.op, ExprOp::Extract);
        // Extract immediate = [start:u16 LE][width:u16 LE].
        let start = high
            .immediate
            .get(..2)
            .and_then(|b| <[u8; 2]>::try_from(b).ok())
            .map(u16::from_le_bytes);
        let width = high
            .immediate
            .get(2..4)
            .and_then(|b| <[u8; 2]>::try_from(b).ok())
            .map(u16::from_le_bytes);
        assert_eq!(start, Some(64));
        assert_eq!(width, Some(448));
        assert_eq!(high.sort, ExprSort::BitVec(448));

        // Reading the 64-bit view back folds the extract chain to the
        // written constant; reading the xmm view yields a 128-bit expression.
        let second = block(vec![
            with_result(
                0,
                IrInstruction {
                    result: None,
                    op: IrOp::ReadRegister {
                        register: ZMM0 + 2,
                        ty: bits(64),
                    },
                },
            ),
            IrInstruction {
                result: None,
                op: IrOp::WriteRegister {
                    register: 0,
                    value: IrValueId(0),
                    kind: RegisterWriteKind::ReplaceParent,
                },
            },
            with_result(
                1,
                IrInstruction {
                    result: None,
                    op: IrOp::ReadRegister {
                        register: ZMM0 + 2,
                        ty: vec_ty(128, 8),
                    },
                },
            ),
            IrInstruction {
                result: None,
                op: IrOp::WriteRegister {
                    register: ZMM0 + 3,
                    value: IrValueId(1),
                    kind: RegisterWriteKind::ReplaceParent,
                },
            },
        ]);
        evaluator.eval_block(&second)?;
        let low_view = evaluator
            .register_value(0)
            .ok_or(SymbolicEvalError::UndefinedValue(IrValueId(0)))?;
        // The 64-bit view is Extract(splice, 0, 64) — the high 448 bits are
        // a fresh symbol, so the extract cannot fold to a constant, but its
        // window and operand must be exact.
        let low_node = arena
            .get(low_view)
            .ok_or(SymbolicEvalError::UndefinedValue(IrValueId(0)))?;
        assert_eq!(low_node.op, ExprOp::Extract);
        let start = low_node
            .immediate
            .get(..2)
            .and_then(|b| <[u8; 2]>::try_from(b).ok())
            .map(u16::from_le_bytes);
        let width = low_node
            .immediate
            .get(2..4)
            .and_then(|b| <[u8; 2]>::try_from(b).ok())
            .map(u16::from_le_bytes);
        assert_eq!(start, Some(0));
        assert_eq!(width, Some(64));
        assert_eq!(low_node.operands, vec![expr]);
        let xmm_view = evaluator
            .register_value(ZMM0 + 3)
            .ok_or(SymbolicEvalError::UndefinedValue(IrValueId(1)))?;
        assert_eq!(arena.sort_of(xmm_view), Some(ExprSort::BitVec(128)));
        Ok(())
    }

    #[test]
    fn gpr_partial_write_keeps_64_bit_parent() -> Result<(), SymbolicEvalError> {
        let arena = arena();
        let mut evaluator = SymbolicEvaluator::new(&arena);
        // setcc-shaped write: one byte into al of an untracked rax — the
        // parent stays a 64-bit GPR splice.
        let first = block(vec![
            with_result(0, const_bytes(bits(8), vec![7])),
            IrInstruction {
                result: None,
                op: IrOp::WriteRegister {
                    register: 0,
                    value: IrValueId(0),
                    kind: RegisterWriteKind::PreserveParent {
                        bit_offset: 0,
                        width_bits: 8,
                    },
                },
            },
        ]);
        evaluator.eval_block(&first)?;
        let expr = evaluator
            .register_value(0)
            .ok_or(SymbolicEvalError::UndefinedValue(IrValueId(0)))?;
        assert_eq!(arena.sort_of(expr), Some(ExprSort::BitVec(64)));
        Ok(())
    }

    #[test]
    fn wide_read_ignores_u64_concrete_snapshot() -> Result<(), SymbolicEvalError> {
        let arena = arena();
        let mut evaluator = SymbolicEvaluator::new(&arena);
        evaluator.restore(&SymbolicStateSnapshot {
            concrete_registers: BTreeMap::from([(ZMM0, 0xA5A5A5A5u64)]),
            ..SymbolicStateSnapshot::default()
        });
        // A 128-bit read of a register whose snapshot value is a u64 must
        // not fabricate a zero-padded constant (the arena would reject the
        // non-canonical immediate) — it materializes an under-constrained
        // symbol instead.
        let read_block = block(vec![with_result(
            0,
            IrInstruction {
                result: None,
                op: IrOp::ReadRegister {
                    register: ZMM0,
                    ty: vec_ty(128, 8),
                },
            },
        )]);
        evaluator.eval_block(&read_block)?;
        let expr = evaluator
            .register_value(ZMM0)
            .ok_or(SymbolicEvalError::UndefinedValue(IrValueId(0)))?;
        assert_eq!(arena.op_of(expr), Some(ExprOp::Symbol));
        Ok(())
    }

    #[test]
    fn vector_lane_primitive_concretizes_with_debt() -> Result<(), SymbolicEvalError> {
        let arena = arena();
        let mut evaluator = SymbolicEvaluator::new(&arena);

        let lane_add_block = block(vec![
            with_result(0, const_bytes(vec_ty(128, 8), vec![1u8; 16])),
            with_result(1, const_bytes(vec_ty(128, 8), vec![2u8; 16])),
            with_result(
                2,
                IrInstruction {
                    result: None,
                    op: IrOp::Primitive {
                        op: IrPrimitive::VecLaneAdd,
                        ty: vec_ty(128, 8),
                        inputs: vec![IrValueId(0), IrValueId(1)],
                    },
                },
            ),
            IrInstruction {
                result: None,
                op: IrOp::WriteRegister {
                    register: ZMM0 + 4,
                    value: IrValueId(2),
                    kind: RegisterWriteKind::ReplaceParent,
                },
            },
        ]);
        evaluator.eval_block(&lane_add_block)?;

        let expr = evaluator
            .register_value(ZMM0 + 4)
            .ok_or(SymbolicEvalError::UndefinedValue(IrValueId(2)))?;
        assert_eq!(
            arena.op_of(expr),
            Some(ExprOp::Symbol),
            "lane add falls back to a fresh symbol"
        );
        assert_eq!(arena.sort_of(expr), Some(ExprSort::BitVec(128)));
        assert_eq!(evaluator.debt_total(), 1);
        assert_eq!(
            evaluator.debt_sites(),
            &[SymbolicDebtSite {
                op: IrPrimitive::VecLaneAdd,
                width_bits: 128,
                lane_bits: 8,
            }]
        );

        // A second, different primitive adds a site; repeating the first
        // only moves the total (sites dedupe, total counts every hit).
        let shuffle_block = block(vec![
            with_result(0, const_bytes(vec_ty(128, 8), vec![3u8; 16])),
            with_result(
                1,
                IrInstruction {
                    result: None,
                    op: IrOp::Primitive {
                        op: IrPrimitive::VecInterleaveLow,
                        ty: vec_ty(128, 8),
                        inputs: vec![IrValueId(0), IrValueId(0)],
                    },
                },
            ),
        ]);
        evaluator.eval_block(&shuffle_block)?;
        assert_eq!(evaluator.debt_total(), 2);
        assert_eq!(evaluator.debt_sites().len(), 2);
        evaluator.eval_block(&lane_add_block)?;
        assert_eq!(evaluator.debt_total(), 3);
        assert_eq!(evaluator.debt_sites().len(), 2);
        Ok(())
    }

    /// Minimal concrete image for the concolic vector tests: a byte-backed
    /// memory and explicit register bytes.
    struct VecImage {
        regs: BTreeMap<u32, Vec<u8>>,
        mem: BTreeMap<u64, u8>,
    }

    impl ConcolicImage for VecImage {
        fn read_register(&self, register: u32) -> Option<Vec<u8>> {
            self.regs.get(&register).cloned()
        }

        fn read_bytes(&self, address: u64, length: usize) -> Option<Vec<angryier_memory::ByteValue>> {
            let mut out = Vec::with_capacity(length);
            for offset in 0..length as u64 {
                out.push(angryier_memory::ByteValue::Concrete(
                    *self.mem.get(&(address + offset))?,
                ));
            }
            Some(out)
        }
    }

    #[test]
    fn concolic_vector_move_is_exact_and_debt_records_lane_ops() -> Result<(), SymbolicEvalError> {
        let arena = arena();
        let mut evaluator = ConcolicEvaluator::new(&arena);
        let payload: Vec<u8> = (0x30u8..0x40).collect();
        let image = VecImage {
            regs: BTreeMap::new(),
            mem: payload
                .iter()
                .enumerate()
                .map(|(index, byte)| (0x5000 + index as u64, *byte))
                .collect(),
        };

        let move_block = block(vec![
            with_result(0, const_bytes(bits(64), 0x5000u64.to_le_bytes().to_vec())),
            with_result(
                1,
                IrInstruction {
                    result: None,
                    op: IrOp::Load {
                        address: IrValueId(0),
                        ty: vec_ty(128, 8),
                    },
                },
            ),
            IrInstruction {
                result: None,
                op: IrOp::WriteRegister {
                    register: ZMM0 + 5,
                    value: IrValueId(1),
                    kind: RegisterWriteKind::ReplaceParent,
                },
            },
            with_result(2, const_bytes(bits(64), 0x6000u64.to_le_bytes().to_vec())),
            with_result(
                3,
                IrInstruction {
                    result: None,
                    op: IrOp::ReadRegister {
                        register: ZMM0 + 5,
                        ty: vec_ty(128, 8),
                    },
                },
            ),
            IrInstruction {
                result: None,
                op: IrOp::Store {
                    address: IrValueId(2),
                    value: IrValueId(3),
                },
            },
        ]);
        evaluator.eval_block(&image, &move_block)?;

        // The whole-vector move never leaves the concrete-first path: every
        // moved byte lands in the shadow memory, and the register shadow
        // keeps an exact 128-bit concrete tag.
        for (index, byte) in payload.iter().enumerate() {
            assert_eq!(
                evaluator.shadow_memory().get(&(0x6000 + index as u64)),
                Some(&angryier_memory::ByteValue::Concrete(*byte))
            );
        }
        let expected_tag = payload
            .iter()
            .enumerate()
            .fold(0u128, |acc, (index, byte)| acc | (u128::from(*byte) << (8 * index)));
        assert_eq!(
            evaluator.register_concretes().get(&(ZMM0 + 5)),
            Some(&Some(expected_tag))
        );
        assert_eq!(evaluator.debt_total(), 0);

        // A lane op on the concolic path records visible debt and yields an
        // untagged (under-constrained) shadow.
        let lane_block = block(vec![
            with_result(0, const_bytes(vec_ty(128, 8), vec![5u8; 16])),
            with_result(1, const_bytes(vec_ty(128, 8), vec![6u8; 16])),
            with_result(
                2,
                IrInstruction {
                    result: None,
                    op: IrOp::Primitive {
                        op: IrPrimitive::VecLaneMaskEq,
                        ty: vec_ty(128, 8),
                        inputs: vec![IrValueId(0), IrValueId(1)],
                    },
                },
            ),
            IrInstruction {
                result: None,
                op: IrOp::WriteRegister {
                    register: ZMM0 + 6,
                    value: IrValueId(2),
                    kind: RegisterWriteKind::ReplaceParent,
                },
            },
        ]);
        evaluator.eval_block(&image, &lane_block)?;
        assert_eq!(evaluator.debt_total(), 1);
        assert_eq!(
            evaluator.debt_sites(),
            &[SymbolicDebtSite {
                op: IrPrimitive::VecLaneMaskEq,
                width_bits: 128,
                lane_bits: 8,
            }]
        );
        assert_eq!(evaluator.register_concretes().get(&(ZMM0 + 6)), Some(&None));
        let shadowed = evaluator
            .register_value(ZMM0 + 6)
            .ok_or(SymbolicEvalError::UndefinedValue(IrValueId(2)))?;
        assert_eq!(arena.op_of(shadowed), Some(ExprOp::Symbol));
        Ok(())
    }

    #[test]
    fn merge_accepts_equal_width_vector_and_bits_bindings() -> Result<(), String> {
        // One side tracked the xmm view as a Vector type, the other as flat
        // Bits(128) — same flat width, same sort, so the merge must succeed.
        let arena = arena();
        let a = symbol(&arena, 128)?;
        // Canonical 128-bit constant: exactly 16 immediate bytes.
        let b = arena
            .intern(ExprNode {
                sort: ExprSort::BitVec(128),
                op: ExprOp::Constant,
                operands: Vec::new(),
                immediate: {
                    let mut bytes = 9u64.to_le_bytes().to_vec();
                    bytes.resize(16, 0);
                    bytes
                },
            })
            .map_err(|e| format!("{e:?}"))?;
        let parent = SymbolicStateSnapshot::default();
        let left = SymbolicStateSnapshot {
            registers: BTreeMap::from([(ZMM0, (a, vec_ty(128, 8)))]),
            concrete_registers: BTreeMap::new(),
            constraints: Vec::new(),
            symbols: Vec::new(),
            expr_concrete: BTreeMap::new(),
        };
        let right = SymbolicStateSnapshot {
            registers: BTreeMap::from([(ZMM0, (b, IrType::Bits(128)))]),
            concrete_registers: BTreeMap::new(),
            constraints: Vec::new(),
            symbols: Vec::new(),
            expr_concrete: BTreeMap::new(),
        };
        let merged = merge_snapshots(&arena, &parent, &left, &right).map_err(|e| format!("{e:?}"))?;
        let (expr, _) = *merged.registers.get(&ZMM0).ok_or("zmm0")?;
        let node = arena.get(expr).ok_or("merged node")?;
        assert_eq!(node.op, ExprOp::Ite);
        assert_eq!(node.sort, ExprSort::BitVec(128));
        Ok(())
    }

    /// The `uc_memory` policy: with the flag armed on the persistent memory
    /// under a session's byte store, unmapped reads resolve to zero bytes
    /// and unmapped writes allocate zero-backed pages — both debt-recorded
    /// in the shared ledger — instead of surfacing
    /// `UnsupportedOperation("memory read/write: Unmapped(..)")`. Flag off
    /// keeps the exact faulting behavior.
    #[test]
    fn uc_memory_session_accesses_resolve_when_armed_and_fault_when_off() -> Result<(), SymbolicEvalError> {
        let region = || angryier_memory::MemoryRegion {
            object: angryier_types::ObjectId(1),
            base: 0x2000,
            size: 0x2000,
            readable: true,
            writable: true,
            executable: false,
        };
        let armed = angryier_memory::PersistentMemory::new(vec![region()])
            .map_err(|e| SymbolicEvalError::UnsupportedOperation(format!("memory init: {e:?}")))?
            .with_uc_memory();
        let mut memory = SymbolicSessionMemory::new(armed);

        // Unmapped read: zero bytes, no fault.
        let read = memory.read_bytes(0x7000, 8)?;
        assert!(
            read.iter().all(|byte| *byte == angryier_memory::ByteValue::Concrete(0)),
            "an unmapped read under the policy returns zero bytes"
        );
        // Unmapped write: allocates the page, bytes read back.
        let payload: Vec<angryier_memory::ByteValue> = b"UCMEM"
            .iter()
            .copied()
            .map(angryier_memory::ByteValue::Concrete)
            .collect();
        memory.write_bytes(0x9000, &payload)?;
        let readback = memory.read_bytes(0x9000, 5)?;
        let moved: Option<Vec<u8>> = readback
            .iter()
            .map(|byte| match byte {
                angryier_memory::ByteValue::Concrete(value) => Some(*value),
                angryier_memory::ByteValue::Symbolic(_) => None,
            })
            .collect();
        assert_eq!(
            moved.as_deref(),
            Some(b"UCMEM".as_slice()),
            "store must land byte-exact"
        );

        // Debt is in the shared ledger, reachable through any handle.
        let inner = memory.memory.inner();
        assert!(inner.uc_memory_armed());
        assert_eq!(inner.uc_memory_total(), 3, "read + write + read-back");
        let sites = inner.uc_memory_sites();
        assert_eq!(sites.len(), 3, "read@0x7000, write@0x9000, read@0x9000");
        assert_eq!(sites[0].op, angryier_memory::UcMemoryOp::Read);
        assert_eq!(sites[0].address, 0x7000);
        assert_eq!(sites[1].op, angryier_memory::UcMemoryOp::Write);
        assert_eq!(sites[1].address, 0x9000);

        // Flag off: the same accesses fault exactly as today.
        let mut strict = SymbolicSessionMemory::new(
            angryier_memory::PersistentMemory::new(vec![region()])
                .map_err(|e| SymbolicEvalError::UnsupportedOperation(format!("memory init: {e:?}")))?,
        );
        assert!(matches!(
            strict.read_bytes(0x7000, 8),
            Err(SymbolicEvalError::UnsupportedOperation(message))
                if message.contains("memory read") && message.contains("Unmapped")
        ));
        assert!(matches!(
            strict.write_bytes(0x7000, &[angryier_memory::ByteValue::Concrete(1)]),
            Err(SymbolicEvalError::UnsupportedOperation(message))
                if message.contains("memory write") && message.contains("Unmapped")
        ));
        Ok(())
    }

    // --- Read-only-write relaxation through the session store -------------

    fn ro_region() -> angryier_memory::MemoryRegion {
        angryier_memory::MemoryRegion {
            object: angryier_types::ObjectId(1),
            base: 0x1404d0000,
            size: 0x2000,
            readable: true,
            writable: false,
            executable: false,
        }
    }

    #[test]
    fn uc_write_ro_relaxes_through_the_session_store() -> Result<(), SymbolicEvalError> {
        let memory = angryier_memory::PersistentMemory::new(vec![ro_region()])
            .map_err(|e| SymbolicEvalError::UnsupportedOperation(format!("memory init: {e:?}")))?;
        let mut armed = SymbolicSessionMemory::new(memory.with_uc_memory().with_uc_write_ro(true));
        armed.write_bytes(0x1404d0018, &[angryier_memory::ByteValue::Concrete(0xaa); 4])?;
        let inner = armed.memory.inner();
        assert_eq!(inner.uc_memory_ro_write_total(), 1);
        assert_eq!(inner.uc_memory_sites()[0].op, angryier_memory::UcMemoryOp::WriteRO);
        assert_eq!(
            armed.read_bytes(0x1404d0018, 4)?,
            vec![angryier_memory::ByteValue::Concrete(0xaa); 4]
        );
        Ok(())
    }

    #[test]
    fn uc_write_ro_off_still_denies_through_the_session_store() -> Result<(), SymbolicEvalError> {
        let memory = angryier_memory::PersistentMemory::new(vec![ro_region()])
            .map_err(|e| SymbolicEvalError::UnsupportedOperation(format!("memory init: {e:?}")))?;
        let mut armed = SymbolicSessionMemory::new(memory.with_uc_memory());
        let error = match armed.write_bytes(0x1404d0018, &[angryier_memory::ByteValue::Concrete(0xaa)]) {
            Ok(()) => {
                return Err(SymbolicEvalError::UnsupportedOperation(
                    "uc_write_ro=false unexpectedly allowed a write to read-only memory".into(),
                ));
            }
            Err(error) => error,
        };
        assert!(error.to_string().contains("PermissionDenied"));
        Ok(())
    }

    // --- Bit-precise Popcnt / Clz / Ctz / Crc32 ---------------------------

    /// The test sink register every block below writes its result to.
    const SINK: u32 = 0x7f;

    /// Ends a block by writing value slot `slot` into the sink register —
    /// the evaluator's public surface exposes computed values through the
    /// register file, not the block-local value table.
    fn write_sink(slot: u8) -> IrInstruction {
        IrInstruction {
            result: None,
            op: IrOp::WriteRegister {
                register: SINK,
                value: IrValueId(u32::from(slot)),
                kind: angryier_ir::RegisterWriteKind::ReplaceParent,
            },
        }
    }

    /// A one-input primitive block: Constant (or symbolic register) input,
    /// one primitive, result written to the sink register.
    fn bitcount_block(op: IrPrimitive, ty: IrType, input: IrOp) -> IrBlock {
        block(vec![
            IrInstruction {
                result: Some(IrValueId(0)),
                op: input,
            },
            IrInstruction {
                result: Some(IrValueId(1)),
                op: IrOp::Primitive {
                    op,
                    ty,
                    inputs: vec![IrValueId(0)],
                },
            },
            write_sink(1),
        ])
    }

    fn const_op(ty: IrType, value: u64) -> IrOp {
        let width = match ty {
            IrType::Bits(bits) => bits,
            IrType::Float32 => 32,
            IrType::Float64 => 64,
            _ => 0,
        };
        let byte_width = usize::from(width).div_ceil(8);
        IrOp::Constant {
            ty,
            bytes_le: value.to_le_bytes()[..byte_width].to_vec(),
        }
    }

    fn mask64(width: u16) -> u64 {
        if width >= 64 { u64::MAX } else { (1u64 << width) - 1 }
    }

    #[test]
    fn popcnt_concrete_inputs_round_trip_against_concrete_semantics() -> Result<(), SymbolicEvalError> {
        let arena = arena();
        for width in [8u16, 16, 32, 64] {
            for value in [0u64, 1, 0x0f, 0x55, 0x8000_0000_0000_0000, u64::MAX] {
                let masked = value & mask64(width);
                let mut evaluator = SymbolicEvaluator::new(&arena);
                evaluator.eval_block(&bitcount_block(
                    IrPrimitive::Popcnt,
                    bits(width),
                    const_op(bits(width), masked),
                ))?;
                let expression = evaluator
                    .register_value(SINK)
                    .ok_or(SymbolicEvalError::UndefinedValue(IrValueId(1)))?;
                let folded = constant_value(&arena, expression)
                    .map_err(|e| SymbolicEvalError::UnsupportedOperation(format!("popcnt did not fold: {e:?}")))?;
                assert_eq!(
                    folded as u32,
                    masked.count_ones(),
                    "popcnt {masked:#x} at width {width}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn clz_ctz_concrete_inputs_round_trip_against_concrete_semantics() -> Result<(), SymbolicEvalError> {
        let arena = arena();
        for width in [8u16, 16, 32, 64] {
            for value in [0u64, 1, 0x8000, 0x8000_0000_0000_0000, u64::MAX] {
                let masked = value & mask64(width);
                // Clz: the interpreter takes leading_zeros over the full
                // u128 carrier (whose upper half is always zero for these
                // widths) and subtracts the unused head — equivalently the
                // u64 leading_zeros shifted by the width gap.
                let expected_clz = if masked == 0 {
                    u32::from(width)
                } else {
                    masked.leading_zeros() - (64 - u32::from(width))
                };
                let expected_ctz = if masked == 0 {
                    u32::from(width)
                } else {
                    masked.trailing_zeros()
                };
                for (op, expected) in [(IrPrimitive::Clz, expected_clz), (IrPrimitive::Ctz, expected_ctz)] {
                    let mut evaluator = SymbolicEvaluator::new(&arena);
                    evaluator.eval_block(&bitcount_block(op, bits(width), const_op(bits(width), masked)))?;
                    let expression = evaluator
                        .register_value(SINK)
                        .ok_or(SymbolicEvalError::UndefinedValue(IrValueId(1)))?;
                    let folded = constant_value(&arena, expression)
                        .map_err(|e| SymbolicEvalError::UnsupportedOperation(format!("{op:?} did not fold: {e:?}")))?;
                    assert_eq!(folded as u32, expected, "{op:?} {masked:#x} at width {width}");
                }
            }
        }
        Ok(())
    }

    #[test]
    fn popcnt_clz_ctz_symbolic_inputs_stay_symbolic() -> Result<(), SymbolicEvalError> {
        let arena = arena();
        for op in [IrPrimitive::Popcnt, IrPrimitive::Clz, IrPrimitive::Ctz] {
            let mut evaluator = SymbolicEvaluator::new(&arena);
            evaluator.eval_block(&bitcount_block(
                op,
                bits(64),
                IrOp::ReadRegister {
                    register: 7,
                    ty: bits(64),
                },
            ))?;
            let expression = evaluator
                .register_value(SINK)
                .ok_or(SymbolicEvalError::UndefinedValue(IrValueId(1)))?;
            let node = arena
                .get(expression)
                .ok_or(SymbolicEvalError::UndefinedValue(IrValueId(1)))?;
            assert!(
                node.op != ExprOp::Constant,
                "{op:?} over a symbolic input must stay symbolic, got {node:?}"
            );
            // The lowering only uses well-sorted bitvector nodes.
            assert!(matches!(node.sort, ExprSort::BitVec(64)));
        }
        Ok(())
    }

    #[test]
    fn crc32_concrete_inputs_match_the_bitwise_reference() -> Result<(), SymbolicEvalError> {
        let arena = arena();
        // The concrete interpreter's bitwise CRC-32C reference.
        fn reference(crc: u32, data: u64, byte_count: usize) -> u32 {
            let mut crc = crc;
            for byte_idx in 0..byte_count {
                let byte = ((data >> (byte_idx * 8)) & 0xFF) as u8;
                crc ^= u32::from(byte);
                for _ in 0..8 {
                    crc = if crc & 1 != 0 {
                        (crc >> 1) ^ 0x82F63B78
                    } else {
                        crc >> 1
                    };
                }
            }
            crc
        }
        for (data_bits, byte_count) in [(8u16, 1usize), (16, 2), (32, 4), (64, 8)] {
            for (crc_in, data) in [
                (0u64, 0u64),
                (0xFFFF_FFFF, u64::MAX),
                (0x1234_5678, 0x0102_0304_0506_0708),
                (42, 0x80),
            ] {
                let mut evaluator = SymbolicEvaluator::new(&arena);
                evaluator.eval_block(&block(vec![
                    IrInstruction {
                        result: Some(IrValueId(0)),
                        op: const_op(bits(32), crc_in),
                    },
                    IrInstruction {
                        result: Some(IrValueId(1)),
                        op: const_op(bits(data_bits), data & mask64(data_bits)),
                    },
                    IrInstruction {
                        result: Some(IrValueId(2)),
                        op: IrOp::Primitive {
                            op: IrPrimitive::Crc32,
                            ty: bits(32),
                            inputs: vec![IrValueId(0), IrValueId(1)],
                        },
                    },
                    write_sink(2),
                ]))?;
                let expression = evaluator
                    .register_value(SINK)
                    .ok_or(SymbolicEvalError::UndefinedValue(IrValueId(2)))?;
                let folded = constant_value(&arena, expression)
                    .map_err(|e| SymbolicEvalError::UnsupportedOperation(format!("crc32 did not fold: {e:?}")))?;
                assert_eq!(
                    folded as u32,
                    reference(crc_in as u32, data & mask64(data_bits), byte_count),
                    "crc32 crc={crc_in:#x} data={data:#x} width={data_bits}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn crc32_symbolic_input_stays_symbolic() -> Result<(), SymbolicEvalError> {
        let arena = arena();
        let mut evaluator = SymbolicEvaluator::new(&arena);
        evaluator.eval_block(&block(vec![
            IrInstruction {
                result: Some(IrValueId(0)),
                op: IrOp::ReadRegister {
                    register: 1,
                    ty: bits(32),
                },
            },
            IrInstruction {
                result: Some(IrValueId(1)),
                op: IrOp::ReadRegister {
                    register: 2,
                    ty: bits(64),
                },
            },
            IrInstruction {
                result: Some(IrValueId(2)),
                op: IrOp::Primitive {
                    op: IrPrimitive::Crc32,
                    ty: bits(32),
                    inputs: vec![IrValueId(0), IrValueId(1)],
                },
            },
            write_sink(2),
        ]))?;
        let expression = evaluator
            .register_value(SINK)
            .ok_or(SymbolicEvalError::UndefinedValue(IrValueId(2)))?;
        let node = arena
            .get(expression)
            .ok_or(SymbolicEvalError::UndefinedValue(IrValueId(2)))?;
        assert!(
            node.op != ExprOp::Constant,
            "crc32 over symbolic input must stay symbolic"
        );
        assert!(matches!(node.sort, ExprSort::BitVec(32)));
        Ok(())
    }

    // --- Float primitives --------------------------------------------------

    #[test]
    fn float_concrete_operands_compute_exact_results() -> Result<(), SymbolicEvalError> {
        let arena = arena();
        // 1.5 + 2.25 = 3.75, encoded as a Float64 bit pattern.
        let mut evaluator = SymbolicEvaluator::new(&arena);
        evaluator.eval_block(&block(vec![
            IrInstruction {
                result: Some(IrValueId(0)),
                op: const_op(IrType::Float64, (1.5f64).to_bits()),
            },
            IrInstruction {
                result: Some(IrValueId(1)),
                op: const_op(IrType::Float64, (2.25f64).to_bits()),
            },
            IrInstruction {
                result: Some(IrValueId(2)),
                op: IrOp::Primitive {
                    op: IrPrimitive::FAdd,
                    ty: IrType::Float64,
                    inputs: vec![IrValueId(0), IrValueId(1)],
                },
            },
            write_sink(2),
        ]))?;
        let expression = evaluator
            .register_value(SINK)
            .ok_or(SymbolicEvalError::UndefinedValue(IrValueId(2)))?;
        let folded = constant_value(&arena, expression)
            .map_err(|e| SymbolicEvalError::UnsupportedOperation(format!("fadd did not fold: {e:?}")))?;
        assert_eq!(f64::from_bits(folded), 3.75);

        // FDiv over Float32: mirrored through f32 rounding.
        let mut evaluator = SymbolicEvaluator::new(&arena);
        evaluator.eval_block(&block(vec![
            IrInstruction {
                result: Some(IrValueId(0)),
                op: const_op(IrType::Float32, u64::from(1.0f32.to_bits())),
            },
            IrInstruction {
                result: Some(IrValueId(1)),
                op: const_op(IrType::Float32, u64::from(3.0f32.to_bits())),
            },
            IrInstruction {
                result: Some(IrValueId(2)),
                op: IrOp::Primitive {
                    op: IrPrimitive::FDiv,
                    ty: IrType::Float32,
                    inputs: vec![IrValueId(0), IrValueId(1)],
                },
            },
            write_sink(2),
        ]))?;
        let expression = evaluator
            .register_value(SINK)
            .ok_or(SymbolicEvalError::UndefinedValue(IrValueId(2)))?;
        let folded = constant_value(&arena, expression)
            .map_err(|e| SymbolicEvalError::UnsupportedOperation(format!("fdiv did not fold: {e:?}")))?;
        assert_eq!(f32::from_bits(folded as u32), 1.0f32 / 3.0f32);
        Ok(())
    }

    #[test]
    fn fcompare_flags_concrete_operands_mirror_rflags_layout() -> Result<(), SymbolicEvalError> {
        let arena = arena();
        // (left, right, expected flags) — CF=0/PF=2/ZF=6, NaN unordered
        // triple, exactly the concrete interpreter's encoding.
        let cases: &[(f64, f64, u64)] = &[
            (1.0, 2.0, 1u64 << 0),                           // below → CF
            (2.0, 1.0, 0),                                   // above → none
            (2.0, 2.0, 1u64 << 6),                           // equal → ZF
            (f64::NAN, 1.0, (1 << 6) | (1 << 2) | (1 << 0)), // unordered
        ];
        for (left, right, expected) in cases {
            let mut evaluator = SymbolicEvaluator::new(&arena);
            evaluator.eval_block(&block(vec![
                IrInstruction {
                    result: Some(IrValueId(0)),
                    op: const_op(IrType::Float64, left.to_bits()),
                },
                IrInstruction {
                    result: Some(IrValueId(1)),
                    op: const_op(IrType::Float64, right.to_bits()),
                },
                IrInstruction {
                    result: Some(IrValueId(2)),
                    op: IrOp::Primitive {
                        op: IrPrimitive::FCompareFlags,
                        ty: bits(64),
                        inputs: vec![IrValueId(0), IrValueId(1)],
                    },
                },
                write_sink(2),
            ]))?;
            let expression = evaluator
                .register_value(SINK)
                .ok_or(SymbolicEvalError::UndefinedValue(IrValueId(2)))?;
            let folded = constant_value(&arena, expression)
                .map_err(|e| SymbolicEvalError::UnsupportedOperation(format!("compare did not fold: {e:?}")))?;
            assert_eq!(folded, *expected, "compare {left} vs {right}");
            // No debt: the compare was exact.
            assert_eq!(evaluator.debt_total(), 0);
        }
        Ok(())
    }

    #[test]
    fn float_symbolic_operands_concretize_with_debt() -> Result<(), SymbolicEvalError> {
        let arena = arena();
        for op in [
            IrPrimitive::FAdd,
            IrPrimitive::FSub,
            IrPrimitive::FMul,
            IrPrimitive::FDiv,
            IrPrimitive::FCompareFlags,
        ] {
            let mut evaluator = SymbolicEvaluator::new(&arena);
            evaluator.eval_block(&block(vec![
                IrInstruction {
                    result: Some(IrValueId(0)),
                    op: IrOp::ReadRegister {
                        register: 1,
                        ty: IrType::Float64,
                    },
                },
                IrInstruction {
                    result: Some(IrValueId(1)),
                    op: const_op(IrType::Float64, (2.0f64).to_bits()),
                },
                IrInstruction {
                    result: Some(IrValueId(2)),
                    op: IrOp::Primitive {
                        op,
                        ty: if op == IrPrimitive::FCompareFlags {
                            bits(64)
                        } else {
                            IrType::Float64
                        },
                        inputs: vec![IrValueId(0), IrValueId(1)],
                    },
                },
                write_sink(2),
            ]))?;
            let expression = evaluator
                .register_value(SINK)
                .ok_or(SymbolicEvalError::UndefinedValue(IrValueId(2)))?;
            let node = arena
                .get(expression)
                .ok_or(SymbolicEvalError::UndefinedValue(IrValueId(2)))?;
            assert!(
                node.op != ExprOp::Constant,
                "{op:?} over a symbolic operand must concretize with debt, got {node:?}"
            );
            assert_eq!(evaluator.debt_total(), 1, "{op:?} must record its debt site");
            assert_eq!(evaluator.debt_sites().len(), 1);
        }
        Ok(())
    }

    // --- Concretization retry pinning mechanics ---------------------------

    /// A block that reads an UNBOUND register (no symbolic binding, no
    /// concrete value) — the read materializes a fresh under-constrained
    /// symbol — and returns it through the sink register.
    fn fresh_symbol_block(register: u32) -> IrBlock {
        block(vec![
            IrInstruction {
                result: Some(IrValueId(0)),
                op: IrOp::ReadRegister { register, ty: bits(64) },
            },
            write_sink(0),
        ])
    }

    /// The runtime retry loop restores the evaluator from the state's
    /// PRE-EVAL bindings (register writes commit only after a clean eval),
    /// so the retry re-sees an unbound register and materializes a fresh
    /// symbol again. This helper mirrors exactly that: pristine snapshot
    /// first, eval, restore, re-eval.
    fn retry_passes(
        evaluator: &mut SymbolicEvaluator,
        arena: &ShardedExprArena,
    ) -> Result<(Option<ExprId>, Option<ExprId>), SymbolicEvalError> {
        let pristine = evaluator.snapshot();
        let _ = arena;
        evaluator.eval_block(&fresh_symbol_block(0x30))?;
        let first = evaluator.register_value(SINK);
        evaluator.restore(&pristine);
        evaluator.eval_block(&fresh_symbol_block(0x30))?;
        let second = evaluator.register_value(SINK);
        Ok((first, second))
    }

    #[test]
    fn block_local_symbols_rebuild_identical_exprs_across_re_evaluations() -> Result<(), SymbolicEvalError> {
        let arena = arena();
        let mut evaluator = SymbolicEvaluator::new(&arena).with_block_local_symbols();
        let (first, second) = retry_passes(&mut evaluator, &arena)?;
        assert_eq!(
            first, second,
            "retry re-evaluation must rebuild byte-identical expressions so a pin keyed by ExprId hits"
        );
        Ok(())
    }

    #[test]
    fn monotonic_symbols_rematerialize_new_exprs_per_re_evaluation() -> Result<(), SymbolicEvalError> {
        // The pre-fix behavior, kept as a documented regression guard: with
        // a monotonically advancing counter across re-evaluations, every
        // retry rebuilds the fresh symbol under a NEW ExprId — the original
        // root cause that made the old 4-retry budget unable to converge.
        let arena = arena();
        let mut evaluator = SymbolicEvaluator::new(&arena);
        let (first, second) = retry_passes(&mut evaluator, &arena)?;
        assert_ne!(first, second, "monotonic ids must change across re-evaluations");
        Ok(())
    }

    /// Reproduces the runtime retry loop's pin-and-rerun mechanics: a block
    /// whose LOAD address depends on a fresh symbol fails UnresolvedAddress
    /// on the first pass, and — with block-local symbols — converges once
    /// the failing address expression is pinned in `expr_concrete`.
    #[test]
    fn pinned_address_converges_across_block_local_re_evaluations() -> Result<(), SymbolicEvalError> {
        use angryier_memory::{ByteValue, PersistentMemory};
        let arena = arena();
        let inner = PersistentMemory::new(vec![angryier_memory::MemoryRegion {
            object: angryier_types::ObjectId(1),
            base: 0x10000,
            size: 0x1000,
            readable: true,
            writable: true,
            executable: false,
        }])
        .map_err(|e| SymbolicEvalError::UnsupportedOperation(format!("memory init: {e:?}")))?;
        let mut memory = SymbolicSessionMemory::new(inner);
        memory.write_bytes(0x10420, &[ByteValue::Concrete(0xab)])?;

        // The address is `fresh_symbol + 0x420`: unresolved while the fresh
        // symbol has no concrete value.
        let load_block = block(vec![
            IrInstruction {
                result: Some(IrValueId(0)),
                op: IrOp::ReadRegister {
                    register: 0x30,
                    ty: bits(64),
                },
            },
            IrInstruction {
                result: Some(IrValueId(1)),
                op: IrOp::Constant {
                    ty: bits(64),
                    bytes_le: 0x420u64.to_le_bytes().to_vec(),
                },
            },
            IrInstruction {
                result: Some(IrValueId(2)),
                op: IrOp::Primitive {
                    op: IrPrimitive::Add,
                    ty: bits(64),
                    inputs: vec![IrValueId(0), IrValueId(1)],
                },
            },
            IrInstruction {
                result: Some(IrValueId(3)),
                op: IrOp::Load {
                    address: IrValueId(2),
                    ty: bits(8),
                },
            },
            write_sink(3),
        ]);

        let mut evaluator = SymbolicEvaluator::new(&arena).with_block_local_symbols();
        // Pristine pre-eval bindings (what the retry loop restores).
        let pristine = evaluator.snapshot();
        // Pass 1: the address can't resolve.
        let first = evaluator.eval_block_with_memory(&load_block, &mut memory);
        let expr = match first {
            Err(SymbolicEvalError::UnresolvedAddress(expr)) => expr,
            other => {
                return Err(SymbolicEvalError::UnsupportedOperation(format!(
                    "expected UnresolvedAddress on pass 1, got {other:?}"
                )));
            }
        };
        // The retry: restore the pristine bindings, pin the failing
        // expression to the mapped address, and re-run — the SAME ExprId
        // must rebuild (block-local symbols), so the pin resolves the load.
        let mut restored = pristine.clone();
        restored.expr_concrete.insert(expr, 0x10420);
        evaluator.restore(&restored);
        let second = evaluator.eval_block_with_memory(&load_block, &mut memory);
        assert!(second.is_ok(), "pinned re-evaluation must converge, got {second:?}");
        let expression = evaluator
            .register_value(SINK)
            .ok_or(SymbolicEvalError::UndefinedValue(IrValueId(3)))?;
        let folded = constant_value(&arena, expression)
            .map_err(|e| SymbolicEvalError::UnsupportedOperation(format!("load did not fold: {e:?}")))?;
        assert_eq!(folded, 0xab);
        Ok(())
    }
}
