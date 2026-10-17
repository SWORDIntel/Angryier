//! Opaque predicate and junk-code detection and pruning for Angryier CFGs.
//!
//! Provides static algebraic invariant evaluation, context register invariance,
//! overlapping junk-instruction neutralization, and dead branch elimination
//! with basic block straightening.
//!
//! # Invariants Evaluated
//! - Algebraic parity tautology: `(x * (x + 1)) % 2 == 0`
//! - Domain / square invariant: `x^2 >= 0` (and unsigned bounds `u >= 0`)
//! - Bitwise relationship: `(x | y) >= (x & y)`
//! - Identity invariant: `(x ^ y) == 0 <=> x == y`
//! - MBA and double-negation simplifications via `angryier_expr::deobf`
//! - Overlapping junk sequences (`0xE8` or `0xEB 0xFF` mid-instruction overlaps)
//! - Context invariants (identical context registers / constants)

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use angryier_arch::{DecodedInstruction, MemoryBase, MemoryOperand, OperandKind, RegisterId};
use angryier_expr::deobf::deobfuscate;
use angryier_expr::{ExprArena, ExprNode, ExprOp, ExprSort, ShardedExprArena};
use angryier_semantics_intel64::forms;
use angryier_types::{Address, ExprId, ExpressionNormalizationVersion};

use crate::{BasicBlock, Cfg, CfgEdge, EdgeKind};

/// Type alias for the recovered CFG.
pub type ControlFlowGraph = Cfg;

/// Flavor of detected opaque predicate or junk-code sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OpaquePredicateKind {
    /// Branch condition algebraically proven == 1 (always taken).
    TautologyAlwaysTrue,
    /// Branch condition algebraically proven == 0 (never taken).
    TautologyAlwaysFalse,
    /// `0xE8` or `0xEB 0xFF` mid-instruction overlapping call/jump.
    OverlappingJunkInstruction,
    /// Comparison between two context registers known to be identical or constant.
    ContextInvariant,
}

/// A detected opaque predicate candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DetectedOpaquePredicate {
    /// Address of the branch or junk instruction.
    pub address: Address,
    /// Starting address of the containing basic block.
    pub block_start: Address,
    /// Detected flavor.
    pub kind: OpaquePredicateKind,
    /// Descriptive explanation of the algebraic identity or pattern detected.
    pub description: String,
}

/// Actions performed by the pruner to transform the CFG.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PruningAction {
    /// Replaces conditional jump with unconditional jump or removes edge from CFG.
    EliminateDeadBranch {
        branch_address: Address,
        retained_target: Address,
        removed_target: Address,
        kind: OpaquePredicateKind,
    },
    /// Merges predecessor and successor when dead branch is removed.
    StraightenBlocks {
        predecessor: Address,
        successor: Address,
    },
    /// Replaces the overlapping prefix with NOPs or direct fallthrough.
    NeutralizeJunkOverlap {
        address: Address,
        target: Address,
        length: usize,
    },
}

/// Resource and iteration limits for pruning passes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PruningLimits {
    /// Maximum fixpoint passes over the CFG.
    pub max_passes: usize,
    /// Maximum number of instructions inspected across all passes.
    pub max_instructions_scanned: usize,
    /// Maximum number of basic block pairs to straighten.
    pub max_blocks_straightened: usize,
}

impl Default for PruningLimits {
    fn default() -> Self {
        Self {
            max_passes: 32,
            max_instructions_scanned: 100_000,
            max_blocks_straightened: 10_000,
        }
    }
}

/// Summary report of the opaque predicate detection and pruning pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PruningReport {
    /// Number of dead branch edges eliminated.
    pub eliminated_branches: usize,
    /// Number of basic block pairs merged.
    pub straightened_blocks: usize,
    /// Number of overlapping junk sequences neutralized.
    pub neutralized_junk: usize,
    /// All detected opaque predicates and junk patterns.
    pub detected: Vec<DetectedOpaquePredicate>,
    /// Exact sequence of transformations applied.
    pub actions: Vec<PruningAction>,
}

/// Abstract representation of register state and symbolic provenance in a basic block.
#[derive(Clone, Debug, PartialEq, Eq)]
enum SymbolicValue {
    /// Concrete known constant value.
    Constant(u64),
    /// A value from a context register (e.g. Themida VM_CONTEXT or caller state).
    ContextRegister { reg: RegisterId, offset: Option<i64> },
    /// Value derived as an integer offset from a base register.
    OffsetFrom { base: RegisterId, offset: i64 },
    /// Parity product: x * (x + 1) or x * (x - 1), algebraically even (value % 2 == 0).
    ParityEven { source: RegisterId },
    /// Value is a square: x * x >= 0.
    Square { source: RegisterId },
    /// Bitwise OR expression: (x | y).
    BitwiseOr { op1: RegisterId, op2: RegisterId },
    /// Bitwise AND expression: (x & y).
    BitwiseAnd { op1: RegisterId, op2: RegisterId },
}

/// Record of the last instruction that modified processor flags.
#[derive(Clone, Debug, PartialEq, Eq)]
enum FlagsSetter {
    TestRegImm { op: RegisterId, imm: u64 },
    TestRegReg { op1: RegisterId, op2: RegisterId },
    CmpRegReg { op1: RegisterId, op2: RegisterId },
    CmpRegImm { op: RegisterId, imm: u64 },
    SubRegReg { dst: RegisterId, src: RegisterId },
}

/// Detector for opaque predicates and junk instructions.
#[derive(Clone, Debug, Default)]
pub struct OpaquePredicateDetector;

impl OpaquePredicateDetector {
    /// Creates a new detector instance.
    pub fn new() -> Self {
        Self
    }

    /// Detects if the conditional terminator of `block` is an opaque predicate.
    pub fn detect_block(&self, block: &BasicBlock) -> Option<DetectedOpaquePredicate> {
        if block.terminator != EdgeKind::ConditionalTaken {
            return None;
        }
        let branch_insn = block.instructions.last()?;
        if !is_conditional_branch(branch_insn.form_id) {
            return None;
        }

        let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
        let mut registers: BTreeMap<RegisterId, SymbolicValue> = BTreeMap::new();
        let mut expr_map: BTreeMap<RegisterId, ExprId> = BTreeMap::new();
        let mut next_symbol = 1u64;
        let mut last_flags: Option<FlagsSetter> = None;

        // Bounded forward pass over block instructions preceding the branch
        for insn in &block.instructions[..block.instructions.len().saturating_sub(1)] {
            self.track_instruction(
                insn,
                &arena,
                &mut registers,
                &mut expr_map,
                &mut next_symbol,
                &mut last_flags,
            );
        }

        let flags_setter = last_flags?;
        self.evaluate_condition(
            branch_insn,
            &flags_setter,
            &registers,
            &arena,
            &mut expr_map,
            &mut next_symbol,
            block.start,
        )
    }

    /// Detects overlapping junk instruction patterns in `block`.
    pub fn detect_overlapping_junk(&self, block: &BasicBlock) -> Option<DetectedOpaquePredicate> {
        for insn in &block.instructions {
            if let Some(target) = static_target(insn) {
                // Target lands at pc + 1 into self (e.g., 0xEB 0xFF jumping to pc + 1)
                let pc_plus_1 = insn.address.wrapping_add(1);
                let pc_plus_2 = insn.address.wrapping_add(2);
                let pc_over_junk_1 = insn.address.wrapping_add(u64::from(insn.length)).wrapping_add(1);
                let pc_over_junk_2 = insn.address.wrapping_add(u64::from(insn.length)).wrapping_add(2);

                let is_overlap = target == pc_plus_1
                    || target == pc_plus_2
                    || target == pc_over_junk_1
                    || target == pc_over_junk_2;

                if is_overlap {
                    return Some(DetectedOpaquePredicate {
                        address: insn.address,
                        block_start: block.start,
                        kind: OpaquePredicateKind::OverlappingJunkInstruction,
                        description: format!(
                            "Overlapping junk jump/call at {:#x} landing at {:#x} (offset {})",
                            insn.address, target, target.wrapping_sub(insn.address)
                        ),
                    });
                }
            }
        }
        None
    }

    /// Scans an entire CFG for all opaque predicates and overlapping junk sequences.
    pub fn scan_cfg(&self, cfg: &Cfg) -> Vec<DetectedOpaquePredicate> {
        let mut detected = Vec::new();
        for block in cfg.blocks.values() {
            if let Some(pred) = self.detect_block(block) {
                detected.push(pred);
            }
            if let Some(junk) = self.detect_overlapping_junk(block) {
                detected.push(junk);
            }
        }
        detected
    }

    fn track_instruction(
        &self,
        insn: &DecodedInstruction,
        arena: &ShardedExprArena,
        registers: &mut BTreeMap<RegisterId, SymbolicValue>,
        expr_map: &mut BTreeMap<RegisterId, ExprId>,
        next_symbol: &mut u64,
        last_flags: &mut Option<FlagsSetter>,
    ) {
        let form_id = insn.form_id;

        // 1. MOV reg, imm
        if is_mov_imm(form_id) {
            if let (Some(dst), Some(imm)) = (reg_operand(insn, 0), imm_operand(insn, 1)) {
                registers.insert(dst, SymbolicValue::Constant(imm));
                if let Ok(k) = constant_node(arena, u128::from(imm), 64) {
                    expr_map.insert(dst, k);
                }
            }
            return;
        }

        // 2. MOV reg, reg
        if is_mov(form_id) {
            if let (Some(dst), Some(src)) = (reg_operand(insn, 0), reg_operand(insn, 1)) {
                let base_src = base_register(registers, src);
                let val = match registers.get(&src) {
                    Some(v) => v.clone(),
                    None => SymbolicValue::OffsetFrom { base: base_src, offset: 0 },
                };
                registers.insert(dst, val);
                let e = get_or_create_expr(arena, expr_map, src, next_symbol);
                expr_map.insert(dst, e);
            }
            return;
        }

        // 3. MOV reg, [base + disp] (Context load candidate)
        if is_mov_load(form_id) {
            if let (Some(dst), Some(mem)) = (reg_operand(insn, 0), mem_operand(insn, 1))
                && let Some(MemoryBase::Register(base_view)) = mem.base
                    && mem.index.is_none() {
                        registers.insert(
                            dst,
                            SymbolicValue::ContextRegister {
                                reg: base_view.parent,
                                offset: Some(mem.displacement),
                            },
                        );
                    }
            return;
        }

        // 4. ADD reg, imm / INC
        if is_inc(form_id) {
            if let Some(dst) = reg_operand(insn, 0) {
                let base_dst = base_register(registers, dst);
                let base = match registers.get(&dst) {
                    Some(SymbolicValue::OffsetFrom { base, offset }) => (*base, offset.saturating_add(1)),
                    _ => (base_dst, 1),
                };
                registers.insert(dst, SymbolicValue::OffsetFrom { base: base.0, offset: base.1 });
                let e = get_or_create_expr(arena, expr_map, dst, next_symbol);
                if let Ok(one) = constant_node(arena, 1, 64)
                    && let Ok(add) = binary_node(arena, ExprOp::Add, e, one, 64) {
                        expr_map.insert(dst, add);
                    }
            }
            return;
        }

        if is_add(form_id) {
            if let (Some(dst), Some(imm)) = (reg_operand(insn, 0), imm_operand(insn, 1)) {
                let imm_i64 = imm as i64;
                let base_dst = base_register(registers, dst);
                let base = match registers.get(&dst) {
                    Some(SymbolicValue::OffsetFrom { base, offset }) => {
                        (*base, offset.saturating_add(imm_i64))
                    }
                    _ => (base_dst, imm_i64),
                };
                registers.insert(dst, SymbolicValue::OffsetFrom { base: base.0, offset: base.1 });
                let e = get_or_create_expr(arena, expr_map, dst, next_symbol);
                if let Ok(k) = constant_node(arena, u128::from(imm), 64)
                    && let Ok(add) = binary_node(arena, ExprOp::Add, e, k, 64) {
                        expr_map.insert(dst, add);
                    }
            } else if let (Some(dst), Some(src)) = (reg_operand(insn, 0), reg_operand(insn, 1)) {
                let e_dst = get_or_create_expr(arena, expr_map, dst, next_symbol);
                let e_src = get_or_create_expr(arena, expr_map, src, next_symbol);
                if let Ok(add) = binary_node(arena, ExprOp::Add, e_dst, e_src, 64) {
                    expr_map.insert(dst, add);
                }
            }
            return;
        }

        // 5. SUB reg, imm / DEC
        if is_dec(form_id) {
            if let Some(dst) = reg_operand(insn, 0) {
                let base_dst = base_register(registers, dst);
                let base = match registers.get(&dst) {
                    Some(SymbolicValue::OffsetFrom { base, offset }) => (*base, offset.saturating_sub(1)),
                    _ => (base_dst, -1),
                };
                registers.insert(dst, SymbolicValue::OffsetFrom { base: base.0, offset: base.1 });
                let e = get_or_create_expr(arena, expr_map, dst, next_symbol);
                if let Ok(one) = constant_node(arena, 1, 64)
                    && let Ok(sub) = binary_node(arena, ExprOp::Sub, e, one, 64) {
                        expr_map.insert(dst, sub);
                    }
            }
            return;
        }

        if is_sub(form_id) {
            if let (Some(dst), Some(src)) = (reg_operand(insn, 0), reg_operand(insn, 1)) {
                if dst == src {
                    registers.insert(dst, SymbolicValue::Constant(0));
                    if let Ok(zero) = constant_node(arena, 0, 64) {
                        expr_map.insert(dst, zero);
                    }
                } else {
                    let e_dst = get_or_create_expr(arena, expr_map, dst, next_symbol);
                    let e_src = get_or_create_expr(arena, expr_map, src, next_symbol);
                    if let Ok(sub) = binary_node(arena, ExprOp::Sub, e_dst, e_src, 64) {
                        expr_map.insert(dst, sub);
                    }
                    *last_flags = Some(FlagsSetter::SubRegReg { dst, src });
                }
            }
            return;
        }

        // 6. IMUL reg, reg
        if is_imul(form_id) {
            if let (Some(dst), Some(src)) = (reg_operand(insn, 0), reg_operand(insn, 1)) {
                let base_dst = base_register(registers, dst);
                let base_src = base_register(registers, src);

                let offset_dst = match registers.get(&dst) {
                    Some(SymbolicValue::OffsetFrom { offset, .. }) => *offset,
                    _ => 0,
                };
                let offset_src = match registers.get(&src) {
                    Some(SymbolicValue::OffsetFrom { offset, .. }) => *offset,
                    _ => 0,
                };

                let is_square = dst == src || (base_dst == base_src && offset_dst == offset_src);

                if is_square {
                    registers.insert(dst, SymbolicValue::Square { source: base_src });
                } else {
                    let diff = offset_dst - offset_src;
                    let is_parity = base_dst == base_src && (diff == 1 || diff == -1);

                    if is_parity {
                        registers.insert(dst, SymbolicValue::ParityEven { source: base_src });
                    }
                }

                let e_dst = get_or_create_expr(arena, expr_map, dst, next_symbol);
                let e_src = get_or_create_expr(arena, expr_map, src, next_symbol);
                if let Ok(mul) = binary_node(arena, ExprOp::Mul, e_dst, e_src, 64) {
                    expr_map.insert(dst, mul);
                }
            }
            return;
        }

        // 7. OR reg, reg
        if is_or(form_id) {
            if let (Some(dst), Some(src)) = (reg_operand(insn, 0), reg_operand(insn, 1)) {
                let base_dst = base_register(registers, dst);
                let base_src = base_register(registers, src);
                registers.insert(dst, SymbolicValue::BitwiseOr { op1: base_dst, op2: base_src });
                let e_dst = get_or_create_expr(arena, expr_map, dst, next_symbol);
                let e_src = get_or_create_expr(arena, expr_map, src, next_symbol);
                if let Ok(or_node) = binary_node(arena, ExprOp::Or, e_dst, e_src, 64) {
                    expr_map.insert(dst, or_node);
                }
            }
            return;
        }

        // 8. AND reg, reg / imm
        if is_and(form_id) {
            if let (Some(dst), Some(src)) = (reg_operand(insn, 0), reg_operand(insn, 1)) {
                let base_dst = base_register(registers, dst);
                let base_src = base_register(registers, src);
                registers.insert(dst, SymbolicValue::BitwiseAnd { op1: base_dst, op2: base_src });
                let e_dst = get_or_create_expr(arena, expr_map, dst, next_symbol);
                let e_src = get_or_create_expr(arena, expr_map, src, next_symbol);
                if let Ok(and_node) = binary_node(arena, ExprOp::And, e_dst, e_src, 64) {
                    expr_map.insert(dst, and_node);
                }
            } else if let (Some(dst), Some(imm)) = (reg_operand(insn, 0), imm_operand(insn, 1)) {
                if imm == 1
                    && let Some(SymbolicValue::ParityEven { .. }) = registers.get(&dst) {
                        registers.insert(dst, SymbolicValue::Constant(0));
                    }
                let e_dst = get_or_create_expr(arena, expr_map, dst, next_symbol);
                if let Ok(k) = constant_node(arena, u128::from(imm), 64)
                    && let Ok(and_node) = binary_node(arena, ExprOp::And, e_dst, k, 64) {
                        expr_map.insert(dst, and_node);
                    }
            }
            return;
        }

        // 9. XOR reg, reg
        if is_xor(form_id) {
            if let (Some(dst), Some(src)) = (reg_operand(insn, 0), reg_operand(insn, 1)) {
                if dst == src {
                    registers.insert(dst, SymbolicValue::Constant(0));
                    if let Ok(zero) = constant_node(arena, 0, 64) {
                        expr_map.insert(dst, zero);
                    }
                } else {
                    let e_dst = get_or_create_expr(arena, expr_map, dst, next_symbol);
                    let e_src = get_or_create_expr(arena, expr_map, src, next_symbol);
                    if let Ok(xor_node) = binary_node(arena, ExprOp::Xor, e_dst, e_src, 64) {
                        expr_map.insert(dst, xor_node);
                    }
                }
            }
            return;
        }

        // 10. NOT reg
        if is_not(form_id) {
            if let Some(dst) = reg_operand(insn, 0) {
                let e_dst = get_or_create_expr(arena, expr_map, dst, next_symbol);
                if let Ok(not_node) = unary_node(arena, ExprOp::Not, e_dst, 64) {
                    expr_map.insert(dst, not_node);
                }
            }
            return;
        }

        // 11. Flag setters: TEST
        if is_test(form_id) {
            if let (Some(op), Some(imm)) = (reg_operand(insn, 0), imm_operand(insn, 1)) {
                *last_flags = Some(FlagsSetter::TestRegImm { op, imm });
            } else if let (Some(op1), Some(op2)) = (reg_operand(insn, 0), reg_operand(insn, 1)) {
                *last_flags = Some(FlagsSetter::TestRegReg { op1, op2 });
            }
            return;
        }

        // 12. Flag setters: CMP
        if is_cmp(form_id) {
            if let (Some(op), Some(imm)) = (reg_operand(insn, 0), imm_operand(insn, 1)) {
                *last_flags = Some(FlagsSetter::CmpRegImm { op, imm });
            } else if let (Some(op1), Some(op2)) = (reg_operand(insn, 0), reg_operand(insn, 1)) {
                *last_flags = Some(FlagsSetter::CmpRegReg { op1, op2 });
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn evaluate_condition(
        &self,
        branch_insn: &DecodedInstruction,
        flags_setter: &FlagsSetter,
        registers: &BTreeMap<RegisterId, SymbolicValue>,
        arena: &ShardedExprArena,
        expr_map: &mut BTreeMap<RegisterId, ExprId>,
        next_symbol: &mut u64,
        block_start: Address,
    ) -> Option<DetectedOpaquePredicate> {
        let branch_form = branch_insn.form_id;

        // Invariant 1: Parity check (x * (x + 1)) % 2 == 0
        if let FlagsSetter::TestRegImm { op, imm: 1 } = flags_setter
            && let Some(SymbolicValue::ParityEven { .. }) = registers.get(op) {
                // (x * (x + 1)) & 1 == 0 algebraically
                // ZF = 1, PF = 1
                if is_je_or_jz(branch_form) || branch_form == forms::JPE_REL32 {
                    return Some(DetectedOpaquePredicate {
                        address: branch_insn.address,
                        block_start,
                        kind: OpaquePredicateKind::TautologyAlwaysTrue,
                        description: "Algebraic parity tautology: (x * (x + 1)) % 2 == 0 proven, branch always taken"
                            .to_string(),
                    });
                }
                if is_jne_or_jnz(branch_form) || branch_form == forms::JPO_REL32 {
                    return Some(DetectedOpaquePredicate {
                        address: branch_insn.address,
                        block_start,
                        kind: OpaquePredicateKind::TautologyAlwaysFalse,
                        description: "Algebraic parity tautology: (x * (x + 1)) % 2 == 0 proven, branch never taken"
                            .to_string(),
                    });
                }
            }

        // Invariant 2: Domain / Square invariant: x^2 >= 0
        if let FlagsSetter::CmpRegImm { op, imm: 0 } = flags_setter {
            if let Some(SymbolicValue::Square { .. }) = registers.get(op) {
                if branch_form == forms::JGE_REL32 || branch_form == forms::JAE_REL32 || branch_form == forms::JNC_REL32 {
                    return Some(DetectedOpaquePredicate {
                        address: branch_insn.address,
                        block_start,
                        kind: OpaquePredicateKind::TautologyAlwaysTrue,
                        description: "Domain invariant: x^2 >= 0 proven, branch always taken".to_string(),
                    });
                }
                if branch_form == forms::JL_REL32 || branch_form == forms::JB_REL32 || branch_form == forms::JC_REL32 {
                    return Some(DetectedOpaquePredicate {
                        address: branch_insn.address,
                        block_start,
                        kind: OpaquePredicateKind::TautologyAlwaysFalse,
                        description: "Domain invariant: x^2 < 0 impossible, branch never taken".to_string(),
                    });
                }
            }
            // General unsigned comparison against zero: any u >= 0
            if branch_form == forms::JAE_REL32 || branch_form == forms::JNC_REL32 {
                return Some(DetectedOpaquePredicate {
                    address: branch_insn.address,
                    block_start,
                    kind: OpaquePredicateKind::TautologyAlwaysTrue,
                    description: "Unsigned domain invariant: reg >= 0 always holds".to_string(),
                });
            }
            if branch_form == forms::JB_REL32 || branch_form == forms::JC_REL32 {
                return Some(DetectedOpaquePredicate {
                    address: branch_insn.address,
                    block_start,
                    kind: OpaquePredicateKind::TautologyAlwaysFalse,
                    description: "Unsigned domain invariant: reg < 0 impossible".to_string(),
                });
            }
        }

        if let FlagsSetter::TestRegReg { op1, op2 } = flags_setter
            && op1 == op2
                && let Some(SymbolicValue::Square { .. }) = registers.get(op1) {
                    if branch_form == forms::JNS_REL32 || branch_form == forms::JGE_REL32 {
                        return Some(DetectedOpaquePredicate {
                            address: branch_insn.address,
                            block_start,
                            kind: OpaquePredicateKind::TautologyAlwaysTrue,
                            description: "Domain invariant: x^2 >= 0 proven via sign bit test".to_string(),
                        });
                    }
                    if branch_form == forms::JS_REL32 || branch_form == forms::JL_REL32 {
                        return Some(DetectedOpaquePredicate {
                            address: branch_insn.address,
                            block_start,
                            kind: OpaquePredicateKind::TautologyAlwaysFalse,
                            description: "Domain invariant: x^2 < 0 impossible via sign bit test".to_string(),
                        });
                    }
                }

        // Invariant 3: Bitwise invariant: (x | y) >= (x & y)
        if let FlagsSetter::CmpRegReg { op1, op2 } = flags_setter {
            let val1 = registers.get(op1);
            let val2 = registers.get(op2);

            if let (
                Some(SymbolicValue::BitwiseOr { op1: a1, op2: b1 }),
                Some(SymbolicValue::BitwiseAnd { op1: a2, op2: b2 }),
            ) = (val1, val2)
                && ((*a1 == *a2 && *b1 == *b2) || (*a1 == *b2 && *b1 == *a2)) {
                    // (x | y) >= (x & y) holds for all bitvectors: CF == 0
                    if branch_form == forms::JAE_REL32 || branch_form == forms::JNC_REL32 {
                        return Some(DetectedOpaquePredicate {
                            address: branch_insn.address,
                            block_start,
                            kind: OpaquePredicateKind::TautologyAlwaysTrue,
                            description: "Bitwise invariant (x | y) >= (x & y) proven, branch always taken"
                                .to_string(),
                        });
                    }
                    if branch_form == forms::JB_REL32 || branch_form == forms::JC_REL32 {
                        return Some(DetectedOpaquePredicate {
                            address: branch_insn.address,
                            block_start,
                            kind: OpaquePredicateKind::TautologyAlwaysFalse,
                            description: "Bitwise invariant (x | y) < (x & y) impossible, branch never taken"
                                .to_string(),
                        });
                    }
                }

            // Reverse comparison: (x & y) compared with (x | y)
            if let (
                Some(SymbolicValue::BitwiseAnd { op1: a1, op2: b1 }),
                Some(SymbolicValue::BitwiseOr { op1: a2, op2: b2 }),
            ) = (val1, val2)
                && ((*a1 == *a2 && *b1 == *b2) || (*a1 == *b2 && *b1 == *a2)) {
                    if branch_form == forms::JB_REL32 || branch_form == forms::JC_REL32 {
                        return Some(DetectedOpaquePredicate {
                            address: branch_insn.address,
                            block_start,
                            kind: OpaquePredicateKind::TautologyAlwaysTrue,
                            description: "Bitwise invariant (x & y) <= (x | y) proven, branch always taken"
                                .to_string(),
                        });
                    }
                    if branch_form == forms::JA_REL32 {
                        return Some(DetectedOpaquePredicate {
                            address: branch_insn.address,
                            block_start,
                            kind: OpaquePredicateKind::TautologyAlwaysFalse,
                            description: "Bitwise invariant (x & y) > (x | y) impossible, branch never taken"
                                .to_string(),
                        });
                    }
                }

            // Invariant 4: Context Invariant / Identical context registers
            if let (
                Some(SymbolicValue::ContextRegister { reg: r1, offset: o1 }),
                Some(SymbolicValue::ContextRegister { reg: r2, offset: o2 }),
            ) = (val1, val2)
                && r1 == r2 && o1 == o2 {
                    if is_je_or_jz(branch_form)
                        || branch_form == forms::JAE_REL32
                        || branch_form == forms::JGE_REL32
                        || branch_form == forms::JBE_REL32
                        || branch_form == forms::JLE_REL32
                    {
                        return Some(DetectedOpaquePredicate {
                            address: branch_insn.address,
                            block_start,
                            kind: OpaquePredicateKind::ContextInvariant,
                            description: "Context invariant: identical context register offsets compared (always true)"
                                .to_string(),
                        });
                    }
                    if is_jne_or_jnz(branch_form)
                        || branch_form == forms::JB_REL32
                        || branch_form == forms::JL_REL32
                        || branch_form == forms::JA_REL32
                        || branch_form == forms::JG_REL32
                    {
                        return Some(DetectedOpaquePredicate {
                            address: branch_insn.address,
                            block_start,
                            kind: OpaquePredicateKind::ContextInvariant,
                            description:
                                "Context invariant: identical context register offsets compared (always false)"
                                    .to_string(),
                        });
                    }
                }

            // Invariant 5: Identity: cmp reg, reg
            if op1 == op2 {
                if is_je_or_jz(branch_form)
                    || branch_form == forms::JAE_REL32
                    || branch_form == forms::JGE_REL32
                    || branch_form == forms::JBE_REL32
                    || branch_form == forms::JLE_REL32
                {
                    return Some(DetectedOpaquePredicate {
                        address: branch_insn.address,
                        block_start,
                        kind: OpaquePredicateKind::TautologyAlwaysTrue,
                        description: "Identity invariant: comparing register to itself is always equal".to_string(),
                    });
                }
                if is_jne_or_jnz(branch_form)
                    || branch_form == forms::JB_REL32
                    || branch_form == forms::JL_REL32
                    || branch_form == forms::JA_REL32
                    || branch_form == forms::JG_REL32
                {
                    return Some(DetectedOpaquePredicate {
                        address: branch_insn.address,
                        block_start,
                        kind: OpaquePredicateKind::TautologyAlwaysFalse,
                        description: "Identity invariant: comparing register to itself is never not-equal".to_string(),
                    });
                }
            }

            // Invariant 6: angryier-expr MBA simplification on (op1 - op2)
            let e1 = get_or_create_expr(arena, expr_map, *op1, next_symbol);
            let e2 = get_or_create_expr(arena, expr_map, *op2, next_symbol);
            if let Ok(diff) = binary_node(arena, ExprOp::Sub, e1, e2, 64) {
                    let simplified = deobfuscate(arena, diff);
                    if let Some(c) = read_constant(arena, simplified) {
                        if c == 0 {
                            if is_je_or_jz(branch_form)
                                || branch_form == forms::JAE_REL32
                                || branch_form == forms::JGE_REL32
                                || branch_form == forms::JBE_REL32
                                || branch_form == forms::JLE_REL32
                            {
                                return Some(DetectedOpaquePredicate {
                                    address: branch_insn.address,
                                    block_start,
                                    kind: OpaquePredicateKind::TautologyAlwaysTrue,
                                    description: "MBA fixpoint simplification proven equivalent to 0 (always true)"
                                        .to_string(),
                                });
                            }
                            if is_jne_or_jnz(branch_form)
                                || branch_form == forms::JB_REL32
                                || branch_form == forms::JL_REL32
                                || branch_form == forms::JA_REL32
                                || branch_form == forms::JG_REL32
                            {
                                return Some(DetectedOpaquePredicate {
                                    address: branch_insn.address,
                                    block_start,
                                    kind: OpaquePredicateKind::TautologyAlwaysFalse,
                                    description: "MBA fixpoint simplification proven equivalent to 0 (never true)"
                                        .to_string(),
                                });
                            }
                        } else {
                            if is_je_or_jz(branch_form) {
                                return Some(DetectedOpaquePredicate {
                                    address: branch_insn.address,
                                    block_start,
                                    kind: OpaquePredicateKind::TautologyAlwaysFalse,
                                    description: "MBA simplification non-zero constant difference (never equal)"
                                        .to_string(),
                                });
                            }
                            if is_jne_or_jnz(branch_form) {
                                return Some(DetectedOpaquePredicate {
                                    address: branch_insn.address,
                                    block_start,
                                    kind: OpaquePredicateKind::TautologyAlwaysTrue,
                                    description: "MBA simplification non-zero constant difference (always not-equal)"
                                        .to_string(),
                                });
                            }
                        }
                    }
                }
        }

        // SubRegReg checking: sub op1, op2 where (x | y) - (x & y)
        if let FlagsSetter::SubRegReg { dst, src } = flags_setter {
            let val1 = registers.get(dst);
            let val2 = registers.get(src);
            if let (
                Some(SymbolicValue::BitwiseOr { op1: a1, op2: b1 }),
                Some(SymbolicValue::BitwiseAnd { op1: a2, op2: b2 }),
            ) = (val1, val2)
                && ((*a1 == *a2 && *b1 == *b2) || (*a1 == *b2 && *b1 == *a2)) {
                    if branch_form == forms::JNC_REL32 || branch_form == forms::JAE_REL32 {
                        return Some(DetectedOpaquePredicate {
                            address: branch_insn.address,
                            block_start,
                            kind: OpaquePredicateKind::TautologyAlwaysTrue,
                            description: "Bitwise invariant (x | y) - (x & y) >= 0 proven, CF is 0".to_string(),
                        });
                    }
                    if branch_form == forms::JC_REL32 || branch_form == forms::JB_REL32 {
                        return Some(DetectedOpaquePredicate {
                            address: branch_insn.address,
                            block_start,
                            kind: OpaquePredicateKind::TautologyAlwaysFalse,
                            description: "Bitwise invariant (x | y) - (x & y) >= 0 proven, CF is never 1".to_string(),
                        });
                    }
                }
        }

        None
    }
}

/// Prunes detected opaque predicates and overlapping junk code from the CFG.
pub fn prune_opaque_predicates(cfg: &mut ControlFlowGraph, limits: PruningLimits) -> PruningReport {
    let mut report = PruningReport::default();
    let detector = OpaquePredicateDetector::new();
    let mut total_instructions_scanned = 0usize;

    for _pass in 0..limits.max_passes {
        let mut pass_changed = false;

        // 1. Scan and neutralize Overlapping Junk Instructions
        let block_addrs: Vec<Address> = cfg.blocks.keys().copied().collect();
        for &b_addr in &block_addrs {
            if total_instructions_scanned >= limits.max_instructions_scanned {
                break;
            }
            let Some(block) = cfg.blocks.get(&b_addr) else {
                continue;
            };
            total_instructions_scanned += block.instructions.len();

            if let Some(junk) = detector.detect_overlapping_junk(block)
                && let Some(action) = neutralize_junk(cfg, b_addr, &junk) {
                    report.detected.push(junk);
                    report.actions.push(action);
                    report.neutralized_junk += 1;
                    pass_changed = true;
                }
        }

        // 2. Scan and eliminate Dead Branches from Opaque Predicates
        let block_addrs: Vec<Address> = cfg.blocks.keys().copied().collect();
        for &b_addr in &block_addrs {
            if total_instructions_scanned >= limits.max_instructions_scanned {
                break;
            }
            let Some(block) = cfg.blocks.get(&b_addr) else {
                continue;
            };
            total_instructions_scanned += block.instructions.len();

            if let Some(pred) = detector.detect_block(block)
                && let Some(action) = eliminate_dead_branch(cfg, b_addr, &pred) {
                    report.detected.push(pred);
                    report.actions.push(action);
                    report.eliminated_branches += 1;
                    pass_changed = true;
                }
        }

        // 3. Straighten basic block pairs where branch was pruned
        if report.straightened_blocks < limits.max_blocks_straightened {
            let max_straighten = limits.max_blocks_straightened - report.straightened_blocks;
            let straightened = straighten_all_blocks(cfg, max_straighten);
            if !straightened.is_empty() {
                report.straightened_blocks += straightened.len();
                report.actions.extend(straightened);
                pass_changed = true;
            }
        }

        if !pass_changed {
            break;
        }
    }

    report
}

/// Eliminates a dead branch in `cfg` at `block_addr` based on `pred`.
pub fn eliminate_dead_branch(
    cfg: &mut ControlFlowGraph,
    block_addr: Address,
    pred: &DetectedOpaquePredicate,
) -> Option<PruningAction> {
    let block = cfg.blocks.get_mut(&block_addr)?;
    if block.terminator != EdgeKind::ConditionalTaken {
        return None;
    }
    let last_insn = block.instructions.last()?;
    let branch_addr = last_insn.address;

    // Determine branch targets from CFG edges
    let mut taken_target = None;
    let mut fallthrough_target = None;

    for edge in &cfg.edges {
        if edge.from == branch_addr {
            match edge.kind {
                EdgeKind::ConditionalTaken => taken_target = edge.to,
                EdgeKind::FallThrough => fallthrough_target = edge.to,
                _ => {}
            }
        }
    }

    let taken = taken_target?;
    let fallthrough = fallthrough_target?;

    let is_taken = match pred.kind {
        OpaquePredicateKind::TautologyAlwaysTrue => true,
        OpaquePredicateKind::TautologyAlwaysFalse => false,
        OpaquePredicateKind::ContextInvariant => {
            // Check if condition was true or false
            let form = last_insn.form_id;
            is_je_or_jz(form)
                || form == forms::JAE_REL32
                || form == forms::JGE_REL32
                || form == forms::JBE_REL32
                || form == forms::JLE_REL32
        }
        OpaquePredicateKind::OverlappingJunkInstruction => return None,
    };

    let (retained_target, removed_target) = if is_taken {
        (taken, fallthrough)
    } else {
        (fallthrough, taken)
    };

    if is_taken {
        // Retain taken edge as unconditional; remove fallthrough
        cfg.edges.retain(|e| !(e.from == branch_addr && e.kind == EdgeKind::FallThrough));
        for e in &mut cfg.edges {
            if e.from == branch_addr && e.kind == EdgeKind::ConditionalTaken {
                e.kind = EdgeKind::Unconditional;
            }
        }

        let block = cfg.blocks.get_mut(&block_addr)?;
        block.terminator = EdgeKind::Unconditional;
        if let Some(insn) = block.instructions.last_mut() {
            insn.form_id = forms::JMP_REL32;
        }
    } else {
        // Retain fallthrough; remove conditional taken edge
        cfg.edges.retain(|e| !(e.from == branch_addr && e.kind == EdgeKind::ConditionalTaken));

        let block = cfg.blocks.get_mut(&block_addr)?;
        block.terminator = EdgeKind::FallThrough;
        // Replace conditional jump with NOPs
        if let Some(insn) = block.instructions.last_mut() {
            insn.form_id = forms::NOP;
            insn.operands.clear();
        }
    }

    Some(PruningAction::EliminateDeadBranch {
        branch_address: branch_addr,
        retained_target,
        removed_target,
        kind: pred.kind,
    })
}

/// Neutralizes an overlapping junk instruction sequence in `block_addr`.
pub fn neutralize_junk(
    cfg: &mut ControlFlowGraph,
    block_addr: Address,
    pred: &DetectedOpaquePredicate,
) -> Option<PruningAction> {
    let block = cfg.blocks.get_mut(&block_addr)?;
    let mut junk_info = None;

    for (idx, insn) in block.instructions.iter().enumerate() {
        if insn.address == pred.address
            && let Some(target) = static_target(insn) {
                let len = target.wrapping_sub(insn.address) as usize;
                junk_info = Some((idx, target, len.max(1)));
                break;
            }
    }

    let (junk_idx, target, length) = junk_info?;
    let is_last = junk_idx == block.instructions.len().saturating_sub(1);

    if is_last {
        let block = cfg.blocks.get_mut(&block_addr)?;
        block.terminator = EdgeKind::FallThrough;
        if let Some(insn) = block.instructions.get_mut(junk_idx) {
            insn.form_id = forms::NOP;
            insn.operands.clear();
        }

        // Update CFG edges from this terminator
        for e in &mut cfg.edges {
            if e.from == pred.address {
                e.kind = EdgeKind::FallThrough;
                e.to = Some(target);
            }
        }
    } else {
        let block = cfg.blocks.get_mut(&block_addr)?;
        if let Some(insn) = block.instructions.get_mut(junk_idx) {
            insn.form_id = forms::NOP;
            insn.operands.clear();
        }
    }

    Some(PruningAction::NeutralizeJunkOverlap {
        address: pred.address,
        target,
        length,
    })
}

/// Straightens all candidate basic block pairs in `cfg` up to `max_merges`.
pub fn straighten_all_blocks(cfg: &mut ControlFlowGraph, max_merges: usize) -> Vec<PruningAction> {
    let mut actions = Vec::new();

    while actions.len() < max_merges {
        let mut candidate_pair = None;

        // Find a predecessor block P and successor block S that can be straightened
        for (&p_addr, p_block) in &cfg.blocks {
            // Successors of P via edges
            let last_addr = p_block.instructions.last().map(|i| i.address).unwrap_or(p_addr);
            let p_edges: Vec<&CfgEdge> = cfg
                .edges
                .iter()
                .filter(|e| (e.from == last_addr || e.from == p_addr) && e.to.is_some())
                .collect();

            // P must have exactly one static successor
            if p_edges.len() != 1 {
                continue;
            }
            let edge = p_edges[0];
            if edge.kind != EdgeKind::FallThrough && edge.kind != EdgeKind::Unconditional {
                continue;
            }
            let s_addr = match edge.to {
                Some(to) => to,
                None => continue,
            };

            if s_addr == p_addr || s_addr == cfg.entry {
                continue;
            }

            if !cfg.blocks.contains_key(&s_addr) {
                continue;
            }

            // S must have exactly one predecessor (which is P)
            let s_incoming_count = cfg.edges.iter().filter(|e| e.to == Some(s_addr)).count();
            if s_incoming_count != 1 {
                continue;
            }

            candidate_pair = Some((p_addr, s_addr));
            break;
        }

        let Some((p_addr, s_addr)) = candidate_pair else {
            break;
        };

        // Merge S into P
        let Some(s_block) = cfg.blocks.remove(&s_addr) else {
            break;
        };
        let Some(p_block) = cfg.blocks.get_mut(&p_addr) else {
            break;
        };

        p_block.instructions.extend(s_block.instructions);
        p_block.end = s_block.end;
        p_block.terminator = s_block.terminator;

        let p_last_addr = p_block.instructions.last().map(|i| i.address).unwrap_or(p_addr);

        // Remove the edge P -> S
        cfg.edges.retain(|e| !(e.to == Some(s_addr)));

        // Remap outgoing edges that left S so they point from P's terminator
        for e in &mut cfg.edges {
            if e.from == s_addr || (s_block.start..s_block.end).contains(&e.from) {
                e.from = p_last_addr;
            }
        }

        actions.push(PruningAction::StraightenBlocks {
            predecessor: p_addr,
            successor: s_addr,
        });
    }

    actions
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn is_conditional_branch(form_id: u32) -> bool {
    const CONDITIONAL: &[u32] = &[
        forms::JO_REL32,
        forms::JNO_REL32,
        forms::JB_REL32,
        forms::JAE_REL32,
        forms::JZ_REL32,
        forms::JNZ_REL32,
        forms::JBE_REL32,
        forms::JA_REL32,
        forms::JS_REL32,
        forms::JNS_REL32,
        forms::JPE_REL32,
        forms::JPO_REL32,
        forms::JL_REL32,
        forms::JGE_REL32,
        forms::JLE_REL32,
        forms::JG_REL32,
        forms::JC_REL32,
        forms::JNC_REL32,
    ];
    CONDITIONAL.contains(&form_id)
}

fn is_je_or_jz(form_id: u32) -> bool {
    form_id == forms::JZ_REL32
}

fn is_jne_or_jnz(form_id: u32) -> bool {
    form_id == forms::JNZ_REL32
}

fn is_mov(form_id: u32) -> bool {
    matches!(
        form_id,
        forms::MOV_R64_R64 | forms::MOV_R32_R32 | forms::MOV_R16_R16 | forms::MOV_R8_R8
    )
}

fn is_mov_imm(form_id: u32) -> bool {
    matches!(
        form_id,
        forms::MOV_R64_IMM64 | forms::MOV_R32_IMM32 | forms::MOV_R16_IMM16 | forms::MOV_R8_IMM8
    )
}

fn is_mov_load(form_id: u32) -> bool {
    matches!(form_id, forms::MOV_R64_MEM64 | forms::MOV_R32_MEM32)
}

fn is_inc(form_id: u32) -> bool {
    matches!(
        form_id,
        forms::INC_R64 | forms::INC_R32 | forms::INC_R16 | forms::INC_R8
    )
}

fn is_dec(form_id: u32) -> bool {
    matches!(form_id, forms::DEC_R64 | forms::DEC_R32 | forms::DEC_R8)
}

fn is_add(form_id: u32) -> bool {
    matches!(
        form_id,
        forms::ADD_R64_R64 | forms::ADD_R32_R32 | forms::ADD_R64_IMM32 | forms::ADD_R32_IMM8
    )
}

fn is_sub(form_id: u32) -> bool {
    matches!(
        form_id,
        forms::SUB_R64_R64 | forms::SUB_R32_R32 | forms::SUB_R64_IMM32 | forms::SUB_R32_IMM8
    )
}

fn is_imul(form_id: u32) -> bool {
    matches!(
        form_id,
        forms::IMUL_R64_R64 | forms::IMUL_R32_R32 | forms::IMUL_1OP_R64
    )
}

fn is_or(form_id: u32) -> bool {
    matches!(
        form_id,
        forms::OR_R64_R64 | forms::OR_R32_R32 | forms::OR_R64_IMM32 | forms::OR_R32_IMM32
    )
}

fn is_and(form_id: u32) -> bool {
    matches!(
        form_id,
        forms::AND_R64_R64 | forms::AND_R32_R32 | forms::AND_R64_IMM32 | forms::AND_R32_IMM32
    )
}

fn is_xor(form_id: u32) -> bool {
    matches!(
        form_id,
        forms::XOR_R64_R64 | forms::XOR_R32_R32 | forms::XOR_R64_IMM32 | forms::XOR_R32_IMM32
    )
}

fn is_not(form_id: u32) -> bool {
    matches!(form_id, forms::NOT_R64 | forms::NOT_R32 | forms::NOT_R8)
}

fn is_test(form_id: u32) -> bool {
    matches!(
        form_id,
        forms::TEST_R64_R64
            | forms::TEST_R32_R32
            | forms::TEST_R8_R8
            | forms::TEST_R64_IMM32
            | forms::TEST_R32_IMM32
            | forms::TEST_R8_IMM8
    )
}

fn is_cmp(form_id: u32) -> bool {
    matches!(
        form_id,
        forms::CMP_R64_R64
            | forms::CMP_R32_R32
            | forms::CMP_R16_R16
            | forms::CMP_R8_R8
            | forms::CMP_R64_IMM32
            | forms::CMP_R32_IMM8
            | forms::CMP_R8_IMM8
    )
}

fn reg_operand(insn: &DecodedInstruction, idx: usize) -> Option<RegisterId> {
    insn.operands.get(idx).and_then(|op| match op.kind {
        OperandKind::Register(view) => Some(view.parent),
        _ => None,
    })
}

fn imm_operand(insn: &DecodedInstruction, idx: usize) -> Option<u64> {
    insn.operands.get(idx).and_then(|op| match op.kind {
        OperandKind::Immediate(imm) => Some(imm.value),
        _ => None,
    })
}

fn mem_operand(insn: &DecodedInstruction, idx: usize) -> Option<&MemoryOperand> {
    insn.operands.get(idx).and_then(|op| match &op.kind {
        OperandKind::Memory(mem) => Some(mem),
        _ => None,
    })
}

fn static_target(insn: &DecodedInstruction) -> Option<Address> {
    insn.operands.iter().find_map(|operand| match operand.kind {
        OperandKind::RelativeBranch(branch) => Some(insn.relative_target(branch)),
        _ => None,
    })
}

fn constant_node(
    arena: &ShardedExprArena,
    value: u128,
    bits: u16,
) -> Result<ExprId, angryier_expr::ExprArenaError> {
    let len = usize::from(bits).div_ceil(8);
    let bytes = value.to_le_bytes()[..len].to_vec();
    arena.intern(ExprNode {
        sort: ExprSort::BitVec(bits),
        op: ExprOp::Constant,
        operands: Vec::new(),
        immediate: bytes,
    })
}

fn symbol_node(
    arena: &ShardedExprArena,
    sym_id: u64,
    bits: u16,
) -> Result<ExprId, angryier_expr::ExprArenaError> {
    arena.intern(ExprNode {
        sort: ExprSort::BitVec(bits),
        op: ExprOp::Symbol,
        operands: Vec::new(),
        immediate: sym_id.to_le_bytes().to_vec(),
    })
}

fn binary_node(
    arena: &ShardedExprArena,
    op: ExprOp,
    left: ExprId,
    right: ExprId,
    bits: u16,
) -> Result<ExprId, angryier_expr::ExprArenaError> {
    arena.intern(ExprNode {
        sort: ExprSort::BitVec(bits),
        op,
        operands: vec![left, right],
        immediate: Vec::new(),
    })
}

fn unary_node(
    arena: &ShardedExprArena,
    op: ExprOp,
    operand: ExprId,
    bits: u16,
) -> Result<ExprId, angryier_expr::ExprArenaError> {
    arena.intern(ExprNode {
        sort: ExprSort::BitVec(bits),
        op,
        operands: vec![operand],
        immediate: Vec::new(),
    })
}

fn read_constant(arena: &ShardedExprArena, id: ExprId) -> Option<u128> {
    let node = arena.get(id)?;
    if node.op == ExprOp::Constant {
        let mut bytes = [0u8; 16];
        let len = node.immediate.len().min(16);
        bytes[..len].copy_from_slice(&node.immediate[..len]);
        Some(u128::from_le_bytes(bytes))
    } else {
        None
    }
}

fn get_or_create_expr(
    arena: &ShardedExprArena,
    expr_map: &mut BTreeMap<RegisterId, ExprId>,
    reg: RegisterId,
    next_symbol: &mut u64,
) -> ExprId {
    if let Some(&e) = expr_map.get(&reg) {
        return e;
    }
    let sym = *next_symbol;
    *next_symbol += 1;
    if let Ok(id) = symbol_node(arena, sym, 64) {
        expr_map.insert(reg, id);
        id
    } else {
        ExprId(0)
    }
}

fn base_register(registers: &BTreeMap<RegisterId, SymbolicValue>, reg: RegisterId) -> RegisterId {
    match registers.get(&reg) {
        Some(SymbolicValue::OffsetFrom { base, .. }) => *base,
        _ => reg,
    }
}

