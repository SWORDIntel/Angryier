//! Comprehensive unit and integration tests for Phase 2: Opaque Predicate & Junk-Code Pruner.
//!
//! Validates:
//! 1. Algebraic parity tautology: (x * (x + 1)) % 2 == 0
//! 2. Bitwise invariant: (x | y) >= (x & y)
//! 3. Mid-instruction 0xE8 and 0xEB 0xFF junk overlap neutralization
//! 4. True negative validation: genuine non-opaque conditional branches are preserved untouched
//! 5. Identity invariant: (x ^ y) == 0 <=> x == y and cmp reg, reg
//! 6. Domain square invariant: x^2 >= 0
//! 7. Context invariant: identical context register loads
//! 8. MBA fixpoint simplification via angryier-expr: (x | y) - (x & y) == x ^ y and not(not(x))
//! 9. Basic block straightening after dead branch elimination

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use angryier_arch::{
    AccessKind, DecodedInstruction, ImmediateOperand, InstructionModifiers, MemoryBase, MemoryOperand,
    Operand, OperandKind, OperandVisibility, RegisterId, RegisterView, RelativeBranchOperand,
};
use angryier_cfg::opaque::{
    OpaquePredicateDetector, OpaquePredicateKind, PruningLimits,
    prune_opaque_predicates,
};
use angryier_cfg::{BasicBlock, Cfg, CfgEdge, EdgeKind};
use angryier_semantics_intel64::forms;
use angryier_types::Address;

const fn addr(a: u64) -> Address {
    a
}

fn reg_view(id: u32) -> RegisterView {
    RegisterView::full(RegisterId(id), 64)
}

fn r64_write(id: u32, idx: u8) -> Operand {
    Operand {
        index: idx,
        width_bits: 64,
        access: AccessKind::Write,
        visibility: OperandVisibility::Explicit,
        kind: OperandKind::Register(reg_view(id)),
    }
}

fn r64_read(id: u32, idx: u8) -> Operand {
    Operand {
        index: idx,
        width_bits: 64,
        access: AccessKind::Read,
        visibility: OperandVisibility::Explicit,
        kind: OperandKind::Register(reg_view(id)),
    }
}

fn imm_op(val: u64, width: u16, idx: u8) -> Operand {
    Operand {
        index: idx,
        width_bits: width,
        access: AccessKind::Read,
        visibility: OperandVisibility::Explicit,
        kind: OperandKind::Immediate(ImmediateOperand {
            value: val,
            signed: false,
        }),
    }
}

fn rel_branch_op(disp: i64, idx: u8) -> Operand {
    Operand {
        index: idx,
        width_bits: 32,
        access: AccessKind::Read,
        visibility: OperandVisibility::Explicit,
        kind: OperandKind::RelativeBranch(RelativeBranchOperand {
            displacement: disp,
            displacement_width_bits: 32,
        }),
    }
}

fn mem_load_op(base_reg: u32, disp: i64, idx: u8) -> Operand {
    Operand {
        index: idx,
        width_bits: 64,
        access: AccessKind::Read,
        visibility: OperandVisibility::Explicit,
        kind: OperandKind::Memory(MemoryOperand {
            memory_index: 0,
            address_width_bits: 64,
            segment: None,
            segment_base: None,
            base: Some(MemoryBase::Register(reg_view(base_reg))),
            index: None,
            scale: 1,
            displacement: disp,
            displacement_width_bits: 32,
        }),
    }
}

fn insn(addr: Address, len: u8, form_id: u32, operands: Vec<Operand>) -> DecodedInstruction {
    DecodedInstruction {
        address: addr,
        length: len,
        form_id,
        features: Vec::new(),
        operands,
        modifiers: InstructionModifiers::default(),
    }
}

// ── Test 1: Algebraic Parity Tautology ────────────────────────────────────────

#[test]
fn test_algebraic_parity_tautology_always_true() {
    // Block at 0x1000 computes:
    //   mov rbx, rax
    //   inc rbx           ; rbx = rax + 1
    //   imul rbx, rax      ; rbx = (rax + 1) * rax (always even!)
    //   test rbx, 1        ; test low bit -> ZF is 1
    //   jz 0x2000          ; Always taken!
    let entry = addr(0x1000);
    let target = addr(0x2000);
    let fallthrough = addr(0x1015);

    let b1_insns = vec![
        insn(addr(0x1000), 3, forms::MOV_R64_R64, vec![r64_write(1, 0), r64_read(0, 1)]),
        insn(addr(0x1003), 3, forms::INC_R64, vec![r64_write(1, 0)]),
        insn(addr(0x1006), 3, forms::IMUL_R64_R64, vec![r64_write(1, 0), r64_read(0, 1)]),
        insn(addr(0x1009), 6, forms::TEST_R64_IMM32, vec![r64_read(1, 0), imm_op(1, 32, 1)]),
        // jz 0x2000 (displacement = 0x2000 - 0x1015 = 0x0FEB)
        insn(addr(0x100F), 6, forms::JZ_REL32, vec![rel_branch_op(0x0FEB, 0)]),
    ];

    let b1 = BasicBlock {
        start: addr(0x1000),
        end: fallthrough,
        instructions: b1_insns,
        terminator: EdgeKind::ConditionalTaken,
    };

    let b_target = BasicBlock {
        start: target,
        end: addr(0x2005),
        instructions: vec![insn(target, 5, forms::MOV_R64_IMM64, vec![r64_write(0, 0), imm_op(42, 64, 1)])],
        terminator: EdgeKind::Return,
    };

    let b_fallthrough = BasicBlock {
        start: fallthrough,
        end: addr(0x1020),
        instructions: vec![insn(fallthrough, 5, forms::MOV_R64_IMM64, vec![r64_write(0, 0), imm_op(99, 64, 1)])],
        terminator: EdgeKind::Return,
    };

    let mut blocks = BTreeMap::new();
    blocks.insert(b1.start, b1);
    blocks.insert(b_target.start, b_target);
    blocks.insert(b_fallthrough.start, b_fallthrough);

    let edges = vec![
        CfgEdge {
            from: addr(0x100F),
            to: Some(target),
            kind: EdgeKind::ConditionalTaken,
        },
        CfgEdge {
            from: addr(0x100F),
            to: Some(fallthrough),
            kind: EdgeKind::FallThrough,
        },
    ];

    let mut cfg = Cfg { entry, blocks, edges };

    let detector = OpaquePredicateDetector::new();
    let detected = detector.detect_block(cfg.blocks.get(&entry).unwrap());
    assert!(detected.is_some(), "Detector must identify parity tautology");
    let pred = detected.unwrap();
    assert_eq!(pred.kind, OpaquePredicateKind::TautologyAlwaysTrue);

    // Prune the CFG
    let report = prune_opaque_predicates(&mut cfg, PruningLimits::default());
    assert_eq!(report.eliminated_branches, 1);
    assert_eq!(report.straightened_blocks, 1, "Should straighten block 0x1000 and target 0x2000");

    // The pruned block should have taken branch retained and fallthrough dead
    let merged_block = cfg.blocks.get(&entry).unwrap();
    assert_eq!(merged_block.terminator, EdgeKind::Return);
    assert!(merged_block.instructions.iter().any(|i| i.address == target));

    // Fallthrough edge was removed
    assert!(!cfg.edges.iter().any(|e| e.to == Some(fallthrough)));
}

#[test]
fn test_algebraic_parity_tautology_always_false() {
    // Parity tautology with jnz (never taken)
    let entry = addr(0x1000);
    let target = addr(0x2000);
    let fallthrough = addr(0x1015);

    let b1_insns = vec![
        insn(addr(0x1000), 3, forms::MOV_R64_R64, vec![r64_write(1, 0), r64_read(0, 1)]),
        insn(addr(0x1003), 3, forms::INC_R64, vec![r64_write(1, 0)]),
        insn(addr(0x1006), 3, forms::IMUL_R64_R64, vec![r64_write(1, 0), r64_read(0, 1)]),
        insn(addr(0x1009), 6, forms::TEST_R64_IMM32, vec![r64_read(1, 0), imm_op(1, 32, 1)]),
        insn(addr(0x100F), 6, forms::JNZ_REL32, vec![rel_branch_op(0x0FEB, 0)]),
    ];

    let b1 = BasicBlock {
        start: addr(0x1000),
        end: fallthrough,
        instructions: b1_insns,
        terminator: EdgeKind::ConditionalTaken,
    };

    let b_target = BasicBlock {
        start: target,
        end: addr(0x2005),
        instructions: vec![insn(target, 5, forms::NOP, vec![])],
        terminator: EdgeKind::Return,
    };

    let b_fallthrough = BasicBlock {
        start: fallthrough,
        end: addr(0x1020),
        instructions: vec![insn(fallthrough, 5, forms::MOV_R64_IMM64, vec![r64_write(0, 0), imm_op(7, 64, 1)])],
        terminator: EdgeKind::Return,
    };

    let mut blocks = BTreeMap::new();
    blocks.insert(b1.start, b1);
    blocks.insert(b_target.start, b_target);
    blocks.insert(b_fallthrough.start, b_fallthrough);

    let edges = vec![
        CfgEdge {
            from: addr(0x100F),
            to: Some(target),
            kind: EdgeKind::ConditionalTaken,
        },
        CfgEdge {
            from: addr(0x100F),
            to: Some(fallthrough),
            kind: EdgeKind::FallThrough,
        },
    ];

    let mut cfg = Cfg { entry, blocks, edges };

    let detector = OpaquePredicateDetector::new();
    let detected = detector.detect_block(cfg.blocks.get(&entry).unwrap());
    assert!(detected.is_some());
    assert_eq!(detected.unwrap().kind, OpaquePredicateKind::TautologyAlwaysFalse);

    let report = prune_opaque_predicates(&mut cfg, PruningLimits::default());
    assert_eq!(report.eliminated_branches, 1);
    assert_eq!(report.straightened_blocks, 1, "Should straighten block 0x1000 and fallthrough");

    let merged_block = cfg.blocks.get(&entry).unwrap();
    assert_eq!(merged_block.terminator, EdgeKind::Return);
    assert!(merged_block.instructions.iter().any(|i| i.address == fallthrough));
    assert!(!cfg.edges.iter().any(|e| e.to == Some(target)));
}

// ── Test 2: Bitwise Invariant (x | y) >= (x & y) ──────────────────────────────

#[test]
fn test_bitwise_or_ge_and_invariant() {
    let entry = addr(0x1000);
    let target = addr(0x3000);
    let fallthrough = addr(0x1015);

    // Compute (x | y) in r8, (x & y) in r9, compare, jump if above-or-equal (always true!)
    let b1_insns = vec![
        insn(addr(0x1000), 3, forms::MOV_R64_R64, vec![r64_write(8, 0), r64_read(0, 1)]),
        insn(addr(0x1003), 3, forms::OR_R64_R64, vec![r64_write(8, 0), r64_read(1, 1)]),
        insn(addr(0x1006), 3, forms::MOV_R64_R64, vec![r64_write(9, 0), r64_read(0, 1)]),
        insn(addr(0x1009), 3, forms::AND_R64_R64, vec![r64_write(9, 0), r64_read(1, 1)]),
        insn(addr(0x100C), 3, forms::CMP_R64_R64, vec![r64_read(8, 0), r64_read(9, 1)]),
        insn(addr(0x100F), 6, forms::JAE_REL32, vec![rel_branch_op(0x1FEB, 0)]),
    ];

    let b1 = BasicBlock {
        start: addr(0x1000),
        end: fallthrough,
        instructions: b1_insns,
        terminator: EdgeKind::ConditionalTaken,
    };

    let b_target = BasicBlock {
        start: target,
        end: addr(0x3005),
        instructions: vec![insn(target, 5, forms::RET, vec![])],
        terminator: EdgeKind::Return,
    };

    let b_fallthrough = BasicBlock {
        start: fallthrough,
        end: addr(0x1020),
        instructions: vec![insn(fallthrough, 5, forms::RET, vec![])],
        terminator: EdgeKind::Return,
    };

    let mut blocks = BTreeMap::new();
    blocks.insert(b1.start, b1);
    blocks.insert(b_target.start, b_target);
    blocks.insert(b_fallthrough.start, b_fallthrough);

    let edges = vec![
        CfgEdge {
            from: addr(0x100F),
            to: Some(target),
            kind: EdgeKind::ConditionalTaken,
        },
        CfgEdge {
            from: addr(0x100F),
            to: Some(fallthrough),
            kind: EdgeKind::FallThrough,
        },
    ];

    let mut cfg = Cfg { entry, blocks, edges };

    let detector = OpaquePredicateDetector::new();
    let detected = detector.detect_block(cfg.blocks.get(&entry).unwrap());
    assert!(detected.is_some(), "(x | y) >= (x & y) invariant must be detected");
    assert_eq!(detected.unwrap().kind, OpaquePredicateKind::TautologyAlwaysTrue);

    let report = prune_opaque_predicates(&mut cfg, PruningLimits::default());
    assert_eq!(report.eliminated_branches, 1);
    assert_eq!(report.straightened_blocks, 1);
    assert!(!cfg.edges.iter().any(|e| e.to == Some(fallthrough)));
}

// ── Test 3: Mid-Instruction 0xE8 Junk Overlap Neutralization ───────────────────

#[test]
fn test_mid_instruction_0xe8_junk_overlap_neutralization() {
    let entry = addr(0x1000);
    let junk_addr = addr(0x1000);
    let target = addr(0x1003); // jmp $+3 skips 1 junk byte (0xE8) at 0x1002

    // Block 1 ends with short jump over 1 junk byte
    let b1_insns = vec![
        insn(junk_addr, 2, forms::JMP_REL32, vec![rel_branch_op(1, 0)]),
    ];

    let b1 = BasicBlock {
        start: entry,
        end: addr(0x1002),
        instructions: b1_insns,
        terminator: EdgeKind::Unconditional,
    };

    // Block 2 starts at the true target 0x1003
    let b2_insns = vec![
        insn(target, 3, forms::MOV_R64_R64, vec![r64_write(0, 0), r64_read(1, 1)]),
        insn(addr(0x1006), 1, forms::RET, vec![]),
    ];

    let b2 = BasicBlock {
        start: target,
        end: addr(0x1007),
        instructions: b2_insns,
        terminator: EdgeKind::Return,
    };

    let mut blocks = BTreeMap::new();
    blocks.insert(b1.start, b1);
    blocks.insert(b2.start, b2);

    let edges = vec![
        CfgEdge {
            from: junk_addr,
            to: Some(target),
            kind: EdgeKind::Unconditional,
        },
    ];

    let mut cfg = Cfg { entry, blocks, edges };

    let detector = OpaquePredicateDetector::new();
    let junk = detector.detect_overlapping_junk(cfg.blocks.get(&entry).unwrap());
    assert!(junk.is_some(), "Must detect overlapping junk sequence");
    assert_eq!(junk.unwrap().kind, OpaquePredicateKind::OverlappingJunkInstruction);

    let report = prune_opaque_predicates(&mut cfg, PruningLimits::default());
    assert_eq!(report.neutralized_junk, 1);
    assert_eq!(report.straightened_blocks, 1, "Blocks must be straightened after junk neutralization");

    let merged = cfg.blocks.get(&entry).unwrap();
    assert_eq!(merged.instructions.first().unwrap().form_id, forms::NOP, "Junk prefix neutralized to NOP");
    assert_eq!(merged.terminator, EdgeKind::Return);
}

#[test]
fn test_mid_instruction_eb_ff_junk_overlap_neutralization() {
    let entry = addr(0x1000);
    let junk_addr = addr(0x1000);
    let target = addr(0x1001); // 0xEB 0xFF lands at pc + 1

    let b1_insns = vec![
        insn(junk_addr, 2, forms::JMP_REL32, vec![rel_branch_op(-1, 0)]),
    ];

    let b1 = BasicBlock {
        start: entry,
        end: addr(0x1002),
        instructions: b1_insns,
        terminator: EdgeKind::Unconditional,
    };

    let b2 = BasicBlock {
        start: target,
        end: addr(0x1005),
        instructions: vec![insn(target, 4, forms::RET, vec![])],
        terminator: EdgeKind::Return,
    };

    let mut blocks = BTreeMap::new();
    blocks.insert(b1.start, b1);
    blocks.insert(b2.start, b2);

    let edges = vec![
        CfgEdge {
            from: junk_addr,
            to: Some(target),
            kind: EdgeKind::Unconditional,
        },
    ];

    let mut cfg = Cfg { entry, blocks, edges };

    let detector = OpaquePredicateDetector::new();
    let junk = detector.detect_overlapping_junk(cfg.blocks.get(&entry).unwrap());
    assert!(junk.is_some(), "Must detect 0xEB 0xFF overlapping junk");
    assert_eq!(junk.unwrap().kind, OpaquePredicateKind::OverlappingJunkInstruction);

    let report = prune_opaque_predicates(&mut cfg, PruningLimits::default());
    assert_eq!(report.neutralized_junk, 1);
}

// ── Test 4: True Negative Validation ─────────────────────────────────────────

#[test]
fn test_genuine_non_opaque_conditional_branch_preserved() {
    // Normal conditional branch depending on runtime input
    let entry = addr(0x1000);
    let target = addr(0x2000);
    let fallthrough = addr(0x100B);

    let b1_insns = vec![
        insn(addr(0x1000), 5, forms::CMP_R64_IMM32, vec![r64_read(0, 0), imm_op(42, 32, 1)]),
        insn(addr(0x1005), 6, forms::JG_REL32, vec![rel_branch_op(0x0FF5, 0)]),
    ];

    let b1 = BasicBlock {
        start: entry,
        end: fallthrough,
        instructions: b1_insns,
        terminator: EdgeKind::ConditionalTaken,
    };

    let b_target = BasicBlock {
        start: target,
        end: addr(0x2005),
        instructions: vec![insn(target, 5, forms::RET, vec![])],
        terminator: EdgeKind::Return,
    };

    let b_fallthrough = BasicBlock {
        start: fallthrough,
        end: addr(0x1015),
        instructions: vec![insn(fallthrough, 5, forms::RET, vec![])],
        terminator: EdgeKind::Return,
    };

    let mut blocks = BTreeMap::new();
    blocks.insert(b1.start, b1);
    blocks.insert(b_target.start, b_target);
    blocks.insert(b_fallthrough.start, b_fallthrough);

    let edges = vec![
        CfgEdge {
            from: addr(0x1005),
            to: Some(target),
            kind: EdgeKind::ConditionalTaken,
        },
        CfgEdge {
            from: addr(0x1005),
            to: Some(fallthrough),
            kind: EdgeKind::FallThrough,
        },
    ];

    let mut cfg = Cfg { entry, blocks, edges };

    let detector = OpaquePredicateDetector::new();
    let detected = detector.detect_block(cfg.blocks.get(&entry).unwrap());
    assert!(detected.is_none(), "Genuine dynamic branch must NOT be flagged as opaque");

    let report = prune_opaque_predicates(&mut cfg, PruningLimits::default());
    assert_eq!(report.eliminated_branches, 0, "No branches should be eliminated");
    assert_eq!(report.neutralized_junk, 0);
    assert_eq!(report.straightened_blocks, 0);

    // Both edges must be preserved untouched
    assert!(cfg.edges.iter().any(|e| e.to == Some(target) && e.kind == EdgeKind::ConditionalTaken));
    assert!(cfg.edges.iter().any(|e| e.to == Some(fallthrough) && e.kind == EdgeKind::FallThrough));
}

// ── Test 5: Identity Invariant (cmp reg, reg) ─────────────────────────────────

#[test]
fn test_identity_invariant_cmp_reg_self() {
    let entry = addr(0x1000);
    let target = addr(0x2000);
    let fallthrough = addr(0x1009);

    let b1_insns = vec![
        insn(addr(0x1000), 3, forms::CMP_R64_R64, vec![r64_read(3, 0), r64_read(3, 1)]),
        insn(addr(0x1003), 6, forms::JZ_REL32, vec![rel_branch_op(0x0FF7, 0)]),
    ];

    let b1 = BasicBlock {
        start: entry,
        end: fallthrough,
        instructions: b1_insns,
        terminator: EdgeKind::ConditionalTaken,
    };

    let b_target = BasicBlock {
        start: target,
        end: addr(0x2005),
        instructions: vec![insn(target, 5, forms::RET, vec![])],
        terminator: EdgeKind::Return,
    };

    let b_fallthrough = BasicBlock {
        start: fallthrough,
        end: addr(0x1015),
        instructions: vec![insn(fallthrough, 5, forms::RET, vec![])],
        terminator: EdgeKind::Return,
    };

    let mut blocks = BTreeMap::new();
    blocks.insert(b1.start, b1);
    blocks.insert(b_target.start, b_target);
    blocks.insert(b_fallthrough.start, b_fallthrough);

    let edges = vec![
        CfgEdge {
            from: addr(0x1003),
            to: Some(target),
            kind: EdgeKind::ConditionalTaken,
        },
        CfgEdge {
            from: addr(0x1003),
            to: Some(fallthrough),
            kind: EdgeKind::FallThrough,
        },
    ];

    let mut cfg = Cfg { entry, blocks, edges };

    let detector = OpaquePredicateDetector::new();
    let detected = detector.detect_block(cfg.blocks.get(&entry).unwrap());
    assert!(detected.is_some());
    assert_eq!(detected.unwrap().kind, OpaquePredicateKind::TautologyAlwaysTrue);

    let report = prune_opaque_predicates(&mut cfg, PruningLimits::default());
    assert_eq!(report.eliminated_branches, 1);
    assert_eq!(report.straightened_blocks, 1);
}

// ── Test 6: Domain / Square Invariant (x^2 >= 0) ───────────────────────────────

#[test]
fn test_domain_square_invariant() {
    let entry = addr(0x1000);
    let target = addr(0x2000);
    let fallthrough = addr(0x100C);

    let b1_insns = vec![
        insn(addr(0x1000), 3, forms::IMUL_R64_R64, vec![r64_write(5, 0), r64_read(5, 1)]),
        insn(addr(0x1003), 3, forms::CMP_R64_IMM32, vec![r64_read(5, 0), imm_op(0, 32, 1)]),
        insn(addr(0x1006), 6, forms::JGE_REL32, vec![rel_branch_op(0x0FF4, 0)]),
    ];

    let b1 = BasicBlock {
        start: entry,
        end: fallthrough,
        instructions: b1_insns,
        terminator: EdgeKind::ConditionalTaken,
    };

    let b_target = BasicBlock {
        start: target,
        end: addr(0x2005),
        instructions: vec![insn(target, 5, forms::RET, vec![])],
        terminator: EdgeKind::Return,
    };

    let b_fallthrough = BasicBlock {
        start: fallthrough,
        end: addr(0x1015),
        instructions: vec![insn(fallthrough, 5, forms::RET, vec![])],
        terminator: EdgeKind::Return,
    };

    let mut blocks = BTreeMap::new();
    blocks.insert(b1.start, b1);
    blocks.insert(b_target.start, b_target);
    blocks.insert(b_fallthrough.start, b_fallthrough);

    let edges = vec![
        CfgEdge {
            from: addr(0x1006),
            to: Some(target),
            kind: EdgeKind::ConditionalTaken,
        },
        CfgEdge {
            from: addr(0x1006),
            to: Some(fallthrough),
            kind: EdgeKind::FallThrough,
        },
    ];

    let mut cfg = Cfg { entry, blocks, edges };

    let detector = OpaquePredicateDetector::new();
    let detected = detector.detect_block(cfg.blocks.get(&entry).unwrap());
    assert!(detected.is_some(), "x^2 >= 0 square invariant must be detected");
    assert_eq!(detected.unwrap().kind, OpaquePredicateKind::TautologyAlwaysTrue);

    let report = prune_opaque_predicates(&mut cfg, PruningLimits::default());
    assert_eq!(report.eliminated_branches, 1);
    assert_eq!(report.straightened_blocks, 1);
}

// ── Test 7: Context Invariant ─────────────────────────────────────────────────

#[test]
fn test_context_invariant_identical_loads() {
    let entry = addr(0x1000);
    let target = addr(0x2000);
    let fallthrough = addr(0x1010);

    // Two registers loaded from same context offset [rsi + 0x20]
    let b1_insns = vec![
        insn(addr(0x1000), 4, forms::MOV_R64_MEM64, vec![r64_write(1, 0), mem_load_op(6, 0x20, 1)]),
        insn(addr(0x1004), 4, forms::MOV_R64_MEM64, vec![r64_write(2, 0), mem_load_op(6, 0x20, 1)]),
        insn(addr(0x1008), 3, forms::CMP_R64_R64, vec![r64_read(1, 0), r64_read(2, 1)]),
        insn(addr(0x100B), 5, forms::JZ_REL32, vec![rel_branch_op(0x0FF0, 0)]),
    ];

    let b1 = BasicBlock {
        start: entry,
        end: fallthrough,
        instructions: b1_insns,
        terminator: EdgeKind::ConditionalTaken,
    };

    let b_target = BasicBlock {
        start: target,
        end: addr(0x2005),
        instructions: vec![insn(target, 5, forms::RET, vec![])],
        terminator: EdgeKind::Return,
    };

    let b_fallthrough = BasicBlock {
        start: fallthrough,
        end: addr(0x1015),
        instructions: vec![insn(fallthrough, 5, forms::RET, vec![])],
        terminator: EdgeKind::Return,
    };

    let mut blocks = BTreeMap::new();
    blocks.insert(b1.start, b1);
    blocks.insert(b_target.start, b_target);
    blocks.insert(b_fallthrough.start, b_fallthrough);

    let edges = vec![
        CfgEdge {
            from: addr(0x100B),
            to: Some(target),
            kind: EdgeKind::ConditionalTaken,
        },
        CfgEdge {
            from: addr(0x100B),
            to: Some(fallthrough),
            kind: EdgeKind::FallThrough,
        },
    ];

    let mut cfg = Cfg { entry, blocks, edges };

    let detector = OpaquePredicateDetector::new();
    let detected = detector.detect_block(cfg.blocks.get(&entry).unwrap());
    assert!(detected.is_some(), "Context invariant must be detected");
    assert_eq!(detected.unwrap().kind, OpaquePredicateKind::ContextInvariant);

    let report = prune_opaque_predicates(&mut cfg, PruningLimits::default());
    assert_eq!(report.eliminated_branches, 1);
    assert_eq!(report.straightened_blocks, 1);
}

// ── Test 8: angryier-expr MBA Deobfuscation Integration ───────────────────────

#[test]
fn test_mba_double_negation_simplification() {
    let entry = addr(0x1000);
    let target = addr(0x2000);
    let fallthrough = addr(0x1010);

    // Double negation: rbx = not(not(rax)) => rbx == rax
    let b1_insns = vec![
        insn(addr(0x1000), 3, forms::MOV_R64_R64, vec![r64_write(1, 0), r64_read(0, 1)]),
        insn(addr(0x1003), 3, forms::NOT_R64, vec![r64_write(1, 0)]),
        insn(addr(0x1006), 3, forms::NOT_R64, vec![r64_write(1, 0)]),
        insn(addr(0x1009), 3, forms::CMP_R64_R64, vec![r64_read(1, 0), r64_read(0, 1)]),
        insn(addr(0x100C), 4, forms::JZ_REL32, vec![rel_branch_op(0x0FF0, 0)]),
    ];

    let b1 = BasicBlock {
        start: entry,
        end: fallthrough,
        instructions: b1_insns,
        terminator: EdgeKind::ConditionalTaken,
    };

    let b_target = BasicBlock {
        start: target,
        end: addr(0x2005),
        instructions: vec![insn(target, 5, forms::RET, vec![])],
        terminator: EdgeKind::Return,
    };

    let b_fallthrough = BasicBlock {
        start: fallthrough,
        end: addr(0x1015),
        instructions: vec![insn(fallthrough, 5, forms::RET, vec![])],
        terminator: EdgeKind::Return,
    };

    let mut blocks = BTreeMap::new();
    blocks.insert(b1.start, b1);
    blocks.insert(b_target.start, b_target);
    blocks.insert(b_fallthrough.start, b_fallthrough);

    let edges = vec![
        CfgEdge {
            from: addr(0x100C),
            to: Some(target),
            kind: EdgeKind::ConditionalTaken,
        },
        CfgEdge {
            from: addr(0x100C),
            to: Some(fallthrough),
            kind: EdgeKind::FallThrough,
        },
    ];

    let mut cfg = Cfg { entry, blocks, edges };

    let detector = OpaquePredicateDetector::new();
    let detected = detector.detect_block(cfg.blocks.get(&entry).unwrap());
    assert!(detected.is_some(), "Double negation MBA must simplify to equality");
    assert_eq!(detected.unwrap().kind, OpaquePredicateKind::TautologyAlwaysTrue);

    let report = prune_opaque_predicates(&mut cfg, PruningLimits::default());
    assert_eq!(report.eliminated_branches, 1);
    assert_eq!(report.purged_dead_blocks, 1);
    assert_eq!(report.straightened_blocks, 1);
    assert_eq!(cfg.blocks.len(), 1);
}

// ── Test 9: Opaque Diamond Collapse (P -> Dead -> S and P -> S) ───────────────

#[test]
fn test_opaque_diamond_de_spaghettification() {
    // Classic OLLVM / Themida opaque diamond:
    //   Block P (0x1000): parity tautology (always false JNZ to Dead 0x2000, fallthrough to S 0x1015)
    //   Block Dead (0x2000): junk instructions ending with unconditional JMP back to S (0x1015)
    //   Block S (0x1015): real continuation ending with RET
    // Without dead-block & dead-edge purging, S has 2 incoming edges (P->S and Dead->S) so P and S
    // cannot straighten. With de_spaghettify, Dead and Dead->S are purged, and P+S collapse into 1 block.
    let entry = addr(0x1000);
    let dead_addr = addr(0x2000);
    let real_succ = addr(0x1015);

    let b_p = BasicBlock {
        start: entry,
        end: real_succ,
        instructions: vec![
            insn(addr(0x1000), 3, forms::MOV_R64_R64, vec![r64_write(1, 0), r64_read(0, 1)]),
            insn(addr(0x1003), 3, forms::INC_R64, vec![r64_write(1, 0)]),
            insn(addr(0x1006), 3, forms::IMUL_R64_R64, vec![r64_write(1, 0), r64_read(0, 1)]),
            insn(addr(0x1009), 6, forms::TEST_R64_IMM32, vec![r64_read(1, 0), imm_op(1, 32, 1)]),
            insn(addr(0x100F), 6, forms::JNZ_REL32, vec![rel_branch_op(0x0FEB, 0)]),
        ],
        terminator: EdgeKind::ConditionalTaken,
    };

    let b_dead = BasicBlock {
        start: dead_addr,
        end: addr(0x200B),
        instructions: vec![
            insn(dead_addr, 5, forms::MOV_R64_IMM64, vec![r64_write(0, 0), imm_op(0xDEAD, 64, 1)]),
            insn(addr(0x2005), 6, forms::JMP_REL32, vec![rel_branch_op(-0x0FF6, 0)]),
        ],
        terminator: EdgeKind::Unconditional,
    };

    let b_succ = BasicBlock {
        start: real_succ,
        end: addr(0x101B),
        instructions: vec![
            insn(real_succ, 5, forms::MOV_R64_IMM64, vec![r64_write(0, 0), imm_op(1, 64, 1)]),
            insn(addr(0x101A), 1, forms::RET, vec![]),
        ],
        terminator: EdgeKind::Return,
    };

    let mut blocks = BTreeMap::new();
    blocks.insert(b_p.start, b_p);
    blocks.insert(b_dead.start, b_dead);
    blocks.insert(b_succ.start, b_succ);

    let edges = vec![
        CfgEdge {
            from: addr(0x100F),
            to: Some(dead_addr),
            kind: EdgeKind::ConditionalTaken,
        },
        CfgEdge {
            from: addr(0x100F),
            to: Some(real_succ),
            kind: EdgeKind::FallThrough,
        },
        CfgEdge {
            from: addr(0x2005),
            to: Some(real_succ),
            kind: EdgeKind::Unconditional,
        },
    ];

    let mut cfg = Cfg { entry, blocks, edges };
    let report = cfg.de_spaghettify(PruningLimits::default());

    assert_eq!(report.initial_blocks, 3);
    assert_eq!(report.eliminated_branches, 1);
    assert_eq!(report.purged_dead_blocks, 1, "Dead diamond branch block must be purged");
    assert_eq!(report.purged_dead_edges, 1, "Reconverging edge Dead -> S must be purged");
    assert_eq!(report.straightened_blocks, 1, "P and S must straighten once Dead -> S is purged");
    assert_eq!(report.final_blocks, 1, "Entire 3-block diamond must collapse into 1 block");
    assert_eq!(report.final_edges, 0);
    assert!(!cfg.blocks.contains_key(&dead_addr));
}

// ── Test 10: Opaque Bogus Loop Destruction ────────────────────────────────────

#[test]
fn test_opaque_bogus_loop_destruction() {
    // Protectors inject fake back-edges guarded by opaque predicates to manufacture bogus natural loops:
    //   Header (0x1000) -> Body (0x1010)
    //   Body (0x1010) has opaque false JNZ -> BogusLatch (0x3000), fallthrough -> Exit (0x1025)
    //   BogusLatch (0x3000) -> jumps back to Header (0x1000)
    let header = addr(0x1000);
    let body = addr(0x1010);
    let bogus_latch = addr(0x3000);
    let exit = addr(0x1025);

    let b_header = BasicBlock {
        start: header,
        end: body,
        instructions: vec![
            insn(header, 5, forms::MOV_R64_IMM64, vec![r64_write(2, 0), imm_op(10, 64, 1)]),
        ],
        terminator: EdgeKind::FallThrough,
    };

    let b_body = BasicBlock {
        start: body,
        end: exit,
        instructions: vec![
            insn(addr(0x1010), 3, forms::CMP_R64_R64, vec![r64_read(0, 0), r64_read(0, 1)]),
            insn(addr(0x1013), 6, forms::JNZ_REL32, vec![rel_branch_op(0x1FE7, 0)]),
        ],
        terminator: EdgeKind::ConditionalTaken,
    };

    let b_latch = BasicBlock {
        start: bogus_latch,
        end: addr(0x3006),
        instructions: vec![
            insn(bogus_latch, 6, forms::JMP_REL32, vec![rel_branch_op(-0x2006, 0)]),
        ],
        terminator: EdgeKind::Unconditional,
    };

    let b_exit = BasicBlock {
        start: exit,
        end: addr(0x1026),
        instructions: vec![insn(exit, 1, forms::RET, vec![])],
        terminator: EdgeKind::Return,
    };

    let mut blocks = BTreeMap::new();
    blocks.insert(b_header.start, b_header);
    blocks.insert(b_body.start, b_body);
    blocks.insert(b_latch.start, b_latch);
    blocks.insert(b_exit.start, b_exit);

    let edges = vec![
        CfgEdge {
            from: header,
            to: Some(body),
            kind: EdgeKind::FallThrough,
        },
        CfgEdge {
            from: addr(0x1013),
            to: Some(bogus_latch),
            kind: EdgeKind::ConditionalTaken,
        },
        CfgEdge {
            from: addr(0x1013),
            to: Some(exit),
            kind: EdgeKind::FallThrough,
        },
        CfgEdge {
            from: bogus_latch,
            to: Some(header),
            kind: EdgeKind::Unconditional,
        },
    ];

    let mut cfg = Cfg {
        entry: header,
        blocks,
        edges,
    };

    assert_eq!(cfg.loops().len(), 1, "Before pruning, CFG contains 1 bogus natural loop");

    let report = cfg.de_spaghettify(PruningLimits::default());
    assert_eq!(report.initial_loops, 1);
    assert_eq!(report.final_loops, 0, "Bogus natural loop must be completely eliminated");
    assert_eq!(report.purged_dead_blocks, 1);
    assert_eq!(report.final_blocks, 1, "Header, Body, and Exit must collapse into 1 linear block");
    assert!(cfg.loops().is_empty());
}

// ── Test 11: Multi-Block Cyclic Dead Subgraph Cascade Purge ───────────────────

#[test]
fn test_cyclic_dead_subgraph_cascade_purge() {
    // Entry (0x1000) has opaque true JZ -> RealExit (0x1020), dead fallthrough -> Dead1 (0x2000).
    // Dead1 (0x2000) <-> Dead2 (0x2010) form a disconnected loop that also branches into RealExit (0x1020).
    let entry = addr(0x1000);
    let real_exit = addr(0x1020);
    let dead1 = addr(0x2000);
    let dead2 = addr(0x2010);

    let b_entry = BasicBlock {
        start: entry,
        end: addr(0x1010),
        instructions: vec![
            insn(addr(0x1000), 3, forms::CMP_R64_R64, vec![r64_read(3, 0), r64_read(3, 1)]),
            insn(addr(0x1003), 6, forms::JZ_REL32, vec![rel_branch_op(0x17, 0)]),
        ],
        terminator: EdgeKind::ConditionalTaken,
    };

    let b_dead1 = BasicBlock {
        start: dead1,
        end: addr(0x2006),
        instructions: vec![insn(dead1, 6, forms::JMP_REL32, vec![rel_branch_op(0x0A, 0)])],
        terminator: EdgeKind::Unconditional,
    };

    let b_dead2 = BasicBlock {
        start: dead2,
        end: addr(0x2016),
        instructions: vec![insn(dead2, 6, forms::JZ_REL32, vec![rel_branch_op(-0x16, 0)])],
        terminator: EdgeKind::ConditionalTaken,
    };

    let b_exit = BasicBlock {
        start: real_exit,
        end: addr(0x1021),
        instructions: vec![insn(real_exit, 1, forms::RET, vec![])],
        terminator: EdgeKind::Return,
    };

    let mut blocks = BTreeMap::new();
    blocks.insert(b_entry.start, b_entry);
    blocks.insert(b_dead1.start, b_dead1);
    blocks.insert(b_dead2.start, b_dead2);
    blocks.insert(b_exit.start, b_exit);

    let edges = vec![
        CfgEdge {
            from: addr(0x1003),
            to: Some(real_exit),
            kind: EdgeKind::ConditionalTaken,
        },
        CfgEdge {
            from: addr(0x1003),
            to: Some(dead1),
            kind: EdgeKind::FallThrough,
        },
        CfgEdge {
            from: dead1,
            to: Some(dead2),
            kind: EdgeKind::Unconditional,
        },
        CfgEdge {
            from: dead2,
            to: Some(dead1),
            kind: EdgeKind::ConditionalTaken,
        },
        CfgEdge {
            from: dead2,
            to: Some(real_exit),
            kind: EdgeKind::FallThrough,
        },
    ];

    let mut cfg = Cfg { entry, blocks, edges };
    let report = cfg.de_spaghettify(PruningLimits::default());

    assert_eq!(report.purged_dead_blocks, 2, "Both blocks in the dead cycle must be purged");
    assert_eq!(report.purged_dead_edges, 3, "All 3 edges in the dead subgraph must be purged");
    assert_eq!(report.final_blocks, 1, "Entry and RealExit must straighten into 1 block");
    let merged = cfg.blocks.get(&entry).unwrap();
    assert!(
        !merged.instructions.iter().any(|i| i.form_id == forms::JMP_REL32),
        "Seam JMP_REL32 must be neutralized to NOP during straightening"
    );
}

// ── Test 12: Cross-Block Chained Opaque Predicates (Multi-Pass Fixpoint) ──────

#[test]
fn test_cross_block_chained_opaque_predicates() {
    // Block 1 (0x1000) computes rbx = rax * (rax + 1) AND has an identity opaque predicate (cmp rcx, rcx; jz B2).
    // Block 2 (0x1020) uses rbx from Block 1 in a second opaque predicate (test rbx, 1; jnz Dead2, fallthrough B3).
    // Pass 1 straightens Block 1 + Block 2, allowing Pass 2 to see rbx's parity invariant across the seam!
    let b1_addr = addr(0x1000);
    let b2_addr = addr(0x1020);
    let b3_addr = addr(0x1030);
    let dead1_addr = addr(0x2000);
    let dead2_addr = addr(0x3000);

    let b1 = BasicBlock {
        start: b1_addr,
        end: b2_addr,
        instructions: vec![
            insn(addr(0x1000), 3, forms::MOV_R64_R64, vec![r64_write(1, 0), r64_read(0, 1)]),
            insn(addr(0x1003), 3, forms::INC_R64, vec![r64_write(1, 0)]),
            insn(addr(0x1006), 3, forms::IMUL_R64_R64, vec![r64_write(1, 0), r64_read(0, 1)]),
            insn(addr(0x1009), 3, forms::CMP_R64_R64, vec![r64_read(2, 0), r64_read(2, 1)]),
            insn(addr(0x100C), 6, forms::JZ_REL32, vec![rel_branch_op(0x0E, 0)]),
        ],
        terminator: EdgeKind::ConditionalTaken,
    };

    let b2 = BasicBlock {
        start: b2_addr,
        end: b3_addr,
        instructions: vec![
            insn(addr(0x1020), 6, forms::TEST_R64_IMM32, vec![r64_read(1, 0), imm_op(1, 32, 1)]),
            insn(addr(0x1026), 6, forms::JNZ_REL32, vec![rel_branch_op(0x1FD4, 0)]),
        ],
        terminator: EdgeKind::ConditionalTaken,
    };

    let b3 = BasicBlock {
        start: b3_addr,
        end: addr(0x1031),
        instructions: vec![insn(b3_addr, 1, forms::RET, vec![])],
        terminator: EdgeKind::Return,
    };

    let dead1 = BasicBlock {
        start: dead1_addr,
        end: addr(0x2001),
        instructions: vec![insn(dead1_addr, 1, forms::RET, vec![])],
        terminator: EdgeKind::Return,
    };

    let dead2 = BasicBlock {
        start: dead2_addr,
        end: addr(0x3001),
        instructions: vec![insn(dead2_addr, 1, forms::RET, vec![])],
        terminator: EdgeKind::Return,
    };

    let mut blocks = BTreeMap::new();
    blocks.insert(b1.start, b1);
    blocks.insert(b2.start, b2);
    blocks.insert(b3.start, b3);
    blocks.insert(dead1.start, dead1);
    blocks.insert(dead2.start, dead2);

    let edges = vec![
        CfgEdge {
            from: addr(0x100C),
            to: Some(b2_addr),
            kind: EdgeKind::ConditionalTaken,
        },
        CfgEdge {
            from: addr(0x100C),
            to: Some(dead1_addr),
            kind: EdgeKind::FallThrough,
        },
        CfgEdge {
            from: addr(0x1026),
            to: Some(dead2_addr),
            kind: EdgeKind::ConditionalTaken,
        },
        CfgEdge {
            from: addr(0x1026),
            to: Some(b3_addr),
            kind: EdgeKind::FallThrough,
        },
    ];

    let mut cfg = Cfg {
        entry: b1_addr,
        blocks,
        edges,
    };

    let report = cfg.de_spaghettify(PruningLimits::default());
    assert_eq!(report.initial_blocks, 5);
    assert_eq!(report.eliminated_branches, 2, "Both B1 and cross-block B2 opaque branches must be eliminated");
    assert_eq!(report.purged_dead_blocks, 2, "Both dead1 and dead2 must be purged");
    assert_eq!(report.straightened_blocks, 2, "B1+B2+B3 must straighten into 1 block");
    assert_eq!(report.final_blocks, 1);
}

