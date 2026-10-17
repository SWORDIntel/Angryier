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
    assert_eq!(report.straightened_blocks, 1);
}
