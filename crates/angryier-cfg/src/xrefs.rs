//! Source-backed direct control-flow and RIP-relative cross-references.
//!
//! This is an index of *known* references, not an indirect-call solver.
//! Every result carries its source instruction. Memory-indirect calls refer
//! to their IAT/vtable SLOT rather than falsely claiming the call target.
//! The index is deterministic and is derived from an existing bounded CFG.

use std::collections::{BTreeMap, BTreeSet};

use angryier_arch::{AccessKind, MemoryBase, OperandKind};
use angryier_types::Address;

use crate::{Cfg, EdgeKind};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum XrefKind {
    Call,
    Branch,
    FallThrough,
    TableDispatch,
    ImportOrIndirectSlot,
    AddressOf,
    Read,
    Write,
    ReadWrite,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Xref {
    pub source: Address,
    pub target: Address,
    pub kind: XrefKind,
    pub table_index: Option<u16>,
}

/// Both incoming and outgoing indexes reuse the same deduplicated evidence.
#[derive(Clone, Debug, Default)]
pub struct XrefIndex {
    by_target: BTreeMap<Address, Vec<Xref>>,
    by_source: BTreeMap<Address, Vec<Xref>>,
    total: usize,
}

impl XrefIndex {
    pub fn from_cfg(cfg: &Cfg) -> Self {
        let mut records = BTreeSet::new();

        for edge in &cfg.edges {
            let Some(target) = edge.to else {
                continue;
            };
            let (kind, table_index) = match edge.kind {
                EdgeKind::Call => (XrefKind::Call, None),
                EdgeKind::ConditionalTaken | EdgeKind::Unconditional => (XrefKind::Branch, None),
                EdgeKind::FallThrough => (XrefKind::FallThrough, None),
                EdgeKind::TableDispatch { index } => (XrefKind::TableDispatch, Some(index)),
                EdgeKind::IndirectCall | EdgeKind::IndirectJump | EdgeKind::Return => continue,
            };
            records.insert(Xref {
                source: edge.from,
                target,
                kind,
                table_index,
            });
        }

        // Literal RIP-relative reads, writes and pointer expressions are
        // anchored to the bytes that actually reference them.
        for block in cfg.blocks.values() {
            for insn in &block.instructions {
                for operand in &insn.operands {
                    let (memory, kind) = match operand.kind {
                        OperandKind::AddressGeneration(mem) => (mem, XrefKind::AddressOf),
                        OperandKind::Memory(mem) => {
                            if matches!(
                                insn.form_id,
                                angryier_semantics_intel64::forms::CALL_INDIRECT_MEM64
                                    | angryier_semantics_intel64::forms::JMP_INDIRECT_MEM64
                            ) {
                                (mem, XrefKind::ImportOrIndirectSlot)
                            } else {
                                let kind = match operand.access {
                                    AccessKind::Read | AccessKind::ConditionalRead => XrefKind::Read,
                                    AccessKind::Write | AccessKind::ConditionalWrite => XrefKind::Write,
                                    AccessKind::ReadWrite
                                    | AccessKind::ReadConditionalWrite
                                    | AccessKind::ConditionalReadWrite => XrefKind::ReadWrite,
                                };
                                (mem, kind)
                            }
                        }
                        _ => continue,
                    };
                    if !matches!(memory.base, Some(MemoryBase::InstructionPointer { .. })) || memory.index.is_some() {
                        continue;
                    }
                    let Some(target) = insn
                        .address
                        .checked_add(u64::from(insn.length))
                        .and_then(|base| base.checked_add_signed(memory.displacement))
                    else {
                        continue;
                    };
                    records.insert(Xref {
                        source: insn.address,
                        target,
                        kind,
                        table_index: None,
                    });
                }
            }
        }

        let mut index = Self::default();
        for record in records {
            index.by_source.entry(record.source).or_default().push(record);
            index.by_target.entry(record.target).or_default().push(record);
            index.total += 1;
        }
        index
    }

    pub fn len(&self) -> usize {
        self.total
    }

    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    pub fn to(&self, target: Address) -> &[Xref] {
        self.by_target.get(&target).map_or(&[], Vec::as_slice)
    }

    pub fn from(&self, source: Address) -> &[Xref] {
        self.by_source.get(&source).map_or(&[], Vec::as_slice)
    }

    /// Only direct, statically identified call sites. Memory-indirect call
    /// slots are intentionally excluded: resolving their targets requires an
    /// import linker, concrete state or explicit evidence from elsewhere.
    pub fn callers_of(&self, callee: Address) -> Vec<Address> {
        self.to(callee)
            .iter()
            .filter(|record| record.kind == XrefKind::Call)
            .map(|record| record.source)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{BasicBlock, CfgEdge};
    use angryier_arch::{
        DecodedInstruction, InstructionModifiers, MemoryOperand, Operand, OperandVisibility, RelativeBranchOperand,
    };

    fn rip_reference(addr: u64, disp: i64, form: u32, access: AccessKind) -> DecodedInstruction {
        DecodedInstruction {
            address: addr,
            length: 6,
            form_id: form,
            features: Vec::new(),
            operands: vec![Operand {
                index: 0,
                width_bits: 64,
                access,
                visibility: OperandVisibility::Explicit,
                kind: OperandKind::Memory(MemoryOperand {
                    memory_index: 0,
                    address_width_bits: 64,
                    segment: None,
                    segment_base: None,
                    base: Some(MemoryBase::InstructionPointer { width_bits: 64 }),
                    index: None,
                    scale: 1,
                    displacement: disp,
                    displacement_width_bits: 32,
                }),
            }],
            modifiers: InstructionModifiers::default(),
        }
    }

    #[test]
    fn exact_direct_caller_and_rip_iat_slot_are_distinct() {
        let instructions = vec![
            rip_reference(
                0x1000,
                -0x10,
                angryier_semantics_intel64::forms::CALL_INDIRECT_MEM64,
                AccessKind::Read,
            ),
            DecodedInstruction {
                address: 0x1006,
                length: 5,
                form_id: angryier_semantics_intel64::forms::CALL_REL32,
                features: Vec::new(),
                operands: vec![Operand {
                    index: 0,
                    width_bits: 32,
                    access: AccessKind::Read,
                    visibility: OperandVisibility::Explicit,
                    kind: OperandKind::RelativeBranch(RelativeBranchOperand {
                        displacement: 0x15,
                        displacement_width_bits: 32,
                    }),
                }],
                modifiers: InstructionModifiers::default(),
            },
        ];
        let cfg = Cfg {
            entry: 0x1000,
            blocks: BTreeMap::from([(
                0x1000,
                BasicBlock {
                    start: 0x1000,
                    end: 0x100b,
                    instructions,
                    terminator: EdgeKind::Call,
                },
            )]),
            edges: vec![
                CfgEdge {
                    from: 0x1006,
                    to: Some(0x1020),
                    kind: EdgeKind::Call,
                },
                CfgEdge {
                    from: 0x1006,
                    to: Some(0x100b),
                    kind: EdgeKind::FallThrough,
                },
                CfgEdge {
                    from: 0x1006,
                    to: Some(0x1020),
                    kind: EdgeKind::Call,
                }, // dedup
            ],
        };
        let idx = XrefIndex::from_cfg(&cfg);
        assert_eq!(idx.callers_of(0x1020), vec![0x1006]);
        assert_eq!(idx.to(0x0ff6)[0].kind, XrefKind::ImportOrIndirectSlot);
        assert!(idx.callers_of(0x0ff6).is_empty());
        assert_eq!(idx.len(), 3);
    }

    #[test]
    fn rip_relative_negative_displacement_and_conditional_access() {
        let insn = rip_reference(
            0x140005000,
            -0x20,
            angryier_semantics_intel64::forms::MOV_R64_MEM64,
            AccessKind::ConditionalRead,
        );
        let cfg = Cfg {
            entry: 0x140005000,
            blocks: BTreeMap::from([(
                0x140005000,
                BasicBlock {
                    start: 0x140005000,
                    end: 0x140005006,
                    instructions: vec![insn],
                    terminator: EdgeKind::IndirectJump,
                },
            )]),
            edges: Vec::new(),
        };
        let idx = XrefIndex::from_cfg(&cfg);
        assert_eq!(idx.to(0x140004fe6)[0].kind, XrefKind::Read);
    }
}
