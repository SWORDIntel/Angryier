//! Conservative, single-block AngryIR effect discovery for VM handlers.
//!
//! This is the bridge between VM-site reconnaissance and output-rooted
//! expression reduction. It enumerates *all* explicit architectural writes,
//! memory reads (including otherwise unused potentially faulting loads), and
//! control transfers before an analyst decides which effects are VM-internal.
//! It never interprets an IR value ID as a symbolic ExprId, never joins paths,
//! and never claims that an instruction sequence is a complete handler.
//!
//! A separate symbolic executor must map each retained SSA value into an
//! expression under a known entry state. Only then can vm_effects simplify it.

use std::collections::BTreeSet;

use angryier_types::ExprId;

use crate::{
    BasicIrVerifier, IrBlock, IrOp, IrPrimitive, IrValueId, IrVerificationError, IrVerifier, RegisterWriteKind,
};

/// An effect in original instruction order. Store ordering must be preserved:
/// aliasing writes cannot be sorted or coalesced without a proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmIrEffect {
    MemoryRead {
        address: IrValueId,
        mask: Option<IrValueId>,
        result: IrValueId,
    },
    MemoryWrite {
        address: IrValueId,
        value: IrValueId,
    },
    RegisterWrite {
        register: u32,
        value: IrValueId,
        kind: RegisterWriteKind,
    },
    Branch {
        condition: IrValueId,
        taken: u64,
        not_taken: u64,
    },
    Jump {
        target: u64,
    },
    IndirectJump {
        target: IrValueId,
    },
    Call {
        target: u64,
    },
    Return,
    Trap {
        vector: u32,
    },
}

/// Inputs referenced by the retained SSA slice. A memory read is represented
/// by its producer value ID; its address/mask are separately traversed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum VmIrSource {
    Register(u32),
    Expression(ExprId),
    MemoryRead(IrValueId),
}

/// Explicitly unresolved semantic obligations. They are not evidence of an
/// actual exception: a primitive may be side-effect-free on a given path.
/// Consumers must not use this static footprint as an equivalence certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmIrCaveat {
    /// General primitives may have exceptional or environment-dependent
    /// semantics not represented by a pure expression DAG.
    PrimitiveRequiresSemanticReview { result: IrValueId, primitive: IrPrimitive },
    /// A block-level inventory is not a whole-handler path or all its exits.
    HandlerBoundaryUnverified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmIrLimits {
    pub max_instructions: usize,
    pub max_dependency_values: usize,
}

impl Default for VmIrLimits {
    fn default() -> Self {
        Self {
            max_instructions: 16_384,
            max_dependency_values: 16_384,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VmIrError {
    InvalidIr(IrVerificationError),
    InstructionBudgetExceeded { required: usize, limit: usize },
    DependencyBudgetExceeded { limit: usize },
    MissingValueProducer(IrValueId),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmIrFootprint {
    /// Effect order matches the IR source order, including all memory writes.
    pub effects: Vec<VmIrEffect>,
    /// SSA values reachable from effect values and memory fault dependencies.
    /// Sorted in producer order (SSA value ID order).
    pub dependencies: Vec<IrValueId>,
    pub sources: Vec<VmIrSource>,
    /// Explicit semantic review work. Never silently interpreted as proof.
    pub caveats: Vec<VmIrCaveat>,
}

/// Discover a full *syntactic* effect footprint of one validated AngryIR
/// block. All loads are included even if their result is otherwise dead,
/// because dropping a load without alias/exception analysis can erase faults.
/// A partial-width register write also implicitly reads the parent register.
///
/// The result is a starting point for a handler effect collector, not a
/// complete handler semantics summary. To analyze multiple blocks, retain
/// each block's independent SSA namespace and explicit path/VM context.
pub fn collect_vm_ir_effects(block: &IrBlock, limits: VmIrLimits) -> Result<VmIrFootprint, VmIrError> {
    if block.instructions.len() > limits.max_instructions {
        return Err(VmIrError::InstructionBudgetExceeded {
            required: block.instructions.len(),
            limit: limits.max_instructions,
        });
    }
    BasicIrVerifier.verify(block).map_err(VmIrError::InvalidIr)?;

    let mut producers: Vec<&IrOp> = Vec::new();
    let mut effects = Vec::new();
    let mut roots = Vec::new();
    let mut sources = BTreeSet::new();
    let mut caveats = Vec::new();

    for instruction in &block.instructions {
        if let Some(result) = instruction.result {
            // Checked by BasicIrVerifier: value IDs are sequential.
            if usize::try_from(result.0).ok() != Some(producers.len()) {
                return Err(VmIrError::MissingValueProducer(result));
            }
            producers.push(&instruction.op);
        }
        match &instruction.op {
            IrOp::WriteRegister { register, value, kind } => {
                effects.push(VmIrEffect::RegisterWrite {
                    register: *register,
                    value: *value,
                    kind: *kind,
                });
                roots.push(*value);
                if matches!(kind, RegisterWriteKind::PreserveParent { .. }) {
                    sources.insert(VmIrSource::Register(*register));
                }
            }
            IrOp::Store { address, value } => {
                effects.push(VmIrEffect::MemoryWrite {
                    address: *address,
                    value: *value,
                });
                roots.extend([*address, *value]);
            }
            IrOp::Load { address, .. } => {
                let result = instruction.result.ok_or(VmIrError::MissingValueProducer(IrValueId(
                    u32::try_from(producers.len()).unwrap_or(u32::MAX),
                )))?;
                effects.push(VmIrEffect::MemoryRead {
                    address: *address,
                    mask: None,
                    result,
                });
                roots.push(result);
            }
            IrOp::PredicatedVectorLoad { address, mask, .. } => {
                let result = instruction.result.ok_or(VmIrError::MissingValueProducer(IrValueId(
                    u32::try_from(producers.len()).unwrap_or(u32::MAX),
                )))?;
                effects.push(VmIrEffect::MemoryRead {
                    address: *address,
                    mask: Some(*mask),
                    result,
                });
                roots.push(result);
            }
            IrOp::Branch {
                condition,
                taken,
                not_taken,
            } => {
                effects.push(VmIrEffect::Branch {
                    condition: *condition,
                    taken: *taken,
                    not_taken: *not_taken,
                });
                roots.push(*condition);
            }
            IrOp::Jump { target } => effects.push(VmIrEffect::Jump { target: *target }),
            IrOp::JumpIndirect { target } => {
                effects.push(VmIrEffect::IndirectJump { target: *target });
                roots.push(*target);
            }
            IrOp::Call { target } => effects.push(VmIrEffect::Call { target: *target }),
            IrOp::Return => effects.push(VmIrEffect::Return),
            IrOp::Trap { vector } => effects.push(VmIrEffect::Trap { vector: *vector }),
            IrOp::Primitive { op, .. } => {
                if let Some(result) = instruction.result {
                    caveats.push(VmIrCaveat::PrimitiveRequiresSemanticReview { result, primitive: *op });
                }
            }
            IrOp::Constant { .. } | IrOp::ExprRef { .. } | IrOp::ReadRegister { .. } => {}
        }
    }

    let mut seen = BTreeSet::new();
    let mut pending = roots;
    while let Some(value) = pending.pop() {
        if seen.contains(&value) {
            continue;
        }
        if seen.len() >= limits.max_dependency_values {
            return Err(VmIrError::DependencyBudgetExceeded {
                limit: limits.max_dependency_values,
            });
        }
        let index = usize::try_from(value.0).map_err(|_| VmIrError::MissingValueProducer(value))?;
        let producer = producers.get(index).ok_or(VmIrError::MissingValueProducer(value))?;
        seen.insert(value);
        match producer {
            IrOp::ReadRegister { register, .. } => {
                sources.insert(VmIrSource::Register(*register));
            }
            IrOp::ExprRef { expression, .. } => {
                sources.insert(VmIrSource::Expression(*expression));
            }
            IrOp::Load { address, .. } => {
                sources.insert(VmIrSource::MemoryRead(value));
                pending.push(*address);
            }
            IrOp::PredicatedVectorLoad { address, mask, .. } => {
                sources.insert(VmIrSource::MemoryRead(value));
                pending.extend([*address, *mask]);
            }
            IrOp::Primitive { inputs, .. } => pending.extend(inputs.iter().copied()),
            IrOp::Constant { .. } => {}
            // The IR verifier requires every produced value to come from one
            // of the value-generating operations above.
            _ => return Err(VmIrError::MissingValueProducer(value)),
        }
    }

    caveats.push(VmIrCaveat::HandlerBoundaryUnverified);
    Ok(VmIrFootprint {
        effects,
        dependencies: seen.into_iter().collect(),
        sources: sources.into_iter().collect(),
        caveats,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IrBlockKey, IrInstruction, IrPrimitive, IrType};
    use angryier_types::{BlockId, ContentId, ImageId, TargetProfileId};

    fn block(instructions: Vec<IrInstruction>) -> IrBlock {
        IrBlock {
            key: IrBlockKey {
                image: ImageId(1),
                block: BlockId(1),
                address: 0x1000,
                semantic_content: ContentId([2; 32]),
                target_profile: TargetProfileId(1),
                code_versions: Vec::new(),
            },
            instructions,
        }
    }

    fn value(id: u32, op: IrOp) -> IrInstruction {
        IrInstruction {
            result: Some(IrValueId(id)),
            op,
        }
    }

    fn effect(op: IrOp) -> IrInstruction {
        IrInstruction { result: None, op }
    }

    fn limits() -> VmIrLimits {
        VmIrLimits::default()
    }

    #[test]
    fn preserves_unused_faulting_load_and_ordered_aliasing_writes() -> Result<(), String> {
        let b = block(vec![
            value(
                0,
                IrOp::ReadRegister {
                    register: 14,
                    ty: IrType::Bits(64),
                },
            ),
            value(
                1,
                IrOp::Load {
                    address: IrValueId(0),
                    ty: IrType::Bits(64),
                },
            ),
            value(
                2,
                IrOp::Constant {
                    ty: IrType::Bits(64),
                    bytes_le: 7u64.to_le_bytes().to_vec(),
                },
            ),
            effect(IrOp::Store {
                address: IrValueId(0),
                value: IrValueId(2),
            }),
            effect(IrOp::Store {
                address: IrValueId(0),
                value: IrValueId(2),
            }),
            effect(IrOp::Return),
        ]);
        let p = collect_vm_ir_effects(&b, limits()).map_err(|error| format!("{error:?}"))?;
        assert_eq!(p.effects.len(), 4);
        assert!(matches!(
            p.effects[0],
            VmIrEffect::MemoryRead {
                result: IrValueId(1),
                ..
            }
        ));
        assert_eq!(p.effects[1], p.effects[2]);
        assert_eq!(
            p.sources,
            vec![VmIrSource::Register(14), VmIrSource::MemoryRead(IrValueId(1)),]
        );
        assert_eq!(p.dependencies, vec![IrValueId(0), IrValueId(1), IrValueId(2)]);
        Ok(())
    }

    #[test]
    fn retains_mask_and_indirect_dispatch_dependencies() -> Result<(), String> {
        let b = block(vec![
            value(
                0,
                IrOp::ReadRegister {
                    register: 10,
                    ty: IrType::Bits(64),
                },
            ),
            value(
                1,
                IrOp::ReadRegister {
                    register: 11,
                    ty: IrType::Bits(8),
                },
            ),
            value(
                2,
                IrOp::PredicatedVectorLoad {
                    address: IrValueId(0),
                    mask: IrValueId(1),
                    ty: IrType::Vector {
                        width_bits: 256,
                        lane_bits: 32,
                    },
                },
            ),
            value(
                3,
                IrOp::ExprRef {
                    expression: ExprId(55),
                    ty: IrType::Bits(64),
                },
            ),
            effect(IrOp::JumpIndirect { target: IrValueId(3) }),
        ]);
        let p = collect_vm_ir_effects(&b, limits()).map_err(|error| format!("{error:?}"))?;
        assert_eq!(
            p.sources,
            vec![
                VmIrSource::Register(10),
                VmIrSource::Register(11),
                VmIrSource::Expression(ExprId(55)),
                VmIrSource::MemoryRead(IrValueId(2)),
            ]
        );
        assert!(p.dependencies.contains(&IrValueId(1)));
        assert!(
            p.effects
                .iter()
                .any(|effect| matches!(effect, VmIrEffect::IndirectJump { target: IrValueId(3) }))
        );
        Ok(())
    }

    #[test]
    fn partial_register_update_keeps_implicit_parent_and_path_condition() -> Result<(), String> {
        let b = block(vec![
            value(
                0,
                IrOp::Constant {
                    ty: IrType::Bits(8),
                    bytes_le: vec![1],
                },
            ),
            effect(IrOp::WriteRegister {
                register: 4,
                value: IrValueId(0),
                kind: RegisterWriteKind::PreserveParent {
                    bit_offset: 8,
                    width_bits: 8,
                },
            }),
            effect(IrOp::Branch {
                condition: IrValueId(0),
                taken: 0x10,
                not_taken: 0x20,
            }),
        ]);
        let p = collect_vm_ir_effects(&b, limits()).map_err(|error| format!("{error:?}"))?;
        assert_eq!(p.sources, vec![VmIrSource::Register(4)]);
        assert!(matches!(
            p.effects[1],
            VmIrEffect::Branch {
                condition: IrValueId(0),
                ..
            }
        ));
        Ok(())
    }

    #[test]
    fn refuses_unverified_ir_and_budgets_without_partial_results() -> Result<(), String> {
        let bad = block(vec![effect(IrOp::Store {
            address: IrValueId(44),
            value: IrValueId(45),
        })]);
        assert!(matches!(
            collect_vm_ir_effects(&bad, limits()),
            Err(VmIrError::InvalidIr(_))
        ));
        let b = block(vec![
            value(
                0,
                IrOp::ReadRegister {
                    register: 1,
                    ty: IrType::Bits(64),
                },
            ),
            value(
                1,
                IrOp::ReadRegister {
                    register: 2,
                    ty: IrType::Bits(64),
                },
            ),
            value(
                2,
                IrOp::Primitive {
                    op: IrPrimitive::Add,
                    ty: IrType::Bits(64),
                    inputs: vec![IrValueId(0), IrValueId(1)],
                },
            ),
            effect(IrOp::WriteRegister {
                register: 3,
                value: IrValueId(2),
                kind: RegisterWriteKind::ReplaceParent,
            }),
        ]);
        assert!(matches!(
            collect_vm_ir_effects(
                &b,
                VmIrLimits {
                    max_instructions: 2,
                    max_dependency_values: 8
                }
            ),
            Err(VmIrError::InstructionBudgetExceeded { .. })
        ));
        assert!(matches!(
            collect_vm_ir_effects(
                &b,
                VmIrLimits {
                    max_instructions: 8,
                    max_dependency_values: 2
                }
            ),
            Err(VmIrError::DependencyBudgetExceeded { .. })
        ));
        assert!(
            matches!(collect_vm_ir_effects(&b, limits()), Ok(VmIrFootprint { caveats, .. }) if caveats.iter().any(|c| matches!(c, VmIrCaveat::PrimitiveRequiresSemanticReview { .. })))
        );
        Ok(())
    }
}
