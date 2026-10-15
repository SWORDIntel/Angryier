//! Observed multi-block VM-handler traces with conservative AngryIR footprints.
//!
//! The trace caller supplies execution observations from a *single* capture
//! and a *single* thread, including before/after PC, VPC and VM-context hash.
//! A validated IR block is NOT an executed handler, and the code below never
//! discovers a handler boundary from linear disassembly or proves semantics.
//!
//! Each AngryIR block has an independent SSA value namespace: IrValueId(0)
//! in step 1 is unrelated to IrValueId(0) in step 0. Every exported
//! dependency/source/effect is therefore explicitly scoped to its trace step.
//!
//! Ordered memory operations and possibly faulting loads remain retained.
//! Conditional control choices are checked against observed successors,
//! while indirect transfers and unproven fallthroughs remain visible caveats.
//! This is a trace-derived syntactic footprint, never a substitute for
//! differential replay and independent state/effect verification.

use std::collections::BTreeMap;

use angryier_types::{Address, CodePageId, CodePageVersion, ImageId, TargetProfileId};

use crate::{
    IrBlock, IrOp, IrPrimitive, IrValueId,
    vm_footprint::{VmIrCaveat, VmIrEffect, VmIrError, VmIrLimits, VmIrSource, collect_vm_ir_effects},
};

/// Exact observed machine location. Context digests bind all relevant VM
/// state as supplied by the observer, not authenticated by this module.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmObservedLocation {
    pub native_pc: Address,
    pub virtual_pc: Address,
    pub context_digest: [u8; 32],
}

/// Cross-step capture identity. These digests must be computed by the
/// producer from exact byte/state/capture evidence, not from guessed values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmTraceIdentity {
    pub image: ImageId,
    pub target_profile: TargetProfileId,
    pub executable_digest: [u8; 32],
    pub capture_digest: [u8; 32],
    pub initial_state_digest: [u8; 32],
}

/// One observed execution of a *specific* AngryIR block. An IR block can
/// appear multiple times with different VPC/context values. The code epoch
/// increments whenever executable page versions may change, e.g. after
/// self-modification. Code-version guards must agree within one epoch.
#[derive(Clone, Copy, Debug)]
pub struct VmObservedBlock<'a> {
    pub block: &'a IrBlock,
    pub before: VmObservedLocation,
    pub after: VmObservedLocation,
    pub code_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmTraceLimits {
    pub max_steps: usize,
    pub max_instructions: usize,
    pub max_effects: usize,
    pub max_dependencies: usize,
}

impl Default for VmTraceLimits {
    fn default() -> Self {
        Self {
            max_steps: 4_096,
            max_instructions: 65_536,
            max_effects: 65_536,
            max_dependencies: 131_072,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VmTraceError {
    EmptyTrace,
    MissingCaptureIdentity,
    StepLimitExceeded { required: usize, limit: usize },
    InstructionLimitExceeded { required: usize, limit: usize },
    EffectLimitExceeded { required: usize, limit: usize },
    DependencyLimitExceeded { required: usize, limit: usize },
    BlockIdentityMismatch { step: usize },
    EntryMismatch,
    ExitMismatch,
    DisconnectedTransition { step: usize },
    CodeEpochRegressed { step: usize },
    CodeVersionConflict { step: usize, page: CodePageId },
    Ir { step: usize, error: VmIrError },
    DirectControlMismatch { step: usize, observed: Address },
    TrapRequiresExceptionEvidence { step: usize },
}

/// An IR value ID scoped to one execution step. Converting this to an
/// expression-arena ExprId by numeric cast is always incorrect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct VmScopedValue {
    pub step: usize,
    pub value: IrValueId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmScopedEffect {
    pub step: usize,
    pub effect: VmIrEffect,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct VmScopedSource {
    pub step: usize,
    pub source: VmIrSource,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VmTraceCaveat {
    /// Primitive operation might fault or depend on environment semantics.
    PrimitiveReview {
        step: usize,
        value: IrValueId,
        primitive: IrPrimitive,
    },
    /// The observer supplied the next PC but the IR does not prove it.
    IndirectTargetObservedOnly { step: usize },
    /// The IR has no explicit terminator; next-PC was only observed.
    FallthroughObservedOnly { step: usize },
    /// Execution crossed a code-epoch boundary; replay must validate both.
    ExecutableCodeEpochChanged { step: usize },
    /// The path's start/end were supplied, not independently proven.
    HandlerBoundaryObserverSupplied,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmObservedEdge {
    pub from: VmObservedLocation,
    pub to: VmObservedLocation,
    pub code_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmTraceFootprint {
    /// Ordered effects, preserving stores and loads even across revisits.
    pub effects: Vec<VmScopedEffect>,
    /// Dependencies sorted within each block, but never conflated across
    /// independently numbered SSA namespaces.
    pub dependencies: Vec<VmScopedValue>,
    pub sources: Vec<VmScopedSource>,
    pub edges: Vec<VmObservedEdge>,
    /// Explicitly observed branch predicates and their selected directions.
    pub chosen_branches: Vec<(VmScopedValue, bool)>,
    pub caveats: Vec<VmTraceCaveat>,
    pub total_instructions: usize,
}

/// Build an *observational* footprint for one caller-declared VM handler
/// execution. The entry/exit observations are separately supplied by the
/// observer, and every intermediate after-state must match the next
/// before-state, including VPC and context identity.
///
/// Direct jumps/calls and conditional branches are checked against their
/// declared IR targets; a trap cannot be treated as an ordinary successor.
/// Unmapped indirect targets and implicit fallthroughs are retained as
/// explicit uncertainty, never promoted to proof.
pub fn collect_observed_vm_trace(
    identity: VmTraceIdentity,
    entry: VmObservedLocation,
    exit: VmObservedLocation,
    steps: &[VmObservedBlock<'_>],
    limits: VmTraceLimits,
) -> Result<VmTraceFootprint, VmTraceError> {
    if steps.is_empty() {
        return Err(VmTraceError::EmptyTrace);
    }
    if [
        identity.executable_digest,
        identity.capture_digest,
        identity.initial_state_digest,
    ]
    .iter()
    .any(|digest| *digest == [0; 32])
    {
        return Err(VmTraceError::MissingCaptureIdentity);
    }
    if steps.len() > limits.max_steps {
        return Err(VmTraceError::StepLimitExceeded {
            required: steps.len(),
            limit: limits.max_steps,
        });
    }
    if steps[0].before != entry {
        return Err(VmTraceError::EntryMismatch);
    }
    if steps[steps.len() - 1].after != exit {
        return Err(VmTraceError::ExitMismatch);
    }

    let mut effects = Vec::new();
    let mut dependencies = Vec::new();
    let mut sources = Vec::new();
    let mut edges = Vec::new();
    let mut chosen_branches = Vec::new();
    let mut caveats = vec![VmTraceCaveat::HandlerBoundaryObserverSupplied];
    let mut total_instructions = 0usize;
    let mut code_versions: BTreeMap<(u64, CodePageId), CodePageVersion> = BTreeMap::new();

    for (index, step) in steps.iter().enumerate() {
        if step.before.native_pc != step.block.key.address
            || step.block.key.image != identity.image
            || step.block.key.target_profile != identity.target_profile
            || step.before.context_digest == [0; 32]
            || step.after.context_digest == [0; 32]
        {
            return Err(VmTraceError::BlockIdentityMismatch { step: index });
        }
        if index > 0 {
            if steps[index - 1].after != step.before {
                return Err(VmTraceError::DisconnectedTransition { step: index });
            }
            if step.code_epoch < steps[index - 1].code_epoch {
                return Err(VmTraceError::CodeEpochRegressed { step: index });
            }
            if step.code_epoch != steps[index - 1].code_epoch {
                caveats.push(VmTraceCaveat::ExecutableCodeEpochChanged { step: index });
            }
        }
        for guard in &step.block.key.code_versions {
            let key = (step.code_epoch, guard.page);
            if let Some(previous) = code_versions.insert(key, guard.version)
                && previous != guard.version
            {
                return Err(VmTraceError::CodeVersionConflict {
                    step: index,
                    page: guard.page,
                });
            }
        }

        total_instructions = total_instructions.saturating_add(step.block.instructions.len());
        if total_instructions > limits.max_instructions {
            return Err(VmTraceError::InstructionLimitExceeded {
                required: total_instructions,
                limit: limits.max_instructions,
            });
        }
        let block_report = collect_vm_ir_effects(
            step.block,
            VmIrLimits {
                max_instructions: limits.max_instructions,
                max_dependency_values: limits.max_dependencies,
            },
        )
        .map_err(|error| VmTraceError::Ir { step: index, error })?;

        let new_effect_count = effects.len().saturating_add(block_report.effects.len());
        if new_effect_count > limits.max_effects {
            return Err(VmTraceError::EffectLimitExceeded {
                required: new_effect_count,
                limit: limits.max_effects,
            });
        }
        let new_dependency_count = dependencies.len().saturating_add(block_report.dependencies.len());
        if new_dependency_count > limits.max_dependencies {
            return Err(VmTraceError::DependencyLimitExceeded {
                required: new_dependency_count,
                limit: limits.max_dependencies,
            });
        }

        for effect in block_report.effects {
            effects.push(VmScopedEffect { step: index, effect });
        }
        for value in block_report.dependencies {
            dependencies.push(VmScopedValue { step: index, value });
        }
        for source in block_report.sources {
            sources.push(VmScopedSource { step: index, source });
        }
        for caveat in block_report.caveats {
            if let VmIrCaveat::PrimitiveRequiresSemanticReview { result, primitive } = caveat {
                caveats.push(VmTraceCaveat::PrimitiveReview {
                    step: index,
                    value: result,
                    primitive,
                });
            }
        }

        match step.block.instructions.last().map(|instruction| &instruction.op) {
            Some(IrOp::Branch {
                condition,
                taken,
                not_taken,
            }) => {
                let is_taken = if step.after.native_pc == *taken {
                    true
                } else if step.after.native_pc == *not_taken {
                    false
                } else {
                    return Err(VmTraceError::DirectControlMismatch {
                        step: index,
                        observed: step.after.native_pc,
                    });
                };
                chosen_branches.push((
                    VmScopedValue {
                        step: index,
                        value: *condition,
                    },
                    is_taken,
                ));
            }
            Some(IrOp::Jump { target } | IrOp::Call { target }) if *target != step.after.native_pc => {
                return Err(VmTraceError::DirectControlMismatch {
                    step: index,
                    observed: step.after.native_pc,
                });
            }
            Some(IrOp::JumpIndirect { .. } | IrOp::Return) => {
                caveats.push(VmTraceCaveat::IndirectTargetObservedOnly { step: index });
            }
            Some(IrOp::Trap { .. }) => {
                return Err(VmTraceError::TrapRequiresExceptionEvidence { step: index });
            }
            Some(IrOp::Jump { .. } | IrOp::Call { .. }) => {}
            _ => caveats.push(VmTraceCaveat::FallthroughObservedOnly { step: index }),
        }
        edges.push(VmObservedEdge {
            from: step.before,
            to: step.after,
            code_epoch: step.code_epoch,
        });
    }

    Ok(VmTraceFootprint {
        effects,
        dependencies,
        sources,
        edges,
        chosen_branches,
        caveats,
        total_instructions,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IrBlockKey, IrInstruction, IrPrimitive, IrType, RegisterWriteKind};
    use angryier_types::{BlockId, CodeVersionGuard, ContentId};

    fn key(id: u64, address: u64, version: u64) -> IrBlockKey {
        IrBlockKey {
            image: ImageId(1),
            block: BlockId(id),
            address,
            semantic_content: ContentId([5; 32]),
            target_profile: TargetProfileId(1),
            code_versions: vec![CodeVersionGuard {
                page: CodePageId(1),
                version: CodePageVersion(version),
            }],
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

    fn location(native: u64, virtual_pc: u64, digest: u8) -> VmObservedLocation {
        VmObservedLocation {
            native_pc: native,
            virtual_pc,
            context_digest: [digest; 32],
        }
    }

    fn identity() -> VmTraceIdentity {
        VmTraceIdentity {
            image: ImageId(1),
            target_profile: TargetProfileId(1),
            executable_digest: [1; 32],
            capture_digest: [2; 32],
            initial_state_digest: [3; 32],
        }
    }

    fn block_a(version: u64) -> IrBlock {
        IrBlock {
            key: key(1, 0x1000, version),
            instructions: vec![
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
                effect(IrOp::Store {
                    address: IrValueId(0),
                    value: IrValueId(1),
                }),
                effect(IrOp::Store {
                    address: IrValueId(0),
                    value: IrValueId(1),
                }),
                effect(IrOp::Jump { target: 0x2000 }),
            ],
        }
    }

    fn block_b(version: u64) -> IrBlock {
        IrBlock {
            key: key(2, 0x2000, version),
            instructions: vec![
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
                        op: IrPrimitive::Eq,
                        ty: IrType::Bits(1),
                        inputs: vec![IrValueId(0), IrValueId(1)],
                    },
                ),
                effect(IrOp::WriteRegister {
                    register: 9,
                    value: IrValueId(0),
                    kind: RegisterWriteKind::ReplaceParent,
                }),
                effect(IrOp::Branch {
                    condition: IrValueId(2),
                    taken: 0x3000,
                    not_taken: 0x4000,
                }),
            ],
        }
    }

    fn observed<'a>(a: &'a IrBlock, b: &'a IrBlock, second_epoch: u64) -> Vec<VmObservedBlock<'a>> {
        let first = location(0x1000, 0x50, 11);
        let next = location(0x2000, 0x51, 12);
        let end = location(0x3000, 0x53, 14);
        vec![
            VmObservedBlock {
                block: a,
                before: first,
                after: next,
                code_epoch: 0,
            },
            VmObservedBlock {
                block: b,
                before: next,
                after: end,
                code_epoch: second_epoch,
            },
        ]
    }

    #[test]
    fn scopes_ssa_per_step_and_keeps_store_order_and_branch_choice() -> Result<(), String> {
        let a = block_a(1);
        let b = block_b(1);
        let steps = observed(&a, &b, 0);
        let result = collect_observed_vm_trace(
            identity(),
            steps[0].before,
            steps[1].after,
            &steps,
            VmTraceLimits::default(),
        )
        .map_err(|error| format!("{error:?}"))?;
        assert_eq!(result.edges.len(), 2);
        assert_eq!(result.total_instructions, 10);
        assert!(matches!(
            result.effects[1],
            VmScopedEffect {
                step: 0,
                effect: VmIrEffect::MemoryWrite { .. }
            }
        ));
        assert_eq!(result.effects[1], result.effects[2]); // repeated store stays ordered
        assert!(result.dependencies.contains(&VmScopedValue {
            step: 0,
            value: IrValueId(0)
        }));
        assert!(result.dependencies.contains(&VmScopedValue {
            step: 1,
            value: IrValueId(0)
        }));
        assert_eq!(
            result.chosen_branches,
            vec![(
                VmScopedValue {
                    step: 1,
                    value: IrValueId(2)
                },
                true
            ),]
        );
        assert!(result.caveats.contains(&VmTraceCaveat::HandlerBoundaryObserverSupplied));
        Ok(())
    }

    #[test]
    fn disallows_identity_gaps_wrong_targets_and_unproven_traps() {
        let a = block_a(1);
        let b = block_b(1);
        let mut steps = observed(&a, &b, 0);
        steps[1].before.virtual_pc = 0xdead;
        assert_eq!(
            collect_observed_vm_trace(
                identity(),
                steps[0].before,
                steps[1].after,
                &steps,
                VmTraceLimits::default()
            ),
            Err(VmTraceError::DisconnectedTransition { step: 1 }),
        );
        let mut steps = observed(&a, &b, 0);
        steps[0].after.native_pc = 0xdead;
        assert!(matches!(
            collect_observed_vm_trace(
                identity(),
                steps[0].before,
                steps[1].after,
                &steps,
                VmTraceLimits::default()
            ),
            Err(VmTraceError::DisconnectedTransition { .. } | VmTraceError::DirectControlMismatch { .. })
        ));
        let mut bad = block_b(1);
        bad.instructions.pop();
        bad.instructions.push(effect(IrOp::Trap { vector: 3 }));
        let t = observed(&a, &bad, 0);
        assert_eq!(
            collect_observed_vm_trace(identity(), t[0].before, t[1].after, &t, VmTraceLimits::default()),
            Err(VmTraceError::TrapRequiresExceptionEvidence { step: 1 }),
        );
    }

    #[test]
    fn catches_code_version_conflicts_unless_epoch_explicitly_changes() {
        let a = block_a(1);
        let b = block_b(2);
        let trace = observed(&a, &b, 0);
        assert_eq!(
            collect_observed_vm_trace(
                identity(),
                trace[0].before,
                trace[1].after,
                &trace,
                VmTraceLimits::default()
            ),
            Err(VmTraceError::CodeVersionConflict {
                step: 1,
                page: CodePageId(1)
            }),
        );
        let trace = observed(&a, &b, 1);
        let ok = collect_observed_vm_trace(
            identity(),
            trace[0].before,
            trace[1].after,
            &trace,
            VmTraceLimits::default(),
        )
        .map_err(|error| format!("{error:?}"));
        assert!(matches!(ok, Ok(ref p) if p.caveats.contains(&VmTraceCaveat::ExecutableCodeEpochChanged { step: 1 })));
    }

    #[test]
    fn all_budgets_fail_closed_without_truncated_success() {
        let a = block_a(1);
        let b = block_b(1);
        let steps = observed(&a, &b, 0);
        let mut limits = VmTraceLimits::default();
        limits.max_steps = 1;
        assert!(matches!(
            collect_observed_vm_trace(identity(), steps[0].before, steps[1].after, &steps, limits),
            Err(VmTraceError::StepLimitExceeded { .. })
        ));
        limits = VmTraceLimits::default();
        limits.max_instructions = 6;
        assert!(matches!(
            collect_observed_vm_trace(identity(), steps[0].before, steps[1].after, &steps, limits),
            Err(VmTraceError::InstructionLimitExceeded { .. })
        ));
        limits = VmTraceLimits::default();
        limits.max_effects = 2;
        assert!(matches!(
            collect_observed_vm_trace(identity(), steps[0].before, steps[1].after, &steps, limits),
            Err(VmTraceError::EffectLimitExceeded { .. })
        ));
        limits = VmTraceLimits::default();
        limits.max_dependencies = 2;
        assert!(matches!(
            collect_observed_vm_trace(identity(), steps[0].before, steps[1].after, &steps, limits),
            Err(VmTraceError::DependencyLimitExceeded { .. } | VmTraceError::Ir { .. })
        ));
    }

    #[test]
    fn repeat_same_block_is_an_independent_observation() -> Result<(), String> {
        let b = IrBlock {
            key: key(1, 0x1000, 1),
            instructions: vec![
                value(
                    0,
                    IrOp::ReadRegister {
                        register: 1,
                        ty: IrType::Bits(64),
                    },
                ),
                effect(IrOp::Jump { target: 0x1000 }),
            ],
        };
        let s1 = location(0x1000, 0x40, 4);
        let s2 = location(0x1000, 0x41, 5);
        let s3 = location(0x1000, 0x42, 6);
        let steps = [
            VmObservedBlock {
                block: &b,
                before: s1,
                after: s2,
                code_epoch: 0,
            },
            VmObservedBlock {
                block: &b,
                before: s2,
                after: s3,
                code_epoch: 0,
            },
        ];
        let footprint = collect_observed_vm_trace(identity(), s1, s3, &steps, VmTraceLimits::default())
            .map_err(|e| format!("{e:?}"))?;
        assert_eq!(footprint.edges.len(), 2);
        assert_eq!(footprint.total_instructions, 4);
        Ok(())
    }
}
