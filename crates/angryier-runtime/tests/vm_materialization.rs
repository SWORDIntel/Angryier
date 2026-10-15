//! Native VM symbolic-materialization regression using a synthetic,
 //! two-block handler. No protected target is necessary.
use angryier_arch::{DecodedInstruction, Decoder};
use angryier_expr::ShardedExprArena;
use angryier_ir::{
    IrBlock, IrBlockKey, IrInstruction, IrOp, IrPrimitive, IrType, IrValueId,
    RegisterWriteKind,
    vm_trace::{collect_observed_vm_trace, VmObservedBlock, VmObservedLocation,
        VmTraceIdentity, VmTraceLimits},
};
use angryier_loader::{LoadedImage, Segment};
use angryier_runtime::{
    Runtime, StepOutcome,
    vm_materialize::materialize_vm_handler,
    vm_observe::{VmHandlerCapture, VmHandlerWindow, VmRecordedInstruction},
};
use angryier_types::{
    BlockId, ContentId, ExpressionNormalizationVersion, ImageId,
    SemanticVersion, TargetProfileId,
};

#[derive(Debug)]
struct NoDecoder;
impl Decoder for NoDecoder {
    type Error = String;
    fn decode(&self, _: u64, _: &[u8]) -> Result<DecodedInstruction, Self::Error> {
        Err("decoder not needed".into())
    }
}
fn location(pc: u64, vpc: u64, state: u8) -> VmObservedLocation {
    VmObservedLocation { native_pc: pc, virtual_pc: vpc, context_digest: [state; 32] }
}
fn block(pc: u64, index: u64, source: u32, increment: u64) -> IrBlock {
    let v = |id, op| IrInstruction { result: Some(IrValueId(id)), op };
    let e = |op| IrInstruction { result: None, op };
    let mut instructions = vec![
        v(0, IrOp::ReadRegister { register: source, ty: IrType::Bits(64) }),
        v(1, IrOp::Constant {
            ty: IrType::Bits(64), bytes_le: increment.to_le_bytes().to_vec(),
        }),
        v(2, IrOp::Primitive {
            op: IrPrimitive::Add, ty: IrType::Bits(64),
            inputs: vec![IrValueId(0), IrValueId(1)],
        }),
    ];
    if index == 1 {
        // Faultable load whose value is deliberately unused; expression
        // reduction must not discard its exception obligation.
        instructions.push(v(3, IrOp::Constant {
            ty: IrType::Bits(64), bytes_le: 0x1000u64.to_le_bytes().to_vec(),
        }));
        instructions.push(v(4, IrOp::Load {
            address: IrValueId(3), ty: IrType::Bits(8),
        }));
    }
    instructions.push(e(IrOp::WriteRegister {
        register: 1, value: IrValueId(2), kind: RegisterWriteKind::ReplaceParent,
    }));
    instructions.push(e(IrOp::Jump { target: pc + 1 }));
    IrBlock {
        key: IrBlockKey {
            image: ImageId(1), block: BlockId(index), address: pc,
            semantic_content: ContentId([8; 32]), target_profile: TargetProfileId(1),
            code_versions: Vec::new(),
        },
        instructions,
    }
}
fn fixture() -> Result<VmHandlerCapture, String> {
    let runtime = Runtime::new(NoDecoder, SemanticVersion(1), TargetProfileId(1));
    let image = LoadedImage {
        id: ImageId(1), entry: 0x1000, target_profile: TargetProfileId(1),
        segments: vec![Segment {
            address: 0x1000, bytes: vec![0x90, 0x90, 0xc3],
            readable: true, writable: false, executable: true,
        }],
        symbols: Vec::new(), program_headers: None, dynamic: None, pe: None,
    };
    let process = runtime.load_image(image).map_err(|e| e.to_string())?;
    let a = location(0x1000, 0x50, 1);
    let b = location(0x1001, 0x51, 2);
    let c = location(0x1002, 0x53, 3);
    let window = VmHandlerWindow {
        entry: a, exit: c,
        identity: VmTraceIdentity {
            image: ImageId(1), target_profile: TargetProfileId(1),
            executable_digest: [1; 32], capture_digest: [2; 32],
            initial_state_digest: [3; 32],
        },
        limits: VmTraceLimits::default(),
    };
    let mk = |block: IrBlock, before: VmObservedLocation, after: VmObservedLocation|
        VmRecordedInstruction {
            outcome: StepOutcome::Stepped {
                pc: before.native_pc, next_pc: after.native_pc, length: 1, form_id: 1,
            },
            block, before, after, code_epoch: 0,
        };
    let steps = vec![mk(block(0x1000, 1, 0, 7), a, b),
                     mk(block(0x1001, 2, 1, 2), b, c)];
    let borrowed: Vec<_> = steps.iter().map(|s| VmObservedBlock {
        block: &s.block, before: s.before, after: s.after, code_epoch: s.code_epoch,
    }).collect();
    let footprint = collect_observed_vm_trace(
        window.identity, a, c, &borrowed, window.limits
    ).map_err(|e| format!("{e:?}"))?;
    // Independent expected concrete result for the synthetic two-block
    // ADD handler: initial RAX=0, RCX=7, then RCX=RCX+2 => 9.
    let mut final_process = process.clone();
    final_process.write_register(1, 9).map_err(|error| error.to_string())?;
    final_process.write_pc(0x1002).map_err(|error| error.to_string())?;
    Ok(VmHandlerCapture {
        window,
        initial_state: process.state,
        final_state: final_process.state,
        steps,
        footprint,
    })
}
#[test]
fn two_blocks_reuse_symbolic_state_not_numeric_ssa_ids() -> Result<(), String> {
    let capture = fixture()?;
    let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
    let candidate = materialize_vm_handler(&capture, &arena, 1024)
        .map_err(|e| format!("{e:?}"))?;
    assert_eq!(candidate.reduced.effects.len(), 2);
    assert_eq!(candidate.original_effects.len(), 2);
    assert_eq!(candidate.potentially_faulting_reads.len(), 1);
    let first = candidate.reduced.effects[0].value;
    let second = candidate.reduced.effects[1].value;
    assert_eq!(angryier_execution::constant_value(&arena, first).map_err(|e| e.to_string())?, 7);
    assert_eq!(angryier_execution::constant_value(&arena, second).map_err(|e| e.to_string())?, 9);
    assert!(!candidate.input_had_fidelity_debt);
    Ok(())
}
#[test]
fn edited_footprint_is_rejected_before_materialization() -> Result<(), String> {
    let mut capture = fixture()?;
    let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
    capture.footprint.effects.clear();
    assert!(materialize_vm_handler(&capture, &arena, 1024).is_err());
    Ok(())
}

#[test]
fn fabricated_native_step_outcome_fails_closed() -> Result<(), String> {
    let mut capture = fixture()?;
    capture.steps[0].outcome = StepOutcome::Stepped {
        pc: 0xdeaf,
        next_pc: 0x1001,
        length: 1,
        form_id: 1,
    };
    let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
    assert!(materialize_vm_handler(&capture, &arena, 1024).is_err());
    Ok(())
}

#[test]
fn candidate_replay_is_only_a_captured_input_check() -> Result<(), String> {
    let captured = fixture()?;
    let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
    let candidate = materialize_vm_handler(&captured, &arena, 1024)
        .map_err(|error| format!("{error:?}"))?;
    let report = angryier_runtime::vm_replay::check_vm_concrete_replay(
        &captured, &candidate, &arena
    ).map_err(|error| format!("{error:?}"))?;
    assert!(report.checked_registers > 0);
    assert_eq!(report.unresolved_fault_obligations, 1);
    assert!(report.observed_input_only);
    Ok(())
}

#[test]
fn captured_replay_detects_changed_register_and_rejects_debt() -> Result<(), String> {
    use angryier_state::RegisterState;
    use angryier_runtime::vm_replay::{check_vm_concrete_replay, VmReplayError};
    let mut capture = fixture()?;
    let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
    let candidate = materialize_vm_handler(&capture, &arena, 1024)
        .map_err(|error| format!("{error:?}"))?;
    capture.final_state.registers = capture.final_state.registers
        .write(1, &8u64.to_le_bytes()).map_err(|error| format!("{error:?}"))?;
    assert_eq!(
        check_vm_concrete_replay(&capture, &candidate, &arena),
        Err(VmReplayError::RegisterMismatch { register: 1 })
    );
    let mut capture = fixture()?;
    capture.initial_state.fidelity = capture.initial_state.fidelity
        .record(angryier_types::AnalysisDebtKind::Concretized, 0x1000);
    let candidate = materialize_vm_handler(&capture, &arena, 1024)
        .map_err(|error| format!("{error:?}"))?;
    assert_eq!(
        check_vm_concrete_replay(&capture, &candidate, &arena),
        Err(VmReplayError::ExistingFidelityDebt)
    );
    Ok(())
}
