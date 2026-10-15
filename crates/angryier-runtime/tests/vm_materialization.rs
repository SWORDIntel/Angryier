//! Native VM symbolic-materialization regression using a synthetic,
//! two-block handler. No protected target is necessary.
use angryier_arch::{DecodedInstruction, Decoder};
use angryier_expr::ShardedExprArena;
use angryier_ir::{
    IrBlock, IrBlockKey, IrInstruction, IrOp, IrPrimitive, IrType, IrValueId, RegisterWriteKind,
    vm_trace::{VmObservedBlock, VmObservedLocation, VmTraceIdentity, VmTraceLimits, collect_observed_vm_trace},
};
use angryier_loader::{LoadedImage, Segment};
use angryier_runtime::{
    Runtime, StepOutcome,
    vm_materialize::materialize_vm_handler,
    vm_observe::{VmHandlerCapture, VmHandlerWindow, VmRecordedInstruction},
};
use angryier_types::{BlockId, ContentId, ExpressionNormalizationVersion, ImageId, SemanticVersion, TargetProfileId};

#[derive(Debug)]
struct NoDecoder;
impl Decoder for NoDecoder {
    type Error = String;
    fn decode(&self, _: u64, _: &[u8]) -> Result<DecodedInstruction, Self::Error> {
        Err("decoder not needed".into())
    }
}
fn location(pc: u64, vpc: u64, state: u8) -> VmObservedLocation {
    VmObservedLocation {
        native_pc: pc,
        virtual_pc: vpc,
        context_digest: [state; 32],
    }
}
fn block(pc: u64, index: u64, source: u32, increment: u64) -> IrBlock {
    let v = |id, op| IrInstruction {
        result: Some(IrValueId(id)),
        op,
    };
    let e = |op| IrInstruction { result: None, op };
    let mut instructions = vec![
        v(
            0,
            IrOp::ReadRegister {
                register: source,
                ty: IrType::Bits(64),
            },
        ),
        v(
            1,
            IrOp::Constant {
                ty: IrType::Bits(64),
                bytes_le: increment.to_le_bytes().to_vec(),
            },
        ),
        v(
            2,
            IrOp::Primitive {
                op: IrPrimitive::Add,
                ty: IrType::Bits(64),
                inputs: vec![IrValueId(0), IrValueId(1)],
            },
        ),
    ];
    if index == 1 {
        // Faultable load whose value is deliberately unused; expression
        // reduction must not discard its exception obligation.
        instructions.push(v(
            3,
            IrOp::Constant {
                ty: IrType::Bits(64),
                bytes_le: 0x1000u64.to_le_bytes().to_vec(),
            },
        ));
        instructions.push(v(
            4,
            IrOp::Load {
                address: IrValueId(3),
                ty: IrType::Bits(8),
            },
        ));
    }
    instructions.push(e(IrOp::WriteRegister {
        register: 1,
        value: IrValueId(2),
        kind: RegisterWriteKind::ReplaceParent,
    }));
    instructions.push(e(IrOp::Jump { target: pc + 1 }));
    IrBlock {
        key: IrBlockKey {
            image: ImageId(1),
            block: BlockId(index),
            address: pc,
            semantic_content: ContentId([8; 32]),
            target_profile: TargetProfileId(1),
            code_versions: Vec::new(),
        },
        instructions,
    }
}
fn fixture() -> Result<VmHandlerCapture, String> {
    let runtime = Runtime::new(NoDecoder, SemanticVersion(1), TargetProfileId(1));
    let image = LoadedImage {
        id: ImageId(1),
        entry: 0x1000,
        target_profile: TargetProfileId(1),
        segments: vec![Segment {
            address: 0x1000,
            bytes: vec![0x90, 0x90, 0xc3],
            readable: true,
            writable: false,
            executable: true,
        }],
        symbols: Vec::new(),
        program_headers: None,
        dynamic: None,
        pe: None,
    };
    let process = runtime.load_image(image).map_err(|e| e.to_string())?;
    let a = location(0x1000, 0x50, 1);
    let b = location(0x1001, 0x51, 2);
    let c = location(0x1002, 0x53, 3);
    let window = VmHandlerWindow {
        entry: a,
        exit: c,
        identity: VmTraceIdentity {
            image: ImageId(1),
            target_profile: TargetProfileId(1),
            executable_digest: [1; 32],
            capture_digest: [2; 32],
            initial_state_digest: [3; 32],
        },
        limits: VmTraceLimits::default(),
    };
    let mk = |block: IrBlock, before: VmObservedLocation, after: VmObservedLocation| VmRecordedInstruction {
        outcome: StepOutcome::Stepped {
            pc: before.native_pc,
            next_pc: after.native_pc,
            length: 1,
            form_id: 1,
        },
        block,
        before,
        after,
        code_epoch: 0,
    };
    let steps = vec![mk(block(0x1000, 1, 0, 7), a, b), mk(block(0x1001, 2, 1, 2), b, c)];
    let borrowed: Vec<_> = steps
        .iter()
        .map(|s| VmObservedBlock {
            block: &s.block,
            before: s.before,
            after: s.after,
            code_epoch: s.code_epoch,
        })
        .collect();
    let footprint =
        collect_observed_vm_trace(window.identity, a, c, &borrowed, window.limits).map_err(|e| format!("{e:?}"))?;
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
    let candidate = materialize_vm_handler(&capture, &arena, 1024).map_err(|e| format!("{e:?}"))?;
    assert_eq!(candidate.reduced.effects.len(), 2);
    assert_eq!(candidate.original_effects.len(), 2);
    assert_eq!(candidate.potentially_faulting_reads.len(), 1);
    let first = candidate.reduced.effects[0].value;
    let second = candidate.reduced.effects[1].value;
    assert_eq!(
        angryier_execution::constant_value(&arena, first).map_err(|e| e.to_string())?,
        7
    );
    assert_eq!(
        angryier_execution::constant_value(&arena, second).map_err(|e| e.to_string())?,
        9
    );
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
    let candidate = materialize_vm_handler(&captured, &arena, 1024).map_err(|error| format!("{error:?}"))?;
    let report = angryier_runtime::vm_replay::check_vm_concrete_replay(&captured, &candidate, &arena)
        .map_err(|error| format!("{error:?}"))?;
    assert!(report.checked_registers > 0);
    assert_eq!(report.unresolved_fault_obligations, 1);
    assert!(report.observed_input_only);
    Ok(())
}

#[test]
fn captured_replay_detects_changed_register_and_rejects_debt() -> Result<(), String> {
    use angryier_runtime::vm_replay::{VmReplayError, check_vm_concrete_replay};
    use angryier_state::RegisterState;
    let mut capture = fixture()?;
    let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
    let candidate = materialize_vm_handler(&capture, &arena, 1024).map_err(|error| format!("{error:?}"))?;
    capture.final_state.registers = capture
        .final_state
        .registers
        .write(1, &8u64.to_le_bytes())
        .map_err(|error| format!("{error:?}"))?;
    assert_eq!(
        check_vm_concrete_replay(&capture, &candidate, &arena),
        Err(VmReplayError::RegisterMismatch { register: 1 })
    );
    let mut capture = fixture()?;
    capture.initial_state.fidelity = capture
        .initial_state
        .fidelity
        .record(angryier_types::AnalysisDebtKind::Concretized, 0x1000);
    let candidate = materialize_vm_handler(&capture, &arena, 1024).map_err(|error| format!("{error:?}"))?;
    assert_eq!(
        check_vm_concrete_replay(&capture, &candidate, &arena),
        Err(VmReplayError::ExistingFidelityDebt)
    );
    Ok(())
}

#[test]
fn repeated_writes_and_partial_parent_updates_replay_in_original_order() -> Result<(), String> {
    use angryier_runtime::vm_replay::check_vm_concrete_replay;
    use angryier_state::RegisterState;

    let mut capture = fixture()?;
    // Make the high bits nonzero so an incorrect low-byte replacement
    // cannot accidentally appear equivalent to PreserveParent.
    let wide = 0x1_0000_0007u64;
    capture.steps[0].block.instructions[1].op = IrOp::Constant {
        ty: IrType::Bits(64),
        bytes_le: wide.to_le_bytes().to_vec(),
    };

    // The second block first writes RCX = original + 2, then RCX += 5,
    // then replaces only the low byte with 3. Three writes to the same
    // parent register MUST be materialized as three distinct effects.
    let instructions = &mut capture.steps[1].block.instructions;
    let terminal = instructions.pop().ok_or("missing direct jump")?;
    assert!(matches!(terminal.op, IrOp::Jump { .. }));
    instructions.push(IrInstruction {
        result: Some(IrValueId(3)),
        op: IrOp::Constant {
            ty: IrType::Bits(64),
            bytes_le: 5u64.to_le_bytes().to_vec(),
        },
    });
    instructions.push(IrInstruction {
        result: Some(IrValueId(4)),
        op: IrOp::Primitive {
            op: IrPrimitive::Add,
            ty: IrType::Bits(64),
            inputs: vec![IrValueId(2), IrValueId(3)],
        },
    });
    instructions.push(IrInstruction {
        result: None,
        op: IrOp::WriteRegister {
            register: 1,
            value: IrValueId(4),
            kind: RegisterWriteKind::ReplaceParent,
        },
    });
    instructions.push(IrInstruction {
        result: Some(IrValueId(5)),
        op: IrOp::Constant {
            ty: IrType::Bits(8),
            bytes_le: vec![3],
        },
    });
    instructions.push(IrInstruction {
        result: None,
        op: IrOp::WriteRegister {
            register: 1,
            value: IrValueId(5),
            kind: RegisterWriteKind::PreserveParent {
                bit_offset: 0,
                width_bits: 8,
            },
        },
    });
    instructions.push(terminal);

    let borrowed: Vec<_> = capture
        .steps
        .iter()
        .map(|step| VmObservedBlock {
            block: &step.block,
            before: step.before,
            after: step.after,
            code_epoch: step.code_epoch,
        })
        .collect();
    capture.footprint = collect_observed_vm_trace(
        capture.window.identity,
        capture.window.entry,
        capture.window.exit,
        &borrowed,
        capture.window.limits,
    )
    .map_err(|error| format!("{error:?}"))?;

    let expected = 0x1_0000_0003u64;
    capture.final_state.registers = capture
        .final_state
        .registers
        .write(1, &expected.to_le_bytes())
        .map_err(|error| format!("{error:?}"))?;

    let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
    let candidate = materialize_vm_handler(&capture, &arena, 4096).map_err(|error| format!("{error:?}"))?;
    assert_eq!(candidate.effect_steps, vec![0, 1, 1, 1]);
    let expected_writes = [wide, wide + 2, wide + 7, expected];
    for (index, value) in expected_writes.iter().enumerate() {
        let expression = candidate.reduced.effects[index].value;
        assert_eq!(
            angryier_execution::constant_value(&arena, expression).map_err(|error| error.to_string())?,
            *value,
            "write {index} was replaced by a later write",
        );
    }
    let verified = check_vm_concrete_replay(&capture, &candidate, &arena).map_err(|error| format!("{error:?}"))?;
    assert!(verified.checked_registers > 0);
    assert!(verified.observed_input_only);
    Ok(())
}

#[cfg(feature = "xed")]
#[test]
fn native_xed_two_instruction_execution_replays_materialized_effects() -> Result<(), String> {
    use angryier_runtime::{vm_observe::VmStateObservation, vm_replay::check_vm_concrete_replay};

    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let image = LoadedImage {
        id: ImageId(1),
        entry: 0x1000,
        target_profile: TargetProfileId(1),
        // mov eax, 7 ; add eax, 2 ; nop
        // The actual x86 interpreter runs both instructions and produces
        // the final register/flag state used as an independent witness.
        segments: vec![Segment {
            address: 0x1000,
            bytes: vec![0xB8, 7, 0, 0, 0, 0x83, 0xC0, 2, 0x90],
            readable: true,
            writable: false,
            executable: true,
        }],
        symbols: Vec::new(),
        program_headers: None,
        dynamic: None,
        pe: None,
    };
    let mut process = runtime.load_image(image).map_err(|error| error.to_string())?;
    // A MOV EAX must clear the upper half of RAX, even if the original
    // captured RAX had nonzero upper bits.
    process
        .write_register(0, 0xFFFF_FFFF_0000_0000)
        .map_err(|error| error.to_string())?;
    let location = |native_pc: u64| {
        let offset = native_pc.saturating_sub(0x1000);
        VmObservedLocation {
            native_pc,
            virtual_pc: offset,
            context_digest: [u8::try_from(offset).unwrap_or(u8::MAX).saturating_add(1); 32],
        }
    };
    let window = VmHandlerWindow {
        entry: location(0x1000),
        exit: location(0x1008),
        identity: VmTraceIdentity {
            image: ImageId(1),
            target_profile: TargetProfileId(1),
            // Synthetic nonzero identities, not forensic attestations.
            executable_digest: [1; 32],
            capture_digest: [2; 32],
            initial_state_digest: [3; 32],
        },
        limits: VmTraceLimits {
            max_steps: 2,
            ..VmTraceLimits::default()
        },
    };
    let captured = runtime
        .observe_vm_handler(&mut process, window, |running| {
            let pc = running.pc()?;
            let offset = pc.checked_sub(0x1000).ok_or_else(|| {
                angryier_runtime::RuntimeError::Environment("native trace left fixture region".into())
            })?;
            let context_byte = u8::try_from(offset)
                .map_err(|_| {
                    angryier_runtime::RuntimeError::Environment("native trace offset outside byte fixture".into())
                })?
                .saturating_add(1);
            Ok(VmStateObservation {
                virtual_pc: offset,
                context_digest: [context_byte; 32],
                code_epoch: 0,
            })
        })
        .map_err(|error| error.to_string())?;

    assert_eq!(captured.steps.len(), 2);
    assert_eq!(process.pc().map_err(|error| error.to_string())?, 0x1008);
    assert_eq!(process.read_register(0).map_err(|error| error.to_string())?, 9,);

    let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
    let candidate = materialize_vm_handler(&captured, &arena, 4096).map_err(|error| format!("{error:?}"))?;
    let report = check_vm_concrete_replay(&captured, &candidate, &arena).map_err(|error| format!("{error:?}"))?;
    assert!(report.checked_registers > 0);
    assert!(report.observed_input_only);
    assert_eq!(report.checked_indirect_targets, 0);
    Ok(())
}
