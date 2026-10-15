//! Opt-in VM-handler observation over Angryier's existing native execution.
//!
//! The caller supplies a trusted VPC/context observer and a pinned identity;
//! this module does not identify, guess or decrypt a virtual instruction.
//! `step_with` captures the same AngryIR the concrete interpreter executes.
//! No SimProcedure or redirect can silently stand in for a native handler:
//! those paths have no captured instruction block and fail explicitly.
//!
//! The process is advanced by the underlying runtime; failed observations
//! do NOT rewind the process. To retry deterministically, start from a
//! verified Process checkpoint and keep the capture identity unchanged.

use angryier_arch::Decoder;
use angryier_ir::{
    IrBlock,
    vm_trace::{
        collect_observed_vm_trace, VmObservedBlock, VmObservedLocation, VmTraceFootprint,
        VmTraceIdentity, VmTraceLimits,
    },
};

use crate::{Process, Runtime, RuntimeError, StepOutcome};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmStateObservation {
    pub virtual_pc: u64,
    /// Digest of the caller-identified VM context state.
    pub context_digest: [u8; 32],
    /// Executable-code version epoch supplied by the observer.
    pub code_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmHandlerWindow {
    pub entry: VmObservedLocation,
    pub exit: VmObservedLocation,
    pub identity: VmTraceIdentity,
    pub limits: VmTraceLimits,
}

#[derive(Clone, Debug)]
pub struct VmRecordedInstruction {
    pub block: IrBlock,
    pub before: VmObservedLocation,
    pub after: VmObservedLocation,
    pub code_epoch: u64,
    pub outcome: StepOutcome,
}

#[derive(Clone, Debug)]
pub struct VmHandlerCapture {
    /// COW process state from BEFORE the first captured native instruction.
    /// Needed for exact entry-state SSA/expr materialization; never use the
    /// mutated final process or an unrelated load-time entry_state instead.
    pub initial_state: angryier_state::ExecutionState<
        angryier_state::PersistentRegisters,
        angryier_memory::PersistentMemory,
    >,
    pub steps: Vec<VmRecordedInstruction>,
    pub footprint: VmTraceFootprint,
}

fn observation_location(pc: u64, observed: VmStateObservation) -> VmObservedLocation {
    VmObservedLocation {
        native_pc: pc,
        virtual_pc: observed.virtual_pc,
        context_digest: observed.context_digest,
    }
}

impl<D: Decoder> Runtime<D> {
    /// Execute an explicitly bounded and observed VM-handler window.
    ///
    /// The observer must read VPC, full relevant VM-context digest and code
    /// epoch from an independently established mapping. Every `before`
    /// snapshot is checked against the previous `after` snapshot, and the
    /// terminal observation must match `window.exit`. Silent synthesized
    /// successors, skipped SimProcedures, failed execution and step-budget
    /// exhaustion are errors, never "completed" handler captures.
    ///
    /// This is observational groundwork for symbolic materialization, NOT
    /// a proof of handler equivalence or a general Themida devirtualizer.
    pub fn observe_vm_handler<F>(
        &self,
        process: &mut Process,
        window: VmHandlerWindow,
        mut observe: F,
    ) -> Result<VmHandlerCapture, RuntimeError>
    where
        F: FnMut(&Process) -> Result<VmStateObservation, RuntimeError>,
    {
        if process.image_id != window.identity.image
            || process.target_profile != window.identity.target_profile
        {
            return Err(RuntimeError::Environment(
                "VM handler capture image/profile identity mismatch".into(),
            ));
        }
        if [
            window.identity.executable_digest,
            window.identity.capture_digest,
            window.identity.initial_state_digest,
        ].iter().any(|digest| *digest == [0; 32]) {
            return Err(RuntimeError::Environment(
                "VM handler observation lacks executable/capture/initial-state identity".into(),
            ));
        }
        if window.limits.max_steps == 0 {
            return Err(RuntimeError::Environment(
                "VM handler capture requires a nonzero step budget".into(),
            ));
        }
        let initial_state = process.state.clone();
        let mut steps = Vec::new();
        loop {
            let pc = process.pc()?;
            let before_obs = observe(process)?;
            let before = observation_location(pc, before_obs);
            if steps.is_empty() && before != window.entry {
                return Err(RuntimeError::Environment(
                    "VM handler entry PC/VPC/context does not match pinned observation".into(),
                ));
            }
            if before == window.exit {
                break;
            }
            if steps.len() >= window.limits.max_steps {
                return Err(RuntimeError::StepLimitExceeded);
            }
            let mut recorded_block: Option<IrBlock> = None;
            let outcome = self.step_with(process, |_, block| {
                if recorded_block.replace(block.clone()).is_some() {
                    return Err(RuntimeError::Environment(
                        "VM observer captured more than one IR block for one step".into(),
                    ));
                }
                Ok(())
            })?;
            let block = recorded_block.ok_or_else(|| RuntimeError::Environment(
                "VM handler window crossed an unrecorded hook/redirect/model; capture incomplete".into(),
            ))?;
            let after_pc = process.pc()?;
            let after_obs = observe(process)?;
            let after = observation_location(after_pc, after_obs);
            match outcome {
                StepOutcome::Stepped { .. } => {}
                _ => {
                    return Err(RuntimeError::Environment(
                        "VM handler execution ended in trap, termination or model dispatch; capture incomplete".into(),
                    ));
                }
            }
            steps.push(VmRecordedInstruction {
                block,
                before,
                after,
                code_epoch: before_obs.code_epoch,
                outcome,
            });
        }
        let scoped: Vec<VmObservedBlock<'_>> = steps.iter().map(|step| VmObservedBlock {
            block: &step.block,
            before: step.before,
            after: step.after,
            code_epoch: step.code_epoch,
        }).collect();
        let footprint = collect_observed_vm_trace(
            window.identity,
            window.entry,
            window.exit,
            &scoped,
            window.limits,
        )
        .map_err(|error| RuntimeError::Environment(format!(
            "VM handler trace validation failed: {error:?}"
        )))?;
        Ok(VmHandlerCapture { initial_state, steps, footprint })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_types::{ImageId, TargetProfileId};

    #[test]
    fn context_observation_preserves_native_and_virtual_address_distinction() {
        let observation = VmStateObservation {
            virtual_pc: 0x123,
            context_digest: [7; 32],
            code_epoch: 5,
        };
        let location = observation_location(0x140001000, observation);
        assert_eq!(location.native_pc, 0x140001000);
        assert_eq!(location.virtual_pc, 0x123);
        assert_eq!(location.context_digest, [7; 32]);
    }

    #[cfg(feature = "xed")]
    #[test]
    fn real_runtime_steps_feed_an_observed_two_block_trace() -> Result<(), Box<dyn std::error::Error>> {
        use angryier_loader::{LoadedImage, Segment};
        use angryier_types::{ImageId, SemanticVersion, TargetProfileId};
        let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
        let image = LoadedImage {
            id: ImageId(1),
            entry: 0x1000,
            target_profile: TargetProfileId(1),
            segments: vec![Segment {
                address: 0x1000,
                bytes: vec![0x90, 0x90, 0xC3], // NOP; NOP; RET
                readable: true,
                writable: false,
                executable: true,
            }],
            symbols: Vec::new(),
            program_headers: None,
            dynamic: None,
            pe: None,
        };
        let mut process = runtime.load_image(image)?;
        let start = VmObservedLocation {
            native_pc: 0x1000,
            virtual_pc: 0,
            context_digest: [1; 32],
        };
        let end = VmObservedLocation {
            native_pc: 0x1002,
            virtual_pc: 2,
            context_digest: [3; 32],
        };
        let window = VmHandlerWindow {
            entry: start,
            exit: end,
            identity: VmTraceIdentity {
                image: ImageId(1),
                target_profile: TargetProfileId(1),
                executable_digest: [5; 32],
                capture_digest: [6; 32],
                initial_state_digest: [7; 32],
            },
            limits: VmTraceLimits {
                max_steps: 2,
                ..VmTraceLimits::default()
            },
        };
        let capture = runtime.observe_vm_handler(&mut process, window, |state| {
            let pc = state.pc()?;
            let offset = pc.checked_sub(0x1000).ok_or_else(|| {
                RuntimeError::Environment("unexpected native program counter".into())
            })?;
            let offset = u8::try_from(offset).map_err(|_| {
                RuntimeError::Environment("virtual counter beyond synthetic fixture".into())
            })?;
            Ok(VmStateObservation {
                virtual_pc: u64::from(offset),
                context_digest: [offset + 1; 32],
                code_epoch: 0,
            })
        })?;
        assert_eq!(capture.steps.len(), 2);
        assert_eq!(capture.footprint.edges.len(), 2);
        assert_eq!(capture.footprint.total_instructions > 0, true);
        assert_eq!(capture.steps[0].before, start);
        assert_eq!(capture.steps[1].after, end);
        assert_eq!(process.pc()?, 0x1002);
        Ok(())
    }

    #[cfg(feature = "xed")]
    #[test]
    fn captured_handler_rejects_missing_identity_before_execution() -> Result<(), Box<dyn std::error::Error>> {
        use angryier_loader::{LoadedImage, Segment};
        use angryier_types::{ImageId, SemanticVersion, TargetProfileId};
        let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
        let image = LoadedImage {
            id: ImageId(1),
            entry: 0x1000,
            target_profile: TargetProfileId(1),
            segments: vec![Segment {
                address: 0x1000,
                bytes: vec![0x90],
                readable: true,
                writable: false,
                executable: true,
            }],
            symbols: Vec::new(),
            program_headers: None,
            dynamic: None,
            pe: None,
        };
        let mut process = runtime.load_image(image)?;
        let here = VmObservedLocation {
            native_pc: 0x1000,
            virtual_pc: 0,
            context_digest: [1; 32],
        };
        let out = VmObservedLocation {
            native_pc: 0x1001,
            virtual_pc: 1,
            context_digest: [2; 32],
        };
        let window = VmHandlerWindow {
            entry: here,
            exit: out,
            identity: VmTraceIdentity {
                image: ImageId(1),
                target_profile: TargetProfileId(1),
                executable_digest: [0; 32],
                capture_digest: [0; 32],
                initial_state_digest: [0; 32],
            },
            limits: VmTraceLimits::default(),
        };
        let result = runtime.observe_vm_handler(&mut process, window, |_| {
            Err(RuntimeError::Environment("observer must not be invoked".into()))
        });
        assert!(matches!(result, Err(RuntimeError::Environment(message)) if message.contains("identity")));
        assert_eq!(process.step_count, 0);
        assert_eq!(process.pc()?, 0x1000);
        Ok(())
    }

    #[test]
    fn scoped_handler_window_cannot_claim_missing_capture_identity() {
        let window = VmHandlerWindow {
            entry: VmObservedLocation {
                native_pc: 0x1000,
                virtual_pc: 1,
                context_digest: [1; 32],
            },
            exit: VmObservedLocation {
                native_pc: 0x2000,
                virtual_pc: 2,
                context_digest: [2; 32],
            },
            identity: VmTraceIdentity {
                image: ImageId(1),
                target_profile: TargetProfileId(1),
                executable_digest: [0; 32],
                capture_digest: [0; 32],
                initial_state_digest: [0; 32],
            },
            limits: VmTraceLimits::default(),
        };
        assert_eq!(window.identity.capture_digest, [0; 32]);
        // An actual capture must validate this through collect_observed_vm_trace;
        // constructing an untrusted window alone cannot produce a footprint.
        assert!(matches!(
            collect_observed_vm_trace(
                window.identity, window.entry, window.exit,
                &[], window.limits
            ),
            Err(angryier_ir::vm_trace::VmTraceError::EmptyTrace)
        ));
    }
}
