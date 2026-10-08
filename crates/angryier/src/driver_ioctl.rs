//! Reproducible x64 IOCTL-dispatch seeding for targeted driver exploration.
//!
//! The synthetic addresses and structure offsets mirror KP14's current
//! POPKORN seeding contract. This module prepares [`RunOptions`]; it does not
//! classify a reached sink or claim POPKORN verdict parity.

use crate::{ApiError, RunOptions};

const DEVICE_OBJECT_ADDR: u64 = 0x444d_0000;
const IRP_ADDR: u64 = 0x0133_7000;
const IRP_STACK_ADDR: u64 = 0x0600_0000;
const INPUT_BUFFER_ADDR: u64 = 0x0700_0000;

const DEVICE_OBJECT_BYTES: usize = 0x100;
const IRP_BYTES: usize = 0x200;
const IRP_STACK_BYTES: usize = 0x48;
const INPUT_BUFFER_BYTES: usize = 0x200;

const IRP_SYSTEM_BUFFER_OFFSET: u64 = 0x18;
const IRP_USER_BUFFER_OFFSET: u64 = 0x70;
const IRP_CURRENT_STACK_OFFSET: u64 = 0xb8;
const STACK_IOCTL_CODE_OFFSET: u64 = 0x18;
const STACK_TYPE3_INPUT_OFFSET: u64 = 0x20;
const IRP_MJ_DEVICE_CONTROL: u64 = 0x0e;

/// One x64 IOCTL dispatch path selected by static analysis.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DriverIoctlTarget {
    /// Absolute virtual address of the dispatch routine entry.
    pub handler_va: u64,
    /// Absolute virtual address of the sink call site to seek.
    pub sink_va: u64,
    /// Concrete IOCTL code, or `None` to leave the code symbolic.
    pub ioctl_code: Option<u32>,
}

impl DriverIoctlTarget {
    /// Build bounded options with POPKORN-compatible synthetic x64 input
    /// objects. The caller supplies instruction and live-state limits.
    ///
    /// `Engine::run` still requires a PE32+ driver image with matching image
    /// base and kernel models. A target hit is evidence of reachability under
    /// the current model, not yet a classified KP14 verdict.
    pub fn run_options(self, steps: u64, max_states: usize) -> Result<RunOptions, ApiError> {
        if self.handler_va == 0 || self.sink_va == 0 {
            return Err(ApiError::InvalidArgument(
                "IOCTL handler and sink addresses must be nonzero".to_string(),
            ));
        }
        if steps == 0 || max_states == 0 {
            return Err(ApiError::InvalidArgument(
                "IOCTL step and state budgets must be positive".to_string(),
            ));
        }

        let mut poke = vec![
            (IRP_ADDR + IRP_SYSTEM_BUFFER_OFFSET, INPUT_BUFFER_ADDR),
            (IRP_ADDR + IRP_USER_BUFFER_OFFSET, INPUT_BUFFER_ADDR),
            (IRP_ADDR + IRP_CURRENT_STACK_OFFSET, IRP_STACK_ADDR),
            (IRP_STACK_ADDR, IRP_MJ_DEVICE_CONTROL),
            (IRP_STACK_ADDR + STACK_TYPE3_INPUT_OFFSET, INPUT_BUFFER_ADDR),
        ];
        if let Some(code) = self.ioctl_code {
            poke.push((IRP_STACK_ADDR + STACK_IOCTL_CODE_OFFSET, u64::from(code)));
        }

        Ok(RunOptions {
            regs: vec![("rcx".to_string(), DEVICE_OBJECT_ADDR), ("rdx".to_string(), IRP_ADDR)],
            poke,
            symbolic_memory: vec![
                (DEVICE_OBJECT_ADDR, DEVICE_OBJECT_BYTES),
                (IRP_ADDR, IRP_BYTES),
                (IRP_STACK_ADDR, IRP_STACK_BYTES),
                (INPUT_BUFFER_ADDR, INPUT_BUFFER_BYTES),
            ],
            entry: Some(self.handler_va),
            find: vec![self.sink_va],
            steps,
            max_states,
            solve: true,
            ..RunOptions::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_pinned_ioctl_and_kernel_pointers() {
        let target = DriverIoctlTarget {
            handler_va: 0x0001_4000_1000,
            sink_va: 0x0001_4000_1100,
            ioctl_code: Some(0x0022_0004),
        };
        let options = target.run_options(2_000, 32).expect("valid target");
        assert_eq!(options.entry, Some(target.handler_va));
        assert_eq!(options.find, vec![target.sink_va]);
        assert_eq!(options.regs[0], ("rcx".to_string(), DEVICE_OBJECT_ADDR));
        assert_eq!(options.regs[1], ("rdx".to_string(), IRP_ADDR));
        assert!(
            options
                .poke
                .contains(&(IRP_ADDR + IRP_CURRENT_STACK_OFFSET, IRP_STACK_ADDR))
        );
        assert!(options.poke.contains(&(IRP_STACK_ADDR, IRP_MJ_DEVICE_CONTROL)));
        assert!(
            options
                .poke
                .contains(&(IRP_STACK_ADDR + STACK_IOCTL_CODE_OFFSET, 0x0022_0004))
        );
        assert_eq!(options.symbolic_memory.len(), 4);
        assert!(options.solve);
    }

    #[test]
    fn leaves_unspecified_ioctl_symbolic_and_rejects_invalid_budgets() {
        let target = DriverIoctlTarget {
            handler_va: 0x0001_4000_1000,
            sink_va: 0x0001_4000_1100,
            ioctl_code: None,
        };
        let options = target.run_options(1, 1).expect("valid target");
        assert!(
            !options
                .poke
                .iter()
                .any(|(address, _)| *address == IRP_STACK_ADDR + STACK_IOCTL_CODE_OFFSET)
        );
        assert!(target.run_options(0, 1).is_err());
        assert!(target.run_options(1, 0).is_err());
    }
}
