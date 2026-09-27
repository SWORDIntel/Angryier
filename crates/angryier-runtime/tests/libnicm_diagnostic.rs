#![cfg(feature = "xed")]

use angryier_arch::Decoder;
use angryier_memory::{ByteValue, LayeredMemory};
use angryier_runtime::{Runtime, StepOutcome};
use angryier_types::{SemanticVersion, TargetProfileId};

#[test]
fn trace_libnicm_bad_pointer() -> Result<(), Box<dyn std::error::Error>> {
    let path = "/home/john/Documents/driver_analysis/drivers/sources/caledonia-drivers/bin-elastic/libnicm.sys";
    let image = match std::fs::read(path) {
        Ok(image) => image,
        Err(_) => return Ok(()),
    };
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_pe_driver(&image)?;
    let tracker = std::sync::Arc::new(angryier_models::KernelPoolTracker::new());
    runtime.attach_kernel_pool_model(&mut process, tracker.clone())?;

    for step in 0..80 {
        let pc = process.pc()?;
        let bytes = process.state.memory.read(pc, 15).ok().map(|values| {
            values
                .iter()
                .map(|value| match value {
                    ByteValue::Concrete(byte) => *byte,
                    ByteValue::Symbolic(_) => 0xcc,
                })
                .collect::<Vec<_>>()
        });
        let decoded = bytes.as_ref().and_then(|bytes| runtime.decoder.decode(pc, bytes).ok());
        if step >= 38 {
            let rax = process.read_register(angryier_arch_intel64::register_id::GPR_BASE)?;
            let rcx = process.read_register(angryier_arch_intel64::register_id::GPR_BASE + 1)?;
            eprintln!("step={step} pc={pc:#x} rax={rax:#x} rcx={rcx:#x} decoded={decoded:?}");
        }
        match runtime.step(&mut process) {
            Ok(outcome) => {
                if let StepOutcome::SimProcedure { address, name } = outcome {
                    let import = process
                        .pe_import_stubs
                        .get(&address)
                        .map(|(_, export)| export.as_str())
                        .unwrap_or("?");
                    eprintln!("step={step} pc={pc:#x} simproc={name} import={import}");
                }
            }
            Err(error) => {
                eprintln!("step={step} pc={pc:#x} decoded={decoded:?} error={error:?}");
                for index in 0..8u32 {
                    let value = process.read_register(angryier_arch_intel64::register_id::GPR_BASE + index)?;
                    eprintln!("  gpr[{index}]={value:#018x}");
                }
                eprintln!("  pool={:?}", tracker.snapshot());
                return Ok(());
            }
        }
    }
    Ok(())
}
