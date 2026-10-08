# KP14 targeted IOCTL seed

`angryier::driver_ioctl::DriverIoctlTarget` prepares an x64 PE driver handler
run using the current KP14 POPKORN synthetic addresses and Windows structure
offsets. It points RCX at a symbolic `_DEVICE_OBJECT`, RDX at a symbolic
`_IRP`, connects the IRP to a symbolic `_IO_STACK_LOCATION` and input buffer,
pins `MajorFunction` to `IRP_MJ_DEVICE_CONTROL`, and optionally pins an IOCTL
code. The selected sink call site becomes the run's `find` address.

```rust
use angryier::{Engine, driver_ioctl::DriverIoctlTarget};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let engine = Engine::new()?;
    let image = engine.load("./fixture.sys")?;
    let target = DriverIoctlTarget {
        handler_va: 0x0001_4000_1000,
        sink_va: 0x0001_4000_1100,
        ioctl_code: Some(0x0022_0004),
    };
    let report = engine.run(&image, &target.run_options(2_000, 32)?)?;
    println!("sink hits: {}", report.found_pcs.len());
    Ok(())
}
```

Addresses are absolute virtual addresses for the loaded image. The caller
must select the handler, sink, budgets, and any IOCTL code from verified static
evidence. This helper does not implement POPKORN's sink argument classifier,
constraint summaries, full kernel import models, loop policy, or KP14 verdict
taxonomy. A missed sink under a finite budget is inconclusive, not a proof of
unreachability. Use the current KP14 POPKORN fixtures as the parity baseline
before promoting Angryier to the default verifier.
