//! Footprint + fork-cost measurement for the persistent memory layer,
//! mirroring the runtime Gate B concrete regime: 10,000 chained states, each
//! forking from the previous one and writing a distinct 6-byte value at a
//! 6-byte stride, so every descendant genuinely diverges from its ancestors.
//!
//! Measurement, not regression test — run with `--ignored --nocapture`.

use angryier_memory::{ByteValue, LayeredMemory, MemoryRegion, PersistentMemory};
use angryier_types::ObjectId;
use std::time::Instant;

const STATE_COUNT: usize = 10_000;

fn resident_bytes() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let field = statm.split_whitespace().nth(1)?;
    let resident_pages: u64 = field.parse().ok()?;
    Some(resident_pages * 4096)
}

#[test]
#[ignore = "footprint measurement: run with --ignored --nocapture"]
fn chained_state_footprint_10k() -> Result<(), angryier_memory::MemoryError> {
    let memory = PersistentMemory::new(vec![MemoryRegion {
        object: ObjectId(1),
        base: 0x1000,
        size: 0x10000,
        readable: true,
        writable: true,
        executable: false,
    }])?;

    let before = resident_bytes();
    let started = Instant::now();
    let mut states = Vec::with_capacity(STATE_COUNT);
    let mut current = memory.clone();
    for index in 0..STATE_COUNT {
        if index > 0 {
            let address = 0x1000 + 6 * index as u64;
            let bytes: Vec<ByteValue> = (index as u64)
                .to_le_bytes()
                .iter()
                .copied()
                .map(ByteValue::Concrete)
                .collect();
            current = current.write(address, &bytes)?;
        }
        states.push(current.clone());
    }
    let elapsed = started.elapsed();
    let after = resident_bytes();

    // Divergence is real: the last state's own write reads back.
    let probe = 6 * (STATE_COUNT - 1) as u64;
    let tail = current.read(0x1000 + probe, 8)?;
    let mut observed = 0u64;
    for (index, byte) in tail.iter().enumerate() {
        if let ByteValue::Concrete(byte) = byte {
            observed |= u64::from(*byte) << (8 * index);
        }
    }
    assert_eq!(observed, (STATE_COUNT - 1) as u64, "each state's write must survive");

    if let (Some(before), Some(after)) = (before, after) {
        let delta_kb = after.saturating_sub(before) as f64 / 1024.0;
        let per_state_kb = delta_kb / STATE_COUNT as f64;
        let fork_us = elapsed.as_secs_f64() * 1e6 / STATE_COUNT as f64;
        println!(
            "MEMORY-B footprint: {STATE_COUNT} chained states, RSS +{delta_kb:.1} KB \
             ({per_state_kb:.2} KB/state), fork cost {fork_us:.2} us/state over {elapsed:.2?}"
        );
    } else {
        eprintln!("skipping RSS report: /proc/self/statm unavailable");
    }
    Ok(())
}
