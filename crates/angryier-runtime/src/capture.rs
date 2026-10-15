//! Explicitly selected read-only minidump ranges -> persistent process memory.
//!
//! This is NOT Windows thread/process restoration. Callers must supply ranges,
//! permissions and matching image/capture provenance. Missing dump bytes are
//! never silently converted into zero-backed heap memory.
//! Admission is atomic across all selected ranges; no partial mutation.

use angryier_loader::minidump_file::MiniDumpFile;
use angryier_memory::{MemoryRegion, PersistentMemory};
use angryier_types::ObjectId;

use crate::{Process, RuntimeError};

const MAX_CAPTURED_TOTAL: u64 = 64 * 1024 * 1024;
const MAX_SINGLE_READ: u64 = 1024 * 1024;
const MAX_SELECTIONS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CaptureRange {
    pub address: u64,
    pub length: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaptureBaseline {
    /// Change only the current execution state, not its original replay base.
    CurrentOnly,
    /// Also update entry-state memory; registers/PC/OS context stay unchanged.
    ReplayMemory,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureImportReport {
    pub ranges: usize,
    pub bytes: u64,
    pub mapped_new_ranges: usize,
    pub baseline: CaptureBaseline,
}

fn capture_error(message: impl Into<String>) -> RuntimeError {
    RuntimeError::Environment(format!("capture overlay: {}", message.into()))
}

fn region_placement(
    memory: &PersistentMemory,
    address: u64,
    length: u64,
) -> Result<bool, RuntimeError> {
    let end = address.checked_add(length).ok_or_else(|| capture_error("VA overflow"))?;
    let existing: Vec<&MemoryRegion> = memory.regions().iter()
        .filter(|region| {
            let Some(region_end) = region.base.checked_add(region.size) else { return true; };
            address < region_end && region.base < end
        })
        .collect();
    if existing.is_empty() {
        return Ok(true); // entire range unmapped; allocate exactly captured span
    }
    if existing.len() != 1
        || address < existing[0].base
        || end > existing[0].base.saturating_add(existing[0].size)
    {
        return Err(capture_error("range partially overlaps existing mapping; refusing ambiguous overlay"));
    }
    Ok(false)
}

/// Atomically import selected captured VA ranges from one minidump file.
/// The current Process entry_state is unchanged unless ReplayMemory is
/// explicitly selected. The caller must independently bind the dump and
/// executable to matching capture identity; this function cannot assert they
/// came from the same process or moment.
pub fn import_captured_memory(
    process: &mut Process,
    dump: &mut MiniDumpFile,
    selections: &[CaptureRange],
    baseline: CaptureBaseline,
) -> Result<CaptureImportReport, RuntimeError> {
    if selections.is_empty() || selections.len() > MAX_SELECTIONS {
        return Err(capture_error("range count must be 1..=256"));
    }
    let mut total = 0u64;
    let mut previous_end = None::<u64>;
    let mut ordered = selections.to_vec();
    ordered.sort_by_key(|range| range.address);
    for range in &ordered {
        if range.length == 0 || !range.readable {
            return Err(capture_error("nonempty readable ranges required"));
        }
        let end = range.address.checked_add(range.length)
            .ok_or_else(|| capture_error("VA overflow"))?;
        if previous_end.is_some_and(|prior| range.address < prior) {
            return Err(capture_error("overlapping capture selections"));
        }
        previous_end = Some(end);
        total = total.checked_add(range.length)
            .ok_or_else(|| capture_error("size overflow"))?;
        if total > MAX_CAPTURED_TOTAL {
            return Err(capture_error("capture exceeds 64 MiB budget"));
        }
    }

    let mut staged = process.state.memory.clone();
    let mut new_regions = 0usize;
    for (index, range) in ordered.iter().enumerate() {
        let add_region = region_placement(&staged, range.address, range.length)?;
        if add_region {
            staged = staged.with_region(MemoryRegion {
                object: ObjectId(0x9000 + index as u64),
                base: range.address,
                size: range.length,
                readable: range.readable,
                writable: range.writable,
                executable: range.executable,
            }).map_err(|e| capture_error(format!("{e:?}")))?;
            new_regions += 1;
        }
        let mut offset = 0u64;
        while offset < range.length {
            let count = (range.length - offset).min(MAX_SINGLE_READ);
            let location = range.address.checked_add(offset)
                .ok_or_else(|| capture_error("VA overflow"))?;
            let bytes = dump.read(location, count as usize)
                .map_err(|e| capture_error(format!("{e:?}")))?;
            // No fabricated bytes; the source reader requires a complete
            // captured range and reports the first missing byte.
            staged = staged.load_concrete(location, &bytes)
                .map_err(|e| capture_error(format!("{e:?}")))?;
            offset += count;
        }
    }

    // Commit only after every source read and memory mapping has succeeded.
    process.state.memory = staged.clone();
    if baseline == CaptureBaseline::ReplayMemory {
        process.entry_state.memory = staged;
    }
    Ok(CaptureImportReport {
        ranges: ordered.len(),
        bytes: total,
        mapped_new_ranges: new_regions,
        baseline,
    })
}
