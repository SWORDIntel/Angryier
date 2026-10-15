//! Explicitly selected read-only minidump ranges -> persistent process memory.
//!
//! This is NOT Windows thread/process restoration. Callers must supply ranges,
//! permissions and matching image/capture provenance. Missing dump bytes are
//! never silently converted into zero-backed heap memory.
//! Admission is atomic across all selected ranges; no partial mutation.

use angryier_loader::minidump_file::MiniDumpFile;
use angryier_memory::{LayeredMemory, MemoryRegion, PersistentMemory};
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

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_arch::{DecodedInstruction, Decoder};
    use angryier_loader::{LoadedImage, Segment};
    use angryier_memory::{ByteValue, LayeredMemory};
    use angryier_types::{ImageId, SemanticVersion, TargetProfileId};
    use crate::Runtime;

    #[derive(Debug)]
    struct NoDecode;
    impl Decoder for NoDecode {
        type Error = ();
        fn decode(&self, _address: u64, _bytes: &[u8]) -> Result<DecodedInstruction, ()> {
            Err(())
        }
    }

    fn make_process() -> Result<Process, String> {
        let image = LoadedImage {
            id: ImageId(1),
            entry: 0x1000,
            target_profile: TargetProfileId(1),
            segments: vec![Segment {
                address: 0x1000,
                bytes: vec![0x90, 0xc3],
                readable: true,
                writable: false,
                executable: true,
            }],
            symbols: Vec::new(),
            program_headers: None,
            dynamic: None,
            pe: None,
        };
        Runtime::new(NoDecode, SemanticVersion(1), TargetProfileId(1))
            .load_image(image)
            .map_err(|error| error.to_string())
    }

    fn capture_file() -> Result<std::path::PathBuf, String> {
        let mut bytes = vec![0u8; 0x200];
        bytes[0..4].copy_from_slice(b"MDMP");
        bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&0x40u32.to_le_bytes());
        bytes[0x40..0x44].copy_from_slice(&9u32.to_le_bytes());
        bytes[0x44..0x48].copy_from_slice(&32u32.to_le_bytes());
        bytes[0x48..0x4c].copy_from_slice(&0x60u32.to_le_bytes());
        bytes[0x60..0x68].copy_from_slice(&1u64.to_le_bytes());
        bytes[0x68..0x70].copy_from_slice(&0x100u64.to_le_bytes());
        bytes[0x70..0x78].copy_from_slice(&0x60000000u64.to_le_bytes());
        bytes[0x78..0x80].copy_from_slice(&32u64.to_le_bytes());
        for i in 0..32 {
            bytes[0x100 + i] = (0xa0 + i) as u8;
        }
        let filename = format!(
            "angryier-capture-{}-{:?}.dmp",
            std::process::id(),
            std::thread::current().id()
        );
        let path = std::env::temp_dir().join(filename);
        std::fs::write(&path, &bytes).map_err(|error| error.to_string())?;
        Ok(path)
    }

    fn range(len: u64) -> CaptureRange {
        CaptureRange {
            address: 0x60000000,
            length: len,
            readable: true,
            writable: true,
            executable: false,
        }
    }

    #[test]
    fn captured_heap_overlay_is_exact_and_replayable() -> Result<(), String> {
        let path = capture_file()?;
        let mut dump = MiniDumpFile::open(&path).map_err(|error| format!("{error:?}"))?;
        let mut process = make_process()?;
        let report = import_captured_memory(
            &mut process, &mut dump, &[range(32)], CaptureBaseline::ReplayMemory,
        ).map_err(|error| error.to_string())?;
        assert_eq!(report.bytes, 32);
        assert_eq!(report.mapped_new_ranges, 1);
        let snapshot = process.state.memory.read(0x60000000, 32)
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(snapshot.first(), Some(&ByteValue::Concrete(0xa0)));
        assert_eq!(snapshot.last(), Some(&ByteValue::Concrete(0xbf)));
        process.reset_to_entry();
        assert_eq!(
            process.state.memory.read(0x60000000, 32).map_err(|error| format!("{error:?}"))?,
            snapshot,
        );
        std::fs::remove_file(path).map_err(|error| error.to_string())?;
        Ok(())
    }

    #[test]
    fn unavailable_dump_bytes_cannot_partially_mutate_process() -> Result<(), String> {
        let path = capture_file()?;
        let mut dump = MiniDumpFile::open(&path).map_err(|error| format!("{error:?}"))?;
        let mut process = make_process()?;
        let before = process.state.memory.regions().len();
        assert!(import_captured_memory(
            &mut process, &mut dump, &[range(48)], CaptureBaseline::ReplayMemory
        ).is_err());
        assert_eq!(process.state.memory.regions().len(), before);
        assert!(process.state.memory.read(0x60000000, 1).is_err());
        std::fs::remove_file(path).map_err(|error| error.to_string())?;
        Ok(())
    }
}
