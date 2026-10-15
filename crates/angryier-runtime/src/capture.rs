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

/// Exact memory input boundary shared by valid MINIDUMP_MEMORY64 streams
/// and independently verified, pre-extracted heap slices. The trait cannot
/// return invented zero-filled gaps or partial reads.
pub trait CapturedMemoryReader {
    fn read_captured(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String>;
}

impl CapturedMemoryReader for MiniDumpFile {
    fn read_captured(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String> {
        self.read(address, length).map_err(|e| format!("{e:?}"))
    }
}

/// One capture region independently associated with a guest virtual address.
/// No ownership of bytes is taken; the caller must retain each source file.
#[derive(Clone, Copy, Debug)]
pub struct CapturedSlice<'a> {
    pub base: u64,
    pub bytes: &'a [u8],
}

/// Read-only collection of verified VA-backed slices. Use when the OS dump's
/// stream directory is missing/corrupted but an independent extraction step
/// has established exact byte-to-VA mappings. The declared source identity
/// is provided by the caller, not authenticated or inferred here.
pub struct SliceCapture<'a> {
    source_identity: [u8; 32],
    regions: Vec<CapturedSlice<'a>>,
}

impl<'a> SliceCapture<'a> {
    pub fn new(source_identity: [u8; 32], mut regions: Vec<CapturedSlice<'a>>) -> Result<Self, RuntimeError> {
        if source_identity == [0; 32] {
            return Err(capture_error("capture identity must not be all zeros"));
        }
        if regions.is_empty() || regions.len() > MAX_SELECTIONS {
            return Err(capture_error("no capture regions or excessive region count"));
        }
        regions.sort_by_key(|r| r.base);
        let mut previous_end: Option<u64> = None;
        for region in &regions {
            if region.bytes.is_empty() {
                return Err(capture_error("empty captured slice"));
            }
            let len = u64::try_from(region.bytes.len()).map_err(|_| capture_error("slice length overflow"))?;
            let end = region
                .base
                .checked_add(len)
                .ok_or_else(|| capture_error("slice VA overflow"))?;
            if previous_end.is_some_and(|p| region.base < p) {
                return Err(capture_error("overlapping captured slices"));
            }
            previous_end = Some(end);
        }
        Ok(Self {
            source_identity,
            regions,
        })
    }

    pub fn source_identity(&self) -> [u8; 32] {
        self.source_identity
    }
}

impl CapturedMemoryReader for SliceCapture<'_> {
    fn read_captured(&mut self, address: u64, length: usize) -> Result<Vec<u8>, String> {
        if length > MAX_SINGLE_READ as usize {
            return Err("requested capture read exceeds 1 MiB".into());
        }
        let end = address
            .checked_add(length as u64)
            .ok_or_else(|| "requested capture address overflow".to_string())?;
        let mut cursor = address;
        let mut out = Vec::with_capacity(length);
        while cursor < end {
            let region = self
                .regions
                .iter()
                .find(|r| cursor >= r.base && cursor - r.base < r.bytes.len() as u64)
                .ok_or_else(|| format!("no captured bytes at VA {cursor:#x}"))?;
            let index = usize::try_from(cursor - region.base).map_err(|_| "slice index overflow".to_string())?;
            let remaining = (end - cursor).min((region.bytes.len() - index) as u64);
            let count = usize::try_from(remaining).map_err(|_| "slice read size overflow".to_string())?;
            out.extend_from_slice(&region.bytes[index..index + count]);
            cursor = cursor
                .checked_add(remaining)
                .ok_or_else(|| "capture cursor overflow".to_string())?;
        }
        Ok(out)
    }
}

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

fn region_placement(memory: &PersistentMemory, address: u64, length: u64) -> Result<bool, RuntimeError> {
    let end = address
        .checked_add(length)
        .ok_or_else(|| capture_error("VA overflow"))?;
    let existing: Vec<&MemoryRegion> = memory
        .regions()
        .iter()
        .filter(|region| {
            let Some(region_end) = region.base.checked_add(region.size) else {
                return true;
            };
            address < region_end && region.base < end
        })
        .collect();
    if existing.is_empty() {
        return Ok(true); // entire range unmapped; allocate exactly captured span
    }
    if existing.len() != 1 || address < existing[0].base || end > existing[0].base.saturating_add(existing[0].size) {
        return Err(capture_error(
            "range partially overlaps existing mapping; refusing ambiguous overlay",
        ));
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
    dump: &mut impl CapturedMemoryReader,
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
        let end = range
            .address
            .checked_add(range.length)
            .ok_or_else(|| capture_error("VA overflow"))?;
        if previous_end.is_some_and(|prior| range.address < prior) {
            return Err(capture_error("overlapping capture selections"));
        }
        previous_end = Some(end);
        total = total
            .checked_add(range.length)
            .ok_or_else(|| capture_error("size overflow"))?;
        if total > MAX_CAPTURED_TOTAL {
            return Err(capture_error("capture exceeds 64 MiB budget"));
        }
    }

    let mut staged = process.state.memory.clone();
    // Object IDs are persistent memory-layer identities; a second import
    // must never reuse the same arbitrary ID for a different captured map.
    let mut next_object_id = staged
        .regions()
        .iter()
        .map(|r| r.object.0)
        .max()
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| capture_error("no free memory object identity"))?;
    let mut new_regions = 0usize;
    for range in &ordered {
        let add_region = region_placement(&staged, range.address, range.length)?;
        if add_region {
            let object = ObjectId(next_object_id);
            next_object_id = next_object_id
                .checked_add(1)
                .ok_or_else(|| capture_error("memory object identity overflow"))?;
            staged = staged
                .with_region(MemoryRegion {
                    object,
                    base: range.address,
                    size: range.length,
                    readable: range.readable,
                    writable: range.writable,
                    executable: range.executable,
                })
                .map_err(|e| capture_error(format!("{e:?}")))?;
            new_regions += 1;
        }
        let mut offset = 0u64;
        while offset < range.length {
            let count = (range.length - offset).min(MAX_SINGLE_READ);
            let location = range
                .address
                .checked_add(offset)
                .ok_or_else(|| capture_error("VA overflow"))?;
            let bytes = dump.read_captured(location, count as usize).map_err(capture_error)?;
            // No fabricated bytes; the source reader requires a complete
            // captured range and reports the first missing byte.
            staged = staged
                .load_concrete(location, &bytes)
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
    use crate::Runtime;
    use angryier_arch::{DecodedInstruction, Decoder};
    use angryier_loader::{LoadedImage, Segment};
    use angryier_memory::{ByteValue, LayeredMemory};
    use angryier_types::{ImageId, SemanticVersion, TargetProfileId};

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
        let report = import_captured_memory(&mut process, &mut dump, &[range(32)], CaptureBaseline::ReplayMemory)
            .map_err(|error| error.to_string())?;
        assert_eq!(report.bytes, 32);
        assert_eq!(report.mapped_new_ranges, 1);
        let snapshot = process
            .state
            .memory
            .read(0x60000000, 32)
            .map_err(|error| format!("{error:?}"))?;
        assert_eq!(snapshot.first(), Some(&ByteValue::Concrete(0xa0)));
        assert_eq!(snapshot.last(), Some(&ByteValue::Concrete(0xbf)));
        process.reset_to_entry();
        assert_eq!(
            process
                .state
                .memory
                .read(0x60000000, 32)
                .map_err(|error| format!("{error:?}"))?,
            snapshot,
        );
        std::fs::remove_file(path).map_err(|error| error.to_string())?;
        Ok(())
    }

    #[test]
    fn independently_mapped_heap_slices_share_the_atomic_import_pipeline() -> Result<(), String> {
        let left = [0xaau8; 16];
        let right = [0xbbu8; 16];
        let regions = vec![
            CapturedSlice {
                base: 0x60000010,
                bytes: &right,
            },
            CapturedSlice {
                base: 0x60000000,
                bytes: &left,
            },
        ];
        let mut capture = SliceCapture::new([0x42; 32], regions).map_err(|e| e.to_string())?;
        assert_eq!(capture.source_identity(), [0x42; 32]);
        assert_eq!(
            capture.read_captured(0x60000008, 16).map_err(|e| e.to_string())?,
            [&left[8..], &right[..8]].concat(),
        );
        let mut process = make_process()?;
        let report = import_captured_memory(&mut process, &mut capture, &[range(32)], CaptureBaseline::ReplayMemory)
            .map_err(|e| e.to_string())?;
        assert_eq!(report.mapped_new_ranges, 1);
        assert_eq!(report.bytes, 32);
        let memory = process
            .state
            .memory
            .read(0x60000000, 32)
            .map_err(|e| format!("{e:?}"))?;
        assert!(memory[..16].iter().all(|b| *b == ByteValue::Concrete(0xaa)));
        assert!(memory[16..].iter().all(|b| *b == ByteValue::Concrete(0xbb)));
        Ok(())
    }

    #[test]
    fn mapped_slices_reject_overlaps_and_uncaptured_gaps() -> Result<(), String> {
        let first = [0x11u8; 8];
        let second = [0x22u8; 8];
        assert!(
            SliceCapture::new(
                [1; 32],
                vec![
                    CapturedSlice {
                        base: 0x2000,
                        bytes: &first
                    },
                    CapturedSlice {
                        base: 0x2004,
                        bytes: &second
                    },
                ]
            )
            .is_err()
        );
        let mut valid = SliceCapture::new(
            [1; 32],
            vec![
                CapturedSlice {
                    base: 0x2000,
                    bytes: &first,
                },
                CapturedSlice {
                    base: 0x2010,
                    bytes: &second,
                },
            ],
        )
        .map_err(|e| e.to_string())?;
        assert!(valid.read_captured(0x2004, 16).is_err());
        assert!(
            SliceCapture::new(
                [0; 32],
                vec![CapturedSlice {
                    base: 0x2000,
                    bytes: &first
                }]
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn unavailable_dump_bytes_cannot_partially_mutate_process() -> Result<(), String> {
        let path = capture_file()?;
        let mut dump = MiniDumpFile::open(&path).map_err(|error| format!("{error:?}"))?;
        let mut process = make_process()?;
        let before = process.state.memory.regions().len();
        assert!(import_captured_memory(&mut process, &mut dump, &[range(48)], CaptureBaseline::ReplayMemory).is_err());
        assert_eq!(process.state.memory.regions().len(), before);
        assert!(process.state.memory.read(0x60000000, 1).is_err());
        std::fs::remove_file(path).map_err(|error| error.to_string())?;
        Ok(())
    }
}
