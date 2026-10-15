//! Read-only Windows minidump memory backed by actual captured bytes.
//!
//! Supports MiniDumpMemoryListStream (5) and MiniDumpMemory64ListStream (9).
//! Uncaptured pages are NEVER synthesized as zero: callers receive a precise
//! missing-address error instead. No process is executed or modified here,
//! and thread contexts, heap objects, handles and synchronization state are
//! not inferred from opaque memory. This is a read-only forensic import seam.

use std::collections::BTreeMap;

const HEADER_SIZE: usize = 32;
const DIRECTORY_SIZE: usize = 12;
const MAX_STREAMS: usize = 1024;
const MAX_RANGES: usize = 200_000;
const MAX_READ: usize = 1024 * 1024;
const MEMORY_LIST: u32 = 5;
const MEMORY64_LIST: u32 = 9;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MiniDumpError {
    InvalidSignature,
    Truncated,
    Overflow,
    UnsupportedMemoryStream,
    TooManyStreams,
    TooManyRanges,
    InvalidRange,
    OverlappingRanges,
    MissingCapture { address: u64 },
    ReadLimitExceeded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MiniDumpSource {
    MemoryList,
    Memory64List,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MiniDumpRegion {
    pub base: u64,
    pub len: u64,
    pub file_offset: u64,
    pub source: MiniDumpSource,
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, MiniDumpError> {
    let end = offset.checked_add(4).ok_or(MiniDumpError::Overflow)?;
    let data: [u8; 4] = bytes.get(offset..end).ok_or(MiniDumpError::Truncated)?
        .try_into().map_err(|_| MiniDumpError::Truncated)?;
    Ok(u32::from_le_bytes(data))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, MiniDumpError> {
    let end = offset.checked_add(8).ok_or(MiniDumpError::Overflow)?;
    let data: [u8; 8] = bytes.get(offset..end).ok_or(MiniDumpError::Truncated)?
        .try_into().map_err(|_| MiniDumpError::Truncated)?;
    Ok(u64::from_le_bytes(data))
}

fn usize_checked(value: u64) -> Result<usize, MiniDumpError> {
    usize::try_from(value).map_err(|_| MiniDumpError::Overflow)
}

#[derive(Clone, Debug)]
pub struct MiniDumpMemory<'a> {
    bytes: &'a [u8],
    regions: Vec<MiniDumpRegion>,
    // Indexed by captured virtual-memory start address.
    starts: BTreeMap<u64, usize>,
}

impl<'a> MiniDumpMemory<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, MiniDumpError> {
        if bytes.get(..4) != Some(b"MDMP") {
            return Err(MiniDumpError::InvalidSignature);
        }
        if bytes.len() < HEADER_SIZE {
            return Err(MiniDumpError::Truncated);
        }
        let count = usize_checked(u64::from(u32_at(bytes, 8)?))?;
        if count > MAX_STREAMS {
            return Err(MiniDumpError::TooManyStreams);
        }
        let directory_offset = usize_checked(u64::from(u32_at(bytes, 12)?))?;
        let directory_len = count.checked_mul(DIRECTORY_SIZE).ok_or(MiniDumpError::Overflow)?;
        let directory_end = directory_offset.checked_add(directory_len).ok_or(MiniDumpError::Overflow)?;
        if directory_end > bytes.len() {
            return Err(MiniDumpError::Truncated);
        }

        let mut regions = Vec::new();
        let mut found = false;
        for i in 0..count {
            let dir = directory_offset + i * DIRECTORY_SIZE;
            let stream_type = u32_at(bytes, dir)?;
            if stream_type != MEMORY_LIST && stream_type != MEMORY64_LIST {
                continue;
            }
            found = true;
            let size = usize_checked(u64::from(u32_at(bytes, dir + 4)?))?;
            let offset = usize_checked(u64::from(u32_at(bytes, dir + 8)?))?;
            let stream_end = offset.checked_add(size).ok_or(MiniDumpError::Overflow)?;
            if stream_end > bytes.len() {
                return Err(MiniDumpError::Truncated);
            }
            if stream_type == MEMORY_LIST {
                if size < 4 {
                    return Err(MiniDumpError::Truncated);
                }
                let n = usize_checked(u64::from(u32_at(bytes, offset)?))?;
                if n > MAX_RANGES || n > MAX_RANGES.saturating_sub(regions.len()) {
                    return Err(MiniDumpError::TooManyRanges);
                }
                let needed = n.checked_mul(16).and_then(|len| len.checked_add(4))
                    .ok_or(MiniDumpError::Overflow)?;
                if needed > size {
                    return Err(MiniDumpError::Truncated);
                }
                for j in 0..n {
                    let item = offset + 4 + j * 16;
                    let base = u64_at(bytes, item)?;
                    let length = u64::from(u32_at(bytes, item + 8)?);
                    let file_offset = u64::from(u32_at(bytes, item + 12)?);
                    regions.push(MiniDumpRegion {
                        base,
                        len: length,
                        file_offset,
                        source: MiniDumpSource::MemoryList,
                    });
                }
            } else {
                if size < 16 {
                    return Err(MiniDumpError::Truncated);
                }
                let n = usize_checked(u64_at(bytes, offset)?)?;
                if n > MAX_RANGES || n > MAX_RANGES.saturating_sub(regions.len()) {
                    return Err(MiniDumpError::TooManyRanges);
                }
                let needed = n.checked_mul(16).and_then(|len| len.checked_add(16))
                    .ok_or(MiniDumpError::Overflow)?;
                if needed > size {
                    return Err(MiniDumpError::Truncated);
                }
                let mut file_offset = u64_at(bytes, offset + 8)?;
                for j in 0..n {
                    let item = offset + 16 + j * 16;
                    let base = u64_at(bytes, item)?;
                    let length = u64_at(bytes, item + 8)?;
                    regions.push(MiniDumpRegion {
                        base,
                        len: length,
                        file_offset,
                        source: MiniDumpSource::Memory64List,
                    });
                    file_offset = file_offset.checked_add(length).ok_or(MiniDumpError::Overflow)?;
                }
            }
        }
        if !found {
            return Err(MiniDumpError::UnsupportedMemoryStream);
        }
        regions.sort_by_key(|region| region.base);
        let mut starts = BTreeMap::new();
        let mut previous_end: Option<u64> = None;
        for (index, region) in regions.iter().enumerate() {
            let end = region.base.checked_add(region.len).ok_or(MiniDumpError::Overflow)?;
            let last_file_byte = region.file_offset.checked_add(region.len).ok_or(MiniDumpError::Overflow)?;
            if region.len == 0 || last_file_byte > bytes.len() as u64 {
                return Err(MiniDumpError::InvalidRange);
            }
            if previous_end.is_some_and(|previous| region.base < previous) {
                return Err(MiniDumpError::OverlappingRanges);
            }
            previous_end = Some(end);
            starts.insert(region.base, index);
        }
        Ok(Self { bytes, regions, starts })
    }

    pub fn regions(&self) -> &[MiniDumpRegion] {
        &self.regions
    }

    pub fn region_at(&self, address: u64) -> Option<&MiniDumpRegion> {
        let (_, &index) = self.starts.range(..=address).next_back()?;
        let region = &self.regions[index];
        (address - region.base < region.len).then_some(region)
    }

    /// Reads captured data without inventing zero-filled gaps. Crossing
    /// adjacent captured VA ranges is supported even if their underlying
    /// file offsets are non-contiguous. The one-call ceiling bounds allocation.
    pub fn read(&self, address: u64, length: usize) -> Result<Vec<u8>, MiniDumpError> {
        if length > MAX_READ {
            return Err(MiniDumpError::ReadLimitExceeded);
        }
        let end = address.checked_add(length as u64).ok_or(MiniDumpError::Overflow)?;
        let mut out = Vec::with_capacity(length);
        let mut current = address;
        while current < end {
            let region = self.region_at(current)
                .ok_or(MiniDumpError::MissingCapture { address: current })?;
            let offset_in_region = current - region.base;
            let remaining_region = region.len - offset_in_region;
            let available = (end - current).min(remaining_region);
            let file_offset = region.file_offset.checked_add(offset_in_region)
                .ok_or(MiniDumpError::Overflow)?;
            let start = usize_checked(file_offset)?;
            let chunk_len = usize_checked(available)?;
            let file_end = start.checked_add(chunk_len).ok_or(MiniDumpError::Overflow)?;
            out.extend_from_slice(
                self.bytes.get(start..file_end).ok_or(MiniDumpError::InvalidRange)?
            );
            current = current.checked_add(available).ok_or(MiniDumpError::Overflow)?;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn memory_list_fixture() -> Vec<u8> {
        let mut bytes = vec![0u8; 0x200];
        bytes[0..4].copy_from_slice(b"MDMP");
        bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&0x40u32.to_le_bytes());
        bytes[0x40..0x44].copy_from_slice(&MEMORY_LIST.to_le_bytes());
        bytes[0x44..0x48].copy_from_slice(&20u32.to_le_bytes());
        bytes[0x48..0x4c].copy_from_slice(&0x60u32.to_le_bytes());
        bytes[0x60..0x64].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x64..0x6c].copy_from_slice(&0x094464c0u64.to_le_bytes());
        bytes[0x6c..0x70].copy_from_slice(&64u32.to_le_bytes());
        bytes[0x70..0x74].copy_from_slice(&0x100u32.to_le_bytes());
        for i in 0..64 {
            bytes[0x100 + i] = i as u8;
        }
        bytes
    }

    #[test]
    fn extracts_exact_captured_singleton_bytes() {
        let bytes = memory_list_fixture();
        let dump = MiniDumpMemory::parse(&bytes).expect("minidump");
        assert_eq!(dump.regions().len(), 1);
        let read = dump.read(0x094464c0, 0x40).expect("captured object");
        assert_eq!(read.len(), 64);
        assert_eq!(read[0], 0);
        assert_eq!(read[63], 63);
    }

    #[test]
    fn missing_page_is_not_zero_filled() {
        let bytes = memory_list_fixture();
        let dump = MiniDumpMemory::parse(&bytes).expect("minidump");
        assert_eq!(
            dump.read(0x094464fc, 16),
            Err(MiniDumpError::MissingCapture { address: 0x09446500 })
        );
        assert_eq!(
            dump.read(0x094464c0, MAX_READ + 1),
            Err(MiniDumpError::ReadLimitExceeded)
        );
    }

    #[test]
    fn memory64_stream_uses_cumulative_file_offsets() {
        let mut bytes = vec![0u8; 0x200];
        bytes[0..4].copy_from_slice(b"MDMP");
        bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
        bytes[12..16].copy_from_slice(&0x40u32.to_le_bytes());
        bytes[0x40..0x44].copy_from_slice(&MEMORY64_LIST.to_le_bytes());
        bytes[0x44..0x48].copy_from_slice(&48u32.to_le_bytes());
        bytes[0x48..0x4c].copy_from_slice(&0x60u32.to_le_bytes());
        bytes[0x60..0x68].copy_from_slice(&2u64.to_le_bytes());
        bytes[0x68..0x70].copy_from_slice(&0x100u64.to_le_bytes());
        bytes[0x70..0x78].copy_from_slice(&0x1000u64.to_le_bytes());
        bytes[0x78..0x80].copy_from_slice(&2u64.to_le_bytes());
        bytes[0x80..0x88].copy_from_slice(&0x1002u64.to_le_bytes());
        bytes[0x88..0x90].copy_from_slice(&3u64.to_le_bytes());
        bytes[0x100..0x105].copy_from_slice(&[1, 2, 3, 4, 5]);
        let dump = MiniDumpMemory::parse(&bytes).expect("minidump64");
        assert_eq!(dump.read(0x1000, 5), Ok(vec![1, 2, 3, 4, 5]));
    }

    #[test]
    fn malformed_and_overlap_fail_closed() {
        assert!(matches!(MiniDumpMemory::parse(b"bad"), Err(MiniDumpError::InvalidSignature)));
        let mut bytes = memory_list_fixture();
        bytes[0x70..0x74].copy_from_slice(&0x1f0u32.to_le_bytes());
        assert!(matches!(MiniDumpMemory::parse(&bytes), Err(MiniDumpError::InvalidRange)));
    }
}
