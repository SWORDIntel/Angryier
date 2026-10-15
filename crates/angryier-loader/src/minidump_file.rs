//! Streaming, read-only minidump memory reader for large forensic dumps.
//! Only stream tables and the requested captured bytes are read from disk.
//! This avoids loading multi-gigabyte dumps just to inspect an object.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crate::minidump::{MiniDumpError, MiniDumpRegion, MiniDumpSource};

const MAX_STREAMS: usize = 1024;
const MAX_RANGES: usize = 200_000;
const MAX_READ: usize = 1024 * 1024;
const MEMORY_LIST: u32 = 5;
const MEMORY64_LIST: u32 = 9;

#[derive(Debug)]
pub enum MiniDumpFileError {
    Io(std::io::Error),
    Format(MiniDumpError),
}

impl From<std::io::Error> for MiniDumpFileError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<MiniDumpError> for MiniDumpFileError {
    fn from(value: MiniDumpError) -> Self {
        Self::Format(value)
    }
}

fn as_u32(bytes: &[u8], offset: usize) -> Result<u32, MiniDumpFileError> {
    let end = offset.checked_add(4).ok_or(MiniDumpError::Overflow)?;
    let value: [u8; 4] = bytes
        .get(offset..end)
        .ok_or(MiniDumpError::Truncated)?
        .try_into()
        .map_err(|_| MiniDumpError::Truncated)?;
    Ok(u32::from_le_bytes(value))
}

fn as_u64(bytes: &[u8], offset: usize) -> Result<u64, MiniDumpFileError> {
    let end = offset.checked_add(8).ok_or(MiniDumpError::Overflow)?;
    let value: [u8; 8] = bytes
        .get(offset..end)
        .ok_or(MiniDumpError::Truncated)?
        .try_into()
        .map_err(|_| MiniDumpError::Truncated)?;
    Ok(u64::from_le_bytes(value))
}

fn read_at(
    file: &mut File,
    file_size: u64,
    offset: u64,
    size: usize,
) -> Result<Vec<u8>, MiniDumpFileError> {
    let end = offset
        .checked_add(u64::try_from(size).map_err(|_| MiniDumpError::Overflow)?)
        .ok_or(MiniDumpError::Overflow)?;
    if end > file_size {
        return Err(MiniDumpError::Truncated.into());
    }
    let mut bytes = vec![0u8; size];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut bytes)?;
    Ok(bytes)
}

pub struct MiniDumpFile {
    file: File,
    file_size: u64,
    regions: Vec<MiniDumpRegion>,
    starts: BTreeMap<u64, usize>,
}

impl MiniDumpFile {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, MiniDumpFileError> {
        let mut file = File::open(path)?;
        let file_size = file.metadata()?.len();
        let header = read_at(&mut file, file_size, 0, 32)?;
        if header.get(..4) != Some(b"MDMP") {
            return Err(MiniDumpError::InvalidSignature.into());
        }
        let count = usize::try_from(as_u32(&header, 8)?).map_err(|_| MiniDumpError::Overflow)?;
        if count > MAX_STREAMS {
            return Err(MiniDumpError::TooManyStreams.into());
        }
        let directory_rva = u64::from(as_u32(&header, 12)?);
        let directory_size = count.checked_mul(12).ok_or(MiniDumpError::Overflow)?;
        let directory = read_at(&mut file, file_size, directory_rva, directory_size)?;

        let mut regions = Vec::new();
        let mut found = false;
        for i in 0..count {
            let off = i * 12;
            let kind = as_u32(&directory, off)?;
            if kind != MEMORY_LIST && kind != MEMORY64_LIST {
                continue;
            }
            found = true;
            let stream_len = usize::try_from(as_u32(&directory, off + 4)?)
                .map_err(|_| MiniDumpError::Overflow)?;
            let stream_rva = u64::from(as_u32(&directory, off + 8)?);
            // Stream data is a list of descriptors, not the memory bytes.
            // Refuse maliciously large table allocations before reading.
            if stream_len > 16 + MAX_RANGES * 16 {
                return Err(MiniDumpError::TooManyRanges.into());
            }
            let stream = read_at(&mut file, file_size, stream_rva, stream_len)?;
            let header_size = if kind == MEMORY_LIST { 4 } else { 16 };
            if stream.len() < header_size {
                return Err(MiniDumpError::Truncated.into());
            }
            let ranges = if kind == MEMORY_LIST {
                usize::try_from(as_u32(&stream, 0)?).map_err(|_| MiniDumpError::Overflow)?
            } else {
                usize::try_from(as_u64(&stream, 0)?).map_err(|_| MiniDumpError::Overflow)?
            };
            if ranges > MAX_RANGES.saturating_sub(regions.len())
                || ranges.checked_mul(16).and_then(|v| v.checked_add(header_size))
                    .is_none_or(|needed| needed > stream.len())
            {
                return Err(MiniDumpError::TooManyRanges.into());
            }
            let mut file_offset = if kind == MEMORY64_LIST { as_u64(&stream, 8)? } else { 0 };
            for j in 0..ranges {
                let entry = header_size + j * 16;
                let base = as_u64(&stream, entry)?;
                let (len, offset) = if kind == MEMORY_LIST {
                    (
                        u64::from(as_u32(&stream, entry + 8)?),
                        u64::from(as_u32(&stream, entry + 12)?),
                    )
                } else {
                    let len = as_u64(&stream, entry + 8)?;
                    let offset = file_offset;
                    file_offset = file_offset.checked_add(len).ok_or(MiniDumpError::Overflow)?;
                    (len, offset)
                };
                regions.push(MiniDumpRegion {
                    base,
                    len,
                    file_offset: offset,
                    source: if kind == MEMORY_LIST {
                        MiniDumpSource::MemoryList
                    } else {
                        MiniDumpSource::Memory64List
                    },
                });
            }
        }
        if !found {
            return Err(MiniDumpError::UnsupportedMemoryStream.into());
        }
        regions.sort_by_key(|region| region.base);
        let mut starts = BTreeMap::new();
        let mut end = None::<u64>;
        for (index, region) in regions.iter().enumerate() {
            let region_end = region.base.checked_add(region.len).ok_or(MiniDumpError::Overflow)?;
            let file_end = region.file_offset.checked_add(region.len).ok_or(MiniDumpError::Overflow)?;
            if region.len == 0 || file_end > file_size {
                return Err(MiniDumpError::InvalidRange.into());
            }
            if end.is_some_and(|last| region.base < last) {
                return Err(MiniDumpError::OverlappingRanges.into());
            }
            end = Some(region_end);
            starts.insert(region.base, index);
        }
        Ok(Self { file, file_size, regions, starts })
    }

    pub fn regions(&self) -> &[MiniDumpRegion] {
        &self.regions
    }

    pub fn file_size(&self) -> u64 {
        self.file_size
    }

    /// Read only complete captured bytes with a strict per-call allocation
    /// limit. Uncaptured heap pages yield MissingCapture, not fake zeroes.
    pub fn read(&mut self, address: u64, length: usize) -> Result<Vec<u8>, MiniDumpFileError> {
        if length > MAX_READ {
            return Err(MiniDumpError::ReadLimitExceeded.into());
        }
        let end = address.checked_add(length as u64).ok_or(MiniDumpError::Overflow)?;
        let mut cursor = address;
        let mut out = Vec::with_capacity(length);
        while cursor < end {
            let (_, &index) = self.starts.range(..=cursor).next_back()
                .ok_or(MiniDumpError::MissingCapture { address: cursor })?;
            let region = self.regions[index];
            if cursor - region.base >= region.len {
                return Err(MiniDumpError::MissingCapture { address: cursor }.into());
            }
            let take = (region.len - (cursor - region.base)).min(end - cursor);
            let raw_start = region.file_offset.checked_add(cursor - region.base)
                .ok_or(MiniDumpError::Overflow)?;
            let data = read_at(
                &mut self.file,
                self.file_size,
                raw_start,
                usize::try_from(take).map_err(|_| MiniDumpError::Overflow)?,
            )?;
            out.extend_from_slice(&data);
            cursor = cursor.checked_add(take).ok_or(MiniDumpError::Overflow)?;
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn memory64_file_reads_only_requested_bytes() -> Result<(), MiniDumpFileError> {
        let mut dump = vec![0u8; 0x200];
        dump[0..4].copy_from_slice(b"MDMP");
        dump[8..12].copy_from_slice(&1u32.to_le_bytes());
        dump[12..16].copy_from_slice(&0x40u32.to_le_bytes());
        dump[0x40..0x44].copy_from_slice(&MEMORY64_LIST.to_le_bytes());
        dump[0x44..0x48].copy_from_slice(&32u32.to_le_bytes());
        dump[0x48..0x4c].copy_from_slice(&0x60u32.to_le_bytes());
        dump[0x60..0x68].copy_from_slice(&1u64.to_le_bytes());
        dump[0x68..0x70].copy_from_slice(&0x100u64.to_le_bytes());
        dump[0x70..0x78].copy_from_slice(&0x094464c0u64.to_le_bytes());
        dump[0x78..0x80].copy_from_slice(&64u64.to_le_bytes());
        dump[0x100..0x140].copy_from_slice(&[0x41u8; 64]);

        let dir = std::env::temp_dir().join(format!(
            "angryier-dump-{}-{:?}.dmp",
            std::process::id(),
            std::thread::current().id(),
        ));
        let mut file = File::create(&dir)?;
        file.write_all(&dump)?;
        drop(file);
        let mut reader = MiniDumpFile::open(&dir)?;
        assert_eq!(reader.file_size(), 512);
        assert_eq!(reader.read(0x094464c0, 4)?, vec![0x41; 4]);
        assert!(matches!(
            reader.read(0x09446500, 1),
            Err(MiniDumpFileError::Format(MiniDumpError::MissingCapture { address: 0x09446500 }))
        ));
        std::fs::remove_file(&dir)?;
        Ok(())
    }
}
