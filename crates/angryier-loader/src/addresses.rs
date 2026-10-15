//! Exact PE32+ address translation for file-backed binary analysis.
//!
//! A mapped virtual image is NOT a byte-for-byte PE file. This module keeps
//! VA/RVA/file-offset conversion separate and refuses to decode a BSS tail or
//! an unavailable file range as though it held executable bytes. Its file map
//! describes the original image and must not be used to infer post-unpacking
//! changes in process memory.

use crate::{LoaderError, read_u16_le, read_u32_le, read_u64_le_at};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeAddressError {
    InvalidImage,
    Overflow,
    AmbiguousMapping,
    Unmapped { rva: u32 },
    NotFileBacked { rva: u32 },
    CrossesBoundary,
    OutOfBounds,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeFileSection {
    pub name: String,
    pub rva: u32,
    /// Effective address-space span: max(VirtualSize, SizeOfRawData).
    pub virtual_span: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeLocation {
    Header { file_offset: u64 },
    Section { index: usize, file_offset: u64 },
    ZeroFill { index: usize },
}

#[derive(Clone, Debug)]
pub struct PeAddressMap {
    image_base: u64,
    header_len: u32,
    file_size: u64,
    sections: Vec<PeFileSection>,
}

fn checked_u32(bytes: &[u8], offset: usize) -> Result<u32, PeAddressError> {
    read_u32_le(bytes, offset).map_err(|_| PeAddressError::InvalidImage)
}

fn checked_u16(bytes: &[u8], offset: usize) -> Result<u16, PeAddressError> {
    read_u16_le(bytes, offset).map_err(|_| PeAddressError::InvalidImage)
}

fn checked_u64(bytes: &[u8], offset: usize) -> Result<u64, PeAddressError> {
    read_u64_le_at(bytes, offset).map_err(|_| PeAddressError::InvalidImage)
}

impl PeAddressMap {
    /// Parse the file-backed PE32+ x86-64 section map using checked offsets.
    /// Overlapping mapped section spans and sections overlapping PE headers
    /// are rejected: resolving them by arbitrary first-match order would
    /// produce misleading disassembly.
    pub fn parse(bytes: &[u8]) -> Result<Self, PeAddressError> {
        if bytes.get(..2) != Some(b"MZ") || bytes.len() < 0x40 {
            return Err(PeAddressError::InvalidImage);
        }
        let pe_offset = usize::try_from(checked_u32(bytes, 0x3c)?)
            .map_err(|_| PeAddressError::Overflow)?;
        let coff = pe_offset.checked_add(4).ok_or(PeAddressError::Overflow)?;
        if bytes.get(pe_offset..coff) != Some(b"PE\0\0") {
            return Err(PeAddressError::InvalidImage);
        }
        if checked_u16(bytes, coff)? != 0x8664 {
            return Err(PeAddressError::InvalidImage);
        }
        let sections_count = usize::from(checked_u16(bytes, coff + 2)?);
        // Avoid allocating attacker-controlled section counts and parsing
        // implausible images that cannot be trusted for analysis.
        if sections_count > 96 {
            return Err(PeAddressError::InvalidImage);
        }
        let optional_size = usize::from(checked_u16(bytes, coff + 16)?);
        let optional = coff.checked_add(20).ok_or(PeAddressError::Overflow)?;
        let optional_end = optional.checked_add(optional_size).ok_or(PeAddressError::Overflow)?;
        if optional_size < 64 || optional_end > bytes.len()
            || checked_u16(bytes, optional)? != 0x20b
        {
            return Err(PeAddressError::InvalidImage);
        }
        let image_base = checked_u64(bytes, optional + 24)?;
        let header_len = checked_u32(bytes, optional + 60)?;
        if header_len == 0 || u64::from(header_len) > bytes.len() as u64
            || optional_end > usize::try_from(header_len).unwrap_or(0)
        {
            return Err(PeAddressError::InvalidImage);
        }
        let table_bytes = sections_count.checked_mul(40).ok_or(PeAddressError::Overflow)?;
        let table_end = optional_end.checked_add(table_bytes).ok_or(PeAddressError::Overflow)?;
        if table_end > bytes.len() || table_end > usize::try_from(header_len).unwrap_or(0) {
            return Err(PeAddressError::InvalidImage);
        }
        let mut sections = Vec::with_capacity(sections_count);
        for i in 0..sections_count {
            let off = optional_end + i * 40;
            let name_bytes = bytes.get(off..off + 8).ok_or(PeAddressError::InvalidImage)?;
            let name_end = name_bytes.iter().position(|b| *b == 0).unwrap_or(8);
            let name = String::from_utf8_lossy(&name_bytes[..name_end]).to_string();
            let virtual_size = checked_u32(bytes, off + 8)?;
            let rva = checked_u32(bytes, off + 12)?;
            let raw_size = checked_u32(bytes, off + 16)?;
            let raw_offset = checked_u32(bytes, off + 20)?;
            let characteristics = checked_u32(bytes, off + 36)?;
            let virtual_span = virtual_size.max(raw_size);
            let virtual_end = rva.checked_add(virtual_span).ok_or(PeAddressError::Overflow)?;
            let raw_end = u64::from(raw_offset)
                .checked_add(u64::from(raw_size)).ok_or(PeAddressError::Overflow)?;
            if raw_end > bytes.len() as u64 {
                return Err(PeAddressError::OutOfBounds);
            }
            if virtual_span != 0 && rva < header_len {
                return Err(PeAddressError::AmbiguousMapping);
            }
            if virtual_end < rva {
                return Err(PeAddressError::Overflow);
            }
            sections.push(PeFileSection {
                name,
                rva,
                virtual_span,
                raw_offset,
                raw_size,
                readable: characteristics & 0x4000_0000 != 0,
                writable: characteristics & 0x8000_0000 != 0,
                executable: characteristics & 0x2000_0000 != 0,
            });
        }
        sections.sort_by_key(|s| s.rva);
        let mut last_end = header_len;
        for section in &sections {
            if section.virtual_span > 0 && section.rva < last_end {
                return Err(PeAddressError::AmbiguousMapping);
            }
            last_end = last_end.max(section.rva.saturating_add(section.virtual_span));
        }
        Ok(Self {
            image_base,
            header_len,
            file_size: bytes.len() as u64,
            sections,
        })
    }

    pub fn image_base(&self) -> u64 {
        self.image_base
    }

    pub fn sections(&self) -> &[PeFileSection] {
        &self.sections
    }

    pub fn va_to_rva(&self, va: u64) -> Result<u32, PeAddressError> {
        let delta = va.checked_sub(self.image_base).ok_or(PeAddressError::OutOfBounds)?;
        u32::try_from(delta).map_err(|_| PeAddressError::OutOfBounds)
    }

    pub fn rva_to_va(&self, rva: u32) -> Result<u64, PeAddressError> {
        self.image_base.checked_add(u64::from(rva)).ok_or(PeAddressError::Overflow)
    }

    pub fn locate_rva(&self, rva: u32) -> Result<PeLocation, PeAddressError> {
        if rva < self.header_len {
            return Ok(PeLocation::Header {
                file_offset: u64::from(rva),
            });
        }
        let section = self.sections.iter().enumerate().find(|(_, section)| {
            rva >= section.rva && u64::from(rva - section.rva) < u64::from(section.virtual_span)
        });
        let (index, section) = section.ok_or(PeAddressError::Unmapped { rva })?;
        let offset = rva - section.rva;
        if offset < section.raw_size {
            let file_offset = u64::from(section.raw_offset) + u64::from(offset);
            if file_offset < self.file_size {
                return Ok(PeLocation::Section { index, file_offset });
            }
            return Err(PeAddressError::OutOfBounds);
        }
        Ok(PeLocation::ZeroFill { index })
    }

    pub fn locate_va(&self, va: u64) -> Result<PeLocation, PeAddressError> {
        self.locate_rva(self.va_to_rva(va)?)
    }

    /// Return a file offset ONLY when all requested bytes are contiguous,
    /// file-backed and belong to the same section/header. A read into BSS or
    /// across a section boundary fails rather than emitting invented bytes.
    pub fn file_offset(&self, va: u64, length: usize) -> Result<u64, PeAddressError> {
        let rva = self.va_to_rva(va)?;
        let len = u64::try_from(length).map_err(|_| PeAddressError::Overflow)?;
        let rva_end = u64::from(rva).checked_add(len).ok_or(PeAddressError::Overflow)?;
        match self.locate_rva(rva)? {
            PeLocation::Header { file_offset } => {
                if rva_end > u64::from(self.header_len) {
                    return Err(PeAddressError::CrossesBoundary);
                }
                Ok(file_offset)
            }
            PeLocation::Section { index, file_offset } => {
                let section = &self.sections[index];
                if rva_end > u64::from(section.rva) + u64::from(section.raw_size) {
                    return Err(PeAddressError::CrossesBoundary);
                }
                Ok(file_offset)
            }
            PeLocation::ZeroFill { .. } => Err(PeAddressError::NotFileBacked { rva }),
        }
    }

    pub fn bytes_at_va<'a>(
        &self,
        bytes: &'a [u8],
        va: u64,
        length: usize,
    ) -> Result<&'a [u8], PeAddressError> {
        if bytes.len() as u64 != self.file_size {
            return Err(PeAddressError::InvalidImage);
        }
        let offset = usize::try_from(self.file_offset(va, length)?)
            .map_err(|_| PeAddressError::Overflow)?;
        let end = offset.checked_add(length).ok_or(PeAddressError::Overflow)?;
        bytes.get(offset..end).ok_or(PeAddressError::OutOfBounds)
    }
}

impl From<LoaderError> for PeAddressError {
    fn from(_: LoaderError) -> Self {
        Self::InvalidImage
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Vec<u8> {
        let mut image = vec![0u8; 0x800];
        image[0..2].copy_from_slice(b"MZ");
        image[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        image[0x80..0x84].copy_from_slice(b"PE\0\0");
        image[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        image[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        image[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
        let opt = 0x98;
        image[opt..opt + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        image[opt + 24..opt + 32].copy_from_slice(&0x140000000u64.to_le_bytes());
        image[opt + 60..opt + 64].copy_from_slice(&0x200u32.to_le_bytes());
        let sec = 0x188;
        image[sec..sec + 5].copy_from_slice(b".text");
        image[sec + 8..sec + 12].copy_from_slice(&0x600u32.to_le_bytes());
        image[sec + 12..sec + 16].copy_from_slice(&0x1000u32.to_le_bytes());
        image[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes());
        image[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes());
        image[sec + 36..sec + 40].copy_from_slice(&0x6000_0000u32.to_le_bytes());
        image[0x210..0x215].copy_from_slice(&[0x48, 0x89, 0xe0, 0x55, 0x57]);
        image
    }

    #[test]
    fn pe_va_rva_and_disk_bytes_remain_distinct() {
        let bytes = fixture();
        let map = PeAddressMap::parse(&bytes).expect("map");
        let va = 0x140001010;
        assert_eq!(map.va_to_rva(va), Ok(0x1010));
        assert_eq!(map.file_offset(va, 5), Ok(0x210));
        assert_eq!(map.bytes_at_va(&bytes, va, 5), Ok(&bytes[0x210..0x215]));
        assert_eq!(map.rva_to_va(0x1010), Ok(va));
        assert_eq!(map.locate_rva(0x1400), Ok(PeLocation::ZeroFill { index: 0 }));
        assert_eq!(map.file_offset(0x140001400, 1), Err(PeAddressError::NotFileBacked { rva: 0x1400 }));
        assert_eq!(map.file_offset(0x1400011ff, 2), Err(PeAddressError::CrossesBoundary));
        assert_eq!(map.locate_rva(0x3000), Err(PeAddressError::Unmapped { rva: 0x3000 }));
    }

    #[test]
    fn rejects_ambiguous_and_out_of_range_sections() {
        let mut bytes = fixture();
        bytes[0x188 + 12..0x188 + 16].copy_from_slice(&0x100u32.to_le_bytes());
        assert!(matches!(PeAddressMap::parse(&bytes), Err(PeAddressError::AmbiguousMapping)));
        let mut bytes = fixture();
        bytes[0x188 + 20..0x188 + 24].copy_from_slice(&0x700u32.to_le_bytes());
        assert!(matches!(PeAddressMap::parse(&bytes), Err(PeAddressError::OutOfBounds)));
        assert!(matches!(PeAddressMap::parse(&bytes[..0x90]), Err(PeAddressError::InvalidImage)));
    }
}
