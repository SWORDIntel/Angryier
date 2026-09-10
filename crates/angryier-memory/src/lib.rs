#![forbid(unsafe_code)]

use angryier_core::CodeVersionSource;
use angryier_types::{Address, CodePageId, CodePageVersion, CodeVersionGuard, ExprId, ObjectId};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

pub const DEFAULT_PAGE_SIZE: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MemoryAccessKind {
    Read,
    Write,
    Execute,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteValue {
    Concrete(u8),
    Symbolic(ExprId),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageVersion {
    pub page: CodePageId,
    pub version: CodePageVersion,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryRegion {
    pub object: ObjectId,
    pub base: Address,
    pub size: u64,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MemoryError {
    InvalidRegion,
    RegionOverlap,
    AddressOverflow,
    Unmapped(Address),
    PermissionDenied { address: Address, access: MemoryAccessKind },
    VersionOverflow(CodePageId),
}

impl core::fmt::Display for MemoryError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidRegion => formatter.write_str("invalid zero-sized memory region"),
            Self::RegionOverlap => formatter.write_str("memory regions overlap"),
            Self::AddressOverflow => formatter.write_str("memory address arithmetic overflow"),
            Self::Unmapped(address) => write!(formatter, "unmapped memory address: {address:#x}"),
            Self::PermissionDenied { address, access } => {
                write!(formatter, "{access:?} access denied at {address:#x}")
            }
            Self::VersionOverflow(page) => {
                write!(formatter, "code-page version overflow for page {}", page.0)
            }
        }
    }
}

impl std::error::Error for MemoryError {}

pub trait LayeredMemory: Clone + Send + Sync {
    type Error;
    fn read(&self, address: Address, len: usize) -> Result<Vec<ByteValue>, Self::Error>;
    fn write(&self, address: Address, bytes: &[ByteValue]) -> Result<Self, Self::Error>;
    fn fork(&self) -> Self;
    fn page_version(&self, page: CodePageId) -> Option<CodePageVersion>;
    fn regions(&self) -> &[MemoryRegion];
}

pub trait SymbolicAddressResolver: Send + Sync {
    type Error;
    fn candidates(&self, address: ExprId, limit: usize) -> Result<Vec<Address>, Self::Error>;
}

type PageCells = BTreeMap<usize, ByteValue>;

/// Sparse, copy-on-write memory intended for execution-state snapshots.
///
/// The top-level page map and each individual page are independently shared.
/// A fork is O(1); a write clones only the top-level page index and the pages
/// touched by the write. Unmaterialized mapped bytes read as concrete zero.
#[derive(Clone, Debug)]
pub struct PersistentMemory {
    regions: Arc<Vec<MemoryRegion>>,
    pages: Arc<BTreeMap<u64, Arc<PageCells>>>,
    code_versions: Arc<BTreeMap<CodePageId, CodePageVersion>>,
}

impl PersistentMemory {
    pub fn new(mut regions: Vec<MemoryRegion>) -> Result<Self, MemoryError> {
        regions.sort_by_key(|region| region.base);

        let mut previous_end = None;
        let mut code_versions = BTreeMap::new();

        for region in &regions {
            if region.size == 0 {
                return Err(MemoryError::InvalidRegion);
            }

            let end = region
                .base
                .checked_add(region.size)
                .ok_or(MemoryError::AddressOverflow)?;

            if let Some(previous_end) = previous_end
                && region.base < previous_end
            {
                return Err(MemoryError::RegionOverlap);
            }
            previous_end = Some(end);

            if region.executable {
                let first_page = Self::page_number(region.base);
                let last_page = Self::page_number(end - 1);
                for page in first_page..=last_page {
                    code_versions.insert(CodePageId(page), CodePageVersion(0));
                }
            }
        }

        Ok(Self {
            regions: Arc::new(regions),
            pages: Arc::new(BTreeMap::new()),
            code_versions: Arc::new(code_versions),
        })
    }

    /// Loads initial image bytes without applying runtime write permissions or
    /// advancing executable-page versions. This is for loader construction only.
    pub fn load_concrete(&self, address: Address, bytes: &[u8]) -> Result<Self, MemoryError> {
        self.check_mapped_range(address, bytes.len())?;
        let values: Vec<_> = bytes.iter().copied().map(ByteValue::Concrete).collect();
        self.write_materialized(address, &values, false)
    }

    pub fn page_id_for_address(address: Address) -> CodePageId {
        CodePageId(Self::page_number(address))
    }

    pub fn code_version_guards_for_range(
        &self,
        address: Address,
        len: usize,
    ) -> Result<Vec<CodeVersionGuard>, MemoryError> {
        self.check_mapped_range(address, len)?;
        if len == 0 {
            return Ok(Vec::new());
        }

        let end = Self::inclusive_end(address, len)?;
        let first_page = Self::page_number(address);
        let last_page = Self::page_number(end);

        let mut guards = Vec::new();
        for page in first_page..=last_page {
            let page_id = CodePageId(page);
            if let Some(version) = self.code_versions.get(&page_id) {
                guards.push(CodeVersionGuard {
                    page: page_id,
                    version: *version,
                });
            }
        }
        Ok(guards)
    }

    fn page_number(address: Address) -> u64 {
        address / DEFAULT_PAGE_SIZE as u64
    }

    fn page_offset(address: Address) -> usize {
        (address % DEFAULT_PAGE_SIZE as u64) as usize
    }

    fn inclusive_end(address: Address, len: usize) -> Result<Address, MemoryError> {
        if len == 0 {
            return Ok(address);
        }
        let delta = u64::try_from(len - 1).map_err(|_| MemoryError::AddressOverflow)?;
        address.checked_add(delta).ok_or(MemoryError::AddressOverflow)
    }

    fn region_end(region: &MemoryRegion) -> Result<Address, MemoryError> {
        region.base.checked_add(region.size).ok_or(MemoryError::AddressOverflow)
    }

    fn region_containing(&self, address: Address) -> Option<&MemoryRegion> {
        self.regions.iter().find(|region| {
            let Some(end) = region.base.checked_add(region.size) else {
                return false;
            };
            address >= region.base && address < end
        })
    }

    fn check_mapped_range(&self, address: Address, len: usize) -> Result<(), MemoryError> {
        if len == 0 {
            return Ok(());
        }

        let end = Self::inclusive_end(address, len)?;
        let mut cursor = address;

        loop {
            let region = self.region_containing(cursor).ok_or(MemoryError::Unmapped(cursor))?;
            let region_end = Self::region_end(region)?;
            if region_end == 0 {
                return Err(MemoryError::AddressOverflow);
            }
            let region_last = region_end - 1;
            if region_last >= end {
                return Ok(());
            }
            cursor = region_end;
        }
    }

    fn check_access(&self, address: Address, len: usize, access: MemoryAccessKind) -> Result<(), MemoryError> {
        if len == 0 {
            return Ok(());
        }

        let end = Self::inclusive_end(address, len)?;
        let mut cursor = address;

        loop {
            let region = self.region_containing(cursor).ok_or(MemoryError::Unmapped(cursor))?;
            let allowed = match access {
                MemoryAccessKind::Read => region.readable,
                MemoryAccessKind::Write => region.writable,
                MemoryAccessKind::Execute => region.executable,
            };
            if !allowed {
                return Err(MemoryError::PermissionDenied {
                    address: cursor,
                    access,
                });
            }

            let region_end = Self::region_end(region)?;
            let region_last = region_end - 1;
            if region_last >= end {
                return Ok(());
            }
            cursor = region_end;
        }
    }

    fn write_materialized(
        &self,
        address: Address,
        bytes: &[ByteValue],
        bump_executable_versions: bool,
    ) -> Result<Self, MemoryError> {
        if bytes.is_empty() {
            return Ok(self.clone());
        }

        let mut grouped: BTreeMap<u64, Vec<(usize, ByteValue)>> = BTreeMap::new();
        for (index, value) in bytes.iter().copied().enumerate() {
            let offset = u64::try_from(index).map_err(|_| MemoryError::AddressOverflow)?;
            let current = address.checked_add(offset).ok_or(MemoryError::AddressOverflow)?;
            grouped
                .entry(Self::page_number(current))
                .or_default()
                .push((Self::page_offset(current), value));
        }

        let mut pages = (*self.pages).clone();
        for (page, changes) in grouped {
            let mut cells = pages
                .get(&page)
                .map(|existing| (**existing).clone())
                .unwrap_or_default();
            for (offset, value) in changes {
                cells.insert(offset, value);
            }
            pages.insert(page, Arc::new(cells));
        }

        let mut code_versions = (*self.code_versions).clone();
        if bump_executable_versions {
            let end = Self::inclusive_end(address, bytes.len())?;
            let mut touched = BTreeSet::new();
            for page in Self::page_number(address)..=Self::page_number(end) {
                touched.insert(CodePageId(page));
            }

            for page in touched {
                if let Some(version) = code_versions.get_mut(&page) {
                    version.0 = version.0.checked_add(1).ok_or(MemoryError::VersionOverflow(page))?;
                }
            }
        }

        Ok(Self {
            regions: Arc::clone(&self.regions),
            pages: Arc::new(pages),
            code_versions: Arc::new(code_versions),
        })
    }
}

impl LayeredMemory for PersistentMemory {
    type Error = MemoryError;

    fn read(&self, address: Address, len: usize) -> Result<Vec<ByteValue>, Self::Error> {
        self.check_access(address, len, MemoryAccessKind::Read)?;

        let mut output = Vec::with_capacity(len);
        for index in 0..len {
            let offset = u64::try_from(index).map_err(|_| MemoryError::AddressOverflow)?;
            let current = address.checked_add(offset).ok_or(MemoryError::AddressOverflow)?;
            let value = self
                .pages
                .get(&Self::page_number(current))
                .and_then(|page| page.get(&Self::page_offset(current)))
                .copied()
                .unwrap_or(ByteValue::Concrete(0));
            output.push(value);
        }
        Ok(output)
    }

    fn write(&self, address: Address, bytes: &[ByteValue]) -> Result<Self, Self::Error> {
        self.check_access(address, bytes.len(), MemoryAccessKind::Write)?;
        self.write_materialized(address, bytes, true)
    }

    fn fork(&self) -> Self {
        self.clone()
    }

    fn page_version(&self, page: CodePageId) -> Option<CodePageVersion> {
        self.code_versions.get(&page).copied()
    }

    fn regions(&self) -> &[MemoryRegion] {
        self.regions.as_slice()
    }
}

impl CodeVersionSource for PersistentMemory {
    fn code_page_version(&self, page: CodePageId) -> Option<CodePageVersion> {
        self.code_versions.get(&page).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn region(base: u64, size: u64, writable: bool, executable: bool) -> MemoryRegion {
        MemoryRegion {
            object: ObjectId(1),
            base,
            size,
            readable: true,
            writable,
            executable,
        }
    }

    #[test]
    fn forked_memory_is_copy_on_write() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x2000, true, false)])?;
        let memory = memory.load_concrete(0x1000, &[1, 2, 3])?;
        let fork = memory.fork();
        let changed = fork.write(0x1001, &[ByteValue::Concrete(0xaa)])?;

        assert_eq!(
            memory.read(0x1000, 3)?,
            vec![ByteValue::Concrete(1), ByteValue::Concrete(2), ByteValue::Concrete(3)]
        );
        assert_eq!(
            changed.read(0x1000, 3)?,
            vec![
                ByteValue::Concrete(1),
                ByteValue::Concrete(0xaa),
                ByteValue::Concrete(3)
            ]
        );
        Ok(())
    }

    #[test]
    fn executable_write_advances_only_touched_code_pages() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x3000, true, true)])?;
        let page1 = PersistentMemory::page_id_for_address(0x1fff);
        let page2 = PersistentMemory::page_id_for_address(0x2000);
        let page3 = PersistentMemory::page_id_for_address(0x3000);

        assert_eq!(memory.page_version(page1), Some(CodePageVersion(0)));
        assert_eq!(memory.page_version(page2), Some(CodePageVersion(0)));
        assert_eq!(memory.page_version(page3), Some(CodePageVersion(0)));

        let changed = memory.write(0x1fff, &[ByteValue::Concrete(0x90), ByteValue::Concrete(0x90)])?;

        assert_eq!(changed.page_version(page1), Some(CodePageVersion(1)));
        assert_eq!(changed.page_version(page2), Some(CodePageVersion(1)));
        assert_eq!(changed.page_version(page3), Some(CodePageVersion(0)));
        assert_eq!(memory.page_version(page1), Some(CodePageVersion(0)));
        Ok(())
    }

    #[test]
    fn loader_initialization_does_not_advance_code_version() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x4000, 0x1000, false, true)])?;
        let page = PersistentMemory::page_id_for_address(0x4000);
        let loaded = memory.load_concrete(0x4000, &[0x90, 0xc3])?;

        assert_eq!(loaded.page_version(page), Some(CodePageVersion(0)));
        assert_eq!(
            loaded.read(0x4000, 2)?,
            vec![ByteValue::Concrete(0x90), ByteValue::Concrete(0xc3)]
        );
        Ok(())
    }

    #[test]
    fn permission_and_mapping_fail_closed() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x5000, 0x1000, false, true)])?;

        assert!(matches!(
            memory.write(0x5000, &[ByteValue::Concrete(1)]),
            Err(MemoryError::PermissionDenied {
                access: MemoryAccessKind::Write,
                ..
            })
        ));
        assert!(matches!(memory.read(0x7000, 1), Err(MemoryError::Unmapped(0x7000))));
        Ok(())
    }
}
