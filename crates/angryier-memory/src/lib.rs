#![forbid(unsafe_code)]

use angryier_types::{Address, CodePageId, CodePageVersion, ExprId, ObjectId};

pub const DEFAULT_PAGE_SIZE: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MemoryAccessKind { Read, Write, Execute }

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ByteValue { Concrete(u8), Symbolic(ExprId) }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageVersion { pub page: CodePageId, pub version: CodePageVersion }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryRegion { pub object: ObjectId, pub base: Address, pub size: u64, pub readable: bool, pub writable: bool, pub executable: bool }

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
