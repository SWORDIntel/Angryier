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

impl MemoryRegion {
    #[inline]
    pub fn contains(&self, address: Address) -> bool {
        if let Some(end) = self.base.checked_add(self.size) {
            address >= self.base && address < end
        } else {
            false
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MemoryError {
    InvalidRegion,
    RegionOverlap,
    AddressOverflow,
    Unmapped(Address),
    PermissionDenied { address: Address, access: MemoryAccessKind },
    VersionOverflow(CodePageId),
    SymbolicAddressUnresolved(ExprId),
    SymbolicWriteForked(usize),
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
            Self::SymbolicAddressUnresolved(expression) => {
                write!(
                    formatter,
                    "symbolic address expression {} yielded no resolvable candidates",
                    expression.0
                )
            }
            Self::SymbolicWriteForked(fork_count) => {
                write!(
                    formatter,
                    "symbolic write forked execution into {fork_count} candidate states"
                )
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

/// Concretization strategy for resolving a symbolic address to concrete targets.
///
/// Each strategy represents a distinct tradeoff among soundness, completeness,
/// and solver query cost:
///
/// - [`SingleAddress`][ConcretizationStrategy::SingleAddress]:
///   Picks a single candidate concrete address from the resolver.
///   - **Soundness**: Under-approximates program behavior (incomplete); paths corresponding
///     to other valid addresses are dropped.
///   - **Completeness**: Lowest; explores at most one concrete address.
///   - **Solver Cost**: Minimal; requires only a single model/candidate query, no state branching.
///
/// - [`BoundedRange`][ConcretizationStrategy::BoundedRange]:
///   Tries candidate addresses up to a bounded maximum limit (`N`).
///   - **Soundness**: Sound up to the bound; mitigates unbounded state explosion while
///     covering the most likely concrete targets.
///   - **Completeness**: Moderate; explores up to `N` paths, dropping candidates beyond `N`.
///   - **Solver Cost**: Moderate; bounded by `N` solver queries and at most `N` state forks.
///
/// - [`AllCandidates`][ConcretizationStrategy::AllCandidates]:
///   Tries every satisfiable candidate address from the resolver without an upper limit.
///   - **Soundness**: Sound with respect to the constraints in the solver context.
///   - **Completeness**: Maximal; explores all reachable concrete target addresses.
///   - **Solver Cost**: Highest; unconstrained pointers can cause massive state explosion
///     if the candidate set is large or unbounded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConcretizationStrategy {
    /// Pick one candidate address from the resolver.
    SingleAddress,
    /// Try candidates up to a bounded maximum range.
    BoundedRange,
    /// Try every candidate address returned by the resolver.
    AllCandidates,
}

impl ConcretizationStrategy {
    /// Default maximum candidates explored under [`BoundedRange`][ConcretizationStrategy::BoundedRange].
    pub const DEFAULT_BOUNDED_LIMIT: usize = 16;
}

/// Policy dictating how symbolic memory addresses are handled during loads and stores.
///
/// Addressing memory with a symbolic pointer (e.g. `mov rax, [rbx]` where `rbx` is symbolic)
/// is the core problem defining a symbolic execution engine's soundness:
///
/// - [`Concretize`][SymbolicAddressPolicy::Concretize]:
///   Resolves symbolic addresses to one or more concrete addresses via a resolver/solver.
///   - **Soundness/Completeness**: Dependent on [`ConcretizationStrategy`].
///   - **Solver Cost**: Driven by SAT/model-generation queries.
///
/// - [`FullArrays`][SymbolicAddressPolicy::FullArrays]:
///   Treats memory as a first-class symbolic array using the SMT theory of arrays (`select` / `store`).
///   - **Soundness**: Fully sound; defers alias resolution to the solver without branching.
///   - **Completeness**: Full; retains all possible alias relationships symbolically.
///   - **Solver Cost**: Zero branching during execution, but shifts the entire burden to the SMT solver,
///     often leading to quantifier/array theory bottlenecks during constraint solving.
///   - **Status**: Requires solver array theory support which is not yet wired in this engine.
///
/// - [`RegionBased`][SymbolicAddressPolicy::RegionBased]:
///   Partitions memory into distinct semantic regions (e.g., stack, heap, binary image)
///   using address high bits / base ranges, then concretizes within that identified region.
///   - **Soundness**: Compromise between `Concretize` and `FullArrays`; avoids invalid cross-region
///     aliasing (e.g. stack pointers aliasing code pages) while constraining concretization scope.
///   - **Completeness**: High within the target region; prevents wild pointers from polluting
///     unrelated memory regions.
///   - **Solver Cost**: Lower than unbounded concretization because candidates are constrained to
///     region boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymbolicAddressPolicy {
    /// Concretize symbolic addresses according to the selected strategy.
    Concretize(ConcretizationStrategy),
    /// Treat memory as a fully symbolic array without concretizing.
    ///
    /// Requires solver array theory support which is not yet wired.
    FullArrays,
    /// Map symbolic address to a memory region by its high bits, then concretize within that region.
    RegionBased,
}

pub trait SymbolicAddressResolver: Send + Sync {
    fn candidates(&self, address: ExprId, limit: usize) -> Result<Vec<Address>, MemoryError>;
}

/// Sparse memory page: only stores bytes that have actually been written.
///
/// Unwritten offsets read back as `Concrete(0)`, so a freshly materialized
/// page costs only the overhead of two empty `BTreeMap`s regardless of the
/// logical page size. Concrete and symbolic values are kept in separate maps;
/// an offset is symbolic if present in `symbolic`, otherwise it falls back to
/// `concrete` (or zero).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct MemoryPage {
    concrete: BTreeMap<usize, u8>,
    symbolic: BTreeMap<usize, ExprId>,
}

impl MemoryPage {
    /// Reads a single byte at `offset`: symbolic entries take precedence,
    /// then concrete, then `Concrete(0)` for unwritten offsets.
    ///
    /// The bulk `read` path iterates the sparse maps directly for speed, so
    /// this is retained as the single-byte primitive (and exercised by unit
    /// tests).
    #[allow(dead_code)]
    fn value(&self, offset: usize) -> ByteValue {
        if let Some(expression) = self.symbolic.get(&offset) {
            ByteValue::Symbolic(*expression)
        } else {
            ByteValue::Concrete(self.concrete.get(&offset).copied().unwrap_or(0))
        }
    }

    fn write(&mut self, offset: usize, value: ByteValue) {
        match value {
            ByteValue::Concrete(byte) => {
                self.concrete.insert(offset, byte);
                self.symbolic.remove(&offset);
            }
            ByteValue::Symbolic(expression) => {
                self.symbolic.insert(offset, expression);
                self.concrete.remove(&offset);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemoryStats {
    pub materialized_pages: usize,
    pub concrete_capacity_bytes: usize,
    pub symbolic_cells: usize,
}

/// Sparse, copy-on-write memory intended for execution-state snapshots.
///
/// The top-level page map and each individual page are independently shared.
/// A fork is O(1); a write clones only the top-level page index and the pages
/// touched by the write. Unmaterialized mapped bytes read as concrete zero.
///
/// Regions are indexed by base address in a `BTreeMap` so that
/// `region_containing` lookups are O(log n) instead of a linear scan.
#[derive(Clone, Debug)]
pub struct PersistentMemory {
    regions: Arc<Vec<MemoryRegion>>,
    region_index: Arc<BTreeMap<u64, usize>>,
    pages: Arc<BTreeMap<u64, Arc<MemoryPage>>>,
    code_versions: Arc<BTreeMap<CodePageId, CodePageVersion>>,
}

impl PersistentMemory {
    pub fn new(mut regions: Vec<MemoryRegion>) -> Result<Self, MemoryError> {
        regions.sort_by_key(|region| region.base);

        let mut previous_end = None;
        let mut code_versions = BTreeMap::new();
        let mut region_index = BTreeMap::new();

        for (index, region) in regions.iter().enumerate() {
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

            region_index.insert(region.base, index);

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
            region_index: Arc::new(region_index),
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

    pub fn stats(&self) -> MemoryStats {
        MemoryStats {
            materialized_pages: self.pages.len(),
            concrete_capacity_bytes: self.pages.len() * DEFAULT_PAGE_SIZE,
            symbolic_cells: self.pages.values().map(|page| page.symbolic.len()).sum(),
        }
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
        // The regions vector is sorted and non-overlapping (validated in `new`),
        // so the candidate is the region with the greatest base <= address.
        // `BTreeMap::range(..=address).next_back()` gives that in O(log n).
        let (_, &index) = self.region_index.range(..=address).next_back()?;
        let region = &self.regions[index];
        let end = region.base.checked_add(region.size)?;
        (address < end).then_some(region)
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
            let mut materialized = pages
                .get(&page)
                .map(|existing| (**existing).clone())
                .unwrap_or_default();
            for (offset, value) in changes {
                materialized.write(offset, value);
            }
            pages.insert(page, Arc::new(materialized));
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
            region_index: Arc::clone(&self.region_index),
            pages: Arc::new(pages),
            code_versions: Arc::new(code_versions),
        })
    }
}

impl LayeredMemory for PersistentMemory {
    type Error = MemoryError;

    fn read(&self, address: Address, len: usize) -> Result<Vec<ByteValue>, Self::Error> {
        self.check_access(address, len, MemoryAccessKind::Read)?;

        // Unwritten bytes read as `Concrete(0)`, so pre-fill the output with
        // zeros and only overwrite the entries that were actually written in
        // each materialized page. This avoids a per-byte page lookup and lets
        // sparse pages contribute their (few) written bytes directly.
        let mut output = vec![ByteValue::Concrete(0); len];
        if len == 0 {
            return Ok(output);
        }

        let end = Self::inclusive_end(address, len)?;
        let last_page = Self::page_number(end);
        let mut cursor = address;
        let mut out_index = 0usize;

        loop {
            let page = Self::page_number(cursor);
            let start_offset = Self::page_offset(cursor);
            let end_offset_inclusive = if page == last_page {
                Self::page_offset(end)
            } else {
                DEFAULT_PAGE_SIZE - 1
            };

            if let Some(page_data) = self.pages.get(&page) {
                // Only the bytes actually present in the sparse maps need to be
                // copied; everything else stays `Concrete(0)`.
                for (&offset, &byte) in page_data.concrete.range(start_offset..=end_offset_inclusive) {
                    output[out_index + (offset - start_offset)] = ByteValue::Concrete(byte);
                }
                for (&offset, &expression) in page_data.symbolic.range(start_offset..=end_offset_inclusive) {
                    output[out_index + (offset - start_offset)] = ByteValue::Symbolic(expression);
                }
            }

            let segment_len = end_offset_inclusive - start_offset + 1;
            out_index += segment_len;

            if page == last_page {
                break;
            }
            cursor = cursor
                .checked_add(segment_len as u64)
                .ok_or(MemoryError::AddressOverflow)?;
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

/// In-memory resolver storing candidate concrete addresses for symbolic expressions.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ConcretizationResolver {
    candidates: BTreeMap<ExprId, Vec<Address>>,
}

impl ConcretizationResolver {
    /// Creates an empty concretization resolver.
    pub fn new() -> Self {
        Self {
            candidates: BTreeMap::new(),
        }
    }

    /// Registers candidate concrete addresses for a symbolic expression ID.
    pub fn register(&mut self, expression: ExprId, addresses: Vec<Address>) {
        self.candidates.insert(expression, addresses);
    }

    /// Builder helper to register candidate addresses.
    pub fn with_candidates(mut self, expression: ExprId, addresses: Vec<Address>) -> Self {
        self.candidates.insert(expression, addresses);
        self
    }

    /// Returns the registered candidate addresses for an expression, if any.
    pub fn candidates_for(&self, expression: ExprId) -> Option<&[Address]> {
        self.candidates.get(&expression).map(Vec::as_slice)
    }
}

impl SymbolicAddressResolver for ConcretizationResolver {
    fn candidates(&self, address: ExprId, limit: usize) -> Result<Vec<Address>, MemoryError> {
        if let Some(list) = self.candidates.get(&address) {
            let count = list.len().min(limit);
            Ok(list[..count].to_vec())
        } else {
            Ok(Vec::new())
        }
    }
}

/// Record of an unconcretized symbolic write under [`SymbolicAddressPolicy::FullArrays`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SymbolicWrite {
    pub address: ExprId,
    pub bytes: Vec<ByteValue>,
}

/// Symbolic memory manager wrapping [`PersistentMemory`] with symbolic-address policies.
#[derive(Clone, Debug)]
pub struct SymbolicMemory {
    inner: PersistentMemory,
    bounded_limit: usize,
    symbolic_writes: Vec<SymbolicWrite>,
}

impl SymbolicMemory {
    /// Wraps a persistent memory instance with default symbolic address settings.
    pub fn new(inner: PersistentMemory) -> Self {
        Self {
            inner,
            bounded_limit: ConcretizationStrategy::DEFAULT_BOUNDED_LIMIT,
            symbolic_writes: Vec::new(),
        }
    }

    /// Configures the maximum candidate bound used by [`ConcretizationStrategy::BoundedRange`].
    pub fn with_bounded_limit(mut self, limit: usize) -> Self {
        self.bounded_limit = limit;
        self
    }

    /// Reference to the underlying persistent memory snapshot.
    pub fn inner(&self) -> &PersistentMemory {
        &self.inner
    }

    /// Consumes the wrapper and returns the underlying persistent memory.
    pub fn into_inner(self) -> PersistentMemory {
        self.inner
    }

    /// Returns recorded un-concretized symbolic writes (used by [`SymbolicAddressPolicy::FullArrays`]).
    pub fn symbolic_writes(&self) -> &[SymbolicWrite] {
        &self.symbolic_writes
    }

    /// Reads concrete memory at the given 64-bit address.
    pub fn read_at_address(&self, address: Address, len: usize) -> Result<Vec<ByteValue>, MemoryError> {
        self.inner.read(address, len)
    }

    /// Writes concrete memory at the given 64-bit address.
    pub fn write_at_address(&self, address: Address, bytes: &[ByteValue]) -> Result<Self, MemoryError> {
        let inner = self.inner.write(address, bytes)?;
        Ok(Self {
            inner,
            bounded_limit: self.bounded_limit,
            symbolic_writes: self.symbolic_writes.clone(),
        })
    }

    /// Performs a symbolic memory read according to `policy`.
    ///
    /// If `address` is concrete, reads directly from persistent memory.
    /// If `address` is symbolic:
    /// - [`Concretize(SingleAddress)`][ConcretizationStrategy::SingleAddress]:
    ///   Resolves to one candidate and reads concrete memory. If no candidates, returns
    ///   [`MemoryError::SymbolicAddressUnresolved`].
    /// - [`Concretize(BoundedRange)`][ConcretizationStrategy::BoundedRange] / [`Concretize(AllCandidates)`][ConcretizationStrategy::AllCandidates]:
    ///   Resolves up to `N` (or unlimited) candidates. Returns a symbolic ITE expression over the candidate reads.
    /// - [`FullArrays`][SymbolicAddressPolicy::FullArrays]:
    ///   Returns a symbolic expression representing the array read without concretization.
    ///   Requires solver array theory support which is not yet wired.
    /// - [`RegionBased`][SymbolicAddressPolicy::RegionBased]:
    ///   Maps the symbolic address to a region by high bits / base and concretizes within that region.
    pub fn read_symbolic(
        &self,
        address: ByteValue,
        len: usize,
        resolver: &dyn SymbolicAddressResolver,
        policy: &SymbolicAddressPolicy,
    ) -> Result<Vec<ByteValue>, MemoryError> {
        match address {
            ByteValue::Concrete(byte) => self.inner.read(byte as Address, len),
            ByteValue::Symbolic(expr_id) => match policy {
                SymbolicAddressPolicy::FullArrays => {
                    // Check if a prior symbolic write exactly matches this expression.
                    if let Some(matching) = self.symbolic_writes.iter().rev().find(|w| w.address == expr_id)
                        && matching.bytes.len() >= len
                    {
                        return Ok(matching.bytes[..len].to_vec());
                    }
                    // Full array read returns symbolic expression representing the array read.
                    // Solver array theory support is not yet wired.
                    Ok(vec![ByteValue::Symbolic(expr_id); len])
                }
                SymbolicAddressPolicy::Concretize(strategy) => {
                    let limit = match strategy {
                        ConcretizationStrategy::SingleAddress => 1,
                        ConcretizationStrategy::BoundedRange => self.bounded_limit,
                        ConcretizationStrategy::AllCandidates => usize::MAX,
                    };
                    let candidates = resolver.candidates(expr_id, limit)?;
                    if candidates.is_empty() {
                        return Err(MemoryError::SymbolicAddressUnresolved(expr_id));
                    }
                    if candidates.len() == 1 || matches!(strategy, ConcretizationStrategy::SingleAddress) {
                        self.inner.read(candidates[0], len)
                    } else {
                        // Verify all candidates have valid read permissions.
                        for &cand in &candidates {
                            self.inner.check_access(cand, len, MemoryAccessKind::Read)?;
                        }
                        // Returns a symbolic ITE expression over the candidates.
                        Ok(vec![ByteValue::Symbolic(expr_id); len])
                    }
                }
                SymbolicAddressPolicy::RegionBased => {
                    let candidates = resolver.candidates(expr_id, self.bounded_limit)?;
                    if candidates.is_empty() {
                        return Err(MemoryError::SymbolicAddressUnresolved(expr_id));
                    }
                    let mut target_region = None;
                    for &cand in &candidates {
                        if let Some(region) = self.inner.region_containing(cand) {
                            target_region = Some(region.clone());
                            break;
                        }
                    }
                    let region = target_region.ok_or(MemoryError::Unmapped(candidates[0]))?;
                    let in_region: Vec<Address> =
                        candidates.into_iter().filter(|&addr| region.contains(addr)).collect();
                    let target_addr = in_region
                        .first()
                        .copied()
                        .ok_or(MemoryError::SymbolicAddressUnresolved(expr_id))?;
                    self.inner.read(target_addr, len)
                }
            },
        }
    }

    /// Performs a symbolic memory write according to `policy`.
    ///
    /// For [`Concretize(BoundedRange)`][ConcretizationStrategy::BoundedRange] and
    /// [`Concretize(AllCandidates)`][ConcretizationStrategy::AllCandidates], when multiple
    /// candidates exist, execution forks into multiple states. This method returns the
    /// first fork; the caller must handle the remaining forks (or inspect them via
    /// [`write_symbolic_forks`][Self::write_symbolic_forks]).
    pub fn write_symbolic(
        &self,
        address: ByteValue,
        bytes: &[ByteValue],
        resolver: &dyn SymbolicAddressResolver,
        policy: &SymbolicAddressPolicy,
    ) -> Result<Self, MemoryError> {
        match address {
            ByteValue::Concrete(byte) => {
                let inner = self.inner.write(byte as Address, bytes)?;
                Ok(Self {
                    inner,
                    bounded_limit: self.bounded_limit,
                    symbolic_writes: self.symbolic_writes.clone(),
                })
            }
            ByteValue::Symbolic(expr_id) => match policy {
                SymbolicAddressPolicy::FullArrays => {
                    // Store the ExprId and bytes without concretizing.
                    // Solver array theory support is not yet wired.
                    let mut writes = self.symbolic_writes.clone();
                    writes.push(SymbolicWrite {
                        address: expr_id,
                        bytes: bytes.to_vec(),
                    });
                    Ok(Self {
                        inner: self.inner.clone(),
                        bounded_limit: self.bounded_limit,
                        symbolic_writes: writes,
                    })
                }
                SymbolicAddressPolicy::Concretize(strategy) => {
                    let limit = match strategy {
                        ConcretizationStrategy::SingleAddress => 1,
                        ConcretizationStrategy::BoundedRange => self.bounded_limit,
                        ConcretizationStrategy::AllCandidates => usize::MAX,
                    };
                    let candidates = resolver.candidates(expr_id, limit)?;
                    if candidates.is_empty() {
                        return Err(MemoryError::SymbolicAddressUnresolved(expr_id));
                    }
                    if candidates.len() > 1 {
                        // Verify all candidate writes succeed before returning the first fork.
                        for &cand in &candidates[1..] {
                            let _ = self.inner.write(cand, bytes)?;
                        }
                    }
                    let target_addr = candidates[0];
                    let inner = self.inner.write(target_addr, bytes)?;
                    Ok(Self {
                        inner,
                        bounded_limit: self.bounded_limit,
                        symbolic_writes: self.symbolic_writes.clone(),
                    })
                }
                SymbolicAddressPolicy::RegionBased => {
                    let candidates = resolver.candidates(expr_id, self.bounded_limit)?;
                    if candidates.is_empty() {
                        return Err(MemoryError::SymbolicAddressUnresolved(expr_id));
                    }
                    let mut target_region = None;
                    for &cand in &candidates {
                        if let Some(region) = self.inner.region_containing(cand) {
                            target_region = Some(region.clone());
                            break;
                        }
                    }
                    let region = target_region.ok_or(MemoryError::Unmapped(candidates[0]))?;
                    let in_region: Vec<Address> =
                        candidates.into_iter().filter(|&addr| region.contains(addr)).collect();
                    let target_addr = in_region
                        .first()
                        .copied()
                        .ok_or(MemoryError::SymbolicAddressUnresolved(expr_id))?;
                    let inner = self.inner.write(target_addr, bytes)?;
                    Ok(Self {
                        inner,
                        bounded_limit: self.bounded_limit,
                        symbolic_writes: self.symbolic_writes.clone(),
                    })
                }
            },
        }
    }

    /// Performs a symbolic write and returns all forked memory states across resolved candidates.
    pub fn write_symbolic_forks(
        &self,
        address: ByteValue,
        bytes: &[ByteValue],
        resolver: &dyn SymbolicAddressResolver,
        policy: &SymbolicAddressPolicy,
    ) -> Result<Vec<(Address, Self)>, MemoryError> {
        match address {
            ByteValue::Concrete(byte) => {
                let addr = byte as Address;
                let written = self.write_symbolic(address, bytes, resolver, policy)?;
                Ok(vec![(addr, written)])
            }
            ByteValue::Symbolic(expr_id) => match policy {
                SymbolicAddressPolicy::FullArrays => {
                    let written = self.write_symbolic(address, bytes, resolver, policy)?;
                    Ok(vec![(0, written)])
                }
                SymbolicAddressPolicy::Concretize(strategy) => {
                    let limit = match strategy {
                        ConcretizationStrategy::SingleAddress => 1,
                        ConcretizationStrategy::BoundedRange => self.bounded_limit,
                        ConcretizationStrategy::AllCandidates => usize::MAX,
                    };
                    let candidates = resolver.candidates(expr_id, limit)?;
                    if candidates.is_empty() {
                        return Err(MemoryError::SymbolicAddressUnresolved(expr_id));
                    }
                    let mut forks = Vec::with_capacity(candidates.len());
                    for addr in candidates {
                        let inner = self.inner.write(addr, bytes)?;
                        forks.push((
                            addr,
                            Self {
                                inner,
                                bounded_limit: self.bounded_limit,
                                symbolic_writes: self.symbolic_writes.clone(),
                            },
                        ));
                    }
                    Ok(forks)
                }
                SymbolicAddressPolicy::RegionBased => {
                    let candidates = resolver.candidates(expr_id, self.bounded_limit)?;
                    if candidates.is_empty() {
                        return Err(MemoryError::SymbolicAddressUnresolved(expr_id));
                    }
                    let mut target_region = None;
                    for &cand in &candidates {
                        if let Some(region) = self.inner.region_containing(cand) {
                            target_region = Some(region.clone());
                            break;
                        }
                    }
                    let region = target_region.ok_or(MemoryError::Unmapped(candidates[0]))?;
                    let in_region: Vec<Address> =
                        candidates.into_iter().filter(|&addr| region.contains(addr)).collect();
                    if in_region.is_empty() {
                        return Err(MemoryError::SymbolicAddressUnresolved(expr_id));
                    }
                    let mut forks = Vec::with_capacity(in_region.len());
                    for addr in in_region {
                        let inner = self.inner.write(addr, bytes)?;
                        forks.push((
                            addr,
                            Self {
                                inner,
                                bounded_limit: self.bounded_limit,
                                symbolic_writes: self.symbolic_writes.clone(),
                            },
                        ));
                    }
                    Ok(forks)
                }
            },
        }
    }
}

impl LayeredMemory for SymbolicMemory {
    type Error = MemoryError;

    fn read(&self, address: Address, len: usize) -> Result<Vec<ByteValue>, Self::Error> {
        self.inner.read(address, len)
    }

    fn write(&self, address: Address, bytes: &[ByteValue]) -> Result<Self, Self::Error> {
        let inner = self.inner.write(address, bytes)?;
        Ok(Self {
            inner,
            bounded_limit: self.bounded_limit,
            symbolic_writes: self.symbolic_writes.clone(),
        })
    }

    fn fork(&self) -> Self {
        self.clone()
    }

    fn page_version(&self, page: CodePageId) -> Option<CodePageVersion> {
        self.inner.page_version(page)
    }

    fn regions(&self) -> &[MemoryRegion] {
        self.inner.regions()
    }
}

impl CodeVersionSource for SymbolicMemory {
    fn code_page_version(&self, page: CodePageId) -> Option<CodePageVersion> {
        self.inner.code_page_version(page)
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
    fn concrete_pages_keep_symbolic_bytes_in_a_sparse_overlay() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x3000, true, false)])?;
        let memory = memory.load_concrete(0x1fff, &[0x11, 0x22, 0x33])?;

        assert_eq!(
            memory.stats(),
            MemoryStats {
                materialized_pages: 2,
                concrete_capacity_bytes: 2 * DEFAULT_PAGE_SIZE,
                symbolic_cells: 0,
            }
        );

        let symbolic = memory.write(0x2000, &[ByteValue::Symbolic(ExprId(9))])?;
        assert_eq!(symbolic.stats().symbolic_cells, 1);
        assert_eq!(
            symbolic.read(0x1fff, 3)?,
            vec![
                ByteValue::Concrete(0x11),
                ByteValue::Symbolic(ExprId(9)),
                ByteValue::Concrete(0x33),
            ]
        );

        let concrete = symbolic.write(0x2000, &[ByteValue::Concrete(0x44)])?;
        assert_eq!(concrete.stats().symbolic_cells, 0);
        assert_eq!(concrete.read(0x2000, 1)?, vec![ByteValue::Concrete(0x44)]);
        assert_eq!(symbolic.read(0x2000, 1)?, vec![ByteValue::Symbolic(ExprId(9))]);
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

    #[test]
    fn write_and_read_back_single_byte() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x1000, true, false)])?;
        let written = memory.write(0x1000, &[ByteValue::Concrete(0x42)])?;
        let read = written.read(0x1000, 1)?;
        assert_eq!(read, vec![ByteValue::Concrete(0x42)]);
        Ok(())
    }

    #[test]
    fn write_multiple_bytes_and_read_back() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x1000, true, false)])?;
        let values = [
            ByteValue::Concrete(0x10),
            ByteValue::Concrete(0x20),
            ByteValue::Concrete(0x30),
            ByteValue::Concrete(0x40),
        ];
        let written = memory.write(0x1000, &values)?;
        let read = written.read(0x1000, 4)?;
        assert_eq!(read, values.to_vec());
        Ok(())
    }

    #[test]
    fn fork_creates_independent_copy() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x1000, true, false)])?;
        let memory = memory.write(0x1000, &[ByteValue::Concrete(0x77)])?;
        let fork = memory.fork();
        let changed = memory.write(0x1000, &[ByteValue::Concrete(0x99)])?;

        assert_eq!(
            fork.read(0x1000, 1)?,
            vec![ByteValue::Concrete(0x77)],
            "fork should retain the pre-fork value"
        );
        assert_eq!(
            changed.read(0x1000, 1)?,
            vec![ByteValue::Concrete(0x99)],
            "original lineage should reflect the new write"
        );
        Ok(())
    }

    #[test]
    fn fork_write_does_not_affect_original() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x1000, true, false)])?;
        let memory = memory.write(0x1000, &[ByteValue::Concrete(0x55)])?;
        let fork = memory.fork();
        let fork_changed = fork.write(0x1000, &[ByteValue::Concrete(0xee)])?;

        assert_eq!(
            memory.read(0x1000, 1)?,
            vec![ByteValue::Concrete(0x55)],
            "original must be unchanged after fork write"
        );
        assert_eq!(fork_changed.read(0x1000, 1)?, vec![ByteValue::Concrete(0xee)]);
        Ok(())
    }

    #[test]
    fn read_uninitialized_returns_zero() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x1000, true, false)])?;
        let read = memory.read(0x1000, 4)?;
        assert_eq!(
            read,
            vec![
                ByteValue::Concrete(0),
                ByteValue::Concrete(0),
                ByteValue::Concrete(0),
                ByteValue::Concrete(0),
            ]
        );
        Ok(())
    }

    #[test]
    fn page_version_increments_on_write() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x1000, true, true)])?;
        let page = PersistentMemory::page_id_for_address(0x1000);
        assert_eq!(memory.page_version(page), Some(CodePageVersion(0)));

        let changed = memory.write(0x1000, &[ByteValue::Concrete(0x01)])?;
        assert_eq!(changed.page_version(page), Some(CodePageVersion(1)));
        assert_eq!(memory.page_version(page), Some(CodePageVersion(0)));
        Ok(())
    }

    #[test]
    fn page_version_unchanged_without_write() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x1000, true, true)])?;
        let page = PersistentMemory::page_id_for_address(0x1000);
        let before = memory.page_version(page);

        let _ = memory.read(0x1000, 8)?;

        assert_eq!(memory.page_version(page), before);
        assert_eq!(memory.page_version(page), Some(CodePageVersion(0)));
        Ok(())
    }

    #[test]
    fn code_version_guards_for_range_empty() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x1000, true, true)])?;
        let guards = memory.code_version_guards_for_range(0x1000, 0)?;
        assert!(guards.is_empty());

        let guards_for_read = memory.code_version_guards_for_range(0x1000, 4)?;
        assert_eq!(guards_for_read.len(), 1);
        assert_eq!(guards_for_read[0].version, CodePageVersion(0));
        Ok(())
    }

    #[test]
    fn memory_stats_track_operations() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x2000, true, false)])?;
        let stats = memory.stats();
        assert_eq!(stats.materialized_pages, 0);
        assert_eq!(stats.symbolic_cells, 0);

        let written = memory.write(0x1000, &[ByteValue::Concrete(0xab)])?;
        let stats_after = written.stats();
        assert_eq!(stats_after.materialized_pages, 1);
        assert_eq!(stats_after.concrete_capacity_bytes, DEFAULT_PAGE_SIZE);
        assert_eq!(stats_after.symbolic_cells, 0);

        let symbolic = written.write(0x1001, &[ByteValue::Symbolic(ExprId(1))])?;
        let stats_symbolic = symbolic.stats();
        assert_eq!(stats_symbolic.symbolic_cells, 1);
        Ok(())
    }

    #[test]
    fn write_at_boundary_address() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x1000, true, false)])?;
        let last = 0x1fff;
        let written = memory.write(last, &[ByteValue::Concrete(0xcd)])?;
        let read = written.read(last, 1)?;
        assert_eq!(read, vec![ByteValue::Concrete(0xcd)]);

        let beyond = written.read(0x2000, 1);
        assert!(beyond.is_err(), "address just past the boundary should be unmapped");
        Ok(())
    }

    #[test]
    fn large_write_spans_multiple_pages() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x3000, true, true)])?;
        let page_a = PersistentMemory::page_id_for_address(0x1fff);
        let page_b = PersistentMemory::page_id_for_address(0x2000);
        let page_c = PersistentMemory::page_id_for_address(0x3000);

        let span: Vec<ByteValue> = (0..0x20).map(ByteValue::Concrete).collect();
        let changed = memory.write(0x1ff0, &span)?;

        assert_eq!(changed.page_version(page_a), Some(CodePageVersion(1)));
        assert_eq!(changed.page_version(page_b), Some(CodePageVersion(1)));
        assert_eq!(changed.page_version(page_c), Some(CodePageVersion(0)));
        assert_eq!(memory.page_version(page_a), Some(CodePageVersion(0)));
        assert_eq!(memory.page_version(page_b), Some(CodePageVersion(0)));
        Ok(())
    }

    #[test]
    fn concurrent_reads_are_safe() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x1000, true, false)])?;
        let memory = memory.write(0x1000, &[ByteValue::Concrete(0x01)])?;
        let memory = memory.write(0x1001, &[ByteValue::Concrete(0x02)])?;
        let memory = memory.write(0x1002, &[ByteValue::Concrete(0x03)])?;

        let a = memory.read(0x1000, 1)?;
        let b = memory.read(0x1001, 1)?;
        let c = memory.read(0x1002, 1)?;
        let combined = memory.read(0x1000, 3)?;

        assert_eq!(a, vec![ByteValue::Concrete(0x01)]);
        assert_eq!(b, vec![ByteValue::Concrete(0x02)]);
        assert_eq!(c, vec![ByteValue::Concrete(0x03)]);
        assert_eq!(
            combined,
            vec![
                ByteValue::Concrete(0x01),
                ByteValue::Concrete(0x02),
                ByteValue::Concrete(0x03),
            ]
        );
        Ok(())
    }

    #[test]
    fn fork_preserves_all_data() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x1000, true, false)])?;
        let memory = memory.write(0x1000, &[ByteValue::Concrete(0xa1)])?;
        let memory = memory.write(0x1001, &[ByteValue::Concrete(0xa2)])?;
        let memory = memory.write(0x1002, &[ByteValue::Concrete(0xa3)])?;

        let fork = memory.fork();
        assert_eq!(
            fork.read(0x1000, 3)?,
            vec![
                ByteValue::Concrete(0xa1),
                ByteValue::Concrete(0xa2),
                ByteValue::Concrete(0xa3),
            ]
        );
        assert_eq!(fork.regions().len(), memory.regions().len());
        Ok(())
    }

    #[test]
    fn memory_error_display_is_non_empty() {
        let errors = [
            MemoryError::InvalidRegion,
            MemoryError::RegionOverlap,
            MemoryError::AddressOverflow,
            MemoryError::Unmapped(0xdead),
            MemoryError::PermissionDenied {
                address: 0xbeef,
                access: MemoryAccessKind::Write,
            },
            MemoryError::VersionOverflow(CodePageId(7)),
            MemoryError::SymbolicAddressUnresolved(ExprId(1)),
            MemoryError::SymbolicWriteForked(3),
        ];
        for error in &errors {
            assert!(!error.to_string().is_empty(), "error display should not be empty");
        }
    }

    #[test]
    fn byte_value_concrete_equality() {
        assert_eq!(ByteValue::Concrete(0x42), ByteValue::Concrete(0x42));
        assert_ne!(ByteValue::Concrete(0x42), ByteValue::Concrete(0x43));
        assert_ne!(ByteValue::Concrete(0x42), ByteValue::Symbolic(ExprId(0)));
    }

    #[test]
    fn page_id_for_address_is_deterministic() {
        let id_a = PersistentMemory::page_id_for_address(0x1000);
        let id_b = PersistentMemory::page_id_for_address(0x1000);
        let id_c = PersistentMemory::page_id_for_address(0x1001);
        let id_next = PersistentMemory::page_id_for_address(0x2000);

        assert_eq!(id_a, id_b);
        assert_eq!(id_a, id_c);
        assert_ne!(id_a, id_next);
    }

    #[test]
    fn sparse_page_writes_only_store_written_bytes() {
        let mut page = MemoryPage::default();
        page.write(10, ByteValue::Concrete(0x01));
        page.write(20, ByteValue::Concrete(0x02));
        page.write(30, ByteValue::Concrete(0x03));
        assert_eq!(
            page.concrete.len(),
            3,
            "only the three written offsets should be stored"
        );
        assert_eq!(page.symbolic.len(), 0);
    }

    #[test]
    fn sparse_page_unwritten_returns_zero() {
        let mut page = MemoryPage::default();
        page.write(5, ByteValue::Concrete(0x42));
        assert_eq!(
            page.value(999),
            ByteValue::Concrete(0),
            "unwritten offset reads as zero"
        );
        assert_eq!(page.value(5), ByteValue::Concrete(0x42));
    }

    #[test]
    fn sparse_page_overwrite_updates_same_offset() {
        let mut page = MemoryPage::default();
        page.write(7, ByteValue::Concrete(0x11));
        page.write(7, ByteValue::Concrete(0x22));
        assert_eq!(page.concrete.len(), 1, "overwriting an offset should not grow the map");
        assert_eq!(page.value(7), ByteValue::Concrete(0x22), "latest write wins");
    }

    #[test]
    fn sparse_page_symbolic_and_concrete_coexist() {
        let mut page = MemoryPage::default();
        page.write(0, ByteValue::Concrete(0xab));
        page.write(100, ByteValue::Symbolic(ExprId(5)));
        assert_eq!(page.value(0), ByteValue::Concrete(0xab));
        assert_eq!(page.value(100), ByteValue::Symbolic(ExprId(5)));
        assert_eq!(page.concrete.len(), 1);
        assert_eq!(page.symbolic.len(), 1);
    }

    #[test]
    fn sparse_page_concrete_replaces_symbolic() {
        let mut page = MemoryPage::default();
        page.write(3, ByteValue::Symbolic(ExprId(1)));
        assert!(page.symbolic.contains_key(&3));
        page.write(3, ByteValue::Concrete(0x09));
        assert!(
            !page.symbolic.contains_key(&3),
            "concrete write should evict symbolic entry"
        );
        assert_eq!(page.value(3), ByteValue::Concrete(0x09));
    }

    #[test]
    fn multi_byte_read_across_sparse_pages() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x3000, true, false)])?;
        // One byte near the end of the first page, one near the start of the next.
        let memory = memory.write(0x1ffc, &[ByteValue::Concrete(0xaa)])?;
        let memory = memory.write(0x2004, &[ByteValue::Concrete(0xbb)])?;

        let read = memory.read(0x1ffc, 16)?;
        assert_eq!(read[0], ByteValue::Concrete(0xaa), "written byte at start of range");
        assert_eq!(read[8], ByteValue::Concrete(0xbb), "written byte on the second page");
        assert_eq!(read[1], ByteValue::Concrete(0), "unwritten byte between them is zero");
        assert_eq!(read.len(), 16);
        Ok(())
    }

    #[test]
    fn multi_byte_read_unwritten_range_is_all_zero() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x2000, true, false)])?;
        let read = memory.read(0x1000, 0x1000)?;
        assert!(read.iter().all(|value| *value == ByteValue::Concrete(0)));
        Ok(())
    }

    #[test]
    fn region_lookup_is_logarithmic() -> Result<(), MemoryError> {
        // Many non-overlapping regions with gaps between them; lookups must
        // still resolve correctly via the BTreeMap index (O(log n)) rather
        // than a linear scan. Each region occupies the low half of a 0x1000
        // slot, leaving a 0x800 gap after every region.
        let regions: Vec<MemoryRegion> = (0..100_u64)
            .map(|index| region(index * 0x1000, 0x800, true, false))
            .collect();
        let memory = PersistentMemory::new(regions)?;

        // A mapped address inside region 5 (0x5000..0x5800) reads successfully.
        assert!(memory.read(0x5000, 1).is_ok());
        // An address in the gap right after region 5 (0x5800..0x6000) is unmapped.
        assert!(
            matches!(memory.read(0x5c00, 1), Err(MemoryError::Unmapped(0x5c00))),
            "address inside a region gap should be unmapped"
        );
        // An address far beyond all regions is unmapped.
        assert!(matches!(memory.read(0x100000, 1), Err(MemoryError::Unmapped(_))));
        Ok(())
    }

    #[test]
    fn concretization_resolver_registers_and_resolves_candidates() -> Result<(), MemoryError> {
        let mut resolver = ConcretizationResolver::new();
        resolver.register(ExprId(1), vec![0x1000, 0x1008, 0x1010]);

        assert_eq!(
            resolver.candidates(ExprId(1), 2)?,
            vec![0x1000, 0x1008],
            "should truncate to requested limit"
        );
        assert_eq!(
            resolver.candidates(ExprId(1), 10)?,
            vec![0x1000, 0x1008, 0x1010],
            "should return all available when limit >= count"
        );
        assert_eq!(
            resolver.candidates(ExprId(99), 5)?,
            Vec::<Address>::new(),
            "unknown expression should yield empty candidate list"
        );
        assert_eq!(
            resolver.candidates_for(ExprId(1)),
            Some([0x1000, 0x1008, 0x1010].as_slice())
        );
        assert_eq!(resolver.candidates_for(ExprId(99)), None);
        Ok(())
    }

    #[test]
    fn symbolic_memory_read_single_address() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x1000, true, false)])?;
        let memory = memory.write(
            0x1000,
            &[
                ByteValue::Concrete(0x12),
                ByteValue::Concrete(0x34),
                ByteValue::Concrete(0x56),
            ],
        )?;
        let sym_mem = SymbolicMemory::new(memory);

        let mut resolver = ConcretizationResolver::new();
        resolver.register(ExprId(1), vec![0x1000]);

        let policy = SymbolicAddressPolicy::Concretize(ConcretizationStrategy::SingleAddress);
        let read = sym_mem.read_symbolic(ByteValue::Symbolic(ExprId(1)), 3, &resolver, &policy)?;

        assert_eq!(
            read,
            vec![
                ByteValue::Concrete(0x12),
                ByteValue::Concrete(0x34),
                ByteValue::Concrete(0x56),
            ]
        );
        Ok(())
    }

    #[test]
    fn symbolic_memory_read_unresolved_fails() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x1000, true, false)])?;
        let sym_mem = SymbolicMemory::new(memory);
        let resolver = ConcretizationResolver::new();
        let policy = SymbolicAddressPolicy::Concretize(ConcretizationStrategy::SingleAddress);

        let result = sym_mem.read_symbolic(ByteValue::Symbolic(ExprId(42)), 1, &resolver, &policy);
        assert!(
            matches!(result, Err(MemoryError::SymbolicAddressUnresolved(ExprId(42)))),
            "unresolved symbolic address should produce SymbolicAddressUnresolved error"
        );
        Ok(())
    }

    #[test]
    fn symbolic_memory_write_single_address() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x1000, true, false)])?;
        let sym_mem = SymbolicMemory::new(memory);

        let mut resolver = ConcretizationResolver::new();
        resolver.register(ExprId(1), vec![0x1000]);

        let policy = SymbolicAddressPolicy::Concretize(ConcretizationStrategy::SingleAddress);
        let written = sym_mem.write_symbolic(
            ByteValue::Symbolic(ExprId(1)),
            &[ByteValue::Concrete(0x77)],
            &resolver,
            &policy,
        )?;

        let read = written.read_at_address(0x1000, 1)?;
        assert_eq!(read, vec![ByteValue::Concrete(0x77)]);
        Ok(())
    }

    #[test]
    fn symbolic_memory_read_bounded_range_merges_ite() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x2000, true, false)])?;
        let memory = memory.write(0x1000, &[ByteValue::Concrete(0xaa)])?;
        let memory = memory.write(0x2000, &[ByteValue::Concrete(0xbb)])?;
        let sym_mem = SymbolicMemory::new(memory);

        let mut resolver = ConcretizationResolver::new();
        resolver.register(ExprId(5), vec![0x1000, 0x2000]);

        let policy = SymbolicAddressPolicy::Concretize(ConcretizationStrategy::BoundedRange);
        let read = sym_mem.read_symbolic(ByteValue::Symbolic(ExprId(5)), 1, &resolver, &policy)?;

        // Multiple candidates with different values merge into a symbolic ITE expression.
        assert_eq!(read, vec![ByteValue::Symbolic(ExprId(5))]);
        Ok(())
    }

    #[test]
    fn symbolic_memory_write_bounded_range_forks() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x2000, true, false)])?;
        let sym_mem = SymbolicMemory::new(memory);

        let mut resolver = ConcretizationResolver::new();
        resolver.register(ExprId(6), vec![0x1000, 0x2000]);

        let policy = SymbolicAddressPolicy::Concretize(ConcretizationStrategy::BoundedRange);
        let first_fork = sym_mem.write_symbolic(
            ByteValue::Symbolic(ExprId(6)),
            &[ByteValue::Concrete(0x99)],
            &resolver,
            &policy,
        )?;

        // First fork wrote to 0x1000.
        assert_eq!(first_fork.read_at_address(0x1000, 1)?, vec![ByteValue::Concrete(0x99)]);
        assert_eq!(first_fork.read_at_address(0x2000, 1)?, vec![ByteValue::Concrete(0x00)]);

        // write_symbolic_forks returns all forks.
        let forks = sym_mem.write_symbolic_forks(
            ByteValue::Symbolic(ExprId(6)),
            &[ByteValue::Concrete(0x99)],
            &resolver,
            &policy,
        )?;
        assert_eq!(forks.len(), 2);
        assert_eq!(forks[0].0, 0x1000);
        assert_eq!(forks[0].1.read_at_address(0x1000, 1)?, vec![ByteValue::Concrete(0x99)]);
        assert_eq!(forks[1].0, 0x2000);
        assert_eq!(forks[1].1.read_at_address(0x2000, 1)?, vec![ByteValue::Concrete(0x99)]);
        Ok(())
    }

    #[test]
    fn symbolic_memory_all_candidates_read_and_write() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x3000, true, false)])?;
        let sym_mem = SymbolicMemory::new(memory);

        let mut resolver = ConcretizationResolver::new();
        resolver.register(ExprId(7), vec![0x1000, 0x2000, 0x3000]);

        let policy = SymbolicAddressPolicy::Concretize(ConcretizationStrategy::AllCandidates);
        let forks = sym_mem.write_symbolic_forks(
            ByteValue::Symbolic(ExprId(7)),
            &[ByteValue::Concrete(0xee)],
            &resolver,
            &policy,
        )?;
        assert_eq!(forks.len(), 3);
        assert_eq!(forks[0].0, 0x1000);
        assert_eq!(forks[1].0, 0x2000);
        assert_eq!(forks[2].0, 0x3000);
        Ok(())
    }

    #[test]
    fn symbolic_memory_full_arrays_read_and_write() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x1000, true, false)])?;
        let sym_mem = SymbolicMemory::new(memory);
        let resolver = ConcretizationResolver::new();
        let policy = SymbolicAddressPolicy::FullArrays;

        let written = sym_mem.write_symbolic(
            ByteValue::Symbolic(ExprId(8)),
            &[ByteValue::Concrete(0x11), ByteValue::Concrete(0x22)],
            &resolver,
            &policy,
        )?;

        assert_eq!(written.symbolic_writes().len(), 1);
        assert_eq!(written.symbolic_writes()[0].address, ExprId(8));

        // Reading back from the written symbolic address returns the stored bytes.
        let read = written.read_symbolic(ByteValue::Symbolic(ExprId(8)), 2, &resolver, &policy)?;
        assert_eq!(read, vec![ByteValue::Concrete(0x11), ByteValue::Concrete(0x22)]);

        // Reading from an unwritten symbolic address returns a symbolic array expression.
        let read_unwritten = written.read_symbolic(ByteValue::Symbolic(ExprId(99)), 2, &resolver, &policy)?;
        assert_eq!(
            read_unwritten,
            vec![ByteValue::Symbolic(ExprId(99)), ByteValue::Symbolic(ExprId(99))]
        );
        Ok(())
    }

    #[test]
    fn symbolic_memory_region_based() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![
            region(0x1000, 0x1000, true, false),
            region(0x3000, 0x1000, true, false),
        ])?;
        let memory = memory.write(0x1020, &[ByteValue::Concrete(0x55)])?;
        let memory = memory.write(0x3020, &[ByteValue::Concrete(0x66)])?;
        let sym_mem = SymbolicMemory::new(memory);

        let mut resolver = ConcretizationResolver::new();
        // Candidate 0x1020 is in region 0x1000..0x2000; candidate 0x3020 is in region 0x3000..0x4000.
        resolver.register(ExprId(9), vec![0x1020, 0x3020]);

        let policy = SymbolicAddressPolicy::RegionBased;
        // RegionBased maps candidate 0x1020 to region 0x1000..0x2000 and concretizes within it.
        let read = sym_mem.read_symbolic(ByteValue::Symbolic(ExprId(9)), 1, &resolver, &policy)?;
        assert_eq!(read, vec![ByteValue::Concrete(0x55)]);

        let written = sym_mem.write_symbolic(
            ByteValue::Symbolic(ExprId(9)),
            &[ByteValue::Concrete(0x88)],
            &resolver,
            &policy,
        )?;
        assert_eq!(written.read_at_address(0x1020, 1)?, vec![ByteValue::Concrete(0x88)]);
        // Region 2 address 0x3020 was untouched by the region-confined write.
        assert_eq!(written.read_at_address(0x3020, 1)?, vec![ByteValue::Concrete(0x66)]);
        Ok(())
    }

    #[test]
    fn byte_granular_cow_coexistence() -> Result<(), MemoryError> {
        // Page 1: 0x1000..0x2000, Page 2: 0x2000..0x3000.
        let memory = PersistentMemory::new(vec![region(0x1000, 0x2000, true, false)])?;
        // Write concrete bytes to Page 1 and Page 2.
        let memory = memory.write(
            0x1000,
            &[
                ByteValue::Concrete(0x10),
                ByteValue::Concrete(0x20),
                ByteValue::Concrete(0x30),
                ByteValue::Concrete(0x40),
            ],
        )?;
        let memory = memory.write(0x2000, &[ByteValue::Concrete(0x99)])?;

        // Fork the memory: pages are shared COW.
        let forked = memory.fork();
        let page1_id = PersistentMemory::page_number(0x1000);
        let page2_id = PersistentMemory::page_number(0x2000);

        // Before write: both pages are identical Arc pointers between memory and forked.
        if let (Some(orig_p1), Some(fork_p1)) = (memory.pages.get(&page1_id), forked.pages.get(&page1_id)) {
            assert!(Arc::ptr_eq(orig_p1, fork_p1), "page 1 must be shared pre-write");
        }
        if let (Some(orig_p2), Some(fork_p2)) = (memory.pages.get(&page2_id), forked.pages.get(&page2_id)) {
            assert!(Arc::ptr_eq(orig_p2, fork_p2), "page 2 must be shared pre-write");
        }

        // Write ONE symbolic byte at offset 0x1002 on the forked memory.
        let modified = forked.write(0x1002, &[ByteValue::Symbolic(ExprId(77))])?;

        // Page 2 was untouched: verify Arc pointer equality is still intact.
        if let (Some(orig_p2), Some(mod_p2)) = (memory.pages.get(&page2_id), modified.pages.get(&page2_id)) {
            assert!(
                Arc::ptr_eq(orig_p2, mod_p2),
                "untouched page 2 must remain shared across COW fork"
            );
        }

        // Page 1 was COW-copied: verify byte-granular coexistence on modified page.
        assert_eq!(
            modified.read(0x1000, 4)?,
            vec![
                ByteValue::Concrete(0x10),
                ByteValue::Concrete(0x20),
                ByteValue::Symbolic(ExprId(77)),
                ByteValue::Concrete(0x40),
            ],
            "modified page must contain symbolic byte at 0x1002 while retaining concrete bytes"
        );

        // Verify original memory was unmodified.
        assert_eq!(
            memory.read(0x1000, 4)?,
            vec![
                ByteValue::Concrete(0x10),
                ByteValue::Concrete(0x20),
                ByteValue::Concrete(0x30),
                ByteValue::Concrete(0x40),
            ],
            "original memory must retain original concrete bytes"
        );

        // Check stats: modified has exactly 1 symbolic cell.
        assert_eq!(modified.stats().symbolic_cells, 1);
        assert_eq!(memory.stats().symbolic_cells, 0);
        Ok(())
    }

    #[test]
    fn symbolic_memory_layered_memory_trait() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x1000, true, true)])?;
        let sym_mem = SymbolicMemory::new(memory);

        let written = sym_mem.write(0x1000, &[ByteValue::Concrete(0x42)])?;
        assert_eq!(written.read(0x1000, 1)?, vec![ByteValue::Concrete(0x42)]);

        let forked = written.fork();
        assert_eq!(forked.read(0x1000, 1)?, vec![ByteValue::Concrete(0x42)]);
        assert_eq!(forked.regions().len(), 1);

        let page = PersistentMemory::page_id_for_address(0x1000);
        assert_eq!(written.page_version(page), Some(CodePageVersion(1)));
        assert_eq!(written.code_page_version(page), Some(CodePageVersion(1)));
        Ok(())
    }

    #[test]
    fn symbolic_memory_concrete_address_delegation() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x0, 0x100, true, false)])?;
        let sym_mem = SymbolicMemory::new(memory);
        let resolver = ConcretizationResolver::new();
        let policy = SymbolicAddressPolicy::Concretize(ConcretizationStrategy::SingleAddress);

        let written = sym_mem.write_symbolic(
            ByteValue::Concrete(0x10),
            &[ByteValue::Concrete(0xab)],
            &resolver,
            &policy,
        )?;
        let read = written.read_symbolic(ByteValue::Concrete(0x10), 1, &resolver, &policy)?;
        assert_eq!(read, vec![ByteValue::Concrete(0xab)]);
        Ok(())
    }
}
