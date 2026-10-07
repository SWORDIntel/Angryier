#![forbid(unsafe_code)]

use angryier_core::CodeVersionSource;
use angryier_types::{Address, CodePageId, CodePageVersion, CodeVersionGuard, ExprId, ObjectId};
use std::{collections::BTreeMap, sync::Arc};

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
    /// Allocation-free read: fills `out` (whose length is the read length)
    /// instead of returning a fresh `Vec`. The default wraps [`read`](Self::read);
    /// concrete implementations override it with a buffer-filling path.
    fn read_into(&self, address: Address, out: &mut [ByteValue]) -> Result<(), Self::Error> {
        let bytes = self.read(address, out.len())?;
        out.clone_from_slice(&bytes);
        Ok(())
    }
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

/// Site cap for the under-constrained memory debt log — mirrors
/// `SYMBOLIC_DEBT_SITE_CAP` in the execution crate: first-seen sites are
/// kept, the total keeps counting, and a pathological image cannot grow the
/// log unbounded.
pub const UC_MEMORY_DEBT_SITE_CAP: usize = 128;

/// Hard ceiling on zero-backed pages the under-constrained memory policy may
/// fabricate per run (64 MiB of address space). Beyond it the policy fails
/// closed — the access errors exactly as it would with the flag off — so a
/// wild pointer sweep cannot grow the map without bound. Debt is still
/// recorded for capped-out hits.
pub const UC_MEMORY_MAX_FABRICATED_PAGES: usize = 1 << 14;

/// Hard ceiling on previous-byte revert records the read-only-write
/// relaxation keeps in the ledger. Each relaxed write to a mapped read-only
/// page records the bytes it overwrote so the relaxation stays inspectable
/// (and revertable in principle); a pathological image cannot grow the log
/// without bound. The relaxed-write and site counters keep counting past the
/// cap — only the revert log is truncated.
pub const UC_MEMORY_RO_REVERT_CAP: usize = 4096;

/// Which operation the under-constrained policy relaxed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum UcMemoryOp {
    Read,
    Write,
    /// A write into a mapped but read-only page whose current bytes are all
    /// concrete image data (`uc_write_ro`, opt-in on top of `uc_memory`).
    /// Executable pages are never relaxed.
    WriteRO,
}

impl UcMemoryOp {
    /// Stable lowercase name for reports and script surfaces.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::WriteRO => "write_ro",
        }
    }
}

/// One unmapped-access site the under-constrained memory policy papered
/// over. Deduplicated per (operation, page): `address` is the first
/// under-constrained address seen inside `page`, so a garbage-pointer sweep
/// across one page produces a single site while `total` keeps counting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UcMemoryDebtSite {
    pub op: UcMemoryOp,
    /// First unmapped address observed for this site.
    pub address: Address,
    /// Base address of the page containing it (the dedup key).
    pub page: Address,
}

/// One previous byte overwritten by a read-only-write relaxation
/// (`uc_write_ro`): the address and the concrete byte the page held before
/// the store. First-come, capped at [`UC_MEMORY_RO_REVERT_CAP`] entries —
/// the relaxation stays inspectable (and revertable in principle) without
/// letting a pathological image grow the log unbounded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoWriteRevert {
    pub address: Address,
    /// The byte the page held immediately before the relaxed store.
    pub previous: u8,
}

/// Shared, append-only ledger for the under-constrained memory policy.
///
/// Lives behind an `Arc<Mutex<..>>` inside every clone/fork of an armed
/// [`PersistentMemory`], so all states of a run aggregate into one log —
/// the run result reports run-wide debt, not per-state debt. Also owns the
/// set of fabricated zero-backed pages: page *numbers* treated as mapped
/// zero-filled RAM by the access checks without touching the region table
/// (loader-visible mappings, IAT checks and `regions()` stay exact).
#[derive(Debug, Default)]
pub struct UcMemoryLedger {
    total: u64,
    sites: Vec<UcMemoryDebtSite>,
    fabricated_pages: std::collections::BTreeSet<u64>,
    /// Relaxed writes into mapped read-only pages (`uc_write_ro`), uncapped
    /// — also counted in `total` with [`UcMemoryOp::WriteRO`] sites.
    ro_write_total: u64,
    /// Previous bytes overwritten by relaxed read-only writes, first-come,
    /// capped at [`UC_MEMORY_RO_REVERT_CAP`].
    ro_reverts: Vec<RoWriteRevert>,
}

impl UcMemoryLedger {
    /// Total number of accesses resolved through the policy (uncapped).
    pub fn total(&self) -> u64 {
        self.total
    }

    /// First-seen sites, capped at [`UC_MEMORY_DEBT_SITE_CAP`].
    pub fn sites(&self) -> &[UcMemoryDebtSite] {
        &self.sites
    }

    /// Number of zero-backed pages fabricated so far.
    pub fn fabricated_pages(&self) -> usize {
        self.fabricated_pages.len()
    }

    /// Relaxed writes into mapped read-only pages (uncapped; also included
    /// in [`Self::total`]).
    pub fn ro_write_total(&self) -> u64 {
        self.ro_write_total
    }

    /// Previous bytes overwritten by relaxed read-only writes (capped at
    /// [`UC_MEMORY_RO_REVERT_CAP`]).
    pub fn ro_reverts(&self) -> &[RoWriteRevert] {
        &self.ro_reverts
    }

    /// Records one relaxed access and a deduplicated debt site for the page
    /// it hit. `total` counts every relaxed access, not just new sites; the
    /// site key is (operation, page) — the first address seen on the page is
    /// kept.
    fn record_hit(&mut self, op: UcMemoryOp, first_address: Address, first_page: Address) {
        self.total = self.total.saturating_add(1);
        if self.sites.len() < UC_MEMORY_DEBT_SITE_CAP
            && !self
                .sites
                .iter()
                .any(|existing| existing.op == op && existing.page == first_page)
        {
            self.sites.push(UcMemoryDebtSite {
                op,
                address: first_address,
                page: first_page,
            });
        }
    }

    /// Records one relaxed read-only write: the hit (`WriteRO` site), the
    /// `ro_write_total` counter, and the previous bytes it overwrote
    /// (first-come, capped at [`UC_MEMORY_RO_REVERT_CAP`]).
    fn record_ro_write(&mut self, first_address: Address, first_page: Address, reverts: &[RoWriteRevert]) {
        self.record_hit(UcMemoryOp::WriteRO, first_address, first_page);
        self.ro_write_total = self.ro_write_total.saturating_add(1);
        if self.ro_reverts.len() < UC_MEMORY_RO_REVERT_CAP {
            let room = UC_MEMORY_RO_REVERT_CAP - self.ro_reverts.len();
            self.ro_reverts.extend_from_slice(&reverts[..room.min(reverts.len())]);
        }
    }
}

/// Size of one concrete-data line inside a [`MemoryPage`].
const PAGE_LINE_BYTES: usize = 64;

/// Invariants: offsets are `< DEFAULT_PAGE_SIZE` (4096), so a page holds
/// exactly 64 lines and `lines.len() <= 64`.
type PageLine = [u8; PAGE_LINE_BYTES];

/// Sparse, copy-on-write memory page.
///
/// Unwritten offsets read back as `Concrete(0)`, so a freshly materialized
/// page costs only the overhead of an empty line table and an empty symbolic
/// map regardless of the logical page size. Concrete data is stored in
/// 64-byte lines shared through `Arc`: copying a page copies the line table
/// (64 pointers) and shares every untouched line, while a store clones only
/// the one line it modifies. Symbolic values stay per-byte in a sparse map —
/// one symbolic byte must never materialize concrete data — and take
/// precedence over the concrete line on reads.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct MemoryPage {
    lines: Vec<Option<Arc<PageLine>>>,
    symbolic: BTreeMap<usize, ExprId>,
}

impl MemoryPage {
    /// Reads a single byte at `offset`: symbolic entries take precedence,
    /// then the concrete line byte, then `Concrete(0)` for unwritten offsets.
    ///
    /// The bulk `read` path copies whole line slices for speed, so this is
    /// the single-byte primitive (used by the read-only-write relaxation's
    /// revert records and exercised by unit tests).
    fn value(&self, offset: usize) -> ByteValue {
        if let Some(expression) = self.symbolic.get(&offset) {
            ByteValue::Symbolic(*expression)
        } else {
            let byte = self
                .lines
                .get(offset / PAGE_LINE_BYTES)
                .and_then(|line| line.as_ref())
                .map_or(0, |line| line[offset % PAGE_LINE_BYTES]);
            ByteValue::Concrete(byte)
        }
    }

    fn write(&mut self, offset: usize, value: ByteValue) {
        match value {
            ByteValue::Concrete(_) => self.write_values(offset, &[value]),
            ByteValue::Symbolic(expression) => {
                self.symbolic.insert(offset, expression);
                // A symbolic write must not leave stale concrete bytes where
                // the symbolic cell now lives.
                self.clear_line_bytes(offset);
            }
        }
    }

    /// Applies a contiguous run of concrete values at consecutive offsets
    /// starting at `offset`, cloning (or first materializing) only the lines
    /// the run touches and evicting any symbolic cells it covers. Offsets
    /// must stay inside the page. Symbolic entries inside `values`, if any,
    /// are ignored — callers route those through [`write`](Self::write).
    fn write_values(&mut self, offset: usize, values: &[ByteValue]) {
        if values.is_empty() {
            return;
        }
        let mut cursor = 0usize;
        while cursor < values.len() {
            let page_offset = offset + cursor;
            let line_index = page_offset / PAGE_LINE_BYTES;
            let in_line = page_offset % PAGE_LINE_BYTES;
            let chunk = (values.len() - cursor).min(PAGE_LINE_BYTES - in_line);
            if line_index >= self.lines.len() {
                self.lines.resize(line_index + 1, None);
            }
            let line = self.lines[line_index].get_or_insert_with(|| Arc::new([0u8; PAGE_LINE_BYTES]));
            let line = Arc::make_mut(line);
            for (index, value) in values[cursor..cursor + chunk].iter().enumerate() {
                if let ByteValue::Concrete(byte) = value {
                    line[in_line + index] = *byte;
                }
            }
            cursor += chunk;
        }
        let end = offset + values.len();
        self.symbolic
            .retain(|cell_offset, _| *cell_offset < offset || *cell_offset >= end);
    }

    /// Zeroes the concrete byte at `offset` so a symbolic cell is not
    /// shadowed by stale concrete data.
    fn clear_line_bytes(&mut self, offset: usize) {
        let line_index = offset / PAGE_LINE_BYTES;
        if let Some(slot) = self.lines.get_mut(line_index)
            && let Some(line) = slot
        {
            let line = Arc::make_mut(line);
            line[offset % PAGE_LINE_BYTES] = 0;
        }
    }

    /// Number of materialized concrete lines (diagnostics and tests).
    #[cfg(test)]
    fn concrete_lines(&self) -> usize {
        self.lines.iter().flatten().count()
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
    /// Under-constrained memory policy (`uc_memory`), `None` when off. When
    /// armed, unmapped reads return zero bytes and unmapped writes allocate
    /// zero-backed pages on demand, with every hit debt-recorded in the
    /// shared ledger. Clones/forks share one ledger, so a whole run
    /// aggregates into it.
    uc: Option<Arc<std::sync::Mutex<UcMemoryLedger>>>,
    /// Read-only-write relaxation (`uc_write_ro`), meaningful only while
    /// `uc` is armed: a write into a mapped, non-executable page whose
    /// current bytes are all concrete is allowed, debt-recorded, and its
    /// previous bytes logged. Fail-closed default (`false`).
    uc_write_ro: bool,
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
            uc: None,
            uc_write_ro: false,
        })
    }

    /// Returns a memory map with `region` added — pages (the actual bytes)
    /// are shared unchanged; only the region index and code-version guards
    /// are rebuilt. Used by `mmap`/`mprotect` models to grow the map at
    /// runtime.
    pub fn with_region(&self, region: MemoryRegion) -> Result<Self, MemoryError> {
        let mut regions: Vec<MemoryRegion> = self.regions.iter().cloned().collect();
        regions.push(region);
        regions.sort_by_key(|r| r.base);
        let mut region_index = BTreeMap::new();
        let mut code_versions: BTreeMap<CodePageId, CodePageVersion> =
            self.code_versions.iter().map(|(k, v)| (*k, *v)).collect();
        let mut previous_end = None;
        for (index, r) in regions.iter().enumerate() {
            if r.size == 0 {
                return Err(MemoryError::InvalidRegion);
            }
            let end = r.base.checked_add(r.size).ok_or(MemoryError::AddressOverflow)?;
            if let Some(pe) = previous_end
                && r.base < pe
            {
                return Err(MemoryError::RegionOverlap);
            }
            previous_end = Some(end);
            region_index.insert(r.base, index);
            if r.executable {
                let first = Self::page_number(r.base);
                let last = Self::page_number(end - 1);
                for page in first..=last {
                    code_versions.insert(CodePageId(page), CodePageVersion(0));
                }
            }
        }
        Ok(Self {
            regions: Arc::new(regions),
            region_index: Arc::new(region_index),
            pages: self.pages.clone(),
            code_versions: Arc::new(code_versions),
            uc: self.uc.clone(),
            uc_write_ro: self.uc_write_ro,
        })
    }

    /// Arms the under-constrained memory policy on this snapshot
    /// (opt-in — the Lua `uc_memory` flag).
    ///
    /// With the policy armed:
    /// - an unmapped READ returns zero bytes (the missing pages read as
    ///   `Concrete(0)` exactly like mapped-but-unwritten bytes);
    /// - an unmapped WRITE allocates the covering pages zero-backed on
    ///   demand, so a later read-back observes the stored bytes;
    /// - every relaxed access is debt-recorded in a ledger shared with every
    ///   clone/fork of this snapshot (see [`UcMemoryLedger`]).
    ///
    /// Deliberately NOT relaxed: permissions (a mapped page that denies the
    /// access still fails closed), execute accesses, and
    /// [`PersistentMemory::load_concrete`] (loader/setup writes keep their
    /// exact mapped-only contract). Fabrication is bounded by
    /// [`UC_MEMORY_MAX_FABRICATED_PAGES`]; beyond the cap the access errors
    /// exactly as it would with the flag off, with the debt still recorded.
    pub fn with_uc_memory(self) -> Self {
        Self {
            uc: Some(Arc::new(std::sync::Mutex::new(UcMemoryLedger::default()))),
            uc_write_ro: false,
            ..self
        }
    }

    /// Arms (or disarms) the read-only-write relaxation on top of an armed
    /// under-constrained policy (opt-in — the Lua `uc_write_ro` flag).
    ///
    /// When enabled and `uc_memory` is armed, a WRITE into a mapped,
    /// non-executable page whose current bytes are all concrete (image data
    /// sections — never code, never symbolic cells) is allowed: the ledger
    /// records the previous bytes ([`UcMemoryLedger::ro_reverts`], capped at
    /// [`UC_MEMORY_RO_REVERT_CAP`]), the write proceeds, and the hit is
    /// debt-recorded as [`UcMemoryOp::WriteRO`] (surfaced in
    /// `unmapped_sites` with `op = "write_ro"` and counted in the parallel
    /// `ro_write_total`). Writes into executable pages, spans touching
    /// unmapped memory, and spans crossing symbolic cells still fail closed.
    /// Without `uc_memory` this flag is inert — there is no ledger to record
    /// the relaxation into, so the write keeps its exact permission error.
    pub fn with_uc_write_ro(mut self, enabled: bool) -> Self {
        self.uc_write_ro = enabled;
        self
    }

    /// Whether the under-constrained memory policy is armed.
    pub fn uc_memory_armed(&self) -> bool {
        self.uc.is_some()
    }

    /// Whether the read-only-write relaxation is armed (meaningful only
    /// together with [`Self::uc_memory_armed`]).
    pub fn uc_write_ro_armed(&self) -> bool {
        self.uc_write_ro
    }

    /// Locks the shared policy ledger. A poisoned lock still yields the
    /// ledger — debt accounting must not turn a panicking state into
    /// unusable memory.
    fn uc_ledger(&self) -> Option<std::sync::MutexGuard<'_, UcMemoryLedger>> {
        self.uc
            .as_ref()
            .map(|ledger| ledger.lock().unwrap_or_else(|p| p.into_inner()))
    }

    /// Total accesses resolved through the under-constrained policy
    /// (uncapped), or 0 when the policy is off.
    pub fn uc_memory_total(&self) -> u64 {
        self.uc
            .as_ref()
            .map_or(0, |ledger| ledger.lock().unwrap_or_else(|p| p.into_inner()).total())
    }

    /// First-seen under-constrained access sites (capped, deduplicated per
    /// operation + page), or empty when the policy is off.
    pub fn uc_memory_sites(&self) -> Vec<UcMemoryDebtSite> {
        self.uc.as_ref().map_or_else(Vec::new, |ledger| {
            ledger.lock().unwrap_or_else(|p| p.into_inner()).sites().to_vec()
        })
    }

    /// Number of zero-backed pages the policy has fabricated so far.
    pub fn uc_memory_fabricated_pages(&self) -> usize {
        self.uc.as_ref().map_or(0, |ledger| {
            ledger.lock().unwrap_or_else(|p| p.into_inner()).fabricated_pages()
        })
    }

    /// Relaxed writes into mapped read-only pages so far (uncapped), or 0
    /// when the policy is off.
    pub fn uc_memory_ro_write_total(&self) -> u64 {
        self.uc.as_ref().map_or(0, |ledger| {
            ledger.lock().unwrap_or_else(|p| p.into_inner()).ro_write_total()
        })
    }

    /// Previous bytes overwritten by relaxed read-only writes (capped at
    /// [`UC_MEMORY_RO_REVERT_CAP`]), or empty when the policy is off.
    pub fn uc_memory_ro_reverts(&self) -> Vec<RoWriteRevert> {
        self.uc.as_ref().map_or_else(Vec::new, |ledger| {
            ledger.lock().unwrap_or_else(|p| p.into_inner()).ro_reverts().to_vec()
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
        // Instruction fetch and step-cache validation read through the same
        // relaxed policy as data accesses: with `uc_memory` armed, an
        // unmapped (garbage-transfer) pc resolves to zero-backed pages and
        // its code guards come back empty, exactly like a data read would.
        match self.check_mapped_range(address, len) {
            Ok(()) => {}
            Err(MemoryError::Unmapped(first)) if self.uc_memory_armed() => {
                self.uc_resolve_unmapped(address, len.max(1), MemoryAccessKind::Read, first)?
            }
            Err(error) => return Err(error),
        }
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

        match self.check_access_strict(address, len, access) {
            Ok(()) => Ok(()),
            // Under-constrained policy: an unmapped span resolves to
            // zero-backed pages with debt recorded. Permission denials and
            // execute accesses keep their exact strict errors.
            Err(MemoryError::Unmapped(first)) if self.uc_memory_armed() => {
                self.uc_resolve_unmapped(address, len, access, first)
            }
            Err(error) => Err(error),
        }
    }

    /// The exact flag-off access check: every byte of the span must sit in a
    /// mapped region that allows `access`.
    fn check_access_strict(&self, address: Address, len: usize, access: MemoryAccessKind) -> Result<(), MemoryError> {
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

        let end = Self::inclusive_end(address, bytes.len())?;
        let mut pages = (*self.pages).clone();

        // Walk the store one page window at a time: the page being written
        // copies its line table (untouched lines stay shared through their
        // `Arc`s) and clones only the lines the store modifies. Page windows
        // are disjoint, so each materialized page is inserted exactly once.
        let mut cursor = 0usize;
        while cursor < bytes.len() {
            let current = address
                .checked_add(u64::try_from(cursor).map_err(|_| MemoryError::AddressOverflow)?)
                .ok_or(MemoryError::AddressOverflow)?;
            let page_number = Self::page_number(current);
            let page_start_offset = Self::page_offset(current);
            let page_span = (DEFAULT_PAGE_SIZE - page_start_offset).min(bytes.len() - cursor);
            let window = &bytes[cursor..cursor + page_span];

            let mut materialized = pages
                .get(&page_number)
                .map(|existing| (**existing).clone())
                .unwrap_or_default();
            let mut window_index = 0usize;
            while window_index < window.len() {
                match window[window_index] {
                    ByteValue::Concrete(_) => {
                        // Extend over the contiguous concrete run and apply
                        // it directly from the caller's slice.
                        let run_start = window_index;
                        while window_index < window.len() && matches!(window[window_index], ByteValue::Concrete(_)) {
                            window_index += 1;
                        }
                        materialized.write_values(page_start_offset + run_start, &window[run_start..window_index]);
                    }
                    ByteValue::Symbolic(expression) => {
                        materialized.write(page_start_offset + window_index, ByteValue::Symbolic(expression));
                        window_index += 1;
                    }
                }
            }
            pages.insert(page_number, Arc::new(materialized));
            cursor += page_span;
        }

        // Version guards only diverge when an executable page is actually
        // bumped: data/stack stores share the previous code-version table
        // instead of cloning it.
        let code_versions = if bump_executable_versions {
            let to_bump: Vec<CodePageId> = (Self::page_number(address)..=Self::page_number(end))
                .map(CodePageId)
                .filter(|page| self.code_versions.contains_key(page))
                .collect();
            if to_bump.is_empty() {
                Arc::clone(&self.code_versions)
            } else {
                let mut versions = (*self.code_versions).clone();
                for page in to_bump {
                    let Some(version) = versions.get_mut(&page) else {
                        continue;
                    };
                    version.0 = version.0.checked_add(1).ok_or(MemoryError::VersionOverflow(page))?;
                }
                Arc::new(versions)
            }
        } else {
            Arc::clone(&self.code_versions)
        };

        Ok(Self {
            regions: Arc::clone(&self.regions),
            region_index: Arc::clone(&self.region_index),
            pages: Arc::new(pages),
            code_versions,
            uc: self.uc.clone(),
            uc_write_ro: self.uc_write_ro,
        })
    }

    /// Under-constrained policy resolution of an access whose span touched
    /// unmapped memory: mapped parts of the span still enforce their
    /// permission (fail closed), unmapped parts are recorded as debt and
    /// their pages fabricated zero-backed — bounded by
    /// [`UC_MEMORY_MAX_FABRICATED_PAGES`], beyond which the original
    /// unmapped error is returned unchanged.
    ///
    /// `access` is never [`MemoryAccessKind::Execute`]: the callers refuse
    /// to relax executable accesses (code pages never appear by accident).
    fn uc_resolve_unmapped(
        &self,
        address: Address,
        len: usize,
        access: MemoryAccessKind,
        first_unmapped: Address,
    ) -> Result<(), MemoryError> {
        let op = match access {
            MemoryAccessKind::Read => UcMemoryOp::Read,
            MemoryAccessKind::Write => UcMemoryOp::Write,
            MemoryAccessKind::Execute => return Err(MemoryError::Unmapped(first_unmapped)),
        };
        let end = Self::inclusive_end(address, len)?;
        let mut ledger = self.uc_ledger().ok_or(MemoryError::Unmapped(first_unmapped))?;

        let mut new_pages: Vec<u64> = Vec::new();
        let mut capped = false;
        let mut cursor = address;
        loop {
            match self.region_containing(cursor) {
                Some(region) => {
                    // Mapped part: the permission check keeps its exact
                    // strict semantics — mapping is relaxed, permissions
                    // never are.
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
                    if region_end > end {
                        break;
                    }
                    cursor = region_end;
                }
                None => {
                    // Unmapped gap: bounded by the next region's base or the
                    // end of the access, whichever comes first.
                    let gap_start = cursor;
                    let gap_end = match self.region_index.range(cursor..).next() {
                        Some((&base, _)) if base <= end => base - 1,
                        _ => end,
                    };
                    let mut page = Self::page_number(gap_start);
                    let last = Self::page_number(gap_end);
                    loop {
                        let fabricated = ledger.fabricated_pages.len() + new_pages.len();
                        if fabricated >= UC_MEMORY_MAX_FABRICATED_PAGES {
                            capped = true;
                            break;
                        }
                        if !ledger.fabricated_pages.contains(&page) && !new_pages.contains(&page) {
                            new_pages.push(page);
                        }
                        if page == last {
                            break;
                        }
                        page += 1;
                    }
                    if gap_end == end {
                        break;
                    }
                    cursor = gap_end + 1;
                }
            }
        }
        // One hit per relaxed access; sites deduplicate per (op, page).
        // Recorded after the loop to avoid counting hits that returned early
        // with a permission error.
        ledger.record_hit(op, first_unmapped, Self::page_base(first_unmapped));
        if capped {
            // Fail closed exactly like the flag-off path (debt is still
            // recorded above — the hit happened either way).
            return Err(MemoryError::Unmapped(first_unmapped));
        }
        for page in new_pages {
            ledger.fabricated_pages.insert(page);
        }
        Ok(())
    }

    /// Read-only-write relaxation (`uc_write_ro`) of a store that hit a
    /// mapped, non-writable page: validates the span, records the debt and
    /// the previous bytes, and returns so the caller performs the store.
    ///
    /// Validation is fail-closed — the store proceeds only when EVERY page
    /// under the span is
    /// 1. mapped (a span touching unmapped memory keeps the exact unmapped /
    ///    permission error the strict path produced — the fabrication policy
    ///    owns unmapped spans),
    /// 2. NOT executable (image code is never relaxed, byte-identically to
    ///    the flag-off path), and
    /// 3. concrete under the span: no symbolic cell may be clobbered by a
    ///    relaxation that cannot represent what it would overwrite.
    ///
    /// On success the ledger records a [`UcMemoryOp::WriteRO`] hit, bumps
    /// `ro_write_total`, and logs the previous byte of each span byte
    /// (first-come, capped at [`UC_MEMORY_RO_REVERT_CAP`]).
    fn uc_resolve_ro_write(&self, address: Address, bytes: &[ByteValue], denied: Address) -> Result<(), MemoryError> {
        let fail = || MemoryError::PermissionDenied {
            address: denied,
            access: MemoryAccessKind::Write,
        };
        let len = bytes.len();
        if len == 0 {
            return Ok(());
        }
        let end = Self::inclusive_end(address, len)?;

        // (1) + (2): every byte of the span sits in a mapped, non-executable
        // region. The walk mirrors `check_access_strict`'s region hop so a
        // span crossing a region boundary cannot dodge the check.
        let mut cursor = address;
        loop {
            let region = self.region_containing(cursor).ok_or_else(fail)?;
            if region.executable {
                return Err(fail());
            }
            let region_end = Self::region_end(region)?;
            let region_last = region_end - 1;
            if region_last >= end {
                break;
            }
            cursor = region_end;
        }

        // (2) + (3) per page window: executable pages never appear here (the
        // region walk refused them), and a symbolic cell under the window
        // fails closed.
        let mut cursor = 0usize;
        while cursor < len {
            let current = address
                .checked_add(u64::try_from(cursor).map_err(|_| MemoryError::AddressOverflow)?)
                .ok_or_else(fail)?;
            let page = Self::page_number(current);
            let start_offset = Self::page_offset(current);
            let span = (DEFAULT_PAGE_SIZE - start_offset).min(len - cursor);
            if let Some(page_data) = self.pages.get(&page)
                && page_data
                    .symbolic
                    .range(start_offset..start_offset + span)
                    .next()
                    .is_some()
            {
                return Err(fail());
            }
            cursor += span;
        }

        // The relaxation is accepted: record the hit, the parallel counter,
        // and the previous bytes (the page model reads unwritten offsets as
        // `Concrete(0)`, and (3) guarantees no symbolic cell shadows them).
        let recorded = len.min(UC_MEMORY_RO_REVERT_CAP);
        let mut reverts = Vec::with_capacity(recorded);
        for index in 0..recorded {
            let current = address
                .checked_add(u64::try_from(index).map_err(|_| MemoryError::AddressOverflow)?)
                .ok_or_else(fail)?;
            let page_data = self.pages.get(&Self::page_number(current));
            let previous = page_data.map_or(0, |page| match page.value(Self::page_offset(current)) {
                ByteValue::Concrete(byte) => byte,
                // Unreachable under (3); a symbolic cell stays unrelaxed.
                ByteValue::Symbolic(_) => 0,
            });
            reverts.push(RoWriteRevert {
                address: current,
                previous,
            });
        }
        let mut ledger = self.uc_ledger().ok_or_else(fail)?;
        ledger.record_ro_write(denied, Self::page_base(denied), &reverts);
        Ok(())
    }

    /// Base address of the 4 KiB page containing `address`.
    fn page_base(address: Address) -> Address {
        address - (address % DEFAULT_PAGE_SIZE as u64)
    }
}

impl LayeredMemory for PersistentMemory {
    type Error = MemoryError;

    fn read(&self, address: Address, len: usize) -> Result<Vec<ByteValue>, Self::Error> {
        // Unwritten bytes read as `Concrete(0)`, so pre-fill the output with
        // zeros and let `read_into` overwrite only materialized data.
        let mut output = vec![ByteValue::Concrete(0); len];
        self.read_into(address, &mut output)?;
        Ok(output)
    }

    fn read_into(&self, address: Address, out: &mut [ByteValue]) -> Result<(), Self::Error> {
        self.check_access(address, out.len(), MemoryAccessKind::Read)?;
        out.fill(ByteValue::Concrete(0));
        if out.is_empty() {
            return Ok(());
        }

        let end = Self::inclusive_end(address, out.len())?;
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
                // Copy whole concrete-line slices where materialized; gaps
                // stay `Concrete(0)` from the pre-fill, and symbolic cells
                // overlay their bytes afterwards.
                let range = start_offset..=end_offset_inclusive;
                let first_line = start_offset / PAGE_LINE_BYTES;
                let last_line = end_offset_inclusive / PAGE_LINE_BYTES;
                for line_index in first_line..=last_line {
                    let Some(line) = page_data.lines.get(line_index).and_then(|line| line.as_ref()) else {
                        continue;
                    };
                    let line_start = line_index * PAGE_LINE_BYTES;
                    let from = start_offset.max(line_start);
                    let to = (end_offset_inclusive + 1).min(line_start + PAGE_LINE_BYTES);
                    let byte_values: &mut [ByteValue] =
                        &mut out[out_index + from - start_offset..out_index + to - start_offset];
                    for (slot, byte) in byte_values
                        .iter_mut()
                        .zip(line[(from - line_start)..(to - line_start)].iter())
                    {
                        *slot = ByteValue::Concrete(*byte);
                    }
                }
                for (&offset, &expression) in page_data.symbolic.range(range) {
                    out[out_index + (offset - start_offset)] = ByteValue::Symbolic(expression);
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

        Ok(())
    }

    fn write(&self, address: Address, bytes: &[ByteValue]) -> Result<Self, Self::Error> {
        // Dispatch on the exact strict check instead of `check_access` so the
        // read-only-write relaxation can interpose on permission denials
        // without touching the read path. Flag-off behavior is byte-identical:
        // the unmapped arm re-issues exactly what `check_access` did, and the
        // permission arm only exists under `uc_memory` + `uc_write_ro`.
        match self.check_access_strict(address, bytes.len(), MemoryAccessKind::Write) {
            Ok(()) => self.write_materialized(address, bytes, true),
            Err(MemoryError::Unmapped(first)) if self.uc_memory_armed() => {
                self.uc_resolve_unmapped(address, bytes.len(), MemoryAccessKind::Write, first)?;
                self.write_materialized(address, bytes, true)
            }
            Err(MemoryError::PermissionDenied {
                address: denied,
                access: MemoryAccessKind::Write,
            }) if self.uc_memory_armed() && self.uc_write_ro => {
                self.uc_resolve_ro_write(address, bytes, denied)?;
                self.write_materialized(address, bytes, true)
            }
            Err(error) => Err(error),
        }
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

    fn read_into(&self, address: Address, out: &mut [ByteValue]) -> Result<(), Self::Error> {
        self.inner.read_into(address, out)
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
        // Three writes inside one 64-byte line: one line, no symbolic cells.
        assert_eq!(page.concrete_lines(), 1, "writes in one line share a single line");
        assert_eq!(page.value(10), ByteValue::Concrete(0x01));
        assert_eq!(page.value(20), ByteValue::Concrete(0x02));
        assert_eq!(page.value(30), ByteValue::Concrete(0x03));
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
        assert_eq!(
            page.concrete_lines(),
            1,
            "overwriting an offset should not grow the line table"
        );
        assert_eq!(page.value(7), ByteValue::Concrete(0x22), "latest write wins");
    }

    #[test]
    fn sparse_page_symbolic_and_concrete_coexist() {
        let mut page = MemoryPage::default();
        page.write(0, ByteValue::Concrete(0xab));
        page.write(100, ByteValue::Symbolic(ExprId(5)));
        assert_eq!(page.value(0), ByteValue::Concrete(0xab));
        assert_eq!(page.value(100), ByteValue::Symbolic(ExprId(5)));
        assert_eq!(page.concrete_lines(), 1);
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

    #[test]
    fn store_clones_only_the_touched_line() -> Result<(), MemoryError> {
        // Fill two lines of one page, then store into the first: the second
        // line must remain Arc-shared with the pre-store page.
        let memory = PersistentMemory::new(vec![region(0x1000, 0x1000, true, false)])?;
        let filled: Vec<ByteValue> = (0..128_u8).map(ByteValue::Concrete).collect();
        let memory = memory.write(0x1000, &filled)?;

        let page_number = PersistentMemory::page_number(0x1000);
        let untouched_before = memory
            .pages
            .get(&page_number)
            .and_then(|page| page.lines.get(1))
            .and_then(|line| line.clone());

        let modified = memory.write(0x1000, &[ByteValue::Concrete(0xee)])?;

        let untouched_after = modified
            .pages
            .get(&page_number)
            .and_then(|page| page.lines.get(1))
            .and_then(|line| line.clone());
        assert!(
            untouched_before.is_some() && untouched_after.is_some(),
            "both lines must be materialized"
        );
        if let (Some(before), Some(after)) = (untouched_before, untouched_after) {
            assert!(
                Arc::ptr_eq(&before, &after),
                "an untouched line must stay shared across the store"
            );
        }
        assert_eq!(modified.read(0x1000, 1)?, vec![ByteValue::Concrete(0xee)]);
        assert_eq!(modified.read(0x1040, 1)?, vec![ByteValue::Concrete(0x40)]);
        Ok(())
    }

    #[test]
    fn data_store_shares_code_version_table() -> Result<(), MemoryError> {
        // A store that touches no executable page must share (not clone) the
        // code-version table; an executable store must diverge it.
        let memory = PersistentMemory::new(vec![
            region(0x1000, 0x1000, true, true),
            region(0x9000, 0x1000, true, false),
        ])?;
        let code_page = PersistentMemory::page_id_for_address(0x1000);

        let data_write = memory.write(0x9000, &[ByteValue::Concrete(0x11)])?;
        assert!(
            Arc::ptr_eq(&memory.code_versions, &data_write.code_versions),
            "non-executable store must share the code-version table"
        );
        assert_eq!(
            data_write.page_version(code_page),
            Some(CodePageVersion(0)),
            "non-executable store must not bump versions"
        );

        let code_write = memory.write(0x1000, &[ByteValue::Concrete(0x22)])?;
        assert!(
            !Arc::ptr_eq(&memory.code_versions, &code_write.code_versions),
            "executable store must diverge the code-version table"
        );
        assert_eq!(code_write.page_version(code_page), Some(CodePageVersion(1)));
        assert_eq!(memory.page_version(code_page), Some(CodePageVersion(0)));
        Ok(())
    }

    #[test]
    fn read_into_matches_read_and_handles_mixed_content() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x3000, true, false)])?;
        // Concrete run spanning a line boundary, a symbolic byte, a gap, and
        // a second page.
        let memory = memory.write(
            0x103e,
            &[ByteValue::Concrete(1), ByteValue::Concrete(2), ByteValue::Concrete(3)],
        )?;
        let memory = memory.write(0x1042, &[ByteValue::Symbolic(ExprId(31))])?;
        let memory = memory.write(0x2001, &[ByteValue::Concrete(0x77)])?;

        let mut buffer = [ByteValue::Concrete(0); 12];
        memory.read_into(0x103e, &mut buffer)?;
        let via_vec = memory.read(0x103e, 12)?;
        assert_eq!(buffer.as_slice(), via_vec.as_slice(), "read_into must match read");
        assert_eq!(
            &buffer[..3],
            &[ByteValue::Concrete(1), ByteValue::Concrete(2), ByteValue::Concrete(3)]
        );
        assert_eq!(buffer[3], ByteValue::Concrete(0), "unwritten gap reads zero");
        assert_eq!(buffer[4], ByteValue::Symbolic(ExprId(31)));
        assert!(buffer[5..].iter().all(|byte| *byte == ByteValue::Concrete(0)));
        // The second page's byte reads back through both APIs as well.
        let mut single = [ByteValue::Concrete(0); 1];
        memory.read_into(0x2001, &mut single)?;
        assert_eq!(single[0], ByteValue::Concrete(0x77));

        // Zero-length and error paths.
        memory.read_into(0x103e, &mut [])?;
        assert!(matches!(
            memory.read_into(0x8000, &mut buffer),
            Err(MemoryError::Unmapped(0x8000))
        ));
        Ok(())
    }

    #[test]
    fn mixed_concrete_symbolic_store_across_lines_and_pages() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x3000, true, false)])?;
        let store = [
            ByteValue::Concrete(0xaa),
            ByteValue::Concrete(0xbb),
            ByteValue::Symbolic(ExprId(7)),
            ByteValue::Concrete(0xdd),
        ];
        // Straddle the first page's last line and the next page.
        let written = memory.write(0x1ffe, &store)?;

        assert_eq!(
            written.read(0x1ffe, 4)?,
            vec![
                ByteValue::Concrete(0xaa),
                ByteValue::Concrete(0xbb),
                ByteValue::Symbolic(ExprId(7)),
                ByteValue::Concrete(0xdd),
            ]
        );
        // Neighbors outside the store stay zero.
        assert_eq!(written.read(0x1ffd, 1)?, vec![ByteValue::Concrete(0)]);
        assert_eq!(written.read(0x2002, 1)?, vec![ByteValue::Concrete(0)]);
        // Concrete over a symbolic cell evicts it.
        let overwritten = written.write(0x2000, &[ByteValue::Concrete(0x99)])?;
        assert_eq!(overwritten.read(0x2000, 1)?, vec![ByteValue::Concrete(0x99)]);
        Ok(())
    }

    // --- Under-constrained memory policy (`uc_memory`) -------------------

    #[test]
    fn uc_read_unmapped_returns_zeros_and_records_debt() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x1000, true, false)])?.with_uc_memory();
        assert!(memory.uc_memory_armed());

        let read = memory.read(0x7000, 8)?;
        assert_eq!(read, vec![ByteValue::Concrete(0); 8], "unmapped read is zero bytes");
        assert_eq!(memory.uc_memory_total(), 1);
        assert_eq!(
            memory.uc_memory_sites(),
            vec![UcMemoryDebtSite {
                op: UcMemoryOp::Read,
                address: 0x7000,
                page: 0x7000,
            }]
        );
        assert_eq!(memory.uc_memory_fabricated_pages(), 1);

        // A repeat hit counts toward the total but deduplicates the site,
        // and a different page becomes a new site.
        let _ = memory.read(0x7004, 4)?;
        let _ = memory.read(0x8000, 1)?;
        assert_eq!(memory.uc_memory_total(), 3);
        assert_eq!(memory.uc_memory_sites().len(), 2);
        Ok(())
    }

    #[test]
    fn uc_write_unmapped_allocates_zero_backed_and_records_debt() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x1000, true, false)])?.with_uc_memory();

        let written = memory.write(0x5000, &[ByteValue::Concrete(0x42)])?;
        assert_eq!(
            written.read(0x5000, 1)?,
            vec![ByteValue::Concrete(0x42)],
            "unmapped write allocates the page so the store reads back"
        );
        // Unwritten bytes of the fabricated page read as zeros.
        assert_eq!(written.read(0x5001, 1)?, vec![ByteValue::Concrete(0)]);
        // Total counts every relaxed access: one write + two reads of the
        // fabricated page. Sites deduplicate per (op, page): one Write site
        // from the store, one Read site from the first read-back.
        assert_eq!(written.uc_memory_total(), 3);
        assert_eq!(
            written.uc_memory_sites(),
            vec![
                UcMemoryDebtSite {
                    op: UcMemoryOp::Write,
                    address: 0x5000,
                    page: 0x5000,
                },
                UcMemoryDebtSite {
                    op: UcMemoryOp::Read,
                    address: 0x5000,
                    page: 0x5000,
                },
            ]
        );
        assert_eq!(written.uc_memory_fabricated_pages(), 1);

        // A write spanning mapped and unmapped pages only fabricates the
        // uncovered one, and the mapped part keeps its permission check.
        let span = vec![ByteValue::Concrete(0x11); 8];
        let straddling = written.write(0x1ffc, &span)?;
        assert_eq!(straddling.uc_memory_fabricated_pages(), 2);
        assert_eq!(straddling.read(0x2003, 1)?, vec![ByteValue::Concrete(0x11)]);
        Ok(())
    }

    #[test]
    fn uc_flag_off_keeps_exact_unmapped_errors() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x1000, true, false)])?;
        assert!(!memory.uc_memory_armed());

        assert!(matches!(memory.read(0x7000, 1), Err(MemoryError::Unmapped(0x7000))));
        assert!(matches!(
            memory.write(0x7000, &[ByteValue::Concrete(1)]),
            Err(MemoryError::Unmapped(0x7000))
        ));
        assert_eq!(memory.uc_memory_total(), 0);
        assert!(memory.uc_memory_sites().is_empty());
        assert_eq!(memory.uc_memory_fabricated_pages(), 0);

        // Permission denials fail closed even when armed (the test helper's
        // regions are always readable, so writes exercise the denial).
        let armed = PersistentMemory::new(vec![region(0x5000, 0x1000, false, true)])?.with_uc_memory();
        assert!(matches!(
            armed.write(0x5000, &[ByteValue::Concrete(1)]),
            Err(MemoryError::PermissionDenied {
                access: MemoryAccessKind::Write,
                ..
            })
        ));
        // ...and a span whose unmapped gap precedes a mapped but
        // permission-denied page still fails closed on the permission.
        let mixed = PersistentMemory::new(vec![
            region(0x3000, 0x1000, true, false),
            region(0x10000, 0x1000, false, false),
        ])?
        .with_uc_memory();
        assert!(matches!(
            mixed.write(0x4000, &vec![ByteValue::Concrete(1); 0xc001]),
            Err(MemoryError::PermissionDenied {
                access: MemoryAccessKind::Write,
                ..
            })
        ));
        Ok(())
    }

    #[test]
    fn uc_fork_and_writes_share_one_ledger() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x1000, true, false)])?.with_uc_memory();
        let fork = memory.fork();
        let changed = memory.write(0x9000, &[ByteValue::Concrete(7)])?;

        // Every lineage clone reports the shared run-wide ledger.
        assert_eq!(fork.uc_memory_total(), 1);
        assert_eq!(changed.uc_memory_total(), 1);
        assert_eq!(fork.uc_memory_sites().len(), 1);
        assert_eq!(changed.uc_memory_sites().len(), 1);
        assert_eq!(fork.uc_memory_fabricated_pages(), 1);
        Ok(())
    }

    #[test]
    fn uc_relaxes_code_version_guards_for_fabricated_pages() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x1000, true, true)])?.with_uc_memory();
        // A wild transfer into unmapped memory: guards resolve (empty — the
        // fabricated page carries no code versions) instead of faulting.
        let guards = memory.code_version_guards_for_range(0x10000, 4)?;
        assert!(guards.is_empty());
        assert_eq!(memory.uc_memory_total(), 1);

        // Flag off: the same range faults.
        let strict = PersistentMemory::new(vec![region(0x1000, 0x1000, true, true)])?;
        assert!(matches!(
            strict.code_version_guards_for_range(0x10000, 4),
            Err(MemoryError::Unmapped(0x10000))
        ));
        Ok(())
    }

    #[test]
    fn uc_load_concrete_stays_strict_when_armed() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x1000, true, false)])?.with_uc_memory();
        assert!(matches!(
            memory.load_concrete(0x7000, &[1, 2, 3]),
            Err(MemoryError::Unmapped(0x7000))
        ));
        Ok(())
    }

    #[test]
    fn uc_fabrication_cap_fails_closed_but_records_debt() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x1000, true, false)])?.with_uc_memory();
        // One access spanning more distinct pages than the fabrication cap
        // allows: the policy refuses (exact flag-off error) after recording.
        let span_pages = UC_MEMORY_MAX_FABRICATED_PAGES + 2;
        let address = 0x1_0000_0000u64;
        let len = span_pages * DEFAULT_PAGE_SIZE;
        let result = memory.read(address, len);
        assert!(
            matches!(result, Err(MemoryError::Unmapped(_))),
            "a span beyond the fabrication cap must fail closed"
        );
        assert_eq!(memory.uc_memory_total(), 1);
        assert_eq!(memory.uc_memory_fabricated_pages(), 0);
        Ok(())
    }

    #[test]
    fn uc_debt_site_cap_limits_the_log_not_the_total() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x1000, true, false)])?.with_uc_memory();
        // Sweep pages well above the mapped region so every access is a hit.
        let base = 0x10_0000u64;
        for page in 0..(UC_MEMORY_DEBT_SITE_CAP as u64 + 8) {
            let _ = memory.read(base + page * DEFAULT_PAGE_SIZE as u64, 1)?;
        }
        assert_eq!(memory.uc_memory_sites().len(), UC_MEMORY_DEBT_SITE_CAP);
        assert_eq!(
            memory.uc_memory_total(),
            UC_MEMORY_DEBT_SITE_CAP as u64 + 8,
            "the total keeps counting past the site cap"
        );
        Ok(())
    }

    #[test]
    fn uc_top_of_address_space_span_does_not_overflow() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1000, 0x1000, true, false)])?.with_uc_memory();
        // The span ends exactly at u64::MAX — the gap walk must terminate
        // instead of overflowing.
        let written = memory.write(0xfffffffffffffff8, &[ByteValue::Concrete(1); 8])?;
        assert_eq!(written.uc_memory_total(), 1);
        assert_eq!(written.uc_memory_fabricated_pages(), 1);
        assert_eq!(written.read(0xffffffffffffffff, 1)?, vec![ByteValue::Concrete(1)]);
        Ok(())
    }

    // --- Read-only-write relaxation (`uc_write_ro`) -----------------------

    /// A read-only data page (image .rdata shape) holding distinct bytes.
    fn ro_data_memory(policy: fn(PersistentMemory) -> PersistentMemory) -> Result<PersistentMemory, MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1404d0000, 0x2000, false, false)])?;
        let memory = memory.load_concrete(0x1404d0000, &[0x11, 0x22, 0x33, 0x44])?;
        Ok(policy(memory))
    }

    #[test]
    fn uc_write_ro_relaxes_concrete_read_only_data_writes() -> Result<(), MemoryError> {
        let memory = ro_data_memory(|m| m.with_uc_memory().with_uc_write_ro(true))?;
        let written = memory.write(0x1404d0018, &[ByteValue::Concrete(0xaa), ByteValue::Concrete(0xbb)])?;

        // The write lands and reads back.
        assert_eq!(
            written.read(0x1404d0018, 2)?,
            vec![ByteValue::Concrete(0xaa), ByteValue::Concrete(0xbb)]
        );
        // Debt: one WriteRO hit, surfaced with the write_ro op name, plus
        // the parallel ro counter.
        assert_eq!(written.uc_memory_total(), 1);
        assert_eq!(written.uc_memory_ro_write_total(), 1);
        assert_eq!(
            written.uc_memory_sites(),
            vec![UcMemoryDebtSite {
                op: UcMemoryOp::WriteRO,
                address: 0x1404d0018,
                page: 0x1404d0000,
            }]
        );
        // The previous bytes are recorded for inspection/reversion.
        assert_eq!(
            written.uc_memory_ro_reverts(),
            vec![
                RoWriteRevert {
                    address: 0x1404d0018,
                    previous: 0x00
                },
                RoWriteRevert {
                    address: 0x1404d0019,
                    previous: 0x00
                },
            ]
        );
        Ok(())
    }

    #[test]
    fn uc_write_ro_records_the_previous_image_bytes() -> Result<(), MemoryError> {
        let memory = ro_data_memory(|m| m.with_uc_memory().with_uc_write_ro(true))?;
        let written = memory.write(0x1404d0000, &[ByteValue::Concrete(0xff)])?;
        assert_eq!(
            written.uc_memory_ro_reverts(),
            vec![RoWriteRevert {
                address: 0x1404d0000,
                previous: 0x11
            }]
        );
        // A second store over the (now rewritten) first byte records the
        // byte it actually replaced — the revert log mirrors each hit.
        let again = written.write(0x1404d0000, &[ByteValue::Concrete(0x77)])?;
        assert_eq!(again.uc_memory_ro_write_total(), 2);
        assert_eq!(
            again.uc_memory_ro_reverts(),
            vec![
                RoWriteRevert {
                    address: 0x1404d0000,
                    previous: 0x11
                },
                RoWriteRevert {
                    address: 0x1404d0000,
                    previous: 0xff
                },
            ]
        );
        Ok(())
    }

    #[test]
    fn uc_write_ro_off_keeps_permission_denied() -> Result<(), MemoryError> {
        // uc_memory alone (the exact prior flag surface): the write must
        // fail closed with the same error as no policy at all.
        let memory = ro_data_memory(|m| m.with_uc_memory())?;
        let result = memory.write(0x1404d0018, &[ByteValue::Concrete(0xaa)]);
        assert!(
            matches!(
                result,
                Err(MemoryError::PermissionDenied {
                    address: 0x1404d0018,
                    access: MemoryAccessKind::Write
                })
            ),
            "flag off must keep the exact permission denial"
        );
        // And the bare policy-off path errors identically.
        let bare = ro_data_memory(|m| m)?;
        assert!(matches!(
            bare.write(0x1404d0018, &[ByteValue::Concrete(0xaa)]),
            Err(MemoryError::PermissionDenied { .. })
        ));
        Ok(())
    }

    #[test]
    fn uc_write_ro_without_uc_memory_is_inert() -> Result<(), MemoryError> {
        // The relaxation records into the shared ledger — without the policy
        // there is no ledger, so the flag must not open any door.
        let memory = ro_data_memory(|m| m.with_uc_write_ro(true))?;
        assert!(!memory.uc_write_ro_armed() || memory.uc_write_ro_armed());
        assert!(matches!(
            memory.write(0x1404d0018, &[ByteValue::Concrete(0xaa)]),
            Err(MemoryError::PermissionDenied { .. })
        ));
        assert_eq!(memory.uc_memory_total(), 0);
        Ok(())
    }

    #[test]
    fn uc_write_ro_never_relaxes_executable_pages() -> Result<(), MemoryError> {
        // An executable read-only page (image .text): denied even armed.
        let memory = PersistentMemory::new(vec![region(0x140001000, 0x1000, false, true)])?
            .load_concrete(0x140001000, &[0x90, 0xc3])?
            .with_uc_memory()
            .with_uc_write_ro(true);
        assert!(matches!(
            memory.write(0x140001000, &[ByteValue::Concrete(0x90)]),
            Err(MemoryError::PermissionDenied { .. })
        ));
        assert_eq!(memory.uc_memory_total(), 0);
        // A span straddling a read-only data page into an executable page:
        // one executable page anywhere under the span denies the whole
        // store.
        let straddled = PersistentMemory::new(vec![
            region(0x1404d0000, 0x10000, false, false),
            region(0x1404e0000, 0x10000, false, true),
        ])?
        .with_uc_memory()
        .with_uc_write_ro(true);
        assert!(matches!(
            straddled.write(0x1404dfffc, &[ByteValue::Concrete(1); 8]),
            Err(MemoryError::PermissionDenied { .. })
        ));
        assert_eq!(straddled.uc_memory_total(), 0);
        Ok(())
    }

    #[test]
    fn uc_write_ro_refuses_spans_over_symbolic_cells() -> Result<(), MemoryError> {
        // A symbolic byte (the memory layer only carries the ExprId, no
        // arena needed) planted into the read-only page through the
        // relaxation itself: the plant is one WriteRO hit.
        let symbol = ByteValue::Symbolic(ExprId(0x1234));
        let memory = PersistentMemory::new(vec![region(0x1404d0000, 0x2000, false, false)])?
            .load_concrete(0x1404d0000, &[0x11, 0x22, 0x33, 0x44])?
            .with_uc_memory()
            .with_uc_write_ro(true);
        let planted = memory.write(0x1404d0020, &[symbol])?;
        assert_eq!(planted.uc_memory_ro_write_total(), 1);
        // A store covering the symbolic cell fails closed — the relaxation
        // must not clobber symbolic state it cannot represent.
        assert!(matches!(
            planted.write(0x1404d0000, &[ByteValue::Concrete(1); 64]),
            Err(MemoryError::PermissionDenied { .. })
        ));
        assert_eq!(planted.uc_memory_ro_write_total(), 1);
        // ...but a store clear of the symbolic cell is relaxed as usual.
        let cleared = planted.write(0x1404d0100, &[ByteValue::Concrete(9)])?;
        assert_eq!(cleared.uc_memory_ro_write_total(), 2);
        Ok(())
    }

    #[test]
    fn uc_write_ro_straddles_into_writable_pages() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![
            region(0x1404d0000, 0x10000, false, false),
            region(0x1404e0000, 0x10000, true, false),
        ])?
        .load_concrete(0x1404d0ffc, &[1, 2, 3, 4])?
        .with_uc_memory()
        .with_uc_write_ro(true);
        let written = memory.write(0x1404d0ffe, &[ByteValue::Concrete(0xaa); 4])?;
        // RO part relaxed, writable part written normally.
        assert_eq!(written.read(0x1404d0ffe, 4)?, vec![ByteValue::Concrete(0xaa); 4]);
        assert_eq!(written.uc_memory_ro_write_total(), 1);
        assert_eq!(written.uc_memory_sites().len(), 1);
        Ok(())
    }

    #[test]
    fn uc_write_ro_revert_log_is_capped() -> Result<(), MemoryError> {
        let memory = PersistentMemory::new(vec![region(0x1404d0000, 0x20000, false, false)])?
            .with_uc_memory()
            .with_uc_write_ro(true);
        // One span wider than the revert cap: the write relaxes, the log
        // keeps the first UC_MEMORY_RO_REVERT_CAP previous bytes, counters
        // are uncapped.
        let len = UC_MEMORY_RO_REVERT_CAP + 512;
        let written = memory.write(0x1404d0000, &vec![ByteValue::Concrete(1); len])?;
        assert_eq!(written.uc_memory_ro_write_total(), 1);
        assert_eq!(written.uc_memory_ro_reverts().len(), UC_MEMORY_RO_REVERT_CAP);
        assert_eq!(written.uc_memory_ro_reverts()[0].address, 0x1404d0000);
        Ok(())
    }

    #[test]
    fn uc_write_ro_ledger_is_shared_with_forks() -> Result<(), MemoryError> {
        let memory = ro_data_memory(|m| m.with_uc_memory().with_uc_write_ro(true))?;
        let written = memory.write(0x1404d0018, &[ByteValue::Concrete(0xaa)])?;
        // The original snapshot and any fork observe the same run-wide debt.
        assert_eq!(memory.uc_memory_ro_write_total(), 1);
        assert_eq!(written.fork().uc_memory_ro_write_total(), 1);
        assert_eq!(written.fork().uc_memory_ro_reverts().len(), 1);
        Ok(())
    }
}
