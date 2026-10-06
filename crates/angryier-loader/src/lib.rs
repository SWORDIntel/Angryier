#![forbid(unsafe_code)]

use std::fmt;
use std::sync::Mutex;

use angryier_types::{Address, ImageId, TargetProfileId};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ImportKind {
    StaticBinary,
    Snapshot,
    Checkpoint,
    LiveProcessCapture,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Segment {
    pub address: Address,
    pub bytes: Vec<u8>,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

/// ELF symbol type: data object (`STT_OBJECT`).
pub const STT_OBJECT: u8 = 1;
/// ELF symbol type: function or code label (`STT_FUNC`).
pub const STT_FUNC: u8 = 2;

/// A named symbol from the image's static symbol table (`.symtab`).
///
/// Symbol addresses are virtual addresses as recorded in the image and can be
/// used to hook SimProcedures or to identify function entry points.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Symbol {
    pub name: String,
    pub address: Address,
    pub size: u64,
    pub section_index: u16,
    /// ELF symbol type (`STT_*`), e.g. [`STT_FUNC`] or [`STT_OBJECT`].
    pub kind: u8,
    /// ELF symbol binding (`STB_*`), e.g. 1 = global, 2 = weak.
    pub binding: u8,
}

impl Symbol {
    /// Returns `true` when the symbol is a function or code label.
    pub fn is_function(&self) -> bool {
        self.kind == STT_FUNC
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedImage {
    pub id: ImageId,
    pub entry: Address,
    pub target_profile: TargetProfileId,
    pub segments: Vec<Segment>,
    /// Symbols parsed from the static symbol table; empty when the image has
    /// no section headers or no `.symtab`.
    pub symbols: Vec<Symbol>,
    /// Where the program header table landed in memory, when it is covered by
    /// a loaded segment. Needed for the `AT_PHDR`/`AT_PHENT`/`AT_PHNUM`
    /// auxiliary-vector entries consumed by libc startup code.
    pub program_headers: Option<ProgramHeadersInfo>,
    /// Parsed `PT_DYNAMIC` tables — present on dynamically-linked images.
    pub dynamic: Option<DynamicInfo>,
    /// Parsed PE32+ metadata — present on PE images only.
    pub pe: Option<PeInfo>,
}

/// A parsed `PT_DYNAMIC` entry of interest — a `(tag, value)` pair where
/// `value` is a virtual address or a scalar depending on the tag.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelaEntry {
    /// Address to relocate (VA).
    pub offset: u64,
    /// Relocation type (`R_X86_64_*`).
    pub r#type: u32,
    /// Symbol-table index (0 for RELATIVE).
    pub symbol: u32,
    /// Signed addend.
    pub addend: i64,
}

/// The dynamic-linking tables extracted from `PT_DYNAMIC`: `DT_NEEDED`
/// names, RELA relocations, PLT relocations, and the dynamic
/// symbol/string tables. VAs here are as-written in the file — for a
/// PIE/ET_DYN image add the load bias.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DynamicInfo {
    /// `DT_NEEDED` shared-object names.
    pub needed: Vec<String>,
    /// `DT_RELA` entries (`.rela.dyn`).
    pub rela: Vec<RelaEntry>,
    /// `DT_JMPREL` entries (`.rela.plt`).
    pub jmprel: Vec<RelaEntry>,
    /// Dynamic symbol-table VA (`DT_SYMTAB`).
    pub symtab: u64,
    /// Dynamic string-table VA (`DT_STRTAB`).
    pub strtab: u64,
}

/// Location of the loaded ELF program header table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProgramHeadersInfo {
    /// Virtual address of the table in the process image.
    pub address: Address,
    /// Size of one entry in bytes (`e_phentsize`).
    pub entry_size: u16,
    /// Number of entries (`e_phnum`).
    pub count: u16,
}

impl LoadedImage {
    /// Looks up a symbol by exact name.
    pub fn symbol(&self, name: &str) -> Option<&Symbol> {
        self.symbols.iter().find(|symbol| symbol.name == name)
    }

    /// Returns the imports parsed from a PE32+ import directory, or `None`
    /// for non-PE images. A PE image without an import directory yields an
    /// empty slice, not an error.
    ///
    /// Delay imports (`IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT`) and bound
    /// imports (`IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT`) are out of scope and
    /// skipped — only `IMAGE_DIRECTORY_ENTRY_IMPORT` (index 1) is parsed.
    /// Resolving/patching the recorded IAT slots is left to downstream
    /// consumers.
    pub fn pe_imports(&self) -> Option<&[PeImport]> {
        self.pe.as_ref().map(|pe| pe.imports.as_slice())
    }

    /// Returns the named exports parsed from a PE32+ export directory, or
    /// `None` for non-PE images. A PE image without an export directory
    /// yields an empty slice, not an error.
    ///
    /// Forwarded exports (RVA inside the export directory itself — the entry
    /// resolves in another module) are skipped at parse time and never appear
    /// here; they are not executable code in this image.
    pub fn pe_exports(&self) -> Option<&[PeExport]> {
        self.pe.as_ref().map(|pe| pe.exports.as_slice())
    }

    /// Resolves a PE export name to its in-image virtual address
    /// (`ImageBase + RVA` of the exported function/data) — the address a
    /// direct internal `call` inside the image lands on. Name matching is
    /// exact (the runtime's PE-import binding convention); Windows
    /// `GetProcAddress` case-folding is deliberately not applied. Returns
    /// `None` for non-PE images, images without an export directory, or
    /// unknown names. Use [`LoadedImage::pe_exports`] for custom matching.
    pub fn export_address(&self, name: &str) -> Option<Address> {
        let pe = self.pe.as_ref()?;
        let export = pe.exports.iter().find(|export| export.name == name)?;
        Some(pe.image_base + u64::from(export.rva))
    }
}

pub trait ImageLoader: Send + Sync {
    type Error;
    fn load(&self, bytes: &[u8]) -> Result<LoadedImage, Self::Error>;
}
pub trait StateImporter: Send + Sync {
    type State;
    type Error;
    fn import(&self, kind: ImportKind, source: &[u8]) -> Result<Self::State, Self::Error>;
}

/// Errors produced by the in-memory loader, state importer, and ELF64/PE32+ loader backends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoaderError {
    /// The provided input buffer was empty.
    EmptyInput,
    /// The provided input could not be parsed in the expected format.
    InvalidFormat,
    /// The requested import kind is not supported by this backend.
    UnsupportedKind,
    /// Internal state could not be accessed because a lock was poisoned.
    Poisoned,
    /// The ELF header or program header table was truncated.
    TruncatedHeader,
    /// The ELF class is invalid or unsupported (expected 64-bit ELF).
    InvalidElfClass,
    /// The target machine architecture is unsupported (expected x86-64).
    InvalidMachine,
    /// No program headers or loadable segments were found.
    NoProgramHeaders,
    /// A segment file offset or memory size extends beyond the input buffer.
    SegmentOutOfRange,
    /// The PE32+ import directory, a descriptor, thunk array, or import name
    /// is truncated or points outside the mapped image.
    TruncatedImportTable,
    /// A PE32+ import DLL name exceeds the enforced maximum of 64 bytes.
    ImportDllNameTooLong,
    /// The PE32+ export directory, its RVAs, lookup arrays, or an export name
    /// is truncated or points outside the mapped image.
    TruncatedExportTable,
}

impl fmt::Display for LoaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyInput => f.write_str("input buffer is empty"),
            Self::InvalidFormat => f.write_str("input has an invalid format"),
            Self::UnsupportedKind => f.write_str("unsupported import kind"),
            Self::Poisoned => f.write_str("internal state is poisoned"),
            Self::TruncatedHeader => f.write_str("truncated ELF header"),
            Self::InvalidElfClass => f.write_str("invalid ELF class (expected 64-bit)"),
            Self::InvalidMachine => f.write_str("invalid machine architecture (expected x86-64)"),
            Self::NoProgramHeaders => f.write_str("no program headers found"),
            Self::SegmentOutOfRange => f.write_str("segment offset or size is out of range"),
            Self::TruncatedImportTable => f.write_str("PE import table is truncated or out of range"),
            Self::ImportDllNameTooLong => f.write_str("PE import DLL name exceeds 64 characters"),
            Self::TruncatedExportTable => f.write_str("PE export table is truncated or out of range"),
        }
    }
}

impl std::error::Error for LoaderError {}

/// Default target profile identifier representing 64-bit Intel architecture.
pub const INTEL64_TARGET_PROFILE: TargetProfileId = TargetProfileId(1);

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const EV_CURRENT: u8 = 1;

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const EM_X86_64: u16 = 62;

const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

const SHT_SYMTAB: u32 = 2;
const ELF64_SECTION_HEADER_SIZE: u64 = 64;
const ELF64_SYMBOL_SIZE: u64 = 24;

/// Reads a little-endian `u16` at `offset`.
fn read_u16_le(src: &[u8], offset: usize) -> Result<u16, LoaderError> {
    let end = offset.checked_add(2).ok_or(LoaderError::TruncatedHeader)?;
    let slice = src.get(offset..end).ok_or(LoaderError::TruncatedHeader)?;
    let mut buf = [0u8; 2];
    buf.copy_from_slice(slice);
    Ok(u16::from_le_bytes(buf))
}

/// Reads a little-endian `u32` at `offset`.
fn read_u32_le(src: &[u8], offset: usize) -> Result<u32, LoaderError> {
    let end = offset.checked_add(4).ok_or(LoaderError::TruncatedHeader)?;
    let slice = src.get(offset..end).ok_or(LoaderError::TruncatedHeader)?;
    let mut buf = [0u8; 4];
    buf.copy_from_slice(slice);
    Ok(u32::from_le_bytes(buf))
}

/// Reads a little-endian `u64` from the first 8 bytes of `src`.
fn read_u64_le(src: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&src[..8]);
    u64::from_le_bytes(buf)
}

/// Reads a little-endian `u64` at `offset`.
fn read_u64_le_at(src: &[u8], offset: usize) -> Result<u64, LoaderError> {
    let end = offset.checked_add(8).ok_or(LoaderError::TruncatedHeader)?;
    let slice = src.get(offset..end).ok_or(LoaderError::TruncatedHeader)?;
    let mut buf = [0u8; 8];
    buf.copy_from_slice(slice);
    Ok(u64::from_le_bytes(buf))
}

/// In-memory `ImageLoader` implementation that parses a trivial binary format.
///
/// Format:
/// - bytes `0..8`  : entry address (LE u64)
/// - bytes `8..16` : target profile id (LE u64)
/// - bytes `16..`  : payload of a single executable segment at address `0x1000`
pub struct InMemoryImageLoader {
    next_id: Mutex<u64>,
}

impl InMemoryImageLoader {
    /// Creates a new loader whose first assigned `ImageId` is `1`.
    pub fn new() -> Self {
        Self { next_id: Mutex::new(1) }
    }

    fn allocate_id(&self) -> Result<ImageId, LoaderError> {
        let mut guard = self.next_id.lock().unwrap_or_else(|e| e.into_inner());
        let id = ImageId(*guard);
        *guard = guard.checked_add(1).ok_or(LoaderError::Poisoned)?;
        Ok(id)
    }
}

impl Default for InMemoryImageLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl ImageLoader for InMemoryImageLoader {
    type Error = LoaderError;

    fn load(&self, bytes: &[u8]) -> Result<LoadedImage, Self::Error> {
        if bytes.is_empty() {
            return Err(LoaderError::EmptyInput);
        }
        if bytes.len() < 16 {
            return Err(LoaderError::InvalidFormat);
        }

        let entry = read_u64_le(&bytes[0..8]);
        let target_profile = TargetProfileId(read_u64_le(&bytes[8..16]));
        let segment_bytes = bytes[16..].to_vec();

        let id = self.allocate_id()?;

        Ok(LoadedImage {
            id,
            entry,
            target_profile,
            segments: vec![Segment {
                address: 0x1000,
                bytes: segment_bytes,
                readable: true,
                writable: false,
                executable: true,
            }],
            symbols: Vec::new(),
            program_headers: None,
            dynamic: None,
            pe: None,
        })
    }
}

/// In-memory `StateImporter` that tags raw imported bytes with their kind.
pub struct InMemoryStateImporter {
    /// Stores the most recently imported kind for inspection in tests.
    last_kind: Mutex<Option<ImportKind>>,
}

impl InMemoryStateImporter {
    pub fn new() -> Self {
        Self {
            last_kind: Mutex::new(None),
        }
    }
}

impl Default for InMemoryStateImporter {
    fn default() -> Self {
        Self::new()
    }
}

impl StateImporter for InMemoryStateImporter {
    type State = Vec<u8>;
    type Error = LoaderError;

    fn import(&self, kind: ImportKind, source: &[u8]) -> Result<Self::State, Self::Error> {
        match kind {
            ImportKind::StaticBinary | ImportKind::Snapshot | ImportKind::Checkpoint => {
                let mut guard = self.last_kind.lock().unwrap_or_else(|e| e.into_inner());
                *guard = Some(kind);
                Ok(source.to_vec())
            }
            // Fail-closed: live process capture is not supported by this backend.
            ImportKind::LiveProcessCapture => Err(LoaderError::UnsupportedKind),
        }
    }
}

/// Parses the static symbol table (`.symtab`) from an ELF64 image.
///
/// Returns an empty vector when the image has no section header table or no
/// `SHT_SYMTAB` section. All section, symbol, and string-table offsets are
/// validated against the input buffer; malformed tables are reported as
/// [`LoaderError::TruncatedHeader`].
/// Parses `PT_DYNAMIC`: `DT_NEEDED` names, RELA + JMPREL relocation
/// entries, and the symbol/string table VAs. `load_ranges` maps dynamic
/// table VAs back to file offsets for string/reloc decoding.
fn parse_dynamic(
    bytes: &[u8],
    dyn_offset: u64,
    dyn_size: u64,
    load_ranges: &[(u64, u64, u64)],
) -> Result<DynamicInfo, LoaderError> {
    const DT_NEEDED: i64 = 1;
    const DT_STRTAB: i64 = 5;
    const DT_SYMTAB: i64 = 6;
    const DT_RELA: i64 = 7;
    const DT_RELASZ: i64 = 8;
    const DT_JMPREL: i64 = 23;
    const DT_PLTRELSZ: i64 = 2;
    const DT_NULL: i64 = 0;

    let start = usize::try_from(dyn_offset).map_err(|_| LoaderError::TruncatedHeader)?;
    let size = usize::try_from(dyn_size).map_err(|_| LoaderError::TruncatedHeader)?;
    if start + size > bytes.len() {
        return Err(LoaderError::TruncatedHeader);
    }
    // VA → file offset through the PT_LOAD ranges.
    let va_to_off = |va: u64| -> Option<usize> {
        load_ranges
            .iter()
            .find(|(_, vaddr, filesz)| va >= *vaddr && va < vaddr + filesz)
            .and_then(|(off, vaddr, _)| usize::try_from(off + (va - *vaddr)).ok())
    };
    let mut needed_offs = Vec::new();
    let (mut strtab, mut symtab, mut rela_va, mut rela_sz, mut jmprel_va, mut jmprel_sz) =
        (0u64, 0u64, 0u64, 0u64, 0u64, 0u64);
    for i in 0..size / 16 {
        let e = start + i * 16;
        let tag = i64::from_le_bytes(bytes[e..e + 8].try_into().unwrap_or([0; 8]));
        let val = u64::from_le_bytes(bytes[e + 8..e + 16].try_into().unwrap_or([0; 8]));
        match tag {
            DT_NULL => break,
            DT_NEEDED => needed_offs.push(val),
            DT_STRTAB => strtab = val,
            DT_SYMTAB => symtab = val,
            DT_RELA => rela_va = val,
            DT_RELASZ => rela_sz = val,
            DT_JMPREL => jmprel_va = val,
            DT_PLTRELSZ => jmprel_sz = val,
            _ => {}
        }
    }
    // Resolve needed names through strtab.
    let str_off = va_to_off(strtab);
    let cstr = |off: usize| -> String {
        let end = bytes[off..]
            .iter()
            .position(|b| *b == 0)
            .map(|p| off + p)
            .unwrap_or(off);
        String::from_utf8_lossy(&bytes[off..end]).to_string()
    };
    let needed = needed_offs
        .iter()
        .filter_map(|o| str_off.map(|s| cstr(s + *o as usize)))
        .collect();
    // RELA entry: r_offset u64, r_info u64, r_addend i64.
    let read_rela = |va: u64, size: u64| -> Vec<RelaEntry> {
        let Some(off) = va_to_off(va) else {
            return Vec::new();
        };
        let count = (size / 24) as usize;
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let e = off + i * 24;
            if e + 24 > bytes.len() {
                break;
            }
            let r_offset = u64::from_le_bytes(bytes[e..e + 8].try_into().unwrap_or([0; 8]));
            let r_info = u64::from_le_bytes(bytes[e + 8..e + 16].try_into().unwrap_or([0; 8]));
            let addend = i64::from_le_bytes(bytes[e + 16..e + 24].try_into().unwrap_or([0; 8]));
            out.push(RelaEntry {
                offset: r_offset,
                r#type: (r_info & 0xFFFF_FFFF) as u32,
                symbol: (r_info >> 32) as u32,
                addend,
            });
        }
        out
    };
    Ok(DynamicInfo {
        needed,
        rela: read_rela(rela_va, rela_sz),
        jmprel: read_rela(jmprel_va, jmprel_sz),
        symtab,
        strtab,
    })
}

fn parse_symbol_table(bytes: &[u8]) -> Result<Vec<Symbol>, LoaderError> {
    // e_shoff (40..48), e_shentsize (58..60), e_shnum (60..62)
    let shoff = read_u64_le_at(bytes, 40)?;
    let shentsize = read_u16_le(bytes, 58)?;
    let shnum = read_u16_le(bytes, 60)?;
    if shoff == 0 || shnum == 0 || shentsize == 0 {
        return Ok(Vec::new());
    }
    if u64::from(shentsize) < ELF64_SECTION_HEADER_SIZE {
        return Err(LoaderError::TruncatedHeader);
    }

    let shoff_usize = usize::try_from(shoff).map_err(|_| LoaderError::TruncatedHeader)?;
    let shentsize_usize = usize::from(shentsize);
    let shnum_usize = usize::from(shnum);
    let table_bytes = shnum_usize
        .checked_mul(shentsize_usize)
        .ok_or(LoaderError::TruncatedHeader)?;
    let table_end = shoff_usize
        .checked_add(table_bytes)
        .ok_or(LoaderError::TruncatedHeader)?;
    if table_end > bytes.len() {
        return Err(LoaderError::TruncatedHeader);
    }

    // Locate the first SHT_SYMTAB section.
    let mut symtab: Option<(usize, usize, u64, usize)> = None;
    for index in 0..shnum_usize {
        // Bounded by `table_end`: header + 64 <= table_end <= bytes.len().
        let header = shoff_usize + index * shentsize_usize;
        let sh_type = read_u32_le(bytes, header + 4)?;
        if sh_type != SHT_SYMTAB {
            continue;
        }
        let sh_offset = read_u64_le_at(bytes, header + 24)?;
        let sh_size = read_u64_le_at(bytes, header + 32)?;
        let sh_link = read_u32_le(bytes, header + 40)?;
        let sh_entsize = read_u64_le_at(bytes, header + 56)?;
        symtab = Some((
            usize::try_from(sh_offset).map_err(|_| LoaderError::TruncatedHeader)?,
            usize::try_from(sh_size).map_err(|_| LoaderError::TruncatedHeader)?,
            sh_entsize,
            usize::try_from(sh_link).map_err(|_| LoaderError::TruncatedHeader)?,
        ));
        break;
    }
    let Some((sym_offset, sym_size, sym_entsize, strtab_index)) = symtab else {
        return Ok(Vec::new());
    };

    if strtab_index >= shnum_usize {
        return Err(LoaderError::TruncatedHeader);
    }
    let strtab_header = shoff_usize + strtab_index * shentsize_usize;
    let strtab_offset =
        usize::try_from(read_u64_le_at(bytes, strtab_header + 24)?).map_err(|_| LoaderError::TruncatedHeader)?;
    let strtab_size =
        usize::try_from(read_u64_le_at(bytes, strtab_header + 32)?).map_err(|_| LoaderError::TruncatedHeader)?;
    let strtab_end = strtab_offset
        .checked_add(strtab_size)
        .ok_or(LoaderError::TruncatedHeader)?;
    if strtab_end > bytes.len() {
        return Err(LoaderError::TruncatedHeader);
    }
    let strtab = bytes
        .get(strtab_offset..strtab_end)
        .ok_or(LoaderError::TruncatedHeader)?;

    let entsize = if sym_entsize == 0 {
        ELF64_SYMBOL_SIZE
    } else {
        sym_entsize
    };
    if entsize < ELF64_SYMBOL_SIZE {
        return Err(LoaderError::TruncatedHeader);
    }
    let entsize_usize = usize::try_from(entsize).map_err(|_| LoaderError::TruncatedHeader)?;
    let sym_end = sym_offset.checked_add(sym_size).ok_or(LoaderError::TruncatedHeader)?;
    if sym_end > bytes.len() {
        return Err(LoaderError::TruncatedHeader);
    }

    let entry_count = sym_size / entsize_usize;
    let mut symbols = Vec::new();
    for index in 0..entry_count {
        // Bounded by `sym_end`: entry + 24 <= sym_end <= bytes.len().
        let entry = sym_offset + index * entsize_usize;
        let st_name = read_u32_le(bytes, entry)?;
        let st_info = bytes.get(entry + 4).copied().ok_or(LoaderError::TruncatedHeader)?;
        let st_shndx = read_u16_le(bytes, entry + 6)?;
        let st_value = read_u64_le_at(bytes, entry + 8)?;
        let st_size = read_u64_le_at(bytes, entry + 16)?;

        let name_offset = usize::try_from(st_name).map_err(|_| LoaderError::TruncatedHeader)?;
        let name_bytes = strtab.get(name_offset..).ok_or(LoaderError::TruncatedHeader)?;
        let name_end = name_bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(name_bytes.len());
        if name_end == 0 {
            continue;
        }

        symbols.push(Symbol {
            name: String::from_utf8_lossy(&name_bytes[..name_end]).into_owned(),
            address: st_value,
            size: st_size,
            section_index: st_shndx,
            kind: st_info & 0x0f,
            binding: st_info >> 4,
        });
    }
    Ok(symbols)
}

/// Real 64-bit ELF image loader for x86-64 binaries.
///
/// Validates ELF headers and extracts all `PT_LOAD` segments, populating
/// execution permissions and memory bounds directly from program headers,
/// plus the static symbol table when present.
pub struct Elf64Loader {
    next_id: Mutex<u64>,
}

impl Elf64Loader {
    /// Creates a new `Elf64Loader` whose first assigned `ImageId` is `1`.
    pub fn new() -> Self {
        Self { next_id: Mutex::new(1) }
    }

    fn allocate_id(&self) -> Result<ImageId, LoaderError> {
        let mut guard = self.next_id.lock().unwrap_or_else(|e| e.into_inner());
        let id = ImageId(*guard);
        *guard = guard.checked_add(1).ok_or(LoaderError::Poisoned)?;
        Ok(id)
    }
}

impl Default for Elf64Loader {
    fn default() -> Self {
        Self::new()
    }
}

impl ImageLoader for Elf64Loader {
    type Error = LoaderError;

    fn load(&self, bytes: &[u8]) -> Result<LoadedImage, Self::Error> {
        if bytes.is_empty() {
            return Err(LoaderError::EmptyInput);
        }
        if bytes.len() < 4 || bytes[0..4] != ELF_MAGIC {
            return Err(LoaderError::InvalidFormat);
        }
        if bytes.len() < 64 {
            return Err(LoaderError::TruncatedHeader);
        }

        // EI_CLASS (offset 4): must be ELFCLASS64 (2)
        let class = bytes[4];
        if class != ELFCLASS64 {
            return Err(LoaderError::InvalidElfClass);
        }

        // EI_DATA (offset 5): must be ELFDATA2LSB (1)
        let data = bytes[5];
        if data != ELFDATA2LSB {
            return Err(LoaderError::InvalidFormat);
        }

        // EI_VERSION (offset 6): must be EV_CURRENT (1)
        let version = bytes[6];
        if version != EV_CURRENT {
            return Err(LoaderError::InvalidFormat);
        }

        // e_type (offset 16..18): ET_EXEC (2) or ET_DYN (3)
        let e_type = read_u16_le(bytes, 16)?;
        if e_type != ET_EXEC && e_type != ET_DYN {
            return Err(LoaderError::InvalidFormat);
        }

        // e_machine (offset 18..20): EM_X86_64 (62)
        let e_machine = read_u16_le(bytes, 18)?;
        if e_machine != EM_X86_64 {
            return Err(LoaderError::InvalidMachine);
        }

        // e_version (offset 20..24): EV_CURRENT (1)
        let e_version = read_u32_le(bytes, 20)?;
        if e_version != 1 {
            return Err(LoaderError::InvalidFormat);
        }

        // e_entry (offset 24..32)
        let e_entry = read_u64_le_at(bytes, 24)?;

        // e_phoff (offset 32..40)
        let e_phoff = read_u64_le_at(bytes, 32)?;

        // e_ehsize (offset 52..54)
        let e_ehsize = read_u16_le(bytes, 52)?;
        if e_ehsize < 64 {
            return Err(LoaderError::InvalidFormat);
        }

        // e_phentsize (offset 54..56)
        let e_phentsize = read_u16_le(bytes, 54)?;
        if e_phentsize < 56 {
            return Err(LoaderError::InvalidFormat);
        }

        // e_phnum (offset 56..58)
        let e_phnum = read_u16_le(bytes, 56)?;
        if e_phnum == 0 || e_phoff == 0 {
            return Err(LoaderError::NoProgramHeaders);
        }

        let phoff = usize::try_from(e_phoff).map_err(|_| LoaderError::TruncatedHeader)?;
        let phentsize = usize::from(e_phentsize);
        let phnum = usize::from(e_phnum);

        let ph_table_bytes = phnum.checked_mul(phentsize).ok_or(LoaderError::TruncatedHeader)?;
        let ph_table_end = phoff.checked_add(ph_table_bytes).ok_or(LoaderError::TruncatedHeader)?;
        if ph_table_end > bytes.len() {
            return Err(LoaderError::TruncatedHeader);
        }

        let mut segments = Vec::new();
        let mut load_ranges = Vec::new();
        let mut dynamic_range = None;

        for i in 0..phnum {
            let ph_offset = phoff
                .checked_add(i.checked_mul(phentsize).ok_or(LoaderError::TruncatedHeader)?)
                .ok_or(LoaderError::TruncatedHeader)?;
            let p_type = read_u32_le(bytes, ph_offset)?;
            let p_flags = read_u32_le(bytes, ph_offset + 4)?;
            let p_offset = read_u64_le_at(bytes, ph_offset + 8)?;
            let p_vaddr = read_u64_le_at(bytes, ph_offset + 16)?;
            let p_filesz = read_u64_le_at(bytes, ph_offset + 32)?;
            let p_memsz = read_u64_le_at(bytes, ph_offset + 40)?;

            if p_type == PT_DYNAMIC {
                dynamic_range = Some((p_offset, p_filesz));
            }
            if p_type == PT_LOAD {
                load_ranges.push((p_offset, p_vaddr, p_filesz));
                if p_memsz < p_filesz {
                    return Err(LoaderError::SegmentOutOfRange);
                }

                let seg_offset = usize::try_from(p_offset).map_err(|_| LoaderError::SegmentOutOfRange)?;
                let filesz = usize::try_from(p_filesz).map_err(|_| LoaderError::SegmentOutOfRange)?;
                let memsz = usize::try_from(p_memsz).map_err(|_| LoaderError::SegmentOutOfRange)?;

                let seg_end = seg_offset.checked_add(filesz).ok_or(LoaderError::SegmentOutOfRange)?;
                if seg_end > bytes.len() {
                    return Err(LoaderError::SegmentOutOfRange);
                }

                let slice = bytes.get(seg_offset..seg_end).ok_or(LoaderError::SegmentOutOfRange)?;
                let mut seg_bytes = slice.to_vec();
                if memsz > filesz {
                    let padding = memsz.saturating_sub(filesz);
                    seg_bytes.resize(seg_bytes.len().saturating_add(padding), 0);
                }

                segments.push(Segment {
                    address: p_vaddr,
                    bytes: seg_bytes,
                    readable: (p_flags & PF_R) != 0,
                    writable: (p_flags & PF_W) != 0,
                    executable: (p_flags & PF_X) != 0,
                });
            }
        }

        if segments.is_empty() {
            return Err(LoaderError::NoProgramHeaders);
        }

        let dynamic = dynamic_range.and_then(|(off, size)| parse_dynamic(bytes, off, size, &load_ranges).ok());

        let id = self.allocate_id()?;

        let ph_table_end = e_phoff.saturating_add(ph_table_bytes as u64);
        let program_headers = load_ranges
            .iter()
            .find(|(offset, _, filesz)| *offset <= e_phoff && ph_table_end <= offset.saturating_add(*filesz))
            .map(|(offset, vaddr, _)| ProgramHeadersInfo {
                address: vaddr + (e_phoff - *offset),
                entry_size: e_phentsize,
                count: e_phnum,
            });

        Ok(LoadedImage {
            id,
            entry: e_entry,
            target_profile: INTEL64_TARGET_PROFILE,
            segments,
            symbols: parse_symbol_table(bytes)?,
            program_headers,
            dynamic,
            pe: None,
        })
    }
}

// ---------------------------------------------------------------------------
// PE32+ (x86-64 Portable Executable) loader
// ---------------------------------------------------------------------------

const PE_MACHINE_AMD64: u16 = 0x8664;
const PE32PLUS_MAGIC: u16 = 0x20B;
const SECTION_EXEC: u32 = 0x2000_0000;
const SECTION_READ: u32 = 0x4000_0000;
const SECTION_WRITE: u32 = 0x8000_0000;
/// PE32+ optional-header offset of the `NumberOfRvaAndSizes` field.
const PE32PLUS_NUM_RVA_AND_SIZES: usize = 108;
/// PE32+ optional-header offset of the data-directory array.
const PE32PLUS_DATA_DIRS: usize = 112;
/// `IMAGE_DIRECTORY_ENTRY_IMPORT` — data-directory index of the import table.
const IMAGE_DIRECTORY_ENTRY_IMPORT: u32 = 1;
/// Size of one `IMAGE_IMPORT_DESCRIPTOR` (5 x u32) in bytes.
const PE_IMPORT_DESCRIPTOR_SIZE: usize = 20;
/// `IMAGE_ORDINAL_FLAG64`: PE32+ thunks with the high bit set are ordinal imports.
const PE_IMPORT_ORDINAL_FLAG: u64 = 0x8000_0000_0000_0000;
/// Maximum accepted import DLL-name length in bytes (excluding the NUL).
const PE_IMPORT_DLL_NAME_MAX: usize = 64;
/// `IMAGE_DIRECTORY_ENTRY_EXPORT` — data-directory index of the export table.
const IMAGE_DIRECTORY_ENTRY_EXPORT: u32 = 0;
/// Size of one `IMAGE_EXPORT_DIRECTORY` (10 fields, 40 bytes).
const PE_EXPORT_DIRECTORY_SIZE: usize = 40;

/// How a PE32+ import is resolved by the exporting DLL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PeImportKind {
    /// By-name import via `IMAGE_IMPORT_BY_NAME` (a hint plus an ASCIZ name) —
    /// the dominant case for e.g. ntoskrnl imports.
    Name(String),
    /// Ordinal import: the low 16 bits of the thunk.
    Ordinal(u16),
}

/// One imported function parsed from a PE32+ import directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeImport {
    /// Name of the DLL owning the import (ASCIZ from the descriptor's Name RVA).
    pub dll: String,
    /// Resolution kind: by-name or ordinal.
    pub kind: PeImportKind,
    /// RVA of the IAT slot for this import (`FirstThunk + 8*i` on PE32+) —
    /// the slot a loader must patch. Add the image base for a VA.
    pub iat_rva: u32,
}

/// One named export parsed from a PE32+ export directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeExport {
    /// Export name as recorded in the export name table (ASCIZ).
    pub name: String,
    /// RVA of the exported function/data. Add [`PeInfo::image_base`] for a
    /// virtual address. Forwarded exports are skipped at parse time.
    pub rva: u32,
    /// Absolute export ordinal (`OrdinalBase + index` into
    /// `AddressOfFunctions`), as `GetProcAddress` would report it.
    pub ordinal: u32,
}

/// PE32+ metadata parsed by [`Pe32Loader`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeInfo {
    /// Imports from `IMAGE_DIRECTORY_ENTRY_IMPORT` (directory index 1), in
    /// descriptor- then thunk-array order. Empty when the image declares no
    /// import directory. Delay imports (`IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT`)
    /// and bound imports (`IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT`) are out of
    /// scope and skipped — drivers rarely use them.
    pub imports: Vec<PeImport>,
    /// Named exports from `IMAGE_DIRECTORY_ENTRY_EXPORT` (directory index
    /// 0), in export-name-table order. Empty when the image declares no
    /// export directory. Ordinal-only exports (no name) are not enumerated.
    pub exports: Vec<PeExport>,
    /// `ImageBase` from the optional header — every segment address and
    /// [`LoadedImage::export_address`] result is relative to this.
    pub image_base: u64,
}

/// PE32+ image loader: maps each section at `image_base + VirtualAddress`
/// and resolves the entry point from the optional header. The import and
/// export directories are parsed into [`PeInfo`] (see
/// [`LoadedImage::pe_imports`] and [`LoadedImage::pe_exports`]); IAT
/// patching/import linking is out of scope — that is downstream work.
pub struct Pe32Loader {
    next_id: Mutex<u64>,
}

impl Pe32Loader {
    pub fn new() -> Self {
        Self { next_id: Mutex::new(1) }
    }
}

impl Default for Pe32Loader {
    fn default() -> Self {
        Self::new()
    }
}

impl ImageLoader for Pe32Loader {
    type Error = LoaderError;

    fn load(&self, bytes: &[u8]) -> Result<LoadedImage, Self::Error> {
        if bytes.is_empty() {
            return Err(LoaderError::EmptyInput);
        }
        // DOS header: 'MZ', e_lfanew at 0x3C.
        if bytes.len() < 0x40 || bytes[0] != 0x4D || bytes[1] != 0x5A {
            return Err(LoaderError::InvalidFormat);
        }
        let e_lfanew = read_u32_le(bytes, 0x3C)? as usize;
        if e_lfanew + 24 > bytes.len() {
            return Err(LoaderError::TruncatedHeader);
        }
        if bytes[e_lfanew..e_lfanew + 4] != [0x50, 0x45, 0, 0] {
            return Err(LoaderError::InvalidFormat);
        }
        let coff = e_lfanew + 4;
        let machine = read_u16_le(bytes, coff)?;
        if machine != PE_MACHINE_AMD64 {
            return Err(LoaderError::InvalidMachine);
        }
        let num_sections = read_u16_le(bytes, coff + 2)? as usize;
        let opt_size = read_u16_le(bytes, coff + 16)? as usize;
        let opt = coff + 20;
        if opt + opt_size > bytes.len() {
            return Err(LoaderError::TruncatedHeader);
        }
        let magic = read_u16_le(bytes, opt)?;
        if magic != PE32PLUS_MAGIC {
            return Err(LoaderError::InvalidFormat); // PE32 (32-bit) unsupported
        }
        let entry_rva = read_u32_le(bytes, opt + 16)? as u64;
        let image_base = read_u64_le_at(bytes, opt + 24)?;

        // Sections start right after the optional header.
        let sec_base = opt + opt_size;
        let mut segments = Vec::with_capacity(num_sections);
        // (VirtualAddress, raw size, raw pointer) per section, for RVA -> file
        // offset translation while parsing the import directory.
        let mut file_ranges: Vec<(u32, u32, u32)> = Vec::with_capacity(num_sections);
        for i in 0..num_sections {
            let off = sec_base + i * 40;
            if off + 40 > bytes.len() {
                return Err(LoaderError::TruncatedHeader);
            }
            let virtual_size = read_u32_le(bytes, off + 8)? as u64;
            let va = read_u32_le(bytes, off + 12)?;
            let raw_size = read_u32_le(bytes, off + 16)? as usize;
            let raw_ptr = read_u32_le(bytes, off + 20)? as usize;
            let characteristics = read_u32_le(bytes, off + 36)?;
            if raw_ptr + raw_size > bytes.len() {
                return Err(LoaderError::SegmentOutOfRange);
            }
            file_ranges.push((va, raw_size as u32, raw_ptr as u32));
            // Section data is raw_size bytes on disk, virtual_size in memory
            // (bss-style tail zero-fills).
            let mut data = bytes[raw_ptr..raw_ptr + raw_size].to_vec();
            let vsize =
                usize::try_from(virtual_size.max(raw_size as u64)).map_err(|_| LoaderError::SegmentOutOfRange)?;
            data.resize(vsize, 0);
            segments.push(Segment {
                address: image_base + u64::from(va),
                bytes: data,
                readable: characteristics & SECTION_READ != 0,
                writable: characteristics & SECTION_WRITE != 0,
                executable: characteristics & SECTION_EXEC != 0,
            });
        }
        if segments.is_empty() {
            return Err(LoaderError::NoProgramHeaders);
        }
        let pe = Some(PeInfo {
            imports: parse_pe_imports(bytes, opt, opt_size, &file_ranges)?,
            exports: parse_pe_exports(bytes, opt, opt_size, &file_ranges)?,
            image_base,
        });
        Ok(LoadedImage {
            id: {
                let mut g = self.next_id.lock().unwrap_or_else(|e| e.into_inner());
                let id = ImageId(*g);
                *g = g.checked_add(1).ok_or(LoaderError::Poisoned)?;
                id
            },
            entry: image_base + entry_rva,
            target_profile: TargetProfileId(1),
            segments,
            symbols: Vec::new(),
            program_headers: None,
            dynamic: None,
            pe,
        })
    }
}

/// RVA → file-offset translation through the section table's raw ranges.
/// Below `SizeOfHeaders` the image maps the file header identically. Shared
/// by the import- and export-directory parsers.
fn pe_rva_to_file(rva: u32, file_ranges: &[(u32, u32, u32)], size_of_headers: usize) -> Option<usize> {
    let rva = usize::try_from(rva).unwrap_or(usize::MAX);
    for &(va, raw_size, raw_ptr) in file_ranges {
        let (va, raw_size, raw_ptr) = (
            usize::try_from(va).unwrap_or(usize::MAX),
            usize::try_from(raw_size).unwrap_or(0),
            usize::try_from(raw_ptr).unwrap_or(usize::MAX),
        );
        if rva >= va && rva.saturating_sub(va) < raw_size {
            return raw_ptr.checked_add(rva - va);
        }
    }
    (rva < size_of_headers).then_some(rva)
}

/// Parses the PE32+ import directory (`IMAGE_DIRECTORY_ENTRY_IMPORT`, index
/// 1) into an ordered import list.
///
/// Behavior:
/// - No data directories, fewer than two of them, or a null import-directory
///   RVA yields an empty list (an image without imports is not an error).
/// - Descriptors are 20 bytes each; an all-zero descriptor terminates.
/// - Thunks are `u64` on PE32+. High bit set → ordinal (low 16 bits); otherwise
///   the value is an RVA to `IMAGE_IMPORT_BY_NAME` (u16 hint, then ASCIZ name).
///   The IAT slot for import `i` is `FirstThunk + 8*i`.
/// - When `OriginalFirstThunk` is zero (legacy/bound images) the thunks are
///   read through `FirstThunk`.
/// - All RVAs must resolve inside the file-backed image; every read is
///   bounds-checked and malformed data fails closed with
///   [`LoaderError::TruncatedImportTable`].
/// - DLL names are ASCIZ with a hard 64-byte cap ([`PE_IMPORT_DLL_NAME_MAX`])
///   enforced via [`LoaderError::ImportDllNameTooLong`].
/// - Delay imports and bound imports live in other data directories and are
///   skipped.
fn parse_pe_imports(
    bytes: &[u8],
    opt: usize,
    opt_size: usize,
    file_ranges: &[(u32, u32, u32)],
) -> Result<Vec<PeImport>, LoaderError> {
    if opt_size < PE32PLUS_DATA_DIRS {
        // Optional header too small to carry data directories: no imports.
        return Ok(Vec::new());
    }
    let num_dirs = read_u32_le(bytes, opt + PE32PLUS_NUM_RVA_AND_SIZES)?;
    if num_dirs <= IMAGE_DIRECTORY_ENTRY_IMPORT {
        // Import directory not declared: no imports.
        return Ok(Vec::new());
    }
    let dir_va_field = PE32PLUS_DATA_DIRS + 8 * IMAGE_DIRECTORY_ENTRY_IMPORT as usize;
    if opt_size < dir_va_field + 4 {
        // Declared but the optional header is too small to hold it.
        return Err(LoaderError::TruncatedImportTable);
    }
    let dir_rva = read_u32_le(bytes, opt + dir_va_field)?;
    if dir_rva == 0 {
        return Ok(Vec::new());
    }
    let size_of_headers = usize::try_from(read_u32_le(bytes, opt + 60)?).unwrap_or(0);
    let rva_to_file = |rva: u32| pe_rva_to_file(rva, file_ranges, size_of_headers);

    let mut imports = Vec::new();
    let mut desc_off = rva_to_file(dir_rva).ok_or(LoaderError::TruncatedImportTable)?;
    loop {
        let desc_end = desc_off
            .checked_add(PE_IMPORT_DESCRIPTOR_SIZE)
            .ok_or(LoaderError::TruncatedImportTable)?;
        let descriptor = bytes.get(desc_off..desc_end).ok_or(LoaderError::TruncatedImportTable)?;
        if descriptor.iter().all(|&byte| byte == 0) {
            break; // All-zero terminator.
        }
        let original_first_thunk = read_u32_le(bytes, desc_off)?;
        let name_rva = read_u32_le(bytes, desc_off + 12)?;
        let first_thunk = read_u32_le(bytes, desc_off + 16)?;
        if name_rva == 0 || (original_first_thunk == 0 && first_thunk == 0) {
            // Non-terminator descriptor without a name or any thunk table.
            return Err(LoaderError::TruncatedImportTable);
        }
        let dll = {
            let name_off = rva_to_file(name_rva).ok_or(LoaderError::TruncatedImportTable)?;
            let (dll, len) = read_pe_asciz(bytes, name_off).map_err(|_| LoaderError::TruncatedImportTable)?;
            if len > PE_IMPORT_DLL_NAME_MAX {
                return Err(LoaderError::ImportDllNameTooLong);
            }
            dll
        };

        // Legacy/bound images leave OriginalFirstThunk zero and keep the
        // thunks in the IAT itself.
        let thunk_rva = if original_first_thunk != 0 {
            original_first_thunk
        } else {
            first_thunk
        };
        let mut index: u32 = 0;
        loop {
            let slot = thunk_rva
                .checked_add(index.checked_mul(8).ok_or(LoaderError::TruncatedImportTable)?)
                .ok_or(LoaderError::TruncatedImportTable)?;
            let thunk_off = rva_to_file(slot).ok_or(LoaderError::TruncatedImportTable)?;
            let thunk = read_u64_le_at(bytes, thunk_off).map_err(|_| LoaderError::TruncatedImportTable)?;
            if thunk == 0 {
                break; // End of the thunk array.
            }
            let iat_rva = first_thunk
                .checked_add(index.checked_mul(8).ok_or(LoaderError::TruncatedImportTable)?)
                .ok_or(LoaderError::TruncatedImportTable)?;
            let kind = if thunk & PE_IMPORT_ORDINAL_FLAG != 0 {
                PeImportKind::Ordinal((thunk & 0xFFFF) as u16)
            } else {
                // PE32+ thunks carry a 32-bit RVA; the hint is a u16 at +0
                // and the ASCIZ name starts at +2.
                let by_name_rva = (thunk & 0xFFFF_FFFF) as u32;
                let by_name_off = rva_to_file(by_name_rva).ok_or(LoaderError::TruncatedImportTable)?;
                let name_off = by_name_off.checked_add(2).ok_or(LoaderError::TruncatedImportTable)?;
                let (name, _) = read_pe_asciz(bytes, name_off).map_err(|_| LoaderError::TruncatedImportTable)?;
                PeImportKind::Name(name)
            };
            imports.push(PeImport {
                dll: dll.clone(),
                kind,
                iat_rva,
            });
            index = index.checked_add(1).ok_or(LoaderError::TruncatedImportTable)?;
        }
        desc_off = desc_end;
    }
    Ok(imports)
}

/// Parses the PE32+ export directory (`IMAGE_DIRECTORY_ENTRY_EXPORT`, index
/// 0) into an ordered list of named [`PeExport`]s.
///
/// Behavior:
/// - No data directories, fewer than one of them, or a null export-directory
///   RVA yields an empty list (an image without exports is not an error).
/// - The `IMAGE_EXPORT_DIRECTORY` drives three parallel arrays:
///   `AddressOfFunctions` (u32 RVA per function), `AddressOfNames` (u32 RVA
///   per name), and `AddressOfNameOrdinals` (u16 index into the function
///   array per name). A name whose ordinal index lands past the function
///   table fails closed with [`LoaderError::TruncatedExportTable`].
/// - Forwarded exports — a function RVA pointing inside the export directory
///   itself — resolve in another module and are skipped.
/// - Ordinal-only exports (function-table entries without a name-table
///   entry) are not enumerated.
/// - All RVAs must resolve inside the file-backed image; every read is
///   bounds-checked and malformed data fails closed with
///   [`LoaderError::TruncatedExportTable`].
fn parse_pe_exports(
    bytes: &[u8],
    opt: usize,
    opt_size: usize,
    file_ranges: &[(u32, u32, u32)],
) -> Result<Vec<PeExport>, LoaderError> {
    if opt_size < PE32PLUS_DATA_DIRS {
        // Optional header too small to carry data directories: no exports.
        return Ok(Vec::new());
    }
    let num_dirs = read_u32_le(bytes, opt + PE32PLUS_NUM_RVA_AND_SIZES)?;
    // Index 0 is the lowest directory, so "not declared" is exactly zero.
    if num_dirs == IMAGE_DIRECTORY_ENTRY_EXPORT {
        // Export directory not declared: no exports.
        return Ok(Vec::new());
    }
    let dir_va_field = PE32PLUS_DATA_DIRS + 8 * IMAGE_DIRECTORY_ENTRY_EXPORT as usize;
    if opt_size < dir_va_field + 8 {
        // Declared but the optional header is too small to hold it.
        return Err(LoaderError::TruncatedExportTable);
    }
    let dir_rva = read_u32_le(bytes, opt + dir_va_field)?;
    let dir_size = read_u32_le(bytes, opt + dir_va_field + 4)?;
    if dir_rva == 0 {
        return Ok(Vec::new());
    }
    let size_of_headers = usize::try_from(read_u32_le(bytes, opt + 60)?).unwrap_or(0);
    let rva_to_file = |rva: u32| pe_rva_to_file(rva, file_ranges, size_of_headers);

    let dir_off = rva_to_file(dir_rva).ok_or(LoaderError::TruncatedExportTable)?;
    let dir_end = dir_off
        .checked_add(PE_EXPORT_DIRECTORY_SIZE)
        .ok_or(LoaderError::TruncatedExportTable)?;
    bytes.get(dir_off..dir_end).ok_or(LoaderError::TruncatedExportTable)?;
    let ordinal_base = read_u32_le(bytes, dir_off + 0x10)?;
    let number_of_functions = read_u32_le(bytes, dir_off + 0x14)?;
    let number_of_names = read_u32_le(bytes, dir_off + 0x18)?;
    let functions_rva = read_u32_le(bytes, dir_off + 0x1C)?;
    let names_rva = read_u32_le(bytes, dir_off + 0x20)?;
    let ordinals_rva = read_u32_le(bytes, dir_off + 0x24)?;
    if number_of_functions == 0 || number_of_names == 0 || functions_rva == 0 || names_rva == 0 || ordinals_rva == 0 {
        // Degenerate directory: nothing name-resolvable to enumerate.
        return Ok(Vec::new());
    }

    // Function-RVA table, read once; every name entry indexes into it.
    let functions_off = rva_to_file(functions_rva).ok_or(LoaderError::TruncatedExportTable)?;
    let max_possible = (bytes.len().saturating_sub(functions_off)) / 4;
    let capacity = (number_of_functions as usize).min(max_possible).min(65536);
    let mut function_rvas = Vec::with_capacity(capacity);
    for index in 0..number_of_functions as usize {
        let entry = functions_off
            .checked_add(index.checked_mul(4).ok_or(LoaderError::TruncatedExportTable)?)
            .ok_or(LoaderError::TruncatedExportTable)?;
        let rva = read_u32_le(bytes, entry).map_err(|_| LoaderError::TruncatedExportTable)?;
        function_rvas.push(rva);
    }

    let names_off = rva_to_file(names_rva).ok_or(LoaderError::TruncatedExportTable)?;
    let ordinals_off = rva_to_file(ordinals_rva).ok_or(LoaderError::TruncatedExportTable)?;
    let mut exports = Vec::new();
    for index in 0..number_of_names as usize {
        let name_ptr = names_off
            .checked_add(index.checked_mul(4).ok_or(LoaderError::TruncatedExportTable)?)
            .ok_or(LoaderError::TruncatedExportTable)?;
        let name_rva = read_u32_le(bytes, name_ptr).map_err(|_| LoaderError::TruncatedExportTable)?;
        let name_off = rva_to_file(name_rva).ok_or(LoaderError::TruncatedExportTable)?;
        let (name, _) = read_pe_asciz(bytes, name_off).map_err(|_| LoaderError::TruncatedExportTable)?;

        let ordinal_slot = ordinals_off
            .checked_add(index.checked_mul(2).ok_or(LoaderError::TruncatedExportTable)?)
            .ok_or(LoaderError::TruncatedExportTable)?;
        let ordinal_index =
            usize::from(read_u16_le(bytes, ordinal_slot).map_err(|_| LoaderError::TruncatedExportTable)?);
        if ordinal_index >= function_rvas.len() {
            // Name entry indexing past the function table: malformed.
            return Err(LoaderError::TruncatedExportTable);
        }
        let rva = function_rvas[ordinal_index];
        // A function RVA inside the export directory itself is a forwarder
        // string ("OTHER.dll.Symbol"), not code in this image — skip it.
        if rva >= dir_rva && rva < dir_rva.saturating_add(dir_size) {
            continue;
        }
        exports.push(PeExport {
            name,
            rva,
            ordinal: ordinal_base.wrapping_add(ordinal_index as u32),
        });
    }
    Ok(exports)
}

/// Reads an ASCIZ string at `off`, returning it together with its byte length
/// (excluding the NUL). Fails when `off` is out of range or the NUL
/// terminator is missing before the end of the buffer; callers map the
/// failure onto their directory-specific truncation error.
fn read_pe_asciz(bytes: &[u8], off: usize) -> Result<(String, usize), ()> {
    let rest = bytes.get(off..).ok_or(())?;
    let nul = rest.iter().position(|&byte| byte == 0).ok_or(())?;
    Ok((String::from_utf8_lossy(&rest[..nul]).into_owned(), nul))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a valid 16-byte header followed by `payload`.
    fn make_image(entry: u64, profile: u64, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + payload.len());
        out.extend_from_slice(&entry.to_le_bytes());
        out.extend_from_slice(&profile.to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    #[test]
    fn load_valid_image_produces_correct_entry_profile_segments() {
        let loader = InMemoryImageLoader::new();
        let payload = [0xAA, 0xBB, 0xCC];
        let bytes = make_image(0xDEADBEEF, 0x42, &payload);

        let result = loader.load(&bytes);
        assert!(result.is_ok(), "valid image should load");
        let image = match result {
            Ok(ref img) => img,
            Err(_) => return,
        };
        assert_eq!(image.id, ImageId(1));
        assert_eq!(image.entry, 0xDEADBEEF);
        assert_eq!(image.target_profile, TargetProfileId(0x42));
        assert_eq!(image.segments.len(), 1);
        let seg = &image.segments[0];
        assert_eq!(seg.address, 0x1000);
        assert_eq!(seg.bytes, payload);
        assert!(seg.readable);
        assert!(!seg.writable);
        assert!(seg.executable);
    }

    #[test]
    fn load_empty_input_errors() {
        let loader = InMemoryImageLoader::new();
        let result = loader.load(&[]);
        assert!(result.is_err());
        assert_eq!(result.err(), Some(LoaderError::EmptyInput));
    }

    #[test]
    fn load_too_short_input_errors() {
        let loader = InMemoryImageLoader::new();
        // Non-empty but fewer than 16 bytes.
        let result = loader.load(&[0u8; 8]);
        assert!(result.is_err());
        assert_eq!(result.err(), Some(LoaderError::InvalidFormat));
    }

    #[test]
    fn sequential_image_ids_increment() {
        let loader = InMemoryImageLoader::new();
        let bytes = make_image(1, 2, &[0xFF]);

        let first = loader.load(&bytes);
        let second = loader.load(&bytes);
        let third = loader.load(&bytes);

        assert!(first.is_ok());
        assert!(second.is_ok());
        assert!(third.is_ok());

        let first_id = match first {
            Ok(ref img) => img.id,
            Err(_) => return,
        };
        let second_id = match second {
            Ok(ref img) => img.id,
            Err(_) => return,
        };
        let third_id = match third {
            Ok(ref img) => img.id,
            Err(_) => return,
        };
        assert_eq!(first_id, ImageId(1));
        assert_eq!(second_id, ImageId(2));
        assert_eq!(third_id, ImageId(3));
    }

    #[test]
    fn state_importer_accepts_static_binary() {
        let importer = InMemoryStateImporter::new();
        let result = importer.import(ImportKind::StaticBinary, b"static");
        assert!(result.is_ok());
        assert_eq!(result.ok(), Some(b"static".to_vec()));
    }

    #[test]
    fn state_importer_accepts_snapshot() {
        let importer = InMemoryStateImporter::new();
        let result = importer.import(ImportKind::Snapshot, b"snap");
        assert!(result.is_ok());
        assert_eq!(result.ok(), Some(b"snap".to_vec()));
    }

    #[test]
    fn state_importer_accepts_checkpoint() {
        let importer = InMemoryStateImporter::new();
        let result = importer.import(ImportKind::Checkpoint, b"ckpt");
        assert!(result.is_ok());
        assert_eq!(result.ok(), Some(b"ckpt".to_vec()));
    }

    #[test]
    fn state_importer_rejects_live_process_capture() {
        let importer = InMemoryStateImporter::new();
        let result = importer.import(ImportKind::LiveProcessCapture, b"live");
        assert!(result.is_err());
        assert_eq!(result.err(), Some(LoaderError::UnsupportedKind));
    }

    #[test]
    fn round_trip_load_image_then_import_as_snapshot() {
        let loader = InMemoryImageLoader::new();
        let importer = InMemoryStateImporter::new();

        let payload = [0x10, 0x20, 0x30, 0x40];
        let bytes = make_image(0x100, 0x200, &payload);

        let image_result = loader.load(&bytes);
        assert!(image_result.is_ok());
        let image = match image_result {
            Ok(ref img) => img,
            Err(_) => return,
        };

        // Serialize the loaded image's segment back into a snapshot blob.
        let snapshot_blob: Vec<u8> = image.segments.iter().flat_map(|s| s.bytes.iter().copied()).collect();

        let import_result = importer.import(ImportKind::Snapshot, &snapshot_blob);
        assert!(import_result.is_ok());
        assert_eq!(import_result.ok(), Some(payload.to_vec()));
    }

    #[test]
    fn loader_error_display_is_human_readable() {
        assert_eq!(format!("{}", LoaderError::EmptyInput), "input buffer is empty");
        assert_eq!(format!("{}", LoaderError::InvalidFormat), "input has an invalid format");
        assert_eq!(format!("{}", LoaderError::UnsupportedKind), "unsupported import kind");
        assert_eq!(format!("{}", LoaderError::Poisoned), "internal state is poisoned");
        assert_eq!(format!("{}", LoaderError::TruncatedHeader), "truncated ELF header");
        assert_eq!(
            format!("{}", LoaderError::InvalidElfClass),
            "invalid ELF class (expected 64-bit)"
        );
        assert_eq!(
            format!("{}", LoaderError::InvalidMachine),
            "invalid machine architecture (expected x86-64)"
        );
        assert_eq!(format!("{}", LoaderError::NoProgramHeaders), "no program headers found");
        assert_eq!(
            format!("{}", LoaderError::SegmentOutOfRange),
            "segment offset or size is out of range"
        );
        assert_eq!(
            format!("{}", LoaderError::TruncatedImportTable),
            "PE import table is truncated or out of range"
        );
        assert_eq!(
            format!("{}", LoaderError::ImportDllNameTooLong),
            "PE import DLL name exceeds 64 characters"
        );
    }

    #[test]
    fn loader_default_equals_new() {
        let a = InMemoryImageLoader::default();
        let b = InMemoryImageLoader::new();
        // Both should start assigning from id 1.
        let bytes = make_image(0, 0, &[]);
        assert_eq!(a.load(&bytes).ok().map(|i| i.id), Some(ImageId(1)));
        assert_eq!(b.load(&bytes).ok().map(|i| i.id), Some(ImageId(1)));
    }

    fn make_elf64_binary(entry: u64, is_pie: bool, segments: &[(u32, u64, u64, &[u8])]) -> Vec<u8> {
        let ehdr_size = 64usize;
        let phdr_size = 56usize;
        let phnum = segments.len();
        let phoff = ehdr_size;
        let file_data_offset = ehdr_size.saturating_add(phnum.saturating_mul(phdr_size));

        let mut binary = Vec::new();
        // 0..4: magic
        binary.extend_from_slice(&[0x7f, b'E', b'L', b'F']);
        // 4: class = 2 (64-bit)
        binary.push(2);
        // 5: data = 1 (LSB)
        binary.push(1);
        // 6: version = 1
        binary.push(1);
        // 7..16: padding
        binary.extend_from_slice(&[0u8; 9]);
        // 16..18: e_type (2 = ET_EXEC, 3 = ET_DYN)
        let e_type = if is_pie { 3u16 } else { 2u16 };
        binary.extend_from_slice(&e_type.to_le_bytes());
        // 18..20: e_machine = EM_X86_64 (62)
        binary.extend_from_slice(&62u16.to_le_bytes());
        // 20..24: e_version = 1
        binary.extend_from_slice(&1u32.to_le_bytes());
        // 24..32: e_entry
        binary.extend_from_slice(&entry.to_le_bytes());
        // 32..40: e_phoff
        binary.extend_from_slice(&(phoff as u64).to_le_bytes());
        // 40..48: e_shoff = 0
        binary.extend_from_slice(&0u64.to_le_bytes());
        // 48..52: e_flags = 0
        binary.extend_from_slice(&0u32.to_le_bytes());
        // 52..54: e_ehsize = 64
        binary.extend_from_slice(&(ehdr_size as u16).to_le_bytes());
        // 54..56: e_phentsize = 56
        binary.extend_from_slice(&(phdr_size as u16).to_le_bytes());
        // 56..58: e_phnum
        binary.extend_from_slice(&(phnum as u16).to_le_bytes());
        // 58..60: e_shentsize = 0
        binary.extend_from_slice(&0u16.to_le_bytes());
        // 60..62: e_shnum = 0
        binary.extend_from_slice(&0u16.to_le_bytes());
        // 62..64: e_shstrndx = 0
        binary.extend_from_slice(&0u16.to_le_bytes());

        let mut current_offset = file_data_offset;
        let mut phdr_bytes = Vec::new();
        let mut payload_bytes = Vec::new();

        for &(p_flags, p_vaddr, p_memsz, payload) in segments {
            let p_offset = current_offset as u64;
            let p_filesz = payload.len() as u64;
            let memsz = if p_memsz < p_filesz { p_filesz } else { p_memsz };

            // p_type: PT_LOAD (1)
            phdr_bytes.extend_from_slice(&1u32.to_le_bytes());
            // p_flags
            phdr_bytes.extend_from_slice(&p_flags.to_le_bytes());
            // p_offset
            phdr_bytes.extend_from_slice(&p_offset.to_le_bytes());
            // p_vaddr
            phdr_bytes.extend_from_slice(&p_vaddr.to_le_bytes());
            // p_paddr = p_vaddr
            phdr_bytes.extend_from_slice(&p_vaddr.to_le_bytes());
            // p_filesz
            phdr_bytes.extend_from_slice(&p_filesz.to_le_bytes());
            // p_memsz
            phdr_bytes.extend_from_slice(&memsz.to_le_bytes());
            // p_align = 0x1000
            phdr_bytes.extend_from_slice(&0x1000u64.to_le_bytes());

            payload_bytes.extend_from_slice(payload);
            current_offset = current_offset.saturating_add(payload.len());
        }

        binary.extend_from_slice(&phdr_bytes);
        binary.extend_from_slice(&payload_bytes);
        binary
    }

    #[test]
    fn elf64_loads_valid_binary() {
        let loader = Elf64Loader::new();
        let payload = [0xB8, 0x3C, 0x00, 0x00, 0x00, 0x0F, 0x05]; // mov eax, 60; syscall
        let elf = make_elf64_binary(0x401000, false, &[(5, 0x401000, payload.len() as u64, &payload)]);

        let result = loader.load(&elf);
        assert!(result.is_ok(), "valid ELF64 should load");
        let image = match result {
            Ok(ref img) => img,
            Err(_) => return,
        };

        assert_eq!(image.id, ImageId(1));
        assert_eq!(image.entry, 0x401000);
        assert_eq!(image.target_profile, INTEL64_TARGET_PROFILE);
        assert_eq!(image.segments.len(), 1);

        let seg = &image.segments[0];
        assert_eq!(seg.address, 0x401000);
        assert_eq!(seg.bytes, payload);
        assert!(seg.readable);
        assert!(!seg.writable);
        assert!(seg.executable);
    }

    /// Appends a `.strtab` + `.symtab` + section header table to a
    /// program-header-only ELF and patches the ELF header to reference it.
    fn append_symbol_table(binary: &mut Vec<u8>, symbols: &[(&str, u64, u64, u8)]) {
        let mut strtab = vec![0u8];
        let mut name_offsets = Vec::with_capacity(symbols.len());
        for (name, _, _, _) in symbols {
            name_offsets.push(strtab.len() as u32);
            strtab.extend_from_slice(name.as_bytes());
            strtab.push(0);
        }

        let mut symtab = vec![0u8; 24];
        for (index, (_, address, size, info)) in symbols.iter().enumerate() {
            symtab.extend_from_slice(&name_offsets[index].to_le_bytes());
            symtab.push(*info);
            symtab.push(0);
            symtab.extend_from_slice(&1u16.to_le_bytes());
            symtab.extend_from_slice(&address.to_le_bytes());
            symtab.extend_from_slice(&size.to_le_bytes());
        }

        let strtab_offset = binary.len() as u64;
        binary.extend_from_slice(&strtab);
        let symtab_offset = binary.len() as u64;
        binary.extend_from_slice(&symtab);
        let shoff = binary.len() as u64;

        // NULL section header.
        binary.extend_from_slice(&[0u8; 64]);
        // .strtab section header (SHT_STRTAB = 3).
        let mut strtab_header = vec![0u8; 64];
        strtab_header[4..8].copy_from_slice(&3u32.to_le_bytes());
        strtab_header[24..32].copy_from_slice(&strtab_offset.to_le_bytes());
        strtab_header[32..40].copy_from_slice(&(strtab.len() as u64).to_le_bytes());
        strtab_header[48..56].copy_from_slice(&1u64.to_le_bytes());
        binary.extend_from_slice(&strtab_header);
        // .symtab section header (SHT_SYMTAB = 2, sh_link = 1 -> .strtab).
        let mut symtab_header = vec![0u8; 64];
        symtab_header[4..8].copy_from_slice(&2u32.to_le_bytes());
        symtab_header[24..32].copy_from_slice(&symtab_offset.to_le_bytes());
        symtab_header[32..40].copy_from_slice(&(symtab.len() as u64).to_le_bytes());
        symtab_header[40..44].copy_from_slice(&1u32.to_le_bytes());
        symtab_header[48..56].copy_from_slice(&1u64.to_le_bytes());
        symtab_header[56..64].copy_from_slice(&24u64.to_le_bytes());
        binary.extend_from_slice(&symtab_header);

        // e_shoff, e_shentsize, e_shnum, e_shstrndx.
        binary[40..48].copy_from_slice(&shoff.to_le_bytes());
        binary[58..60].copy_from_slice(&64u16.to_le_bytes());
        binary[60..62].copy_from_slice(&3u16.to_le_bytes());
        binary[62..64].copy_from_slice(&0u16.to_le_bytes());
    }

    #[test]
    fn elf64_parses_static_symbol_table() {
        let loader = Elf64Loader::new();
        let payload = [0x90, 0xC3];
        let mut elf = make_elf64_binary(0x401000, false, &[(5, 0x401000, payload.len() as u64, &payload)]);
        append_symbol_table(
            &mut elf,
            &[
                ("_start", 0x401000, 2, 0x12),  // global function
                ("counter", 0x600000, 8, 0x11), // global object
                ("helper", 0x401002, 4, 0x02),  // local function
            ],
        );

        let result = loader.load(&elf);
        assert!(result.is_ok(), "ELF with symbol table should load");
        let image = match result {
            Ok(ref img) => img,
            Err(_) => return,
        };

        assert_eq!(image.symbols.len(), 3);
        let start = match image.symbol("_start") {
            Some(symbol) => symbol,
            None => return,
        };
        assert_eq!(start.address, 0x401000);
        assert_eq!(start.size, 2);
        assert!(start.is_function());
        assert_eq!(start.binding, 1);

        let counter = match image.symbol("counter") {
            Some(symbol) => symbol,
            None => return,
        };
        assert_eq!(counter.address, 0x600000);
        assert_eq!(counter.size, 8);
        assert_eq!(counter.kind, STT_OBJECT);

        let helper = match image.symbol("helper") {
            Some(symbol) => symbol,
            None => return,
        };
        assert_eq!(helper.address, 0x401002);
        assert_eq!(helper.binding, 0);
    }

    #[test]
    fn elf64_without_sections_has_no_symbols() {
        let loader = Elf64Loader::new();
        let elf = make_elf64_binary(0x401000, false, &[(5, 0x401000, 1, &[0xC3])]);

        let result = loader.load(&elf);
        assert!(result.is_ok());
        let image = match result {
            Ok(ref img) => img,
            Err(_) => return,
        };
        assert!(image.symbols.is_empty());
    }

    #[test]
    fn elf64_rejects_out_of_range_section_table() {
        let loader = Elf64Loader::new();
        let mut elf = make_elf64_binary(0x401000, false, &[(5, 0x401000, 1, &[0xC3])]);
        let bogus_shoff = (elf.len() as u64) + 0x1000;
        elf[40..48].copy_from_slice(&bogus_shoff.to_le_bytes());
        elf[58..60].copy_from_slice(&64u16.to_le_bytes());
        elf[60..62].copy_from_slice(&1u16.to_le_bytes());

        let result = loader.load(&elf);
        assert_eq!(result.err(), Some(LoaderError::TruncatedHeader));
    }

    #[test]
    fn elf64_loads_multi_segment_binary() {
        let loader = Elf64Loader::new();
        let code_payload = [0x90, 0x90, 0xC3]; // nop, nop, ret
        let data_payload = [0x42, 0x43, 0x44, 0x45];
        let elf = make_elf64_binary(
            0x400000,
            false,
            &[
                (5, 0x400000, code_payload.len() as u64, &code_payload), // R-X
                (6, 0x600000, data_payload.len() as u64, &data_payload), // RW-
            ],
        );

        let result = loader.load(&elf);
        assert!(result.is_ok());
        let image = match result {
            Ok(ref img) => img,
            Err(_) => return,
        };

        assert_eq!(image.entry, 0x400000);
        assert_eq!(image.segments.len(), 2);

        let code_seg = &image.segments[0];
        assert_eq!(code_seg.address, 0x400000);
        assert_eq!(code_seg.bytes, code_payload);
        assert!(code_seg.readable);
        assert!(!code_seg.writable);
        assert!(code_seg.executable);

        let data_seg = &image.segments[1];
        assert_eq!(data_seg.address, 0x600000);
        assert_eq!(data_seg.bytes, data_payload);
        assert!(data_seg.readable);
        assert!(data_seg.writable);
        assert!(!data_seg.executable);
    }

    #[test]
    fn elf64_loads_pie_binary_preserving_relative_entry() {
        let loader = Elf64Loader::new();
        let payload = [0xC3];
        let elf = make_elf64_binary(0x1050, true, &[(5, 0x1000, payload.len() as u64, &payload)]);

        let result = loader.load(&elf);
        assert!(result.is_ok());
        let image = match result {
            Ok(ref img) => img,
            Err(_) => return,
        };
        assert_eq!(image.entry, 0x1050);
    }

    #[test]
    fn elf64_zero_pads_bss_segment() {
        let loader = Elf64Loader::new();
        let payload = [0x11, 0x22];
        // memsz is 6, filesz is 2 => 4 extra zero bytes expected
        let elf = make_elf64_binary(0x401000, false, &[(6, 0x401000, 6, &payload)]);

        let result = loader.load(&elf);
        assert!(result.is_ok());
        let image = match result {
            Ok(ref img) => img,
            Err(_) => return,
        };

        let seg = &image.segments[0];
        assert_eq!(seg.bytes.len(), 6);
        assert_eq!(seg.bytes, vec![0x11, 0x22, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn elf64_rejects_empty_input() {
        let loader = Elf64Loader::new();
        let result = loader.load(&[]);
        assert!(result.is_err());
        assert_eq!(result.err(), Some(LoaderError::EmptyInput));
    }

    #[test]
    fn elf64_rejects_non_elf_format() {
        let loader = Elf64Loader::new();
        let result = loader.load(b"NOT_AN_ELF_FILE_AT_ALL");
        assert!(result.is_err());
        assert_eq!(result.err(), Some(LoaderError::InvalidFormat));
    }

    #[test]
    fn elf64_rejects_32bit_elf() {
        let loader = Elf64Loader::new();
        let mut elf = make_elf64_binary(0x401000, false, &[(5, 0x401000, 1, &[0x90])]);
        // Alter EI_CLASS to ELFCLASS32 (1)
        elf[4] = 1;

        let result = loader.load(&elf);
        assert!(result.is_err());
        assert_eq!(result.err(), Some(LoaderError::InvalidElfClass));
    }

    #[test]
    fn elf64_rejects_invalid_machine() {
        let loader = Elf64Loader::new();
        let mut elf = make_elf64_binary(0x401000, false, &[(5, 0x401000, 1, &[0x90])]);
        // Set e_machine to 3 (EM_386)
        elf[18] = 3;
        elf[19] = 0;

        let result = loader.load(&elf);
        assert!(result.is_err());
        assert_eq!(result.err(), Some(LoaderError::InvalidMachine));
    }

    #[test]
    fn elf64_rejects_big_endian() {
        let loader = Elf64Loader::new();
        let mut elf = make_elf64_binary(0x401000, false, &[(5, 0x401000, 1, &[0x90])]);
        // Set EI_DATA to 2 (ELFDATA2MSB)
        elf[5] = 2;

        let result = loader.load(&elf);
        assert!(result.is_err());
        assert_eq!(result.err(), Some(LoaderError::InvalidFormat));
    }

    #[test]
    fn elf64_rejects_truncated_header() {
        let loader = Elf64Loader::new();
        // Starts with ELF magic but shorter than 64 bytes
        let truncated = [0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0];
        let result = loader.load(&truncated);
        assert!(result.is_err());
        assert_eq!(result.err(), Some(LoaderError::TruncatedHeader));
    }

    #[test]
    fn elf64_rejects_no_program_headers() {
        let loader = Elf64Loader::new();
        let mut elf = make_elf64_binary(0x401000, false, &[(5, 0x401000, 1, &[0x90])]);
        // Set e_phnum to 0
        elf[56] = 0;
        elf[57] = 0;

        let result = loader.load(&elf);
        assert!(result.is_err());
        assert_eq!(result.err(), Some(LoaderError::NoProgramHeaders));
    }

    #[test]
    fn elf64_rejects_segment_out_of_range() {
        let loader = Elf64Loader::new();
        let mut elf = make_elf64_binary(0x401000, false, &[(5, 0x401000, 1, &[0x90])]);
        // Truncate the file so that payload is missing
        elf.truncate(64 + 56);

        let result = loader.load(&elf);
        assert!(result.is_err());
        assert_eq!(result.err(), Some(LoaderError::SegmentOutOfRange));
    }

    #[test]
    fn elf64_sequential_image_ids_increment() {
        let loader = Elf64Loader::new();
        let elf = make_elf64_binary(0x401000, false, &[(5, 0x401000, 1, &[0x90])]);

        let id1 = loader.load(&elf).ok().map(|i| i.id);
        let id2 = loader.load(&elf).ok().map(|i| i.id);
        assert_eq!(id1, Some(ImageId(1)));
        assert_eq!(id2, Some(ImageId(2)));
    }
}

#[cfg(test)]
mod pe32_tests {
    use super::*;

    /// Hand-build a minimal PE32+ with one .text section containing
    /// `mov eax, 0x2a; ret`.
    fn fixture() -> Vec<u8> {
        let mut pe = vec![0u8; 0x400];
        // DOS header.
        pe[0] = 0x4D;
        pe[1] = 0x5A;
        pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        // PE signature + COFF header at 0x80.
        pe[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0, 0]);
        pe[0x84..0x86].copy_from_slice(&PE_MACHINE_AMD64.to_le_bytes());
        pe[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // 1 section
        pe[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes()); // opt size 240
        // Optional header at 0x98.
        pe[0x98..0x9A].copy_from_slice(&PE32PLUS_MAGIC.to_le_bytes());
        pe[0xA8..0xAC].copy_from_slice(&0x1000u32.to_le_bytes()); // entry RVA
        pe[0xB0..0xB8].copy_from_slice(&0x140000000u64.to_le_bytes()); // image base
        // .text section header at 0x98+0xF0 = 0x188.
        pe[0x188..0x190].copy_from_slice(b".text\0\0\0");
        pe[0x190..0x194].copy_from_slice(&0x100u32.to_le_bytes()); // virtual size
        pe[0x194..0x198].copy_from_slice(&0x1000u32.to_le_bytes()); // va
        pe[0x198..0x19C].copy_from_slice(&6u32.to_le_bytes()); // raw size
        pe[0x19C..0x1A0].copy_from_slice(&0x200u32.to_le_bytes()); // raw ptr
        pe[0x1AC..0x1B0].copy_from_slice(&(SECTION_EXEC | SECTION_READ).to_le_bytes());
        // Code at file offset 0x200: mov eax,0x2a ; ret.
        pe.resize(0x206, 0);
        pe[0x200..0x205].copy_from_slice(&[0xB8, 0x2A, 0, 0, 0]);
        pe[0x205] = 0xC3;
        pe
    }

    #[test]
    fn pe32_loads_entry_and_section() {
        let loader = Pe32Loader::new();
        let image = match loader.load(&fixture()) {
            Ok(img) => img,
            Err(e) => return assert_eq!(format!("{e:?}"), ""),
        };
        assert_eq!(image.entry, 0x140001000);
        assert_eq!(image.segments.len(), 1);
        let text = &image.segments[0];
        assert_eq!(text.address, 0x140001000);
        assert!(text.executable);
        assert_eq!(&text.bytes[..6], &[0xB8, 0x2A, 0, 0, 0, 0xC3]);
    }

    #[test]
    fn pe32_rejects_pe32_and_non_amd64() {
        let loader = Pe32Loader::new();
        let mut bad = fixture();
        bad[0x98..0x9A].copy_from_slice(&0x10Bu16.to_le_bytes()); // PE32 magic
        assert!(loader.load(&bad).is_err());
        let mut bad2 = fixture();
        bad2[0x84..0x86].copy_from_slice(&0x14Cu16.to_le_bytes()); // i386
        assert!(loader.load(&bad2).is_err());
    }

    /// One import the [`make_pe_with_imports`] builder emits.
    enum ImportFunc {
        Name(&'static str, u16),
        Ordinal(u16),
    }

    /// Hand-builds a minimal PE32+ with a `.text` section and a `.rdata`
    /// section (file offset 0x400, RVA 0x2000) holding an import directory
    /// for `dll` with `funcs`. The `.rdata` layout is
    /// `[descriptors 20*2 incl. all-zero terminator][dll ASCIZ][pad to 8][INT 8*(n+1)][IAT 8*(n+1)][pad to 2][hint/name]`,
    /// so tests can recompute expected RVAs from it.
    fn make_pe_with_imports(dll: &str, funcs: &[ImportFunc]) -> Vec<u8> {
        const RDATA_FILE: usize = 0x400;
        const RDATA_VA: u32 = 0x2000;

        let mut rdata = Vec::new();
        let desc_off = rdata.len();
        // One real descriptor plus the mandatory all-zero terminator.
        rdata.extend_from_slice(&[0u8; 2 * 20]);
        let dll_off = rdata.len();
        rdata.extend_from_slice(dll.as_bytes());
        rdata.push(0);
        while rdata.len() % 8 != 0 {
            rdata.push(0);
        }
        let int_off = rdata.len();
        rdata.extend_from_slice(&vec![0u8; 8 * (funcs.len() + 1)]); // Patched below.
        let iat_off = rdata.len();
        rdata.extend_from_slice(&vec![0u8; 8 * (funcs.len() + 1)]); // Patched below.
        if rdata.len() % 2 != 0 {
            rdata.push(0);
        }
        let rva = |off: usize| RDATA_VA + off as u32;

        for (index, func) in funcs.iter().enumerate() {
            let thunk = match func {
                ImportFunc::Name(func_name, hint) => {
                    let by_name_off = rdata.len();
                    rdata.extend_from_slice(&hint.to_le_bytes());
                    rdata.extend_from_slice(func_name.as_bytes());
                    rdata.push(0);
                    if rdata.len() % 2 != 0 {
                        rdata.push(0); // Hint/name entries are 2-byte aligned.
                    }
                    u64::from(rva(by_name_off))
                }
                ImportFunc::Ordinal(ordinal) => PE_IMPORT_ORDINAL_FLAG | u64::from(*ordinal),
            };
            // INT and IAT start out identical; a real loader rewrites the IAT.
            rdata[int_off + index * 8..int_off + index * 8 + 8].copy_from_slice(&thunk.to_le_bytes());
            rdata[iat_off + index * 8..iat_off + index * 8 + 8].copy_from_slice(&thunk.to_le_bytes());
        }
        // Descriptor: OriginalFirstThunk, TimeDateStamp, ForwarderChain, Name, FirstThunk.
        rdata[desc_off..desc_off + 4].copy_from_slice(&rva(int_off).to_le_bytes());
        rdata[desc_off + 12..desc_off + 16].copy_from_slice(&rva(dll_off).to_le_bytes());
        rdata[desc_off + 16..desc_off + 20].copy_from_slice(&rva(iat_off).to_le_bytes());

        let mut pe = vec![0u8; RDATA_FILE];
        pe[0] = 0x4D;
        pe[1] = 0x5A;
        pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0, 0]);
        pe[0x84..0x86].copy_from_slice(&PE_MACHINE_AMD64.to_le_bytes());
        pe[0x86..0x88].copy_from_slice(&2u16.to_le_bytes()); // 2 sections
        pe[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes()); // opt size 240
        pe[0x98..0x9A].copy_from_slice(&PE32PLUS_MAGIC.to_le_bytes());
        pe[0xA8..0xAC].copy_from_slice(&0x1000u32.to_le_bytes()); // entry RVA
        pe[0xB0..0xB8].copy_from_slice(&0x140000000u64.to_le_bytes()); // image base
        pe[0xD4..0xD8].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfHeaders
        pe[0x104..0x108].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
        // Data directory 1 (IMPORT) at optional-header offset 112 + 8 = 0x110.
        pe[0x110..0x114].copy_from_slice(&rva(desc_off).to_le_bytes());
        pe[0x114..0x118].copy_from_slice(&(rdata.len() as u32).to_le_bytes());
        // .text section header at 0x98 + 0xF0 = 0x188.
        pe[0x188..0x190].copy_from_slice(b".text\0\0\0");
        pe[0x190..0x194].copy_from_slice(&0x100u32.to_le_bytes()); // virtual size
        pe[0x194..0x198].copy_from_slice(&0x1000u32.to_le_bytes()); // va
        pe[0x198..0x19C].copy_from_slice(&6u32.to_le_bytes()); // raw size
        pe[0x19C..0x1A0].copy_from_slice(&0x200u32.to_le_bytes()); // raw ptr
        pe[0x1AC..0x1B0].copy_from_slice(&(SECTION_EXEC | SECTION_READ).to_le_bytes());
        // .rdata section header at 0x1B0.
        pe[0x1B0..0x1B8].copy_from_slice(b".rdata\0\0");
        pe[0x1B8..0x1BC].copy_from_slice(&(rdata.len() as u32).to_le_bytes()); // virtual size
        pe[0x1BC..0x1C0].copy_from_slice(&RDATA_VA.to_le_bytes()); // va
        pe[0x1C0..0x1C4].copy_from_slice(&(rdata.len() as u32).to_le_bytes()); // raw size
        pe[0x1C4..0x1C8].copy_from_slice(&(RDATA_FILE as u32).to_le_bytes()); // raw ptr
        pe[0x1D4..0x1D8].copy_from_slice(&SECTION_READ.to_le_bytes()); // characteristics
        // Code at file offset 0x200: mov eax,0x2a ; ret.
        pe[0x200..0x205].copy_from_slice(&[0xB8, 0x2A, 0, 0, 0]);
        pe[0x205] = 0xC3;
        pe.extend_from_slice(&rdata);
        pe
    }

    #[test]
    fn pe32_parses_by_name_imports() {
        let loader = Pe32Loader::new();
        let pe = make_pe_with_imports(
            "ntoskrnl.exe",
            &[
                ImportFunc::Name("DbgPrint", 0x42),
                ImportFunc::Name("IoCreateDevice", 7),
            ],
        );
        let image = match loader.load(&pe) {
            Ok(image) => image,
            Err(e) => return assert_eq!(format!("{e:?}"), "expected load to succeed"),
        };
        let imports = image.pe_imports().unwrap_or(&[]);
        assert_eq!(imports.len(), 2);
        assert_eq!(imports[0].dll, "ntoskrnl.exe");
        assert_eq!(imports[0].kind, PeImportKind::Name("DbgPrint".to_string()));
        assert_eq!(imports[1].dll, "ntoskrnl.exe");
        assert_eq!(imports[1].kind, PeImportKind::Name("IoCreateDevice".to_string()));
        // Layout: descriptors 40 + "ntoskrnl.exe\0" 13 = 53, padded to 56; INT
        // holds 8*(2+1) bytes, so FirstThunk (the IAT) is at rdata offset 80
        // and import i patches the slot at FirstThunk + 8*i.
        assert_eq!(imports[0].iat_rva, 0x2000 + 80);
        assert_eq!(imports[1].iat_rva, 0x2000 + 88);
    }

    #[test]
    fn pe32_parses_ordinal_import() {
        let loader = Pe32Loader::new();
        let pe = make_pe_with_imports("HAL.dll", &[ImportFunc::Ordinal(0x2A)]);
        let image = match loader.load(&pe) {
            Ok(image) => image,
            Err(e) => return assert_eq!(format!("{e:?}"), "expected load to succeed"),
        };
        let imports = image.pe_imports().unwrap_or(&[]);
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].dll, "HAL.dll");
        assert_eq!(imports[0].kind, PeImportKind::Ordinal(0x2A));
        // Layout: descriptors 40 + "HAL.dll\0" 8 = 48 (already 8-aligned); INT
        // holds 8*(1+1) bytes, so the IAT (FirstThunk) is at rdata offset 64.
        assert_eq!(imports[0].iat_rva, 0x2000 + 64);
    }

    #[test]
    fn pe32_rejects_malformed_import_directory() {
        let loader = Pe32Loader::new();

        // Import-directory RVA points outside the mapped image.
        let mut pe = make_pe_with_imports("ntoskrnl.exe", &[ImportFunc::Name("DbgPrint", 1)]);
        pe[0x110..0x114].copy_from_slice(&0x0090_0000u32.to_le_bytes());
        assert_eq!(loader.load(&pe).err(), Some(LoaderError::TruncatedImportTable));

        // Descriptor Name RVA (descriptor at file 0x400, Name at +12) is unmapped.
        let mut pe = make_pe_with_imports("ntoskrnl.exe", &[ImportFunc::Name("DbgPrint", 1)]);
        pe[0x40C..0x410].copy_from_slice(&0x0090_0000u32.to_le_bytes());
        assert_eq!(loader.load(&pe).err(), Some(LoaderError::TruncatedImportTable));

        // By-name thunk RVA (INT entry at rdata offset 56 = file 0x438) is unmapped.
        let mut pe = make_pe_with_imports("ntoskrnl.exe", &[ImportFunc::Name("DbgPrint", 1)]);
        pe[0x438..0x440].copy_from_slice(&0x0090_0000u64.to_le_bytes());
        assert_eq!(loader.load(&pe).err(), Some(LoaderError::TruncatedImportTable));
    }

    #[test]
    fn pe32_without_import_directory_yields_empty_imports() {
        let loader = Pe32Loader::new();
        let image = match loader.load(&fixture()) {
            Ok(image) => image,
            Err(e) => return assert_eq!(format!("{e:?}"), "expected load to succeed"),
        };
        let imports = image.pe_imports().unwrap_or(&[]);
        assert!(
            imports.is_empty(),
            "absent import directory must yield empty, not error"
        );
    }

    #[test]
    fn pe32_immediate_import_terminator_yields_empty_imports() {
        let loader = Pe32Loader::new();
        let mut pe = make_pe_with_imports("ntoskrnl.exe", &[ImportFunc::Name("DbgPrint", 1)]);
        // Zero the only descriptor: the array becomes an immediate all-zero terminator.
        pe[0x400..0x414].fill(0);
        let image = match loader.load(&pe) {
            Ok(image) => image,
            Err(e) => return assert_eq!(format!("{e:?}"), "expected load to succeed"),
        };
        let imports = image.pe_imports().unwrap_or(&[]);
        assert!(imports.is_empty());
    }

    #[test]
    fn pe32_enforces_import_dll_name_limit() {
        let loader = Pe32Loader::new();
        // 64 bytes is the cap and is accepted.
        let capped = make_pe_with_imports(&"d".repeat(64), &[ImportFunc::Name("DbgPrint", 1)]);
        let image = match loader.load(&capped) {
            Ok(image) => image,
            Err(e) => return assert_eq!(format!("{e:?}"), "expected load to succeed"),
        };
        let imports = image.pe_imports().unwrap_or(&[]);
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].dll.len(), 64);
        // 65 bytes fail closed.
        let too_long = make_pe_with_imports(&"d".repeat(65), &[ImportFunc::Name("DbgPrint", 1)]);
        assert_eq!(loader.load(&too_long).err(), Some(LoaderError::ImportDllNameTooLong));
    }

    #[test]
    fn pe_imports_none_for_non_pe_images() {
        let loader = InMemoryImageLoader::new();
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x1000u64.to_le_bytes()); // entry
        buf.extend_from_slice(&1u64.to_le_bytes()); // target profile
        buf.push(0xC3);
        let image = match loader.load(&buf) {
            Ok(image) => image,
            Err(e) => return assert_eq!(format!("{e:?}"), "expected load to succeed"),
        };
        assert!(image.pe_imports().is_none());
    }
}

#[cfg(test)]
mod pe_exports_tests {
    use super::*;

    /// Hand-builds a minimal PE32+ with a `.text` section (RVA 0x1000, code
    /// at file 0x200) and a `.rdata` section (RVA 0x2000, file 0x400) whose
    /// export directory lists `funcs` by name plus one ordinal-only export
    /// (function-table slot without a name-table entry). Layout is
    /// deterministic: directory at rdata+0, module name at +40, function
    /// table next, then name pointers, then ordinal indices, then strings —
    /// tests recompute the offsets to mutate them.
    fn make_pe_with_exports(funcs: &[(&str, u32)]) -> Vec<u8> {
        const RDATA_FILE: usize = 0x400;
        const RDATA_VA: u32 = 0x2000;
        let rva = |off: usize| RDATA_VA + off as u32;

        let mut rdata = Vec::new();
        let dir_off = rdata.len();
        rdata.extend_from_slice(&[0u8; 40]); // IMAGE_EXPORT_DIRECTORY, patched below.
        let module_off = rdata.len();
        rdata.extend_from_slice(b"kernel_mod.sys\0");
        // Function table: one slot per named export + one ordinal-only slot.
        let functions_off = rdata.len();
        for _ in funcs {
            rdata.extend_from_slice(&0u32.to_le_bytes()); // patched below
        }
        rdata.extend_from_slice(&0x1050u32.to_le_bytes()); // ordinal-only slot
        let names_off = rdata.len();
        for _ in funcs {
            rdata.extend_from_slice(&0u32.to_le_bytes()); // patched below
        }
        let ordinals_off = rdata.len();
        for index in 0..funcs.len() {
            rdata.extend_from_slice(&(index as u16).to_le_bytes());
        }
        for (index, (name, target_rva)) in funcs.iter().enumerate() {
            let name_off = rdata.len();
            rdata.extend_from_slice(name.as_bytes());
            rdata.push(0);
            let slot = names_off + index * 4;
            rdata[slot..slot + 4].copy_from_slice(&rva(name_off).to_le_bytes());
            let fslot = functions_off + index * 4;
            rdata[fslot..fslot + 4].copy_from_slice(&target_rva.to_le_bytes());
        }
        // Directory fields: Name, Base, NumberOfFunctions, NumberOfNames,
        // AddressOfFunctions, AddressOfNames, AddressOfNameOrdinals.
        rdata[dir_off + 0x0C..dir_off + 0x10].copy_from_slice(&rva(module_off).to_le_bytes());
        rdata[dir_off + 0x10..dir_off + 0x14].copy_from_slice(&1u32.to_le_bytes()); // OrdinalBase
        rdata[dir_off + 0x14..dir_off + 0x18].copy_from_slice(&((funcs.len() + 1) as u32).to_le_bytes());
        rdata[dir_off + 0x18..dir_off + 0x1C].copy_from_slice(&(funcs.len() as u32).to_le_bytes());
        rdata[dir_off + 0x1C..dir_off + 0x20].copy_from_slice(&rva(functions_off).to_le_bytes());
        rdata[dir_off + 0x20..dir_off + 0x24].copy_from_slice(&rva(names_off).to_le_bytes());
        rdata[dir_off + 0x24..dir_off + 0x28].copy_from_slice(&rva(ordinals_off).to_le_bytes());

        let mut pe = vec![0u8; RDATA_FILE];
        pe[0] = 0x4D;
        pe[1] = 0x5A;
        pe[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(&[0x50, 0x45, 0, 0]);
        pe[0x84..0x86].copy_from_slice(&PE_MACHINE_AMD64.to_le_bytes());
        pe[0x86..0x88].copy_from_slice(&2u16.to_le_bytes()); // 2 sections
        pe[0x94..0x96].copy_from_slice(&0xF0u16.to_le_bytes()); // opt size 240
        pe[0x98..0x9A].copy_from_slice(&PE32PLUS_MAGIC.to_le_bytes());
        pe[0xA8..0xAC].copy_from_slice(&0x1000u32.to_le_bytes()); // entry RVA
        pe[0xB0..0xB8].copy_from_slice(&0x140000000u64.to_le_bytes()); // image base
        pe[0xD4..0xD8].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfHeaders
        pe[0x104..0x108].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
        // Data directory 0 (EXPORT) at optional-header offset 112.
        pe[0x108..0x10C].copy_from_slice(&rva(dir_off).to_le_bytes());
        pe[0x10C..0x110].copy_from_slice(&(rdata.len() as u32).to_le_bytes());
        // .text section header at 0x188.
        pe[0x188..0x190].copy_from_slice(b".text\0\0\0");
        pe[0x190..0x194].copy_from_slice(&0x100u32.to_le_bytes()); // virtual size
        pe[0x194..0x198].copy_from_slice(&0x1000u32.to_le_bytes()); // va
        pe[0x198..0x19C].copy_from_slice(&6u32.to_le_bytes()); // raw size
        pe[0x19C..0x1A0].copy_from_slice(&0x200u32.to_le_bytes()); // raw ptr
        pe[0x1AC..0x1B0].copy_from_slice(&(SECTION_EXEC | SECTION_READ).to_le_bytes());
        // .rdata section header at 0x1B0.
        pe[0x1B0..0x1B8].copy_from_slice(b".rdata\0\0");
        pe[0x1B8..0x1BC].copy_from_slice(&(rdata.len() as u32).to_le_bytes()); // virtual size
        pe[0x1BC..0x1C0].copy_from_slice(&RDATA_VA.to_le_bytes()); // va
        pe[0x1C0..0x1C4].copy_from_slice(&(rdata.len() as u32).to_le_bytes()); // raw size
        pe[0x1C4..0x1C8].copy_from_slice(&(RDATA_FILE as u32).to_le_bytes()); // raw ptr
        pe[0x1D4..0x1D8].copy_from_slice(&SECTION_READ.to_le_bytes()); // characteristics
        // Code at file offset 0x200: mov eax,0x2a ; ret.
        pe[0x200..0x205].copy_from_slice(&[0xB8, 0x2A, 0, 0, 0]);
        pe[0x205] = 0xC3;
        pe.extend_from_slice(&rdata);
        pe
    }

    /// File offset of the .rdata byte at `rdata_off` in the built image.
    fn rdata_file(rdata_off: usize) -> usize {
        0x400 + rdata_off
    }

    #[test]
    fn pe32_parses_named_exports_and_resolves_addresses() {
        let loader = Pe32Loader::new();
        let pe = make_pe_with_exports(&[("ExAllocatePoolWithTag", 0x1000), ("ExFreePoolWithTag", 0x1010)]);
        let image = match loader.load(&pe) {
            Ok(image) => image,
            Err(e) => return assert_eq!(format!("{e:?}"), "expected load to succeed"),
        };
        let exports = image.pe_exports().unwrap_or(&[]);
        // The ordinal-only slot must NOT be enumerated.
        assert_eq!(exports.len(), 2);
        assert_eq!(exports[0].name, "ExAllocatePoolWithTag");
        assert_eq!(exports[0].rva, 0x1000);
        assert_eq!(exports[0].ordinal, 1); // OrdinalBase 1 + index 0
        assert_eq!(exports[1].name, "ExFreePoolWithTag");
        assert_eq!(exports[1].rva, 0x1010);
        assert_eq!(exports[1].ordinal, 2);
        // export_address = ImageBase + RVA — the in-image call target.
        assert_eq!(image.export_address("ExAllocatePoolWithTag"), Some(0x140001000));
        assert_eq!(image.export_address("ExFreePoolWithTag"), Some(0x140001010));
        // Exact-name matching only (the runtime's import-binding convention).
        assert_eq!(image.export_address("exallocatepoolwithtag"), None);
        assert_eq!(image.export_address("NotExported"), None);
    }

    #[test]
    fn pe32_skips_forwarded_export() {
        let loader = Pe32Loader::new();
        let mut pe = make_pe_with_exports(&[("RtlFoo", 0x1000)]);
        // Point the function slot inside the export directory itself
        // (directory RVA = 0x2000): a forwarder string, not code here.
        let fslot = rdata_file(40 + 15); // module name is 15 bytes ("kernel_mod.sys\0")
        pe[fslot..fslot + 4].copy_from_slice(&0x2004u32.to_le_bytes());
        let image = match loader.load(&pe) {
            Ok(image) => image,
            Err(e) => return assert_eq!(format!("{e:?}"), "expected load to succeed"),
        };
        assert!(
            image.pe_exports().unwrap_or(&[]).is_empty(),
            "forwarded export must be skipped"
        );
        assert_eq!(image.export_address("RtlFoo"), None);
    }

    #[test]
    fn pe32_without_export_directory_yields_empty_exports() {
        let loader = Pe32Loader::new();
        let mut pe = make_pe_with_exports(&[("ExAllocatePoolWithTag", 0x1000)]);
        // Zero the export-directory RVA: the directory is not declared.
        pe[0x108..0x10C].copy_from_slice(&0u32.to_le_bytes());
        let image = match loader.load(&pe) {
            Ok(image) => image,
            Err(e) => return assert_eq!(format!("{e:?}"), "expected load to succeed"),
        };
        assert!(image.pe_exports().unwrap_or(&[]).is_empty());
        assert_eq!(image.export_address("ExAllocatePoolWithTag"), None);
    }

    #[test]
    fn pe32_rejects_malformed_export_directory() {
        let loader = Pe32Loader::new();

        // Directory RVA points outside the mapped image.
        let mut pe = make_pe_with_exports(&[("ExAllocatePoolWithTag", 0x1000)]);
        pe[0x108..0x10C].copy_from_slice(&0x0090_0000u32.to_le_bytes());
        assert_eq!(loader.load(&pe).err(), Some(LoaderError::TruncatedExportTable));

        // Function-table RVA (directory field +0x1C) is unmapped.
        let mut pe = make_pe_with_exports(&[("ExAllocatePoolWithTag", 0x1000)]);
        pe[rdata_file(0x1C)..rdata_file(0x1C) + 4].copy_from_slice(&0x0090_0000u32.to_le_bytes());
        assert_eq!(loader.load(&pe).err(), Some(LoaderError::TruncatedExportTable));

        // Name-pointer slot (names table follows the function table:
        // 40 dir + 15 module + 4*2 function slots = 63) is unmapped.
        let mut pe = make_pe_with_exports(&[("ExAllocatePoolWithTag", 0x1000)]);
        pe[rdata_file(63)..rdata_file(63) + 4].copy_from_slice(&0x0090_0000u32.to_le_bytes());
        assert_eq!(loader.load(&pe).err(), Some(LoaderError::TruncatedExportTable));

        // Ordinal index past the function table (ordinals at 63 + 4 = 67).
        let mut pe = make_pe_with_exports(&[("ExAllocatePoolWithTag", 0x1000)]);
        pe[rdata_file(67)..rdata_file(67) + 2].copy_from_slice(&0xFFFFu16.to_le_bytes());
        assert_eq!(loader.load(&pe).err(), Some(LoaderError::TruncatedExportTable));
    }

    #[test]
    fn pe_exports_none_for_non_pe_images() {
        let loader = InMemoryImageLoader::new();
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x1000u64.to_le_bytes()); // entry
        buf.extend_from_slice(&1u64.to_le_bytes()); // target profile
        buf.push(0xC3);
        let image = match loader.load(&buf) {
            Ok(image) => image,
            Err(e) => return assert_eq!(format!("{e:?}"), "expected load to succeed"),
        };
        assert!(image.pe_exports().is_none());
        assert_eq!(image.export_address("anything"), None);
    }

    /// Real driver fixture: every parsed export name must round-trip through
    /// `export_address` to `ImageBase + RVA`, and pool-family wrapper exports
    /// (these fixtures export their own `ExAllocatePool`/`ExFreePool`) must
    /// resolve to non-zero in-image addresses. Silent skip when the fixture
    /// tree is absent so the suite stays environment-independent.
    #[test]
    fn pe32_resolves_exports_in_real_driver_fixture() {
        let Ok(home) = std::env::var("HOME") else {
            return;
        };
        let bin_dir = std::path::Path::new(&home).join("Documents/byovd-harness/ghidra_pipeline/fixtures/bin");
        let Ok(entries) = std::fs::read_dir(&bin_dir) else {
            return;
        };
        let Some(fixture) = entries
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .find(|path| path.extension().is_some_and(|ext| ext == "sys"))
        else {
            return;
        };
        let Ok(bytes) = std::fs::read(&fixture) else {
            return;
        };
        let image = match Pe32Loader::new().load(&bytes) {
            Ok(image) => image,
            Err(_) => return, // Not a PE32+ image: out of scope for this test.
        };
        let base = image.pe.as_ref().map(|pe| pe.image_base).unwrap_or(0);
        let exports = image.pe_exports().unwrap_or(&[]);
        assert!(!exports.is_empty(), "fixture {} has exports", fixture.display());
        for export in exports {
            let expected = base + u64::from(export.rva);
            assert_eq!(image.export_address(&export.name), Some(expected));
            assert_ne!(expected, 0);
        }
        // The pool-model-relevant wrapper exports, when present, resolve.
        for name in ["DriverEntry", "ExAllocatePool", "ExFreePool"] {
            if exports.iter().any(|export| export.name == name) {
                assert!(image.export_address(name).is_some(), "{name} resolves");
            }
        }
    }
}
