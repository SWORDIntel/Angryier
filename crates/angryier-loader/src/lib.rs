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

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedImage {
    pub id: ImageId,
    pub entry: Address,
    pub target_profile: TargetProfileId,
    pub segments: Vec<Segment>,
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

/// Errors produced by the in-memory loader, state importer, and ELF64 loader backends.
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
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

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

/// Real 64-bit ELF image loader for x86-64 binaries.
///
/// Validates ELF headers and extracts all `PT_LOAD` segments, populating
/// execution permissions and memory bounds directly from program headers.
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

            if p_type == PT_LOAD {
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

        let id = self.allocate_id()?;

        Ok(LoadedImage {
            id,
            entry: e_entry,
            target_profile: INTEL64_TARGET_PROFILE,
            segments,
        })
    }
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
