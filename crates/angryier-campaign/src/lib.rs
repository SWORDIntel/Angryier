//! Host-native, single-writer sustained campaign over authenticated loopback.
//! Raw TCP is plaintext and must never be exposed outside loopback; use an
//! independently pinned encrypted tunnel for connections between hosts.
pub mod local;
mod progress;
pub mod worker_config;
use angryier_distribution::{
    contracts::{CampaignArtifacts, CampaignManifest, CampaignSpec, Digest, ExplorationLimits},
    transport::{Message, TcpServer, TcpSession, Transport},
};
use angryier_expr::{ExprReader, ShardedExprArena};
use angryier_ledger::{evidence::AcceptedEvidence, sustained::Report};
use angryier_types::{ExpressionNormalizationVersion, FidelityProfile, SemanticVersion, TargetProfileId};
pub use local::{LocalCampaign, LocalConfig, LocalOutcome, LocalPolicy};
use sha2::{Digest as _, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs,
    io::{self, Read},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

#[cfg(target_arch = "x86_64")]
use angryier_arch_intel64::register_id;
#[cfg(target_arch = "x86_64")]
use angryier_distribution::transport::TcpError;
#[cfg(target_arch = "x86_64")]
use angryier_ir::IrType;
#[cfg(target_arch = "x86_64")]
use angryier_ledger::sustained::FencedReservation;
#[cfg(target_arch = "x86_64")]
use angryier_runtime::{
    Process, Runtime, SymbolicSession,
    sustained::SustainedCampaign,
    sustained_pool::{AdvanceOutcome, VerifiedRemoteOutcome, WireGrant},
};
#[cfg(target_arch = "x86_64")]
use angryier_solver_z3::Z3Backend;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const COORDINATOR: &str = "coordinator";
const WORKER: &str = "worker";

#[derive(Clone)]
pub struct Peer {
    pub id: String,
    pub addr: SocketAddr,
    pub key_file: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImageMode {
    Elf,
    /// Opt-in loader model, not Windows execution or Windows-fidelity evidence.
    PeDriver,
}

impl std::str::FromStr for ImageMode {
    type Err = &'static str;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "elf" => Ok(Self::Elf),
            "pe-driver" => Ok(Self::PeDriver),
            _ => Err("--image-mode must be elf or pe-driver (a model, not full Windows semantics)"),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymbolicRegister {
    Rbx,
    Rcx,
    Rdx,
    Rsi,
    Rdi,
    R8,
    R9,
    /// Linux x86-64 SysV user-controlled argument pair (`rsi` + `rdx`),
    /// leaving `rdi` on the deterministic `ET_REL` scratch struct.
    Sysv,
}

impl std::str::FromStr for SymbolicRegister {
    type Err = &'static str;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value {
            "rbx" => Ok(Self::Rbx),
            "rcx" => Ok(Self::Rcx),
            "rdx" => Ok(Self::Rdx),
            "rsi" => Ok(Self::Rsi),
            "rdi" => Ok(Self::Rdi),
            "r8" => Ok(Self::R8),
            "r9" => Ok(Self::R9),
            "sysv" => Ok(Self::Sysv),
            _ => Err("--symbolic-reg must be rbx, rcx, rdx, rsi, rdi, r8, r9, or sysv"),
        }
    }
}

impl SymbolicRegister {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rbx => "rbx",
            Self::Rcx => "rcx",
            Self::Rdx => "rdx",
            Self::Rsi => "rsi",
            Self::Rdi => "rdi",
            Self::R8 => "r8",
            Self::R9 => "r9",
            Self::Sysv => "sysv",
        }
    }

    pub const fn register_names(self) -> &'static [&'static str] {
        match self {
            Self::Rbx => &["rbx"],
            Self::Rcx => &["rcx"],
            Self::Rdx => &["rdx"],
            Self::Rsi => &["rsi"],
            Self::Rdi => &["rdi"],
            Self::R8 => &["r8"],
            Self::R9 => &["r9"],
            Self::Sysv => &["rsi", "rdx"],
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub fn register_ids(self) -> Vec<u32> {
        match self {
            Self::Rbx => vec![register_id::GPR_BASE + 3],
            Self::Rcx => vec![register_id::GPR_BASE + 1],
            Self::Rdx => vec![register_id::GPR_BASE + 2],
            Self::Rsi => vec![register_id::GPR_BASE + 6],
            Self::Rdi => vec![register_id::GPR_BASE + 7],
            Self::R8 => vec![register_id::GPR_BASE + 8],
            Self::R9 => vec![register_id::GPR_BASE + 9],
            Self::Sysv => vec![register_id::GPR_BASE + 6, register_id::GPR_BASE + 2],
        }
    }
}

/// Keep omission distinct from every numeric CLI value until the image mode is known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RamCap {
    ModeDefault,
    Bytes(u64),
}

impl std::str::FromStr for RamCap {
    type Err = std::num::ParseIntError;

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        value.parse().map(Self::Bytes)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CampaignLimits {
    pub max_steps: u64,
    pub max_path_steps: u64,
    pub max_active_states: u64,
    pub max_path_depth: u64,
    pub max_loop_visits: u64,
    pub max_solver_millis: u64,
    pub max_wall_millis: u64,
    pub max_ram_bytes: RamCap,
    pub max_disk_bytes: u64,
    pub max_trace_bytes: u64,
}

impl CampaignLimits {
    fn resolve(&self, mode: ImageMode) -> ExplorationLimits {
        ExplorationLimits {
            max_steps: self.max_steps,
            max_path_steps: self.max_path_steps,
            max_active_states: self.max_active_states,
            max_path_depth: self.max_path_depth,
            max_loop_visits: self.max_loop_visits,
            max_solver_millis: self.max_solver_millis,
            max_wall_millis: self.max_wall_millis,
            max_ram_bytes: match (self.max_ram_bytes, mode) {
                (RamCap::Bytes(bytes), _) => bytes,
                (RamCap::ModeDefault, ImageMode::Elf) => 64 * 1024 * 1024,
                // Budget the mapped PE plus driver-model loader regions, not just file bytes.
                (RamCap::ModeDefault, ImageMode::PeDriver) => 576 * 1024 * 1024,
            },
            max_disk_bytes: self.max_disk_bytes,
            max_trace_bytes: self.max_trace_bytes,
        }
    }
}

/// Cloneable so a typed local specification can keep its campaign config for
/// a later resume; all fields are value types.
#[derive(Clone)]
pub struct Config {
    pub binary: PathBuf,
    pub image_mode: ImageMode,
    /// Absolute mapped PC, not an RVA; None selects the image header entry.
    pub entry: Option<u64>,
    pub symbolic_reg: SymbolicRegister,
    pub key_file: PathBuf,
    pub build_id: String,
    pub worker_id: String,
    pub peers: Vec<Peer>,
    pub limits: CampaignLimits,
    /// Optional live accepted-event journal; defaults to `<ledger>.progress.jsonl`.
    pub progress_jsonl: Option<PathBuf>,
}

impl Config {
    pub fn defaults(binary: PathBuf, key_file: PathBuf, build_id: String) -> Self {
        Self {
            binary,
            image_mode: ImageMode::Elf,
            entry: None,
            symbolic_reg: SymbolicRegister::Rbx,
            key_file,
            build_id,
            worker_id: WORKER.into(),
            peers: Vec::new(),
            progress_jsonl: None,
            limits: CampaignLimits {
                max_steps: 128,
                max_path_steps: 64,
                max_active_states: 2,
                max_path_depth: 64,
                max_loop_visits: 64,
                max_solver_millis: 10_000,
                max_wall_millis: 30_000,
                max_ram_bytes: RamCap::ModeDefault,
                max_disk_bytes: 1024 * 1024,
                max_trace_bytes: 1024 * 1024,
            },
        }
    }
    /// Canonical model policy for manifest artifacts; entry is the resolved PC.
    pub fn policy(&self, entry: u64) -> Vec<u8> {
        let mode = match self.image_mode {
            ImageMode::Elf => "elf",
            ImageMode::PeDriver => "pe-driver-model-not-windows",
        };
        let register = self.symbolic_reg.as_str();
        format!("campaign-root-v2/{mode}/entry:{entry:016x}/symbolic:{register}").into_bytes()
    }

    fn validate(&self) -> Result<()> {
        if self.build_id.is_empty()
            || self.build_id.len() > 128
            || !self
                .build_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-._".contains(&byte))
        {
            return Err("--build-id must be a pinned 1..128 byte version token".into());
        }
        Ok(())
    }
}

fn build_profile() -> Result<Vec<u8>> {
    let mut executable = fs::File::open(std::env::current_exe()?)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = executable.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        total = total.checked_add(n as u64).ok_or("executable too large")?;
        if total > 512 * 1024 * 1024 {
            return Err("executable exceeds 512 MiB build pin cap".into());
        }
        hasher.update(&buffer[..n]);
    }
    let mut profile = b"native-xed-v1/executable-sha256:".to_vec();
    profile.extend_from_slice(&hasher.finalize());
    Ok(profile)
}

fn artifacts<'a>(image: &'a [u8], profile: &'a [u8], policy: &'a [u8]) -> CampaignArtifacts<'a> {
    CampaignArtifacts {
        binary: image,
        semantic_profile: profile,
        script: b"no-script",
        policy,
        solver_policy: b"z3-native-v1",
        inputs: vec![],
        stubs: vec![],
    }
}

pub fn manifest(config: &Config, image: &[u8], entry: u64, profile: &[u8]) -> Result<CampaignManifest> {
    config.validate()?;
    if config.entry.is_some_and(|requested| requested != entry) {
        return Err("resolved entry does not match --entry".into());
    }
    Ok(CampaignManifest::seal(CampaignSpec {
        binary_digest: Digest::of(image),
        architecture: "x86_64".into(),
        entry_pc: entry,
        semantic_version: format!("1/{}", config.build_id),
        semantic_profile_digest: Digest::of(profile),
        script_digest: Digest::of(b"no-script"),
        policy_digest: Digest::of(&config.policy(entry)),
        inputs: vec![],
        stubs: vec![],
        solver_version: "z3".into(),
        solver_policy_digest: Digest::of(b"z3-native-v1"),
        fidelity: match config.image_mode {
            ImageMode::Elf => FidelityProfile::Prove,
            ImageMode::PeDriver => FidelityProfile::Explore,
        },
        limits: config.limits.resolve(config.image_mode),
    })?)
}

fn key(path: &PathBuf) -> Result<[u8; 32]> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
            return Err("key file must not be group/world accessible (chmod 600)".into());
        }
    }
    let bytes = fs::read(path)?;
    let key: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "key file must be exactly 32 raw bytes")?;
    if key == [0; 32] {
        return Err("zero pairwise key rejected".into());
    }
    Ok(key)
}

fn transport(manifest: CampaignManifest, local: &str, remote: &str, secret: [u8; 32]) -> Result<Transport> {
    Ok(Transport::new(
        manifest,
        1,
        local.into(),
        HashMap::from([(remote.into(), secret)]),
    )?)
}

/// Fixed mapped RAM the pe-driver model joins around the image before the
/// campaign's own budget check can run (see `Runtime::load_pe_driver` and
/// `load_image`): a 4 MiB `brk` heap, a 64 KiB stack, the 1 MiB
/// import-stub region, the 64 KiB `DRIVER_OBJECT` scratch, the 4 KiB
/// universal-callback page, the 0x11'0000 kernel-pool shadow and the
/// 64 KiB zeroed low page. Preflighted together with the section table so
/// the up-front bound matches the regions the sustained campaign later
/// sums against the same cap.
const PE_DRIVER_FIXED_RAM: u64 = 0x0064_1000;

/// Bound a raw PE32+ image's mapped footprint before the runtime loader
/// allocates it. `Pe32Loader` materializes every section at
/// `max(SizeOfRawData, VirtualSize)` — zero-filling the bss tail — and
/// every field is a u32 (up to 4 GiB per section), so a small file with
/// large virtual sections can otherwise demand gigabytes before any
/// campaign mapped-RAM accounting runs. Walks the section table with
/// checked arithmetic, rejects truncated tables and raw ranges that leave
/// the file, and requires the mapped sum plus [`PE_DRIVER_FIXED_RAM`] to
/// fit `max_ram_bytes`.
fn preflight_pe_mapped_ram(image: &[u8], max_ram_bytes: u64) -> Result<()> {
    fn le_u16(image: &[u8], offset: usize) -> Result<u16> {
        let end = offset
            .checked_add(2)
            .ok_or("pe-driver preflight: PE header offset overflow")?;
        let bytes: [u8; 2] = image
            .get(offset..end)
            .and_then(|slice| slice.try_into().ok())
            .ok_or("pe-driver preflight: truncated PE header")?;
        Ok(u16::from_le_bytes(bytes))
    }
    fn le_u32(image: &[u8], offset: usize) -> Result<u32> {
        let end = offset
            .checked_add(4)
            .ok_or("pe-driver preflight: PE header offset overflow")?;
        let bytes: [u8; 4] = image
            .get(offset..end)
            .and_then(|slice| slice.try_into().ok())
            .ok_or("pe-driver preflight: truncated PE header")?;
        Ok(u32::from_le_bytes(bytes))
    }
    // read_image already pinned MZ/PE\0\0/AMD64/PE32+; re-derive the same
    // layout defensively so this stays safe for any input slice.
    let e_lfanew = le_u32(image, 0x3c)? as usize;
    let coff = e_lfanew
        .checked_add(4)
        .ok_or("pe-driver preflight: e_lfanew overflow")?;
    if le_u16(image, coff)? != 0x8664
        || le_u16(image, coff.checked_add(20).ok_or("pe-driver preflight: COFF overflow")?)? != 0x020b
    {
        return Err("pe-driver preflight: expected a raw AMD64 PE32+ image".into());
    }
    let num_sections = le_u16(image, coff.checked_add(2).ok_or("pe-driver preflight: COFF overflow")?)? as usize;
    let opt_size = le_u16(image, coff.checked_add(16).ok_or("pe-driver preflight: COFF overflow")?)? as usize;
    let sec_base = coff
        .checked_add(20)
        .and_then(|opt| opt.checked_add(opt_size))
        .ok_or("pe-driver preflight: optional-header offset overflow")?;
    let table_end = sec_base
        .checked_add(
            num_sections
                .checked_mul(40)
                .ok_or("pe-driver preflight: section-count overflow")?,
        )
        .ok_or("pe-driver preflight: section-table offset overflow")?;
    if table_end > image.len() {
        return Err("pe-driver preflight: section table exceeds the image".into());
    }
    let mut mapped: u64 = 0;
    for index in 0..num_sections {
        let off = sec_base
            .checked_add(index * 40)
            .ok_or("pe-driver preflight: section offset overflow")?;
        let virtual_size = u64::from(le_u32(image, off + 8)?);
        let raw_size = u64::from(le_u32(image, off + 16)?);
        let raw_ptr = le_u32(image, off + 20)? as usize;
        let raw_end = raw_ptr
            .checked_add(usize::try_from(raw_size).map_err(|_| "pe-driver preflight: raw size overflow")?)
            .ok_or("pe-driver preflight: raw pointer overflow")?;
        if raw_end > image.len() {
            return Err(format!("pe-driver preflight: section {index} raw range leaves the image").into());
        }
        mapped = mapped
            .checked_add(virtual_size.max(raw_size))
            .ok_or("pe-driver preflight: mapped-size overflow")?;
    }
    let total = mapped
        .checked_add(PE_DRIVER_FIXED_RAM)
        .ok_or("pe-driver preflight: mapped-size overflow")?;
    if total > max_ram_bytes {
        return Err(format!(
            "pe-driver mapped RAM {total} (sections {mapped} + fixed loader regions {PE_DRIVER_FIXED_RAM}) exceeds max-ram-bytes {max_ram_bytes}"
        )
        .into());
    }
    Ok(())
}

fn read_image(config: &Config) -> Result<Vec<u8>> {
    let (cap, error) = match config.image_mode {
        ImageMode::Elf => (32 * 1024 * 1024, "ELF exceeds 32 MiB cap"),
        ImageMode::PeDriver => (512 * 1024 * 1024, "PE exceeds 512 MiB cap"),
    };
    let mut file = fs::File::open(&config.binary)?;
    if file.metadata()?.len() > cap {
        return Err(error.into());
    }
    let mut image = Vec::new();
    file.by_ref().take(cap + 1).read_to_end(&mut image)?;
    if image.len() as u64 > cap {
        return Err(error.into());
    }
    match config.image_mode {
        ImageMode::Elf if !image.starts_with(b"\x7fELF") => {
            return Err("expected an ELF binary (PE requires explicit --image-mode pe-driver)".into());
        }
        ImageMode::PeDriver => {
            // Require a raw AMD64 PE32+ file, never a mapped dump or PE32.
            // The runtime loader handles section and import validation, but it
            // allocates every section at max(raw, virtual) first, so bound
            // that mapped footprint against the explicit or mode-default RAM
            // cap before the loader runs.
            let pe = image
                .get(0x3c..0x40)
                .and_then(|bytes| bytes.try_into().ok())
                .map(u32::from_le_bytes)
                .map(|pe| pe as usize);
            let valid = image.starts_with(b"MZ")
                && pe.is_some_and(|pe| {
                    image.get(pe..pe + 4) == Some(b"PE\0\0".as_slice())
                        && image.get(pe + 4..pe + 6) == Some([0x64, 0x86].as_slice())
                        && image.get(pe + 24..pe + 26) == Some([0x0b, 0x02].as_slice())
                });
            if !valid {
                return Err(
                    "pe-driver requires a raw x86_64 PE32+ image; this model is not full Windows semantics".into(),
                );
            }
            preflight_pe_mapped_ram(&image, config.limits.resolve(ImageMode::PeDriver).max_ram_bytes)?;
        }
        _ => {}
    }
    Ok(image)
}

/// Resolves `--root-symbol NAME` to a runtime virtual address in the
/// configured image. Prefers a `STT_FUNC` match; any named symbol is accepted
/// otherwise. Kernel modules (ET_REL) have no entry point, so campaigns target
/// one through this path or an explicit `--entry`; the two are mutually
/// exclusive.
pub fn resolve_entry_symbol(config: &Config, name: &str) -> Result<u64> {
    if config.entry.is_some() {
        return Err("--entry and --root-symbol are mutually exclusive".into());
    }
    lookup_symbol(config, name)
}

/// Resolves `NAME` or `NAME+OFFSET` (decimal or `0x` hex) to a runtime virtual
/// address in the configured ELF image. Intended for `--find-symbol` /
/// `--avoid-symbol` targets on `ET_REL` or static ELF binaries.
pub fn resolve_symbol(config: &Config, spec: &str) -> Result<u64> {
    if let Some((name, off_str)) = spec.split_once('+') {
        if name.is_empty() || off_str.is_empty() {
            return Err("symbol target requires NAME or NAME+OFFSET".into());
        }
        let offset = if let Some(hex) = off_str.strip_prefix("0x") {
            u64::from_str_radix(hex, 16)
        } else {
            off_str.parse::<u64>()
        }
        .map_err(|_| "symbol offset must be a u64 (decimal or 0x hexadecimal)")?;
        let base = lookup_symbol(config, name)?;
        base.checked_add(offset)
            .ok_or_else(|| "symbol target offset overflow".into())
    } else {
        lookup_symbol(config, spec)
    }
}

fn lookup_symbol(config: &Config, name: &str) -> Result<u64> {
    let image = read_image(config)?;
    let loader = angryier_loader::Elf64Loader::new();
    let loaded = angryier_loader::ImageLoader::load(&loader, &image)
        .map_err(|error| format!("root symbol resolution failed: {error}"))?;
    let symbol = loaded
        .symbols
        .iter()
        .find(|symbol| symbol.name == name && symbol.is_function())
        .or_else(|| loaded.symbols.iter().find(|symbol| symbol.name == name))
        .ok_or_else(|| format!("root symbol '{name}' not found in image"))?;
    Ok(symbol.address)
}

#[cfg(target_arch = "x86_64")]
fn configure_root(config: &Config, mut root: Process) -> Result<Process> {
    // pe-driver retains the runtime's deterministic import stubs, scratch
    // DRIVER_OBJECT, sentinel return and zero-page/cookie assumptions. It does
    // not initialize a Windows user process or establish a real function ABI.
    // An entry override changes only the PC; all other loader state is retained.
    let entry = config.entry.unwrap_or(root.pc()?);
    if !root
        .state
        .memory
        .regions()
        .iter()
        .any(|region| region.executable && entry >= region.base && entry - region.base < region.size)
    {
        return Err(format!("entry {entry:#x} is not in mapped executable memory").into());
    }
    root.write_pc(entry)?;
    root.entry = entry;
    root.entry_state = root.state.clone();
    Ok(root)
}

#[cfg(target_arch = "x86_64")]
fn initial(config: &Config, image: &[u8]) -> Result<(u64, Digest)> {
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let root = configure_root(
        config,
        match config.image_mode {
            ImageMode::Elf => runtime.load_elf(image)?,
            ImageMode::PeDriver => runtime.load_pe_driver(image)?,
        },
    )?;
    let entry = root.pc()?;
    let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
    let mut session = SymbolicSession::new(&runtime, &arena, root);
    for reg_id in config.symbolic_reg.register_ids() {
        session.mark_symbolic(0, reg_id, IrType::Bits(64))?;
    }
    if config.symbolic_reg == SymbolicRegister::Sysv && config.image_mode == ImageMode::Elf {
        session.mark_et_rel_abi_scratch_symbolic()?;
    }
    let digest = session.sustained_initial_digest().map_err(|error| {
        format!("root cannot be pinned for sustained replay ({:?}; pe-driver is a loader model, not Windows fidelity): {error}", config.image_mode)
    })?;
    Ok((entry, digest))
}

#[cfg(target_arch = "x86_64")]
fn execute(config: &Config, image: &[u8], manifest: &CampaignManifest, grant: &WireGrant) -> Result<AdvanceOutcome> {
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let root = configure_root(
        config,
        match config.image_mode {
            ImageMode::Elf => runtime.load_elf(image)?,
            ImageMode::PeDriver => runtime.load_pe_driver(image)?,
        },
    )?;
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), root);
    for reg_id in config.symbolic_reg.register_ids() {
        session.mark_symbolic(0, reg_id, IrType::Bits(64))?;
    }
    if config.symbolic_reg == SymbolicRegister::Sysv && config.image_mode == ImageMode::Elf {
        session.mark_et_rel_abi_scratch_symbolic()?;
    }
    let mut solver = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
    Ok(session.advance_sustained(&grant.fence, manifest, &mut solver, grant.timeout, grant.step_budget)?)
}

#[cfg(target_arch = "x86_64")]
fn verify(
    config: &Config,
    image: &[u8],
    campaign: &SustainedCampaign,
    grant: &WireGrant,
    claimed: &AdvanceOutcome,
) -> Result<VerifiedRemoteOutcome> {
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let root = configure_root(
        config,
        match config.image_mode {
            ImageMode::Elf => runtime.load_elf(image)?,
            ImageMode::PeDriver => runtime.load_pe_driver(image)?,
        },
    )?;
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), root);
    for reg_id in config.symbolic_reg.register_ids() {
        session.mark_symbolic(0, reg_id, IrType::Bits(64))?;
    }
    if config.symbolic_reg == SymbolicRegister::Sysv && config.image_mode == ImageMode::Elf {
        session.mark_et_rel_abi_scratch_symbolic()?;
    }
    let mut solver = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
    Ok(campaign.verify_remote(
        &grant.fence,
        claimed,
        &mut session,
        &mut solver,
        grant.timeout,
        grant.step_budget,
    )?)
}

/// The worker never opens or modifies the ledger. Each accepted connection runs
/// one leased subtree and returns one typed outcome; failures close the session.
#[cfg(target_arch = "x86_64")]
pub fn serve(config: &Config, addr: SocketAddr, max_connections: u64) -> Result<()> {
    serve_with_image(config, addr, max_connections, read_image(config)?)
}

/// Serve only the image bytes matching the digest returned by `WorkerConfig::load`.
#[cfg(target_arch = "x86_64")]
pub fn serve_pinned(
    config: &Config,
    addr: SocketAddr,
    max_connections: u64,
    expected_image_sha256: &str,
) -> Result<()> {
    let image = read_image(config)?;
    if format!("{:x}", Sha256::digest(&image)) != expected_image_sha256 {
        return Err("worker image SHA256 mismatch".into());
    }
    serve_with_image(config, addr, max_connections, image)
}

#[cfg(target_arch = "x86_64")]
fn serve_with_image(config: &Config, addr: SocketAddr, max_connections: u64, image: Vec<u8>) -> Result<()> {
    let (entry, initial_digest) = initial(config, &image)?;
    let profile = build_profile()?;
    let policy = config.policy(entry);
    let manifest = manifest(config, &image, entry, &profile)?;
    manifest.validate_artifacts(&artifacts(&image, &profile, &policy))?;
    peer_id(&config.worker_id)?;
    let secret = key(&config.key_file)?;
    let server = TcpServer::bind(addr)?;
    println!("READY {}", server.local_addr()?);
    use std::io::Write as _;
    io::stdout().flush()?;
    let mut connections = 0u64;
    while max_connections == 0 || connections < max_connections {
        let mut session = match server.accept(
            transport(manifest.clone(), &config.worker_id, COORDINATOR, secret)?,
            COORDINATOR,
        ) {
            Ok(session) => session,
            Err(error) => {
                eprintln!("rejected connection: {error}");
                continue;
            }
        };
        connections += 1;
        session.set_timeouts(Duration::from_secs(15))?;
        session.set_deadline(Some(Instant::now() + Duration::from_secs(15)));
        let result = (|| -> Result<()> {
            let received = session.receive()?;
            session.set_deadline(None);
            session.set_timeouts(Duration::from_secs(15))?;
            let Message::Grant { work, payload } = received.message else {
                return Err("expected fenced grant".into());
            };
            let grant = WireGrant::decode(work.clone(), &payload, &manifest)?;
            if grant.fence.owner_id != Digest::of(config.worker_id.as_bytes())
                || grant.fence.reservation.replay.initial_state_digest != initial_digest
            {
                return Err("worker owner or pinned root digest mismatch".into());
            }
            let outcome = execute(config, &image, &manifest, &grant)?;
            session.send(&Message::Outcome {
                work,
                payload: outcome.encode_wire()?,
            })?;
            Ok(())
        })();
        if let Err(error) = result {
            eprintln!("worker rejected grant: {error}");
        }
    }
    Ok(())
}

fn peer_id(id: &str) -> Result<()> {
    if id.is_empty()
        || id == COORDINATOR
        || id.len() > 128
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._".contains(&byte))
    {
        return Err("worker ID must be a distinct 1..128 byte token".into());
    }
    Ok(())
}

/// Coordinator-owned outcome of one sustained campaign run: the single-writer
/// ledger's committed status counters plus the coordinator's accepted evidence
/// snapshot.
pub struct CampaignOutcome {
    /// Committed ledger counters. A run that stops at a declared limit still
    /// returns `Ok` with `complete_within_declared_bounds == false`.
    pub report: Report,
    /// The coordinator's independently verified accepted evidence snapshot:
    /// the latest accepted disposition for each path in the durable ledger,
    /// including deferred events. Never transient worker claims.
    pub accepted_evidence: Vec<AcceptedEvidence>,
}

/// Single-writer ledger admission; network I/O alone runs on parallel threads.
/// Each round joins every request before replaying and committing in reservation order.
#[cfg(target_arch = "x86_64")]
pub fn coordinate_with_evidence(config: &Config, addr: SocketAddr, ledger: PathBuf) -> Result<CampaignOutcome> {
    let peers = if config.peers.is_empty() {
        vec![Peer {
            id: config.worker_id.clone(),
            addr,
            key_file: config.key_file.clone(),
        }]
    } else {
        config.peers.clone()
    };
    if !matches!(peers.len(), 1 | 2 | 4) {
        return Err("pool requires exactly 1, 2 or 4 workers".into());
    }
    let mut ids = HashSet::new();
    let mut addresses = HashSet::new();
    let mut secrets = HashSet::new();
    let mut authenticated = Vec::new();
    for peer in peers {
        peer_id(&peer.id)?;
        if !peer.addr.ip().is_loopback() || !ids.insert(peer.id.clone()) || !addresses.insert(peer.addr) {
            return Err("workers require distinct IDs and loopback addresses".into());
        }
        let secret = key(&peer.key_file)?;
        if !secrets.insert(secret) {
            return Err("workers require distinct pairwise keys".into());
        }
        authenticated.push((peer, secret));
    }
    let image = read_image(config)?;
    let (entry, initial_digest) = initial(config, &image)?;
    let profile = build_profile()?;
    let policy = config.policy(entry);
    let manifest = manifest(config, &image, entry, &profile)?;
    let progress_path = config
        .progress_jsonl
        .clone()
        .unwrap_or_else(|| progress::default_path(&ledger));
    let mut campaign = SustainedCampaign::open(
        ledger.clone(),
        manifest.clone(),
        &artifacts(&image, &profile, &policy),
        initial_digest,
    )?;
    let mut journal = progress::ProgressJournal::reconcile(
        progress_path.clone(),
        &ledger,
        manifest.campaign_digest,
        campaign.accepted_events(),
    )?;
    println!(
        "campaign startup: progress journal {} ({}) with {} ledger-accepted events",
        progress_path.display(),
        if journal.recovered() {
            "recovered/rebuilt"
        } else {
            "validated"
        },
        campaign.accepted_events().len()
    );
    use std::io::Write as _;
    io::stdout().flush()?;
    let start = Instant::now();
    let deadline = Duration::from_millis(config.limits.max_wall_millis);
    let campaign_deadline = start + deadline;
    let mut used_steps = 0u64;
    while start.elapsed() < deadline && used_steps < config.limits.max_steps {
        let mut grants = Vec::new();
        for (peer, _) in &authenticated {
            if used_steps + grants.len() as u64 >= config.limits.max_steps {
                break;
            }
            match campaign.reserve_remote(Digest::of(peer.id.as_bytes())) {
                Ok(Some(fence)) => grants.push(fence),
                Ok(None) => break,
                Err(error) => {
                    for fence in &grants {
                        campaign.revoke_remote(fence)?;
                    }
                    return Err(error.into());
                }
            }
        }
        if grants.is_empty() {
            break;
        }
        println!(
            "campaign active: {} worker grant(s) dispatched; accepted={} (active is not accepted)",
            grants.len(),
            campaign.accepted_events().len()
        );
        io::stdout().flush()?;
        let remaining = campaign_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            for fence in &grants {
                campaign.revoke_remote(fence)?;
            }
            break;
        }
        let count = grants.len() as u64;
        let available = config.limits.max_steps - used_steps;
        let round_deadline = campaign_deadline;
        let results = thread::scope(|scope| {
            let mut handles = Vec::new();
            for (index, fence) in grants.iter().cloned().enumerate() {
                let (peer, secret) = &authenticated[index];
                let budget = available / count + u64::from((index as u64) < available % count);
                let grant = WireGrant {
                    fence,
                    timeout: remaining,
                    step_budget: budget,
                };
                let manifest = &manifest;
                handles.push(scope.spawn(move || {
                    let result = request(peer, *secret, manifest, &grant, round_deadline);
                    (grant, result)
                }));
            }
            handles.into_iter().map(|handle| handle.join()).collect::<Vec<_>>()
        });
        let mut processed = 0usize;
        let mut wall_limit = false;
        let admission = (|| -> Result<()> {
            for result in results {
                let (grant, outcome) = result.map_err(|_| "network worker thread panicked")?;
                let outcome = match outcome {
                    Ok(outcome) => outcome,
                    Err(RoundAbort::Fault(error)) => return Err(error.into()),
                    // The declared wall bound elapsed while this grant was in
                    // flight: stop the round at the bound instead of failing.
                    Err(RoundAbort::WallLimitElapsed) => {
                        wall_limit = true;
                        break;
                    }
                };
                let verified = verify(config, &image, &campaign, &grant, &outcome)?;
                let violation_reason = verified
                    .reason()
                    .starts_with("kernel ")
                    .then(|| verified.reason().to_owned());
                if start.elapsed() >= deadline {
                    // No commit after the declared bound: the verified outcome is
                    // dropped and its still-active grant is revoked below.
                    wall_limit = true;
                    break;
                }
                let steps = campaign.commit_remote(&grant.fence, verified, grant.step_budget)?;
                // The ledger commit is authoritative and cannot be undone: count
                // this grant as processed before the progress projection append so
                // a projection failure never revokes an already committed grant.
                processed += 1;
                let accepted = journal.append_new(manifest.campaign_digest, campaign.accepted_events())?;
                for index in accepted {
                    let event = &campaign.accepted_events()[index];
                    println!(
                        "accepted {}",
                        progress::event_json(manifest.campaign_digest, index, event)
                    );
                    if let Some(reason) = &violation_reason {
                        let verified_witness = event.delta.path.witness.as_ref().is_some_and(|w| {
                            matches!(w.replay, angryier_ledger::evidence::ReplayVerification::Verified { .. })
                        });
                        let campaign_hex: String =
                            manifest.campaign_digest.0.iter().map(|b| format!("{b:02x}")).collect();
                        let path_hex: String = event.delta.path.path_id.iter().map(|b| format!("{b:02x}")).collect();
                        println!(
                            "violation {{\"event_id\":\"{campaign_hex}:{index}\",\"path_id\":\"{path_hex}\",\"reason\":\"{reason}\",\"witness_replay_verified\":{verified_witness}}}"
                        );
                    }
                    io::stdout().flush()?;
                }
                used_steps = used_steps.checked_add(steps).ok_or("step budget overflow")?;
            }
            Ok(())
        })();
        if let Err(error) = admission {
            // Revoke every grant that is still active, but keep the admission
            // error: a failed revocation must neither mask it nor stop the
            // remaining grants from being revoked.
            release_uncommitted(&mut campaign, &grants, processed);
            return Err(error);
        }
        if wall_limit {
            // Stop at the declared wall bound: revoke only the grants that were
            // never committed, keep every committed event, and fall through to
            // the durable partial report. A revocation failure cannot mask the
            // bound stop, so it is reported without changing the outcome.
            release_uncommitted(&mut campaign, &grants, processed);
            println!(
                "campaign wall limit reached: stopped at the declared bound with {} grant(s) revoked",
                grants.len() - processed
            );
            io::stdout().flush()?;
            break;
        }
        if used_steps >= config.limits.max_steps {
            break;
        }
    }
    if config.image_mode == ImageMode::PeDriver {
        eprintln!("pe-driver report: Explore under a modeled driver ABI; not Windows GUI execution");
    }
    let report = campaign.report();
    if !report.complete_within_declared_bounds {
        println!(
            "campaign partial: accepted={} unresolved work remains",
            campaign.accepted_events().len()
        );
        io::stdout().flush()?;
    }
    // The accepted snapshot is read after the final verified commit, so it
    // includes every deferred event the coordinator accepted into the ledger.
    let accepted_evidence = campaign.cumulative_evidence().cloned().collect();
    Ok(CampaignOutcome {
        report,
        accepted_evidence,
    })
}

/// [`coordinate_with_evidence`] without the evidence snapshot; preserves the
/// original ledger-counter-only API and behavior unchanged.
#[cfg(target_arch = "x86_64")]
pub fn coordinate(config: &Config, addr: SocketAddr, ledger: PathBuf) -> Result<Report> {
    Ok(coordinate_with_evidence(config, addr, ledger)?.report)
}

#[cfg(target_arch = "x86_64")]
/// Revoke the grants a stopped round never committed. A failed revocation is
/// reported but never replaces the round's own outcome, and a committed grant
/// is never passed here, so no grant is revoked twice.
fn release_uncommitted(campaign: &mut SustainedCampaign, grants: &[FencedReservation], processed: usize) {
    let mut cleanup_failed = Vec::new();
    for fence in &grants[processed..] {
        if let Err(revoke) = campaign.revoke_remote(fence) {
            cleanup_failed.push(revoke.to_string());
        }
    }
    if !cleanup_failed.is_empty() {
        eprintln!(
            "campaign cleanup: {} grant revocation(s) failed: {}",
            cleanup_failed.len(),
            cleanup_failed.join("; ")
        );
    }
}

#[cfg(target_arch = "x86_64")]
/// Why one grant round stopped without an admitted result.
#[derive(Debug, PartialEq, Eq)]
enum RoundAbort {
    /// The declared wall bound elapsed while this grant was in flight. The
    /// round stops cleanly and reports its durable partial ledger instead of
    /// surfacing the expired socket timeout as a transport error.
    WallLimitElapsed,
    /// A transport or protocol fault observed before the wall bound; this
    /// stays a hard error so a genuine worker fault is never masked.
    Fault(String),
}

/// The wall bound is reached only once that instant has actually passed; a
/// timeout that fires while budget remains is a worker fault, not a bound stop.
#[cfg(target_arch = "x86_64")]
fn wall_bound_elapsed(deadline: Instant, now: Instant) -> bool {
    now >= deadline
}

/// Classify one transport error against the campaign wall bound.
#[cfg(target_arch = "x86_64")]
fn round_abort(error: TcpError, deadline: Instant) -> RoundAbort {
    let timed_out = match &error {
        TcpError::Io(source) => {
            matches!(source.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
        }
        TcpError::InsecureEndpoint | TcpError::Protocol(_) => false,
    };
    if timed_out && wall_bound_elapsed(deadline, Instant::now()) {
        RoundAbort::WallLimitElapsed
    } else {
        RoundAbort::Fault(error.to_string())
    }
}

/// One worker request. The deadline bounds connect, handshake, send and receive;
/// only a timeout at that bound is reported as [`RoundAbort::WallLimitElapsed`].
#[cfg(target_arch = "x86_64")]
fn request(
    peer: &Peer,
    secret: [u8; 32],
    manifest: &CampaignManifest,
    grant: &WireGrant,
    deadline: Instant,
) -> std::result::Result<AdvanceOutcome, RoundAbort> {
    let mut session = TcpSession::connect_until(
        peer.addr,
        transport(manifest.clone(), COORDINATOR, &peer.id, secret)
            .map_err(|error| RoundAbort::Fault(error.to_string()))?,
        &peer.id,
        deadline,
    )
    .map_err(|error| round_abort(error, deadline))?;
    session
        .send(&Message::Grant {
            work: grant.fence.reservation.unit.clone(),
            payload: grant.encode().map_err(|error| RoundAbort::Fault(error.to_string()))?,
        })
        .map_err(|error| round_abort(error, deadline))?;
    let received = session.receive().map_err(|error| round_abort(error, deadline))?;
    if wall_bound_elapsed(deadline, Instant::now()) {
        return Err(RoundAbort::WallLimitElapsed);
    }
    let Message::Outcome { work, payload } = received.message else {
        return Err(RoundAbort::Fault("worker did not return typed outcome".into()));
    };
    if work != grant.fence.reservation.unit {
        return Err(RoundAbort::Fault("result work identity mismatch".into()));
    }
    AdvanceOutcome::decode_wire(work, &payload, manifest).map_err(|error| RoundAbort::Fault(error.to_string()))
}

#[cfg(not(target_arch = "x86_64"))]
pub fn unsupported_architecture() -> Result<()> {
    Err("native XED + Z3 campaign worker currently supports only x86_64 ELF or opt-in PE32+ driver model; ARM64 and Windows are not emulated".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_mode_and_symbolic_register_parse_fail_closed() {
        assert_eq!("elf".parse::<ImageMode>(), Ok(ImageMode::Elf));
        assert_eq!("pe-driver".parse::<ImageMode>(), Ok(ImageMode::PeDriver));
        assert!("pe-user".parse::<ImageMode>().is_err());
        assert_eq!("rbx".parse::<SymbolicRegister>(), Ok(SymbolicRegister::Rbx));
        assert_eq!("rcx".parse::<SymbolicRegister>(), Ok(SymbolicRegister::Rcx));
        assert_eq!("rdx".parse::<SymbolicRegister>(), Ok(SymbolicRegister::Rdx));
        assert_eq!("rsi".parse::<SymbolicRegister>(), Ok(SymbolicRegister::Rsi));
        assert_eq!("rdi".parse::<SymbolicRegister>(), Ok(SymbolicRegister::Rdi));
        assert_eq!("sysv".parse::<SymbolicRegister>(), Ok(SymbolicRegister::Sysv));
        for name in ["rax", "rsp", "RCX", "", "1"] {
            assert!(name.parse::<SymbolicRegister>().is_err(), "accepted {name}");
        }
        #[cfg(target_arch = "x86_64")]
        {
            assert_eq!(SymbolicRegister::Rbx.register_ids(), vec![register_id::GPR_BASE + 3]);
            assert_eq!(SymbolicRegister::Rcx.register_ids(), vec![register_id::GPR_BASE + 1]);
            assert_eq!(SymbolicRegister::Rdx.register_ids(), vec![register_id::GPR_BASE + 2]);
            assert_eq!(SymbolicRegister::Rsi.register_ids(), vec![register_id::GPR_BASE + 6]);
            assert_eq!(SymbolicRegister::Rdi.register_ids(), vec![register_id::GPR_BASE + 7]);
            assert_eq!(
                SymbolicRegister::Sysv.register_ids(),
                vec![register_id::GPR_BASE + 6, register_id::GPR_BASE + 2]
            );
        }
    }

    #[test]
    fn manifest_pins_effective_ram_cap_and_fidelity() -> Result<()> {
        let mut config = Config::defaults(PathBuf::new(), PathBuf::new(), "test-v1".into());
        let seal = |cfg: &Config| manifest(cfg, b"image", 0x1000, b"profile");
        let elf = seal(&config)?;
        assert_eq!(elf.spec.limits.max_ram_bytes, 64 << 20);
        assert_eq!(elf.spec.fidelity, FidelityProfile::Prove);

        config.image_mode = ImageMode::PeDriver;
        let pe = seal(&config)?;
        assert_eq!(pe.spec.limits.max_ram_bytes, 576 << 20);
        assert_eq!(pe.spec.fidelity, FidelityProfile::Explore);

        config.limits.max_ram_bytes = (64_u64 << 20).to_string().parse()?;
        let limited = seal(&config)?;
        assert_eq!(limited.spec.limits.max_ram_bytes, 64 << 20);
        assert_ne!(limited.campaign_digest, pe.campaign_digest);
        config.limits.max_ram_bytes = RamCap::Bytes(576 << 20);
        assert_eq!(seal(&config)?.campaign_digest, pe.campaign_digest);
        config.limits.max_ram_bytes = "0".parse()?;
        assert!(seal(&config).is_err());
        Ok(())
    }

    #[test]
    fn manifest_policy_pins_mode_resolved_entry_and_register() -> Result<()> {
        let mut config = Config::defaults(PathBuf::new(), PathBuf::new(), "test-v1".into());
        let base = manifest(&config, b"image", 0x1000, b"profile")?;
        assert_eq!(base.spec.policy_digest, Digest::of(&config.policy(0x1000)));
        assert_ne!(
            base.spec.policy_digest,
            manifest(&config, b"image", 0x1001, b"profile")?.spec.policy_digest
        );
        config.symbolic_reg = SymbolicRegister::Rcx;
        assert_ne!(
            base.spec.policy_digest,
            manifest(&config, b"image", 0x1000, b"profile")?.spec.policy_digest
        );
        config.symbolic_reg = SymbolicRegister::Rbx;
        config.image_mode = ImageMode::PeDriver;
        assert_ne!(
            base.spec.policy_digest,
            manifest(&config, b"image", 0x1000, b"profile")?.spec.policy_digest
        );
        config.entry = Some(0x1001);
        assert!(manifest(&config, b"image", 0x1000, b"profile").is_err());
        Ok(())
    }

    /// Tiny valid AMD64 PE32+ image: DOS header, COFF + PE32+ optional
    /// headers (fixed 0xf0 optional size, section table at 0x188) and one
    /// entry per `(VirtualSize, VirtualAddress, SizeOfRawData)` tuple, with
    /// raw data at 0x200 inside a 0x400-byte file.
    fn synthetic_pe(sections: &[(u32, u32, u32)]) -> Vec<u8> {
        let mut pe = vec![0u8; 0x400];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        pe[0x86..0x88].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        pe[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
        pe[0x98..0x9a].copy_from_slice(&0x020bu16.to_le_bytes());
        for (index, &(virtual_size, virtual_address, raw_size)) in sections.iter().enumerate() {
            let off = 0x188 + index * 40;
            pe[off + 8..off + 12].copy_from_slice(&virtual_size.to_le_bytes());
            pe[off + 12..off + 16].copy_from_slice(&virtual_address.to_le_bytes());
            pe[off + 16..off + 20].copy_from_slice(&raw_size.to_le_bytes());
            pe[off + 20..off + 24].copy_from_slice(&0x200u32.to_le_bytes());
            pe[off + 36..off + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes());
        }
        pe
    }

    #[test]
    fn pe_preflight_bounds_mapped_ram_before_load() -> Result<()> {
        // One huge virtual section against an explicit cap: rejected before
        // the loader can allocate the zero-extended mapping.
        let huge = synthetic_pe(&[(0xFFFF_F000, 0x1000, 0x200)]);
        let Err(error) = preflight_pe_mapped_ram(&huge, 64 << 20) else {
            return Err("huge virtual section must be rejected before load".into());
        };
        let message = error.to_string();
        assert!(message.contains("exceeds max-ram-bytes"), "{message}");
        // The mode default (576 MiB) bounds the same ~4 GiB virtual section.
        assert!(preflight_pe_mapped_ram(&huge, 576 << 20).is_err());
        // A sane section still fits the explicit cap.
        assert!(preflight_pe_mapped_ram(&synthetic_pe(&[(0x200, 0x1000, 0x200)]), 64 << 20).is_ok());
        // The checked sum bounds moderate sections that overflow together.
        let sum = synthetic_pe(&[(32 << 20, 0x1000, 0x200), (32 << 20, 0x2000, 0x200)]);
        assert!(preflight_pe_mapped_ram(&sum, 64 << 20).is_err());
        assert!(preflight_pe_mapped_ram(&sum, 96 << 20).is_ok());
        Ok(())
    }

    #[test]
    fn pe_preflight_rejects_malformed_tables_and_raw_ranges() {
        // Section table pushed past the end of the file.
        let mut beyond = synthetic_pe(&[(0x200, 0x1000, 0x200)]);
        beyond[0x94..0x96].copy_from_slice(&0x400u16.to_le_bytes());
        assert!(preflight_pe_mapped_ram(&beyond, 576 << 20).is_err());
        // Raw pointer + size leaving the file.
        let mut raw = synthetic_pe(&[(0x200, 0x1000, 0x200)]);
        raw[0x198..0x19c].copy_from_slice(&0x300u32.to_le_bytes());
        assert!(preflight_pe_mapped_ram(&raw, 576 << 20).is_err());
        // Truncated headers fail closed.
        assert!(preflight_pe_mapped_ram(&synthetic_pe(&[])[..0x3a], 576 << 20).is_err());
    }

    #[test]
    fn read_image_bounds_pe_mapped_ram_before_load() -> Result<()> {
        struct Temp(PathBuf);
        impl Drop for Temp {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let dir = Temp(std::env::temp_dir().join(format!("angryier-pe-preflight-{}", std::process::id())));
        fs::create_dir_all(&dir.0)?;
        let binary = dir.0.join("huge.sys");
        fs::write(&binary, synthetic_pe(&[(0xFFFF_F000, 0x1000, 0x200)]))?;
        let mut config = Config::defaults(binary, PathBuf::new(), "test-v1".into());
        config.image_mode = ImageMode::PeDriver;
        config.limits.max_ram_bytes = RamCap::Bytes(64 << 20);
        let Err(error) = read_image(&config) else {
            return Err("read_image must reject the huge virtual section before load".into());
        };
        let message = error.to_string();
        assert!(message.contains("exceeds max-ram-bytes"), "{message}");
        // The mode default (576 MiB) rejects the same image pre-load.
        config.limits.max_ram_bytes = RamCap::ModeDefault;
        assert!(read_image(&config).is_err());
        // A sane section passes the explicit cap unchanged.
        fs::write(&config.binary, synthetic_pe(&[(0x200, 0x1000, 0x200)]))?;
        config.limits.max_ram_bytes = RamCap::Bytes(64 << 20);
        assert_eq!(read_image(&config)?.len(), 0x400);
        Ok(())
    }

    /// Compile/API pin for the public coordinator surface: `coordinate` keeps
    /// its counter-only signature while `coordinate_with_evidence` returns the
    /// accepted evidence snapshot alongside the report.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn campaign_outcome_public_api_and_wrapper_pin() {
        let _: fn(&Config, SocketAddr, PathBuf) -> Result<CampaignOutcome> = coordinate_with_evidence;
        let _: fn(&Config, SocketAddr, PathBuf) -> Result<Report> = coordinate;
        // A partial campaign's report stays Ok with
        // complete_within_declared_bounds == false, and the accepted snapshot
        // is an empty coordinator-owned ledger view, never a worker claim.
        let outcome = CampaignOutcome {
            report: Report::default(),
            accepted_evidence: Vec::new(),
        };
        assert!(!outcome.report.complete_within_declared_bounds);
        assert!(outcome.accepted_evidence.is_empty());
    }

    /// The declared wall bound is reached only once it has actually elapsed, so
    /// budget remaining at the check keeps every verified commit admissible.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn wall_bound_gate_requires_an_elapsed_deadline() {
        let start = Instant::now();
        let bound = start + Duration::from_millis(400);
        assert!(!wall_bound_elapsed(bound, start));
        assert!(!wall_bound_elapsed(bound, bound - Duration::from_millis(1)));
        assert!(wall_bound_elapsed(bound, bound));
        assert!(wall_bound_elapsed(bound, bound + Duration::from_millis(1)));
    }

    /// A socket timeout at the wall bound stops the round cleanly, while the
    /// same timeout before the bound (and any non-timeout fault) stays a hard
    /// error so genuine worker faults are never masked as a bound stop.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn round_abort_is_a_wall_stop_only_after_the_bound() {
        let elapsed = Instant::now() - Duration::from_millis(1);
        let pending = Instant::now() + Duration::from_secs(60);
        for kind in [io::ErrorKind::WouldBlock, io::ErrorKind::TimedOut] {
            assert_eq!(
                round_abort(TcpError::Io(io::Error::from(kind)), elapsed),
                RoundAbort::WallLimitElapsed,
                "{kind:?} at the wall bound must stop the round"
            );
            assert!(
                matches!(
                    round_abort(TcpError::Io(io::Error::from(kind)), pending),
                    RoundAbort::Fault(_)
                ),
                "{kind:?} before the wall bound must stay a hard error"
            );
        }
        for fault in [
            TcpError::InsecureEndpoint,
            TcpError::Io(io::Error::from(io::ErrorKind::ConnectionReset)),
        ] {
            assert!(
                matches!(round_abort(fault, elapsed), RoundAbort::Fault(_)),
                "a non-timeout fault is never a wall-limit stop"
            );
        }
    }

    /// A bound stop revokes only the grants the round never committed: the
    /// committed prefix keeps its active ledger record, the uncommitted grant
    /// returns to the queue, no evidence is accepted, and the report stays a
    /// partial one instead of an error.
    #[cfg(target_arch = "x86_64")]
    #[test]
    fn wall_stop_releases_only_uncommitted_grants() -> Result<()> {
        struct Temp(PathBuf);
        impl Drop for Temp {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let dir = Temp(std::env::temp_dir().join(format!("angryier-wall-stop-{}", std::process::id())));
        fs::create_dir_all(&dir.0)?;
        let config = Config::defaults(PathBuf::new(), PathBuf::new(), "test-v1".into());
        let (image, profile) = (&b"image"[..], &b"profile"[..]);
        let policy = config.policy(0x1000);
        let sealed = manifest(&config, image, 0x1000, profile)?;
        let artifacts = CampaignArtifacts {
            binary: image,
            semantic_profile: profile,
            script: b"no-script",
            policy: &policy,
            solver_policy: b"z3-native-v1",
            inputs: Vec::new(),
            stubs: Vec::new(),
        };
        let mut campaign = SustainedCampaign::open(
            dir.0.join("campaign.ledger"),
            sealed,
            &artifacts,
            Digest::of(b"initial"),
        )?;
        let grants = vec![
            campaign
                .reserve_remote(Digest::of(b"worker"))?
                .ok_or("root grant must be available")?,
        ];
        // A committed prefix is never revoked, so a round that committed every
        // grant leaves all of them active.
        release_uncommitted(&mut campaign, &grants, grants.len());
        let report = campaign.report();
        assert_eq!(
            (report.active, report.queued),
            (1, 0),
            "a committed grant must stay active"
        );
        // The bound stop releases only the uncommitted suffix.
        release_uncommitted(&mut campaign, &grants, 0);
        let report = campaign.report();
        assert_eq!(
            (report.queued, report.active),
            (1, 0),
            "uncommitted grant was not requeued"
        );
        assert_eq!(
            campaign.cumulative_evidence().count(),
            0,
            "a bound stop accepted evidence"
        );
        assert!(
            !report.complete_within_declared_bounds,
            "stalled work must be reported as partial"
        );
        // A grant is released exactly once: the ledger refuses a second revoke.
        assert!(
            campaign.revoke_remote(&grants[0]).is_err(),
            "double revoke must be refused"
        );
        Ok(())
    }
}
