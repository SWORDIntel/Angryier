//! Typed in-host sustained campaign API: the production Rust mirror of the
//! `angry.sustained` Lua contract (docs/LUA_API.md §9 and
//! `angryier_runtime::script::prepared::LuaSustained`) reusing this crate's
//! pinned-root machinery ([`crate::initial`], [`crate::configure_root`],
//! [`crate::read_image`]) and the runtime's durable
//! `SustainedCampaign`/`run_sustained_ranked` with the native Z3 backend.
//!
//! Local-mode invariants, mirroring the Lua contract's explicit rejections:
//! - Only static ELF64 x86-64 images at their image entry
//!   ([`ImageMode::PeDriver`] and `Config::entry` overrides are rejected);
//!   there is no network peer, no hidden worker and no progress journal.
//! - The root is rebuilt from the image file before every
//!   [`LocalCampaign::advance`]; the image bytes are re-validated against the
//!   sealed manifest digest and the rebuilt root digest against the pinned
//!   ledger root.
//! - The ForkAll(v1)/RankTargets(v2) choice and the canonical `find`/`avoid`
//!   lists (plus the `exclude_avoid` flag and a digest of the whole local
//!   specification) are sealed into the manifest's script/policy digests. A
//!   resume with any different specification therefore fails with the
//!   ledger's `MismatchedCampaign` error instead of reopening foreign work —
//!   the same mechanism rejects ledgers created by the Lua `angry.sustained`
//!   path, whose sealed script/policy bytes differ. Resume never overwrites
//!   or reinitializes an existing ledger, and start never overwrites one.
//!
//! Root marks and seeds are local-only and sealed in the options digest;
//! this does not imply interchangeability with Lua-created ledgers.
use std::{path::PathBuf, str::FromStr};

use angryier_distribution::contracts::{CampaignManifest, Digest};
use angryier_ledger::{evidence::AcceptedEvidence, sustained::Report};

use crate::{Config, ImageMode, Result, SymbolicRegister};

/// Local sustained-campaign specification: a [`Config`] narrowed to the local
/// contract, the durable ledger path, the typed exploration policy, and the
/// find/avoid target lists.
///
/// `find`/`avoid` are observations and ranking hints, never pruning: under
/// [`LocalPolicy::ForkAll`] they are purely observational, and under
/// [`LocalPolicy::RankTargets`] they rank reservation order (find matches
/// first, neutral successors next, avoid last). Only
/// `RankTargets { exclude_avoid: true }` excludes, and only at an exact
/// validated dynamic branch successor with a solver proof. Lists are sorted
/// canonically before pinning (reordering does not change campaign identity;
/// duplicates or more than 4096 entries are rejected).
#[derive(Clone)]
pub struct LocalConfig {
    pub campaign: Config,
    pub ledger: PathBuf,
    pub policy: LocalPolicy,
    pub find: Vec<u64>,
    pub avoid: Vec<u64>,
    /// None retains the distributed Config's default single symbolic GPR;
    /// Some explicitly replaces it with one or more 64-bit GPR marks.
    pub symbolic: Option<Vec<(LocalRegister, u16)>>,
    /// Concrete u64 seeds for distinct GPRs, disjoint from symbolic marks.
    pub regs: Vec<(LocalRegister, u64)>,
}

/// A canonical x86-64 general-purpose register (no aliases or partial widths).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct LocalRegister(u8);

impl LocalRegister {
    const NAMES: [&'static str; 16] = [
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    ];

    pub fn name(self) -> &'static str {
        Self::NAMES[self.0 as usize]
    }

    #[cfg(target_arch = "x86_64")]
    fn register_id(self) -> u32 {
        angryier_arch_intel64::register_id::GPR_BASE + u32::from(self.0)
    }
}

impl FromStr for LocalRegister {
    type Err = &'static str;

    fn from_str(name: &str) -> std::result::Result<Self, Self::Err> {
        Self::NAMES
            .iter()
            .position(|candidate| *candidate == name)
            .map(|index| Self(index as u8))
            .ok_or("local: expected canonical x86-64 GPR name (rax..r15)")
    }
}

/// Local exploration policy. `ForkAll` is the FIFO `fork-all/v1` contract
/// (`angry.sustained/v1`); `RankTargets` is the `rank-targets/v1` contract
/// (`angry.sustained/v2`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalPolicy {
    ForkAll,
    RankTargets { exclude_avoid: bool },
}

impl LocalPolicy {
    /// Script artifact label sealed in the manifest; v1 = fork-all, v2 =
    /// rank-targets.
    fn script_label(self) -> &'static [u8] {
        match self {
            Self::ForkAll => b"angryier.local/sustained/v1",
            Self::RankTargets { .. } => b"angryier.local/sustained/v2",
        }
    }

    /// Policy tag appended to the sealed policy bytes when targets or the
    /// ranked policy are in play (mirrors the Lua `observational-targets/v1`
    /// and `rank-targets/v1` markers).
    fn policy_tag(self) -> &'static [u8] {
        match self {
            Self::ForkAll => b"observational-targets/v1",
            Self::RankTargets { .. } => b"rank-targets/v1",
        }
    }
}

/// Outcome of one [`LocalCampaign::advance`]: the committed ledger report,
/// the local runner's step count and stop reason, and the accepted evidence
/// snapshot (the latest accepted disposition per path, including deferred
/// events, as durably accepted by the single-writer ledger).
#[derive(Debug)]
pub struct LocalOutcome {
    pub report: Report,
    pub steps: u64,
    pub reason: Option<String>,
    pub accepted_evidence: Vec<AcceptedEvidence>,
}

/// A durable local sustained campaign. Constructed only through
/// [`LocalCampaign::start`] or [`LocalCampaign::resume`]; both validate the
/// pinned image, manifest, artifacts and root before any work is reserved.
#[cfg_attr(not(target_arch = "x86_64"), allow(dead_code))]
pub struct LocalCampaign {
    config: LocalConfig,
    manifest: CampaignManifest,
    entry: u64,
    initial: Digest,
    campaign: angryier_runtime::sustained::SustainedCampaign,
}

/// Sort and validate one target list: at most 4096 addresses, canonically
/// sorted, no duplicates (the Lua contract's dense-array rules).
fn canonical_targets(mut config: LocalConfig) -> Result<LocalConfig> {
    for (name, list) in [("find", &mut config.find), ("avoid", &mut config.avoid)] {
        if list.len() > 4096 {
            return Err(format!("local: targets.{name} accepts at most 4096 addresses").into());
        }
        list.sort_unstable();
        if list.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(format!("local: duplicate targets.{name} address").into());
        }
    }
    if let Some(symbolic) = &mut config.symbolic {
        if symbolic.is_empty() {
            return Err("local: explicit symbolic registers cannot be empty; use None for the default".into());
        }
        symbolic.sort_unstable_by_key(|(register, _)| *register);
        for (register, width) in symbolic.iter() {
            if *width != 64 {
                return Err(format!("local: symbolic {} must have width 64", register.name()).into());
            }
        }
        if symbolic.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err("local: duplicate symbolic register".into());
        }
    }
    config.regs.sort_unstable_by_key(|(register, _)| *register);
    if config.regs.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return Err("local: duplicate concrete register seed".into());
    }
    if config.regs.iter().any(|(register, _)| {
        config.symbolic.as_ref().map_or_else(
            || {
                register.name()
                    == match config.campaign.symbolic_reg {
                        SymbolicRegister::Rbx => "rbx",
                        SymbolicRegister::Rcx => "rcx",
                    }
            },
            |symbolic| symbolic.iter().any(|(marked, _)| register == marked),
        )
    }) {
        return Err("local: register cannot be both symbolic and concretely seeded".into());
    }
    Ok(config)
}

/// Reject the [`Config`] fields the local contract does not support, instead
/// of silently ignoring them.
fn validate_local(config: &LocalConfig) -> Result<()> {
    if config.ledger.as_os_str().is_empty() {
        return Err("local: empty ledger path".into());
    }
    if config.campaign.image_mode != ImageMode::Elf {
        return Err(
            "local: only the static ELF x86-64 image mode of the angry.sustained contract is supported; pe-driver is a distributed loader-model mode".into(),
        );
    }
    if config.campaign.entry.is_some() {
        return Err("local: entry overrides are unsupported; local campaigns run at the image entry".into());
    }
    if !config.campaign.peers.is_empty() {
        return Err(
            "local: Config.peers is a distributed-coordinator option; local campaigns have no network peers".into(),
        );
    }
    if config.campaign.progress_jsonl.is_some() {
        return Err(
            "local: Config.progress_jsonl is a distributed progress-journal option; local campaigns have no journal"
                .into(),
        );
    }
    Ok(())
}

/// Digest of the effective local specification, sealed into the policy bytes
/// for every policy (like the Lua options digest, binding
/// the ledger path, root marker, policy, targets and limits to campaign
/// identity rather than trusting a resume-time caller).
fn options_digest(config: &LocalConfig) -> Digest {
    let mut bytes = b"angryier.local/sustained/options/v2\0".to_vec();
    bytes.extend_from_slice(config.ledger.as_os_str().as_encoded_bytes());
    bytes.push(0);
    bytes.extend_from_slice(config.campaign.build_id.as_bytes());
    bytes.push(0);
    bytes.extend_from_slice(match config.campaign.symbolic_reg {
        SymbolicRegister::Rbx => b"rbx".as_slice(),
        SymbolicRegister::Rcx => b"rcx",
    });
    bytes.push(u8::from(config.symbolic.is_some()));
    if let Some(symbolic) = &config.symbolic {
        bytes.extend_from_slice(&(symbolic.len() as u64).to_le_bytes());
        for (register, width) in symbolic {
            bytes.push(register.0);
            bytes.extend_from_slice(&width.to_le_bytes());
        }
    }
    bytes.extend_from_slice(&(config.regs.len() as u64).to_le_bytes());
    for (register, value) in &config.regs {
        bytes.push(register.0);
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.push(match config.policy {
        LocalPolicy::ForkAll => 0,
        LocalPolicy::RankTargets { exclude_avoid: false } => 1,
        LocalPolicy::RankTargets { exclude_avoid: true } => 2,
    });
    for list in [&config.find, &config.avoid] {
        bytes.extend_from_slice(&(list.len() as u64).to_le_bytes());
        for &address in list {
            bytes.extend_from_slice(&address.to_le_bytes());
        }
    }
    let limits = config.campaign.limits.resolve(ImageMode::Elf);
    for value in [
        limits.max_steps,
        limits.max_path_steps,
        limits.max_active_states,
        limits.max_path_depth,
        limits.max_loop_visits,
        limits.max_solver_millis,
        limits.max_wall_millis,
        limits.max_ram_bytes,
        limits.max_disk_bytes,
        limits.max_trace_bytes,
    ] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    Digest::of(&bytes)
}

/// The manifest policy artifact: the campaign-root marker, the effective
/// initial-state digest, optional typed v1/v2 target-policy bytes, and the
/// local options digest. All root marks, seeds, targets and limits are sealed;
/// resume with a changed specification fails closed.
fn sealed_policy(config: &LocalConfig, entry: u64, initial: &Digest, options: &Digest) -> Vec<u8> {
    let mut policy = config.campaign.policy(entry);
    policy.extend_from_slice(&initial.0);
    if !matches!(config.policy, LocalPolicy::ForkAll) || !config.find.is_empty() || !config.avoid.is_empty() {
        policy.push(0);
        policy.extend_from_slice(config.policy.policy_tag());
        for list in [&config.find, &config.avoid] {
            policy.extend_from_slice(&(list.len() as u64).to_le_bytes());
            for &address in list {
                policy.extend_from_slice(&address.to_le_bytes());
            }
        }
        if let LocalPolicy::RankTargets { exclude_avoid } = config.policy {
            policy.push(u8::from(exclude_avoid));
        }
    }
    policy.extend_from_slice(&options.0);
    policy
}

impl LocalCampaign {
    /// Raw ledger counts; use `checked_report` when publishing completion.
    pub fn report(&self) -> Report {
        self.campaign.report()
    }

    /// Reject completed exclusion campaigns whose avoid addresses lack an
    /// exact excluded/infeasible dynamic branch successor. Rejection does not
    /// change the ledger or manufacture a completed disposition.
    pub fn checked_report(&self) -> Result<Report> {
        let avoid = match self.config.policy {
            LocalPolicy::RankTargets { exclude_avoid: true } => self.config.avoid.as_slice(),
            _ => &[],
        };
        Ok(self.campaign.checked_report(avoid)?)
    }

    /// Latest durably accepted evidence for each path, in ledger order.
    pub fn cumulative_evidence(&self) -> impl Iterator<Item = &AcceptedEvidence> + '_ {
        self.campaign.cumulative_evidence()
    }

    /// Full durably accepted event history, including superseded retries.
    pub fn accepted_events(&self) -> &[AcceptedEvidence] {
        self.campaign.accepted_events()
    }

    /// Requeue deferred, unknown and failed owned work for the next
    /// [`LocalCampaign::advance`]; resume never silently marks it complete.
    pub fn retry_deferred(&mut self) -> Result<()> {
        Ok(self.campaign.retry_deferred()?)
    }
}

#[cfg(target_arch = "x86_64")]
mod native {
    use std::{sync::Arc, time::Duration};

    use angryier_distribution::contracts::{CampaignArtifacts, CampaignManifest, CampaignSpec, Digest};
    use angryier_expr::{ExprReader, ShardedExprArena};
    use angryier_ir::IrType;
    use angryier_runtime::{Runtime, SymbolicSession, sustained::SustainedCampaign, sustained::SustainedRanking};
    use angryier_solver_z3::Z3Backend;
    use angryier_types::{ExpressionNormalizationVersion, FidelityProfile, SemanticVersion, TargetProfileId};

    use super::{
        LocalCampaign, LocalConfig, LocalOutcome, LocalPolicy, canonical_targets, options_digest, sealed_policy,
        validate_local,
    };
    use crate::{ImageMode, Result};

    /// Only a static ELF64 x86-64 ET_EXEC without an interpreter or dynamic
    /// table is supported by the local entry-point execution model.
    fn validate_static_elf(image: &[u8]) -> Result<()> {
        if image.len() < 64 || &image[..4] != b"\x7fELF" || image[4] != 2 || image[5] != 1 {
            return Err("local: expected ELF64 little-endian image".into());
        }
        if u16::from_le_bytes([image[16], image[17]]) != 2 {
            return Err("local: static ELF requires ET_EXEC (ET_DYN/PIE is unsupported)".into());
        }
        if u16::from_le_bytes([image[18], image[19]]) != 62 {
            return Err("local: static ELF requires EM_X86_64".into());
        }
        let phoff = usize::try_from(u64::from_le_bytes(image[32..40].try_into()?))?;
        let phentsize = usize::from(u16::from_le_bytes(image[54..56].try_into()?));
        let phnum = usize::from(u16::from_le_bytes(image[56..58].try_into()?));
        if phentsize < 56 || phnum == 0 || phoff == 0 {
            return Err("local: invalid ELF program headers".into());
        }
        for index in 0..phnum {
            let offset = phoff
                .checked_add(
                    index
                        .checked_mul(phentsize)
                        .ok_or("local: invalid ELF program headers")?,
                )
                .ok_or("local: invalid ELF program headers")?;
            let header = image
                .get(offset..offset.checked_add(56).ok_or("local: invalid ELF program headers")?)
                .ok_or("local: invalid ELF program headers")?;
            let kind = u32::from_le_bytes(header[..4].try_into()?);
            if kind == 2 || kind == 3 {
                return Err("local: static ELF cannot contain PT_DYNAMIC or PT_INTERP".into());
            }
        }
        Ok(())
    }

    impl LocalCampaign {
        /// Open (and never overwrite) the durable ledger and pin the campaign.
        /// Fails if the ledger path already exists.
        pub fn start(config: LocalConfig) -> Result<Self> {
            Self::open(config, false)
        }

        /// Open an existing ledger pinned by an earlier
        /// [`LocalCampaign::start`] with the identical sealed specification.
        /// Fails if the ledger path does not exist, if any pinned artifact
        /// differs, or if the ledger was created under a different
        /// specification (including any `angry.sustained` Lua ledger). Never
        /// overwrites or reinitializes.
        pub fn resume(config: LocalConfig) -> Result<Self> {
            Self::open(config, true)
        }

        fn open(mut config: LocalConfig, resume: bool) -> Result<Self> {
            config = canonical_targets(config)?;
            validate_local(&config)?;
            config.campaign.validate()?;
            // Pin the image and the root exactly as the distributed path does.
            let image = crate::read_image(&config.campaign)?;
            validate_static_elf(&image)?;
            let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
            let arena = ShardedExprArena::new(ExpressionNormalizationVersion(1));
            let root = crate::configure_root(&config.campaign, runtime.load_elf(&image)?)?;
            let entry = root.pc()?;
            let mut session = SymbolicSession::new(&runtime, &arena, root);
            if let Some(symbolic) = &config.symbolic {
                for (register, width) in symbolic {
                    session.mark_symbolic(0, register.register_id(), IrType::Bits(*width))?;
                }
            } else {
                session.mark_symbolic(0, config.campaign.symbolic_reg.register_id(), IrType::Bits(64))?;
            }
            for (register, value) in &config.regs {
                session.states[0]
                    .process
                    .write_register(register.register_id(), *value)?;
                session.states[0]
                    .concrete_registers
                    .insert(register.register_id(), *value);
            }
            let initial = session.sustained_initial_digest()?;
            if let LocalPolicy::RankTargets { exclude_avoid: true } = config.policy
                && config.avoid.binary_search(&entry).is_ok()
            {
                return Err("local: avoid=exclude requires an exact dynamic branch target, not the entry".into());
            }
            let options = options_digest(&config);
            let policy = sealed_policy(&config, entry, &initial, &options);
            let script = config.policy.script_label();
            let profile = crate::build_profile()?;
            let manifest = CampaignManifest::seal(CampaignSpec {
                binary_digest: Digest::of(&image),
                architecture: "x86_64".into(),
                entry_pc: entry,
                semantic_version: format!("1/{}", config.campaign.build_id),
                semantic_profile_digest: Digest::of(&profile),
                script_digest: Digest::of(script),
                policy_digest: Digest::of(&policy),
                inputs: Vec::new(),
                stubs: Vec::new(),
                solver_version: "z3".into(),
                solver_policy_digest: Digest::of(b"z3-native-v1"),
                fidelity: FidelityProfile::Prove,
                limits: config.campaign.limits.resolve(ImageMode::Elf),
            })?;
            let artifacts = CampaignArtifacts {
                binary: &image,
                semantic_profile: &profile,
                script,
                policy: &policy,
                solver_policy: b"z3-native-v1",
                inputs: Vec::new(),
                stubs: Vec::new(),
            };
            // Validates the pinned artifacts against the manifest and, on
            // resume, the sealed campaign and root digest against the ledger.
            let campaign = if resume {
                SustainedCampaign::resume_existing(&config.ledger, manifest.clone(), &artifacts, initial)?
            } else {
                SustainedCampaign::start_new(&config.ledger, manifest.clone(), &artifacts, initial)?
            };
            Ok(Self {
                config,
                manifest,
                entry,
                initial,
                campaign,
            })
        }

        /// Rebuild the pinned root from the image file and run one bounded
        /// batch of durably owned subtrees in-process (native Z3, no network,
        /// no worker pool).
        pub fn advance(&mut self, timeout: Duration) -> Result<super::LocalOutcome> {
            if timeout.is_zero() {
                return Err("local: timeout must be positive".into());
            }
            // The image must still be the pinned binary (mirrors the Lua
            // advance-time artifact check).
            let image = crate::read_image(&self.config.campaign)?;
            if Digest::of(&image) != self.manifest.spec.binary_digest {
                return Err("local: binary artifact mismatch (image changed on disk)".into());
            }
            // Root REBUILT before every advance, through the same configured
            // loader path that pinned the ledger root.
            let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
            let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
            let root = crate::configure_root(&self.config.campaign, runtime.load_elf(&image)?)?;
            if root.pc()? != self.entry {
                return Err("local: rebuilt entry does not match the pinned manifest entry".into());
            }
            let mut session = SymbolicSession::new(&runtime, arena.as_ref(), root);
            if let Some(symbolic) = &self.config.symbolic {
                for (register, width) in symbolic {
                    session.mark_symbolic(0, register.register_id(), IrType::Bits(*width))?;
                }
            } else {
                session.mark_symbolic(0, self.config.campaign.symbolic_reg.register_id(), IrType::Bits(64))?;
            }
            for (register, value) in &self.config.regs {
                session.states[0]
                    .process
                    .write_register(register.register_id(), *value)?;
                session.states[0]
                    .concrete_registers
                    .insert(register.register_id(), *value);
            }
            let initial = session.sustained_initial_digest()?;
            if initial != self.initial {
                return Err("local: rebuilt root digest does not match the pinned ledger root".into());
            }
            let mut solver = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
            let ranking = match self.config.policy {
                LocalPolicy::ForkAll => None,
                LocalPolicy::RankTargets { exclude_avoid } => Some(SustainedRanking {
                    find: &self.config.find,
                    avoid: &self.config.avoid,
                    exclude_avoid,
                }),
            };
            let run = session.run_sustained_ranked(&mut self.campaign, &mut solver, timeout, ranking)?;
            let report = self.checked_report()?;
            let accepted_evidence = self.cumulative_evidence().cloned().collect();
            Ok(LocalOutcome {
                report,
                steps: run.steps,
                reason: run.reason,
                accepted_evidence,
            })
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
impl LocalCampaign {
    pub fn start(_config: LocalConfig) -> Result<Self> {
        Err(
            "local sustained campaigns require x86_64 native XED + Z3; ARM64 and Windows hosts are not supported"
                .into(),
        )
    }

    pub fn resume(_config: LocalConfig) -> Result<Self> {
        Err(
            "local sustained campaigns require x86_64 native XED + Z3; ARM64 and Windows hosts are not supported"
                .into(),
        )
    }

    pub fn advance(&mut self, _timeout: std::time::Duration) -> Result<LocalOutcome> {
        Err(
            "local sustained campaigns require x86_64 native XED + Z3; ARM64 and Windows hosts are not supported"
                .into(),
        )
    }
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
    use super::*;
    use std::{fs, time::Duration};

    struct Temp(PathBuf);
    impl Temp {
        fn new(name: &str) -> std::io::Result<Self> {
            let dir = std::env::temp_dir().join(format!(
                "angryier-campaign-local-{name}-{}-{}",
                std::process::id(),
                NAME_SUFFIX.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            ));
            fs::create_dir_all(&dir)?;
            Ok(Self(dir))
        }
    }
    impl Drop for Temp {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    static NAME_SUFFIX: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    #[test]
    fn targets_are_sorted_canonically_and_reject_duplicates_and_overflows() -> Result<()> {
        let config = LocalConfig {
            campaign: Config::defaults(PathBuf::new(), PathBuf::new(), "t".into()),
            ledger: PathBuf::from("ledger"),
            policy: LocalPolicy::ForkAll,
            find: vec![0x4020, 0x4010],
            avoid: vec![0x1, 0x1],
            symbolic: None,
            regs: Vec::new(),
        };
        let Err(error) = canonical_targets(config) else {
            return Err("duplicates must be rejected".into());
        };
        assert!(error.to_string().contains("duplicate targets.avoid"));
        let mut config = LocalConfig {
            campaign: Config::defaults(PathBuf::new(), PathBuf::new(), "t".into()),
            ledger: PathBuf::from("ledger"),
            policy: LocalPolicy::ForkAll,
            find: (0..4097).collect(),
            avoid: Vec::new(),
            symbolic: None,
            regs: Vec::new(),
        };
        config.find.reverse();
        let Err(error) = canonical_targets(config) else {
            return Err("overflows must be rejected".into());
        };
        assert!(error.to_string().contains("at most 4096"));
        let config = LocalConfig {
            campaign: Config::defaults(PathBuf::new(), PathBuf::new(), "t".into()),
            ledger: PathBuf::from("ledger"),
            policy: LocalPolicy::RankTargets { exclude_avoid: true },
            find: vec![0x4020, 0x4010],
            avoid: vec![0x9],
            symbolic: None,
            regs: Vec::new(),
        };
        let canonical = canonical_targets(config).map(|config| (config.find, config.avoid));
        assert_eq!(
            canonical.map_err(|error| error.to_string()),
            Ok((vec![0x4010, 0x4020], vec![0x9]))
        );
        Ok(())
    }

    #[test]
    fn local_rejects_unsupported_config_options() -> Result<()> {
        let base = LocalConfig {
            campaign: Config::defaults(PathBuf::new(), PathBuf::new(), "t".into()),
            ledger: PathBuf::from("ledger"),
            policy: LocalPolicy::ForkAll,
            find: Vec::new(),
            avoid: Vec::new(),
            symbolic: None,
            regs: Vec::new(),
        };
        let cases: Vec<(LocalConfig, &str)> = vec![
            (
                LocalConfig {
                    ledger: PathBuf::new(),
                    ..base.clone()
                },
                "empty ledger path",
            ),
            (
                LocalConfig {
                    campaign: Config {
                        image_mode: crate::ImageMode::PeDriver,
                        ..base.campaign.clone()
                    },
                    ..base.clone()
                },
                "static ELF x86-64",
            ),
            (
                LocalConfig {
                    campaign: Config {
                        entry: Some(0x1000),
                        ..base.campaign.clone()
                    },
                    ..base.clone()
                },
                "entry overrides are unsupported",
            ),
            (
                LocalConfig {
                    campaign: Config {
                        peers: vec![crate::Peer {
                            id: "w".into(),
                            addr: std::net::SocketAddr::from(([127, 0, 0, 1], 9)),
                            key_file: PathBuf::new(),
                        }],
                        ..base.campaign.clone()
                    },
                    ..base.clone()
                },
                "no network peers",
            ),
            (
                LocalConfig {
                    campaign: Config {
                        progress_jsonl: Some(PathBuf::from("p.jsonl")),
                        ..base.campaign.clone()
                    },
                    ..base.clone()
                },
                "no journal",
            ),
        ];
        for (config, needle) in cases {
            let Err(error) = validate_local(&config) else {
                return Err(format!("{needle} must be rejected").into());
            };
            assert!(error.to_string().contains(needle), "{error} missing {needle}");
        }
        assert!(validate_local(&base).is_ok());
        Ok(())
    }

    #[test]
    fn options_digest_pins_path_marker_policy_targets_and_limits() {
        let mut base = LocalConfig {
            campaign: Config::defaults(PathBuf::new(), PathBuf::new(), "t".into()),
            ledger: PathBuf::from("a.ledger"),
            policy: LocalPolicy::RankTargets { exclude_avoid: false },
            find: vec![0x10],
            avoid: vec![0x20],
            symbolic: None,
            regs: Vec::new(),
        };
        let baseline = options_digest(&base);
        assert_eq!(options_digest(&base), baseline);
        base.ledger = PathBuf::from("b.ledger");
        assert_ne!(options_digest(&base), baseline);
        base.ledger = PathBuf::from("a.ledger");
        base.find = vec![0x11];
        assert_ne!(options_digest(&base), baseline);
        base.find = vec![0x10];
        base.avoid = vec![0x20, 0x21];
        assert_ne!(options_digest(&base), baseline);
        base.avoid = vec![0x20];
        base.policy = LocalPolicy::RankTargets { exclude_avoid: true };
        assert_ne!(options_digest(&base), baseline);
        base.policy = LocalPolicy::ForkAll;
        assert_ne!(options_digest(&base), baseline);
        base.policy = LocalPolicy::RankTargets { exclude_avoid: false };
        base.campaign.symbolic_reg = crate::SymbolicRegister::Rcx;
        assert_ne!(options_digest(&base), baseline);
        base.campaign.symbolic_reg = crate::SymbolicRegister::Rbx;
        base.campaign.limits.max_steps += 1;
        assert_ne!(options_digest(&base), baseline);
        base.campaign.limits.max_steps -= 1;
        base.campaign.build_id = "t2".into();
        assert_ne!(options_digest(&base), baseline);
    }

    #[test]
    fn sealed_policy_encodes_v1_v2_targets_exclude_and_options() {
        let mut config = LocalConfig {
            campaign: Config::defaults(PathBuf::new(), PathBuf::new(), "t".into()),
            ledger: PathBuf::from("a.ledger"),
            policy: LocalPolicy::ForkAll,
            find: Vec::new(),
            avoid: Vec::new(),
            symbolic: None,
            regs: Vec::new(),
        };
        let entry = 0x1000;
        let initial = Digest::of(b"initial");
        let options = options_digest(&config);
        // v1 without targets: marker + initial digest + sealed options.
        let fork_all = sealed_policy(&config, entry, &initial, &options);
        let mut expected = config.campaign.policy(entry);
        expected.extend_from_slice(&initial.0);
        expected.extend_from_slice(&options.0);
        assert_eq!(fork_all, expected);
        // v1 with observations: the observational tag plus ordered lists
        // (open canonicalizes targets before sealing).
        config.find = vec![0x1, 0x2];
        config.avoid = vec![0x3];
        let observed = sealed_policy(&config, entry, &initial, &options);
        let mut observed_expected = config.campaign.policy(entry);
        observed_expected.extend_from_slice(&initial.0);
        observed_expected.push(0);
        observed_expected.extend_from_slice(b"observational-targets/v1");
        observed_expected.extend_from_slice(&2u64.to_le_bytes());
        observed_expected.extend_from_slice(&0x1u64.to_le_bytes());
        observed_expected.extend_from_slice(&0x2u64.to_le_bytes());
        observed_expected.extend_from_slice(&1u64.to_le_bytes());
        observed_expected.extend_from_slice(&0x3u64.to_le_bytes());
        observed_expected.extend_from_slice(&options.0);
        assert_eq!(observed, observed_expected);
        // v2: rank tag, lists, exclude flag and the options digest.
        config.policy = LocalPolicy::RankTargets { exclude_avoid: true };
        let ranked = sealed_policy(&config, entry, &initial, &options);
        let mut ranked_expected = config.campaign.policy(entry);
        ranked_expected.extend_from_slice(&initial.0);
        ranked_expected.push(0);
        ranked_expected.extend_from_slice(b"rank-targets/v1");
        ranked_expected.extend_from_slice(&2u64.to_le_bytes());
        ranked_expected.extend_from_slice(&0x1u64.to_le_bytes());
        ranked_expected.extend_from_slice(&0x2u64.to_le_bytes());
        ranked_expected.extend_from_slice(&1u64.to_le_bytes());
        ranked_expected.extend_from_slice(&0x3u64.to_le_bytes());
        ranked_expected.push(1);
        ranked_expected.extend_from_slice(&options.0);
        assert_eq!(ranked, ranked_expected);
        assert_eq!(config.policy.script_label(), b"angryier.local/sustained/v2");
        assert_eq!(LocalPolicy::ForkAll.script_label(), b"angryier.local/sustained/v1");
    }

    /// Minimal static ELF64 x86-64 executable: one R+X PT_LOAD at 0x400000
    /// with the payload at the entry.
    fn synthetic_elf(payload: &[u8]) -> Vec<u8> {
        const MAX_INSN_LEN: usize = 15;
        let segment_base = 0x400000u64;
        let code_offset = 64 + 56;
        let total_size = (code_offset + payload.len() + MAX_INSN_LEN).next_multiple_of(0x1000);
        let entry = segment_base + code_offset as u64;
        let mut elf = vec![0u8; total_size];
        elf[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[16..18].copy_from_slice(&2u16.to_le_bytes());
        elf[18..20].copy_from_slice(&62u16.to_le_bytes());
        elf[20..24].copy_from_slice(&1u32.to_le_bytes());
        elf[24..32].copy_from_slice(&entry.to_le_bytes());
        elf[32..40].copy_from_slice(&64u64.to_le_bytes());
        elf[52..54].copy_from_slice(&64u16.to_le_bytes());
        elf[54..56].copy_from_slice(&56u16.to_le_bytes());
        elf[56..58].copy_from_slice(&1u16.to_le_bytes());
        elf[64..68].copy_from_slice(&1u32.to_le_bytes());
        elf[68..72].copy_from_slice(&5u32.to_le_bytes());
        elf[72..80].copy_from_slice(&0u64.to_le_bytes());
        elf[80..88].copy_from_slice(&segment_base.to_le_bytes());
        elf[88..96].copy_from_slice(&segment_base.to_le_bytes());
        elf[96..104].copy_from_slice(&(total_size as u64).to_le_bytes());
        elf[104..112].copy_from_slice(&(total_size as u64).to_le_bytes());
        elf[112..120].copy_from_slice(&0x1000u64.to_le_bytes());
        elf[code_offset..code_offset + payload.len()].copy_from_slice(payload);
        elf
    }

    fn branch_fixture() -> (Vec<u8>, u64, u64) {
        // entry: test %rbx,%rbx; je target; xor %eax,%eax; jmp exit; target:
        // xor %eax,%eax; exit: mov $60,%rax; syscall — rbx is symbolic, so
        // the je forks and both children converge on exit(60).
        let payload: &[u8] = &[
            0x48, 0x85, 0xdb, // test %rbx,%rbx
            0x74, 0x06, // je +6 -> exit block
            0x31, 0xc0, // xor %eax,%eax
            0xeb, 0x02, // jmp +2 -> exit block
            0x90, 0x90, // padding
            0x48, 0xc7, 0xc0, 0x3c, 0x00, 0x00, 0x00, // mov $60,%rax
            0x0f, 0x05, // syscall
        ];
        let elf = synthetic_elf(payload);
        let entry = 0x400000 + (64 + 56) as u64;
        (elf, entry, entry + 0x0b)
    }

    #[test]
    fn local_campaign_end_to_end_start_advance_resume_and_rejections() -> Result<()> {
        let dir = Temp::new("e2e").map_err(|error| error.to_string())?;
        let (elf, entry, found) = branch_fixture();
        let elf_path = dir.0.join("program.elf");
        fs::write(&elf_path, &elf).map_err(|error| error.to_string())?;
        let mut config = Config::defaults(elf_path, PathBuf::new(), "local-test-v1".into());
        config.limits.max_steps = 64;
        let mut local = LocalConfig {
            campaign: config,
            ledger: dir.0.join("local.ledger"),
            policy: LocalPolicy::RankTargets { exclude_avoid: false },
            find: vec![found],
            avoid: Vec::new(),
            symbolic: None,
            regs: Vec::new(),
        };
        // Resume before start fails; with exclusion armed, avoid at the image
        // entry fails (an exact dynamic branch target is required).
        assert!(LocalCampaign::resume(local.clone()).is_err());
        local.policy = LocalPolicy::RankTargets { exclude_avoid: true };
        local.avoid = vec![entry];
        assert!(LocalCampaign::start(local.clone()).is_err());
        local.policy = LocalPolicy::RankTargets { exclude_avoid: false };
        local.avoid = Vec::new();
        // find lists are canonically sorted before pinning; duplicates rejected.
        local.find = vec![found, found];
        let Err(error) = LocalCampaign::start(local.clone()) else {
            return Err("duplicate find targets must be rejected".into());
        };
        assert!(error.to_string().contains("duplicate targets.find"));
        local.find = vec![found];

        let mut campaign = LocalCampaign::start(local.clone())?;
        // Start never overwrites an existing ledger.
        assert!(LocalCampaign::start(local.clone()).is_err());
        let outcome = campaign.advance(Duration::from_millis(15_000))?;
        let report = campaign.report();
        assert_eq!(report.completed, outcome.report.completed);
        assert!(outcome.report.completed >= 2, "{:?}", outcome.report);
        assert!(outcome.steps > 0);
        assert!(
            outcome
                .accepted_evidence
                .iter()
                .any(|event| matches!(event.status, angryier_ledger::sustained::Status::Completed)),
            "expected an accepted terminal path"
        );
        campaign.retry_deferred()?;
        drop(campaign);

        // Resume with the identical pinned specification reopens the ledger.
        let mut resumed = LocalCampaign::resume(local.clone())?;
        let next = resumed.advance(Duration::from_millis(15_000))?;
        assert!(next.report.complete_within_declared_bounds, "{:?}", next.report);
        drop(resumed);

        // A different sealed specification (targets, policy, limits, marker,
        // binary) is rejected instead of reopening foreign work.
        let mut changed = local.clone();
        changed.find = vec![found - 1];
        assert!(LocalCampaign::resume(changed).is_err());
        let mut changed = local.clone();
        changed.policy = LocalPolicy::ForkAll;
        assert!(LocalCampaign::resume(changed).is_err());
        let mut changed = local.clone();
        changed.campaign.limits.max_steps += 1;
        assert!(LocalCampaign::resume(changed).is_err());
        let mut changed = local;
        changed.campaign.build_id = "local-test-v2".into();
        assert!(LocalCampaign::resume(changed).is_err());

        // A swapped image under the same specification is rejected on resume.
        let dir2 = Temp::new("e2e-image").map_err(|error| error.to_string())?;
        let (elf2, _, _) = branch_fixture();
        let mut swapped = elf2;
        swapped[64 + 56] = 0x48 ^ 0xff;
        let elf_path2 = dir2.0.join("program.elf");
        fs::write(&elf_path2, &swapped).map_err(|error| error.to_string())?;
        // Rebuild a valid campaign in dir2 first so the rejection is due to
        // the swapped bytes, not a missing ledger.
        let mut config2 = Config::defaults(elf_path2.clone(), PathBuf::new(), "local-test-v1".into());
        config2.limits.max_steps = 64;
        let local2 = LocalConfig {
            campaign: config2,
            ledger: dir2.0.join("local.ledger"),
            policy: LocalPolicy::ForkAll,
            find: Vec::new(),
            avoid: Vec::new(),
            symbolic: None,
            regs: Vec::new(),
        };
        let _campaign2 = LocalCampaign::start(local2.clone())?;
        drop(_campaign2);
        fs::write(&elf_path2, &elf).map_err(|error| error.to_string())?;
        assert!(LocalCampaign::resume(local2).is_err());
        Ok(())
    }
}
