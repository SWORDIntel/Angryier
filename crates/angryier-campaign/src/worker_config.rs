//! Versioned on-disk handoff for a loopback worker. No key material is stored.
#[cfg(test)]
use crate::SymbolicRegister;
use crate::{CampaignLimits, Config, ImageMode, RamCap, Result, build_profile, peer_id, read_image};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    net::SocketAddr,
    path::{Component, Path, PathBuf},
};

const MAX_CONFIG_BYTES: u64 = 16 * 1024;
const PROFILE_PREFIX: &[u8] = b"native-xed-v1/executable-sha256:";
const AEAD_KEY_DOMAIN: &[u8] = b"angryier/worker-config/v2/xchacha20poly1305/key\0";
const AEAD_AAD_DOMAIN: &[u8] = b"angryier/worker-config/v2/xchacha20poly1305/aad\0";

fn encryption_key(pairwise: &[u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(AEAD_KEY_DOMAIN);
    hash.update(pairwise);
    hash.finalize().into()
}

fn envelope_aad(version: u64, key_file: &Path) -> Result<Vec<u8>> {
    let path = key_file.to_str().ok_or("worker key pathname must be UTF-8")?;
    if path.is_empty() {
        return Err("worker key pathname must not be empty".into());
    }
    let mut aad = Vec::with_capacity(AEAD_AAD_DOMAIN.len() + 16 + path.len());
    aad.extend_from_slice(AEAD_AAD_DOMAIN);
    aad.extend_from_slice(&version.to_be_bytes());
    aad.extend_from_slice(&(path.len() as u64).to_be_bytes());
    aad.extend_from_slice(path.as_bytes());
    Ok(aad)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode(text: &str) -> Result<Vec<u8>> {
    let (pairs, remainder) = text.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err("invalid worker config hex encoding".into());
    }
    pairs
        .iter()
        .map(|pair| {
            let digit = |byte: u8| match byte {
                b'0'..=b'9' => Some(byte - b'0'),
                b'a'..=b'f' => Some(byte - b'a' + 10),
                _ => None,
            };
            Ok((digit(pair[0]).ok_or("invalid worker config hex encoding")? << 4)
                | digit(pair[1]).ok_or("invalid worker config hex encoding")?)
        })
        .collect()
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct WorkerEnvelope {
    version: u64,
    key_file: PathBuf,
    nonce: String,
    ciphertext: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct SealedLimits {
    max_steps: u64,
    max_path_steps: u64,
    max_active_states: u64,
    max_path_depth: u64,
    max_loop_visits: u64,
    max_solver_millis: u64,
    max_wall_millis: u64,
    max_ram_bytes: u64,
    max_disk_bytes: u64,
    max_trace_bytes: u64,
}

/// Inner authenticated worker settings, encrypted inside a strict v2 envelope.
/// The binary is pinned to an absolute canonical pathname and its image digest.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct WorkerConfig {
    version: u64,
    executable_sha256: String,
    image_sha256: String,
    binary: PathBuf,
    key_file: PathBuf,
    worker_id: String,
    build_id: String,
    image_mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    entry: Option<u64>,
    symbolic_reg: String,
    limits: SealedLimits,
    listen: SocketAddr,
    connections: u64,
}

fn executable_digest() -> Result<String> {
    let profile = build_profile()?;
    let digest = profile
        .strip_prefix(PROFILE_PREFIX)
        .ok_or("invalid executable profile")?;
    if digest.len() != 32 {
        return Err("invalid executable profile digest length".into());
    }
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn checked_image(config: &Config) -> Result<String> {
    // read_image enforces the ELF/PE file-size and mapped PE RAM limits before hashing.
    Ok(format!("{:x}", Sha256::digest(read_image(config)?)))
}

fn check_listen(addr: SocketAddr) -> Result<()> {
    if !addr.ip().is_loopback() {
        return Err("worker listener must be loopback".into());
    }
    Ok(())
}

fn check_normalized_absolute(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || path.as_os_str() != path.components().collect::<PathBuf>().as_os_str()
    {
        return Err("worker binary path must be absolute and normalized".into());
    }
    Ok(())
}

fn canonical_binary(path: &Path) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path)?;
    if !canonical.is_absolute() || !fs::metadata(&canonical)?.is_file() {
        return Err("worker binary must be a regular file".into());
    }
    Ok(canonical)
}

impl WorkerConfig {
    /// Pin the current executable and image; the remote key pathname need not
    /// exist on the generator and is deliberately never opened here.
    pub fn from_worker(config: &Config, listen: SocketAddr, connections: u64) -> Result<Self> {
        config.validate()?;
        peer_id(&config.worker_id)?;
        check_listen(listen)?;
        let binary = canonical_binary(&config.binary)?;
        let image_sha256 = checked_image(config)?;
        // Apply the same numeric-limit validation as load before emitting TOML.
        crate::manifest(config, b"pin-validation", config.entry.unwrap_or(0), b"profile")?;
        let effective = config.limits.resolve(config.image_mode);
        Ok(Self {
            version: 2,
            executable_sha256: executable_digest()?,
            image_sha256,
            binary,
            key_file: config.key_file.clone(),
            worker_id: config.worker_id.clone(),
            build_id: config.build_id.clone(),
            image_mode: match config.image_mode {
                ImageMode::Elf => "elf",
                ImageMode::PeDriver => "pe-driver",
            }
            .into(),
            entry: config.entry,
            symbolic_reg: config.symbolic_reg.as_str().into(),
            limits: SealedLimits {
                max_steps: effective.max_steps,
                max_path_steps: effective.max_path_steps,
                max_active_states: effective.max_active_states,
                max_path_depth: effective.max_path_depth,
                max_loop_visits: effective.max_loop_visits,
                max_solver_millis: effective.max_solver_millis,
                max_wall_millis: effective.max_wall_millis,
                max_ram_bytes: effective.max_ram_bytes,
                max_disk_bytes: effective.max_disk_bytes,
                max_trace_bytes: effective.max_trace_bytes,
            },
            listen,
            connections,
        })
    }

    /// Set the worker-side image pathname after hashing the generator-local image.
    /// It need not exist on this machine, but must be staged unchanged on the worker.
    pub fn set_worker_binary_path(&mut self, path: PathBuf) -> Result<()> {
        check_normalized_absolute(&path)?;
        self.binary = path;
        Ok(())
    }

    /// Atomically create a private config; never truncate an existing path.
    pub fn write_new(&self, path: &Path, sign_key: &Path) -> Result<()> {
        if self.version != 2 {
            return Err("unsupported worker config version".into());
        }
        let inner = toml::to_string(self)?;
        let key = encryption_key(&crate::key(&sign_key.to_path_buf())?);
        let cipher = XChaCha20Poly1305::new((&key).into());
        let mut nonce = [0u8; 24];
        getrandom::getrandom(&mut nonce).map_err(|_| "OS randomness unavailable")?;
        let aad = envelope_aad(2, &self.key_file)?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: inner.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| "worker config encryption failed")?;
        let text = toml::to_string(&WorkerEnvelope {
            version: 2,
            key_file: self.key_file.clone(),
            nonce: hex_encode(&nonce),
            ciphertext: hex_encode(&ciphertext),
        })?;
        if text.len() as u64 > MAX_CONFIG_BYTES {
            return Err("worker config exceeds 16 KiB".into());
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
        Ok(())
    }

    /// Authenticate and decrypt the v2 handoff before validating pins and returning
    /// parameters for `serve_pinned`.
    pub fn load(path: &Path) -> Result<(Config, SocketAddr, u64, String)> {
        let link = fs::symlink_metadata(path)?;
        if !link.is_file() || link.len() > MAX_CONFIG_BYTES {
            return Err("worker config must be a regular file of at most 16 KiB".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if link.uid() != rustix::process::geteuid().as_raw() || link.permissions().mode() & 0o077 != 0 {
                return Err("worker config must be owned by the current user and private".into());
            }
        }
        #[cfg(unix)]
        let file = fs::File::from(rustix::fs::open(
            path,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )?);
        #[cfg(not(unix))]
        let file = fs::File::open(path)?;
        let opened = file.metadata()?;
        if !opened.is_file() || opened.len() > MAX_CONFIG_BYTES {
            return Err("worker config must be a regular file of at most 16 KiB".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            use std::os::unix::fs::PermissionsExt;
            if opened.dev() != link.dev()
                || opened.ino() != link.ino()
                || opened.uid() != rustix::process::geteuid().as_raw()
                || opened.permissions().mode() & 0o077 != 0
            {
                return Err("worker config changed while opening".into());
            }
        }
        let mut text = Vec::new();
        file.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut text)?;
        if text.len() as u64 > MAX_CONFIG_BYTES {
            return Err("worker config exceeds 16 KiB".into());
        }
        let envelope: WorkerEnvelope = toml::from_str(std::str::from_utf8(&text)?)?;
        if envelope.version != 2 {
            return Err("unsupported worker config version".into());
        }
        let aad = envelope_aad(envelope.version, &envelope.key_file)?;
        if envelope.nonce.len() != 48 || envelope.ciphertext.len() < 32 {
            return Err("invalid worker config ciphertext or nonce length".into());
        }
        let nonce: [u8; 24] = hex_decode(&envelope.nonce)?
            .try_into()
            .map_err(|_| "invalid worker config nonce length")?;
        let ciphertext = hex_decode(&envelope.ciphertext)?;
        let key = encryption_key(&crate::key(&envelope.key_file)?);
        let cipher = XChaCha20Poly1305::new((&key).into());
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| "worker config authentication failed")?;
        let sealed: Self = toml::from_str(std::str::from_utf8(&plaintext)?)?;
        if sealed.version != 2 || sealed.key_file != envelope.key_file {
            return Err("worker config inner version or key path mismatch".into());
        }
        check_listen(sealed.listen)?;
        if sealed.executable_sha256 != executable_digest()? {
            return Err("worker executable SHA256 mismatch".into());
        }
        check_normalized_absolute(&sealed.binary)?;
        if sealed.binary.as_os_str() != canonical_binary(&sealed.binary)?.as_os_str() {
            return Err("worker binary path is not canonical".into());
        }
        let mut config = Config::defaults(sealed.binary, sealed.key_file, sealed.build_id);
        config.worker_id = sealed.worker_id;
        config.image_mode = sealed.image_mode.parse()?;
        config.entry = sealed.entry;
        config.symbolic_reg = sealed.symbolic_reg.parse()?;
        config.limits = CampaignLimits {
            max_steps: sealed.limits.max_steps,
            max_path_steps: sealed.limits.max_path_steps,
            max_active_states: sealed.limits.max_active_states,
            max_path_depth: sealed.limits.max_path_depth,
            max_loop_visits: sealed.limits.max_loop_visits,
            max_solver_millis: sealed.limits.max_solver_millis,
            max_wall_millis: sealed.limits.max_wall_millis,
            max_ram_bytes: RamCap::Bytes(sealed.limits.max_ram_bytes),
            max_disk_bytes: sealed.limits.max_disk_bytes,
            max_trace_bytes: sealed.limits.max_trace_bytes,
        };
        config.validate()?;
        peer_id(&config.worker_id)?;
        // Manifest sealing applies all numeric-limit validation without loading
        // an executable image into the runtime or accessing the key pathname.
        crate::manifest(&config, b"pin-validation", config.entry.unwrap_or(0), b"profile")?;
        if sealed.image_sha256 != checked_image(&config)? {
            return Err("worker image SHA256 mismatch".into());
        }
        Ok((config, sealed.listen, sealed.connections, sealed.image_sha256))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIR: AtomicU64 = AtomicU64::new(0);

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Result<Self> {
            let path = std::env::temp_dir().join(format!(
                "angryier-worker-config-{}-{}",
                std::process::id(),
                NEXT_DIR.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path)?;
            Ok(Self(path))
        }
        fn path(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
        fn config(&self) -> Result<Config> {
            let binary = self.path("image");
            fs::write(&binary, b"\x7fELFworker-target-v1")?;
            let key_file = self.path("worker.key");
            fs::write(&key_file, [0x42; 32])?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600))?;
            }
            Ok(Config::defaults(binary, key_file, "build-v1".into()))
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn listener() -> Result<SocketAddr> {
        Ok("127.0.0.1:9001".parse()?)
    }

    #[test]
    fn aead_key_is_domain_separated_from_pairwise_transport_key() {
        assert_ne!(encryption_key(&[0x42; 32]), [0x42; 32]);
        assert_ne!(encryption_key(&[0x42; 32]), encryption_key(&[0x43; 32]));
    }

    fn rewrite_envelope(path: &Path, mutate: impl FnOnce(&mut WorkerEnvelope)) -> Result<()> {
        let mut envelope: WorkerEnvelope = toml::from_str(&fs::read_to_string(path)?)?;
        mutate(&mut envelope);
        fs::write(path, toml::to_string(&envelope)?)?;
        Ok(())
    }

    fn sealed_with(path: &Path, key: &Path, mutate: impl FnOnce(&mut WorkerConfig)) -> Result<()> {
        let envelope: WorkerEnvelope = toml::from_str(&fs::read_to_string(path)?)?;
        let nonce = hex_decode(&envelope.nonce)?;
        let ciphertext = hex_decode(&envelope.ciphertext)?;
        let aad = envelope_aad(envelope.version, &envelope.key_file)?;
        let key = encryption_key(&crate::key(&key.to_path_buf())?);
        let cipher = XChaCha20Poly1305::new((&key).into());
        let inner = cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| "test fixture decryption failed")?;
        let mut config: WorkerConfig = toml::from_str(std::str::from_utf8(&inner)?)?;
        mutate(&mut config);
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: toml::to_string(&config)?.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| "test fixture encryption failed")?;
        fs::write(
            path,
            toml::to_string(&WorkerEnvelope {
                ciphertext: hex_encode(&ciphertext),
                ..envelope
            })?,
        )?;
        Ok(())
    }

    #[test]
    fn roundtrip_resolves_ram_and_never_persists_key_bytes() -> Result<()> {
        let dir = TestDir::new()?;
        let mut source = dir.config()?;
        source.symbolic_reg = SymbolicRegister::Rcx;
        source.entry = Some(0x1234);
        source.limits.max_steps = 42;
        let sealed = WorkerConfig::from_worker(&source, listener()?, 3)?;
        let path = dir.path("worker.toml");
        sealed.write_new(&path, &source.key_file)?;
        assert!(sealed.write_new(&path, &source.key_file).is_err());
        let text = fs::read_to_string(&path)?;
        let envelope: WorkerEnvelope = toml::from_str(&text)?;
        assert_eq!(envelope.version, 2);
        assert_eq!(envelope.key_file, source.key_file);
        assert_eq!(envelope.nonce.len(), 48);
        assert!(envelope.ciphertext.len() > 32);
        for secret in [
            "build-v1",
            "image",
            "max-ram-bytes",
            "127.0.0.1",
            "symbolic-reg",
            "executable-sha256",
            &sealed.image_sha256,
        ] {
            assert!(!text.contains(secret), "envelope leaks {secret}");
        }
        assert_eq!(text.lines().count(), 4);
        let next_path = dir.path("next.toml");
        sealed.write_new(&next_path, &source.key_file)?;
        let next: WorkerEnvelope = toml::from_str(&fs::read_to_string(&next_path)?)?;
        assert_ne!(envelope.nonce, next.nonce);
        assert_ne!(envelope.ciphertext, next.ciphertext);
        let (loaded, addr, connections, expected_image_sha256) = WorkerConfig::load(&path)?;
        assert_eq!(expected_image_sha256, sealed.image_sha256);
        assert_eq!(addr, listener()?);
        assert_eq!(connections, 3);
        assert_eq!(loaded.symbolic_reg, SymbolicRegister::Rcx);
        assert_eq!(loaded.entry, Some(0x1234));
        assert_eq!(loaded.limits.max_steps, 42);
        assert_eq!(loaded.limits.max_ram_bytes, RamCap::Bytes(64 << 20));
        assert_eq!(loaded.key_file, source.key_file);
        assert_eq!(loaded.binary, fs::canonicalize(source.binary)?);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        }
        Ok(())
    }

    #[test]
    fn strict_fields_version_and_digest_pins() -> Result<()> {
        let dir = TestDir::new()?;
        let source = dir.config()?;
        let sealed = WorkerConfig::from_worker(&source, listener()?, 0)?;
        let path = dir.path("worker.toml");
        sealed.write_new(&path, &source.key_file)?;
        let valid = fs::read_to_string(&path)?;
        for invalid in [
            valid.replace("version = 2", "version = 1"),
            valid.replace("version = 2", "version = 3"),
            valid.replace("version = 2", "version = 2\nversion = 2"),
            valid.replace("version = 2", "version = 2\nunknown = true"),
            valid.replace("version = 2", "version = 2\nnonce = \"00\""),
            valid.replace("version = 2", "version = 2\nauthentication-tag = \"legacy\""),
            valid.replace("nonce = \"", "nonce = \"z"),
            valid.replace("ciphertext = \"", "ciphertext = \"z"),
        ] {
            assert_ne!(invalid, valid);
            fs::write(&path, invalid)?;
            assert!(WorkerConfig::load(&path).is_err());
        }
        fs::write(&path, &valid)?;
        assert!(WorkerConfig::load(&path).is_ok());
        for mutate in [
            (|inner: &mut WorkerConfig| inner.executable_sha256 = "0".repeat(64)) as fn(&mut WorkerConfig),
            |inner| inner.image_sha256 = "0".repeat(64),
            |inner| inner.binary = PathBuf::from("relative/image"),
            |inner| inner.listen = SocketAddr::from(([0, 0, 0, 0], 9001)),
            |inner| inner.version = 1,
            |inner| inner.key_file = PathBuf::from("different-worker.key"),
        ] {
            sealed_with(&path, &source.key_file, mutate)?;
            assert!(WorkerConfig::load(&path).is_err());
            fs::write(&path, &valid)?;
        }
        fs::write(&source.binary, b"\x7fELFworker-target-v2")?;
        assert!(WorkerConfig::load(&path).is_err());
        Ok(())
    }

    #[test]
    fn authenticates_valid_fields_with_worker_key_before_acceptance() -> Result<()> {
        let dir = TestDir::new()?;
        let source = dir.config()?;
        let sealed = WorkerConfig::from_worker(&source, listener()?, 3)?;
        let path = dir.path("worker.toml");
        sealed.write_new(&path, &source.key_file)?;
        let valid = fs::read_to_string(&path)?;
        assert_eq!(WorkerConfig::load(&path)?.2, 3);
        let other_key = dir.path("other.key");
        fs::copy(&source.key_file, &other_key)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&other_key, fs::Permissions::from_mode(0o600))?;
        }
        for field in ["nonce", "ciphertext", "tag", "key-path"] {
            rewrite_envelope(&path, |envelope| match field {
                "nonce" => {
                    let replacement = if envelope.nonce.starts_with('0') { "1" } else { "0" };
                    envelope.nonce.replace_range(..1, replacement);
                }
                "ciphertext" | "tag" => {
                    let index = if field == "tag" {
                        envelope.ciphertext.len() - 1
                    } else {
                        0
                    };
                    let replacement = if envelope.ciphertext.as_bytes()[index] == b'0' {
                        "1"
                    } else {
                        "0"
                    };
                    envelope.ciphertext.replace_range(index..index + 1, replacement);
                }
                "key-path" => envelope.key_file = other_key.clone(),
                _ => unreachable!(),
            })?;
            let error = WorkerConfig::load(&path).err().ok_or("altered envelope accepted")?;
            assert!(error.to_string().contains("authentication"), "{field}: {error}");
            fs::write(&path, &valid)?;
        }
        let legacy = toml::to_string(&sealed)?.replace("version = 2", "version = 1");
        fs::write(&path, format!("{legacy}authentication-tag = \"{}\"\n", "0".repeat(64)))?;
        assert!(WorkerConfig::load(&path).is_err());
        fs::write(&path, &valid)?;
        fs::write(&other_key, [0x43; 32])?;
        let wrong_path = dir.path("wrong-signature.toml");
        sealed.write_new(&wrong_path, &other_key)?;
        let error = WorkerConfig::load(&wrong_path)
            .err()
            .ok_or("incorrect signing key accepted")?;
        assert!(error.to_string().contains("authentication"), "{error}");
        fs::write(&source.key_file, [0x43; 32])?;
        let error = WorkerConfig::load(&path).err().ok_or("wrong worker key accepted")?;
        assert!(error.to_string().contains("authentication"), "{error}");
        fs::write(&source.key_file, [0; 32])?;
        assert!(WorkerConfig::load(&path).is_err());
        fs::write(&source.key_file, [0x42; 32])?;
        assert_eq!(WorkerConfig::load(&path)?.2, 3);
        Ok(())
    }

    #[test]
    fn path_aliases_and_different_images_fail_closed() -> Result<()> {
        let dir = TestDir::new()?;
        let source = dir.config()?;
        assert!(WorkerConfig::from_worker(&source, "192.0.2.1:9001".parse()?, 0).is_err());
        let sealed = WorkerConfig::from_worker(&source, listener()?, 1)?;
        let path = dir.path("worker.toml");
        sealed.write_new(&path, &source.key_file)?;
        let valid = fs::read_to_string(&path)?;
        let alias = source
            .binary
            .parent()
            .ok_or("missing image parent")?
            .join(".")
            .join("image");
        sealed_with(&path, &source.key_file, |inner| inner.binary = alias)?;
        assert!(WorkerConfig::load(&path).is_err());
        let other = dir.path("different-image");
        fs::write(&other, b"\x7fELFworker-target-v2")?;
        fs::write(&path, &valid)?;
        sealed_with(&path, &source.key_file, |inner| inner.binary = other)?;
        assert!(WorkerConfig::load(&path).is_err());
        Ok(())
    }

    #[test]
    fn remote_image_path_must_be_normalized_and_staged_with_same_bytes() -> Result<()> {
        let generator = TestDir::new()?;
        let worker = TestDir::new()?;
        let mut source = generator.config()?;
        let signing_key = source.key_file.clone();
        source.key_file = worker.path("worker.key");
        let mut sealed = WorkerConfig::from_worker(&source, listener()?, 1)?;
        let remote = worker.path("image");
        assert!(!remote.exists());
        for invalid in [
            PathBuf::from("relative/image"),
            worker.path("../image"),
            worker.path("./image"),
        ] {
            assert!(sealed.set_worker_binary_path(invalid).is_err());
        }
        sealed.set_worker_binary_path(remote.clone())?;
        let path = generator.path("worker.toml");
        sealed.write_new(&path, &signing_key)?;
        let text = fs::read_to_string(&path)?;
        assert!(!text.contains(&signing_key.display().to_string()));
        assert!(WorkerConfig::load(&path).is_err());
        fs::copy(&signing_key, &source.key_file)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&source.key_file, fs::Permissions::from_mode(0o600))?;
        }
        fs::copy(&source.binary, &remote)?;
        let (loaded, _, _, digest) = WorkerConfig::load(&path)?;
        assert_eq!(loaded.binary, fs::canonicalize(&remote)?);
        assert_ne!(loaded.binary, fs::canonicalize(&source.binary)?);
        assert_eq!(digest, sealed.image_sha256);
        fs::write(&remote, b"\x7fELFworker-target-v2")?;
        assert!(WorkerConfig::load(&path).is_err());
        Ok(())
    }

    #[test]
    fn constructor_rejects_zero_resolved_limits() -> Result<()> {
        let dir = TestDir::new()?;
        let source = dir.config()?;
        for field in [
            "max_steps",
            "max_path_steps",
            "max_active_states",
            "max_path_depth",
            "max_loop_visits",
            "max_solver_millis",
            "max_wall_millis",
            "max_ram_bytes",
            "max_disk_bytes",
            "max_trace_bytes",
        ] {
            let mut invalid = source.clone();
            match field {
                "max_steps" => invalid.limits.max_steps = 0,
                "max_path_steps" => invalid.limits.max_path_steps = 0,
                "max_active_states" => invalid.limits.max_active_states = 0,
                "max_path_depth" => invalid.limits.max_path_depth = 0,
                "max_loop_visits" => invalid.limits.max_loop_visits = 0,
                "max_solver_millis" => invalid.limits.max_solver_millis = 0,
                "max_wall_millis" => invalid.limits.max_wall_millis = 0,
                "max_ram_bytes" => invalid.limits.max_ram_bytes = RamCap::Bytes(0),
                "max_disk_bytes" => invalid.limits.max_disk_bytes = 0,
                "max_trace_bytes" => invalid.limits.max_trace_bytes = 0,
                _ => unreachable!(),
            }
            assert!(WorkerConfig::from_worker(&invalid, listener()?, 1).is_err(), "{field}");
        }
        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn pinned_serve_rejects_image_changed_after_load_before_bind() -> Result<()> {
        let dir = TestDir::new()?;
        let source = dir.config()?;
        let sealed = WorkerConfig::from_worker(&source, listener()?, 1)?;
        let path = dir.path("worker.toml");
        sealed.write_new(&path, &source.key_file)?;
        let (loaded, _, _, digest) = WorkerConfig::load(&path)?;
        fs::write(&source.binary, b"\x7fELFworker-target-v2")?;
        // Invalid ELF would fail later; the digest must fail before bind/READY.
        let error = crate::serve_pinned(&loaded, listener()?, 1, &digest)
            .err()
            .ok_or("changed image accepted after load")?;
        assert!(error.to_string().contains("image SHA256 mismatch"), "{error}");
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn rejects_public_files_symlinks_nonregular_and_oversized() -> Result<()> {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let dir = TestDir::new()?;
        let source = dir.config()?;
        let sealed = WorkerConfig::from_worker(&source, listener()?, 1)?;
        let path = dir.path("worker.toml");
        sealed.write_new(&path, &source.key_file)?;
        let link = dir.path("alias.toml");
        symlink(&path, &link)?;
        assert!(WorkerConfig::load(&link).is_err());
        assert!(WorkerConfig::load(&dir.0).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?;
        assert!(WorkerConfig::load(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        OpenOptions::new()
            .write(true)
            .open(&path)?
            .set_len(MAX_CONFIG_BYTES + 1)?;
        assert!(WorkerConfig::load(&path).is_err());
        Ok(())
    }
}
