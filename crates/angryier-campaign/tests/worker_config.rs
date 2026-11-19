#![cfg(all(unix, target_arch = "x86_64"))]
use angryier_ledger::evidence::ReplayVerification;
use std::{
    fs,
    io::{BufRead, BufReader, Read},
    net::SocketAddr,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const BIN: &str = env!("CARGO_BIN_EXE_angryier-campaign");
const WATCHDOG: Duration = Duration::from_secs(120);
const SOURCE: &str = ".global _start\n.text\n_start:\n cmp $5, %rbx\n je equal\n mov $1, %rdi\n jmp exit\nequal:\n xor %rdi, %rdi\nexit:\n mov $60, %rax\n syscall\n";
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    dir: PathBuf,
    local: PathBuf,
    remote: PathBuf,
    key: PathBuf,
    sign_key: PathBuf,
    config: PathBuf,
}
impl Fixture {
    fn new() -> TestResult<Self> {
        let dir = std::env::temp_dir().join(format!(
            "angryier-config-process-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir)?;
        let source = dir.join("fixture.s");
        let object = dir.join("fixture.o");
        let local = dir.join("local.elf");
        let remote = dir.join("remote.elf");
        let key = dir.join("remote.key");
        let sign_key = dir.join("local-signing.key");
        let config = dir.join("worker.toml");
        fs::write(&source, SOURCE)?;
        fs::write(&key, [0x4bu8; 32])?;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600))?;
        fs::write(&sign_key, [0x4bu8; 32])?;
        fs::set_permissions(&sign_key, fs::Permissions::from_mode(0o600))?;
        assert!(
            Command::new("as")
                .args(["--64", "-o"])
                .arg(&object)
                .arg(&source)
                .status()?
                .success()
        );
        assert!(
            Command::new("ld")
                .arg("-o")
                .arg(&local)
                .arg(&object)
                .status()?
                .success()
        );
        let fixture = Self {
            dir,
            local,
            remote,
            key,
            sign_key,
            config,
        };
        let generated = fixture.generator(&fixture.config).output()?;
        assert!(
            generated.status.success(),
            "generator: {}",
            String::from_utf8_lossy(&generated.stderr)
        );
        fs::copy(&fixture.local, &fixture.remote)?;
        Ok(fixture)
    }
    fn generator(&self, output: &Path) -> Command {
        let mut command = Command::new(BIN);
        command
            .arg("worker-config")
            .arg("--binary")
            .arg(&self.local)
            .arg("--worker-binary")
            .arg(&self.remote)
            .arg("--worker-id")
            .arg("worker-a")
            .arg("--key-file")
            .arg(&self.key)
            .arg("--sign-key")
            .arg(&self.sign_key)
            .arg("--build-id")
            .arg("v1")
            .arg("--listen")
            .arg("127.0.0.1:0")
            .arg("--connections")
            .arg("1")
            .arg("--max-wall-ms")
            .arg("10000")
            .arg("--output")
            .arg(output);
        command
    }
    fn worker(&self, config: &Path) -> Command {
        let mut command = Command::new(BIN);
        command.arg("worker").arg("--config").arg(config);
        command
    }
    fn coordinator(&self, addr: SocketAddr) -> Command {
        let mut command = Command::new(BIN);
        command
            .arg("coordinator")
            .arg("--binary")
            .arg(&self.local)
            .arg("--build-id")
            .arg("v1")
            .arg("--max-wall-ms")
            .arg("10000")
            .arg("--ledger")
            .arg(self.dir.join("campaign.ledger"))
            .arg("--peer")
            .arg(format!("worker-a@{addr}@{}", self.key.display()));
        command
    }
    fn private_config(&self, name: &str, text: &str) -> TestResult<PathBuf> {
        let path = self.dir.join(name);
        fs::write(&path, text)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        Ok(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

struct Guard(Child);
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn bounded_output(mut command: Command) -> TestResult<Output> {
    let mut child = Guard(command.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?);
    let started = Instant::now();
    loop {
        if let Some(status) = child.0.try_wait()? {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            child
                .0
                .stdout
                .take()
                .ok_or("missing child stdout")?
                .read_to_end(&mut stdout)?;
            child
                .0
                .stderr
                .take()
                .ok_or("missing child stderr")?
                .read_to_end(&mut stderr)?;
            return Ok(Output { status, stdout, stderr });
        }
        assert!(
            started.elapsed() < WATCHDOG,
            "process exceeded {WATCHDOG:?}: {command:?}"
        );
        thread::sleep(Duration::from_millis(25));
    }
}
fn rejected(command: Command) -> TestResult {
    let output = bounded_output(command)?;
    assert!(
        !output.status.success(),
        "unexpected success: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        !output.stdout.windows(6).any(|window| window == b"READY "),
        "rejected worker bound a listener"
    );
    assert!(!output.stderr.is_empty(), "rejection did not report an error");
    Ok(())
}
fn ready(mut command: Command) -> TestResult<(Guard, SocketAddr)> {
    let mut worker = Guard(command.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?);
    let stdout = worker.0.stdout.take().ok_or("missing worker stdout")?;
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let mut line = String::new();
        let result = BufReader::new(stdout).read_line(&mut line);
        let _ = tx.send((result, line));
    });
    let (result, line) = rx.recv_timeout(WATCHDOG)?;
    assert_ne!(result?, 0, "worker exited without READY: {command:?}");
    let addr: SocketAddr = line
        .strip_prefix("READY ")
        .ok_or_else(|| format!("unexpected worker startup: {line:?}"))?
        .trim()
        .parse()?;
    assert!(
        addr.ip().is_loopback() && addr.port() != 0,
        "READY did not advertise an actual loopback port: {addr}"
    );
    Ok((worker, addr))
}

fn envelope(text: &str, key: &Path) -> TestResult<toml::Table> {
    let fields = text.parse::<toml::Table>()?;
    assert_eq!(fields.len(), 4, "envelope exposed additional fields: {fields:?}");
    assert_eq!(fields.get("version").and_then(toml::Value::as_integer), Some(2));
    assert_eq!(
        fields.get("key-file").and_then(toml::Value::as_str),
        Some(key.to_str().ok_or("non-UTF8 key path")?)
    );
    for name in ["nonce", "ciphertext"] {
        let value = fields
            .get(name)
            .and_then(toml::Value::as_str)
            .ok_or("missing encrypted envelope field")?;
        assert!(value.len() >= if name == "nonce" { 48 } else { 32 }, "short {name}");
        assert!(value.bytes().all(|byte| byte.is_ascii_hexdigit()), "non-hex {name}");
    }
    assert_eq!(fields["nonce"].as_str().ok_or("missing nonce")?.len(), 48);
    Ok(fields)
}

fn changed_envelope(text: &str, name: &str, value: toml::Value) -> TestResult<String> {
    let mut fields = text.parse::<toml::Table>()?;
    let original = fields.insert(name.into(), value).ok_or("missing envelope field")?;
    assert_ne!(fields.get(name), Some(&original), "fixture did not mutate {name}");
    Ok(toml::to_string(&fields)?)
}

fn flipped_first_char(value: &str) -> String {
    let first = if value.starts_with('0') { '1' } else { '0' };
    format!("{first}{}", value.chars().skip(1).collect::<String>())
}

#[test]
fn generated_handoff_is_private_and_never_overwritten() -> TestResult {
    let fixture = Fixture::new()?;
    let text = fs::read_to_string(&fixture.config)?;
    let fields = envelope(&text, &fixture.key)?;
    assert!(!text.contains(&fixture.remote.display().to_string()));
    assert!(!text.contains(&fixture.local.display().to_string()));
    assert!(!text.contains(&fixture.sign_key.display().to_string()));
    for hidden in [
        "executable-sha256",
        "image-sha256",
        "binary",
        "worker-id",
        "build-id",
        "image-mode",
        "entry",
        "symbolic-reg",
        "limits",
        "listen",
        "connections",
        "max-wall-millis",
        "authentication-tag",
        "worker-a",
        "127.0.0.1:0",
    ] {
        assert!(!text.contains(hidden), "envelope exposed {hidden}");
    }
    assert!(!text.as_bytes().windows(32).any(|bytes| bytes == [0x4b; 32]));
    assert!(!text.contains(&"4b".repeat(32)));
    assert_eq!(fs::metadata(&fixture.config)?.permissions().mode() & 0o777, 0o600);
    let second = fixture.dir.join("second.toml");
    let generated = fixture.generator(&second).output()?;
    assert!(
        generated.status.success(),
        "generator: {}",
        String::from_utf8_lossy(&generated.stderr)
    );
    let other = envelope(&fs::read_to_string(&second)?, &fixture.key)?;
    assert_ne!(fields.get("nonce"), other.get("nonce"), "nonce reused across handoffs");
    assert_ne!(
        fields.get("ciphertext"),
        other.get("ciphertext"),
        "ciphertext reused across handoffs"
    );
    rejected(fixture.generator(&fixture.config))?;
    assert_eq!(fs::read_to_string(&fixture.config)?, text);
    Ok(())
}

#[test]
fn generator_uses_local_signing_key_without_reading_remote_key_path() -> TestResult {
    let fixture = Fixture::new()?;
    let remote_key = fixture.dir.join("absent-on-generator.key");
    let output = fixture.dir.join("remote-key.toml");
    let generated = fixture.generator(&output).arg("--key-file").arg(&remote_key).output()?;
    assert!(
        generated.status.success(),
        "generator: {}",
        String::from_utf8_lossy(&generated.stderr)
    );
    assert!(!remote_key.exists());
    let text = fs::read_to_string(&output)?;
    envelope(&text, &remote_key)?;
    assert!(!text.contains(&fixture.sign_key.display().to_string()));
    assert!(!text.as_bytes().windows(32).any(|bytes| bytes == [0x4b; 32]));
    rejected(fixture.worker(&output))?;
    Ok(())
}

#[test]
fn envelope_tampering_and_wrong_key_fail_before_ready() -> TestResult {
    let fixture = Fixture::new()?;
    let text = fs::read_to_string(&fixture.config)?;
    let fields = envelope(&text, &fixture.key)?;
    let other_key = fixture.dir.join("other-remote.key");
    fs::copy(&fixture.key, &other_key)?;
    fs::set_permissions(&other_key, fs::Permissions::from_mode(0o600))?;
    let mut mutations = Vec::new();
    for name in ["nonce", "ciphertext"] {
        let original = fields
            .get(name)
            .and_then(toml::Value::as_str)
            .ok_or("missing encrypted field")?;
        mutations.push((
            name,
            changed_envelope(&text, name, flipped_first_char(original).into())?,
        ));
    }
    mutations.push(("version", changed_envelope(&text, "version", 3.into())?));
    mutations.push((
        "key-file",
        changed_envelope(&text, "key-file", other_key.display().to_string().into())?,
    ));
    for (name, changed) in mutations {
        let path = fixture.private_config(&format!("tampered-{name}.toml"), &changed)?;
        rejected(fixture.worker(&path))?;
    }
    let wrong_key = fixture.dir.join("wrong-signing.key");
    fs::write(&wrong_key, [0x5au8; 32])?;
    fs::set_permissions(&wrong_key, fs::Permissions::from_mode(0o600))?;
    let wrong_config = fixture.dir.join("wrong-signing.toml");
    let generated = fixture
        .generator(&wrong_config)
        .arg("--sign-key")
        .arg(&wrong_key)
        .output()?;
    assert!(
        generated.status.success(),
        "generator: {}",
        String::from_utf8_lossy(&generated.stderr)
    );
    rejected(fixture.worker(&wrong_config))?;
    fs::write(&fixture.key, [0x5au8; 32])?;
    rejected(fixture.worker(&fixture.config))?;
    Ok(())
}

#[test]
fn invalid_handoffs_fail_before_ready() -> TestResult {
    let fixture = Fixture::new()?;
    let text = fs::read_to_string(&fixture.config)?;
    envelope(&text, &fixture.key)?;
    let changed = [
        ("unknown", format!("unexpected = 1\n{text}")),
        ("duplicate", format!("version = 2\n{text}")),
        (
            "missing-ciphertext",
            text.lines()
                .filter(|line| !line.starts_with("ciphertext = "))
                .collect::<Vec<_>>()
                .join("\n"),
        ),
    ];
    for (name, changed_text) in changed {
        assert_ne!(changed_text, text, "fixture did not mutate {name}");
        let path = fixture.private_config(&format!("{name}.toml"), &changed_text)?;
        rejected(fixture.worker(&path))?;
    }
    let symlink_path = fixture.dir.join("linked.toml");
    symlink(&fixture.config, &symlink_path)?;
    rejected(fixture.worker(&symlink_path))?;
    let public = fixture.private_config("public.toml", &text)?;
    fs::set_permissions(&public, fs::Permissions::from_mode(0o644))?;
    rejected(fixture.worker(&public))?;
    let image = fixture.dir.join("original-image.elf");
    fs::rename(&fixture.remote, &image)?;
    symlink(&image, &fixture.remote)?;
    rejected(fixture.worker(&fixture.config))?;
    fs::remove_file(&fixture.remote)?;
    fs::rename(&image, &fixture.remote)?;
    let original = fs::read(&fixture.remote)?;
    fs::write(&fixture.remote, b"\x7fELFchanged-image")?;
    rejected(fixture.worker(&fixture.config))?;
    fs::write(&fixture.remote, original)?;
    for extras in [
        vec!["--listen", "127.0.0.1:0"],
        vec!["--binary", "ignored"],
        vec!["--config", "again"],
    ] {
        let mut command = fixture.worker(&fixture.config);
        command.args(extras);
        rejected(command)?;
    }
    Ok(())
}

#[test]
fn pinned_worker_accepts_verified_grant_and_replays_ledger() -> TestResult {
    use angryier_campaign::{Config, manifest};
    use angryier_ledger::sustained::SustainedLedger;
    use angryier_runtime::Runtime;
    use angryier_types::{SemanticVersion, TargetProfileId};
    use sha2::Digest as _;

    let fixture = Fixture::new()?;
    let elf = fs::read(&fixture.local)?;
    let mut profile = b"native-xed-v1/executable-sha256:".to_vec();
    profile.extend_from_slice(&sha2::Sha256::digest(fs::read(BIN)?));
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let entry = runtime.load_elf(&elf)?.pc()?;
    let mut config = Config::defaults(fixture.local.clone(), fixture.key.clone(), "v1".into());
    config.limits.max_wall_millis = 10_000;
    let sealed = manifest(&config, &elf, entry, &profile)?;
    let ledger_path = fixture.dir.join("campaign.ledger");
    let mut prior = 0;
    let mut statuses = Vec::new();
    for launch in 1..=5 {
        let (worker, addr) = ready(fixture.worker(&fixture.config))?;
        let output = bounded_output(fixture.coordinator(addr))?;
        drop(worker);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let partial = stdout.contains("campaign partial: accepted=")
            && stderr.trim() == "campaign: campaign partial: unresolved owned work remains";
        let exhausted_worker = stderr.trim() == "campaign: TCP I/O: Connection refused (os error 111)";
        assert!(
            output.status.success() || (output.status.code() == Some(1) && (partial || exhausted_worker)),
            "coordinator failed on launch {launch}: status={} stdout={stdout} stderr={stderr}",
            output.status
        );
        let ledger = SustainedLedger::open(&ledger_path, sealed.clone())?;
        let (_, events) = ledger.read_snapshot();
        let verified = events.iter().any(|event| {
            event
                .delta
                .path
                .witness
                .as_ref()
                .is_some_and(|witness| matches!(witness.replay, ReplayVerification::Verified { .. }))
        });
        statuses.push(format!(
            "launch {launch}: exit={}, accepted={}, verified={verified}, event_statuses={:?}",
            output.status,
            events.len(),
            events.iter().map(|event| &event.status).collect::<Vec<_>>()
        ));
        assert!(
            stdout.lines().any(|line| line.starts_with("accepted ")) && events.len() > prior,
            "new grant did not produce coordinator-accepted evidence: {statuses:?}; stdout={stdout}; stderr={stderr}"
        );
        prior = events.len();
        if launch >= 2 && verified {
            return Ok(());
        }
    }
    Err(format!("no independently verified replay witness after five worker launches: {statuses:?}").into())
}
