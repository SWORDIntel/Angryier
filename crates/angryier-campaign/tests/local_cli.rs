//! Bounded subprocess coverage of the shipped campaign CLI.
#![cfg(target_arch = "x86_64")]

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    dir: PathBuf,
    binary: PathBuf,
    ledger: PathBuf,
    entry: u64,
}

impl Fixture {
    fn new() -> TestResult<Self> {
        // ELF branch using the legacy symbolic RBX default.
        Self::new_with_code(&[
            0x48, 0x83, 0xfb, 0x05, // cmp $5,%rbx
            0x74, 0x06, // je +6
            0x31, 0xc0, // xor %eax,%eax
            0xeb, 0x02, // jmp +2
            0x90, 0x90, 0x48, 0xc7, 0xc0, 0x3c, 0, 0, 0, // mov $60,%rax
            0x0f, 0x05, // syscall
        ])
    }

    fn new_with_code(code: &[u8]) -> TestResult<Self> {
        let dir = std::env::temp_dir().join(format!(
            "angryier-local-cli-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir)?;
        let binary = dir.join("branch.elf");
        let ledger = dir.join("campaign.ledger");
        let entry = 0x400000u64 + 120;
        // ELF64 ET_EXEC, one static R+X PT_LOAD.
        let mut elf = vec![0u8; 4096];
        elf[..7].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1]);
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
        elf[80..88].copy_from_slice(&0x400000u64.to_le_bytes());
        elf[88..96].copy_from_slice(&0x400000u64.to_le_bytes());
        elf[96..104].copy_from_slice(&4096u64.to_le_bytes());
        elf[104..112].copy_from_slice(&4096u64.to_le_bytes());
        elf[112..120].copy_from_slice(&4096u64.to_le_bytes());
        elf[120..120 + code.len()].copy_from_slice(code);
        fs::write(&binary, elf)?;
        Ok(Self {
            dir,
            binary,
            ledger,
            entry,
        })
    }

    fn command(&self, role: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_angryier-campaign"));
        command
            .arg(role)
            .arg("--binary")
            .arg(&self.binary)
            .arg("--build-id")
            .arg("local-cli-v1");
        if role.starts_with("local-") {
            command.arg("--ledger").arg(&self.ledger);
        }
        command
    }

    fn local(&self, role: &str, extra: &[&str]) -> TestResult<Output> {
        self.local_bounded(role, extra, Duration::from_secs(75))
    }

    fn local_bounded(&self, role: &str, extra: &[&str], limit: Duration) -> TestResult<Output> {
        let mut command = self.command(role);
        command
            .args(["--policy", "rank-targets", "--find"])
            .arg(format!("0x{:x}", self.entry + 12))
            .args(["--avoid"])
            .arg(format!("0x{:x}", self.entry + 6))
            .args(["--max-steps", "4", "--max-wall-ms", "10000"])
            .args(extra);
        bounded_with_limit(command, limit)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn bounded(command: Command) -> TestResult<Output> {
    bounded_with_limit(command, Duration::from_secs(75))
}

fn bounded_with_limit(mut command: Command, limit: Duration) -> TestResult<Output> {
    let description = format!("{command:?}");
    let mut child = command.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?;
    let deadline = Instant::now() + limit;
    loop {
        if child.try_wait()?.is_some() {
            return Ok(child.wait_with_output()?);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output()?;
            return Err(format!("CLI timed out: {description}: {output:?}").into());
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn success(output: &Output) {
    assert!(output.status.success(), "{output:?}");
}

fn rejected(output: &Output, message: &str) {
    assert!(!output.status.success(), "unexpected success: {output:?}");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(message),
        "expected {message:?}: {output:?}"
    );
}

fn ledger_bytes(path: &Path) -> TestResult<(Vec<u8>, Option<Vec<u8>>)> {
    let wal = PathBuf::from(format!("{}.wal", path.display()));
    Ok((fs::read(path)?, wal.exists().then(|| fs::read(wal)).transpose()?))
}

// The CLI emits flat JSON objects; keep this test independent of a JSON crate.
fn flat_json_line(line: &str) -> bool {
    fn string(bytes: &[u8], index: &mut usize) -> bool {
        if bytes.get(*index) != Some(&b'"') {
            return false;
        }
        *index += 1;
        while let Some(&byte) = bytes.get(*index) {
            *index += 1;
            match byte {
                b'"' => return true,
                b'\\' => {
                    let Some(&escaped) = bytes.get(*index) else {
                        return false;
                    };
                    *index += 1;
                    if escaped == b'u' {
                        if !bytes
                            .get(*index..*index + 4)
                            .is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit))
                        {
                            return false;
                        }
                        *index += 4;
                    } else if !b"\"\\/bfnrt".contains(&escaped) {
                        return false;
                    }
                }
                0..=31 => return false,
                _ => {}
            }
        }
        false
    }
    let bytes = line.as_bytes();
    if bytes.first() != Some(&b'{') {
        return false;
    }
    let mut i = 1;
    loop {
        if bytes.get(i) == Some(&b'}') {
            return i + 1 == bytes.len();
        }
        if !string(bytes, &mut i) || bytes.get(i) != Some(&b':') {
            return false;
        }
        i += 1;
        if bytes.get(i) == Some(&b'"') {
            if !string(bytes, &mut i) {
                return false;
            }
        } else {
            let start = i;
            while bytes.get(i).is_some_and(|b| b.is_ascii_alphanumeric()) {
                i += 1;
            }
            let token = &line[start..i];
            if token != "null"
                && token != "true"
                && token != "false"
                && (token.is_empty() || !token.bytes().all(|b| b.is_ascii_digit()))
            {
                return false;
            }
        }
        match bytes.get(i) {
            Some(b',') => i += 1,
            Some(b'}') => return i + 1 == bytes.len(),
            _ => return false,
        }
    }
}

#[test]
fn disposition_reason_json_syntax_regression() {
    let escaped = "{\"disposition\":\"Pending(Unknown(\\\"quote\\\\slash\\nline\\\"))\"}";
    assert!(flat_json_line(escaped));
    let unescaped = "{\"disposition\":\"Pending(Unknown(\"quote\\slash\nline\"))\"}";
    assert!(!flat_json_line(unescaped));
}

#[test]
fn real_cli_start_advance_status_resume_retry() -> TestResult {
    let f = Fixture::new()?;
    rejected(&f.local("local-resume", &[])?, "No such file or directory");
    let started = f.local("local-start", &[])?;
    success(&started);
    assert!(
        String::from_utf8_lossy(&started.stdout).contains("queued: 1"),
        "{started:?}"
    );
    rejected(&f.local("local-start", &[])?, "File exists");
    let before = ledger_bytes(&f.ledger)?;
    let status = f.local("local-status", &[])?;
    success(&status);
    assert_eq!(status.stdout, started.stdout);
    assert_eq!(ledger_bytes(&f.ledger)?, before);
    let advanced = f.local("local-advance", &[])?;
    let text = String::from_utf8_lossy(&advanced.stdout);
    if advanced.status.success() {
        assert!(text.contains("complete_within_declared_bounds: true"), "{advanced:?}");
    } else {
        rejected(&advanced, "campaign partial: unresolved owned work remains");
        assert!(text.contains("complete_within_declared_bounds: false"), "{advanced:?}");
    }
    assert!(text.contains("\"type\":\"evidence_latest\""), "{advanced:?}");
    assert!(text.contains("\"type\":\"evidence_event\""), "{advanced:?}");
    for line in text.lines().filter(|line| line.starts_with('{')) {
        assert!(flat_json_line(line), "invalid JSONL row: {line:?}");
    }
    let resumed = f.local("local-resume", &[])?;
    success(&resumed);
    assert_eq!(
        resumed.stdout, advanced.stdout,
        "restart changed accepted evidence or target observation"
    );
    let status_after_resume = f.local("local-status", &[])?;
    success(&status_after_resume);
    assert_eq!(
        status_after_resume.stdout, advanced.stdout,
        "status duplicated accepted events"
    );
    assert!(
        text.lines().any(|line| line.contains("\"type\":\"target\"")
            && line.contains("\"kind\":\"find\"")
            && line.contains("\"observed\":false")
            && line.contains("\"path_id\":null")),
        "{advanced:?}"
    );
    assert!(
        text.lines().any(|line| line.contains("\"type\":\"target\"")
            && line.contains("\"kind\":\"avoid\"")
            && line.contains("\"observed\":false")
            && line.contains("\"path_id\":null")),
        "{advanced:?}"
    );
    let retried = f.local("local-retry", &[])?;
    success(&retried);
    let after_retry = f.local("local-status", &[])?;
    success(&after_retry);
    assert_eq!(retried.stdout, after_retry.stdout);
    let next = f.local("local-advance", &[])?;
    if !next.status.success() {
        rejected(&next, "campaign partial: unresolved owned work remains");
    }
    let next_text = String::from_utf8_lossy(&next.stdout);
    assert!(
        next_text.lines().any(|line| line.contains("\"type\":\"target\"")
            && line.contains("\"kind\":\"find\"")
            && line.contains("\"observed\":true")
            && line.contains("\"path_id\":\"")),
        "target not verified after child advance: {next:?}"
    );
    let status = f.local("local-status", &[])?;
    success(&status);
    assert_eq!(
        status.stdout, next.stdout,
        "verified target or evidence identity changed on restart"
    );
    Ok(())
}

#[test]
fn real_cli_terminal_without_verified_witness_is_not_observed_after_restart() -> TestResult {
    let f = Fixture::new_with_code(&[
        0x48, 0xc7, 0xc0, 0x3c, 0, 0, 0, // mov $60,%rax
        0x0f, 0x05, // syscall
    ])?;
    let entry = format!("0x{:x}", f.entry);
    let options = ["--find", entry.as_str()];
    success(&f.local("local-start", &options)?);
    let advanced = f.local("local-advance", &options)?;
    success(&advanced);
    let text = String::from_utf8_lossy(&advanced.stdout);
    let target = text
        .lines()
        .find(|line| line.contains("\"type\":\"target\"") && line.contains(&format!("\"pc\":{}", f.entry)))
        .ok_or("entry target missing")?;
    assert!(
        target.contains("\"observed\":false") && target.contains("\"path_id\":null"),
        "{target}"
    );
    assert!(
        text.lines().any(|line| line.contains("\"type\":\"evidence_latest\"")
            && line.contains("\"status\":\"Completed\"")
            && line.contains("\"verified_trace_digest\":null")),
        "{advanced:?}"
    );
    let before = ledger_bytes(&f.ledger)?;
    for role in ["local-resume", "local-status"] {
        let output = f.local(role, &options)?;
        success(&output);
        assert_eq!(output.stdout, advanced.stdout, "{role} changed accepted evidence");
    }
    assert_eq!(ledger_bytes(&f.ledger)?, before, "read-only status appended an event");
    Ok(())
}

#[test]
fn real_cli_unproven_exclusion_never_prints_completion() -> TestResult {
    let f = Fixture::new_with_code(&[
        0x48, 0xc7, 0xc0, 0x3c, 0, 0, 0, // mov $60,%rax
        0x0f, 0x05, // syscall
    ])?;
    success(&f.local("local-start", &["--exclude-avoid"])?);
    let advanced = f.local("local-advance", &["--exclude-avoid"])?;
    rejected(&advanced, "ExclusionUnproven");
    assert!(
        advanced.stdout.is_empty(),
        "unproven exclusion printed completion: {advanced:?}"
    );
    let status = f.local("local-status", &["--exclude-avoid"])?;
    rejected(&status, "ExclusionUnproven");
    assert!(
        status.stdout.is_empty(),
        "unproven exclusion printed completion: {status:?}"
    );
    Ok(())
}

#[test]
fn real_cli_rejects_changed_image_limits_policy_and_targets() -> TestResult {
    let f = Fixture::new()?;
    success(&f.local("local-start", &[])?);
    let before = ledger_bytes(&f.ledger)?;
    for (extra, message) in [
        (vec!["--max-steps", "5"], "MismatchedCampaign"),
        (vec!["--policy", "fork-all"], "MismatchedCampaign"),
        (vec!["--exclude-avoid"], "MismatchedCampaign"),
        (vec!["--find", "0x401000"], "MismatchedCampaign"),
        (vec!["--build-id", "local-cli-v2"], "MismatchedCampaign"),
    ] {
        rejected(&f.local("local-resume", &extra)?, message);
        assert_eq!(ledger_bytes(&f.ledger)?, before);
    }
    let original = fs::read(&f.binary)?;
    let mut changed = original.clone();
    let last = changed.len() - 1;
    changed[last] ^= 1;
    fs::write(&f.binary, changed)?;
    rejected(&f.local("local-resume", &[])?, "MismatchedCampaign");
    assert_eq!(ledger_bytes(&f.ledger)?, before);
    fs::write(&f.binary, original)?;
    success(&f.local("local-resume", &[])?);
    Ok(())
}

#[test]
fn real_cli_rejects_network_flags_without_changing_distributed_roles() -> TestResult {
    let f = Fixture::new()?;
    for flag in [
        "--listen",
        "--connect",
        "--peer",
        "--key-file",
        "--worker-id",
        "--connections",
        "--progress-jsonl",
        "--entry",
        "--image-mode",
    ] {
        rejected(&f.local("local-start", &[flag, "127.0.0.1:0"])?, "unsupported option");
        assert!(!f.ledger.exists(), "{flag} created a ledger");
    }
    rejected(&f.local("local-start", &["--policy", "unknown"])?, "--policy requires");
    rejected(
        &f.local("local-start", &["--policy", "fork-all", "--exclude-avoid"])?,
        "--exclude-avoid requires",
    );
    // The same executable still dispatches worker and coordinator roles, and
    // applies their original role-specific parser and key validation.
    for role in ["worker", "coordinator"] {
        let mut command = f.command(role);
        command.args(if role == "worker" {
            ["--listen", "127.0.0.1:0"]
        } else {
            ["--connect", "127.0.0.1:0"]
        });
        if role == "coordinator" {
            command.arg("--ledger").arg(&f.ledger);
        }
        rejected(&bounded(command)?, "No such file or directory");
        let mut command = f.command(role);
        command.args(["--policy", "rank-targets"]);
        rejected(&bounded(command)?, "unsupported option --policy");
    }
    Ok(())
}

#[test]
fn real_cli_multi_symbolic_and_seeded_root_survives_restart() -> TestResult {
    let f = Fixture::new_with_code(&[
        0x48, 0x83, 0xfa, 0x07, // cmp $7,%rdx
        0x75, 0x06, // jne +6
        0x48, 0x83, 0xff, 0x05, // cmp $5,%rdi
        0x74, 0x06, // je +6
        0x31, 0xc0, // xor %eax,%eax
        0xeb, 0x02, // jmp +2
        0x90, 0x90, 0x48, 0xc7, 0xc0, 0x3c, 0, 0, 0, // mov $60,%rax
        0x0f, 0x05, // syscall
    ])?;
    let root = [
        "--symbolic",
        "rdi",
        "--symbolic",
        "rsi",
        "--reg",
        "rdx=0x7",
        "--reg",
        "r8=10",
    ];
    success(&f.local("local-start", &root)?);
    let status = f.local("local-status", &root)?;
    success(&status);
    assert!(
        String::from_utf8_lossy(&status.stdout).contains("queued: 1"),
        "{status:?}"
    );
    let advanced = f.local("local-advance", &root)?;
    if !advanced.status.success() {
        rejected(&advanced, "campaign partial: unresolved owned work remains");
    }
    assert!(
        String::from_utf8_lossy(&advanced.stdout).contains("\"type\":\"evidence_event\""),
        "{advanced:?}"
    );
    success(&f.local("local-resume", &root)?);
    success(&f.local("local-retry", &root)?);
    success(&f.local("local-status", &root)?);
    let before = ledger_bytes(&f.ledger)?;
    for role in ["local-resume", "local-status", "local-advance", "local-retry"] {
        let mut changed = root.to_vec();
        changed[5] = "rdx=8";
        rejected(&f.local(role, &changed)?, "MismatchedCampaign");
        changed[5] = root[5];
        changed[3] = "rbx";
        rejected(&f.local(role, &changed)?, "MismatchedCampaign");
        rejected(&f.local(role, &root[..6])?, "MismatchedCampaign");
        assert_eq!(ledger_bytes(&f.ledger)?, before, "{role} changed ledger");
    }
    for invalid in [
        vec!["--symbolic", "rdi", "--symbolic-reg", "rbx"],
        vec!["--symbolic-reg", "rcx", "--symbolic", "rdi"],
        vec!["--symbolic", "eax"],
        vec!["--reg", "rdx=-1"],
        vec!["--reg", "rdx=0x10000000000000000"],
    ] {
        rejected(&f.local("local-resume", &invalid)?, "campaign:");
    }
    let mut worker = f.command("worker");
    worker.args(["--listen", "127.0.0.1:0", "--symbolic", "rdi"]);
    rejected(&bounded(worker)?, "unsupported option --symbolic");
    Ok(())
}

#[test]
fn real_cli_local_run_rejects_invalid_time_bounds() -> TestResult {
    let f = Fixture::new()?;
    for options in [
        ["--batch-ms", "0"],
        ["--run-ms", "0"],
        ["--batch-ms", "invalid"],
        ["--run-ms", "invalid"],
        ["--batch-ms", "10001"],
        ["--run-ms", "10001"],
    ] {
        let output = f.local_bounded("local-run", &options, Duration::from_secs(1))?;
        assert_eq!(output.status.code(), Some(1), "{options:?}: {output:?}");
        assert!(!output.stderr.is_empty(), "{options:?}: {output:?}");
        assert!(!f.ledger.exists(), "{options:?} created a ledger");
    }
    Ok(())
}

#[test]
fn real_cli_local_run_creates_reports_and_resumes_without_duplicate_ids() -> TestResult {
    let f = Fixture::new()?;
    let options = ["--batch-ms", "1", "--run-ms", "400"];
    assert!(!f.ledger.exists());
    let first = f.local_bounded("local-run", &options, Duration::from_secs(120))?;
    assert!(matches!(first.status.code(), Some(0 | 2)), "{first:?}");
    assert!(f.ledger.exists(), "local-run did not create its ledger");
    let first_text = String::from_utf8_lossy(&first.stdout);
    let reports: Vec<_> = first_text.lines().filter(|line| line.starts_with("Report {")).collect();
    assert!(!reports.is_empty(), "no per-batch report: {first:?}");
    let first_ids: Vec<_> = first_text
        .lines()
        .filter(|line| line.starts_with("{\"type\":\"accepted_event_id\""))
        .collect();
    assert!(!first_ids.is_empty(), "no accepted progress: {first:?}");
    assert!(first_ids.iter().all(|line| flat_json_line(line)), "{first:?}");
    assert!(
        first_text
            .lines()
            .next()
            .is_some_and(|line| line.starts_with("Report {")),
        "{first:?}"
    );
    let second = f.local_bounded("local-run", &options, Duration::from_secs(120))?;
    assert!(matches!(second.status.code(), Some(0 | 2)), "{second:?}");
    let second_text = String::from_utf8_lossy(&second.stdout);
    assert!(
        second_text.lines().any(|line| line.starts_with("Report {")),
        "{second:?}"
    );
    let mut ids: std::collections::HashSet<_> = first_ids.iter().copied().collect();
    assert_eq!(
        ids.len(),
        first_ids.len(),
        "duplicate accepted IDs within first run: {first:?}"
    );
    for line in second_text
        .lines()
        .filter(|line| line.starts_with("{\"type\":\"accepted_event_id\""))
    {
        assert!(
            flat_json_line(line) && ids.insert(line),
            "duplicate or invalid accepted ID: {line}"
        );
    }
    Ok(())
}

#[test]
fn real_cli_local_run_replays_committed_ids_after_lost_stdout() -> TestResult {
    fn id(line: &str) -> Vec<String> {
        let fields: Vec<_> = ["work_index", "attempt", "sequence", "path_id", "replay_digest"]
            .iter()
            .filter_map(|key| {
                line.split_once(&format!("\"{key}\":"))
                    .and_then(|(_, tail)| tail.split([',', '}']).next())
                    .map(str::to_owned)
            })
            .collect();
        assert_eq!(fields.len(), 5, "missing stable event ID field: {line}");
        assert!(
            fields.iter().all(|value| !value.is_empty()),
            "missing event ID value: {line}"
        );
        fields
    }

    for (f, limit, expected_exit) in [
        (Fixture::new()?, "1", 2),
        (
            Fixture::new_with_code(&[0x48, 0xc7, 0xc0, 0x3c, 0, 0, 0, 0x0f, 0x05])?,
            "4",
            0,
        ),
    ] {
        let options = ["--max-steps", limit];
        success(&f.local("local-start", &options)?);
        let advanced = f.local("local-advance", &options)?;
        assert!(matches!(advanced.status.code(), Some(0 | 1)), "{advanced:?}");
        let history: Vec<_> = String::from_utf8_lossy(&advanced.stdout)
            .lines()
            .filter(|line| line.starts_with("{\"type\":\"evidence_event\""))
            .map(id)
            .collect();
        assert!(!history.is_empty(), "no committed history: {advanced:?}");
        // Treat all local-start/local-advance stdout as lost after the ledger commit.
        let run_options = ["--max-steps", limit, "--batch-ms", "1", "--run-ms", "400"];
        let first = f.local_bounded("local-run", &run_options, Duration::from_secs(120))?;
        assert_eq!(first.status.code(), Some(expected_exit), "{first:?}");
        let first_text = String::from_utf8_lossy(&first.stdout);
        let replay: Vec<_> = first_text
            .lines()
            .filter(|line| line.starts_with("{\"type\":\"replayed_event_id\""))
            .inspect(|line| assert!(flat_json_line(line), "{line}"))
            .map(id)
            .collect();
        assert_eq!(replay, history, "lost accepted IDs not reconstructed: {first:?}");
        assert!(
            first_text
                .lines()
                .next()
                .is_some_and(|line| line.starts_with("{\"type\":\"replayed_event_id\"")),
            "history must precede report/advance: {first:?}"
        );
        let first_new: Vec<_> = first_text
            .lines()
            .filter(|line| line.starts_with("{\"type\":\"accepted_event_id\""))
            .map(id)
            .collect();
        assert!(
            first_new.iter().all(|event| !history.contains(event)),
            "historical event labelled newly accepted: {first:?}"
        );

        let second = f.local_bounded("local-run", &run_options, Duration::from_secs(120))?;
        assert_eq!(second.status.code(), Some(expected_exit), "{second:?}");
        let second_text = String::from_utf8_lossy(&second.stdout);
        let mut all_history = history;
        all_history.extend(first_new);
        let second_replay: Vec<_> = second_text
            .lines()
            .filter(|line| line.starts_with("{\"type\":\"replayed_event_id\""))
            .inspect(|line| assert!(flat_json_line(line), "{line}"))
            .map(id)
            .collect();
        assert_eq!(
            second_replay, all_history,
            "restart did not reconstruct full history: {second:?}"
        );
        for line in second_text
            .lines()
            .filter(|line| line.starts_with("{\"type\":\"accepted_event_id\""))
        {
            assert!(
                flat_json_line(line) && !all_history.contains(&id(line)),
                "duplicate or falsely new ID: {line}"
            );
        }
    }
    Ok(())
}

#[test]
fn real_cli_local_run_partial_deferred_stops_and_mismatch_is_hard_error() -> TestResult {
    let f = Fixture::new()?;
    let options = ["--max-steps", "1", "--batch-ms", "1", "--run-ms", "400"];
    let partial = f.local_bounded("local-run", &options, Duration::from_secs(120))?;
    assert_eq!(partial.status.code(), Some(2), "{partial:?}");
    let text = String::from_utf8_lossy(&partial.stdout);
    let deferred = text
        .lines()
        .filter_map(|line| line.split_once("deferred: "))
        .filter_map(|(_, tail)| tail.split(',').next()?.parse::<usize>().ok())
        .next_back();
    assert!(
        deferred.is_some_and(|count| count > 0) && text.contains("complete_within_declared_bounds: false"),
        "{partial:?}"
    );
    let resumed = f.local_bounded("local-run", &options, Duration::from_secs(120))?;
    assert_eq!(resumed.status.code(), Some(2), "{resumed:?}");
    assert!(
        String::from_utf8_lossy(&resumed.stdout)
            .lines()
            .filter(|line| line.starts_with("Report {"))
            .count()
            <= 2,
        "deferred resume spun: {resumed:?}"
    );
    let mismatch = f.local_bounded(
        "local-run",
        &["--max-steps", "2", "--batch-ms", "1", "--run-ms", "400"],
        Duration::from_secs(120),
    )?;
    assert_eq!(mismatch.status.code(), Some(1), "{mismatch:?}");
    rejected(&mismatch, "MismatchedCampaign");
    Ok(())
}
