#![cfg(target_arch = "x86_64")]
#![allow(clippy::expect_used)]
use std::{
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
const SOURCE: &str = ".global _start\n.text\n_start:\n cmp $5, %rbx\n je equal\n mov $1, %rdi\n jmp exit\nequal:\n xor %rdi, %rdi\nexit:\n mov $60, %rax\n syscall\n";
struct Fixture {
    dir: PathBuf,
    elf: PathBuf,
    key: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "angryier-host-process-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir).expect("directory");
        let source = dir.join("program.s");
        let object = dir.join("program.o");
        let elf = dir.join("program.elf");
        fs::write(&source, SOURCE).expect("source");
        assert!(
            Command::new("as")
                .args(["--64", "-o"])
                .arg(&object)
                .arg(&source)
                .status()
                .expect("as")
                .success()
        );
        assert!(
            Command::new("ld")
                .arg("-o")
                .arg(&elf)
                .arg(&object)
                .status()
                .expect("ld")
                .success()
        );
        let key = dir.join("pairwise.key");
        fs::write(&key, [0x4bu8; 32]).expect("key");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("permissions");
        Self { dir, elf, key }
    }
    fn common<'a>(&'a self, cmd: &'a mut Command, version: &str) -> &'a mut Command {
        cmd.args([
            "--binary",
            self.elf.to_str().expect("elf"),
            "--key-file",
            self.key.to_str().expect("key"),
            "--build-id",
            version,
        ])
    }
    fn worker(&self, connections: u64) -> (Worker, String) {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_angryier-campaign"));
        cmd.arg("worker");
        self.common(&mut cmd, "build-v1");
        let mut child = cmd
            .args(["--listen", "127.0.0.1:0", "--connections", &connections.to_string()])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("worker");
        let mut line = String::new();
        BufReader::new(child.stdout.take().expect("worker stdout"))
            .read_line(&mut line)
            .expect("worker READY");
        assert!(line.starts_with("READY 127.0.0.1:"), "worker startup: {line:?}");
        (Worker(child), line.trim_start_matches("READY ").trim().to_owned())
    }
    fn keyed_worker(&self, index: usize, connections: u64) -> (Worker, String, PathBuf) {
        let key = self.dir.join(format!("worker-{index}.key"));
        fs::write(&key, [index as u8 + 1; 32]).expect("pairwise key");
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).expect("permissions");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_angryier-campaign"));
        cmd.args(["worker", "--binary"])
            .arg(&self.elf)
            .args(["--key-file"])
            .arg(&key)
            .args([
                "--build-id",
                "build-v1",
                "--worker-id",
                &format!("worker-{index}"),
                "--listen",
                "127.0.0.1:0",
                "--connections",
                &connections.to_string(),
            ]);
        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("worker");
        let mut line = String::new();
        BufReader::new(child.stdout.take().expect("stdout"))
            .read_line(&mut line)
            .expect("READY");
        assert!(line.starts_with("READY 127.0.0.1:"), "worker startup: {line:?}");
        (Worker(child), line.trim_start_matches("READY ").trim().into(), key)
    }
    fn pool(&self, peers: &[(String, String, PathBuf)]) -> std::process::Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_angryier-campaign"));
        cmd.args(["coordinator", "--binary"])
            .arg(&self.elf)
            .args(["--build-id", "build-v1", "--ledger"])
            .arg(self.ledger());
        for (id, addr, key) in peers {
            cmd.args(["--peer", &format!("{id}@{addr}@{}", key.display())]);
        }
        cmd.output().expect("coordinator")
    }
    fn coordinator(&self, addr: &str, version: &str) -> std::process::Output {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_angryier-campaign"));
        cmd.arg("coordinator");
        self.common(&mut cmd, version);
        cmd.args(["--connect", addr, "--ledger"])
            .arg(self.dir.join("campaign.ledger"));
        cmd.output().expect("coordinator")
    }
    fn ledger(&self) -> PathBuf {
        self.dir.join("campaign.ledger")
    }
    fn replace_elf(&self, assembly: &str) {
        let source = self.dir.join("changed.s");
        let object = self.dir.join("changed.o");
        fs::write(&source, assembly).expect("changed assembly");
        assert!(
            Command::new("as")
                .args(["--64", "-o"])
                .arg(&object)
                .arg(&source)
                .status()
                .expect("as")
                .success()
        );
        assert!(
            Command::new("ld")
                .arg("-o")
                .arg(&self.elf)
                .arg(&object)
                .status()
                .expect("ld")
                .success()
        );
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}
struct Worker(Child);
impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn report_ok(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("complete_within_declared_bounds: true"));
}
fn progress_path(f: &Fixture) -> PathBuf {
    PathBuf::from(format!("{}.progress.jsonl", f.ledger().display()))
}

fn accepted_rows(output: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(output)
        .lines()
        .filter_map(|line| line.strip_prefix("accepted ").map(str::to_owned))
        .collect()
}

fn assert_progress_matches_ledger(f: &Fixture) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    use sha2::Digest as _;
    let elf = fs::read(&f.elf)?;
    let mut profile = b"native-xed-v1/executable-sha256:".to_vec();
    profile.extend_from_slice(&sha2::Sha256::digest(fs::read(env!(
        "CARGO_BIN_EXE_angryier-campaign"
    ))?));
    let runtime = angryier_runtime::Runtime::with_native_xed(
        angryier_types::SemanticVersion(1),
        angryier_types::TargetProfileId(1),
    );
    let entry = runtime.load_elf(&elf)?.pc()?;
    let config = angryier_campaign::Config::defaults(f.elf.clone(), f.key.clone(), "build-v1".into());
    let manifest = angryier_campaign::manifest(&config, &elf, entry, &profile)?;
    let campaign = manifest
        .campaign_digest
        .0
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let ledger = angryier_ledger::sustained::SustainedLedger::open(f.ledger(), manifest)?;
    let (_, evidence) = ledger.read_snapshot();
    let text = fs::read_to_string(progress_path(f))?;
    assert!(text.ends_with('\n'), "progress must consist of complete JSONL rows");
    let rows: Vec<_> = text.lines().map(str::to_owned).collect();
    assert_eq!(
        rows.len(),
        evidence.len(),
        "mirror must contain exactly the accepted ledger history"
    );
    let mut ids = std::collections::HashSet::new();
    for (index, (row, event)) in rows.iter().zip(evidence).enumerate() {
        let id = format!("{campaign}:{index}");
        let path_id = event
            .delta
            .path
            .path_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert!(ids.insert(id.clone()), "duplicate stable event ID");
        assert!(
            row.starts_with(&format!(
                "{{\"event_id\":\"{id}\",\"path_id\":\"{path_id}\",\"status\":\"{:?}\"",
                event.status
            )),
            "row differs from ledger: {row}"
        );
        assert!(row.contains(&format!(
            "\"attempt\":{},\"sequence\":{}",
            event.attempt, event.delta.sequence
        )));
        assert!(row.contains("\"disposition\":"), "missing disposition: {row}");
        assert!(
            row.contains("\"block_pcs\":[") && row.contains("\"branch_pcs\":["),
            "missing PC arrays: {row}"
        );
        assert!(
            row.contains("\"witness_replay_verified\":") && row.contains("\"semantic_debt\":"),
            "missing evidence fields: {row}"
        );
        assert!(row.ends_with(" }"), "incomplete JSON object: {row}");
        // Check the JSONL object's string escaping and balanced containers without an extra JSON dependency.
        let mut stack = Vec::new();
        let (mut quoted, mut escaped) = (false, false);
        for ch in row.chars() {
            if quoted {
                if escaped {
                    escaped = false;
                } else if ch == '\\' {
                    escaped = true;
                } else if ch == '"' {
                    quoted = false;
                }
            } else {
                match ch {
                    '"' => quoted = true,
                    '{' | '[' => stack.push(ch),
                    '}' => assert_eq!(stack.pop(), Some('{'), "malformed JSON object: {row}"),
                    ']' => assert_eq!(stack.pop(), Some('['), "malformed JSON array: {row}"),
                    _ => {}
                }
            }
        }
        assert!(!quoted && !escaped && stack.is_empty(), "malformed JSONL row: {row}");
    }
    Ok(rows)
}

#[test]
fn separate_processes_replay_and_changed_manifest_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new();
    let (_worker, addr) = f.worker(8);
    report_ok(&f.coordinator(&addr, "build-v1"));
    let wrong = f.coordinator(&addr, "build-v2");
    assert!(!wrong.status.success(), "changed version unexpectedly resumed");
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("MismatchedCampaign"));
    let original = fs::read(&f.elf).expect("original ELF");
    f.replace_elf(&SOURCE.replace("mov $1", "mov $2"));
    let wrong = f.coordinator(&addr, "build-v1");
    assert!(!wrong.status.success(), "changed ELF unexpectedly resumed");
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("MismatchedCampaign"));
    fs::write(&f.elf, original).expect("restore ELF fixture");
    report_ok(&f.coordinator(&addr, "build-v1"));
    assert!(Path::new(&f.ledger()).exists());
    let elf = fs::read(&f.elf)?;
    let executable = fs::read(env!("CARGO_BIN_EXE_angryier-campaign"))?;
    use sha2::Digest as _;
    let mut profile = b"native-xed-v1/executable-sha256:".to_vec();
    profile.extend_from_slice(&sha2::Sha256::digest(executable));
    let runtime = angryier_runtime::Runtime::with_native_xed(
        angryier_types::SemanticVersion(1),
        angryier_types::TargetProfileId(1),
    );
    let entry = runtime.load_elf(&elf)?.pc()?;
    let config = angryier_campaign::Config::defaults(f.elf.clone(), f.key.clone(), "build-v1".into());
    let manifest = angryier_campaign::manifest(&config, &elf, entry, &profile)?;
    let ledger = angryier_ledger::sustained::SustainedLedger::open(f.ledger(), manifest)?;
    let (_, evidence) = ledger.read_snapshot();
    assert_eq!(
        evidence.iter().filter(|e| e.delta.path.witness.is_some()).count(),
        2,
        "worker and coordinator must retain two independently verified child witnesses"
    );
    Ok(())
}
#[test]
fn separate_process_pool_has_equal_unique_paths_and_verified_witnesses() -> Result<(), Box<dyn std::error::Error>> {
    let mut baseline = None;
    for count in [1, 2, 4] {
        let f = Fixture::new();
        let mut processes = Vec::new();
        let mut peers = Vec::new();
        for index in 0..count {
            let (worker, addr, key) = f.keyed_worker(index, 8);
            processes.push(worker);
            peers.push((format!("worker-{index}"), addr, key));
        }
        report_ok(&f.pool(&peers));
        let elf = fs::read(&f.elf)?;
        use sha2::Digest as _;
        let mut profile = b"native-xed-v1/executable-sha256:".to_vec();
        profile.extend_from_slice(&sha2::Sha256::digest(fs::read(env!(
            "CARGO_BIN_EXE_angryier-campaign"
        ))?));
        let runtime = angryier_runtime::Runtime::with_native_xed(
            angryier_types::SemanticVersion(1),
            angryier_types::TargetProfileId(1),
        );
        let entry = runtime.load_elf(&elf)?.pc()?;
        let config = angryier_campaign::Config::defaults(f.elf.clone(), f.key.clone(), "build-v1".into());
        let manifest = angryier_campaign::manifest(&config, &elf, entry, &profile)?;
        let ledger = angryier_ledger::sustained::SustainedLedger::open(f.ledger(), manifest)?;
        let (_, events) = ledger.read_snapshot();
        assert!(ledger.report().complete_within_declared_bounds);
        let mut paths: Vec<_> = events.iter().map(|event| event.delta.path.clone()).collect();
        paths.sort_by_key(|path| path.path_id);
        paths.dedup_by_key(|path| path.path_id);
        assert_eq!(paths.len(), events.len(), "duplicate accepted path identity");
        assert_eq!(paths.iter().filter(|path| path.witness.is_some()).count(), 2);
        if let Some(expected) = &baseline {
            assert_eq!(&paths, expected, "{count} workers changed verified paths");
        } else {
            baseline = Some(paths);
        }
        drop(processes);
    }
    Ok(())
}

#[test]
fn pool_rejects_duplicate_key_and_wrong_authentication() {
    let f = Fixture::new();
    let (_first, first_addr, first_key) = f.keyed_worker(0, 8);
    let (_second, second_addr, second_key) = f.keyed_worker(1, 8);
    let mut peers = vec![
        ("worker-0".into(), first_addr, first_key),
        ("worker-1".into(), second_addr, second_key),
    ];
    peers[1].2 = peers[0].2.clone();
    let rejected = f.pool(&peers);
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("distinct pairwise keys"));
    peers[1].2 = f.dir.join("wrong.key");
    fs::write(&peers[1].2, [0x7bu8; 32]).expect("wrong key");
    fs::set_permissions(&peers[1].2, fs::Permissions::from_mode(0o600)).expect("permissions");
    let rejected = f.pool(&peers);
    assert!(!rejected.status.success(), "wrong peer authentication passed");
    assert!(!String::from_utf8_lossy(&rejected.stdout).contains("complete_within_declared_bounds: true"));
    let recovered = f.pool(&[
        ("worker-0".into(), peers[0].1.clone(), peers[0].2.clone()),
        ("worker-1".into(), peers[1].1.clone(), f.dir.join("worker-1.key")),
    ]);
    report_ok(&recovered);
}

#[test]
fn disconnected_grant_is_requeued_and_new_process_reconnects() {
    let f = Fixture::new();
    let (first, addr) = f.worker(1);
    let interrupted = f.coordinator(&addr, "build-v1");
    assert!(!interrupted.status.success(), "worker should exit after first grant");
    drop(first);
    let (second, addr) = f.worker(8);
    report_ok(&f.coordinator(&addr, "build-v1"));
    drop(second);
}

#[test]
fn authenticated_drip_outcome_expires_and_requeues_grant() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_distribution::transport::{Message, TcpServer, Transport};
    use angryier_runtime::Runtime;
    use angryier_types::{SemanticVersion, TargetProfileId};
    use sha2::Digest as _;

    let f = Fixture::new();
    let elf = fs::read(&f.elf)?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let root = runtime.load_elf(&elf)?;
    let entry = root.pc()?;
    let mut config = angryier_campaign::Config::defaults(f.elf.clone(), f.key.clone(), "build-v1".into());
    config.limits.max_wall_millis = 400;
    let mut profile = b"native-xed-v1/executable-sha256:".to_vec();
    profile.extend_from_slice(&sha2::Sha256::digest(fs::read(std::env::current_exe()?)?));
    let manifest = angryier_campaign::manifest(&config, &elf, entry, &profile)?;

    let worker_listener = TcpServer::bind("127.0.0.1:0")?;
    let worker_addr = worker_listener.local_addr()?;
    let worker_manifest = manifest.clone();
    let (grant_tx, grant_rx) = std::sync::mpsc::channel();
    let worker = thread::spawn(move || {
        let transport = Transport::new(
            worker_manifest,
            1,
            "worker".into(),
            std::collections::HashMap::from([("coordinator".into(), [0x4b; 32])]),
        )
        .expect("construct worker transport");
        let mut session = worker_listener
            .accept(transport, "coordinator")
            .expect("accept coordinator session");
        let message = session.receive().expect("receive worker grant").message;
        assert!(matches!(message, Message::Grant { .. }), "expected grant");
        let Message::Grant { work, .. } = message else {
            return;
        };
        grant_tx.send(Instant::now()).expect("send grant timestamp");
        session
            .send(&Message::Outcome {
                work,
                payload: vec![0; 4096],
            })
            .expect("send worker outcome");
    });
    let proxy_listener = TcpListener::bind("127.0.0.1:0")?;
    let proxy_addr = proxy_listener.local_addr()?;
    let proxy = thread::spawn(move || {
        let (mut coordinator, _) = proxy_listener.accept().expect("accept coordinator");
        let mut from_worker = TcpStream::connect(worker_addr).expect("connect worker");
        let mut to_worker = from_worker.try_clone().expect("clone worker stream");
        let mut coordinator_to_worker = coordinator.try_clone().expect("clone coordinator stream");
        let relay = thread::spawn(move || {
            let _ = io::copy(&mut coordinator_to_worker, &mut to_worker);
        });
        // Forward both handshake halves intact, then drip the authenticated outcome frame.
        for _ in 0..2 {
            let mut half = [0; 32];
            from_worker.read_exact(&mut half).expect("read worker handshake half");
            coordinator.write_all(&half).expect("forward worker handshake half");
        }
        let mut header = [0; 4];
        from_worker.read_exact(&mut header).expect("read worker frame header");
        coordinator.write_all(&header).expect("forward worker frame header");
        let mut frame = vec![0; u32::from_be_bytes(header) as usize];
        from_worker.read_exact(&mut frame).expect("read worker frame");
        for chunk in frame.chunks(4) {
            if coordinator.write_all(chunk).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        relay.join().expect("join relay thread");
    });
    let result = angryier_campaign::coordinate(&config, proxy_addr, f.ledger());
    let finished = Instant::now();
    assert!(result.is_err(), "partial outcome must not commit");
    let grant_time = grant_rx.recv_timeout(Duration::from_secs(2))?;
    assert!(
        finished.duration_since(grant_time) < Duration::from_secs(2),
        "coordinator joined past grant deadline: {:?}, result={result:?}",
        finished.duration_since(grant_time)
    );
    proxy.join().expect("join proxy thread");
    worker.join().expect("join worker thread");
    let ledger = angryier_ledger::sustained::SustainedLedger::open(f.ledger(), manifest)?;
    assert_eq!(ledger.report().queued, 1, "expired grant was not revoked");
    assert_eq!(ledger.read_snapshot().1.len(), 0, "expired evidence was accepted");
    Ok(())
}

#[test]
fn revoked_generation_cannot_commit_old_worker_result() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_arch_intel64::register_id;
    use angryier_distribution::contracts::{CampaignArtifacts, Digest};
    use angryier_expr::{ExprReader, ShardedExprArena};
    use angryier_ir::IrType;
    use angryier_runtime::{Runtime, SymbolicSession, sustained::SustainedCampaign, sustained_pool::AdvanceOutcome};
    use angryier_solver_z3::Z3Backend;
    use angryier_types::{ExpressionNormalizationVersion, SemanticVersion, TargetProfileId};
    use std::{sync::Arc, time::Duration};

    let fixture = Fixture::new();
    let elf = fs::read(&fixture.elf)?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let entry = runtime.load_elf(&elf)?.pc()?;
    let config = angryier_campaign::Config::defaults(fixture.elf.clone(), fixture.key.clone(), "build-v1".into());
    let profile = b"test-native-profile";
    let manifest = angryier_campaign::manifest(&config, &elf, entry, profile)?;
    let artifacts = CampaignArtifacts {
        binary: &elf,
        semantic_profile: profile,
        script: b"no-script",
        policy: &config.policy(entry),
        solver_policy: b"z3-native-v1",
        inputs: vec![],
        stubs: vec![],
    };
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), runtime.load_elf(&elf)?);
    session.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let initial = session.sustained_initial_digest()?;
    let mut campaign = SustainedCampaign::open(fixture.ledger(), manifest.clone(), &artifacts, initial)?;
    let old = campaign.reserve_remote(Digest::of(b"worker"))?.expect("root grant");
    let mut solver = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
    let outcome = session.advance_sustained(&old, &manifest, &mut solver, Duration::from_secs(10), 64)?;
    let result = AdvanceOutcome::decode_wire(old.reservation.unit.clone(), &outcome.encode_wire()?, &manifest)?;
    let mut verifier = SymbolicSession::new(&runtime, arena.as_ref(), runtime.load_elf(&elf)?);
    verifier.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let mut independent_solver = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
    let verified = campaign.verify_remote(
        &old,
        &result,
        &mut verifier,
        &mut independent_solver,
        Duration::from_secs(10),
        64,
    )?;
    campaign.revoke_remote(&old)?;
    assert!(
        campaign.commit_remote(&old, verified, 64).is_err(),
        "stale attempt accepted"
    );
    assert_eq!(campaign.report().queued, 1);
    let current = campaign.reserve_remote(Digest::of(b"worker"))?.expect("requeued grant");
    assert_ne!(current.ownership_epoch, old.ownership_epoch);
    campaign.revoke_remote(&current)?;
    Ok(())
}

#[test]
fn forged_root_child_and_solver_cannot_close_scope() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_arch_intel64::register_id;
    use angryier_distribution::contracts::{CampaignArtifacts, Digest};
    use angryier_expr::{ExprReader, ShardedExprArena};
    use angryier_ir::IrType;
    use angryier_runtime::{Runtime, SymbolicSession, sustained::SustainedCampaign, sustained_pool::AdvanceOutcome};
    use angryier_solver_z3::Z3Backend;
    use angryier_types::{ExpressionNormalizationVersion, SemanticVersion, TargetProfileId};
    use std::{sync::Arc, time::Duration};
    let f = Fixture::new();
    let elf = fs::read(&f.elf)?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let entry = runtime.load_elf(&elf)?.pc()?;
    let config = angryier_campaign::Config::defaults(f.elf.clone(), f.key.clone(), "build-v1".into());
    let profile = b"test-native-profile";
    let manifest = angryier_campaign::manifest(&config, &elf, entry, profile)?;
    let artifacts = CampaignArtifacts {
        binary: &elf,
        semantic_profile: profile,
        script: b"no-script",
        policy: &config.policy(entry),
        solver_policy: b"z3-native-v1",
        inputs: vec![],
        stubs: vec![],
    };
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut worker = SymbolicSession::new(&runtime, arena.as_ref(), runtime.load_elf(&elf)?);
    worker.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let mut campaign = SustainedCampaign::open(
        f.ledger(),
        manifest.clone(),
        &artifacts,
        worker.sustained_initial_digest()?,
    )?;
    let check = |campaign: &SustainedCampaign,
                 grant: &angryier_ledger::sustained::FencedReservation,
                 claimed: &AdvanceOutcome|
     -> bool {
        let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
        let mut session = SymbolicSession::new(&runtime, arena.as_ref(), runtime.load_elf(&elf).expect("ELF"));
        session
            .mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))
            .expect("RBX");
        let mut solver = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>).expect("Z3");
        campaign
            .verify_remote(grant, claimed, &mut session, &mut solver, Duration::from_secs(10), 64)
            .is_ok()
    };
    let root = campaign.reserve_remote(Digest::of(b"worker"))?.expect("root");
    let mut solver = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
    let root_bytes = worker
        .advance_sustained(&root, &manifest, &mut solver, Duration::from_secs(10), 64)?
        .encode_wire()?;
    let mut forged = root_bytes[..81].to_vec(); // authenticated fence, forged empty completed terminal
    forged.extend_from_slice(&1u64.to_le_bytes());
    forged.extend_from_slice(&[0, 4, 0]);
    forged.extend_from_slice(b"fake");
    forged.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    forged.extend_from_slice(&0u32.to_le_bytes()); // v2 semantic-debt count
    let claimed = AdvanceOutcome::decode_wire(root.reservation.unit.clone(), &forged, &manifest)
        .map_err(|error| format!("forged root decode: {error}"))?;
    assert!(!check(&campaign, &root, &claimed), "empty forged root accepted");
    assert!(!campaign.report().complete_within_declared_bounds);
    let honest = AdvanceOutcome::decode_wire(root.reservation.unit.clone(), &root_bytes, &manifest)?;
    assert!(check(&campaign, &root, &honest));
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), runtime.load_elf(&elf)?);
    session.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let mut solver = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
    let verified = campaign
        .verify_remote(&root, &honest, &mut session, &mut solver, Duration::from_secs(10), 64)
        .map_err(|error| format!("honest root verification: {error}"))?;
    campaign.commit_remote(&root, verified, 64)?;
    let child = campaign.reserve_remote(Digest::of(b"worker"))?.expect("child");
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), runtime.load_elf(&elf)?);
    session.mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))?;
    let mut solver = Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>)?;
    let bytes = session
        .advance_sustained(&child, &manifest, &mut solver, Duration::from_secs(10), 64)?
        .encode_wire()?;
    let trace_at = 90 + 2 + u16::from_le_bytes(bytes[90..92].try_into()?) as usize + 1 + 4;
    let mut forged = bytes.clone();
    forged[trace_at..trace_at + 8].copy_from_slice(&0xdead_beefu64.to_le_bytes());
    let claimed = AdvanceOutcome::decode_wire(child.reservation.unit.clone(), &forged, &manifest)
        .map_err(|error| format!("forged child decode: {error}"))?;
    assert!(!check(&campaign, &child, &claimed), "forged child trace accepted");
    let trace_count = u32::from_le_bytes(bytes[trace_at - 4..trace_at].try_into()?) as usize;
    let query_at = trace_at + trace_count * 8 + 4 + 8 + 8 + 32;
    let mut forged = bytes.clone();
    forged[query_at] ^= 0x80;
    let claimed = AdvanceOutcome::decode_wire(child.reservation.unit.clone(), &forged, &manifest)
        .map_err(|error| format!("forged child decode: {error}"))?;
    assert!(!check(&campaign, &child, &claimed), "forged SAT query accepted");
    campaign.revoke_remote(&child)?;
    assert!(!campaign.report().complete_within_declared_bounds);
    Ok(())
}

#[test]
fn real_process_progress_mirrors_accepted_ledger_and_stdout() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new();
    let (_worker, addr) = f.worker(8);
    let output = f.coordinator(&addr, "build-v1");
    report_ok(&output);
    assert!(progress_path(&f).is_file(), "default progress path must exist");
    let rows = assert_progress_matches_ledger(&f)?;
    assert!(!rows.is_empty(), "tiny ELF must produce accepted events");
    assert_eq!(
        accepted_rows(&output.stdout),
        rows,
        "only durably mirrored accepted rows may reach stdout"
    );
    Ok(())
}

#[test]
fn real_process_progress_repairs_corruption_and_truncation_after_restart() -> Result<(), Box<dyn std::error::Error>> {
    let f = Fixture::new();
    let (_worker, addr) = f.worker(16);
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_angryier-campaign"));
    cmd.arg("coordinator");
    f.common(&mut cmd, "build-v1");
    cmd.args(["--connect", &addr, "--ledger"]).arg(f.ledger());
    let mut child = Worker(cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?);
    let stdout = child.0.stdout.take().expect("coordinator stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    loop {
        line.clear();
        assert_ne!(
            reader.read_line(&mut line)?,
            0,
            "coordinator exited before an accepted event"
        );
        if let Some(row) = line.strip_prefix("accepted ") {
            let mirror = fs::read_to_string(progress_path(&f))?;
            assert!(
                mirror.lines().any(|stored| stored == row.trim_end()),
                "ACCEPTED printed before the durable progress row"
            );
            break;
        }
    }
    // Signal this exact child only after its flushed ACCEPTED marker, without a timer or polling loop.
    if child.0.try_wait()?.is_none() {
        child.0.kill()?;
    }
    child.0.wait()?;
    drop(reader);
    let before = assert_progress_matches_ledger(&f)?;
    assert!(!before.is_empty());
    let path = progress_path(&f);
    fs::write(&path, format!("{}\n{{\"event_id\":\"cut", before[0]))?;
    let resumed = f.coordinator(&addr, "build-v1");
    report_ok(&resumed);
    assert!(String::from_utf8_lossy(&resumed.stdout).contains("(recovered/rebuilt)"));
    let repaired = assert_progress_matches_ledger(&f)?;
    assert!(repaired.starts_with(&before), "restart dropped accepted ledger history");
    assert_eq!(
        accepted_rows(&resumed.stdout),
        repaired[before.len()..],
        "replayed history must not be emitted as newly accepted"
    );

    fs::write(&path, format!("{}\n", repaired[0]))?;
    let resumed = f.coordinator(&addr, "build-v1");
    report_ok(&resumed);
    assert!(String::from_utf8_lossy(&resumed.stdout).contains("(recovered/rebuilt)"));
    assert!(
        accepted_rows(&resumed.stdout).is_empty(),
        "completed replay emitted duplicate accepted events"
    );
    assert_eq!(
        assert_progress_matches_ledger(&f)?,
        repaired,
        "truncated journal not restored from ledger"
    );
    Ok(())
}

#[test]
fn committed_grant_survives_projection_failure_and_sibling_is_revoked() -> Result<(), Box<dyn std::error::Error>> {
    use angryier_arch_intel64::register_id;
    use angryier_distribution::contracts::WorkUnit;
    use angryier_distribution::transport::{Message, TcpServer, Transport};
    use angryier_expr::{ExprReader, ShardedExprArena};
    use angryier_ir::IrType;
    use angryier_ledger::sustained::{Status, SustainedLedger};
    use angryier_runtime::{Runtime, SymbolicSession, sustained_pool::WireGrant};
    use angryier_solver_z3::Z3Backend;
    use angryier_types::{ExpressionNormalizationVersion, SemanticVersion, TargetProfileId};
    use sha2::Digest as _;
    use std::sync::{Arc, mpsc};

    enum Event {
        Line(String),
        ErrLine(String),
        GrantedA(WorkUnit),
        ServedB(WorkUnit),
    }

    let f = Fixture::new();
    // Test-side manifest identical to the one the spawned coordinator computes
    // from its default config (same binary, build id, profile and limits).
    let elf = fs::read(&f.elf)?;
    let mut profile = b"native-xed-v1/executable-sha256:".to_vec();
    profile.extend_from_slice(&sha2::Sha256::digest(fs::read(env!(
        "CARGO_BIN_EXE_angryier-campaign"
    ))?));
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let entry = runtime.load_elf(&elf)?.pc()?;
    let config = angryier_campaign::Config::defaults(f.elf.clone(), f.key.clone(), "build-v1".into());
    let manifest = angryier_campaign::manifest(&config, &elf, entry, &profile)?;

    let key_a = f.dir.join("worker-A.key");
    fs::write(&key_a, [0x01u8; 32])?;
    fs::set_permissions(&key_a, fs::Permissions::from_mode(0o600))?;
    let key_b = f.dir.join("worker-B.key");
    fs::write(&key_b, [0x02u8; 32])?;
    fs::set_permissions(&key_b, fs::Permissions::from_mode(0o600))?;
    let listener_a = TcpServer::bind("127.0.0.1:0")?;
    let addr_a = listener_a.local_addr()?;
    let listener_b = TcpServer::bind("127.0.0.1:0")?;
    let addr_b = listener_b.local_addr()?;

    let (event_tx, event_rx) = mpsc::channel::<Event>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    // Worker A honestly serves the root grant, then holds the round-2 child
    // outcome until the test has sabotaged the progress projection, so the
    // coordinator's commit lands but its journal append fails.
    let worker_a = {
        let manifest = manifest.clone();
        let elf = elf.clone();
        let event_tx = event_tx.clone();
        thread::spawn(move || -> Result<(), String> {
            for connection in 0..2u32 {
                let transport = Transport::new(
                    manifest.clone(),
                    1,
                    "worker-A".into(),
                    std::collections::HashMap::from([("coordinator".into(), [0x01; 32])]),
                )
                .map_err(|error| error.to_string())?;
                let mut conn = listener_a
                    .accept(transport, "coordinator")
                    .map_err(|error| error.to_string())?;
                let (work, grant) = match conn.receive().map_err(|error| error.to_string())?.message {
                    Message::Grant { work, payload } => {
                        let grant =
                            WireGrant::decode(work.clone(), &payload, &manifest).map_err(|error| error.to_string())?;
                        (work, grant)
                    }
                    other => return Err(format!("expected grant, got {other:?}")),
                };
                if connection == 1 {
                    event_tx
                        .send(Event::GrantedA(grant.fence.reservation.unit.clone()))
                        .map_err(|_| "event channel closed")?;
                    let _ = release_rx.recv_timeout(Duration::from_secs(240));
                }
                let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
                let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
                let mut session = SymbolicSession::new(
                    &runtime,
                    arena.as_ref(),
                    runtime.load_elf(&elf).map_err(|error| error.to_string())?,
                );
                session
                    .mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))
                    .map_err(|error| error.to_string())?;
                let mut solver =
                    Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>).map_err(|error| error.to_string())?;
                let outcome = session
                    .advance_sustained(&grant.fence, &manifest, &mut solver, grant.timeout, grant.step_budget)
                    .map_err(|error| error.to_string())?;
                conn.send(&Message::Outcome {
                    work,
                    payload: outcome.encode_wire().map_err(|error| error.to_string())?,
                })
                .map_err(|error| error.to_string())?;
            }
            Ok(())
        })
    };
    // Worker B serves its child grant immediately and reports the unit so the
    // test can assert cleanup revoked exactly that sibling grant.
    let worker_b = {
        let manifest = manifest.clone();
        let elf = elf.clone();
        let event_tx = event_tx.clone();
        thread::spawn(move || -> Result<(), String> {
            let transport = Transport::new(
                manifest.clone(),
                1,
                "worker-B".into(),
                std::collections::HashMap::from([("coordinator".into(), [0x02; 32])]),
            )
            .map_err(|error| error.to_string())?;
            let mut conn = listener_b
                .accept(transport, "coordinator")
                .map_err(|error| error.to_string())?;
            let (work, grant) = match conn.receive().map_err(|error| error.to_string())?.message {
                Message::Grant { work, payload } => {
                    let grant =
                        WireGrant::decode(work.clone(), &payload, &manifest).map_err(|error| error.to_string())?;
                    (work, grant)
                }
                other => return Err(format!("expected grant, got {other:?}")),
            };
            let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
            let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
            let mut session = SymbolicSession::new(
                &runtime,
                arena.as_ref(),
                runtime.load_elf(&elf).map_err(|error| error.to_string())?,
            );
            session
                .mark_symbolic(0, register_id::GPR_BASE + 3, IrType::Bits(64))
                .map_err(|error| error.to_string())?;
            let mut solver =
                Z3Backend::native_ffi(arena.clone() as Arc<dyn ExprReader>).map_err(|error| error.to_string())?;
            let outcome = session
                .advance_sustained(&grant.fence, &manifest, &mut solver, grant.timeout, grant.step_budget)
                .map_err(|error| error.to_string())?;
            conn.send(&Message::Outcome {
                work,
                payload: outcome.encode_wire().map_err(|error| error.to_string())?,
            })
            .map_err(|error| error.to_string())?;
            event_tx
                .send(Event::ServedB(grant.fence.reservation.unit.clone()))
                .map_err(|_| "event channel closed")?;
            Ok(())
        })
    };

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_angryier-campaign"));
    cmd.args(["coordinator", "--binary"])
        .arg(&f.elf)
        .args(["--build-id", "build-v1", "--ledger"])
        .arg(f.ledger())
        .args(["--peer", &format!("worker-A@{addr_a}@{}", key_a.display())])
        .args(["--peer", &format!("worker-B@{addr_b}@{}", key_b.display())]);
    let mut child = Worker(cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?);
    let stdout = child.0.stdout.take().expect("coordinator stdout");
    let line_tx = event_tx.clone();
    let reader = thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            if line_tx.send(Event::Line(line)).is_err() {
                break;
            }
        }
    });
    let stderr = child.0.stderr.take().expect("coordinator stderr");
    let err_tx = event_tx.clone();
    let err_reader = thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { break };
            if err_tx.send(Event::ErrLine(line)).is_err() {
                break;
            }
        }
    });

    let started = Instant::now();
    let (mut committed_unit, mut other_unit) = (None, None);
    let mut accepted = Vec::new();
    let mut late = Vec::new();
    let mut stderr_lines = Vec::new();
    let mut stdout_lines = Vec::new();
    let mut journal_rows = None;
    let deadline = Duration::from_secs(300);
    loop {
        let remaining = deadline.saturating_sub(started.elapsed());
        match event_rx.recv_timeout(remaining.min(Duration::from_secs(10))) {
            Ok(Event::Line(line)) => {
                stdout_lines.push(line.clone());
                if let Some(row) = line.strip_prefix("accepted ") {
                    let row = row.trim_end().to_owned();
                    if committed_unit.is_none() {
                        accepted.push(row);
                    } else {
                        late.push(row);
                    }
                }
            }
            Ok(Event::GrantedA(unit)) => {
                assert!(committed_unit.is_none(), "blocking worker granted more than once");
                committed_unit = Some(unit);
                // Round 2 cannot start until round 1 is fully projected, so the
                // journal now holds exactly the root rows already printed.
                let text = fs::read_to_string(progress_path(&f))?;
                assert!(text.ends_with('\n'), "root projection must be complete JSONL rows");
                let rows: Vec<String> = text.lines().map(str::to_owned).collect();
                assert!(!rows.is_empty(), "root commit must project accepted events");
                journal_rows = Some(rows);
                // Sabotage the projection path: the open append descriptor is
                // retained, but the named path is no longer a regular file.
                fs::remove_file(progress_path(&f))?;
                fs::create_dir(progress_path(&f))?;
                release_tx.send(()).expect("worker A released");
            }
            Ok(Event::ServedB(unit)) => {
                assert!(other_unit.is_none(), "sibling worker reported twice");
                other_unit = Some(unit);
            }
            Ok(Event::ErrLine(line)) => stderr_lines.push(line),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if child.0.try_wait()?.is_some() {
                    break;
                }
                if started.elapsed() >= deadline {
                    assert!(
                        started.elapsed() < deadline,
                        "coordinator or scripted workers stalled past {}s; coordinator stdout: {}; coordinator stderr: {}",
                        deadline.as_secs(),
                        stdout_lines.join("\n"),
                        stderr_lines.join("\n")
                    );
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let status = child.0.wait()?;
    let stderr = stderr_lines.join("\n");
    assert!(
        committed_unit.is_some() && other_unit.is_some(),
        "coordinator exited before both scripted grants completed: {stderr}"
    );
    worker_a.join().map_err(|_| "scripted worker A panicked")??;
    worker_b.join().map_err(|_| "scripted worker B panicked")??;
    reader.join().map_err(|_| "stdout reader panicked")?;
    err_reader.join().map_err(|_| "stderr reader panicked")?;

    assert!(
        !status.success(),
        "coordinator must fail closed when the projection append fails"
    );
    assert!(
        stderr.contains("progress path changed or is not a regular file"),
        "original projection error must survive cleanup, not be masked by a stale revocation: {stderr}"
    );
    let mut stdout_rows = accepted;
    stdout_rows.extend(late);
    stdout_rows.sort();
    let mut projected = journal_rows.expect("root projection snapshot");
    projected.sort();
    assert_eq!(
        stdout_rows, projected,
        "only durably projected rows may reach stdout after the failed commit"
    );

    // The committed child grant must stay accepted (never revoked back to
    // queued) while the still-active sibling must be revoked by cleanup.
    {
        let ledger = SustainedLedger::open(f.ledger(), manifest.clone())?;
        let (records, evidence) = ledger.read_snapshot();
        let committed_unit = committed_unit.expect("committed child unit");
        let other_unit = other_unit.expect("revoked sibling unit");
        let committed = records
            .iter()
            .find(|record| record.unit == committed_unit)
            .expect("committed child record");
        assert_eq!(
            committed.status,
            Status::Completed,
            "committed grant must not be revoked: {committed:?}"
        );
        let sibling = records
            .iter()
            .find(|record| record.unit == other_unit)
            .expect("sibling child record");
        assert_eq!(
            sibling.status,
            Status::Queued,
            "pending sibling grant must be revoked by cleanup: {sibling:?}"
        );
        let report = ledger.report();
        assert_eq!(report.active, 0, "cleanup must not leak active grants");
        assert_eq!(report.queued, 1, "only the revoked sibling may be requeued");
        assert!(
            evidence.len() > projected.len(),
            "committed events beyond the failed projection must not be reported as accepted"
        );
    }

    // Recovery semantics: remove the sabotage marker; the next run rebuilds the
    // projection from the authoritative ledger and completes the campaign.
    // The assertion ledger above must be dropped first: its stable lock would
    // otherwise reject the recovering coordinator.
    fs::remove_dir(progress_path(&f))?;
    let (_worker, addr) = f.worker(8);
    let resumed = f.coordinator(&addr, "build-v1");
    report_ok(&resumed);
    assert!(String::from_utf8_lossy(&resumed.stdout).contains("(recovered/rebuilt)"));
    assert!(
        !assert_progress_matches_ledger(&f)?.is_empty(),
        "rebuilt projection must mirror the ledger"
    );
    Ok(())
}
