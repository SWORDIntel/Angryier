#![cfg(all(target_arch = "x86_64", unix))]
use angryier_ledger::{
    evidence::{PathDisposition, ReplayVerification},
    sustained::SustainedLedger,
};
use angryier_runtime::Runtime;
use angryier_types::{SemanticVersion, TargetProfileId};
use sha2::{Digest as _, Sha256};
use std::{
    fs,
    io::{BufRead, BufReader, Read},
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Child, Command, Output, Stdio},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

static NEXT: AtomicU64 = AtomicU64::new(0);
const IMAGE_BASE: u64 = 0x1_4000_0000;
const ENTRY: u64 = IMAGE_BASE + 0x1020;
const ENTRY_ARG: &str = "0x140001020";

fn pe_image() -> Vec<u8> {
    let mut pe = vec![0u8; 0x400];
    pe[..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    pe[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    pe[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    pe[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
    pe[0x96..0x98].copy_from_slice(&0x2022u16.to_le_bytes());
    pe[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
    pe[0x9c..0xa0].copy_from_slice(&0x200u32.to_le_bytes());
    pe[0xa8..0xac].copy_from_slice(&0x1000u32.to_le_bytes());
    pe[0xac..0xb0].copy_from_slice(&0x1000u32.to_le_bytes());
    pe[0xb0..0xb8].copy_from_slice(&IMAGE_BASE.to_le_bytes());
    pe[0xb8..0xbc].copy_from_slice(&0x1000u32.to_le_bytes());
    pe[0xbc..0xc0].copy_from_slice(&0x200u32.to_le_bytes());
    pe[0xd0..0xd4].copy_from_slice(&0x2000u32.to_le_bytes());
    pe[0xd4..0xd8].copy_from_slice(&0x200u32.to_le_bytes());
    pe[0xdc..0xde].copy_from_slice(&1u16.to_le_bytes()); // IMAGE_SUBSYSTEM_NATIVE
    pe[0x104..0x108].copy_from_slice(&16u32.to_le_bytes());
    pe[0x188..0x190].copy_from_slice(b".text\0\0\0");
    pe[0x190..0x194].copy_from_slice(&0x200u32.to_le_bytes());
    pe[0x194..0x198].copy_from_slice(&0x1000u32.to_le_bytes());
    pe[0x198..0x19c].copy_from_slice(&0x200u32.to_le_bytes());
    pe[0x19c..0x1a0].copy_from_slice(&0x200u32.to_le_bytes());
    pe[0x1ac..0x1b0].copy_from_slice(&0x6000_0020u32.to_le_bytes());
    // The header entry must not run: only the explicit --entry reaches the branch.
    pe[0x200..0x202].copy_from_slice(&[0x0f, 0x0b]); // ud2
    pe[0x220..0x22f].copy_from_slice(&[
        0x48, 0x83, 0xf9, 0x05, // cmp rcx, 5
        0x74, 0x06, // je equal
        0xbf, 0x01, 0x00, 0x00, 0x00, // mov edi, 1
        0xc3, // ret into load_pe_driver's synthetic exit sentinel
        0x31, 0xff, // equal: xor edi, edi
        0xc3, // ret into the same sentinel
    ]);
    pe
}

struct Fixture {
    dir: PathBuf,
    image: PathBuf,
    key: PathBuf,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let dir = std::env::temp_dir().join(format!(
            "angryier-pe-replay-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&dir)?;
        let image = dir.join("branch.sys");
        fs::write(&image, pe_image())?;
        let key = dir.join("pairwise.key");
        fs::write(&key, [0x6bu8; 32])?;
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600))?;
        Ok(Self { dir, image, key })
    }

    fn ledger(&self) -> PathBuf {
        self.dir.join("campaign.ledger")
    }

    fn command(&self, role: &str, mode: &str, entry: &str, register: &str) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_angryier-campaign"));
        cmd.arg(role)
            .arg("--binary")
            .arg(&self.image)
            .arg("--key-file")
            .arg(&self.key)
            .args([
                "--build-id",
                "pe-test-v1",
                "--image-mode",
                mode,
                "--entry",
                entry,
                "--symbolic-reg",
                register,
            ]);
        cmd
    }

    fn worker(&self) -> Result<(Running, String), Box<dyn std::error::Error>> {
        let mut cmd = self.command("worker", "pe-driver", ENTRY_ARG, "rcx");
        let mut worker = Running(
            cmd.args(["--listen", "127.0.0.1:0", "--connections", "8"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?,
        );
        let stdout = worker
            .0
            .stdout
            .take()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "worker stdout was not piped"))?;
        let (sender, receiver) = mpsc::channel();
        let reader = thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
            let _ = sender.send(result);
        });
        let line = receiver.recv_timeout(Duration::from_secs(20))??;
        reader
            .join()
            .map_err(|_| std::io::Error::other("worker readiness reader panicked"))?;
        if !line.starts_with("READY 127.0.0.1:") {
            let _ = worker.0.kill();
            let _ = worker.0.wait();
            let mut stderr = String::new();
            if let Some(mut stream) = worker.0.stderr.take() {
                stream.read_to_string(&mut stderr)?;
            }
            return Err(std::io::Error::other(format!("PE worker failed to start: {line:?}; {stderr}")).into());
        }
        Ok((worker, line.trim_start_matches("READY ").trim().into()))
    }

    fn coordinator(
        &self,
        addr: &str,
        mode: &str,
        entry: &str,
        register: &str,
    ) -> Result<Output, Box<dyn std::error::Error>> {
        let mut cmd = self.command("coordinator", mode, entry, register);
        cmd.args(["--connect", addr, "--ledger"]).arg(self.ledger());
        bounded_output(&mut cmd)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn bounded_output(cmd: &mut Command) -> Result<Output, Box<dyn std::error::Error>> {
    let mut process = Running(cmd.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn()?);
    let mut stdout = process
        .0
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "campaign stdout was not piped"))?;
    let mut stderr = process
        .0
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "campaign stderr was not piped"))?;
    let out = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).map(|_| bytes)
    });
    let err = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).map(|_| bytes)
    });
    // Debug builds hash the PE root and run real worker replay within this deadline.
    let timeout = Duration::from_secs(180);
    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = process.0.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = process.0.kill();
            let _ = process.0.wait();
            let stdout = out
                .join()
                .map_err(|_| std::io::Error::other("stdout reader panicked"))??;
            let stderr = err
                .join()
                .map_err(|_| std::io::Error::other("stderr reader panicked"))??;
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "campaign exceeded {timeout:?} deadline; stdout={} stderr={}",
                    String::from_utf8_lossy(&stdout),
                    String::from_utf8_lossy(&stderr)
                ),
            )
            .into());
        }
        thread::sleep(Duration::from_millis(20));
    };
    Ok(Output {
        status,
        stdout: out
            .join()
            .map_err(|_| std::io::Error::other("stdout reader panicked"))??,
        stderr: err
            .join()
            .map_err(|_| std::io::Error::other("stderr reader panicked"))??,
    })
}

fn report_ok(output: &Output) {
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report = String::from_utf8_lossy(&output.stdout);
    assert!(report.contains("complete_within_declared_bounds: true"), "{report}");
    assert!(
        report.contains("completed: 2"),
        "both PE return arms must complete: {report}"
    );
    assert!(report.contains("failed: 0"), "{report}");
}

fn executable_profile() -> Result<Vec<u8>, std::io::Error> {
    let mut executable = fs::File::open(env!("CARGO_BIN_EXE_angryier-campaign"))?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = executable.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    let mut profile = b"native-xed-v1/executable-sha256:".to_vec();
    profile.extend_from_slice(&hash.finalize());
    Ok(profile)
}

#[test]
fn pe_driver_return_sentinel_is_deterministic() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let image = pe_image();
    let mut digests = Vec::new();
    for rcx in [5, 6] {
        let mut root = runtime.load_pe_driver(&image)?;
        assert_eq!(root.pc()?, IMAGE_BASE + 0x1000);
        root.write_register(angryier_arch_intel64::register_id::RIP.0, ENTRY)?;
        let arena = angryier_expr::ShardedExprArena::new(angryier_types::ExpressionNormalizationVersion(1));
        let mut session = angryier_runtime::SymbolicSession::new(&runtime, &arena, root.clone());
        session.mark_symbolic(
            0,
            angryier_arch_intel64::register_id::GPR_BASE + 1,
            angryier_ir::IrType::Bits(64),
        )?;
        digests.push(session.sustained_initial_digest()?);
        root.write_register(angryier_arch_intel64::register_id::GPR_BASE + 1, rcx)?;
        runtime.run(&mut root, 16)?;
        assert!(
            root.terminated,
            "both return arms must reach the synthetic exit sentinel"
        );
    }
    assert_eq!(
        digests[0], digests[1],
        "independent PE loads must produce the same pinned root"
    );
    Ok(())
}

#[test]
fn pe_worker_replay_and_ledger_reopen_pin_image_entry_register_and_mode() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let (_worker, addr) = fixture.worker()?;
    report_ok(&fixture.coordinator(&addr, "pe-driver", ENTRY_ARG, "rcx")?);
    let accepted = fs::read(fixture.ledger())?;

    let original = fs::read(&fixture.image)?;
    let mut changed = original.clone();
    changed[0x223] = 6; // Still valid PE; only the branch's compared value changes.
    fs::write(&fixture.image, changed)?;
    let rejected = fixture.coordinator(&addr, "pe-driver", ENTRY_ARG, "rcx")?;
    assert!(!rejected.status.success(), "changed PE unexpectedly resumed");
    assert!(
        String::from_utf8_lossy(&rejected.stderr).contains("MismatchedCampaign"),
        "changed PE must fail ledger identity: {}",
        String::from_utf8_lossy(&rejected.stderr)
    );
    assert_eq!(fs::read(fixture.ledger())?, accepted, "rejection changed the ledger");
    fs::write(&fixture.image, original)?;

    for (label, mode, entry, register) in [
        ("entry", "pe-driver", "0x14000102c", "rcx"),
        ("register", "pe-driver", ENTRY_ARG, "rbx"),
        ("mode", "elf", ENTRY_ARG, "rcx"),
    ] {
        let rejected = fixture.coordinator(&addr, mode, entry, register)?;
        assert!(!rejected.status.success(), "changed {label} unexpectedly resumed");
        assert!(!String::from_utf8_lossy(&rejected.stdout).contains("complete_within_declared_bounds: true"));
        assert_eq!(fs::read(fixture.ledger())?, accepted, "changed {label} mutated ledger");
        if label != "mode" {
            assert!(
                String::from_utf8_lossy(&rejected.stderr).contains("MismatchedCampaign"),
                "changed {label} must fail ledger identity: {}",
                String::from_utf8_lossy(&rejected.stderr)
            );
        }
    }
    report_ok(&fixture.coordinator(&addr, "pe-driver", ENTRY_ARG, "rcx")?);

    let image = fs::read(&fixture.image)?;
    let mut config =
        angryier_campaign::Config::defaults(fixture.image.clone(), fixture.key.clone(), "pe-test-v1".into());
    config.image_mode = angryier_campaign::ImageMode::PeDriver;
    config.entry = Some(ENTRY);
    config.symbolic_reg = angryier_campaign::SymbolicRegister::Rcx;
    let profile = executable_profile()?;
    config.image_mode = angryier_campaign::ImageMode::Elf;
    let wrong_mode = angryier_campaign::manifest(&config, &image, ENTRY, &profile)?;
    assert!(
        matches!(
            SustainedLedger::open(fixture.ledger(), wrong_mode),
            Err(angryier_ledger::sustained::Error::MismatchedCampaign)
        ),
        "mode must be pinned by ledger identity, not just rejected by the image loader"
    );
    assert_eq!(fs::read(fixture.ledger())?, accepted);
    config.image_mode = angryier_campaign::ImageMode::PeDriver;
    let manifest = angryier_campaign::manifest(&config, &image, ENTRY, &profile)?;
    let ledger = SustainedLedger::open(fixture.ledger(), manifest)?;
    assert!(ledger.report().complete_within_declared_bounds);
    let (_, events) = ledger.read_snapshot();
    let terminal: Vec<_> = events
        .iter()
        .filter(|event| event.delta.path.disposition == PathDisposition::Terminal)
        .collect();
    assert_eq!(terminal.len(), 2, "both PE branch arms need accepted terminal evidence");
    let mut inputs = Vec::new();
    let mut successors = Vec::new();
    for event in terminal {
        let witness = event
            .delta
            .path
            .witness
            .as_ref()
            .ok_or_else(|| std::io::Error::other("PE terminal evidence is missing its concrete replay witness"))?;
        assert!(
            matches!(witness.replay, ReplayVerification::Verified { .. }),
            "PE terminal evidence must be independently replay-verified: {witness:?}"
        );
        assert!(witness.replay_input_provenance.is_some());
        assert_eq!(
            witness.replay_trace.first().map(|block| block.pc),
            Some(ENTRY),
            "replay evidence must begin at the explicit PE entry"
        );
        assert!(
            witness.replay_trace.iter().any(|block| block.pc == ENTRY + 6)
                || witness.replay_trace.iter().any(|block| block.pc == ENTRY + 12)
        );
        inputs.push(witness.input_digest);
        successors.push(witness.replay_trace.iter().any(|block| block.pc == ENTRY + 12));
    }
    assert_ne!(inputs[0], inputs[1], "two arms require different concrete RCX inputs");
    successors.sort();
    assert_eq!(successors, [false, true], "replay must observe each RCX branch arm");
    Ok(())
}

#[test]
fn unsupported_image_mode_is_rejected_before_work_or_ledger_creation() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    for role in ["worker", "coordinator"] {
        let mut cmd = fixture.command(role, "pe-user", ENTRY_ARG, "rcx");
        cmd.args(["--listen", "127.0.0.1:0", "--ledger"]).arg(fixture.ledger());
        let rejected = bounded_output(&mut cmd)?;
        assert!(!rejected.status.success(), "{role} accepted an unsupported image mode");
        let stderr = String::from_utf8_lossy(&rejected.stderr);
        assert!(
            stderr.contains("image mode") || stderr.contains("image-mode"),
            "{stderr}"
        );
        assert!(!String::from_utf8_lossy(&rejected.stdout).contains("READY "));
        assert!(!fixture.ledger().exists(), "unsupported mode created a ledger");
    }
    Ok(())
}
