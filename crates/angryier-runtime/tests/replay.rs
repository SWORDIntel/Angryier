//! Replay-capsule proof tests (roadmap item 9, Gate 0 remainder).
//!
//! A real, statically-linked ELF64 binary with a data-dependent branch is
//! assembled and linked at test time with the system binutils. Each test:
//!
//! 1. runs the binary NATIVELY for ground truth (exit code + stdout),
//! 2. records a replay capsule through the engine's recorder,
//! 3. drops all in-memory state and reloads the capsule from disk through
//!    `FileReplayStore`,
//! 4. replays it — the replayed outcome must match BOTH the capsule's
//!    checkpoints and the native ground truth.
//!
//! Fail-closed tampering checks prove that a wrong image hash, wrong
//! schema/semantic version, or drifted checkpoint rejects explicitly and
//! that validation runs before any re-execution.
//!
//! When the binutils toolchain is unavailable the tests report a skip.

#![cfg(feature = "xed")]

use std::path::{Path, PathBuf};
use std::process::Command;

use angryier_arch_intel64::register_id;
use angryier_replay::{FileReplayStore, ReplayError};
use angryier_runtime::Runtime;
use angryier_runtime::replay::{ReplayRecorder, ReplayRuntimeError};
use angryier_types::{ContentId, ReplaySchemaVersion, SemanticVersion, TargetProfileId};

/// A real Intel 64 program with a data-dependent branch: RAX = 42 falls
/// through to `ok_path` (writes "OK", exits 0); anything else takes the
/// branch to `fail_path` (writes "NO", exits 1). Both observable outcome
/// checkpoints — captured `write` output and exit code — are path-specific.
const FIXTURE_SOURCE: &str = r#"
    .global _start
    .global run
    .text
_start:
run:
    cmp $42, %rax
    jne fail_path
ok_path:
    mov $1, %rax
    mov $1, %rdi
    mov $ok_msg, %rsi
    mov $2, %rdx
    syscall
    mov $60, %rax
    xor %rdi, %rdi
ok_exit:
    syscall
fail_path:
    mov $1, %rax
    mov $1, %rdi
    mov $fail_msg, %rsi
    mov $2, %rdx
    syscall
    mov $60, %rax
    mov $1, %rdi
fail_exit:
    syscall
    .data
ok_msg:
    .ascii "OK"
fail_msg:
    .ascii "NO"
"#;

/// Assembled fixture object plus the linked executable bytes.
struct Fixture {
    object: PathBuf,
    elf: Vec<u8>,
}

/// Builds the fixture once and shares it across test threads.
fn fixture() -> Option<&'static Fixture> {
    static FIXTURE: std::sync::OnceLock<Option<Fixture>> = std::sync::OnceLock::new();
    FIXTURE.get_or_init(build_fixture).as_ref()
}

fn build_fixture() -> Option<Fixture> {
    let dir = temp_dir("angryier-replay-fixture")?;
    let source = dir.join("fixture.s");
    let object = dir.join("fixture.o");
    let binary = dir.join("fixture.elf");
    std::fs::write(&source, FIXTURE_SOURCE).ok()?;

    assemble(&source, &object)?;
    link(&binary, &[&object])?;
    let elf = std::fs::read(&binary).ok()?;
    Some(Fixture { object, elf })
}

/// Runs the fixture NATIVELY with RAX = `input`, returning the observed
/// ground truth (exit code, stdout). This is the `run_native` pattern
/// extended to capture the written output as well as the exit status.
fn run_native_observed(input: u64) -> Option<(i32, Vec<u8>)> {
    let fixture = fixture()?;
    let dir = temp_dir(&format!("angryier-replay-harness-{input}"))?;
    let source = dir.join("harness.s");
    let object = dir.join("harness.o");
    let binary = dir.join("harness.elf");
    let harness = format!(
        "    .global _start\n    .text\n_start:\n    mov ${input}, %rax\n    call run\n    mov $60, %rax\n    xor %rdi, %rdi\n    syscall\n"
    );
    std::fs::write(&source, harness).ok()?;

    assemble(&source, &object)?;
    link(&binary, &[&object, &fixture.object])?;
    let output = Command::new(&binary).output().ok()?;
    Some((output.status.code()?, output.stdout))
}

fn temp_dir(name: &str) -> Option<PathBuf> {
    let dir = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

fn assemble(source: &Path, object: &Path) -> Option<()> {
    let output = Command::new("as")
        .arg("--64")
        .arg("-o")
        .arg(object)
        .arg(source)
        .output()
        .ok()?;
    output.status.success().then_some(())
}

fn link(binary: &Path, objects: &[&PathBuf]) -> Option<()> {
    let mut command = Command::new("ld");
    command.arg("-o").arg(binary);
    for object in objects {
        command.arg(object);
    }
    command.output().ok()?.status.success().then_some(())
}

/// Assembles and links a one-off binary from `body`.
fn build_binary_from(body: &str) -> Option<Vec<u8>> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let suffix = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = temp_dir(&format!("angryier-replay-oneoff-{suffix}"))?;
    let source = dir.join("fixture.s");
    let object = dir.join("fixture.o");
    let binary = dir.join("fixture.elf");
    std::fs::write(&source, format!("    .global _start\n    .text\n{body}")).ok()?;
    assemble(&source, &object)?;
    link(&binary, &[&object])?;
    std::fs::read(&binary).ok()
}

/// Flagship proof: record → drop → reload from disk → replay must agree with
/// both the capsule's checkpoints and the native run, for both paths of a
/// data-dependent branch.
#[test]
fn native_agreement_record_then_disk_replay() -> Result<(), Box<dyn std::error::Error>> {
    let Some(fixture) = fixture() else {
        eprintln!("skipping: binutils (as/ld) unavailable");
        return Ok(());
    };

    // (input, expected exit code, expected stdout) — two inputs, two exits.
    let cases: [(u64, i32, &[u8]); 2] = [(6, 1, b"NO"), (42, 0, b"OK")];

    let store_dir = temp_dir("angryier-replay-store").ok_or("temp dir unavailable")?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let recorder = ReplayRecorder::new();
    let store = FileReplayStore::new(&store_dir)?;

    // Record one capsule per input and publish it durably.
    let mut published = Vec::new();
    for (input, expected_code, expected_stdout) in cases {
        let Some((native_code, native_stdout)) = run_native_observed(input) else {
            eprintln!("skipping: native harness could not be built");
            return Ok(());
        };
        // Native ground truth sanity: the fixture must actually branch.
        assert_eq!(
            native_code, expected_code,
            "native run of input {input} must exit {expected_code}"
        );
        assert_eq!(
            native_stdout, expected_stdout,
            "native run of input {input} must write the path output"
        );

        let recorded = recorder.record(&runtime, &fixture.elf, &[(register_id::GPR_BASE, input)], b"", 64)?;
        assert_eq!(
            recorded.capsule.expected.exit_code,
            Some(u64::try_from(expected_code)?),
            "capsule checkpoint must match the recorded engine outcome"
        );
        assert_eq!(recorded.capsule.expected.write_output, expected_stdout);
        assert_eq!(recorded.exit_code, u64::try_from(expected_code)?);
        assert_eq!(recorded.write_output, expected_stdout);
        store.publish(&recorded.capsule)?;
        published.push((recorded.capsule.id, input, expected_code, expected_stdout));
    }
    // The two inputs must produce two distinct capsules with distinct ids.
    assert_ne!(
        published[0].0, published[1].0,
        "different inputs must yield different capsule ids"
    );

    // Drop the in-memory state that matters: the runtime (block caches,
    // registers, captured syscalls) and the store handle. The recorder is
    // stateless configuration (a seed) and is recreated fresh below.
    drop(runtime);
    drop(store);

    // Reload from disk as a fresh process would and replay each capsule.
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let recorder = ReplayRecorder::new();
    let store = FileReplayStore::new(&store_dir)?;
    for (capsule_id, input, expected_code, expected_stdout) in published {
        assert!(
            store.contains(capsule_id),
            "capsule {capsule_id:?} must survive on disk"
        );
        let outcome = recorder.replay(&runtime, &store, capsule_id, &fixture.elf, 64)?;
        // Agreement with the capsule's checkpoints...
        assert_eq!(
            i32::try_from(outcome.exit_code)?,
            expected_code,
            "replayed exit code must match the capsule checkpoint"
        );
        assert_eq!(
            outcome.write_output, expected_stdout,
            "replayed output must match the capsule checkpoint"
        );
        // ...and with the native ground truth for the same input.
        let Some((native_code, native_stdout)) = run_native_observed(input) else {
            eprintln!("skipping: native harness could not be rebuilt");
            return Ok(());
        };
        assert_eq!(
            i32::try_from(outcome.exit_code)?,
            native_code,
            "replay must agree with the native exit code"
        );
        assert_eq!(
            outcome.write_output, native_stdout,
            "replay must agree with the native stdout"
        );
    }
    let _ = std::fs::remove_dir_all(&store_dir);
    Ok(())
}

/// Replaying the same capsule twice — through independent reloads — yields
/// identical outcomes (exit code, output, and step count).
#[test]
fn replaying_the_same_capsule_twice_is_deterministic() -> Result<(), Box<dyn std::error::Error>> {
    let Some(fixture) = fixture() else {
        eprintln!("skipping: binutils (as/ld) unavailable");
        return Ok(());
    };
    let store_dir = temp_dir("angryier-replay-determinism").ok_or("temp dir unavailable")?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let recorder = ReplayRecorder::new();
    let store = FileReplayStore::new(&store_dir)?;

    let recorded = recorder.record(&runtime, &fixture.elf, &[(register_id::GPR_BASE, 42)], b"", 64)?;
    let capsule_id = recorded.capsule.id;
    store.publish(&recorded.capsule)?;
    drop(recorded);
    drop(runtime);
    drop(store);

    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let store = FileReplayStore::new(&store_dir)?;
    let first = recorder.replay(&runtime, &store, capsule_id, &fixture.elf, 64)?;
    let second = recorder.replay(&runtime, &store, capsule_id, &fixture.elf, 64)?;
    assert_eq!(first, second, "two replays of the same capsule must be identical");
    assert_eq!(first.exit_code, 0);
    assert_eq!(first.write_output, b"OK");
    let _ = std::fs::remove_dir_all(&store_dir);
    Ok(())
}

/// Fail-closed evidence: tampered capsules reject with explicit errors and
/// validation runs BEFORE any re-execution.
#[test]
fn tampered_capsules_fail_closed_without_executing() -> Result<(), Box<dyn std::error::Error>> {
    let Some(fixture) = fixture() else {
        eprintln!("skipping: binutils (as/ld) unavailable");
        return Ok(());
    };
    let store_dir = temp_dir("angryier-replay-tamper").ok_or("temp dir unavailable")?;
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let recorder = ReplayRecorder::new();
    let store = FileReplayStore::new(&store_dir)?;
    let recorded = recorder.record(&runtime, &fixture.elf, &[(register_id::GPR_BASE, 42)], b"", 64)?;
    let capsule_id = recorded.capsule.id;
    store.publish(&recorded.capsule)?;
    let capsule = store.retrieve(capsule_id)?;
    drop(recorded);

    let rejection = |error: &ReplayRuntimeError, needle: &str, what: &str| -> Result<(), Box<dyn std::error::Error>> {
        let rendered = error.to_string();
        assert!(
            rendered.contains(needle),
            "{what} must reject with `{needle}`, got: {rendered}"
        );
        Ok(())
    };

    // A DIFFERENT binary: the host recomputes the image hash and must reject
    // before executing anything. The wrong image deliberately contains an
    // instruction the engine cannot execute (`addps` has no corpus form), so
    // an ImageMismatch — not an execution error — proves validation
    // short-circuited the run.
    let wrong_image = build_binary_from("_start:\n    addps %xmm1, %xmm0\n    hlt\n")
        .ok_or("binutils unavailable to build the wrong image")?;
    match runtime.replay_capsule(&wrong_image, &capsule, 64) {
        Err(error @ ReplayRuntimeError::Replay(ReplayError::ImageMismatch)) => {
            rejection(&error, "image hash", "wrong image")?
        }
        other => return Err(format!("wrong image must reject with ImageMismatch, got {other:?}").into()),
    }

    // Tampered image-hash field: same explicit rejection.
    let mut tampered = capsule.clone();
    tampered.image_hash = ContentId([0xEE; 32]);
    match runtime.replay_capsule(&fixture.elf, &tampered, 64) {
        Err(error @ ReplayRuntimeError::Replay(ReplayError::ImageMismatch)) => {
            rejection(&error, "image hash", "tampered image hash")?
        }
        other => return Err(format!("tampered hash must reject with ImageMismatch, got {other:?}").into()),
    }

    // Tampered schema version field.
    let mut tampered = capsule.clone();
    tampered.schema = ReplaySchemaVersion(99);
    match runtime.replay_capsule(&fixture.elf, &tampered, 64) {
        Err(error @ ReplayRuntimeError::Replay(ReplayError::SchemaMismatch)) => {
            rejection(&error, "schema", "tampered schema")?
        }
        other => return Err(format!("tampered schema must reject with SchemaMismatch, got {other:?}").into()),
    }

    // Old-shape version 1 capsule: it carries no recorded inputs or
    // checkpoints, so the replay host (schema 2) rejects it fail-closed.
    let mut v1 = capsule.clone();
    v1.schema = ReplaySchemaVersion(1);
    v1.image_hash = ContentId::default();
    v1.inputs = Default::default();
    v1.expected = Default::default();
    match runtime.replay_capsule(&fixture.elf, &v1, 64) {
        Err(error @ ReplayRuntimeError::Replay(ReplayError::SchemaMismatch)) => {
            rejection(&error, "schema", "version 1 capsule")?
        }
        other => return Err(format!("v1 capsule must reject with SchemaMismatch, got {other:?}").into()),
    }

    // Tampered semantic version.
    let mut tampered = capsule.clone();
    tampered.semantic_version = SemanticVersion(99);
    match runtime.replay_capsule(&fixture.elf, &tampered, 64) {
        Err(error @ ReplayRuntimeError::Replay(ReplayError::SemanticMismatch)) => {
            rejection(&error, "semantic", "tampered semantic version")?
        }
        other => return Err(format!("tampered semantic version must reject, got {other:?}").into()),
    }

    // Tampered checkpoint: validation passes (identity is intact) and the
    // replay executes, but the drifted outcome must be rejected, not
    // best-effort accepted.
    let mut tampered = capsule.clone();
    tampered.expected.exit_code = Some(1);
    match runtime.replay_capsule(&fixture.elf, &tampered, 64) {
        Err(error @ ReplayRuntimeError::Replay(ReplayError::CheckpointMismatch)) => {
            rejection(&error, "checkpoints", "drifted checkpoint")?
        }
        other => return Err(format!("drifted checkpoint must reject, got {other:?}").into()),
    }

    // The untampered capsule still replays cleanly after all of this.
    let outcome = recorder.replay(&runtime, &store, capsule_id, &fixture.elf, 64)?;
    assert_eq!(outcome.exit_code, 0);
    assert_eq!(outcome.write_output, b"OK");
    let _ = std::fs::remove_dir_all(&store_dir);
    Ok(())
}
