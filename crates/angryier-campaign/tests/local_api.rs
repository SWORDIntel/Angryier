//! Bounded public-API coverage for the in-host, single-writer campaign.
#![cfg(target_arch = "x86_64")]

use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use angryier_campaign::{Config, LocalCampaign, LocalConfig, LocalPolicy, Result, local::LocalRegister};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    dir: PathBuf,
    binary: PathBuf,
    entry: u64,
    fallthrough: u64,
    jump: u64,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn fixture() -> Result<Option<Fixture>> {
    fixture_with_source(
        ".global _start\n.text\n_start:\n cmp $5, %rbx\n je equal\n mov $1, %rdi\n jmp exit\nequal:\n xor %rdi, %rdi\nexit:\n mov $60, %rax\n syscall\n",
        &[0x48, 0x83, 0xfb, 0x05, 0x74],
    )
}

fn fixture_with_source(source_text: &str, opcode: &[u8; 5]) -> Result<Option<Fixture>> {
    let dir = std::env::temp_dir().join(format!(
        "angryier-local-api-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&dir)?;
    let source = dir.join("branch.s");
    let object = dir.join("branch.o");
    let binary = dir.join("branch.elf");
    fs::write(&source, source_text)?;
    for (program, args) in [
        (
            "as",
            vec![
                std::ffi::OsStr::new("--64"),
                std::ffi::OsStr::new("-o"),
                object.as_os_str(),
                source.as_os_str(),
            ],
        ),
        (
            "ld",
            vec![std::ffi::OsStr::new("-o"), binary.as_os_str(), object.as_os_str()],
        ),
    ] {
        let output = match Command::new(program).args(args).output() {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        assert!(
            output.status.success(),
            "{program}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let elf = fs::read(&binary)?;
    let entry = u64::from_le_bytes(elf[24..32].try_into()?);
    let phoff = u64::from_le_bytes(elf[32..40].try_into()?) as usize;
    let phentsize = u16::from_le_bytes(elf[54..56].try_into()?) as usize;
    let phnum = u16::from_le_bytes(elf[56..58].try_into()?) as usize;
    let offset = (0..phnum)
        .find_map(|index| {
            let ph = phoff + index * phentsize;
            let file = u64::from_le_bytes(elf.get(ph + 8..ph + 16)?.try_into().ok()?);
            let addr = u64::from_le_bytes(elf.get(ph + 16..ph + 24)?.try_into().ok()?);
            let len = u64::from_le_bytes(elf.get(ph + 32..ph + 40)?.try_into().ok()?);
            (entry >= addr && entry < addr + len).then_some((file + entry - addr) as usize)
        })
        .ok_or("entry not mapped")?;
    assert_eq!(&elf[offset..offset + 5], opcode);
    let fallthrough = entry + 6;
    let jump = fallthrough.wrapping_add_signed(i8::from_ne_bytes([elf[offset + 5]]) as i64);
    Ok(Some(Fixture {
        dir,
        binary,
        entry,
        fallthrough,
        jump,
    }))
}

fn config(f: &Fixture) -> LocalConfig {
    let mut campaign = Config::defaults(f.binary.clone(), PathBuf::new(), "local-api-v1".into());
    campaign.limits.max_steps = 4;
    LocalConfig {
        campaign,
        ledger: f.dir.join("campaign.ledger"),
        policy: LocalPolicy::RankTargets { exclude_avoid: false },
        find: vec![f.jump],
        avoid: vec![f.entry + 0x100, f.fallthrough],
        symbolic: None,
        regs: Vec::new(),
    }
}

fn ledger_bytes(path: &std::path::Path) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    let wal = PathBuf::from(format!("{}.wal", path.display()));
    Ok((fs::read(path)?, wal.exists().then(|| fs::read(wal)).transpose()?))
}

#[test]
fn ranked_handle_resumes_with_accepted_evidence_and_explicit_retry() -> Result<()> {
    let Some(f) = fixture()? else { return Ok(()) };
    let mut config = config(&f);
    assert!(LocalCampaign::resume(config.clone()).is_err());
    let mut handle = LocalCampaign::start(config.clone())?;
    assert!(LocalCampaign::start(config.clone()).is_err());
    let first = handle.advance(Duration::from_secs(10))?;
    assert!(first.steps > 0, "{first:?}");
    assert_eq!(first.report, handle.report());
    assert_eq!(first.report.retired_splits, 1, "{first:?}");
    let first_child = first.accepted_evidence.iter().find_map(|event| {
        event
            .delta
            .path
            .branches
            .first()
            .and_then(|branch| branch.tested_target)
    });
    assert_eq!(
        first_child,
        Some(f.jump),
        "ranked target must be accepted first: {first:?}"
    );
    assert_eq!(first.report.queued, 1, "sibling remains queued: {first:?}");
    drop(handle);

    // Lists are canonicalized before sealing; a reordered objective is the same campaign.
    config.avoid.reverse();
    let mut resumed = LocalCampaign::resume(config.clone())?;
    assert_eq!(resumed.report(), first.report);
    // Retry is explicit, not an implicit side effect of resume.
    resumed.retry_deferred()?;
    let next = resumed.advance(Duration::from_secs(10))?;
    assert!(next.report.completed >= first.report.completed, "{next:?}");
    assert!(
        next.accepted_evidence
            .iter()
            .any(|event| event.status == angryier_ledger::sustained::Status::Completed)
    );
    drop(resumed);
    assert_eq!(LocalCampaign::resume(config)?.report(), next.report);
    Ok(())
}

#[test]
fn deferred_work_requires_explicit_retry_after_resume() -> Result<()> {
    let Some(f) = fixture()? else { return Ok(()) };
    let mut config = config(&f);
    config.policy = LocalPolicy::ForkAll;
    config.campaign.limits.max_steps = 64;
    config.campaign.limits.max_active_states = 1;
    let mut handle = LocalCampaign::start(config.clone())?;
    let first = handle.advance(Duration::from_secs(10))?;
    assert_eq!(first.report.deferred, 2, "{first:?}");
    assert_eq!(first.report.completed, 0);
    drop(handle);
    let mut resumed = LocalCampaign::resume(config)?;
    assert_eq!(resumed.report().deferred, 2, "resume must not retry implicitly");
    resumed.retry_deferred()?;
    assert_eq!(resumed.report().queued, 2);
    let retried = resumed.advance(Duration::from_secs(10))?;
    assert_eq!(retried.report.completed, 2, "{retried:?}");
    assert_eq!(retried.report.deferred, 0);
    assert!(retried.report.complete_within_declared_bounds);
    Ok(())
}

#[test]
fn changed_pins_and_image_are_rejected_without_ledger_mutation() -> Result<()> {
    let Some(f) = fixture()? else { return Ok(()) };
    let config = config(&f);
    let mut handle = LocalCampaign::start(config.clone())?;
    let before = handle.report();
    let bytes = ledger_bytes(&config.ledger)?;
    let original = fs::read(&f.binary)?;
    let mut swapped = original.clone();
    swapped[original.len() - 1] ^= 1;
    fs::write(&f.binary, &swapped)?;
    assert!(
        handle.advance(Duration::from_secs(1)).is_err(),
        "advance must recheck the image"
    );
    assert_eq!(handle.report(), before);
    drop(handle);
    assert!(
        LocalCampaign::resume(config.clone()).is_err(),
        "resume must recheck the image"
    );
    assert_eq!(ledger_bytes(&config.ledger)?, bytes);
    fs::write(&f.binary, original)?;
    let mut variants = Vec::new();
    let mut changed = config.clone();
    changed.campaign.build_id.push_str("-changed");
    variants.push(changed);
    let mut changed = config.clone();
    changed.campaign.limits.max_steps += 1;
    variants.push(changed);
    let mut changed = config.clone();
    changed.policy = LocalPolicy::ForkAll;
    variants.push(changed);
    let mut changed = config.clone();
    changed.find = vec![f.fallthrough];
    variants.push(changed);
    let mut changed = config.clone();
    changed.avoid = vec![f.jump];
    variants.push(changed);
    let mut changed = config.clone();
    changed.policy = LocalPolicy::RankTargets { exclude_avoid: true };
    variants.push(changed);
    for variant in variants {
        assert!(LocalCampaign::resume(variant).is_err());
        assert_eq!(ledger_bytes(&config.ledger)?, bytes);
    }
    assert_eq!(LocalCampaign::resume(config)?.report(), before);
    Ok(())
}

#[test]
fn explicit_gpr_roots_replay_and_reject_changes_without_mutation() -> Result<()> {
    let Some(f) = fixture_with_source(
        ".global _start\n.text\n_start:\n cmp %rdx, %rdi\n nop\n je equal\n mov $1, %rdi\n jmp exit\nequal:\n xor %rdi, %rdi\nexit:\n mov $60, %rax\n syscall\n",
        &[0x48, 0x39, 0xd7, 0x90, 0x74],
    )?
    else {
        return Ok(());
    };
    let rdi: LocalRegister = "rdi".parse()?;
    let rsi: LocalRegister = "rsi".parse()?;
    let rdx: LocalRegister = "rdx".parse()?;
    for name in ["edi", "RDI", "rip", "r16", "al", "xmm0"] {
        assert!(name.parse::<LocalRegister>().is_err(), "{name} must be rejected");
    }
    for name in [
        "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    ] {
        assert_eq!(name.parse::<LocalRegister>()?.name(), name);
    }
    let mut config = config(&f);
    config.campaign.limits.max_steps = 64;
    config.symbolic = Some(vec![(rsi, 64), (rdi, 64)]);
    config.regs = vec![(rdx, 0xffff_8000_0000_1234)];
    for (symbolic, regs, expected) in [
        (Some(vec![]), vec![], "cannot be empty"),
        (Some(vec![(rdi, 32)]), vec![], "width 64"),
        (Some(vec![(rdi, 64), (rdi, 64)]), vec![], "duplicate symbolic"),
        (Some(vec![(rdi, 64)]), vec![(rdx, 1), (rdx, 2)], "duplicate concrete"),
        (Some(vec![(rdi, 64)]), vec![(rdi, 1)], "both symbolic"),
        (None, vec![("rbx".parse()?, 1)], "both symbolic"),
    ] {
        let mut invalid = config.clone();
        invalid.symbolic = symbolic;
        invalid.regs = regs;
        let error = match LocalCampaign::start(invalid) {
            Ok(_) => return Err(format!("expected {expected} to be rejected").into()),
            Err(error) => error,
        };
        assert!(error.to_string().contains(expected), "{error}");
        assert!(!config.ledger.exists(), "invalid roots must not create a ledger");
    }
    let mut handle = LocalCampaign::start(config.clone())?;
    let first = handle.advance(Duration::from_secs(10))?;
    assert!(first.report.retired_splits >= 1, "RDI branch must fork: {first:?}");
    assert!(!first.accepted_evidence.is_empty());
    drop(handle);
    let bytes = ledger_bytes(&config.ledger)?;
    if let Some(symbolic) = &mut config.symbolic {
        symbolic.reverse();
    }
    let mut resumed = LocalCampaign::resume(config.clone())?;
    assert_eq!(resumed.report(), first.report);
    let second = resumed.advance(Duration::from_secs(10))?;
    assert_eq!(second.report, first.report);
    let mut first_evidence = first.accepted_evidence;
    let mut second_evidence = second.accepted_evidence;
    first_evidence.sort_by_key(|event| event.work_index);
    second_evidence.sort_by_key(|event| event.work_index);
    assert_eq!(second_evidence, first_evidence);
    drop(resumed);
    assert_eq!(ledger_bytes(&config.ledger)?, bytes);
    for changed in [
        {
            let mut x = config.clone();
            x.symbolic = Some(vec![(rdi, 64)]);
            x
        },
        {
            let mut x = config.clone();
            x.symbolic = None;
            x
        },
        {
            let mut x = config.clone();
            x.regs[0].1 ^= 1;
            x
        },
        {
            let mut x = config.clone();
            x.regs.clear();
            x
        },
    ] {
        assert!(LocalCampaign::resume(changed).is_err());
        assert_eq!(ledger_bytes(&config.ledger)?, bytes);
    }
    Ok(())
}

#[test]
fn static_elf_validation_rejects_pie_machine_and_dynamic_headers_before_ledger() -> Result<()> {
    let Some(f) = fixture()? else { return Ok(()) };
    let config = config(&f);
    let original = fs::read(&f.binary)?;
    let phoff = usize::try_from(u64::from_le_bytes(original[32..40].try_into()?))?;
    for (offset, bytes, expected) in [
        (16, 3u16.to_le_bytes().to_vec(), "ET_EXEC"),
        (18, 3u16.to_le_bytes().to_vec(), "EM_X86_64"),
        (phoff, 3u32.to_le_bytes().to_vec(), "PT_INTERP"),
        (phoff, 2u32.to_le_bytes().to_vec(), "PT_DYNAMIC"),
    ] {
        let mut modified = original.clone();
        modified[offset..offset + bytes.len()].copy_from_slice(&bytes);
        fs::write(&f.binary, modified)?;
        let error = match LocalCampaign::start(config.clone()) {
            Err(error) => error,
            Ok(_) => return Err(format!("expected {expected} rejection").into()),
        };
        assert!(error.to_string().contains(expected), "{error}");
        assert!(!config.ledger.exists(), "invalid image must not create ledger");
    }
    fs::write(&f.binary, original)?;
    Ok(())
}

#[test]
fn existing_ledger_never_reopened_by_start_and_evidence_accessors_are_read_only() -> Result<()> {
    let Some(f) = fixture()? else { return Ok(()) };
    let mut config = config(&f);
    config.campaign.limits.max_steps = 64;
    let mut handle = LocalCampaign::start(config.clone())?;
    let outcome = handle.advance(Duration::from_secs(10))?;
    let accepted: Vec<_> = handle.cumulative_evidence().cloned().collect();
    assert_eq!(accepted, outcome.accepted_evidence);
    assert!(handle.accepted_events().len() >= accepted.len());
    let events = handle.accepted_events().to_vec();
    drop(handle);
    let bytes = ledger_bytes(&config.ledger)?;
    assert!(LocalCampaign::start(config.clone()).is_err());
    assert_eq!(ledger_bytes(&config.ledger)?, bytes);
    let reopened = LocalCampaign::resume(config.clone())?;
    assert_eq!(reopened.accepted_events(), events);
    assert_eq!(ledger_bytes(&config.ledger)?, bytes);
    Ok(())
}

#[test]
fn completed_exclusion_requires_exact_proven_avoid_without_ledger_mutation() -> Result<()> {
    let Some(f) = fixture()? else { return Ok(()) };
    let mut config = config(&f);
    config.campaign.limits.max_steps = 64;
    config.policy = LocalPolicy::RankTargets { exclude_avoid: true };
    config.avoid = vec![f.entry + 0x100];
    let mut handle = LocalCampaign::start(config.clone())?;
    assert!(!handle.checked_report()?.complete_within_declared_bounds);
    let error = match handle.advance(Duration::from_secs(10)) {
        Err(error) => error,
        Ok(_) => return Err("unproven exclusion must be rejected".into()),
    };
    assert!(error.to_string().contains("ExclusionUnproven"), "{error}");
    assert!(handle.report().complete_within_declared_bounds);
    let bytes = ledger_bytes(&config.ledger)?;
    assert!(handle.checked_report().is_err());
    assert_eq!(ledger_bytes(&config.ledger)?, bytes);
    drop(handle);
    assert!(LocalCampaign::resume(config)?.checked_report().is_err());
    Ok(())
}
