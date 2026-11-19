#![cfg(all(feature = "xed", feature = "script", target_arch = "x86_64"))]
#![allow(clippy::expect_used)]

use angryier_runtime::{
    mlua::{AnyUserData, Lua, ObjectLike, Table},
    script,
};
use std::{
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    dir: PathBuf,
    binary: PathBuf,
    ledger: PathBuf,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
fn fixture() -> Result<Option<Fixture>, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "angryier-policy-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&dir)?;
    let source = dir.join("branch.s");
    let object = dir.join("branch.o");
    let binary = dir.join("branch.elf");
    std::fs::write(
        &source,
        ".global _start\n.text\n_start:\n cmp $5, %rbx\n je equal\n mov $1, %rdi\n jmp exit\nequal:\n xor %rdi, %rdi\nexit:\n mov $60, %rax\n syscall\n",
    )?;
    for (program, args) in [
        (
            "as",
            vec![
                "--64",
                "-o",
                object.to_str().expect("object"),
                source.to_str().expect("source"),
            ],
        ),
        (
            "ld",
            vec!["-o", binary.to_str().expect("binary"), object.to_str().expect("object")],
        ),
    ] {
        let output = match Command::new(program).args(args).output() {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("{program}: {error}").into()),
        };
        assert!(
            output.status.success(),
            "{program}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(Some(Fixture {
        ledger: dir.join("frontier.ledger"),
        binary,
        dir,
    }))
}
fn options(lua: &Lua, f: &Fixture, version: u8) -> Table {
    let opts = lua.create_table().expect("opts");
    opts.set("ledger", f.ledger.to_str().expect("ledger")).expect("ledger");
    opts.set("fidelity", "prove").expect("fidelity");
    let symbolic = lua.create_table().expect("symbolic");
    symbolic.set("rbx", 64).expect("rbx");
    opts.set("symbolic", symbolic).expect("symbolic");
    let artifacts = lua.create_table().expect("artifacts");
    artifacts
        .set(
            "script",
            if version == 1 {
                "angry.sustained/v1"
            } else {
                "angry.sustained/v2"
            },
        )
        .expect("script");
    artifacts
        .set("policy", if version == 1 { "fork-all/v1" } else { "rank-targets/v1" })
        .expect("policy");
    artifacts.set("solver_policy", "z3-default").expect("solver");
    opts.set("artifacts", artifacts).expect("artifacts");
    let limits = lua.create_table().expect("limits");
    for (name, value) in [
        ("max_steps", 64),
        ("max_path_steps", 64),
        ("max_active_states", 2),
        ("max_path_depth", 64),
        ("max_loop_visits", 64),
        ("max_solver_millis", 10000),
        ("max_wall_millis", 30000),
        ("max_ram_bytes", 64 * 1024 * 1024),
        ("max_disk_bytes", 1024 * 1024),
        ("max_trace_bytes", 1024 * 1024),
    ] {
        limits.set(name, value).expect("limit");
    }
    opts.set("limits", limits).expect("limits");
    opts
}
fn invoke(lua: &Lua, f: &Fixture, opts: Table) -> angryier_runtime::mlua::Result<AnyUserData> {
    let sustained: Table = lua.globals().get::<Table>("angry")?.get("sustained")?;
    sustained
        .get::<angryier_runtime::mlua::Function>("start")?
        .call((f.binary.to_str().expect("binary"), opts))
}

fn branch_targets(f: &Fixture) -> (u64, u64) {
    let binary = std::fs::read(&f.binary).expect("ELF");
    let entry = u64::from_le_bytes(binary[24..32].try_into().expect("entry"));
    let phoff = u64::from_le_bytes(binary[32..40].try_into().expect("phoff")) as usize;
    let phentsize = u16::from_le_bytes(binary[54..56].try_into().expect("phentsize")) as usize;
    let phnum = u16::from_le_bytes(binary[56..58].try_into().expect("phnum")) as usize;
    let offset = (0..phnum)
        .find_map(|i| {
            let ph = phoff + i * phentsize;
            let file = u64::from_le_bytes(binary[ph + 8..ph + 16].try_into().ok()?);
            let virtual_addr = u64::from_le_bytes(binary[ph + 16..ph + 24].try_into().ok()?);
            let len = u64::from_le_bytes(binary[ph + 32..ph + 40].try_into().ok()?);
            (entry >= virtual_addr && entry < virtual_addr + len).then_some((file + entry - virtual_addr) as usize)
        })
        .expect("entry segment");
    assert_eq!(&binary[offset..offset + 5], &[0x48, 0x83, 0xfb, 0x05, 0x74]);
    let false_target = entry + 6;
    let true_target = false_target.wrapping_add_signed(i8::from_ne_bytes([binary[offset + 5]]) as i64);
    (false_target, true_target)
}

fn target_options(lua: &Lua, f: &Fixture, version: u8, target: u64, avoid: bool, exclude: bool) -> Table {
    let opts = options(lua, f, version);
    let targets = lua.create_table().expect("targets");
    let list = lua.create_table().expect("target list");
    list.set(1, format!("0x{target:x}")).expect("target");
    targets
        .set(if avoid { "avoid" } else { "find" }, list)
        .expect("target kind");
    opts.set("targets", targets).expect("targets");
    if version == 2 {
        let policy = lua.create_table().expect("policy");
        policy.set("exclude_avoid", exclude).expect("exclusion");
        opts.set("policy", policy).expect("policy");
    }
    opts
}

#[test]
fn v2_ranked_find_changes_the_first_accepted_child_vs_fifo() -> Result<(), Box<dyn std::error::Error>> {
    let Some(f) = fixture()? else { return Ok(()) };
    let (find_target, fifo_target) = branch_targets(&f);
    let lua = Lua::new();
    script::register(&lua).expect("register");
    let ranked_opts = target_options(&lua, &f, 2, find_target, false, false);
    ranked_opts
        .get::<Table>("limits")
        .expect("limits")
        .set("max_steps", 4)
        .expect("partial batch");
    let handle = invoke(&lua, &f, ranked_opts).expect("v2 start");
    let ranked: Table = handle.call_method("advance", ()).expect("ranked advance");
    let paths: Table = ranked
        .get::<Table>("cumulative_evidence")
        .expect("evidence")
        .get("paths")
        .expect("paths");
    assert_eq!(
        paths.raw_len(),
        2,
        "fork and only the first ranked child should have evidence"
    );
    let first: Table = paths.get(2).expect("first child");
    let branch: Table = first
        .get::<Table>("branches")
        .expect("branches")
        .get(1)
        .expect("first branch");
    assert_eq!(branch.get::<u64>("tested_target").expect("tested target"), find_target);

    let Some(fifo_fixture) = fixture()? else { return Ok(()) };
    assert_eq!(branch_targets(&fifo_fixture), (find_target, fifo_target));
    let fifo_opts = target_options(&lua, &fifo_fixture, 1, find_target, false, false);
    fifo_opts
        .get::<Table>("limits")
        .expect("limits")
        .set("max_steps", 4)
        .expect("partial batch");
    let fifo = invoke(&lua, &fifo_fixture, fifo_opts).expect("v1 start");
    let fifo_report: Table = fifo.call_method("advance", ()).expect("fifo advance");
    let fifo_paths: Table = fifo_report
        .get::<Table>("cumulative_evidence")
        .expect("evidence")
        .get("paths")
        .expect("paths");
    assert_eq!(
        fifo_paths.raw_len(),
        2,
        "fork and only the FIFO child should have evidence"
    );
    let first: Table = fifo_paths.get(2).expect("first child");
    let branch: Table = first
        .get::<Table>("branches")
        .expect("branches")
        .get(1)
        .expect("first branch");
    assert_eq!(branch.get::<u64>("tested_target").expect("target"), fifo_target);
    Ok(())
}

#[test]
fn v2_partial_ranked_resume_keeps_pinned_order_and_identity() -> Result<(), Box<dyn std::error::Error>> {
    let Some(f) = fixture()? else { return Ok(()) };
    let (find_target, _) = branch_targets(&f);
    let (campaign_id, accepted_id) = {
        let lua = Lua::new();
        script::register(&lua).expect("register");
        let opts = target_options(&lua, &f, 2, find_target, false, false);
        opts.get::<Table>("limits")
            .expect("limits")
            .set("max_steps", 4)
            .expect("partial batch");
        let handle = invoke(&lua, &f, opts).expect("start");
        let report: Table = handle.call_method("advance", ()).expect("advance");
        let paths: Table = report
            .get::<Table>("cumulative_evidence")
            .expect("evidence")
            .get("paths")
            .expect("paths");
        assert_eq!(paths.raw_len(), 2);
        (
            report.get::<String>("campaign_digest").expect("campaign"),
            paths
                .get::<Table>(2)
                .expect("ranked child")
                .get::<String>("path_id")
                .expect("id"),
        )
    };
    let lua = Lua::new();
    script::register(&lua).expect("register");
    let opts = target_options(&lua, &f, 2, find_target, false, false);
    opts.get::<Table>("limits")
        .expect("limits")
        .set("max_steps", 4)
        .expect("partial batch");
    let handle = invoke_resume(&lua, &f, opts).expect("resume");
    let report: Table = handle.call_method("report", ()).expect("persisted report");
    assert_eq!(report.get::<String>("campaign_digest").expect("campaign"), campaign_id);
    let paths: Table = report
        .get::<Table>("evidence")
        .expect("evidence")
        .get("paths")
        .expect("paths");
    assert_eq!(paths.raw_len(), 2);
    assert_eq!(
        paths
            .get::<Table>(2)
            .expect("child")
            .get::<String>("path_id")
            .expect("id"),
        accepted_id
    );
    assert_eq!(report.get::<usize>("queued").expect("queued"), 1);
    Ok(())
}

#[test]
fn v2_rejects_invalid_policy_and_v1_keeps_existing_behavior() -> Result<(), Box<dyn std::error::Error>> {
    let Some(f) = fixture()? else { return Ok(()) };
    let lua = Lua::new();
    script::register(&lua).expect("register");
    let opts = options(&lua, &f, 2);
    let policy = lua.create_table().expect("policy");
    policy.set("mystery", true).expect("field");
    opts.set("policy", policy).expect("policy");
    let error = invoke(&lua, &f, opts).expect_err("reject unsupported policy");
    assert!(format!("{error:?}").contains("unsupported policy field"), "{error:?}");
    let opts = options(&lua, &f, 1);
    let handle = invoke(&lua, &f, opts.clone()).expect("v1 start");
    let report: Table = handle.call_method("report", ()).expect("report");
    assert_eq!(report.get::<usize>("queued").expect("queued"), 1);
    opts.get::<Table>("artifacts")
        .expect("artifacts")
        .set("policy", "rank-targets/v1")
        .expect("mutate policy");
    let error = handle
        .call_method::<Table>("report", ())
        .expect_err("mutated policy rejected");
    assert!(
        format!("{error:?}").contains("custom exploration policy is unsupported"),
        "{error:?}"
    );
    opts.get::<Table>("artifacts")
        .expect("artifacts")
        .set("policy", "fork-all/v1")
        .expect("restore policy");
    opts.set("workers", 2).expect("unsupported mutation");
    let error = handle
        .call_method::<Table>("advance", ())
        .expect_err("invalid options rejected before execution");
    assert!(format!("{error:?}").contains("unsupported option workers"), "{error:?}");
    Ok(())
}

#[test]
fn report_reads_persisted_paths_and_rejects_mutated_targets() -> Result<(), Box<dyn std::error::Error>> {
    let Some(f) = fixture()? else { return Ok(()) };
    let binary = std::fs::read(&f.binary).expect("ELF");
    let entry = u64::from_le_bytes(binary[24..32].try_into().expect("ELF entry"));
    let (id, edges, verified, count) = {
        let lua = Lua::new();
        script::register(&lua).expect("register");
        let opts = options_with_entry_target(&lua, &f, entry);
        let handle = invoke(&lua, &f, opts).expect("start");
        let initial: Table = handle.call_method("report", ()).expect("initial report");
        assert_eq!(
            initial
                .get::<Table>("evidence")
                .expect("evidence")
                .get::<Table>("paths")
                .expect("paths")
                .raw_len(),
            0
        );
        let advanced: Table = handle.call_method("advance", ()).expect("advance");
        let persisted: Table = advanced.get("cumulative_evidence").expect("cumulative evidence");
        let paths: Table = persisted.get("paths").expect("paths");
        assert!(paths.raw_len() > 0, "advance must persist accepted path evidence");
        let first: Table = paths.get(1).expect("first path");
        (
            first.get::<String>("path_id").expect("id"),
            first.get::<Table>("edges").expect("edges").raw_len(),
            persisted
                .get::<usize>("replay_verified_witnesses")
                .expect("verified count"),
            paths.raw_len(),
        )
    };
    let lua = Lua::new();
    script::register(&lua).expect("register");
    let resumed_opts = options_with_entry_target(&lua, &f, entry);
    let resumed = invoke_resume(&lua, &f, resumed_opts.clone()).expect("resume");
    let report: Table = resumed.call_method("report", ()).expect("resumed report");
    let evidence: Table = report.get("evidence").expect("persisted evidence");
    let resumed_paths: Table = evidence.get("paths").expect("paths");
    assert_eq!(resumed_paths.raw_len(), count);
    assert_eq!(
        resumed_paths
            .get::<Table>(1)
            .expect("first")
            .get::<String>("path_id")
            .expect("id"),
        id
    );
    assert_eq!(
        resumed_paths
            .get::<Table>(1)
            .expect("first")
            .get::<Table>("edges")
            .expect("edges")
            .raw_len(),
        edges
    );
    assert_eq!(
        evidence
            .get::<usize>("replay_verified_witnesses")
            .expect("verified count"),
        verified
    );
    resumed_opts
        .get::<Table>("targets")
        .expect("targets")
        .get::<Table>("find")
        .expect("find")
        .set(1, entry + 1)
        .expect("mutate target");
    let error = resumed
        .call_method::<Table>("report", ())
        .expect_err("mutation must fail");
    assert!(format!("{error:?}").contains("options changed"), "{error:?}");
    Ok(())
}

#[test]
fn v2_excludes_exact_sat_child_with_atomic_policy_evidence_and_resume() -> Result<(), Box<dyn std::error::Error>> {
    let Some(f) = fixture()? else { return Ok(()) };
    let (false_target, true_target) = branch_targets(&f);
    let (campaign, excluded_id, count) = {
        let lua = Lua::new();
        script::register(&lua).expect("register");
        let opts = target_options(&lua, &f, 2, false_target, true, true);
        let handle = invoke(&lua, &f, opts.clone()).expect("v2 start");
        let report: Table = handle.call_method("advance", ()).expect("exclude advance");
        assert_eq!(report.get::<usize>("excluded").expect("excluded"), 1);
        assert_eq!(report.get::<usize>("infeasible").expect("infeasible"), 0);
        let evidence: Table = report.get("cumulative_evidence").expect("evidence");
        assert_eq!(evidence.get::<usize>("excluded_paths").expect("excluded paths"), 1);
        assert_eq!(evidence.get::<usize>("infeasible_paths").expect("infeasible paths"), 0);
        let paths: Table = evidence.get("paths").expect("paths");
        let excluded = (1..=paths.raw_len())
            .map(|i| paths.get::<Table>(i).expect("path"))
            .find(|p| p.get::<String>("disposition").expect("disposition") == "ExcludedByPolicy")
            .expect("excluded path");
        let branch: Table = excluded
            .get::<Table>("branches")
            .expect("branches")
            .get(1)
            .expect("branch");
        assert_eq!(branch.get::<u64>("tested_target").expect("target"), false_target);
        assert_eq!(branch.get::<String>("solver_status").expect("status"), "Sat");
        let edges: Table = excluded.get("edges").expect("edges");
        for i in 1..=edges.raw_len() {
            assert_ne!(
                edges
                    .get::<Table>(i)
                    .expect("edge")
                    .get::<String>("basis")
                    .expect("basis"),
                "solver_infeasible"
            );
        }
        let campaign = report.get::<String>("campaign_digest").expect("campaign");
        let excluded_id = excluded.get::<String>("path_id").expect("id");
        opts.get::<Table>("policy")
            .expect("policy")
            .set("exclude_avoid", false)
            .expect("mutate");
        let error = handle
            .call_method::<Table>("advance", ())
            .expect_err("policy mutation rejected");
        assert!(format!("{error:?}").contains("options changed"));
        (campaign, excluded_id, paths.raw_len())
    };
    let lua = Lua::new();
    script::register(&lua).expect("register");
    let wrong = target_options(&lua, &f, 2, true_target, true, true);
    assert!(
        invoke_resume(&lua, &f, wrong).is_err(),
        "different objective cannot resume"
    );
    let resumed = invoke_resume(&lua, &f, target_options(&lua, &f, 2, false_target, true, true)).expect("resume");
    let report: Table = resumed.call_method("report", ()).expect("report");
    assert_eq!(report.get::<String>("campaign_digest").expect("campaign"), campaign);
    let paths: Table = report
        .get::<Table>("evidence")
        .expect("evidence")
        .get("paths")
        .expect("paths");
    assert_eq!(paths.raw_len(), count);
    assert!((1..=count).any(|i| {
        paths
            .get::<Table>(i)
            .expect("path")
            .get::<String>("path_id")
            .expect("id")
            == excluded_id
    }));
    Ok(())
}

#[test]
fn v2_rejects_exclude_without_exact_branch_target() -> Result<(), Box<dyn std::error::Error>> {
    let Some(f) = fixture()? else { return Ok(()) };
    let lua = Lua::new();
    script::register(&lua).expect("register");
    let entry = u64::from_le_bytes(
        std::fs::read(&f.binary).expect("binary")[24..32]
            .try_into()
            .expect("entry"),
    );
    let error = invoke(&lua, &f, target_options(&lua, &f, 2, entry, true, true))
        .expect_err("entry cannot be excluded as branch target");
    assert!(
        format!("{error:?}").contains("exact dynamic branch target"),
        "{error:?}"
    );
    assert!(!f.ledger.exists());
    Ok(())
}

fn options_with_entry_target(lua: &Lua, f: &Fixture, entry: u64) -> Table {
    let opts = options(lua, f, 1);
    let targets = lua.create_table().expect("targets");
    let find = lua.create_table().expect("find");
    find.set(1, entry).expect("entry target");
    targets.set("find", find).expect("find");
    opts.set("targets", targets).expect("targets");
    opts
}

fn invoke_resume(lua: &Lua, f: &Fixture, opts: Table) -> angryier_runtime::mlua::Result<AnyUserData> {
    let sustained: Table = lua.globals().get::<Table>("angry")?.get("sustained")?;
    sustained
        .get::<angryier_runtime::mlua::Function>("resume")?
        .call((f.binary.to_str().expect("binary"), opts))
}
