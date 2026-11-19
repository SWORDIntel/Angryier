#![cfg(all(feature = "xed", feature = "script", target_arch = "x86_64"))]
#![allow(clippy::expect_used)]

use angryier_runtime::{
    mlua::{Lua, ObjectLike, Table},
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
fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!(
        "angryier-sustained-lua-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&dir).expect("fixture dir");
    let source = dir.join("branch.s");
    let object = dir.join("branch.o");
    let binary = dir.join("branch.elf");
    std::fs::write(&source, ".global _start\n.text\n_start:\n cmp $5, %rbx\n je equal\n mov $1, %rdi\n jmp exit\nequal:\n xor %rdi, %rdi\nexit:\n mov $60, %rax\n syscall\n").expect("fixture source");
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
        let output = Command::new(program)
            .args(args)
            .output()
            .map_err(|error| std::io::Error::new(error.kind(), format!("failed to invoke {program}: {error}")))?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "{program} failed ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ))
            .into());
        }
    }
    Ok(Fixture {
        ledger: dir.join("frontier.ledger"),
        binary,
        dir,
    })
}
fn lua() -> Lua {
    let lua = Lua::new();
    script::register(&lua).expect("register Lua API");
    lua
}
fn options(lua: &Lua, f: &Fixture, cap: u64) -> Table {
    let opts = lua.create_table().expect("opts");
    opts.set("ledger", f.ledger.to_str().expect("ledger path"))
        .expect("ledger");
    opts.set("fidelity", "prove").expect("fidelity");
    let symbolic = lua.create_table().expect("symbolic");
    symbolic.set("rbx", 64).expect("symbolic register");
    opts.set("symbolic", symbolic).expect("symbolic");
    let artifacts = lua.create_table().expect("artifacts");
    artifacts.set("script", "angry.sustained/v1").expect("script");
    artifacts.set("policy", "fork-all/v1").expect("policy");
    artifacts.set("solver_policy", "z3-default").expect("solver policy");
    opts.set("artifacts", artifacts).expect("artifacts");
    let limits = lua.create_table().expect("limits");
    for (key, value) in [
        ("max_steps", 64),
        ("max_path_steps", 64),
        ("max_active_states", cap),
        ("max_path_depth", 64),
        ("max_loop_visits", 64),
        ("max_solver_millis", 10_000),
        ("max_wall_millis", 30_000),
        ("max_ram_bytes", 64 * 1024 * 1024),
        ("max_disk_bytes", 1024 * 1024),
        ("max_trace_bytes", 1024 * 1024),
    ] {
        limits.set(key, value).expect("limit");
    }
    opts.set("limits", limits).expect("limits");
    opts
}
fn invoke(
    lua: &Lua,
    method: &str,
    f: &Fixture,
    opts: Table,
) -> angryier_runtime::mlua::Result<angryier_runtime::mlua::AnyUserData> {
    let sustained: Table = lua.globals().get::<Table>("angry")?.get("sustained")?;
    let func: angryier_runtime::mlua::Function = sustained.get(method)?;
    func.call((f.binary.to_str().expect("binary path"), opts))
}

#[test]
fn lua_fork_cap_restart_manifest_and_corruption() -> Result<(), Box<dyn std::error::Error>> {
    let f = fixture()?;
    {
        let lua = lua();
        let bad_fidelity = options(&lua, &f, 1);
        bad_fidelity.set("fidelity", "hunt").expect("fidelity");
        assert!(
            format!(
                "{:?}",
                invoke(&lua, "start", &f, bad_fidelity).expect_err("fidelity mismatch")
            )
            .contains("only prove")
        );
        let bad_solver = options(&lua, &f, 1);
        bad_solver
            .get::<Table>("artifacts")
            .expect("artifacts")
            .set("solver_policy", "different")
            .expect("policy");
        assert!(
            format!(
                "{:?}",
                invoke(&lua, "start", &f, bad_solver).expect_err("solver policy mismatch")
            )
            .contains("z3-default")
        );
        for (field, bytes, expected) in [
            (
                "script",
                "print('not executed')",
                "analyst script execution is unsupported",
            ),
            ("policy", "find=0x401000", "custom exploration policy is unsupported"),
        ] {
            let opts = options(&lua, &f, 1);
            opts.get::<Table>("artifacts")
                .expect("artifacts")
                .set(field, bytes)
                .expect("artifact");
            let error = invoke(&lua, "start", &f, opts).expect_err("unapplied artifact");
            assert!(format!("{error:?}").contains(expected), "{error:?}");
        }
        for field in ["inputs", "stubs"] {
            let opts = options(&lua, &f, 1);
            let table = lua.create_table().expect("named artifacts");
            table.set("example", "bytes").expect("artifact bytes");
            opts.get::<Table>("artifacts")
                .expect("artifacts")
                .set(field, table)
                .expect("artifact");
            let error = invoke(&lua, "start", &f, opts).expect_err("unapplied named artifact");
            assert!(
                format!("{error:?}").contains("not applied or replay-validated"),
                "{error:?}"
            );
        }
        let find = options(&lua, &f, 1);
        find.set("find", lua.create_table().expect("find targets"))
            .expect("find");
        assert!(
            format!("{:?}", invoke(&lua, "start", &f, find).expect_err("unsupported find"))
                .contains("unsupported option find")
        );
        let handle = invoke(&lua, "start", &f, options(&lua, &f, 1)).expect("start");
        let initial: Table = handle.call_method("report", ()).expect("initial report");
        assert_eq!(initial.get::<usize>("queued").expect("queued"), 1);
        let report: Table = handle.call_method("advance", ()).expect("fork under cap");
        assert_eq!(report.get::<usize>("retired_splits").expect("split"), 1);
        assert_eq!(report.get::<usize>("deferred").expect("deferred"), 2);
        assert!(!report.get::<bool>("complete_within_declared_bounds").expect("partial"));
        let evidence: Table = report.get("evidence").expect("evidence");
        assert!(evidence.get::<usize>("retained_frontier").expect("frontier") >= 2);
        let frontier: Table = evidence.get("frontier").expect("frontier records");
        assert_eq!(
            frontier.raw_len(),
            evidence.get::<usize>("retained_frontier").expect("count")
        );
        for entry in frontier.sequence_values::<Table>() {
            let entry = entry.expect("pending path");
            assert_eq!(entry.get::<String>("path_id").expect("path id").len(), 64);
            assert!(!entry.get::<String>("reason").expect("pending reason").is_empty());
        }
    }
    {
        let lua = lua();
        let changed = options(&lua, &f, 2);
        let error = invoke(&lua, "resume", &f, changed).expect_err("changed cap changes manifest");
        assert!(format!("{error:?}").contains("MismatchedCampaign"), "{error:?}");
        let seeded = options(&lua, &f, 1);
        let regs = lua.create_table().expect("register seeds");
        regs.set("rax", 5).expect("seed rax");
        seeded.set("regs", regs).expect("regs");
        let error =
            invoke(&lua, "resume", &f, seeded).expect_err("changed applied register seed changes campaign identity");
        assert!(format!("{error:?}").contains("MismatchedCampaign"), "{error:?}");
        let symbolic = options(&lua, &f, 1);
        symbolic
            .get::<Table>("symbolic")
            .expect("symbolic")
            .set("rdi", 64)
            .expect("symbolic rdi");
        let error =
            invoke(&lua, "resume", &f, symbolic).expect_err("changed applied symbolic seed changes campaign identity");
        assert!(format!("{error:?}").contains("MismatchedCampaign"), "{error:?}");
        let handle = invoke(&lua, "resume", &f, options(&lua, &f, 1)).expect("resume pinned campaign");
        let report: Table = handle.call_method("report", ()).expect("reopened report");
        assert_eq!(report.get::<usize>("deferred").expect("deferred"), 2);
        let retry: Table = handle.call_method("retry_deferred", ()).expect("explicit retry");
        assert_eq!(retry.get::<usize>("queued").expect("queued"), 2);
        let report: Table = handle.call_method("advance", ()).expect("retry under same cap");
        assert_eq!(report.get::<usize>("completed").expect("completed"), 2);
        assert!(report.get::<bool>("complete_within_declared_bounds").expect("complete"));
        assert_eq!(report.get::<usize>("retired_splits").expect("splits"), 1);
        let evidence: Table = report.get("evidence").expect("evidence");
        let paths: Table = evidence.get("paths").expect("actual paths");
        assert_eq!(paths.raw_len(), 2);
        assert_eq!(evidence.get::<usize>("terminal_paths").expect("terminal count"), 2);
        assert_eq!(evidence.get::<Table>("frontier").expect("frontier").raw_len(), 0);
        let mut saw_branch = false;
        let mut saw_edge = false;
        for path in paths.sequence_values::<Table>() {
            let path = path.expect("observed path");
            assert_eq!(path.get::<String>("path_id").expect("path id").len(), 64);
            assert_eq!(path.get::<String>("provenance_digest").expect("provenance").len(), 64);
            assert_eq!(path.get::<String>("fidelity").expect("fidelity"), "Prove");
            assert_eq!(path.get::<String>("disposition").expect("disposition"), "Terminal");
            assert!(path.get::<bool>("witness_present").expect("replayed witness"));
            assert!(path.get::<bool>("replay_verified").expect("concrete replay proof"));
            let witness: Table = path.get("witness").expect("witness provenance");
            assert_eq!(witness.get::<String>("input_digest").expect("input digest").len(), 64);
            assert_eq!(witness.get::<String>("trace_digest").expect("trace digest").len(), 64);
            assert_eq!(path.get::<Table>("semantic_debt").expect("debt").raw_len(), 0);
            let blocks: Table = path.get("blocks").expect("dynamic blocks");
            assert!(blocks.raw_len() > 1);
            let first: Table = blocks.get(1).expect("entry block");
            assert_eq!(
                first.get::<String>("pc_hex").expect("exact pc"),
                format!("0x{:016x}", first.get::<u64>("pc").expect("pc"))
            );
            let edges: Table = path.get("edges").expect("flow edges");
            assert!(edges.raw_len() > 0);
            let edge: Table = edges.get(1).expect("first edge");
            assert_eq!(edge.get::<String>("basis").expect("basis"), "observed");
            assert_eq!(edge.get::<String>("trace_digest").expect("trace digest").len(), 64);
            assert_eq!(
                edge.get::<u64>("from_pc").expect("edge from"),
                first.get::<u64>("pc").expect("block pc")
            );
            saw_edge = true;
            let branches: Table = path.get("branches").expect("branches");
            for branch in branches.sequence_values::<Table>() {
                let branch = branch.expect("query");
                assert_eq!(
                    branch
                        .get::<String>("predicate_digest")
                        .expect("condition digest")
                        .len(),
                    64
                );
                assert_eq!(branch.get::<String>("query_digest").expect("query digest").len(), 64);
                assert_eq!(branch.get::<String>("solver_status").expect("solver"), "Sat");
                assert_eq!(branch.get::<String>("result_digest").expect("solver result").len(), 64);
                assert!(
                    branch
                        .get::<Option<String>>("tested_target_hex")
                        .expect("target")
                        .is_some()
                );
                saw_branch = true;
            }
        }
        assert!(saw_branch && saw_edge, "paths must expose branch and edge evidence");
        let binary = std::fs::read(&f.binary).expect("pinned binary");
        let mut changed = binary.clone();
        changed.push(0);
        std::fs::write(&f.binary, changed).expect("mutate fixture image");
        assert!(
            format!(
                "{:?}",
                handle.call_method::<Table>("advance", ()).expect_err("binary mismatch")
            )
            .contains("binary artifact mismatch")
        );
        std::fs::write(&f.binary, binary).expect("restore fixture image");
    }
    std::fs::write(&f.ledger, b"corrupt frontier").expect("corrupt fixture ledger");
    let lua = lua();
    let error = invoke(&lua, "resume", &f, options(&lua, &f, 1)).expect_err("corrupt ledger rejected");
    assert!(format!("{error:?}").contains("Corrupt"), "{error:?}");
    Ok(())
}

#[test]
fn lua_observational_targets_are_canonical_and_never_prune() -> Result<(), Box<dyn std::error::Error>> {
    let f = fixture()?;
    let image = std::fs::read(&f.binary).expect("ELF");
    let entry = u64::from_le_bytes(image[24..32].try_into().expect("ELF entry"));
    let high = "0xffff800000000001";
    let make_opts = |lua: &Lua, reverse: bool, different: bool| {
        let opts = options(lua, &f, 1);
        let targets = lua.create_table().expect("targets");
        let find = lua.create_table().expect("find");
        find.set(if reverse { 2 } else { 1 }, entry).expect("entry target");
        find.set(
            if reverse { 1 } else { 2 },
            if different { "0xffff800000000002" } else { high },
        )
        .expect("high target");
        let avoid = lua.create_table().expect("avoid");
        avoid.set(1, entry).expect("avoid entry, observational only");
        targets.set("find", find).expect("find");
        targets.set("avoid", avoid).expect("avoid");
        opts.set("targets", targets).expect("targets");
        opts
    };
    {
        let lua = lua();
        let malformed = make_opts(&lua, false, false);
        malformed
            .get::<Table>("targets")
            .expect("targets")
            .set("mystery", true)
            .expect("invalid key");
        assert!(
            format!(
                "{:?}",
                invoke(&lua, "start", &f, malformed).expect_err("unknown target option")
            )
            .contains("unknown targets field")
        );
        let malformed = make_opts(&lua, false, false);
        malformed
            .get::<Table>("targets")
            .expect("targets")
            .get::<Table>("find")
            .expect("find")
            .set(3, 1.5)
            .expect("float");
        assert!(
            format!(
                "{:?}",
                invoke(&lua, "start", &f, malformed).expect_err("lossy target option")
            )
            .contains("invalid targets.find address")
        );
        let handle = invoke(&lua, "start", &f, make_opts(&lua, false, false)).expect("start");
        let partial: Table = handle.call_method("advance", ()).expect("fork cap");
        assert_eq!(partial.get::<usize>("excluded").expect("not pruned"), 0);
        assert!(!partial.get::<bool>("complete_within_declared_bounds").expect("partial"));
        let targets: Table = partial.get("targets").expect("observational targets");
        let find: Table = targets.get("find").expect("find");
        assert_eq!(find.raw_len(), 2);
        let entry_target: Table = find.get(1).expect("sorted entry");
        assert_eq!(entry_target.get::<u64>("pc").expect("entry"), entry);
        assert!(!entry_target.get::<bool>("observed").expect("no retained trace yet"));
    }
    {
        let lua = lua();
        let error =
            invoke(&lua, "resume", &f, make_opts(&lua, true, true)).expect_err("changed target changes identity");
        assert!(format!("{error:?}").contains("MismatchedCampaign"), "{error:?}");
        let handle = invoke(&lua, "resume", &f, make_opts(&lua, true, false)).expect("canonical order allows resume");
        let retry: Table = handle.call_method("retry_deferred", ()).expect("retry children");
        assert_eq!(retry.get::<usize>("queued").expect("queued"), 2);
        let report: Table = handle.call_method("advance", ()).expect("complete children");
        assert_eq!(report.get::<usize>("completed").expect("completed"), 2);
        assert_eq!(report.get::<usize>("excluded").expect("not pruned"), 0);
        let targets: Table = report.get("targets").expect("targets");
        let find: Table = targets.get("find").expect("find");
        let reached: Table = find.get(1).expect("entry target");
        let absent: Table = find.get(2).expect("high target");
        assert!(reached.get::<bool>("observed").expect("entry observed"));
        assert_eq!(
            reached.get::<String>("pc_hex").expect("entry hex"),
            format!("0x{entry:016x}")
        );
        assert!(!absent.get::<bool>("observed").expect("unseen is not feasible"));
        assert_eq!(absent.get::<String>("pc_hex").expect("high hex"), high);
        let avoid: Table = targets.get("avoid").expect("avoid");
        assert!(
            avoid
                .get::<Table>(1)
                .expect("avoided observation")
                .get::<bool>("observed")
                .expect("observed")
        );
    }
    Ok(())
}

#[test]
fn lua_local_v1_v2_ledgers_reopen_with_seeded_registers() -> Result<(), Box<dyn std::error::Error>> {
    for version in [1, 2] {
        let f = fixture()?;
        let seeded_options = |lua: &Lua| {
            let opts = options(lua, &f, 1);
            let regs = lua.create_table().expect("concrete register seeds");
            regs.set("rax", 5).expect("seed rax");
            opts.set("regs", regs).expect("regs");
            if version == 2 {
                let artifacts: Table = opts.get("artifacts").expect("artifacts");
                artifacts.set("script", "angry.sustained/v2").expect("v2 script");
                artifacts.set("policy", "rank-targets/v1").expect("v2 policy");
            }
            opts
        };
        let (campaign_id, deferred) = {
            let lua = lua();
            let handle = invoke(&lua, "start", &f, seeded_options(&lua)).expect("start Lua local ledger");
            let report: Table = handle.call_method("advance", ()).expect("persist seeded frontier");
            assert_eq!(report.get::<usize>("retired_splits").expect("split"), 1);
            (
                report.get::<String>("campaign_digest").expect("campaign identity"),
                report.get::<usize>("deferred").expect("deferred frontier"),
            )
        };
        assert_eq!(deferred, 2, "v{version} must persist both fork children");
        let ledger_before = std::fs::read(&f.ledger)?;
        let lua = lua();
        for changed_seed in ["cap", "concrete", "symbolic"] {
            let changed = seeded_options(&lua);
            match changed_seed {
                "cap" => changed
                    .get::<Table>("limits")
                    .expect("limits")
                    .set("max_active_states", 2)
                    .expect("changed cap"),
                "concrete" => changed
                    .get::<Table>("regs")
                    .expect("regs")
                    .set("rax", 6)
                    .expect("changed concrete seed"),
                "symbolic" => changed
                    .get::<Table>("symbolic")
                    .expect("symbolic")
                    .set("rdi", 64)
                    .expect("changed symbolic seed"),
                _ => unreachable!(),
            }
            let error = invoke(&lua, "resume", &f, changed).expect_err("changed manifest rejected");
            assert!(
                format!("{error:?}").contains("MismatchedCampaign"),
                "v{version} {changed_seed}: {error:?}"
            );
            assert_eq!(
                std::fs::read(&f.ledger)?,
                ledger_before,
                "rejection must not mutate v{version} ledger"
            );
        }
        let reopened = invoke(&lua, "resume", &f, seeded_options(&lua)).expect("reopen with same Lua API");
        let report: Table = reopened.call_method("report", ()).expect("persisted Lua report");
        assert_eq!(
            report.get::<String>("campaign_digest").expect("campaign identity"),
            campaign_id
        );
        assert_eq!(report.get::<usize>("deferred").expect("deferred frontier"), deferred);
        assert!(
            report
                .get::<Table>("evidence")
                .expect("persisted evidence")
                .get::<Table>("paths")
                .expect("accepted paths")
                .raw_len()
                > 0,
            "v{version} must retain accepted path evidence"
        );
    }
    Ok(())
}
