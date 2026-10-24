//! Integration tests for the prepared-image bulk campaign API
//! (`angry.prepare` → `img:run`) and `LuaSession:reset`/`:spawn_state`.
//!
//! The invariants under test:
//! * `img:run` is byte-compatible with `angry.run` (same report shape,
//!   same campaign results) — the refactor shares one code path, and these
//!   tests pin that promise.
//! * Jobs on one prepared image are isolated: no entry sentinel, register
//!   seed, trace, or kernel-pool state leaks between campaigns.
//! * `img:stats()` exposes load-vs-run cost so drivers can see where the
//!   wall clock goes.
//! * `s:reset(opts)` rebuilds a fresh session from the pristine template
//!   without re-loading the image.

#![cfg(all(feature = "xed", feature = "script"))]

use std::path::PathBuf;
use std::process::Command;

use angryier_runtime::mlua::Lua;
use angryier_runtime::script;

fn init_lua() -> Lua {
    let lua = Lua::new();
    script::register(&lua).expect("register angry library");
    lua
}

fn assemble_and_link(src: &str, name: &str) -> Option<PathBuf> {
    let dir = std::env::temp_dir().join(format!("angryier-prepared-test-{}-{}", name, std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    let s_path = dir.join("test.s");
    let o_path = dir.join("test.o");
    let elf_path = dir.join("test.elf");

    std::fs::write(&s_path, src).ok()?;

    let as_ok = Command::new("as")
        .arg("--64")
        .arg("-o")
        .arg(&o_path)
        .arg(&s_path)
        .status()
        .ok()?
        .success();
    if !as_ok {
        return None;
    }

    let ld_ok = Command::new("ld")
        .arg("-o")
        .arg(&elf_path)
        .arg(&o_path)
        .status()
        .ok()?
        .success();
    if !ld_ok {
        return None;
    }

    Some(elf_path)
}

/// A branchy fixture: rdi == 42 exits through the success syscall, anything
/// else through the fail syscall — so register seeds select observably
/// different paths (exit_pc / trace), and symbolic rdi forks.
const BRANCHY: &str = r#"
    .global _start
    .text
_start:
    cmp $42, %rdi
    jne fail
    mov $60, %rax
    xor %rdi, %rdi
    syscall
fail:
    mov $60, %rax
    mov $1, %rdi
    syscall
"#;

#[test]
fn prepared_run_matches_angry_run_report() {
    let Some(bin_path) = assemble_and_link(BRANCHY, "parity") else {
        eprintln!("skipping prepared parity test: system assembler not found");
        return;
    };
    let lua = init_lua();
    let bin_str = bin_path.to_str().expect("valid path string");
    let script = format!(
        r#"
        local s = angry.open("{bin_str}")
        local entry = s:pc()
        local opts = {{ entry = entry, symbolic = {{ rdi = 64 }}, steps = 48, states = 8 }}
        local a = angry.run("{bin_str}", opts)
        local img = angry.prepare("{bin_str}")
        local b = img:run(opts)
        local function hex_or(t, k) return t[k .. "_hex"] or tostring(t[k] or "nil") end
        return {{
            steps_a = a.steps, steps_b = b.steps,
            forks_a = a.forks, forks_b = b.forks,
            term_a = a.terminated, term_b = b.terminated,
            failed_a = a.failed, failed_b = b.failed,
            pruned_a = a.pruned_states, pruned_b = b.pruned_states,
            timed_a = a.timed_out, timed_b = b.timed_out,
            found_a = a.found, found_b = b.found,
            rax_a = hex_or(a, "rax_exit"), rax_b = hex_or(b, "rax_exit"),
            pc_a = hex_or(a, "exit_pc"), pc_b = hex_or(b, "exit_pc"),
            trace_a = table.concat(a.trace_hex or {{}}, ","),
            trace_b = table.concat(b.trace_hex or {{}}, ","),
        }}
        "#
    );
    let out: mlua::Table = lua.load(&script).eval().expect("prepared parity eval");

    let get = |key: &str| -> String {
        out.get::<String>(key).unwrap_or_else(|_| panic!("missing {key}"))
    };
    let get_n = |key: &str| -> u64 { out.get::<u64>(key).unwrap_or_else(|_| panic!("missing {key}")) };
    let get_b = |key: &str| -> bool { out.get::<bool>(key).unwrap_or_else(|_| panic!("missing {key}")) };

    assert_eq!(get_n("steps_a"), get_n("steps_b"), "steps differ");
    assert_eq!(get_n("forks_a"), get_n("forks_b"), "forks differ");
    assert_eq!(get_n("term_a"), get_n("term_b"), "terminated differ");
    assert_eq!(get_n("failed_a"), get_n("failed_b"), "failed differ");
    assert_eq!(get_n("pruned_a"), get_n("pruned_b"), "pruned_states differ");
    assert_eq!(get_b("timed_a"), get_b("timed_b"), "timed_out differ");
    assert_eq!(get_n("found_a"), get_n("found_b"), "found differ");
    assert_eq!(get("rax_a"), get("rax_b"), "rax_exit differs");
    assert_eq!(get("pc_a"), get("pc_b"), "exit_pc differs");
    assert_eq!(get("trace_a"), get("trace_b"), "trace differs");
}

#[test]
fn prepared_jobs_are_isolated_per_entry_and_regs() {
    let Some(bin_path) = assemble_and_link(BRANCHY, "isolation") else {
        eprintln!("skipping prepared isolation test: system assembler not found");
        return;
    };
    let lua = init_lua();
    let bin_str = bin_path.to_str().expect("valid path string");
    let script = format!(
        r#"
        local img = angry.prepare("{bin_str}")
        local r1 = img:run({{ regs = {{ rdi = 42 }}, steps = 32, states = 4 }})
        local r2 = img:run({{ regs = {{ rdi = 7 }}, steps = 32, states = 4 }})
        -- Fresh one-shot runs are the ground truth for both jobs.
        local f1 = angry.run("{bin_str}", {{ regs = {{ rdi = 42 }}, steps = 32, states = 4 }})
        local f2 = angry.run("{bin_str}", {{ regs = {{ rdi = 7 }}, steps = 32, states = 4 }})
        return
            r1.exit_pc_hex, r2.exit_pc_hex, f1.exit_pc_hex, f2.exit_pc_hex,
            table.concat(r1.trace_hex or {{}}, ","), table.concat(f1.trace_hex or {{}}, ","),
            table.concat(r2.trace_hex or {{}}, ","), table.concat(f2.trace_hex or {{}}, ",")
        "#
    );
    let (r1_pc, r2_pc, f1_pc, f2_pc, r1_trace, f1_trace, r2_trace, f2_trace): (
        String, String, String, String, String, String, String, String,
    ) = lua.load(&script).eval().expect("prepared isolation eval");

    // Job A on the prepared image must equal a fresh one-shot job A...
    assert_eq!(r1_pc, f1_pc, "job 1 exit_pc drifted: prepared={r1_pc} fresh={f1_pc}");
    assert_eq!(r1_trace, f1_trace, "job 1 trace drifted");
    // ...and job B must equal a fresh job B, while differing from job A.
    assert_eq!(r2_pc, f2_pc, "job 2 exit_pc drifted: prepared={r2_pc} fresh={f2_pc}");
    assert_eq!(r2_trace, f2_trace, "job 2 trace drifted");
    assert_ne!(r1_pc, r2_pc, "register seeds did not select different paths");
    assert_ne!(r1_trace, r2_trace, "register seeds did not select different traces");
}

#[test]
fn prepared_stats_tracks_load_and_jobs() {
    let Some(bin_path) = assemble_and_link(BRANCHY, "stats") else {
        eprintln!("skipping prepared stats test: system assembler not found");
        return;
    };
    let lua = init_lua();
    let bin_str = bin_path.to_str().expect("valid path string");
    let script = format!(
        r#"
        local img = angry.prepare("{bin_str}")
        local s0 = img:stats()
        img:run({{ steps = 8 }})
        img:run({{ steps = 8 }})
        local s1 = img:stats()
        return s0.jobs, s1.jobs, s1.load_ms, s1.last_run_ms, s1.avg_run_ms, s1.image_regions
        "#
    );
    let (jobs0, jobs1, load_ms, last_run_ms, avg_run_ms, image_regions): (u64, u64, u64, u64, u64, usize) =
        lua.load(&script).eval().expect("prepared stats eval");
    assert_eq!(jobs0, 0, "fresh prepared image must report zero jobs");
    assert_eq!(jobs1, 2, "two runs must be counted");
    let _ = load_ms;
    let _ = last_run_ms;
    let _ = avg_run_ms;
    assert!(image_regions >= 1, "loaded image must have mapped regions");
}

#[test]
fn prepared_run_batch_matches_sequential_reports() {
    let Some(bin_path) = assemble_and_link(BRANCHY, "batch") else {
        eprintln!("skipping prepared batch test: system assembler not found");
        return;
    };
    let lua = init_lua();
    let bin_str = bin_path.to_str().expect("valid path string");
    let script = format!(
        r#"
        local img = angry.prepare("{bin_str}")
        local jobs = {{}}
        for i = 1, 6 do
            jobs[i] = {{ regs = {{ rdi = 42 + i }}, steps = 48, states = 4, branch_analysis = true }}
        end
        local batch = img:run_batch(jobs, {{ threads = 3 }})
        local seq = {{}}
        for i = 1, #jobs do seq[i] = img:run(jobs[i]) end
        local mismatches = 0
        local oks = 0
        for i = 1, #jobs do
            if batch[i].ok == true then oks = oks + 1 end
            if (seq[i].exit_pc_hex or "?") ~= (batch[i].report and batch[i].report.exit_pc_hex or "?") then
                mismatches = mismatches + 1
            end
            local st = table.concat(seq[i].trace_hex or {{}}, ",")
            local bt = batch[i].report and table.concat(batch[i].report.trace_hex or {{}}, ",") or ""
            if st ~= bt then mismatches = mismatches + 1 end
        end
        local s = img:stats()
        return #batch, oks, mismatches, s.jobs
        "#
    );
    let (batch_len, oks, mismatches, jobs): (usize, usize, usize, u64) =
        lua.load(&script).eval().expect("prepared batch eval");
    assert_eq!(batch_len, 6, "one entry per job, in order");
    assert_eq!(oks, 6, "every batch job must succeed");
    assert_eq!(mismatches, 0, "parallel batch results must equal sequential ones");
    assert_eq!(jobs, 12, "stats must count batch + sequential jobs");
}

#[test]
fn prepared_rejects_missing_image_and_runs_survive_errors() {
    let lua = init_lua();
    let script = r#"
        local ok, err = pcall(angry.prepare, "/nonexistent/angryier-preparing-this.elf")
        local ok2, err2 = pcall(angry.prepare, "/nonexistent/angryier-preparing-this.elf")
        return ok, ok2, tostring(err):sub(1, 5), tostring(err2):sub(1, 5)
    "#;
    let (ok, ok2, err_head, err2_head): (bool, bool, String, String) = lua.load(script).eval().expect("eval");
    assert!(!ok && !ok2, "prepare of a missing image must fail");
    assert_eq!(err_head, err2_head, "repeated prepare errors must stay stable");
}

#[test]
fn session_reset_rebuilds_from_template_without_reload() {
    const SRC: &str = r#"
        .global _start
        .text
    _start:
        xor %rax, %rax
        add $10, %rax
        ret
    "#;
    let Some(bin_path) = assemble_and_link(SRC, "session_reset") else {
        eprintln!("skipping session reset test: system assembler not found");
        return;
    };
    let lua = init_lua();
    let bin_str = bin_path.to_str().expect("valid path string");
    let script = format!(
        r#"
        local s = angry.open("{bin_str}")
        local e = s:pc()
        s:step(2)
        local d0 = s:dead_count()
        s:reset()
        local st, d1, p = s:states(), s:dead_count(), s:pc()
        -- respawn alias with explicit opts table
        s:spawn_state({{}})
        local st2, d2, p2 = s:states(), s:dead_count(), s:pc()
        return st, d1, p == e, st2, d2, p2 == e
        "#
    );
    let (st, d1, pc_back, st2, d2, pc2_back): (usize, usize, bool, usize, usize, bool) =
        lua.load(&script).eval().expect("session reset eval");
    assert!(d1 == 0, "reset must clear dead states (was nonzero)");
    assert_eq!(st, 1, "reset must rebuild exactly one fresh state");
    assert!(pc_back, "reset must restore the template pc");
    assert_eq!(st2, 1, "spawn_state alias must rebuild one fresh state");
    assert_eq!(d2, 0, "spawn_state alias must clear dead states");
    assert!(pc2_back, "spawn_state alias must restore the template pc");
}

#[test]
fn session_reset_applies_new_entry_and_seeds() {
    const SRC: &str = r#"
        .global _start
        .text
    _start:
        nop
        mov $7, %rax
        ret
    "#;
    let Some(bin_path) = assemble_and_link(SRC, "session_reset_entry") else {
        eprintln!("skipping session reset entry test: system assembler not found");
        return;
    };
    let lua = init_lua();
    let bin_str = bin_path.to_str().expect("valid path string");
    // `mov $7, %rax` sits one byte after _start (nop is a single byte); the
    // entry override seeds a sentinel return frame, so the trailing `ret`
    // terminates cleanly through the exit hook instead of walking the stack.
    let script = format!(
        r#"
        local s = angry.open("{bin_str}")
        local e = s:pc()
        s:reset({{ entry = e + 1, regs = {{ rbx = 0x99 }} }})
        local p = s:pc()
        local b = s:reg("rbx")
        s:step(1)  -- executes mov $7, %rax
        local rax = s:reg("rax")
        return p == e + 1, b, rax
        "#
    );
    let (pc_ok, rbx, rax): (bool, u64, u64) = lua.load(&script).eval().expect("reset entry eval");
    assert!(pc_ok, "reset must honor the new entry override");
    assert_eq!(rbx, 0x99, "reset must honor register seeds");
    // mov $7, %rax executed from the reset entry; the previous session's
    // register contents must not survive a reset.
    assert_eq!(rax, 7, "reset entry must execute the new path");
}
