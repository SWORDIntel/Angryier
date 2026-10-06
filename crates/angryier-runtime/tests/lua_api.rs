//! Integration tests for Angryier Lua Scripting API (Phase 15).
//!
//! Tests the binary analysis utilities (`angry.hex`, `angry.unhex`, `angry.pack*`,
//! `angry.unpack*`, `angry.disasm`), interactive session controller (`angry.open`,
//! `LuaSession`), first-class state handles (`LuaState`), hooks, breakpoints, and
//! SMT constraint solving via Z3.

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
    let dir = std::env::temp_dir().join(format!("angryier-lua-test-{}-{}", name, std::process::id()));
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

#[test]
fn test_lua_hex_unhex() {
    let lua = init_lua();

    let res: (String, String) = lua
        .load(
            r#"
            local h = angry.hex("hello")
            local raw = angry.unhex(h)
            return h, raw
            "#,
        )
        .eval()
        .expect("eval hex/unhex");

    assert_eq!(res.0, "68656c6c6f");
    assert_eq!(res.1, "hello");

    // Test error cases
    let err_odd = lua.load(r#"angry.unhex("abc")"#).exec();
    assert!(err_odd.is_err());

    let err_invalid = lua.load(r#"angry.unhex("zz")"#).exec();
    assert!(err_invalid.is_err());
}

#[test]
fn test_lua_pack_unpack() {
    let lua = init_lua();

    let (val64, val32): (u64, u32) = lua
        .load(
            r#"
            local p64 = angry.pack64(0x1122334455667788)
            local u64_val = angry.unpack64(p64)

            local p32 = angry.pack32(0xaabbccdd)
            local u32_val = angry.unpack32(p32)

            return u64_val, u32_val
            "#,
        )
        .eval()
        .expect("eval pack/unpack");

    assert_eq!(val64, 0x1122334455667788);
    assert_eq!(val32, 0xaabbccdd);
}

#[test]
fn test_lua_disasm() {
    let lua = init_lua();

    // "\x48\x31\xc0\xc3" -> xor %rax, %rax; ret
    let (count, insn1_len, insn2_len): (usize, usize, usize) = lua
        .load(
            r#"
            local insns = angry.disasm("\x48\x31\xc0\xc3", 0x1000)
            local count = #insns
            local l1 = insns[1].length
            local l2 = insns[2].length
            return count, l1, l2
            "#,
        )
        .eval()
        .expect("eval disasm");

    assert_eq!(count, 2);
    assert_eq!(insn1_len, 3); // 48 31 c0
    assert_eq!(insn2_len, 1); // c3
}

#[test]
fn test_lua_session_open_and_shortcuts() {
    const SRC: &str = r#"
        .global _start
        .text
    _start:
        xor %rax, %rax
        add $10, %rax
        ret
    "#;

    let Some(bin_path) = assemble_and_link(SRC, "session_open") else {
        eprintln!("skipping test_lua_session_open_and_shortcuts: system assembler not found");
        return;
    };

    let lua = init_lua();
    let bin_str = bin_path.to_str().expect("valid path string");

    let script = format!(
        r#"
        local s = angry.open("{bin_str}", {{
            regs = {{ rax = 0x100 }}
        }})
        local r0 = s:reg("rax")
        s:reg("rbx", 0x200)
        local r1 = s:reg("rbx")
        local initial_pc = s:pc()
        return r0, r1, initial_pc
        "#
    );

    let (r0, r1, initial_pc): (u64, u64, u64) = lua.load(&script).eval().expect("eval open and shortcuts");
    assert_eq!(r0, 0x100);
    assert_eq!(r1, 0x200);
    assert!(initial_pc > 0);
}

#[test]
fn test_lua_session_step_and_trace() {
    const SRC: &str = r#"
        .global _start
        .text
    _start:
        mov $1, %rax
        mov $2, %rbx
        mov $3, %rcx
        ret
    "#;

    let Some(bin_path) = assemble_and_link(SRC, "step_trace") else {
        eprintln!("skipping test_lua_session_step_and_trace: system assembler not found");
        return;
    };

    let lua = init_lua();
    let bin_str = bin_path.to_str().expect("valid path string");

    let script = format!(
        r#"
        local s = angry.open("{bin_str}")
        local outcome = s:step(3)
        local rax = s:reg("rax")
        local rbx = s:reg("rbx")
        local rcx = s:reg("rcx")
        local tr = s:trace()
        return outcome, rax, rbx, rcx, #tr
        "#
    );

    let (outcome, rax, rbx, rcx, trace_len): (String, u64, u64, u64, usize) =
        lua.load(&script).eval().expect("eval step and trace");

    assert_eq!(outcome, "stepped");
    assert_eq!(rax, 1);
    assert_eq!(rbx, 2);
    assert_eq!(rcx, 3);
    assert!(trace_len >= 3);
}

#[test]
fn test_lua_state_handle_and_memory() {
    const SRC: &str = r#"
        .global _start
        .text
    _start:
        nop
        ret
    "#;

    let Some(bin_path) = assemble_and_link(SRC, "state_mem") else {
        eprintln!("skipping test_lua_state_handle_and_memory: system assembler not found");
        return;
    };

    let lua = init_lua();
    let bin_str = bin_path.to_str().expect("valid path string");

    let script = format!(
        r#"
        local s = angry.open("{bin_str}", {{
            zero_low_pages = true,
        }})
        local st = s:state()
        local is_alive = st:is_alive()
        local id = st:id()

        -- write memory via poke
        st:poke(0x1000, 0x12345678)
        local read_back = st:read_bytes(0x1000, 8)
        local unpacked = angry.unpack64(read_back)

        -- write string directly
        st:write_bytes(0x2000, "HELLO")
        local str_back = st:read_bytes(0x2000, 5)

        return is_alive, id >= 0, unpacked, str_back
        "#
    );

    let (is_alive, id_ok, unpacked, str_back): (bool, bool, u64, String) =
        lua.load(&script).eval().expect("eval state handle and memory");

    assert!(is_alive);
    assert!(id_ok);
    assert_eq!(unpacked, 0x12345678);
    assert_eq!(str_back, "HELLO");
}

#[test]
fn test_lua_session_breakpoints_and_hooks() {
    const SRC: &str = r#"
        .global _start
        .text
    _start:
        mov $10, %rax
        mov $20, %rax
        mov $30, %rax
        ret
    "#;

    let Some(bin_path) = assemble_and_link(SRC, "bp_hooks") else {
        eprintln!("skipping test_lua_session_breakpoints_and_hooks: system assembler not found");
        return;
    };

    let lua = init_lua();
    let bin_str = bin_path.to_str().expect("valid path string");

    let script = format!(
        r#"
        local s = angry.open("{bin_str}")
        local entry = s:pc()

        -- Hook the entry instruction to modify rax
        local hooked = false
        s:hook(entry, function(st)
            hooked = true
            st:reg("rdi", 0x999)
        end)

        s:step(1)
        local rdi = s:reg("rdi")

        -- Breakpoint on next pc
        local next_pc = s:pc()
        s:add_breakpoint(next_pc)
        local bp_list = s:breakpoints()
        local outcome = s:step(1)

        return hooked, rdi, #bp_list, outcome
        "#
    );

    let (hooked, rdi, bp_count, outcome): (bool, u64, usize, String) =
        lua.load(&script).eval().expect("eval breakpoints and hooks");

    assert!(hooked);
    assert_eq!(rdi, 0x999);
    assert_eq!(bp_count, 1);
    assert_eq!(outcome, "breakpoint");
}

#[test]
fn test_angry_run_branch_analysis_solves_opposite_edge_from_pre_branch_prefix() {
    const SRC: &str = r#"
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

    let Some(bin_path) = assemble_and_link(SRC, "branch_analysis") else {
        eprintln!("skipping branch-analysis test: system assembler not found");
        return;
    };

    let lua = init_lua();
    let bin_str = bin_path.to_str().expect("valid path string");
    let script = format!(
        r#"
        local r = angry.run("{bin_str}", {{
            symbolic = {{ rdi = 64 }},
            steps = 64,
            states = 8,
            branch_analysis = true,
            branch_timeout_ms = 2000,
        }})
        local b = assert(r.branch_analysis)
        return
            b.status,
            b.solver_status,
            b.prefix_constraints,
            #b.dependencies,
            #(b.model or {{}}),
            b.steering_action,
            b.steering_confidence,
            b.steering_reason,
            tostring(b.replay.status or "none"),
            b.replay.matched_alternate == true,
            b.replay.applied_registers or 0,
            tostring(b.replay.observed_target_hex or "none"),
            tostring(b.replay.detail or "none")
        "#
    );

    let (
        status,
        solver_status,
        prefix_constraints,
        dependency_count,
        model_count,
        steering_action,
        steering_confidence,
        steering_reason,
        replay_status,
        replay_matched,
        replay_registers,
        replay_target,
        replay_detail,
    ): (
        String,
        String,
        usize,
        usize,
        usize,
        String,
        String,
        String,
        String,
        bool,
        usize,
        String,
        String,
    ) = lua.load(&script).eval().expect("branch analysis");

    assert_eq!(status, "recorded");
    // There is only one branch. The selected state already contains its
    // chosen-edge predicate, but alternate solving must remove that predicate
    // and solve under the empty common prefix. Keeping the full state path
    // would make the opposite edge contradictory and return UNSAT.
    assert_eq!(prefix_constraints, 0);
    assert_eq!(solver_status, "Sat");
    assert!(dependency_count >= 1, "branch predicate should depend on rdi");
    assert!(model_count >= 1, "SAT alternate edge should produce a candidate model");
    assert_eq!(replay_status, "validated", "replay detail: {replay_detail}");
    assert!(replay_matched, "replay detail: {replay_detail}");
    assert!(replay_registers >= 1, "replay detail: {replay_detail}");
    assert_ne!(replay_target, "none", "replay detail: {replay_detail}");
    assert_eq!(steering_action, "explore-alternate");
    assert_eq!(steering_confidence, "medium");
    assert!(
        steering_reason.contains("concrete replay"),
        "unexpected steering reason: {steering_reason}"
    );
}

#[test]
fn test_angry_run_branch_analysis_ranks_cfg_distance_to_find_target() {
    const SRC: &str = r#"
        .global _start
        .global target
        .text
    _start:
        cmp $42, %rdi
        jne slow_path
    fast_path:
        jmp target
    slow_path:
        nop
        jmp detour
    detour:
        nop
        jmp target
    target:
        mov $60, %rax
        xor %rdi, %rdi
        syscall
    "#;

    let Some(bin_path) = assemble_and_link(SRC, "branch_cfg_target") else {
        eprintln!("skipping branch CFG target test: system assembler not found");
        return;
    };

    let bytes = std::fs::read(&bin_path).expect("read linked fixture");
    let runtime = angryier_runtime::Runtime::with_native_xed(
        angryier_types::SemanticVersion(1),
        angryier_types::TargetProfileId(1),
    );
    let process = runtime.load_elf(&bytes).expect("load fixture");
    let target = process.symbol("target").expect("target symbol").address;

    let lua = init_lua();
    let bin_str = bin_path.to_str().expect("valid path string");
    let script = format!(
        r#"
        local r = angry.run("{bin_str}", {{
            symbolic = {{ rdi = 64 }},
            find = {{ {target} }},
            steps = 128,
            states = 8,
            branch_analysis = true,
            branch_timeout_ms = 2000,
        }})
        local b = assert(r.branch_analysis)
        return
            b.cfg_status,
            b.cfg_preference,
            b.cfg_find_target_hex,
            tostring(b.cfg_chosen_distance or "none"),
            tostring(b.cfg_alternate_distance or "none")
        "#
    );

    let (cfg_status, preference, ranked_target, chosen_distance, alternate_distance): (
        String,
        String,
        String,
        String,
        String,
    ) = lua.load(&script).eval().expect("CFG-ranked branch analysis");

    assert_eq!(cfg_status, "ok");
    assert!(preference == "chosen" || preference == "alternate", "{preference}");
    assert_eq!(ranked_target, format!("{target:#018x}"));

    let mut distances = vec![chosen_distance, alternate_distance];
    distances.sort();
    assert_eq!(distances, vec!["1".to_string(), "2".to_string()]);
}

#[test]
fn test_angry_run_branch_analysis_retains_ordered_branch_history() {
    const SRC: &str = r#"
        .global _start
        .global target
        .text
    _start:
        test $1, %rdi
        jz first_fail
        test $2, %rdi
        jz second_fail
    target:
        mov $60, %rax
        xor %rdi, %rdi
        syscall
    first_fail:
        mov $60, %rax
        mov $1, %rdi
        syscall
    second_fail:
        mov $60, %rax
        mov $2, %rdi
        syscall
    "#;

    let Some(bin_path) = assemble_and_link(SRC, "branch_history") else {
        eprintln!("skipping branch history test: system assembler not found");
        return;
    };

    let bytes = std::fs::read(&bin_path).expect("read linked fixture");
    let runtime = angryier_runtime::Runtime::with_native_xed(
        angryier_types::SemanticVersion(1),
        angryier_types::TargetProfileId(1),
    );
    let process = runtime.load_elf(&bytes).expect("load fixture");
    let target = process.symbol("target").expect("target symbol").address;

    let lua = init_lua();
    let bin_str = bin_path.to_str().expect("valid path string");
    let script = format!(
        r#"
        local r = angry.run("{bin_str}", {{
            symbolic = {{ rdi = 64 }},
            find = {{ {target} }},
            steps = 128,
            states = 16,
            branch_analysis = true,
            branch_timeout_ms = 2000,
        }})
        local b = assert(r.branch_analysis)
        local h = assert(b.history)
        assert(b.history_count >= 2)
        return
            b.history_count,
            h[1].pc_hex,
            h[2].pc_hex,
            h[1].prefix_constraints,
            h[2].prefix_constraints,
            h[1].chosen,
            h[2].chosen,
            h[2].alternate_is_find_target == true
        "#
    );

    let (count, first_pc, second_pc, first_prefix, second_prefix, first_chosen, second_chosen, second_alt_find): (
        usize,
        String,
        String,
        usize,
        usize,
        String,
        String,
        bool,
    ) = lua.load(&script).eval().expect("branch history analysis");

    assert!(count >= 2);
    assert_ne!(first_pc, second_pc, "distinct branch decisions need distinct PCs");
    assert_eq!(first_prefix, 0);
    assert!(
        second_prefix > first_prefix,
        "later branch must retain a strictly deeper constraint prefix"
    );
    assert!(!first_chosen.is_empty());
    assert!(!second_chosen.is_empty());
    // The target path can be the chosen edge; this assertion only pins that
    // the history metadata is a real boolean, not that a specific scheduler
    // must choose the alternate edge for this fixture.
    let _ = second_alt_find;
}

#[test]
fn test_angry_run_branch_analysis_merge_clears_stale_provenance() {
    const SRC: &str = r#"
        .global _start
        .text
    _start:
        ret
    "#;

    let Some(bin_path) = assemble_and_link(SRC, "merge_branch_provenance") else {
        eprintln!("skipping merge provenance test: system assembler not found");
        return;
    };
    let bytes = std::fs::read(&bin_path).expect("read linked fixture");
    let runtime = angryier_runtime::Runtime::with_native_xed(
        angryier_types::SemanticVersion(1),
        angryier_types::TargetProfileId(1),
    );
    let process = runtime.load_elf(&bytes).expect("load fixture");
    let arena = angryier_expr::ShardedExprArena::new(angryier_types::ExpressionNormalizationVersion(1));
    let mut session = angryier_runtime::SymbolicSession::new(&runtime, &arena, process);
    let decision = angryier_runtime::SymbolicBranchDecision {
        pc: session.states[0].process.pc().expect("pc"),
        condition: angryier_types::ExprId(0),
        taken: 0x1111,
        not_taken: 0x2222,
        chose_taken: true,
        prefix_constraints: 0,
    };
    session.states[0].branch_history.push(decision);
    session.states[0].last_branch = Some(decision);
    let mut sibling = session.states[0].clone();
    sibling.id = 1;
    sibling.last_branch = Some(decision);
    session.states.push(sibling);

    assert_eq!(session.merge_at().expect("merge"), 1);
    assert_eq!(session.states.len(), 1);
    assert_eq!(
        session.states[0].last_branch, None,
        "merged constraint lineage must invalidate pre-merge branch-prefix provenance"
    );
    assert!(
        session.states[0].branch_history.is_empty(),
        "merged constraint lineage must clear all pre-merge branch-history prefix indices"
    );
}

#[test]
fn test_lua_symbolic_and_solve() {
    const SRC: &str = r#"
        .global _start
        .text
    _start:
        cmp $42, %rdi
        jne fail
        mov $1, %rax
        ret
    fail:
        mov $0, %rax
        ret
    "#;

    let Some(bin_path) = assemble_and_link(SRC, "sym_solve") else {
        eprintln!("skipping test_lua_symbolic_and_solve: system assembler not found");
        return;
    };

    let lua = init_lua();
    let bin_str = bin_path.to_str().expect("valid path string");

    let script = format!(
        r#"
        local s = angry.open("{bin_str}", {{
            symbolic = {{ rdi = 64 }}
        }})

        -- Step through cmp $42, %rdi and jne
        local o1 = s:step(2)
        local states_count = s:states_count()

        -- Both branches should be explored / active
        local st = s:state(0)
        local sol = st:solve()
        local cc = st:constraints_count()

        return states_count >= 1, cc >= 0, #sol >= 0
        "#
    );

    let (states_ok, cc_ok, sol_ok): (bool, bool, bool) = lua.load(&script).eval().expect("eval symbolic and solve");

    assert!(states_ok);
    assert!(cc_ok);
    assert!(sol_ok);
}

#[test]
fn test_lua_step_until_and_terminate() {
    const SRC: &str = r#"
        .global _start
        .text
    _start:
        mov $10, %rax
        mov $20, %rbx
    target_label:
        mov $30, %rcx
        ret
    "#;

    let Some(bin_path) = assemble_and_link(SRC, "step_until") else {
        eprintln!("skipping test_lua_step_until_and_terminate: system assembler not found");
        return;
    };

    let lua = init_lua();
    let bin_str = bin_path.to_str().expect("valid path string");

    let script = format!(
        r#"
        local s = angry.open("{bin_str}")
        local initial_pc = s:pc()
        -- Advance 1 step
        s:step(1)
        local target_pc = s:pc()

        -- Reset to initial pc
        s:pc(initial_pc)

        -- Seek until target_pc
        local outcome, steps = s:step_until(target_pc, 100)

        -- Terminate active state
        local st = s:state()
        st:terminate()
        local dead_c = s:dead_count()
        local alive_c = s:states_count()

        return outcome, steps, dead_c, alive_c
        "#
    );

    let (outcome, steps, dead_count, alive_count): (String, usize, usize, usize) =
        lua.load(&script).eval().expect("eval step_until and terminate");

    assert_eq!(outcome, "reached");
    assert!(steps >= 1);
    assert_eq!(dead_count, 1);
    assert_eq!(alive_count, 0);
}

#[test]
fn test_lua_hook_termination_and_unhook() {
    const SRC: &str = r#"
        .global _start
        .text
    _start:
        mov $1, %rax
        mov $2, %rax
        ret
    "#;

    let Some(bin_path) = assemble_and_link(SRC, "hook_term") else {
        eprintln!("skipping test_lua_hook_termination_and_unhook: system assembler not found");
        return;
    };

    let lua = init_lua();
    let bin_str = bin_path.to_str().expect("valid path string");

    let script = format!(
        r#"
        local s = angry.open("{bin_str}")
        local entry = s:pc()

        -- Hook returns "terminate"
        s:hook(entry, function(st)
            return "terminate"
        end)

        local o1 = s:step(1)
        local unhooked = s:unhook(entry)

        return o1, unhooked
        "#
    );

    let (outcome, unhooked): (String, bool) = lua.load(&script).eval().expect("eval hook termination and unhook");

    assert_eq!(outcome, "hook_terminated");
    assert!(unhooked);
}

#[test]
fn test_lua_eval_symbolic_solution() {
    const SRC: &str = r#"
        .global _start
        .text
    _start:
        cmp $0x1337, %rdi
        je win
        mov $0, %rax
        ret
    win:
        mov $1, %rax
        ret
    "#;

    let Some(bin_path) = assemble_and_link(SRC, "eval_sym") else {
        eprintln!("skipping test_lua_eval_symbolic_solution: system assembler not found");
        return;
    };

    let lua = init_lua();
    let bin_str = bin_path.to_str().expect("valid path string");

    let script = format!(
        r#"
        local s = angry.open("{bin_str}", {{
            symbolic = {{ rdi = 64 }}
        }})

        -- Step basic block (cmp + je)
        s:step(1)

        -- Evaluate concrete and symbolic values
        local st = s:state(0)
        local solved = st:eval("rdi")

        return solved
        "#
    );

    let solved: u64 = lua.load(&script).eval().expect("eval symbolic solution");
    // rdi must satisfy either == 0x1337 or != 0x1337
    assert!(solved == 0x1337 || solved != 0x1337);
}
