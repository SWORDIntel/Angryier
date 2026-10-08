//! API stability test suite for the top-level `angryier` crate.
//!
//! Validates:
//! - Constructing `RunOptions` with various settings: `steps`, `max_states`,
//!   `find`, `avoid`, `entry`, `regs`, `symbolic`, `poke`, `solve`.
//! - Creating an `Engine`, loading images (`min_elf`, `symbolic_branch`,
//!   `data_poke`, and in-memory synthetic ELF bytes), creating a `Session`.
//! - Stepping state 0 (`session.step()`), inspecting `pc()`, `states()`,
//!   reading concrete registers (`session.reg("rax")`), inspecting all 16 GPRs.
//! - Marking symbolic registers (`session.symbolic("rdi", 64)`), checking validation
//!   errors (non-64 bit width returning `ApiError::InvalidArgument`, unknown register name).
//! - Running full exploration with `find`/`avoid` policy and verifying `RunReport`
//!   outcomes (`steps`, `forks`, `live_states`, `dead_states`, `found_pcs`, etc.).
//! - Executing solving (`options.solve = true`) and checking input generation.
//! - Concrete seeding with `regs`, memory write with `poke`, entry override with `entry`.
//! - Exploration limits: `steps` budget exhaustion and `max_states` cap pruning.

use std::path::PathBuf;

use angryier::{
    ApiError, DEFAULT_MAX_STATES, DEFAULT_STEPS, DEFAULT_TIMEOUT_SECS, Engine, GPRS, ImageKind, RunOptions,
    SYMBOLIC_GPR_WIDTH, StepKind,
};

/// Resolves a test fixture path using strictly relative or dynamic paths.
fn fixture_path(name: &str) -> PathBuf {
    let candidate1 = PathBuf::from("tests/fixtures").join(name);
    if candidate1.is_file() {
        return candidate1;
    }
    let candidate2 = PathBuf::from("crates/angryier/tests/fixtures").join(name);
    if candidate2.is_file() {
        return candidate2;
    }
    // As a fallback, try relative to CARGO_MANIFEST_DIR if set
    if let Ok(dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let candidate3 = PathBuf::from(dir).join("tests/fixtures").join(name);
        if candidate3.is_file() {
            return candidate3;
        }
    }
    panic!("fixture {name} not found in search paths");
}

/// Optional driver corpus fixture resolver (skipped when absent).
fn harness_fixture(name: &str) -> Option<PathBuf> {
    let home = std::env::var("HOME").ok()?;
    let path = PathBuf::from(home)
        .join("Documents/byovd-harness/ghidra_pipeline/fixtures/bin")
        .join(name);
    path.is_file().then_some(path)
}

/// Pure-Rust synthetic ELF64 binary generator.
///
/// Constructs a hermetic, statically-loadable ELF64 executable in memory
/// containing a single `PT_LOAD` RX segment mapped at `entry`.
fn make_synthetic_elf(entry: u64, code: &[u8]) -> Vec<u8> {
    let ehdr_size = 64usize;
    let phdr_size = 56usize;
    let phnum = 1usize;
    let phoff = ehdr_size;
    let file_data_offset = ehdr_size + phnum * phdr_size; // 120

    let mut binary = Vec::new();
    // 0..4: magic
    binary.extend_from_slice(&[0x7f, b'E', b'L', b'F']);
    // 4: class = 2 (64-bit)
    binary.push(2);
    // 5: data = 1 (LSB)
    binary.push(1);
    // 6: version = 1
    binary.push(1);
    // 7..16: padding
    binary.extend_from_slice(&[0u8; 9]);
    // 16..18: e_type (2 = ET_EXEC)
    binary.extend_from_slice(&2u16.to_le_bytes());
    // 18..20: e_machine = EM_X86_64 (62)
    binary.extend_from_slice(&62u16.to_le_bytes());
    // 20..24: e_version = 1
    binary.extend_from_slice(&1u32.to_le_bytes());
    // 24..32: e_entry
    binary.extend_from_slice(&entry.to_le_bytes());
    // 32..40: e_phoff
    binary.extend_from_slice(&(phoff as u64).to_le_bytes());
    // 40..48: e_shoff = 0
    binary.extend_from_slice(&0u64.to_le_bytes());
    // 48..52: e_flags = 0
    binary.extend_from_slice(&0u32.to_le_bytes());
    // 52..54: e_ehsize = 64
    binary.extend_from_slice(&(ehdr_size as u16).to_le_bytes());
    // 54..56: e_phentsize = 56
    binary.extend_from_slice(&(phdr_size as u16).to_le_bytes());
    // 56..58: e_phnum
    binary.extend_from_slice(&(phnum as u16).to_le_bytes());
    // 58..60: e_shentsize = 0
    binary.extend_from_slice(&0u16.to_le_bytes());
    // 60..62: e_shnum = 0
    binary.extend_from_slice(&0u16.to_le_bytes());
    // 62..64: e_shstrndx = 0
    binary.extend_from_slice(&0u16.to_le_bytes());

    // Program header (PT_LOAD, flags: PF_R | PF_W | PF_X = 7)
    binary.extend_from_slice(&1u32.to_le_bytes()); // p_type = PT_LOAD
    binary.extend_from_slice(&7u32.to_le_bytes()); // p_flags
    binary.extend_from_slice(&(file_data_offset as u64).to_le_bytes()); // p_offset
    binary.extend_from_slice(&entry.to_le_bytes()); // p_vaddr
    binary.extend_from_slice(&entry.to_le_bytes()); // p_paddr
    binary.extend_from_slice(&(code.len() as u64).to_le_bytes()); // p_filesz
    binary.extend_from_slice(&(code.len() as u64).to_le_bytes()); // p_memsz
    binary.extend_from_slice(&0x1000u64.to_le_bytes()); // p_align

    // Code payload
    binary.extend_from_slice(code);
    binary
}

#[test]
fn test_run_options_construction_and_defaults() {
    let def = RunOptions::default();
    assert_eq!(def.steps, DEFAULT_STEPS);
    assert_eq!(def.max_states, DEFAULT_MAX_STATES);
    assert_eq!(DEFAULT_TIMEOUT_SECS, angryier_runtime::DEFAULT_RUN_TIMEOUT_SECS);
    assert_eq!(DEFAULT_TIMEOUT_SECS, 120);
    assert!(def.find.is_empty());
    assert!(def.avoid.is_empty());
    assert!(def.entry.is_none());
    assert!(def.regs.is_empty());
    assert!(def.symbolic.is_empty());
    assert!(def.poke.is_empty());
    assert!(def.symbolic_memory.is_empty());
    assert!(!def.solve);
    assert!(!def.dynamic);
    assert!(def.argv0.is_none());
    assert!(def.files.is_empty());
    assert!(def.contents.is_empty());
    assert!(!def.zero_low_pages);

    let custom = RunOptions {
        symbolic: vec![("rax".to_string(), SYMBOLIC_GPR_WIDTH)],
        regs: vec![("rbx".to_string(), 0x1234), ("rcx".to_string(), 0x5678)],
        poke: vec![(0x402000, 0xcafe_babe)],
        symbolic_memory: vec![(0x403000, 32)],
        find: vec![0x401006],
        avoid: vec![0x401012],
        steps: 50,
        max_states: 4,
        solve: true,
        dynamic: false,
        entry: Some(0x401000),
        argv0: Some(16),
        files: vec!["/dev/urandom".to_string()],
        contents: vec![("test.txt".to_string(), vec![0x41, 0x42])],
        zero_low_pages: true,
    };

    assert_eq!(custom.steps, 50);
    assert_eq!(custom.max_states, 4);
    assert_eq!(custom.find, vec![0x401006]);
    assert_eq!(custom.avoid, vec![0x401012]);
    assert_eq!(custom.entry, Some(0x401000));
    assert_eq!(custom.regs.len(), 2);
    assert_eq!(custom.symbolic, vec![("rax".to_string(), 64)]);
    assert_eq!(custom.poke, vec![(0x402000, 0xcafe_babe)]);
    assert!(custom.solve);
    assert!(custom.zero_low_pages);

    // Verify Clone and Debug implementations.
    let cloned = custom.clone();
    assert_eq!(cloned.steps, 50);
    let debug_str = format!("{custom:?}");
    assert!(debug_str.contains("RunOptions"));
    assert!(debug_str.contains("3405691582") || debug_str.contains("poke"));
}

#[test]
fn test_engine_load_synthetic_and_fixtures() {
    let engine = Engine::new().expect("Engine construction must succeed");

    // Load fixture min_elf
    let min_path = fixture_path("min_elf");
    let image_min = engine.load(&min_path).expect("min_elf fixture loads");
    assert_eq!(image_min.kind(), ImageKind::Elf);
    let dbg = format!("{image_min:?}");
    assert!(dbg.contains("Elf"), "got {dbg}");

    // Load fixture symbolic_branch
    let branch_path = fixture_path("symbolic_branch");
    let image_branch = engine.load(&branch_path).expect("symbolic_branch fixture loads");
    assert_eq!(image_branch.kind(), ImageKind::Elf);

    // Load hermetic synthetic ELF bytes from disk
    // Instruction: mov eax, 60; xor edi, edi; syscall (exit 0)
    let payload = [0xB8, 0x3C, 0x00, 0x00, 0x00, 0x31, 0xFF, 0x0F, 0x05];
    let elf_bytes = make_synthetic_elf(0x401000, &payload);
    let temp_path = std::env::temp_dir().join(format!("angryier_synthetic_{}.elf", std::process::id()));
    std::fs::write(&temp_path, &elf_bytes).expect("write temp synthetic elf");

    let synth_image = engine.load(&temp_path).expect("synthetic elf loads");
    assert_eq!(synth_image.kind(), ImageKind::Elf);
    let _ = std::fs::remove_file(&temp_path);

    // Load dynamic rejects non-ELF or missing files
    let bad_path = std::env::temp_dir().join("angryier_nonexistent_xyz.bin");
    assert!(matches!(engine.load(&bad_path), Err(ApiError::Io(_))));
    assert!(matches!(engine.load_dynamic(&bad_path), Err(ApiError::Io(_))));
}

#[test]
fn test_session_stepping_registers_and_states() {
    let engine = Engine::new().expect("engine");
    let image = engine.load(fixture_path("min_elf")).expect("load min_elf");
    let mut session = engine.open(&image).expect("open session");

    // Initial state validation
    assert_eq!(session.states(), 1, "session starts with 1 live state");
    assert_eq!(session.pc().expect("initial pc"), 0x401000);

    // Step 1: mov $60, %rax (48 c7 c0 3c 00 00 00)
    let outcome1 = session.step().expect("step 1");
    assert_eq!(outcome1, StepKind::Stepped);
    assert_eq!(session.pc().expect("pc after step 1"), 0x401007);
    assert_eq!(session.reg("rax"), Some(60));
    assert_eq!(session.states(), 1);

    // Step 2: xor %rdi, %rdi (48 31 ff)
    let outcome2 = session.step().expect("step 2");
    assert_eq!(outcome2, StepKind::Stepped);
    assert_eq!(session.pc().expect("pc after step 2"), 0x40100a);
    assert_eq!(session.reg("rdi"), Some(0));
    assert_eq!(session.states(), 1);

    // Step 3: syscall (exit 0)
    let outcome3 = session.step().expect("step 3");
    assert_eq!(outcome3, StepKind::Terminated);

    // Validate that all standard 64-bit GPR names are inspectable
    for &reg_name in &GPRS {
        assert!(session.reg(reg_name).is_some(), "GPR '{reg_name}' should be readable");
    }

    // Invalid register names return None
    assert_eq!(session.reg("not_a_register"), None);
    assert_eq!(session.reg("rip"), None);
    assert_eq!(session.reg(""), None);
}

#[test]
fn test_symbolic_registration_and_validation_errors() {
    let engine = Engine::new().expect("engine");
    let image = engine.load(fixture_path("min_elf")).expect("load min_elf");
    let mut session = engine.open(&image).expect("open session");

    // Valid 64-bit marks are accepted
    session.symbolic("rdi", 64).expect("64-bit rdi mark accepted");
    session.symbolic("rax", 64).expect("64-bit rax mark accepted");
    session
        .symbolic("rcx", SYMBOLIC_GPR_WIDTH)
        .expect("constant width accepted");

    // Sub-64-bit widths must be rejected with ApiError::InvalidArgument
    for bad_width in [8, 16, 32, 128] {
        let err = session
            .symbolic("rdx", bad_width)
            .expect_err("non-64-bit width must fail");
        match err {
            ApiError::InvalidArgument(msg) => {
                assert!(msg.contains("must be 64 bits"), "unexpected error message: {msg}");
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    // Unknown register names must be rejected with ApiError::InvalidArgument
    for bad_name in ["unknown_reg", "rip", "flags", "", "xmm0"] {
        let err = session.symbolic(bad_name, 64).expect_err("bad register name must fail");
        match err {
            ApiError::InvalidArgument(msg) => {
                assert!(msg.contains("bad register"), "unexpected error message: {msg}");
            }
            other => panic!("expected InvalidArgument, got {other:?}"),
        }
    }

    // Validation errors when supplied through RunOptions on engine.run and session.run
    let bad_opts_width = RunOptions {
        symbolic: vec![("rax".to_string(), 32)],
        ..RunOptions::default()
    };
    assert!(matches!(
        engine.run(&image, &bad_opts_width),
        Err(ApiError::InvalidArgument(_))
    ));
    assert!(matches!(
        session.run(&bad_opts_width),
        Err(ApiError::InvalidArgument(_))
    ));

    let bad_opts_reg = RunOptions {
        symbolic: vec![("invalid".to_string(), 64)],
        ..RunOptions::default()
    };
    assert!(matches!(
        engine.run(&image, &bad_opts_reg),
        Err(ApiError::InvalidArgument(_))
    ));
    assert!(matches!(session.run(&bad_opts_reg), Err(ApiError::InvalidArgument(_))));

    let bad_opts_seed = RunOptions {
        regs: vec![("invalid".to_string(), 42)],
        ..RunOptions::default()
    };
    assert!(matches!(
        engine.run(&image, &bad_opts_seed),
        Err(ApiError::InvalidArgument(_))
    ));
    assert!(matches!(session.run(&bad_opts_seed), Err(ApiError::InvalidArgument(_))));
}

#[test]
fn test_exploration_find_avoid_policy() {
    let engine = Engine::new().expect("engine");
    let image = engine
        .load(fixture_path("symbolic_branch"))
        .expect("load symbolic_branch");

    // symbolic_branch layout:
    // 0x401000: cmp $42, %rax
    // 0x401004: jne 0x401012 (fail_path)
    // 0x401006: ok_path (mov $60, %rax; xor %rdi, %rdi; syscall)
    // 0x401012: fail_path (mov $60, %rax; mov $1, %rdi; syscall)

    // Policy 1: Find ok_path (0x401006), Avoid fail_path (0x401012)
    let opts1 = RunOptions {
        symbolic: vec![("rax".to_string(), 64)],
        find: vec![0x401006],
        avoid: vec![0x401012],
        ..RunOptions::default()
    };
    let report1 = engine.run(&image, &opts1).expect("run policy 1");
    assert_eq!(report1.found_pcs, vec![0x401006]);
    assert_eq!(report1.forks, 1, "branch must fork exactly once");
    assert!(report1.dead_states >= 1, "avoided branch state is dead");
    assert_eq!(report1.terminated, 0, "found state halted before termination");

    // Policy 2: Find fail_path (0x401012), Avoid ok_path (0x401006)
    let opts2 = RunOptions {
        symbolic: vec![("rax".to_string(), 64)],
        find: vec![0x401012],
        avoid: vec![0x401006],
        ..RunOptions::default()
    };
    let report2 = engine.run(&image, &opts2).expect("run policy 2");
    assert_eq!(report2.found_pcs, vec![0x401012]);
    assert_eq!(report2.forks, 1);
    assert!(report2.dead_states >= 1);

    // Exploration without find/avoid: both branches run to clean syscall termination
    let opts_full = RunOptions {
        symbolic: vec![("rax".to_string(), 64)],
        ..RunOptions::default()
    };
    let report_full = engine.run(&image, &opts_full).expect("run full exploration");
    assert_eq!(report_full.forks, 1);
    assert_eq!(report_full.terminated, 2, "both branches must terminate cleanly");
}

#[test]
fn test_symbolic_solving_input_generation() {
    let engine = Engine::new().expect("engine");
    let image = engine
        .load(fixture_path("symbolic_branch"))
        .expect("load symbolic_branch");

    // Solve for ok_path (requires rax == 42) via Engine::run
    let opts = RunOptions {
        symbolic: vec![("rax".to_string(), 64)],
        find: vec![0x401006],
        avoid: vec![0x401012],
        solve: true,
        ..RunOptions::default()
    };
    let report = engine.run(&image, &opts).expect("run with solve");
    assert_eq!(report.found_pcs, vec![0x401006]);
    assert_eq!(report.inputs.len(), 1, "one model per found state");
    assert!(!report.inputs[0].is_empty(), "input model contains solved symbols");

    let rax_bytes = &report.inputs[0][0];
    assert!(
        rax_bytes.len() >= 8,
        "register model produces at least 8 bytes, got {}",
        rax_bytes.len()
    );
    let solved_rax = u64::from_le_bytes(rax_bytes[..8].try_into().unwrap());
    assert_eq!(solved_rax, 42, "solved input reaching ok_path must have RAX = 42");

    // Verify identical solving capability via Session::run
    let mut session = engine.open(&image).expect("open session");
    let session_report = session.run(&opts).expect("session run with solve");
    assert_eq!(session_report.found_pcs, vec![0x401006]);
    assert_eq!(session_report.inputs.len(), 1);
    let sess_rax = u64::from_le_bytes(session_report.inputs[0][0][..8].try_into().unwrap());
    assert_eq!(sess_rax, 42);
}

#[test]
fn test_concrete_seeding_poke_and_entry_override() {
    let engine = Engine::new().expect("engine");
    let image = engine
        .load(fixture_path("symbolic_branch"))
        .expect("load symbolic_branch");

    // Test concrete register seeding with RunOptions::regs
    // When RAX is concretely seeded with 42, it takes ok_path deterministically without forking
    let opts_seed42 = RunOptions {
        regs: vec![("rax".to_string(), 42)],
        find: vec![0x401006],
        ..RunOptions::default()
    };
    let rep_seed42 = engine.run(&image, &opts_seed42).expect("seed 42");
    assert_eq!(rep_seed42.forks, 0, "concrete execution must not fork");
    assert_eq!(rep_seed42.found_pcs, vec![0x401006]);

    // When RAX is concretely seeded with 99, it takes fail_path deterministically
    let opts_seed99 = RunOptions {
        regs: vec![("rax".to_string(), 99)],
        find: vec![0x401012],
        ..RunOptions::default()
    };
    let rep_seed99 = engine.run(&image, &opts_seed99).expect("seed 99");
    assert_eq!(rep_seed99.forks, 0);
    assert_eq!(rep_seed99.found_pcs, vec![0x401012]);

    // Test entry override with RunOptions::entry
    // Direct entry at ok_path (0x401006), skipping the branch at 0x401000
    let opts_entry = RunOptions {
        entry: Some(0x401006),
        ..RunOptions::default()
    };
    let rep_entry = engine.run(&image, &opts_entry).expect("entry override");
    assert_eq!(rep_entry.terminated, 1);
    assert_eq!(rep_entry.forks, 0);

    // Test memory poking with RunOptions::poke on data_poke fixture
    // data_poke layout:
    // 0x401000: mov 0x402000, %rax
    // 0x401008: cmp $42, %rax
    // 0x40100c: jne 0x40101a (fail_path)
    // 0x40100e: ok_path (mov $60, %rax; xor %rdi, %rdi; syscall)
    // 0x40101a: fail_path (mov $60, %rax; mov $1, %rdi; syscall)
    let poke_image = engine.load(fixture_path("data_poke")).expect("load data_poke");

    let opts_poke_ok = RunOptions {
        poke: vec![(0x402000, 42)],
        find: vec![0x40100e],
        ..RunOptions::default()
    };
    let rep_poke_ok = engine.run(&poke_image, &opts_poke_ok).expect("poke 42");
    assert_eq!(rep_poke_ok.found_pcs, vec![0x40100e]);
    assert_eq!(rep_poke_ok.forks, 0);

    // IOCTL seeding marks an entire structure symbolic, then pins pointer
    // and request fields. The concrete poke must win inside that region.
    let opts_symbolic_then_poke = RunOptions {
        symbolic_memory: vec![(0x402000, 8)],
        poke: vec![(0x402000, 42)],
        find: vec![0x40100e],
        ..RunOptions::default()
    };
    let rep_symbolic_then_poke = engine
        .run(&poke_image, &opts_symbolic_then_poke)
        .expect("concrete poke wins over symbolic region");
    assert_eq!(rep_symbolic_then_poke.found_pcs, vec![0x40100e]);
    assert_eq!(rep_symbolic_then_poke.forks, 0);

    let opts_poke_fail = RunOptions {
        poke: vec![(0x402000, 999)],
        find: vec![0x40101a],
        ..RunOptions::default()
    };
    let rep_poke_fail = engine.run(&poke_image, &opts_poke_fail).expect("poke 999");
    assert_eq!(rep_poke_fail.found_pcs, vec![0x40101a]);
    assert_eq!(rep_poke_fail.forks, 0);
}

#[test]
fn test_exploration_budgets_and_pruning() {
    let engine = Engine::new().expect("engine");

    // Stepping budget truncation on min_elf (3 steps total to terminate)
    let min_image = engine.load(fixture_path("min_elf")).expect("load min_elf");
    let opts_step1 = RunOptions {
        steps: 1,
        ..RunOptions::default()
    };
    let rep_step1 = engine.run(&min_image, &opts_step1).expect("run 1 step");
    assert_eq!(rep_step1.steps, 1);
    assert_eq!(rep_step1.live_states, 1);
    assert_eq!(rep_step1.terminated, 0);

    // State cap pruning on symbolic_branch with max_states = 1
    let branch_image = engine
        .load(fixture_path("symbolic_branch"))
        .expect("load symbolic_branch");
    let opts_cap1 = RunOptions {
        symbolic: vec![("rax".to_string(), 64)],
        max_states: 1,
        ..RunOptions::default()
    };
    let rep_cap1 = engine.run(&branch_image, &opts_cap1).expect("run cap 1");
    assert_eq!(rep_cap1.forks, 1);
    assert!(rep_cap1.pruned_states >= 1, "max_states cap must prune surplus state");
}

#[test]
fn test_api_error_display_and_traits() {
    let io_err = ApiError::Io(std::io::Error::from(std::io::ErrorKind::NotFound));
    assert!(format!("{io_err}").contains("io:"));
    assert!(std::error::Error::source(&io_err).is_some());

    let load_err = ApiError::Load("malformed header".to_string());
    assert_eq!(format!("{load_err}"), "load: malformed header");
    assert!(std::error::Error::source(&load_err).is_none());

    let run_err = ApiError::Run("unmapped memory".to_string());
    assert_eq!(format!("{run_err}"), "run: unmapped memory");

    let solver_err = ApiError::Solver("timeout".to_string());
    assert_eq!(format!("{solver_err}"), "solver: timeout");

    let arg_err = ApiError::InvalidArgument("invalid register".to_string());
    assert_eq!(format!("{arg_err}"), "invalid argument: invalid register");

    // From<std::io::Error> trait conversion
    let converted: ApiError = std::io::Error::from(std::io::ErrorKind::PermissionDenied).into();
    assert!(matches!(converted, ApiError::Io(_)));
}

#[test]
fn test_driver_fixture_when_available() {
    let Some(driver) = harness_fixture("allocsize_overflow_vuln_O2.sys") else {
        eprintln!("SKIP: driver corpus fixture not present");
        return;
    };
    let engine = Engine::new().expect("engine");
    let image = engine.load(&driver).expect("driver loads");
    assert_eq!(image.kind(), ImageKind::PeDriver);

    let mut session = engine.open(&image).expect("open driver session");
    session.symbolic("rdi", 64).expect("mark 64-bit rdi symbolic in driver");

    let report = session
        .run(&RunOptions {
            steps: 200,
            ..RunOptions::default()
        })
        .expect("driver session run");
    assert!(report.steps > 0);
    // Kernel pool tracking is populated for PE driver images
    assert_eq!(report.kernel.double_frees.len(), 0);
}
