//! ANG-090 phase 2: symbolic execution of a hand-assembled A64 program on the
//! ARM64 backend — a symbolic register flows through `subs` flag computation
//! into a `b.ne` fork, and both paths must be enumerated with distinct
//! constraints (no external samples, no Titan corpus, no network).

#![allow(clippy::unwrap_used, clippy::panic)]

use angryier_arch::Decoder;
use angryier_arch_arm64::{Arm64Decoder, regs::register_id};
use angryier_ir::IrType;
use angryier_runtime::{Runtime, SymbolicSession};
use angryier_types::{ExpressionNormalizationVersion, SemanticVersion, TargetProfileId};
use std::sync::Arc;
use std::time::Duration;

const CODE_BASE: u64 = 0x400078;

/// Minimal 64-bit ELF carrier matching the `arm64_concrete.rs` harness.
fn build_test_elf(code: &[u8]) -> Vec<u8> {
    let segment_base = 0x400000u64;
    let code_offset = 0x78usize;
    let total_size = code_offset + code.len();
    let mut buf = vec![0u8; total_size];

    buf[0..4].copy_from_slice(b"\x7fELF");
    buf[4] = 2;
    buf[5] = 1;
    buf[6] = 1;
    buf[7] = 0;

    buf[16..18].copy_from_slice(&2u16.to_le_bytes());
    buf[18..20].copy_from_slice(&62u16.to_le_bytes());
    buf[20..24].copy_from_slice(&1u32.to_le_bytes());
    let entry = segment_base + code_offset as u64;
    buf[24..32].copy_from_slice(&entry.to_le_bytes());
    buf[32..40].copy_from_slice(&64u64.to_le_bytes());
    buf[52..54].copy_from_slice(&64u16.to_le_bytes());
    buf[54..56].copy_from_slice(&56u16.to_le_bytes());
    buf[56..58].copy_from_slice(&1u16.to_le_bytes());

    buf[64..68].copy_from_slice(&1u32.to_le_bytes());
    buf[68..72].copy_from_slice(&5u32.to_le_bytes());
    buf[72..80].copy_from_slice(&0u64.to_le_bytes());
    buf[80..88].copy_from_slice(&segment_base.to_le_bytes());
    buf[88..96].copy_from_slice(&segment_base.to_le_bytes());
    buf[96..104].copy_from_slice(&(total_size as u64).to_le_bytes());
    buf[104..112].copy_from_slice(&(total_size as u64).to_le_bytes());
    buf[112..120].copy_from_slice(&0x1000u64.to_le_bytes());

    buf[code_offset..code_offset + code.len()].copy_from_slice(code);
    buf
}

#[test]
fn arm64_symbolic_branch_forks_on_flags() -> Result<(), Box<dyn std::error::Error>> {
    // The ELF harness is exercised at 36 code bytes elsewhere; pad the
    // program with NOPs to the same length so the loader sees a known-good
    // segment shape.
    let words: [u32; 9] = [
        0xD280_0062, // movz x2, #3
        0xEB01_0042, // subs x2, x2, x1   (flags become symbolic in x1)
        0x5400_0041, // b.ne +8           (x1 != 3 -> 0x400088 ret; else -> 0x400084)
        0xD280_0020, // movz x0, #1
        0xD65F_03C0, // ret
        0xD503_201F, // nop
        0xD503_201F, // nop
        0xD503_201F, // nop
        0xD503_201F, // nop
    ];
    let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();

    let decoder = Arm64Decoder::with_profile_id(TargetProfileId(7));
    for (index, word) in words.iter().enumerate() {
        let address = CODE_BASE + (index as u64) * 4;
        decoder
            .decode(address, &word.to_le_bytes())
            .unwrap_or_else(|error| panic!("A64 word {word:#010x} must decode: {error}"));
    }

    let elf = build_test_elf(&code);
    let runtime = Runtime::new_arm64(decoder, SemanticVersion(1), TargetProfileId(7));
    let process = runtime.load_elf(&elf).unwrap();

    let arena = angryier_expr::ShardedExprArena::new(ExpressionNormalizationVersion(1));
    let mut session = SymbolicSession::new(&runtime, &arena, process);
    session.mark_symbolic(0, register_id::X1.0, IrType::Bits(64))?;

    // Step through movz, subs, b.ne: the third step must fork on the
    // symbolic Z flag computed from x1.
    for step in 0..3 {
        session
            .step_state(0)
            .unwrap_or_else(|error| panic!("symbolic step {step} failed: {error:?}"));
    }

    assert_eq!(
        session.states.len(),
        2,
        "the symbolic b.ne must fork into exactly two live states"
    );

    let pcs: Vec<u64> = session
        .states
        .iter()
        .map(|state| state.process.read_register(register_id::PC.0).unwrap())
        .collect();
    assert!(
        pcs.contains(&(CODE_BASE + 3 * 4)),
        "fall-through path (x1 == 3) must reach 0x400084, got {pcs:#x?}"
    );
    assert!(
        pcs.contains(&(CODE_BASE + 4 * 4)),
        "taken path (x1 != 3) must reach 0x400088, got {pcs:#x?}"
    );

    // Both forks carry a path constraint over the symbolic x1.
    for state in &session.states {
        assert!(
            !state.constraints.is_empty(),
            "every forked path must accumulate a branch constraint"
        );
    }

    // x2 is the symbolic expression 3 - x1 on both paths.
    for state in &session.states {
        assert!(
            state.registers.contains_key(&register_id::X2.0),
            "x2 must be symbolic on both paths"
        );
    }

    Ok(())
}

/// Solver-assisted path solving on the A64 fork: every forked path must be
/// satisfiable, and the fall-through path's model must pin the symbolic x1
/// to the value its constraint demands (x1 == 3).
#[cfg(feature = "z3")]
#[test]
fn arm64_symbolic_fork_solves_path_models() -> Result<(), Box<dyn std::error::Error>> {
    let words: [u32; 9] = [
        0xD280_0062, // movz x2, #3
        0xEB01_0042, // subs x2, x2, x1   (flags become symbolic in x1)
        0x5400_0041, // b.ne +8           (x1 != 3 -> 0x400088 ret; else -> 0x400084)
        0xD280_0020, // movz x0, #1
        0xD65F_03C0, // ret
        0xD503_201F, // nop
        0xD503_201F, // nop
        0xD503_201F, // nop
        0xD503_201F, // nop
    ];
    let code: Vec<u8> = words.iter().flat_map(|word| word.to_le_bytes()).collect();
    let decoder = Arm64Decoder::with_profile_id(TargetProfileId(7));
    let elf = build_test_elf(&code);
    let runtime = Runtime::new_arm64(decoder, SemanticVersion(1), TargetProfileId(7));
    let process = runtime.load_elf(&elf).unwrap();

    let arena = Arc::new(angryier_expr::ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut session = SymbolicSession::new(&runtime, arena.as_ref(), process);
    session.mark_symbolic(0, register_id::X1.0, IrType::Bits(64))?;

    for step in 0..3 {
        session
            .step_state(0)
            .unwrap_or_else(|error| panic!("symbolic step {step} failed: {error:?}"));
    }
    assert_eq!(session.states.len(), 2, "b.ne must fork into two states");

    let backend_arena = arena.clone() as Arc<dyn angryier_expr::ExprReader>;
    let mut backend = angryier_solver_z3::Z3Backend::native_ffi(backend_arena)?;

    for (index, state) in session.states.iter().enumerate() {
        let pc = state.process.read_register(register_id::PC.0).unwrap();
        let model = session
            .solve_state_symbols(index, &mut backend, Duration::from_secs(10))
            .unwrap_or_else(|error| panic!("path at {pc:#x} must be satisfiable: {error:?}"));

        let x1_value = state
            .symbols
            .iter()
            .find(|binding| binding.register == register_id::X1.0)
            .and_then(|binding| {
                model
                    .iter()
                    .find(|(key, _)| *key == u64::from(binding.expression.0))
                    .map(|(_, bytes)| u64::from_le_bytes(bytes[..8].try_into().unwrap()))
            });

        if pc == CODE_BASE + 3 * 4 {
            // Fall-through path: constraint is x1 == 3.
            assert_eq!(x1_value, Some(3), "fall-through model must pin x1 == 3");
        } else {
            // Taken path: constraint is x1 != 3.
            assert_eq!(pc, CODE_BASE + 4 * 4, "unexpected fork pc {pc:#x}");
            assert_ne!(x1_value, Some(3), "taken model must satisfy x1 != 3");
        }
    }

    Ok(())
}
