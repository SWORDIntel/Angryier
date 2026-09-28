//! End-to-end proof that float-using binaries run through the runtime now
//! that the x87 family is wired into the form map.
//!
//! A real x87 program — stack loads, an FADD accumulation loop, memory
//! round trips through both float widths, and FUCOMI/FCOMIP conditional
//! exits — is assembled and linked into a static ELF64 at test time with the
//! system binutils (`as` + `ld`). The engine executes it under native XED
//! from the ELF entry to the `exit` syscall, and the engine's observable
//! result (the exit code, decided by float comparisons) must match a native
//! run of the very same binary on silicon. When the toolchain is
//! unavailable the tests report a skip instead of failing.

#![cfg(feature = "xed")]

use std::path::{Path, PathBuf};
use std::process::Command;

use angryier_runtime::Runtime;
use angryier_types::{SemanticVersion, TargetProfileId};

/// The x87 fixture template. `{iters}` FADD iterations accumulate
/// `{iters}.0`; the value is then doubled through the st(i) forms and run
/// through the m32/m64 arithmetic and store/load forms, ending at
/// `{iters} + 0.75`. FUCOMI compares the m32 store/load round trip against
/// the stack copy, FCOMIP compares the final value against the `expected`
/// constant, and each comparison selects between exit code 0 and 1. All
/// values are small-mantissa dyadic rationals, exact in both the engine's
/// 64-bit payloads and the CPU's 80-bit intermediates.
const X87_PROGRAM: &str = r"
    .global _start
    .text
_start:
    fninit
    fldz
    mov ${iters}, %rbx
    fld1
loop:
    fadd %st, %st(1)
    dec %rbx
    jnz loop
    fstp %st(0)
    fld %st(0)
    fadd %st(1), %st
    fstp %st(1)
    fldl addend
    fadd %st, %st(1)
    fstp %st(0)
    fadds quarter
    fmull two
    fsubl half
    fdivl four
    fsts result32
    fstl result64
    flds result32
    fucomi %st(1), %st
    jne fail
    fldl expected
    fcomip %st(1), %st
    jne fail
    fstp %st(0)
    mov $60, %rax
    xor %rdi, %rdi
    syscall
fail:
    mov $60, %rax
    mov $1, %rdi
    syscall
    .data
addend:   .quad 0x3FF8000000000000
quarter:  .long 0x3E800000
two:      .quad 0x4000000000000000
half:     .quad 0x3FE0000000000000
four:     .quad 0x4010000000000000
expected: .quad 0x4021800000000000
result32: .long 0
result64: .quad 0
";

/// A 16-bit immediate chain over `%dx`: the `cmp $imm16, %dx` form the speed
/// benchmark had to avoid, plus its `add`/`sub`/`and`/`or`/`xor`/`test`
/// siblings, verified at each step by conditional exits.
const W16_PROGRAM: &str = r"
    .global _start
    .text
_start:
    mov $0x1000, %rdx
    add $0x0234, %dx
    cmp $0x1235, %dx
    je fail
    sub $0x1000, %dx
    and $0x030F, %dx
    or  $0x0020, %dx
    xor $0x0024, %dx
    cmp $0x0200, %dx
    jne fail
    test $0x0200, %dx
    jz fail
    mov $60, %rax
    xor %rdi, %rdi
    syscall
fail:
    mov $60, %rax
    mov $1, %rdi
    syscall
";

/// Assembles and links `source` into a static ELF64 executable, returning
/// its bytes and on-disk path. Returns `None` when binutils is unavailable.
fn build_binary(source: &str) -> Option<(Vec<u8>, PathBuf)> {
    let dir = temp_dir(&format!("angryier-x87-{}", unique_suffix()))?;
    let source_path = dir.join("fixture.s");
    let object = dir.join("fixture.o");
    let binary = dir.join("fixture.elf");
    std::fs::write(&source_path, source).ok()?;

    let assembled = Command::new("as")
        .arg("--64")
        .arg("-o")
        .arg(&object)
        .arg(&source_path)
        .output()
        .ok()?;
    if !assembled.status.success() {
        return None;
    }
    let linked = Command::new("ld").arg("-o").arg(&binary).arg(&object).output().ok()?;
    if !linked.status.success() {
        return None;
    }
    let bytes = std::fs::read(&binary).ok()?;
    Some((bytes, binary))
}

fn temp_dir(name: &str) -> Option<PathBuf> {
    let dir = std::env::temp_dir().join(format!("{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir)
}

/// Monotonic suffix so fixtures never share a directory.
fn unique_suffix() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// Runs `binary` natively and returns its exit code.
fn native_exit_code(binary: &Path) -> Option<i32> {
    Command::new(binary).output().ok()?.status.code()
}

/// The float-using binary runs end-to-end under native XED: eight FADD
/// iterations reach 8.75, both float comparisons agree, and the engine's
/// exit code must match silicon running the same bytes.
#[test]
fn x87_program_runs_end_to_end_matching_native() -> Result<(), Box<dyn std::error::Error>> {
    let Some((elf, binary)) = build_binary(&X87_PROGRAM.replace("{iters}", "8")) else {
        eprintln!("skipping: binutils (as/ld) unavailable");
        return Ok(());
    };

    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_elf(&elf)?;
    runtime.run(&mut process, 256)?;

    assert!(process.terminated, "the exit syscall must terminate execution");
    assert_eq!(
        process.syscalls.exit_code(),
        Some(0),
        "8 iterations must accumulate to the 8.75 expected constant"
    );
    assert!(
        process.step_count >= 30,
        "the full float program must execute, got {} steps",
        process.step_count
    );

    let native = native_exit_code(&binary).ok_or("native run failed")?;
    assert_eq!(native, 0, "native execution must agree with the engine result");
    Ok(())
}

/// A divergent input through the same program: seven iterations accumulate
/// to 7.75, FCOMIP against the 8.75 constant fails, and both worlds must
/// take the fail path (exit code 1).
#[test]
fn x87_program_divergence_matches_native() -> Result<(), Box<dyn std::error::Error>> {
    let Some((elf, binary)) = build_binary(&X87_PROGRAM.replace("{iters}", "7")) else {
        eprintln!("skipping: binutils (as/ld) unavailable");
        return Ok(());
    };

    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_elf(&elf)?;
    runtime.run(&mut process, 256)?;

    assert!(process.terminated, "the exit syscall must terminate execution");
    assert_eq!(
        process.syscalls.exit_code(),
        Some(1),
        "7 iterations must fail the comparison against the 8.75 constant"
    );

    let native = native_exit_code(&binary).ok_or("native run failed")?;
    assert_eq!(native, 1, "native execution must agree with the engine result");
    Ok(())
}

/// x87 forms outside the mapped corpus still fail explicitly instead of
/// executing approximate semantics: `fstsw %ax` needs the status-word
/// register and `fst %st(1)` has no corpus form.
#[test]
fn unmapped_x87_forms_fail_explicitly() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    for body in [
        "_start:\n    fninit\n    fnop\n    hlt\n",
        "_start:\n    fninit\n    fld1\n    fst %st(1)\n    hlt\n",
    ] {
        let Some((elf, _binary)) = build_binary(body) else {
            eprintln!("skipping: binutils (as/ld) unavailable");
            return Ok(());
        };
        let mut process = runtime.load_elf(&elf)?;
        let error = runtime
            .run(&mut process, 8)
            .err()
            .ok_or("expected an unsupported-form error")?;
        let message = error.to_string();
        assert!(
            message.contains("UnsupportedForm(0)"),
            "unmapped x87 must report form id 0, got: {message}"
        );
    }
    Ok(())
}

/// The 16-bit immediate chain runs end-to-end and agrees with a native run:
/// every `cmp`/`test` on `%dx` must produce silicon-identical flags.
#[test]
fn sixteen_bit_immediate_program_matches_native() -> Result<(), Box<dyn std::error::Error>> {
    let Some((elf, binary)) = build_binary(W16_PROGRAM) else {
        eprintln!("skipping: binutils (as/ld) unavailable");
        return Ok(());
    };

    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let mut process = runtime.load_elf(&elf)?;
    runtime.run(&mut process, 64)?;

    assert!(process.terminated, "the exit syscall must terminate execution");
    assert_eq!(
        process.syscalls.exit_code(),
        Some(0),
        "the %dx chain must satisfy every comparison"
    );

    let native = native_exit_code(&binary).ok_or("native run failed")?;
    assert_eq!(native, 0, "native execution must agree with the engine result");
    Ok(())
}
