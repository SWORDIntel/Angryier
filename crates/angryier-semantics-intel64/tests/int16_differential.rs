#![forbid(unsafe_code)]

//! Native execution smoke matrix for the 16-bit ALU, IMUL, and MOVSXD
//! expansion. The corpus's existing integration machinery exercises provider
//! execution; this test additionally makes every listed encoding execute on
//! the host rather than accepting assembler-only coverage.

use angryier_semantics_intel64::{Intel64CorpusRegistry, forms};
use angryier_types::SemanticVersion;
use std::path::PathBuf;
use std::process::Command;

type BoxError = Box<dyn std::error::Error>;

const ARITHMETIC_FLAGS: u64 = (1 << 0) | (1 << 2) | (1 << 4) | (1 << 6) | (1 << 7) | (1 << 11);
const IMUL_FLAGS: u64 = (1 << 0) | (1 << 11);

fn native_case(name: &str, body: &str, flag_mask: u64) -> Result<(u64, u64), BoxError> {
    let dir: PathBuf = std::env::temp_dir().join(format!("angryier-int16-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let source = dir.join("case.s");
    let object = dir.join("case.o");
    let binary = dir.join("case");
    let assembly = format!(
        ".global _start\n.text\n_start:\n{body}\nmov %rax, result(%rip)\npushfq\npop %rbx\nmov %rbx, result+8(%rip)\nmov $1, %rax\nmov $1, %rdi\nlea result(%rip), %rsi\nmov $16, %rdx\nsyscall\nmov $60, %rax\nxor %rdi, %rdi\nsyscall\n.data\nresult: .quad 0, 0\n"
    );
    std::fs::write(&source, assembly)?;
    let assembled = Command::new("as")
        .args(["--64", "-o"])
        .arg(&object)
        .arg(&source)
        .output()?;
    if !assembled.status.success() {
        return Err(format!(
            "assembler rejected {name}: {}",
            String::from_utf8_lossy(&assembled.stderr)
        )
        .into());
    }
    let linked = Command::new("ld").arg("-o").arg(&binary).arg(&object).output()?;
    if !linked.status.success() {
        return Err(format!("linker rejected {name}: {}", String::from_utf8_lossy(&linked.stderr)).into());
    }
    let output = Command::new(&binary).output()?;
    if !output.status.success() || output.stdout.len() != 16 {
        return Err(format!(
            "native case {name} failed: status={:?}, bytes={}",
            output.status,
            output.stdout.len()
        )
        .into());
    }
    let result = u64::from_le_bytes(output.stdout[..8].try_into()?);
    let flags = u64::from_le_bytes(output.stdout[8..].try_into()?) & flag_mask;
    Ok((result, flags))
}

#[test]
fn arithmetic_register_and_immediate_encodings_run_natively() -> Result<(), BoxError> {
    let cases = [
        ("add-r16", "mov $0xffff, %eax\nmov $1, %dx\nadd %dx, %ax"),
        ("add-i16", "mov $0x8000, %eax\naddw $0x7fff, %ax"),
        ("add-i8", "mov $1, %eax\naddw $-1, %ax"),
        ("adc-r16", "mov $0xffff, %eax\nmov $0, %dx\nstc\nadc %dx, %ax"),
        ("adc-i16", "mov $0x7fff, %eax\nstc\nadcw $0, %ax"),
        ("adc-i8", "mov $0, %eax\nstc\nadcw $-1, %ax"),
        ("sbb-r16", "mov $1, %eax\nmov $1, %dx\nstc\nsbb %dx, %ax"),
        ("sbb-i16", "mov $0x8000, %eax\nstc\nsbbw $0x7fff, %ax"),
        ("sbb-i8", "mov $1, %eax\nstc\nsbbw $-1, %ax"),
        ("cmp-r16", "mov $1, %eax\nmov $2, %dx\ncmp %dx, %ax"),
        ("cmp-i16", "mov $0xffff, %eax\ncmpw $0x7fff, %ax"),
        ("cmp-i8", "mov $0x8000, %eax\ncmpw $-1, %ax"),
        ("or-r16", "mov $0x8000, %eax\nmov $1, %dx\nor %dx, %ax"),
        ("or-i16", "mov $0, %eax\norw $0x7fff, %ax"),
        ("or-i8", "mov $0, %eax\norw $-1, %ax"),
        ("xor-r16", "mov $0xffff, %eax\nmov $0xffff, %dx\nxor %dx, %ax"),
        ("xor-i16", "mov $0x8000, %eax\nxorw $0x8000, %ax"),
        ("xor-i8", "mov $0x7fff, %eax\nxorw $-1, %ax"),
        ("sub-r16", "mov $1, %eax\nmov $2, %dx\nsub %dx, %ax"),
        ("sub-i16", "mov $0x8000, %eax\nsubw $1, %ax"),
        ("sub-i8", "mov $0, %eax\nsubw $-1, %ax"),
    ];
    for (name, body) in cases {
        let _ = native_case(name, body, ARITHMETIC_FLAGS)?;
    }
    Ok(())
}

#[test]
fn imul_and_movsxd_encodings_run_natively() -> Result<(), BoxError> {
    let cases = [
        (
            "imul-r16-clear",
            "mov $0x10, %eax\nmov $0x10, %dx\nimul %dx, %ax",
            IMUL_FLAGS,
        ),
        (
            "imul-r16-set",
            "mov $0x80, %eax\nmov $0x80, %dx\nimul %dx, %ax",
            IMUL_FLAGS,
        ),
        ("imul-i16", "mov $0x10, %edx\nimulw $0x10, %dx, %ax", IMUL_FLAGS),
        ("imul-i8", "mov $0x80, %edx\nimulw $-1, %dx, %ax", IMUL_FLAGS),
        ("movsxd-positive", "mov $0x7fffffff, %edx\nmovslq %edx, %rax", 0),
        ("movsxd-negative", "mov $0x80000000, %edx\nmovslq %edx, %rax", 0),
    ];
    for (name, body, mask) in cases {
        let _ = native_case(name, body, mask)?;
    }
    Ok(())
}

#[test]
fn every_new_form_has_a_registered_provider() -> Result<(), BoxError> {
    let registry = Intel64CorpusRegistry::new(SemanticVersion(1));
    for form in 0x0420..=0x045D {
        if registry.provider_for_form(form).is_none() {
            return Err(format!("missing provider for form {form:#x}").into());
        }
    }
    assert_eq!(forms::ADD_R16_IMM16, 0x0420);
    assert_eq!(forms::MOVSXD_R64_MEM32, 0x045A);
    Ok(())
}
