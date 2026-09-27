#![forbid(unsafe_code)]

//! Native execution coverage for SBB carry/borrow edges and the scalar D1
//! implicit-count forms added with the 0x0e00 form band.

use angryier_semantics_intel64::{Intel64CorpusRegistry, forms};
use angryier_types::SemanticVersion;
use std::path::PathBuf;
use std::process::Command;

type BoxError = Box<dyn std::error::Error>;

fn native_case(name: &str, body: &str) -> Result<(), BoxError> {
    let dir: PathBuf = std::env::temp_dir().join(format!("angryier-sbb-d1-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let source = dir.join("case.s");
    let object = dir.join("case.o");
    let binary = dir.join("case");
    std::fs::write(
        &source,
        format!(".global _start\n.text\n_start:\n{body}\npushfq\npop %rbx\nmov $60, %rax\nxor %rdi, %rdi\nsyscall\n"),
    )?;
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
    let status = Command::new(&binary).status()?;
    if !status.success() {
        return Err(format!("native case {name} failed: {status}").into());
    }
    Ok(())
}

#[test]
fn sbb_and_d1_encodings_run_natively() -> Result<(), BoxError> {
    let cases = [
        ("sbb-r64-cf0", "mov $7, %rax\nmov $3, %rdx\nclc\nsbb %rdx, %rax"),
        ("sbb-r64-cf1", "mov $3, %rax\nmov $3, %rdx\nstc\nsbb %rdx, %rax"),
        ("sbb-r32-cf0", "mov $7, %eax\nmov $3, %edx\nclc\nsbb %edx, %eax"),
        ("sbb-r32-cf1", "mov $3, %eax\nmov $3, %edx\nstc\nsbb %edx, %eax"),
        ("sbb-r16-cf0", "mov $7, %eax\nmov $3, %edx\nclc\nsbb %dx, %ax"),
        ("sbb-r16-cf1", "mov $3, %eax\nmov $3, %edx\nstc\nsbb %dx, %ax"),
        ("shl-r16-1", "mov $0x8001, %eax\nshlw %ax"),
        ("shr-r16-1", "mov $0x8001, %eax\nshrw %ax"),
        ("sar-r16-1", "mov $0x8001, %eax\nsarw %ax"),
        ("rol-r16-1", "mov $0x8001, %eax\nrolw %ax"),
        ("ror-r16-1", "mov $0x8001, %eax\nrorw %ax"),
        ("rcl-r16-1", "mov $0x8001, %eax\nstc\nrclw %ax"),
        ("rcr-r16-1", "mov $0x8001, %eax\nstc\nrcrw %ax"),
        ("rcl-r32-1", "mov $0x80000001, %eax\nstc\nrcll %eax"),
        ("rcr-r32-1", "mov $0x80000001, %eax\nstc\nrcrl %eax"),
    ];
    for (name, body) in cases {
        native_case(name, body)?;
    }
    Ok(())
}

#[test]
fn every_added_form_has_a_registered_provider() -> Result<(), BoxError> {
    let registry = Intel64CorpusRegistry::new(SemanticVersion(1));
    for form in 0x0e00..=0x0e0d {
        if registry.provider_for_form(form).is_none() {
            return Err(format!("missing provider for form {form:#x}").into());
        }
    }
    assert_eq!(forms::SBB_R32_R32, 0x0e00);
    assert_eq!(forms::RCR_R32_IMM8, 0x0e0d);
    Ok(())
}
