#![forbid(unsafe_code)]

//! Native execution coverage for the memory/cache batch.  The semantic
//! providers are checked by the registry tests; this test additionally makes
//! binutils assemble and the host CPU execute every requested encoding/count.

use std::path::PathBuf;
use std::process::Command;

const COUNTS: [u8; 9] = [0, 1, 31, 32, 33, 63, 64, 127, 255];

fn temp_dir() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let path = std::env::temp_dir().join(format!("angryier-memforms-{}", std::process::id()));
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

#[test]
fn memory_and_cache_forms_run_natively() -> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_dir()?;
    let source = dir.join("memforms.s");
    let object = dir.join("memforms.o");
    let binary = dir.join("memforms");
    let mut body = String::from(
        ".global _start\n.text\n_start:\n lea scratch(%rip), %rdi\n movabs $0x8000000000000001, %rax\n mov %rax, (%rdi)\n",
    );
    let mut cases = 0usize;
    for op in ["shl", "shr", "sar", "rol", "ror", "rcl", "rcr"] {
        for (suffix, directive) in [("w", ".word"), ("l", ".long"), ("q", ".quad")] {
            for count in COUNTS {
                body.push_str(&format!(
                    " movabs $0x8000000000000001, %rax\n mov %rax, (%rdi)\n stc\n {op}{suffix} ${count}, (%rdi)\n"
                ));
                body.push_str(&format!(
                    " movabs $0xfeedface000000{count:02x}, %rcx\n movabs $0x8000000000000001, %rax\n mov %rax, (%rdi)\n stc\n {op}{suffix} %cl, (%rdi)\n"
                ));
                let _ = directive;
                cases += 2;
            }
        }
    }
    for op in ["bts", "btr", "btc"] {
        for suffix in ["l", "q"] {
            for index in [0u64, 1, 31, 32, 63, 127] {
                let index_register = if suffix == "l" { "%ecx" } else { "%rcx" };
                body.push_str(&format!(
                    " movabs $0x8000000000000001, %rax\n mov %rax, (%rdi)\n mov ${index}, %rcx\n {op}{suffix} {index_register}, (%rdi)\n"
                ));
                cases += 1;
            }
        }
    }
    for value in [0xffffu16, 0x8000, 1] {
        body.push_str(&format!(
            " movw ${value}, (%rdi)\n movw $0x55aa, %ax\n andw %ax, (%rdi)\n movw ${value}, %ax\n andw $0x55aa, %ax\n andw $0x55, %ax\n testw %ax, %ax\n testw $0x55aa, %ax\n testw %ax, (%rdi)\n testw $0x55aa, (%rdi)\n"
        ));
        cases += 9;
    }
    for mnemonic in [
        "cmovz", "cmovnz", "cmovb", "cmovnb", "cmovl", "cmovnl", "cmovbe", "cmovnbe", "cmovle", "cmovnle",
    ] {
        body.push_str(&format!(
            " mov $1, %ax\n mov $2, %dx\n cmp %ax, %ax\n {mnemonic} %dx, %ax\n cmp %ax, %dx\n {mnemonic} %dx, %ax\n"
        ));
        cases += 2;
    }
    body.push_str(
        "pxor %xmm0, %xmm0\n movntdq %xmm0, 16(%rdi)\n mov $0x12345678, %eax\n movnti %eax, 32(%rdi)\n movnti %rax, 40(%rdi)\n prefetchnta (%rdi)\n prefetcht0 (%rdi)\n prefetcht1 (%rdi)\n prefetcht2 (%rdi)\n mov $60, %rax\n xor %rdi, %rdi\n syscall\n.data\n.balign 16\nscratch:\n.space 64\n",
    );
    cases += 7;
    std::fs::write(&source, body)?;
    let assembled = Command::new("as")
        .args(["--64", "-o"])
        .arg(&object)
        .arg(&source)
        .output()?;
    assert!(
        assembled.status.success(),
        "assembler: {}",
        String::from_utf8_lossy(&assembled.stderr)
    );
    let linked = Command::new("ld").arg("-o").arg(&binary).arg(&object).output()?;
    assert!(
        linked.status.success(),
        "linker: {}",
        String::from_utf8_lossy(&linked.stderr)
    );
    let status = Command::new(&binary).status()?;
    assert!(status.success());
    assert_eq!(cases, 468);
    Ok(())
}
