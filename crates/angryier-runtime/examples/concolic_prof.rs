//! Throwaway concolic profiling driver (callgrind target). Not part of the
//! crate's public surface; delete after the speed round.

use std::process::Command;
use std::sync::Arc;
use std::time::Instant;

use angryier_arch_intel64::register_id;
use angryier_expr::ShardedExprArena;
use angryier_ir::IrType;
use angryier_runtime::Runtime;
use angryier_types::{ExpressionNormalizationVersion, SemanticVersion, TargetProfileId};

const SOURCE: &str = r#"
#define LOOPS 3000
volatile unsigned long g_input;
volatile unsigned long g_sink;
static unsigned long mix(unsigned long x, unsigned long i) {
    unsigned long h = x ^ (i * 0x9E3779B97F4A7C15UL);
    h ^= h >> 29;
    h *= 0xBF58476D1CE4E5B9UL;
    h ^= h >> 32;
    return h;
}
#define BASE 0x100000000UL
void run(void) {
    unsigned long x = g_input;
    unsigned long acc = x;
    for (unsigned long i = BASE; i < BASE + LOOPS; i++) {
        unsigned long v = mix(x, i);
        if (v & 1UL) {
            acc += (v << 17) ^ (v >> 13);
        } else {
            acc -= (v >> 7) ^ (v << 41);
        }
        acc ^= acc >> 23;
        acc += (v >> 3) + (i >> 1);
    }
    g_sink = acc;
    __asm__ volatile("mov $60, %%rax\n\txor %%rdi, %%rdi\n\tsyscall\n\t" ::: "rax", "rdi", "memory");
}
__asm__(
    ".global _start\n"
    "_start:\n"
    "    movq %rax, g_input(%rip)\n"
    "    call run\n"
    "    mov $60, %rax\n"
    "    xor %rdi, %rdi\n"
    "    syscall\n");
"#;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::temp_dir().join(format!("angryier-prof-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let src = dir.join("looptrace.c");
    let bin = dir.join("looptrace.elf");
    std::fs::write(&src, SOURCE)?;
    let out = Command::new("cc")
        .args([
            "-O2",
            "-static",
            "-nostdlib",
            "-fno-stack-protector",
            "-fcf-protection=none",
            "-fno-asynchronous-unwind-tables",
            "-fno-pie",
            "-no-pie",
        ])
        .arg("-o")
        .arg(&bin)
        .arg(&src)
        .output()?;
    if !out.status.success() {
        return Err("fixture build failed".into());
    }
    let elf = std::fs::read(&bin)?;
    let steps: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(20_000);

    let runtime = Runtime::with_native_xed(SemanticVersion(1), TargetProfileId(1));
    let arena = Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)));
    let mut process = runtime.load_elf(&elf)?;
    process.write_register(register_id::GPR_BASE, 0x00C0_FFEE_1234_5678)?;
    let mut session = runtime.concolic(process, arena.as_ref());
    session.mark_input_register(register_id::GPR_BASE, IrType::Bits(64))?;
    let started = Instant::now();
    let mut done = 0u64;
    for _ in 0..steps {
        match session.step()? {
            angryier_runtime::StepOutcome::Stepped { .. } => done += 1,
            angryier_runtime::StepOutcome::Terminated { .. } | angryier_runtime::StepOutcome::Trap { .. } => break,
            _ => {}
        }
    }
    let elapsed = started.elapsed();
    println!(
        "concolic prof: {done} steps in {:.1} ms ({:.2} us/step), constraints {}",
        elapsed.as_secs_f64() * 1000.0,
        elapsed.as_secs_f64() * 1e6 / steps.max(1) as f64,
        session.path_constraints().len()
    );
    Ok(())
}
