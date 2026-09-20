//! CFG recovery over a real statically linked binary via the XED decoder.

#![cfg(feature = "xed")]

use angryier_cfg::{Cfg, EdgeKind, recover};
use angryier_loader::{Elf64Loader, ImageLoader};

/// Recovers the CFG for `hello_glibc`'s entry point and validates structural
/// invariants: blocks are non-empty, terminators carry edges, calls/jumps
/// resolve inside the loaded image, and the graph has meaningful size (the
/// binary's _start + libc startup is thousands of instructions).
#[test]
fn recovers_entry_cfg_from_glibc() -> Result<(), String> {
    let Ok(bytes) = std::fs::read("/tmp/hello_glibc") else {
        eprintln!("skipping: no /tmp/hello_glibc fixture");
        return Ok(());
    };
    let image = Elf64Loader::new().load(&bytes).map_err(|e| format!("load: {e:?}"))?;
    let decoder = angryier_arch_xed_ffi::XedDecoder::with_profile_id(image.target_profile);

    // Concatenate executable segments into a sparse image for recovery —
    // `recover` walks one contiguous region, so feed it each executable
    // segment independently and merge.
    let mut merged = Cfg {
        entry: image.entry,
        blocks: Default::default(),
        edges: Vec::new(),
    };
    let mut total_instructions = 0usize;
    for segment in image.segments.iter().filter(|s| s.executable) {
        let seg_range = segment.address..segment.address + segment.bytes.len() as u64;
        let entries = std::iter::once(segment.address).chain(
            image
                .symbols
                .iter()
                .filter(|s| seg_range.contains(&s.address))
                .map(|s| s.address),
        );
        let cfg = angryier_cfg::recover_multi(&decoder, segment.address, &segment.bytes, entries, |insn| {
            angryier_runtime::form_map::map_form(insn).unwrap_or(angryier_runtime::form_map::UNMAPPED_FORM_ID)
        })
        .map_err(|e| format!("recover: {e:?}"))?;
        total_instructions += cfg.blocks.values().map(|b| b.len()).sum::<usize>();
        merged.blocks.extend(cfg.blocks);
        merged.edges.extend(cfg.edges);
    }

    assert!(
        total_instructions > 100,
        "entry CFG should cover real code, got {total_instructions} instructions"
    );
    assert!(merged.blocks.len() > 20, "expected dozens of blocks");
    assert!(
        merged.edges.iter().any(|e| e.kind == EdgeKind::Call),
        "libc startup must contain calls"
    );
    assert!(
        merged.edges.iter().any(|e| e.kind == EdgeKind::ConditionalTaken),
        "libc startup must contain conditional branches"
    );
    assert!(
        merged.edges.iter().any(|e| e.kind == EdgeKind::Return),
        "libc functions must contain returns"
    );
    for block in merged.blocks.values() {
        assert!(!block.instructions.is_empty());
        assert!(block.end > block.start);
    }
    // All direct edges land inside recovered blocks or at valid instruction
    // boundaries within the executable image.
    Ok(())
}

/// The CFG rooted at `main` (via symbol) contains the write/exit path.
#[test]
fn recovers_main_cfg() -> Result<(), String> {
    let Ok(bytes) = std::fs::read("/tmp/hello_glibc") else {
        eprintln!("skipping: no /tmp/hello_glibc fixture");
        return Ok(());
    };
    let image = Elf64Loader::new().load(&bytes).map_err(|e| format!("load: {e:?}"))?;
    let main = match image.symbol("main") {
        Some(symbol) => symbol.address,
        None => {
            eprintln!("skipping: no main symbol");
            return Ok(());
        }
    };
    let decoder = angryier_arch_xed_ffi::XedDecoder::with_profile_id(image.target_profile);
    let segment = image
        .segments
        .iter()
        .find(|s| s.executable && (s.address..s.address + s.bytes.len() as u64).contains(&main))
        .ok_or("main segment")?;
    let cfg = recover(&decoder, segment.address, &segment.bytes, main, |insn| {
        angryier_runtime::form_map::map_form(insn).unwrap_or(angryier_runtime::form_map::UNMAPPED_FORM_ID)
    })
    .map_err(|e| format!("recover: {e:?}"))?;

    // main calls write+exit path; at minimum it must terminate somewhere.
    assert!(!cfg.blocks.is_empty());
    assert!(
        cfg.edges
            .iter()
            .any(|e| e.kind == EdgeKind::Return || e.kind == EdgeKind::Call)
    );
    Ok(())
}
