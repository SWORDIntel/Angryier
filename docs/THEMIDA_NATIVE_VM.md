# Native VM analysis — experimental Themida/VMProtect building blocks

**Status (2026-10-15): structural inspection, bounded evidence graph, and
output-rooted expression reduction. Not an automatic Themida devirtualizer.**

## Scope and threat model

This code handles locally obtained binaries and trusted analysis evidence in a
controlled laboratory. A large decode census, an indirect jump, or a VM_CONTEXT
register hypothesis is **not** proof that an instruction belongs to a VM.
Likewise, an observed trace does not establish complete CFG coverage.

The opt-in API does not modify the ordinary CFG, eagerly resolve unknown
control transfers, bypass debugger protections, execute foreign samples, or
replace the existing concolic/symbolic engine.

## Implemented

1. **Signed address handling:** CFG constant/table-base resolution uses
   `u64::checked_add_signed` for signed RIP/base displacements. Regression
   tests include a negative-displacement table located before the dispatcher.
2. **Conservative LEA provenance:** `themida::DispatchWindow` distinguishes
   RIP/absolute constants from register-relative context derivations and
   unknown two-register addressing.
3. **Native static VM-site reconnaissance:** `vm::inspect_native_cfg` consumes
   unresolved indirect-jump blocks, runs existing `themida` classification and
   `vpc` heuristics, and returns candidates with context provenance.
   `Runtime::inspect_vm_window(process, entry, max_bytes)` exposes this to
   native consumers using the existing bounded executable-window CFG builder.
4. **VPC/context-sensitive observed graph:** `vm::VmAnalysisSession` accepts
   explicit handler-boundary transitions keyed by native PC, virtual PC, state
   digest, and code digest; distinct virtual instructions in the same handler
   cannot accidentally share a node. Duplicate evidence is aggregated.
   Exceeding node/edge budgets rejects admission atomically and increments
   the rejection count. `projected_edges()` emits only edges supported by
   supplied observations, collapsing contexts for downstream analysis.
5. **Output-rooted handler semantics:** `angryier_expr::vm_effects::reduce_vm_effects`
   traverses expression DAG dependencies from caller-declared register,
   flag, virtual-PC, dispatch, and ordered memory-write effects, plus branch
   guards. It retains symbolic memory *addresses* as roots, applies the
   existing `deobf` simplifier, and reports source dependencies and node
   counts. Unknown nodes and capacity overruns fail closed.

## AngryIR effect-footprint discovery (experimental)

`angryier_ir::vm_footprint::collect_vm_ir_effects` now collects an
**instruction-order-preserving syntactic footprint** from a verified, single
AngryIR block. It discovers register writes (including partial parent-register
updates), ordered memory writes, memory reads even when their result is dead
(the read may fault), masked-load address/mask dependencies, branches, indirect
dispatches, direct calls, returns, and explicit traps. It returns the backward
SSA dependency closure in producer order, including source registers, external
expression references and memory read results. Invalid IR or exhausted
instruction/dependency budgets abort the collection without a partial result.

```rust
use angryier_ir::vm_footprint::{collect_vm_ir_effects, VmIrLimits};

// `ir_block` is one lowered, source-identified AngryIR block.
let footprint = collect_vm_ir_effects(&ir_block, VmIrLimits::default())?;
// Consume `footprint.effects` in original order; do not sort stores.
// `footprint.dependencies` are IR value IDs, NOT ExprIds.
// `footprint.caveats` prohibits interpreting this as verified semantics.
```

This collector is deliberately **not** a handler synthesizer. It has no
cross-block memory SSA, confirmed VPC role, path-condition accumulation,
Windows process restoration or proof that every architectural exception is
represented. It marks all primitives for semantic review. Do not discard a
register write merely because it appears VM-internal; boundary/state evidence
must justify that decision. In particular, a register write with
`PreserveParent` implicitly depends on the pre-write parent register.

**Next integration gate:** for a trace with independently established handler
boundaries and VPC/context values, keep each block's SSA namespace distinct,
materialize its retained IR values into expression IDs under the recorded
entry state, and feed ordered, width-qualified effects to
`angryier_expr::vm_effects::reduce_vm_effects`. Differential replay must
validate the resulting summary before it can replace native interpreter
execution. No automatic full Themida devirtualization is implied.

## Minimal native use

```rust
// After obtaining Runtime<D> and its loaded Process:
let report = runtime.inspect_vm_window(&process, entry_pc, 1024 * 1024)?;
for site in &report.findings {
    println!("dispatch={:#x} kind={:?} possible_context={:?}",
        site.dispatch_pc, site.kind, site.context_origin);
}
// No virtual-PC values are manufactured by this static scan.
```

Feed exact transitions from a native runtime observer or a versioned external
capture (the observer must establish handler boundaries and VPC values):

```rust
use angryier_cfg::vm::{
    VmAnalysisLimits, VmAnalysisSession, VmNodeKey, VmTransition, VmTransitionSource,
};

let mut vm = VmAnalysisSession::new(VmAnalysisLimits {
    max_nodes: 4096,
    max_edges: 8192,
});
let entry = VmNodeKey {
    native_pc: 0x140010000,
    virtual_pc: 0x100,
    state_digest: [1; 32], // replace with an exact capture-derived digest
    code_digest: [2; 32],  // hash the captured executable bytes
};
let next = VmNodeKey {
    native_pc: 0x140020000,
    virtual_pc: 0x105,
    state_digest: [3; 32],
    code_digest: [2; 32],
};
vm.observe(VmTransition {
    from: entry,
    to: next,
    source: VmTransitionSource::ObservedTrace,
})?;
assert_eq!(vm.projected_edges().len(), 1);
assert_eq!(vm.rejected(), 0);
```

These examples are API sketches; the surrounding client selects its decoder,
source identity and runtime. Synthetic digest literals are **not** valid
capture provenance. Observed transitions should carry independent binary,
architecture, mapping, timestamp/epoch and acquisition provenance in the
client's artifact envelope (METHRA/QIHSE); a digest alone cannot prove origin.

## Validation

```sh
cargo fmt --all -- --check
cargo test -p angryier-cfg vm::
cargo test -p angryier-cfg themida::
cargo test -p angryier-cfg negative_rip_relative_jump_table_displacement_resolves
cargo test -p angryier-expr vm_effects::
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

Acceptance gates for future milestones:

- Static dispatch precision/recall on compiler-switch negative controls and
  deliberately virtualized functions, with reachable-code ground truth;
- dynamic VPC values and handler boundaries validated against a known VM;
- context-hash compatibility rules, page-version coherence, capture provenance,
  and explicit missing-state/incomplete outcomes;
- handler read/write footprint extraction from AngryIR rather than analyst-
  supplied roots, preserving memory effects and exception/flag semantics;
- semantic replay or SMT-equivalence tests for every accepted handler summary;
- multi-successor, context-sensitive CFG recovery with measured state budgets;
- versioned IR/CFG handoff to METHRA, without rebuilding a second decompiler.

## Sarin Advisor 8.3 — native forensic continuation

The terminal record identifies a PE file-offset mistake and an unsolved
wait/singleton state. The following commands replace the repeated external
PE section and dump-memory probes. They do **not** bypass a wait condition or
prove the runtime's loaded image matches the on-disk file.

For the lightweight, no-XED/no-Z3 CLI:

```sh
cargo build --release -p angryier-cli --no-default-features --features inspect
./target/release/angryier pe-address advisor_unpacked_state.exe 0x140404e10 16
./target/release/angryier dump-read diag_1892.dmp 0x094464c0 64
```

The first command should report the mapped section, RVA and original
file offset (verify the transcript's reported 0x404e10 -> 0x404410 with
your exact PE file). The second opens MINIDUMP_MEMORY_LIST (5) or
MINIDUMP_MEMORY64_LIST (9) **without loading the whole dump** and reads
only the requested captured bytes. If the target heap page is missing,
the reader returns `MissingCapture` with the exact first absent address.

The file mapping and memory dump are distinct evidence sources. A dump
may reflect a rebased, unpacked or patched image; translating a VA through
the original PE tells you only where original file bytes reside. Do not
substitute one for the other without matching image hashes, load bases,
code-page versions and timestamps.

Relevant native APIs:

- `angryier_loader::addresses::PeAddressMap::{parse,locate_va,file_offset,bytes_at_va}`
- `angryier_loader::minidump::MiniDumpMemory` (borrowed in-memory captures)
- `angryier_loader::minidump_file::MiniDumpFile` (streaming large dump files)
- `angryier_cfg::xrefs::XrefIndex::{from_cfg,callers_of,to,from}`
- `Runtime::inspect_xrefs_window` for source-backed direct and RIP-relative
  references in a bounded executable region.

Still missing for exact execution-state replay: thread-context selection,
module mappings and relocations, page protection/version snapshots, Windows
TEB/PEB/loader state, lock/event handle models and a partial-page unknown
policy. The capture reader alone does not safely initialize an
`angryier_runtime::Process`. Keep this work separate from guessed
singleton-object values.

The observed wait at 0x140404e10 and the two conflicting reported R8 values
must be correlated to one exact dump/thread/timepoint. This branch does not
claim that the wait predicate or GDI+ continuation has been solved.

## Explicitly not yet implemented

- Automatic virtual-PC discovery with runtime-state confirmation;
- automatic encrypted-bytecode/key recovery or Themida-version fingerprints;
- full VM handler execution/summarization from binary input;
- Windows live-process checkpoint import, capture or anti-debug handling;
- arbitrary indirect-target resolution, complete virtual CFG or C output;
- proof of general Themida/VMProtect support.

The most useful next step is an **AngryIR handler-effect collector**, so
`vm_effects` can receive complete and defensible read/write effect sets
without relying on manual or script-generated sink lists. It should validate
summaries by replay before allowing them to replace interpreter execution.

## Design constraints

Keep this feature opt-in, keep every ambiguous edge unresolved, preserve the
`PROVE/EXPLORE/HUNT` fidelity distinction, and record exact versioned input
identity. Reuse ISANITY and Angryier semantics, METHRA orchestration, and
QIHSE evidence storage rather than introducing another ISA, scheduler,
database, or decompiler.
