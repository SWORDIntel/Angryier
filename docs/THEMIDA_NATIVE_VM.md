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
