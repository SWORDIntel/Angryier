# Angryier — active cross-session engineering checkpoint

**Updated:** 2026-10-15 (UK date)  
**Purpose:** Shared, privacy-safe handoff between independent ChatGPT sessions and devices.  
**Scope:** Angryier core engine and experimental VM-analysis pipeline, not a target-specific bypass.  
**Canonical PR:** https://github.com/SWORDIntel/Angryier/pull/1  
**Last verified implementation head before this checkpoint:** `221be5fc7e3018b361228a6cfdf8916d890de1c9`  
**Target branch:** `feat/themida-vm-structural-20261015`  
**Base `main`:** `b3df3e55d9604252b27ea4e1d67bb6367294d9b4`

> This is a dated checkpoint, not a substitute for checking the current branch/PR/CI. The commit creating this file advances the branch. Check the current Git ref before changing code. Local uncommitted work and separate ChatGPT conversations are not synchronized by GitHub.

## Verified GitHub state before checkpoint

- Branch is 88 commits ahead of `main`, zero behind; PR #1 is open, draft and mergeable. **Nothing from PR #1 was merged into `main`.**
- The focused `Native VM analysis validation` run **38763710027** passed. It covers CFG, expression, loader, models, runtime tests, Lua integration, direct/indirect-call fixtures, CLI and scoped Clippy.
- Full CI run **38763710438** failed at the **format** step. This is still an open quality gate; some formatting backlog predates this PR. Do not report full CI as green.
- The original indirect-call frame fix `b3df3e5` on `main` was incorporated into this branch through a two-parent merge, retaining the updated Lua investigation scripts. No force-push is required.

## Implemented and checked in the shared branch

### Core control-flow fidelity and Win32 environment

- Correct signed RIP-relative/address-generation handling; conservative LEA provenance.
- Indirect-call `mirror_call_frame` from the baseline `b3df3e5`; process-memory and symbolic-frame cooperation.
- Executable-target checking uses current mapped executable regions and explicit runtime hooks rather than target-specific address bands.
- Return-address resynchronization uses a bounded search, refuses multiple eligible stack cells, and records concretization debt; not a formal call-stack proof.
- MS x64 arguments come from RCX/RDX/R8/R9 and stack slots; missing argument evidence is distinguishable from concrete zero.
- Windows event models share handle state and distinguish manual reset, auto reset, signaled, pending/blocked and invalid handles. No deterministic multithread scheduler is implemented.
- The synthetic user-mode IAT stub boundary is guarded in **both** concrete and symbolic execution. In particular, `CreateThread` cannot silently succeed through `RET` or a lazy pure-function summary without an explicit model.
- An approximate scalar `IsProcessorFeaturePresent` result records fidelity debt; it is not authoritative Windows behavior.

### Forensic input and diagnosis

- PE VA/RVA/file-offset mapping distinguishes original file-backed bytes from zero-fill and rejects invalid overlapping mappings.
- Source-backed xref index covers direct call sites, branches and RIP-relative IAT/indirect slots; it does not invent indirect callees.
- In-memory and streaming MINIDUMP_MEMORY_LIST/MEMORY64_LIST readers reject missing captured bytes instead of synthesizing zeroes.
- Atomic, bounded capture overlays support either valid minidump ranges or independently evidence-mapped heap slices, with collision-free persistent-memory object IDs and explicit replay-baseline control.
- `angryier doctor` reports compiled source revision, current checkout revision, build features and running executable SHA-256, masking local paths by default.
- `angryier pe-address`, `angryier pe-imports`, `angryier dump-read` expose forensic data without repeated external Python probes.
- Audited single-step CALL/RET checks preserve pre/post RIP, RSP, concretely known stack-top and the first trace divergence; incomplete stack evidence has an explicit outcome.

### Native VM semantic analysis

- Opt-in `angryier_cfg::vm::inspect_native_cfg` joins existing Themida dispatch classification and candidate VPC heuristics. The findings remain **unverified structural hypotheses**.
- `VmAnalysisSession` stores context-sensitive observed transitions keyed by native PC, virtual PC, state digest and code digest, with bounded resources and no fabricated CFG edges.
- `angryier_expr::vm_effects::reduce_vm_effects` slices from declared observable effects, memory addresses and path guards, with explicit node/source accounting.
- **Newest phone-session work (commit `ac7c6cf4082215450548ee9aa7d4117fdedd550c`, formatting finalized in `221be5fc7e30`):** `crates/angryier-ir/src/vm_footprint.rs` contains the single-block, conservative AngryIR effect collector. It verifies IR, inventories ordered memory writes, potentially faulting reads/masked loads, full/partial register writes, branch/indirect/call/return/trap effects and transitive SSA dependencies. It refuses unsupported/missing producer data and bounded-analysis overruns. Tests passed in focused CI.
- The collector's SSA `IrValueId` **must not** be confused with an expression-arena `ExprId`. No automatic handler summarization/equivalence proof has been claimed.

## Current research / investigation findings

- The investigation corrected a major mistake in raw dump-to-image address mapping. Do not revive the earlier assumption that one specific unregistered data structure was encrypted Themida ciphertext.
- Captured provider/singleton/registration heap objects exist, but recovered pointers are observations rather than verified field semantics.
- The application's bounded wait and provider registration rely on missing modeled environment behavior; executing more symbolic instructions is not by itself a solution.
- The earlier indirect-call corruption was genuine and fixed; synthetic success returns for threading/synchronization were only exploration aids, not a faithful OS.
- The deeper component-manager path still has no proven final GUI success. Do not label application initialization complete.

## Next gates — carry forward in this order

1. **Trace-backed VM handler boundaries:** native PC, VPC, context identity, and exact executable/state/capture identity. No boundary inference from a disassembly census alone.
2. **Multi-block effect collection:** compose single-block AngryIR footprints without losing memory aliasing, faults, conditional effects, register-part preservation or control exits.
3. **Symbolic materialization:** map retained SSA values and memory operations into width-qualified expression IDs under a pinned entry state; reuse Angryier expression arena, not a new symbolic engine.
4. **Validation:** differential replay / SMT equivalence of handler summaries before execution replacement; record incomplete/failing cases and solver budgets.
5. **Virtual CFG export:** use observed, context-sensitive transitions and produce versioned IR/CFG for METHRA; keep high-level decompilation in METHRA.
6. **Windows environment parity:** deterministic user-mode thread creation and scheduling, per-execution-state handle/event registries, accurate user-mode loader/TEB/PEB, and identity-backed dump/thread checkpoint restoration. No invented worker success.
7. **Quality gate:** address formatting and full CI while keeping focused tests green; use an independent evaluation corpus (known VM/normal compiler-switch negative controls) rather than accepting speed or depth as semantic correctness.

## Operational constraints

- Work on the current PR branch; fetch latest branch tip before committing. Avoid blindly merging divergent work.
- Treat reported observations as evidence and distinguish them from hypotheses.
- Prefer reusing ISANITY, AngryIR, existing expression DAG, replay/provenance, QIHSE, and METHRA; no duplicate decoder, database, scheduler or decompiler.
- Keep exploration relaxations opt-in and clearly separated from PROVE fidelity.
- Preserve private analyst data: don't publish hostnames, local account names, credentials, actual IP addresses, raw dumps, user identity or target-specific deployment details in handoff artifacts. Use `#########` wherever an IP would otherwise appear.
- Do not assert ChatGPT conversations have been merged; this GitHub document is a **shared context pointer** only.

## Minimal cross-device recovery command

In another ChatGPT session: **“Read the current `SWORDIntel/Angryier` feature branch and `docs/ACTIVE_ENGINE_HANDOFF.md` using GitHub, then continue PR #1 from its current HEAD. Do not assume any unsynced local checkout changes are on GitHub.”**
