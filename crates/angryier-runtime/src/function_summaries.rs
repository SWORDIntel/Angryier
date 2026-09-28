//! Function summaries (Phase 10 remainder — roadmap §5 item 8).
//!
//! The loop-summary half of item 8 collapses pure induction loops; this
//! module is the function counterpart: a callee that qualifies as a **pure
//! function** — straight-line body, register-only computation, arguments the
//! only inputs, no memory effects — collapses a call site into one symbolic
//! step. The first call at a given argument *shape* executes the body in a
//! scratch evaluator over placeholder symbols and caches the resulting
//! expression **template**; every further call substitutes the caller's live
//! argument expressions into the template (the hash-consed arena folds
//! concrete arguments at intern time), turning repeated calls into O(1)
//! expression rewrites instead of re-execution.
//!
//! Soundness policy (mirrors the loop summaries' "a wrong summary is worse
//! than no summary"):
//!
//! - **Extraction** (`Runtime::function_summaries`) accepts only a
//!   straight-line body (single block or an unconditional-jump chain ending
//!   in `ret`) whose instructions have no memory/address-generation operands
//!   and are not control transfers. This filter is advisory — it keeps
//!   hopeless candidates cheap to reject.
//! - **The lowered-IR scan is the real gate.** Each body instruction is
//!   lowered through the same `Runtime::lower_at` path the engines execute,
//!   and its AngryIR is scanned: any `Load`/`Store` (memory effect),
//!   `Branch` (internal control flow), `Call`/`JumpIndirect`/`Trap` (side
//!   effects), or `PreserveParent` register write (a partial write the
//!   template cannot carry) rejects the candidate — independent of any form
//!   table.
//! - **Dynamic purity check.** The scratch evaluator seeds only the seed
//!   registers with placeholder symbols. Any *additional* symbol created
//!   during the body evaluation means the body read a register outside the
//!   seed set; that register is added to the seed set and the evaluation
//!   retries (bounded) — a template over more inputs is still exact, since
//!   every input substitutes the caller's live value at apply time. The
//!   usual discovery is rflags: the providers implement flag writes as
//!   read-modify-write, so any flag-writing body "reads" the incoming
//!   flags, and the template then carries the flags effect exactly.
//! - **Exact register delta.** The template records the final symbolic value
//!   of rax plus every register the body wrote (flags included, when the
//!   lowered semantics write them) — substitution reproduces precisely the
//!   register effects stepping would have produced.
//! - **No memory.** The scan guarantees the body cannot load or store, so
//!   replacing the call/`ret` pair — which would push a frame and pop it —
//!   with a direct register effect leaves memory untouched: rsp is
//!   net-zero, and bytes below rsp are dead by the calling convention (a
//!   caller cannot observe the skipped frame write; red-zone contents are
//!   unspecified once the callee returns).

use std::collections::BTreeMap;

use angryier_arch::{DecodedInstruction, Decoder, OperandKind};
use angryier_arch_intel64::register_id;
use angryier_execution::{SymbolicEvaluator, SymbolicSessionMemory, SymbolicStateSnapshot};
use angryier_expr::{ExprNode, ExprOp, ExprSort};
use angryier_ir::{IrOp, IrType, RegisterWriteKind};
use angryier_memory::LayeredMemory as _;
use angryier_types::fx::FxHashMap;
use angryier_types::{Address, ExprId};

use crate::{Process, Runtime, SymbolicSession, SymbolicStepOutcome};

/// RAX — the return-value register of both the System V and Microsoft x64
/// conventions, and an implicit input of every summary (a body that never
/// writes rax returns the caller's rax unchanged).
const RAX: u32 = register_id::GPR_BASE;
/// RFLAGS — excluded from a summary's register delta. Flags are
/// caller-saved: the x86-64 ABIs leave them undefined after a call, so no
/// conforming program can observe their post-call value. Carrying them is
/// also unbounded in practice — the flag providers compose each write from
/// the incoming flags, so a carried flags effect multiplies the template
/// DAG on every application and overflows the solver's recursive
/// expression translator within a handful of calls.
const RFLAGS: u32 = register_id::RFLAGS.0;

/// Immediate marker for summary placeholder symbols. Real evaluator symbols
/// carry their sequential id in the immediate; this value sits in a range
/// sequential ids cannot reach, so a placeholder can never collide with a
/// live input symbol in the hash-consed arena.
fn placeholder_immediate(slot: usize) -> Vec<u8> {
    (0xFFFF_FFFF_0000_0000u64 | slot as u64).to_le_bytes().to_vec()
}

/// Instruction budget for one summarized function body.
const MAX_FN_BODY_INSNS: usize = 64;
/// Template cache cap — shapes beyond this keep stepping (bounded memory).
const TEMPLATE_CACHE_CAP: usize = 1024;
/// Seed budget per template: base arguments plus discovered inputs (flag
/// read-modify-writes are the common discovery). Beyond this the summary is
/// refused — the shape keeps stepping.
const MAX_SUMMARY_SEEDS: usize = 8;

/// A callee that qualifies as a pure function: a straight-line instruction
/// sequence (entry → … → `ret`, block links dropped) with no memory or
/// control-transfer instructions on its operand surface. Produced by
/// [`Runtime::function_summaries`].
#[derive(Clone, Debug)]
pub struct FunctionSummary {
    /// Callee entry address (the call target this summary is keyed by).
    pub entry: Address,
    /// The straight-line body in execution order, terminating with `ret`.
    /// The `ret` itself is a marker only — the template build evaluates the
    /// body *without* it (a `ret` lowers to a stack load the template does
    /// not model; skipping the call-frame push and `ret` pop leaves rsp
    /// net-zero and writes nothing the calling convention keeps alive).
    pub insns: Vec<DecodedInstruction>,
    /// Dropped chain-link jump addresses keyed by the index of the kept
    /// instruction that precedes the link — the lowered IR of that
    /// instruction jumps to the link address, and the template build's IR
    /// scan accepts exactly that (plus the fall-through and the final ret).
    pub chain_jumps: BTreeMap<usize, Address>,
    /// Registers the body may read on its operand surface (canonical parent
    /// ids), excluding rax — rax is always an implicit summary input.
    pub reads: Vec<u32>,
    /// Body length — the depth input of the placeholder cost model.
    pub depth: u64,
    /// Widest register operand — the width input of the cost model.
    pub width: u16,
}

impl FunctionSummary {
    /// The base registers substituted into a summary template, in canonical
    /// order: rax first (return-value passthrough), then the read set. The
    /// template may carry more inputs than this — registers discovered
    /// during the build (flags) are listed in the template's placeholders.
    pub fn arg_registers(&self) -> Vec<u32> {
        let mut regs = vec![RAX];
        regs.extend(self.reads.iter().copied().filter(|&r| r != RAX));
        regs
    }
}

/// The cached body of a pure function: the register delta as expressions
/// over the placeholder symbols, plus the placeholders themselves.
#[derive(Clone, Debug)]
pub struct FunctionTemplate {
    /// `(register, expression over placeholders, IR type)` — always includes
    /// rax (the return value), plus every register the body wrote. Applying
    /// the template writes exactly these registers, which is precisely the
    /// register effect of executing the body.
    pub effects: Vec<(u32, ExprId, IrType)>,
    /// `(register, placeholder expression)` per seed input — the base
    /// arguments plus build-time discoveries, in seed order.
    pub placeholders: Vec<(u32, ExprId)>,
}

/// Placeholder merge-cost model seam — the interface the real multifactor
/// merge-cost model (Phase 10 remaining) slots into.
///
/// The decision this models is summarize-vs-inline: summarizing trades
/// per-call re-execution (steps, forks, state growth) for a larger symbolic
/// expression that solvers must carry. The default [`DepthWidthCostModel`]
/// prices the summary side of that trade with a **depth × width**
/// heuristic; a future implementation weighs the other side too (call-site
/// frequency, loop-nesting factor of the callers, live state count, and the
/// solver's measured cost per expression node). The trait — not the
/// heuristic — is the contract.
pub trait FunctionSummaryCostModel: std::fmt::Debug + Send + Sync {
    /// Whether `candidate` should be summarized at its call sites (true) or
    /// left to inline stepping (false).
    fn should_summarize(&self, candidate: &FunctionSummary) -> bool;
    /// Estimated symbolic-expression cost of summarizing `candidate`, for
    /// ranking candidates once multiple models compete (unused by the
    /// engine today; part of the seam).
    fn summary_cost(&self, candidate: &FunctionSummary) -> u64;
}

/// The placeholder heuristic: **depth × width**.
///
/// `depth` is the body instruction count — each instruction's semantics
/// compose into the result expression, so it proxies both the expression
/// size a solver sees and the step count summarization saves (the two scale
/// together for straight-line bodies). `width` is the widest register
/// operand in bits — the solver-domain factor (a 64-bit multiply costs a
/// solver far more than an 8-bit one). The product is capped:
/// `should_summarize` holds while `depth × width ≤ max_summary_cost`, so a
/// 64-instruction all-64-bit helper sits exactly at the default budget and
/// anything smaller passes. The cap exists to keep the *symbolic* cost from
/// erasing the *step* win on solvers — it is deliberately coarse, and every
/// threshold failure means plain stepping, never an approximation.
#[derive(Clone, Debug)]
pub struct DepthWidthCostModel {
    /// Budget for `depth × width`; candidates above it keep stepping.
    pub max_summary_cost: u64,
}

impl Default for DepthWidthCostModel {
    fn default() -> Self {
        Self {
            max_summary_cost: u64::from(MAX_FN_BODY_INSNS as u32) * 64,
        }
    }
}

impl FunctionSummaryCostModel for DepthWidthCostModel {
    fn should_summarize(&self, candidate: &FunctionSummary) -> bool {
        candidate.depth >= 1 && self.summary_cost(candidate) <= self.max_summary_cost
    }

    fn summary_cost(&self, candidate: &FunctionSummary) -> u64 {
        candidate.depth * u64::from(candidate.width)
    }
}

impl<D: Decoder> Runtime<D> {
    /// Recovers the image CFG and extracts pure-function candidates: every
    /// CFG function whose body is a straight-line chain of register-only
    /// instructions ending in `ret`. Companion to [`Runtime::loop_summaries`]
    /// — same recovery, same conservative posture; candidates that fail the
    /// session-side IR scan (see module docs) simply never summarize.
    pub fn function_summaries(&self, process: &Process) -> Vec<FunctionSummary> {
        use angryier_cfg::recover;
        let mut out = Vec::new();
        let regions: Vec<(u64, Vec<u8>)> = process
            .state
            .memory
            .regions()
            .iter()
            .filter(|r| r.executable)
            .filter_map(|r| {
                let bytes = crate::read_concrete_bytes(process, r.base, r.size.min(1 << 22)).ok()?;
                Some((r.base, bytes))
            })
            .collect();
        for (base, bytes) in &regions {
            let Ok(cfg) = recover(&self.decoder, *base, bytes, process.entry, |i| i.form_id) else {
                continue;
            };
            for function in cfg.functions() {
                let Some(summary) = extract_pure_function(&cfg, &function) else {
                    continue;
                };
                out.push(summary);
            }
        }
        out
    }
}

impl<D: Decoder> Runtime<D> {
    /// [`Runtime::function_summaries`] restricted to one callee: CFG
    /// recovery seeded at `entry` (a resolved indirect-call target the
    /// static pass could not see), then the same straight-line pure-body
    /// extraction. `None` when the target is not a pure function.
    pub fn function_summaries_seeded(&self, process: &Process, entry: Address) -> Option<FunctionSummary> {
        use angryier_cfg::recover_multi;
        let regions: Vec<(u64, Vec<u8>)> = process
            .state
            .memory
            .regions()
            .iter()
            .filter(|r| r.executable && r.base <= entry && entry < r.base.saturating_add(r.size))
            .filter_map(|r| {
                let bytes = crate::read_concrete_bytes(process, r.base, r.size.min(1 << 22)).ok()?;
                Some((r.base, bytes))
            })
            .collect();
        for (base, bytes) in &regions {
            let Ok(cfg) = recover_multi(&self.decoder, *base, bytes, [entry], |i| i.form_id) else {
                continue;
            };
            let function = angryier_cfg::Function {
                entry,
                blocks: cfg.blocks.keys().copied().collect(),
                returns: Vec::new(),
            };
            if let Some(summary) = extract_pure_function(&cfg, &function) {
                return Some(summary);
            }
        }
        None
    }
}

/// Operand-surface purity: no memory or address-generation operands, no
/// far pointers. This is the cheap advisory filter; the lowered-IR scan in
/// the session is the binding one.
fn operand_surface_pure(insn: &DecodedInstruction) -> bool {
    use angryier_semantics_intel64::forms as f;
    // Control transfers and stack operations are never pure body members.
    if matches!(
        insn.form_id,
        f::CALL_REL32
            | f::CALL_INDIRECT_R64
            | f::CALL_INDIRECT_MEM64
            | f::JMP_REL32
            | f::JMP_INDIRECT_R64
            | f::JMP_INDIRECT_MEM64
            | f::RET
            | f::PUSH_R64
            | f::POP_R64
            | f::PUSH_IMM8
            | f::PUSH_IMM32
            | f::JZ_REL32
            | f::JNZ_REL32
            | f::JC_REL32
            | f::JNC_REL32
            | f::JS_REL32
            | f::JNS_REL32
            | f::JO_REL32
            | f::JNO_REL32
            | f::JPE_REL32
            | f::JPO_REL32
            | f::JL_REL32
            | f::JGE_REL32
            | f::JLE_REL32
            | f::JG_REL32
            | f::JA_REL32
            | f::JB_REL32
            | f::JBE_REL32
            | f::JAE_REL32
    ) || insn.form_id == crate::SYSCALL_FORM_ID
        || insn.form_id == crate::CPUID_FORM_ID
    {
        return false;
    }
    insn.operands
        .iter()
        .all(|operand| matches!(operand.kind, OperandKind::Register(_) | OperandKind::Immediate(_)))
}

/// Walks a CFG function's straight-line body: entry block, then blocks
/// linked only by single fall-through/unconditional edges, ending at a
/// `ret` block. Any conditional edge, call, indirect transfer, or missing
/// block rejects the function. Returns the concatenated instructions with
/// chain-link jumps dropped (they have no state effect); their addresses
/// are recorded in `chain_jumps` because the preceding instruction's
/// lowered IR jumps there.
fn extract_pure_function(cfg: &angryier_cfg::Cfg, function: &angryier_cfg::Function) -> Option<FunctionSummary> {
    use angryier_cfg::EdgeKind;
    use angryier_semantics_intel64::forms as f;
    let mut chain = vec![function.entry];
    let mut current = function.entry;
    loop {
        let block = cfg.blocks.get(&current)?;
        let last = block.instructions.last()?.address;
        if block.terminator == EdgeKind::Return {
            break;
        }
        // Exactly one static successor, reached without condition or call.
        let successors: Vec<&angryier_cfg::CfgEdge> = cfg
            .edges
            .iter()
            .filter(|edge| edge.from == last && edge.to.is_some())
            .collect();
        if successors.len() != 1 {
            return None;
        }
        let edge = successors.first()?;
        if !matches!(edge.kind, EdgeKind::FallThrough | EdgeKind::Unconditional) {
            return None;
        }
        let next = edge.to?;
        if chain.len() > MAX_FN_BODY_INSNS {
            return None;
        }
        chain.push(next);
        current = next;
    }
    // Concatenate, dropping the unconditional jumps that chain blocks. The
    // final `ret` is the body's terminator — allowed (and required) exactly
    // there; every other instruction must be operand-surface pure.
    let mut insns: Vec<DecodedInstruction> = Vec::new();
    let mut chain_jumps: BTreeMap<usize, Address> = BTreeMap::new();
    let mut reads = BTreeMap::new();
    let mut width = 0u16;
    for (i, &start) in chain.iter().enumerate() {
        let block = cfg.blocks.get(&start)?;
        let count = block.instructions.len();
        for (j, insn) in block.instructions.iter().enumerate() {
            let links_next = j + 1 == count && i + 1 < chain.len() && insn.form_id == f::JMP_REL32;
            if links_next {
                chain_jumps.insert(insns.len().saturating_sub(1), insn.address);
                continue;
            }
            let is_final_ret = i + 1 == chain.len() && j + 1 == count;
            if is_final_ret {
                if insn.form_id != f::RET {
                    return None;
                }
            } else if !operand_surface_pure(insn) {
                return None;
            }
            for operand in &insn.operands {
                if let OperandKind::Register(view) = &operand.kind {
                    match operand.access {
                        angryier_arch::AccessKind::Read | angryier_arch::AccessKind::ReadWrite => {
                            reads.insert(view.parent.0, ());
                        }
                        angryier_arch::AccessKind::Write => {}
                    }
                    width = width.max(operand.width_bits);
                }
            }
            insns.push(insn.clone());
        }
        if insns.len() > MAX_FN_BODY_INSNS {
            return None;
        }
    }
    if insns.is_empty() || insns.last()?.form_id != f::RET {
        return None;
    }
    Some(FunctionSummary {
        entry: function.entry,
        depth: insns.len() as u64,
        width: if width == 0 { 64 } else { width },
        reads: reads.into_keys().collect::<Vec<u32>>(),
        insns,
        chain_jumps,
    })
}

/// Rewrites `expr` replacing placeholder leaves per `binding` (arena-node
/// identity, which hash-consing makes structural). Memoized per
/// application; the arena folds any newly-constant results at intern time,
/// so substituting concrete arguments yields a concrete return value.
pub fn substitute_expression(
    arena: &angryier_execution::SymbolicArena,
    expr: ExprId,
    binding: &FxHashMap<ExprId, ExprId>,
    memo: &mut FxHashMap<ExprId, ExprId>,
    depth: u32,
) -> Option<ExprId> {
    if depth > 4096 {
        return None;
    }
    if let Some(&bound) = binding.get(&expr) {
        return Some(bound);
    }
    if let Some(&cached) = memo.get(&expr) {
        return Some(cached);
    }
    let node = arena.get(expr)?;
    if node.operands.is_empty() {
        memo.insert(expr, expr);
        return Some(expr);
    }
    let mut rewritten = Vec::with_capacity(node.operands.len());
    for child in &node.operands {
        rewritten.push(substitute_expression(arena, *child, binding, memo, depth + 1)?);
    }
    let rebuilt = arena
        .intern(ExprNode {
            sort: node.sort,
            op: node.op,
            operands: rewritten,
            immediate: node.immediate,
        })
        .ok()?;
    memo.insert(expr, rebuilt);
    Some(rebuilt)
}

impl<'a, D: Decoder> SymbolicSession<'a, D> {
    /// Computes pure-function candidates for the loaded image and enables
    /// call-site collapsing: a call whose callee qualifies and whose
    /// arguments are concrete-or-trackable runs once per argument *shape*
    /// (callee entry + argument widths), then reuses the cached expression
    /// template. Companion to [`SymbolicSession::enable_loop_summaries`].
    pub fn enable_function_summaries(&mut self) {
        if let Some(state) = self.states.first() {
            let summaries = self
                .runtime
                .function_summaries(&state.process)
                .into_iter()
                .map(|s| (s.entry, std::sync::Arc::new(s)))
                .collect::<BTreeMap<_, _>>();
            self.function_summaries = summaries;
        }
    }

    /// Installs a merge-cost model (summarize-vs-inline seam). The default
    /// is [`DepthWidthCostModel`].
    pub fn set_function_summary_cost_model(&mut self, model: std::sync::Arc<dyn FunctionSummaryCostModel>) {
        self.summary_cost_model = model;
    }

    /// How many call sites were satisfied from a summary template (evidence
    /// counter for benchmarks and tests).
    pub fn function_summary_hits(&self) -> u64 {
        self.function_summary_hits
    }

    /// How many templates were built (each corresponds to one re-executed
    /// body per argument shape).
    pub fn function_summary_builds(&self) -> u64 {
        self.function_summary_builds
    }

    /// The caller's live value for one seed register: the symbolic binding
    /// when present, otherwise the concrete shadow interned as a 64-bit
    /// constant (constants substitute into templates and fold).
    fn resolve_argument(&self, index: usize, register: u32) -> Option<(ExprId, u16)> {
        let state = self.states.get(index)?;
        if let Some((expr, ty)) = state.registers.get(&register) {
            let width = match ty {
                IrType::Bits(w) => *w,
                _ => 64,
            };
            return Some((*expr, width));
        }
        let value = state
            .concrete_registers
            .get(&register)
            .copied()
            .or_else(|| state.process.read_register(register).ok())?;
        let expr = self
            .arena
            .intern(ExprNode {
                sort: ExprSort::BitVec(64),
                op: ExprOp::Constant,
                operands: Vec::new(),
                immediate: value.to_le_bytes().to_vec(),
            })
            .ok()?;
        Some((expr, 64))
    }

    /// Attempts to collapse a call at `index` to `target`: applies a cached
    /// template, or builds one by executing the body once in a scratch
    /// evaluator over placeholder arguments. `None` means "keep stepping" —
    /// the caller executes the call normally, exactly as without summaries.
    pub(crate) fn try_function_summary(
        &mut self,
        index: usize,
        target: Address,
        ret_addr: Address,
    ) -> Option<SymbolicStepOutcome> {
        // SimProcedure hook addresses (kernel-return stubs, the exit hook)
        // are NOT pure functions: their body is a bare `ret` cell whose
        // observable effect is the kernel-model dispatch. Summarizing them
        // would silently skip the model (pool allocations, status results)
        // and diverge the symbolic path from concrete — real drivers hit
        // this on every `call [IAT]`. Refuse, so stepping reaches the stub
        // and the top-of-step SimProcedure dispatch runs the model.
        let process = self.states.get(index)?;
        if process.process.simproc_hooks.contains_key(&target)
            || process.process.simproc_instances.contains_key(&target)
        {
            return None;
        }
        // An empty map does not bail: indirect-only callees never appear in
        // the static pass, so an unseen target earns one lazy extraction.
        if self.function_summaries.is_empty() && self.lazy_summary_targets.contains(&target) {
            return None;
        }
        let summary = match self.function_summaries.get(&target) {
            Some(summary) => summary.clone(),
            // Indirect-only callees never appear in the static call-edge
            // pass (the CFG records IndirectCall edges target-less), so a
            // resolved indirect target gets one lazy per-target extraction;
            // failures are remembered so the cost is paid once.
            None => {
                if !self.lazy_summary_targets.insert(target) {
                    return None;
                }
                let process = self.states.get(index)?.process.clone();
                let summary = self.runtime.function_summaries_seeded(&process, target)?;
                self.function_summaries.insert(target, std::sync::Arc::new(summary));
                self.function_summaries.get(&target)?.clone()
            }
        };
        if !self.summary_cost_model.should_summarize(&summary) {
            return None;
        }
        // Base argument registers (rax + the static read set); their widths
        // form the shape key. Registers the lowered IR reads beyond the base
        // (flag read-modify-writes are the common case) are discovered
        // during the first build and carried inside the template, so the
        // cache key stays a property of the call shape, not of discovery.
        let base_regs = summary.arg_registers();
        let mut widths: Vec<u16> = Vec::with_capacity(base_regs.len());
        for reg in &base_regs {
            let (_, width) = self.resolve_argument(index, *reg)?;
            widths.push(width);
        }
        let key = (target, widths);
        if let Some(template) = self.function_templates.get(&key).cloned() {
            return self.apply_template(index, &template, ret_addr);
        }
        if self.failed_templates.contains(&key) || self.function_templates.len() >= TEMPLATE_CACHE_CAP {
            return None;
        }
        let Some(template) = self.build_function_template(target, index, &base_regs) else {
            // Either impure or beyond the seed budget: this shape keeps
            // stepping, and the negative cache makes the cost once-per-shape.
            self.failed_templates.insert(key);
            return None;
        };
        self.function_templates.insert(key, template.clone());
        self.function_summary_builds += 1;
        self.apply_template(index, &template, ret_addr)
    }

    /// Executes the body once in a scratch evaluator over placeholder
    /// symbols and captures the register delta. Every gate below is
    /// fail-closed: anything the template cannot represent exactly returns
    /// `None` and the shape keeps stepping.
    ///
    /// The body is evaluated with ONLY the seed registers bound; registers
    /// the lowered IR reads beyond them (the providers implement flag
    /// writes as read-modify-write of rflags, so any flag-writing body
    /// "reads" the incoming flags) are discovered from the evaluator's own
    /// symbol table and seeded on a retry — a template over MORE inputs is
    /// still exact, because every input substitutes the caller's live value
    /// at apply time. Lowering is cached on the process, so retries pay
    /// only re-evaluation.
    fn build_function_template(
        &mut self,
        target: Address,
        index: usize,
        base_regs: &[u32],
    ) -> Option<FunctionTemplate> {
        let summary = self.function_summaries.get(&target)?.clone();
        let arena = self.arena;
        let body_len = summary.insns.len().checked_sub(1)?;
        let ret_address = summary.insns.last()?.address;

        let mut seed_regs: Vec<u32> = base_regs.to_vec();
        loop {
            // Seed the scratch evaluator with placeholders — ONLY the seed
            // registers. Reads of anything else auto-symbol and are picked
            // up below, so "arguments are the only inputs" is enforced by
            // execution, not by trusting the static read set.
            let mut placeholders = Vec::with_capacity(seed_regs.len());
            let mut seeded = BTreeMap::new();
            for (slot, reg) in seed_regs.iter().enumerate() {
                let (expr, width) = self.resolve_argument(index, *reg)?;
                let width = match arena.sort_of(expr) {
                    Some(ExprSort::BitVec(w)) if w == width => w,
                    _ => return None,
                };
                let placeholder = arena
                    .intern(ExprNode {
                        sort: ExprSort::BitVec(width),
                        op: ExprOp::Symbol,
                        operands: Vec::new(),
                        immediate: placeholder_immediate(slot),
                    })
                    .ok()?;
                seeded.insert(*reg, (placeholder, IrType::Bits(width)));
                placeholders.push((*reg, placeholder));
            }
            let mut evaluator = SymbolicEvaluator::new(arena);
            evaluator.restore(&SymbolicStateSnapshot {
                registers: seeded,
                concrete_registers: BTreeMap::new(),
                constraints: Vec::new(),
                symbols: Vec::new(),
                expr_concrete: BTreeMap::new(),
            });
            let mut scratch_memory =
                SymbolicSessionMemory::new(angryier_memory::PersistentMemory::new(Vec::new()).ok()?);

            // Walk the straight-line body through the engine's own lowering
            // — identical semantics to stepping — scanning each lowered
            // block for operations the template cannot carry. The trailing
            // `ret` is NOT evaluated: it lowers to a stack load of the
            // return frame, and the template replaces the whole push/ret
            // pair (net-zero rsp, no observable memory effect — see the
            // module docs).
            let mut written: Vec<u32> = Vec::new();
            for (i, insn) in summary.insns.iter().take(body_len).enumerate() {
                let process = &mut self.states.get_mut(index)?.process;
                let (ir_block, _) = self.runtime.lower_at(process, insn.address, insn).ok()?;
                let last_body_insn = i + 1 == body_len;
                for ir in &ir_block.instructions {
                    match &ir.op {
                        IrOp::Constant { .. }
                        | IrOp::ExprRef { .. }
                        | IrOp::ReadRegister { .. }
                        | IrOp::Primitive { .. } => {}
                        IrOp::WriteRegister {
                            kind: RegisterWriteKind::PreserveParent { .. },
                            ..
                        } => return None, // partial write — not representable
                        IrOp::WriteRegister { register, .. } => {
                            if !written.contains(register) {
                                written.push(*register);
                            }
                        }
                        IrOp::Jump { target } => {
                            // Providers emit an explicit jump per
                            // instruction: to the next kept instruction
                            // (fall-through), to a dropped chain-link jump,
                            // or — from the last body instruction — to the
                            // `ret`. Anything else means the body is not
                            // the straight-line shape that was extracted.
                            let ok = if last_body_insn {
                                *target == ret_address
                            } else {
                                summary.insns.get(i + 1).map(|next| next.address) == Some(*target)
                                    || summary.chain_jumps.get(&i) == Some(target)
                            };
                            if !ok {
                                return None;
                            }
                        }
                        // Memory effects, control flow, traps, calls: no template.
                        _ => return None,
                    }
                }
                let block_summary = evaluator.eval_block_with_memory(&ir_block, &mut scratch_memory).ok()?;
                // A branch here would mean the body is not straight-line;
                // the scan already rejects the op, but treat any reported
                // branch as a hard stop as well.
                if block_summary.branch.is_some() {
                    return None;
                }
            }

            // Dynamic purity: the scratch evaluator must have created no
            // symbols beyond the placeholders — any extra symbol is a read
            // of a register outside the seed set. Reseed and retry (bounded)
            // instead of refusing: the result then depends on MORE inputs,
            // each substituted from the caller's live state — still exact.
            if evaluator.symbols().is_empty() {
                // Capture the register delta: rax always (return value,
                // possibly the caller's rax passed through), plus every
                // caller-clobber GPR the body wrote. Flags are excluded —
                // caller-saved per the ABIs (see the RFLAGS notes above);
                // rsp/rip cannot be written by a scanned body.
                let snapshot = evaluator.snapshot();
                let mut effects = Vec::with_capacity(written.len() + 1);
                let seeds = written
                    .into_iter()
                    .filter(|&r| r != RAX && r != RFLAGS && r != register_id::RIP.0);
                for reg in std::iter::once(RAX).chain(seeds) {
                    let (expr, ty) = snapshot.registers.get(&reg).copied()?;
                    effects.push((reg, expr, ty));
                }
                return Some(FunctionTemplate { effects, placeholders });
            }
            let mut extras: Vec<u32> = evaluator.symbols().iter().map(|binding| binding.register).collect();
            extras.sort_unstable();
            extras.dedup();
            let fresh: Vec<u32> = extras.into_iter().filter(|reg| !seed_regs.contains(reg)).collect();
            if fresh.is_empty() || seed_regs.len() + fresh.len() > MAX_SUMMARY_SEEDS {
                return None;
            }
            seed_regs.extend(fresh);
        }
    }

    /// Substitutes the caller's live arguments into the template and commits
    /// the register delta. The template carries its full seed list (base
    /// arguments plus build-time discoveries), so application re-resolves
    /// every placeholder from the caller's live state; a width drift means
    /// the shape changed under the cache — fail closed. No memory is
    /// touched (the scan guarantees the body cannot), so skipping the frame
    /// push/pop leaves state identical to stepping while the pc lands
    /// directly on the return address.
    fn apply_template(
        &mut self,
        index: usize,
        template: &FunctionTemplate,
        ret_addr: Address,
    ) -> Option<SymbolicStepOutcome> {
        let arena = self.arena;
        let mut binding: FxHashMap<ExprId, ExprId> = FxHashMap::default();
        for (reg, placeholder) in &template.placeholders {
            let width = match arena.sort_of(*placeholder) {
                Some(ExprSort::BitVec(w)) => w,
                _ => return None,
            };
            let (expr, resolved) = self.resolve_argument(index, *reg)?;
            if resolved != width {
                return None; // shape drift — fail closed
            }
            binding.insert(*placeholder, expr);
        }
        let mut committed: Vec<(u32, ExprId, IrType)> = Vec::with_capacity(template.effects.len());
        {
            let mut memo: FxHashMap<ExprId, ExprId> = FxHashMap::default();
            for (reg, expr, ty) in &template.effects {
                let actual = substitute_expression(arena, *expr, &binding, &mut memo, 0)?;
                committed.push((*reg, actual, *ty));
            }
        }
        let state = &mut self.states[index];
        for (reg, expr, ty) in committed {
            state.registers.insert(reg, (expr, ty));
            // The concrete shadow only takes a value when the substituted
            // expression folds — exactly the loop-summary write-back policy.
            if let Ok(value) = angryier_execution::constant_value(arena, expr) {
                state.concrete_registers.insert(reg, value);
                let _ = state.process.write_register(reg, value);
            }
        }
        let _ = state.process.write_pc(ret_addr);
        self.function_summary_hits += 1;
        Some(SymbolicStepOutcome::Stepped { next_pc: ret_addr })
    }
}
