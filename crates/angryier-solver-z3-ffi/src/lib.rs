//! Native Z3 solver backend via FFI to the system libz3.
//!
//! This crate translates Angryier expression trees to Z3 ASTs and uses Z3 to
//! check satisfiability of path constraints. It requires libz3 to be installed
//! (e.g., `libz3-dev` on Debian/Ubuntu).

#![allow(unsafe_code)]

use angryier_expr::{ExprNode, ExprOp, ExprReader, ExprSort};
use angryier_solver::{SolverBackend, SolverQuery, SolverResult};
use angryier_types::{ConstraintId, ExprId, SolverOutcomeKind};
use core::time::Duration;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use z3_sys::*;

/// Entry ceiling for the persistent AST interning cache. On overflow the
/// cache is cleared wholesale (correct — the solver holds its own
/// references to asserted formulas — just a one-query translation hiccup).
const AST_CACHE_CAP: usize = 1 << 20;

/// Error returned by the Z3 FFI bridge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Z3FfiError {
    UnresolvedExpression(ExprId),
    NullAst,
    NullContext,
    UnsupportedSort,
    MalformedExpression,
}

impl core::fmt::Display for Z3FfiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnresolvedExpression(id) => write!(f, "unresolved expression id {}", id.0),
            Self::NullAst => f.write_str("Z3 returned a null AST"),
            Self::NullContext => f.write_str("Z3 returned a null context"),
            Self::UnsupportedSort => f.write_str("unsupported expression sort"),
            Self::MalformedExpression => f.write_str("malformed expression tree"),
        }
    }
}

impl std::error::Error for Z3FfiError {}

/// Native Z3 solver backend.
pub struct Z3FfiBridge {
    reader: Arc<dyn ExprReader>,
    context: Z3_context,
    /// Persistent incremental solver — scopes are pushed one per path
    /// constraint so consecutive queries sharing a constraint prefix
    /// reuse the solver's learned state instead of rebuilding.
    solver: Z3_solver,
    /// Identity + tracking literal per live scope. Scope i asserts
    /// `assumption_i → constraint_i` so UNSAT cores name the culprit
    /// constraints. Scope identity is `(constraint id, expr id)` in the
    /// caller's constraint order — see [`Z3FfiBridge::solve_incremental`]
    /// for why the query's canonical key list cannot serve as identity.
    scopes: Vec<ScopeEntry>,
    /// Persistent translation cache (AST interning): `ExprId -> Z3_ast`.
    /// Z3 hash-conses ASTs within a context, so an AST built for one
    /// query is the identical pointer the same expression needs in any
    /// later query on this bridge; caching it makes repeated translation
    /// of shared subtrees O(new nodes) instead of O(all nodes). Entries
    /// are `Z3_inc_ref`ed and released on eviction/drop.
    ast_cache: HashMap<ExprId, Z3_ast>,
    /// Symbol table for `ExprOp::Symbol` nodes translated so far (same
    /// ASTs as the `ast_cache` entries; kept for model extraction).
    symbol_asts: HashMap<ExprId, Z3_ast>,
    /// Memoized per-subtree symbol sets: the model-extraction universe of
    /// a query is the symbol set reachable from its predicate.
    subtree_symbols: HashMap<ExprId, Arc<[u32]>>,
    /// Timeout param value last installed on the solver, so an unchanged
    /// query timeout doesn't re-set solver params every query.
    installed_timeout_ms: Option<u32>,
    /// Counters describing the most recent solve (diagnostics + tests).
    last_stats: IncrementalStats,
    /// Watchdog thread armed around the check call of a
    /// `solve_with_deadline` solve — `None` unless a check is in flight.
    /// Only ever touched under `&mut self`; see the watchdog commentary
    /// below [`WatchdogFlags`] for the lifetime reasoning.
    watchdog: Option<ArmedWatchdog>,
}

/// One live solver scope: the constraint it asserts (identity pair), and
/// the assumption literal guarding it for UNSAT-core extraction.
struct ScopeEntry {
    cid: angryier_types::ConstraintId,
    expr: ExprId,
    assumption: Z3_ast,
}

/// Counters from the most recent solve on a [`Z3FfiBridge`] — evidence for
/// whether incremental scope reuse is actually engaging:
/// `shared_prefix` scopes survived from the previous query, `popped` were
/// popped, `pushed` were freshly asserted, `translated_nodes` ASTs were
/// built (cache misses), and `cache_entries` are interned overall.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IncrementalStats {
    pub shared_prefix: usize,
    pub popped: usize,
    pub pushed: usize,
    pub translated_nodes: usize,
    pub cache_entries: usize,
}

/// Process-wide knobs (env), read once:
/// - `ANGRYIER_Z3_FFI_NO_SOLVER_TIMEOUT=1`: never install the per-query
///   `timeout` solver param (rely on `solve_with_deadline`'s watchdog for
///   limits). For isolating whether per-query param updates disturb the
///   persistent solver.
fn env_knob(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| !v.is_empty() && v != "0")
}

/// Whether per-solve phase timings should print (`ANGRYIER_Z3_FFI_DEBUG_TIMING`).
fn debug_timing_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| env_knob("ANGRYIER_Z3_FFI_DEBUG_TIMING"))
}

// SAFETY: The caller must ensure single-threaded access to the Z3 context,
// with one documented exception: `Z3_interrupt` (see the watchdog commentary
// below) is Z3's thread-safe cancellation point and is the only context call
// ever made off the owning thread.
unsafe impl Send for Z3FfiBridge {}

// ---------------------------------------------------------------------------
// Mid-flight cancellation watchdog
// ---------------------------------------------------------------------------
//
// `interrupt()` only helps while a Z3 procedure is actually running: measured
// in `tests/preemption_bench.rs`, a *pre-armed* interrupt flag is consumed by
// the API calls that precede the check (translation, pushes), so arming
// before `Z3_solver_check_assumptions` does nothing. `solve_with_deadline`
// therefore arms a watchdog thread immediately *before* the check call and
// retires it immediately *after*, so the interrupt can only ever land on a
// check that is in flight.
//
// Memory-model and lifetime reasoning for the watchdog:
//
// * Pointer validity: `Z3_context` is an opaque handle created in
//   [`Z3FfiBridge::new`] and freed only in `Drop`; its pointer value is
//   stable and valid for the bridge's whole lifetime. The watchdog's only
//   use of the pointer is passing it to `Z3_interrupt`.
// * Why the cross-thread call is safe: `Z3_interrupt` is Z3's documented
//   cancellation point for exactly this pattern — "Interrupt the execution
//   of a Z3 procedure. This procedure can be used to interrupt: solvers,
//   simplifiers and tactics" (`z3_api.h`), and the upstream API docs state
//   it may be invoked from a different thread. It only raises the context's
//   cancel flag; it does not mutate ASTs or solver state, so it cannot race
//   the owning thread's context use into corruption. All other context use
//   stays on the owning thread, preserving this crate's single-threaded
//   access invariant with `Z3_interrupt` as its one documented exception.
// * The bridge always outlives any armed watchdog. Happy path: retirement
//   (disarm + join) happens inside `check_and_extract` while the `&mut self`
//   borrow is live, so the bridge cannot be dropped beneath the thread.
//   Panic path: `Drop` retires any still-armed watchdog (reachable only if a
//   deadline solve panicked between arming and retiring) *before*
//   `Z3_del_context`, so the watchdog can never touch a freed context.
// * Ordering: `disarmed` is stored `Release` before the channel wake and is
//   loaded `Acquire` after the watchdog's sleep expires, so retirement
//   happens-before a would-be firing decision; `fired` is stored `Release`
//   by the watchdog and read after `join`, which itself happens-before the
//   joiner's subsequent accesses. The channel exists so retirement wakes
//   the sleeper immediately — joining never blocks out the rest of the
//   deadline after the check has already returned.
// * Residual race (fundamental to cancelling the canceller): if the check
//   completes in the instant between the watchdog's sleep expiring and the
//   `disarmed` store, the interrupt lands just after the check returned and
//   its flag sits on the context. The preemption bench measured that routine
//   API traffic (translation/push) consumes such a stray flag; worst case a
//   later procedure reports UNKNOWN once — a conservative miss, never a
//   fabricated Sat/Unsat.

/// Flags shared between the owning thread and one armed watchdog.
#[derive(Default)]
struct WatchdogFlags {
    /// Set by the owning thread to retire the watchdog; checked after its
    /// sleep expires — if set, the thread exits without touching the
    /// context.
    disarmed: AtomicBool,
    /// Set by the watchdog iff it actually called `Z3_interrupt`.
    fired: AtomicBool,
}

/// A watchdog thread armed around a single check call.
struct ArmedWatchdog {
    flags: Arc<WatchdogFlags>,
    /// Sending wakes the sleeping watchdog early (retirement handshake).
    disarm_tx: mpsc::Sender<()>,
    handle: std::thread::JoinHandle<()>,
}

/// A `Z3_context` pointer wrapped for its one permitted cross-thread use.
struct InterruptCtx(Z3_context);

impl InterruptCtx {
    /// The watchdog's entire cross-thread use of the context: raise Z3's
    /// cancel flag. A method (not a field access) so closures capture the
    /// whole `Send` wrapper instead of disjoint-capturing its `!Send` field.
    fn interrupt(&self) {
        // SAFETY: `self.0` is the owning bridge's `Z3_context`, valid for
        // the bridge's whole lifetime (freed only in `Drop`, which retires
        // the calling watchdog thread first), and `Z3_interrupt` is
        // documented safe to call from another thread — it only raises the
        // context's cancel flag.
        unsafe { Z3_interrupt(self.0) }
    }
}

// SAFETY: the pointer is only ever dereferenced by being passed to
// `Z3_interrupt`, which Z3 documents as callable from another thread, and it
// stays valid for the bridge's whole lifetime (the arm/retire protocol
// described above guarantees the thread is joined before the context is
// freed), so moving it into the watchdog thread cannot introduce a
// use-after-free.
unsafe impl Send for InterruptCtx {}

impl Z3FfiBridge {
    /// Create a new Z3 FFI bridge with the given expression reader.
    pub fn new(reader: Arc<dyn ExprReader>) -> Result<Self, Z3FfiError> {
        let context = unsafe {
            let config = Z3_mk_config().ok_or(Z3FfiError::NullContext)?;
            let ctx = Z3_mk_context(config);
            Z3_del_config(config);
            let ctx = ctx.ok_or(Z3FfiError::NullContext)?;
            // Z3's default handler prints and exit()s — install a quiet
            // handler so API errors (e.g. push while interrupted) surface as
            // return values instead of killing the process.
            unsafe extern "C" fn quiet_handler(_ctx: Z3_context, _code: Z3_error_code) {}
            Z3_set_error_handler(ctx, Some(quiet_handler));
            ctx
        };
        let solver = unsafe {
            // Z3_mk_solver (the default tactic pipeline). Measured A/B
            // against Z3_mk_simple_solver (raw SMT core): the simple
            // solver is ~1.3x faster per check on the incremental
            // campaign pattern (tests/incremental_reuse_bench.rs), but it
            // cannot solve the Gate C semiprime-factoring family inside
            // its 30 s budget — the tactic pipeline's preprocessing
            // (simplification, solve-eqs) is decisive for hard cold
            // queries, so it stays.
            let s = Z3_mk_solver(context).ok_or(Z3FfiError::NullContext)?;
            Z3_solver_inc_ref(context, s);
            // Assumption-based UNSAT-core extraction.
            if let Some(params) = Z3_mk_params(context) {
                Z3_params_inc_ref(context, params);
                if let Some(key) = Z3_mk_string_symbol(context, c"unsat_core".as_ptr()) {
                    Z3_params_set_bool(context, params, key, true);
                    Z3_solver_set_params(context, s, params);
                }
                Z3_params_dec_ref(context, params);
            }
            s
        };
        Ok(Self {
            reader,
            context,
            solver,
            scopes: Vec::new(),
            ast_cache: HashMap::new(),
            symbol_asts: HashMap::new(),
            subtree_symbols: HashMap::new(),
            installed_timeout_ms: None,
            last_stats: IncrementalStats::default(),
            watchdog: None,
        })
    }

    /// Incremental solve over the persistent solver: pops the scopes past
    /// the longest shared constraint prefix, pushes the suffix, then
    /// checks the predicate in a transient scope.
    ///
    /// Scope identity is `(constraint id, expr id)` at each position of
    /// the caller's constraint order — the order a growing path extends,
    /// so consecutive queries of an append-only path share the full
    /// prefix and each solve pushes exactly one scope. The query's
    /// canonical key list (`constraint_keys`) must NOT be used as scope
    /// identity: `SolverQuery::canonical` returns it sorted and deduped,
    /// so a freshly appended constraint's key (a hash) lands at a
    /// uniformly random rank — the shared prefix collapses to O(1) in
    /// expectation and every query pays a full pop/re-push/re-translate
    /// cycle, which measured as linear per-query cost growth with path
    /// length. Within one arena a constraint's key is a pure function of
    /// its expr, so matching `(id, expr)` implies matching keys.
    fn solve_incremental(&mut self, query: &SolverQuery) -> SolverResult {
        self.solve_incremental_inner(query, None)
    }

    /// Shared body of [`SolverBackend::solve`] and
    /// [`Z3FfiBridge::solve_with_deadline`]: identical translation and
    /// scoping; a `Some(deadline)` additionally arms the mid-flight
    /// cancellation watchdog around the check call itself (see
    /// [`Z3FfiBridge::solve_with_deadline`] for how the two cancellation
    /// mechanisms compose).
    fn solve_incremental_inner(&mut self, query: &SolverQuery, deadline: Option<Duration>) -> SolverResult {
        if query.validate_identity().is_err() {
            return backend_error();
        }
        let ctx = self.context;
        let timing = debug_timing_enabled();
        let started = std::time::Instant::now();
        self.last_stats = IncrementalStats::default();
        // Per-query timeout on the persistent solver — installed only when
        // the value changes, so an unchanged timeout doesn't churn solver
        // params on every query. `ANGRYIER_Z3_FFI_NO_SOLVER_TIMEOUT=1`
        // skips the param entirely; `solve_with_deadline`'s watchdog then
        // remains the only limit (useful to isolate whether per-query
        // param updates disturb the persistent solver's reuse).
        let timeout_ms = query.timeout().as_millis();
        if timeout_ms > 0 && !env_knob("ANGRYIER_Z3_FFI_NO_SOLVER_TIMEOUT") {
            let wanted = u32::try_from(timeout_ms).unwrap_or(u32::MAX);
            if self.installed_timeout_ms != Some(wanted) {
                unsafe {
                    if let Some(params) = Z3_mk_params(ctx) {
                        Z3_params_inc_ref(ctx, params);
                        if let Some(key) = Z3_mk_string_symbol(ctx, c"timeout".as_ptr()) {
                            Z3_params_set_uint(ctx, params, key, wanted);
                            Z3_solver_set_params(ctx, self.solver, params);
                        }
                        Z3_params_dec_ref(ctx, params);
                    }
                }
                self.installed_timeout_ms = Some(wanted);
            }
        }
        let entries = query.constraint_expressions();
        // Longest common prefix of live scopes and this query's
        // constraints, identified positionally by (constraint id, expr id)
        // in the caller's constraint order (see `solve_incremental`).
        let shared = self
            .scopes
            .iter()
            .zip(entries.iter())
            .take_while(|(scope, (cid, expr))| scope.cid == *cid && scope.expr == *expr)
            .count();
        self.last_stats.shared_prefix = shared;
        let excess = self.scopes.len() - shared;
        if excess > 0 {
            unsafe { Z3_solver_pop(ctx, self.solver, excess as u32) };
            // SAFETY: assumption literals are inc_ref'd on push; release
            // the ones leaving the live scope set.
            for scope in self.scopes.drain(shared..) {
                unsafe { Z3_dec_ref(ctx, scope.assumption) };
            }
            self.last_stats.popped = excess;
        }
        // Phase A: translate every new constraint expr BEFORE touching the
        // scope stack — translation only interns ASTs, so a failure leaves
        // the persistent solver's scopes exactly as the previous query
        // left them (no half-pushed state).
        let mut new_asts = Vec::with_capacity(entries.len().saturating_sub(shared));
        for (cid, expr) in entries.iter().skip(shared) {
            match self.translate(*expr) {
                Ok(ast) => new_asts.push((*cid, *expr, ast)),
                Err(_) => return backend_error(),
            }
        }
        let translate_done = if timing { Some(started.elapsed()) } else { None };
        // Phase B: push one scope per new constraint, guarded by a fresh
        // assumption literal so UNSAT cores name the responsible
        // constraints. The literal is created (and checked) before the
        // push so a failure can never leave an untracked scope behind.
        for (cid, expr, ast) in new_asts {
            unsafe {
                let sym_name = std::ffi::CString::new(format!("pc{}", self.scopes.len())).unwrap_or_default();
                let name = Z3_mk_string_symbol(ctx, sym_name.as_ptr());
                let bool_sort = Z3_mk_bool_sort(ctx);
                let assumption = match (name, bool_sort) {
                    (Some(n), Some(s)) => Z3_mk_const(ctx, n, s),
                    _ => None,
                };
                let Some(assumption) = assumption else {
                    return backend_error();
                };
                let Some(imp) = Z3_mk_implies(ctx, assumption, ast) else {
                    Z3_dec_ref(ctx, assumption);
                    return backend_error();
                };
                Z3_solver_push(ctx, self.solver);
                Z3_solver_assert(ctx, self.solver, imp);
                Z3_inc_ref(ctx, assumption);
                self.scopes.push(ScopeEntry { cid, expr, assumption });
                self.last_stats.pushed += 1;
            }
        }
        let push_done = if timing { Some(started.elapsed()) } else { None };
        // Transient scope for the predicate. Translation happens before
        // the push for the same half-push-avoidance reason as Phase A.
        // (Tried: passing the predicate as an extra check ASSUMPTION
        // instead of a scope, to spare Z3 the pop's lemma retraction —
        // measured SLOWER (~30 ms vs ~18 ms mean per query): Z3
        // internalizes a non-atomic assumption by re-asserting it per
        // check. The scoped push/pop is the cheaper of the two.)
        let predicate = query.predicate();
        let failed = match self.translate(predicate) {
            Ok(ast) => {
                unsafe {
                    Z3_solver_push(ctx, self.solver);
                    Z3_solver_assert(ctx, self.solver, ast);
                }
                false
            }
            Err(e) => {
                let mut stack = vec![predicate];
                let mut seen = std::collections::HashSet::new();
                let mut scratch = HashMap::new();
                while let Some(id) = stack.pop() {
                    if !seen.insert(id) {
                        continue;
                    }
                    if let Some(n) = self.reader.read(id) {
                        let res = Self::translate_node(&self.reader, ctx, id, &n, &mut HashMap::new(), &mut scratch);
                        if let Err(e2) = res {
                            eprintln!(
                                "  fail node {:?} {:?} sort={:?} ops={:?} -> {e2:?}",
                                id, n.op, n.sort, n.operands
                            );
                        }
                        stack.extend_from_slice(&n.operands);
                    }
                }
                eprintln!("predicate translate failed: {e:?}");
                true
            }
        };
        // Model-extraction universe: symbols reachable from the predicate
        // (the runtime consumes register assignments for exactly those).
        let predicate_symbols: Arc<[u32]> = self.subtree_symbols.get(&predicate).cloned().unwrap_or_default();
        self.last_stats.cache_entries = self.ast_cache.len();
        let result = if failed {
            // No transient scope was pushed (the predicate never
            // translated) — popping here would eat a constraint scope.
            backend_error()
        } else {
            let r = self.check_and_extract(&predicate_symbols, deadline);
            // Retire the transient predicate scope.
            unsafe { Z3_solver_pop(ctx, self.solver, 1) };
            r
        };
        if timing {
            let total = started.elapsed();
            let translate = translate_done.unwrap_or_default();
            let push = push_done.map(|p| p - translate).unwrap_or_default();
            let check = total - push_done.unwrap_or_default();
            eprintln!(
                "[z3ffi] constraints={} shared={} popped={} pushed={} translated={} cache={} \
                 translate={:.2?} push={:.2?} check={:.2?} total={:.2?}",
                entries.len(),
                shared,
                excess,
                self.last_stats.pushed,
                self.last_stats.translated_nodes,
                self.last_stats.cache_entries,
                translate,
                push,
                check,
                total
            );
        }
        result
    }

    /// Runs `check` on the persistent solver and extracts the model —
    /// factored so the incremental path and the fallback share it.
    /// Interrupts any in-progress `check` on this context — Z3's documented
    /// thread-safe cancellation point. The next check returns UNKNOWN.
    pub fn interrupt(&self) {
        unsafe { Z3_interrupt(self.context) }
    }

    /// Solve `query` under a hard wall-clock `deadline` enforced by
    /// mid-flight cancellation.
    ///
    /// The query's soft timeout ([`SolverQuery::timeout`]) is still
    /// installed on the solver params exactly as in [`SolverBackend::solve`]
    /// — it remains the always-on backstop (and the only limit when no
    /// deadline is given). The deadline adds an *external* guarantee: a
    /// watchdog thread that sleeps for `deadline` and then fires
    /// [`Z3FfiBridge::interrupt`] on this bridge's context, cancelling the
    /// running `Z3_solver_check_assumptions`, which then returns `UNKNOWN`.
    /// The two mechanisms compose rather than fight: whichever expires first
    /// cancels the check and yields `Unknown` — never a fabricated
    /// `Sat`/`Unsat` — while the loser is retired without side effects (the
    /// soft limit simply never trips; the watchdog is disarmed and joined
    /// before it fires).
    ///
    /// The watchdog is armed only around the check call itself, after all
    /// translation and pushes complete: a *pre-armed* interrupt flag is
    /// consumed by intervening Z3 API calls (measured in
    /// `tests/preemption_bench.rs`), so arming any earlier would let the
    /// flag be eaten before the check starts. A zero deadline is treated as
    /// "no hard deadline" (soft limit only).
    pub fn solve_with_deadline(&mut self, query: &SolverQuery, deadline: Duration) -> SolverResult {
        self.solve_incremental_inner(query, Some(deadline))
    }

    /// Arm the mid-flight cancellation watchdog for the check that is about
    /// to start. Degrades gracefully: if the thread cannot be spawned the
    /// check still runs under the soft-limit params (the always-on
    /// backstop), just without the external hard deadline.
    fn arm_watchdog(&mut self, deadline: Duration) {
        debug_assert!(
            self.watchdog.is_none(),
            "previous watchdog must be retired before arming a new one"
        );
        let (disarm_tx, disarm_rx) = mpsc::channel::<()>();
        let flags = Arc::new(WatchdogFlags::default());
        let watcher_flags = flags.clone();
        // SAFETY: the raw context pointer crosses into the watchdog thread
        // inside `InterruptCtx`, whose `Send` impl documents why that is
        // sound; the call it enables (`Z3_interrupt`) is guarded by the
        // arm/retire protocol described above [`WatchdogFlags`].
        let ctx = InterruptCtx(self.context);
        let handle = std::thread::Builder::new()
            .name("z3-ffi-watchdog".to_owned())
            .spawn(move || {
                match disarm_rx.recv_timeout(deadline) {
                    // Retired early (or the owning bridge vanished without
                    // disarming): exit without ever touching the context.
                    Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => {}
                    // The check outlived its deadline: cancel it in flight.
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if !watcher_flags.disarmed.load(Ordering::Acquire) {
                            watcher_flags.fired.store(true, Ordering::Release);
                            ctx.interrupt();
                        }
                    }
                }
            });
        match handle {
            Ok(handle) => {
                self.watchdog = Some(ArmedWatchdog {
                    flags,
                    disarm_tx,
                    handle,
                })
            }
            Err(spawn_err) => {
                eprintln!("z3-ffi: watchdog spawn failed ({spawn_err}); relying on the soft timeout param");
            }
        }
    }

    /// Disarm and join the armed watchdog, if any. Returns whether the
    /// retired watchdog reports having actually fired `Z3_interrupt`.
    fn retire_watchdog(&mut self) -> bool {
        let Some(watchdog) = self.watchdog.take() else {
            return false;
        };
        // Order matters: publish `disarmed` first so a watchdog whose sleep
        // is expiring right now exits instead of firing; the channel send
        // then wakes it immediately (so joining never blocks for the rest
        // of the deadline); `join` reaps it before this method returns.
        watchdog.flags.disarmed.store(true, Ordering::Release);
        let _ = watchdog.disarm_tx.send(());
        let _ = watchdog.handle.join();
        watchdog.flags.fired.load(Ordering::Acquire)
    }

    /// Check under the live scope assumptions — the UNSAT core names
    /// which constraint literals are responsible.
    fn check_and_extract(&mut self, predicate_symbols: &[u32], deadline: Option<Duration>) -> SolverResult {
        let ctx = self.context;
        let assumptions: Vec<Z3_ast> = self.scopes.iter().map(|s| s.assumption).collect();
        // Arm the watchdog only now: every translation/push is complete, so
        // the interrupt can only land on the check itself — never before it
        // (a pre-armed flag is consumed by preceding API calls).
        if let Some(deadline) = deadline.filter(|d| !d.is_zero()) {
            self.arm_watchdog(deadline);
        }
        let result =
            unsafe { Z3_solver_check_assumptions(ctx, self.solver, assumptions.len() as u32, assumptions.as_ptr()) };
        // Retire (disarm + join) before any further context traffic — model
        // extraction and the caller's transient-scope pop must not race a
        // late interrupt.
        let watchdog_fired = self.retire_watchdog();
        let outcome = if result == Z3_L_TRUE {
            SolverOutcomeKind::Sat
        } else if result == Z3_L_FALSE {
            SolverOutcomeKind::Unsat
        } else {
            SolverOutcomeKind::Unknown
        };
        if watchdog_fired && outcome != SolverOutcomeKind::Unknown {
            // The check completed in the instants between the watchdog's
            // deadline expiring and the disarm store — see the residual-race
            // note above [`WatchdogFlags`]. The decision above is still
            // truthful (the check genuinely finished before observing the
            // interrupt); only a stray cancel flag may remain on the
            // context, which subsequent API traffic consumes.
            eprintln!(
                "z3-ffi: deadline watchdog fired just after the check returned {outcome:?}; \
                 a stray interrupt flag may linger on the context"
            );
        }
        unsafe {
            let model = if outcome == SolverOutcomeKind::Sat {
                match Z3_solver_get_model(ctx, self.solver) {
                    Some(model) => {
                        Z3_model_inc_ref(ctx, model);
                        let mut extracted = Vec::new();
                        for &sym_raw in predicate_symbols {
                            let sym_id = ExprId(sym_raw);
                            // The AST for this symbol: persistent interning
                            // means it is the very AST asserted in scopes.
                            let Some(&ast) = self.symbol_asts.get(&sym_id) else {
                                continue;
                            };
                            let mut eval_result: std::mem::MaybeUninit<Z3_ast> = std::mem::MaybeUninit::zeroed();
                            let success = Z3_model_eval(ctx, model, ast, true, eval_result.as_mut_ptr());
                            if success {
                                let eval_ast = eval_result.assume_init();
                                // Expected model-value size from the symbol's
                                // sort: >128-bit symbols get full-width
                                // little-endian values (the old u128 parse
                                // silently dropped them); everything else
                                // keeps the historical 16-byte form.
                                let byte_width = match self.reader.read(sym_id).map(|node| node.sort) {
                                    Some(ExprSort::BitVec(w)) => Some(usize::from(w).div_ceil(8)),
                                    _ => None,
                                };
                                if let Some(bytes) = numeral_to_bytes(ctx, eval_ast, byte_width) {
                                    extracted.push((u64::from(sym_raw), bytes));
                                }
                            }
                        }
                        Z3_model_dec_ref(ctx, model);
                        extracted
                    }
                    None => Vec::new(),
                }
            } else {
                Vec::new()
            };
            let unsat_core = if outcome == SolverOutcomeKind::Unsat {
                match Z3_solver_get_unsat_core(ctx, self.solver) {
                    Some(core) => {
                        let mut ids = Vec::new();
                        for i in 0..Z3_ast_vector_size(ctx, core) {
                            if let Some(ast) = Z3_ast_vector_get(ctx, core, i)
                                && let Some(entry) = self.scopes.iter().find(|s| s.assumption == ast)
                            {
                                ids.push(entry.cid);
                            }
                        }
                        ids
                    }
                    None => Vec::new(),
                }
            } else {
                Vec::new()
            };
            SolverResult {
                outcome,
                model,
                unsat_core,
                elapsed: Duration::ZERO,
            }
        }
    }

    /// Iterative post-order DAG translator over the PERSISTENT interning
    /// cache (`ast_cache`): each `ExprId` is built at most once per bridge,
    /// not once per query — Z3 ASTs are hash-consed within a context, so
    /// a cached pointer is the identical AST a re-translation would build.
    /// Replaces the formerly-recursive `translate` to avoid stack overflow
    /// on deeply-nested symbolic expressions (documented in ROADMAP.md
    /// Known Gaps).
    ///
    /// Algorithm — explicit two-phase work stack:
    ///
    /// Each entry on the work stack is `(ExprId, /* children_pushed */ bool)`.
    ///
    /// * **First encounter** (`children_pushed == false`): re-push the node
    ///   with `children_pushed == true`, then push all children with
    ///   `children_pushed == false`.  This ensures children are processed
    ///   (post-ordered) before the parent.
    ///
    /// * **Second encounter** (`children_pushed == true`): all operands are
    ///   now guaranteed to be in `cache`, so call `translate_node` — which
    ///   reads operand ASTs from `cache` instead of recursing — and store the
    ///   result.
    ///
    /// Already-cached nodes (DAG sharing) are short-circuited at the top of
    /// the first-encounter branch, so each `ExprId` is built at most once.
    fn translate(&mut self, root: ExprId) -> Result<Z3_ast, Z3FfiError> {
        // Fast path: root already translated (e.g. shared sub-expression).
        if let Some(&ast) = self.ast_cache.get(&root) {
            return Ok(ast);
        }
        // Bound the interning cache: a pathological walk (or a very long
        // campaign) could otherwise grow it without limit. Eviction is a
        // full clear — the solver keeps its asserted formulas alive on its
        // own references, so this is sound, just a one-query translation
        // hiccup.
        if self.ast_cache.len() >= AST_CACHE_CAP {
            self.clear_ast_cache();
        }

        // Work stack: (node_id, children_have_been_pushed_already)
        let mut stack: Vec<(ExprId, bool)> = Vec::new();
        stack.push((root, false));
        let reader = self.reader.clone();
        let mut translated = 0usize;

        while let Some((id, children_pushed)) = stack.pop() {
            // Short-circuit for nodes already in cache (DAG sharing).
            if self.ast_cache.contains_key(&id) {
                continue;
            }

            let node = reader.read(id).ok_or(Z3FfiError::UnresolvedExpression(id))?;

            if !children_pushed {
                // If all operands are already in cache (or leaf node with 0 operands),
                // translate immediately without a second push/pop cycle.
                if node.operands.iter().all(|child| self.ast_cache.contains_key(child)) {
                    let ast = Self::translate_node(
                        &reader,
                        self.context,
                        id,
                        &node,
                        &mut self.ast_cache,
                        &mut self.symbol_asts,
                    )?;
                    // SAFETY: the cache (and only the cache) keeps this AST
                    // alive past the current solve; released on clear/drop.
                    unsafe { Z3_inc_ref(self.context, ast) };
                    self.ast_cache.insert(id, ast);
                    self.memoize_symbols(id, &node);
                    translated += 1;
                } else {
                    // Phase 1: schedule this node for building after its children.
                    stack.push((id, true));
                    // Push children in reverse order so the leftmost child is
                    // processed first (stack is LIFO).
                    for &child in node.operands.iter().rev() {
                        if !self.ast_cache.contains_key(&child) {
                            stack.push((child, false));
                        }
                    }
                }
            } else {
                // Phase 2: all operands are guaranteed to be in `cache` now.
                // `translate_node` reads them directly from `cache` — no recursion.
                let ast = Self::translate_node(
                    &reader,
                    self.context,
                    id,
                    &node,
                    &mut self.ast_cache,
                    &mut self.symbol_asts,
                )?;
                // SAFETY: as above.
                unsafe { Z3_inc_ref(self.context, ast) };
                self.ast_cache.insert(id, ast);
                self.memoize_symbols(id, &node);
                translated += 1;
            }
        }

        self.last_stats.translated_nodes += translated;
        self.ast_cache
            .get(&root)
            .copied()
            .ok_or(Z3FfiError::UnresolvedExpression(root))
    }

    /// Release every interned AST and the memoization tables that describe
    /// them. Sound at any point: the solver holds its own references to
    /// anything asserted, and assumption literals in `scopes` are inc_ref'd
    /// independently.
    fn clear_ast_cache(&mut self) {
        // SAFETY: every entry was inc_ref'd on insertion; the solver's
        // assertions keep any still-asserted formulas alive on their own
        // references.
        unsafe {
            for (_, ast) in self.ast_cache.drain() {
                Z3_dec_ref(self.context, ast);
            }
        }
        self.symbol_asts.clear();
        self.subtree_symbols.clear();
    }

    /// Record `id`'s subtree symbol set: the union of its operands' sets
    /// (every operand is interned before its parent — post-order) plus
    /// itself if it is a Symbol node. Read once per translated node; read
    /// back at the query predicate to define the model-extraction universe.
    fn memoize_symbols(&mut self, id: ExprId, node: &ExprNode) {
        let mut set: Vec<u32> = Vec::new();
        for &child in &node.operands {
            if let Some(children) = self.subtree_symbols.get(&child) {
                set.extend_from_slice(children);
            }
        }
        if node.op == ExprOp::Symbol {
            set.push(id.0);
        }
        set.sort_unstable();
        set.dedup();
        self.subtree_symbols.insert(id, Arc::from(set));
    }

    /// Diagnostics for the most recent solve — see [`IncrementalStats`].
    /// (`cache_entries` is read live so direct `translate` experiments
    /// report truthfully too.)
    pub fn last_incremental_stats(&self) -> IncrementalStats {
        let mut stats = self.last_stats;
        stats.cache_entries = self.ast_cache.len();
        stats
    }

    fn translate_node(
        reader: &Arc<dyn ExprReader>,
        ctx: Z3_context,
        id: ExprId,
        node: &ExprNode,
        cache: &mut HashMap<ExprId, Z3_ast>,
        symbols: &mut HashMap<ExprId, Z3_ast>,
    ) -> Result<Z3_ast, Z3FfiError> {
        let get = |child: ExprId| -> Result<Z3_ast, Z3FfiError> {
            cache
                .get(&child)
                .copied()
                .ok_or(Z3FfiError::UnresolvedExpression(child))
        };
        match node.op {
            ExprOp::Constant => match node.sort {
                ExprSort::BitVec(width) => {
                    let sort = unsafe { Z3_mk_bv_sort(ctx, width as u32) }.ok_or(Z3FfiError::NullAst)?;
                    let byte_width = usize::from(width).div_ceil(8);
                    let mut bytes = node.immediate.clone();
                    if bytes.len() < byte_width {
                        bytes.resize(byte_width, 0);
                    }
                    bytes.truncate(byte_width);
                    // Convert little-endian bytes to a decimal string for Z3.
                    // Widths up to 128 bits take the historical u128 fold
                    // (byte-identical strings); wider constants (256/512-bit
                    // AVX workloads) are formatted exactly — folding them
                    // through a u128 used to shift-overflow (panic in debug,
                    // wrapped garbage in release).
                    let numeral_str = le_bytes_to_decimal(&bytes);
                    let c_str =
                        std::ffi::CString::new(numeral_str.as_str()).map_err(|_| Z3FfiError::MalformedExpression)?;
                    let ast = unsafe { Z3_mk_numeral(ctx, c_str.as_ptr(), sort) }.ok_or(Z3FfiError::NullAst)?;
                    Ok(ast)
                }
                ExprSort::Bool => {
                    let is_true = node.immediate.first().copied().is_some_and(|b| b != 0);
                    unsafe {
                        if is_true {
                            Z3_mk_true(ctx).ok_or(Z3FfiError::NullAst)
                        } else {
                            Z3_mk_false(ctx).ok_or(Z3FfiError::NullAst)
                        }
                    }
                }
                _ => Err(Z3FfiError::UnsupportedSort),
            },
            ExprOp::Symbol => {
                let sort = match node.sort {
                    ExprSort::BitVec(width) => unsafe { Z3_mk_bv_sort(ctx, width as u32) },
                    ExprSort::Bool => unsafe { Z3_mk_bool_sort(ctx) },
                    _ => return Err(Z3FfiError::UnsupportedSort),
                }
                .ok_or(Z3FfiError::NullAst)?;
                let name_str = format!("sym_{}", id.0);
                let c_name = std::ffi::CString::new(name_str.as_str()).map_err(|_| Z3FfiError::MalformedExpression)?;
                let name = unsafe { Z3_mk_string_symbol(ctx, c_name.as_ptr()) }.ok_or(Z3FfiError::NullAst)?;
                let ast = unsafe { Z3_mk_const(ctx, name, sort) }.ok_or(Z3FfiError::NullAst)?;
                symbols.insert(id, ast);
                Ok(ast)
            }
            ExprOp::Add
            | ExprOp::Sub
            | ExprOp::Mul
            | ExprOp::UDiv
            | ExprOp::SDiv
            | ExprOp::And
            | ExprOp::Or
            | ExprOp::Xor
            | ExprOp::Shl
            | ExprOp::LShr
            | ExprOp::AShr => {
                if node.operands.len() != 2 {
                    return Err(Z3FfiError::MalformedExpression);
                }
                let left = get(node.operands[0])?;
                let right = get(node.operands[1])?;
                // Bool-sorted And/Or are propositional conjunction and
                // disjunction (path-constraint trees, region-bound
                // disjunctions); BitVec-sorted are the bitwise ALU ops.
                // A sort mismatch (one Bool, one BitVec operand) is
                // malformed — Z3 would return a sort-error AST.
                let ast = unsafe {
                    match (node.op, &node.sort) {
                        (ExprOp::And, ExprSort::Bool) => Z3_mk_and(ctx, 2, [left, right].as_mut_ptr()),
                        (ExprOp::Or, ExprSort::Bool) => Z3_mk_or(ctx, 2, [left, right].as_mut_ptr()),
                        (ExprOp::Add, _) => Z3_mk_bvadd(ctx, left, right),
                        (ExprOp::Sub, _) => Z3_mk_bvsub(ctx, left, right),
                        (ExprOp::Mul, _) => Z3_mk_bvmul(ctx, left, right),
                        (ExprOp::UDiv, _) => Z3_mk_bvudiv(ctx, left, right),
                        (ExprOp::SDiv, _) => Z3_mk_bvsdiv(ctx, left, right),
                        (ExprOp::And, _) => Z3_mk_bvand(ctx, left, right),
                        (ExprOp::Or, _) => Z3_mk_bvor(ctx, left, right),
                        (ExprOp::Xor, _) => Z3_mk_bvxor(ctx, left, right),
                        (ExprOp::Shl, _) => Z3_mk_bvshl(ctx, left, right),
                        (ExprOp::LShr, _) => Z3_mk_bvlshr(ctx, left, right),
                        (ExprOp::AShr, _) => Z3_mk_bvashr(ctx, left, right),
                        _ => return Err(Z3FfiError::MalformedExpression),
                    }
                }
                .ok_or(Z3FfiError::NullAst)?;
                Ok(ast)
            }
            ExprOp::RotL | ExprOp::RotR => {
                if node.operands.len() != 2 {
                    return Err(Z3FfiError::MalformedExpression);
                }
                let width = match node.sort {
                    ExprSort::BitVec(w) => w,
                    _ => return Err(Z3FfiError::UnsupportedSort),
                };
                let value = get(node.operands[0])?;
                let count_node = reader
                    .read(node.operands[1])
                    .ok_or(Z3FfiError::UnresolvedExpression(node.operands[1]))?;
                let count_width = match count_node.sort {
                    ExprSort::BitVec(w) => w,
                    _ => return Err(Z3FfiError::UnsupportedSort),
                };
                let count = get(node.operands[1])?;
                // Z3's rotate entry points require the amount at the value's
                // own width: widen a narrower count (an 8-bit CL count is the
                // machine shape), narrow a wider one to its low bits.
                let count = if count_width < width {
                    unsafe { Z3_mk_zero_ext(ctx, u32::from(width - count_width), count) }.ok_or(Z3FfiError::NullAst)?
                } else if count_width > width {
                    unsafe { Z3_mk_extract(ctx, u32::from(width) - 1, 0, count) }.ok_or(Z3FfiError::NullAst)?
                } else {
                    count
                };
                let ast = if count_node.op == ExprOp::Constant {
                    // Constant amount: the indexed rotate, with the count
                    // taken modulo the width (the op's defining semantics).
                    // The count folds straight out of the little-endian
                    // immediate with per-byte modular reduction (MSB first),
                    // so a count constant wider than 128 bits — a 256-bit
                    // constant count — stays exact instead of being truncated
                    // to its low 16 bytes. Widths are u16, so every
                    // intermediate fits comfortably in u64.
                    let mut rem: u64 = 0;
                    for &b in count_node.immediate.iter().rev() {
                        rem = (rem * 256 + u64::from(b)) % u64::from(width);
                    }
                    let amount = u32::try_from(rem).map_err(|_| Z3FfiError::MalformedExpression)?;
                    unsafe {
                        if node.op == ExprOp::RotL {
                            Z3_mk_rotate_left(ctx, amount, value)
                        } else {
                            Z3_mk_rotate_right(ctx, amount, value)
                        }
                    }
                    .ok_or(Z3FfiError::NullAst)?
                } else {
                    // Symbolic amount: the extended rotate applies the same
                    // modulo-width masking inside Z3.
                    unsafe {
                        if node.op == ExprOp::RotL {
                            Z3_mk_ext_rotate_left(ctx, value, count)
                        } else {
                            Z3_mk_ext_rotate_right(ctx, value, count)
                        }
                    }
                    .ok_or(Z3FfiError::NullAst)?
                };
                Ok(ast)
            }
            ExprOp::Not => {
                if node.operands.len() != 1 {
                    return Err(Z3FfiError::MalformedExpression);
                }
                let operand = get(node.operands[0])?;
                let ast = match node.sort {
                    ExprSort::Bool => unsafe { Z3_mk_not(ctx, operand) },
                    _ => unsafe { Z3_mk_bvnot(ctx, operand) },
                }
                .ok_or(Z3FfiError::NullAst)?;
                Ok(ast)
            }
            ExprOp::Eq | ExprOp::Ult | ExprOp::Ule | ExprOp::Slt | ExprOp::Sle => {
                if node.operands.len() != 2 {
                    return Err(Z3FfiError::MalformedExpression);
                }
                let left = get(node.operands[0])?;
                let right = get(node.operands[1])?;
                let ast = unsafe {
                    match node.op {
                        ExprOp::Eq => Z3_mk_eq(ctx, left, right),
                        ExprOp::Ult => Z3_mk_bvult(ctx, left, right),
                        ExprOp::Ule => Z3_mk_bvule(ctx, left, right),
                        ExprOp::Slt => Z3_mk_bvslt(ctx, left, right),
                        ExprOp::Sle => Z3_mk_bvsle(ctx, left, right),
                        _ => return Err(Z3FfiError::MalformedExpression),
                    }
                }
                .ok_or(Z3FfiError::NullAst)?;
                Ok(ast)
            }
            ExprOp::Ite => {
                if node.operands.len() != 3 {
                    return Err(Z3FfiError::MalformedExpression);
                }
                let cond = get(node.operands[0])?;
                let then_val = get(node.operands[1])?;
                let else_val = get(node.operands[2])?;
                let ast = unsafe { Z3_mk_ite(ctx, cond, then_val, else_val) }.ok_or(Z3FfiError::NullAst)?;
                Ok(ast)
            }
            ExprOp::Concat => {
                if node.operands.len() != 2 {
                    return Err(Z3FfiError::MalformedExpression);
                }
                let low = get(node.operands[0])?;
                let high = get(node.operands[1])?;
                let ast = unsafe { Z3_mk_concat(ctx, high, low) }.ok_or(Z3FfiError::NullAst)?;
                Ok(ast)
            }
            ExprOp::Extract => {
                // Canonical encoding: 1 operand (the value) + immediate
                // [start:u16, width:u16]. Legacy encoding: operands[1] is a
                // Constant node holding the start.
                let (operand_id, start) = match node.operands.len() {
                    1 => {
                        let start = node
                            .immediate
                            .get(..2)
                            .map(|b| u16::from_le_bytes(b.try_into().unwrap_or([0; 2])))
                            .map(u64::from)
                            .unwrap_or(0);
                        (node.operands[0], start)
                    }
                    2 => {
                        let start_node = reader
                            .read(node.operands[1])
                            .ok_or(Z3FfiError::UnresolvedExpression(node.operands[1]))?;
                        (node.operands[0], bytes_to_u64(&start_node.immediate))
                    }
                    _ => return Err(Z3FfiError::MalformedExpression),
                };
                let operand = get(operand_id)?;
                let width = match node.sort {
                    ExprSort::BitVec(w) => w,
                    _ => return Err(Z3FfiError::UnsupportedSort),
                };
                let high = start + u64::from(width) - 1;
                let low = start;
                let ast = unsafe { Z3_mk_extract(ctx, high as u32, low as u32, operand) }.ok_or(Z3FfiError::NullAst)?;
                Ok(ast)
            }
            ExprOp::ZExt | ExprOp::SExt => {
                if node.operands.len() != 1 {
                    return Err(Z3FfiError::MalformedExpression);
                }
                let operand = get(node.operands[0])?;
                let operand_node = reader
                    .read(node.operands[0])
                    .ok_or(Z3FfiError::UnresolvedExpression(node.operands[0]))?;
                let input_bits = match operand_node.sort {
                    ExprSort::BitVec(w) => w,
                    _ => return Err(Z3FfiError::UnsupportedSort),
                };
                let output_bits = match node.sort {
                    ExprSort::BitVec(w) => w,
                    _ => return Err(Z3FfiError::UnsupportedSort),
                };
                if output_bits == input_bits {
                    // No-op extension (width coercion emits these).
                    return Ok(operand);
                }
                if output_bits < input_bits {
                    return Err(Z3FfiError::MalformedExpression);
                }
                let diff = (output_bits - input_bits) as u32;
                let ast = unsafe {
                    if node.op == ExprOp::ZExt {
                        Z3_mk_zero_ext(ctx, diff, operand)
                    } else {
                        Z3_mk_sign_ext(ctx, diff, operand)
                    }
                }
                .ok_or(Z3FfiError::NullAst)?;
                Ok(ast)
            }
        }
    }
}

impl SolverBackend for Z3FfiBridge {
    fn name(&self) -> &'static str {
        "z3-ffi"
    }

    fn solve(&mut self, query: &SolverQuery) -> SolverResult {
        // Incremental path: persistent solver with scoped constraints —
        // shared constraint prefixes reuse learned state.
        self.solve_incremental(query)
    }

    fn solve_batch(&mut self, _shared: &[ConstraintId], predicates: &[SolverQuery]) -> Vec<SolverResult> {
        predicates.iter().map(|q| self.solve_incremental(q)).collect()
    }
}

impl Drop for Z3FfiBridge {
    fn drop(&mut self) {
        // Belt-and-braces: retire any watchdog that is still armed (only
        // reachable if a deadline solve panicked between arming and
        // retiring) BEFORE freeing the context, so the watchdog thread can
        // never call `Z3_interrupt` on a freed context.
        self.retire_watchdog();
        // SAFETY: `self.context` was created by `Z3_mk_context` in `new`,
        // is not used after this point, and retirement above joined every
        // thread that held it. Every AST the bridge stored past a single
        // solve (interning cache entries, live assumption literals) was
        // inc_ref'd on insertion and is released here.
        unsafe {
            for scope in self.scopes.drain(..) {
                Z3_dec_ref(self.context, scope.assumption);
            }
            for (_, ast) in self.ast_cache.drain() {
                Z3_dec_ref(self.context, ast);
            }
            Z3_solver_dec_ref(self.context, self.solver);
            Z3_del_context(self.context);
        }
    }
}

fn backend_error() -> SolverResult {
    SolverResult {
        outcome: SolverOutcomeKind::BackendError,
        model: Vec::new(),
        unsat_core: Vec::new(),
        elapsed: Duration::ZERO,
    }
}

fn bytes_to_u64(bytes: &[u8]) -> u64 {
    let mut buf = [0u8; 8];
    let len = bytes.len().min(8);
    buf[..len].copy_from_slice(&bytes[..len]);
    u64::from_le_bytes(buf)
}

/// Format a little-endian immediate as an exact decimal numeral for Z3.
///
/// Values that fit a `u128` (every width <= 128 bits) keep the historical
/// fold-and-`to_string` path, so their numeral strings — and therefore the
/// constructed ASTs — are identical to the pre-AVX behavior. Wider values
/// use schoolbook long division by 10 over the little-endian bytes:
/// O(decimal_digits * bytes), microseconds at 512 bits. Folding a 256-bit
/// constant through a `u128`, as before, shifted by >= 128 bits — a panic
/// under debug assertions and wrapped garbage in release.
fn le_bytes_to_decimal(bytes: &[u8]) -> String {
    if bytes.len() <= core::mem::size_of::<u128>() {
        let mut value: u128 = 0;
        for (i, &b) in bytes.iter().enumerate() {
            value |= u128::from(b) << (i * 8);
        }
        return value.to_string();
    }
    let mut work = bytes.to_vec();
    let mut digits_low_first: Vec<u8> = Vec::with_capacity(bytes.len() * 3);
    while work.iter().any(|&b| b != 0) {
        // One long-division pass by 10, most-significant byte first. The
        // remainder is < 10 and every intermediate <= 2569, so u16 suffices.
        let mut rem: u16 = 0;
        for byte in work.iter_mut().rev() {
            let cur = (rem << 8) | u16::from(*byte);
            *byte = (cur / 10) as u8;
            rem = cur % 10;
        }
        digits_low_first.push(rem as u8);
    }
    if digits_low_first.is_empty() {
        return "0".to_owned();
    }
    let mut out = String::with_capacity(digits_low_first.len());
    for d in digits_low_first.into_iter().rev() {
        out.push((b'0' + d) as char);
    }
    out
}

/// Parse an exact decimal numeral into `byte_width` little-endian bytes,
/// rejecting non-digit input and values that do not fit. Used for model
/// values of sorts wider than a `u128` (the old `u128` parse silently
/// dropped those symbols from extracted models).
fn decimal_to_le_bytes(s: &str, byte_width: usize) -> Option<Vec<u8>> {
    let mut bytes = vec![0u8; byte_width];
    for d in s.bytes() {
        let digit = u16::from(d.checked_sub(b'0')?);
        if digit > 9 {
            return None;
        }
        // Multiply the accumulator by 10 and add the digit, least
        // significant byte first. The carry stays <= 10, so every
        // intermediate fits in u16.
        let mut carry = digit;
        for byte in bytes.iter_mut() {
            let cur = u16::from(*byte) * 10 + carry;
            *byte = (cur & 0xff) as u8;
            carry = cur >> 8;
        }
        if carry != 0 {
            // Value does not fit byte_width — malformed for its sort.
            return None;
        }
    }
    Some(bytes)
}

/// Extract a numeral value from a Z3 AST as little-endian bytes.
///
/// `wide_byte_width` is the expected model-value size derived from the
/// symbol's bitvector sort. Values that fit a `u128` keep the historical
/// 16-byte little-endian form; a wider numeral (a >128-bit symbol, which
/// the old `u128` parse silently dropped from the model) is converted
/// exactly and zero-extended to the full width.
unsafe fn numeral_to_bytes(ctx: Z3_context, ast: Z3_ast, wide_byte_width: Option<usize>) -> Option<Vec<u8>> {
    let str_ptr = unsafe { Z3_get_numeral_string(ctx, ast) };
    if str_ptr.is_null() {
        return None;
    }
    let c_str = unsafe { std::ffi::CStr::from_ptr(str_ptr) };
    let s = c_str.to_str().ok()?;
    // Z3 returns decimal; numerals that fit a u128 keep the exact
    // historical representation.
    if let Ok(val) = s.parse::<u128>() {
        return match wide_byte_width {
            Some(w) if w > core::mem::size_of::<u128>() => {
                let mut bytes = val.to_le_bytes().to_vec();
                bytes.resize(w, 0);
                Some(bytes)
            }
            _ => Some(val.to_le_bytes().to_vec()),
        };
    }
    decimal_to_le_bytes(s, wide_byte_width?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_expr::{ExprArena, ExprNode, ExprOp, ExprReader, ExprSort, ShardedExprArena};
    use angryier_solver::{CanonicalConstraint, SolverQuery};
    use angryier_types::{
        ConstraintCanonicalizationVersion, ConstraintId, DependencyKey, ExprId, ExpressionNormalizationVersion,
        SolverQueryId, TargetProfileId,
    };
    use std::sync::Arc;

    fn make_arena() -> Arc<ShardedExprArena> {
        Arc::new(ShardedExprArena::new(ExpressionNormalizationVersion(1)))
    }

    fn make_symbol(arena: &ShardedExprArena, width: u16, sym_id: u64) -> ExprId {
        arena
            .intern(ExprNode {
                sort: ExprSort::BitVec(width),
                op: ExprOp::Symbol,
                operands: Vec::new(),
                immediate: sym_id.to_le_bytes().to_vec(),
            })
            .unwrap_or(ExprId(0))
    }

    fn make_const(arena: &ShardedExprArena, width: u16, value: u128) -> ExprId {
        let byte_width = usize::from(width).div_ceil(8);
        // Zero-extend the u128 into the full immediate width so widths above
        // 128 bits work for small values (0, 1, ...) too.
        let raw = value.to_le_bytes();
        let mut immediate = vec![0u8; byte_width];
        let len = raw.len().min(byte_width);
        immediate[..len].copy_from_slice(&raw[..len]);
        make_const_bytes(arena, width, &immediate)
    }

    /// Intern a constant from its exact little-endian immediate (the arena's
    /// canonical form: exactly `ceil(width/8)` bytes). Unlike [`make_const`],
    /// this supports values wider than a `u128`.
    fn make_const_bytes(arena: &ShardedExprArena, width: u16, immediate: &[u8]) -> ExprId {
        arena
            .intern(ExprNode {
                sort: ExprSort::BitVec(width),
                op: ExprOp::Constant,
                operands: Vec::new(),
                immediate: immediate.to_vec(),
            })
            .unwrap()
    }

    fn make_binop(arena: &ShardedExprArena, op: ExprOp, width: u16, left: ExprId, right: ExprId) -> ExprId {
        arena
            .intern(ExprNode {
                sort: ExprSort::BitVec(width),
                op,
                operands: vec![left, right],
                immediate: Vec::new(),
            })
            .unwrap_or(ExprId(0))
    }

    fn make_eq(arena: &ShardedExprArena, left: ExprId, right: ExprId) -> ExprId {
        arena
            .intern(ExprNode {
                sort: ExprSort::Bool,
                op: ExprOp::Eq,
                operands: vec![left, right],
                immediate: Vec::new(),
            })
            .unwrap_or(ExprId(0))
    }

    fn make_ult(arena: &ShardedExprArena, left: ExprId, right: ExprId) -> ExprId {
        arena
            .intern(ExprNode {
                sort: ExprSort::Bool,
                op: ExprOp::Ult,
                operands: vec![left, right],
                immediate: Vec::new(),
            })
            .unwrap_or(ExprId(0))
    }

    fn make_query(
        predicate: ExprId,
        constraints: &[(ConstraintId, ExprId)],
        arena: &Arc<ShardedExprArena>,
    ) -> SolverQuery {
        let canonical_constraints: Vec<_> = constraints
            .iter()
            .map(|(cid, eid)| {
                let summary = arena.dependency_summary(*eid);
                let key = summary.map(|s| s.key).unwrap_or(DependencyKey([0; 32]));
                CanonicalConstraint {
                    id: *cid,
                    key,
                    expr: *eid,
                }
            })
            .collect();
        let pred_summary = arena.dependency_summary(predicate);
        let pred_key = pred_summary.map(|s| s.key).unwrap_or(DependencyKey([0; 32]));
        SolverQuery::canonical(
            SolverQueryId(1),
            &canonical_constraints,
            predicate,
            pred_key,
            TargetProfileId(1),
            ConstraintCanonicalizationVersion(1),
            Duration::from_secs(10),
        )
        .unwrap_or_else(|_| {
            // Fallback: create a minimal valid query with a dummy constraint
            SolverQuery::canonical(
                SolverQueryId(1),
                &[CanonicalConstraint {
                    id: ConstraintId(0),
                    key: DependencyKey([0; 32]),
                    expr: predicate,
                }],
                predicate,
                DependencyKey([0; 32]),
                TargetProfileId(1),
                ConstraintCanonicalizationVersion(1),
                Duration::from_secs(10),
            )
            .unwrap_or_else(|_| {
                // If even this fails, use a trivially valid query
                SolverQuery::canonical(
                    SolverQueryId(1),
                    &[CanonicalConstraint {
                        id: ConstraintId(0),
                        key: DependencyKey([1; 32]),
                        expr: predicate,
                    }],
                    predicate,
                    DependencyKey([1; 32]),
                    TargetProfileId(1),
                    ConstraintCanonicalizationVersion(1),
                    Duration::from_secs(10),
                )
                .unwrap_or_else(|_| panic!("could not construct test query"))
            })
        })
    }

    #[test]
    fn z3_solves_simple_sat() -> Result<(), Box<dyn std::error::Error>> {
        let arena = make_arena();
        let x = make_symbol(&arena, 64, 1);
        let three = make_const(&arena, 64, 3);
        let five = make_const(&arena, 64, 5);
        let x_plus_3 = make_binop(&arena, ExprOp::Add, 64, x, three);
        let predicate = make_eq(&arena, x_plus_3, five);

        let reader: Arc<dyn ExprReader> = arena.clone();
        let mut bridge = Z3FfiBridge::new(reader)?;

        let query = make_query(predicate, &[], &arena);
        let result = bridge.solve(&query);

        assert_eq!(result.outcome, SolverOutcomeKind::Sat);
        assert!(!result.model.is_empty());
        Ok(())
    }

    #[test]
    fn z3_solves_truly_unsat() -> Result<(), Box<dyn std::error::Error>> {
        let arena = make_arena();
        let x = make_symbol(&arena, 64, 1);
        let three = make_const(&arena, 64, 3);
        let five = make_const(&arena, 64, 5);
        let two = make_const(&arena, 64, 2);
        let x_plus_3 = make_binop(&arena, ExprOp::Add, 64, x, three);
        let eq_two = make_eq(&arena, x_plus_3, two);
        let eq_five = make_eq(&arena, x_plus_3, five);

        let reader: Arc<dyn ExprReader> = arena.clone();
        let mut bridge = Z3FfiBridge::new(reader)?;

        // x + 3 == 2 AND x + 3 == 5 is UNSAT
        let query = make_query(eq_two, &[(ConstraintId(1), eq_five)], &arena);
        let result = bridge.solve(&query);
        assert_eq!(result.outcome, SolverOutcomeKind::Unsat);
        Ok(())
    }

    #[test]
    fn z3_solves_with_ult_constraint() -> Result<(), Box<dyn std::error::Error>> {
        let arena = make_arena();
        let x = make_symbol(&arena, 64, 1);
        let ten = make_const(&arena, 64, 10);
        let twenty = make_const(&arena, 64, 20);
        // x < 20 AND x > 10 is SAT
        let x_lt_20 = make_ult(&arena, x, twenty);
        let ten_lt_x = make_ult(&arena, ten, x);

        let reader: Arc<dyn ExprReader> = arena.clone();
        let mut bridge = Z3FfiBridge::new(reader)?;

        let query = make_query(x_lt_20, &[(ConstraintId(1), ten_lt_x)], &arena);
        let result = bridge.solve(&query);
        assert_eq!(result.outcome, SolverOutcomeKind::Sat);
        Ok(())
    }

    #[test]
    fn z3_backend_name() -> Result<(), Box<dyn std::error::Error>> {
        let arena = make_arena();
        let reader: Arc<dyn ExprReader> = arena.clone();
        let bridge = Z3FfiBridge::new(reader)?;
        assert_eq!(bridge.name(), "z3-ffi");
        Ok(())
    }

    /// Verifies that deeply nested expressions with DAG sharing (e.g. repeated
    /// doubling) are translated iteratively without stack overflow and without
    /// exponential node blowup (O(N) nodes translated thanks to AST caching).
    #[test]
    fn deep_expression_dag_sharing_no_stack_overflow() -> Result<(), Box<dyn std::error::Error>> {
        const DEPTH: usize = 600;

        let arena = make_arena();
        let x = make_symbol(&arena, 64, 99);

        // Build: x, (x + x), ((x + x) + (x + x)), ... to depth 600.
        // Without DAG sharing cache, this would be 2^600 nodes.
        let mut acc = x;
        for _ in 0..DEPTH {
            acc = make_binop(&arena, ExprOp::Add, 64, acc, acc);
        }

        let predicate = make_eq(&arena, acc, acc);

        let reader: Arc<dyn ExprReader> = arena.clone();
        let mut bridge = Z3FfiBridge::new(reader)?;

        // Test direct translation through the persistent intern cache.
        let first_stats = bridge.last_incremental_stats();
        let ast = bridge.translate(predicate)?;
        let after_first = bridge.last_incremental_stats();
        assert_eq!(after_first.cache_entries, DEPTH + 2);
        assert_eq!(
            after_first.translated_nodes - first_stats.translated_nodes,
            DEPTH + 2,
            "a cold translation builds exactly DEPTH + 2 unique nodes"
        );
        // Re-translation of the same root is a pure cache hit: no new
        // nodes translated, the identical AST pointer returns.
        let again = bridge.translate(predicate)?;
        assert_eq!(again, ast);
        let after_second = bridge.last_incremental_stats();
        assert_eq!(
            after_second.translated_nodes - after_first.translated_nodes,
            0,
            "a warm re-translation must hit the intern cache for every node"
        );
        assert_eq!(after_second.cache_entries, DEPTH + 2);

        // Also test solving the query.
        let query = make_query(predicate, &[], &arena);
        let result = bridge.solve(&query);
        assert_eq!(
            result.outcome,
            SolverOutcomeKind::Sat,
            "reflexive deep DAG equality should solve to SAT"
        );
        Ok(())
    }

    /// Verifies that the iterative translator handles a deeply-nested
    /// expression DAG (depth > 500) without a stack overflow.
    ///
    /// Constructs:  x + 1 + 1 + … + 1  (DEPTH additions)
    ///
    /// The expected value of the sum (given x = 0) is `DEPTH`.  We then ask
    /// Z3 whether the chain equals `DEPTH` — this must be SAT with x = 0
    /// in the model.
    ///
    /// Prior to the iterative rewrite, the recursive translator overflowed
    /// the test-thread stack well below 500 additions (~40 iterations for a
    /// ~118-node-per-iteration symbolic loop accumulator).
    #[test]
    fn deep_expression_no_stack_overflow() -> Result<(), Box<dyn std::error::Error>> {
        const DEPTH: u128 = 600;

        let arena = make_arena();
        // Symbolic variable x (64-bit).
        let x = make_symbol(&arena, 64, 42);
        let one = make_const(&arena, 64, 1);

        // Build: x + 1 + 1 + … + 1  (DEPTH ones added left-linearly).
        let mut acc = x;
        for _ in 0..DEPTH {
            acc = make_binop(&arena, ExprOp::Add, 64, acc, one);
        }

        // The sum equals DEPTH iff x = 0.
        let expected = make_const(&arena, 64, DEPTH);
        let predicate = make_eq(&arena, acc, expected);

        let reader: Arc<dyn ExprReader> = arena.clone();
        let mut bridge = Z3FfiBridge::new(reader)?;

        let query = make_query(predicate, &[], &arena);
        let result = bridge.solve(&query);

        assert_eq!(
            result.outcome,
            SolverOutcomeKind::Sat,
            "deep expression translate should succeed and be SAT"
        );
        // The model must assign x = 0.
        // The model is keyed by ExprId (the arena-assigned integer for the
        // symbol node), not the immediate/user-facing symbol id passed to
        // `make_symbol`.  Use `x.0` (the interned ExprId) as the lookup key.
        let x_expr_id = u64::from(x.0);
        let x_val = result.model.iter().find(|(sym, _)| *sym == x_expr_id).map(|(_, v)| {
            let mut buf = [0u8; 16];
            let len = v.len().min(16);
            buf[..len].copy_from_slice(&v[..len]);
            u128::from_le_bytes(buf)
        });
        assert_eq!(
            x_val,
            Some(0),
            "model should assign x = 0 (ExprId={}), got {:?}",
            x_expr_id,
            result.model
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Wide-constant lowering (128 / 256 / 512-bit)
    //
    // The historical constant path folded the little-endian immediate through
    // a u128, so any constant above 128 bits shifted by >= 128 bits — a panic
    // under debug assertions, wrapped garbage in release. The tests below pin
    // the exact lowering at the AVX widths (256-bit ymm, 512-bit zmm) while
    // proving the 128-bit path is byte-identical to the pre-AVX behavior.
    // -----------------------------------------------------------------------

    fn make_extract(arena: &ShardedExprArena, value: ExprId, start: u16, width: u16) -> ExprId {
        let mut immediate = Vec::with_capacity(4);
        immediate.extend_from_slice(&start.to_le_bytes());
        immediate.extend_from_slice(&width.to_le_bytes());
        arena
            .intern(ExprNode {
                sort: ExprSort::BitVec(width),
                op: ExprOp::Extract,
                operands: vec![value],
                immediate,
            })
            .unwrap()
    }

    fn make_rotate(arena: &ShardedExprArena, op: ExprOp, width: u16, value: ExprId, count: ExprId) -> ExprId {
        arena
            .intern(ExprNode {
                sort: ExprSort::BitVec(width),
                op,
                operands: vec![value, count],
                immediate: Vec::new(),
            })
            .unwrap()
    }

    /// Constant power-of-two helper: a `width`-bit little-endian immediate
    /// with bit `exponent` set (exponent must be < width).
    fn make_const_pow2(arena: &ShardedExprArena, width: u16, exponent: usize) -> ExprId {
        assert!(exponent < usize::from(width));
        let mut immediate = vec![0u8; usize::from(width).div_ceil(8)];
        immediate[exponent / 8] |= 1 << (exponent % 8);
        make_const_bytes(arena, width, &immediate)
    }

    /// 128-bit constants must lower exactly as before the wide-constant work:
    /// the u128 fast fold, the same decimal numeral strings, the same query
    /// outcomes, and the historical 16-byte model-value form.
    ///
    /// All-constant subtrees fold inside the arena (widths <= 128 never reach
    /// Z3), so the exact-value proof pins a 128-bit constant against a
    /// symbol: with `x == c` as a path constraint, byte-granular extracts of
    /// `x` must match the constant's little-endian immediate bytes — bits
    /// [8k, 8k+8) are immediate byte k (the evaluator's Extract takes `start`
    /// from the LSB).
    #[test]
    fn z3_128bit_constant_roundtrip_no_regression() -> Result<(), Box<dyn std::error::Error>> {
        let arena = make_arena();
        // LE bytes: [AC 68 24 F0 BD 79 35 01 EF CD AB 89 67 45 23 01]
        let c: u128 = 0x0123_4567_89AB_CDEF_0135_79BD_F024_68AC;
        let c128 = make_const(&arena, 128, c);
        let one = make_const(&arena, 128, 1);

        let reader: Arc<dyn ExprReader> = arena.clone();
        let mut bridge = Z3FfiBridge::new(reader)?;

        // const == const → Sat (arena-folded; sanity that the query builds).
        assert_eq!(
            bridge
                .solve(&make_query(make_eq(&arena, c128, c128), &[], &arena))
                .outcome,
            SolverOutcomeKind::Sat
        );
        // const != const + 1 → Unsat.
        let c_plus_1 = make_binop(&arena, ExprOp::Add, 128, c128, one);
        assert_eq!(
            bridge
                .solve(&make_query(make_eq(&arena, c128, c_plus_1), &[], &arena))
                .outcome,
            SolverOutcomeKind::Unsat
        );

        // Exact-value byte-order proof through the bridge: x == c, then two
        // byte extracts must return the LE immediate's first and last bytes.
        let x = make_symbol(&arena, 128, 11);
        let eq_c = make_eq(&arena, x, c128);
        let low_byte = make_eq(&arena, make_extract(&arena, x, 0, 8), make_const(&arena, 8, c & 0xFF));
        let high_byte = make_eq(&arena, make_extract(&arena, x, 120, 8), make_const(&arena, 8, c >> 120));
        let mid_byte = make_eq(
            &arena,
            make_extract(&arena, x, 64, 8),
            make_const(&arena, 8, (c >> 64) & 0xFF),
        );
        for (name, pred) in [("low", low_byte), ("mid", mid_byte), ("high", high_byte)] {
            let result = bridge.solve(&make_query(pred, &[(ConstraintId(1), eq_c)], &arena));
            assert_eq!(
                result.outcome,
                SolverOutcomeKind::Sat,
                "{name} byte of the 128-bit immediate must land at its little-endian bit span"
            );
        }

        // Model regression: a 128-bit symbol's model value keeps the
        // historical 16-byte little-endian form.
        let y = make_symbol(&arena, 128, 9);
        let big = make_const(&arena, 128, 1 << 120);
        let pred = make_ult(&arena, one, y);
        let bounded = make_ult(&arena, y, big);
        let result = bridge.solve(&make_query(pred, &[(ConstraintId(1), bounded)], &arena));
        assert_eq!(result.outcome, SolverOutcomeKind::Sat);
        let entry = result.model.iter().find(|(sym, _)| *sym == u64::from(y.0));
        let (_, bytes) = entry.expect("128-bit symbol must appear in the model");
        assert_eq!(
            bytes.len(),
            16,
            "historical model form for <= 128-bit symbols is 16 bytes"
        );
        Ok(())
    }

    /// A 256-bit constant (2^200) whose value is entirely above bit 128:
    /// the old u128 fold produced 0 (debug: shift-overflow panic; release:
    /// wrapped garbage), so the assertions below distinguish exact lowering
    /// from truncation. Widths > 128 never fold in the arena, so every
    /// comparison here runs through the bridge's numeral construction.
    #[test]
    fn z3_256bit_constant_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let arena = make_arena();
        let c256 = make_const_pow2(&arena, 256, 200);
        let one = make_const(&arena, 256, 1);

        let reader: Arc<dyn ExprReader> = arena.clone();
        let mut bridge = Z3FfiBridge::new(reader)?;

        // const == const → Sat.
        assert_eq!(
            bridge
                .solve(&make_query(make_eq(&arena, c256, c256), &[], &arena))
                .outcome,
            SolverOutcomeKind::Sat
        );
        // const != const + 1 → Unsat.
        let c_plus_1 = make_binop(&arena, ExprOp::Add, 256, c256, one);
        assert_eq!(
            bridge
                .solve(&make_query(make_eq(&arena, c256, c_plus_1), &[], &arena))
                .outcome,
            SolverOutcomeKind::Unsat
        );
        // Truncation canaries: a folded-to-0 constant would flip all four of
        // these (Unsat, Sat, Unsat, Unsat respectively).
        assert_eq!(
            bridge
                .solve(&make_query(make_ult(&arena, c256, one), &[], &arena))
                .outcome,
            SolverOutcomeKind::Unsat
        );
        assert_eq!(
            bridge
                .solve(&make_query(make_ult(&arena, one, c256), &[], &arena))
                .outcome,
            SolverOutcomeKind::Sat
        );
        // Neighbor comparisons pin the exact exponent: 2^199 < 2^200 < 2^201.
        let below = make_const_pow2(&arena, 256, 199);
        let above = make_const_pow2(&arena, 256, 201);
        assert_eq!(
            bridge
                .solve(&make_query(make_ult(&arena, below, c256), &[], &arena))
                .outcome,
            SolverOutcomeKind::Sat
        );
        assert_eq!(
            bridge
                .solve(&make_query(make_ult(&arena, c256, above), &[], &arena))
                .outcome,
            SolverOutcomeKind::Sat
        );
        Ok(())
    }

    /// Same shape at 512 bits (zmm width): 2^400 vs its neighbors and 1.
    #[test]
    fn z3_512bit_constant_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let arena = make_arena();
        let c512 = make_const_pow2(&arena, 512, 400);
        let one = make_const(&arena, 512, 1);

        let reader: Arc<dyn ExprReader> = arena.clone();
        let mut bridge = Z3FfiBridge::new(reader)?;

        assert_eq!(
            bridge
                .solve(&make_query(make_eq(&arena, c512, c512), &[], &arena))
                .outcome,
            SolverOutcomeKind::Sat
        );
        let c_plus_1 = make_binop(&arena, ExprOp::Add, 512, c512, one);
        assert_eq!(
            bridge
                .solve(&make_query(make_eq(&arena, c512, c_plus_1), &[], &arena))
                .outcome,
            SolverOutcomeKind::Unsat
        );
        assert_eq!(
            bridge
                .solve(&make_query(make_ult(&arena, c512, one), &[], &arena))
                .outcome,
            SolverOutcomeKind::Unsat
        );
        assert_eq!(
            bridge
                .solve(&make_query(make_ult(&arena, one, c512), &[], &arena))
                .outcome,
            SolverOutcomeKind::Sat
        );
        let below = make_const_pow2(&arena, 512, 399);
        let above = make_const_pow2(&arena, 512, 401);
        assert_eq!(
            bridge
                .solve(&make_query(make_ult(&arena, below, c512), &[], &arena))
                .outcome,
            SolverOutcomeKind::Sat
        );
        assert_eq!(
            bridge
                .solve(&make_query(make_ult(&arena, c512, above), &[], &arena))
                .outcome,
            SolverOutcomeKind::Sat
        );
        Ok(())
    }

    /// A >128-bit symbol must appear in the extracted model with a
    /// full-width little-endian value — the old u128 parse of Z3's decimal
    /// numeral failed and silently dropped the symbol from the model.
    #[test]
    fn z3_256bit_symbol_model_full_width() -> Result<(), Box<dyn std::error::Error>> {
        let arena = make_arena();
        let x = make_symbol(&arena, 256, 7);
        let one = make_const(&arena, 256, 1);
        let upper = make_const_pow2(&arena, 256, 200); // x < 2^200

        let reader: Arc<dyn ExprReader> = arena.clone();
        let mut bridge = Z3FfiBridge::new(reader)?;

        let pred = make_ult(&arena, one, x);
        let bounded = make_ult(&arena, x, upper);
        let result = bridge.solve(&make_query(pred, &[(ConstraintId(1), bounded)], &arena));
        assert_eq!(result.outcome, SolverOutcomeKind::Sat);
        let entry = result.model.iter().find(|(sym, _)| *sym == u64::from(x.0));
        let (_, bytes) = entry.expect("256-bit symbol must appear in the model");
        assert_eq!(bytes.len(), 32, "model value must be full-width (32 bytes)");
        assert!(
            bytes[26..].iter().all(|&b| b == 0),
            "x < 2^200 forces bytes 26..32 to zero"
        );
        assert!(bytes[25] <= 1, "x < 2^200 forces byte 25 into {{0, 1}}");
        let is_zero = bytes.iter().all(|&b| b == 0);
        let is_one = bytes[0] == 1 && bytes[1..].iter().all(|&b| b == 0);
        assert!(!is_zero && !is_one, "1 < x must hold in the model");
        Ok(())
    }

    /// The rotate lowering folds a constant count through the full
    /// little-endian immediate: for a 96-bit rotate, count 2^200 is
    /// congruent to 64 (mod 96), while the old u128 fold saw only the low 16
    /// bytes (all zero) and rotated by 0. The value operand is pinned to 1
    /// by a path constraint — with a free symbolic value, any two rotation
    /// amounts agree on rotate-invariant values (0, all-ones), so the query
    /// must constrain `x` for the amount to be observable. RotL(1, a) over
    /// 96 bits is exactly 2^(a mod 96), making the amount uniquely visible.
    #[test]
    fn z3_rotate_wide_constant_count() -> Result<(), Box<dyn std::error::Error>> {
        let arena = make_arena();
        let x = make_symbol(&arena, 96, 3);
        let count256 = make_const_pow2(&arena, 256, 200); // 2^200 ≡ 64 (mod 96)
        let rot_by_wide = make_rotate(&arena, ExprOp::RotL, 96, x, count256);
        let expect_64 = make_eq(&arena, rot_by_wide, make_const_pow2(&arena, 96, 64));
        let expect_63 = make_eq(&arena, rot_by_wide, make_const_pow2(&arena, 96, 63));
        let x_is_one = make_eq(&arena, x, make_const(&arena, 96, 1));

        let reader: Arc<dyn ExprReader> = arena.clone();
        let mut bridge = Z3FfiBridge::new(reader)?;

        assert_eq!(
            bridge
                .solve(&make_query(expect_64, &[(ConstraintId(1), x_is_one)], &arena))
                .outcome,
            SolverOutcomeKind::Sat,
            "2^200 mod 96 == 64: the wide constant count must rotate 1 into 2^64, not leave it (amount 0)"
        );
        assert_eq!(
            bridge
                .solve(&make_query(expect_63, &[(ConstraintId(1), x_is_one)], &arena))
                .outcome,
            SolverOutcomeKind::Unsat,
            "the amount must be 64, not 63: rotating 1 by 63 gives 2^63, not 2^64"
        );
        Ok(())
    }
}

#[cfg(test)]
mod unsat_core_tests {
    use super::*;
    use angryier_expr::{ExprArena, ExprNode, ExprOp, ExprSort, ShardedExprArena};
    use angryier_solver::{CanonicalConstraint, SolverQuery};
    use angryier_types::{ConstraintCanonicalizationVersion, ConstraintId, SolverQueryId, TargetProfileId};
    use std::sync::Arc;
    use std::time::Duration;

    /// A query with two contradictory constraints (x==0 ∧ x==1, predicate
    /// x>2) must return UNSAT and name both constraints in the core.
    #[test]
    fn unsat_core_names_responsible_constraints() {
        let arena = Arc::new(ShardedExprArena::new(angryier_types::ExpressionNormalizationVersion(1)));
        let x = arena
            .intern(ExprNode {
                sort: ExprSort::BitVec(64),
                op: ExprOp::Symbol,
                operands: Vec::new(),
                immediate: 7u64.to_le_bytes().to_vec(),
            })
            .unwrap();
        let zero = arena
            .intern(ExprNode {
                sort: ExprSort::BitVec(64),
                op: ExprOp::Constant,
                operands: Vec::new(),
                immediate: 0u64.to_le_bytes().to_vec(),
            })
            .unwrap();
        let one = arena
            .intern(ExprNode {
                sort: ExprSort::BitVec(64),
                op: ExprOp::Constant,
                operands: Vec::new(),
                immediate: 1u64.to_le_bytes().to_vec(),
            })
            .unwrap();
        let eq0 = arena
            .intern(ExprNode {
                sort: ExprSort::Bool,
                op: ExprOp::Eq,
                operands: vec![x, zero],
                immediate: Vec::new(),
            })
            .unwrap();
        let eq1 = arena
            .intern(ExprNode {
                sort: ExprSort::Bool,
                op: ExprOp::Eq,
                operands: vec![x, one],
                immediate: Vec::new(),
            })
            .unwrap();
        let two = arena
            .intern(ExprNode {
                sort: ExprSort::BitVec(64),
                op: ExprOp::Constant,
                operands: Vec::new(),
                immediate: 2u64.to_le_bytes().to_vec(),
            })
            .unwrap();
        let gt = arena
            .intern(ExprNode {
                sort: ExprSort::Bool,
                op: ExprOp::Ult,
                operands: vec![x, two],
                immediate: Vec::new(),
            })
            .unwrap();

        let c0 = CanonicalConstraint {
            id: ConstraintId(0),
            key: arena.dependency_summary(eq0).unwrap().key,
            expr: eq0,
        };
        let c1 = CanonicalConstraint {
            id: ConstraintId(1),
            key: arena.dependency_summary(eq1).unwrap().key,
            expr: eq1,
        };
        let pred_key = arena.dependency_summary(gt).unwrap().key;
        let query = SolverQuery::canonical(
            SolverQueryId(0),
            &[c0, c1],
            gt,
            pred_key,
            TargetProfileId(1),
            ConstraintCanonicalizationVersion(1),
            Duration::from_secs(5),
        )
        .unwrap();

        let reader: Arc<dyn ExprReader> = arena.clone();
        let mut bridge = Z3FfiBridge::new(reader).expect("z3");
        let result = bridge.solve(&query);
        assert_eq!(result.outcome, SolverOutcomeKind::Unsat);
        assert!(
            result.unsat_core.contains(&ConstraintId(0)) && result.unsat_core.contains(&ConstraintId(1)),
            "core should name both contradictory constraints, got {:?}",
            result.unsat_core
        );
    }
}
