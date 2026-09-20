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
use std::sync::Arc;
use z3_sys::*;

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
    /// Persistent solver for incremental queries — scopes are pushed one
    /// per path constraint so consecutive queries sharing a constraint
    /// prefix reuse the solver's learned state instead of rebuilding.
    solver: Z3_solver,
    /// Dependency key + tracking literal per live scope (scope i asserts
    /// `assumption_i → constraint_i` so UNSAT cores name the culprit
    /// constraints).
    scope_keys: Vec<(angryier_types::DependencyKey, angryier_types::ConstraintId, Z3_ast)>,
}

// SAFETY: The caller must ensure single-threaded access to the Z3 context.
unsafe impl Send for Z3FfiBridge {}

impl Z3FfiBridge {
    /// Create a new Z3 FFI bridge with the given expression reader.
    pub fn new(reader: Arc<dyn ExprReader>) -> Result<Self, Z3FfiError> {
        let context = unsafe {
            let config = Z3_mk_config().ok_or(Z3FfiError::NullContext)?;
            let ctx = Z3_mk_context(config);
            Z3_del_config(config);
            ctx.ok_or(Z3FfiError::NullContext)?
        };
        let solver = unsafe {
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
            scope_keys: Vec::new(),
        })
    }

    /// Incremental solve over the persistent solver: pops the scopes past
    /// the longest shared constraint-key prefix, pushes the suffix, then
    /// checks the predicate in a transient scope. Returns `None` to signal
    /// the caller should fall back to a fresh solver (timeout param is
    /// set per-query and can't be scoped).
    fn solve_incremental(&mut self, query: &SolverQuery) -> SolverResult {
        if query.validate_identity().is_err() {
            return backend_error();
        }
        let ctx = self.context;
        // Per-query timeout on the persistent solver.
        let timeout_ms = query.timeout().as_millis();
        if timeout_ms > 0 {
            unsafe {
                if let Some(params) = Z3_mk_params(ctx) {
                    Z3_params_inc_ref(ctx, params);
                    if let Some(key) = Z3_mk_string_symbol(ctx, c"timeout".as_ptr()) {
                        Z3_params_set_uint(ctx, params, key, timeout_ms as u32);
                        Z3_solver_set_params(ctx, self.solver, params);
                    }
                    Z3_params_dec_ref(ctx, params);
                }
            }
        }
        let keys = query.constraint_keys();
        // Longest common prefix of live scopes and this query's constraints.
        let shared = self
            .scope_keys
            .iter()
            .zip(keys.iter())
            .take_while(|((a, _, _), b)| a == *b)
            .count();
        let excess = self.scope_keys.len() - shared;
        if excess > 0 {
            unsafe { Z3_solver_pop(ctx, self.solver, excess as u32) };
            self.scope_keys.truncate(shared);
        }
        let mut cache = HashMap::new();
        let mut symbols = HashMap::new();
        // Push one scope per new constraint, guarded by a fresh assumption
        // literal so UNSAT cores name the responsible constraints.
        for ((cid, expr), key) in query.constraint_expressions().iter().zip(keys.iter()).skip(shared) {
            match self.translate(*expr, &mut cache, &mut symbols) {
                Ok(ast) => unsafe {
                    Z3_solver_push(ctx, self.solver);
                    let sym_name = std::ffi::CString::new(format!("pc{}", self.scope_keys.len())).unwrap_or_default();
                    let name = Z3_mk_string_symbol(ctx, sym_name.as_ptr());
                    let bool_sort = Z3_mk_bool_sort(ctx);
                    let assumption = match (name, bool_sort) {
                        (Some(n), Some(s)) => Z3_mk_const(ctx, n, s),
                        _ => None,
                    };
                    let Some(assumption) = assumption else {
                        return backend_error();
                    };
                    if let Some(imp) = Z3_mk_implies(ctx, assumption, ast) {
                        Z3_solver_assert(ctx, self.solver, imp);
                    }
                    self.scope_keys.push((*key, *cid, assumption));
                },
                Err(_) => return backend_error(),
            }
        }
        // Transient scope for the predicate.
        unsafe { Z3_solver_push(ctx, self.solver) };
        let failed = match self.translate(query.predicate(), &mut cache, &mut symbols) {
            Ok(ast) => {
                unsafe { Z3_solver_assert(ctx, self.solver, ast) };
                false
            }
            Err(_) => true,
        };
        let result = if failed {
            backend_error()
        } else {
            self.check_and_extract(&mut symbols)
        };
        unsafe { Z3_solver_pop(ctx, self.solver, 1) };
        result
    }

    /// Runs `check` on the persistent solver and extracts the model —
    /// factored so the incremental path and the fallback share it.
    fn check_and_extract(&self, symbols: &mut HashMap<ExprId, Z3_ast>) -> SolverResult {
        let ctx = self.context;
        unsafe {
            // Check under the live scope assumptions — the UNSAT core names
            // which constraint literals are responsible.
            let assumptions: Vec<Z3_ast> = self.scope_keys.iter().map(|(_, _, a)| *a).collect();
            let result = Z3_solver_check_assumptions(ctx, self.solver, assumptions.len() as u32, assumptions.as_ptr());
            let outcome = if result == Z3_L_TRUE {
                SolverOutcomeKind::Sat
            } else if result == Z3_L_FALSE {
                SolverOutcomeKind::Unsat
            } else {
                SolverOutcomeKind::Unknown
            };
            let model = if outcome == SolverOutcomeKind::Sat {
                match Z3_solver_get_model(ctx, self.solver) {
                    Some(model) => {
                        Z3_model_inc_ref(ctx, model);
                        let mut extracted = Vec::new();
                        for (sym_id, ast) in symbols.iter() {
                            let mut eval_result: std::mem::MaybeUninit<Z3_ast> = std::mem::MaybeUninit::zeroed();
                            let success = Z3_model_eval(ctx, model, *ast, true, eval_result.as_mut_ptr());
                            if success {
                                let eval_ast = eval_result.assume_init();
                                if let Some(bytes) = numeral_to_bytes(ctx, eval_ast) {
                                    extracted.push((u64::from(sym_id.0), bytes));
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
                                && let Some((_, cid, _)) = self.scope_keys.iter().find(|(_, _, a)| *a == ast)
                            {
                                ids.push(*cid);
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

    fn translate(
        &self,
        id: ExprId,
        cache: &mut HashMap<ExprId, Z3_ast>,
        symbols: &mut HashMap<ExprId, Z3_ast>,
    ) -> Result<Z3_ast, Z3FfiError> {
        if let Some(&ast) = cache.get(&id) {
            return Ok(ast);
        }
        let node = self.reader.read(id).ok_or(Z3FfiError::UnresolvedExpression(id))?;
        let ast = self.translate_node(id, &node, cache, symbols)?;
        cache.insert(id, ast);
        Ok(ast)
    }

    fn translate_node(
        &self,
        id: ExprId,
        node: &ExprNode,
        cache: &mut HashMap<ExprId, Z3_ast>,
        symbols: &mut HashMap<ExprId, Z3_ast>,
    ) -> Result<Z3_ast, Z3FfiError> {
        let ctx = self.context;
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
                    // Convert little-endian bytes to a decimal string for Z3
                    let mut value: u128 = 0;
                    for (i, &b) in bytes.iter().enumerate() {
                        value |= u128::from(b) << (i * 8);
                    }
                    let numeral_str = value.to_string();
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
                let left = self.translate(node.operands[0], cache, symbols)?;
                let right = self.translate(node.operands[1], cache, symbols)?;
                let ast = unsafe {
                    match node.op {
                        ExprOp::Add => Z3_mk_bvadd(ctx, left, right),
                        ExprOp::Sub => Z3_mk_bvsub(ctx, left, right),
                        ExprOp::Mul => Z3_mk_bvmul(ctx, left, right),
                        ExprOp::UDiv => Z3_mk_bvudiv(ctx, left, right),
                        ExprOp::SDiv => Z3_mk_bvsdiv(ctx, left, right),
                        ExprOp::And => Z3_mk_bvand(ctx, left, right),
                        ExprOp::Or => Z3_mk_bvor(ctx, left, right),
                        ExprOp::Xor => Z3_mk_bvxor(ctx, left, right),
                        ExprOp::Shl => Z3_mk_bvshl(ctx, left, right),
                        ExprOp::LShr => Z3_mk_bvlshr(ctx, left, right),
                        ExprOp::AShr => Z3_mk_bvashr(ctx, left, right),
                        _ => return Err(Z3FfiError::MalformedExpression),
                    }
                }
                .ok_or(Z3FfiError::NullAst)?;
                Ok(ast)
            }
            ExprOp::Not => {
                if node.operands.len() != 1 {
                    return Err(Z3FfiError::MalformedExpression);
                }
                let operand = self.translate(node.operands[0], cache, symbols)?;
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
                let left = self.translate(node.operands[0], cache, symbols)?;
                let right = self.translate(node.operands[1], cache, symbols)?;
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
                let cond = self.translate(node.operands[0], cache, symbols)?;
                let then_val = self.translate(node.operands[1], cache, symbols)?;
                let else_val = self.translate(node.operands[2], cache, symbols)?;
                let ast = unsafe { Z3_mk_ite(ctx, cond, then_val, else_val) }.ok_or(Z3FfiError::NullAst)?;
                Ok(ast)
            }
            ExprOp::Concat => {
                if node.operands.len() != 2 {
                    return Err(Z3FfiError::MalformedExpression);
                }
                let low = self.translate(node.operands[0], cache, symbols)?;
                let high = self.translate(node.operands[1], cache, symbols)?;
                let ast = unsafe { Z3_mk_concat(ctx, high, low) }.ok_or(Z3FfiError::NullAst)?;
                Ok(ast)
            }
            ExprOp::Extract => {
                if node.operands.len() != 2 {
                    return Err(Z3FfiError::MalformedExpression);
                }
                let operand = self.translate(node.operands[0], cache, symbols)?;
                let start_node = self
                    .reader
                    .read(node.operands[1])
                    .ok_or(Z3FfiError::UnresolvedExpression(node.operands[1]))?;
                let start = bytes_to_u64(&start_node.immediate);
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
                let operand = self.translate(node.operands[0], cache, symbols)?;
                let operand_node = self
                    .reader
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
                if output_bits <= input_bits {
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
        unsafe {
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

/// Extract a numeral value from a Z3 AST as little-endian bytes.
unsafe fn numeral_to_bytes(ctx: Z3_context, ast: Z3_ast) -> Option<Vec<u8>> {
    let str_ptr = unsafe { Z3_get_numeral_string(ctx, ast) };
    if str_ptr.is_null() {
        return None;
    }
    let c_str = unsafe { std::ffi::CStr::from_ptr(str_ptr) };
    let s = c_str.to_str().ok()?;
    // Z3 returns decimal; parse as u128 and convert to bytes
    let val: u128 = s.parse().ok()?;
    Some(val.to_le_bytes().to_vec())
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
        let immediate = value.to_le_bytes()[..byte_width].to_vec();
        arena
            .intern(ExprNode {
                sort: ExprSort::BitVec(width),
                op: ExprOp::Constant,
                operands: Vec::new(),
                immediate,
            })
            .unwrap_or(ExprId(0))
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
