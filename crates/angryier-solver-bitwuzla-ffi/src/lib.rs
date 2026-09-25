//! Native Bitwuzla solver backend via FFI.
//!
//! This crate translates Angryier expression trees to Bitwuzla terms and uses
//! Bitwuzla to check satisfiability of path constraints. The `bitwuzla-sys`
//! crate vendors and builds Bitwuzla from source, so no system installation is
//! required.

#![allow(unsafe_code)]
#![allow(unsafe_op_in_unsafe_fn)]

use angryier_expr::{ExprNode, ExprOp, ExprReader, ExprSort};
use angryier_solver::{SolverBackend, SolverQuery, SolverResult};
use angryier_types::{ConstraintId, ExprId, SolverOutcomeKind};
use bitwuzla_sys::*;
use core::time::Duration;
use std::collections::HashMap;
use std::sync::Arc;

/// Error returned by the Bitwuzla FFI bridge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitwuzlaFfiError {
    UnresolvedExpression(ExprId),
    NullTermManager,
    NullBitwuzla,
    NullOptions,
    UnsupportedSort,
    MalformedExpression,
}

impl core::fmt::Display for BitwuzlaFfiError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnresolvedExpression(id) => write!(f, "unresolved expression id {}", id.0),
            Self::NullTermManager => f.write_str("Bitwuzla term manager creation failed"),
            Self::NullBitwuzla => f.write_str("Bitwuzla instance creation failed"),
            Self::NullOptions => f.write_str("Bitwuzla options creation failed"),
            Self::UnsupportedSort => f.write_str("unsupported expression sort"),
            Self::MalformedExpression => f.write_str("malformed expression tree"),
        }
    }
}

impl std::error::Error for BitwuzlaFfiError {}

/// Native Bitwuzla solver backend.
pub struct BitwuzlaFfiBridge {
    reader: Arc<dyn ExprReader>,
    term_manager: *mut BitwuzlaTermManager,
}

// SAFETY: The caller must ensure single-threaded access.
unsafe impl Send for BitwuzlaFfiBridge {}

impl BitwuzlaFfiBridge {
    /// Create a new Bitwuzla FFI bridge with the given expression reader.
    pub fn new(reader: Arc<dyn ExprReader>) -> Result<Self, BitwuzlaFfiError> {
        let term_manager = unsafe { bitwuzla_term_manager_new() };
        if term_manager.is_null() {
            return Err(BitwuzlaFfiError::NullTermManager);
        }
        Ok(Self { reader, term_manager })
    }

    fn translate(
        &self,
        id: ExprId,
        cache: &mut HashMap<ExprId, BitwuzlaTerm>,
        symbols: &mut HashMap<ExprId, BitwuzlaTerm>,
    ) -> Result<BitwuzlaTerm, BitwuzlaFfiError> {
        if let Some(&term) = cache.get(&id) {
            return Ok(term);
        }
        let node = self.reader.read(id).ok_or(BitwuzlaFfiError::UnresolvedExpression(id))?;
        let term = self.translate_node(id, &node, cache, symbols)?;
        cache.insert(id, term);
        Ok(term)
    }

    fn translate_node(
        &self,
        id: ExprId,
        node: &ExprNode,
        cache: &mut HashMap<ExprId, BitwuzlaTerm>,
        symbols: &mut HashMap<ExprId, BitwuzlaTerm>,
    ) -> Result<BitwuzlaTerm, BitwuzlaFfiError> {
        let tm = self.term_manager;
        match node.op {
            ExprOp::Constant => match node.sort {
                ExprSort::BitVec(width) => {
                    let sort = unsafe { bitwuzla_mk_bv_sort(tm, width as u64) };
                    let byte_width = usize::from(width).div_ceil(8);
                    let mut bytes = node.immediate.clone();
                    if bytes.len() < byte_width {
                        bytes.resize(byte_width, 0);
                    }
                    bytes.truncate(byte_width);
                    let mut value: u128 = 0;
                    for (i, &b) in bytes.iter().enumerate() {
                        value |= u128::from(b) << (i * 8);
                    }
                    let val_str = value.to_string();
                    let c_str =
                        std::ffi::CString::new(val_str.as_str()).map_err(|_| BitwuzlaFfiError::MalformedExpression)?;
                    let term = unsafe { bitwuzla_mk_bv_value(tm, sort, c_str.as_ptr(), 10) };
                    Ok(term)
                }
                ExprSort::Bool => {
                    let is_true = node.immediate.first().copied().is_some_and(|b| b != 0);
                    unsafe {
                        if is_true {
                            Ok(bitwuzla_mk_true(tm))
                        } else {
                            Ok(bitwuzla_mk_false(tm))
                        }
                    }
                }
                _ => Err(BitwuzlaFfiError::UnsupportedSort),
            },
            ExprOp::Symbol => {
                let sort = match node.sort {
                    ExprSort::BitVec(width) => unsafe { bitwuzla_mk_bv_sort(tm, width as u64) },
                    ExprSort::Bool => unsafe { bitwuzla_mk_bool_sort(tm) },
                    _ => return Err(BitwuzlaFfiError::UnsupportedSort),
                };
                let name_str = format!("sym_{}", id.0);
                let c_name =
                    std::ffi::CString::new(name_str.as_str()).map_err(|_| BitwuzlaFfiError::MalformedExpression)?;
                let term = unsafe { bitwuzla_mk_const(tm, sort, c_name.as_ptr()) };
                symbols.insert(id, term);
                Ok(term)
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
                    return Err(BitwuzlaFfiError::MalformedExpression);
                }
                let left = self.translate(node.operands[0], cache, symbols)?;
                let right = self.translate(node.operands[1], cache, symbols)?;
                let kind = match node.op {
                    ExprOp::Add => BITWUZLA_KIND_BV_ADD,
                    ExprOp::Sub => BITWUZLA_KIND_BV_SUB,
                    ExprOp::Mul => BITWUZLA_KIND_BV_MUL,
                    ExprOp::UDiv => BITWUZLA_KIND_BV_UDIV,
                    ExprOp::SDiv => BITWUZLA_KIND_BV_SDIV,
                    ExprOp::And => BITWUZLA_KIND_BV_AND,
                    ExprOp::Or => BITWUZLA_KIND_BV_OR,
                    ExprOp::Xor => BITWUZLA_KIND_BV_XOR,
                    ExprOp::Shl => BITWUZLA_KIND_BV_SHL,
                    ExprOp::LShr => BITWUZLA_KIND_BV_SHR,
                    ExprOp::AShr => BITWUZLA_KIND_BV_ASHR,
                    _ => return Err(BitwuzlaFfiError::MalformedExpression),
                };
                let term = unsafe { bitwuzla_mk_term2(tm, kind, left, right) };
                Ok(term)
            }
            ExprOp::RotL | ExprOp::RotR => {
                if node.operands.len() != 2 {
                    return Err(BitwuzlaFfiError::MalformedExpression);
                }
                let width = match node.sort {
                    ExprSort::BitVec(w) => u64::from(w),
                    _ => return Err(BitwuzlaFfiError::UnsupportedSort),
                };
                let value = self.translate(node.operands[0], cache, symbols)?;
                let count_node = self
                    .reader
                    .read(node.operands[1])
                    .ok_or(BitwuzlaFfiError::UnresolvedExpression(node.operands[1]))?;
                let count_width = match count_node.sort {
                    ExprSort::BitVec(w) => u64::from(w),
                    _ => return Err(BitwuzlaFfiError::UnsupportedSort),
                };
                let count = self.translate(node.operands[1], cache, symbols)?;
                // Bitwuzla's ROL/ROR are indexed by a numeral amount, so a
                // constant count uses the indexed kinds with the count taken
                // modulo the width (the op's defining semantics).
                if count_node.op == ExprOp::Constant {
                    let mut raw: u128 = 0;
                    for (i, &b) in count_node.immediate.iter().enumerate().take(16) {
                        raw |= u128::from(b) << (i * 8);
                    }
                    let amount =
                        u64::try_from(raw % u128::from(width)).map_err(|_| BitwuzlaFfiError::MalformedExpression)?;
                    let kind = if node.op == ExprOp::RotL {
                        BITWUZLA_KIND_BV_ROL
                    } else {
                        BITWUZLA_KIND_BV_ROR
                    };
                    let term = unsafe { bitwuzla_mk_term1_indexed1(tm, kind, value, amount) };
                    return Ok(term);
                }
                // Symbolic count: normalize it to the value's width, then
                // lower rot(x, n) to (x shifted by m) | (x shifted by
                // (width - m)) with m = urem(n, width). When m = 0 the
                // counter-shift is `width`, whose SMT shift semantics yield 0
                // — the identity rotation falls out.
                let count = if count_width < width {
                    unsafe { bitwuzla_mk_term1_indexed1(tm, BITWUZLA_KIND_BV_ZERO_EXTEND, count, width - count_width) }
                } else if count_width > width {
                    unsafe { bitwuzla_mk_term1_indexed2(tm, BITWUZLA_KIND_BV_EXTRACT, count, width - 1, 0) }
                } else {
                    count
                };
                let width_sort = unsafe { bitwuzla_mk_bv_sort(tm, width) };
                let width_value = unsafe { bitwuzla_mk_bv_value_uint64(tm, width_sort, width) };
                let amount = unsafe { bitwuzla_mk_term2(tm, BITWUZLA_KIND_BV_UREM, count, width_value) };
                let counter_amount = unsafe { bitwuzla_mk_term2(tm, BITWUZLA_KIND_BV_SUB, width_value, amount) };
                let (by_amount, by_counter) = if node.op == ExprOp::RotL {
                    let shifted = unsafe { bitwuzla_mk_term2(tm, BITWUZLA_KIND_BV_SHL, value, amount) };
                    let countered = unsafe { bitwuzla_mk_term2(tm, BITWUZLA_KIND_BV_SHR, value, counter_amount) };
                    (shifted, countered)
                } else {
                    let shifted = unsafe { bitwuzla_mk_term2(tm, BITWUZLA_KIND_BV_SHR, value, amount) };
                    let countered = unsafe { bitwuzla_mk_term2(tm, BITWUZLA_KIND_BV_SHL, value, counter_amount) };
                    (shifted, countered)
                };
                let term = unsafe { bitwuzla_mk_term2(tm, BITWUZLA_KIND_BV_OR, by_amount, by_counter) };
                Ok(term)
            }
            ExprOp::Not => {
                if node.operands.len() != 1 {
                    return Err(BitwuzlaFfiError::MalformedExpression);
                }
                let operand = self.translate(node.operands[0], cache, symbols)?;
                let kind = match node.sort {
                    ExprSort::Bool => BITWUZLA_KIND_NOT,
                    _ => BITWUZLA_KIND_BV_NOT,
                };
                let term = unsafe { bitwuzla_mk_term1(tm, kind, operand) };
                Ok(term)
            }
            ExprOp::Eq | ExprOp::Ult | ExprOp::Ule | ExprOp::Slt | ExprOp::Sle => {
                if node.operands.len() != 2 {
                    return Err(BitwuzlaFfiError::MalformedExpression);
                }
                let left = self.translate(node.operands[0], cache, symbols)?;
                let right = self.translate(node.operands[1], cache, symbols)?;
                let kind = match node.op {
                    ExprOp::Eq => BITWUZLA_KIND_EQUAL,
                    ExprOp::Ult => BITWUZLA_KIND_BV_ULT,
                    ExprOp::Ule => BITWUZLA_KIND_BV_ULE,
                    ExprOp::Slt => BITWUZLA_KIND_BV_SLT,
                    ExprOp::Sle => BITWUZLA_KIND_BV_SLE,
                    _ => return Err(BitwuzlaFfiError::MalformedExpression),
                };
                let term = unsafe { bitwuzla_mk_term2(tm, kind, left, right) };
                Ok(term)
            }
            ExprOp::Ite => {
                if node.operands.len() != 3 {
                    return Err(BitwuzlaFfiError::MalformedExpression);
                }
                let cond = self.translate(node.operands[0], cache, symbols)?;
                let then_val = self.translate(node.operands[1], cache, symbols)?;
                let else_val = self.translate(node.operands[2], cache, symbols)?;
                let term = unsafe { bitwuzla_mk_term3(tm, BITWUZLA_KIND_ITE, cond, then_val, else_val) };
                Ok(term)
            }
            ExprOp::Concat => {
                if node.operands.len() != 2 {
                    return Err(BitwuzlaFfiError::MalformedExpression);
                }
                let low = self.translate(node.operands[0], cache, symbols)?;
                let high = self.translate(node.operands[1], cache, symbols)?;
                let term = unsafe { bitwuzla_mk_term2(tm, BITWUZLA_KIND_BV_CONCAT, high, low) };
                Ok(term)
            }
            ExprOp::Extract => {
                if node.operands.len() != 2 {
                    return Err(BitwuzlaFfiError::MalformedExpression);
                }
                let operand = self.translate(node.operands[0], cache, symbols)?;
                let start_node = self
                    .reader
                    .read(node.operands[1])
                    .ok_or(BitwuzlaFfiError::UnresolvedExpression(node.operands[1]))?;
                let start = bytes_to_u64(&start_node.immediate);
                let width = match node.sort {
                    ExprSort::BitVec(w) => w,
                    _ => return Err(BitwuzlaFfiError::UnsupportedSort),
                };
                let high = start + u64::from(width) - 1;
                let low = start;
                let term = unsafe { bitwuzla_mk_term1_indexed2(tm, BITWUZLA_KIND_BV_EXTRACT, operand, high, low) };
                Ok(term)
            }
            ExprOp::ZExt | ExprOp::SExt => {
                if node.operands.len() != 1 {
                    return Err(BitwuzlaFfiError::MalformedExpression);
                }
                let operand = self.translate(node.operands[0], cache, symbols)?;
                let operand_node = self
                    .reader
                    .read(node.operands[0])
                    .ok_or(BitwuzlaFfiError::UnresolvedExpression(node.operands[0]))?;
                let input_bits = match operand_node.sort {
                    ExprSort::BitVec(w) => w,
                    _ => return Err(BitwuzlaFfiError::UnsupportedSort),
                };
                let output_bits = match node.sort {
                    ExprSort::BitVec(w) => w,
                    _ => return Err(BitwuzlaFfiError::UnsupportedSort),
                };
                if output_bits <= input_bits {
                    return Err(BitwuzlaFfiError::MalformedExpression);
                }
                let diff = (output_bits - input_bits) as u64;
                let kind = if node.op == ExprOp::ZExt {
                    BITWUZLA_KIND_BV_ZERO_EXTEND
                } else {
                    BITWUZLA_KIND_BV_SIGN_EXTEND
                };
                let term = unsafe { bitwuzla_mk_term1_indexed1(tm, kind, operand, diff) };
                Ok(term)
            }
        }
    }

    fn solve_query(&self, query: &SolverQuery) -> SolverResult {
        if query.validate_identity().is_err() {
            return backend_error();
        }

        let tm = self.term_manager;
        unsafe {
            let options = bitwuzla_options_new();
            if options.is_null() {
                return backend_error();
            }
            bitwuzla_set_option(options, BITWUZLA_OPT_PRODUCE_MODELS, 1);

            let bzla = bitwuzla_new(tm, options);
            bitwuzla_options_delete(options);
            if bzla.is_null() {
                return backend_error();
            }

            let mut cache = HashMap::new();
            let mut symbols = HashMap::new();

            let mut failed = false;
            for (_constraint_id, expr_id) in query.constraint_expressions() {
                match self.translate(*expr_id, &mut cache, &mut symbols) {
                    Ok(term) => {
                        bitwuzla_assert(bzla, term);
                    }
                    Err(_) => {
                        failed = true;
                        break;
                    }
                }
            }

            if !failed {
                match self.translate(query.predicate(), &mut cache, &mut symbols) {
                    Ok(term) => {
                        bitwuzla_assert(bzla, term);
                    }
                    Err(_) => {
                        failed = true;
                    }
                }
            }

            if failed {
                bitwuzla_delete(bzla);
                return backend_error();
            }

            let result = bitwuzla_check_sat(bzla);
            let outcome = if result == BITWUZLA_SAT {
                SolverOutcomeKind::Sat
            } else if result == BITWUZLA_UNSAT {
                SolverOutcomeKind::Unsat
            } else {
                SolverOutcomeKind::Unknown
            };

            let model = if outcome == SolverOutcomeKind::Sat {
                let mut extracted = Vec::new();
                for (sym_id, term) in &symbols {
                    let value_term = bitwuzla_get_value(bzla, *term);
                    let str_ptr = bitwuzla_term_value_get_str(value_term);
                    if !str_ptr.is_null()
                        && let Ok(c_str) = std::ffi::CStr::from_ptr(str_ptr).to_str()
                        && let Ok(val) = u128::from_str_radix(c_str, 2)
                    {
                        extracted.push((u64::from(sym_id.0), val.to_le_bytes().to_vec()));
                    }
                }
                extracted
            } else {
                Vec::new()
            };

            bitwuzla_delete(bzla);

            SolverResult {
                outcome,
                model,
                unsat_core: Vec::new(),
                elapsed: Duration::ZERO,
            }
        }
    }
}

impl SolverBackend for BitwuzlaFfiBridge {
    fn name(&self) -> &'static str {
        "bitwuzla-ffi"
    }

    fn solve(&mut self, query: &SolverQuery) -> SolverResult {
        self.solve_query(query)
    }

    fn solve_batch(&mut self, _shared: &[ConstraintId], predicates: &[SolverQuery]) -> Vec<SolverResult> {
        predicates.iter().map(|q| self.solve_query(q)).collect()
    }
}

impl Drop for BitwuzlaFfiBridge {
    fn drop(&mut self) {
        unsafe {
            bitwuzla_term_manager_delete(self.term_manager);
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
    }

    #[test]
    fn bitwuzla_solves_simple_sat() -> Result<(), Box<dyn std::error::Error>> {
        let arena = make_arena();
        let x = make_symbol(&arena, 64, 1);
        let three = make_const(&arena, 64, 3);
        let five = make_const(&arena, 64, 5);
        let x_plus_3 = make_binop(&arena, ExprOp::Add, 64, x, three);
        let predicate = make_eq(&arena, x_plus_3, five);

        let reader: Arc<dyn ExprReader> = arena.clone();
        let mut bridge = BitwuzlaFfiBridge::new(reader)?;

        let query = make_query(predicate, &[], &arena);
        let result = bridge.solve(&query);

        assert_eq!(result.outcome, SolverOutcomeKind::Sat);
        assert!(!result.model.is_empty());
        Ok(())
    }

    #[test]
    fn bitwuzla_solves_truly_unsat() -> Result<(), Box<dyn std::error::Error>> {
        let arena = make_arena();
        let x = make_symbol(&arena, 64, 1);
        let three = make_const(&arena, 64, 3);
        let five = make_const(&arena, 64, 5);
        let two = make_const(&arena, 64, 2);
        let x_plus_3 = make_binop(&arena, ExprOp::Add, 64, x, three);
        let eq_two = make_eq(&arena, x_plus_3, two);
        let eq_five = make_eq(&arena, x_plus_3, five);

        let reader: Arc<dyn ExprReader> = arena.clone();
        let mut bridge = BitwuzlaFfiBridge::new(reader)?;

        let query = make_query(eq_two, &[(ConstraintId(1), eq_five)], &arena);
        let result = bridge.solve(&query);
        assert_eq!(result.outcome, SolverOutcomeKind::Unsat);
        Ok(())
    }

    #[test]
    fn bitwuzla_solves_with_ult_constraint() -> Result<(), Box<dyn std::error::Error>> {
        let arena = make_arena();
        let x = make_symbol(&arena, 64, 1);
        let ten = make_const(&arena, 64, 10);
        let twenty = make_const(&arena, 64, 20);
        let x_lt_20 = make_ult(&arena, x, twenty);
        let ten_lt_x = make_ult(&arena, ten, x);

        let reader: Arc<dyn ExprReader> = arena.clone();
        let mut bridge = BitwuzlaFfiBridge::new(reader)?;

        let query = make_query(x_lt_20, &[(ConstraintId(1), ten_lt_x)], &arena);
        let result = bridge.solve(&query);
        assert_eq!(result.outcome, SolverOutcomeKind::Sat);
        Ok(())
    }

    #[test]
    fn bitwuzla_backend_name() -> Result<(), Box<dyn std::error::Error>> {
        let arena = make_arena();
        let reader: Arc<dyn ExprReader> = arena.clone();
        let bridge = BitwuzlaFfiBridge::new(reader)?;
        assert_eq!(bridge.name(), "bitwuzla-ffi");
        Ok(())
    }
}
