#![forbid(unsafe_code)]

//! Taint and dataflow contracts with a concrete in-memory taint engine.
//!
//! The engine tracks how taint flows from sources through transforms and merges
//! to sinks, promoting heavily-transformed taint to symbolic values once a
//! configurable transform-count threshold is crossed.

use angryier_types::{ExprId, TaintId};
use std::{
    collections::BTreeMap,
    sync::{
        RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TaintEventKind {
    Source,
    Transform,
    Merge,
    Sink,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaintRecord {
    pub id: TaintId,
    pub kind: TaintEventKind,
    pub parents: Vec<TaintId>,
    pub expression: Option<ExprId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromotionDecision {
    StayConcrete,
    TrackTaint,
    PromoteSymbolic,
}

pub trait TaintEngine: Send + Sync {
    fn record(&self, record: TaintRecord);
    fn promotion_decision(&self, taint: TaintId) -> PromotionDecision;
}

/// The source category of a taint label.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TaintLabel {
    None,
    UserInput,
    NetworkInput,
    FileInput,
    Derived,
    Concrete,
}

/// The taint state of a value, tracked by taint identifier when non-concrete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaintState {
    Concrete,
    Tainted(TaintId),
    Symbolic(TaintId),
}

/// Errors returned by taint-engine operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TaintError {
    UnknownTaint,
    UnknownExpression,
    Poisoned,
    InvalidMerge,
}

impl core::fmt::Display for TaintError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::UnknownTaint => "unknown taint identifier",
            Self::UnknownExpression => "unknown expression identifier",
            Self::Poisoned => "taint engine synchronization primitive poisoned",
            Self::InvalidMerge => "invalid taint merge with no parents",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for TaintError {}

/// A concrete, thread-safe taint engine backed by in-memory maps.
pub struct InMemoryTaintEngine {
    next_id: AtomicU64,
    records: RwLock<BTreeMap<TaintId, TaintRecord>>,
    labels: RwLock<BTreeMap<TaintId, TaintLabel>>,
    states: RwLock<BTreeMap<ExprId, TaintState>>,
    promotion_threshold: u32,
    transform_counts: RwLock<BTreeMap<TaintId, u32>>,
}

impl InMemoryTaintEngine {
    /// Create an engine that promotes taint to symbolic after `promotion_threshold`
    /// transforms.
    pub fn new(promotion_threshold: u32) -> Self {
        Self {
            next_id: AtomicU64::new(1),
            records: RwLock::new(BTreeMap::new()),
            labels: RwLock::new(BTreeMap::new()),
            states: RwLock::new(BTreeMap::new()),
            promotion_threshold,
            transform_counts: RwLock::new(BTreeMap::new()),
        }
    }

    /// Create an engine with the default promotion threshold of 10 transforms.
    pub fn new_default() -> Self {
        Self::new(10)
    }

    fn allocate_id(&self) -> TaintId {
        TaintId(self.next_id.fetch_add(1, Ordering::Relaxed))
    }

    fn is_concrete_label(label: TaintLabel) -> bool {
        matches!(label, TaintLabel::Concrete | TaintLabel::None)
    }

    fn state_for_count(&self, id: TaintId, count: u32) -> TaintState {
        if count >= self.promotion_threshold {
            TaintState::Symbolic(id)
        } else {
            TaintState::Tainted(id)
        }
    }

    /// Create a new taint source, associating `label` with `expr`.
    ///
    /// Concrete/None labels produce a `Concrete` state; all other labels
    /// produce a `Tainted` state tracked by the returned identifier.
    pub fn source(&self, expr: ExprId, label: TaintLabel) -> TaintId {
        let id = self.allocate_id();
        let record = TaintRecord {
            id,
            kind: TaintEventKind::Source,
            parents: Vec::new(),
            expression: Some(expr),
        };
        let state = if Self::is_concrete_label(label) {
            TaintState::Concrete
        } else {
            TaintState::Tainted(id)
        };
        if let Ok(mut guard) = self.records.write() {
            guard.insert(id, record);
        }
        if let Ok(mut guard) = self.labels.write() {
            guard.insert(id, label);
        }
        if let Ok(mut guard) = self.states.write() {
            guard.insert(expr, state);
        }
        if let Ok(mut guard) = self.transform_counts.write() {
            guard.insert(id, 0);
        }
        id
    }

    /// Record a transform from `parent` taint, producing a new derived taint
    /// associated with `result_expr`.  The transform count is incremented
    /// relative to the parent's count.
    pub fn transform(&self, expr: ExprId, parent: TaintId, result_expr: ExprId) -> TaintId {
        let _ = expr;
        let id = self.allocate_id();
        let parent_count = match self.transform_counts.read() {
            Ok(guard) => guard.get(&parent).copied().unwrap_or(0),
            Err(_) => 0,
        };
        let new_count = parent_count.saturating_add(1);
        let state = self.state_for_count(id, new_count);
        let record = TaintRecord {
            id,
            kind: TaintEventKind::Transform,
            parents: vec![parent],
            expression: Some(result_expr),
        };
        if let Ok(mut guard) = self.records.write() {
            guard.insert(id, record);
        }
        if let Ok(mut guard) = self.labels.write() {
            guard.insert(id, TaintLabel::Derived);
        }
        if let Ok(mut guard) = self.states.write() {
            guard.insert(result_expr, state);
        }
        if let Ok(mut guard) = self.transform_counts.write() {
            guard.insert(id, new_count);
        }
        id
    }

    /// Merge taint from multiple `parents`, producing a new derived taint
    /// associated with `result_expr`.  The new transform count is one greater
    /// than the maximum parent count.
    pub fn merge(&self, expr: ExprId, parents: &[TaintId], result_expr: ExprId) -> TaintId {
        let _ = expr;
        let id = self.allocate_id();
        let max_count = match self.transform_counts.read() {
            Ok(guard) => parents
                .iter()
                .filter_map(|parent| guard.get(parent).copied())
                .max()
                .unwrap_or(0),
            Err(_) => 0,
        };
        let new_count = max_count.saturating_add(1);
        let state = self.state_for_count(id, new_count);
        let record = TaintRecord {
            id,
            kind: TaintEventKind::Merge,
            parents: parents.to_vec(),
            expression: Some(result_expr),
        };
        if let Ok(mut guard) = self.records.write() {
            guard.insert(id, record);
        }
        if let Ok(mut guard) = self.labels.write() {
            guard.insert(id, TaintLabel::Derived);
        }
        if let Ok(mut guard) = self.states.write() {
            guard.insert(result_expr, state);
        }
        if let Ok(mut guard) = self.transform_counts.write() {
            guard.insert(id, new_count);
        }
        id
    }

    /// Check whether `expr` is a sink (has a recorded taint state).
    pub fn sink(&self, expr: ExprId) -> Result<TaintState, TaintError> {
        let guard = self.states.read().map_err(|_| TaintError::Poisoned)?;
        guard.get(&expr).copied().ok_or(TaintError::UnknownExpression)
    }

    /// Get the taint state of an expression, defaulting to `Concrete` when
    /// the expression has no recorded state.
    pub fn state(&self, expr: ExprId) -> TaintState {
        match self.states.read() {
            Ok(guard) => guard.get(&expr).copied().unwrap_or(TaintState::Concrete),
            Err(_) => TaintState::Concrete,
        }
    }

    /// Get the label of a taint identifier, defaulting to `None` when the
    /// identifier is unknown.
    pub fn label(&self, taint: TaintId) -> TaintLabel {
        match self.labels.read() {
            Ok(guard) => guard.get(&taint).copied().unwrap_or(TaintLabel::None),
            Err(_) => TaintLabel::None,
        }
    }
}

impl TaintEngine for InMemoryTaintEngine {
    fn record(&self, record: TaintRecord) {
        let id = record.id;
        let expr = record.expression;
        if let Ok(mut guard) = self.records.write() {
            guard.insert(id, record);
        }
        if let Some(expr) = expr
            && let Ok(mut guard) = self.states.write()
        {
            guard.entry(expr).or_insert(TaintState::Tainted(id));
        }
    }

    fn promotion_decision(&self, taint: TaintId) -> PromotionDecision {
        let label = match self.labels.read() {
            Ok(guard) => guard.get(&taint).copied().unwrap_or(TaintLabel::None),
            Err(_) => return PromotionDecision::StayConcrete,
        };
        if Self::is_concrete_label(label) {
            return PromotionDecision::StayConcrete;
        }
        let count = match self.transform_counts.read() {
            Ok(guard) => guard.get(&taint).copied().unwrap_or(0),
            Err(_) => return PromotionDecision::StayConcrete,
        };
        if count >= self.promotion_threshold {
            PromotionDecision::PromoteSymbolic
        } else {
            PromotionDecision::TrackTaint
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_creates_taint_with_correct_label() {
        let engine = InMemoryTaintEngine::new_default();
        let expr = ExprId(1);
        let id = engine.source(expr, TaintLabel::UserInput);
        assert_eq!(engine.label(id), TaintLabel::UserInput);
        assert_eq!(engine.state(expr), TaintState::Tainted(id));
    }

    #[test]
    fn source_concrete_label_stays_concrete() {
        let engine = InMemoryTaintEngine::new_default();
        let expr = ExprId(1);
        let id = engine.source(expr, TaintLabel::Concrete);
        assert_eq!(engine.label(id), TaintLabel::Concrete);
        assert_eq!(engine.state(expr), TaintState::Concrete);
        assert_eq!(engine.promotion_decision(id), PromotionDecision::StayConcrete);
    }

    #[test]
    fn source_none_label_stays_concrete() {
        let engine = InMemoryTaintEngine::new_default();
        let expr = ExprId(1);
        let id = engine.source(expr, TaintLabel::None);
        assert_eq!(engine.label(id), TaintLabel::None);
        assert_eq!(engine.state(expr), TaintState::Concrete);
        assert_eq!(engine.promotion_decision(id), PromotionDecision::StayConcrete);
    }

    #[test]
    fn transform_increments_count_and_creates_derived() {
        let engine = InMemoryTaintEngine::new_default();
        let expr = ExprId(1);
        let result_expr = ExprId(2);
        let parent = engine.source(expr, TaintLabel::UserInput);
        let child = engine.transform(expr, parent, result_expr);
        assert_eq!(engine.label(child), TaintLabel::Derived);
        assert_eq!(engine.state(result_expr), TaintState::Tainted(child));
        assert_eq!(engine.promotion_decision(parent), PromotionDecision::TrackTaint);
        assert_eq!(engine.promotion_decision(child), PromotionDecision::TrackTaint);
    }

    #[test]
    fn merge_combines_multiple_taint_sources() {
        let engine = InMemoryTaintEngine::new_default();
        let expr_a = ExprId(1);
        let expr_b = ExprId(2);
        let result_expr = ExprId(3);
        let taint_a = engine.source(expr_a, TaintLabel::UserInput);
        let taint_b = engine.source(expr_b, TaintLabel::NetworkInput);
        let merged = engine.merge(expr_a, &[taint_a, taint_b], result_expr);
        assert_eq!(engine.label(merged), TaintLabel::Derived);
        assert_eq!(engine.state(result_expr), TaintState::Tainted(merged));
    }

    #[test]
    fn merge_with_empty_parents_creates_derived() {
        let engine = InMemoryTaintEngine::new_default();
        let result_expr = ExprId(1);
        let id = engine.merge(ExprId(0), &[], result_expr);
        assert_eq!(engine.label(id), TaintLabel::Derived);
        assert_eq!(engine.state(result_expr), TaintState::Tainted(id));
    }

    #[test]
    fn sink_detects_tainted_expressions() -> Result<(), TaintError> {
        let engine = InMemoryTaintEngine::new_default();
        let expr = ExprId(1);
        let id = engine.source(expr, TaintLabel::UserInput);
        let state = engine.sink(expr)?;
        assert_eq!(state, TaintState::Tainted(id));
        Ok(())
    }

    #[test]
    fn sink_returns_concrete_for_concrete_source() -> Result<(), TaintError> {
        let engine = InMemoryTaintEngine::new_default();
        let expr = ExprId(1);
        engine.source(expr, TaintLabel::Concrete);
        let state = engine.sink(expr)?;
        assert_eq!(state, TaintState::Concrete);
        Ok(())
    }

    #[test]
    fn sink_unknown_expression_returns_error() {
        let engine = InMemoryTaintEngine::new_default();
        assert_eq!(engine.sink(ExprId(999)), Err(TaintError::UnknownExpression));
    }

    #[test]
    fn promotion_threshold_triggers_symbolic() {
        let engine = InMemoryTaintEngine::new(3);
        let mut current_expr = ExprId(1);
        let mut current_taint = engine.source(current_expr, TaintLabel::UserInput);
        assert_eq!(engine.promotion_decision(current_taint), PromotionDecision::TrackTaint);
        current_expr = ExprId(2);
        current_taint = engine.transform(ExprId(1), current_taint, current_expr);
        assert_eq!(engine.promotion_decision(current_taint), PromotionDecision::TrackTaint);
        current_expr = ExprId(3);
        current_taint = engine.transform(ExprId(2), current_taint, current_expr);
        assert_eq!(engine.promotion_decision(current_taint), PromotionDecision::TrackTaint);
        current_expr = ExprId(4);
        current_taint = engine.transform(ExprId(3), current_taint, current_expr);
        assert_eq!(
            engine.promotion_decision(current_taint),
            PromotionDecision::PromoteSymbolic
        );
        assert_eq!(engine.state(current_expr), TaintState::Symbolic(current_taint));
    }

    #[test]
    fn concrete_expressions_stay_concrete() {
        let engine = InMemoryTaintEngine::new_default();
        let expr = ExprId(1);
        let id = engine.source(expr, TaintLabel::Concrete);
        assert_eq!(engine.state(expr), TaintState::Concrete);
        assert_eq!(engine.promotion_decision(id), PromotionDecision::StayConcrete);
    }

    #[test]
    fn unknown_taint_returns_none_label_and_stays_concrete() {
        let engine = InMemoryTaintEngine::new_default();
        let unknown = TaintId(999);
        assert_eq!(engine.label(unknown), TaintLabel::None);
        assert_eq!(engine.promotion_decision(unknown), PromotionDecision::StayConcrete);
    }

    #[test]
    fn multiple_sources_with_different_labels() {
        let engine = InMemoryTaintEngine::new_default();
        let id_a = engine.source(ExprId(1), TaintLabel::UserInput);
        let id_b = engine.source(ExprId(2), TaintLabel::NetworkInput);
        let id_c = engine.source(ExprId(3), TaintLabel::FileInput);
        assert_eq!(engine.label(id_a), TaintLabel::UserInput);
        assert_eq!(engine.label(id_b), TaintLabel::NetworkInput);
        assert_eq!(engine.label(id_c), TaintLabel::FileInput);
        assert_ne!(id_a, id_b);
        assert_ne!(id_b, id_c);
        assert_ne!(id_a, id_c);
    }

    #[test]
    fn transform_chain_reaches_threshold_and_promotes() {
        let engine = InMemoryTaintEngine::new(5);
        let mut expr = ExprId(1);
        let mut taint = engine.source(expr, TaintLabel::UserInput);
        for i in 1..=5u32 {
            let next_expr = ExprId(i + 1);
            taint = engine.transform(expr, taint, next_expr);
            expr = next_expr;
        }
        assert_eq!(engine.promotion_decision(taint), PromotionDecision::PromoteSymbolic);
        assert_eq!(engine.state(expr), TaintState::Symbolic(taint));
    }

    #[test]
    fn merge_promotes_when_threshold_reached() {
        let engine = InMemoryTaintEngine::new(2);
        let taint_a = engine.source(ExprId(1), TaintLabel::UserInput);
        let taint_b = engine.transform(ExprId(1), taint_a, ExprId(2));
        let merged = engine.merge(ExprId(1), &[taint_a, taint_b], ExprId(3));
        assert_eq!(engine.promotion_decision(merged), PromotionDecision::PromoteSymbolic);
        assert_eq!(engine.state(ExprId(3)), TaintState::Symbolic(merged));
    }

    #[test]
    fn taint_engine_trait_methods_work() {
        let engine = InMemoryTaintEngine::new_default();
        let id = engine.source(ExprId(1), TaintLabel::UserInput);
        assert_eq!(engine.promotion_decision(id), PromotionDecision::TrackTaint);
        let record = TaintRecord {
            id: TaintId(100),
            kind: TaintEventKind::Sink,
            parents: vec![id],
            expression: Some(ExprId(1)),
        };
        engine.record(record);
        assert_eq!(engine.promotion_decision(id), PromotionDecision::TrackTaint);
    }

    #[test]
    fn taint_engine_record_sets_state_for_expression() {
        let engine = InMemoryTaintEngine::new_default();
        let record = TaintRecord {
            id: TaintId(1),
            kind: TaintEventKind::Source,
            parents: Vec::new(),
            expression: Some(ExprId(5)),
        };
        engine.record(record);
        assert_eq!(engine.state(ExprId(5)), TaintState::Tainted(TaintId(1)));
    }

    #[test]
    fn taint_engine_record_does_not_override_existing_state() {
        let engine = InMemoryTaintEngine::new_default();
        let id = engine.source(ExprId(1), TaintLabel::UserInput);
        let record = TaintRecord {
            id: TaintId(100),
            kind: TaintEventKind::Sink,
            parents: vec![id],
            expression: Some(ExprId(1)),
        };
        engine.record(record);
        assert_eq!(engine.state(ExprId(1)), TaintState::Tainted(id));
    }

    #[test]
    fn sink_returns_symbolic_after_promotion() -> Result<(), TaintError> {
        let engine = InMemoryTaintEngine::new(1);
        let expr = ExprId(1);
        let result_expr = ExprId(2);
        let parent = engine.source(expr, TaintLabel::UserInput);
        let child = engine.transform(expr, parent, result_expr);
        let state = engine.sink(result_expr)?;
        assert_eq!(state, TaintState::Symbolic(child));
        Ok(())
    }

    #[test]
    fn state_defaults_to_concrete_for_unknown_expression() {
        let engine = InMemoryTaintEngine::new_default();
        assert_eq!(engine.state(ExprId(999)), TaintState::Concrete);
    }

    #[test]
    fn label_defaults_to_none_for_unknown_taint() {
        let engine = InMemoryTaintEngine::new_default();
        assert_eq!(engine.label(TaintId(999)), TaintLabel::None);
    }

    #[test]
    fn taint_error_display_messages() {
        assert_eq!(TaintError::UnknownTaint.to_string(), "unknown taint identifier");
        assert_eq!(
            TaintError::UnknownExpression.to_string(),
            "unknown expression identifier"
        );
        assert_eq!(
            TaintError::Poisoned.to_string(),
            "taint engine synchronization primitive poisoned"
        );
        assert_eq!(
            TaintError::InvalidMerge.to_string(),
            "invalid taint merge with no parents"
        );
    }

    #[test]
    fn new_default_uses_threshold_of_ten() {
        let engine = InMemoryTaintEngine::new_default();
        let expr = ExprId(1);
        let mut taint = engine.source(expr, TaintLabel::UserInput);
        let mut current_expr = expr;
        for i in 1..10 {
            let next = ExprId(i + 1);
            taint = engine.transform(current_expr, taint, next);
            current_expr = next;
        }
        assert_eq!(engine.promotion_decision(taint), PromotionDecision::TrackTaint);
        let next = ExprId(11);
        taint = engine.transform(current_expr, taint, next);
        assert_eq!(engine.promotion_decision(taint), PromotionDecision::PromoteSymbolic);
    }
}
