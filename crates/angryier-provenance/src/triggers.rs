//! Tier-2 trigger predicate utilities for provenance flight recording.
//!
//! Tier-2 diagnostic events (branches, memory/register effects, solver queries) provide
//! deep forensic detail but incur high storage and transport overhead.
//!
//! Trigger predicates monitor symbolic execution signals (e.g., state fork bursts,
//! solver budget escalation, novelty spikes, target proximity) to dynamically signal
//! the governor or flight recorder to capture a high-fidelity Tier-2 snapshot and
//! open a post-trigger diagnostic capture window.

use crate::{ProvenanceEvent, ProvenanceEventKind, TraceInterest};
use angryier_types::ProvenanceSeq;

/// Outcome of evaluating a [`Tier2Trigger`].
#[derive(Clone, Debug, PartialEq)]
pub enum TriggerDecision {
    /// No trigger condition met; continue normal tiered recording.
    Ignore,
    /// Trigger fired; capture a Tier-2 snapshot and keep subsequent events promoted.
    Fire {
        /// Diagnostic explanation of why the trigger fired.
        reason: String,
        /// Number of subsequent events that should remain promoted to Tier-2.
        capture_window: usize,
    },
}

impl TriggerDecision {
    pub fn is_fired(&self) -> bool {
        matches!(self, Self::Fire { .. })
    }

    pub fn capture_window(&self) -> usize {
        match self {
            Self::Fire { capture_window, .. } => *capture_window,
            Self::Ignore => 0,
        }
    }
}

/// Dynamic metrics and execution context evaluated by [`Tier2Trigger`] predicates.
#[derive(Clone, Debug, PartialEq)]
pub struct TriggerContext {
    /// Monotonic total events observed.
    pub event_count: u64,
    /// Number of state forks observed within the recent window.
    pub forks_in_window: usize,
    /// Size of the sliding window for state fork counting.
    pub fork_window_size: usize,
    /// Latest normalized solver cost in `[0.0, 1.0]`.
    pub solver_cost: f32,
    /// Prior solver cost, used to detect sudden cost escalation.
    pub previous_solver_cost: f32,
    /// Total solver budget or time consumed (e.g. microseconds).
    pub solver_budget_used: u64,
    /// Prior solver budget consumed.
    pub previous_solver_budget_used: u64,
    /// Latest novelty score in `[0.0, 1.0]`.
    pub novelty_score: f32,
    /// Exponential moving average of novelty score.
    pub average_novelty: f32,
    /// Estimated proximity to crash or vulnerability condition in `[0.0, 1.0]`.
    pub crash_proximity: f32,
    /// Estimated semantic approximation/uncertainty in `[0.0, 1.0]`.
    pub approximation: f32,
}

impl TriggerContext {
    pub fn new() -> Self {
        Self {
            event_count: 0,
            forks_in_window: 0,
            fork_window_size: 16,
            solver_cost: 0.0,
            previous_solver_cost: 0.0,
            solver_budget_used: 0,
            previous_solver_budget_used: 0,
            novelty_score: 0.0,
            average_novelty: 0.0,
            crash_proximity: 0.0,
            approximation: 0.0,
        }
    }

    /// Observes a provenance event, updating event counts and windowed fork metrics.
    pub fn observe_event(&mut self, event: &ProvenanceEvent) {
        self.event_count = self.event_count.saturating_add(1);
        if event.kind == ProvenanceEventKind::StateFork {
            self.forks_in_window = self.forks_in_window.saturating_add(1);
        }
        let win = (self.fork_window_size as u64).max(1);
        if self.event_count.is_multiple_of(win) {
            // Decay older forks across window boundaries.
            self.forks_in_window /= 2;
        }
    }

    /// Records an explicit state fork event.
    pub fn record_fork(&mut self) {
        self.forks_in_window = self.forks_in_window.saturating_add(1);
    }

    /// Records solver execution metrics.
    pub fn record_solver_query(&mut self, cost: f32, budget_used: u64) {
        self.previous_solver_cost = self.solver_cost;
        self.solver_cost = cost.clamp(0.0, 1.0);
        self.previous_solver_budget_used = self.solver_budget_used;
        self.solver_budget_used = budget_used;
    }

    /// Records a new novelty observation, updating the moving average.
    pub fn record_novelty(&mut self, novelty: f32) {
        let clamped = novelty.clamp(0.0, 1.0);
        self.average_novelty = if self.event_count == 0 {
            clamped
        } else {
            self.average_novelty * 0.85 + clamped * 0.15
        };
        self.novelty_score = clamped;
    }

    /// Updates context directly from a [`TraceInterest`] snapshot.
    pub fn record_interest(&mut self, interest: &TraceInterest) {
        self.record_novelty(interest.novelty);
        self.record_solver_query(interest.solver_cost, self.solver_budget_used);
        self.crash_proximity = interest.crash_proximity.clamp(0.0, 1.0);
        self.approximation = interest.approximation.clamp(0.0, 1.0);
    }
}

impl Default for TriggerContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Predicate interface for signaling Tier-2 capture in the governor or recorder.
pub trait Tier2Trigger: Send + Sync {
    /// Human-readable identifier for this trigger predicate.
    fn name(&self) -> &str;

    /// Evaluates execution signals against the trigger condition.
    fn evaluate(&mut self, context: &TriggerContext) -> TriggerDecision;

    /// Resets internal history and cooldown timers.
    fn reset(&mut self);
}

/// Trigger fired when the number of state forks in a window exceeds a burst threshold.
pub struct ForkBurstTrigger {
    pub burst_threshold: usize,
    pub capture_window: usize,
    pub cooldown: u64,
    last_fired_at: Option<u64>,
}

impl ForkBurstTrigger {
    pub fn new(burst_threshold: usize, capture_window: usize, cooldown: u64) -> Self {
        Self {
            burst_threshold: burst_threshold.max(1),
            capture_window,
            cooldown,
            last_fired_at: None,
        }
    }
}

impl Tier2Trigger for ForkBurstTrigger {
    fn name(&self) -> &str {
        "ForkBurstTrigger"
    }

    fn evaluate(&mut self, context: &TriggerContext) -> TriggerDecision {
        if context.forks_in_window >= self.burst_threshold {
            if self
                .last_fired_at
                .is_some_and(|last| context.event_count.saturating_sub(last) < self.cooldown)
            {
                return TriggerDecision::Ignore;
            }
            self.last_fired_at = Some(context.event_count);
            TriggerDecision::Fire {
                reason: format!(
                    "State fork burst detected: {} forks in window (threshold: {})",
                    context.forks_in_window, self.burst_threshold
                ),
                capture_window: self.capture_window,
            }
        } else {
            TriggerDecision::Ignore
        }
    }

    fn reset(&mut self) {
        self.last_fired_at = None;
    }
}

/// Trigger fired when solver cost or budget escalates abruptly.
pub struct SolverEscalationTrigger {
    pub cost_threshold: f32,
    pub escalation_factor: f32,
    pub budget_delta_threshold: u64,
    pub capture_window: usize,
    pub cooldown: u64,
    last_fired_at: Option<u64>,
}

impl SolverEscalationTrigger {
    pub fn new(
        cost_threshold: f32,
        escalation_factor: f32,
        budget_delta_threshold: u64,
        capture_window: usize,
        cooldown: u64,
    ) -> Self {
        Self {
            cost_threshold,
            escalation_factor: escalation_factor.max(1.0),
            budget_delta_threshold,
            capture_window,
            cooldown,
            last_fired_at: None,
        }
    }
}

impl Tier2Trigger for SolverEscalationTrigger {
    fn name(&self) -> &str {
        "SolverEscalationTrigger"
    }

    fn evaluate(&mut self, context: &TriggerContext) -> TriggerDecision {
        let cost_exceeded = context.solver_cost >= self.cost_threshold;
        let cost_jumped = context.previous_solver_cost > 0.0
            && context.solver_cost >= context.previous_solver_cost * self.escalation_factor;
        let budget_jumped = self.budget_delta_threshold > 0
            && context
                .solver_budget_used
                .saturating_sub(context.previous_solver_budget_used)
                >= self.budget_delta_threshold;

        if cost_exceeded || cost_jumped || budget_jumped {
            if self
                .last_fired_at
                .is_some_and(|last| context.event_count.saturating_sub(last) < self.cooldown)
            {
                return TriggerDecision::Ignore;
            }
            self.last_fired_at = Some(context.event_count);
            let reason = if cost_jumped {
                format!(
                    "Solver cost escalated: {:.3} -> {:.3} (factor >= {:.1})",
                    context.previous_solver_cost, context.solver_cost, self.escalation_factor
                )
            } else if cost_exceeded {
                format!(
                    "Solver cost exceeded threshold: {:.3} >= {:.3}",
                    context.solver_cost, self.cost_threshold
                )
            } else {
                format!(
                    "Solver budget delta exceeded: +{}us >= {}us",
                    context
                        .solver_budget_used
                        .saturating_sub(context.previous_solver_budget_used),
                    self.budget_delta_threshold
                )
            };

            TriggerDecision::Fire {
                reason,
                capture_window: self.capture_window,
            }
        } else {
            TriggerDecision::Ignore
        }
    }

    fn reset(&mut self) {
        self.last_fired_at = None;
    }
}

/// Trigger fired when novelty jumps sharply above baseline or threshold.
pub struct NoveltySpikeTrigger {
    pub spike_threshold: f32,
    pub delta_threshold: f32,
    pub capture_window: usize,
    pub cooldown: u64,
    last_fired_at: Option<u64>,
}

impl NoveltySpikeTrigger {
    pub fn new(spike_threshold: f32, delta_threshold: f32, capture_window: usize, cooldown: u64) -> Self {
        Self {
            spike_threshold,
            delta_threshold,
            capture_window,
            cooldown,
            last_fired_at: None,
        }
    }
}

impl Tier2Trigger for NoveltySpikeTrigger {
    fn name(&self) -> &str {
        "NoveltySpikeTrigger"
    }

    fn evaluate(&mut self, context: &TriggerContext) -> TriggerDecision {
        let absolute_high = context.novelty_score >= self.spike_threshold;
        let delta_high = (context.novelty_score - context.average_novelty) >= self.delta_threshold;

        if absolute_high || delta_high {
            if self
                .last_fired_at
                .is_some_and(|last| context.event_count.saturating_sub(last) < self.cooldown)
            {
                return TriggerDecision::Ignore;
            }
            self.last_fired_at = Some(context.event_count);
            TriggerDecision::Fire {
                reason: format!(
                    "Novelty score spike: {:.3} (average: {:.3}, threshold: {:.3})",
                    context.novelty_score, context.average_novelty, self.spike_threshold
                ),
                capture_window: self.capture_window,
            }
        } else {
            TriggerDecision::Ignore
        }
    }

    fn reset(&mut self) {
        self.last_fired_at = None;
    }
}

/// Trigger fired when execution reaches close proximity to a crash/target condition.
pub struct CrashProximityTrigger {
    pub proximity_threshold: f32,
    pub capture_window: usize,
    pub cooldown: u64,
    last_fired_at: Option<u64>,
}

impl CrashProximityTrigger {
    pub fn new(proximity_threshold: f32, capture_window: usize, cooldown: u64) -> Self {
        Self {
            proximity_threshold,
            capture_window,
            cooldown,
            last_fired_at: None,
        }
    }
}

impl Tier2Trigger for CrashProximityTrigger {
    fn name(&self) -> &str {
        "CrashProximityTrigger"
    }

    fn evaluate(&mut self, context: &TriggerContext) -> TriggerDecision {
        if context.crash_proximity >= self.proximity_threshold {
            if self
                .last_fired_at
                .is_some_and(|last| context.event_count.saturating_sub(last) < self.cooldown)
            {
                return TriggerDecision::Ignore;
            }
            self.last_fired_at = Some(context.event_count);
            TriggerDecision::Fire {
                reason: format!(
                    "Crash proximity reached threshold: {:.3} >= {:.3}",
                    context.crash_proximity, self.proximity_threshold
                ),
                capture_window: self.capture_window,
            }
        } else {
            TriggerDecision::Ignore
        }
    }

    fn reset(&mut self) {
        self.last_fired_at = None;
    }
}

/// Logical combinator for composite triggers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogicalCombinator {
    Any,
    All,
}

/// Composite trigger evaluating a set of sub-triggers with `Any` (OR) or `All` (AND) logic.
pub struct CompositeTrigger {
    name: String,
    triggers: Vec<Box<dyn Tier2Trigger>>,
    combinator: LogicalCombinator,
}

impl CompositeTrigger {
    pub fn any(name: impl Into<String>, triggers: Vec<Box<dyn Tier2Trigger>>) -> Self {
        Self {
            name: name.into(),
            triggers,
            combinator: LogicalCombinator::Any,
        }
    }

    pub fn all(name: impl Into<String>, triggers: Vec<Box<dyn Tier2Trigger>>) -> Self {
        Self {
            name: name.into(),
            triggers,
            combinator: LogicalCombinator::All,
        }
    }
}

impl Tier2Trigger for CompositeTrigger {
    fn name(&self) -> &str {
        &self.name
    }

    fn evaluate(&mut self, context: &TriggerContext) -> TriggerDecision {
        match self.combinator {
            LogicalCombinator::Any => {
                let mut max_window = 0;
                let mut reasons = Vec::new();
                for t in &mut self.triggers {
                    if let TriggerDecision::Fire { reason, capture_window } = t.evaluate(context) {
                        max_window = max_window.max(capture_window);
                        reasons.push(reason);
                    }
                }
                if !reasons.is_empty() {
                    TriggerDecision::Fire {
                        reason: reasons.join("; "),
                        capture_window: max_window,
                    }
                } else {
                    TriggerDecision::Ignore
                }
            }
            LogicalCombinator::All => {
                let mut max_window = 0;
                let mut reasons = Vec::new();
                for t in &mut self.triggers {
                    match t.evaluate(context) {
                        TriggerDecision::Fire { reason, capture_window } => {
                            max_window = max_window.max(capture_window);
                            reasons.push(reason);
                        }
                        TriggerDecision::Ignore => return TriggerDecision::Ignore,
                    }
                }
                if !reasons.is_empty() {
                    TriggerDecision::Fire {
                        reason: reasons.join("; "),
                        capture_window: max_window,
                    }
                } else {
                    TriggerDecision::Ignore
                }
            }
        }
    }

    fn reset(&mut self) {
        for t in &mut self.triggers {
            t.reset();
        }
    }
}

/// An immutable diagnostic snapshot captured from a [`crate::FlightRecorder`] when a trigger fires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tier2Snapshot {
    /// Reason explaining why the snapshot was triggered.
    pub reason: String,
    /// Highest provenance sequence number included in the snapshot.
    pub captured_at_sequence: ProvenanceSeq,
    /// Total number of events contained in the snapshot.
    pub total_events: usize,
    /// Number of Tier-0 ephemeral events in the snapshot.
    pub tier0_count: usize,
    /// Number of Tier-1 permanent structural events in the snapshot.
    pub tier1_count: usize,
    /// Number of Tier-2 diagnostic events in the snapshot.
    pub tier2_count: usize,
    /// Events captured in chronological order.
    pub events: Vec<ProvenanceEvent>,
}
