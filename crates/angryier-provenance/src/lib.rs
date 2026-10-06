#![forbid(unsafe_code)]

//! Adaptive tiered provenance transport.
//!
//! Tier-1 structural events are never silently dropped. The in-memory sink
//! provides bounded priority-aware queuing with worker-local batching.
//! The adaptive governor promotes or demotes events between tiers based on
//! trace interest signals.
//!
//! [`RepetitionDetector`] and [`StructuralRepetitionSummarizer`] detect contiguous
//! loop cycles and compact repetitive events, while [`Tier2Trigger`] predicates monitor
//! execution signals (state fork bursts, solver budget escalations, novelty spikes)
//! to capture high-fidelity diagnostic snapshots.

pub mod repetition;
pub mod triggers;

pub use repetition::*;
pub use triggers::*;

use angryier_types::{ContentId, ProvenanceNodeId, ProvenanceSeq, ProvenanceTier, StateId};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// Provenance event model
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProvenanceEventKind {
    StateFork,
    ConstraintAdded,
    ConstraintRemoved,
    Branch,
    MemoryEffect,
    RegisterEffect,
    SolverQuery,
    SolverResult,
    ModelUse,
    SummaryUse,
    Concretization,
    Approximation,
    JitInvalidation,
    ReplayCheckpoint,
    StateMerge,
    StateTerminate,
    Syscall,
    /// Compacted repetition summary representing repeated execution cycles.
    RepetitionSummary,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TraceInterest {
    pub novelty: f32,
    pub coverage: f32,
    pub symbolic_depth: f32,
    pub taint_relevance: f32,
    pub solver_cost: f32,
    pub semantic_uncertainty: f32,
    pub approximation: f32,
    pub crash_proximity: f32,
    pub target_proximity: f32,
    pub repetition: f32,
    pub event_rate: f32,
}

impl TraceInterest {
    /// A low-interest event that is common and well-understood.
    pub fn low() -> Self {
        Self {
            novelty: 0.0,
            coverage: 0.0,
            symbolic_depth: 0.0,
            taint_relevance: 0.0,
            solver_cost: 0.0,
            semantic_uncertainty: 0.0,
            approximation: 0.0,
            crash_proximity: 0.0,
            target_proximity: 0.0,
            repetition: 1.0,
            event_rate: 0.0,
        }
    }

    /// A high-interest event that is novel and potentially security-relevant.
    pub fn high() -> Self {
        Self {
            novelty: 1.0,
            coverage: 0.8,
            symbolic_depth: 0.9,
            taint_relevance: 0.8,
            solver_cost: 0.7,
            semantic_uncertainty: 0.6,
            approximation: 0.0,
            crash_proximity: 0.5,
            target_proximity: 0.7,
            repetition: 0.0,
            event_rate: 0.5,
        }
    }

    /// Compute a scalar priority score in [0, 1].
    pub fn priority(&self) -> f32 {
        // Weighted sum of interest signals, normalized to [0, 1].
        let weights = [
            (self.novelty, 0.20),
            (self.coverage, 0.10),
            (self.symbolic_depth, 0.15),
            (self.taint_relevance, 0.10),
            (self.solver_cost, 0.10),
            (self.semantic_uncertainty, 0.10),
            (self.crash_proximity, 0.10),
            (self.target_proximity, 0.10),
            (self.repetition, -0.05),
            (self.event_rate, 0.05),
            (self.approximation, -0.05),
        ];
        let sum: f32 = weights.iter().map(|(v, w)| v * w).sum();
        let total_weight: f32 = weights.iter().map(|(_, w)| w.abs()).sum();
        if total_weight > 0.0 {
            (sum / total_weight).clamp(0.0, 1.0)
        } else {
            0.0
        }
    }
}

impl Default for TraceInterest {
    fn default() -> Self {
        Self::low()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProvenanceEvent {
    pub id: ProvenanceNodeId,
    pub sequence: ProvenanceSeq,
    pub state: StateId,
    pub tier: ProvenanceTier,
    pub kind: ProvenanceEventKind,
    pub semantic_content: Option<ContentId>,
    pub parents: Vec<ProvenanceNodeId>,
}

impl ProvenanceEvent {
    /// Extracts the structural equivalence key for this event.
    pub fn structural_key(&self) -> repetition::StructuralEventKey {
        repetition::StructuralEventKey::from_event(self)
    }
}

// ---------------------------------------------------------------------------
// Error model
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProvenanceError {
    /// The provenance sink is full (backpressure).
    Full,
    /// The provenance sink is poisoned (lock failure).
    Poisoned,
    /// An event with a duplicate node ID was published.
    DuplicateNode,
    /// An event references an unknown parent.
    UnknownParent,
    /// An event has a non-monotonic sequence number.
    NonMonotonicSequence,
    /// A tier-1 event was dropped, which is forbidden.
    Tier1Dropped,
}

impl core::fmt::Display for ProvenanceError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::Full => "provenance sink is full (backpressure)",
            Self::Poisoned => "provenance sink poisoned",
            Self::DuplicateNode => "duplicate provenance node ID",
            Self::UnknownParent => "provenance event references unknown parent",
            Self::NonMonotonicSequence => "non-monotonic provenance sequence",
            Self::Tier1Dropped => "tier-1 provenance event was dropped",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ProvenanceError {}

// ---------------------------------------------------------------------------
// Sink and governor traits
// ---------------------------------------------------------------------------

pub trait ProvenanceSink: Send + Sync {
    type Error;
    fn publish(&self, events: &[ProvenanceEvent]) -> Result<(), Self::Error>;
}

pub trait TraceGovernor: Send + Sync {
    fn choose_tier(&self, interest: TraceInterest, current: ProvenanceTier) -> ProvenanceTier;
}

// ---------------------------------------------------------------------------
// In-memory provenance store with bounded priority queue
// ---------------------------------------------------------------------------

/// A bounded in-memory provenance store with priority-aware queuing.
///
/// Tier-1 events are always retained (never dropped under backpressure).
/// Tier-2 events may be dropped when the queue is full, starting with
/// the lowest-priority events.
pub struct InMemoryProvenanceStore {
    events: Mutex<BTreeMap<ProvenanceNodeId, ProvenanceEvent>>,
    sequence: Mutex<ProvenanceSeq>,
    capacity: usize,
}

impl InMemoryProvenanceStore {
    pub fn new(capacity: usize) -> Self {
        Self {
            events: Mutex::new(BTreeMap::new()),
            sequence: Mutex::new(ProvenanceSeq(0)),
            capacity,
        }
    }

    pub fn len(&self) -> usize {
        match self.events.lock() {
            Ok(guard) => guard.len(),
            Err(_) => 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn next_sequence(&self) -> Result<ProvenanceSeq, ProvenanceError> {
        let mut seq = self.sequence.lock().map_err(|_| ProvenanceError::Poisoned)?;
        seq.0 = seq.0.checked_add(1).ok_or(ProvenanceError::Full)?;
        Ok(*seq)
    }

    pub fn contains(&self, id: ProvenanceNodeId) -> bool {
        match self.events.lock() {
            Ok(guard) => guard.contains_key(&id),
            Err(_) => false,
        }
    }

    pub fn get(&self, id: ProvenanceNodeId) -> Option<ProvenanceEvent> {
        match self.events.lock() {
            Ok(guard) => guard.get(&id).cloned(),
            Err(_) => None,
        }
    }

    fn validate_event(&self, event: &ProvenanceEvent) -> Result<(), ProvenanceError> {
        let events = self.events.lock().map_err(|_| ProvenanceError::Poisoned)?;
        if events.contains_key(&event.id) {
            return Err(ProvenanceError::DuplicateNode);
        }
        // Check that all parents exist.
        for parent in &event.parents {
            if !events.contains_key(parent) {
                return Err(ProvenanceError::UnknownParent);
            }
        }
        // Check sequence monotonicity against the current counter.
        let seq = self.sequence.lock().map_err(|_| ProvenanceError::Poisoned)?;
        if event.sequence.0 < seq.0 {
            return Err(ProvenanceError::NonMonotonicSequence);
        }
        Ok(())
    }

    fn insert_event(&self, event: ProvenanceEvent) -> Result<(), ProvenanceError> {
        let mut events = self.events.lock().map_err(|_| ProvenanceError::Poisoned)?;
        if events.len() >= self.capacity {
            // Under backpressure, evict the lowest-sequence Tier-2 event.
            // Tier-1 events are never evicted.
            let candidate = events
                .iter()
                .filter(|(_, e)| e.tier == ProvenanceTier::Tier2)
                .min_by_key(|(_, e)| e.sequence.0)
                .map(|(id, _)| *id);
            match candidate {
                Some(id) => {
                    events.remove(&id);
                }
                None => {
                    // Only Tier-1 events remain — cannot drop them.
                    return Err(ProvenanceError::Full);
                }
            }
        }
        events.insert(event.id, event);
        Ok(())
    }
}

impl ProvenanceSink for InMemoryProvenanceStore {
    type Error = ProvenanceError;

    fn publish(&self, events: &[ProvenanceEvent]) -> Result<(), Self::Error> {
        for event in events {
            self.validate_event(event)?;
        }
        // Update the sequence counter to the highest sequence in the batch.
        {
            let mut seq = self.sequence.lock().map_err(|_| ProvenanceError::Poisoned)?;
            for event in events {
                if event.sequence.0 > seq.0 {
                    *seq = event.sequence;
                }
            }
        }
        for event in events {
            self.insert_event(event.clone())?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Adaptive trace governor
// ---------------------------------------------------------------------------

/// An adaptive governor that promotes events to higher tiers based on
/// trace interest, and demotes low-interest events.
pub struct AdaptiveTraceGovernor {
    /// Priority threshold above which events are promoted to Tier-1.
    tier1_threshold: f32,
    /// Priority threshold above which events are promoted to Tier-2.
    tier2_threshold: f32,
    /// Number of subsequent events kept promoted to Tier-2 via trigger capture window.
    capture_window: AtomicUsize,
}

impl AdaptiveTraceGovernor {
    pub fn new(tier1_threshold: f32, tier2_threshold: f32) -> Self {
        Self {
            tier1_threshold,
            tier2_threshold,
            capture_window: AtomicUsize::new(0),
        }
    }

    pub fn default_governor() -> Self {
        Self::new(0.7, 0.3)
    }

    /// Notifies the governor that a Tier-2 trigger fired, opening a capture window.
    pub fn notify_trigger(&self, decision: &TriggerDecision) {
        if let TriggerDecision::Fire { capture_window, .. } = decision {
            self.capture_window.fetch_max(*capture_window, Ordering::SeqCst);
        }
    }

    /// Explicitly arms a Tier-2 capture window of `window_size` events.
    pub fn arm_capture_window(&self, window_size: usize) {
        self.capture_window.fetch_max(window_size, Ordering::SeqCst);
    }

    /// Number of events remaining in the active Tier-2 capture window.
    pub fn remaining_capture_window(&self) -> usize {
        self.capture_window.load(Ordering::SeqCst)
    }
}

impl TraceGovernor for AdaptiveTraceGovernor {
    fn choose_tier(&self, interest: TraceInterest, current: ProvenanceTier) -> ProvenanceTier {
        let priority = interest.priority();
        // Tier-1 events can never be demoted — structural events are permanent.
        if current == ProvenanceTier::Tier1 {
            return ProvenanceTier::Tier1;
        }
        if priority >= self.tier1_threshold {
            return ProvenanceTier::Tier1;
        }

        // Active trigger capture window forces promotion to Tier-2.
        let active = self.capture_window.load(Ordering::SeqCst);
        if active > 0 {
            let _ = self
                .capture_window
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |w| Some(w.saturating_sub(1)));
            return ProvenanceTier::Tier2;
        }

        if priority >= self.tier2_threshold {
            ProvenanceTier::Tier2
        } else {
            ProvenanceTier::Tier0
        }
    }
}

// ---------------------------------------------------------------------------
// Per-worker circular flight recorder
// ---------------------------------------------------------------------------

/// A bounded ring of provenance events for one worker. Tier-1 events are
/// never evicted (structural lineage is permanent); under pressure the
/// recorder drops the oldest Tier-0 event, then Tier-2, then reports
/// `ProvenanceError::Full` rather than lose structural data.
pub struct FlightRecorder {
    capacity: usize,
    events: std::collections::VecDeque<ProvenanceEvent>,
    dropped_tier0: u64,
    dropped_tier2: u64,
}

impl FlightRecorder {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            events: std::collections::VecDeque::with_capacity(capacity.max(1)),
            dropped_tier0: 0,
            dropped_tier2: 0,
        }
    }

    /// Appends `event`, evicting the oldest droppable event when full.
    pub fn record(&mut self, event: ProvenanceEvent) -> Result<(), ProvenanceError> {
        if self.events.len() >= self.capacity {
            // Evict oldest Tier-0 first; then Tier-2; never Tier-1.
            let pos = self
                .events
                .iter()
                .position(|e| e.tier == ProvenanceTier::Tier0)
                .or_else(|| self.events.iter().position(|e| e.tier == ProvenanceTier::Tier2));
            match pos {
                Some(i) => {
                    let ev = self.events.remove(i);
                    match ev.map(|e| e.tier) {
                        Some(ProvenanceTier::Tier0) => self.dropped_tier0 += 1,
                        Some(ProvenanceTier::Tier2) => self.dropped_tier2 += 1,
                        _ => {}
                    }
                }
                None => return Err(ProvenanceError::Full),
            }
        }
        self.events.push_back(event);
        Ok(())
    }

    /// Flushes all events to `sink` in order; the recorder is empty after.
    pub fn drain_to<S: ProvenanceSink>(&mut self, sink: &S) -> Result<usize, S::Error> {
        let batch: Vec<ProvenanceEvent> = self.events.drain(..).collect();
        let n = batch.len();
        sink.publish(&batch)?;
        Ok(n)
    }

    /// Oldest-to-newest events currently held.
    pub fn events(&self) -> impl Iterator<Item = &ProvenanceEvent> {
        self.events.iter()
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// How many events were evicted under pressure, per droppable tier.
    pub fn dropped(&self) -> (u64, u64) {
        (self.dropped_tier0, self.dropped_tier2)
    }

    /// Takes an immutable snapshot of all events currently held in the ring buffer.
    pub fn snapshot(&self) -> Vec<ProvenanceEvent> {
        self.events.iter().cloned().collect()
    }

    /// Captures a Tier-2 diagnostic snapshot with reason and tier statistics.
    pub fn capture_tier2_snapshot(&self, reason: impl Into<String>) -> Tier2Snapshot {
        let events: Vec<_> = self.events.iter().cloned().collect();
        let mut tier0_count = 0;
        let mut tier1_count = 0;
        let mut tier2_count = 0;
        let mut last_seq = ProvenanceSeq(0);

        for e in &events {
            match e.tier {
                ProvenanceTier::Tier0 => tier0_count += 1,
                ProvenanceTier::Tier1 => tier1_count += 1,
                ProvenanceTier::Tier2 => tier2_count += 1,
            }
            if e.sequence.0 > last_seq.0 {
                last_seq = e.sequence;
            }
        }

        Tier2Snapshot {
            reason: reason.into(),
            captured_at_sequence: last_seq,
            total_events: events.len(),
            tier0_count,
            tier1_count,
            tier2_count,
            events,
        }
    }

    /// Evaluates a trigger and, if fired, immediately captures a Tier-2 snapshot.
    pub fn check_and_capture(&self, trigger: &mut dyn Tier2Trigger, context: &TriggerContext) -> Option<Tier2Snapshot> {
        match trigger.evaluate(context) {
            TriggerDecision::Fire { reason, .. } => Some(self.capture_tier2_snapshot(reason)),
            TriggerDecision::Ignore => None,
        }
    }

    /// Records an event through a [`StructuralRepetitionSummarizer`], compacting repeating cycles
    /// and suppressing redundant Tier-2 events.
    pub fn record_summarized(
        &mut self,
        event: ProvenanceEvent,
        summarizer: &mut StructuralRepetitionSummarizer,
    ) -> Result<Vec<RepetitionSummary>, ProvenanceError> {
        let outputs = summarizer.feed(event);
        let mut summaries = Vec::new();
        for output in outputs {
            match output {
                SummarizerOutput::Event(e) => {
                    self.record(e)?;
                }
                SummarizerOutput::Suppressed { .. } => {}
                SummarizerOutput::Summary(summary) => {
                    summaries.push(summary);
                }
            }
        }
        Ok(summaries)
    }

    /// Flushes any pending repeating cycle from the summarizer into the flight recorder.
    pub fn flush_summarized(
        &mut self,
        summarizer: &mut StructuralRepetitionSummarizer,
    ) -> Result<Vec<RepetitionSummary>, ProvenanceError> {
        let outputs = summarizer.flush();
        let mut summaries = Vec::new();
        for output in outputs {
            match output {
                SummarizerOutput::Event(e) => {
                    self.record(e)?;
                }
                SummarizerOutput::Suppressed { .. } => {}
                SummarizerOutput::Summary(summary) => {
                    summaries.push(summary);
                }
            }
        }
        Ok(summaries)
    }
}

/// High-level flight recorder combining circular buffer recording, Tier-2 trigger
/// predicates, and structural repetition summarization.
pub struct TriggeredFlightRecorder {
    pub recorder: FlightRecorder,
    pub summarizer: StructuralRepetitionSummarizer,
    pub triggers: Vec<Box<dyn Tier2Trigger>>,
    pub context: TriggerContext,
    pub captured_snapshots: Vec<Tier2Snapshot>,
    active_capture_window: usize,
}

impl TriggeredFlightRecorder {
    pub fn new(capacity: usize, config: RepetitionConfig, triggers: Vec<Box<dyn Tier2Trigger>>) -> Self {
        Self {
            recorder: FlightRecorder::new(capacity),
            summarizer: StructuralRepetitionSummarizer::new(config),
            triggers,
            context: TriggerContext::new(),
            captured_snapshots: Vec::new(),
            active_capture_window: 0,
        }
    }

    pub fn with_defaults(capacity: usize) -> Self {
        Self::new(capacity, RepetitionConfig::default(), Vec::new())
    }

    /// Records an event, evaluating triggers and compacting repeating cycles.
    pub fn record(&mut self, mut event: ProvenanceEvent) -> Result<Vec<RepetitionSummary>, ProvenanceError> {
        self.context.observe_event(&event);

        // Evaluate all triggers against the updated context.
        for trigger in &mut self.triggers {
            if let TriggerDecision::Fire { reason, capture_window } = trigger.evaluate(&self.context) {
                let snapshot = self.recorder.capture_tier2_snapshot(reason);
                self.captured_snapshots.push(snapshot);
                self.active_capture_window = self.active_capture_window.max(capture_window);
            }
        }

        // If in an active capture window, promote Tier-0 event to Tier-2.
        if self.active_capture_window > 0 {
            if event.tier == ProvenanceTier::Tier0 {
                event.tier = ProvenanceTier::Tier2;
            }
            self.active_capture_window = self.active_capture_window.saturating_sub(1);
        }

        self.recorder.record_summarized(event, &mut self.summarizer)
    }

    /// Flushes any pending repetition cycles.
    pub fn flush(&mut self) -> Result<Vec<RepetitionSummary>, ProvenanceError> {
        self.recorder.flush_summarized(&mut self.summarizer)
    }

    pub fn snapshots(&self) -> &[Tier2Snapshot] {
        &self.captured_snapshots
    }
}

// ---------------------------------------------------------------------------
// Batching sink for worker-local provenance
// ---------------------------------------------------------------------------

/// A worker-local batching sink that accumulates events and flushes them
/// to an underlying store in batches.
pub struct BatchingProvenanceSink {
    store: InMemoryProvenanceStore,
    batch: Mutex<Vec<ProvenanceEvent>>,
    batch_size: usize,
}

impl BatchingProvenanceSink {
    pub fn new(store: InMemoryProvenanceStore, batch_size: usize) -> Self {
        Self {
            store,
            batch: Mutex::new(Vec::new()),
            batch_size,
        }
    }

    pub fn push(&self, event: ProvenanceEvent) -> Result<(), ProvenanceError> {
        let mut batch = self.batch.lock().map_err(|_| ProvenanceError::Poisoned)?;
        batch.push(event);
        if batch.len() >= self.batch_size {
            let events: Vec<_> = batch.drain(..).collect();
            drop(batch);
            self.store.publish(&events)?;
        }
        Ok(())
    }

    pub fn flush(&self) -> Result<(), ProvenanceError> {
        let mut batch = self.batch.lock().map_err(|_| ProvenanceError::Poisoned)?;
        if batch.is_empty() {
            return Ok(());
        }
        let events: Vec<_> = batch.drain(..).collect();
        drop(batch);
        self.store.publish(&events)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn event(id: u64, seq: u64, tier: ProvenanceTier) -> ProvenanceEvent {
        ProvenanceEvent {
            id: ProvenanceNodeId(id),
            sequence: ProvenanceSeq(seq),
            state: StateId(1),
            tier,
            kind: ProvenanceEventKind::StateFork,
            semantic_content: None,
            parents: Vec::new(),
        }
    }

    fn event_with_parents(id: u64, seq: u64, parents: &[u64]) -> ProvenanceEvent {
        ProvenanceEvent {
            id: ProvenanceNodeId(id),
            sequence: ProvenanceSeq(seq),
            state: StateId(1),
            tier: ProvenanceTier::Tier1,
            kind: ProvenanceEventKind::Branch,
            semantic_content: Some(ContentId([42; 32])),
            parents: parents.iter().map(|p| ProvenanceNodeId(*p)).collect(),
        }
    }

    #[test]
    fn store_publishes_and_retrieves_events() {
        let store = InMemoryProvenanceStore::new(100);
        let e = event(1, 1, ProvenanceTier::Tier1);
        assert!(store.publish(std::slice::from_ref(&e)).is_ok());
        assert!(store.contains(ProvenanceNodeId(1)));
        let retrieved = store.get(ProvenanceNodeId(1));
        assert!(retrieved.is_some());
        assert_eq!(retrieved, Some(e));
    }

    #[test]
    fn store_rejects_duplicate_node() {
        let store = InMemoryProvenanceStore::new(100);
        let e = event(1, 1, ProvenanceTier::Tier1);
        assert!(store.publish(std::slice::from_ref(&e)).is_ok());
        let result = store.publish(std::slice::from_ref(&e));
        assert_eq!(result, Err(ProvenanceError::DuplicateNode));
    }

    #[test]
    fn store_rejects_unknown_parent() {
        let store = InMemoryProvenanceStore::new(100);
        let e = event_with_parents(1, 1, &[99]);
        let result = store.publish(&[e]);
        assert_eq!(result, Err(ProvenanceError::UnknownParent));
    }

    #[test]
    fn store_accepts_known_parent() {
        let store = InMemoryProvenanceStore::new(100);
        let parent = event(1, 1, ProvenanceTier::Tier1);
        assert!(store.publish(&[parent]).is_ok());
        let child = event_with_parents(2, 2, &[1]);
        assert!(store.publish(&[child]).is_ok());
        assert!(store.contains(ProvenanceNodeId(2)));
    }

    #[test]
    fn store_evicts_tier2_under_pressure() {
        let store = InMemoryProvenanceStore::new(3);
        assert!(store.publish(&[event(1, 1, ProvenanceTier::Tier2)]).is_ok());
        assert!(store.publish(&[event(2, 2, ProvenanceTier::Tier2)]).is_ok());
        assert!(store.publish(&[event(3, 3, ProvenanceTier::Tier1)]).is_ok());
        // Adding a 4th event should evict the lowest-sequence Tier-2 event (id=1).
        assert!(store.publish(&[event(4, 4, ProvenanceTier::Tier1)]).is_ok());
        assert!(!store.contains(ProvenanceNodeId(1)), "Tier-2 event should be evicted");
        assert!(store.contains(ProvenanceNodeId(2)));
        assert!(store.contains(ProvenanceNodeId(3)));
        assert!(store.contains(ProvenanceNodeId(4)));
    }

    #[test]
    fn store_rejects_full_when_only_tier1_remains() {
        let store = InMemoryProvenanceStore::new(2);
        assert!(store.publish(&[event(1, 1, ProvenanceTier::Tier1)]).is_ok());
        assert!(store.publish(&[event(2, 2, ProvenanceTier::Tier1)]).is_ok());
        // All slots are Tier-1 — cannot evict.
        let result = store.publish(&[event(3, 3, ProvenanceTier::Tier1)]);
        assert_eq!(result, Err(ProvenanceError::Full));
    }

    #[test]
    fn store_rejects_non_monotonic_sequence() {
        let store = InMemoryProvenanceStore::new(100);
        assert!(store.publish(&[event(1, 5, ProvenanceTier::Tier1)]).is_ok());
        // Sequence 3 < 5 is non-monotonic.
        let result = store.publish(&[event(2, 3, ProvenanceTier::Tier1)]);
        assert_eq!(result, Err(ProvenanceError::NonMonotonicSequence));
    }

    #[test]
    fn governor_promotes_high_interest_to_tier1() {
        let governor = AdaptiveTraceGovernor::default_governor();
        let tier = governor.choose_tier(TraceInterest::high(), ProvenanceTier::Tier0);
        assert_eq!(tier, ProvenanceTier::Tier1);
    }

    #[test]
    fn governor_keeps_tier1_events_at_tier1() {
        let governor = AdaptiveTraceGovernor::default_governor();
        let tier = governor.choose_tier(TraceInterest::low(), ProvenanceTier::Tier1);
        assert_eq!(tier, ProvenanceTier::Tier1);
    }

    #[test]
    fn governor_demotes_low_interest_to_tier0() {
        let governor = AdaptiveTraceGovernor::default_governor();
        let tier = governor.choose_tier(TraceInterest::low(), ProvenanceTier::Tier2);
        assert_eq!(tier, ProvenanceTier::Tier0);
    }

    #[test]
    fn governor_promotes_medium_interest_to_tier2() {
        let governor = AdaptiveTraceGovernor::default_governor();
        let interest = TraceInterest {
            novelty: 0.5,
            coverage: 0.4,
            symbolic_depth: 0.5,
            taint_relevance: 0.4,
            solver_cost: 0.4,
            semantic_uncertainty: 0.4,
            approximation: 0.0,
            crash_proximity: 0.3,
            target_proximity: 0.4,
            repetition: 0.1,
            event_rate: 0.1,
        };
        let tier = governor.choose_tier(interest, ProvenanceTier::Tier0);
        assert_eq!(tier, ProvenanceTier::Tier2);
    }

    #[test]
    fn trace_interest_priority_is_bounded() {
        let low = TraceInterest::low();
        let high = TraceInterest::high();
        let low_p = low.priority();
        let high_p = high.priority();
        assert!((0.0..=1.0).contains(&low_p));
        assert!((0.0..=1.0).contains(&high_p));
        assert!(high_p > low_p);
    }

    #[test]
    fn batching_sink_flushes_on_threshold() {
        let store = InMemoryProvenanceStore::new(100);
        let batching = BatchingProvenanceSink::new(store, 2);
        assert!(batching.push(event(1, 1, ProvenanceTier::Tier1)).is_ok());
        // Second push triggers flush at batch_size=2.
        assert!(batching.push(event(2, 2, ProvenanceTier::Tier1)).is_ok());
    }

    #[test]
    fn batching_sink_flushes_remaining_on_flush() {
        let store = InMemoryProvenanceStore::new(100);
        let batching = BatchingProvenanceSink::new(store, 10);
        assert!(batching.push(event(1, 1, ProvenanceTier::Tier1)).is_ok());
        assert!(batching.flush().is_ok());
    }

    #[test]
    fn store_next_sequence_is_monotonic() {
        let store = InMemoryProvenanceStore::new(100);
        let s1 = store.next_sequence();
        let s2 = store.next_sequence();
        assert!(s1.is_ok());
        assert!(s2.is_ok());
        assert_eq!(s1, Ok(ProvenanceSeq(1)));
        assert_eq!(s2, Ok(ProvenanceSeq(2)));
    }
}

#[cfg(test)]
mod flight_recorder_tests {
    use super::*;

    fn event(tier: ProvenanceTier, kind: ProvenanceEventKind, id: u64) -> ProvenanceEvent {
        ProvenanceEvent {
            id: ProvenanceNodeId(id),
            sequence: ProvenanceSeq(id),
            state: StateId(0),
            tier,
            kind,
            semantic_content: None,
            parents: Vec::new(),
        }
    }

    #[test]
    fn recorder_evicts_tier0_before_tier1() {
        let mut rec = FlightRecorder::new(2);
        assert!(
            rec.record(event(ProvenanceTier::Tier0, ProvenanceEventKind::Branch, 0))
                .is_ok()
        );
        assert!(
            rec.record(event(ProvenanceTier::Tier1, ProvenanceEventKind::StateFork, 1))
                .is_ok()
        );
        // Third event: evicts the Tier-0, keeps the Tier-1.
        assert!(
            rec.record(event(ProvenanceTier::Tier1, ProvenanceEventKind::StateFork, 2))
                .is_ok()
        );
        let ids: Vec<u64> = rec.events().map(|e| e.id.0).collect();
        assert_eq!(ids, vec![1, 2], "tier-0 evicted, tier-1s retained");
        assert_eq!(rec.dropped(), (1, 0));
    }

    #[test]
    fn recorder_full_of_tier1_reports_full() {
        let mut rec = FlightRecorder::new(1);
        assert!(
            rec.record(event(ProvenanceTier::Tier1, ProvenanceEventKind::StateFork, 0))
                .is_ok()
        );
        let result = rec.record(event(ProvenanceTier::Tier1, ProvenanceEventKind::StateFork, 1));
        assert_eq!(result, Err(ProvenanceError::Full));
    }
}

#[cfg(test)]
mod repetition_tests {
    use super::*;

    fn branch_event(id: u64, seq: u64, target: u8, tier: ProvenanceTier) -> ProvenanceEvent {
        ProvenanceEvent {
            id: ProvenanceNodeId(id),
            sequence: ProvenanceSeq(seq),
            state: StateId(1),
            tier,
            kind: ProvenanceEventKind::Branch,
            semantic_content: Some(ContentId([target; 32])),
            parents: Vec::new(),
        }
    }

    fn mem_event(id: u64, seq: u64, addr: u8, tier: ProvenanceTier) -> ProvenanceEvent {
        ProvenanceEvent {
            id: ProvenanceNodeId(id),
            sequence: ProvenanceSeq(seq),
            state: StateId(1),
            tier,
            kind: ProvenanceEventKind::MemoryEffect,
            semantic_content: Some(ContentId([addr; 32])),
            parents: Vec::new(),
        }
    }

    #[test]
    fn detects_single_event_tight_loop_and_suppresses_tier2() {
        let config = RepetitionConfig {
            max_period: 4,
            min_repetitions: 2,
            suppression_threshold: 2,
            suppress_tier2: true,
            suppress_tier0: true,
        };
        let mut summarizer = StructuralRepetitionSummarizer::new(config);

        // Feed 5 identical Tier-2 branch events
        let mut outputs = Vec::new();
        for i in 1..=5 {
            outputs.extend(summarizer.feed(branch_event(i, i, 0xAA, ProvenanceTier::Tier2)));
        }

        // Iteration 1 & 2: pass-through event.
        // Iterations 3, 4, 5: suppressed redundant Tier-2 events.
        let mut event_count = 0;
        let mut suppressed_count = 0;
        for out in &outputs {
            match out {
                SummarizerOutput::Event(_) => event_count += 1,
                SummarizerOutput::Suppressed { .. } => suppressed_count += 1,
                SummarizerOutput::Summary(_) => {}
            }
        }
        assert_eq!(event_count, 2, "First two events passed through");
        assert_eq!(suppressed_count, 3, "Subsequent three events suppressed");

        // Breaking the loop emits the summary and the breaking event.
        let breaking = branch_event(6, 6, 0xBB, ProvenanceTier::Tier2);
        let break_outputs = summarizer.feed(breaking);
        assert_eq!(break_outputs.len(), 2);

        assert!(matches!(&break_outputs[0], SummarizerOutput::Summary(_)));
        if let SummarizerOutput::Summary(summary) = &break_outputs[0] {
            assert_eq!(summary.repetition_count, 5);
            assert_eq!(summary.period, 1);
            assert_eq!(summary.suppressed_tier2_count, 3);
            assert_eq!(summary.start_sequence, ProvenanceSeq(1));
            assert_eq!(summary.end_sequence, ProvenanceSeq(5));
        }
    }

    #[test]
    fn preserves_tier1_events_during_repetition() {
        let config = RepetitionConfig {
            max_period: 4,
            min_repetitions: 2,
            suppression_threshold: 2,
            suppress_tier2: true,
            suppress_tier0: true,
        };
        let mut summarizer = StructuralRepetitionSummarizer::new(config);

        // Tier-1 events in a repeating cycle must never be suppressed.
        let mut outputs = Vec::new();
        for i in 1..=4 {
            outputs.extend(summarizer.feed(branch_event(i, i, 0xAA, ProvenanceTier::Tier1)));
        }

        for out in &outputs {
            assert!(
                matches!(out, SummarizerOutput::Event(_)),
                "Tier-1 structural events must never be suppressed"
            );
        }
    }

    #[test]
    fn detects_multi_event_period_cycle() {
        let config = RepetitionConfig {
            max_period: 4,
            min_repetitions: 2,
            suppression_threshold: 2,
            suppress_tier2: true,
            suppress_tier0: true,
        };
        let mut summarizer = StructuralRepetitionSummarizer::new(config);

        // Cycle of period 2: [Branch 0x11, Memory 0x22] repeating 3 times
        let mut seq = 1;
        let mut node = 1;
        for _ in 0..3 {
            summarizer.feed(branch_event(node, seq, 0x11, ProvenanceTier::Tier2));
            node += 1;
            seq += 1;
            summarizer.feed(mem_event(node, seq, 0x22, ProvenanceTier::Tier2));
            node += 1;
            seq += 1;
        }

        // Flush active cycle
        let flushed = summarizer.flush();
        assert_eq!(flushed.len(), 1);
        assert!(matches!(&flushed[0], SummarizerOutput::Summary(_)));
        if let SummarizerOutput::Summary(summary) = &flushed[0] {
            assert_eq!(summary.period, 2);
            assert_eq!(summary.repetition_count, 3);
            assert_eq!(summary.pattern.len(), 2);
            assert_eq!(summary.suppressed_tier2_count, 2); // 3rd repetition (2 events) suppressed
        }
    }

    #[test]
    fn batch_compaction_replaces_cycles() {
        let config = RepetitionConfig::default();
        let summarizer = StructuralRepetitionSummarizer::new(config);

        let mut events = Vec::new();
        // 1 non-repeating event
        events.push(branch_event(1, 1, 0x01, ProvenanceTier::Tier1));
        // 10 repeating branch events
        for i in 2..=11 {
            events.push(branch_event(i, i, 0xAA, ProvenanceTier::Tier2));
        }
        // 1 non-repeating trailing event
        events.push(branch_event(12, 12, 0x02, ProvenanceTier::Tier1));

        let compacted = summarizer.compact(&events);
        assert_eq!(compacted.len(), 3, "1 event + 1 summary + 1 event");

        assert!(matches!(&compacted[1], CompactedProvenance::Summary(_)));
        if let CompactedProvenance::Summary(s) = &compacted[1] {
            assert_eq!(s.repetition_count, 10);
            assert_eq!(s.period, 1);
            assert_eq!(s.start_sequence, ProvenanceSeq(2));
            assert_eq!(s.end_sequence, ProvenanceSeq(11));
        }

        // Compact to synthetic ProvenanceEvents
        let mut next_id = 1000;
        let synthetic_events = summarizer.compact_to_events(&events, || {
            let id = next_id;
            next_id += 1;
            ProvenanceNodeId(id)
        });
        assert_eq!(synthetic_events.len(), 3);
        assert_eq!(synthetic_events[1].kind, ProvenanceEventKind::RepetitionSummary);
        assert_eq!(synthetic_events[1].id, ProvenanceNodeId(1000));
        assert_eq!(synthetic_events[1].sequence, ProvenanceSeq(11));
    }

    #[test]
    fn flight_recorder_summarized_recording() {
        let mut rec = FlightRecorder::new(10);
        let mut summarizer = StructuralRepetitionSummarizer::new(RepetitionConfig {
            max_period: 2,
            min_repetitions: 2,
            suppression_threshold: 2,
            suppress_tier2: true,
            suppress_tier0: true,
        });

        // Record 10 identical Tier-2 events.
        for i in 1..=10 {
            let _ = rec.record_summarized(branch_event(i, i, 0x99, ProvenanceTier::Tier2), &mut summarizer);
        }

        // Only the first 2 events should be in recorder; 8 should have been suppressed!
        assert_eq!(rec.len(), 2);

        // Flushed summary captures full count
        let summaries = rec.flush_summarized(&mut summarizer).unwrap_or_default();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].repetition_count, 10);
        assert_eq!(summaries[0].suppressed_tier2_count, 8);
    }
}

#[cfg(test)]
mod trigger_tests {
    use super::*;

    #[test]
    fn fork_burst_trigger_fires_and_cooldown_works() {
        let mut trigger = ForkBurstTrigger::new(3, 10, 5);
        let mut context = TriggerContext::new();

        // 2 forks: below threshold
        context.record_fork();
        context.record_fork();
        assert_eq!(trigger.evaluate(&context), TriggerDecision::Ignore);

        // 3rd fork: meets threshold
        context.record_fork();
        let decision = trigger.evaluate(&context);
        assert!(decision.is_fired());
        assert_eq!(decision.capture_window(), 10);

        // Immediate next event during cooldown should ignore
        context.event_count = 2; // within cooldown (5)
        context.record_fork();
        assert_eq!(trigger.evaluate(&context), TriggerDecision::Ignore);

        // After cooldown expires
        context.event_count = 10;
        let decision2 = trigger.evaluate(&context);
        assert!(decision2.is_fired());
    }

    #[test]
    fn solver_escalation_trigger_fires_on_cost_and_budget_jump() {
        let mut trigger = SolverEscalationTrigger::new(0.8, 2.0, 5000, 16, 5);
        let mut context = TriggerContext::new();

        // Baseline low query
        context.record_solver_query(0.2, 1000);
        assert_eq!(trigger.evaluate(&context), TriggerDecision::Ignore);

        // Escalation: 0.2 -> 0.5 (2.5x jump >= 2.0)
        context.record_solver_query(0.5, 2000);
        let decision = trigger.evaluate(&context);
        assert!(decision.is_fired());

        // Cooldown reset
        trigger.reset();

        // Budget delta jump: 2000 -> 8000 (+6000 >= 5000)
        context.record_solver_query(0.5, 8000);
        let decision2 = trigger.evaluate(&context);
        assert!(decision2.is_fired());
    }

    #[test]
    fn novelty_spike_trigger_fires_on_high_novelty_and_delta() {
        let mut trigger = NoveltySpikeTrigger::new(0.85, 0.40, 8, 3);
        let mut context = TriggerContext::new();

        // Baseline novelty around 0.1
        for _ in 0..10 {
            context.event_count += 1;
            context.record_novelty(0.1);
        }
        assert_eq!(trigger.evaluate(&context), TriggerDecision::Ignore);

        // Spike to 0.7 (delta is 0.7 - ~0.1 = ~0.6 >= 0.40)
        context.event_count += 1;
        context.record_novelty(0.7);
        let decision = trigger.evaluate(&context);
        assert!(decision.is_fired());
    }

    #[test]
    fn composite_trigger_any_and_all() {
        let t1 = Box::new(ForkBurstTrigger::new(2, 5, 0));
        let t2 = Box::new(CrashProximityTrigger::new(0.9, 10, 0));

        let mut comp_any = CompositeTrigger::any("AnyTrigger", vec![t1, t2]);
        let mut context = TriggerContext::new();
        context.record_fork();
        context.record_fork(); // t1 satisfies
        context.crash_proximity = 0.2; // t2 does not satisfy

        assert!(comp_any.evaluate(&context).is_fired());

        let t3 = Box::new(ForkBurstTrigger::new(2, 5, 0));
        let t4 = Box::new(CrashProximityTrigger::new(0.9, 10, 0));
        let mut comp_all = CompositeTrigger::all("AllTrigger", vec![t3, t4]);
        assert_eq!(comp_all.evaluate(&context), TriggerDecision::Ignore);

        context.crash_proximity = 0.95; // now both satisfy
        assert!(comp_all.evaluate(&context).is_fired());
    }

    #[test]
    fn flight_recorder_check_and_capture_snapshot() {
        let mut rec = FlightRecorder::new(10);
        assert!(
            rec.record(ProvenanceEvent {
                id: ProvenanceNodeId(1),
                sequence: ProvenanceSeq(1),
                state: StateId(1),
                tier: ProvenanceTier::Tier1,
                kind: ProvenanceEventKind::StateFork,
                semantic_content: None,
                parents: Vec::new(),
            })
            .is_ok()
        );
        assert!(
            rec.record(ProvenanceEvent {
                id: ProvenanceNodeId(2),
                sequence: ProvenanceSeq(2),
                state: StateId(1),
                tier: ProvenanceTier::Tier2,
                kind: ProvenanceEventKind::Branch,
                semantic_content: None,
                parents: Vec::new(),
            })
            .is_ok()
        );

        let mut trigger = ForkBurstTrigger::new(1, 4, 0);
        let mut context = TriggerContext::new();
        context.record_fork();

        let snapshot = rec.check_and_capture(&mut trigger, &context);
        assert!(snapshot.is_some());
        if let Some(snap) = snapshot {
            assert_eq!(snap.total_events, 2);
            assert_eq!(snap.tier1_count, 1);
            assert_eq!(snap.tier2_count, 1);
            assert_eq!(snap.captured_at_sequence, ProvenanceSeq(2));
        }
    }

    #[test]
    fn governor_promotes_tier0_to_tier2_during_capture_window() {
        let governor = AdaptiveTraceGovernor::default_governor();
        let low = TraceInterest::low();

        // Baseline: low interest produces Tier-0
        assert_eq!(governor.choose_tier(low, ProvenanceTier::Tier0), ProvenanceTier::Tier0);

        // Notify trigger with capture window = 2
        governor.notify_trigger(&TriggerDecision::Fire {
            reason: "Anomaly detected".into(),
            capture_window: 2,
        });
        assert_eq!(governor.remaining_capture_window(), 2);

        // Next 2 events promoted to Tier-2 despite low interest
        assert_eq!(governor.choose_tier(low, ProvenanceTier::Tier0), ProvenanceTier::Tier2);
        assert_eq!(governor.choose_tier(low, ProvenanceTier::Tier0), ProvenanceTier::Tier2);

        // Window expired: returns to Tier-0
        assert_eq!(governor.choose_tier(low, ProvenanceTier::Tier0), ProvenanceTier::Tier0);
    }

    #[test]
    fn triggered_flight_recorder_end_to_end() {
        let trigger = Box::new(ForkBurstTrigger::new(2, 5, 0));
        let mut t_rec = TriggeredFlightRecorder::new(20, RepetitionConfig::default(), vec![trigger]);

        // Record 2 StateFork events -> should trigger capture
        let e1 = ProvenanceEvent {
            id: ProvenanceNodeId(1),
            sequence: ProvenanceSeq(1),
            state: StateId(1),
            tier: ProvenanceTier::Tier1,
            kind: ProvenanceEventKind::StateFork,
            semantic_content: None,
            parents: Vec::new(),
        };
        let e2 = ProvenanceEvent {
            id: ProvenanceNodeId(2),
            sequence: ProvenanceSeq(2),
            state: StateId(1),
            tier: ProvenanceTier::Tier1,
            kind: ProvenanceEventKind::StateFork,
            semantic_content: None,
            parents: Vec::new(),
        };

        assert!(t_rec.record(e1).is_ok());
        assert!(t_rec.record(e2).is_ok());

        assert_eq!(t_rec.snapshots().len(), 1);
        assert!(t_rec.snapshots()[0].reason.contains("State fork burst detected"));
    }
}
