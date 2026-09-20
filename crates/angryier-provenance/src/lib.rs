#![forbid(unsafe_code)]

//! Adaptive tiered provenance transport.
//!
//! Tier-1 structural events are never silently dropped. The in-memory sink
//! provides bounded priority-aware queuing with worker-local batching.
//! The adaptive governor promotes or demotes events between tiers based on
//! trace interest signals.

use angryier_types::{ContentId, ProvenanceNodeId, ProvenanceSeq, ProvenanceTier, StateId};
use std::collections::BTreeMap;
use std::sync::Mutex;

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
}

impl AdaptiveTraceGovernor {
    pub fn new(tier1_threshold: f32, tier2_threshold: f32) -> Self {
        Self {
            tier1_threshold,
            tier2_threshold,
        }
    }

    pub fn default_governor() -> Self {
        Self::new(0.7, 0.3)
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
            ProvenanceTier::Tier1
        } else if priority >= self.tier2_threshold {
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
        rec.record(event(ProvenanceTier::Tier0, ProvenanceEventKind::Branch, 0))
            .unwrap();
        rec.record(event(ProvenanceTier::Tier1, ProvenanceEventKind::StateFork, 1))
            .unwrap();
        // Third event: evicts the Tier-0, keeps the Tier-1.
        rec.record(event(ProvenanceTier::Tier1, ProvenanceEventKind::StateFork, 2))
            .unwrap();
        let ids: Vec<u64> = rec.events().map(|e| e.id.0).collect();
        assert_eq!(ids, vec![1, 2], "tier-0 evicted, tier-1s retained");
        assert_eq!(rec.dropped(), (1, 0));
    }

    #[test]
    fn recorder_full_of_tier1_reports_full() {
        let mut rec = FlightRecorder::new(1);
        rec.record(event(ProvenanceTier::Tier1, ProvenanceEventKind::StateFork, 0))
            .unwrap();
        let err = rec
            .record(event(ProvenanceTier::Tier1, ProvenanceEventKind::StateFork, 1))
            .unwrap_err();
        assert_eq!(err, ProvenanceError::Full);
    }
}
