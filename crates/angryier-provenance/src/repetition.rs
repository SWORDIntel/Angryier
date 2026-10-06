//! Structural repetition detection and trace summarization.
//!
//! When symbolic execution runs tight loops or repeated branching constructs,
//! provenance sinks and flight recorders can be inundated by repetitive events
//! with identical structural targets.
//!
//! [`RepetitionDetector`] identifies contiguous repeating cycles of period `1..=max_period`.
//! [`StructuralRepetitionSummarizer`] compacts contiguous cycles into [`RepetitionSummary`]
//! records and suppresses redundant Tier-2 events, preventing diagnostic history from being
//! prematurely evicted while strictly preserving structural lineage.

use crate::{ProvenanceEvent, ProvenanceEventKind};
use angryier_types::{ContentId, ProvenanceNodeId, ProvenanceSeq, ProvenanceTier, StateId};

/// Structural equivalence key for provenance events.
///
/// Ignores instance-unique identifiers (like `id`, `sequence`, and dynamic `parents`),
/// focusing purely on the state, kind of operation, and semantic content.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct StructuralEventKey {
    pub state: StateId,
    pub kind: ProvenanceEventKind,
    pub semantic_content: Option<ContentId>,
}

impl StructuralEventKey {
    pub fn from_event(event: &ProvenanceEvent) -> Self {
        Self {
            state: event.state,
            kind: event.kind,
            semantic_content: event.semantic_content,
        }
    }
}

/// Configuration for repetition detection and summarization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepetitionConfig {
    /// Maximum cycle period (pattern length in events) to detect.
    pub max_period: usize,
    /// Minimum repetitions required before qualifying as a cycle.
    pub min_repetitions: usize,
    /// Number of repetitions after which redundant events are suppressed.
    pub suppression_threshold: usize,
    /// Whether to suppress redundant Tier-2 events once threshold is reached.
    pub suppress_tier2: bool,
    /// Whether to suppress redundant Tier-0 events once threshold is reached.
    pub suppress_tier0: bool,
}

impl Default for RepetitionConfig {
    fn default() -> Self {
        Self {
            max_period: 8,
            min_repetitions: 2,
            suppression_threshold: 2,
            suppress_tier2: true,
            suppress_tier0: true,
        }
    }
}

/// A compact summary of a repeating execution cycle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepetitionSummary {
    /// Total number of completed repetitions of the cycle.
    pub repetition_count: usize,
    /// Length of the pattern period (e.g. 1 for simple repeat, k for k-event loop).
    pub period: usize,
    /// Node ID of the first event in the repeating sequence.
    pub start_node: ProvenanceNodeId,
    /// Sequence number of the first event in the repeating sequence.
    pub start_sequence: ProvenanceSeq,
    /// Sequence number of the last event in the repeating sequence.
    pub end_sequence: ProvenanceSeq,
    /// One complete period of the repeating pattern.
    pub pattern: Vec<ProvenanceEvent>,
    /// Number of redundant Tier-2 events suppressed.
    pub suppressed_tier2_count: usize,
    /// Number of redundant Tier-0 events suppressed.
    pub suppressed_tier0_count: usize,
}

impl RepetitionSummary {
    /// Converts this repetition summary into a synthetic [`ProvenanceEvent`].
    pub fn to_provenance_event(&self, summary_id: ProvenanceNodeId, tier: ProvenanceTier) -> ProvenanceEvent {
        let (state, semantic_content, parents) = match self.pattern.first() {
            Some(first) => (first.state, first.semantic_content, first.parents.clone()),
            None => (StateId(0), None, Vec::new()),
        };
        ProvenanceEvent {
            id: summary_id,
            sequence: self.end_sequence,
            state,
            tier,
            kind: ProvenanceEventKind::RepetitionSummary,
            semantic_content,
            parents,
        }
    }
}

/// Result of evaluating an incoming event against an active cycle in [`RepetitionDetector`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RepetitionAction {
    /// Event does not form part of a repeating cycle.
    PassThrough(ProvenanceEvent),
    /// Cycle active and this event is kept (e.g. within first N iterations).
    TrackedCycle {
        period: usize,
        repetition_count: usize,
        event: ProvenanceEvent,
    },
    /// Event is part of an active repeating cycle and is suppressed as redundant.
    Suppressed {
        period: usize,
        repetition_count: usize,
        event: ProvenanceEvent,
    },
    /// A previously active cycle broken by this new non-matching event.
    CycleBroken {
        summary: RepetitionSummary,
        new_event: ProvenanceEvent,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ActiveCycleState {
    period: usize,
    pattern: Vec<ProvenanceEvent>,
    repetition_count: usize,
    offset_in_period: usize,
    start_node: ProvenanceNodeId,
    start_sequence: ProvenanceSeq,
    last_sequence: ProvenanceSeq,
    suppressed_tier2: usize,
    suppressed_tier0: usize,
}

/// Online detector for contiguous repeated patterns in event streams.
pub struct RepetitionDetector {
    config: RepetitionConfig,
    recent_history: Vec<ProvenanceEvent>,
    active_cycle: Option<ActiveCycleState>,
}

impl RepetitionDetector {
    pub fn new(config: RepetitionConfig) -> Self {
        Self {
            config,
            recent_history: Vec::new(),
            active_cycle: None,
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(RepetitionConfig::default())
    }

    pub fn config(&self) -> &RepetitionConfig {
        &self.config
    }

    pub fn is_cycle_active(&self) -> bool {
        self.active_cycle.is_some()
    }

    /// Resets all internal cycle and history state.
    pub fn reset(&mut self) {
        self.recent_history.clear();
        self.active_cycle = None;
    }

    /// Flushes any active cycle and returns its summary if one was in progress.
    pub fn flush(&mut self) -> Option<RepetitionSummary> {
        let active = self.active_cycle.take()?;
        self.recent_history.clear();
        Some(RepetitionSummary {
            repetition_count: active.repetition_count,
            period: active.period,
            start_node: active.start_node,
            start_sequence: active.start_sequence,
            end_sequence: active.last_sequence,
            pattern: active.pattern,
            suppressed_tier2_count: active.suppressed_tier2,
            suppressed_tier0_count: active.suppressed_tier0,
        })
    }

    /// Observes a single incoming event and returns the [`RepetitionAction`].
    pub fn observe(&mut self, event: ProvenanceEvent) -> RepetitionAction {
        if let Some(mut active) = self.active_cycle.take() {
            // Check if incoming event matches the next expected position in the repeating cycle.
            let expected_key = match active.pattern.get(active.offset_in_period) {
                Some(p) => StructuralEventKey::from_event(p),
                None => {
                    // Pattern offset out of bounds (should not happen); reset cycle.
                    self.recent_history.clear();
                    self.recent_history.push(event.clone());
                    return RepetitionAction::PassThrough(event);
                }
            };
            let current_key = StructuralEventKey::from_event(&event);

            if current_key == expected_key {
                active.last_sequence = event.sequence;
                active.offset_in_period = active.offset_in_period.saturating_add(1);
                if active.offset_in_period >= active.period {
                    active.repetition_count = active.repetition_count.saturating_add(1);
                    active.offset_in_period = 0;
                }

                let is_redundant = active.repetition_count >= self.config.suppression_threshold;
                let suppress = is_redundant
                    && match event.tier {
                        ProvenanceTier::Tier2 => self.config.suppress_tier2,
                        ProvenanceTier::Tier0 => self.config.suppress_tier0,
                        ProvenanceTier::Tier1 => false, // Tier-1 structural lineage is never suppressed
                    };

                if suppress {
                    match event.tier {
                        ProvenanceTier::Tier2 => {
                            active.suppressed_tier2 = active.suppressed_tier2.saturating_add(1);
                        }
                        ProvenanceTier::Tier0 => {
                            active.suppressed_tier0 = active.suppressed_tier0.saturating_add(1);
                        }
                        ProvenanceTier::Tier1 => {}
                    }
                    let period = active.period;
                    let repetition_count = active.repetition_count;
                    self.active_cycle = Some(active);
                    return RepetitionAction::Suppressed {
                        period,
                        repetition_count,
                        event,
                    };
                } else {
                    let period = active.period;
                    let repetition_count = active.repetition_count;
                    self.active_cycle = Some(active);
                    return RepetitionAction::TrackedCycle {
                        period,
                        repetition_count,
                        event,
                    };
                }
            } else {
                // Incoming event broke the active cycle!
                let summary = RepetitionSummary {
                    repetition_count: active.repetition_count,
                    period: active.period,
                    start_node: active.start_node,
                    start_sequence: active.start_sequence,
                    end_sequence: active.last_sequence,
                    pattern: active.pattern,
                    suppressed_tier2_count: active.suppressed_tier2,
                    suppressed_tier0_count: active.suppressed_tier0,
                };
                self.recent_history.clear();
                self.recent_history.push(event.clone());
                return RepetitionAction::CycleBroken {
                    summary,
                    new_event: event,
                };
            }
        }

        // No active cycle: buffer event in recent history and check for emerging cycles.
        self.recent_history.push(event.clone());
        let n = self.recent_history.len();

        // Search for shortest period p in 1..=max_period that repeats at least min_repetitions times.
        let mut detected: Option<(usize, usize)> = None; // (period, total_repetitions)
        let max_p = self.config.max_period.min(n / self.config.min_repetitions.max(1));

        for p in 1..=max_p {
            let required_len = match p.checked_mul(self.config.min_repetitions) {
                Some(v) => v,
                None => continue,
            };
            if n < required_len {
                continue;
            }

            // Check if last min_repetitions slices of length p match.
            let base_start = n.saturating_sub(p);
            let base_slice = &self.recent_history[base_start..n];

            let mut all_match = true;
            for rep in 1..self.config.min_repetitions {
                let rep_end = n.saturating_sub(rep * p);
                let rep_start = rep_end.saturating_sub(p);
                let slice = &self.recent_history[rep_start..rep_end];

                for (a, b) in slice.iter().zip(base_slice.iter()) {
                    if StructuralEventKey::from_event(a) != StructuralEventKey::from_event(b) {
                        all_match = false;
                        break;
                    }
                }
                if !all_match {
                    break;
                }
            }

            if all_match {
                // Count how many total contiguous repetitions exist in recent history.
                let mut total_reps = self.config.min_repetitions;
                while n >= total_reps.saturating_add(1) * p {
                    let prev_end = n.saturating_sub(total_reps * p);
                    let prev_start = prev_end.saturating_sub(p);
                    let slice = &self.recent_history[prev_start..prev_end];

                    let mut matches = true;
                    for (a, b) in slice.iter().zip(base_slice.iter()) {
                        if StructuralEventKey::from_event(a) != StructuralEventKey::from_event(b) {
                            matches = false;
                            break;
                        }
                    }
                    if matches {
                        total_reps = total_reps.saturating_add(1);
                    } else {
                        break;
                    }
                }
                detected = Some((p, total_reps));
                break;
            }
        }

        if let Some((p, total_reps)) = detected {
            let start_idx = n.saturating_sub(total_reps * p);
            let pattern_start = n.saturating_sub(p);
            let pattern = self.recent_history[pattern_start..n].to_vec();

            let (start_node, start_sequence) = match self.recent_history.get(start_idx) {
                Some(first) => (first.id, first.sequence),
                None => (event.id, event.sequence),
            };

            let active = ActiveCycleState {
                period: p,
                pattern,
                repetition_count: total_reps,
                offset_in_period: 0,
                start_node,
                start_sequence,
                last_sequence: event.sequence,
                suppressed_tier2: 0,
                suppressed_tier0: 0,
            };

            self.active_cycle = Some(active);
            self.recent_history.drain(..start_idx);

            RepetitionAction::TrackedCycle {
                period: p,
                repetition_count: total_reps,
                event,
            }
        } else {
            // Keep recent history bounded.
            let limit = self.config.max_period.saturating_mul(4).max(32);
            if self.recent_history.len() > limit {
                let excess = self.recent_history.len() - limit;
                self.recent_history.drain(..excess);
            }
            RepetitionAction::PassThrough(event)
        }
    }
}

/// Output item from [`StructuralRepetitionSummarizer::feed`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SummarizerOutput {
    /// Non-redundant event passed through for recording.
    Event(ProvenanceEvent),
    /// Redundant event suppressed to conserve storage.
    Suppressed {
        event_id: ProvenanceNodeId,
        sequence: ProvenanceSeq,
        tier: ProvenanceTier,
    },
    /// Repetition summary produced when a cycle finishes or flushes.
    Summary(RepetitionSummary),
}

/// Compacted element from batch compaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CompactedProvenance {
    Event(ProvenanceEvent),
    Summary(RepetitionSummary),
}

/// Structural summarizer that detects repetition and compacts provenance streams.
pub struct StructuralRepetitionSummarizer {
    detector: RepetitionDetector,
}

impl StructuralRepetitionSummarizer {
    pub fn new(config: RepetitionConfig) -> Self {
        Self {
            detector: RepetitionDetector::new(config),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(RepetitionConfig::default())
    }

    pub fn config(&self) -> &RepetitionConfig {
        self.detector.config()
    }

    /// Feeds an event into the summarizer, returning any resulting outputs.
    pub fn feed(&mut self, event: ProvenanceEvent) -> Vec<SummarizerOutput> {
        match self.detector.observe(event) {
            RepetitionAction::PassThrough(ev) => vec![SummarizerOutput::Event(ev)],
            RepetitionAction::TrackedCycle { event, .. } => vec![SummarizerOutput::Event(event)],
            RepetitionAction::Suppressed { event, .. } => vec![SummarizerOutput::Suppressed {
                event_id: event.id,
                sequence: event.sequence,
                tier: event.tier,
            }],
            RepetitionAction::CycleBroken { summary, new_event } => {
                vec![SummarizerOutput::Summary(summary), SummarizerOutput::Event(new_event)]
            }
        }
    }

    /// Flushes any pending repeating cycle into a [`RepetitionSummary`].
    pub fn flush(&mut self) -> Vec<SummarizerOutput> {
        match self.detector.flush() {
            Some(summary) => vec![SummarizerOutput::Summary(summary)],
            None => Vec::new(),
        }
    }

    /// Performs batch compaction on a sequence of events.
    ///
    /// Identifies contiguous repeating cycles of period `1..=max_period` and replaces
    /// repeated runs with a [`RepetitionSummary`].
    pub fn compact(&self, events: &[ProvenanceEvent]) -> Vec<CompactedProvenance> {
        let mut results = Vec::new();
        let n = events.len();
        let mut i = 0;

        while i < n {
            let mut best_match: Option<(usize, usize)> = None; // (period, repetitions)
            let mut best_saved = 0;

            let max_p = self
                .detector
                .config
                .max_period
                .min((n - i) / self.detector.config.min_repetitions.max(1));

            for p in 1..=max_p {
                let required = match p.checked_mul(self.detector.config.min_repetitions) {
                    Some(v) => v,
                    None => continue,
                };
                if i + required > n {
                    continue;
                }

                let pattern = &events[i..i + p];
                let mut reps = 1;

                while i + (reps + 1) * p <= n {
                    let next_slice = &events[i + reps * p..i + (reps + 1) * p];
                    let mut matches = true;
                    for (a, b) in next_slice.iter().zip(pattern.iter()) {
                        if StructuralEventKey::from_event(a) != StructuralEventKey::from_event(b) {
                            matches = false;
                            break;
                        }
                    }
                    if matches {
                        reps = reps.saturating_add(1);
                    } else {
                        break;
                    }
                }

                if reps >= self.detector.config.min_repetitions {
                    let saved = (reps - 1) * p;
                    if saved > best_saved {
                        best_saved = saved;
                        best_match = Some((p, reps));
                    }
                }
            }

            if let Some((p, reps)) = best_match {
                let total_events = reps * p;
                let pattern = events[i..i + p].to_vec();
                let start_node = events[i].id;
                let start_sequence = events[i].sequence;
                let end_sequence = events[i + total_events - 1].sequence;

                // Count suppressed events after suppression threshold
                let mut suppressed_tier2 = 0;
                let mut suppressed_tier0 = 0;
                let threshold_events = self.detector.config.suppression_threshold * p;

                if total_events > threshold_events {
                    for ev in &events[i + threshold_events..i + total_events] {
                        match ev.tier {
                            ProvenanceTier::Tier2 if self.detector.config.suppress_tier2 => {
                                suppressed_tier2 += 1;
                            }
                            ProvenanceTier::Tier0 if self.detector.config.suppress_tier0 => {
                                suppressed_tier0 += 1;
                            }
                            _ => {}
                        }
                    }
                }

                results.push(CompactedProvenance::Summary(RepetitionSummary {
                    repetition_count: reps,
                    period: p,
                    start_node,
                    start_sequence,
                    end_sequence,
                    pattern,
                    suppressed_tier2_count: suppressed_tier2,
                    suppressed_tier0_count: suppressed_tier0,
                }));
                i += total_events;
            } else {
                results.push(CompactedProvenance::Event(events[i].clone()));
                i += 1;
            }
        }

        results
    }

    /// Compacts events directly into a condensed vector of [`ProvenanceEvent`], replacing
    /// repeating cycles with synthetic [`ProvenanceEventKind::RepetitionSummary`] nodes.
    pub fn compact_to_events(
        &self,
        events: &[ProvenanceEvent],
        mut next_node_id: impl FnMut() -> ProvenanceNodeId,
    ) -> Vec<ProvenanceEvent> {
        let compacted = self.compact(events);
        let mut out = Vec::with_capacity(compacted.len());

        for item in compacted {
            match item {
                CompactedProvenance::Event(ev) => out.push(ev),
                CompactedProvenance::Summary(summary) => {
                    let node_id = next_node_id();
                    out.push(summary.to_provenance_event(node_id, ProvenanceTier::Tier1));
                }
            }
        }

        out
    }
}
