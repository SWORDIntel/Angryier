#![forbid(unsafe_code)]

use std::fmt;
use std::sync::Mutex;

use angryier_types::{FidelityProfile, RunId};

#[derive(Clone, Debug, PartialEq)]
pub struct BenchmarkRecord {
    pub run: RunId,
    pub case: &'static str,
    pub fidelity: FidelityProfile,
    pub wall_seconds: f64,
    pub states: u64,
    pub solver_queries: u64,
    pub coverage_units: u64,
    pub replay_verified: bool,
    pub semantic_verified: bool,
}

pub trait BenchmarkSink: Send + Sync {
    type Error;
    fn record(&self, result: &BenchmarkRecord) -> Result<(), Self::Error>;
}

/// Errors that can occur while recording benchmark results.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BenchmarkError {
    /// The internal mutex was poisoned by a panicking thread.
    Poisoned,
    /// A record reported a negative wall-clock duration.
    NegativeWallTime,
    /// A record reported zero explored states.
    ZeroStates,
    /// A duplicate `(run, case)` pair was submitted.
    DuplicateCase,
}

impl fmt::Display for BenchmarkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Poisoned => f.write_str("benchmark sink mutex was poisoned"),
            Self::NegativeWallTime => f.write_str("benchmark record has negative wall time"),
            Self::ZeroStates => f.write_str("benchmark record has zero states"),
            Self::DuplicateCase => f.write_str("benchmark record duplicates an existing (run, case) pair"),
        }
    }
}

impl std::error::Error for BenchmarkError {}

/// Aggregate statistics over a set of recorded benchmarks.
#[derive(Clone, Debug, PartialEq)]
pub struct BenchmarkSummary {
    pub total_records: usize,
    pub total_states: u64,
    pub total_solver_queries: u64,
    pub total_coverage_units: u64,
    pub avg_wall_seconds: f64,
    pub all_replay_verified: bool,
    pub all_semantic_verified: bool,
}

/// A thread-safe, in-memory implementation of [`BenchmarkSink`].
#[derive(Default)]
pub struct InMemoryBenchmarkSink {
    records: Mutex<Vec<BenchmarkRecord>>,
}

impl InMemoryBenchmarkSink {
    /// Creates a new, empty sink.
    pub fn new() -> Self {
        Self {
            records: Mutex::new(Vec::new()),
        }
    }

    /// Returns the number of records currently stored.
    pub fn len(&self) -> usize {
        let guard = self.records.lock().unwrap_or_else(|e| e.into_inner());
        guard.len()
    }

    /// Returns `true` if no records have been stored.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns a clone of all records, sorted by `run` then `case` for determinism.
    pub fn records(&self) -> Vec<BenchmarkRecord> {
        let guard = self.records.lock().unwrap_or_else(|e| e.into_inner());
        let mut out: Vec<BenchmarkRecord> = guard.clone();
        out.sort_by(|a, b| a.run.cmp(&b.run).then_with(|| a.case.cmp(b.case)));
        out
    }

    /// Returns aggregate statistics over the stored records, or `None` if empty.
    pub fn summary(&self) -> Option<BenchmarkSummary> {
        let guard = self.records.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_empty() {
            return None;
        }

        let total_records = guard.len();
        let mut total_states: u64 = 0;
        let mut total_solver_queries: u64 = 0;
        let mut total_coverage_units: u64 = 0;
        let mut total_wall: f64 = 0.0;
        let mut all_replay_verified = true;
        let mut all_semantic_verified = true;

        for record in guard.iter() {
            total_states = total_states.saturating_add(record.states);
            total_solver_queries = total_solver_queries.saturating_add(record.solver_queries);
            total_coverage_units = total_coverage_units.saturating_add(record.coverage_units);
            total_wall += record.wall_seconds;
            if !record.replay_verified {
                all_replay_verified = false;
            }
            if !record.semantic_verified {
                all_semantic_verified = false;
            }
        }

        let avg_wall_seconds = total_wall / total_records as f64;

        Some(BenchmarkSummary {
            total_records,
            total_states,
            total_solver_queries,
            total_coverage_units,
            avg_wall_seconds,
            all_replay_verified,
            all_semantic_verified,
        })
    }
}

impl BenchmarkSink for InMemoryBenchmarkSink {
    type Error = BenchmarkError;

    fn record(&self, result: &BenchmarkRecord) -> Result<(), Self::Error> {
        if result.wall_seconds < 0.0 {
            return Err(BenchmarkError::NegativeWallTime);
        }
        if result.states == 0 {
            return Err(BenchmarkError::ZeroStates);
        }

        let mut guard = self.records.lock().unwrap_or_else(|e| e.into_inner());

        if guard
            .iter()
            .any(|existing| existing.run == result.run && existing.case == result.case)
        {
            return Err(BenchmarkError::DuplicateCase);
        }

        guard.push(result.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_record(run: u64, case: &'static str) -> BenchmarkRecord {
        BenchmarkRecord {
            run: RunId(run),
            case,
            fidelity: FidelityProfile::Prove,
            wall_seconds: 1.0,
            states: 10,
            solver_queries: 5,
            coverage_units: 3,
            replay_verified: true,
            semantic_verified: true,
        }
    }

    /// Extracts a `BenchmarkSummary`, failing the test if the sink is empty.
    fn require_summary(sink: &InMemoryBenchmarkSink) -> BenchmarkSummary {
        let summary = sink.summary();
        assert!(summary.is_some());
        match summary {
            Some(s) => s,
            None => {
                // Unreachable: asserted above. Return a default to satisfy types.
                BenchmarkSummary {
                    total_records: 0,
                    total_states: 0,
                    total_solver_queries: 0,
                    total_coverage_units: 0,
                    avg_wall_seconds: 0.0,
                    all_replay_verified: false,
                    all_semantic_verified: false,
                }
            }
        }
    }

    #[test]
    fn record_valid_benchmark_succeeds() {
        let sink = InMemoryBenchmarkSink::new();
        let result = sink.record(&sample_record(1, "case-a"));
        assert!(result.is_ok());
        assert_eq!(sink.len(), 1);
    }

    #[test]
    fn record_negative_wall_time_fails() {
        let sink = InMemoryBenchmarkSink::new();
        let mut record = sample_record(1, "case-a");
        record.wall_seconds = -0.5;
        let result = sink.record(&record);
        assert!(result.is_err());
        assert_eq!(result, Err(BenchmarkError::NegativeWallTime));
        assert_eq!(sink.len(), 0);
    }

    #[test]
    fn record_zero_states_fails() {
        let sink = InMemoryBenchmarkSink::new();
        let mut record = sample_record(1, "case-a");
        record.states = 0;
        let result = sink.record(&record);
        assert!(result.is_err());
        assert_eq!(result, Err(BenchmarkError::ZeroStates));
        assert_eq!(sink.len(), 0);
    }

    #[test]
    fn record_duplicate_case_fails() {
        let sink = InMemoryBenchmarkSink::new();
        let record = sample_record(1, "case-a");
        assert!(sink.record(&record).is_ok());
        let result = sink.record(&record);
        assert!(result.is_err());
        assert_eq!(result, Err(BenchmarkError::DuplicateCase));
        assert_eq!(sink.len(), 1);
    }

    #[test]
    fn len_tracks_records() {
        let sink = InMemoryBenchmarkSink::new();
        assert_eq!(sink.len(), 0);
        assert!(sink.record(&sample_record(1, "case-a")).is_ok());
        assert_eq!(sink.len(), 1);
        assert!(sink.record(&sample_record(1, "case-b")).is_ok());
        assert_eq!(sink.len(), 2);
        assert!(sink.record(&sample_record(2, "case-a")).is_ok());
        assert_eq!(sink.len(), 3);
    }

    #[test]
    fn records_returns_sorted_by_run_then_case() {
        let sink = InMemoryBenchmarkSink::new();
        assert!(sink.record(&sample_record(2, "case-b")).is_ok());
        assert!(sink.record(&sample_record(1, "case-b")).is_ok());
        assert!(sink.record(&sample_record(1, "case-a")).is_ok());
        assert!(sink.record(&sample_record(2, "case-a")).is_ok());

        let records = sink.records();
        assert_eq!(records.len(), 4);
        assert_eq!(records[0].run, RunId(1));
        assert_eq!(records[0].case, "case-a");
        assert_eq!(records[1].run, RunId(1));
        assert_eq!(records[1].case, "case-b");
        assert_eq!(records[2].run, RunId(2));
        assert_eq!(records[2].case, "case-a");
        assert_eq!(records[3].run, RunId(2));
        assert_eq!(records[3].case, "case-b");
    }

    #[test]
    fn summary_returns_none_for_empty_sink() {
        let sink = InMemoryBenchmarkSink::new();
        assert!(sink.summary().is_none());
    }

    #[test]
    fn summary_aggregates_correctly_for_multiple_records() {
        let sink = InMemoryBenchmarkSink::new();
        let mut r1 = sample_record(1, "case-a");
        r1.states = 10;
        r1.solver_queries = 5;
        r1.coverage_units = 3;
        r1.wall_seconds = 2.0;
        let mut r2 = sample_record(1, "case-b");
        r2.states = 20;
        r2.solver_queries = 15;
        r2.coverage_units = 7;
        r2.wall_seconds = 4.0;

        assert!(sink.record(&r1).is_ok());
        assert!(sink.record(&r2).is_ok());

        let summary = require_summary(&sink);
        assert_eq!(summary.total_records, 2);
        assert_eq!(summary.total_states, 30);
        assert_eq!(summary.total_solver_queries, 20);
        assert_eq!(summary.total_coverage_units, 10);
        assert!((summary.avg_wall_seconds - 3.0).abs() < 1e-6);
    }

    #[test]
    fn summary_reports_all_replay_verified_correctly() {
        let sink = InMemoryBenchmarkSink::new();
        let mut r1 = sample_record(1, "case-a");
        r1.replay_verified = true;
        let mut r2 = sample_record(1, "case-b");
        r2.replay_verified = false;

        assert!(sink.record(&r1).is_ok());
        assert!(sink.record(&r2).is_ok());

        let summary = require_summary(&sink);
        assert!(!summary.all_replay_verified);
    }

    #[test]
    fn summary_reports_all_replay_verified_true_when_all_pass() {
        let sink = InMemoryBenchmarkSink::new();
        let mut r1 = sample_record(1, "case-a");
        r1.replay_verified = true;
        let mut r2 = sample_record(1, "case-b");
        r2.replay_verified = true;

        assert!(sink.record(&r1).is_ok());
        assert!(sink.record(&r2).is_ok());

        let summary = require_summary(&sink);
        assert!(summary.all_replay_verified);
    }

    #[test]
    fn summary_reports_all_semantic_verified_correctly() {
        let sink = InMemoryBenchmarkSink::new();
        let mut r1 = sample_record(1, "case-a");
        r1.semantic_verified = false;
        let mut r2 = sample_record(1, "case-b");
        r2.semantic_verified = true;

        assert!(sink.record(&r1).is_ok());
        assert!(sink.record(&r2).is_ok());

        let summary = require_summary(&sink);
        assert!(!summary.all_semantic_verified);
    }

    #[test]
    fn summary_reports_all_semantic_verified_true_when_all_pass() {
        let sink = InMemoryBenchmarkSink::new();
        let mut r1 = sample_record(1, "case-a");
        r1.semantic_verified = true;
        let mut r2 = sample_record(1, "case-b");
        r2.semantic_verified = true;

        assert!(sink.record(&r1).is_ok());
        assert!(sink.record(&r2).is_ok());

        let summary = require_summary(&sink);
        assert!(summary.all_semantic_verified);
    }

    #[test]
    fn summary_avg_wall_seconds_is_correct() {
        let sink = InMemoryBenchmarkSink::new();
        let mut r1 = sample_record(1, "case-a");
        r1.wall_seconds = 1.0;
        let mut r2 = sample_record(1, "case-b");
        r2.wall_seconds = 2.0;
        let mut r3 = sample_record(2, "case-a");
        r3.wall_seconds = 6.0;

        assert!(sink.record(&r1).is_ok());
        assert!(sink.record(&r2).is_ok());
        assert!(sink.record(&r3).is_ok());

        let summary = require_summary(&sink);
        assert!((summary.avg_wall_seconds - 3.0).abs() < 1e-6);
    }

    #[test]
    fn multiple_records_with_different_runs_and_cases_all_succeed() {
        let sink = InMemoryBenchmarkSink::new();
        assert!(sink.record(&sample_record(1, "case-a")).is_ok());
        assert!(sink.record(&sample_record(1, "case-b")).is_ok());
        assert!(sink.record(&sample_record(2, "case-a")).is_ok());
        assert!(sink.record(&sample_record(2, "case-b")).is_ok());
        assert!(sink.record(&sample_record(3, "case-c")).is_ok());

        assert_eq!(sink.len(), 5);
        let records = sink.records();
        assert_eq!(records.len(), 5);
        assert_eq!(records[0].run, RunId(1));
        assert_eq!(records[4].run, RunId(3));
    }

    #[test]
    fn duplicate_case_with_different_run_succeeds() {
        let sink = InMemoryBenchmarkSink::new();
        assert!(sink.record(&sample_record(1, "case-a")).is_ok());
        assert!(sink.record(&sample_record(2, "case-a")).is_ok());
        assert_eq!(sink.len(), 2);
    }

    #[test]
    fn negative_wall_time_takes_precedence_over_zero_states() {
        let sink = InMemoryBenchmarkSink::new();
        let mut record = sample_record(1, "case-a");
        record.wall_seconds = -1.0;
        record.states = 0;
        let result = sink.record(&record);
        assert!(result.is_err());
        assert_eq!(result, Err(BenchmarkError::NegativeWallTime));
    }

    #[test]
    fn display_implementations_are_non_empty() {
        let variants = [
            BenchmarkError::Poisoned,
            BenchmarkError::NegativeWallTime,
            BenchmarkError::ZeroStates,
            BenchmarkError::DuplicateCase,
        ];
        for variant in variants {
            assert!(!variant.to_string().is_empty());
        }
    }
}
