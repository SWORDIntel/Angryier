#![forbid(unsafe_code)]

//! Performance, backpressure, and time-series telemetry contracts.
//!
//! This crate provides a concrete in-memory telemetry sink with metric
//! aggregation, backpressure tracking, and time-series recording. The
//! sink is designed for observability of the execution, provenance, and
//! solver planes without coupling to any external telemetry backend.

use angryier_types::RunId;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Metric model
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MetricKind {
    Counter,
    Gauge,
    Histogram,
    Duration,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Metric {
    pub run: RunId,
    pub name: &'static str,
    pub kind: MetricKind,
    pub value: f64,
}

// ---------------------------------------------------------------------------
// Backpressure model
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct BackpressureSnapshot {
    pub queued_events: u64,
    pub wal_bytes: u64,
    pub dropped_noncritical: u64,
    pub blocked_critical: u64,
}

// ---------------------------------------------------------------------------
// Telemetry traits
// ---------------------------------------------------------------------------

pub trait TelemetrySink: Send + Sync {
    fn record(&self, metric: Metric);
    fn backpressure(&self) -> BackpressureSnapshot;
}

// ---------------------------------------------------------------------------
// Error model
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TelemetryError {
    /// The telemetry sink is poisoned (lock failure).
    Poisoned,
    /// The metric name was not found.
    NotFound,
}

impl core::fmt::Display for TelemetryError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::Poisoned => "telemetry sink poisoned",
            Self::NotFound => "telemetry metric not found",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for TelemetryError {}

// ---------------------------------------------------------------------------
// Aggregated metric summary
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct MetricSummary {
    pub count: u64,
    pub sum: f64,
    pub min: f64,
    pub max: f64,
    pub last: f64,
}

impl MetricSummary {
    pub fn update(&mut self, value: f64) {
        self.count = self.count.saturating_add(1);
        self.sum += value;
        if self.count == 1 {
            self.min = value;
            self.max = value;
        } else {
            if value < self.min {
                self.min = value;
            }
            if value > self.max {
                self.max = value;
            }
        }
        self.last = value;
    }

    pub fn average(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.sum / (self.count as f64)
        }
    }
}

// ---------------------------------------------------------------------------
// Time-series sample
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct TimeSeriesSample {
    pub elapsed: Duration,
    pub value: f64,
}

// ---------------------------------------------------------------------------
// In-memory telemetry sink
// ---------------------------------------------------------------------------

/// A concrete in-memory telemetry sink with metric aggregation,
/// backpressure tracking, and time-series recording.
pub struct InMemoryTelemetrySink {
    metrics: Mutex<BTreeMap<(RunId, &'static str), MetricSummary>>,
    series: Mutex<BTreeMap<(RunId, &'static str), Vec<TimeSeriesSample>>>,
    backpressure: Mutex<BackpressureSnapshot>,
    start: Instant,
}

impl InMemoryTelemetrySink {
    pub fn new() -> Self {
        Self {
            metrics: Mutex::new(BTreeMap::new()),
            series: Mutex::new(BTreeMap::new()),
            backpressure: Mutex::new(BackpressureSnapshot::default()),
            start: Instant::now(),
        }
    }

    pub fn summary(&self, run: RunId, name: &'static str) -> Result<MetricSummary, TelemetryError> {
        let metrics = self.metrics.lock().map_err(|_| TelemetryError::Poisoned)?;
        metrics.get(&(run, name)).copied().ok_or(TelemetryError::NotFound)
    }

    pub fn series(&self, run: RunId, name: &'static str) -> Result<Vec<TimeSeriesSample>, TelemetryError> {
        let series = self.series.lock().map_err(|_| TelemetryError::Poisoned)?;
        series.get(&(run, name)).cloned().ok_or(TelemetryError::NotFound)
    }

    pub fn metric_names(&self, run: RunId) -> Result<Vec<&'static str>, TelemetryError> {
        let metrics = self.metrics.lock().map_err(|_| TelemetryError::Poisoned)?;
        let mut names: Vec<&'static str> = metrics
            .keys()
            .filter(|(r, _)| *r == run)
            .map(|(_, name)| *name)
            .collect();
        names.sort_unstable();
        names.dedup();
        Ok(names)
    }

    pub fn update_backpressure(&self, snapshot: BackpressureSnapshot) -> Result<(), TelemetryError> {
        let mut bp = self.backpressure.lock().map_err(|_| TelemetryError::Poisoned)?;
        *bp = snapshot;
        Ok(())
    }

    pub fn record_dropped_noncritical(&self, count: u64) -> Result<(), TelemetryError> {
        let mut bp = self.backpressure.lock().map_err(|_| TelemetryError::Poisoned)?;
        bp.dropped_noncritical = bp.dropped_noncritical.saturating_add(count);
        Ok(())
    }

    pub fn record_blocked_critical(&self, count: u64) -> Result<(), TelemetryError> {
        let mut bp = self.backpressure.lock().map_err(|_| TelemetryError::Poisoned)?;
        bp.blocked_critical = bp.blocked_critical.saturating_add(count);
        Ok(())
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    fn record_internal(&self, metric: Metric) -> Result<(), TelemetryError> {
        let key = (metric.run, metric.name);
        {
            let mut metrics = self.metrics.lock().map_err(|_| TelemetryError::Poisoned)?;
            let entry = metrics.entry(key).or_default();
            entry.update(metric.value);
        }
        let elapsed = self.start.elapsed();
        let sample = TimeSeriesSample {
            elapsed,
            value: metric.value,
        };
        let mut series = self.series.lock().map_err(|_| TelemetryError::Poisoned)?;
        series.entry(key).or_default().push(sample);
        Ok(())
    }
}

impl Default for InMemoryTelemetrySink {
    fn default() -> Self {
        Self::new()
    }
}

impl TelemetrySink for InMemoryTelemetrySink {
    fn record(&self, metric: Metric) {
        let _ = self.record_internal(metric);
    }

    fn backpressure(&self) -> BackpressureSnapshot {
        match self.backpressure.lock() {
            Ok(guard) => *guard,
            Err(_) => BackpressureSnapshot::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn metric(run: u64, name: &'static str, value: f64) -> Metric {
        Metric {
            run: RunId(run),
            name,
            kind: MetricKind::Counter,
            value,
        }
    }

    #[test]
    fn sink_records_and_summarizes_metrics() {
        let sink = InMemoryTelemetrySink::new();
        sink.record(metric(1, "solver_queries", 5.0));
        sink.record(metric(1, "solver_queries", 10.0));
        sink.record(metric(1, "solver_queries", 15.0));

        let summary = sink.summary(RunId(1), "solver_queries");
        assert!(summary.is_ok());
        let summary = summary.unwrap_or_default();
        assert_eq!(summary.count, 3);
        assert_eq!(summary.sum, 30.0);
        assert_eq!(summary.min, 5.0);
        assert_eq!(summary.max, 15.0);
        assert_eq!(summary.last, 15.0);
    }

    #[test]
    fn sink_average_is_correct() {
        let sink = InMemoryTelemetrySink::new();
        sink.record(metric(1, "avg_test", 10.0));
        sink.record(metric(1, "avg_test", 20.0));
        sink.record(metric(1, "avg_test", 30.0));

        let summary = sink.summary(RunId(1), "avg_test");
        assert!(summary.is_ok());
        let summary = summary.unwrap_or_default();
        assert_eq!(summary.average(), 20.0);
    }

    #[test]
    fn sink_separates_metrics_by_run() {
        let sink = InMemoryTelemetrySink::new();
        sink.record(metric(1, "shared_name", 1.0));
        sink.record(metric(2, "shared_name", 2.0));

        let s1 = sink.summary(RunId(1), "shared_name");
        let s2 = sink.summary(RunId(2), "shared_name");
        assert!(s1.is_ok());
        assert!(s2.is_ok());
        assert_eq!(s1.unwrap_or_default().last, 1.0);
        assert_eq!(s2.unwrap_or_default().last, 2.0);
    }

    #[test]
    fn sink_separates_metrics_by_name() {
        let sink = InMemoryTelemetrySink::new();
        sink.record(metric(1, "metric_a", 10.0));
        sink.record(metric(1, "metric_b", 20.0));

        let a = sink.summary(RunId(1), "metric_a");
        let b = sink.summary(RunId(1), "metric_b");
        assert!(a.is_ok());
        assert!(b.is_ok());
        assert_eq!(a.unwrap_or_default().last, 10.0);
        assert_eq!(b.unwrap_or_default().last, 20.0);
    }

    #[test]
    fn sink_returns_not_found_for_unknown_metric() {
        let sink = InMemoryTelemetrySink::new();
        let result = sink.summary(RunId(1), "nonexistent");
        assert_eq!(result, Err(TelemetryError::NotFound));
    }

    #[test]
    fn sink_records_time_series() {
        let sink = InMemoryTelemetrySink::new();
        sink.record(metric(1, "series_test", 1.0));
        sink.record(metric(1, "series_test", 2.0));
        sink.record(metric(1, "series_test", 3.0));

        let series = sink.series(RunId(1), "series_test");
        assert!(series.is_ok());
        let series = series.unwrap_or_default();
        assert_eq!(series.len(), 3);
        assert_eq!(series[0].value, 1.0);
        assert_eq!(series[1].value, 2.0);
        assert_eq!(series[2].value, 3.0);
    }

    #[test]
    fn sink_time_series_has_increasing_elapsed() {
        let sink = InMemoryTelemetrySink::new();
        sink.record(metric(1, "elapsed_test", 1.0));
        sink.record(metric(1, "elapsed_test", 2.0));

        let series = sink.series(RunId(1), "elapsed_test");
        assert!(series.is_ok());
        let series = series.unwrap_or_default();
        assert!(series.len() >= 2);
        assert!(series[1].elapsed >= series[0].elapsed);
    }

    #[test]
    fn sink_lists_metric_names_for_run() {
        let sink = InMemoryTelemetrySink::new();
        sink.record(metric(1, "alpha", 1.0));
        sink.record(metric(1, "beta", 2.0));
        sink.record(metric(2, "gamma", 3.0));

        let names = sink.metric_names(RunId(1));
        assert!(names.is_ok());
        let names = names.unwrap_or_default();
        assert_eq!(names.len(), 2);
        assert!(names.contains(&"alpha"));
        assert!(names.contains(&"beta"));
        assert!(!names.contains(&"gamma"));
    }

    #[test]
    fn sink_backpressure_defaults_to_zero() {
        let sink = InMemoryTelemetrySink::new();
        let bp = sink.backpressure();
        assert_eq!(bp, BackpressureSnapshot::default());
    }

    #[test]
    fn sink_updates_backpressure_snapshot() {
        let sink = InMemoryTelemetrySink::new();
        let snapshot = BackpressureSnapshot {
            queued_events: 100,
            wal_bytes: 4096,
            dropped_noncritical: 5,
            blocked_critical: 0,
        };
        assert!(sink.update_backpressure(snapshot).is_ok());
        assert_eq!(sink.backpressure(), snapshot);
    }

    #[test]
    fn sink_records_dropped_noncritical() {
        let sink = InMemoryTelemetrySink::new();
        assert!(sink.record_dropped_noncritical(10).is_ok());
        assert!(sink.record_dropped_noncritical(5).is_ok());
        let bp = sink.backpressure();
        assert_eq!(bp.dropped_noncritical, 15);
    }

    #[test]
    fn sink_records_blocked_critical() {
        let sink = InMemoryTelemetrySink::new();
        assert!(sink.record_blocked_critical(3).is_ok());
        let bp = sink.backpressure();
        assert_eq!(bp.blocked_critical, 3);
    }

    #[test]
    fn metric_summary_update_tracks_min_max() {
        let mut summary = MetricSummary::default();
        summary.update(5.0);
        summary.update(1.0);
        summary.update(10.0);
        assert_eq!(summary.min, 1.0);
        assert_eq!(summary.max, 10.0);
        assert_eq!(summary.count, 3);
    }

    #[test]
    fn metric_summary_average_empty_is_zero() {
        let summary = MetricSummary::default();
        assert_eq!(summary.average(), 0.0);
    }

    #[test]
    fn backpressure_snapshot_default_is_zero() {
        let bp = BackpressureSnapshot::default();
        assert_eq!(bp.queued_events, 0);
        assert_eq!(bp.wal_bytes, 0);
        assert_eq!(bp.dropped_noncritical, 0);
        assert_eq!(bp.blocked_critical, 0);
    }

    #[test]
    fn telemetry_error_display_is_non_empty() {
        assert!(!TelemetryError::Poisoned.to_string().is_empty());
        assert!(!TelemetryError::NotFound.to_string().is_empty());
    }

    #[test]
    fn sink_elapsed_increases_over_time() {
        let sink = InMemoryTelemetrySink::new();
        let e1 = sink.elapsed();
        // Spin briefly to ensure time passes.
        let mut sum: u64 = 0;
        for i in 0..1000 {
            sum = sum.wrapping_add(i);
        }
        let _ = sum;
        let e2 = sink.elapsed();
        assert!(e2 >= e1);
    }
}
