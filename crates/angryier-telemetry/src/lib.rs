#![forbid(unsafe_code)]

use angryier_types::RunId;

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackpressureSnapshot {
    pub queued_events: u64,
    pub wal_bytes: u64,
    pub dropped_noncritical: u64,
    pub blocked_critical: u64,
}

pub trait TelemetrySink: Send + Sync {
    fn record(&self, metric: Metric);
    fn backpressure(&self) -> BackpressureSnapshot;
}
