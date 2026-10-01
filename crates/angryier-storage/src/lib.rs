#![forbid(unsafe_code)]

//! Local WAL, spill, raw chunk, and retention contracts.
//!
//! This crate provides a concrete in-memory write-ahead log (WAL) with
//! checkpoint-based replay, priority-aware retention, and quarantine
//! lifecycle management. The WAL is designed for backpressure scenarios
//! where provenance events and replay capsules must be durably buffered
//! before being forwarded to the knowledge plane.

use angryier_types::{ContentId, RetentionProfile};
use std::collections::BTreeMap;
use std::sync::Mutex;

// ---------------------------------------------------------------------------
// Record priority and WAL record model
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecordPriority {
    /// Best-effort records may be dropped under backpressure.
    BestEffort,
    /// Structural records should be retained if at all possible.
    Structural,
    /// Correctness-critical records must never be dropped.
    CorrectnessCritical,
}

impl RecordPriority {
    /// Returns the numeric severity of this priority (higher = more important).
    pub fn severity(&self) -> u8 {
        match self {
            Self::BestEffort => 0,
            Self::Structural => 1,
            Self::CorrectnessCritical => 2,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalRecord {
    pub artifact: ContentId,
    pub priority: RecordPriority,
    pub bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Error model
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalError {
    /// The WAL is full (backpressure).
    Full,
    /// The WAL is poisoned (lock failure).
    Poisoned,
    /// An invalid checkpoint was provided.
    InvalidCheckpoint,
    /// A record with a duplicate artifact ID was appended.
    DuplicateArtifact,
    /// The WAL is at capacity and cannot accept best-effort records.
    BestEffortDropped,
}

impl core::fmt::Display for WalError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::Full => "WAL is full (backpressure)",
            Self::Poisoned => "WAL poisoned",
            Self::InvalidCheckpoint => "invalid WAL checkpoint",
            Self::DuplicateArtifact => "duplicate WAL artifact",
            Self::BestEffortDropped => "best-effort WAL record dropped due to backpressure",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for WalError {}

// ---------------------------------------------------------------------------
// WAL traits
// ---------------------------------------------------------------------------

pub trait LocalWal: Send + Sync {
    type Error;
    fn append(&self, record: WalRecord) -> Result<(), Self::Error>;
    fn checkpoint(&self) -> Result<u64, Self::Error>;
    fn replay_from(&self, checkpoint: u64) -> Result<Vec<WalRecord>, Self::Error>;
}

pub trait RetentionPolicy: Send + Sync {
    fn may_quarantine(&self, profile: RetentionProfile, artifact: ContentId) -> bool;
    fn may_purge(&self, profile: RetentionProfile, artifact: ContentId) -> bool;
}

// ---------------------------------------------------------------------------
// In-memory WAL with checkpoint-based replay
// ---------------------------------------------------------------------------

/// A bounded in-memory write-ahead log with priority-aware retention.
///
/// Correctness-critical records are never dropped. Structural records are
/// retained until the WAL is at capacity with only critical/structural records.
/// Best-effort records are dropped first under backpressure.
pub struct InMemoryWal {
    records: Mutex<BTreeMap<u64, WalRecord>>,
    next_seq: Mutex<u64>,
    capacity: usize,
}

impl InMemoryWal {
    pub fn new(capacity: usize) -> Self {
        Self {
            records: Mutex::new(BTreeMap::new()),
            next_seq: Mutex::new(0),
            capacity,
        }
    }

    pub fn len(&self) -> usize {
        match self.records.lock() {
            Ok(guard) => guard.len(),
            Err(_) => 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn next_sequence(&self) -> Result<u64, WalError> {
        let mut seq = self.next_seq.lock().map_err(|_| WalError::Poisoned)?;
        *seq = seq.checked_add(1).ok_or(WalError::Full)?;
        Ok(*seq)
    }

    fn evict_under_pressure(
        records: &mut BTreeMap<u64, WalRecord>,
        incoming_priority: RecordPriority,
    ) -> Result<(), WalError> {
        // Try to evict the oldest best-effort record first.
        let candidate = records
            .iter()
            .filter(|(_, r)| r.priority == RecordPriority::BestEffort)
            .map(|(seq, _)| *seq)
            .next();
        if let Some(seq) = candidate {
            records.remove(&seq);
            return Ok(());
        }

        // Only allow eviction of Structural records if incoming record is CorrectnessCritical.
        if incoming_priority == RecordPriority::CorrectnessCritical {
            let candidate = records
                .iter()
                .filter(|(_, r)| r.priority == RecordPriority::Structural)
                .map(|(seq, _)| *seq)
                .next();
            if let Some(seq) = candidate {
                records.remove(&seq);
                return Ok(());
            }
        }

        if incoming_priority == RecordPriority::BestEffort {
            return Err(WalError::BestEffortDropped);
        }

        // Never evict correctness-critical records (and structural cannot evict structural/critical).
        Err(WalError::Full)
    }
}

impl LocalWal for InMemoryWal {
    type Error = WalError;

    fn append(&self, record: WalRecord) -> Result<(), Self::Error> {
        let seq = self.next_sequence()?;
        let mut records = self.records.lock().map_err(|_| WalError::Poisoned)?;

        // Check for duplicate artifacts.
        if records.values().any(|r| r.artifact == record.artifact) {
            return Err(WalError::DuplicateArtifact);
        }

        if records.len() >= self.capacity {
            // Under backpressure, try to evict lower-priority records.
            Self::evict_under_pressure(&mut records, record.priority)?;
        }
        records.insert(seq, record);
        Ok(())
    }

    fn checkpoint(&self) -> Result<u64, Self::Error> {
        let records = self.records.lock().map_err(|_| WalError::Poisoned)?;
        Ok(records.keys().next().copied().unwrap_or(0))
    }

    fn replay_from(&self, checkpoint: u64) -> Result<Vec<WalRecord>, Self::Error> {
        let records = self.records.lock().map_err(|_| WalError::Poisoned)?;
        Ok(records.range(checkpoint..).map(|(_, r)| r.clone()).collect())
    }
}

// ---------------------------------------------------------------------------
// Retention policy implementation
// ---------------------------------------------------------------------------

/// A basic retention policy that quarantines forensic/research artifacts
/// and purges disposable artifacts after checkpoint.
pub struct BasicRetentionPolicy {
    /// Whether to quarantine forensic artifacts.
    quarantine_forensic: bool,
    /// Whether to quarantine research artifacts.
    quarantine_research: bool,
    /// Whether to purge disposable artifacts.
    purge_disposable: bool,
}

impl BasicRetentionPolicy {
    pub fn new() -> Self {
        Self {
            quarantine_forensic: true,
            quarantine_research: true,
            purge_disposable: true,
        }
    }

    pub fn strict() -> Self {
        Self {
            quarantine_forensic: true,
            quarantine_research: true,
            purge_disposable: false,
        }
    }

    pub fn lenient() -> Self {
        Self {
            quarantine_forensic: false,
            quarantine_research: false,
            purge_disposable: true,
        }
    }
}

impl Default for BasicRetentionPolicy {
    fn default() -> Self {
        Self::new()
    }
}

impl RetentionPolicy for BasicRetentionPolicy {
    fn may_quarantine(&self, profile: RetentionProfile, _artifact: ContentId) -> bool {
        match profile {
            RetentionProfile::Forensic => self.quarantine_forensic,
            RetentionProfile::Research => self.quarantine_research,
            RetentionProfile::Benchmark => false,
            RetentionProfile::Disposable => false,
        }
    }

    fn may_purge(&self, profile: RetentionProfile, _artifact: ContentId) -> bool {
        match profile {
            RetentionProfile::Forensic => false,
            RetentionProfile::Research => false,
            RetentionProfile::Benchmark => false,
            RetentionProfile::Disposable => self.purge_disposable,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: u8, priority: RecordPriority) -> WalRecord {
        WalRecord {
            artifact: ContentId([id; 32]),
            priority,
            bytes: vec![id],
        }
    }

    #[test]
    fn wal_appends_and_replays_records() {
        let wal = InMemoryWal::new(100);
        assert!(wal.append(record(1, RecordPriority::CorrectnessCritical)).is_ok());
        assert!(wal.append(record(2, RecordPriority::Structural)).is_ok());
        assert!(wal.append(record(3, RecordPriority::BestEffort)).is_ok());
        assert_eq!(wal.len(), 3);

        let replayed = wal.replay_from(0);
        assert!(replayed.is_ok());
        assert_eq!(replayed.as_ref().map(Vec::len), Ok(3));
    }

    #[test]
    fn wal_rejects_duplicate_artifact() {
        let wal = InMemoryWal::new(100);
        assert!(wal.append(record(1, RecordPriority::CorrectnessCritical)).is_ok());
        let result = wal.append(record(1, RecordPriority::CorrectnessCritical));
        assert_eq!(result, Err(WalError::DuplicateArtifact));
    }

    #[test]
    fn wal_evicts_best_effort_under_pressure() {
        let wal = InMemoryWal::new(3);
        assert!(wal.append(record(1, RecordPriority::BestEffort)).is_ok());
        assert!(wal.append(record(2, RecordPriority::Structural)).is_ok());
        assert!(wal.append(record(3, RecordPriority::CorrectnessCritical)).is_ok());
        // Adding a 4th record should evict the best-effort record (id=1).
        assert!(wal.append(record(4, RecordPriority::CorrectnessCritical)).is_ok());
        assert_eq!(wal.len(), 3);

        let replayed = wal.replay_from(0).unwrap_or_default();
        // The best-effort record should have been evicted.
        assert!(!replayed.iter().any(|r| r.artifact == ContentId([1; 32])));
        assert!(replayed.iter().any(|r| r.artifact == ContentId([2; 32])));
    }

    #[test]
    fn wal_evicts_structural_before_critical() {
        let wal = InMemoryWal::new(2);
        assert!(wal.append(record(1, RecordPriority::Structural)).is_ok());
        assert!(wal.append(record(2, RecordPriority::CorrectnessCritical)).is_ok());
        // Adding a 3rd record should evict the structural record (id=1).
        assert!(wal.append(record(3, RecordPriority::CorrectnessCritical)).is_ok());

        let replayed = wal.replay_from(0).unwrap_or_default();
        assert!(!replayed.iter().any(|r| r.artifact == ContentId([1; 32])));
        assert!(replayed.iter().any(|r| r.artifact == ContentId([2; 32])));
        assert!(replayed.iter().any(|r| r.artifact == ContentId([3; 32])));
    }

    #[test]
    fn wal_drops_best_effort_when_only_structural_remain() {
        let wal = InMemoryWal::new(2);
        assert!(wal.append(record(1, RecordPriority::Structural)).is_ok());
        assert!(wal.append(record(2, RecordPriority::Structural)).is_ok());
        let result = wal.append(record(3, RecordPriority::BestEffort));
        assert_eq!(result, Err(WalError::BestEffortDropped));
    }

    #[test]
    fn wal_rejects_full_when_only_critical_remain() {
        let wal = InMemoryWal::new(2);
        assert!(wal.append(record(1, RecordPriority::CorrectnessCritical)).is_ok());
        assert!(wal.append(record(2, RecordPriority::CorrectnessCritical)).is_ok());
        // All slots are critical — cannot evict.
        let result = wal.append(record(3, RecordPriority::CorrectnessCritical));
        assert_eq!(result, Err(WalError::Full));
    }

    #[test]
    fn wal_checkpoint_returns_oldest_sequence() {
        let wal = InMemoryWal::new(100);
        assert!(wal.append(record(1, RecordPriority::CorrectnessCritical)).is_ok());
        assert!(wal.append(record(2, RecordPriority::CorrectnessCritical)).is_ok());
        let checkpoint = wal.checkpoint();
        assert!(checkpoint.is_ok());
        // The checkpoint should be the sequence of the first record.
        let checkpoint = checkpoint.unwrap_or(0);
        let replayed = wal.replay_from(checkpoint).unwrap_or_default();
        assert_eq!(replayed.len(), 2);
    }

    #[test]
    fn wal_replay_from_checkpoint_returns_subset() {
        let wal = InMemoryWal::new(100);
        assert!(wal.append(record(1, RecordPriority::CorrectnessCritical)).is_ok());
        assert!(wal.append(record(2, RecordPriority::CorrectnessCritical)).is_ok());
        assert!(wal.append(record(3, RecordPriority::CorrectnessCritical)).is_ok());

        // Replay from the second record's sequence.
        let replayed = wal.replay_from(2).unwrap_or_default();
        assert_eq!(replayed.len(), 2);
        assert!(replayed.iter().any(|r| r.artifact == ContentId([2; 32])));
        assert!(replayed.iter().any(|r| r.artifact == ContentId([3; 32])));
    }

    #[test]
    fn wal_replay_from_empty_returns_empty() {
        let wal = InMemoryWal::new(100);
        let replayed = wal.replay_from(0);
        assert!(replayed.is_ok());
        assert_eq!(replayed.as_ref().map(Vec::len), Ok(0));
    }

    #[test]
    fn retention_policy_quarantines_forensic() {
        let policy = BasicRetentionPolicy::new();
        assert!(policy.may_quarantine(RetentionProfile::Forensic, ContentId([1; 32])));
        assert!(policy.may_quarantine(RetentionProfile::Research, ContentId([1; 32])));
        assert!(!policy.may_quarantine(RetentionProfile::Benchmark, ContentId([1; 32])));
        assert!(!policy.may_quarantine(RetentionProfile::Disposable, ContentId([1; 32])));
    }

    #[test]
    fn retention_policy_purges_disposable() {
        let policy = BasicRetentionPolicy::new();
        assert!(policy.may_purge(RetentionProfile::Disposable, ContentId([1; 32])));
        assert!(!policy.may_purge(RetentionProfile::Forensic, ContentId([1; 32])));
        assert!(!policy.may_purge(RetentionProfile::Research, ContentId([1; 32])));
    }

    #[test]
    fn retention_policy_strict_never_purges() {
        let policy = BasicRetentionPolicy::strict();
        assert!(!policy.may_purge(RetentionProfile::Disposable, ContentId([1; 32])));
    }

    #[test]
    fn retention_policy_lenient_never_quarantines() {
        let policy = BasicRetentionPolicy::lenient();
        assert!(!policy.may_quarantine(RetentionProfile::Forensic, ContentId([1; 32])));
        assert!(!policy.may_quarantine(RetentionProfile::Research, ContentId([1; 32])));
    }

    #[test]
    fn record_priority_severity_is_ordered() {
        assert!(RecordPriority::CorrectnessCritical.severity() > RecordPriority::Structural.severity());
        assert!(RecordPriority::Structural.severity() > RecordPriority::BestEffort.severity());
    }

    #[test]
    fn wal_error_display_is_non_empty() {
        assert!(!WalError::Full.to_string().is_empty());
        assert!(!WalError::Poisoned.to_string().is_empty());
        assert!(!WalError::InvalidCheckpoint.to_string().is_empty());
        assert!(!WalError::DuplicateArtifact.to_string().is_empty());
        assert!(!WalError::BestEffortDropped.to_string().is_empty());
    }
}
