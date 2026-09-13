#![forbid(unsafe_code)]

use angryier_types::{
    CodeVersionGuard, ContentId, LedgerEpoch, ProvenanceSeq, ReplayCapsuleId, SemanticVersion, StateId,
};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, RwLock},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerSnapshot {
    pub epoch: LedgerEpoch,
    pub state: StateId,
    pub provenance: ProvenanceSeq,
    pub replay: Option<ReplayCapsuleId>,
    pub semantic_version: SemanticVersion,
    pub semantic_content: ContentId,
    pub code_versions: Vec<CodeVersionGuard>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerMutation {
    pub state: StateId,
    pub code_versions: Vec<CodeVersionGuard>,
    pub provenance_from: ProvenanceSeq,
    pub provenance_to: ProvenanceSeq,
    pub replay: Option<ReplayCapsuleId>,
    pub semantic_version: SemanticVersion,
    pub semantic_content: ContentId,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LedgerError {
    UnknownState,
    DuplicateState,
    StaleEpoch,
    StaleCodeVersion,
    SemanticVersionMismatch,
    SemanticContentMismatch,
    ProvenanceGap,
    ReplayMismatch,
    Conflict,
    Poisoned,
}

impl core::fmt::Display for LedgerError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::UnknownState => "unknown execution state",
            Self::DuplicateState => "execution state already registered",
            Self::StaleEpoch => "stale execution-ledger epoch",
            Self::StaleCodeVersion => "stale code-page version",
            Self::SemanticVersionMismatch => "semantic version mismatch",
            Self::SemanticContentMismatch => "semantic content identity mismatch",
            Self::ProvenanceGap => "provenance sequence gap",
            Self::ReplayMismatch => "replay checkpoint mismatch",
            Self::Conflict => "conflicting ledger mutation",
            Self::Poisoned => "execution-ledger synchronization primitive poisoned",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for LedgerError {}

pub trait ExecutionLedger: Send + Sync {
    type Transaction;
    fn begin(&self, base: &LedgerSnapshot) -> Result<Self::Transaction, LedgerError>;
    fn commit(&self, tx: Self::Transaction, mutation: LedgerMutation) -> Result<LedgerSnapshot, LedgerError>;
    fn abort(&self, tx: Self::Transaction);
}

#[derive(Clone, Debug)]
pub struct InMemoryTransaction {
    base: LedgerSnapshot,
}

#[derive(Debug, Default)]
pub struct InMemoryExecutionLedger {
    states: RwLock<BTreeMap<StateId, Arc<Mutex<LedgerSnapshot>>>>,
}

impl InMemoryExecutionLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&self, snapshot: LedgerSnapshot) -> Result<(), LedgerError> {
        let mut states = self.states.write().map_err(|_| LedgerError::Poisoned)?;
        if states.contains_key(&snapshot.state) {
            return Err(LedgerError::DuplicateState);
        }
        states.insert(snapshot.state, Arc::new(Mutex::new(snapshot)));
        Ok(())
    }

    pub fn snapshot(&self, state: StateId) -> Result<LedgerSnapshot, LedgerError> {
        let slot = {
            let states = self.states.read().map_err(|_| LedgerError::Poisoned)?;
            Arc::clone(states.get(&state).ok_or(LedgerError::UnknownState)?)
        };
        let snapshot = slot.lock().map_err(|_| LedgerError::Poisoned)?.clone();
        Ok(snapshot)
    }

    fn slot(&self, state: StateId) -> Result<Arc<Mutex<LedgerSnapshot>>, LedgerError> {
        let states = self.states.read().map_err(|_| LedgerError::Poisoned)?;
        states.get(&state).cloned().ok_or(LedgerError::UnknownState)
    }

    fn validate_base(current: &LedgerSnapshot, base: &LedgerSnapshot) -> Result<(), LedgerError> {
        if current.state != base.state {
            return Err(LedgerError::Conflict);
        }
        if current.epoch != base.epoch {
            return Err(LedgerError::StaleEpoch);
        }
        if current.code_versions != base.code_versions {
            return Err(LedgerError::StaleCodeVersion);
        }
        if current.semantic_version != base.semantic_version {
            return Err(LedgerError::SemanticVersionMismatch);
        }
        if current.semantic_content != base.semantic_content {
            return Err(LedgerError::SemanticContentMismatch);
        }
        if current.provenance != base.provenance {
            return Err(LedgerError::ProvenanceGap);
        }
        if current.replay != base.replay {
            return Err(LedgerError::ReplayMismatch);
        }
        Ok(())
    }

    fn validate_mutation(current: &LedgerSnapshot, mutation: &LedgerMutation) -> Result<(), LedgerError> {
        if mutation.state != current.state {
            return Err(LedgerError::Conflict);
        }
        if mutation.provenance_from != current.provenance {
            return Err(LedgerError::ProvenanceGap);
        }
        if mutation.provenance_to.0 < mutation.provenance_from.0 {
            return Err(LedgerError::ProvenanceGap);
        }
        Ok(())
    }
}

impl ExecutionLedger for InMemoryExecutionLedger {
    type Transaction = InMemoryTransaction;

    fn begin(&self, base: &LedgerSnapshot) -> Result<Self::Transaction, LedgerError> {
        let slot = self.slot(base.state)?;
        let current = slot.lock().map_err(|_| LedgerError::Poisoned)?;
        Self::validate_base(&current, base)?;
        Ok(InMemoryTransaction { base: base.clone() })
    }

    fn commit(&self, tx: Self::Transaction, mutation: LedgerMutation) -> Result<LedgerSnapshot, LedgerError> {
        let slot = self.slot(tx.base.state)?;
        let mut current = slot.lock().map_err(|_| LedgerError::Poisoned)?;

        Self::validate_base(&current, &tx.base)?;
        Self::validate_mutation(&current, &mutation)?;

        let next_epoch = current
            .epoch
            .0
            .checked_add(1)
            .map(LedgerEpoch)
            .ok_or(LedgerError::Conflict)?;

        let next = LedgerSnapshot {
            epoch: next_epoch,
            state: current.state,
            provenance: mutation.provenance_to,
            replay: mutation.replay,
            semantic_version: mutation.semantic_version,
            semantic_content: mutation.semantic_content,
            code_versions: mutation.code_versions,
        };

        *current = next.clone();
        Ok(next)
    }

    fn abort(&self, _tx: Self::Transaction) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_types::{CodePageId, CodePageVersion};
    use std::thread;

    fn content(byte: u8) -> ContentId {
        ContentId([byte; 32])
    }

    fn snapshot(state: u64) -> LedgerSnapshot {
        LedgerSnapshot {
            epoch: LedgerEpoch(0),
            state: StateId(state),
            provenance: ProvenanceSeq(0),
            replay: None,
            semantic_version: SemanticVersion(1),
            semantic_content: content(1),
            code_versions: vec![CodeVersionGuard {
                page: CodePageId(1),
                version: CodePageVersion(0),
            }],
        }
    }

    fn mutation(state: u64) -> LedgerMutation {
        LedgerMutation {
            state: StateId(state),
            code_versions: vec![CodeVersionGuard {
                page: CodePageId(1),
                version: CodePageVersion(1),
            }],
            provenance_from: ProvenanceSeq(0),
            provenance_to: ProvenanceSeq(4),
            replay: Some(ReplayCapsuleId(9)),
            semantic_version: SemanticVersion(2),
            semantic_content: content(2),
        }
    }

    #[test]
    fn successful_commit_publishes_one_atomic_epoch() -> Result<(), LedgerError> {
        let ledger = InMemoryExecutionLedger::new();
        let base = snapshot(1);
        ledger.register(base.clone())?;

        let tx = ledger.begin(&base)?;
        let next = ledger.commit(tx, mutation(1))?;

        assert_eq!(next.epoch, LedgerEpoch(1));
        assert_eq!(next.provenance, ProvenanceSeq(4));
        assert_eq!(next.replay, Some(ReplayCapsuleId(9)));
        assert_eq!(next.semantic_version, SemanticVersion(2));
        assert_eq!(next.semantic_content, content(2));
        assert_eq!(next.code_versions[0].version, CodePageVersion(1));
        assert_eq!(ledger.snapshot(StateId(1))?, next);
        Ok(())
    }

    #[test]
    fn stale_transaction_is_rejected_without_partial_publication() -> Result<(), LedgerError> {
        let ledger = InMemoryExecutionLedger::new();
        let base = snapshot(1);
        ledger.register(base.clone())?;

        let stale = ledger.begin(&base)?;
        let fresh = ledger.begin(&base)?;
        let committed = ledger.commit(fresh, mutation(1))?;

        assert_eq!(ledger.commit(stale, mutation(1)), Err(LedgerError::StaleEpoch));
        assert_eq!(ledger.snapshot(StateId(1))?, committed);
        Ok(())
    }

    #[test]
    fn provenance_gap_fails_closed() -> Result<(), LedgerError> {
        let ledger = InMemoryExecutionLedger::new();
        let base = snapshot(1);
        ledger.register(base.clone())?;
        let tx = ledger.begin(&base)?;
        let mut bad = mutation(1);
        bad.provenance_from = ProvenanceSeq(3);

        assert_eq!(ledger.commit(tx, bad), Err(LedgerError::ProvenanceGap));
        assert_eq!(ledger.snapshot(StateId(1))?, base);
        Ok(())
    }

    #[test]
    fn independent_states_commit_without_shared_state_lock() -> Result<(), LedgerError> {
        let ledger = Arc::new(InMemoryExecutionLedger::new());
        let first = snapshot(1);
        let second = snapshot(2);
        ledger.register(first.clone())?;
        ledger.register(second.clone())?;

        let left = {
            let ledger = Arc::clone(&ledger);
            thread::spawn(move || -> Result<LedgerSnapshot, LedgerError> {
                let tx = ledger.begin(&first)?;
                ledger.commit(tx, mutation(1))
            })
        };
        let right = {
            let ledger = Arc::clone(&ledger);
            thread::spawn(move || -> Result<LedgerSnapshot, LedgerError> {
                let tx = ledger.begin(&second)?;
                ledger.commit(tx, mutation(2))
            })
        };

        let left = left.join().map_err(|_| LedgerError::Conflict)??;
        let right = right.join().map_err(|_| LedgerError::Conflict)??;
        assert_eq!(left.epoch, LedgerEpoch(1));
        assert_eq!(right.epoch, LedgerEpoch(1));
        Ok(())
    }

    #[test]
    fn register_duplicate_state_fails() -> Result<(), LedgerError> {
        let ledger = InMemoryExecutionLedger::new();
        let base = snapshot(1);
        ledger.register(base.clone())?;
        assert_eq!(ledger.register(base), Err(LedgerError::DuplicateState));
        Ok(())
    }

    #[test]
    fn snapshot_unknown_state_fails() -> Result<(), LedgerError> {
        let ledger = InMemoryExecutionLedger::new();
        assert_eq!(ledger.snapshot(StateId(1)), Err(LedgerError::UnknownState));
        Ok(())
    }

    #[test]
    fn begin_unknown_state_fails() -> Result<(), LedgerError> {
        let ledger = InMemoryExecutionLedger::new();
        let base = snapshot(1);
        let result = ledger.begin(&base);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, LedgerError::UnknownState);
        }
        Ok(())
    }

    #[test]
    fn commit_with_wrong_state_fails() -> Result<(), LedgerError> {
        let ledger = InMemoryExecutionLedger::new();
        let base = snapshot(1);
        ledger.register(base.clone())?;
        let tx = ledger.begin(&base)?;
        let mut bad = mutation(1);
        bad.state = StateId(2);
        assert_eq!(ledger.commit(tx, bad), Err(LedgerError::Conflict));
        assert_eq!(ledger.snapshot(StateId(1))?, base);
        Ok(())
    }

    #[test]
    fn begin_with_stale_code_version_fails() -> Result<(), LedgerError> {
        let ledger = InMemoryExecutionLedger::new();
        let base = snapshot(1);
        ledger.register(base.clone())?;
        let mut drifted = base;
        drifted.code_versions = vec![CodeVersionGuard {
            page: CodePageId(1),
            version: CodePageVersion(7),
        }];
        let result = ledger.begin(&drifted);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, LedgerError::StaleCodeVersion);
        }
        Ok(())
    }

    #[test]
    fn begin_with_semantic_version_mismatch_fails() -> Result<(), LedgerError> {
        let ledger = InMemoryExecutionLedger::new();
        let base = snapshot(1);
        ledger.register(base.clone())?;
        let mut drifted = base;
        drifted.semantic_version = SemanticVersion(99);
        let result = ledger.begin(&drifted);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, LedgerError::SemanticVersionMismatch);
        }
        Ok(())
    }

    #[test]
    fn begin_with_semantic_content_mismatch_fails() -> Result<(), LedgerError> {
        let ledger = InMemoryExecutionLedger::new();
        let base = snapshot(1);
        ledger.register(base.clone())?;
        let mut drifted = base;
        drifted.semantic_content = content(77);
        let result = ledger.begin(&drifted);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, LedgerError::SemanticContentMismatch);
        }
        Ok(())
    }

    #[test]
    fn begin_with_replay_mismatch_fails() -> Result<(), LedgerError> {
        let ledger = InMemoryExecutionLedger::new();
        let base = snapshot(1);
        ledger.register(base.clone())?;
        let mut drifted = base;
        drifted.replay = Some(ReplayCapsuleId(42));
        let result = ledger.begin(&drifted);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, LedgerError::ReplayMismatch);
        }
        Ok(())
    }

    #[test]
    fn commit_with_provenance_to_less_than_from_fails() -> Result<(), LedgerError> {
        let ledger = InMemoryExecutionLedger::new();
        let base = snapshot(1);
        ledger.register(base.clone())?;

        // First commit advances provenance to 4 so a subsequent mutation can
        // legitimately reference it as `provenance_from`.
        let tx = ledger.begin(&base)?;
        let first = mutation(1);
        ledger.commit(tx, first)?;

        let refreshed = ledger.snapshot(StateId(1))?;
        let tx2 = ledger.begin(&refreshed)?;
        let mut bad = mutation(1);
        bad.provenance_from = ProvenanceSeq(4);
        bad.provenance_to = ProvenanceSeq(2);
        assert_eq!(ledger.commit(tx2, bad), Err(LedgerError::ProvenanceGap));
        assert_eq!(ledger.snapshot(StateId(1))?, refreshed);
        Ok(())
    }

    #[test]
    fn abort_does_not_modify_state() -> Result<(), LedgerError> {
        let ledger = InMemoryExecutionLedger::new();
        let base = snapshot(1);
        ledger.register(base.clone())?;
        let tx = ledger.begin(&base)?;
        ledger.abort(tx);
        assert_eq!(ledger.snapshot(StateId(1))?, base);
        Ok(())
    }

    #[test]
    fn multiple_commits_increment_epoch() -> Result<(), LedgerError> {
        let ledger = InMemoryExecutionLedger::new();
        let base = snapshot(1);
        ledger.register(base.clone())?;

        let tx = ledger.begin(&base)?;
        let first = ledger.commit(tx, mutation(1))?;
        assert_eq!(first.epoch, LedgerEpoch(1));

        let tx = ledger.begin(&first)?;
        let mut second_mutation = mutation(1);
        second_mutation.provenance_from = first.provenance;
        let second = ledger.commit(tx, second_mutation)?;
        assert_eq!(second.epoch, LedgerEpoch(2));
        assert_eq!(ledger.snapshot(StateId(1))?, second);
        Ok(())
    }

    #[test]
    fn concurrent_commits_to_same_state_one_wins() -> Result<(), LedgerError> {
        let ledger = Arc::new(InMemoryExecutionLedger::new());
        let base = snapshot(1);
        ledger.register(base.clone())?;

        // Both transactions begin from the same base snapshot before either commits.
        let tx_a = ledger.begin(&base)?;
        let tx_b = ledger.begin(&base)?;

        let ledger_a = Arc::clone(&ledger);
        let handle =
            thread::spawn(move || -> Result<LedgerSnapshot, LedgerError> { ledger_a.commit(tx_a, mutation(1)) });

        let winner = handle.join().map_err(|_| LedgerError::Conflict)??;
        assert_eq!(winner.epoch, LedgerEpoch(1));

        // The second transaction must observe a stale epoch and fail closed.
        assert_eq!(ledger.commit(tx_b, mutation(1)), Err(LedgerError::StaleEpoch));
        assert_eq!(ledger.snapshot(StateId(1))?, winner);
        Ok(())
    }

    #[test]
    fn ledger_error_display_is_non_empty() {
        let errors = [
            LedgerError::UnknownState,
            LedgerError::DuplicateState,
            LedgerError::StaleEpoch,
            LedgerError::StaleCodeVersion,
            LedgerError::SemanticVersionMismatch,
            LedgerError::SemanticContentMismatch,
            LedgerError::ProvenanceGap,
            LedgerError::ReplayMismatch,
            LedgerError::Conflict,
            LedgerError::Poisoned,
        ];
        for error in errors {
            assert!(!error.to_string().is_empty());
        }
    }

    #[test]
    fn register_and_snapshot_roundtrip() -> Result<(), LedgerError> {
        let ledger = InMemoryExecutionLedger::new();
        let base = snapshot(1);
        ledger.register(base.clone())?;
        let observed = ledger.snapshot(StateId(1))?;
        assert_eq!(observed, base);
        Ok(())
    }
}
