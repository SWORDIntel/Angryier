#![forbid(unsafe_code)]

use angryier_types::{
    CodeVersionGuard, ContentId, LedgerEpoch, ProvenanceSeq, ReplayCapsuleId, SemanticVersion, StateId,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerSnapshot {
    pub epoch: LedgerEpoch,
    pub state: StateId,
    pub provenance: ProvenanceSeq,
    pub semantic_version: SemanticVersion,
    pub semantic_content: ContentId,
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
    StaleEpoch,
    StaleCodeVersion,
    SemanticVersionMismatch,
    SemanticContentMismatch,
    ProvenanceGap,
    ReplayMismatch,
    Conflict,
}

pub trait ExecutionLedger: Send + Sync {
    type Transaction;
    fn begin(&self, base: &LedgerSnapshot) -> Result<Self::Transaction, LedgerError>;
    fn commit(&self, tx: Self::Transaction, mutation: LedgerMutation) -> Result<LedgerSnapshot, LedgerError>;
    fn abort(&self, tx: Self::Transaction);
}
