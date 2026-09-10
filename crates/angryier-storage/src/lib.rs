#![forbid(unsafe_code)]

use angryier_types::{ContentId, RetentionProfile};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecordPriority {
    BestEffort,
    Structural,
    CorrectnessCritical,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalRecord {
    pub artifact: ContentId,
    pub priority: RecordPriority,
    pub bytes: Vec<u8>,
}

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
