#![forbid(unsafe_code)]

use angryier_types::{AnalysisContext, ContentId, DependencyKey, StateId, WorkUnitId};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkEnvelope {
    pub work: WorkUnitId,
    pub context: AnalysisContext,
    pub state: StateId,
    pub semantic_content: ContentId,
    pub validity: Vec<DependencyKey>,
    pub payload: Vec<u8>,
}

pub trait WorkCodec: Send + Sync {
    type Error;
    fn encode(&self, work: &WorkEnvelope) -> Result<Vec<u8>, Self::Error>;
    fn decode(&self, bytes: &[u8]) -> Result<WorkEnvelope, Self::Error>;
}
