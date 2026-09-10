#![forbid(unsafe_code)]

use angryier_types::{AnalysisContext, ContentId, DependencyKey, SemanticFingerprint};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QihseWrite { pub context: AnalysisContext, pub artifact: ContentId, pub dependency: DependencyKey, pub payload: Vec<u8> }

pub trait QihseAdapter: Send + Sync { type Error; fn enqueue(&self, write: QihseWrite) -> Result<(), Self::Error>; fn fetch_exact(&self, context: AnalysisContext, artifact: ContentId) -> Result<Option<Vec<u8>>, Self::Error>; fn query_vector(&self, context: AnalysisContext, fingerprint: SemanticFingerprint, limit: usize) -> Result<Vec<ContentId>, Self::Error>; }
