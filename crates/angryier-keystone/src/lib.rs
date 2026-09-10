#![forbid(unsafe_code)]

use angryier_types::{AnalysisContext, ContentId, DependencyKey};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexRecord { pub context: AnalysisContext, pub artifact: ContentId, pub dependency: DependencyKey, pub fields: Vec<(&'static str, Vec<u8>)> }

pub trait KeystoneAdapter: Send + Sync { type Error; fn enqueue_index(&self, record: IndexRecord) -> Result<(), Self::Error>; fn lookup(&self, context: AnalysisContext, query: &[u8], limit: usize) -> Result<Vec<ContentId>, Self::Error>; }
