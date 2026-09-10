#![forbid(unsafe_code)]

use angryier_types::{ContentId, DependencyKey, KnowledgeSchemaVersion, SemanticFingerprint};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KnowledgeTrust { Authoritative, Advisory }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidityEnvelope { pub schema: KnowledgeSchemaVersion, pub dependencies: Vec<DependencyKey>, pub semantic_content: Option<ContentId> }

#[derive(Clone, Debug, PartialEq)]
pub struct SimilarityHit { pub artifact: ContentId, pub fingerprint: SemanticFingerprint, pub fused_score: f32, pub modality_scores: Vec<(&'static str, f32)>, pub exact_validated: bool }

pub trait DependencyGraph: Send + Sync { type Error; fn depend(&self, artifact: ContentId, on: DependencyKey) -> Result<(), Self::Error>; fn invalidate(&self, changed: DependencyKey) -> Result<Vec<ContentId>, Self::Error>; }

pub trait KnowledgeStore: Send + Sync { type Error; fn put_exact(&self, id: ContentId, validity: &ValidityEnvelope, bytes: &[u8]) -> Result<(), Self::Error>; fn get_exact(&self, id: ContentId, validity: &ValidityEnvelope) -> Result<Option<Vec<u8>>, Self::Error>; fn similar(&self, fingerprint: SemanticFingerprint, limit: usize) -> Result<Vec<SimilarityHit>, Self::Error>; }
