#![forbid(unsafe_code)]

use angryier_types::{ContentId, EmbeddingModelVersion, EmbeddingSchemaVersion};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Modality { SemanticIr, CfgPath, ConstraintDag, TaintFlow, MemoryBehavior, SolverProfile, DynamicBehavior, FidelityProvenance, FindingContext, AnalystAnnotation }

#[derive(Clone, Debug, PartialEq)]
pub struct ModalityVector { pub modality: Modality, pub values: Vec<f32>, pub masked: bool }

#[derive(Clone, Debug, PartialEq)]
pub struct FusedEmbedding { pub artifact: ContentId, pub model: EmbeddingModelVersion, pub schema: EmbeddingSchemaVersion, pub values: Vec<f32>, pub contributions: Vec<(Modality, f32)> }

pub trait SpecialistEncoder: Send + Sync { type Input; fn modality(&self) -> Modality; fn encode(&self, input: &Self::Input) -> ModalityVector; }
pub trait FusionModel: Send + Sync { type Error; fn fuse(&self, artifact: ContentId, modalities: &[ModalityVector]) -> Result<FusedEmbedding, Self::Error>; }
