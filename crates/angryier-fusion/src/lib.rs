#![forbid(unsafe_code)]

use angryier_types::{ContentId, EmbeddingModelVersion, EmbeddingSchemaVersion};
use std::fmt;
use std::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Modality {
    SemanticIr,
    CfgPath,
    ConstraintDag,
    TaintFlow,
    MemoryBehavior,
    SolverProfile,
    DynamicBehavior,
    FidelityProvenance,
    FindingContext,
    AnalystAnnotation,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ModalityVector {
    pub modality: Modality,
    pub values: Vec<f32>,
    pub masked: bool,
}

#[derive(Clone, Debug, PartialEq)]
pub struct FusedEmbedding {
    pub artifact: ContentId,
    pub model: EmbeddingModelVersion,
    pub schema: EmbeddingSchemaVersion,
    pub values: Vec<f32>,
    pub contributions: Vec<(Modality, f32)>,
}

pub trait SpecialistEncoder: Send + Sync {
    type Input;
    fn modality(&self) -> Modality;
    fn encode(&self, input: &Self::Input) -> ModalityVector;
}
pub trait FusionModel: Send + Sync {
    type Error;
    fn fuse(&self, artifact: ContentId, modalities: &[ModalityVector]) -> Result<FusedEmbedding, Self::Error>;
}

/// Errors that can arise during fusion of modality vectors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FusionError {
    /// No modality vectors were supplied.
    NoModalities,
    /// Every supplied modality vector was masked.
    AllMasked,
    /// Non-masked modality vectors disagreed on dimensionality.
    DimensionMismatch,
    /// The fusion state was poisoned by a prior panic.
    Poisoned,
}

impl fmt::Display for FusionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoModalities => f.write_str("no modality vectors were supplied"),
            Self::AllMasked => f.write_str("all modality vectors were masked"),
            Self::DimensionMismatch => f.write_str("non-masked modality vectors have mismatched dimensions"),
            Self::Poisoned => f.write_str("fusion state was poisoned"),
        }
    }
}

impl std::error::Error for FusionError {}

/// A specialist encoder that passes its input through unchanged.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IdentityEncoder;

impl SpecialistEncoder for IdentityEncoder {
    type Input = Vec<f32>;

    fn modality(&self) -> Modality {
        Modality::SemanticIr
    }

    fn encode(&self, input: &Self::Input) -> ModalityVector {
        ModalityVector {
            modality: self.modality(),
            values: input.clone(),
            masked: false,
        }
    }
}

/// A specialist encoder that emits a single constant value as a one-element vector.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConstantEncoder;

impl SpecialistEncoder for ConstantEncoder {
    type Input = f32;

    fn modality(&self) -> Modality {
        Modality::CfgPath
    }

    fn encode(&self, input: &Self::Input) -> ModalityVector {
        ModalityVector {
            modality: self.modality(),
            values: vec![*input],
            masked: false,
        }
    }
}

/// An in-memory `FusionModel` that averages non-masked modality vectors.
#[derive(Debug)]
pub struct InMemoryFusionModel {
    model: EmbeddingModelVersion,
    schema: EmbeddingSchemaVersion,
    last_result: Mutex<Option<FusedEmbedding>>,
}

impl InMemoryFusionModel {
    /// Construct a new in-memory fusion model with the given model and schema versions.
    pub fn new(model: EmbeddingModelVersion, schema: EmbeddingSchemaVersion) -> Self {
        Self {
            model,
            schema,
            last_result: Mutex::new(None),
        }
    }

    /// Returns a snapshot of the most recently fused embedding, if any.
    pub fn last_result(&self) -> Option<FusedEmbedding> {
        let guard = self.last_result.lock().unwrap_or_else(|e| e.into_inner());
        guard.clone()
    }
}

impl FusionModel for InMemoryFusionModel {
    type Error = FusionError;

    fn fuse(&self, artifact: ContentId, modalities: &[ModalityVector]) -> Result<FusedEmbedding, Self::Error> {
        if modalities.is_empty() {
            return Err(FusionError::NoModalities);
        }

        // Collect the non-masked vectors we will actually fuse.
        let active: Vec<&ModalityVector> = modalities.iter().filter(|m| !m.masked).collect();
        if active.is_empty() {
            return Err(FusionError::AllMasked);
        }

        // Validate that all active vectors share the same dimensionality.
        let dim = active[0].values.len();
        if active.iter().any(|m| m.values.len() != dim) {
            return Err(FusionError::DimensionMismatch);
        }

        let count = active.len() as f32;
        let weight = 1.0 / count;

        // Element-wise average across active vectors.
        let mut summed = vec![0.0_f32; dim];
        for mv in &active {
            for (i, v) in mv.values.iter().enumerate() {
                summed[i] += *v;
            }
        }
        let values: Vec<f32> = summed.iter().map(|v| v / count).collect();

        // Record contributions for each contributing modality.
        let contributions: Vec<(Modality, f32)> = active.iter().map(|mv| (mv.modality, weight)).collect();

        let fused = FusedEmbedding {
            artifact,
            model: self.model,
            schema: self.schema,
            values,
            contributions,
        };

        let mut guard = self.last_result.lock().unwrap_or_else(|e| e.into_inner());
        *guard = Some(fused.clone());

        Ok(fused)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn content_id(n: u8) -> ContentId {
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        ContentId(bytes)
    }

    fn new_model() -> InMemoryFusionModel {
        InMemoryFusionModel::new(EmbeddingModelVersion(1), EmbeddingSchemaVersion(1))
    }

    #[test]
    fn identity_encoder_returns_semantic_ir_modality() {
        let encoder = IdentityEncoder;
        assert_eq!(encoder.modality(), Modality::SemanticIr);
    }

    #[test]
    fn identity_encoder_passes_values_through_unchanged() {
        let encoder = IdentityEncoder;
        let input = vec![1.0, 2.0, 3.0];
        let mv = encoder.encode(&input);
        assert_eq!(mv.modality, Modality::SemanticIr);
        assert!(!mv.masked);
        assert_eq!(mv.values.len(), 3);
        for (a, b) in mv.values.iter().zip(input.iter()) {
            assert!((a - b).abs() < 1e-6);
        }
    }

    #[test]
    fn constant_encoder_returns_cfg_path_modality() {
        let encoder = ConstantEncoder;
        assert_eq!(encoder.modality(), Modality::CfgPath);
    }

    #[test]
    fn constant_encoder_produces_single_element_vector() {
        let encoder = ConstantEncoder;
        let mv = encoder.encode(&4.2);
        assert_eq!(mv.modality, Modality::CfgPath);
        assert!(!mv.masked);
        assert_eq!(mv.values.len(), 1);
        assert!((mv.values[0] - 4.2).abs() < 1e-6);
    }

    #[test]
    fn fuse_with_no_modalities_errors() {
        let model = new_model();
        let result = model.fuse(content_id(1), &[]);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, FusionError::NoModalities);
        }
    }

    #[test]
    fn fuse_with_all_masked_errors() {
        let model = new_model();
        let mv = ModalityVector {
            modality: Modality::SemanticIr,
            values: vec![1.0, 2.0],
            masked: true,
        };
        let result = model.fuse(content_id(1), &[mv]);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, FusionError::AllMasked);
        }
    }

    #[test]
    fn fuse_with_dimension_mismatch_errors() {
        let model = new_model();
        let a = ModalityVector {
            modality: Modality::SemanticIr,
            values: vec![1.0, 2.0],
            masked: false,
        };
        let b = ModalityVector {
            modality: Modality::CfgPath,
            values: vec![3.0, 4.0, 5.0],
            masked: false,
        };
        let result = model.fuse(content_id(1), &[a, b]);
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e, FusionError::DimensionMismatch);
        }
    }

    #[test]
    fn fuse_with_single_modality_returns_same_values() {
        let model = new_model();
        let mv = ModalityVector {
            modality: Modality::SemanticIr,
            values: vec![1.0, 2.0, 3.0],
            masked: false,
        };
        let result = model.fuse(content_id(7), &[mv]);
        assert!(result.is_ok());
        if let Ok(fused) = result {
            assert_eq!(fused.values.len(), 3);
            for (a, b) in fused.values.iter().zip(&[1.0_f32, 2.0, 3.0]) {
                assert!((a - b).abs() < 1e-6);
            }
        }
    }

    #[test]
    fn fuse_with_two_modalities_averages_correctly() {
        let model = new_model();
        let a = ModalityVector {
            modality: Modality::SemanticIr,
            values: vec![0.0, 2.0, 4.0],
            masked: false,
        };
        let b = ModalityVector {
            modality: Modality::CfgPath,
            values: vec![2.0, 4.0, 6.0],
            masked: false,
        };
        let result = model.fuse(content_id(3), &[a, b]);
        assert!(result.is_ok());
        if let Ok(fused) = result {
            let expected = [1.0_f32, 3.0, 5.0];
            for (a, b) in fused.values.iter().zip(expected.iter()) {
                assert!((a - b).abs() < 1e-6);
            }
        }
    }

    #[test]
    fn fuse_contributions_are_recorded() {
        let model = new_model();
        let a = ModalityVector {
            modality: Modality::SemanticIr,
            values: vec![1.0],
            masked: false,
        };
        let b = ModalityVector {
            modality: Modality::CfgPath,
            values: vec![3.0],
            masked: false,
        };
        let result = model.fuse(content_id(1), &[a, b]);
        assert!(result.is_ok());
        if let Ok(fused) = result {
            assert_eq!(fused.contributions.len(), 2);
            let mut found_semantic = false;
            let mut found_cfg = false;
            for (m, w) in &fused.contributions {
                assert!((w - 0.5).abs() < 1e-6);
                match m {
                    Modality::SemanticIr => found_semantic = true,
                    Modality::CfgPath => found_cfg = true,
                    _ => {}
                }
            }
            assert!(found_semantic);
            assert!(found_cfg);
        }
    }

    #[test]
    fn fuse_with_mixed_masked_unmasked_uses_only_unmasked() {
        let model = new_model();
        let a = ModalityVector {
            modality: Modality::SemanticIr,
            values: vec![10.0, 20.0],
            masked: false,
        };
        let b = ModalityVector {
            modality: Modality::CfgPath,
            values: vec![0.0, 0.0],
            masked: true,
        };
        let result = model.fuse(content_id(2), &[a, b]);
        assert!(result.is_ok());
        if let Ok(fused) = result {
            // Only the unmasked vector contributes, so average == its values.
            for (a, b) in fused.values.iter().zip(&[10.0_f32, 20.0]) {
                assert!((a - b).abs() < 1e-6);
            }
            // Only one contribution recorded, with weight 1.0.
            assert_eq!(fused.contributions.len(), 1);
            assert_eq!(fused.contributions[0].0, Modality::SemanticIr);
            assert!((fused.contributions[0].1 - 1.0).abs() < 1e-6);
        }
    }

    #[test]
    fn fused_embedding_has_correct_model_and_schema_versions() {
        let model = InMemoryFusionModel::new(EmbeddingModelVersion(42), EmbeddingSchemaVersion(7));
        let mv = ModalityVector {
            modality: Modality::SemanticIr,
            values: vec![1.0],
            masked: false,
        };
        let result = model.fuse(content_id(1), &[mv]);
        assert!(result.is_ok());
        if let Ok(fused) = result {
            assert_eq!(fused.model, EmbeddingModelVersion(42));
            assert_eq!(fused.schema, EmbeddingSchemaVersion(7));
            assert_eq!(fused.artifact, content_id(1));
        }
    }

    #[test]
    fn last_result_is_stored_after_successful_fuse() {
        let model = new_model();
        assert!(model.last_result().is_none());
        let mv = ModalityVector {
            modality: Modality::SemanticIr,
            values: vec![5.0],
            masked: false,
        };
        let result = model.fuse(content_id(9), &[mv]);
        assert!(result.is_ok());
        let stored = model.last_result();
        assert!(stored.is_some());
        if let Some(stored) = stored {
            assert_eq!(stored.artifact, content_id(9));
            assert!((stored.values[0] - 5.0).abs() < 1e-6);
        }
    }

    #[test]
    fn fusion_error_implements_display_and_error() {
        let err = FusionError::NoModalities;
        let s = format!("{err}");
        assert!(!s.is_empty());
        // Verify it can be used as a std::error::Error.
        let _e: &dyn std::error::Error = &err;
    }
}
