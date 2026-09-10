#![forbid(unsafe_code)]

use angryier_types::{ContentId, SemanticRuleId, SemanticVersion};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DefinitionOrigin { Declarative, RustCombinator, HandwrittenOverride }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedRule { pub rule: SemanticRuleId, pub version: SemanticVersion, pub origin: DefinitionOrigin, pub generated_source: Vec<u8>, pub content: ContentId }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageEntry { pub form_id: u32, pub supported: bool, pub origin: Option<DefinitionOrigin> }

pub trait SemanticsCompiler: Send + Sync { type Error; fn compile(&self, definition: &[u8]) -> Result<GeneratedRule, Self::Error>; fn coverage_manifest(&self) -> Result<Vec<CoverageEntry>, Self::Error>; }
