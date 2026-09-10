#![forbid(unsafe_code)]

use angryier_ir::IrBlockKey;
use angryier_types::{CodeVersionGuard, ContentId};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum JitTier { Interpreter, SpecializedCached, NativeTranslated }
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NativeIsolation { TrustedTranslatedInProcess, RestrictedWorker }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompiledBlockKey { pub source: IrBlockKey, pub semantic_content: ContentId, pub code_versions: Vec<CodeVersionGuard> }

pub trait JitCompiler: Send + Sync { type Artifact; type Error; fn compile(&self, key: &CompiledBlockKey, tier: JitTier) -> Result<Self::Artifact, Self::Error>; }
pub trait JitValidity: Send + Sync { fn valid(&self, key: &CompiledBlockKey) -> bool; }
