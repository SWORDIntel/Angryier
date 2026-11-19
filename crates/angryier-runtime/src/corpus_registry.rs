//! Architecture-dispatched semantic registry.
//!
//! The runtime holds exactly one registry slot regardless of decoder backend.
//! This enum keeps that slot neutral: resolution and positional form lookup
//! delegate to whichever corpus is active, so the Intel 64 and AArch64 paths
//! share the same [`Runtime`](crate::Runtime) plumbing.

use angryier_semantics::{DecodedInstructionView, SemanticError, SemanticRegistry, SemanticResolution};
use angryier_semantics_arm64::Arm64CorpusRegistry;
use angryier_semantics_intel64::Intel64CorpusRegistry;
use angryier_types::SemanticVersion;
use std::sync::Arc;

/// The active semantic corpus, selected at construction time.
pub enum CorpusRegistry {
    /// Intel 64 handwritten corpus.
    Intel64(Intel64CorpusRegistry),
    /// AArch64 (A64) handwritten corpus.
    Arm64(Arm64CorpusRegistry),
}

impl CorpusRegistry {
    /// Returns the provider registered for `form_id` by positional form
    /// index, bypassing rule-id lookup (see
    /// `Intel64CorpusRegistry::provider_for_form`).
    pub fn provider_for_form(&self, form_id: u32) -> Option<Arc<dyn angryier_semantics::SemanticProvider>> {
        match self {
            CorpusRegistry::Intel64(inner) => inner.provider_for_form(form_id).cloned(),
            CorpusRegistry::Arm64(inner) => inner.provider_for(form_id),
        }
    }

    /// Installs the unsupported-form fallback provider for the active corpus.
    ///
    /// The fallback concept exists in the Intel 64 corpus (unmapped XED
    /// forms fall back to a conservative provider). The A64 corpus resolves
    /// strictly — unsupported forms fail explicitly — so the ARM64 arm is a
    /// documented no-op until ANG-090 defines an equivalent fallback.
    pub fn set_unsupported_fallback(&mut self, provider: Arc<dyn angryier_semantics::SemanticProvider>) {
        if let CorpusRegistry::Intel64(inner) = self {
            inner.set_unsupported_fallback(provider);
        }
    }

    /// Clears the unsupported-form fallback provider for the active corpus
    /// (no-op for the A64 corpus, which has no fallback slot).
    pub fn clear_unsupported_fallback(&mut self) {
        if let CorpusRegistry::Intel64(inner) = self {
            inner.clear_unsupported_fallback();
        }
    }
}

impl SemanticRegistry for CorpusRegistry {
    fn resolve(
        &self,
        insn: &dyn DecodedInstructionView,
        version: SemanticVersion,
    ) -> Result<SemanticResolution, SemanticError> {
        match self {
            CorpusRegistry::Intel64(inner) => inner.resolve(insn, version),
            CorpusRegistry::Arm64(inner) => inner.resolve(insn, version),
        }
    }
}
