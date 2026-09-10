#![forbid(unsafe_code)]

//! Top-level engine orchestration contracts. This crate coordinates subsystems but
//! must not own decoder, solver, database, or JIT implementation details.

pub use angryier_types::{AnalysisContext, FidelityProfile, RunId, TargetProfileId};
use angryier_types::{CodePageId, CodePageVersion, CodeVersionGuard};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EngineMode {
    Normal,
    DeterministicRecord,
    DeterministicReplay,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EngineConfig {
    pub mode: EngineMode,
    pub context: AnalysisContext,
}

pub trait EngineSubsystem: Send + Sync {
    fn name(&self) -> &'static str;
    fn ready(&self) -> bool;
}

pub trait EngineControl: Send + Sync {
    type Error;
    fn start(&self, config: EngineConfig) -> Result<(), Self::Error>;
    fn stop(&self) -> Result<(), Self::Error>;
}

/// Read-only view of executable code-page versions.
///
/// JIT, replay, and block-cache consumers depend on this contract rather than a
/// concrete memory implementation. Missing versions fail closed when checked by
/// `guards_match`.
pub trait CodeVersionSource: Send + Sync {
    fn code_page_version(&self, page: CodePageId) -> Option<CodePageVersion>;

    fn guards_match(&self, guards: &[CodeVersionGuard]) -> bool {
        guards
            .iter()
            .all(|guard| self.code_page_version(guard.page) == Some(guard.version))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct Versions(BTreeMap<CodePageId, CodePageVersion>);

    impl CodeVersionSource for Versions {
        fn code_page_version(&self, page: CodePageId) -> Option<CodePageVersion> {
            self.0.get(&page).copied()
        }
    }

    #[test]
    fn guard_matching_fails_closed_for_missing_or_stale_pages() {
        let source = Versions(BTreeMap::from([(CodePageId(1), CodePageVersion(4))]));

        assert!(source.guards_match(&[CodeVersionGuard {
            page: CodePageId(1),
            version: CodePageVersion(4),
        }]));
        assert!(!source.guards_match(&[CodeVersionGuard {
            page: CodePageId(1),
            version: CodePageVersion(3),
        }]));
        assert!(!source.guards_match(&[CodeVersionGuard {
            page: CodePageId(2),
            version: CodePageVersion(0),
        }]));
    }
}
