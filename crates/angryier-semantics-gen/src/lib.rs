#![forbid(unsafe_code)]

use std::fmt;
use std::sync::Mutex;

use angryier_types::{ContentDomain, ContentId, ContentIdentitySchemaVersion, SemanticRuleId, SemanticVersion};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DefinitionOrigin {
    Declarative,
    RustCombinator,
    HandwrittenOverride,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GeneratedRule {
    pub rule: SemanticRuleId,
    pub version: SemanticVersion,
    pub origin: DefinitionOrigin,
    pub generated_source: Vec<u8>,
    pub content: ContentId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageEntry {
    pub form_id: u32,
    pub supported: bool,
    pub origin: Option<DefinitionOrigin>,
}

pub trait SemanticsCompiler: Send + Sync {
    type Error;
    fn compile(&self, definition: &[u8]) -> Result<GeneratedRule, Self::Error>;
    fn coverage_manifest(&self) -> Result<Vec<CoverageEntry>, Self::Error>;
}

/// Errors emitted by [`InMemorySemanticsCompiler`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SemanticsGenError {
    /// The supplied definition was empty.
    EmptyDefinition,
    /// The origin tag byte did not map to a known [`DefinitionOrigin`].
    InvalidOrigin,
    /// The internal state mutex was poisoned by a panicking thread.
    Poisoned,
    /// A rule for the same `form_id` has already been compiled.
    DuplicateForm,
}

impl fmt::Display for SemanticsGenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyDefinition => f.write_str("semantic definition is empty"),
            Self::InvalidOrigin => f.write_str("semantic definition has an invalid origin tag"),
            Self::Poisoned => f.write_str("semantics compiler state is poisoned"),
            Self::DuplicateForm => f.write_str("semantic form_id has already been compiled"),
        }
    }
}

impl std::error::Error for SemanticsGenError {}

/// In-memory implementation of [`SemanticsCompiler`].
///
/// Stores compiled rules and coverage entries behind a [`Mutex`] so the
/// compiler remains `Send + Sync`. The definition format is intentionally
/// trivial: the first byte selects the [`DefinitionOrigin`], the next four
/// little-endian bytes carry the `form_id`, and the remaining bytes become the
/// generated source for the rule.
pub struct InMemorySemanticsCompiler {
    rules: Mutex<Vec<GeneratedRule>>,
    coverage: Mutex<Vec<CoverageEntry>>,
}

impl InMemorySemanticsCompiler {
    /// Creates a fresh compiler with no compiled rules.
    pub fn new() -> Self {
        Self {
            rules: Mutex::new(Vec::new()),
            coverage: Mutex::new(Vec::new()),
        }
    }

    /// Returns the number of rules compiled so far.
    pub fn len(&self) -> usize {
        let guard = self.rules.lock().unwrap_or_else(|e| e.into_inner());
        guard.len()
    }

    /// Returns `true` if no rules have been compiled yet.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for InMemorySemanticsCompiler {
    fn default() -> Self {
        Self::new()
    }
}

impl SemanticsCompiler for InMemorySemanticsCompiler {
    type Error = SemanticsGenError;

    fn compile(&self, definition: &[u8]) -> Result<GeneratedRule, Self::Error> {
        if definition.is_empty() {
            return Err(SemanticsGenError::EmptyDefinition);
        }

        // A valid definition needs at least the origin tag and the form_id.
        if definition.len() < 5 {
            return Err(SemanticsGenError::EmptyDefinition);
        }

        let origin = match definition[0] {
            0 => DefinitionOrigin::Declarative,
            1 => DefinitionOrigin::RustCombinator,
            2 => DefinitionOrigin::HandwrittenOverride,
            _ => return Err(SemanticsGenError::InvalidOrigin),
        };

        let form_id = u32::from_le_bytes([definition[1], definition[2], definition[3], definition[4]]);

        let generated_source = definition[5..].to_vec();

        // Acquire both locks using the poison-recovery pattern so a panicked
        // peer thread never permanently corrupts the compiler state. The
        // coverage table is the source of truth for `form_id`s, so duplicate
        // detection only needs to consult it.
        let mut rules = self.rules.lock().unwrap_or_else(|e| e.into_inner());
        let mut coverage = self.coverage.lock().unwrap_or_else(|e| e.into_inner());

        if coverage.iter().any(|c| c.form_id == form_id) {
            return Err(SemanticsGenError::DuplicateForm);
        }

        // Rule ids are sequential starting at 1. `unwrap_or(0)` is a safe
        // fallback that can only trigger on a pathological usize->u64 overflow.
        let next_id = u64::try_from(rules.len())
            .ok()
            .and_then(|n| n.checked_add(1))
            .unwrap_or(0);
        let rule_id = SemanticRuleId(next_id);

        let content = ContentId::derive(
            ContentDomain::SemanticBlock,
            ContentIdentitySchemaVersion(1),
            &generated_source,
        );

        let rule = GeneratedRule {
            rule: rule_id,
            version: SemanticVersion(1),
            origin,
            generated_source: generated_source.clone(),
            content,
        };

        coverage.push(CoverageEntry {
            form_id,
            supported: true,
            origin: Some(origin),
        });
        rules.push(rule.clone());

        Ok(rule)
    }

    fn coverage_manifest(&self) -> Result<Vec<CoverageEntry>, Self::Error> {
        let coverage = self.coverage.lock().unwrap_or_else(|e| e.into_inner());
        let mut manifest = coverage.clone();
        manifest.sort_by_key(|c| c.form_id);
        Ok(manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a trivial definition: `[origin][form_id LE 4 bytes][source...]`.
    fn make_definition(origin: u8, form_id: u32, source: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(5 + source.len());
        bytes.push(origin);
        bytes.extend_from_slice(&form_id.to_le_bytes());
        bytes.extend_from_slice(source);
        bytes
    }

    #[test]
    fn compile_valid_declarative_definition_succeeds() {
        let compiler = InMemorySemanticsCompiler::new();
        let definition = make_definition(0, 1, b"decl-source");
        let result = compiler.compile(&definition);
        assert!(result.is_ok());
        if let Ok(rule) = result {
            assert_eq!(rule.origin, DefinitionOrigin::Declarative);
            assert_eq!(rule.generated_source, b"decl-source");
        }
    }

    #[test]
    fn compile_valid_rust_combinator_definition_succeeds() {
        let compiler = InMemorySemanticsCompiler::new();
        let definition = make_definition(1, 2, b"rust-source");
        let result = compiler.compile(&definition);
        assert!(result.is_ok());
        if let Ok(rule) = result {
            assert_eq!(rule.origin, DefinitionOrigin::RustCombinator);
        }
    }

    #[test]
    fn compile_valid_handwritten_override_definition_succeeds() {
        let compiler = InMemorySemanticsCompiler::new();
        let definition = make_definition(2, 3, b"hand-source");
        let result = compiler.compile(&definition);
        assert!(result.is_ok());
        if let Ok(rule) = result {
            assert_eq!(rule.origin, DefinitionOrigin::HandwrittenOverride);
        }
    }

    #[test]
    fn compile_empty_definition_fails() {
        let compiler = InMemorySemanticsCompiler::new();
        let result = compiler.compile(&[]);
        assert!(result.is_err());
        assert_eq!(result.err(), Some(SemanticsGenError::EmptyDefinition));
    }

    #[test]
    fn compile_invalid_origin_fails() {
        let compiler = InMemorySemanticsCompiler::new();
        let definition = make_definition(9, 1, b"bad-origin");
        let result = compiler.compile(&definition);
        assert!(result.is_err());
        assert_eq!(result.err(), Some(SemanticsGenError::InvalidOrigin));
    }

    #[test]
    fn compile_duplicate_form_id_fails() {
        let compiler = InMemorySemanticsCompiler::new();
        let first = make_definition(0, 7, b"first");
        let second = make_definition(1, 7, b"second");
        assert!(compiler.compile(&first).is_ok());
        let result = compiler.compile(&second);
        assert!(result.is_err());
        assert_eq!(result.err(), Some(SemanticsGenError::DuplicateForm));
    }

    #[test]
    fn coverage_manifest_returns_sorted_entries() {
        let compiler = InMemorySemanticsCompiler::new();
        assert!(compiler.compile(&make_definition(0, 30, b"a")).is_ok());
        assert!(compiler.compile(&make_definition(1, 10, b"b")).is_ok());
        assert!(compiler.compile(&make_definition(2, 20, b"c")).is_ok());

        let manifest_result = compiler.coverage_manifest();
        assert!(manifest_result.is_ok());
        if let Ok(manifest) = manifest_result {
            let ids: Vec<u32> = manifest.iter().map(|c| c.form_id).collect();
            assert_eq!(ids, vec![10, 20, 30]);
        }
    }

    #[test]
    fn coverage_manifest_includes_all_compiled_rules() {
        let compiler = InMemorySemanticsCompiler::new();
        assert!(compiler.compile(&make_definition(0, 1, b"a")).is_ok());
        assert!(compiler.compile(&make_definition(1, 2, b"b")).is_ok());
        assert!(compiler.compile(&make_definition(2, 3, b"c")).is_ok());

        let manifest_result = compiler.coverage_manifest();
        assert!(manifest_result.is_ok());
        if let Ok(manifest) = manifest_result {
            assert_eq!(manifest.len(), 3);
            assert!(manifest.iter().all(|c| c.supported));
        }
    }

    #[test]
    fn len_tracks_compilations() {
        let compiler = InMemorySemanticsCompiler::new();
        assert_eq!(compiler.len(), 0);
        assert!(compiler.is_empty());
        assert!(compiler.compile(&make_definition(0, 1, b"a")).is_ok());
        assert_eq!(compiler.len(), 1);
        assert!(compiler.compile(&make_definition(1, 2, b"b")).is_ok());
        assert_eq!(compiler.len(), 2);
    }

    #[test]
    fn generated_rule_has_correct_content_derived_from_source() {
        let compiler = InMemorySemanticsCompiler::new();
        let source = b"canonical-source";
        let definition = make_definition(0, 1, source);
        let result = compiler.compile(&definition);
        assert!(result.is_ok());

        let expected = ContentId::derive(ContentDomain::SemanticBlock, ContentIdentitySchemaVersion(1), source);
        if let Ok(rule) = result {
            assert_eq!(rule.content, expected);
        }
    }

    #[test]
    fn generated_rule_has_sequential_rule_ids() {
        let compiler = InMemorySemanticsCompiler::new();
        let r1 = compiler.compile(&make_definition(0, 1, b"a"));
        let r2 = compiler.compile(&make_definition(1, 2, b"b"));
        let r3 = compiler.compile(&make_definition(2, 3, b"c"));
        assert!(r1.is_ok());
        assert!(r2.is_ok());
        assert!(r3.is_ok());
        if let (Ok(a), Ok(b), Ok(c)) = (r1, r2, r3) {
            assert_eq!(a.rule, SemanticRuleId(1));
            assert_eq!(b.rule, SemanticRuleId(2));
            assert_eq!(c.rule, SemanticRuleId(3));
        }
    }

    #[test]
    fn duplicate_form_id_across_origins_still_rejected() {
        let compiler = InMemorySemanticsCompiler::new();
        assert!(compiler.compile(&make_definition(0, 5, b"decl")).is_ok());
        // Same form_id but different origin should still be rejected.
        let result = compiler.compile(&make_definition(2, 5, b"hand"));
        assert!(result.is_err());
        assert_eq!(result.err(), Some(SemanticsGenError::DuplicateForm));
    }

    #[test]
    fn definition_with_only_origin_tag_fails() {
        let compiler = InMemorySemanticsCompiler::new();
        // Only the origin byte, no form_id bytes.
        let result = compiler.compile(&[0u8]);
        assert!(result.is_err());
        assert_eq!(result.err(), Some(SemanticsGenError::EmptyDefinition));
    }

    #[test]
    fn error_display_is_human_readable() {
        assert_eq!(
            SemanticsGenError::EmptyDefinition.to_string(),
            "semantic definition is empty"
        );
        assert_eq!(
            SemanticsGenError::InvalidOrigin.to_string(),
            "semantic definition has an invalid origin tag"
        );
        assert_eq!(
            SemanticsGenError::Poisoned.to_string(),
            "semantics compiler state is poisoned"
        );
        assert_eq!(
            SemanticsGenError::DuplicateForm.to_string(),
            "semantic form_id has already been compiled"
        );
    }
}
