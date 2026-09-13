#![forbid(unsafe_code)]

//! KEYSTONE indexing and ingestion adapter contracts plus a default
//! in-memory backend suitable for tests, single-process replays, and
//! reference implementations.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Mutex;

use angryier_types::{AnalysisContext, ContentId, DependencyKey};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexRecord {
    pub context: AnalysisContext,
    pub artifact: ContentId,
    pub dependency: DependencyKey,
    pub fields: Vec<(&'static str, Vec<u8>)>,
}

pub trait KeystoneAdapter: Send + Sync {
    type Error;
    fn enqueue_index(&self, record: IndexRecord) -> Result<(), Self::Error>;
    fn lookup(&self, context: AnalysisContext, query: &[u8], limit: usize) -> Result<Vec<ContentId>, Self::Error>;
}

/// Errors emitted by [`InMemoryKeystoneAdapter`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KeystoneError {
    /// The internal lock was poisoned by a panicking thread.
    Poisoned,
    /// An index record carried no fields to index.
    EmptyFields,
    /// An artifact was already indexed for the given context.
    DuplicateArtifact,
    /// A lookup requested a zero-sized result window.
    LimitIsZero,
}

impl fmt::Display for KeystoneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Poisoned => write!(f, "keystone lock was poisoned"),
            Self::EmptyFields => write!(f, "index record contained no fields"),
            Self::DuplicateArtifact => write!(f, "artifact already indexed for this context"),
            Self::LimitIsZero => write!(f, "lookup limit must be greater than zero"),
        }
    }
}

impl std::error::Error for KeystoneError {}

/// Internal mutable state guarded by the adapter's [`Mutex`].
#[derive(Default)]
struct Inner {
    /// Records keyed by `(AnalysisContext, ContentId)` for exact lookup and
    /// duplicate detection.
    records: BTreeMap<(AnalysisContext, ContentId), IndexRecord>,
    /// Simple inverted index mapping `(field name, field value)` to the set
    /// of artifacts that carry that exact field value.
    inverted: BTreeMap<(&'static str, Vec<u8>), BTreeSet<ContentId>>,
}

/// A purely in-memory [`KeystoneAdapter`] backed by a [`Mutex`]-guarded
/// [`BTreeMap`] and a small inverted index.
///
/// This implementation is deterministic and thread-safe but makes no
/// persistence guarantees; it is intended for tests, reference behavior, and
/// single-process replay harnesses.
pub struct InMemoryKeystoneAdapter {
    inner: Mutex<Inner>,
}

impl InMemoryKeystoneAdapter {
    /// Create an empty adapter.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
        }
    }

    /// Number of records currently indexed across all contexts.
    pub fn len(&self) -> usize {
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        guard.records.len()
    }

    /// `true` if no records are currently indexed.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for InMemoryKeystoneAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl KeystoneAdapter for InMemoryKeystoneAdapter {
    type Error = KeystoneError;

    fn enqueue_index(&self, record: IndexRecord) -> Result<(), Self::Error> {
        if record.fields.is_empty() {
            return Err(KeystoneError::EmptyFields);
        }
        let mut guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let key = (record.context, record.artifact);
        if guard.records.contains_key(&key) {
            return Err(KeystoneError::DuplicateArtifact);
        }
        // Update the inverted index before inserting the record so that a
        // duplicate key (impossible here, but defensive) never leaves the
        // index half-populated.
        for (name, value) in &record.fields {
            guard
                .inverted
                .entry((*name, value.clone()))
                .or_default()
                .insert(record.artifact);
        }
        guard.records.insert(key, record);
        Ok(())
    }

    fn lookup(&self, context: AnalysisContext, query: &[u8], limit: usize) -> Result<Vec<ContentId>, Self::Error> {
        if limit == 0 {
            return Err(KeystoneError::LimitIsZero);
        }
        let guard = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        // An empty query is treated as matching nothing. This keeps the
        // operation total and avoids the `windows(0)` panic.
        if query.is_empty() {
            return Ok(Vec::new());
        }

        // Walk the inverted index: any field value that contains the query as
        // a substring contributes its artifact set. BTreeSet deduplicates and
        // sorts candidates for deterministic output.
        let mut candidates: BTreeSet<ContentId> = BTreeSet::new();
        for ((_name, value), ids) in &guard.inverted {
            if value.windows(query.len()).any(|window| window == query) {
                candidates.extend(ids.iter().copied());
            }
        }

        // Restrict to artifacts actually indexed under the requested context.
        let mut results: Vec<ContentId> = candidates
            .into_iter()
            .filter(|id| guard.records.contains_key(&(context, *id)))
            .collect();
        results.truncate(limit);
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_types::{DependencyKey, FidelityProfile, RetentionProfile, RunId, SecurityContext, TargetProfileId};

    fn ctx(run: u64) -> AnalysisContext {
        AnalysisContext {
            run_id: RunId(run),
            target_profile: TargetProfileId(1),
            fidelity: FidelityProfile::Prove,
            retention: RetentionProfile::Forensic,
            security: SecurityContext {
                classification: 0,
                compartment: 0,
            },
        }
    }

    fn content_id(n: u8) -> ContentId {
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        ContentId(bytes)
    }

    fn dep_key(n: u8) -> DependencyKey {
        let mut bytes = [0u8; 32];
        bytes[0] = n;
        DependencyKey(bytes)
    }

    fn record(run: u64, artifact: u8, fields: Vec<(&'static str, Vec<u8>)>) -> IndexRecord {
        IndexRecord {
            context: ctx(run),
            artifact: content_id(artifact),
            dependency: dep_key(artifact),
            fields,
        }
    }

    #[test]
    fn enqueue_valid_record_succeeds() {
        let adapter = InMemoryKeystoneAdapter::new();
        let result = adapter.enqueue_index(record(1, 1, vec![("tag", b"hello".to_vec())]));
        assert!(result.is_ok());
        assert_eq!(adapter.len(), 1);
    }

    #[test]
    fn enqueue_record_with_empty_fields_fails() {
        let adapter = InMemoryKeystoneAdapter::new();
        let result = adapter.enqueue_index(record(1, 1, Vec::new()));
        assert_eq!(result, Err(KeystoneError::EmptyFields));
        assert_eq!(adapter.len(), 0);
    }

    #[test]
    fn enqueue_duplicate_artifact_fails() {
        let adapter = InMemoryKeystoneAdapter::new();
        let first = record(1, 1, vec![("tag", b"hello".to_vec())]);
        let second = record(1, 1, vec![("tag", b"world".to_vec())]);
        assert!(adapter.enqueue_index(first).is_ok());
        let result = adapter.enqueue_index(second);
        assert_eq!(result, Err(KeystoneError::DuplicateArtifact));
        assert_eq!(adapter.len(), 1);
    }

    #[test]
    fn enqueue_same_artifact_under_different_context_succeeds() {
        let adapter = InMemoryKeystoneAdapter::new();
        assert!(
            adapter
                .enqueue_index(record(1, 1, vec![("tag", b"hello".to_vec())]))
                .is_ok()
        );
        assert!(
            adapter
                .enqueue_index(record(2, 1, vec![("tag", b"hello".to_vec())]))
                .is_ok()
        );
        assert_eq!(adapter.len(), 2);
    }

    #[test]
    fn lookup_with_matching_query_returns_results() {
        let adapter = InMemoryKeystoneAdapter::new();
        assert!(
            adapter
                .enqueue_index(record(1, 7, vec![("tag", b"hello world".to_vec())]))
                .is_ok()
        );
        assert_eq!(adapter.lookup(ctx(1), b"hello", 10), Ok(vec![content_id(7)]));
    }

    #[test]
    fn lookup_with_non_matching_query_returns_empty() {
        let adapter = InMemoryKeystoneAdapter::new();
        assert!(
            adapter
                .enqueue_index(record(1, 7, vec![("tag", b"hello world".to_vec())]))
                .is_ok()
        );
        assert_eq!(adapter.lookup(ctx(1), b"goodbye", 10), Ok(Vec::new()));
    }

    #[test]
    fn lookup_with_limit_zero_fails() {
        let adapter = InMemoryKeystoneAdapter::new();
        assert!(
            adapter
                .enqueue_index(record(1, 7, vec![("tag", b"hello".to_vec())]))
                .is_ok()
        );
        let result = adapter.lookup(ctx(1), b"hello", 0);
        assert_eq!(result, Err(KeystoneError::LimitIsZero));
    }

    #[test]
    fn lookup_respects_limit() {
        let adapter = InMemoryKeystoneAdapter::new();
        for n in 1u8..=5u8 {
            assert!(
                adapter
                    .enqueue_index(record(1, n, vec![("tag", b"shared-token".to_vec())]))
                    .is_ok()
            );
        }
        // Results are sorted for determinism; the two smallest ids come first.
        assert_eq!(
            adapter.lookup(ctx(1), b"shared", 2),
            Ok(vec![content_id(1), content_id(2)])
        );
    }

    #[test]
    fn lookup_with_different_context_returns_empty() {
        let adapter = InMemoryKeystoneAdapter::new();
        assert!(
            adapter
                .enqueue_index(record(1, 7, vec![("tag", b"hello world".to_vec())]))
                .is_ok()
        );
        assert_eq!(adapter.lookup(ctx(2), b"hello", 10), Ok(Vec::new()));
    }

    #[test]
    fn lookup_matches_substring_within_field_values() {
        let adapter = InMemoryKeystoneAdapter::new();
        assert!(
            adapter
                .enqueue_index(record(1, 9, vec![("path", b"/usr/local/bin/tool".to_vec())]))
                .is_ok()
        );
        assert_eq!(adapter.lookup(ctx(1), b"local/bin", 10), Ok(vec![content_id(9)]));
    }

    #[test]
    fn len_tracks_enqueued_records() {
        let adapter = InMemoryKeystoneAdapter::new();
        assert_eq!(adapter.len(), 0);
        assert!(adapter.is_empty());
        assert!(
            adapter
                .enqueue_index(record(1, 1, vec![("tag", b"a".to_vec())]))
                .is_ok()
        );
        assert_eq!(adapter.len(), 1);
        assert!(!adapter.is_empty());
        assert!(
            adapter
                .enqueue_index(record(1, 2, vec![("tag", b"b".to_vec())]))
                .is_ok()
        );
        assert_eq!(adapter.len(), 2);
        assert!(
            adapter
                .enqueue_index(record(2, 1, vec![("tag", b"c".to_vec())]))
                .is_ok()
        );
        assert_eq!(adapter.len(), 3);
    }

    #[test]
    fn lookup_deduplicates_across_multiple_matching_fields() {
        let adapter = InMemoryKeystoneAdapter::new();
        assert!(
            adapter
                .enqueue_index(record(
                    1,
                    4,
                    vec![("tag", b"needle".to_vec()), ("other", b"also-needle-here".to_vec()),],
                ))
                .is_ok()
        );
        assert_eq!(adapter.lookup(ctx(1), b"needle", 10), Ok(vec![content_id(4)]));
    }

    #[test]
    fn keystone_error_implements_display_and_error() {
        fn render<E: std::error::Error>(err: E) -> String {
            err.to_string()
        }
        assert_eq!(render(KeystoneError::EmptyFields), "index record contained no fields");
        assert_eq!(
            render(KeystoneError::DuplicateArtifact),
            "artifact already indexed for this context"
        );
        assert_eq!(
            render(KeystoneError::LimitIsZero),
            "lookup limit must be greater than zero"
        );
        assert_eq!(render(KeystoneError::Poisoned), "keystone lock was poisoned");
    }
}
