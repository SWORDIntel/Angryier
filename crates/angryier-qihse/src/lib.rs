#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

use angryier_types::{AnalysisContext, ContentId, DependencyKey, SemanticFingerprint};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QihseWrite {
    pub context: AnalysisContext,
    pub artifact: ContentId,
    pub dependency: DependencyKey,
    pub payload: Vec<u8>,
}

pub trait QihseAdapter: Send + Sync {
    type Error;
    fn enqueue(&self, write: QihseWrite) -> Result<(), Self::Error>;
    fn fetch_exact(&self, context: AnalysisContext, artifact: ContentId) -> Result<Option<Vec<u8>>, Self::Error>;
    fn query_vector(
        &self,
        context: AnalysisContext,
        fingerprint: SemanticFingerprint,
        limit: usize,
    ) -> Result<Vec<ContentId>, Self::Error>;
}

/// Errors emitted by [`InMemoryQihseAdapter`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum QihseError {
    /// A lock was poisoned by a panicking thread.
    Poisoned,
    /// An enqueue was attempted with an empty payload.
    EmptyPayload,
    /// An enqueue was attempted for an artifact already stored for the same context.
    DuplicateArtifact,
    /// A vector query was attempted with a zero limit.
    LimitIsZero,
}

impl fmt::Display for QihseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Poisoned => f.write_str("qihse mutex was poisoned"),
            Self::EmptyPayload => f.write_str("qihse enqueue rejected an empty payload"),
            Self::DuplicateArtifact => f.write_str("qihse enqueue rejected a duplicate artifact"),
            Self::LimitIsZero => f.write_str("qihse vector query requires a non-zero limit"),
        }
    }
}

impl std::error::Error for QihseError {}

/// In-memory implementation of [`QihseAdapter`] intended for tests and ephemeral runs.
///
/// Writes are keyed by `(AnalysisContext, ContentId)` inside a [`HashMap`]. A secondary
/// map keyed by `(AnalysisContext, SemanticFingerprint)` records the artifacts that share
/// a given fingerprint, enabling `query_vector` to return candidate matches.
///
/// Note: `AnalysisContext` implements `Eq + Hash` but not `Ord`, so a `HashMap` is used
/// rather than a `BTreeMap` for the composite keys.
pub struct InMemoryQihseAdapter {
    writes: Mutex<HashMap<(AnalysisContext, ContentId), Vec<u8>>>,
    fingerprints: Mutex<HashMap<(AnalysisContext, SemanticFingerprint), Vec<ContentId>>>,
}

impl Default for InMemoryQihseAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryQihseAdapter {
    /// Creates an empty adapter.
    pub fn new() -> Self {
        Self {
            writes: Mutex::new(HashMap::new()),
            fingerprints: Mutex::new(HashMap::new()),
        }
    }

    /// Returns the number of writes currently stored.
    pub fn len(&self) -> usize {
        let guard = self.writes.lock().unwrap_or_else(|e| e.into_inner());
        guard.len()
    }

    /// Returns `true` when no writes are currently stored.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Derives a simple, deterministic 32-byte fingerprint from a payload.
    ///
    /// This is intentionally a lightweight fold over the bytes and is NOT a
    /// cryptographic hash; it exists only to populate the vector-query index.
    pub fn derive_fingerprint(payload: &[u8]) -> SemanticFingerprint {
        let mut out = [0u8; 32];
        for (idx, byte) in payload.iter().enumerate() {
            let slot = idx % 32;
            // Folding: rotate the existing slot, mix in the byte and its position.
            let mixed = out[slot]
                .wrapping_add(*byte)
                .wrapping_add((idx as u8).wrapping_mul(0x9E));
            out[slot] = mixed;
        }
        // Final diffusion pass so that short payloads still spread across slots.
        for slot in 0..32 {
            let prev = out[(slot + 31) % 32];
            let next = out[(slot + 1) % 32];
            out[slot] = out[slot].wrapping_add(prev).wrapping_mul(31).wrapping_add(next);
        }
        SemanticFingerprint(out)
    }
}

impl QihseAdapter for InMemoryQihseAdapter {
    type Error = QihseError;

    fn enqueue(&self, write: QihseWrite) -> Result<(), Self::Error> {
        if write.payload.is_empty() {
            return Err(Self::Error::EmptyPayload);
        }

        let key = (write.context, write.artifact);

        let mut writes = self.writes.lock().unwrap_or_else(|e| e.into_inner());
        if writes.contains_key(&key) {
            return Err(Self::Error::DuplicateArtifact);
        }

        let fingerprint = Self::derive_fingerprint(&write.payload);
        writes.insert(key, write.payload.clone());

        let mut fingerprints = self.fingerprints.lock().unwrap_or_else(|e| e.into_inner());
        fingerprints
            .entry((write.context, fingerprint))
            .or_default()
            .push(write.artifact);

        Ok(())
    }

    fn fetch_exact(&self, context: AnalysisContext, artifact: ContentId) -> Result<Option<Vec<u8>>, Self::Error> {
        let writes = self.writes.lock().unwrap_or_else(|e| e.into_inner());
        Ok(writes.get(&(context, artifact)).cloned())
    }

    fn query_vector(
        &self,
        context: AnalysisContext,
        fingerprint: SemanticFingerprint,
        limit: usize,
    ) -> Result<Vec<ContentId>, Self::Error> {
        if limit == 0 {
            return Err(Self::Error::LimitIsZero);
        }

        let fingerprints = self.fingerprints.lock().unwrap_or_else(|e| e.into_inner());
        let mut hits = fingerprints.get(&(context, fingerprint)).cloned().unwrap_or_default();
        hits.truncate(limit);
        Ok(hits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use angryier_types::{
        AnalysisContext, ContentDomain, ContentId, ContentIdentitySchemaVersion, DependencyKey, FidelityProfile,
        RetentionProfile, RunId, SecurityContext, TargetProfileId,
    };

    fn sample_context() -> AnalysisContext {
        AnalysisContext {
            run_id: RunId(1),
            target_profile: TargetProfileId(7),
            fidelity: FidelityProfile::Prove,
            retention: RetentionProfile::Forensic,
            security: SecurityContext {
                classification: 0,
                compartment: 0,
            },
        }
    }

    fn sample_artifact(seed: u8) -> ContentId {
        ContentId::derive(ContentDomain::SemanticBlock, ContentIdentitySchemaVersion(1), &[seed])
    }

    fn sample_dependency() -> DependencyKey {
        DependencyKey([0u8; 32])
    }

    fn make_write(context: AnalysisContext, artifact: ContentId, payload: &[u8]) -> QihseWrite {
        QihseWrite {
            context,
            artifact,
            dependency: sample_dependency(),
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn enqueue_valid_write_succeeds() {
        let adapter = InMemoryQihseAdapter::new();
        let write = make_write(sample_context(), sample_artifact(1), b"payload");
        let result = adapter.enqueue(write);
        assert!(result.is_ok());
        assert_eq!(adapter.len(), 1);
    }

    #[test]
    fn enqueue_empty_payload_fails() {
        let adapter = InMemoryQihseAdapter::new();
        let write = make_write(sample_context(), sample_artifact(1), b"");
        assert_eq!(adapter.enqueue(write), Err(QihseError::EmptyPayload));
        assert_eq!(adapter.len(), 0);
    }

    #[test]
    fn enqueue_duplicate_artifact_fails() {
        let adapter = InMemoryQihseAdapter::new();
        let context = sample_context();
        let artifact = sample_artifact(1);
        let first = make_write(context, artifact, b"first");
        let second = make_write(context, artifact, b"second");
        assert_eq!(adapter.enqueue(first), Ok(()));
        assert_eq!(adapter.enqueue(second), Err(QihseError::DuplicateArtifact));
        assert_eq!(adapter.len(), 1);
    }

    #[test]
    fn fetch_exact_returns_some_for_existing() {
        let adapter = InMemoryQihseAdapter::new();
        let context = sample_context();
        let artifact = sample_artifact(1);
        let payload = b"hello";
        assert_eq!(adapter.enqueue(make_write(context, artifact, payload)), Ok(()));

        assert_eq!(adapter.fetch_exact(context, artifact), Ok(Some(payload.to_vec())));
    }

    #[test]
    fn fetch_exact_returns_none_for_missing() {
        let adapter = InMemoryQihseAdapter::new();
        let context = sample_context();
        let artifact = sample_artifact(1);
        assert_eq!(adapter.fetch_exact(context, artifact), Ok(None));
    }

    #[test]
    fn fetch_exact_with_different_context_returns_none() {
        let adapter = InMemoryQihseAdapter::new();
        let context_a = sample_context();
        let mut context_b = context_a;
        context_b.run_id = RunId(99);
        let artifact = sample_artifact(1);
        assert_eq!(adapter.enqueue(make_write(context_a, artifact, b"payload")), Ok(()));

        assert_eq!(adapter.fetch_exact(context_b, artifact), Ok(None));
    }

    #[test]
    fn query_vector_returns_matching_artifacts() {
        let adapter = InMemoryQihseAdapter::new();
        let context = sample_context();
        let artifact = sample_artifact(1);
        let payload = b"shared semantics";
        assert_eq!(adapter.enqueue(make_write(context, artifact, payload)), Ok(()));

        let fingerprint = InMemoryQihseAdapter::derive_fingerprint(payload);
        assert_eq!(adapter.query_vector(context, fingerprint, 10), Ok(vec![artifact]));
    }

    #[test]
    fn query_vector_with_limit_zero_fails() {
        let adapter = InMemoryQihseAdapter::new();
        let context = sample_context();
        let fingerprint = SemanticFingerprint([0u8; 32]);
        assert_eq!(
            adapter.query_vector(context, fingerprint, 0),
            Err(QihseError::LimitIsZero)
        );
    }

    #[test]
    fn query_vector_with_no_matches_returns_empty() {
        let adapter = InMemoryQihseAdapter::new();
        let context = sample_context();
        let fingerprint = SemanticFingerprint([0u8; 32]);
        assert_eq!(adapter.query_vector(context, fingerprint, 5), Ok(Vec::new()));
    }

    #[test]
    fn query_vector_respects_limit() {
        let adapter = InMemoryQihseAdapter::new();
        let context = sample_context();
        let payload = b"shared semantics";
        let fingerprint = InMemoryQihseAdapter::derive_fingerprint(payload);

        for seed in 1..=4u8 {
            assert_eq!(
                adapter.enqueue(make_write(context, sample_artifact(seed), payload)),
                Ok(())
            );
        }

        let result = adapter.query_vector(context, fingerprint, 2);
        assert!(result.is_ok());
        assert_eq!(result.as_ref().ok().map(Vec::len), Some(2));
    }

    #[test]
    fn len_tracks_enqueued_writes() {
        let adapter = InMemoryQihseAdapter::new();
        assert_eq!(adapter.len(), 0);
        assert!(adapter.is_empty());

        let context = sample_context();
        for seed in 1..=3u8 {
            assert_eq!(
                adapter.enqueue(make_write(context, sample_artifact(seed), &[seed])),
                Ok(())
            );
        }
        assert_eq!(adapter.len(), 3);
        assert!(!adapter.is_empty());
    }

    #[test]
    fn derive_fingerprint_is_deterministic_and_payload_sensitive() {
        let a = InMemoryQihseAdapter::derive_fingerprint(b"abc");
        let b = InMemoryQihseAdapter::derive_fingerprint(b"abc");
        let c = InMemoryQihseAdapter::derive_fingerprint(b"abd");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn query_vector_is_context_scoped() {
        let adapter = InMemoryQihseAdapter::new();
        let context_a = sample_context();
        let mut context_b = context_a;
        context_b.run_id = RunId(42);
        let payload = b"shared semantics";
        let fingerprint = InMemoryQihseAdapter::derive_fingerprint(payload);

        assert_eq!(
            adapter.enqueue(make_write(context_a, sample_artifact(1), payload)),
            Ok(())
        );

        assert_eq!(adapter.query_vector(context_b, fingerprint, 10), Ok(Vec::new()));
    }

    #[test]
    fn qihse_error_display_is_human_readable() {
        assert_eq!(format!("{}", QihseError::Poisoned), "qihse mutex was poisoned");
        assert_eq!(
            format!("{}", QihseError::EmptyPayload),
            "qihse enqueue rejected an empty payload"
        );
        assert_eq!(
            format!("{}", QihseError::DuplicateArtifact),
            "qihse enqueue rejected a duplicate artifact"
        );
        assert_eq!(
            format!("{}", QihseError::LimitIsZero),
            "qihse vector query requires a non-zero limit"
        );
    }
}
