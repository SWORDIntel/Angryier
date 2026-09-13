#![forbid(unsafe_code)]

//! In-memory knowledge store with dependency graph and exact-match cache.
//!
//! The exact-match cache rejects retrieval unless the full validity envelope
//! (schema version, dependency set, and semantic content) matches the
//! envelope recorded at insertion time. Similarity search is intentionally
//! fail-closed at this phase: `similar` always returns an empty result.

use angryier_types::{ContentId, DependencyKey, KnowledgeSchemaVersion, SemanticFingerprint};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::RwLock;

// ---------------------------------------------------------------------------
// Contracts (preserved)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KnowledgeTrust {
    Authoritative,
    Advisory,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidityEnvelope {
    pub schema: KnowledgeSchemaVersion,
    pub dependencies: Vec<DependencyKey>,
    pub semantic_content: Option<ContentId>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SimilarityHit {
    pub artifact: ContentId,
    pub fingerprint: SemanticFingerprint,
    pub fused_score: f32,
    pub modality_scores: Vec<(&'static str, f32)>,
    pub exact_validated: bool,
}

pub trait DependencyGraph: Send + Sync {
    type Error;
    fn depend(&self, artifact: ContentId, on: DependencyKey) -> Result<(), Self::Error>;
    fn invalidate(&self, changed: DependencyKey) -> Result<Vec<ContentId>, Self::Error>;
}

pub trait KnowledgeStore: Send + Sync {
    type Error;
    fn put_exact(&self, id: ContentId, validity: &ValidityEnvelope, bytes: &[u8]) -> Result<(), Self::Error>;
    fn get_exact(&self, id: ContentId, validity: &ValidityEnvelope) -> Result<Option<Vec<u8>>, Self::Error>;
    fn similar(&self, fingerprint: SemanticFingerprint, limit: usize) -> Result<Vec<SimilarityHit>, Self::Error>;
}

// ---------------------------------------------------------------------------
// Error model
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KnowledgeError {
    Poisoned,
    SchemaMismatch,
    DependencyMismatch,
    InvalidFingerprint,
    ArtifactNotFound,
    DuplicateArtifact,
}

impl core::fmt::Display for KnowledgeError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::Poisoned => "knowledge store synchronization primitive poisoned",
            Self::SchemaMismatch => "knowledge schema version mismatch",
            Self::DependencyMismatch => "knowledge dependency set mismatch",
            Self::InvalidFingerprint => "invalid semantic fingerprint",
            Self::ArtifactNotFound => "knowledge artifact not found",
            Self::DuplicateArtifact => "knowledge artifact already stored",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for KnowledgeError {}

// ---------------------------------------------------------------------------
// Validity envelope comparison
// ---------------------------------------------------------------------------

/// Returns true when two validity envelopes are exactly equivalent: same
/// schema version, same dependency keys in the same order, and matching
/// semantic content (both `None`, or both `Some` and equal).
fn envelopes_match(stored: &ValidityEnvelope, requested: &ValidityEnvelope) -> bool {
    if stored.schema != requested.schema {
        return false;
    }
    if stored.dependencies != requested.dependencies {
        return false;
    }
    stored.semantic_content == requested.semantic_content
}

// ---------------------------------------------------------------------------
// In-memory dependency graph
// ---------------------------------------------------------------------------

/// A thread-safe in-memory dependency graph.
///
/// Forward edges map a `DependencyKey` to the artifacts (`ContentId`s) that
/// depend on it. Reverse edges map an artifact to the dependency keys it
/// depends on. Transitive invalidation treats an invalidated artifact's
/// `ContentId` as a `DependencyKey` so that dependents-of-dependents are
/// reached.
pub struct InMemoryDependencyGraph {
    forward: RwLock<BTreeMap<DependencyKey, Vec<ContentId>>>,
    reverse: RwLock<BTreeMap<ContentId, Vec<DependencyKey>>>,
}

impl InMemoryDependencyGraph {
    pub fn new() -> Self {
        Self {
            forward: RwLock::new(BTreeMap::new()),
            reverse: RwLock::new(BTreeMap::new()),
        }
    }

    /// Adds a dependency edge from `artifact` to `on`. Duplicate edges are
    /// ignored (idempotent).
    pub fn depend(&self, artifact: ContentId, on: DependencyKey) -> Result<(), KnowledgeError> {
        {
            let mut reverse = self.reverse.write().map_err(|_| KnowledgeError::Poisoned)?;
            let entry = reverse.entry(artifact).or_default();
            if !entry.contains(&on) {
                entry.push(on);
            }
        }
        {
            let mut forward = self.forward.write().map_err(|_| KnowledgeError::Poisoned)?;
            let entry = forward.entry(on).or_default();
            if !entry.contains(&artifact) {
                entry.push(artifact);
            }
        }
        Ok(())
    }

    /// Returns all artifacts transitively depending on `changed`, in a
    /// deterministic (sorted) order with no duplicates.
    pub fn invalidate(&self, changed: DependencyKey) -> Result<Vec<ContentId>, KnowledgeError> {
        let forward = self.forward.read().map_err(|_| KnowledgeError::Poisoned)?;
        let mut visited: BTreeSet<ContentId> = BTreeSet::new();
        let mut queue: Vec<DependencyKey> = vec![changed];
        let mut result: Vec<ContentId> = Vec::new();
        while let Some(key) = queue.pop() {
            if let Some(dependents) = forward.get(&key) {
                for artifact in dependents {
                    if visited.insert(*artifact) {
                        result.push(*artifact);
                        // Treat the artifact's identity as a dependency key so
                        // that its own dependents are reached transitively.
                        queue.push(DependencyKey(artifact.0));
                    }
                }
            }
        }
        result.sort();
        Ok(result)
    }

    /// Returns the direct dependencies of `artifact`, in insertion order.
    pub fn dependencies_of(&self, artifact: ContentId) -> Result<Vec<DependencyKey>, KnowledgeError> {
        let reverse = self.reverse.read().map_err(|_| KnowledgeError::Poisoned)?;
        Ok(reverse.get(&artifact).cloned().unwrap_or_default())
    }

    /// Returns the direct dependents of `key`, in insertion order.
    pub fn dependents_of(&self, key: DependencyKey) -> Result<Vec<ContentId>, KnowledgeError> {
        let forward = self.forward.read().map_err(|_| KnowledgeError::Poisoned)?;
        Ok(forward.get(&key).cloned().unwrap_or_default())
    }
}

impl Default for InMemoryDependencyGraph {
    fn default() -> Self {
        Self::new()
    }
}

impl DependencyGraph for InMemoryDependencyGraph {
    type Error = KnowledgeError;
    fn depend(&self, artifact: ContentId, on: DependencyKey) -> Result<(), Self::Error> {
        Self::depend(self, artifact, on)
    }
    fn invalidate(&self, changed: DependencyKey) -> Result<Vec<ContentId>, Self::Error> {
        Self::invalidate(self, changed)
    }
}

// ---------------------------------------------------------------------------
// Knowledge entry (inspection)
// ---------------------------------------------------------------------------

/// A snapshot of a stored knowledge artifact, for testing and inspection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnowledgeEntry {
    pub id: ContentId,
    pub validity: ValidityEnvelope,
    pub bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// In-memory knowledge store
// ---------------------------------------------------------------------------

/// A thread-safe in-memory exact-match knowledge store.
///
/// Retrieval via `get_exact` succeeds only when the requested validity
/// envelope matches the stored envelope exactly. Similarity search is
/// fail-closed: `similar` always returns an empty vector at this phase.
pub struct InMemoryKnowledgeStore {
    entries: RwLock<BTreeMap<ContentId, (ValidityEnvelope, Vec<u8>)>>,
}

impl InMemoryKnowledgeStore {
    pub fn new() -> Self {
        Self {
            entries: RwLock::new(BTreeMap::new()),
        }
    }

    /// Stores `bytes` under `id` with the exact validity envelope. Rejects
    /// duplicates with `KnowledgeError::DuplicateArtifact`.
    pub fn put_exact(&self, id: ContentId, validity: &ValidityEnvelope, bytes: &[u8]) -> Result<(), KnowledgeError> {
        let mut entries = self.entries.write().map_err(|_| KnowledgeError::Poisoned)?;
        if entries.contains_key(&id) {
            return Err(KnowledgeError::DuplicateArtifact);
        }
        entries.insert(id, (validity.clone(), bytes.to_vec()));
        Ok(())
    }

    /// Retrieves the bytes for `id` only if the requested validity envelope
    /// matches the stored envelope exactly. Returns `Ok(None)` when the
    /// artifact is absent or the envelope does not match.
    pub fn get_exact(&self, id: ContentId, validity: &ValidityEnvelope) -> Result<Option<Vec<u8>>, KnowledgeError> {
        let entries = self.entries.read().map_err(|_| KnowledgeError::Poisoned)?;
        match entries.get(&id) {
            Some((stored, bytes)) if envelopes_match(stored, validity) => Ok(Some(bytes.clone())),
            _ => Ok(None),
        }
    }

    /// Fail-closed similarity search: always returns an empty vector at this
    /// phase. The `fingerprint` and `limit` arguments are accepted but not
    /// used, so callers must never treat an empty result as "no similar
    /// artifacts exist".
    pub fn similar(
        &self,
        _fingerprint: SemanticFingerprint,
        _limit: usize,
    ) -> Result<Vec<SimilarityHit>, KnowledgeError> {
        Ok(Vec::new())
    }

    pub fn len(&self) -> usize {
        match self.entries.read() {
            Ok(guard) => guard.len(),
            Err(_) => 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains(&self, id: ContentId) -> bool {
        match self.entries.read() {
            Ok(guard) => guard.contains_key(&id),
            Err(_) => false,
        }
    }

    /// Returns a snapshot of every stored entry, sorted by `ContentId`.
    /// Intended for testing and inspection.
    pub fn entries(&self) -> Result<Vec<KnowledgeEntry>, KnowledgeError> {
        let entries = self.entries.read().map_err(|_| KnowledgeError::Poisoned)?;
        Ok(entries
            .iter()
            .map(|(id, (validity, bytes))| KnowledgeEntry {
                id: *id,
                validity: validity.clone(),
                bytes: bytes.clone(),
            })
            .collect())
    }
}

impl Default for InMemoryKnowledgeStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KnowledgeStore for InMemoryKnowledgeStore {
    type Error = KnowledgeError;
    fn put_exact(&self, id: ContentId, validity: &ValidityEnvelope, bytes: &[u8]) -> Result<(), Self::Error> {
        Self::put_exact(self, id, validity, bytes)
    }
    fn get_exact(&self, id: ContentId, validity: &ValidityEnvelope) -> Result<Option<Vec<u8>>, Self::Error> {
        Self::get_exact(self, id, validity)
    }
    fn similar(&self, fingerprint: SemanticFingerprint, limit: usize) -> Result<Vec<SimilarityHit>, Self::Error> {
        Self::similar(self, fingerprint, limit)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    fn content(byte: u8) -> ContentId {
        ContentId([byte; 32])
    }

    fn dep(byte: u8) -> DependencyKey {
        DependencyKey([byte; 32])
    }

    fn envelope(schema: u64, deps: Vec<DependencyKey>, semantic: Option<u8>) -> ValidityEnvelope {
        ValidityEnvelope {
            schema: KnowledgeSchemaVersion(schema),
            dependencies: deps,
            semantic_content: semantic.map(content),
        }
    }

    #[test]
    fn put_and_get_exact_match() -> Result<(), KnowledgeError> {
        let store = InMemoryKnowledgeStore::new();
        let id = content(1);
        let env = envelope(1, vec![dep(7)], Some(9));
        store.put_exact(id, &env, b"payload")?;
        let got = store.get_exact(id, &env)?;
        assert_eq!(got, Some(b"payload".to_vec()));
        Ok(())
    }

    #[test]
    fn schema_mismatch_rejects_get() -> Result<(), KnowledgeError> {
        let store = InMemoryKnowledgeStore::new();
        let id = content(1);
        let stored = envelope(1, vec![dep(7)], Some(9));
        store.put_exact(id, &stored, b"payload")?;
        let requested = envelope(2, vec![dep(7)], Some(9));
        let got = store.get_exact(id, &requested)?;
        assert_eq!(got, None);
        Ok(())
    }

    #[test]
    fn dependency_mismatch_length_rejects_get() -> Result<(), KnowledgeError> {
        let store = InMemoryKnowledgeStore::new();
        let id = content(1);
        let stored = envelope(1, vec![dep(7), dep(8)], Some(9));
        store.put_exact(id, &stored, b"payload")?;
        let requested = envelope(1, vec![dep(7)], Some(9));
        let got = store.get_exact(id, &requested)?;
        assert_eq!(got, None);
        Ok(())
    }

    #[test]
    fn dependency_mismatch_elements_rejects_get() -> Result<(), KnowledgeError> {
        let store = InMemoryKnowledgeStore::new();
        let id = content(1);
        let stored = envelope(1, vec![dep(7)], Some(9));
        store.put_exact(id, &stored, b"payload")?;
        let requested = envelope(1, vec![dep(8)], Some(9));
        let got = store.get_exact(id, &requested)?;
        assert_eq!(got, None);
        Ok(())
    }

    #[test]
    fn dependency_mismatch_order_rejects_get() -> Result<(), KnowledgeError> {
        let store = InMemoryKnowledgeStore::new();
        let id = content(1);
        let stored = envelope(1, vec![dep(7), dep(8)], Some(9));
        store.put_exact(id, &stored, b"payload")?;
        let requested = envelope(1, vec![dep(8), dep(7)], Some(9));
        let got = store.get_exact(id, &requested)?;
        assert_eq!(got, None);
        Ok(())
    }

    #[test]
    fn semantic_content_mismatch_rejects_get() -> Result<(), KnowledgeError> {
        let store = InMemoryKnowledgeStore::new();
        let id = content(1);
        let stored = envelope(1, vec![dep(7)], Some(9));
        store.put_exact(id, &stored, b"payload")?;

        let some_vs_none = store.get_exact(id, &envelope(1, vec![dep(7)], None))?;
        assert_eq!(some_vs_none, None);

        let different_some = store.get_exact(id, &envelope(1, vec![dep(7)], Some(10)))?;
        assert_eq!(different_some, None);
        Ok(())
    }

    #[test]
    fn both_none_semantic_matches() -> Result<(), KnowledgeError> {
        let store = InMemoryKnowledgeStore::new();
        let id = content(1);
        let stored = envelope(1, vec![dep(7)], None);
        store.put_exact(id, &stored, b"payload")?;
        let got = store.get_exact(id, &stored)?;
        assert_eq!(got, Some(b"payload".to_vec()));
        Ok(())
    }

    #[test]
    fn duplicate_artifact_rejected() -> Result<(), KnowledgeError> {
        let store = InMemoryKnowledgeStore::new();
        let id = content(1);
        let env = envelope(1, vec![dep(7)], Some(9));
        store.put_exact(id, &env, b"first")?;
        let result = store.put_exact(id, &env, b"second");
        assert_eq!(result, Err(KnowledgeError::DuplicateArtifact));
        // Original payload is preserved.
        let got = store.get_exact(id, &env)?;
        assert_eq!(got, Some(b"first".to_vec()));
        Ok(())
    }

    #[test]
    fn empty_store_get_returns_none() -> Result<(), KnowledgeError> {
        let store = InMemoryKnowledgeStore::new();
        let id = content(1);
        let env = envelope(1, vec![], None);
        let got = store.get_exact(id, &env)?;
        assert_eq!(got, None);
        Ok(())
    }

    #[test]
    fn similar_returns_empty_fail_closed() -> Result<(), KnowledgeError> {
        let store = InMemoryKnowledgeStore::new();
        let fp = SemanticFingerprint([0xAB; 32]);
        let hits = store.similar(fp, 10)?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn len_and_is_empty() -> Result<(), KnowledgeError> {
        let store = InMemoryKnowledgeStore::new();
        assert!(store.is_empty());
        assert_eq!(store.len(), 0);
        let env = envelope(1, vec![], None);
        store.put_exact(content(1), &env, b"a")?;
        store.put_exact(content(2), &env, b"b")?;
        assert!(!store.is_empty());
        assert_eq!(store.len(), 2);
        Ok(())
    }

    #[test]
    fn contains_check() -> Result<(), KnowledgeError> {
        let store = InMemoryKnowledgeStore::new();
        let id = content(5);
        let env = envelope(1, vec![], None);
        store.put_exact(id, &env, b"x")?;
        assert!(store.contains(id));
        assert!(!store.contains(content(6)));
        Ok(())
    }

    #[test]
    fn entries_lists_all_artifacts() -> Result<(), KnowledgeError> {
        let store = InMemoryKnowledgeStore::new();
        let env = envelope(1, vec![dep(1)], None);
        store.put_exact(content(2), &env, b"two")?;
        store.put_exact(content(1), &env, b"one")?;
        let all = store.entries()?;
        assert_eq!(all.len(), 2);
        // BTreeMap ordering => content(1) comes first.
        assert_eq!(all[0].id, content(1));
        assert_eq!(all[0].bytes, b"one");
        assert_eq!(all[1].id, content(2));
        assert_eq!(all[1].bytes, b"two");
        Ok(())
    }

    #[test]
    fn graph_adds_and_reads_direct_edges() -> Result<(), KnowledgeError> {
        let graph = InMemoryDependencyGraph::new();
        let artifact = content(1);
        let key = dep(7);
        graph.depend(artifact, key)?;
        assert_eq!(graph.dependencies_of(artifact)?, vec![key]);
        assert_eq!(graph.dependents_of(key)?, vec![artifact]);
        Ok(())
    }

    #[test]
    fn graph_invalidate_returns_transitive_dependents() -> Result<(), KnowledgeError> {
        let graph = InMemoryDependencyGraph::new();
        // artifact1 -> dep(7); artifact2 -> artifact1 (as a dependency key)
        let artifact1 = content(1);
        let artifact2 = content(2);
        let root = dep(7);
        graph.depend(artifact1, root)?;
        graph.depend(artifact2, DependencyKey(artifact1.0))?;

        let affected = graph.invalidate(root)?;
        // Both artifact1 (direct) and artifact2 (transitive) are affected.
        assert!(affected.contains(&artifact1));
        assert!(affected.contains(&artifact2));
        assert_eq!(affected.len(), 2);
        Ok(())
    }

    #[test]
    fn graph_invalidate_no_duplicates_or_cycles() -> Result<(), KnowledgeError> {
        let graph = InMemoryDependencyGraph::new();
        let a = content(1);
        let b = content(2);
        let root = dep(7);
        // a depends on root; b depends on a; a also depends on b (cycle).
        graph.depend(a, root)?;
        graph.depend(b, DependencyKey(a.0))?;
        graph.depend(a, DependencyKey(b.0))?;

        let affected = graph.invalidate(root)?;
        // Each artifact appears at most once despite the cycle.
        let mut sorted = affected.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), affected.len());
        assert!(affected.contains(&a));
        assert!(affected.contains(&b));
        Ok(())
    }

    #[test]
    fn graph_dependencies_of_unknown_returns_empty() -> Result<(), KnowledgeError> {
        let graph = InMemoryDependencyGraph::new();
        let deps = graph.dependencies_of(content(99))?;
        assert!(deps.is_empty());
        let dependents = graph.dependents_of(dep(99))?;
        assert!(dependents.is_empty());
        Ok(())
    }

    #[test]
    fn graph_depend_is_idempotent() -> Result<(), KnowledgeError> {
        let graph = InMemoryDependencyGraph::new();
        let artifact = content(1);
        let key = dep(7);
        graph.depend(artifact, key)?;
        graph.depend(artifact, key)?;
        assert_eq!(graph.dependencies_of(artifact)?.len(), 1);
        assert_eq!(graph.dependents_of(key)?.len(), 1);
        Ok(())
    }

    #[test]
    fn knowledge_error_display_messages() {
        assert_eq!(
            KnowledgeError::Poisoned.to_string(),
            "knowledge store synchronization primitive poisoned"
        );
        assert_eq!(
            KnowledgeError::SchemaMismatch.to_string(),
            "knowledge schema version mismatch"
        );
        assert_eq!(
            KnowledgeError::DependencyMismatch.to_string(),
            "knowledge dependency set mismatch"
        );
        assert_eq!(
            KnowledgeError::InvalidFingerprint.to_string(),
            "invalid semantic fingerprint"
        );
        assert_eq!(
            KnowledgeError::ArtifactNotFound.to_string(),
            "knowledge artifact not found"
        );
        assert_eq!(
            KnowledgeError::DuplicateArtifact.to_string(),
            "knowledge artifact already stored"
        );
    }

    #[test]
    fn concurrent_put_and_get() -> Result<(), KnowledgeError> {
        let store = Arc::new(InMemoryKnowledgeStore::new());
        let mut handles = Vec::new();
        for i in 0..8u8 {
            let store = Arc::clone(&store);
            handles.push(thread::spawn(move || -> Result<(), KnowledgeError> {
                let id = content(i);
                let env = envelope(1, vec![dep(i)], Some(i));
                store.put_exact(id, &env, &[i])?;
                let got = store.get_exact(id, &env)?;
                match got {
                    Some(bytes) => assert_eq!(bytes, vec![i]),
                    None => return Err(KnowledgeError::ArtifactNotFound),
                }
                Ok(())
            }));
        }
        for handle in handles {
            handle.join().map_err(|_| KnowledgeError::Poisoned)??;
        }
        assert_eq!(store.len(), 8);
        Ok(())
    }

    #[test]
    fn concurrent_graph_depend_and_invalidate() -> Result<(), KnowledgeError> {
        let graph = Arc::new(InMemoryDependencyGraph::new());
        let root = dep(200);
        let mut handles = Vec::new();
        for i in 0..8u8 {
            let graph = Arc::clone(&graph);
            handles.push(thread::spawn(move || -> Result<(), KnowledgeError> {
                graph.depend(content(i), root)
            }));
        }
        for handle in handles {
            handle.join().map_err(|_| KnowledgeError::Poisoned)??;
        }
        let affected = graph.invalidate(root)?;
        assert_eq!(affected.len(), 8);
        Ok(())
    }

    #[test]
    fn store_trait_object_works() -> Result<(), KnowledgeError> {
        let store: Box<dyn KnowledgeStore<Error = KnowledgeError>> = Box::new(InMemoryKnowledgeStore::new());
        let id = content(1);
        let env = envelope(1, vec![], None);
        store.put_exact(id, &env, b"payload")?;
        let got = store.get_exact(id, &env)?;
        assert_eq!(got, Some(b"payload".to_vec()));
        let hits = store.similar(SemanticFingerprint([1; 32]), 5)?;
        assert!(hits.is_empty());
        Ok(())
    }

    #[test]
    fn graph_trait_object_works() -> Result<(), KnowledgeError> {
        let graph: Box<dyn DependencyGraph<Error = KnowledgeError>> = Box::new(InMemoryDependencyGraph::new());
        let artifact = content(1);
        let key = dep(7);
        graph.depend(artifact, key)?;
        let affected = graph.invalidate(key)?;
        assert_eq!(affected, vec![artifact]);
        Ok(())
    }
}
