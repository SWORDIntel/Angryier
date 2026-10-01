#![forbid(unsafe_code)]

//! In-memory knowledge store with dependency graph, exact-match cache, and
//! semantic fingerprint similarity search.
//!
//! The exact-match cache rejects retrieval unless the full validity envelope
//! (schema version, dependency set, and semantic content) matches the
//! envelope recorded at insertion time. Advisory similarity search computes
//! cosine similarity and per-modality score breakdowns over semantic
//! fingerprints, ranking candidates and verifying exact validity. Dependency
//! invalidation marks stale artifacts and removes them from similarity search.

use angryier_types::{ContentId, DependencyKey, KnowledgeSchemaVersion, SemanticFingerprint};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};

// ---------------------------------------------------------------------------
// Modality constants and vector similarity
// ---------------------------------------------------------------------------

pub const MODALITY_IR: &str = "ir";
pub const MODALITY_CFG: &str = "cfg";
pub const MODALITY_CONSTRAINTS: &str = "constraints";
pub const MODALITY_TAINT: &str = "taint";

pub const MODALITY_SLICES: [(&str, std::ops::Range<usize>); 4] = [
    (MODALITY_IR, 0..8),
    (MODALITY_CFG, 8..16),
    (MODALITY_CONSTRAINTS, 16..24),
    (MODALITY_TAINT, 24..32),
];

/// Computes cosine similarity between two byte slices of equal length.
///
/// Returns 1.0 if both vectors are identical (including both zero vectors).
/// Returns 0.0 if one vector is all zeros and the other is non-zero, or if
/// the vectors are orthogonal. Otherwise returns the cosine of the angle
/// clamped to `[0.0, 1.0]`.
pub fn cosine_similarity_bytes(a: &[u8], b: &[u8]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }
    let mut dot = 0.0f64;
    let mut norm_a_sq = 0.0f64;
    let mut norm_b_sq = 0.0f64;
    for (&x, &y) in a.iter().zip(b.iter()) {
        let fx = f64::from(x);
        let fy = f64::from(y);
        dot += fx * fy;
        norm_a_sq += fx * fx;
        norm_b_sq += fy * fy;
    }
    if norm_a_sq == 0.0 && norm_b_sq == 0.0 {
        return 1.0;
    }
    if norm_a_sq == 0.0 || norm_b_sq == 0.0 {
        return 0.0;
    }
    let denom = (norm_a_sq * norm_b_sq).sqrt();
    if denom == 0.0 {
        return 0.0;
    }
    let sim = dot / denom;
    sim.clamp(0.0, 1.0) as f32
}

/// Cosine similarity alias for byte slices.
#[inline]
pub fn cosine_similarity(a: &[u8], b: &[u8]) -> f32 {
    cosine_similarity_bytes(a, b)
}

/// Computes cosine similarity between two float slices of equal length.
pub fn cosine_similarity_f32(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }
    let mut dot = 0.0f64;
    let mut norm_a_sq = 0.0f64;
    let mut norm_b_sq = 0.0f64;
    for (&x, &y) in a.iter().zip(b.iter()) {
        let fx = f64::from(x);
        let fy = f64::from(y);
        dot += fx * fy;
        norm_a_sq += fx * fx;
        norm_b_sq += fy * fy;
    }
    if norm_a_sq == 0.0 && norm_b_sq == 0.0 {
        return 1.0;
    }
    if norm_a_sq == 0.0 || norm_b_sq == 0.0 {
        return 0.0;
    }
    let denom = (norm_a_sq * norm_b_sq).sqrt();
    if denom == 0.0 {
        return 0.0;
    }
    let sim = dot / denom;
    sim.clamp(0.0, 1.0) as f32
}

/// Computes modality score breakdown between two semantic fingerprints across
/// the four canonical modalities: `ir` (0..8), `cfg` (8..16), `constraints` (16..24),
/// and `taint` (24..32).
pub fn modality_scores(query: &SemanticFingerprint, candidate: &SemanticFingerprint) -> Vec<(&'static str, f32)> {
    vec![
        (MODALITY_IR, cosine_similarity_bytes(&query.0[0..8], &candidate.0[0..8])),
        (MODALITY_CFG, cosine_similarity_bytes(&query.0[8..16], &candidate.0[8..16])),
        (MODALITY_CONSTRAINTS, cosine_similarity_bytes(&query.0[16..24], &candidate.0[16..24])),
        (MODALITY_TAINT, cosine_similarity_bytes(&query.0[24..32], &candidate.0[24..32])),
    ]
}

/// Computes the fused similarity score from modality scores using an equal-weighted average.
pub fn compute_fused_score(scores: &[(&'static str, f32)]) -> f32 {
    if scores.is_empty() {
        return 0.0;
    }
    let sum: f32 = scores.iter().map(|(_, s)| *s).sum();
    sum / (scores.len() as f32)
}

/// Computes full cosine similarity between two 32-byte semantic fingerprints.
#[inline]
pub fn fingerprint_cosine_similarity(a: &SemanticFingerprint, b: &SemanticFingerprint) -> f32 {
    cosine_similarity_bytes(&a.0, &b.0)
}

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
    fn put_fingerprint(&self, id: ContentId, fingerprint: SemanticFingerprint) -> Result<(), Self::Error>;
    fn put_exact_with_fingerprint(
        &self,
        id: ContentId,
        validity: &ValidityEnvelope,
        bytes: &[u8],
        fingerprint: SemanticFingerprint,
    ) -> Result<(), Self::Error> {
        self.put_exact(id, validity, bytes)?;
        self.put_fingerprint(id, fingerprint)?;
        Ok(())
    }
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

/// Shared callback invoked whenever a set of artifacts is transitively
/// invalidated. Boxed behind `Arc` so that the listener list can be cloned
/// cheaply during notification.
type InvalidationListener = Arc<dyn Fn(&[ContentId]) + Send + Sync>;

/// A thread-safe in-memory dependency graph.
///
/// Forward edges map a `DependencyKey` to the artifacts (`ContentId`s) that
/// depend on it. Reverse edges map an artifact to the dependency keys it
/// depends on. Transitive invalidation treats an invalidated artifact's
/// `ContentId` as a `DependencyKey` so that dependents-of-dependents are
/// reached. Registered listeners are notified with all transitively affected
/// artifacts whenever an invalidation occurs.
pub struct InMemoryDependencyGraph {
    forward: RwLock<BTreeMap<DependencyKey, Vec<ContentId>>>,
    reverse: RwLock<BTreeMap<ContentId, Vec<DependencyKey>>>,
    listeners: RwLock<Vec<InvalidationListener>>,
}

impl InMemoryDependencyGraph {
    pub fn new() -> Self {
        Self {
            forward: RwLock::new(BTreeMap::new()),
            reverse: RwLock::new(BTreeMap::new()),
            listeners: RwLock::new(Vec::new()),
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

    /// Registers an invalidation listener callback that will be notified with
    /// the transitively invalidated artifacts whenever `invalidate` is called.
    pub fn register_listener<F>(&self, listener: F) -> Result<(), KnowledgeError>
    where
        F: Fn(&[ContentId]) + Send + Sync + 'static,
    {
        let mut listeners = self.listeners.write().map_err(|_| KnowledgeError::Poisoned)?;
        listeners.push(Arc::new(listener));
        Ok(())
    }

    /// Returns all artifacts transitively depending on `changed`, in a
    /// deterministic (sorted) order with no duplicates. Also notifies all
    /// registered listeners with the affected artifacts.
    pub fn invalidate(&self, changed: DependencyKey) -> Result<Vec<ContentId>, KnowledgeError> {
        let mut visited: BTreeSet<ContentId> = BTreeSet::new();
        let mut queue: Vec<DependencyKey> = vec![changed];
        let mut result: Vec<ContentId> = Vec::new();
        let self_artifact = ContentId(changed.0);
        if visited.insert(self_artifact) {
            result.push(self_artifact);
        }
        {
            let forward = self.forward.read().map_err(|_| KnowledgeError::Poisoned)?;
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
        }
        result.sort();

        let listeners = {
            let guard = self.listeners.read().map_err(|_| KnowledgeError::Poisoned)?;
            guard.clone()
        };
        for listener in listeners {
            listener(&result);
        }

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

/// A thread-safe in-memory knowledge store with exact-match cache and
/// semantic fingerprint similarity search.
///
/// Exact retrieval via `get_exact` succeeds only when the requested validity
/// envelope matches the stored envelope and the artifact has not been invalidated.
/// Advisory retrieval via `similar` ranks candidate artifacts by fused cosine
/// similarity across four modality slices, annotating exact validation status
/// and filtering out invalidated/stale entries.
pub struct InMemoryKnowledgeStore {
    entries: RwLock<BTreeMap<ContentId, (ValidityEnvelope, Vec<u8>)>>,
    fingerprints: Arc<RwLock<BTreeMap<ContentId, SemanticFingerprint>>>,
    stale: Arc<RwLock<BTreeSet<ContentId>>>,
    graph: Arc<InMemoryDependencyGraph>,
}

impl InMemoryKnowledgeStore {
    pub fn new() -> Self {
        Self::with_graph(Arc::new(InMemoryDependencyGraph::new()))
    }

    /// Constructs a store wired to a specific dependency graph. Invalidation
    /// in the graph automatically marks affected artifacts stale and removes
    /// them from the similarity index.
    pub fn with_graph(graph: Arc<InMemoryDependencyGraph>) -> Self {
        let entries = RwLock::new(BTreeMap::new());
        let fingerprints = Arc::new(RwLock::new(BTreeMap::new()));
        let stale = Arc::new(RwLock::new(BTreeSet::new()));

        let fp_weak = Arc::downgrade(&fingerprints);
        let stale_weak = Arc::downgrade(&stale);

        let _ = graph.register_listener(move |affected: &[ContentId]| {
            if let Some(stale_lock) = stale_weak.upgrade()
                && let Ok(mut stale_guard) = stale_lock.write()
            {
                for &id in affected {
                    stale_guard.insert(id);
                }
            }
            if let Some(fp_lock) = fp_weak.upgrade()
                && let Ok(mut fp_guard) = fp_lock.write()
            {
                for id in affected {
                    fp_guard.remove(id);
                }
            }
        });

        Self {
            entries,
            fingerprints,
            stale,
            graph,
        }
    }

    /// Returns a reference to the underlying dependency graph.
    pub fn graph(&self) -> &Arc<InMemoryDependencyGraph> {
        &self.graph
    }

    /// Stores `bytes` under `id` with the exact validity envelope. Also registers
    /// envelope dependencies into the dependency graph. Rejects duplicates with
    /// `KnowledgeError::DuplicateArtifact`.
    pub fn put_exact(&self, id: ContentId, validity: &ValidityEnvelope, bytes: &[u8]) -> Result<(), KnowledgeError> {
        {
            let mut entries = self.entries.write().map_err(|_| KnowledgeError::Poisoned)?;
            if entries.contains_key(&id) {
                return Err(KnowledgeError::DuplicateArtifact);
            }
            entries.insert(id, (validity.clone(), bytes.to_vec()));
        }
        for &dep in &validity.dependencies {
            self.graph.depend(id, dep)?;
        }
        Ok(())
    }

    /// Stores or updates an advisory semantic fingerprint for `id`.
    pub fn put_fingerprint(&self, id: ContentId, fingerprint: SemanticFingerprint) -> Result<(), KnowledgeError> {
        let mut fingerprints = self.fingerprints.write().map_err(|_| KnowledgeError::Poisoned)?;
        fingerprints.insert(id, fingerprint);
        Ok(())
    }

    /// Stores `bytes` under `id` with exact validity envelope and associated semantic fingerprint.
    pub fn put_exact_with_fingerprint(
        &self,
        id: ContentId,
        validity: &ValidityEnvelope,
        bytes: &[u8],
        fingerprint: SemanticFingerprint,
    ) -> Result<(), KnowledgeError> {
        self.put_exact(id, validity, bytes)?;
        self.put_fingerprint(id, fingerprint)?;
        Ok(())
    }

    /// Retrieves the bytes for `id` only if the requested validity envelope
    /// matches the stored envelope exactly and the artifact is not marked stale.
    /// Returns `Ok(None)` when the artifact is absent, stale, or the envelope
    /// does not match.
    pub fn get_exact(&self, id: ContentId, validity: &ValidityEnvelope) -> Result<Option<Vec<u8>>, KnowledgeError> {
        let stale = self.stale.read().map_err(|_| KnowledgeError::Poisoned)?;
        if stale.contains(&id) {
            return Ok(None);
        }
        let entries = self.entries.read().map_err(|_| KnowledgeError::Poisoned)?;
        match entries.get(&id) {
            Some((stored, bytes)) if envelopes_match(stored, validity) => {
                if stored.dependencies.iter().any(|d| stale.contains(&ContentId(d.0))) {
                    return Ok(None);
                }
                Ok(Some(bytes.clone()))
            }
            _ => Ok(None),
        }
    }

    /// Advisory similarity search over semantic fingerprints.
    ///
    /// Computes similarity against all stored fingerprints, ranking results
    /// descending by `fused_score` with deterministic tie-breaking. Stale or
    /// invalidated artifacts are excluded. `exact_validated` is set to true
    /// if the candidate exists in the exact store and passes dependency checks.
    /// Returns up to `limit` hits.
    pub fn similar(
        &self,
        fingerprint: SemanticFingerprint,
        limit: usize,
    ) -> Result<Vec<SimilarityHit>, KnowledgeError> {
        if limit == 0 {
            return Ok(Vec::new());
        }

        let candidates: Vec<(ContentId, SemanticFingerprint, bool)> = {
            let fingerprints = self.fingerprints.read().map_err(|_| KnowledgeError::Poisoned)?;
            let entries = self.entries.read().map_err(|_| KnowledgeError::Poisoned)?;
            let stale = self.stale.read().map_err(|_| KnowledgeError::Poisoned)?;

            fingerprints
                .iter()
                .filter(|(id, _)| !stale.contains(id))
                .map(|(id, fp)| {
                    let exact_validated = match entries.get(id) {
                        Some((envelope, _)) => {
                            !envelope.dependencies.iter().any(|d| stale.contains(&ContentId(d.0)))
                        }
                        None => false,
                    };
                    (*id, *fp, exact_validated)
                })
                .collect()
        };

        if candidates.is_empty() {
            return Ok(Vec::new());
        }

        let mut hits: Vec<SimilarityHit> = candidates
            .into_iter()
            .map(|(artifact, cand_fp, exact_validated)| {
                let modality = modality_scores(&fingerprint, &cand_fp);
                let fused = compute_fused_score(&modality);
                SimilarityHit {
                    artifact,
                    fingerprint: cand_fp,
                    fused_score: fused,
                    modality_scores: modality,
                    exact_validated,
                }
            })
            .collect();

        hits.sort_by(|a, b| {
            b.fused_score
                .partial_cmp(&a.fused_score)
                .unwrap_or(core::cmp::Ordering::Equal)
                .then_with(|| a.artifact.cmp(&b.artifact))
        });

        hits.truncate(limit);
        Ok(hits)
    }

    /// Records dependency edge on the store's dependency graph.
    pub fn depend(&self, artifact: ContentId, on: DependencyKey) -> Result<(), KnowledgeError> {
        self.graph.depend(artifact, on)
    }

    /// Invalidates `changed` in the dependency graph, transitively marking
    /// all dependent artifacts as stale and removing them from similarity search.
    pub fn invalidate(&self, changed: DependencyKey) -> Result<Vec<ContentId>, KnowledgeError> {
        self.graph.invalidate(changed)
    }

    /// Returns true if the artifact has been marked stale or invalidated.
    pub fn is_stale(&self, id: ContentId) -> Result<bool, KnowledgeError> {
        let stale = self.stale.read().map_err(|_| KnowledgeError::Poisoned)?;
        Ok(stale.contains(&id))
    }

    /// Explicitly marks an artifact as stale and removes it from the similarity index.
    pub fn mark_stale(&self, id: ContentId) -> Result<(), KnowledgeError> {
        {
            let mut stale = self.stale.write().map_err(|_| KnowledgeError::Poisoned)?;
            stale.insert(id);
        }
        {
            let mut fingerprints = self.fingerprints.write().map_err(|_| KnowledgeError::Poisoned)?;
            fingerprints.remove(&id);
        }
        let _ = self.graph.invalidate(DependencyKey(id.0))?;
        Ok(())
    }

    /// Removes an artifact's semantic fingerprint from the similarity index.
    pub fn remove_fingerprint(&self, id: ContentId) -> Result<Option<SemanticFingerprint>, KnowledgeError> {
        let mut fingerprints = self.fingerprints.write().map_err(|_| KnowledgeError::Poisoned)?;
        Ok(fingerprints.remove(&id))
    }

    /// Returns the stored semantic fingerprint for `id`, if present.
    pub fn fingerprint_of(&self, id: ContentId) -> Result<Option<SemanticFingerprint>, KnowledgeError> {
        let fingerprints = self.fingerprints.read().map_err(|_| KnowledgeError::Poisoned)?;
        Ok(fingerprints.get(&id).copied())
    }

    /// Returns the number of indexed fingerprints.
    pub fn fingerprint_count(&self) -> usize {
        match self.fingerprints.read() {
            Ok(guard) => guard.len(),
            Err(_) => 0,
        }
    }

    /// Returns true if `id` has an indexed semantic fingerprint.
    pub fn contains_fingerprint(&self, id: ContentId) -> bool {
        match self.fingerprints.read() {
            Ok(guard) => guard.contains_key(&id),
            Err(_) => false,
        }
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
    fn put_fingerprint(&self, id: ContentId, fingerprint: SemanticFingerprint) -> Result<(), Self::Error> {
        Self::put_fingerprint(self, id, fingerprint)
    }
    fn put_exact_with_fingerprint(
        &self,
        id: ContentId,
        validity: &ValidityEnvelope,
        bytes: &[u8],
        fingerprint: SemanticFingerprint,
    ) -> Result<(), Self::Error> {
        Self::put_exact_with_fingerprint(self, id, validity, bytes, fingerprint)
    }
}

impl DependencyGraph for InMemoryKnowledgeStore {
    type Error = KnowledgeError;
    fn depend(&self, artifact: ContentId, on: DependencyKey) -> Result<(), Self::Error> {
        Self::depend(self, artifact, on)
    }
    fn invalidate(&self, changed: DependencyKey) -> Result<Vec<ContentId>, Self::Error> {
        Self::invalidate(self, changed)
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

    // -----------------------------------------------------------------------
    // Original exact-match & dependency graph tests
    // -----------------------------------------------------------------------

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
    fn similar_returns_empty_when_empty_index() -> Result<(), KnowledgeError> {
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
        // Both artifact1 (direct) and artifact2 (transitive) are affected, plus root itself.
        assert!(affected.contains(&ContentId(root.0)));
        assert!(affected.contains(&artifact1));
        assert!(affected.contains(&artifact2));
        assert_eq!(affected.len(), 3);
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
        assert_eq!(affected.len(), 9);
        assert!(affected.contains(&ContentId(root.0)));
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
        assert_eq!(affected, vec![artifact, ContentId(key.0)]);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Similarity search & vector mathematics tests
    // -----------------------------------------------------------------------

    #[test]
    fn cosine_similarity_edge_cases() {
        // Both vectors identical non-zero
        let v1 = [10u8, 20, 30, 40];
        assert!((cosine_similarity_bytes(&v1, &v1) - 1.0).abs() < 1e-6);

        // Both vectors zero
        let z1 = [0u8; 8];
        let z2 = [0u8; 8];
        assert_eq!(cosine_similarity_bytes(&z1, &z2), 1.0);

        // One zero, one non-zero
        assert_eq!(cosine_similarity_bytes(&z1, &[1u8; 8]), 0.0);
        assert_eq!(cosine_similarity_bytes(&[1u8; 8], &z1), 0.0);

        // Orthogonal vectors
        let o1 = [1u8, 0, 1, 0];
        let o2 = [0u8, 1, 0, 1];
        assert_eq!(cosine_similarity_bytes(&o1, &o2), 0.0);

        // Scalar multiples have cosine similarity 1.0
        let a = [10u8, 20, 30];
        let b = [20u8, 40, 60];
        assert!((cosine_similarity_bytes(&a, &b) - 1.0).abs() < 1e-6);

        // Length mismatch returns 0.0
        assert_eq!(cosine_similarity_bytes(&[1, 2], &[1, 2, 3]), 0.0);

        // Float cosine similarity
        let fa = [1.0f32, 0.0, 0.0];
        let fb = [0.0f32, 1.0, 0.0];
        assert_eq!(cosine_similarity_f32(&fa, &fb), 0.0);
        assert!((cosine_similarity_f32(&fa, &fa) - 1.0).abs() < 1e-6);
        assert_eq!(cosine_similarity_f32(&[0.0, 0.0], &[0.0, 0.0]), 1.0);
    }

    #[test]
    fn modality_scores_and_fused_computation() {
        let q = SemanticFingerprint([10; 32]);
        let mut cand_bytes = [10; 32];
        // Make taint modality (bytes 24..32) orthogonal
        cand_bytes[24..32].fill(0);
        let cand = SemanticFingerprint(cand_bytes);

        let scores = modality_scores(&q, &cand);
        assert_eq!(scores.len(), 4);
        assert_eq!(scores[0].0, MODALITY_IR);
        assert!((scores[0].1 - 1.0).abs() < 1e-6);
        assert_eq!(scores[1].0, MODALITY_CFG);
        assert!((scores[1].1 - 1.0).abs() < 1e-6);
        assert_eq!(scores[2].0, MODALITY_CONSTRAINTS);
        assert!((scores[2].1 - 1.0).abs() < 1e-6);
        assert_eq!(scores[3].0, MODALITY_TAINT);
        assert_eq!(scores[3].1, 0.0);

        let fused = compute_fused_score(&scores);
        // (1 + 1 + 1 + 0) / 4 = 0.75
        assert!((fused - 0.75).abs() < 1e-6);
    }

    #[test]
    fn store_put_fingerprint_and_exact_validated_flag() -> Result<(), KnowledgeError> {
        let store = InMemoryKnowledgeStore::new();

        // 1. Artifact indexed via put_fingerprint alone (no exact envelope stored)
        let id_advisory = content(1);
        let fp_advisory = SemanticFingerprint([1; 32]);
        store.put_fingerprint(id_advisory, fp_advisory)?;

        // 2. Artifact stored with put_exact_with_fingerprint
        let id_exact = content(2);
        let env = envelope(1, vec![dep(5)], None);
        let fp_exact = SemanticFingerprint([2; 32]);
        store.put_exact_with_fingerprint(id_exact, &env, b"payload", fp_exact)?;

        assert_eq!(store.fingerprint_count(), 2);
        assert!(store.contains_fingerprint(id_advisory));
        assert!(store.contains_fingerprint(id_exact));
        assert_eq!(store.fingerprint_of(id_advisory)?, Some(fp_advisory));

        // Querying advisory artifact: exact_validated should be false
        let hits_advisory = store.similar(fp_advisory, 10)?;
        let adv_validated = hits_advisory
            .iter()
            .filter(|h| h.artifact == id_advisory)
            .map(|h| h.exact_validated)
            .collect::<Vec<_>>();
        assert_eq!(adv_validated, vec![false], "advisory artifact must not be exact-validated");

        // Querying exact artifact: exact_validated should be true
        let hits_exact = store.similar(fp_exact, 10)?;
        let ex_validated = hits_exact
            .iter()
            .filter(|h| h.artifact == id_exact)
            .map(|h| h.exact_validated)
            .collect::<Vec<_>>();
        assert_eq!(ex_validated, vec![true], "exact artifact must be exact-validated");

        Ok(())
    }

    #[test]
    fn similar_ranking_and_score_ordering() -> Result<(), KnowledgeError> {
        let store = InMemoryKnowledgeStore::new();
        let env = envelope(1, vec![], None);

        // Query fingerprint: all 10s
        let q = SemanticFingerprint([10; 32]);

        // Candidate 1: Exact match (all 4 modalities identical -> score 1.0)
        let cand1_id = content(1);
        let cand1_fp = SemanticFingerprint([10; 32]);
        store.put_exact_with_fingerprint(cand1_id, &env, b"c1", cand1_fp)?;

        // Candidate 2: 3 modalities identical (0..24), 4th modality has non-zero overlap
        // [10; 8] vs [20, 0, 0, 0, 0, 0, 0, 0] -> cosine similarity ~0.3535
        let cand2_id = content(2);
        let mut cand2_bytes = [10; 32];
        cand2_bytes[24..32].fill(0);
        cand2_bytes[24] = 20;
        let cand2_fp = SemanticFingerprint(cand2_bytes);
        store.put_exact_with_fingerprint(cand2_id, &env, b"c2", cand2_fp)?;

        // Candidate 3: 2 modalities identical (0..16), last two modalities overlap partially
        let cand3_id = content(3);
        let mut cand3_bytes = [10; 32];
        cand3_bytes[16..32].fill(0);
        cand3_bytes[16] = 20;
        cand3_bytes[24] = 20;
        let cand3_fp = SemanticFingerprint(cand3_bytes);
        store.put_exact_with_fingerprint(cand3_id, &env, b"c3", cand3_fp)?;

        // Candidate 4: All zeros (orthogonal to non-zero query -> score 0.0)
        let cand4_id = content(4);
        let cand4_fp = SemanticFingerprint([0; 32]);
        store.put_exact_with_fingerprint(cand4_id, &env, b"c4", cand4_fp)?;

        let hits = store.similar(q, 10)?;
        assert_eq!(hits.len(), 4);

        // Ranking must strictly descend
        assert_eq!(hits[0].artifact, cand1_id);
        assert!((hits[0].fused_score - 1.0).abs() < 1e-6);

        assert_eq!(hits[1].artifact, cand2_id);
        assert!(hits[0].fused_score > hits[1].fused_score);

        assert_eq!(hits[2].artifact, cand3_id);
        assert!(hits[1].fused_score > hits[2].fused_score);

        assert_eq!(hits[3].artifact, cand4_id);
        assert!(hits[2].fused_score > hits[3].fused_score);
        assert_eq!(hits[3].fused_score, 0.0);

        Ok(())
    }

    #[test]
    fn similar_limit_truncation_and_empty_cases() -> Result<(), KnowledgeError> {
        let store = InMemoryKnowledgeStore::new();
        let env = envelope(1, vec![], None);

        // Empty store query
        let empty_hits = store.similar(SemanticFingerprint([1; 32]), 5)?;
        assert!(empty_hits.is_empty());

        // Limit = 0
        let zero_limit = store.similar(SemanticFingerprint([1; 32]), 0)?;
        assert!(zero_limit.is_empty());

        // Insert 5 items
        for i in 1..=5u8 {
            let fp = SemanticFingerprint([i * 10; 32]);
            store.put_exact_with_fingerprint(content(i), &env, &[i], fp)?;
        }

        // Limit 0 returns empty
        assert_eq!(store.similar(SemanticFingerprint([10; 32]), 0)?.len(), 0);

        // Limit 2 returns top 2
        let top2 = store.similar(SemanticFingerprint([10; 32]), 2)?;
        assert_eq!(top2.len(), 2);
        assert_eq!(top2[0].artifact, content(1));

        // Limit 5 returns all 5
        let all = store.similar(SemanticFingerprint([10; 32]), 5)?;
        assert_eq!(all.len(), 5);

        // Limit 10 returns all 5 without error
        let larger = store.similar(SemanticFingerprint([10; 32]), 10)?;
        assert_eq!(larger.len(), 5);

        Ok(())
    }

    #[test]
    fn dependency_invalidation_removes_from_similarity() -> Result<(), KnowledgeError> {
        let store = InMemoryKnowledgeStore::new();

        let id1 = content(1);
        let env1 = envelope(1, vec![dep(10)], None);
        let fp1 = SemanticFingerprint([1; 32]);
        store.put_exact_with_fingerprint(id1, &env1, b"payload1", fp1)?;

        let id2 = content(2);
        let env2 = envelope(1, vec![dep(20)], None);
        let fp2 = SemanticFingerprint([2; 32]);
        store.put_exact_with_fingerprint(id2, &env2, b"payload2", fp2)?;

        // Initially both artifacts appear in similarity query
        let hits = store.similar(fp1, 10)?;
        assert_eq!(hits.len(), 2);

        // Invalidate dependency key 10
        let affected = store.invalidate(dep(10))?;
        assert_eq!(affected, vec![id1, ContentId(dep(10).0)]);

        // After invalidation, artifact 1 must be removed from similarity results
        let hits_after = store.similar(fp1, 10)?;
        assert_eq!(hits_after.len(), 1);
        assert_eq!(hits_after[0].artifact, id2);

        // State inspection verifies artifact 1 is stale and rejected on exact get
        assert!(store.is_stale(id1)?);
        assert!(!store.is_stale(id2)?);
        assert_eq!(store.get_exact(id1, &env1)?, None);
        assert_eq!(store.get_exact(id2, &env2)?, Some(b"payload2".to_vec()));

        Ok(())
    }

    #[test]
    fn transitive_dependency_invalidation_removes_from_similarity() -> Result<(), KnowledgeError> {
        let store = InMemoryKnowledgeStore::new();

        // id1 depends on root dep(100)
        let id1 = content(1);
        let env1 = envelope(1, vec![dep(100)], None);
        store.put_exact_with_fingerprint(id1, &env1, b"one", SemanticFingerprint([1; 32]))?;

        // id2 depends on id1
        let id2 = content(2);
        let env2 = envelope(1, vec![DependencyKey(id1.0)], None);
        store.put_exact_with_fingerprint(id2, &env2, b"two", SemanticFingerprint([2; 32]))?;

        // id3 depends on an independent root dep(200)
        let id3 = content(3);
        let env3 = envelope(1, vec![dep(200)], None);
        store.put_exact_with_fingerprint(id3, &env3, b"three", SemanticFingerprint([3; 32]))?;

        assert_eq!(store.similar(SemanticFingerprint([1; 32]), 10)?.len(), 3);

        // Invalidate root dep(100): affects root itself, id1 directly and id2 transitively
        let affected = store.invalidate(dep(100))?;
        assert_eq!(affected.len(), 3);
        assert!(affected.contains(&ContentId(dep(100).0)));
        assert!(affected.contains(&id1));
        assert!(affected.contains(&id2));

        // Both id1 and id2 are removed from similarity search
        let hits = store.similar(SemanticFingerprint([1; 32]), 10)?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].artifact, id3);

        assert!(store.is_stale(id1)?);
        assert!(store.is_stale(id2)?);
        assert!(!store.is_stale(id3)?);

        Ok(())
    }

    #[test]
    fn manual_mark_stale_and_remove_fingerprint() -> Result<(), KnowledgeError> {
        let store = InMemoryKnowledgeStore::new();
        let id = content(1);
        let fp = SemanticFingerprint([0x55; 32]);
        store.put_fingerprint(id, fp)?;

        assert!(store.contains_fingerprint(id));
        assert_eq!(store.similar(fp, 10)?.len(), 1);

        // Explicit mark_stale removes from similarity
        store.mark_stale(id)?;
        assert!(store.is_stale(id)?);
        assert!(store.similar(fp, 10)?.is_empty());

        // Test remove_fingerprint
        let id2 = content(2);
        store.put_fingerprint(id2, fp)?;
        assert_eq!(store.remove_fingerprint(id2)?, Some(fp));
        assert_eq!(store.remove_fingerprint(id2)?, None);
        assert!(store.similar(fp, 10)?.is_empty());

        Ok(())
    }

    #[test]
    fn shared_dependency_graph_with_graph() -> Result<(), KnowledgeError> {
        let graph = Arc::new(InMemoryDependencyGraph::new());
        let store = InMemoryKnowledgeStore::with_graph(Arc::clone(&graph));

        let id = content(1);
        let root = dep(99);
        let env = envelope(1, vec![root], None);
        let fp = SemanticFingerprint([0xAA; 32]);
        store.put_exact_with_fingerprint(id, &env, b"payload", fp)?;

        assert_eq!(store.similar(fp, 10)?.len(), 1);

        // Invalidate directly on the shared graph
        let affected = graph.invalidate(root)?;
        assert_eq!(affected, vec![id, ContentId(root.0)]);

        // Store observed invalidation and removed it from similarity results
        assert!(store.similar(fp, 10)?.is_empty());
        assert!(store.is_stale(id)?);

        Ok(())
    }

    #[test]
    fn knowledge_store_trait_object_with_fingerprints() -> Result<(), KnowledgeError> {
        let store: Box<dyn KnowledgeStore<Error = KnowledgeError>> = Box::new(InMemoryKnowledgeStore::new());
        let id = content(1);
        let env = envelope(1, vec![], None);
        let fp = SemanticFingerprint([7; 32]);

        store.put_exact_with_fingerprint(id, &env, b"trait_payload", fp)?;
        let got = store.get_exact(id, &env)?;
        assert_eq!(got, Some(b"trait_payload".to_vec()));

        let hits = store.similar(fp, 5)?;
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].artifact, id);
        assert_eq!(hits[0].fused_score, 1.0);
        assert!(hits[0].exact_validated);

        Ok(())
    }

    #[test]
    fn store_as_dependency_graph_trait_object() -> Result<(), KnowledgeError> {
        let store: Box<dyn DependencyGraph<Error = KnowledgeError>> = Box::new(InMemoryKnowledgeStore::new());
        let artifact = content(1);
        let key = dep(7);
        store.depend(artifact, key)?;
        let affected = store.invalidate(key)?;
        assert_eq!(affected, vec![artifact, ContentId(key.0)]);
        Ok(())
    }

    #[test]
    fn cascading_stale_and_dependency_stale_in_get_exact() -> Result<(), KnowledgeError> {
        let store = InMemoryKnowledgeStore::new();

        let id1 = content(1);
        let env1 = envelope(1, vec![], None);
        store.put_exact(id1, &env1, b"payload1")?;

        let id2 = content(2);
        let env2 = envelope(1, vec![DependencyKey(id1.0)], None);
        store.put_exact(id2, &env2, b"payload2")?;

        // id2 is valid initially
        assert_eq!(store.get_exact(id2, &env2)?, Some(b"payload2".to_vec()));

        // Mark id1 as stale: cascades to id2 via graph invalidation
        store.mark_stale(id1)?;
        assert!(store.is_stale(id1)?);
        assert!(store.is_stale(id2)?);

        // id2 is rejected because it is stale, and even if not explicitly checked,
        // its dependency is stale
        assert_eq!(store.get_exact(id2, &env2)?, None);

        Ok(())
    }
}
