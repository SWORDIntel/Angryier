//! Fuzzing session engine orchestrating corpus, mutator, and bridge communication.

use crate::corpus::{CorpusId, FuzzCorpus};
use crate::mutator::Mutator;
use crate::{ConstraintHint, CoverageDelta, FuzzBridge, FuzzSeed, InMemoryFuzzBridge};

/// Hybrid fuzzing session tying together corpus management, mutators, and the bridge boundary.
#[derive(Debug)]
pub struct FuzzSession<B: FuzzBridge = InMemoryFuzzBridge> {
    corpus: FuzzCorpus,
    mutator: Mutator,
    bridge: B,
    iteration: u64,
}

impl Default for FuzzSession<InMemoryFuzzBridge> {
    fn default() -> Self {
        Self::new(InMemoryFuzzBridge::default())
    }
}

impl<B: FuzzBridge> FuzzSession<B> {
    /// Creates a new fuzz session with default corpus and mutator.
    pub fn new(bridge: B) -> Self {
        Self {
            corpus: FuzzCorpus::new(),
            mutator: Mutator::new(),
            bridge,
            iteration: 0,
        }
    }

    /// Creates a fuzz session with explicit corpus and mutator configurations.
    pub fn with_corpus_and_mutator(bridge: B, corpus: FuzzCorpus, mutator: Mutator) -> Self {
        Self {
            corpus,
            mutator,
            bridge,
            iteration: 0,
        }
    }

    /// Read-only reference to the active corpus.
    pub fn corpus(&self) -> &FuzzCorpus {
        &self.corpus
    }

    /// Mutable reference to the active corpus.
    pub fn corpus_mut(&mut self) -> &mut FuzzCorpus {
        &mut self.corpus
    }

    /// Read-only reference to the mutator.
    pub fn mutator(&self) -> &Mutator {
        &self.mutator
    }

    /// Mutable reference to the mutator.
    pub fn mutator_mut(&mut self) -> &mut Mutator {
        &mut self.mutator
    }

    /// Reference to the underlying bridge.
    pub fn bridge(&self) -> &B {
        &self.bridge
    }

    /// Current iteration / step counter.
    pub fn iteration(&self) -> u64 {
        self.iteration
    }

    /// Submits a seed to both the bridge and the local corpus.
    pub fn add_seed(&mut self, seed: FuzzSeed) -> Result<CorpusId, B::Error> {
        self.bridge.submit_seed(seed.clone())?;
        let id = self.corpus.add_seed(seed, None);
        Ok(id)
    }

    /// Generates a batch of mutated candidate seeds selected from the corpus.
    pub fn generate_batch(&mut self, count: usize) -> Vec<FuzzSeed> {
        if self.corpus.is_empty() || count == 0 {
            return Vec::new();
        }

        let mut batch = Vec::with_capacity(count);

        for _ in 0..count {
            let primary_id = match self.corpus.select_seed(&mut self.mutator.rng) {
                Some(id) => id,
                None => break,
            };

            let (bytes, origin_state, validity) = match self.corpus.get(primary_id) {
                Some(entry) => (
                    entry.seed.bytes.clone(),
                    entry.seed.origin_state,
                    entry.seed.validity,
                ),
                None => break,
            };

            // Select an optional secondary seed for splicing if corpus has multiple seeds
            let secondary_bytes = if self.corpus.len() > 1 {
                let sec_idx = self.mutator.rng.gen_range(0, self.corpus.len());
                if sec_idx != primary_id.0 {
                    self.corpus.get(CorpusId(sec_idx)).map(|e| e.seed.bytes.clone())
                } else {
                    None
                }
            } else {
                None
            };

            let mutated_bytes = self
                .mutator
                .mutate(&bytes, secondary_bytes.as_deref());

            let candidate = FuzzSeed {
                bytes: if mutated_bytes.is_empty() {
                    vec![0]
                } else {
                    mutated_bytes
                },
                origin_state,
                validity,
            };

            batch.push(candidate);
            self.iteration += 1;
        }

        batch
    }

    /// Incorporates execution feedback for a candidate testcase.
    ///
    /// If the `delta` contains globally new blocks or edges, the candidate is promoted
    /// into the corpus as a descendant of `parent_id` and submitted to the bridge.
    /// Returns `Ok(Some(new_corpus_id))` if promoted, or `Ok(None)` if no new coverage was found.
    pub fn record_coverage_result(
        &mut self,
        parent_id: CorpusId,
        candidate: FuzzSeed,
        delta: CoverageDelta,
    ) -> Result<Option<CorpusId>, B::Error> {
        let _ = self.bridge.publish_coverage(delta.clone());

        let has_new_blocks = delta
            .blocks
            .iter()
            .any(|b| !self.corpus.global_blocks().contains(b));
        let has_new_edges = delta
            .edges
            .iter()
            .any(|e| !self.corpus.global_edges().contains(e));

        if has_new_blocks || has_new_edges {
            let new_id = self.corpus.add_seed(candidate.clone(), Some(parent_id));
            let _ = self.corpus.record_coverage(new_id, &delta);
            let _ = self.bridge.submit_seed(candidate);
            Ok(Some(new_id))
        } else {
            let _ = self.corpus.record_coverage(parent_id, &delta);
            Ok(None)
        }
    }

    /// Consumes a `ConstraintHint` from concolic or symbolic solver outputs.
    ///
    /// Converts the hint into a high-priority seed and adds it to the corpus.
    pub fn ingest_hint(&mut self, hint: ConstraintHint) -> Result<CorpusId, B::Error> {
        let _ = self.bridge.publish_hint(hint.clone());

        let mut bytes = Vec::with_capacity(32 + 8);
        bytes.extend_from_slice(&hint.canonical_key.0);
        if let Some(target) = hint.target {
            bytes.extend_from_slice(&target.to_le_bytes());
        }

        let seed = FuzzSeed {
            bytes,
            origin_state: None,
            validity: hint.canonical_key,
        };

        let _ = self.bridge.submit_seed(seed.clone());
        let id = self.corpus.add_seed(seed, None);
        if let Some(entry) = self.corpus.get_mut(id) {
            entry.energy = entry.energy.saturating_mul(2);
        }

        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FuzzIntegrationStage;
    use angryier_types::{DependencyKey, StateId};

    fn make_seed(bytes: &[u8]) -> FuzzSeed {
        FuzzSeed {
            bytes: bytes.to_vec(),
            origin_state: Some(StateId(1)),
            validity: DependencyKey([0u8; 32]),
        }
    }

    #[test]
    fn full_fuzz_session_workflow() -> Result<(), String> {
        let bridge = InMemoryFuzzBridge::new(FuzzIntegrationStage::Bidirectional);
        let mut session = FuzzSession::new(bridge);

        // 1. Initial Seed Submission
        let seed = make_seed(b"initial_corpus_seed");
        let id0 = session.add_seed(seed).map_err(|e| e.to_string())?;
        assert_eq!(session.corpus().len(), 1);
        assert_eq!(session.bridge().seed_count(), 1);

        // 2. Batch Generation / Mutation
        let batch = session.generate_batch(5);
        assert_eq!(batch.len(), 5);
        assert_eq!(session.iteration(), 5);
        for item in &batch {
            assert!(!item.bytes.is_empty());
        }

        // 3. Coverage Update without new coverage -> no promotion
        let redundant_delta = CoverageDelta {
            blocks: Vec::new(),
            edges: Vec::new(),
        };
        let promo_none = session
            .record_coverage_result(id0, batch[0].clone(), redundant_delta)
            .map_err(|e| e.to_string())?;
        assert_eq!(promo_none, None);
        assert_eq!(session.corpus().len(), 1);

        // 4. Coverage Update with new coverage -> Seed Promotion
        let new_delta = CoverageDelta {
            blocks: vec![0x401000],
            edges: vec![(0x401000, 0x401020)],
        };
        let promo_new = session
            .record_coverage_result(id0, batch[1].clone(), new_delta)
            .map_err(|e| e.to_string())?;
        assert!(promo_new.is_some());
        let new_id = promo_new.ok_or("expected promotion")?;
        assert_eq!(session.corpus().len(), 2);
        assert_eq!(
            session
                .corpus()
                .get(new_id)
                .ok_or("missing new seed")?
                .generation,
            1
        );
        assert_eq!(session.bridge().coverage_block_count(), 1);
        assert_eq!(session.bridge().coverage_edge_count(), 1);

        // 5. Hint Ingestion from concolic solver
        let hint = ConstraintHint {
            canonical_key: DependencyKey([0xAA; 32]),
            target: Some(0x402000),
        };
        let hint_seed_id = session.ingest_hint(hint).map_err(|e| e.to_string())?;
        assert_eq!(session.corpus().len(), 3);
        assert_eq!(session.bridge().hint_count(), 1);

        let hint_entry = session
            .corpus()
            .get(hint_seed_id)
            .ok_or("missing hint seed")?;
        assert_eq!(hint_entry.generation, 0);
        assert!(hint_entry.energy >= 200); // boosted priority
        Ok(())
    }
}
