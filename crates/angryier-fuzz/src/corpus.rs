//! Corpus management with metadata tracking, coverage accounting, and energy-based scheduling.

use std::fmt;

use angryier_types::Address;
use angryier_types::fx::FxHashSet;

use crate::rng::FastRng;
use crate::{CoverageDelta, FuzzSeed};

/// Identifier for a seed entry within the corpus.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CorpusId(pub usize);

impl fmt::Display for CorpusId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CorpusId({})", self.0)
    }
}

/// Metadata associated with a fuzz seed in the corpus.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorpusEntry {
    pub id: CorpusId,
    pub seed: FuzzSeed,
    pub execution_count: u64,
    pub energy: u64,
    pub discovered_blocks: FxHashSet<Address>,
    pub discovered_edges: FxHashSet<(Address, Address)>,
    pub generation: u32,
    pub parent_id: Option<CorpusId>,
    pub has_new_coverage: bool,
}

impl CorpusEntry {
    /// Computes scheduling weight prioritizing seeds with higher energy, newly discovered edges,
    /// and penalizing excessively executed seeds to prevent starvation.
    pub fn scheduling_weight(&self) -> u64 {
        let mut weight = self.energy.max(1);

        // Substantial boost for discovering edges
        let edge_count = self.discovered_edges.len() as u64;
        let block_count = self.discovered_blocks.len() as u64;
        if edge_count > 0 {
            weight = weight.saturating_add(edge_count.saturating_mul(100));
        }
        if block_count > 0 {
            weight = weight.saturating_add(block_count.saturating_mul(20));
        }
        if self.has_new_coverage {
            weight = weight.saturating_mul(2);
        }

        // Slight execution count dampening (decays slowly)
        let penalty = (self.execution_count / 8).min(weight.saturating_sub(1));
        weight.saturating_sub(penalty).max(1)
    }
}

/// Fuzzing corpus storing seeds, global coverage, and execution statistics.
#[derive(Clone, Debug, Default)]
pub struct FuzzCorpus {
    entries: Vec<CorpusEntry>,
    global_blocks: FxHashSet<Address>,
    global_edges: FxHashSet<(Address, Address)>,
    total_executions: u64,
}

impl FuzzCorpus {
    /// Creates a new, empty corpus.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of seeds currently in the corpus.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the corpus contains no seeds.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Read-only slice of all corpus entries.
    pub fn entries(&self) -> &[CorpusEntry] {
        &self.entries
    }

    /// Retrieves an entry by ID.
    pub fn get(&self, id: CorpusId) -> Option<&CorpusEntry> {
        self.entries.get(id.0)
    }

    /// Retrieves a mutable reference to an entry by ID.
    pub fn get_mut(&mut self, id: CorpusId) -> Option<&mut CorpusEntry> {
        self.entries.get_mut(id.0)
    }

    /// Global set of discovered basic block addresses.
    pub fn global_blocks(&self) -> &FxHashSet<Address> {
        &self.global_blocks
    }

    /// Global set of discovered control-flow edges.
    pub fn global_edges(&self) -> &FxHashSet<(Address, Address)> {
        &self.global_edges
    }

    /// Count of unique basic blocks discovered across all executions.
    pub fn global_block_count(&self) -> usize {
        self.global_blocks.len()
    }

    /// Count of unique control-flow edges discovered across all executions.
    pub fn global_edge_count(&self) -> usize {
        self.global_edges.len()
    }

    /// Total number of seed selections across the corpus lifetime.
    pub fn total_executions(&self) -> u64 {
        self.total_executions
    }

    /// Inserts a seed into the corpus with lineage tracking and default initial energy.
    pub fn add_seed(&mut self, seed: FuzzSeed, parent_id: Option<CorpusId>) -> CorpusId {
        let id = CorpusId(self.entries.len());
        let generation = match parent_id {
            Some(pid) => self.entries.get(pid.0).map(|p| p.generation + 1).unwrap_or(0),
            None => 0,
        };

        // Base energy is 100, slightly modulated by byte length (smaller preferred)
        let base_energy = if seed.bytes.len() < 32 {
            120
        } else if seed.bytes.len() > 1024 {
            80
        } else {
            100
        };

        let entry = CorpusEntry {
            id,
            seed,
            execution_count: 0,
            energy: base_energy,
            discovered_blocks: FxHashSet::default(),
            discovered_edges: FxHashSet::default(),
            generation,
            parent_id,
            has_new_coverage: false,
        };
        self.entries.push(entry);
        id
    }

    /// Incorporates a coverage delta, attributing newly discovered blocks and edges to the given seed.
    ///
    /// Returns `true` if this delta discovered at least one new block or edge globally.
    pub fn record_coverage(&mut self, id: CorpusId, delta: &CoverageDelta) -> bool {
        let mut new_coverage = false;
        let mut new_blocks = 0u64;
        let mut new_edges = 0u64;

        for &block in &delta.blocks {
            if self.global_blocks.insert(block) {
                new_coverage = true;
                new_blocks += 1;
            }
        }
        for &edge in &delta.edges {
            if self.global_edges.insert(edge) {
                new_coverage = true;
                new_edges += 1;
            }
        }

        if let Some(entry) = self.entries.get_mut(id.0) {
            entry.discovered_blocks.extend(delta.blocks.iter().copied());
            entry.discovered_edges.extend(delta.edges.iter().copied());
            if new_coverage {
                entry.has_new_coverage = true;
                // Boost energy based on coverage discovery
                entry.energy = entry
                    .energy
                    .saturating_add(new_edges.saturating_mul(50))
                    .saturating_add(new_blocks.saturating_mul(25));
            }
        }

        new_coverage
    }

    /// Selects a seed according to the scheduling policy using weighted random sampling.
    ///
    /// Seeds that discovered new edges or possess higher energy have higher probability
    /// of selection. The selected seed's execution count is incremented.
    pub fn select_seed(&mut self, rng: &mut FastRng) -> Option<CorpusId> {
        if self.entries.is_empty() {
            return None;
        }

        let total_weight: u64 = self
            .entries
            .iter()
            .map(|e| e.scheduling_weight())
            .fold(0u64, |acc, w| acc.saturating_add(w));
        if total_weight == 0 {
            let id = CorpusId(0);
            if let Some(entry) = self.entries.get_mut(0) {
                entry.execution_count += 1;
                entry.has_new_coverage = false;
                self.total_executions += 1;
            }
            return Some(id);
        }

        let choice_point = rng.next_u64() % total_weight;
        let mut cumulative = 0u64;
        let mut chosen_id = CorpusId(0);

        for entry in &mut self.entries {
            cumulative = cumulative.saturating_add(entry.scheduling_weight());
            if cumulative > choice_point {
                entry.execution_count += 1;
                entry.has_new_coverage = false;
                chosen_id = entry.id;
                break;
            }
        }

        self.total_executions += 1;
        Some(chosen_id)
    }

    /// Deterministically returns the seed ID with the highest scheduling weight.
    pub fn highest_priority_seed(&self) -> Option<CorpusId> {
        self.entries.iter().max_by_key(|e| e.scheduling_weight()).map(|e| e.id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_types::{DependencyKey, StateId};

    fn make_seed(bytes: &[u8]) -> FuzzSeed {
        FuzzSeed {
            bytes: bytes.to_vec(),
            origin_state: Some(StateId(1)),
            validity: DependencyKey([0u8; 32]),
        }
    }

    #[test]
    fn corpus_insertion_tracks_metadata() -> Result<(), String> {
        let mut corpus = FuzzCorpus::new();
        assert!(corpus.is_empty());
        assert_eq!(corpus.len(), 0);

        let id0 = corpus.add_seed(make_seed(b"seed0"), None);
        assert_eq!(id0, CorpusId(0));
        assert_eq!(corpus.len(), 1);

        let entry = corpus.get(id0).ok_or("missing id0")?;
        assert_eq!(entry.generation, 0);
        assert_eq!(entry.execution_count, 0);
        assert_eq!(entry.parent_id, None);
        assert!(entry.energy > 0);

        let id1 = corpus.add_seed(make_seed(b"seed1"), Some(id0));
        let entry1 = corpus.get(id1).ok_or("missing id1")?;
        assert_eq!(entry1.generation, 1);
        assert_eq!(entry1.parent_id, Some(id0));
        Ok(())
    }

    #[test]
    fn coverage_incorporation_updates_state_and_boosts_energy() -> Result<(), String> {
        let mut corpus = FuzzCorpus::new();
        let id = corpus.add_seed(make_seed(b"seed"), None);
        let initial_energy = corpus.get(id).ok_or("missing seed")?.energy;

        let delta = CoverageDelta {
            blocks: vec![0x1000, 0x2000],
            edges: vec![(0x1000, 0x2000)],
        };

        let new_cov = corpus.record_coverage(id, &delta);
        assert!(new_cov);
        assert_eq!(corpus.global_block_count(), 2);
        assert_eq!(corpus.global_edge_count(), 1);

        let entry = corpus.get(id).ok_or("missing entry")?;
        assert!(entry.has_new_coverage);
        assert!(entry.energy > initial_energy);
        assert_eq!(entry.discovered_blocks.len(), 2);
        assert_eq!(entry.discovered_edges.len(), 1);

        // Recording the same delta again should report no new global coverage
        let repeat = corpus.record_coverage(id, &delta);
        assert!(!repeat);
        Ok(())
    }

    #[test]
    fn scheduling_prioritizes_new_edges_and_high_energy() -> Result<(), String> {
        let mut corpus = FuzzCorpus::new();
        let id0 = corpus.add_seed(make_seed(b"base"), None);
        let id1 = corpus.add_seed(make_seed(b"high_value"), None);

        // Give id1 new coverage
        let delta = CoverageDelta {
            blocks: vec![0x3000],
            edges: vec![(0x2000, 0x3000)],
        };
        corpus.record_coverage(id1, &delta);

        let weight0 = corpus.get(id0).ok_or("missing id0")?.scheduling_weight();
        let weight1 = corpus.get(id1).ok_or("missing id1")?.scheduling_weight();
        assert!(weight1 > weight0);

        assert_eq!(corpus.highest_priority_seed(), Some(id1));

        let mut rng = FastRng::new(42);
        let mut count1 = 0;
        for _ in 0..100 {
            if corpus.select_seed(&mut rng) == Some(id1) {
                count1 += 1;
            }
        }
        // id1 should be selected significantly more often than id0
        assert!(count1 > 60);
        Ok(())
    }
}
