#![forbid(unsafe_code)]

pub mod corpus;
pub mod mutator;
pub mod rng;
pub mod session;

use std::fmt;
use std::sync::Mutex;

use angryier_types::{Address, DependencyKey, StateId};

pub use corpus::{CorpusEntry, CorpusId, FuzzCorpus};
pub use mutator::{
    DEFAULT_MAX_INPUT_SIZE, Endianness, INTERESTING_8, INTERESTING_16, INTERESTING_32, Mutator, arith_u8, arith_u16,
    arith_u32, block_delete, block_insert, block_replace, flip_bit, flip_byte, flip_four_bits, flip_four_bytes,
    flip_two_bits, flip_two_bytes, inject_token_insert, inject_token_overwrite, insert_interest_u8,
    insert_interest_u16, insert_interest_u32, splice,
};
pub use rng::FastRng;
pub use session::FuzzSession;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FuzzIntegrationStage {
    SeedsOnly,
    SeedsAndCoverage,
    Bidirectional,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuzzSeed {
    pub bytes: Vec<u8>,
    pub origin_state: Option<StateId>,
    pub validity: DependencyKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageDelta {
    pub blocks: Vec<Address>,
    pub edges: Vec<(Address, Address)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConstraintHint {
    pub canonical_key: DependencyKey,
    pub target: Option<Address>,
}

pub trait FuzzBridge: Send + Sync {
    type Error;
    fn submit_seed(&self, seed: FuzzSeed) -> Result<(), Self::Error>;
    fn publish_coverage(&self, delta: CoverageDelta) -> Result<(), Self::Error>;
    fn publish_hint(&self, hint: ConstraintHint) -> Result<(), Self::Error>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FuzzError {
    Poisoned,
    EmptySeed,
    StageViolation,
}

impl fmt::Display for FuzzError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Poisoned => f.write_str("fuzz bridge mutex is poisoned"),
            Self::EmptySeed => f.write_str("submitted seed is empty"),
            Self::StageViolation => f.write_str("operation is not permitted in the current integration stage"),
        }
    }
}

impl std::error::Error for FuzzError {}

#[derive(Debug)]
pub struct InMemoryFuzzBridge {
    stage: FuzzIntegrationStage,
    seeds: Mutex<Vec<FuzzSeed>>,
    coverage_blocks: Mutex<Vec<Address>>,
    coverage_edges: Mutex<Vec<(Address, Address)>>,
    hints: Mutex<Vec<ConstraintHint>>,
}

impl Default for InMemoryFuzzBridge {
    fn default() -> Self {
        Self::new(FuzzIntegrationStage::SeedsOnly)
    }
}

impl InMemoryFuzzBridge {
    pub fn new(stage: FuzzIntegrationStage) -> Self {
        Self {
            stage,
            seeds: Mutex::new(Vec::new()),
            coverage_blocks: Mutex::new(Vec::new()),
            coverage_edges: Mutex::new(Vec::new()),
            hints: Mutex::new(Vec::new()),
        }
    }

    pub fn stage(&self) -> FuzzIntegrationStage {
        self.stage
    }

    pub fn seed_count(&self) -> usize {
        self.seeds.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn coverage_block_count(&self) -> usize {
        self.coverage_blocks.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn coverage_edge_count(&self) -> usize {
        self.coverage_edges.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn hint_count(&self) -> usize {
        self.hints.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl FuzzBridge for InMemoryFuzzBridge {
    type Error = FuzzError;

    fn submit_seed(&self, seed: FuzzSeed) -> Result<(), Self::Error> {
        if seed.bytes.is_empty() {
            return Err(FuzzError::EmptySeed);
        }
        let mut seeds = self.seeds.lock().unwrap_or_else(|e| e.into_inner());
        // All stages accept seeds.
        seeds.push(seed);
        Ok(())
    }

    fn publish_coverage(&self, delta: CoverageDelta) -> Result<(), Self::Error> {
        match self.stage {
            FuzzIntegrationStage::SeedsOnly => Err(FuzzError::StageViolation),
            FuzzIntegrationStage::SeedsAndCoverage | FuzzIntegrationStage::Bidirectional => {
                let mut blocks = self.coverage_blocks.lock().unwrap_or_else(|e| e.into_inner());
                let mut edges = self.coverage_edges.lock().unwrap_or_else(|e| e.into_inner());
                blocks.extend(delta.blocks);
                edges.extend(delta.edges);
                Ok(())
            }
        }
    }

    fn publish_hint(&self, hint: ConstraintHint) -> Result<(), Self::Error> {
        match self.stage {
            FuzzIntegrationStage::SeedsOnly | FuzzIntegrationStage::SeedsAndCoverage => Err(FuzzError::StageViolation),
            FuzzIntegrationStage::Bidirectional => {
                let mut hints = self.hints.lock().unwrap_or_else(|e| e.into_inner());
                hints.push(hint);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_seed(bytes: &[u8]) -> FuzzSeed {
        FuzzSeed {
            bytes: bytes.to_vec(),
            origin_state: Some(StateId(1)),
            validity: DependencyKey([0u8; 32]),
        }
    }

    fn sample_delta() -> CoverageDelta {
        CoverageDelta {
            blocks: vec![0x1000, 0x2000],
            edges: vec![(0x1000, 0x2000)],
        }
    }

    fn sample_hint() -> ConstraintHint {
        ConstraintHint {
            canonical_key: DependencyKey([1u8; 32]),
            target: Some(0x3000),
        }
    }

    #[test]
    fn submit_non_empty_seed_succeeds() {
        let bridge = InMemoryFuzzBridge::default();
        let result = bridge.submit_seed(sample_seed(b"hello"));
        assert!(result.is_ok());
    }

    #[test]
    fn submit_empty_seed_fails_with_empty_seed() {
        let bridge = InMemoryFuzzBridge::default();
        let result = bridge.submit_seed(sample_seed(b""));
        assert!(matches!(result, Err(FuzzError::EmptySeed)));
    }

    #[test]
    fn seeds_only_rejects_coverage_publish() {
        let bridge = InMemoryFuzzBridge::default();
        let result = bridge.publish_coverage(sample_delta());
        assert!(matches!(result, Err(FuzzError::StageViolation)));
    }

    #[test]
    fn seeds_only_rejects_hint_publish() {
        let bridge = InMemoryFuzzBridge::default();
        let result = bridge.publish_hint(sample_hint());
        assert!(matches!(result, Err(FuzzError::StageViolation)));
    }

    #[test]
    fn seeds_and_coverage_accepts_coverage() {
        let bridge = InMemoryFuzzBridge::new(FuzzIntegrationStage::SeedsAndCoverage);
        let result = bridge.publish_coverage(sample_delta());
        assert!(result.is_ok());
    }

    #[test]
    fn seeds_and_coverage_rejects_hints() {
        let bridge = InMemoryFuzzBridge::new(FuzzIntegrationStage::SeedsAndCoverage);
        let result = bridge.publish_hint(sample_hint());
        assert!(matches!(result, Err(FuzzError::StageViolation)));
    }

    #[test]
    fn bidirectional_accepts_hints() {
        let bridge = InMemoryFuzzBridge::new(FuzzIntegrationStage::Bidirectional);
        let result = bridge.publish_hint(sample_hint());
        assert!(result.is_ok());
    }

    #[test]
    fn bidirectional_accepts_coverage() {
        let bridge = InMemoryFuzzBridge::new(FuzzIntegrationStage::Bidirectional);
        let result = bridge.publish_coverage(sample_delta());
        assert!(result.is_ok());
    }

    #[test]
    fn seed_count_tracks_submissions() {
        let bridge = InMemoryFuzzBridge::default();
        assert_eq!(bridge.seed_count(), 0);
        assert!(bridge.submit_seed(sample_seed(b"a")).is_ok());
        assert!(bridge.submit_seed(sample_seed(b"bc")).is_ok());
        assert_eq!(bridge.seed_count(), 2);
    }

    #[test]
    fn coverage_counts_track_publish() {
        let bridge = InMemoryFuzzBridge::new(FuzzIntegrationStage::SeedsAndCoverage);
        assert_eq!(bridge.coverage_block_count(), 0);
        assert_eq!(bridge.coverage_edge_count(), 0);
        assert!(bridge.publish_coverage(sample_delta()).is_ok());
        assert_eq!(bridge.coverage_block_count(), 2);
        assert_eq!(bridge.coverage_edge_count(), 1);
        assert!(
            bridge
                .publish_coverage(CoverageDelta {
                    blocks: vec![0x4000],
                    edges: vec![(0x4000, 0x5000), (0x5000, 0x6000),],
                })
                .is_ok()
        );
        assert_eq!(bridge.coverage_block_count(), 3);
        assert_eq!(bridge.coverage_edge_count(), 3);
    }

    #[test]
    fn hint_count_tracks_publish_in_bidirectional() {
        let bridge = InMemoryFuzzBridge::new(FuzzIntegrationStage::Bidirectional);
        assert_eq!(bridge.hint_count(), 0);
        assert!(bridge.publish_hint(sample_hint()).is_ok());
        assert!(bridge.publish_hint(sample_hint()).is_ok());
        assert_eq!(bridge.hint_count(), 2);
    }

    #[test]
    fn fuzz_error_display_is_non_empty() {
        assert!(!FuzzError::Poisoned.to_string().is_empty());
        assert!(!FuzzError::EmptySeed.to_string().is_empty());
        assert!(!FuzzError::StageViolation.to_string().is_empty());
    }

    #[test]
    fn default_stage_is_seeds_only() {
        let bridge = InMemoryFuzzBridge::default();
        assert_eq!(bridge.stage(), FuzzIntegrationStage::SeedsOnly);
    }

    #[test]
    fn end_to_end_hybrid_fuzz_cycle() -> Result<(), String> {
        let bridge = InMemoryFuzzBridge::new(FuzzIntegrationStage::Bidirectional);
        let mut session = FuzzSession::new(bridge);

        let s1 = sample_seed(b"seed_one");
        let id1 = session.add_seed(s1).map_err(|e| e.to_string())?;
        assert_eq!(id1, CorpusId(0));

        let batch = session.generate_batch(10);
        assert_eq!(batch.len(), 10);

        let delta = CoverageDelta {
            blocks: vec![0x8000],
            edges: vec![(0x1000, 0x8000)],
        };
        let promo = session
            .record_coverage_result(id1, batch[0].clone(), delta)
            .map_err(|e| e.to_string())?;
        assert_eq!(promo, Some(CorpusId(1)));

        let hint = ConstraintHint {
            canonical_key: DependencyKey([0x55; 32]),
            target: Some(0x9000),
        };
        let hint_id = session.ingest_hint(hint).map_err(|e| e.to_string())?;
        assert_eq!(hint_id, CorpusId(2));
        assert_eq!(session.corpus().len(), 3);
        Ok(())
    }
}
