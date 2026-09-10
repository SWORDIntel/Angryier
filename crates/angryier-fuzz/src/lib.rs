#![forbid(unsafe_code)]

use angryier_types::{Address, DependencyKey, StateId};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FuzzIntegrationStage { SeedsOnly, SeedsAndCoverage, Bidirectional }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FuzzSeed { pub bytes: Vec<u8>, pub origin_state: Option<StateId>, pub validity: DependencyKey }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoverageDelta { pub blocks: Vec<Address>, pub edges: Vec<(Address, Address)> }

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConstraintHint { pub canonical_key: DependencyKey, pub target: Option<Address> }

pub trait FuzzBridge: Send + Sync { type Error; fn submit_seed(&self, seed: FuzzSeed) -> Result<(), Self::Error>; fn publish_coverage(&self, delta: CoverageDelta) -> Result<(), Self::Error>; fn publish_hint(&self, hint: ConstraintHint) -> Result<(), Self::Error>; }
