#![forbid(unsafe_code)]

use angryier_memory::LayeredMemory;
use angryier_types::{AnalysisDebtKind, FidelityProfile, StateId, TargetProfileId};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FidelityEntry {
    pub kind: AnalysisDebtKind,
    pub source: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FidelityLedger {
    pub profile: FidelityProfile,
    pub entries: Vec<FidelityEntry>,
}

pub trait RegisterState: Clone + Send + Sync {
    type Error;
    fn read(&self, register: u32) -> Result<Vec<u8>, Self::Error>;
    fn write(&self, register: u32, value: &[u8]) -> Result<Self, Self::Error>;
}

#[derive(Clone, Debug)]
pub struct ExecutionState<R, M> {
    pub id: StateId,
    pub parent: Option<StateId>,
    pub target_profile: TargetProfileId,
    pub registers: R,
    pub memory: M,
    pub fidelity: FidelityLedger,
}

impl<R: RegisterState, M: LayeredMemory> ExecutionState<R, M> {
    pub fn fork_with_id(&self, id: StateId) -> Self {
        let mut child = self.clone();
        child.parent = Some(self.id);
        child.id = id;
        child
    }
}
