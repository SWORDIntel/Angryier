#![forbid(unsafe_code)]

use angryier_memory::{ByteValue, LayeredMemory};
use angryier_types::{
    Address, AnalysisDebtKind, FidelityProfile, StateId, TargetProfileId,
};
use std::{collections::BTreeMap, sync::Arc};

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

impl FidelityLedger {
    pub fn new(profile: FidelityProfile) -> Self {
        Self {
            profile,
            entries: Vec::new(),
        }
    }

    pub fn record(&self, kind: AnalysisDebtKind, source: u64) -> Self {
        let mut next = self.clone();
        next.entries.push(FidelityEntry { kind, source });
        next
    }

    pub fn is_exact(&self) -> bool {
        self.entries.is_empty()
    }
}

pub trait RegisterState: Clone + Send + Sync {
    type Error;
    fn read(&self, register: u32) -> Result<Vec<u8>, Self::Error>;
    fn write(&self, register: u32, value: &[u8]) -> Result<Self, Self::Error>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegisterError {
    DuplicateRegister(u32),
    InvalidWidth(u32),
    UnknownRegister(u32),
    WidthMismatch {
        register: u32,
        expected: usize,
        actual: usize,
    },
}

/// Copy-on-write register storage with fixed widths established by the
/// architecture backend. Cloning the register file is O(1); a write clones only
/// the small register index and replaces one value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistentRegisters {
    widths: Arc<BTreeMap<u32, usize>>,
    values: Arc<BTreeMap<u32, Arc<[u8]>>>,
}

impl PersistentRegisters {
    pub fn from_widths<I>(widths: I) -> Result<Self, RegisterError>
    where
        I: IntoIterator<Item = (u32, usize)>,
    {
        let mut width_map = BTreeMap::new();
        let mut values = BTreeMap::new();

        for (register, width) in widths {
            if width == 0 {
                return Err(RegisterError::InvalidWidth(register));
            }
            if width_map.insert(register, width).is_some() {
                return Err(RegisterError::DuplicateRegister(register));
            }
            values.insert(register, Arc::<[u8]>::from(vec![0; width]));
        }

        Ok(Self {
            widths: Arc::new(width_map),
            values: Arc::new(values),
        })
    }

    pub fn register_width(&self, register: u32) -> Option<usize> {
        self.widths.get(&register).copied()
    }

    pub fn contains(&self, register: u32) -> bool {
        self.widths.contains_key(&register)
    }
}

impl RegisterState for PersistentRegisters {
    type Error = RegisterError;

    fn read(&self, register: u32) -> Result<Vec<u8>, Self::Error> {
        self.values
            .get(&register)
            .map(|value| value.as_ref().to_vec())
            .ok_or(RegisterError::UnknownRegister(register))
    }

    fn write(&self, register: u32, value: &[u8]) -> Result<Self, Self::Error> {
        let expected = self
            .widths
            .get(&register)
            .copied()
            .ok_or(RegisterError::UnknownRegister(register))?;
        if value.len() != expected {
            return Err(RegisterError::WidthMismatch {
                register,
                expected,
                actual: value.len(),
            });
        }

        let mut values = (*self.values).clone();
        values.insert(register, Arc::<[u8]>::from(value.to_vec()));

        Ok(Self {
            widths: Arc::clone(&self.widths),
            values: Arc::new(values),
        })
    }
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

    pub fn write_register(&self, register: u32, value: &[u8]) -> Result<Self, R::Error> {
        let mut next = self.clone();
        next.registers = self.registers.write(register, value)?;
        Ok(next)
    }

    pub fn write_memory(&self, address: Address, bytes: &[ByteValue]) -> Result<Self, M::Error> {
        let mut next = self.clone();
        next.memory = self.memory.write(address, bytes)?;
        Ok(next)
    }

    pub fn with_fidelity_debt(&self, kind: AnalysisDebtKind, source: u64) -> Self {
        let mut next = self.clone();
        next.fidelity = self.fidelity.record(kind, source);
        next
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_memory::{LayeredMemory, MemoryRegion, PersistentMemory};
    use angryier_types::ObjectId;

    #[test]
    fn persistent_register_write_does_not_mutate_parent() {
        let registers = PersistentRegisters::from_widths([(1, 8), (2, 4)]).unwrap();
        let changed = registers.write(1, &[0xaa; 8]).unwrap();

        assert_eq!(registers.read(1).unwrap(), vec![0; 8]);
        assert_eq!(changed.read(1).unwrap(), vec![0xaa; 8]);
        assert_eq!(changed.read(2).unwrap(), vec![0; 4]);
    }

    #[test]
    fn register_widths_fail_closed() {
        let registers = PersistentRegisters::from_widths([(7, 8)]).unwrap();

        assert!(matches!(
            registers.write(7, &[0; 4]),
            Err(RegisterError::WidthMismatch {
                register: 7,
                expected: 8,
                actual: 4
            })
        ));
        assert_eq!(
            registers.read(99),
            Err(RegisterError::UnknownRegister(99))
        );
    }

    #[test]
    fn state_fork_and_mutation_preserve_parent_snapshot() {
        let memory = PersistentMemory::new(vec![MemoryRegion {
            object: ObjectId(1),
            base: 0x1000,
            size: 0x1000,
            readable: true,
            writable: true,
            executable: false,
        }])
        .unwrap();
        let registers = PersistentRegisters::from_widths([(1, 8)]).unwrap();
        let state = ExecutionState {
            id: StateId(10),
            parent: None,
            target_profile: TargetProfileId(1),
            registers,
            memory,
            fidelity: FidelityLedger::new(FidelityProfile::Prove),
        };

        let child = state
            .fork_with_id(StateId(11))
            .write_register(1, &[0x42; 8])
            .unwrap()
            .write_memory(0x1000, &[ByteValue::Concrete(0xcc)])
            .unwrap();

        assert_eq!(child.parent, Some(StateId(10)));
        assert_eq!(state.registers.read(1).unwrap(), vec![0; 8]);
        assert_eq!(child.registers.read(1).unwrap(), vec![0x42; 8]);
        assert_eq!(
            state.memory.read(0x1000, 1).unwrap(),
            vec![ByteValue::Concrete(0)]
        );
        assert_eq!(
            child.memory.read(0x1000, 1).unwrap(),
            vec![ByteValue::Concrete(0xcc)]
        );
    }

    #[test]
    fn fidelity_debt_is_snapshot_local() {
        let ledger = FidelityLedger::new(FidelityProfile::Explore);
        let changed = ledger.record(AnalysisDebtKind::Concretized, 55);

        assert!(ledger.is_exact());
        assert!(!changed.is_exact());
        assert_eq!(changed.entries.len(), 1);
    }
}
