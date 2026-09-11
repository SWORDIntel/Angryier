#![forbid(unsafe_code)]

use angryier_memory::{ByteValue, LayeredMemory};
use angryier_types::{Address, AnalysisDebtKind, ConstraintId, ExprId, FidelityProfile, StateId, TargetProfileId};
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
pub enum RegisterValue {
    Concrete(Arc<[u8]>),
    Symbolic { expression: ExprId, width_bytes: usize },
}

pub trait SymbolicRegisterState: RegisterState {
    fn read_value(&self, register: u32) -> Result<RegisterValue, Self::Error>;
    fn write_symbolic(&self, register: u32, expression: ExprId) -> Result<Self, Self::Error>;
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
    SymbolicValue(u32),
}

impl core::fmt::Display for RegisterError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DuplicateRegister(register) => {
                write!(formatter, "duplicate register definition: {register}")
            }
            Self::InvalidWidth(register) => {
                write!(formatter, "register {register} has an invalid zero width")
            }
            Self::UnknownRegister(register) => write!(formatter, "unknown register: {register}"),
            Self::WidthMismatch {
                register,
                expected,
                actual,
            } => write!(
                formatter,
                "register {register} width mismatch: expected {expected} bytes, got {actual}"
            ),
            Self::SymbolicValue(register) => {
                write!(formatter, "register {register} contains a symbolic value")
            }
        }
    }
}

impl std::error::Error for RegisterError {}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ConstraintLineageNode {
    Root,
    Entry {
        constraint: ConstraintId,
        parent: Arc<ConstraintLineageNode>,
        depth: u64,
    },
}

/// Immutable constraint lineage. Cloning and appending are O(1); materializing
/// the ordered path is intentionally an explicit O(n) operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistentConstraintLineage {
    tail: Arc<ConstraintLineageNode>,
}

impl PersistentConstraintLineage {
    pub fn new() -> Self {
        Self {
            tail: Arc::new(ConstraintLineageNode::Root),
        }
    }

    pub fn append(&self, constraint: ConstraintId) -> Self {
        Self {
            tail: Arc::new(ConstraintLineageNode::Entry {
                constraint,
                parent: Arc::clone(&self.tail),
                depth: self.len().saturating_add(1),
            }),
        }
    }

    pub fn len(&self) -> u64 {
        match self.tail.as_ref() {
            ConstraintLineageNode::Root => 0,
            ConstraintLineageNode::Entry { depth, .. } => *depth,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn materialize(&self) -> Vec<ConstraintId> {
        let mut reversed = Vec::with_capacity(usize::try_from(self.len()).unwrap_or(0));
        let mut cursor = self.tail.as_ref();
        while let ConstraintLineageNode::Entry { constraint, parent, .. } = cursor {
            reversed.push(*constraint);
            cursor = parent.as_ref();
        }
        reversed.reverse();
        reversed
    }
}

impl Default for PersistentConstraintLineage {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StateOwnership {
    pub worker: Option<u32>,
    pub transfer_sequence: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OwnershipError {
    pub expected_worker: u32,
    pub actual_worker: Option<u32>,
}

impl core::fmt::Display for OwnershipError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "state ownership mismatch: expected worker {}, found {:?}",
            self.expected_worker, self.actual_worker
        )
    }
}

impl std::error::Error for OwnershipError {}

impl StateOwnership {
    pub fn claim(self, worker: u32) -> Result<Self, OwnershipError> {
        match self.worker {
            None => Ok(Self {
                worker: Some(worker),
                transfer_sequence: self.transfer_sequence,
            }),
            Some(current) if current == worker => Ok(Self {
                worker: Some(worker),
                transfer_sequence: self.transfer_sequence,
            }),
            actual => Err(OwnershipError {
                expected_worker: worker,
                actual_worker: actual,
            }),
        }
    }

    pub fn transfer(self, from: u32, to: u32) -> Result<Self, OwnershipError> {
        if self.worker != Some(from) {
            return Err(OwnershipError {
                expected_worker: from,
                actual_worker: self.worker,
            });
        }
        Ok(Self {
            worker: Some(to),
            transfer_sequence: self.transfer_sequence.saturating_add(1),
        })
    }
}

/// Copy-on-write register storage with fixed widths established by the
/// architecture backend. Cloning the register file is O(1); a write clones only
/// the small register index and replaces one value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistentRegisters {
    widths: Arc<BTreeMap<u32, usize>>,
    values: Arc<BTreeMap<u32, RegisterValue>>,
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
            values.insert(register, RegisterValue::Concrete(Arc::<[u8]>::from(vec![0; width])));
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
            .ok_or(RegisterError::UnknownRegister(register))
            .and_then(|value| match value {
                RegisterValue::Concrete(bytes) => Ok(bytes.as_ref().to_vec()),
                RegisterValue::Symbolic { .. } => Err(RegisterError::SymbolicValue(register)),
            })
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
        values.insert(register, RegisterValue::Concrete(Arc::<[u8]>::from(value.to_vec())));

        Ok(Self {
            widths: Arc::clone(&self.widths),
            values: Arc::new(values),
        })
    }
}

impl SymbolicRegisterState for PersistentRegisters {
    fn read_value(&self, register: u32) -> Result<RegisterValue, Self::Error> {
        self.values
            .get(&register)
            .cloned()
            .ok_or(RegisterError::UnknownRegister(register))
    }

    fn write_symbolic(&self, register: u32, expression: ExprId) -> Result<Self, Self::Error> {
        let width_bytes = self
            .widths
            .get(&register)
            .copied()
            .ok_or(RegisterError::UnknownRegister(register))?;
        let mut values = (*self.values).clone();
        values.insert(
            register,
            RegisterValue::Symbolic {
                expression,
                width_bytes,
            },
        );
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
    pub constraints: PersistentConstraintLineage,
    pub ownership: StateOwnership,
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

    pub fn with_constraint(&self, constraint: ConstraintId) -> Self {
        let mut next = self.clone();
        next.constraints = self.constraints.append(constraint);
        next
    }

    pub fn transfer_ownership(&self, from: u32, to: u32) -> Result<Self, OwnershipError> {
        let mut next = self.clone();
        next.ownership = self.ownership.transfer(from, to)?;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_memory::{LayeredMemory, MemoryRegion, PersistentMemory};
    use angryier_types::ObjectId;

    #[test]
    fn persistent_register_write_does_not_mutate_parent() -> Result<(), RegisterError> {
        let registers = PersistentRegisters::from_widths([(1, 8), (2, 4)])?;
        let changed = registers.write(1, &[0xaa; 8])?;

        assert_eq!(registers.read(1)?, vec![0; 8]);
        assert_eq!(changed.read(1)?, vec![0xaa; 8]);
        assert_eq!(changed.read(2)?, vec![0; 4]);
        Ok(())
    }

    #[test]
    fn register_widths_fail_closed() -> Result<(), RegisterError> {
        let registers = PersistentRegisters::from_widths([(7, 8)])?;

        assert!(matches!(
            registers.write(7, &[0; 4]),
            Err(RegisterError::WidthMismatch {
                register: 7,
                expected: 8,
                actual: 4
            })
        ));
        assert_eq!(registers.read(99), Err(RegisterError::UnknownRegister(99)));
        Ok(())
    }

    #[test]
    fn symbolic_register_values_preserve_width_and_parent_snapshot() -> Result<(), RegisterError> {
        let registers = PersistentRegisters::from_widths([(7, 8)])?;
        let symbolic = registers.write_symbolic(7, ExprId(42))?;

        assert_eq!(registers.read(7)?, vec![0; 8]);
        assert_eq!(symbolic.read(7), Err(RegisterError::SymbolicValue(7)));
        assert_eq!(
            symbolic.read_value(7)?,
            RegisterValue::Symbolic {
                expression: ExprId(42),
                width_bytes: 8
            }
        );
        Ok(())
    }

    #[test]
    fn state_fork_and_mutation_preserve_parent_snapshot() -> Result<(), Box<dyn std::error::Error>> {
        let memory = PersistentMemory::new(vec![MemoryRegion {
            object: ObjectId(1),
            base: 0x1000,
            size: 0x1000,
            readable: true,
            writable: true,
            executable: false,
        }])?;
        let registers = PersistentRegisters::from_widths([(1, 8)])?;
        let state = ExecutionState {
            id: StateId(10),
            parent: None,
            target_profile: TargetProfileId(1),
            registers,
            memory,
            constraints: PersistentConstraintLineage::new(),
            ownership: StateOwnership::default(),
            fidelity: FidelityLedger::new(FidelityProfile::Prove),
        };

        let child = state
            .fork_with_id(StateId(11))
            .write_register(1, &[0x42; 8])?
            .write_memory(0x1000, &[ByteValue::Concrete(0xcc)])?;

        assert_eq!(child.parent, Some(StateId(10)));
        assert_eq!(state.registers.read(1)?, vec![0; 8]);
        assert_eq!(child.registers.read(1)?, vec![0x42; 8]);
        assert_eq!(state.memory.read(0x1000, 1)?, vec![ByteValue::Concrete(0)]);
        assert_eq!(child.memory.read(0x1000, 1)?, vec![ByteValue::Concrete(0xcc)]);
        Ok(())
    }

    #[test]
    fn fidelity_debt_is_snapshot_local() {
        let ledger = FidelityLedger::new(FidelityProfile::Explore);
        let changed = ledger.record(AnalysisDebtKind::Concretized, 55);

        assert!(ledger.is_exact());
        assert!(!changed.is_exact());
        assert_eq!(changed.entries.len(), 1);
    }

    #[test]
    fn constraint_lineage_appends_without_changing_ancestors() {
        let root = PersistentConstraintLineage::new();
        let left = root.append(ConstraintId(1));
        let right = left.append(ConstraintId(2));

        assert!(root.is_empty());
        assert_eq!(left.materialize(), vec![ConstraintId(1)]);
        assert_eq!(right.materialize(), vec![ConstraintId(1), ConstraintId(2)]);
    }

    #[test]
    fn ownership_transfer_requires_the_current_owner() -> Result<(), OwnershipError> {
        let claimed = StateOwnership::default().claim(3)?;
        let transferred = claimed.transfer(3, 5)?;

        assert_eq!(transferred.worker, Some(5));
        assert_eq!(transferred.transfer_sequence, 1);
        assert_eq!(
            transferred.transfer(3, 7),
            Err(OwnershipError {
                expected_worker: 3,
                actual_worker: Some(5)
            })
        );
        Ok(())
    }
}
