#![forbid(unsafe_code)]

use angryier_memory::{ByteValue, LayeredMemory};
use angryier_types::{Address, AnalysisDebtKind, ConstraintId, ExprId, FidelityProfile, StateId, TargetProfileId};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

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
/// architecture backend.
///
/// The file is structurally shared like a persistent map: the committed
/// `base` lives behind one `Arc` that a fork clones in O(1), and each write
/// copies only the small `pending` overlay (bounded by
/// [`PENDING_FLUSH_THRESHOLD`]) before replacing one entry. Siblings
/// therefore share the base until they diverge, while sequential stepping
/// never deep-clones the full register map. Once the overlay reaches the
/// flush threshold the next write merges it into a fresh base, amortizing
/// the merge to a bounded cost per write.
///
/// The [`RegisterState::write`] signature is `&self -> Self` (callers keep
/// both the old and new snapshot observable), so the persistent path always
/// copies the bounded overlay rather than mutating in place. Callers that
/// hold the register file uniquely and do not need the previous snapshot can
/// use [`PersistentRegisters::write_in_place`], which mutates a
/// uniquely-owned base map directly via `Arc::make_mut` and clones it only
/// on the first write after a fork.
#[derive(Clone)]
pub struct PersistentRegisters {
    widths: Arc<BTreeMap<u32, usize>>,
    base: Arc<BTreeMap<u32, RegisterValue>>,
    /// Writes since the last flush; consulted before `base` on reads.
    pending: BTreeMap<u32, RegisterValue>,
}

/// Overlay size at which the next persistent write flushes `pending` into a
/// fresh base map. Bounds both the per-write overlay copy and the amortized
/// flush cost for the ~100-entry Intel 64 register file.
const PENDING_FLUSH_THRESHOLD: usize = 16;

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
            base: Arc::new(values),
            pending: BTreeMap::new(),
        })
    }

    pub fn register_width(&self, register: u32) -> Option<usize> {
        self.widths.get(&register).copied()
    }

    pub fn contains(&self, register: u32) -> bool {
        self.widths.contains_key(&register)
    }

    /// The logically visible value for `register`: the pending overlay wins
    /// over the committed base.
    fn effective_value(&self, register: u32) -> Option<&RegisterValue> {
        match self.pending.get(&register) {
            Some(value) => Some(value),
            None => self.base.get(&register),
        }
    }

    /// In-place concrete write for uniquely-held register files.
    ///
    /// Flushes any pending overlay, then inserts through `Arc::make_mut`: a
    /// uniquely-owned base map mutates in place (O(log n)); a base shared
    /// with a fork sibling is cloned exactly once, on the first write after
    /// the fork, and mutates in place afterwards.
    pub fn write_in_place(&mut self, register: u32, value: &[u8]) -> Result<(), RegisterError> {
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
        self.flush_pending();
        Arc::make_mut(&mut self.base).insert(register, RegisterValue::Concrete(Arc::<[u8]>::from(value)));
        Ok(())
    }

    /// In-place symbolic write; see [`write_in_place`](Self::write_in_place)
    /// for the copy-on-write contract.
    pub fn write_symbolic_in_place(&mut self, register: u32, expression: ExprId) -> Result<(), RegisterError> {
        let width_bytes = self
            .widths
            .get(&register)
            .copied()
            .ok_or(RegisterError::UnknownRegister(register))?;
        self.flush_pending();
        Arc::make_mut(&mut self.base).insert(
            register,
            RegisterValue::Symbolic {
                expression,
                width_bytes,
            },
        );
        Ok(())
    }

    /// Merges the pending overlay into the base map, mutating in place when
    /// the base is uniquely owned.
    fn flush_pending(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let pending = std::mem::take(&mut self.pending);
        Arc::make_mut(&mut self.base).extend(pending);
    }

    /// Builds the next snapshot for a persistent write: shares the base,
    /// copies the bounded overlay, and flushes when the overlay is full.
    fn next_with(&self, register: u32, value: RegisterValue) -> Self {
        let mut pending = self.pending.clone();
        pending.insert(register, value);
        if pending.len() >= PENDING_FLUSH_THRESHOLD {
            let mut base = (*self.base).clone();
            base.extend(pending);
            return Self {
                widths: Arc::clone(&self.widths),
                base: Arc::new(base),
                pending: BTreeMap::new(),
            };
        }
        Self {
            widths: Arc::clone(&self.widths),
            base: Arc::clone(&self.base),
            pending,
        }
    }
}

impl core::fmt::Debug for PersistentRegisters {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Render the logical map (base overlaid by pending) so differently
        // flattened but equal files debug identically.
        let mut logical: Vec<(u32, &RegisterValue)> = self.base.iter().map(|(k, v)| (*k, v)).collect();
        for (register, value) in &self.pending {
            if let Some(slot) = logical.iter_mut().find(|(id, _)| id == register) {
                slot.1 = value;
            } else {
                logical.push((*register, value));
            }
        }
        logical.sort_by_key(|(id, _)| *id);
        formatter
            .debug_struct("PersistentRegisters")
            .field("widths", &self.widths)
            .field("values", &logical)
            .finish()
    }
}

impl PartialEq for PersistentRegisters {
    fn eq(&self, other: &Self) -> bool {
        if self.widths != other.widths {
            return false;
        }
        let keys: BTreeSet<u32> = self.base.keys().chain(self.pending.keys()).copied().collect();
        keys.iter()
            .all(|register| self.effective_value(*register) == other.effective_value(*register))
    }
}

impl Eq for PersistentRegisters {}

impl RegisterState for PersistentRegisters {
    type Error = RegisterError;

    fn read(&self, register: u32) -> Result<Vec<u8>, Self::Error> {
        self.effective_value(register)
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
        Ok(self.next_with(register, RegisterValue::Concrete(Arc::<[u8]>::from(value))))
    }
}

impl SymbolicRegisterState for PersistentRegisters {
    fn read_value(&self, register: u32) -> Result<RegisterValue, Self::Error> {
        self.effective_value(register)
            .cloned()
            .ok_or(RegisterError::UnknownRegister(register))
    }

    fn write_symbolic(&self, register: u32, expression: ExprId) -> Result<Self, Self::Error> {
        let width_bytes = self
            .widths
            .get(&register)
            .copied()
            .ok_or(RegisterError::UnknownRegister(register))?;
        Ok(self.next_with(
            register,
            RegisterValue::Symbolic {
                expression,
                width_bytes,
            },
        ))
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

    #[test]
    fn register_read_after_write() -> Result<(), RegisterError> {
        let registers = PersistentRegisters::from_widths([(1, 8)])?;
        let written = registers.write(1, &[0xab; 8])?;

        assert!(written.read(1).is_ok());
        if let Ok(value) = written.read(1) {
            assert_eq!(value, vec![0xab; 8]);
        }
        Ok(())
    }

    #[test]
    fn register_write_overwrites_previous() -> Result<(), RegisterError> {
        let registers = PersistentRegisters::from_widths([(1, 4)])?;
        let first = registers.write(1, &[0x11; 4])?;
        let second = first.write(1, &[0x22; 4])?;

        assert!(second.read(1).is_ok());
        if let Ok(value) = second.read(1) {
            assert_eq!(value, vec![0x22; 4]);
        }
        assert!(first.read(1).is_ok());
        if let Ok(value) = first.read(1) {
            assert_eq!(value, vec![0x11; 4]);
        }
        Ok(())
    }

    #[test]
    fn register_read_uninitialized_returns_zero() -> Result<(), RegisterError> {
        let registers = PersistentRegisters::from_widths([(1, 8), (2, 4)])?;

        assert!(registers.read(1).is_ok());
        if let Ok(value) = registers.read(1) {
            assert_eq!(value, vec![0; 8]);
        }
        assert!(registers.read(2).is_ok());
        if let Ok(value) = registers.read(2) {
            assert_eq!(value, vec![0; 4]);
        }
        Ok(())
    }

    #[test]
    fn register_fork_creates_independent_copy() -> Result<(), RegisterError> {
        let registers = PersistentRegisters::from_widths([(1, 8)])?;
        let fork = registers.clone();
        let changed = registers.write(1, &[0xff; 8])?;

        assert!(fork.read(1).is_ok());
        if let Ok(value) = fork.read(1) {
            assert_eq!(value, vec![0; 8]);
        }
        assert!(changed.read(1).is_ok());
        if let Ok(value) = changed.read(1) {
            assert_eq!(value, vec![0xff; 8]);
        }
        Ok(())
    }

    #[test]
    fn register_fork_write_does_not_affect_original() -> Result<(), RegisterError> {
        let registers = PersistentRegisters::from_widths([(1, 8)])?;
        let fork = registers.clone();
        let fork_changed = fork.write(1, &[0xee; 8])?;

        assert!(registers.read(1).is_ok());
        if let Ok(value) = registers.read(1) {
            assert_eq!(value, vec![0; 8]);
        }
        assert!(fork_changed.read(1).is_ok());
        if let Ok(value) = fork_changed.read(1) {
            assert_eq!(value, vec![0xee; 8]);
        }
        Ok(())
    }

    #[test]
    fn fidelity_ledger_records_entries() {
        let ledger = FidelityLedger::new(FidelityProfile::Prove);
        let recorded = ledger.record(AnalysisDebtKind::Concretized, 7);

        assert_eq!(recorded.entries.len(), 1);
        assert_eq!(
            recorded.entries[0],
            FidelityEntry {
                kind: AnalysisDebtKind::Concretized,
                source: 7
            }
        );
        assert_eq!(ledger.entries.len(), 0);
    }

    #[test]
    fn fidelity_ledger_is_exact_when_no_debt() {
        let ledger = FidelityLedger::new(FidelityProfile::Prove);

        assert!(ledger.is_exact());
        assert!(ledger.entries.is_empty());
    }

    #[test]
    fn fidelity_ledger_is_not_exact_with_debt() {
        let ledger = FidelityLedger::new(FidelityProfile::Explore);
        let recorded = ledger.record(AnalysisDebtKind::Concretized, 1);

        assert!(!recorded.is_exact());
        assert!(ledger.is_exact());
    }

    #[test]
    fn constraint_lineage_append_and_materialize() {
        let root = PersistentConstraintLineage::new();
        let first = root.append(ConstraintId(10));
        let second = first.append(ConstraintId(20));
        let third = second.append(ConstraintId(30));

        assert_eq!(
            third.materialize(),
            vec![ConstraintId(10), ConstraintId(20), ConstraintId(30)]
        );
    }

    #[test]
    fn constraint_lineage_len_increments() {
        let lineage = PersistentConstraintLineage::new();

        assert_eq!(lineage.len(), 0);
        let first = lineage.append(ConstraintId(1));
        assert_eq!(first.len(), 1);
        let second = first.append(ConstraintId(2));
        assert_eq!(second.len(), 2);
        let third = second.append(ConstraintId(3));
        assert_eq!(third.len(), 3);
    }

    #[test]
    fn constraint_lineage_empty_has_zero_len() {
        let lineage = PersistentConstraintLineage::new();

        assert_eq!(lineage.len(), 0);
        assert!(lineage.is_empty());
        assert!(lineage.materialize().is_empty());
    }

    #[test]
    fn ownership_claim_succeeds_for_unowned() -> Result<(), OwnershipError> {
        let ownership = StateOwnership::default();
        let claimed = ownership.claim(7)?;

        assert_eq!(claimed.worker, Some(7));
        assert_eq!(claimed.transfer_sequence, 0);
        assert_eq!(ownership.worker, None);
        Ok(())
    }

    #[test]
    fn ownership_claim_fails_for_owned() {
        let claimed = StateOwnership {
            worker: Some(2),
            transfer_sequence: 0,
        };
        let result = claimed.claim(5);

        assert!(result.is_err());
        if let Err(error) = result {
            assert_eq!(
                error,
                OwnershipError {
                    expected_worker: 5,
                    actual_worker: Some(2)
                }
            );
        }
    }

    #[test]
    fn ownership_transfer_succeeds_for_owner() -> Result<(), OwnershipError> {
        let claimed = StateOwnership {
            worker: Some(3),
            transfer_sequence: 0,
        };
        let transferred = claimed.transfer(3, 9)?;

        assert_eq!(transferred.worker, Some(9));
        assert_eq!(transferred.transfer_sequence, 1);
        Ok(())
    }

    #[test]
    fn ownership_transfer_fails_for_non_owner() {
        let claimed = StateOwnership {
            worker: Some(4),
            transfer_sequence: 0,
        };
        let result = claimed.transfer(2, 8);

        assert!(result.is_err());
        if let Err(error) = result {
            assert_eq!(
                error,
                OwnershipError {
                    expected_worker: 2,
                    actual_worker: Some(4)
                }
            );
        }
    }

    #[test]
    fn register_error_display_is_non_empty() {
        let cases = [
            RegisterError::DuplicateRegister(1),
            RegisterError::InvalidWidth(2),
            RegisterError::UnknownRegister(3),
            RegisterError::WidthMismatch {
                register: 4,
                expected: 8,
                actual: 4,
            },
            RegisterError::SymbolicValue(5),
        ];

        for error in cases {
            let message = format!("{error}");
            assert!(!message.is_empty(), "Display output was empty for {error:?}");
        }
    }

    #[test]
    fn ownership_error_display_is_non_empty() {
        let cases = [
            OwnershipError {
                expected_worker: 1,
                actual_worker: None,
            },
            OwnershipError {
                expected_worker: 2,
                actual_worker: Some(3),
            },
        ];

        for error in cases {
            let message = format!("{error}");
            assert!(!message.is_empty(), "Display output was empty for {error:?}");
        }
    }

    #[test]
    fn symbolic_register_value_preserves_expr_id() -> Result<(), RegisterError> {
        let registers = PersistentRegisters::from_widths([(1, 8)])?;
        let symbolic = registers.write_symbolic(1, ExprId(99))?;

        let value = symbolic.read_value(1)?;
        assert!(
            matches!(value, RegisterValue::Symbolic { .. }),
            "expected a symbolic register value, got {value:?}"
        );
        if let RegisterValue::Symbolic {
            expression,
            width_bytes,
        } = value
        {
            assert_eq!(expression, ExprId(99));
            assert_eq!(width_bytes, 8);
        }
        Ok(())
    }

    #[test]
    fn persistent_write_shares_base_with_parent() -> Result<(), RegisterError> {
        // The persistent (&self) write must keep forks sharing the committed
        // base; only the bounded pending overlay diverges.
        let registers = PersistentRegisters::from_widths((0..48_u32).map(|id| (id, 8)))?;
        let fork = registers.clone();
        let written = registers.write(3, &[0x7f; 8])?;

        assert!(Arc::ptr_eq(&registers.base, &fork.base), "fork shares the base Arc");
        assert!(Arc::ptr_eq(&registers.base, &written.base), "write shares the base Arc");
        assert_eq!(written.read(3)?, vec![0x7f; 8]);
        assert_eq!(registers.read(3)?, vec![0; 8]);
        assert_eq!(fork.read(3)?, vec![0; 8]);
        Ok(())
    }

    #[test]
    fn pending_overlay_flushes_and_reads_stay_correct() -> Result<(), RegisterError> {
        // Push enough distinct registers through the overlay to cross the
        // flush threshold repeatedly; every intermediate snapshot must read
        // back exactly its own writes.
        let registers = PersistentRegisters::from_widths((0..32_u32).map(|id| (id, 8)))?;
        let mut current = registers.clone();
        for round in 0..4_u8 {
            for register in 0..24_u32 {
                let byte = round.wrapping_add(register as u8);
                current = current.write(register, &[byte; 8])?;
                assert_eq!(current.read(register)?, vec![byte; 8]);
            }
        }
        // Final state: later rounds win.
        for register in 0..24_u32 {
            assert_eq!(current.read(register)?, vec![3_u8.wrapping_add(register as u8); 8]);
        }
        // Original untouched.
        for register in 0..24_u32 {
            assert_eq!(registers.read(register)?, vec![0; 8]);
        }
        Ok(())
    }

    #[test]
    fn write_in_place_mutates_unique_map_without_clone() -> Result<(), RegisterError> {
        let mut registers = PersistentRegisters::from_widths([(1, 8), (2, 8)])?;
        registers.write_in_place(1, &[0x11; 8])?;
        // Snapshot the allocation address without holding a reference, so
        // the uniqueness check is not disturbed by the probe itself.
        let base_before = Arc::as_ptr(&registers.base);

        // Uniquely owned: the same base allocation is mutated in place.
        registers.write_in_place(2, &[0x22; 8])?;
        assert_eq!(
            Arc::as_ptr(&registers.base),
            base_before,
            "uniquely-owned base must mutate in place"
        );
        assert_eq!(registers.read(1)?, vec![0x11; 8]);
        assert_eq!(registers.read(2)?, vec![0x22; 8]);
        Ok(())
    }

    #[test]
    fn write_in_place_clones_shared_map_only_on_first_write() -> Result<(), RegisterError> {
        let mut registers = PersistentRegisters::from_widths([(1, 8)])?;
        registers.write_in_place(1, &[0x01; 8])?;
        let fork = registers.clone();

        // First write after the fork: base is shared, so it clones once.
        registers.write_in_place(1, &[0x02; 8])?;
        assert!(
            !Arc::ptr_eq(&registers.base, &fork.base),
            "divergent write must not mutate the sibling's base"
        );
        assert_eq!(fork.read(1)?, vec![0x01; 8], "sibling keeps its snapshot");

        // Second write: the new base is uniquely owned, so it mutates in
        // place (same allocation address).
        let diverged_base = Arc::as_ptr(&registers.base);
        registers.write_in_place(1, &[0x03; 8])?;
        assert_eq!(
            Arc::as_ptr(&registers.base),
            diverged_base,
            "only the first write after a fork clones the base"
        );
        assert_eq!(registers.read(1)?, vec![0x03; 8]);
        Ok(())
    }

    #[test]
    fn write_in_place_respects_overlay_and_validation() -> Result<(), RegisterError> {
        let mut registers = PersistentRegisters::from_widths([(1, 4)])?;
        registers = registers.write(1, &[0xaa; 4])?; // sits in the pending overlay
        registers.write_in_place(1, &[0xbb; 4])?;
        assert_eq!(registers.read(1)?, vec![0xbb; 4]);
        assert!(registers.pending.is_empty(), "overlay must be flushed into the base");

        assert!(matches!(
            registers.write_in_place(1, &[0; 8]),
            Err(RegisterError::WidthMismatch {
                register: 1,
                expected: 4,
                actual: 8
            })
        ));
        assert!(matches!(
            registers.write_in_place(9, &[0; 4]),
            Err(RegisterError::UnknownRegister(9))
        ));
        Ok(())
    }

    #[test]
    fn equality_is_logical_across_flush_boundaries() -> Result<(), RegisterError> {
        let widths: Vec<(u32, usize)> = (0..40_u32).map(|id| (id, 8)).collect();
        let mut overlaid = PersistentRegisters::from_widths(widths.clone())?;
        let mut flushed = overlaid.clone();
        for register in 0..24_u32 {
            overlaid = overlaid.write(register, &[register as u8; 8])?; // stays partly overlaid
            flushed.write_in_place(register, &[register as u8; 8])?; // always flushed
        }
        assert_eq!(overlaid, flushed, "same logical content must compare equal");
        assert_eq!(
            format!("{overlaid:?}"),
            format!("{flushed:?}"),
            "Debug renders the logical map"
        );
        let diverged = overlaid.write(0, &[0xff; 8])?;
        assert_ne!(overlaid, diverged);
        Ok(())
    }
}
