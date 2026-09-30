#![forbid(unsafe_code)]

mod interpreter;
pub mod symbolic;

pub use interpreter::{ConcreteExecutionError, ConcreteInterpreter};
pub use symbolic::{
    ConcolicBinding, ConcolicEvaluator, ConcolicImage, ConcolicSource, PathConstraint, SymbolBinding, SymbolicArena,
    SymbolicBlockSummary, SymbolicBranch, SymbolicDebtSite, SymbolicEvalError, SymbolicEvaluator,
    SymbolicSessionMemory, SymbolicStateSnapshot, SYMBOLIC_DEBT_SITE_CAP, bit_to_bool, constant_value,
    merge_snapshots,
};

use angryier_ir::IrBlock;
use angryier_types::{Address, StateId};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExecutionMode {
    Concrete,
    Taint,
    Symbolic,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutionOutcome {
    Continue { state: StateId, next_pc: Address },
    Fork { children: Vec<StateId> },
    Terminated { state: StateId },
    Trap { state: StateId, vector: u32 },
}

pub trait ExecutionEngine: Send + Sync {
    type State;
    type Error;
    fn execute_block(
        &self,
        state: &Self::State,
        block: &IrBlock,
        mode: ExecutionMode,
    ) -> Result<(Self::State, ExecutionOutcome), Self::Error>;
}
