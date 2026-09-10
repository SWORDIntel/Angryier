#![forbid(unsafe_code)]

use angryier_solver::{SolverQuery, SolverResult};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Z3AdapterError {
    NotLinked,
    ContextCreationFailed,
    TranslationFailed,
}

pub trait Z3NativeBridge: Send {
    fn solve_z3(&mut self, query: &SolverQuery) -> Result<SolverResult, Z3AdapterError>;
}
