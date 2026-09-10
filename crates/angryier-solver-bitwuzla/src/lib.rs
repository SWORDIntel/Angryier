#![forbid(unsafe_code)]

use angryier_solver::{SolverQuery, SolverResult};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitwuzlaAdapterError {
    NotLinked,
    ContextCreationFailed,
    TranslationFailed,
}

pub trait BitwuzlaNativeBridge: Send {
    fn solve_bitwuzla(&mut self, query: &SolverQuery) -> Result<SolverResult, BitwuzlaAdapterError>;
}
