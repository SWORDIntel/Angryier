#![forbid(unsafe_code)]

use angryier_types::{DependencyKey, ExprId, ExpressionNormalizationVersion};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExprSort {
    BitVec(u16),
    Float { exponent_bits: u8, significand_bits: u8 },
    Bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ExprOp {
    Constant,
    Symbol,
    Add,
    Sub,
    Mul,
    UDiv,
    SDiv,
    And,
    Or,
    Xor,
    Not,
    Shl,
    LShr,
    AShr,
    Eq,
    Ult,
    Ule,
    Slt,
    Sle,
    Ite,
    Concat,
    Extract,
    ZExt,
    SExt,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ExprNode {
    pub sort: ExprSort,
    pub op: ExprOp,
    pub operands: Vec<ExprId>,
    pub immediate: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DependencySummary {
    pub key: DependencyKey,
    pub symbolic_sources: Vec<u64>,
}

pub trait ExprArena: Send + Sync {
    type Error;

    fn intern(&self, node: ExprNode) -> Result<ExprId, Self::Error>;
    fn get(&self, id: ExprId) -> Option<ExprNode>;
    fn dependency_summary(&self, id: ExprId) -> Option<DependencySummary>;
    fn normalization_version(&self) -> ExpressionNormalizationVersion;
}

pub trait HotCanonicalizer: Send + Sync {
    fn canonicalize(&self, node: ExprNode) -> ExprNode;
}

pub trait DeepCanonicalizer: Send + Sync {
    type Error;
    fn canonicalize_equivalence_class(&self, root: ExprId) -> Result<DependencyKey, Self::Error>;
}
