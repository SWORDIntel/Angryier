#![forbid(unsafe_code)]

use angryier_types::{ExprId, TaintId};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TaintEventKind {
    Source,
    Transform,
    Merge,
    Sink,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaintRecord {
    pub id: TaintId,
    pub kind: TaintEventKind,
    pub parents: Vec<TaintId>,
    pub expression: Option<ExprId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromotionDecision {
    StayConcrete,
    TrackTaint,
    PromoteSymbolic,
}

pub trait TaintEngine: Send + Sync {
    fn record(&self, record: TaintRecord);
    fn promotion_decision(&self, taint: TaintId) -> PromotionDecision;
}
