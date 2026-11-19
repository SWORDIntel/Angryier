#![forbid(unsafe_code)]

//! Handwritten AArch64 (A64) semantic corpus — ANG-023 phase 1.
//!
//! Covers the integer core subset decoded by `angryier-arch-arm64`:
//! branches (B/BL/B.cond/CBZ/CBNZ/TBZ/TBNZ/RET/BR/BLR), PC-relative
//! address generation, add/subtract (immediate and shifted-register, with
//! NZCV flag computation for the S variants), logical (immediate and
//! shifted-register, ANDS flags), wide immediates, bitfield/extract,
//! conditional select, multiply-accumulate, and the load/store family
//! (unsigned-scaled, unscaled, register-offset, and pair with write-back).
//!
//! FP/SIMD semantics are a later ANG-023 increment.

extern crate self as angryier_semantics_arm64;

mod providers;
pub(crate) mod providers_ext;
mod registry;
pub(crate) mod registry_ext;

pub use providers::*;
pub use registry::Arm64CorpusRegistry;

use angryier_types::SemanticRuleId;

/// Stable rule-id base for the handwritten A64 corpus.
pub const CORPUS_RULE_BASE: u64 = 0x2000;

/// Rule id for a corpus provider.
pub const fn rule_id(offset: u64) -> SemanticRuleId {
    SemanticRuleId(CORPUS_RULE_BASE + offset)
}
