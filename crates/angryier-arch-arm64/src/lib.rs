#![forbid(unsafe_code)]

//! AArch64 (A64) architecture support for Angryier — ANG-023 phase 1.
//!
//! This crate provides the ISA-neutral contracts for AArch64:
//!
//! - the architectural register file and register views (`regs`),
//! - the target profile and `Architecture` implementation,
//! - stable encoding classes and instruction form identifiers (`forms`),
//! - a safe-Rust A64 decoder for the integer core subset (`decode`).
//!
//! The decoder covers the A64 integer core needed for Android shared-object
//! analysis: PC-relative and branch group, add/subtract (immediate and
//! shifted-register), logical (immediate and shifted-register), bitfield
//! and extract, conditional select/compare, wide immediates, loads and
//! stores (unsigned-scaled, unscaled, register-offset, pair), and
//! unconditional/conditional/indirect branches. FP/SIMD decode is a later
//! ANG-023 increment and currently reports `UnsupportedEncoding`.

use angryier_arch::Architecture;
use angryier_types::TargetProfileId;

pub mod decode;
pub(crate) mod decode_ext;
pub(crate) mod decode_fp;
pub(crate) mod decode_shifts;
pub(crate) mod decode_simd;
pub mod forms;
pub mod forms_fp;
pub mod forms_shifts;
pub mod forms_simd;
pub mod regs;

pub use decode::{Arm64DecodeError, Arm64Decoder};
pub use regs::Arm64RegisterFile;

/// Stable encoding classes consumed by A64 semantics.
pub mod encoding_class {
    use angryier_arch::EncodingClass;

    /// Fixed-width 32-bit A64 instruction (the only AArch64 class modelled so far).
    pub const A64: EncodingClass = EncodingClass(1);
}

/// AArch64 features. Phase 1 enables the architectural baseline only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Arm64Feature {
    BaseV8,
    Fp,
    Simd,
    Lse,
    Pauth,
    Bti,
    MtE,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeatureSet {
    pub features: Vec<Arm64Feature>,
}

impl Default for FeatureSet {
    fn default() -> Self {
        Self {
            features: vec![Arm64Feature::BaseV8, Arm64Feature::Fp, Arm64Feature::Simd],
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Arm64ProfileKind {
    Native,
    Named(String),
    Custom,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Arm64TargetProfile {
    pub id: TargetProfileId,
    pub kind: Arm64ProfileKind,
    pub features: FeatureSet,
}

/// `Architecture` implementation for AArch64.
#[derive(Clone, Debug)]
pub struct Arm64Architecture {
    pub profile: Arm64TargetProfile,
}

impl Arm64Architecture {
    pub fn new(profile: Arm64TargetProfile) -> Self {
        Self { profile }
    }
}

impl Architecture for Arm64Architecture {
    type RegisterFile = Arm64RegisterFile;

    fn name(&self) -> &'static str {
        "arm64"
    }

    fn target_profile(&self) -> TargetProfileId {
        self.profile.id
    }

    fn register_width(&self, register: angryier_arch::RegisterId) -> Option<u16> {
        regs::canonical_parent_width(register)
    }

    fn initial_registers(&self) -> Self::RegisterFile {
        Arm64RegisterFile::canonical()
    }
}

/// Constructs the default native AArch64 architecture profile.
pub fn native_arm64(profile_id: TargetProfileId) -> Arm64Architecture {
    Arm64Architecture::new(Arm64TargetProfile {
        id: profile_id,
        kind: Arm64ProfileKind::Native,
        features: FeatureSet::default(),
    })
}
