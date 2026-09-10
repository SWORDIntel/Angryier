#![forbid(unsafe_code)]

use angryier_arch::{Architecture, RegisterId};
use angryier_types::TargetProfileId;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum IntelFeature {
    Sse,
    Sse2,
    Sse3,
    Ssse3,
    Sse41,
    Sse42,
    AesNi,
    Sha,
    Bmi1,
    Bmi2,
    Avx,
    Avx2,
    Avx512,
    AvxVnni,
    Avx10,
    Amx,
    Cet,
    Apx,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeatureSet {
    pub features: Vec<IntelFeature>,
    pub xcr0: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Intel64ProfileKind {
    Native,
    Named(String),
    Custom,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intel64TargetProfile {
    pub id: TargetProfileId,
    pub kind: Intel64ProfileKind,
    pub features: FeatureSet,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intel64RegisterFile {
    pub architectural_registers: Vec<(RegisterId, u16)>,
}

#[derive(Clone, Debug)]
pub struct Intel64Architecture {
    pub profile: Intel64TargetProfile,
}

impl Architecture for Intel64Architecture {
    type RegisterFile = Intel64RegisterFile;

    fn name(&self) -> &'static str {
        "intel64"
    }

    fn target_profile(&self) -> TargetProfileId {
        self.profile.id
    }

    fn register_width(&self, register: RegisterId) -> Option<u16> {
        self.initial_registers()
            .architectural_registers
            .into_iter()
            .find_map(|(id, width)| (id == register).then_some(width))
    }

    fn initial_registers(&self) -> Self::RegisterFile {
        Intel64RegisterFile {
            architectural_registers: Vec::new(),
        }
    }
}
