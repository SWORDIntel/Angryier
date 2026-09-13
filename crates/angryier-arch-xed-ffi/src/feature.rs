//! Mapping from raw XED ISA-set enumerants to Angryier's stable `IntelFeature`
//! families.
//!
//! XED splits AVX-512, AMX, and APX into many fine-grained ISA-set enumerants.
//! This module collapses those ranges into the coarse feature families owned by
//! `angryier-arch-intel64`.

use angryier_arch_intel64::IntelFeature;
use xed_sys::xed_isa_set_enum_t;

// Coarse ISA-set enumerant values extracted from the vendored XED bindings.
const ISA_AES: xed_isa_set_enum_t = 3;
const ISA_AMX_FIRST: xed_isa_set_enum_t = 6; // AMX_BF16
const ISA_AMX_LAST: xed_isa_set_enum_t = 10; // AMX_TILE
const ISA_APX_FIRST: xed_isa_set_enum_t = 11; // APX_F
const ISA_APX_LAST: xed_isa_set_enum_t = 31; // APX_F_VMX
const ISA_AVX: xed_isa_set_enum_t = 32;
const ISA_AVX2: xed_isa_set_enum_t = 33;
const ISA_AVX512_FIRST: xed_isa_set_enum_t = 35; // AVX512BW_128
const ISA_AVX512_LAST: xed_isa_set_enum_t = 100; // AVX512_VPOPCNTDQ_512
const ISA_AVX_VNNI_FIRST: xed_isa_set_enum_t = 105; // AVX_VNNI
const ISA_AVX_VNNI_LAST: xed_isa_set_enum_t = 107; // AVX_VNNI_INT8
const ISA_BMI1: xed_isa_set_enum_t = 108;
const ISA_BMI2: xed_isa_set_enum_t = 109;
const ISA_CET: xed_isa_set_enum_t = 110;
const ISA_SHA: xed_isa_set_enum_t = 183;
const ISA_SSE: xed_isa_set_enum_t = 190;
const ISA_SSE2: xed_isa_set_enum_t = 191;
const ISA_SSE3: xed_isa_set_enum_t = 193;
const ISA_SSE4: xed_isa_set_enum_t = 195; // SSE4 (SSE4.1)
const ISA_SSE42: xed_isa_set_enum_t = 196;
const ISA_SSSE3: xed_isa_set_enum_t = 200;

/// Translates a raw XED ISA-set enumerant to an Angryier feature family.
///
/// Returns `None` for ISA-sets that do not correspond to a tracked feature
/// (e.g. the baseline `I86` set used by plain integer instructions).
pub(crate) fn map_feature(isa_set: xed_isa_set_enum_t) -> Option<IntelFeature> {
    match isa_set {
        ISA_AES => Some(IntelFeature::AesNi),
        ISA_AVX => Some(IntelFeature::Avx),
        ISA_AVX2 => Some(IntelFeature::Avx2),
        ISA_BMI1 => Some(IntelFeature::Bmi1),
        ISA_BMI2 => Some(IntelFeature::Bmi2),
        ISA_CET => Some(IntelFeature::Cet),
        ISA_SHA => Some(IntelFeature::Sha),
        ISA_SSE => Some(IntelFeature::Sse),
        ISA_SSE2 => Some(IntelFeature::Sse2),
        ISA_SSE3 => Some(IntelFeature::Sse3),
        ISA_SSE4 => Some(IntelFeature::Sse41),
        ISA_SSE42 => Some(IntelFeature::Sse42),
        ISA_SSSE3 => Some(IntelFeature::Ssse3),
        set if (ISA_AVX512_FIRST..=ISA_AVX512_LAST).contains(&set) => Some(IntelFeature::Avx512),
        set if (ISA_AMX_FIRST..=ISA_AMX_LAST).contains(&set) => Some(IntelFeature::Amx),
        set if (ISA_APX_FIRST..=ISA_APX_LAST).contains(&set) => Some(IntelFeature::Apx),
        set if (ISA_AVX_VNNI_FIRST..=ISA_AVX_VNNI_LAST).contains(&set) => Some(IntelFeature::AvxVnni),
        _ => None,
    }
}
