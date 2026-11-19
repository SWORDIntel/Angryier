//! Extension decode groups, each owned by a separate module so parallel
//! work streams never edit the same file.

use crate::Arm64DecodeError;
use angryier_arch::DecodedInstruction;
use angryier_types::{Address, TargetProfileId};

pub(crate) fn try_decode(
    profile: TargetProfileId,
    address: Address,
    word: u32,
) -> Option<Result<DecodedInstruction, Arm64DecodeError>> {
    if let Some(decoded) = crate::decode_shifts::try_decode(profile, address, word) {
        return Some(decoded);
    }
    if let Some(decoded) = crate::decode_fp::try_decode(profile, address, word) {
        return Some(decoded);
    }
    if let Some(decoded) = crate::decode_simd::try_decode(profile, address, word) {
        return Some(decoded);
    }
    None
}
