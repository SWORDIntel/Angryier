#![forbid(unsafe_code)]

//! Safe Intel XED adapter boundary.
//!
//! Raw XED pointers, lifetimes, generated enum discriminants, and FFI ownership
//! never cross this crate's public API. A native bridge must translate XED
//! output into value-only metadata, after which this crate validates and
//! normalizes it into Angryier's architecture-neutral decode representation.

pub mod error;
pub mod metadata;
mod normalize;

pub use error::XedAdapterError;
pub use metadata::*;
pub use normalize::normalize_decoded;

use angryier_arch::{DecodedInstruction, Decoder};
use angryier_arch_intel64::Intel64TargetProfile;
use angryier_types::Address;
use core::fmt::Debug;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XedDecodeConfig {
    pub mode: XedMachineMode,
    pub profile: Intel64TargetProfile,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XedDecoderAdapter {
    pub config: XedDecodeConfig,
}

/// Implemented by a real native XED bridge.
///
/// Implementations return only stable, value-owned metadata. They are not
/// permitted to construct `DecodedInstruction` directly, so every decode must
/// pass through the validation and normalization gate in this crate.
pub trait XedDecodeBackend: Debug + Send + Sync {
    fn decode_metadata(
        &self,
        config: &XedDecodeConfig,
        address: Address,
        bytes: &[u8],
    ) -> Result<XedDecodedMetadata, XedAdapterError>;
}

#[derive(Debug)]
pub struct BoundXedDecoder<B: XedDecodeBackend> {
    pub adapter: XedDecoderAdapter,
    pub backend: B,
}

impl<B: XedDecodeBackend> Decoder for BoundXedDecoder<B> {
    type Error = XedAdapterError;

    fn decode(&self, address: Address, bytes: &[u8]) -> Result<DecodedInstruction, Self::Error> {
        let metadata = self.backend.decode_metadata(&self.adapter.config, address, bytes)?;
        normalize_decoded(&self.adapter.config, address, bytes.len(), metadata)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use angryier_arch::Decoder;
    use angryier_arch_intel64::{FeatureSet, Intel64ProfileKind};
    use angryier_types::TargetProfileId;

    #[derive(Debug)]
    struct FakeBackend;

    impl XedDecodeBackend for FakeBackend {
        fn decode_metadata(
            &self,
            _config: &XedDecodeConfig,
            _address: Address,
            _bytes: &[u8],
        ) -> Result<XedDecodedMetadata, XedAdapterError> {
            Ok(XedDecodedMetadata {
                length: 1,
                form_id: 1,
                features: Vec::new(),
                operands: Vec::new(),
                modifiers: XedInstructionModifiers::default(),
            })
        }
    }

    fn decoder() -> BoundXedDecoder<FakeBackend> {
        BoundXedDecoder {
            adapter: XedDecoderAdapter {
                config: XedDecodeConfig {
                    mode: XedMachineMode::Intel64,
                    profile: Intel64TargetProfile {
                        id: TargetProfileId(1),
                        kind: Intel64ProfileKind::Custom,
                        features: FeatureSet {
                            features: Vec::new(),
                            xcr0: 0,
                        },
                    },
                },
            },
            backend: FakeBackend,
        }
    }

    #[test]
    fn bound_decoder_cannot_bypass_normalization() -> Result<(), XedAdapterError> {
        let decoded = decoder().decode(0x4000, &[0x90])?;
        assert_eq!(decoded.address, 0x4000);
        assert_eq!(decoded.length, 1);
        Ok(())
    }

    #[test]
    fn normalized_length_is_checked_against_input() {
        let result = decoder().decode(0x4000, &[]);
        assert_eq!(result, Err(XedAdapterError::EmptyInput));
    }
}
