#![forbid(unsafe_code)]

//! Intel XED adapter boundary. No XED-owned pointer or lifetime may cross this crate's public API.

use angryier_arch::{DecodedInstruction, Decoder};
use angryier_types::{Address, TargetProfileId};
use core::fmt::Debug;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum XedMachineMode {
    Intel64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct XedDecodeConfig {
    pub mode: XedMachineMode,
    pub target_profile: TargetProfileId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum XedAdapterError {
    NotLinked,
    DecodeFailed,
    UnsupportedMode,
    InvalidOperandMetadata,
    TargetProfileViolation,
}

/// Marker object for the eventual native XED-backed decoder.
/// The scaffold deliberately provides no fake decoder implementation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct XedDecoderAdapter {
    pub config: XedDecodeConfig,
}

/// Implemented only by the real XED bridge once native integration exists.
pub trait XedDecodeBackend: Debug + Send + Sync {
    fn decode_normalized(
        &self,
        config: XedDecodeConfig,
        address: Address,
        bytes: &[u8],
    ) -> Result<DecodedInstruction, XedAdapterError>;
}

/// Adapter wrapper allowing a real backend to satisfy the ISA-neutral decoder contract.
#[derive(Debug)]
pub struct BoundXedDecoder<B: XedDecodeBackend> {
    pub adapter: XedDecoderAdapter,
    pub backend: B,
}

impl<B: XedDecodeBackend> Decoder for BoundXedDecoder<B> {
    type Error = XedAdapterError;

    fn decode(&self, address: Address, bytes: &[u8]) -> Result<DecodedInstruction, Self::Error> {
        self.backend
            .decode_normalized(self.adapter.config, address, bytes)
    }
}
