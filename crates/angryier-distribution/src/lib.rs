#![forbid(unsafe_code)]

use std::fmt;

use angryier_types::{
    AnalysisContext, ContentId, DependencyKey, FidelityProfile, RetentionProfile, RunId, SecurityContext, StateId,
    TargetProfileId, WorkUnitId,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkEnvelope {
    pub work: WorkUnitId,
    pub context: AnalysisContext,
    pub state: StateId,
    pub semantic_content: ContentId,
    pub validity: Vec<DependencyKey>,
    pub payload: Vec<u8>,
}

pub trait WorkCodec: Send + Sync {
    type Error;
    fn encode(&self, work: &WorkEnvelope) -> Result<Vec<u8>, Self::Error>;
    fn decode(&self, bytes: &[u8]) -> Result<WorkEnvelope, Self::Error>;
}

/// Errors produced by the in-memory distribution codec.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DistributionError {
    /// The envelope carried no payload bytes.
    EmptyPayload,
    /// The frame magic bytes did not match the expected header.
    InvalidFrame,
    /// The byte stream ended before a complete frame could be read.
    Truncated,
    /// The shared state could not be read because it was poisoned.
    Poisoned,
}

impl fmt::Display for DistributionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPayload => f.write_str("distribution envelope payload is empty"),
            Self::InvalidFrame => f.write_str("distribution frame has invalid magic bytes"),
            Self::Truncated => f.write_str("distribution frame is truncated"),
            Self::Poisoned => f.write_str("distribution state is poisoned"),
        }
    }
}

impl std::error::Error for DistributionError {}

/// Magic bytes prefixing every encoded [`WorkEnvelope`] frame.
const FRAME_MAGIC: &[u8; 4] = b"WORK";

/// Fixed-size header length (in bytes) preceding the variable-length sections.
///   4  magic
/// + 8  work
/// + 8  run_id
/// + 8  target_profile
/// + 1  fidelity
/// + 1  retention
/// + 4  classification
/// + 4  compartment
/// + 8  state
/// + 32 semantic_content
/// + 4  validity count
const HEADER_LEN: usize = 4 + 8 + 8 + 8 + 1 + 1 + 4 + 4 + 8 + 32 + 4;

/// In-memory, deterministic binary codec for [`WorkEnvelope`].
///
/// The frame layout is intentionally simple and fixed-width for the header so
/// that decoding can validate length up front without scanning. This backend
/// is intended for single-process use and tests; it performs no compression,
/// encryption, or network framing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InMemoryWorkCodec;

impl InMemoryWorkCodec {
    /// Creates a new in-memory codec.
    pub const fn new() -> Self {
        Self
    }

    fn fidelity_to_byte(fidelity: FidelityProfile) -> u8 {
        match fidelity {
            FidelityProfile::Prove => 0,
            FidelityProfile::Explore => 1,
            FidelityProfile::Hunt => 2,
        }
    }

    fn retention_to_byte(retention: RetentionProfile) -> u8 {
        match retention {
            RetentionProfile::Forensic => 0,
            RetentionProfile::Research => 1,
            RetentionProfile::Benchmark => 2,
            RetentionProfile::Disposable => 3,
        }
    }

    fn byte_to_fidelity(byte: u8) -> Result<FidelityProfile, DistributionError> {
        match byte {
            0 => Ok(FidelityProfile::Prove),
            1 => Ok(FidelityProfile::Explore),
            2 => Ok(FidelityProfile::Hunt),
            _ => Err(DistributionError::InvalidFrame),
        }
    }

    fn byte_to_retention(byte: u8) -> Result<RetentionProfile, DistributionError> {
        match byte {
            0 => Ok(RetentionProfile::Forensic),
            1 => Ok(RetentionProfile::Research),
            2 => Ok(RetentionProfile::Benchmark),
            3 => Ok(RetentionProfile::Disposable),
            _ => Err(DistributionError::InvalidFrame),
        }
    }
}

impl WorkCodec for InMemoryWorkCodec {
    type Error = DistributionError;

    fn encode(&self, work: &WorkEnvelope) -> Result<Vec<u8>, Self::Error> {
        if work.payload.is_empty() {
            return Err(DistributionError::EmptyPayload);
        }

        let mut buf: Vec<u8> = Vec::with_capacity(HEADER_LEN + work.validity.len() * 32 + 4 + work.payload.len());

        // Magic
        buf.extend_from_slice(FRAME_MAGIC);
        // work unit id
        buf.extend_from_slice(&work.work.0.to_le_bytes());
        // context.run_id
        buf.extend_from_slice(&work.context.run_id.0.to_le_bytes());
        // context.target_profile
        buf.extend_from_slice(&work.context.target_profile.0.to_le_bytes());
        // fidelity
        buf.push(Self::fidelity_to_byte(work.context.fidelity));
        // retention
        buf.push(Self::retention_to_byte(work.context.retention));
        // security.classification
        buf.extend_from_slice(&work.context.security.classification.to_le_bytes());
        // security.compartment
        buf.extend_from_slice(&work.context.security.compartment.to_le_bytes());
        // state id
        buf.extend_from_slice(&work.state.0.to_le_bytes());
        // semantic_content
        buf.extend_from_slice(&work.semantic_content.0);
        // validity count
        let validity_count: u32 = work
            .validity
            .len()
            .try_into()
            .map_err(|_| DistributionError::InvalidFrame)?;
        buf.extend_from_slice(&validity_count.to_le_bytes());
        // validity keys
        for key in &work.validity {
            buf.extend_from_slice(&key.0);
        }
        // payload length
        let payload_len: u32 = work
            .payload
            .len()
            .try_into()
            .map_err(|_| DistributionError::InvalidFrame)?;
        buf.extend_from_slice(&payload_len.to_le_bytes());
        // payload bytes
        buf.extend_from_slice(&work.payload);

        Ok(buf)
    }

    fn decode(&self, bytes: &[u8]) -> Result<WorkEnvelope, Self::Error> {
        // Empty input is treated as truncated rather than invalid magic, since
        // there are no bytes to compare against the magic header.
        if bytes.is_empty() {
            return Err(DistributionError::Truncated);
        }

        // Validate magic.
        let magic: &[u8; 4] = bytes
            .get(0..4)
            .and_then(|s| s.try_into().ok())
            .ok_or(DistributionError::Truncated)?;
        if magic != FRAME_MAGIC {
            return Err(DistributionError::InvalidFrame);
        }

        // Validate the fixed header is fully present.
        if bytes.len() < HEADER_LEN {
            return Err(DistributionError::Truncated);
        }

        let mut cursor: usize = 4;

        let work: WorkUnitId = {
            let arr: [u8; 8] = bytes
                .get(cursor..cursor + 8)
                .and_then(|s| s.try_into().ok())
                .ok_or(DistributionError::Truncated)?;
            cursor += 8;
            WorkUnitId(u64::from_le_bytes(arr))
        };

        let run_id: RunId = {
            let arr: [u8; 8] = bytes
                .get(cursor..cursor + 8)
                .and_then(|s| s.try_into().ok())
                .ok_or(DistributionError::Truncated)?;
            cursor += 8;
            RunId(u64::from_le_bytes(arr))
        };

        let target_profile: TargetProfileId = {
            let arr: [u8; 8] = bytes
                .get(cursor..cursor + 8)
                .and_then(|s| s.try_into().ok())
                .ok_or(DistributionError::Truncated)?;
            cursor += 8;
            TargetProfileId(u64::from_le_bytes(arr))
        };

        let fidelity: FidelityProfile = {
            let byte: u8 = *bytes.get(cursor).ok_or(DistributionError::Truncated)?;
            cursor += 1;
            Self::byte_to_fidelity(byte)?
        };

        let retention: RetentionProfile = {
            let byte: u8 = *bytes.get(cursor).ok_or(DistributionError::Truncated)?;
            cursor += 1;
            Self::byte_to_retention(byte)?
        };

        let classification: u32 = {
            let arr: [u8; 4] = bytes
                .get(cursor..cursor + 4)
                .and_then(|s| s.try_into().ok())
                .ok_or(DistributionError::Truncated)?;
            cursor += 4;
            u32::from_le_bytes(arr)
        };

        let compartment: u32 = {
            let arr: [u8; 4] = bytes
                .get(cursor..cursor + 4)
                .and_then(|s| s.try_into().ok())
                .ok_or(DistributionError::Truncated)?;
            cursor += 4;
            u32::from_le_bytes(arr)
        };

        let state: StateId = {
            let arr: [u8; 8] = bytes
                .get(cursor..cursor + 8)
                .and_then(|s| s.try_into().ok())
                .ok_or(DistributionError::Truncated)?;
            cursor += 8;
            StateId(u64::from_le_bytes(arr))
        };

        let semantic_content: ContentId = {
            let arr: [u8; 32] = bytes
                .get(cursor..cursor + 32)
                .and_then(|s| s.try_into().ok())
                .ok_or(DistributionError::Truncated)?;
            cursor += 32;
            ContentId(arr)
        };

        let validity_count: usize = {
            let arr: [u8; 4] = bytes
                .get(cursor..cursor + 4)
                .and_then(|s| s.try_into().ok())
                .ok_or(DistributionError::Truncated)?;
            cursor += 4;
            u32::from_le_bytes(arr) as usize
        };

        // Validate validity keys section is fully present.
        let validity_bytes_needed: usize = validity_count.checked_mul(32).ok_or(DistributionError::InvalidFrame)?;
        if bytes.len() < cursor + validity_bytes_needed + 4 {
            return Err(DistributionError::Truncated);
        }

        let mut validity: Vec<DependencyKey> = Vec::with_capacity(validity_count);
        for _ in 0..validity_count {
            let arr: [u8; 32] = bytes
                .get(cursor..cursor + 32)
                .and_then(|s| s.try_into().ok())
                .ok_or(DistributionError::Truncated)?;
            cursor += 32;
            validity.push(DependencyKey(arr));
        }

        let payload_len: usize = {
            let arr: [u8; 4] = bytes
                .get(cursor..cursor + 4)
                .and_then(|s| s.try_into().ok())
                .ok_or(DistributionError::Truncated)?;
            cursor += 4;
            u32::from_le_bytes(arr) as usize
        };

        let payload: Vec<u8> = {
            let slice: &[u8] = bytes
                .get(cursor..cursor + payload_len)
                .ok_or(DistributionError::Truncated)?;
            slice.to_vec()
        };

        if payload.is_empty() {
            return Err(DistributionError::EmptyPayload);
        }

        Ok(WorkEnvelope {
            work,
            context: AnalysisContext {
                run_id,
                target_profile,
                fidelity,
                retention,
                security: SecurityContext {
                    classification,
                    compartment,
                },
            },
            state,
            semantic_content,
            validity,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_envelope() -> WorkEnvelope {
        WorkEnvelope {
            work: WorkUnitId(0x0123_4567_89ab_cdef),
            context: AnalysisContext {
                run_id: RunId(0x1111_2222_3333_4444),
                target_profile: TargetProfileId(0x5555_6666_7777_8888),
                fidelity: FidelityProfile::Explore,
                retention: RetentionProfile::Research,
                security: SecurityContext {
                    classification: 0x2143_6587,
                    compartment: 0x7856_3412,
                },
            },
            state: StateId(0xabcd_ef01_2345_6789),
            semantic_content: ContentId([
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
                28, 29, 30, 31,
            ]),
            validity: vec![DependencyKey([0xaa; 32])],
            payload: b"hello-distribution".to_vec(),
        }
    }

    /// Encodes `envelope` with `codec`, asserting success and returning the bytes.
    fn encode_ok(codec: &InMemoryWorkCodec, envelope: &WorkEnvelope) -> Vec<u8> {
        let encoded = codec.encode(envelope);
        assert!(encoded.is_ok());
        encoded.unwrap_or_default()
    }

    #[test]
    fn round_trip_preserves_envelope() {
        let codec = InMemoryWorkCodec::new();
        let original = sample_envelope();
        let bytes = encode_ok(&codec, &original);
        let decoded = codec.decode(&bytes);
        assert!(decoded.is_ok());
        if let Ok(env) = decoded {
            assert_eq!(env, original);
        }
    }

    #[test]
    fn encode_produces_non_empty_bytes() {
        let codec = InMemoryWorkCodec::new();
        let bytes = encode_ok(&codec, &sample_envelope());
        assert!(!bytes.is_empty());
        assert!(bytes.len() > HEADER_LEN);
    }

    #[test]
    fn decode_with_bad_magic_fails() {
        let codec = InMemoryWorkCodec::new();
        let mut bytes = encode_ok(&codec, &sample_envelope());
        // Corrupt the magic bytes.
        if let Some(first) = bytes.get_mut(0) {
            *first = 0xff;
        }
        let decoded = codec.decode(&bytes);
        assert_eq!(decoded, Err(DistributionError::InvalidFrame));
    }

    #[test]
    fn decode_with_truncated_frame_fails() {
        let codec = InMemoryWorkCodec::new();
        let full = encode_ok(&codec, &sample_envelope());
        // Keep only the header plus a few bytes (no payload).
        let truncated: Vec<u8> = full.get(0..HEADER_LEN).map(|s| s.to_vec()).unwrap_or_default();
        let decoded = codec.decode(&truncated);
        assert_eq!(decoded, Err(DistributionError::Truncated));
    }

    #[test]
    fn decode_of_empty_bytes_fails() {
        let codec = InMemoryWorkCodec::new();
        let decoded = codec.decode(&[]);
        assert_eq!(decoded, Err(DistributionError::Truncated));
    }

    #[test]
    fn round_trip_with_zero_validity_keys() {
        let codec = InMemoryWorkCodec::new();
        let mut original = sample_envelope();
        original.validity.clear();
        let bytes = encode_ok(&codec, &original);
        let decoded = codec.decode(&bytes);
        assert!(decoded.is_ok());
        if let Ok(env) = decoded {
            assert_eq!(env, original);
            assert!(env.validity.is_empty());
        }
    }

    #[test]
    fn round_trip_with_multiple_validity_keys() {
        let codec = InMemoryWorkCodec::new();
        let mut original = sample_envelope();
        original.validity = vec![
            DependencyKey([0x01; 32]),
            DependencyKey([0x02; 32]),
            DependencyKey([0x03; 32]),
            DependencyKey([0x04; 32]),
        ];
        let bytes = encode_ok(&codec, &original);
        let decoded = codec.decode(&bytes);
        assert!(decoded.is_ok());
        if let Ok(env) = decoded {
            assert_eq!(env, original);
            assert_eq!(env.validity.len(), 4);
        }
    }

    #[test]
    fn encode_rejects_empty_payload() {
        let codec = InMemoryWorkCodec::new();
        let mut original = sample_envelope();
        original.payload.clear();
        let encoded = codec.encode(&original);
        assert_eq!(encoded, Err(DistributionError::EmptyPayload));
    }

    #[test]
    fn round_trip_with_non_empty_payload() {
        let codec = InMemoryWorkCodec::new();
        let mut original = sample_envelope();
        original.payload = (0u16..512).map(|i| (i & 0xff) as u8).collect();
        let bytes = encode_ok(&codec, &original);
        let decoded = codec.decode(&bytes);
        assert!(decoded.is_ok());
        if let Ok(env) = decoded {
            assert_eq!(env, original);
            assert_eq!(env.payload.len(), 512);
        }
    }

    #[test]
    fn different_envelopes_produce_different_encodings() {
        let codec = InMemoryWorkCodec::new();
        let first = sample_envelope();
        let mut second = sample_envelope();
        second.work = WorkUnitId(0xffff_ffff_ffff_ffff);
        let first_bytes = encode_ok(&codec, &first);
        let second_bytes = encode_ok(&codec, &second);
        assert_ne!(first_bytes, second_bytes);
    }

    #[test]
    fn decode_rejects_truncated_within_validity_section() {
        let codec = InMemoryWorkCodec::new();
        let mut original = sample_envelope();
        original.validity = vec![DependencyKey([0x09; 32]), DependencyKey([0x0a; 32])];
        let full = encode_ok(&codec, &original);
        // Drop the last few bytes so the validity section / payload is incomplete.
        let cut: usize = full.len().saturating_sub(10);
        let truncated: Vec<u8> = full.get(0..cut).map(|s| s.to_vec()).unwrap_or_default();
        let decoded = codec.decode(&truncated);
        assert_eq!(decoded, Err(DistributionError::Truncated));
    }

    #[test]
    fn decode_rejects_truncated_payload_section() {
        let codec = InMemoryWorkCodec::new();
        let original = sample_envelope();
        let full = encode_ok(&codec, &original);
        // Remove the final payload byte; the declared length will exceed available bytes.
        let cut: usize = full.len().saturating_sub(1);
        let truncated: Vec<u8> = full.get(0..cut).map(|s| s.to_vec()).unwrap_or_default();
        let decoded = codec.decode(&truncated);
        assert_eq!(decoded, Err(DistributionError::Truncated));
    }

    #[test]
    fn decode_rejects_bad_fidelity_byte() {
        let codec = InMemoryWorkCodec::new();
        let mut bytes = encode_ok(&codec, &sample_envelope());
        // Fidelity byte sits right after the two 8-byte id fields following magic.
        // Offset: 4 (magic) + 8 (work) + 8 (run_id) + 8 (target) = 28.
        if let Some(b) = bytes.get_mut(28) {
            *b = 0x7f;
        }
        let decoded = codec.decode(&bytes);
        assert_eq!(decoded, Err(DistributionError::InvalidFrame));
    }

    #[test]
    fn decode_rejects_bad_retention_byte() {
        let codec = InMemoryWorkCodec::new();
        let mut bytes = encode_ok(&codec, &sample_envelope());
        // Retention byte follows the fidelity byte at offset 29.
        if let Some(b) = bytes.get_mut(29) {
            *b = 0x7f;
        }
        let decoded = codec.decode(&bytes);
        assert_eq!(decoded, Err(DistributionError::InvalidFrame));
    }

    #[test]
    fn display_messages_are_non_empty() {
        let variants = [
            DistributionError::EmptyPayload,
            DistributionError::InvalidFrame,
            DistributionError::Truncated,
            DistributionError::Poisoned,
        ];
        for v in variants {
            let msg: String = v.to_string();
            assert!(!msg.is_empty());
        }
    }
}
