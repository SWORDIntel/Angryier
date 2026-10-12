//! Evidence-only handoff for the pinned, five-rule ISANITY EncodingBundle fixture.
//!
//! The bundle's `rule_id` is local to that producer snapshot. Its XED IFORM
//! name is source-version-scoped, not an Angryier semantic form id. All five
//! `canonical_form_id` fields are null, so matching a rule never authorizes
//! execution or selects a corpus provider. This module deliberately does not
//! alter the existing XED instruction-class mapping in `form_map`.

/// SHA-256 identity declared by the five-rule producer fixture. A regenerated
/// bundle requires a reviewed update here, not an implicit acceptance.
pub const FIXTURE_BUNDLE_SHA256: &str = "338a643bff7a590da04ff82af155cc7f39b999c903b9076a28296cf0d532d738";
/// Pinned upstream XED version shared by the producer and Angryier bridge.
pub const FIXTURE_XED_VERSION: &str = "0.6.0+xed-2024.05.20";

/// A source rule, not a canonical instruction or semantic form identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixtureRule {
    KmovbGprFromMask,
    KmovbMaskFromGpr,
    TileRelease,
    Hlt,
    Ud2,
}

impl FixtureRule {
    pub const fn rule_id(self) -> &'static str {
        match self {
            Self::KmovbGprFromMask => "xed-source-record-6697-vex2-low-register",
            Self::KmovbMaskFromGpr => "xed-source-record-6696-vex2-low-register",
            Self::TileRelease => "xed-source-record-7031-vex3-low-register",
            Self::Hlt => "xed-source-record-980-fixed-bytes",
            Self::Ud2 => "xed-source-record-1324-fixed-bytes",
        }
    }

    pub const fn source_iform(self) -> &'static str {
        match self {
            Self::KmovbGprFromMask => "XED_IFORM_KMOVB_GPR32u32_MASKmskw_AVX512",
            Self::KmovbMaskFromGpr => "XED_IFORM_KMOVB_MASKmskw_GPR32u32_AVX512",
            Self::TileRelease => "XED_IFORM_TILERELEASE",
            Self::Hlt => "XED_IFORM_HLT",
            Self::Ud2 => "XED_IFORM_UD2",
        }
    }

    fn from_rule_id(id: &str) -> Option<Self> {
        [
            Self::KmovbGprFromMask,
            Self::KmovbMaskFromGpr,
            Self::TileRelease,
            Self::Hlt,
            Self::Ud2,
        ]
        .into_iter()
        .find(|rule| rule.rule_id() == id)
    }

    fn matches_bytes(self, bytes: &[u8]) -> bool {
        match self {
            Self::KmovbGprFromMask => bytes.len() == 4 && bytes[..3] == [0xc5, 0xf9, 0x93] && bytes[3] & 0xc0 == 0xc0,
            Self::KmovbMaskFromGpr => bytes.len() == 4 && bytes[..3] == [0xc5, 0xf9, 0x92] && bytes[3] & 0xc0 == 0xc0,
            Self::TileRelease => bytes == [0xc4, 0xe2, 0x78, 0x49, 0xc0],
            Self::Hlt => bytes == [0xf4],
            Self::Ud2 => bytes == [0x0f, 0x0b],
        }
    }
}

/// Source-owned claim carried with bytes. `xed_iform` must be supplied from a
/// real decode if a caller wants to cross-check the producer observation.
/// Neither form of evidence grants semantic or feature-legality authority.
#[derive(Clone, Copy, Debug)]
pub struct FixtureHandoff<'a> {
    pub bundle_sha256: &'a str,
    pub xed_version: &'a str,
    pub rule_id: &'a str,
    pub source_iform: &'a str,
    pub mode: &'a str,
    pub bytes: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HandoffError {
    BundleRevisionMismatch,
    XedVersionMismatch,
    UnknownRule,
    SourceIformMismatch,
    ModeMismatch,
    ByteConstraintMismatch,
    LiveIformMismatch,
    /// A producer rule cannot be used as an Angryier semantic provider.
    CanonicalIdentityUnresolved,
}

/// Structurally and byte-validated evidence. Construction is private so
/// callers cannot accidentally bless arbitrary source strings or bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidatedFixtureEvidence {
    rule: FixtureRule,
}

impl ValidatedFixtureEvidence {
    pub const fn rule(self) -> FixtureRule {
        self.rule
    }

    /// The current fixture has no canonical FormID or semantic binding.
    /// This stays an error even when Angryier independently has a provider
    /// for the same XED instruction class.
    pub const fn semantic_form_id(self) -> Result<u32, HandoffError> {
        Err(HandoffError::CanonicalIdentityUnresolved)
    }

    /// Check a version-scoped IFORM returned by `XedDecoder::decode_with_iform`.
    /// This only strengthens the byte/source observation; it is not a provider
    /// or legality check.
    #[cfg(feature = "xed")]
    pub fn verify_live_xed_iform(self, iform: &angryier_arch_xed_ffi::XedIformMetadata) -> Result<Self, HandoffError> {
        if iform.xed_sys_version != "xed-sys 0.6.0+xed-2024.05.20" {
            return Err(HandoffError::XedVersionMismatch);
        }
        if iform.name != self.rule.source_iform() {
            return Err(HandoffError::LiveIformMismatch);
        }
        Ok(self)
    }
}

impl FixtureHandoff<'_> {
    pub fn validate(self) -> Result<ValidatedFixtureEvidence, HandoffError> {
        if self.bundle_sha256 != FIXTURE_BUNDLE_SHA256 {
            return Err(HandoffError::BundleRevisionMismatch);
        }
        if self.xed_version != FIXTURE_XED_VERSION {
            return Err(HandoffError::XedVersionMismatch);
        }
        let rule = FixtureRule::from_rule_id(self.rule_id).ok_or(HandoffError::UnknownRule)?;
        if self.source_iform != rule.source_iform() {
            return Err(HandoffError::SourceIformMismatch);
        }
        if self.mode != "long64" {
            return Err(HandoffError::ModeMismatch);
        }
        if !rule.matches_bytes(self.bytes) {
            return Err(HandoffError::ByteConstraintMismatch);
        }
        Ok(ValidatedFixtureEvidence { rule })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handoff(rule: FixtureRule, bytes: &[u8]) -> FixtureHandoff<'_> {
        FixtureHandoff {
            bundle_sha256: FIXTURE_BUNDLE_SHA256,
            xed_version: FIXTURE_XED_VERSION,
            rule_id: rule.rule_id(),
            source_iform: rule.source_iform(),
            mode: "long64",
            bytes,
        }
    }

    #[test]
    fn five_source_rules_remain_evidence_only() {
        for (rule, bytes) in [
            (FixtureRule::KmovbGprFromMask, &[0xc5, 0xf9, 0x93, 0xee][..]),
            (FixtureRule::KmovbMaskFromGpr, &[0xc5, 0xf9, 0x92, 0xef]),
            (FixtureRule::TileRelease, &[0xc4, 0xe2, 0x78, 0x49, 0xc0]),
            (FixtureRule::Hlt, &[0xf4]),
            (FixtureRule::Ud2, &[0x0f, 0x0b]),
        ] {
            let evidence = handoff(rule, bytes).validate().unwrap();
            assert_eq!(evidence.rule(), rule);
            assert_eq!(
                evidence.semantic_form_id(),
                Err(HandoffError::CanonicalIdentityUnresolved)
            );
        }
    }

    #[test]
    fn mismatched_namespace_revision_mode_and_bytes_are_rejected() {
        let mut claim = handoff(FixtureRule::KmovbGprFromMask, &[0xc5, 0xf9, 0x93, 0xee]);
        claim.source_iform = FixtureRule::KmovbMaskFromGpr.source_iform();
        assert_eq!(claim.validate(), Err(HandoffError::SourceIformMismatch));
        claim.source_iform = FixtureRule::KmovbGprFromMask.source_iform();
        claim.bundle_sha256 = "different";
        assert_eq!(claim.validate(), Err(HandoffError::BundleRevisionMismatch));
        claim.bundle_sha256 = FIXTURE_BUNDLE_SHA256;
        claim.mode = "legacy32";
        assert_eq!(claim.validate(), Err(HandoffError::ModeMismatch));
        claim.mode = "long64";
        claim.bytes = &[0xc5, 0xf9, 0x93, 0x2e];
        assert_eq!(claim.validate(), Err(HandoffError::ByteConstraintMismatch));
    }

    #[test]
    fn modrm_projection_is_bounded_and_fixed_rules_are_exact() {
        for modrm in 0u8..=255 {
            let bytes = [0xc5, 0xf9, 0x93, modrm];
            assert_eq!(
                handoff(FixtureRule::KmovbGprFromMask, &bytes).validate().is_ok(),
                modrm & 0xc0 == 0xc0
            );
        }
        assert_eq!(
            handoff(FixtureRule::TileRelease, &[0xc4, 0xe2, 0x78, 0x49, 0xc1]).validate(),
            Err(HandoffError::ByteConstraintMismatch)
        );
        assert_eq!(
            handoff(FixtureRule::Hlt, &[0x66, 0xf4]).validate(),
            Err(HandoffError::ByteConstraintMismatch)
        );
    }

    #[cfg(feature = "xed")]
    #[test]
    fn live_xed_iforms_join_the_five_source_witnesses() {
        let decoder = angryier_arch_xed_ffi::XedDecoder::new();
        for (rule, bytes) in [
            (FixtureRule::KmovbGprFromMask, &[0xc5, 0xf9, 0x93, 0xee][..]),
            (FixtureRule::KmovbMaskFromGpr, &[0xc5, 0xf9, 0x92, 0xef]),
            (FixtureRule::TileRelease, &[0xc4, 0xe2, 0x78, 0x49, 0xc0]),
            (FixtureRule::Hlt, &[0xf4]),
            (FixtureRule::Ud2, &[0x0f, 0x0b]),
        ] {
            let (_, iform) = decoder.decode_with_iform(0x1000, bytes).unwrap();
            handoff(rule, bytes)
                .validate()
                .unwrap()
                .verify_live_xed_iform(&iform)
                .unwrap();
        }
    }
}
