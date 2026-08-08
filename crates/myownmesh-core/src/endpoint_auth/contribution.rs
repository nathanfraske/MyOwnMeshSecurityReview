//! Per-attempt contributions: one local draw, one accepted peer value.
//!
//! Moved here unchanged in behaviour from the combined module. Freshness is the
//! primary anti-replay mechanism for this profile, because the channel binding
//! is not session-unique, so the construction rules are invariants rather than
//! conventions: a local contribution can only come from the CSPRNG, and a peer
//! contribution is decoded rather than measured.

use super::EndpointAuthError;

/// A 32-byte draw encoded as lowercase BASE32 without padding.
pub(crate) const CONTRIBUTION_BYTES: usize = 32;

/// This endpoint's own per-attempt contribution.
///
/// Constructible **only** from a fresh CSPRNG draw. Deliberately not `Clone`: a
/// clone would let any crate code copy a stale value into a second attempt,
/// which is exactly the reuse the construction rule exists to prevent.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LocalContribution(String);

impl LocalContribution {
    /// Draw one fresh contribution from the OS CSPRNG.
    pub(crate) fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; CONTRIBUTION_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(data_encoding::BASE32_NOPAD.encode(&bytes).to_lowercase())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// Rebuild an exact prior contribution. **Controls only.**
    ///
    /// Compiled out of production entirely. The construction rule above is
    /// unchanged: outside `cfg(test)` `generate` remains the only constructor
    /// and this type stays non-`Clone`, so no production path can carry a stale
    /// value into a second attempt.
    ///
    /// This exists because one control has to build the exact case the rule
    /// prevents — two channels between one Device pair reusing the same
    /// certificates *and* the same contribution pair — in order to show what
    /// still holds there. Without it that control silently degenerates into an
    /// ordinary freshness check and stops proving anything about ownership.
    #[cfg(test)]
    pub(crate) fn reuse_for_test(value: &str) -> Self {
        Self(value.to_owned())
    }
}

/// The peer's per-attempt contribution, as received on the wire.
///
/// Decoded, not measured: a character count would accept any long-enough
/// string, which is a width check masquerading as a full-width contribution
/// guard. The round-trip comparison is what makes the encoding canonical rather
/// than merely decodable, so one draw has exactly one accepted wire form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PeerContribution(String);

impl PeerContribution {
    /// Accept exactly the canonical lowercase BASE32-nopad encoding of
    /// [`CONTRIBUTION_BYTES`] bytes.
    pub(crate) fn from_wire(value: &str) -> Result<Self, EndpointAuthError> {
        if value.is_empty() {
            return Err(EndpointAuthError::MissingTranscriptField);
        }
        let decoded = data_encoding::BASE32_NOPAD
            .decode(value.to_ascii_uppercase().as_bytes())
            .map_err(|_| EndpointAuthError::ContributionMalformed)?;
        if decoded.len() != CONTRIBUTION_BYTES {
            return Err(EndpointAuthError::ContributionTooShort);
        }
        if data_encoding::BASE32_NOPAD.encode(&decoded).to_lowercase() != value {
            return Err(EndpointAuthError::ContributionMalformed);
        }
        Ok(Self(value.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_arc04_local_contribution_is_fresh_per_draw() {
        // Freshness is the primary anti-replay mechanism for this profile,
        // because the channel binding is not session-unique. Two draws must
        // therefore differ, and each must be a full-width canonical value.
        let first = LocalContribution::generate();
        let second = LocalContribution::generate();

        assert_ne!(first, second);
        for drawn in [&first, &second] {
            PeerContribution::from_wire(drawn.as_str())
                .expect("a local draw is canonical on the wire");
        }
    }

    #[test]
    fn v4_arc04_peer_contribution_rejects_short_and_noncanonical_wire_values() {
        let drawn = LocalContribution::generate();
        let canonical = drawn.as_str();

        assert_eq!(
            PeerContribution::from_wire(""),
            Err(EndpointAuthError::MissingTranscriptField)
        );
        // A short value cannot carry a full-width draw, and accepting one would
        // silently shrink the freshness the transcript rests on.
        assert_eq!(
            PeerContribution::from_wire(&canonical[..canonical.len() - 2]),
            Err(EndpointAuthError::ContributionTooShort)
        );
        // Uppercase decodes to the same bytes but is not the canonical
        // spelling: one draw has exactly one accepted wire form.
        assert_eq!(
            PeerContribution::from_wire(&canonical.to_ascii_uppercase()),
            Err(EndpointAuthError::ContributionMalformed)
        );
        assert_eq!(
            PeerContribution::from_wire("not-base32!"),
            Err(EndpointAuthError::ContributionMalformed)
        );
        assert!(PeerContribution::from_wire(canonical).is_ok());
    }
}
