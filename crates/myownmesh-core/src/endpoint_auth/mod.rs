//! Endpoint-authentication capability boundary for V4.
//!
//! This module states the boundary and re-exports the narrow internal types.
//! The work is owned by purpose-owned modules rather than gathered here:
//!
//! - [`context`] fixes what one task authenticates under, and derives the
//!   endpoint-authentication profile from the connector's closed binding;
//! - [`contribution`] owns the local draw and the accepted peer value;
//! - [`transcript`] owns the one signed framing and its role-canonical order;
//! - [`task`] owns the exchange: one draw, one bound peer contribution, one
//!   cached proof, one verified peer proof, and a terminal state;
//! - [`capability`] owns the issued capability and its private provenance.
//!
//! Endpoint authentication is transport independent. It names the generic
//! connector types — the handoff, the incarnation, and the binding — and
//! imports no `transport::webrtc` type. A future exporter, QUIC, serial, or
//! storage profile supplies another closed binding without changing the task.
//!
//! The channel-binding terms in the currently accepted profile are DTLS
//! certificate fingerprints, which are not session-unique; replay separation is
//! carried by per-attempt CSPRNG contributions and by connector-incarnation
//! ownership. See `BOUNDARY.md`.

mod capability;
mod context;
mod contribution;
/// Live two-connector controls over the production `on_auth_response` handler.
///
/// Basal V4 behaviour, so it is gated on `transport-lab` alone: deleting the
/// LegacyV1 compatibility subtree must not delete the only controls that prove
/// the production handler refuses a substituted channel binding.
#[cfg(all(test, feature = "transport-lab"))]
pub(crate) mod native_link;
mod task;
mod transcript;

#[cfg(test)]
pub(crate) use capability::authenticated_for_test;
pub use capability::{AuthenticatedChannelCapability, EndpointAuthPermit};
pub(crate) use context::EndpointAuthContext;
// The peer's canonical value is parsed on the production inbound path, so it
// stays a current re-export. The local draw is *not* exported for production
// use: generation belongs to `EndpointAuthTask`, which draws once per attempt
// and owns that value for its whole life, so the only crate-root callers are
// fixtures that need to mint a canonical value to feed a control. Gating it
// keeps that true — a production caller that started generating its own
// contribution outside the task would fail to resolve the name.
#[cfg(test)]
pub(crate) use contribution::LocalContribution;
pub(crate) use contribution::PeerContribution;
#[cfg(test)]
pub(crate) use task::{peer_proof_for_test, task_for_test, task_reusing_contribution_for_test};
pub(crate) use task::{AcceptedPeerHello, EndpointAuthTask, LocalIdentitySigner};
// The signed framing is deliberately *not* re-exported. It used to be, so that
// controls outside this module could rebuild the exact bytes it signs — but
// rebuilding them meant restating the mesh, profile, Device pair and channel
// binding, which is the substitution the task now exists to prevent. A control
// that needs the peer's half asks `peer_proof_for_test` for it instead, and gets
// bytes derived from the task's own context rather than from its own arguments.

/// Domain tag for every endpoint-authentication transcript.
///
/// Distinct from the legacy handshake tag, so a signature produced under one
/// can never verify under the other. Domain separation is what makes the hard
/// cutover safe: a peer speaking the old format fails to verify rather than
/// being offered a weaker format it could select.
pub(crate) const ENDPOINT_AUTH_DOMAIN_TAG: &str = "myownmesh-endpoint-auth-v1:";

/// Ordered endpoint roles for one exact authentication attempt.
///
/// The role is signed, so the two sides of one attempt produce different
/// transcripts. A responder cannot reflect the initiator's signature back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EndpointRole {
    Initiator,
    Responder,
}

impl EndpointRole {
    fn tag(self) -> &'static str {
        match self {
            Self::Initiator => "initiator",
            Self::Responder => "responder",
        }
    }

    pub(crate) fn peer(self) -> Self {
        match self {
            Self::Initiator => Self::Responder,
            Self::Responder => Self::Initiator,
        }
    }
}

/// Typed endpoint-authentication failure. Every variant is terminal for the
/// attempt: no variant leaves a partially promoted capability behind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EndpointAuthError {
    /// A required transcript field was empty.
    MissingTranscriptField,
    /// Local and remote Device IDs are equal, so no mutual proof exists.
    NotMutual,
    /// Both endpoints supplied the same contribution, so neither is fresh.
    ContributionNotFresh,
    /// A contribution did not decode to exactly the full draw width.
    ContributionTooShort,
    /// A contribution was not in the canonical lowercase BASE32-nopad
    /// encoding: it failed to decode, or it decoded from a non-canonical
    /// spelling of the same bytes.
    ContributionMalformed,
    /// The remote signature did not verify over the exact transcript.
    SignatureInvalid,
    /// The peer did not advertise the one closed endpoint-authentication
    /// profile, so there is no agreed transcript to prove anything over.
    ///
    /// Refused *before* any proof work: no transcript is built, no signature
    /// is produced or verified, and no capability can be minted. There is no
    /// fallback and no second profile to select, so this is terminal for the
    /// attempt rather than a step in a negotiation.
    IncompatibleProfile,
    /// The task's channel is gone: it was replaced or retired, or a previous
    /// attempt already consumed it.
    ///
    /// This is a security condition, not housekeeping. Because the channel
    /// binding is not session-unique, exact connector-incarnation ownership is
    /// what distinguishes two channels between the same pair — so refusing here
    /// is what defeats cross-channel relay.
    ///
    /// Reserved for retirement and currentness. A conflicting peer contribution
    /// is *not* one of these: the channel was current and the attempt intact,
    /// so it has its own cause in [`Self::ConflictingPeerContribution`].
    ChannelNotCurrent,
    /// A second, different peer contribution arrived after this attempt was
    /// already bound to one. Terminal for this exact task.
    ///
    /// Deliberately distinct from [`Self::ChannelNotCurrent`]. Nothing about
    /// the channel had gone stale: the attempt held its bound pair and its
    /// cached proof, and a value that is neither that pair's peer half nor an
    /// exact retransmission of it is an attempt to rebind an attempt that is
    /// already bound. Recording it as a currentness failure would file a
    /// peer-supplied conflict under the same cause as ordinary lifecycle
    /// teardown, and the two need to be told apart: one is a live peer sending
    /// something it cannot be sending, the other is this endpoint closing up.
    ///
    /// Retirement still follows — the conflict retires this exact task — but
    /// retirement is the consequence, not the cause, and the cause is what is
    /// kept.
    ConflictingPeerContribution,
}

/// The closed set of endpoint-authentication crypto profiles.
///
/// A closed enum rather than a caller string: the profile is bound into the
/// transcript so a peer cannot negotiate one profile and prove another. The
/// value is derived in [`context`] from the connector's closed binding profile,
/// never supplied by the engine or by a peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EndpointAuthProfile {
    /// Ed25519 device signatures over a DTLS-fingerprint-bound transcript.
    V1Ed25519Dtls,
}

/// Resolve the profile to prove under, from what the peer advertised.
///
/// Called before any transcript is built, so an unsupported peer costs no
/// signing or verification work. Returns the one closed profile or refuses;
/// there is deliberately no third outcome, because a "negotiation" that could
/// select a weaker profile is exactly what this must not become. Advertising
/// [`Feature::ENDPOINT_AUTH_V1`] is how a peer states it speaks the closed
/// profile, not how it chooses among alternatives.
pub(crate) fn negotiate_profile(
    peer_features: &[String],
) -> Result<EndpointAuthProfile, EndpointAuthError> {
    if crate::protocol::features::peer_supports(
        peer_features,
        crate::protocol::features::Feature::ENDPOINT_AUTH_V1,
    ) {
        Ok(EndpointAuthProfile::V1Ed25519Dtls)
    } else {
        Err(EndpointAuthError::IncompatibleProfile)
    }
}

impl EndpointAuthProfile {
    fn tag(self) -> &'static str {
        match self {
            Self::V1Ed25519Dtls => "ed25519-dtls-v1",
        }
    }
}

/// Arc 04 compatibility container.
///
/// The adapter accepts an already-issued capability. It cannot authenticate a
/// legacy value, and the raw value remains private to this owner module.
#[allow(
    dead_code,
    reason = "Arc 05 installs and deletes this migration adapter"
)]
pub(crate) struct LegacyAuthenticatedChannel<T> {
    capability: AuthenticatedChannelCapability,
    legacy: T,
}

#[allow(
    dead_code,
    reason = "Arc 05 installs and deletes this migration adapter"
)]
impl<T> LegacyAuthenticatedChannel<T> {
    pub(crate) fn new(capability: AuthenticatedChannelCapability, legacy: T) -> Self {
        Self { capability, legacy }
    }

    pub(crate) fn capability(&self) -> &AuthenticatedChannelCapability {
        &self.capability
    }

    fn into_parts(self) -> (AuthenticatedChannelCapability, T) {
        (self.capability, self.legacy)
    }
}
