//! Endpoint-authentication capability boundary for V4.
//!
//! Arc 04 has landed the transcript and the production issuer.
//! [`EndpointAuthTask::authenticate`] is the sole path that promotes a
//! connected channel to an [`AuthenticatedChannelCapability`], and the live
//! Hello/AuthResponse handlers drive it.
//!
//! The channel-binding terms are DTLS certificate fingerprints, which are not
//! session-unique; replay separation is carried by per-attempt CSPRNG
//! contributions and by connector-incarnation ownership. See `BOUNDARY.md`.
//! Landing this makes the arc reachable — it does not mark it complete, which
//! still requires the gate controls to be executed and audited.

use crate::connector::ConnectedChannelCapability;
use crate::runtime::RuntimeIncarnation;
use crate::transport::{EndpointAuthHandoff, WebRtcConnectorIncarnation};
use std::sync::{Arc, Mutex};

/// The one runtime owner that receives a newly working channel before any
/// authentication frame may be emitted or consumed. Arc 04 replaces the
/// legacy handshake body, but Arc 03 makes this ownership handoff mandatory.
pub(crate) struct EndpointAuthTask {
    /// Retained separately from the handoff, so the task still names its exact
    /// connector incarnation after promotion has moved the handoff out. Install
    /// needs that to prove a capability came from *this* channel.
    incarnation: Arc<WebRtcConnectorIncarnation>,
    /// Explicit lifecycle, kept separate from handoff presence.
    ///
    /// Handoff presence cannot stand in for liveness: a successful promotion
    /// moves the handoff out, so an identity test based on it would report a
    /// freshly authenticated task as not belonging to its own connector and
    /// break every downstream compatibility path. Pointer equality alone has
    /// the opposite fault — an explicitly retired task would still look live.
    retired: std::sync::atomic::AtomicBool,
    connected: Mutex<Option<EndpointAuthHandoff>>,
}

impl EndpointAuthTask {
    pub(crate) fn begin(connected: EndpointAuthHandoff) -> Self {
        Self {
            incarnation: Arc::clone(connected.incarnation()),
            retired: std::sync::atomic::AtomicBool::new(false),
            connected: Mutex::new(Some(connected)),
        }
    }

    pub(crate) fn is_retired(&self) -> bool {
        self.retired.load(std::sync::atomic::Ordering::Acquire)
    }

    /// The exact connector incarnation this task authenticates for.
    pub(crate) fn incarnation(&self) -> &Arc<WebRtcConnectorIncarnation> {
        &self.incarnation
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<EndpointAuthHandoff>> {
        self.connected
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Identity, not handoff presence: a task that has successfully promoted
    /// still belongs to its connector, while a retired one belongs to none.
    pub(crate) fn belongs_to(&self, incarnation: &Arc<WebRtcConnectorIncarnation>) -> bool {
        !self.is_retired() && Arc::ptr_eq(&self.incarnation, incarnation)
    }

    /// Retire this task's handoff.
    ///
    /// Dropping the handoff runs its retention, so a retired task releases the
    /// channel claim rather than stranding it. A retired task can never
    /// authenticate again, which is what makes channel replacement invalidate
    /// in-flight authentication rather than racing it.
    pub(crate) fn retire(&self) {
        // Marked before the handoff is released, so no observer can see a task
        // that has lost its channel but still reports itself live.
        self.retired
            .store(true, std::sync::atomic::Ordering::Release);
        drop(self.lock().take());
    }

    /// The one production path that issues an [`EndpointAuthPermit`] and an
    /// [`AuthenticatedChannelCapability`].
    ///
    /// Ownership contract, which is load-bearing because the channel binding
    /// is not session-unique: every check runs against a **borrowed**
    /// capability, the capability is taken exactly once only after both halves
    /// have verified, and any failure after the take hands it back so the
    /// handoff's retention still runs. A refused attempt therefore leaves the
    /// channel exactly as it found it.
    /// ## Why this takes no runtime argument
    ///
    /// The permit is minted from the connected capability's own runtime, so
    /// [`EndpointAuthError::RuntimeMismatch`] is **unreachable from this
    /// path**. The engine holds no `RuntimeIncarnation` of its own to compare
    /// against, so a parameter here could only be sourced from the very
    /// capability it would be checked against. That check still guards the
    /// move-only [`EndpointAuthAttempt::begin`] constructor, where a caller
    /// can supply a mismatched pair — it must not be cited as a production
    /// control on this path.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn authenticate(
        &self,
        mesh_context: &str,
        profile: EndpointAuthProfile,
        local_device_id: &str,
        remote_device_id: &str,
        local_contribution: &LocalContribution,
        remote_contribution: &PeerContribution,
        local_fingerprint: &str,
        remote_fingerprint: &str,
        local_signature: &str,
        remote_signature: &str,
    ) -> Result<AuthenticatedChannelCapability, EndpointAuthError> {
        let mut guard = self.lock();
        let permit;
        let local_role = {
            let handoff = guard.as_ref().ok_or(EndpointAuthError::ChannelNotCurrent)?;
            let capability = handoff
                .capability()
                .ok_or(EndpointAuthError::ChannelNotCurrent)?;
            permit = EndpointAuthPermit::admitted(capability.runtime().clone());
            EndpointAuthAttempt::check(
                capability,
                &permit,
                mesh_context,
                profile,
                local_device_id,
                remote_device_id,
                local_contribution,
                remote_contribution,
                local_fingerprint,
                remote_fingerprint,
                local_signature,
            )?
        };
        // Only now, with every borrow-checkable condition satisfied. The
        // *whole* handoff moves, so the close owner and its retention travel
        // with the promotion rather than being stripped off it.
        let handoff = guard.take().ok_or(EndpointAuthError::ChannelNotCurrent)?;
        let attempt = EndpointAuthAttempt::commit(
            PromotedChannelOwner::Handoff(handoff),
            permit,
            mesh_context,
            profile,
            local_role,
            local_device_id,
            remote_device_id,
            local_contribution,
            remote_contribution,
            local_fingerprint,
            remote_fingerprint,
        );
        match attempt.verify_remote_returning(remote_signature) {
            Ok(authenticated) => Ok(authenticated),
            Err((owner, error)) => {
                // The peer half failed. Put the whole handoff back, so the
                // task still owns a retainable claim and a later retirement
                // still drives native close exactly once.
                match owner {
                    PromotedChannelOwner::Handoff(handoff) => *guard = Some(handoff),
                    #[cfg(test)]
                    PromotedChannelOwner::Bare(_) => {
                        unreachable!("this path always commits a handoff owner")
                    }
                }
                Err(error)
            }
        }
    }
}

/// Attestation of the connected-channel ownership an attempt is built on.
///
/// Deliberately **not** described as proof that bounded work was admitted:
/// there is no independent Arc 04 resource admission. The production
/// constructor derives this from the runtime of the `ConnectedChannelCapability`
/// the task already owns, so what it carries is that existing ownership. A real
/// pre-authentication admission remains unimplemented, and this type must not
/// be cited as evidence of one.
///
/// The type has no public constructor, serialization, or cloning path.
pub struct EndpointAuthPermit {
    runtime: RuntimeIncarnation,
}

impl EndpointAuthPermit {
    /// Private to this module, and reached only through
    /// [`EndpointAuthTask::authenticate`], so the task is the sole issuer.
    fn admitted(runtime: RuntimeIncarnation) -> Self {
        Self { runtime }
    }

    #[cfg(test)]
    fn admitted_for_test(runtime: RuntimeIncarnation) -> Self {
        Self::admitted(runtime)
    }
}

/// Local proof that both Device identities were freshly authenticated on one
/// exact connected channel.
///
/// Issued only by [`EndpointAuthTask::authenticate`], after both halves of the
/// channel-bound transcript verify. It has no public constructor, so a
/// connected channel cannot become an authenticated one by any other route.
///
/// Its validity is scoped to one connector incarnation: `PeerConnection` drops
/// it when that connector is retired or replaced. That is load-bearing rather
/// than tidy, because the certificate-fingerprint binding is not
/// session-unique — see the residual in `BOUNDARY.md`.
///
/// A connected channel has no implicit conversion into authentication:
///
/// ```compile_fail,E0308
/// use myownmesh_core::connector::ConnectedChannelCapability;
/// use myownmesh_core::endpoint_auth::AuthenticatedChannelCapability;
///
/// fn connected() -> ConnectedChannelCapability { unimplemented!() }
/// fn requires_authentication(_: AuthenticatedChannelCapability) {}
///
/// requires_authentication(connected());
/// ```
pub struct AuthenticatedChannelCapability {
    owner: PromotedChannelOwner,
    permit: EndpointAuthPermit,
}

impl AuthenticatedChannelCapability {
    /// The runtime this capability is bound to.
    ///
    /// Read from the permit, which was minted from the connected capability's
    /// own runtime and proven equal to it during verification.
    pub(crate) fn runtime(&self) -> &RuntimeIncarnation {
        &self.permit.runtime
    }

    /// Whether this capability was promoted from that exact connector
    /// incarnation.
    ///
    /// Install must check this, not merely that the *task* it was handed is
    /// current. Checking the task alone would accept a capability promoted
    /// from a superseded channel as long as the caller passed the current
    /// task alongside it — which is precisely the cross-channel relay the
    /// non-session-unique binding cannot rule out on its own.
    pub(crate) fn belongs_to(&self, incarnation: &Arc<WebRtcConnectorIncarnation>) -> bool {
        self.owner.belongs_to(incarnation)
    }
}

/// Move-only ownership of the channel a promotion is built on.
///
/// Promotion must carry the **whole** handoff, not just the connected
/// capability inside it. The handoff is what holds the connector incarnation
/// and the close owner, and its `Drop` is what re-retains the connected claim
/// so it survives until native close succeeds. Moving only the capability out
/// would strip that retention, and dropping an authenticated capability — on
/// connector retirement, or on a refused install — would then release the
/// claim early, regressing the Arc 03 invariant.
pub(crate) enum PromotedChannelOwner {
    /// The production shape: dropping this runs the handoff's retention.
    Handoff(EndpointAuthHandoff),
    /// Test-only. Direct attempts built from a bare capability have no close
    /// owner to retain through, so this variant exists solely so unit tests
    /// can exercise transcript logic without a connector fixture. It is never
    /// constructed in a production build.
    #[cfg(test)]
    Bare(ConnectedChannelCapability),
}

impl PromotedChannelOwner {
    /// Borrow the connected capability, if this owner still holds one.
    ///
    /// Test-only. Production reaches the capability through
    /// [`EndpointAuthHandoff::capability`] on the handoff itself, before the
    /// handoff is moved into a [`PromotedChannelOwner`].
    #[cfg(test)]
    fn capability(&self) -> Option<&ConnectedChannelCapability> {
        match self {
            Self::Handoff(handoff) => handoff.capability(),
            #[cfg(test)]
            Self::Bare(capability) => Some(capability),
        }
    }

    fn belongs_to(&self, incarnation: &Arc<WebRtcConnectorIncarnation>) -> bool {
        match self {
            Self::Handoff(handoff) => handoff.belongs_to(incarnation),
            // A bare test capability has no connector incarnation, so it
            // belongs to none. Production installs cannot see this variant.
            #[cfg(test)]
            Self::Bare(_) => false,
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

/// Domain tag for the Arc 04 endpoint-authentication transcript.
///
/// Deliberately distinct from [`crate::SIGN_DOMAIN_TAG`], which covered the
/// legacy Arc 03 handshake payload. Domain separation means an Arc 03
/// handshake signature can never be replayed as an Arc 04 endpoint-auth
/// signature.
///
/// The live Hello/AuthResponse handlers now sign and verify **this**
/// transcript, so the legacy payload semantics are no longer in use on that
/// path; only the frame envelope is retained. A peer still producing the old
/// signature simply fails to verify — it is not an accepted fallback, and
/// there is nothing for an attacker to select between.
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
    /// A contribution did not decode to exactly [`CONTRIBUTION_BYTES`] bytes,
    /// so it cannot represent a full-width random draw.
    ContributionTooShort,
    /// A contribution was not in the canonical lowercase BASE32-nopad
    /// encoding: it failed to decode, or it decoded from a non-canonical
    /// spelling of the same bytes.
    ContributionMalformed,
    /// The permit was admitted for a different runtime than the channel.
    RuntimeMismatch,
    /// The local half of the proof was absent or did not verify under the
    /// local Device ID, so no mutual claim can be made from this attempt.
    LocalHalfUnproven,
    /// The remote signature did not verify over the exact transcript.
    SignatureInvalid,
    /// The task's handoff is gone: the channel was replaced or retired, or a
    /// previous attempt already consumed it.
    ///
    /// This is a security condition, not housekeeping. Because the channel
    /// binding is not session-unique, exact connector-incarnation ownership is
    /// what distinguishes two channels between the same pair — so refusing
    /// here is what defeats cross-channel relay.
    ChannelNotCurrent,
}

/// The closed set of negotiated endpoint-authentication crypto profiles.
///
/// A closed enum rather than a caller string: the profile is bound into the
/// transcript so a peer cannot negotiate one profile and prove another, and a
/// free-form field would let a caller invent a profile identifier that no
/// verifier ever agreed to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EndpointAuthProfile {
    /// Ed25519 device signatures over a DTLS-fingerprint-bound transcript.
    V1Ed25519Dtls,
}

impl EndpointAuthProfile {
    fn tag(self) -> &'static str {
        match self {
            Self::V1Ed25519Dtls => "ed25519-dtls-v1",
        }
    }
}

/// A 32-byte draw encoded as lowercase BASE32 without padding.
const CONTRIBUTION_BYTES: usize = 32;

/// This endpoint's own per-attempt contribution.
///
/// Constructible **only** from a fresh CSPRNG draw. With no session-unique
/// channel binding available (see [`EndpointAuthAttempt::begin`]), per-attempt
/// freshness is the primary anti-replay mechanism rather than a secondary one,
/// so the type refuses to represent a value that did not come from the RNG.
///
/// Deliberately **not** `Clone`. A clone would let any crate code copy a stale
/// value into a second attempt, which is exactly the reuse the construction
/// rule exists to prevent — the guarantee would then be documentation rather
/// than an invariant.
///
/// Callers copy the encoded form via [`Self::as_str`] rather than taking the
/// value. Production deliberately **keeps** this owned by per-peer state for
/// the whole connector attempt: consuming it on completion would open a retry
/// race, where a retransmitted or reordered Hello finds no contribution and
/// tears down a peer whose proof is valid. Single promotion is enforced by the
/// move-only handoff inside [`EndpointAuthTask`], not by consuming this.
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
}

/// The peer's per-attempt contribution, as received on the wire.
///
/// This one genuinely arrives as bytes, so it cannot be RNG-constructed. It is
/// decoded instead of merely measured: a character count would accept any
/// long-enough string, which is a width check masquerading as a full-width
/// contribution guard. Accepting a short or non-canonical value would silently
/// shrink the freshness the whole transcript rests on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PeerContribution(String);

impl PeerContribution {
    /// Accept exactly the canonical lowercase BASE32-nopad encoding of
    /// [`CONTRIBUTION_BYTES`] bytes.
    ///
    /// The round-trip comparison is what makes the encoding canonical rather
    /// than merely decodable: it rejects uppercase spellings and any
    /// non-canonical trailing-bit variant that would decode to the same bytes,
    /// so one draw has exactly one accepted wire form.
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

/// One in-progress endpoint-authentication attempt for one exact channel.
///
/// The attempt is move-only and is consumed by verification, so a transcript
/// can be used at most once. There is no timer, expiry, or rate window here:
/// freshness is carried by the two per-attempt contributions, both of which
/// are bound into the signed transcript.
pub(crate) struct EndpointAuthAttempt {
    owner: PromotedChannelOwner,
    permit: EndpointAuthPermit,
    mesh_context: String,
    profile: EndpointAuthProfile,
    local_role: EndpointRole,
    local_device_id: String,
    remote_device_id: String,
    /// Encoded copies, not owned typed values. The typed originals stay with
    /// the caller — the local one lives in per-peer state for the whole
    /// connector attempt — so Hello retransmissions can re-sign the same
    /// attempt. Single promotion is enforced by the move-only handoff, not by
    /// consuming the contribution.
    local_contribution: String,
    remote_contribution: String,
    local_fingerprint: String,
    remote_fingerprint: String,
}

impl EndpointAuthAttempt {
    /// Canonical role ordering for one Device pair.
    ///
    /// The role is derived from the pair, never chosen by the caller, so a
    /// caller cannot pick whichever ordering makes a signature verify.
    pub(crate) fn role_of(local_device_id: &str, remote_device_id: &str) -> EndpointRole {
        if local_device_id < remote_device_id {
            EndpointRole::Initiator
        } else {
            EndpointRole::Responder
        }
    }

    /// Begin one attempt over an exact connected channel, holding both halves.
    ///
    /// `mesh_context` is the canonical mesh identifier for the exact mesh this
    /// channel belongs to, in the same canonical form the durable layer signs
    /// under, not a display string.
    ///
    /// `profile` is the negotiated crypto profile, drawn from a closed set. It
    /// is bound into the transcript rather than left implicit in the domain
    /// tag, so a peer cannot negotiate one profile and prove another.
    ///
    /// `local_fingerprint` and `remote_fingerprint` are the DTLS certificate
    /// fingerprints of **both** endpoints of that exact channel: the one this
    /// endpoint presents and the one it observes from the peer. Both are
    /// bound, in role-canonical order, so the transcript commits to the pair
    /// rather than only to the signer's own certificate.
    ///
    /// ## What this binding does and does not prove
    ///
    /// It **does** defeat a terminating signaling man-in-the-middle: an
    /// interceptor must present its own certificate to each leg, so the
    /// fingerprints a verifier observes differ from the ones the real peer
    /// signed and the signature fails.
    ///
    /// It is **not** an RFC 5705 exporter and is **not session-unique**. A
    /// certificate fingerprint identifies the certificate, not the handshake:
    /// every session reusing that certificate yields the same value, and it
    /// does not cover the key exchange. Two channels between the same pair
    /// with the same certificates therefore carry an identical binding.
    ///
    /// The consequence is load-bearing and must not be misattributed:
    /// **cross-channel replay is prevented by the two per-attempt CSPRNG
    /// contributions and by exact connector-incarnation ownership, not by
    /// this binding.** If either of those weakens, the property is lost. A
    /// true exporter is deferred; it is unreachable without vendoring the
    /// DTLS crate, which is a larger supply-chain question than it settles.
    ///
    /// `local_signature` is the local half of the proof, over this attempt's
    /// local-role transcript. It is verified here under `local_device_id`, so
    /// an attempt cannot exist unless the local key actually produced its
    /// half. Without it, a later remote-signature check would prove one
    /// direction while the type claimed mutual authentication.
    /// Test-only direct construction from a bare capability.
    ///
    /// Production promotes through [`EndpointAuthTask::authenticate`], which
    /// carries the whole handoff so close-owner retention survives. A bare
    /// capability has no retention to carry, so this path is confined to
    /// tests rather than left available to production callers.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin(
        connected: ConnectedChannelCapability,
        permit: EndpointAuthPermit,
        mesh_context: &str,
        profile: EndpointAuthProfile,
        local_device_id: &str,
        remote_device_id: &str,
        local_contribution: &LocalContribution,
        remote_contribution: &PeerContribution,
        local_fingerprint: &str,
        remote_fingerprint: &str,
        local_signature: &str,
    ) -> Result<Self, EndpointAuthError> {
        let local_role = Self::check(
            &connected,
            &permit,
            mesh_context,
            profile,
            local_device_id,
            remote_device_id,
            local_contribution,
            remote_contribution,
            local_fingerprint,
            remote_fingerprint,
            local_signature,
        )?;
        Ok(Self::commit(
            PromotedChannelOwner::Bare(connected),
            permit,
            mesh_context,
            profile,
            local_role,
            local_device_id,
            remote_device_id,
            local_contribution,
            remote_contribution,
            local_fingerprint,
            remote_fingerprint,
        ))
    }

    /// Every fallible check, performed against a **borrowed** capability.
    ///
    /// Separating this from [`Self::commit`] is what lets the production
    /// issuer validate an attempt before taking the connected capability out
    /// of its handoff. Taking first and validating second would mean a refused
    /// attempt had already emptied the handoff, and the handoff's `Drop` only
    /// re-retains a capability that is still present — so a refusal would
    /// silently drop the channel's retention instead of preserving it.
    #[allow(clippy::too_many_arguments)]
    fn check(
        connected: &ConnectedChannelCapability,
        permit: &EndpointAuthPermit,
        mesh_context: &str,
        profile: EndpointAuthProfile,
        local_device_id: &str,
        remote_device_id: &str,
        local_contribution: &LocalContribution,
        remote_contribution: &PeerContribution,
        local_fingerprint: &str,
        remote_fingerprint: &str,
        local_signature: &str,
    ) -> Result<EndpointRole, EndpointAuthError> {
        if mesh_context.is_empty()
            || local_device_id.is_empty()
            || remote_device_id.is_empty()
            || local_fingerprint.is_empty()
            || remote_fingerprint.is_empty()
            || local_signature.is_empty()
        {
            return Err(EndpointAuthError::MissingTranscriptField);
        }
        if local_device_id == remote_device_id {
            return Err(EndpointAuthError::NotMutual);
        }
        if local_contribution.as_str() == remote_contribution.as_str() {
            return Err(EndpointAuthError::ContributionNotFresh);
        }
        if !connected.runtime().is_same(&permit.runtime) {
            return Err(EndpointAuthError::RuntimeMismatch);
        }
        let local_role = Self::role_of(local_device_id, remote_device_id);
        let local_half = Self::transcript_bytes(
            mesh_context,
            profile,
            local_role,
            local_device_id,
            remote_device_id,
            local_contribution.as_str(),
            remote_contribution.as_str(),
            local_fingerprint,
            remote_fingerprint,
        );
        match crate::signing::verify(local_device_id, &local_half, local_signature) {
            Ok(true) => Ok(local_role),
            Ok(false) | Err(_) => Err(EndpointAuthError::LocalHalfUnproven),
        }
    }

    /// Infallible construction. Every check has already passed.
    #[allow(clippy::too_many_arguments)]
    fn commit(
        owner: PromotedChannelOwner,
        permit: EndpointAuthPermit,
        mesh_context: &str,
        profile: EndpointAuthProfile,
        local_role: EndpointRole,
        local_device_id: &str,
        remote_device_id: &str,
        local_contribution: &LocalContribution,
        remote_contribution: &PeerContribution,
        local_fingerprint: &str,
        remote_fingerprint: &str,
    ) -> Self {
        Self {
            owner,
            permit,
            mesh_context: mesh_context.to_owned(),
            profile,
            local_role,
            local_device_id: local_device_id.to_owned(),
            remote_device_id: remote_device_id.to_owned(),
            local_contribution: local_contribution.as_str().to_owned(),
            remote_contribution: remote_contribution.as_str().to_owned(),
            local_fingerprint: local_fingerprint.to_owned(),
            remote_fingerprint: remote_fingerprint.to_owned(),
        }
    }

    /// The exact bytes a named signer must cover, derived from the same
    /// fields [`Self::begin`] will hold.
    ///
    /// This is exposed so an endpoint can produce its own half before an
    /// attempt exists, and so both endpoints derive byte-identical input.
    /// Role ordering is computed from the Device pair, never supplied.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn transcript_bytes(
        mesh_context: &str,
        profile: EndpointAuthProfile,
        signer: EndpointRole,
        local_device_id: &str,
        remote_device_id: &str,
        local_contribution: &str,
        remote_contribution: &str,
        local_fingerprint: &str,
        remote_fingerprint: &str,
    ) -> Vec<u8> {
        // Both endpoints must derive byte-identical input, so every paired
        // field is ordered by role rather than by which side is "local".
        let (
            initiator_id,
            responder_id,
            initiator_contribution,
            responder_contribution,
            initiator_fingerprint,
            responder_fingerprint,
        ) = match Self::role_of(local_device_id, remote_device_id) {
            EndpointRole::Initiator => (
                local_device_id,
                remote_device_id,
                local_contribution,
                remote_contribution,
                local_fingerprint,
                remote_fingerprint,
            ),
            EndpointRole::Responder => (
                remote_device_id,
                local_device_id,
                remote_contribution,
                local_contribution,
                remote_fingerprint,
                local_fingerprint,
            ),
        };
        // Length-prefixed fields, not separator-joined. `mesh_context` and
        // both fingerprints are free-form caller strings, so a separator
        // appearing inside one of them would shift every later field boundary
        // and let two distinct field tuples serialize to identical signed
        // bytes. Netstring-style `len:value` framing is injective, so no such
        // collision exists. Every field added since — the profile tag and the
        // second fingerprint — is framed the same way.
        fn push_field(out: &mut Vec<u8>, field: &str) {
            out.extend_from_slice(field.len().to_string().as_bytes());
            out.push(b':');
            out.extend_from_slice(field.as_bytes());
        }

        let mut transcript = Vec::from(ENDPOINT_AUTH_DOMAIN_TAG.as_bytes());
        for field in [
            mesh_context,
            profile.tag(),
            signer.tag(),
            initiator_id,
            responder_id,
            initiator_contribution,
            responder_contribution,
            initiator_fingerprint,
            responder_fingerprint,
        ] {
            push_field(&mut transcript, field);
        }
        transcript
    }

    /// The exact bytes the named role must sign for this attempt.
    pub(crate) fn transcript_for(&self, signer: EndpointRole) -> Vec<u8> {
        Self::transcript_bytes(
            &self.mesh_context,
            self.profile,
            signer,
            &self.local_device_id,
            &self.remote_device_id,
            &self.local_contribution,
            &self.remote_contribution,
            &self.local_fingerprint,
            &self.remote_fingerprint,
        )
    }

    /// Consume the attempt and promote only on a complete verified proof.
    ///
    /// The local half was already proven in [`Self::begin`], so verifying the
    /// remote half here completes a genuinely mutual proof rather than a
    /// one-directional one.
    ///
    /// Fail-closed: a malformed signature, a rejected signature, or any
    /// verifier error all return `SignatureInvalid`, and the connected
    /// capability is dropped with the attempt rather than returned.
    /// Test-only convenience wrapper that discards the connected capability on
    /// refusal.
    ///
    /// Production must keep using [`Self::verify_remote_returning`]: it took
    /// the capability out of a handoff whose `Drop` re-retains only what is
    /// still present, so a refusal has to hand it back. Routing production
    /// through this wrapper would silently drop that retention.
    #[cfg(test)]
    pub(crate) fn verify_remote(
        self,
        remote_signature: &str,
    ) -> Result<AuthenticatedChannelCapability, EndpointAuthError> {
        self.verify_remote_returning(remote_signature)
            .map_err(|(_, error)| error)
    }

    /// As [`Self::verify_remote`], but yielding the connected capability back
    /// on refusal instead of dropping it with the attempt.
    ///
    /// The production issuer needs this: it took the capability out of a
    /// handoff whose `Drop` re-retains only what is still present, so a
    /// refusal must be able to put it back. Callers with nothing to hand it
    /// back to use [`Self::verify_remote`] and let the drop stand.
    #[allow(
        clippy::result_large_err,
        reason = "the Err variant carries the whole channel owner back on refusal; \
                  that is the retention contract, not an oversight. Boxing it would \
                  add an allocation on a security-failure path purely to satisfy a \
                  size lint, and the large Err does not propagate — `authenticate` \
                  converts it to a bare EndpointAuthError"
    )]
    pub(crate) fn verify_remote_returning(
        self,
        remote_signature: &str,
    ) -> Result<AuthenticatedChannelCapability, (PromotedChannelOwner, EndpointAuthError)> {
        let transcript = self.transcript_for(self.local_role.peer());
        match crate::signing::verify(&self.remote_device_id, &transcript, remote_signature) {
            Ok(true) => Ok(AuthenticatedChannelCapability {
                owner: self.owner,
                permit: self.permit,
            }),
            Ok(false) | Err(_) => Err((self.owner, EndpointAuthError::SignatureInvalid)),
        }
    }
}

#[cfg(test)]
pub(crate) fn authenticated_for_test(
    runtime: RuntimeIncarnation,
) -> AuthenticatedChannelCapability {
    let connected = crate::connector::connected_for_test(runtime.clone());
    let permit = EndpointAuthPermit::admitted_for_test(runtime);
    assert!(connected.runtime().is_same(&permit.runtime));
    AuthenticatedChannelCapability {
        owner: PromotedChannelOwner::Bare(connected),
        permit,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::sign_with;
    use data_encoding::BASE32_NOPAD;
    use ed25519_dalek::SigningKey;

    const MESH: &str = "mesh-context-alpha";
    const PROFILE: EndpointAuthProfile = EndpointAuthProfile::V1Ed25519Dtls;
    const LOCAL_FP: &str = "sha-256 AA:BB:CC:DD";
    const REMOTE_FP: &str = "sha-256 11:22:33:44";

    /// Two distinct full-width contributions, as the wire would carry them.
    fn contributions() -> (LocalContribution, PeerContribution) {
        let local = LocalContribution::generate();
        let remote = PeerContribution::from_wire(LocalContribution::generate().as_str())
            .expect("a generated draw is full width");
        (local, remote)
    }

    fn fixture_key(seed: u8) -> (SigningKey, String) {
        let signing_key = SigningKey::from_bytes(&[seed; 32]);
        let device_id = BASE32_NOPAD
            .encode(signing_key.verifying_key().as_bytes())
            .to_lowercase();
        (signing_key, device_id)
    }

    /// Build one well-formed attempt whose local half is genuinely signed,
    /// returning the remote key so a test can produce the remote half.
    #[allow(clippy::too_many_arguments)]
    fn attempt_with(
        mesh: &str,
        profile: EndpointAuthProfile,
        local_fingerprint: &str,
        remote_fingerprint: &str,
        local_contribution: &LocalContribution,
        remote_contribution: &PeerContribution,
    ) -> (EndpointAuthAttempt, SigningKey) {
        let (local_key, local_id) = fixture_key(1);
        let (remote_key, remote_id) = fixture_key(2);
        let local_role = EndpointAuthAttempt::role_of(&local_id, &remote_id);
        let local_signature = sign_with(
            &local_key,
            &EndpointAuthAttempt::transcript_bytes(
                mesh,
                profile,
                local_role,
                &local_id,
                &remote_id,
                local_contribution.as_str(),
                remote_contribution.as_str(),
                local_fingerprint,
                remote_fingerprint,
            ),
        );
        let runtime = crate::runtime::runtime_for_test();
        let attempt = EndpointAuthAttempt::begin(
            crate::connector::connected_for_test(runtime.clone()),
            EndpointAuthPermit::admitted_for_test(runtime),
            mesh,
            profile,
            &local_id,
            &remote_id,
            local_contribution,
            remote_contribution,
            local_fingerprint,
            remote_fingerprint,
            &local_signature,
        )
        .expect("fixture attempt is well formed");
        (attempt, remote_key)
    }

    /// The same fixture pair, defaulting the fields a test is not varying.
    fn initiator_attempt(
        mesh: &str,
        local_fingerprint: &str,
        remote_fingerprint: &str,
        local_contribution: &LocalContribution,
        remote_contribution: &PeerContribution,
    ) -> (EndpointAuthAttempt, SigningKey) {
        attempt_with(
            mesh,
            PROFILE,
            local_fingerprint,
            remote_fingerprint,
            local_contribution,
            remote_contribution,
        )
    }

    /// The role the remote peer must sign as, for the fixture pair.
    fn remote_role(attempt: &EndpointAuthAttempt) -> EndpointRole {
        attempt.local_role.peer()
    }

    /// Assert a promotion refused with exactly this typed error.
    ///
    /// Written as a match rather than `assert_eq!` on the whole `Result`
    /// because `AuthenticatedChannelCapability` deliberately implements
    /// neither `PartialEq` nor `Debug`: an authority artifact must not be
    /// comparable or printable, and deriving either to make an assertion
    /// compile would widen that surface for test convenience. The exact
    /// refusal variant is still bound — a promotion, or the wrong variant,
    /// both fail.
    #[track_caller]
    fn assert_refused(
        outcome: Result<AuthenticatedChannelCapability, EndpointAuthError>,
        expected: EndpointAuthError,
        context: &str,
    ) {
        match outcome {
            Ok(_) => panic!("{context}: expected {expected:?}, but the attempt promoted"),
            Err(actual) => assert_eq!(actual, expected, "{context}"),
        }
    }

    /// A non-empty placeholder for cases refused before the local half is
    /// ever checked, so those tests prove their own cause and not this one.
    const UNCHECKED_LOCAL_SIG: &str = "placeholder";

    #[test]
    fn v4_arc04_complete_proof_promotes_the_exact_channel() {
        let (local_c, remote_c) = contributions();
        let (attempt, remote_key) =
            initiator_attempt(MESH, LOCAL_FP, REMOTE_FP, &local_c, &remote_c);
        let runtime = attempt
            .owner
            .capability()
            .expect("a fixture attempt owns its channel")
            .runtime()
            .clone();
        let signature = sign_with(&remote_key, &attempt.transcript_for(remote_role(&attempt)));

        let authenticated = attempt
            .verify_remote(&signature)
            .expect("a complete fresh mutual proof promotes");

        assert!(authenticated.runtime().is_same(&runtime));
    }

    #[test]
    fn v4_arc04_transcript_binds_mesh_context() {
        let (local_c, remote_c) = contributions();
        let (attempt, remote_key) =
            initiator_attempt(MESH, LOCAL_FP, REMOTE_FP, &local_c, &remote_c);
        let (other, _) = initiator_attempt(
            "mesh-context-beta",
            LOCAL_FP,
            REMOTE_FP,
            &local_c,
            &remote_c,
        );
        let role = remote_role(&attempt);
        assert_ne!(
            attempt.transcript_for(role),
            other.transcript_for(role),
            "mesh context must change the signed transcript"
        );
        let foreign = sign_with(&remote_key, &other.transcript_for(role));

        assert_refused(
            attempt.verify_remote(&foreign),
            EndpointAuthError::SignatureInvalid,
            "a proof bound to another mesh context must not authenticate this one",
        );
    }

    #[test]
    fn v4_arc04_transcript_commits_to_the_fixed_profile_selection() {
        // The profile is a closed enum with one inhabitant, so a caller cannot
        // select a weaker one: cross-profile downgrade is refused by
        // construction rather than at runtime, and no negative control can be
        // written without inventing a second variant. What is checkable, and
        // what keeps that true, is that the profile tag is genuinely a signed
        // field — so adding a variant changes the transcript rather than
        // silently sharing one.
        let (_local, local_id) = fixture_key(1);
        let (_remote, remote_id) = fixture_key(2);
        let (local_c, remote_c) = contributions();
        let role = EndpointAuthAttempt::role_of(&local_id, &remote_id);
        let transcript = EndpointAuthAttempt::transcript_bytes(
            MESH,
            PROFILE,
            role,
            &local_id,
            &remote_id,
            local_c.as_str(),
            remote_c.as_str(),
            LOCAL_FP,
            REMOTE_FP,
        );

        let tag = PROFILE.tag();
        let field = format!("{}:{tag}", tag.len());
        assert!(
            transcript
                .windows(field.len())
                .any(|window| window == field.as_bytes()),
            "the fixed profile selection must appear as a length-prefixed signed field"
        );
    }

    #[test]
    fn v4_arc04_transcript_binds_both_endpoint_fingerprints() {
        let (local_c, remote_c) = contributions();
        let (attempt, remote_key) =
            initiator_attempt(MESH, LOCAL_FP, REMOTE_FP, &local_c, &remote_c);
        let role = remote_role(&attempt);

        // Changing the remote certificate alone changes the transcript.
        let (other_remote, _) =
            initiator_attempt(MESH, LOCAL_FP, "sha-256 99:88:77:66", &local_c, &remote_c);
        assert_ne!(
            attempt.transcript_for(role),
            other_remote.transcript_for(role),
            "the observed remote fingerprint must be bound"
        );

        // And so does changing the local one, which a signer-only binding
        // would leave uncommitted.
        let (other_local, _) =
            initiator_attempt(MESH, "sha-256 55:44:33:22", REMOTE_FP, &local_c, &remote_c);
        assert_ne!(
            attempt.transcript_for(role),
            other_local.transcript_for(role),
            "the presented local fingerprint must be bound too"
        );

        let relayed = sign_with(&remote_key, &other_remote.transcript_for(role));
        assert_refused(
            attempt.verify_remote(&relayed),
            EndpointAuthError::SignatureInvalid,
            "a proof bound to a different observed certificate must not authenticate",
        );
    }

    #[test]
    fn v4_arc04_fingerprint_pair_order_is_role_canonical_not_positional() {
        let (_local, local_id) = fixture_key(1);
        let (_remote, remote_id) = fixture_key(2);
        let (local_c, remote_c) = contributions();
        let role = EndpointAuthAttempt::role_of(&local_id, &remote_id);
        let bytes = |a: &str, b: &str| {
            EndpointAuthAttempt::transcript_bytes(
                MESH,
                PROFILE,
                role,
                &local_id,
                &remote_id,
                local_c.as_str(),
                remote_c.as_str(),
                a,
                b,
            )
        };

        assert_ne!(
            bytes(LOCAL_FP, REMOTE_FP),
            bytes(REMOTE_FP, LOCAL_FP),
            "swapping which certificate is presented and which is observed must \
             change the transcript; an unordered pair would let one side claim \
             the other's certificate"
        );
    }

    #[test]
    fn v4_arc04_legacy_handshake_signature_is_not_an_accepted_fallback() {
        // H1. The cutover must be enforced by domain separation, not by
        // comments. This builds a *genuinely valid* legacy signature — right
        // key, right identities, same channel material — and requires the
        // Arc 04 verifier to reject it. A malformed-input test would not
        // discriminate: it would pass even if the two domains collided.
        let (local_c, remote_c) = contributions();
        let (attempt, remote_key) =
            initiator_attempt(MESH, LOCAL_FP, REMOTE_FP, &local_c, &remote_c);
        let (_local, local_id) = fixture_key(1);
        let (_remote, remote_id) = fixture_key(2);

        // Exactly what an Arc 03 peer would sign for this handshake: the peer
        // is the signer, so the ids are their-first from its perspective, and
        // the binding is the fingerprint it presents.
        let legacy =
            crate::signing::handshake_payload(local_c.as_str(), &remote_id, &local_id, REMOTE_FP);
        let legacy_signature = sign_with(&remote_key, &legacy);

        // Non-vacuity: that signature really is valid over the legacy payload,
        // so the rejection below is domain separation and not a bad key.
        assert_eq!(
            crate::signing::verify(&remote_id, &legacy, &legacy_signature).ok(),
            Some(true),
            "the legacy proof must genuinely verify under the legacy domain"
        );
        assert_ne!(
            attempt.transcript_for(remote_role(&attempt)),
            legacy,
            "the two domains must not produce identical signed bytes"
        );

        assert_refused(
            attempt.verify_remote(&legacy_signature),
            EndpointAuthError::SignatureInvalid,
            "a valid legacy signature must not authenticate under Arc 04; there \
             is no attacker-selectable downgrade",
        );
    }

    #[test]
    fn v4_arc04_role_tag_defeats_signature_reflection() {
        let (local_c, remote_c) = contributions();
        let (attempt, remote_key) =
            initiator_attempt(MESH, LOCAL_FP, REMOTE_FP, &local_c, &remote_c);
        // The peer signs our half and tries to pass it back as its own.
        let reflected = sign_with(&remote_key, &attempt.transcript_for(attempt.local_role));

        assert_refused(
            attempt.verify_remote(&reflected),
            EndpointAuthError::SignatureInvalid,
            "our own half reflected back must not pass as the peer's",
        );
    }

    #[test]
    fn v4_arc04_stale_contribution_does_not_verify() {
        let (local_c, remote_c) = contributions();
        let (attempt, remote_key) =
            initiator_attempt(MESH, LOCAL_FP, REMOTE_FP, &local_c, &remote_c);
        // A previous attempt's remote contribution, replayed into this one.
        let previous = PeerContribution::from_wire(LocalContribution::generate().as_str())
            .expect("a generated draw is canonical");
        let (stale, _) = initiator_attempt(MESH, LOCAL_FP, REMOTE_FP, &local_c, &previous);
        let replayed = sign_with(&remote_key, &stale.transcript_for(remote_role(&stale)));

        assert_refused(
            attempt.verify_remote(&replayed),
            EndpointAuthError::SignatureInvalid,
            "a proof over a previous attempt's contribution must not authenticate",
        );
    }

    #[test]
    fn v4_arc04_wrong_remote_identity_does_not_verify() {
        let (local_c, remote_c) = contributions();
        let (attempt, _) = initiator_attempt(MESH, LOCAL_FP, REMOTE_FP, &local_c, &remote_c);
        let (impostor_key, _) = fixture_key(9);
        let signature = sign_with(
            &impostor_key,
            &attempt.transcript_for(remote_role(&attempt)),
        );

        assert_refused(
            attempt.verify_remote(&signature),
            EndpointAuthError::SignatureInvalid,
            "a signature from a key that is not the claimed remote Device must not \
             authenticate",
        );
    }

    #[test]
    fn v4_arc04_malformed_signature_fails_closed() {
        let (local_c, remote_c) = contributions();
        let (attempt, _) = initiator_attempt(MESH, LOCAL_FP, REMOTE_FP, &local_c, &remote_c);

        assert_refused(
            attempt.verify_remote("not-a-signature"),
            EndpointAuthError::SignatureInvalid,
            "a verifier error must fail closed rather than promote",
        );
    }

    #[test]
    fn v4_arc04_local_contribution_is_fresh_per_draw() {
        // Freshness is the primary anti-replay mechanism here, so the type
        // that carries it must not be able to repeat itself.
        let first = LocalContribution::generate();
        let second = LocalContribution::generate();

        assert_ne!(first.as_str(), second.as_str());
        assert_eq!(
            first.as_str().chars().count(),
            52,
            "a full 32-byte draw encodes to 52 BASE32 characters"
        );
    }

    #[test]
    fn v4_arc04_peer_contribution_rejects_short_and_noncanonical_wire_values() {
        let canonical = LocalContribution::generate();
        assert!(PeerContribution::from_wire(canonical.as_str()).is_ok());

        assert_eq!(
            PeerContribution::from_wire(""),
            Err(EndpointAuthError::MissingTranscriptField)
        );
        // Decodes cleanly, but to fewer than 32 bytes: a width check that only
        // counted characters would have to guess, and a truncated draw would
        // silently shrink the freshness the transcript rests on.
        assert_eq!(
            PeerContribution::from_wire("aaaaaaaa"),
            Err(EndpointAuthError::ContributionTooShort)
        );
        // Correct bytes, non-canonical spelling.
        assert_eq!(
            PeerContribution::from_wire(&canonical.as_str().to_uppercase()),
            Err(EndpointAuthError::ContributionMalformed),
            "one draw must have exactly one accepted wire form"
        );
        assert_eq!(
            PeerContribution::from_wire("not-base32!!"),
            Err(EndpointAuthError::ContributionMalformed)
        );
    }

    #[test]
    fn v4_arc04_unproven_local_half_refuses_the_attempt() {
        let (_local, local_id) = fixture_key(1);
        let (_remote, remote_id) = fixture_key(2);
        let (impostor_key, _) = fixture_key(9);
        let local_role = EndpointAuthAttempt::role_of(&local_id, &remote_id);
        let (local_c, remote_c) = contributions();
        // Signed by a key that is not the local Device.
        let forged_local = sign_with(
            &impostor_key,
            &EndpointAuthAttempt::transcript_bytes(
                MESH,
                PROFILE,
                local_role,
                &local_id,
                &remote_id,
                local_c.as_str(),
                remote_c.as_str(),
                LOCAL_FP,
                REMOTE_FP,
            ),
        );
        let runtime = crate::runtime::runtime_for_test();

        let refused = EndpointAuthAttempt::begin(
            crate::connector::connected_for_test(runtime.clone()),
            EndpointAuthPermit::admitted_for_test(runtime),
            MESH,
            PROFILE,
            &local_id,
            &remote_id,
            &local_c,
            &remote_c,
            LOCAL_FP,
            REMOTE_FP,
            &forged_local,
        );

        assert_eq!(
            refused.err(),
            Some(EndpointAuthError::LocalHalfUnproven),
            "mutual authentication cannot rest on a remote signature alone"
        );
    }

    #[test]
    fn v4_arc04_self_authentication_is_not_mutual() {
        let (_key, device_id) = fixture_key(1);
        let (local_c, remote_c) = contributions();
        let runtime = crate::runtime::runtime_for_test();

        let refused = EndpointAuthAttempt::begin(
            crate::connector::connected_for_test(runtime.clone()),
            EndpointAuthPermit::admitted_for_test(runtime),
            MESH,
            PROFILE,
            &device_id,
            &device_id,
            &local_c,
            &remote_c,
            LOCAL_FP,
            REMOTE_FP,
            UNCHECKED_LOCAL_SIG,
        );

        assert_eq!(refused.err(), Some(EndpointAuthError::NotMutual));
    }

    #[test]
    fn v4_arc04_shared_contribution_is_not_fresh() {
        let (_local, local_id) = fixture_key(1);
        let (_remote, remote_id) = fixture_key(2);
        // The same draw on both sides: well-formed individually, but no
        // freshness separates the two endpoints.
        let shared = LocalContribution::generate();
        let echoed =
            PeerContribution::from_wire(shared.as_str()).expect("a generated draw is canonical");
        let runtime = crate::runtime::runtime_for_test();

        let refused = EndpointAuthAttempt::begin(
            crate::connector::connected_for_test(runtime.clone()),
            EndpointAuthPermit::admitted_for_test(runtime),
            MESH,
            PROFILE,
            &local_id,
            &remote_id,
            &shared,
            &echoed,
            LOCAL_FP,
            REMOTE_FP,
            UNCHECKED_LOCAL_SIG,
        );

        assert_eq!(refused.err(), Some(EndpointAuthError::ContributionNotFresh));
    }

    #[test]
    fn v4_arc04_empty_transcript_field_is_refused() {
        let (_local, local_id) = fixture_key(1);
        let (_remote, remote_id) = fixture_key(2);
        let (local_c, remote_c) = contributions();
        let runtime = crate::runtime::runtime_for_test();

        let refused = EndpointAuthAttempt::begin(
            crate::connector::connected_for_test(runtime.clone()),
            EndpointAuthPermit::admitted_for_test(runtime),
            "",
            PROFILE,
            &local_id,
            &remote_id,
            &local_c,
            &remote_c,
            LOCAL_FP,
            REMOTE_FP,
            UNCHECKED_LOCAL_SIG,
        );

        assert_eq!(
            refused.err(),
            Some(EndpointAuthError::MissingTranscriptField)
        );
    }

    #[test]
    fn v4_arc04_permit_from_another_runtime_is_refused() {
        let (_local, local_id) = fixture_key(1);
        let (_remote, remote_id) = fixture_key(2);

        let (local_c, remote_c) = contributions();
        let refused = EndpointAuthAttempt::begin(
            crate::connector::connected_for_test(crate::runtime::runtime_for_test()),
            EndpointAuthPermit::admitted_for_test(crate::runtime::runtime_for_test()),
            MESH,
            PROFILE,
            &local_id,
            &remote_id,
            &local_c,
            &remote_c,
            LOCAL_FP,
            REMOTE_FP,
            UNCHECKED_LOCAL_SIG,
        );

        assert_eq!(refused.err(), Some(EndpointAuthError::RuntimeMismatch));
    }

    #[test]
    fn v4_arc04_both_endpoints_derive_one_identical_transcript() {
        let (_local, local_id) = fixture_key(1);
        let (_remote, remote_id) = fixture_key(2);
        let (one, other) = contributions();

        for role in [EndpointRole::Initiator, EndpointRole::Responder] {
            assert_eq!(
                // Seen from this endpoint: our id, our contribution, the
                // certificate we present, the one we observe.
                EndpointAuthAttempt::transcript_bytes(
                    MESH,
                    PROFILE,
                    role,
                    &local_id,
                    &remote_id,
                    one.as_str(),
                    other.as_str(),
                    LOCAL_FP,
                    REMOTE_FP,
                ),
                // Seen from the peer: every paired field mirrored, including
                // both fingerprints.
                EndpointAuthAttempt::transcript_bytes(
                    MESH,
                    PROFILE,
                    role,
                    &remote_id,
                    &local_id,
                    other.as_str(),
                    one.as_str(),
                    REMOTE_FP,
                    LOCAL_FP,
                ),
                "both endpoints must derive byte-identical input for one signer"
            );
        }
    }

    #[test]
    fn v4_arc04_separator_in_a_field_cannot_collide_two_transcripts() {
        let (_local, local_id) = fixture_key(1);
        let (_remote, remote_id) = fixture_key(2);
        let (local_c, remote_c) = contributions();
        let role = EndpointAuthAttempt::role_of(&local_id, &remote_id);
        let bytes = |a: &str, b: &str| {
            EndpointAuthAttempt::transcript_bytes(
                MESH,
                PROFILE,
                role,
                &local_id,
                &remote_id,
                local_c.as_str(),
                remote_c.as_str(),
                a,
                b,
            )
        };

        // Two distinct fingerprint pairs chosen so that a separator-joined
        // encoding would serialize them identically: the separator and the
        // next field are folded into the first field of the second tuple.
        let shifted = bytes("aa", "bb");
        let smuggled = bytes("aa|bb", "");

        assert_ne!(
            shifted, smuggled,
            "length-prefixed framing must keep distinct field tuples distinct; \
             a separator-joined encoding would collide these two"
        );
    }

    #[test]
    fn v4_arc04_role_is_derived_from_the_pair_not_chosen() {
        let (_local, local_id) = fixture_key(1);
        let (_remote, remote_id) = fixture_key(2);

        assert_eq!(
            EndpointAuthAttempt::role_of(&local_id, &remote_id).peer(),
            EndpointAuthAttempt::role_of(&remote_id, &local_id),
            "the two endpoints of one pair must occupy opposite roles"
        );
    }

    #[test]
    fn v4_arc02_authenticated_channel_preserves_runtime_binding() {
        let runtime = crate::runtime::runtime_for_test();
        let authenticated = authenticated_for_test(runtime.clone());

        assert!(authenticated.runtime().is_same(&runtime));
        // The channel the capability owns and the permit it carries must name
        // the same runtime. Asserted through the owner rather than a
        // `connected` field, which promotion replaced so that the whole
        // handoff — and its close-owner retention — travels with the
        // capability.
        assert!(authenticated
            .owner
            .capability()
            .expect("a test capability owns its channel")
            .runtime()
            .is_same(&authenticated.permit.runtime));
    }

    #[test]
    fn v4_arc02_legacy_adapter_cannot_manufacture_authentication() {
        let authenticated = authenticated_for_test(crate::runtime::runtime_for_test());
        let wrapper = LegacyAuthenticatedChannel::new(authenticated, "legacy auth channel");
        let _ = wrapper.capability();
        let (_capability, legacy) = wrapper.into_parts();

        assert_eq!(legacy, "legacy auth channel");
    }
}
