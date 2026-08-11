//! WebRTC-specific connector policy.
//!
//! The process resource owner remains connector-neutral. ICE candidate work and
//! the application's registered real-time codecs are transport-edge choices
//! owned by this profile.

use std::num::NonZeroUsize;

use crate::runtime::attempt::ConnectorCallbackPolicy;

/// Owner-selected cumulative bounds for one ICE attempt's remote candidates.
///
/// Content bytes are the candidate strings and optional identifiers presented
/// to the connector. They are not a claim about allocator capacity or exact
/// retained memory. Duplicate submissions and native application work have
/// independent cumulative ceilings. The envelope is renewed only by a new
/// connector attempt or an explicit ICE restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingRemoteCandidatePolicy {
    local_ceiling: Option<PendingRemoteCandidateLocalCeiling>,
}

/// Explicit optional deployment/test envelope for one ICE attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingRemoteCandidateLocalCeiling {
    max_unique_items: NonZeroUsize,
    max_content_bytes: NonZeroUsize,
    max_duplicate_submissions: NonZeroUsize,
    max_application_work: NonZeroUsize,
}

impl PendingRemoteCandidatePolicy {
    pub const fn new(
        max_unique_items: NonZeroUsize,
        max_content_bytes: NonZeroUsize,
        max_duplicate_submissions: NonZeroUsize,
        max_application_work: NonZeroUsize,
    ) -> Self {
        Self {
            local_ceiling: Some(PendingRemoteCandidateLocalCeiling {
                max_unique_items,
                max_content_bytes,
                max_duplicate_submissions,
                max_application_work,
            }),
        }
    }

    /// Provider-backed candidate work with no product item ceiling.
    pub const fn elastic() -> Self {
        Self {
            local_ceiling: None,
        }
    }

    pub const fn local_ceiling(self) -> Option<PendingRemoteCandidateLocalCeiling> {
        self.local_ceiling
    }
}

impl PendingRemoteCandidateLocalCeiling {
    pub const fn max_unique_items(self) -> NonZeroUsize {
        self.max_unique_items
    }

    pub const fn max_content_bytes(self) -> NonZeroUsize {
        self.max_content_bytes
    }

    pub const fn max_duplicate_submissions(self) -> NonZeroUsize {
        self.max_duplicate_submissions
    }

    pub const fn max_application_work(self) -> NonZeroUsize {
        self.max_application_work
    }
}

/// Why a connector profile was refused.
///
/// One variant, and the two that stood beside it are gone rather than
/// deprecated. `RealtimeProfileRequiresLocalCeiling` refused the elastic
/// deployment this release exists to support, and
/// `RealtimeProfileExceedsFlowCeiling` compared a number the profile no longer
/// carries against a ceiling that is now enforced where it is held. Neither can
/// be reached any more, so neither is described any more.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WebRtcConnectorProfileError {
    #[error("a real-time codec profile requires the connector's real-time policy to be enabled")]
    RealtimeProfileRequiresRealtime,
}

/// WebRTC-specific construction and work policy for one Mesh runtime.
///
/// The process resource owner never inspects this profile. It owns only the
/// connector-neutral resource ownership. WebRTC callback, ICE candidate,
/// and temporary compatibility-provider choices stay at the transport edge.
/// No longer `Copy`: the real-time profile it now carries owns its codec
/// registrations, and interning them to keep a marker copyable would buy
/// nothing but a lifetime to get wrong. The getters take `&self` instead, so
/// every existing `profile.callbacks()` call still reads the same.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebRtcConnectorProfile {
    callbacks: ConnectorCallbackPolicy,
    remote_candidates: PendingRemoteCandidatePolicy,
    realtime: Option<super::RealtimeProfile>,
}

impl WebRtcConnectorProfile {
    pub const fn new(
        callbacks: ConnectorCallbackPolicy,
        remote_candidates: PendingRemoteCandidatePolicy,
    ) -> Self {
        Self {
            callbacks,
            remote_candidates,
            realtime: None,
        }
    }

    /// Supply the application's real-time codec profile.
    ///
    /// The only public way a real-time profile reaches the connector, and it
    /// takes an already-validated [`super::RealtimeProfile`] — so the shape
    /// refusals happen once, at parse time, where the application can still
    /// say which line of its configuration was wrong.
    ///
    /// It must be set before the peer connection exists, because codec
    /// registration is a property of the media engine a connection is built
    /// from. There is no later point at which core could accept one, and
    /// therefore no point at which core could fall back to a built-in list.
    ///
    /// It refuses exactly one thing: a profile on a connector whose realtime
    /// policy is `Disabled`. That is a contradiction the owner can only have
    /// stated by mistake — codecs registered on a connector that will admit no
    /// flow at all.
    ///
    /// **`Enabled(None)` is accepted, and that is the elastic case, not a
    /// missing one.** A profile states *which encodings the application can
    /// carry* and nothing else. How many concurrent flows may exist is the
    /// owner's to say through its envelope, or the owner's to leave open — so a
    /// profile carries no capacity of its own and is checked against none. A
    /// second number here would describe the same thing the envelope already
    /// describes, and requiring one would make "I have codecs and no fixed
    /// ceiling" — the ordinary elastic deployment — unstateable.
    ///
    /// Nothing is counted here, and nothing needs to be. The registry remains
    /// the sole enforcer of concurrency, and it enforces the owner's real
    /// ceilings when there are ceilings and the provider's real leases when
    /// there are not. There is no shadow ceiling in this file and no second
    /// counter to drift from the first.
    pub fn with_realtime_profile(
        mut self,
        profile: super::RealtimeProfile,
    ) -> std::result::Result<Self, WebRtcConnectorProfileError> {
        match self.callbacks.realtime() {
            crate::runtime::attempt::RealtimeConnectorPolicy::Disabled => {
                return Err(WebRtcConnectorProfileError::RealtimeProfileRequiresRealtime)
            }
            crate::runtime::attempt::RealtimeConnectorPolicy::Enabled(_) => {}
        }
        self.realtime = Some(profile);
        Ok(self)
    }

    pub const fn callbacks(&self) -> ConnectorCallbackPolicy {
        self.callbacks
    }

    pub const fn remote_candidates(&self) -> PendingRemoteCandidatePolicy {
        self.remote_candidates
    }

    /// The application's registered real-time codecs, if it supplied any.
    ///
    /// Borrowed, and crate-internal: the daemon supplies this profile and
    /// core reads it. Handing a copy back out would invite a caller to treat
    /// its own edit as configuration.
    pub(crate) fn realtime(&self) -> Option<&super::RealtimeProfile> {
        self.realtime.as_ref()
    }
}

// A guessed Annex-B fragment stop used to live here: one constant, 2048,
// chosen against an estimate of a large keyframe. It is gone, and nothing
// replaces it in this file. Retention on an inbound path is bounded where the
// bound can be exact — `RealtimeAssemblyReservation::retain_ordered_fragment`,
// which admits each fragment against the owner's selected ceilings and against
// a real provider claim. A second bound in front of that could only be a guess,
// and a guess that fires first is the one that decides: it would cap a stream
// the owner had deliberately provisioned for, and would do it in units the
// owner never chose.
