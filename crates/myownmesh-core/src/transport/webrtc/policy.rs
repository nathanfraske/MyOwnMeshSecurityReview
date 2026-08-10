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

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WebRtcConnectorProfileError {
    #[error("a real-time codec profile requires the connector's real-time policy to be enabled")]
    RealtimeProfileRequiresRealtime,
    #[error("a real-time codec profile requires an owner-selected local flow ceiling")]
    RealtimeProfileRequiresLocalCeiling,
    #[error(
        "the real-time profile advertises {advertised} concurrent flows but the owner ceiling \
         admits {enforced}"
    )]
    RealtimeProfileExceedsFlowCeiling { advertised: usize, enforced: usize },
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
    /// Fallible because advertised capacity and enforced capacity must not be
    /// able to diverge. `flow_capacity` is what the application tells its peer
    /// it will carry; the owner's `ConnectorRealtimeFlowCapacities` is what
    /// the registry will actually admit. If the first exceeds the second, the
    /// application has promised flows that will be refused one at a time at
    /// open, which reads as an intermittent fault rather than as the
    /// misconfiguration it is.
    ///
    /// Checked here rather than counted anywhere: there is no second counter
    /// and no shadow ceiling. The registry stays the sole enforcer, and this
    /// only refuses a profile that claims more than the enforcer will give.
    ///
    /// **This is an aggregate ceiling, not a guarantee for every
    /// distribution.** `flow_capacity` is one direction-agnostic number and
    /// the owner's envelope is two, so a profile can pass here and still be
    /// unsatisfiable in a particular mix: capacity 10 against a 9-inbound,
    /// 1-outbound ceiling admits ten flows only if at most one of them is
    /// outbound. A second outbound flow is refused with
    /// [`super::RealtimeFlowError::FlowRefused`] at open, by the registry,
    /// which is the component that actually knows the direction.
    ///
    /// That asymmetry is deliberate. Splitting the profile's capacity by
    /// direction would move a connector-shaped decision into the application,
    /// which does not own the resource envelope and should not have to model
    /// it. What this check buys is that the clearly-wrong case — promising
    /// more flows than exist in any arrangement — is a named configuration
    /// error at construction rather than an intermittent-looking fault later.
    pub fn with_realtime_profile(
        mut self,
        profile: super::RealtimeProfile,
    ) -> std::result::Result<Self, WebRtcConnectorProfileError> {
        let enabled = match self.callbacks.realtime() {
            crate::runtime::attempt::RealtimeConnectorPolicy::Disabled => {
                return Err(WebRtcConnectorProfileError::RealtimeProfileRequiresRealtime)
            }
            crate::runtime::attempt::RealtimeConnectorPolicy::Enabled(Some(enabled)) => enabled,
            crate::runtime::attempt::RealtimeConnectorPolicy::Enabled(None) => {
                return Err(WebRtcConnectorProfileError::RealtimeProfileRequiresLocalCeiling)
            }
        };
        // The profile's capacity is a combined audio-plus-video count in one
        // direction-agnostic number, so it is measured against the total the
        // owner admits across both directions.
        let enforced = enabled
            .flows()
            .max_inbound_active_flows()
            .get()
            .saturating_add(enabled.flows().max_outbound_active_flows().get());
        let advertised = usize::from(profile.flow_capacity());
        if advertised > enforced {
            return Err(
                WebRtcConnectorProfileError::RealtimeProfileExceedsFlowCeiling {
                    advertised,
                    enforced,
                },
            );
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

/// Hard stop on how many RTP fragments one Annex-B unit may retain.
///
/// A property of the framing adapter, not of any codec policy: a unit needing
/// more fragments than this is a wedged stream rather than a large picture — a
/// 40 Mbps keyframe runs to roughly four hundred — and continuing to retain
/// them would grow without bound on an inbound path a peer controls.
///
pub const ANNEXB_MAX_FRAGMENTS_PER_UNIT: usize = 2_048;

#[cfg(test)]
mod tests {
    use super::*;

    /// The Annex-B fragment hard stop is a real bound, not a placeholder.
    ///
    /// A unit is allowed to span many fragments — a large keyframe genuinely
    /// does — and the stop is far enough above that to be a wedged-stream
    /// detector rather than a picture-size limit.
    #[test]
    fn v4_macro1_the_annexb_fragment_stop_is_above_any_real_unit() {
        // ~400 fragments is a 40 Mbps keyframe at MTU-sized payloads.
        assert!(
            ANNEXB_MAX_FRAGMENTS_PER_UNIT > 400,
            "a stop at or below a real keyframe would drop valid media rather \
             than catching a wedged stream"
        );
        // And bounded, which is the whole point: an inbound path a peer drives
        // must not be able to grow retention without limit.
        assert!(ANNEXB_MAX_FRAGMENTS_PER_UNIT < usize::MAX);
    }
}
