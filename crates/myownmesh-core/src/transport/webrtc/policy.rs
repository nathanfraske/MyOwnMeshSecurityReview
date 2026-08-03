//! WebRTC-specific connector policy.
//!
//! The process resource owner remains connector-neutral. ICE candidate work
//! and the temporary legacy media provider are transport-edge choices owned by
//! this profile.

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
            max_unique_items,
            max_content_bytes,
            max_duplicate_submissions,
            max_application_work,
        }
    }

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

/// Temporary provider-specific H.264 and Opus media compatibility profile.
///
/// Generic real-time ownership never creates media tracks. This explicit
/// profile is the only construction input that can request the legacy WebRTC
/// adapter. Lane suspension and finalization are explicit events.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegacyWebRtcMediaProfile {
    max_lanes_per_kind: NonZeroUsize,
    preprovisioned_video_lanes: usize,
    preprovisioned_audio_lanes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum LegacyWebRtcMediaProfileError {
    #[error(
        "legacy WebRTC media lane ceiling {requested} exceeds the fixed compatibility provider ceiling {maximum}"
    )]
    LaneIdentitySpaceExceeded { requested: usize, maximum: usize },
    #[error(
        "legacy WebRTC media pre-provisions {preprovisioned} {kind} lanes but its per-kind ceiling is {maximum}"
    )]
    PreprovisionedLanesExceedCeiling {
        kind: &'static str,
        preprovisioned: usize,
        maximum: usize,
    },
}

impl LegacyWebRtcMediaProfile {
    pub fn h264_opus(
        max_lanes_per_kind: NonZeroUsize,
        preprovisioned_video_lanes: usize,
        preprovisioned_audio_lanes: usize,
    ) -> std::result::Result<Self, LegacyWebRtcMediaProfileError> {
        let maximum = max_lanes_per_kind.get();
        if maximum > LEGACY_MEDIA_MAX_LANES_PER_KIND {
            return Err(LegacyWebRtcMediaProfileError::LaneIdentitySpaceExceeded {
                requested: maximum,
                maximum: LEGACY_MEDIA_MAX_LANES_PER_KIND,
            });
        }
        for (kind, preprovisioned) in [
            ("video", preprovisioned_video_lanes),
            ("audio", preprovisioned_audio_lanes),
        ] {
            if preprovisioned > maximum {
                return Err(
                    LegacyWebRtcMediaProfileError::PreprovisionedLanesExceedCeiling {
                        kind,
                        preprovisioned,
                        maximum,
                    },
                );
            }
        }
        Ok(Self {
            max_lanes_per_kind,
            preprovisioned_video_lanes,
            preprovisioned_audio_lanes,
        })
    }

    pub const fn max_lanes_per_kind(self) -> NonZeroUsize {
        self.max_lanes_per_kind
    }

    pub const fn preprovisioned_video_lanes(self) -> usize {
        self.preprovisioned_video_lanes
    }

    pub const fn preprovisioned_audio_lanes(self) -> usize {
        self.preprovisioned_audio_lanes
    }

    pub const fn preprovisioned_outbound_flows(self) -> Option<usize> {
        self.preprovisioned_video_lanes
            .checked_add(self.preprovisioned_audio_lanes)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum WebRtcConnectorProfileError {
    #[error("legacy WebRTC media compatibility requires enabled generic real-time ownership")]
    LegacyMediaRequiresRealtime,
    #[error("legacy WebRTC media pre-provisioned flow count overflowed")]
    LegacyMediaFlowCountOverflow,
    #[error(
        "legacy WebRTC media pre-provisions {required_flows} outbound flows but the owner ceiling is {available_flows}"
    )]
    LegacyMediaExceedsOutboundFlowCeiling {
        required_flows: usize,
        available_flows: usize,
    },
    #[error("legacy H.264 fragment ceiling {requested} exceeds the adapter hard stop {maximum}")]
    LegacyH264FragmentCeilingExceeded { requested: usize, maximum: usize },
}

/// WebRTC-specific construction and work policy for one Mesh runtime.
///
/// The process resource owner never inspects this profile. It owns only the
/// connector-neutral candidate cardinality. WebRTC callback, ICE candidate,
/// and temporary compatibility-provider choices stay at the transport edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WebRtcConnectorProfile {
    callbacks: ConnectorCallbackPolicy,
    remote_candidates: PendingRemoteCandidatePolicy,
    legacy_media: Option<LegacyWebRtcMediaProfile>,
}

impl WebRtcConnectorProfile {
    pub const fn new(
        callbacks: ConnectorCallbackPolicy,
        remote_candidates: PendingRemoteCandidatePolicy,
    ) -> Self {
        Self {
            callbacks,
            remote_candidates,
            legacy_media: None,
        }
    }

    pub const fn callbacks(self) -> ConnectorCallbackPolicy {
        self.callbacks
    }

    pub const fn remote_candidates(self) -> PendingRemoteCandidatePolicy {
        self.remote_candidates
    }

    pub const fn legacy_media(self) -> Option<LegacyWebRtcMediaProfile> {
        self.legacy_media
    }

    #[cfg(any(test, feature = "legacy-media", feature = "transport-lab"))]
    pub fn with_legacy_webrtc_media(
        mut self,
        profile: LegacyWebRtcMediaProfile,
    ) -> std::result::Result<Self, WebRtcConnectorProfileError> {
        let enabled = match self.callbacks.realtime() {
            crate::runtime::attempt::RealtimeConnectorPolicy::Disabled => {
                return Err(WebRtcConnectorProfileError::LegacyMediaRequiresRealtime)
            }
            crate::runtime::attempt::RealtimeConnectorPolicy::Enabled(enabled) => enabled,
        };
        let required_flows = profile
            .preprovisioned_outbound_flows()
            .ok_or(WebRtcConnectorProfileError::LegacyMediaFlowCountOverflow)?;
        let available_flows = enabled.flows().max_outbound_active_flows().get();
        if required_flows > available_flows {
            return Err(
                WebRtcConnectorProfileError::LegacyMediaExceedsOutboundFlowCeiling {
                    required_flows,
                    available_flows,
                },
            );
        }
        let requested = enabled.flows().max_inbound_fragments_per_unit().get();
        if requested > LEGACY_H264_MAX_FRAGMENTS_PER_UNIT {
            return Err(
                WebRtcConnectorProfileError::LegacyH264FragmentCeilingExceeded {
                    requested,
                    maximum: LEGACY_H264_MAX_FRAGMENTS_PER_UNIT,
                },
            );
        }
        self.legacy_media = Some(profile);
        Ok(self)
    }
}

/// Fixed hard stop implemented by the temporary H.264 adapter.
pub const LEGACY_H264_MAX_FRAGMENTS_PER_UNIT: usize = 2_048;

/// Fixed lane count implemented by the temporary H.264 and Opus adapter.
pub const LEGACY_MEDIA_MAX_LANES_PER_KIND: usize = 8;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::attempt::{
        ConnectorCallbackMailboxCapacities, ConnectorCallbackPolicy,
        ConnectorCallbackServiceWeights, ConnectorRealtimeByteBudgets,
        ConnectorRealtimeFlowCapacities, ConnectorRealtimeFlowPolicy,
        ConnectorRealtimeInboundLimits, RealtimeConnectorPolicy, RealtimeQueueOverflowRule,
    };

    fn nz(value: usize) -> NonZeroUsize {
        NonZeroUsize::new(value).expect("test fixture value is nonzero")
    }

    #[test]
    fn v4_arc03h_legacy_lane_ceiling_matches_the_fixed_provider() {
        assert!(
            LegacyWebRtcMediaProfile::h264_opus(nz(LEGACY_MEDIA_MAX_LANES_PER_KIND), 0, 0).is_ok()
        );
        assert!(matches!(
            LegacyWebRtcMediaProfile::h264_opus(nz(LEGACY_MEDIA_MAX_LANES_PER_KIND + 1), 0, 0),
            Err(LegacyWebRtcMediaProfileError::LaneIdentitySpaceExceeded { .. })
        ));
    }

    #[test]
    fn v4_arc03h_legacy_h264_fragment_policy_cannot_exceed_adapter_hard_stop() {
        let flows = ConnectorRealtimeFlowPolicy::new(
            ConnectorRealtimeFlowCapacities::new(nz(1), nz(1), nz(1)),
            ConnectorRealtimeInboundLimits::new(
                nz(1),
                nz(LEGACY_H264_MAX_FRAGMENTS_PER_UNIT + 1),
                nz(1),
                nz(1),
                nz(1),
            ),
            ConnectorRealtimeByteBudgets::new(nz(2), nz(1)),
            RealtimeQueueOverflowRule::DropNewest,
        );
        let realtime = RealtimeConnectorPolicy::enabled(nz(1), flows)
            .expect("test policy is otherwise structurally valid");
        let callbacks = ConnectorCallbackPolicy::new(
            ConnectorCallbackMailboxCapacities::new(nz(1), nz(1)),
            ConnectorCallbackServiceWeights::new(nz(1), nz(1), nz(1)),
            realtime,
        )
        .expect("test callback policy is otherwise structurally valid");
        let profile = WebRtcConnectorProfile::new(
            callbacks,
            PendingRemoteCandidatePolicy::new(nz(1), nz(1), nz(1), nz(1)),
        );
        let legacy = LegacyWebRtcMediaProfile::h264_opus(nz(1), 0, 0)
            .expect("test provider is structurally valid");

        assert!(matches!(
            profile.with_legacy_webrtc_media(legacy),
            Err(WebRtcConnectorProfileError::LegacyH264FragmentCeilingExceeded {
                requested,
                maximum
            }) if requested == LEGACY_H264_MAX_FRAGMENTS_PER_UNIT + 1
                && maximum == LEGACY_H264_MAX_FRAGMENTS_PER_UNIT
        ));
    }
}
