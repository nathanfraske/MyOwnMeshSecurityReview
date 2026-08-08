//! WebRTC transport. Wraps `webrtc-rs` so the engine can drive peer
//! connections without dealing with the crate's callback-driven API
//! directly. Every transport event lands on the exact worker's
//! bounded mailbox and is handled in order by that worker's pump.
//!
//! Architecture:
//!
//! - One [`Transport`] per engine instance — owns the shared
//!   `webrtc::api::API` (codec / interceptor / setting registries).
//! - One [`PeerSession`] per remote peer — owns the
//!   `RTCPeerConnection` and the application data channel. Drops
//!   close the connection.
//! - Events ([`TransportEvent`]) flow out of `PeerSession` on a
//!   bounded mpsc. One worker pump handles each peer in order, while
//!   exact owner checks fence replacement races.

pub mod diag;
pub mod ice;
pub(crate) mod webrtc;

pub use diag::{
    IceCandidateKind, IceCandidateStats, IceCheckSnapshot, IcePairSnapshot, PeerDiag,
    SelectedCandidatePair,
};
pub use ice::{build_rtc_configuration, classify_candidate_sdp};
#[cfg(not(feature = "transport-lab"))]
pub(crate) use webrtc::TransportEvent;
#[cfg(feature = "legacy-media")]
#[allow(
    deprecated,
    reason = "these are the explicit deprecated legacy-media compatibility exports"
)]
#[deprecated(
    since = "0.3.2",
    note = "temporary legacy H.264 and Opus compatibility surface"
)]
pub use webrtc::{
    resolved_media_lanes, AudioSample, LaneKind, LegacyWebRtcMediaProfile,
    LegacyWebRtcMediaProfileError, VideoSample, MEDIA_LANES,
};
#[cfg(feature = "transport-lab")]
pub use webrtc::{
    transport_lab_connector_fixture_grant, transport_lab_remote_candidate_fixture_grant,
    transport_lab_remote_description_fixture_grant, TransportEvent,
};
// `EndpointAuthHandoff` is deliberately no longer re-exported: it is now an
// internal WebRTC detail that converts to the generic
// `connector::ConnectedChannelHandoff` at the boundary, and endpoint
// authentication names only the generic form.
/// Controls only. Named here so the live open-path controls can arm a connector
/// to withhold one binding component.
///
/// There is no production re-export, because the type does not exist outside
/// the controls. The gate carries `transport-lab` as well as `test` to match
/// both the type itself and its only consumers, the live open-path controls: a
/// default-feature test build has no live link to arm, so re-exporting there
/// would name something that neither exists nor could be used.
#[cfg(all(test, feature = "transport-lab"))]
pub(crate) use webrtc::WithheldBindingComponent;
pub(crate) use webrtc::{
    DataChannelOpenOwnership, RemoteCandidateDisposition, WebRtcConnectorEvent,
    WebRtcConnectorIncarnation, WebRtcConnectorWorker,
};
pub use webrtc::{
    LocalIceCandidate, PeerSession, PendingRemoteCandidatePolicy, Role, Transport,
    WebRtcConnectorProfile, WebRtcConnectorProfileError,
};
