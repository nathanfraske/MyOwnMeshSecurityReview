//! WebRTC peer connection wrapper. Bridges webrtc-rs's callback-driven
//! API to one bounded mailbox per connector worker.
//!
//! Lifecycle per peer:
//!
//! 1. The engine admits one connector candidate and calls
//!    [`Transport::open_connector_peer`] with [`Role::Offerer`] or
//!    [`Role::Answerer`]. A fresh [`WebRtcConnectorWorker`] owns the session.
//! 2. The worker creates and applies offers, answers, and remote descriptions;
//!    the engine moves the resulting transport control through signaling.
//! 3. ICE candidates flow both ways via signaling; the engine moves inbound
//!    candidates through its connector worker and the worker owns raw apply.
//! 4. A data-channel open promotes the exact connector candidate and hands its
//!    connected-channel capability to the Endpoint Auth Task.
//! 5. Connector retirement fences callbacks, drains owned work, and explicitly
//!    closes the native peer connection.

use std::future::Future;
use std::mem::size_of;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use bytes::Bytes;
use parking_lot::Mutex as SyncMutex;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use sha2::{Digest, Sha256};
#[cfg(any(test, feature = "transport-lab"))]
use tokio::sync::mpsc;
#[cfg(test)]
use tokio::sync::Semaphore;
use tokio::sync::{oneshot, watch};
use tracing::{debug, info, trace, warn};
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::ice_transport::ice_connection_state::RTCIceConnectionState;
use webrtc::interceptor::registry::Registry;
use webrtc::media::Sample;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::policy::ice_transport_policy::RTCIceTransportPolicy;
use webrtc::peer_connection::sdp::sdp_type::RTCSdpType;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::signaling_state::RTCSignalingState;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecCapability;
use webrtc::rtp_transceiver::rtp_codec::RTPCodecType;
use webrtc::rtp_transceiver::rtp_sender::RTCRtpSender;
use webrtc::rtp_transceiver::rtp_transceiver_direction::RTCRtpTransceiverDirection;
use webrtc::rtp_transceiver::{RTCRtpTransceiver, RTCRtpTransceiverInit};
use webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample;
use webrtc::track::track_local::TrackLocal;
use webrtc::track::track_remote::TrackRemote;

use crate::error::{Error, Result};
use crate::resource::{
    ObservationLease, PeerConnectionResourceScope, PreAuthResourceFamily, ProcessResourceRoot,
    ResourceMeasurement, ResourceReclaimSubscription, ResourceUnavailable, ResourceUse,
};
use crate::runtime::attempt::{
    admit_single_connector_candidate, AttemptLifetime, AttemptLiveness, ConnectorCallbackPolicy,
    ConnectorCandidateCapability, ConnectorResourceOwnerReport, ConnectorWorkResourceScope,
    EnabledRealtimeConnectorPolicy, MaxCumulativeRemoteCandidateApplications,
    MaxCumulativeRemoteCandidateContentBytes, MaxCumulativeRemoteCandidateSubmissions,
    MeshConnectorResourceReport, MeshConnectorResourceScope,
    OwnedRemoteCandidate as ElasticRemoteCandidateLease, RealtimeConnectorPolicy,
    RemoteCandidateAdmission as ElasticRemoteCandidateAdmission,
    RemoteCandidateAdmissionError as ElasticRemoteCandidateAdmissionError,
    RemoteCandidateApplyError as ElasticRemoteCandidateApplyError,
    RemoteCandidateAttempt as ElasticRemoteCandidateAttempt,
    RemoteCandidateDigestDecision as ElasticRemoteCandidateDigestDecision,
    RemoteCandidateInput as ElasticRemoteCandidateInput, RemoteCandidateLocalCeilings,
    RemoteCandidateTerminalReason as ElasticRemoteCandidateTerminalReason,
    WebRtcConnectorCapablePolicy,
};

use super::ice::build_rtc_configuration;

mod callback;
mod cleanup;
mod h264;
mod inbound;
mod policy;
mod provider;
mod realtime;
mod session_flow;
/// The application-facing WebRTC realtime vocabulary.
///
/// Public, and public *here* rather than in `crate::realtime`, because every
/// one of these carries something only a negotiated RTP clock makes readable.
/// The basal module holds what is true of any flow; this holds what is true of
/// a WebRTC one, and [`crate::JoinedNetwork`]'s `*_webrtc_realtime` methods are
/// where the two meet.
///
/// The four DTOs come from [`provider`] and the RTP kind from [`session_flow`],
/// which is a split worth stating: the kind is a *negotiation* primitive the
/// flow machinery selects capabilities with, so it lives beside that machinery
/// and is published from there; the DTOs exist only to cross the application
/// boundary and have no business inside the flow set.
pub use provider::{
    WebRtcRealtimeFlowOpen, WebRtcRealtimeInboundArrival, WebRtcRealtimeInboundUnit,
    WebRtcRealtimeOutboundUnit,
};
/// The connector's own short spelling of the profile.
///
/// Private, so it changes nothing for a caller. It exists because the public
/// name is qualified for the benefit of code that can see more than one
/// provider, and this module can see exactly one.
///
/// Only the profile. The other four qualified types above are constructed by
/// the daemon and validated by `RealtimeProfile::new`; nothing in the connector
/// names them outside the module that defines them, so importing them here
/// would be four names that document an expectation rather than a use.
use session_flow::RealtimeProfile;
pub use session_flow::WebRtcRtpKind;
/// The application's real-time configuration, and only that.
///
/// One of two public re-exports from this module. `crates/myownmesh` is a
/// separate crate, so the daemon cannot name anything `pub(crate)` here — but
/// the only thing it needs to name is the profile it parsed at startup. These
/// five types are inert plain data plus one validating constructor: they carry
/// no session, no incarnation, no label and no port, so publishing them hands
/// out no authority. Everything that *is* authority stays in the `pub(crate)`
/// list below.
///
/// **Published under qualified names, and that is not cosmetic.** A codec, a
/// framing strategy, an RTCP feedback mechanism and the profile that holds them
/// are WebRTC facts; an unqualified `RealtimeProfile` at the crate root reads as
/// *the* realtime profile, which invites an application to treat it as the
/// generic layer's concept and a second provider to believe it must fit into it.
/// There is no unqualified public spelling and no compatibility alias — a caller
/// updates the name or does not compile, which is the only signal strong enough
/// to relocate a concept.
///
/// Aliased rather than renamed at the definition because inside the connector
/// there is nothing to disambiguate from: `RealtimeProfile` is unambiguous in a
/// module that has no other kind of profile, and the qualification is only owed
/// to callers who see it next to other providers' vocabularies.
pub use session_flow::{
    RealtimeCodec as WebRtcRealtimeCodec, RealtimeFlowName,
    RealtimeFraming as WebRtcRealtimeFraming, RealtimeProfile as WebRtcRealtimeProfile,
    RealtimeProfileError as WebRtcRealtimeProfileError,
    RealtimeRtcpFeedback as WebRtcRealtimeRtcpFeedback,
};
/// The per-session flow vocabulary, and nothing else from that module.
///
/// A re-export rather than `pub(crate) mod`: the engine stores the flow set in
/// the promoted-session bundle and converts the rest at its DTO boundary, but
/// `RealtimeFlowLabels`, `RealtimeFlow` and `RealtimeFlowPort` must stay
/// unreachable from outside the connector. Widening the module would have
/// exposed all of them.
pub(crate) use session_flow::{
    RealtimeDirection, RealtimeEncoding, RealtimeFlowError, RealtimeFlowEvent, RealtimeFlowEvents,
    RealtimeFlowLabel, RealtimeFlowRemains, RealtimeFlowSetIdentity, RealtimeFlowSpec,
    RealtimeInboundArrivals, RealtimeRecvUnit, RealtimeSendUnit, RealtimeTrackIdentity,
    SessionRealtimeFlows,
};
mod unit_assembly;
use callback::*;
use cleanup::*;
use h264::*;
/// The session-gated inbound pump, and nothing public.
///
/// Private because there is no application vocabulary here to publish: an
/// inbound track's destination and framing are both facts this side
/// established, so nothing an application names is involved.
use inbound::*;
pub use policy::*;
use realtime::*;
/// Private, not added to the `pub(crate)` re-export above, and deliberately so.
///
/// All three are connector-internal: the binding table decides which flow a
/// negotiated track may attach to, the port handle is a pump's non-owning claim
/// on an already-open flow, and the unit policy is how a flow's framing reaches
/// it. Re-exporting any of them would put it in the engine's vocabulary, and the
/// engine has no business naming a demux table it must not write to — still less
/// a route to a flow's accounting that skips the session gate. A private `use`
/// makes them nameable here and in this module's children — which is exactly the
/// connector — and nowhere else.
///
/// `RealtimeInboundAttachment` is deliberately absent even though this module
/// uses one. `on_track` never writes the name: it binds the value `admit`
/// returns and destructures it into the pump's owner. Importing a type only to
/// leave it unwritten is an import that documents an intention rather than a
/// dependency, and it goes stale silently the moment the intention changes.
use session_flow::{RealtimeFlowPortHandle, RealtimeInboundBindings, RealtimeUnitPolicy};
use unit_assembly::*;

/// Interface-name prefixes for virtual / container / overlay networks
/// whose host addresses can never be reached by a remote peer. Gathering
/// ICE host candidates on them only bloats the candidate set and slows
/// the connectivity-check phase — a storage box running Docker routinely
/// carries three or more bridge gateways (`docker0`, `br-…`), each adding
/// a dead `172.x.0.1` host candidate that every peer then has to pair and
/// time out against. Real interfaces — physical NICs, Wi-Fi, and the
/// Tailscale tunnel (`tailscale0` / `utun*` / `wg*`), which is a
/// legitimate peer path — are deliberately *not* listed, so they keep
/// gathering candidates.
const VIRTUAL_IFACE_PREFIXES: &[&str] = &[
    "docker",  // docker0 and the default bridge
    "br-",     // docker user-defined bridge networks
    "veth",    // per-container veth pairs
    "virbr",   // libvirt
    "vmnet",   // vmware / parallels host-only nets
    "cni",     // container network interface plugins (k8s)
    "flannel", // flannel overlay
    "cali",    // calico
    "kube",    // kube-* bridges
];

/// True when `name` is a virtual interface we exclude from ICE gathering
/// (see [`VIRTUAL_IFACE_PREFIXES`]). Prefix match: `docker0`, `br-abc123`,
/// and `veth9f2` all hit; `eth0`, `wlan0`, `enp3s0`, and `tailscale0`
/// don't.
pub(crate) fn is_virtual_interface(name: &str) -> bool {
    VIRTUAL_IFACE_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

/// Stable label for the application data channel. Receivers can
/// filter the incoming [`on_data_channel`] event on this so other
/// channels (e.g. browser-initiated debug) don't get routed into
/// the mesh frame path.
pub const APP_DATA_CHANNEL_LABEL: &str = "myownmesh";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeDataChannelAdmission {
    Install,
    Violation(&'static str),
}

fn admit_native_data_channel(
    label: &str,
    application_channel_installed: bool,
) -> NativeDataChannelAdmission {
    if label != APP_DATA_CHANNEL_LABEL {
        return NativeDataChannelAdmission::Violation("unexpected application data-channel label");
    }
    if application_channel_installed {
        return NativeDataChannelAdmission::Violation("duplicate application data channel");
    }
    NativeDataChannelAdmission::Install
}

/// Who initiated this peer pairing. Drives whether we create the
/// data channel pre-offer (offerer) or wait for the peer to open
/// it (answerer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Offerer,
    Answerer,
}

/// Transport-layer event surfaced to the engine. The engine pumps
/// these on the network's main loop; nothing here lives across
/// tokio runtime ticks.
#[derive(Debug)]
pub enum TransportEvent {
    /// A locally-gathered ICE candidate the engine should ship to
    /// the peer over signaling. `None` after gathering completes.
    LocalIceCandidate(Option<LocalIceCandidate>),
    /// ICE connection state changed.
    IceConnectionStateChanged(RTCIceConnectionState),
    /// PeerConnection state changed (covers the full DTLS+ICE
    /// lifecycle, including `Failed` and `Closed`).
    PeerConnectionStateChanged(RTCPeerConnectionState),
    /// The data channel works and its exact connector is eligible for
    /// Endpoint Auth. This is not proof of application reachability.
    DataChannelOpen,
    /// Inbound application frame.
    Message(Bytes),
    /// Data channel closed (peer initiated or local error).
    DataChannelClosed,
    /// The local track set changed (a media lane opened or closed) and
    /// the SDP no longer matches — the engine should renegotiate in
    /// place (fresh offer, same DTLS fingerprint). Coalesced by the
    /// engine per peer, so a burst of lane changes costs one offer.
    RenegotiationNeeded,
    /// One assembled unit from a negotiated inbound real-time flow.
    ///
    /// The one inbound real-time crossing, reusing this queue rather than a
    /// second channel: two inbound paths would be two things that can stall
    /// independently, and an ordering between them to reason about.
    ///
    /// Codec-opaque and authority-free. It carries a label, a timestamp, a
    /// marker and bytes — no session reference, no capability, no peer
    /// identity. The admission decision was made before this existed, by
    /// matching the negotiated track against a binding this side established;
    /// an event that reached the engine cannot grant what the connector
    /// already refused.
    RealtimeUnit(RealtimeInboundDelivery),
}

/// One inbound realtime unit in transit from the connector to the engine.
///
/// Codec-opaque and authority-free by construction. Every field is private, so
/// nothing outside this crate can read the label back, reach the unit, or hold
/// the payload reservation — and nothing inside it can build one of these
/// except the connector's own inbound path.
///
/// It rides the existing inbound event stream rather than a second channel:
/// one inbound path means one thing that can stall, and no ordering to reason
/// about between two. Which of that stream's sources feeds it — the realtime
/// flow queue or a callback mailbox — decides how it is charged and capped, and
/// is settled at the emit site rather than here.
///
/// The label is demux data, not a handle. It names a flow *within one session*,
/// and the engine resolves that session at the fence before it delivers — so a
/// unit that arrives for a session that has since gone is dropped, and its
/// payload reservation is released with it rather than stranded.
pub struct RealtimeInboundDelivery {
    label: RealtimeFlowLabel,
    unit: RealtimeRecvUnit,
    /// Attached by the queue, then moved out with the unit and never released
    /// separately: whoever takes the unit takes responsibility for the bytes it
    /// occupies, and a delivery dropped undelivered releases them by dropping
    /// this.
    ///
    /// `Option` because the queue is what mints it. `enqueue_checked` validates
    /// the output reservation against its own registry, key and liveness before
    /// converting it to a lease, so a delivery that arrived holding one would
    /// mean either that conversion happened early and unvalidated, or that a
    /// second lease is about to be attached and the bytes counted twice.
    ///
    /// The property this gives up at the constructor is regained downstream:
    /// nothing but `enqueue_checked` puts one of these on the event stream, and
    /// it attaches before it queues. A delivery reaching the engine without a
    /// lease did not come through the accounting path at all.
    payload: Option<RealtimePayloadLease>,
}

/// Written out rather than derived, and it redacts.
///
/// [`TransportEvent`] is `Debug`, so this has to be — but a derive would print
/// the payload, and the payload is the peer's media. A unit that reaches a log
/// or a panic message is application content leaving the process through a
/// diagnostic channel that nothing audits. What is printed instead is what a
/// diagnostic actually needs: which flow it was for, how many bytes it carried,
/// and whether it is still holding a lease for them.
///
/// The byte count is not content. It is already visible to the resource owner
/// that admitted the unit, so reporting it here discloses nothing that side of
/// the boundary did not already account for.
impl std::fmt::Debug for RealtimeInboundDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealtimeInboundDelivery")
            .field("label", &self.label)
            .field("bytes", &self.unit.data.len())
            .field("leased", &self.payload.is_some())
            .finish()
    }
}

impl RealtimeInboundDelivery {
    /// Bind an assembled unit to the flow the connector's binding table
    /// resolved for the track it arrived on.
    pub(crate) fn new(label: RealtimeFlowLabel, unit: RealtimeRecvUnit) -> Self {
        Self {
            label,
            unit,
            payload: None,
        }
    }

    /// **Controls only.** A delivery for `name` that never passed the
    /// accounting path.
    ///
    /// The engine's unaccounted-delivery negative needs exactly one thing that
    /// production cannot produce: a delivery naming a live flow while carrying
    /// no payload lease. It is named for that, rather than reached by widening
    /// [`RealtimeFlowLabel::mint`] — a caller able to mint could make a *real*
    /// label outside admission, which is the opposite of what this proves.
    ///
    /// What is unaccounted is the **payload**. The label itself takes a real
    /// lease, against a control-only elastic scope created once here, because
    /// there is no such thing as an unleased label and a fixture that faked one
    /// would be proving something about a shape that cannot exist. That is also
    /// why the scope is never retired: a fixture label may outlive the control
    /// that made it.
    /// `pub(crate)`, matching [`RealtimeRecvUnit`]'s own visibility. The
    /// engine's lab control is in this crate, so that is the whole audience;
    /// a `pub` signature naming a `pub(crate)` type would be a private
    /// interface, and widening the unit to reach for `pub` would publish an
    /// inbound unit type nothing outside core has any use for.
    ///
    /// Gated on **both**, because its one caller is. The engine's negative is a
    /// `#[tokio::test]` that is itself `cfg(feature = "transport-lab")`, so
    /// `test` alone leaves this uncalled in a default-feature test build and
    /// the lab feature alone leaves it uncallable in a library build. The
    /// conjunction is the exact audience.
    ///
    /// The helper it calls stays plain `cfg(test)` on purpose: that one has a
    /// second caller in this module's own controls, which do not need the lab.
    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) fn unaccounted_for_test(name: &RealtimeFlowName, unit: RealtimeRecvUnit) -> Self {
        Self::new(control_label_for_test(name), unit)
    }

    /// How many payload bytes this delivery carries.
    ///
    /// Read at callback admission, which charges the delivery against the
    /// pump's class budget. Borrowing rather than consuming, because admission
    /// happens before the decision to take the event. Read from the unit rather
    /// than the lease, so it answers the same before and after attachment.
    pub(crate) fn payload_bytes(&self) -> usize {
        self.unit.data.len()
    }

    /// Take custody of the lease the queue minted for this delivery.
    ///
    /// Refuses a second attachment rather than overwriting, and hands the
    /// refused lease back so it is released rather than stranded. Overwriting
    /// would drop a live lease silently and leave the bytes it accounted for
    /// charged to nothing.
    fn attach(
        &mut self,
        payload: RealtimePayloadLease,
    ) -> std::result::Result<(), RealtimePayloadLease> {
        if self.payload.is_some() {
            return Err(payload);
        }
        self.payload = Some(payload);
        Ok(())
    }

    /// The lease, for the dequeue-time transition from queued to delivered.
    fn payload_mut(&mut self) -> Option<&mut RealtimePayloadLease> {
        self.payload.as_mut()
    }

    /// Split the delivery into the three parts a flow set enqueues.
    ///
    /// **Private, and that is the whole point of its scope.** Everything it
    /// hands back names [`RealtimePayloadLease`], which is a connector-internal
    /// type; a wider visibility would put a private type in a signature the
    /// engine could name, and the engine holding a bare lease is exactly the
    /// ownership it must not have — it could then drop the bytes' accounting
    /// separately from the unit they belong to. Rust's module privacy makes this
    /// callable from this module's descendants, which is precisely the set that
    /// may legally hold one: the flow set that enqueues it.
    ///
    /// By value on purpose: the three parts move together, so a delivery that
    /// has been split cannot be accidentally delivered twice.
    ///
    /// `None` for a delivery that never received a lease. That is not a state
    /// anything models — it means the delivery bypassed the one path that mints
    /// one — so it is refused rather than carried further as an `Option` into a
    /// flow set where it would have no meaning. Refused, not asserted: this
    /// rides an inbound path, and a wiring mistake should cost a dropped unit
    /// rather than the process.
    fn into_parts(self) -> Option<(RealtimeFlowLabel, RealtimeRecvUnit, RealtimePayloadLease)> {
        Some((self.label, self.unit, self.payload?))
    }
}

/// A real leased label for a control, over a scope that is never retired.
///
/// One shared elastic registry for every fixture label in the crate. Controls
/// and lab harnesses need labels that are *real* — minted at admission, holding
/// a real lease — without owning a session to mint them from, and a per-call
/// provider stack would be both slower and a second thing to keep in step.
///
/// The scope is created once and deliberately leaked. A fixture label can be
/// retained by a queued event that outlives the control that made it, so tying
/// the scope to any one control's lifetime would retire it under a live lease.
#[cfg(test)]
fn control_label_for_test(name: &RealtimeFlowName) -> RealtimeFlowLabel {
    static CONTROL_REGISTRY: std::sync::OnceLock<Arc<RealtimeFlowRegistry>> =
        std::sync::OnceLock::new();
    let registry = CONTROL_REGISTRY.get_or_init(|| {
        let (registry, resources) =
            RealtimeFlowRegistry::elastic_for_control(elastic_control_grant());
        std::mem::forget(resources);
        registry
    });
    RealtimeFlowLabel::mint(name.clone(), registry)
        .expect("the control grant admits one fixture label")
}

/// The grant every elastic control registry in this crate stands on.
///
/// **Two halves, and only one of them is a number anyone chose.** The
/// structural half is `explicit_test_grant(1, 1)` — the same mechanical
/// derivation the rest of the fixtures use, covering the process cleanup
/// infrastructure, one Mesh scope and one connector candidate with its
/// operation and reservation bookkeeping. That is what
/// [`RealtimeFlowRegistry::elastic_for_control`] actually builds, so listing
/// its dimensions by hand meant omitting whichever one nobody thought of; a
/// missing `SocketOrHandle` was exactly that.
///
/// The second half is deliberate headroom for the real-time leases the elastic
/// controls take — labels, profiles, flows, output and queued bytes, ready
/// records and packet work. It is generous on purpose and states nothing about
/// policy: an elastic control is about what the path *charges*, not about where
/// it stops, and the controls that care about stopping derive their own grant
/// exactly from the claim under test.
///
/// **The entries are the six dimensions the real-time claim constructors in
/// `realtime.rs` actually name**, not a list of the ones that happened to be
/// needed when it was written — the two byte-denominated classes
/// (`AccountedMemoryBytes` for retention, `QueuedBytes` for what
/// `queue_claim` charges) and the four counted ones. A dimension omitted here
/// is not a smaller grant, it is a zero, so the way this goes wrong is a
/// control failing on a class nobody thought to list. Re-derive by grepping
/// `ResourceClass::` in `realtime.rs` if a claim gains a term.
#[cfg(test)]
fn elastic_control_grant() -> crate::resource::ResourceClaim {
    crate::runtime::attempt::explicit_test_grant(1, 1)
        .checked_add(
            crate::resource::ResourceClaim::try_from_entries([
                (
                    crate::resource::ResourceClass::AccountedMemoryBytes,
                    1 << 24,
                ),
                (crate::resource::ResourceClass::QueuedBytes, 1 << 24),
                (crate::resource::ResourceClass::WorkerOrTask, 64),
                (crate::resource::ResourceClass::CallbackOrScheduledWork, 64),
                (crate::resource::ResourceClass::ParsingOrCpuWork, 64),
                (
                    crate::resource::ResourceClass::OpaqueDependencyResidual,
                    4_096,
                ),
            ])
            .expect("the elastic control headroom is representable"),
        )
        .expect("the elastic control grant is representable")
}

/// One negotiated native track for an outbound session flow.
///
/// Opaque to the engine on purpose: it is created by the connector, carried
/// across one await by the engine's negotiation phase, and handed either to
/// [`SessionRealtimeFlows::attach_outbound`] or straight back to the connector
/// for release. The engine can do nothing else with one — it holds no session,
/// no label and no capability, so possession authorizes nothing.
///
/// It carries the connector's own liveness handle alongside the track because
/// the pump needs both and they must not be able to drift: the incarnation is
/// the single authoritative source for whether this connector is still live,
/// and pairing it with the track here means a pump cannot be constructed
/// holding one without the other.
pub(crate) struct RealtimeOutboundTrack {
    track: Arc<TrackLocalStaticSample>,
    /// The only handle the peer connection accepts for detaching this track.
    ///
    /// Dropping it detaches nothing: `remove_track` is what flips the
    /// transceiver's direction and stops the sender, and until it runs the
    /// connection still holds and still offers to send on this m-line.
    sender: Arc<RTCRtpSender>,
    /// Held so whoever owns this value can actually retire it. Removal needs
    /// the connection, not just the sender, so carrying one without the other
    /// would make this type look retirable when it is not.
    pc: Arc<RTCPeerConnection>,
    /// The exact connector this track was negotiated on.
    incarnation: Arc<WebRtcConnectorIncarnation>,
}

impl RealtimeOutboundTrack {
    /// Detach this track from its connection.
    ///
    /// Consuming, because a detached track must not be detachable again. The
    /// pump is the single owner and calls this on **every** exit, so there is
    /// no second caller to race with.
    async fn retire(self) {
        if let Err(error) = self.pc.remove_track(&self.sender).await {
            warn!(?error, "detaching an outbound realtime track");
        }
    }
}

/// A flow's promise that its native half has actually been retired.
///
/// Completed by the pump after `remove_track` returns, so an awaiting close ack
/// means "the sender is gone", not "someone has been asked to remove it".
///
/// **Awaiting it is optional and that is the design.** The pump retires
/// unconditionally on every exit; this only reports when it finished. An
/// explicit close takes the receiver and awaits it outside the fence, so the
/// daemon's ack is truthful. An implicit session drop takes nothing and awaits
/// nothing — the queue dies with the flow set, the pump wakes on that, retires,
/// and completes into a receiver nobody holds. That is why the drop case needs
/// no engine hook and no async `Drop`: the cleanup owner is the pump either
/// way, and only the *reporting* differs.
pub(crate) type RealtimeNativeRetired = tokio::sync::oneshot::Receiver<()>;

/// The connector's view of the **current** session's inbound realtime wiring.
///
/// Two facts, held together because they are only ever meaningful together: the
/// session's binding table, and the transceivers this side created against the
/// tokens on it. Splitting them would allow a transceiver record to outlive the
/// table that gives its token meaning.
///
/// Shared by the worker, which writes it during negotiation, and the `on_track`
/// callback, which reads it when a track arrives.
pub(super) struct RealtimeSessionTracks {
    /// The current session's table, **weakly**.
    ///
    /// Weak is the correctness property, not hygiene. The table's whole job is
    /// to stop admitting media the moment its session ends; a strong reference
    /// here would keep it alive past the `PromotedSession` that owns the flows
    /// it names, leaving a table that still resolves tokens to labels in a flow
    /// set that no longer exists. A failed upgrade is the answer we want, and
    /// it arrives without anything having to be told.
    bindings: SyncMutex<std::sync::Weak<RealtimeInboundBindings>>,
    /// Transceivers created here, each against the token the fence bound before
    /// the transceiver existed.
    negotiated: SyncMutex<Vec<RealtimeNegotiatedTrack>>,
}

/// One transceiver this side created for a realtime flow.
///
/// It stays on the list from the moment it is created until its stop has
/// *completed*, and the two states are distinguished by `claimed` rather than by
/// presence. That is two properties at once, and neither survives if the record
/// is simply removed when someone decides to retire it:
///
/// - **Exactly one retirer.** Three parties can reach the same transceiver — an
///   explicit close, the pump that was feeding it, and the install that replaces
///   a session — and `claimed` is what makes the second and third arrivals
///   no-ops instead of a second `stop` on a stopped transceiver.
/// - **Classification survives retirement.** `on_track` decides whether a track
///   is realtime-owned by looking this list up. A record removed at the start of
///   a retirement would make a track arriving during it look like a track this
///   side never negotiated — a track the peer named — when in fact it is one we
///   solicited and are in the middle of taking back.
struct RealtimeNegotiatedTrack {
    identity: Arc<RealtimeTrackIdentity>,
    transceiver: Arc<RTCRtpTransceiver>,
    retirement: RealtimeRetirement,
}

/// Who stops one native object, and what everyone else is told.
///
/// Deliberately holds no native object of its own. The two hard parts of this
/// are the claim and the completion, and neither has anything to do with what is
/// being stopped — keeping them separate is what lets a control exercise the
/// race directly instead of standing up a peer connection to reach it.
struct RealtimeRetirement {
    /// Whether someone has already taken responsibility.
    claimed: bool,
    /// Flips once that responsibility has been *discharged*.
    ///
    /// Single ownership decides who acts; this decides what everyone else is
    /// told. A caller that loses the claim must not return as though the work
    /// were done — on an explicit close that return is the daemon's
    /// acknowledgement, and answering before the transceiver is actually stopped
    /// would let a reopen on the same label race one still offering to receive.
    /// So a loser waits here instead of no-opping.
    ///
    /// A `watch` rather than a `Notify`, because completion is a *state* and a
    /// waiter that subscribes after it has already happened must still see it. A
    /// notification goes to whoever is parked at that instant and is lost
    /// otherwise, which is the missed-wake this module avoids everywhere else.
    /// Behind an `Arc` because a `watch::Sender` is not `Clone` and the claimant
    /// carries it out of the lock.
    done: Arc<watch::Sender<bool>>,
}

/// What a won claim carries out of the lock: the right to stop this one thing,
/// and the obligation to announce that it is stopped.
struct RealtimeTrackClaim {
    identity: Arc<RealtimeTrackIdentity>,
    transceiver: Arc<RTCRtpTransceiver>,
    done: Arc<watch::Sender<bool>>,
}

impl RealtimeRetirement {
    fn new() -> Self {
        let (done, _) = watch::channel(false);
        Self {
            claimed: false,
            done: Arc::new(done),
        }
    }

    /// Take responsibility, or find out who already has.
    ///
    /// `Ok` is the claim and comes with the completion channel to announce on.
    /// `Err` is a subscription to the winner's announcement — not a refusal, and
    /// never to be treated as "already done".
    fn claim(&mut self) -> std::result::Result<Arc<watch::Sender<bool>>, watch::Receiver<bool>> {
        if self.claimed {
            return Err(self.done.subscribe());
        }
        self.claimed = true;
        Ok(Arc::clone(&self.done))
    }
}

/// Wait for the caller who won a claim to finish.
///
/// A dropped sender is completion, not failure: the only thing that drops one is
/// the record being forgotten, and a record is forgotten only after its stop has
/// returned. There is nothing a caller could do differently either way, so the
/// error is not surfaced.
async fn await_retirement(mut done: watch::Receiver<bool>) {
    let _ = done.wait_for(|done| *done).await;
}

impl Default for RealtimeSessionTracks {
    fn default() -> Self {
        Self {
            bindings: SyncMutex::new(std::sync::Weak::new()),
            negotiated: SyncMutex::new(Vec::new()),
        }
    }
}

impl RealtimeSessionTracks {
    /// Point at a newly promoted session's table, replacing any previous one,
    /// and retire everything the old session left behind.
    ///
    /// **Retire, not clear.** The old records' tokens were bound in a table that
    /// died with its session, so none of them will ever admit a track again —
    /// but the transceivers are still on the peer connection, still `recvonly`,
    /// and dropping the records would leave nothing able to name them. That is
    /// the leak for the case with no other owner at all: a flow whose transceiver
    /// was created and whose track never arrived has no pump, so the pump's own
    /// cleanup never runs and this is the only sweep that reaches it.
    ///
    /// Claimed synchronously, stopped asynchronously. The claim is what makes
    /// this disjoint from an old pump racing the same edge — whichever gets
    /// there first is the only one that stops — and it happens under the same
    /// lock acquisition that replaces the table, so there is no window in which
    /// a record is neither this install's responsibility nor its previous
    /// owner's. The records stay on the list until their stops complete, so a
    /// late track arriving on one is still classified as realtime-owned and
    /// refused for the reason it was actually refused for.
    fn install(self: &Arc<Self>, bindings: std::sync::Weak<RealtimeInboundBindings>) {
        // Order matters only in that both are replaced before anything can
        // observe a half-installed pair; each lock is taken and released on its
        // own, and `on_track` reads them in the opposite order, so no caller
        // can hold one while waiting on the other.
        *self.bindings.lock() = bindings;
        // Claimed *and* taken in one locked pass. Marking here and re-claiming
        // on the task would find every record already claimed and stop nothing,
        // so the transceiver comes out with the claim rather than being looked
        // up again from a token whose record now says someone else owns it.
        let superseded: Vec<RealtimeTrackClaim> = {
            let mut negotiated = self.negotiated.lock();
            negotiated
                .iter_mut()
                .filter_map(|track| {
                    let done = track.retirement.claim().ok()?;
                    Some(RealtimeTrackClaim {
                        identity: Arc::clone(&track.identity),
                        transceiver: Arc::clone(&track.transceiver),
                        done,
                    })
                })
                .collect()
        };
        if superseded.is_empty() {
            return;
        }
        let tracks = Arc::clone(self);
        // Fire and forget, and only here. Nobody is acknowledging a superseded
        // session's teardown, so there is no answer whose truthfulness depends
        // on waiting; an explicit close is the opposite and awaits.
        tokio::spawn(async move {
            for claim in superseded {
                tracks.stop_owned(claim).await;
            }
        });
    }

    /// The current table, if its session is still alive.
    fn current(&self) -> Option<Arc<RealtimeInboundBindings>> {
        self.bindings.lock().upgrade()
    }

    fn record(&self, identity: Arc<RealtimeTrackIdentity>, transceiver: Arc<RTCRtpTransceiver>) {
        self.negotiated.lock().push(RealtimeNegotiatedTrack {
            identity,
            transceiver,
            retirement: RealtimeRetirement::new(),
        });
    }

    /// The token a track arriving on `transceiver` was negotiated against.
    ///
    /// **Pointer identity against a transceiver this side created**, which is
    /// the strongest form the demux key can take: the peer cannot produce one,
    /// cannot name one, and nothing about it appears in SDP.
    ///
    /// If a future `webrtc` release stopped handing `on_track` the same `Arc`
    /// the connection stores, this answers `None` and the track is dropped.
    /// That is the intended degradation — a refusal, never a misattachment.
    /// The obvious fallback, comparing MIDs, is deliberately absent: a MID is a
    /// string that appears in SDP, and reintroducing it as a key is exactly the
    /// property this token was minted to remove.
    /// Answers for a retiring record as readily as for a live one. The question
    /// it exists to settle is "did this side create this transceiver for a
    /// realtime flow", and the answer to that does not change when someone
    /// starts stopping it.
    fn resolve(&self, transceiver: &Arc<RTCRtpTransceiver>) -> Option<Arc<RealtimeTrackIdentity>> {
        self.negotiated
            .lock()
            .iter()
            .find(|track| Arc::ptr_eq(&track.transceiver, transceiver))
            .map(|track| Arc::clone(&track.identity))
    }

    /// Drop one record, once its transceiver is stopped.
    fn forget(&self, identity: &Arc<RealtimeTrackIdentity>) {
        self.negotiated
            .lock()
            .retain(|track| !Arc::ptr_eq(&track.identity, identity));
    }

    /// Stop one token's transceiver, and do not return until it is stopped.
    ///
    /// The whole retirement path, and the only one. Three parties reach it — an
    /// explicit close, the pump that was feeding the flow, and the install that
    /// supersedes the session — and none can know which of the others got there
    /// first, so the answer comes from the record rather than from an ordering
    /// rule each of them has to remember.
    ///
    /// All three outcomes end with the transceiver stopped by the time this
    /// returns: the caller that wins the claim stops it, a caller that loses
    /// waits for the winner, and a caller that finds no record at all is looking
    /// at a retirement that has already completed and been forgotten. That
    /// uniformity is what makes it safe for the daemon to acknowledge a close as
    /// soon as this returns.
    async fn stop_claimed(&self, identity: &Arc<RealtimeTrackIdentity>) {
        // Claimed under the lock, stopped outside it: `stop` awaits and the
        // record list is guarded by a sync mutex.
        let claim = {
            let mut negotiated = self.negotiated.lock();
            let Some(track) = negotiated
                .iter_mut()
                .find(|track| Arc::ptr_eq(&track.identity, identity))
            else {
                // No record: already stopped and forgotten.
                return;
            };
            match track.retirement.claim() {
                Ok(done) => Ok(RealtimeTrackClaim {
                    identity: Arc::clone(identity),
                    transceiver: Arc::clone(&track.transceiver),
                    done,
                }),
                Err(waiting) => Err(waiting),
            }
        };
        match claim {
            Ok(claim) => self.stop_owned(claim).await,
            Err(waiting) => await_retirement(waiting).await,
        }
    }

    /// Finish a retirement whose claim the caller already holds.
    ///
    /// Taking the claim by value is what says the right to stop came with it:
    /// there is no path here that looks a token up and stops whatever it finds.
    async fn stop_owned(&self, claim: RealtimeTrackClaim) {
        let RealtimeTrackClaim {
            identity,
            transceiver,
            done,
        } = claim;
        if let Err(error) = transceiver.stop().await {
            // The flow is going away regardless; a failed stop is worth knowing
            // about and is not worth failing a teardown over.
            warn!(?error, "stopping a negotiated inbound realtime transceiver");
        }
        // Announced before the record goes, so a waiter that subscribed to this
        // record's channel is released by the value rather than by the sender
        // dropping. `send_replace` because there may be no waiter at all, which
        // is the ordinary case and not a failure.
        done.send_replace(true);
        // Last, so the record stays resolvable for the whole of the stop and a
        // track arriving during it is still refused as realtime-owned.
        self.forget(&identity);
    }
}

/// The RTP transceiver primitive one encoding negotiates.
///
/// A total map, and the only place this module turns the application's declared
/// media kind into the library's. It reads no MIME name.
fn native_codec_type(kind: WebRtcRtpKind) -> RTPCodecType {
    match kind {
        WebRtcRtpKind::Audio => RTPCodecType::Audio,
        WebRtcRtpKind::Video => RTPCodecType::Video,
    }
}

/// The declared media kind a negotiated track carries.
///
/// The inverse of [`native_codec_type`], for the admission comparison. The
/// library's enum is `non_exhaustive` in practice — it carries an
/// `Unspecified` — and anything that is neither audio nor video is mapped to
/// `None` rather than guessed: an unspecified kind matches no binding, and a
/// track that matches no binding is dropped.
fn native_rtp_kind(kind: RTPCodecType) -> Option<WebRtcRtpKind> {
    match kind {
        RTPCodecType::Audio => Some(WebRtcRtpKind::Audio),
        RTPCodecType::Video => Some(WebRtcRtpKind::Video),
        _ => None,
    }
}

/// Drain one outbound session flow onto its negotiated native track, and retire
/// that track when the flow ends.
///
/// **The pump is the single owner of the native half.** It holds the track, the
/// sender and the connection, and on *every* exit — closed queue, retired
/// connector, failed write — it awaits `remove_track` before returning. Nothing
/// else may detach, so there is no double-remove to prevent and no flag to keep
/// in step.
///
/// That ownership is what closes the implicit case as well as the explicit one.
/// Dropping a `SessionRealtimeFlows` with live flows drops their queues; each
/// pump wakes on that, retires its track, and completes. No async `Drop` is
/// needed anywhere, and session retirement does not have to be distinguished
/// from an application close — the pump cannot tell them apart and does not
/// need to.
///
/// Dropping the sender `Arc` is **not** a detach. `remove_track` is what flips
/// the transceiver direction and stops the sender
/// (`peer_connection/mod.rs:1786-1791` in the vendored crate); until it runs the
/// connection still offers to send on that m-line. An earlier version of this
/// pump held the sender as `_sender` and returned, which retired nothing.
///
/// Two rechecks per unit, and both are needed:
///
/// - the queue upgrade, which is the **session** check. The queue is owned by
///   the flow, the flow by the flow set, the flow set by `PromotedSession`, so
///   a failed upgrade means the session that authorized this flow is gone.
///   Nothing else has to be consulted, and nothing else could be — the pump
///   runs outside the registry fence and cannot take it.
/// - `is_active`, which is the **connector** check. A connector can retire
///   while its session is still promoted, and writing to a retired
///   connector's track would push bytes through a transport this side has
///   already given up.
///
/// The write itself happens here rather than under the fence because it awaits,
/// and the fence is a sync mutex that connector replacement also takes.
///
/// Private, matching its parameter. `RealtimeOutboundPump` is `pub(super)` in
/// the flow module — visible exactly within the connector — so a `pub(super)`
/// here would have published a function whose argument type its own audience
/// could not name. Module privacy already reaches the one caller,
/// `attach_outbound`, which is a descendant of this module; nothing wider ever
/// needed it, and narrowing the function is the fix rather than widening the
/// pump, which would hand out a way to write to a flow's queue.
fn spawn_outbound_realtime_pump(
    pump: session_flow::RealtimeOutboundPump,
    track: RealtimeOutboundTrack,
    retired: tokio::sync::oneshot::Sender<()>,
) {
    tokio::spawn(async move {
        // One exit point, so "retire on every exit" is structural rather than a
        // rule each `return` has to remember. The inner block produces nothing;
        // everything after it runs however it ended.
        let incarnation = Arc::clone(&track.incarnation);
        let native = Arc::clone(&track.track);
        async {
            loop {
                match pump.next() {
                    session_flow::RealtimePumpStep::Unit(unit) => {
                        // Checked per unit rather than once at attach. A pump
                        // that proved liveness only when it started would keep
                        // writing for as long as the application kept feeding
                        // it.
                        if !incarnation.is_active() {
                            return;
                        }
                        if native
                            .write_sample(&Sample {
                                data: unit.data,
                                duration: unit.pace,
                                ..Default::default()
                            })
                            .await
                            .is_err()
                        {
                            // The native track is gone. Ending is the whole
                            // response; the retirement below still runs.
                            return;
                        }
                    }
                    // Nothing queued on a live flow is idle, not closed. Park.
                    session_flow::RealtimePumpStep::Empty => pump.ready().await,
                    // Terminal. The flow, and so the session, is gone. This is
                    // the implicit case too: a dropped flow set drops the
                    // queue, which lands here.
                    session_flow::RealtimePumpStep::Closed => return,
                }
            }
        }
        .await;
        // However that ended, the native half goes back. `retire` consumes the
        // track, so this cannot run twice.
        track.retire().await;
        // Last, and only after the detach has completed, so a waiting closer
        // that observes this has observed a finished retirement rather than a
        // scheduled one. Nobody may be waiting — implicit drop has no closer —
        // and that is why the error is discarded.
        let _ = retired.send(());
    });
}

/// Exact process-local identity for one WebRTC connector worker.
///
/// This is a stale-callback guard, not authority. Only a
/// `ConnectorCandidateCapability` can authorize an admitted candidate.
pub(crate) struct WebRtcConnectorIncarnation {
    active: AtomicBool,
    retired: watch::Sender<bool>,
    /// The transport-independent identity for this same incarnation.
    ///
    /// Owned here rather than replacing this type, so the WebRTC worker keeps
    /// its native retirement plumbing while endpoint authentication and any
    /// other downstream owner name only the generic identity. The generic token
    /// carries identity alone: this type stays the single authoritative source
    /// of whether the connector is still live, so there is no second liveness
    /// flag that could disagree with `active`.
    generic: Arc<crate::connector::ConnectorIncarnation>,
}

impl WebRtcConnectorIncarnation {
    fn new() -> Self {
        let (retired, _receiver) = watch::channel(false);
        Self {
            active: AtomicBool::new(true),
            retired,
            generic: crate::connector::ConnectorIncarnation::new(),
        }
    }

    fn retire(&self) {
        self.active.store(false, Ordering::Release);
        self.retired.send_replace(true);
    }

    /// The transport-independent identity for this exact incarnation.
    pub(crate) fn generic(&self) -> &Arc<crate::connector::ConnectorIncarnation> {
        &self.generic
    }

    pub(crate) fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    fn subscribe_retirement(&self) -> watch::Receiver<bool> {
        self.retired.subscribe()
    }
}

async fn await_until_connector_retirement<T>(
    mut retirement: watch::Receiver<bool>,
    work: impl Future<Output = T>,
) -> Option<T> {
    if *retirement.borrow() {
        return None;
    }
    tokio::pin!(work);
    tokio::select! {
        biased;
        _ = retirement.changed() => None,
        result = &mut work => Some(result),
    }
}

/// One callback value stamped with the exact worker that received it.
pub struct WebRtcConnectorEvent {
    incarnation: Arc<WebRtcConnectorIncarnation>,
    event: TransportEvent,
    _queue_observation: Option<ObservationLease>,
    _callback_work: Option<CallbackWorkLease>,
}

impl WebRtcConnectorEvent {
    /// Whether this is the data-channel-open callback. **Controls only.**
    ///
    /// A control that must hand the *genuine* native open event to the
    /// production engine arm has to recognise it without consuming it first —
    /// `accept_event` takes the event by value, so classifying through that
    /// would spend the very event the control needs to deliver. Read-only, and
    /// it exposes no payload: the answer is a bool, and the event's resources
    /// and its incarnation stay unreachable.
    ///
    /// Gated to match its only caller. The live pre-open fixture needs
    /// `transport-lab`, so gating on `test` alone would leave this with no
    /// caller in a default-feature test build — an orphan the compiler is right
    /// to refuse, and one that would have to be silenced with a mask rather
    /// than fixed.
    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) fn is_data_channel_open(&self) -> bool {
        matches!(self.event, TransportEvent::DataChannelOpen)
    }
}

/// Resource ownership retained while the engine handles one accepted native
/// callback. The fields are intentionally opaque outside this module.
pub(crate) struct AcceptedWebRtcConnectorEventResources {
    _queue_observation: Option<ObservationLease>,
    _callback_work: Option<CallbackWorkLease>,
}

/// One stale-owner-checked callback and the resources that remain owned until
/// its engine handler completes.
pub(crate) struct AcceptedWebRtcConnectorEvent {
    event: TransportEvent,
    resources: AcceptedWebRtcConnectorEventResources,
}

impl AcceptedWebRtcConnectorEvent {
    pub(crate) fn into_parts(self) -> (TransportEvent, AcceptedWebRtcConnectorEventResources) {
        (self.event, self.resources)
    }
}

struct QueuedTransportEvent {
    event: TransportEvent,
    observation: Option<ObservationLease>,
    callback_work: Option<CallbackWorkLease>,
}

impl QueuedTransportEvent {
    fn attach_realtime_reservation(
        &mut self,
        reservation: RealtimePayloadLease,
    ) -> std::result::Result<(), RealtimePayloadLease> {
        match &mut self.event {
            // Refuses a second attachment rather than overwriting: overwriting
            // would drop a live lease silently and leave the bytes it accounted
            // for charged to nothing, whereas handing the lease back means a
            // double attachment releases rather than strands.
            TransportEvent::RealtimeUnit(delivery) => delivery.attach(reservation),
            _ => Err(reservation),
        }
    }
}

fn callback_payload_limit(
    policy: ConnectorCallbackPolicy,
    class: ConnectorCallbackClass,
) -> Option<usize> {
    match class {
        ConnectorCallbackClass::Control => None,
        ConnectorCallbackClass::EndpointData => Some(crate::engine::MAX_ENDPOINT_FRAME_BYTES),
        ConnectorCallbackClass::Realtime => match policy.realtime() {
            RealtimeConnectorPolicy::Disabled => None,
            RealtimeConnectorPolicy::Enabled(Some(enabled)) => Some(enabled.max_unit_bytes().get()),
            RealtimeConnectorPolicy::Enabled(None) => None,
        },
    }
}

#[derive(Clone)]
struct ConnectorEventMailboxes {
    control: Arc<ResourceBackedCallbackMailbox>,
    endpoint_data: Arc<ResourceBackedCallbackMailbox>,
    lifecycle: Arc<ConnectorLifecycleOwner>,
    #[cfg(test)]
    callback_producer: CallbackProducerOwner,
}

impl ConnectorEventMailboxes {
    fn mailbox(&self, class: ConnectorCallbackClass) -> Option<&ResourceBackedCallbackMailbox> {
        match class {
            ConnectorCallbackClass::Control => Some(self.control.as_ref()),
            ConnectorCallbackClass::EndpointData => Some(self.endpoint_data.as_ref()),
            ConnectorCallbackClass::Realtime => None,
        }
    }

    #[cfg(test)]
    fn try_insert_for_test(
        &self,
        event: TransportEvent,
        observation: Option<ObservationLease>,
    ) -> std::result::Result<(), ConnectorCallbackInsertResult> {
        if matches!(&event, TransportEvent::DataChannelOpen) {
            return self
                .lifecycle
                .record_open()
                .accepted()
                .then_some(())
                .ok_or(ConnectorCallbackInsertResult::PolicyRefused);
        }
        if matches!(&event, TransportEvent::DataChannelClosed) {
            return self
                .lifecycle
                .record_close(false)
                .accepted()
                .then_some(())
                .ok_or(ConnectorCallbackInsertResult::PolicyRefused);
        }
        let class = ConnectorCallbackClass::for_event(&event);
        let (payload_bytes, retained_slack) = match &event {
            TransportEvent::Message(bytes) => (bytes.len(), 0),
            // The payload lease it carries bounds *registry* retention; this
            // bounds the callback pump's own class budget, which is what
            // decides whether the event is admitted to the callback queue at
            // all. Two ceilings over two different resources, so leaving this
            // at zero would not avoid a double count — it would let real-time
            // units bypass the callback ceiling that bounds them.
            TransportEvent::RealtimeUnit(delivery) => (delivery.payload_bytes(), 0),
            TransportEvent::LocalIceCandidate(candidate) => {
                let Some(sizes) = candidate_callback_sizes(candidate) else {
                    return Err(ConnectorCallbackInsertResult::PolicyRefused);
                };
                sizes
            }
            _ => (0, 0),
        };
        let work = self
            .callback_producer
            .try_admit_with_accounted_slack(class, payload_bytes, retained_slack)
            .map_err(|_| ConnectorCallbackInsertResult::Overloaded)?;
        let result = match event {
            TransportEvent::DataChannelOpen | TransportEvent::DataChannelClosed => unreachable!(
                "data-channel lifecycle events return before ordinary callback admission"
            ),
            TransportEvent::RenegotiationNeeded => self.lifecycle.record_renegotiation(work),
            TransportEvent::IceConnectionStateChanged(state) => {
                self.lifecycle.record_ice_state(state, work)
            }
            TransportEvent::PeerConnectionStateChanged(state) => {
                self.lifecycle.record_peer_state(state, work)
            }
            event => {
                let Some(mailbox) = self.mailbox(class) else {
                    return Err(ConnectorCallbackInsertResult::WrongOwnerPath);
                };
                return mailbox
                    .try_insert(QueuedTransportEvent {
                        event,
                        observation,
                        callback_work: Some(work),
                    })
                    .map_err(|error| match error.kind() {
                        CallbackMailboxInsertErrorKind::Closed => {
                            ConnectorCallbackInsertResult::ReceiverClosed
                        }
                        CallbackMailboxInsertErrorKind::LocalItemCeiling => {
                            ConnectorCallbackInsertResult::Overloaded
                        }
                        CallbackMailboxInsertErrorKind::MissingLease
                        | CallbackMailboxInsertErrorKind::WrongClass
                        | CallbackMailboxInsertErrorKind::WrongPhase => {
                            ConnectorCallbackInsertResult::PolicyRefused
                        }
                    });
            }
        };
        result
            .accepted()
            .then_some(())
            .ok_or(ConnectorCallbackInsertResult::PolicyRefused)
    }
}

#[derive(Clone)]
struct ConnectorEventSink {
    events: ConnectorEventMailboxes,
    realtime_flows: Arc<RealtimeFlowRegistry>,
    resource_scope: Option<PeerConnectionResourceScope>,
    attempt_liveness: Option<AttemptLiveness>,
    candidate_promoted: Arc<AtomicBool>,
    callback_gate: Arc<WebRtcConnectorIncarnation>,
    callback_violation_reported: Arc<AtomicBool>,
    callback_policy: ConnectorCallbackPolicy,
    callback_producer: CallbackProducerOwner,
    operation_fence: Arc<ConnectorOperationFence>,
    close_owner: Option<Weak<ConnectorCloseOwner>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectorCallbackInsertResult {
    Queued,
    DiscardedAfterClose,
    Overloaded,
    ReceiverClosed,
    PolicyRefused,
    WrongOwnerPath,
}

impl ConnectorCallbackInsertResult {
    const fn accepted(self) -> bool {
        matches!(self, Self::Queued | Self::DiscardedAfterClose)
    }
}

fn callback_admission_error(context: &'static str, error: CallbackProducerOverload) -> Error {
    match error {
        CallbackProducerOverload::ResourceUnavailable { unavailable, .. } => {
            Error::ResourceUnavailable(unavailable)
        }
        other => Error::Transport(format!("{context}: {other:?}")),
    }
}

impl ConnectorEventSink {
    fn begin_native_callback_operation(
        &self,
        class: ConnectorCallbackClass,
    ) -> std::result::Result<CallbackWorkLease, CallbackProducerOverload> {
        self.begin_native_callback_operation_with_payload(class, 0, 0)
    }

    fn begin_native_callback_operation_with_payload(
        &self,
        class: ConnectorCallbackClass,
        payload_bytes: usize,
        retained_slack: usize,
    ) -> std::result::Result<CallbackWorkLease, CallbackProducerOverload> {
        let mut work = self.callback_producer.try_admit_with_accounted_slack(
            class,
            payload_bytes,
            retained_slack,
        )?;
        work.begin_execution()?;
        Ok(work)
    }

    #[cfg(test)]
    fn open_inbound_realtime_flow(&self) -> Option<RealtimeFlowPort> {
        self.realtime_flows.open_inbound_flow()
    }

    fn observe_realtime_payload(&self, payload_bytes: usize) -> Option<ObservationLease> {
        self.resource_scope.as_ref().map(|scope| {
            let measurement = match u64::try_from(payload_bytes) {
                Ok(bytes) => {
                    ResourceMeasurement::inexact(ResourceUse::observed(1, bytes, bytes, 0))
                }
                Err(_) => ResourceMeasurement::inexact(ResourceUse::ZERO),
            };
            scope.observe_pre_authentication_measurement(
                PreAuthResourceFamily::MediaQuarantine,
                measurement,
            )
        })
    }

    fn emit_realtime(
        &self,
        flow: &RealtimeFlowPort,
        event: TransportEvent,
        reservation: RealtimeOutputReservation,
    ) -> bool {
        let Some(_operation) = self.operation_fence.try_enter() else {
            return true;
        };
        if !self.callback_gate.is_active() {
            return true;
        }
        let payload_bytes = match &event {
            // The route a real-time unit must take. Down here it is charged
            // against the real-time class, observed as media quarantine, and
            // gated by the operation fence above — all of which the general
            // callback route loses.
            //
            // What authorizes the unit is not checked here and deliberately
            // never was a flag: `flow` is a port on a flow the promoted session
            // opened, and a unit can only reach this call if a track attached to
            // a binding that session established. A connector with no promoted
            // session has no flow to pass, so there is nothing for a boolean to
            // add.
            TransportEvent::RealtimeUnit(delivery) => delivery.payload_bytes(),
            _ => return false,
        };
        let observation = self.observe_realtime_payload(payload_bytes);
        flow.enqueue(
            QueuedTransportEvent {
                event,
                observation,
                callback_work: None,
            },
            reservation,
        )
    }

    async fn emit_data_channel(&self, event: TransportEvent) -> bool {
        let endpoint_protocol = matches!(&event, TransportEvent::Message(_));
        let result = self.try_emit_data_channel(event).await;
        if endpoint_protocol
            && matches!(
                result,
                ConnectorCallbackInsertResult::Overloaded
                    | ConnectorCallbackInsertResult::PolicyRefused
                    | ConnectorCallbackInsertResult::ReceiverClosed
            )
        {
            self.retire_after_callback_violation();
        }
        result.accepted()
    }

    async fn try_emit_data_channel(&self, event: TransportEvent) -> ConnectorCallbackInsertResult {
        if matches!(event, TransportEvent::DataChannelClosed) {
            self.operation_fence.begin_close();
            self.realtime_flows.retire();
            return self
                .events
                .lifecycle
                .record_close(self.callback_gate.is_active());
        }
        self.emit_inner(event, true).await
    }

    async fn emit(&self, event: TransportEvent) -> bool {
        let candidate_obligation = matches!(&event, TransportEvent::LocalIceCandidate(_));
        let result = self.emit_inner(event, true).await;
        if candidate_obligation
            && matches!(
                result,
                ConnectorCallbackInsertResult::Overloaded
                    | ConnectorCallbackInsertResult::PolicyRefused
                    | ConnectorCallbackInsertResult::ReceiverClosed
            )
        {
            self.retire_after_callback_violation();
        }
        result.accepted()
    }

    fn retire_after_callback_violation(&self) {
        self.operation_fence.begin_close();
        self.realtime_flows.retire();
        self.events
            .lifecycle
            .record_close(self.callback_gate.is_active());
        if let Some(owner) = self.close_owner.as_ref().and_then(Weak::upgrade) {
            owner.start();
        }
    }

    fn structural_violation(&self, reason: &'static str) {
        if self
            .callback_violation_reported
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            warn!(
                reason,
                "retiring connector after native callback shape violation"
            );
            self.retire_after_callback_violation();
        }
    }

    async fn emit_inner(
        &self,
        event: TransportEvent,
        fence_operation: bool,
    ) -> ConnectorCallbackInsertResult {
        let _operation = if fence_operation {
            match self.operation_fence.try_enter() {
                Some(operation) => Some(operation),
                None => return ConnectorCallbackInsertResult::DiscardedAfterClose,
            }
        } else {
            None
        };
        let event = match event {
            TransportEvent::DataChannelOpen => {
                return self.events.lifecycle.record_open();
            }
            TransportEvent::DataChannelClosed => {
                return self
                    .events
                    .lifecycle
                    .record_close(self.callback_gate.is_active());
            }
            TransportEvent::RenegotiationNeeded => {
                let work = match self
                    .callback_producer
                    .try_admit(ConnectorCallbackClass::Control, 0)
                {
                    Ok(work) => work,
                    Err(_) => return ConnectorCallbackInsertResult::Overloaded,
                };
                return self.events.lifecycle.record_renegotiation(work);
            }
            TransportEvent::IceConnectionStateChanged(state) => {
                let work = match self
                    .callback_producer
                    .try_admit(ConnectorCallbackClass::Control, 0)
                {
                    Ok(work) => work,
                    Err(_) => return ConnectorCallbackInsertResult::Overloaded,
                };
                return self.events.lifecycle.record_ice_state(state, work);
            }
            TransportEvent::PeerConnectionStateChanged(state) => {
                let work = match self
                    .callback_producer
                    .try_admit(ConnectorCallbackClass::Control, 0)
                {
                    Ok(work) => work,
                    Err(_) => return ConnectorCallbackInsertResult::Overloaded,
                };
                return self.events.lifecycle.record_peer_state(state, work);
            }
            event => event,
        };
        // Refused here rather than at the mailbox lookup below, which would
        // reach the same answer only after admitting callback work and taking
        // an observation for it. A real-time unit on the general route is a
        // routing error in every state — it must enter through an exact
        // `RealtimeFlowPort`, because a connector-wide mailbox would let one
        // flow consume or reorder another flow's admitted queue — so nothing
        // should be charged on the way to saying so.
        if matches!(&event, TransportEvent::RealtimeUnit(_)) {
            return ConnectorCallbackInsertResult::WrongOwnerPath;
        }
        let callback_class = ConnectorCallbackClass::for_event(&event);
        let (payload_bytes, retained_slack) = match &event {
            TransportEvent::Message(bytes) => (bytes.len(), 0),
            // Same reasoning as the other admission site: charged here as well
            // as against its payload lease, because the two bound different
            // resources.
            TransportEvent::RealtimeUnit(delivery) => (delivery.payload_bytes(), 0),
            TransportEvent::LocalIceCandidate(candidate) => {
                let Some(sizes) = candidate_callback_sizes(candidate) else {
                    return ConnectorCallbackInsertResult::PolicyRefused;
                };
                sizes
            }
            _ => (0, 0),
        };
        let payload_limit = callback_payload_limit(self.callback_policy, callback_class);
        if let Some(limit) = payload_limit.filter(|limit| payload_bytes > *limit) {
            warn!(
                payload_bytes,
                limit,
                callback_class = ?callback_class,
                "dropping oversized connector callback payload"
            );
            return ConnectorCallbackInsertResult::PolicyRefused;
        }
        let callback_work = match self.callback_producer.try_admit_with_accounted_slack(
            callback_class,
            payload_bytes,
            retained_slack,
        ) {
            Ok(lease) => Some(lease),
            Err(error) => {
                warn!(
                    ?error,
                    ?callback_class,
                    "connector callback resource pressure"
                );
                return ConnectorCallbackInsertResult::Overloaded;
            }
        };
        let family = match &event {
            TransportEvent::Message(_) => PreAuthResourceFamily::FrameBytes,
            TransportEvent::RealtimeUnit(_) => PreAuthResourceFamily::MediaQuarantine,
            _ => PreAuthResourceFamily::ConnectorSpecificWork,
        };
        let observation = self.resource_scope.as_ref().map(|scope| {
            let measurement = payload_bytes
                .checked_add(retained_slack)
                .and_then(|retained| {
                    Some((
                        u64::try_from(payload_bytes).ok()?,
                        u64::try_from(retained).ok()?,
                    ))
                })
                .map_or_else(
                    || ResourceMeasurement::inexact(ResourceUse::ZERO),
                    |(logical, retained)| {
                        ResourceMeasurement::inexact(ResourceUse::observed(1, logical, retained, 0))
                    },
                );
            scope.observe_pre_authentication_measurement(family, measurement)
        });
        let queued = QueuedTransportEvent {
            event,
            observation,
            callback_work,
        };
        let Some(mailbox) = self.events.mailbox(callback_class) else {
            // Real-time units must enter through an exact RealtimeFlowPort.
            // A connector-wide compatibility mailbox would let one flow
            // consume or reorder another flow's admitted queue.
            return ConnectorCallbackInsertResult::WrongOwnerPath;
        };
        if fence_operation && self.operation_fence.is_closed() {
            return ConnectorCallbackInsertResult::DiscardedAfterClose;
        }
        if !self.callback_gate.is_active()
            || self.attempt_liveness.as_ref().is_some_and(|liveness| {
                !liveness.is_active() && !self.candidate_promoted.load(Ordering::Acquire)
            })
        {
            return ConnectorCallbackInsertResult::ReceiverClosed;
        }
        match mailbox.try_insert(queued) {
            Ok(()) => ConnectorCallbackInsertResult::Queued,
            Err(error) => match error.kind() {
                CallbackMailboxInsertErrorKind::Closed => {
                    ConnectorCallbackInsertResult::ReceiverClosed
                }
                CallbackMailboxInsertErrorKind::LocalItemCeiling => {
                    ConnectorCallbackInsertResult::Overloaded
                }
                CallbackMailboxInsertErrorKind::MissingLease
                | CallbackMailboxInsertErrorKind::WrongClass
                | CallbackMailboxInsertErrorKind::WrongPhase => {
                    ConnectorCallbackInsertResult::PolicyRefused
                }
            },
        }
    }
}

/// Receiver half owned by the connector callback pump.
pub(crate) struct WebRtcConnectorEventReceiver {
    ownership: ConnectorOwnership,
    retirement: watch::Receiver<bool>,
    attempt_retirement: Option<watch::Receiver<bool>>,
    raw: TransportEventReceiver,
    attempt_lifetime: Option<AttemptLifetime>,
    remote_candidates: Arc<SyncMutex<RemoteCandidateState>>,
    close_owner: Option<Arc<ConnectorCloseOwner>>,
    reclaim: Option<ResourceReclaimSubscription>,
    data_channel_open_committed: bool,
    data_channel_closed: bool,
    operation_fence: Arc<ConnectorOperationFence>,
}

/// Lab/test receiver for raw WebRTC behavior. Production wraps it in the
/// connector owner before any event can reach the engine.
pub struct TransportEventReceiver {
    control: Arc<ResourceBackedCallbackMailbox>,
    endpoint_data: Arc<ResourceBackedCallbackMailbox>,
    lifecycle: Arc<ConnectorLifecycleOwner>,
    lifecycle_closed: bool,
    callback_ready: Arc<tokio::sync::Notify>,
    callback_failed: bool,
    realtime_flows: Arc<RealtimeFlowRegistry>,
    scheduler: ConnectorCallbackScheduler,
    control_cursor: ConnectorControlSourceCursor,
}

impl TransportEventReceiver {
    fn begin_callback_execution(
        &mut self,
        mut event: QueuedTransportEvent,
    ) -> Option<QueuedTransportEvent> {
        if let Some(work) = event.callback_work.as_mut() {
            if let Err(error) = work.begin_execution() {
                warn!(
                    ?error,
                    "connector callback execution resource transition failed"
                );
                self.callback_failed = true;
                return None;
            }
        }
        Some(event)
    }

    fn try_scheduled_filtered(
        &mut self,
        allow_endpoint_data: bool,
    ) -> Option<QueuedTransportEvent> {
        if self.lifecycle_closed {
            return None;
        }
        for _ in 0..3 {
            let class = self.scheduler.current();
            if class == ConnectorCallbackClass::EndpointData && !allow_endpoint_data {
                self.scheduler.skip_current();
                continue;
            }
            let event = if class == ConnectorCallbackClass::Realtime {
                self.realtime_flows.try_recv()
            } else {
                match class {
                    ConnectorCallbackClass::Control => {
                        self.control_cursor.try_take(&self.lifecycle, &self.control)
                    }
                    ConnectorCallbackClass::EndpointData => self.endpoint_data.try_take(),
                    ConnectorCallbackClass::Realtime => unreachable!(),
                }
            };
            match event {
                Some(event) => {
                    if matches!(event.event, TransportEvent::DataChannelClosed) {
                        self.lifecycle_closed = true;
                    }
                    self.scheduler.delivered(class);
                    if let Some(event) = self.begin_callback_execution(event) {
                        return Some(event);
                    }
                    continue;
                }
                None => {
                    self.scheduler.skip_current();
                }
            }
        }
        None
    }

    fn try_terminal_close(&mut self) -> Option<QueuedTransportEvent> {
        if self.lifecycle_closed {
            return None;
        }
        let event = self.lifecycle.try_take_close_event()?;
        self.lifecycle_closed = true;
        self.begin_callback_execution(event)
    }

    #[cfg(any(test, feature = "transport-lab"))]
    fn try_scheduled(&mut self) -> Option<QueuedTransportEvent> {
        self.try_scheduled_filtered(true)
    }

    async fn recv_queued_filtered(
        &mut self,
        allow_endpoint_data: bool,
    ) -> Option<QueuedTransportEvent> {
        loop {
            if self.callback_failed {
                return None;
            }
            if let Some(event) = self.try_scheduled_filtered(allow_endpoint_data) {
                return Some(event);
            }
            if self.control.is_closed()
                && self.control.is_empty()
                && (!allow_endpoint_data
                    || (self.endpoint_data.is_closed() && self.endpoint_data.is_empty()))
                && self.realtime_flows.is_empty()
                && !self.lifecycle.has_pending()
            {
                return None;
            }
            tokio::select! {
                _ = self.lifecycle.notified() => {
                    continue;
                }
                _ = self.callback_ready.notified() => { continue; }
                _ = self.realtime_flows.ready.notified() => {
                    continue;
                }
            }
        }
    }

    #[cfg(any(test, feature = "transport-lab"))]
    async fn recv_queued(&mut self) -> Option<QueuedTransportEvent> {
        self.recv_queued_filtered(true).await
    }

    #[cfg(any(test, feature = "transport-lab"))]
    pub async fn recv(&mut self) -> Option<TransportEvent> {
        self.recv_queued().await.map(|queued| queued.event)
    }

    #[cfg(any(test, feature = "transport-lab"))]
    pub fn try_recv(&mut self) -> std::result::Result<TransportEvent, mpsc::error::TryRecvError> {
        if let Some(queued) = self.try_scheduled() {
            return Ok(queued.event);
        }
        if self.control.is_closed()
            && self.endpoint_data.is_closed()
            && self.realtime_flows.is_empty()
            && !self.lifecycle.has_pending()
        {
            Err(mpsc::error::TryRecvError::Disconnected)
        } else {
            Err(mpsc::error::TryRecvError::Empty)
        }
    }
}

impl Drop for TransportEventReceiver {
    fn drop(&mut self) {
        self.control.close();
        self.endpoint_data.close();
    }
}

impl WebRtcConnectorEventReceiver {
    fn expose_queued(&mut self, queued: QueuedTransportEvent) -> Option<WebRtcConnectorEvent> {
        let terminal_close = matches!(&queued.event, TransportEvent::DataChannelClosed);
        if self.operation_fence.is_closed() && !terminal_close {
            return None;
        }
        let incarnation_active = self.ownership.incarnation.is_active();
        if terminal_close && !incarnation_active && !self.raw.lifecycle.close_survives_retirement()
        {
            self.data_channel_closed = true;
            return None;
        }
        if !terminal_close && !incarnation_active {
            return None;
        }
        if terminal_close {
            self.data_channel_closed = true;
        }
        Some(WebRtcConnectorEvent {
            incarnation: Arc::clone(&self.ownership.incarnation),
            event: queued.event,
            _queue_observation: queued.observation,
            _callback_work: queued.callback_work,
        })
    }

    fn expose_recorded_close(&mut self) -> Option<WebRtcConnectorEvent> {
        let queued = self.raw.try_terminal_close()?;
        self.expose_queued(queued)
    }

    pub(crate) async fn recv(&mut self) -> Option<WebRtcConnectorEvent> {
        loop {
            if self.data_channel_closed {
                return None;
            }
            if let Some(close) = self.expose_recorded_close() {
                return Some(close);
            }
            if *self.retirement.borrow() {
                return None;
            }
            if self
                .attempt_retirement
                .as_ref()
                .is_some_and(|retirement| *retirement.borrow())
                && self.reclaim_retired_attempt_candidate()
            {
                return None;
            }
            if self
                .reclaim
                .as_ref()
                .is_some_and(ResourceReclaimSubscription::is_requested)
            {
                if let Some(close_owner) = self.close_owner.as_ref() {
                    close_owner.start();
                }
                return None;
            }
            let queued = tokio::select! {
                biased;
                _ = self.retirement.changed() => {
                    if let Some(close) = self.expose_recorded_close() {
                        return Some(close);
                    }
                    return None;
                },
                _ = wait_for_optional_reclaim(self.reclaim.as_ref()) => {
                    if let Some(close_owner) = self.close_owner.as_ref() {
                        close_owner.start();
                    }
                    return None;
                },
                _ = wait_for_optional_retirement(&mut self.attempt_retirement) => {
                    if self.reclaim_retired_attempt_candidate() {
                        return None;
                    }
                    continue;
                }
                queued = self.raw.recv_queued_filtered(self.data_channel_open_committed) => queued,
            };
            if let Some(queued) = queued {
                if let Some(event) = self.expose_queued(queued) {
                    return Some(event);
                }
                continue;
            }
            return None;
        }
    }

    /// Release bounded endpoint-protocol callbacks only after the engine has
    /// committed the exact connector's working-channel ownership transition.
    /// Delivering the control event is insufficient because its owner may be
    /// stale or may reject the transition.
    pub(crate) fn commit_data_channel_open(&mut self) {
        if self.raw.lifecycle.commit_open() {
            self.data_channel_open_committed = true;
        }
    }

    fn reclaim_retired_attempt_candidate(&mut self) -> bool {
        self.attempt_retirement = None;
        if !self.ownership.retire_if_unconnected() {
            return false;
        }
        drain_remote_candidates(&self.remote_candidates);
        if let Some(close_owner) = self.close_owner.as_ref() {
            close_owner.start();
        } else {
            self.ownership.complete_cleanup();
        }
        true
    }

    #[cfg(test)]
    fn retire_attempt_for_test(&self) {
        self.attempt_lifetime
            .as_ref()
            .expect("test receiver owns its attempt")
            .retire();
    }
}

impl Drop for WebRtcConnectorEventReceiver {
    fn drop(&mut self) {
        if let Some(lifetime) = self.attempt_lifetime.take() {
            lifetime.retire();
        }
        self.ownership.retire();
        drain_remote_candidates(&self.remote_candidates);
        if let Some(close_owner) = self.close_owner.as_ref() {
            close_owner.start();
        } else {
            self.ownership.complete_cleanup();
        }
    }
}

async fn wait_for_optional_retirement(retirement: &mut Option<watch::Receiver<bool>>) {
    match retirement {
        Some(retirement) => {
            let _ = retirement.changed().await;
        }
        None => std::future::pending::<()>().await,
    }
}

async fn wait_for_optional_reclaim(reclaim: Option<&ResourceReclaimSubscription>) {
    match reclaim {
        Some(reclaim) => reclaim.requested().await,
        None => std::future::pending::<()>().await,
    }
}

fn drain_remote_candidates(remote_candidates: &SyncMutex<RemoteCandidateState>) {
    let mut state = remote_candidates.lock();
    state.current.retire();
    if let Some(provisional) = state.provisional.as_mut() {
        provisional.envelope.retire();
    }
}

/// Result of applying an inbound candidate through the connector owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteCandidateDisposition {
    Applied,
    QueuedUntilRemoteDescription,
    DuplicateIgnored,
    InvalidBinding(CandidateUsernameFragmentError),
    RefusedByOwner,
    AttemptRetired,
}

pub(crate) struct RemoteCandidateAdmissionReport {
    pub(crate) disposition: RemoteCandidateDisposition,
    pub(crate) kind: Option<super::diag::IceCandidateKind>,
}

/// Outcome of the data-channel-open ownership transition.
#[allow(
    clippy::large_enum_variant,
    reason = "boxing the move-only capability would add an unaccounted allocation"
)]
pub(crate) enum DataChannelOpenOwnership {
    /// Exact admitted candidate produced a capability for Endpoint Auth Task.
    Connected(EndpointAuthHandoff),
    /// The exact worker has already handed its one capability onward.
    AlreadyConnected,
    /// Worker, attempt, or candidate was no longer live.
    Rejected,
}

#[allow(
    clippy::large_enum_variant,
    reason = "boxing the move-only cleanup claim would add an unaccounted allocation"
)]
enum DataChannelOpenTransition {
    Connected(crate::connector::ConnectedChannelCapability),
    AlreadyConnected,
    Rejected,
}

/// Candidate failures observed while a newly applied remote description drains
/// the connector-owned pre-SDP queue.
pub(crate) struct RemoteDescriptionApplyReport {
    pub(crate) queued_candidate_count: usize,
    pub(crate) candidate_failure_count: usize,
}

/// One remote candidate paired with the observation that follows its owner.
/// Moving this value moves the observation. Dropping it ends the observation.
#[derive(Debug)]
struct PendingRemoteCandidate {
    candidate: LocalIceCandidate,
    attempt: Arc<RemoteCandidateAttemptIdentity>,
    observation: CandidateObservationLease,
    _queue_reservation: Option<PendingRemoteCandidateReservation>,
    _elastic_lease: Option<ElasticRemoteCandidateLease>,
    _production_queue_lease: Option<crate::resource::ResourceLease>,
}

impl PendingRemoteCandidate {
    fn observe(
        candidate: LocalIceCandidate,
        attempt: Arc<RemoteCandidateAttemptIdentity>,
        resource_scope: &PeerConnectionResourceScope,
    ) -> Self {
        let observation = CandidateObservationLease {
            _observation: resource_scope.observe_pre_authentication_measurement(
                PreAuthResourceFamily::CandidateObject,
                candidate_resource_measurement(&candidate),
            ),
        };
        Self {
            candidate,
            attempt,
            observation,
            _queue_reservation: None,
            _elastic_lease: None,
            _production_queue_lease: None,
        }
    }

    fn retained(
        candidate: LocalIceCandidate,
        attempt: Arc<RemoteCandidateAttemptIdentity>,
        resource_scope: &PeerConnectionResourceScope,
        queue_reservation: PendingRemoteCandidateReservation,
        elastic_lease: ElasticRemoteCandidateLease,
        production_queue_lease: crate::resource::ResourceLease,
    ) -> Self {
        let mut pending = Self::observe(candidate, attempt, resource_scope);
        pending._queue_reservation = Some(queue_reservation);
        pending._elastic_lease = Some(elastic_lease);
        pending._production_queue_lease = Some(production_queue_lease);
        pending
    }
}

/// Apply an observed candidate while retaining its lease across the await.
/// Cancellation drops both the future and its observation.
#[cfg(test)]
async fn apply_pending_remote_candidate<F, Fut, T>(pending: PendingRemoteCandidate, apply: F) -> T
where
    F: FnOnce(LocalIceCandidate) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let PendingRemoteCandidate {
        candidate,
        attempt: _,
        observation,
        _queue_reservation,
        _elastic_lease,
        _production_queue_lease,
    } = pending;
    let _elastic_application = _elastic_lease.and_then(|lease| lease.begin_apply().ok());
    let result = apply(candidate).await;
    drop(observation);
    drop(_queue_reservation);
    result
}

#[derive(Debug)]
struct CandidateObservationLease {
    _observation: ObservationLease,
}

#[derive(Debug)]
struct PendingRemoteCandidateQueue {
    entries: std::collections::LinkedList<PendingRemoteCandidate>,
    container_observation: Option<ObservationLease>,
    budget: Arc<PendingRemoteCandidateBudget>,
}

impl PendingRemoteCandidateQueue {
    fn new(policy: PendingRemoteCandidatePolicy) -> Self {
        Self {
            entries: std::collections::LinkedList::new(),
            container_observation: None,
            budget: Arc::new(PendingRemoteCandidateBudget::new(policy)),
        }
    }

    fn push(
        &mut self,
        candidate: LocalIceCandidate,
        attempt: Arc<RemoteCandidateAttemptIdentity>,
        resource_scope: &PeerConnectionResourceScope,
        work_resources: &ConnectorWorkResourceScope,
        reservation: PendingRemoteCandidateReservation,
        elastic_lease: ElasticRemoteCandidateLease,
    ) -> PendingRemoteCandidateQueuePush {
        let production_queue_claim = match pending_remote_candidate_queue_claim(&candidate) {
            Ok(claim) => claim,
            Err(error) => {
                warn!(?error, "remote-candidate queue ownership claim overflowed");
                return PendingRemoteCandidateQueuePush::ResourceUnavailable(
                    ResourceUnavailable::ProviderInvariant {
                        dimension: match error {
                            crate::resource::ResourceClaimArithmeticError::Overflow {
                                dimension,
                            }
                            | crate::resource::ResourceClaimArithmeticError::Underflow {
                                dimension,
                            } => dimension,
                        },
                    },
                );
            }
        };
        let production_queue_lease = match work_resources.acquire(
            crate::resource::ResourceAuthorityClass::Speculative,
            production_queue_claim,
        ) {
            Ok(lease) => lease,
            Err(error) => {
                warn!(?error, "remote-candidate queue wrapper was refused");
                return PendingRemoteCandidateQueuePush::ResourceUnavailable(error);
            }
        };
        self.entries.push_back(PendingRemoteCandidate::retained(
            candidate,
            attempt,
            resource_scope,
            reservation,
            elastic_lease,
            production_queue_lease,
        ));
        let measurement = queue_container_resource_measurement(&self.entries);
        match self.container_observation.as_mut() {
            Some(observation) => observation.replace_measurement(measurement),
            None => {
                self.container_observation =
                    Some(resource_scope.observe_pre_authentication_measurement(
                        PreAuthResourceFamily::CandidateObject,
                        measurement,
                    ));
            }
        }
        PendingRemoteCandidateQueuePush::Queued
    }

    #[cfg(test)]
    fn push_observed_for_test(
        &mut self,
        candidate: LocalIceCandidate,
        attempt: Arc<RemoteCandidateAttemptIdentity>,
        resource_scope: &PeerConnectionResourceScope,
    ) -> PendingRemoteCandidateQueuePush {
        let Some(content_bytes) = candidate_content_bytes(&candidate) else {
            self.budget.poison();
            return PendingRemoteCandidateQueuePush::Refused;
        };
        let Some(reservation) = self.budget.reserve(content_bytes) else {
            return PendingRemoteCandidateQueuePush::Refused;
        };
        let mut pending = PendingRemoteCandidate::observe(candidate, attempt, resource_scope);
        pending._queue_reservation = Some(reservation);
        self.entries.push_back(pending);
        let measurement = queue_container_resource_measurement(&self.entries);
        match self.container_observation.as_mut() {
            Some(observation) => observation.replace_measurement(measurement),
            None => {
                self.container_observation =
                    Some(resource_scope.observe_pre_authentication_measurement(
                        PreAuthResourceFamily::CandidateObject,
                        measurement,
                    ));
            }
        }
        PendingRemoteCandidateQueuePush::Queued
    }

    fn take(&mut self) -> PendingRemoteCandidateDrain {
        let entries = std::mem::take(&mut self.entries);
        let container_observation = self.container_observation.take();
        PendingRemoteCandidateDrain {
            entries: entries.into_iter(),
            _container_observation: container_observation,
        }
    }

    fn retain_candidates(&mut self, mut keep: impl FnMut(&PendingRemoteCandidate) -> bool) {
        let mut retained = std::collections::LinkedList::new();
        while let Some(pending) = self.entries.pop_front() {
            if keep(&pending) {
                retained.push_back(pending);
            }
        }
        self.entries = retained;
        if self.entries.is_empty() {
            self.container_observation = None;
        } else if let Some(observation) = self.container_observation.as_mut() {
            observation.replace_measurement(queue_container_resource_measurement(&self.entries));
        }
    }

    fn retain_matching_remote_credentials(&mut self, credentials: &RemoteIceCredentials) {
        self.retain_candidates(|pending| {
            candidate_matches_remote_credentials(&pending.candidate, credentials)
        });
    }

    fn retain_remote_restart_migratable_candidates(&mut self, credentials: &RemoteIceCredentials) {
        self.retain_candidates(|pending| {
            matches!(candidate_username_fragment(&pending.candidate), Ok(Some(_)))
                && candidate_matches_remote_credentials(&pending.candidate, credentials)
        });
    }

    fn pop_last_for_application(
        &mut self,
        resource_scope: &PeerConnectionResourceScope,
    ) -> Option<PendingRemoteCandidate> {
        let pending = self.entries.pop_back()?;
        if self.entries.is_empty() {
            self.container_observation = None;
        } else if let Some(observation) = self.container_observation.as_mut() {
            observation.replace_measurement(queue_container_resource_measurement(&self.entries));
        } else {
            self.container_observation =
                Some(resource_scope.observe_pre_authentication_measurement(
                    PreAuthResourceFamily::CandidateObject,
                    queue_container_resource_measurement(&self.entries),
                ));
        }
        Some(pending)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingRemoteCandidateQueuePush {
    Queued,
    Duplicate,
    InvalidBinding(CandidateUsernameFragmentError),
    ResourceUnavailable(ResourceUnavailable),
    Refused,
    Retired,
}

#[derive(Debug)]
struct PendingRemoteCandidateBudgetState {
    items: usize,
    content_bytes: usize,
    duplicate_submissions: usize,
    application_work: usize,
    accounting_poisoned: bool,
}

#[derive(Debug)]
struct PendingRemoteCandidateBudget {
    policy: PendingRemoteCandidatePolicy,
    state: SyncMutex<PendingRemoteCandidateBudgetState>,
}

impl PendingRemoteCandidateBudget {
    fn new(policy: PendingRemoteCandidatePolicy) -> Self {
        Self {
            policy,
            state: SyncMutex::new(PendingRemoteCandidateBudgetState {
                items: 0,
                content_bytes: 0,
                duplicate_submissions: 0,
                application_work: 0,
                accounting_poisoned: false,
            }),
        }
    }

    fn reserve(
        self: &Arc<Self>,
        content_bytes: usize,
    ) -> Option<PendingRemoteCandidateReservation> {
        let Some(local) = self.policy.local_ceiling() else {
            return Some(PendingRemoteCandidateReservation {
                budget: Arc::clone(self),
                application: None,
            });
        };
        let mut state = self.state.lock();
        if state.accounting_poisoned {
            return None;
        }
        let Some(remaining_content) = local
            .max_content_bytes()
            .get()
            .checked_sub(state.content_bytes)
        else {
            state.accounting_poisoned = true;
            return None;
        };
        if state.items >= local.max_unique_items().get() || content_bytes > remaining_content {
            return None;
        }
        let items = state.items + 1;
        let Some(bytes) = state.content_bytes.checked_add(content_bytes) else {
            state.accounting_poisoned = true;
            return None;
        };
        state.items = items;
        state.content_bytes = bytes;
        Some(PendingRemoteCandidateReservation {
            budget: Arc::clone(self),
            application: None,
        })
    }

    fn poison(&self) {
        self.state.lock().accounting_poisoned = true;
    }

    fn record_duplicate(&self) -> bool {
        let Some(local) = self.policy.local_ceiling() else {
            return true;
        };
        let mut state = self.state.lock();
        if state.accounting_poisoned {
            return false;
        }
        if state.duplicate_submissions >= local.max_duplicate_submissions().get() {
            return false;
        }
        let duplicates = state.duplicate_submissions + 1;
        state.duplicate_submissions = duplicates;
        true
    }

    fn reserve_application_work(&self) -> bool {
        let Some(local) = self.policy.local_ceiling() else {
            return true;
        };
        let mut state = self.state.lock();
        if state.accounting_poisoned {
            return false;
        }
        if state.application_work >= local.max_application_work().get() {
            return false;
        }
        let work = state.application_work + 1;
        state.application_work = work;
        true
    }

    #[cfg(test)]
    fn report(&self) -> (usize, usize, usize, usize, bool) {
        let state = self.state.lock();
        (
            state.items,
            state.content_bytes,
            state.duplicate_submissions,
            state.application_work,
            state.accounting_poisoned,
        )
    }
}

#[derive(Debug)]
struct PendingRemoteCandidateReservation {
    budget: Arc<PendingRemoteCandidateBudget>,
    application: Option<crate::runtime::attempt::ApplyingRemoteCandidate>,
}

/// Exact Rust-owned production queue contribution for one candidate.
///
/// The connector-neutral elastic lease owns its digest state. This separate
/// lease moves with the `LocalIceCandidate` and owns the production wrapper,
/// exact retained String capacities, logical queued content bytes, the second
/// digest key, and the two allocator domains used by LinkedList and BTreeSet.
/// Allocator metadata remains an explicit opaque residual.
fn pending_remote_candidate_queue_claim(
    candidate: &LocalIceCandidate,
) -> std::result::Result<
    crate::resource::ResourceClaim,
    crate::resource::ResourceClaimArithmeticError,
> {
    let string_capacity = candidate
        .candidate
        .capacity()
        .checked_add(candidate.sdp_mid.as_ref().map_or(0, String::capacity))
        .and_then(|bytes| {
            let username = candidate
                .username_fragment
                .as_ref()
                .map_or(0, String::capacity);
            bytes.checked_add(username)
        })
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        })?;
    let string_capacity = u64::try_from(string_capacity).map_err(|_| {
        crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        }
    })?;
    let content_bytes = candidate_content_bytes(candidate)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::QueuedBytes,
        })?;
    pending_remote_candidate_queue_claim_with_content(string_capacity, content_bytes)
}

fn pending_remote_candidate_queue_claim_with_content(
    string_capacity: u64,
    content_bytes: u64,
) -> std::result::Result<
    crate::resource::ResourceClaim,
    crate::resource::ResourceClaimArithmeticError,
> {
    let accounted_bytes = std::mem::size_of::<PendingRemoteCandidate>()
        .checked_add(std::mem::size_of::<[u8; 32]>())
        .and_then(|bytes| u64::try_from(bytes).ok())
        .and_then(|bytes| bytes.checked_add(string_capacity))
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        })?;
    crate::resource::ResourceClaim::try_from_entries([
        (
            crate::resource::ResourceClass::AccountedMemoryBytes,
            accounted_bytes,
        ),
        (crate::resource::ResourceClass::QueuedBytes, content_bytes),
        (crate::resource::ResourceClass::StorageObject, 2),
        (crate::resource::ResourceClass::OpaqueDependencyResidual, 2),
    ])
}

fn candidate_content_bytes(candidate: &LocalIceCandidate) -> Option<usize> {
    let strings = candidate
        .candidate
        .len()
        .checked_add(candidate.sdp_mid.as_ref().map_or(0, String::len))?
        .checked_add(candidate.username_fragment.as_ref().map_or(0, String::len))?;
    strings.checked_add(
        candidate
            .sdp_mline_index
            .map_or(0, |_| std::mem::size_of::<u16>()),
    )
}

fn candidate_callback_sizes(candidate: &Option<LocalIceCandidate>) -> Option<(usize, usize)> {
    let Some(candidate) = candidate.as_ref() else {
        return Some((0, 0));
    };
    let content = candidate_content_bytes(candidate)?;
    let slack = candidate
        .candidate
        .capacity()
        .checked_sub(candidate.candidate.len())?
        .checked_add(
            candidate
                .sdp_mid
                .as_ref()
                .map_or(0, |value| value.capacity().saturating_sub(value.len())),
        )?
        .checked_add(
            candidate
                .username_fragment
                .as_ref()
                .map_or(0, |value| value.capacity().saturating_sub(value.len())),
        )?;
    Some((content, slack))
}

#[derive(Debug)]
struct PendingRemoteCandidateDrain {
    entries: std::collections::linked_list::IntoIter<PendingRemoteCandidate>,
    _container_observation: Option<ObservationLease>,
}

impl Default for PendingRemoteCandidateDrain {
    fn default() -> Self {
        Self {
            entries: std::collections::LinkedList::new().into_iter(),
            _container_observation: None,
        }
    }
}

impl PendingRemoteCandidateDrain {
    fn len(&self) -> usize {
        self.entries.len()
    }
}

impl Iterator for PendingRemoteCandidateDrain {
    type Item = PendingRemoteCandidate;

    fn next(&mut self) -> Option<Self::Item> {
        self.entries.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.entries.size_hint()
    }
}

impl ExactSizeIterator for PendingRemoteCandidateDrain {}

struct RemoteCandidateAttemptEnvelope {
    attempt: Arc<RemoteCandidateAttemptIdentity>,
    elastic_attempt: ElasticRemoteCandidateAttempt,
    work_resources: ConnectorWorkResourceScope,
    remote_description_set: bool,
    pending: PendingRemoteCandidateQueue,
    seen: std::collections::BTreeSet<[u8; 32]>,
    retained_reservations: std::collections::LinkedList<PendingRemoteCandidateReservation>,
    remote_ice_credentials: Option<RemoteIceCredentials>,
    remote_description_in_flight: bool,
    /// A provisional replacement owns a second root claim until commit drops
    /// the retiring root. The connector floor then resumes ownership of the
    /// one current root.
    provisional_root_lease: Option<crate::resource::ResourceLease>,
}

impl RemoteCandidateAttemptEnvelope {
    fn new(
        policy: PendingRemoteCandidatePolicy,
        work_resources: ConnectorWorkResourceScope,
    ) -> Self {
        let elastic_attempt = ElasticRemoteCandidateAttempt::new(
            work_resources.clone(),
            elastic_remote_candidate_ceilings(policy),
        );
        Self {
            attempt: Arc::new(RemoteCandidateAttemptIdentity::default()),
            elastic_attempt,
            work_resources,
            remote_description_set: false,
            pending: PendingRemoteCandidateQueue::new(policy),
            seen: std::collections::BTreeSet::new(),
            retained_reservations: std::collections::LinkedList::new(),
            remote_ice_credentials: None,
            remote_description_in_flight: false,
            provisional_root_lease: None,
        }
    }

    fn new_provisional(
        policy: PendingRemoteCandidatePolicy,
        work_resources: ConnectorWorkResourceScope,
    ) -> Result<Self> {
        let root_lease = work_resources
            .acquire(
                crate::resource::ResourceAuthorityClass::Speculative,
                crate::runtime::attempt::remote_candidate_attempt_root_claim().map_err(
                    |error| {
                        Error::Transport(format!(
                            "replacement candidate-attempt root claim overflowed: {error}"
                        ))
                    },
                )?,
            )
            .map_err(Error::from)?;
        let mut replacement = Self::new(policy, work_resources);
        replacement.provisional_root_lease = Some(root_lease);
        Ok(replacement)
    }

    #[cfg(test)]
    fn admit(
        &mut self,
        candidate: LocalIceCandidate,
        resource_scope: &PeerConnectionResourceScope,
    ) -> PendingRemoteCandidateQueuePush {
        self.admit_observed(candidate, resource_scope).0
    }

    fn admit_observed(
        &mut self,
        candidate: LocalIceCandidate,
        resource_scope: &PeerConnectionResourceScope,
    ) -> (
        PendingRemoteCandidateQueuePush,
        Option<super::diag::IceCandidateKind>,
    ) {
        if !self.attempt.is_active() {
            return (PendingRemoteCandidateQueuePush::Retired, None);
        }
        let elastic_input = ElasticRemoteCandidateInput {
            candidate: candidate.candidate.as_bytes(),
            sdp_mid: candidate.sdp_mid.as_deref().map(str::as_bytes),
            sdp_mline_index: candidate.sdp_mline_index,
            username_fragment: candidate.username_fragment.as_deref().map(str::as_bytes),
        };
        let Some(content_bytes) = candidate_content_bytes(&candidate) else {
            self.pending.budget.poison();
            self.retire();
            return (PendingRemoteCandidateQueuePush::Refused, None);
        };
        let mut kind = None;
        let mut binding = None;
        let mut local_reservation = None;
        let seen = &self.seen;
        let duplicate_budget = Arc::clone(&self.pending.budget);
        let unique_budget = Arc::clone(&self.pending.budget);
        let admitted = self.elastic_attempt.admit_with_digest_decision(
            elastic_input,
            || {
                kind = Some(super::ice::classify_candidate_sdp(&candidate.candidate));
                let parsed = candidate_username_fragment(&candidate);
                let valid = parsed.is_ok();
                binding = Some(parsed);
                valid
            },
            |digest| {
                if seen.contains(&digest) {
                    if duplicate_budget.record_duplicate() {
                        ElasticRemoteCandidateDigestDecision::Duplicate
                    } else {
                        ElasticRemoteCandidateDigestDecision::Refuse
                    }
                } else if let Some(reservation) = unique_budget.reserve(content_bytes) {
                    local_reservation = Some(reservation);
                    ElasticRemoteCandidateDigestDecision::Retain
                } else {
                    ElasticRemoteCandidateDigestDecision::Refuse
                }
            },
        );
        if let Some(Err(error)) = binding {
            self.retire();
            return (PendingRemoteCandidateQueuePush::InvalidBinding(error), kind);
        }
        let elastic_lease = match admitted {
            Ok(ElasticRemoteCandidateAdmission::Retained(lease)) => lease,
            Ok(ElasticRemoteCandidateAdmission::Duplicate) => {
                return (PendingRemoteCandidateQueuePush::Duplicate, kind);
            }
            Err(ElasticRemoteCandidateAdmissionError::Provider(error))
            | Err(ElasticRemoteCandidateAdmissionError::Terminal(
                ElasticRemoteCandidateTerminalReason::Provider(error),
            )) => {
                warn!(?error, "remote-candidate provider retired the ICE attempt");
                self.retire();
                return (
                    PendingRemoteCandidateQueuePush::ResourceUnavailable(error),
                    kind,
                );
            }
            Err(ElasticRemoteCandidateAdmissionError::Terminal(
                ElasticRemoteCandidateTerminalReason::AccountingInexact,
            )) => {
                self.retire();
                return (
                    PendingRemoteCandidateQueuePush::ResourceUnavailable(
                        ResourceUnavailable::ProviderInvariant {
                            dimension: crate::resource::ResourceClass::OpaqueDependencyResidual,
                        },
                    ),
                    kind,
                );
            }
            Err(ElasticRemoteCandidateAdmissionError::Terminal(
                ElasticRemoteCandidateTerminalReason::Retired,
            )) => {
                self.retire();
                return (PendingRemoteCandidateQueuePush::Retired, kind);
            }
            Err(error) => {
                warn!(
                    ?error,
                    "remote-candidate local wrapper retired the ICE attempt"
                );
                self.retire();
                return (PendingRemoteCandidateQueuePush::Refused, kind);
            }
        };
        let kind = kind.expect("successful candidate validation records its classification");
        let Some(digest) = elastic_lease.digest() else {
            self.retire();
            return (
                PendingRemoteCandidateQueuePush::ResourceUnavailable(
                    ResourceUnavailable::ProviderInvariant {
                        dimension: crate::resource::ResourceClass::StorageObject,
                    },
                ),
                Some(kind),
            );
        };
        let result = self.pending.push(
            candidate,
            Arc::clone(&self.attempt),
            resource_scope,
            &self.work_resources,
            local_reservation
                .take()
                .expect("retained candidate owns its pre-retention local reservation"),
            elastic_lease,
        );
        if result == PendingRemoteCandidateQueuePush::Queued {
            self.seen.insert(digest);
        } else if matches!(
            result,
            PendingRemoteCandidateQueuePush::Refused
                | PendingRemoteCandidateQueuePush::ResourceUnavailable(_)
        ) {
            self.retire();
        }
        (result, Some(kind))
    }

    fn retire(&mut self) {
        self.attempt.retire();
        self.elastic_attempt.retire();
        self.pending.entries.clear();
        self.pending.container_observation = None;
        self.seen.clear();
        self.retained_reservations.clear();
    }

    fn owns_attempt(&self, attempt: &Arc<RemoteCandidateAttemptIdentity>) -> bool {
        Arc::ptr_eq(&self.attempt, attempt) && attempt.is_active()
    }

    fn last_candidate_matches_remote_credentials(&self) -> bool {
        let Some(credentials) = self.remote_ice_credentials.as_ref() else {
            return true;
        };
        self.pending.entries.back().is_none_or(|pending| {
            candidate_matches_remote_credentials(&pending.candidate, credentials)
        })
    }

    fn adopt_queued_candidates_for_remote_restart(
        &mut self,
        source: &mut Self,
        credentials: &RemoteIceCredentials,
    ) -> bool {
        self.pending.entries = std::mem::take(&mut source.pending.entries);
        self.pending.container_observation = source.pending.container_observation.take();
        // The retiring set no longer owns any queued candidate after the list
        // moves. Release those digest nodes before the replacement set is
        // populated so migration never retains two uncharged copies.
        source.seen.clear();
        self.pending
            .retain_remote_restart_migratable_candidates(credentials);

        for pending in &mut self.pending.entries {
            let Some(content_bytes) = candidate_content_bytes(&pending.candidate) else {
                self.retire();
                self.pending.budget.poison();
                return false;
            };
            let Some(reservation) = self.pending.budget.reserve(content_bytes) else {
                self.retire();
                return false;
            };
            let input = ElasticRemoteCandidateInput {
                candidate: pending.candidate.candidate.as_bytes(),
                sdp_mid: pending.candidate.sdp_mid.as_deref().map(str::as_bytes),
                sdp_mline_index: pending.candidate.sdp_mline_index,
                username_fragment: pending
                    .candidate
                    .username_fragment
                    .as_deref()
                    .map(str::as_bytes),
            };
            let elastic_lease = match self.elastic_attempt.admit(input) {
                Ok(lease) => lease,
                Err(error) => {
                    warn!(
                        ?error,
                        "replacement ICE attempt refused migrated candidate work"
                    );
                    self.retire();
                    return false;
                }
            };
            let Some(digest) = elastic_lease.digest() else {
                self.retire();
                return false;
            };
            pending.attempt = Arc::clone(&self.attempt);
            pending._queue_reservation = Some(reservation);
            pending._elastic_lease = Some(elastic_lease);
            self.seen.insert(digest);
        }
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IceRestartDirection {
    Local,
    Remote,
}

struct ProvisionalRemoteCandidateAttempt {
    direction: IceRestartDirection,
    envelope: RemoteCandidateAttemptEnvelope,
}

fn elastic_remote_candidate_ceilings(
    policy: PendingRemoteCandidatePolicy,
) -> RemoteCandidateLocalCeilings {
    let Some(policy) = policy.local_ceiling() else {
        return RemoteCandidateLocalCeilings::none();
    };
    let unique = u64::try_from(policy.max_unique_items().get())
        .expect("usize candidate item ceiling fits u64 on supported platforms");
    let duplicates = u64::try_from(policy.max_duplicate_submissions().get())
        .expect("usize duplicate ceiling fits u64 on supported platforms");
    // The two optional wrappers remain independently enforced below the
    // primitive. If their sum cannot be represented, omit the redundant
    // aggregate ceiling instead of panicking or inventing a smaller bound.
    let submissions = unique
        .checked_add(duplicates)
        .and_then(std::num::NonZeroU64::new);
    let content = std::num::NonZeroU64::new(
        u64::try_from(policy.max_content_bytes().get())
            .expect("usize candidate content ceiling fits u64 on supported platforms"),
    )
    .expect("candidate content ceiling is nonzero");
    let applications = std::num::NonZeroU64::new(
        u64::try_from(policy.max_application_work().get())
            .expect("usize candidate application ceiling fits u64 on supported platforms"),
    )
    .expect("candidate application ceiling is nonzero");
    RemoteCandidateLocalCeilings::new(
        submissions.map(MaxCumulativeRemoteCandidateSubmissions::new),
        Some(MaxCumulativeRemoteCandidateContentBytes::new(content)),
        Some(MaxCumulativeRemoteCandidateApplications::new(applications)),
    )
}

#[cfg(test)]
fn elastic_remote_candidate_test_scope(
    policy: PendingRemoteCandidatePolicy,
) -> ConnectorWorkResourceScope {
    elastic_remote_candidate_test_scope_with_additional(
        policy,
        crate::resource::ResourceClaim::ZERO,
    )
}

#[cfg(test)]
fn elastic_remote_candidate_test_scope_with_restart_overlap(
    policy: PendingRemoteCandidatePolicy,
) -> ConnectorWorkResourceScope {
    let local = policy
        .local_ceiling()
        .expect("raw candidate-state tests declare an explicit local fixture ceiling");
    let unique =
        u64::try_from(local.max_unique_items().get()).expect("fixture candidate count fits u64");
    let reservation_records = unique
        .checked_add(1)
        .expect("fixture restart reservation records fit");
    let overlap = crate::runtime::attempt::remote_candidate_attempt_root_claim()
        .and_then(|claim| {
            claim.checked_add(
                crate::runtime::attempt::remote_candidate_digest_retention_aggregate_claim(unique)?,
            )
        })
        .and_then(|claim| {
            claim.checked_add(crate::resource::ResourceClaim::single(
                crate::resource::ResourceClass::OpaqueDependencyResidual,
                reservation_records,
            ))
        })
        .expect("fixture restart overlap claim is representable");
    elastic_remote_candidate_test_scope_with_additional(policy, overlap)
}

#[cfg(test)]
fn elastic_remote_candidate_test_scope_with_additional(
    policy: PendingRemoteCandidatePolicy,
    additional: crate::resource::ResourceClaim,
) -> ConnectorWorkResourceScope {
    let (_provider, _owner, _candidate, _lifetime, work_scope) =
        elastic_remote_candidate_test_resources_with_additional(policy, additional);
    work_scope
}

#[cfg(test)]
fn elastic_remote_candidate_test_resources_with_additional(
    policy: PendingRemoteCandidatePolicy,
    additional: crate::resource::ResourceClaim,
) -> (
    crate::resource::FiniteResourceProvider,
    crate::runtime::attempt::ConnectorResourceOwnerPort,
    crate::runtime::attempt::ConnectorCandidateCapability,
    AttemptLifetime,
    ConnectorWorkResourceScope,
) {
    let policy = policy
        .local_ceiling()
        .expect("raw candidate-state tests declare an explicit local fixture ceiling");
    let unique =
        u64::try_from(policy.max_unique_items().get()).expect("fixture candidate count fits u64");
    let content = u64::try_from(policy.max_content_bytes().get())
        .expect("fixture candidate content fits u64");
    let parsing = content
        .checked_add(crate::runtime::attempt::REMOTE_CANDIDATE_MAX_DIGEST_OVERHEAD_BYTES)
        .expect("fixture parsing work fits");
    let candidate_work =
        crate::runtime::attempt::remote_candidate_digest_retention_aggregate_claim(unique)
            .and_then(|claim| {
                claim.checked_add(crate::resource::ResourceClaim::try_from_entries([
                    (crate::resource::ResourceClass::ParsingOrCpuWork, parsing),
                    (
                        crate::resource::ResourceClass::OpaqueDependencyResidual,
                        unique
                            .checked_add(1)
                            .expect("fixture reservation records fit"),
                    ),
                ])?)
            })
            .and_then(|claim| {
                let queue = pending_remote_candidate_queue_claim_with_content(0, 0)?
                    .checked_scale(unique)?
                    .checked_add(crate::resource::ResourceClaim::single(
                        crate::resource::ResourceClass::AccountedMemoryBytes,
                        content,
                    ))?
                    .checked_add(crate::resource::ResourceClaim::single(
                        crate::resource::ResourceClass::QueuedBytes,
                        content,
                    ))?
                    .checked_add(crate::resource::ResourceClaim::single(
                        crate::resource::ResourceClass::OpaqueDependencyResidual,
                        unique,
                    ))?;
                claim.checked_add(queue)
            })
            .expect("fixture candidate-work grant is representable");
    let grant = crate::runtime::attempt::explicit_test_grant(1, 1)
        .checked_add(candidate_work)
        .and_then(|grant| grant.checked_add(additional))
        .expect("fixture resource grant is representable");
    let provider = crate::resource::FiniteResourceProvider::new(grant);
    let port = crate::resource::ResourceProviderPort::new(provider.clone())
        .expect("fixture provider admits its process scope");
    let owner = crate::runtime::attempt::ConnectorResourceOwnerPort::new(port);
    let mesh = owner
        .issue_mesh_scope()
        .expect("fixture provider admits its Mesh scope");
    let (permit, lifetime, claim) =
        admit_single_connector_candidate(crate::runtime::runtime_for_test(), mesh);
    let candidate = permit
        .reserve_connector_candidate(claim)
        .expect("fixture provider admits its connector candidate");
    let work_scope = candidate.work_resource_scope();
    (provider, owner, candidate, lifetime, work_scope)
}

struct RemoteCandidateState {
    current: RemoteCandidateAttemptEnvelope,
    provisional: Option<ProvisionalRemoteCandidateAttempt>,
}

impl RemoteCandidateState {
    fn with_resources(
        policy: PendingRemoteCandidatePolicy,
        work_resources: ConnectorWorkResourceScope,
    ) -> Self {
        Self {
            current: RemoteCandidateAttemptEnvelope::new(policy, work_resources),
            provisional: None,
        }
    }

    #[cfg(test)]
    fn new(policy: PendingRemoteCandidatePolicy) -> Self {
        Self::with_resources(policy, elastic_remote_candidate_test_scope(policy))
    }

    #[cfg(test)]
    fn new_with_restart_overlap(policy: PendingRemoteCandidatePolicy) -> Self {
        Self::with_resources(
            policy,
            elastic_remote_candidate_test_scope_with_restart_overlap(policy),
        )
    }

    fn admission_target(&mut self) -> &mut RemoteCandidateAttemptEnvelope {
        self.provisional
            .as_mut()
            .map_or(&mut self.current, |provisional| &mut provisional.envelope)
    }

    #[cfg(test)]
    fn admit(
        &mut self,
        candidate: LocalIceCandidate,
        resource_scope: &PeerConnectionResourceScope,
    ) -> PendingRemoteCandidateQueuePush {
        self.admission_target().admit(candidate, resource_scope)
    }

    fn admit_observed(
        &mut self,
        candidate: LocalIceCandidate,
        resource_scope: &PeerConnectionResourceScope,
    ) -> (
        PendingRemoteCandidateQueuePush,
        Option<super::diag::IceCandidateKind>,
    ) {
        self.admission_target()
            .admit_observed(candidate, resource_scope)
    }

    fn begin_local_ice_restart(
        &mut self,
    ) -> Result<(
        Arc<RemoteCandidateAttemptIdentity>,
        Arc<RemoteCandidateAttemptIdentity>,
    )> {
        if self.provisional.is_some() {
            return Err(Error::Transport(
                "an ICE restart transaction is already provisional".to_string(),
            ));
        }
        if self.current.remote_description_in_flight {
            return Err(Error::Transport(
                "cannot begin local ICE restart while a remote description is in flight"
                    .to_string(),
            ));
        }
        let policy = self.current.pending.budget.policy;
        let retiring = Arc::clone(&self.current.attempt);
        let replacement = RemoteCandidateAttemptEnvelope::new_provisional(
            policy,
            self.current.work_resources.clone(),
        )?;
        self.current.retire();
        let replacement_attempt = Arc::clone(&replacement.attempt);
        self.provisional = Some(ProvisionalRemoteCandidateAttempt {
            direction: IceRestartDirection::Local,
            envelope: replacement,
        });
        Ok((retiring, replacement_attempt))
    }

    fn owns_attempt(&self, attempt: &Arc<RemoteCandidateAttemptIdentity>) -> bool {
        self.current.owns_attempt(attempt)
            || self
                .provisional
                .as_ref()
                .is_some_and(|provisional| provisional.envelope.owns_attempt(attempt))
    }

    fn candidate_matches_attempt(
        &self,
        attempt: &Arc<RemoteCandidateAttemptIdentity>,
        candidate: &LocalIceCandidate,
    ) -> bool {
        let envelope = if Arc::ptr_eq(&self.current.attempt, attempt) {
            Some(&self.current)
        } else {
            self.provisional.as_ref().and_then(|provisional| {
                Arc::ptr_eq(&provisional.envelope.attempt, attempt).then_some(&provisional.envelope)
            })
        };
        let Some(credentials) =
            envelope.and_then(|envelope| envelope.remote_ice_credentials.as_ref())
        else {
            return envelope.is_some();
        };
        candidate_matches_remote_credentials(candidate, credentials)
    }

    fn commit_local_ice_restart(
        &mut self,
        attempt: &Arc<RemoteCandidateAttemptIdentity>,
    ) -> Result<()> {
        let mut provisional = self.provisional.take().ok_or_else(|| {
            Error::Transport("local ICE restart lost its provisional attempt".to_string())
        })?;
        if provisional.direction != IceRestartDirection::Local
            || !provisional.envelope.owns_attempt(attempt)
        {
            provisional.envelope.retire();
            return Err(Error::Transport(
                "local ICE restart provisional attempt was replaced".to_string(),
            ));
        }
        let mut replacement = provisional.envelope;
        let provisional_root_lease = replacement.provisional_root_lease.take();
        self.current = replacement;
        drop(provisional_root_lease);
        Ok(())
    }

    #[cfg(test)]
    fn fail_provisional(&mut self, attempt: &Arc<RemoteCandidateAttemptIdentity>) {
        if self
            .provisional
            .as_ref()
            .is_some_and(|provisional| Arc::ptr_eq(&provisional.envelope.attempt, attempt))
        {
            if let Some(mut provisional) = self.provisional.take() {
                provisional.envelope.retire();
            }
        }
    }

    /// Abort an ICE transaction whose native outcome was never proven and
    /// leave no reusable candidate-attempt state behind.
    ///
    /// This method is intentionally synchronous so a dropped async operation
    /// can fence its exact process-local attempt before the connector close
    /// owner drains the remaining native state.
    fn abort_unproven_transaction(&mut self, attempt: &Arc<RemoteCandidateAttemptIdentity>) {
        if Arc::ptr_eq(&self.current.attempt, attempt) {
            self.current.remote_description_in_flight = false;
            self.current.retire();
            return;
        }
        if self
            .provisional
            .as_ref()
            .is_some_and(|provisional| Arc::ptr_eq(&provisional.envelope.attempt, attempt))
        {
            if let Some(mut provisional) = self.provisional.take() {
                provisional.envelope.retire();
            }
        }
    }

    fn has_no_viable_attempt(&self) -> bool {
        !self.current.attempt.is_active()
            && self
                .provisional
                .as_ref()
                .is_none_or(|provisional| !provisional.envelope.attempt.is_active())
    }

    fn prepare_remote_description(
        &mut self,
        credentials: RemoteIceCredentials,
    ) -> Result<RemoteDescriptionAttempt> {
        if let Some(provisional) = self.provisional.as_mut() {
            if provisional.direction == IceRestartDirection::Local {
                return Err(Error::Transport(
                    "replacement remote description arrived before native local ICE restart committed"
                        .to_string(),
                ));
            }
            if provisional.envelope.remote_description_in_flight {
                return Err(Error::Transport(
                    "replacement remote description is already in flight".to_string(),
                ));
            }
            if let Some(expected) = provisional.envelope.remote_ice_credentials.as_ref() {
                if expected != &credentials {
                    provisional.envelope.retire();
                    return Err(Error::Transport(
                        "replacement remote description changed ICE credentials during the provisional transaction"
                            .to_string(),
                    ));
                }
            } else {
                provisional.envelope.remote_ice_credentials = Some(credentials.clone());
            }
            provisional.envelope.remote_description_in_flight = true;
            return Ok(RemoteDescriptionAttempt {
                attempt: Arc::clone(&provisional.envelope.attempt),
                provisional: true,
                retiring: None,
                credentials,
            });
        }

        if self.current.remote_description_in_flight {
            return Err(Error::Transport(
                "remote description is already in flight for this ICE attempt".to_string(),
            ));
        }

        let is_restart = self
            .current
            .remote_ice_credentials
            .as_ref()
            .is_some_and(|current| current.proves_restart_to(&credentials));
        if !is_restart {
            self.current.remote_description_in_flight = true;
            return Ok(RemoteDescriptionAttempt {
                attempt: Arc::clone(&self.current.attempt),
                provisional: false,
                retiring: None,
                credentials,
            });
        }

        let policy = self.current.pending.budget.policy;
        let mut replacement = RemoteCandidateAttemptEnvelope::new_provisional(
            policy,
            self.current.work_resources.clone(),
        )?;
        replacement.remote_ice_credentials = Some(credentials.clone());
        replacement.remote_description_in_flight = true;
        let migrated =
            replacement.adopt_queued_candidates_for_remote_restart(&mut self.current, &credentials);
        let retiring = Arc::clone(&self.current.attempt);
        self.current.retire();
        let attempt = Arc::clone(&replacement.attempt);
        self.provisional = Some(ProvisionalRemoteCandidateAttempt {
            direction: IceRestartDirection::Remote,
            envelope: replacement,
        });
        if !migrated {
            return Err(Error::Transport(
                "remote ICE restart could not conservatively transfer its bounded pre-description candidates"
                    .to_string(),
            ));
        }
        Ok(RemoteDescriptionAttempt {
            attempt,
            provisional: true,
            retiring: Some(retiring),
            credentials,
        })
    }

    fn commit_remote_description(
        &mut self,
        prepared: &RemoteDescriptionAttempt,
    ) -> Result<PendingRemoteCandidateDrain> {
        if prepared.provisional {
            let mut provisional = self.provisional.take().ok_or_else(|| {
                Error::Transport("remote description lost its provisional ICE attempt".to_string())
            })?;
            if !provisional.envelope.owns_attempt(&prepared.attempt) {
                provisional.envelope.retire();
                return Err(Error::Transport(
                    "remote description provisional ICE attempt was replaced".to_string(),
                ));
            }
            let mut replacement = provisional.envelope;
            let provisional_root_lease = replacement.provisional_root_lease.take();
            self.current = replacement;
            drop(provisional_root_lease);
        } else if !self.current.owns_attempt(&prepared.attempt) {
            return Err(Error::Transport(
                "remote description belongs to a retired ICE attempt".to_string(),
            ));
        }
        if !self.current.remote_description_in_flight {
            self.current.retire();
            return Err(Error::Transport(
                "remote description commit lost its in-flight transaction".to_string(),
            ));
        }
        self.current.remote_description_in_flight = false;
        self.current.remote_ice_credentials = Some(prepared.credentials.clone());
        self.current.remote_description_set = true;
        self.current
            .pending
            .retain_matching_remote_credentials(&prepared.credentials);
        Ok(self.current.pending.take())
    }

    fn retire_attempt(&mut self, attempt: &Arc<RemoteCandidateAttemptIdentity>) {
        if Arc::ptr_eq(&self.current.attempt, attempt) {
            self.current.retire();
            return;
        }
        if let Some(provisional) = self.provisional.as_mut() {
            if Arc::ptr_eq(&provisional.envelope.attempt, attempt) {
                provisional.envelope.retire();
            }
        }
    }

    #[cfg(test)]
    fn fail_remote_description(&mut self, prepared: &RemoteDescriptionAttempt) {
        if prepared.provisional {
            self.fail_provisional(&prepared.attempt);
        } else if Arc::ptr_eq(&self.current.attempt, &prepared.attempt) {
            self.current.remote_description_in_flight = false;
        }
    }
}

impl Drop for RemoteCandidateState {
    fn drop(&mut self) {
        self.current.retire();
        if let Some(provisional) = self.provisional.as_mut() {
            provisional.envelope.retire();
        }
    }
}

struct RemoteDescriptionAttempt {
    attempt: Arc<RemoteCandidateAttemptIdentity>,
    provisional: bool,
    retiring: Option<Arc<RemoteCandidateAttemptIdentity>>,
    credentials: RemoteIceCredentials,
}

/// Drop guard for an ICE mutation that has changed process-local ownership but
/// has not yet proven both native success and the exact state commit.
struct UncommittedIceTransaction {
    state: Arc<SyncMutex<RemoteCandidateState>>,
    close_owner: Arc<ConnectorCloseOwner>,
    attempt: Arc<RemoteCandidateAttemptIdentity>,
    armed: bool,
}

impl UncommittedIceTransaction {
    fn new(
        state: Arc<SyncMutex<RemoteCandidateState>>,
        close_owner: Arc<ConnectorCloseOwner>,
        attempt: Arc<RemoteCandidateAttemptIdentity>,
    ) -> Self {
        Self {
            state,
            close_owner,
            attempt,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for UncommittedIceTransaction {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        {
            self.state.lock().abort_unproven_transaction(&self.attempt);
        }
        // `start` drains the candidate state, so it must run after the state
        // lock above has been released.
        self.close_owner.start();
    }
}

#[derive(Debug)]
struct RemoteCandidateAttemptState {
    active_operations: usize,
    accounting_poisoned: bool,
}

/// Process-local identity and cancellation fence for one ICE candidate attempt.
#[derive(Debug)]
struct RemoteCandidateAttemptIdentity {
    active: AtomicBool,
    state: SyncMutex<RemoteCandidateAttemptState>,
    active_signal: watch::Sender<usize>,
}

impl Default for RemoteCandidateAttemptIdentity {
    fn default() -> Self {
        let (active_signal, _receiver) = watch::channel(0);
        Self {
            active: AtomicBool::new(true),
            state: SyncMutex::new(RemoteCandidateAttemptState {
                active_operations: 0,
                accounting_poisoned: false,
            }),
            active_signal,
        }
    }
}

impl RemoteCandidateAttemptIdentity {
    fn try_enter(self: &Arc<Self>) -> Option<RemoteCandidateAttemptPermit> {
        let mut state = self.state.lock();
        if !self.active.load(Ordering::Acquire) || state.accounting_poisoned {
            return None;
        }
        let Some(active_operations) = state.active_operations.checked_add(1) else {
            state.accounting_poisoned = true;
            self.active.store(false, Ordering::Release);
            return None;
        };
        state.active_operations = active_operations;
        self.active_signal.send_replace(active_operations);
        Some(RemoteCandidateAttemptPermit {
            attempt: Arc::clone(self),
            active: true,
        })
    }

    fn retire(&self) {
        self.active.store(false, Ordering::Release);
    }

    fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    async fn wait_for_operations(&self) {
        let mut active = self.active_signal.subscribe();
        loop {
            if *active.borrow() == 0 {
                return;
            }
            if active.changed().await.is_err() {
                return;
            }
        }
    }
}

struct RemoteCandidateAttemptPermit {
    attempt: Arc<RemoteCandidateAttemptIdentity>,
    active: bool,
}

impl Drop for RemoteCandidateAttemptPermit {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = self.attempt.state.lock();
        let Some(active_operations) = state.active_operations.checked_sub(1) else {
            state.accounting_poisoned = true;
            self.attempt.active.store(false, Ordering::Release);
            return;
        };
        state.active_operations = active_operations;
        self.attempt.active_signal.send_replace(active_operations);
        self.active = false;
    }
}

#[cfg(test)]
fn candidate_content_digest(candidate: &LocalIceCandidate) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash_candidate_string(&mut hash, Some(&candidate.candidate));
    hash_candidate_string(&mut hash, candidate.sdp_mid.as_ref());
    match candidate.sdp_mline_index {
        Some(value) => {
            hash.update([1]);
            hash.update(value.to_be_bytes());
        }
        None => hash.update([0]),
    }
    hash_candidate_string(&mut hash, candidate.username_fragment.as_ref());
    hash.finalize().into()
}

#[cfg(test)]
fn hash_candidate_string(hash: &mut Sha256, value: Option<&String>) {
    match value {
        Some(value) => {
            hash.update([1]);
            hash.update(value.len().to_be_bytes());
            hash.update(value.as_bytes());
        }
        None => {
            hash.update([0]);
        }
    }
}

#[allow(
    clippy::large_enum_variant,
    reason = "boxing the move-only candidate would add an unaccounted allocation"
)]
enum ConnectorAuthorityState {
    Awaiting {
        candidate: ConnectorCandidateCapability,
        liveness: AttemptLiveness,
    },
    /// The candidate has left the connector mutex and is being promoted under
    /// the attempt transition. No connector event is accepted in this state.
    Promoting,
    Connected,
    Retired {
        /// An unpromoted child claim remains owned until native cleanup has
        /// completed. Promotion can lose a race with retirement, so the slot
        /// may be filled after cleanup starts.
        candidate: Option<ConnectorCandidateCapability>,
    },
}

#[derive(Clone)]
struct ConnectorOwnership {
    incarnation: Arc<WebRtcConnectorIncarnation>,
    authority: Arc<SyncMutex<ConnectorAuthorityState>>,
    operation_fence: Arc<ConnectorOperationFence>,
    work_resource_scope: ConnectorWorkResourceScope,
    candidate_promoted: Arc<AtomicBool>,
    cleanup_complete: Arc<AtomicBool>,
    cleanup_failed: Arc<AtomicBool>,
}

impl ConnectorOwnership {
    fn admitted(
        candidate: ConnectorCandidateCapability,
        operation_fence: Arc<ConnectorOperationFence>,
        work_resource_scope: ConnectorWorkResourceScope,
        candidate_promoted: Arc<AtomicBool>,
        incarnation: Arc<WebRtcConnectorIncarnation>,
    ) -> Self {
        let attempt = candidate.liveness();
        Self {
            incarnation,
            authority: Arc::new(SyncMutex::new(ConnectorAuthorityState::Awaiting {
                candidate,
                liveness: attempt,
            })),
            operation_fence,
            work_resource_scope,
            candidate_promoted,
            cleanup_complete: Arc::new(AtomicBool::new(false)),
            cleanup_failed: Arc::new(AtomicBool::new(false)),
        }
    }

    fn accepts(&self, event: &WebRtcConnectorEvent) -> bool {
        if !Arc::ptr_eq(&self.incarnation, &event.incarnation) || !self.incarnation.is_active() {
            return false;
        }
        match (&*self.authority.lock(), &event.event) {
            (ConnectorAuthorityState::Retired { .. }, _) => false,
            // Application bytes and real-time units are both refused before the
            // channel is connected, and for the same reason: neither can be
            // authorized by anything this state holds. The real-time arm is
            // structurally unreachable — a unit exists only for a flow a
            // promoted session opened, and promotion cannot happen before
            // `Connected` — and it is written out rather than folded into the
            // liveness arm below so that reachability is a property of this
            // match rather than an inference about a caller.
            (
                ConnectorAuthorityState::Awaiting { liveness, .. },
                TransportEvent::Message(_) | TransportEvent::RealtimeUnit(_),
            ) => {
                let _ = liveness;
                false
            }
            (ConnectorAuthorityState::Awaiting { liveness, .. }, _) => liveness.is_active(),
            (ConnectorAuthorityState::Promoting, _) => false,
            (ConnectorAuthorityState::Connected, _) => true,
        }
    }

    /// Whether `task` is the endpoint-authentication owner for this exact
    /// connector incarnation.
    ///
    /// Two conjuncts, and both are load-bearing. The WebRTC liveness flag is
    /// this adapter's own retirement state; the identity comparison is made
    /// against the transport-independent identity, because that is the only one
    /// the task holds. The task names a `ConnectorIncarnation` and knows nothing
    /// about WebRTC — the translation belongs on this side of the boundary, not
    /// in `endpoint_auth`, and `belongs_to` stays an exact identity check rather
    /// than being widened to accept a transport type.
    fn owns_endpoint_auth(&self, task: &crate::endpoint_auth::EndpointAuthTask) -> bool {
        self.incarnation.is_active() && task.belongs_to(self.incarnation.generic())
    }

    /// This worker's transport-independent connector identity, but only while
    /// the connector is still live.
    ///
    /// Both conjuncts, from their one authoritative source each: the identity is
    /// the incarnation's, and the liveness is `is_active`, which this type owns.
    /// A retired worker answers `None`, so a promotion cannot name a connector
    /// that has already gone.
    pub(crate) fn live_connector_incarnation(
        &self,
    ) -> Option<&Arc<crate::connector::ConnectorIncarnation>> {
        self.incarnation
            .is_active()
            .then(|| self.incarnation.generic())
    }

    fn enter_operation(&self) -> Result<ConnectorOwnedOperationPermit> {
        let resources = self
            .work_resource_scope
            .acquire(
                crate::resource::ResourceAuthorityClass::Speculative,
                crate::runtime::attempt::connector_operation_claim(),
            )
            .map_err(Error::from)?;
        let fence = self
            .operation_fence
            .try_enter()
            .ok_or_else(|| Error::Transport("connector close fence has committed".to_string()))?;
        Ok(ConnectorOwnedOperationPermit {
            _fence: fence,
            _resources: resources,
        })
    }

    fn begin_close(&self) {
        self.operation_fence.begin_close();
    }

    fn mark_data_channel_open(&self) -> DataChannelOpenTransition {
        self.mark_data_channel_open_after_extract(|| {})
    }

    /// Promote without nesting the connector-authority mutex and attempt
    /// transition mutex.
    ///
    /// The candidate first moves into a private `Promoting` state under the
    /// connector mutex. That mutex is released before `mark_connected` enters
    /// the attempt transition. The connector mutex is then reacquired only to
    /// publish the result. Attempt retirement may therefore notify connector
    /// retirement after releasing its own transition mutex without creating a
    /// reverse lock edge.
    fn mark_data_channel_open_after_extract(
        &self,
        after_extract: impl FnOnce(),
    ) -> DataChannelOpenTransition {
        let candidate = {
            let mut authority = self.authority.lock();
            if !self.incarnation.is_active() {
                return DataChannelOpenTransition::Rejected;
            }
            match std::mem::replace(
                &mut *authority,
                ConnectorAuthorityState::Retired { candidate: None },
            ) {
                ConnectorAuthorityState::Awaiting {
                    candidate,
                    liveness: _,
                } => {
                    *authority = ConnectorAuthorityState::Promoting;
                    candidate
                }
                ConnectorAuthorityState::Promoting => {
                    *authority = ConnectorAuthorityState::Promoting;
                    return DataChannelOpenTransition::Rejected;
                }
                ConnectorAuthorityState::Connected => {
                    *authority = ConnectorAuthorityState::Connected;
                    return DataChannelOpenTransition::AlreadyConnected;
                }
                ConnectorAuthorityState::Retired { candidate } => {
                    *authority = ConnectorAuthorityState::Retired { candidate };
                    self.incarnation.retire();
                    return DataChannelOpenTransition::Rejected;
                }
            }
        };

        after_extract();
        let promoted = crate::connector::try_mark_connected(candidate);
        let mut authority = self.authority.lock();
        match (
            std::mem::replace(
                &mut *authority,
                ConnectorAuthorityState::Retired { candidate: None },
            ),
            promoted,
        ) {
            (ConnectorAuthorityState::Promoting, Ok(capability))
                if self.incarnation.is_active() =>
            {
                *authority = ConnectorAuthorityState::Connected;
                self.candidate_promoted.store(true, Ordering::Release);
                DataChannelOpenTransition::Connected(capability)
            }
            (state, promoted) => {
                let candidate = match promoted {
                    Ok(capability) => capability.into_candidate(),
                    Err(candidate) => candidate,
                };
                *authority = match state {
                    ConnectorAuthorityState::Retired {
                        candidate: existing,
                    } => ConnectorAuthorityState::Retired {
                        candidate: existing.or(Some(candidate)),
                    },
                    _ => ConnectorAuthorityState::Retired {
                        candidate: Some(candidate),
                    },
                };
                self.incarnation.retire();
                if self.cleanup_failed.load(Ordering::Acquire) {
                    Self::retain_failed_candidate_locked(&mut authority);
                } else if self.cleanup_complete.load(Ordering::Acquire) {
                    Self::release_cleanup_candidate_locked(&mut authority);
                }
                DataChannelOpenTransition::Rejected
            }
        }
    }

    fn retire(&self) {
        self.begin_close();
        let mut authority = self.authority.lock();
        self.incarnation.retire();
        let candidate = match std::mem::replace(
            &mut *authority,
            ConnectorAuthorityState::Retired { candidate: None },
        ) {
            ConnectorAuthorityState::Awaiting { candidate, .. } => Some(candidate),
            ConnectorAuthorityState::Retired { candidate } => candidate,
            ConnectorAuthorityState::Promoting | ConnectorAuthorityState::Connected => None,
        };
        *authority = ConnectorAuthorityState::Retired { candidate };
        if self.cleanup_failed.load(Ordering::Acquire) {
            Self::retain_failed_candidate_locked(&mut authority);
        } else if self.cleanup_complete.load(Ordering::Acquire) {
            Self::release_cleanup_candidate_locked(&mut authority);
        }
    }

    /// Attempt retirement reclaims only candidates that have not promoted.
    /// A connected winner has already transferred into Endpoint Auth Task and
    /// is retired by its peer installation owner instead.
    fn retire_if_unconnected(&self) -> bool {
        self.begin_close();
        let mut authority = self.authority.lock();
        if matches!(&*authority, ConnectorAuthorityState::Connected) {
            return false;
        }
        self.incarnation.retire();
        let candidate = match std::mem::replace(
            &mut *authority,
            ConnectorAuthorityState::Retired { candidate: None },
        ) {
            ConnectorAuthorityState::Awaiting { candidate, .. } => Some(candidate),
            ConnectorAuthorityState::Retired { candidate } => candidate,
            ConnectorAuthorityState::Promoting | ConnectorAuthorityState::Connected => None,
        };
        *authority = ConnectorAuthorityState::Retired { candidate };
        if self.cleanup_failed.load(Ordering::Acquire) {
            Self::retain_failed_candidate_locked(&mut authority);
        } else if self.cleanup_complete.load(Ordering::Acquire) {
            Self::release_cleanup_candidate_locked(&mut authority);
        }
        true
    }

    fn complete_cleanup(&self) {
        self.cleanup_complete.store(true, Ordering::Release);
        let mut authority = self.authority.lock();
        Self::release_cleanup_candidate_locked(&mut authority);
    }

    fn retain_after_cleanup_failure(&self) {
        self.cleanup_failed.store(true, Ordering::Release);
        let mut authority = self.authority.lock();
        Self::retain_failed_candidate_locked(&mut authority);
    }

    fn retain_failed_candidate_locked(authority: &mut ConnectorAuthorityState) {
        if let ConnectorAuthorityState::Retired {
            candidate: Some(candidate),
        } = authority
        {
            candidate.retain_after_cleanup_failure();
        }
    }

    fn release_cleanup_candidate_locked(authority: &mut ConnectorAuthorityState) {
        if let ConnectorAuthorityState::Retired { candidate } = authority {
            if let Some(candidate) = candidate.as_mut() {
                candidate.release_after_cleanup_success();
            }
            drop(candidate.take());
        }
    }

    #[cfg(test)]
    fn cleanup_candidate_reserved_for_test(&self) -> bool {
        match &*self.authority.lock() {
            ConnectorAuthorityState::Retired {
                candidate: Some(candidate),
            } => candidate.reservation_is_active_for_test(),
            _ => false,
        }
    }
}

struct ConnectorOwnedOperationPermit {
    _fence: ConnectorOperationPermit,
    _resources: crate::resource::ResourceLease,
}

fn candidate_resource_measurement(candidate: &LocalIceCandidate) -> ResourceMeasurement {
    let (logical_bytes, _) = measured_sum([
        candidate.candidate.len(),
        candidate.sdp_mid.as_ref().map_or(0, String::len),
        candidate
            .sdp_mline_index
            .map_or(0, |_| std::mem::size_of::<u16>()),
        candidate.username_fragment.as_ref().map_or(0, String::len),
    ]);
    let (retained_bytes, _) = measured_sum([
        candidate.candidate.capacity(),
        candidate.sdp_mid.as_ref().map_or(0, String::capacity),
        candidate
            .username_fragment
            .as_ref()
            .map_or(0, String::capacity),
    ]);
    let observed = ResourceUse::observed(1, logical_bytes, retained_bytes, 0);
    // String capacities and the content fields are observable, but allocator
    // overhead and storage retained inside webrtc-rs are not. This must not be
    // reported as exact retained memory.
    ResourceMeasurement::inexact(observed)
}

fn queue_container_resource_measurement(
    entries: &std::collections::LinkedList<PendingRemoteCandidate>,
) -> ResourceMeasurement {
    let bytes = entries
        .len()
        .checked_mul(size_of::<PendingRemoteCandidate>());
    let (retained_bytes, _) = measured_usize(bytes);
    let observed = ResourceUse::observed(0, 0, retained_bytes, 0);
    // Each linked-list node is paired with the candidate's provider-backed
    // storage-object claim. Allocator overhead remains observationally
    // inexact.
    ResourceMeasurement::inexact(observed)
}

fn measured_usize(value: Option<usize>) -> (u64, bool) {
    match value.and_then(|value| u64::try_from(value).ok()) {
        Some(value) => (value, false),
        None => (0, true),
    }
}

fn measured_sum<const N: usize>(values: [usize; N]) -> (u64, bool) {
    let mut sum = 0_u64;
    let mut inexact = false;
    for value in values {
        let (value, conversion_inexact) = measured_usize(Some(value));
        inexact |= conversion_inexact;
        match sum.checked_add(value) {
            Some(next) => sum = next,
            None => {
                sum = 0;
                inexact = true;
            }
        }
    }
    (sum, inexact)
}

/// Observe one explicitly owned connector item. Retained memory remains
/// inexact until the underlying webrtc-rs owner exposes an allocation report.
fn observe_inexact_item(
    scope: &PeerConnectionResourceScope,
    family: PreAuthResourceFamily,
    items: u64,
    tasks: u64,
) -> ObservationLease {
    scope.observe_pre_authentication_measurement(
        family,
        ResourceMeasurement::inexact(ResourceUse::observed(items, 0, 0, tasks)),
    )
}

fn observe_inexact_item_if(
    scope: Option<&PeerConnectionResourceScope>,
    family: PreAuthResourceFamily,
    items: u64,
    tasks: u64,
) -> Option<ObservationLease> {
    scope.map(|scope| observe_inexact_item(scope, family, items, tasks))
}

/// One move-only handoff from the exact connector incarnation to Endpoint
/// Auth Task.
pub(crate) struct EndpointAuthHandoff {
    capability: Option<crate::connector::ConnectedChannelCapability>,
    incarnation: Arc<WebRtcConnectorIncarnation>,
    close_owner: Arc<ConnectorCloseOwner>,
}

impl EndpointAuthHandoff {
    fn new(
        capability: crate::connector::ConnectedChannelCapability,
        incarnation: Arc<WebRtcConnectorIncarnation>,
        close_owner: Arc<ConnectorCloseOwner>,
    ) -> Self {
        Self {
            capability: Some(capability),
            incarnation,
            close_owner,
        }
    }

    // No accessors for the incarnation or the borrowed capability. This type is
    // now a one-way staging step: a connector builds it and immediately moves it
    // into its transport-independent form. Endpoint authentication inspects and
    // validates the *generic* handoff, so exposing a WebRTC-shaped identity or
    // capability borrow here would only offer a second, transport-specific way
    // to reach facts that already have one owner.

    // Deliberately no `take`/`restore` of the bare capability. Promotion moves
    // the *whole* handoff, because this type is what carries the connector
    // incarnation and the close owner, and its `Drop` is what re-retains the
    // connected claim until native close succeeds. Extracting the capability
    // alone would strip that retention, so an authenticated capability dropped
    // on retirement or on a refused install would release the claim early.

    /// Move this handoff into its transport-independent form.
    ///
    /// The whole ownership triple moves together: the capability, the generic
    /// identity for this exact incarnation, and this close owner as the
    /// retention obligation. Nothing is copied and nothing is left behind — the
    /// consumed WebRTC handoff drops with no capability, so the claim is
    /// retained exactly once, by the generic handoff's `Drop`, through the same
    /// close owner as before.
    ///
    /// Returns `None` only if the capability was already moved out, which is
    /// the same condition under which the old `Drop` would have retained
    /// nothing.
    pub(crate) fn into_generic(mut self) -> Option<crate::connector::ConnectedChannelHandoff> {
        let capability = self.capability.take()?;
        Some(crate::connector::ConnectedChannelHandoff::new(
            capability,
            Arc::clone(self.incarnation.generic()),
            self.close_owner.generic_retention(),
        ))
    }
}

/// One fixture task over a WebRTC handoff, for the connector lifecycle
/// controls.
///
/// Those controls exercise retirement, replacement, and admission around a
/// task; they do not exercise the exchange. This converts the handoff to its
/// generic form and defers to the endpoint-authentication fixture constructor,
/// so the cryptographic context is defined in exactly one place rather than
/// re-stated at every call site.
#[cfg(test)]
fn task_from_handoff(handoff: EndpointAuthHandoff) -> crate::endpoint_auth::EndpointAuthTask {
    crate::endpoint_auth::task_for_test(
        handoff
            .into_generic()
            .expect("a freshly built handoff still carries its capability"),
    )
}

/// The same conversion, forcing this endpoint's contribution to a prior value.
///
/// Only the same-certificate replay control needs it, to build the one case the
/// freshness rule prevents. See `endpoint_auth::task_reusing_contribution_for_test`.
#[cfg(test)]
fn task_from_handoff_reusing(
    handoff: EndpointAuthHandoff,
    local_contribution: &str,
) -> crate::endpoint_auth::EndpointAuthTask {
    crate::endpoint_auth::task_reusing_contribution_for_test(
        handoff
            .into_generic()
            .expect("a freshly built handoff still carries its capability"),
        crate::endpoint_auth::LocalContribution::reuse_for_test(local_contribution),
    )
}

impl Drop for EndpointAuthHandoff {
    fn drop(&mut self) {
        if let Some(capability) = self.capability.take() {
            self.close_owner.retain_connected_claim(capability);
        }
    }
}

/// One component of the endpoint-authentication channel binding this connector
/// can be made to withhold. **Controls only.**
///
/// A live native link whose data channel is open always presents both DTLS
/// fingerprints, so the condition the production supplier fails closed on —
/// half a pair — cannot be reached by driving the stack. Naming the component
/// here is what lets the two missing-side controls be exact twins that differ in
/// one value, rather than one control that proves "something was missing".
///
/// The whole withheld-binding surface is gated on `transport-lab` as well as
/// `test`, because the only thing that can arm it is the live two-connector
/// fixture, and that needs a real WebRTC link. Gating it on `test` alone leaves
/// every item here uncalled in a default-feature test build.
#[cfg(all(test, feature = "transport-lab"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WithheldBindingComponent {
    Local,
    Remote,
}

#[cfg(all(test, feature = "transport-lab"))]
impl WithheldBindingComponent {
    /// The armed marker for this component. Never zero: zero is "withholding
    /// nothing", which is the state every connector is constructed in.
    fn marker(self) -> u8 {
        match self {
            Self::Local => 1,
            Self::Remote => 2,
        }
    }
}

/// Narrow owner of one RTCPeerConnection, its ICE agent, callback identity,
/// and pending remote-candidate queue.
///
/// Production construction requires an admitted connector-candidate capability.
/// The worker cannot mint admission from a peer label or native transport value.
pub(crate) struct WebRtcConnectorWorker {
    session: Arc<PeerSession>,
    ownership: ConnectorOwnership,
    remote_candidates: Arc<SyncMutex<RemoteCandidateState>>,
    close_owner: Arc<ConnectorCloseOwner>,
    /// The flow registry this worker's sessions open against.
    ///
    /// Retained here rather than reached through `close_owner`, which already
    /// holds a handle for teardown. A teardown owner that also handed out live
    /// registries for constructing new things would carry two jobs that can
    /// disagree about which is authoritative during a close.
    realtime_flows: Arc<RealtimeFlowRegistry>,
    resource_scope: PeerConnectionResourceScope,
    _transport_observation: ObservationLease,
    /// Which single binding component this connector withholds from its own
    /// supplier. **Controls only**, compiled out of production entirely.
    ///
    /// Withhold-only and monotonic: there is no operation that supplies a
    /// component, restores one, or names both, so a fixture can remove material
    /// the live link genuinely stated and can never inject material it did not.
    /// That direction is the safety property — a seam that could supply a
    /// fingerprint would be the substitution this whole boundary exists to
    /// refuse, dressed as a test helper.
    #[cfg(all(test, feature = "transport-lab"))]
    withheld_binding_component: std::sync::atomic::AtomicU8,
}

struct AdmittedConnectorOwnership {
    ownership: ConnectorOwnership,
    attempt_lifetime: AttemptLifetime,
    attempt_liveness: AttemptLiveness,
    close_owner: Arc<ConnectorCloseOwner>,
    resource_scope: PeerConnectionResourceScope,
    work_resource_scope: ConnectorWorkResourceScope,
    transport_observation: ObservationLease,
    remote_candidate_policy: PendingRemoteCandidatePolicy,
    reclaim: ResourceReclaimSubscription,
}

/// The session side of the realtime flow binding.
///
/// Placed here rather than in `runtime::session_broker` so the session type
/// stays transport-independent: it never names a WebRTC incarnation, and this
/// module already knows both vocabularies.
///
/// `is_current_on` answers **identity only**, and that is not a gap. The
/// liveness half is carried by how the caller obtains its argument: the only
/// production source of an incarnation to pass here is
/// [`WebRtcConnectorWorker::live_connector_incarnation`], which yields `None`
/// once the connector is retired. So a retired connector cannot produce an
/// argument for this call at all, and the pair of conjuncts holds without the
/// session caching a liveness flag that could disagree with the connector.
impl session_flow::RealtimeSessionBinding for crate::runtime::session_broker::SessionCapability {
    fn is_current_on(&self, incarnation: &Arc<crate::connector::ConnectorIncarnation>) -> bool {
        self.belongs_to(incarnation)
    }
}

impl WebRtcConnectorWorker {
    /// Build the flow set one promoted session owns.
    ///
    /// The engine calls this at promotion and stores the result beside the
    /// capability, so the set is bound to the exact worker the session was
    /// promoted from. Constructing it here is what keeps `RealtimeFlowRegistry`
    /// unnameable by the engine — the opaque set is the only thing that crosses.
    pub(crate) fn new_session_flows(&self) -> session_flow::SessionRealtimeFlows {
        let flows = session_flow::SessionRealtimeFlows::new(
            Arc::clone(&self.realtime_flows),
            self.session.realtime_profile.clone(),
        );
        // Point the connector's `on_track` handler at this session's table, and
        // at no other. Installed here rather than by the engine because the
        // engine must not name `RealtimeInboundBindings` at all — this accessor
        // is the one place both vocabularies are already in scope.
        //
        // Weak, so the table cannot outlive the `PromotedSession` about to own
        // this set: when that drops, the upgrade in `on_track` fails and an
        // arriving track is refused, with nothing having to be told.
        self.session
            .realtime_tracks
            .install(flows.inbound_bindings());
        flows
    }

    /// Whether this connector may still do native realtime work, and the
    /// profile that says what it may do.
    ///
    /// One helper for the two conjuncts every method below opens with, so the
    /// order cannot drift between them: the connector is still live, and the
    /// application registered the family being asked for. The second is the
    /// **registered-profile selection** rule — core has no opinion about
    /// codecs, only about whether this one was offered, so an unregistered
    /// family is refused here rather than negotiated and then found
    /// unframeable at admission.
    fn realtime_negotiation_guard(&self, encoding: &RealtimeEncoding) -> Result<()> {
        if !self.ownership.incarnation.is_active() {
            return Err(Error::Transport(
                "connector retired before realtime negotiation".to_string(),
            ));
        }
        let registered = self
            .session
            .realtime_profile
            .as_ref()
            .is_some_and(|profile| profile.profile().admits_encoding(encoding).is_some());
        if !registered {
            return Err(Error::Transport(
                "realtime encoding names no registered capability".to_string(),
            ));
        }
        Ok(())
    }

    /// Create the receive-only transceiver an inbound session flow attaches to.
    ///
    /// `identity` is minted and **already bound** by the engine's fence before
    /// this is called. That ordering is the whole design: the transceiver that
    /// could carry a track is created against a token that already resolves, so
    /// no track can arrive ahead of its binding and no start-of-flow media is
    /// lost to a race.
    ///
    /// This does not drive renegotiation. Adding a transceiver raises
    /// `RenegotiationNeeded`, which the engine already coalesces into one
    /// offer; a second path here would be a second offer for the same change.
    pub(crate) async fn open_inbound_realtime_transceiver(
        &self,
        identity: &Arc<RealtimeTrackIdentity>,
        encoding: &RealtimeEncoding,
    ) -> Result<()> {
        // Held across the whole call so a close cannot commit underneath a
        // half-created transceiver.
        let _operation = self.ownership.enter_operation()?;
        self.realtime_negotiation_guard(encoding)?;
        let transceiver = self
            .session
            .pc
            .add_transceiver_from_kind(
                native_codec_type(encoding.kind()),
                Some(RTCRtpTransceiverInit {
                    // Receive only. A sendrecv transceiver would offer to send
                    // on a flow the application opened to receive, advertising
                    // a direction nothing here will ever write to.
                    direction: RTCRtpTransceiverDirection::Recvonly,
                    send_encodings: Vec::new(),
                }),
            )
            .await
            .map_err(|error| {
                Error::Transport(format!("inbound realtime add_transceiver: {error}"))
            })?;
        self.session
            .realtime_tracks
            .record(Arc::clone(identity), transceiver);
        Ok(())
    }

    /// Release a transceiver whose commit fence refused.
    ///
    /// Safe for a token that never recorded one — the engine calls this on
    /// paths where negotiation may not have got that far, and a caller should
    /// not have to know which. Answers nothing for the same reason: there is no
    /// action left for the caller either way.
    /// It is also the retirement path for a token handed back by
    /// `SessionRealtimeFlows::close`, which is the ordinary case rather than the
    /// exceptional one. Both go through the same claim, so a close racing the
    /// pump that was feeding the same flow cannot stop one transceiver twice.
    pub(crate) async fn close_inbound_realtime_transceiver(
        &self,
        identity: &Arc<RealtimeTrackIdentity>,
    ) {
        self.session.realtime_tracks.stop_claimed(identity).await;
    }

    /// Create and attach the native sender for an outbound session flow.
    ///
    /// The track's MIME is the one the application registered, taken from the
    /// encoding rather than from a constant: this module has no codec table and
    /// must not acquire one.
    pub(crate) async fn open_outbound_realtime_track(
        &self,
        encoding: &RealtimeEncoding,
    ) -> Result<RealtimeOutboundTrack> {
        let _operation = self.ownership.enter_operation()?;
        self.realtime_negotiation_guard(encoding)?;
        let track = Arc::new(TrackLocalStaticSample::new(
            RTCRtpCodecCapability {
                mime_type: encoding.mime().to_string(),
                clock_rate: encoding.clock_rate(),
                channels: encoding.channels(),
                ..Default::default()
            },
            // Ids the peer never routes on. Inbound demux is by the transceiver
            // this side created, never by a name off the wire, so these exist
            // for traces and for the library's own bookkeeping.
            format!("flow-{}", encoding.mime()),
            "myownmesh".to_string(),
        ));
        let sender = self
            .session
            .pc
            .add_track(Arc::clone(&track) as Arc<dyn TrackLocal + Send + Sync>)
            .await
            .map_err(|error| Error::Transport(format!("outbound realtime add_track: {error}")))?;
        Ok(RealtimeOutboundTrack {
            track,
            sender,
            // Carried on the track rather than looked up at retirement time,
            // because the pump that ends up owning this has no worker to ask.
            pc: Arc::clone(&self.session.pc),
            incarnation: Arc::clone(&self.ownership.incarnation),
        })
    }

    /// Release a track the commit fence refused.
    ///
    /// Taken by value: a released track must not be attachable afterwards, and
    /// consuming it is what makes that structural rather than a rule.
    ///
    /// This exists for exactly one case — negotiation succeeded and the fence
    /// then refused, so the caller is holding a track that was never attached
    /// and therefore has no pump and no completion lease. Once
    /// `attach_outbound` accepts, the pump is the only owner and this path is
    /// unreachable for that track.
    pub(crate) async fn close_outbound_realtime_track(&self, track: RealtimeOutboundTrack) {
        track.retire().await;
    }

    /// This worker's transport-independent connector identity, while live.
    ///
    /// Forwards to the ownership that actually holds the incarnation, so there
    /// is one implementation of the identity-and-liveness pair rather than two
    /// that could drift.
    pub(crate) fn live_connector_incarnation(
        &self,
    ) -> Option<&Arc<crate::connector::ConnectorIncarnation>> {
        self.ownership.live_connector_incarnation()
    }

    fn admitted(
        session: PeerSession,
        raw: TransportEventReceiver,
        admitted: AdmittedConnectorOwnership,
    ) -> Result<(Self, WebRtcConnectorEventReceiver)> {
        let AdmittedConnectorOwnership {
            ownership,
            attempt_lifetime,
            attempt_liveness,
            close_owner,
            resource_scope,
            work_resource_scope,
            transport_observation,
            remote_candidate_policy,
            reclaim,
        } = admitted;
        let attempt_retirement = attempt_liveness.subscribe_retirement();
        let session = Arc::new(session);
        let remote_candidates = Arc::new(SyncMutex::new(RemoteCandidateState::with_resources(
            remote_candidate_policy,
            work_resource_scope,
        )));
        if !close_owner.attach_remote_candidates(Arc::clone(&remote_candidates)) {
            close_owner.start();
            return Err(Error::Transport(
                "remote-candidate owner installation was refused".to_string(),
            ));
        }
        if !close_owner.attach_realtime_flows(Arc::clone(&raw.realtime_flows)) {
            close_owner.start();
            return Err(Error::Transport(
                "real-time registry owner installation was refused".to_string(),
            ));
        }
        // Cloned before `raw` moves into the receiver below.
        let realtime_flows = Arc::clone(&raw.realtime_flows);
        let receiver = WebRtcConnectorEventReceiver {
            ownership: ownership.clone(),
            retirement: ownership.incarnation.subscribe_retirement(),
            attempt_retirement: Some(attempt_retirement),
            raw,
            attempt_lifetime: Some(attempt_lifetime),
            remote_candidates: Arc::clone(&remote_candidates),
            close_owner: Some(Arc::clone(&close_owner)),
            reclaim: Some(reclaim),
            data_channel_open_committed: false,
            data_channel_closed: false,
            operation_fence: Arc::clone(&ownership.operation_fence),
        };
        Ok((
            Self {
                session,
                ownership,
                realtime_flows,
                remote_candidates,
                close_owner,
                resource_scope,
                _transport_observation: transport_observation,
                #[cfg(all(test, feature = "transport-lab"))]
                withheld_binding_component: std::sync::atomic::AtomicU8::new(0),
            },
            receiver,
        ))
    }

    /// Consume an event only when it came from this still-active worker, and —
    /// for a real-time unit — only while this session still owns a binding
    /// table for it to have come from.
    ///
    /// Two questions, asked by the two owners that can actually answer them.
    /// `ownership.accepts` answers the connector one: same incarnation, still
    /// live, past the states in which nothing can be authorized. It cannot
    /// answer the second, because the session's binding table is not the
    /// connector's to know about — a connector stays `Connected` across the
    /// whole life of a peer connection, including after a promoted session's
    /// table has died with it.
    ///
    /// The second is asked here because this is the first point that holds
    /// both. A `RealtimeUnit` exists only for a flow some session opened, so
    /// once `realtime_tracks.current()` is `None` there is no live table that
    /// unit could belong to: it was minted against a table that has since been
    /// dropped, or against a session this worker no longer serves. Refusing it
    /// here means the refusal lands *before* delivery and before any
    /// consumer-side work or accounting is charged for it. The connector-side
    /// flow and output leases the unit already carries are not undone by that —
    /// they were taken when the unit was assembled and are simply released when
    /// the refused event drops, which is the same path any dropped unit takes.
    ///
    /// Deliberately not the callback-work lease: that a callback was afforded
    /// says the provider had capacity, not that the event is authorized, and
    /// reading capacity as authority is how a resource decision becomes a
    /// security one.
    pub(crate) fn accept_event(
        &self,
        event: WebRtcConnectorEvent,
    ) -> Option<AcceptedWebRtcConnectorEvent> {
        if !self.ownership.accepts(&event) {
            return None;
        }
        if matches!(&event.event, TransportEvent::RealtimeUnit(_))
            && self.session.realtime_tracks.current().is_none()
        {
            return None;
        }
        Some(AcceptedWebRtcConnectorEvent {
            event: event.event,
            resources: AcceptedWebRtcConnectorEventResources {
                _queue_observation: event._queue_observation,
                _callback_work: event._callback_work,
            },
        })
    }

    #[cfg(test)]
    pub(crate) fn stamp_event_for_test(&self, event: TransportEvent) -> WebRtcConnectorEvent {
        WebRtcConnectorEvent {
            incarnation: Arc::clone(&self.ownership.incarnation),
            event,
            _queue_observation: None,
            _callback_work: None,
        }
    }

    /// Apply or retain one inbound candidate under this worker's ownership.
    #[cfg(test)]
    pub(crate) async fn add_remote_candidate(
        &self,
        candidate: LocalIceCandidate,
    ) -> Result<RemoteCandidateDisposition> {
        Ok(self
            .add_remote_candidate_observed(candidate)
            .await?
            .disposition)
    }

    pub(crate) async fn add_remote_candidate_observed(
        &self,
        candidate: LocalIceCandidate,
    ) -> Result<RemoteCandidateAdmissionReport> {
        let _operation = self.ownership.enter_operation()?;
        let (pending, kind) = {
            let mut state = self.remote_candidates.lock();
            if !self.ownership.incarnation.is_active() {
                return Err(Error::Transport("connector worker is retired".to_string()));
            }
            let (admitted, kind) = state.admit_observed(candidate, &self.resource_scope);
            let target = state.admission_target();
            if !target.remote_description_set
                || (admitted == PendingRemoteCandidateQueuePush::Queued
                    && !target.last_candidate_matches_remote_credentials())
            {
                let disposition = match admitted {
                    PendingRemoteCandidateQueuePush::Queued => {
                        RemoteCandidateDisposition::QueuedUntilRemoteDescription
                    }
                    PendingRemoteCandidateQueuePush::Duplicate => {
                        RemoteCandidateDisposition::DuplicateIgnored
                    }
                    PendingRemoteCandidateQueuePush::InvalidBinding(error) => {
                        RemoteCandidateDisposition::InvalidBinding(error)
                    }
                    PendingRemoteCandidateQueuePush::ResourceUnavailable(error) => {
                        return Err(Error::ResourceUnavailable(error));
                    }
                    PendingRemoteCandidateQueuePush::Refused => {
                        RemoteCandidateDisposition::RefusedByOwner
                    }
                    PendingRemoteCandidateQueuePush::Retired => {
                        RemoteCandidateDisposition::AttemptRetired
                    }
                };
                return Ok(RemoteCandidateAdmissionReport { disposition, kind });
            }
            let pending = match admitted {
                PendingRemoteCandidateQueuePush::Queued => target
                    .pending
                    .pop_last_for_application(&self.resource_scope)
                    .ok_or_else(|| {
                        Error::Transport(
                            "remote-candidate admission lost its exact queued value".to_string(),
                        )
                    })?,
                PendingRemoteCandidateQueuePush::Duplicate => {
                    return Ok(RemoteCandidateAdmissionReport {
                        disposition: RemoteCandidateDisposition::DuplicateIgnored,
                        kind,
                    })
                }
                PendingRemoteCandidateQueuePush::InvalidBinding(error) => {
                    return Ok(RemoteCandidateAdmissionReport {
                        disposition: RemoteCandidateDisposition::InvalidBinding(error),
                        kind,
                    })
                }
                PendingRemoteCandidateQueuePush::ResourceUnavailable(error) => {
                    return Err(Error::ResourceUnavailable(error));
                }
                PendingRemoteCandidateQueuePush::Refused => {
                    return Ok(RemoteCandidateAdmissionReport {
                        disposition: RemoteCandidateDisposition::RefusedByOwner,
                        kind,
                    })
                }
                PendingRemoteCandidateQueuePush::Retired => {
                    return Ok(RemoteCandidateAdmissionReport {
                        disposition: RemoteCandidateDisposition::AttemptRetired,
                        kind,
                    })
                }
            };
            (pending, kind)
        };
        self.apply_remote_candidate(pending).await?;
        Ok(RemoteCandidateAdmissionReport {
            disposition: RemoteCandidateDisposition::Applied,
            kind,
        })
    }

    /// Admit raw remote SDP before the native dependency parses or retains it.
    pub(crate) async fn apply_remote_sdp(
        &self,
        sdp_type: RTCSdpType,
        sdp: String,
    ) -> Result<RemoteDescriptionApplyReport> {
        let _operation = self.ownership.enter_operation()?;
        if !self.ownership.incarnation.is_active() {
            return Err(Error::Transport("connector worker is retired".to_string()));
        }
        let _work_observation = observe_inexact_item(
            &self.resource_scope,
            PreAuthResourceFamily::ConnectorSpecificWork,
            1,
            0,
        );
        let work_resources = self
            .remote_candidates
            .lock()
            .admission_target()
            .work_resources
            .clone();
        let credentials = sdp_ice_credentials_owned(&sdp, sdp.capacity(), &work_resources)?;
        let description = match sdp_type {
            RTCSdpType::Offer => RTCSessionDescription::offer(sdp),
            RTCSdpType::Answer => RTCSessionDescription::answer(sdp),
            _ => {
                return Err(Error::Transport(
                    "only offer and answer remote descriptions are supported".to_string(),
                ));
            }
        }
        .map_err(|error| Error::Transport(format!("parse remote SDP: {error}")))?;
        self.apply_remote_description_owned(description, credentials)
            .await
    }

    /// Apply remote SDP, transfer queue ownership into the async drain, and
    /// apply every retained candidate through the connector-private raw API.
    /// The caller must retain the exact connector operation permit.
    async fn apply_remote_description_owned(
        &self,
        description: RTCSessionDescription,
        credentials: RemoteIceCredentials,
    ) -> Result<RemoteDescriptionApplyReport> {
        let prepared = {
            let mut state = self.remote_candidates.lock();
            match state.prepare_remote_description(credentials) {
                Ok(prepared) => prepared,
                Err(error) => {
                    let must_retire_connector = state.has_no_viable_attempt();
                    drop(state);
                    if must_retire_connector {
                        self.close_owner.start();
                    }
                    return Err(error);
                }
            }
        };
        let mut transaction = UncommittedIceTransaction::new(
            Arc::clone(&self.remote_candidates),
            Arc::clone(&self.close_owner),
            Arc::clone(&prepared.attempt),
        );
        if let Some(resources) = prepared.credentials.resource_owner() {
            // The native dependency may retain a parsed description even when
            // its future is cancelled or returns an error. Transfer the exact
            // residual owner to the connector close owner before entering the
            // native operation.
            self.close_owner
                .retain_remote_description_resources(resources);
        }
        if let Some(retiring) = prepared.retiring.as_ref() {
            retiring.wait_for_operations().await;
        }
        let _attempt_operation = match prepared.attempt.try_enter() {
            Some(operation) => operation,
            None => {
                if prepared.provisional {
                    self.close_owner.start();
                }
                return Err(Error::Transport(
                    "remote-candidate attempt is retired".to_string(),
                ));
            }
        };
        let native_result = await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.set_remote_description(description),
        )
        .await
        .ok_or_else(|| Error::Transport("connector worker retired during SDP apply".to_string()))?;
        native_result?;
        prepared.credentials.finish_native_commit()?;
        let pending = {
            let mut state = self.remote_candidates.lock();
            if !self.ownership.incarnation.is_active() {
                return Err(Error::Transport(
                    "connector worker retired during SDP apply".to_string(),
                ));
            }
            match state.commit_remote_description(&prepared) {
                Ok(pending) => pending,
                Err(error) => {
                    drop(state);
                    self.close_owner.start();
                    return Err(error);
                }
            }
        };
        transaction.disarm();
        let queued_candidate_count = pending.len();
        let mut candidate_failure_count = 0_usize;
        for candidate in pending {
            if let Err(error) = self.apply_remote_candidate(candidate).await {
                candidate_failure_count =
                    candidate_failure_count
                        .checked_add(1)
                        .ok_or(Error::ResourceUnavailable(
                            ResourceUnavailable::ProviderInvariant {
                                dimension: crate::resource::ResourceClass::OpaqueDependencyResidual,
                            },
                        ))?;
                warn!(?error, "queued remote-candidate application failed");
            }
        }
        Ok(RemoteDescriptionApplyReport {
            queued_candidate_count,
            candidate_failure_count,
        })
    }

    async fn apply_remote_candidate(&self, pending: PendingRemoteCandidate) -> Result<()> {
        // Both callers already hold the exact connector operation lease. This
        // helper remains private so one native candidate application cannot
        // manufacture a nested claim or bypass the outer close fence.
        if !self.ownership.incarnation.is_active() {
            return Err(Error::Transport("connector worker is retired".to_string()));
        }
        let _attempt_operation = pending.attempt.try_enter().ok_or_else(|| {
            Error::Transport("remote candidate belongs to a retired ICE attempt".to_string())
        })?;
        let candidate_matches_attempt = {
            let state = self.remote_candidates.lock();
            state.owns_attempt(&pending.attempt)
                && state.candidate_matches_attempt(&pending.attempt, &pending.candidate)
        };
        if !candidate_matches_attempt {
            self.remote_candidates
                .lock()
                .retire_attempt(&pending.attempt);
            return Err(Error::Transport(
                "remote candidate does not match the exact current ICE attempt".to_string(),
            ));
        }
        let Some(budget) = pending
            ._queue_reservation
            .as_ref()
            .map(|reservation| Arc::clone(&reservation.budget))
        else {
            self.remote_candidates
                .lock()
                .retire_attempt(&pending.attempt);
            return Err(Error::Transport(
                "remote candidate reached production application without queue ownership"
                    .to_string(),
            ));
        };
        if !budget.reserve_application_work() {
            self.remote_candidates
                .lock()
                .retire_attempt(&pending.attempt);
            return Err(Error::Transport(
                "remote-candidate application work exceeded the owner-selected ICE-attempt envelope"
                    .to_string(),
            ));
        }
        let _ice_observation =
            observe_inexact_item(&self.resource_scope, PreAuthResourceFamily::IceWork, 1, 0);
        let PendingRemoteCandidate {
            candidate,
            attempt,
            observation,
            _queue_reservation,
            _elastic_lease,
            _production_queue_lease,
        } = pending;
        let mut elastic_application = match _elastic_lease {
            Some(lease) => lease.begin_apply().map_err(|error| {
                self.remote_candidates.lock().retire_attempt(&attempt);
                match error {
                    ElasticRemoteCandidateApplyError::Provider(unavailable) => {
                        Error::ResourceUnavailable(unavailable)
                    }
                    other => Error::Transport(format!(
                        "remote-candidate application ownership transition failed: {other}"
                    )),
                }
            })?,
            None => {
                self.remote_candidates.lock().retire_attempt(&attempt);
                return Err(Error::Transport(
                    "remote candidate reached production application without elastic ownership"
                        .to_string(),
                ));
            }
        };
        let result = await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.add_ice_candidate(candidate),
        )
        .await
        .ok_or_else(|| Error::Transport("connector worker retired during ICE apply".to_string()))?;
        result?;
        if !attempt.is_active() || !self.remote_candidates.lock().owns_attempt(&attempt) {
            return Err(Error::Transport(
                "remote candidate completed after its ICE attempt retired".to_string(),
            ));
        }
        drop(observation);
        if let Some(mut reservation) = _queue_reservation {
            let retained_bytes = std::mem::size_of::<PendingRemoteCandidateReservation>()
                .checked_add(std::mem::size_of::<[u8; 32]>())
                .ok_or_else(|| {
                    Error::Transport(
                        "applied remote-candidate ownership size overflowed".to_string(),
                    )
                })?;
            let retained_bytes = u64::try_from(retained_bytes).map_err(|_| {
                Error::Transport(
                    "applied remote-candidate ownership size is not representable".to_string(),
                )
            })?;
            let retained_claim = crate::resource::ResourceClaim::try_from_entries([
                (
                    crate::resource::ResourceClass::AccountedMemoryBytes,
                    retained_bytes,
                ),
                (crate::resource::ResourceClass::StorageObject, 2),
                // One ordered-set node, one linked-list node, and the native
                // ICE-agent copy whose byte shape is hidden by webrtc-rs. The
                // residual remains owned until this exact attempt retires.
                (crate::resource::ResourceClass::OpaqueDependencyResidual, 3),
            ])
            .map_err(|error| {
                Error::Transport(format!(
                    "applied remote-candidate ownership claim overflowed: {error}"
                ))
            })?;
            if let Err(error) = elastic_application.transition_after_application(retained_claim) {
                self.remote_candidates.lock().retire_attempt(&attempt);
                return Err(Error::ResourceUnavailable(error));
            }
            reservation.application = Some(elastic_application);
            let mut state = self.remote_candidates.lock();
            if state.current.owns_attempt(&attempt) {
                state.current.retained_reservations.push_back(reservation);
            }
        }
        Ok(())
    }

    pub(crate) fn observe_owned_task(&self) -> ObservationLease {
        observe_inexact_item(&self.resource_scope, PreAuthResourceFamily::Task, 1, 1)
    }

    pub(crate) async fn send_owned(&self, data: Bytes) -> Result<usize> {
        let _operation = self.ownership.enter_operation()?;
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.send(data),
        )
        .await
        .ok_or_else(|| Error::Transport("connector worker retired during send".to_string()))?
    }

    pub(crate) async fn create_offer(&self) -> Result<RTCSessionDescription> {
        let _operation = self.ownership.enter_operation()?;
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.create_offer(),
        )
        .await
        .ok_or_else(|| Error::Transport("connector worker retired during offer".to_string()))?
    }

    pub(crate) async fn create_answer(&self) -> Result<RTCSessionDescription> {
        let _operation = self.ownership.enter_operation()?;
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.create_answer(),
        )
        .await
        .ok_or_else(|| Error::Transport("connector worker retired during answer".to_string()))?
    }

    pub(crate) async fn remote_fingerprint(&self) -> Option<String> {
        let _operation = self.ownership.enter_operation().ok()?;
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.remote_fingerprint(),
        )
        .await
        .flatten()
    }

    pub(crate) async fn local_fingerprint(&self) -> Option<String> {
        let _operation = self.ownership.enter_operation().ok()?;
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.local_fingerprint(),
        )
        .await
        .flatten()
    }

    /// Supply the accepted channel binding for this exact live connector.
    ///
    /// This is the WebRTC adapter's whole contribution to endpoint
    /// authentication: it reads its own two native fingerprints and hands them
    /// over as endpoint-relative components. It selects no role, applies no
    /// canonical ordering, and states nothing about what the pair proves —
    /// those belong to the endpoint authentication owner.
    ///
    /// Fail-closed: a missing local or missing remote fingerprint yields no
    /// binding, so a caller cannot proceed with half a pair.
    pub(crate) async fn endpoint_auth_binding(
        &self,
    ) -> Option<crate::connector::EndpointAuthBinding> {
        let local = self.local_fingerprint().await?;
        let remote = self.remote_fingerprint().await?;
        // Controls only, compiled out of production. Both genuine components
        // have been read by this point and are discarded unread when one is
        // withheld — the refusal is the absence of a component, never a blank
        // or defaulted one, so the constructor below is never reached with an
        // empty string and no fallback value exists anywhere on this path.
        //
        // The gate is exactly the one on the field and the helper below. It has
        // to be: a build where those are absent and this line is present would
        // not compile at all.
        #[cfg(all(test, feature = "transport-lab"))]
        self.refuse_withheld_binding_component_for_test()?;
        crate::connector::EndpointAuthBinding::webrtc_certificate_fingerprints(&local, &remote)
    }

    /// Arm this connector to withhold one binding component. **Controls only.**
    ///
    /// Set-only and monotonic: there is no clearing operation, so an armed
    /// connector stays armed for its whole life and the positive twin has to be
    /// a fixture that was never armed rather than the same one disarmed. That
    /// keeps the twins genuinely independent — a control cannot arrange the
    /// failure, observe it, and then arrange the success on the same connector.
    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) fn withhold_binding_component_for_test(&self, component: WithheldBindingComponent) {
        self.withheld_binding_component
            .store(component.marker(), Ordering::Release);
    }

    /// `None` when a component is withheld, so the caller's `?` refuses.
    ///
    /// Returns `Some(())` and nothing else: this cannot hand back material, only
    /// stop material that was genuinely read from being assembled into a pair.
    #[cfg(all(test, feature = "transport-lab"))]
    fn refuse_withheld_binding_component_for_test(&self) -> Option<()> {
        (self.withheld_binding_component.load(Ordering::Acquire) == 0).then_some(())
    }

    pub(crate) fn awaiting_answer(&self) -> bool {
        self.ownership.incarnation.is_active() && self.session.awaiting_answer()
    }

    /// The role this connector's peer connection was opened for.
    ///
    /// Fixed when the session is constructed and never recomputed. A caller
    /// deciding whether it may offer on an existing connection has to ask the
    /// connection, not re-derive a role from identifiers: identifier ordering
    /// describes which side would *open* a connection that does not exist yet,
    /// and is not a fact about one that does.
    pub(crate) fn role(&self) -> Role {
        self.session.role()
    }

    pub(crate) fn signaling_state(&self) -> RTCSignalingState {
        self.session.signaling_state()
    }

    pub(crate) fn ice_connection_state(&self) -> RTCIceConnectionState {
        self.session.ice_connection_state()
    }

    pub(crate) fn connection_state(&self) -> RTCPeerConnectionState {
        self.session.connection_state()
    }

    pub(crate) async fn restart_ice(&self) -> Result<()> {
        let _operation = self.ownership.enter_operation()?;
        let (retiring_attempt, replacement_attempt) =
            self.remote_candidates.lock().begin_local_ice_restart()?;
        let mut transaction = UncommittedIceTransaction::new(
            Arc::clone(&self.remote_candidates),
            Arc::clone(&self.close_owner),
            Arc::clone(&replacement_attempt),
        );
        retiring_attempt.wait_for_operations().await;
        let native_result = await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.restart_ice(),
        )
        .await
        .ok_or_else(|| {
            Error::Transport("connector worker retired during ICE restart".to_string())
        })?;
        native_result?;
        let commit_result = {
            self.remote_candidates
                .lock()
                .commit_local_ice_restart(&replacement_attempt)
        };
        if let Err(error) = commit_result {
            self.close_owner.start();
            return Err(error);
        }
        transaction.disarm();
        Ok(())
    }

    pub(crate) async fn selected_candidate_pair(
        &self,
    ) -> Option<super::diag::SelectedCandidatePair> {
        let _operation = self.ownership.enter_operation().ok()?;
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.selected_candidate_pair(),
        )
        .await
        .flatten()
    }

    pub(crate) async fn ice_check_snapshot(&self) -> super::diag::IceCheckSnapshot {
        let Ok(_operation) = self.ownership.enter_operation() else {
            return super::diag::IceCheckSnapshot::default();
        };
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.ice_check_snapshot(),
        )
        .await
        .unwrap_or_default()
    }

    pub(crate) fn confirm_data_channel_open(&self) -> DataChannelOpenOwnership {
        let Some(_operation) = self.ownership.operation_fence.try_enter() else {
            return DataChannelOpenOwnership::Rejected;
        };
        match self.ownership.mark_data_channel_open() {
            DataChannelOpenTransition::Connected(capability) => {
                DataChannelOpenOwnership::Connected(EndpointAuthHandoff::new(
                    capability,
                    Arc::clone(&self.ownership.incarnation),
                    Arc::clone(&self.close_owner),
                ))
            }
            DataChannelOpenTransition::AlreadyConnected => {
                DataChannelOpenOwnership::AlreadyConnected
            }
            DataChannelOpenTransition::Rejected => DataChannelOpenOwnership::Rejected,
        }
    }

    /// Fence this connector for an open that must never be authenticated over.
    ///
    /// The caller has already decided that nothing can be proved about this
    /// channel — the connector could not state its endpoint-auth binding — so
    /// the channel must not merely go unpromoted, it must be closed, and the
    /// connector's finite claim must be held until that close is observed to
    /// have succeeded.
    ///
    /// The order is load-bearing and is the whole reason this is a method
    /// rather than two calls at the call site:
    ///
    /// 1. `confirm_data_channel_open()` first. On a live connector this takes
    ///    the connected claim and hands back a handoff; dropping that handoff
    ///    immediately is the *normal* Connected path's `Drop`, which returns the
    ///    claim to the close owner's conservative retention and starts the
    ///    close. The brief promotion exists for exactly that reason — to return
    ///    the claim to connected retention rather than to use the channel. No
    ///    task is built, no capability escapes, and nothing is ever sent: the
    ///    handoff is dropped in the same expression that produced it.
    /// 2. `close_owner.start()` second, unconditionally. `retain_connected_claim`
    ///    already started the close on the path above, so this is an idempotent
    ///    second call there. It is not redundant: when `confirm` answers
    ///    `Rejected` — a connector already stale or retired, so there is no
    ///    handoff to drop — this is the only thing that starts a close owner, and
    ///    the refusal must still start exactly one.
    ///
    /// Never retire before confirming. `retire()` would fence the operation
    /// before `confirm` could take the claim, so the claim would sit outside
    /// the close owner's retention and the connector would be torn down with a
    /// claim nobody was holding conservatively.
    ///
    /// This makes no statement about certificates, exporters, or any keying
    /// material: it is ownership and cleanup only.
    pub(crate) fn refuse_data_channel_open(&self) {
        drop(self.confirm_data_channel_open());
        self.close_owner.start();
    }

    /// Revoke callback acceptance and release every connector-owned candidate.
    pub(crate) fn retire(&self) {
        self.close_owner.retire_local();
    }

    /// Install this connector's native-close hold point. **Controls only.**
    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) fn install_native_close_gate_for_test(&self) -> NativeCloseGateHandle {
        self.close_owner.install_native_close_gate_for_test()
    }

    /// How many connected claims this connector's close owner is holding in
    /// conservative retention right now. **Controls only.**
    ///
    /// Non-zero means the claim has been taken but not released: the close has
    /// not yet reported success, or reported failure and is retaining it. Zero
    /// after a successful close is the release; zero before any promotion is
    /// simply that no claim has moved into retention yet.
    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) fn retained_connected_claims_for_test(&self) -> usize {
        self.close_owner.retained_connected_claims_for_test()
    }

    pub(crate) fn owns_endpoint_auth(&self, task: &crate::endpoint_auth::EndpointAuthTask) -> bool {
        self.ownership.owns_endpoint_auth(task)
    }

    /// Retire local ownership first, then close the native peer connection.
    /// This is the only operation intentionally allowed to continue after
    /// retirement. The local proof is limited to requesting and awaiting the
    /// dependency's idempotent peer-connection close operation.
    pub(crate) async fn retire_and_close(&self) -> Result<()> {
        self.close_owner.wait().await
    }
}

impl Drop for WebRtcConnectorWorker {
    fn drop(&mut self) {
        self.close_owner.start();
    }
}

/// One locally-gathered ICE candidate, in the form the signaling
/// layer needs (matches the webrtc-rs `RTCIceCandidateInit` shape).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LocalIceCandidate {
    pub candidate: String,
    pub sdp_mid: Option<String>,
    pub sdp_mline_index: Option<u16>,
    pub username_fragment: Option<String>,
}

impl LocalIceCandidate {
    fn into_init(self) -> RTCIceCandidateInit {
        RTCIceCandidateInit {
            candidate: self.candidate,
            sdp_mid: self.sdp_mid,
            sdp_mline_index: self.sdp_mline_index,
            username_fragment: self.username_fragment,
        }
    }
}

/// Engine-owned WebRTC factory. Construct once per [`crate::Mesh`]
/// instance; cheap to clone.
#[derive(Clone)]
pub struct Transport {
    api: Arc<webrtc::api::API>,
    runtime: crate::runtime::RuntimeIncarnation,
    ice_transport_policy: RTCIceTransportPolicy,
    connector_resource_scope: Option<MeshConnectorResourceScope>,
    webrtc_profile: Option<WebRtcConnectorProfile>,
    #[cfg(test)]
    construction_hook: Option<Arc<ConstructionTestHook>>,
}

struct PeerOpenOwnership {
    resource_scope: Option<PeerConnectionResourceScope>,
    work_resource_scope: Option<ConnectorWorkResourceScope>,
    attempt_liveness: Option<AttemptLiveness>,
    candidate_promoted: Arc<AtomicBool>,
    callback_gate: Arc<WebRtcConnectorIncarnation>,
    callback_policy: ConnectorCallbackPolicy,
    operation_fence: Arc<ConnectorOperationFence>,
    /// The application's registered codecs, carried through to the session so
    /// a flow set can resolve framing without re-reading the connector profile.
    ///
    /// Unlike its two neighbours this is not `Copy`, so it is cloned once here
    /// rather than being read out of the profile at each use.
    realtime_profile: Option<RealtimeProfile>,
    close_owner: Option<Arc<ConnectorCloseOwner>>,
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum ConstructionPause {
    BeforeNativeConstructor,
    AfterNativeAllocation,
    AfterNativeAllocationWithCloseError,
    AfterResultDelivery,
    FailAfterNativeAllocation,
}

#[cfg(test)]
struct ConstructionTestHook {
    pause: ConstructionPause,
    created: Semaphore,
    resume: Semaphore,
    peer_connection: SyncMutex<Option<Arc<RTCPeerConnection>>>,
}

#[cfg(test)]
impl ConstructionTestHook {
    fn new(pause: ConstructionPause) -> Arc<Self> {
        Arc::new(Self {
            pause,
            created: Semaphore::new(0),
            resume: Semaphore::new(0),
            peer_connection: SyncMutex::new(None),
        })
    }

    async fn pause_after_native_allocation(&self, pc: &Arc<RTCPeerConnection>) {
        if self.pause == ConstructionPause::FailAfterNativeAllocation {
            *self.peer_connection.lock() = Some(Arc::clone(pc));
            panic!("injected connector construction task failure");
        }
        if matches!(
            self.pause,
            ConstructionPause::AfterNativeAllocation
                | ConstructionPause::AfterNativeAllocationWithCloseError
        ) {
            self.pause_at(pc).await;
        }
    }

    async fn pause_before_native_constructor(&self) {
        if self.pause != ConstructionPause::BeforeNativeConstructor {
            return;
        }
        self.created.add_permits(1);
        let permit = self
            .resume
            .acquire()
            .await
            .expect("construction test hook remains open");
        permit.forget();
    }

    async fn pause_after_result_delivery(&self, pc: &Arc<RTCPeerConnection>) {
        if self.pause == ConstructionPause::AfterResultDelivery {
            self.pause_at(pc).await;
        }
    }

    async fn pause_at(&self, pc: &Arc<RTCPeerConnection>) {
        *self.peer_connection.lock() = Some(Arc::clone(pc));
        self.created.add_permits(1);
        let permit = self
            .resume
            .acquire()
            .await
            .expect("construction test hook remains open");
        permit.forget();
    }

    fn inject_native_close_error(&self) -> bool {
        self.pause == ConstructionPause::AfterNativeAllocationWithCloseError
    }
}

/// Private construction result that retains the child reservation until the
/// outer connector owner accepts it. If the caller is cancelled after result
/// delivery, dropping this value closes the native peer before releasing the
/// candidate claim.
struct ConstructedConnectorResult {
    session: Option<PeerSession>,
    events: Option<TransportEventReceiver>,
    close_owner: Arc<ConnectorCloseOwner>,
}

/// Cancels connector construction when the awaiting caller is dropped. Any
/// native object already returned to the task is then retired by its
/// `PeerConstructionGuard` during future cancellation.
struct AbortConstructionOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortConstructionOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Starts the one connector cleanup owner if the outer construction future is
/// cancelled or fails before the admitted worker takes ownership.
struct StartConnectorCleanupOnDrop(Option<Arc<ConnectorCloseOwner>>);

impl StartConnectorCleanupOnDrop {
    fn new(owner: Arc<ConnectorCloseOwner>) -> Self {
        Self(Some(owner))
    }

    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for StartConnectorCleanupOnDrop {
    fn drop(&mut self) {
        if let Some(owner) = self.0.take() {
            owner.start();
        }
    }
}

/// Retains an exact failed connector claim if dependency construction is
/// cancelled or panics after native allocation may have begun but before a
/// close port is returned. Successful return disarms the guard before the
/// native object is handed to its ordinary construction owner.
struct PendingNativeConstructorGuard(Option<Arc<ConnectorCloseOwner>>);

impl PendingNativeConstructorGuard {
    fn new(owner: Option<Arc<ConnectorCloseOwner>>) -> Self {
        Self(owner)
    }

    fn disarm(&mut self) {
        self.0 = None;
    }

    fn fail(mut self, reason: String) {
        if let Some(owner) = self.0.take() {
            owner.finish_native_allocation_without_close_port(reason);
        }
    }
}

impl Drop for PendingNativeConstructorGuard {
    fn drop(&mut self) {
        if let Some(owner) = self.0.take() {
            owner.finish_native_allocation_without_close_port(
                "native construction was cancelled before returning a close port".to_string(),
            );
        }
    }
}

impl ConstructedConnectorResult {
    fn new(
        session: PeerSession,
        events: TransportEventReceiver,
        close_owner: Arc<ConnectorCloseOwner>,
    ) -> Self {
        Self {
            session: Some(session),
            events: Some(events),
            close_owner,
        }
    }

    #[cfg(test)]
    fn peer_connection(&self) -> &Arc<RTCPeerConnection> {
        &self
            .session
            .as_ref()
            .expect("constructed result retains its session")
            .pc
    }

    fn into_parts(
        mut self,
    ) -> (
        PeerSession,
        TransportEventReceiver,
        Arc<ConnectorCloseOwner>,
    ) {
        (
            self.session.take().expect("constructed session exists"),
            self.events.take().expect("constructed event owner exists"),
            Arc::clone(&self.close_owner),
        )
    }
}

impl Drop for ConstructedConnectorResult {
    fn drop(&mut self) {
        let (Some(session), Some(events)) = (self.session.take(), self.events.take()) else {
            return;
        };
        drop(session);
        drop(events);
        self.close_owner.start();
    }
}

/// The application's registered codecs, translated into what the transport
/// library wants.
///
/// A total translation, not a selection: every registration is passed
/// through, in the order supplied. Deployed H.264 is five entries agreeing on
/// MIME, clock rate and channels and differing only in payload type and
/// fmtp — all five must reach the media engine, because the offer advertises
/// all five and the answerer picks one. Registering fewer would silently
/// narrow what a peer can choose.
///
/// Nothing here reads a MIME name. This is the whole of core's knowledge of
/// the application's codecs: copy the fields across and register them.
fn realtime_media_codecs(
    profile: &RealtimeProfile,
) -> Vec<(
    webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecParameters,
    RTPCodecType,
)> {
    use webrtc::rtp_transceiver::rtp_codec::{RTCRtpCodecCapability, RTCRtpCodecParameters};
    use webrtc::rtp_transceiver::RTCPFeedback;

    profile
        .codecs()
        .iter()
        .map(|codec| {
            (
                RTCRtpCodecParameters {
                    capability: RTCRtpCodecCapability {
                        mime_type: codec.mime.clone(),
                        clock_rate: codec.clock_rate,
                        channels: codec.channels,
                        sdp_fmtp_line: codec.fmtp.clone(),
                        rtcp_feedback: codec
                            .rtcp_feedback
                            .iter()
                            .map(|feedback| RTCPFeedback {
                                typ: feedback.mechanism.clone(),
                                parameter: feedback.parameter.clone(),
                            })
                            .collect(),
                    },
                    payload_type: codec.payload_type,
                    ..Default::default()
                },
                // `codec.kind` is already a `WebRtcRtpKind`; the `from` that
                // used to wrap it dated from when the two sides of this match
                // were different types and had become an identity conversion.
                // Matching the value directly keeps the total map — every
                // variant still names its `RTPCodecType`, so adding one is
                // still a compile error here — without the round trip.
                match codec.kind {
                    WebRtcRtpKind::Audio => RTPCodecType::Audio,
                    WebRtcRtpKind::Video => RTPCodecType::Video,
                },
            )
        })
        .collect()
}

fn build_realtime_media_api(profile: &RealtimeProfile) -> Result<webrtc::api::API> {
    let mut media_engine = MediaEngine::default();
    for (codec, kind) in realtime_media_codecs(profile) {
        media_engine.register_codec(codec, kind).map_err(|error| {
            Error::Transport(format!("register application real-time codec: {error}"))
        })?;
    }
    let mut registry = Registry::new();
    registry = register_default_interceptors(registry, &mut media_engine)
        .map_err(|error| Error::Transport(format!("register real-time interceptors: {error}")))?;
    let mut setting_engine = SettingEngine::default();
    setting_engine.set_interface_filter(Box::new(|name: &str| !is_virtual_interface(name)));
    setting_engine.set_ip_filter(Box::new(|ip: std::net::IpAddr| !is_link_local_ip(&ip)));
    Ok(APIBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .with_setting_engine(setting_engine)
        .build())
}

impl Transport {
    /// Build a fresh transport with the default media engine and
    /// interceptors. The webrtc-rs defaults cover everything we
    /// need for data-channel-only operation.
    pub fn new() -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        let mut registry = Registry::new();
        registry = register_default_interceptors(registry, &mut media_engine)
            .map_err(|e| Error::Transport(format!("register interceptors: {e}")))?;

        // Trim ICE candidate gathering to interfaces that can actually
        // carry peer traffic. Without this the agent gathers a host
        // candidate on every up interface — including Docker bridges and
        // other virtual nets whose `172.x.0.1`-style gateway addresses no
        // remote peer can ever reach — which bloats the candidate set and
        // drags out the connectivity-check phase. The Tailscale tunnel is
        // intentionally *kept* (it's a real path); only the dead virtual
        // interfaces in `VIRTUAL_IFACE_PREFIXES` are dropped.
        let mut setting_engine = SettingEngine::default();
        setting_engine.set_interface_filter(Box::new(|name: &str| {
            let keep = !is_virtual_interface(name);
            // Instrumentation: a one-liner per excluded interface so a log
            // (with our crate at DEBUG) confirms exactly which interfaces
            // the filter pruned — the direct check that the candidate
            // explosion is actually being trimmed on a given box.
            if !keep {
                debug!(
                    interface = name,
                    "ICE: excluding virtual interface from candidate gathering"
                );
            }
            keep
        }));
        // Drop link-local addresses (v6 `fe80::/10`, v4 `169.254/16`) from
        // gathering. They can't be bound without a scope/zone id, so the
        // agent's bind fails on every one — a dozen per gather on a typical
        // macOS box — flooding the log with `could not listen udp fe80::… :
        // Can't assign requested address` while producing zero usable
        // candidates. Returning `false` excludes the address; routable host
        // addresses (global v4/v6, RFC-1918, ULA `fc00::/7`) and the
        // STUN/TURN base addresses are all kept. Loopback is already
        // excluded upstream unless explicitly enabled.
        setting_engine.set_ip_filter(Box::new(|ip: std::net::IpAddr| !is_link_local_ip(&ip)));

        let api = APIBuilder::new()
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .with_setting_engine(setting_engine)
            .build();
        // One startup line. The excluded prefixes live in the structured
        // field for anyone who needs them; the message stays a clean
        // one-liner rather than dumping the whole array into the stream.
        info!(
            excluded = VIRTUAL_IFACE_PREFIXES.len(),
            "ICE interface filter active — Docker/virtual interfaces excluded from candidate gathering"
        );
        Ok(Self {
            api: Arc::new(api),
            runtime: crate::runtime::RuntimeIncarnation::new(),
            ice_transport_policy: RTCIceTransportPolicy::All,
            connector_resource_scope: None,
            webrtc_profile: None,
            #[cfg(test)]
            construction_hook: None,
        })
    }

    /// Bind this transport to an explicitly configured process resource owner.
    /// Connector construction is refused until this port is present.
    pub(crate) fn with_connector_resource_scope(
        mut self,
        scope: MeshConnectorResourceScope,
        profile: WebRtcConnectorProfile,
    ) -> Self {
        self.connector_resource_scope = Some(scope);
        self.webrtc_profile = Some(profile);
        self
    }

    /// Bind this transport to the one resource provider held by the process
    /// root. A second Mesh runtime shares the same provider grant and scope
    /// creation cannot multiply capacity.
    pub fn with_connector_resource_policy(
        self,
        policy: WebRtcConnectorCapablePolicy,
    ) -> Result<Self> {
        let root = ProcessResourceRoot::global();
        root.install_resource_provider(policy.resources())?;
        let scope = root.issue_mesh_connector_scope()?;
        let profile = policy.webrtc().clone();
        // Codec registration is a property of the media engine a peer
        // connection is built from, so the application's profile has to be
        // installed here, before any connection exists. There is no later
        // point at which a codec can be added, and therefore no point at
        // which core could fall back to a list of its own.
        let installed = match profile.realtime() {
            Some(realtime) => self.with_realtime_media_api(realtime)?,
            None => self,
        };
        Ok(installed.with_connector_resource_scope(scope, profile))
    }

    /// Replace the data-only media engine with one carrying exactly the
    /// codecs the application registered.
    ///
    /// Exactly those and no others: `MediaEngine::default()` starts empty, so
    /// what the profile lists is the complete negotiable set. A codec core
    /// was never told about cannot be offered, which is what makes inbound
    /// admission answerable by "did the application register this family"
    /// rather than by recognising a name.
    fn with_realtime_media_api(mut self, profile: &RealtimeProfile) -> Result<Self> {
        self.api = Arc::new(build_realtime_media_api(profile)?);
        Ok(self)
    }

    /// Install the Session Broker for this transport's runtime, if the process
    /// owner selected a resource provider.
    ///
    /// `None` when no provider is installed, and that is fail-closed by
    /// construction: without a provider there is no post-authentication capacity
    /// to reserve, so no session can be promoted and no application operation
    /// can run. A connector-capable policy is what installs one.
    ///
    /// The runtime is taken from this transport rather than minted fresh: it
    /// must be the same incarnation the connector's channel capabilities are
    /// bound to, or every promotion would refuse on runtime mismatch.
    pub(crate) fn session_broker(&self) -> Option<crate::runtime::session_broker::SessionBroker> {
        self.connector_resource_scope.as_ref().map(|scope| {
            crate::runtime::session_broker::SessionBroker::new(self.runtime.clone(), scope.clone())
        })
    }

    pub fn connector_resource_report(&self) -> Option<ConnectorResourceOwnerReport> {
        self.connector_resource_scope
            .as_ref()
            .map(|scope| scope.process_report())
    }

    pub fn mesh_connector_resource_report(&self) -> Option<MeshConnectorResourceReport> {
        self.connector_resource_scope
            .as_ref()
            .map(MeshConnectorResourceScope::report)
    }

    /// Build a lab transport that rejects host and server-reflexive candidate
    /// pairs. This is available only with `transport-lab` so production callers
    /// cannot accidentally make relay-only behavior the default.
    #[cfg(feature = "transport-lab")]
    pub fn new_relay_only_for_lab() -> Result<Self> {
        let mut transport = Self::new()?;
        transport.ice_transport_policy = RTCIceTransportPolicy::Relay;
        Ok(transport)
    }

    /// Open a new [`PeerSession`] for the given peer with the
    /// supplied STUN/TURN configuration. The session immediately
    /// installs all webrtc callbacks; events flow out the returned
    /// receiver until the session is dropped.
    #[cfg(any(test, feature = "transport-lab"))]
    pub async fn open_peer(
        &self,
        role: Role,
        stun: &[crate::config::StunServer],
        turn: &[crate::config::TurnServer],
        callback_policy: ConnectorCallbackPolicy,
    ) -> Result<(PeerSession, TransportEventReceiver)> {
        let mut config = build_rtc_configuration(stun, turn);
        config.ice_transport_policy = self.ice_transport_policy;
        self.open_peer_with_config(role, config, callback_policy)
            .await
    }

    /// Open the engine-owned connector wrapper around the existing WebRTC
    /// machinery. Arc 03 keeps the old transport behavior inside this owner.
    pub(crate) async fn open_connector_peer(
        &self,
        role: Role,
        stun: &[crate::config::StunServer],
        turn: &[crate::config::TurnServer],
        resource_scope: PeerConnectionResourceScope,
    ) -> Result<(WebRtcConnectorWorker, WebRtcConnectorEventReceiver)> {
        let resource_owner = self
            .connector_resource_scope
            .clone()
            .ok_or(Error::ConnectorPolicyRequired)?;
        // Borrowed, not moved: the profile stopped being `Copy` when it took
        // on the application's codec registrations, and it is read again after
        // the construction task is spawned.
        let webrtc_profile = self
            .webrtc_profile
            .as_ref()
            .ok_or(Error::ConnectorPolicyRequired)?;
        let transport_observation = observe_inexact_item(
            &resource_scope,
            PreAuthResourceFamily::TransportObject,
            1,
            0,
        );
        let mut config = build_rtc_configuration(stun, turn);
        config.ice_transport_policy = self.ice_transport_policy;
        let (permit, attempt_lifetime, claim) =
            admit_single_connector_candidate(self.runtime.clone(), resource_owner.clone());
        let (mut candidate, reclaim_subscription) = permit
            .reserve_connector_candidate_cooperatively(claim)
            .await?
            .ok_or_else(|| {
                Error::Transport("connector attempt retired before admission".to_string())
            })?;
        let cleanup_capability = candidate
            .issue_cleanup_capability()
            .map_err(|error| Error::Transport(error.to_string()))?;
        let liveness = candidate.liveness();
        let work_resource_scope = candidate.work_resource_scope();
        let construction_work_resource_scope = work_resource_scope.clone();
        let transport = self.clone();
        let construction_scope = resource_scope.clone();
        let candidate_promoted = Arc::new(AtomicBool::new(false));
        let construction_candidate_promoted = Arc::clone(&candidate_promoted);
        let construction_liveness = liveness.clone();
        let result_liveness = liveness.clone();
        let incarnation = Arc::new(WebRtcConnectorIncarnation::new());
        let construction_incarnation = Arc::clone(&incarnation);
        let operation_fence = Arc::new(ConnectorOperationFence::default());
        let ownership = ConnectorOwnership::admitted(
            candidate,
            Arc::clone(&operation_fence),
            work_resource_scope.clone(),
            Arc::clone(&candidate_promoted),
            Arc::clone(&incarnation),
        );
        let close_owner = ConnectorCloseOwner::new(
            ownership.clone(),
            resource_owner.clone(),
            cleanup_capability,
        );
        let mut outer_cleanup = StartConnectorCleanupOnDrop::new(Arc::clone(&close_owner));
        let construction_close_owner = Arc::clone(&close_owner);
        let construction_reclaim = reclaim_subscription.clone();
        let reclaim_scope_id = work_resource_scope.scope_id();
        let (construction_tx, construction_rx) = oneshot::channel();
        // The profile answer the construction task needs, taken before it is
        // spawned. It is `Copy`, so the task owns it and the profile itself
        // never crosses into the task.
        let construction_callback_policy = webrtc_profile.callbacks();
        // Cloned rather than taken by reference: the profile itself still never
        // crosses into the task, and the codec list is registration data the
        // session keeps for the lifetime of the connection anyway.
        let construction_realtime_profile = webrtc_profile.realtime().cloned();
        let construction_task = AbortConstructionOnDrop(tokio::spawn(async move {
            let construction = transport.open_peer_with_config_observed(
                role,
                config,
                PeerOpenOwnership {
                    resource_scope: Some(construction_scope),
                    work_resource_scope: Some(construction_work_resource_scope),
                    attempt_liveness: Some(construction_liveness),
                    candidate_promoted: construction_candidate_promoted,
                    callback_gate: construction_incarnation,
                    callback_policy: construction_callback_policy,
                    operation_fence,
                    realtime_profile: construction_realtime_profile,
                    close_owner: Some(Arc::clone(&construction_close_owner)),
                },
            );
            tokio::pin!(construction);
            let result = tokio::select! {
                result = &mut construction => result,
                _ = construction_reclaim.requested() => {
                    Err(Error::ResourceUnavailable(
                        ResourceUnavailable::ReclaimRequested {
                            scope_id: reclaim_scope_id,
                        },
                    ))
                }
            };
            match result {
                Ok((session, events)) if result_liveness.is_active() => {
                    let _ = construction_tx.send(Ok(ConstructedConnectorResult::new(
                        session,
                        events,
                        construction_close_owner,
                    )));
                }
                Ok((session, events)) => {
                    drop(events);
                    drop(session);
                    construction_close_owner.start();
                    let _ = construction_tx.send(Err(Error::Transport(
                        "connector attempt retired during construction".to_string(),
                    )));
                }
                Err(error) => {
                    let _ = construction_tx.send(Err(error));
                }
            }
        }));
        let constructed = construction_rx
            .await
            .map_err(|_| Error::Transport("connector construction owner stopped".to_string()))??;
        drop(construction_task);
        #[cfg(test)]
        if let Some(hook) = self.construction_hook.as_ref() {
            hook.pause_after_result_delivery(constructed.peer_connection())
                .await;
        }
        let (session, events, constructed_close_owner) = constructed.into_parts();
        if !Arc::ptr_eq(&constructed_close_owner, &close_owner) {
            close_owner.start();
            constructed_close_owner.start();
            return Err(Error::Transport(
                "connector construction returned a different close owner".to_string(),
            ));
        }
        let admitted = WebRtcConnectorWorker::admitted(
            session,
            events,
            AdmittedConnectorOwnership {
                ownership,
                attempt_lifetime,
                attempt_liveness: liveness,
                close_owner,
                resource_scope,
                work_resource_scope,
                transport_observation,
                remote_candidate_policy: webrtc_profile.remote_candidates(),
                reclaim: reclaim_subscription,
            },
        );
        if admitted.is_ok() {
            outer_cleanup.disarm();
        }
        admitted
    }

    /// Lower-level entry point that takes an explicit
    /// `RTCConfiguration`. Tests can use this to short-circuit
    /// the user-config path.
    #[cfg(any(test, feature = "transport-lab"))]
    pub async fn open_peer_with_config(
        &self,
        role: Role,
        config: RTCConfiguration,
        callback_policy: ConnectorCallbackPolicy,
    ) -> Result<(PeerSession, TransportEventReceiver)> {
        self.open_peer_with_config_observed(
            role,
            config,
            PeerOpenOwnership {
                resource_scope: None,
                work_resource_scope: None,
                attempt_liveness: None,
                candidate_promoted: Arc::new(AtomicBool::new(true)),
                callback_gate: Arc::new(WebRtcConnectorIncarnation::new()),
                callback_policy,
                operation_fence: Arc::new(ConnectorOperationFence::default()),
                realtime_profile: None,
                close_owner: None,
            },
        )
        .await
    }

    async fn open_peer_with_config_observed(
        &self,
        role: Role,
        config: RTCConfiguration,
        ownership: PeerOpenOwnership,
    ) -> Result<(PeerSession, TransportEventReceiver)> {
        let PeerOpenOwnership {
            resource_scope,
            work_resource_scope,
            attempt_liveness,
            candidate_promoted,
            callback_gate,
            callback_policy,
            operation_fence,
            realtime_profile,
            close_owner,
        } = ownership;
        let api = Arc::clone(&self.api);
        if let Some(owner) = close_owner.as_ref() {
            owner.mark_native_allocation_started();
        }
        let mut pending_native_constructor =
            PendingNativeConstructorGuard::new(close_owner.as_ref().map(Arc::clone));
        #[cfg(test)]
        if let Some(hook) = self.construction_hook.as_ref() {
            hook.pause_before_native_constructor().await;
        }
        let callback_close_owner = close_owner.as_ref().map(Arc::downgrade);
        let pc = match api.new_peer_connection(config).await {
            Ok(pc) => {
                pending_native_constructor.disarm();
                pc
            }
            Err(error) => {
                pending_native_constructor.fail(format!(
                    "native construction returned without a close port: {error}"
                ));
                return Err(Error::Transport(format!("new_peer_connection: {error}")));
            }
        };
        let pc = Arc::new(pc);
        let attached_close_owner = match close_owner {
            Some(owner)
                if {
                    #[cfg(test)]
                    if self
                        .construction_hook
                        .as_ref()
                        .is_some_and(|hook| hook.inject_native_close_error())
                    {
                        owner.attach_native_port(Arc::new(WebRtcNativeCloseErrorPort {
                            peer: Arc::clone(&pc),
                        }))
                    } else {
                        owner.attach_native(Arc::clone(&pc))
                    }
                    #[cfg(not(test))]
                    {
                        owner.attach_native(Arc::clone(&pc))
                    }
                } =>
            {
                Some(owner)
            }
            Some(owner) => {
                let mut rejected =
                    PeerConstructionGuard::new(Arc::clone(&pc), Arc::clone(&callback_gate), None);
                rejected.close().await;
                owner.start();
                return Err(Error::Transport(
                    "native peer installation into close owner was refused".to_string(),
                ));
            }
            None => None,
        };
        let mut construction = PeerConstructionGuard::new(
            Arc::clone(&pc),
            Arc::clone(&callback_gate),
            attached_close_owner,
        );
        let result = async {
            #[cfg(test)]
            if let Some(hook) = self.construction_hook.as_ref() {
                hook.pause_after_native_allocation(&pc).await;
            }

            let callback_producer = match work_resource_scope.clone() {
                Some(scope) => CallbackProducerOwner::new(
                    scope,
                    crate::resource::ResourceAuthorityClass::Speculative,
                    CallbackProducerClaims::structural_only(),
                ),
                #[cfg(any(test, feature = "transport-lab"))]
                None => CallbackProducerOwner::for_local_lab_policy(callback_policy).map_err(
                    |error| {
                        Error::Transport(format!(
                            "raw transport callback resource policy is unavailable: {error:?}"
                        ))
                    },
                )?,
                #[cfg(not(any(test, feature = "transport-lab")))]
                None => return Err(Error::ConnectorPolicyRequired),
            };
            let callback_ready = Arc::new(tokio::sync::Notify::new());
            let local_mailboxes = callback_policy.local_mailboxes();
            let control = callback_producer
                .create_mailbox(
                    ConnectorCallbackClass::Control,
                    local_mailboxes.map(|mailboxes| mailboxes.control()),
                    Arc::clone(&callback_ready),
                )
                .map_err(|error| {
                    callback_admission_error(
                        "control callback mailbox resource admission failed",
                        error,
                    )
                })?;
            let endpoint_data = callback_producer
                .create_mailbox(
                    ConnectorCallbackClass::EndpointData,
                    local_mailboxes.map(|mailboxes| mailboxes.endpoint_data()),
                    Arc::clone(&callback_ready),
                )
                .map_err(|error| {
                    callback_admission_error(
                        "endpoint callback mailbox resource admission failed",
                        error,
                    )
                })?;
            let reserved_open_work =
                callback_producer
                    .reserve_lifecycle_delivery()
                    .map_err(|error| {
                        callback_admission_error(
                            "connector open callback resource admission failed",
                            error,
                        )
                    })?;
            let reserved_close_work =
                callback_producer
                    .reserve_lifecycle_delivery()
                    .map_err(|error| {
                        callback_admission_error(
                            "connector close callback resource admission failed",
                            error,
                        )
                    })?;
            let (realtime_resources, realtime_local_ceiling) = match callback_policy.realtime() {
                RealtimeConnectorPolicy::Disabled => (None, None),
                RealtimeConnectorPolicy::Enabled(local_ceiling) => {
                    (work_resource_scope.clone(), local_ceiling)
                }
            };
            let realtime_flows =
                RealtimeFlowRegistry::new(realtime_resources, realtime_local_ceiling);
            // The application's codecs become a shared, leased record here —
            // once, against this connector's own work scope — and every session
            // promoted on this connector then holds a pointer to it. Each
            // promotion used to deep-clone the codec vector, both `String`s per
            // codec and every feedback entry, and pay for none of it.
            //
            // Refusal is ordinary and fails the connector rather than the
            // session: registering codecs whose retention nothing accounted for
            // is the state this exists to make unreachable.
            let realtime_profile = match realtime_profile {
                Some(profile) => Some(
                    session_flow::LeasedRealtimeProfile::mint(profile, &realtime_flows).map_err(
                        |_| {
                            Error::Transport(
                                "connector resources refused the real-time profile".to_string(),
                            )
                        },
                    )?,
                ),
                None => None,
            };
            let lifecycle = Arc::new(ConnectorLifecycleOwner::with_reserved_lifecycle_work(
                reserved_open_work,
                reserved_close_work,
            ));
            let event_sink = ConnectorEventSink {
                events: ConnectorEventMailboxes {
                    control: Arc::clone(&control),
                    endpoint_data: Arc::clone(&endpoint_data),
                    lifecycle: Arc::clone(&lifecycle),
                    #[cfg(test)]
                    callback_producer: callback_producer.clone(),
                },
                realtime_flows: Arc::clone(&realtime_flows),
                resource_scope: resource_scope.clone(),
                attempt_liveness,
                candidate_promoted,
                callback_gate: Arc::clone(&callback_gate),
                callback_violation_reported: Arc::new(AtomicBool::new(false)),
                callback_policy,
                callback_producer,
                operation_fence: Arc::clone(&operation_fence),
                close_owner: callback_close_owner,
            };
            let data_channel = Arc::new(SyncMutex::new(None::<Arc<RTCDataChannel>>));

            // Built before the callbacks so the `on_track` handler and the
            // session share one object rather than two that could diverge.
            let realtime_tracks = Arc::new(RealtimeSessionTracks::default());

            register_callbacks(
                &pc,
                &event_sink,
                &data_channel,
                resource_scope.clone(),
                Arc::clone(&realtime_tracks),
            );

            // Offerer creates the data channel synchronously so the
            // resulting SDP includes it. Answerer waits for the
            // `on_data_channel` callback that fires when the peer's
            // offer is applied.
            if role == Role::Offerer {
                let _operation = operation_fence.try_enter().ok_or_else(|| {
                    Error::Transport(
                        "connector close fence committed during data-channel construction"
                            .to_string(),
                    )
                })?;
                let dc = pc
                    .create_data_channel(
                        APP_DATA_CHANNEL_LABEL,
                        Some(RTCDataChannelInit {
                            ordered: Some(true),
                            ..Default::default()
                        }),
                    )
                    .await
                    .map_err(|e| Error::Transport(format!("create_data_channel: {e}")))?;
                install_data_channel_handlers(
                    dc.clone(),
                    event_sink.clone(),
                    resource_scope.as_ref(),
                );
                *data_channel.lock() = Some(dc);
            }

            let session = PeerSession {
                pc,
                data_channel,
                realtime_profile,
                realtime_tracks,
                _events_tx: event_sink,
                callback_gate,
                role,
                _resource_scope: resource_scope,
                _work_resource_scope: work_resource_scope,
            };
            Ok((
                session,
                TransportEventReceiver {
                    control,
                    endpoint_data,
                    lifecycle,
                    lifecycle_closed: false,
                    callback_ready,
                    callback_failed: false,
                    realtime_flows,
                    scheduler: ConnectorCallbackScheduler::new(callback_policy),
                    control_cursor: ConnectorControlSourceCursor::default(),
                },
            ))
        }
        .await;

        match result {
            Ok(result) => {
                construction.disarm();
                Ok(result)
            }
            Err(error) => {
                construction.close().await;
                Err(error)
            }
        }
    }
}

/// Closes a native peer connection when construction errors or its owned task
/// is cancelled after the dependency returned the object but before the
/// complete `PeerSession` can be handed to its connector owner.
struct PeerConstructionGuard {
    pc: Option<Arc<RTCPeerConnection>>,
    callback_gate: Arc<WebRtcConnectorIncarnation>,
    close_owner: Option<Arc<ConnectorCloseOwner>>,
}

impl PeerConstructionGuard {
    fn new(
        pc: Arc<RTCPeerConnection>,
        callback_gate: Arc<WebRtcConnectorIncarnation>,
        close_owner: Option<Arc<ConnectorCloseOwner>>,
    ) -> Self {
        Self {
            pc: Some(pc),
            callback_gate,
            close_owner,
        }
    }

    fn disarm(&mut self) {
        self.pc = None;
        self.close_owner = None;
    }

    async fn close(&mut self) {
        if let Some(owner) = self.close_owner.as_ref() {
            self.pc = None;
            let _ = owner.wait().await;
            return;
        }
        let Some(pc) = self.pc.take() else {
            return;
        };
        self.callback_gate.retire();
        let _ = pc.close().await;
    }
}

impl Drop for PeerConstructionGuard {
    fn drop(&mut self) {
        if let Some(owner) = self.close_owner.as_ref() {
            self.pc = None;
            owner.start();
            return;
        }
        let Some(pc) = self.pc.take() else {
            return;
        };
        self.callback_gate.retire();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = pc.close().await;
            });
            return;
        }
        let _ = std::thread::Builder::new()
            .name("myownmesh-webrtc-construction-close".to_string())
            .spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return;
                };
                runtime.block_on(async move {
                    let _ = pc.close().await;
                });
            });
    }
}

fn register_callbacks(
    pc: &Arc<RTCPeerConnection>,
    events_tx: &ConnectorEventSink,
    data_channel: &Arc<SyncMutex<Option<Arc<RTCDataChannel>>>>,
    resource_scope: Option<PeerConnectionResourceScope>,
    realtime_tracks: Arc<RealtimeSessionTracks>,
) {
    // Local ICE candidate gathered — ship via signaling.
    {
        let tx = events_tx.clone();
        let callback_observation = observe_inexact_item_if(
            resource_scope.as_ref(),
            PreAuthResourceFamily::Callback,
            1,
            0,
        );
        pc.on_ice_candidate(Box::new(move |cand| {
            let _keep_callback_observation = &callback_observation;
            let mut callback_work =
                match tx.begin_native_callback_operation(ConnectorCallbackClass::Control) {
                    Ok(work) => work,
                    Err(error) => {
                        warn!(
                            ?error,
                            "refusing native ICE callback before candidate conversion"
                        );
                        tx.retire_after_callback_violation();
                        return Box::pin(async {});
                    }
                };
            let candidate = match cand {
                Some(candidate) => match candidate.to_json() {
                    Ok(init) => Some(LocalIceCandidate {
                        candidate: init.candidate,
                        sdp_mid: init.sdp_mid,
                        sdp_mline_index: init.sdp_mline_index,
                        username_fragment: init.username_fragment,
                    }),
                    Err(error) => {
                        warn!("ice_candidate to_json: {error}");
                        tx.retire_after_callback_violation();
                        return Box::pin(async {});
                    }
                },
                None => None,
            };
            let Some((payload_bytes, retained_slack)) = candidate_callback_sizes(&candidate) else {
                tx.retire_after_callback_violation();
                return Box::pin(async {});
            };
            if let Err(error) = tx.callback_producer.account_executing_payload(
                &mut callback_work,
                payload_bytes,
                retained_slack,
            ) {
                warn!(
                    ?error,
                    "refusing converted native ICE callback under resource pressure"
                );
                tx.retire_after_callback_violation();
                return Box::pin(async {});
            }
            let tx = tx.clone();
            Box::pin(async move {
                let _callback_work = callback_work;
                tx.emit(TransportEvent::LocalIceCandidate(candidate)).await;
            })
        }));
    }

    // ICE connection state changed.
    {
        let tx = events_tx.clone();
        let callback_observation = observe_inexact_item_if(
            resource_scope.as_ref(),
            PreAuthResourceFamily::Callback,
            1,
            0,
        );
        pc.on_ice_connection_state_change(Box::new(move |state| {
            let _keep_callback_observation = &callback_observation;
            let callback_work =
                match tx.begin_native_callback_operation(ConnectorCallbackClass::Control) {
                    Ok(work) => work,
                    Err(error) => {
                        warn!(
                            ?error,
                            "refusing native ICE-state callback under resource pressure"
                        );
                        tx.retire_after_callback_violation();
                        return Box::pin(async {});
                    }
                };
            let tx = tx.clone();
            Box::pin(async move {
                let _callback_work = callback_work;
                tx.emit(TransportEvent::IceConnectionStateChanged(state))
                    .await;
            })
        }));
    }

    // PeerConnection state changed.
    {
        let tx = events_tx.clone();
        let callback_observation = observe_inexact_item_if(
            resource_scope.as_ref(),
            PreAuthResourceFamily::Callback,
            1,
            0,
        );
        pc.on_peer_connection_state_change(Box::new(move |state| {
            let _keep_callback_observation = &callback_observation;
            let callback_work =
                match tx.begin_native_callback_operation(ConnectorCallbackClass::Control) {
                    Ok(work) => work,
                    Err(error) => {
                        warn!(
                            ?error,
                            "refusing native peer-state callback under resource pressure"
                        );
                        tx.retire_after_callback_violation();
                        return Box::pin(async {});
                    }
                };
            let tx = tx.clone();
            Box::pin(async move {
                let _callback_work = callback_work;
                tx.emit(TransportEvent::PeerConnectionStateChanged(state))
                    .await;
            })
        }));
    }

    // Answerer side: data channel arrives via callback.
    {
        let tx = events_tx.clone();
        let dc_slot = data_channel.clone();
        let handler_scope = resource_scope.clone();
        let callback_observation = observe_inexact_item_if(
            resource_scope.as_ref(),
            PreAuthResourceFamily::Callback,
            1,
            0,
        );
        pc.on_data_channel(Box::new(move |dc| {
            let _keep_callback_observation = &callback_observation;
            let callback_work =
                match tx.begin_native_callback_operation(ConnectorCallbackClass::Control) {
                    Ok(work) => work,
                    Err(error) => {
                        warn!(
                            ?error,
                            "refusing native data-channel callback under resource pressure"
                        );
                        tx.retire_after_callback_violation();
                        return Box::pin(async {});
                    }
                };
            let tx = tx.clone();
            let dc_slot = dc_slot.clone();
            let handler_scope = handler_scope.clone();
            Box::pin(async move {
                let _callback_work = callback_work;
                let Some(_operation) = tx.operation_fence.try_enter() else {
                    return;
                };
                {
                    let mut slot = dc_slot.lock();
                    match admit_native_data_channel(dc.label(), slot.is_some()) {
                        NativeDataChannelAdmission::Install => *slot = Some(dc.clone()),
                        NativeDataChannelAdmission::Violation(reason) => {
                            drop(slot);
                            tx.structural_violation(reason);
                            return;
                        }
                    }
                }
                install_data_channel_handlers(dc.clone(), tx, handler_scope.as_ref());
            })
        }));
    }

    // A negotiated inbound real-time track went live — pump its RTP until the
    // flow it feeds ends, or the track (i.e. the connection) does.
    {
        let tx = events_tx.clone();
        let task_scope = resource_scope.clone();
        let session_tracks = Arc::clone(&realtime_tracks);
        let callback_observation = observe_inexact_item_if(
            resource_scope.as_ref(),
            PreAuthResourceFamily::Callback,
            1,
            0,
        );
        pc.on_track(Box::new(move |track, _receiver, transceiver| {
            let _keep_callback_observation = &callback_observation;
            let callback_work =
                match tx.begin_native_callback_operation(ConnectorCallbackClass::Realtime) {
                    Ok(work) => work,
                    Err(error) => {
                        warn!(
                            ?error,
                            "refusing native track callback under resource pressure"
                        );
                        tx.retire_after_callback_violation();
                        return Box::pin(async {});
                    }
                };
            let tx = tx.clone();
            let session_tracks = Arc::clone(&session_tracks);
            let task_observation =
                observe_inexact_item_if(task_scope.as_ref(), PreAuthResourceFamily::Task, 1, 1);
            Box::pin(async move {
                let _callback_work = callback_work;
                let Some(_operation) = tx.operation_fence.try_enter() else {
                    return;
                };
                if !tx.callback_gate.is_active() {
                    return;
                }

                // **Classified by transceiver identity, and by nothing else.**
                // A track that arrived on a transceiver *this side* created for
                // a realtime flow is realtime-owned, permanently and regardless
                // of what has happened to the session since. A track on any
                // other transceiver is one the peer opened the m-line for, and
                // there is nothing here it can be attached to: a destination is
                // a fact this side established at bind time, so a track we did
                // not solicit has none.
                //
                // Every refusal below drops the track and returns. None of them
                // calls `structural_violation` or `retire_after_callback_
                // violation`: a track we did not offer is the peer doing
                // something we simply do not accept, not this connector having
                // broken its own invariants, and tearing the connection down
                // would let a peer end a session by offering one unsolicited
                // track.
                let Some(identity) = session_tracks.resolve(&transceiver) else {
                    trace!("dropping a track on a transceiver this side did not negotiate");
                    return;
                };
                // Our transceiver, but the session that gave its token meaning
                // is gone. Refused, and deliberately not passed on.
                let Some(bindings) = session_tracks.current() else {
                    return;
                };
                // An unspecified kind is not guessed at: it matches no binding,
                // and a track matching no binding is dropped.
                let Some(kind) = native_rtp_kind(track.kind()) else {
                    return;
                };
                let capability = &track.codec().capability;
                let Some(attachment) = bindings.admit(
                    &identity,
                    kind,
                    &capability.mime_type,
                    capability.clock_rate,
                    capability.channels,
                ) else {
                    // Our transceiver, a shape we did not open the flow for —
                    // or one whose flow has since closed. Attaching would feed
                    // a decoder configured for something else.
                    return;
                };
                // No second flow open here, and that is the point of the weak
                // port handle the admission carried. The
                // application already opened this flow and it already holds the
                // one active-flow lease it is entitled to; taking a second for
                // the same flow would halve the configured capacity and let a
                // refusal land on a flow whose open had already succeeded.
                tokio::spawn(pump_session_flow_track(
                    track,
                    tx,
                    SessionInboundTrackOwner {
                        task_observation,
                        port: attachment.port,
                        end: attachment.end,
                        tracks: Arc::clone(&session_tracks),
                        identity,
                        label: attachment.label,
                        policy: attachment.policy,
                    },
                ));
            })
        }));
    }
}

fn install_data_channel_handlers(
    dc: Arc<RTCDataChannel>,
    tx: ConnectorEventSink,
    resource_scope: Option<&PeerConnectionResourceScope>,
) {
    {
        let tx = tx.clone();
        let callback_observation =
            observe_inexact_item_if(resource_scope, PreAuthResourceFamily::Callback, 1, 0);
        dc.on_open(Box::new(move || {
            let _keep_callback_observation = &callback_observation;
            let callback_work =
                match tx.begin_native_callback_operation(ConnectorCallbackClass::Control) {
                    Ok(work) => work,
                    Err(error) => {
                        warn!(
                            ?error,
                            "refusing native data-channel-open callback under resource pressure"
                        );
                        tx.retire_after_callback_violation();
                        return Box::pin(async {});
                    }
                };
            let tx = tx.clone();
            Box::pin(async move {
                let _callback_work = callback_work;
                tx.emit_data_channel(TransportEvent::DataChannelOpen).await;
            })
        }));
    }
    {
        let tx = tx.clone();
        let callback_observation =
            observe_inexact_item_if(resource_scope, PreAuthResourceFamily::Callback, 1, 0);
        dc.on_close(Box::new(move || {
            let _keep_callback_observation = &callback_observation;
            let callback_work =
                match tx.begin_native_callback_operation(ConnectorCallbackClass::Control) {
                    Ok(work) => work,
                    Err(error) => {
                        warn!(
                            ?error,
                            "refusing native data-channel-close callback under resource pressure"
                        );
                        tx.retire_after_callback_violation();
                        return Box::pin(async {});
                    }
                };
            let tx = tx.clone();
            Box::pin(async move {
                let _callback_work = callback_work;
                tx.emit_data_channel(TransportEvent::DataChannelClosed)
                    .await;
            })
        }));
    }
    {
        let tx = tx.clone();
        let callback_observation =
            observe_inexact_item_if(resource_scope, PreAuthResourceFamily::Callback, 1, 0);
        dc.on_message(Box::new(move |msg: DataChannelMessage| {
            let _keep_callback_observation = &callback_observation;
            let payload_bytes = msg.data.len();
            if callback_payload_limit(tx.callback_policy, ConnectorCallbackClass::EndpointData)
                .is_some_and(|limit| payload_bytes > limit)
            {
                tx.retire_after_callback_violation();
                return Box::pin(async {});
            }
            let callback_work = match tx.begin_native_callback_operation_with_payload(
                ConnectorCallbackClass::EndpointData,
                payload_bytes,
                0,
            ) {
                Ok(work) => work,
                Err(error) => {
                    warn!(
                        ?error,
                        "refusing native endpoint-data callback under resource pressure"
                    );
                    tx.retire_after_callback_violation();
                    return Box::pin(async {});
                }
            };
            let tx = tx.clone();
            Box::pin(async move {
                let _callback_work = callback_work;
                tx.emit_data_channel(TransportEvent::Message(msg.data))
                    .await;
            })
        }));
    }
    {
        let tx = tx.clone();
        let callback_observation =
            observe_inexact_item_if(resource_scope, PreAuthResourceFamily::Callback, 1, 0);
        dc.on_error(Box::new(move |err| {
            let _keep_callback_observation = &callback_observation;
            let callback_work =
                match tx.begin_native_callback_operation(ConnectorCallbackClass::Control) {
                    Ok(work) => work,
                    Err(error) => {
                        warn!(
                            ?error,
                            "refusing native data-channel-error callback under resource pressure"
                        );
                        tx.retire_after_callback_violation();
                        return Box::pin(async {});
                    }
                };
            let tx = tx.clone();
            Box::pin(async move {
                let _callback_work = callback_work;
                warn!("data channel error: {err}");
                tx.emit_data_channel(TransportEvent::DataChannelClosed)
                    .await;
            })
        }));
    }
}

/// True if `ip` is a private / local-scope address — RFC1918 v4
/// (`10/8`, `172.16/12`, `192.168/16`), v4 link-local (`169.254/16`),
/// v6 unique-local (`fc00::/7`), or v6 link-local (`fe80::/10`).
/// Carrier-grade NAT space (`100.64/10`) is deliberately excluded: it's
/// reachable only via the carrier, not a LAN. Used to classify a
/// connected ICE pair as a direct local link from its endpoint address
/// rather than trusting the ICE candidate type alone — a peer-reflexive
/// candidate on a `192.168.x.x` address is still the LAN.
fn is_private_lan_ip(ip: &str) -> bool {
    use std::net::IpAddr;
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.is_private() || v4.is_link_local(),
        Ok(IpAddr::V6(v6)) => {
            let seg = v6.segments();
            // fc00::/7 (unique-local) or fe80::/10 (link-local).
            (seg[0] & 0xfe00) == 0xfc00 || (seg[0] & 0xffc0) == 0xfe80
        }
        Err(_) => false,
    }
}

/// True for v4 link-local (`169.254/16`) or v6 link-local (`fe80::/10`)
/// addresses. These can't be bound for ICE gathering without a
/// scope/zone id, so the agent's bind fails on every one; we filter them
/// out of gathering up front (see the `set_ip_filter` call in
/// [`Transport::new`]) instead of letting each fail and log. Unlike
/// [`is_private_lan_ip`], unique-local (`fc00::/7`) is deliberately *not*
/// matched — ULAs are bindable, routable on the local network, and make
/// perfectly good host candidates.
pub(crate) fn is_link_local_ip(ip: &std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        // fe80::/10 — the first 10 bits are 1111 1110 10.
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// Render an ICE candidate as a compact `kind net addr:port` string
/// for the connectivity-check snapshot — e.g. `host udp4
/// 192.168.1.50:54321`. Keeps the log line readable while still
/// showing the exact address so the user can spot a wrong subnet, a
/// link-local IPv6 that won't route, or a srflx that resolved to an
/// unexpected public IP.
fn fmt_candidate(
    t: webrtc::ice::candidate::CandidateType,
    net: webrtc::ice::network_type::NetworkType,
    ip: &str,
    port: u16,
) -> String {
    use webrtc::ice::candidate::CandidateType;
    let kind = match t {
        CandidateType::Host => "host",
        CandidateType::ServerReflexive => "srflx",
        CandidateType::PeerReflexive => "prflx",
        CandidateType::Relay => "relay",
        CandidateType::Unspecified => "?",
    };
    format!("{kind} {net} {ip}:{port}")
}

/// Lower-case wire name for a candidate-pair check state, matching the
/// strings [`super::diag::IceCheckSnapshot`] compares against.
fn pair_state_str(s: webrtc::ice::candidate::CandidatePairState) -> String {
    use webrtc::ice::candidate::CandidatePairState as S;
    match s {
        S::Waiting => "waiting",
        S::InProgress => "in-progress",
        S::Failed => "failed",
        S::Succeeded => "succeeded",
        S::Unspecified => "unspecified",
    }
    .to_string()
}

/// Extract the DTLS fingerprint (`a=fingerprint:<hash> <value>`) from an SDP
/// blob and lowercase it for stable comparison. This is endpoint-authentication
/// binding and diagnostic input. ICE restart detection uses the exact effective
/// ICE credentials instead of this fingerprint.
pub(crate) fn sdp_fingerprint(sdp: &str) -> Option<String> {
    sdp.lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("a=fingerprint:"))
        .map(|v| v.trim().to_ascii_lowercase())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteIceCredentialBinding {
    media_index: usize,
    mid: Option<String>,
    username_fragment: String,
    password: String,
}

/// Exact effective remote ICE credentials for every SDP media section.
///
/// Session-level credentials are inherited by a media section only when that
/// section does not override them. MID, or media index when MID is absent,
/// identifies an existing ICE transport across renegotiation. Adding or
/// removing a media section does not manufacture an ICE restart. A changed
/// credential pair on the same transport does.
#[derive(Debug)]
struct RemoteIceCredentialsInner {
    bindings: Vec<RemoteIceCredentialBinding>,
    resources: Option<Arc<RemoteDescriptionResourceOwner>>,
}

#[derive(Debug)]
struct RemoteDescriptionResourceOwner {
    lease: SyncMutex<Option<crate::resource::ResourceLease>>,
    post_native_claim: crate::resource::ResourceClaim,
}

impl RemoteDescriptionResourceOwner {
    fn new(
        lease: crate::resource::ResourceLease,
        post_native_claim: crate::resource::ResourceClaim,
    ) -> Arc<Self> {
        Arc::new(Self {
            lease: SyncMutex::new(Some(lease)),
            post_native_claim,
        })
    }

    fn finish_native_commit(&self) -> Result<()> {
        let mut lease = self.lease.lock();
        let Some(lease) = lease.as_mut() else {
            return Err(Error::ResourceUnavailable(
                ResourceUnavailable::ProviderInvariant {
                    dimension: crate::resource::ResourceClass::OpaqueDependencyResidual,
                },
            ));
        };
        lease
            .transition(self.post_native_claim)
            .map_err(Error::ResourceUnavailable)
    }

    fn retain_after_cleanup_failure(&self) {
        if let Some(lease) = self.lease.lock().take() {
            let _ = lease.retain_after_failed_cleanup();
        }
    }
}

#[derive(Debug, Clone)]
struct RemoteIceCredentials {
    inner: Arc<RemoteIceCredentialsInner>,
}

impl RemoteIceCredentials {
    fn new(
        bindings: Vec<RemoteIceCredentialBinding>,
        resources: Option<Arc<RemoteDescriptionResourceOwner>>,
    ) -> Self {
        Self {
            inner: Arc::new(RemoteIceCredentialsInner {
                bindings,
                resources,
            }),
        }
    }

    fn finish_native_commit(&self) -> Result<()> {
        let Some(resources) = self.resources.as_ref() else {
            return Ok(());
        };
        resources.finish_native_commit()
    }

    fn resource_owner(&self) -> Option<Arc<RemoteDescriptionResourceOwner>> {
        self.resources.as_ref().map(Arc::clone)
    }
}

impl std::ops::Deref for RemoteIceCredentials {
    type Target = RemoteIceCredentialsInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl PartialEq for RemoteIceCredentials {
    fn eq(&self, other: &Self) -> bool {
        self.bindings == other.bindings
    }
}

impl Eq for RemoteIceCredentials {}

impl RemoteIceCredentials {
    fn has_unambiguous_credential_pair(&self, username_fragment: &str) -> bool {
        let mut matching = self
            .bindings
            .iter()
            .filter(|binding| binding.username_fragment == username_fragment);
        let Some(first) = matching.next() else {
            return false;
        };
        matching.all(|binding| binding.password == first.password)
    }

    fn proves_restart_to(&self, replacement: &Self) -> bool {
        let mut overlapping_transport = false;
        for current in &self.bindings {
            let next = match current.mid.as_deref() {
                Some(mid) => replacement
                    .bindings
                    .iter()
                    .find(|binding| binding.mid.as_deref() == Some(mid)),
                None => replacement.bindings.iter().find(|binding| {
                    binding.mid.is_none() && binding.media_index == current.media_index
                }),
            };
            let Some(next) = next else {
                continue;
            };
            overlapping_transport = true;
            if current.username_fragment != next.username_fragment
                || current.password != next.password
            {
                return true;
            }
        }
        if overlapping_transport {
            return false;
        }

        let mut current_pairs: Vec<(&str, &str)> = self
            .bindings
            .iter()
            .map(|binding| {
                (
                    binding.username_fragment.as_str(),
                    binding.password.as_str(),
                )
            })
            .collect();
        let mut replacement_pairs: Vec<(&str, &str)> = replacement
            .bindings
            .iter()
            .map(|binding| {
                (
                    binding.username_fragment.as_str(),
                    binding.password.as_str(),
                )
            })
            .collect();
        current_pairs.sort_unstable();
        current_pairs.dedup();
        replacement_pairs.sort_unstable();
        replacement_pairs.dedup();
        current_pairs != replacement_pairs
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CandidateUsernameFragmentError {
    MissingCandidateLineValue,
    DuplicateCandidateLineDeclaration,
    ConflictingDeclarations,
}

impl CandidateUsernameFragmentError {
    pub(crate) const fn description(self) -> &'static str {
        match self {
            Self::MissingCandidateLineValue => "candidate-line ufrag has no value",
            Self::DuplicateCandidateLineDeclaration => {
                "candidate line declares ufrag more than once"
            }
            Self::ConflictingDeclarations => {
                "structured and candidate-line username fragments conflict"
            }
        }
    }
}

fn candidate_line_username_fragment(
    candidate_line: &str,
) -> std::result::Result<Option<&str>, CandidateUsernameFragmentError> {
    let mut fields = candidate_line.split_ascii_whitespace();
    for _ in 0..8 {
        if fields.next().is_none() {
            return Ok(None);
        }
    }

    let mut username_fragment = None;
    while let Some(extension) = fields.next() {
        let value = fields.next();
        if !extension.eq_ignore_ascii_case("ufrag") {
            continue;
        }
        let Some(value) = value else {
            return Err(CandidateUsernameFragmentError::MissingCandidateLineValue);
        };
        if username_fragment.replace(value).is_some() {
            return Err(CandidateUsernameFragmentError::DuplicateCandidateLineDeclaration);
        }
    }
    Ok(username_fragment)
}

fn candidate_username_fragment(
    candidate: &LocalIceCandidate,
) -> std::result::Result<Option<&str>, CandidateUsernameFragmentError> {
    let structured = candidate
        .username_fragment
        .as_deref()
        .filter(|username_fragment| !username_fragment.is_empty());
    let candidate_line = candidate_line_username_fragment(&candidate.candidate)?;
    match (structured, candidate_line) {
        (Some(structured), Some(candidate_line)) if structured != candidate_line => {
            Err(CandidateUsernameFragmentError::ConflictingDeclarations)
        }
        (Some(structured), _) => Ok(Some(structured)),
        (None, candidate_line) => Ok(candidate_line),
    }
}

fn candidate_matches_remote_credentials(
    candidate: &LocalIceCandidate,
    credentials: &RemoteIceCredentials,
) -> bool {
    // webrtc-rs currently serializes a gathered candidate with `Some("")` for
    // an unavailable MID while still supplying the exact media-line index.
    // An empty MID carries no identity. A nonempty MID and an index, when both
    // exist, must still resolve to the same credential binding.
    let candidate_mid = candidate.sdp_mid.as_deref().filter(|mid| !mid.is_empty());
    let declares_location = candidate.sdp_mline_index.is_some() || candidate_mid.is_some();
    let Ok(username_fragment) = candidate_username_fragment(candidate) else {
        return false;
    };
    if !declares_location && username_fragment.is_none() {
        return false;
    }
    let exact_binding = declares_location.then(|| {
        credentials.bindings.iter().find(|binding| {
            candidate
                .sdp_mline_index
                .is_none_or(|media_index| usize::from(media_index) == binding.media_index)
                && candidate_mid.is_none_or(|mid| binding.mid.as_deref() == Some(mid))
        })
    });
    let exact_binding = exact_binding.flatten();
    if declares_location && exact_binding.is_none() {
        return false;
    }
    match (exact_binding, username_fragment) {
        (Some(binding), Some(username_fragment)) => binding.username_fragment == username_fragment,
        (Some(_), None) => true,
        (None, Some(username_fragment)) => {
            credentials.has_unambiguous_credential_pair(username_fragment)
        }
        (None, None) => false,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RemoteIceCredentialAllocationPlan {
    media_count: usize,
    binding_count: usize,
    string_bytes: usize,
}

#[derive(Default)]
struct PlannedIceMediaSection<'a> {
    media_index: usize,
    rejected: bool,
    mid: Option<&'a str>,
    username_fragment: Option<&'a str>,
    password: Option<&'a str>,
}

fn finish_planned_ice_media_section(
    section: PlannedIceMediaSection<'_>,
    session_username_fragment: Option<&str>,
    session_password: Option<&str>,
    binding_count: &mut usize,
    string_bytes: &mut usize,
) -> Result<()> {
    if section.rejected {
        return Ok(());
    }
    let username_fragment = section
        .username_fragment
        .or(session_username_fragment)
        .ok_or_else(|| {
            Error::Transport(format!(
                "remote SDP media section {} has no effective ICE username fragment",
                section.media_index
            ))
        })?;
    let password = section.password.or(session_password).ok_or_else(|| {
        Error::Transport(format!(
            "remote SDP media section {} has no effective ICE password",
            section.media_index
        ))
    })?;
    *binding_count = binding_count.checked_add(1).ok_or_else(|| {
        Error::Transport("remote SDP credential binding count overflowed".to_string())
    })?;
    *string_bytes = string_bytes
        .checked_add(section.mid.map_or(0, str::len))
        .and_then(|total| total.checked_add(username_fragment.len()))
        .and_then(|total| total.checked_add(password.len()))
        .ok_or_else(|| {
            Error::Transport("remote SDP credential string size overflowed".to_string())
        })?;
    Ok(())
}

/// Inspect the exact retained credential shape without allocating parser
/// records or credential strings. The retained output claim is acquired from
/// this plan before the allocating parser runs. Parser scratch, allocator
/// slack, and the dependency-owned native description remain named opaque
/// residual domains.
fn plan_sdp_ice_credential_allocations(sdp: &str) -> Result<RemoteIceCredentialAllocationPlan> {
    let mut session_username_fragment = None;
    let mut session_password = None;
    let mut current = None::<PlannedIceMediaSection<'_>>;
    let mut media_count = 0_usize;
    let mut binding_count = 0_usize;
    let mut string_bytes = 0_usize;

    for raw_line in sdp.lines() {
        let line = raw_line.trim().trim_end_matches('\r');
        if let Some(media) = line.strip_prefix("m=") {
            if let Some(section) = current.take() {
                finish_planned_ice_media_section(
                    section,
                    session_username_fragment,
                    session_password,
                    &mut binding_count,
                    &mut string_bytes,
                )?;
            }
            let media_index = media_count;
            media_count = media_count.checked_add(1).ok_or_else(|| {
                Error::Transport("remote SDP media section count overflowed".to_string())
            })?;
            let rejected = media
                .split_ascii_whitespace()
                .nth(1)
                .and_then(|port| port.split('/').next())
                .is_some_and(|port| port == "0");
            current = Some(PlannedIceMediaSection {
                media_index,
                rejected,
                ..Default::default()
            });
            continue;
        }
        if let Some(value) = line.strip_prefix("a=mid:") {
            if let Some(section) = current.as_mut() {
                let value = value.trim();
                if value.is_empty() {
                    return Err(Error::Transport(
                        "remote SDP carries an empty MID".to_string(),
                    ));
                }
                if section.mid.replace(value).is_some() {
                    return Err(Error::Transport(
                        "remote SDP media section carries more than one MID".to_string(),
                    ));
                }
            }
            continue;
        }
        if let Some(value) = line.strip_prefix("a=ice-ufrag:") {
            let value = value.trim();
            if value.is_empty() {
                return Err(Error::Transport(
                    "remote SDP carries an empty ICE username fragment".to_string(),
                ));
            }
            match current.as_mut() {
                Some(section) => {
                    if section.username_fragment.replace(value).is_some() {
                        return Err(Error::Transport(
                            "remote SDP media section carries more than one ICE username fragment"
                                .to_string(),
                        ));
                    }
                }
                None => {
                    if session_username_fragment.replace(value).is_some() {
                        return Err(Error::Transport(
                            "remote SDP session carries more than one ICE username fragment"
                                .to_string(),
                        ));
                    }
                }
            }
            continue;
        }
        if let Some(value) = line.strip_prefix("a=ice-pwd:") {
            let value = value.trim();
            if value.is_empty() {
                return Err(Error::Transport(
                    "remote SDP carries an empty ICE password".to_string(),
                ));
            }
            match current.as_mut() {
                Some(section) => {
                    if section.password.replace(value).is_some() {
                        return Err(Error::Transport(
                            "remote SDP media section carries more than one ICE password"
                                .to_string(),
                        ));
                    }
                }
                None => {
                    if session_password.replace(value).is_some() {
                        return Err(Error::Transport(
                            "remote SDP session carries more than one ICE password".to_string(),
                        ));
                    }
                }
            }
        }
    }

    let Some(section) = current else {
        return Err(Error::Transport(
            "remote SDP has no media section for exact ICE credentials".to_string(),
        ));
    };
    finish_planned_ice_media_section(
        section,
        session_username_fragment,
        session_password,
        &mut binding_count,
        &mut string_bytes,
    )?;
    if binding_count == 0 {
        return Err(Error::Transport(
            "remote SDP has no active media section with exact ICE credentials".to_string(),
        ));
    }
    Ok(RemoteIceCredentialAllocationPlan {
        media_count,
        binding_count,
        string_bytes,
    })
}

#[derive(Default)]
struct ParsedIceMediaSection {
    rejected: bool,
    mid: Option<String>,
    username_fragment: Option<String>,
    password: Option<String>,
}

fn parse_sdp_ice_credential_bindings_with_plan(
    sdp: &str,
    plan: RemoteIceCredentialAllocationPlan,
) -> Result<Vec<RemoteIceCredentialBinding>> {
    let mut session_username_fragment = None;
    let mut session_password = None;
    let mut sections = Vec::<ParsedIceMediaSection>::with_capacity(plan.media_count);

    for raw_line in sdp.lines() {
        let line = raw_line.trim().trim_end_matches('\r');
        if let Some(media) = line.strip_prefix("m=") {
            let rejected = media
                .split_ascii_whitespace()
                .nth(1)
                .and_then(|port| port.split('/').next())
                .is_some_and(|port| port == "0");
            sections.push(ParsedIceMediaSection {
                rejected,
                ..Default::default()
            });
            continue;
        }
        let target = sections.last_mut();
        if let Some(value) = line.strip_prefix("a=mid:") {
            if let Some(section) = target {
                let value = value.trim();
                if value.is_empty() {
                    return Err(Error::Transport(
                        "remote SDP carries an empty MID".to_string(),
                    ));
                }
                if section.mid.is_some() {
                    return Err(Error::Transport(
                        "remote SDP media section carries more than one MID".to_string(),
                    ));
                }
                section.mid = Some(value.to_string());
            }
            continue;
        }
        if let Some(value) = line.strip_prefix("a=ice-ufrag:") {
            let value = value.trim();
            if value.is_empty() {
                return Err(Error::Transport(
                    "remote SDP carries an empty ICE username fragment".to_string(),
                ));
            }
            match target {
                Some(section) if section.username_fragment.is_some() => {
                    return Err(Error::Transport(
                        "remote SDP media section carries more than one ICE username fragment"
                            .to_string(),
                    ));
                }
                Some(section) => section.username_fragment = Some(value.to_string()),
                None if session_username_fragment.is_some() => {
                    return Err(Error::Transport(
                        "remote SDP session carries more than one ICE username fragment"
                            .to_string(),
                    ));
                }
                None => session_username_fragment = Some(value.to_string()),
            }
            continue;
        }
        if let Some(value) = line.strip_prefix("a=ice-pwd:") {
            let value = value.trim();
            if value.is_empty() {
                return Err(Error::Transport(
                    "remote SDP carries an empty ICE password".to_string(),
                ));
            }
            match target {
                Some(section) if section.password.is_some() => {
                    return Err(Error::Transport(
                        "remote SDP media section carries more than one ICE password".to_string(),
                    ));
                }
                Some(section) => section.password = Some(value.to_string()),
                None if session_password.is_some() => {
                    return Err(Error::Transport(
                        "remote SDP session carries more than one ICE password".to_string(),
                    ));
                }
                None => session_password = Some(value.to_string()),
            }
        }
    }

    if sections.is_empty() {
        return Err(Error::Transport(
            "remote SDP has no media section for exact ICE credentials".to_string(),
        ));
    }

    let mut bindings = Vec::with_capacity(plan.binding_count);
    let mut active_mids = std::collections::HashSet::with_capacity(plan.binding_count);
    for (media_index, section) in sections.into_iter().enumerate() {
        if section.rejected {
            continue;
        }
        if let Some(mid) = section.mid.as_ref() {
            if !active_mids.insert(mid.clone()) {
                return Err(Error::Transport(format!(
                    "remote SDP repeats active MID {mid}"
                )));
            }
        }
        let username_fragment = section
            .username_fragment
            .or_else(|| session_username_fragment.clone())
            .ok_or_else(|| {
                Error::Transport(format!(
                    "remote SDP media section {media_index} has no effective ICE username fragment"
                ))
            })?;
        let password = section
            .password
            .or_else(|| session_password.clone())
            .ok_or_else(|| {
                Error::Transport(format!(
                    "remote SDP media section {media_index} has no effective ICE password"
                ))
            })?;
        bindings.push(RemoteIceCredentialBinding {
            media_index,
            mid: section.mid,
            username_fragment,
            password,
        });
    }
    if bindings.is_empty() {
        return Err(Error::Transport(
            "remote SDP has no active media section with exact ICE credentials".to_string(),
        ));
    }
    Ok(bindings)
}

#[cfg(test)]
fn parse_sdp_ice_credential_bindings(sdp: &str) -> Result<Vec<RemoteIceCredentialBinding>> {
    let plan = plan_sdp_ice_credential_allocations(sdp)?;
    parse_sdp_ice_credential_bindings_with_plan(sdp, plan)
}

#[cfg(test)]
fn sdp_ice_credentials(sdp: &str) -> Result<RemoteIceCredentials> {
    parse_sdp_ice_credential_bindings(sdp).map(|bindings| RemoteIceCredentials::new(bindings, None))
}

fn remote_description_operation_claim(
    input_capacity: usize,
) -> std::result::Result<
    crate::resource::ResourceClaim,
    crate::resource::ResourceClaimArithmeticError,
> {
    let input_capacity = u64::try_from(input_capacity).map_err(|_| {
        crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        }
    })?;
    crate::resource::ResourceClaim::try_from_entries([
        (
            crate::resource::ResourceClass::AccountedMemoryBytes,
            input_capacity,
        ),
        (crate::resource::ResourceClass::CallbackOrScheduledWork, 1),
        (
            crate::resource::ResourceClass::ParsingOrCpuWork,
            input_capacity,
        ),
        // Credential-extraction scratch and the dependency-owned parsed/native
        // remote-description tree are explicit non-byte residual domains.
        (crate::resource::ResourceClass::OpaqueDependencyResidual, 2),
    ])
}

fn remote_description_registry_entry_claim() -> std::result::Result<
    crate::resource::ResourceClaim,
    crate::resource::ResourceClaimArithmeticError,
> {
    let arc_counters = std::mem::size_of::<usize>().checked_mul(2).ok_or(
        crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        },
    )?;
    let accounted = std::mem::size_of::<Arc<RemoteDescriptionResourceOwner>>()
        .checked_add(std::mem::size_of::<RemoteDescriptionResourceOwner>())
        .and_then(|value| value.checked_add(arc_counters))
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        })?;
    let accounted = u64::try_from(accounted).map_err(|_| {
        crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        }
    })?;
    crate::resource::ResourceClaim::try_from_entries([
        (
            crate::resource::ResourceClass::AccountedMemoryBytes,
            accounted,
        ),
        (crate::resource::ResourceClass::StorageObject, 1),
        // Arc and linked-list allocation metadata, padding, and allocator
        // behavior are two named residual domains.
        (crate::resource::ResourceClass::OpaqueDependencyResidual, 2),
    ])
}

#[cfg(any(test, feature = "transport-lab"))]
fn retained_remote_description_claim_from_plan(
    plan: RemoteIceCredentialAllocationPlan,
    input_capacity: usize,
    native_work_in_flight: bool,
) -> std::result::Result<
    crate::resource::ResourceClaim,
    crate::resource::ResourceClaimArithmeticError,
> {
    let binding_records = plan
        .binding_count
        .checked_mul(std::mem::size_of::<RemoteIceCredentialBinding>())
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        })?;
    let accounted = std::mem::size_of::<RemoteIceCredentialsInner>()
        .checked_add(std::mem::size_of::<Vec<RemoteIceCredentialBinding>>())
        .and_then(|total| total.checked_add(binding_records))
        .and_then(|total| total.checked_add(plan.string_bytes))
        .and_then(|total| total.checked_add(input_capacity))
        .and_then(|total| u64::try_from(total).ok())
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        })?;
    let mut claim = crate::resource::ResourceClaim::try_from_entries([
        (
            crate::resource::ResourceClass::AccountedMemoryBytes,
            accounted,
        ),
        (crate::resource::ResourceClass::OpaqueDependencyResidual, 2),
    ])?
    .checked_add(remote_description_registry_entry_claim()?)?;
    if native_work_in_flight {
        claim = claim.checked_add(crate::resource::ResourceClaim::single(
            crate::resource::ResourceClass::CallbackOrScheduledWork,
            1,
        ))?;
    }
    Ok(claim)
}

fn retained_remote_description_claim(
    bindings: &[RemoteIceCredentialBinding],
    binding_capacity: usize,
    input_capacity: usize,
    native_work_in_flight: bool,
) -> std::result::Result<
    crate::resource::ResourceClaim,
    crate::resource::ResourceClaimArithmeticError,
> {
    let binding_records = binding_capacity
        .checked_mul(std::mem::size_of::<RemoteIceCredentialBinding>())
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        })?;
    let string_capacities = bindings.iter().try_fold(0_usize, |total, binding| {
        total
            .checked_add(binding.mid.as_ref().map_or(0, String::capacity))
            .and_then(|total| total.checked_add(binding.username_fragment.capacity()))
            .and_then(|total| total.checked_add(binding.password.capacity()))
    });
    let accounted = std::mem::size_of::<RemoteIceCredentialsInner>()
        .checked_add(std::mem::size_of::<Vec<RemoteIceCredentialBinding>>())
        .and_then(|total| total.checked_add(binding_records))
        .and_then(|total| total.checked_add(string_capacities?))
        .and_then(|total| total.checked_add(input_capacity))
        .and_then(|total| u64::try_from(total).ok())
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        })?;
    let mut claim = crate::resource::ResourceClaim::try_from_entries([
        (
            crate::resource::ResourceClass::AccountedMemoryBytes,
            accounted,
        ),
        (crate::resource::ResourceClass::OpaqueDependencyResidual, 2),
    ])?
    .checked_add(remote_description_registry_entry_claim()?)?;
    if native_work_in_flight {
        claim = claim.checked_add(crate::resource::ResourceClaim::single(
            crate::resource::ResourceClass::CallbackOrScheduledWork,
            1,
        ))?;
    }
    Ok(claim)
}

fn planned_remote_description_claim(
    plan: RemoteIceCredentialAllocationPlan,
    input_capacity: usize,
) -> std::result::Result<
    crate::resource::ResourceClaim,
    crate::resource::ResourceClaimArithmeticError,
> {
    let binding_records = plan
        .binding_count
        .checked_mul(std::mem::size_of::<RemoteIceCredentialBinding>())
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        })?;
    let parser_sections = plan
        .media_count
        .checked_mul(std::mem::size_of::<ParsedIceMediaSection>())
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        })?;
    let parser_mid_keys = plan
        .binding_count
        .checked_mul(std::mem::size_of::<String>())
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        })?;
    let parser_string_copies = input_capacity.checked_mul(2).ok_or(
        crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        },
    )?;
    let accounted = std::mem::size_of::<RemoteIceCredentialsInner>()
        .checked_add(std::mem::size_of::<Vec<RemoteIceCredentialBinding>>())
        .and_then(|total| total.checked_add(std::mem::size_of::<Vec<ParsedIceMediaSection>>()))
        .and_then(|total| {
            total.checked_add(std::mem::size_of::<std::collections::HashSet<String>>())
        })
        .and_then(|total| total.checked_add(binding_records))
        .and_then(|total| total.checked_add(parser_sections))
        .and_then(|total| total.checked_add(parser_mid_keys))
        .and_then(|total| total.checked_add(plan.string_bytes))
        .and_then(|total| total.checked_add(parser_string_copies))
        .and_then(|total| total.checked_add(input_capacity))
        .and_then(|total| u64::try_from(total).ok())
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        })?;
    crate::resource::ResourceClaim::try_from_entries([
        (
            crate::resource::ResourceClass::AccountedMemoryBytes,
            accounted,
        ),
        (crate::resource::ResourceClass::CallbackOrScheduledWork, 1),
        (
            crate::resource::ResourceClass::ParsingOrCpuWork,
            u64::try_from(input_capacity).map_err(|_| {
                crate::resource::ResourceClaimArithmeticError::Overflow {
                    dimension: crate::resource::ResourceClass::ParsingOrCpuWork,
                }
            })?,
        ),
        // One unit protects HashSet and allocator slack. The other protects
        // the dependency-owned parsed/native remote description.
        (crate::resource::ResourceClass::OpaqueDependencyResidual, 2),
    ])?
    .checked_add(remote_description_registry_entry_claim()?)
}

fn sdp_ice_credentials_owned(
    sdp: &str,
    input_capacity: usize,
    work_resources: &ConnectorWorkResourceScope,
) -> Result<RemoteIceCredentials> {
    let initial_claim = remote_description_operation_claim(input_capacity).map_err(|error| {
        Error::Transport(format!(
            "remote-description operation claim overflowed: {error}"
        ))
    })?;
    let mut lease = work_resources
        .acquire(
            crate::resource::ResourceAuthorityClass::Speculative,
            initial_claim,
        )
        .map_err(Error::ResourceUnavailable)?;
    let plan = plan_sdp_ice_credential_allocations(sdp)?;
    let planned_claim =
        planned_remote_description_claim(plan, input_capacity).map_err(|error| {
            Error::Transport(format!(
                "remote-description planned claim overflowed: {error}"
            ))
        })?;
    lease
        .transition(planned_claim)
        .map_err(Error::ResourceUnavailable)?;
    let bindings = parse_sdp_ice_credential_bindings_with_plan(sdp, plan)?;
    let retained_claim =
        retained_remote_description_claim(&bindings, bindings.capacity(), input_capacity, true)
            .map_err(|error| {
                Error::Transport(format!(
                    "remote-description retained claim overflowed: {error}"
                ))
            })?;
    lease
        .transition(retained_claim)
        .map_err(Error::ResourceUnavailable)?;
    let post_native_claim =
        retained_remote_description_claim(&bindings, bindings.capacity(), input_capacity, false)
            .map_err(|error| {
                Error::Transport(format!(
                    "remote-description post-native claim overflowed: {error}"
                ))
            })?;
    Ok(RemoteIceCredentials::new(
        bindings,
        Some(RemoteDescriptionResourceOwner::new(
            lease,
            post_native_claim,
        )),
    ))
}

pub struct PeerSession {
    pc: Arc<RTCPeerConnection>,
    data_channel: Arc<SyncMutex<Option<Arc<RTCDataChannel>>>>,
    /// The application's registered codecs, retained past media-engine
    /// construction.
    ///
    /// The API build asks "what do I register"; binding an inbound flow asks
    /// "which framing does this family want". Re-deriving the second from the
    /// first is not possible — the media engine keeps no framing — so the
    /// profile is held rather than consumed.
    ///
    /// Leased and shared: this is the connector's one charged copy, and a
    /// promoted session's flow set holds a pointer to the same record rather
    /// than a deep clone of it.
    realtime_profile: Option<session_flow::LeasedRealtimeProfile>,
    /// The current session's inbound realtime wiring, shared with the
    /// `on_track` callback that reads it when a track arrives.
    realtime_tracks: Arc<RealtimeSessionTracks>,
    /// Retention, not a send path. Every native handler installed on this peer
    /// connection holds its own clone of the sink and reports through that one;
    /// nothing reads this field. It exists so the mailboxes, the callback
    /// producer's reserved lifecycle work, and the close owner outlive the last
    /// native handler rather than the other way round — a dependency callback
    /// that fires while its owner is being torn down must find a live sink to
    /// be refused by, not a freed one.
    _events_tx: ConnectorEventSink,
    callback_gate: Arc<WebRtcConnectorIncarnation>,
    role: Role,
    /// The observation scope this session's pre-authentication measurements are
    /// attributed to. Held rather than read: the accountant is reference
    /// counted, so keeping a clone for exactly the session's lifetime is what
    /// keeps the scope from being torn down while a native callback can still
    /// observe into it.
    _resource_scope: Option<PeerConnectionResourceScope>,
    /// The connector work scope every lease under this session was acquired
    /// from. `ResourceScope` deregisters itself from the provider when its last
    /// clone drops, so this clone is what keeps the scope registered for as
    /// long as the session can still acquire — and what releases it exactly
    /// when the session goes.
    _work_resource_scope: Option<ConnectorWorkResourceScope>,
}

impl PeerSession {
    pub fn role(&self) -> Role {
        self.role
    }

    /// True once the data channel is established on this side
    /// (open and `on_open` fired).
    pub async fn has_data_channel(&self) -> bool {
        self.data_channel.lock().is_some()
    }

    /// Build an offer SDP. Offerer-only (answerer never calls this).
    ///
    /// The stage logs exist because this pair is the engine's
    /// inline-on-the-driver excursion into webrtc-rs: it wedges on the NanoKVM
    /// with nothing inside logging, so knowing *which* stage stopped is what
    /// turns an invisible freeze into a diagnosis.
    ///
    /// They were INFO on the premise that they "fire once per connect attempt —
    /// negligible in a healthy log". That premise is what broke: an unhealthy
    /// mesh renegotiates constantly, and at ~12 lines per peer per attempt
    /// across 20+ peers this became the single largest contributor to a
    /// multi-gigabyte syslog. Precisely when the daemon is sickest, its logs
    /// grow fastest — and the disk that fills takes the diagnosis with it.
    ///
    /// So they are DEBUG now, and the field workflow is unchanged in substance:
    /// `MYOWNMESH_LOG_EXTRA=myownmesh_core=debug` (what `just serve-trace`
    /// already sets) brings every one of them back verbatim.
    pub async fn create_offer(&self) -> Result<RTCSessionDescription> {
        debug!("create_offer: building SDP (pc.create_offer)");
        let offer = self
            .pc
            .create_offer(None)
            .await
            .map_err(|e| Error::Transport(format!("create_offer: {e}")))?;
        debug!(
            sdp_bytes = offer.sdp.len(),
            "create_offer: applying local description (starts ICE gathering)"
        );
        self.pc
            .set_local_description(offer.clone())
            .await
            .map_err(|e| Error::Transport(format!("set_local_description (offer): {e}")))?;
        debug!("create_offer: local description applied");
        Ok(offer)
    }

    /// Apply the remote SDP. Both sides call this — offerer with
    /// the answer they got back, answerer with the offer they
    /// received first. Stage-logged like create_offer: the answer path runs
    /// the same inline-on-the-driver webrtc-rs machinery (and processes the
    /// REMOTE side's media sections regardless of our own lane count), so it
    /// is equally capable of freezing the engine invisibly.
    pub async fn set_remote_description(&self, desc: RTCSessionDescription) -> Result<()> {
        debug!(
            sdp_type = %desc.sdp_type,
            sdp_bytes = desc.sdp.len(),
            "set_remote_description: applying remote SDP"
        );
        self.pc
            .set_remote_description(desc)
            .await
            .map_err(|e| Error::Transport(format!("set_remote_description: {e}")))
    }

    /// DTLS fingerprint of the currently-applied remote description, if any.
    /// A *restart* offer keeps this fingerprint (same peer connection, new ICE
    /// ufrag); a *rebuild* offer carries a new one (the peer tore its PC down
    /// and built fresh). The answerer compares the incoming offer's fingerprint
    /// to this to decide between renegotiating in place and dropping for a
    /// clean rebuild — applying a rebuild offer onto the stale PC deadlocks
    /// (it lands on a corpse and no candidates ever flow). `None` before any
    /// remote description is set.
    pub async fn remote_fingerprint(&self) -> Option<String> {
        sdp_fingerprint(&self.pc.remote_description().await?.sdp)
    }

    /// DTLS fingerprint of our *local* description — the fingerprint of the
    /// certificate THIS side presents on the DTLS channel. WebRTC verifies a
    /// peer's presented certificate against the `a=fingerprint:` in the SDP it
    /// received, so on an un-intercepted channel a peer's
    /// [`Self::remote_fingerprint`] equals its counterpart's
    /// `local_fingerprint`. The auth handshake folds this value — together
    /// with [`Self::remote_fingerprint`], so the transcript commits to the
    /// pair rather than to the signer alone — into the signed Arc 04
    /// endpoint-auth transcript (see [`crate::endpoint_auth`]), so a
    /// signaling-path man-in-the-middle — which must present its own
    /// certificate on each leg it terminates — is detected: the victim's
    /// observed remote fingerprint no longer matches the one the real peer
    /// signed. `None` before the local description is set.
    ///
    /// A fingerprint identifies the certificate, not the session, so this is
    /// not a session-unique exporter and does not separate two channels that
    /// reuse the same certificates; per-attempt contributions and
    /// connector-incarnation ownership carry that.
    pub async fn local_fingerprint(&self) -> Option<String> {
        sdp_fingerprint(&self.pc.local_description().await?.sdp)
    }

    /// True when the peer connection is awaiting a remote Answer — i.e. we
    /// have a local offer outstanding (`have-local-offer`). An Answer that
    /// arrives in any other state is stale (a duplicate from relay redundancy,
    /// or the answer to an offer we've since superseded); applying it throws
    /// webrtc-rs's "invalid proposed signaling state transition from stable"
    /// error and wedges the negotiation, so the engine drops it instead.
    pub fn awaiting_answer(&self) -> bool {
        self.pc.signaling_state() == RTCSignalingState::HaveLocalOffer
    }

    /// Build an answer SDP. Answerer-only; call after
    /// [`Self::set_remote_description`]. Stage-logged like create_offer —
    /// same inline-on-the-driver machinery, same invisible-freeze potential.
    pub async fn create_answer(&self) -> Result<RTCSessionDescription> {
        debug!("create_answer: building SDP (pc.create_answer)");
        let answer = self
            .pc
            .create_answer(None)
            .await
            .map_err(|e| Error::Transport(format!("create_answer: {e}")))?;
        debug!(
            sdp_bytes = answer.sdp.len(),
            "create_answer: applying local description (starts ICE gathering)"
        );
        self.pc
            .set_local_description(answer.clone())
            .await
            .map_err(|e| Error::Transport(format!("set_local_description (answer): {e}")))?;
        debug!("create_answer: local description applied");
        Ok(answer)
    }

    /// Add an ICE candidate the peer sent us. The peer's nominal
    /// `null` (gathering complete) is also acceptable.
    ///
    /// The raw port is private to `WebRtcConnectorWorker`. External and engine
    /// callers must use the worker so queue, lifetime, and observation owners
    /// cannot be bypassed.
    async fn add_ice_candidate(&self, cand: LocalIceCandidate) -> Result<()> {
        self.pc
            .add_ice_candidate(cand.into_init())
            .await
            .map_err(|e| Error::Transport(format!("add_ice_candidate: {e}")))
    }

    /// Send bytes on the data channel. Returns the number of bytes
    /// queued for transmission (matches webrtc-rs's contract).
    pub async fn send(&self, payload: Bytes) -> Result<usize> {
        let dc = self
            .data_channel
            .lock()
            .clone()
            .ok_or_else(|| Error::Transport("data channel not open".into()))?;
        dc.send(&payload)
            .await
            .map_err(|e| Error::Transport(format!("data channel send: {e}")))
    }

    /// The peer connection's signaling state. The media-renegotiation
    /// pass gates its in-place offers on `Stable` so it never stacks
    /// an offer onto a negotiation that's still settling (glare).
    pub fn signaling_state(&self) -> RTCSignalingState {
        self.pc.signaling_state()
    }

    /// Force ICE restart. Used by the engine's Tier 2.5 / Tier 3
    /// recovery path.
    pub async fn restart_ice(&self) -> Result<()> {
        self.pc
            .restart_ice()
            .await
            .map_err(|e| Error::Transport(format!("restart_ice: {e}")))
    }

    /// Read the peer connection's current ICE state. Useful for
    /// the ICE watchdog without subscribing to every transition.
    pub fn ice_connection_state(&self) -> RTCIceConnectionState {
        self.pc.ice_connection_state()
    }

    /// Read the overall connection state (DTLS + ICE composite).
    pub fn connection_state(&self) -> RTCPeerConnectionState {
        self.pc.connection_state()
    }

    /// Ask the underlying ICE agent which candidate pair it actually
    /// selected for sending packets. This is the authoritative
    /// answer to "is this a LAN link or going through STUN/TURN" —
    /// gathered candidate counts only tell us what was tried, not
    /// what's in use. Returns `None` until ICE has settled
    /// (Connected / Completed) and the agent has nominated a pair.
    ///
    /// Implementation note: webrtc-rs's `get_selected_candidate_pair`
    /// returns a struct with private fields and no accessors (as of
    /// 0.13), so we go through the stats API instead — the candidate-
    /// pair stats expose `nominated` plus ids that resolve to local /
    /// remote candidate stats with public `candidate_type` fields.
    pub async fn selected_candidate_pair(&self) -> Option<super::diag::SelectedCandidatePair> {
        use webrtc::ice::candidate::{CandidatePairState, CandidateType};
        use webrtc::stats::StatsReportType;
        let report = self.pc.get_stats().await;
        // Find the nominated pair. There can be several pair entries
        // (one per checklist combination); only the nominated one is
        // currently carrying packets.
        //
        // Fallback: webrtc-rs doesn't always flip `nominated=true` on
        // the controlling (Offerer) side — the field can stay false
        // even after ICE is solidly Connected and bytes are flowing.
        // When no pair is marked nominated, fall back to the
        // Succeeded pair with the most bytes_received (the one
        // actually carrying traffic); if multiple have zero bytes,
        // any Succeeded pair classifies the same way for our
        // purposes (LAN / STUN / TURN). Without this fallback the
        // Offerer side stays unclassified on a healthy LAN pair —
        // packets flow, GUI never paints the link type.
        let (local_id, remote_id) = {
            let nominated = report.reports.values().find_map(|r| match r {
                StatsReportType::CandidatePair(p) if p.nominated => {
                    Some((p.local_candidate_id.clone(), p.remote_candidate_id.clone()))
                }
                _ => None,
            });
            match nominated {
                Some(ids) => ids,
                None => report
                    .reports
                    .values()
                    .filter_map(|r| match r {
                        StatsReportType::CandidatePair(p)
                            if p.state == CandidatePairState::Succeeded =>
                        {
                            Some(p)
                        }
                        _ => None,
                    })
                    .max_by_key(|p| p.bytes_received)
                    .map(|p| (p.local_candidate_id.clone(), p.remote_candidate_id.clone()))?,
            }
        };
        // Classify from the candidate's actual address first, falling
        // back to the ICE type. A *working* pair whose endpoint is a
        // private/RFC1918 address is, by definition, a direct
        // local-network link: those ranges aren't routable across the
        // internet, so if packets are flowing the two devices share a
        // LAN. We report it as `Host` even when ICE labelled the
        // candidate `prflx` (peer-reflexive) — which happens routinely
        // when the remote's host candidate arrived a beat before its
        // SDP and was learned from a STUN binding rather than the
        // candidate list, the exact reason a genuinely-local peer was
        // mis-painted as "STUN / over the internet". `Relay` always
        // wins (a TURN relay is a relay even on a private address).
        fn classify(t: CandidateType, ip: &str) -> super::diag::IceCandidateKind {
            use super::diag::IceCandidateKind;
            match t {
                CandidateType::Relay => IceCandidateKind::Relay,
                _ if is_private_lan_ip(ip) => IceCandidateKind::Host,
                CandidateType::Host => IceCandidateKind::Host,
                CandidateType::ServerReflexive => IceCandidateKind::ServerReflexive,
                CandidateType::PeerReflexive => IceCandidateKind::PeerReflexive,
                CandidateType::Unspecified => IceCandidateKind::Unknown,
            }
        }
        let local = report.reports.values().find_map(|r| match r {
            StatsReportType::LocalCandidate(c) if c.id == local_id => {
                Some(classify(c.candidate_type, &c.ip))
            }
            _ => None,
        })?;
        let remote = report.reports.values().find_map(|r| match r {
            StatsReportType::RemoteCandidate(c) if c.id == remote_id => {
                Some(classify(c.candidate_type, &c.ip))
            }
            _ => None,
        })?;
        Some(super::diag::SelectedCandidatePair { local, remote })
    }

    /// Capture a full connectivity-check snapshot from the ICE agent's
    /// stats. Where [`Self::selected_candidate_pair`] only reports the
    /// *winning* pair once ICE is Connected, this returns **every**
    /// candidate pair and its live STUN check counters at any point in
    /// the lifecycle — the data you need to answer "why is this peer
    /// stuck in Checking / why did it go Failed". The engine logs it on
    /// ICE failure and periodically while a peer is still checking.
    pub async fn ice_check_snapshot(&self) -> super::diag::IceCheckSnapshot {
        use std::collections::HashMap;
        use webrtc::stats::StatsReportType;

        let report = self.pc.get_stats().await;

        // First pass: build candidate-id → "kind net addr:port" so the
        // pairs below can render real addresses instead of opaque ids,
        // and collect the flat local/remote candidate lists.
        let mut by_id: HashMap<String, String> = HashMap::new();
        let mut local_candidates = Vec::new();
        let mut remote_candidates = Vec::new();
        for r in report.reports.values() {
            match r {
                StatsReportType::LocalCandidate(c) => {
                    let s = fmt_candidate(c.candidate_type, c.network_type, &c.ip, c.port);
                    by_id.insert(c.id.clone(), s.clone());
                    local_candidates.push(s);
                }
                StatsReportType::RemoteCandidate(c) => {
                    let s = fmt_candidate(c.candidate_type, c.network_type, &c.ip, c.port);
                    by_id.insert(c.id.clone(), s.clone());
                    remote_candidates.push(s);
                }
                _ => {}
            }
        }

        // Second pass: the candidate pairs and their check counters.
        let mut pairs = Vec::new();
        for r in report.reports.values() {
            if let StatsReportType::CandidatePair(p) = r {
                let resolve = |id: &str| by_id.get(id).cloned().unwrap_or_else(|| id.to_string());
                pairs.push(super::diag::IcePairSnapshot {
                    local: resolve(&p.local_candidate_id),
                    remote: resolve(&p.remote_candidate_id),
                    state: pair_state_str(p.state),
                    nominated: p.nominated,
                });
            }
        }

        // Stable ordering so successive snapshots diff cleanly in the log
        // and a capped dump shows the pairs that matter: nominated first,
        // then succeeded, then everything else. (We can't rank by check
        // activity — webrtc-ice 0.13 never populates the per-pair STUN
        // counters, so they're all zero; see `diag::IcePairSnapshot`.)
        let rank = |p: &super::diag::IcePairSnapshot| -> u8 {
            match (p.nominated, p.state.as_str()) {
                (true, _) => 0,
                (_, "succeeded") => 1,
                (_, "in-progress") => 2,
                (_, "waiting") => 3,
                _ => 4,
            }
        };
        pairs.sort_by_key(rank);
        local_candidates.sort();
        remote_candidates.sort();
        super::diag::IceCheckSnapshot {
            local_candidates,
            remote_candidates,
            pairs,
        }
    }

    /// Close the connection. Idempotent — subsequent close calls
    /// The callback gate retires before the native close is awaited so a full
    /// callback queue cannot deadlock shutdown.
    pub async fn close(&self) -> Result<()> {
        debug!("closing peer connection");
        self.callback_gate.retire();
        self.pc
            .close()
            .await
            .map_err(|e| Error::Transport(format!("close: {e}")))?;
        Ok(())
    }
}

#[cfg(any(test, feature = "transport-lab"))]
fn realtime_fixture_provider_grant(
    local: crate::runtime::attempt::EnabledRealtimeConnectorPolicy,
) -> Result<crate::resource::ResourceClaim> {
    use crate::resource::FiniteResourceProvider;

    fn add_lease(
        total: &mut crate::resource::ResourceClaim,
        claim: crate::resource::ResourceClaim,
    ) -> Result<()> {
        *total = total
            .checked_add(
                FiniteResourceProvider::reservation_charge_for_test(claim).map_err(Error::from)?,
            )
            .map_err(|error| {
                Error::Transport(format!("fixture real-time claim overflowed: {error}"))
            })?;
        Ok(())
    }

    let flows = local.flows();
    let inbound_flows = flows.max_inbound_active_flows().get();
    let outbound_flows = flows.max_outbound_active_flows().get();
    let total_flows = inbound_flows
        .checked_add(outbound_flows)
        .ok_or_else(|| Error::Transport("fixture flow total overflowed".to_string()))?;
    let queue_slots = total_flows
        .checked_mul(flows.queue_capacity_per_flow().get())
        .ok_or_else(|| Error::Transport("fixture queue-slot total overflowed".to_string()))?;
    let inbound_units = inbound_flows
        .checked_mul(flows.max_in_progress_units_per_flow().get())
        .ok_or_else(|| Error::Transport("fixture assembly total overflowed".to_string()))?;
    let fragments = inbound_units
        .checked_mul(flows.max_inbound_fragments_per_unit().get())
        .ok_or_else(|| Error::Transport("fixture fragment total overflowed".to_string()))?;

    let mut grant = crate::resource::ResourceClaim::ZERO;
    for _ in 0..total_flows {
        add_lease(&mut grant, RealtimeFlowRegistry::flow_claim()?)?;
        add_lease(&mut grant, RealtimeFlowRegistry::ready_claim()?)?;
        // One label per flow, sized by the longest name the frame can carry.
        // The fixture cannot know what an application will call its flows, and
        // a grant derived from a shorter guess would refuse opens the policy
        // itself admits.
        add_lease(
            &mut grant,
            session_flow::RealtimeFlowLabel::mint_claim(
                crate::realtime::MAX_REALTIME_FLOW_LABEL_BYTES,
            )?,
        )?;
    }
    for _ in 0..inbound_flows {
        add_lease(&mut grant, RealtimeFlowRegistry::native_read_claim()?)?;
    }
    for _ in 0..inbound_units {
        add_lease(&mut grant, RealtimeFlowRegistry::assembly_claim()?)?;
    }
    for _ in 0..fragments {
        add_lease(
            &mut grant,
            RealtimeFlowRegistry::ordered_fragment_claim(flows.max_inbound_fragment_bytes().get())?,
        )?;
    }
    for _ in 0..queue_slots {
        add_lease(
            &mut grant,
            RealtimeFlowRegistry::output_claim(local.max_unit_bytes().get())?,
        )?;
        add_lease(
            &mut grant,
            RealtimeFlowRegistry::queue_claim(local.max_unit_bytes().get())?,
        )?;
    }
    // One packet-work lease per inbound pump, because each holds exactly one
    // for the duration of the packet it is classifying and releases it before
    // reading the next.
    //
    // Sized by the largest payload either inbound shape can present: a
    // fragmented unit is bounded per fragment, a whole-payload unit by the unit
    // ceiling, and the pump takes this lease before it knows which shape it
    // holds. Taking the larger of the two is what keeps the lab grant from
    // refusing work the policy actually admits.
    let max_packet_bytes = flows
        .max_inbound_fragment_bytes()
        .get()
        .max(local.max_unit_bytes().get());
    for _ in 0..inbound_flows {
        add_lease(
            &mut grant,
            RealtimeFlowRegistry::session_packet_work_claim(max_packet_bytes)?,
        )?;
    }
    Ok(grant)
}

/// Derive a finite resource grant for an explicit transport-lab fixture.
///
/// The caller supplies the exact connector profiles and concurrent Mesh scope
/// count exercised by the fixture. This function selects no production value
/// and is unavailable without the `transport-lab` feature.
#[cfg(any(test, feature = "transport-lab"))]
pub fn transport_lab_connector_fixture_grant(
    profiles: &[WebRtcConnectorProfile],
    mesh_scope_count: std::num::NonZeroU64,
) -> Result<crate::resource::ResourceClaim> {
    use crate::resource::FiniteResourceProvider;

    fn add(
        total: &mut crate::resource::ResourceClaim,
        claim: crate::resource::ResourceClaim,
        context: &'static str,
    ) -> Result<()> {
        *total = total.checked_add(claim).map_err(|error| {
            Error::Transport(format!(
                "fixture resource claim overflowed while adding {context}: {error}"
            ))
        })?;
        Ok(())
    }

    let structural = crate::runtime::attempt::connector_resource_structural_claims();
    let mut grant = FiniteResourceProvider::scope_record_charge_for_test();
    add(
        &mut grant,
        FiniteResourceProvider::reservation_charge_for_test(structural.process_infrastructure())
            .map_err(Error::from)?,
        "process cleanup infrastructure",
    )?;
    for _ in 0..mesh_scope_count.get() {
        add(
            &mut grant,
            FiniteResourceProvider::scope_record_charge_for_test(),
            "Mesh resource scope",
        )?;
    }

    for profile in profiles {
        add(
            &mut grant,
            FiniteResourceProvider::child_scope_with_reservation_charge_for_test(
                structural.connector_opening(),
            )
            .map_err(Error::from)?,
            "connector opening scope and reservation",
        )?;
        add(
            &mut grant,
            FiniteResourceProvider::reservation_charge_for_test(structural.connector_operation())
                .map_err(Error::from)?,
            "one fixture connector operation",
        )?;
        for callback_claim in callback::connector_construction_claims().map_err(|error| {
            Error::Transport(format!("fixture callback claim overflowed: {error}"))
        })? {
            add(
                &mut grant,
                FiniteResourceProvider::reservation_charge_for_test(callback_claim)
                    .map_err(Error::from)?,
                "connector callback construction",
            )?;
        }

        for callback_claim in callback::connector_fixture_operation_claims(profile.callbacks(), 0)
            .map_err(|error| {
            Error::Transport(format!(
                "fixture callback operation claim overflowed: {error}"
            ))
        })? {
            add(
                &mut grant,
                FiniteResourceProvider::reservation_charge_for_test(callback_claim)
                    .map_err(Error::from)?,
                "connector callback operation",
            )?;
        }

        if let RealtimeConnectorPolicy::Enabled(Some(local)) = profile.callbacks().realtime() {
            add(
                &mut grant,
                realtime_fixture_provider_grant(local)?,
                "connector real-time fixture envelope",
            )?;
        }

        // The connector's one shared, leased copy of the application's codecs.
        // Charged per profile that registers any, and only once each: a
        // promotion clones the pointer rather than the codecs.
        if let Some(realtime) = profile.realtime() {
            add(
                &mut grant,
                FiniteResourceProvider::reservation_charge_for_test(
                    session_flow::LeasedRealtimeProfile::mint_claim(realtime)
                        .map_err(Error::from)?,
                )
                .map_err(Error::from)?,
                "connector real-time profile record",
            )?;
        }
    }
    Ok(grant)
}

/// Derive a conservative finite grant for an explicit remote-candidate fixture.
///
/// Every bound comes from the caller's test workload. The result covers the
/// connector-neutral digest owner, production queue owner, parsing work, and
/// each provider reservation record. It selects no production value.
#[cfg(any(test, feature = "transport-lab"))]
pub fn transport_lab_remote_candidate_fixture_grant(
    max_unique_candidates: std::num::NonZeroU64,
    max_concurrent_digest_work: std::num::NonZeroU64,
    max_total_string_capacity: std::num::NonZeroU64,
    max_total_content_bytes: std::num::NonZeroU64,
    max_single_candidate_content_bytes: std::num::NonZeroU64,
) -> Result<crate::resource::ResourceClaim> {
    use crate::resource::{FiniteResourceProvider, ResourceClaim, ResourceClass};

    let unique = max_unique_candidates.get();
    let digest_retention =
        crate::runtime::attempt::remote_candidate_digest_retention_aggregate_claim(unique)
            .and_then(|claim| {
                claim.checked_add(ResourceClaim::single(
                    ResourceClass::OpaqueDependencyResidual,
                    unique,
                ))
            })
            .map_err(|error| {
                Error::Transport(format!(
                    "fixture candidate digest retention overflowed: {error}"
                ))
            })?;
    let digest_work = FiniteResourceProvider::reservation_charge_for_test(
        crate::runtime::attempt::remote_candidate_max_digest_work_claim(
            max_single_candidate_content_bytes.get(),
        )
        .map_err(|error| {
            Error::Transport(format!("fixture candidate digest work overflowed: {error}"))
        })?,
    )
    .map_err(Error::from)?
    .checked_scale(max_concurrent_digest_work.get())
    .map_err(|error| {
        Error::Transport(format!(
            "fixture concurrent candidate digest work overflowed: {error}"
        ))
    })?;
    let queue = pending_remote_candidate_queue_claim_with_content(0, 0)
        .and_then(|claim| claim.checked_scale(unique))
        .and_then(|claim| {
            claim.checked_add(ResourceClaim::single(
                ResourceClass::AccountedMemoryBytes,
                max_total_string_capacity.get(),
            ))
        })
        .and_then(|claim| {
            claim.checked_add(ResourceClaim::single(
                ResourceClass::QueuedBytes,
                max_total_content_bytes.get(),
            ))
        })
        .and_then(|claim| {
            claim.checked_add(ResourceClaim::single(
                ResourceClass::OpaqueDependencyResidual,
                unique,
            ))
        })
        .map_err(|error| {
            Error::Transport(format!("fixture candidate queue claim overflowed: {error}"))
        })?;
    digest_retention
        .checked_add(digest_work)
        .and_then(|claim| claim.checked_add(queue))
        .map_err(|error| Error::Transport(format!("fixture candidate grant overflowed: {error}")))
}

/// Derive a conservative finite grant for explicit remote-SDP fixture shapes.
///
/// The caller supplies the maximum raw input, media-section, active-binding,
/// and retained credential-string shape for each concurrent connector. This
/// helper is unavailable from the default V4 API and selects no production
/// value.
#[cfg(any(test, feature = "transport-lab"))]
pub fn transport_lab_remote_description_fixture_grant(
    concurrent_connectors: std::num::NonZeroU64,
    max_input_capacity: std::num::NonZeroU64,
    max_media_sections: std::num::NonZeroU64,
    max_active_bindings: std::num::NonZeroU64,
    max_retained_credential_string_bytes: std::num::NonZeroU64,
) -> Result<crate::resource::ResourceClaim> {
    use crate::resource::{FiniteResourceProvider, ResourceClaim, ResourceClass};

    let input_capacity = usize::try_from(max_input_capacity.get()).map_err(|_| {
        Error::Transport("fixture remote-SDP input capacity does not fit usize".to_string())
    })?;
    let media_count = usize::try_from(max_media_sections.get()).map_err(|_| {
        Error::Transport("fixture remote-SDP media count does not fit usize".to_string())
    })?;
    let binding_count = usize::try_from(max_active_bindings.get()).map_err(|_| {
        Error::Transport("fixture remote-SDP binding count does not fit usize".to_string())
    })?;
    if binding_count > media_count {
        return Err(Error::Transport(
            "fixture active remote-SDP bindings exceed its media sections".to_string(),
        ));
    }
    let string_bytes =
        usize::try_from(max_retained_credential_string_bytes.get()).map_err(|_| {
            Error::Transport(
                "fixture remote-SDP credential string size does not fit usize".to_string(),
            )
        })?;
    let plan = RemoteIceCredentialAllocationPlan {
        media_count,
        binding_count,
        string_bytes,
    };
    let claims = [
        remote_description_operation_claim(input_capacity),
        planned_remote_description_claim(plan, input_capacity),
        retained_remote_description_claim_from_plan(plan, input_capacity, true),
        retained_remote_description_claim_from_plan(plan, input_capacity, false),
    ];
    let mut peak = ResourceClaim::ZERO;
    for claim in claims {
        let claim = claim.map_err(|error| {
            Error::Transport(format!("fixture remote-SDP claim overflowed: {error}"))
        })?;
        peak = ResourceClaim::try_from_entries(ResourceClass::ALL.into_iter().map(|dimension| {
            (
                dimension,
                peak.amount(dimension).max(claim.amount(dimension)),
            )
        }))
        .map_err(|error| {
            Error::Transport(format!("fixture remote-SDP peak overflowed: {error}"))
        })?;
    }
    FiniteResourceProvider::reservation_charge_for_test(peak)
        .map_err(Error::from)?
        .checked_scale(concurrent_connectors.get())
        .map_err(|error| Error::Transport(format!("fixture remote-SDP grant overflowed: {error}")))
}

#[cfg(test)]
pub(crate) fn one_mesh_connector_fixture_grant(
    profiles: &[WebRtcConnectorProfile],
) -> Result<crate::resource::ResourceClaim> {
    transport_lab_connector_fixture_grant(
        profiles,
        std::num::NonZeroU64::new(1).expect("one Mesh fixture scope is nonzero"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::{
        FiniteResourceProvider, ProcessResourceRoot, ResourceFamilyReport, ResourceProviderPort,
        PRE_AUTH_RESOURCE_FAMILY_COUNT,
    };
    use crate::runtime::attempt::{
        ConnectorCallbackServiceWeights, ConnectorRealtimeByteBudgets,
        ConnectorRealtimeFlowCapacities, ConnectorRealtimeFlowPolicy,
        ConnectorRealtimeInboundLimits, ConnectorResourceOwnerPort,
    };
    use std::future::Future;
    use std::sync::atomic::AtomicUsize;
    use std::task::{Context, Poll, Waker};

    // Explicit fixture input shared by the native loopback controls. It is
    // not a production default or an operational sufficiency claim.
    const NATIVE_LOOPBACK_CALLBACK_CAPACITY: usize = 32;

    fn test_resource_owner(
        max_active_candidates: usize,
        callback_capacity: usize,
    ) -> MeshConnectorResourceScope {
        let max_active_candidates = std::num::NonZeroUsize::new(max_active_candidates)
            .expect("fixture has a nonzero candidate bound");
        let profiles = vec![test_webrtc_profile(callback_capacity); max_active_candidates.get()];
        let connector_grant = transport_lab_connector_fixture_grant(
            &profiles,
            std::num::NonZeroU64::new(1).expect("the fixture Mesh scope count is nonzero"),
        )
        .expect("fixture connector and callback claims are representable");
        let provider = ResourceProviderPort::new(FiniteResourceProvider::new(connector_grant))
            .expect("fixture provider accounts for its process scope");
        crate::runtime::attempt::ConnectorResourceOwnerPort::new(provider)
            .issue_mesh_scope()
            .expect("fixture process owner issues one explicit Mesh scope")
    }

    fn test_webrtc_profile(callback_capacity: usize) -> WebRtcConnectorProfile {
        let callback_capacity =
            NonZeroUsize::new(callback_capacity).expect("fixture callback capacity is nonzero");
        let callbacks = ConnectorCallbackPolicy::new(
            crate::runtime::attempt::ConnectorCallbackMailboxCapacities::new(
                callback_capacity,
                callback_capacity,
            ),
            ConnectorCallbackServiceWeights::data_only(callback_capacity, callback_capacity),
            RealtimeConnectorPolicy::Disabled,
        )
        .expect("fixture callback policy is valid");
        WebRtcConnectorProfile::new(callbacks, PendingRemoteCandidatePolicy::elastic())
    }

    fn test_generic_realtime_webrtc_profile(_callback_capacity: usize) -> WebRtcConnectorProfile {
        WebRtcConnectorProfile::new(
            explicit_realtime_callback_policy(8, 1, 1, 8, 1, 16),
            PendingRemoteCandidatePolicy::elastic(),
        )
    }

    fn close_owner_fixture(
        owner: &MeshConnectorResourceScope,
    ) -> (Arc<ConnectorCloseOwner>, AttemptLifetime) {
        let (permit, lifetime, claim) =
            admit_single_connector_candidate(crate::runtime::runtime_for_test(), owner.clone());
        let mut candidate = permit
            .reserve_connector_candidate(claim)
            .expect("fixture owner admits one candidate");
        let cleanup_capability = candidate
            .issue_cleanup_capability()
            .expect("fixture candidate issues one cleanup capability");
        let ownership = admitted_ownership(candidate);
        (
            ConnectorCloseOwner::new(ownership, owner.clone(), cleanup_capability),
            lifetime,
        )
    }

    fn connected_claim_fixture(
        owner: &MeshConnectorResourceScope,
    ) -> (
        crate::connector::ConnectedChannelCapability,
        AttemptLifetime,
    ) {
        let (permit, lifetime, claim) =
            admit_single_connector_candidate(crate::runtime::runtime_for_test(), owner.clone());
        let candidate = permit
            .reserve_connector_candidate(claim)
            .expect("fixture owner admits connected candidate");
        let connected = crate::connector::mark_connected(candidate)
            .expect("fixture attempt remains live through promotion");
        (connected, lifetime)
    }

    /// A native-close hold point for controls, built on stored state.
    ///
    /// `Notify` is the wrong primitive for this seam. `TestNativeClosePort`
    /// records its call *synchronously*, before the future it returns is ever
    /// polled, so the call counter goes up while the close is still short of the
    /// hold point. A control that keys off that counter can therefore release in
    /// the window between "call recorded" and "close actually parked", and
    /// `notify_waiters` stores nothing: a release landing in that window is
    /// dropped and the control waits forever instead of failing.
    ///
    /// Both halves here are `watch` channels, which carry their value rather
    /// than only waking whoever is already parked. A release published before
    /// the close parks is still observed, and an entry published before the
    /// control looks is still counted, so no scheduling order can lose either
    /// signal. This mirrors the production-side `NativeCloseGate` for the same
    /// reason.
    struct TestNativeCloseGate {
        /// How many closes have reached the hold point. A `watch` rather than a
        /// bare counter so a control can await the first entry deterministically
        /// instead of spinning on a load.
        entries: watch::Sender<usize>,
        /// The stored permit. Held closes proceed once this is `true`.
        open: watch::Sender<bool>,
    }

    impl TestNativeCloseGate {
        fn new() -> Arc<Self> {
            let (entries, _entries_receiver) = watch::channel(0usize);
            let (open, _open_receiver) = watch::channel(false);
            Arc::new(Self { entries, open })
        }

        /// Record this entry, then park until a control opens the gate.
        ///
        /// The subscription is taken *before* the entry is published, so a
        /// control that observes the entry is observing a close that is already
        /// able to see the release. The permit is stored regardless, so the
        /// ordering here is belt and braces rather than the correctness
        /// argument.
        async fn hold(&self) {
            let mut open = self.open.subscribe();
            self.entries.send_modify(|count| *count += 1);
            loop {
                // The borrow is released before the await: holding a `watch`
                // guard across a suspension point would block every sender.
                if *open.borrow() {
                    return;
                }
                if open.changed().await.is_err() {
                    return;
                }
            }
        }

        /// How many closes have reached the hold point.
        fn entries(&self) -> usize {
            *self.entries.borrow()
        }

        /// Park until at least one close has reached the hold point.
        ///
        /// Resolves on the entry itself rather than by polling a counter.
        /// Callers bound it with a deadline so a close that never arrives fails
        /// the control rather than hanging it.
        async fn wait_for_entry(&self) {
            let mut entries = self.entries.subscribe();
            loop {
                if *entries.borrow() > 0 {
                    return;
                }
                if entries.changed().await.is_err() {
                    return;
                }
            }
        }

        /// Let every held close proceed. Idempotent, and the permit is stored,
        /// so this can never be published too early to be observed.
        fn open(&self) {
            self.open.send_replace(true);
        }
    }

    enum TestNativeCloseResult {
        Success,
        Error,
        Gate(Arc<TestNativeCloseGate>),
    }

    struct TestNativeClosePort {
        result: TestNativeCloseResult,
        calls: Arc<AtomicUsize>,
    }

    impl NativeConnectorClosePort for TestNativeClosePort {
        fn close(&self) -> NativeCloseFuture<'_> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            Box::pin(async move {
                match &self.result {
                    TestNativeCloseResult::Success => Ok(()),
                    TestNativeCloseResult::Error => Err(Error::Transport(
                        "injected native close failure".to_string(),
                    )),
                    TestNativeCloseResult::Gate(gate) => {
                        gate.hold().await;
                        Ok(())
                    }
                }
            })
        }
    }

    fn candidate_report(
        reports: &[ResourceFamilyReport<PreAuthResourceFamily>; PRE_AUTH_RESOURCE_FAMILY_COUNT],
    ) -> ResourceFamilyReport<PreAuthResourceFamily> {
        *reports
            .iter()
            .find(|report| report.family == PreAuthResourceFamily::CandidateObject)
            .expect("candidate family is present")
    }

    fn observed_candidate() -> LocalIceCandidate {
        let candidate_fixture = "candidate:foundation 1 udp 2113937151 192.0.2.1 5000 typ host";
        let mut candidate =
            String::with_capacity(candidate_fixture.len() + "candidate-slack".len());
        candidate.push_str(candidate_fixture);

        let mid_fixture = "data";
        let mut sdp_mid = String::with_capacity(mid_fixture.len() + "mid-slack".len());
        sdp_mid.push_str(mid_fixture);

        let username_fixture = "remote-fragment";
        let mut username_fragment =
            String::with_capacity(username_fixture.len() + "fragment-slack".len());
        username_fragment.push_str(username_fixture);

        LocalIceCandidate {
            candidate,
            sdp_mid: Some(sdp_mid),
            sdp_mline_index: None,
            username_fragment: Some(username_fragment),
        }
    }

    fn exact_ice_sdp(username_fragment: &str, password: &str, fingerprint: &str) -> String {
        format!(
            "v=0\r\n\
             o=- 1 2 IN IP4 127.0.0.1\r\n\
             a=group:BUNDLE data\r\n\
             a=ice-ufrag:{username_fragment}\r\n\
             a=ice-pwd:{password}\r\n\
             a=fingerprint:sha-256 {fingerprint}\r\n\
             m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
             a=mid:data\r\n"
        )
    }

    fn test_pending_candidate_policy() -> PendingRemoteCandidatePolicy {
        test_pending_candidate_policy_for(&[])
    }

    fn test_pending_candidate_policy_for(
        additional_inputs: &[LocalIceCandidate],
    ) -> PendingRemoteCandidatePolicy {
        let candidate_bytes = std::iter::once(observed_candidate())
            .chain(additional_inputs.iter().cloned())
            .filter_map(|candidate| candidate_content_bytes(&candidate))
            .max()
            .and_then(NonZeroUsize::new)
            .expect("fixture candidate has nonzero representable content");
        PendingRemoteCandidatePolicy::new(
            NonZeroUsize::new(1).expect("fixture item ceiling is nonzero"),
            candidate_bytes,
            NonZeroUsize::new(1).expect("fixture duplicate ceiling is nonzero"),
            NonZeroUsize::new(1).expect("fixture work ceiling is nonzero"),
        )
    }

    fn test_remote_candidate_state() -> RemoteCandidateState {
        RemoteCandidateState::new(test_pending_candidate_policy())
    }

    /// Build a finite test provider from the local fixture envelope. This is
    /// test accounting only. It is not a product cardinality or a production
    /// policy value.
    fn test_realtime_resource_scope(
        local: EnabledRealtimeConnectorPolicy,
    ) -> ConnectorWorkResourceScope {
        // One control profile per fixture registry, charged here rather than in
        // the shared envelope helper: the envelope describes flows, and which
        // profile a fixture registers is this module's fact.
        let profile_claim = FiniteResourceProvider::reservation_charge_for_test(
            session_flow::LeasedRealtimeProfile::mint_claim(
                &session_flow::control_realtime_profile(),
            )
            .expect("the control profile claim is representable"),
        )
        .expect("the control profile reservation is representable");
        let grant = crate::runtime::attempt::explicit_test_grant(1, 1)
            .checked_add(
                realtime_fixture_provider_grant(local)
                    .expect("fixture real-time envelope is representable"),
            )
            .and_then(|grant| grant.checked_add(profile_claim))
            .expect("fixture provider grant is representable");

        let provider = ResourceProviderPort::new(FiniteResourceProvider::new(grant))
            .expect("the derived fixture grant accounts for its process scope");
        let mesh = ConnectorResourceOwnerPort::new(provider)
            .issue_mesh_scope()
            .expect("the derived fixture grant accounts for its Mesh scope");
        let (permit, _attempt, claim) =
            admit_single_connector_candidate(crate::runtime::runtime_for_test(), mesh);
        let candidate = permit
            .reserve_connector_candidate(claim)
            .expect("the derived fixture grant admits its connector candidate");
        candidate.work_resource_scope()
    }

    fn test_realtime_registry(policy: ConnectorCallbackPolicy) -> Arc<RealtimeFlowRegistry> {
        match policy.realtime() {
            RealtimeConnectorPolicy::Disabled => RealtimeFlowRegistry::new(None, None),
            RealtimeConnectorPolicy::Enabled(Some(local)) => {
                RealtimeFlowRegistry::new(Some(test_realtime_resource_scope(local)), Some(local))
            }
            RealtimeConnectorPolicy::Enabled(None) => {
                panic!("an elastic real-time test must supply its exact provider fixture")
            }
        }
    }

    fn test_realtime_registry_with_observer(
        policy: ConnectorCallbackPolicy,
        observer: Arc<dyn RealtimeFlowObserver>,
    ) -> Arc<RealtimeFlowRegistry> {
        let RealtimeConnectorPolicy::Enabled(Some(local)) = policy.realtime() else {
            panic!("an observed real-time test requires an explicit local fixture envelope");
        };
        RealtimeFlowRegistry::with_observer(
            Some(test_realtime_resource_scope(local)),
            Some(local),
            Some(observer),
        )
    }

    /// The one real-time payload the shared callback fixture is sized for.
    ///
    /// `test_callback_policy` derives its unit ceiling, fragment ceiling and
    /// retained-byte envelope from this exact length, so a control that emits
    /// any *other* payload through that policy is either refused as oversize or
    /// silently given slack the policy never promised. Both are arrangement
    /// failures wearing the costume of a result, which is why there is one
    /// constant rather than a literal at each site.
    const FIXTURE_REALTIME_PAYLOAD: &[u8] = b"realtime-unit";

    fn test_callback_policy(capacity: NonZeroUsize) -> ConnectorCallbackPolicy {
        let unit_bytes = FIXTURE_REALTIME_PAYLOAD.len();
        let flow_domains = 2usize;
        let accounted_bytes = unit_bytes
            .checked_mul(capacity.get())
            .and_then(|bytes| bytes.checked_mul(flow_domains))
            .and_then(|bytes| bytes.checked_mul(2))
            .and_then(NonZeroUsize::new)
            .expect("fixture retained-byte envelope is representable and nonzero");
        let flows = ConnectorRealtimeFlowPolicy::new(
            ConnectorRealtimeFlowCapacities::new(
                NonZeroUsize::new(flow_domains).expect("fixture has two flow kinds"),
                NonZeroUsize::new(flow_domains).expect("fixture has two flow kinds"),
                capacity,
            ),
            ConnectorRealtimeInboundLimits::new(
                NonZeroUsize::new(unit_bytes).expect("fixture unit is nonempty"),
                NonZeroUsize::new(1).expect("fixture uses complete units"),
                NonZeroUsize::new(1).expect("fixture uses one in-progress unit"),
            ),
            ConnectorRealtimeByteBudgets::new(accounted_bytes, accounted_bytes),
            crate::runtime::attempt::RealtimeQueueOverflowRule::DropNewest,
        );
        let realtime = RealtimeConnectorPolicy::enabled_with_local_ceiling(
            NonZeroUsize::new(unit_bytes).expect("fixture unit is nonempty"),
            flows,
        )
        .expect("fixture real-time envelope is internally consistent");
        ConnectorCallbackPolicy::new(
            crate::runtime::attempt::ConnectorCallbackMailboxCapacities::new(capacity, capacity),
            ConnectorCallbackServiceWeights::new(capacity, capacity, capacity),
            realtime,
        )
        .expect("fixture callback policy is valid")
    }

    fn retained_realtime_bytes(state: &RealtimeFlowRegistryState) -> usize {
        state
            .retained_bytes_by_domain
            .into_iter()
            .try_fold(0usize, usize::checked_add)
            .expect("fixture real-time accounting total is representable")
    }

    fn realtime_accounting_is_clean(state: &RealtimeFlowRegistryState) -> bool {
        state.accounting_poisoned_by_domain == [false, false]
    }

    fn admitted_ownership(candidate: ConnectorCandidateCapability) -> ConnectorOwnership {
        let work_resource_scope = candidate.work_resource_scope();
        ConnectorOwnership::admitted(
            candidate,
            Arc::new(ConnectorOperationFence::default()),
            work_resource_scope,
            Arc::new(AtomicBool::new(false)),
            Arc::new(WebRtcConnectorIncarnation::new()),
        )
    }

    fn test_event_mailboxes(capacity: usize) -> (ConnectorEventMailboxes, TransportEventReceiver) {
        let capacity =
            std::num::NonZeroUsize::new(capacity).expect("fixture callback capacity is nonzero");
        test_event_mailboxes_with_policy(test_callback_policy(capacity))
    }

    fn test_event_mailboxes_with_policy(
        policy: ConnectorCallbackPolicy,
    ) -> (ConnectorEventMailboxes, TransportEventReceiver) {
        let capacities = policy
            .local_mailboxes()
            .expect("fixture callback mailboxes are explicit");
        let callback_producer = CallbackProducerOwner::for_local_lab_policy(policy)
            .expect("fixture callback resources are derivable from its local policy");
        let realtime_flows = test_realtime_registry(policy);
        let callback_ready = Arc::new(tokio::sync::Notify::new());
        let control = callback_producer
            .create_mailbox(
                ConnectorCallbackClass::Control,
                Some(capacities.control()),
                Arc::clone(&callback_ready),
            )
            .expect("fixture control mailbox is admitted");
        let endpoint_data = callback_producer
            .create_mailbox(
                ConnectorCallbackClass::EndpointData,
                Some(capacities.endpoint_data()),
                Arc::clone(&callback_ready),
            )
            .expect("fixture endpoint mailbox is admitted");
        let open_work = callback_producer
            .reserve_lifecycle_delivery()
            .expect("fixture open lifecycle work is reserved");
        let close_work = callback_producer
            .reserve_lifecycle_delivery()
            .expect("fixture close lifecycle work is reserved");
        let lifecycle = Arc::new(ConnectorLifecycleOwner::with_reserved_lifecycle_work(
            open_work, close_work,
        ));
        (
            ConnectorEventMailboxes {
                control: Arc::clone(&control),
                endpoint_data: Arc::clone(&endpoint_data),
                lifecycle: Arc::clone(&lifecycle),
                callback_producer,
            },
            TransportEventReceiver {
                control,
                endpoint_data,
                lifecycle,
                lifecycle_closed: false,
                callback_ready,
                callback_failed: false,
                realtime_flows,
                scheduler: ConnectorCallbackScheduler::new(policy),
                control_cursor: ConnectorControlSourceCursor::default(),
            },
        )
    }

    fn test_event_sink(
        events: ConnectorEventMailboxes,
        policy: ConnectorCallbackPolicy,
        resource_scope: Option<PeerConnectionResourceScope>,
    ) -> ConnectorEventSink {
        let callback_producer = events.callback_producer.clone();
        ConnectorEventSink {
            events,
            realtime_flows: test_realtime_registry(policy),
            resource_scope,
            attempt_liveness: None,
            candidate_promoted: Arc::new(AtomicBool::new(true)),
            callback_gate: Arc::new(WebRtcConnectorIncarnation::new()),
            callback_violation_reported: Arc::new(AtomicBool::new(false)),
            callback_policy: policy,
            callback_producer,
            operation_fence: Arc::new(ConnectorOperationFence::default()),
            close_owner: None,
        }
    }

    fn test_event_sink_for_receiver(
        events: ConnectorEventMailboxes,
        policy: ConnectorCallbackPolicy,
        resource_scope: Option<PeerConnectionResourceScope>,
        receiver: &TransportEventReceiver,
    ) -> ConnectorEventSink {
        let mut sink = test_event_sink(events, policy, resource_scope);
        sink.realtime_flows = Arc::clone(&receiver.realtime_flows);
        sink
    }

    fn explicit_callback_policy(
        capacity: usize,
        control_weight: usize,
        endpoint_data_weight: usize,
        realtime_weight: usize,
        realtime: RealtimeConnectorPolicy,
    ) -> ConnectorCallbackPolicy {
        let capacity =
            std::num::NonZeroUsize::new(capacity).expect("fixture callback capacity is nonzero");
        ConnectorCallbackPolicy::new(
            crate::runtime::attempt::ConnectorCallbackMailboxCapacities::new(capacity, capacity),
            ConnectorCallbackServiceWeights::new(
                std::num::NonZeroUsize::new(control_weight)
                    .expect("fixture control weight is nonzero"),
                std::num::NonZeroUsize::new(endpoint_data_weight)
                    .expect("fixture endpoint-data weight is nonzero"),
                std::num::NonZeroUsize::new(realtime_weight)
                    .expect("fixture real-time weight is nonzero"),
            ),
            realtime,
        )
        .expect("fixture callback policy is valid")
    }

    fn explicit_realtime_callback_policy(
        max_unit_bytes: usize,
        max_active_flows_per_domain: usize,
        queue_capacity_per_flow: usize,
        max_inbound_fragment_bytes: usize,
        max_in_progress_units_per_flow: usize,
        max_accounted_bytes: usize,
    ) -> ConnectorCallbackPolicy {
        let nonzero = |value, name| {
            std::num::NonZeroUsize::new(value)
                .unwrap_or_else(|| panic!("fixture {name} must be nonzero"))
        };
        let flows = ConnectorRealtimeFlowPolicy::new(
            ConnectorRealtimeFlowCapacities::new(
                nonzero(max_active_flows_per_domain, "inbound flow count"),
                nonzero(max_active_flows_per_domain, "outbound flow count"),
                nonzero(queue_capacity_per_flow, "per-flow queue capacity"),
            ),
            ConnectorRealtimeInboundLimits::new(
                nonzero(max_inbound_fragment_bytes, "fragment limit"),
                // The fixture is the owner here, so it names its own ceiling
                // rather than borrowing a core constant. It used to read a
                // shared `MAX_AU_PARTS`; core no longer has one, because a
                // per-unit fragment count is exactly the kind of number an
                // owner chooses and core cannot. The value is the one these
                // controls were written against, so their arithmetic is
                // unchanged — it is now stated where it is chosen.
                nonzero(2_048, "fixture per-unit fragment count"),
                nonzero(
                    max_in_progress_units_per_flow,
                    "per-flow in-progress unit limit",
                ),
            ),
            ConnectorRealtimeByteBudgets::new(
                nonzero(max_accounted_bytes, "inbound accounted-byte limit"),
                nonzero(max_accounted_bytes, "outbound accounted-byte limit"),
            ),
            crate::runtime::attempt::RealtimeQueueOverflowRule::DropNewest,
        );
        let realtime = RealtimeConnectorPolicy::enabled_with_local_ceiling(
            nonzero(max_unit_bytes, "unit limit"),
            flows,
        )
        .expect("fixture real-time policy can carry one guarded assembly");
        explicit_callback_policy(1, 1, 1, 1, realtime)
    }

    #[derive(Default)]
    struct TestRealtimeObserver {
        observations: SyncMutex<Vec<RealtimeFlowObservation>>,
    }

    impl RealtimeFlowObserver for TestRealtimeObserver {
        fn observe(&self, observation: RealtimeFlowObservation) {
            self.observations.lock().push(observation);
        }
    }

    struct PanickingRealtimeObserver;

    impl RealtimeFlowObserver for PanickingRealtimeObserver {
        fn observe(&self, _observation: RealtimeFlowObservation) {
            panic!("injected observation-only callback failure");
        }
    }

    fn stamped_event(
        ownership: &ConnectorOwnership,
        event: TransportEvent,
    ) -> WebRtcConnectorEvent {
        WebRtcConnectorEvent {
            incarnation: Arc::clone(&ownership.incarnation),
            event,
            _queue_observation: None,
            _callback_work: None,
        }
    }

    /// A leased label for one fixture flow.
    ///
    /// The controls in this module care *which* flow a delivery is on rather
    /// than what its name spells, so they keep naming flows by number — but
    /// what they get back is a real minted label over a shared elastic control
    /// registry, because a hand-built label is not the shape production ever
    /// produces. Two calls with the same number compare equal, which is what
    /// the demultiplexing assertions rely on.
    ///
    /// It stands on the crate's shared control scope, which is deliberately
    /// never retired: a fixture label can be retained by a queued event that
    /// outlives the control that made it.
    fn test_label(number: u8) -> RealtimeFlowLabel {
        control_label_for_test(
            &RealtimeFlowName::new(format!("flow-{number}").into_bytes())
                .expect("a fixture name is within the frame bound"),
        )
    }

    /// The raw name a fixture flow is opened under, before any session has
    /// accepted it and minted a lease for it.
    fn fixture_flow_name() -> RealtimeFlowName {
        RealtimeFlowName::new(b"fixture-flow".to_vec())
            .expect("the fixture name is within the frame bound")
    }

    /// One inbound delivery shaped exactly as the session pump builds one: a
    /// label this side minted and an opaque unit, with no lease attached —
    /// the queue mints that at enqueue.
    fn test_realtime_event(label: u8, timestamp: u32, data: &'static [u8]) -> TransportEvent {
        TransportEvent::RealtimeUnit(RealtimeInboundDelivery::new(
            test_label(label),
            RealtimeRecvUnit {
                timestamp,
                marker: true,
                data: Bytes::from_static(data),
            },
        ))
    }

    async fn assert_callback_class_has_independent_capacity(
        first: TransportEvent,
        second: TransportEvent,
    ) {
        let (events, mut receiver) = test_event_mailboxes(1);
        let policy = test_callback_policy(
            std::num::NonZeroUsize::new(1).expect("fixture capacity is nonzero"),
        );
        let sink = test_event_sink_for_receiver(events, policy, None, &receiver);
        assert!(sink.emit(first).await);
        let mut retained_flow = None;
        match second {
            event @ TransportEvent::RealtimeUnit(_) => {
                let TransportEvent::RealtimeUnit(delivery) = &event else {
                    unreachable!("the arm matched a real-time unit");
                };
                let payload_bytes = delivery.payload_bytes();
                let flow = sink
                    .open_inbound_realtime_flow()
                    .expect("fixture admits one exact real-time flow");
                let reservation = flow
                    .reserve_output(payload_bytes)
                    .expect("fixture reserves the exact complete unit");
                assert!(sink.emit_realtime(&flow, event, reservation));
                retained_flow = Some(flow);
            }
            event => assert!(sink.emit(event).await),
        }
        assert!(receiver.try_recv().is_ok());
        assert!(receiver.try_recv().is_ok());
        drop(retained_flow);
    }

    #[tokio::test]
    async fn v4_arc03_control_and_data_callback_capacity_are_independent() {
        assert_callback_class_has_independent_capacity(
            TransportEvent::DataChannelOpen,
            TransportEvent::Message(Bytes::from_static(b"endpoint-data")),
        )
        .await;
    }

    #[tokio::test]
    async fn v4_arc03_control_and_realtime_callback_capacity_are_independent() {
        // The payload the shared policy is sized for. A longer one would be
        // refused as oversize before the two classes were ever compared, and
        // this control would report a capacity conclusion it had not reached.
        assert_callback_class_has_independent_capacity(
            TransportEvent::DataChannelOpen,
            test_realtime_event(0, 0, FIXTURE_REALTIME_PAYLOAD),
        )
        .await;
    }

    #[tokio::test]
    async fn v4_arc03_endpoint_data_and_realtime_callback_capacity_are_independent() {
        let (events, mut receiver) = test_event_mailboxes(1);
        let policy = test_callback_policy(
            std::num::NonZeroUsize::new(1).expect("fixture capacity is nonzero"),
        );
        let sink = test_event_sink_for_receiver(events, policy, None, &receiver);
        assert!(
            sink.emit(TransportEvent::Message(Bytes::from_static(b"data")))
                .await
        );
        let first_flow = sink
            .open_inbound_realtime_flow()
            .expect("fixture admits the first real-time flow");
        let first_reservation = first_flow
            .reserve_output(5)
            .expect("fixture reserves the first unit");
        assert!(sink.emit_realtime(
            &first_flow,
            test_realtime_event(0, 0, b"first"),
            first_reservation
        ));
        assert!(receiver.try_recv().is_ok());
        assert!(receiver.try_recv().is_ok());
        let second_flow = sink
            .open_inbound_realtime_flow()
            .expect("fixture admits the second real-time flow");
        let second_reservation = second_flow
            .reserve_output(5)
            .expect("fixture reserves the second unit");
        assert!(sink.emit_realtime(
            &second_flow,
            test_realtime_event(1, 0, b"secnd"),
            second_reservation
        ));
        assert!(receiver.try_recv().is_ok());
    }

    #[tokio::test]
    async fn v4_arc03i_close_supersedes_prequeued_endpoint_data_without_hidden_producers() {
        let one = NonZeroUsize::new(1).expect("one is nonzero");
        let policy = ConnectorCallbackPolicy::new(
            crate::runtime::attempt::ConnectorCallbackMailboxCapacities::new(one, one),
            ConnectorCallbackServiceWeights::data_only(one, one),
            RealtimeConnectorPolicy::Disabled,
        )
        .expect("data-only fixture policy is valid");
        let (events, mut receiver) = test_event_mailboxes_with_policy(policy);
        let sink = test_event_sink_for_receiver(events, policy, None, &receiver);

        assert!(
            sink.emit_data_channel(TransportEvent::Message(Bytes::from_static(b"before-close")))
                .await
        );
        assert_eq!(
            sink.try_emit_data_channel(TransportEvent::Message(Bytes::from_static(b"overload")))
                .await,
            ConnectorCallbackInsertResult::Overloaded,
            "a full mailbox returns typed overload without parking a producer"
        );

        assert!(
            sink.emit_data_channel(TransportEvent::DataChannelClosed)
                .await
        );
        assert!(
            sink.emit_data_channel(TransportEvent::Message(Bytes::from_static(b"after-close")))
                .await,
            "a causally later message is discarded after the close commit"
        );

        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::DataChannelClosed)
        ));
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn v4_arc03i_open_and_close_do_not_depend_on_control_mailbox_capacity() {
        let one = NonZeroUsize::new(1).expect("one is nonzero");
        let policy = ConnectorCallbackPolicy::new(
            crate::runtime::attempt::ConnectorCallbackMailboxCapacities::new(one, one),
            ConnectorCallbackServiceWeights::data_only(one, one),
            RealtimeConnectorPolicy::Disabled,
        )
        .expect("data-only fixture policy is valid");
        let (events, mut receiver) = test_event_mailboxes_with_policy(policy);
        let sink = test_event_sink_for_receiver(events, policy, None, &receiver);

        assert!(sink.emit(TransportEvent::LocalIceCandidate(None)).await);
        assert_eq!(
            sink.try_emit_data_channel(TransportEvent::DataChannelOpen)
                .await,
            ConnectorCallbackInsertResult::Queued
        );
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::DataChannelOpen)
        ));
        assert!(receiver.lifecycle.commit_open());

        assert_eq!(
            sink.try_emit_data_channel(TransportEvent::DataChannelClosed)
                .await,
            ConnectorCallbackInsertResult::Queued
        );
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::DataChannelClosed)
        ));
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn v4_arc03i_close_supersedes_an_uncommitted_open_exactly_once() {
        let (events, mut receiver) = test_event_mailboxes(1);
        let policy = test_callback_policy(NonZeroUsize::new(1).expect("one is nonzero"));
        let sink = test_event_sink_for_receiver(events, policy, None, &receiver);

        assert_eq!(
            sink.try_emit_data_channel(TransportEvent::DataChannelOpen)
                .await,
            ConnectorCallbackInsertResult::Queued
        );
        assert_eq!(
            sink.try_emit_data_channel(TransportEvent::DataChannelClosed)
                .await,
            ConnectorCallbackInsertResult::Queued
        );
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::DataChannelClosed)
        ));
        assert!(!receiver.lifecycle.commit_open());
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn v4_arc03i_candidate_and_gathering_overload_retires_the_connector() {
        let one = NonZeroUsize::new(1).expect("one is nonzero");
        let policy = ConnectorCallbackPolicy::new(
            crate::runtime::attempt::ConnectorCallbackMailboxCapacities::new(one, one),
            ConnectorCallbackServiceWeights::data_only(one, one),
            RealtimeConnectorPolicy::Disabled,
        )
        .expect("data-only fixture policy is valid");
        let (events, mut receiver) = test_event_mailboxes_with_policy(policy);
        let sink = test_event_sink_for_receiver(events, policy, None, &receiver);

        assert!(
            sink.emit(TransportEvent::LocalIceCandidate(
                Some(observed_candidate())
            ))
            .await
        );
        assert!(
            !sink.emit(TransportEvent::LocalIceCandidate(None)).await,
            "gathering completion reports overload instead of disappearing"
        );
        assert_eq!(
            receiver.lifecycle.phase(),
            ConnectorLifecyclePhase::ClosedPending
        );
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::DataChannelClosed)
        ));
    }

    #[tokio::test]
    async fn v4_arc03i_renegotiation_and_state_observations_are_coalesced() {
        let (events, mut receiver) = test_event_mailboxes(1);
        let policy = test_callback_policy(NonZeroUsize::new(1).expect("one is nonzero"));
        let sink = test_event_sink_for_receiver(events, policy, None, &receiver);

        assert!(sink.emit(TransportEvent::RenegotiationNeeded).await);
        assert!(sink.emit(TransportEvent::RenegotiationNeeded).await);
        assert!(
            sink.emit(TransportEvent::IceConnectionStateChanged(
                RTCIceConnectionState::Checking,
            ))
            .await
        );
        assert!(
            sink.emit(TransportEvent::IceConnectionStateChanged(
                RTCIceConnectionState::Connected,
            ))
            .await
        );

        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::RenegotiationNeeded)
        ));
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::IceConnectionStateChanged(
                RTCIceConnectionState::Connected
            ))
        ));
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn v4_arc03i_first_structural_violation_retires_once() {
        let (events, mut receiver) = test_event_mailboxes(1);
        let policy = test_callback_policy(NonZeroUsize::new(1).expect("one is nonzero"));
        let sink = test_event_sink_for_receiver(events, policy, None, &receiver);

        sink.structural_violation("first fixture violation");
        sink.structural_violation("second fixture violation");
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::DataChannelClosed)
        ));
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn v4_arc03_structural_violation_starts_native_cleanup_without_receiver_polling() {
        let owner = test_resource_owner(1, 1);
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        let close_calls = Arc::new(AtomicUsize::new(0));
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Success,
                calls: Arc::clone(&close_calls),
            }))
        );
        let (events, receiver) = test_event_mailboxes(1);
        let policy = test_callback_policy(NonZeroUsize::new(1).expect("one is nonzero"));
        let mut sink = test_event_sink_for_receiver(events, policy, None, &receiver);
        sink.close_owner = Some(Arc::downgrade(&close_owner));

        sink.structural_violation("fixture violation");
        tokio::time::timeout(Duration::from_secs(1), close_owner.wait())
            .await
            .expect("cleanup completes without consuming the lifecycle event")
            .expect("the deterministic native close succeeds");
        assert_eq!(close_calls.load(Ordering::Acquire), 1);
        assert_eq!(
            receiver.lifecycle.phase(),
            ConnectorLifecyclePhase::ClosedPending,
            "the proof does not depend on polling the close event"
        );
    }

    #[tokio::test]
    async fn v4_arc03_recorded_close_survives_connector_retirement_to_engine_delivery() {
        let owner = test_resource_owner(1, 1);
        let (close_owner, lifetime) = close_owner_fixture(&owner);
        let close_calls = Arc::new(AtomicUsize::new(0));
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Success,
                calls: Arc::clone(&close_calls),
            }))
        );
        let ownership = close_owner.ownership.clone();
        let (events, raw) = test_event_mailboxes(1);
        let policy = test_callback_policy(NonZeroUsize::new(1).expect("one is nonzero"));
        let mut sink = test_event_sink_for_receiver(events, policy, None, &raw);
        sink.close_owner = Some(Arc::downgrade(&close_owner));
        let mut receiver = WebRtcConnectorEventReceiver {
            ownership: ownership.clone(),
            retirement: ownership.incarnation.subscribe_retirement(),
            attempt_retirement: None,
            raw,
            attempt_lifetime: Some(lifetime),
            remote_candidates: Arc::new(SyncMutex::new(test_remote_candidate_state())),
            close_owner: Some(Arc::clone(&close_owner)),
            reclaim: None,
            data_channel_open_committed: false,
            data_channel_closed: false,
            operation_fence: Arc::clone(&ownership.operation_fence),
        };

        sink.structural_violation("fixture violation");
        tokio::time::timeout(Duration::from_secs(1), close_owner.wait())
            .await
            .expect("cleanup reaches its terminal state")
            .expect("the deterministic native close succeeds");
        assert!(!ownership.incarnation.is_active());
        let delivered = receiver
            .recv()
            .await
            .expect("the recorded close survives retirement");
        assert!(matches!(delivered.event, TransportEvent::DataChannelClosed));
        assert_eq!(close_calls.load(Ordering::Acquire), 1);
        assert!(receiver.recv().await.is_none());
    }

    #[test]
    fn v4_arc03i_native_data_channel_shape_is_fixed_and_violation_work_is_coalesced() {
        assert_eq!(
            admit_native_data_channel(APP_DATA_CHANNEL_LABEL, false),
            NativeDataChannelAdmission::Install
        );
        assert_eq!(
            admit_native_data_channel(APP_DATA_CHANNEL_LABEL, true),
            NativeDataChannelAdmission::Violation("duplicate application data channel")
        );

        let (events, mut receiver) = test_event_mailboxes(1);
        let policy = test_callback_policy(NonZeroUsize::new(1).expect("one is nonzero"));
        let sink = test_event_sink_for_receiver(events, policy, None, &receiver);
        for _ in 0..32 {
            let NativeDataChannelAdmission::Violation(reason) =
                admit_native_data_channel("unexpected", true)
            else {
                panic!("unexpected label cannot become an application channel");
            };
            sink.structural_violation(reason);
        }
        sink.structural_violation("duplicate application data channel");

        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::DataChannelClosed)
        ));
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn v4_arc03f_close_fence_rejects_callback_invoked_after_close_commit() {
        let one = NonZeroUsize::new(1).expect("one is nonzero");
        let policy = ConnectorCallbackPolicy::new(
            crate::runtime::attempt::ConnectorCallbackMailboxCapacities::new(one, one),
            ConnectorCallbackServiceWeights::data_only(one, one),
            RealtimeConnectorPolicy::Disabled,
        )
        .expect("data-only fixture policy is valid");
        let (events, mut receiver) = test_event_mailboxes_with_policy(policy);
        let sink = test_event_sink_for_receiver(events, policy, None, &receiver);

        assert!(
            sink.emit_data_channel(TransportEvent::DataChannelClosed)
                .await
        );
        assert!(
            sink.emit_data_channel(TransportEvent::Message(Bytes::from_static(b"after-close")))
                .await
        );

        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::DataChannelClosed)
        ));
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn v4_arc03g_close_retires_realtime_before_forced_realtime_dispatch() {
        let policy = explicit_realtime_callback_policy(8, 1, 2, 8, 1, 16);
        let (events, mut raw) = test_event_mailboxes_with_policy(policy);
        let (candidate, lifetime) = crate::runtime::attempt::connector_candidate_for_test(
            crate::runtime::runtime_for_test(),
        );
        let ownership = admitted_ownership(candidate);
        let mut sink = test_event_sink_for_receiver(events, policy, None, &raw);
        sink.operation_fence = Arc::clone(&ownership.operation_fence);
        sink.callback_gate = Arc::clone(&ownership.incarnation);

        let flow = sink
            .open_inbound_realtime_flow()
            .expect("fixture admits one inbound flow");
        let queued = test_realtime_event(0, 1, b"queued");
        let queued_reservation = flow
            .reserve_output(6)
            .expect("queued unit reserves its exact bytes");
        assert!(sink.emit_realtime(&flow, queued, queued_reservation));
        let invoked_after_close = flow
            .reserve_output(5)
            .expect("later invocation reserves before close commits");
        raw.scheduler.cursor = ConnectorCallbackClass::Realtime.index();
        raw.scheduler.remaining = 1;

        assert!(
            sink.emit_data_channel(TransportEvent::DataChannelClosed)
                .await
        );
        assert!(sink.emit_realtime(
            &flow,
            test_realtime_event(0, 2, b"later"),
            invoked_after_close,
        ));
        {
            let state = raw.realtime_flows.state.lock();
            assert!(state.retired);
            assert_eq!(retained_realtime_bytes(&state), 0);
        }
        assert!(raw.realtime_flows.is_empty());

        let mut receiver = WebRtcConnectorEventReceiver {
            ownership: ownership.clone(),
            retirement: ownership.incarnation.subscribe_retirement(),
            attempt_retirement: None,
            raw,
            attempt_lifetime: Some(lifetime),
            remote_candidates: Arc::new(SyncMutex::new(test_remote_candidate_state())),
            close_owner: None,
            reclaim: None,
            data_channel_open_committed: true,
            data_channel_closed: false,
            operation_fence: Arc::clone(&ownership.operation_fence),
        };
        let event = receiver
            .recv()
            .await
            .expect("the exact close event reaches engine dispatch");
        assert!(matches!(event.event, TransportEvent::DataChannelClosed));
        assert!(receiver.recv().await.is_none());
        assert!(flow.reserve_output(1).is_none());
    }

    #[test]
    fn v4_arc03_scheduler_gives_each_ready_class_a_bounded_service_turn() {
        let capacity = 3;
        let (events, mut receiver) = test_event_mailboxes(capacity);
        receiver.scheduler = ConnectorCallbackScheduler::new(explicit_callback_policy(
            capacity,
            2,
            1,
            1,
            RealtimeConnectorPolicy::enabled(),
        ));
        for candidate in ["candidate-1", "candidate-2", "candidate-3"] {
            events
                .try_insert_for_test(
                    TransportEvent::LocalIceCandidate(Some(LocalIceCandidate {
                        candidate: candidate.to_string(),
                        sdp_mid: Some("0".to_string()),
                        sdp_mline_index: Some(0),
                        username_fragment: Some("fixture".to_string()),
                    })),
                    None,
                )
                .expect("fixture control mailbox has capacity");
        }
        events
            .try_insert_for_test(
                TransportEvent::Message(Bytes::from_static(b"endpoint")),
                None,
            )
            .expect("fixture endpoint-data mailbox has capacity");
        let realtime_flow = receiver
            .realtime_flows
            .open_inbound_flow()
            .expect("fixture admits one exact real-time flow");
        let reservation = realtime_flow
            .reserve_output(0)
            .expect("zero-byte fixture unit is admitted");
        assert!(realtime_flow.enqueue(
            QueuedTransportEvent {
                event: test_realtime_event(0, 0, b""),
                observation: None,
                callback_work: None,
            },
            reservation,
        ));

        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::LocalIceCandidate(_))
        ));
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::LocalIceCandidate(_))
        ));
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::Message(_))
        ));
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::RealtimeUnit(_))
        ));
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::LocalIceCandidate(_))
        ));
    }

    #[tokio::test]
    async fn v4_arc03_endpoint_protocol_waits_for_committed_open_despite_scheduler_cursor() {
        let (events, mut receiver) = test_event_mailboxes(3);
        receiver.scheduler.cursor = ConnectorCallbackClass::EndpointData.index();
        receiver.scheduler.remaining = 1;
        let first_handshake = Bytes::from(
            serde_json::to_vec(&crate::protocol::MeshMessage::Hello(
                crate::protocol::HelloMessage {
                    protocol: crate::PROTOCOL_VERSION,
                    device_id: "lifecycle-peer".to_string(),
                    label: "Lifecycle fixture".to_string(),
                    nonce: "nonce".to_string(),
                    verification_code: "code".to_string(),
                    capabilities: None,
                    max_connections: None,
                    features: Vec::new(),
                    app_version: None,
                },
            ))
            .expect("fixture Hello serializes"),
        );
        events
            .try_insert_for_test(TransportEvent::Message(first_handshake.clone()), None)
            .expect("fixture endpoint mailbox has capacity");
        events
            .try_insert_for_test(TransportEvent::DataChannelOpen, None)
            .expect("fixture control mailbox has capacity");

        let before_commit = receiver
            .recv_queued_filtered(false)
            .await
            .expect("open control event is deliverable");
        assert!(matches!(
            before_commit.event,
            TransportEvent::DataChannelOpen
        ));

        let after_commit = receiver
            .recv_queued_filtered(true)
            .await
            .expect("retained handshake is released after commitment");
        assert!(matches!(
            after_commit.event,
            TransportEvent::Message(bytes) if bytes == first_handshake
        ));
    }

    #[tokio::test]
    async fn v4_arc03_close_can_retire_before_uncommitted_endpoint_protocol() {
        let (events, mut receiver) = test_event_mailboxes(2);
        receiver.scheduler.cursor = ConnectorCallbackClass::EndpointData.index();
        receiver.scheduler.remaining = 1;
        events
            .try_insert_for_test(
                TransportEvent::Message(Bytes::from_static(b"stale-handshake")),
                None,
            )
            .expect("fixture endpoint mailbox has capacity");
        events
            .try_insert_for_test(TransportEvent::DataChannelClosed, None)
            .expect("fixture control mailbox has capacity");

        let event = receiver
            .recv_queued_filtered(false)
            .await
            .expect("close remains deliverable before open commitment");
        assert!(matches!(event.event, TransportEvent::DataChannelClosed));
        assert!(matches!(
            receiver.endpoint_data.try_take(),
            Some(QueuedTransportEvent {
                event: TransportEvent::Message(bytes),
                ..
            }) if bytes == Bytes::from_static(b"stale-handshake")
        ));
    }

    #[tokio::test]
    async fn v4_arc03_retirement_drops_uncommitted_endpoint_protocol_and_its_observation() {
        let process = ProcessResourceRoot::isolated();
        let context = process.mesh_runtime_scope().network_instance_scope();
        let resource_scope = context.peer_connection_scope();
        let observation = resource_scope.observe_pre_authentication(
            PreAuthResourceFamily::FrameBytes,
            ResourceUse::observed(1, 15, 15, 0),
        );
        let active_frame_bytes = || {
            context
                .report()
                .pre_authentication
                .iter()
                .find(|report| report.family == PreAuthResourceFamily::FrameBytes)
                .expect("frame-byte family is present")
                .active
        };
        assert_ne!(active_frame_bytes(), ResourceUse::ZERO);

        let (candidate, lifetime) = crate::runtime::attempt::connector_candidate_for_test(
            crate::runtime::runtime_for_test(),
        );
        let ownership = admitted_ownership(candidate);
        let (events, raw) = test_event_mailboxes(2);
        let mut receiver = WebRtcConnectorEventReceiver {
            ownership: ownership.clone(),
            retirement: ownership.incarnation.subscribe_retirement(),
            attempt_retirement: None,
            raw,
            attempt_lifetime: Some(lifetime),
            remote_candidates: Arc::new(SyncMutex::new(test_remote_candidate_state())),
            close_owner: None,
            reclaim: None,
            data_channel_open_committed: false,
            data_channel_closed: false,
            operation_fence: Arc::clone(&ownership.operation_fence),
        };
        events
            .try_insert_for_test(
                TransportEvent::Message(Bytes::from_static(b"stale-handshake")),
                Some(observation),
            )
            .expect("fixture endpoint mailbox has capacity");
        events
            .try_insert_for_test(TransportEvent::DataChannelClosed, None)
            .expect("fixture control mailbox has capacity");

        let close = receiver
            .recv()
            .await
            .expect("close control event remains deliverable before open");
        assert!(matches!(close.event, TransportEvent::DataChannelClosed));
        drop(close);

        ownership.retire();
        assert!(receiver.recv().await.is_none());
        drop(receiver);
        assert_eq!(active_frame_bytes(), ResourceUse::ZERO);
    }

    #[test]
    fn v4_arc03_observer_panic_cannot_poison_realtime_resource_ownership() {
        let registry = test_realtime_registry_with_observer(
            explicit_realtime_callback_policy(16, 1, 1, 16, 1, 32),
            Arc::new(PanickingRealtimeObserver) as Arc<dyn RealtimeFlowObserver>,
        );
        let first = registry
            .open_inbound_flow()
            .expect("observation failure cannot refuse an admitted flow");
        drop(first);
        let second = registry
            .open_inbound_flow()
            .expect("the exact released flow claim remains reusable");
        drop(second);
        assert!(realtime_accounting_is_clean(&registry.state.lock()));
    }

    #[test]
    fn v4_arc03_realtime_flows_have_independent_bounded_queues() {
        let policy = explicit_realtime_callback_policy(16, 2, 1, 16, 2, 32);
        let observer = Arc::new(TestRealtimeObserver::default());
        let registry = test_realtime_registry_with_observer(
            policy,
            observer.clone() as Arc<dyn RealtimeFlowObserver>,
        );
        let first = registry
            .open_inbound_flow()
            .expect("first flow is admitted");
        let second = registry
            .open_inbound_flow()
            .expect("second flow is admitted");

        assert!(first.enqueue(
            QueuedTransportEvent {
                event: test_realtime_event(0, 1, b"first"),
                observation: None,
                callback_work: None,
            },
            first.reserve_output(5).expect("first unit is reserved"),
        ));
        assert!(first.enqueue(
            QueuedTransportEvent {
                event: test_realtime_event(0, 2, b"first"),
                observation: None,
                callback_work: None,
            },
            first
                .reserve_output(5)
                .expect("full-queue unit is still measured before refusal"),
        ));
        assert!(second.enqueue(
            QueuedTransportEvent {
                event: test_realtime_event(1, 1, b"secnd"),
                observation: None,
                callback_work: None,
            },
            second.reserve_output(5).expect("second unit is reserved"),
        ));

        assert!(matches!(
            registry.try_recv().map(|queued| queued.event),
            Some(TransportEvent::RealtimeUnit(delivery))
                if delivery.label == test_label(0)
                    && delivery.unit.timestamp == 1
        ));
        assert!(matches!(
            registry.try_recv().map(|queued| queued.event),
            Some(TransportEvent::RealtimeUnit(delivery))
                if delivery.label == test_label(1)
                    && delivery.unit.timestamp == 1
        ));
        assert!(registry.try_recv().is_none());
        let state = registry.state.lock();
        assert_eq!(retained_realtime_bytes(&state), 0);
        assert!(realtime_accounting_is_clean(&state));
        drop(state);
        assert!(observer.observations.lock().iter().any(|observation| {
            matches!(
                observation,
                RealtimeFlowObservation::Drop {
                    reason: RealtimeFlowDropReason::FlowQueueFull,
                    ..
                }
            )
        }));
    }

    #[test]
    fn v4_arc03f_inbound_and_outbound_flow_slots_cannot_starve_each_other() {
        let policy = explicit_realtime_callback_policy(8, 1, 1, 8, 1, 16);
        let registry = test_realtime_registry(policy);

        let inbound = registry
            .open_inbound_flow()
            .expect("the inbound quarantine owns its slot");
        assert!(registry.open_inbound_flow().is_none());
        let outbound = registry
            .open_outbound_flow()
            .expect("inbound saturation cannot consume the outbound slot");
        assert!(registry.open_outbound_flow().is_none());

        drop(inbound);
        assert!(registry.open_inbound_flow().is_some());
        drop(outbound);
        assert!(registry.open_outbound_flow().is_some());
    }

    #[test]
    fn v4_arc03f_realtime_bytes_follow_payload_clones_through_downstream_queues() {
        let policy = explicit_realtime_callback_policy(8, 1, 1, 8, 1, 16);
        let registry = test_realtime_registry(policy);
        let flow = registry
            .open_inbound_flow()
            .expect("fixture inbound flow is admitted");
        assert!(flow.enqueue(
            QueuedTransportEvent {
                event: test_realtime_event(0, 1, b"owned"),
                observation: None,
                callback_work: None,
            },
            flow.reserve_output(5).expect("payload bytes are reserved"),
        ));

        let queued = registry.try_recv().expect("queued payload is serviceable");
        assert_eq!(retained_realtime_bytes(&registry.state.lock()), 5);
        let TransportEvent::RealtimeUnit(delivery) = queued.event else {
            panic!("fixture receives its real-time unit");
        };
        let downstream_clone = delivery.payload.clone();
        drop(delivery);
        assert_eq!(retained_realtime_bytes(&registry.state.lock()), 5);
        drop(downstream_clone);
        assert_eq!(retained_realtime_bytes(&registry.state.lock()), 0);
    }

    #[tokio::test]
    async fn v4_arc03f_complete_realtime_unit_has_no_wall_clock_expiry() {
        let policy = explicit_realtime_callback_policy(16, 1, 2, 16, 1, 32);
        let observer = Arc::new(TestRealtimeObserver::default());
        let registry = test_realtime_registry_with_observer(
            policy,
            observer.clone() as Arc<dyn RealtimeFlowObserver>,
        );
        let flow = registry.open_inbound_flow().expect("flow is admitted");
        assert!(flow.enqueue(
            QueuedTransportEvent {
                event: test_realtime_event(0, 7, b"stale"),
                observation: None,
                callback_work: None,
            },
            flow.reserve_output(5).expect("unit is reserved"),
        ));
        tokio::time::sleep(Duration::from_millis(10)).await;

        let queued = registry
            .try_recv()
            .expect("elapsed time cannot revoke a structurally bounded complete unit");
        let state = registry.state.lock();
        assert_eq!(retained_realtime_bytes(&state), 5);
        assert!(realtime_accounting_is_clean(&state));
        drop(state);
        drop(queued);
        assert_eq!(retained_realtime_bytes(&registry.state.lock()), 0);
        assert!(!observer
            .observations
            .lock()
            .iter()
            .any(|observation| { matches!(observation, RealtimeFlowObservation::Drop { .. }) }));
    }

    #[test]
    fn v4_arc03_realtime_byte_claims_precede_fragment_and_output_retention() {
        let policy = explicit_realtime_callback_policy(4, 1, 1, 4, 1, 8);
        let registry = test_realtime_registry(policy);
        let flow = registry.open_inbound_flow().expect("flow is admitted");
        let mut assembly = flow.begin_unit().expect("first unit is admitted");
        assert!(flow.begin_unit().is_none(), "in-progress limit is exact");
        assert!(assembly.retain_ordered_fragment(4));
        assert!(
            !assembly.retain_ordered_fragment(3),
            "unit ceiling is checked first"
        );
        let concurrent_output = flow
            .reserve_output(4)
            .expect("one complete output fits beside the guarded input");
        assert!(
            flow.reserve_output(1).is_none(),
            "the next byte is refused at the connector aggregate"
        );
        drop(concurrent_output);
        drop(assembly);

        let first_output = flow.reserve_output(4).expect("first output is admitted");
        let second_output = flow
            .reserve_output(4)
            .expect("the exact aggregate ceiling is admitted");
        assert!(flow.reserve_output(1).is_none());
        drop(first_output);
        drop(second_output);
        assert!(
            flow.reserve_output(5).is_none(),
            "oversized output is refused"
        );

        let mut oversized_fragment = flow.begin_unit().expect("unit slot was released");
        assert!(!oversized_fragment.retain_ordered_fragment(5));
        drop(oversized_fragment);
        let state = registry.state.lock();
        assert_eq!(retained_realtime_bytes(&state), 0);
        assert_eq!(RealtimeFlowRegistry::in_progress_units(&state), 0);
        assert_eq!(state.accounting_poisoned_by_domain, [false, false]);
    }

    #[test]
    fn v4_arc03f_realtime_fragment_count_is_structurally_bounded() {
        let nonzero = |value| NonZeroUsize::new(value).expect("fixture value is nonzero");
        let flows = ConnectorRealtimeFlowPolicy::new(
            ConnectorRealtimeFlowCapacities::new(nonzero(1), nonzero(1), nonzero(1)),
            ConnectorRealtimeInboundLimits::new(nonzero(4), nonzero(1), nonzero(1)),
            ConnectorRealtimeByteBudgets::new(nonzero(8), nonzero(4)),
            crate::runtime::attempt::RealtimeQueueOverflowRule::DropNewest,
        );
        let realtime = RealtimeConnectorPolicy::enabled_with_local_ceiling(nonzero(4), flows)
            .expect("fixture can hold one guarded input and output");
        let policy = ConnectorCallbackPolicy::new(
            crate::runtime::attempt::ConnectorCallbackMailboxCapacities::new(
                nonzero(1),
                nonzero(1),
            ),
            ConnectorCallbackServiceWeights::new(nonzero(1), nonzero(1), nonzero(1)),
            realtime,
        )
        .expect("fixture callback policy is valid");
        let registry = test_realtime_registry(policy);
        let flow = registry.open_inbound_flow().expect("flow is admitted");
        let mut assembly = flow.begin_unit().expect("unit is admitted");

        assert!(assembly.retain_ordered_fragment(1));
        assert!(!assembly.retain_ordered_fragment(1));
        assert_eq!(retained_realtime_bytes(&registry.state.lock()), 1);

        drop(assembly);
        let state = registry.state.lock();
        assert_eq!(retained_realtime_bytes(&state), 0);
        assert_eq!(RealtimeFlowRegistry::in_progress_units(&state), 0);
        assert!(realtime_accounting_is_clean(&state));
    }

    #[test]
    fn v4_arc03_realtime_accounting_corruption_fails_closed() {
        let policy = explicit_realtime_callback_policy(4, 1, 1, 4, 1, 8);
        let registry = test_realtime_registry(policy);
        let flow = registry.open_inbound_flow().expect("flow is admitted");
        let reservation = flow.reserve_output(4).expect("output is admitted");
        registry.state.lock().retained_bytes_by_domain
            [RealtimeFlowDomain::InboundQuarantine.index()] = 0;
        drop(reservation);

        let state = registry.state.lock();
        assert!(state.accounting_poisoned_by_domain[RealtimeFlowDomain::InboundQuarantine.index()]);
        assert_eq!(
            state.retained_bytes_by_domain[RealtimeFlowDomain::InboundQuarantine.index()],
            8,
            "a damaged domain is conservatively charged at its full ceiling"
        );
        assert!(
            !state.accounting_poisoned_by_domain[RealtimeFlowDomain::OutboundCompatibility.index()]
        );
        drop(state);
        assert!(registry.open_inbound_flow().is_none());
        assert!(flow.reserve_output(1).is_none());
        assert!(
            registry.open_outbound_flow().is_some(),
            "inbound accounting corruption does not poison the independent outbound owner"
        );
    }

    /// Sustained inbound RTP is bounded by the per-packet work claim rather
    /// than by any cumulative counter: a packet is admitted only while the
    /// provider still owns capacity for the classification and framing it is
    /// about to cost, and that capacity returns when the packet's work does.
    #[test]
    fn v4_arc03h_sustained_inbound_rtp_is_bounded_by_its_exact_packet_work() {
        // A grant sized to exactly what this control opens, and nothing else:
        // the fixture base, the one inbound flow it takes, and exactly one
        // packet-work claim.
        //
        // The shared real-time fixture grant cannot express this. It also funds
        // one ordered-fragment claim per admissible fragment, and a fragment
        // claim carries `ParsingOrCpuWork` — the same dimension the packet claim
        // is scarce in. Under that grant the second packet below is afforded out
        // of fragment capacity this control never retains a fragment against,
        // and the refusal it asserts is unreachable. Scarcity has to be built
        // for the claim under test or it is not scarcity at all.
        let policy = explicit_realtime_callback_policy(8, 1, 1, 8, 1, 16);
        let RealtimeConnectorPolicy::Enabled(Some(local)) = policy.realtime() else {
            panic!("the fixture policy carries an explicit local envelope");
        };
        let packet_bytes = 8usize;
        let mut grant = crate::runtime::attempt::explicit_test_grant(1, 1);
        for claim in [
            RealtimeFlowRegistry::flow_claim().expect("the flow claim is representable"),
            RealtimeFlowRegistry::ready_claim().expect("the ready claim is representable"),
            RealtimeFlowRegistry::session_packet_work_claim(packet_bytes)
                .expect("the packet work claim is representable"),
        ] {
            grant = grant
                .checked_add(
                    FiniteResourceProvider::reservation_charge_for_test(claim)
                        .expect("the fixture reservation charge is representable"),
                )
                .expect("the exact packet-work grant is representable");
        }
        let provider = ResourceProviderPort::new(FiniteResourceProvider::new(grant))
            .expect("the exact grant accounts for its process scope");
        let mesh = ConnectorResourceOwnerPort::new(provider)
            .issue_mesh_scope()
            .expect("the exact grant accounts for its Mesh scope");
        let (permit, _attempt, claim) =
            admit_single_connector_candidate(crate::runtime::runtime_for_test(), mesh);
        let candidate = permit
            .reserve_connector_candidate(claim)
            .expect("the exact grant admits its connector candidate");
        let registry =
            RealtimeFlowRegistry::new(Some(candidate.work_resource_scope()), Some(local));

        let _flow = registry
            .open_inbound_flow()
            .expect("the exact grant owns one speculative inbound flow");

        let packet = registry
            .admit_session_packet_checked(packet_bytes)
            .expect("and one inbound pump's packet work");
        assert!(
            !registry.admit_session_packet(packet_bytes),
            "a second concurrent packet has no unowned work capacity"
        );

        drop(packet);
        assert!(
            registry.admit_session_packet(packet_bytes),
            "and completing the packet returns exactly that capacity"
        );
    }

    #[tokio::test]
    async fn v4_arc03_cancelled_realtime_output_work_releases_its_claim() {
        let registry = test_realtime_registry(explicit_realtime_callback_policy(8, 1, 1, 8, 1, 16));
        let flow = registry.open_inbound_flow().expect("flow is admitted");
        let (ready_tx, ready_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _reservation = flow.reserve_output(8).expect("output is admitted");
            let _ = ready_tx.send(());
            std::future::pending::<()>().await;
        });
        ready_rx.await.expect("fixture reserved output");
        assert_eq!(retained_realtime_bytes(&registry.state.lock()), 8);
        task.abort();
        assert!(task
            .await
            .expect_err("fixture task is cancelled")
            .is_cancelled());
        let state = registry.state.lock();
        assert_eq!(retained_realtime_bytes(&state), 0);
        assert!(realtime_accounting_is_clean(&state));
    }

    #[test]
    fn v4_arc03_realtime_flow_retirement_drains_its_owned_queue() {
        let registry = test_realtime_registry(explicit_realtime_callback_policy(8, 1, 2, 8, 1, 16));
        let flow = registry.open_inbound_flow().expect("flow is admitted");
        assert!(flow.enqueue(
            QueuedTransportEvent {
                event: test_realtime_event(0, 1, b"owned"),
                observation: None,
                callback_work: None,
            },
            flow.reserve_output(5).expect("unit is admitted"),
        ));
        assert_eq!(retained_realtime_bytes(&registry.state.lock()), 5);
        drop(flow);
        let state = registry.state.lock();
        assert_eq!(retained_realtime_bytes(&state), 0);
        assert!(state.flows.is_empty());
        assert!(state.ready.is_empty());
        assert!(realtime_accounting_is_clean(&state));
    }

    #[tokio::test]
    async fn v4_arc03_endpoint_and_realtime_units_have_independent_limits() {
        let realtime_limit = 4;
        let policy = explicit_realtime_callback_policy(realtime_limit, 1, 2, realtime_limit, 1, 16);
        assert_eq!(
            callback_payload_limit(policy, ConnectorCallbackClass::EndpointData),
            Some(crate::engine::MAX_ENDPOINT_FRAME_BYTES)
        );
        assert_eq!(
            callback_payload_limit(policy, ConnectorCallbackClass::Realtime),
            Some(realtime_limit)
        );

        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let (events, mut receiver) = test_event_mailboxes_with_policy(policy);
        let sink = test_event_sink_for_receiver(events, policy, Some(scope.clone()), &receiver);

        let flow = sink
            .open_inbound_realtime_flow()
            .expect("fixture admits one exact real-time flow");
        assert!(flow.reserve_output(5).is_none());
        assert!(receiver.try_recv().is_err());

        assert!(
            sink.emit(TransportEvent::Message(Bytes::from_static(b"12345")))
                .await
        );
        let unit = test_realtime_event(0, 1, b"1234");
        let reservation = flow
            .reserve_output(4)
            .expect("fixture reserves the complete real-time unit");
        assert!(sink.emit_realtime(&flow, unit, reservation));

        let report = scope.report();
        let frame = report
            .pre_authentication
            .iter()
            .find(|entry| entry.family == PreAuthResourceFamily::FrameBytes)
            .expect("frame-byte family is present");
        let realtime = report
            .pre_authentication
            .iter()
            .find(|entry| entry.family == PreAuthResourceFamily::MediaQuarantine)
            .expect("real-time quarantine family is present");
        assert_eq!(frame.active.logical_bytes(), 5);
        assert_eq!(realtime.active.logical_bytes(), 4);
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::Message(_))
        ));
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::RealtimeUnit(_))
        ));
    }

    #[tokio::test]
    async fn v4_arc03_native_close_success_releases_exact_candidate_claim() {
        let owner = test_resource_owner(1, 1);
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Success,
                calls: Arc::clone(&calls),
            }))
        );

        close_owner
            .wait()
            .await
            .expect("fixture native close succeeds");

        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(owner.report().active_candidates, 0);
        assert_eq!(owner.report().failed_cleanup_candidates, 0);
        assert!(!owner.report().accounting_poisoned);
    }

    #[tokio::test]
    async fn v4_arc03_close_before_native_attach_closes_late_port_and_releases_claim() {
        let owner = test_resource_owner(1, 1);
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        let calls = Arc::new(AtomicUsize::new(0));
        close_owner.mark_native_allocation_started();

        close_owner.start();
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::Acquire), 0);
        assert_eq!(owner.report().active_candidates, 1);
        assert_eq!(owner.report().failed_cleanup_candidates, 0);

        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Success,
                calls: Arc::clone(&calls),
            }))
        );
        close_owner
            .wait()
            .await
            .expect("the exact late close port completes the pending close owner");

        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(owner.report().active_candidates, 0);
        assert_eq!(owner.report().failed_cleanup_candidates, 0);
        assert!(!owner.report().accounting_poisoned);
    }

    #[tokio::test]
    async fn v4_arc03_native_constructor_without_close_port_retains_exact_claim() {
        let owner = test_resource_owner(2, 1);
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        close_owner.mark_native_allocation_started();
        close_owner.finish_native_allocation_without_close_port(
            "native construction ended without an observable close owner".to_string(),
        );

        let error = close_owner
            .wait()
            .await
            .expect_err("unobservable constructor cleanup must retain its exact claim");
        assert!(error
            .to_string()
            .contains("native construction ended without an observable close owner"));
        assert_eq!(owner.report().active_candidates, 1);
        assert_eq!(owner.report().failed_cleanup_candidates, 1);
        assert!(!owner.report().accounting_poisoned);

        let (permit, _lifetime, claim) =
            admit_single_connector_candidate(crate::runtime::runtime_for_test(), owner.clone());
        let unrelated = permit
            .reserve_connector_candidate(claim)
            .expect("the failed constructor retains only its own exact claim");
        assert_eq!(owner.report().active_candidates, 2);
        drop(unrelated);
    }

    #[tokio::test]
    async fn v4_arc03_native_close_error_retains_only_its_exact_claim() {
        let owner = test_resource_owner(2, 1);
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Error,
                calls: Arc::clone(&calls),
            }))
        );

        let error = close_owner
            .wait()
            .await
            .expect_err("native close failure is fail closed");
        assert!(error.to_string().contains("native close failure"));
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(owner.report().active_candidates, 1);
        assert_eq!(owner.report().failed_cleanup_candidates, 1);
        assert!(!owner.report().accounting_poisoned);

        drop(close_owner);
        assert_eq!(owner.report().active_candidates, 1);
        assert_eq!(owner.report().failed_cleanup_candidates, 1);

        let (permit, _lifetime, claim) =
            admit_single_connector_candidate(crate::runtime::runtime_for_test(), owner.clone());
        let unrelated = permit
            .reserve_connector_candidate(claim)
            .expect("a known failed close does not poison the remaining slot");
        assert_eq!(owner.report().active_candidates, 2);
        drop(unrelated);
        assert_eq!(owner.report().active_candidates, 1);
    }

    #[tokio::test]
    async fn v4_arc03g_native_close_has_no_timer_and_waiter_cancellation_does_not_cancel_owner() {
        let owner = test_resource_owner(2, 1);
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = TestNativeCloseGate::new();
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Gate(Arc::clone(&gate)),
                calls: Arc::clone(&calls),
            }))
        );
        let in_flight = close_owner
            .ownership
            .operation_fence
            .try_enter()
            .expect("fixture operation enters before close");

        close_owner.start();
        tokio::task::yield_now().await;
        assert_eq!(
            close_owner
                .ownership
                .operation_fence
                .active_operations_for_test(),
            1
        );
        assert_eq!(calls.load(Ordering::Acquire), 0);
        drop(in_flight);
        tokio::time::timeout(Duration::from_secs(1), async {
            while calls.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the process cleanup executor polls native close");
        assert!(
            tokio::time::timeout(Duration::from_millis(20), close_owner.wait())
                .await
                .is_err(),
            "test observation time cannot turn Closing into a terminal state"
        );
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(owner.report().active_candidates, 1);
        assert_eq!(owner.report().failed_cleanup_candidates, 0);
        assert!(!owner.report().accounting_poisoned);

        gate.open();
        tokio::time::timeout(Duration::from_secs(1), close_owner.wait())
            .await
            .expect("released native dependency completes")
            .expect("confirmed native close releases the exact claim");
        assert_eq!(owner.report().active_candidates, 0);
    }

    #[tokio::test]
    async fn v4_arc03_cleanup_thread_start_failure_is_visible_and_fail_closed() {
        let owner = test_resource_owner(2, 1);
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        close_owner.fail_background_start_for_test();

        let error = close_owner
            .wait()
            .await
            .expect_err("background start failure retains this cleanup claim");
        assert!(error.to_string().contains("failed to start"));
        assert_eq!(owner.report().active_candidates, 1);
        assert_eq!(owner.report().failed_cleanup_candidates, 1);
        assert!(!owner.report().accounting_poisoned);
        let (permit, _lifetime, claim) =
            admit_single_connector_candidate(crate::runtime::runtime_for_test(), owner.clone());
        assert!(permit.reserve_connector_candidate(claim).is_some());
    }

    #[tokio::test]
    async fn v4_arc03h_cleanup_future_panic_marks_exact_owner_failed() {
        let owner = test_resource_owner(2, 1);
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        close_owner.panic_cleanup_future_for_test();

        let error = close_owner
            .wait()
            .await
            .expect_err("cleanup panic must retain this exact claim");
        assert!(error.to_string().contains("panicked"));
        tokio::time::timeout(Duration::from_secs(1), async {
            while owner.process_report().cleanup.failed_jobs == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cleanup health observes the panic");
        let report = owner.process_report();
        assert_eq!(owner.report().active_candidates, 1);
        assert_eq!(owner.report().failed_cleanup_candidates, 1);
        assert_eq!(report.cleanup.failed_jobs, 1);
        assert!(!report.cleanup.executor_failed);
    }

    #[tokio::test]
    async fn v4_arc03i_cleanup_panic_retains_claim_after_last_external_owner_drops() {
        let owner = test_resource_owner(1, 1);
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        close_owner.panic_cleanup_future_for_test();
        close_owner.start();
        drop(close_owner);

        tokio::time::timeout(Duration::from_secs(1), async {
            while owner.report().failed_cleanup_candidates != 1
                || owner.process_report().cleanup.failed_jobs != 1
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the cleanup job retains its exact failure owner");
        let mesh = owner.report();
        let process = owner.process_report();
        assert_eq!(mesh.active_candidates, 1);
        assert_eq!(mesh.failed_cleanup_candidates, 1);
        assert_eq!(process.active_candidates, 1);
        assert_eq!(process.failed_cleanup_candidates, 1);
        assert_eq!(process.cleanup.failed_jobs, 1);
    }

    #[tokio::test]
    async fn v4_arc03i_executor_termination_retains_active_job_without_external_owner() {
        let owner = test_resource_owner(1, 1);
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = TestNativeCloseGate::new();
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Gate(gate),
                calls: Arc::clone(&calls),
            }))
        );
        close_owner.start();
        tokio::time::timeout(Duration::from_secs(1), async {
            while calls.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cleanup future is active before executor termination");
        drop(close_owner);

        owner.fail_cleanup_executor_for_test();
        tokio::time::timeout(Duration::from_secs(1), async {
            while owner.report().failed_cleanup_candidates != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("executor termination invokes the job-owned failure capability");
        assert_eq!(owner.report().active_candidates, 1);
        assert_eq!(owner.process_report().failed_cleanup_candidates, 1);
        assert!(owner.process_report().cleanup.executor_failed);
    }

    #[tokio::test]
    async fn v4_arc03h_cleanup_executor_failure_refuses_job_and_fails_exact_owner() {
        let owner = test_resource_owner(2, 1);
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        owner.fail_cleanup_executor_for_test();

        let error = close_owner
            .wait()
            .await
            .expect_err("failed executor must retain this exact claim");
        assert!(error
            .to_string()
            .contains("cleanup executor is unavailable"));
        assert_eq!(owner.report().active_candidates, 1);
        assert_eq!(owner.report().failed_cleanup_candidates, 1);
        assert!(owner.process_report().cleanup.executor_failed);
    }

    #[tokio::test]
    async fn v4_arc03_terminal_cleanup_failure_cannot_be_overwritten_by_start() {
        let owner = test_resource_owner(2, 1);
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Success,
                calls: Arc::clone(&calls),
            }))
        );
        close_owner.fail_cleanup("fixture terminal cleanup failure".to_string());

        let error = close_owner
            .wait()
            .await
            .expect_err("a prior cleanup failure remains terminal");

        tokio::time::timeout(Duration::from_secs(1), async {
            while calls.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the terminal failure does not suppress native close");

        assert!(error
            .to_string()
            .contains("fixture terminal cleanup failure"));
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(owner.report().active_candidates, 1);
        assert_eq!(owner.report().failed_cleanup_candidates, 1);
        assert!(!owner.report().accounting_poisoned);
    }

    #[test]
    fn v4_arc03_cleanup_owner_outlives_caller_runtime_shutdown() {
        let owner = test_resource_owner(1, 1);
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Success,
                calls: Arc::clone(&calls),
            }))
        );

        let caller_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("fixture caller runtime");
        caller_runtime.block_on(async { close_owner.start() });
        drop(caller_runtime);

        let verifier_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("fixture verifier runtime");
        verifier_runtime
            .block_on(close_owner.wait())
            .expect("dedicated close owner survives caller runtime shutdown");
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(owner.report().active_candidates, 0);
    }

    #[tokio::test]
    async fn v4_arc03_duplicate_connected_claims_remain_exact_and_local() {
        let owner = test_resource_owner(4, 1);
        let (close_owner, _owner_lifetime) = close_owner_fixture(&owner);
        let (first, _first_lifetime) = connected_claim_fixture(&owner);
        let (second, _second_lifetime) = connected_claim_fixture(&owner);
        close_owner.fail_background_start_for_test();

        close_owner.retain_connected_claim(first);
        close_owner.retain_connected_claim(second);

        assert!(close_owner.wait().await.is_err());
        assert_eq!(close_owner.retained_connected_claims_for_test(), 2);
        assert_eq!(owner.report().active_candidates, 3);
        assert_eq!(owner.report().failed_cleanup_candidates, 3);
        assert!(!owner.report().accounting_poisoned);
        drop(close_owner);
        assert_eq!(owner.report().active_candidates, 3);
        assert_eq!(owner.report().failed_cleanup_candidates, 3);
        let (permit, _lifetime, claim) =
            admit_single_connector_candidate(crate::runtime::runtime_for_test(), owner.clone());
        assert!(permit.reserve_connector_candidate(claim).is_some());
    }

    #[tokio::test]
    async fn v4_arc03_endpoint_handoff_release_before_native_close_releases_once() {
        let owner = test_resource_owner(1, 1);
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Success,
                calls: Arc::clone(&calls),
            }))
        );
        let connected = match close_owner.ownership.mark_data_channel_open() {
            DataChannelOpenTransition::Connected(capability) => capability,
            _ => panic!("fixture connector promotes"),
        };
        let task = task_from_handoff(EndpointAuthHandoff::new(
            connected,
            Arc::clone(&close_owner.ownership.incarnation),
            Arc::clone(&close_owner),
        ));

        drop(task);
        close_owner
            .wait()
            .await
            .expect("native close follows released handoff");

        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(owner.report().active_candidates, 0);
    }

    // ---- Arc 04 endpoint-authentication controls -------------------------
    //
    // These live here rather than in `endpoint_auth` because the ownership
    // half of the property needs real connector incarnations and a real close
    // owner, which is exactly what `close_owner_fixture` provides. The
    // transcript half is covered by the controls in `endpoint_auth::tests`.

    /// The fixture Device keys. Seed 1 is this endpoint, seed 2 the expected
    /// remote; both match the identities the fixture task is constructed with,
    /// so a proof signed by seed 2 is the one it will accept. Any other seed is
    /// an impostor by construction.
    fn auth_key(seed: u8) -> (ed25519_dalek::SigningKey, String) {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let device_id = data_encoding::BASE32_NOPAD
            .encode(signing_key.verifying_key().as_bytes())
            .to_lowercase();
        (signing_key, device_id)
    }

    type AuthTaskFixture = (
        Arc<crate::endpoint_auth::EndpointAuthTask>,
        Arc<ConnectorCloseOwner>,
        AttemptLifetime,
        Arc<AtomicUsize>,
    );

    /// One live endpoint-auth task over a fresh connector incarnation.
    fn auth_task_fixture(owner: &MeshConnectorResourceScope) -> AuthTaskFixture {
        auth_task_fixture_with(owner, None, TestNativeCloseResult::Success)
    }

    /// The same fixture with the native close held open by a caller's gate.
    ///
    /// Only the refused-proof control uses it, and only because the property it
    /// asserts is a *during*: the connected claim stays owned while the one
    /// native close is in flight. With the ungated port that window is not
    /// observable — the dedicated cleanup thread may finish the close before
    /// any assertion runs, so the same assertion would be a race rather than a
    /// control. The gate makes the window exact instead of timed.
    fn auth_task_fixture_gated(
        owner: &MeshConnectorResourceScope,
        gate: Arc<TestNativeCloseGate>,
    ) -> AuthTaskFixture {
        auth_task_fixture_with(owner, None, TestNativeCloseResult::Gate(gate))
    }

    /// The same fixture, forcing this endpoint's contribution to a prior value.
    ///
    /// Only the same-certificate control uses it, and only to build the case
    /// production freshness makes unreachable.
    fn auth_task_fixture_reusing(
        owner: &MeshConnectorResourceScope,
        local_contribution: &str,
    ) -> AuthTaskFixture {
        auth_task_fixture_with(
            owner,
            Some(local_contribution),
            TestNativeCloseResult::Success,
        )
    }

    fn auth_task_fixture_with(
        owner: &MeshConnectorResourceScope,
        reuse: Option<&str>,
        native_close: TestNativeCloseResult,
    ) -> AuthTaskFixture {
        let (close_owner, lifetime) = close_owner_fixture(owner);
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: native_close,
                calls: Arc::clone(&calls),
            }))
        );
        let connected = match close_owner.ownership.mark_data_channel_open() {
            DataChannelOpenTransition::Connected(capability) => capability,
            _ => panic!("fixture connector promotes"),
        };
        let handoff = EndpointAuthHandoff::new(
            connected,
            Arc::clone(&close_owner.ownership.incarnation),
            Arc::clone(&close_owner),
        );
        let task = Arc::new(match reuse {
            Some(value) => task_from_handoff_reusing(handoff, value),
            None => task_from_handoff(handoff),
        });
        (task, close_owner, lifetime, calls)
    }

    /// One fresh peer contribution, as the wire would carry it.
    fn peer_draw() -> crate::endpoint_auth::PeerContribution {
        crate::endpoint_auth::PeerContribution::from_wire(
            crate::endpoint_auth::LocalContribution::generate().as_str(),
        )
        .expect("a generated draw is canonical")
    }

    /// What the exchange drivers return.
    ///
    /// Spelled through `std::result::Result` on purpose. This module has the
    /// crate-wide `Result<T>` alias in scope, which fixes the error type to
    /// `crate::Error`, so a bare `Result<Capability, EndpointAuthError>` here is
    /// not a two-parameter `Result` at all — it silently resolves to the alias.
    /// These drivers must surface the exact `EndpointAuthError` the typed
    /// assertions below match on, so the error type is named explicitly rather
    /// than left to whichever `Result` happens to be in scope.
    ///
    /// The success side is the task's own closed outcome, not a bare capability.
    /// An attempt that has already promoted is not a failure of this exchange,
    /// so it does not appear on the error side at all: `Err` here means the task
    /// terminalized, which is exactly what the refusal controls below assert.
    type ExchangeResult = std::result::Result<
        crate::endpoint_auth::PeerProofAcceptance,
        crate::endpoint_auth::EndpointAuthError,
    >;

    /// Drive one task through its exchange using typed inputs only.
    ///
    /// The mesh, the profile, the Device pair, the channel binding, this
    /// endpoint's own contribution and its own local proof all belong to the
    /// task and none of them is supplied here. A control chooses exactly two
    /// things: the peer contribution that binds the attempt, and which key signs
    /// the peer's half. The signature itself is built inside `endpoint_auth`
    /// from the task's own context, so no control can make a proof verify by
    /// describing an exchange the task does not hold — which is precisely what
    /// the deleted all-facts entry point allowed.
    fn drive_exchange(
        task: &crate::endpoint_auth::EndpointAuthTask,
        peer: &crate::endpoint_auth::PeerContribution,
        peer_key: &ed25519_dalek::SigningKey,
    ) -> ExchangeResult {
        task.accept_peer_hello(peer.clone())?;
        let proof = crate::endpoint_auth::peer_proof_for_test(task, peer, peer_key);
        task.accept_peer_proof(&proof)
    }

    /// The same two typed steps, with the peer's half supplied verbatim.
    ///
    /// Only for the replay control, which must offer a signature captured from
    /// a different channel rather than one built for this task.
    fn drive_exchange_with_signature(
        task: &crate::endpoint_auth::EndpointAuthTask,
        peer: &crate::endpoint_auth::PeerContribution,
        peer_signature: &str,
    ) -> ExchangeResult {
        task.accept_peer_hello(peer.clone())?;
        task.accept_peer_proof(peer_signature)
    }

    #[tokio::test]
    async fn v4_arc04_complete_transcript_promotes_the_exact_channel() {
        let owner = test_resource_owner(1, 1);
        let (task, _close_owner, _lifetime, _calls) = auth_task_fixture(&owner);
        let (remote_key, _remote_id) = auth_key(2);
        let remote_c = peer_draw();

        let authenticated = drive_exchange(&task, &remote_c, &remote_key)
            .expect("a complete mutual proof over the exact channel promotes")
            .into_promoted()
            .expect("the promotion issues the capability");
        drop(authenticated);

        // The handoff is consumed exactly once: replaying the whole exchange
        // against this task finds no channel left to move. The Hello is an exact
        // duplicate and is still answered from the cached proof, and promotion
        // states that it already happened — so the replay yields no second
        // capability, without the intact task being reported as terminal.
        assert!(
            matches!(
                drive_exchange(&task, &remote_c, &remote_key)
                    .expect("a replay against a promoted attempt is not a refusal"),
                crate::endpoint_auth::PeerProofAcceptance::AlreadyPromoted
            ),
            "one channel yields at most one authenticated capability"
        );
    }

    #[tokio::test]
    async fn v4_arc04_refused_remote_half_is_terminal_and_drives_exactly_one_native_close() {
        // The failure path that positive-only tests miss. A refusal is terminal
        // and drops the handoff there and then — which is what runs connector
        // retention — so the refused attempt neither strands the claim nor
        // releases it behind the close it is supposed to drive. The native
        // close is held on a gate so each of those is asserted at a point where
        // it is actually decided, rather than wherever the dedicated cleanup
        // thread happened to be.
        let owner = test_resource_owner(1, 1);
        let gate = TestNativeCloseGate::new();
        let (task, close_owner, _lifetime, calls) =
            auth_task_fixture_gated(&owner, Arc::clone(&gate));
        // Signed by a key that is not the expected remote Device.
        let (impostor_key, _) = auth_key(9);
        let (remote_key, _remote_id) = auth_key(2);
        let remote_c = peer_draw();

        // Non-vacuity: the channel is claimed and nothing has closed yet, so
        // every transition below is one this refusal caused.
        assert_eq!(owner.report().active_candidates, 1);
        assert_eq!(calls.load(Ordering::Acquire), 0);

        assert_eq!(
            drive_exchange(&task, &remote_c, &impostor_key).err(),
            Some(crate::endpoint_auth::EndpointAuthError::SignatureInvalid),
            "an impostor's half is refused with the exact typed cause"
        );
        assert_eq!(
            task.terminal_error(),
            Some(crate::endpoint_auth::EndpointAuthError::SignatureInvalid),
            "and the refusal is terminal for this exact task"
        );

        // No retry, and no promotion by a later genuine half. The task keeps the
        // cause that actually refused it rather than reporting whichever
        // lifecycle event reached it next, so a refused channel cannot be
        // reopened by supplying the key it was expecting all along.
        assert_eq!(
            drive_exchange(&task, &peer_draw(), &remote_key).err(),
            Some(crate::endpoint_auth::EndpointAuthError::SignatureInvalid),
            "the first cause stands and the genuine remote cannot promote it"
        );

        // Exactly one native close begins, driven by the terminal release
        // itself: the task is still alive here, so nothing but the refusal put
        // this connector into close.
        tokio::time::timeout(Duration::from_secs(1), async {
            while calls.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("terminal release drives the connector's native close");
        assert_eq!(calls.load(Ordering::Acquire), 1);

        // While that close is in flight the connected claim is still owned. An
        // unheld close could complete before this line, which is why the gate
        // exists: the claim releases on the confirmed close, never ahead of it.
        assert_eq!(
            owner.report().active_candidates,
            1,
            "the refusal must leave the channel claim owned while close is in flight"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), close_owner.wait())
                .await
                .is_err(),
            "and the close cannot be terminal while the native dependency is held"
        );

        // Release the gate: the one native close succeeds and the claim goes
        // back with it.
        gate.open();
        tokio::time::timeout(Duration::from_secs(1), close_owner.wait())
            .await
            .expect("released native dependency completes")
            .expect("native close follows the terminal release");
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(owner.report().active_candidates, 0);
        drop(task);
    }

    #[tokio::test]
    async fn v4_arc04_production_retirement_invalidates_the_endpoint_auth_task() {
        // Drives the *production* replacement path, `retire_connector`, rather
        // than calling `task.retire()` directly. Before this was wired, the
        // task survived replacement with `is_retired() == false` and its
        // handoff intact, so a late proof could still mint a capability —
        // install would reject it, but only after the fact. Retirement must
        // fail closed at the source.
        let owner = test_resource_owner(1, 1);
        let (task, _close_owner, _lifetime, _calls) = auth_task_fixture(&owner);
        let peer = crate::engine::connection::PeerConnection::with_endpoint_auth_for_test(
            "retiring-peer".to_string(),
            Arc::clone(&task),
        );
        *peer.state.write() = admitted_legacy_state();
        peer.install_authenticated_channel_for_test();

        // Non-vacuity: everything is live and admitted before replacement.
        assert!(!task.is_retired());
        assert!(task.belongs_to(task.incarnation()));
        assert!(peer.has_authenticated_channel());

        // The exact production replacement call.
        peer.retire_connector();

        assert!(
            task.is_retired(),
            "replacement must retire the task at the source"
        );
        assert!(
            !task.belongs_to(task.incarnation()),
            "a retired task belongs to no connector"
        );
        assert!(
            !peer.has_authenticated_channel(),
            "the channel authority must be gone immediately after replacement, which is what leaves nothing for the session gate to promote from"
        );

        // An exchange that would otherwise promote is now refused with the exact
        // typed cause, before any capability can be minted.
        let (remote_key, _remote_id) = auth_key(2);
        assert_eq!(
            drive_exchange(&task, &peer_draw(), &remote_key).err(),
            Some(crate::endpoint_auth::EndpointAuthError::ChannelNotCurrent),
            "a superseded connector must refuse promotion, not merely fail to install"
        );
        assert!(
            !peer.has_authenticated_channel(),
            "and no capability is installed by the attempt"
        );
    }

    #[tokio::test]
    async fn v4_arc04_retired_task_cannot_authenticate() {
        // Replacement invalidation is a security control here, not
        // housekeeping: with a certificate-fingerprint binding that is not
        // session-unique, exact incarnation ownership is what separates two
        // channels between the same pair.
        let owner = test_resource_owner(1, 1);
        let (task, _close_owner, _lifetime, _calls) = auth_task_fixture(&owner);
        let (remote_key, _remote_id) = auth_key(2);
        let remote_c = peer_draw();

        // The channel is replaced/retired before the proof arrives.
        task.retire();

        assert_eq!(
            drive_exchange(&task, &remote_c, &remote_key).err(),
            Some(crate::endpoint_auth::EndpointAuthError::ChannelNotCurrent),
            "a proof that would otherwise verify must not promote a retired channel"
        );
    }

    #[tokio::test]
    async fn v4_arc04_same_certificate_two_channels_bind_capabilities_to_distinct_incarnations() {
        // C5. Two channels between one device pair reusing the same
        // certificates, so the channel binding is identical by construction.
        let owner = test_resource_owner(3, 3);
        let (channel_one, _co1, _l1, _c1) = auth_task_fixture(&owner);
        let (channel_two, _co2, _l2, _c2) = auth_task_fixture(&owner);
        let (remote_key, _remote_id) = auth_key(2);

        // (a) NON-VACUITY. Both channels are built by the same fixture, so they
        // share one Device pair and one channel binding by construction — the
        // context is fixed inside `endpoint_auth`, identically for both. Nothing
        // cryptographic separates these two channels; if the fixture ever varied
        // the binding per channel this control would silently become a no-op
        // that passes while proving nothing.
        //
        // Channel 1 authenticates normally.
        let one_remote = peer_draw();
        let promoted = drive_exchange(&channel_one, &one_remote, &remote_key)
            .expect("channel 1 authenticates")
            .into_promoted()
            .expect("channel 1's promotion issues the capability");
        // The exact proof channel 1 accepted, captured for replay below.
        let one_remote_sig =
            crate::endpoint_auth::peer_proof_for_test(&channel_one, &one_remote, &remote_key);

        // (b) ORDINARY REPLAY. Channel 2 binds its own fresh peer contribution,
        // and its task drew its own local one, so channel 1's captured
        // signature does not cover channel 2's transcript. This is freshness
        // doing the work, not the binding.
        assert_eq!(
            drive_exchange_with_signature(&channel_two, &peer_draw(), &one_remote_sig).err(),
            Some(crate::endpoint_auth::EndpointAuthError::SignatureInvalid),
            "a replayed proof must not authenticate a channel with fresh contributions"
        );

        // (c) THE DISCRIMINATING CASE, stated honestly. Force a third channel to
        // reuse channel 1's exact contribution pair — its local draw as well as
        // the peer value, because forcing only the peer half leaves the local
        // halves different and this degenerates back into (b). With the binding
        // already equal, the two transcripts are now byte-identical and channel
        // 1's signature is cryptographically VALID over this one. Ownership
        // cannot and does not change that; asserting otherwise would be an
        // overclaim, so this asserts that it DOES promote.
        let (forced, _co3, _l3, _c3) =
            auth_task_fixture_reusing(&owner, &channel_one.local_contribution());
        let forced_capability =
            drive_exchange_with_signature(&forced, &one_remote, &one_remote_sig)
                .expect(
                    "with identical certificates and identical contributions the replayed proof \
                     is genuinely valid, and the task cannot tell where it was signed",
                )
                .into_promoted()
                .expect("the replayed proof genuinely promotes this third channel");

        // Two distinct mechanisms carry this, and they must not be conflated:
        //
        //  * Cross-channel *proof* replay is prevented by per-attempt
        //    contribution uniqueness, and by that alone — which is exactly what
        //    (c) just demonstrated by removing it. In production that case does
        //    not arise: the task draws its own contribution at `begin` and
        //    `LocalContribution` has no constructor that rebuilds one from bytes
        //    outside `cfg(test)`. Non-`Clone` prevents casual duplication; it is
        //    not by itself the guarantee.
        //
        //  * Ownership prevents *already-issued authority* from transferring
        //    across channels or surviving replacement. That is what the
        //    assertions below cover, and what
        //    `v4_arc04_install_refuses_a_capability_from_another_incarnation`
        //    exercises through the real install path.
        //
        // So even where the proof replays, the authority does not: the
        // capability minted from the replayed proof belongs to the channel that
        // ran the exchange, never to channel 1.
        assert!(
            forced_capability.belongs_to(forced.incarnation()),
            "a replayed-but-valid proof mints authority bound to the channel that ran it"
        );
        assert!(
            !forced_capability.belongs_to(channel_one.incarnation()),
            "and that authority is not channel 1's, valid proof or not"
        );
        assert!(
            promoted.belongs_to(channel_one.incarnation()),
            "non-vacuity: the predicate is not constantly false"
        );
        assert!(
            !promoted.belongs_to(channel_two.incarnation()),
            "a capability promoted on channel 1 must not be installable against \
             channel 2, valid proof or not"
        );
        assert!(
            !Arc::ptr_eq(channel_one.incarnation(), channel_two.incarnation()),
            "the two fixtures really are distinct incarnations"
        );
        drop(forced_capability);
        drop(promoted);
    }

    /// Promote one channel to an authenticated capability, for install tests.
    fn promote_for_install(
        task: &Arc<crate::endpoint_auth::EndpointAuthTask>,
    ) -> crate::endpoint_auth::AuthenticatedChannelCapability {
        let (remote_key, _remote_id) = auth_key(2);
        drive_exchange(task, &peer_draw(), &remote_key)
            .expect("the fixture proof promotes")
            .into_promoted()
            .expect("the promotion issues the capability")
    }

    /// Peer state that legacy policy would call admitted.
    fn admitted_legacy_state() -> crate::engine::connection::PeerStateData {
        crate::engine::connection::PeerStateData {
            authenticated: true,
            status: crate::engine::connection::PeerStatus::Active,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn v4_arc04_application_admission_requires_a_live_capability_not_just_the_legacy_bool() {
        // The enforcement half. Storing the capability is not the same as
        // gating on it: `authenticated` records policy history and survives
        // channel replacement, so a gate reading only the bool would keep
        // admitting application traffic after the authority artifact is gone.
        let owner = test_resource_owner(1, 1);
        let (task, _close_owner, _lifetime, _calls) = auth_task_fixture(&owner);
        let peer = crate::engine::connection::PeerConnection::with_endpoint_auth_for_test(
            "gate-peer".to_string(),
            Arc::clone(&task),
        );

        // This control owns the *channel-authority* half of admission. The
        // policy half moved to the broker, where `CurrentPolicyAdmission` is a
        // promotion conjunct with its own negative control — this fixture holds
        // no registry and no broker, so it cannot promote and must not pretend
        // to test policy.

        // (1) Legacy bool set, no capability installed → no channel authority.
        *peer.state.write() = admitted_legacy_state();
        assert!(
            peer.state.read().is_admitted(),
            "non-vacuity: legacy policy really does consider this admitted"
        );
        assert!(
            !peer.has_authenticated_channel(),
            "the legacy bool alone establishes no channel authority, so there is \
             nothing for the session gate to promote from"
        );

        // (2) Capability installed on the current connector → authority present.
        let capability = promote_for_install(&task);
        assert!(peer.install_authenticated_channel(&task, capability));
        assert!(peer.has_authenticated_channel());

        // (3) Replacement invalidates immediately, while the registry entry and
        // the legacy bool are both untouched.
        peer.retire_connector();
        assert!(
            peer.state.read().is_admitted(),
            "the legacy bool is deliberately left set, which is why it could \
             never have been the gate"
        );
        assert!(
            !peer.has_authenticated_channel(),
            "retiring the connector drops the channel authority at once"
        );
    }

    #[tokio::test]
    async fn v4_arc04_install_refuses_a_capability_from_another_incarnation() {
        // The install-path half of C5, and the one that actually fails if the
        // capability/incarnation binding is removed from
        // `install_authenticated_channel`. Both channels share device
        // identities and certificate fingerprints, so nothing cryptographic
        // separates them — only provenance does.
        let owner = test_resource_owner(3, 3);
        let (task_one, _co1, _l1, _c1) = auth_task_fixture(&owner);
        let (task_two, _co2, _l2, _c2) = auth_task_fixture(&owner);
        // A third live channel, so the negative case uses a capability this
        // test still owns rather than one already moved into `peer_one`.
        let (task_three, _co3, _l3, _c3) = auth_task_fixture(&owner);
        assert!(
            !Arc::ptr_eq(task_one.incarnation(), task_two.incarnation()),
            "non-vacuity: the fixtures are genuinely distinct incarnations"
        );

        // POSITIVE: a capability installs on the peer whose current task
        // promoted it. Without this the negative case below could pass simply
        // because install always refuses.
        let cap_one = promote_for_install(&task_one);
        let peer_one = crate::engine::connection::PeerConnection::with_endpoint_auth_for_test(
            "peer-one".to_string(),
            Arc::clone(&task_one),
        );
        assert!(
            peer_one.install_authenticated_channel(&task_one, cap_one),
            "a capability must install against the task that promoted it"
        );
        assert!(peer_one.has_authenticated_channel());

        // NEGATIVE: channel 2's task is current on its own peer, but the
        // capability came from channel 1. Checking only that the *task* is
        // current would accept this, which is the cross-channel relay.
        let relayed = promote_for_install(&task_three);
        let peer_two = crate::engine::connection::PeerConnection::with_endpoint_auth_for_test(
            "peer-two".to_string(),
            Arc::clone(&task_two),
        );
        assert!(
            !peer_two.install_authenticated_channel(&task_two, relayed),
            "a capability promoted on another connector incarnation must not \
             install, even with the current task supplied alongside it"
        );
        assert!(
            !peer_two.has_authenticated_channel(),
            "and nothing is left installed after the refusal"
        );
    }

    #[tokio::test]
    async fn v4_arc04_promoted_capability_retains_the_connected_claim_until_native_close() {
        // Promotion must carry the *whole* handoff. If it moved only the
        // connected capability, dropping the authenticated capability — on
        // retirement, or on a refused install — would release the claim
        // directly and defeat Arc 03's "retained until native close succeeds".
        let owner = test_resource_owner(1, 1);
        // A *gated* native close, so the interval between "close entered" and
        // "close succeeded" is observable. With an immediate close, an early
        // release would produce the same before/after readings and the control
        // would not discriminate.
        let gate = TestNativeCloseGate::new();
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Gate(Arc::clone(&gate)),
                calls: Arc::clone(&calls),
            }))
        );
        let connected = match close_owner.ownership.mark_data_channel_open() {
            DataChannelOpenTransition::Connected(capability) => capability,
            _ => panic!("fixture connector promotes"),
        };
        let task = Arc::new(task_from_handoff(EndpointAuthHandoff::new(
            connected,
            Arc::clone(&close_owner.ownership.incarnation),
            Arc::clone(&close_owner),
        )));
        let (remote_key, _remote_id) = auth_key(2);
        let promoted = drive_exchange(&task, &peer_draw(), &remote_key)
            .expect("promotes")
            .into_promoted()
            .expect("the promotion issues the capability");
        assert_eq!(
            owner.report().active_candidates,
            1,
            "promotion does not release the connected claim"
        );

        // Dropping the authenticated capability is what a retirement or a
        // refused install does. The claim must survive into native close.
        drop(promoted);
        drop(task);

        // Native close has now been entered but is blocked on the gate. This
        // is the load-bearing interval: if promotion had stripped the handoff
        // and the capability released the claim directly, the claim would
        // already be gone here.
        let closing = tokio::spawn({
            let close_owner = Arc::clone(&close_owner);
            async move { close_owner.wait().await }
        });
        // Wait on the gate's own entry rather than on the port's call counter.
        // The counter is bumped before the returned future is polled, so it
        // reports a close that has been *submitted*; the gate publishes from
        // inside the held future, so it reports one that has genuinely reached
        // the hold point. Every wait below is bounded, so a regression that
        // reintroduces a lost wake fails this named control at its deadline
        // instead of hanging the suite.
        tokio::time::timeout(Duration::from_secs(1), gate.wait_for_entry())
            .await
            .expect("the promoted claim's native close reaches the hold point");
        assert_eq!(
            gate.entries(),
            1,
            "native close is entered exactly once, and is still held here"
        );
        assert_eq!(
            calls.load(Ordering::Acquire),
            1,
            "and that entry is the one submitted close, not a second port call"
        );
        assert_eq!(
            owner.report().active_candidates,
            1,
            "the connected claim must still be retained while native close is in flight"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), close_owner.wait())
                .await
                .is_err(),
            "and the close cannot be terminal while the gate still holds it"
        );

        // Release. The permit is stored, so it is observed even if it is
        // published before the held close parks — the exact window in which a
        // wake-only primitive would drop it and strand this control.
        gate.open();
        tokio::time::timeout(Duration::from_secs(1), closing)
            .await
            .expect("the released native close completes")
            .expect("close task joins")
            .expect("native close succeeds once released");
        assert_eq!(
            calls.load(Ordering::Acquire),
            1,
            "exactly one native close: no double retention, no missed release"
        );
        assert_eq!(
            gate.entries(),
            1,
            "and the release drove that one close through, not a repeat of it"
        );
        assert_eq!(
            owner.report().active_candidates,
            0,
            "and the claim is released only after close succeeded"
        );
    }

    #[tokio::test]
    async fn v4_arc03_native_close_before_endpoint_handoff_release_keeps_claim_visible() {
        let owner = test_resource_owner(1, 1);
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Success,
                calls: Arc::clone(&calls),
            }))
        );
        let connected = match close_owner.ownership.mark_data_channel_open() {
            DataChannelOpenTransition::Connected(capability) => capability,
            _ => panic!("fixture connector promotes"),
        };
        let task = task_from_handoff(EndpointAuthHandoff::new(
            connected,
            Arc::clone(&close_owner.ownership.incarnation),
            Arc::clone(&close_owner),
        ));

        close_owner
            .wait()
            .await
            .expect("native close completes while handoff owns the claim");
        assert_eq!(owner.report().active_candidates, 1);
        drop(task);

        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(owner.report().active_candidates, 0);
    }

    #[tokio::test]
    async fn v4_arc03_failed_native_close_before_endpoint_handoff_release_retains_exact_claim() {
        let owner = test_resource_owner(2, 1);
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Error,
                calls: Arc::clone(&calls),
            }))
        );
        let connected = match close_owner.ownership.mark_data_channel_open() {
            DataChannelOpenTransition::Connected(capability) => capability,
            _ => panic!("fixture connector promotes"),
        };
        let task = task_from_handoff(EndpointAuthHandoff::new(
            connected,
            Arc::clone(&close_owner.ownership.incarnation),
            Arc::clone(&close_owner),
        ));

        close_owner
            .wait()
            .await
            .expect_err("native close failure remains terminal while Endpoint Auth owns the claim");
        let before_handoff_release = owner.report();
        assert_eq!(before_handoff_release.active_candidates, 1);
        assert_eq!(before_handoff_release.failed_cleanup_candidates, 0);
        assert!(!before_handoff_release.accounting_poisoned);

        drop(task);
        let after_handoff_release = owner.report();
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(after_handoff_release.active_candidates, 1);
        assert_eq!(after_handoff_release.failed_cleanup_candidates, 1);
        assert!(!after_handoff_release.accounting_poisoned);

        drop(close_owner);
        let after_owner_drop = owner.report();
        assert_eq!(after_owner_drop.active_candidates, 1);
        assert_eq!(after_owner_drop.failed_cleanup_candidates, 1);
        assert!(!after_owner_drop.accounting_poisoned);

        let (permit, _unrelated_lifetime, claim) =
            admit_single_connector_candidate(crate::runtime::runtime_for_test(), owner.clone());
        assert!(permit.reserve_connector_candidate(claim).is_some());
    }

    #[test]
    fn v4_arc03_cross_connector_endpoint_auth_capabilities_are_rejected() {
        let owner = test_resource_owner(2, 1);
        let (first_close_owner, _first_lifetime) = close_owner_fixture(&owner);
        let (second_close_owner, _second_lifetime) = close_owner_fixture(&owner);
        let connected = match first_close_owner.ownership.mark_data_channel_open() {
            DataChannelOpenTransition::Connected(capability) => capability,
            _ => panic!("fixture connector promotes"),
        };
        let first_task = task_from_handoff(EndpointAuthHandoff::new(
            connected,
            Arc::clone(&first_close_owner.ownership.incarnation),
            Arc::clone(&first_close_owner),
        ));

        assert!(first_close_owner.ownership.owns_endpoint_auth(&first_task));
        assert!(!second_close_owner.ownership.owns_endpoint_auth(&first_task));

        first_close_owner.retire_local();
        assert!(!first_close_owner.ownership.owns_endpoint_auth(&first_task));
        drop(first_task);
    }

    #[test]
    fn v4_arc03_connector_operations_require_and_release_exact_work_claims() {
        let owner = test_resource_owner(1, 1);
        let (close_owner, _lifetime) = close_owner_fixture(&owner);

        let first = close_owner
            .ownership
            .enter_operation()
            .expect("fixture provider grants one connector operation");
        let pressure = match close_owner.ownership.enter_operation() {
            Ok(_) => panic!("a second operation has no unowned work capacity"),
            Err(error) => error,
        };
        assert!(pressure.to_string().contains("resource pressure"));

        drop(first);
        let replacement = close_owner
            .ownership
            .enter_operation()
            .expect("dropping the exact operation restores its work capacity");
        drop(replacement);
    }

    #[tokio::test]
    async fn v4_arc03_connector_retirement_before_promotion_rejects_and_cleans() {
        let owner = test_resource_owner(1, 1);
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Success,
                calls: Arc::clone(&calls),
            }))
        );

        close_owner.retire_local();
        assert!(matches!(
            close_owner.ownership.mark_data_channel_open(),
            DataChannelOpenTransition::Rejected
        ));
        close_owner
            .wait()
            .await
            .expect("retired unpromoted connector cleans exactly once");

        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(owner.report().active_candidates, 0);
    }

    #[test]
    fn v4_arc03_candidate_queue_is_connector_owned_and_observed() {
        let process = ProcessResourceRoot::isolated();
        let mesh = process.mesh_runtime_scope();
        let context = mesh.network_instance_scope();
        let scope = context.peer_connection_scope();
        let candidate = observed_candidate();
        let candidate_use = candidate_resource_measurement(&candidate).observed();
        let mut queue = PendingRemoteCandidateQueue::new(test_pending_candidate_policy());
        assert_eq!(
            queue.push_observed_for_test(
                candidate,
                Arc::new(RemoteCandidateAttemptIdentity::default()),
                &scope,
            ),
            PendingRemoteCandidateQueuePush::Queued
        );
        let container_use = queue_container_resource_measurement(&queue.entries).observed();

        let active = candidate_report(&context.report().pre_authentication);
        assert_eq!(active.active.items(), candidate_use.items());
        assert_eq!(active.active.logical_bytes(), candidate_use.logical_bytes());
        assert_eq!(
            active.active.retained_bytes(),
            candidate_use.retained_bytes() + container_use.retained_bytes()
        );
        assert_eq!(active.active_lease_count, 2);

        let mut drain = queue.take();
        let candidate = drain.next().expect("queued candidate transfers to drain");
        drop(candidate);
        assert_eq!(
            candidate_report(&context.report().pre_authentication)
                .active
                .retained_bytes(),
            container_use.retained_bytes()
        );
        drop(drain);
        let completed = candidate_report(&context.report().pre_authentication);
        assert_eq!(completed.active, ResourceUse::ZERO);
        assert_eq!(completed.completed_lease_count, 2);
    }

    #[test]
    fn v4_arc03_candidate_queue_reserves_actual_string_capacity_before_node_insertion() {
        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let mut candidate = observed_candidate();
        let mut state = RemoteCandidateState::new(test_pending_candidate_policy());
        let pressure = state
            .current
            .work_resources
            .pressure(
                crate::resource::ResourceAuthorityClass::Speculative,
                crate::resource::ResourceClass::AccountedMemoryBytes,
            )
            .expect("fixture provider reports its exact remaining capacity");
        let remaining = pressure
            .capacity
            .checked_sub(pressure.in_use)
            .and_then(|bytes| usize::try_from(bytes).ok())
            .expect("fixture remaining capacity is representable");
        let mut inflated = String::with_capacity(
            candidate
                .candidate
                .len()
                .checked_add(remaining)
                .and_then(|capacity| capacity.checked_add(1))
                .expect("fixture capacity is representable"),
        );
        inflated.push_str(&candidate.candidate);
        candidate.candidate = inflated;

        assert!(matches!(
            state.admit(candidate, &scope),
            PendingRemoteCandidateQueuePush::ResourceUnavailable(ResourceUnavailable::Pressure(_))
        ));
        assert!(state.current.pending.entries.is_empty());
        assert!(state.current.seen.is_empty());
        assert!(!state.current.attempt.is_active());
    }

    #[test]
    fn v4_arc03g_candidate_queue_deduplicates_before_retention_and_enforces_both_bounds() {
        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let first = observed_candidate();
        let content_bytes =
            candidate_content_bytes(&first).expect("fixture content is representable");
        let one = NonZeroUsize::new(1).expect("one is nonzero");
        let two = NonZeroUsize::new(2).expect("two is nonzero");
        let two_candidates = content_bytes
            .checked_mul(2)
            .and_then(NonZeroUsize::new)
            .expect("two candidate contents are representable and nonzero");

        let mut item_bounded = RemoteCandidateState::new(PendingRemoteCandidatePolicy::new(
            one,
            two_candidates,
            one,
            two,
        ));
        assert_eq!(
            item_bounded.admit(first.clone(), &scope),
            PendingRemoteCandidateQueuePush::Queued
        );
        assert_eq!(
            item_bounded.admit(first.clone(), &scope),
            PendingRemoteCandidateQueuePush::Duplicate
        );
        assert_eq!(
            item_bounded.current.pending.budget.report(),
            (1, content_bytes, 1, 0, false)
        );
        let mut distinct = first.clone();
        distinct.candidate.replace_range(0..1, "C");
        assert_eq!(
            candidate_content_bytes(&distinct),
            Some(content_bytes),
            "fixture variation keeps the byte test independent from item count"
        );
        assert_eq!(
            item_bounded.admit(distinct.clone(), &scope),
            PendingRemoteCandidateQueuePush::Refused
        );
        assert_eq!(
            item_bounded.current.pending.budget.report(),
            (1, content_bytes, 1, 0, false)
        );

        let exact_one_payload =
            NonZeroUsize::new(content_bytes).expect("fixture candidate content is nonzero");
        let mut byte_bounded = RemoteCandidateState::new(PendingRemoteCandidatePolicy::new(
            two,
            exact_one_payload,
            one,
            two,
        ));
        assert_eq!(
            byte_bounded.admit(first, &scope),
            PendingRemoteCandidateQueuePush::Queued
        );
        assert_eq!(
            byte_bounded.admit(distinct, &scope),
            PendingRemoteCandidateQueuePush::Refused
        );
        assert_eq!(
            byte_bounded.current.pending.budget.report(),
            (1, content_bytes, 0, 0, false)
        );
    }

    #[test]
    fn v4_arc03h_candidate_content_bytes_cover_every_candidate_content_field() {
        let candidate = LocalIceCandidate {
            candidate: "candidate-content".to_string(),
            sdp_mid: Some("mid".to_string()),
            sdp_mline_index: Some(7),
            username_fragment: Some("ufrag".to_string()),
        };
        assert_eq!(
            candidate_content_bytes(&candidate),
            Some("candidate-content".len() + "mid".len() + size_of::<u16>() + "ufrag".len())
        );
    }

    #[test]
    fn v4_arc03h_candidate_digest_is_structurally_unambiguous() {
        let mut first = observed_candidate();
        first.candidate = "a".to_string();
        first.sdp_mid = Some("b\0".to_string());
        first.sdp_mline_index = None;
        first.username_fragment = None;
        let mut second = first.clone();
        second.candidate = "a\0b".to_string();
        second.sdp_mid = None;

        assert_ne!(first, second);
        assert_ne!(
            candidate_content_digest(&first),
            candidate_content_digest(&second),
            "field boundaries participate in duplicate identity"
        );
    }

    #[test]
    fn v4_arc03i_candidate_digest_distinguishes_absent_and_maximum_mline_index() {
        let mut absent = observed_candidate();
        absent.sdp_mline_index = None;
        let mut maximum = absent.clone();
        maximum.sdp_mline_index = Some(u16::MAX);

        assert_ne!(
            candidate_content_digest(&absent),
            candidate_content_digest(&maximum),
            "option presence participates in duplicate identity"
        );
    }

    #[test]
    fn v4_arc03h_candidate_attempt_envelope_survives_delayed_apply_and_cancellation() {
        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let candidate = observed_candidate();
        let content_bytes =
            candidate_content_bytes(&candidate).expect("fixture content is representable");
        let policy = PendingRemoteCandidatePolicy::new(
            NonZeroUsize::new(1).expect("one is nonzero"),
            NonZeroUsize::new(content_bytes).expect("fixture content is nonzero"),
            NonZeroUsize::new(1).expect("one is nonzero"),
            NonZeroUsize::new(1).expect("one is nonzero"),
        );
        let mut queue = PendingRemoteCandidateQueue::new(policy);
        let budget = Arc::clone(&queue.budget);
        assert_eq!(
            queue.push_observed_for_test(
                candidate,
                Arc::new(RemoteCandidateAttemptIdentity::default()),
                &scope,
            ),
            PendingRemoteCandidateQueuePush::Queued
        );
        let mut drain = queue.take();
        let pending = drain
            .next()
            .expect("delayed SDP drains the queued candidate");
        let mut application = Box::pin(apply_pending_remote_candidate(pending, |_| {
            std::future::pending::<std::result::Result<(), ()>>()
        }));
        let waker = Waker::noop();
        let mut task_context = Context::from_waker(waker);
        assert_eq!(application.as_mut().poll(&mut task_context), Poll::Pending);
        assert_eq!(budget.report(), (1, content_bytes, 0, 0, false));

        drop(application);
        assert_eq!(budget.report(), (1, content_bytes, 0, 0, false));
        drop(drain);
    }

    #[test]
    fn v4_arc03h_new_attempt_gets_a_fresh_candidate_envelope() {
        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let policy = test_pending_candidate_policy();
        let mut state = RemoteCandidateState::new(policy);
        let displaced_budget = Arc::clone(&state.current.pending.budget);
        assert_eq!(
            state.current.pending.push_observed_for_test(
                observed_candidate(),
                Arc::clone(&state.current.attempt),
                &scope,
            ),
            PendingRemoteCandidateQueuePush::Queued
        );
        assert_eq!(displaced_budget.report().0, 1);

        let displaced = std::mem::replace(&mut state, RemoteCandidateState::new(policy));
        drop(displaced);
        assert_eq!(displaced_budget.report().0, 1);
        assert_eq!(state.current.pending.budget.report(), (0, 0, 0, 0, false));
    }

    #[tokio::test]
    async fn v4_arc03j_local_ice_restart_is_provisional_until_explicit_commit() {
        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let mut state = RemoteCandidateState::new(test_pending_candidate_policy());
        assert_eq!(
            state.admit(observed_candidate(), &scope),
            PendingRemoteCandidateQueuePush::Queued
        );
        let old_attempt = Arc::clone(&state.current.attempt);
        let old_operation = old_attempt
            .try_enter()
            .expect("old attempt admits work before restart");
        let (retiring, replacement) = state
            .begin_local_ice_restart()
            .expect("one local restart becomes provisional");

        assert!(Arc::ptr_eq(&old_attempt, &retiring));
        assert!(!old_attempt.is_active());
        assert!(Arc::ptr_eq(&old_attempt, &state.current.attempt));
        assert!(!state.current.attempt.is_active());
        let provisional = state
            .provisional
            .as_ref()
            .expect("replacement is provisional");
        assert!(Arc::ptr_eq(&replacement, &provisional.envelope.attempt));
        assert!(provisional.envelope.attempt.is_active());
        assert!(!provisional.envelope.remote_description_set);
        assert!(provisional.envelope.pending.entries.is_empty());

        let replacement_candidate = observed_candidate();
        assert_eq!(
            state.admit(replacement_candidate, &scope),
            PendingRemoteCandidateQueuePush::Queued
        );
        let provisional = state
            .provisional
            .as_ref()
            .expect("replacement remains provisional");
        assert_eq!(provisional.envelope.pending.entries.len(), 1);
        assert!(Arc::ptr_eq(
            &provisional
                .envelope
                .pending
                .entries
                .front()
                .expect("replacement queue contains its candidate")
                .attempt,
            &replacement
        ));
        assert!(
            !provisional.envelope.remote_description_set,
            "replacement candidates remain held until replacement SDP commits"
        );

        let mut waiting = Box::pin(retiring.wait_for_operations());
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut waiting)
                .await
                .is_err()
        );
        drop(old_operation);
        tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .expect("restart barrier releases after old work retires");

        state
            .commit_local_ice_restart(&replacement)
            .expect("native success commits the exact provisional replacement");
        assert!(state.provisional.is_none());
        assert!(Arc::ptr_eq(&state.current.attempt, &replacement));
        assert_eq!(state.current.pending.entries.len(), 1);
        assert!(
            state.current.provisional_root_lease.is_none(),
            "steady state cannot retain the provisional overlap root"
        );
    }

    #[test]
    fn v4_arc03_local_restart_overlap_charge_releases_on_commit_and_failure() {
        let policy = test_pending_candidate_policy();
        let root_claim = crate::runtime::attempt::remote_candidate_attempt_root_claim()
            .expect("fixture restart root claim is representable");
        let overlap_charge = FiniteResourceProvider::reservation_charge_for_test(root_claim)
            .expect("fixture restart reservation charge is representable");
        let (provider, _owner, _candidate, _lifetime, work_scope) =
            elastic_remote_candidate_test_resources_with_additional(policy, overlap_charge);
        let mut state = RemoteCandidateState::with_resources(policy, work_scope);
        let baseline = provider.in_use();

        let (_, replacement) = state
            .begin_local_ice_restart()
            .expect("the exact overlap charge admits one provisional restart");
        assert_eq!(
            provider.in_use(),
            baseline
                .checked_add(overlap_charge)
                .expect("fixture overlap total is representable")
        );
        state
            .commit_local_ice_restart(&replacement)
            .expect("commit installs the replacement attempt");
        assert_eq!(provider.in_use(), baseline);

        let (_, failed_replacement) = state
            .begin_local_ice_restart()
            .expect("the restored capacity admits another provisional restart");
        assert_eq!(
            provider.in_use(),
            baseline
                .checked_add(overlap_charge)
                .expect("fixture overlap total is representable")
        );
        state.fail_provisional(&failed_replacement);
        assert_eq!(provider.in_use(), baseline);
    }

    #[tokio::test]
    async fn v4_arc03_dropped_ice_transaction_fences_attempt_and_starts_exact_close_owner() {
        let policy = test_pending_candidate_policy();
        let state = Arc::new(SyncMutex::new(
            RemoteCandidateState::new_with_restart_overlap(policy),
        ));
        let resource_owner = test_resource_owner(1, 1);
        let (close_owner, _attempt_lifetime) = close_owner_fixture(&resource_owner);
        assert!(close_owner.attach_remote_candidates(Arc::clone(&state)));

        let replacement = {
            let mut candidate_state = state.lock();
            let (_, replacement) = candidate_state
                .begin_local_ice_restart()
                .expect("fixture local restart becomes provisional");
            replacement
        };
        let transaction = UncommittedIceTransaction::new(
            Arc::clone(&state),
            Arc::clone(&close_owner),
            Arc::clone(&replacement),
        );

        drop(transaction);

        {
            let candidate_state = state.lock();
            assert!(candidate_state.provisional.is_none());
            assert!(!candidate_state.current.attempt.is_active());
            assert!(!replacement.is_active());
        }
        close_owner
            .wait()
            .await
            .expect("the exact close owner completes after cancellation");
    }

    #[tokio::test]
    async fn v4_arc03_dropped_remote_description_cannot_leave_reusable_inflight_state() {
        let state = Arc::new(SyncMutex::new(RemoteCandidateState::new(
            test_pending_candidate_policy(),
        )));
        let resource_owner = test_resource_owner(1, 1);
        let (close_owner, _attempt_lifetime) = close_owner_fixture(&resource_owner);
        assert!(close_owner.attach_remote_candidates(Arc::clone(&state)));
        let prepared = state
            .lock()
            .prepare_remote_description(
                sdp_ice_credentials(&exact_ice_sdp("cancel-u", "cancel-p", "AA:BB:CC:DD"))
                    .expect("fixture remote credentials are exact"),
            )
            .expect("fixture remote description enters its transaction");
        assert!(state.lock().current.remote_description_in_flight);
        let transaction = UncommittedIceTransaction::new(
            Arc::clone(&state),
            Arc::clone(&close_owner),
            Arc::clone(&prepared.attempt),
        );

        drop(transaction);

        {
            let candidate_state = state.lock();
            assert!(!candidate_state.current.remote_description_in_flight);
            assert!(!candidate_state.current.attempt.is_active());
        }
        close_owner
            .wait()
            .await
            .expect("remote-description cancellation closes the exact connector");
    }

    #[test]
    fn v4_arc03j_local_restart_failure_discards_replacement_without_rollback() {
        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let mut state = RemoteCandidateState::new(test_pending_candidate_policy());
        let old_attempt = Arc::clone(&state.current.attempt);
        let (_retiring, replacement) = state
            .begin_local_ice_restart()
            .expect("local restart becomes provisional");
        assert_eq!(
            state.admit(observed_candidate(), &scope),
            PendingRemoteCandidateQueuePush::Queued
        );

        state.fail_provisional(&replacement);

        assert!(state.provisional.is_none());
        assert!(Arc::ptr_eq(&state.current.attempt, &old_attempt));
        assert!(!state.current.attempt.is_active());
        assert!(!replacement.is_active());
        assert_eq!(
            state.admit(observed_candidate(), &scope),
            PendingRemoteCandidateQueuePush::Retired,
            "failure cannot publish or renew a candidate envelope"
        );
    }

    #[tokio::test]
    async fn v4_arc03j_remote_same_fingerprint_credential_change_is_transactional() {
        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let mut replacement_candidate = observed_candidate();
        replacement_candidate.username_fragment = Some("second-fragment".to_string());
        let candidate_bytes = candidate_content_bytes(&replacement_candidate)
            .expect("fixture candidate content is representable");
        let two = NonZeroUsize::new(2).expect("two is nonzero");
        let policy = PendingRemoteCandidatePolicy::new(
            two,
            NonZeroUsize::new(candidate_bytes * 2)
                .expect("two fixture candidates have nonzero content"),
            two,
            two,
        );
        let mut state = RemoteCandidateState::new(policy);
        let fingerprint = "AA:BB:CC:DD";
        let initial_sdp = exact_ice_sdp("remote-fragment", "old-password", fingerprint);
        let initial = state
            .prepare_remote_description(
                sdp_ice_credentials(&initial_sdp).expect("initial credentials are exact"),
            )
            .expect("initial description uses the current attempt");
        assert!(!initial.provisional);
        drop(
            state
                .commit_remote_description(&initial)
                .expect("initial description commits"),
        );
        let old_attempt = Arc::clone(&state.current.attempt);
        let old_operation = old_attempt
            .try_enter()
            .expect("old candidate work can be in flight");

        let replacement_sdp = exact_ice_sdp("second-fragment", "new-password", fingerprint);
        assert_eq!(
            state.admit(replacement_candidate, &scope),
            PendingRemoteCandidateQueuePush::Queued,
            "a replacement candidate may arrive before its replacement SDP"
        );
        assert_eq!(state.current.pending.entries.len(), 1);
        assert_eq!(
            sdp_fingerprint(&initial_sdp),
            sdp_fingerprint(&replacement_sdp),
            "DTLS identity is unchanged for an in-place remote ICE restart"
        );
        let prepared = state
            .prepare_remote_description(
                sdp_ice_credentials(&replacement_sdp).expect("replacement credentials are exact"),
            )
            .expect("changed ICE credentials create a provisional replacement");
        assert!(prepared.provisional);
        assert!(!old_attempt.is_active());
        assert!(Arc::ptr_eq(&state.current.attempt, &old_attempt));
        assert!(state.provisional.is_some());

        let provisional = state
            .provisional
            .as_ref()
            .expect("replacement stays provisional");
        assert!(Arc::ptr_eq(
            &provisional
                .envelope
                .pending
                .entries
                .front()
                .expect("replacement queue contains its candidate")
                .attempt,
            &prepared.attempt
        ));

        let mut waiting = Box::pin(
            prepared
                .retiring
                .as_ref()
                .expect("remote restart retires the previous attempt")
                .wait_for_operations(),
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut waiting)
                .await
                .is_err(),
            "a delayed old-attempt completion holds the replacement barrier"
        );
        drop(old_operation);
        tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .expect("old-attempt work eventually drains");

        let pending = state
            .commit_remote_description(&prepared)
            .expect("native SDP success commits the exact replacement");
        assert_eq!(pending.len(), 1);
        assert!(state.provisional.is_none());
        assert!(Arc::ptr_eq(&state.current.attempt, &prepared.attempt));

        let mut old_candidate = observed_candidate();
        old_candidate.username_fragment = Some("remote-fragment".to_string());
        assert_eq!(
            state.admit(old_candidate, &scope),
            PendingRemoteCandidateQueuePush::Queued,
            "a delayed old candidate is retained only as bounded future-SDP work"
        );
        assert!(state.current.attempt.is_active());
        assert!(!state.current.last_candidate_matches_remote_credentials());
    }

    #[test]
    fn v4_arc03j_remote_restart_migrates_only_explicit_replacement_candidates() {
        fn initialized_state() -> RemoteCandidateState {
            let mut state =
                RemoteCandidateState::new_with_restart_overlap(test_pending_candidate_policy());
            let initial = state
                .prepare_remote_description(
                    sdp_ice_credentials(&exact_ice_sdp("old-u", "old-p", "AA:BB:CC:DD"))
                        .expect("initial credentials are exact"),
                )
                .expect("initial remote description starts");
            drop(
                state
                    .commit_remote_description(&initial)
                    .expect("initial remote description commits"),
            );
            state
        }

        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let replacement = sdp_ice_credentials(&exact_ice_sdp("new-u", "new-p", "AA:BB:CC:DD"))
            .expect("replacement credentials are exact");

        let mut state = initialized_state();
        let mut location_only = observed_candidate();
        location_only.username_fragment = None;
        assert_eq!(
            state.admit(location_only, &scope),
            PendingRemoteCandidateQueuePush::Queued
        );
        let prepared = state
            .prepare_remote_description(replacement.clone())
            .expect("changed credentials create a replacement attempt");
        assert!(
            state
                .provisional
                .as_ref()
                .expect("replacement stays provisional")
                .envelope
                .pending
                .entries
                .is_empty(),
            "a location-only candidate owned by the old attempt cannot migrate"
        );
        state.fail_remote_description(&prepared);

        let mut state = initialized_state();
        let mut replacement_candidate = observed_candidate();
        replacement_candidate.username_fragment = Some("new-u".to_string());
        assert_eq!(
            state.admit(replacement_candidate, &scope),
            PendingRemoteCandidateQueuePush::Queued
        );
        let prepared = state
            .prepare_remote_description(replacement.clone())
            .expect("changed credentials create a replacement attempt");
        let migrated = &state
            .provisional
            .as_ref()
            .expect("replacement stays provisional")
            .envelope
            .pending
            .entries;
        assert_eq!(migrated.len(), 1);
        assert!(Arc::ptr_eq(
            &migrated
                .front()
                .expect("replacement queue contains its candidate")
                .attempt,
            &prepared.attempt
        ));
        state.fail_remote_description(&prepared);

        let mut state = initialized_state();
        let mut old_candidate = observed_candidate();
        old_candidate.username_fragment = Some("old-u".to_string());
        assert_eq!(
            state.admit(old_candidate, &scope),
            PendingRemoteCandidateQueuePush::Queued
        );
        let prepared = state
            .prepare_remote_description(replacement.clone())
            .expect("changed credentials create a replacement attempt");
        assert!(
            state
                .provisional
                .as_ref()
                .expect("replacement stays provisional")
                .envelope
                .pending
                .entries
                .is_empty(),
            "an old-credential candidate cannot migrate into the replacement attempt"
        );
        state.fail_remote_description(&prepared);

        let mut state = initialized_state();
        let prepared = state
            .prepare_remote_description(replacement)
            .expect("changed credentials create a replacement attempt");
        let mut replacement_owned_location = observed_candidate();
        replacement_owned_location.username_fragment = None;
        assert_eq!(
            state.admit(replacement_owned_location, &scope),
            PendingRemoteCandidateQueuePush::Queued,
            "the exact provisional owner may admit a location-only candidate"
        );
        let provisional = state
            .provisional
            .as_ref()
            .expect("replacement stays provisional");
        assert_eq!(provisional.envelope.pending.entries.len(), 1);
        assert!(Arc::ptr_eq(
            &provisional
                .envelope
                .pending
                .entries
                .front()
                .expect("replacement queue contains its candidate")
                .attempt,
            &prepared.attempt
        ));
        assert_eq!(
            state
                .commit_remote_description(&prepared)
                .expect("replacement description commits")
                .len(),
            1,
            "a location-only candidate admitted by the replacement owner survives commit"
        );
    }

    #[test]
    fn v4_arc03j_media_renegotiation_cannot_mint_a_candidate_attempt() {
        let mut state = RemoteCandidateState::new(test_pending_candidate_policy());
        let initial_sdp = exact_ice_sdp("data-u", "data-p", "AA:BB:CC:DD");
        let initial = state
            .prepare_remote_description(
                sdp_ice_credentials(&initial_sdp).expect("initial credentials are exact"),
            )
            .expect("initial remote description starts");
        drop(
            state
                .commit_remote_description(&initial)
                .expect("initial remote description commits"),
        );
        let exact_attempt = Arc::clone(&state.current.attempt);

        let added_media = "v=0\r\n\
                           a=fingerprint:sha-256 AA:BB:CC:DD\r\n\
                           m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
                           a=mid:data\r\n\
                           a=ice-ufrag:data-u\r\n\
                           a=ice-pwd:data-p\r\n\
                           m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
                           a=mid:audio\r\n\
                           a=ice-ufrag:audio-u\r\n\
                           a=ice-pwd:audio-p\r\n";
        let renegotiation = state
            .prepare_remote_description(
                sdp_ice_credentials(added_media).expect("added media credentials are exact"),
            )
            .expect("ordinary media renegotiation stays on the current attempt");
        assert!(!renegotiation.provisional);
        assert!(Arc::ptr_eq(&renegotiation.attempt, &exact_attempt));
        drop(
            state
                .commit_remote_description(&renegotiation)
                .expect("renegotiation updates bindings without renewing capacity"),
        );
        assert!(Arc::ptr_eq(&state.current.attempt, &exact_attempt));
    }

    #[test]
    fn v4_arc03j_terminal_candidate_exhaustion_stops_later_hash_and_work_admission() {
        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let mut over_limit = observed_candidate();
        over_limit.candidate.push_str(" distinct");
        let mut state =
            RemoteCandidateState::new(test_pending_candidate_policy_for(&[over_limit.clone()]));
        assert_eq!(
            state.admit(observed_candidate(), &scope),
            PendingRemoteCandidateQueuePush::Queued
        );
        assert_eq!(
            state.admit(over_limit, &scope),
            PendingRemoteCandidateQueuePush::Refused
        );
        let terminal_report = state.current.pending.budget.report();
        for index in 0..1024 {
            let mut hostile = observed_candidate();
            hostile.candidate.push_str(&format!(" hostile-{index}"));
            assert_eq!(
                state.admit(hostile, &scope),
                PendingRemoteCandidateQueuePush::Retired
            );
        }
        assert_eq!(
            state.current.pending.budget.report(),
            terminal_report,
            "terminal attempts perform no later digest, retention, duplicate, or work accounting"
        );
    }

    #[test]
    fn v4_arc03h_post_sdp_candidates_share_one_cumulative_attempt_envelope() {
        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let first = observed_candidate();
        let content_bytes = candidate_content_bytes(&first).expect("fixture content is finite");
        let two = NonZeroUsize::new(2).expect("two is nonzero");
        let policy = PendingRemoteCandidatePolicy::new(
            two,
            NonZeroUsize::new(content_bytes * 2).expect("fixture content bound is nonzero"),
            two,
            NonZeroUsize::new(1).expect("one application is permitted"),
        );
        let mut state = RemoteCandidateState::new(policy);
        state.current.remote_description_set = true;

        assert_eq!(
            state.admit(first.clone(), &scope),
            PendingRemoteCandidateQueuePush::Queued
        );
        let first_pending = state
            .current
            .pending
            .pop_last_for_application(&scope)
            .expect("post-SDP candidate moves directly to application");
        let first_reservation = first_pending
            ._queue_reservation
            .expect("unique candidate carries the attempt budget");
        assert!(first_reservation.budget.reserve_application_work());
        state
            .current
            .retained_reservations
            .push_back(first_reservation);

        assert_eq!(
            state.admit(first.clone(), &scope),
            PendingRemoteCandidateQueuePush::Duplicate
        );
        assert_eq!(
            state.admit(first.clone(), &scope),
            PendingRemoteCandidateQueuePush::Duplicate
        );
        assert_eq!(
            state.admit(first, &scope),
            PendingRemoteCandidateQueuePush::Refused
        );

        let old_budget = Arc::clone(&state.current.pending.budget);
        assert_eq!(old_budget.report(), (1, content_bytes, 2, 1, false));
        assert!(!state.current.attempt.is_active());

        let mut second = observed_candidate();
        second.candidate.replace_range(0..1, "C");
        assert_eq!(
            state.admit(second, &scope),
            PendingRemoteCandidateQueuePush::Retired,
            "the first envelope refusal makes later unique submissions constant-work refusals"
        );
        let (retiring_attempt, replacement_attempt) = state
            .begin_local_ice_restart()
            .expect("only an explicit restart creates a fresh envelope");
        assert!(!retiring_attempt.is_active());
        let replacement = state
            .provisional
            .as_ref()
            .expect("replacement is provisional");
        assert!(Arc::ptr_eq(
            &replacement.envelope.attempt,
            &replacement_attempt
        ));
        assert_eq!(
            replacement.envelope.pending.budget.report(),
            (0, 0, 0, 0, false)
        );
        assert_eq!(old_budget.report(), (1, content_bytes, 2, 1, false));
    }

    #[test]
    #[ignore = "owner-run observation; requires an explicit candidate-burst workload shape"]
    fn v4_arc03g_measure_candidate_burst_without_selecting_budget() {
        let candidate_count = std::env::var("MYOWNMESH_ARC03_OBSERVE_CANDIDATES")
            .expect("candidate-burst observation supplies a candidate count")
            .parse::<usize>()
            .ok()
            .and_then(NonZeroUsize::new)
            .expect("candidate-burst count is a nonzero integer");
        let mut candidates = Vec::with_capacity(candidate_count.get());
        let mut total_content_bytes = 0usize;
        for index in 0..candidate_count.get() {
            let mut candidate = observed_candidate();
            candidate.candidate.push_str(&format!(" {index}"));
            let content_bytes = candidate_content_bytes(&candidate)
                .expect("finite observation candidate content is representable");
            total_content_bytes = total_content_bytes
                .checked_add(content_bytes)
                .expect("finite observation burst content is representable");
            candidates.push(candidate);
        }
        let policy = PendingRemoteCandidatePolicy::new(
            candidate_count,
            NonZeroUsize::new(total_content_bytes)
                .expect("observation burst carries nonzero candidate content"),
            candidate_count,
            candidate_count,
        );
        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let mut queue = PendingRemoteCandidateQueue::new(policy);
        let started = Instant::now();
        for (index, candidate) in candidates.iter().cloned().enumerate() {
            let pushed_at = Instant::now();
            assert_eq!(
                queue.push_observed_for_test(
                    candidate,
                    Arc::new(RemoteCandidateAttemptIdentity::default()),
                    &scope,
                ),
                PendingRemoteCandidateQueuePush::Queued
            );
            let (items, content_bytes, duplicates, work, poisoned) = queue.budget.report();
            println!(
                "arc03_candidate_burst_raw index={index} push_ns={} items={items} content_bytes={content_bytes} duplicates={duplicates} application_work={work} poisoned={poisoned}",
                pushed_at.elapsed().as_nanos()
            );
        }
        let duplicate_at = Instant::now();
        assert_eq!(
            queue.push_observed_for_test(
                candidates[0].clone(),
                Arc::new(RemoteCandidateAttemptIdentity::default()),
                &scope,
            ),
            PendingRemoteCandidateQueuePush::Duplicate
        );
        println!(
            "arc03_candidate_burst_raw duplicate_ns={} total_push_ns={}",
            duplicate_at.elapsed().as_nanos(),
            started.elapsed().as_nanos()
        );
        let budget = Arc::clone(&queue.budget);
        drop(queue.take());
        assert_eq!(
            budget.report(),
            (candidate_count.get(), total_content_bytes, 1, 0, false)
        );
    }

    #[test]
    fn v4_arc03_candidate_apply_observation_survives_await_and_cancellation() {
        let process = ProcessResourceRoot::isolated();
        let context = process.mesh_runtime_scope().network_instance_scope();
        let scope = context.peer_connection_scope();
        let pending = PendingRemoteCandidate::observe(
            observed_candidate(),
            Arc::new(RemoteCandidateAttemptIdentity::default()),
            &scope,
        );
        let mut application = Box::pin(apply_pending_remote_candidate(pending, |_| {
            std::future::pending::<std::result::Result<(), ()>>()
        }));
        let waker = Waker::noop();
        let mut task_context = Context::from_waker(waker);

        assert_eq!(application.as_mut().poll(&mut task_context), Poll::Pending);
        assert_eq!(
            candidate_report(&context.report().pre_authentication).active_lease_count,
            1
        );
        drop(application);
        let completed = candidate_report(&context.report().pre_authentication);
        assert_eq!(completed.active, ResourceUse::ZERO);
        assert_eq!(completed.completed_lease_count, 1);
    }

    #[tokio::test]
    async fn v4_arc03_retirement_cancels_inflight_candidate_observation() {
        let process = ProcessResourceRoot::isolated();
        let context = process.mesh_runtime_scope().network_instance_scope();
        let scope = context.peer_connection_scope();
        let pending = PendingRemoteCandidate::observe(
            observed_candidate(),
            Arc::new(RemoteCandidateAttemptIdentity::default()),
            &scope,
        );
        let incarnation = Arc::new(WebRtcConnectorIncarnation::new());
        let retirement = incarnation.subscribe_retirement();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let application = tokio::spawn(async move {
            await_until_connector_retirement(
                retirement,
                apply_pending_remote_candidate(pending, |_| async move {
                    let _ = entered_tx.send(());
                    std::future::pending::<std::result::Result<(), ()>>().await
                }),
            )
            .await
        });

        entered_rx
            .await
            .expect("candidate application was polled before retirement");
        assert_eq!(
            candidate_report(&context.report().pre_authentication).active_lease_count,
            1
        );
        incarnation.retire();
        assert!(application.await.expect("application task joins").is_none());
        let completed = candidate_report(&context.report().pre_authentication);
        assert_eq!(completed.active, ResourceUse::ZERO);
        assert_eq!(completed.completed_lease_count, 1);
    }

    #[test]
    fn v4_arc03_callback_stamp_requires_exact_live_worker() {
        let (first_candidate, first_lifetime) =
            crate::runtime::attempt::connector_candidate_for_test(
                crate::runtime::runtime_for_test(),
            );
        let (second_candidate, second_lifetime) =
            crate::runtime::attempt::connector_candidate_for_test(
                crate::runtime::runtime_for_test(),
            );
        let first = admitted_ownership(first_candidate);
        let second = admitted_ownership(second_candidate);
        let event = stamped_event(&first, TransportEvent::DataChannelClosed);
        assert!(first.accepts(&event));
        assert!(!second.accepts(&event));
        first.retire();
        assert!(!first.accepts(&event));
        drop((first_lifetime, second_lifetime));
    }

    #[test]
    fn v4_arc03_retired_candidate_claim_waits_for_cleanup_completion() {
        let (candidate, lifetime) = crate::runtime::attempt::connector_candidate_for_test(
            crate::runtime::runtime_for_test(),
        );
        let ownership = admitted_ownership(candidate);

        ownership.retire();
        assert!(ownership.cleanup_candidate_reserved_for_test());
        ownership.complete_cleanup();
        assert!(!ownership.cleanup_candidate_reserved_for_test());
        drop(lifetime);
    }

    #[tokio::test]
    async fn v4_arc03_retirement_stops_event_pump_before_stale_callback_queueing() {
        let (candidate, lifetime) = crate::runtime::attempt::connector_candidate_for_test(
            crate::runtime::runtime_for_test(),
        );
        let ownership = admitted_ownership(candidate);
        let (events_tx, events) = test_event_mailboxes(1);
        let remote_candidates = Arc::new(SyncMutex::new(test_remote_candidate_state()));
        let mut receiver = WebRtcConnectorEventReceiver {
            ownership: ownership.clone(),
            retirement: ownership.incarnation.subscribe_retirement(),
            attempt_retirement: None,
            raw: events,
            attempt_lifetime: Some(lifetime),
            remote_candidates,
            close_owner: None,
            reclaim: None,
            data_channel_open_committed: false,
            data_channel_closed: false,
            operation_fence: Arc::clone(&ownership.operation_fence),
        };

        ownership.retire();
        events_tx
            .try_insert_for_test(TransportEvent::DataChannelClosed, None)
            .expect("retained callback sender still has a bounded raw receiver");

        assert!(receiver.recv().await.is_none());
    }

    fn assert_callback_class_backpressure(first: TransportEvent, second: TransportEvent) {
        let (events, mut receiver) = test_event_mailboxes(1);
        let policy = test_callback_policy(
            std::num::NonZeroUsize::new(1).expect("fixture capacity is nonzero"),
        );
        let sink = test_event_sink(events, policy, None);
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);

        let mut first = Box::pin(sink.emit(first));
        assert_eq!(first.as_mut().poll(&mut context), Poll::Ready(true));

        let mut second = Box::pin(sink.emit(second));
        assert_eq!(second.as_mut().poll(&mut context), Poll::Ready(false));
        drop(
            receiver
                .try_recv()
                .expect("first callback occupies the queue"),
        );
        assert!(
            receiver.try_recv().is_err(),
            "overload creates no hidden queue"
        );
    }

    fn assert_realtime_flow_backpressure(first: TransportEvent, second: TransportEvent) {
        let policy = explicit_realtime_callback_policy(16, 1, 1, 16, 1, 32);
        let observer = Arc::new(TestRealtimeObserver::default());
        let registry = test_realtime_registry_with_observer(
            policy,
            observer.clone() as Arc<dyn RealtimeFlowObserver>,
        );
        let flow = registry
            .open_inbound_flow()
            .expect("fixture admits one exact real-time flow");
        let payload_bytes = |event: &TransportEvent| match event {
            TransportEvent::RealtimeUnit(delivery) => delivery.payload_bytes(),
            _ => panic!("fixture event must be a real-time unit"),
        };
        let first_reservation = flow
            .reserve_output(payload_bytes(&first))
            .expect("fixture reserves the first complete unit");
        assert!(flow.enqueue(
            QueuedTransportEvent {
                event: first,
                observation: None,
                callback_work: None,
            },
            first_reservation,
        ));
        let second_reservation = flow
            .reserve_output(payload_bytes(&second))
            .expect("aggregate bytes admit the competing unit before queue pressure");
        assert!(flow.enqueue(
            QueuedTransportEvent {
                event: second,
                observation: None,
                callback_work: None,
            },
            second_reservation,
        ));
        assert!(observer.observations.lock().iter().any(|observation| {
            matches!(
                observation,
                RealtimeFlowObservation::Drop {
                    reason: RealtimeFlowDropReason::FlowQueueFull,
                    ..
                }
            )
        }));
        assert!(matches!(
            registry.try_recv().map(|queued| queued.event),
            Some(TransportEvent::RealtimeUnit(_))
        ));
        assert!(registry.try_recv().is_none());
    }

    #[test]
    fn v4_arc03i_lifecycle_control_does_not_compete_for_mailbox_capacity() {
        let (events, mut receiver) = test_event_mailboxes(1);
        let policy =
            test_callback_policy(NonZeroUsize::new(1).expect("fixture capacity is nonzero"));
        let sink = test_event_sink(events, policy, None);
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);

        let mut open = Box::pin(sink.emit(TransportEvent::DataChannelOpen));
        assert_eq!(open.as_mut().poll(&mut context), Poll::Ready(true));
        let mut close = Box::pin(sink.emit(TransportEvent::DataChannelClosed));
        assert_eq!(close.as_mut().poll(&mut context), Poll::Ready(true));
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::DataChannelClosed)
        ));
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn v4_arc03_data_callback_contention_honors_configured_bound() {
        assert_callback_class_backpressure(
            TransportEvent::Message(Bytes::from_static(b"first")),
            TransportEvent::Message(Bytes::from_static(b"second")),
        );
    }

    #[test]
    fn v4_arc03_realtime_callback_contention_honors_configured_bound() {
        assert_realtime_flow_backpressure(
            test_realtime_event(0, 0, b"first"),
            test_realtime_event(0, 1, b"second"),
        );
    }

    #[tokio::test]
    #[ignore = "owner-run observation; requires only workload-shape inputs"]
    async fn v4_arc03_measure_callback_classes_without_selecting_a_budget() {
        fn workload_nonzero(name: &str) -> std::num::NonZeroUsize {
            std::env::var(name)
                .unwrap_or_else(|_| panic!("observation scenario supplies {name}"))
                .parse::<usize>()
                .ok()
                .and_then(std::num::NonZeroUsize::new)
                .unwrap_or_else(|| panic!("{name} must be a nonzero integer"))
        }
        let samples = workload_nonzero("MYOWNMESH_ARC03_OBSERVE_SAMPLES");
        let flows = workload_nonzero("MYOWNMESH_ARC03_OBSERVE_FLOWS");
        let payload_bytes = workload_nonzero("MYOWNMESH_ARC03_OBSERVE_PAYLOAD_BYTES");
        let total_realtime_units = samples
            .get()
            .checked_mul(flows.get())
            .expect("observation workload unit count fits usize");
        let callback_capacity =
            std::num::NonZeroUsize::new(samples.get().max(total_realtime_units))
                .expect("derived observation queue is nonzero");
        // This raw laboratory envelope is derived only to hold the requested
        // finite observation workload. It is not a production policy or a
        // proposed default.
        let policy = test_callback_policy(callback_capacity);

        for class in [
            ConnectorCallbackClass::Control,
            ConnectorCallbackClass::EndpointData,
        ] {
            let (events, mut receiver) = test_event_mailboxes_with_policy(policy);
            let sink = test_event_sink(events, policy, None);
            let mut queued_at = std::collections::VecDeque::new();
            for index in 0..samples.get() {
                let event = match class {
                    ConnectorCallbackClass::Control => TransportEvent::DataChannelClosed,
                    ConnectorCallbackClass::EndpointData => {
                        TransportEvent::Message(Bytes::from(index.to_le_bytes().to_vec()))
                    }
                    ConnectorCallbackClass::Realtime => unreachable!(),
                };
                let observed_at = Instant::now();
                assert!(sink.emit(event).await);
                queued_at.push_back(observed_at);
            }
            for index in 0..samples.get() {
                receiver.recv().await.expect("observed callback arrives");
                let queue_age = queued_at
                    .pop_front()
                    .expect("one timestamp exists per observed callback")
                    .elapsed();
                println!(
                    "arc03_callback_raw class={class:?} index={index} queue_age_ns={}",
                    queue_age.as_nanos()
                );
            }
        }

        let observer = Arc::new(TestRealtimeObserver::default());
        let registry = test_realtime_registry_with_observer(
            policy,
            observer.clone() as Arc<dyn RealtimeFlowObserver>,
        );
        let mut admitted_flows = Vec::with_capacity(flows.get());
        for _ in 0..flows.get() {
            admitted_flows.push(
                registry
                    .open_inbound_flow()
                    .expect("raw observation envelope admits the requested flow"),
            );
        }
        for (flow_index, flow) in admitted_flows.iter().enumerate() {
            for unit_index in 0..samples.get() {
                let payload = Bytes::from(vec![0u8; payload_bytes.get()]);
                let reservation = flow
                    .reserve_output(payload.len())
                    .expect("raw observation envelope retains the requested unit");
                assert!(flow.enqueue(
                    QueuedTransportEvent {
                        event: TransportEvent::RealtimeUnit(RealtimeInboundDelivery::new(
                            test_label(u8::try_from(flow_index).unwrap_or(u8::MAX)),
                            RealtimeRecvUnit {
                                timestamp: unit_index as u32,
                                marker: false,
                                data: payload,
                            },
                        )),
                        observation: None,
                        callback_work: None,
                    },
                    reservation,
                ));
            }
        }
        for _ in 0..total_realtime_units {
            registry
                .try_recv()
                .expect("raw real-time observation unit remains serviceable");
        }
        for observation in observer.observations.lock().iter() {
            println!("arc03_realtime_raw observation={observation:?}");
        }
        drop(admitted_flows);
    }

    #[test]
    #[ignore = "owner-run observation; requires explicit saturation workload inputs"]
    fn v4_arc03g_measure_saturated_flow_fairness_without_selecting_budget() {
        let workload_nonzero = |name: &str| {
            std::env::var(name)
                .unwrap_or_else(|_| panic!("observation scenario supplies {name}"))
                .parse::<usize>()
                .ok()
                .and_then(NonZeroUsize::new)
                .unwrap_or_else(|| panic!("{name} must be a nonzero integer"))
        };
        let saturated_units = workload_nonzero("MYOWNMESH_ARC03_OBSERVE_SATURATED_UNITS");
        let latency_units = workload_nonzero("MYOWNMESH_ARC03_OBSERVE_LATENCY_UNITS");
        let payload_bytes = workload_nonzero("MYOWNMESH_ARC03_OBSERVE_PAYLOAD_BYTES");
        assert!(
            latency_units.get() <= saturated_units.get(),
            "the latency-sensitive observation flow must fit the saturated flow's explicit queue shape"
        );
        let total_units = saturated_units
            .get()
            .checked_add(latency_units.get())
            .expect("finite observation unit count is representable");
        let retained_bytes = total_units
            .checked_mul(payload_bytes.get())
            .expect("finite observation bytes are representable");
        let policy = explicit_realtime_callback_policy(
            payload_bytes.get(),
            2,
            saturated_units.get(),
            payload_bytes.get(),
            1,
            retained_bytes,
        );
        let registry = test_realtime_registry(policy);
        let saturated_label = test_label(0);
        let latency_label = test_label(1);
        let saturated = registry
            .open_inbound_flow()
            .expect("observation admits the saturated flow");
        let latency = registry
            .open_inbound_flow()
            .expect("observation admits the latency-sensitive flow");
        let mut saturated_at = std::collections::VecDeque::new();
        let mut latency_at = std::collections::VecDeque::new();

        for index in 0..saturated_units.get() {
            let payload = Bytes::from(vec![0u8; payload_bytes.get()]);
            let reservation = saturated
                .reserve_output(payload.len())
                .expect("observation reserves saturated-flow output");
            saturated_at.push_back(Instant::now());
            assert!(saturated.enqueue(
                QueuedTransportEvent {
                    event: TransportEvent::RealtimeUnit(RealtimeInboundDelivery::new(
                        saturated_label.clone(),
                        RealtimeRecvUnit {
                            timestamp: u32::try_from(index).unwrap_or(u32::MAX),
                            marker: false,
                            data: payload,
                        },
                    )),
                    observation: None,
                    callback_work: None,
                },
                reservation,
            ));
        }
        for index in 0..latency_units.get() {
            let payload = Bytes::from(vec![0u8; payload_bytes.get()]);
            let reservation = latency
                .reserve_output(payload.len())
                .expect("observation reserves latency-flow output");
            latency_at.push_back(Instant::now());
            assert!(latency.enqueue(
                QueuedTransportEvent {
                    event: TransportEvent::RealtimeUnit(RealtimeInboundDelivery::new(
                        latency_label.clone(),
                        RealtimeRecvUnit {
                            timestamp: u32::try_from(index).unwrap_or(u32::MAX),
                            marker: false,
                            data: payload,
                        },
                    )),
                    observation: None,
                    callback_work: None,
                },
                reservation,
            ));
        }

        let mut first_latency_service_index = None;
        for service_index in 0..total_units {
            let event = registry
                .try_recv()
                .expect("every admitted observation unit remains serviceable")
                .event;
            let TransportEvent::RealtimeUnit(delivery) = event else {
                panic!("observation registry returned a non-real-time event");
            };
            // The label is the only thing that says which flow served this
            // turn, and it is a fact this observation minted rather than
            // anything read back out of the unit.
            if delivery.label == saturated_label {
                let queued_at = saturated_at
                    .pop_front()
                    .expect("one timestamp exists per saturated unit");
                println!(
                    "arc03_flow_fairness_raw class=saturated service_index={service_index} queue_age_ns={}",
                    queued_at.elapsed().as_nanos()
                );
            } else {
                first_latency_service_index.get_or_insert(service_index);
                let queued_at = latency_at
                    .pop_front()
                    .expect("one timestamp exists per latency-sensitive unit");
                println!(
                    "arc03_flow_fairness_raw class=latency service_index={service_index} queue_age_ns={}",
                    queued_at.elapsed().as_nanos()
                );
            }
        }
        assert!(
            first_latency_service_index.is_some_and(|index| index <= 1),
            "a ready latency-sensitive flow must receive a turn after at most one saturated-flow unit"
        );
    }

    #[tokio::test]
    async fn v4_arc03h_callback_producer_flood_cannot_queue_behind_full_mailbox() {
        let (events, mut receiver) = test_event_mailboxes(1);
        let policy = test_callback_policy(
            std::num::NonZeroUsize::new(1).expect("fixture capacity is nonzero"),
        );
        let sink = test_event_sink(events, policy, None);

        assert!(
            sink.emit(TransportEvent::Message(Bytes::from_static(b"retained")))
                .await
        );
        let mut producers = tokio::task::JoinSet::new();
        for _ in 0..128 {
            let producer = sink.clone();
            producers.spawn(async move {
                producer
                    .emit(TransportEvent::Message(Bytes::from_static(b"refused")))
                    .await
            });
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while let Some(result) = producers.join_next().await {
                assert!(!result.expect("producer task joins"));
            }
        })
        .await
        .expect("all overloaded producers finish without a hidden queue");
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::Message(bytes)) if bytes == Bytes::from_static(b"retained")
        ));
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn v4_arc03_event_receiver_adds_no_hidden_engine_queue() {
        let (candidate, lifetime) = crate::runtime::attempt::connector_candidate_for_test(
            crate::runtime::runtime_for_test(),
        );
        let attempt_retirement = candidate.liveness().subscribe_retirement();
        let ownership = admitted_ownership(candidate);
        let (events_tx, events) = test_event_mailboxes(1);
        let mut receiver = WebRtcConnectorEventReceiver {
            ownership: ownership.clone(),
            retirement: ownership.incarnation.subscribe_retirement(),
            attempt_retirement: Some(attempt_retirement),
            raw: events,
            attempt_lifetime: Some(lifetime),
            remote_candidates: Arc::new(SyncMutex::new(test_remote_candidate_state())),
            close_owner: None,
            reclaim: None,
            data_channel_open_committed: false,
            data_channel_closed: false,
            operation_fence: Arc::clone(&ownership.operation_fence),
        };
        events_tx
            .try_insert_for_test(TransportEvent::DataChannelOpen, None)
            .expect("first callback is queued");
        let first = receiver.recv().await.expect("first event reaches engine");
        events_tx
            .try_insert_for_test(TransportEvent::DataChannelClosed, None)
            .expect("second callback is queued behind the engine handoff");

        let mut second_receive = Box::pin(receiver.recv());
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        assert!(matches!(
            second_receive.as_mut().poll(&mut context),
            Poll::Ready(Some(_))
        ));
        drop(first);
    }

    #[tokio::test]
    async fn v4_arc03_attempt_retirement_wakes_and_reclaims_silent_candidate() {
        let process = ProcessResourceRoot::isolated();
        let context = process.mesh_runtime_scope().network_instance_scope();
        let resource_scope = context.peer_connection_scope();
        let (candidate, lifetime) = crate::runtime::attempt::connector_candidate_for_test(
            crate::runtime::runtime_for_test(),
        );
        let attempt_retirement = candidate.liveness().subscribe_retirement();
        let ownership = admitted_ownership(candidate);
        let remote_candidates = Arc::new(SyncMutex::new(test_remote_candidate_state()));
        {
            let mut candidates = remote_candidates.lock();
            let attempt = Arc::clone(&candidates.current.attempt);
            candidates.current.pending.push_observed_for_test(
                observed_candidate(),
                attempt,
                &resource_scope,
            );
        }
        let (_events_tx, events) = test_event_mailboxes(1);
        let mut receiver = WebRtcConnectorEventReceiver {
            ownership: ownership.clone(),
            retirement: ownership.incarnation.subscribe_retirement(),
            attempt_retirement: Some(attempt_retirement),
            raw: events,
            attempt_lifetime: Some(lifetime),
            remote_candidates,
            close_owner: None,
            reclaim: None,
            data_channel_open_committed: false,
            data_channel_closed: false,
            operation_fence: Arc::clone(&ownership.operation_fence),
        };
        assert_eq!(
            candidate_report(&context.report().pre_authentication).active_lease_count,
            2
        );

        receiver.retire_attempt_for_test();
        assert!(receiver.recv().await.is_none());
        assert!(!ownership.incarnation.is_active());
        assert_eq!(
            candidate_report(&context.report().pre_authentication).active,
            ResourceUse::ZERO
        );
    }

    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    async fn v4_arc03j_native_local_ice_restart_commits_exact_replacement() {
        // Transactional restart retains the old candidate-attempt claim until
        // the replacement attempt commits.
        let owner = test_resource_owner(2, 4);
        let scope = ProcessResourceRoot::isolated()
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(owner, test_webrtc_profile(4));
        let (worker, _events) = transport
            .open_connector_peer(Role::Offerer, &[], &[], scope)
            .await
            .expect("data-only connector is constructed");
        worker
            .create_offer()
            .await
            .expect("local description starts the native ICE agent");
        let previous_attempt = Arc::clone(&worker.remote_candidates.lock().current.attempt);

        worker
            .restart_ice()
            .await
            .expect("native local restart succeeds");

        {
            let state = worker.remote_candidates.lock();
            assert!(state.provisional.is_none());
            assert!(!Arc::ptr_eq(&state.current.attempt, &previous_attempt));
            assert!(!previous_attempt.is_active());
            assert!(state.current.attempt.is_active());
        }
        worker
            .retire_and_close()
            .await
            .expect("native peer closes through its exact owner");
    }

    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    async fn v4_arc03j_native_local_ice_restart_failure_retires_connector() {
        // The failure interleaving exercises the same provisional two-attempt
        // ownership overlap as the successful restart.
        let owner = test_resource_owner(2, 4);
        let scope = ProcessResourceRoot::isolated()
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(owner, test_webrtc_profile(4));
        let (worker, _events) = transport
            .open_connector_peer(Role::Offerer, &[], &[], scope)
            .await
            .expect("data-only connector is constructed");
        worker
            .create_offer()
            .await
            .expect("local description starts the native ICE agent");
        let previous_attempt = Arc::clone(&worker.remote_candidates.lock().current.attempt);
        worker
            .session
            .pc
            .close()
            .await
            .expect("fixture closes the native peer without retiring its V4 owner");

        worker
            .restart_ice()
            .await
            .expect_err("native restart failure cannot publish replacement capacity");

        {
            let state = worker.remote_candidates.lock();
            assert!(state.provisional.is_none());
            assert!(Arc::ptr_eq(&state.current.attempt, &previous_attempt));
            assert!(!state.current.attempt.is_active());
        }
        assert!(!worker.ownership.incarnation.is_active());
        worker
            .retire_and_close()
            .await
            .expect("idempotent final cleanup owns the already closed native peer");
    }

    #[tokio::test]
    async fn v4_arc03_cancelled_pending_native_constructor_retains_exact_claim() {
        let process = ProcessResourceRoot::isolated();
        let context = process.mesh_runtime_scope().network_instance_scope();
        let owner = test_resource_owner(1, 4);
        let mut transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(owner.clone(), test_webrtc_profile(4));
        let hook = ConstructionTestHook::new(ConstructionPause::BeforeNativeConstructor);
        transport.construction_hook = Some(Arc::clone(&hook));
        let construction_scope = context.peer_connection_scope();
        let construction = tokio::spawn(async move {
            transport
                .open_connector_peer(Role::Answerer, &[], &[], construction_scope)
                .await
        });

        let entered = hook
            .created
            .acquire()
            .await
            .expect("construction hook remains open");
        entered.forget();
        construction.abort();
        assert!(construction.await.is_err());

        for _ in 0..32 {
            if owner.report().failed_cleanup_candidates == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(owner.report().active_candidates, 1);
        assert_eq!(owner.report().failed_cleanup_candidates, 1);
        assert!(!owner.report().accounting_poisoned);
    }

    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    async fn v4_arc03_cancelled_construction_closes_partial_native_peer() {
        let process = ProcessResourceRoot::isolated();
        let context = process.mesh_runtime_scope().network_instance_scope();
        let mut transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(test_resource_owner(1, 4), test_webrtc_profile(4));
        let hook = ConstructionTestHook::new(ConstructionPause::AfterNativeAllocation);
        transport.construction_hook = Some(Arc::clone(&hook));
        let construction_scope = context.peer_connection_scope();
        let construction = tokio::spawn(async move {
            transport
                .open_connector_peer(Role::Answerer, &[], &[], construction_scope)
                .await
        });

        let created = hook
            .created
            .acquire()
            .await
            .expect("construction hook remains open");
        created.forget();
        let native = hook
            .peer_connection
            .lock()
            .take()
            .expect("native peer exists at the cancellation point");

        let close_observed_at = Instant::now();
        construction.abort();
        assert!(construction.await.is_err());
        hook.resume.add_permits(1);

        tokio::time::timeout(Duration::from_secs(10), async {
            while native.connection_state() != RTCPeerConnectionState::Closed {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("owned construction closes the partial native peer");
        if std::env::var_os("MYOWNMESH_ARC03_OBSERVE_RAW").is_some() {
            println!(
                "arc03_native_close_raw disposition=success close_ns={}",
                close_observed_at.elapsed().as_nanos()
            );
        }
        drop(native);

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let report = context.report();
                let callbacks = report
                    .pre_authentication
                    .iter()
                    .find(|entry| entry.family == PreAuthResourceFamily::Callback)
                    .expect("callback family exists");
                let tasks = report
                    .pre_authentication
                    .iter()
                    .find(|entry| entry.family == PreAuthResourceFamily::Task)
                    .expect("task family exists");
                if callbacks.active == ResourceUse::ZERO && tasks.active == ResourceUse::ZERO {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("partial construction releases callback and task observations");
    }

    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    async fn v4_arc03_cancelled_construction_with_native_close_error_retains_exact_claim() {
        let owner = test_resource_owner(2, 4);
        let process = ProcessResourceRoot::isolated();
        let context = process.mesh_runtime_scope().network_instance_scope();
        let mut transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(owner.clone(), test_webrtc_profile(4));
        let hook =
            ConstructionTestHook::new(ConstructionPause::AfterNativeAllocationWithCloseError);
        transport.construction_hook = Some(Arc::clone(&hook));
        let construction_scope = context.peer_connection_scope();
        let construction = tokio::spawn(async move {
            transport
                .open_connector_peer(Role::Answerer, &[], &[], construction_scope)
                .await
        });

        let created = hook
            .created
            .acquire()
            .await
            .expect("construction hook remains open");
        created.forget();
        let native = hook
            .peer_connection
            .lock()
            .take()
            .expect("native peer exists at the cancellation point");

        let close_observed_at = Instant::now();
        construction.abort();
        assert!(construction.await.is_err());
        hook.resume.add_permits(1);

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let report = owner.report();
                if native.connection_state() == RTCPeerConnectionState::Closed
                    && report.active_candidates == 1
                    && report.failed_cleanup_candidates == 1
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled construction closes the native peer and retains its exact failed claim");
        if std::env::var_os("MYOWNMESH_ARC03_OBSERVE_RAW").is_some() {
            println!(
                "arc03_native_close_raw disposition=returned_error close_ns={}",
                close_observed_at.elapsed().as_nanos()
            );
        }
        let report = owner.report();
        assert_eq!(native.connection_state(), RTCPeerConnectionState::Closed);
        assert_eq!(report.active_candidates, 1);
        assert_eq!(report.failed_cleanup_candidates, 1);
        assert!(!report.accounting_poisoned);

        let (permit, _unrelated_lifetime, claim) =
            admit_single_connector_candidate(crate::runtime::runtime_for_test(), owner.clone());
        assert!(permit.reserve_connector_candidate(claim).is_some());
    }

    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    async fn v4_arc03_cancelled_delivered_result_closes_native_peer_before_release() {
        let process = ProcessResourceRoot::isolated();
        let context = process.mesh_runtime_scope().network_instance_scope();
        let mut transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(test_resource_owner(1, 4), test_webrtc_profile(4));
        let hook = ConstructionTestHook::new(ConstructionPause::AfterResultDelivery);
        transport.construction_hook = Some(Arc::clone(&hook));
        let construction_scope = context.peer_connection_scope();
        let construction = tokio::spawn(async move {
            transport
                .open_connector_peer(Role::Answerer, &[], &[], construction_scope)
                .await
        });

        let delivered = hook
            .created
            .acquire()
            .await
            .expect("result-delivery hook remains open");
        delivered.forget();
        let native = hook
            .peer_connection
            .lock()
            .take()
            .expect("delivered result still owns its native peer");

        construction.abort();
        assert!(construction.await.is_err());

        tokio::time::timeout(Duration::from_secs(10), async {
            while native.connection_state() != RTCPeerConnectionState::Closed {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled delivered result closes its native peer");
        drop(native);

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let report = context.report();
                let callbacks = report
                    .pre_authentication
                    .iter()
                    .find(|entry| entry.family == PreAuthResourceFamily::Callback)
                    .expect("callback family exists");
                let tasks = report
                    .pre_authentication
                    .iter()
                    .find(|entry| entry.family == PreAuthResourceFamily::Task)
                    .expect("task family exists");
                if callbacks.active == ResourceUse::ZERO && tasks.active == ResourceUse::ZERO {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled delivered result releases callback and task observations");
    }

    #[test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    fn v4_arc03_construction_runtime_shutdown_is_bounded_and_fail_closed() {
        let owner = test_resource_owner(1, 4);
        let mut transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(owner.clone(), test_webrtc_profile(4));
        let hook = ConstructionTestHook::new(ConstructionPause::AfterNativeAllocation);
        transport.construction_hook = Some(Arc::clone(&hook));
        let process = ProcessResourceRoot::isolated();
        let construction_scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let caller_runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("fixture caller runtime");
        let construction = caller_runtime.spawn(async move {
            transport
                .open_connector_peer(Role::Answerer, &[], &[], construction_scope)
                .await
        });
        let created = caller_runtime
            .block_on(hook.created.acquire())
            .expect("construction reaches native allocation");
        created.forget();
        let native = hook
            .peer_connection
            .lock()
            .take()
            .expect("partial native peer exists");
        construction.abort();
        let cancelled = caller_runtime.block_on(construction);
        assert!(
            cancelled.is_err_and(|error| error.is_cancelled()),
            "runtime owner cancels and joins construction before shutdown"
        );
        drop(caller_runtime);

        let verifier_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("fixture verifier runtime");
        let terminal = verifier_runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let report = owner.report();
                    let released =
                        report.active_candidates == 0 && report.failed_cleanup_candidates == 0;
                    let retained =
                        report.active_candidates == 1 && report.failed_cleanup_candidates == 1;
                    if native.connection_state() == RTCPeerConnectionState::Closed
                        && (released || retained)
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
        });
        assert!(
            terminal.is_ok(),
            "runtime shutdown did not reach a bounded cleanup outcome: state={:?}, report={:?}",
            native.connection_state(),
            owner.report()
        );
        let report = owner.report();
        assert_eq!(native.connection_state(), RTCPeerConnectionState::Closed);
        assert!(
            (report.active_candidates == 0 && report.failed_cleanup_candidates == 0)
                || (report.active_candidates == 1 && report.failed_cleanup_candidates == 1),
            "confirmed close releases the claim; an unconfirmed close retains only its exact claim: {report:?}"
        );
        assert!(!report.accounting_poisoned);
    }

    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    async fn v4_arc03_background_construction_failure_closes_partial_native_peer() {
        let owner = test_resource_owner(1, 4);
        let mut transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(owner.clone(), test_webrtc_profile(4));
        let hook = ConstructionTestHook::new(ConstructionPause::FailAfterNativeAllocation);
        transport.construction_hook = Some(Arc::clone(&hook));
        let process = ProcessResourceRoot::isolated();
        let construction_scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();

        let result = transport
            .open_connector_peer(Role::Answerer, &[], &[], construction_scope)
            .await;
        assert!(
            result.is_err(),
            "injected construction task failure reaches the caller"
        );
        let native = hook
            .peer_connection
            .lock()
            .take()
            .expect("failed construction returned a native peer to its guard");

        tokio::time::timeout(Duration::from_secs(10), async {
            while native.connection_state() != RTCPeerConnectionState::Closed
                || owner.report().active_candidates != 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("failed construction closes its native peer before releasing the claim");
        assert_eq!(native.connection_state(), RTCPeerConnectionState::Closed);
        assert_eq!(owner.report().failed_cleanup_candidates, 0);
        assert!(!owner.report().accounting_poisoned);
    }

    #[test]
    fn v4_arc03_data_channel_open_requires_live_exact_candidate() {
        let (candidate, lifetime) = crate::runtime::attempt::connector_candidate_for_test(
            crate::runtime::runtime_for_test(),
        );
        let ownership = admitted_ownership(candidate);
        let connected = match ownership.mark_data_channel_open() {
            DataChannelOpenTransition::Connected(capability) => capability,
            _ => panic!("live exact candidate must produce one connected capability"),
        };
        assert!(matches!(
            ownership.mark_data_channel_open(),
            DataChannelOpenTransition::AlreadyConnected
        ));
        ownership.retire();
        assert!(matches!(
            ownership.mark_data_channel_open(),
            DataChannelOpenTransition::Rejected
        ));
        drop(connected);
        drop(lifetime);
    }

    #[test]
    fn v4_arc03_promotion_does_not_nest_connector_and_attempt_transitions() {
        let (candidate, lifetime) = crate::runtime::attempt::connector_candidate_for_test(
            crate::runtime::runtime_for_test(),
        );
        let ownership = Arc::new(admitted_ownership(candidate));
        let (extracted_tx, extracted_rx) = std::sync::mpsc::channel();
        let (continue_tx, continue_rx) = std::sync::mpsc::channel();
        let promoting = Arc::clone(&ownership);

        let open = std::thread::spawn(move || {
            promoting.mark_data_channel_open_after_extract(|| {
                extracted_tx
                    .send(())
                    .expect("test observes the connector extraction point");
                continue_rx
                    .recv()
                    .expect("test releases candidate promotion");
            })
        });

        extracted_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("promotion releases connector authority before entering attempt transition");
        lifetime.retire();
        ownership.retire();
        continue_tx
            .send(())
            .expect("promotion thread remains available");

        assert!(matches!(
            open.join().expect("promotion thread joins"),
            DataChannelOpenTransition::Rejected
        ));
    }

    #[test]
    fn v4_arc03_admitted_worker_rejects_protocol_bytes_before_channel_capability() {
        let (candidate, _lifetime) = crate::runtime::attempt::connector_candidate_for_test(
            crate::runtime::runtime_for_test(),
        );
        let ownership = admitted_ownership(candidate);
        let before_open = stamped_event(
            &ownership,
            TransportEvent::Message(Bytes::from_static(b"not-connected")),
        );

        assert!(!ownership.accepts(&before_open));
        let _connected = match ownership.mark_data_channel_open() {
            DataChannelOpenTransition::Connected(capability) => capability,
            _ => panic!("live exact candidate must produce one connected capability"),
        };
        assert!(ownership.accepts(&before_open));
    }

    /// Connector authority refuses a real-time unit before the channel is
    /// connected, and that refusal is the connector's own to make: nothing this
    /// state holds could authorize one.
    ///
    /// What it deliberately does **not** claim is the converse. Once connected,
    /// this type answers `true`, and it should — the session's binding table is
    /// not the connector's to know about. Whether a unit belongs to a live
    /// session is asked one layer up, by
    /// `v4_arc03_realtime_unit_requires_a_live_session_binding_table`.
    #[test]
    fn v4_arc03_connector_authority_refuses_realtime_units_before_connection() {
        let (candidate, _lifetime) = crate::runtime::attempt::connector_candidate_for_test(
            crate::runtime::runtime_for_test(),
        );
        let ownership = admitted_ownership(candidate);
        let unit = stamped_event(&ownership, test_realtime_event(0, 0, b""));

        assert!(
            !ownership.accepts(&unit),
            "an unconnected connector authorizes no real-time unit"
        );
        // Non-vacuity: the refusal is about the state, not about this event
        // being unacceptable to the type in general.
        let lifecycle = stamped_event(&ownership, TransportEvent::DataChannelClosed);
        assert!(
            ownership.accepts(&lifecycle),
            "the same awaiting connector still carries its own lifecycle events"
        );
    }

    #[test]
    fn v4_arc03_rejected_open_retires_callback_admission() {
        let (candidate, lifetime) = crate::runtime::attempt::connector_candidate_for_test(
            crate::runtime::runtime_for_test(),
        );
        let ownership = admitted_ownership(candidate);
        lifetime.retire();

        assert!(matches!(
            ownership.mark_data_channel_open(),
            DataChannelOpenTransition::Rejected
        ));
        let after_rejection = stamped_event(
            &ownership,
            TransportEvent::Message(Bytes::from_static(b"retired")),
        );
        assert!(!ownership.accepts(&after_rejection));
    }

    #[test]
    fn v4_arc03_attempt_retirement_preserves_winner_and_invalidates_awaiting_loser() {
        let (first, second, lifetime) = crate::runtime::attempt::two_connector_candidates_for_test(
            crate::runtime::runtime_for_test(),
        );
        let first = admitted_ownership(first);
        let second = admitted_ownership(second);

        let connected = match first.mark_data_channel_open() {
            DataChannelOpenTransition::Connected(capability) => capability,
            _ => panic!("the first live candidate must promote"),
        };

        lifetime.retire();

        let winner_message = stamped_event(
            &first,
            TransportEvent::Message(Bytes::from_static(b"promoted-winner")),
        );
        let awaiting_control = stamped_event(&second, TransportEvent::DataChannelClosed);
        assert!(first.accepts(&winner_message));
        assert!(!second.accepts(&awaiting_control));
        assert!(matches!(
            first.mark_data_channel_open(),
            DataChannelOpenTransition::AlreadyConnected
        ));
        assert!(matches!(
            second.mark_data_channel_open(),
            DataChannelOpenTransition::Rejected
        ));
        assert!(first.incarnation.is_active());
        assert!(!second.incarnation.is_active());
        drop(connected);
    }

    #[test]
    fn v4_arc03_unsupported_candidate_measurement_is_inexact_not_a_panic() {
        assert_eq!(measured_usize(None), (0, true));
    }

    #[test]
    #[ignore = "manual candidate-observer metadata measurement"]
    fn v4_arc03_candidate_observer_metadata_measurement() {
        println!(
            "arc03_candidate_metadata_bytes local_candidate={} observation_lease={} pending_candidate={} queue={} drain={} vec_header={}",
            size_of::<LocalIceCandidate>(),
            size_of::<CandidateObservationLease>(),
            size_of::<PendingRemoteCandidate>(),
            size_of::<PendingRemoteCandidateQueue>(),
            size_of::<PendingRemoteCandidateDrain>(),
            size_of::<Vec<PendingRemoteCandidate>>()
        );
    }

    #[test]
    fn sdp_fingerprint_extracts_and_normalises() {
        let sdp = "v=0\r\n\
                   o=- 1 2 IN IP4 127.0.0.1\r\n\
                   a=group:BUNDLE 0\r\n\
                   a=fingerprint:sha-256 AA:BB:CC:DD\r\n\
                   m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";
        assert_eq!(
            sdp_fingerprint(sdp).as_deref(),
            Some("sha-256 aa:bb:cc:dd"),
            "the fingerprint is extracted and lowercased for stable comparison"
        );

        // A rebuild carries a different fingerprint; a restart keeps it.
        let restart = sdp.replace("a=ice-ufrag:x", "a=ice-ufrag:y");
        assert_eq!(
            sdp_fingerprint(&restart),
            sdp_fingerprint(sdp),
            "same PC (restart) → same fingerprint"
        );
        let rebuilt = sdp.replace("AA:BB:CC:DD", "11:22:33:44");
        assert_ne!(
            sdp_fingerprint(&rebuilt),
            sdp_fingerprint(sdp),
            "fresh PC (rebuild) → different fingerprint"
        );

        // No fingerprint line → None (glare / not-yet-applied).
        assert_eq!(sdp_fingerprint("v=0\r\nm=application 9\r\n"), None);
    }

    #[test]
    fn v4_arc03j_sdp_ice_credentials_apply_session_inheritance_and_media_overrides() {
        let sdp = "v=0\r\n\
                   a=ice-ufrag:session-u\r\n\
                   a=ice-pwd:session-p\r\n\
                   m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
                   a=mid:data\r\n\
                   m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
                   a=mid:audio\r\n\
                   a=ice-ufrag:audio-u\r\n\
                   a=ice-pwd:audio-p\r\n";
        let credentials = sdp_ice_credentials(sdp).expect("every section has exact credentials");
        assert_eq!(credentials.bindings.len(), 2);
        assert_eq!(credentials.bindings[0].mid.as_deref(), Some("data"));
        assert_eq!(credentials.bindings[0].username_fragment, "session-u");
        assert_eq!(credentials.bindings[0].password, "session-p");
        assert_eq!(credentials.bindings[1].mid.as_deref(), Some("audio"));
        assert_eq!(credentials.bindings[1].username_fragment, "audio-u");
        assert_eq!(credentials.bindings[1].password, "audio-p");

        let reordered = sdp_ice_credentials(
            "v=0\r\n\
             a=ice-ufrag:session-u\r\n\
             a=ice-pwd:session-p\r\n\
             m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
             a=mid:audio\r\n\
             a=ice-ufrag:audio-u\r\n\
             a=ice-pwd:audio-p\r\n\
             m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
             a=mid:data\r\n",
        )
        .expect("reordered media sections keep exact credentials");
        assert!(
            !credentials.proves_restart_to(&reordered),
            "media reordering cannot manufacture an ICE restart"
        );

        let data_restart = sdp_ice_credentials(
            "v=0\r\n\
             a=ice-ufrag:replacement-u\r\n\
             a=ice-pwd:replacement-p\r\n\
             m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
             a=mid:data\r\n\
             m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
             a=mid:audio\r\n\
             a=ice-ufrag:audio-u\r\n\
             a=ice-pwd:audio-p\r\n",
        )
        .expect("replacement data credentials are exact");
        assert!(
            credentials.proves_restart_to(&data_restart),
            "changed credentials on one stable MID prove a restart"
        );

        let incomplete =
            "v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=ice-ufrag:u\r\n";
        assert!(
            sdp_ice_credentials(incomplete).is_err(),
            "a partial credential pair is not exact restart evidence"
        );

        for ambiguous in [
            "v=0\r\n\
             a=ice-ufrag:first\r\n\
             a=ice-ufrag:second\r\n\
             a=ice-pwd:password\r\n\
             m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
             a=mid:data\r\n",
            "v=0\r\n\
             a=ice-ufrag:u\r\n\
             a=ice-pwd:p\r\n\
             m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
             a=mid:data\r\n\
             a=mid:other\r\n",
            "v=0\r\n\
             a=ice-ufrag:u\r\n\
             a=ice-pwd:p\r\n\
             m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
             a=mid:duplicate\r\n\
             m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
             a=mid:duplicate\r\n",
        ] {
            assert!(
                sdp_ice_credentials(ambiguous).is_err(),
                "duplicate credential or MID input cannot choose a parser interpretation"
            );
        }

        let rejected_without_credentials = "v=0\r\n\
                                            a=ice-ufrag:session-u\r\n\
                                            a=ice-pwd:session-p\r\n\
                                            m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
                                            a=mid:data\r\n\
                                            m=audio 0 UDP/TLS/RTP/SAVPF 111\r\n\
                                            a=mid:rejected-audio\r\n";
        let active = sdp_ice_credentials(rejected_without_credentials)
            .expect("a rejected media section needs no effective ICE credential pair");
        assert_eq!(active.bindings.len(), 1);

        let rejected_port_range = rejected_without_credentials.replace(
            "m=audio 0 UDP/TLS/RTP/SAVPF 111",
            "m=audio 0/2 UDP/TLS/RTP/SAVPF 111",
        );
        assert_eq!(
            sdp_ice_credentials(&rejected_port_range)
                .expect("a zero-based rejected port range needs no credentials")
                .bindings
                .len(),
            1
        );

        let mut candidate = observed_candidate();
        candidate.username_fragment = None;
        assert!(
            candidate_matches_remote_credentials(&candidate, &active),
            "a candidate without a declared ufrag is bound by its exact active MID"
        );
        candidate.candidate.push_str(" ufrag session-u");
        assert!(candidate_matches_remote_credentials(&candidate, &active));
        candidate.candidate = candidate.candidate.replace("session-u", "other-u");
        assert!(!candidate_matches_remote_credentials(&candidate, &active));

        let mut native_candidate = observed_candidate();
        native_candidate.sdp_mid = Some(String::new());
        native_candidate.sdp_mline_index = Some(0);
        native_candidate.username_fragment = Some("session-u".to_string());
        assert!(
            candidate_matches_remote_credentials(&native_candidate, &active),
            "webrtc-rs empty-MID candidates bind through their exact media-line index"
        );
        native_candidate.sdp_mline_index = Some(1);
        assert!(
            !candidate_matches_remote_credentials(&native_candidate, &active),
            "an empty native MID cannot excuse an invalid media-line index"
        );

        let mut audio_candidate = observed_candidate();
        audio_candidate.sdp_mid = Some("audio".to_string());
        audio_candidate.sdp_mline_index = Some(1);
        audio_candidate.username_fragment = Some("audio-u".to_string());
        assert!(candidate_matches_remote_credentials(
            &audio_candidate,
            &credentials
        ));
        audio_candidate.sdp_mline_index = Some(0);
        assert!(
            !candidate_matches_remote_credentials(&audio_candidate, &credentials),
            "a username fragment from another media section cannot satisfy the declared index"
        );
        audio_candidate.sdp_mline_index = Some(1);
        audio_candidate.sdp_mid = Some("data".to_string());
        assert!(
            !candidate_matches_remote_credentials(&audio_candidate, &credentials),
            "MID and media-line index must identify the same exact credential binding"
        );
        audio_candidate.username_fragment = None;
        audio_candidate.sdp_mline_index = None;
        audio_candidate.sdp_mid = Some("unknown".to_string());
        assert!(
            !candidate_matches_remote_credentials(&audio_candidate, &credentials),
            "process-local attempt ownership cannot excuse an invalid declared media location"
        );
    }

    #[test]
    fn v4_arc03j_remote_candidates_require_an_exact_or_unambiguous_binding() {
        let credentials = sdp_ice_credentials(
            "v=0\r\n\
             m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
             a=mid:data\r\n\
             a=ice-ufrag:shared-u\r\n\
             a=ice-pwd:data-p\r\n\
             m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
             a=mid:audio\r\n\
             a=ice-ufrag:shared-u\r\n\
             a=ice-pwd:audio-p\r\n",
        )
        .expect("fixture has two exact active credential pairs");

        let mut unbound = observed_candidate();
        unbound.sdp_mid = None;
        unbound.sdp_mline_index = None;
        unbound.username_fragment = None;
        assert!(
            !candidate_matches_remote_credentials(&unbound, &credentials),
            "a wholly unbound candidate cannot enter an active or replacement attempt"
        );

        let mut mismatched_location = observed_candidate();
        mismatched_location.sdp_mid = Some("data".to_string());
        mismatched_location.sdp_mline_index = Some(1);
        mismatched_location.username_fragment = Some("shared-u".to_string());
        assert!(
            !candidate_matches_remote_credentials(&mismatched_location, &credentials),
            "MID and media-line index must select the same active SDP binding"
        );

        let mut ambiguous_username = observed_candidate();
        ambiguous_username.sdp_mid = None;
        ambiguous_username.sdp_mline_index = None;
        ambiguous_username.username_fragment = Some("shared-u".to_string());
        assert!(
            !candidate_matches_remote_credentials(&ambiguous_username, &credentials),
            "a username fragment reused by distinct credential pairs is ambiguous"
        );

        let unique_credentials =
            sdp_ice_credentials(&exact_ice_sdp("unique-u", "unique-p", "AA:BB:CC:DD"))
                .expect("one exact active credential pair");
        ambiguous_username.username_fragment = Some("unique-u".to_string());
        assert!(
            candidate_matches_remote_credentials(&ambiguous_username, &unique_credentials),
            "a username-fragment-only candidate may select one unambiguous credential pair"
        );
    }

    #[test]
    fn v4_arc03j_candidate_username_fragment_declarations_must_agree() {
        let credentials =
            sdp_ice_credentials(&exact_ice_sdp("session-u", "session-p", "AA:BB:CC:DD"))
                .expect("one exact active credential pair");

        let mut matching = observed_candidate();
        matching.username_fragment = Some("session-u".to_string());
        matching.candidate.push_str(" ufrag session-u");
        assert_eq!(
            candidate_username_fragment(&matching),
            Ok(Some("session-u"))
        );
        assert!(candidate_matches_remote_credentials(
            &matching,
            &credentials
        ));

        let mut conflicting = matching.clone();
        conflicting.username_fragment = Some("other-u".to_string());
        assert_eq!(
            candidate_username_fragment(&conflicting),
            Err(CandidateUsernameFragmentError::ConflictingDeclarations)
        );
        assert!(!candidate_matches_remote_credentials(
            &conflicting,
            &credentials
        ));

        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let mut state =
            RemoteCandidateState::new(test_pending_candidate_policy_for(&[conflicting.clone()]));
        assert_eq!(
            state.admit(conflicting, &scope),
            PendingRemoteCandidateQueuePush::InvalidBinding(
                CandidateUsernameFragmentError::ConflictingDeclarations
            ),
            "conflicting declarations are rejected before hashing or retention"
        );
        assert!(state.current.pending.entries.is_empty());
        assert!(!state.current.attempt.is_active());

        let mut empty_structured = matching.clone();
        empty_structured.username_fragment = Some(String::new());
        assert_eq!(
            candidate_username_fragment(&empty_structured),
            Ok(Some("session-u")),
            "an empty structured value is absent and cannot hide the candidate-line declaration"
        );
        assert!(candidate_matches_remote_credentials(
            &empty_structured,
            &credentials
        ));

        let mut duplicate_line = matching;
        duplicate_line.candidate.push_str(" ufrag session-u");
        assert_eq!(
            candidate_username_fragment(&duplicate_line),
            Err(CandidateUsernameFragmentError::DuplicateCandidateLineDeclaration),
            "duplicate line declarations are rejected even when their text agrees"
        );
        assert!(!candidate_matches_remote_credentials(
            &duplicate_line,
            &credentials
        ));
    }

    #[test]
    fn v4_arc03_remote_sdp_credentials_share_one_exact_retention_lease() {
        let sdp = exact_ice_sdp("shared-u", "shared-p", "AA:BB:CC:DD");
        let bindings = parse_sdp_ice_credential_bindings(&sdp)
            .expect("fixture SDP has one exact credential binding");
        let initial_claim = remote_description_operation_claim(sdp.capacity())
            .expect("fixture operation claim is representable");
        let plan = plan_sdp_ice_credential_allocations(&sdp)
            .expect("fixture allocation plan is representable");
        let planned_claim = planned_remote_description_claim(plan, sdp.capacity())
            .expect("fixture planned claim is representable");
        let retained_claim =
            retained_remote_description_claim(&bindings, bindings.capacity(), sdp.capacity(), true)
                .expect("fixture retained claim is representable");
        let post_native_claim = retained_remote_description_claim(
            &bindings,
            bindings.capacity(),
            sdp.capacity(),
            false,
        )
        .expect("fixture post-native claim is representable");
        let additional = FiniteResourceProvider::reservation_charge_for_test(initial_claim)
            .expect("fixture operation reservation is representable")
            .checked_add(
                FiniteResourceProvider::reservation_charge_for_test(planned_claim)
                    .expect("fixture planned reservation is representable"),
            )
            .and_then(|claim| {
                claim.checked_add(
                    FiniteResourceProvider::reservation_charge_for_test(retained_claim)
                        .expect("fixture retained reservation is representable"),
                )
            })
            .expect("fixture description grant is representable");
        let policy = test_pending_candidate_policy_for(&[observed_candidate()]);
        let (provider, _owner, _candidate, _lifetime, work_scope) =
            elastic_remote_candidate_test_resources_with_additional(policy, additional);
        let baseline = provider.in_use();

        let credentials = sdp_ice_credentials_owned(&sdp, sdp.capacity(), &work_scope)
            .expect("the exact remote-description claim is admitted");
        assert_eq!(
            provider
                .in_use()
                .checked_sub(baseline)
                .expect("the live description charge includes the baseline"),
            FiniteResourceProvider::reservation_charge_for_test(retained_claim)
                .expect("fixture retained reservation is representable")
        );

        let shared_charge = provider.in_use();
        let clone = credentials.clone();
        assert_eq!(
            provider.in_use(),
            shared_charge,
            "a process-local credential clone shares the original lease"
        );

        credentials
            .finish_native_commit()
            .expect("native commit releases only the scheduled-work claim");
        let post_native_charge = provider.in_use();
        assert_eq!(
            post_native_charge
                .checked_sub(baseline)
                .expect("the post-native charge includes the baseline"),
            FiniteResourceProvider::reservation_charge_for_test(post_native_claim)
                .expect("fixture post-native reservation is representable")
        );
        drop(credentials);
        assert_eq!(
            provider.in_use(),
            post_native_charge,
            "dropping one shared owner cannot release the credential lease"
        );
        drop(clone);
        assert_eq!(provider.in_use(), baseline);
    }

    #[tokio::test]
    async fn v4_arc03_remote_sdp_residual_survives_failed_native_close() {
        let sdp = exact_ice_sdp("failure-u", "failure-p", "AA:BB:CC:DD");
        let bindings = parse_sdp_ice_credential_bindings(&sdp)
            .expect("fixture SDP has one exact credential binding");
        let plan = plan_sdp_ice_credential_allocations(&sdp)
            .expect("fixture allocation plan is representable");
        let initial_claim = remote_description_operation_claim(sdp.capacity())
            .expect("fixture operation claim is representable");
        let planned_claim = planned_remote_description_claim(plan, sdp.capacity())
            .expect("fixture planned claim is representable");
        let retained_claim =
            retained_remote_description_claim(&bindings, bindings.capacity(), sdp.capacity(), true)
                .expect("fixture retained claim is representable");
        let post_native_claim = retained_remote_description_claim(
            &bindings,
            bindings.capacity(),
            sdp.capacity(),
            false,
        )
        .expect("fixture post-native claim is representable");
        let additional = [initial_claim, planned_claim, retained_claim]
            .into_iter()
            .map(|claim| {
                FiniteResourceProvider::reservation_charge_for_test(claim)
                    .expect("fixture description reservation is representable")
            })
            .try_fold(crate::resource::ResourceClaim::ZERO, |total, claim| {
                total.checked_add(claim)
            })
            .expect("fixture description grant is representable");
        let grant = crate::runtime::attempt::explicit_test_grant(1, 1)
            .checked_add(additional)
            .expect("fixture process grant is representable");
        let provider = FiniteResourceProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone())
            .expect("fixture provider admits its process scope");
        let process_owner = ConnectorResourceOwnerPort::new(port);
        let mesh = process_owner
            .issue_mesh_scope()
            .expect("fixture process owner issues one Mesh scope");
        let (close_owner, _lifetime) = close_owner_fixture(&mesh);
        let credentials = sdp_ice_credentials_owned(
            &sdp,
            sdp.capacity(),
            &close_owner.ownership.work_resource_scope,
        )
        .expect("the exact remote-description claim is admitted");
        close_owner.retain_remote_description_resources(
            credentials
                .resource_owner()
                .expect("owned credentials expose one residual owner"),
        );
        credentials
            .finish_native_commit()
            .expect("native commit releases only the scheduled-work claim");
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Error,
                calls: Arc::new(AtomicUsize::new(0)),
            }))
        );

        let error = close_owner
            .wait()
            .await
            .expect_err("injected native close failure remains terminal");
        assert!(error.to_string().contains("retained its exact claim"));
        let expected = crate::runtime::attempt::connector_resource_structural_claims()
            .connector_opening()
            .checked_add(post_native_claim)
            .expect("fixture retained claims are representable");
        assert_eq!(provider.retained_after_failed_cleanup(), expected);

        drop(credentials);
        drop(close_owner);
        assert_eq!(
            provider.retained_after_failed_cleanup(),
            expected,
            "no external owner drop can make failed native state reusable"
        );
    }

    #[test]
    fn v4_arc03j_invalid_candidate_bindings_terminally_retire_the_attempt() {
        let mut conflicting = observed_candidate();
        conflicting.username_fragment = Some("structured-u".to_string());
        conflicting.candidate.push_str(" ufrag line-u");

        let mut duplicate = observed_candidate();
        duplicate
            .candidate
            .push_str(" ufrag remote-fragment ufrag remote-fragment");

        let mut missing_value = observed_candidate();
        missing_value.candidate.push_str(" ufrag");

        let cases = [
            (
                conflicting,
                CandidateUsernameFragmentError::ConflictingDeclarations,
            ),
            (
                duplicate,
                CandidateUsernameFragmentError::DuplicateCandidateLineDeclaration,
            ),
            (
                missing_value,
                CandidateUsernameFragmentError::MissingCandidateLineValue,
            ),
        ];

        for (invalid, expected_error) in cases {
            let process = ProcessResourceRoot::isolated();
            let scope = process
                .mesh_runtime_scope()
                .network_instance_scope()
                .peer_connection_scope();
            let mut state =
                RemoteCandidateState::new(test_pending_candidate_policy_for(&[invalid.clone()]));
            assert_eq!(
                state.admit(observed_candidate(), &scope),
                PendingRemoteCandidateQueuePush::Queued,
                "the terminal snapshot includes one already retained candidate"
            );
            let (first, first_kind) = state.admit_observed(invalid.clone(), &scope);
            assert_eq!(
                first,
                PendingRemoteCandidateQueuePush::InvalidBinding(expected_error)
            );
            assert!(
                first_kind.is_some(),
                "the one terminal result is classified"
            );
            assert!(!state.current.attempt.is_active());

            let terminal_queue_len = state.current.pending.entries.len();
            let terminal_digest_len = state.current.seen.len();
            let terminal_budget = state.current.pending.budget.report();
            let terminal_resources = candidate_report(&process.report().pre_authentication);
            let terminal_resource_counters = (
                terminal_resources.active,
                terminal_resources.peak_active,
                terminal_resources.active_lease_count,
                terminal_resources.peak_active_lease_count,
                terminal_resources.completed_lease_count,
                terminal_resources.completed_total_use,
                terminal_resources.completed_total_lifetime,
                terminal_resources.measurement_inexact,
            );
            let mut classified_results = usize::from(first_kind.is_some());

            for index in 0..1024 {
                let mut later = invalid.clone();
                later.candidate.push_str(&format!(" later-{index}"));
                let (disposition, kind) = state.admit_observed(later, &scope);
                assert_eq!(disposition, PendingRemoteCandidateQueuePush::Retired);
                assert!(
                    kind.is_none(),
                    "a retired attempt performs no later diagnostic classification"
                );
                classified_results += usize::from(kind.is_some());
            }

            assert_eq!(classified_results, 1);
            assert_eq!(state.current.pending.entries.len(), terminal_queue_len);
            assert_eq!(state.current.seen.len(), terminal_digest_len);
            assert_eq!(state.current.pending.budget.report(), terminal_budget);
            let later_resources = candidate_report(&process.report().pre_authentication);
            assert_eq!(
                (
                    later_resources.active,
                    later_resources.peak_active,
                    later_resources.active_lease_count,
                    later_resources.peak_active_lease_count,
                    later_resources.completed_lease_count,
                    later_resources.completed_total_use,
                    later_resources.completed_total_lifetime,
                    later_resources.measurement_inexact,
                ),
                terminal_resource_counters
            );
        }
    }

    #[test]
    fn v4_arc03j_restart_transactions_reject_ambiguous_interleavings() {
        let mut state = RemoteCandidateState::new(test_pending_candidate_policy());
        let credentials = sdp_ice_credentials(&exact_ice_sdp(
            "remote-fragment",
            "remote-password",
            "AA:BB:CC:DD",
        ))
        .expect("fixture credentials are exact");
        let initial = state
            .prepare_remote_description(credentials.clone())
            .expect("initial remote description starts");
        assert!(state.begin_local_ice_restart().is_err());
        assert!(state
            .prepare_remote_description(credentials.clone())
            .is_err());
        state.fail_remote_description(&initial);

        let (_retiring, local_replacement) = state
            .begin_local_ice_restart()
            .expect("local restart begins after the remote transaction ends");
        assert!(state.prepare_remote_description(credentials).is_err());
        state.fail_provisional(&local_replacement);
    }

    #[test]
    fn v4_arc03j_corrupt_restart_migration_leaves_no_viable_attempt() {
        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let corrupt_candidates = ["one", "two"].map(|suffix| {
            let mut candidate = observed_candidate();
            candidate.username_fragment = Some("replacement-fragment".to_string());
            candidate.candidate.push_str(suffix);
            candidate
        });
        let candidate_bytes = corrupt_candidates
            .iter()
            .filter_map(candidate_content_bytes)
            .max()
            .and_then(NonZeroUsize::new)
            .expect("corrupt fixture candidates have finite nonzero content");
        let one = NonZeroUsize::new(1).expect("one is nonzero");
        let mut state = RemoteCandidateState::new_with_restart_overlap(
            PendingRemoteCandidatePolicy::new(one, candidate_bytes, one, one),
        );
        let initial_credentials = sdp_ice_credentials(&exact_ice_sdp(
            "initial-fragment",
            "initial-password",
            "AA:BB:CC:DD",
        ))
        .expect("initial credentials are exact");
        let initial = state
            .prepare_remote_description(initial_credentials)
            .expect("initial remote description starts");
        drop(
            state
                .commit_remote_description(&initial)
                .expect("initial remote description commits"),
        );

        for candidate in corrupt_candidates {
            state
                .current
                .pending
                .entries
                .push_back(PendingRemoteCandidate::observe(
                    candidate,
                    Arc::clone(&state.current.attempt),
                    &scope,
                ));
        }
        let replacement_credentials = sdp_ice_credentials(&exact_ice_sdp(
            "replacement-fragment",
            "replacement-password",
            "AA:BB:CC:DD",
        ))
        .expect("replacement credentials are exact");
        assert!(state
            .prepare_remote_description(replacement_credentials)
            .is_err());
        assert!(
            state.has_no_viable_attempt(),
            "a corrupt over-limit migration must fence both attempts so the caller retires the connector"
        );
    }

    // ---- ICE interface filter -----------------------------------------

    #[test]
    fn virtual_interfaces_are_excluded_real_ones_kept() {
        // Docker / container / overlay interfaces — the dead-candidate
        // sources we trim. `br-…` and `veth…` carry hashed suffixes.
        for name in [
            "docker0",
            "br-1a2b3c4d5e6f",
            "veth9f2a1b",
            "virbr0",
            "vmnet8",
            "cni0",
            "flannel.1",
            "cali1234abcd",
            "kube-bridge",
        ] {
            assert!(
                is_virtual_interface(name),
                "{name} should be excluded from ICE gathering"
            );
        }

        // Real interfaces — physical NICs, Wi-Fi, and the Tailscale tunnel
        // (a legitimate peer path the user asked us to keep).
        for name in [
            "eth0",
            "enp3s0",
            "eno1",
            "wlan0",
            "wlp2s0",
            "en0",
            "tailscale0",
            "utun3",
            "wg0",
            "lo",
        ] {
            assert!(
                !is_virtual_interface(name),
                "{name} should keep gathering ICE candidates"
            );
        }
    }

    #[test]
    fn link_local_ips_are_filtered_routable_ones_kept() {
        use std::net::IpAddr;
        // Link-local — the unbindable addresses we drop from gathering.
        for s in ["fe80::1", "fe80::ce81:b1c:bd2c:69e", "169.254.10.20"] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(is_link_local_ip(&ip), "{s} should be filtered");
        }
        // Kept: RFC-1918, CGNAT, ULA, and globals all make usable host
        // candidates. ULA (`fdb8::`/`fd…`) in particular must survive —
        // it's bindable and routes on the local network.
        for s in [
            "192.168.88.15",
            "10.0.0.5",
            "172.20.10.2",
            "100.64.0.7",
            "fdb8:7b28:9cfa:0:1c5f:1ecb:63c0:1a03",
            "2600:382:2187:2bf1::1",
            "127.0.0.1",
            "::1",
        ] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(!is_link_local_ip(&ip), "{s} should be kept");
        }
    }

    // ---- the H.264 access-unit assembler ------------------------------

    fn rtp_pkt(seq: u16, ts: u32, marker: bool, payload: &[u8]) -> webrtc::rtp::packet::Packet {
        webrtc::rtp::packet::Packet {
            header: webrtc::rtp::header::Header {
                sequence_number: seq,
                timestamp: ts,
                marker,
                ..Default::default()
            },
            payload: Bytes::copy_from_slice(payload),
        }
    }

    /// The framing every assembler control below drives.
    ///
    /// The assembly machinery is codec-neutral and the fragmentation rules are
    /// not, so a control that exercises reordering, loss or the fragment stop
    /// has to name one framing. H.264 is the one with real fragment shapes to
    /// build a chain out of.
    fn h264_framing() -> Arc<dyn RealtimeUnitFraming> {
        Arc::new(H264Framing)
    }

    /// A single-NAL IDR payload (type 5) — emits as one whole unit.
    const IDR_NAL: &[u8] = &[0x65, 0xAA, 0xBB];
    /// The same IDR as three FU-A fragments (start / middle / end).
    const FU_S: &[u8] = &[0x7C, 0x85, 0x11];
    const FU_M: &[u8] = &[0x7C, 0x05, 0x22];
    const FU_E: &[u8] = &[0x7C, 0x45, 0x33];

    #[test]
    fn v4_arc03_guarded_video_refuses_fragment_before_retention() {
        let registry = test_realtime_registry(explicit_realtime_callback_policy(8, 1, 1, 2, 1, 16));
        let flow = registry.open_inbound_flow().expect("flow is admitted");
        let mut assembler =
            RealtimeUnitAssembler::guarded(h264_framing(), RealtimeFlowPortHandle::of(&flow));
        assert!(assembler.push(&rtp_pkt(1, 100, true, IDR_NAL)).is_err());
        assert_eq!(assembler.fragments_held(), 0);
        let state = registry.state.lock();
        assert_eq!(retained_realtime_bytes(&state), 0);
        assert_eq!(RealtimeFlowRegistry::in_progress_units(&state), 0);
        assert!(realtime_accounting_is_clean(&state));
    }

    #[test]
    fn v4_arc03f_silent_partial_unit_retains_only_its_finite_claim_until_owner_drop() {
        let registry = test_realtime_registry(explicit_realtime_callback_policy(8, 1, 1, 8, 1, 16));
        let flow = registry.open_inbound_flow().expect("flow is admitted");
        let mut assembler =
            RealtimeUnitAssembler::guarded(h264_framing(), RealtimeFlowPortHandle::of(&flow));
        assert!(assembler
            .push(&rtp_pkt(1, 100, false, FU_S))
            .expect("the bounded fragment is valid")
            .is_none());
        {
            let state = registry.state.lock();
            assert_eq!(retained_realtime_bytes(&state), FU_S.len());
            assert_eq!(RealtimeFlowRegistry::in_progress_units(&state), 1);
        }

        drop(assembler);
        let state = registry.state.lock();
        assert_eq!(retained_realtime_bytes(&state), 0);
        assert_eq!(RealtimeFlowRegistry::in_progress_units(&state), 0);
        assert!(realtime_accounting_is_clean(&state));
    }

    /// Replacing a session frees its labels and its resources, and the
    /// replaced session's label stops working.
    ///
    /// The single control for the bundle-drop invariant. One name throughout on
    /// purpose: it is the name an application is most likely to ask for again
    /// the instant it reconnects, so a retired session's hold on it outliving
    /// the session would show here first.
    ///
    /// The fixture admits exactly one active flow per domain and exactly one
    /// queued unit. That is what makes the last assertion a proof rather than
    /// a formality — the fresh session can only open at all if the replaced
    /// session's flow was genuinely released, not merely forgotten.
    #[test]
    fn v4_macro1_a_replacing_a_session_frees_label_zero_and_its_resources() {
        struct FixtureSession {
            incarnation: Arc<crate::connector::ConnectorIncarnation>,
        }

        impl session_flow::RealtimeSessionBinding for FixtureSession {
            fn is_current_on(
                &self,
                incarnation: &Arc<crate::connector::ConnectorIncarnation>,
            ) -> bool {
                Arc::ptr_eq(&self.incarnation, incarnation)
            }
        }

        fn fixture_unit() -> RealtimeSendUnit {
            RealtimeSendUnit {
                pace: Duration::from_millis(20),
                data: Bytes::from_static(b"unit"),
            }
        }

        let registry =
            test_realtime_registry(explicit_realtime_callback_policy(16, 1, 1, 16, 1, 128));
        let name = fixture_flow_name();
        let encoding = RealtimeEncoding::new(WebRtcRtpKind::Video, "video/H264", 90_000, 0)
            .expect("the fixture encoding names a shape a flow can carry");

        let incarnation = crate::connector::ConnectorIncarnation::new();
        let session = FixtureSession {
            incarnation: Arc::clone(&incarnation),
        };
        let mut flows = SessionRealtimeFlows::new(
            Arc::clone(&registry),
            Some(session_flow::leased_control_profile(&registry)),
        );

        assert_eq!(
            flows.open(
                &session,
                Some(&incarnation),
                RealtimeFlowSpec {
                    direction: RealtimeDirection::Outbound,
                    encoding: encoding.clone(),
                    name: name.clone(),
                },
            ),
            Ok(name.clone()),
            "the application names its own flow and this side claims it exactly"
        );
        flows
            .send(&session, Some(&incarnation), &name, fixture_unit())
            .expect("a live flow of a current session takes a unit");

        let queued = {
            let state = registry.state.lock();
            retained_realtime_bytes(&state)
        };
        assert!(
            queued > 0,
            "a queued unit holds its payload lease while it is queued — without \
             this the release assertion below would pass vacuously"
        );

        // Retirement: the worker no longer has a live incarnation to offer.
        assert_eq!(
            flows.send(&session, None, &name, fixture_unit()),
            Err(RealtimeFlowError::SessionNotCurrent),
            "a retired connector cannot keep feeding a torn-down peer"
        );

        // Replacement: a different incarnation is a different connector, and
        // the session's own belief that it is current is not enough.
        let replacement = crate::connector::ConnectorIncarnation::new();
        assert_eq!(
            flows.send(&session, Some(&replacement), &name, fixture_unit()),
            Err(RealtimeFlowError::SessionNotCurrent),
            "the replaced session's label is unusable against the connector \
             that replaced it"
        );

        // The drop of the bundle is the release. Nothing announces it.
        drop(flows);
        {
            let state = registry.state.lock();
            assert_eq!(
                retained_realtime_bytes(&state),
                0,
                "the queued unit's bytes went with the session that owned it"
            );
            assert!(
                realtime_accounting_is_clean(&state),
                "and they were released rather than lost, which would poison \
                 the domain instead"
            );
        }

        // A freshly promoted session claims exactly the label the replaced one
        // held. Under a one-flow-per-domain ceiling this is only possible if
        // the flow itself was released, not just its name.
        let next_session = FixtureSession {
            incarnation: Arc::clone(&replacement),
        };
        let mut next = SessionRealtimeFlows::new(
            Arc::clone(&registry),
            Some(session_flow::leased_control_profile(&registry)),
        );
        assert_eq!(
            next.open(
                &next_session,
                Some(&replacement),
                RealtimeFlowSpec {
                    direction: RealtimeDirection::Outbound,
                    encoding,
                    name: name.clone(),
                },
            ),
            Ok(name),
            "the name an application is most likely to reuse is available again"
        );
    }

    /// A fixture session bound to one connector incarnation.
    ///
    /// Hoisted out of the controls that declare their own copy, because three
    /// of the flow-lifecycle controls below need one and a fourth definition
    /// would be the point at which they start disagreeing.
    struct FlowFixtureSession {
        incarnation: Arc<crate::connector::ConnectorIncarnation>,
    }

    impl session_flow::RealtimeSessionBinding for FlowFixtureSession {
        fn is_current_on(&self, incarnation: &Arc<crate::connector::ConnectorIncarnation>) -> bool {
            Arc::ptr_eq(&self.incarnation, incarnation)
        }
    }

    /// One inbound application flow consumes exactly one active-flow slot, and
    /// the admitted track's handle on it is not a second owner.
    ///
    /// **The discriminating case is a one-flow ceiling.** Under it, the two
    /// defects this control exists for are each a hard failure rather than a
    /// degradation:
    ///
    /// - The connector used to open a *second* registry flow when the negotiated
    ///   track arrived, for a flow the application had already opened. At
    ///   capacity one that second acquisition refuses, so a flow whose open had
    ///   succeeded would silently carry no media; at capacity *n* it would
    ///   simply halve the configured capacity, which is the same defect wearing
    ///   a number that looks deliberate.
    /// - A strong port on the pump would keep the flow's lease alive past its
    ///   close, so the replacement open below would refuse.
    ///
    /// The positive half is not decoration: an attachment that resolved to
    /// nothing would satisfy the capacity assertion vacuously, so the control
    /// proves the admitted handle really does reach *this* flow's accounting
    /// while it is open, and really does stop after the close.
    #[test]
    fn v4_macro1_one_inbound_flow_holds_exactly_one_active_flow_slot() {
        let registry =
            test_realtime_registry(explicit_realtime_callback_policy(16, 1, 1, 16, 1, 128));
        let name = fixture_flow_name();
        let encoding = RealtimeEncoding::new(WebRtcRtpKind::Video, "video/H264", 90_000, 0)
            .expect("the fixture encoding names a shape a flow can carry");
        let incarnation = crate::connector::ConnectorIncarnation::new();
        let session = FlowFixtureSession {
            incarnation: Arc::clone(&incarnation),
        };
        let mut flows = SessionRealtimeFlows::new(
            Arc::clone(&registry),
            Some(session_flow::leased_control_profile(&registry)),
        );

        assert_eq!(
            flows.open(
                &session,
                Some(&incarnation),
                RealtimeFlowSpec {
                    direction: RealtimeDirection::Inbound,
                    encoding: encoding.clone(),
                    name: name.clone(),
                },
            ),
            Ok(name.clone()),
            "the one inbound slot this fixture has is taken by the application's \
             own open"
        );

        // Exactly what the fence does: mint, then bind, then negotiate.
        let identity = RealtimeTrackIdentity::new();
        flows
            .bind_inbound(&session, Some(&incarnation), &name, Arc::clone(&identity))
            .expect("an open inbound flow of a current session takes a binding");

        // Exactly what `on_track` does. No second open anywhere on this path.
        let bindings = flows
            .inbound_bindings()
            .upgrade()
            .expect("the set that just bound is still alive");
        let attachment = bindings
            .admit(&identity, WebRtcRtpKind::Video, "video/h264", 90_000, 0)
            .expect("the track this side negotiated is admitted to its own flow");
        assert_eq!(attachment.label.name(), &name);

        // Positive: the handle reaches this flow's accounting while it is open.
        // Without this the capacity assertion below could pass because the
        // attachment pointed at nothing at all.
        assert!(
            attachment.port.port().is_some(),
            "an admitted track's handle resolves to the flow it was admitted to"
        );

        // The attachment stays alive across the close, exactly as a running pump
        // would be. If it owned a lease, this is where the leak would start.
        let remains = flows
            .close(&session, Some(&incarnation), &name)
            .expect("the session that opened this flow may close it");
        assert!(
            matches!(remains, RealtimeFlowRemains::Inbound(ref token) if Arc::ptr_eq(token, &identity)),
            "closing a bound inbound flow hands back the exact token whose \
             transceiver is still to be stopped"
        );
        assert!(
            attachment.port.port().is_none(),
            "and the pump's handle stops resolving, which is the whole of how it \
             learns the flow is gone"
        );

        assert_eq!(
            flows.open(
                &session,
                Some(&incarnation),
                RealtimeFlowSpec {
                    direction: RealtimeDirection::Inbound,
                    encoding,
                    name: name.clone(),
                },
            ),
            Ok(name),
            "the one slot is free again while the closed flow's attachment is \
             still held — so the attachment never owned one"
        );
    }

    /// An outbound open for a family the application never registered is
    /// refused as such, and costs nothing.
    ///
    /// The defect this replaces was silent in the way that matters: the open
    /// succeeded, took a label and a flow slot, and the refusal surfaced later
    /// from native negotiation as `FlowRefused` — which tells a caller to back
    /// off and retry something that can never succeed. Inbound already answered
    /// at bind time; outbound had no such point.
    ///
    /// Proved by consequence rather than by the error alone: under a one-flow
    /// ceiling and on the same label, a registered open immediately afterwards
    /// can only succeed if the refusal consumed neither.
    #[test]
    fn v4_macro1_an_unregistered_outbound_open_costs_no_label_and_no_capacity() {
        let registry =
            test_realtime_registry(explicit_realtime_callback_policy(16, 1, 1, 16, 1, 128));
        let name = fixture_flow_name();
        let incarnation = crate::connector::ConnectorIncarnation::new();
        let session = FlowFixtureSession {
            incarnation: Arc::clone(&incarnation),
        };
        let mut flows = SessionRealtimeFlows::new(
            Arc::clone(&registry),
            Some(session_flow::leased_control_profile(&registry)),
        );

        let unregistered = RealtimeEncoding::new(WebRtcRtpKind::Video, "video/VP8", 90_000, 0)
            .expect("an encoding naming a family the control profile never registered");
        assert_eq!(
            flows.open(
                &session,
                Some(&incarnation),
                RealtimeFlowSpec {
                    direction: RealtimeDirection::Outbound,
                    encoding: unregistered,
                    name: name.clone(),
                },
            ),
            Err(RealtimeFlowError::EncodingInvalid),
            "an unregistered family has no codec to negotiate and no framer to \
             install, which is a property of the request and not of what the \
             transport later makes of it"
        );

        let registered = RealtimeEncoding::new(WebRtcRtpKind::Video, "video/H264", 90_000, 0)
            .expect("an encoding naming a family the control profile registers");
        assert_eq!(
            flows.open(
                &session,
                Some(&incarnation),
                RealtimeFlowSpec {
                    direction: RealtimeDirection::Outbound,
                    encoding: registered,
                    name: name.clone(),
                },
            ),
            Ok(name),
            "the same name and the only outbound slot are both still free, so \
             the refusal above acquired neither"
        );
    }

    /// A second party to one retirement waits for the first to finish, and is
    /// never told the work is done before it is.
    ///
    /// Three parties can reach the same native object — an explicit close, the
    /// pump that was feeding the flow, and the install that supersedes the
    /// session — and single ownership is only half the answer. The other half
    /// is what the losers are told. A loser that returned immediately would let
    /// the daemon acknowledge a close while the transceiver was still being
    /// stopped, and a reopen on that label would then race a transceiver still
    /// offering to receive.
    ///
    /// Exercised on [`RealtimeRetirement`] directly, which is why that state is
    /// a type of its own and holds no transceiver: the race is in the claim and
    /// the completion, and standing up a peer connection to reach it would test
    /// `webrtc`'s `stop` rather than this decision. The assertion that matters
    /// is the *negative* one — that the waiter is still waiting — because a
    /// completion that fired early would satisfy every positive assertion here.
    #[tokio::test]
    async fn v4_macro1_a_losing_retirer_waits_for_the_winner_to_finish() {
        let mut retirement = RealtimeRetirement::new();

        let done = retirement
            .claim()
            .expect("the first caller takes responsibility");
        let waiting = retirement
            .claim()
            .expect_err("a second caller does not get a second claim on one object");
        let mut third = retirement.claim().expect_err("nor does any later one");

        let mut waiter = tokio::spawn(await_retirement(waiting));
        // Not `is_finished`, which would be a race against the spawn itself.
        // A timed poll that expires is the honest form of "still waiting".
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut waiter)
                .await
                .is_err(),
            "the loser is still waiting while the winner's stop is outstanding — \
             without this the assertion below would pass on a completion that \
             had fired immediately"
        );
        assert!(
            !*third.borrow_and_update(),
            "and nothing observing the state reports it as retired yet"
        );

        // What `stop_owned` does once `stop` has returned.
        done.send_replace(true);

        waiter
            .await
            .expect("the loser is released once the winner has finished");
        third
            .changed()
            .await
            .expect("and a later subscriber sees the same completion");
        assert!(*third.borrow());
    }

    /// A unit that arrives for a label with no open inbound flow is dropped at
    /// arrival, and its bytes go with it.
    ///
    /// The discriminating case for the early-arrival race: a peer's first
    /// units can outrun the application-level announcement that would have
    /// caused this side to open the flow. Nothing queues them against a
    /// future open — there is no place to put them that is not an unbounded,
    /// unaccounted buffer keyed on a label the session does not yet use, and
    /// a label is not a reservation.
    ///
    /// So the answer is refuse-and-release, and the second half is the part
    /// worth a control: the caller's lease is consumed by the drop, which
    /// returns the bytes rather than stranding them. A drop that leaked its
    /// lease would look identical from the caller's side and would exhaust
    /// the envelope one unarrived flow at a time.
    #[test]
    fn v4_macro1_a_unit_for_an_unopened_flow_is_dropped_and_its_bytes_released() {
        let registry =
            test_realtime_registry(explicit_realtime_callback_policy(16, 1, 1, 16, 1, 128));
        let flows = SessionRealtimeFlows::new(
            Arc::clone(&registry),
            Some(session_flow::leased_control_profile(&registry)),
        );
        let data = Bytes::from_static(b"unit");

        // A lease taken exactly as the inbound pump would take it.
        let port = registry
            .open_inbound_flow()
            .expect("the fixture admits one inbound flow");
        let output = port
            .reserve_output(data.len())
            .expect("the fixture envelope admits one unit");
        let payload = output.into_payload_lease();
        {
            let state = registry.state.lock();
            assert!(
                retained_realtime_bytes(&state) > 0,
                "the lease is really holding bytes before the drop — without \
                 this the release assertion below would pass vacuously"
            );
        }

        // Assembled exactly as the inbound pump assembles one: a leaseless
        // delivery, with the queue's lease attached afterwards. Passed intact,
        // because that is the only shape the engine can hand over — it cannot
        // name the lease inside, let alone separate it.
        let mut delivery = RealtimeInboundDelivery::new(
            test_label(7),
            RealtimeRecvUnit {
                timestamp: 90_000,
                marker: true,
                data,
            },
        );
        delivery
            .attach(payload)
            .expect("a freshly built delivery has no lease to displace");

        assert!(
            !flows.deliver_inbound(delivery),
            "a label this session holds no flow for takes nothing"
        );

        drop(port);
        let state = registry.state.lock();
        assert_eq!(
            retained_realtime_bytes(&state),
            0,
            "the refused unit's lease was consumed by the drop, not stranded"
        );
        assert!(
            realtime_accounting_is_clean(&state),
            "and released rather than lost, which would poison the domain"
        );
    }

    #[test]
    fn v4_arc03_guarded_video_reordered_unit_transfers_exact_output_claim() {
        let registry =
            test_realtime_registry(explicit_realtime_callback_policy(32, 1, 1, 8, 1, 64));
        let flow = registry.open_inbound_flow().expect("flow is admitted");
        let mut assembler =
            RealtimeUnitAssembler::guarded(h264_framing(), RealtimeFlowPortHandle::of(&flow));
        let anchor = assembler
            .push(&rtp_pkt(9, 100, true, IDR_NAL))
            .expect("anchor is valid")
            .expect("anchor emits");
        drop(anchor);
        assert!(assembler
            .push(&rtp_pkt(10, 200, false, FU_S))
            .unwrap()
            .is_none());
        assert!(assembler
            .push(&rtp_pkt(12, 200, true, FU_E))
            .unwrap()
            .is_none());
        let unit = assembler
            .push(&rtp_pkt(11, 200, false, FU_M))
            .expect("late middle is valid")
            .expect("whole reordered unit emits");
        assert_eq!(unit.data.as_ref(), &[0, 0, 0, 1, 0x65, 0x11, 0x22, 0x33]);
        assert_eq!(
            retained_realtime_bytes(&registry.state.lock()),
            unit.data.len()
        );
        drop(unit);
        assert_eq!(retained_realtime_bytes(&registry.state.lock()), 0);
    }

    #[test]
    fn v4_arc03f_guarded_video_in_progress_limit_is_independent_per_flow() {
        let registry =
            test_realtime_registry(explicit_realtime_callback_policy(32, 2, 1, 8, 1, 64));
        let first_flow = registry
            .open_inbound_flow()
            .expect("first flow is admitted");
        let second_flow = registry
            .open_inbound_flow()
            .expect("second flow is admitted");
        let mut first =
            RealtimeUnitAssembler::guarded(h264_framing(), RealtimeFlowPortHandle::of(&first_flow));
        let mut second = RealtimeUnitAssembler::guarded(
            h264_framing(),
            RealtimeFlowPortHandle::of(&second_flow),
        );
        assert!(first.push(&rtp_pkt(1, 100, false, FU_S)).unwrap().is_none());
        assert!(second
            .push(&rtp_pkt(2, 200, false, FU_S))
            .unwrap()
            .is_none());
        assert_eq!(second.fragments_held(), 1);
        assert_eq!(
            RealtimeFlowRegistry::in_progress_units(&registry.state.lock()),
            2
        );
        drop(first);
        assert_eq!(
            RealtimeFlowRegistry::in_progress_units(&registry.state.lock()),
            1
        );
        drop(second);
        assert_eq!(
            RealtimeFlowRegistry::in_progress_units(&registry.state.lock()),
            0
        );
    }

    #[test]
    fn v4_arc03f_in_progress_unit_limit_is_enforced_per_flow() {
        let registry =
            test_realtime_registry(explicit_realtime_callback_policy(32, 2, 1, 8, 1, 64));
        let first_flow = registry
            .open_inbound_flow()
            .expect("first flow is admitted");
        let second_flow = registry
            .open_inbound_flow()
            .expect("second flow is admitted");

        let first_unit = first_flow.begin_unit().expect("first unit is admitted");
        assert!(
            first_flow.begin_unit().is_none(),
            "the same flow cannot exceed its unit ceiling"
        );
        let second_unit = second_flow
            .begin_unit()
            .expect("another flow retains its independent unit slot");
        assert_eq!(
            RealtimeFlowRegistry::in_progress_units(&registry.state.lock()),
            2
        );

        drop(first_unit);
        assert!(first_flow.begin_unit().is_some());
        drop(second_unit);
    }

    #[test]
    fn single_packet_units_emit_in_order() {
        let mut asm = RealtimeUnitAssembler::new(h264_framing());
        let s1 = asm.push(&rtp_pkt(1, 100, true, IDR_NAL)).unwrap().unwrap();
        assert!(s1.entry_point, "type-5 NAL is a decoder entry point");
        assert_eq!(&s1.data[..], &[0, 0, 0, 1, 0x65, 0xAA, 0xBB]);
        let s2 = asm.push(&rtp_pkt(2, 200, true, IDR_NAL)).unwrap();
        assert!(s2.is_some(), "the anchored next unit emits too");
    }

    #[test]
    fn fragments_reassemble_even_when_reordered() {
        let mut asm = RealtimeUnitAssembler::new(h264_framing());
        // Anchor with a complete first unit.
        asm.push(&rtp_pkt(9, 100, true, IDR_NAL)).unwrap().unwrap();
        // Fragments arrive start, END (marker), middle — out of order.
        assert!(asm.push(&rtp_pkt(10, 200, false, FU_S)).unwrap().is_none());
        assert!(asm.push(&rtp_pkt(12, 200, true, FU_E)).unwrap().is_none());
        let s = asm
            .push(&rtp_pkt(11, 200, false, FU_M))
            .unwrap()
            .expect("contiguous after the late middle arrives");
        // Reconstructed: start code + NAL header (idc|type) + fragments.
        assert_eq!(&s.data[..], &[0, 0, 0, 1, 0x65, 0x11, 0x22, 0x33]);
        assert!(s.entry_point);
    }

    #[test]
    fn a_hole_mid_unit_drops_that_unit_never_a_torn_one() {
        let mut asm = RealtimeUnitAssembler::new(h264_framing());
        asm.push(&rtp_pkt(20, 100, true, IDR_NAL)).unwrap().unwrap();
        // Unit 2 loses its middle fragment for good.
        assert!(asm.push(&rtp_pkt(21, 200, false, FU_S)).unwrap().is_none());
        assert!(asm.push(&rtp_pkt(23, 200, true, FU_E)).unwrap().is_none());
        // Unit 3 arrives — unit 2 is abandoned, and unit 3 (which starts
        // an AU) emits despite the lost anchor.
        let s = asm
            .push(&rtp_pkt(24, 300, true, IDR_NAL))
            .unwrap()
            .expect("the stream re-syncs on the next unit");
        assert_eq!(s.rtp_timestamp, 300);
    }

    #[test]
    fn an_anchored_hole_waits_for_the_retransmit() {
        let mut asm = RealtimeUnitAssembler::new(h264_framing());
        asm.push(&rtp_pkt(29, 100, true, IDR_NAL)).unwrap().unwrap();
        // The unit's *first* packet is missing; the marker alone must not
        // emit a headless tail.
        assert!(asm.push(&rtp_pkt(31, 200, false, FU_M)).unwrap().is_none());
        assert!(asm.push(&rtp_pkt(32, 200, true, FU_E)).unwrap().is_none());
        // The NACK retransmit fills the hole late — the unit completes.
        let s = asm
            .push(&rtp_pkt(30, 200, false, FU_S))
            .unwrap()
            .expect("retransmit completes the chain");
        assert_eq!(&s.data[..], &[0, 0, 0, 1, 0x65, 0x11, 0x22, 0x33]);
    }

    #[test]
    fn late_retransmit_of_an_abandoned_unit_cannot_clobber_the_live_one() {
        let mut asm = RealtimeUnitAssembler::new(h264_framing());
        // Unit at ts 100 never completes (tail lost)…
        assert!(asm.push(&rtp_pkt(40, 100, false, FU_S)).unwrap().is_none());
        // …the next unit begins…
        assert!(asm.push(&rtp_pkt(42, 200, false, FU_S)).unwrap().is_none());
        // …a stale retransmit for ts 100 arrives and must be ignored…
        assert!(asm.push(&rtp_pkt(41, 100, true, FU_E)).unwrap().is_none());
        // …and the live unit still completes intact.
        let s = asm
            .push(&rtp_pkt(43, 200, true, FU_E))
            .unwrap()
            .expect("live unit unaffected by the stale packet");
        assert_eq!(s.rtp_timestamp, 200);
        assert_eq!(&s.data[..], &[0, 0, 0, 1, 0x65, 0x11, 0x33]);
    }

    #[test]
    fn a_headless_tail_never_emits_without_an_anchor() {
        let mut asm = RealtimeUnitAssembler::new(h264_framing());
        // Fresh stream joined mid-unit: middle + end fragments only.
        assert!(asm.push(&rtp_pkt(50, 100, false, FU_M)).unwrap().is_none());
        assert!(
            asm.push(&rtp_pkt(51, 100, true, FU_E)).unwrap().is_none(),
            "a contiguous-looking run that doesn't *start* a unit stays dropped"
        );
    }

    #[test]
    fn sequence_wraparound_is_transparent() {
        let mut asm = RealtimeUnitAssembler::new(h264_framing());
        asm.push(&rtp_pkt(65534, 100, true, IDR_NAL))
            .unwrap()
            .unwrap();
        assert!(asm
            .push(&rtp_pkt(65535, 200, false, FU_S))
            .unwrap()
            .is_none());
        assert!(asm.push(&rtp_pkt(0, 200, false, FU_M)).unwrap().is_none());
        let s = asm
            .push(&rtp_pkt(1, 200, true, FU_E))
            .unwrap()
            .expect("the chain is contiguous across the wrap");
        assert_eq!(&s.data[..], &[0, 0, 0, 1, 0x65, 0x11, 0x22, 0x33]);
    }

    #[test]
    fn au_start_detection_matches_rtp_payload_shapes() {
        assert!(payload_starts_au(&Bytes::from_static(IDR_NAL)));
        assert!(payload_starts_au(&Bytes::from_static(FU_S)));
        assert!(!payload_starts_au(&Bytes::from_static(FU_M)));
        assert!(!payload_starts_au(&Bytes::from_static(FU_E)));
        // STAP-A aggregates start units too.
        assert!(payload_starts_au(&Bytes::from_static(&[0x78, 0x00, 0x01])));
    }

    /// The connector's binding slot dies with the session that owns it, and a
    /// replacement points only at the new one.
    ///
    /// This is the `Weak` doing the whole job. The slot exists so `on_track`
    /// can find the table that says which flow a negotiated track may attach
    /// to, and the one thing it must never do is keep answering after the
    /// `PromotedSession` that owned those flows is gone — a table that outlived
    /// its session would resolve tokens to labels in a flow set that no longer
    /// exists.
    ///
    /// Three cases, and the middle one is the discriminating one: a strong
    /// slot would pass "install works" and "replacement points at the new set"
    /// identically, and would fail only here.
    #[test]
    fn v4_macro1_the_connector_binding_slot_cannot_outlive_its_session() {
        // No resources and no ceiling, and **no profile either**. What this
        // control exercises is the slot's `Weak`, which never consults codecs:
        // nothing here opens a flow or admits a track. A registry with no
        // resources could not pay for a profile record in any case — the
        // acquisition answers `OwnerPolicyMissing` before capacity is even a
        // question — so asking for one would make the fixture, rather than the
        // slot, the thing under test.
        let registry = RealtimeFlowRegistry::new(None, None);
        // Shared, because the table owns the retirement of the transceivers it
        // records and hands a clone of itself to whichever task performs one.
        // This control negotiates none, so that sweep has nothing to do here.
        let tracks = Arc::new(RealtimeSessionTracks::default());

        // Nothing installed yet: an arriving track has nothing to consult.
        assert!(
            tracks.current().is_none(),
            "a connector with no promoted session admits no inbound track"
        );

        let flows = SessionRealtimeFlows::new(Arc::clone(&registry), None);
        tracks.install(flows.inbound_bindings());
        let installed = tracks
            .current()
            .expect("the installed table upgrades while its flow set is alive");
        assert!(
            flows.owns_bindings(&installed),
            "and it is *that* flow set's table, not merely some table"
        );
        // Released before the session ends, and that is load-bearing rather
        // than tidy: `current()` hands back a *strong* reference, so a control
        // still holding one is itself a second owner and the slot below would
        // upgrade for that reason alone. The premise of the next assertion is
        // that the flow set is the only strong holder.
        drop(installed);

        // The session ends. This is the case a strong slot would fail: the
        // flow set is the only strong holder, so dropping it must make the
        // connector's slot unupgradable.
        drop(flows);
        assert!(
            tracks.current().is_none(),
            "the table died with the session that owned the flows it names — a \
             strong slot here would have kept it resolving into a flow set that \
             no longer exists"
        );

        // A replacement session installs its own, and the slot points only at
        // the new one.
        let replacement = SessionRealtimeFlows::new(Arc::clone(&registry), None);
        tracks.install(replacement.inbound_bindings());
        let current = tracks
            .current()
            .expect("the replacement's table upgrades in its turn");
        assert!(
            replacement.owns_bindings(&current),
            "the slot names the replacement's table and not a survivor of the \
             session it replaced"
        );
        drop(current);

        // And the replacement's own drop clears it again, so the slot is not
        // merely correct once.
        drop(replacement);
        assert!(tracks.current().is_none());
    }

    /// An FU-B start fragment is not an anchor, because this side cannot frame
    /// one.
    ///
    /// The two halves of the assembler have to agree about which payloads it
    /// can act on. `annexb_output_len` handles single NAL, STAP-A and FU-A and
    /// errors on everything else, so anchoring on an FU-B (type 29) commits to
    /// a chain the framing then always rejects. `try_emit` treats a framing
    /// error as a *consumed* unit — it advances `prev_end` and clears — so the
    /// cost is the whole unit, repeated for as long as the peer sends FU-B,
    /// rather than one refused packet.
    ///
    /// The discriminating comparison is against FU-A, which is byte-identical
    /// apart from the NAL type and must still anchor: a fix that refused both
    /// would stop the deployed H.264 path dead and would pass a test that only
    /// asserted the FU-B negative.
    #[test]
    fn v4_macro1_an_fu_b_fragment_is_not_an_anchor_the_framing_would_reject() {
        // 0x7D = FU-B (type 29) with the same start bit and NAL header the
        // FU-A fixtures use, so the only difference from `FU_S` is the type.
        const FU_B_S: &[u8] = &[0x7D, 0x85, 0x11];

        assert!(
            payload_starts_au(&Bytes::from_static(FU_S)),
            "FU-A still anchors — this is the deployed shape and refusing it \
             would be worse than the defect"
        );
        assert!(
            !payload_starts_au(&Bytes::from_static(FU_B_S)),
            "FU-B does not, because the framing has no case for type 29"
        );

        // The reason, stated against the framing itself rather than restated:
        // an FU-B chain really is unframeable, so admitting it as an anchor
        // could only ever produce the error path.
        let mut parts = std::collections::BTreeMap::new();
        parts.insert(0i64, Bytes::from_static(FU_B_S));
        assert!(
            H264Framing
                .framed_len(UnitFragments::new(
                    &parts,
                    FragmentCursor::for_test(0),
                    FragmentCursor::for_test(0)
                ))
                .is_err(),
            "type 29 has no framing case, which is what makes anchoring on it \
             a guaranteed lost unit"
        );
    }

    /// A retransmit arriving after a successful emit does not rewind the
    /// assembler or cost the next unit its anchor.
    ///
    /// The steady state between two units is `parts` empty and `prev_end`
    /// holding the last marker. Testing emptiness to decide whether a
    /// timestamp may be adopted therefore accepts an *older* timestamp in
    /// exactly that state — the assembler rewinds, files the stale packet as
    /// the start of a new unit, and the next genuine packet then sees a
    /// non-empty `parts`, discards `prev_end` as an abandoned unit, and forces
    /// the unit after it to re-anchor.
    ///
    /// So the visible damage is one unit *later* than the stale packet, which
    /// is what makes it worth a control: the retransmit itself is correctly
    /// swallowed either way, and only the third unit shows the difference.
    #[test]
    fn v4_macro1_a_retransmit_after_an_emit_does_not_rewind_the_assembler() {
        let mut asm = RealtimeUnitAssembler::new(h264_framing());

        // Unit one emits and anchors the stream at seq 10.
        let first = asm
            .push(&rtp_pkt(10, 100, true, IDR_NAL))
            .unwrap()
            .expect("a single-packet unit emits immediately");
        assert_eq!(first.rtp_timestamp, 100);

        // A duplicate of that same unit arrives late, in the window where
        // `parts` is empty because the emit cleared it.
        assert!(
            asm.push(&rtp_pkt(10, 100, true, IDR_NAL))
                .unwrap()
                .is_none(),
            "the stale copy emits nothing, which is true before and after the \
             fix and is therefore not the discriminating assertion"
        );

        // The next unit is fragmented, so it can only emit if `prev_end`
        // survived: its first fragment is an FU-A start, and re-anchoring
        // would work here too — so make the unit after it the real test.
        assert!(asm.push(&rtp_pkt(11, 200, false, FU_S)).unwrap().is_none());
        let second = asm
            .push(&rtp_pkt(12, 200, true, FU_E))
            .unwrap()
            .expect("the anchor survived the stale retransmit");
        assert_eq!(second.rtp_timestamp, 200);
        assert_eq!(&second.data[..], &[0, 0, 0, 1, 0x65, 0x11, 0x33]);

        // And a headless unit — one with no start fragment — still emits,
        // which it can do only from a live anchor. This is the assertion that
        // separates the two implementations: with the rewind, `prev_end` is
        // gone by now and this unit is dropped for want of something
        // `payload_starts_au` accepts.
        assert!(asm.push(&rtp_pkt(13, 300, false, FU_M)).unwrap().is_none());
        let third = asm
            .push(&rtp_pkt(14, 300, true, FU_E))
            .unwrap()
            .expect("a headless unit emits from the surviving anchor");
        assert_eq!(third.rtp_timestamp, 300);
    }

    /// A stream whose first packet carries a high random RTP timestamp still
    /// starts.
    ///
    /// The companion to the control above, and the reason the fix cannot
    /// simply compare timestamps. `self.timestamp` initialises to 0 while a
    /// real sender picks a random 32-bit start, so for roughly half of all
    /// streams the first packet is "older than zero" under shortest-distance
    /// comparison. Without an explicit uninitialised case those streams would
    /// never produce a single unit.
    #[test]
    fn v4_macro1_a_stream_starting_past_the_wrap_point_still_emits() {
        let mut asm = RealtimeUnitAssembler::new(h264_framing());
        // Greater than 2^31, so `newer_rtp_ts(ts, 0)` is false.
        let high = 0x9000_0000u32;
        assert!(
            !crate::transport::webrtc::unit_assembly::newer_rtp_ts(high, 0),
            "the fixture really is on the far side of the wrap, or this test \
             proves nothing"
        );
        let unit = asm
            .push(&rtp_pkt(7, high, true, IDR_NAL))
            .unwrap()
            .expect("the first packet of a stream is adopted whatever its timestamp");
        assert_eq!(unit.rtp_timestamp, high);
    }

    #[test]
    fn private_lan_ips_recognised_public_ones_not() {
        // RFC1918 + link-local → LAN.
        assert!(is_private_lan_ip("192.168.1.50"));
        assert!(is_private_lan_ip("10.0.0.3"));
        assert!(is_private_lan_ip("172.16.4.9"));
        assert!(is_private_lan_ip("169.254.10.20"));
        assert!(is_private_lan_ip("fe80::1"));
        assert!(is_private_lan_ip("fd12:3456::1"));
        // Public, CGNAT, and junk → not LAN.
        assert!(!is_private_lan_ip("1.2.3.4"));
        assert!(!is_private_lan_ip("100.64.0.1")); // carrier-grade NAT, not a LAN
        assert!(!is_private_lan_ip("2606:4700::1111"));
        assert!(!is_private_lan_ip("not-an-ip"));
    }

    #[tokio::test]
    async fn loopback_handshake_opens_data_channel() {
        // Bring up two peer sessions on the same in-process
        // Transport. No STUN / TURN — they exchange host
        // candidates over the same loopback interface. Verifies
        // the entire offer/answer/candidate cycle plus the
        // data-channel handshake without external dependencies.
        let observed_at = Instant::now();
        let transport = Transport::new().expect("transport");
        let cfg = RTCConfiguration::default();
        let callback_policy = test_webrtc_profile(NATIVE_LOOPBACK_CALLBACK_CAPACITY).callbacks();
        let (offerer, mut off_rx) = transport
            .open_peer_with_config(Role::Offerer, cfg.clone(), callback_policy)
            .await
            .expect("offerer");
        let (answerer, mut ans_rx) = transport
            .open_peer_with_config(Role::Answerer, cfg, callback_policy)
            .await
            .expect("answerer");

        let offer = offerer.create_offer().await.expect("create_offer");
        let offer_credentials =
            sdp_ice_credentials(&offer.sdp).expect("native offer exposes exact ICE credentials");
        answerer
            .set_remote_description(offer)
            .await
            .expect("answerer.set_remote");
        let answer = answerer.create_answer().await.expect("create_answer");
        let answer_credentials =
            sdp_ice_credentials(&answer.sdp).expect("native answer exposes exact ICE credentials");
        offerer
            .set_remote_description(answer)
            .await
            .expect("offerer.set_remote");

        // Pump ICE candidates between the two sides for up to 10s.
        // Either order is fine — we just need both to see the
        // DataChannelOpen event before the deadline.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
        let mut off_open = false;
        let mut ans_open = false;

        while (!off_open || !ans_open) && tokio::time::Instant::now() < deadline {
            tokio::select! {
                Some(ev) = off_rx.recv() => {
                    if let TransportEvent::LocalIceCandidate(Some(c)) = &ev {
                        assert!(
                            candidate_matches_remote_credentials(c, &offer_credentials),
                            "native offer candidate {c:?} must identify its exact SDP binding {offer_credentials:?}"
                        );
                        answerer
                            .add_ice_candidate(c.clone())
                            .await
                            .expect("add ice to answerer");
                    }
                    if matches!(ev, TransportEvent::DataChannelOpen) { off_open = true; }
                }
                Some(ev) = ans_rx.recv() => {
                    if let TransportEvent::LocalIceCandidate(Some(c)) = &ev {
                        assert!(
                            candidate_matches_remote_credentials(c, &answer_credentials),
                            "native answer candidate {c:?} must identify its exact SDP binding {answer_credentials:?}"
                        );
                        offerer
                            .add_ice_candidate(c.clone())
                            .await
                            .expect("add ice to offerer");
                    }
                    if matches!(ev, TransportEvent::DataChannelOpen) { ans_open = true; }
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
            }
        }

        assert!(off_open, "offerer never saw DataChannelOpen");
        assert!(ans_open, "answerer never saw DataChannelOpen");

        offerer
            .send(Bytes::from_static(b"hello"))
            .await
            .expect("send");
        // Drain answerer events for the message.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut got = false;
        while tokio::time::Instant::now() < deadline {
            tokio::select! {
                Some(ev) = ans_rx.recv() => {
                    if let TransportEvent::Message(b) = ev {
                        assert_eq!(b.as_ref(), b"hello");
                        got = true;
                        break;
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
            }
        }
        assert!(got, "answerer never received the app frame");

        if std::env::var_os("MYOWNMESH_ARC03_OBSERVE_RAW").is_some() {
            println!(
                "arc03_direct_raw handshake_and_data_ns={}",
                observed_at.elapsed().as_nanos()
            );
        }
        let offerer_close_at = Instant::now();
        offerer.close().await.expect("close offerer");
        if std::env::var_os("MYOWNMESH_ARC03_OBSERVE_RAW").is_some() {
            println!(
                "arc03_direct_raw endpoint=offerer close_ns={}",
                offerer_close_at.elapsed().as_nanos()
            );
        }
        let answerer_close_at = Instant::now();
        answerer.close().await.expect("close answerer");
        if std::env::var_os("MYOWNMESH_ARC03_OBSERVE_RAW").is_some() {
            println!(
                "arc03_direct_raw endpoint=answerer close_ns={}",
                answerer_close_at.elapsed().as_nanos()
            );
        }
    }

    #[test]
    fn annexb_nal_scan_finds_types_across_both_start_codes() {
        // 4-byte start code SPS (7), 3-byte start code PPS (8), then IDR (5).
        let au = [
            0, 0, 0, 1, 0x67, 0xAA, // SPS
            0, 0, 1, 0x68, 0xBB, // PPS
            0, 0, 0, 1, 0x65, 0x11, 0x22, // IDR slice
        ];
        let types: Vec<u8> = annexb_nal_types(&au).collect();
        assert_eq!(types, vec![7, 8, 5]);
        assert!(au_has_idr(&au));

        // A delta slice (type 1) alone is not a key.
        let p = [0, 0, 0, 1, 0x41, 0x99];
        assert!(!au_has_idr(&p));

        // Degenerate inputs scan to nothing without panicking.
        assert_eq!(annexb_nal_types(&[]).count(), 0);
        assert_eq!(annexb_nal_types(&[0, 0, 1]).count(), 0);
    }

    #[test]
    fn au_assembler_groups_by_timestamp_and_drops_torn_units() {
        let mut asm = RealtimeUnitAssembler::new(h264_framing());
        // Two single-NAL packets of one frame; marker closes it.
        assert!(asm
            .push(&rtp_pkt(1, 1000, false, &[0x41, 1, 1, 1]))
            .unwrap()
            .is_none());
        let s = asm
            .push(&rtp_pkt(2, 1000, true, &[0x65, 2, 2, 2]))
            .unwrap()
            .expect("marker completes the unit");
        assert!(
            s.entry_point,
            "an IDR NAL anywhere in the unit marks it a decoder entry point"
        );
        assert_eq!(s.rtp_timestamp, 1000);
        // Depacketized single NALs come back with start codes attached.
        assert_eq!(
            s.data.as_ref(),
            &[0, 0, 0, 1, 0x41, 1, 1, 1, 0, 0, 0, 1, 0x65, 2, 2, 2]
        );

        // A unit whose marker never arrived is dropped when the next
        // timestamp starts; the new unit is unaffected.
        assert!(asm
            .push(&rtp_pkt(3, 2000, false, &[0x41, 7, 7, 7]))
            .unwrap()
            .is_none());
        let s = asm
            .push(&rtp_pkt(4, 3000, true, &[0x41, 9, 9, 9]))
            .unwrap()
            .expect("fresh unit completes");
        assert_eq!(s.rtp_timestamp, 3000);
        assert!(!s.entry_point);
        assert_eq!(s.data.as_ref(), &[0, 0, 0, 1, 0x41, 9, 9, 9]);
    }

    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    async fn v4_arc03h_data_only_and_generic_realtime_without_flows_allocate_no_media_lines() {
        for (profile_name, profile) in [
            ("disabled", test_webrtc_profile(4)),
            (
                "generic-without-open-flow",
                test_generic_realtime_webrtc_profile(4),
            ),
        ] {
            let observed_at = Instant::now();
            let grant = one_mesh_connector_fixture_grant(&[profile.clone()])
                .expect("the codec-neutral fixture claim is representable");
            let provider = ResourceProviderPort::new(FiniteResourceProvider::new(grant))
                .expect("the codec-neutral fixture accounts for its process scope");
            let owner = ConnectorResourceOwnerPort::new(provider)
                .issue_mesh_scope()
                .expect("the codec-neutral fixture accounts for its Mesh scope");
            let process = ProcessResourceRoot::isolated();
            let scope = process
                .mesh_runtime_scope()
                .network_instance_scope()
                .peer_connection_scope();
            let transport = Transport::new()
                .expect("test transport")
                .with_connector_resource_scope(owner, profile);
            let (worker, _events) = transport
                .open_connector_peer(Role::Offerer, &[], &[], scope)
                .await
                .expect("data-only connector is constructed");

            let offer = worker
                .create_offer()
                .await
                .expect("data-only connector creates an offer");
            assert!(offer
                .sdp
                .lines()
                .any(|line| line.starts_with("m=application")));
            assert!(!offer.sdp.lines().any(|line| line.starts_with("m=audio")));
            assert!(!offer.sdp.lines().any(|line| line.starts_with("m=video")));
            if std::env::var_os("MYOWNMESH_ARC03_OBSERVE_RAW").is_some() {
                println!(
                    "arc03_data_only_raw profile={} constructed_ns={} media_lines=0",
                    profile_name,
                    observed_at.elapsed().as_nanos()
                );
            }

            worker
                .retire_and_close()
                .await
                .expect("native peer closes through its exact owner");
        }
    }

    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    async fn v4_arc03g_close_fence_rejects_endpoint_send() {
        let owner = test_resource_owner(1, 4);
        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(owner, test_webrtc_profile(4));
        let (worker, _events) = transport
            .open_connector_peer(Role::Answerer, &[], &[], scope)
            .await
            .expect("data-only connector is constructed");

        worker.retire();

        let error = worker
            .send_owned(Bytes::from_static(b"endpoint"))
            .await
            .expect_err("endpoint send is fenced after close");
        assert!(
            error
                .to_string()
                .contains("connector close fence has committed"),
            "the operation reached its native owner after close: {error}"
        );

        worker
            .retire_and_close()
            .await
            .expect("native peer closes through its exact owner");
    }

    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    async fn v4_arc03h_close_wins_before_open_promotion() {
        let owner = test_resource_owner(1, 4);
        let scope = ProcessResourceRoot::isolated()
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(owner, test_webrtc_profile(4));
        let (worker, _events) = transport
            .open_connector_peer(Role::Answerer, &[], &[], scope)
            .await
            .expect("data-only connector is constructed");

        worker.retire();
        assert!(matches!(
            worker.confirm_data_channel_open(),
            DataChannelOpenOwnership::Rejected
        ));
        worker
            .retire_and_close()
            .await
            .expect("native peer closes through its exact owner");
    }

    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    /// A retired connector can no longer be named by a promotion, so nothing
    /// downstream of promotion — including every real-time flow — can be opened
    /// against it. Close wins the race by removing the only identity the
    /// admission fence is allowed to bind.
    async fn v4_arc03h_close_wins_before_connector_naming() {
        let owner = test_resource_owner(1, 4);
        let scope = ProcessResourceRoot::isolated()
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(owner, test_generic_realtime_webrtc_profile(4));
        let (worker, _events) = transport
            .open_connector_peer(Role::Answerer, &[], &[], scope)
            .await
            .expect("real-time connector is constructed");
        let handoff = match worker.confirm_data_channel_open() {
            DataChannelOpenOwnership::Connected(handoff) => handoff,
            _ => panic!("live connector produces one Endpoint Auth handoff"),
        };
        let task = task_from_handoff(handoff);
        assert!(
            worker.live_connector_incarnation().is_some(),
            "non-vacuity — a live connector really can be named"
        );
        assert!(worker.owns_endpoint_auth(&task));

        worker.retire();
        assert!(worker.live_connector_incarnation().is_none());
        assert!(!worker.owns_endpoint_auth(&task));
        worker
            .retire_and_close()
            .await
            .expect("native peer closes through its exact owner");
    }

    /// A real-time unit is admitted only while the session that could have
    /// produced it still owns a live binding table.
    ///
    /// Driven through `accept_event`, which is the production entry point the
    /// engine's connector pump calls — not through `ConnectorOwnership::accepts`
    /// underneath it, which answers the connector question only and answers
    /// `true` for a connected connector however long ago its session died.
    ///
    /// The connector is held at `Connected` and untouched for the whole body,
    /// so every transition below is the session table's alone.
    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    async fn v4_arc03_realtime_unit_requires_a_live_session_binding_table() {
        let owner = test_resource_owner(1, 4);
        let scope = ProcessResourceRoot::isolated()
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(owner, test_generic_realtime_webrtc_profile(4));
        let (worker, _events) = transport
            .open_connector_peer(Role::Answerer, &[], &[], scope)
            .await
            .expect("real-time connector is constructed");
        let _task = match worker.confirm_data_channel_open() {
            DataChannelOpenOwnership::Connected(handoff) => task_from_handoff(handoff),
            _ => panic!("live connector produces one Endpoint Auth handoff"),
        };

        // BEFORE PROMOTION. Connector authority is fully satisfied — the
        // connector is live, connected, and stamped these events itself — so a
        // refusal here is attributable to the session gate and to nothing else.
        assert!(
            worker
                .accept_event(worker.stamp_event_for_test(TransportEvent::DataChannelClosed))
                .is_some(),
            "non-vacuity: connector authority admits this worker's own events"
        );
        assert!(
            worker
                .accept_event(worker.stamp_event_for_test(test_realtime_event(0, 0, b"early")))
                .is_none(),
            "a unit with no live session table behind it is refused before delivery"
        );

        // PROMOTED. The same event on the same connector is now admitted, which
        // is what makes the refusals on either side of it discriminating rather
        // than a path that never accepts a unit at all.
        let flows = worker.new_session_flows();
        assert!(
            worker
                .accept_event(worker.stamp_event_for_test(test_realtime_event(0, 1, b"live")))
                .is_some(),
            "a promoted session's table is what admits a unit"
        );

        // SESSION GONE, CONNECTOR UNCHANGED. The table is held weakly, so
        // dropping the flow set is exactly what a `PromotedSession` dropping
        // does — no retirement, no close, no connector state change.
        drop(flows);
        assert!(
            worker
                .accept_event(worker.stamp_event_for_test(test_realtime_event(0, 2, b"late")))
                .is_none(),
            "and a unit outliving its session's table is refused again"
        );
        assert!(
            worker
                .accept_event(worker.stamp_event_for_test(TransportEvent::DataChannelClosed))
                .is_some(),
            "while the connector itself is untouched — the gate is the session's, not a retirement"
        );

        worker
            .retire_and_close()
            .await
            .expect("native peer closes through its exact owner");
    }
}
