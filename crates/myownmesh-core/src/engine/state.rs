//! Shared per-network state. Exposes the operations subsystems
//! (`Channel<T>`, `Rpc`, `MeshHandle`) call to interact with the
//! engine; all per-peer state mutation is funneled through the
//! command queue so the driver loop owns serial access.

use std::sync::Arc;

use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tracing::trace;

use crate::channels::RawChannelFrame;
use crate::config::{NetworkConfig, TopologyMode};
use crate::error::{Error, Result};
use crate::events::{DiagEntry, DiagLevel, DropReason, MeshEvent, MeshPhase, PhaseEvent};
use crate::identity::Identity;
use crate::protocol::{rpc::RpcRequestMessage, CapabilityAdvert};
use crate::resource::{
    MeshRuntimeResourceScope, NetworkInstanceResourceScope, ProcessResourceRoot, ResourceReport,
};
use crate::roster::Roster;
use crate::rpc::RpcInner;
use crate::topology::Topology;
use crate::transport::webrtc::{AudioSample, VideoSample};
use crate::transport::{LocalIceCandidate, Transport};

use super::conn_trace::ConnTrace;
use super::connection::PeerConnection;
use super::scheduler::{
    RECONNECTING_GRACE_MS, RECONNECT_RETRY_BACKOFF_MS, RELAY_RESCUE_MIN_INTERVAL_MS,
};

/// One assembled video access unit from a peer's track lane, as the
/// embedder-facing subscription surfaces it.
#[derive(Debug, Clone)]
#[cfg_attr(
    not(feature = "legacy-media"),
    allow(dead_code, reason = "frozen legacy-media compatibility value")
)]
pub struct InboundVideoSample {
    /// The authenticated peer the unit arrived from.
    pub from: String,
    pub sample: VideoSample,
}

/// One audio frame from a peer's track lane, as the engine's
/// subscribers receive it (tagged with the sending peer).
#[derive(Debug, Clone)]
#[cfg_attr(
    not(feature = "legacy-media"),
    allow(dead_code, reason = "frozen legacy-media compatibility value")
)]
pub struct InboundAudioSample {
    /// Sending peer's device id.
    pub from: String,
    pub sample: AudioSample,
}

/// Bookkeeping for an offerer-side reconnect intent. When we drop a peer we
/// were the *offerer* for (a recoverable `IceFailed`), we keep one of these
/// in [`NetworkState::reconnect_intents`] and the single state-watch tick
/// re-offers on a backoff until the link comes back or `give_up_at` passes.
/// This is the offerer-side counterpart to an answerer recovering from the
/// remote's re-offers — without it, an offerer-role peer that drops on a
/// network shift is never re-offered (it only comes back on the peer's slow
/// steady-state announce). The backoff (`next_retry_at`/`attempt`) keeps the
/// recovery from publishing an offer on every tick — one re-offer per
/// backoff step, never cadence traffic.
#[derive(Debug, Clone, Copy)]
pub struct ReconnectIntent {
    /// Stop retrying after this instant (drop time + `RECONNECTING_GRACE_MS`).
    /// A sticky intent ignores this — see [`ReconnectIntent::sticky`].
    pub give_up_at: std::time::Instant,
    /// Earliest instant for the next re-offer; advanced by the backoff each
    /// time the tick services this intent.
    pub next_retry_at: std::time::Instant,
    /// Number of re-offers issued so far — indexes `RECONNECT_RETRY_BACKOFF_MS`.
    pub attempt: usize,
    /// A pinned peer's intent: never expires, and once the active backoff
    /// schedule is spent it parks (no more tick-driven re-offers) and waits
    /// for the peer's next announce to dial — the recovery loop a support
    /// session needs on a Silent network, without endless blind offers to
    /// a peer that may be off for the weekend.
    pub sticky: bool,
}

/// Bump a reconnect intent's backoff after a re-offer: advance the attempt
/// and push `next_retry_at` out by the next step (saturating at the last
/// one). One offer per backoff window — never a per-tick publish.
fn advance_backoff(intent: &mut ReconnectIntent, now: std::time::Instant) {
    let step = RECONNECT_RETRY_BACKOFF_MS
        .get(intent.attempt)
        .copied()
        .or_else(|| RECONNECT_RETRY_BACKOFF_MS.last().copied())
        .unwrap_or(15_000);
    intent.attempt = intent.attempt.saturating_add(1);
    intent.next_retry_at = now + std::time::Duration::from_millis(step);
}

/// General engine command queue entry. Application requests and network
/// reconfiguration use this serialized path. Connector events remain on their
/// bounded per-worker runtime path and do not enter this enum.
pub enum NetworkCmd {
    /// Stop the engine and tear down all peer sessions.
    Shutdown,
    /// Switch the topology selector at runtime.
    SetTopology(TopologyMode),
    /// Approve a peer into the roster (and emit the approve frame).
    ApproveRoster {
        device_id: String,
        label: String,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Remove a peer from the roster and drop any active session.
    RemoveRoster {
        device_id: String,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Drop a single peer, surfacing the given reason in the
    /// `Dropped` event.
    DropPeer {
        device_id: String,
        reason: DropReason,
    },
    /// Manually triggered in-place reconnect — the non-destructive twin of a
    /// leave-then-rejoin. `peer == None` reconnects the whole network (redial
    /// signaling + renegotiate ICE with every peer); `peer == Some(id)`
    /// reconnects just that one peer. Nothing is torn down and no `Leave` is
    /// announced, so peers keep their sessions and app-level state — this is
    /// the gentle recovery the GUI's refresh / reconnect controls drive
    /// instead of the old `NetworkRemove` + `NetworkAdd`. See
    /// [`super::network_watch::reconnect_all_in_place`].
    Reconnect { peer: Option<String> },
    /// Deliberately dial exactly one signaling-discovered peer as the
    /// offerer, opening the WebRTC session the announce path would have
    /// opened automatically on a non-Silent network. This is the manual
    /// "dial by device id" a `Silent` network exposes (via
    /// [`crate::JoinedNetwork::connect_peer`]): on a Silent mesh nothing
    /// connects on its own, so a connection is initiated only here or by
    /// answering an inbound offer. Idempotent — a no-op if a live session
    /// already exists; upgrades a discovery-only `Sighted` placeholder to a
    /// real session otherwise.
    ConnectPeer {
        device_id: String,
        /// Record a standing dial for this peer (see
        /// [`NetworkState::sticky_peers`]) so the engine keeps
        /// re-establishing the link across drops and announces.
        sticky: bool,
        /// When present, resolved once the peer reaches ACTIVE (or
        /// with the reason on a terminal failure). `None` preserves
        /// the fire-and-forget contract.
        reply: Option<oneshot::Sender<Result<()>>>,
    },
    /// Open the lowest free media lane of `kind` toward `peer`,
    /// resolving with the lane id. The explicit twin of the
    /// write-time auto-open.
    #[cfg(feature = "legacy-media")]
    MediaLaneOpen {
        peer: String,
        kind: crate::transport::webrtc::LaneKind,
        reply: oneshot::Sender<Result<u8>>,
    },
    /// Close an open media lane (idempotent) — the track is removed
    /// and the next renegotiation drops its m-line send side.
    #[cfg(feature = "legacy-media")]
    MediaLaneClose {
        peer: String,
        kind: crate::transport::webrtc::LaneKind,
        lane: u8,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Queue a channel frame for acknowledged delivery (see
    /// [`super::reliable`]): parked until the peer's link is up,
    /// retransmitted across session rebuilds, resolved on the peer's
    /// cumulative ack (or with an error at TTL / terminal failure).
    SendChannelReliable {
        peer: String,
        channel: String,
        payload: serde_json::Value,
        ttl_ms: Option<u64>,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Send a [`crate::protocol::MeshMessage::Channel`] frame to
    /// one peer.
    SendChannelFrame {
        peer: String,
        channel: String,
        payload: serde_json::Value,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Broadcast a channel frame to every active peer.
    BroadcastChannelFrame {
        channel: String,
        payload: serde_json::Value,
        reply: oneshot::Sender<usize>,
    },
    /// Send an RPC request frame to one peer.
    SendRpcRequest {
        peer: String,
        request: RpcRequestMessage,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Push a new capabilities advert to every active peer.
    BroadcastCapabilities {
        caps: CapabilityAdvert,
        reply: oneshot::Sender<usize>,
    },
    // ---- governance (closed networks) ----
    /// Float a new signed transition. The engine signs with the
    /// local identity, persists the proposal to the governance
    /// state's pending list, and broadcasts a
    /// `NetworkStatePropose` to every active peer that supports
    /// `network_state_v1`. Reply carries the new proposal id so
    /// the caller can correlate acks.
    ProposeTransition {
        variant: crate::network_state::TransitionVariant,
        /// Per-device custody second factor, if the network requires one on
        /// this device. `None` when no custody lock is enrolled.
        mfa_code: Option<String>,
        reply: oneshot::Sender<Result<String>>,
    },
    /// Sign an existing pending proposal. Verifies the local user
    /// has authority for the variant + that the proposal hasn't
    /// already been signed by this device, then signs and
    /// broadcasts a `NetworkStateAck { decision: Sign }`. If the
    /// signature satisfies the quorum, the engine ratifies the
    /// transition in the same step.
    SignProposal {
        proposal_id: String,
        /// Per-device custody second factor (see `ProposeTransition`).
        mfa_code: Option<String>,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Deny a pending proposal. Any single deny invalidates the
    /// proposal — the engine drops it from pending and broadcasts
    /// the signed deny.
    DenyProposal {
        proposal_id: String,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Withdraw a proposal the local device floated. No
    /// broadcast — peers see the proposal disappear via the
    /// next `NetworkState` snapshot.
    WithdrawProposal {
        proposal_id: String,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Proposer-initiated split fallback. Spawns a derived closed
    /// network from the signers the proposer has so far. Reply
    /// carries the derived `network_id` so the caller can join
    /// the new network straight away.
    SpawnSplit {
        proposal_id: String,
        reply: oneshot::Sender<Result<String>>,
    },
    /// Snapshot of the current governance state. Used by the
    /// control protocol to surface live state to the GUI.
    GovernanceSnapshot {
        reply: oneshot::Sender<crate::network_state::NetworkState>,
    },
}

/// Inbound signaling messages from the signaling task.
#[derive(Debug)]
pub enum SignalingInbound {
    PeerAnnounced {
        device_id: String,
    },
    Offer {
        device_id: String,
        sdp: String,
    },
    Answer {
        device_id: String,
        sdp: String,
    },
    Candidate {
        device_id: String,
        candidate: LocalIceCandidate,
    },
    PeerLeft {
        device_id: String,
    },
}

impl SignalingInbound {
    /// Variant name for driver-liveness traces — cheap, no payload.
    pub fn kind_name(&self) -> &'static str {
        match self {
            SignalingInbound::PeerAnnounced { .. } => "peer_announced",
            SignalingInbound::Offer { .. } => "offer",
            SignalingInbound::Answer { .. } => "answer",
            SignalingInbound::Candidate { .. } => "candidate",
            SignalingInbound::PeerLeft { .. } => "peer_left",
        }
    }
}

/// Narrow owner of the current peer set.
///
/// Callers can take owned read snapshots, but only this registry can install,
/// replace, remove, or retire peers. Every ownership exit explicitly ends the
/// connector worker even when another task retains an external
/// `Arc<PeerConnection>`.
pub(super) struct PeerRegistry {
    peers: DashMap<String, PeerRegistryEntry>,
    mutation: Mutex<()>,
}

struct PeerRegistryEntry {
    peer: Arc<PeerConnection>,
    installation: Arc<()>,
}

/// Unforgeable process-local identity for one installed peer owner.
///
/// This is carried by delayed engine work so a timer or callback created for
/// peer A cannot mutate or remove replacement peer B under the same device id.
/// It is not authentication, application, or durable mesh authority.
#[doc(hidden)]
#[derive(Clone)]
pub struct PeerOwnerToken {
    peer: Arc<PeerConnection>,
    installation: Arc<()>,
}

impl PeerOwnerToken {
    pub(crate) fn device_id(&self) -> &str {
        &self.peer.device_id
    }
}

impl Default for PeerRegistry {
    fn default() -> Self {
        Self {
            peers: DashMap::new(),
            mutation: Mutex::new(()),
        }
    }
}

impl PeerRegistry {
    pub(super) fn get(&self, device_id: &str) -> Option<Arc<PeerConnection>> {
        self.peers
            .get(device_id)
            .map(|entry| Arc::clone(&entry.value().peer))
    }

    pub(super) fn owner(&self, device_id: &str) -> Option<PeerOwnerToken> {
        self.peers.get(device_id).map(|entry| PeerOwnerToken {
            peer: Arc::clone(&entry.value().peer),
            installation: Arc::clone(&entry.value().installation),
        })
    }

    pub(super) fn get_if_current(&self, owner: &PeerOwnerToken) -> Option<Arc<PeerConnection>> {
        self.peers.get(owner.device_id()).and_then(|entry| {
            Arc::ptr_eq(&entry.value().installation, &owner.installation)
                .then(|| Arc::clone(&entry.value().peer))
        })
    }

    /// Run one synchronous effect only while `owner` is still the installed
    /// peer. Registry replacement and removal take the same mutation lock, so
    /// the effect cannot cross from an accepted callback for peer A into a
    /// replacement peer B that reused the same device id.
    pub(super) fn with_current<R>(
        &self,
        owner: &PeerOwnerToken,
        effect: impl FnOnce(&Arc<PeerConnection>) -> R,
    ) -> Option<R> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation) {
            return None;
        }
        Some(effect(&current.value().peer))
    }

    /// Run one synchronous legacy application operation, only while `owner` is
    /// the installed peer **and** that peer is admitted for application work.
    ///
    /// This is the one admission linearization point. All three conjuncts — the
    /// exact current owner, a live authenticated capability for that peer's
    /// exact current connector, and retained policy — are evaluated together
    /// under the registry mutation lock, and the witness that proves them is
    /// minted inside it. Replacement takes the same lock, so it orders strictly
    /// before or after the whole effect.
    ///
    /// `None` means the operation was not authorized. The caller deliberately
    /// cannot tell whether the owner was stale or admission failed: an
    /// admission answer that escaped as a value would be exactly the transient
    /// boolean this replaces.
    pub(super) fn with_admitted_current<R>(
        &self,
        owner: &PeerOwnerToken,
        effect: impl FnOnce(&AdmittedLegacyOperation<'_>) -> R,
    ) -> Option<R> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation) {
            return None;
        }
        let peer = &current.value().peer;
        if !peer.admitted_for_legacy_application() {
            return None;
        }
        Some(effect(&AdmittedLegacyOperation {
            peer,
            owner,
            _not_send: std::marker::PhantomData,
        }))
    }

    /// The same fence, with an explicit refusal arm.
    ///
    /// `refused` receives the exact current peer and may only *record* — it
    /// authorizes nothing, because no witness exists on that arm. It exists so
    /// the inbound path can count a refused application frame under the same
    /// acquisition that refused it, instead of re-entering the registry and
    /// racing its own refusal. `None` still means the owner is stale.
    pub(super) fn with_admitted_current_or_refused<R>(
        &self,
        owner: &PeerOwnerToken,
        admitted: impl FnOnce(&AdmittedLegacyOperation<'_>) -> R,
        refused: impl FnOnce(&Arc<PeerConnection>) -> R,
    ) -> Option<R> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation) {
            return None;
        }
        let peer = &current.value().peer;
        if !peer.admitted_for_legacy_application() {
            return Some(refused(peer));
        }
        Some(admitted(&AdmittedLegacyOperation {
            peer,
            owner,
            _not_send: std::marker::PhantomData,
        }))
    }

    /// Mint one owned authority for a legacy application operation that will
    /// cross an await.
    ///
    /// Built under the same fence and the same three conjuncts as
    /// [`Self::with_admitted_current`], and additionally requires a live
    /// connector worker, since an operation that cannot name its exact
    /// connector has nothing to write through.
    pub(super) fn admit_application_operation(
        &self,
        owner: &PeerOwnerToken,
    ) -> Option<AdmittedApplicationOperation> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation) {
            return None;
        }
        let peer = &current.value().peer;
        if !peer.admitted_for_legacy_application() {
            return None;
        }
        let session = peer.session.lock().clone()?;
        Some(AdmittedApplicationOperation {
            peer: Arc::clone(peer),
            session,
        })
    }

    pub(super) fn contains_key(&self, device_id: &str) -> bool {
        self.peers.contains_key(device_id)
    }

    pub(super) fn len(&self) -> usize {
        self.peers.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Snapshot peer owners without duplicating registry keys. The peer already
    /// owns its device id, so value-oriented scans need one `Arc` clone only.
    pub(super) fn values_snapshot(&self) -> Vec<Arc<PeerConnection>> {
        self.peers
            .iter()
            .map(|entry| Arc::clone(&entry.value().peer))
            .collect()
    }

    /// Build one output vector from an `Arc`-only snapshot. The DashMap guards
    /// are released before the callback can take a peer-state lock. This avoids
    /// the old key clones without introducing a registry-to-peer lock order.
    pub(super) fn collect_map<T>(
        &self,
        mut map: impl FnMut(&PeerConnection) -> Option<T>,
    ) -> Vec<T> {
        self.values_snapshot()
            .into_iter()
            .filter_map(|peer| map(peer.as_ref()))
            .collect()
    }

    /// Visit an `Arc`-only snapshot after releasing every DashMap guard.
    pub(super) fn visit(&self, mut visit: impl FnMut(&PeerConnection)) {
        for peer in self.values_snapshot() {
            visit(peer.as_ref());
        }
    }

    pub(super) fn count_where(&self, mut predicate: impl FnMut(&PeerConnection) -> bool) -> usize {
        self.values_snapshot()
            .into_iter()
            .filter(|peer| predicate(peer.as_ref()))
            .count()
    }

    /// Snapshot only registry keys for topology code that does not need peer
    /// state or connector ownership.
    pub(super) fn device_ids_snapshot(&self) -> Vec<String> {
        self.peers.iter().map(|entry| entry.key().clone()).collect()
    }

    pub(super) fn install(&self, peer: Arc<PeerConnection>) -> Option<Arc<PeerConnection>> {
        let device_id = peer.device_id.clone();
        let _mutation = self.mutation.lock();
        if self
            .peers
            .get(&device_id)
            .is_some_and(|current| Arc::ptr_eq(&current.value().peer, &peer))
        {
            return None;
        }
        if peer.registry_retired() {
            return None;
        }
        let replaced = self
            .peers
            .insert(
                device_id,
                PeerRegistryEntry {
                    peer,
                    installation: Arc::new(()),
                },
            )
            .map(|entry| entry.peer);
        if let Some(replaced) = replaced.as_ref() {
            replaced.retire_connector();
        }
        replaced
    }

    pub(super) fn remove(&self, device_id: &str) -> Option<Arc<PeerConnection>> {
        let _mutation = self.mutation.lock();
        let (_, entry) = self.peers.remove(device_id)?;
        let peer = entry.peer;
        peer.retire_connector();
        Some(peer)
    }

    pub(super) fn remove_if_current(&self, owner: &PeerOwnerToken) -> Option<Arc<PeerConnection>> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation) {
            return None;
        }
        drop(current);
        let (_, entry) = self.peers.remove(owner.device_id())?;
        let peer = entry.peer;
        peer.retire_connector();
        Some(peer)
    }

    /// Remove every current owner after retiring its connector worker.
    /// Returned peers let shutdown close sessions after map ownership ends.
    pub(super) fn retire_all(&self) -> Vec<Arc<PeerConnection>> {
        let _mutation = self.mutation.lock();
        let retired: Vec<_> = self
            .peers
            .iter()
            .map(|entry| Arc::clone(&entry.value().peer))
            .collect();
        for peer in &retired {
            peer.retire_connector();
        }
        self.peers.clear();
        retired
    }
}

impl Drop for PeerRegistry {
    fn drop(&mut self) {
        let retired = self.retire_all();
        drop(retired);
    }
}

/// Proof that one exact peer installation was admitted for legacy application
/// work, valid only for the body of one synchronous effect.
///
/// Minted only inside the registry fence, so possessing one *is* the proof that
/// the owner was current and admission held at a single linearization point.
/// The peer is bound internally and reached through the operations below rather
/// than handed out, so a witness for peer A cannot be presented alongside peer
/// B's connection. [`Self::record_inbound`] is the one exception: it lends the
/// exact admitted peer to a closure. That `Arc` conveys no admission authority —
/// it is the same handle any registry read yields — and the borrow ends with the
/// closure, inside the fence.
///
/// `PhantomData<*const ()>` makes it `!Send`: it cannot be moved into a task,
/// and the lifetime keeps it inside the closure, so it can never be held across
/// an await or outlive the fence that minted it.
pub(super) struct AdmittedLegacyOperation<'a> {
    peer: &'a Arc<PeerConnection>,
    /// The exact owner token this fence admitted, borrowed rather than cloned
    /// so entering the fence costs nothing. Any witness that crosses an await
    /// clones it, so later bookkeeping names *this* installation instead of
    /// re-resolving a device id that a replacement may since have taken over.
    owner: &'a PeerOwnerToken,
    _not_send: std::marker::PhantomData<*const ()>,
}

impl AdmittedLegacyOperation<'_> {
    /// The exact admitted peer's device id, for dispatch attribution.
    pub(super) fn device_id(&self) -> &str {
        &self.peer.device_id
    }

    /// Record inbound liveness and traffic on the exact admitted peer.
    pub(super) fn record_inbound(&self, effect: impl FnOnce(&Arc<PeerConnection>)) {
        effect(self.peer);
    }

    /// Install the retained legacy real-time flow for this admitted peer.
    pub(super) fn install_legacy_realtime_flow(&self) -> bool {
        self.peer.install_legacy_realtime_flow()
    }

    /// Take the paired real-time ports as one owned value that can cross an
    /// await without ever being re-paired with another peer or connector.
    pub(super) fn realtime_operation(&self) -> Option<AdmittedRealtimeOperation> {
        let (session, flow) = self.peer.realtime_flow_ports()?;
        Some(AdmittedRealtimeOperation {
            peer: Arc::clone(self.peer),
            owner: self.owner.clone(),
            session,
            flow,
        })
    }

    /// Take one admitted inbound frame as an owned, move-only operation.
    ///
    /// The message is moved *in* to the fence by the caller and comes back out
    /// only here, on the admitted arm, bound to the exact peer and owner this
    /// fence proved. Mirrors [`Self::realtime_operation`]: the binding is what
    /// lets the dispatch that follows name *this* installation instead of
    /// re-resolving a device id a replacement may since have taken over.
    pub(super) fn inbound_application_operation(
        &self,
        msg: crate::protocol::MeshMessage,
    ) -> AdmittedInboundApplicationOperation {
        AdmittedInboundApplicationOperation {
            msg,
            dispatch: AdmittedInboundDispatch {
                peer: Arc::clone(self.peer),
                owner: self.owner.clone(),
            },
        }
    }
}

/// Move-only authority to dispatch exactly one already-parsed inbound
/// application frame against one exact peer installation.
///
/// This is what the inbound path used to answer with an `Option<bool>`. The
/// boolean was the defect: it outlived the fence that produced it, and every
/// dispatch arm below then re-resolved the peer *by device id*, so a
/// replacement installed during the await answered the lookup and received the
/// effect, the liveness touch, the counters, and the delivery. An authority
/// cannot be re-resolved — it names one installation, and after replacement it
/// names nothing.
///
/// Carries all three things one admission decided, as a single value: the
/// exact owner, the exact captured peer, and the one parsed frame. Deliberately
/// not `Clone`, `Copy`, `Debug`, `Default`, or serializable, and consumed by
/// value, so one admission dispatches exactly one frame.
#[must_use = "an admitted inbound frame authorizes exactly one dispatch and must be consumed"]
pub(super) struct AdmittedInboundApplicationOperation {
    msg: crate::protocol::MeshMessage,
    dispatch: AdmittedInboundDispatch,
}

impl AdmittedInboundApplicationOperation {
    /// Split into the one frame this admission authorized and the installation
    /// binding that outlives it for the dispatch.
    ///
    /// Consuming by value is the single-dispatch rule: the frame cannot be
    /// dispatched twice, and it cannot be paired with a different admission.
    pub(super) fn into_dispatch(self) -> (crate::protocol::MeshMessage, AdmittedInboundDispatch) {
        (self.msg, self.dispatch)
    }
}

/// The installation binding an admitted inbound frame dispatches against.
///
/// There is deliberately **no device-id accessor here**. The device id is the
/// re-resolution key this witness exists to remove, so a handler that needs
/// mesh identity for attribution takes it from [`Self::owner`], which names one
/// *installation* and not merely one device — and which every peer-reaching
/// helper (`get_if_current`, `send_to_peer_owner`) already accepts directly.
///
/// Dropping one is harmless: unlike [`AdmittedRenegotiation`] it latches
/// nothing, so an arm that decides the frame needs no effect simply drops it.
///
/// Strictly `pub(super)`. Every inbound handler that takes one is reachable
/// only from the engine's own dispatch, so they are narrowed to `pub(super)`
/// too rather than this witness being widened to fit them — an admission
/// authority that had to become a public item to be usable would be the wrong
/// trade, and `#[doc(hidden)]` is a documentation flag, not a visibility one.
pub(super) struct AdmittedInboundDispatch {
    peer: Arc<PeerConnection>,
    owner: PeerOwnerToken,
}

impl AdmittedInboundDispatch {
    /// The exact owner this frame was admitted for. Never a fresh
    /// `owner(device_id)` lookup — that is the escape being closed.
    pub(super) fn owner(&self) -> &PeerOwnerToken {
        &self.owner
    }

    /// Run one synchronous application effect on the exact captured peer,
    /// **inside** the registry fence, and answer with whatever it produced.
    ///
    /// This delegates to [`PeerRegistry::with_current`], which holds the
    /// mutation lock across the whole effect. That is the point, and it is the
    /// difference between this and a currency *check*: replacement takes the
    /// same lock, so it orders strictly before or after the entire effect and
    /// there is no instant at which "still current" has been established but
    /// the effect has not yet run. A `get_if_current` guard followed by the
    /// effect would be exactly the check-then-act shape this witness exists to
    /// remove — the boolean would simply have moved inside the type.
    ///
    /// Everything the effect needs must therefore be synchronous and
    /// non-reentrant: it runs under the registry mutation lock. It must not
    /// await, and it must not call back into [`PeerRegistry`] (the lock is not
    /// reentrant). Broadcast sends are fine — they hand off a value and wake
    /// tasks without running them inline — which is what lets a state change
    /// and the event announcing it happen as one atomic step.
    ///
    /// The effect receives the *captured* handle rather than the registry's.
    /// They are the same object whenever the fence admits, and naming the
    /// captured one states the invariant: this operation writes to the
    /// installation that was admitted, or to nothing at all.
    ///
    /// `None` means the captured installation is no longer the installed one,
    /// so nothing ran.
    pub(super) fn with_captured_peer<R>(
        &self,
        peers: &PeerRegistry,
        effect: impl FnOnce(&Arc<PeerConnection>) -> R,
    ) -> Option<R> {
        peers.with_current(&self.owner, |_current| effect(&self.peer))
    }
}

/// Move-only authority to perform exactly one legacy application send on one
/// exact peer installation.
///
/// Carries the peer and the connector worker captured **at admission**, under
/// the registry fence. The send writes through that captured worker and records
/// against that captured peer; nothing here re-resolves a device id, so a
/// replacement installed during the await cannot receive this operation or its
/// accounting.
///
/// No separate incarnation is stored. `send_owned` enters the worker's own
/// operation and close fence and races the write against retirement, so the
/// captured worker *is* the incarnation check; a duplicate field would be state
/// that never decides anything.
///
/// Deliberately not `Clone`, `Copy`, `Debug`, `Default`, or serializable, and
/// consumed by value, so one admission authorizes one operation.
#[must_use = "an admitted operation authorizes exactly one send and must be consumed"]
pub(super) struct AdmittedApplicationOperation {
    peer: Arc<PeerConnection>,
    session: Arc<crate::transport::WebRtcConnectorWorker>,
}

impl AdmittedApplicationOperation {
    /// Send one serialized frame through the exact captured connector, then
    /// record it against the exact captured peer.
    ///
    /// Both halves use the captured values, so a send and its accounting can
    /// never land on different installations.
    pub(super) async fn send_frame(
        self,
        bytes: bytes::Bytes,
        timeout: std::time::Duration,
    ) -> Result<usize> {
        let sent = tokio::time::timeout(timeout, self.session.send_owned(bytes))
            .await
            .map_err(|_| Error::Transport("peer send timed out".into()))??;
        let mut data = self.peer.state.write();
        data.diag.bytes_out += sent as u64;
        data.diag.frames_out += 1;
        Ok(sent)
    }
}

/// Move-only authority for one legacy real-time operation, keeping the exact
/// peer, connector worker, and flow capability bound together.
///
/// The binding is the point, so there is deliberately no accessor that yields
/// the worker and the capability separately: every operation below applies the
/// pair this witness captured, which makes a cross-paired call unconstructible
/// rather than merely refused by the connector. Renegotiation is the one path
/// that legitimately needs the worker alone, and it says so by name.
#[must_use = "an admitted real-time operation must be consumed"]
pub(super) struct AdmittedRealtimeOperation {
    peer: Arc<PeerConnection>,
    /// The exact owner captured under the same fence that admitted this
    /// witness. Completion bookkeeping must name this token, never a fresh
    /// `owner(device_id)` lookup: a replacement installed after the mint would
    /// answer that lookup and receive another installation's result.
    owner: PeerOwnerToken,
    session: Arc<crate::transport::WebRtcConnectorWorker>,
    flow: Arc<crate::connector::ConnectorRealtimeFlowCapability>,
}

impl AdmittedRealtimeOperation {
    /// Whether the captured peer has a pending lane-set change.
    pub(super) fn media_reneg_pending(&self) -> bool {
        self.peer.state.read().media_reneg_pending
    }

    /// Consume this witness into the renegotiation session, claiming the
    /// renegotiation only once the captured pair has revalidated.
    ///
    /// Renegotiation drives SDP on the connector and opens no lane, so it is the
    /// one legitimate session-only use — but it is still minted from a live
    /// real-time capability, and yielding the worker while silently discarding
    /// that capability would make the witness's own authority decorative. The
    /// pair is therefore rechecked here, under every feature configuration:
    /// `owns_realtime_flow` asks the connector whether this exact capability
    /// belongs to this exact incarnation, so a capability from a superseded
    /// connector yields no session and the caller fails closed.
    ///
    /// The claim is taken **inside** this method, after validation, and
    /// deliberately not by a separate call before it. `media_reneg_inflight` is
    /// cleared only by the spawned renegotiation task, so claiming and then
    /// failing validation would leave the single-flight guard latched and that
    /// peer would never renegotiate again.
    ///
    /// This yields the worker **and** the exact owner captured at admission.
    /// Every later SDP call still passes the connector's own liveness and close
    /// fence, which stays authoritative.
    ///
    /// The owner travels with the session deliberately. Re-resolving it by
    /// device id after this point would reopen the window this witness exists
    /// to close: a replacement installed between the mint and that lookup would
    /// answer it, and the spawned task's completion bookkeeping —
    /// `media_reneg_inflight`, `media_reneg_pending`, `last_offer_sent_at` —
    /// would land on the replacement instead of the peer whose renegotiation
    /// actually ran. Carrying the token makes that bookkeeping a no-op after a
    /// replacement rather than a misattribution.
    pub(super) fn into_renegotiation(self) -> Option<AdmittedRenegotiation> {
        if !self.session.owns_realtime_flow(&self.flow) {
            return None;
        }
        {
            let mut data = self.peer.state.write();
            data.media_reneg_inflight = true;
            data.media_reneg_pending = false;
        }
        Some(AdmittedRenegotiation {
            session: self.session,
            owner: self.owner,
        })
    }

    #[cfg(feature = "legacy-media")]
    pub(super) async fn open_media_lane(
        self,
        kind: crate::transport::webrtc::LaneKind,
    ) -> Result<u8> {
        self.session.open_media_lane(&self.flow, kind).await
    }

    #[cfg(feature = "legacy-media")]
    pub(super) async fn close_media_lane(
        self,
        kind: crate::transport::webrtc::LaneKind,
        lane: u8,
    ) -> Result<()> {
        self.session.close_media_lane(&self.flow, kind, lane).await
    }

    #[cfg(feature = "legacy-media")]
    pub(super) async fn send_video(
        self,
        lane: u8,
        data: bytes::Bytes,
        duration: std::time::Duration,
    ) -> Result<()> {
        self.session
            .send_video(&self.flow, lane, data, duration)
            .await
    }

    #[cfg(feature = "legacy-media")]
    pub(super) async fn send_audio(
        self,
        lane: u8,
        data: bytes::Bytes,
        duration: std::time::Duration,
    ) -> Result<()> {
        self.session
            .send_audio(&self.flow, lane, data, duration)
            .await
    }

    /// Finalize suspended lanes and, if any were removed, mark renegotiation
    /// pending on the captured peer rather than on a post-await lookup.
    #[cfg(feature = "legacy-media")]
    pub(super) async fn finalize_suspended_lanes(self) -> usize {
        let finalized = self.session.finalize_suspended_lanes(&self.flow).await;
        if finalized != 0 {
            self.peer.state.write().media_reneg_pending = true;
        }
        finalized
    }
}

/// One claimed renegotiation: the connector to drive, plus the exact owner it
/// was claimed for, as a single move-only value.
///
/// The pairing is the point. `complete` takes **no owner argument**, so the
/// caller cannot substitute a freshly resolved one — a regression to
/// `peers.owner(device_id)` after the claim would have to abandon this API and
/// hand-roll the bookkeeping, which is a visible deletion rather than a silent
/// misattribution. `media_reneg_inflight` is already latched by the time this
/// exists, so a still-current installation must be completed: dropping it while
/// its peer is current would leave the single-flight guard set and that peer
/// would never renegotiate again. Dropping it once the installation has been
/// replaced is safe — `complete` would find nothing current and write nothing.
#[must_use = "a claimed renegotiation must be completed, or its in-flight guard stays latched"]
pub(super) struct AdmittedRenegotiation {
    session: Arc<crate::transport::WebRtcConnectorWorker>,
    owner: PeerOwnerToken,
}

impl AdmittedRenegotiation {
    /// The connector this renegotiation drives. Its own liveness and close
    /// fence stays authoritative for every SDP call.
    pub(super) fn session(&self) -> &Arc<crate::transport::WebRtcConnectorWorker> {
        &self.session
    }

    /// The captured owner's device id, for logging and signaling attribution.
    pub(super) fn device_id(&self) -> &str {
        self.owner.device_id()
    }

    /// Whether the exact installation this was claimed for is still current.
    pub(super) fn is_current(&self, peers: &PeerRegistry) -> bool {
        peers.get_if_current(&self.owner).is_some()
    }

    /// Record the outcome against the exact captured installation.
    ///
    /// A peer replaced while the offer was in flight fails `get_if_current`, so
    /// every write here becomes a no-op: the result is dropped rather than
    /// attributed to the replacement.
    pub(super) fn complete(self, peers: &PeerRegistry, outcome: std::result::Result<(), String>) {
        let Some(peer) = peers.get_if_current(&self.owner) else {
            return;
        };
        let mut data = peer.state.write();
        data.media_reneg_inflight = false;
        match outcome {
            Ok(()) => {
                data.last_offer_sent_at = Some(std::time::Instant::now());
            }
            Err(error) => {
                // Leave the work owed: the flag re-arms the next tick's attempt
                // instead of losing the lane change.
                data.media_reneg_pending = true;
                drop(data);
                tracing::debug!(peer = %self.owner.device_id(), "media renegotiation deferred: {error}");
            }
        }
    }
}

/// Outbound signaling messages from the engine to the signaling task.
/// `Clone` so the bridge's fan-out can hand one engine emission to
/// several concurrently-attached drivers (Nostr + mDNS).
#[derive(Debug, Clone)]
pub enum SignalingOutbound {
    Announce,
    /// Graceful departure broadcast — the dual of [`Announce`]. Tells every
    /// peer in the room to tear our session down *now* instead of waiting
    /// out the heartbeat timeout (~90 s). Emitted on a deliberate leave
    /// (network remove / transport restart / daemon shutdown) so that a
    /// "reconnect" — which is a leave-then-rejoin — doesn't strand peers
    /// holding a dead session whose ICE still falsely reports `Connected`.
    /// Public relays never synthesise a `Leave` for us (only an intelligent
    /// signaling server does), so the departing peer announces its own.
    Leave,
    Offer {
        device_id: String,
        sdp: String,
    },
    Answer {
        device_id: String,
        sdp: String,
    },
    Candidate {
        device_id: String,
        candidate: LocalIceCandidate,
    },
}

/// The shared state for a single joined network. Every long-lived
/// subsystem (driver loop, channels, rpc, handle) holds an
/// `Arc<NetworkState>`. Internally everything uses non-blocking
/// concurrent primitives (DashMap, RwLock, broadcast) so callers
/// don't serialize on a single lock.
pub struct NetworkState {
    pub network_id: String,
    pub identity: Arc<Identity>,
    pub transport: Transport,
    resource_scope: NetworkInstanceResourceScope,

    pub config: RwLock<NetworkConfig>,
    pub topology: RwLock<TopologyMode>,
    pub topology_impl: RwLock<Box<dyn Topology>>,

    pub(super) peers: PeerRegistry,
    pub roster: RwLock<Roster>,
    /// Signed governance state — kind + role assignments + the
    /// append-only signed transition log + pending proposals.
    /// Authority on a `closed` network derives from this; on an
    /// `open` network it's a no-op tracker that ratifies the
    /// open→closed transition if one ever fires.
    ///
    /// The on-disk projection lives at
    /// `~/.myownmesh/mesh/states/{network_id}.json` (per-network,
    /// 0600 on Unix). Loaded once on construction; the engine
    /// persists after every signed transition that lands.
    pub governance_state: RwLock<crate::network_state::NetworkState>,
    pub current_phase: RwLock<MeshPhase>,

    pub events_tx: broadcast::Sender<MeshEvent>,
    pub channel_subscribers: DashMap<String, broadcast::Sender<RawChannelFrame>>,
    /// Fan-out for assembled video access units arriving on peers'
    /// track lanes. One broadcast per network (subscribers filter by
    /// `from`); kept shallow — video is a freshness stream, a lagging
    /// subscriber loses old frames, never delays new ones.
    pub(crate) video_subscribers: broadcast::Sender<InboundVideoSample>,
    /// Fan-out for audio frames arriving on peers' audio lanes —
    /// deeper than video's (audio frames are tiny and a dropped one
    /// is an audible tick), still bounded so a lagging subscriber
    /// sheds the oldest instead of growing a backlog.
    pub(crate) audio_subscribers: broadcast::Sender<InboundAudioSample>,
    pub rpc: RwLock<Option<Arc<RpcInner>>>,

    pub signaling_tx: mpsc::UnboundedSender<SignalingOutbound>,
    pub signaling_inbound_tx: mpsc::UnboundedSender<SignalingInbound>,
    pub cmd_tx: mpsc::UnboundedSender<NetworkCmd>,

    /// Receiving end of `signaling_tx` — held here so callers can
    /// drain it via [`Self::take_signaling_outbound_rx`] when they
    /// bring up their signaling task.
    signaling_outbound_rx: Mutex<Option<mpsc::UnboundedReceiver<SignalingOutbound>>>,

    /// Offerer-side reconnect intents (see [`ReconnectIntent`]). Keyed by
    /// device id; an entry lives from the moment we drop a peer we owe an
    /// offer to until the link is re-established or the reconnecting grace
    /// expires. Events re-offer these immediately (relay reconnect, the
    /// peer's announce); the state-watch tick is the backstop that retries
    /// on a backoff for the cases no event covers.
    pub reconnect_intents: Mutex<std::collections::HashMap<String, ReconnectIntent>>,

    /// Peers this node maintains a standing dial for (config
    /// `pinned_peers` plus runtime `connect_peer(…, sticky)`). On a
    /// Silent network a pinned peer is dialed whenever it announces —
    /// the one exception to "Silent never auto-dials" — and its
    /// reconnect intent never expires. See `handle_signaling_inbound`.
    pub sticky_peers: Mutex<std::collections::HashSet<String>>,

    /// Whether this network's **signed governance** has evicted *this
    /// device* — the cached verdict of
    /// [`super::governance::refresh_self_evicted`], recomputed at startup
    /// and after every log adoption/ratification. While true the engine
    /// stands down on this network: no announces out, no dialing on
    /// announces in (every member would deny us anyway — with proof).
    /// Derived state, never persisted: the adopted signed log IS the
    /// durable record, so a restart recomputes the same verdict.
    pub self_evicted: std::sync::atomic::AtomicBool,

    /// Acked-delivery outboxes, one per peer with frames pending (see
    /// [`super::reliable`]). Driver-serial like all engine state; the
    /// mutex guards snapshot readers only.
    pub(crate) reliable_out: Mutex<std::collections::HashMap<String, super::reliable::Outbox>>,

    /// Receive-side high-water marks for acked delivery, one per peer
    /// that has sent us `channel_seq` frames.
    pub(crate) reliable_in: Mutex<std::collections::HashMap<String, super::reliable::InboundMark>>,

    /// Routed-frame dedup ring: `(origin, frame id)` pairs already
    /// delivered/forwarded, so flood cross-paths and retransmits are
    /// dropped at the door. Bounded at
    /// [`super::routing::ROUTING_SEEN_CAPACITY`].
    #[allow(
        dead_code,
        reason = "RTM-001 retains legacy forwarding state until that compatibility surface is dispositioned"
    )]
    pub(crate) routing_seen: Mutex<std::collections::VecDeque<(String, u64)>>,

    /// Per-network traffic accounting (see [`super::traffic`]) —
    /// written from the frame chokepoints, read by the status surface.
    pub traffic: super::traffic::TrafficCounters,

    /// Callers waiting for a specific peer to reach ACTIVE (the
    /// `connect_peer_wait` contract). Resolved on the mutual-approve
    /// transition; failed on terminal drops and shutdown.
    pub(crate) connect_waiters:
        Mutex<std::collections::HashMap<String, Vec<oneshot::Sender<Result<()>>>>>,

    /// Last time we reflected a peer's announce with one of our
    /// own. Rate-limited so a room with N peers all reacting to
    /// each other's announces doesn't degenerate into a publish
    /// storm — one outbound reactive announce per
    /// [`REACTIVE_ANNOUNCE_MIN_INTERVAL_MS`] coalesces any number
    /// of inbound announces in that window. See the comment on
    /// the call site in `engine::mod::handle_signaling_inbound`
    /// for the discovery rationale.
    pub last_reactive_announce_at: Mutex<Option<std::time::Instant>>,

    /// Latched state of the passive clock-skew diagnostic — warn once when
    /// this device's wall clock has disagreed with its peers' (measured off
    /// the heartbeat pings they already send) for several consecutive
    /// ticks, clear once when it resolves. See `heartbeat::watch_clock_skew`.
    pub clock_skew_watch: Mutex<super::heartbeat::ClockSkewWatch>,

    /// Force-reconnect handle for the signaling driver, stashed by
    /// [`crate::engine::signaling_bridge::attach_nostr`] once the
    /// Nostr driver is up. Bumping the generation makes every relay
    /// drop its socket and redial immediately (see the driver's
    /// `force_reconnect`); the engine triggers it on resume-from-sleep
    /// so a zombie relay socket is replaced at once rather than after
    /// the kernel's multi-minute TCP timeout. `None` when no driver is
    /// attached (e.g. the in-process local broker used in tests).
    relay_reconnect: Mutex<Option<Arc<watch::Sender<u64>>>>,

    /// The signaling driver's relay-connected generation (its
    /// `relay_connected`); bumped on every fresh relay session. After a
    /// network change asks for a redial, the change handler waits for the
    /// next bump before renegotiating ICE, so the offer isn't published into
    /// a relay that hasn't reconnected yet. `None` when no driver is attached.
    relay_connected: Mutex<Option<Arc<watch::Sender<u64>>>>,

    /// Last time the ICE-failure path forced a relay redial via
    /// [`request_relay_reconnect_throttled`]. Gates the "no remote
    /// candidates arrived" rescue (see
    /// `ice_watchdog::on_checking_timeout`) so a peer that keeps timing
    /// out every `ICE_CHECKING_TIMEOUT_MS` can't redial the relays on
    /// every cycle — one redial per
    /// [`RELAY_RESCUE_MIN_INTERVAL_MS`] window is enough to recover a
    /// genuinely-wedged signaling socket without churning healthy ones.
    last_relay_rescue_at: Mutex<Option<std::time::Instant>>,

    /// Set by the network watcher when the OS reports *no* primary
    /// outbound IP (neither v4 nor v6) — i.e. the host is fully
    /// offline, the state macOS lands in for a second or two on wake
    /// before the interface comes back. While true, the ICE machinery
    /// holds off re-gathering and tearing down peers: a `restart_ice()`
    /// in this window can't bind a socket (the `Network is unreachable`
    /// wall in the logs) and would only burn a checking-timeout on a
    /// doomed attempt. Cleared the moment an interface returns, at which
    /// point the network-change handler drives a clean restart fan-out.
    offline: std::sync::atomic::AtomicBool,

    /// Broadcast of per-peer connection-state transitions for the
    /// Phase-0 connection tracer (`engine::conn_trace`). Kept separate
    /// from `events_tx` so trace volume can never evict real Peer /
    /// Phase events from the GUI's subscriber, and so `receiver_count()`
    /// cleanly reflects whether anyone is watching — which is what gates
    /// the sweep's cost in the driver loop.
    pub conn_trace_tx: broadcast::Sender<ConnTrace>,
    /// When true, the connection tracer emits even with no live
    /// subscriber, so daemon file logs capture transitions. Read once
    /// from `MYOWNMESH_CONN_TRACE` at construction (any non-empty value
    /// other than `0` enables it).
    conn_trace_force_on: bool,
}

impl NetworkState {
    /// Construct a new network state. Returns the state plus the
    /// inbound signaling receiver and the command-queue receiver
    /// the driver consumes.
    #[allow(clippy::type_complexity)]
    pub fn new(
        config: NetworkConfig,
        identity: Arc<Identity>,
        transport: Transport,
    ) -> Result<(
        Arc<Self>,
        mpsc::UnboundedReceiver<SignalingInbound>,
        mpsc::UnboundedReceiver<NetworkCmd>,
    )> {
        let mesh_scope = ProcessResourceRoot::global().mesh_runtime_scope();
        Self::new_in_mesh_scope(config, identity, transport, &mesh_scope)
    }

    /// Construct state below an existing Mesh runtime observation scope.
    #[allow(clippy::type_complexity)]
    pub(crate) fn new_in_mesh_scope(
        config: NetworkConfig,
        identity: Arc<Identity>,
        transport: Transport,
        mesh_scope: &MeshRuntimeResourceScope,
    ) -> Result<(
        Arc<Self>,
        mpsc::UnboundedReceiver<SignalingInbound>,
        mpsc::UnboundedReceiver<NetworkCmd>,
    )> {
        Self::new_in_resource_scope(
            config,
            identity,
            transport,
            mesh_scope.network_instance_scope(),
        )
    }

    #[allow(clippy::type_complexity)]
    fn new_in_resource_scope(
        config: NetworkConfig,
        identity: Arc<Identity>,
        transport: Transport,
        resource_scope: NetworkInstanceResourceScope,
    ) -> Result<(
        Arc<Self>,
        mpsc::UnboundedReceiver<SignalingInbound>,
        mpsc::UnboundedReceiver<NetworkCmd>,
    )> {
        // Standing dials survive restarts by riding the network config —
        // the daemon re-joins with the same `pinned_peers`, and this seed
        // re-arms them without any runtime re-pinning.
        let pinned: std::collections::HashSet<String> =
            config.pinned_peers.iter().cloned().collect();
        let roster = crate::roster::load(&config.network_id)?;
        // Load (or initialise) the per-network signed state log. If
        // the config requests Closed kind but the on-disk log says
        // Open (or vice-versa), the on-disk log wins — kind is
        // authoritatively a signed-state property, not a config one.
        // The config field only seeds new networks at first attach.
        let governance_state = {
            let mut s = crate::network_state::load(&config.network_id)?;
            if s.transitions.is_empty() && s.kind == crate::network_state::NetworkKind::Open {
                // Brand-new state log — adopt the config's initial
                // kind. (For the open default, this is a no-op; for
                // Closed, the engine emits the founder-self-election
                // transition on first ACTIVE.)
                s.kind = config.kind;
            }
            s
        };
        // Topology has the same precedence as kind: a ratified
        // `TopologyChange` in the signed log outranks whatever the
        // local config says; the config value only shapes networks
        // governance hasn't spoken for.
        let effective_topology = governance_state
            .topology
            .clone()
            .unwrap_or_else(|| config.topology.clone());
        let topology_impl = crate::topology::from_mode(&effective_topology);
        let (events_tx, _) = broadcast::channel(256);
        // Shallow: at 30 fps a depth of 16 is half a second of slack —
        // beyond that a slow consumer should lose frames, not delay them.
        let (video_subscribers, _) = broadcast::channel(16);
        let (audio_subscribers, _) = broadcast::channel(64);
        // Deep enough to ride out a transition storm (a sleep/wake
        // fan-out re-handshaking every peer) without the watcher lagging;
        // lossy past that, with a `lagged` marker surfaced to the stream.
        let (conn_trace_tx, _) = broadcast::channel(512);
        let conn_trace_force_on = std::env::var("MYOWNMESH_CONN_TRACE")
            .map(|v| !v.is_empty() && v != "0")
            .unwrap_or(false);
        let (signaling_tx, signaling_outbound_rx) = mpsc::unbounded_channel();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (signaling_inbound_tx, signaling_inbound_rx) = mpsc::unbounded_channel();
        let state = Arc::new(Self {
            network_id: config.network_id.clone(),
            identity,
            transport,
            resource_scope,
            config: RwLock::new(config.clone()),
            topology: RwLock::new(effective_topology),
            topology_impl: RwLock::new(topology_impl),
            peers: PeerRegistry::default(),
            roster: RwLock::new(roster),
            governance_state: RwLock::new(governance_state),
            current_phase: RwLock::new(MeshPhase::Joining),
            events_tx,
            channel_subscribers: DashMap::new(),
            video_subscribers,
            audio_subscribers,
            rpc: RwLock::new(None),
            signaling_tx,
            signaling_inbound_tx,
            cmd_tx,
            signaling_outbound_rx: Mutex::new(Some(signaling_outbound_rx)),
            reconnect_intents: Mutex::new(std::collections::HashMap::new()),
            sticky_peers: Mutex::new(pinned),
            self_evicted: std::sync::atomic::AtomicBool::new(false),
            reliable_out: Mutex::new(std::collections::HashMap::new()),
            reliable_in: Mutex::new(std::collections::HashMap::new()),
            routing_seen: Mutex::new(std::collections::VecDeque::new()),
            traffic: super::traffic::TrafficCounters::default(),
            connect_waiters: Mutex::new(std::collections::HashMap::new()),
            last_reactive_announce_at: Mutex::new(None),
            clock_skew_watch: Mutex::new(super::heartbeat::ClockSkewWatch::default()),
            relay_reconnect: Mutex::new(None),
            relay_connected: Mutex::new(None),
            last_relay_rescue_at: Mutex::new(None),
            offline: std::sync::atomic::AtomicBool::new(false),
            conn_trace_tx,
            conn_trace_force_on,
        });
        Ok((state, signaling_inbound_rx, cmd_rx))
    }

    pub(crate) fn peer_connection_resource_scope(
        &self,
    ) -> crate::resource::PeerConnectionResourceScope {
        self.resource_scope.peer_connection_scope()
    }

    /// Read observations for this live joined network instance.
    pub fn resource_report(&self) -> ResourceReport {
        self.resource_scope.report()
    }

    /// Take the outbound signaling receiver so the signaling task
    /// can drain it. Only one consumer is supported; subsequent
    /// calls return `None`.
    pub fn take_signaling_outbound_rx(
        self: &Arc<Self>,
    ) -> Option<mpsc::UnboundedReceiver<SignalingOutbound>> {
        self.signaling_outbound_rx.lock().take()
    }

    /// Remember that we owe `device_id` a fresh offer after a recoverable
    /// drop, so the engine self-drives the reconnect instead of waiting for
    /// the peer's slow steady-state announce. The *first* drop opens the
    /// grace window; subsequent drops while the intent is still live (a failed
    /// rebuild that never opened a channel) deliberately do NOT extend it, so
    /// a peer that never comes back ages out at the grace instead of spinning
    /// forever. A genuine reconnect clears the intent
    /// ([`clear_reconnect_intent`](Self::clear_reconnect_intent) on
    /// `DataChannelOpen`), so the next loss opens a fresh window.
    pub fn record_reconnect_intent(&self, device_id: &str, sticky: bool) {
        let now = std::time::Instant::now();
        let mut map = self.reconnect_intents.lock();
        let intent = map.entry(device_id.to_string()).or_insert(ReconnectIntent {
            give_up_at: now + std::time::Duration::from_millis(RECONNECTING_GRACE_MS),
            next_retry_at: now,
            attempt: 0,
            sticky,
        });
        // A pin arriving while a plain intent is mid-backoff upgrades it —
        // stickiness must not be lost to entry order.
        intent.sticky = intent.sticky || sticky;
    }

    /// Forget a reconnect intent — the link is back (or the peer was
    /// explicitly removed). Cheap no-op if none was held.
    pub fn clear_reconnect_intent(&self, device_id: &str) {
        self.reconnect_intents.lock().remove(device_id);
    }

    /// Whether we're currently holding a reconnect intent for this peer.
    pub fn has_reconnect_intent(&self, device_id: &str) -> bool {
        self.reconnect_intents.lock().contains_key(device_id)
    }

    /// Intent ids whose backoff is due now. Drops expired intents (past the
    /// reconnecting grace) and advances the backoff of the ones returned, so
    /// the state-watch tick re-offers each at most once per backoff step.
    pub fn due_reconnect_intents(&self) -> Vec<String> {
        let now = std::time::Instant::now();
        let mut map = self.reconnect_intents.lock();
        map.retain(|_, i| i.sticky || now < i.give_up_at);
        let mut due = Vec::new();
        for (id, intent) in map.iter_mut() {
            if now < intent.next_retry_at {
                continue;
            }
            // A sticky intent past its active schedule parks: the entry
            // stays (so the peer's next announce dials immediately) but
            // the tick stops issuing blind offers into the void.
            if intent.sticky && intent.attempt >= RECONNECT_RETRY_BACKOFF_MS.len() + 2 {
                continue;
            }
            due.push(id.clone());
            advance_backoff(intent, now);
        }
        due
    }

    /// All live intent ids, with their backoff advanced. Used when a strong
    /// event — a relay reconnect after a network shift — makes it worth
    /// re-offering everything we owe at once, rather than waiting for each
    /// one's backoff to come due on the tick.
    pub fn flush_reconnect_intents(&self) -> Vec<String> {
        let now = std::time::Instant::now();
        let mut map = self.reconnect_intents.lock();
        map.retain(|_, i| i.sticky || now < i.give_up_at);
        for intent in map.values_mut() {
            advance_backoff(intent, now);
        }
        map.keys().cloned().collect()
    }

    /// Register the signaling driver's force-reconnect signal. Called
    /// once when the Nostr driver is attached.
    pub fn set_relay_reconnect(&self, signal: Arc<watch::Sender<u64>>) {
        *self.relay_reconnect.lock() = Some(signal);
    }

    /// Register the signaling driver's relay-connected signal (its
    /// `relay_connected` generation). Called once when the Nostr driver is
    /// attached, alongside [`set_relay_reconnect`].
    pub fn set_relay_connected_signal(&self, signal: Arc<watch::Sender<u64>>) {
        *self.relay_connected.lock() = Some(signal);
    }

    /// A receiver for the relay-connected generation, or `None` when no
    /// driver is attached (tests, the in-process broker). Callers
    /// `borrow_and_update()` to set a baseline, then `changed()` to wait for
    /// the next fresh relay session.
    pub fn relay_connected_rx(&self) -> Option<watch::Receiver<u64>> {
        self.relay_connected.lock().as_ref().map(|s| s.subscribe())
    }

    /// Ask every relay to drop its socket and redial immediately,
    /// skipping the backoff. Returns `true` if a driver was attached
    /// to receive the request. Used on resume-from-sleep so the node
    /// stops being invisible the moment it wakes instead of waiting
    /// for a stale socket to time out. Cheap and idempotent — bumps a
    /// `watch` generation the relay tasks observe.
    pub fn request_relay_reconnect(&self) -> bool {
        match self.relay_reconnect.lock().as_ref() {
            Some(signal) => {
                signal.send_modify(|gen| *gen = gen.wrapping_add(1));
                true
            }
            None => false,
        }
    }

    /// Like [`request_relay_reconnect`], but throttled to at most one
    /// redial per [`RELAY_RESCUE_MIN_INTERVAL_MS`]. This is the rescue
    /// path for the "ICE timed out with zero remote candidates"
    /// fingerprint — the peer's candidates never crossed the relay, which
    /// is almost always a relay socket that went stale after a network
    /// blip (held open for minutes because the kernel never saw a
    /// FIN/RST). Unlike the bare redial, this fires *even when other peers
    /// are still up*: a wedged relay socket starves candidate delivery for
    /// every peer, not just one, so gating on "no other live peer" (the
    /// old behavior) left the wedge in place whenever the room wasn't
    /// completely dark. The throttle is what makes that safe — a peer
    /// stuck re-timing-out every `ICE_CHECKING_TIMEOUT_MS` can still only
    /// bounce the relays once per window.
    ///
    /// Returns `true` when a redial was actually issued (driver attached
    /// *and* past the throttle), `false` when suppressed — callers log the
    /// distinction so the rescue's decisions are visible in diagnostics.
    pub fn request_relay_reconnect_throttled(&self) -> bool {
        let now = std::time::Instant::now();
        {
            let mut guard = self.last_relay_rescue_at.lock();
            let due = guard
                .map(|prev| {
                    now.duration_since(prev)
                        >= std::time::Duration::from_millis(RELAY_RESCUE_MIN_INTERVAL_MS)
                })
                .unwrap_or(true);
            if !due {
                return false;
            }
            *guard = Some(now);
        }
        self.request_relay_reconnect()
    }

    /// Record whether the host currently has any primary outbound IP.
    /// Called by the network watcher each time the snapshot changes.
    /// Returns the previous value so the caller can detect the
    /// online→offline / offline→online edges.
    pub fn set_offline(&self, offline: bool) -> bool {
        self.offline
            .swap(offline, std::sync::atomic::Ordering::Relaxed)
    }

    /// True while the host has no primary outbound IP. The ICE
    /// machinery checks this to avoid re-gathering or dropping peers
    /// during a brief network outage (see `set_offline`).
    pub fn is_offline(&self) -> bool {
        self.offline.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Emit a top-level mesh event. Silently drops if no
    /// subscribers — the broadcast channel returns an error on
    /// every send-with-zero-listeners, and we'd rather log nothing
    /// than spam on every emit.
    pub fn emit(&self, event: MeshEvent) {
        let _ = self.events_tx.send(event);
    }

    /// Subscribe to this network's connection-state transition trace.
    /// The control socket's `trace_subscribe` op hands the receiver to
    /// a `ctl trace` client; subscribing is also what flips
    /// [`conn_trace_enabled`](Self::conn_trace_enabled) on, so the
    /// driver's sweep starts emitting.
    pub fn subscribe_conn_trace(&self) -> broadcast::Receiver<ConnTrace> {
        self.conn_trace_tx.subscribe()
    }

    /// Whether the connection tracer should do any work this sweep.
    /// True when forced on via `MYOWNMESH_CONN_TRACE`, or when at least
    /// one subscriber is attached. The driver loop checks this first so
    /// the production path with no observer pays only one atomic load.
    pub fn conn_trace_enabled(&self) -> bool {
        self.conn_trace_force_on || self.conn_trace_tx.receiver_count() > 0
    }

    /// Emit one connection-state trace record. Lossy like
    /// [`emit`](Self::emit) — drops if there is no subscriber.
    pub fn emit_conn_trace(&self, trace: ConnTrace) {
        let _ = self.conn_trace_tx.send(trace);
    }

    /// Emit a structured diagnostic — both to the tracing layer
    /// (visible in daemon stderr) and to the broadcast channel as
    /// a [`MeshEvent::Diag`] (consumed by the GUI's Activity tab).
    /// Prefer this over a bare `tracing::info!`/`warn!` for events
    /// the user should see in the UI; the helper writes to both
    /// surfaces so operators reading logs and users watching the
    /// GUI stay in sync.
    pub fn log_diag(&self, level: DiagLevel, category: &str, message: impl Into<String>) {
        self.log_diag_with(level, category, message, serde_json::Value::Null);
    }

    /// Variant of [`log_diag`] that carries a structured `detail`
    /// payload alongside the message. Use for events where the GUI
    /// might want to drill into fields (peer id, error code, etc.)
    /// rather than just render the human-readable line.
    pub fn log_diag_with(
        &self,
        level: DiagLevel,
        category: &str,
        message: impl Into<String>,
        detail: serde_json::Value,
    ) {
        let message = message.into();
        // Console line reads "category: message" — clean, demo-like, no
        // field-suffix clutter. The structured network_id + category still
        // ride the MeshEvent::Diag below for the GUI; only the console
        // rendering is simplified.
        match level {
            DiagLevel::Debug => tracing::debug!("{category}: {message}"),
            DiagLevel::Info => tracing::info!("{category}: {message}"),
            DiagLevel::Warn => tracing::warn!("{category}: {message}"),
            DiagLevel::Error => tracing::error!("{category}: {message}"),
        }
        self.emit(MeshEvent::Diag(DiagEntry {
            ts: now_unix_ms(),
            network_id: self.network_id.clone(),
            level,
            category: category.to_string(),
            message,
            detail,
        }));
    }

    /// Update the per-network phase and emit on change.
    pub fn set_phase(&self, next: MeshPhase) {
        let mut current = self.current_phase.write();
        let prev = *current;
        if prev == next {
            return;
        }
        *current = next;
        drop(current);
        self.emit(MeshEvent::Phase(PhaseEvent::Changed {
            network_id: self.network_id.clone(),
            prev,
            next,
        }));
        self.log_diag(DiagLevel::Info, "phase", format!("{prev:?} → {next:?}"));
    }

    /// Subscribe to a named user channel. Returns a fresh
    /// broadcast::Receiver every call; the engine fan-outs each
    /// inbound channel frame to all subscribers.
    pub fn subscribe_channel(&self, name: &str) -> broadcast::Receiver<RawChannelFrame> {
        if let Some(tx) = self.channel_subscribers.get(name) {
            tx.subscribe()
        } else {
            let (tx, rx) = broadcast::channel(256);
            self.channel_subscribers.insert(name.to_string(), tx);
            rx
        }
    }

    /// Engine-side dispatch: route an inbound channel frame to
    /// the matching subscribers. Silently drops when no
    /// subscribers are registered for the named channel.
    pub fn dispatch_channel_frame(&self, name: &str, from: &str, payload: serde_json::Value) {
        if let Some(tx) = self.channel_subscribers.get(name) {
            let frame = RawChannelFrame {
                from: from.to_string(),
                payload,
            };
            let _ = tx.send(frame);
        } else {
            trace!(channel = name, "no subscriber for channel frame");
        }
    }

    /// Subscribe to assembled video access units from every peer on
    /// this network (filter by [`InboundVideoSample::from`]). Lagging
    /// loses old frames, never delays new ones — video is freshness.
    #[deprecated(since = "0.3.2", note = "temporary legacy H.264 compatibility facade")]
    #[cfg(feature = "legacy-media")]
    pub fn subscribe_video(&self) -> broadcast::Receiver<InboundVideoSample> {
        self.video_subscribers.subscribe()
    }

    /// Engine-side dispatch: fan an assembled access unit out to the
    /// video subscribers. Silently drops with none registered.
    pub(crate) fn dispatch_video(&self, from: &str, sample: VideoSample) {
        let _ = self.video_subscribers.send(InboundVideoSample {
            from: from.to_string(),
            sample,
        });
    }

    /// Write one encoded H.264 access unit (Annex-B) onto the video
    /// lane to `peer`. `duration` paces the RTP clock (1/fps). Errors
    /// when the peer is unknown or its session isn't established;
    /// writes on a lane the peer never consumes are simply discarded
    /// by the far side.
    #[deprecated(since = "0.3.2", note = "temporary legacy H.264 compatibility facade")]
    #[cfg(feature = "legacy-media")]
    pub async fn send_video_sample(
        &self,
        peer: &str,
        lane: u8,
        data: bytes::Bytes,
        duration: std::time::Duration,
    ) -> Result<()> {
        self.admitted_realtime_operation(peer)?
            .send_video(lane, data, duration)
            .await
    }

    /// Subscribe to audio frames from every peer on this network
    /// (filter by [`InboundAudioSample::from`]). Lagging loses old
    /// frames, never delays new ones — live audio is freshness too.
    #[deprecated(since = "0.3.2", note = "temporary legacy Opus compatibility facade")]
    #[cfg(feature = "legacy-media")]
    pub fn subscribe_audio(&self) -> broadcast::Receiver<InboundAudioSample> {
        self.audio_subscribers.subscribe()
    }

    /// Engine-side dispatch: fan an audio frame out to the audio
    /// subscribers. Silently drops with none registered.
    pub(crate) fn dispatch_audio(&self, from: &str, sample: AudioSample) {
        let _ = self.audio_subscribers.send(InboundAudioSample {
            from: from.to_string(),
            sample,
        });
    }

    /// Write one encoded Opus frame onto the audio lane to `peer`.
    /// `duration` is the frame length (20 ms canonically) — it paces
    /// the RTP clock. Same contract as [`Self::send_video_sample`].
    #[deprecated(since = "0.3.2", note = "temporary legacy Opus compatibility facade")]
    #[cfg(feature = "legacy-media")]
    pub async fn send_audio_sample(
        &self,
        peer: &str,
        lane: u8,
        data: bytes::Bytes,
        duration: std::time::Duration,
    ) -> Result<()> {
        self.admitted_realtime_operation(peer)?
            .send_audio(lane, data, duration)
            .await
    }

    /// Resolve one admitted real-time operation for `peer` through the fence.
    ///
    /// One owner resolution, then the admission fence, then an owned wrapper
    /// that keeps the worker and the flow capability paired across the await.
    #[cfg(feature = "legacy-media")]
    fn admitted_realtime_operation(&self, peer: &str) -> Result<AdmittedRealtimeOperation> {
        let owner = self
            .peers
            .owner(peer)
            .ok_or_else(|| Error::Network(format!("peer not found: {peer}")))?;
        self.peers
            .with_admitted_current(&owner, |admitted| admitted.realtime_operation())
            .flatten()
            .ok_or_else(|| Error::Transport("authenticated real-time flow not admitted".into()))
    }

    /// Send a channel frame to one peer via the command queue.
    /// Used by [`crate::Channel::send_to`].
    pub async fn send_channel_frame(
        &self,
        peer: &str,
        channel: &str,
        payload: serde_json::Value,
    ) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(NetworkCmd::SendChannelFrame {
                peer: peer.to_string(),
                channel: channel.to_string(),
                payload,
                reply,
            })
            .map_err(|_| Error::Network("engine command queue closed".into()))?;
        rx.await
            .map_err(|_| Error::Network("engine dropped reply".into()))?
    }

    /// Broadcast a channel frame to every active peer. Returns
    /// the count of peers it was dispatched to.
    pub async fn broadcast_channel_frame(
        &self,
        channel: &str,
        payload: serde_json::Value,
    ) -> usize {
        let (reply, rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(NetworkCmd::BroadcastChannelFrame {
                channel: channel.to_string(),
                payload,
                reply,
            })
            .is_err()
        {
            return 0;
        }
        rx.await.unwrap_or(0)
    }

    /// Send an RPC request to one peer. Lower-level than the
    /// `Rpc` facade; `Rpc::call` builds the request, registers
    /// the pending entry, and then calls this.
    pub async fn send_rpc_request(&self, peer: &str, request: RpcRequestMessage) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(NetworkCmd::SendRpcRequest {
                peer: peer.to_string(),
                request,
                reply,
            })
            .map_err(|_| Error::Network("engine command queue closed".into()))?;
        rx.await
            .map_err(|_| Error::Network("engine dropped reply".into()))?
    }

    /// Broadcast a capabilities update to every active peer.
    pub async fn broadcast_capabilities(&self, caps: CapabilityAdvert) -> usize {
        let (reply, rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(NetworkCmd::BroadcastCapabilities { caps, reply })
            .is_err()
        {
            return 0;
        }
        rx.await.unwrap_or(0)
    }

    /// Persist `device_id` into the per-network roster. Does NOT
    /// transition any active session — call
    /// [`crate::engine::handshake::send_local_approve`] (or the
    /// higher-level [`crate::JoinedNetwork::roster_approve`])
    /// to actually emit the `approve` frame.
    pub async fn approve_roster(&self, device_id: &str, label: &str) -> Result<()> {
        self.approve_roster_now(device_id, label)
    }

    /// Synchronous roster commit used by an already-serialized runtime owner.
    ///
    /// The public compatibility operation remains async, but the underlying
    /// roster mutation and file replacement contain no await point. Arc 03
    /// uses this form while holding the exact peer-installation fence so a
    /// replacement cannot land between owner validation and persistence.
    pub(super) fn approve_roster_now(&self, device_id: &str, label: &str) -> Result<()> {
        // Defense in depth behind the handshake's eviction gate: on a
        // closed network a device the signed state evicted can't be
        // rostered by ANY path — not mutual-ACTIVE persistence, not a
        // manual approve from a stale UI. Re-admission is a signed member
        // grant (the owner re-claiming it), which flips the verdict first.
        {
            let gov = self.governance_state.read();
            if !gov.kind.is_open_governance() {
                let pubkey = crate::signing::pubkey_part(device_id).to_string();
                let evicted = !matches!(
                    gov.roles.get(&pubkey),
                    Some(crate::network_state::Role::Owner)
                        | Some(crate::network_state::Role::Controller)
                ) && crate::network_state::member_log_removed(
                    &gov,
                    &gov.member_log,
                    &self.network_id,
                )
                .contains(&pubkey);
                if evicted {
                    return Err(Error::Network(
                        "this device was evicted by the network's signed governance — \
                         re-admit it by signing it back in (re-claim), not by approving"
                            .into(),
                    ));
                }
            }
        }
        let mut roster = self.roster.write();
        crate::roster::add_peer_in(&mut roster, device_id, label);
        crate::roster::save(&roster)?;
        Ok(())
    }

    /// Remove a peer from the roster and tear down any session.
    pub async fn remove_roster(&self, device_id: &str) -> Result<()> {
        let mut roster = self.roster.write();
        crate::roster::remove_peer_in(&mut roster, device_id);
        crate::roster::save(&roster)?;
        Ok(())
    }

    /// True if the peer is currently in the roster.
    pub fn is_rostered(&self, device_id: &str) -> bool {
        crate::roster::is_authorized(&self.roster.read(), device_id)
    }

    /// Total count of peers in any state.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Snapshot the current per-peer view as an owned list. The
    /// engine drops behind the lock during this call; callers
    /// should treat the snapshot as instantaneous and re-fetch
    /// for fresh data.
    pub fn peer_snapshot(&self) -> Vec<crate::handle::PeerInfo> {
        self.peers.collect_map(|peer| {
            let device_id = peer.device_id.clone();
            let data = peer.snapshot();
            let pubkey = crate::signing::pubkey_part(&device_id);
            let device_suffix = crate::identity::display_suffix(pubkey.as_bytes());
            Some(crate::handle::PeerInfo {
                device_id: device_id.clone(),
                status: data.status,
                tier: data.tier,
                rtt_ms: data.rtt_ms,
                clock_skew_ms: data.clock_skew_ms,
                label: data.label,
                capabilities: data.capabilities,
                local_shelved: data.local_shelved,
                remote_shelved: data.remote_shelved,
                authenticated: data.authenticated,
                device_suffix,
                verification_code_received: data.verification_code_received,
                verification_code_sent: data.verification_code_sent,
                local_approve_sent: data.local_approve_sent,
                remote_approve_seen: data.remote_approve_seen,
                needs_turn: data.needs_turn,
                local_candidates: data.diag.local_candidates,
                remote_candidates: data.diag.remote_candidates,
                selected_pair: data.selected_pair,
            })
        })
    }

    /// Per-peer detail. Returns `None` if the peer is not in the
    /// engine's map.
    pub fn peer_info(&self, device_id: &str) -> Option<crate::handle::PeerInfo> {
        let peer = self.peers.get(device_id)?;
        let data = peer.snapshot();
        let pubkey = crate::signing::pubkey_part(device_id);
        let device_suffix = crate::identity::display_suffix(pubkey.as_bytes());
        Some(crate::handle::PeerInfo {
            device_id: device_id.to_string(),
            status: data.status,
            tier: data.tier,
            rtt_ms: data.rtt_ms,
            clock_skew_ms: data.clock_skew_ms,
            label: data.label,
            capabilities: data.capabilities,
            local_shelved: data.local_shelved,
            remote_shelved: data.remote_shelved,
            authenticated: data.authenticated,
            device_suffix,
            verification_code_received: data.verification_code_received,
            verification_code_sent: data.verification_code_sent,
            local_approve_sent: data.local_approve_sent,
            remote_approve_seen: data.remote_approve_seen,
            needs_turn: data.needs_turn,
            local_candidates: data.diag.local_candidates,
            remote_candidates: data.diag.remote_candidates,
            selected_pair: data.selected_pair,
        })
    }

    /// Tear down every active peer session. Called from the
    /// driver's shutdown path.
    pub(crate) async fn shutdown(&self) {
        let retired = self.peers.retire_all();
        for peer in &retired {
            if let Err(error) = peer.retire_and_close().await {
                tracing::warn!(%error, peer = %peer.device_id, "peer cleanup failed during shutdown");
            }
        }
        drop(retired);
        // Nothing outlives the engine: parked connect waits and queued
        // reliable sends resolve with the truth instead of hanging.
        let waiting: Vec<String> = self.connect_waiters.lock().keys().cloned().collect();
        for peer in waiting {
            self.resolve_connect_waiters(&peer, Some("network shut down"));
        }
        let queued: Vec<String> = self.reliable_out.lock().keys().cloned().collect();
        for peer in queued {
            super::reliable::fail_peer(self, &peer, "network shut down");
        }
    }

    /// Broadcast a graceful departure so peers drop our session immediately
    /// rather than waiting out the ~90 s heartbeat timeout. Fire-and-forget,
    /// like every other signaling publish: the message is handed to the
    /// signaling driver and rides the relays best-effort. Callers tearing
    /// the network down (see [`crate::JoinedNetwork::announce_leave`]) should
    /// emit this *before* dropping the signaling driver and give it a brief
    /// moment to reach the relays.
    pub fn announce_departure(&self) {
        let _ = self.signaling_tx.send(SignalingOutbound::Leave);
    }

    /// Queue an in-place reconnect on the engine driver — redial signaling and
    /// renegotiate ICE without leaving the room. `peer == None` reconnects
    /// every peer on this network; `peer == Some(id)` reconnects just that one.
    /// The non-destructive twin of [`Self::announce_departure`] + rejoin: no
    /// `Leave` is announced and no session is torn down, so peers keep their
    /// connections and app-level state. The actual work runs on the driver via
    /// [`NetworkCmd::Reconnect`] so it's serialized with every other per-peer
    /// mutation. See [`super::network_watch::reconnect_all_in_place`].
    pub fn reconnect(&self, peer: Option<String>) {
        let _ = self.cmd_tx.send(NetworkCmd::Reconnect { peer });
    }

    /// Queue a deliberate offerer-side dial of exactly one peer on the engine
    /// driver. The manual-connect primitive a `Silent` network needs: on a
    /// Silent mesh the engine never auto-dials on presence, so a session is
    /// opened only here (or by answering an inbound offer). Fire-and-forget,
    /// like [`Self::reconnect`]; the work runs on the driver via
    /// [`NetworkCmd::ConnectPeer`]. Backs [`crate::JoinedNetwork::connect_peer`].
    pub fn connect_peer(&self, device_id: &str) {
        let _ = self.cmd_tx.send(NetworkCmd::ConnectPeer {
            device_id: device_id.to_string(),
            sticky: false,
            reply: None,
        });
    }

    /// Deliberately dial one peer and resolve when the link reaches
    /// ACTIVE (or fail with the terminal reason). `sticky` records a
    /// standing dial: the engine re-dials on every announce and holds a
    /// never-expiring reconnect intent — the "support session" contract
    /// on a Silent network. The returned future is bounded only by the
    /// caller's own timeout.
    pub async fn connect_peer_wait(&self, device_id: &str, sticky: bool) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(NetworkCmd::ConnectPeer {
                device_id: device_id.to_string(),
                sticky,
                reply: Some(reply),
            })
            .map_err(|_| Error::Network("engine command queue closed".into()))?;
        rx.await
            .map_err(|_| Error::Network("engine dropped the connect wait".into()))?
    }

    /// Queue a frame for acknowledged delivery to `peer` — see
    /// [`NetworkCmd::SendChannelReliable`] for the contract. Resolves on
    /// the peer's ack; errs on TTL expiry, outbox backpressure, or
    /// terminal peer failure.
    pub async fn send_channel_reliable(
        &self,
        peer: &str,
        channel: &str,
        payload: serde_json::Value,
        ttl_ms: Option<u64>,
    ) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(NetworkCmd::SendChannelReliable {
                peer: peer.to_string(),
                channel: channel.to_string(),
                payload,
                ttl_ms,
                reply,
            })
            .map_err(|_| Error::Network("engine command queue closed".into()))?;
        rx.await
            .map_err(|_| Error::Network("engine dropped the reliable send".into()))?
    }

    /// Point-in-time traffic accounting for this network, with the
    /// acked-delivery backlog folded in — the number an operator (or a
    /// topology experiment) compares across configurations.
    pub fn traffic_snapshot(&self) -> super::traffic::TrafficSnapshot {
        let mut snap = self.traffic.snapshot();
        snap.reliable_pending = super::reliable::pending_total(self) as u64;
        snap
    }

    /// Open the lowest free media lane of `kind` toward `peer`.
    #[cfg(feature = "legacy-media")]
    pub(crate) async fn media_lane_open(
        &self,
        peer: &str,
        kind: crate::transport::webrtc::LaneKind,
    ) -> Result<u8> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(NetworkCmd::MediaLaneOpen {
                peer: peer.to_string(),
                kind,
                reply,
            })
            .map_err(|_| Error::Network("engine command queue closed".into()))?;
        rx.await
            .map_err(|_| Error::Network("engine dropped the lane open".into()))?
    }

    /// Close a media lane toward `peer` (idempotent).
    #[cfg(feature = "legacy-media")]
    pub(crate) async fn media_lane_close(
        &self,
        peer: &str,
        kind: crate::transport::webrtc::LaneKind,
        lane: u8,
    ) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(NetworkCmd::MediaLaneClose {
                peer: peer.to_string(),
                kind,
                lane,
                reply,
            })
            .map_err(|_| Error::Network("engine command queue closed".into()))?;
        rx.await
            .map_err(|_| Error::Network("engine dropped the lane close".into()))?
    }

    #[cfg(feature = "legacy-media")]
    #[allow(
        deprecated,
        reason = "this exact method is the temporary legacy media finalization boundary"
    )]
    pub(crate) async fn media_lanes_finalize(&self, peer: &str) -> Result<usize> {
        // The pending flag is written through the captured peer inside the
        // operation, so a replacement installed during the finalize await
        // cannot inherit it.
        Ok(self
            .admitted_realtime_operation(peer)?
            .finalize_suspended_lanes()
            .await)
    }

    /// Whether `device_id` has a standing dial (config pin or runtime
    /// `connect_peer(…, sticky)`).
    pub fn is_sticky(&self, device_id: &str) -> bool {
        self.sticky_peers.lock().contains(device_id)
    }

    /// Record a standing dial for `device_id`, mirrored into the live
    /// config's `pinned_peers` so a config read-back (and the daemon's
    /// persistence of it) carries the pin across restarts.
    pub fn add_sticky(&self, device_id: &str) {
        self.sticky_peers.lock().insert(device_id.to_string());
        let mut cfg = self.config.write();
        if !cfg.pinned_peers.iter().any(|p| p == device_id) {
            cfg.pinned_peers.push(device_id.to_string());
        }
    }

    /// Drop a standing dial (and its never-expiring intent), e.g. when
    /// the app "forgets" the peer.
    pub fn remove_sticky(&self, device_id: &str) {
        self.sticky_peers.lock().remove(device_id);
        self.config.write().pinned_peers.retain(|p| p != device_id);
        self.reconnect_intents.lock().remove(device_id);
    }

    /// Park a waiter to be resolved when `device_id` reaches ACTIVE.
    pub(crate) fn register_connect_waiter(
        &self,
        device_id: &str,
        reply: oneshot::Sender<Result<()>>,
    ) {
        self.connect_waiters
            .lock()
            .entry(device_id.to_string())
            .or_default()
            .push(reply);
    }

    /// Resolve every waiter parked on `device_id`. `error == None`
    /// resolves Ok; otherwise each waiter gets the reason.
    pub(crate) fn resolve_connect_waiters(&self, device_id: &str, error: Option<&str>) {
        let waiters = self.connect_waiters.lock().remove(device_id);
        let Some(waiters) = waiters else { return };
        for w in waiters {
            let result = match error {
                None => Ok(()),
                Some(e) => Err(Error::Network(format!("connect {device_id}: {e}"))),
            };
            let _ = w.send(result);
        }
    }

    /// True when this network's governance kind is `Silent`. The load-bearing
    /// predicate for the two Silent behaviours: the engine suppresses
    /// auto-dial-on-presence (see `handle_signaling_inbound`) and roster
    /// gossip (see [`super::governance::broadcast_roster_summary`]). Read off
    /// the authoritative signed-state kind, which is seeded from
    /// `NetworkConfig.kind` at attach.
    pub fn is_silent(&self) -> bool {
        matches!(
            self.governance_state.read().kind,
            crate::network_state::NetworkKind::Silent
        )
    }

    /// Whether this network gossips its roster (the membership summary /
    /// entries anti-entropy). True everywhere except `Silent` networks, on
    /// which membership is never advertised — every connection is deliberate,
    /// so there is nothing to converge. Presence (`Sighted`) and the per-peer
    /// handshake are unaffected; only the roster gossip is suppressed.
    pub fn gossip_roster_enabled(&self) -> bool {
        !self.is_silent()
    }
}

/// Unix epoch milliseconds. Stamped on every [`DiagEntry`] so the
/// GUI's Activity log can render a per-entry HH:MM:SS clock — wall
/// time, not monotonic: the user cares what time it actually was
/// when something happened, not how long after process start.
pub(crate) fn now_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod arc03_peer_registry_tests {
    use super::*;
    use crate::engine::connection::PeerStatus;
    use std::hint::black_box;
    use std::time::{Duration, Instant};

    #[test]
    fn v4_arc03_registry_scan_releases_map_guard_before_peer_callback() {
        let registry = Arc::new(PeerRegistry::default());
        assert!(registry
            .install(Arc::new(PeerConnection::new(
                "arc03-lock-order-peer".to_string(),
                None,
            )))
            .is_none());
        let scan = Arc::clone(&registry);
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
            let _: Vec<()> = scan.collect_map(|_| {
                assert!(scan
                    .install(Arc::new(PeerConnection::new(
                        "arc03-lock-order-peer".to_string(),
                        None,
                    )))
                    .is_some());
                None
            });
            let _ = finished_tx.send(());
        });

        finished_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("peer callback must run after every DashMap guard is released");
    }

    #[test]
    fn v4_arc03_stale_owner_cannot_remove_replacement_peer() {
        let registry = PeerRegistry::default();
        assert!(registry
            .install(Arc::new(PeerConnection::new(
                "arc03-owner-peer".to_string(),
                None,
            )))
            .is_none());
        let stale_owner = registry
            .owner("arc03-owner-peer")
            .expect("first owner is installed");
        assert!(registry
            .install(Arc::new(PeerConnection::new(
                "arc03-owner-peer".to_string(),
                None,
            )))
            .is_some());
        let replacement = registry
            .owner("arc03-owner-peer")
            .expect("replacement owner is installed");

        assert!(registry.remove_if_current(&stale_owner).is_none());
        assert!(registry.get_if_current(&stale_owner).is_none());
        assert!(registry.get_if_current(&replacement).is_some());
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn v4_arc03_current_effect_linearizes_before_replacement() {
        let registry = Arc::new(PeerRegistry::default());
        let first = Arc::new(PeerConnection::new("arc03-effect-owner".to_string(), None));
        assert!(registry.install(Arc::clone(&first)).is_none());
        let owner = registry
            .owner("arc03-effect-owner")
            .expect("first installation has an owner stamp");
        let (effect_entered_tx, effect_entered_rx) = std::sync::mpsc::channel();
        let (release_effect_tx, release_effect_rx) = std::sync::mpsc::channel();
        let effect_registry = Arc::clone(&registry);
        let effect = std::thread::spawn(move || {
            effect_registry.with_current(&owner, |peer| {
                effect_entered_tx
                    .send(())
                    .expect("test observes the exact-owner effect");
                release_effect_rx
                    .recv()
                    .expect("test releases the exact-owner effect");
                peer.state.write().data_channel_open = true;
            })
        });
        effect_entered_rx
            .recv()
            .expect("exact-owner effect holds the registry transition");

        let replacement_registry = Arc::clone(&registry);
        let (replacement_done_tx, replacement_done_rx) = std::sync::mpsc::channel();
        let replacement = std::thread::spawn(move || {
            let replaced = replacement_registry.install(Arc::new(PeerConnection::new(
                "arc03-effect-owner".to_string(),
                None,
            )));
            replacement_done_tx
                .send(replaced.is_some())
                .expect("replacement reports completion");
        });
        assert!(
            replacement_done_rx.try_recv().is_err(),
            "replacement cannot pass an in-progress exact-owner effect"
        );

        release_effect_tx
            .send(())
            .expect("release the exact-owner effect");
        assert!(effect.join().expect("effect thread joins").is_some());
        assert!(replacement_done_rx
            .recv()
            .expect("replacement completes after the effect"));
        replacement.join().expect("replacement thread joins");

        assert!(first.state.read().data_channel_open);
        assert!(
            !registry
                .get("arc03-effect-owner")
                .expect("replacement remains installed")
                .state
                .read()
                .data_channel_open
        );
    }

    #[test]
    fn v4_arc03_retired_peer_arc_cannot_be_reinstalled() {
        let registry = PeerRegistry::default();
        let peer = Arc::new(PeerConnection::new(
            "arc03-reinstalled-owner".to_string(),
            None,
        ));
        assert!(registry.install(Arc::clone(&peer)).is_none());
        let stale_owner = registry
            .owner("arc03-reinstalled-owner")
            .expect("first installation has an owner stamp");
        assert!(registry.remove("arc03-reinstalled-owner").is_some());
        assert!(registry.install(peer).is_none());

        assert!(registry.get_if_current(&stale_owner).is_none());
        assert!(registry.remove_if_current(&stale_owner).is_none());
        assert!(registry.is_empty());
    }

    #[test]
    fn v4_arc03_installing_current_peer_arc_is_idempotent() {
        let registry = PeerRegistry::default();
        let peer = Arc::new(PeerConnection::new(
            "arc03-idempotent-owner".to_string(),
            None,
        ));
        assert!(registry.install(Arc::clone(&peer)).is_none());
        let owner = registry
            .owner("arc03-idempotent-owner")
            .expect("first installation has an owner stamp");

        assert!(registry.install(peer).is_none());
        assert!(registry.get_if_current(&owner).is_some());
        assert_eq!(registry.len(), 1);
    }

    fn scan_counts() -> Vec<usize> {
        std::env::var("MYOWNMESH_ARC03_PEER_SCAN_COUNTS")
            .expect("set MYOWNMESH_ARC03_PEER_SCAN_COUNTS to comma-separated sample counts")
            .split(',')
            .map(|value| {
                value
                    .trim()
                    .parse::<usize>()
                    .expect("every peer scan count must be a positive integer")
            })
            .inspect(|count| assert!(*count > 0, "peer scan counts must be positive"))
            .collect()
    }

    fn scan_rounds() -> usize {
        let rounds = std::env::var("MYOWNMESH_ARC03_PEER_SCAN_ROUNDS")
            .expect("set MYOWNMESH_ARC03_PEER_SCAN_ROUNDS")
            .parse::<usize>()
            .expect("peer scan rounds must be a positive integer");
        assert!(rounds > 0, "peer scan rounds must be positive");
        rounds
    }

    #[test]
    #[ignore = "manual release-mode scaling observation; requires explicit sample counts"]
    fn v4_arc03_peer_registry_scan_scaling() {
        let rounds = scan_rounds();
        for count in scan_counts() {
            let registry = PeerRegistry::default();
            for index in 0..count {
                let device_id = format!("arc03-scan-peer-{index:08}");
                let peer = Arc::new(PeerConnection::new(device_id.clone(), None));
                peer.state.write().status = PeerStatus::Active;
                assert!(registry.install(peer).is_none());
            }
            assert_eq!(registry.len(), count, "benchmark input cardinality");

            let old_started = Instant::now();
            for _ in 0..rounds {
                let snapshot: Vec<(String, Arc<PeerConnection>)> = registry
                    .peers
                    .iter()
                    .map(|entry| (entry.key().clone(), Arc::clone(&entry.value().peer)))
                    .collect();
                let active: Vec<String> = snapshot
                    .into_iter()
                    .filter(|(_, peer)| peer.state.read().status == PeerStatus::Active)
                    .map(|(key, _)| key.clone())
                    .collect();
                assert_eq!(active.len(), count, "legacy scan output cardinality");
                black_box(active);
            }
            let old_elapsed = old_started.elapsed();

            let specialized_started = Instant::now();
            for _ in 0..rounds {
                let active = registry.collect_map(|peer| {
                    (peer.state.read().status == PeerStatus::Active).then(|| peer.device_id.clone())
                });
                assert_eq!(active.len(), count, "specialized scan output cardinality");
                black_box(active);
            }
            let specialized_elapsed = specialized_started.elapsed();

            println!(
                "arc03_peer_scan count={count} rounds={rounds} legacy_total_ns={} specialized_total_ns={} legacy_ns_per_peer={:.3} specialized_ns_per_peer={:.3}",
                old_elapsed.as_nanos(),
                specialized_elapsed.as_nanos(),
                old_elapsed.as_nanos() as f64 / (count * rounds) as f64,
                specialized_elapsed.as_nanos() as f64 / (count * rounds) as f64,
            );
        }
    }
}
