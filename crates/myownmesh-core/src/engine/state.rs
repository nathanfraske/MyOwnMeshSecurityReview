//! Shared per-network state. Exposes the operations subsystems
//! (`Channel<T>`, `Rpc`, `MeshHandle`) call to interact with the
//! engine; all per-peer state mutation is funneled through the
//! command queue so the driver loop owns serial access.

use std::sync::Arc;

use crate::config::{NetworkConfig, TopologyMode};
use crate::error::{Error, Result};
use crate::events::{DiagEntry, DiagLevel, DropReason, MeshEvent, MeshPhase, PhaseEvent};
use crate::identity::Identity;
use crate::protocol::{rpc::RpcRequestMessage, CapabilityAdvert};
use crate::resource::{
    checked_measure_add, mailbox_measure_serialized, mailbox_retained_claim, strings_measure,
    LocalApplicationResourceScope, MeshRuntimeResourceScope, NetworkInstanceResourceScope,
    ResourceClaim, ResourceClaimArithmeticError, ResourceClass, ResourceLease, ResourceMailboxItem,
    ResourceMailboxItemError, ResourceMailboxReceiver, ResourceMailboxSender, ResourceReport,
};
use crate::roster::Roster;
use crate::runtime::session_broker::SessionBroker;
use crate::topology::Topology;
use crate::transport::webrtc::{
    RealtimeDirection, RealtimeFlowError, RealtimeFlowName, RealtimeFlowRemains,
    RealtimeFlowSetIdentity, RealtimeFlowSpec, RealtimeRecvUnit, RealtimeSendUnit,
    SessionRealtimeFlows,
};
use crate::transport::{LocalIceCandidate, Transport};
use parking_lot::{Mutex, RwLock};
use tokio::sync::{broadcast, oneshot, watch};
use tokio::task::JoinHandle;

use super::peer_registry::{PeerOwnerToken, PeerRegistry};
use super::signaling_ingress::EphemeralIngress;

pub(crate) type AttemptSettlement = Arc<
    dyn Fn(&str, myownmesh_signaling::nostr::delivery::DeliveryTerminal) -> usize + Send + Sync,
>;

struct RecoveryCohort {
    pending: RecoveryCohortCauseList,
    in_flight: Option<RecoveryCohortGeneration>,
    next_generation: u64,
    queued_publication: Option<RecoveryPublishId>,
    publication: Option<RecoveryPublication>,
}

/// Process-local identity for one exact recovery cohort publication.  It is
/// deliberately separate from any wire/event id: carrier copies must report
/// back to this process and stale reports must never settle a later cohort.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryPublishId {
    generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RecoveryCarrierInstance(u64);

struct RecoveryPublication {
    id: RecoveryPublishId,
    remaining: CarrierInstanceList,
}

#[derive(Default)]
struct CarrierInstanceList {
    head: Option<Box<CarrierInstanceNode>>,
}

struct CarrierInstanceNode {
    instance: RecoveryCarrierInstance,
    _lease: ResourceLease,
    next: Option<Box<CarrierInstanceNode>>,
}

impl CarrierInstanceList {
    fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    fn contains(&self, instance: RecoveryCarrierInstance) -> bool {
        let mut cursor = self.head.as_deref();
        while let Some(node) = cursor {
            if node.instance == instance {
                return true;
            }
            cursor = node.next.as_deref();
        }
        false
    }

    fn push_front(&mut self, mut node: Box<CarrierInstanceNode>) {
        node.next = self.head.take();
        self.head = Some(node);
    }

    fn pop_front(&mut self) -> Option<Box<CarrierInstanceNode>> {
        let mut node = self.head.take()?;
        self.head = node.next.take();
        Some(node)
    }

    fn remove(&mut self, instance: RecoveryCarrierInstance) -> Option<Box<CarrierInstanceNode>> {
        let mut link = &mut self.head;
        loop {
            match link {
                Some(node) if node.instance == instance => {
                    let mut removed = link.take().expect("matched carrier instance");
                    *link = removed.next.take();
                    return Some(removed);
                }
                Some(node) => link = &mut node.next,
                None => return None,
            }
        }
    }
}

impl Drop for CarrierInstanceList {
    fn drop(&mut self) {
        while self.pop_front().is_some() {}
    }
}

struct CarrierAttemptNode {
    attempt: String,
    _entry_lease: ResourceLease,
    carriers: Option<Box<CarrierAttemptCarrier>>,
    expected: usize,
    resolved: usize,
    accepted: bool,
    next: Option<Box<CarrierAttemptNode>>,
}

struct CarrierAttemptCarrier {
    instance: RecoveryCarrierInstance,
    resolved: bool,
    next: Option<Box<CarrierAttemptCarrier>>,
}

impl CarrierAttemptNode {
    fn carrier_mut(
        &mut self,
        instance: RecoveryCarrierInstance,
    ) -> Option<&mut CarrierAttemptCarrier> {
        let mut cursor = self.carriers.as_deref_mut();
        while let Some(carrier) = cursor {
            if carrier.instance == instance {
                return Some(carrier);
            }
            cursor = carrier.next.as_deref_mut();
        }
        None
    }
}

impl Drop for CarrierAttemptNode {
    fn drop(&mut self) {
        let mut cursor = self.carriers.take();
        while let Some(mut carrier) = cursor {
            cursor = carrier.next.take();
        }
    }
}

#[derive(Default)]
struct CarrierAttemptList {
    head: Option<Box<CarrierAttemptNode>>,
}

impl CarrierAttemptList {
    fn find_mut(&mut self, attempt: &str) -> Option<&mut CarrierAttemptNode> {
        let mut cursor = self.head.as_deref_mut();
        while let Some(node) = cursor {
            if node.attempt == attempt {
                return Some(node);
            }
            cursor = node.next.as_deref_mut();
        }
        None
    }

    fn push_front(&mut self, mut node: Box<CarrierAttemptNode>) {
        node.next = self.head.take();
        self.head = Some(node);
    }

    fn remove(&mut self, attempt: &str) -> Option<Box<CarrierAttemptNode>> {
        let mut link = &mut self.head;
        loop {
            if link.as_ref().is_some_and(|node| node.attempt == attempt) {
                let mut removed = link.take().expect("matched attempt node");
                *link = removed.next.take();
                return Some(removed);
            }
            match link.as_mut() {
                Some(node) => link = &mut node.next,
                None => return None,
            }
        }
    }
}

impl Drop for CarrierAttemptList {
    fn drop(&mut self) {
        while let Some(mut node) = self.head.take() {
            self.head = node.next.take();
        }
    }
}

struct RecoveryCohortGeneration {
    id: RecoveryPublishId,
    causes: RecoveryCohortCauseList,
}

struct RecoveryCohortCause {
    owner: PeerOwnerToken,
    demand: crate::runtime::peer_session::RecoveryDemandHandle,
    collection_lease: ResourceLease,
    next: Option<Box<RecoveryCohortCause>>,
}

impl RecoveryCohortCause {
    fn release(self) {
        let Self {
            owner,
            demand,
            collection_lease,
            next,
        } = self;
        drop(next);
        drop(collection_lease);
        drop(demand);
        drop(owner);
    }

    fn cancel(self) {
        let Self {
            owner,
            demand,
            collection_lease,
            next,
        } = self;
        demand.cancel();
        drop(next);
        drop(collection_lease);
        drop(demand);
        drop(owner);
    }
}

#[derive(Default)]
struct RecoveryCohortCauseList {
    head: Option<Box<RecoveryCohortCause>>,
}

impl RecoveryCohortCauseList {
    fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    fn push_front(&mut self, mut cause: Box<RecoveryCohortCause>) {
        cause.next = self.head.take();
        self.head = Some(cause);
    }

    fn pop_front(&mut self) -> Option<Box<RecoveryCohortCause>> {
        let mut cause = self.head.take()?;
        self.head = cause.next.take();
        Some(cause)
    }

    fn append(&mut self, other: &mut Self) {
        while let Some(cause) = other.pop_front() {
            self.push_front(cause);
        }
    }

    fn contains_owner(&self, owner: &PeerOwnerToken) -> bool {
        let mut cursor = self.head.as_deref();
        while let Some(cause) = cursor {
            if NetworkState::same_recovery_owner(&cause.owner, owner) {
                return true;
            }
            cursor = cause.next.as_deref();
        }
        false
    }
}

impl Drop for RecoveryCohortCauseList {
    fn drop(&mut self) {
        let mut cursor = self.head.take();
        while let Some(mut cause) = cursor {
            cursor = cause.next.take();
        }
    }
}

impl RecoveryCohort {
    fn new() -> Self {
        Self {
            pending: RecoveryCohortCauseList::default(),
            in_flight: None,
            next_generation: 0,
            queued_publication: None,
            publication: None,
        }
    }
}

/// Internal driver work for reducing one authenticated candidate.
///
/// Kept out of [`NetworkCmd`]: neither the exact worker pointer nor candidate
/// promotion is part of the public command surface.
pub(super) struct SpeculativePromotionCmd {
    pub(super) owner: PeerOwnerToken,
    pub(super) candidate: Arc<crate::transport::WebRtcConnectorWorker>,
    pub(super) correlation: String,
}

impl ResourceMailboxItem for SpeculativePromotionCmd {
    fn retained_claim(&self) -> std::result::Result<ResourceClaim, ResourceMailboxItemError> {
        let measure = strings_measure([self.correlation.as_str()])?;
        mailbox_retained_claim::<Self>(measure.0, measure.1, measure.2)
    }
}

#[cfg(test)]
pub(super) fn speculative_promotion_item_charge_for_test(correlation: &str) -> ResourceClaim {
    struct PlanningItem<'a>(&'a str);

    impl crate::resource::ResourceMailboxItemBuilder<SpeculativePromotionCmd> for PlanningItem<'_> {
        fn retained_claim(&self) -> std::result::Result<ResourceClaim, ResourceMailboxItemError> {
            let measure = strings_measure([self.0])?;
            mailbox_retained_claim::<SpeculativePromotionCmd>(measure.0, measure.1, measure.2)
        }

        fn build(self) -> SpeculativePromotionCmd {
            unreachable!("planning a fixture mailbox charge never builds the command")
        }
    }

    ResourceMailboxSender::<SpeculativePromotionCmd>::building_item_planning_charge(&PlanningItem(
        correlation,
    ))
    .expect("fixture speculative-promotion charge is representable")
}

/// See a closed flow's native half retired, whichever half it had.
///
/// A free function rather than a method, and the only place the engine waits on
/// either kind of retirement, so there is exactly one account of what closing a
/// flow costs. Two would be two things that can disagree about which half a
/// flow had.
///
/// The two arms are asymmetric because the ownership is. **Outbound** removal
/// belongs to the pump, which is the only holder of the sender and the peer
/// connection: closing the flow drops its queue, the pump wakes, removes its
/// own track and completes the lease. The engine does not remove anything here
/// — it waits for the removal to have happened. **Inbound** has no pump-side
/// owner for the transceiver, so the engine stops it directly against the
/// identity it takes out of the retirement the close handed back.
///
/// A dropped sender on the outbound lease is completion, not failure: it means
/// the pump is gone, and a pump that is gone has already run its exit. There is
/// nothing left to wait for and nothing a retry could learn, so the error is
/// discarded rather than surfaced as a close failure the caller cannot act on.
///
/// Awaits, so every caller is outside the fence before it runs. Nothing here is
/// retried, timed or generation-checked.
async fn retire_realtime_remains(
    worker: &Arc<crate::transport::WebRtcConnectorWorker>,
    remains: RealtimeFlowRemains,
) {
    match remains {
        RealtimeFlowRemains::Inbound(mut retirement) => {
            // Taken rather than dropped: this caller is going to await the
            // receipt, and the retirement must not also submit one of its own
            // behind it. Dropping it instead would still retire the
            // transceiver — it would just do it without telling anybody.
            let identity = retirement.take_for_explicit_close();
            worker.close_inbound_realtime_transceiver(&identity).await;
        }
        RealtimeFlowRemains::Outbound(completed) => {
            let _ = completed.await;
        }
        // A flow whose native half never came up, or one whose pump has already
        // taken the cleanup because the flow set was dropped rather than closed.
        RealtimeFlowRemains::None => {}
    }
}

use super::conn_trace::ConnTrace;
use super::scheduler::{
    RECONNECTING_GRACE_MS, RECONNECT_RETRY_BACKOFF_MS, RELAY_RESCUE_MIN_INTERVAL_MS,
};

/// Bookkeeping for an offerer-side reconnect intent. When we drop a peer we
/// were the *offerer* for (a recoverable `IceFailed`), we keep one of these
/// in [`NetworkState::reconnect_intents`] and event paths re-offer on a
/// backoff until the link comes back or `give_up_at` passes.
/// This is the offerer-side counterpart to an answerer recovering from the
/// remote's re-offers — without it, an offerer-role peer that drops on a
/// network shift is never re-offered (it only comes back on the peer's slow
/// steady-state announce). The backoff (`next_retry_at`/`attempt`) keeps the
/// recovery from publishing an offer on every event — one re-offer per
/// backoff step, never cadence traffic.
#[derive(Debug, Clone, Copy)]
pub struct ReconnectIntent {
    /// Stop retrying after this instant (drop time + `RECONNECTING_GRACE_MS`).
    /// A sticky intent ignores this — see [`ReconnectIntent::sticky`].
    pub give_up_at: std::time::Instant,
    /// Earliest instant for the next re-offer; advanced by the backoff each
    /// time an event services this intent.
    pub next_retry_at: std::time::Instant,
    /// Number of re-offers issued so far — indexes `RECONNECT_RETRY_BACKOFF_MS`.
    pub attempt: usize,
    /// A pinned peer's intent: never expires, and once the active backoff
    /// schedule is spent it parks (no more event-driven re-offers) and waits
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
    /// A session was just minted for this exact owner.
    ///
    /// Enqueued synchronously by the registry fence at the moment of promotion,
    /// and handled here so the work happens after every fence lock is released.
    /// It carries the exact owner rather than a device id: a replacement
    /// resolves to a different token, so a command cannot be applied to a
    /// session that did not mint it.
    ///
    /// Emitted once per session, on the call that minted it — never on reuse and
    /// never on a refusal. A promotion the provider refuses mints nothing and
    /// announces nothing; the later operation that finally promotes is the one
    /// that announces.
    ReplayCapabilities {
        owner: super::peer_registry::PeerOwnerToken,
    },
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
    /// A Nostr provider refused this exact outbound attempt before it could
    /// enter the driver's live delivery map.  The owner token is captured at
    /// refusal routing time; the command must never re-resolve by device id.
    AttemptRefused {
        owner: super::peer_registry::PeerOwnerToken,
        refusal: myownmesh_signaling::AttemptRefusal,
    },
    /// An authoritative terminal emitted by the provider-owned Nostr store.
    /// The owner token and attempt are both rechecked by the engine handler;
    /// stale outcomes are discarded and never settle a successor.
    AttemptOutcome {
        owner: super::peer_registry::PeerOwnerToken,
        outcome: myownmesh_signaling::AttemptOutcome,
    },
    /// Manually triggered in-place reconnect — the non-destructive twin of a
    /// leave-then-rejoin. `peer == None` reconnects the whole network (redial
    /// signaling + renegotiate ICE with every peer); `peer == Some(id)`
    /// reconnects just that one peer. Nothing is torn down and no `Leave` is
    /// announced, so peers keep their sessions and app-level state — this is
    /// the gentle recovery the GUI's refresh / reconnect controls drive, in
    /// place of a `NetworkRemove` + `NetworkAdd` pair. See
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
        reply: Option<ConnectWaiterRegistration>,
    },
    /// Retain a channel frame for acknowledged delivery under the peer's
    /// current session (see [`super::reliable`]), resolved on the peer's
    /// cumulative acknowledgement.
    ///
    /// Refused outright, with the reason, when the peer has no live session or
    /// when the provider will not fund retaining the frame. There is no deadline to expire against and
    /// no ceiling to be backpressured by: an entry ends when it is acknowledged
    /// or when its session does, and both are events, not guesses.
    SendChannelReliable {
        peer: String,
        channel: String,
        payload: serde_json::Value,
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
    ///
    /// Fire-and-forget, and deliberately so: it replaced a variant that carried
    /// a `oneshot::Sender<usize>` for the caller to wait on. A oneshot nobody
    /// reads is still an allocation the command retains and the mailbox funds,
    /// and `Rpc::advertise`'s documented answer is its local commit rather than
    /// how many peers the push reached — so the reply channel was charged for on
    /// every advertisement and read on none.
    ///
    /// Fire-and-forget, but not unaccounted: the resource mailbox funds the
    /// payload, its node, and the scheduled work, and the driver's own lifecycle
    /// owns the running of it. That is the difference between this and the
    /// detached task it replaces, which was scheduled work no owner had funded
    /// and no shutdown could wait for.
    FanoutCapabilities { caps: CapabilityAdvert },
    // ---- governance (closed networks) ----
    /// Float a new signed transition. The engine signs with the
    /// local identity, persists the proposal to the governance
    /// state's pending list, and broadcasts a
    /// `NetworkStatePropose` to every active peer that supports
    /// the current closed governance profile. Reply carries the new proposal id so
    /// the caller can correlate acks.
    ProposeTransition {
        variant: crate::network_state::TransitionVariant,
        /// Per-device custody second factor, if the network requires one on
        /// this device. `None` when no custody lock is enrolled.
        mfa_code: Option<String>,
        reply: oneshot::Sender<Result<crate::semantic::FactId>>,
    },
    /// Snapshot of the current governance state. Used by the
    /// control protocol to surface live state to the GUI.
    GovernanceSnapshot {
        reply: oneshot::Sender<crate::network_state::NetworkState>,
    },
}

impl ResourceMailboxItem for NetworkCmd {
    fn retained_claim(&self) -> std::result::Result<ResourceClaim, ResourceMailboxItemError> {
        let measure = match self {
            Self::ReplayCapabilities { .. } | Self::GovernanceSnapshot { .. } => (0, 0, 0),
            Self::SetTopology(mode) => mailbox_measure_serialized(mode)?,
            Self::ApproveRoster {
                device_id, label, ..
            } => strings_measure([device_id.as_str(), label.as_str()])?,
            Self::RemoveRoster { device_id, .. } | Self::ConnectPeer { device_id, .. } => {
                strings_measure([device_id.as_str()])?
            }
            Self::DropPeer { device_id, reason } => {
                let reason = match reason {
                    DropReason::TransportError { message } => Some(message.as_str()),
                    DropReason::Denied
                    | DropReason::IceFailed
                    | DropReason::AuthFailed
                    | DropReason::UserLeft
                    | DropReason::TopologyPruned
                    | DropReason::HeartbeatTimeout => None,
                };
                strings_measure([Some(device_id.as_str()), reason].into_iter().flatten())?
            }
            Self::AttemptRefused { refusal, .. } => {
                let reason = match &refusal.refusal {
                    myownmesh_signaling::NegotiationRefusal::DuplicateLiveEvent => None,
                    myownmesh_signaling::NegotiationRefusal::Provider(reason) => {
                        Some(reason.as_str())
                    }
                };
                strings_measure(
                    [
                        Some(refusal.attempt.as_str()),
                        Some(refusal.event_id.as_str()),
                        reason,
                    ]
                    .into_iter()
                    .flatten(),
                )?
            }
            Self::AttemptOutcome { outcome, .. } => {
                let reason = match &outcome.kind {
                    myownmesh_signaling::AttemptOutcomeKind::TypedRefused(reason) => {
                        Some(reason.as_str())
                    }
                    _ => None,
                };
                strings_measure(
                    [
                        Some(outcome.attempt.as_str()),
                        Some(outcome.event_id.as_str()),
                        reason,
                    ]
                    .into_iter()
                    .flatten(),
                )?
            }
            Self::Reconnect { peer } => strings_measure(peer.iter().map(String::as_str))?,
            Self::SendChannelReliable {
                peer,
                channel,
                payload,
                ..
            }
            | Self::SendChannelFrame {
                peer,
                channel,
                payload,
                ..
            } => checked_measure_add(
                strings_measure([peer.as_str(), channel.as_str()])?,
                mailbox_measure_serialized(payload)?,
            )?,
            Self::BroadcastChannelFrame {
                channel, payload, ..
            } => checked_measure_add(
                strings_measure([channel.as_str()])?,
                mailbox_measure_serialized(payload)?,
            )?,
            Self::SendRpcRequest { peer, request, .. } => checked_measure_add(
                strings_measure([peer.as_str()])?,
                mailbox_measure_serialized(request)?,
            )?,
            Self::FanoutCapabilities { caps } => mailbox_measure_serialized(caps)?,
            Self::ProposeTransition {
                variant, mfa_code, ..
            } => checked_measure_add(
                mailbox_measure_serialized(variant)?,
                strings_measure(mfa_code.iter().map(String::as_str))?,
            )?,
        };
        // Channel/Arc-backed effects are opaque dependency allocations, not OS
        // sockets or handles. The payload walk above counts its own allocations;
        // this adds only allocations retained by reply/cancellation effects.
        let effect_allocations = match self {
            // No reply, no cancellation, no channel: nothing to fund past the
            // payload the walk above already measured.
            Self::ReplayCapabilities { .. } | Self::FanoutCapabilities { .. } => 0,
            Self::SetTopology(_) | Self::DropPeer { .. } | Self::Reconnect { .. } => 0,
            Self::AttemptRefused { .. } | Self::AttemptOutcome { .. } => 1,
            Self::ConnectPeer { reply, .. } => usize::from(reply.is_some()) * 2,
            Self::ApproveRoster { .. }
            | Self::RemoveRoster { .. }
            | Self::SendChannelReliable { .. }
            | Self::SendChannelFrame { .. }
            | Self::BroadcastChannelFrame { .. }
            | Self::SendRpcRequest { .. }
            | Self::ProposeTransition { .. }
            | Self::GovernanceSnapshot { .. } => 1,
        };
        let allocations = measure.2.checked_add(effect_allocations).ok_or(
            ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::OpaqueDependencyResidual,
            },
        )?;
        mailbox_retained_claim::<Self>(measure.0, measure.1, allocations)
    }
}

pub struct ConnectWaiterRegistration {
    pub(super) id: u64,
    pub(super) reply: oneshot::Sender<Result<()>>,
    pub(super) cancelled: Arc<std::sync::atomic::AtomicBool>,
}

pub(super) struct ConnectWaitCancellation<'a> {
    pub(super) state: &'a NetworkState,
    pub(super) device_id: String,
    pub(super) id: u64,
    pub(super) cancelled: Arc<std::sync::atomic::AtomicBool>,
    pub(super) armed: bool,
}

impl Drop for ConnectWaitCancellation<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.cancelled
                .store(true, std::sync::atomic::Ordering::Release);
            self.state.cancel_connect_waiter(&self.device_id, self.id);
        }
    }
}

/// Inbound signaling messages from the signaling task.
#[derive(Debug)]
pub enum SignalingInbound {
    PeerAnnounced {
        device_id: String,
    },
    Offer {
        device_id: String,
        /// The sender's attempt correlation, preserved from the carrier frame.
        ///
        /// Kept because discarding it here is what left de-duplication unable
        /// to tell one attempt from the next: a host candidate with no
        /// `username_fragment` recurs verbatim on a replacement attempt, and a
        /// key built from content alone suppressed the live copy on the
        /// strength of a retired one. Unauthenticated and used for correlation
        /// only.
        attempt: String,
        sdp: String,
    },
    Answer {
        device_id: String,
        /// The attempt correlation this answer echoes — see [`Self::Offer`].
        attempt: String,
        sdp: String,
    },
    Candidate {
        device_id: String,
        /// The attempt correlation this candidate belongs to — see
        /// [`Self::Offer`]. Empty when the sender did not stamp one.
        attempt: String,
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

impl SignalingInbound {
    /// Everything this value reaches, measured for the owner that will hold it.
    ///
    /// Deliberately not a [`ResourceMailboxItem`] impl. What the engine's
    /// inbound mailbox carries is a
    /// [`super::signaling_ingress::EphemeralIngress`] — an admitted input with its
    /// lane and carrier provenance — and that is the type whose footprint the
    /// claim has to be priced against. Splitting the measurement out means the
    /// owner supplies `size_of::<Self>()` while this stays the one description
    /// of what a `SignalingInbound` reaches, rather than the two drifting.
    pub(super) fn string_measure(
        &self,
    ) -> std::result::Result<(usize, usize, usize), ResourceMailboxItemError> {
        match self {
            Self::PeerAnnounced { device_id } | Self::PeerLeft { device_id } => {
                strings_measure([device_id.as_str()])
            }
            Self::Offer {
                device_id,
                attempt,
                sdp,
            }
            | Self::Answer {
                device_id,
                attempt,
                sdp,
            } => strings_measure([device_id.as_str(), attempt.as_str(), sdp.as_str()]),
            Self::Candidate {
                device_id,
                attempt,
                candidate,
            } => strings_measure(
                [
                    Some(device_id.as_str()),
                    Some(attempt.as_str()),
                    Some(candidate.candidate.as_str()),
                    candidate.sdp_mid.as_deref(),
                    candidate.username_fragment.as_deref(),
                ]
                .into_iter()
                .flatten(),
            ),
        }
    }
}

/// Outbound signaling messages from the engine to the signaling task.
/// `Clone` so the bridge's fan-out can hand one engine emission to
/// several concurrently-attached drivers (Nostr + mDNS).
///
/// Crate-private, with the rest of the raw signaling surface. Nothing outside
/// `engine` constructs one, and a `pub` emission type is exactly the generic
/// message bus `FORMAL-PROOFS.md` Theorem 11.2 turns on application code not
/// having.
#[derive(Debug, Clone)]
pub(crate) enum SignalingOutbound {
    Announce,
    /// A recovery-scoped announce carrying the exact publication generation.
    /// Ordinary [`Announce`] values never participate in recovery admission.
    RecoveryAnnounce {
        id: RecoveryPublishId,
    },
    /// Carrier departure observation — the dual of [`Announce`]. This is a
    /// sender-claimed reachability hint, not an authenticated session terminal
    /// and not durable participation or authorization. A receiver may use it
    /// to update carrier availability, cancel speculative work, or trigger
    /// exact connector/liveness validation; it must not tear down a healthy
    /// authenticated session solely because this hint names its Device.
    /// Authenticated departure travels over the exact live session instead.
    Leave,
    Offer {
        device_id: String,
        /// The attempt this offer opens, minted once by the attempt's owner.
        ///
        /// Carried here rather than invented per carrier, which is what the
        /// three translations used to do: each stamped its own id, so the two
        /// copies of one fanned-out offer disagreed about which attempt they
        /// belonged to and the value was useless for correlating anything.
        attempt: String,
        sdp: String,
    },
    Answer {
        device_id: String,
        /// The offerer's correlation, echoed verbatim — see [`Self::Offer`].
        attempt: String,
        sdp: String,
    },
    Candidate {
        device_id: String,
        /// The attempt this candidate belongs to — see [`Self::Offer`].
        attempt: String,
        candidate: LocalIceCandidate,
    },
}

impl ResourceMailboxItem for SignalingOutbound {
    fn retained_claim(&self) -> std::result::Result<ResourceClaim, ResourceMailboxItemError> {
        let measure = match self {
            Self::Announce | Self::RecoveryAnnounce { .. } | Self::Leave => (0, 0, 0),
            Self::Offer {
                device_id,
                attempt,
                sdp,
            }
            | Self::Answer {
                device_id,
                attempt,
                sdp,
            } => strings_measure([device_id.as_str(), attempt.as_str(), sdp.as_str()])?,
            Self::Candidate {
                device_id,
                attempt,
                candidate,
            } => strings_measure(
                [
                    Some(device_id.as_str()),
                    Some(attempt.as_str()),
                    Some(candidate.candidate.as_str()),
                    candidate.sdp_mid.as_deref(),
                    candidate.username_fragment.as_deref(),
                ]
                .into_iter()
                .flatten(),
            )?,
        };
        mailbox_retained_claim::<Self>(measure.0, measure.1, measure.2)
    }
}

/// The shared state for a single joined network. Every long-lived
/// subsystem (driver loop, channels, rpc, handle) holds an
/// `Arc<NetworkState>`. Independent ownership domains use their own narrow
/// locks and notification points rather than one process-wide state lock.
pub struct NetworkState {
    pub network_id: String,
    /// The exact semantic bootstrap accepted before any peer or signaling
    /// surface is assembled.
    verified_bootstrap: crate::semantic::VerifiedBootstrap,
    mesh_context_id: crate::semantic::MeshContextId,
    pub identity: Arc<Identity>,
    pub transport: Transport,
    resource_scope: NetworkInstanceResourceScope,
    local_resources: LocalApplicationResourceScope,
    /// The one owner of session promotion for this network instance.
    ///
    /// `None` when the process owner installed no resource provider. That is
    /// fail-closed: there is no post-authentication capacity to reserve, so no
    /// session promotes and no application operation runs. It is deliberately
    /// not a compatibility mode — nothing falls back to a peer string.
    ///
    /// `pub(super)` so the engine's own send path can hand it to the fence, and
    /// no wider: promotion itself happens inside the registry mutation lock,
    /// which is the only place the policy conjunct is true of an installation
    /// rather than of a device id. Nothing outside the engine can reach it, and
    /// there is no public accessor.
    pub(crate) session_broker: Option<SessionBroker>,

    pub config: RwLock<NetworkConfig>,
    pub topology: RwLock<TopologyMode>,
    pub topology_impl: RwLock<Box<dyn Topology>>,

    pub(crate) peers: PeerRegistry,
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
    pub governance_state: Arc<RwLock<crate::network_state::NetworkState>>,
    /// The one authoritative semantic graph for this joined network.
    ///
    /// This is persistent for the lifetime of the shared `NetworkState`: all
    /// durable-fact ingress paths must borrow this exact graph rather than
    /// constructing a transient `FactGraph::new()`. Its context and authority
    /// roots come only from `verified_bootstrap`; pinned peers and
    /// carrier/session identities are selectors and never become semantic
    /// authority.
    pub(crate) fact_graph: Arc<RwLock<crate::semantic::FactGraph>>,
    pub current_phase: RwLock<MeshPhase>,

    pub events_tx: broadcast::Sender<MeshEvent>,
    pub(crate) application_gateway: crate::application_gateway::ApplicationGateway,

    pub(crate) signaling_tx: ResourceMailboxSender<SignalingOutbound>,
    /// Where every attached carrier delivers, and it takes a classified value
    /// rather than a bare [`SignalingInbound`]: the lane and the carrier
    /// provenance ride with the message to the engine instead of being computed
    /// and dropped at the bridge.
    pub(crate) signaling_inbound_tx: ResourceMailboxSender<EphemeralIngress>,
    /// The network's signaling runtime, once a carrier has attached one.
    ///
    /// Published here so the peer lifecycle can reach the single owner of
    /// de-duplication. The runtime is built by the bridge — it is the bridge
    /// that knows how many carriers share one — but "this attempt is over"
    /// is known here, and a key scoped to an attempt has to be released when
    /// that attempt ends or the scoping only defers the problem.
    ///
    /// `None` before any attach and after the last one is replaced. Nothing
    /// fails without it: releasing early is an optimization over waiting for
    /// provider pressure, so an unattached network simply has nothing to tell.
    signaling_runtime: parking_lot::RwLock<Option<Arc<super::signaling_ingress::SignalingRuntime>>>,
    /// Exact Nostr delivery settlement for this network's current driver.
    /// The bridge installs a closure over the retained driver handle; engine
    /// lifecycle code supplies only the exact attempt correlation and terminal
    /// outcome, never a device-id fallback.
    attempt_settlement: Mutex<Option<AttemptSettlement>>,
    pub cmd_tx: ResourceMailboxSender<NetworkCmd>,
    pub(super) speculative_promotion_tx: ResourceMailboxSender<SpeculativePromotionCmd>,
    speculative_promotion_rx: Mutex<Option<ResourceMailboxReceiver<SpeculativePromotionCmd>>>,

    /// Receiving end of `signaling_tx` — held here so callers can
    /// drain it via [`Self::take_signaling_outbound_rx`] when they
    /// bring up their signaling task.
    signaling_outbound_rx: Mutex<Option<ResourceMailboxReceiver<SignalingOutbound>>>,
    /// Joinable forwarders created by the in-process signaling bridge. `Some`
    /// means registration is open; shutdown takes the option under this mutex
    /// before awaiting the handles, so a concurrent late attach cannot become
    /// an untracked task.
    local_signaling_forwarders: Mutex<Option<Vec<JoinHandle<()>>>>,
    /// Controls that do not run an engine driver still need the command
    /// mailbox to be live: session promotion announces on it, and a closed
    /// receiver truthfully means the driver is gone. Parking the receiver in
    /// the state models an unread queue without turning it into a dead queue.
    #[cfg(test)]
    parked_command_receiver: Mutex<Option<ResourceMailboxReceiver<NetworkCmd>>>,
    shutdown_requested: std::sync::atomic::AtomicBool,
    shutdown_ready: tokio::sync::Notify,

    /// Offerer-side reconnect intents (see [`ReconnectIntent`]). Keyed by
    /// device id; an entry lives from the moment we drop a peer we owe an
    /// offer to until the link is re-established or the reconnecting grace
    /// expires. Events re-offer these immediately (relay reconnect, the
    /// peer's announce); the state-watch tick is the backstop that retries
    /// on a backoff for the cases no event covers.
    pub reconnect_intents: Mutex<std::collections::HashMap<String, ReconnectIntent>>,

    /// One provider-owned answerer recovery cohort. Causes are exact owner
    /// tokens, while the collection itself has one retained provider lease and
    /// one in-flight publish generation. A later cause waits for the next
    /// generation rather than mutating a cohort already admitted for publish.
    recovery_cohort: Mutex<RecoveryCohort>,
    /// Exact carrier admission for ordinary attempt publications. The map is
    /// keyed by the authenticated attempt correlation; each entry is a finite
    /// attach cohort and is removed once every carrier refuses or the attempt
    /// is settled.
    carrier_attempts: Mutex<CarrierAttemptList>,

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

    /// Per-network traffic accounting (see [`super::traffic`]) —
    /// written from the frame chokepoints, read by the status surface.
    pub traffic: super::traffic::TrafficCounters,

    /// Callers waiting for a specific peer to reach ACTIVE (the
    /// `connect_peer_wait` contract). Resolved on the mutual-approve
    /// transition; failed on terminal drops and shutdown.
    pub(crate) connect_waiters:
        Mutex<std::collections::HashMap<String, Vec<ConnectWaiterRegistration>>>,
    next_connect_waiter: std::sync::atomic::AtomicU64,

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

    /// Controls only: how many reliable acknowledgements this runtime has
    /// *attempted* to send.
    ///
    /// Incremented immediately before the send in `reliable::on_channel_seq_admitted`,
    /// so it counts the decision to acknowledge rather than a completed write —
    /// the same reading as [`crate::transport::diag::PeerDiag::hellos_sent`],
    /// and for the same reason. The lab fixture has no remote peer, so no write
    /// there can complete; a control measuring completions could not tell an
    /// acknowledgement this node refused to send from one it sent into a link
    /// with no far end, which is exactly the distinction the acceptance rule is
    /// about.
    ///
    /// It is test observation and nothing else. Nothing admits, accounts,
    /// retains or refuses on this value, and it does not exist in a production
    /// build.
    #[cfg(test)]
    pub(crate) channel_ack_attempts: std::sync::atomic::AtomicU64,

    /// Controls only: one action to run at the instant every exact-session
    /// retirement site has captured its `(owner, witness)` and has not yet
    /// retired anything.
    ///
    /// It exists for one property, which cannot be observed from outside the
    /// engine at all: that retirement names the session that failed rather than
    /// whichever session holds the device id when it runs. Driving a refusal and
    /// then replacing the session afterwards does not test that — a retirement
    /// keyed by device id passes it too. The replacement has to land *inside*
    /// the window, and this is the only point at which a control can put it
    /// there without a race of its own.
    ///
    /// One shot: it is taken before it is run, so a staged action fires for the
    /// first refusal that reaches a barrier and never for a later one. A control
    /// that stages it and observes it did not fire has learned that its refusal
    /// never reached the retirement it was aimed at, which is worth as much as
    /// the positive observation.
    ///
    /// Constraints on what may be staged, both of which every use below honours:
    /// it runs on the engine's own thread with no registry lock held, so it may
    /// promote or file state through the ordinary registry entry points; and it
    /// may not await, because these sites are not all async.
    ///
    /// Test observation and staging only. Nothing admits, accounts, retains or
    /// refuses on it, and it does not exist in a production build.
    #[cfg(test)]
    pub(crate) exact_retirement_barrier: Mutex<Option<Box<dyn FnOnce() + Send>>>,

    /// The park an armed control puts at the RPC reply's send boundary.
    ///
    /// Sibling of the barrier above and there for the same kind of reason: the
    /// property is about what happens *during* an operation, and no control can
    /// reach the inside of a spawned run from outside it. Revoking before the
    /// run starts and revoking after it finishes are both easy and neither is
    /// the case the finding names.
    ///
    /// Test observation and staging only. Nothing admits, accounts, retains or
    /// refuses on it, and it does not exist in a production build.
    #[cfg(test)]
    pub(crate) rpc_send_boundary: RpcSendBoundary,

    /// The instant between a handler run's fenced start and the embedder's
    /// closure being entered.
    ///
    /// The other half of the same problem `rpc_send_boundary` solves, at the
    /// other end of the run. A control asserting that a *started* run cannot be
    /// un-started has to deliver revocation after the start commits and before
    /// the closure is called, and that window is otherwise two adjacent
    /// statements with nothing between them.
    ///
    /// The same type, because it is the same mechanism and a second one could
    /// drift from it. Test observation and staging only; it does not exist in a
    /// production build.
    #[cfg(test)]
    pub(crate) rpc_handler_start_boundary: RpcSendBoundary,

    /// Controls only: park the next production DepartObserved receipt after
    /// it has been admitted, so a control can prove the receipt is in flight
    /// before allowing the exact send/retirement path to continue.
    ///
    /// Test and transport-lab observation only. It is absent from ordinary
    /// production builds and has no effect on receipt admission or custody.
    #[cfg(any(test, feature = "transport-lab"))]
    pub(crate) depart_observed_gate: DepartObservedGate,

    /// One action to run inside a handler run's start, between its early
    /// validity read and the fenced commit.
    ///
    /// A staged **synchronous** action rather than a park, because that instant
    /// is inside a synchronous decision: the run is not a future there, it is a
    /// function that has not returned yet, and there is nothing for an async
    /// boundary to hold. What a control needs to do there is act — revoke — and
    /// acting is exactly what a `FnOnce` can do.
    ///
    /// It is reached through the production call path rather than by a control
    /// calling the fenced begin itself. That distinction is the whole point: a
    /// control that called `begin` directly could observe the refusal and prove
    /// nothing about whether `on_rpc_request`'s spawned arm honours it.
    ///
    /// Test staging only, and it does not exist in a production build.
    #[cfg(test)]
    pub(crate) rpc_handler_precommit_action: Mutex<Option<Box<dyn FnOnce() + Send>>>,

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
    fn funded_carrier_instances<I>(&self, instances: I) -> Option<CarrierInstanceList>
    where
        I: IntoIterator<Item = RecoveryCarrierInstance> + Clone,
    {
        let claim = ResourceClaim::try_from_entries([
            (
                ResourceClass::AccountedMemoryBytes,
                u64::try_from(std::mem::size_of::<CarrierInstanceNode>()).ok()?,
            ),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
        .ok()?;
        let mut list = CarrierInstanceList::default();
        for (index, instance) in instances.clone().into_iter().enumerate() {
            let duplicate = instances
                .clone()
                .into_iter()
                .take(index)
                .any(|prior| prior == instance);
            if duplicate {
                continue;
            }
            let lease = self.local_resources.acquire(claim).ok()?;
            list.push_front(Box::new(CarrierInstanceNode {
                instance,
                _lease: lease,
                next: None,
            }));
        }
        Some(list)
    }

    /// Construct state below an existing Mesh runtime observation scope.
    ///
    /// The entry point for every construction. There used to be a `new` above
    /// this that acquired the global scopes itself and delegated here; nothing
    /// called it once the raw signaling surface stopped being public, because
    /// both real paths ([`super::spawn_network`] and its in-scope sibling)
    /// already hold the scopes they want this state to live under. Reaching for
    /// the global root inside a constructor was the thing that made it a
    /// convenience rather than a seam.
    #[cfg(test)]
    #[allow(clippy::type_complexity)]
    pub(crate) fn new_in_mesh_scope(
        config: NetworkConfig,
        identity: Arc<Identity>,
        transport: Transport,
        verified_bootstrap: crate::semantic::VerifiedBootstrap,
        mesh_scope: &MeshRuntimeResourceScope,
        local_resources: &LocalApplicationResourceScope,
    ) -> Result<(
        Arc<Self>,
        ResourceMailboxReceiver<EphemeralIngress>,
        ResourceMailboxReceiver<NetworkCmd>,
    )> {
        Self::new_in_mesh_scope_with_instance_root(
            config,
            identity,
            transport,
            verified_bootstrap,
            mesh_scope,
            local_resources,
            None,
        )
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn new_in_mesh_scope_with_instance_root(
        config: NetworkConfig,
        identity: Arc<Identity>,
        transport: Transport,
        verified_bootstrap: crate::semantic::VerifiedBootstrap,
        mesh_scope: &MeshRuntimeResourceScope,
        local_resources: &LocalApplicationResourceScope,
        instance_root: Option<std::path::PathBuf>,
    ) -> Result<(
        Arc<Self>,
        ResourceMailboxReceiver<EphemeralIngress>,
        ResourceMailboxReceiver<NetworkCmd>,
    )> {
        Self::new_in_resource_scope(
            config,
            identity,
            transport,
            mesh_scope.network_instance_scope(),
            local_resources.child()?,
            verified_bootstrap,
            instance_root,
        )
    }

    #[allow(clippy::type_complexity)]
    fn new_in_resource_scope(
        config: NetworkConfig,
        identity: Arc<Identity>,
        transport: Transport,
        resource_scope: NetworkInstanceResourceScope,
        local_resources: LocalApplicationResourceScope,
        verified_bootstrap: crate::semantic::VerifiedBootstrap,
        instance_root: Option<std::path::PathBuf>,
    ) -> Result<(
        Arc<Self>,
        ResourceMailboxReceiver<EphemeralIngress>,
        ResourceMailboxReceiver<NetworkCmd>,
    )> {
        // Standing dials survive restarts by riding the network config —
        // the daemon re-joins with the same `pinned_peers`, and this seed
        // re-arms them without any runtime re-pinning.
        verified_bootstrap
            .validate()
            .map_err(|error| Error::Network(format!("verified bootstrap rejected: {error}")))?;
        if verified_bootstrap.context().scope != config.network_id {
            return Err(Error::Network(format!(
                "verified bootstrap scope {} does not match network id {}",
                verified_bootstrap.context().scope,
                config.network_id
            )));
        }
        let bootstrap_is_closed = matches!(
            verified_bootstrap.policy(),
            crate::semantic::VerifiedProjectPolicy::Closed(_)
        );
        let config_is_closed = matches!(config.kind, crate::network_state::NetworkKind::Closed);
        if bootstrap_is_closed != config_is_closed {
            return Err(Error::Network(format!(
                "verified bootstrap policy shape does not match configured network kind {:?}",
                config.kind
            )));
        }
        let mesh_context_id = verified_bootstrap.context_id();

        let pinned: std::collections::HashSet<String> =
            config.pinned_peers.iter().cloned().collect();
        let persistence_root = instance_root.as_deref();
        let roster = crate::roster::load_at(persistence_root, &config.network_id)?;
        // The legacy NetworkState is a derived compatibility snapshot only.
        // Never load its transitions, member log, pending proposals, or split
        // records as authority. Canonical bootstrap policy supplies the kind
        // and initial root role; Silent remains a local transport behavior on
        // the verified Open semantic profile.
        let governance_kind = if bootstrap_is_closed {
            crate::network_state::NetworkKind::Closed
        } else {
            crate::network_state::NetworkKind::Open
        };
        let mut governance_roles = std::collections::BTreeMap::new();
        if let crate::semantic::VerifiedProjectPolicy::Closed(policy) = verified_bootstrap.policy()
        {
            governance_roles.insert(
                policy.authority_root().to_string(),
                crate::network_state::Role::Owner,
            );
        }
        let governance_state = crate::network_state::NetworkState::from_canonical_projection(
            &config.network_id,
            governance_kind,
            governance_roles,
        );
        // Topology is connector/deployment policy, not a canonical
        // authority-bearing fact. It therefore remains local configuration.
        let effective_topology = config.topology.clone();
        let topology_impl = crate::topology::from_mode(&effective_topology);
        let (events_tx, _) = broadcast::channel(256);
        // Deep enough to ride out a transition storm (a sleep/wake
        // fan-out re-handshaking every peer) without the watcher lagging;
        // lossy past that, with a `lagged` marker surfaced to the stream.
        let (conn_trace_tx, _) = broadcast::channel(512);
        let conn_trace_force_on =
            std::env::var("MYOWNMESH_CONN_TRACE").is_ok_and(|v| !v.is_empty() && v != "0");
        let (signaling_tx, signaling_outbound_rx) =
            crate::resource::resource_mailbox(local_resources.child()?)?;
        let (cmd_tx, cmd_rx) = crate::resource::resource_mailbox(local_resources.child()?)?;
        let (speculative_promotion_tx, speculative_promotion_rx) =
            crate::resource::resource_mailbox(local_resources.child()?)?;
        let (signaling_inbound_tx, signaling_inbound_rx) =
            crate::resource::resource_mailbox(local_resources.child()?)?;
        let session_broker = transport.session_broker();
        let governance_state = Arc::new(RwLock::new(governance_state));
        let local_device_id = identity.public_id().to_string();
        let fact_graph = Arc::new(RwLock::new(crate::semantic::FactGraph::from_bootstrap(
            &verified_bootstrap,
        )));
        let state = Arc::new(Self {
            network_id: config.network_id.clone(),
            verified_bootstrap,
            mesh_context_id,
            identity,
            transport,
            resource_scope,
            session_broker,
            config: RwLock::new(config.clone()),
            topology: RwLock::new(effective_topology),
            topology_impl: RwLock::new(topology_impl),
            peers: PeerRegistry::new(local_device_id),
            roster: RwLock::new(roster),
            governance_state,
            fact_graph,
            current_phase: RwLock::new(MeshPhase::Joining),
            events_tx,
            application_gateway: crate::application_gateway::ApplicationGateway::new(
                local_resources.clone(),
            ),
            local_resources,
            signaling_tx,
            signaling_inbound_tx,
            signaling_runtime: parking_lot::RwLock::new(None),
            attempt_settlement: Mutex::new(None),
            cmd_tx,
            speculative_promotion_tx,
            speculative_promotion_rx: Mutex::new(Some(speculative_promotion_rx)),
            signaling_outbound_rx: Mutex::new(Some(signaling_outbound_rx)),
            local_signaling_forwarders: Mutex::new(Some(Vec::new())),
            #[cfg(test)]
            parked_command_receiver: Mutex::new(None),
            shutdown_requested: std::sync::atomic::AtomicBool::new(false),
            shutdown_ready: tokio::sync::Notify::new(),
            reconnect_intents: Mutex::new(std::collections::HashMap::new()),
            recovery_cohort: Mutex::new(RecoveryCohort::new()),
            carrier_attempts: Mutex::new(CarrierAttemptList::default()),
            sticky_peers: Mutex::new(pinned),
            self_evicted: std::sync::atomic::AtomicBool::new(false),
            traffic: super::traffic::TrafficCounters::default(),
            connect_waiters: Mutex::new(std::collections::HashMap::new()),
            next_connect_waiter: std::sync::atomic::AtomicU64::new(1),
            last_reactive_announce_at: Mutex::new(None),
            clock_skew_watch: Mutex::new(super::heartbeat::ClockSkewWatch::default()),
            #[cfg(test)]
            channel_ack_attempts: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            exact_retirement_barrier: Mutex::new(None),
            #[cfg(test)]
            rpc_send_boundary: RpcSendBoundary::default(),
            #[cfg(test)]
            rpc_handler_start_boundary: RpcSendBoundary::default(),
            #[cfg(any(test, feature = "transport-lab"))]
            depart_observed_gate: DepartObservedGate::default(),
            #[cfg(test)]
            rpc_handler_precommit_action: Mutex::new(None),
            relay_reconnect: Mutex::new(None),
            relay_connected: Mutex::new(None),
            last_relay_rescue_at: Mutex::new(None),
            offline: std::sync::atomic::AtomicBool::new(false),
            conn_trace_tx,
            conn_trace_force_on,
        });
        // The registry announces a newly minted session on this same queue, so
        // the driver handles it once every fence lock has been released. Bound
        // here because this is the one place that owns both the registry and the
        // queue; the registry cannot construct it and the driver cannot reach
        // inside the fence.
        state.peers.bind_canonical_authority(
            state.verified_bootstrap().clone(),
            state.authoritative_fact_graph(),
        );
        state.peers.bind_command_sink(state.cmd_tx.clone());
        state
            .peers
            .bind_speculative_promotion_sink(state.speculative_promotion_tx.clone());
        Ok((state, signaling_inbound_rx, cmd_rx))
    }

    /// The exact semantic identity selected by the verified bootstrap.
    pub fn mesh_context_id(&self) -> crate::semantic::MeshContextId {
        self.mesh_context_id
    }

    /// The canonical, wire-safe spelling of this state's semantic context.
    ///
    /// This is derived from the immutable [`crate::semantic::MeshContextId`]
    /// selected by the
    /// verified bootstrap; it is never reconstructed from a carrier, peer, or
    /// mutable network configuration.
    pub fn mesh_context_id_string(&self) -> String {
        self.mesh_context_id.to_string()
    }

    /// The validated bootstrap that owns this network state's semantic policy.
    pub fn verified_bootstrap(&self) -> &crate::semantic::VerifiedBootstrap {
        &self.verified_bootstrap
    }

    /// The sealed policy projected by the validated bootstrap.
    ///
    /// Callers may inspect this immutable projection when deciding whether a
    /// canonical semantic commit can affect a policy-owned path. They cannot
    /// supply roots or mutate the bootstrap through this reference.
    pub fn verified_policy(&self) -> &crate::semantic::VerifiedProjectPolicy {
        self.verified_bootstrap.policy()
    }

    /// The exact authority root, when this state is backed by a Closed
    /// bootstrap. Open profiles intentionally have no root authority.
    pub fn verified_authority_root(&self) -> Option<&str> {
        match self.verified_policy() {
            crate::semantic::VerifiedProjectPolicy::Open => None,
            crate::semantic::VerifiedProjectPolicy::Closed(policy) => Some(policy.authority_root()),
        }
    }

    /// The exact persisted bootstrap record, exposed read-only for durable
    /// handoff and diagnostics without exposing mutable authority state.
    pub fn verified_bootstrap_record(&self) -> &crate::semantic::BootstrapRecord {
        self.verified_bootstrap.record()
    }

    pub(crate) fn peer_connection_resource_scope(
        &self,
    ) -> crate::resource::PeerConnectionResourceScope {
        self.resource_scope.peer_connection_scope()
    }

    pub(crate) fn local_application_resource_scope(&self) -> Result<LocalApplicationResourceScope> {
        Ok(self.local_resources.child()?)
    }

    /// Reached by every exact-session retirement site, after it has captured the
    /// owner and witness it will retire under and before it retires anything.
    ///
    /// In a production build this is an empty function over a field that does
    /// not exist. Under test it runs whatever a control staged with
    /// [`stage_exact_retirement_barrier`](Self::stage_exact_retirement_barrier),
    /// once, and never re-enters: the action is taken out from under the lock
    /// before it is called, so an action that itself reached a retirement site
    /// would find the barrier already empty rather than recurse.
    pub(crate) fn reach_exact_retirement_barrier(&self) {
        #[cfg(test)]
        {
            let staged = self.exact_retirement_barrier.lock().take();
            if let Some(staged) = staged {
                staged();
            }
        }
    }

    /// Stage the one action the next retirement site will run in its capture →
    /// retire window. See [`exact_retirement_barrier`](Self::exact_retirement_barrier).
    #[cfg(test)]
    pub(crate) fn stage_exact_retirement_barrier(&self, staged: impl FnOnce() + Send + 'static) {
        let displaced = self
            .exact_retirement_barrier
            .lock()
            .replace(Box::new(staged));
        assert!(
            displaced.is_none(),
            "a control staged a second retirement barrier over one that never fired"
        );
    }

    /// Whether the staged action is still waiting, i.e. no retirement site has
    /// been reached since it was staged.
    #[cfg(test)]
    pub(crate) fn exact_retirement_barrier_pending(&self) -> bool {
        self.exact_retirement_barrier.lock().is_some()
    }

    /// The point in an RPC handler run at which the reply is about to reach the
    /// wire, and the last point at which revocation can still take it back.
    ///
    /// In a production build this is an empty function over a field that does
    /// not exist. Under test, and only while a control has armed it, a run that
    /// reaches here parks until that control releases it — which is what lets a
    /// control revoke the authority *while the send is in flight* rather than
    /// before it starts or after it finished. Those are the two states an
    /// unassisted control can reach, and neither is the one the finding is
    /// about.
    ///
    /// No timer is involved on either side. The park ends when the control
    /// releases it or when the run is cancelled, and the cancellation is what
    /// the control observes.
    pub(crate) async fn reach_rpc_send_boundary(&self) {
        #[cfg(test)]
        self.rpc_send_boundary.reach().await;
    }

    /// The point in an RPC handler run at which the start has committed under
    /// the registry fence and the embedder's closure has not yet been called.
    ///
    /// In a production build this is an empty function over a field that does
    /// not exist. Under test, and only while a control has armed it, a run that
    /// reaches here parks until that control releases it — which is what lets a
    /// control revoke the authority in the one instant the contract is about:
    /// after the start is committed, before the closure is entered.
    ///
    /// What must be observed there is that the closure is entered anyway,
    /// exactly once, because the start was already ordered before that
    /// revocation. Everything the run does *afterwards* is still cancelled by
    /// the witness, which is the other half of the same assertion.
    pub(crate) async fn reach_rpc_handler_start_boundary(&self) {
        #[cfg(test)]
        self.rpc_handler_start_boundary.reach().await;
    }

    /// Reach the one-shot DepartObserved control gate. In an ordinary build
    /// this compiles to no behavior because the gate is not part of the state.
    pub(crate) async fn reach_depart_observed_gate(&self) {
        #[cfg(any(test, feature = "transport-lab"))]
        self.depart_observed_gate.reach().await;
    }

    /// The point inside a handler run's start, after its early validity read and
    /// before the fenced commit.
    ///
    /// In a production build this is an empty function over a field that does
    /// not exist, called with nothing staged, and it compiles away. Under test
    /// it runs whatever a control staged, exactly once — which is how a control
    /// revokes *in that instant* rather than before or after it.
    ///
    /// Taken rather than borrowed, so one staging fires once. A second run
    /// reaching the same point finds nothing and proceeds, which is what makes
    /// "the action was consumed" a usable non-vacuity check for the control that
    /// staged it.
    pub(crate) fn reach_rpc_handler_precommit_point(&self) {
        #[cfg(test)]
        if let Some(staged) = self.rpc_handler_precommit_action.lock().take() {
            staged();
        }
    }

    /// Stage the action the next handler run will perform at its pre-commit
    /// point.
    #[cfg(test)]
    pub(crate) fn stage_rpc_handler_precommit_action(
        &self,
        staged: impl FnOnce() + Send + 'static,
    ) {
        let displaced = self
            .rpc_handler_precommit_action
            .lock()
            .replace(Box::new(staged));
        assert!(
            displaced.is_none(),
            "a control staged a second handler pre-commit action over one that never fired"
        );
    }

    /// Whether the staged action is still waiting — i.e. no handler run has
    /// reached its pre-commit point since it was staged.
    ///
    /// The non-vacuity half. A control asserting "the closure was never entered"
    /// has to know the run got as far as the point that refused it; without
    /// this, the same assertion passes for a run that never started.
    #[cfg(test)]
    pub(crate) fn rpc_handler_precommit_action_pending(&self) -> bool {
        self.rpc_handler_precommit_action.lock().is_some()
    }
}

/// One-shot control gate for the exact DepartObserved receipt path.
///
/// The release future is subscribed before the arm is consumed. That ordering
/// makes a release concurrent with arrival observable rather than a lost
/// `Notify` wake. Consuming the arm before announcing entry makes only one
/// receipt park, even if several receipt tasks reach the hook together.
#[cfg(any(test, feature = "transport-lab"))]
#[derive(Default)]
pub(crate) struct DepartObservedGate {
    armed: std::sync::atomic::AtomicBool,
    entered_notify: tokio::sync::Notify,
    release_notify: tokio::sync::Notify,
}

#[cfg(any(test, feature = "transport-lab"))]
impl DepartObservedGate {
    pub(crate) async fn reach(&self) {
        use std::sync::atomic::Ordering;

        let release = self.release_notify.notified();
        tokio::pin!(release);
        release.as_mut().enable();
        if !self.armed.swap(false, Ordering::AcqRel) {
            return;
        }
        self.entered_notify.notify_waiters();
        release.await;
    }

    /// Arm exactly one future receipt. A second arm before arrival is a
    /// control mistake rather than a silently displaced observation.
    pub(crate) fn arm(&self) {
        assert!(
            !self.armed.swap(true, std::sync::atomic::Ordering::AcqRel),
            "a DepartObserved gate was armed twice"
        );
    }

    /// Subscribe before causing the receipt so entry cannot be missed.
    pub(crate) fn entered(&self) -> tokio::sync::futures::Notified<'_> {
        self.entered_notify.notified()
    }

    /// Alias matching the other engine controls' arrival terminology.
    pub(crate) fn arrival(&self) -> tokio::sync::futures::Notified<'_> {
        self.entered()
    }

    /// Release the one receipt currently parked at the gate.
    pub(crate) fn release(&self) {
        self.release_notify.notify_waiters();
    }
}

/// A control-armed park at the RPC send boundary, and the record of what
/// happened to every run that reached it.
///
/// The three counters are what make the observation causal rather than
/// circumstantial. `entered` says a run got as far as the boundary at all —
/// without it, "no frame was sent" is equally true of a run that never started.
/// `abandoned` is written by a guard living *inside* the parked future, so it is
/// incremented by the cancellation itself: a run whose task is dropped at the
/// boundary records that fact as it unwinds, and the task lease held beside it
/// is released in the same drop. `passed` is the post-boundary effect, and it
/// staying at zero is the assertion.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct RpcSendBoundary {
    armed: std::sync::atomic::AtomicBool,
    entered: std::sync::atomic::AtomicUsize,
    passed: std::sync::atomic::AtomicUsize,
    abandoned: std::sync::atomic::AtomicUsize,
    finished: std::sync::atomic::AtomicUsize,
    semantic_finished: std::sync::atomic::AtomicUsize,
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

/// Records, on drop, that the run holding it left the boundary without passing
/// it — which for a parked run means its task was cancelled here.
#[cfg(test)]
struct RpcSendBoundaryVisit<'a> {
    boundary: &'a RpcSendBoundary,
    passed: bool,
}

#[cfg(test)]
impl Drop for RpcSendBoundaryVisit<'_> {
    fn drop(&mut self) {
        if !self.passed {
            self.boundary
                .abandoned
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
impl RpcSendBoundary {
    async fn reach(&self) {
        use std::sync::atomic::Ordering;

        // Unarmed is the whole of production and the whole of every other
        // control: one load and a return, with nothing to park on.
        if !self.armed.load(Ordering::Acquire) {
            return;
        }
        // Subscribed *before* the arrival is announced. A control that released
        // the boundary the instant it saw the arrival would otherwise race a
        // notification against a subscription that had not happened yet, and
        // `Notify` does not keep one for a waiter that is not yet waiting.
        let release = self.release.notified();
        tokio::pin!(release);
        release.as_mut().enable();

        let mut visit = RpcSendBoundaryVisit {
            boundary: self,
            passed: false,
        };
        self.entered.fetch_add(1, Ordering::SeqCst);
        self.reached.notify_waiters();
        release.await;
        visit.passed = true;
        self.passed.fetch_add(1, Ordering::SeqCst);
    }

    /// Park every run that reaches the boundary from here on.
    pub(crate) fn arm(&self) {
        self.armed.store(true, std::sync::atomic::Ordering::Release);
    }

    /// Let every currently parked run continue past the boundary.
    ///
    /// The other exit, and the one a control needs when the point of the
    /// control is what happens *after* the boundary rather than instead of it:
    /// revoke while the run is parked, then release, and observe what the run
    /// does with an authority that ended while it was standing still.
    ///
    /// `notify_waiters` rather than `notify_one`, and it wakes only runs already
    /// parked — a run that arrives later parks as usual, because arming is not
    /// undone by releasing. That is what keeps one release from silently
    /// disarming the boundary for every run after it.
    pub(crate) fn release(&self) {
        self.release.notify_waiters();
    }

    /// A future that resolves when a run arrives at the boundary.
    ///
    /// Handed out as a future rather than polled for, so a control can subscribe
    /// before it delivers the frame and cannot miss the arrival.
    pub(crate) fn arrival(&self) -> tokio::sync::futures::Notified<'_> {
        self.reached.notified()
    }

    /// How many runs reached the boundary.
    pub(crate) fn entered(&self) -> usize {
        self.entered.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// How many runs got past it — the post-boundary effect.
    pub(crate) fn passed(&self) -> usize {
        self.passed.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// How many runs were dropped while parked on it.
    pub(crate) fn abandoned(&self) -> usize {
        self.abandoned.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// How many handler tasks have finished **and released their lease**.
    ///
    /// The one that answers "the task ended", as against
    /// [`Self::abandoned`], which answers "the run left the boundary". Those are
    /// not the same instant: the boundary guard is dropped inside the run
    /// future, and the task's own epilogue — the task lease among it — runs
    /// afterwards. A control that read `abandoned` and concluded the lease was
    /// released would be racing that epilogue.
    ///
    /// See [`RpcRunEpilogue`] for why this is ordered after the lease and not
    /// merely near it.
    pub(crate) fn finished(&self) -> usize {
        self.finished.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Record that one durable semantic reducer returned successfully. This is
    /// separate from task/epilogue completion: a task may finish without
    /// committing the semantic effect the control is proving.
    pub(crate) fn mark_semantic_finished(&self) {
        self.semantic_finished
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }

    /// How many durable semantic reducer completions were recorded.
    pub(crate) fn semantic_finished(&self) -> usize {
        self.semantic_finished
            .load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Records one handler task's end, **after** that task's lease has been
/// released.
///
/// The ordering is the whole value of this type and it is structural, not
/// hopeful: locals drop in reverse declaration order, so the spawned run
/// declares this guard *before* it rebinds `_task_lease`. The lease is therefore
/// released first and this increment happens strictly afterwards — which makes
/// the count an observation of "the task is gone and has stopped costing its
/// owner", rather than of "the run stopped running", which is an earlier and
/// weaker fact.
///
/// Test-only. It exists because task completion is otherwise unobservable from
/// outside a spawned task: a cancelled run sends nothing, and its absence is
/// equally true of a run that never started.
#[cfg(test)]
pub(crate) struct RpcRunEpilogue(std::sync::Arc<NetworkState>);

#[cfg(test)]
impl RpcRunEpilogue {
    pub(crate) fn new(state: std::sync::Arc<NetworkState>) -> Self {
        Self(state)
    }
}

#[cfg(test)]
impl Drop for RpcRunEpilogue {
    fn drop(&mut self) {
        self.0
            .rpc_send_boundary
            .finished
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl NetworkState {
    /// Borrow the single semantic authority graph for this network instance.
    /// Callers must use this shared graph for admission and projection; a new
    /// default graph would silently bypass the trusted-root boundary.
    pub(crate) fn authoritative_fact_graph(&self) -> Arc<RwLock<crate::semantic::FactGraph>> {
        Arc::clone(&self.fact_graph)
    }

    /// Read observations for this live joined network instance.
    pub fn resource_report(&self) -> ResourceReport {
        self.resource_scope.report()
    }

    /// Take the outbound signaling receiver so the signaling task
    /// can drain it. Only one consumer is supported; subsequent
    /// calls return `None`.
    /// Publish the signaling runtime this network's carriers share.
    ///
    /// Called by the bridge at every attach. A later attach replaces the
    /// earlier value, which is correct: the replaced runtime is dropped with
    /// every key it held, and the keys of a runtime nothing is delivering
    /// through describe attempts nothing can arrive for.
    pub(crate) fn publish_signaling_runtime(
        &self,
        runtime: &Arc<super::signaling_ingress::SignalingRuntime>,
    ) {
        *self.signaling_runtime.write() = Some(Arc::clone(runtime));
        self.peers.bind_signaling_runtime(Arc::downgrade(runtime));
        // A carrier attach/restore is an explicit recovery trigger.  This
        // path intentionally bypasses the ordinary presence floor; if the
        // carrier cannot admit the queued copy, the exact cohort remains
        // pending for the next attach.
        let _ = self.queue_recovery_announce();
    }

    /// The signaling runtime, if a carrier has attached one.
    pub(crate) fn signaling_runtime(
        &self,
    ) -> Option<Arc<super::signaling_ingress::SignalingRuntime>> {
        self.signaling_runtime.read().clone()
    }

    pub(crate) fn set_attempt_settlement(&self, settlement: AttemptSettlement) {
        *self.attempt_settlement.lock() = Some(settlement);
    }

    pub(crate) fn clear_attempt_settlement(&self) {
        self.attempt_settlement.lock().take();
    }

    pub(crate) fn begin_carrier_attempt<I>(&self, attempt: &str, instances: I) -> bool
    where
        I: IntoIterator<Item = RecoveryCarrierInstance> + Clone,
    {
        if attempt.is_empty() {
            return false;
        }
        let mut expected = 0usize;
        for (index, instance) in instances.clone().into_iter().enumerate() {
            let duplicate = instances
                .clone()
                .into_iter()
                .take(index)
                .any(|prior| prior == instance);
            if !duplicate {
                expected = match expected.checked_add(1) {
                    Some(expected) => expected,
                    None => return false,
                };
            }
        }
        if expected == 0 {
            return false;
        }
        let Some(bytes) = std::mem::size_of::<CarrierAttemptNode>()
            .checked_add(attempt.len())
            .and_then(|bytes| {
                bytes.checked_add(
                    expected.checked_mul(std::mem::size_of::<CarrierAttemptCarrier>())?,
                )
            })
        else {
            return false;
        };
        let Ok(bytes) = u64::try_from(bytes) else {
            return false;
        };
        let Some(residual_count) = expected.checked_add(1) else {
            return false;
        };
        let Ok(residuals) = u64::try_from(residual_count) else {
            return false;
        };
        let Ok(claim) = ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, bytes),
            (ResourceClass::OpaqueDependencyResidual, residuals),
        ]) else {
            return false;
        };
        let Ok(entry_lease) = self.local_resources.acquire(claim) else {
            return false;
        };
        let mut attempts = self.carrier_attempts.lock();
        if attempts.find_mut(attempt).is_some() {
            drop(entry_lease);
            return true;
        }
        let mut carriers = None;
        for (index, instance) in instances.clone().into_iter().enumerate() {
            let duplicate = instances
                .clone()
                .into_iter()
                .take(index)
                .any(|prior| prior == instance);
            if !duplicate {
                carriers = Some(Box::new(CarrierAttemptCarrier {
                    instance,
                    resolved: false,
                    next: carriers.take(),
                }));
            }
        }
        attempts.push_front(Box::new(CarrierAttemptNode {
            attempt: attempt.to_string(),
            _entry_lease: entry_lease,
            carriers,
            expected,
            resolved: 0,
            accepted: false,
            next: None,
        }));
        true
    }

    /// Record an exact carrier's source admission. `true` is returned only
    /// for the final refusal in a cohort with no accepted copy; callers may
    /// then route the typed refusal to the exact attempt owner.
    pub(crate) fn record_carrier_attempt(
        &self,
        attempt: &str,
        instance: RecoveryCarrierInstance,
        accepted: bool,
    ) -> bool {
        let mut attempts = self.carrier_attempts.lock();
        let final_refusal = {
            let Some(state) = attempts.find_mut(attempt) else {
                return false;
            };
            if accepted {
                if state.carrier_mut(instance).is_none() {
                    return false;
                }
                state.accepted = true;
                false
            } else {
                let already_resolved = {
                    let Some(carrier) = state.carrier_mut(instance) else {
                        return false;
                    };
                    if carrier.resolved {
                        true
                    } else {
                        carrier.resolved = true;
                        false
                    }
                };
                if already_resolved {
                    return false;
                }
                state.resolved += 1;
                !state.accepted && state.resolved == state.expected
            }
        };
        if final_refusal {
            let _ = attempts.remove(attempt);
        }
        final_refusal
    }

    pub(crate) fn clear_carrier_attempt(&self, attempt: &str) {
        let _ = self.carrier_attempts.lock().remove(attempt);
    }

    pub(crate) fn settle_attempt(
        &self,
        attempt: &str,
        terminal: myownmesh_signaling::nostr::delivery::DeliveryTerminal,
    ) -> usize {
        let settlement = self.attempt_settlement.lock().clone();
        let settled = settlement.map_or(0, |settlement| settlement(attempt, terminal));
        self.clear_carrier_attempt(attempt);
        settled
    }

    pub(crate) fn take_signaling_outbound_rx(
        self: &Arc<Self>,
    ) -> Option<ResourceMailboxReceiver<SignalingOutbound>> {
        self.signaling_outbound_rx.lock().take()
    }

    pub(super) fn take_speculative_promotion_rx(
        &self,
    ) -> Option<ResourceMailboxReceiver<SpeculativePromotionCmd>> {
        self.speculative_promotion_rx.lock().take()
    }

    /// Keep an otherwise undriven fixture's command receiver alive until the
    /// fixture state drops. A production driver always owns this receiver.
    #[cfg(test)]
    pub(crate) fn park_command_receiver_for_test(
        &self,
        receiver: ResourceMailboxReceiver<NetworkCmd>,
    ) {
        let replaced = self.parked_command_receiver.lock().replace(receiver);
        assert!(
            replaced.is_none(),
            "a fixture parks its command receiver once"
        );
    }

    pub fn request_shutdown(&self) {
        self.shutdown_requested
            .store(true, std::sync::atomic::Ordering::Release);
        self.shutdown_ready.notify_waiters();
        self.cmd_tx.close();
        self.speculative_promotion_tx.close();
        self.signaling_inbound_tx.close();
        self.signaling_tx.close();
    }

    /// Run one local signaling attach while holding the registration fence.
    /// The closure must return the exact spawned forwarder; keeping spawn and
    /// registration in this critical section prevents shutdown from taking the
    /// registry between those two operations.
    pub(crate) fn with_local_signaling_forwarder<R>(
        &self,
        start: impl FnOnce() -> (R, JoinHandle<()>),
    ) -> Option<R> {
        let mut forwarders = self.local_signaling_forwarders.lock();
        if self
            .shutdown_requested
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return None;
        }
        let handles = forwarders.as_mut()?;
        let (result, handle) = start();
        handles.push(handle);
        Some(result)
    }

    fn take_local_signaling_forwarders(&self) -> Vec<JoinHandle<()>> {
        self.local_signaling_forwarders
            .lock()
            .take()
            .unwrap_or_default()
    }

    pub(crate) async fn wait_for_shutdown(&self) {
        loop {
            let notified = self.shutdown_ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self
                .shutdown_requested
                .load(std::sync::atomic::Ordering::Acquire)
            {
                return;
            }
            notified.await;
        }
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

    fn same_recovery_owner(left: &PeerOwnerToken, right: &PeerOwnerToken) -> bool {
        if !Arc::ptr_eq(left.connection(), right.connection()) {
            return false;
        }
        match (left.worker(), right.worker()) {
            (None, None) => true,
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }

    fn recovery_cohort_cause_claim(
    ) -> std::result::Result<ResourceClaim, ResourceClaimArithmeticError> {
        let bytes = u64::try_from(std::mem::size_of::<RecoveryCohortCause>()).map_err(|_| {
            ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            }
        })?;
        ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, bytes),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
    }

    /// Publish one exact-owner cause into the network's single provider-owned
    /// cohort after its terminal mutation succeeds. Repeated publication of
    /// the same exact owner coalesces without replacing a captured generation.
    pub(crate) fn retain_recovery_demand(
        &self,
        owner: PeerOwnerToken,
        demand: crate::runtime::peer_session::RecoveryDemandHandle,
    ) {
        let owner_for_check = owner.clone();
        let mut cohort = self.recovery_cohort.lock();
        if cohort.pending.contains_owner(&owner)
            || cohort
                .in_flight
                .as_ref()
                .is_some_and(|generation| generation.causes.contains_owner(&owner))
        {
            return;
        }
        let Ok(claim) = Self::recovery_cohort_cause_claim() else {
            demand.cancel();
            return;
        };
        let Ok(collection_lease) = self.local_resources.acquire(claim) else {
            demand.cancel();
            return;
        };
        cohort.pending.push_front(Box::new(RecoveryCohortCause {
            owner,
            demand,
            collection_lease,
            next: None,
        }));

        // A successor may have committed between its one-time cancellation
        // check and this terminal publication. Release the cohort lock before
        // the registry query to preserve the registry-then-cohort lock order;
        // either ordering still gets a second cancellation check.
        drop(cohort);
        let successor = self
            .peers
            .owner(owner_for_check.device_id())
            .filter(|current| self.peers.has_usable_authenticated_current(current));
        if successor.is_some() {
            self.cancel_recovery_demands_for_device(owner_for_check.device_id());
        }
    }

    /// Capture the current pending causes as one publish generation. The
    /// captured set is immutable until its matching outcome settles.
    pub(crate) fn capture_recovery_cohort(&self) -> Option<RecoveryPublishId> {
        let mut cohort = self.recovery_cohort.lock();
        if cohort.in_flight.is_some() || cohort.pending.is_empty() {
            return None;
        }
        let next_generation = cohort.next_generation.checked_add(1)?;
        cohort.next_generation = next_generation;
        let id = RecoveryPublishId {
            generation: cohort.next_generation,
        };
        let causes = std::mem::take(&mut cohort.pending);
        cohort.in_flight = Some(RecoveryCohortGeneration { id, causes });
        Some(id)
    }

    /// Queue one recovery announce behind the engine mailbox.  Unlike an
    /// ordinary reactive presence announce this path has no presence floor:
    /// the exact captured cohort remains in-flight until a carrier source has
    /// admitted at least one copy.  The queue marker is installed before the
    /// mailbox send so a concurrently running carrier cannot consume an
    /// unmarked publication.
    pub(crate) fn queue_recovery_announce(&self) -> Option<RecoveryPublishId> {
        let id = self.capture_recovery_cohort()?;
        {
            let mut cohort = self.recovery_cohort.lock();
            if cohort
                .in_flight
                .as_ref()
                .is_none_or(|generation| generation.id != id)
                || cohort.queued_publication.is_some()
            {
                return None;
            }
            cohort.queued_publication = Some(id);
        }
        if self
            .signaling_tx
            .send(SignalingOutbound::RecoveryAnnounce { id })
            .is_err()
        {
            let mut cohort = self.recovery_cohort.lock();
            if cohort.queued_publication == Some(id) {
                cohort.queued_publication = None;
                drop(cohort);
                self.settle_recovery_cohort(
                    id,
                    crate::runtime::peer_session::RecoveryAttempt::Refused,
                );
            }
            return None;
        }
        Some(id)
    }

    pub(crate) fn recovery_publication_in_flight(&self) -> bool {
        let cohort = self.recovery_cohort.lock();
        cohort.in_flight.is_some()
    }

    /// Snapshot recovery custody for deterministic lifecycle controls. The
    /// tuple reports pending causes, captured generation, queued mailbox
    /// publication, and attached carrier publication respectively.
    #[cfg(test)]
    pub(crate) fn recovery_custody_snapshot_for_test(&self) -> (bool, bool, bool, bool) {
        let cohort = self.recovery_cohort.lock();
        (
            !cohort.pending.is_empty(),
            cohort.in_flight.is_some(),
            cohort.queued_publication.is_some(),
            cohort.publication.is_some(),
        )
    }

    #[cfg(test)]
    pub(crate) fn recovery_generation_for_test(&self) -> Option<RecoveryPublishId> {
        self.recovery_cohort
            .lock()
            .in_flight
            .as_ref()
            .map(|generation| generation.id)
    }

    /// Move the queued publication into the finite cohort of currently
    /// attached carrier instances.  A source/driver must present the exact
    /// instance it was assigned at attach; a stale source cannot begin a new
    /// publication.
    pub(crate) fn begin_recovery_publication(
        &self,
        id: RecoveryPublishId,
        instances: impl IntoIterator<Item = RecoveryCarrierInstance> + Clone,
    ) -> bool {
        let Some(remaining) = self.funded_carrier_instances(instances) else {
            return false;
        };
        let mut cohort = self.recovery_cohort.lock();
        if cohort.queued_publication != Some(id)
            || cohort
                .in_flight
                .as_ref()
                .is_none_or(|generation| generation.id != id)
            || cohort.publication.is_some()
        {
            return false;
        }
        cohort.queued_publication = None;
        cohort.publication = Some(RecoveryPublication { id, remaining });
        true
    }

    pub(crate) fn begin_recovery_for_carrier(
        &self,
        expected_id: RecoveryPublishId,
        instance: RecoveryCarrierInstance,
    ) -> Option<RecoveryPublishId> {
        let queued_id = { self.recovery_cohort.lock().queued_publication };
        if let Some(id) = queued_id {
            if id != expected_id {
                return None;
            }
            return self
                .begin_recovery_publication(id, [instance])
                .then_some(id);
        }
        let cohort = self.recovery_cohort.lock();
        cohort.publication.as_ref().and_then(|publication| {
            (publication.id == expected_id && publication.remaining.contains(instance))
                .then_some(publication.id)
        })
    }

    pub(crate) fn refuse_empty_recovery_publication(&self, id: RecoveryPublishId) {
        let should_refuse =
            {
                let mut cohort = self.recovery_cohort.lock();
                cohort.publication.as_ref().is_some_and(|publication| {
                    publication.id == id && publication.remaining.is_empty()
                }) && cohort.publication.take().is_some()
            };
        if should_refuse {
            self.settle_recovery_cohort(id, crate::runtime::peer_session::RecoveryAttempt::Refused);
        }
    }

    /// Record one exact carrier admission.  One accepted carrier settles the
    /// captured generation immediately; refusals only settle as refused after
    /// every carrier in the finite attach cohort has refused.  Reports from a
    /// replaced publication or an instance outside the captured cohort are
    /// ignored.
    pub(crate) fn record_recovery_carrier(
        &self,
        id: RecoveryPublishId,
        instance: RecoveryCarrierInstance,
        accepted: bool,
    ) {
        let outcome = {
            let mut cohort = self.recovery_cohort.lock();
            let Some(publication) = cohort.publication.as_mut() else {
                return;
            };
            if publication.id != id || publication.remaining.remove(instance).is_none() {
                return;
            }
            let terminal = accepted || publication.remaining.is_empty();
            let outcome = if accepted {
                crate::runtime::peer_session::RecoveryAttempt::Accepted
            } else {
                crate::runtime::peer_session::RecoveryAttempt::Refused
            };
            if terminal {
                cohort.publication.take();
                Some(outcome)
            } else {
                None
            }
        };
        if let Some(outcome) = outcome {
            self.settle_recovery_cohort(id, outcome);
        }
    }

    pub(crate) fn next_recovery_carrier_instance(&self) -> Option<RecoveryCarrierInstance> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        NEXT.fetch_update(
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
            |value| value.checked_add(1),
        )
        .ok()
        .map(RecoveryCarrierInstance)
    }

    /// Apply one provider outcome only to the exact captured generation.
    /// Refusal/rate-limit returns that generation's causes to the pending
    /// cohort; accepted consumes only those causes, leaving later causes for a
    /// subsequent generation.
    pub(crate) fn settle_recovery_cohort(
        &self,
        generation_id: RecoveryPublishId,
        attempt: crate::runtime::peer_session::RecoveryAttempt,
    ) {
        let detached_publication = {
            let mut cohort = self.recovery_cohort.lock();
            let Some(mut generation) = cohort.in_flight.take() else {
                return;
            };
            if generation.id != generation_id {
                cohort.in_flight = Some(generation);
                return;
            }
            if cohort.queued_publication == Some(generation_id) {
                cohort.queued_publication = None;
            }
            let detached_publication = cohort
                .publication
                .as_ref()
                .is_some_and(|publication| publication.id == generation_id)
                .then(|| cohort.publication.take().expect("matching publication"));
            let mut retry = RecoveryCohortCauseList::default();
            let mut causes = std::mem::take(&mut generation.causes);
            while let Some(cause) = causes.pop_front() {
                let outcome = cause.demand.settle_post_terminal(attempt);
                if matches!(
                    outcome,
                    crate::runtime::peer_session::RecoveryDemandSettlement::Unsatisfied
                        | crate::runtime::peer_session::RecoveryDemandSettlement::PreTerminal
                ) {
                    retry.push_front(cause);
                } else {
                    let cause = *cause;
                    cause.release();
                }
            }
            cohort.pending.append(&mut retry);
            detached_publication
        };
        drop(detached_publication);
    }

    /// A usable replacement for this device supersedes every older exact
    /// demand.  The removal is keyed by device only for cancellation; no
    /// device lookup is used to settle a terminal demand.
    pub(crate) fn cancel_recovery_demands_for_device(&self, device_id: &str) {
        let (mut cancelled, detached_publication) = {
            let mut cohort = self.recovery_cohort.lock();
            let mut cancelled = RecoveryCohortCauseList::default();
            let mut pending = std::mem::take(&mut cohort.pending);
            let mut retained = RecoveryCohortCauseList::default();
            while let Some(cause) = pending.pop_front() {
                if cause.owner.device_id() == device_id {
                    cancelled.push_front(cause);
                } else {
                    retained.push_front(cause);
                }
            }
            cohort.pending = retained;
            if let Some(generation) = cohort.in_flight.as_mut() {
                let mut causes = std::mem::take(&mut generation.causes);
                let mut retained = RecoveryCohortCauseList::default();
                while let Some(cause) = causes.pop_front() {
                    if cause.owner.device_id() == device_id {
                        cancelled.push_front(cause);
                    } else {
                        retained.push_front(cause);
                    }
                }
                generation.causes = retained;
            }
            let empty_generation = cohort
                .in_flight
                .as_ref()
                .is_some_and(|generation| generation.causes.is_empty());
            let generation_id = empty_generation.then(|| {
                cohort
                    .in_flight
                    .take()
                    .expect("empty recovery generation")
                    .id
            });
            if let Some(id) = generation_id {
                if cohort.queued_publication == Some(id) {
                    cohort.queued_publication = None;
                }
            }
            let detached_publication = generation_id.and_then(|id| {
                cohort
                    .publication
                    .as_ref()
                    .is_some_and(|publication| publication.id == id)
                    .then(|| cohort.publication.take().expect("matching publication"))
            });
            (cancelled, detached_publication)
        };
        drop(detached_publication);
        while let Some(cause) = cancelled.pop_front() {
            let cause = *cause;
            cause.cancel();
        }
    }

    /// Shutdown owns all remaining provider custody and releases it exactly
    /// once, outside the pending-map lock.
    pub(crate) fn cancel_all_recovery_demands(&self) {
        let (mut demands, detached_publication) = {
            let mut cohort = self.recovery_cohort.lock();
            let mut demands = std::mem::take(&mut cohort.pending);
            if let Some(mut generation) = cohort.in_flight.take() {
                let mut causes = std::mem::take(&mut generation.causes);
                demands.append(&mut causes);
            }
            cohort.queued_publication = None;
            (demands, cohort.publication.take())
        };
        drop(detached_publication);
        while let Some(cause) = demands.pop_front() {
            let cause = *cause;
            cause.cancel();
        }
    }

    /// Intent ids whose backoff is due now. Drops expired intents (past the
    /// reconnecting grace) and advances the backoff of the ones returned, so
    /// the state-watch tick re-offers each at most once per backoff step.
    #[cfg(test)]
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
                let _ = self.queue_recovery_announce();
                true
            }
            None => {
                let _ = self.queue_recovery_announce();
                false
            }
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
            let due = guard.is_none_or(|prev| {
                now.duration_since(prev)
                    >= std::time::Duration::from_millis(RELAY_RESCUE_MIN_INTERVAL_MS)
            });
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

    /// Open one realtime flow on `peer`'s current session, native half included.
    ///
    /// Takes an already-validated connector spec: the provider's own
    /// configuration is parsed and refused at the public boundary, before any
    /// session is resolved, so an unusable request never reaches the fence and
    /// the engine never inspects what a provider's vocabulary means.
    ///
    /// **This is the only realtime operation that resolves a Device selector,
    /// and it resolves it exactly once.** `peer` names an installation to look
    /// up; everything that authorizes the open is produced inside the fence at
    /// the moment of use. From the first line onwards the operation carries the
    /// [`PeerOwnerToken`] that resolution produced, and phase 3 and the
    /// abandonment path re-enter the fence with *that* rather than with the
    /// name — so a replacement landing mid-open fails a pointer check instead of
    /// being resolved to and quietly committed onto.
    ///
    /// A resolution failure is reported as `SessionNotCurrent` rather than a
    /// distinct "no such peer" — an unknown selector, a replaced installation
    /// and an unpromoted peer are the same fact from the caller's side, and
    /// separating them would leak peer-existence to a caller that has proved
    /// nothing.
    ///
    /// Three phases, because the fence is a synchronous lock that connector
    /// replacement also takes and the native operations await. Nothing is held
    /// across an await, and nothing is trusted across one either — the handle
    /// carried through phase 2 grants nothing, and phase 3 re-proves the same
    /// facts rather than assuming they survived.
    ///
    /// 1. **In the fence:** claim the label, capture the exact flow record it
    ///    produced, and for an inbound flow mint the track identity and bind it,
    ///    so the claim and the binding are one atomic step. That ordering is
    ///    what removes the start window: any track that can arrive under that
    ///    identity has a binding before the transceiver carrying it exists.
    ///    Capture the worker and the flow-set identity, then release.
    /// 2. **No locks:** create the native transceiver or track.
    /// 3. **Back in the fence, against the same owner:** prove it is the same
    ///    flow set, then attach the outbound track. An inbound flow has nothing
    ///    left to commit.
    ///
    /// The flow-set check in phase 3 is not redundant with having carried the
    /// owner. The owner proves the installation is the one this open started
    /// against; the flow set proves the *session* is, which is the finer
    /// question and the one the committed track actually belongs to. Same window
    /// as the one the arrivals stream check closes, one call earlier.
    ///
    /// Answers a [`crate::realtime::RealtimeFlowHandle`], and only from facts
    /// captured inside the fence: the owner, the flow-set identity and the flow
    /// record. The name travels in it as a wire coordinate. Nothing in the
    /// handle can be re-derived afterwards from a selector, which is the whole
    /// difference from the coordinate-based API it replaces.
    ///
    /// Every refusal releases both halves: the flow and its label through the
    /// fence, the native object through the connector. Nothing is retried and
    /// nothing is timed.
    /// Takes `&Arc<Self>` rather than `&self` for one reason: the handle this
    /// mints closes its flow when it is dropped, and the only honest way to
    /// reach this engine from a `Drop` that owns nothing is a weak reference to
    /// it. Downgrading requires the `Arc`, and every caller already has one.
    pub(crate) async fn open_realtime_negotiated(
        self: &Arc<Self>,
        peer: &str,
        spec: RealtimeFlowSpec,
    ) -> std::result::Result<crate::realtime::RealtimeFlowHandle, crate::realtime::RealtimeRefusal>
    {
        let encoding = spec.encoding.clone();
        // The one resolution. Everything after this names the installation it
        // produced, never the bytes it was produced from.
        let Some(owner) = self.peers.owner(peer) else {
            return Err(crate::realtime::RealtimeRefusal::SessionNotCurrent);
        };

        // Phase 1.
        let (name, flow, worker, flow_set, identity, validity) = self
            .with_owned_realtime_flows_and_worker(&owner, |session, flows, live, worker| {
                let inbound = spec.direction == RealtimeDirection::Inbound;
                let name = flows.open(session, Some(live), spec)?;
                // Taken from the record `open` just filed, not from the name it
                // spells, and taken here so it exists before anything below can
                // release the fence. A handle built from a later lookup would
                // name whatever held the name at that later moment, which is the
                // defect this whole path exists to remove.
                let Some(flow) = flows.flow_identity(&name) else {
                    let _ = flows.close(session, Some(live), &name);
                    return Err(RealtimeFlowError::FlowRefused);
                };
                let identity = if inbound {
                    // Minted by the connector, not here. The identity is a
                    // connector-scoped allocation and the engine has no scope to
                    // fund one; asking for it is all this side does.
                    let Ok(identity) = worker.mint_inbound_realtime_identity() else {
                        let _ = flows.close(session, Some(live), &name);
                        return Err(RealtimeFlowError::FlowRefused);
                    };
                    // Minted here and moved into the flow, so from the bind
                    // onwards the flow — not this function, and not a later
                    // caller who remembers — is what owes the transceiver its
                    // retirement.
                    //
                    // It can refuse, and refusing here is the point: the
                    // retirement's cleanup is funded at this moment, so a
                    // connector that could not afford to retire the transceiver
                    // never negotiates one. The flow and its name go back the
                    // same way a refused bind returns them.
                    let retirement = match worker.inbound_realtime_retirement(Arc::clone(&identity))
                    {
                        Ok(retirement) => retirement,
                        Err(_) => {
                            let _ = flows.close(session, Some(live), &name);
                            return Err(RealtimeFlowError::FlowRefused);
                        }
                    };
                    // A bind that fails leaves a flow holding a name against a
                    // negotiation that will never happen, so the name goes back
                    // now rather than at the next open that collides with it.
                    if let Err(error) = flows.bind_inbound(
                        session,
                        Some(live),
                        &name,
                        Arc::clone(&identity),
                        retirement,
                    ) {
                        let _ = flows.close(session, Some(live), &name);
                        return Err(error);
                    }
                    Some(identity)
                } else {
                    None
                };
                Ok((
                    name,
                    flow,
                    Arc::clone(worker),
                    flows.identity(),
                    identity,
                    session.validity_witness(),
                ))
            })?;
        let owner = owner.for_worker(Arc::clone(&worker));

        // Phase 2. Branching on the minted identity rather than re-deriving the
        // direction: the two must not be able to disagree.
        let native = tokio::select! {
            biased;
            () = validity.revoked() => Err(crate::error::Error::Transport(
                "the session authorizing this realtime open was revoked".into(),
            )),
            native = async {
                match identity.as_ref() {
                    Some(identity) => worker
                        .open_inbound_realtime_transceiver(identity, &encoding)
                        .await
                        .map(|()| None),
                    None => worker
                        .open_outbound_realtime_track(&encoding)
                        .await
                        .map(Some),
                }
            } => native,
        };
        let Ok(mut track) = native else {
            // The connector cleaned up its own failed construction; what is
            // left is the flow, its name, and — for an inbound open — a
            // binding to an identity nothing will ever present.
            self.abandon_realtime_open(&owner, &flow_set, &name).await;
            return Err(crate::realtime::RealtimeRefusal::FlowRefused);
        };

        // Phase 3. The track is taken from `track` only on the path that
        // attaches it, so whatever remains afterwards is a native object this
        // side still owns and must release.
        let committed = self.with_owned_realtime_flows(&owner, |session, flows, live| {
            if !flows.is_same(&flow_set) {
                return Err(RealtimeFlowError::SessionNotCurrent);
            }
            match track.take() {
                Some(outbound) => flows
                    .attach_outbound(session, Some(live), &name, outbound)
                    .map_err(|(error, outbound)| {
                        track = Some(outbound);
                        error
                    }),
                // Inbound: bound in phase 1, so there is nothing to commit and
                // nothing that could half-commit.
                None => Ok(()),
            }
        });

        if let Some(outbound) = track {
            worker.close_outbound_realtime_track(outbound).await;
        }
        match committed {
            // Built only now, and only from values phase 1 captured under the
            // fence: the owner that resolution produced, the flow set that
            // answered, and the record `open` filed. None of the three is
            // re-derivable from the selector this call was given.
            Ok(()) => Ok(crate::realtime::RealtimeFlowHandle::new(
                owner,
                flow_set,
                flow,
                name,
                Arc::downgrade(self),
            )),
            Err(error) => {
                // Ordered so the caller does not return before the transceiver
                // is retired. If the flow set is still ours, `abandon` closed
                // the flow and the close handed the retirement back, so it has
                // already been retired and awaited. If it is not ours, the flow
                // died with the set that owned it — and its retirement went
                // with it, which submits, but fire-and-forget. This awaits the
                // same retirement through the identity minted in phase 1, and
                // the claim makes the two the same single stop.
                if !self.abandon_realtime_open(&owner, &flow_set, &name).await {
                    if let Some(identity) = identity.as_ref() {
                        worker.close_inbound_realtime_transceiver(identity).await;
                    }
                }
                Err(error.into())
            }
        }
    }

    /// Hand one unit to the outbound flow a handle names.
    ///
    /// Takes the connector's unit, already converted at the public boundary:
    /// the engine moves bytes between a handle and a flow and never reads what a
    /// unit carries.
    ///
    /// **Borrows the handle and resolves nothing.** The fence is entered with
    /// the installation the flow was opened on, then the handle's two identities
    /// are proved against the set that answered. A caller whose session has been
    /// replaced, or whose label has been closed and reopened, is refused here.
    /// Resolving by name instead would enqueue into the successor's flow of the
    /// same name and tell nobody, because nothing on this path is acknowledged
    /// per unit.
    pub(crate) fn send_realtime(
        &self,
        handle: &crate::realtime::RealtimeFlowHandle,
        unit: RealtimeSendUnit,
    ) -> std::result::Result<(), crate::realtime::RealtimeRefusal> {
        self.with_owned_realtime_flows(handle.owner(), |session, flows, live| {
            Self::handle_names_live_flow(flows, handle)?;
            flows.send(session, Some(live), handle.name(), unit)
        })
        .map_err(Into::into)
    }

    /// Close one flow and retire the native half it was standing on.
    ///
    /// The mirror of [`Self::open_realtime_negotiated`], and async for the same
    /// reason: releasing a transceiver or a sender awaits, and the fence is a
    /// synchronous lock. Phase 1 closes the flow and carries out both the exact
    /// worker and whatever the flow still owned; phase 2 retires it with no
    /// lock held.
    ///
    /// **Whole-connector retirement is deliberately not relied on.** The same
    /// worker may host a replacement session, so a flow's native half can
    /// outlive the flow while the connector it belongs to stays perfectly
    /// healthy. Retiring per flow is the only thing that tracks the flow's own
    /// lifetime.
    ///
    /// The label is released at the end of phase 1, so a re-open can claim it
    /// before the stop lands. That is safe rather than merely tolerated: the
    /// new flow mints its own identity and `close` has already removed the old
    /// one from the bindings table, so a track arriving on the stale
    /// transceiver has nothing to attach to and is refused. What it still costs
    /// until phase 2 finishes is an m-line and bandwidth — which is why the
    /// caller awaits this rather than being told the flow is gone while it is
    /// not.
    /// **Consumes the handle**, because a close is the end of the thing the
    /// handle names. Taking it by value is what makes "closed twice" and "closed
    /// then sent on" unrepresentable rather than merely refused, and it is why
    /// closing A cannot close B after an immediate reuse of A's label: the
    /// identities travelled with the handle, and B's flow is a different record.
    pub(crate) async fn close_realtime_negotiated(
        &self,
        mut handle: crate::realtime::RealtimeFlowHandle,
    ) -> std::result::Result<(), crate::realtime::RealtimeRefusal> {
        // Before anything, and unconditionally. This call is the close, so the
        // handle's own drop-close must not run behind it — on the success path
        // it would be a second close of a record this one removed, and on the
        // refusal path there is nothing to close: every way this refuses is a
        // way the flow was already not ours.
        handle.disarm();
        let (worker, remains) = self.with_owned_realtime_flows_and_worker(
            handle.owner(),
            |session, flows, live, worker| {
                Self::handle_names_live_flow(flows, &handle)?;
                let remains = flows.close(session, Some(live), handle.name())?;
                Ok((Arc::clone(worker), remains))
            },
        )?;
        retire_realtime_remains(&worker, remains).await;
        Ok(())
    }

    /// Close the flow an abandoned handle named, telling nobody.
    ///
    /// The drop half of [`Self::close_realtime_negotiated`], and deliberately
    /// only its phase 1. Phase 2 is an await this cannot perform and does not
    /// need to: `close` hands back a [`RealtimeFlowRemains`], and both of its
    /// arms retire what they hold when they are dropped — which is what happens
    /// to the value below. The difference between this and an explicit close is
    /// therefore the acknowledgement, not the retirement.
    ///
    /// Every refusal is discarded, because each one means the flow is already
    /// gone: a stale owner, a session that has been replaced, a label closed and
    /// reopened. There is no caller left to tell, and nothing here to undo.
    pub(crate) fn abandon_realtime_flow(&self, handle: &crate::realtime::RealtimeFlowHandle) {
        // Dropped, not ignored: this value *is* the retirement, and naming it
        // is how that reads as the retirement happening rather than as a result
        // being thrown away.
        drop(
            self.with_owned_realtime_flows(handle.owner(), |session, flows, live| {
                Self::handle_names_live_flow(flows, handle)?;
                flows.close(session, Some(live), handle.name())
            }),
        );
    }

    /// Whether that handle still names a usable flow.
    ///
    /// Borrows rather than consumes: asking is not using, and a caller that
    /// learns `false` still has to drop its handle, which costs nothing.
    pub(crate) fn realtime_is_current(&self, handle: &crate::realtime::RealtimeFlowHandle) -> bool {
        self.with_owned_realtime_flows(handle.owner(), |session, flows, live| {
            Self::handle_names_live_flow(flows, handle)?;
            Ok(flows.is_current(session, Some(live), handle.name()))
        })
        .unwrap_or(false)
    }

    /// Deliver one inbound realtime unit onto the flow it names.
    ///
    /// The connector half resolved which flow the track belongs to and
    /// assembled the unit; this half proves the flow set is still one this
    /// engine may write to. Both halves are needed and neither substitutes for
    /// the other: a binding table says *which* flow, and only the fence says
    /// *whether* — the exact owner installation, the current session, and a
    /// freshly acquired live incarnation, all under the mutation lock the
    /// replacement path also takes.
    ///
    /// Synchronous throughout. Nothing here awaits, so the currency proof and
    /// the enqueue are one step against connector replacement rather than two
    /// with a window between them.
    ///
    /// Every failure drops the unit and releases its payload reservation, and
    /// does so without a branch: the delivery moves into the closure, so a fence
    /// that refuses before running it drops it, and `deliver_inbound` drops it
    /// itself when the flow is gone or when it carries no lease. Answers whether
    /// the unit was taken — `false` for a stale owner, an ended session, an
    /// absent flow, or an unaccounted delivery, which are one fact to the
    /// connector: it has nothing left to do either way.
    ///
    /// **The delivery is carried whole and never split here.** Its three parts
    /// include a payload lease, which is a `transport::webrtc` type and stays
    /// one: an engine holding a bare lease could release the bytes' accounting
    /// separately from the unit they belong to, and there is no reason for this
    /// layer to be able to. What crosses is one opaque value that either lands
    /// on a flow or is dropped intact.
    pub(crate) fn deliver_realtime_unit(
        &self,
        owner: &PeerOwnerToken,
        delivery: crate::transport::webrtc::RealtimeInboundDelivery,
    ) -> bool {
        self.peers
            .with_live_session_flow(
                owner,
                self.session_broker.as_ref(),
                &self.network_id,
                move |_session, flows, _live| flows.deliver_inbound(delivery),
            )
            .unwrap_or(false)
    }

    /// Claim the inbound stream of `peer`'s current session.
    ///
    /// `None` covers both "no live session" and "already claimed", for the same
    /// reason every other operation collapses resolution failures: the caller
    /// has proved nothing, so it learns only that it does not have the stream.
    ///
    /// Synchronous on purpose. The claim happens inside the fence, and the
    /// reader it produces borrows nothing from the flow set, so the caller
    /// leaves the lock behind before it ever awaits.
    pub(crate) fn claim_realtime_inbound(
        &self,
        peer: &str,
    ) -> Option<crate::realtime::RealtimeInboundStream> {
        let reader = self
            .with_realtime_flows(peer, |_session, flows, _live| Ok(flows.inbound_arrivals()))
            .ok()
            .flatten()?;
        // Only the reader crosses. The selector did its work resolving the
        // session here and has nothing left to say: the reader already names the
        // one queue that session's flow set owns, so carrying the bytes along
        // would be a second copy of a binding the handle already has.
        Some(crate::realtime::RealtimeInboundStream::new(reader))
    }

    /// The next unit to arrive on any inbound flow of that session.
    ///
    /// **Nothing is held, and no fence is entered.** The reader takes whole
    /// units from the one queue its own flow set owns, so there is nothing left
    /// for a fence to establish: the unit was funded, retained and handed over
    /// by that set, and no session but that one can put anything into it.
    ///
    /// That is what makes this a single step rather than a loop. Awaiting a
    /// *name* and resolving it afterwards left a window a replacement could land
    /// in — the same bytes name a different flow on a different session, and the
    /// fence would resolve the replacement quite correctly and hand back a real
    /// unit belonging to something else. There is no name to resolve here.
    ///
    /// `None` is terminal and means the session ended: the flow set was dropped,
    /// so its queue was, so the reader is done. There is no retirement event to
    /// consume; a caller that gets `None` closes.
    ///
    /// What leaves this bridge is a copy of the label's bytes, made once. The
    /// leased label stays inside the connector, because a consumer holding one
    /// would be an untracked holder of the session's lease — and the copy is
    /// taken in the form the caller publishes, so the name is not allocated
    /// twice on the way out.
    pub(crate) async fn next_realtime_arrival(
        &self,
        inbound: &crate::realtime::RealtimeInboundStream,
    ) -> Option<(Vec<u8>, RealtimeRecvUnit)> {
        let (label, unit) = inbound.reader().next().await?;
        Some((label.name().as_bytes().to_vec(), unit))
    }

    /// The worker-lending fence, entered against an owner the caller already
    /// holds.
    ///
    /// **No selector is resolved here, and there is no variant that does.**
    /// [`Self::with_realtime_flows`] is the only realtime fence that turns a
    /// Device name into whichever installation answers to it now, and only two
    /// operations may do that: opening a flow, and claiming a session's inbound
    /// stream. Everything with a native half enters here instead, with the
    /// installation the operation started against, so a replacement fails a
    /// pointer check rather than being resolved to.
    fn with_owned_realtime_flows_and_worker<T>(
        &self,
        owner: &PeerOwnerToken,
        effect: impl FnOnce(
            &crate::runtime::session_broker::SessionCapability,
            &mut SessionRealtimeFlows,
            &Arc<crate::connector::ConnectorIncarnation>,
            &Arc<crate::transport::WebRtcConnectorWorker>,
        ) -> std::result::Result<T, RealtimeFlowError>,
    ) -> std::result::Result<T, RealtimeFlowError> {
        self.peers
            .with_live_session_flow_and_worker(
                owner,
                self.session_broker.as_ref(),
                &self.network_id,
                effect,
            )
            .unwrap_or(Err(RealtimeFlowError::SessionNotCurrent))
    }

    /// The flow-set-only fence, entered against an owner the caller already
    /// holds.
    ///
    /// The synchronous twin of [`Self::with_owned_realtime_flows_and_worker`],
    /// for the send path — which must not await and has no native half to reach.
    fn with_owned_realtime_flows<T>(
        &self,
        owner: &PeerOwnerToken,
        effect: impl FnOnce(
            &crate::runtime::session_broker::SessionCapability,
            &mut SessionRealtimeFlows,
            &Arc<crate::connector::ConnectorIncarnation>,
        ) -> std::result::Result<T, RealtimeFlowError>,
    ) -> std::result::Result<T, RealtimeFlowError> {
        self.peers
            .with_live_session_flow(
                owner,
                self.session_broker.as_ref(),
                &self.network_id,
                effect,
            )
            .unwrap_or(Err(RealtimeFlowError::SessionNotCurrent))
    }

    /// Prove a handle still names a live flow, inside a fence already entered.
    ///
    /// Two questions, both against identity and neither against bytes.
    ///
    /// The flow set names the **exact promoted session**. The owner the fence
    /// was entered with names the installation, and those are not the same
    /// statement: one installation promotes one session today — the entry
    /// admits a single endpoint-auth task, that task a single capability, and
    /// promotion consumes it — but that is a property of the promotion path,
    /// not of this one. Asking the direct question costs a pointer comparison
    /// and does not have to be revisited when the promotion path changes.
    ///
    /// The flow record rules out a **replacement flow inside the same session**,
    /// which the flow-set check cannot see at all: closing a name and reopening
    /// it changes neither the session nor the set, only the record.
    ///
    /// Both refusals are `SessionNotCurrent`, which is the honest answer in both
    /// cases and deliberately the same one. A caller holding a stale handle has
    /// no live flow, and telling it *why* would report on a flow it has no
    /// standing to learn about — the one that took the name.
    fn handle_names_live_flow(
        flows: &SessionRealtimeFlows,
        handle: &crate::realtime::RealtimeFlowHandle,
    ) -> std::result::Result<(), RealtimeFlowError> {
        if !flows.is_same(handle.flow_set()) || !flows.is_same_flow(handle.name(), handle.flow()) {
            return Err(RealtimeFlowError::SessionNotCurrent);
        }
        Ok(())
    }

    /// Close a flow whose native half never came up, releasing its label and
    /// retiring whatever the flow still owned.
    ///
    /// Answers whether it did the retiring, so a caller holding its own handle
    /// on the native object knows not to retire it a second time.
    ///
    /// `false` also covers the case where the fence no longer resolves the same
    /// flow set. The flow and its label went with the session that owned them —
    /// which is the state this was trying to reach — but the native half did
    /// not, so the caller still has work to do.
    ///
    /// Enters against the **owner the open resolved**, never the selector it was
    /// given. Cleaning up after a failed open by re-resolving a Device name
    /// would be the same defect as sending by one: the flow this is trying to
    /// release belongs to a particular installation, and a replacement that has
    /// since taken the name is not it. The flow-set check below then narrows
    /// that installation to the exact session.
    async fn abandon_realtime_open(
        &self,
        owner: &PeerOwnerToken,
        flow_set: &RealtimeFlowSetIdentity,
        name: &RealtimeFlowName,
    ) -> bool {
        let closed =
            self.with_owned_realtime_flows_and_worker(owner, |session, flows, live, worker| {
                if !flows.is_same(flow_set) {
                    return Err(RealtimeFlowError::SessionNotCurrent);
                }
                let remains = flows.close(session, Some(live), name)?;
                Ok((Arc::clone(worker), remains))
            });
        let Ok((worker, remains)) = closed else {
            return false;
        };
        retire_realtime_remains(&worker, remains).await;
        true
    }

    /// Resolve a Device selector to its live session and flow set, once.
    ///
    /// **The only realtime fence that resolves a name, and it has exactly one
    /// caller left**: claiming a session's inbound stream, which is a fresh
    /// question about whoever is current rather than an operation on something
    /// already open. (Opening a flow resolves too, but resolves for itself and
    /// keeps the owner, because it has two more fence acquisitions to make and
    /// must make them against the same installation.)
    ///
    /// The resolution rule is stated once, here: no live session means
    /// `SessionNotCurrent`, and the fence — not the caller — supplies both the
    /// session and the freshly acquired incarnation.
    fn with_realtime_flows<T>(
        &self,
        peer: &str,
        effect: impl FnOnce(
            &crate::runtime::session_broker::SessionCapability,
            &mut SessionRealtimeFlows,
            &Arc<crate::connector::ConnectorIncarnation>,
        ) -> std::result::Result<T, RealtimeFlowError>,
    ) -> std::result::Result<T, RealtimeFlowError> {
        let Some(owner) = self.peers.owner(peer) else {
            return Err(RealtimeFlowError::SessionNotCurrent);
        };
        self.peers
            .with_live_session_flow(
                &owner,
                self.session_broker.as_ref(),
                &self.network_id,
                effect,
            )
            .unwrap_or(Err(RealtimeFlowError::SessionNotCurrent))
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
            .map_err(|error| error.into_admission_error())?;
        rx.await
            .map_err(|_| Error::Network("engine dropped reply".into()))?
    }

    /// Broadcast a channel frame to every active peer. Returns
    /// the count of peers it was dispatched to.
    pub async fn broadcast_channel_frame(
        &self,
        channel: &str,
        payload: serde_json::Value,
    ) -> Result<usize> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(NetworkCmd::BroadcastChannelFrame {
                channel: channel.to_string(),
                payload,
                reply,
            })
            .map_err(|error| error.into_admission_error())?;
        rx.await
            .map_err(|_| Error::Network("engine dropped broadcast reply".into()))
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
    /// The public facade remains async, but the underlying roster mutation and
    /// file replacement contain no await point. The admitted handshake path
    /// uses this form while holding the exact peer-installation fence so a
    /// replacement cannot land between owner validation and persistence.
    pub(super) fn approve_roster_now(&self, device_id: &str, label: &str) -> Result<()> {
        let graph = self.fact_graph.read();
        let admitted = super::governance::canonical_policy_admits_from(
            &self.verified_bootstrap,
            &graph,
            self.identity.public_id(),
            device_id,
        );
        drop(graph);
        if !admitted {
            return Err(Error::Network(
                "Closed membership requires a signed governance grant".into(),
            ));
        }
        // Defense in depth behind the handshake's eviction gate: on a
        // closed network a device the signed state evicted can't be
        // rostered by ANY path — not mutual-ACTIVE persistence, not a
        // manual approve from a stale UI. Re-admission is a signed member
        // grant (the owner re-claiming it), which flips the verdict first.
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
        self.peers
            .collect_map(|peer| Some(peer.with_peer_view(Self::peer_info_from_view)))
    }

    /// Build one [`crate::handle::PeerInfo`] from a single coherent observation.
    ///
    /// Both public snapshot paths go through here, so they cannot drift and
    /// neither can pair a stale advert with fresh state — the view's session and
    /// data halves were read together.
    ///
    /// Reads exactly the fields `PeerInfo` publishes. The shape this replaces
    /// went through `PeerStateSnapshot`, which cloned the whole `PeerDiag` so
    /// that two of its counters could be projected and the rest discarded; the
    /// wire result is identical and the clone is gone.
    fn peer_info_from_view(view: super::connection::PeerView<'_>) -> crate::handle::PeerInfo {
        let data = view.data;
        let pubkey = crate::signing::pubkey_part(view.device_id);
        crate::handle::PeerInfo {
            device_id: view.device_id.to_string(),
            status: data.status,
            tier: data.tier,
            rtt_ms: data.rtt_ms,
            clock_skew_ms: data.clock_skew_ms,
            label: data.label.clone(),
            capabilities: view.session.and_then(|app| app.capabilities()),
            local_shelved: data.local_shelved,
            remote_shelved: data.remote_shelved,
            authenticated: data.authenticated,
            device_suffix: crate::identity::display_suffix(pubkey.as_bytes()),
            verification_code_received: data.verification_code_received.clone(),
            verification_code_sent: data.verification_code_sent.clone(),
            local_approve_sent: data.local_approve_sent,
            remote_approve_seen: data.remote_approve_seen,
            needs_turn: data.no_turn_diag_emitted,
            // Cloned because `IceCandidateStats` is not `Copy`. It is five
            // `u32`s with no heap under them, so the clone is the copy the
            // compiler would have made — and still strictly less than the shape
            // this replaced, which cloned the whole `PeerDiag` to project two
            // of its fields.
            local_candidates: data.diag.local_candidates.clone(),
            remote_candidates: data.diag.remote_candidates.clone(),
            selected_pair: data.selected_pair,
        }
    }

    /// Plan a funded peers snapshot.
    /// Per-peer detail. Returns `None` if the peer is not in the
    /// engine's map.
    pub fn peer_info(&self, device_id: &str) -> Option<crate::handle::PeerInfo> {
        Some(
            self.peers
                .get(device_id)?
                .with_peer_view(Self::peer_info_from_view),
        )
    }

    /// Tear down every active peer session. Called from the
    /// driver's shutdown path.
    pub(crate) async fn shutdown(&self) {
        self.request_shutdown();
        self.cancel_all_recovery_demands();
        // Keep the published runtime alive while every retired connector has
        // finished releasing its exact de-duplication custody.  The field is
        // cleared only after this is the last shutdown consumer of it.
        let runtime = self.signaling_runtime();
        let retired = self.peers.retire_all();
        for peer in &retired {
            self.settle_attempt(
                &peer.attempt(),
                myownmesh_signaling::nostr::delivery::DeliveryTerminal::Cancelled,
            );
            if let Err(error) = peer.retire_and_close().await {
                tracing::warn!(%error, peer = %peer.device_id, "peer cleanup failed during shutdown");
            }
            if let Some(runtime) = runtime.as_ref() {
                for token in peer.take_retired_dedup() {
                    runtime.forget_token(token);
                }
            }
        }
        self.peers.await_replaced_closes().await;
        drop(retired);
        drop(runtime);
        self.signaling_runtime.write().take();
        self.clear_attempt_settlement();
        for forwarder in self.take_local_signaling_forwarders() {
            if let Err(error) = forwarder.await {
                tracing::warn!(%error, "local signaling forwarder failed during shutdown");
            }
        }
        // Nothing outlives the engine: parked connect waits resolve with the
        // truth instead of hanging.
        //
        // Queued reliable sends need no pass of their own here, and that is the
        // point of moving them. `retire_and_close` above drops each peer's
        // promoted session, which drops the record that retained them, which
        // resolves every waiting caller — before this function even reaches the
        // connect waiters. A separate shutdown sweep would be a second place
        // that has to remember, and the one that is forgotten is the one that
        // leaves a caller hanging.
        let waiting: Vec<String> = self.connect_waiters.lock().keys().cloned().collect();
        for peer in waiting {
            self.resolve_connect_waiters(&peer, Some("network shut down"));
        }
        self.application_gateway.close();
    }

    /// Publish a carrier departure observation. Fire-and-forget, like every
    /// other signaling publish: the message is handed to the signaling driver
    /// and rides the relays best-effort. This does not own or retire any peer
    /// session; [`crate::JoinedNetwork::announce_leave`] first performs the
    /// authenticated-session departure protocol, then publishes this hint
    /// while the signaling driver still exists.
    pub fn announce_departure(&self) {
        if let Err(error) = self.signaling_tx.send(SignalingOutbound::Leave) {
            tracing::warn!(error = %error.into_admission_error(), "departure announcement was refused");
        }
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
        if let Err(error) = self.cmd_tx.send(NetworkCmd::Reconnect { peer }) {
            tracing::warn!(error = %error.into_admission_error(), "reconnect command was refused");
        }
    }

    /// Queue a deliberate offerer-side dial of exactly one peer on the engine
    /// driver. The manual-connect primitive a `Silent` network needs: on a
    /// Silent mesh the engine never auto-dials on presence, so a session is
    /// opened only here (or by answering an inbound offer). Fire-and-forget,
    /// like [`Self::reconnect`]; the work runs on the driver via
    /// [`NetworkCmd::ConnectPeer`]. Backs [`crate::JoinedNetwork::connect_peer`].
    pub fn connect_peer(&self, device_id: &str) {
        if let Err(error) = self.cmd_tx.send(NetworkCmd::ConnectPeer {
            device_id: device_id.to_string(),
            sticky: false,
            reply: None,
        }) {
            tracing::warn!(error = %error.into_admission_error(), peer = %device_id, "connect command was refused");
        }
    }

    /// Deliberately dial one peer and resolve when the link reaches
    /// ACTIVE (or fail with the terminal reason). `sticky` records a
    /// standing dial: the engine re-dials on every announce and holds a
    /// never-expiring reconnect intent — the "support session" contract
    /// on a Silent network. The returned future is bounded only by the
    /// caller's own timeout.
    pub async fn connect_peer_wait(&self, device_id: &str, sticky: bool) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        let id = self
            .next_connect_waiter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        self.cmd_tx
            .send(NetworkCmd::ConnectPeer {
                device_id: device_id.to_string(),
                sticky,
                reply: Some(ConnectWaiterRegistration {
                    id,
                    reply,
                    cancelled: Arc::clone(&cancelled),
                }),
            })
            .map_err(|error| error.into_admission_error())?;
        let mut cancellation = ConnectWaitCancellation {
            state: self,
            device_id: device_id.to_string(),
            id,
            cancelled,
            armed: true,
        };
        let result = rx
            .await
            .map_err(|_| Error::Network("engine dropped the connect wait".into()))?;
        cancellation.armed = false;
        result
    }

    /// Retain a frame for acknowledged delivery to `peer` — see
    /// [`NetworkCmd::SendChannelReliable`] for the contract. Resolves on the
    /// peer's cumulative acknowledgement; errs on refusal at submission, or when
    /// the session retaining it ends before the peer acknowledges.
    pub async fn send_channel_reliable(
        &self,
        peer: &str,
        channel: &str,
        payload: serde_json::Value,
    ) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(NetworkCmd::SendChannelReliable {
                peer: peer.to_string(),
                channel: channel.to_string(),
                payload,
                reply,
            })
            .map_err(|error| error.into_admission_error())?;
        rx.await
            .map_err(|_| Error::Network("engine dropped the reliable send".into()))?
    }

    /// Point-in-time traffic accounting for this network, with the
    /// acked-delivery backlog folded in — the number an operator (or a
    /// topology experiment) compares across configurations.
    pub fn traffic_snapshot(&self) -> super::traffic::TrafficSnapshot {
        let mut snap = self.traffic.snapshot();
        snap.reliable_pending = self.peers.reliable_pending_total() as u64;
        snap
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
        waiter: ConnectWaiterRegistration,
    ) {
        let mut waiters = self.connect_waiters.lock();
        if waiter.cancelled.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        waiters
            .entry(device_id.to_string())
            .or_default()
            .push(waiter);
    }

    fn cancel_connect_waiter(&self, device_id: &str, id: u64) {
        let mut waiters = self.connect_waiters.lock();
        if let Some(peer_waiters) = waiters.get_mut(device_id) {
            peer_waiters.retain(|waiter| waiter.id != id);
            if peer_waiters.is_empty() {
                waiters.remove(device_id);
            }
        }
    }

    #[cfg(test)]
    pub(super) fn connect_waiter_count_for_test(&self, device_id: &str) -> usize {
        self.connect_waiters
            .lock()
            .get(device_id)
            .map_or(0, Vec::len)
    }

    /// Resolve every waiter parked on `device_id`. `error == None`
    /// resolves Ok; otherwise each waiter gets the reason.
    pub(crate) fn resolve_connect_waiters(&self, device_id: &str, error: Option<&str>) {
        let waiters = self.connect_waiters.lock().remove(device_id);
        let Some(waiters) = waiters else { return };
        for waiter in waiters {
            let result = match error {
                None => Ok(()),
                Some(e) => Err(Error::Network(format!("connect {device_id}: {e}"))),
            };
            let _ = waiter.reply.send(result);
        }
    }

    /// True when this network uses local `Silent` connection policy. The load-bearing
    /// predicate for the two Silent behaviours: the engine suppresses
    /// auto-dial-on-presence (see `handle_signaling_inbound`) and roster
    /// gossip (see [`super::governance::broadcast_roster_summary`]). This is
    /// not a durable semantic governance kind.
    pub fn is_silent(&self) -> bool {
        matches!(
            self.config.read().kind,
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
        .map_or(0, |d| d.as_millis() as u64)
}

#[cfg(test)]
mod arc03_peer_registry_tests {
    use super::*;
    use crate::engine::connection::{PeerConnection, PeerStatus};
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
                // The shape this harness exists to measure against: materialize a
                // keyed pair for every peer, then filter. Its cost is one id clone
                // per peer whether or not the peer survives the filter, plus the
                // intermediate vector. Reconstructed from `values_snapshot` rather
                // than read out of the map directly — the registry key *is* the
                // peer's device id, so cloning the field is the same work as
                // cloning the key, and the comparison stays honest without the
                // benchmark reaching into registry internals.
                let snapshot: Vec<(String, Arc<PeerConnection>)> = registry
                    .values_snapshot()
                    .into_iter()
                    .map(|peer| (peer.device_id.clone(), peer))
                    .collect();
                let active: Vec<String> = snapshot
                    .into_iter()
                    .filter(|(_, peer)| peer.state.read().status == PeerStatus::Active)
                    .map(|(key, _)| key)
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
