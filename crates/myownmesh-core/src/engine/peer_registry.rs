//! The current peer installation map and the authorities minted under its
//! fence.
//!
//! One state class: which `PeerConnection` is installed under each device id
//! right now, and who is allowed to act on it. Three things live here and
//! nothing else does.
//!
//! * **The map.** [`PeerRegistry`] is the only owner that can install, replace,
//!   remove or retire a peer. Every ownership exit ends the connector worker,
//!   even when another task still holds an `Arc<PeerConnection>`.
//! * **The exact owner token.** [`PeerOwnerToken`] names one *installation*,
//!   not one device. A device id is a re-resolution key; a token is not, which
//!   is why every peer-reaching helper takes one.
//! * **The one-operation witnesses.** [`AdmittedSessionOperation`],
//!   [`AdmittedInboundApplicationOperation`], [`AdmittedInboundDispatch`],
//!   [`AdmittedApplicationOperation`] and [`AdmittedRenegotiation`] are minted
//!   under the mutation lock and bind the exact installation they were admitted
//!   for. An admission answer never becomes a boolean that outlives the
//!   acquisition that decided it.
//!
//! The mutation lock is the linearization point. A fence holds it across the
//! whole effect, so replacement orders strictly before or after and never
//! between a check and the act it authorized. Everything run under it must be
//! synchronous, non-reentrant, and free to hand a value off but not to await.

use std::sync::Arc;

use crate::error::{Error, Result};
use crate::resource::ResourceMailboxSender;
use crate::runtime::session_broker::SessionBroker;
use dashmap::DashMap;
use parking_lot::Mutex;

use super::connection::PeerConnection;

/// Narrow owner of the current peer set.
///
/// Callers can take owned read snapshots, but only this registry can install,
/// replace, remove, or retire peers. Every ownership exit explicitly ends the
/// connector worker even when another task retains an external
/// `Arc<PeerConnection>`.
pub(crate) struct PeerRegistry {
    peers: DashMap<String, PeerRegistryEntry>,
    mutation: Mutex<()>,
    governance: Arc<parking_lot::RwLock<crate::network_state::NetworkState>>,
    local_device_id: String,
    /// Where a newly minted session is announced.
    ///
    /// The engine's own command queue, so the announcement is handled by the
    /// driver after every lock here has been released — nothing runs, awaits or
    /// re-enters under the fence. A `OnceLock` because the queue is created
    /// alongside this registry and bound once during state construction, and
    /// because reading it costs no lock on a path that already holds one.
    ///
    /// Unbound in a bare registry, which is what the unit fixtures build: those
    /// promote and exercise the fence without a driver, and an announcement with
    /// nowhere to go is correctly dropped rather than being an error.
    promotion_tx: std::sync::OnceLock<ResourceMailboxSender<super::state::NetworkCmd>>,
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
        Self::new(
            Arc::new(parking_lot::RwLock::new(
                crate::network_state::NetworkState::default(),
            )),
            String::new(),
        )
    }
}

impl PeerRegistry {
    pub(super) fn new(
        governance: Arc<parking_lot::RwLock<crate::network_state::NetworkState>>,
        local_device_id: String,
    ) -> Self {
        Self {
            peers: DashMap::new(),
            mutation: Mutex::new(()),
            governance,
            local_device_id,
            promotion_tx: std::sync::OnceLock::new(),
        }
    }

    fn policy_admits(&self, remote_device_id: &str) -> bool {
        super::governance::current_policy_admits(
            &self.governance.read(),
            &self.local_device_id,
            remote_device_id,
        )
    }

    /// Apply one verified governance mutation and synchronously revoke every
    /// session the resulting projection no longer admits.
    ///
    /// The lock order is the live authority order: registry mutation first,
    /// governance second. Every application lender uses the same first lock, so
    /// no effect can occur between publishing the new projection and clearing
    /// its denied session. The closure is synchronous; callers perform roster
    /// mirrors, broadcasts and connector cleanup after this returns.
    pub(super) fn with_governance_commit<R>(
        &self,
        commit: impl FnOnce(&mut crate::network_state::NetworkState) -> R,
    ) -> R {
        let _mutation = self.mutation.lock();
        let (result, denied) = {
            let mut governance = self.governance.write();
            let result = commit(&mut governance);
            let local_admitted = super::governance::current_policy_admits(
                &governance,
                &self.local_device_id,
                &self.local_device_id,
            );
            let denied = self
                .peers
                .iter()
                .filter(|entry| {
                    !local_admitted
                        || !super::governance::current_policy_admits(
                            &governance,
                            &self.local_device_id,
                            &entry.value().peer.device_id,
                        )
                })
                .map(|entry| Arc::clone(&entry.value().peer))
                .collect::<Vec<_>>();
            (result, denied)
        };
        for peer in denied {
            peer.revoke_promoted_session();
        }
        result
    }

    /// Bind the queue newly minted sessions are announced on.
    ///
    /// Called once, during state construction, by the owner of both this
    /// registry and the command queue. Later calls are ignored rather than
    /// panicking: the binding is an identity this registry holds for its whole
    /// life, so a second one could only be the same queue again or a mistake,
    /// and neither is worth taking a process down for.
    pub(super) fn bind_promotion_sink(&self, tx: ResourceMailboxSender<super::state::NetworkCmd>) {
        let _ = self.promotion_tx.set(tx);
    }

    /// Promote if needed, announcing a session this call minted.
    ///
    /// **The one place promotion is reached from the fence**, so no entry point
    /// can promote without announcing. That is the whole reason it exists: the
    /// alternative is seven call sites that each have to remember, and the
    /// failure mode of forgetting one is a peer that never receives what its
    /// session was owed, silently and only on that path.
    ///
    /// The announcement is enqueued **synchronously, before returning**, so it
    /// cannot be lost to a task that never runs, and it carries the exact owner
    /// rather than a device id — a replacement resolves to a different token, so
    /// a command cannot be applied to a session that did not mint it.
    ///
    /// Nothing executes under the fence. Resource-backed admission stores the
    /// command and wakes the driver; it does not run the handler or await. If
    /// the provider refuses that one pending callback, the newly minted session
    /// is revoked before this fence reports it usable: a session that silently
    /// skipped its first application replay would not be the session callers
    /// were promised.
    fn promote_and_announce(
        &self,
        peer: &Arc<PeerConnection>,
        owner: &PeerOwnerToken,
        broker: &SessionBroker,
        mesh_context: &str,
    ) -> bool {
        let promotion = peer.promote_session_if_needed(
            broker,
            mesh_context,
            peer.state.read().is_admitted() && self.policy_admits(owner.device_id()),
        );
        if promotion == super::connection::Promotion::NewlyPromoted {
            if let Some(tx) = self.promotion_tx.get() {
                if tx
                    .send(super::state::NetworkCmd::ReplayCapabilities {
                        owner: owner.clone(),
                    })
                    .is_err()
                {
                    peer.revoke_promoted_session();
                    return false;
                }
            }
        }
        promotion.is_usable()
    }

    pub(super) fn get(&self, device_id: &str) -> Option<Arc<PeerConnection>> {
        self.peers
            .get(device_id)
            .map(|entry| Arc::clone(&entry.value().peer))
    }

    pub(crate) fn owner(&self, device_id: &str) -> Option<PeerOwnerToken> {
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

    /// Run one synchronous application operation, only while `owner` is the
    /// installed peer **and** that peer holds a live promoted session.
    ///
    /// This is the one admission linearization point. The owner check and the
    /// promotion — which itself proves the exact current connector, current
    /// policy, the local principal, and a held post-authentication reservation —
    /// are evaluated together under the registry mutation lock, and the witness
    /// that proves them is minted inside it. Replacement takes the same lock, so
    /// it orders strictly before or after the whole effect.
    ///
    /// `None` means the operation was not authorized. The caller deliberately
    /// cannot tell whether the owner was stale or the session was absent: an
    /// admission answer that escaped as a value would be exactly the transient
    /// boolean this replaces.
    ///
    /// Production callers all need one of the specialized arms below — the
    /// refusal arm, an owned witness, or a lent session — so this bare form
    /// exists only for controls that must ask the fence's question and nothing
    /// else. Widening it to a production entry point would be a way to observe
    /// admission without acting on it under the same acquisition.
    #[cfg(test)]
    pub(super) fn with_admitted_current<R>(
        &self,
        owner: &PeerOwnerToken,
        broker: Option<&SessionBroker>,
        mesh_context: &str,
        effect: impl FnOnce(&AdmittedSessionOperation<'_>) -> R,
    ) -> Option<R> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation) {
            return None;
        }
        let peer = &current.value().peer;
        if !self.promote_and_announce(peer, owner, broker?, mesh_context) {
            return None;
        }
        Some(effect(&AdmittedSessionOperation {
            peer,
            owner,
            _not_send: std::marker::PhantomData,
        }))
    }

    /// The same fence, session-gated, with an explicit refusal arm.
    ///
    /// Inbound application delivery is authorized by the same promoted session
    /// as outbound: a frame reaches the application only once this exact
    /// installation has a live session, so "the application receives no data
    /// before promotion" is enforced by the delivery path itself.
    ///
    /// `refused` receives the exact current peer and may only *record* — it
    /// authorizes nothing, because no witness exists on that arm. It exists so
    /// the inbound path can count a refused application frame under the same
    /// acquisition that refused it, instead of re-entering the registry and
    /// racing its own refusal. A missing broker refuses rather than returning
    /// `None`, because the peer is still the installed one: what failed is
    /// authorization, and the refusal arm is where that is counted. `None`
    /// means the owner is stale.
    pub(super) fn with_admitted_current_or_refused<R>(
        &self,
        owner: &PeerOwnerToken,
        broker: Option<&SessionBroker>,
        mesh_context: &str,
        admitted: impl FnOnce(&AdmittedSessionOperation<'_>) -> R,
        refused: impl FnOnce(&Arc<PeerConnection>) -> R,
    ) -> Option<R> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation) {
            return None;
        }
        let peer = &current.value().peer;
        let promoted = broker
            .is_some_and(|broker| self.promote_and_announce(peer, owner, broker, mesh_context));
        if !promoted {
            return Some(refused(peer));
        }
        Some(admitted(&AdmittedSessionOperation {
            peer,
            owner,
            _not_send: std::marker::PhantomData,
        }))
    }

    /// Re-enter the fence to commit work an earlier acquisition funded, only if
    /// the exact session that funded it is still this peer's live one.
    ///
    /// This is the second half of a deliberately split admission. Work whose
    /// cost is bounded but whose *duration* is set by peer-supplied input — a
    /// JSON parse over an admitted frame is the case that motivated this — must
    /// not run under the registry's single mutation lock, because that lock
    /// orders every peer's promotion, replacement and dispatch. One peer's
    /// pathological payload would otherwise stall the whole mesh for as long as
    /// the parse takes, and the admission that authorized the parse is exactly
    /// what makes the payload's shape adversary-chosen.
    ///
    /// So the first acquisition admits, records, and *funds*; the work happens
    /// outside every lock; and this commits the result. What that costs is one
    /// extra check, and it is the check the split makes necessary: the session
    /// may have been revoked or replaced while the work ran, and work funded by
    /// a session that is gone authorizes nothing. `witness` is matched by
    /// identity against the peer's current session rather than merely tested for
    /// liveness, so a *replacement* that promoted in the interval refuses here
    /// instead of inheriting the predecessor's admitted frame.
    ///
    /// No refusal arm and no counting. A frame that reaches here was already
    /// admitted and already counted; failing this test means the session went
    /// away underneath it, which is this side's lifecycle and not the peer's
    /// misbehaviour. `None` covers all three ways that happens — stale owner,
    /// no live session, different session — because none of them authorizes the
    /// commit and telling them apart out here would be a distinction the caller
    /// could only misuse.
    pub(super) fn with_same_session<R>(
        &self,
        owner: &PeerOwnerToken,
        witness: &crate::runtime::session_broker::SessionValidityWitness,
        committed: impl FnOnce(&AdmittedSessionOperation<'_>) -> R,
    ) -> Option<R> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation) {
            return None;
        }
        let peer = &current.value().peer;
        // Read under the lock, like every other authorizing fact in this file.
        // Deliberately *not* a promotion: promoting here would mint a fresh
        // session on demand and then hand it work the previous session paid
        // for, which is the precise substitution this check exists to refuse.
        if !peer.with_live_session(|session| witness.witnesses(session))? {
            return None;
        }
        Some(committed(&AdmittedSessionOperation {
            peer,
            owner,
            _not_send: std::marker::PhantomData,
        }))
    }

    /// End **exactly** the session `witness` names, and nothing else.
    ///
    /// For the two ways an admitted frame dies after its session has already
    /// been proved current: the owner refuses to fund it, and it does not
    /// decode. Both mean this side is holding a session it cannot use — the
    /// first because the peer's traffic costs more than the owner will pay for,
    /// the second because what arrived over an authenticated channel was not a
    /// message at all — and in both the honest answer is to stop having that
    /// session rather than to drop the frame and wait for the next one.
    ///
    /// **Exactly, and the exactness is the whole design.** Three things are
    /// checked under the mutation lock before anything is torn down: the peer is
    /// still installed under this device id, its installation is still the one
    /// the captured owner names, and its live session is the very one the
    /// witness was minted from. A replacement that promoted while the frame was
    /// being decoded fails the third and is left completely alone — it did not
    /// send this frame, it did not refuse to fund it, and it is not the session
    /// being ended. Removing by device id would have taken it; that is the
    /// device-only removal this deliberately is not.
    ///
    /// **What ending it does.** Only the session slot is cleared. That is
    /// sufficient because of what the session owns: dropping it resolves the
    /// `SessionRpcState` it holds — every pending local call settles, every open
    /// stream is finished — and releases its reliable pending state, all through
    /// `Drop` rather than through a sweep this function would have to perform.
    /// And it cannot come back: promotion **moved** the authenticated channel
    /// into the session, so the slot it came from is already spent and a
    /// re-promotion has nothing to promote until the peer authenticates again.
    ///
    /// No timer, no grace period, no retry. The session either is the one that
    /// failed or is not.
    pub(super) fn retire_exact_session(
        &self,
        owner: &PeerOwnerToken,
        witness: &crate::runtime::session_broker::SessionValidityWitness,
    ) -> bool {
        let _mutation = self.mutation.lock();
        let Some(current) = self.peers.get(owner.device_id()) else {
            return false;
        };
        if !Arc::ptr_eq(&current.value().installation, &owner.installation) {
            return false;
        }
        let peer = &current.value().peer;
        // Identity, not liveness. "This peer has *a* live session" would retire
        // a successor for its predecessor's failure.
        if peer.with_live_session(|session| witness.witnesses(session)) != Some(true) {
            return false;
        }
        peer.revoke_promoted_session();
        true
    }

    /// Mint one owned authority for an application operation that will cross an
    /// await, **gated on a live promoted session**.
    ///
    /// Built under the same fence as `with_admitted_current`. Promotion
    /// is what authorizes the send: it proves the exact current connector,
    /// current policy, the authenticated local principal, and a held
    /// post-authentication reservation in one atomic transition under this same
    /// mutation lock, so an operation that cannot name its exact connector has
    /// nothing to write through.
    ///
    /// A `None` broker means the process owner installed no resource provider,
    /// so no session can exist and nothing is authorized. That is fail-closed,
    /// not a compatibility mode: there is deliberately no arm that falls back to
    /// the peer string.
    pub(super) fn admit_application_operation(
        &self,
        owner: &PeerOwnerToken,
        broker: Option<&SessionBroker>,
        mesh_context: &str,
    ) -> Option<AdmittedApplicationOperation> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation) {
            return None;
        }
        let peer = &current.value().peer;
        if !self.promote_and_announce(peer, owner, broker?, mesh_context) {
            return None;
        }
        let session = peer.session.lock().clone()?;
        let validity = peer.with_live_session(|session| session.validity_witness())?;
        Some(AdmittedApplicationOperation {
            peer: Arc::clone(peer),
            session,
            validity,
            owner: owner.clone(),
        })
    }

    /// Run one realtime-flow operation against a live promoted session and a
    /// freshly acquired live connector incarnation.
    ///
    /// This is the engine-side bridge a Device selector resolves through. The
    /// selector names an installation; everything the operation is authorized by
    /// is produced inside this fence, under the mutation lock, at the moment of
    /// use — the session by promotion, the incarnation by fresh acquisition from
    /// the current worker.
    ///
    /// The session is **lent**, never handed out. It is not `Clone`, the borrow
    /// ends with the closure, and nothing here is serializable, so no session
    /// authority can escape to IPC or outlive the fence that authorized it.
    /// Run one operation against a live promoted session, lending the session
    /// and nothing else.
    ///
    /// The generic form of the fence below, for operations that must prove a
    /// current session authorized them but have no business touching the
    /// realtime flow set. Same conjuncts, same `None` on any failure: current
    /// installation, promotion, live incarnation, session belongs to it.
    ///
    /// The session is **lent**, never handed out — not `Clone`, borrow ends with
    /// the closure, nothing serializable — so no session authority escapes to
    /// IPC or outlives the fence that authorized it.
    pub(super) fn with_live_session<R>(
        &self,
        owner: &PeerOwnerToken,
        broker: Option<&SessionBroker>,
        mesh_context: &str,
        effect: impl FnOnce(&crate::runtime::session_broker::SessionCapability) -> R,
    ) -> Option<R> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation) {
            return None;
        }
        let peer = &current.value().peer;
        if !self.promote_and_announce(peer, owner, broker?, mesh_context) {
            return None;
        }
        peer.with_live_session(effect)
    }

    /// Run one operation against a live promoted session and the application
    /// state that session owns.
    ///
    /// The same fence, projected to the application side. What `effect` mutates
    /// is a field of the session it is handed, so the state cannot outlive the
    /// authority that admitted it and a replacement cannot reach its
    /// predecessor's — there is no key by which to name one.
    pub(crate) fn with_live_session_state<R>(
        &self,
        owner: &PeerOwnerToken,
        broker: Option<&SessionBroker>,
        mesh_context: &str,
        effect: impl FnOnce(
            &crate::runtime::session_broker::SessionCapability,
            &mut crate::runtime::peer_session::PeerSessionState,
        ) -> R,
    ) -> Option<R> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation) {
            return None;
        }
        let peer = &current.value().peer;
        if !self.promote_and_announce(peer, owner, broker?, mesh_context) {
            return None;
        }
        peer.with_live_session_state(effect)
    }

    /// The installations whose live session still holds frames that have not
    /// reached the wire.
    ///
    /// Owner tokens, not device ids: the flush that follows must reach the exact
    /// installation whose record was read, and a device id re-resolved after
    /// this snapshot could name a replacement. Non-promoting, like the backlog
    /// count below — a tick that promoted sessions in order to decide whether to
    /// flush them would create the very thing it was checking for.
    pub(super) fn owners_with_unsent_reliable_frames(&self) -> Vec<PeerOwnerToken> {
        let _mutation = self.mutation.lock();
        self.owners_snapshot(|peer| {
            self.policy_admits(&peer.device_id)
                && peer
                    .with_live_session_state(|_session, record| record.has_unsent())
                    .unwrap_or(false)
        })
    }

    /// Frames retained and unacknowledged across every peer holding a live
    /// session — the acked-delivery backlog the status surface reports.
    ///
    /// Deliberately **non-promoting**: it reads the sessions that exist and
    /// creates none. A diagnostic read that promoted would make observing the
    /// backlog change what the backlog is, and would take a post-authentication
    /// reservation on behalf of a caller that asked for a number. A peer with no
    /// live session contributes nothing, which is exact rather than approximate
    /// — with no session there is nothing retained.
    pub(super) fn reliable_pending_total(&self) -> usize {
        let _mutation = self.mutation.lock();
        self.collect_map(|peer| {
            self.policy_admits(&peer.device_id)
                .then(|| peer.with_live_session_state(|_session, app| app.pending()))
                .flatten()
        })
        .into_iter()
        .sum()
    }

    pub(super) fn with_live_session_flow<R>(
        &self,
        owner: &PeerOwnerToken,
        broker: Option<&SessionBroker>,
        mesh_context: &str,
        effect: impl FnOnce(
            &crate::runtime::session_broker::SessionCapability,
            &mut crate::transport::webrtc::SessionRealtimeFlows,
            &Arc<crate::connector::ConnectorIncarnation>,
        ) -> R,
    ) -> Option<R> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation) {
            return None;
        }
        let peer = &current.value().peer;
        if !self.promote_and_announce(peer, owner, broker?, mesh_context) {
            return None;
        }
        peer.with_live_session_flow(effect)
    }

    /// The same fence, additionally lending the connector worker.
    ///
    /// Used only by the two-phase native-negotiation path, which has to reach
    /// the connector from outside the lock. See
    /// [`PeerConnection::with_live_session_flow_and_worker`] for why the handle
    /// is not authority.
    pub(super) fn with_live_session_flow_and_worker<R>(
        &self,
        owner: &PeerOwnerToken,
        broker: Option<&SessionBroker>,
        mesh_context: &str,
        effect: impl FnOnce(
            &crate::runtime::session_broker::SessionCapability,
            &mut crate::transport::webrtc::SessionRealtimeFlows,
            &Arc<crate::connector::ConnectorIncarnation>,
            &Arc<crate::transport::WebRtcConnectorWorker>,
        ) -> R,
    ) -> Option<R> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation) {
            return None;
        }
        let peer = &current.value().peer;
        if !self.promote_and_announce(peer, owner, broker?, mesh_context) {
            return None;
        }
        peer.with_live_session_flow_and_worker(effect)
    }

    /// Claim the pending renegotiation for `owner`, if there is one to claim.
    ///
    /// Renegotiation drives SDP on the connector and opens no flow, so what it
    /// needs is the connector this session was promoted from — proved live at
    /// the moment of the claim, not carried in from an earlier decision. That
    /// is exactly what [`Self::with_live_session_flow_and_worker`] establishes:
    /// the owner is current, the session is promoted, the incarnation is
    /// freshly acquired from the current worker, and the session belongs to it.
    /// A superseded connector satisfies none of those and yields `None`.
    ///
    /// **An empty flow set is not a refusal.** The flow set is lent and
    /// deliberately not inspected: a track-set change that *removed* the last
    /// flow is precisely the case that most needs an offer, and keying the
    /// claim off flow presence would strand that peer holding a track set its
    /// peer never learns about.
    ///
    /// The claim is taken **inside** the fence, after validation, and never by
    /// a separate call before it. `media_reneg_inflight` is cleared only by the
    /// spawned renegotiation task, so latching it and then failing validation
    /// would leave the single-flight guard set and that peer would never
    /// renegotiate again.
    ///
    /// The returned value carries the exact owner captured here. Re-resolving
    /// it by device id afterwards would reopen the window this exists to close:
    /// a replacement installed between the claim and that lookup would answer
    /// it, and the spawned task's completion bookkeeping would land on the
    /// replacement instead of the peer whose renegotiation actually ran.
    pub(super) fn claim_renegotiation(
        &self,
        owner: &PeerOwnerToken,
        broker: Option<&SessionBroker>,
        mesh_context: &str,
    ) -> Option<AdmittedRenegotiation> {
        self.with_live_session_flow_and_worker(
            owner,
            broker,
            mesh_context,
            |session, _flows, _live, worker| {
                let peer = self.peers.get(owner.device_id())?;
                let mut data = peer.value().peer.state.write();
                if !data.media_reneg_pending {
                    return None;
                }
                data.media_reneg_inflight = true;
                data.media_reneg_pending = false;
                drop(data);
                Some(AdmittedRenegotiation {
                    session: Arc::clone(worker),
                    owner: owner.clone(),
                    validity: session.validity_witness(),
                })
            },
        )
        .flatten()
    }

    /// Snapshot owner tokens for the entries a fanout selects.
    ///
    /// Owner tokens rather than device id **strings**, because a string has to
    /// be re-resolved at send time: between the collection and the send a peer
    /// can be replaced, and the replacement answers the lookup and receives the
    /// payload. An owner token names one *installation*, so after replacement it
    /// names nothing and that element of the fanout simply drops.
    ///
    /// Selection stays a policy read — it is not authority. Each element is
    /// still individually authorized by the session gate when it is sent.
    pub(super) fn owners_snapshot(
        &self,
        mut select: impl FnMut(&PeerConnection) -> bool,
    ) -> Vec<PeerOwnerToken> {
        self.peers
            .iter()
            .filter(|entry| select(&entry.value().peer))
            .map(|entry| PeerOwnerToken {
                peer: Arc::clone(&entry.value().peer),
                installation: Arc::clone(&entry.value().installation),
            })
            .collect()
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
    /// are released before the callback can take a peer-state lock, so no key
    /// is cloned and no registry-to-peer lock order is introduced.
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

/// Proof that one exact peer installation held a live promoted session, valid
/// only for the body of one synchronous effect.
///
/// Named for the invariant it carries and nothing else: a live session for
/// *this* installation. That is the whole of what the fence establishes, and it
/// is what every operation below relies on. Current policy is proved *inside*
/// promotion and consumed by it, so the witness stands alone: no second
/// connector-side capability and no delivery boolean sits behind it to be kept
/// in step.
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
pub(super) struct AdmittedSessionOperation<'a> {
    peer: &'a Arc<PeerConnection>,
    /// The exact owner token this fence admitted, borrowed rather than cloned
    /// so entering the fence costs nothing. Any witness that crosses an await
    /// clones it, so later bookkeeping names *this* installation instead of
    /// re-resolving a device id that a replacement may since have taken over.
    owner: &'a PeerOwnerToken,
    _not_send: std::marker::PhantomData<*const ()>,
}

impl AdmittedSessionOperation<'_> {
    /// The exact admitted peer's device id.
    ///
    /// Production dispatch reads the id off the owner token it already carries,
    /// so this exists for controls that must name the peer the fence admitted
    /// without holding a witness for anything else.
    #[cfg(test)]
    pub(super) fn device_id(&self) -> &str {
        &self.peer.device_id
    }

    /// Record inbound liveness and traffic on the exact admitted peer.
    pub(super) fn record_inbound(&self, effect: impl FnOnce(&Arc<PeerConnection>)) {
        effect(self.peer);
    }

    /// A witness for the exact session this fence admitted.
    ///
    /// Read-only and carrying no authority of its own: it cannot send, cannot
    /// retain, and cannot be turned back into a session. Its whole purpose is to
    /// let work funded here be committed by a *later* acquisition through
    /// [`PeerRegistry::with_same_session`], which is what allows peer-supplied
    /// work to run outside the mutation lock without letting a replacement
    /// inherit the result.
    pub(super) fn session_witness(
        &self,
    ) -> Option<crate::runtime::session_broker::SessionValidityWitness> {
        self.peer
            .with_live_session(|session| session.validity_witness())
    }

    /// Lend the live session this fence admitted, and the application state it
    /// owns.
    ///
    /// No further locking: this fence already holds the mutation lock and has
    /// already promoted, so the session it lends is the one the admission was
    /// decided on. `None` only if the promoted session was invalidated by its
    /// connector between promotion and here, which is the same answer every
    /// other operation gives in that case.
    ///
    /// Used by the inbound acknowledgement path, which must settle retained
    /// frames under the very acquisition that admitted the acknowledgement — an
    /// acknowledgement applied after the fence could settle frames a
    /// replacement's session had merely numbered the same way.
    pub(super) fn with_session_state<R>(
        &self,
        effect: impl FnOnce(
            &crate::runtime::session_broker::SessionCapability,
            &mut crate::runtime::peer_session::PeerSessionState,
        ) -> R,
    ) -> Option<R> {
        self.peer.with_live_session_state(effect)
    }

    /// Take one admitted inbound frame as an owned, move-only operation.
    ///
    /// The message is moved *in* to the fence by the caller and comes back out
    /// only here, on the admitted arm, bound to the exact peer and owner this
    /// fence proved. The binding is what lets the dispatch that follows name
    /// *this* installation instead of re-resolving a device id a replacement
    /// may since have taken over.
    pub(super) fn inbound_application_operation(
        &self,
        frame: crate::application_gateway::DecodedApplicationFrame,
    ) -> AdmittedInboundApplicationOperation {
        AdmittedInboundApplicationOperation {
            frame,
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
/// An authority rather than an `Option<bool>`, because a boolean outlives the
/// fence that produced it: every dispatch arm would then re-resolve the peer *by
/// device id*, so a replacement installed during the await would answer the
/// lookup and receive the effect, the liveness touch, the counters, and the
/// delivery. An authority cannot be re-resolved — it names one installation, and
/// after replacement it names nothing.
///
/// Carries all three things one admission decided, as a single value: the
/// exact owner, the exact captured peer, and the one parsed frame. Deliberately
/// not `Clone`, `Copy`, `Debug`, `Default`, or serializable, and consumed by
/// value, so one admission dispatches exactly one frame.
#[must_use = "an admitted inbound frame authorizes exactly one dispatch and must be consumed"]
pub(super) struct AdmittedInboundApplicationOperation {
    frame: crate::application_gateway::DecodedApplicationFrame,
    dispatch: AdmittedInboundDispatch,
}

impl AdmittedInboundApplicationOperation {
    /// Split into the one frame this admission authorized and the installation
    /// binding that outlives it for the dispatch.
    ///
    /// Consuming by value is the single-dispatch rule: the frame cannot be
    /// dispatched twice, and it cannot be paired with a different admission.
    pub(super) fn into_dispatch(
        self,
    ) -> (
        crate::protocol::MeshMessage,
        crate::resource::ResourceClaim,
        crate::resource::ResourceLease,
        AdmittedInboundDispatch,
    ) {
        let (message, claim, work) = self.frame.into_parts();
        (message, claim, work, self.dispatch)
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

    /// The same fence, additionally lending the live session this frame was
    /// admitted under and the application state that session owns.
    ///
    /// The one shape the reliable receive path needs: the high-water mark, the
    /// delivery and the currency proof are a single step, and the mark now lives
    /// inside the session rather than in a device-keyed map, so all three are
    /// reachable at once or not at all. `None` if the captured installation was
    /// replaced or holds no live session — in which case nothing moved, nothing
    /// was delivered, and the caller owes the sender no acknowledgement.
    ///
    /// Carries [`Self::with_captured_peer`]'s rule unchanged: `effect` runs
    /// under the registry mutation lock, so it must not await, must not re-enter
    /// the registry, and may only hand values off.
    pub(super) fn with_captured_session_state<R>(
        &self,
        peers: &PeerRegistry,
        effect: impl FnOnce(
            &crate::runtime::session_broker::SessionCapability,
            &mut crate::runtime::peer_session::PeerSessionState,
        ) -> R,
    ) -> Option<R> {
        peers
            .with_current(&self.owner, |_current| {
                self.peer.with_live_session_state(effect)
            })
            .flatten()
    }
}

/// Move-only authority to perform exactly one application send on one exact
/// peer installation, minted only from a live promoted session.
///
/// Carries the peer and the connector worker captured **at admission**, under
/// the registry fence. The send writes through that captured worker and records
/// against that captured peer; nothing here re-resolves a device id, so a
/// replacement installed during the await cannot receive this operation or its
/// accounting.
///
/// Before the native future is first polled, [`Self::begin`] takes the
/// connector's own send authority and then re-enters the registry mutation
/// fence to prove both the captured installation and its session witness are
/// live. Crossing that synchronous point orders the effect before any later
/// replacement or governance commit, and the held connector authority makes
/// that ordering effective rather than merely recorded: revocation may retire
/// and close the connector immediately afterwards, and the send still lands.
/// The await then holds no registry lock and makes no impossible claim that
/// cancellation can retract bytes already handed to the native sender.
///
/// Deliberately not `Clone`, `Copy`, `Debug`, `Default`, or serializable, and
/// consumed by value, so one admission authorizes one operation.
#[must_use = "an admitted operation authorizes exactly one send and must be consumed"]
pub(super) struct AdmittedApplicationOperation {
    peer: Arc<PeerConnection>,
    session: Arc<crate::transport::WebRtcConnectorWorker>,
    validity: crate::runtime::session_broker::SessionValidityWitness,
    owner: PeerOwnerToken,
}

impl AdmittedApplicationOperation {
    /// Send one serialized frame through the exact captured connector, then
    /// record it against the exact captured peer.
    ///
    /// Both halves use the captured values, so a send and its accounting can
    /// never land on different installations.
    pub(super) async fn send_frame(
        self,
        peers: &PeerRegistry,
        bytes: bytes::Bytes,
        timeout: std::time::Duration,
    ) -> Result<usize> {
        self.begin(peers)?.send_frame(bytes, timeout).await
    }

    /// Cross the application effect's synchronous linearization point.
    ///
    /// Governance revocation takes the same mutation lock before invalidating
    /// the session. Therefore this either refuses without ever constructing a
    /// native send future, or returns an operation ordered before any later
    /// commit. No registry or parking_lot guard escapes this method.
    fn begin(self, peers: &PeerRegistry) -> Result<StartedApplicationOperation> {
        self.begin_after(peers, || {})
    }

    /// [`Self::begin`], with one observable instant inside it.
    ///
    /// `after_precheck` runs between the early validity precheck and the
    /// connector acquisition, which is the one window a caller cannot otherwise
    /// reach: everything before it is a single atomic read and everything after
    /// it is this method's own. A control that must revoke *there* — after the
    /// precheck has already passed, before the connector is asked — has no
    /// other way to say so, and that interleaving is exactly what the refusal
    /// translation below exists to answer correctly.
    ///
    /// Production passes an empty closure, so this costs a call to a closure
    /// that does nothing and compiles away. The hook is deliberately given no
    /// arguments and no return: it can observe and act on the wider system, but
    /// it cannot inspect or influence this operation's own decision.
    fn begin_after(
        self,
        peers: &PeerRegistry,
        after_precheck: impl FnOnce(),
    ) -> Result<StartedApplicationOperation> {
        // Policy before resources. A witness already known dead takes nothing
        // and is refused for the reason it is actually dead.
        //
        // This is not the linearization point — the authoritative check is the
        // one under the mutation lock below, and this one cannot replace it
        // because it reads no registry state. It exists for two production
        // reasons. A revoked session must not acquire a connector operation
        // permit: that permit joins the connector's active-operation count and
        // holds up the close drain, so a peer that has just lost its authority
        // could still delay teardown. And the refusal must name revocation
        // rather than whatever the transport happened to fail first — a caller
        // that cannot tell a policy refusal from a broken connector has lost
        // the distinction this whole gate exists to draw.
        if !self.validity.is_live() {
            return Err(Self::revoked());
        }
        after_precheck();
        // Connector authority next, and outside the registry lock.
        //
        // First, because the send is awaited long after this method returns: a
        // connector permit taken at await time can find a close already
        // committed, which is a refusal of an effect this fence has already
        // ordered as permitted. Held from here, the connector cannot close
        // until the send resolves or the value is dropped.
        //
        // Outside, because acquiring it touches a resource provider and the
        // connector's own fence, and neither belongs inside the registry-wide
        // critical section that every peer mutation contends on. Ordering is
        // unaffected: revocation commits under the mutation lock below, so a
        // validation that passes proves no revocation had committed while this
        // permit was already held.
        let send = match self.session.begin_send() {
            Ok(send) => send,
            // The connector refused. Which answer is truthful depends on
            // whether this witness survived, because revocation closes this
            // connector too: a caller told only "the close fence has
            // committed" would be told about the symptom while the cause —
            // that it no longer has authority to send at all — went unnamed.
            //
            // Re-reading validity here is sound in one direction, which is the
            // direction used. The flag is monotonic — set true once at
            // construction and false once in `SessionValidity::invalidate`,
            // with no path back — so a `false` now proves revocation happened
            // at or before this refusal and cannot be a value about to change
            // its mind. A `true` proves only that no revocation had been
            // observed by this load; one may begin immediately after it. That
            // is enough, because it leaves the connector's own error as the
            // only cause established at the moment of answering, and the
            // authoritative check under the mutation lock is not reached on
            // this path at all.
            Err(native) => {
                return Err(if self.validity.is_live() {
                    native
                } else {
                    Self::revoked()
                })
            }
        };
        let _mutation = peers.mutation.lock();
        let current = peers
            .peers
            .get(self.owner.device_id())
            .filter(|current| Arc::ptr_eq(&current.value().installation, &self.owner.installation));
        if current.is_none() || !self.validity.is_live() {
            return Err(Self::revoked());
        }
        Ok(StartedApplicationOperation {
            peer: self.peer,
            send,
        })
    }

    /// The one refusal a revoked application send gives, from either check.
    ///
    /// Built in one place so the two cannot drift apart: a caller is entitled
    /// to the same answer whether the witness was already dead on entry or was
    /// revoked while this operation was being admitted, and a divergence would
    /// leak which of the two happened.
    fn revoked() -> Error {
        Error::Transport("the session authorizing this send was revoked".into())
    }

    #[cfg(all(test, feature = "transport-lab"))]
    pub(super) fn begin_for_test(
        self,
        peers: &PeerRegistry,
    ) -> Result<StartedApplicationOperation> {
        self.begin(peers)
    }

    /// Begin, with `revoke` run at the one instant the precheck cannot cover.
    ///
    /// The production entry point is [`Self::begin`] and its closure is empty;
    /// this exists only so a control can be the concurrency rather than race
    /// against it. Nothing here is reachable from production, and the closure
    /// still cannot reach this operation's own state.
    #[cfg(all(test, feature = "transport-lab"))]
    pub(super) fn begin_racing_revocation_for_test(
        self,
        peers: &PeerRegistry,
        revoke: impl FnOnce(),
    ) -> Result<StartedApplicationOperation> {
        self.begin_after(peers, revoke)
    }
}

/// An application effect that crossed the registry-fenced begin point.
/// Revocation after this value exists is ordered after the admitted effect and
/// does not claim to roll back bytes a native sender may already own.
pub(super) struct StartedApplicationOperation {
    peer: Arc<PeerConnection>,
    /// Connector authority already taken, not a worker to ask again later.
    ///
    /// Holding the started send rather than the worker is what makes this type
    /// honest: its documented claim is that the effect is ordered before any
    /// later revocation, and that is only true if the connector cannot close
    /// underneath the await. Dropping this value before the send resolves
    /// releases the connector, which is the cancellation this type does allow.
    send: crate::transport::StartedConnectorSend,
}

impl StartedApplicationOperation {
    pub(super) async fn send_frame(
        self,
        bytes: bytes::Bytes,
        timeout: std::time::Duration,
    ) -> Result<usize> {
        let sent = tokio::time::timeout(timeout, self.send.send(bytes))
            .await
            .map_err(|_| Error::Transport("peer send timed out".into()))??;
        let mut data = self.peer.state.write();
        data.diag.bytes_out += sent as u64;
        data.diag.frames_out += 1;
        Ok(sent)
    }
}

/// Authority to *start* one inbound handler run, before the embedder's code is
/// entered.
///
/// The same shape as [`AdmittedApplicationOperation`] and for the same reason,
/// with one difference that decides everything about it: there is no connector
/// to hold. A send's begin point can take native authority and so can promise
/// the effect lands; a handler run cannot promise anything about what the
/// handler will later do. What it can establish — and what the whole type
/// exists for — is *when the run started*, as a synchronous point ordered
/// against every peer mutation and every governance commit.
///
/// **Why a fenced point at all, rather than the outer race.** The run is
/// already raced against its witness, and a biased select answers revocation
/// first at every poll. That makes revocation win every tie, including ties it
/// should lose: a run whose authority was live when it was admitted, and which
/// was revoked in the instant before its first poll, would silently never enter
/// the embedder's closure — the select would erase a start that had already been
/// authorized. Bias is a scheduling artefact, not a commit. This is the commit,
/// and it is reached exactly once.
///
/// After it, revocation may cancel every await the run has left — the handler's
/// own future, the terminal send — but it cannot retract the fact that the
/// closure was called. Before it, revocation refuses the run outright and the
/// closure is never called at all. Those are the only two outcomes.
///
/// Deliberately not `Clone`, `Copy`, `Debug` or `Default`, and consumed by
/// value, so one admission starts one run.
#[must_use = "an admitted handler run authorizes exactly one start and must be consumed"]
pub(super) struct AdmittedHandlerRun {
    validity: crate::runtime::session_broker::SessionValidityWitness,
    owner: PeerOwnerToken,
}

impl AdmittedHandlerRun {
    /// Capture the exact installation and session a dispatched call was
    /// admitted under.
    ///
    /// Both are captured rather than resolved later, for the reason the whole
    /// owner-token pattern exists: a device id re-resolved at start time can
    /// name a replacement installation, and a run would then be started under
    /// authority that never asked for it.
    pub(super) fn new(
        owner: PeerOwnerToken,
        validity: crate::runtime::session_broker::SessionValidityWitness,
    ) -> Self {
        Self { validity, owner }
    }

    /// Cross the run's synchronous start point.
    ///
    /// Governance revocation takes the same mutation lock before invalidating
    /// the session, so this either refuses without the embedder's closure ever
    /// being entered, or returns a start ordered before any later commit. No
    /// registry or `parking_lot` guard escapes this method — the caller invokes
    /// user code only after it has returned, and never under a lock.
    ///
    /// `at_precommit` runs between the early validity read and the fenced
    /// commit, which is the one window nothing else can reach: everything
    /// before it is a single atomic read and everything after it is this
    /// method's own. There is one caller and it passes
    /// [`crate::engine::state::NetworkState::reach_rpc_handler_precommit_point`],
    /// which is empty in a production build and runs a control's staged action
    /// under test. Deliberately **not** a second test-only entry point: a
    /// control calling its own variant would observe this refusal without
    /// proving the production arm honours it, which is the only thing worth
    /// proving here.
    ///
    /// The hook takes nothing and returns nothing, so it can act on the wider
    /// system but cannot inspect or influence this run's own decision.
    pub(super) fn begin(
        self,
        peers: &PeerRegistry,
        at_precommit: impl FnOnce(),
    ) -> Result<StartedHandlerRun> {
        // An already-dead witness is refused for the reason it is actually
        // dead, and without touching the registry-wide lock every peer mutation
        // contends on. Not the linearization point: it reads no registry state,
        // and the authoritative check is the one under the fence below.
        if !self.validity.is_live() {
            return Err(Self::revoked());
        }
        at_precommit();
        let _mutation = peers.mutation.lock();
        let current = peers
            .peers
            .get(self.owner.device_id())
            .filter(|current| Arc::ptr_eq(&current.value().installation, &self.owner.installation));
        if current.is_none() || !self.validity.is_live() {
            return Err(Self::revoked());
        }
        Ok(StartedHandlerRun { _started: () })
    }

    /// The one refusal a revoked start gives, from either check, built in one
    /// place so the two cannot drift apart or leak which of them fired.
    fn revoked() -> Error {
        Error::Transport("the session authorizing this handler run was revoked".into())
    }
}

/// A handler run that crossed its fenced start point.
///
/// Opaque and empty on purpose. It carries no connector, no lock and no lease,
/// because it makes no claim about any of them: it is the *evidence* that the
/// start was ordered before any later revocation, and evidence is all the
/// caller needs to know it may enter the embedder's closure exactly once.
///
/// Held by the run for its whole life rather than dropped at the start, so the
/// authority to have started and the running work end together.
#[must_use = "a started handler run is the evidence the closure may be entered"]
pub(super) struct StartedHandlerRun {
    _started: (),
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
    validity: crate::runtime::session_broker::SessionValidityWitness,
}

impl AdmittedRenegotiation {
    pub(super) fn is_live(&self) -> bool {
        self.validity.is_live()
    }

    pub(super) async fn revoked(&self) {
        let validity = self.validity.clone();
        validity.revoked().await;
    }

    /// Run the final synchronous effect only while this installation and the
    /// promoted session that minted the claim are both still live. Governance
    /// revocation takes the same registry mutation lock while it invalidates
    /// the session witness, so the check and hand-off order wholly before or
    /// after that commit rather than leaving a check-then-send window.
    pub(super) fn with_live<R>(
        &self,
        peers: &PeerRegistry,
        effect: impl FnOnce() -> R,
    ) -> Option<R> {
        peers.with_current(&self.owner, |_peer| self.validity.is_live().then(effect))?
    }
    /// The connector this renegotiation drives. Its own liveness and close
    /// fence stays authoritative for every SDP call.
    pub(super) fn session(&self) -> &Arc<crate::transport::WebRtcConnectorWorker> {
        &self.session
    }

    /// The captured owner's device id, for logging and signaling attribution.
    pub(super) fn device_id(&self) -> &str {
        self.owner.device_id()
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
                // instead of losing the track-set change.
                data.media_reneg_pending = true;
                drop(data);
                tracing::debug!(peer = %self.owner.device_id(), "renegotiation deferred: {error}");
            }
        }
    }
}
