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

use dashmap::DashMap;
use parking_lot::Mutex;

use crate::error::{Error, Result};
use crate::runtime::session_broker::SessionBroker;

use super::connection::PeerConnection;

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
        if !peer.promote_session_if_needed(broker?, mesh_context) {
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
        let promoted =
            broker.is_some_and(|broker| peer.promote_session_if_needed(broker, mesh_context));
        if !promoted {
            return Some(refused(peer));
        }
        Some(admitted(&AdmittedSessionOperation {
            peer,
            owner,
            _not_send: std::marker::PhantomData,
        }))
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
        if !peer.promote_session_if_needed(broker?, mesh_context) {
            return None;
        }
        let session = peer.session.lock().clone()?;
        Some(AdmittedApplicationOperation {
            peer: Arc::clone(peer),
            session,
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
        if !peer.promote_session_if_needed(broker?, mesh_context) {
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
    pub(super) fn with_live_session_state<R>(
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
        if !peer.promote_session_if_needed(broker?, mesh_context) {
            return None;
        }
        peer.with_live_session_state(effect)
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
    /// The installations whose live session still holds frames that have not
    /// reached the wire.
    ///
    /// Owner tokens, not device ids: the flush that follows must reach the exact
    /// installation whose record was read, and a device id re-resolved after
    /// this snapshot could name a replacement. Non-promoting, like the backlog
    /// count — a tick that promoted sessions in order to decide whether to flush
    /// them would create the very thing it was checking for.
    pub(super) fn owners_with_unsent_reliable_frames(&self) -> Vec<PeerOwnerToken> {
        self.owners_snapshot(|peer| {
            peer.with_live_session_state(|_session, record| record.has_unsent())
                .unwrap_or(false)
        })
    }

    pub(super) fn reliable_pending_total(&self) -> usize {
        self.collect_map(|peer| peer.with_live_session_state(|_session, app| app.pending()))
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
        if !peer.promote_session_if_needed(broker?, mesh_context) {
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
        if !peer.promote_session_if_needed(broker?, mesh_context) {
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
            |_session, _flows, _live, worker| {
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
                })
            },
        )
        .flatten()
    }

    /// Snapshot owner tokens for the entries a fanout selects.
    ///
    /// Fanout used to collect device id **strings** and then re-resolve each one
    /// at send time. That is the same re-resolution defect the inbound path
    /// removed: between the collection and the send, a peer can be replaced, and
    /// the replacement answers the lookup and receives the payload. An owner
    /// token names one *installation*, so after replacement it names nothing and
    /// that element of the fanout simply drops.
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
                // instead of losing the track-set change.
                data.media_reneg_pending = true;
                drop(data);
                tracing::debug!(peer = %self.owner.device_id(), "renegotiation deferred: {error}");
            }
        }
    }
}
