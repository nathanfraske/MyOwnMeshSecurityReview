//! Authorization adapter for the Closed member relay.
//!
//! This module is the engine-side half of the relay boundary.  It proves the
//! semantic policy and captures the exact authenticated sessions that may be
//! handed to `runtime::relay`.  The runtime owns the allocation permit,
//! ciphertext queue, forwarding and terminal settlement; this adapter owns
//! neither a queue nor endpoint key material.
//!
//! A relay route has one local member (the relay) and two remote endpoints.
//! The local member is identified by the immutable state identity.  It is not
//! resolved as a third peer, and a route can never select an address, fan out,
//! or recursively create another relay.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Weak};

use super::peer_registry::PeerOwnerToken;
use super::NetworkState;
use crate::config::ClosedRelayPolicyConfig;
use crate::protocol::relay::{ClosedRelayControl, ClosedRelayData, RelayKeyShare};
use crate::protocol::OpaqueRelayPacket;
use crate::resource::{ResourceClaim, ResourceClass, ResourceLease};
use crate::runtime::relay::{
    ClosedRelayEndpoints, ClosedRelayHandle, ClosedRelayHandshakeGuard, ClosedRelayRuntime,
    ClosedRelayTerminal, OpaqueRelaySession, PendingEndpointKeyAgreement, RelayAllocationPermit,
    RelayDirection,
};
use crate::runtime::session_broker::SessionValidityWitness;
use crate::semantic::{DeviceId, MeshContextId, Role, VerifiedProjectPolicy};
use parking_lot::Mutex;
use tokio::sync::Notify;

pub(crate) use crate::runtime::relay::ClosedRelayRefusal;

enum EndpointCrypto {
    Pending(PendingEndpointKeyAgreement),
    Ready(OpaqueRelaySession),
    Closing(OpaqueRelaySession),
    Closed,
}

pub(crate) struct EndpointSessionInner {
    state: Weak<NetworkState>,
    relay_owner: PeerOwnerToken,
    relay_witness: SessionValidityWitness,
    context: MeshContextId,
    requester: DeviceId,
    relay: DeviceId,
    target: DeviceId,
    session_id: [u8; 16],
    allocation_epoch: AtomicU64,
    crypto: Mutex<EndpointCrypto>,
    inbound: Mutex<VecDeque<OpaqueRelayPacket>>,
    inbound_capacity: usize,
    _lease: ResourceLease,
    wake: Notify,
    closed: AtomicBool,
    consumer_state: AtomicU8,
    public_refs: std::sync::atomic::AtomicUsize,
}

/// A bounded, synchronous handoff from a dropped public endpoint to the
/// network owner. The owner performs the asynchronous Close and exact relay
/// settlement at the next engine boundary; Drop never spawns or awaits.
pub(crate) struct ClosedRelayAbandonment {
    pub(crate) route: crate::protocol::relay::ClosedRelayRoute,
    pub(crate) relay_owner: PeerOwnerToken,
    pub(crate) relay_witness: SessionValidityWitness,
    pub(crate) allocation_generation: Option<ClosedRelayGeneration>,
}

const ENDPOINT_CONSUMER_UNCLAIMED: u8 = 0;
const ENDPOINT_CONSUMER_CLAIMED: u8 = 1;
const ENDPOINT_CONSUMER_CANCELLED: u8 = 2;

/// Endpoint-owned opaque session handle. The relay only sees the bounded
/// ciphertext queues; this handle retains endpoint AEAD state at A or C.
pub(crate) struct EndpointSession(Arc<EndpointSessionInner>, EndpointSessionRole);

#[derive(Clone, Copy, PartialEq, Eq)]
enum EndpointSessionRole {
    Public,
    Registry,
    Borrowed,
}

impl Drop for EndpointSession {
    fn drop(&mut self) {
        if self.1 != EndpointSessionRole::Public
            || self.0.public_refs.fetch_sub(1, Ordering::AcqRel) != 1
        {
            return;
        }
        // A public endpoint handle may be abandoned without an explicit
        // Close. The explicit public-owner counter is separate from Arc
        // registry custody, so this retires even while registries retain an
        // Arc to the same endpoint.
        self.cancel_consumer();
    }
}

impl Clone for EndpointSession {
    fn clone(&self) -> Self {
        if self.1 == EndpointSessionRole::Public {
            self.0.public_refs.fetch_add(1, Ordering::AcqRel);
        }
        Self(Arc::clone(&self.0), self.1)
    }
}

struct EndpointSessionRoute {
    relay_owner: PeerOwnerToken,
    relay_witness: SessionValidityWitness,
    context: MeshContextId,
    requester: DeviceId,
    relay: DeviceId,
    target: DeviceId,
    session_id: [u8; 16],
    allocation_epoch: u64,
}

#[derive(Clone)]
pub(crate) struct EndpointSessionMetadata {
    pub(crate) context: MeshContextId,
    pub(crate) requester: DeviceId,
    pub(crate) relay: DeviceId,
    pub(crate) target: DeviceId,
    pub(crate) session_id: [u8; 16],
    pub(crate) allocation_epoch: u64,
}

impl EndpointSession {
    fn into_registry(mut self) -> Self {
        self.disarm_public();
        self.1 = EndpointSessionRole::Registry;
        self
    }

    fn into_public(mut self) -> Self {
        if self.1 == EndpointSessionRole::Registry {
            self.0
                .consumer_state
                .store(ENDPOINT_CONSUMER_CLAIMED, Ordering::Release);
            self.0.public_refs.fetch_add(1, Ordering::AcqRel);
        }
        self.1 = EndpointSessionRole::Public;
        self
    }

    fn borrowed_clone(&self) -> Self {
        Self(Arc::clone(&self.0), EndpointSessionRole::Borrowed)
    }

    fn disarm_public(&mut self) {
        if self.1 == EndpointSessionRole::Public {
            let _ = self.0.public_refs.fetch_sub(1, Ordering::AcqRel);
            self.1 = EndpointSessionRole::Borrowed;
        }
    }

    pub(crate) fn cancel_consumer(&self) {
        if self
            .0
            .consumer_state
            .swap(ENDPOINT_CONSUMER_CANCELLED, Ordering::AcqRel)
            == ENDPOINT_CONSUMER_CANCELLED
        {
            return;
        }
        self.mark_closed();
        if let Some(state) = self.0.state.upgrade() {
            state.enqueue_closed_relay_abandonment(self.abandonment(&state));
            state.remove_closed_relay_endpoint(self);
        }
    }

    fn abandonment(&self, state: &NetworkState) -> ClosedRelayAbandonment {
        let metadata = self.metadata();
        ClosedRelayAbandonment {
            route: crate::protocol::relay::ClosedRelayRoute::with_epoch(
                metadata.context,
                metadata.requester,
                metadata.relay,
                metadata.target,
                metadata.session_id,
                metadata.allocation_epoch,
            ),
            relay_owner: self.0.relay_owner.clone(),
            relay_witness: self.0.relay_witness.clone(),
            allocation_generation: state.closed_relay_generation(metadata.session_id),
        }
    }

    pub(crate) fn metadata(&self) -> EndpointSessionMetadata {
        EndpointSessionMetadata {
            context: self.0.context,
            requester: self.0.requester.clone(),
            relay: self.0.relay.clone(),
            target: self.0.target.clone(),
            session_id: self.0.session_id,
            allocation_epoch: self.0.allocation_epoch.load(Ordering::Acquire),
        }
    }

    pub(crate) fn set_allocation_epoch(&self, allocation_epoch: u64) {
        let _ = self.0.allocation_epoch.compare_exchange(
            0,
            allocation_epoch,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    fn relay_owner_is_current(&self, state: &NetworkState) -> bool {
        self.0.relay_witness.is_live()
            && state
                .peers
                .with_current(&self.0.relay_owner, |peer| {
                    peer.with_live_session(|session| self.0.relay_witness.witnesses(session))
                })
                .flatten()
                .unwrap_or(false)
    }

    fn pending(
        state: &Arc<NetworkState>,
        route: EndpointSessionRoute,
        pending: PendingEndpointKeyAgreement,
        capacity: usize,
        lease: ResourceLease,
    ) -> Self {
        Self(
            Arc::new(EndpointSessionInner {
                state: Arc::downgrade(state),
                relay_owner: route.relay_owner,
                relay_witness: route.relay_witness,
                context: route.context,
                requester: route.requester,
                relay: route.relay,
                target: route.target,
                session_id: route.session_id,
                allocation_epoch: AtomicU64::new(route.allocation_epoch),
                crypto: Mutex::new(EndpointCrypto::Pending(pending)),
                inbound: Mutex::new(VecDeque::with_capacity(capacity)),
                inbound_capacity: capacity,
                _lease: lease,
                wake: Notify::new(),
                closed: AtomicBool::new(false),
                consumer_state: AtomicU8::new(ENDPOINT_CONSUMER_CLAIMED),
                public_refs: std::sync::atomic::AtomicUsize::new(1),
            }),
            EndpointSessionRole::Public,
        )
    }

    fn ready(
        state: &Arc<NetworkState>,
        route: EndpointSessionRoute,
        session: OpaqueRelaySession,
        capacity: usize,
        lease: ResourceLease,
    ) -> Self {
        Self(
            Arc::new(EndpointSessionInner {
                state: Arc::downgrade(state),
                relay_owner: route.relay_owner,
                relay_witness: route.relay_witness,
                context: route.context,
                requester: route.requester,
                relay: route.relay,
                target: route.target,
                session_id: route.session_id,
                allocation_epoch: AtomicU64::new(route.allocation_epoch),
                crypto: Mutex::new(EndpointCrypto::Ready(session)),
                inbound: Mutex::new(VecDeque::with_capacity(capacity)),
                inbound_capacity: capacity,
                _lease: lease,
                wake: Notify::new(),
                closed: AtomicBool::new(false),
                consumer_state: AtomicU8::new(ENDPOINT_CONSUMER_UNCLAIMED),
                public_refs: std::sync::atomic::AtomicUsize::new(1),
            }),
            EndpointSessionRole::Public,
        )
    }

    pub(crate) async fn send(&self, plaintext: &[u8]) -> Result<(), ClosedRelayRefusal> {
        if self.0.closed.load(Ordering::Acquire) {
            return Err(ClosedRelayRefusal::OwnerNotLive);
        }
        let packet = {
            let mut crypto = self.0.crypto.lock();
            match &mut *crypto {
                EndpointCrypto::Ready(session) => session.seal(plaintext)?,
                EndpointCrypto::Pending(_) => return Err(ClosedRelayRefusal::OwnerNotLive),
                EndpointCrypto::Closing(_) => return Err(ClosedRelayRefusal::OwnerNotLive),
                EndpointCrypto::Closed => return Err(ClosedRelayRefusal::OwnerNotLive),
            }
        };
        let state = self
            .0
            .state
            .upgrade()
            .ok_or(ClosedRelayRefusal::OwnerNotLive)?;
        let data = ClosedRelayData {
            version: crate::protocol::relay::CLOSED_RELAY_CONTROL_VERSION,
            context_id: self.0.context,
            requester: self.0.requester.clone(),
            relay: self.0.relay.clone(),
            target: self.0.target.clone(),
            session_id: self.0.session_id,
            allocation_epoch: self.0.allocation_epoch.load(Ordering::Acquire),
            packet,
        };
        super::send_to_peer_owner(
            &state,
            &self.0.relay_owner,
            &crate::protocol::MeshMessage::ClosedRelayData(data),
        )
        .await
        .map_err(|_| ClosedRelayRefusal::CarrierUnavailable)
    }

    pub(crate) async fn recv(&self) -> Result<Vec<u8>, ClosedRelayRefusal> {
        loop {
            if self.0.closed.load(Ordering::Acquire) {
                return Err(ClosedRelayRefusal::OwnerNotLive);
            }
            if let Some(packet) = self.0.inbound.lock().pop_front() {
                let mut crypto = self.0.crypto.lock();
                return match &mut *crypto {
                    EndpointCrypto::Ready(session) => session.open(&packet),
                    EndpointCrypto::Pending(_)
                    | EndpointCrypto::Closing(_)
                    | EndpointCrypto::Closed => Err(ClosedRelayRefusal::OwnerNotLive),
                };
            }
            let notified = self.0.wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.0.closed.load(Ordering::Acquire) {
                return Err(ClosedRelayRefusal::OwnerNotLive);
            }
            let Some(state) = self.0.state.upgrade() else {
                return Err(ClosedRelayRefusal::OwnerNotLive);
            };
            tokio::select! {
                _ = &mut notified => {},
                _ = state.wait_for_shutdown() => return Err(ClosedRelayRefusal::OwnerNotLive),
            }
        }
    }

    async fn wait_ready(&self) -> Result<(), ClosedRelayRefusal> {
        loop {
            if self.0.closed.load(Ordering::Acquire) {
                return Err(ClosedRelayRefusal::OwnerNotLive);
            }
            match &*self.0.crypto.lock() {
                EndpointCrypto::Ready(_) => return Ok(()),
                EndpointCrypto::Closing(_) | EndpointCrypto::Closed => {
                    return Err(ClosedRelayRefusal::OwnerNotLive)
                }
                EndpointCrypto::Pending(_) => {}
            }
            let notified = self.0.wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.0.closed.load(Ordering::Acquire) {
                return Err(ClosedRelayRefusal::OwnerNotLive);
            }
            match &*self.0.crypto.lock() {
                EndpointCrypto::Ready(_) => return Ok(()),
                EndpointCrypto::Closing(_) | EndpointCrypto::Closed => {
                    return Err(ClosedRelayRefusal::OwnerNotLive)
                }
                EndpointCrypto::Pending(_) => {}
            }
            let Some(state) = self.0.state.upgrade() else {
                return Err(ClosedRelayRefusal::OwnerNotLive);
            };
            tokio::select! {
                _ = &mut notified => {},
                _ = state.wait_for_shutdown() => return Err(ClosedRelayRefusal::OwnerNotLive),
            }
        }
    }

    pub(crate) async fn close(self) -> Result<(), ClosedRelayRefusal> {
        let Some(state) = self.0.state.upgrade() else {
            self.mark_closed();
            return Err(ClosedRelayRefusal::OwnerNotLive);
        };
        if self.0.allocation_epoch.load(Ordering::Acquire) == 0 {
            state.remove_closed_relay_endpoint(&self);
            self.mark_closed();
            return Ok(());
        }
        let control = ClosedRelayControl::Close {
            version: crate::protocol::relay::OPAQUE_RELAY_VERSION,
            context_id: self.0.context,
            requester: self.0.requester.clone(),
            relay: self.0.relay.clone(),
            target: self.0.target.clone(),
            session_id: self.0.session_id,
            allocation_epoch: self.0.allocation_epoch.load(Ordering::Acquire),
        };
        validate_outbound_control(&state, &control)?;
        if self.begin_closing() {
            let result = send_control_to_owner(&state, &self.0.relay_owner, control).await;
            if let Err(error) = result {
                state.remove_closed_relay_endpoint(&self);
                self.mark_closed();
                return Err(error);
            }
        }
        match self.wait_terminal().await {
            Ok(()) => {
                self.mark_closed();
                state.remove_closed_relay_endpoint(&self);
                Ok(())
            }
            Err(error) => {
                state.remove_closed_relay_endpoint(&self);
                self.mark_closed();
                Err(error)
            }
        }
    }

    fn begin_closing(&self) -> bool {
        let mut crypto = self.0.crypto.lock();
        match std::mem::replace(&mut *crypto, EndpointCrypto::Closed) {
            EndpointCrypto::Ready(session) => {
                *crypto = EndpointCrypto::Closing(session);
                true
            }
            EndpointCrypto::Closing(session) => {
                *crypto = EndpointCrypto::Closing(session);
                false
            }
            EndpointCrypto::Pending(_) | EndpointCrypto::Closed => {
                self.0.closed.store(true, Ordering::Release);
                false
            }
        }
    }

    fn is_closing(&self) -> bool {
        matches!(&*self.0.crypto.lock(), EndpointCrypto::Closing(_))
    }

    async fn wait_terminal(&self) -> Result<(), ClosedRelayRefusal> {
        loop {
            if self.0.closed.load(Ordering::Acquire) {
                return Ok(());
            }
            let notified = self.0.wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.0.closed.load(Ordering::Acquire) {
                return Ok(());
            }
            let Some(state) = self.0.state.upgrade() else {
                return Err(ClosedRelayRefusal::OwnerNotLive);
            };
            tokio::select! {
                _ = &mut notified => {},
                _ = state.wait_for_shutdown() => return Err(ClosedRelayRefusal::OwnerNotLive),
            }
        }
    }

    pub(crate) fn mark_closed(&self) {
        self.0
            .consumer_state
            .store(ENDPOINT_CONSUMER_CANCELLED, Ordering::Release);
        self.0.closed.store(true, Ordering::Release);
        *self.0.crypto.lock() = EndpointCrypto::Closed;
        self.0.wake.notify_waiters();
    }

    pub(crate) fn complete(&self, target_share: &RelayKeyShare) -> Result<(), ClosedRelayRefusal> {
        let mut crypto = self.0.crypto.lock();
        let pending = match std::mem::replace(&mut *crypto, EndpointCrypto::Closed) {
            EndpointCrypto::Pending(pending) => pending,
            EndpointCrypto::Ready(_) => return Ok(()),
            EndpointCrypto::Closing(_) => return Err(ClosedRelayRefusal::OwnerNotLive),
            EndpointCrypto::Closed => return Err(ClosedRelayRefusal::OwnerNotLive),
        };
        match pending.finish(target_share) {
            Ok(session) => {
                *crypto = EndpointCrypto::Ready(session);
                drop(crypto);
                self.0.wake.notify_waiters();
                Ok(())
            }
            Err(error) => {
                drop(crypto);
                self.0.closed.store(true, Ordering::Release);
                self.0.wake.notify_waiters();
                Err(error)
            }
        }
    }

    pub(crate) fn deliver(&self, packet: OpaqueRelayPacket) -> Result<(), ClosedRelayRefusal> {
        if self.0.closed.load(Ordering::Acquire) {
            return Err(ClosedRelayRefusal::OwnerNotLive);
        }
        let mut inbound = self.0.inbound.lock();
        if inbound.len() >= self.0.inbound_capacity {
            return Err(ClosedRelayRefusal::QueueFull);
        }
        inbound.push_back(packet);
        drop(inbound);
        self.0.wake.notify_one();
        Ok(())
    }
}

pub(crate) struct ClosedRelayEndpointRegistry {
    sessions: Vec<EndpointSession>,
    capacity: usize,
}

impl Drop for ClosedRelayEndpointRegistry {
    fn drop(&mut self) {
        for session in self.sessions.drain(..) {
            session.mark_closed();
        }
    }
}

impl ClosedRelayEndpointRegistry {
    pub(crate) fn new(profile: &ClosedRelayPolicyConfig) -> Result<Self, ClosedRelayRefusal> {
        if !profile.enabled || !profile.validate() {
            return Err(ClosedRelayRefusal::InvalidProfile);
        }
        let capacity = usize::try_from(profile.max_allocations)
            .map_err(|_| ClosedRelayRefusal::InvalidProfile)?;
        Ok(Self {
            sessions: Vec::with_capacity(capacity),
            capacity,
        })
    }

    pub(crate) fn insert(&mut self, session: EndpointSession) -> Result<(), ClosedRelayRefusal> {
        if self.sessions.len() >= self.capacity
            || self
                .sessions
                .iter()
                .any(|existing| existing.0.session_id == session.0.session_id)
        {
            return Err(ClosedRelayRefusal::QueueFull);
        }
        self.sessions.push(session.into_registry());
        Ok(())
    }

    pub(crate) fn find(&self, session_id: [u8; 16]) -> Option<EndpointSession> {
        self.sessions
            .iter()
            .find(|session| session.0.session_id == session_id)
            .map(EndpointSession::borrowed_clone)
    }

    /// Move every retained endpoint out for synchronous cancellation by the
    /// network owner. Moving the registry nodes first keeps cancellation free
    /// of a registry lock while it records the exact Close handoff.
    pub(crate) fn take_all_for_cancel(&mut self) -> Vec<EndpointSession> {
        std::mem::take(&mut self.sessions)
    }

    pub(crate) fn remove(&mut self, session: &EndpointSession) {
        if let Some(index) = self
            .sessions
            .iter()
            .position(|existing| Arc::ptr_eq(&existing.0, &session.0))
        {
            let removed = self.sessions.swap_remove(index);
            removed.mark_closed();
        }
    }

    pub(crate) fn remove_stale(&mut self, state: &NetworkState) -> usize {
        let mut removed = 0;
        let mut index = 0;
        while index < self.sessions.len() {
            if self.sessions[index].relay_owner_is_current(state) {
                index += 1;
                continue;
            }
            let session = self.sessions.swap_remove(index);
            session.mark_closed();
            removed += 1;
        }
        removed
    }
}

/// One-consumer handoff for a target that accepted an Offer. Only ready C-side
/// sessions enter this queue; requester pending sessions never do. The queue
/// is fixed at the same owner-selected allocation ceiling as the relay.
pub(crate) struct ClosedRelayTargetAcceptedRegistry {
    ready: VecDeque<EndpointSession>,
    capacity: usize,
    wake: Arc<Notify>,
}

impl Drop for ClosedRelayTargetAcceptedRegistry {
    fn drop(&mut self) {
        // A target Accept may be waiting for its one consumer when shutdown
        // takes the registry.  Wake and close every retained endpoint before
        // the queue's last Arc is released; otherwise a dropped receiver can
        // retain its endpoint lease past engine shutdown.
        for session in self.ready.drain(..) {
            session.mark_closed();
        }
        self.wake.notify_waiters();
    }
}

impl ClosedRelayTargetAcceptedRegistry {
    pub(crate) fn new(profile: &ClosedRelayPolicyConfig) -> Result<Self, ClosedRelayRefusal> {
        if !profile.enabled || !profile.validate() {
            return Err(ClosedRelayRefusal::InvalidProfile);
        }
        let capacity = usize::try_from(profile.max_allocations)
            .map_err(|_| ClosedRelayRefusal::InvalidProfile)?;
        Ok(Self {
            ready: VecDeque::with_capacity(capacity),
            capacity,
            wake: Arc::new(Notify::new()),
        })
    }

    pub(crate) fn publish(&mut self, session: EndpointSession) -> Result<(), ClosedRelayRefusal> {
        if self.ready.len() >= self.capacity
            || self
                .ready
                .iter()
                .any(|existing| existing.0.session_id == session.0.session_id)
        {
            return Err(ClosedRelayRefusal::QueueFull);
        }
        self.ready.push_back(session.into_registry());
        self.wake.notify_one();
        Ok(())
    }

    pub(crate) fn take_next(&mut self) -> Option<EndpointSession> {
        self.ready.pop_front().map(EndpointSession::into_public)
    }

    pub(crate) fn take_all_unpulled_for_cancel(&mut self) -> Vec<EndpointSession> {
        let mut unpulled = Vec::with_capacity(self.ready.len());
        let mut remaining = VecDeque::with_capacity(self.ready.len());
        while let Some(session) = self.ready.pop_front() {
            if session.0.consumer_state.load(Ordering::Acquire) == ENDPOINT_CONSUMER_UNCLAIMED {
                unpulled.push(session);
            } else {
                remaining.push_back(session);
            }
        }
        self.ready = remaining;
        unpulled
    }

    pub(crate) fn wake(&self) -> Arc<Notify> {
        Arc::clone(&self.wake)
    }

    pub(crate) fn remove(&mut self, session: &EndpointSession) {
        if let Some(index) = self
            .ready
            .iter()
            .position(|existing| Arc::ptr_eq(&existing.0, &session.0))
        {
            if let Some(removed) = self.ready.remove(index) {
                removed.mark_closed();
            }
            self.wake.notify_waiters();
        }
    }

    pub(crate) fn remove_stale(&mut self, state: &NetworkState) -> usize {
        let mut removed = 0;
        let mut index = 0;
        while index < self.ready.len() {
            if self.ready[index].relay_owner_is_current(state) {
                index += 1;
                continue;
            }
            let session = self.ready.remove(index).expect("accepted index is present");
            session.mark_closed();
            removed += 1;
        }
        removed
    }
}

fn invalid(reason: impl Into<String>) -> ClosedRelayRefusal {
    ClosedRelayRefusal::InvalidEndpoints(reason.into())
}

fn validate_session_id(session_id: [u8; 16]) -> Result<(), ClosedRelayRefusal> {
    if session_id.iter().all(|byte| *byte == 0) {
        Err(ClosedRelayRefusal::InvalidPacket(
            "closed relay session id must be nonzero".into(),
        ))
    } else {
        Ok(())
    }
}

/// One exact remote peer installation and the promoted session that
/// authenticated it.  Both identities are retained together: resolving a
/// device again at terminal time would allow a successor installation to be
/// used by a predecessor route.
#[derive(Clone)]
pub(crate) struct ClosedRelayEndpoint {
    device: DeviceId,
    owner: PeerOwnerToken,
    session: SessionValidityWitness,
}

impl ClosedRelayEndpoint {
    pub(crate) fn device(&self) -> &DeviceId {
        &self.device
    }
}

/// The engine authorization handed to the concrete `runtime::relay` adapter.
///
/// This is deliberately a witness bundle rather than a second relay runtime:
/// the runtime consumes it together with its provider-backed
/// `RelayAllocationPermit`.  It contains no IP address, key, payload, queue,
/// destination selector, or recursive forwarding capability.
#[derive(Clone)]
pub(crate) struct ClosedRelayAuthorization {
    state: Arc<NetworkState>,
    context: MeshContextId,
    relay: DeviceId,
    requester: ClosedRelayEndpoint,
    target: ClosedRelayEndpoint,
}

/// A successfully admitted runtime handle paired with the exact engine
/// witness and one provider lease for its engine-side registry custody.
pub(crate) struct ClosedRelayAdmission {
    pub(super) handle: ClosedRelayHandle,
    pub(super) terminal: ClosedRelayTerminalWitness,
    pub(super) lease: ResourceLease,
}

pub(crate) struct ClosedRelayResponse {
    control: ClosedRelayControl,
    owner: PeerOwnerToken,
}
pub(crate) type ClosedRelayGeneration = Arc<()>;

pub(crate) struct ClosedRelayCheckoutControl {
    closing: AtomicBool,
    finished: AtomicBool,
    wake: Notify,
    finished_wake: Notify,
}

impl ClosedRelayCheckoutControl {
    pub(crate) fn request_close(&self) {
        self.closing.store(true, Ordering::Release);
        self.wake.notify_waiters();
    }

    pub(crate) fn closing_notified(&self) -> tokio::sync::futures::Notified<'_> {
        self.wake.notified()
    }

    pub(crate) fn finish(&self) {
        self.finished.store(true, Ordering::Release);
        self.finished_wake.notify_waiters();
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.finished.load(Ordering::Acquire)
    }

    pub(crate) fn finished_notified(&self) -> tokio::sync::futures::Notified<'_> {
        self.finished_wake.notified()
    }
}

pub(crate) struct ClosedRelayCheckout {
    state: Weak<NetworkState>,
    session_id: [u8; 16],
    generation: ClosedRelayGeneration,
    route: (MeshContextId, DeviceId, DeviceId, DeviceId, u64),
    handle: Option<ClosedRelayHandle>,
    terminal: Option<ClosedRelayTerminalWitness>,
    lease: Option<ResourceLease>,
    control: Arc<ClosedRelayCheckoutControl>,
}

impl ClosedRelayCheckout {
    pub(crate) async fn recv(
        &mut self,
        direction: RelayDirection,
    ) -> Result<Option<OpaqueRelayPacket>, ClosedRelayRefusal> {
        self.handle
            .as_mut()
            .ok_or(ClosedRelayRefusal::OwnerNotLive)?
            .recv_direction_checked(direction)
            .await
    }

    pub(crate) fn control(&self) -> &Arc<ClosedRelayCheckoutControl> {
        &self.control
    }

    pub(crate) fn is_closing(&self) -> bool {
        self.control.closing.load(Ordering::Acquire)
    }

    pub(crate) fn route_and_generation(
        &self,
    ) -> (
        (MeshContextId, DeviceId, DeviceId, DeviceId, u64),
        ClosedRelayGeneration,
    ) {
        (self.route.clone(), self.generation.clone())
    }
}

impl Drop for ClosedRelayCheckout {
    fn drop(&mut self) {
        let control = Arc::clone(&self.control);
        let Some(handle) = self.handle.take() else {
            control.finish();
            return;
        };
        let Some(terminal) = self.terminal.take() else {
            drop(handle);
            control.finish();
            return;
        };
        let Some(lease) = self.lease.take() else {
            drop(handle);
            drop(terminal);
            control.finish();
            return;
        };
        if let Some(state) = self.state.upgrade() {
            state.finish_closed_relay_checkout(
                self.session_id,
                self.generation.clone(),
                handle,
                terminal,
                lease,
                Arc::clone(&self.control),
            );
        } else {
            drop(handle);
            drop(terminal);
            drop(lease);
        }
        control.finish();
    }
}

/// The state owner for admitted relay allocations. The vector is allocated at
/// the configured maximum before any allocation is admitted; no unbounded map
/// or hidden per-session collection is introduced. A slot's handle is taken
/// out before `recv_direction` awaits, so this registry mutex is never held
/// across an async boundary.
pub(crate) struct ClosedRelayRegistry {
    slots: Vec<ClosedRelaySlot>,
    capacity: usize,
}

struct ClosedRelaySlot {
    session_id: [u8; 16],
    generation: ClosedRelayGeneration,
    handle: Option<ClosedRelayHandle>,
    terminal: ClosedRelayTerminalWitness,
    lease: Option<ResourceLease>,
    checkout: Option<Arc<ClosedRelayCheckoutControl>>,
    closing: bool,
}

impl ClosedRelayRegistry {
    pub(crate) fn new(profile: &ClosedRelayPolicyConfig) -> Result<Self, ClosedRelayRefusal> {
        if !profile.enabled || !profile.validate() {
            return Err(ClosedRelayRefusal::InvalidProfile);
        }
        let capacity = usize::try_from(profile.max_allocations)
            .map_err(|_| ClosedRelayRefusal::InvalidProfile)?;
        Ok(Self {
            slots: Vec::with_capacity(capacity),
            capacity,
        })
    }

    pub(crate) fn insert(
        &mut self,
        session_id: [u8; 16],
        admission: ClosedRelayAdmission,
    ) -> Result<ClosedRelayGeneration, ClosedRelayRefusal> {
        if self.slots.len() >= self.capacity
            || self.slots.iter().any(|slot| slot.session_id == session_id)
        {
            drop(admission);
            return Err(ClosedRelayRefusal::QueueFull);
        }
        let ClosedRelayAdmission {
            handle,
            terminal,
            lease,
        } = admission;
        let generation = Arc::new(());
        self.slots.push(ClosedRelaySlot {
            session_id,
            generation: generation.clone(),
            handle: Some(handle),
            terminal,
            lease: Some(lease),
            checkout: None,
            closing: false,
        });
        Ok(generation)
    }

    pub(crate) fn take_checkout(
        &mut self,
        state: &Arc<NetworkState>,
        session_id: [u8; 16],
    ) -> Option<ClosedRelayCheckout> {
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.session_id == session_id && slot.handle.is_some())?;
        let handle = slot.handle.take()?;
        let lease = slot.lease.take()?;
        let control = Arc::new(ClosedRelayCheckoutControl {
            closing: AtomicBool::new(slot.closing),
            finished: AtomicBool::new(false),
            wake: Notify::new(),
            finished_wake: Notify::new(),
        });
        slot.checkout = Some(Arc::clone(&control));
        Some(ClosedRelayCheckout {
            state: Arc::downgrade(state),
            session_id,
            generation: slot.generation.clone(),
            route: (
                slot.terminal.context,
                slot.terminal.requester.device.clone(),
                slot.terminal.relay.clone(),
                slot.terminal.target.device.clone(),
                slot.terminal.allocation_epoch,
            ),
            handle: Some(handle),
            terminal: Some(slot.terminal.clone()),
            lease: Some(lease),
            control,
        })
    }

    pub(crate) fn mark_closing_exact(
        &mut self,
        session_id: [u8; 16],
        generation: &ClosedRelayGeneration,
    ) -> Result<Option<Arc<ClosedRelayCheckoutControl>>, ClosedRelayRefusal> {
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.session_id == session_id)
            .ok_or(ClosedRelayRefusal::OwnerNotLive)?;
        if !Arc::ptr_eq(&slot.generation, generation) {
            return Err(ClosedRelayRefusal::OwnerNotLive);
        }
        slot.closing = true;
        Ok(slot.checkout.clone())
    }

    pub(crate) fn contains(&self, session_id: [u8; 16]) -> bool {
        self.slots.iter().any(|slot| slot.session_id == session_id)
    }

    pub(crate) fn generation(&self, session_id: [u8; 16]) -> Option<ClosedRelayGeneration> {
        self.slots
            .iter()
            .find(|slot| slot.session_id == session_id)
            .map(|slot| slot.generation.clone())
    }

    pub(crate) fn request_close_all(&mut self) {
        for slot in &mut self.slots {
            slot.closing = true;
            if let Some(control) = slot.checkout.as_ref() {
                control.request_close();
            }
        }
    }

    pub(crate) fn finish_checkout(
        &mut self,
        session_id: [u8; 16],
        generation: ClosedRelayGeneration,
        handle: ClosedRelayHandle,
        terminal: ClosedRelayTerminalWitness,
        lease: ResourceLease,
        control: Arc<ClosedRelayCheckoutControl>,
    ) -> Option<ClosedRelayAdmission> {
        let Some(index) = self.slots.iter().position(|slot| {
            slot.session_id == session_id
                && Arc::ptr_eq(&slot.generation, &generation)
                && slot
                    .checkout
                    .as_ref()
                    .is_some_and(|existing| Arc::ptr_eq(existing, &control))
        }) else {
            return Some(ClosedRelayAdmission {
                handle,
                terminal,
                lease,
            });
        };
        let slot = &mut self.slots[index];
        slot.checkout = None;
        if slot.closing || control.closing.load(Ordering::Acquire) {
            let _ = self.slots.swap_remove(index);
            Some(ClosedRelayAdmission {
                handle,
                terminal,
                lease,
            })
        } else {
            slot.handle = Some(handle);
            slot.lease = Some(lease);
            None
        }
    }

    pub(crate) fn forward(
        &mut self,
        session_id: [u8; 16],
        direction: RelayDirection,
        packet: OpaqueRelayPacket,
    ) -> Result<(), ClosedRelayRefusal> {
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.session_id == session_id && !slot.closing)
            .ok_or(ClosedRelayRefusal::OwnerNotLive)?;
        slot.handle
            .as_mut()
            .ok_or(ClosedRelayRefusal::OwnerNotLive)?
            .try_forward_direction(direction, packet)
    }

    pub(crate) fn settle_exact(
        &mut self,
        session_id: [u8; 16],
        generation: &ClosedRelayGeneration,
    ) -> Result<ClosedRelayTerminal, ClosedRelayRefusal> {
        let index = self
            .slots
            .iter()
            .position(|slot| {
                slot.session_id == session_id
                    && Arc::ptr_eq(&slot.generation, generation)
                    && slot.handle.is_some()
            })
            .ok_or(ClosedRelayRefusal::OwnerNotLive)?;
        let slot = self.slots.swap_remove(index);
        settle_closed_relay(slot.handle.expect("slot handle was present"), slot.terminal)
    }

    pub(crate) fn retire_exact(
        &mut self,
        session_id: [u8; 16],
        generation: &ClosedRelayGeneration,
    ) -> Result<ClosedRelayTerminal, ClosedRelayRefusal> {
        let index = self
            .slots
            .iter()
            .position(|slot| {
                slot.session_id == session_id && Arc::ptr_eq(&slot.generation, generation)
            })
            .ok_or(ClosedRelayRefusal::OwnerNotLive)?;
        let slot = self.slots.swap_remove(index);
        let handle = slot.handle.ok_or(ClosedRelayRefusal::OwnerNotLive)?;
        settle_closed_relay(handle, slot.terminal)
    }

    pub(crate) fn settle_all(&mut self) -> usize {
        let mut settled = 0;
        let mut index = 0;
        while index < self.slots.len() {
            if self.slots[index].handle.is_none() {
                // A checked-out handle is finalized by its owner Drop. Keep
                // the slot until that Drop returns the exact custody.
                index += 1;
                continue;
            }
            let slot = self.slots.swap_remove(index);
            if settle_closed_relay(slot.handle.expect("slot handle was present"), slot.terminal)
                .is_ok()
            {
                settled += 1;
            }
        }
        settled
    }

    pub(crate) fn retire_stale(&mut self) -> usize {
        let mut retired = 0;
        let mut index = 0;
        while index < self.slots.len() {
            if self.slots[index].terminal.is_current() {
                index += 1;
                continue;
            }
            let checkout_control = self.slots[index].checkout.as_ref().map(Arc::clone);
            if let Some(control) = checkout_control {
                self.slots[index].closing = true;
                control.request_close();
                index += 1;
                continue;
            }
            let slot = self.slots.swap_remove(index);
            if let Some(handle) = slot.handle {
                let _ = settle_closed_relay(handle, slot.terminal);
            }
            retired += 1;
        }
        retired
    }

    pub(crate) fn checkout_control(&self) -> Option<Arc<ClosedRelayCheckoutControl>> {
        self.slots
            .iter()
            .find_map(|slot| slot.checkout.as_ref().map(Arc::clone))
    }

    pub(crate) fn route(
        &self,
        session_id: [u8; 16],
    ) -> Option<(MeshContextId, DeviceId, DeviceId, DeviceId, u64)> {
        let slot = self
            .slots
            .iter()
            .find(|slot| slot.session_id == session_id)?;
        Some((
            slot.terminal.context,
            slot.terminal.requester.device.clone(),
            slot.terminal.relay.clone(),
            slot.terminal.target.device.clone(),
            slot.terminal.allocation_epoch,
        ))
    }

    pub(crate) fn route_if_generation(
        &self,
        session_id: [u8; 16],
        generation: &ClosedRelayGeneration,
    ) -> Option<(MeshContextId, DeviceId, DeviceId, DeviceId, u64)> {
        let slot = self.slots.iter().find(|slot| {
            slot.session_id == session_id
                && Arc::ptr_eq(&slot.generation, generation)
                && slot.terminal.is_current()
        })?;
        Some((
            slot.terminal.context,
            slot.terminal.requester.device.clone(),
            slot.terminal.relay.clone(),
            slot.terminal.target.device.clone(),
            slot.terminal.allocation_epoch,
        ))
    }
}

/// Bounded Open/Offer/Accept handshake custody. The runtime guard remains
/// inside the pending value until Accept, refusal, or shutdown drops it.
pub(crate) struct ClosedRelayPendingRegistry {
    slots: Vec<ClosedRelayPending>,
    capacity: usize,
}

pub(crate) struct ClosedRelayPending {
    pub(crate) session_id: [u8; 16],
    pub(crate) allocation_epoch: u64,
    pub(crate) authorization: ClosedRelayAuthorization,
    pub(crate) _requester_share: RelayKeyShare,
    pub(crate) _guard: ClosedRelayHandshakeGuard,
    pub(crate) _expiry: ClosedRelayPendingExpiry,
    pub(crate) _lease: ResourceLease,
}

/// Owns the pending-expiry signal and cancels its waiter when the pending
/// record leaves the registry. Keeping this drop behavior in a field rather
/// than on `ClosedRelayPending` permits the authorization to be moved into
/// the admitted allocation while all remaining custody still drops normally.
pub(crate) struct ClosedRelayPendingExpiry {
    control: Arc<ClosedRelayPendingExpiryControl>,
}

impl ClosedRelayPendingExpiry {
    pub(crate) fn new(control: Arc<ClosedRelayPendingExpiryControl>) -> Self {
        Self { control }
    }
}

impl Drop for ClosedRelayPendingExpiry {
    fn drop(&mut self) {
        self.control.cancel();
    }
}

pub(crate) struct ClosedRelayPendingExpiryControl {
    wake: Notify,
    cancelled: AtomicBool,
}

impl ClosedRelayPendingExpiryControl {
    pub(crate) fn new() -> Self {
        Self {
            wake: Notify::new(),
            cancelled: AtomicBool::new(false),
        }
    }

    pub(crate) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.wake.notify_waiters();
    }

    pub(crate) fn cancelled(&self) -> tokio::sync::futures::Notified<'_> {
        self.wake.notified()
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

impl ClosedRelayPendingRegistry {
    pub(crate) fn new(profile: &ClosedRelayPolicyConfig) -> Result<Self, ClosedRelayRefusal> {
        if !profile.enabled || !profile.validate() {
            return Err(ClosedRelayRefusal::InvalidProfile);
        }
        let capacity = usize::try_from(profile.max_pending_handshakes)
            .map_err(|_| ClosedRelayRefusal::InvalidProfile)?;
        Ok(Self {
            slots: Vec::with_capacity(capacity),
            capacity,
        })
    }

    pub(crate) fn insert(&mut self, pending: ClosedRelayPending) -> Result<(), ClosedRelayRefusal> {
        if self.slots.len() >= self.capacity
            || self
                .slots
                .iter()
                .any(|slot| slot.session_id == pending.session_id)
        {
            drop(pending);
            return Err(ClosedRelayRefusal::QueueFull);
        }
        self.slots.push(pending);
        Ok(())
    }

    pub(crate) fn take(&mut self, session_id: [u8; 16]) -> Option<ClosedRelayPending> {
        let index = self
            .slots
            .iter()
            .position(|slot| slot.session_id == session_id)?;
        Some(self.slots.swap_remove(index))
    }

    pub(crate) fn take_matching(
        &mut self,
        session_id: [u8; 16],
        route: &crate::protocol::relay::ClosedRelayRoute,
        target_witness: &SessionValidityWitness,
    ) -> Result<ClosedRelayPending, ClosedRelayRefusal> {
        let index = self.matching_index(session_id, route, target_witness)?;
        Ok(self.slots.swap_remove(index))
    }

    pub(crate) fn matching_authorization(
        &self,
        session_id: [u8; 16],
        route: &crate::protocol::relay::ClosedRelayRoute,
        target_witness: &SessionValidityWitness,
    ) -> Result<ClosedRelayAuthorization, ClosedRelayRefusal> {
        let index = self.matching_index(session_id, route, target_witness)?;
        Ok(self.slots[index].authorization.clone())
    }

    fn matching_index(
        &self,
        session_id: [u8; 16],
        route: &crate::protocol::relay::ClosedRelayRoute,
        target_witness: &SessionValidityWitness,
    ) -> Result<usize, ClosedRelayRefusal> {
        let index = self
            .slots
            .iter()
            .position(|pending| pending.session_id == session_id)
            .ok_or(ClosedRelayRefusal::OwnerNotLive)?;
        let pending = &self.slots[index];
        let pending_route = crate::protocol::relay::ClosedRelayRoute::new(
            pending.authorization.context,
            pending.authorization.requester.device().clone(),
            pending.authorization.relay.clone(),
            pending.authorization.target.device().clone(),
            session_id,
        );
        let pending_route = crate::protocol::relay::ClosedRelayRoute::with_epoch(
            pending_route.context_id,
            pending_route.requester,
            pending_route.relay,
            pending_route.target,
            pending_route.session_id,
            pending.allocation_epoch,
        );
        if pending_route != *route
            || !pending
                .authorization
                .target
                .session
                .same_validity(target_witness)
        {
            return Err(ClosedRelayRefusal::OwnerMismatch);
        }
        Ok(index)
    }

    pub(crate) fn contains(&self, session_id: [u8; 16]) -> bool {
        self.slots.iter().any(|slot| slot.session_id == session_id)
    }

    pub(crate) fn epoch(&self, session_id: [u8; 16]) -> Option<u64> {
        self.slots
            .iter()
            .find(|slot| slot.session_id == session_id)
            .map(|slot| slot.allocation_epoch)
    }

    pub(crate) fn remove_stale(&mut self) -> usize {
        let mut removed = 0;
        let mut index = 0;
        while index < self.slots.len() {
            if self.slots[index].authorization.is_current() {
                index += 1;
                continue;
            }
            self.slots.swap_remove(index);
            removed += 1;
        }
        removed
    }

    pub(crate) fn clear(&mut self) -> usize {
        let count = self.slots.len();
        self.slots.clear();
        count
    }
}

pub(crate) struct ClosedRelayCloseRecord {
    // A close record is only a route-bound coordination record. The exact
    // allocation/pending registry retains its single lease until terminal
    // settlement, so this record deliberately does not double-charge it.
    pub(crate) session_id: [u8; 16],
    pub(crate) allocation_epoch: u64,
    pub(crate) allocation_generation: Option<ClosedRelayGeneration>,
    pub(crate) initiator: DeviceId,
    pub(crate) opposite: DeviceId,
    pub(crate) initiator_owner: PeerOwnerToken,
    pub(crate) opposite_owner: PeerOwnerToken,
    pub(crate) initiator_witness: SessionValidityWitness,
    pub(crate) opposite_witness: SessionValidityWitness,
}

impl ClosedRelayCloseRecord {
    fn is_current(&self, state: &NetworkState) -> bool {
        let owners_current = owner_witness_is_current(
            state,
            &self.initiator_owner,
            &self.initiator,
            &self.initiator_witness,
        ) && owner_witness_is_current(
            state,
            &self.opposite_owner,
            &self.opposite,
            &self.opposite_witness,
        );
        let exact_lifecycle = if let Some(generation) = self.allocation_generation.as_ref() {
            state
                .closed_relay_route(self.session_id)
                .is_some_and(|(_, _, _, _, epoch)| epoch == self.allocation_epoch)
                && state
                    .closed_relay_generation(self.session_id)
                    .is_some_and(|current| Arc::ptr_eq(&current, generation))
        } else {
            state
                .closed_relay_pending_epoch(self.session_id)
                .is_some_and(|epoch| epoch == self.allocation_epoch)
        };
        owners_current && self.allocation_epoch != 0 && exact_lifecycle
    }
}

pub(crate) struct ClosedRelayClosingRegistry {
    records: Vec<ClosedRelayCloseRecord>,
    capacity: usize,
}

impl ClosedRelayClosingRegistry {
    pub(crate) fn new(profile: &ClosedRelayPolicyConfig) -> Result<Self, ClosedRelayRefusal> {
        if !profile.enabled || !profile.validate() {
            return Err(ClosedRelayRefusal::InvalidProfile);
        }
        let capacity = usize::try_from(profile.max_allocations)
            .map_err(|_| ClosedRelayRefusal::InvalidProfile)?;
        Ok(Self {
            records: Vec::with_capacity(capacity),
            capacity,
        })
    }

    pub(crate) fn begin(
        &mut self,
        record: ClosedRelayCloseRecord,
    ) -> Result<bool, ClosedRelayRefusal> {
        if self
            .records
            .iter()
            .any(|existing| existing.session_id == record.session_id)
        {
            return Ok(false);
        }
        if self.records.len() >= self.capacity {
            return Err(ClosedRelayRefusal::QueueFull);
        }
        self.records.push(record);
        Ok(true)
    }

    pub(crate) fn take(
        &mut self,
        session_id: [u8; 16],
        opposite: &DeviceId,
        witness: &SessionValidityWitness,
        allocation_epoch: u64,
    ) -> Option<ClosedRelayCloseRecord> {
        let index = self.records.iter().position(|record| {
            record.session_id == session_id
                && &record.opposite == opposite
                && record.opposite_witness.same_validity(witness)
                && record.allocation_epoch == allocation_epoch
        })?;
        Some(self.records.swap_remove(index))
    }

    pub(crate) fn remove(&mut self, session_id: [u8; 16]) -> Option<ClosedRelayCloseRecord> {
        let index = self
            .records
            .iter()
            .position(|record| record.session_id == session_id)?;
        Some(self.records.swap_remove(index))
    }

    pub(crate) fn remove_stale(&mut self, state: &NetworkState) -> usize {
        let mut removed = 0;
        let mut index = 0;
        while index < self.records.len() {
            if self.records[index].is_current(state) {
                index += 1;
                continue;
            }
            let record = self.records.swap_remove(index);
            if let Some(generation) = record.allocation_generation.as_ref() {
                // Stale Close custody is terminal, not merely forgotten. The
                // exact generation fence prevents a successor from being
                // touched, while runtime settlement installs its provider-
                // funded non-expiring session tombstone.
                let _ = state.settle_closed_relay_exact(record.session_id, generation);
            }
            removed += 1;
        }
        removed
    }

    pub(crate) fn contains(&self, session_id: [u8; 16]) -> bool {
        self.records
            .iter()
            .any(|record| record.session_id == session_id)
    }
}

impl ClosedRelayAuthorization {
    /// Admit this already-bound route through the concrete provider-backed
    /// runtime. Permit issuance deliberately occurs after `bind_closed_relay`
    /// and its currentness fence; a failed semantic or owner check therefore
    /// cannot reserve a relay allocation.
    pub(crate) fn admit_to_runtime(
        &self,
        runtime: &ClosedRelayRuntime,
        profile: &ClosedRelayPolicyConfig,
        session_id: [u8; 16],
        allocation_epoch: u64,
    ) -> Result<ClosedRelayAdmission, ClosedRelayRefusal> {
        if !self.is_current() {
            return Err(ClosedRelayRefusal::OwnerNotLive);
        }
        let lease = self
            .state
            .acquire_closed_relay_lease(allocation_lease_claim(self)?)
            .map_err(|_| ClosedRelayRefusal::QueueFull)?;
        let permit = RelayAllocationPermit::try_new(self.requester.session.clone(), profile)?;
        let endpoints = ClosedRelayEndpoints::new(
            self.context,
            self.requester.device.clone(),
            self.target.device.clone(),
            session_id,
            allocation_epoch,
        )?;
        let terminal = self.terminal_witness(session_id, allocation_epoch);
        runtime
            .admit_closed_relay(
                permit,
                terminal.requester.session.clone(),
                terminal.target.session.clone(),
                endpoints,
            )
            .map(|handle| ClosedRelayAdmission {
                handle,
                terminal,
                lease,
            })
    }

    /// Re-prove the immutable policy and both exact session lineages before a
    /// runtime terminal effect.  This is synchronous and lock-bounded; the
    /// runtime must call it before forwarding or settlement and must not await
    /// while any engine registry lock is held.
    pub(crate) fn is_current(&self) -> bool {
        if !closed_profile(&self.state) || self.state.mesh_context_id() != self.context {
            return false;
        }
        let graph = self.state.authoritative_fact_graph();
        let graph = graph.read();
        if graph.context_id() != self.context {
            return false;
        }
        let evaluator = graph.evaluator();
        if !evaluator.admits_closed_session(&self.relay, self.requester.device())
            || !evaluator.admits_closed_session(&self.relay, self.target.device())
        {
            return false;
        }
        drop(graph);

        endpoint_is_current(&self.state, &self.requester)
            && endpoint_is_current(&self.state, &self.target)
    }

    /// Consume the authorization only after the runtime has observed its
    /// exact terminal state.  No new authority is minted here; the returned
    /// state is only the engine-side witness needed by a runtime settlement
    /// hook.
    pub(crate) fn terminal_witness(
        &self,
        session_id: [u8; 16],
        allocation_epoch: u64,
    ) -> ClosedRelayTerminalWitness {
        ClosedRelayTerminalWitness {
            state: Arc::clone(&self.state),
            context: self.context,
            relay: self.relay.clone(),
            requester: self.requester.clone(),
            target: self.target.clone(),
            session_id,
            allocation_epoch,
        }
    }
}

/// Recheck the exact engine witness before consuming the runtime handle. A
/// stale replacement is refused and dropping the un-settled handle performs
/// runtime cleanup; no second settlement path is introduced here.
pub(crate) fn settle_closed_relay(
    handle: ClosedRelayHandle,
    terminal: ClosedRelayTerminalWitness,
) -> Result<ClosedRelayTerminal, ClosedRelayRefusal> {
    if !terminal.is_current() {
        handle.settle_stale();
        return Err(ClosedRelayRefusal::OwnerNotLive);
    }
    Ok(handle.settle())
}

/// Exact owner/session data retained until `runtime::relay` settles.  This is
/// not a terminal enum and does not settle a provider permit; it is a narrow
/// engine callback input that lets the runtime re-prove successor safety.
#[derive(Clone)]
pub(crate) struct ClosedRelayTerminalWitness {
    state: Arc<NetworkState>,
    context: MeshContextId,
    relay: DeviceId,
    requester: ClosedRelayEndpoint,
    target: ClosedRelayEndpoint,
    session_id: [u8; 16],
    allocation_epoch: u64,
}

impl ClosedRelayTerminalWitness {
    pub(crate) fn is_current(&self) -> bool {
        if let Some((_, _, _, _, epoch)) = self.state.closed_relay_route(self.session_id) {
            if epoch != self.allocation_epoch {
                return false;
            }
        }
        ClosedRelayAuthorization {
            state: Arc::clone(&self.state),
            context: self.context,
            relay: self.relay.clone(),
            requester: self.requester.clone(),
            target: self.target.clone(),
        }
        .is_current()
    }
}

/// Bind a Closed route to canonical semantic state and exact promoted remote
/// sessions.  All checks happen before the runtime receives an allocation
/// permit, so a refusal cannot reserve a queue or create an endpoint session.
pub(crate) fn bind_closed_relay(
    state: &Arc<NetworkState>,
    requester: DeviceId,
    relay: DeviceId,
    target: DeviceId,
) -> Result<ClosedRelayAuthorization, ClosedRelayRefusal> {
    let context = state.mesh_context_id();
    if !closed_profile(state) {
        return Err(ClosedRelayRefusal::InvalidProfile);
    }
    let local = DeviceId::from_canonical_str(state.identity.public_id())
        .map_err(|_| invalid("local identity is not a canonical DeviceId"))?;
    validate_route(&requester, &relay, &target, &local)?;

    {
        let graph = state.authoritative_fact_graph();
        let graph = graph.read();
        if graph.context_id() != context {
            return Err(invalid(
                "semantic graph context does not match engine context",
            ));
        }
        let evaluator = graph.evaluator();
        if !member_with_authority(&evaluator, &relay)
            || !member_with_authority(&evaluator, &requester)
            || !member_with_authority(&evaluator, &target)
            || !evaluator.admits_closed_session(&relay, &requester)
            || !evaluator.admits_closed_session(&relay, &target)
        {
            return Err(invalid(
                "Closed projection does not admit every route member",
            ));
        }
    }

    let requester = capture_endpoint(state, requester).ok_or(ClosedRelayRefusal::OwnerNotLive)?;
    let target = capture_endpoint(state, target).ok_or(ClosedRelayRefusal::OwnerNotLive)?;
    let authorization = ClosedRelayAuthorization {
        state: Arc::clone(state),
        context,
        relay: local,
        requester,
        target,
    };
    authorization
        .is_current()
        .then_some(authorization)
        .ok_or(ClosedRelayRefusal::OwnerNotLive)
}

fn closed_profile(state: &NetworkState) -> bool {
    matches!(
        state.verified_policy(),
        VerifiedProjectPolicy::Closed(policy)
            if policy.profile()
                == crate::semantic::ClosedProfileId::SingleRootSignedMemberLogV1
    )
}

fn validate_route(
    requester: &DeviceId,
    relay: &DeviceId,
    target: &DeviceId,
    local: &DeviceId,
) -> Result<(), ClosedRelayRefusal> {
    if requester == relay || requester == target || relay == target || relay != local {
        Err(invalid(
            "route endpoints must be distinct and the relay must be local",
        ))
    } else {
        Ok(())
    }
}

fn member_with_authority(
    evaluator: &crate::semantic::causal::SemanticEvaluator<'_>,
    device: &DeviceId,
) -> bool {
    evaluator
        .effective_authorized_role(device)
        .is_some_and(|role| matches!(role, Role::Owner | Role::Controller | Role::Member))
        && evaluator
            .effective_membership(device)
            .is_none_or(|joined| joined)
}

fn capture_endpoint(state: &Arc<NetworkState>, device: DeviceId) -> Option<ClosedRelayEndpoint> {
    let owner = state.peers.owner(&device)?;
    let session = state
        .peers
        .with_current(&owner, |peer| {
            peer.with_live_session(|session| session.validity_witness())
        })
        .flatten()?;
    Some(ClosedRelayEndpoint {
        device,
        owner,
        session,
    })
}

fn endpoint_is_current(state: &Arc<NetworkState>, endpoint: &ClosedRelayEndpoint) -> bool {
    endpoint.session.is_live()
        && state
            .peers
            .with_current(&endpoint.owner, |peer| {
                peer.with_live_session(|session| endpoint.session.witnesses(session))
            })
            .flatten()
            .unwrap_or(false)
}

fn owner_witness_is_current(
    state: &NetworkState,
    owner: &PeerOwnerToken,
    device: &DeviceId,
    witness: &SessionValidityWitness,
) -> bool {
    witness.is_live()
        && owner.device_id() == device.base32().as_str()
        && state
            .peers
            .with_current(owner, |peer| {
                peer.with_live_session(|session| witness.witnesses(session))
            })
            .flatten()
            .unwrap_or(false)
}

fn control_fields(
    control: &ClosedRelayControl,
) -> (&MeshContextId, &DeviceId, &DeviceId, &DeviceId, &[u8; 16]) {
    match control {
        ClosedRelayControl::Open {
            context_id,
            requester,
            relay,
            target,
            session_id,
            ..
        }
        | ClosedRelayControl::Offer {
            context_id,
            requester,
            relay,
            target,
            session_id,
            ..
        }
        | ClosedRelayControl::Accept {
            context_id,
            requester,
            relay,
            target,
            session_id,
            ..
        }
        | ClosedRelayControl::Close {
            context_id,
            requester,
            relay,
            target,
            session_id,
            ..
        } => (context_id, requester, relay, target, session_id),
    }
}

fn canonical_route_admitted(
    state: &NetworkState,
    requester: &DeviceId,
    relay: &DeviceId,
    target: &DeviceId,
) -> Result<(), ClosedRelayRefusal> {
    if !closed_profile(state) {
        return Err(ClosedRelayRefusal::InvalidProfile);
    }
    if requester == relay || requester == target || relay == target {
        return Err(invalid("Closed relay route endpoints must be distinct"));
    }
    let context = state.mesh_context_id();
    let graph = state.authoritative_fact_graph();
    let graph = graph.read();
    if graph.context_id() != context {
        return Err(invalid(
            "relay control context differs from the semantic graph",
        ));
    }
    let evaluator = graph.evaluator();
    if !member_with_authority(&evaluator, requester)
        || !member_with_authority(&evaluator, relay)
        || !member_with_authority(&evaluator, target)
        || !evaluator.admits_closed_session(relay, requester)
        || !evaluator.admits_closed_session(relay, target)
    {
        return Err(invalid(
            "Closed projection does not admit the complete route",
        ));
    }
    Ok(())
}

fn validate_control_for_relay(
    state: &NetworkState,
    control: &ClosedRelayControl,
) -> Result<(), ClosedRelayRefusal> {
    control
        .validate()
        .map_err(|error| invalid(format!("invalid Closed relay control: {error}")))?;
    let (context, requester, relay, target, _) = control_fields(control);
    let local = DeviceId::from_canonical_str(state.identity.public_id())
        .map_err(|_| invalid("local identity is not a canonical DeviceId"))?;
    if *context != state.mesh_context_id()
        || *relay != local
        || *requester == local
        || *target == local
    {
        return Err(invalid("control is not bound to this local relay"));
    }
    canonical_route_admitted(state, requester, relay, target)
}

fn current_owner_witness(
    state: &Arc<NetworkState>,
    owner: &PeerOwnerToken,
    expected: &DeviceId,
) -> Result<SessionValidityWitness, ClosedRelayRefusal> {
    if owner.device_id() != expected.base32().as_str() {
        return Err(ClosedRelayRefusal::OwnerMismatch);
    }
    state
        .peers
        .with_current(owner, |peer| {
            peer.with_live_session(|session| session.validity_witness())
        })
        .flatten()
        .ok_or(ClosedRelayRefusal::OwnerNotLive)
}

fn current_owner_for_device(
    state: &NetworkState,
    device: &DeviceId,
) -> Result<PeerOwnerToken, ClosedRelayRefusal> {
    let owner = state
        .peers
        .owner(device)
        .ok_or(ClosedRelayRefusal::OwnerNotLive)?;
    state
        .peers
        .get_if_current(&owner)
        .map(|_| owner)
        .ok_or(ClosedRelayRefusal::OwnerNotLive)
}

async fn handle_close(
    state: &Arc<NetworkState>,
    owner: &PeerOwnerToken,
    control: ClosedRelayControl,
) -> Result<(), ClosedRelayRefusal> {
    control
        .validate()
        .map_err(|error| invalid(format!("invalid Closed relay Close: {error}")))?;
    validate_outbound_control(state, &control)?;
    let (context, requester, relay, target, session_id) = control_fields(&control);
    let allocation_epoch = match &control {
        ClosedRelayControl::Close {
            allocation_epoch, ..
        } => *allocation_epoch,
        _ => unreachable!("handle_close only receives Close"),
    };
    let local = DeviceId::from_canonical_str(state.identity.public_id())
        .map_err(|_| invalid("local identity is not a canonical DeviceId"))?;

    if *relay == local {
        canonical_route_admitted(state, requester, relay, target)?;
        if state.has_closed_relay_custody(*session_id) {
            let current_epoch = state
                .closed_relay_route(*session_id)
                .map(|(_, _, _, _, epoch)| epoch)
                .or_else(|| state.closed_relay_pending_epoch(*session_id));
            if current_epoch.is_some_and(|epoch| epoch != allocation_epoch) {
                return Err(ClosedRelayRefusal::OwnerNotLive);
            }
        }
        let (sender_device, opposite, sender_witness) =
            if owner.device_id() == requester.base32().as_str() {
                (
                    requester,
                    target,
                    current_owner_witness(state, owner, requester)?,
                )
            } else if owner.device_id() == target.base32().as_str() {
                (
                    target,
                    requester,
                    current_owner_witness(state, owner, target)?,
                )
            } else {
                return Err(ClosedRelayRefusal::OwnerMismatch);
            };
        if let Some(record) = state.take_closed_relay_close(
            *session_id,
            sender_device,
            &sender_witness,
            allocation_epoch,
        ) {
            let record_current = record.is_current(state);
            if let Some(generation) = record.allocation_generation.as_ref() {
                let _ = state.settle_closed_relay_exact(*session_id, generation);
            } else {
                // A pending Open has no allocation generation yet. Its
                // handshake custody is nevertheless exact and must be
                // consumed once this close record is consumed, even when the
                // captured owner witness has gone stale; dropping a stale
                // pending record cannot touch a successor installation.
                let _ = state.take_closed_relay_pending(*session_id);
            }
            if !record_current {
                // A delayed Close may still match the opposite endpoint's
                // witness after the initiator or allocation was replaced.
                // Consume only this close record; never acknowledge it or
                // touch the successor allocation.
                return Err(ClosedRelayRefusal::OwnerNotLive);
            }
            send_control_to_owner(state, &record.initiator_owner, control).await?;
            return Ok(());
        }

        // A valid duplicate after exact settlement is terminally harmless;
        // it must not require a successor owner or recreate custody.
        if !state.has_closed_relay_custody(*session_id) {
            return Ok(());
        }

        let opposite_owner = current_owner_for_device(state, opposite)?;
        let opposite_witness = current_owner_witness(state, &opposite_owner, opposite)?;
        let allocation_generation = state.closed_relay_generation(*session_id);
        let record = ClosedRelayCloseRecord {
            session_id: *session_id,
            allocation_epoch,
            allocation_generation: allocation_generation.clone(),
            initiator: sender_device.clone(),
            opposite: opposite.clone(),
            initiator_owner: owner.clone(),
            opposite_owner: opposite_owner.clone(),
            initiator_witness: sender_witness,
            opposite_witness,
        };
        match state.begin_closed_relay_close(record)? {
            true => {}
            false => return Ok(()),
        }

        if let Err(error) = send_control_to_owner(state, &opposite_owner, control.clone()).await {
            let _ = state.cancel_closed_relay_close(*session_id);
            let _ = state.take_closed_relay_pending(*session_id);
            if let Some(generation) = allocation_generation.as_ref() {
                let _ = state.settle_closed_relay_exact(*session_id, generation);
            }
            let _ = send_control_to_owner(state, owner, control).await;
            return Err(error);
        }
        Ok(())
    } else {
        if *context != state.mesh_context_id() || (*requester != local && *target != local) {
            return Err(ClosedRelayRefusal::OwnerMismatch);
        }
        canonical_route_admitted(state, requester, relay, target)?;
        let _relay_witness = current_owner_witness(state, owner, relay)?;
        let Some(session) = state.closed_relay_endpoint(*session_id) else {
            // A duplicate terminal Close is harmless after the exact endpoint
            // has already been removed; it cannot recreate endpoint custody.
            return Ok(());
        };
        let metadata = session.metadata();
        let epoch_matches = metadata.allocation_epoch == allocation_epoch
            || (metadata.allocation_epoch == 0
                && state
                    .closed_relay_pending_epoch(*session_id)
                    .is_some_and(|pending_epoch| pending_epoch == allocation_epoch));
        if metadata.context != *context
            || metadata.requester != *requester
            || metadata.relay != *relay
            || metadata.target != *target
            || metadata.session_id != *session_id
            || !epoch_matches
            || (local != metadata.requester && local != metadata.target)
        {
            return Err(ClosedRelayRefusal::OwnerMismatch);
        }
        let was_closing = session.is_closing();
        state.remove_closed_relay_endpoint(&session);
        session.mark_closed();
        if was_closing {
            return Ok(());
        }
        send_control_to_owner(state, owner, control).await
    }
}

async fn send_control_to_owner(
    state: &Arc<NetworkState>,
    owner: &PeerOwnerToken,
    control: ClosedRelayControl,
) -> Result<(), ClosedRelayRefusal> {
    validate_outbound_control(state, &control)?;
    super::send_to_peer_owner(
        state,
        owner,
        &crate::protocol::MeshMessage::ClosedRelayControl(control),
    )
    .await
    .map_err(|_| ClosedRelayRefusal::CarrierUnavailable)
}

/// Execute one network-owned abandonment handoff. This is deliberately
/// awaited by state-owned engine boundaries; `EndpointSession::Drop` only
/// enqueues the bounded record and never creates a detached task.
pub(crate) async fn settle_closed_relay_abandonment(
    state: &Arc<NetworkState>,
    abandonment: ClosedRelayAbandonment,
) -> Result<(), ClosedRelayAbandonment> {
    if abandonment.route.allocation_epoch == 0 {
        let _ = state.take_closed_relay_pending(abandonment.route.session_id);
        return Ok(());
    }
    let control = ClosedRelayControl::Close {
        version: crate::protocol::relay::CLOSED_RELAY_CONTROL_VERSION,
        context_id: abandonment.route.context_id,
        requester: abandonment.route.requester.clone(),
        relay: abandonment.route.relay.clone(),
        target: abandonment.route.target.clone(),
        session_id: abandonment.route.session_id,
        allocation_epoch: abandonment.route.allocation_epoch,
    };
    let mut settled = false;
    if owner_witness_is_current(
        state,
        &abandonment.relay_owner,
        &abandonment.route.relay,
        &abandonment.relay_witness,
    ) {
        settled = send_control_to_owner(state, &abandonment.relay_owner, control)
            .await
            .is_ok();
    }
    if let Some(generation) = abandonment.allocation_generation.as_ref() {
        settled |= state
            .settle_closed_relay_exact(abandonment.route.session_id, generation)
            .is_ok();
    }
    if settled {
        Ok(())
    } else {
        Err(abandonment)
    }
}

fn validate_outbound_control(
    state: &NetworkState,
    control: &ClosedRelayControl,
) -> Result<(), ClosedRelayRefusal> {
    let profile = state.config.read().closed_relay.clone();
    if !profile.validate() {
        return Err(ClosedRelayRefusal::InvalidProfile);
    }
    if !profile.validate_closed_relay_control(control) {
        return Err(ClosedRelayRefusal::InvalidPacket(
            "closed relay control exceeds configured encoded-byte bound".into(),
        ));
    }
    Ok(())
}

fn endpoint_capacity(state: &NetworkState) -> Result<usize, ClosedRelayRefusal> {
    usize::try_from(state.config.read().closed_relay.queue_items_per_direction)
        .map_err(|_| ClosedRelayRefusal::InvalidProfile)
}

fn checked_claim_bytes(value: usize) -> Result<u64, ClosedRelayRefusal> {
    u64::try_from(value).map_err(|_| ClosedRelayRefusal::InvalidProfile)
}

fn endpoint_lease_claim(
    profile: &ClosedRelayPolicyConfig,
    capacity: usize,
    context: &MeshContextId,
    requester: &DeviceId,
    relay: &DeviceId,
    target: &DeviceId,
) -> Result<ResourceClaim, ClosedRelayRefusal> {
    let max_ciphertext =
        crate::runtime::relay::checked_ciphertext_ceiling(profile.max_frame_ciphertext_bytes)?;
    let queued_bytes = capacity
        .checked_mul(max_ciphertext)
        .ok_or(ClosedRelayRefusal::InvalidProfile)?;
    // Measure the allocator's actual VecDeque capacity, rather than assuming
    // the requested logical length is the backing allocation.
    let queue_capacity = VecDeque::<OpaqueRelayPacket>::with_capacity(capacity).capacity();
    let packet_slots = queue_capacity
        .checked_mul(std::mem::size_of::<OpaqueRelayPacket>())
        .ok_or(ClosedRelayRefusal::InvalidProfile)?;
    let replay_slots = usize::try_from(profile.replay_window)
        .map_err(|_| ClosedRelayRefusal::InvalidProfile)?
        .checked_mul(std::mem::size_of::<bool>())
        .ok_or(ClosedRelayRefusal::InvalidProfile)?;
    let mesh = context.base32();
    let requester_wire = requester.base32();
    let relay_wire = relay.base32();
    let target_wire = target.base32();
    let route_bytes = requester_wire
        .capacity()
        .checked_add(relay_wire.capacity())
        .and_then(|bytes| bytes.checked_add(target_wire.capacity()))
        .ok_or(ClosedRelayRefusal::InvalidProfile)?;
    let key_session_bytes = requester_wire
        .capacity()
        .checked_add(target_wire.capacity())
        .ok_or(ClosedRelayRefusal::InvalidProfile)?;
    let packet_string_bytes = capacity
        .checked_mul(
            mesh.capacity()
                .checked_add(requester_wire.capacity())
                .and_then(|bytes| bytes.checked_add(target_wire.capacity()))
                .ok_or(ClosedRelayRefusal::InvalidProfile)?,
        )
        .ok_or(ClosedRelayRefusal::InvalidProfile)?;
    let accounted = std::mem::size_of::<EndpointSessionInner>()
        .checked_add(packet_slots)
        .and_then(|bytes| bytes.checked_add(replay_slots))
        .and_then(|bytes| bytes.checked_add(route_bytes))
        .and_then(|bytes| bytes.checked_add(key_session_bytes))
        .and_then(|bytes| bytes.checked_add(packet_string_bytes))
        .ok_or(ClosedRelayRefusal::InvalidProfile)?;
    let retained_allocations = 1usize
        .checked_add(3) // the endpoint's canonical requester/relay/target Strings
        .and_then(|count| count.checked_add(1)) // endpoint inbound VecDeque
        .and_then(|count| count.checked_add(1)) // endpoint replay-window Vec
        .and_then(|count| count.checked_add(capacity.checked_mul(4)?)) // packet Strings + ciphertext
        .ok_or(ClosedRelayRefusal::InvalidProfile)?;
    ResourceClaim::try_from_entries([
        (
            ResourceClass::AccountedMemoryBytes,
            checked_claim_bytes(accounted)?,
        ),
        (
            ResourceClass::QueuedBytes,
            checked_claim_bytes(queued_bytes)?,
        ),
        (ResourceClass::RelayOrProviderAllocation, 1),
        (
            ResourceClass::OpaqueDependencyResidual,
            checked_claim_bytes(retained_allocations)?,
        ),
    ])
    .map_err(|_| ClosedRelayRefusal::InvalidProfile)
}

fn pending_lease_claim(
    authorization: &ClosedRelayAuthorization,
    requester_share: &RelayKeyShare,
) -> Result<ResourceClaim, ClosedRelayRefusal> {
    // These fields are retained String buffers; charge their capacities, not
    // only their visible lengths. The share has one mesh buffer; charging it
    // twice would create a false refusal without funding any additional
    // retained object.
    let route_bytes = retained_route_bytes(authorization)?
        .checked_add(requester_share.mesh.capacity())
        .and_then(|bytes| bytes.checked_add(requester_share.from.capacity()))
        .and_then(|bytes| bytes.checked_add(requester_share.to.capacity()))
        .and_then(|bytes| bytes.checked_add(requester_share.signature.capacity()))
        .ok_or(ClosedRelayRefusal::InvalidProfile)?;
    let accounted = std::mem::size_of::<ClosedRelayPending>()
        .checked_add(route_bytes)
        .ok_or(ClosedRelayRefusal::InvalidProfile)?;
    let retained_allocations = 3usize
        .checked_add(4) // requester-share mesh/from/to/signature Strings
        .and_then(|count| count.checked_add(1)) // pending-expiry control Arc
        .ok_or(ClosedRelayRefusal::InvalidProfile)?;
    ResourceClaim::try_from_entries([
        (
            ResourceClass::AccountedMemoryBytes,
            checked_claim_bytes(accounted)?,
        ),
        (ResourceClass::RelayOrProviderAllocation, 1),
        (
            ResourceClass::OpaqueDependencyResidual,
            checked_claim_bytes(retained_allocations)?,
        ),
    ])
    .map_err(|_| ClosedRelayRefusal::InvalidProfile)
}

fn allocation_lease_claim(
    authorization: &ClosedRelayAuthorization,
) -> Result<ResourceClaim, ClosedRelayRefusal> {
    let route_bytes = retained_route_bytes(authorization)?;
    let checkout_route_bytes = authorization
        .requester
        .device
        .base32()
        .capacity()
        .checked_add(authorization.relay.base32().capacity())
        .and_then(|bytes| bytes.checked_add(authorization.target.device.base32().capacity()))
        .and_then(|bytes| bytes.checked_mul(2))
        .ok_or(ClosedRelayRefusal::InvalidProfile)?;
    let accounted = std::mem::size_of::<ClosedRelaySlot>()
        .checked_add(route_bytes)
        .and_then(|bytes| bytes.checked_add(checkout_route_bytes))
        .ok_or(ClosedRelayRefusal::InvalidProfile)?;
    let retained_allocations = 3usize
        .checked_add(1) // the generation token's Arc allocation
        .and_then(|count| count.checked_add(6)) // checkout route and terminal clones
        .ok_or(ClosedRelayRefusal::InvalidProfile)?;
    ResourceClaim::try_from_entries([
        (
            ResourceClass::AccountedMemoryBytes,
            checked_claim_bytes(accounted)?,
        ),
        (ResourceClass::RelayOrProviderAllocation, 1),
        (
            ResourceClass::OpaqueDependencyResidual,
            checked_claim_bytes(retained_allocations)?,
        ),
    ])
    .map_err(|_| ClosedRelayRefusal::InvalidProfile)
}

fn retained_route_bytes(
    authorization: &ClosedRelayAuthorization,
) -> Result<usize, ClosedRelayRefusal> {
    let context = authorization.context.base32();
    let requester = authorization.requester.device.base32();
    let relay = authorization.relay.base32();
    let target = authorization.target.device.base32();
    context
        .capacity()
        .checked_add(requester.capacity())
        .and_then(|bytes| bytes.checked_add(relay.capacity()))
        .and_then(|bytes| bytes.checked_add(target.capacity()))
        .ok_or(ClosedRelayRefusal::InvalidProfile)
}

fn max_frame_ciphertext(state: &NetworkState) -> Result<usize, ClosedRelayRefusal> {
    crate::runtime::relay::checked_ciphertext_ceiling(
        state.config.read().closed_relay.max_frame_ciphertext_bytes,
    )
}

/// Start the requester-side endpoint agreement. The returned pending value
/// retains the bounded handshake guard until the exact target Accept arrives.
pub(crate) fn begin_closed_relay_open(
    state: &Arc<NetworkState>,
    relay: DeviceId,
    target: DeviceId,
    session_id: [u8; 16],
) -> Result<(PendingEndpointKeyAgreement, ClosedRelayControl), ClosedRelayRefusal> {
    validate_session_id(session_id)?;
    let requester = DeviceId::from_canonical_str(state.identity.public_id())
        .map_err(|_| invalid("local identity is not a canonical DeviceId"))?;
    canonical_route_admitted(state, &requester, &relay, &target)?;
    if requester == relay || requester == target {
        return Err(invalid("requester must not be the relay or target"));
    }
    let profile = state.config.read().closed_relay.clone();
    let runtime = state
        .closed_relay_runtime()
        .ok_or(ClosedRelayRefusal::InvalidProfile)?;
    let (pending, requester_share) = PendingEndpointKeyAgreement::begin_with_runtime(
        runtime,
        &state.identity,
        state.mesh_context_id(),
        target.clone(),
        session_id,
        &profile,
    )?;
    let control = ClosedRelayControl::Open {
        version: crate::protocol::relay::OPAQUE_RELAY_VERSION,
        context_id: state.mesh_context_id(),
        requester,
        relay,
        target,
        session_id,
        requester_share,
    };
    validate_outbound_control(state, &control)?;
    Ok((pending, control))
}

/// Begin and send an endpoint Open through the exact current relay owner.
/// The returned session is ready only after the matching Accept has been
/// processed against this exact endpoint installation.
pub(crate) async fn open_endpoint(
    state: &Arc<NetworkState>,
    relay: DeviceId,
    target: DeviceId,
    session_id: [u8; 16],
) -> Result<EndpointSession, ClosedRelayRefusal> {
    validate_session_id(session_id)?;
    state.drain_closed_relay_abandonments().await;
    let requester = DeviceId::from_canonical_str(state.identity.public_id())
        .map_err(|_| invalid("local identity is not a canonical DeviceId"))?;
    canonical_route_admitted(state, &requester, &relay, &target)?;
    let capacity = endpoint_capacity(state)?;
    let profile = state.config.read().closed_relay.clone();
    let _runtime = state
        .closed_relay_runtime()
        .ok_or(ClosedRelayRefusal::InvalidProfile)?;
    let lease = state
        .acquire_closed_relay_lease(endpoint_lease_claim(
            &profile,
            capacity,
            &state.mesh_context_id(),
            &requester,
            &relay,
            &target,
        )?)
        .map_err(|_| ClosedRelayRefusal::QueueFull)?;
    let (pending, control) =
        match begin_closed_relay_open(state, relay.clone(), target.clone(), session_id) {
            Ok(value) => value,
            Err(error) => {
                drop(lease);
                return Err(error);
            }
        };
    let owner = match current_owner_for_device(state, &relay) {
        Ok(owner) => owner,
        Err(error) => {
            drop(pending);
            drop(lease);
            return Err(error);
        }
    };
    let relay_witness = match current_owner_witness(state, &owner, &relay) {
        Ok(witness) => witness,
        Err(error) => {
            drop(pending);
            drop(lease);
            return Err(error);
        }
    };
    let session = EndpointSession::pending(
        state,
        EndpointSessionRoute {
            relay_owner: owner,
            relay_witness,
            context: state.mesh_context_id(),
            requester,
            relay,
            target,
            session_id,
            allocation_epoch: 0,
        },
        pending,
        capacity,
        lease,
    );
    if let Err(error) = state.insert_closed_relay_endpoint(session.clone()) {
        drop(session);
        return Err(error);
    }
    if let Err(error) = send_control_to_owner(state, &session.0.relay_owner, control).await {
        state.remove_closed_relay_endpoint(&session);
        session.mark_closed();
        return Err(error);
    }
    if let Err(error) = session.wait_ready().await {
        state.remove_closed_relay_endpoint(&session);
        session.mark_closed();
        return Err(error);
    }
    Ok(session)
}

/// Handle the relay member's Open/Accept/Close controls. A response is
/// returned for the caller to send only over the exact owner selected by its
/// route; this function never resolves a peer by a string or sends under a
/// lock.
pub(crate) fn on_control(
    state: &Arc<NetworkState>,
    owner: &PeerOwnerToken,
    control: ClosedRelayControl,
) -> Result<Option<ClosedRelayResponse>, ClosedRelayRefusal> {
    match control {
        ClosedRelayControl::Open {
            version,
            context_id,
            requester,
            relay,
            target,
            session_id,
            requester_share,
        } => {
            let control = ClosedRelayControl::Open {
                version,
                context_id,
                requester: requester.clone(),
                relay: relay.clone(),
                target: target.clone(),
                session_id,
                requester_share: requester_share.clone(),
            };
            validate_control_for_relay(state, &control)?;
            let owner_witness = current_owner_witness(state, owner, &requester)?;
            let authorization =
                bind_closed_relay(state, requester.clone(), relay.clone(), target.clone())?;
            if !authorization
                .requester
                .session
                .same_validity(&owner_witness)
            {
                return Err(ClosedRelayRefusal::OwnerMismatch);
            }
            let allocation_epoch = state
                .closed_relay_runtime()
                .ok_or(ClosedRelayRefusal::InvalidProfile)?
                .mint_allocation_epoch()?;
            let offer = ClosedRelayControl::Offer {
                version,
                context_id,
                requester: requester.clone(),
                relay: relay.clone(),
                target: target.clone(),
                session_id,
                allocation_epoch,
                requester_share: requester_share.clone(),
            };
            validate_outbound_control(state, &offer)?;
            let runtime = state
                .closed_relay_runtime()
                .ok_or(ClosedRelayRefusal::InvalidProfile)?;
            let lease = state
                .acquire_closed_relay_lease(pending_lease_claim(&authorization, &requester_share)?)
                .map_err(|_| ClosedRelayRefusal::QueueFull)?;
            let guard = runtime.try_begin_handshake()?;
            let expiry = Arc::new(ClosedRelayPendingExpiryControl::new());
            let target_owner = authorization.target.owner.clone();
            state.insert_closed_relay_pending(ClosedRelayPending {
                session_id,
                allocation_epoch,
                authorization,
                _requester_share: requester_share.clone(),
                _guard: guard,
                _expiry: ClosedRelayPendingExpiry::new(Arc::clone(&expiry)),
                _lease: lease,
            })?;
            state.arm_closed_relay_pending_expiry(session_id, expiry)?;
            Ok(Some(ClosedRelayResponse {
                control: offer,
                owner: target_owner,
            }))
        }
        ClosedRelayControl::Offer { .. } => Err(invalid(
            "Offer is endpoint input, not a relay-side allocation control",
        )),
        ClosedRelayControl::Accept {
            version,
            context_id,
            requester,
            relay,
            target,
            session_id,
            allocation_epoch,
            target_share,
        } => {
            let control = ClosedRelayControl::Accept {
                version,
                context_id,
                requester: requester.clone(),
                relay: relay.clone(),
                target: target.clone(),
                session_id,
                allocation_epoch,
                target_share: target_share.clone(),
            };
            validate_control_for_relay(state, &control)?;
            validate_outbound_control(state, &control)?;
            let target_witness = current_owner_witness(state, owner, &target)?;
            let route = control.route();
            // Clone only the immutable authorization first.  Runtime/provider
            // refusal must leave the pending handshake, guard, expiry, and
            // lease untouched in the pending registry.
            let authorization =
                state.closed_relay_pending_authorization(session_id, &route, &target_witness)?;
            let runtime = state
                .closed_relay_runtime()
                .ok_or(ClosedRelayRefusal::InvalidProfile)?;
            let profile = state.config.read().closed_relay.clone();
            let admission =
                authorization.admit_to_runtime(runtime, &profile, session_id, allocation_epoch)?;
            // Admission is synchronous, but the owner/session may still be
            // replaced before the pending record is consumed. Recheck the
            // exact captured witnesses before any registry mutation or Accept
            // emission; dropping the admission releases W1 on refusal.
            if !authorization.is_current()
                || !owner_witness_is_current(
                    state,
                    &authorization.target.owner,
                    &target,
                    &target_witness,
                )
            {
                drop(admission);
                return Err(ClosedRelayRefusal::OwnerNotLive);
            }
            // Consume the pending record only after the complete runtime
            // allocation has been admitted.  A concurrent owner replacement
            // makes this exact take fail and dropping `admission` releases
            // its runtime and engine custody without losing the pending slot.
            let pending =
                state.take_closed_relay_pending_matching(session_id, &route, &target_witness)?;
            match state.insert_closed_relay_admission(session_id, admission) {
                Ok(_) => {
                    drop(pending);
                    Ok(Some(ClosedRelayResponse {
                        control,
                        owner: authorization.requester.owner.clone(),
                    }))
                }
                Err(error) => {
                    // The allocation registry may reject after runtime
                    // admission (for example, a concurrent same-session
                    // insert). Restore the still-valid pending custody
                    // before returning the refusal.
                    state.insert_closed_relay_pending(pending)?;
                    Err(error)
                }
            }
        }
        ClosedRelayControl::Close { .. } => Err(invalid(
            "Close requires the asynchronous exact-owner dispatch path",
        )),
    }
}

/// Dispatch one validated relay control and emit its response through the
/// exact owner selected by the authenticated route. Endpoint Offer handling
/// derives the target session locally and returns its Accept through the same
/// owner that delivered the Offer. No lock is held across the send await.
pub(crate) async fn handle_control(
    state: &Arc<NetworkState>,
    owner: &PeerOwnerToken,
    control: ClosedRelayControl,
) -> Result<Option<EndpointSession>, ClosedRelayRefusal> {
    state.drain_closed_relay_abandonments().await;
    match &control {
        ClosedRelayControl::Offer { .. } => {
            let (accept, session) = accept_offer(state, owner, &control)?;
            if let Err(error) = send_control_to_owner(state, owner, accept).await {
                state.remove_closed_relay_endpoint(&session);
                session.mark_closed();
                return Err(error);
            }
            // The accepted target session is now owned by the one-consumer
            // handoff queue; no transient handler return may duplicate it.
            drop(session);
            Ok(None)
        }
        ClosedRelayControl::Open { session_id, .. } => {
            let session_id = *session_id;
            let response = on_control(state, owner, control)?;
            let Some(response) = response else {
                return Ok(None);
            };
            if let Err(error) =
                send_control_to_owner(state, &response.owner, response.control).await
            {
                let _ = state.take_closed_relay_pending(session_id);
                return Err(error);
            }
            Ok(None)
        }
        ClosedRelayControl::Accept {
            requester,
            session_id,
            ..
        } => {
            let session_id = *session_id;
            let local = DeviceId::from_canonical_str(state.identity.public_id())
                .map_err(|_| invalid("local identity is not a canonical DeviceId"))?;
            if *requester == local {
                control
                    .validate()
                    .map_err(|error| invalid(format!("invalid Closed relay Accept: {error}")))?;
                let ClosedRelayControl::Accept {
                    context_id,
                    relay,
                    target,
                    allocation_epoch,
                    target_share,
                    ..
                } = &control
                else {
                    unreachable!("matched Accept above")
                };
                if *context_id != state.mesh_context_id() || *target == local {
                    return Err(invalid("Accept is not bound to this requester"));
                }
                canonical_route_admitted(state, requester, relay, target)?;
                let _ = current_owner_witness(state, owner, relay)?;
                let session = state
                    .closed_relay_endpoint(session_id)
                    .ok_or(ClosedRelayRefusal::OwnerNotLive)?;
                if !endpoint_matches_pending_accept(
                    &session,
                    context_id,
                    requester,
                    relay,
                    target,
                    &session_id,
                    *allocation_epoch,
                ) {
                    return Err(ClosedRelayRefusal::OwnerMismatch);
                }
                let session = match state.complete_closed_relay_endpoint(
                    session_id,
                    &control.route(),
                    target_share,
                ) {
                    Ok(session) => session,
                    Err(error) => {
                        // A malformed or stale target share transitions the
                        // exact requester endpoint to terminal state. Do not
                        // leave its lease and registry node behind while the
                        // caller's open future waits for a wake-up.
                        if let Some(session) = state.closed_relay_endpoint(session_id) {
                            state.remove_closed_relay_endpoint(&session);
                            session.mark_closed();
                        }
                        return Err(error);
                    }
                };
                return Ok(Some(session));
            }
            let response = on_control(state, owner, control)?;
            let Some(response) = response else {
                return Ok(None);
            };
            let generation = state.closed_relay_generation(session_id);
            if let Err(error) =
                send_control_to_owner(state, &response.owner, response.control).await
            {
                if let Some(generation) = generation.as_ref() {
                    let _ = state.settle_closed_relay_exact(session_id, generation);
                }
                return Err(error);
            }
            Ok(None)
        }
        ClosedRelayControl::Close { .. } => {
            handle_close(state, owner, control).await?;
            Ok(None)
        }
    }
}

/// Accept an Offer at the target endpoint and return the local opaque session
/// plus the exact Accept control to send back through the relay.
pub(crate) fn accept_offer(
    state: &Arc<NetworkState>,
    owner: &PeerOwnerToken,
    control: &ClosedRelayControl,
) -> Result<(ClosedRelayControl, EndpointSession), ClosedRelayRefusal> {
    control
        .validate()
        .map_err(|error| invalid(format!("invalid Closed relay Offer: {error}")))?;
    let ClosedRelayControl::Offer {
        version,
        context_id,
        requester,
        relay,
        target,
        session_id,
        allocation_epoch,
        requester_share,
    } = control
    else {
        return Err(invalid("target expected a Closed relay Offer"));
    };
    let local = DeviceId::from_canonical_str(state.identity.public_id())
        .map_err(|_| invalid("local identity is not a canonical DeviceId"))?;
    if *target != local || *context_id != state.mesh_context_id() {
        return Err(invalid("Offer is not addressed to this target"));
    }
    canonical_route_admitted(state, requester, relay, target)?;
    let relay_witness = current_owner_witness(state, owner, relay)?;
    let profile = state.config.read().closed_relay.clone();
    let runtime = state
        .closed_relay_runtime()
        .ok_or(ClosedRelayRefusal::InvalidProfile)?;
    let capacity = endpoint_capacity(state)?;
    let lease = state
        .acquire_closed_relay_lease(endpoint_lease_claim(
            &profile, capacity, context_id, requester, relay, target,
        )?)
        .map_err(|_| ClosedRelayRefusal::QueueFull)?;
    let (pending, target_share) = PendingEndpointKeyAgreement::begin_with_runtime(
        runtime,
        &state.identity,
        *context_id,
        requester.clone(),
        *session_id,
        &profile,
    )?;
    let session = pending.finish(requester_share)?;
    let accept = ClosedRelayControl::Accept {
        version: *version,
        context_id: *context_id,
        requester: requester.clone(),
        relay: relay.clone(),
        target: target.clone(),
        session_id: *session_id,
        allocation_epoch: *allocation_epoch,
        target_share,
    };
    validate_outbound_control(state, &accept)?;
    let session = EndpointSession::ready(
        state,
        EndpointSessionRoute {
            relay_owner: owner.clone(),
            relay_witness,
            context: *context_id,
            requester: requester.clone(),
            relay: relay.clone(),
            target: target.clone(),
            session_id: *session_id,
            allocation_epoch: *allocation_epoch,
        },
        session,
        capacity,
        lease,
    );
    state.insert_closed_relay_endpoint(session.clone())?;
    if let Err(error) = state.publish_closed_relay_target_accept(session.clone()) {
        state.remove_closed_relay_endpoint(&session);
        session.mark_closed();
        return Err(error);
    }
    // The accepted session is now owned only by the two registries until a
    // consumer takes it; this constructor-local wrapper is not public
    // custody and must not cancel the queued handoff when it drops.
    let mut session = session;
    session.disarm_public();
    Ok((accept, session))
}

fn validate_data_for_direction(
    data: &ClosedRelayData,
    max_ciphertext_bytes: usize,
    direction: RelayDirection,
) -> Result<(), ClosedRelayRefusal> {
    // Reuse the protocol's complete envelope check, then apply the direction
    // specific packet binding. `ClosedRelayData::validate` intentionally
    // describes the requester-to-target wire direction; the reverse path is
    // equally exact but must bind the packet to target-to-requester instead.
    ClosedRelayControl::Close {
        version: data.version,
        context_id: data.context_id,
        requester: data.requester.clone(),
        relay: data.relay.clone(),
        target: data.target.clone(),
        session_id: data.session_id,
        allocation_epoch: data.allocation_epoch,
    }
    .validate()
    .map_err(|error| invalid(format!("invalid Closed relay data: {error}")))?;
    data.packet
        .validate(max_ciphertext_bytes)
        .map_err(|error| invalid(format!("invalid opaque relay packet: {error}")))?;
    let (from, to) = match direction {
        RelayDirection::RequesterToTarget => (&data.requester, &data.target),
        RelayDirection::TargetToRequester => (&data.target, &data.requester),
    };
    if data.packet.mesh != data.context_id.to_string()
        || data.packet.session_id != data.session_id
        || data.packet.from != from.base32()
        || data.packet.to != to.base32()
    {
        return Err(ClosedRelayRefusal::InvalidPacket(
            "opaque relay packet does not match its direction binding".into(),
        ));
    }
    Ok(())
}

fn endpoint_matches_route(
    session: &EndpointSession,
    context: &MeshContextId,
    requester: &DeviceId,
    relay: &DeviceId,
    target: &DeviceId,
    session_id: &[u8; 16],
    allocation_epoch: u64,
) -> bool {
    let metadata = session.metadata();
    metadata.context == *context
        && metadata.requester == *requester
        && metadata.relay == *relay
        && metadata.target == *target
        && metadata.session_id == *session_id
        && metadata.allocation_epoch == allocation_epoch
}

/// Match the requester endpoint against the exact Accept route while allowing
/// its pre-admission epoch.  A requester installs its endpoint before relay
/// allocation, so its metadata carries epoch zero until this Accept completes
/// it; the control itself has already passed `ClosedRelayControl::validate`,
/// which requires the incoming allocation epoch to be nonzero.  Data delivery
/// continues to use the strict `endpoint_matches_route` predicate below.
fn endpoint_matches_pending_accept(
    session: &EndpointSession,
    context: &MeshContextId,
    requester: &DeviceId,
    relay: &DeviceId,
    target: &DeviceId,
    session_id: &[u8; 16],
    allocation_epoch: u64,
) -> bool {
    let metadata = session.metadata();
    metadata.context == *context
        && metadata.requester == *requester
        && metadata.relay == *relay
        && metadata.target == *target
        && metadata.session_id == *session_id
        && (metadata.allocation_epoch == 0 || metadata.allocation_epoch == allocation_epoch)
}

/// Validate and enqueue one opaque data frame from the exact requester or
/// target owner. The runtime performs the final packet/queue/bandwidth checks.
pub(crate) fn on_data(
    state: &Arc<NetworkState>,
    owner: &PeerOwnerToken,
    data: ClosedRelayData,
) -> Result<(), ClosedRelayRefusal> {
    let max = max_frame_ciphertext(state)?;
    let local = DeviceId::from_canonical_str(state.identity.public_id())
        .map_err(|_| invalid("local identity is not a canonical DeviceId"))?;
    if data.context_id != state.mesh_context_id() || data.relay != local {
        return Err(invalid("data is not bound to this local relay"));
    }
    let (context_id, requester, relay, target, allocation_epoch) = state
        .closed_relay_route(data.session_id)
        .ok_or(ClosedRelayRefusal::OwnerNotLive)?;
    let generation = state
        .closed_relay_generation(data.session_id)
        .ok_or(ClosedRelayRefusal::OwnerNotLive)?;
    let expected_route = crate::protocol::relay::ClosedRelayRoute::with_epoch(
        context_id,
        requester,
        relay,
        target,
        data.session_id,
        allocation_epoch,
    );
    data.validate_against_route(&expected_route)
        .map_err(|error| invalid(format!("closed relay data route mismatch: {error}")))?;
    let direction = if owner.device_id() == data.requester.base32().as_str() {
        RelayDirection::RequesterToTarget
    } else if owner.device_id() == data.target.base32().as_str() {
        RelayDirection::TargetToRequester
    } else {
        return Err(ClosedRelayRefusal::OwnerMismatch);
    };
    validate_data_for_direction(&data, max, direction)?;
    let _ = current_owner_witness(
        state,
        owner,
        if direction == RelayDirection::RequesterToTarget {
            &data.requester
        } else {
            &data.target
        },
    )?;
    state.forward_closed_relay(
        data.session_id,
        &generation,
        allocation_epoch,
        direction,
        data.packet,
    )
}

/// Async dispatch spelling for engine message loops. The actual admission is
/// synchronous and bounded; keeping this wrapper async lets callers compose it
/// with the owner-bound send path without changing the lock discipline.
pub(crate) async fn handle_data(
    state: &Arc<NetworkState>,
    owner: &PeerOwnerToken,
    data: ClosedRelayData,
) -> Result<(), ClosedRelayRefusal> {
    let local = DeviceId::from_canonical_str(state.identity.public_id())
        .map_err(|_| invalid("local identity is not a canonical DeviceId"))?;
    if data.relay == local {
        return on_data(state, owner, data);
    }
    let direction = if data.target == local {
        RelayDirection::RequesterToTarget
    } else if data.requester == local {
        RelayDirection::TargetToRequester
    } else {
        return Err(ClosedRelayRefusal::OwnerMismatch);
    };
    validate_data_for_direction(&data, max_frame_ciphertext(state)?, direction)?;
    canonical_route_admitted(state, &data.requester, &data.relay, &data.target)?;
    let _ = current_owner_witness(state, owner, &data.relay)?;
    let session = state
        .closed_relay_endpoint(data.session_id)
        .ok_or(ClosedRelayRefusal::OwnerNotLive)?;
    if !endpoint_matches_route(
        &session,
        &data.context_id,
        &data.requester,
        &data.relay,
        &data.target,
        &data.session_id,
        data.allocation_epoch,
    ) {
        return Err(ClosedRelayRefusal::OwnerMismatch);
    }
    let route = data.route();
    state.deliver_closed_relay_endpoint(data.session_id, &route, data.packet)
}

/// Drain one packet from the exact B-side allocation and emit it to the
/// endpoint selected by the already-authenticated direction. The route is
/// read from the retained terminal witness, never reconstructed from an
/// arbitrary caller selector; the registry lock is not held across either
/// receive or send.
pub(crate) async fn forward_closed_relay_data(
    state: &Arc<NetworkState>,
    session_id: [u8; 16],
    direction: RelayDirection,
) -> Result<bool, ClosedRelayRefusal> {
    // Capture the destination owner before the receive await.  A lookup after
    // that await could silently substitute a successor installation for the
    // owner that authenticated this allocation.
    let (captured_context, captured_requester, captured_relay, captured_target, captured_epoch) =
        state
            .closed_relay_route(session_id)
            .ok_or(ClosedRelayRefusal::OwnerNotLive)?;
    let destination = match direction {
        RelayDirection::RequesterToTarget => captured_target.clone(),
        RelayDirection::TargetToRequester => captured_requester.clone(),
    };
    let destination_owner = current_owner_for_device(state, &destination)?;
    let Some((
        packet,
        received_context,
        received_requester,
        received_relay,
        received_target,
        received_epoch,
        generation,
    )) = state.recv_closed_relay(session_id, direction).await
    else {
        return Ok(false);
    };
    let Some((context_id, requester, relay, target, allocation_epoch)) =
        state.closed_relay_route_if_generation(session_id, &generation)
    else {
        let _ = state.retire_closed_relay_exact(session_id, &generation);
        return Err(ClosedRelayRefusal::OwnerNotLive);
    };
    if (
        context_id,
        requester.clone(),
        relay.clone(),
        target.clone(),
        allocation_epoch,
    ) != (
        captured_context,
        captured_requester,
        captured_relay,
        captured_target,
        captured_epoch,
    ) || (
        context_id,
        requester.clone(),
        relay.clone(),
        target.clone(),
        allocation_epoch,
    ) != (
        received_context,
        received_requester,
        received_relay,
        received_target,
        received_epoch,
    ) {
        let _ = state.retire_closed_relay_exact(session_id, &generation);
        return Err(ClosedRelayRefusal::OwnerNotLive);
    }
    let data = ClosedRelayData {
        version: crate::protocol::relay::OPAQUE_RELAY_VERSION,
        context_id,
        requester,
        relay,
        target,
        session_id,
        allocation_epoch,
        packet,
    };
    if super::send_to_peer_owner(
        state,
        &destination_owner,
        &crate::protocol::MeshMessage::ClosedRelayData(data),
    )
    .await
    .is_err()
    {
        let _ = state.settle_closed_relay_exact(session_id, &generation);
        return Err(ClosedRelayRefusal::CarrierUnavailable);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn device(byte: u8) -> DeviceId {
        DeviceId::from_public_key_bytes(
            SigningKey::from_bytes(&[byte; 32])
                .verifying_key()
                .to_bytes(),
        )
        .expect("deterministic test key")
    }

    #[test]
    fn closed_route_rejects_aliases_before_session_lookup() {
        let requester = device(1);
        let relay = device(2);
        let target = device(3);
        assert_eq!(validate_route(&requester, &relay, &target, &relay), Ok(()));
        assert!(matches!(
            validate_route(&requester, &relay, &relay, &relay),
            Err(ClosedRelayRefusal::InvalidEndpoints(_))
        ));
        assert!(matches!(
            validate_route(&requester, &target, &relay, &relay),
            Err(ClosedRelayRefusal::InvalidEndpoints(_))
        ));
    }

    #[test]
    fn route_may_not_select_a_remote_relay_identity() {
        let requester = device(1);
        let relay = device(2);
        let target = device(3);
        assert!(matches!(
            validate_route(&requester, &relay, &target, &target),
            Err(ClosedRelayRefusal::InvalidEndpoints(_))
        ));
    }

    #[test]
    fn session_coordinate_must_be_nonzero_before_engine_admission() {
        assert!(matches!(
            validate_session_id([0; 16]),
            Err(ClosedRelayRefusal::InvalidPacket(reason))
                if reason == "closed relay session id must be nonzero"
        ));
        assert!(validate_session_id([1; 16]).is_ok());
    }

    #[test]
    fn data_direction_control_accepts_only_the_exact_endpoint_pair() {
        let context = MeshContextId::from_bytes([7; 32]);
        let requester = device(1);
        let relay = device(2);
        let target = device(3);
        let session_id = [9; 16];
        let data = ClosedRelayData {
            version: crate::protocol::relay::OPAQUE_RELAY_VERSION,
            context_id: context,
            requester: requester.clone(),
            relay,
            target: target.clone(),
            session_id,
            allocation_epoch: 1,
            packet: OpaqueRelayPacket {
                version: crate::protocol::relay::OPAQUE_RELAY_VERSION,
                mesh: context.to_string(),
                session_id,
                from: target.base32(),
                to: requester.base32(),
                sequence: 0,
                nonce: [0; crate::protocol::relay::OPAQUE_RELAY_NONCE_BYTES],
                ciphertext: vec![1],
            },
        };
        assert!(validate_data_for_direction(&data, 32, RelayDirection::TargetToRequester).is_ok());
        assert!(matches!(
            validate_data_for_direction(&data, 32, RelayDirection::RequesterToTarget),
            Err(ClosedRelayRefusal::InvalidPacket(_))
        ));
    }

    #[test]
    fn outbound_control_accepts_exact_encoded_bound_and_refuses_one_byte_less() {
        let context = MeshContextId::from_bytes([8; 32]);
        let control = ClosedRelayControl::Close {
            version: crate::protocol::relay::CLOSED_RELAY_CONTROL_VERSION,
            context_id: context,
            requester: device(1),
            relay: device(2),
            target: device(3),
            session_id: [10; 16],
            allocation_epoch: 1,
        };
        let encoded = control.encoded_len().expect("close control encodes");
        let exact = ClosedRelayPolicyConfig {
            enabled: true,
            max_control_bytes: u64::try_from(encoded).expect("encoded length fits u64"),
            pending_handshake_timeout_ms: ClosedRelayPolicyConfig::default()
                .pending_handshake_timeout_ms,
            ..ClosedRelayPolicyConfig::default()
        };
        assert!(exact.validate_closed_relay_control(&control));
        let below = ClosedRelayPolicyConfig {
            max_control_bytes: u64::try_from(encoded - 1).expect("encoded length fits u64"),
            pending_handshake_timeout_ms: exact.pending_handshake_timeout_ms,
            ..exact
        };
        assert!(!below.validate_closed_relay_control(&control));
    }

    #[test]
    fn endpoint_claim_covers_replay_queue_and_retained_route_storage() {
        let context = MeshContextId::from_bytes([11; 32]);
        let requester = device(11);
        let relay = device(12);
        let target = device(13);
        let profile = ClosedRelayPolicyConfig {
            enabled: true,
            replay_window: 5,
            max_frame_ciphertext_bytes: 31,
            pending_handshake_timeout_ms: ClosedRelayPolicyConfig::default()
                .pending_handshake_timeout_ms,
            ..ClosedRelayPolicyConfig::default()
        };
        let one = endpoint_lease_claim(&profile, 1, &context, &requester, &relay, &target)
            .expect("one endpoint claim");
        let two = endpoint_lease_claim(&profile, 2, &context, &requester, &relay, &target)
            .expect("two endpoint claim");
        assert_eq!(
            two.amount(ResourceClass::QueuedBytes),
            one.amount(ResourceClass::QueuedBytes)
                + u64::try_from(
                    crate::runtime::relay::checked_ciphertext_ceiling(
                        profile.max_frame_ciphertext_bytes,
                    )
                    .expect("ciphertext ceiling"),
                )
                .expect("ciphertext ceiling fits the claim amount")
        );
        assert!(
            two.amount(ResourceClass::AccountedMemoryBytes)
                > one.amount(ResourceClass::AccountedMemoryBytes),
            "each retained packet must charge its metadata and queue slot"
        );
        assert!(
            two.amount(ResourceClass::OpaqueDependencyResidual)
                > one.amount(ResourceClass::OpaqueDependencyResidual),
            "each retained packet allocation must be observed"
        );
    }
}
