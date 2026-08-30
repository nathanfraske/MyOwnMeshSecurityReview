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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

use super::peer_registry::PeerOwnerToken;
use super::NetworkState;
use crate::config::ClosedRelayPolicyConfig;
use crate::protocol::relay::{ClosedRelayControl, ClosedRelayData, RelayKeyShare};
use crate::protocol::OpaqueRelayPacket;
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
    context: MeshContextId,
    requester: DeviceId,
    relay: DeviceId,
    target: DeviceId,
    session_id: [u8; 16],
    crypto: Mutex<EndpointCrypto>,
    inbound: Mutex<VecDeque<OpaqueRelayPacket>>,
    inbound_capacity: usize,
    wake: Notify,
    closed: AtomicBool,
}

/// Endpoint-owned opaque session handle. The relay only sees the bounded
/// ciphertext queues; this handle retains endpoint AEAD state at A or C.
#[derive(Clone)]
pub(crate) struct EndpointSession(Arc<EndpointSessionInner>);

#[derive(Clone)]
pub(crate) struct EndpointSessionMetadata {
    pub(crate) context: MeshContextId,
    pub(crate) requester: DeviceId,
    pub(crate) relay: DeviceId,
    pub(crate) target: DeviceId,
    pub(crate) session_id: [u8; 16],
}

impl EndpointSession {
    pub(crate) fn metadata(&self) -> EndpointSessionMetadata {
        EndpointSessionMetadata {
            context: self.0.context,
            requester: self.0.requester.clone(),
            relay: self.0.relay.clone(),
            target: self.0.target.clone(),
            session_id: self.0.session_id,
        }
    }

    fn pending(
        state: &Arc<NetworkState>,
        relay_owner: PeerOwnerToken,
        context: MeshContextId,
        requester: DeviceId,
        relay: DeviceId,
        target: DeviceId,
        session_id: [u8; 16],
        pending: PendingEndpointKeyAgreement,
        capacity: usize,
    ) -> Self {
        Self(Arc::new(EndpointSessionInner {
            state: Arc::downgrade(state),
            relay_owner,
            context,
            requester,
            relay,
            target,
            session_id,
            crypto: Mutex::new(EndpointCrypto::Pending(pending)),
            inbound: Mutex::new(VecDeque::with_capacity(capacity)),
            inbound_capacity: capacity,
            wake: Notify::new(),
            closed: AtomicBool::new(false),
        }))
    }

    fn ready(
        state: &Arc<NetworkState>,
        relay_owner: PeerOwnerToken,
        context: MeshContextId,
        requester: DeviceId,
        relay: DeviceId,
        target: DeviceId,
        session_id: [u8; 16],
        session: OpaqueRelaySession,
        capacity: usize,
    ) -> Self {
        Self(Arc::new(EndpointSessionInner {
            state: Arc::downgrade(state),
            relay_owner,
            context,
            requester,
            relay,
            target,
            session_id,
            crypto: Mutex::new(EndpointCrypto::Ready(session)),
            inbound: Mutex::new(VecDeque::with_capacity(capacity)),
            inbound_capacity: capacity,
            wake: Notify::new(),
            closed: AtomicBool::new(false),
        }))
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
            version: crate::protocol::relay::OPAQUE_RELAY_VERSION,
            context_id: self.0.context,
            requester: self.0.requester.clone(),
            relay: self.0.relay.clone(),
            target: self.0.target.clone(),
            session_id: self.0.session_id,
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
        if self.begin_closing() {
            let result = send_control_to_owner(
                &state,
                &self.0.relay_owner,
                ClosedRelayControl::Close {
                    version: crate::protocol::relay::OPAQUE_RELAY_VERSION,
                    context_id: self.0.context,
                    requester: self.0.requester.clone(),
                    relay: self.0.relay.clone(),
                    target: self.0.target.clone(),
                    session_id: self.0.session_id,
                },
            )
            .await;
            if let Err(error) = result {
                state.remove_closed_relay_endpoint(&self);
                self.mark_closed();
                return Err(error);
            }
        }
        match self.wait_terminal().await {
            Ok(()) => {
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
        self.sessions.push(session);
        Ok(())
    }

    pub(crate) fn find(&self, session_id: [u8; 16]) -> Option<EndpointSession> {
        self.sessions
            .iter()
            .find(|session| session.0.session_id == session_id)
            .cloned()
    }

    pub(crate) fn remove(&mut self, session: &EndpointSession) {
        if let Some(index) = self
            .sessions
            .iter()
            .position(|existing| Arc::ptr_eq(&existing.0, &session.0))
        {
            self.sessions.swap_remove(index);
        }
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
        self.ready.push_back(session);
        self.wake.notify_one();
        Ok(())
    }

    pub(crate) fn take(&mut self, session_id: [u8; 16]) -> Option<EndpointSession> {
        let index = self
            .ready
            .iter()
            .position(|session| session.0.session_id == session_id)?;
        self.ready.remove(index)
    }

    pub(crate) fn take_next(&mut self) -> Option<EndpointSession> {
        self.ready.pop_front()
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
            self.ready.remove(index);
            self.wake.notify_waiters();
        }
    }
}

fn invalid(reason: impl Into<String>) -> ClosedRelayRefusal {
    ClosedRelayRefusal::InvalidEndpoints(reason.into())
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

    pub(crate) fn owner(&self) -> &PeerOwnerToken {
        &self.owner
    }

    pub(crate) fn session(&self) -> &SessionValidityWitness {
        &self.session
    }
}

/// The engine authorization handed to the concrete `runtime::relay` adapter.
///
/// This is deliberately a witness bundle rather than a second relay runtime:
/// the runtime consumes it together with its provider-backed
/// `RelayAllocationPermit`.  It contains no IP address, key, payload, queue,
/// destination selector, or recursive forwarding capability.
pub(crate) struct ClosedRelayAuthorization {
    state: Arc<NetworkState>,
    context: MeshContextId,
    relay: DeviceId,
    requester: ClosedRelayEndpoint,
    target: ClosedRelayEndpoint,
}

/// A successfully admitted runtime handle paired with the exact engine
/// witness that must remain alive until terminal settlement.
pub(crate) type ClosedRelayAdmission = (ClosedRelayHandle, ClosedRelayTerminalWitness);
pub(crate) type ClosedRelayGeneration = Arc<()>;

pub(crate) struct ClosedRelayCheckoutControl {
    closing: AtomicBool,
    wake: Notify,
}

impl ClosedRelayCheckoutControl {
    pub(crate) fn request_close(&self) {
        self.closing.store(true, Ordering::Release);
        self.wake.notify_waiters();
    }

    pub(crate) fn closing_notified(&self) -> tokio::sync::futures::Notified<'_> {
        self.wake.notified()
    }
}

pub(crate) struct ClosedRelayCheckout {
    state: Weak<NetworkState>,
    session_id: [u8; 16],
    generation: ClosedRelayGeneration,
    handle: Option<ClosedRelayHandle>,
    terminal: Option<ClosedRelayTerminalWitness>,
    control: Arc<ClosedRelayCheckoutControl>,
}

impl ClosedRelayCheckout {
    pub(crate) async fn recv(&mut self, direction: RelayDirection) -> Option<OpaqueRelayPacket> {
        self.handle.as_mut()?.recv_direction(direction).await
    }

    pub(crate) fn control(&self) -> &Arc<ClosedRelayCheckoutControl> {
        &self.control
    }

    pub(crate) fn is_closing(&self) -> bool {
        self.control.closing.load(Ordering::Acquire)
    }
}

impl Drop for ClosedRelayCheckout {
    fn drop(&mut self) {
        let Some(handle) = self.handle.take() else {
            return;
        };
        let Some(terminal) = self.terminal.take() else {
            drop(handle);
            return;
        };
        if let Some(state) = self.state.upgrade() {
            state.finish_closed_relay_checkout(
                self.session_id,
                self.generation.clone(),
                handle,
                terminal,
                Arc::clone(&self.control),
            );
        } else {
            drop(handle);
            drop(terminal);
        }
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
        let (handle, terminal) = admission;
        let generation = Arc::new(());
        self.slots.push(ClosedRelaySlot {
            session_id,
            generation: generation.clone(),
            handle: Some(handle),
            terminal,
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
        let control = Arc::new(ClosedRelayCheckoutControl {
            closing: AtomicBool::new(slot.closing),
            wake: Notify::new(),
        });
        slot.checkout = Some(Arc::clone(&control));
        Some(ClosedRelayCheckout {
            state: Arc::downgrade(state),
            session_id,
            generation: slot.generation.clone(),
            handle: Some(handle),
            terminal: Some(slot.terminal.clone()),
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
            return Some((handle, terminal));
        };
        let slot = &mut self.slots[index];
        slot.checkout = None;
        if slot.closing || control.closing.load(Ordering::Acquire) {
            let _ = self.slots.swap_remove(index);
            Some((handle, terminal))
        } else {
            slot.handle = Some(handle);
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

    pub(crate) fn settle_all(&mut self) -> usize {
        let mut settled = 0;
        while let Some(slot) = self.slots.pop() {
            if let Some(handle) = slot.handle {
                if settle_closed_relay(handle, slot.terminal).is_ok() {
                    settled += 1;
                }
            }
        }
        settled
    }

    pub(crate) fn len(&self) -> usize {
        self.slots.len()
    }

    pub(crate) fn route(
        &self,
        session_id: [u8; 16],
    ) -> Option<(MeshContextId, DeviceId, DeviceId, DeviceId)> {
        let slot = self
            .slots
            .iter()
            .find(|slot| slot.session_id == session_id)?;
        Some((
            slot.terminal.context,
            slot.terminal.requester.device.clone(),
            slot.terminal.relay.clone(),
            slot.terminal.target.device.clone(),
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
    pub(crate) authorization: ClosedRelayAuthorization,
    pub(crate) requester_share: RelayKeyShare,
    pub(crate) _guard: ClosedRelayHandshakeGuard,
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

    pub(crate) fn contains(&self, session_id: [u8; 16]) -> bool {
        self.slots.iter().any(|slot| slot.session_id == session_id)
    }

    pub(crate) fn len(&self) -> usize {
        self.slots.len()
    }

    pub(crate) fn clear(&mut self) -> usize {
        let count = self.slots.len();
        self.slots.clear();
        count
    }
}

pub(crate) struct ClosedRelayCloseRecord {
    pub(crate) session_id: [u8; 16],
    pub(crate) allocation_generation: Option<ClosedRelayGeneration>,
    pub(crate) initiator: DeviceId,
    pub(crate) opposite: DeviceId,
    pub(crate) initiator_owner: PeerOwnerToken,
    pub(crate) initiator_witness: SessionValidityWitness,
    pub(crate) opposite_witness: SessionValidityWitness,
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
        if self.records.iter().any(|existing| {
            if existing.session_id == record.session_id {
                true
            } else {
                false
            }
        }) {
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
    ) -> Option<ClosedRelayCloseRecord> {
        let index = self.records.iter().position(|record| {
            record.session_id == session_id
                && &record.opposite == opposite
                && record.opposite_witness.same_validity(witness)
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

    pub(crate) fn contains(&self, session_id: [u8; 16]) -> bool {
        self.records
            .iter()
            .any(|record| record.session_id == session_id)
    }

    pub(crate) fn clear(&mut self) {
        self.records.clear();
    }
}

impl ClosedRelayAuthorization {
    /// The exact semantic context selected by the verified bootstrap.
    pub(crate) fn context(&self) -> MeshContextId {
        self.context
    }

    /// The local canonical member performing the relay operation.
    pub(crate) fn relay(&self) -> &DeviceId {
        &self.relay
    }

    pub(crate) fn requester(&self) -> &ClosedRelayEndpoint {
        &self.requester
    }

    pub(crate) fn target(&self) -> &ClosedRelayEndpoint {
        &self.target
    }

    /// Admit this already-bound route through the concrete provider-backed
    /// runtime. Permit issuance deliberately occurs after `bind_closed_relay`
    /// and its currentness fence; a failed semantic or owner check therefore
    /// cannot reserve a relay allocation.
    pub(crate) fn admit_to_runtime(
        self,
        runtime: &ClosedRelayRuntime,
        profile: &ClosedRelayPolicyConfig,
        session_id: [u8; 16],
    ) -> Result<ClosedRelayAdmission, ClosedRelayRefusal> {
        if !self.is_current() {
            return Err(ClosedRelayRefusal::OwnerNotLive);
        }
        let permit = RelayAllocationPermit::try_new(self.requester.session.clone(), profile)?;
        let endpoints = ClosedRelayEndpoints::new(
            self.context,
            self.requester.device.clone(),
            self.target.device.clone(),
            session_id,
        )?;
        let terminal = self.into_terminal();
        runtime
            .admit_closed_relay(
                permit,
                terminal.requester.session.clone(),
                terminal.target.session.clone(),
                endpoints,
            )
            .map(|handle| (handle, terminal))
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
    pub(crate) fn into_terminal(self) -> ClosedRelayTerminalWitness {
        ClosedRelayTerminalWitness {
            state: self.state,
            context: self.context,
            relay: self.relay,
            requester: self.requester,
            target: self.target,
        }
    }
}

/// Bind and admit one Closed relay through the concrete runtime. The returned
/// handle remains keyless and the paired terminal witness must be supplied to
/// [`settle_closed_relay`].
pub(crate) fn admit_closed_relay(
    state: &Arc<NetworkState>,
    runtime: &ClosedRelayRuntime,
    profile: &ClosedRelayPolicyConfig,
    requester: DeviceId,
    relay: DeviceId,
    target: DeviceId,
    session_id: [u8; 16],
) -> Result<ClosedRelayAdmission, ClosedRelayRefusal> {
    bind_closed_relay(state, requester, relay, target)?
        .admit_to_runtime(runtime, profile, session_id)
}

/// Recheck the exact engine witness before consuming the runtime handle. A
/// stale replacement is refused and dropping the un-settled handle performs
/// runtime cleanup; no second settlement path is introduced here.
pub(crate) fn settle_closed_relay(
    handle: ClosedRelayHandle,
    terminal: ClosedRelayTerminalWitness,
) -> Result<ClosedRelayTerminal, ClosedRelayRefusal> {
    if !terminal.is_current() {
        drop(handle);
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
}

impl ClosedRelayTerminalWitness {
    pub(crate) fn is_current(&self) -> bool {
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
    let (context, requester, relay, target, session_id) = control_fields(&control);
    let local = DeviceId::from_canonical_str(state.identity.public_id())
        .map_err(|_| invalid("local identity is not a canonical DeviceId"))?;

    if *relay == local {
        canonical_route_admitted(state, requester, relay, target)?;
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
        if let Some(record) =
            state.take_closed_relay_close(*session_id, sender_device, &sender_witness)
        {
            if let Some(generation) = record.allocation_generation.as_ref() {
                let _ = state.settle_closed_relay_exact(*session_id, generation);
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
            allocation_generation: allocation_generation.clone(),
            initiator: sender_device.clone(),
            opposite: opposite.clone(),
            initiator_owner: owner.clone(),
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
        if metadata.context != *context
            || metadata.requester != *requester
            || metadata.relay != *relay
            || metadata.target != *target
            || metadata.session_id != *session_id
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
    super::send_to_peer_owner(
        state,
        owner,
        &crate::protocol::MeshMessage::ClosedRelayControl(control),
    )
    .await
    .map_err(|_| ClosedRelayRefusal::CarrierUnavailable)
}

fn endpoint_capacity(state: &NetworkState) -> Result<usize, ClosedRelayRefusal> {
    usize::try_from(state.config.read().closed_relay.queue_items_per_direction)
        .map_err(|_| ClosedRelayRefusal::InvalidProfile)
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
    Ok((
        pending,
        ClosedRelayControl::Open {
            version: crate::protocol::relay::OPAQUE_RELAY_VERSION,
            context_id: state.mesh_context_id(),
            requester,
            relay,
            target,
            session_id,
            requester_share,
        },
    ))
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
    let (pending, control) =
        begin_closed_relay_open(state, relay.clone(), target.clone(), session_id)?;
    let owner = match current_owner_for_device(state, &relay) {
        Ok(owner) => owner,
        Err(error) => {
            drop(pending);
            return Err(error);
        }
    };
    let requester = DeviceId::from_canonical_str(state.identity.public_id())
        .map_err(|_| invalid("local identity is not a canonical DeviceId"))?;
    let capacity = endpoint_capacity(state)?;
    let session = EndpointSession::pending(
        state,
        owner,
        state.mesh_context_id(),
        requester,
        relay,
        target,
        session_id,
        pending,
        capacity,
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

/// Finish the requester endpoint agreement from the exact target Accept.
pub(crate) fn finish_closed_relay_open(
    pending: PendingEndpointKeyAgreement,
    control: &ClosedRelayControl,
) -> Result<OpaqueRelaySession, ClosedRelayRefusal> {
    control
        .validate()
        .map_err(|error| invalid(format!("invalid Closed relay Accept: {error}")))?;
    let ClosedRelayControl::Accept { target_share, .. } = control else {
        return Err(invalid("requester expected a Closed relay Accept"));
    };
    pending.finish(target_share)
}

/// Handle the relay member's Open/Accept/Close controls. A response is
/// returned for the caller to send only over the exact owner selected by its
/// route; this function never resolves a peer by a string or sends under a
/// lock.
pub(crate) fn on_control(
    state: &Arc<NetworkState>,
    owner: &PeerOwnerToken,
    control: ClosedRelayControl,
) -> Result<Option<ClosedRelayControl>, ClosedRelayRefusal> {
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
            let runtime = state
                .closed_relay_runtime()
                .ok_or(ClosedRelayRefusal::InvalidProfile)?;
            let guard = runtime.try_begin_handshake()?;
            state.insert_closed_relay_pending(ClosedRelayPending {
                session_id,
                authorization,
                requester_share: requester_share.clone(),
                _guard: guard,
            })?;
            Ok(Some(ClosedRelayControl::Offer {
                version,
                context_id,
                requester,
                relay,
                target,
                session_id,
                requester_share,
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
            target_share,
        } => {
            let control = ClosedRelayControl::Accept {
                version,
                context_id,
                requester: requester.clone(),
                relay: relay.clone(),
                target: target.clone(),
                session_id,
                target_share: target_share.clone(),
            };
            validate_control_for_relay(state, &control)?;
            let target_witness = current_owner_witness(state, owner, &target)?;
            let pending = state
                .take_closed_relay_pending(session_id)
                .ok_or(ClosedRelayRefusal::OwnerNotLive)?;
            if !pending
                .authorization
                .target
                .session
                .same_validity(&target_witness)
            {
                return Err(ClosedRelayRefusal::OwnerMismatch);
            }
            let runtime = state
                .closed_relay_runtime()
                .ok_or(ClosedRelayRefusal::InvalidProfile)?;
            let profile = state.config.read().closed_relay.clone();
            let (handle, terminal) = pending
                .authorization
                .admit_to_runtime(runtime, &profile, session_id)?;
            let _ = state.insert_closed_relay_admission(session_id, (handle, terminal))?;
            Ok(Some(control))
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
        ClosedRelayControl::Open {
            target, session_id, ..
        } => {
            let target = target.clone();
            let session_id = *session_id;
            let response = on_control(state, owner, control)?;
            let Some(response) = response else {
                return Ok(None);
            };
            let target_owner = match current_owner_for_device(state, &target) {
                Ok(target_owner) => target_owner,
                Err(error) => {
                    let _ = state.take_closed_relay_pending(session_id);
                    return Err(error);
                }
            };
            if let Err(error) = send_control_to_owner(state, &target_owner, response).await {
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
            let requester = requester.clone();
            let session_id = *session_id;
            let local = DeviceId::from_canonical_str(state.identity.public_id())
                .map_err(|_| invalid("local identity is not a canonical DeviceId"))?;
            if requester == local {
                control
                    .validate()
                    .map_err(|error| invalid(format!("invalid Closed relay Accept: {error}")))?;
                let ClosedRelayControl::Accept {
                    context_id,
                    relay,
                    target,
                    target_share,
                    ..
                } = &control
                else {
                    unreachable!("matched Accept above")
                };
                if *context_id != state.mesh_context_id() || *target == local {
                    return Err(invalid("Accept is not bound to this requester"));
                }
                canonical_route_admitted(state, &requester, relay, target)?;
                let _ = current_owner_witness(state, owner, relay)?;
                let session = state.complete_closed_relay_endpoint(session_id, target_share)?;
                return Ok(Some(session));
            }
            let response = on_control(state, owner, control)?;
            let Some(response) = response else {
                return Ok(None);
            };
            let generation = state.closed_relay_generation(session_id);
            let requester_owner = match current_owner_for_device(state, &requester) {
                Ok(requester_owner) => requester_owner,
                Err(error) => {
                    if let Some(generation) = generation.as_ref() {
                        let _ = state.settle_closed_relay_exact(session_id, generation);
                    }
                    return Err(error);
                }
            };
            if let Err(error) = send_control_to_owner(state, &requester_owner, response).await {
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
    let _relay_witness = current_owner_witness(state, owner, relay)?;
    let profile = state.config.read().closed_relay.clone();
    let runtime = state
        .closed_relay_runtime()
        .ok_or(ClosedRelayRefusal::InvalidProfile)?;
    let (pending, target_share) = PendingEndpointKeyAgreement::begin_with_runtime(
        runtime,
        &state.identity,
        *context_id,
        requester.clone(),
        *session_id,
        &profile,
    )?;
    let session = pending.finish(requester_share)?;
    let session = EndpointSession::ready(
        state,
        owner.clone(),
        *context_id,
        requester.clone(),
        relay.clone(),
        target.clone(),
        *session_id,
        session,
        endpoint_capacity(state)?,
    );
    state.insert_closed_relay_endpoint(session.clone())?;
    if let Err(error) = state.publish_closed_relay_target_accept(session.clone()) {
        state.remove_closed_relay_endpoint(&session);
        session.mark_closed();
        return Err(error);
    }
    Ok((
        ClosedRelayControl::Accept {
            version: *version,
            context_id: *context_id,
            requester: requester.clone(),
            relay: relay.clone(),
            target: target.clone(),
            session_id: *session_id,
            target_share,
        },
        session,
    ))
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
    state.forward_closed_relay(data.session_id, direction, data.packet)
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
    state.deliver_closed_relay_endpoint(data.session_id, data.packet)
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
    let Some(packet) = state.recv_closed_relay(session_id, direction).await else {
        return Ok(false);
    };
    let Some((context_id, requester, relay, target)) = state.closed_relay_route(session_id) else {
        return Err(ClosedRelayRefusal::OwnerNotLive);
    };
    let destination = match direction {
        RelayDirection::RequesterToTarget => target.clone(),
        RelayDirection::TargetToRequester => requester.clone(),
    };
    let destination_owner = current_owner_for_device(state, &destination)?;
    let data = ClosedRelayData {
        version: crate::protocol::relay::OPAQUE_RELAY_VERSION,
        context_id,
        requester,
        relay,
        target,
        session_id,
        packet,
    };
    super::send_to_peer_owner(
        state,
        &destination_owner,
        &crate::protocol::MeshMessage::ClosedRelayData(data),
    )
    .await
    .map_err(|_| ClosedRelayRefusal::CarrierUnavailable)?;
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
}
