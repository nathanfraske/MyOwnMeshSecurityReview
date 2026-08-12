//! Local-principal and application-queue capability boundary for V4.
//!
//! The principal binding selected here is the **local process itself**: the
//! application operations this crate serves run in-process with the embedder, so
//! the operating-system principal that authenticated is the one already running
//! this code. That is a real binding, not a placeholder, and it is deliberately
//! the narrowest one that is true — there is no per-request principal inference,
//! no client label, and no identity or attestation framework.

use bytes::Bytes;

use crate::resource::{
    LeasedQueue, ResourceClaim, ResourceClaimArithmeticError, ResourceClass, ResourceLease,
    ResourceUnavailable,
};
use crate::runtime::session_broker::SessionCapability;
use crate::runtime::RuntimeIncarnation;

struct LeasedLocalCapabilityAdvert {
    encoded: Box<[u8]>,
    _lease: ResourceLease,
}

/// The one retained local advertisement for a joined network. This is
/// Application Gateway state, not RPC transport state, and its canonical byte
/// representation is funded for exactly as long as it is installed.
pub(crate) struct LocalCapabilityState {
    held: parking_lot::Mutex<Option<LeasedLocalCapabilityAdvert>>,
}

impl LocalCapabilityState {
    pub(crate) fn new() -> Self {
        Self {
            held: parking_lot::Mutex::new(None),
        }
    }

    pub(crate) fn replace(
        &self,
        broker: Option<&crate::runtime::session_broker::SessionBroker>,
        advert: &crate::protocol::CapabilityAdvert,
    ) -> Result<(), String> {
        let encoded = serde_json::to_vec(advert)
            .expect("CapabilityAdvert serialization is infallible")
            .into_boxed_slice();
        let bytes = u64::try_from(encoded.len())
            .map_err(|_| "local capability advertisement is too large to account".to_string())?;
        let claim = ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, bytes),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
        .map_err(|_| "local capability advertisement claim overflowed".to_string())?;
        let lease = broker
            .ok_or_else(|| "no local application resource owner is installed".to_string())?
            .reserve_local_application(claim)
            .map_err(|e| format!("local capability advertisement refused: {e:?}"))?;
        *self.held.lock() = Some(LeasedLocalCapabilityAdvert {
            encoded,
            _lease: lease,
        });
        Ok(())
    }

    pub(crate) fn current(&self) -> Option<crate::protocol::CapabilityAdvert> {
        self.held
            .lock()
            .as_ref()
            .and_then(|held| serde_json::from_slice(&held.encoded).ok())
    }

    pub(crate) fn clear(&self) {
        drop(self.held.lock().take());
    }
}

pub(crate) struct GatewayChannelFrame {
    pub(crate) from: String,
    pub(crate) payload: serde_json::Value,
}

pub(crate) struct ChannelSubscriber {
    mailbox: parking_lot::Mutex<GatewayMailbox<GatewayChannelFrame>>,
    ready: tokio::sync::Notify,
    closed: std::sync::atomic::AtomicBool,
    pressure: std::sync::atomic::AtomicU64,
}

impl ChannelSubscriber {
    fn new() -> Self {
        Self {
            mailbox: parking_lot::Mutex::new(GatewayMailbox::new()),
            ready: tokio::sync::Notify::new(),
            closed: std::sync::atomic::AtomicBool::new(false),
            pressure: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn accept(&self, frame: GatewayChannelFrame, retention: ResourceLease, node: ResourceLease) {
        self.mailbox.lock().accept(frame, retention, node);
        self.ready.notify_one();
    }

    fn note_pressure(&self) {
        self.pressure
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        self.ready.notify_one();
    }

    pub(crate) async fn recv(
        &self,
    ) -> Result<GatewayDelivery<GatewayChannelFrame>, GatewayRefusal> {
        loop {
            let notified = self.ready.notified();
            let skipped = self.pressure.swap(0, std::sync::atomic::Ordering::AcqRel);
            if skipped != 0 {
                return Err(GatewayRefusal::Lag(skipped));
            }
            if let Some(delivery) = self.mailbox.lock().pop() {
                return Ok(delivery);
            }
            if self.closed.load(std::sync::atomic::Ordering::Acquire) {
                return Err(GatewayRefusal::Revoked);
            }
            notified.await;
        }
    }

    fn close(&self) {
        self.closed
            .store(true, std::sync::atomic::Ordering::Release);
        self.ready.notify_waiters();
    }

    #[cfg(test)]
    pub(crate) fn try_recv(&self) -> Option<GatewayDelivery<GatewayChannelFrame>> {
        self.mailbox.lock().pop()
    }
}

/// The one local application owner for a joined network.
pub(crate) struct ApplicationGateway {
    channels: parking_lot::Mutex<
        std::collections::HashMap<String, Vec<std::sync::Weak<ChannelSubscriber>>>,
    >,
    capabilities: LocalCapabilityState,
    rpc: parking_lot::RwLock<Option<std::sync::Arc<crate::rpc::RpcInner>>>,
}

impl ApplicationGateway {
    pub(crate) fn new() -> Self {
        Self {
            channels: parking_lot::Mutex::new(std::collections::HashMap::new()),
            capabilities: LocalCapabilityState::new(),
            rpc: parking_lot::RwLock::new(None),
        }
    }

    pub(crate) fn subscribe_channel(&self, name: &str) -> std::sync::Arc<ChannelSubscriber> {
        let subscriber = std::sync::Arc::new(ChannelSubscriber::new());
        self.channels
            .lock()
            .entry(name.to_string())
            .or_default()
            .push(std::sync::Arc::downgrade(&subscriber));
        subscriber
    }

    pub(crate) fn unsubscribe_channel(
        &self,
        name: &str,
        subscriber: &std::sync::Arc<ChannelSubscriber>,
    ) {
        let mut registry = self.channels.lock();
        if let Some(subscribers) = registry.get_mut(name) {
            subscribers.retain(|candidate| {
                candidate
                    .upgrade()
                    .is_some_and(|candidate| !std::sync::Arc::ptr_eq(&candidate, subscriber))
            });
            if subscribers.is_empty() {
                registry.remove(name);
            }
        }
        subscriber.close();
    }

    pub(crate) fn accept_channel(
        &self,
        session: &SessionCapability,
        claim: ResourceClaim,
        parse_retention: ResourceLease,
        name: &str,
        from: &str,
        payload: serde_json::Value,
    ) -> Result<GatewayAccepted, GatewayRefusal> {
        let mut registry = self.channels.lock();
        let candidate_count = registry.get(name).map_or(0, Vec::len);
        if candidate_count == 0 {
            return Err(GatewayRefusal::NoReceiver);
        }
        // The temporary live-subscriber snapshot and the all-or-nothing
        // prepared-delivery set each own one exact backing allocation. Fund
        // both before either Vec exists; the lease remains live until both
        // buffers have been consumed below.
        let scratch_count =
            u64::try_from(candidate_count).map_err(|_| GatewayRefusal::Malformed)?;
        let live_bytes = u64::try_from(std::mem::size_of::<std::sync::Arc<ChannelSubscriber>>())
            .map_err(|_| GatewayRefusal::Malformed)?
            .checked_mul(scratch_count)
            .ok_or(GatewayRefusal::Malformed)?;
        let prepared_bytes = u64::try_from(std::mem::size_of::<(
            std::sync::Arc<ChannelSubscriber>,
            ResourceLease,
            ResourceLease,
            serde_json::Value,
        )>())
        .map_err(|_| GatewayRefusal::Malformed)?
        .checked_mul(scratch_count)
        .ok_or(GatewayRefusal::Malformed)?;
        let scratch_claim = ResourceClaim::try_from_entries([
            (
                ResourceClass::AccountedMemoryBytes,
                live_bytes
                    .checked_add(prepared_bytes)
                    .ok_or(GatewayRefusal::Malformed)?,
            ),
            (ResourceClass::OpaqueDependencyResidual, 2),
        ])
        .map_err(|_| GatewayRefusal::Malformed)?;
        let _scratch = session
            .reserve_retained(scratch_claim)
            .map_err(GatewayRefusal::Pressure)?;
        let subscribers = {
            let Some(subscribers) = registry.get_mut(name) else {
                return Err(GatewayRefusal::NoReceiver);
            };
            let mut live = Vec::with_capacity(candidate_count);
            live.extend(subscribers.iter().filter_map(std::sync::Weak::upgrade));
            subscribers.retain(|subscriber| subscriber.strong_count() != 0);
            live
        };
        if subscribers.is_empty() {
            return Err(GatewayRefusal::NoReceiver);
        }
        let node_claim = GatewayMailbox::<GatewayChannelFrame>::node_claim()
            .map_err(|_| GatewayRefusal::Malformed)?;
        let from_claim = GatewayMailbox::<GatewayChannelFrame>::retention_claim(
            from.len(),
            usize::from(!from.is_empty()),
        )
        .map_err(|_| GatewayRefusal::Malformed)?;
        let queued_payload = ResourceClaim::single(
            ResourceClass::QueuedBytes,
            claim.amount(ResourceClass::AccountedMemoryBytes),
        );
        let entry_claim = claim
            .checked_add(from_claim)
            .and_then(|claim| claim.checked_add(queued_payload))
            .map_err(|_| GatewayRefusal::Malformed)?;
        let mut original_payload = Some(payload);
        let mut prepared = Vec::with_capacity(candidate_count);
        for (index, subscriber) in subscribers.iter().enumerate() {
            let retention = session.reserve_retained(entry_claim).map_err(|error| {
                for subscriber in &subscribers {
                    subscriber.note_pressure();
                }
                GatewayRefusal::Pressure(error)
            })?;
            let node = session.reserve_retained(node_claim).map_err(|error| {
                for subscriber in &subscribers {
                    subscriber.note_pressure();
                }
                GatewayRefusal::Pressure(error)
            })?;
            let payload = if index + 1 == subscribers.len() {
                original_payload
                    .take()
                    .expect("last subscriber owns payload")
            } else {
                original_payload.as_ref().expect("payload remains").clone()
            };
            prepared.push((std::sync::Arc::clone(subscriber), retention, node, payload));
        }
        for (subscriber, retention, node, payload) in prepared {
            subscriber.accept(
                GatewayChannelFrame {
                    from: from.to_string(),
                    payload,
                },
                retention,
                node,
            );
        }
        drop(registry);
        drop(parse_retention);
        Ok(GatewayAccepted)
    }

    pub(crate) fn capability_state(&self) -> &LocalCapabilityState {
        &self.capabilities
    }

    pub(crate) fn rpc(&self) -> Option<std::sync::Arc<crate::rpc::RpcInner>> {
        self.rpc.read().clone()
    }

    pub(crate) fn install_rpc(
        &self,
        create: impl FnOnce() -> std::sync::Arc<crate::rpc::RpcInner>,
    ) -> std::sync::Arc<crate::rpc::RpcInner> {
        let mut installed = self.rpc.write();
        std::sync::Arc::clone(installed.get_or_insert_with(create))
    }

    pub(crate) fn register_rpc_request(
        &self,
        state: &crate::engine::state::NetworkState,
        peer: &str,
        effect: crate::rpc::PendingEntry,
    ) -> Option<crate::rpc::LocalRequest> {
        let owner = state.peers.owner(peer)?;
        state
            .peers
            .with_live_session_state(
                &owner,
                state.session_broker.as_ref(),
                &state.network_id,
                |session, app| app.rpc_mut().register_local_request(session, effect),
            )
            .flatten()
    }

    pub(crate) fn abandon_rpc_request(
        &self,
        state: &crate::engine::state::NetworkState,
        peer: &str,
        filed: &crate::rpc::LocalRequest,
    ) {
        let Some(owner) = state.peers.owner(peer) else {
            return;
        };
        let _ = state.peers.with_live_session_state(
            &owner,
            state.session_broker.as_ref(),
            &state.network_id,
            |_session, app| app.rpc_mut().abandon_local_request(filed),
        );
    }

    pub(crate) async fn send_rpc_request(
        &self,
        state: &crate::engine::state::NetworkState,
        peer: &str,
        request: crate::protocol::rpc::RpcRequestMessage,
    ) -> crate::error::Result<()> {
        let (reply, rx) = tokio::sync::oneshot::channel();
        state
            .cmd_tx
            .send(crate::engine::state::NetworkCmd::SendRpcRequest {
                peer: peer.to_string(),
                request,
                reply,
            })
            .map_err(|_| crate::error::Error::Network("engine command queue closed".into()))?;
        rx.await
            .map_err(|_| crate::error::Error::Network("engine dropped reply".into()))?
    }

    pub(crate) async fn broadcast_capabilities(
        &self,
        state: &crate::engine::state::NetworkState,
        caps: crate::protocol::CapabilityAdvert,
    ) -> usize {
        let (reply, rx) = tokio::sync::oneshot::channel();
        if state
            .cmd_tx
            .send(crate::engine::state::NetworkCmd::BroadcastCapabilities { caps, reply })
            .is_err()
        {
            return 0;
        }
        rx.await.unwrap_or(0)
    }

    pub(crate) fn close(&self) {
        let subscribers = std::mem::take(&mut *self.channels.lock());
        for subscriber in subscribers
            .into_values()
            .flatten()
            .filter_map(|subscriber| subscriber.upgrade())
        {
            subscriber.close();
        }
        self.capabilities.clear();
        if let Some(rpc) = self.rpc.write().take() {
            rpc.handlers.clear();
        }
    }

    #[cfg(test)]
    pub(crate) fn channel_subscriber_count_for_test(&self, name: &str) -> usize {
        self.channels.lock().get(name).map_or(0, Vec::len)
    }
}

/// Why the Application Gateway refused an encoded application frame or queued
/// delivery. No receiver and provider pressure are different facts and remain
/// distinguishable to reliable delivery.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GatewayRefusal {
    NoReceiver,
    Revoked,
    Lag(u64),
    Pressure(ResourceUnavailable),
    Malformed,
}

/// An encoded application frame whose bytes and parse work were admitted by
/// the exact promoted session before full payload deserialization.
pub(crate) struct AdmittedApplicationFrame {
    encoded: Bytes,
    claim: ResourceClaim,
    _work: ResourceLease,
}

pub(crate) struct DecodedApplicationFrame {
    message: crate::protocol::MeshMessage,
    claim: ResourceClaim,
    _work: ResourceLease,
}

impl AdmittedApplicationFrame {
    pub(crate) fn claim(
        encoded_bytes: usize,
    ) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
        structural_json_claim(encoded_bytes)
    }

    pub(crate) fn admit(
        session: &SessionCapability,
        encoded: Bytes,
    ) -> Result<Self, GatewayRefusal> {
        let claim = Self::claim(encoded.len()).map_err(|_| GatewayRefusal::Malformed)?;
        let work = session
            .reserve_retained(claim)
            .map_err(GatewayRefusal::Pressure)?;
        Ok(Self {
            encoded,
            claim,
            _work: work,
        })
    }

    pub(crate) fn decode(self) -> Result<DecodedApplicationFrame, GatewayRefusal> {
        let message =
            serde_json::from_slice(&self.encoded).map_err(|_| GatewayRefusal::Malformed)?;
        Ok(DecodedApplicationFrame {
            message,
            claim: self.claim,
            _work: self._work,
        })
    }
}

/// The exact claim one JSON input of `max_frame_bytes` will be admitted
/// against, for an owner that has to size a resource provider.
///
/// This exists because the derivation below is the only thing that can answer
/// it, and a provider owner outside this crate previously had to guess. Guessing
/// is what left self-funded test providers granting a residual denominated in
/// records against a claim denominated in bytes, so their first inbound `Hello`
/// was refused with no latch set and no warning. The formula is not restated
/// here — this calls the same function — so the two cannot drift.
///
/// **This sizes a grant. It is not a wire gate and not a limit.** Nothing
/// consults it at admission; a frame is admitted against
/// [`structural_json_claim`] at its own actual length. Passing a value here says
/// only how large an input the owner is willing to fund, and an owner that funds
/// too little sees a refusal rather than a truncation.
pub fn json_input_work_claim(
    max_frame_bytes: usize,
) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    structural_json_claim(max_frame_bytes)
}

/// A mechanically conservative JSON-tree claim derived from the only quantity
/// available before parsing. A JSON value cannot contain more structural values
/// or owned scalar fragments than input bytes. Charging one full `Value` slot
/// and one opaque allocation per byte therefore covers adversarial tree
/// amplification instead of pretending wire length equals decoded retention.
pub(crate) fn structural_json_claim(
    encoded_bytes: usize,
) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    let bytes =
        u64::try_from(encoded_bytes).map_err(|_| ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        })?;
    let value_slot = u64::try_from(std::mem::size_of::<serde_json::Value>()).map_err(|_| {
        ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        }
    })?;
    let bytes_per_input =
        value_slot
            .checked_add(1)
            .ok_or(ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            })?;
    let decoded =
        bytes
            .checked_mul(bytes_per_input)
            .ok_or(ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            })?;
    ResourceClaim::try_from_entries([
        (ResourceClass::AccountedMemoryBytes, decoded),
        (ResourceClass::ParsingOrCpuWork, bytes),
        (ResourceClass::OpaqueDependencyResidual, bytes),
    ])
}

impl DecodedApplicationFrame {
    pub(crate) fn message(&self) -> &crate::protocol::MeshMessage {
        &self.message
    }

    pub(crate) fn into_parts(self) -> (crate::protocol::MeshMessage, ResourceClaim, ResourceLease) {
        (self.message, self.claim, self._work)
    }
}

/// The exact successful Application Gateway acceptance point. Construction is
/// possible only after a live receiver and both value/node leases exist.
pub(crate) struct GatewayAccepted;

struct GatewayEntry<T> {
    value: T,
    _retention: ResourceLease,
}

/// One accepted delivery after its mailbox node has been released. The value's
/// off-node retention remains funded until this wrapper is consumed or dropped.
pub(crate) struct GatewayDelivery<T> {
    value: T,
    _retention: ResourceLease,
}

impl<T> GatewayDelivery<T> {
    pub(crate) fn into_parts(self) -> (T, ResourceLease) {
        (self.value, self._retention)
    }
}

/// Compact one-allocation-per-entry mailbox representation. The queue lease
/// funds only its node; the entry keeps off-node retention funded after pop.
pub(crate) struct GatewayMailbox<T> {
    queue: LeasedQueue<GatewayEntry<T>>,
}

impl<T> GatewayMailbox<T> {
    pub(crate) const fn new() -> Self {
        Self {
            queue: LeasedQueue::new(),
        }
    }

    pub(crate) fn node_claim() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
        LeasedQueue::<GatewayEntry<T>>::entry_claim()
    }

    /// Claim the producer-measured off-node representation retained by one
    /// value. Allocation count is explicit because a serialized byte block and
    /// a decoded tree are different representations and must not share a guess.
    pub(crate) fn retention_claim(
        retained_bytes: usize,
        allocations: usize,
    ) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
        let retained_bytes =
            u64::try_from(retained_bytes).map_err(|_| ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            })?;
        let allocations =
            u64::try_from(allocations).map_err(|_| ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::OpaqueDependencyResidual,
            })?;
        ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, retained_bytes),
            (ResourceClass::QueuedBytes, retained_bytes),
            (ResourceClass::OpaqueDependencyResidual, allocations),
        ])
    }

    pub(crate) fn accept(
        &mut self,
        value: T,
        retention: ResourceLease,
        node: ResourceLease,
    ) -> GatewayAccepted {
        self.queue.push(
            GatewayEntry {
                value,
                _retention: retention,
            },
            node,
        );
        GatewayAccepted
    }

    pub(crate) fn pop(&mut self) -> Option<GatewayDelivery<T>> {
        self.queue.pop_front().map(|entry| GatewayDelivery {
            value: entry.value,
            _retention: entry._retention,
        })
    }

    #[cfg(test)]
    pub(crate) const fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

/// Local proof that an operating-system principal was authenticated and is
/// eligible for a Session Broker policy check.
///
/// One per process, minted by [`Self::for_local_process`] and shared through an
/// `Arc` by every session that speaks for it. A second value would be a second
/// principal, which is why there is no other constructor.
///
/// A public user, client, request, or peer label cannot construct this type:
///
/// ```compile_fail,E0308
/// use myownmesh_core::application_gateway::LocalPrincipalCapability;
///
/// let public_client_label = String::new();
/// let _principal = LocalPrincipalCapability::from(public_client_label);
/// ```
pub struct LocalPrincipalCapability {
    runtime: RuntimeIncarnation,
}

impl LocalPrincipalCapability {
    /// Bind the principal for this process's runtime.
    ///
    /// Crate-private and called once, by the Session Broker. The authority is
    /// the running process's own: no evidence is parsed, because none is
    /// transmitted — an in-process embedder cannot present a principal other
    /// than the one it is.
    ///
    /// The daemon's control clients are deliberately **not** separate
    /// principals. A Device value arriving over control IPC is a selector, and
    /// which local process may call the daemon at all is the operating system's
    /// socket boundary to decide. Each supervising application gets this
    /// principal through its own daemon process, so per-client identities would
    /// add a second identity system without adding a second trust boundary.
    pub(crate) fn for_local_process(runtime: RuntimeIncarnation) -> Self {
        Self { runtime }
    }

    pub(crate) fn runtime(&self) -> &RuntimeIncarnation {
        &self.runtime
    }

    #[cfg(test)]
    pub(crate) fn for_test(runtime: RuntimeIncarnation) -> Self {
        Self::for_local_process(runtime)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::{
        FiniteResourceProvider, ResourceAuthorityClass, ResourceProviderPort, ResourceScope,
    };

    fn mailbox_provider(
        node: ResourceClaim,
        retention: ResourceClaim,
    ) -> (FiniteResourceProvider, ResourceProviderPort, ResourceScope) {
        let scope_record = FiniteResourceProvider::scope_record_charge_for_test();
        let grant = scope_record
            .checked_add(
                FiniteResourceProvider::reservation_charge_for_test(node)
                    .expect("the node reservation is representable"),
            )
            .and_then(|grant| {
                grant.checked_add(
                    FiniteResourceProvider::reservation_charge_for_test(retention)
                        .expect("the retention reservation is representable"),
                )
            })
            .expect("one mailbox entry and its provider records compose");
        let provider = FiniteResourceProvider::new(grant);
        let port =
            ResourceProviderPort::new(provider.clone()).expect("the grant funds the process scope");
        let scope = port.process_scope();
        (provider, port, scope)
    }

    #[test]
    fn gateway_pop_releases_node_but_delivery_keeps_retention_funded() {
        let node = GatewayMailbox::<Bytes>::node_claim().expect("node claim is representable");
        let retention = GatewayMailbox::<Bytes>::retention_claim(4, 1)
            .expect("retention claim is representable");
        let (provider, port, scope) = mailbox_provider(node, retention);
        let baseline = provider.in_use();
        let retention_lease = port
            .acquire(&scope, ResourceAuthorityClass::Admitted, retention)
            .expect("the exact retention claim is available");
        let node_lease = port
            .acquire(&scope, ResourceAuthorityClass::Admitted, node)
            .expect("the exact node claim is available");
        let mut mailbox = GatewayMailbox::new();
        let _accepted = mailbox.accept(Bytes::from_static(b"test"), retention_lease, node_lease);
        assert!(!mailbox.is_empty(), "acceptance installed one real entry");

        let delivery = mailbox.pop().expect("the accepted entry is delivered");
        let (value, retention_lease) = delivery.into_parts();
        assert_eq!(value, Bytes::from_static(b"test"));
        assert!(mailbox.is_empty(), "pop released the mailbox node");
        assert_eq!(
            provider.in_use(),
            baseline
                .checked_add(
                    FiniteResourceProvider::reservation_charge_for_test(retention)
                        .expect("the retention reservation is representable"),
                )
                .expect("baseline and retention compose"),
            "the returned delivery still owns its exact off-node retention",
        );
        drop((value, retention_lease));
        let after_removed_value_drop = provider.in_use();
        assert_eq!(after_removed_value_drop, baseline);
    }

    #[test]
    fn json_admission_does_not_equate_wire_length_with_decoded_tree_retention() {
        let wire = 7usize;
        let claim = structural_json_claim(wire).expect("the small claim is representable");
        assert_eq!(claim.amount(ResourceClass::ParsingOrCpuWork), wire as u64);
        assert_eq!(
            claim.amount(ResourceClass::OpaqueDependencyResidual),
            wire as u64,
            "every possible owned fragment has an explicit residual"
        );
        assert!(
            claim.amount(ResourceClass::AccountedMemoryBytes) > wire as u64,
            "decoded Value slots, rather than wire bytes alone, are funded"
        );
    }

    #[test]
    fn v4_arc02_local_principal_is_runtime_bound() {
        let runtime = crate::runtime::runtime_for_test();
        let principal = LocalPrincipalCapability::for_test(runtime.clone());

        assert!(principal.runtime().is_same(&runtime));
    }
}
