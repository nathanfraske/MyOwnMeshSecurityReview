//! Engine ↔ IPC bridge: synthetic `Rpc::serve` / `serve_stream`
//! handlers that route inbound peer RPCs to whichever IPC
//! client currently holds the matching method claim, plus the
//! per-channel pump task that fans `Channel::subscribe()`
//! frames out to subscribed IPC clients.
//!
//! Lifetime model:
//!
//! - **Handlers** are installed lazily on first claim of a
//!   `(network, method)` pair and forgotten on the last unclaim —
//!   whether that unclaim is an explicit `RpcUnregister` or the
//!   disconnect of the client that held it. Installing is an
//!   admission the engine can refuse, and the refusal is answered
//!   to the claiming client rather than swallowed: a claim whose
//!   handler was never installed would route nothing.
//!
//!   They used to be left in place forever, on the reasoning that a
//!   re-claim would save the install. That was a real saving and it
//!   was paid for in the wrong currency: each installed handler
//!   holds its own retention in the network's gateway scope, and a
//!   local client that claimed many methods and left could strand
//!   all of it indefinitely. A handler still answers "no claim"
//!   truthfully if invoked between the last unclaim and its
//!   removal, so nothing depends on the two being simultaneous.
//!
//! - **Channel pumps** are scoped to subscribers: the first
//!   subscribe spawns a forwarder task, the last unsubscribe
//!   drops the receiver and the task exits on its next loop
//!   iteration. Each task holds a weak reference to the registry rather than
//!   a strong one, so a swept-away registry doesn't keep tasks alive.

use myownmesh_core::application_gateway::GatewayRefusal;
use myownmesh_core::{JoinedNetwork, ResourceMailboxAdmissionError};
use serde_json::Value;
use tracing::{debug, warn};

use super::clients::{ClientRegistry, HandlerMode, IpcAdmissionError, PendingInbound, PendingKey};
use super::wire::ServerOut;

/// Drop the synthetic handler for one method from a network's dispatcher.
///
/// Called on the last unclaim — an explicit `RpcUnregister`, or the disconnect
/// of the client that held the claim. Idempotent in the engine, so a caller that
/// cannot tell whether it was the last claimant is free to ask anyway; the
/// registry answers that question exactly, and both of its answers are honoured
/// here without a second check.
///
/// Lives beside the installs rather than at the call sites so that what is
/// installed and what is removed stay one decision. The engine's own `forget`
/// takes only the method name because a dispatcher belongs to one network
/// already — the `(network, method)` pair is this crate's key, not core's.
pub fn forget_handler(network: &JoinedNetwork, method: &str) {
    network.rpc().forget(method);
}

/// Why one channel pump could not be started.
///
/// Kept as two arms because the caller's remedy is the same but the operator's
/// reading of them is not: a refused subscription means the gateway is closed
/// or under pressure for that channel, while a refused task means this daemon
/// is at its accounted concurrency. Collapsing them into one string would make
/// a capacity problem look like a channel problem.
#[derive(Debug, thiserror::Error)]
pub enum ChannelPumpError {
    #[error("channel subscription was refused: {0}")]
    Subscribe(myownmesh_core::ChannelError),
    #[error("channel pump task could not be accounted: {0}")]
    Task(IpcAdmissionError),
}

/// Install (or re-install) a synthetic single-shot RPC handler
/// for `(network_id, method)` on this network's `Rpc`
/// dispatcher. The handler emits `RpcInbound` to whichever
/// client currently owns the claim and awaits an `RpcRespond`
/// to resolve.
///
/// Installing is an admission: the engine funds the handler's retention out of
/// the network's gateway scope and can refuse. The refusal is returned rather
/// than discarded, because a claim recorded against a handler that was never
/// installed is a client told it is serving a method that will never reach it.
pub fn install_single_handler(
    network: &JoinedNetwork,
    network_key: String,
    method: String,
    registry: ClientRegistry,
) -> Result<(), GatewayRefusal> {
    let rpc = network.rpc();
    let key = (network_key.clone(), method.clone());
    rpc.serve(&method, move |call| {
        let registry = registry.clone();
        let key = key.clone();
        async move {
            let Some(owner_id) = registry.handler_owner(&key) else {
                return Err(format!(
                    "no IPC client holds method '{}' on '{}'",
                    key.1, key.0
                ));
            };
            let Some(client) = registry.client(owner_id) else {
                return Err("handler owner client disconnected".into());
            };
            let (tx, rx) = tokio::sync::oneshot::channel();
            let pending_key = PendingKey {
                network: key.0.clone(),
                method: key.1.clone(),
                remote_peer: call.from.clone(),
                remote_request_id: call.request_id.clone(),
                class: HandlerMode::Single,
            };
            let ticket = match registry.insert_exact_pending(
                pending_key,
                owner_id,
                PendingInbound::Single(tx),
            ) {
                Ok(ticket) => ticket,
                // The reason reaches the peer. Colliding coordinates, an owner
                // that left, and a daemon out of capacity are three different
                // things to be told, and this used to report all three as the
                // first — sending a peer to fix coordinates that were fine.
                Err(rejected) => return Err(rejected.reason.to_string()),
            };
            // A frame the owner's mailbox will not admit is reported to the
            // peer here rather than dropped. Dropping it would leave the
            // pending entry installed and the caller waiting on a request no
            // client was ever told about, which resolves only as a timeout —
            // an outcome indistinguishable from a peer that went away.
            // Returning drops the ticket, which removes the pending entry.
            if let Err(refusal) = client.send(ServerOut::RpcInbound {
                network: key.0.clone(),
                from: call.from.clone(),
                request_id: call.request_id.clone(),
                operation_id: ticket.operation_id(),
                method: call.method.clone(),
                payload: call.payload.clone(),
                streaming: call.streaming,
            }) {
                return Err(format!(
                    "IPC handler owner could not be given the inbound call: {refusal}"
                ));
            }
            // Await this owner's `RpcRespond`. Disconnect and displacement
            // remove this exact operation and settle the oneshot with a
            // truthful error; a later claimant cannot answer it.
            let result = match rx.await {
                Ok(Ok(payload)) => Ok(value_to_response(payload)),
                Ok(Err(e)) => Err(e),
                Err(_) => Err("IPC handler dropped without responding".into()),
            };
            drop(ticket);
            result
        }
    })
}

/// Install (or re-install) a synthetic streaming RPC handler.
/// Mirrors [`install_single_handler`] but stashes a resource-funded
/// `ResourceMailboxSender<RpcStreamItem>` in the pending table instead
/// of a `oneshot`; chunks land via `RpcStreamChunk`, and
/// `RpcStreamEnd` terminates the stream with an explicit
/// `RpcStreamItem::End` carrying clean completion or the
/// client's error.
///
/// Fallible for the same reason [`install_single_handler`] is.
pub fn install_stream_handler(
    network: &JoinedNetwork,
    network_key: String,
    method: String,
    registry: ClientRegistry,
) -> Result<(), GatewayRefusal> {
    let rpc = network.rpc();
    let key = (network_key.clone(), method.clone());
    rpc.serve_stream(&method, move |call| {
        let registry = registry.clone();
        let key = key.clone();
        async move {
            let Some(owner_id) = registry.handler_owner(&key) else {
                return Err(format!(
                    "no IPC client holds streaming method '{}' on '{}'",
                    key.1, key.0
                ));
            };
            let Some(client) = registry.client(owner_id) else {
                return Err("handler owner client disconnected".into());
            };
            // No item count. This queue is bounded by what the process owner
            // funded, measured per chunk, rather than by a number of chunks —
            // which is the only bound that is true of a stream whose items have
            // no fixed size. A capacity of N said nothing about how much memory
            // N chunks would hold.
            //
            // Its own subtree, so everything one stream retains is released as
            // a unit when the stream ends rather than lingering in the
            // registry's scope for the daemon's lifetime.
            //
            // The send side is stashed in `exact_pending_inbound`; chunks land
            // via `RpcStreamChunk`. The stream ends with an explicit terminal
            // item: `RpcStreamEnd` sends `RpcStreamItem::End` carrying either
            // clean completion or the client's own error, so that distinction
            // survives to the peer instead of being flattened into a silent
            // close. A sender that disappears without one is a failure rather
            // than an end, which is what makes the watchdog below necessary.
            let resources = match registry.child_resources() {
                Ok(resources) => resources,
                Err(refusal) => {
                    return Err(format!(
                        "inbound streaming RPC queue could not be scoped: {refusal}"
                    ))
                }
            };
            let (tx, rx) = match myownmesh_core::resource_mailbox::<
                myownmesh_core::rpc::RpcStreamItem,
            >(resources)
            {
                Ok(mailbox) => mailbox,
                Err(refusal) => {
                    return Err(format!(
                        "inbound streaming RPC queue could not be funded: {refusal}"
                    ))
                }
            };
            let pending_key = PendingKey {
                network: key.0.clone(),
                method: key.1.clone(),
                remote_peer: call.from.clone(),
                remote_request_id: call.request_id.clone(),
                class: HandlerMode::Stream,
            };
            let close_probe = tx.clone();
            let ticket = match registry.insert_exact_pending(
                pending_key,
                owner_id,
                PendingInbound::Stream(tx),
            ) {
                Ok(ticket) => ticket,
                // Same three outcomes as the single-shot handler, reported
                // apart for the same reason.
                Err(rejected) => return Err(rejected.reason.to_string()),
            };
            // Same reasoning as the single-shot handler: a frame the owner's
            // mailbox refuses is reported to the peer rather than dropped.
            // Returning here drops `ticket` and `close_probe` before the
            // watchdog below is spawned, so the pending entry leaves with them
            // and no stream is left waiting for chunks nothing will send.
            if let Err(refusal) = client.send(ServerOut::RpcInbound {
                network: key.0.clone(),
                from: call.from.clone(),
                request_id: call.request_id.clone(),
                operation_id: ticket.operation_id(),
                method: call.method.clone(),
                payload: call.payload.clone(),
                streaming: call.streaming,
            }) {
                return Err(format!(
                    "IPC handler owner could not be given the inbound streaming call: {refusal}"
                ));
            }
            // The watchdog is what eventually drops the ticket and its pending
            // entry, so it is funded before it is spawned and the refusal is
            // reported to the peer. An unfunded watchdog would mean either no
            // watchdog — leaving the pending entry installed with nothing left
            // to remove it — or one running unaccounted. Returning here drops
            // `ticket` and `close_probe` together, which removes the entry and
            // settles the stream, so the refusal path needs no separate
            // cleanup.
            let task = match registry.lease_task() {
                Ok(task) => task,
                Err(refusal) => {
                    return Err(format!(
                        "inbound streaming RPC could not be accounted: {refusal}"
                    ))
                }
            };
            tokio::spawn(async move {
                let _task = task;
                tokio::select! {
                    () = close_probe.closed() => {}
                    () = ticket.cancelled() => {}
                }
                drop(close_probe);
                drop(ticket);
            });
            Ok(rx)
        }
    })
}

/// Spawn the per-channel fan-out task for an IPC subscription
/// on `(network_id, channel)`. Idempotent at the registry
/// level — the caller is expected to spawn this only when
/// `subscribe_channel(...)` returns true (the first
/// subscriber). On the last `unsubscribe_channel(...)`
/// returning true (no remaining subscribers), the task ends on
/// its next loop iteration when it sees an empty subscriber
/// list.
///
/// The task lives by polling the channel's broadcast receiver.
/// If the network is torn down (`recv` returns `Closed`) or
/// the subscriber set becomes empty between frames, it exits.
/// Subscription is a resource admission and can be refused, so this reports
/// rather than starts a pump that would never receive anything. The caller
/// answers the requesting client with the refusal instead of recording a
/// subscription the daemon does not actually hold.
pub fn spawn_channel_pump(
    network: &JoinedNetwork,
    network_key: String,
    channel_name: String,
    registry: ClientRegistry,
) -> std::result::Result<(), ChannelPumpError> {
    let channel = network.channel::<Value>(&channel_name);
    let mut sub = channel.subscribe().map_err(ChannelPumpError::Subscribe)?;
    // Funded before the pump exists, and for the same reason the subscription
    // is checked first: this reports rather than starting a pump the daemon
    // cannot account for. Both refusals reach the caller before any subscriber
    // state is recorded, so there is nothing to unwind here — the caller undoes
    // its own registry entry and tells the client.
    let task = registry.lease_task().map_err(ChannelPumpError::Task)?;
    let key = (network_key.clone(), channel_name.clone());
    tokio::spawn(async move {
        let _task = task;
        loop {
            // Exit early if no subscribers remain.
            let subscribers = registry.channel_subscribers(&key);
            if subscribers.is_empty() {
                debug!(
                    network = %key.0,
                    channel = %key.1,
                    "channel pump exiting (no subscribers)"
                );
                break;
            }
            let Some(next) = sub.recv().await else {
                debug!(
                    network = %key.0,
                    channel = %key.1,
                    "channel pump exiting (channel closed)"
                );
                break;
            };
            match next {
                Ok(msg) => {
                    let frame = ServerOut::ChannelInbound {
                        network: key.0.clone(),
                        from: msg.from,
                        channel: key.1.clone(),
                        payload: msg.body,
                    };
                    for client_id in subscribers {
                        if let Some(client) = registry.client(client_id) {
                            // Fan-out has nobody to answer: the frame came off
                            // a broadcast and no peer is waiting on this
                            // subscriber in particular. A refusal is therefore
                            // logged rather than propagated — but it is logged,
                            // because a subscriber silently missing a channel
                            // message is the failure this pump exists to make
                            // visible. `Closed` is the ordinary disconnect race
                            // and stays at debug.
                            match client.send(frame.clone()) {
                                Ok(()) => {}
                                Err(ResourceMailboxAdmissionError::Closed) => debug!(
                                    network = %key.0,
                                    channel = %key.1,
                                    client = %client_id,
                                    "channel frame dropped: subscriber disconnected"
                                ),
                                Err(refusal) => warn!(
                                    network = %key.0,
                                    channel = %key.1,
                                    client = %client_id,
                                    "channel frame refused for a connected subscriber: {refusal}"
                                ),
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        network = %key.0,
                        channel = %key.1,
                        "channel deserialize error: {e}"
                    );
                }
            }
        }
    });
    Ok(())
}

/// `myownmesh-core`'s `Rpc::serve` wants an
/// `Ok(RpcResponse)` — wrap a raw `Value` so callers don't
/// reach across crate-private types.
pub fn value_to_response(v: Value) -> myownmesh_core::rpc::RpcResponse {
    myownmesh_core::rpc::RpcResponse::from_value(v)
}

/// Helper used by `dispatch` when an IPC client releases or
/// has been disconnected: notify the now-displaced client.
pub fn notify_displaced(
    registry: &ClientRegistry,
    prev_owner: super::clients::ClientId,
    by: super::clients::ClientId,
    network: String,
    method: String,
) {
    if let Some(client) = registry.client(prev_owner) {
        // The displacement has already happened in the registry; this frame
        // only tells the loser about it. There is no caller to refuse and no
        // way to undo the claim transfer, so a refusal is recorded and the
        // displaced client is left to notice through its own failing calls.
        let network_id = network.clone();
        let displaced_method = method.clone();
        match client.send(ServerOut::HandlerDisplaced {
            network,
            method,
            by: by.to_string(),
        }) {
            Ok(()) => {}
            Err(ResourceMailboxAdmissionError::Closed) => debug!(
                network = %network_id,
                method = %displaced_method,
                client = %prev_owner,
                "displacement notice dropped: displaced client had already disconnected"
            ),
            Err(refusal) => warn!(
                network = %network_id,
                method = %displaced_method,
                client = %prev_owner,
                "connected client was displaced but could not be told: {refusal}"
            ),
        }
    }
}

/// Public helper for the dispatch layer: install whichever
/// handler shape matches the requested mode. Idempotent —
/// re-claiming an existing method just replaces the synthetic
/// handler (and `Rpc::serve` itself does the same).
pub fn install_handler_for_mode(
    network: &JoinedNetwork,
    network_key: String,
    method: String,
    mode: HandlerMode,
    registry: ClientRegistry,
) -> Result<(), GatewayRefusal> {
    match mode {
        HandlerMode::Single => install_single_handler(network, network_key, method, registry),
        HandlerMode::Stream => install_stream_handler(network, network_key, method, registry),
    }
}

#[cfg(test)]
mod tests {
    //! End-to-end engine-bridge tests. Two engines wired
    //! through `LocalBroker`; one side simulates an IPC client
    //! by holding the receiver end of a `ClientHandle` and
    //! manually feeding `RpcRespond`s back through the
    //! registry — same path the dispatch layer takes when a
    //! real socket client posts `RpcRespond`.

    use crate::ipc::clients::{ClientRegistry, HandlerMode, PendingKey};
    use crate::ipc::wire::ServerOut;
    use myownmesh_core::config::{NetworkConfig, SignalingConfig, TopologyMode};
    use myownmesh_core::engine::{attach_local, spawn_network};
    use myownmesh_core::events::{MeshEvent, PeerEvent};
    use myownmesh_core::identity::Identity;
    use myownmesh_core::transport::Transport;
    use myownmesh_core::{
        ConnectorCallbackMailboxCapacities, ConnectorCallbackPolicy,
        ConnectorCallbackServiceWeights, PendingRemoteCandidatePolicy,
        WebRtcConnectorCapablePolicy, WebRtcConnectorProfile,
    };
    use myownmesh_signaling::local::LocalBroker;
    use std::num::NonZeroUsize;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::Instant;

    // Serialization lives on `crate::exclusive_connector_fixture`, which every
    // connector-consuming family in this binary shares. A mutex local to this
    // module would only stop these three tests racing each other, which was
    // never the problem: they draw on one process-global connector budget that
    // `embedded` and `registry` draw on too.

    struct BridgeTestDrivers {
        alice: Arc<myownmesh_core::engine::NetworkState>,
        bob: Arc<myownmesh_core::engine::NetworkState>,
        drivers: Vec<tokio::task::JoinHandle<()>>,
    }

    impl BridgeTestDrivers {
        async fn shutdown(mut self) {
            // The owner-held coalesced signal, not a queued command: it sets the
            // flag, wakes the waiters and closes both queues itself, so it
            // cannot be dropped or outranked by payload traffic the way a
            // command competing in the same mailbox could be.
            self.alice.request_shutdown();
            self.bob.request_shutdown();
            while let Some(driver) = self.drivers.pop() {
                let _ = driver.await;
            }
        }
    }

    impl Drop for BridgeTestDrivers {
        fn drop(&mut self) {
            // Idempotent by construction, so the explicit `shutdown` above and
            // this backstop can both run: the flag is a store and the queue
            // closes are already-closed no-ops on the second call.
            self.alice.request_shutdown();
            self.bob.request_shutdown();
        }
    }

    fn fresh_network(id: &str, wire_id: &str) -> NetworkConfig {
        NetworkConfig {
            id: id.to_string(),
            network_id: wire_id.to_string(),
            label: id.to_string(),
            kind: Default::default(),
            topology: TopologyMode::FullMesh,
            signaling: SignalingConfig::default(),
            stun_servers: Vec::new(),
            turn_servers: Vec::new(),
            roster_path: None,
            pinned_peers: Vec::new(),
            auto_approve: true,
        }
    }

    fn test_transport() -> Transport {
        let callback_capacity =
            NonZeroUsize::new(16).expect("test callback capacity is explicitly nonzero");
        let callbacks = ConnectorCallbackPolicy::new(
            ConnectorCallbackMailboxCapacities::new(callback_capacity, callback_capacity),
            ConnectorCallbackServiceWeights::data_only(callback_capacity, callback_capacity),
            myownmesh_core::RealtimeConnectorPolicy::Disabled,
        )
        .expect("test data-only callback policy is valid");
        let webrtc_profile =
            WebRtcConnectorProfile::new(callbacks, PendingRemoteCandidatePolicy::elastic());
        let policy =
            WebRtcConnectorCapablePolicy::new(crate::test_resource_provider(), webrtc_profile);
        Transport::new()
            .expect("transport")
            .with_connector_resource_policy(policy)
            .expect("test process connector policy is consistent")
    }

    async fn wait_for_approval(
        rx: &mut tokio::sync::broadcast::Receiver<MeshEvent>,
        peer_id: &str,
    ) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if Instant::now() > deadline {
                panic!("never saw PeerApproved for {peer_id}");
            }
            let next = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await;
            match next {
                Ok(Ok(MeshEvent::Peer(PeerEvent::Approved { device_id, .. })))
                    if device_id == peer_id =>
                {
                    return;
                }
                _ => continue,
            }
        }
    }

    /// Build two engines and an RPC dispatcher pair sharing one LocalBroker.
    /// The returned driver owner performs a real shutdown so one process-global
    /// connector budget is reusable by the next test.
    #[allow(clippy::type_complexity)]
    async fn two_peer_rpc(
        wire_id: &str,
    ) -> (
        Arc<myownmesh_core::engine::NetworkState>,
        Arc<myownmesh_core::engine::NetworkState>,
        Arc<myownmesh_core::rpc::Rpc>,
        Arc<myownmesh_core::rpc::Rpc>,
        Arc<Identity>,
        Arc<Identity>,
        BridgeTestDrivers,
    ) {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::env::set_var("MYOWNMESH_HOME", tmp.path());
        std::mem::forget(tmp); // leak — test scope only

        let broker = LocalBroker::new();
        let transport = test_transport();

        let alice_id = Arc::new(Identity::ephemeral());
        let bob_id = Arc::new(Identity::ephemeral());

        let alice_cfg = fresh_network("alice", wire_id);
        let bob_cfg = fresh_network("bob", wire_id);

        let (alice_state, alice_driver) =
            spawn_network(alice_cfg, alice_id.clone(), transport.clone())
                .await
                .expect("alice engine");
        let (bob_state, bob_driver) = spawn_network(bob_cfg, bob_id.clone(), transport.clone())
            .await
            .expect("bob engine");
        let alice_rpc = Arc::new(
            myownmesh_core::rpc::Rpc::attach(&alice_state)
                .expect("Alice's live gateway admits its RPC owner"),
        );
        let bob_rpc = Arc::new(
            myownmesh_core::rpc::Rpc::attach(&bob_state)
                .expect("Bob's live gateway admits its RPC owner"),
        );

        let mut alice_events = alice_state.events_tx.subscribe();
        let mut bob_events = bob_state.events_tx.subscribe();
        attach_local(&alice_state, &broker);
        attach_local(&bob_state, &broker);

        wait_for_approval(&mut alice_events, bob_id.public_id()).await;
        wait_for_approval(&mut bob_events, alice_id.public_id()).await;

        let drivers = BridgeTestDrivers {
            alice: Arc::clone(&alice_state),
            bob: Arc::clone(&bob_state),
            drivers: vec![alice_driver, bob_driver],
        };
        (
            alice_state,
            bob_state,
            alice_rpc,
            bob_rpc,
            alice_id,
            bob_id,
            drivers,
        )
    }

    /// Single-shot RPC routed via the IPC bridge. Alice's
    /// network registers a synthetic handler bound to a
    /// simulated IPC client; Bob calls the method; the
    /// "client" receives `RpcInbound`, posts `RpcRespond` back
    /// via the registry, and Bob's call resolves with the
    /// returned payload.
    #[tokio::test]
    async fn single_shot_rpc_round_trip_through_bridge() {
        let _fixture = crate::exclusive_connector_fixture().await;
        let (alice_state, _bob_state, _alice_rpc, bob_rpc, alice_id, _bob_id, drivers) =
            two_peer_rpc("ipc-bridge-single").await;

        // Simulate an IPC client on Alice's side.
        let registry = ClientRegistry::default();
        let (tx, mut rx) =
            myownmesh_core::resource_mailbox::<ServerOut>(crate::test_application_scope())
                .expect("the daemon test grant funds this fixture client's writer mailbox");
        let client = registry
            .register(tx)
            .expect("the daemon test grant funds this fixture client record");
        let net_key = "alice".to_string();
        let method = "echo".to_string();
        let key = (net_key.clone(), method.clone());
        registry
            .claim_method(key.clone(), client.id, HandlerMode::Single)
            .expect("the daemon test grant funds this fixture's method claim");

        // The bridge needs a `JoinedNetwork` — but we have the
        // state directly. The synthetic handler only needs to
        // call `Rpc::serve` on the network's Rpc, which we can
        // do via the lower-level `attach` path mirroring what
        // `install_single_handler` does, but inlined here so
        // we don't need a `JoinedNetwork` facade.
        //
        // Both admissions are asserted rather than discarded. This fixture is
        // pointless if the handler is not actually installed, and a discarded
        // refusal would have turned that into a mysteriously silent peer.
        let registry_for_handler = registry.clone();
        let key_for_handler = key.clone();
        myownmesh_core::rpc::Rpc::attach(&alice_state)
            .expect("the fixture network's application gateway admits an Rpc")
            .serve("echo", move |call| {
                let registry = registry_for_handler.clone();
                let key = key_for_handler.clone();
                async move {
                    let owner = registry
                        .handler_owner(&key)
                        .ok_or_else(|| "no claim".to_string())?;
                    let client = registry
                        .client(owner)
                        .ok_or_else(|| "owner gone".to_string())?;
                    let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
                    let pending_key = PendingKey {
                        network: key.0.clone(),
                        method: key.1.clone(),
                        remote_peer: call.from.clone(),
                        remote_request_id: call.request_id.clone(),
                        class: HandlerMode::Single,
                    };
                    let Ok(ticket) = registry.insert_exact_pending(
                        pending_key,
                        owner,
                        crate::ipc::clients::PendingInbound::Single(resp_tx),
                    ) else {
                        return Err("duplicate".into());
                    };
                    // Reported rather than asserted: this runs inside the engine's
                    // handler task, where a panic would surface as a caller that
                    // never settles. An error reaches the assertion in the test
                    // body carrying its own reason.
                    if let Err(refusal) = client.send(ServerOut::RpcInbound {
                        network: key.0.clone(),
                        from: call.from.clone(),
                        request_id: call.request_id.clone(),
                        operation_id: ticket.operation_id(),
                        method: call.method.clone(),
                        payload: call.payload.clone(),
                        streaming: call.streaming,
                    }) {
                        return Err(format!("fixture client mailbox refused inbound: {refusal}"));
                    }
                    let result = match resp_rx.await {
                        Ok(Ok(p)) => Ok(myownmesh_core::rpc::RpcResponse::from_value(p)),
                        Ok(Err(e)) => Err(e),
                        Err(_) => Err("handler dropped".into()),
                    };
                    drop(ticket);
                    result
                }
            })
            .expect("the fixture network admits one single-shot handler");

        // Bob calls the method.
        let alice_did = alice_id.public_id().to_string();
        let call_handle = tokio::spawn(async move {
            bob_rpc
                .call(&alice_did, "echo", serde_json::json!({"n": 7}))
                .await
        });

        // Pull the RpcInbound off the simulated client's writer mailbox.
        let inbound = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("inbound timeout")
            .expect("inbound recv")
            .into_parts()
            .0;
        let (network, from, request_id, operation_id, method, payload) = match inbound {
            ServerOut::RpcInbound {
                network,
                from,
                request_id,
                operation_id,
                payload,
                method,
                ..
            } => {
                assert_eq!(method, "echo");
                (network, from, request_id, operation_id, method, payload)
            }
            other => panic!("expected RpcInbound, got {other:?}"),
        };
        assert_eq!(payload, serde_json::json!({"n": 7}));

        // Respond via the registry (same path dispatch takes).
        let pending_key = PendingKey {
            network,
            method,
            remote_peer: from,
            remote_request_id: request_id,
            class: HandlerMode::Single,
        };
        let resolved = registry.resolve_exact_single(
            &pending_key,
            client.id,
            operation_id,
            Ok(serde_json::json!({"n_squared": 49})),
        );
        assert!(resolved);

        let bob_response = tokio::time::timeout(Duration::from_secs(5), call_handle)
            .await
            .expect("call timeout")
            .expect("join")
            .expect("rpc ok");
        assert_eq!(bob_response.body, serde_json::json!({"n_squared": 49}));
        drivers.shutdown().await;
    }

    /// Streaming RPC: Alice's "client" pushes three chunks
    /// via `push_exact_stream` + closes via
    /// `close_exact_stream`; Bob's `call_stream` drains the
    /// receiver and sees all three plus the end-of-stream.
    #[tokio::test]
    async fn streaming_rpc_round_trip_through_bridge() {
        let _fixture = crate::exclusive_connector_fixture().await;
        let (alice_state, _bob_state, _alice_rpc, bob_rpc, alice_id, _bob_id, drivers) =
            two_peer_rpc("ipc-bridge-stream").await;

        let registry = ClientRegistry::default();
        let (tx, mut rx) =
            myownmesh_core::resource_mailbox::<ServerOut>(crate::test_application_scope())
                .expect("the daemon test grant funds this fixture client's writer mailbox");
        let client = registry
            .register(tx)
            .expect("the daemon test grant funds this fixture client record");
        let key = ("alice".to_string(), "stream_echo".to_string());
        registry
            .claim_method(key.clone(), client.id, HandlerMode::Stream)
            .expect("the daemon test grant funds this fixture's method claim");

        // Wire the synthetic stream handler. Identical to the
        // single-shot test but uses `serve_stream` + the
        // `PendingInbound::Stream` arm — including asserting both
        // admissions rather than discarding them.
        let registry_for_handler = registry.clone();
        let key_for_handler = key.clone();
        myownmesh_core::rpc::Rpc::attach(&alice_state)
            .expect("the fixture network's application gateway admits an Rpc")
            .serve_stream("stream_echo", move |call| {
                let registry = registry_for_handler.clone();
                let key = key_for_handler.clone();
                async move {
                    let owner = registry
                        .handler_owner(&key)
                        .ok_or_else(|| "no claim".to_string())?;
                    let client = registry
                        .client(owner)
                        .ok_or_else(|| "owner gone".to_string())?;
                    let (tx, rx) =
                        myownmesh_core::resource_mailbox::<myownmesh_core::rpc::RpcStreamItem>(
                            registry
                                .child_resources()
                                .expect("the daemon test grant scopes one stream queue"),
                        )
                        .expect("the daemon test grant funds one stream queue");
                    let close_probe = tx.clone();
                    let pending_key = PendingKey {
                        network: key.0.clone(),
                        method: key.1.clone(),
                        remote_peer: call.from.clone(),
                        remote_request_id: call.request_id.clone(),
                        class: HandlerMode::Stream,
                    };
                    let Ok(ticket) = registry.insert_exact_pending(
                        pending_key,
                        owner,
                        crate::ipc::clients::PendingInbound::Stream(tx),
                    ) else {
                        return Err("duplicate".into());
                    };
                    // Same reason as the single-shot fixture above: reported, not
                    // asserted, so the failure arrives at the caller's assertion.
                    if let Err(refusal) = client.send(ServerOut::RpcInbound {
                        network: key.0.clone(),
                        from: call.from.clone(),
                        request_id: call.request_id.clone(),
                        operation_id: ticket.operation_id(),
                        method: call.method.clone(),
                        payload: call.payload.clone(),
                        streaming: call.streaming,
                    }) {
                        return Err(format!("fixture client mailbox refused inbound: {refusal}"));
                    }
                    tokio::spawn(async move {
                        tokio::select! {
                            () = close_probe.closed() => {}
                            () = ticket.cancelled() => {}
                        }
                        drop(close_probe);
                        drop(ticket);
                    });
                    Ok(rx)
                }
            })
            .expect("the fixture network admits one streaming handler");

        let alice_did = alice_id.public_id().to_string();
        let bob_rpc_clone = bob_rpc.clone();
        let stream_handle = tokio::spawn(async move {
            bob_rpc_clone
                .call_stream(&alice_did, "stream_echo", serde_json::json!("start"))
                .await
        });

        // Pull RpcInbound to get the request_id.
        let inbound = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("inbound timeout")
            .expect("inbound recv")
            .into_parts()
            .0;
        let (network, from, request_id, operation_id, method) = match inbound {
            ServerOut::RpcInbound {
                network,
                from,
                request_id,
                operation_id,
                method,
                ..
            } => (network, from, request_id, operation_id, method),
            other => panic!("expected RpcInbound, got {other:?}"),
        };

        // Push three chunks then close.
        let pending_key = PendingKey {
            network,
            method,
            remote_peer: from,
            remote_request_id: request_id,
            class: HandlerMode::Stream,
        };
        for n in 1..=3 {
            assert!(
                registry.push_exact_stream(
                    &pending_key,
                    client.id,
                    operation_id,
                    serde_json::json!(n)
                ),
                "chunk {n} push"
            );
        }
        assert!(registry.close_exact_stream(&pending_key, client.id, operation_id, None));

        // Bob drains his receiver — three chunks then close.
        let mut bob_rx = tokio::time::timeout(Duration::from_secs(5), stream_handle)
            .await
            .expect("stream timeout")
            .expect("join")
            .expect("call_stream ok");
        for n in 1..=3 {
            let chunk = tokio::time::timeout(Duration::from_secs(5), bob_rx.recv())
                .await
                .expect("chunk timeout")
                .expect("chunk recv")
                .expect("chunk ok");
            assert_eq!(chunk, serde_json::json!(n));
        }
        // End-of-stream: receiver returns None.
        let end = tokio::time::timeout(Duration::from_secs(5), bob_rx.recv())
            .await
            .expect("end timeout");
        assert!(end.is_none(), "expected stream end, got {end:?}");
        drivers.shutdown().await;
    }

    /// Channel pub/sub: subscribe Alice's "IPC client" to a
    /// channel, Bob sends a frame on the same name, the
    /// client receives a `ChannelInbound` event with the
    /// correct payload and sender.
    #[tokio::test]
    async fn channel_inbound_round_trip_through_bridge() {
        let _fixture = crate::exclusive_connector_fixture().await;
        let (alice_state, bob_state, _alice_rpc, _bob_rpc, _alice_id, bob_id, drivers) =
            two_peer_rpc("ipc-bridge-channel").await;

        let registry = ClientRegistry::default();
        let (tx, mut rx) =
            myownmesh_core::resource_mailbox::<ServerOut>(crate::test_application_scope())
                .expect("the daemon test grant funds this fixture client's writer mailbox");
        let client = registry
            .register(tx)
            .expect("the daemon test grant funds this fixture client record");
        let net_key = "alice".to_string();
        let chan_key = "catalog".to_string();
        let key = (net_key.clone(), chan_key.clone());

        // Subscribe and spawn the pump. The pump only needs
        // the engine state to build a `Channel<Value>` —
        // bypass the JoinedNetwork facade here for the same
        // reason the bridge module itself takes
        // `&JoinedNetwork` in production.
        let was_first = registry
            .subscribe_channel(key.clone(), client.id)
            .expect("the daemon test grant funds this fixture's subscription");
        assert!(was_first);

        // Spawn a pump that mirrors `bridge::spawn_channel_pump`
        // but uses the engine state directly.
        let chan: myownmesh_core::Channel<serde_json::Value> =
            myownmesh_core::Channel::new(chan_key.clone(), alice_state.clone());
        let mut sub = chan.subscribe().expect("subscription admitted");
        let registry_for_pump = registry.clone();
        let key_for_pump = key.clone();
        tokio::spawn(async move {
            loop {
                let subscribers = registry_for_pump.channel_subscribers(&key_for_pump);
                if subscribers.is_empty() {
                    break;
                }
                let Some(next) = sub.recv().await else {
                    break;
                };
                let Ok(msg) = next else {
                    continue;
                };
                let frame = ServerOut::ChannelInbound {
                    network: key_for_pump.0.clone(),
                    from: msg.from,
                    channel: key_for_pump.1.clone(),
                    payload: msg.body,
                };
                for cid in subscribers {
                    if let Some(c) = registry_for_pump.client(cid) {
                        // The assertion this fixture exists for is on the
                        // frame arriving, so a refusal here is left to fail as
                        // the receive timeout it causes rather than being
                        // reported twice.
                        let _ = c.send(frame.clone());
                    }
                }
            }
        });

        // Bob sends to Alice on the channel.
        let bob_chan: myownmesh_core::Channel<serde_json::Value> =
            myownmesh_core::Channel::new(chan_key.clone(), bob_state.clone());
        bob_chan
            .send_to(
                _alice_id_arg(&alice_state),
                &serde_json::json!({"hello": "from bob"}),
            )
            .await
            .expect("bob send");

        let frame = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("inbound timeout")
            .expect("inbound recv")
            .into_parts()
            .0;
        match frame {
            ServerOut::ChannelInbound {
                network,
                from,
                channel,
                payload,
            } => {
                assert_eq!(network, net_key);
                assert_eq!(channel, chan_key);
                assert_eq!(from, bob_id.public_id());
                assert_eq!(payload, serde_json::json!({"hello": "from bob"}));
            }
            other => panic!("expected ChannelInbound, got {other:?}"),
        }
        drivers.shutdown().await;
    }

    fn _alice_id_arg(state: &Arc<myownmesh_core::engine::NetworkState>) -> &str {
        state.identity.public_id()
    }
}
