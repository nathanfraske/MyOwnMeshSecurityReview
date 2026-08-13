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
//! - **Channel pumps** are owned by a route, not by a subscriber count. The
//!   first subscribe creates the route and installs the pump; the last
//!   unsubscribe retires the route, which cancels the pump and *joins* it, so
//!   the unsubscribe returns only once the task has actually stopped.
//!
//!   It used to be left to notice: the task re-read the subscriber set each
//!   iteration and exited when it found it empty. On a channel nobody is
//!   publishing to there is no next iteration, so the pump was immortal in
//!   exactly the case where it was useless — and `serve`, which waits on every
//!   accepted task, would have waited for it forever.

use std::sync::Arc;

use myownmesh_core::application_gateway::GatewayRefusal;
use myownmesh_core::{JoinedNetwork, ResourceMailboxAdmissionError};
use serde_json::Value;
use tracing::{debug, warn};

use super::clients::{
    ClaimKey, ClientRegistry, HandlerGeneration, HandlerMode, IpcAdmissionError, PendingInbound,
    PendingKey, WeakClientRegistry,
};
use super::wire::ServerOut;
use myownmesh_core::rpc::PreparedRegistration;
use myownmesh_core::{ResourceClaim, ResourceClass};

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
/// What one synthetic handler closure retains, funded before it exists.
///
/// The two method-name buffers of the [`ClaimKey`] it captures. The
/// [`WeakClientRegistry`] beside them is a pair of pointers into an allocation
/// that already exists and is already funded, and the generation and class are
/// scalars — those live in the callable's own layout, which core measures and
/// funds itself.
///
/// Declared rather than left opaque so the charge is the real one: an opaque
/// residual would say "this closure retains something" without saying how much,
/// and what it retains is sized by a name the client chose.
fn handler_capture_claim(key: &ClaimKey) -> Result<ResourceClaim, GatewayRefusal> {
    let bytes = key
        .0
        .len()
        .checked_add(key.1.len())
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(GatewayRefusal::Malformed)?;
    ResourceClaim::try_from_entries([
        (ResourceClass::AccountedMemoryBytes, bytes),
        (ResourceClass::OpaqueDependencyResidual, 2),
    ])
    .map_err(|_| GatewayRefusal::Malformed)
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
pub fn prepare_single_handler(
    rpc: &myownmesh_core::rpc::Rpc,
    key: ClaimKey,
    generation: HandlerGeneration,
    registry: &ClientRegistry,
) -> Result<PreparedRegistration, GatewayRefusal> {
    let captures = handler_capture_claim(&key)?;
    let method = key.1.clone();
    // Weak, always. See [`WeakClientRegistry`]: a network owns its handler
    // entries and an entry owns this closure, so a strong clone here would make
    // the network an owner of the daemon's whole client registry.
    let registry = registry.downgrade();
    rpc.prepare_serve_with_retention_claim(&method, captures, move |call| {
        single_handler_call(registry.clone(), key.clone(), generation, call)
    })
}

/// One inbound single-shot call, as the installed closure runs it.
///
/// A named function rather than an anonymous body, and the difference is what
/// can be *observed*. Core clones this closure per call, so a call that began
/// under one installation can still be running when another replaces it — and
/// the whole exactness argument is about what that in-flight clone does next.
/// Anonymous, there is no way for a control to hold one and drive it across a
/// displacement; named, a control builds a clone carrying the same generation
/// and runs the same code core would.
async fn single_handler_call(
    registry: WeakClientRegistry,
    key: ClaimKey,
    generation: HandlerGeneration,
    call: myownmesh_core::rpc::RpcCall,
) -> Result<myownmesh_core::rpc::RpcResponse, String> {
    let Some(registry) = registry.upgrade() else {
        return Err("the control runtime that installed this handler is gone".to_string());
    };
    // This closure's own generation and class, not the method name. A
    // clone of an *earlier* installation can still be in flight while a
    // successor holds the name, and asking by name would hand it the
    // successor's owner -- dispatching a call in one client's shape to
    // another client that never agreed to serve it.
    let Some(owner_id) = registry.handler_owner_for(&key, generation, HandlerMode::Single) else {
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
    let ticket =
        match registry.insert_exact_pending(pending_key, owner_id, PendingInbound::Single(tx)) {
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

/// Install (or re-install) a synthetic streaming RPC handler.
/// Mirrors [`prepare_single_handler`] but stashes a resource-funded
/// `ResourceMailboxSender<RpcStreamItem>` in the pending table instead
/// of a `oneshot`; chunks land via `RpcStreamChunk`, and
/// `RpcStreamEnd` terminates the stream with an explicit
/// `RpcStreamItem::End` carrying clean completion or the
/// client's error.
///
/// Fallible for the same reason [`prepare_single_handler`] is.
pub fn prepare_stream_handler(
    rpc: &myownmesh_core::rpc::Rpc,
    key: ClaimKey,
    generation: HandlerGeneration,
    registry: &ClientRegistry,
) -> Result<PreparedRegistration, GatewayRefusal> {
    let captures = handler_capture_claim(&key)?;
    let method = key.1.clone();
    let registry = registry.downgrade();
    rpc.prepare_serve_stream_with_retention_claim(&method, captures, move |call| {
        stream_handler_call(registry.clone(), key.clone(), generation, call)
    })
}

/// One inbound streaming call, as the installed closure runs it. Named for the
/// same reason [`single_handler_call`] is.
async fn stream_handler_call(
    registry: WeakClientRegistry,
    key: ClaimKey,
    generation: HandlerGeneration,
    call: myownmesh_core::rpc::RpcCall,
) -> Result<myownmesh_core::ResourceMailboxReceiver<myownmesh_core::rpc::RpcStreamItem>, String> {
    let Some(registry) = registry.upgrade() else {
        return Err("the control runtime that installed this handler is gone".to_string());
    };
    let Some(owner_id) = registry.handler_owner_for(&key, generation, HandlerMode::Stream) else {
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
    let (tx, rx) =
        match myownmesh_core::resource_mailbox::<myownmesh_core::rpc::RpcStreamItem>(resources) {
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
    let ticket =
        match registry.insert_exact_pending(pending_key, owner_id, PendingInbound::Stream(tx)) {
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
    let watchdog_registry = registry.clone();
    tokio::spawn(async move {
        let _task = task;
        tokio::select! {
            () = close_probe.closed() => {}
            () = ticket.cancelled() => {}
            // Third arm because `serve` waits for this task, and the
            // other two are both events a peer controls. A stream nobody
            // ever closes would otherwise hold the daemon open for as
            // long as the peer chose. Every arm below drops the ticket
            // and the probe, so shutting down settles the pending entry
            // exactly as a close would.
            () = watchdog_registry.closing() => {}
        }
        drop(close_probe);
        drop(ticket);
    });
    Ok(rx)
}

/// Spawn the per-channel fan-out task for an IPC subscription on
/// `(network_id, channel)`. The caller spawns this only when
/// `subscribe_channel(...)` hands it a [`ChannelJoin::Install`],
/// and publishes the result -- pump or refusal -- back into that
/// exact generation through `finish_channel_install`. On the last
/// `unsubscribe_channel(...)`, the [`RetiredRoute`] that comes
/// back retires this task through the handles returned here.
///
/// [`ChannelJoin::Install`]: crate::ipc::ChannelJoin::Install
/// [`RetiredRoute`]: crate::ipc::RetiredRoute
///
/// The task lives by polling the channel's broadcast receiver,
/// raced against its own cancellation and the control runtime's
/// shutdown. It exits on any of the three: retirement, shutdown,
/// or the network being torn down under it.
/// Subscription is a resource admission and can be refused, so this reports
/// rather than starts a pump that would never receive anything. The caller
/// answers the requesting client with the refusal instead of recording a
/// subscription the daemon does not actually hold.
pub(crate) fn spawn_channel_pump(
    network: &JoinedNetwork,
    network_key: String,
    channel_name: String,
    registry: ClientRegistry,
) -> std::result::Result<
    (
        Arc<crate::ipc::RouteCancellation>,
        tokio::task::JoinHandle<()>,
    ),
    ChannelPumpError,
> {
    let channel = network.channel::<Value>(&channel_name);
    let mut sub = channel.subscribe().map_err(ChannelPumpError::Subscribe)?;
    // Funded before the pump exists, and for the same reason the subscription
    // is checked first: this reports rather than starting a pump the daemon
    // cannot account for. Both refusals reach the caller before any subscriber
    // state is recorded, so there is nothing to unwind here — the caller undoes
    // its own registry entry and tells the client.
    // The pump keeps its own copies of both coordinates for its whole life —
    // it re-reads them on every frame it forwards and on every log line — so
    // the admission that funds the task funds those bytes too. A bare
    // `lease_task` prices one worker obligation and one bookkeeping object and
    // would call two client-chosen strings free. Checked before the clones
    // exist, on the same pattern as `RpcCallStream`'s request id.
    let captured =
        network_key
            .len()
            .checked_add(channel_name.len())
            .ok_or(ChannelPumpError::Task(IpcAdmissionError::Claim(
                myownmesh_core::ResourceClaimArithmeticError::Overflow {
                    dimension: myownmesh_core::ResourceClass::AccountedMemoryBytes,
                },
            )))?;
    let task = registry
        .lease_task_retaining(captured)
        .map_err(ChannelPumpError::Task)?;
    let key = (network_key.clone(), channel_name.clone());
    // Handed back to the route, which is the only thing entitled to stop this
    // task. Retiring the route cancels and *joins* through these two, so the
    // pump's end is observed rather than assumed — the previous shape had no
    // way to stop a pump at all and waited for it to notice an empty set on its
    // next frame, which on a quiet channel is never.
    let cancel = registry
        .route_cancellation()
        .map_err(ChannelPumpError::Task)?;
    let cancelled = Arc::clone(&cancel);
    let join = tokio::spawn(async move {
        let _task = task;
        loop {
            // Raced against the shutdown signal, biased to it. Without this the
            // pump's only exits are the channel closing or its last subscriber
            // leaving, and neither is something the daemon can bring about while
            // shutting down -- so `serve`, which waits for every accepted task,
            // would wait for a receive on a quiet channel indefinitely.
            let next = tokio::select! {
                biased;
                () = cancelled.cancelled() => {
                    debug!(
                        network = %key.0,
                        channel = %key.1,
                        "channel pump exiting (route retired)"
                    );
                    break;
                }
                () = registry.closing() => {
                    debug!(
                        network = %key.0,
                        channel = %key.1,
                        "channel pump exiting (control runtime closing)"
                    );
                    break;
                }
                next = sub.recv() => next,
            };
            let Some(next) = next else {
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
                    // Visited in place rather than over a snapshot. The
                    // previous shape allocated a `Vec<ClientId>` per frame,
                    // sized by the subscriber count, and nothing funded it.
                    let live = registry.for_each_subscriber(&key, |client| {
                        {
                            let client_id = client.id;
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
                    });
                    if !live {
                        debug!(
                            network = %key.0,
                            channel = %key.1,
                            "channel pump exiting (route gone)"
                        );
                        break;
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
    Ok((cancel, join))
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

/// Fund whichever handler shape matches the requested mode, without publishing
/// it.
///
/// The first half of one transaction: every acquisition happens here, and what
/// comes back publishes only if the daemon's own claim succeeds under the same
/// lock. Nothing is installed on the network by calling this, so a caller that
/// drops the result has installed nothing -- which is the difference between
/// this and the `install_*` pair it replaced, where a refused claim left an
/// orphan handler serving a client that was told it had failed.
///
/// Takes the dispatcher rather than the `JoinedNetwork` it hangs off, because
/// the dispatcher is all any of this needs. Narrowing it is what lets a control
/// drive the real seam — `Rpc::attach` gives a genuine dispatcher over one
/// engine, where reaching a `JoinedNetwork` would mean standing up the whole
/// join path to observe a transaction that has nothing to do with peers.
pub fn prepare_handler_for_mode(
    rpc: &myownmesh_core::rpc::Rpc,
    key: ClaimKey,
    generation: HandlerGeneration,
    mode: HandlerMode,
    registry: &ClientRegistry,
) -> Result<PreparedRegistration, GatewayRefusal> {
    match mode {
        HandlerMode::Single => prepare_single_handler(rpc, key, generation, registry),
        HandlerMode::Stream => prepare_stream_handler(rpc, key, generation, registry),
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

    // The three production items the F3 control drives directly. Named rather
    // than glob-imported so it is visible that the control runs the same
    // handler body core runs, not a copy of it.
    use super::{prepare_handler_for_mode, single_handler_call, stream_handler_call};
    use crate::ipc::clients::{ClientRegistry, HandlerMode, PendingKey, RegistrationError};
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

    /// One engine and its real dispatcher, for the controls that need core to
    /// actually publish something rather than a stand-in.
    ///
    /// No peer and no approval wait: the transaction under test is entirely
    /// local — funding a registration, claiming a method, publishing both under
    /// one lock — and a second engine would only add a connector budget and a
    /// handshake to observe none of it. The exclusive fixture is still taken,
    /// because building a `Transport` at all draws on the one process-global
    /// connector budget every family in this binary shares.
    async fn one_engine_rpc(
        wire_id: &str,
    ) -> (
        Arc<myownmesh_core::engine::NetworkState>,
        myownmesh_core::rpc::Rpc,
        tokio::task::JoinHandle<()>,
    ) {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::env::set_var("MYOWNMESH_HOME", tmp.path());
        std::mem::forget(tmp); // leak — test scope only
        let (state, driver) = spawn_network(
            fresh_network("solo", wire_id),
            Arc::new(Identity::ephemeral()),
            test_transport(),
        )
        .await
        .expect("the solo engine starts");
        let rpc = myownmesh_core::rpc::Rpc::attach(&state)
            .expect("the live gateway admits its RPC owner");
        (state, rpc, driver)
    }

    /// One inbound call, in flight across a displacement, through core's real
    /// two-phase registration.
    ///
    /// The registry controls prove the *predicate* — that an old generation
    /// resolves to nobody. This one proves the behaviour that predicate exists
    /// to produce, by running the handler body core runs, on a call that is
    /// genuinely parked mid-flight when the method changes hands.
    ///
    /// The sequence, and why each step is there:
    ///
    /// 1. `A` publishes single-shot through the production path: a real
    ///    `PreparedRegistration`, a real `commit_with` running the daemon's
    ///    claim under core's handlers lock, a real `OwnedMethodRegistration`.
    /// 2. A newcomer the daemon refuses publishes nothing, and `A` keeps its
    ///    owner, its class *and* its generation. Under the old
    ///    install-then-claim order the incumbent's handler had already been
    ///    overwritten before the refusal was discovered.
    /// 3. A call is started under `A`'s generation and parks at the real park
    ///    point — awaiting `A`'s `RpcRespond`. The barrier is `A`'s own mailbox
    ///    receiving the inbound frame, which cannot happen until the call has
    ///    resolved its owner, filed its pending entry and handed the frame over.
    ///    No timer decides anything.
    /// 4. `B` takes the method as a stream, for real, while that call is parked.
    /// 5. The parked call comes back *displaced*, not answered by `B`. This is
    ///    the observation the predicate alone cannot make: the in-flight call is
    ///    settled truthfully by the displacement rather than left to resolve
    ///    against whoever holds the name when it wakes.
    /// 6. `B` was never told about `A`'s call — its mailbox is empty. A stale
    ///    clone re-run afterwards refuses truthfully and still tells `B`
    ///    nothing.
    /// 7. The installation that *is* published reaches `B`, in the stream shape
    ///    it claimed.
    ///
    /// What this does not observe is core cloning the closure itself: the body
    /// is invoked directly, one call away from where core invokes it, because
    /// reaching core's own dispatch would need a second engine and a peer
    /// handshake to watch a transaction that has nothing to do with peers. The
    /// closure passed to core is this same function and nothing else.
    #[tokio::test]
    async fn v4_f3_daemon_an_in_flight_call_cannot_follow_the_method_to_its_new_owner() {
        let _fixture = crate::exclusive_connector_fixture().await;
        let (state, rpc, driver) = one_engine_rpc("f3-exact").await;
        let registry = ClientRegistry::default();
        let (a, mut a_rx) = fresh_ipc_client(&registry);
        let (b, mut b_rx) = fresh_ipc_client(&registry);
        let (gone, _gone_rx) = fresh_ipc_client(&registry);
        let key = ("solo".to_string(), "infer".to_string());

        // ---- 1. A claims it single-shot, through the production path -------
        let first = registry
            .next_handler_generation()
            .expect("a fresh daemon has generations left");
        let prepared =
            prepare_handler_for_mode(&rpc, key.clone(), first, HandlerMode::Single, &registry)
                .expect("the live gateway funds one synthetic handler");
        let displaced = registry
            .claim_method_committing(key.clone(), a.id, HandlerMode::Single, first, prepared)
            .expect("the claim and the handler publish together");
        assert!(displaced.is_none(), "there was no incumbent to displace");

        // ---- 2. a newcomer the daemon refuses changes nothing --------------
        let gone_id = gone.id;
        drop(registry.unregister(gone_id).expect("registered client"));
        let refused = registry
            .next_handler_generation()
            .expect("a fresh daemon has generations left");
        let prepared =
            prepare_handler_for_mode(&rpc, key.clone(), refused, HandlerMode::Stream, &registry)
                .expect("funding a registration is not publishing it");
        let refusal = registry.claim_method_committing(
            key.clone(),
            gone_id,
            HandlerMode::Stream,
            refused,
            prepared,
        );
        assert!(
            matches!(refusal, Err(RegistrationError::ClientGone)),
            "the refusal names the real cause"
        );
        assert_eq!(
            registry.handler_owner_for(&key, first, HandlerMode::Single),
            Some(a.id),
            "core published nothing, so the incumbent's own generation still routes"
        );
        assert_eq!(
            registry.handler_mode(&key),
            Some(HandlerMode::Single),
            "in the class it claimed, not the one that was refused"
        );
        assert!(
            a.holds_method_for_test(&key),
            "the incumbent's own record of its claim is intact"
        );

        // ---- 3. park a real call under A's generation ----------------------
        let parked = tokio::spawn(single_handler_call(
            registry.downgrade(),
            key.clone(),
            first,
            fixture_call("peer-one", "req-one", false),
        ));
        // The barrier, and it is a state and not a duration: this frame does not
        // exist until the call has resolved its owner, filed its pending entry
        // and handed the frame to A. Past it, the call is parked on A's
        // response and nothing else.
        let inbound = a_rx
            .recv()
            .await
            .expect("A is given the inbound call it owns")
            .into_parts()
            .0;
        assert!(
            matches!(inbound, ServerOut::RpcInbound { ref request_id, .. } if request_id == "req-one"),
            "and it is the call this control started"
        );

        // ---- 4. B takes the method as a stream, mid-flight ------------------
        let second = registry
            .next_handler_generation()
            .expect("a fresh daemon has generations left");
        let prepared =
            prepare_handler_for_mode(&rpc, key.clone(), second, HandlerMode::Stream, &registry)
                .expect("the live gateway funds the displacing handler");
        let displaced = registry
            .claim_method_committing(key.clone(), b.id, HandlerMode::Stream, second, prepared)
            .expect("the displacing claim and its handler publish together");
        assert_eq!(displaced, Some(a.id), "and it says whose method it took");

        // ---- 5. the parked call is displaced, not answered by B -------------
        let outcome = parked.await.expect("the parked call's task completes");
        let reason = outcome.expect_err("a displaced call does not return a response");
        assert!(
            reason.contains("displaced"),
            "the peer is told the handler was displaced, not that it timed out: {reason}"
        );

        // ---- 6. B never heard about A's call, and a stale clone gets nowhere
        assert!(
            b_rx.try_recv().is_none(),
            "the displacing client was never handed a call that began under A"
        );
        let stale = single_handler_call(
            registry.downgrade(),
            key.clone(),
            first,
            fixture_call("peer-two", "req-two", false),
        )
        .await
        .expect_err("a clone of A's installation cannot route once A is displaced");
        assert!(
            stale.contains("no IPC client holds method"),
            "and it says so truthfully rather than reaching the newcomer: {stale}"
        );
        assert!(
            b_rx.try_recv().is_none(),
            "still nothing: a stale generation cannot reach B by any path"
        );

        // ---- 7. the published installation reaches B, in its own shape ------
        let stream = stream_handler_call(
            registry.downgrade(),
            key.clone(),
            second,
            fixture_call("peer-three", "req-three", true),
        )
        .await
        .expect("the installation core published routes to its owner");
        let inbound = b_rx
            .recv()
            .await
            .expect("B is given the streaming call it owns")
            .into_parts()
            .0;
        match inbound {
            ServerOut::RpcInbound {
                request_id,
                streaming,
                ..
            } => {
                assert_eq!(request_id, "req-three");
                assert!(streaming, "and in the stream shape B claimed it as");
            }
            other => panic!("B was given something other than its inbound call: {other:?}"),
        }
        drop(stream);

        state.request_shutdown();
        let _ = driver.await;
    }

    /// One inbound call, as a peer would have made it.
    fn fixture_call(from: &str, request_id: &str, streaming: bool) -> myownmesh_core::rpc::RpcCall {
        myownmesh_core::rpc::RpcCall {
            from: from.to_string(),
            request_id: request_id.to_string(),
            method: "infer".to_string(),
            payload: serde_json::json!({ "q": 1 }),
            streaming,
        }
    }

    /// One IPC client with a funded writer mailbox.
    fn fresh_ipc_client(
        registry: &ClientRegistry,
    ) -> (
        Arc<crate::ipc::ClientHandle>,
        myownmesh_core::ResourceMailboxReceiver<ServerOut>,
    ) {
        let (tx, rx) = myownmesh_core::resource_mailbox(crate::test_application_scope())
            .expect("the daemon test grant funds one client writer mailbox");
        let handle = registry
            .register(tx)
            .expect("the daemon test grant funds one client record");
        (handle, rx)
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

        // Inlined rather than calling `prepare_single_handler`,
        // because this fixture drives the *routing* half of the
        // handler against two live engines and does not need the
        // claim transaction that production wraps it in. The
        // control that does drive that transaction against a real
        // registration is
        // `v4_f3_daemon_an_in_flight_call_cannot_follow_the_method_to_its_new_owner`.
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
        // the engine state to build a `Channel<Value>`, so the
        // `JoinedNetwork` facade `spawn_channel_pump` takes in
        // production is bypassed here.
        let joined = registry
            .subscribe_channel(key.clone(), client.id)
            .expect("the daemon test grant funds this fixture's subscription");
        let crate::ipc::ChannelJoin::Install(installing) = joined else {
            panic!("the fixture's first subscriber owns the install")
        };
        // This fixture is its own installer, so it publishes its own outcome
        // into its own generation: without this the route stays `Installing`
        // and `for_each_subscriber` below would be visiting members of a route
        // nothing had made live.
        assert!(registry
            .finish_channel_install(&key, &installing, None)
            .is_none());
        let joined = registry
            .subscribe_channel(key.clone(), client.id)
            .expect("re-recording the fixture's own subscription");
        assert!(matches!(joined, crate::ipc::ChannelJoin::Install(_)));

        // Spawn a pump that mirrors `bridge::spawn_channel_pump`
        // but uses the engine state directly.
        let chan: myownmesh_core::Channel<serde_json::Value> =
            myownmesh_core::Channel::new(chan_key.clone(), alice_state.clone());
        let mut sub = chan.subscribe().expect("subscription admitted");
        let registry_for_pump = registry.clone();
        let key_for_pump = key.clone();
        tokio::spawn(async move {
            loop {
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
                // The assertion this fixture exists for is on the frame
                // arriving, so a refusal here is left to fail as the receive
                // timeout it causes rather than being reported twice.
                let live = registry_for_pump.for_each_subscriber(&key_for_pump, |c| {
                    let _ = c.send(frame.clone());
                });
                if !live {
                    break;
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
