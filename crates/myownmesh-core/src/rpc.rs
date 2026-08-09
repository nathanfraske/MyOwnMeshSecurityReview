//! Generic request/response RPC over the mesh data channels.
//!
//! Embedders register a handler by `method` name; callers invoke
//! it on a peer via [`Rpc::call`]. Single-shot responses use a
//! `oneshot` round-trip; streaming responses use
//! `tokio::sync::mpsc` plus the
//! [`crate::protocol::rpc::RpcStreamChunkMessage`] /
//! [`crate::protocol::rpc::RpcStreamEndMessage`] frames so a
//! single request can yield many ordered chunks.
//!
//! In-flight requests are tracked per-network in a `DashMap`
//! keyed by the caller-generated request id. Each entry holds the
//! sender side of a `oneshot` (or `mpsc` for streams) so the
//! receive path can route the matching response directly without
//! a global mutex.
//!
//! A request id is a routing key, never an authority. Every entry
//! additionally names the one canonical remote device that may
//! settle it and the one response class it will accept, and the
//! only ways to reach an entry are the three bound operations on
//! [`RpcInner`]. See [`PendingOp`] for the rule those operations
//! enforce and why the binding is to a device rather than to a
//! connector installation.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use dashmap::mapref::entry::Entry;
use dashmap::DashMap;
use parking_lot::Mutex;
use tokio::sync::{mpsc, oneshot};

use crate::engine::state::NetworkState;
use crate::identity::DeviceId;
use crate::protocol::CapabilityAdvert;

#[derive(thiserror::Error, Debug)]
pub enum RpcError {
    #[error("network down")]
    NetworkDown,
    #[error("peer {0} not in active set")]
    PeerNotFound(String),
    #[error("timeout")]
    Timeout,
    #[error("handler returned error: {0}")]
    Remote(String),
    #[error("no handler registered for method '{0}'")]
    NoHandler(String),
    #[error("serialize: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("transport: {0}")]
    Transport(String),
    /// No unused request id was drawn within
    /// [`REQUEST_ID_ATTEMPTS`] tries, so the call was never sent.
    ///
    /// Purely local and, at a 96-bit id, effectively unreachable —
    /// it exists so the collision-safe insertion below has
    /// somewhere to fail *explicitly*. The alternative to naming it
    /// is displacing whichever pending operation already owns the
    /// drawn id, which strands that caller's oneshot forever and
    /// hands its reply to the wrong receiver.
    #[error("no unused request id available")]
    RequestIdUnavailable,
}

/// A single inbound RPC the local handler receives.
#[derive(Debug, Clone)]
pub struct RpcCall {
    pub from: DeviceId,
    pub request_id: String,
    pub method: String,
    pub payload: serde_json::Value,
    pub streaming: bool,
}

/// Response a handler emits for a single-shot RPC. Streaming
/// handlers use [`Rpc::serve_stream`] and emit chunks on the
/// returned sender directly.
#[derive(Debug, Clone)]
pub struct RpcResponse {
    pub body: serde_json::Value,
}

impl RpcResponse {
    pub fn from_value(body: serde_json::Value) -> Self {
        Self { body }
    }

    pub fn from_serialize<T: serde::Serialize>(body: &T) -> Result<Self, serde_json::Error> {
        Ok(Self {
            body: serde_json::to_value(body)?,
        })
    }
}

/// Boxed future returned by an RPC handler.
pub type RpcHandlerFuture =
    Pin<Box<dyn Future<Output = Result<RpcResponse, String>> + Send + 'static>>;

pub type RpcHandler = Arc<dyn Fn(RpcCall) -> RpcHandlerFuture + Send + Sync + 'static>;

/// Streaming-handler signature. Returns a stream of chunk
/// payloads; the engine wraps each into an
/// [`crate::protocol::rpc::RpcStreamChunkMessage`] and ships an
/// [`crate::protocol::rpc::RpcStreamEndMessage`] when the stream
/// closes.
pub type RpcStreamHandlerFuture = Pin<
    Box<dyn Future<Output = Result<mpsc::Receiver<serde_json::Value>, String>> + Send + 'static>,
>;

pub type RpcStreamHandler = Arc<dyn Fn(RpcCall) -> RpcStreamHandlerFuture + Send + Sync + 'static>;

/// RPC dispatcher. One per joined network; cheap to clone.
#[derive(Clone)]
pub struct Rpc {
    pub(crate) inner: Arc<RpcInner>,
}

/// Internal RPC state shared between the [`Rpc`] facade and the
/// engine's frame-dispatch path. Public so `NetworkState` can
/// stash it; embedders never construct these directly.
pub struct RpcInner {
    pub(crate) network: Arc<NetworkState>,
    pub(crate) handlers: DashMap<String, HandlerEntry>,
    /// In-flight local requests, keyed by request id.
    ///
    /// Deliberately **private**, not `pub(crate)`. The engine's
    /// inbound handlers live in a module that is not a descendant
    /// of this one, so they cannot reach the map at all and every
    /// settle they perform must go through one of the three bound
    /// operations below. A `pub(crate)` field would let an inbound
    /// arm look an entry up by request id alone, which is the
    /// escape this binding exists to close.
    pending: DashMap<String, PendingOp>,
    pub(crate) capability: Mutex<CapabilityAdvert>,
}

#[allow(clippy::large_enum_variant)]
pub enum HandlerEntry {
    Single(RpcHandler),
    Stream(RpcStreamHandler),
}

/// The response class a pending operation will accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingClass {
    Single,
    Stream,
}

/// The effect one pending operation will settle with.
///
/// Deliberately left `pub`, as it has always been. Narrowing it
/// would be public API removal that buys nothing: the authority
/// boundary is the `pending` map, which is private, together with
/// the three bound operations that are the only way to reach it.
/// Naming this type gets a caller no closer to an entry — it cannot
/// look one up, insert one, or settle one — so the visibility is
/// orthogonal to the binding rule and is left where downstream
/// found it.
pub enum PendingEntry {
    Single(oneshot::Sender<Result<RpcResponse, String>>),
    Stream(mpsc::UnboundedSender<Result<serde_json::Value, String>>),
}

impl PendingEntry {
    /// The class this effect *is*.
    ///
    /// Derived from the variant rather than stored beside it. A
    /// second field would be a second source of truth that could
    /// disagree with the effect it describes, and the disagreement
    /// would read as a class mismatch and silently strand the call.
    fn class(&self) -> PendingClass {
        match self {
            Self::Single(_) => PendingClass::Single,
            Self::Stream(_) => PendingClass::Stream,
        }
    }
}

/// One in-flight local request, bound to the exact remote that may
/// settle it and the exact response class it will accept.
///
/// **The rule.** A request id identifies an operation; it does not
/// authorize settling one. Before this binding, `pending` was keyed
/// on the id alone and every inbound response arm looked an entry
/// up by the id the *frame* carried, so any authenticated peer that
/// learned or guessed another peer's in-flight id could complete
/// that call: resolve someone else's oneshot with a body of its
/// choosing, inject chunks into someone else's stream, or end it
/// early. The admitted dispatch already knew which peer actually
/// sent the frame, and the handlers simply ignored it.
///
/// **Why a device and not an installation.** `expect_from` is the
/// canonical registry device id, which is the same value the
/// admission owner token reports, so the comparison is exact rather
/// than a normalization guess. It is deliberately *not* the
/// installation: a peer that drops and re-authenticates mid-call
/// arrives on a fresh connector under the same device id, and that
/// is a legitimate completion of a still-pending operation. The
/// selected rule is therefore: the same canonical device over a
/// freshly authenticated replacement connector **may** complete a
/// pending operation; a different device **never** may. This is the
/// one place the RPC response path diverges from `on_rpc_request`,
/// which binds to the installation because it authorizes a handler
/// run rather than resolving a call the local caller is waiting on.
struct PendingOp {
    expect_from: DeviceId,
    effect: PendingEntry,
}

impl PendingOp {
    /// Whether an inbound frame from `from`, of class `class`, is
    /// the one this operation is waiting for.
    ///
    /// Both halves must hold. A wrong source with the right class,
    /// and a right source with the wrong class, are equally not
    /// this operation's response.
    fn accepts(&self, from: &str, class: PendingClass) -> bool {
        self.expect_from == from && self.effect.class() == class
    }
}

/// How many fresh request ids one local call may draw before it
/// fails rather than displace an existing pending owner.
///
/// A bound, not a retry policy: there is no timer, no backoff and
/// no generation counter here. At 96 bits per draw a single
/// collision is already not going to happen, so the loop exists to
/// make "never displace" total rather than to make collisions
/// survivable.
const REQUEST_ID_ATTEMPTS: usize = 8;

/// The bound pending-operation surface.
///
/// These are the only ways to reach the `pending` map, and none of
/// them takes a request id on its own: every one additionally
/// requires the canonical device the inbound frame was
/// *authenticated* as, taken by the caller from the admitted
/// dispatch's owner token.
///
/// **Guard discipline.** Each operation decides and extracts under
/// one DashMap shard guard and then returns the sender to its
/// caller. None of them sends, awaits, or invokes a callback while
/// a guard is live — the engine performs the send after the
/// operation has returned and the guard is gone.
///
/// **Non-destructive refusal.** A wrong source or a wrong class is
/// not a settle attempt that fails; it is not a settle at all. The
/// predicate and the removal are the same shard-locked step, so a
/// refused frame performs zero action, zero removal and zero
/// mutation, and the rightful owner's operation is left exactly as
/// it was.
impl RpcInner {
    /// Claim `request_id` for one locally-originated operation.
    ///
    /// `Ok(request_id)` means the id was unused and is now owned.
    /// `Err(effect)` means an operation already owns it and was
    /// **not** displaced; the effect is handed back unconsumed so
    /// the caller can retry under a fresh id without having to
    /// reconstruct its channel.
    ///
    /// The occupancy test and the insert are one entry-API step, so
    /// there is no window in which the id reads as free and is then
    /// taken by a concurrent call before this one writes.
    fn claim_request_id(
        &self,
        request_id: String,
        expect_from: &str,
        effect: PendingEntry,
    ) -> Result<String, PendingEntry> {
        match self.pending.entry(request_id) {
            // Occupied: another operation owns this id. Hand the
            // effect back rather than overwrite — displacing the
            // owner would strand its caller on a oneshot that can
            // never be resolved.
            Entry::Occupied(_) => Err(effect),
            Entry::Vacant(slot) => {
                let request_id = slot.key().clone();
                // The returned reference holds the shard guard.
                // Drop it here, before returning, so no guard
                // outlives this step.
                drop(slot.insert(PendingOp {
                    expect_from: expect_from.to_string(),
                    effect,
                }));
                Ok(request_id)
            }
        }
    }

    /// Register one locally-originated pending operation under a
    /// freshly drawn id, bound to the device it was addressed to.
    ///
    /// Answers the id the operation was filed under, or `None` when
    /// [`REQUEST_ID_ATTEMPTS`] draws all collided — an explicit
    /// local failure, which the caller reports as
    /// [`RpcError::RequestIdUnavailable`] rather than displacing
    /// whoever holds the id.
    ///
    /// Crate-internal rather than private so the engine's inbound
    /// controls can file a pending operation through the exact
    /// production path they then try to settle. A test-only twin
    /// would be a second insertion that could drift from this one,
    /// and the controls would stop describing the real path.
    pub(crate) fn insert_local_request(
        &self,
        expect_from: &str,
        mut effect: PendingEntry,
    ) -> Option<String> {
        for _ in 0..REQUEST_ID_ATTEMPTS {
            match self.claim_request_id(new_request_id(), expect_from, effect) {
                Ok(request_id) => return Some(request_id),
                // The colliding draw returned the effect untouched;
                // retry with it under a new id.
                Err(returned) => effect = returned,
            }
        }
        None
    }

    /// Drop a local operation the caller is abandoning, but only if
    /// it is still the *same* operation.
    ///
    /// Used when the outbound send fails: the call will never be
    /// answered, so its entry must not linger. The removal is
    /// conditional on the binding this caller filed rather than on
    /// the id alone, so on the vanishing chance that the id was
    /// already recycled, this abandons its own operation and never
    /// a newer occupant of the same key.
    fn abandon_local_request(&self, request_id: &str, expect_from: &str, class: PendingClass) {
        let _ = self
            .pending
            .remove_if(request_id, |_, op| op.accepts(expect_from, class));
    }

    /// Take the single-response sender for `request_id`, but only
    /// if `from` is the bound device and the operation is a
    /// single-response one.
    ///
    /// Removes on success — a single response settles the call.
    /// A wrong source or a streaming operation removes nothing.
    pub(crate) fn take_single_response(
        &self,
        request_id: &str,
        from: &str,
    ) -> Option<oneshot::Sender<Result<RpcResponse, String>>> {
        let (_, op) = self
            .pending
            .remove_if(request_id, |_, op| op.accepts(from, PendingClass::Single))?;
        match op.effect {
            PendingEntry::Single(tx) => Some(tx),
            // Unreachable: the predicate above admitted only
            // `Single`, and the class is derived from this very
            // variant. Answering `None` rather than panicking keeps
            // a future change to either side non-destructive.
            PendingEntry::Stream(_) => None,
        }
    }

    /// Clone the chunk sender for `request_id`, but only if `from`
    /// is the bound device and the operation is a streaming one.
    ///
    /// Removes **nothing**: a chunk is one item of a stream that is
    /// still open, and the operation stays pending until its end
    /// frame arrives. The sender is cloned out under the shard
    /// guard and returned, so the caller sends after the guard has
    /// been released.
    pub(crate) fn stream_chunk_sender(
        &self,
        request_id: &str,
        from: &str,
    ) -> Option<mpsc::UnboundedSender<Result<serde_json::Value, String>>> {
        // The shard guard is the closure's argument, so it is
        // released when the closure returns — the clone crosses out,
        // the guard does not.
        self.pending.get(request_id).and_then(|op| {
            if !op.accepts(from, PendingClass::Stream) {
                return None;
            }
            match &op.effect {
                PendingEntry::Stream(tx) => Some(tx.clone()),
                // Unreachable: `accepts` already matched the class.
                PendingEntry::Single(_) => None,
            }
        })
    }

    /// Take the stream sender for `request_id`, but only if `from`
    /// is the bound device and the operation is a streaming one.
    ///
    /// Removes on success — an end frame closes the stream. A wrong
    /// source or a single-response operation removes nothing, so a
    /// foreign peer cannot cut another peer's stream short.
    pub(crate) fn take_stream_end(
        &self,
        request_id: &str,
        from: &str,
    ) -> Option<mpsc::UnboundedSender<Result<serde_json::Value, String>>> {
        let (_, op) = self
            .pending
            .remove_if(request_id, |_, op| op.accepts(from, PendingClass::Stream))?;
        match op.effect {
            // Unreachable for the same reason as in
            // `take_single_response`, and refused the same way.
            PendingEntry::Single(_) => None,
            PendingEntry::Stream(tx) => Some(tx),
        }
    }
}

impl Rpc {
    pub(crate) fn new(network: Arc<NetworkState>) -> Self {
        Self {
            inner: Arc::new(RpcInner {
                network,
                handlers: DashMap::new(),
                pending: DashMap::new(),
                capability: Mutex::new(CapabilityAdvert::default()),
            }),
        }
    }

    /// Attach (or look up) the RPC dispatcher for a network. Use
    /// this when you've spun up the engine directly via
    /// [`crate::engine::spawn_network`] and want to register
    /// handlers or make calls. The [`crate::JoinedNetwork`] facade
    /// attaches automatically — this is the lower-level
    /// equivalent.
    ///
    /// Idempotent: subsequent calls return a fresh `Rpc` handle
    /// over the same underlying state, so previously-registered
    /// handlers remain in effect.
    pub fn attach(network: &Arc<NetworkState>) -> Self {
        if let Some(existing) = network.rpc.read().clone() {
            return Self { inner: existing };
        }
        let rpc = Self::new(network.clone());
        *network.rpc.write() = Some(rpc.inner.clone());
        rpc
    }

    /// Register a single-shot handler under `method`. Replaces any
    /// previous handler for the same name.
    pub fn serve<F, Fut>(&self, method: &str, handler: F)
    where
        F: Fn(RpcCall) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<RpcResponse, String>> + Send + 'static,
    {
        let h: RpcHandler = Arc::new(move |call| {
            let fut = handler(call);
            Box::pin(fut)
        });
        self.inner
            .handlers
            .insert(method.to_string(), HandlerEntry::Single(h));
    }

    /// Register a streaming handler under `method`. The handler
    /// returns an `mpsc::Receiver<Value>`; each value becomes one
    /// `rpc_stream_chunk` on the wire and a final
    /// `rpc_stream_end` is sent when the receiver closes.
    pub fn serve_stream<F, Fut>(&self, method: &str, handler: F)
    where
        F: Fn(RpcCall) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<mpsc::Receiver<serde_json::Value>, String>> + Send + 'static,
    {
        let h: RpcStreamHandler = Arc::new(move |call| {
            let fut = handler(call);
            Box::pin(fut)
        });
        self.inner
            .handlers
            .insert(method.to_string(), HandlerEntry::Stream(h));
    }

    /// Drop the handler registered under `method`. Idempotent —
    /// no-op if nothing was registered.
    pub fn forget(&self, method: &str) {
        self.inner.handlers.remove(method);
    }

    /// Single-shot RPC call.
    pub async fn call(
        &self,
        peer: &str,
        method: &str,
        payload: serde_json::Value,
    ) -> Result<RpcResponse, RpcError> {
        let (tx, rx) = oneshot::channel();
        // Bound to `peer` at insertion: only that canonical device
        // may resolve this oneshot, and only with a single
        // response. `send_to_peer` resolves the destination by
        // exact registry key, so a `peer` that is not a canonical
        // device id fails the send below rather than filing an
        // entry no inbound frame could ever match.
        let request_id = self
            .inner
            .insert_local_request(peer, PendingEntry::Single(tx))
            .ok_or(RpcError::RequestIdUnavailable)?;
        let frame = crate::protocol::RpcRequestMessage {
            request_id: request_id.clone(),
            method: method.to_string(),
            payload,
            streaming: false,
        };
        let send_res = self
            .inner
            .network
            .send_rpc_request(peer, frame)
            .await
            .map_err(map_engine_err);
        if let Err(e) = send_res {
            self.inner
                .abandon_local_request(&request_id, peer, PendingClass::Single);
            return Err(e);
        }
        match rx.await {
            Ok(Ok(resp)) => Ok(resp),
            Ok(Err(msg)) => Err(RpcError::Remote(msg)),
            Err(_) => Err(RpcError::NetworkDown),
        }
    }

    /// Streaming RPC call. The returned receiver yields each chunk
    /// as it arrives; a `None` signals end-of-stream.
    pub async fn call_stream(
        &self,
        peer: &str,
        method: &str,
        payload: serde_json::Value,
    ) -> Result<mpsc::UnboundedReceiver<Result<serde_json::Value, String>>, RpcError> {
        let (tx, rx) = mpsc::unbounded_channel();
        // Bound exactly as the single-shot path above, with the
        // stream class: only `peer` may feed this receiver, and
        // only through chunk and end frames.
        let request_id = self
            .inner
            .insert_local_request(peer, PendingEntry::Stream(tx))
            .ok_or(RpcError::RequestIdUnavailable)?;
        let frame = crate::protocol::RpcRequestMessage {
            request_id: request_id.clone(),
            method: method.to_string(),
            payload,
            streaming: true,
        };
        let send_res = self
            .inner
            .network
            .send_rpc_request(peer, frame)
            .await
            .map_err(map_engine_err);
        if let Err(e) = send_res {
            self.inner
                .abandon_local_request(&request_id, peer, PendingClass::Stream);
            return Err(e);
        }
        Ok(rx)
    }

    /// Advertise capabilities to the mesh. Sent in every outgoing
    /// `hello` and re-broadcast via
    /// [`crate::protocol::CapabilitiesUpdateMessage`] on change.
    pub fn advertise(&self, caps: CapabilityAdvert) {
        *self.inner.capability.lock() = caps.clone();
        // Fire and forget — the engine's broadcast picks up the
        // update on its next tick.
        let net = self.inner.network.clone();
        tokio::spawn(async move {
            let _ = net.broadcast_capabilities(caps).await;
        });
    }

    /// Snapshot of the currently-advertised capabilities.
    pub fn capabilities(&self) -> CapabilityAdvert {
        self.inner.capability.lock().clone()
    }

    #[allow(dead_code)]
    pub(crate) fn handler_entries(&self) -> &DashMap<String, HandlerEntry> {
        &self.inner.handlers
    }

    // There is deliberately no `take_pending(request_id)` here.
    // One existed, unused and `#[allow(dead_code)]`, and it was the
    // unbound settle in its purest form: a request id in, someone's
    // pending effect out, with no question asked about who was
    // sending or what class they were sending. Reaching a pending
    // operation now requires naming the authenticated device too,
    // which that signature had no way to express.

    /// Track which handlers are currently registered. Used by the
    /// engine to surface "this peer doesn't speak method X" without
    /// shipping a full advertisement on every call.
    pub fn registered_methods(&self) -> Vec<String> {
        self.inner
            .handlers
            .iter()
            .map(|e| e.key().clone())
            .collect()
    }
}

fn new_request_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 12] = rng.gen();
    data_encoding::BASE32_NOPAD.encode(&bytes).to_lowercase()
}

fn map_engine_err(e: crate::error::Error) -> RpcError {
    use crate::error::Error as E;
    match e {
        E::Network(msg) if msg.contains("not found") => RpcError::PeerNotFound(msg),
        E::Transport(msg) => RpcError::Transport(msg),
        other => RpcError::Transport(other.to_string()),
    }
}

/// Build a flat snapshot of currently-registered method names —
/// used by the engine to populate hello.capabilities.
pub fn methods_snapshot(rpc: &Rpc) -> HashMap<String, ()> {
    rpc.inner
        .handlers
        .iter()
        .map(|e| (e.key().clone(), ()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Local insertion never displaces an existing pending owner.
    ///
    /// The unsafe shape this rules out is `pending.insert(id, ..)`,
    /// which overwrites silently: the displaced caller's oneshot is
    /// dropped, so it resolves to `NetworkDown` for a request that
    /// was in fact sent and may well be answered, and the reply that
    /// does arrive is then handed to the wrong receiver.
    ///
    /// Production draws the id randomly. The control supplies it
    /// directly, so the collision is certain rather than
    /// astronomically improbable, and it drives the same
    /// `claim_request_id` step the retry loop drives.
    #[tokio::test]
    async fn v4_arc04f2_request_id_collision_never_displaces_the_existing_pending_owner() {
        let state = crate::engine::build_test_state("arc04f2-request-id-collision");
        let rpc = Rpc::attach(&state);

        // The incumbent: one pending single-response call bound to A.
        let (incumbent_tx, incumbent_rx) = oneshot::channel();
        let request_id = rpc
            .inner
            .insert_local_request("device-a", PendingEntry::Single(incumbent_tx))
            .expect("a fresh id is available");

        // A second local call collides on that exact id.
        let (challenger_tx, mut challenger_rx) = mpsc::unbounded_channel();
        let returned = rpc
            .inner
            .claim_request_id(
                request_id.clone(),
                "device-b",
                PendingEntry::Stream(challenger_tx),
            )
            .expect_err("an already-owned request id is never claimed twice");
        assert!(
            matches!(returned, PendingEntry::Stream(_)),
            "the colliding call gets its own effect back unconsumed, so the retry \
             loop can re-file it under a fresh id"
        );

        // The incumbent still owns the id, under its original
        // binding and class.
        let settle = rpc
            .inner
            .take_single_response(&request_id, "device-a")
            .expect("the incumbent was not displaced by the collision");
        assert!(settle
            .send(Ok(RpcResponse::from_value(serde_json::json!("mine"))))
            .is_ok());
        assert!(
            matches!(incumbent_rx.await, Ok(Ok(response)) if response.body == serde_json::json!("mine")),
            "and its own caller receives its own response"
        );
        assert!(
            challenger_rx.try_recv().is_err(),
            "the colliding call was never filed, so nothing is routed to it"
        );
    }

    /// The bound device survives a collision unchanged: a colliding
    /// draw must not repoint an existing entry at the new caller's
    /// peer, which would let that peer settle the incumbent's call.
    #[tokio::test]
    async fn v4_arc04f2_a_colliding_draw_does_not_rebind_the_incumbents_device() {
        let state = crate::engine::build_test_state("arc04f2-collision-rebind");
        let rpc = Rpc::attach(&state);

        let (incumbent_tx, _incumbent_rx) = oneshot::channel();
        let request_id = rpc
            .inner
            .insert_local_request("device-a", PendingEntry::Single(incumbent_tx))
            .expect("a fresh id is available");

        let (challenger_tx, _challenger_rx) = oneshot::channel();
        let _ = rpc.inner.claim_request_id(
            request_id.clone(),
            "device-b",
            PendingEntry::Single(challenger_tx),
        );

        assert!(
            rpc.inner
                .take_single_response(&request_id, "device-b")
                .is_none(),
            "the colliding caller's device cannot settle the entry it failed to claim"
        );
        assert!(
            rpc.inner
                .take_single_response(&request_id, "device-a")
                .is_some(),
            "and the incumbent's binding is exactly what it was"
        );
    }
}
