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
//!
//! Locally the same holds one level finer. Filing an operation also
//! hands its caller a process-local identity for the exact entry it
//! filed, and a caller withdrawing an entry after a failed send
//! matches on that identity rather than on the key and binding,
//! which a recycled id could reproduce exactly. Nothing inbound is
//! ever matched against it.

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
    /// The one request id this call drew was already owned by a
    /// pending operation, so the call was never sent.
    ///
    /// Purely local and, at a 96-bit id, effectively unreachable —
    /// it exists so the collision-safe insertion below has
    /// somewhere to fail *explicitly*. The alternative to naming it
    /// is displacing whichever pending operation already owns the
    /// drawn id, which strands that caller's oneshot forever and
    /// hands its reply to the wrong receiver.
    ///
    /// One draw, no redraw. The bounded retry this replaces existed
    /// only to make "never displace" total, which a single claim
    /// that fails explicitly already is.
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
///
/// **Identity is not the binding.** `id` names *this* entry among
/// every entry this process ever filed; `expect_from` and `effect`
/// say who may settle it and with what. They answer different
/// questions and are never substituted for one another: inbound
/// settling matches the binding and never the identity, because a
/// frame cannot know an identity and must not have to; local
/// withdrawal matches the identity and never the binding, because
/// the binding names a class of operations and a caller abandoning
/// its own send failure must reach exactly one.
struct PendingOp {
    id: PendingOpId,
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

/// The process-local identity of one filed pending operation.
///
/// A private marker allocation, never a number. Identity *is* the
/// allocation: two of these name the same operation exactly when
/// both are clones of the one minted for it, which [`Self::names`]
/// decides with [`Arc::ptr_eq`]. Every comparison holds a strong
/// reference on both sides for its whole duration, so both
/// allocations are live, and a live allocation's address is never
/// also another live allocation's — a stale owner still holding its
/// clone is precisely what makes its identity unreusable.
///
/// **Not an authority, not a credential, not a generation.** There
/// is no counter to advance and nothing ordered to compare; the
/// marker is a zero-sized private type no other module can name or
/// construct; and it is never serialized, sent, advertised, or
/// derived from anything a remote supplies. No inbound path reads
/// it. It grants nothing to anyone shown it — nobody outside this
/// module can be. Its single job is to let the local caller that
/// filed an entry name *that* entry again later, so a withdrawal
/// reaches one operation instead of every operation that happens to
/// look like it.
///
/// Deliberately **not** [`PartialEq`]. A derived one would compare
/// pointees, and the pointee is zero-sized, so every identity would
/// equal every other and a withdrawal would match any entry under
/// the key — the exact defect this type exists to close.
#[derive(Clone, Debug)]
struct PendingOpId(Arc<PendingOpMarker>);

/// The allocation [`PendingOpId`] is identity over. Zero-sized and
/// private: it carries nothing, so there is nothing in it to read,
/// compare or serialize, and nothing outside this module can name
/// it.
#[derive(Debug)]
struct PendingOpMarker;

impl PendingOpId {
    /// Mint a fresh identity, distinct from every other live one.
    fn fresh() -> Self {
        Self(Arc::new(PendingOpMarker))
    }

    /// Whether `other` is this same identity — the same allocation,
    /// not merely a value that compares equal to it.
    fn names(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

/// One filed pending operation, as handed back to the local caller
/// that filed it.
///
/// Carries the two names that job needs and keeps them apart: the
/// `request_id` is the routing key that goes on the wire, the
/// `op_id` is the identity that never does. The caller sends under
/// the first and withdraws under the second.
#[derive(Debug)]
struct LocalRequest {
    request_id: String,
    op_id: PendingOpId,
}

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
    /// `Ok(filed)` means the id was unused and is now owned by an
    /// entry under a freshly minted identity, which comes back with
    /// it. `Err(effect)` means an operation already owns it and was
    /// **not** displaced; the effect is handed back unconsumed, so
    /// refusing is a decision the caller still holds its own channel
    /// through rather than a displacement it could not undo.
    ///
    /// The occupancy test and the insert are one entry-API step, so
    /// there is no window in which the id reads as free and is then
    /// taken by a concurrent call before this one writes. The
    /// identity is minted inside that same step, so an entry is
    /// never observable without one.
    fn claim_request_id(
        &self,
        request_id: String,
        expect_from: &str,
        effect: PendingEntry,
    ) -> Result<LocalRequest, PendingEntry> {
        match self.pending.entry(request_id) {
            // Occupied: another operation owns this id. Hand the
            // effect back rather than overwrite — displacing the
            // owner would strand its caller on a oneshot that can
            // never be resolved.
            Entry::Occupied(_) => Err(effect),
            Entry::Vacant(slot) => {
                let request_id = slot.key().clone();
                let op_id = PendingOpId::fresh();
                // The returned reference holds the shard guard.
                // Drop it here, before returning, so no guard
                // outlives this step.
                drop(slot.insert(PendingOp {
                    id: op_id.clone(),
                    expect_from: expect_from.to_string(),
                    effect,
                }));
                Ok(LocalRequest { request_id, op_id })
            }
        }
    }

    /// Register one locally-originated pending operation under a
    /// freshly drawn id, bound to the device it was addressed to and
    /// named by a fresh identity.
    ///
    /// **One draw, one claim, no retry.** A claim that collides
    /// answers `None`, which the caller reports as
    /// [`RpcError::RequestIdUnavailable`] rather than displacing
    /// whoever holds the id. That refusal is a real path, not a
    /// decorative one: a 96-bit draw makes a collision negligibly
    /// unlikely, never impossible, so it is handled explicitly here
    /// rather than assumed away. The bounded redraw it replaces
    /// bought nothing the single claim does not already give —
    /// "never displace" is total either way — while reading as a
    /// policy that will eventually secure an id, when the honest
    /// answer is that one collision fails the call.
    fn register_local_request(
        &self,
        expect_from: &str,
        effect: PendingEntry,
    ) -> Option<LocalRequest> {
        self.claim_request_id(new_request_id(), expect_from, effect)
            .ok()
    }

    /// [`Self::register_local_request`] for controls that file an
    /// operation they will never withdraw.
    ///
    /// Compiled for controls only. Every shipped caller registers
    /// through [`Self::register_local_request`] and keeps the
    /// identity, because every shipped caller can have its send fail
    /// and must then withdraw exactly the entry it filed. That
    /// leaves this wrapper with no shipped caller, so it is not
    /// shipped.
    ///
    /// Answers the id the operation was filed under and drops the
    /// identity, which the controls that use it never need: they
    /// file an operation and then settle it through the three bound
    /// operations, which match the device and class the frame
    /// arrived with and never the identity.
    ///
    /// Crate-internal rather than private so the engine's inbound
    /// controls can file a pending operation through the exact
    /// production path they then try to settle. The gate narrows
    /// when this is compiled, not what it does: a test-only twin
    /// would be a second *insertion* that could drift from the real
    /// one, and the controls would stop describing the real path,
    /// whereas this still files through the one registration and
    /// only reaches it under a thinner name.
    #[cfg(test)]
    pub(crate) fn insert_local_request(
        &self,
        expect_from: &str,
        effect: PendingEntry,
    ) -> Option<String> {
        self.register_local_request(expect_from, effect)
            .map(|filed| filed.request_id)
    }

    /// Drop a local operation the caller is abandoning, but only if
    /// the entry under that key is still the *exact* operation this
    /// caller filed.
    ///
    /// Used when the outbound send fails: the call will never be
    /// answered, so its entry must not linger.
    ///
    /// The condition is the identity, not the binding. Matching the
    /// bound device and class instead was the gap: they describe a
    /// *class* of operations rather than one, so if this caller's
    /// own entry had already left the map — settled by a response
    /// that raced the failing send, say — and the id had since been
    /// redrawn by a fresh call to the same device in the same class,
    /// every coordinate the predicate looked at matched the newcomer
    /// exactly. The stale abandonment then removed a live operation,
    /// and its caller waited on a oneshot no inbound frame could
    /// reach any more. An identity names one registration and this
    /// caller is holding the one it filed, so the match is total: it
    /// finds that entry, or it finds nothing and does nothing.
    fn abandon_local_request(&self, filed: &LocalRequest) {
        let _ = self
            .pending
            .remove_if(filed.request_id.as_str(), |_, op| op.id.names(&filed.op_id));
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
        // entry no inbound frame could ever match. Registration also
        // hands back the identity of the entry it filed, which is
        // what the failure path withdraws.
        let filed = self
            .inner
            .register_local_request(peer, PendingEntry::Single(tx))
            .ok_or(RpcError::RequestIdUnavailable)?;
        let frame = crate::protocol::RpcRequestMessage {
            request_id: filed.request_id.clone(),
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
            self.inner.abandon_local_request(&filed);
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
        // only through chunk and end frames. Withdrawal on a failed
        // send is by identity, exactly as above.
        let filed = self
            .inner
            .register_local_request(peer, PendingEntry::Stream(tx))
            .ok_or(RpcError::RequestIdUnavailable)?;
        let frame = crate::protocol::RpcRequestMessage {
            request_id: filed.request_id.clone(),
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
            self.inner.abandon_local_request(&filed);
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
    /// `claim_request_id` step every local registration drives.
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

    /// A stale abandonment never removes the reinstalled owner of a
    /// recycled request id.
    ///
    /// The shape this rules out: operation A files an entry and its
    /// outbound send fails, but by the time the abandonment runs A's
    /// entry has already left the map — a response raced the failing
    /// send and settled it — and the id has been redrawn by a fresh
    /// operation C to the *same* device in the *same* response
    /// class. Every coordinate the old removal predicate looked at,
    /// key and bound device and class, is identical between A and C,
    /// so it removed C: a live operation, whose caller was then left
    /// on a oneshot no inbound frame could reach any more. That is a
    /// local caller silently losing its own call, and the peer that
    /// can trigger it is whichever one answers fast enough to win
    /// the race against a failing send.
    ///
    /// Everything but the identity is deliberately held equal here,
    /// so identity is the only thing that can tell A from C.
    /// Production draws the id randomly; the control supplies it, so
    /// the recycling is certain rather than astronomically
    /// improbable, and both registrations go through the same
    /// `claim_request_id` step production goes through.
    #[tokio::test]
    async fn v4_arc04g1_a_stale_abandonment_never_removes_the_reinstalled_owner_of_a_recycled_id() {
        let state = crate::engine::build_test_state("arc04g1-recycled-id");
        let rpc = Rpc::attach(&state);
        let request_id = "recycled-request-id".to_string();

        // A: filed, and about to have its send fail. Unwrapped by
        // hand rather than with `expect`, which would format the
        // error: the refusal case hands back a `PendingEntry`, and
        // that is a live oneshot or mpsc sender, not something with
        // a `Debug` rendering to print.
        let (stale_tx, stale_rx) = oneshot::channel();
        let Ok(stale) = rpc.inner.claim_request_id(
            request_id.clone(),
            "device-a",
            PendingEntry::Single(stale_tx),
        ) else {
            panic!("the id starts free");
        };

        // A's entry leaves the map before the abandonment runs.
        drop(
            rpc.inner
                .take_single_response(&request_id, "device-a")
                .expect("A's own entry settles under A's own binding"),
        );
        assert!(
            stale_rx.await.is_err(),
            "A is gone, and its caller is resolved either way — the failed send \
             is about to answer it with a transport error"
        );

        // C: a fresh call redraws the same id, to the same device,
        // in the same class.
        let (fresh_tx, fresh_rx) = oneshot::channel();
        let Ok(reinstalled) = rpc.inner.claim_request_id(
            request_id.clone(),
            "device-a",
            PendingEntry::Single(fresh_tx),
        ) else {
            panic!("the recycled id is free again");
        };
        assert!(
            !stale.op_id.names(&reinstalled.op_id),
            "two registrations never share an identity — A is still holding its \
             own, so C could not have been given it — and here that is the only \
             coordinate that differs at all"
        );

        // A's abandonment finally runs, naming A's entry.
        rpc.inner.abandon_local_request(&stale);

        // C survives it, still bound as it was filed, and settles.
        let settle = rpc
            .inner
            .take_single_response(&request_id, "device-a")
            .expect("C is still pending: the stale abandonment named A's entry, not C's");
        assert!(settle
            .send(Ok(RpcResponse::from_value(serde_json::json!("mine"))))
            .is_ok());
        assert!(
            matches!(fresh_rx.await, Ok(Ok(response)) if response.body == serde_json::json!("mine")),
            "and C's own caller receives C's own response"
        );
    }

    /// Abandonment still withdraws the entry that filed it.
    ///
    /// The guard on the control above: a predicate that matched
    /// nothing at all would satisfy it just as well. This pins the
    /// other half — a caller whose send failed still removes its own
    /// entry, so a failed call leaves nothing pending behind it.
    #[tokio::test]
    async fn v4_arc04g1_abandonment_withdraws_the_operation_that_filed_it() {
        let state = crate::engine::build_test_state("arc04g1-abandon-own");
        let rpc = Rpc::attach(&state);

        let (tx, _rx) = oneshot::channel();
        let filed = rpc
            .inner
            .register_local_request("device-a", PendingEntry::Single(tx))
            .expect("the call is filed");

        rpc.inner.abandon_local_request(&filed);

        assert!(
            rpc.inner
                .take_single_response(&filed.request_id, "device-a")
                .is_none(),
            "the abandoned entry is gone, so a late response finds nothing to settle"
        );
    }
}
