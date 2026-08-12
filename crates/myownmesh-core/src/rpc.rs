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
//! In-flight requests are fields of the exact promoted peer session that sent
//! them. Each retained record and queued stream item holds its provider lease;
//! replacement, revocation and shutdown drop that session record and resolve
//! its callers.
//!
//! A request id is a routing key, never an authority. Every entry
//! is only looked up after the admitted inbound dispatch has re-entered the
//! captured installation's session record. A replacement connector therefore
//! has no map in which the predecessor's request can exist.
//!
//! Locally the same holds one level finer. Filing an operation also
//! hands its caller a process-local identity for the exact entry it
//! filed, and a caller withdrawing an entry after a failed send
//! matches on that identity rather than on the key and binding,
//! which a recycled id could reproduce exactly. Nothing inbound is
//! ever matched against it.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Weak};

use parking_lot::Mutex;
use tokio::sync::oneshot;

use crate::engine::state::NetworkState;
use crate::identity::DeviceId;
use crate::protocol::CapabilityAdvert;
use crate::resource::{
    mailbox_measure_serialized, mailbox_retained_claim, strings_measure, LeasedMap,
    LocalApplicationResourceScope, ResourceClaim, ResourceClaimArithmeticError, ResourceClass,
    ResourceLease, ResourceMailboxItem, ResourceMailboxItemError, ResourceMailboxReceiver,
};

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
    /// The peer had no live promoted session when the call was filed.
    ///
    /// Split out from [`Self::RequestIdUnavailable`], which used to answer for
    /// it. The two want opposite responses: this one is ordinary and worth
    /// retrying once a session establishes, and the other is a local draw
    /// colliding and says nothing about the peer at all.
    #[error("no live session for peer {0}")]
    SessionNotCurrent(String),
    /// The session's resource owner would not fund one more pending operation.
    ///
    /// Also split out of [`Self::RequestIdUnavailable`]. Pointing an operator at
    /// a request-id draw when the actual remedy is a larger grant is worse than
    /// saying nothing, because it is specific and wrong.
    #[error("rpc call refused: {0}")]
    ResourceUnavailable(String),
}

impl RpcRegistrationRefusal {
    /// The caller-facing error for one refusal, naming the peer it was about.
    ///
    /// One place, so the three facts cannot be mapped one way on the unary path
    /// and another on the streaming one — which is how they came to be mapped
    /// to a single wrong answer on both.
    pub(crate) fn into_rpc_error(self, peer: &str) -> RpcError {
        match self {
            Self::SessionNotCurrent => RpcError::SessionNotCurrent(peer.to_string()),
            Self::RequestIdCollision => RpcError::RequestIdUnavailable,
            Self::ResourceUnavailable(e) => {
                RpcError::ResourceUnavailable(format!("no capacity to file the call: {e:?}"))
            }
            Self::Unrepresentable => {
                RpcError::ResourceUnavailable("the call is not representable as a claim".into())
            }
        }
    }
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

/// Streaming-handler item. Every successful handler must explicitly terminate;
/// disappearance without `End` is a failed stream, never clean success.
#[derive(Debug, PartialEq)]
pub enum RpcStreamItem {
    Chunk(serde_json::Value),
    End(Result<(), String>),
}

impl ResourceMailboxItem for RpcStreamItem {
    fn retained_claim(&self) -> Result<ResourceClaim, ResourceMailboxItemError> {
        let (retained, queued, allocations) = match self {
            Self::Chunk(payload) => mailbox_measure_serialized(payload)?,
            Self::End(Ok(())) => (0, 0, 0),
            Self::End(Err(error)) => strings_measure([error.as_str()])?,
        };
        mailbox_retained_claim::<Self>(retained, queued, allocations)
    }
}

pub type RpcStreamHandlerFuture = Pin<
    Box<
        dyn Future<Output = Result<ResourceMailboxReceiver<RpcStreamItem>, String>>
            + Send
            + 'static,
    >,
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
    /// Non-owning route back to the runtime. `NetworkState` owns the one RPC
    /// dispatcher; retaining it here would close a permanent strong cycle and
    /// keep handlers and pending effects alive after network retirement.
    pub(crate) network: Weak<NetworkState>,
    pub(crate) handlers: Mutex<LeasedMap<String, HandlerEntry>>,
    handler_resources: LocalApplicationResourceScope,
    _allocation: ResourceLease,
}

/// Locally-originated operations owned by one exact promoted session.
///
/// This value has no peer key and no installation key: it is a field of
/// `PeerSessionState`, so replacement, revocation and retirement destroy the
/// only map capable of settling the old session's calls.
pub(crate) struct SessionRpcState {
    /// Leased, so every pending operation this session files is funded by that
    /// session and released with it.
    ///
    /// This was a `HashMap`, whose nodes the session paid for through a residual
    /// term inside [`pending_operation_claim`] — a number this module had to
    /// keep in agreement with a representation it does not own. A `LeasedMap`
    /// charges its own node from its own `size_of`, so the two halves are read
    /// where each is knowable and cannot drift apart.
    pending: crate::resource::LeasedMap<String, PendingOp>,
}

impl SessionRpcState {
    pub(crate) fn new() -> Self {
        Self {
            pending: crate::resource::LeasedMap::new(),
        }
    }
}

impl Drop for SessionRpcState {
    fn drop(&mut self) {
        // Every value, through the predicate walk, which allocates nothing —
        // this runs while a session is being torn down and a teardown that has
        // to allocate to report a teardown is one that can fail at the worst
        // moment. Answering `false` throughout is what makes it a visit rather
        // than a search.
        self.pending.any_value(|op| {
            if let PendingEntry::Stream(stream) = &op.effect {
                stream.finish(Some("RPC session retired".to_string()));
            }
            false
        });
    }
}

/// What one pending operation retains, off the map node.
///
/// The node is **not** here: [`crate::resource::LeasedMap::entry_claim`] adds
/// it, from a `size_of` only the map can take. This used to carry a residual of
/// 2 — "hash-map node plus the channel allocation retained by its sender" — and
/// the first of those two was an inference about someone else's representation.
/// One term is left, and it is the one this module can actually see: the oneshot
/// or inbox allocation the effect holds.
fn pending_operation_claim(
    request_id_bytes: usize,
) -> Result<crate::resource::ResourceClaim, crate::resource::ResourceClaimArithmeticError> {
    use crate::resource::{ResourceClaim, ResourceClaimArithmeticError, ResourceClass};
    let inline = std::mem::size_of::<PendingOp>()
        .checked_add(request_id_bytes)
        .ok_or(ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        })?;
    ResourceClaim::try_from_entries([
        (
            ResourceClass::AccountedMemoryBytes,
            u64::try_from(inline).map_err(|_| ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            })?,
        ),
        // The channel allocation retained by the effect's sender.
        (ResourceClass::OpaqueDependencyResidual, 1),
    ])
}

/// Why one locally-originated RPC operation was not filed.
///
/// Three facts, kept apart because a caller acts differently on each and
/// because two of them were previously reported as the third. Everything below
/// used to answer `Option`, which `call` and `call_stream` turned into
/// [`RpcError::RequestIdUnavailable`] — so a peer with no live session, and a
/// resource owner that would not fund one more pending entry, were both
/// reported as "no unused request id available". That sentence is false about
/// both of them, and it points a reader at a 96-bit draw when the actual remedy
/// is to wait for a session or to raise a grant.
#[derive(Debug)]
pub(crate) enum RpcRegistrationRefusal {
    /// No live promoted session for this peer at the moment of filing. Nothing
    /// was written and nothing is pending.
    SessionNotCurrent,
    /// The one drawn id was already owned. The incumbent is untouched — see
    /// [`SessionRpcState::claim_request_id`].
    RequestIdCollision,
    /// The session's resource owner would not fund the entry.
    ResourceUnavailable(crate::resource::ResourceUnavailable),
    /// The entry is not representable as a claim at all.
    Unrepresentable,
}

pub(crate) fn handler_task_claim(
    call: &RpcCall,
) -> Result<crate::resource::ResourceClaim, crate::resource::ResourceClaimArithmeticError> {
    use crate::resource::{ResourceClaim, ResourceClaimArithmeticError, ResourceClass};
    let encoded = serde_json::to_vec(&(
        &call.from,
        &call.request_id,
        &call.method,
        &call.payload,
        call.streaming,
    ))
    .map_err(|_| ResourceClaimArithmeticError::Overflow {
        dimension: ResourceClass::AccountedMemoryBytes,
    })?
    .len();
    let bytes = std::mem::size_of::<RpcCall>().checked_add(encoded).ok_or(
        ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        },
    )?;
    ResourceClaim::try_from_entries([
        (
            ResourceClass::AccountedMemoryBytes,
            u64::try_from(bytes).map_err(|_| ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            })?,
        ),
        // Boxed handler future plus the executor task record.
        (ResourceClass::OpaqueDependencyResidual, 2),
    ])
}

#[allow(clippy::large_enum_variant)]
pub enum HandlerEntry {
    Single {
        handler: RpcHandler,
        _retention: ResourceLease,
    },
    Stream {
        handler: RpcStreamHandler,
        _retention: ResourceLease,
    },
}

fn rpc_inner_claim() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    let bytes = std::mem::size_of::<RpcInner>()
        .checked_add(2 * std::mem::size_of::<usize>())
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        })?;
    ResourceClaim::try_from_entries([
        (ResourceClass::AccountedMemoryBytes, bytes),
        (ResourceClass::OpaqueDependencyResidual, 1),
    ])
}

fn handler_retention_claim<F>(method: &str) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    let bytes = method
        .len()
        .checked_add(std::mem::size_of::<F>())
        .and_then(|bytes| bytes.checked_add(2 * std::mem::size_of::<usize>()))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        })?;
    let allocations = u64::from(!method.is_empty()).checked_add(1).ok_or(
        ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::OpaqueDependencyResidual,
        },
    )?;
    ResourceClaim::try_from_entries([
        (ResourceClass::AccountedMemoryBytes, bytes),
        (ResourceClass::OpaqueDependencyResidual, allocations),
    ])
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
pub(crate) enum PendingEntry {
    Single(oneshot::Sender<Result<RpcResponse, String>>),
    Stream(Arc<RpcStreamInbox>),
}

pub(crate) struct RpcStreamInbox {
    mailbox: Mutex<crate::application_gateway::GatewayMailbox<serde_json::Value>>,
    terminal: Mutex<Option<Option<String>>>,
    ready: tokio::sync::Notify,
    finished: std::sync::atomic::AtomicBool,
}

impl RpcStreamInbox {
    pub(crate) fn new() -> Self {
        Self {
            mailbox: Mutex::new(crate::application_gateway::GatewayMailbox::new()),
            terminal: Mutex::new(None),
            ready: tokio::sync::Notify::new(),
            finished: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Admit one stream item, or say exactly why not.
    ///
    /// The refusal is typed because the two ways this fails are different facts
    /// with different remedies, and the caller settles a waiting application
    /// with one of them. `Pressure` means the provider would not fund this item:
    /// the stream is well formed and the owner is out of capacity, which is a
    /// sizing answer. `Malformed` means the item could not be represented at all
    /// — it did not encode, or its size is not expressible as a claim — which is
    /// a statement about the frame and not about the resource owner.
    ///
    /// This used to answer `bool`, and the caller turned every `false` into "RPC
    /// stream refused by resource owner". That sentence is true of one arm and
    /// false of the other, and the arm it is false about is the one that means a
    /// peer sent something this side could not admit. An untyped refusal does
    /// not merely lose detail here; it reports a resource owner that refused
    /// nothing.
    pub(crate) fn push(
        &self,
        session: &crate::runtime::session_broker::SessionCapability,
        payload: serde_json::Value,
    ) -> Result<(), crate::application_gateway::GatewayRefusal> {
        use crate::application_gateway::{GatewayMailbox, GatewayRefusal};

        let encoded_len = serde_json::to_vec(&payload)
            .map_err(|_| GatewayRefusal::Malformed)?
            .len();
        // Measured, then funded, then retained — the order every admission in
        // this crate takes, so nothing is held that the provider never got to
        // refuse.
        let retention = session
            .reserve_retained(
                GatewayMailbox::<serde_json::Value>::retention_claim(encoded_len, 1)
                    .map_err(|_| GatewayRefusal::Malformed)?,
            )
            .map_err(GatewayRefusal::Pressure)?;
        let node = session
            .reserve_retained(
                GatewayMailbox::<serde_json::Value>::node_claim()
                    .map_err(|_| GatewayRefusal::Malformed)?,
            )
            .map_err(GatewayRefusal::Pressure)?;
        self.mailbox.lock().accept(payload, retention, node);
        self.ready.notify_one();
        Ok(())
    }

    pub(crate) fn finish(&self, error: Option<String>) {
        let mut terminal = self.terminal.lock();
        if terminal.is_none() {
            *terminal = Some(error);
            self.finished
                .store(true, std::sync::atomic::Ordering::Release);
            self.ready.notify_waiters();
        }
    }

    async fn recv(&self) -> Option<Result<RpcStreamChunk, String>> {
        self.recv_with_before_wait(|| {}).await
    }

    async fn recv_with_before_wait(
        &self,
        mut before_wait: impl FnMut(),
    ) -> Option<Result<RpcStreamChunk, String>> {
        loop {
            let notified = self.ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(delivery) = self.mailbox.lock().pop() {
                let (value, retention) = delivery.into_parts();
                return Some(Ok(RpcStreamChunk {
                    value,
                    _retention: retention,
                }));
            }
            if let Some(terminal) = self.terminal.lock().take() {
                return terminal.map(Err);
            }
            if self.finished.load(std::sync::atomic::Ordering::Acquire) {
                return None;
            }
            before_wait();
            notified.await;
        }
    }

    #[cfg(test)]
    pub(crate) fn try_recv(&self) -> Option<RpcStreamChunk> {
        self.mailbox.lock().pop().map(|delivery| {
            let (value, retention) = delivery.into_parts();
            RpcStreamChunk {
                value,
                _retention: retention,
            }
        })
    }
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
    effect: PendingEntry,
    next_stream_seq: u64,
    _lease: crate::resource::ResourceLease,
}

impl PendingOp {
    /// Whether an inbound frame from `from`, of class `class`, is
    /// the one this operation is waiting for.
    ///
    /// Both halves must hold. A wrong source with the right class,
    /// and a right source with the wrong class, are equally not
    /// this operation's response.
    fn accepts(&self, class: PendingClass) -> bool {
        self.effect.class() == class
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
pub(crate) struct LocalRequest {
    pub(crate) request_id: String,
    op_id: PendingOpId,
}

struct PendingCancellation {
    network: Weak<NetworkState>,
    peer: String,
    filed: Option<LocalRequest>,
}

impl PendingCancellation {
    fn new(network: &Arc<NetworkState>, peer: &str, filed: LocalRequest) -> Self {
        Self {
            network: Arc::downgrade(network),
            peer: peer.to_string(),
            filed: Some(filed),
        }
    }

    fn request_id(&self) -> &str {
        &self.filed.as_ref().expect("armed cancellation").request_id
    }
}

impl Drop for PendingCancellation {
    fn drop(&mut self) {
        let (Some(network), Some(filed)) = (self.network.upgrade(), self.filed.as_ref()) else {
            return;
        };
        network
            .application_gateway
            .abandon_rpc_request(&network, &self.peer, filed);
    }
}

/// A session-owned streaming response. Dropping the receiver cancels the exact
/// pending operation immediately; a recycled request coordinate cannot match
/// its private allocation identity.
pub struct RpcStream {
    inbox: Arc<RpcStreamInbox>,
    _cancellation: PendingCancellation,
}

/// One popped stream value with its off-node retention lease. The queue node
/// is released at pop; the value remains funded until this wrapper is dropped.
pub struct RpcStreamChunk {
    value: serde_json::Value,
    _retention: crate::resource::ResourceLease,
}

impl std::fmt::Debug for RpcStreamChunk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.value.fmt(f)
    }
}

impl PartialEq<serde_json::Value> for RpcStreamChunk {
    fn eq(&self, other: &serde_json::Value) -> bool {
        &self.value == other
    }
}

impl RpcStreamChunk {
    pub fn into_value(self) -> serde_json::Value {
        self.value
    }
}

impl RpcStream {
    pub async fn recv(&mut self) -> Option<Result<RpcStreamChunk, String>> {
        self.inbox.recv().await
    }
}

/// The bound pending-operation surface.
///
/// These are the only ways to reach the `pending` map, and none of
/// them takes a request id on its own: every one additionally
/// requires the canonical device the inbound frame was
/// *authenticated* as, taken by the caller from the admitted
/// dispatch's owner token.
///
/// **Guard discipline.** The containing session record gives each operation
/// exclusive access to the leased map. It decides and extracts there, then
/// returns the sender to its caller. None of them sends, awaits, or invokes a
/// callback while
/// a guard is live — the engine performs the send after the
/// operation has returned and the guard is gone.
///
/// **Non-destructive refusal.** A wrong source or a wrong class is
/// not a settle attempt that fails; it is not a settle at all. The
/// predicate and the removal are the same exclusive step, so a
/// refused frame performs zero action, zero removal and zero
/// mutation, and the rightful owner's operation is left exactly as
/// it was.
impl SessionRpcState {
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
        &mut self,
        request_id: String,
        session: &crate::runtime::session_broker::SessionCapability,
        effect: PendingEntry,
    ) -> Result<LocalRequest, (PendingEntry, RpcRegistrationRefusal)> {
        // Occupancy first, and the effect never enters the map on this arm.
        // Displacing the owner would strand its caller on a oneshot nothing can
        // resolve. This is a plain read rather than an entry API because
        // `&mut self` is the exclusion: nothing else can touch this map between
        // the question and the insert, so there is no window to close.
        if self.pending.contains_key(request_id.as_str()) {
            return Err((effect, RpcRegistrationRefusal::RequestIdCollision));
        }
        let op_id = PendingOpId::fresh();
        // Measured, then funded, then filed. Two reservations because two things
        // are retained and each is released by its own owner: the value's, held
        // by the `PendingOp`, and the node's, held by the map entry.
        let Ok(claim) = pending_operation_claim(request_id.len()) else {
            return Err((effect, RpcRegistrationRefusal::Unrepresentable));
        };
        let lease = match session.reserve_retained(claim) {
            Ok(lease) => lease,
            Err(e) => return Err((effect, RpcRegistrationRefusal::ResourceUnavailable(e))),
        };
        let Ok(node_claim) = crate::resource::LeasedMap::<String, PendingOp>::entry_claim() else {
            return Err((effect, RpcRegistrationRefusal::Unrepresentable));
        };
        let node = match session.reserve_retained(node_claim) {
            Ok(node) => node,
            Err(e) => return Err((effect, RpcRegistrationRefusal::ResourceUnavailable(e))),
        };
        self.pending
            .insert(
                request_id.clone(),
                PendingOp {
                    id: op_id.clone(),
                    effect,
                    next_stream_seq: 1,
                    _lease: lease,
                },
                node,
            )
            // The map refuses a key it already holds, and the occupancy test
            // above ran under this same `&mut self` — nothing can have inserted
            // between them, because nothing else can hold this map at all. So
            // this arm is a violation of the map's own contract rather than a
            // state a caller can reach, and it is deliberately not given a
            // refusal variant: inventing one would mean fabricating an effect
            // to hand back, since the refusal has already taken the candidate.
            .expect("the id was vacant under this same exclusive borrow");
        Ok(LocalRequest { request_id, op_id })
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
    /// The refusal is typed and the effect is dropped here, deliberately in
    /// that order. Dropping the effect resolves the caller's own channel with a
    /// receive error, which says nothing; the returned reason is what the caller
    /// reports instead, and it is returned rather than logged because only the
    /// caller knows whether "no session yet" is worth retrying and "out of
    /// capacity" is not.
    pub(crate) fn register_local_request(
        &mut self,
        session: &crate::runtime::session_broker::SessionCapability,
        effect: PendingEntry,
    ) -> Result<LocalRequest, RpcRegistrationRefusal> {
        self.claim_request_id(new_request_id(), session, effect)
            .map_err(|(_effect, reason)| reason)
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
    pub(crate) fn abandon_local_request(&mut self, filed: &LocalRequest) {
        if self
            .pending
            .get(filed.request_id.as_str())
            .is_some_and(|op| op.id.names(&filed.op_id))
        {
            if let Some(op) = self.pending.remove(filed.request_id.as_str()) {
                if let PendingEntry::Stream(stream) = op.effect {
                    stream.finish(Some("RPC caller cancelled".to_string()));
                }
            }
        }
    }

    /// Take the single-response sender for `request_id`, but only
    /// if `from` is the bound device and the operation is a
    /// single-response one.
    ///
    /// Removes on success — a single response settles the call.
    /// A wrong source or a streaming operation removes nothing.
    pub(crate) fn take_single_response(
        &mut self,
        request_id: &str,
    ) -> Option<oneshot::Sender<Result<RpcResponse, String>>> {
        if !self.pending.get(request_id)?.accepts(PendingClass::Single) {
            return None;
        }
        let op = self.pending.remove(request_id)?;
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
        &mut self,
        request_id: &str,
        seq: u64,
    ) -> Option<Arc<RpcStreamInbox>> {
        // The shard guard is the closure's argument, so it is
        // released when the closure returns — the clone crosses out,
        // the guard does not.
        self.pending.get_mut(request_id).and_then(|op| {
            if !op.accepts(PendingClass::Stream) {
                return None;
            }
            if seq != op.next_stream_seq {
                return None;
            }
            op.next_stream_seq = op.next_stream_seq.checked_add(1)?;
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
    pub(crate) fn take_stream_end(&mut self, request_id: &str) -> Option<Arc<RpcStreamInbox>> {
        if !self.pending.get(request_id)?.accepts(PendingClass::Stream) {
            return None;
        }
        let op = self.pending.remove(request_id)?;
        match op.effect {
            // Unreachable for the same reason as in
            // `take_single_response`, and refused the same way.
            PendingEntry::Single(_) => None,
            PendingEntry::Stream(tx) => Some(tx),
        }
    }
}

impl RpcInner {
    fn install_handler(
        &self,
        method: &str,
        entry: HandlerEntry,
    ) -> Result<(), crate::application_gateway::GatewayRefusal> {
        let network = self
            .network
            .upgrade()
            .ok_or(crate::application_gateway::GatewayRefusal::Revoked)?;
        if network.application_gateway.is_closed() {
            return Err(crate::application_gateway::GatewayRefusal::Revoked);
        }
        let node = self
            .handler_resources
            .acquire(
                LeasedMap::<String, HandlerEntry>::entry_claim()
                    .map_err(|_| crate::application_gateway::GatewayRefusal::Malformed)?,
            )
            .map_err(crate::application_gateway::GatewayRefusal::Pressure)?;
        let mut handlers = self.handlers.lock();
        if network.application_gateway.is_closed() {
            return Err(crate::application_gateway::GatewayRefusal::Revoked);
        }
        handlers.remove(method);
        handlers
            .insert(method.to_string(), entry, node)
            .map_err(|_| crate::application_gateway::GatewayRefusal::Malformed)
    }
}

impl Rpc {
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
    pub fn attach(
        network: &Arc<NetworkState>,
    ) -> Result<Self, crate::application_gateway::GatewayRefusal> {
        if let Some(inner) = network.application_gateway.rpc() {
            if network.application_gateway.is_closed() {
                return Err(crate::application_gateway::GatewayRefusal::Revoked);
            }
            return Ok(Self { inner });
        }
        let handler_resources = network.application_gateway.rpc_resource_scope()?;
        let allocation = handler_resources
            .acquire(
                rpc_inner_claim()
                    .map_err(|_| crate::application_gateway::GatewayRefusal::Malformed)?,
            )
            .map_err(crate::application_gateway::GatewayRefusal::Pressure)?;
        let candidate = Arc::new(RpcInner {
            network: Arc::downgrade(network),
            handlers: Mutex::new(LeasedMap::new()),
            handler_resources,
            _allocation: allocation,
        });
        let inner = network.application_gateway.install_rpc(candidate)?;
        Ok(Self { inner })
    }

    /// Register a single-shot handler under `method`. Replaces any
    /// previous handler for the same name.
    pub fn serve<F, Fut>(
        &self,
        method: &str,
        handler: F,
    ) -> Result<(), crate::application_gateway::GatewayRefusal>
    where
        F: Fn(RpcCall) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<RpcResponse, String>> + Send + 'static,
    {
        let network = self
            .inner
            .network
            .upgrade()
            .ok_or(crate::application_gateway::GatewayRefusal::Revoked)?;
        if network.application_gateway.is_closed() {
            return Err(crate::application_gateway::GatewayRefusal::Revoked);
        }
        let retention = self
            .inner
            .handler_resources
            .acquire(
                handler_retention_claim::<F>(method)
                    .map_err(|_| crate::application_gateway::GatewayRefusal::Malformed)?,
            )
            .map_err(crate::application_gateway::GatewayRefusal::Pressure)?;
        let h: RpcHandler = Arc::new(move |call| {
            let fut = handler(call);
            Box::pin(fut)
        });
        self.inner.install_handler(
            method,
            HandlerEntry::Single {
                handler: h,
                _retention: retention,
            },
        )
    }

    /// Register a streaming handler under `method`. Chunks map to wire chunks;
    /// `End` maps exactly to the terminal frame. Bare receiver closure is error.
    pub fn serve_stream<F, Fut>(
        &self,
        method: &str,
        handler: F,
    ) -> Result<(), crate::application_gateway::GatewayRefusal>
    where
        F: Fn(RpcCall) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<ResourceMailboxReceiver<RpcStreamItem>, String>>
            + Send
            + 'static,
    {
        let network = self
            .inner
            .network
            .upgrade()
            .ok_or(crate::application_gateway::GatewayRefusal::Revoked)?;
        if network.application_gateway.is_closed() {
            return Err(crate::application_gateway::GatewayRefusal::Revoked);
        }
        let retention = self
            .inner
            .handler_resources
            .acquire(
                handler_retention_claim::<F>(method)
                    .map_err(|_| crate::application_gateway::GatewayRefusal::Malformed)?,
            )
            .map_err(crate::application_gateway::GatewayRefusal::Pressure)?;
        let h: RpcStreamHandler = Arc::new(move |call| {
            let fut = handler(call);
            Box::pin(fut)
        });
        self.inner.install_handler(
            method,
            HandlerEntry::Stream {
                handler: h,
                _retention: retention,
            },
        )
    }

    /// Drop the handler registered under `method`. Idempotent —
    /// no-op if nothing was registered.
    pub fn forget(&self, method: &str) {
        self.inner.handlers.lock().remove(method);
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
        let network = self.inner.network.upgrade().ok_or(RpcError::NetworkDown)?;
        let filed = network
            .application_gateway
            .register_rpc_request(&network, peer, PendingEntry::Single(tx))
            .map_err(|refusal| refusal.into_rpc_error(peer))?;
        let cancellation = PendingCancellation::new(&network, peer, filed);
        let frame = crate::protocol::RpcRequestMessage {
            request_id: cancellation.request_id().to_string(),
            method: method.to_string(),
            payload,
            streaming: false,
        };
        network
            .application_gateway
            .send_rpc_request(&network, peer, frame)
            .await
            .map_err(map_engine_err)?;
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
    ) -> Result<RpcStream, RpcError> {
        let inbox = Arc::new(RpcStreamInbox::new());
        // Bound exactly as the single-shot path above, with the
        // stream class: only `peer` may feed this receiver, and
        // only through chunk and end frames. Withdrawal on a failed
        // send is by identity, exactly as above.
        let network = self.inner.network.upgrade().ok_or(RpcError::NetworkDown)?;
        let filed = network
            .application_gateway
            .register_rpc_request(&network, peer, PendingEntry::Stream(Arc::clone(&inbox)))
            .map_err(|refusal| refusal.into_rpc_error(peer))?;
        let cancellation = PendingCancellation::new(&network, peer, filed);
        let frame = crate::protocol::RpcRequestMessage {
            request_id: cancellation.request_id().to_string(),
            method: method.to_string(),
            payload,
            streaming: true,
        };
        network
            .application_gateway
            .send_rpc_request(&network, peer, frame)
            .await
            .map_err(map_engine_err)?;
        Ok(RpcStream {
            inbox,
            _cancellation: cancellation,
        })
    }

    /// Advertise what this node offers to the mesh.
    ///
    /// None of it crosses in `hello`. An advertisement is application metadata
    /// and a Hello is admitted before a session exists, so the only path out is
    /// [`crate::protocol::CapabilitiesUpdateMessage`], sent to a peer whose
    /// session is live at the moment of the send.
    ///
    /// This call reaches the peers that have one already. A peer that
    /// establishes a session later is sent the value current *then*, on that
    /// establishment — so advertising before any peer exists is not a lost
    /// advertisement, and the embedder is never expected to call this again to
    /// repair one.
    /// **Answers whether the advertisement was committed**, which it did not
    /// used to. Both ways this can fail were silent returns: a network already
    /// down, and a resource owner that would not fund retaining the encoded
    /// advert. The second is the one that mattered — the embedder was told
    /// nothing, `capabilities()` kept answering the *previous* value, and every
    /// session established afterwards was sent that stale value indefinitely.
    /// An advertisement that did not take is not a slow advertisement.
    ///
    /// `Ok` means the value is stored and is what a later session will be sent.
    /// The fan-out to peers already holding one is still a spawn, still
    /// discarded, and still not part of this answer: it reports how many peers
    /// were reached, which is a fact about the mesh at one instant rather than
    /// about whether this call did its job.
    pub fn advertise(&self, caps: CapabilityAdvert) -> Result<(), RpcError> {
        let Some(net) = self.inner.network.upgrade() else {
            return Err(RpcError::NetworkDown);
        };
        net.application_gateway
            .replace_capabilities(net.session_broker.as_ref(), &caps)
            .map_err(|refusal| match refusal {
                crate::application_gateway::CapabilityReplaceRefusal::Revoked => {
                    RpcError::NetworkDown
                }
                crate::application_gateway::CapabilityReplaceRefusal::Unavailable(reason) => {
                    RpcError::ResourceUnavailable(reason)
                }
            })?;
        // The stored value is what a session established later is sent, and it
        // is in place before this returns. The fan-out to peers already holding
        // one is a command the driver runs on its next turn; the spawn is only
        // what keeps this call from waiting on it, and the discarded result is
        // the number of peers reached.
        tokio::spawn(async move {
            if let Err(error) = net
                .application_gateway
                .broadcast_capabilities(&net, caps)
                .await
            {
                tracing::warn!(%error, "capability fan-out was refused after local commit");
            }
        });
        Ok(())
    }

    /// Snapshot of the currently-advertised capabilities.
    pub fn capabilities(&self) -> CapabilityAdvert {
        self.inner
            .network
            .upgrade()
            .and_then(|network| network.application_gateway.capability_state().current())
            .unwrap_or_default()
    }

    // There is deliberately no `take_pending(request_id)` here.
    // One existed, unused and `#[allow(dead_code)]`, and it was the
    // unbound settle in its purest form: a request id in, someone's
    // pending effect out, with no question asked about who was
    // sending or what class they were sending. Reaching a pending
    // operation now requires naming the authenticated device too,
    // which that signature had no way to express.

    /// Snapshot registered methods for lifecycle controls. Production lookup
    /// is borrowed and performs no unfunded allocation.
    #[cfg(test)]
    pub(crate) fn registered_methods(&self) -> Vec<String> {
        let handlers = self.inner.handlers.lock();
        let mut methods = Vec::new();
        handlers.for_each(|method, _entry| methods.push(method.clone()));
        methods
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
        E::ResourceMailboxAdmission(crate::resource::ResourceMailboxAdmissionError::Closed) => {
            RpcError::NetworkDown
        }
        E::ResourceMailboxAdmission(crate::resource::ResourceMailboxAdmissionError::Pressure(
            error,
        )) => RpcError::ResourceUnavailable(format!("command admission refused: {error:?}")),
        E::ResourceMailboxAdmission(error) => {
            RpcError::ResourceUnavailable(format!("command is not representable: {error}"))
        }
        E::Transport(msg) => RpcError::Transport(msg),
        other => RpcError::Transport(other.to_string()),
    }
}

/// Flat snapshot of the method names registered on this node, for an embedder
/// that wants to inspect or publish them.
///
/// No mesh path consults it. Method names are not placed in `hello`, and a peer
/// learns what this node offers only from an advertisement the embedder chooses
/// to publish through [`Rpc::advertise`].
// These pre-session-ownership controls exercised the removed network-global
// pending map. Kept temporarily as historical specifications while the exact
// promoted-session integration controls live with the engine fence.
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
    async fn v4_arc04_session_request_id_collision_never_displaces_existing_owner() {
        let session =
            crate::runtime::session_broker::session_for_test(crate::runtime::runtime_for_test());
        let mut pending = SessionRpcState::new();

        // The incumbent: one pending single-response call bound to A.
        let (incumbent_tx, incumbent_rx) = oneshot::channel();
        let request_id = pending
            .register_local_request(&session, PendingEntry::Single(incumbent_tx))
            .expect("the session funds the incumbent")
            .request_id;

        // A second local call collides on that exact id.
        let challenger = Arc::new(RpcStreamInbox::new());
        let returned = pending
            .claim_request_id(
                request_id.clone(),
                &session,
                PendingEntry::Stream(Arc::clone(&challenger)),
            )
            .expect_err("an already-owned request id is never claimed twice");
        assert!(
            matches!(returned.0, PendingEntry::Stream(_)),
            "the colliding call gets its own effect back unconsumed, so the retry \
             loop can re-file it under a fresh id"
        );
        assert!(
            matches!(returned.1, RpcRegistrationRefusal::RequestIdCollision),
            "and it is told the id collided — not that the session was gone or \
             that the owner was short, which are the two facts this refusal used \
             to be reported as"
        );

        // The incumbent still owns the id, under its original
        // binding and class.
        let settle = pending
            .take_single_response(&request_id)
            .expect("the incumbent was not displaced by the collision");
        assert!(settle
            .send(Ok(RpcResponse::from_value(serde_json::json!("mine"))))
            .is_ok());
        assert!(
            matches!(incumbent_rx.await, Ok(Ok(response)) if response.body == serde_json::json!("mine")),
            "and its own caller receives its own response"
        );
        assert!(
            challenger.try_recv().is_none(),
            "the colliding call was never filed, so nothing is routed to it"
        );
    }

    /// The bound device survives a collision unchanged: a colliding
    /// draw must not repoint an existing entry at the new caller's
    /// peer, which would let that peer settle the incumbent's call.
    #[tokio::test]
    async fn v4_arc04_session_collision_preserves_incumbent_class() {
        let session =
            crate::runtime::session_broker::session_for_test(crate::runtime::runtime_for_test());
        let mut pending = SessionRpcState::new();

        let (incumbent_tx, _incumbent_rx) = oneshot::channel();
        let request_id = pending
            .register_local_request(&session, PendingEntry::Single(incumbent_tx))
            .expect("the session funds the incumbent")
            .request_id;

        let (challenger_tx, _challenger_rx) = oneshot::channel();
        let _ = pending.claim_request_id(
            request_id.clone(),
            &session,
            PendingEntry::Single(challenger_tx),
        );

        assert!(
            pending.take_single_response(&request_id).is_some(),
            "the incumbent entry and class survive the collision"
        );
    }

    /// Each refusal reaches the caller as its own error.
    ///
    /// The mapping *is* the finding. Registration always knew which of these
    /// had happened; `call` and `call_stream` threw that away and reported
    /// [`RpcError::RequestIdUnavailable`] for all of them. So an embedder whose
    /// peer had no session yet, and one whose resource owner was full, were
    /// both told to worry about a 96-bit request-id draw — specific, actionable
    /// and wrong in both cases.
    ///
    /// Asserted as three distinct discriminants rather than three exact
    /// strings: what must hold is that a caller can tell them apart, not how
    /// they are worded.
    #[test]
    fn each_registration_refusal_reaches_the_caller_as_its_own_error() {
        let session_gone = RpcRegistrationRefusal::SessionNotCurrent.into_rpc_error("peer-a");
        let collided = RpcRegistrationRefusal::RequestIdCollision.into_rpc_error("peer-a");
        // `Unrepresentable` rather than `ResourceUnavailable(_)`, which would
        // need a provider refusal constructed by hand. They share an arm, so
        // this covers the same discriminant without a fabricated refusal.
        let unfunded = RpcRegistrationRefusal::Unrepresentable.into_rpc_error("peer-a");

        assert!(matches!(session_gone, RpcError::SessionNotCurrent(ref p) if p == "peer-a"));
        assert!(matches!(collided, RpcError::RequestIdUnavailable));
        assert!(matches!(unfunded, RpcError::ResourceUnavailable(_)));

        // And the one that used to answer for all three still answers for
        // exactly one. Without this the control would pass against a mapping
        // that had merely renamed the single answer.
        assert_eq!(
            [&session_gone, &collided, &unfunded]
                .into_iter()
                .filter(|e| matches!(e, RpcError::RequestIdUnavailable))
                .count(),
            1,
            "only the collision is a request-id problem"
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
        let session =
            crate::runtime::session_broker::session_for_test(crate::runtime::runtime_for_test());
        let mut pending = SessionRpcState::new();
        let request_id = "recycled-request-id".to_string();

        // A: filed, and about to have its send fail. Unwrapped by
        // hand rather than with `expect`, which would format the
        // error: the refusal case hands back a `PendingEntry`, and
        // that is a live oneshot or mpsc sender, not something with
        // a `Debug` rendering to print.
        let (stale_tx, stale_rx) = oneshot::channel();
        let Ok(stale) =
            pending.claim_request_id(request_id.clone(), &session, PendingEntry::Single(stale_tx))
        else {
            panic!("the id starts free");
        };

        // A's entry leaves the map before the abandonment runs.
        drop(
            pending
                .take_single_response(&request_id)
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
        let Ok(reinstalled) =
            pending.claim_request_id(request_id.clone(), &session, PendingEntry::Single(fresh_tx))
        else {
            panic!("the recycled id is free again");
        };
        assert!(
            !stale.op_id.names(&reinstalled.op_id),
            "two registrations never share an identity — A is still holding its \
             own, so C could not have been given it — and here that is the only \
             coordinate that differs at all"
        );

        // A's abandonment finally runs, naming A's entry.
        pending.abandon_local_request(&stale);

        // C survives it, still bound as it was filed, and settles.
        let settle = pending
            .take_single_response(&request_id)
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
        let session =
            crate::runtime::session_broker::session_for_test(crate::runtime::runtime_for_test());
        let mut pending = SessionRpcState::new();

        let (tx, _rx) = oneshot::channel();
        let filed = pending
            .register_local_request(&session, PendingEntry::Single(tx))
            .expect("the call is filed");

        pending.abandon_local_request(&filed);

        assert!(
            pending.take_single_response(&filed.request_id).is_none(),
            "the abandoned entry is gone, so a late response finds nothing to settle"
        );
    }
}

#[cfg(test)]
mod session_ownership_tests {
    use super::*;

    fn session() -> crate::runtime::session_broker::SessionCapability {
        crate::runtime::session_broker::session_for_test(crate::runtime::runtime_for_test())
    }

    #[tokio::test]
    async fn pending_unary_settles_only_from_its_session_record() {
        let session = session();
        let mut pending = SessionRpcState::new();
        let (tx, rx) = oneshot::channel();
        let filed = pending
            .register_local_request(&session, PendingEntry::Single(tx))
            .expect("the session funds one pending unary");
        pending
            .take_single_response(&filed.request_id)
            .expect("the exact session owns the response")
            .send(Ok(RpcResponse::from_value(serde_json::json!(7))))
            .expect("caller is live");
        assert!(matches!(rx.await, Ok(Ok(response)) if response.body == serde_json::json!(7)));
    }

    #[tokio::test]
    async fn dropping_replaced_session_rpc_state_resolves_pending_call() {
        let session = session();
        let (tx, rx) = oneshot::channel();
        let mut pending = SessionRpcState::new();
        pending
            .register_local_request(&session, PendingEntry::Single(tx))
            .expect("the session funds one pending unary");
        drop(pending);
        assert!(rx.await.is_err(), "retirement drops the exact sender");
    }

    #[tokio::test]
    async fn caller_cancellation_removes_only_the_filed_operation() {
        let session = session();
        let (tx, rx) = oneshot::channel();
        let mut pending = SessionRpcState::new();
        let filed = pending
            .register_local_request(&session, PendingEntry::Single(tx))
            .expect("the session funds one pending unary");
        let request_id = filed.request_id.clone();
        pending.abandon_local_request(&filed);
        assert!(pending.take_single_response(&request_id).is_none());
        assert!(rx.await.is_err(), "cancellation drops the exact sender");
    }

    #[tokio::test]
    async fn stream_is_ordered_and_popped_value_keeps_its_lease() {
        let session = session();
        let inbox = Arc::new(RpcStreamInbox::new());
        let mut pending = SessionRpcState::new();
        let filed = pending
            .register_local_request(&session, PendingEntry::Stream(Arc::clone(&inbox)))
            .expect("the session funds one pending stream");
        let first = pending
            .stream_chunk_sender(&filed.request_id, 1)
            .expect("sequence one is accepted");
        assert!(first.push(&session, serde_json::json!("one")).is_ok());
        assert!(
            pending.stream_chunk_sender(&filed.request_id, 3).is_none(),
            "a gap is not delivered as ordinary data"
        );
        let delivery = inbox.recv().await.expect("one item").expect("chunk");
        assert_eq!(delivery, serde_json::json!("one"));
        drop(delivery);
    }

    #[tokio::test]
    async fn stream_finish_in_the_check_to_wait_window_cannot_be_lost() {
        let inbox = RpcStreamInbox::new();
        let finisher = &inbox;
        let terminal = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            inbox.recv_with_before_wait(move || {
                finisher.finish(Some("terminal in the wait window".to_string()));
            }),
        )
        .await
        .expect("the registered stream waiter observes terminal state");
        assert!(matches!(
            terminal,
            Some(Err(error)) if error == "terminal in the wait window"
        ));
    }

    /// An oversized payload is refused, and refused **for its size**.
    ///
    /// The two pushes around the refusal are what make that attributable. This
    /// control used to assert the refusal alone, against a fixture whose grant
    /// named no `QueuedBytes` at all: a five-byte payload was refused there for
    /// exactly the same reason a sixteen-mebibyte one was, so it passed while
    /// proving nothing about pressure. It would have kept passing under any
    /// repair.
    ///
    /// So: a small payload must be admitted first, from the same session and
    /// the same funded fixture, and a second small payload must still be
    /// admitted *after* the refusal. The first rules out a grant that funds no
    /// retention; the second rules out a grant whose last slot the first push
    /// consumed — the only two ways this refusal could be about something other
    /// than the payload's size. The fixture funds exactly two retained items
    /// (`FIXTURE_STREAM_ITEMS`), which is what leaves the second push room.
    ///
    /// The refusal is asserted **by kind**, not merely as a failure. `push`
    /// answers `Pressure` and `Malformed` separately, and only `Pressure` says
    /// what this control is named for; asserting the negation alone would keep
    /// passing if an oversized payload started being reported as unrepresentable
    /// instead of unfunded.
    #[test]
    fn stream_pressure_refuses_without_queueing() {
        use crate::application_gateway::GatewayRefusal;

        let session = session();
        let inbox = RpcStreamInbox::new();

        assert!(
            inbox.push(&session, serde_json::json!("small")).is_ok(),
            "a payload inside the fixture's stated retention capacity is queued"
        );

        let oversized = serde_json::Value::String("x".repeat(16 * 1024 * 1024));
        assert!(
            matches!(
                inbox.push(&session, oversized),
                Err(GatewayRefusal::Pressure(_))
            ),
            "a payload far past that capacity is refused, and refused as \
             pressure: the provider saw it and would not fund it"
        );

        assert!(
            inbox
                .push(&session, serde_json::json!("also small"))
                .is_ok(),
            "and the refusal was about the payload's size, not a slot: the \
             session still admits another small payload afterwards"
        );

        // Nothing the refused push touched was queued: exactly the two admitted
        // payloads are in the mailbox, in order, and then it is empty.
        let mut mailbox = inbox.mailbox.lock();
        assert_eq!(
            mailbox
                .pop()
                .expect("the first admitted payload")
                .into_parts()
                .0,
            serde_json::json!("small")
        );
        assert_eq!(
            mailbox
                .pop()
                .expect("the second admitted payload")
                .into_parts()
                .0,
            serde_json::json!("also small")
        );
        assert!(
            mailbox.is_empty(),
            "the refused push left no entry behind it"
        );
    }

    #[test]
    fn attach_elects_one_owner_and_rpc_does_not_keep_network_alive() {
        let state = crate::engine::build_test_state("rpc-weak-owner");
        let weak = Arc::downgrade(&state);
        let first = Rpc::attach(&state).expect("the fixture funds one dispatcher");
        let second = Rpc::attach(&state).expect("attach reuses the funded dispatcher");
        assert!(Arc::ptr_eq(&first.inner, &second.inner));
        drop(state);
        assert!(weak.upgrade().is_none());
        assert!(first.inner.network.upgrade().is_none());
    }
}
