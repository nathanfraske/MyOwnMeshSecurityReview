//! Per-connection state and the daemon-wide indices that route
//! inbound RPCs / channel messages to the right client.
//!
//! One `ClientHandle` per event-subscribed socket. It owns the outbound writer
//! and an unguessable capability presented on later command connections.
//!
//! The registry maintains five indices:
//!
//! - `clients` — every connected event-subscribed client, keyed
//!   by `ClientId`. Dropped on disconnect.
//! - `handler_claims` — which client owns each method name on
//!   each network. Last-claim-wins: a re-register evicts the
//!   prior owner with a `HandlerDisplaced` event.
//! - `channel_subs` — set of subscribed clients per (network,
//!   channel). Channel inbound events fan out to every member.
//! - `exact_pending_inbound` — full remote coordinates, response class,
//!   claiming connection owner, method claim and private local operation id.
//! - `installed_handlers` — which shape of synthetic handler the bridge has
//!   installed for each claim, so a re-claim can be answered without asking
//!   the engine what it already holds.

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::{DashMap, DashSet};
use parking_lot::Mutex;
use tokio::sync::{mpsc, oneshot};

use super::wire::ServerOut;

/// Process-unique identifier for a connected client.
///
/// Just a monotonic counter; the daemon never reuses ids, so a
/// stale reference in a forwarder task that races with
/// disconnect resolves to a `None` lookup instead of routing to
/// a different client.
///
/// Wire form is the `Display` shape `c<n>` — clients pass it
/// back verbatim on subsequent RPC/channel-management requests
/// to identify which event-subscribed connection a handler
/// claim belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientId(pub u64);

impl std::fmt::Display for ClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "c{}", self.0)
    }
}

impl std::str::FromStr for ClientId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let n_str = s
            .strip_prefix('c')
            .ok_or_else(|| format!("ClientId must start with 'c', got '{s}'"))?;
        let n: u64 = n_str.parse().map_err(|e| format!("ClientId parse: {e}"))?;
        Ok(ClientId(n))
    }
}

impl serde::Serialize for ClientId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for ClientId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Per-network handler-claim key. `network` is the
/// configuration id (matching the rest of the control surface).
pub type ClaimKey = (String, String);

/// Unforgeable authority issued to one event-stream connection. `ClientId`
/// remains a routing coordinate; possession of this value is the authority.
#[derive(Clone, PartialEq, Eq)]
pub struct ClientCapability(String);

impl ClientCapability {
    fn mint() -> Self {
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes)
            .expect("OS randomness is required for local IPC authority");
        Self(data_encoding::BASE64URL_NOPAD.encode(&bytes))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    fn matches(&self, presented: &str) -> bool {
        if self.0.len() != presented.len() {
            return false;
        }
        self.0
            .bytes()
            .zip(presented.bytes())
            .fold(0_u8, |d, (a, b)| d | (a ^ b))
            == 0
    }
}

/// Unforgeable authority naming one realtime flow a client has open.
///
/// Minted when the flow is opened, and the daemon keeps the move-only core
/// handle behind it. A client presents it to write on that flow or to close it;
/// there is no coordinate that substitutes, which is the whole point — the peer
/// selector and the flow label it replaces were both re-resolvable, so a client
/// whose session had been replaced was writing into the successor's flow of the
/// same name.
///
/// Separate from [`ClientCapability`] rather than reusing it, because the two
/// answer different questions: that one says *who* is asking, this one says
/// *which of that client's flows*. One value doing both would make a client's
/// second flow indistinguishable from its first.
///
/// Compared by map lookup rather than in constant time, and that is sound here
/// where it would not be for [`ClientCapability`]: this table is only ever
/// reached after the client capability has authenticated, and it holds only
/// that client's own flows. What a timing probe could learn is which of its own
/// flows it already has.
#[derive(Clone, PartialEq, Eq)]
pub struct RealtimeFlowCapability(String);

impl RealtimeFlowCapability {
    fn mint() -> Self {
        let mut bytes = [0_u8; 32];
        getrandom::getrandom(&mut bytes)
            .expect("OS randomness is required for local IPC authority");
        Self(data_encoding::BASE64URL_NOPAD.encode(&bytes))
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

/// One flow a client owns, and the network it was opened on.
///
/// The network travels with the handle because closing needs a `JoinedNetwork`
/// to close *through*, and asking the client which network its own flow is on
/// would be taking a routing decision from the party being authorized.
struct OwnedRealtimeFlow {
    network: String,
    flow: myownmesh_core::realtime::RealtimeFlowHandle,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PendingKey {
    pub network: String,
    pub method: String,
    pub remote_peer: String,
    pub remote_request_id: String,
    pub class: HandlerMode,
}

struct PendingRecord {
    owner: ClientId,
    operation_id: u64,
    effect: PendingInbound,
    cancelled: Arc<PendingCancellation>,
}

struct PendingCancellation {
    cancelled: AtomicBool,
    notify: tokio::sync::Notify,
}

impl PendingCancellation {
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    async fn wait(&self) {
        loop {
            if self.cancelled.load(Ordering::Acquire) {
                return;
            }
            let notified = self.notify.notified();
            if self.cancelled.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

/// Exact cleanup authority for one pending operation. Stale cleanup cannot
/// remove a later operation that happens to reuse all public coordinates.
pub struct PendingTicket {
    registry: std::sync::Weak<RegistryInner>,
    key: PendingKey,
    operation_id: u64,
    cancelled: Arc<PendingCancellation>,
}

impl PendingTicket {
    pub fn operation_id(&self) -> u64 {
        self.operation_id
    }

    pub async fn cancelled(&self) {
        self.cancelled.wait().await;
    }
}

impl Drop for PendingTicket {
    fn drop(&mut self) {
        let Some(registry) = self.registry.upgrade() else {
            return;
        };
        if let Some((_, pending)) =
            registry
                .exact_pending_inbound
                .remove_if(&self.key, |_, pending| {
                    let matches = pending.operation_id == self.operation_id;
                    if matches {
                        pending.cancelled.cancel();
                    }
                    matches
                })
        {
            drop(pending);
        }
    }
}

/// Engine-side awaiter for an in-flight inbound RPC. The
/// synthetic handler installed by [`super::bridge`] returns the
/// receive side to the engine; the daemon stores the sender
/// here so a later `RpcRespond` from the client resolves it.
pub enum PendingInbound {
    /// Single-shot — resolved by exactly one `RpcRespond`.
    Single(oneshot::Sender<Result<serde_json::Value, String>>),
    /// Streaming — fed by `RpcStreamChunk`s and terminated by `RpcStreamEnd`,
    /// which sends an explicit [`RpcStreamItem::End`] carrying either clean
    /// completion or the client's own error.
    ///
    /// The terminal item is sent rather than implied by dropping the sender,
    /// because those are different outcomes: a sender that disappears without
    /// an `End` is a failed stream, and core reports it to the peer as one.
    /// Flattening the two would make a client that crashed mid-stream
    /// indistinguishable from one that finished.
    ///
    /// [`RpcStreamItem::End`]: myownmesh_core::rpc::RpcStreamItem::End
    Stream(mpsc::Sender<myownmesh_core::rpc::RpcStreamItem>),
}

/// State for a single connected event-subscribed client.
pub struct ClientHandle {
    pub id: ClientId,
    capability: ClientCapability,
    connected: AtomicBool,
    disconnected: tokio::sync::Notify,
    /// Mpsc the read loop and bridge code push outbound frames
    /// into; a writer task on the same connection drains it.
    pub writer_tx: mpsc::UnboundedSender<ServerOut>,
    /// Method claims this client currently holds. Tracked for
    /// O(1) cleanup on disconnect; the authoritative routing
    /// table is on the registry.
    pub method_claims: Arc<DashSet<ClaimKey>>,
    /// Channel subscriptions this client currently holds.
    /// Same disconnect-cleanup rationale.
    pub channel_subs: Arc<DashSet<ClaimKey>>,
    /// Realtime flows this client has open, each under the capability issued
    /// for it.
    ///
    /// **Per client, not per connection**, and that is forced by the protocol
    /// rather than chosen: a client opens a flow on its request connection and
    /// writes to it on a separate `realtime_pipe` connection, so a table owned
    /// by the opening connection could never be reached by the one that needs
    /// it. The client capability is what spans the two, so the flows hang off
    /// the same thing it does.
    ///
    /// Private, because the handles inside are move-only and must stay that
    /// way: an accessor that lent one out by value would let a caller keep a
    /// flow the close path believes it has taken.
    realtime_flows: Arc<DashMap<String, OwnedRealtimeFlow>>,
}

impl ClientHandle {
    /// Take ownership of one open flow and answer the capability naming it.
    ///
    /// The capability is minted here rather than supplied, so a client cannot
    /// choose where its flow is filed or overwrite another of its own.
    fn register_realtime_flow(
        &self,
        network: String,
        flow: myownmesh_core::realtime::RealtimeFlowHandle,
    ) -> RealtimeFlowCapability {
        let capability = RealtimeFlowCapability::mint();
        self.realtime_flows.insert(
            capability.expose().to_string(),
            OwnedRealtimeFlow { network, flow },
        );
        capability
    }

    /// Lend one of this client's flows, if `capability` names one on `network`.
    ///
    /// **Lends and never hands over.** `effect` gets a borrow that ends with the
    /// call, which is what keeps the stored handle the only one — a send cannot
    /// retain the flow past the unit it was authorizing.
    ///
    /// `network` is required to match rather than taken on trust. It would be
    /// safe without: the handle names an exact installation, so presenting it
    /// through the wrong network refuses at the fence anyway. What the check
    /// buys is that the refusal says what happened, instead of surfacing as a
    /// session that is somehow never current.
    ///
    /// Nothing here awaits, so the map's shard guard is never held across a
    /// suspension point.
    pub fn with_realtime_flow<R>(
        &self,
        capability: &str,
        network: &str,
        effect: impl FnOnce(&myownmesh_core::realtime::RealtimeFlowHandle) -> R,
    ) -> Option<R> {
        let owned = self.realtime_flows.get(capability)?;
        (owned.network == network).then(|| effect(&owned.flow))
    }

    /// Take one of this client's flows out, for a close that will consume it.
    ///
    /// Removal and the close are separate steps and the removal comes first, so
    /// two concurrent closes cannot both reach core with the same flow: the
    /// second finds nothing.
    pub fn take_realtime_flow(
        &self,
        capability: &str,
    ) -> Option<(String, myownmesh_core::realtime::RealtimeFlowHandle)> {
        let (_, owned) = self.realtime_flows.remove(capability)?;
        Some((owned.network, owned.flow))
    }

    /// Take every flow this client still owns.
    ///
    /// For disconnect and shutdown, where the flows have to be closed *through*
    /// their networks rather than merely dropped — dropping a handle releases
    /// nothing, by design, so a client that vanished would otherwise leave its
    /// labels claimed and its native halves up until the session itself ended.
    pub fn drain_realtime_flows(
        &self,
    ) -> Vec<(String, myownmesh_core::realtime::RealtimeFlowHandle)> {
        let keys: Vec<String> = self
            .realtime_flows
            .iter()
            .map(|entry| entry.key().clone())
            .collect();
        keys.into_iter()
            .filter_map(|key| self.take_realtime_flow(&key))
            .collect()
    }

    pub fn send(&self, frame: ServerOut) {
        // Best effort: a dropped writer means the connection is
        // gone; the registry will clean up the handle shortly.
        let _ = self.writer_tx.send(frame);
    }

    pub async fn wait_disconnected(&self) {
        loop {
            if !self.connected.load(Ordering::Acquire) {
                return;
            }
            let notified = self.disconnected.notified();
            if !self.connected.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

// There is no media sink on a client handle any more. It existed to let the
// pumps choose between a binary pipe and base64 events per frame, and there is
// no base64 fallback to choose against: units ride an inbound `realtime_pipe`
// and nothing else. A pump that had a fallback would silently take it whenever
// the pipe was missing, which is the case that should be visible.

/// Daemon-wide registry of connected clients + their
/// registrations.
#[derive(Clone)]
pub struct ClientRegistry {
    inner: Arc<RegistryInner>,
}

struct RegistryInner {
    mutation: Mutex<()>,
    stream_capacity: NonZeroUsize,
    next_id: AtomicU64,
    next_call_stream_id: AtomicU64,
    clients: DashMap<ClientId, Arc<ClientHandle>>,
    handler_claims: DashMap<ClaimKey, ClientId>,
    channel_subs: DashMap<ClaimKey, Arc<Mutex<Vec<ClientId>>>>,
    exact_pending_inbound: DashMap<PendingKey, PendingRecord>,
    next_operation_id: AtomicU64,
    /// Streaming methods that have a synthetic handler
    /// installed on the engine. `(network, method) → ()` —
    /// the value side is unused; we only need set semantics.
    /// Tracked so we can ask the bridge to forget the handler
    /// on the last unclaim.
    installed_handlers: DashMap<ClaimKey, HandlerMode>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HandlerMode {
    Single,
    Stream,
}

impl ClientRegistry {
    pub fn with_stream_capacity(stream_capacity: NonZeroUsize) -> Self {
        Self {
            inner: Arc::new(RegistryInner {
                stream_capacity,
                mutation: Mutex::new(()),
                next_id: AtomicU64::new(0),
                next_call_stream_id: AtomicU64::new(0),
                clients: DashMap::new(),
                handler_claims: DashMap::new(),
                channel_subs: DashMap::new(),
                exact_pending_inbound: DashMap::new(),
                next_operation_id: AtomicU64::new(0),
                installed_handlers: DashMap::new(),
            }),
        }
    }

    #[cfg(test)]
    pub fn new() -> Self {
        Self::with_stream_capacity(NonZeroUsize::new(4).expect("test policy is nonzero"))
    }

    pub fn stream_capacity(&self) -> NonZeroUsize {
        self.inner.stream_capacity
    }

    /// Allocate a fresh `ClientId` and register the client's
    /// outbound writer. Returns the handle the read loop should
    /// keep alongside its socket.
    pub fn register(&self, writer_tx: mpsc::UnboundedSender<ServerOut>) -> Arc<ClientHandle> {
        let id = ClientId(self.inner.next_id.fetch_add(1, Ordering::Relaxed));
        let handle = Arc::new(ClientHandle {
            id,
            capability: ClientCapability::mint(),
            connected: AtomicBool::new(true),
            disconnected: tokio::sync::Notify::new(),
            writer_tx,
            method_claims: Arc::new(DashSet::new()),
            channel_subs: Arc::new(DashSet::new()),
            realtime_flows: Arc::new(DashMap::new()),
        });
        self.inner.clients.insert(id, handle.clone());
        handle
    }

    pub fn capability<'a>(&self, client: &'a ClientHandle) -> &'a str {
        client.capability.expose()
    }

    pub fn authenticate(&self, id: ClientId, presented: &str) -> Option<Arc<ClientHandle>> {
        let client = self.client(id)?;
        client.capability.matches(presented).then_some(client)
    }

    /// Install a completed realtime open only while its event-stream owner is
    /// still registered. This shares the registry mutation seam with
    /// [`Self::unregister`]: install-first means the disconnect drain observes
    /// and closes the flow; disconnect-first returns the move-only handle to
    /// the caller, which must close it directly.
    pub fn install_realtime_flow(
        &self,
        owner: &Arc<ClientHandle>,
        network: String,
        flow: myownmesh_core::realtime::RealtimeFlowHandle,
    ) -> Result<RealtimeFlowCapability, myownmesh_core::realtime::RealtimeFlowHandle> {
        self.install_if_live(owner, flow, |flow| {
            owner.register_realtime_flow(network, flow)
        })
    }

    fn install_if_live<T, R>(
        &self,
        owner: &Arc<ClientHandle>,
        value: T,
        install: impl FnOnce(T) -> R,
    ) -> Result<R, T> {
        let _mutation = self.inner.mutation.lock();
        let Some(current) = self.inner.clients.get(&owner.id) else {
            return Err(value);
        };
        if !Arc::ptr_eq(current.value(), owner) || !owner.connected.load(Ordering::Acquire) {
            return Err(value);
        }
        Ok(install(value))
    }

    /// Remove one exact connection owner, all its claims and subscriptions,
    /// and every pending operation it owns. A stream sender disappearing
    /// without an explicit terminal item is a peer-visible failure in core.
    pub fn unregister(&self, id: ClientId) -> Option<Arc<ClientHandle>> {
        let _mutation = self.inner.mutation.lock();
        let (_, handle) = self.inner.clients.remove(&id)?;
        handle.connected.store(false, Ordering::Release);
        handle.disconnected.notify_waiters();
        // Drop method claims this client owned. Note: we don't
        // tear down the synthetic handler on the engine — a
        // future claimant might re-take the same method
        // immediately and we'd save the install. The handler
        // gracefully errors with `no claim` if invoked with no
        // current owner.
        for entry in handle.method_claims.iter() {
            let key = entry.key().clone();
            // Only drop if we still own it (a displacing client
            // might have already taken over).
            self.inner
                .handler_claims
                .remove_if(&key, |_, owner| *owner == id);
        }
        // Drop channel subscriptions. The fan-out task running
        // for this (network, channel) will notice the empty
        // subscriber list and exit on its next iteration.
        for entry in handle.channel_subs.iter() {
            let key = entry.key().clone();
            if let Some(subs) = self.inner.channel_subs.get(&key) {
                subs.lock().retain(|c| *c != id);
            }
        }
        let keys: Vec<_> = self
            .inner
            .exact_pending_inbound
            .iter()
            .filter(|entry| entry.value().owner == id)
            .map(|entry| entry.key().clone())
            .collect();
        for key in keys {
            if let Some((_, pending)) =
                self.inner
                    .exact_pending_inbound
                    .remove_if(&key, |_, pending| {
                        let matches = pending.owner == id;
                        if matches {
                            pending.cancelled.cancel();
                        }
                        matches
                    })
            {
                match pending.effect {
                    PendingInbound::Single(tx) => {
                        let _ = tx.send(Err("local IPC handler disconnected".into()));
                    }
                    PendingInbound::Stream(tx) => drop(tx),
                }
            }
        }
        Some(handle)
    }

    pub fn client(&self, id: ClientId) -> Option<Arc<ClientHandle>> {
        self.inner.clients.get(&id).map(|e| e.value().clone())
    }

    /// Unregister every client and answer the handles that were removed.
    ///
    /// The handles are returned rather than dropped because some of what a
    /// client owns cannot be released by dropping it — realtime flows in
    /// particular, whose handles are non-owning and whose closes have to run
    /// through a joined network and await. This module has neither, so it hands
    /// the owners back to the caller that does.
    #[must_use = "a shut-down client's realtime flows still have to be closed through their networks"]
    pub fn shutdown(&self) -> Vec<Arc<ClientHandle>> {
        let clients: Vec<_> = self
            .inner
            .clients
            .iter()
            .map(|entry| *entry.key())
            .collect();
        let removed: Vec<Arc<ClientHandle>> = clients
            .into_iter()
            .filter_map(|client| self.unregister(client))
            .collect();
        // Defensive: handler futures can race shutdown after the client
        // snapshot. Dropping a stream entry without End is explicitly failed
        // by core; dropping a single sender wakes its waiter with cancellation.
        let remaining: Vec<_> = self
            .inner
            .exact_pending_inbound
            .iter()
            .map(|entry| entry.key().clone())
            .collect();
        for key in remaining {
            if let Some((_, pending)) =
                self.inner
                    .exact_pending_inbound
                    .remove_if(&key, |_, pending| {
                        pending.cancelled.cancel();
                        true
                    })
            {
                drop(pending.effect);
            }
        }
        removed
    }

    /// Claim a method on a network. Returns the previously
    /// claiming client if any (so the caller can notify them
    /// with `HandlerDisplaced`).
    pub fn claim_method(
        &self,
        key: ClaimKey,
        new_owner: ClientId,
        mode: HandlerMode,
    ) -> Option<ClientId> {
        let _mutation = self.inner.mutation.lock();
        // Update the per-client cache first so on-disconnect
        // cleanup sees the new claim.
        let client = self.client(new_owner)?;
        client.method_claims.insert(key.clone());
        let prev = self.inner.handler_claims.insert(key.clone(), new_owner);
        self.inner.installed_handlers.insert(key.clone(), mode);
        if let Some(prev_owner) = prev {
            if prev_owner != new_owner {
                if let Some(prev_client) = self.client(prev_owner) {
                    prev_client.method_claims.remove(&key);
                }
                self.cancel_displaced_claim(&key, prev_owner);
                return Some(prev_owner);
            }
        }
        None
    }

    fn cancel_displaced_claim(&self, claim: &ClaimKey, owner: ClientId) {
        let keys: Vec<_> = self
            .inner
            .exact_pending_inbound
            .iter()
            .filter(|entry| {
                entry.value().owner == owner
                    && entry.key().network == claim.0
                    && entry.key().method == claim.1
            })
            .map(|entry| entry.key().clone())
            .collect();
        for key in keys {
            if let Some((_, pending)) =
                self.inner
                    .exact_pending_inbound
                    .remove_if(&key, |_, pending| {
                        let matches = pending.owner == owner;
                        if matches {
                            pending.cancelled.cancel();
                        }
                        matches
                    })
            {
                match pending.effect {
                    PendingInbound::Single(tx) => {
                        let _ = tx.send(Err("local IPC handler displaced".into()));
                    }
                    PendingInbound::Stream(tx) => drop(tx),
                }
            }
        }
    }

    /// Release a method claim. Returns the prior owner if the
    /// caller did own it.
    pub fn release_method(&self, key: &ClaimKey, owner: ClientId) -> bool {
        let _mutation = self.inner.mutation.lock();
        if let Some(client) = self.client(owner) {
            client.method_claims.remove(key);
        }
        self.inner
            .handler_claims
            .remove_if(key, |_, current| *current == owner)
            .is_some()
    }

    pub fn handler_owner(&self, key: &ClaimKey) -> Option<ClientId> {
        self.inner.handler_claims.get(key).map(|e| *e.value())
    }

    #[allow(dead_code)]
    pub fn handler_mode(&self, key: &ClaimKey) -> Option<HandlerMode> {
        self.inner.installed_handlers.get(key).map(|e| *e.value())
    }

    /// Returns `true` on the FIRST subscriber for this
    /// (network, channel) — caller uses that signal to spawn a
    /// new pump task.
    pub fn subscribe_channel(&self, key: ClaimKey, client: ClientId) -> bool {
        let _mutation = self.inner.mutation.lock();
        let Some(c) = self.client(client) else {
            return false;
        };
        c.channel_subs.insert(key.clone());
        let entry = self
            .inner
            .channel_subs
            .entry(key.clone())
            .or_insert_with(|| Arc::new(Mutex::new(Vec::new())));
        let mut subs = entry.lock();
        let was_empty = subs.is_empty();
        if !subs.contains(&client) {
            subs.push(client);
        }
        was_empty
    }

    /// Release a subscription. Returns `true` if no clients
    /// remain on this channel — caller uses that signal to tear
    /// down the pump task.
    pub fn unsubscribe_channel(&self, key: &ClaimKey, client: ClientId) -> bool {
        let _mutation = self.inner.mutation.lock();
        if let Some(c) = self.client(client) {
            c.channel_subs.remove(key);
        }
        let Some(subs) = self.inner.channel_subs.get(key) else {
            return true;
        };
        let mut subs = subs.lock();
        subs.retain(|c| *c != client);
        subs.is_empty()
    }

    /// Snapshot the current set of subscribers — used by the
    /// channel pump task each iteration.
    pub fn channel_subscribers(&self, key: &ClaimKey) -> Vec<ClientId> {
        self.inner
            .channel_subs
            .get(key)
            .map(|subs| subs.lock().clone())
            .unwrap_or_default()
    }

    /// Monotonic counter used to tag outbound stream calls.
    /// The lib's `Rpc::call_stream` allocates its own request
    /// id internally but doesn't expose it; the IPC layer
    /// generates its own correlation id so clients can match
    /// chunks back to their originating call.
    pub fn next_call_stream_id(&self) -> u64 {
        self.inner
            .next_call_stream_id
            .fetch_add(1, Ordering::Relaxed)
    }

    pub fn insert_exact_pending(
        &self,
        key: PendingKey,
        owner: ClientId,
        effect: PendingInbound,
    ) -> Result<PendingTicket, PendingInbound> {
        use dashmap::mapref::entry::Entry;
        let _mutation = self.inner.mutation.lock();
        if self.client(owner).is_none() {
            return Err(effect);
        }
        let operation_id = self.inner.next_operation_id.fetch_add(1, Ordering::Relaxed);
        let ticket_key = key.clone();
        let cancelled = Arc::new(PendingCancellation {
            cancelled: AtomicBool::new(false),
            notify: tokio::sync::Notify::new(),
        });
        match self.inner.exact_pending_inbound.entry(key) {
            Entry::Vacant(slot) => {
                slot.insert(PendingRecord {
                    owner,
                    operation_id,
                    effect,
                    cancelled: cancelled.clone(),
                });
                Ok(PendingTicket {
                    registry: Arc::downgrade(&self.inner),
                    key: ticket_key,
                    operation_id,
                    cancelled,
                })
            }
            Entry::Occupied(_) => Err(effect),
        }
    }

    /// Settle one single-shot operation, with success or with the client's
    /// error. `true` only if that exact operation was pending and this caller
    /// owned it: the key, the owner and the private operation id must all
    /// match, and the record must be of the single-shot class.
    ///
    /// The class check is what stops a `RpcRespond` from terminating a stream
    /// that happens to share every public coordinate with it.
    pub fn resolve_exact_single(
        &self,
        key: &PendingKey,
        owner: ClientId,
        operation_id: u64,
        result: Result<serde_json::Value, String>,
    ) -> bool {
        let Some((_, pending)) = self
            .inner
            .exact_pending_inbound
            .remove_if(key, |_, pending| {
                pending.owner == owner
                    && pending.operation_id == operation_id
                    && matches!(&pending.effect, PendingInbound::Single(_))
            })
        else {
            return false;
        };
        let PendingInbound::Single(tx) = pending.effect else {
            unreachable!("predicate fixed response class")
        };
        pending.cancelled.cancel();
        let _ = tx.send(result);
        true
    }

    /// Push one chunk into an in-flight stream. `true` if it was accepted.
    ///
    /// Awaits when the queue is full, which is the back-pressure the capacity
    /// policy exists to apply. That wait is what makes the cancellation matter:
    /// the sender and the cancellation are both cloned out here and the map
    /// guard is dropped before the wait, so a settlement that lands meanwhile
    /// cannot be seen by looking the record up again — it is *gone* by then.
    ///
    /// The select is `biased` on cancellation for that reason. Every terminal
    /// path — [`Self::close_exact_stream`], [`Self::unregister`], displacement,
    /// and dropping the [`PendingTicket`] — cancels while holding the map's
    /// write guard, before its own terminal item goes out. So once a stream has
    /// been settled, a blocked chunk answers `false` and is never written: it
    /// cannot appear after the `End` its peer has already been told is final.
    /// A chunk that wins the race outright still lands, ahead of the terminal
    /// item, which is ordinary.
    pub async fn push_exact_stream(
        &self,
        key: &PendingKey,
        owner: ClientId,
        operation_id: u64,
        payload: serde_json::Value,
    ) -> bool {
        let (tx, cancelled) = match self.inner.exact_pending_inbound.get(key) {
            Some(entry) if entry.owner == owner && entry.operation_id == operation_id => {
                match &entry.effect {
                    PendingInbound::Stream(tx) => (tx.clone(), entry.cancelled.clone()),
                    _ => return false,
                }
            }
            _ => return false,
        };
        tokio::select! {
            biased;
            () = cancelled.wait() => false,
            result = tx.send(myownmesh_core::rpc::RpcStreamItem::Chunk(payload)) => result.is_ok(),
        }
    }

    /// Terminate one in-flight stream, cleanly or with the client's error.
    ///
    /// The record is removed and its cancellation fired inside one write
    /// acquisition, before the terminal item is sent, so no chunk still parked
    /// on a full queue can overtake it.
    ///
    /// [`RpcStreamItem::End`] is sent rather than the sender merely dropped:
    /// the error the client supplied is the point, and a drop would report
    /// every ending as the same failure.
    ///
    /// [`RpcStreamItem::End`]: myownmesh_core::rpc::RpcStreamItem::End
    pub async fn close_exact_stream(
        &self,
        key: &PendingKey,
        owner: ClientId,
        operation_id: u64,
        error: Option<String>,
    ) -> bool {
        let Some((_, pending)) = self
            .inner
            .exact_pending_inbound
            .remove_if(key, |_, pending| {
                let matches = pending.owner == owner
                    && pending.operation_id == operation_id
                    && matches!(&pending.effect, PendingInbound::Stream(_));
                if matches {
                    pending.cancelled.cancel();
                }
                matches
            })
        else {
            return false;
        };
        let PendingInbound::Stream(tx) = pending.effect else {
            unreachable!("predicate fixed response class")
        };
        tx.send(myownmesh_core::rpc::RpcStreamItem::End(
            error.map_or(Ok(()), Err),
        ))
        .await
        .is_ok()
    }
}

/// Delegates to [`ClientRegistry::new`], which is itself controls-only.
///
/// Present so the two ways of asking for the same fixture cannot answer
/// differently, not because a registry has a meaningful default. Production
/// names its stream capacity through [`ClientRegistry::with_stream_capacity`],
/// because a stream queue's depth is the local Application Gateway owner's
/// decision and a default would make it a silent one. Neither this nor `new` is
/// compiled into the daemon.
#[cfg(test)]
impl Default for ClientRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_client(
        registry: &ClientRegistry,
    ) -> (Arc<ClientHandle>, mpsc::UnboundedReceiver<ServerOut>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let handle = registry.register(tx);
        (handle, rx)
    }

    #[test]
    fn client_id_roundtrips_through_string() {
        let id = ClientId(42);
        assert_eq!(id.to_string(), "c42");
        let parsed: ClientId = "c42".parse().expect("parse");
        assert_eq!(parsed, id);
        assert!("not-an-id".parse::<ClientId>().is_err());
        assert!("c-99".parse::<ClientId>().is_err());
    }

    #[test]
    fn ids_are_monotonic_and_unique() {
        let reg = ClientRegistry::new();
        let (a, _ra) = fresh_client(&reg);
        let (b, _rb) = fresh_client(&reg);
        let (c, _rc) = fresh_client(&reg);
        assert_eq!(a.id, ClientId(0));
        assert_eq!(b.id, ClientId(1));
        assert_eq!(c.id, ClientId(2));
        assert!(reg.client(a.id).is_some());
        assert!(reg.client(ClientId(99)).is_none());
        assert!(reg.authenticate(a.id, reg.capability(&a)).is_some());
        assert!(reg.authenticate(b.id, reg.capability(&a)).is_none());
    }

    #[test]
    fn disconnect_winner_returns_completed_install_to_its_sole_cleanup_owner() {
        #[derive(Debug)]
        struct Completed(Arc<AtomicU64>);
        impl Drop for Completed {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::AcqRel);
            }
        }

        let reg = ClientRegistry::new();
        let (owner, _) = fresh_client(&reg);
        reg.unregister(owner.id).expect("registered owner");
        let drops = Arc::new(AtomicU64::new(0));
        let installed = Arc::new(AtomicBool::new(false));
        let installed_probe = installed.clone();
        let returned = reg
            .install_if_live(&owner, Completed(drops.clone()), move |completed| {
                installed_probe.store(true, Ordering::Release);
                completed
            })
            .expect_err("disconnect won the shared mutation seam");
        assert!(!installed.load(Ordering::Acquire));
        assert_eq!(drops.load(Ordering::Acquire), 0);
        drop(returned);
        assert_eq!(drops.load(Ordering::Acquire), 1);
    }

    /// The other side of the seam from
    /// `disconnect_winner_returns_completed_install_to_its_sole_cleanup_owner`:
    /// an install that lands while its owner is still registered stays landed,
    /// and the disconnect path hands back the very handle it landed in — which
    /// is what lets the caller's drain find it and close it.
    ///
    /// Bounded deliberately, and the bound is worth stating. A real
    /// `RealtimeFlowHandle` is `pub(crate)` to core and cannot be minted from
    /// this crate, so this drives `install_if_live` generically rather than
    /// `install_realtime_flow`. The ordering under test lives entirely in that
    /// seam — the flow table is only what the closure happens to write to — but
    /// the consequence is that the end-to-end install → disconnect → drain →
    /// close path is still uncovered here.
    #[test]
    fn an_install_that_wins_the_seam_survives_the_disconnect_that_must_clean_it_up() {
        let reg = ClientRegistry::new();
        let (owner, _) = fresh_client(&reg);
        let table: Arc<Mutex<Vec<u32>>> = Arc::new(Mutex::new(Vec::new()));

        let landed = table.clone();
        reg.install_if_live(&owner, 7_u32, move |value| landed.lock().push(value))
            .expect("a registered, connected owner admits the install");
        assert_eq!(&*table.lock(), &[7], "the install ran");

        let returned = reg.unregister(owner.id).expect("registered owner");
        assert!(
            Arc::ptr_eq(&returned, &owner),
            "disconnect answers with the same handle the install landed in"
        );
        assert_eq!(
            &*table.lock(),
            &[7],
            "unregister does not undo a completed install — the drain that runs \
             after it is what releases one, and it can only release what is \
             still there"
        );

        let refused = table.clone();
        assert!(
            reg.install_if_live(&owner, 9_u32, move |value| refused.lock().push(value))
                .is_err(),
            "the same owner admits nothing once it has disconnected"
        );
        assert_eq!(
            &*table.lock(),
            &[7],
            "and the refused value never reached the table"
        );
    }

    #[test]
    fn claim_method_takes_ownership_and_displaces_prior() {
        let reg = ClientRegistry::new();
        let (a, _ra) = fresh_client(&reg);
        let (b, _rb) = fresh_client(&reg);
        let key = ("net".to_string(), "infer".to_string());

        let prev = reg.claim_method(key.clone(), a.id, HandlerMode::Single);
        assert!(prev.is_none());
        assert_eq!(reg.handler_owner(&key), Some(a.id));
        assert!(a.method_claims.contains(&key));

        let prev = reg.claim_method(key.clone(), a.id, HandlerMode::Single);
        assert!(prev.is_none());

        let prev = reg.claim_method(key.clone(), b.id, HandlerMode::Stream);
        assert_eq!(prev, Some(a.id));
        assert_eq!(reg.handler_owner(&key), Some(b.id));
        assert!(b.method_claims.contains(&key));
        assert!(!a.method_claims.contains(&key));
    }

    #[test]
    fn release_method_only_succeeds_for_current_owner() {
        let reg = ClientRegistry::new();
        let (a, _) = fresh_client(&reg);
        let (b, _) = fresh_client(&reg);
        let key = ("net".to_string(), "infer".to_string());

        reg.claim_method(key.clone(), a.id, HandlerMode::Single);
        assert!(!reg.release_method(&key, b.id));
        assert_eq!(reg.handler_owner(&key), Some(a.id));
        assert!(reg.release_method(&key, a.id));
        assert!(reg.handler_owner(&key).is_none());
        assert!(!a.method_claims.contains(&key));
    }

    #[test]
    fn unregister_drops_claims_and_subscriptions() {
        let reg = ClientRegistry::new();
        let (a, _) = fresh_client(&reg);
        let method_key = ("net".to_string(), "infer".to_string());
        let channel_key = ("net".to_string(), "catalog".to_string());

        reg.claim_method(method_key.clone(), a.id, HandlerMode::Single);
        reg.subscribe_channel(channel_key.clone(), a.id);

        assert_eq!(reg.handler_owner(&method_key), Some(a.id));
        assert_eq!(reg.channel_subscribers(&channel_key), vec![a.id]);

        reg.unregister(a.id);

        assert!(reg.handler_owner(&method_key).is_none());
        assert!(reg.channel_subscribers(&channel_key).is_empty());
        assert!(reg.client(a.id).is_none());
    }

    #[test]
    fn unregister_doesnt_collateral_drop_a_displacing_claim() {
        let reg = ClientRegistry::new();
        let (a, _) = fresh_client(&reg);
        let (b, _) = fresh_client(&reg);
        let key = ("net".to_string(), "infer".to_string());

        reg.claim_method(key.clone(), a.id, HandlerMode::Single);
        reg.claim_method(key.clone(), b.id, HandlerMode::Single);
        assert_eq!(reg.handler_owner(&key), Some(b.id));

        reg.unregister(a.id);
        assert_eq!(reg.handler_owner(&key), Some(b.id));
    }

    #[test]
    fn channel_subscribe_first_subscriber_flag() {
        let reg = ClientRegistry::new();
        let (a, _) = fresh_client(&reg);
        let (b, _) = fresh_client(&reg);
        let key = ("net".to_string(), "catalog".to_string());

        assert!(reg.subscribe_channel(key.clone(), a.id), "first sub");
        assert!(!reg.subscribe_channel(key.clone(), b.id), "second sub");

        assert!(!reg.unsubscribe_channel(&key, b.id));
        assert!(reg.unsubscribe_channel(&key, a.id));
    }

    #[tokio::test]
    async fn exact_owner_coordinates_and_operation_identity_all_match() {
        let reg = ClientRegistry::new();
        let (a, _) = fresh_client(&reg);
        let (b, _) = fresh_client(&reg);
        let key = PendingKey {
            network: "n".into(),
            method: "m".into(),
            remote_peer: "peer".into(),
            remote_request_id: "same".into(),
            class: HandlerMode::Single,
        };
        let (tx, rx) = oneshot::channel();
        let Ok(ticket) = reg.insert_exact_pending(key.clone(), a.id, PendingInbound::Single(tx))
        else {
            panic!("first claim must be vacant")
        };
        assert!(!reg.resolve_exact_single(
            &key,
            b.id,
            ticket.operation_id(),
            Ok(serde_json::json!("foreign"))
        ));
        assert!(!reg.resolve_exact_single(
            &key,
            a.id,
            ticket.operation_id() + 1,
            Ok(serde_json::json!("stale"))
        ));
        assert!(reg.resolve_exact_single(
            &key,
            a.id,
            ticket.operation_id(),
            Ok(serde_json::json!("mine"))
        ));
        assert_eq!(
            rx.await.expect("settled").expect("success"),
            serde_json::json!("mine")
        );
    }

    #[test]
    fn collision_refuses_newcomer_and_disconnect_truthfully_settles_owner() {
        let reg = ClientRegistry::new();
        let (a, _) = fresh_client(&reg);
        let key = PendingKey {
            network: "n".into(),
            method: "m".into(),
            remote_peer: "peer".into(),
            remote_request_id: "same".into(),
            class: HandlerMode::Single,
        };
        let (first_tx, first_rx) = oneshot::channel();
        let Ok(_ticket) =
            reg.insert_exact_pending(key.clone(), a.id, PendingInbound::Single(first_tx))
        else {
            panic!("incumbent must be vacant")
        };
        let (new_tx, _new_rx) = oneshot::channel();
        assert!(reg
            .insert_exact_pending(key, a.id, PendingInbound::Single(new_tx))
            .is_err());
        reg.unregister(a.id);
        assert!(
            matches!(first_rx.blocking_recv(), Ok(Err(message)) if message.contains("disconnected"))
        );
    }

    #[test]
    fn identical_remote_id_in_distinct_scopes_does_not_displace() {
        let reg = ClientRegistry::new();
        let (a, _) = fresh_client(&reg);
        let key = |network: &str| PendingKey {
            network: network.into(),
            method: "m".into(),
            remote_peer: "peer".into(),
            remote_request_id: "same".into(),
            class: HandlerMode::Single,
        };
        let (tx_a, _) = oneshot::channel();
        let (tx_b, _) = oneshot::channel();
        assert!(reg
            .insert_exact_pending(key("a"), a.id, PendingInbound::Single(tx_a))
            .is_ok());
        assert!(reg
            .insert_exact_pending(key("b"), a.id, PendingInbound::Single(tx_b))
            .is_ok());
    }

    #[tokio::test]
    async fn handler_displacement_settles_only_that_exact_claim() {
        let reg = ClientRegistry::new();
        let (a, _) = fresh_client(&reg);
        let (b, _) = fresh_client(&reg);
        reg.claim_method(("n".into(), "m".into()), a.id, HandlerMode::Single);
        reg.claim_method(("n".into(), "other".into()), a.id, HandlerMode::Single);
        let key = |method: &str| PendingKey {
            network: "n".into(),
            method: method.into(),
            remote_peer: "peer".into(),
            remote_request_id: "same".into(),
            class: HandlerMode::Single,
        };
        let (m_tx, m_rx) = oneshot::channel();
        let (other_tx, other_rx) = oneshot::channel();
        let Ok(_m) = reg.insert_exact_pending(key("m"), a.id, PendingInbound::Single(m_tx)) else {
            panic!("m")
        };
        let Ok(other) =
            reg.insert_exact_pending(key("other"), a.id, PendingInbound::Single(other_tx))
        else {
            panic!("other")
        };
        assert_eq!(
            reg.claim_method(("n".into(), "m".into()), b.id, HandlerMode::Single),
            Some(a.id)
        );
        assert!(matches!(m_rx.await, Ok(Err(message)) if message.contains("displaced")));
        assert!(reg.resolve_exact_single(
            &key("other"),
            a.id,
            other.operation_id(),
            Ok(serde_json::json!("still-owned"))
        ));
        assert!(
            matches!(other_rx.await, Ok(Ok(value)) if value == serde_json::json!("still-owned"))
        );
    }

    #[tokio::test]
    async fn selected_stream_capacity_applies_backpressure_and_releases() {
        let reg = ClientRegistry::with_stream_capacity(NonZeroUsize::new(1).unwrap());
        let (a, _) = fresh_client(&reg);
        let key = PendingKey {
            network: "n".into(),
            method: "m".into(),
            remote_peer: "peer".into(),
            remote_request_id: "stream".into(),
            class: HandlerMode::Stream,
        };
        let (tx, mut rx) = mpsc::channel(reg.stream_capacity().get());
        let Ok(ticket) = reg.insert_exact_pending(key.clone(), a.id, PendingInbound::Stream(tx))
        else {
            panic!("stream claim")
        };
        assert!(
            reg.push_exact_stream(&key, a.id, ticket.operation_id(), serde_json::json!(1))
                .await
        );
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(1),
            reg.push_exact_stream(&key, a.id, ticket.operation_id(), serde_json::json!(2))
        )
        .await
        .is_err());
        assert_eq!(
            rx.recv().await,
            Some(myownmesh_core::rpc::RpcStreamItem::Chunk(
                serde_json::json!(1)
            ))
        );
        assert!(
            reg.push_exact_stream(&key, a.id, ticket.operation_id(), serde_json::json!(2))
                .await
        );
        let closing = tokio::spawn({
            let reg = reg.clone();
            let key = key.clone();
            let operation_id = ticket.operation_id();
            async move { reg.close_exact_stream(&key, a.id, operation_id, None).await }
        });
        // This control uses Tokio's default current-thread test runtime. After
        // this yield the spawned closer has been polled and can only still be
        // pending because the resident chunk owns the queue's sole permit.
        tokio::task::yield_now().await;
        assert!(
            !closing.is_finished(),
            "the terminal item waits behind the resident chunk instead of overtaking it"
        );
        assert_eq!(
            rx.recv().await,
            Some(myownmesh_core::rpc::RpcStreamItem::Chunk(
                serde_json::json!(2)
            ))
        );
        assert!(closing.await.expect("the closer does not panic"));
        assert_eq!(
            rx.recv().await,
            Some(myownmesh_core::rpc::RpcStreamItem::End(Ok(())))
        );
    }

    #[tokio::test]
    async fn capacity_blocked_chunk_cannot_cross_terminal_settlement() {
        let reg = ClientRegistry::with_stream_capacity(NonZeroUsize::new(1).unwrap());
        let (owner, _) = fresh_client(&reg);
        let owner_id = owner.id;
        let key = PendingKey {
            network: "n".into(),
            method: "m".into(),
            remote_peer: "peer".into(),
            remote_request_id: "ordered".into(),
            class: HandlerMode::Stream,
        };
        let (tx, mut rx) = mpsc::channel(1);
        let Ok(ticket) =
            reg.insert_exact_pending(key.clone(), owner_id, PendingInbound::Stream(tx))
        else {
            panic!("vacant stream")
        };
        let operation_id = ticket.operation_id();
        assert!(
            reg.push_exact_stream(&key, owner_id, operation_id, serde_json::json!(1))
                .await
        );

        let blocked_registry = reg.clone();
        let blocked_key = key.clone();
        let blocked = tokio::spawn(async move {
            blocked_registry
                .push_exact_stream(&blocked_key, owner_id, operation_id, serde_json::json!(2))
                .await
        });
        tokio::task::yield_now().await;
        let closer = {
            let registry = reg.clone();
            let key = key.clone();
            tokio::spawn(async move {
                registry
                    .close_exact_stream(&key, owner_id, operation_id, None)
                    .await
            })
        };

        assert_eq!(
            rx.recv().await,
            Some(myownmesh_core::rpc::RpcStreamItem::Chunk(
                serde_json::json!(1)
            ))
        );
        assert!(!blocked.await.expect("blocked sender joins"));
        assert!(closer.await.expect("closer joins"));
        assert_eq!(
            rx.recv().await,
            Some(myownmesh_core::rpc::RpcStreamItem::End(Ok(())))
        );
        assert_eq!(rx.recv().await, None);
    }

    #[tokio::test]
    async fn stream_terminal_error_is_preserved_exactly() {
        let reg = ClientRegistry::new();
        let (a, _) = fresh_client(&reg);
        let key = PendingKey {
            network: "n".into(),
            method: "m".into(),
            remote_peer: "peer".into(),
            remote_request_id: "err".into(),
            class: HandlerMode::Stream,
        };
        let (tx, mut rx) = mpsc::channel(reg.stream_capacity().get());
        let Ok(ticket) = reg.insert_exact_pending(key.clone(), a.id, PendingInbound::Stream(tx))
        else {
            panic!("stream claim")
        };
        assert!(
            reg.close_exact_stream(&key, a.id, ticket.operation_id(), Some("denied".into()))
                .await
        );
        assert_eq!(
            rx.recv().await,
            Some(myownmesh_core::rpc::RpcStreamItem::End(
                Err("denied".into())
            ))
        );
    }

    #[tokio::test]
    async fn wrong_response_class_retains_same_operation_identity() {
        let reg = ClientRegistry::new();
        let (a, _) = fresh_client(&reg);
        let key = PendingKey {
            network: "n".into(),
            method: "m".into(),
            remote_peer: "peer".into(),
            remote_request_id: "typed".into(),
            class: HandlerMode::Stream,
        };
        let (tx, mut rx) = mpsc::channel(reg.stream_capacity().get());
        let Ok(ticket) = reg.insert_exact_pending(key.clone(), a.id, PendingInbound::Stream(tx))
        else {
            panic!("stream")
        };
        assert!(!reg.resolve_exact_single(
            &key,
            a.id,
            ticket.operation_id(),
            Ok(serde_json::json!("wrong"))
        ));
        assert!(
            reg.push_exact_stream(
                &key,
                a.id,
                ticket.operation_id(),
                serde_json::json!("same-op")
            )
            .await
        );
        assert_eq!(
            rx.recv().await,
            Some(myownmesh_core::rpc::RpcStreamItem::Chunk(
                serde_json::json!("same-op")
            ))
        );
    }
}
