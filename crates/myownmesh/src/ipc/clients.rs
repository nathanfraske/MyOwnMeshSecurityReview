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
//!
//! Every one of them is a [`LeasedMap`], and every entry in every one of them is
//! funded before it exists. That is what makes each of these tables bounded by
//! the process owner's grant rather than by how many method names a local client
//! feels like claiming: an index node is memory the daemon holds on a client's
//! say-so, and a table that admitted entries for free would be an unmetered way
//! for one local process to grow the daemon. So each insertion is an admission
//! and each can be refused, and every removal — including the one that happens
//! when a table is dropped with entries still in it — releases exactly what that
//! entry took.
//!
//! **One lock over all five.** They sit together in [`RegistryTables`] behind a
//! single mutex rather than one mutex each, because almost every operation here
//! touches more than one of them — claiming a method writes three tables, a
//! disconnect writes four — and five locks would mean five acquisition orders to
//! keep consistent forever. Nothing under this lock awaits, and a client's own
//! tables are only ever locked while this one is held, never the reverse.
//!
//! **What is here and what is not.** This file declares the state and what it
//! costs: the tables, the records, the handle, and the exact claims that fund
//! each of them. What the registry *does* with that state is [`registry`], a
//! descendant — which is what lets it hold every operation while every field
//! above stays exactly as private as it was. A sibling module or an outside
//! caller still reaches none of it.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::oneshot;

use myownmesh_core::{
    LeasedMap, LocalApplicationResourceScope, ResourceClaim, ResourceClaimArithmeticError,
    ResourceClass, ResourceLease, ResourceMailboxAdmissionError, ResourceMailboxSender,
    ResourceUnavailable,
};

use super::wire::ServerOut;

/// Encoded width of a minted [`ClientCapability`].
///
/// 32 random bytes in unpadded base64url, which is `ceil(32 * 4 / 3)`. Stated
/// rather than measured because the claim below is taken before the capability
/// exists — the record has to be funded before anything is put in it.
const CLIENT_CAPABILITY_BYTES: usize = 43;

/// Why one thing this registry owns could not be admitted — a client record,
/// or a task the daemon would have to keep running.
///
/// Two arms because they are two different events, exactly as core separates
/// them for a mailbox: the claim being unrepresentable is a defect in this
/// crate's arithmetic, while a refusal is the process owner's envelope being
/// full. Flattening them would report a bug here as ordinary back-pressure.
#[derive(Debug, thiserror::Error)]
pub enum IpcAdmissionError {
    #[error("IPC claim is not representable: {0}")]
    Claim(ResourceClaimArithmeticError),
    #[error("IPC admission was refused by the resource provider: {0:?}")]
    Resources(ResourceUnavailable),
}

/// Why one registration a client asked for could not be installed.
///
/// The two arms are the two things that can go wrong for a method claim, a
/// channel subscription or a realtime flow alike, which is why one type serves
/// all three: either the client stopped being registered while its own request
/// was in flight, or the entry it needed was refused funding. A caller has to
/// answer differently — the first is nobody's fault and there is nobody left to
/// tell, the second is back-pressure the client should see — so they are not
/// flattened.
#[derive(Debug, thiserror::Error)]
pub enum RegistrationError {
    #[error("the local client disconnected before its registration was installed")]
    ClientGone,
    #[error(transparent)]
    Admission(#[from] IpcAdmissionError),
}

/// A completed realtime open that was never installed, handed back with why.
///
/// The handle comes back because it is move-only and owns nothing: dropping it
/// releases neither the label nor the native half behind it. Whoever receives
/// this is the flow's sole close owner, in both arms of `reason`.
pub struct RealtimeFlowRejected {
    pub flow: myownmesh_core::realtime::RealtimeFlowHandle,
    pub reason: RegistrationError,
}

/// What a released method claim leaves behind for a caller with networks.
pub struct MethodRelease {
    /// `true` only if this caller really owned the claim it released. A client
    /// releasing a method a later claimant has since taken gets `false` and
    /// changes nothing.
    pub released: bool,
    /// Set when this was the *last* claim on the method, so the synthetic
    /// handler the bridge installed on the engine now belongs to nobody.
    ///
    /// It has to be answered rather than acted on here: forgetting a handler
    /// needs the `JoinedNetwork` it was installed on, and this module holds
    /// client state, not networks.
    pub forget: bool,
}

/// One removed client, and what removing it left for a caller with networks.
pub struct UnregisteredClient {
    pub handle: Arc<ClientHandle>,
    /// Methods this client was the last claimant of. Each still has a synthetic
    /// handler installed on its network, which now answers every inbound call
    /// with "no claim" — true, but a handler retained for nobody. The caller
    /// forgets them; see [`MethodRelease::forget`] for why not here.
    pub forget: Vec<ClaimKey>,
}

/// An inbound call that could not be tracked, handed back with why.
pub struct PendingRejected {
    /// The engine-side awaiter, returned so the caller drops it deliberately
    /// rather than having it disappear inside a refusal.
    pub effect: PendingInbound,
    pub reason: PendingRefusal,
}

#[derive(Debug, thiserror::Error)]
pub enum PendingRefusal {
    #[error("duplicate inbound RPC coordinates are already pending")]
    Duplicate,
    #[error("the claiming local client disconnected before the call could be tracked")]
    OwnerGone,
    #[error("the inbound call could not be accounted: {0}")]
    Admission(#[from] IpcAdmissionError),
}

/// Exact claim for one IPC task this daemon keeps alive.
///
/// Two dimensions and no byte term. A spawned future's size is not knowable
/// from here — it is an opaque generated type, and each of the three call sites
/// has a different one — so a byte figure written here would be a guess wearing
/// an exact claim's clothes. What *is* exactly true is that the task occupies
/// one runtime worker obligation and one bookkeeping object, and those are the
/// two quantities the process owner's envelope actually bounds.
fn task_claim() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    ResourceClaim::try_from_entries([
        (ResourceClass::WorkerOrTask, 1),
        (ResourceClass::OpaqueDependencyResidual, 1),
    ])
}

/// Exact claim for one registered client's own record.
///
/// Covers what the handle itself retains: its `Arc` allocation and the minted
/// capability's bytes. The three tables it owns are inline fields, so
/// `size_of::<ClientHandle>()` already counts them — an empty [`LeasedMap`] is a
/// null root pointer, a length and a hash seed, and allocates nothing until
/// something is admitted into it.
///
/// It deliberately does *not* cover what those tables later hold. A method
/// claim, a channel subscription or an open flow is funded by the insertion that
/// admits it, so a client that registers and does nothing pays for nothing it is
/// not holding — and, more to the point, a client that claims a thousand methods
/// pays a thousand times rather than once.
///
/// Nor does it cover the registry's own index node for this client. That is not
/// a gap: [`ClientRegistry::register`] acquires that node's claim from the same
/// scope in the same admission, and it has to be a separate claim because the
/// node belongs to the registry's table and is released when the entry is
/// removed, which is a different moment from when the last reference to the
/// handle goes.
fn client_record_claim() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    let overflow = || ResourceClaimArithmeticError::Overflow {
        dimension: ResourceClass::AccountedMemoryBytes,
    };
    let bytes = std::mem::size_of::<ClientHandle>()
        // The strong and weak counts beside the value in one `Arc` allocation.
        .checked_add(2 * std::mem::size_of::<usize>())
        .and_then(|bytes| bytes.checked_add(CLIENT_CAPABILITY_BYTES))
        .ok_or_else(overflow)?;
    let bytes = u64::try_from(bytes).map_err(|_| overflow())?;
    ResourceClaim::try_from_entries([
        (ResourceClass::AccountedMemoryBytes, bytes),
        // The `Arc` allocation and the capability string's own buffer.
        (ResourceClass::OpaqueDependencyResidual, 2),
    ])
}

/// Everything this registry's fixtures acquire, priced from the real APIs.
///
/// `clients` funds that many client records; `entries` funds that many entries
/// *in each* of the registry's tables. Summing the eight node shapes rather than
/// picking the widest is deliberate over-funding, and it is the right kind: a
/// fixture grant that is generous fails only by hiding headroom, while one that
/// is tight fails by refusing a control for reasons the control is not about.
///
/// It lives here rather than beside the grant it feeds because the node types
/// are private to this module. A grant written elsewhere would have to restate
/// them, and every term below comes out of the same function that will charge
/// against it — so this figure and the admission it has to satisfy cannot be
/// derived from two different formulas. That is the failure this shape exists to
/// prevent, and the daemon's IPC mailbox grant already records one instance of
/// it having happened.
#[cfg(test)]
pub(crate) fn registry_fixture_claim(
    clients: u64,
    entries: u64,
) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    let records = client_record_claim()?.checked_scale(clients)?;
    let entry = LeasedMap::<ClientId, Arc<ClientHandle>>::entry_claim()?
        .checked_add(LeasedMap::<ClaimKey, ClientId>::entry_claim()?)?
        .checked_add(LeasedMap::<ClaimKey, HandlerMode>::entry_claim()?)?
        .checked_add(LeasedMap::<ClaimKey, LeasedMap<ClientId, ()>>::entry_claim()?)?
        .checked_add(LeasedMap::<ClientId, ()>::entry_claim()?)?
        .checked_add(LeasedMap::<PendingKey, PendingRecord>::entry_claim()?)?
        .checked_add(LeasedMap::<ClaimKey, ()>::entry_claim()?)?
        .checked_add(LeasedMap::<String, OwnedRealtimeFlow>::entry_claim()?)?;
    records.checked_add(entry.checked_scale(entries)?)
}

/// Who is asking, and which of their things: the client id, the claim key, and
/// the two unforgeable authorities. Values only — nothing in there holds a
/// resource or knows this registry exists.
mod identity;

pub use identity::{ClaimKey, ClientCapability, ClientId, RealtimeFlowCapability};

/// One flow a client owns, and the network it was opened on.
///
/// The network travels with the handle because closing needs a `JoinedNetwork`
/// to close *through*, and asking the client which network its own flow is on
/// would be taking a routing decision from the party being authorized.
struct OwnedRealtimeFlow {
    network: String,
    flow: myownmesh_core::realtime::RealtimeFlowHandle,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
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

    /// Synchronous read, for callers that no longer suspend.
    ///
    /// The stream push used to race this against a bounded channel's
    /// backpressure. There is no backpressure to race now, so the only question
    /// left is the one this answers directly: has this operation already been
    /// cancelled.
    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    async fn wait(&self) {
        loop {
            if self.cancelled.load(Ordering::Acquire) {
                return;
            }
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
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
        let mut tables = registry.tables.lock();
        // This exact operation, or nothing. A later operation that reuses every
        // public coordinate is a different call and not this ticket's to remove.
        let ours = match tables.exact_pending_inbound.get(&self.key) {
            Some(pending) => pending.operation_id == self.operation_id,
            None => false,
        };
        if !ours {
            return;
        }
        if let Some(pending) = tables.exact_pending_inbound.remove(&self.key) {
            pending.cancelled.cancel();
            drop(tables);
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
    Stream(ResourceMailboxSender<myownmesh_core::rpc::RpcStreamItem>),
}

/// State for a single connected event-subscribed client.
pub struct ClientHandle {
    pub id: ClientId,
    capability: ClientCapability,
    connected: AtomicBool,
    disconnected: tokio::sync::Notify,
    /// Mailbox the read loop and bridge code push outbound frames into; a
    /// writer task on the same connection drains it.
    ///
    /// Count-unbounded and resource-bounded: no frame count is invented here,
    /// and every queued frame is funded by the local application scope that
    /// owns this connection. A client that stops reading therefore stops being
    /// admitted rather than growing an unbilled queue in the daemon.
    pub writer_tx: ResourceMailboxSender<ServerOut>,
    /// Method claims this client currently holds. Tracked so disconnect can
    /// find them without walking the registry's whole claim table; the
    /// authoritative routing table is on the registry.
    ///
    /// Private, and it was public. Nothing outside this module ever read it, and
    /// leaving it exposed would have let a caller add a name here that the
    /// registry's own table did not agree with — a client credited with a claim
    /// no inbound call would ever route to.
    method_claims: HeldNames,
    /// Channel subscriptions this client currently holds.
    /// Same disconnect-cleanup rationale, and the same reason for being private.
    channel_subs: HeldNames,
    /// Funding for this record, held rather than read.
    ///
    /// Released when the last reference to this handle goes, which is what
    /// makes an unregistered client's capacity available to the next one
    /// without an explicit release step that a disconnect path could miss.
    _record: ResourceLease,
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
    realtime_flows: Mutex<LeasedMap<String, OwnedRealtimeFlow>>,
}

/// One client's own set of claimed names, funded one name at a time.
///
/// Two fields of a `ClientHandle` are exactly this — held methods and subscribed
/// channels — and they were two `DashSet`s that admitted names for free. A local
/// client chooses how many names go in, so free admission made both of them a
/// way for one process to grow the daemon without the process owner's grant
/// having anything to say about it.
///
/// Every name is now a funded entry. The funding is acquired by the registry,
/// which is the thing that holds the scope, and handed in — a client handle has
/// no acquisition authority of its own and should not grow one.
///
/// The mutex is never held across an await; nothing on this type suspends. It is
/// also only ever locked while the registry's own table lock is held, which is
/// what makes the two orders consistent by construction rather than by
/// convention.
#[derive(Default)]
struct HeldNames(Mutex<LeasedMap<ClaimKey, ()>>);

impl HeldNames {
    fn holds(&self, key: &ClaimKey) -> bool {
        self.0.lock().contains_key(key)
    }

    /// Take a name and the funding that pays for it.
    ///
    /// A name already held is refused by the map, and the refusal releases the
    /// redundant lease as it drops — so a caller that funded speculatively is
    /// corrected rather than charged twice. Every caller in this module checks
    /// [`Self::holds`] first under the registry's table lock, so the refusal
    /// path is a backstop and not the ordinary case.
    fn hold(&self, key: ClaimKey, entry: ResourceLease) {
        let _ = self.0.lock().insert(key, (), entry);
    }

    fn release(&self, key: &ClaimKey) {
        self.0.lock().remove(key);
    }

    /// Owned copies of every name held, for a caller that has to release them
    /// through tables this one does not reach.
    ///
    /// Allocates deliberately: the alternative is calling back into the registry
    /// while this lock is held, which is the one lock order this module does not
    /// take.
    fn snapshot(&self) -> Vec<ClaimKey> {
        let mut names = Vec::new();
        self.0.lock().for_each(|key, ()| names.push(key.clone()));
        names
    }
}

impl ClientHandle {
    /// Take ownership of one open flow and answer the capability naming it.
    ///
    /// The capability is minted here rather than supplied, so a client cannot
    /// choose where its flow is filed or overwrite another of its own.
    ///
    /// `entry` funds the table node this flow will occupy, and is acquired by
    /// the registry before the open is installed. The lease lives in the node,
    /// so taking the flow out again — by close, by disconnect, or by dropping
    /// the handle with flows still in it — releases it without a separate step.
    fn register_realtime_flow(
        &self,
        network: String,
        flow: myownmesh_core::realtime::RealtimeFlowHandle,
        entry: ResourceLease,
    ) -> RealtimeFlowCapability {
        let capability = RealtimeFlowCapability::mint();
        self.realtime_flows
            .lock()
            .insert(
                capability.expose().to_string(),
                OwnedRealtimeFlow { network, flow },
                entry,
            )
            // 32 bytes of OS randomness, minted one line above and never
            // reused. A collision here is not a case to handle; it is evidence
            // the randomness is not random.
            .expect("a freshly minted flow capability cannot already name a flow");
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
    /// Nothing here awaits, so the table's guard is never held across a
    /// suspension point. `effect` is the one thing this cannot see the inside
    /// of, which is why it takes a borrow of the handle and not the guard: a
    /// caller can send on the flow, and cannot park on the table while doing it.
    pub fn with_realtime_flow<R>(
        &self,
        capability: &str,
        network: &str,
        effect: impl FnOnce(&myownmesh_core::realtime::RealtimeFlowHandle) -> R,
    ) -> Option<R> {
        let flows = self.realtime_flows.lock();
        let owned = flows.get(capability)?;
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
        let owned = self.realtime_flows.lock().remove(capability)?;
        Some((owned.network, owned.flow))
    }

    /// Take every flow this client still owns.
    ///
    /// For disconnect and shutdown, where the flows have to be closed *through*
    /// their networks rather than merely dropped — dropping a handle releases
    /// nothing, by design, so a client that vanished would otherwise leave its
    /// labels claimed and its native halves up until the session itself ended.
    /// Taken under one acquisition of the table, unlike the two-phase walk this
    /// replaces: a flow opened between the old snapshot and the old removal
    /// survived the drain and was never closed.
    pub fn drain_realtime_flows(
        &self,
    ) -> Vec<(String, myownmesh_core::realtime::RealtimeFlowHandle)> {
        let mut flows = self.realtime_flows.lock();
        let mut capabilities = Vec::new();
        flows.for_each(|capability, _| capabilities.push(capability.clone()));
        capabilities
            .into_iter()
            .filter_map(|capability| flows.remove(&capability))
            .map(|owned| (owned.network, owned.flow))
            .collect()
    }

    /// Queue one frame for this client's writer task.
    ///
    /// The refusal is returned rather than swallowed because the two ways this
    /// can fail are not the same event, and they used to be flattened into the
    /// same discarded `Err`. `Closed` means the connection is gone and the
    /// registry will drop this handle shortly — nothing was owed to anyone.
    /// `Pressure` and `Claim` mean the frame was real, the client is still
    /// connected, and it will never see it. A caller with a peer waiting on the
    /// other end has to say so rather than leave them to time out.
    pub fn send(&self, frame: ServerOut) -> Result<(), ResourceMailboxAdmissionError> {
        self.writer_tx
            .send(frame)
            .map_err(|refusal| refusal.into_admission_error())
    }

    pub async fn wait_disconnected(&self) {
        loop {
            if !self.connected.load(Ordering::Acquire) {
                return;
            }
            let notified = self.disconnected.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
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
    /// Every routing table this registry owns, under one acquisition.
    ///
    /// This replaced a bare `Mutex<()>` fence beside five separately-locked
    /// `DashMap`s. The fence made the multi-table operations atomic with respect
    /// to each other, but the single-table readers bypassed it, so a reader
    /// could see a claim installed and the client that owned it already gone.
    /// There is one acquisition now, and no way to read one table without it.
    tables: Mutex<RegistryTables>,
    /// The one acquisition port everything this registry admits is funded
    /// from. It is supplied rather than reached for: the registry has no
    /// authority of its own, and a daemon that could mint some here would be
    /// able to admit clients the process owner never granted capacity for.
    resources: LocalApplicationResourceScope,
    next_id: AtomicU64,
    next_call_stream_id: AtomicU64,
    next_operation_id: AtomicU64,
}

/// The registry's five routing tables, which are only ever reached together.
///
/// Each is a [`LeasedMap`], so each entry is funded before it exists and
/// released when it is removed — including when this whole struct is dropped
/// with entries still in it, which is the daemon-shutdown case.
struct RegistryTables {
    clients: LeasedMap<ClientId, Arc<ClientHandle>>,
    handler_claims: LeasedMap<ClaimKey, ClientId>,
    /// Subscribers per (network, channel), as a funded set of funded members.
    ///
    /// Nested rather than a `Vec`, because both counts are chosen by local
    /// clients: how many channels get subscribed to, and how many clients
    /// subscribe to each. A `Vec` would have funded the first and not the
    /// second. The outer entry appears with its first member and is removed with
    /// its last, so an unsubscribed channel costs nothing — the previous shape
    /// left an empty subscriber list behind forever.
    channel_subs: LeasedMap<ClaimKey, LeasedMap<ClientId, ()>>,
    exact_pending_inbound: LeasedMap<PendingKey, PendingRecord>,
    /// Which shape of synthetic handler the bridge has installed on the engine
    /// for each claim. Kept so a re-claim of the same method does not have to
    /// ask the engine what it already holds, and so the last unclaim knows there
    /// is a handler to forget.
    installed_handlers: LeasedMap<ClaimKey, HandlerMode>,
}

impl RegistryTables {
    /// Look one client up while the tables are already held.
    ///
    /// Exists because [`ClientRegistry::client`] takes the same lock, and this
    /// mutex is not reentrant: every method here that both locks and needs a
    /// client handle calls this instead, which is the whole of the discipline.
    fn client(&self, id: ClientId) -> Option<Arc<ClientHandle>> {
        self.clients.get(&id).cloned()
    }
}

impl RegistryInner {
    /// Fund one entry in one of this registry's tables, before it is inserted.
    ///
    /// Generic over the table's key and value because the claim is exactly the
    /// size of that table's node — [`LeasedMap::entry_claim`] is the single
    /// calibration point, and an owner that wrote a node size itself would be
    /// stating a number the map is free to change.
    fn lease_entry<K, V>(&self) -> Result<ResourceLease, IpcAdmissionError> {
        self.resources
            .acquire(LeasedMap::<K, V>::entry_claim().map_err(IpcAdmissionError::Claim)?)
            .map_err(IpcAdmissionError::Resources)
    }
}

/// Which shape of synthetic handler is installed for a claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HandlerMode {
    Single,
    Stream,
}

/// Every operation this registry performs on the tables declared above.
///
/// A descendant, so it reaches every private field here without any of them
/// being widened for it. What the state *is* stays with the claims that fund
/// it; what is *done* with it lives there.
mod registry;

#[cfg(test)]
mod tests;
