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

#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::oneshot;

use myownmesh_core::{
    FundedArc, LeasedMap, LocalApplicationResourceScope, ResourceClaim,
    ResourceClaimArithmeticError, ResourceClass, ResourceLease, ResourceMailboxAdmissionError,
    ResourceMailboxSender, ResourceUnavailable,
};

use super::wire::ServerOut;

/// Encoded width of a minted [`ClientCapability`].
///
/// 32 random bytes in unpadded base64url, which is `ceil(32 * 4 / 3)`. Stated
/// rather than measured because the claim below is taken before the capability
/// exists — the record has to be funded before anything is put in it.
const CLIENT_CAPABILITY_BYTES: usize = 43;

/// Encoded width of a minted [`RealtimeFlowCapability`].
///
/// The same 32-byte mint in the same encoding, named separately because the two
/// authorities are free to diverge and a shared constant would silently make one
/// of them wrong if either did.
const REALTIME_CAPABILITY_BYTES: usize = 43;

/// Why one thing this registry owns could not be admitted — a client record,
/// or a task the daemon would have to keep running.
///
/// Three arms because they are three different events, and a caller that could
/// not tell them apart would misreport two of them. `Claim` is a defect in this
/// crate's arithmetic; `Resources` is the process owner's envelope being full,
/// which is ordinary back-pressure and may pass later; `Closing` is the runtime
/// shutting down, which will never pass and is not a shortage of anything.
/// Flattening any pair of them would report a bug, or a shutdown, as capacity.
#[derive(Debug, thiserror::Error)]
pub enum IpcAdmissionError {
    #[error("IPC claim is not representable: {0}")]
    Claim(ResourceClaimArithmeticError),
    #[error("IPC admission was refused by the resource provider: {0:?}")]
    Resources(ResourceUnavailable),
    /// The control runtime has begun closing, so nothing further is admitted.
    ///
    /// An admission answer rather than a separate error type because it is the
    /// same question with a third reason: a caller asked the registry to take
    /// on something new, and it will not. Callers already branch on refusal
    /// here, and the shape they need — install nothing, tell the client, do not
    /// retry — is identical for all three arms.
    #[error("the control runtime is closing and admits nothing further")]
    Closing,
}

/// Everything one registry is still holding, at one instant.
///
/// `PartialEq` and a `Default` of all zeroes so a control can say what it means
/// — `assert_eq!(residue, RegistryResidue::empty(Lifecycle::Closed))` — rather
/// than a column of individually-passing field assertions that between them
/// still permit a leftover nobody thought to check.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryResidue {
    pub lifecycle: Lifecycle,
    pub live_tasks: u64,
    pub watchdogs: u64,
    pub clients: u64,
    pub realtime_flows: u64,
    pub handler_claims: u64,
    pub installed_handlers: u64,
    pub channel_subs: u64,
    /// Routes, not members. A route with no members should not exist, so a
    /// nonzero count here beside a zero `channel_subs` is a leaked route — the
    /// exact residue a member-only count cannot see.
    pub channel_routes: u64,
    /// Routes still in `Installing`. A terminal registry with one of these has
    /// an install that never published its outcome, and a follower somewhere is
    /// still waiting on it.
    pub installing_routes: u64,
    pub pending_inbound: u64,
}

#[cfg(test)]
impl RegistryResidue {
    /// The same, with `live_tasks` set.
    ///
    /// Separate from [`Self::empty`] because a live accepted task is not a
    /// leftover -- it is the thing `serve` is waiting for -- and a control
    /// asserting mid-shutdown has to be able to say "the tables are empty and
    /// exactly one task is still running" as one value rather than as an empty
    /// comparison it then has to except a field from.
    pub fn with_tasks(mut self, live_tasks: u64) -> Self {
        self.live_tasks = live_tasks;
        self
    }

    /// Holding nothing, in the named state.
    pub fn empty(lifecycle: Lifecycle) -> Self {
        Self {
            lifecycle,
            live_tasks: 0,
            watchdogs: 0,
            clients: 0,
            realtime_flows: 0,
            handler_claims: 0,
            installed_handlers: 0,
            channel_subs: 0,
            channel_routes: 0,
            installing_routes: 0,
            pending_inbound: 0,
        }
    }
}

/// Where the control runtime is in its life.
///
/// Three states and one direction. `Running` admits; `Closing` refuses every
/// new admission while the drain runs and the tasks already accepted finish;
/// `Closed` is reached only once no accepted task is still live, which is what
/// makes `control::serve` returning mean the daemon's control surface is
/// actually over rather than merely no longer accepting.
///
/// It lives *inside* [`RegistryTables`], under the same mutex as the routing
/// tables, deliberately. A separate `AtomicBool` beside the tables would let a
/// registration read `Running`, be preempted, and install itself into tables the
/// drain had already walked — an orphan the shutdown path has no second pass to
/// find. Sharing the one acquisition means "is the runtime still admitting" and
/// "what is in the tables" are answered by the same lock at the same instant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lifecycle {
    Running,
    Closing,
    Closed,
}

/// Why one registration a client asked for could not be installed.
///
/// Two of the arms are the two things that can go wrong for a method claim, a
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
    /// The network's application gateway closed between funding this
    /// registration and publishing it. Distinct from [`Self::ClientGone`]
    /// because the client is fine and there is nothing for it to retry against.
    #[error("the network's gateway closed before the registration was published")]
    GatewayRevoked,
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

/// What a released method claim leaves behind.
///
/// `#[must_use]` because dropping this is the act that removes the handler: the
/// registration inside is what tells core to forget it, and a caller that
/// discards this value without meaning to has silently done the removal anyway.
#[must_use = "dropping this removes the synthetic handler the claim installed"]
pub struct MethodRelease {
    /// `true` only if this caller really owned the claim it released. A client
    /// releasing a method a later claimant has since taken gets `false` and
    /// changes nothing.
    pub released: bool,
    /// The core registration this release retired, if it retired one.
    ///
    /// Carried out rather than dropped in place, and this is the whole reason
    /// the type exists. Dropping an [`OwnedMethodRegistration`] takes core's
    /// handlers lock; the registry holds its own tables lock while it removes
    /// the record. Dropping it there would be daemon-lock → core-lock, the one
    /// direction this daemon never takes. Out here the tables lock is already
    /// gone.
    ///
    /// [`OwnedMethodRegistration`]: myownmesh_core::rpc::OwnedMethodRegistration
    _retired: Option<InstalledHandler>,
}

impl MethodRelease {
    /// Whether this release took an installed handler out with it.
    ///
    /// Controls only. Production does not branch on it: dropping this value is
    /// the removal, so there is nothing for a caller to decide.
    #[cfg(test)]
    pub fn retired(&self) -> bool {
        self._retired.is_some()
    }
}

/// One step of a channel fan-out.
///
/// Three outcomes because a caller answers them differently. `Next` is the
/// subscriber to deliver to; the registry advances the cursor inside the
/// caller's [`ChannelFanout`]. `End` means this frame has no further subscribers
/// to reach, which is an ordinary end to one frame's fan-out; `Gone` means this
/// pump's route is no longer the route under this key, which is the end of the
/// pump rather than of the frame. Collapsing the last two would make
/// "delivered to nobody" and "there is nothing here to deliver through" the
/// same answer.
pub(crate) enum ChannelFanoutStep {
    Next { client: FundedArc<ClientHandle> },
    End,
    Gone,
}

/// Which installation of a route a fan-out step belongs to.
///
/// A channel key is coordinates. The route under it can be removed and
/// reinstalled — last subscriber leaves, a new one arrives — while a pump that
/// belonged to the *previous* installation is between two steps of a frame it
/// started earlier. Matching on the key alone would let that pump walk the
/// successor's subscriber set and deliver a frame from a subscription those
/// clients never made.
///
/// The identity is the one the route lifecycle already has: the exact
/// [`RouteCancellation`] `Arc` the pump was given and the route holds in its
/// `Live` state. No generation, no ledger, no second answer to keep in step —
/// pointer equality on the value that already means "this pump".
pub(crate) enum RouteOwner<'a> {
    /// A live pump, matched against the route's own owner.
    Pump(&'a FundedArc<RouteCancellation>),
    /// No pump to match. Controls only: a control inspects a route's membership
    /// without being one of its pumps, including while the route is still
    /// installing.
    #[cfg(test)]
    Any,
}

/// One frame's position in its own fan-out: who it has reached, and the
/// boundary it may not walk past.
///
/// Built once per frame and threaded through that frame's steps. The boundary is
/// the finding: client ids are monotonic, so every client that subscribes during
/// a fan-out has an id greater than the cursor and would be walked to next — and
/// a channel whose subscribers keep arriving would keep one frame's fan-out
/// going for as long as they kept arriving, so the pump would never take the
/// next frame. Fixing the highest member at the first step bounds the frame by
/// the membership it began with. A client that subscribes mid-frame is simply
/// not part of that frame, which is the truthful answer: it was not subscribed
/// when the frame arrived.
pub(crate) struct ChannelFanout {
    /// Resume strictly after this subscription instance.
    after: Option<ChannelMembershipId>,
    /// The largest member id this frame may reach, fixed at the first step.
    /// `None` until then.
    ceiling: Option<ChannelMembershipId>,
}

impl ChannelFanout {
    /// A fresh position, for one frame.
    pub(crate) fn frame() -> Self {
        Self {
            after: None,
            ceiling: None,
        }
    }
}

impl Default for ChannelFanout {
    fn default() -> Self {
        Self::frame()
    }
}

/// One removed client, and what removing it left for a caller with networks.
pub struct UnregisteredClient {
    pub handle: FundedArc<ClientHandle>,
    /// Methods this client was the last claimant of, each carrying the core
    /// registration that removes its synthetic handler.
    ///
    /// Handed out rather than dropped in place for the same reason
    /// [`MethodRelease`] is: `unregister` is holding the tables lock, and
    /// releasing a registration takes core's handlers lock. Dropping this
    /// vector is what forgets the handlers, and it happens where no daemon lock
    /// is held.
    ///
    /// Each entry also carries the funding for its own name, so the names in
    /// this list are accounted for as long as the caller holds them and are
    /// released when it drops them — not when they left the table.
    ///
    /// A [`LeasedList`] and not a `Vec`, and the difference is not cosmetic: a
    /// `Vec`'s buffer is sized by capacity rather than by length, and its `Drop`
    /// destroys every element — and any lease inside one — before it frees the
    /// shared buffer those elements sat in. Here each entry is its own
    /// allocation, funded by a lease the client acquired when it took the claim
    /// and released only after that allocation is gone.
    ///
    /// [`LeasedList`]: crate::ipc::LeasedList
    pub(crate) forget: crate::ipc::LeasedList<ForgottenMethod>,
    /// Routes this client was the last subscriber of.
    ///
    /// Returned rather than finished in `unregister`, for the same reason
    /// `forget` is: retiring a route means awaiting a task, and that method is
    /// synchronous and holding a lock. The caller retires each one before it
    /// reports the client released — and it must, because `serve` will not
    /// return while any of these pumps is still counted alive.
    ///
    /// One list, not one per outcome: a route that was live and a route that
    /// was still installing are the same obligation at different stages, and
    /// splitting them would be a second allocation to say so. Each node was
    /// pre-paid by the channel subscription that occupies it, on the same
    /// pattern as `forget`.
    pub(crate) routes: crate::ipc::LeasedList<RetiredRoute>,
}

/// One method a disconnect retired: its name, still funded, and the core
/// registration that removes its handler.
#[must_use = "dropping this removes the synthetic handler the claim installed"]
pub struct ForgottenMethod {
    pub key: ClaimKey,
    /// Declared after the key, so a reader of `key` above cannot be looking at
    /// a name whose handler has already gone.
    _retired: Option<InstalledHandler>,
    /// Declared last so the name's buffers are released after everything that
    /// reads them.
    _funding: ResourceLease,
}

impl ForgottenMethod {
    fn new(key: ClaimKey, retired: Option<InstalledHandler>, funding: ResourceLease) -> Self {
        Self {
            key,
            _retired: retired,
            _funding: funding,
        }
    }
}

/// One inbound call's funding, acquired before the call's own state exists.
///
/// The first half of a two-phase filing, and it exists for the ordering. The
/// `PendingKey` is four copies of peer-chosen coordinates, and the oneshot or
/// stream inbox answers the call; building either before asking whether it can
/// be admitted lets a remote peer force those allocations at whatever rate it
/// chose
/// to call, and the refusal, when it came, came after the memory it was refusing
/// had already been taken.
///
/// Everything here is derived from *borrowed* coordinates, so a refusal costs
/// nothing but the answer. What the caller builds afterwards — the key, the
/// channel, the frame — is built against funding that already exists.
///
/// The outbound frame is deliberately **not** here. It was, in the shape of a
/// third network copy, and that was an overcharge with the right instinct: this
/// lease lives until the call settles, while the frame dies as soon as the
/// client's writer mailbox has taken it, so binding the two would report a
/// network name as retained for the whole of an operation that stopped holding
/// it in the first millisecond. The frame is admitted by the writer mailbox
/// itself, from a borrowed measurement, and funded by that mailbox's own lease
/// for exactly the window in which it exists — see `bridge::RpcInboundBuilder`.
#[must_use = "a prepared pending call has acquired funding that its commit or its drop must account for"]
pub struct PreparedPending {
    key: ClaimKey,
    class: HandlerMode,
    owner: ClientId,
    entry: ResourceLease,
    retained: ResourceLease,
    cancellation: ResourceLease,
    cleanup: ResourceLease,
}

/// An inbound call that could not be tracked, handed back with why.
///
/// Controls only. Production files through
/// [`ClientRegistry::prepare_exact_pending`] and
/// [`ClientRegistry::commit_exact_pending`], whose refusals construct no effect
/// at all and so have none to hand back — which is the stronger property, since
/// an effect returned from a refusal outlives the prepared leases that were
/// covering it.
#[cfg(test)]
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
    /// The class a call was funded under is not the class it was filed under.
    ///
    /// Unreachable from production, and checked anyway. The two narrowed commits
    /// each pass a constant that matches the preparation they accept, so this
    /// cannot be produced by calling them — but "unreachable by construction" is
    /// a claim that stops being true silently, and what it would cost to be
    /// wrong is a stream's sender filed under a single-shot's funding, answering
    /// a peer in a shape it never asked for.
    #[error("the inbound call was funded in one handler class and filed in another")]
    ClassMismatch,
}

/// One accepted task's funding and its place in the join count.
///
/// Two things that must end at the same moment, so they are one value. The
/// lease releases the task's share of the grant; the count is what
/// [`ClientRegistry::wait_for_tasks`] is waiting on. Separating them would let a
/// task's resources be returned while `serve` still believed it was live, or —
/// worse in the other order — let `serve` return while a task it had stopped
/// counting was still running.
///
/// Move it into the spawned future. Dropping it anywhere else decrements for a
/// task that has not finished.
#[must_use = "the task's funding and its place in the shutdown join both end when this is dropped"]
pub struct TaskAdmission {
    _lease: ResourceLease,
    /// Declared after the lease so the count is decremented last: a waiter woken
    /// by the decrement then finds the resources already released, rather than
    /// observing zero live tasks over a grant still holding one task's share.
    _gate: TaskGate,
}

impl TaskAdmission {
    fn new(lease: ResourceLease, inner: Arc<RegistryInner>) -> Self {
        Self {
            _lease: lease,
            _gate: TaskGate { inner },
        }
    }
}

/// The decrement half of [`TaskAdmission`], as its own drop.
struct TaskGate {
    inner: Arc<RegistryInner>,
}

impl Drop for TaskGate {
    fn drop(&mut self) {
        // Waking only on the transition to zero, rather than on every task end,
        // keeps a busy daemon from repeatedly waking a drain that is not
        // running. The wake is outside the lock: waking under it would put the
        // woken drain straight into a method that takes the same lock.
        let last = {
            let mut tables = self.inner.tables.lock();
            tables.live_tasks = tables
                .live_tasks
                .checked_sub(1)
                .expect("every decrement pairs with an increment taken under this same lock");
            tables.live_tasks == 0
        };
        if last {
            self.inner.idle.notify_waiters();
        }
    }
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

/// The exact one-task claim exposed to the daemon test grant and its controls.
///
/// Keeping this seam beside [`task_claim`] makes the process-wide fixture pay
/// for the same worker and residual terms that [`ClientRegistry::lease_task`]
/// acquires, rather than maintaining a second formula in the crate root.
#[cfg(test)]
pub(crate) fn task_claim_for_test() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    task_claim()
}

/// One IPC task's exact provider reservation charge for test-grant planning.
///
/// The provider's own planning helper adds the reservation record that exists
/// when the task lease is held; callers must fund that record before acquiring
/// the task claim, just as they do for every other finite test reservation.
#[cfg(test)]
pub(crate) fn task_reservation_planning_charge_for_test(
) -> Result<ResourceClaim, myownmesh_core::ResourceUnavailable> {
    let claim = task_claim().expect("the fixed IPC task claim is representable");
    myownmesh_core::FiniteResourceProvider::reservation_planning_charge(claim)
}

/// Price an isolated cohort from the exact number of task owners the fixture
/// will hold. The owner count belongs to the caller because only the fixture
/// can know how many leases it actually retains; this helper owns the shape of
/// one task and the provider's reservation record, so no caller can restate
/// either term when building its private grant.
#[cfg(test)]
pub(crate) fn task_cohort_reservation_planning_charge_for_test(
    owners: usize,
) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    let owners = u64::try_from(owners).map_err(|_| ResourceClaimArithmeticError::Overflow {
        dimension: ResourceClass::WorkerOrTask,
    })?;
    let per_owner = task_reservation_planning_charge_for_test()
        .expect("the fixed IPC task reservation is representable");
    per_owner.checked_scale(owners)
}

/// [`task_claim`] plus the heap a task's captured state holds for its lifetime.
///
/// Additive rather than a second claim so the task and the state it carries are
/// admitted or refused together: a task admitted whose captures were then
/// refused would have to be aborted after it had already been spawned, and a
/// capture admitted whose task was refused would be funding nothing.
///
/// `retained` is bytes the *caller* can state exactly -- a `String` it is about
/// to clone into the future, whose length it holds. It is not a guess at
/// `size_of` the generated future, which [`task_claim`] explains is unknowable
/// from here. The extra residual is the allocation those bytes live in, whose
/// real size the allocator picks: `String::clone` reserves at least the length
/// and may round up, exactly as the control reader's buffers do.
fn task_claim_retaining(retained: usize) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    let retained = u64::try_from(retained).map_err(|_| ResourceClaimArithmeticError::Overflow {
        dimension: ResourceClass::AccountedMemoryBytes,
    })?;
    ResourceClaim::try_from_entries([
        (ResourceClass::WorkerOrTask, 1),
        (ResourceClass::OpaqueDependencyResidual, 1),
        (ResourceClass::AccountedMemoryBytes, retained),
    ])
}

/// Claim for one registered client's own record.
///
/// Covers the handle's visible record and the minted capability's bytes. The
/// three tables it owns are inline fields, so
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
/// handle goes. `FundedArc` internalizes this lease beside every pointer clone.
fn client_record_claim() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    let overflow = || ResourceClaimArithmeticError::Overflow {
        dimension: ResourceClass::AccountedMemoryBytes,
    };
    let bytes = std::mem::size_of::<ClientHandle>()
        .checked_add(CLIENT_CAPABILITY_BYTES)
        .ok_or_else(overflow)?;
    let bytes = u64::try_from(bytes).map_err(|_| overflow())?;
    ResourceClaim::try_from_entries([
        (ResourceClass::AccountedMemoryBytes, bytes),
        // One broad residual covers dependency-private shared-allocation and
        // string-buffer metadata without making allocator layout an invariant.
        (ResourceClass::OpaqueDependencyResidual, 1),
    ])
    // No sweep slot. The drain takes the first client still in the table,
    // releases it, and asks again, so no vector of ids exists to be funded.
    // An allocation that does not happen needs no funding and
    // cannot be refused, which is a stronger answer than pre-payment.
}

/// What one table entry retains *beyond* the node the map funds.
///
/// [`LeasedMap::entry_claim`] funds the node and says so: it explicitly excludes
/// anything the key or value owns off-node, because the map cannot know what
/// that is. For this registry that exclusion is the whole exposure — almost
/// every table here is keyed by a string a local client chose, and the node is a
/// fixed size no matter how long that string is. A client subscribing to one
/// channel with a megabyte-long name was charged the same as one with a
/// one-byte name, and the difference was heap the daemon held and nothing had
/// admitted.
///
/// `bytes` is what the caller can state exactly: the lengths of the buffers the
/// entry will own. One broad residual covers dependency-private allocation
/// metadata instead of counting String allocator events as protocol state.
fn retained_claim(bytes: usize) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    let bytes = u64::try_from(bytes).map_err(|_| ResourceClaimArithmeticError::Overflow {
        dimension: ResourceClass::AccountedMemoryBytes,
    })?;
    ResourceClaim::try_from_entries([
        (ResourceClass::AccountedMemoryBytes, bytes),
        (ResourceClass::OpaqueDependencyResidual, 1),
    ])
}

/// The sum of several buffer lengths, or the typed refusal if it is not
/// representable.
///
/// `checked_add` and not `saturating_add`, and the difference is the whole
/// point: every length here is chosen by a local client or comes off the wire,
/// so the sum is attacker-influenced. Saturating turns an unrepresentable total
/// into `usize::MAX` -- which fits in a `u64` on a 64-bit target and is
/// therefore *accepted* as a claim, silently charging less than the truth for
/// the one input shaped to overflow. Refusing is the only honest answer to a
/// length this code cannot represent.
fn total_len(
    lengths: impl IntoIterator<Item = usize>,
) -> Result<usize, ResourceClaimArithmeticError> {
    lengths
        .into_iter()
        .try_fold(0usize, |total, len| total.checked_add(len))
        .ok_or(ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        })
}

/// The heap a [`ClaimKey`] owns: two client-chosen strings.
fn claim_key_retained(key: &ClaimKey) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    retained_claim(total_len([key.0.len(), key.1.len()])?)
}

/// The heap a [`PendingKey`] owns: four client- or peer-chosen strings.
///
/// `class` is a `Copy` discriminant and lives in the node, so it is not counted
/// here. The four that are counted include `remote_peer` and
/// `remote_request_id`, which come off the wire rather than from the local
/// client — a remote peer's contribution to what this daemon retains, funded
/// from the same grant because the memory is just as real.
#[cfg(test)]
fn pending_key_retained(key: &PendingKey) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    pending_key_retained_for(
        &key.network,
        &key.method,
        &key.remote_peer,
        &key.remote_request_id,
    )
}

/// The same measurement, from coordinates that have not been copied yet.
///
/// This is the seam that lets a pending call be *admitted before it is built*.
/// Every term above is a length, and a length is readable from a borrow — so the
/// claim can be derived, and refused, while the peer's coordinates still exist
/// only as the borrowed fields of the inbound call. The keyed form calls this one
/// rather than restating it, so the pre-admission figure and the figure the
/// record is finally charged cannot drift.
fn pending_key_retained_for(
    network: &str,
    method: &str,
    remote_peer: &str,
    remote_request_id: &str,
) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    let bytes = total_len([
        network.len(),
        method.len(),
        remote_peer.len(),
        remote_request_id.len(),
    ])?;
    retained_claim(bytes)
}

/// Claim for one funded shared record whose visible value type is `T`.
///
/// The record bytes are knowable here. One broad residual covers the shared
/// allocation and dependency-private metadata; control-block layout and
/// allocator padding are deliberately not part of the resource contract.
fn funded_record_retained<T>() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    retained_claim(std::mem::size_of::<T>())
}

/// Everything one accepted pending call retains beyond its table node.
///
/// **Two** copies of the four coordinate strings, not one. The map holds one and
/// the [`PendingTicket`] clones a second, and neither is a borrow of the other,
/// so the pair is what is really retained for as long as the call is live.
///
/// Two, because `pop_first_where` detaches only the first matching node and
/// leaves the rejected ones where they are: a predicate-selected sweep needs no
/// snapshot of keys to know what to remove, so no third copy and no vector
/// exists to be funded.
///
/// The visible `PendingFunding` record is charged in bytes. Shared-allocation
/// metadata is covered by one broad residual rather than exact Arc layout.
///
/// The `PendingInbound` effect's channel state stays an opaque residual: it is a
/// library allocation whose size is not this crate's to state, and a number
/// invented for it would be a guess wearing a measurement's clothes.
///
/// One sweep slot, not two, and only for one of the three sweeps. Disconnect and
/// shutdown settle a record at a time straight out of the table and allocate
/// nothing — a stronger guarantee than pre-payment, since an allocation that
/// does not happen cannot be refused. Claim displacement still collects, because
/// it must detach the previous owner's calls under the same acquisition that
/// moves the claim, and it is that vector's slot this pays for.
///
/// The multiplicity is the part a node-shaped charge misses entirely.
/// `entry_claim` prices one node; every copy above lives somewhere the map never
/// sees.
#[cfg(test)]
fn pending_retained(key: &PendingKey) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    pending_retained_for(
        &key.network,
        &key.method,
        &key.remote_peer,
        &key.remote_request_id,
    )
}

/// [`pending_retained`] from borrowed coordinates, for the admission that runs
/// before any of them has been copied.
fn pending_retained_for(
    network: &str,
    method: &str,
    remote_peer: &str,
    remote_request_id: &str,
) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    let key_retention = pending_key_retained_for(network, method, remote_peer, remote_request_id)?;
    // The visible funded record has explicit bytes and one broad residual.
    let shared = funded_record_retained::<PendingFunding>()?;
    key_retention
        .checked_scale(2)?
        .checked_add(shared)?
        // The effect's channel state is a library allocation whose size is not
        // this crate's to state, so it stays an honestly named residual rather
        // than a guess dressed as a measurement.
        .checked_add(retained_claim(0)?)
    // The sweep node is *not* here. It is acquired as its own lease beside this
    // one and travels into the node it pays for, because a node's funding
    // cannot be a term of a claim released when the table entry is removed --
    // the node outlives that removal by construction, since it is what the
    // removal produces.
}

fn pending_cancellation_claim() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    funded_record_retained::<PendingCancellation>()
}

/// Everything one installed realtime flow retains beyond its table node.
///
/// The capability string this table is keyed by, the network name the value
/// holds, and the slot the pair occupies when a disconnect sweeps them out.
/// Two allocations: one buffer each.
///
/// The capability is a fixed 32-byte mint rather than a client-chosen name, so
/// it is not the attacker-sized term here — the network name is, and it is the
/// reason this cannot be a constant.
fn realtime_flow_retained(
    capability: usize,
    network: &str,
) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    retained_claim(total_len([capability, network.len()])?)
    // The drain node is acquired as its own lease beside this one, for the
    // reason `pending_retained` gives: a node's funding cannot be a term of a
    // claim released when the table entry is removed.
}

// The cleanup charge names an owner rather than a shared buffer. Charging
// `size_of::<T>()` and one residual per installed entry against a
// shared-capacity `Vec` would be wrong in two mechanical ways: a `Vec`'s
// allocation is sized by capacity rather than length, so geometric
// growth retained slots no entry had paid for and extra residuals do not fund
// missing bytes; and the per-entry funding was released when the entry left the
// table, while the shared buffer went on living. Cleanup storage is now
// [`LeasedList`], one allocation per item, and each entry acquires that node's
// claim as a *separate* lease that travels into the node it pays for and is
// released after that node is freed.
//
// The charge is taken at install time because a cleanup claim taken on the
// disconnect path could be refused, and a disconnect path that cannot allocate
// has no honest answer left -- it cannot decline to clean up. Charging when the
// entry is installed makes the client pay in advance for its own removal.
//
// [`LeasedList`]: crate::ipc::LeasedList

/// Everything this registry's fixtures acquire, priced from the real APIs.
///
/// `clients` funds that many client records and client-index nodes; `entries`
/// funds that many entries *in each* of the registry's tables, at `coordinate`
/// bytes of client-chosen name per entry. Every reservation is priced through
/// `FiniteResourceProvider::reservation_planning_charge`, and the total also
/// includes the registry scope's planning charge. Summing the eight node shapes
/// rather than picking the widest is deliberate over-funding, and it is the
/// right kind: a fixture grant that is generous fails only by hiding headroom,
/// while one that is tight fails by refusing a control for reasons the control
/// is not about.
///
/// `coordinate` is not decoration. Entries now cost node *plus* the heap their
/// keys own, so a grant derived from node size alone would refuse ordinary
/// controls the moment their fixture names got longer than nothing — and the
/// refusal would look like a pressure finding rather than a fixture that had
/// forgotten to pay for its own strings.
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
    coordinate: usize,
) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    let planned = |claim| {
        myownmesh_core::FiniteResourceProvider::reservation_planning_charge(claim)
            .expect("a fixture reservation charge is representable")
    };
    let records = planned(client_record_claim()?)
        .checked_add(planned(
            LeasedMap::<ClientId, FundedArc<ClientHandle>>::entry_claim()?,
        ))?
        .checked_scale(clients)?;
    let entry = planned(LeasedMap::<ClientId, FundedArc<ClientHandle>>::entry_claim()?)
        .checked_add(planned(
            LeasedMap::<ClaimKey, Funded<ClientId>>::entry_claim()?,
        ))?
        .checked_add(planned(
            LeasedMap::<ClaimKey, InstalledHandler>::entry_claim()?,
        ))?
        .checked_add(planned(LeasedMap::<ClaimKey, ChannelRoute>::entry_claim()?))?
        .checked_add(planned(LeasedMap::<ClientId, ()>::entry_claim()?))?
        .checked_add(planned(
            LeasedMap::<PendingKey, PendingRecord>::entry_claim()?,
        ))?
        .checked_add(planned(LeasedMap::<ClaimKey, ResourceLease>::entry_claim()?))?
        .checked_add(planned(
            LeasedMap::<String, OwnedRealtimeFlow>::entry_claim()?,
        ))?
        .checked_add(planned(pending_cancellation_claim()?))?;
    // The off-node half, priced from the same helpers the registry charges
    // with. A `PendingKey` carries four coordinates and a `ClaimKey` two, and
    // the realtime table's key is one -- so a fixture naming everything
    // `coordinate` bytes long pays for the worst of them at every entry rather
    // than for an average nothing actually charges.
    let widest_key = planned(pending_key_retained(&PendingKey {
        network: "x".repeat(coordinate),
        method: "x".repeat(coordinate),
        remote_peer: "x".repeat(coordinate),
        remote_request_id: "x".repeat(coordinate),
        class: HandlerMode::Single,
    })?);
    // And the cleanup nodes each entry pre-pays for, priced from the list that
    // will hold them rather than from a size restated here. Four kinds, summed
    // rather than picked between, on the same over-funding reasoning as the
    // eight node shapes above: a fixture grant that is generous fails only by
    // hiding headroom.
    let cleanup = planned(crate::ipc::LeasedList::<ForgottenMethod>::node_claim()?)
        .checked_add(planned(
            crate::ipc::LeasedList::<RetiredRoute>::node_claim()?
        ))?
        .checked_add(planned(
            crate::ipc::LeasedList::<PendingRecord>::node_claim()?,
        ))?
        .checked_add(planned(
            crate::ipc::LeasedList::<OwnedRealtimeFlow>::node_claim()?,
        ))?;
    let entry = entry
        .checked_add(widest_key.checked_scale(8)?)?
        .checked_add(cleanup.checked_scale(8)?)?;
    myownmesh_core::FiniteResourceProvider::scope_planning_charge()
        .checked_add(records)?
        .checked_add(entry.checked_scale(entries)?)
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
pub(crate) struct OwnedRealtimeFlow {
    /// The node this flow will occupy in the disconnect drain's list.
    ///
    /// `Option` for the same reason [`PendingRecord`]'s is: it has to leave the
    /// value without moving it. Dropped unused by
    /// [`ClientHandle::take_realtime_flow`], which answers one flow directly and
    /// builds no node.
    cleanup: Option<ResourceLease>,
    network: String,
    flow: Option<myownmesh_core::realtime::RealtimeFlowHandle>,
    /// The capability key's bytes and this network name's, funded together and
    /// released when this value drops — which, taken out through
    /// `pop_first_entry`, is after the owned key has gone wherever it is going.
    /// The node lease cannot carry this: it ends inside the removal call. It is
    /// last so it outlives the values whose retained allocation it funds.
    _retained: ResourceLease,
}

impl OwnedRealtimeFlow {
    pub(crate) fn network(&self) -> &str {
        &self.network
    }

    pub(crate) async fn close_through(
        mut self,
        network: &myownmesh_core::JoinedNetwork,
    ) -> Result<(), myownmesh_core::realtime::RealtimeRefusal> {
        let flow = self
            .flow
            .take()
            .expect("an owned realtime flow is consumed only once");
        network.close_realtime(flow).await
    }
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
    cancelled: FundedArc<PendingCancellation>,
    /// The node this record will occupy in the one sweep that has to collect.
    ///
    /// An `Option` so it can be moved out and handed to the list as that node's
    /// own funding without moving the record — which is the sequence that makes
    /// the funding follow the allocation rather than the record. `None` once it
    /// has been handed over.
    ///
    /// The other two sweeps settle a record at a time straight out of the table
    /// and build no node at all, so theirs is simply released with the record.
    /// Only claim displacement collects, because it must detach the previous
    /// owner's in-flight calls under the same acquisition that moves the claim.
    cleanup: Option<ResourceLease>,
    /// See [`PendingFunding`]. Shared with the ticket, so the record leaving the
    /// table releases nothing while the ticket is still alive. Held, never read.
    _funding: FundedArc<PendingFunding>,
}

/// Everything one pending call retains, funded once and released last.
///
/// A pending call is owned twice from the moment it is accepted: the table holds
/// the key and the record, and the [`PendingTicket`] holds a second copy of the
/// same four coordinate strings plus a share of the cancellation. The two do not
/// end together — a ticket can outlive the record's removal, which is the whole
/// reason it exists — so funding attached to the record alone would be released
/// while the ticket was still holding an identical set of buffers.
///
/// Behind an `Arc` shared by both, so the charge is taken once and returned when
/// the *last* of the two goes. That is the general rule this registry now
/// follows: funding follows the last live copy, not the table node.
struct PendingFunding;

struct PendingCancellation {
    cancelled: AtomicBool,
    notify: tokio::sync::Notify,
}

impl PendingCancellation {
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    /// Synchronous read, for callers that do not suspend.
    ///
    /// There is no backpressure to race against here, so the only question is
    /// the one this answers directly: has this operation already been
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
    cancelled: FundedArc<PendingCancellation>,
    /// The other half of the shared charge. Declared last so this ticket's copy
    /// of the key is dropped before the funding that paid for it.
    _funding: FundedArc<PendingFunding>,
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

impl ClientHandle {
    pub(crate) fn capability(&self) -> &str {
        self.capability.expose()
    }

    pub(crate) const fn capability_encoded_len() -> usize {
        ClientCapability::ENCODED_LEN
    }
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
/// One name a client holds, and the two leases that name owes.
///
/// Two, because they end at different moments in different places and a single
/// lease cannot be released twice. `retained` pays for the name's own buffers
/// and goes when the last copy of the name does. `cleanup` pays for the node
/// this name will occupy in the caller's cleanup list, and it is *moved into
/// that node* when the sweep builds it — so the node's funding was acquired
/// before the node existed and is released after the node is freed, which is
/// the whole property. Folding the two together would fund the node with a
/// lease released when the table entry was removed, before the node it paid for
/// had even been built.
///
/// A name that is swept but not forgotten — a claim a successor took over, a
/// subscription whose route was already gone — drops `cleanup` unused, which is
/// correct: no node was built.
struct HeldName {
    retained: ResourceLease,
    cleanup: ResourceLease,
    membership: Option<ChannelMembershipId>,
}

/// The names one client holds, each with the two leases its name owes.
///
/// The value is a [`HeldName`] rather than `()`, so [`Self::pop_first`] can hand
/// back owned names that are still funded while the caller holds them, together
/// with the node funding for the cleanup entry each one becomes. The shape this
/// replaced cloned every key into a fresh vector on disconnect: the clones were
/// unfunded, the vector was unfunded, and both were sized by how many names the
/// client had chosen to claim.
#[derive(Default)]
struct HeldNames(Mutex<LeasedMap<ClaimKey, HeldName>>);

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
    fn hold(&self, key: ClaimKey, node: ResourceLease, held: HeldName) {
        let _ = self.0.lock().insert(key, held, node);
    }

    fn release(&self, key: &ClaimKey) -> Option<HeldName> {
        self.0.lock().remove(key)
    }

    /// Take one name out, still carrying the funding that pays for it.
    ///
    /// One at a time, and not a `drain` returning every name at once, because
    /// two vectors would then be alive together: the drained pairs *and* the
    /// output the caller builds while walking them. Only one output slot per
    /// name is funded — a [`ForgottenMethod`] for methods, a [`RetiredRoute`]
    /// for channels — so a snapshot vector beside it is retention nobody paid
    /// for, sized by how many names the client chose to claim.
    ///
    /// `pop_first_entry` also means no key is ever cloned: the name is *moved*
    /// out with its lease, so the funding follows the last live copy instead of
    /// being released while a copy is still in use.
    fn pop_first(&self) -> Option<(ClaimKey, HeldName)> {
        self.0.lock().pop_first_entry()
    }
}

impl ClientHandle {
    /// Whether this client currently holds a claim on `key`.
    ///
    /// Controls only, and narrow on purpose: what a control wants to know is
    /// whether a displaced client still records a claim it no longer has, and
    /// the alternative -- widening `method_claims` so a sibling module can read
    /// the table directly -- would expose the leases inside it to anything in
    /// the crate. This answers the question without handing over the thing.
    #[cfg(test)]
    pub(crate) fn holds_method_for_test(&self, key: &ClaimKey) -> bool {
        self.method_claims.holds(key)
    }

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
        retained: ResourceLease,
        cleanup: ResourceLease,
    ) -> RealtimeFlowCapability {
        let capability = RealtimeFlowCapability::mint();
        self.realtime_flows
            .lock()
            .insert(
                capability.expose().to_string(),
                OwnedRealtimeFlow {
                    cleanup: Some(cleanup),
                    network,
                    flow: Some(flow),
                    _retained: retained,
                },
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
        if owned.network != network {
            return None;
        }
        let flow = owned.flow.as_ref()?;
        Some(effect(flow))
    }

    /// Take one of this client's flows out, for a close that will consume it.
    ///
    /// Removal and the close are separate steps and the removal comes first, so
    /// two concurrent closes cannot both reach core with the same flow: the
    /// second finds nothing.
    /// Take one flow out by capability, with the funding for its own strings.
    ///
    /// The lease is returned rather than dropped here, for the same reason
    /// [`Self::drain_realtime_flows`] returns one. It pays for the `network`
    /// string handed back alongside it, and the caller reads that string —
    /// looks the network up, closes through it, builds a response — well after
    /// this function has returned. Dropping it on the way out would unfund a
    /// buffer still in use, which is the defect this whole shape exists to
    /// prevent and is easy to reintroduce by destructuring the value here.
    pub(crate) fn take_realtime_flow(&self, capability: &str) -> Option<OwnedRealtimeFlow> {
        let owned = self.realtime_flows.lock().remove(capability)?;
        // `owned.cleanup` is left behind and released here. This answers one
        // flow directly to a caller that asked for it by name; no drain node is
        // built, so the funding for one is not owed to anything.
        Some(owned)
    }

    /// Take every flow this client still owns.
    ///
    /// For disconnect and shutdown, where the flows are closed *through* their
    /// networks rather than dropped here. Not because dropping would release
    /// nothing — a `RealtimeFlowHandle`'s Drop performs exact flow cleanup — but
    /// because an explicit close awaits the native retirement and can report it,
    /// and a shutdown that reports the control surface closed should have waited
    /// for the native halves rather than left them retiring behind it. Drop
    /// remains the backstop for the paths that cannot await.
    /// Taken under one acquisition of the table, so a flow opened part-way
    /// through cannot survive the drain unclosed.
    /// Take every flow out, one detached node at a time.
    ///
    /// `pop_first_entry` rather than collect-the-keys-then-remove. The previous
    /// shape cloned every capability string into a second vector purely to hand
    /// each one straight back to `remove`: unfunded clones in an unfunded
    /// vector, both sized by how many flows the client had opened. Detaching the
    /// first node repeatedly needs no key at all, so that allocation is gone
    /// rather than merely paid for.
    ///
    /// Each value carries its own retained lease, so the network names in the
    /// returned list stay funded for as long as the caller holds them — and each
    /// one lands in a node whose own funding was acquired when the flow was
    /// installed and is released only after that node is freed.
    pub(crate) fn drain_realtime_flows(&self) -> crate::ipc::LeasedList<OwnedRealtimeFlow> {
        let mut flows = self.realtime_flows.lock();
        let mut taken = crate::ipc::LeasedList::new();
        while let Some((_capability, mut owned)) = flows.pop_first_entry() {
            let node = owned
                .cleanup
                .take()
                .expect("an installed flow holds the funding for its own drain node");
            taken.push(owned, node);
        }
        taken
    }

    /// Queue one frame for this client's writer task.
    ///
    /// The refusal is returned rather than swallowed because the two ways this
    /// can fail are not the same event. `Closed` means the connection is gone
    /// and the
    /// registry will drop this handle shortly — nothing was owed to anyone.
    /// `Pressure` and `Claim` mean the frame was real, the client is still
    /// connected, and it will never see it. A caller with a peer waiting on the
    /// other end has to say so rather than leave them to time out.
    pub fn send(&self, frame: ServerOut) -> Result<(), ResourceMailboxAdmissionError> {
        self.writer_tx
            .send(frame)
            .map_err(|refusal| refusal.into_admission_error())
    }

    pub(crate) fn send_building<B>(&self, builder: B) -> Result<(), ResourceMailboxAdmissionError>
    where
        B: myownmesh_core::ResourceMailboxItemBuilder<ServerOut>,
    {
        self.writer_tx.send_building(builder)
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

/// A one-shot pause for the channel pump, at the line between selecting a
/// subscriber and building that subscriber's frame.
///
/// That line is the one that matters. Cloning a publisher-chosen payload into
/// a mailbox with the registry's tables still held would mean that for the whole
/// of one large frame a disconnect could not be recorded and a shutdown could
/// not begin. Checking only that the cursor method returns without the lock
/// checks the easy half; parking the pump *here*, with the frame not yet built,
/// is the interval that matters.
///
/// One pump and one only: both halves are taken on first use, so a second pump
/// -- or the same pump's second subscriber -- runs straight through. The
/// alternative would freeze every fan-out in the binary.
#[cfg(test)]
#[derive(Default)]
pub struct FanoutBarrier {
    arrived: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    release: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
}

#[cfg(test)]
impl FanoutBarrier {
    /// The barrier and the two ends a control drives it by.
    pub fn paired() -> (
        Arc<Self>,
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (arrived_tx, arrived_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        (
            Arc::new(Self {
                arrived: Mutex::new(Some(arrived_tx)),
                release: Mutex::new(Some(release_rx)),
            }),
            arrived_rx,
            release_tx,
        )
    }

    /// Announce arrival and wait, once.
    ///
    /// Both halves are taken before anything is awaited, so no lock is held
    /// across the suspension.
    async fn pass(&self) {
        let arrived = self.arrived.lock().take();
        let release = self.release.lock().take();
        if let Some(arrived) = arrived {
            let _ = arrived.send(());
        }
        if let Some(release) = release {
            let _ = release.await;
        }
    }
}

/// Daemon-wide registry of connected clients + their
/// registrations.
#[derive(Clone)]
pub struct ClientRegistry {
    inner: Arc<RegistryInner>,
}

struct RegistryInner {
    /// Every routing table this registry owns, under one acquisition.
    ///
    /// One acquisition rather than a fence beside separately-locked maps. A
    /// fence makes the multi-table operations atomic with respect to each other
    /// but single-table readers bypass it, so a reader could see a claim
    /// installed and the client that owned it already gone.
    /// There is one acquisition now, and no way to read one table without it.
    tables: Mutex<RegistryTables>,
    /// Where a control parks one channel pump, if one asked to.
    ///
    /// Its own lock and never the tables', which is the whole point: the barrier
    /// is passed at a line the pump reaches *after* it has released the tables,
    /// so a control holding it there is holding nothing the registry needs.
    #[cfg(test)]
    fanout_barrier: Mutex<Option<Arc<FanoutBarrier>>>,
    /// How many `ChannelInbound` frames this registry's pumps have actually
    /// built.
    ///
    /// Incremented inside the builder's `build`, which is the one line past
    /// every refusal, so a control can distinguish "the mailbox said no" from
    /// "the mailbox said no after the copy". It lives here rather than in a
    /// static for the same reason the barrier does: one registry is one
    /// fan-out's worth of state, and a process-wide counter would be perturbed
    /// by whatever other control happened to be running beside it.
    #[cfg(test)]
    channel_frames_built: AtomicUsize,
    /// The one acquisition port everything this registry admits is funded
    /// from. It is supplied rather than reached for: the registry has no
    /// authority of its own, and a daemon that could mint some here would be
    /// able to admit clients the process owner never granted capacity for.
    resources: RegistryResources,
    /// Woken when the live task count reaches zero.
    ///
    /// `notify_waiters` rather than `notify_one`, so that a second waiter is not
    /// left holding a permit nobody will ever consume; the drain re-checks the
    /// count after each wake, which is what makes a missed or spurious wake
    /// harmless rather than a hang.
    idle: tokio::sync::Notify,
    /// Woken once, for everything, when the runtime enters `Closing`.
    ///
    /// The signal half of the shutdown: tasks parked on a socket read or a pump
    /// receive learn about it here rather than by polling the lifecycle. The
    /// lifecycle under the tables lock remains the authority — this only tells
    /// an awaiting task when to go and look.
    closing: tokio::sync::Notify,
    // The four never-reused process-local identity counters. Each hands out the
    // value it read and moves on, so no two live records share one and a
    // released identity is never handed out again. Exhaustion is not modelled:
    // one `u64` per client, per outbound stream call, per inbound operation and
    // per channel membership outlasts the process.
    next_id: AtomicU64,
    next_call_stream_id: AtomicU64,
    next_operation_id: AtomicU64,
    next_membership_id: AtomicU64,
    /// Which installation of a method name a handler belongs to.
    ///
    /// Monotonic and never reused, so "is this still the handler I installed?"
    /// has an answer that a method name alone cannot give. A name can be
    /// claimed, released and claimed again while a closure cloned from the
    /// first installation is still in flight, and the two installations are
    /// indistinguishable by name.
    next_handler_generation: AtomicU64,
}

/// The registry's five routing tables, which are only ever reached together.
///
/// Each is a [`LeasedMap`], so each entry is funded before it exists and
/// released when it is removed — including when this whole struct is dropped
/// with entries still in it, which is the daemon-shutdown case.
struct RegistryTables {
    /// See [`Lifecycle`] for why this is in here rather than beside the mutex.
    lifecycle: Lifecycle,
    /// How many accepted tasks are alive right now.
    ///
    /// Not a statistic. `control::serve` may not return while this is nonzero:
    /// a connection task outliving the function that accepted it would keep
    /// using a registry, a mesh handle and a socket that the caller of `serve`
    /// is entitled to believe are finished with.
    ///
    /// In here, beside `lifecycle`, and not an atomic beside the mutex. The two
    /// have to move together or not at all: with them apart, `begin_closing`
    /// could publish `Closing`, read zero, and return while an admission that
    /// had already passed its lifecycle check was still on its way to
    /// incrementing — a task spawned into a runtime that had finished waiting
    /// for tasks. One lock over both means an admission either happens entirely
    /// before the transition or is refused by it.
    live_tasks: u64,
    /// Inbound stream watchdogs retained until shutdown observes each result.
    /// Keeping the handle here prevents bridge code from detaching a task and
    /// makes its node allocation independently funded.
    watchdogs: crate::ipc::LeasedList<tokio::task::JoinHandle<()>>,
    clients: LeasedMap<ClientId, FundedArc<ClientHandle>>,
    handler_claims: LeasedMap<ClaimKey, Funded<ClientId>>,
    /// Subscribers per (network, channel), as a funded set of funded members.
    ///
    /// Nested rather than a `Vec`, because both counts are chosen by local
    /// clients: how many channels get subscribed to, and how many clients
    /// subscribe to each. A `Vec` would have funded the first and not the
    /// second. The outer entry appears with its first member and is removed with
    /// its last, so an unsubscribed channel costs nothing — the previous shape
    /// left an empty subscriber list behind forever.
    channel_subs: LeasedMap<ClaimKey, ChannelRoute>,
    exact_pending_inbound: LeasedMap<PendingKey, PendingRecord>,
    /// Which shape of synthetic handler the bridge has installed on the engine
    /// for each claim. Kept so a re-claim of the same method does not have to
    /// ask the engine what it already holds, and so the last unclaim knows there
    /// is a handler to forget.
    installed_handlers: LeasedMap<ClaimKey, InstalledHandler>,
}

impl RegistryTables {
    /// Look one client up while the tables are already held.
    ///
    /// Exists because [`ClientRegistry::client`] takes the same lock, and this
    /// mutex is not reentrant: every method here that both locks and needs a
    /// client handle calls this instead, which is the whole of the discipline.
    fn client(&self, id: ClientId) -> Option<FundedArc<ClientHandle>> {
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
        self.lease_entry_retaining::<K, V>(ResourceClaim::ZERO)
    }

    /// The node lease and the retained-heap lease, as two values.
    ///
    /// Two rather than the combined one, because they have to be *stored* in
    /// two places: the node lease goes to the map, and the retained lease goes
    /// inside the value so it survives `remove_entry`. Both are acquired before
    /// either is stored, so a refusal of the second still leaves nothing
    /// written — the atomicity that matters is at the caller's insert, not in
    /// the number of leases.
    fn lease_entry_pair<K, V>(
        &self,
        retained: ResourceClaim,
    ) -> Result<(ResourceLease, ResourceLease), IpcAdmissionError> {
        let node = self.lease_entry::<K, V>()?;
        let retained = self
            .resources
            .acquire(retained)
            .map_err(IpcAdmissionError::Resources)?;
        Ok((node, retained))
    }

    /// The node, plus what the entry retains off it, as one lease.
    ///
    /// One lease and not two because they are released at the same instant —
    /// the entry leaves the table and its key's buffers go with it — and two
    /// leases would be two chances to get that pairing wrong. It also means a
    /// refusal is a refusal of the whole entry: there is no state in which the
    /// node was funded and the name it holds was not.
    fn lease_entry_retaining<K, V>(
        &self,
        retained: ResourceClaim,
    ) -> Result<ResourceLease, IpcAdmissionError> {
        let claim = LeasedMap::<K, V>::entry_claim()
            .and_then(|node| node.checked_add(retained))
            .map_err(IpcAdmissionError::Claim)?;
        self.resources
            .acquire(claim)
            .map_err(IpcAdmissionError::Resources)
    }
}

/// Where this registry's admissions are funded from.
///
/// Production has exactly one answer: the local-application scope the daemon
/// issued it. The second arm exists so a control can own a provider small enough
/// to refuse — which the production arm cannot give it, because the daemon test
/// binary installs one process-global provider by design and a control that
/// cornered it would starve every other test drawing on the same pool.
///
/// A wrapper rather than a core change, because `RegistryInner` only ever
/// *acquires* through this and issues children off it. `FiniteResourceProvider`,
/// `ResourceProviderPort` and `ResourceScope` are all public, so a locally
/// constructed provider needs nothing widened; the same shape already funds the
/// control connection's framing.
enum RegistryResources {
    Application(LocalApplicationResourceScope),
    /// A provider this test owns outright. The provider and port are held, not
    /// merely used to mint the scope: dropping either would take the grant with
    /// it and every later acquisition would refuse for a reason the control is
    /// not about.
    #[cfg(test)]
    Isolated {
        _provider: myownmesh_core::FiniteResourceProvider,
        port: myownmesh_core::ResourceProviderPort,
        scope: myownmesh_core::ResourceScope,
    },
}

impl RegistryResources {
    fn acquire(&self, claim: ResourceClaim) -> Result<ResourceLease, ResourceUnavailable> {
        match self {
            Self::Application(scope) => scope.acquire(claim),
            #[cfg(test)]
            Self::Isolated { port, scope, .. } => port.acquire(
                scope,
                myownmesh_core::ResourceAuthorityClass::Admitted,
                claim,
            ),
        }
    }

    /// One acquisition subtree under this registry.
    ///
    /// What this registry's provider is currently holding, when the provider is
    /// one a control owns.
    ///
    /// `None` for the production arm, and not as an oversight: a
    /// `LocalApplicationResourceScope` is one of many drawing on a process-wide
    /// provider, so a figure read there would include every other scope's usage
    /// and would say nothing about this registry. The isolated arm has the whole
    /// grant to itself, which is exactly what makes the number mean something.
    #[cfg(test)]
    fn in_use(&self) -> Option<ResourceClaim> {
        match self {
            Self::Application(_) => None,
            Self::Isolated { _provider, .. } => Some(_provider.in_use()),
        }
    }

    /// The isolated arm has no subtree to issue, and says so as a refusal
    /// rather than a panic.
    ///
    /// A `LocalApplicationResourceScope` is a child of the *installed*
    /// process-wide provider, and the whole point of the isolated arm is that it
    /// is installed nowhere. A control that needs a real inbound-stream subtree
    /// is testing core's scope tree rather than this registry and should use the
    /// production arm; one that merely files registry entries never calls this.
    ///
    /// Refusing rather than panicking because a control that stumbles onto this
    /// path should fail on its own assertion about admission, which is legible,
    /// rather than on an abort from inside a helper.
    fn child(&self) -> Result<LocalApplicationResourceScope, ResourceUnavailable> {
        match self {
            Self::Application(scope) => scope.child(),
            #[cfg(test)]
            Self::Isolated { scope, .. } => Err(ResourceUnavailable::Pressure(
                myownmesh_core::ResourcePressure {
                    scope_id: scope.id(),
                    authority: myownmesh_core::ResourceAuthorityClass::Admitted,
                    dimension: ResourceClass::OpaqueDependencyResidual,
                    requested: 1,
                    in_use: 0,
                    capacity: 0,
                },
            )),
        }
    }
}

/// A table value carrying the funding for what its *entry* retains off-node.
///
/// The node's own lease is the map's and is released the instant the node
/// leaves the tree — which is before the caller has done anything with the
/// owned key it just got back. Anything the key's buffers pay for therefore
/// cannot live in the node lease: it has to live in the **value**, because the
/// value comes out of [`LeasedMap::remove_entry`] alongside the owned key and
/// travels wherever that key travels.
///
/// That is the whole reason this wrapper exists rather than a wider node claim.
/// A cleanup sweep moves keys into a temporary vector; with the funding in the
/// node, the vector's storage and the strings in it would be unfunded for
/// exactly as long as they were in use, which is the window that matters.
struct Funded<T> {
    value: T,
    /// The key's off-node bytes plus the cleanup slot the entry pre-paid for.
    /// Declared last so it is released after the value it accounts for.
    _retained: ResourceLease,
}

/// One channel's fan-out route, and the single owner of its lifecycle.
///
/// Membership and liveness are one answer. Were they two — a bare subscriber
/// set, with the existence of a pump implied by whoever happened to be first —
/// a second client subscribing while the first was still installing would be
/// told it had succeeded, and if that install then
/// failed the first client unwound only *its own* membership. The second was
/// left subscribed to a route that would never deliver a frame and that nothing
/// would ever tear down.
///
/// One value under the tables lock, so "who is subscribed" and "is there a pump"
/// cannot disagree.
pub(crate) struct ChannelRoute {
    state: RouteState,
    members: LeasedMap<ChannelMembershipId, ClientId>,
    /// The channel key's own buffers and this route's share of cleanup.
    /// Declared last so it outlives the members it accounts for.
    _retained: ResourceLease,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ChannelMembershipId(u64);

enum RouteState {
    /// One subscriber is off building the pump. Nobody may be told they are
    /// subscribed yet — not even the installer, which reports only after it
    /// has finished.
    Installing(FundedArc<RouteReady>),
    /// The pump exists, and this is what will stop it.
    Live(PumpOwner),
}

/// What a follower waits on while the installer works.
///
/// A `Notify` alone would say "something happened" and not "it worked". The
/// outcome has to be carried, because a follower that woke on a failed install
/// and reported success would be exactly the bug the route exists to remove.
///
/// This value's own `Arc` allocation, funded before that allocation exists.
///
/// Not folded into [`ChannelRoute`]'s lease, deliberately. Clones of this
/// readiness outlive the route by design — a failed install removes the
/// route and *then* its waiters observe `FAILED` through their own clones —
/// so funding tied to the route would be returned while the thing it paid
/// for was still being read. Funding follows the last live copy, which for
/// an `Arc` means the `Arc` itself.
pub(crate) struct RouteReady {
    outcome: AtomicU8,
    woken: tokio::sync::Notify,
}

impl RouteReady {
    const INSTALLING: u8 = 0;
    const LIVE: u8 = 1;
    const FAILED: u8 = 2;

    fn new() -> Self {
        Self {
            outcome: AtomicU8::new(Self::INSTALLING),
            woken: tokio::sync::Notify::new(),
        }
    }

    /// Publish failure. Named because three call sites reach it and two of them
    /// are settling a generation they do not own the route for.
    fn settle_failed(&self) {
        self.settle(Self::FAILED);
    }

    /// Publish the outcome once and wake everyone waiting on it.
    ///
    /// First writer wins, enforced rather than documented. A plain store would
    /// let a second settle overwrite the first, and there is a real path to one:
    /// a stale installer settles its own generation `FAILED` after finding the
    /// route replaced, and if it were ever handed a readiness that had already
    /// gone `LIVE` it would demote it under the waiters' feet. `compare_exchange`
    /// from `INSTALLING` makes that a no-op instead of a lie, so the type
    /// enforces the "published once" contract this doc claims.
    ///
    /// `notify_waiters` after the exchange, and the order matters: a follower
    /// woken before the outcome was visible would read `INSTALLING` and go back
    /// to sleep on a notification that is never sent twice. It runs on the
    /// losing path too — nothing is waiting on the loser's behalf, and waking a
    /// waiter that then re-reads a settled outcome is free.
    fn settle(&self, outcome: u8) {
        let _ = self.outcome.compare_exchange(
            Self::INSTALLING,
            outcome,
            Ordering::Release,
            Ordering::Relaxed,
        );
        self.woken.notify_waiters();
    }

    /// Wait until the install finishes, and answer whether it worked.
    ///
    /// Subscribed before the state is read, for the same reason every other
    /// waiter in this crate is: `notify_waiters` reaches whoever is listening at
    /// that instant and nobody else, and this notification is sent exactly once.
    /// A check-then-subscribe would let an install that finished in between wake
    /// nothing, and the follower would wait for a second wake that never comes.
    pub(crate) async fn wait(&self) -> bool {
        loop {
            let woken = self.woken.notified();
            tokio::pin!(woken);
            woken.as_mut().enable();
            match self.outcome.load(Ordering::Acquire) {
                Self::LIVE => return true,
                Self::FAILED => return false,
                _ => {}
            }
            woken.await;
        }
    }
}

/// How a pump is stopped, and how its end is observed.
///
/// Both halves, because either alone is a lie. Cancelling without joining says
/// "stop" and returns before the task has; joining without cancelling waits for
/// something that has not been asked to finish.
///
/// The cancellation is a [`PendingCancellation`] — a flag *and* a notification —
/// and not a bare `Notify`. A bare `Notify` delivers to whoever is listening at
/// that instant and to nobody else, and this signal is sent exactly once. The
/// last unsubscribe can easily beat the spawned pump to its first `notified()`,
/// and then the only wake there will ever be has already been spent: the pump
/// waits on a channel nobody publishes to, and the join that follows never
/// returns. The flag is what a late-arriving waiter reads instead.
struct PumpOwner {
    cancel: FundedArc<RouteCancellation>,
    join: tokio::task::JoinHandle<()>,
}

/// The pump's stop signal: a flag, a notification, and the funding for its own
/// allocation.
///
/// The flag is what makes the signal survivable. A bare `Notify` reaches
/// whoever is listening at that instant and nobody else, and this signal is sent
/// exactly once — so a last unsubscribe that beats the spawned pump to its first
/// `notified()` spends the only wake there will ever be, and the join that
/// follows waits forever on a channel nobody publishes to. A late waiter reads
/// the flag instead.
///
/// Its `FundedArc` carries the lease beside the pointer for the same reason as
/// [`RouteReady`]: the pump holds a clone and is still using it while it
/// unwinds, after the route that created it is gone.
pub(crate) struct RouteCancellation {
    cancelled: AtomicBool,
    woken: tokio::sync::Notify,
}

impl RouteCancellation {
    fn new() -> Self {
        Self {
            cancelled: AtomicBool::new(false),
            woken: tokio::sync::Notify::new(),
        }
    }

    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.woken.notify_waiters();
    }

    /// Resolve once cancelled, immediately if it already has been.
    ///
    /// Subscribe, then read: a check-then-subscribe would let a cancellation
    /// landing in between wake nothing, which is the whole failure this type
    /// exists to prevent.
    pub(crate) async fn cancelled(&self) {
        loop {
            let woken = self.woken.notified();
            tokio::pin!(woken);
            woken.as_mut().enable();
            if self.cancelled.load(Ordering::Acquire) {
                return;
            }
            woken.await;
        }
    }
}

/// One `FundedArc<RouteReady>` pointee, funded before it exists.
///
/// Its own lease and not the route's, because waiters read this after the route
/// is gone. [`RouteCancellation`] is funded separately by
/// [`ClientRegistry::route_cancellation`] for the mirrored reason: the pump
/// holds a clone while it unwinds. Two allocations with two different last
/// owners get two leases; folding either into the route would return funding
/// while the thing it paid for was still in use.
fn route_ready_retained() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    funded_record_retained::<RouteReady>()
}

/// One `FundedArc<RouteCancellation>` pointee, funded before it exists.
fn route_cancellation_retained() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    funded_record_retained::<RouteCancellation>()
}

/// What one subscriber must do next, decided under the tables lock.
///
/// A named outcome rather than a bare `bool`. "You are first, install a pump"
/// and "you are done" do not cover a route that is still installing: answering
/// the second there tells the client it has subscribed before anything can
/// deliver to it.
pub(crate) enum ChannelJoin {
    /// This caller owns the install. Report to its client only after calling
    /// [`ClientRegistry::finish_channel_install`].
    Install(FundedArc<RouteReady>),
    /// Someone else is installing. Await this before reporting anything.
    Pending(FundedArc<RouteReady>),
    /// The pump is already running.
    Live,
}

impl ChannelRoute {
    /// Only [`RegistryResidue`] asks, and only under `cfg(test)`: production
    /// never branches on this, because every caller that cares about liveness
    /// is already holding a [`ChannelJoin`] that told it.
    #[cfg(test)]
    fn is_installing(&self) -> bool {
        matches!(self.state, RouteState::Installing(_))
    }
}

/// A route that is gone, handed to a caller that can await what it left behind.
///
/// One type for both stages a route can be removed in, because they are one
/// obligation: something is still owed to somebody. A live route owes its pump a
/// stop and a join; an installing route owes its followers an answer. Splitting
/// them would mean two vectors on the disconnect path to say the same thing.
///
/// The field is private and the type is `#[must_use]` for the same reason. A
/// bare `JoinHandle` returned from `unsubscribe_channel` would be dropped by an
/// inattentive caller, and dropping a `JoinHandle` **detaches** the task rather
/// than stopping it — the pump would keep running against a channel with no
/// subscribers, which is the exact failure the route lifecycle exists to end.
#[must_use = "a removed route still owes its pump a join or its followers an answer"]
pub(crate) struct RetiredRoute(Retired);

/// What a removed route left behind. Private: the stage is this module's
/// business, and every caller's obligation is the same either way.
enum Retired {
    Pump(PumpOwner),
    /// The install never finished. Its installer will find the route gone and
    /// settle only its own generation, so these followers are nobody else's to
    /// answer.
    Installing(FundedArc<RouteReady>),
}

impl RetiredRoute {
    fn from_state(state: RouteState) -> Self {
        Self(match state {
            RouteState::Live(pump) => Retired::Pump(pump),
            RouteState::Installing(ready) => Retired::Installing(ready),
        })
    }

    /// A pump that was built for a route that no longer wants it.
    fn orphaned_pump(
        cancel: FundedArc<RouteCancellation>,
        join: tokio::task::JoinHandle<()>,
    ) -> Self {
        Self(Retired::Pump(PumpOwner { cancel, join }))
    }

    /// Settle what this route owes: signal the pump and wait for it to actually
    /// stop, or tell the followers the install they were waiting on is over.
    ///
    /// For a pump, both halves in that order, and the await is the part that
    /// matters. Cancelling alone returns while the task is still running, so a
    /// caller that then reported the channel torn down would be wrong — and
    /// `serve`, which waits on the accepted-task count, would be waiting for a
    /// task nobody had finished asking to stop.
    ///
    /// A join error means the pump panicked or was aborted. There is nothing to
    /// do about it here and nothing to report to: the route is gone either way,
    /// and the point of this call is that the task is no longer running.
    pub(crate) async fn retire(self) {
        match self.0 {
            Retired::Pump(pump) => {
                pump.cancel.cancel();
                // Reads as a no-op and is not: `cancel` stores the flag *and*
                // notifies, so a pump that has not yet parked still sees the
                // flag when it does.
                let _ = pump.join.await;
            }
            Retired::Installing(ready) => ready.settle_failed(),
        }
    }
}

/// Which shape of synthetic handler is installed for a claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HandlerMode {
    Single,
    Stream,
}

/// Which installation of a method name something belongs to.
///
/// Minted before the handler closure is built, so the closure can carry its own
/// and ask this registry whether it is still the current one. Comparing names
/// cannot answer that: a client may release a method and another may claim it
/// while a clone of the first closure is still awaiting a response, and both
/// closures answer to the same name.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HandlerGeneration(u64);

/// One installed synthetic handler.
///
/// The mode lives here beside the registration rather than being inferred from
/// the claim, because they are one fact: the shape a call is dispatched as and
/// the closure that dispatches it were installed together and are replaced
/// together.
struct InstalledHandler {
    generation: HandlerGeneration,
    mode: HandlerMode,
    token: HandlerToken,
    /// This record's copy of the method name.
    _retained: ResourceLease,
}

/// The core registration behind an installed handler.
enum HandlerToken {
    /// Core has published the handler, and this registry does not hold its
    /// registration yet — the few instructions between `commit_with` returning
    /// and the finalize below it.
    ///
    /// Still routable, and that is safe rather than convenient. Routing is
    /// decided by generation and class, not by this state: before core
    /// publishes, the only closure that can run is the incumbent's and its
    /// generation does not match this record; after core publishes — which
    /// cannot fail, every acquisition having happened in prepare — the new
    /// closure's generation does match. There is no instant at which a stale
    /// closure maps onto this record, so refusing calls here would refuse
    /// correct ones for nothing.
    Installing,
    /// Dropping this removes exactly the handler it installed. Core compares
    /// the stored identity against whatever currently holds the name, so a
    /// registration released after a successor legitimately took the method
    /// removes nothing.
    ///
    /// Named and underscored because it is held rather than read: nothing in
    /// this crate ever looks inside it, and its whole contribution is what
    /// happens when this variant drops. Spelling that out beats a blanket
    /// allowance, which would also silence a field that had genuinely stopped
    /// being used.
    Live {
        _registration: myownmesh_core::rpc::OwnedMethodRegistration,
    },
    /// A control's stand-in for a published registration.
    ///
    /// Holds nothing and removes nothing when it drops, because there is no
    /// dispatcher behind it. It exists for the same reason
    /// `install_if_live` is generic over its value: a real registration can
    /// only be minted by core against a live network, and the ordering rules
    /// this registry has to get right must be drivable by a control that has
    /// neither a network nor an engine.
    #[cfg(test)]
    LiveWithoutCore,
}

/// What one committed claim leaves for the caller to finish outside the locks.
///
/// Everything in here is something that cannot be dealt with where it was
/// produced: the daemon's half of the transaction runs under core's handlers
/// lock *and* this registry's tables lock, and releasing a registration or
/// settling a pending call reaches code that must not run under either.
pub struct ClaimCommitted {
    /// The client this claim took the method from, if it took it from anyone.
    displaced: Option<ClientId>,
    /// The core registration this claim replaced in an existing record.
    ///
    /// The token alone and not the whole record: a re-claim writes over the
    /// value in a node that already exists, so the node and the lease funding
    /// its key stay exactly where they are. Taking the record out would release
    /// the funding for a key the table is still holding.
    retired: Option<HandlerToken>,
    /// Everything the displaced owner had in flight on this exact method,
    /// detached under the same acquisition that moved the claim so no call can
    /// be admitted to an owner that has just stopped being one.
    settled: crate::ipc::LeasedList<PendingRecord>,
}

/// A registry reference that does not keep the registry alive.
///
/// Every synthetic handler closure holds one of these, and it has to be weak.
/// A live network owns its handler entries, and an entry owns the closure — so
/// a strong clone in the closure would make the *network* an owner of this
/// registry. The control runtime dropping its registry would then free nothing:
/// every client record, every held name and all of their funding would stay
/// alive until the handler was forgotten or the gateway closed, which is a
/// different lifetime entirely and not one the daemon controls.
///
/// Not a reference cycle — an [`OwnedMethodRegistration`] holds only a `Weak`
/// to the dispatcher and keeps nothing alive — but the retention is just as
/// real, and it is the daemon's own state being retained.
///
/// [`OwnedMethodRegistration`]: myownmesh_core::rpc::OwnedMethodRegistration
#[derive(Clone)]
pub struct WeakClientRegistry {
    inner: std::sync::Weak<RegistryInner>,
}

impl WeakClientRegistry {
    /// The registry, if it is still alive. `None` means the daemon is gone and
    /// the caller has nothing left to route to.
    pub fn upgrade(&self) -> Option<ClientRegistry> {
        self.inner.upgrade().map(|inner| ClientRegistry { inner })
    }
}

impl Drop for RegistryTables {
    fn drop(&mut self) {
        // A synchronous drop cannot await. Abort any handle that escaped an
        // orderly control shutdown so the fallback is cancellation, never a
        // live detached watchdog. The normal shutdown path observes JoinError
        // through `drain_watchdogs` first.
        while let Some(handle) = self.watchdogs.pop() {
            handle.abort();
        }
    }
}

/// Every operation this registry performs on the tables declared above.
///
/// A descendant, so it reaches every private field here without any of them
/// being widened for it. What the state *is* stays with the claims that fund
/// it; what is *done* with it lives there.
mod registry;

#[cfg(test)]
mod watchdog_tests {
    use super::{ClientRegistry, IpcAdmissionError};
    use myownmesh_core::ResourceClaim;

    #[tokio::test]
    async fn watchdog_completion_panic_and_shutdown_are_joined_once() {
        let registry = ClientRegistry::default();

        let completion_admission = registry.lease_task().expect("completion is funded");
        let completion = tokio::spawn(async move {
            drop(completion_admission);
        });
        registry
            .retain_watchdog(completion)
            .expect("completion handle is retained");

        let panic_admission = registry.lease_task().expect("panic is funded");
        let panic_task = tokio::spawn(async move {
            drop(panic_admission);
            panic!("watchdog control panic");
        });
        registry
            .retain_watchdog(panic_task)
            .expect("panic handle is retained");

        let shutdown_registry = registry.clone();
        let shutdown_admission = registry.lease_task().expect("shutdown is funded");
        let shutdown_task = tokio::spawn(async move {
            shutdown_registry.closing().await;
            drop(shutdown_admission);
        });
        registry
            .retain_watchdog(shutdown_task)
            .expect("shutdown handle is retained");

        assert!(registry.begin_closing(), "the first close fences admission");
        assert_eq!(
            registry.drain_watchdogs().await,
            1,
            "completion and shutdown are observed, and only panic is abnormal"
        );
        assert_eq!(registry.residue().watchdogs, 0);
        registry.wait_for_tasks().await;
    }

    #[tokio::test]
    async fn watchdog_admission_refuses_full_and_closed_without_detaching() {
        let full = ClientRegistry::over_grant(ResourceClaim::ZERO);
        let full_task = tokio::spawn(async {});
        let (full_task, refusal) = full
            .retain_watchdog(full_task)
            .expect_err("a zero grant cannot retain a watchdog node");
        assert!(matches!(refusal, IpcAdmissionError::Resources(_)));
        full_task.abort();
        let _ = full_task.await;
        assert_eq!(full.residue().watchdogs, 0);

        let closed = ClientRegistry::default();
        assert!(closed.begin_closing());
        let closed_task = tokio::spawn(async {});
        let (closed_task, refusal) = closed
            .retain_watchdog(closed_task)
            .expect_err("a closing registry cannot retain a watchdog");
        assert!(matches!(refusal, IpcAdmissionError::Closing));
        closed_task
            .await
            .expect("the refused handle remains owned by this control");
        assert_eq!(closed.residue().watchdogs, 0);
    }
}

#[cfg(test)]
mod tests;
