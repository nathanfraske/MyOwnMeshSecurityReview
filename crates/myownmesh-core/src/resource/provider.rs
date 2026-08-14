//! Generic, connector-neutral resource admission primitives.
//!
//! A [`ResourceProviderPort`] is the authority-bearing entry point. It mints
//! process-local scopes, but scope creation does not mint capacity. Capacity
//! enters through the provider selected by the process owner, and every
//! successful acquisition is represented by one non-cloneable
//! [`ResourceLease`].

use std::collections::BTreeSet;
use std::fmt;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use tokio::sync::Notify;

/// Number of independent dimensions in a [`ResourceClaim`].
pub const RESOURCE_CLASS_COUNT: usize = 11;

/// Connector-neutral resource dimensions understood by the admission spine.
///
/// Each value is an ordinary finite quantity. No value, including `u64::MAX`,
/// means unlimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
pub enum ResourceClass {
    AccountedMemoryBytes,
    QueuedBytes,
    SocketOrHandle,
    NativeTransportObject,
    WorkerOrTask,
    CallbackOrScheduledWork,
    StorageBytes,
    StorageObject,
    RelayOrProviderAllocation,
    ParsingOrCpuWork,
    OpaqueDependencyResidual,
}

impl ResourceClass {
    pub const ALL: [Self; RESOURCE_CLASS_COUNT] = [
        Self::AccountedMemoryBytes,
        Self::QueuedBytes,
        Self::SocketOrHandle,
        Self::NativeTransportObject,
        Self::WorkerOrTask,
        Self::CallbackOrScheduledWork,
        Self::StorageBytes,
        Self::StorageObject,
        Self::RelayOrProviderAllocation,
        Self::ParsingOrCpuWork,
        Self::OpaqueDependencyResidual,
    ];

    const fn index(self) -> usize {
        self as usize
    }
}

/// A finite, composite resource quantity.
///
/// The representation has no unlimited sentinel. Composite construction and
/// arithmetic report the exact dimension that overflowed or underflowed.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResourceClaim {
    amounts: [u64; RESOURCE_CLASS_COUNT],
}

impl ResourceClaim {
    pub const ZERO: Self = Self {
        amounts: [0; RESOURCE_CLASS_COUNT],
    };

    pub const fn single(dimension: ResourceClass, amount: u64) -> Self {
        let mut amounts = [0; RESOURCE_CLASS_COUNT];
        amounts[dimension.index()] = amount;
        Self { amounts }
    }

    pub fn try_from_entries(
        entries: impl IntoIterator<Item = (ResourceClass, u64)>,
    ) -> Result<Self, ResourceClaimArithmeticError> {
        let mut claim = Self::ZERO;
        for (dimension, amount) in entries {
            claim.amounts[dimension.index()] = claim
                .amount(dimension)
                .checked_add(amount)
                .ok_or(ResourceClaimArithmeticError::Overflow { dimension })?;
        }
        Ok(claim)
    }

    pub const fn amount(self, dimension: ResourceClass) -> u64 {
        self.amounts[dimension.index()]
    }

    pub fn checked_add(self, other: Self) -> Result<Self, ResourceClaimArithmeticError> {
        let mut result = Self::ZERO;
        for dimension in ResourceClass::ALL {
            result.amounts[dimension.index()] = self
                .amount(dimension)
                .checked_add(other.amount(dimension))
                .ok_or(ResourceClaimArithmeticError::Overflow { dimension })?;
        }
        Ok(result)
    }

    pub fn checked_sub(self, other: Self) -> Result<Self, ResourceClaimArithmeticError> {
        let mut result = Self::ZERO;
        for dimension in ResourceClass::ALL {
            result.amounts[dimension.index()] = self
                .amount(dimension)
                .checked_sub(other.amount(dimension))
                .ok_or(ResourceClaimArithmeticError::Underflow { dimension })?;
        }
        Ok(result)
    }

    /// Multiply every resource dimension by an explicit finite factor.
    ///
    /// This is claim arithmetic only. It creates no lease, capacity, object
    /// count, or unlimited sentinel.
    pub fn checked_scale(self, factor: u64) -> Result<Self, ResourceClaimArithmeticError> {
        let mut result = Self::ZERO;
        for dimension in ResourceClass::ALL {
            result.amounts[dimension.index()] = self
                .amount(dimension)
                .checked_mul(factor)
                .ok_or(ResourceClaimArithmeticError::Overflow { dimension })?;
        }
        Ok(result)
    }

    pub fn is_zero(self) -> bool {
        self.amounts.iter().all(|amount| *amount == 0)
    }
}

impl Default for ResourceClaim {
    fn default() -> Self {
        Self::ZERO
    }
}

impl fmt::Debug for ResourceClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = formatter.debug_map();
        for dimension in ResourceClass::ALL {
            let amount = self.amount(dimension);
            if amount != 0 {
                map.entry(&dimension, &amount);
            }
        }
        map.finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceClaimArithmeticError {
    Overflow { dimension: ResourceClass },
    Underflow { dimension: ResourceClass },
}

impl fmt::Display for ResourceClaimArithmeticError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overflow { dimension } => {
                write!(formatter, "resource claim overflow in {dimension:?}")
            }
            Self::Underflow { dimension } => {
                write!(formatter, "resource claim underflow in {dimension:?}")
            }
        }
    }
}

impl std::error::Error for ResourceClaimArithmeticError {}

/// A process-local scope identifier minted by one provider port.
///
/// The numeric value is diagnostic only. It carries no capacity and is not a
/// durable identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceScopeId(NonZeroU64);

impl ResourceScopeId {
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

struct ResourceScopeInner {
    id: ResourceScopeId,
    _identity: Arc<ResourceScopeIdentity>,
    parent: Option<ResourceScope>,
    port: Weak<ResourceProviderPortInner>,
    provider: Arc<dyn ResourceProvider>,
    provider_authority: Arc<ResourceProviderAuthority>,
    registered: AtomicBool,
}

#[derive(Debug)]
struct ResourceScopeIdentity {
    _owned: u8,
}

fn scope_identity() -> (Arc<ResourceScopeIdentity>, ResourceScopeId) {
    let identity = Arc::new(ResourceScopeIdentity { _owned: 0 });
    let address = Arc::as_ptr(&identity) as usize as u64;
    let id = ResourceScopeId(
        NonZeroU64::new(address).expect("an allocated resource-scope identity is nonzero"),
    );
    (identity, id)
}

impl Drop for ResourceScopeInner {
    fn drop(&mut self) {
        if let Some(port) = self.port.upgrade() {
            port.scopes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .known_scopes
                .remove(&self.id);
        }
        if self.registered.swap(false, Ordering::AcqRel) {
            self.provider
                .release_scope(&self.provider_authority, self.id);
        }
    }
}

/// Cloneable RAII ownership token for one process-local resource scope.
///
/// A child retains its parent, and every lease retains its exact scope. The
/// final token drop retires the diagnostic identifier from the port registry.
#[derive(Clone)]
pub struct ResourceScope {
    inner: Arc<ResourceScopeInner>,
}

impl ResourceScope {
    pub fn id(&self) -> ResourceScopeId {
        self.inner.id
    }

    pub fn parent_id(&self) -> Option<ResourceScopeId> {
        self.inner.parent.as_ref().map(Self::id)
    }
}

impl fmt::Debug for ResourceScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceScope")
            .field("id", &self.id())
            .field("parent_id", &self.parent_id())
            .finish_non_exhaustive()
    }
}

impl PartialEq for ResourceScope {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl Eq for ResourceScope {}

/// Why an admitted allocation exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResourceAuthorityClass {
    Cleanup,
    Admitted,
    Speculative,
}

/// Exact finite pressure observed in one resource dimension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourcePressure {
    pub scope_id: ResourceScopeId,
    pub authority: ResourceAuthorityClass,
    pub dimension: ResourceClass,
    pub requested: u64,
    pub in_use: u64,
    pub capacity: u64,
}

/// Typed resource-admission failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceUnavailable {
    Pressure(ResourcePressure),
    UnknownScope {
        scope_id: ResourceScopeId,
    },
    /// This scope already owns its one bounded pending admission demand.
    DemandPending {
        scope_id: ResourceScopeId,
    },
    /// The provider selected this exact speculative reservation for cleanup.
    ReclaimRequested {
        scope_id: ResourceScopeId,
    },
    /// Cooperative admission requires exactly one reclaim target for
    /// speculative work and none for stronger authority classes.
    ReclaimTargetMismatch {
        scope_id: ResourceScopeId,
        authority: ResourceAuthorityClass,
    },
    ScopeIdExhausted,
    ProviderInvariant {
        dimension: ResourceClass,
    },
}

impl ResourceUnavailable {
    pub const fn dimension(self) -> Option<ResourceClass> {
        match self {
            Self::Pressure(pressure) => Some(pressure.dimension),
            Self::ProviderInvariant { dimension } => Some(dimension),
            Self::UnknownScope { .. }
            | Self::DemandPending { .. }
            | Self::ReclaimRequested { .. }
            | Self::ReclaimTargetMismatch { .. }
            | Self::ScopeIdExhausted => None,
        }
    }
}

impl fmt::Display for ResourceUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pressure(pressure) => write!(
                formatter,
                "resource pressure in {:?}: requested {}, in use {}, capacity {}",
                pressure.dimension, pressure.requested, pressure.in_use, pressure.capacity
            ),
            Self::UnknownScope { scope_id } => {
                write!(formatter, "unknown resource scope {}", scope_id.get())
            }
            Self::DemandPending { scope_id } => write!(
                formatter,
                "resource scope {} already owns a pending admission demand",
                scope_id.get()
            ),
            Self::ReclaimRequested { scope_id } => write!(
                formatter,
                "resource scope {} owns a reservation selected for reclamation",
                scope_id.get()
            ),
            Self::ReclaimTargetMismatch {
                scope_id,
                authority,
            } => write!(
                formatter,
                "resource scope {} supplied an invalid reclaim target for {authority:?}",
                scope_id.get()
            ),
            Self::ScopeIdExhausted => formatter.write_str("resource scope identifiers exhausted"),
            Self::ProviderInvariant { dimension } => {
                write!(
                    formatter,
                    "resource provider invariant failed in {dimension:?}"
                )
            }
        }
    }
}

impl std::error::Error for ResourceUnavailable {}

#[derive(Debug)]
struct ReclaimSignal {
    requested: AtomicBool,
    ready: Notify,
}

/// Opaque provider authority to ask one exact speculative owner to retire.
///
/// The target has no public operation. Moving it into a cooperative
/// acquisition lets the provider request cleanup, but never lets the provider
/// release or alter the corresponding resource charge.
#[derive(Clone)]
pub struct ResourceReclaimTarget {
    signal: Arc<ReclaimSignal>,
}

impl fmt::Debug for ResourceReclaimTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceReclaimTarget")
            .finish_non_exhaustive()
    }
}

/// Owner-side observation of a provider reclaim request.
///
/// A request is sticky and has no elapsed-time meaning. The owner completes
/// reclamation only by dropping its exact lease after cleanup, or transfers
/// the exact charge to the provider with
/// [`ResourceLease::retain_after_failed_cleanup`].
#[derive(Clone, Debug)]
pub struct ResourceReclaimSubscription {
    signal: Arc<ReclaimSignal>,
}

impl ResourceReclaimSubscription {
    /// Create the two ends for one speculative reservation.
    pub fn channel() -> (ResourceReclaimTarget, Self) {
        let signal = Arc::new(ReclaimSignal {
            requested: AtomicBool::new(false),
            ready: Notify::new(),
        });
        (
            ResourceReclaimTarget {
                signal: Arc::clone(&signal),
            },
            Self { signal },
        )
    }

    pub fn is_requested(&self) -> bool {
        self.signal.requested.load(Ordering::Acquire)
    }

    /// Wait until the provider asks this exact speculative owner to retire.
    pub async fn requested(&self) {
        loop {
            let notified = self.signal.ready.notified();
            if self.is_requested() {
                return;
            }
            notified.await;
        }
    }
}

impl ResourceReclaimTarget {
    fn request(&self) {
        if !self.signal.requested.swap(true, Ordering::AcqRel) {
            self.signal.ready.notify_waiters();
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DemandOutcome {
    Waiting,
    Granted {
        reservation_id: u64,
        created_scope_id: Option<ResourceScopeId>,
    },
    Pressured(ResourcePressure),
    Cancelled,
}

#[derive(Debug)]
struct DemandSignal {
    outcome: Mutex<DemandOutcome>,
    ready: Notify,
}

impl DemandSignal {
    fn outcome(&self) -> DemandOutcome {
        *self
            .outcome
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn set(&self, outcome: DemandOutcome) {
        *self
            .outcome
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = outcome;
        self.ready.notify_waiters();
    }
}

/// Provider-private identity for one pending admission demand.
///
/// It is public only because [`ResourceProvider`] is an installable port. Its
/// fields are private and it grants no resource authority to callers.
#[doc(hidden)]
#[derive(Debug)]
pub struct ResourceDemandIdentity {
    signal: Arc<DemandSignal>,
}

impl ResourceDemandIdentity {
    fn duplicate(&self) -> Self {
        Self {
            signal: Arc::clone(&self.signal),
        }
    }
}

/// Provider result used by [`ResourceProviderPort`] to construct owned public
/// admission values.
#[doc(hidden)]
#[derive(Debug)]
pub enum ResourceProviderAdmission {
    Acquired(u64),
    Pending(ResourceDemandIdentity),
}

/// The process root already owns a different resource-provider identity.
///
/// Replacing the provider while leases may exist would split the process
/// grant. Callers must clone and reuse the originally installed port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the process resource provider is already installed with a different identity")]
pub struct ResourceProviderConflict;

/// Result of asking a provider to reclaim capacity after pressure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReclaimResult {
    NotNeeded,
    Reclaimed(ResourceClaim),
    /// Cleanup could not prove release, so the provider retained the exact
    /// charge without retaining the lease or its product object.
    Retained(ResourceClaim),
    Deferred(ResourcePressure),
    ProviderInvariant {
        dimension: ResourceClass,
    },
}

/// Owner-supplied admission and accounting implementation.
///
/// Reservation identifiers are provider-local and must identify one live
/// reservation exactly. `transition` must replace `current` with `replacement`
/// atomically. `release` is called exactly once by the owning lease. Provider
/// implementations must not call back into application code while holding an
/// internal accounting lock.
///
/// Every mutating method requires the unforgeable authority owned by the
/// [`ResourceProviderPort`]. Keeping a clone of a concrete provider therefore
/// cannot release, replace, or reuse port-owned reservations.
pub struct ResourceProviderAuthority {
    _private: (),
    identity: Arc<ResourceScopeIdentity>,
}

/// Provider-local facts that identify the exact reservation being replaced.
///
/// This value is not authority. Mutating the provider still requires the
/// matching unforgeable [`ResourceProviderAuthority`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceReservationState {
    pub reservation_id: u64,
    pub scope_id: ResourceScopeId,
    pub authority: ResourceAuthorityClass,
    pub claim: ResourceClaim,
}

pub trait ResourceProvider: Send + Sync + 'static {
    /// Account one provider-owned scope record. This consumes bookkeeping
    /// capacity but grants no capacity to the new scope.
    fn create_scope(
        &self,
        provider_authority: &ResourceProviderAuthority,
        scope_id: ResourceScopeId,
        parent_scope_id: Option<ResourceScopeId>,
    ) -> Result<(), ResourceUnavailable>;

    /// Atomically create one child scope and acquire its first lease.
    ///
    /// Keeping these operations in one provider transaction prevents
    /// concurrent empty child scopes from consuming the bookkeeping needed by
    /// an otherwise admissible claim.
    fn create_scope_and_acquire(
        &self,
        provider_authority: &ResourceProviderAuthority,
        scope_id: ResourceScopeId,
        parent_scope_id: ResourceScopeId,
        authority: ResourceAuthorityClass,
        claim: ResourceClaim,
    ) -> Result<u64, ResourceUnavailable>;

    /// Atomically create one child scope and acquire its first speculative
    /// lease through the cooperative fairness path.
    fn create_scope_and_acquire_cooperatively(
        &self,
        provider_authority: &ResourceProviderAuthority,
        scope_id: ResourceScopeId,
        parent_scope_id: ResourceScopeId,
        claim: ResourceClaim,
        reclaim_target: ResourceReclaimTarget,
    ) -> Result<ResourceProviderAdmission, ResourceUnavailable>;

    /// Release the provider-owned record for a retired scope.
    fn release_scope(
        &self,
        provider_authority: &ResourceProviderAuthority,
        scope_id: ResourceScopeId,
    );

    fn acquire(
        &self,
        provider_authority: &ResourceProviderAuthority,
        scope_id: ResourceScopeId,
        authority: ResourceAuthorityClass,
        claim: ResourceClaim,
    ) -> Result<u64, ResourceUnavailable>;

    /// Acquire through the bounded fairness path.
    ///
    /// A speculative acquisition must provide its one-shot reclaim target.
    /// A pressured request may become the scope's single pending demand. The
    /// provider may ask exact speculative owners to retire, but it cannot
    /// release their reservations.
    fn acquire_cooperatively(
        &self,
        provider_authority: &ResourceProviderAuthority,
        scope_id: ResourceScopeId,
        authority: ResourceAuthorityClass,
        claim: ResourceClaim,
        reclaim_target: Option<ResourceReclaimTarget>,
    ) -> Result<ResourceProviderAdmission, ResourceUnavailable>;

    /// Try one reclaimable speculative acquisition without creating a demand
    /// or requesting another owner to retire.
    fn acquire_reclaimable_now(
        &self,
        provider_authority: &ResourceProviderAuthority,
        scope_id: ResourceScopeId,
        claim: ResourceClaim,
        reclaim_target: ResourceReclaimTarget,
    ) -> Result<u64, ResourceUnavailable>;

    /// Retry the exact move-only demand after its readiness signal fires.
    fn retry_demand(
        &self,
        provider_authority: &ResourceProviderAuthority,
        scope_id: ResourceScopeId,
        demand: &ResourceDemandIdentity,
    ) -> Result<ResourceProviderAdmission, ResourceUnavailable>;

    /// Cancel the exact demand. A pre-granted reservation is released here.
    fn cancel_demand(
        &self,
        provider_authority: &ResourceProviderAuthority,
        scope_id: ResourceScopeId,
        demand: &ResourceDemandIdentity,
    );

    fn transition(
        &self,
        provider_authority: &ResourceProviderAuthority,
        current: ResourceReservationState,
        replacement_authority: ResourceAuthorityClass,
        replacement: ResourceClaim,
    ) -> Result<(), ResourceUnavailable>;

    fn release(
        &self,
        provider_authority: &ResourceProviderAuthority,
        reservation_id: u64,
        scope_id: ResourceScopeId,
        authority: ResourceAuthorityClass,
        claim: ResourceClaim,
    );

    /// Add one holder to a live reservation.
    ///
    /// The claim does not change: this is bookkeeping on an allocation that was
    /// already admitted, and it is how several owners of one shared allocation
    /// come to hold exactly one funding between them. The provider records the
    /// count in the reservation record it already keeps, so a second holder
    /// costs no second record and no further capacity.
    ///
    /// Refuses rather than saturates. A count that wrapped would let the final
    /// decrement arrive early and release a claim whose allocation was still
    /// live, which is the precise failure this whole mechanism exists to
    /// prevent.
    fn retain_shared(
        &self,
        provider_authority: &ResourceProviderAuthority,
        reservation_id: u64,
        scope_id: ResourceScopeId,
    ) -> Result<(), ResourceUnavailable>;

    /// Remove one holder, releasing the claim if and only if it was the last.
    ///
    /// The counterpart to [`ResourceProvider::retain_shared`]. For a singly
    /// held reservation this is exactly [`ResourceProvider::release`]; for a
    /// multiply held one it returns capacity to nobody until the final holder
    /// is gone.
    fn release_shared(
        &self,
        provider_authority: &ResourceProviderAuthority,
        reservation_id: u64,
        scope_id: ResourceScopeId,
        authority: ResourceAuthorityClass,
        claim: ResourceClaim,
    );

    /// Consume a reservation whose underlying cleanup failed.
    ///
    /// The provider must retain the exact charge. It must not make that
    /// capacity available for reuse merely because the caller no longer owns
    /// a lease.
    fn retain_after_failed_cleanup(
        &self,
        provider_authority: &ResourceProviderAuthority,
        reservation_id: u64,
        scope_id: ResourceScopeId,
        authority: ResourceAuthorityClass,
        claim: ResourceClaim,
    ) -> ReclaimResult;

    /// Return a diagnostic snapshot. This method never grants authority.
    fn pressure(
        &self,
        provider_authority: &ResourceProviderAuthority,
        scope_id: ResourceScopeId,
        authority: ResourceAuthorityClass,
        dimension: ResourceClass,
    ) -> ResourcePressure;

    fn reclaim(
        &self,
        provider_authority: &ResourceProviderAuthority,
        scope_id: ResourceScopeId,
        pressure: &ResourcePressure,
    ) -> ReclaimResult;
}

#[derive(Debug)]
struct ScopeRegistry {
    known_scopes: BTreeSet<ResourceScopeId>,
}

struct ResourceProviderPortInner {
    provider: Arc<dyn ResourceProvider>,
    provider_authority: Arc<ResourceProviderAuthority>,
    scopes: Mutex<ScopeRegistry>,
    process_scope: ResourceScope,
}

/// Cloneable authority port for one process resource provider.
///
/// The port validates scopes under its registry lock and releases that lock
/// before invoking provider code. Provider callbacks can therefore re-enter a
/// port without deadlocking on the scope registry.
#[derive(Clone)]
pub struct ResourceProviderPort {
    inner: Arc<ResourceProviderPortInner>,
}

impl fmt::Debug for ResourceProviderPort {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceProviderPort")
            .field("process_scope", &self.inner.process_scope.id())
            .finish_non_exhaustive()
    }
}

impl ResourceProviderPort {
    pub fn new(provider: impl ResourceProvider) -> Result<Self, ResourceUnavailable> {
        let provider: Arc<dyn ResourceProvider> = Arc::new(provider);
        let (process_identity, process_scope_id) = scope_identity();
        let provider_authority = Arc::new(ResourceProviderAuthority {
            _private: (),
            identity: Arc::clone(&process_identity),
        });
        let inner = Arc::new_cyclic(|weak_port| {
            let process_scope = ResourceScope {
                inner: Arc::new(ResourceScopeInner {
                    id: process_scope_id,
                    _identity: Arc::clone(&process_identity),
                    parent: None,
                    port: Weak::clone(weak_port),
                    provider: Arc::clone(&provider),
                    provider_authority: Arc::clone(&provider_authority),
                    registered: AtomicBool::new(false),
                }),
            };
            let mut known_scopes = BTreeSet::new();
            known_scopes.insert(process_scope_id);
            ResourceProviderPortInner {
                provider,
                provider_authority,
                scopes: Mutex::new(ScopeRegistry { known_scopes }),
                process_scope,
            }
        });
        inner
            .provider
            .create_scope(&inner.provider_authority, inner.process_scope.id(), None)?;
        inner
            .process_scope
            .inner
            .registered
            .store(true, Ordering::Release);
        Ok(Self { inner })
    }

    pub fn process_scope(&self) -> ResourceScope {
        self.inner.process_scope.clone()
    }

    /// True only when both ports reference the same provider and scope root.
    pub fn same_provider(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// Mint a child scope without granting it any capacity.
    pub fn create_scope(
        &self,
        parent: &ResourceScope,
    ) -> Result<ResourceScope, ResourceUnavailable> {
        self.validate_scope(parent)?;
        // Identity is tied to a live allocation rather than a never-reused
        // process counter. A refused scope therefore burns no lifetime-wide
        // namespace, and an address can be reused only after the old scope and
        // every lease retaining it have been released.
        let (identity, scope_id) = scope_identity();
        if self.lock_scopes().known_scopes.contains(&scope_id) {
            return Err(ResourceUnavailable::ScopeIdExhausted);
        }
        let scope = ResourceScope {
            inner: Arc::new(ResourceScopeInner {
                id: scope_id,
                _identity: identity,
                parent: Some(parent.clone()),
                port: Arc::downgrade(&self.inner),
                provider: Arc::clone(&self.inner.provider),
                provider_authority: Arc::clone(&self.inner.provider_authority),
                registered: AtomicBool::new(false),
            }),
        };
        self.inner.provider.create_scope(
            &self.inner.provider_authority,
            scope_id,
            Some(parent.id()),
        )?;
        scope.inner.registered.store(true, Ordering::Release);
        self.lock_scopes().known_scopes.insert(scope_id);
        Ok(scope)
    }

    /// Mint one additional trusted fairness-root scope. Test-only.
    ///
    /// Production installs exactly one process root, minted with the port, and
    /// no production path mints another — so this is compiled only under
    /// `cfg(test)`, where controls need several roots to observe cross-root
    /// arbitration at all. It is additionally `pub(crate)`, so even in a test
    /// build no downstream caller can reach it.
    ///
    /// The gate is deliberate rather than an allow: a production caller for
    /// additional trusted roots does not exist yet, and claiming otherwise
    /// would misrepresent the current shape. When a real trusted-composition
    /// caller lands, remove the `cfg(test)` and keep the `pub(crate)`.
    ///
    /// It takes no root argument and returns no root value. The root itself is
    /// provider-private; the caller receives only an ordinary
    /// [`ResourceScope`], and every child created beneath it inherits that root
    /// like any other child. Passing `None` as the parent is what signals the
    /// provider to mint a fresh root rather than inherit one.
    #[cfg(test)]
    pub(crate) fn create_fairness_root_scope(&self) -> Result<ResourceScope, ResourceUnavailable> {
        let (identity, scope_id) = scope_identity();
        if self.lock_scopes().known_scopes.contains(&scope_id) {
            return Err(ResourceUnavailable::ScopeIdExhausted);
        }
        let scope = ResourceScope {
            inner: Arc::new(ResourceScopeInner {
                id: scope_id,
                _identity: identity,
                // A root scope has no parent to inherit attribution from. It is
                // retained by its own descendants, which keeps its order, and
                // therefore the root wrapping that order, alive.
                parent: None,
                port: Arc::downgrade(&self.inner),
                provider: Arc::clone(&self.inner.provider),
                provider_authority: Arc::clone(&self.inner.provider_authority),
                registered: AtomicBool::new(false),
            }),
        };
        self.inner
            .provider
            .create_scope(&self.inner.provider_authority, scope_id, None)?;
        scope.inner.registered.store(true, Ordering::Release);
        self.lock_scopes().known_scopes.insert(scope_id);
        Ok(scope)
    }

    /// Atomically mint a child scope and acquire its first exact lease.
    pub fn create_scope_with_lease(
        &self,
        parent: &ResourceScope,
        authority: ResourceAuthorityClass,
        claim: ResourceClaim,
    ) -> Result<(ResourceScope, ResourceLease), ResourceUnavailable> {
        self.validate_scope(parent)?;
        let (identity, scope_id) = scope_identity();
        if self.lock_scopes().known_scopes.contains(&scope_id) {
            return Err(ResourceUnavailable::ScopeIdExhausted);
        }
        let scope = ResourceScope {
            inner: Arc::new(ResourceScopeInner {
                id: scope_id,
                _identity: identity,
                parent: Some(parent.clone()),
                port: Arc::downgrade(&self.inner),
                provider: Arc::clone(&self.inner.provider),
                provider_authority: Arc::clone(&self.inner.provider_authority),
                registered: AtomicBool::new(false),
            }),
        };
        let reservation_id = self.inner.provider.create_scope_and_acquire(
            &self.inner.provider_authority,
            scope_id,
            parent.id(),
            authority,
            claim,
        )?;
        scope.inner.registered.store(true, Ordering::Release);
        self.lock_scopes().known_scopes.insert(scope_id);
        let lease = ResourceLease {
            provider: Arc::clone(&self.inner.provider),
            reservation_id: Some(reservation_id),
            scope: scope.clone(),
            authority,
            claim,
        };
        Ok((scope, lease))
    }

    /// Atomically create a child scope and acquire its first reclaimable
    /// speculative lease, or return one move-only pending owner.
    ///
    /// A pending result owns the provisional child identity. The provider does
    /// not install that child scope until it can install the first lease in the
    /// same accounting transaction.
    pub fn create_scope_with_reclaimable_lease_cooperatively(
        &self,
        parent: &ResourceScope,
        claim: ResourceClaim,
        reclaim_target: ResourceReclaimTarget,
    ) -> Result<ResourceAdmission, ResourceUnavailable> {
        self.validate_scope(parent)?;
        let (identity, scope_id) = scope_identity();
        if self.lock_scopes().known_scopes.contains(&scope_id) {
            return Err(ResourceUnavailable::ScopeIdExhausted);
        }
        let scope = ResourceScope {
            inner: Arc::new(ResourceScopeInner {
                id: scope_id,
                _identity: identity,
                parent: Some(parent.clone()),
                port: Arc::downgrade(&self.inner),
                provider: Arc::clone(&self.inner.provider),
                provider_authority: Arc::clone(&self.inner.provider_authority),
                registered: AtomicBool::new(false),
            }),
        };
        let provider_admission = self.inner.provider.create_scope_and_acquire_cooperatively(
            &self.inner.provider_authority,
            scope_id,
            parent.id(),
            claim,
            reclaim_target,
        )?;
        Ok(match provider_admission {
            ResourceProviderAdmission::Acquired(reservation_id) => {
                scope.inner.registered.store(true, Ordering::Release);
                self.lock_scopes().known_scopes.insert(scope_id);
                ResourceAdmission::Acquired(ResourceLease {
                    provider: Arc::clone(&self.inner.provider),
                    reservation_id: Some(reservation_id),
                    scope,
                    authority: ResourceAuthorityClass::Speculative,
                    claim,
                })
            }
            ResourceProviderAdmission::Pending(identity) => {
                ResourceAdmission::Pending(ResourceAcquireDemand {
                    provider: Arc::clone(&self.inner.provider),
                    identity,
                    scope,
                    demand_scope_id: parent.id(),
                    authority: ResourceAuthorityClass::Speculative,
                    claim,
                    register_scope_on_acquire: true,
                    active: true,
                })
            }
        })
    }

    pub fn acquire(
        &self,
        scope: &ResourceScope,
        authority: ResourceAuthorityClass,
        claim: ResourceClaim,
    ) -> Result<ResourceLease, ResourceUnavailable> {
        self.validate_scope(scope)?;
        let scope_id = scope.id();
        let reservation_id = self.inner.provider.acquire(
            &self.inner.provider_authority,
            scope_id,
            authority,
            claim,
        )?;
        Ok(ResourceLease {
            provider: Arc::clone(&self.inner.provider),
            reservation_id: Some(reservation_id),
            scope: scope.clone(),
            authority,
            claim,
        })
    }

    /// Acquire through the provider's bounded cooperative-preemption path.
    ///
    /// `Speculative` work must supply a fresh target from
    /// [`ResourceReclaimSubscription::channel`]. `Admitted` and `Cleanup`
    /// work pass `None`. A pending result owns this scope's sole fairness turn
    /// and must be retained, retried, or dropped to cancel it.
    pub fn acquire_cooperatively(
        &self,
        scope: &ResourceScope,
        authority: ResourceAuthorityClass,
        claim: ResourceClaim,
        reclaim_target: Option<ResourceReclaimTarget>,
    ) -> Result<ResourceAdmission, ResourceUnavailable> {
        self.validate_scope(scope)?;
        let provider_admission = self.inner.provider.acquire_cooperatively(
            &self.inner.provider_authority,
            scope.id(),
            authority,
            claim,
            reclaim_target,
        )?;
        Ok(match provider_admission {
            ResourceProviderAdmission::Acquired(reservation_id) => {
                ResourceAdmission::Acquired(ResourceLease {
                    provider: Arc::clone(&self.inner.provider),
                    reservation_id: Some(reservation_id),
                    scope: scope.clone(),
                    authority,
                    claim,
                })
            }
            ResourceProviderAdmission::Pending(identity) => {
                ResourceAdmission::Pending(ResourceAcquireDemand {
                    provider: Arc::clone(&self.inner.provider),
                    identity,
                    scope: scope.clone(),
                    demand_scope_id: scope.id(),
                    authority,
                    claim,
                    register_scope_on_acquire: false,
                    active: true,
                })
            }
        })
    }

    /// Try one reclaimable speculative acquisition without retaining a
    /// pending demand. Pressure is returned synchronously and does not request
    /// cleanup from any existing owner.
    pub fn acquire_reclaimable_now(
        &self,
        scope: &ResourceScope,
        claim: ResourceClaim,
        reclaim_target: ResourceReclaimTarget,
    ) -> Result<ResourceLease, ResourceUnavailable> {
        self.validate_scope(scope)?;
        let reservation_id = self.inner.provider.acquire_reclaimable_now(
            &self.inner.provider_authority,
            scope.id(),
            claim,
            reclaim_target,
        )?;
        Ok(ResourceLease {
            provider: Arc::clone(&self.inner.provider),
            reservation_id: Some(reservation_id),
            scope: scope.clone(),
            authority: ResourceAuthorityClass::Speculative,
            claim,
        })
    }

    pub fn reclaim(
        &self,
        scope: &ResourceScope,
        pressure: &ResourcePressure,
    ) -> Result<ReclaimResult, ResourceUnavailable> {
        self.validate_scope(scope)?;
        Ok(self
            .inner
            .provider
            .reclaim(&self.inner.provider_authority, scope.id(), pressure))
    }

    /// Read current pressure without reserving capacity or authorizing work.
    pub fn pressure(
        &self,
        scope: &ResourceScope,
        authority: ResourceAuthorityClass,
        dimension: ResourceClass,
    ) -> Result<ResourcePressure, ResourceUnavailable> {
        self.validate_scope(scope)?;
        Ok(self.inner.provider.pressure(
            &self.inner.provider_authority,
            scope.id(),
            authority,
            dimension,
        ))
    }

    fn validate_scope(&self, scope: &ResourceScope) -> Result<(), ResourceUnavailable> {
        let same_port = scope
            .inner
            .port
            .upgrade()
            .is_some_and(|port| Arc::ptr_eq(&port, &self.inner));
        let known = same_port && self.lock_scopes().known_scopes.contains(&scope.id());
        if known {
            Ok(())
        } else {
            Err(ResourceUnavailable::UnknownScope {
                scope_id: scope.id(),
            })
        }
    }

    fn lock_scopes(&self) -> MutexGuard<'_, ScopeRegistry> {
        self.inner
            .scopes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// One exact, non-cloneable resource allocation.
///
/// Dropping the lease releases its current claim exactly once. Transition is
/// atomic at the provider boundary: the lease changes its local claim only
/// after the provider commits the complete replacement.
#[must_use = "dropping the lease immediately releases the resource allocation"]
pub struct ResourceLease {
    provider: Arc<dyn ResourceProvider>,
    reservation_id: Option<u64>,
    scope: ResourceScope,
    authority: ResourceAuthorityClass,
    claim: ResourceClaim,
}

impl fmt::Debug for ResourceLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceLease")
            .field("scope_id", &self.scope.id())
            .field("authority", &self.authority)
            .field("claim", &self.claim)
            .finish_non_exhaustive()
    }
}

impl ResourceLease {
    pub fn scope_id(&self) -> ResourceScopeId {
        self.scope.id()
    }

    pub fn scope(&self) -> ResourceScope {
        self.scope.clone()
    }

    pub const fn authority(&self) -> ResourceAuthorityClass {
        self.authority
    }

    pub const fn claim(&self) -> ResourceClaim {
        self.claim
    }

    pub fn transition(&mut self, replacement: ResourceClaim) -> Result<(), ResourceUnavailable> {
        self.transition_to(self.authority, replacement)
    }

    /// Atomically replace both the authority class and resource claim.
    ///
    /// A refusal leaves both old values intact.
    pub fn transition_to(
        &mut self,
        replacement_authority: ResourceAuthorityClass,
        replacement: ResourceClaim,
    ) -> Result<(), ResourceUnavailable> {
        let reservation_id = self
            .reservation_id
            .expect("a live resource lease always owns its reservation");
        self.provider.transition(
            &self.scope.inner.provider_authority,
            ResourceReservationState {
                reservation_id,
                scope_id: self.scope.id(),
                authority: self.authority,
                claim: self.claim,
            },
            replacement_authority,
            replacement,
        )?;
        self.authority = replacement_authority;
        self.claim = replacement;
        Ok(())
    }

    /// Transfer an exact charge to the provider after cleanup cannot prove
    /// that the protected native resource was released.
    ///
    /// This consumes the lease and suppresses ordinary Drop release. The
    /// provider becomes the sole owner of the retained charge.
    pub fn retain_after_failed_cleanup(mut self) -> ReclaimResult {
        let Some(reservation_id) = self.reservation_id.take() else {
            return ReclaimResult::ProviderInvariant {
                dimension: ResourceClass::OpaqueDependencyResidual,
            };
        };
        self.provider.retain_after_failed_cleanup(
            &self.scope.inner.provider_authority,
            reservation_id,
            self.scope.id(),
            self.authority,
            self.claim,
        )
    }
}

impl Drop for ResourceLease {
    fn drop(&mut self) {
        if let Some(reservation_id) = self.reservation_id.take() {
            self.provider.release(
                &self.scope.inner.provider_authority,
                reservation_id,
                self.scope.id(),
                self.authority,
                self.claim,
            );
        }
    }
}

/// One reservation held by several owners at once.
///
/// The counterpart to [`ResourceLease`] for an allocation that genuinely has
/// more than one owner — an `Arc` whose clones outlive each other in no fixed
/// order. Cloning this adds a holder to the *same* reservation rather than
/// taking out a second one, so the allocation is funded exactly once no matter
/// how many handles exist, and the claim goes back on the final drop and not
/// before.
///
/// **No new allocation.** The holder count lives in the reservation record the
/// provider already keeps, and this handle is the same inline fields
/// [`ResourceLease`] has. Sharing therefore costs no second record, which is
/// what keeps the accounting exact rather than merely conservative.
///
/// **Deliberately not convertible back.** There is no way to turn this into a
/// [`ResourceLease`], and it has neither `transition` nor
/// `retain_after_failed_cleanup`. Both of those speak for a whole reservation,
/// and a holder that shares one cannot speak for the owners it does not know
/// about. Making them unspellable is the enforcement; the provider also refuses
/// an outright `release` of a multiply held reservation, so neither layer
/// relies on the other being careful.
///
/// **Private, and never re-exported.** This type is clonable, and a clone that
/// could be obtained on its own would be a reservation token separated from the
/// allocation it funds — attach two such clones to two different `Arc`s and one
/// claim would silently fund both. So it is reachable only through
/// [`FundedArc`] and [`FundedWeak`], whose `clone`, `downgrade` and `upgrade`
/// are the only callers of `Clone` here and always move a pointer alongside it.
/// Construction takes an exclusive [`ResourceLease`] by value and converts it
/// internally, so a caller never holds one of these to hand out twice.
struct SharedResourceLease {
    provider: Arc<dyn ResourceProvider>,
    reservation_id: Option<u64>,
    scope: ResourceScope,
    authority: ResourceAuthorityClass,
    claim: ResourceClaim,
}

impl fmt::Debug for SharedResourceLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SharedResourceLease")
            .field("scope_id", &self.scope.id())
            .field("authority", &self.authority)
            .field("claim", &self.claim)
            .finish_non_exhaustive()
    }
}

impl SharedResourceLease {
    /// Take over an exclusive lease's reservation without releasing it.
    ///
    /// The lease's reservation is moved across, so the incoming lease drops
    /// having released nothing and the claim never lapses in between.
    ///
    /// **A speculative lease is refused, and comes back intact.** A speculative
    /// reservation carries a reclaim target: the provider may ask its owner to
    /// retire. Sharing it would leave no single owner able to answer that, so
    /// the refusal returns the lease itself rather than an error code — the
    /// caller is left holding exactly the funding it arrived with, which is the
    /// only refusal that cannot leak.
    #[expect(
        clippy::result_large_err,
        reason = "the Err *is* the caller's lease, handed back intact so it keeps funding exactly what it funded on the way in; boxing it would allocate on the refusal path, and any smaller error would mean dropping the lease here — releasing a reservation the caller still believes it holds"
    )]
    fn from_lease(mut lease: ResourceLease) -> Result<Self, ResourceLease> {
        if lease.authority == ResourceAuthorityClass::Speculative {
            return Err(lease);
        }
        // Taken, not copied: the lease must not also release this reservation
        // when it drops at the end of this call.
        let reservation_id = lease.reservation_id.take();
        Ok(Self {
            provider: Arc::clone(&lease.provider),
            reservation_id,
            scope: lease.scope.clone(),
            authority: lease.authority,
            claim: lease.claim,
        })
    }
}

/// Cloning adds a holder to the one reservation this handle already owns.
///
/// **Why this is allowed to be infallible.** `Clone` cannot report a refusal,
/// so the holder increment must not be one that can legitimately fail. It is
/// not: the count is bounded by the number of live handles, and every one of
/// those required a successful `Arc` or `Weak` clone first, so exhausting a
/// `u64` of them is unreachable for exactly the reason exhausting `Arc`'s own
/// count is. The provider still checks rather than assuming, and a violated
/// invariant panics rather than wrapping — the same choice `Arc::clone` makes
/// when it aborts past `isize::MAX`. A wrapped count would let the final
/// decrement arrive early and release a claim whose allocation was still live,
/// which is the precise failure this type exists to prevent.
impl Clone for SharedResourceLease {
    fn clone(&self) -> Self {
        let reservation_id = self
            .reservation_id
            .expect("a live shared lease always owns its reservation");
        self.provider
            .retain_shared(
                &self.scope.inner.provider_authority,
                reservation_id,
                self.scope.id(),
            )
            .expect("a live shared reservation admits another holder");
        Self {
            provider: Arc::clone(&self.provider),
            reservation_id: Some(reservation_id),
            scope: self.scope.clone(),
            authority: self.authority,
            claim: self.claim,
        }
    }
}

impl Drop for SharedResourceLease {
    fn drop(&mut self) {
        if let Some(reservation_id) = self.reservation_id.take() {
            self.provider.release_shared(
                &self.scope.inner.provider_authority,
                reservation_id,
                self.scope.id(),
                self.authority,
                self.claim,
            );
        }
    }
}

/// A shared allocation and the funding that outlives it.
///
/// **The token is a sibling of the pointer, declared after it.** On the final
/// handle's drop the `Arc` goes first — which is when the allocation is
/// actually freed, since no strong and no weak reference remains — and only
/// then does the token decrement and release the claim. A lease stored *inside*
/// the pointee would instead be released by the pointee's own drop glue, while
/// the allocation was still there, which is the defect this type exists to make
/// unspellable.
///
/// Clones follow the same order: pointer first, token second. Every handle,
/// strong or weak, carries a token, so the reservation stays live for as long
/// as any of them can still reach the allocation.
///
/// There is no accessor returning the inner `Arc`. Handing one out would let a
/// caller keep the allocation reachable after the last funded handle had gone,
/// which is the same false release wearing a different shape.
pub struct FundedArc<T: ?Sized> {
    value: Arc<T>,
    _shared: SharedResourceLease,
}

/// A weak handle that keeps its allocation's funding alive.
///
/// A live [`std::sync::Weak`] keeps the shared allocation itself alive — the
/// strong count reaching zero destroys the value but not the storage — so a
/// weak observer that carried no funding would be pointing at accounted memory
/// the provider had been told was free. This carries a token for that reason,
/// and the claim is released only once every handle of either kind is gone.
pub struct FundedWeak<T: ?Sized> {
    value: std::sync::Weak<T>,
    _shared: SharedResourceLease,
}

impl<T> FundedArc<T> {
    /// Fund and share one new allocation.
    ///
    /// Takes the exclusive lease **by value** and converts it internally. The
    /// shared token is never a thing a caller holds, so it cannot be cloned
    /// away from its allocation and attached to a second one — one lease in,
    /// one allocation funded, and no way to spell anything else.
    ///
    /// A speculative lease is refused and handed straight back, still funding
    /// exactly what it funded on the way in: a speculative reservation may be
    /// asked to retire, and no single holder of a shared one could answer that.
    #[expect(
        clippy::result_large_err,
        reason = "the Err is the funding lease returned by value, still funding what it arrived funding; the whole point of taking it by value is that a refusal leaks nothing, which a boxed or narrowed error cannot express"
    )]
    pub fn new(value: T, funding: ResourceLease) -> Result<Self, ResourceLease> {
        let shared = SharedResourceLease::from_lease(funding)?;
        Ok(Self {
            value: Arc::new(value),
            _shared: shared,
        })
    }
}

impl<T: ?Sized> FundedArc<T> {
    /// Adopt an `Arc` that was already built and already admitted.
    ///
    /// The one way to hold an unsized pointee — `Arc<dyn Fn(..)>` and the like —
    /// since unsizing has to happen at the `Arc::new` that this crate performs
    /// before wrapping. Crate-private precisely because the caller supplies the
    /// pointer: an outside caller could pass one it had kept a second copy of,
    /// and the funding would then describe an allocation with a reachable
    /// unfunded alias. Callers outside this crate build through
    /// [`FundedArc::new`], which cannot have that problem because it allocates
    /// the value itself.
    ///
    /// Nothing escapes afterwards: there is still no accessor handing the
    /// pointer back out, and as with [`FundedArc::new`] the exclusive lease is
    /// taken by value and internalized, so no shared token is ever in a
    /// caller's hands to clone onto a second allocation.
    #[expect(
        clippy::result_large_err,
        reason = "same contract as [`FundedArc::new`]: the refused lease comes back by value, intact and still funding its reservation, so the refusal path allocates nothing and releases nothing"
    )]
    pub(crate) fn from_admitted_arc(
        value: Arc<T>,
        funding: ResourceLease,
    ) -> Result<Self, ResourceLease> {
        let shared = SharedResourceLease::from_lease(funding)?;
        Ok(Self {
            value,
            _shared: shared,
        })
    }

    /// A weak handle that keeps this allocation's funding alive.
    pub fn downgrade(&self) -> FundedWeak<T> {
        // Pointer first, token second — the same order as `clone`.
        let value = Arc::downgrade(&self.value);
        let shared = self._shared.clone();
        FundedWeak {
            value,
            _shared: shared,
        }
    }

    /// Whether two handles name the same allocation.
    ///
    /// Exposes the *answer*, not the pointer. An owner proving that the handle
    /// it is holding is the exact one a table still records — rather than a
    /// successor that legitimately took its place — needs this comparison and
    /// nothing else, and giving it the comparison keeps the `Arc` itself from
    /// escaping. Without it a caller would have to invent a second identity to
    /// compare, which is the drift this type exists to prevent.
    pub fn ptr_eq(this: &Self, other: &Self) -> bool {
        Arc::ptr_eq(&this.value, &other.value)
    }

    /// How many strong handles share this allocation. Controls only.
    #[cfg(test)]
    pub(crate) fn strong_count(&self) -> usize {
        Arc::strong_count(&self.value)
    }
}

impl<T: ?Sized> Clone for FundedArc<T> {
    fn clone(&self) -> Self {
        // The pointer is cloned before the token, so a panic in the token's
        // increment cannot leave a strong reference behind with no holder
        // recorded for it.
        let value = Arc::clone(&self.value);
        let shared = self._shared.clone();
        Self {
            value,
            _shared: shared,
        }
    }
}

impl<T: ?Sized> std::ops::Deref for FundedArc<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T: ?Sized> FundedWeak<T> {
    /// A strong handle, if the value is still live.
    ///
    /// The allocation is funded either way — this handle's own token saw to
    /// that — so upgrading only decides whether the *value* is still there.
    pub fn upgrade(&self) -> Option<FundedArc<T>> {
        let value = self.value.upgrade()?;
        let shared = self._shared.clone();
        Some(FundedArc {
            value,
            _shared: shared,
        })
    }

    /// How many strong handles are left — `0` once the value is gone.
    ///
    /// For pruning a registry of weak links without the strong clone that
    /// [`Self::upgrade`] would make just to drop it again. It observes and
    /// hands out nothing, so it cannot be a route to an unfunded alias.
    ///
    /// Says nothing about the funding: this handle's own token keeps the
    /// allocation paid for whether the count is zero or not.
    pub fn strong_count(&self) -> usize {
        std::sync::Weak::strong_count(&self.value)
    }
}

impl<T: ?Sized> Clone for FundedWeak<T> {
    fn clone(&self) -> Self {
        let value = std::sync::Weak::clone(&self.value);
        let shared = self._shared.clone();
        Self {
            value,
            _shared: shared,
        }
    }
}

/// Result of a cooperative resource acquisition.
#[must_use = "a pending demand owns a fairness turn and dropping it cancels that turn"]
#[derive(Debug)]
pub enum ResourceAdmission {
    Acquired(ResourceLease),
    Pending(ResourceAcquireDemand),
}

/// Move-only ownership of one scope's bounded pending admission demand.
///
/// In test builds this exposes the provider-side demand key, so a control can
/// bind its own logical demand id at issue time instead of reconstructing an
/// association afterwards from scope and ordering.
#[must_use = "dropping the demand cancels its fairness turn"]
pub struct ResourceAcquireDemand {
    provider: Arc<dyn ResourceProvider>,
    identity: ResourceDemandIdentity,
    scope: ResourceScope,
    demand_scope_id: ResourceScopeId,
    authority: ResourceAuthorityClass,
    claim: ResourceClaim,
    register_scope_on_acquire: bool,
    active: bool,
}

impl fmt::Debug for ResourceAcquireDemand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceAcquireDemand")
            .field("scope_id", &self.scope.id())
            .field("authority", &self.authority)
            .field("claim", &self.claim)
            .field("active", &self.active)
            .finish_non_exhaustive()
    }
}

impl ResourceAcquireDemand {
    pub fn scope_id(&self) -> ResourceScopeId {
        self.scope.id()
    }

    /// The provider-side identity of this demand, stable for its lifetime.
    ///
    /// Test-only, and deliberately not part of the public surface: it exists so
    /// a control can bind a logical demand id at issue time. It conveys no
    /// authority and names no fairness root.
    #[cfg(test)]
    pub(crate) fn demand_key_for_test(&self) -> usize {
        Arc::as_ptr(&self.identity.signal) as usize
    }

    pub const fn authority(&self) -> ResourceAuthorityClass {
        self.authority
    }

    pub const fn claim(&self) -> ResourceClaim {
        self.claim
    }

    /// Wait until capacity is pre-granted or the provider proves exact
    /// non-reclaimable pressure. This wait has no timer or expiry semantics.
    pub async fn ready(&self) -> Result<(), ResourceUnavailable> {
        loop {
            let notified = self.identity.signal.ready.notified();
            match self.identity.signal.outcome() {
                DemandOutcome::Waiting => notified.await,
                DemandOutcome::Granted { .. } => return Ok(()),
                DemandOutcome::Pressured(pressure) => {
                    return Err(ResourceUnavailable::Pressure(pressure));
                }
                DemandOutcome::Cancelled => {
                    return Err(ResourceUnavailable::DemandPending {
                        scope_id: self.scope.id(),
                    });
                }
            }
        }
    }

    /// Consume this exact turn and collect its pre-granted lease.
    ///
    /// Calling this before `ready` is harmless and returns the same pending
    /// owner. No second waiter or provider reservation is created.
    pub fn retry(mut self) -> Result<ResourceAdmission, ResourceUnavailable> {
        if let DemandOutcome::Pressured(pressure) = self.identity.signal.outcome() {
            self.active = false;
            return Err(ResourceUnavailable::Pressure(pressure));
        }
        let provider_admission = self.provider.retry_demand(
            &self.scope.inner.provider_authority,
            self.demand_scope_id,
            &self.identity,
        )?;
        match provider_admission {
            ResourceProviderAdmission::Acquired(reservation_id) => {
                if self.register_scope_on_acquire {
                    self.scope.inner.registered.store(true, Ordering::Release);
                    if let Some(port) = self.scope.inner.port.upgrade() {
                        port.scopes
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .known_scopes
                            .insert(self.scope.id());
                    }
                }
                self.active = false;
                Ok(ResourceAdmission::Acquired(ResourceLease {
                    provider: Arc::clone(&self.provider),
                    reservation_id: Some(reservation_id),
                    scope: self.scope.clone(),
                    authority: self.authority,
                    claim: self.claim,
                }))
            }
            ResourceProviderAdmission::Pending(_) => Ok(ResourceAdmission::Pending(self)),
        }
    }
}

impl Drop for ResourceAcquireDemand {
    fn drop(&mut self) {
        if self.active {
            self.provider.cancel_demand(
                &self.scope.inner.provider_authority,
                self.demand_scope_id,
                &self.identity,
            );
            self.active = false;
        }
    }
}

mod finite {
    use super::*;
    #[cfg(test)]
    use std::collections::VecDeque;
    use std::collections::{BTreeMap, BTreeSet};

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum ReservationLifecycle {
        Live,
        ReclaimRequested,
    }

    #[derive(Debug)]
    struct Reservation {
        scope_id: ResourceScopeId,
        authority: ResourceAuthorityClass,
        claim: ResourceClaim,
        lifecycle: ReservationLifecycle,
        reclaim_target: Option<ResourceReclaimTarget>,
        /// How many owners hold this one reservation.
        ///
        /// One for every reservation an ordinary [`ResourceLease`] owns, and
        /// that never changes: only a shared reservation moves this, and only
        /// through `retain_shared` and `release_shared`. The claim is released
        /// by the final decrement and by nothing else, which is what lets
        /// several owners of one `Arc` allocation keep exactly one funding
        /// alive between them.
        ///
        /// This is a field of the record the provider already keeps, not a new
        /// record: sharing a reservation allocates nothing and prices nothing
        /// extra. See `bookkeeping_claim`.
        holders: u64,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum DemandPlacement {
        ExistingScope,
        NewChild { scope_id: ResourceScopeId },
    }

    #[derive(Debug)]
    struct PendingDemand {
        authority: ResourceAuthorityClass,
        claim: ResourceClaim,
        reclaim_target: Option<ResourceReclaimTarget>,
        identity: ResourceDemandIdentity,
        placement: DemandPlacement,
    }

    impl PendingDemand {
        fn lease_scope_id(&self, owner_scope_id: ResourceScopeId) -> ResourceScopeId {
            match self.placement {
                DemandPlacement::ExistingScope => owner_scope_id,
                DemandPlacement::NewChild { scope_id } => scope_id,
            }
        }

        fn charge(&self) -> Result<ResourceClaim, ResourceUnavailable> {
            let mut charge = FiniteResourceProvider::reservation_charge(self.claim)?;
            if matches!(self.placement, DemandPlacement::NewChild { .. }) {
                charge = charge
                    .checked_add(FiniteResourceProvider::bookkeeping_claim())
                    .map_err(|_| ResourceUnavailable::ProviderInvariant {
                        dimension: ResourceClass::OpaqueDependencyResidual,
                    })?;
            }
            Ok(charge)
        }
    }

    /// Deterministic process-local ordering position for one live scope.
    ///
    /// This is provider-private. It is never exposed, never serialized, and
    /// never durable. It exists so that scheduling and reclaim decisions have a
    /// stable intra-root tie-breaker that does not depend on the
    /// allocation-address-derived `ResourceScopeId`.
    ///
    /// Orders are recycled: a released order returns to the free set and is
    /// handed to the next scope created. Reuse is deliberate, so that creating
    /// and dropping scopes cannot exhaust an order space and cannot become a
    /// lifetime identity-count quota.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct ScopeOrder(u64);

    /// Private, process-local fairness attribution.
    ///
    /// A `FairnessRoot` wraps the live `ScopeOrder` of the trusted root scope
    /// it attributes. It is provider-private: no caller can name one, supply
    /// one, or observe one, and it is neither serialized nor durable. Parent
    /// retention keeps the underlying root scope, and therefore this order,
    /// alive for as long as any descendant exists.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct FairnessRoot(ScopeOrder);

    /// The identity arbitration rotates over.
    ///
    /// In production the second component is always `ScopeOrder(0)`, so the key
    /// is the fairness root and nothing else: every scope beneath one root maps
    /// to the same turn, and the cursor advances a whole root at a time.
    ///
    /// Only the `cfg(test)` scope-keyed fixture puts the scope's real order in
    /// the second component, which is what makes each child an independent turn
    /// and lets the superseded policy actually amplify. Disabling deduplication
    /// alone would not do it: the cursor would still step past the entire root.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    struct TurnKey {
        root: FairnessRoot,
        scope: ScopeOrder,
    }

    /// One cooperative-admission disposition, recorded in the order it happened.
    ///
    /// **Scope, stated exactly.** This is the complete ordered trace of
    /// *cooperative admission* dispositions on the non-failing path: the
    /// outcomes reachable through `acquire_cooperatively` and
    /// `create_scope_and_acquire_cooperatively`, the arbitration that resolves
    /// the demands they create, and **owner** cancellation through
    /// `cancel_demand`. Within that scope it is complete — acceptance,
    /// same-root refusal, immediate grant, arbitration grant, terminal
    /// pressure, and owner cancellation all appear, so a control cannot be
    /// blind to immediate admission or to refusals and terminal outcomes the
    /// way a selection-only log is.
    ///
    /// It is deliberately **not** a global provider trace, and two cancellation
    /// paths are specifically outside it:
    ///
    /// - fail-closed invariant cancellation inside `arbitrate`, where an
    ///   impossible arithmetic or commit failure resolves the demand
    ///   `Cancelled` and poisons the provider;
    /// - teardown cancellation in `release_scope`, where retiring a scope
    ///   cancels any demand it still owns.
    ///
    /// Both set the demand's outcome without appending here. That is
    /// deliberate: neither is part of the controlled Construction A execution,
    /// and a poisoned or torn-down provider is not producing a trace anyone
    /// should reason about. It also does not record non-cooperative admission
    /// through `acquire` or `acquire_reclaimable_now`, scope creation or
    /// release, reclaim requests, or pre-admission validation failures such as
    /// an unknown scope, a mismatched reclaim target, a poisoned domain, or a
    /// claim that can never fit.
    ///
    /// Stating this narrowly is the point: claiming completeness over paths the
    /// trace does not record would replace the selection-only overclaim with a
    /// broader one.
    ///
    /// `requested` is the demand's **exact claim by dimension**, as the
    /// provider recorded it. `charged` is the internal reservation and
    /// bookkeeping charge. The two are deliberately distinct: FORMAL 14.5e
    /// defines `cum_admitted` over the demand's exact claim, so a P6 oracle
    /// accumulates `requested`. `charged` is diagnostic only and must never be
    /// accumulated in its place, or the comparison would be inflated by
    /// internal bookkeeping the model does not define.
    ///
    /// `demand_key` is the provider-side identity of the demand, taken at the
    /// moment the demand is created, so a control binds its own logical id to
    /// it at issue time rather than reconstructing an association afterwards
    /// from scope and ordering.
    #[cfg(test)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) enum ProviderDecision {
        /// A demand was accepted as this scope's pending turn.
        PendingAccepted {
            scope_id: ResourceScopeId,
            demand_key: usize,
            requested: ResourceClaim,
        },
        /// A cooperative request was refused because its root already holds a
        /// turn. `holder` is the exact scope owning that turn.
        PendingRefused {
            scope_id: ResourceScopeId,
            holder: ResourceScopeId,
            requested: ResourceClaim,
        },
        /// A claim fit immediately and was admitted without arbitration.
        ImmediateGrant {
            scope_id: ResourceScopeId,
            requested: ResourceClaim,
            charged: ResourceClaim,
        },
        /// Arbitration selected this demand and granted it.
        ArbitrationGrant {
            scope_id: ResourceScopeId,
            demand_key: usize,
            requested: ResourceClaim,
            charged: ResourceClaim,
        },
        /// Arbitration resolved this demand to typed pressure.
        TerminalPressure {
            scope_id: ResourceScopeId,
            demand_key: usize,
            dimension: ResourceClass,
        },
        /// The demand's owner cancelled it through `cancel_demand`.
        ///
        /// Owner cancellation only. Fail-closed invariant cancellation inside
        /// `arbitrate` and teardown cancellation in `release_scope` also resolve
        /// a demand `Cancelled`, but neither is recorded here.
        Cancelled {
            scope_id: ResourceScopeId,
            demand_key: usize,
        },
    }

    /// Provider-side identity of one demand, stable for its lifetime.
    #[cfg(test)]
    pub(crate) fn demand_key_of(identity: &ResourceDemandIdentity) -> usize {
        Arc::as_ptr(&identity.signal) as usize
    }

    /// An exactly comparable view of every mutation surface relevant to a
    /// refusal. Deliberately excludes the test-only fail-injection flag.
    #[cfg(test)]
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct FiniteProviderSnapshot {
        pub(crate) in_use: ResourceClaim,
        pub(crate) retained_after_failed_cleanup: ResourceClaim,
        pub(crate) poisoned: Option<ResourceClass>,
        pub(crate) next_reservation_id: Option<u64>,
        pub(crate) free_reservation_ids: Vec<u64>,
        pub(crate) next_scope_order: Option<u64>,
        pub(crate) free_scope_orders: Vec<u64>,
        #[allow(clippy::type_complexity)]
        pub(crate) scopes: Vec<(
            ResourceScopeId,
            u64,
            u64,
            Option<(ResourceAuthorityClass, ResourceClaim, DemandPlacement)>,
        )>,
        #[allow(clippy::type_complexity)]
        pub(crate) reservations: Vec<(
            u64,
            ResourceScopeId,
            ResourceAuthorityClass,
            ResourceClaim,
            ReservationLifecycle,
        )>,
        pub(crate) demand_cursor: Vec<Option<(u64, u64)>>,
        pub(crate) reclaim_cursor: Option<u64>,
        pub(crate) active_demand: Option<(u64, ResourceScopeId)>,
        pub(crate) decision_log: Vec<ProviderDecision>,
    }

    /// A root and order reserved for a child scope that has not been inserted.
    ///
    /// Held only between `prepare_child_scope` and either `commit_child_scope`
    /// or `rollback_prepared_child`.
    /// Where an allocated value came from, so an undo can be exact.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum AllocationProvenance {
        /// Minted by advancing the frontier counter.
        Fresh,
        /// Taken from the free set of previously released values.
        Reused,
    }

    /// A reservation id held between allocation and either use or rollback.
    #[derive(Clone, Copy, Debug)]
    struct PreparedReservationId {
        id: u64,
        provenance: AllocationProvenance,
    }

    #[derive(Clone, Copy, Debug)]
    struct PreparedChildScope {
        root: FairnessRoot,
        order: ScopeOrder,
        provenance: AllocationProvenance,
    }

    #[derive(Debug)]
    struct ScopeRecord {
        pending: Option<PendingDemand>,
        /// The exactly-one fairness root this scope is attributed to.
        ///
        /// An ordinary child inherits its parent's root verbatim. Only the
        /// process scope and a trusted root scope introduce a new root.
        root: FairnessRoot,
        /// Deterministic private ordering position for this live scope.
        order: ScopeOrder,
    }

    #[derive(Debug)]
    struct ActiveDemand {
        /// The root whose turn is currently selected. Arbitration is keyed to
        /// this, never to the scope.
        root: FairnessRoot,
        /// The exact scope owning the selected pending demand. Retry, cancel,
        /// lease, and release all remain exact-scope operations.
        scope_id: ResourceScopeId,
        identity: ResourceDemandIdentity,
    }

    #[derive(Debug)]
    struct State {
        grant: ResourceClaim,
        in_use: ResourceClaim,
        retained_after_failed_cleanup: ResourceClaim,
        poisoned: Option<ResourceClass>,
        provider_authority: Option<Arc<ResourceScopeIdentity>>,
        next_reservation_id: Option<u64>,
        free_reservation_ids: BTreeSet<u64>,
        reservations: BTreeMap<u64, Reservation>,
        scopes: BTreeMap<ResourceScopeId, ScopeRecord>,
        active_demand: Option<ActiveDemand>,
        /// Rotation cursors, one per authority class, keyed by fairness root.
        ///
        /// Keying these to the root rather than to the scope is what makes
        /// extra child scopes produce no additional turns.
        demand_cursor: [Option<TurnKey>; 3],
        /// Reclaim rotation cursor, keyed by victim fairness root.
        reclaim_cursor: Option<FairnessRoot>,
        /// Next never-yet-issued scope order. `None` once exhausted.
        next_scope_order: Option<u64>,
        /// Orders returned by truly released scopes, reissued before the
        /// counter is extended.
        free_scope_orders: BTreeSet<ScopeOrder>,
        /// Test-only switch that restores the superseded scope-keyed
        /// scheduling behaviour.
        ///
        /// This exists solely so a control can drive the *same* live provider
        /// through the *same* trace oracle under both selection rules. A
        /// partition non-amplification control that cannot be made to fail
        /// proves nothing, so the negative fixture flips this and asserts the
        /// oracle rejects the result. It is never reachable outside `cfg(test)`.
        #[cfg(test)]
        scope_keyed_selection: bool,
        /// Test-only ordered trace of cooperative-admission dispositions.
        ///
        /// Complete within that scope and no wider; see [`ProviderDecision`]
        /// for exactly what it covers and what it deliberately does not.
        ///
        /// A control cannot infer disposition order from the order it happens
        /// to retry its own outstanding demands; that would measure the test's
        /// iteration, not the provider's behaviour. Every disposition in scope
        /// appends here as it happens.
        #[cfg(test)]
        decision_log: Vec<ProviderDecision>,
        /// Test-only forced failure of the scope-order allocator.
        #[cfg(test)]
        fail_scope_order_allocation: bool,
        /// Test-only forced failure of reservation-id allocation.
        ///
        /// Separate from the order flag so a control can fail the *second*
        /// allocation, which is the only way to exercise rollback after a
        /// successful scope preparation.
        #[cfg(test)]
        fail_reservation_id_allocation: bool,
        #[cfg(test)]
        scripted_pressure: VecDeque<ResourceClass>,
    }

    /// Work-conserving provider backed by one explicit finite process grant.
    ///
    /// Every child scope draws from the same grant. Creating a scope does not
    /// partition or expand that grant. This provider has no defaults and no
    /// product-specific object counts.
    #[derive(Clone, Debug)]
    pub struct FiniteResourceProvider {
        state: Arc<Mutex<State>>,
    }

    impl FiniteResourceProvider {
        pub fn new(grant: ResourceClaim) -> Self {
            Self {
                state: Arc::new(Mutex::new(State {
                    grant,
                    in_use: ResourceClaim::ZERO,
                    retained_after_failed_cleanup: ResourceClaim::ZERO,
                    poisoned: None,
                    provider_authority: None,
                    next_reservation_id: Some(1),
                    free_reservation_ids: BTreeSet::new(),
                    reservations: BTreeMap::new(),
                    scopes: BTreeMap::new(),
                    active_demand: None,
                    demand_cursor: [None; 3],
                    reclaim_cursor: None,
                    next_scope_order: Some(0),
                    free_scope_orders: BTreeSet::new(),
                    #[cfg(test)]
                    scope_keyed_selection: false,
                    #[cfg(test)]
                    decision_log: Vec::new(),
                    #[cfg(test)]
                    fail_scope_order_allocation: false,
                    #[cfg(test)]
                    fail_reservation_id_allocation: false,
                    #[cfg(test)]
                    scripted_pressure: VecDeque::new(),
                })),
            }
        }

        #[cfg(any(test, feature = "transport-lab"))]
        pub(crate) fn scope_record_charge_for_test() -> ResourceClaim {
            Self::bookkeeping_claim()
        }

        /// Restore the superseded scope-keyed scheduling rule.
        ///
        /// Only a control may call this, and only to demonstrate that the
        /// partition non-amplification oracle discriminates: the same live
        /// provider, driven through the same trace, must fail that oracle when
        /// selection is keyed to scopes instead of roots.
        #[cfg(test)]
        pub(crate) fn set_scope_keyed_selection_for_test(&self, scope_keyed: bool) {
            let mut state = self.lock_state();
            state.scope_keyed_selection = scope_keyed;
        }

        /// The provider's ordered cooperative-admission disposition trace,
        /// oldest first. See [`ProviderDecision`] for exactly what it covers
        /// and what it deliberately does not.
        #[cfg(test)]
        pub(crate) fn decision_log_for_test(&self) -> Vec<ProviderDecision> {
            self.lock_state().decision_log.clone()
        }

        /// Force the scope-order allocator to fail, or restore it.
        ///
        /// Restoring re-runs arbitration under the same lock. That is not a
        /// convenience: `retry` on a still-waiting demand only reports
        /// `Pending` and never re-arbitrates, so without this a restored
        /// allocator would never reconsider the demand it previously refused.
        /// In production the allocator recovers when a scope is truly released,
        /// and `release_scope` already calls `arbitrate`, so this emulates the
        /// real recovery event rather than inventing one. Production retry
        /// semantics are unchanged.
        #[cfg(test)]
        pub(crate) fn fail_scope_order_allocation_for_test(&self, fail: bool) {
            let mut state = self.lock_state();
            let was_failing = state.fail_scope_order_allocation;
            state.fail_scope_order_allocation = fail;
            if was_failing && !fail {
                Self::arbitrate(&mut state);
            }
        }

        /// Force reservation-id allocation to fail, or restore it.
        ///
        /// Distinct from the order flag so a control can fail the second
        /// allocation and exercise rollback after a successful preparation.
        #[cfg(test)]
        pub(crate) fn fail_reservation_id_allocation_for_test(&self, fail: bool) {
            let mut state = self.lock_state();
            let was_failing = state.fail_reservation_id_allocation;
            state.fail_reservation_id_allocation = fail;
            if was_failing && !fail {
                Self::arbitrate(&mut state);
            }
        }

        /// Every mutation surface a refusal could disturb.
        ///
        /// Counts are not sufficient: a reservation id or scope order can be
        /// burned without changing any count, and a cursor can move without
        /// changing topology. This captures the actual allocator positions and
        /// free sets, the exact per-scope root, order and pending shape, the
        /// exact reservation shape, all cursors, the active demand, and the
        /// cooperative decision trace. The fail-injection flag is deliberately
        /// excluded, since a control mutates it on purpose.
        ///
        /// The trace is append-only, so comparing two snapshots for equality is
        /// the wrong test wherever a demand was legitimately accepted or
        /// cancelled; compare the prefix and the appended suffix instead.
        #[cfg(test)]
        pub(crate) fn transactional_snapshot_for_test(&self) -> FiniteProviderSnapshot {
            let state = self.lock_state();
            FiniteProviderSnapshot {
                in_use: state.in_use,
                retained_after_failed_cleanup: state.retained_after_failed_cleanup,
                poisoned: state.poisoned,
                next_reservation_id: state.next_reservation_id,
                free_reservation_ids: state.free_reservation_ids.iter().copied().collect(),
                next_scope_order: state.next_scope_order,
                free_scope_orders: state
                    .free_scope_orders
                    .iter()
                    .map(|order| order.0)
                    .collect(),
                scopes: state
                    .scopes
                    .iter()
                    .map(|(scope_id, record)| {
                        (
                            *scope_id,
                            record.root.0 .0,
                            record.order.0,
                            record.pending.as_ref().map(|pending| {
                                (pending.authority, pending.claim, pending.placement)
                            }),
                        )
                    })
                    .collect(),
                reservations: state
                    .reservations
                    .iter()
                    .map(|(reservation_id, reservation)| {
                        (
                            *reservation_id,
                            reservation.scope_id,
                            reservation.authority,
                            reservation.claim,
                            reservation.lifecycle,
                        )
                    })
                    .collect(),
                demand_cursor: state
                    .demand_cursor
                    .iter()
                    .map(|cursor| cursor.map(|key| (key.root.0 .0, key.scope.0)))
                    .collect(),
                reclaim_cursor: state.reclaim_cursor.map(|root| root.0 .0),
                active_demand: state
                    .active_demand
                    .as_ref()
                    .map(|active| (active.root.0 .0, active.scope_id)),
                decision_log: state.decision_log.clone(),
            }
        }

        /// Provider-owned planning charge for one future reservation: the
        /// requested claim plus the exact bookkeeping record the provider will
        /// retain for its lease. This computes capacity only and acquires none.
        pub fn reservation_planning_charge(
            claim: ResourceClaim,
        ) -> Result<ResourceClaim, ResourceUnavailable> {
            Self::reservation_charge(claim)
        }

        /// Provider-owned planning charge for creating one scope.
        ///
        /// A finite provider retains this bookkeeping record for the process
        /// scope opened by [`ResourceProviderPort::new`] and for every child
        /// scope created later. Publishing the planner lets an exact fixture
        /// price the production operation without copying the provider's
        /// private record shape. It computes capacity only and acquires none.
        pub fn scope_planning_charge() -> ResourceClaim {
            Self::bookkeeping_claim()
        }

        #[cfg(any(test, feature = "transport-lab"))]
        pub(crate) fn reservation_charge_for_test(
            claim: ResourceClaim,
        ) -> Result<ResourceClaim, ResourceUnavailable> {
            Self::reservation_planning_charge(claim)
        }

        #[cfg(any(test, feature = "transport-lab"))]
        pub(crate) fn child_scope_with_reservation_charge_for_test(
            claim: ResourceClaim,
        ) -> Result<ResourceClaim, ResourceUnavailable> {
            Self::reservation_charge(claim)?
                .checked_add(Self::bookkeeping_claim())
                .map_err(|_| ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                })
        }

        #[cfg(test)]
        pub(crate) fn script_pressure(&self, dimension: ResourceClass) {
            self.lock_state().scripted_pressure.push_back(dimension);
        }

        pub fn in_use(&self) -> ResourceClaim {
            self.lock_state().in_use
        }

        pub fn retained_after_failed_cleanup(&self) -> ResourceClaim {
            self.lock_state().retained_after_failed_cleanup
        }

        #[cfg(test)]
        pub(crate) fn active_reservations(&self) -> usize {
            self.lock_state().reservations.len()
        }

        #[cfg(test)]
        pub(crate) fn active_scopes(&self) -> usize {
            self.lock_state().scopes.len()
        }

        #[cfg(test)]
        pub(crate) fn poison_accounting_mutex(&self) {
            let state = Arc::clone(&self.state);
            let _ = std::thread::spawn(move || {
                let _guard = state.lock().expect("test mutex starts healthy");
                panic!("intentional provider mutex poison");
            })
            .join();
        }

        fn lock_state(&self) -> MutexGuard<'_, State> {
            match self.state.lock() {
                Ok(state) => state,
                Err(poisoned) => {
                    let mut state = poisoned.into_inner();
                    state
                        .poisoned
                        .get_or_insert(ResourceClass::OpaqueDependencyResidual);
                    state
                }
            }
        }

        fn bookkeeping_claim() -> ResourceClaim {
            ResourceClaim::single(ResourceClass::OpaqueDependencyResidual, 1)
        }

        fn reservation_charge(claim: ResourceClaim) -> Result<ResourceClaim, ResourceUnavailable> {
            claim.checked_add(Self::bookkeeping_claim()).map_err(|_| {
                ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                }
            })
        }

        fn authority_index(authority: ResourceAuthorityClass) -> usize {
            match authority {
                ResourceAuthorityClass::Cleanup => 0,
                ResourceAuthorityClass::Admitted => 1,
                ResourceAuthorityClass::Speculative => 2,
            }
        }

        fn allocate_reservation_id(state: &mut State) -> Result<u64, ResourceUnavailable> {
            Self::allocate_reservation_id_tracked(state).map(|prepared| prepared.id)
        }

        /// Allocate a reservation id, remembering where it came from.
        ///
        /// Provenance matters because undoing an allocation must restore the
        /// allocator exactly. Pushing a freshly minted frontier value onto the
        /// free set would leave the same capacity but a different state, which
        /// is a real difference: it perturbs future issue order.
        fn allocate_reservation_id_tracked(
            state: &mut State,
        ) -> Result<PreparedReservationId, ResourceUnavailable> {
            // Test-only injection so controls can exercise the rollback branch
            // that runs *after* a scope order has already been prepared.
            #[cfg(test)]
            if state.fail_reservation_id_allocation {
                return Err(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                });
            }
            if let Some(reused) = state.free_reservation_ids.pop_first() {
                return Ok(PreparedReservationId {
                    id: reused,
                    provenance: AllocationProvenance::Reused,
                });
            }
            let next = state
                .next_reservation_id
                .ok_or(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                })?;
            state.next_reservation_id = next.checked_add(1);
            Ok(PreparedReservationId {
                id: next,
                provenance: AllocationProvenance::Fresh,
            })
        }

        /// Undo a reservation-id allocation exactly.
        fn rollback_reservation_id(state: &mut State, prepared: PreparedReservationId) {
            match prepared.provenance {
                AllocationProvenance::Fresh => state.next_reservation_id = Some(prepared.id),
                AllocationProvenance::Reused => {
                    state.free_reservation_ids.insert(prepared.id);
                }
            }
        }

        fn demand_matches(pending: &PendingDemand, identity: &ResourceDemandIdentity) -> bool {
            Arc::ptr_eq(&pending.identity.signal, &identity.signal)
        }

        /// Allocate one scope order.
        ///
        /// Called only after a prospective scope creation has already passed
        /// every admission check, so a refused creation consumes no order and
        /// leaves the order pool exactly as it was. Released orders are
        /// reissued before the counter is extended, so repeated create/release
        /// cycles never exhaust the space and never impose a lifetime
        /// identity-count quota.
        fn allocate_scope_order(
            state: &mut State,
        ) -> Result<(ScopeOrder, AllocationProvenance), ResourceUnavailable> {
            // Test-only exhaustion, so controls can prove that an order
            // allocation failure consumes nothing and that the operation
            // succeeds again once the allocator is restored.
            #[cfg(test)]
            if state.fail_scope_order_allocation {
                return Err(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                });
            }
            if let Some(reused) = state.free_scope_orders.iter().next().copied() {
                state.free_scope_orders.remove(&reused);
                return Ok((reused, AllocationProvenance::Reused));
            }
            let next = state
                .next_scope_order
                .ok_or(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                })?;
            state.next_scope_order = next.checked_add(1);
            Ok((ScopeOrder(next), AllocationProvenance::Fresh))
        }

        /// Return an order to the free set on true scope release only.
        fn release_scope_order(state: &mut State, order: ScopeOrder) {
            state.free_scope_orders.insert(order);
        }

        /// Truly retire one scope record, keeping root identity sound.
        ///
        /// A `FairnessRoot` wraps a recyclable `ScopeOrder`, so releasing the
        /// last scope of a root and returning its order would otherwise let a
        /// later scope mint a root with the same value and silently inherit
        /// that root's cursor position. Any cursor or active demand naming a
        /// root that has just become empty is therefore invalidated *before*
        /// the order returns to the free set.
        fn retire_scope_record(state: &mut State, scope_id: ResourceScopeId) {
            let Some(record) = state.scopes.remove(&scope_id) else {
                return;
            };
            let root = record.root;
            let root_still_live = state.scopes.values().any(|scope| scope.root == root);
            if !root_still_live {
                for cursor in &mut state.demand_cursor {
                    if cursor.is_some_and(|key| key.root == root) {
                        *cursor = None;
                    }
                }
                if state.reclaim_cursor == Some(root) {
                    state.reclaim_cursor = None;
                }
                if state
                    .active_demand
                    .as_ref()
                    .is_some_and(|active| active.root == root)
                {
                    state.active_demand = None;
                }
            }
            Self::release_scope_order(state, record.order);
        }

        /// The fairness root a scope is attributed to.
        fn root_of(state: &State, scope_id: ResourceScopeId) -> Option<FairnessRoot> {
            state.scopes.get(&scope_id).map(|scope| scope.root)
        }

        /// The root an ordinary child must inherit.
        ///
        /// A child never introduces a root and never accepts one from a
        /// caller; it takes its parent's verbatim.
        fn inherited_root(
            state: &State,
            parent_scope_id: ResourceScopeId,
        ) -> Result<FairnessRoot, ResourceUnavailable> {
            Self::root_of(state, parent_scope_id).ok_or(ResourceUnavailable::UnknownScope {
                scope_id: parent_scope_id,
            })
        }

        /// Insert the record for an ordinary child scope.
        ///
        /// The child inherits its parent's root verbatim and takes a freshly
        /// allocated order. Callers reach this only after the creation has
        /// already been admitted.
        /// Reserve the root and order a child scope will use, without inserting
        /// it.
        ///
        /// This is the only fallible step of child creation, so callers run it
        /// before mutating any accounting. If a later step fails, the caller
        /// returns the order with `rollback_prepared_child`.
        fn prepare_child_scope(
            state: &mut State,
            parent_scope_id: ResourceScopeId,
        ) -> Result<PreparedChildScope, ResourceUnavailable> {
            let root = Self::inherited_root(state, parent_scope_id)?;
            let (order, provenance) = Self::allocate_scope_order(state)?;
            Ok(PreparedChildScope {
                root,
                order,
                provenance,
            })
        }

        /// Undo a prepared order exactly, restoring the allocator byte for
        /// byte rather than merely restoring capacity.
        ///
        /// A freshly minted frontier value returns the frontier; only a value
        /// that came from the free set goes back into the free set. Pushing a
        /// fresh value into the free set would preserve capacity but change
        /// which order the next scope receives.
        fn rollback_prepared_child(state: &mut State, prepared: PreparedChildScope) {
            match prepared.provenance {
                AllocationProvenance::Fresh => state.next_scope_order = Some(prepared.order.0),
                AllocationProvenance::Reused => {
                    Self::release_scope_order(state, prepared.order);
                }
            }
        }

        /// Insert a prepared child record. Infallible apart from the
        /// duplicate-id invariant, which is a provider bug rather than a
        /// refusal.
        fn commit_child_scope(
            state: &mut State,
            scope_id: ResourceScopeId,
            prepared: PreparedChildScope,
        ) -> Result<(), ResourceUnavailable> {
            // `Entry` rather than `insert`: an occupied id must leave the map
            // untouched. Replacing it would destroy a live exact-scope owner
            // before the error is even returned, and would bury the prepared
            // order inside the replacement where no caller could roll it back.
            match state.scopes.entry(scope_id) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(ScopeRecord {
                        pending: None,
                        root: prepared.root,
                        order: prepared.order,
                    });
                    Ok(())
                }
                std::collections::btree_map::Entry::Occupied(_) => {
                    Err(ResourceUnavailable::ProviderInvariant {
                        dimension: ResourceClass::OpaqueDependencyResidual,
                    })
                }
            }
        }

        /// Whether any scope attributed to `root` already owns a pending demand.
        ///
        /// One move-only pending demand exists per root, not per scope, so
        /// extra child scopes beneath a root create no additional turns. The
        /// pending demand itself remains stored under its exact
        /// `ResourceScopeId`.
        fn pending_holder(
            state: &State,
            scope_id: ResourceScopeId,
            root: FairnessRoot,
        ) -> Option<ResourceScopeId> {
            // Under the superseded rule the scheduling key was the scope, so
            // exactly one pending demand existed per scope. The limit still
            // existed — it was simply keyed more finely. Returning nothing here
            // would let a repeated request overwrite a live `pending` and
            // strand its handle, which the old policy never permitted.
            #[cfg(test)]
            if state.scope_keyed_selection {
                return state
                    .scopes
                    .get(&scope_id)
                    .filter(|record| record.pending.is_some())
                    .map(|_| scope_id);
            }
            let _ = scope_id;
            state
                .scopes
                .iter()
                .find(|(_, scope)| scope.root == root && scope.pending.is_some())
                .map(|(scope_id, _)| *scope_id)
        }

        fn highest_pending_authority(state: &State) -> Option<ResourceAuthorityClass> {
            [
                ResourceAuthorityClass::Cleanup,
                ResourceAuthorityClass::Admitted,
                ResourceAuthorityClass::Speculative,
            ]
            .into_iter()
            .find(|authority| {
                state.scopes.values().any(|scope| {
                    scope
                        .pending
                        .as_ref()
                        .is_some_and(|pending| pending.authority == *authority)
                })
            })
        }

        /// Every root holding a pending demand of this authority, in
        /// deterministic root order, paired with the exact scope that owns it.
        ///
        /// One pending demand exists per root, so this yields at most one entry
        /// per root and additional child scopes contribute no extra entries.
        /// The turn key for one scope.
        ///
        /// Production collapses every scope beneath a root onto that root's
        /// single turn.
        fn turn_key(state: &State, record: &ScopeRecord) -> TurnKey {
            let _ = state;
            #[cfg(test)]
            if state.scope_keyed_selection {
                return TurnKey {
                    root: record.root,
                    scope: record.order,
                };
            }
            TurnKey {
                root: record.root,
                scope: ScopeOrder(0),
            }
        }

        fn pending_turns(
            state: &State,
            authority: ResourceAuthorityClass,
        ) -> Vec<(TurnKey, ResourceScopeId)> {
            let mut turns: Vec<(TurnKey, ResourceScopeId)> = state
                .scopes
                .iter()
                .filter(|(_, scope)| {
                    scope
                        .pending
                        .as_ref()
                        .is_some_and(|pending| pending.authority == authority)
                })
                .map(|(scope_id, scope)| (Self::turn_key(state, scope), *scope_id))
                .collect();
            turns.sort_by_key(|(key, scope_id)| (*key, *scope_id));
            // In production every scope of a root shares one key, so this
            // collapses the root to a single turn.
            turns.dedup_by_key(|(key, _)| *key);
            turns
        }

        /// Select the next turn to serve for this authority.
        fn select_turn_after_cursor(
            state: &State,
            authority: ResourceAuthorityClass,
        ) -> Option<(TurnKey, ResourceScopeId)> {
            let cursor = state.demand_cursor[Self::authority_index(authority)];
            let candidates = Self::pending_turns(state, authority);
            candidates
                .iter()
                .find(|(key, _)| cursor.is_none_or(|cursor| *key > cursor))
                .copied()
                .or_else(|| candidates.first().copied())
        }

        fn select_active_demand(state: &mut State) -> Option<ResourceScopeId> {
            let highest = Self::highest_pending_authority(state)?;
            if let Some(active) = state.active_demand.as_ref() {
                let still_exact = state
                    .scopes
                    .get(&active.scope_id)
                    .and_then(|scope| scope.pending.as_ref())
                    .is_some_and(|pending| {
                        pending.authority == highest
                            && Self::demand_matches(pending, &active.identity)
                    });
                if still_exact {
                    return Some(active.scope_id);
                }
            }
            let (turn, scope_id) = Self::select_turn_after_cursor(state, highest)?;
            let root = turn.root;
            let Some(identity) = state
                .scopes
                .get(&scope_id)
                .and_then(|scope| scope.pending.as_ref())
                .map(|pending| pending.identity.duplicate())
            else {
                Self::poison(state, ResourceClass::OpaqueDependencyResidual);
                return None;
            };
            state.active_demand = Some(ActiveDemand {
                root,
                scope_id,
                identity,
            });
            Some(scope_id)
        }

        fn pressure_for_claim(
            state: &State,
            scope_id: ResourceScopeId,
            authority: ResourceAuthorityClass,
            claim: ResourceClaim,
        ) -> Option<ResourcePressure> {
            let charged = Self::reservation_charge(claim).ok()?;
            Self::pressure_for_charge(state, scope_id, authority, charged)
        }

        fn pressure_for_charge(
            state: &State,
            scope_id: ResourceScopeId,
            authority: ResourceAuthorityClass,
            charged: ResourceClaim,
        ) -> Option<ResourcePressure> {
            ResourceClass::ALL.into_iter().find_map(|dimension| {
                let requested = charged.amount(dimension);
                let in_use = state.in_use.amount(dimension);
                let capacity = state.grant.amount(dimension);
                (requested > capacity.saturating_sub(in_use)).then_some(ResourcePressure {
                    scope_id,
                    authority,
                    dimension,
                    requested,
                    in_use,
                    capacity,
                })
            })
        }

        fn claim_can_ever_fit(
            state: &State,
            scope_id: ResourceScopeId,
            authority: ResourceAuthorityClass,
            claim: ResourceClaim,
        ) -> Result<(), ResourceUnavailable> {
            let charged = Self::reservation_charge(claim)?;
            Self::charge_can_ever_fit(state, scope_id, authority, charged)
        }

        fn charge_can_ever_fit(
            state: &State,
            scope_id: ResourceScopeId,
            authority: ResourceAuthorityClass,
            charged: ResourceClaim,
        ) -> Result<(), ResourceUnavailable> {
            for dimension in ResourceClass::ALL {
                let requested = charged.amount(dimension);
                let capacity = state.grant.amount(dimension);
                if requested > capacity {
                    return Err(ResourceUnavailable::Pressure(ResourcePressure {
                        scope_id,
                        authority,
                        dimension,
                        requested,
                        in_use: state.in_use.amount(dimension),
                        capacity,
                    }));
                }
            }
            Ok(())
        }

        fn active_demand_gate(
            state: &State,
            scope_id: ResourceScopeId,
            authority: ResourceAuthorityClass,
            charged: ResourceClaim,
        ) -> Option<ResourceUnavailable> {
            let active = state.active_demand.as_ref()?;
            let pending = state
                .scopes
                .get(&active.scope_id)
                .and_then(|scope| scope.pending.as_ref())?;
            if authority < pending.authority {
                return None;
            }
            let pending_charge = match pending.charge() {
                Ok(charge) => charge,
                Err(_) => {
                    return Some(ResourceUnavailable::ProviderInvariant {
                        dimension: ResourceClass::OpaqueDependencyResidual,
                    });
                }
            };
            ResourceClass::ALL.into_iter().find_map(|dimension| {
                let available = state
                    .grant
                    .amount(dimension)
                    .saturating_sub(state.in_use.amount(dimension));
                // Capacity beyond the active demand's exact charge remains
                // borrowable. Capacity already needed by that fair turn is
                // reserved so a later arrival cannot prolong reclamation.
                let borrowable = available.saturating_sub(pending_charge.amount(dimension));
                (charged.amount(dimension) > borrowable).then_some(ResourceUnavailable::Pressure(
                    ResourcePressure {
                        scope_id,
                        authority,
                        dimension,
                        requested: charged.amount(dimension),
                        in_use: state.in_use.amount(dimension),
                        capacity: state.grant.amount(dimension),
                    },
                ))
            })
        }

        /// Choose reclaim victims for a deficit.
        ///
        /// `requester_root` is supplied already resolved, by the caller, from
        /// the exact **existing** scope that owns the pending demand. It is
        /// deliberately not recovered from a scope id here: a `NewChild` demand
        /// names a prospective child that has not been committed yet, so
        /// looking it up would yield nothing, silently disabling the
        /// own-root-last protection and letting a claimant route around it by
        /// demanding through a child that does not exist yet.
        ///
        /// The parameter is non-optional on purpose. Accepting an absent root
        /// would keep exactly that silent path available: every selected
        /// pending owner has a scope record and therefore a root, so an
        /// unresolvable requester is an impossible state, and the caller fails
        /// closed rather than reclaiming without attribution.
        fn select_reclaim_victims(
            state: &mut State,
            requester_root: FairnessRoot,
            needed: ResourceClaim,
        ) -> bool {
            let mut deficit = ResourceClaim::ZERO;
            for dimension in ResourceClass::ALL {
                let available = state
                    .grant
                    .amount(dimension)
                    .saturating_sub(state.in_use.amount(dimension));
                deficit.amounts[dimension.index()] =
                    needed.amount(dimension).saturating_sub(available);
            }
            if deficit.is_zero() {
                return true;
            }

            let cursor = state.reclaim_cursor;
            let mut candidates: Vec<(FairnessRoot, ScopeOrder, ResourceScopeId, u64)> = state
                .reservations
                .iter()
                .filter_map(|(reservation_id, reservation)| {
                    let eligible = (reservation.authority == ResourceAuthorityClass::Speculative
                        && reservation.reclaim_target.is_some())
                        || reservation.lifecycle == ReservationLifecycle::ReclaimRequested;
                    if !eligible {
                        return None;
                    }
                    let victim = state.scopes.get(&reservation.scope_id)?;
                    Some((
                        victim.root,
                        victim.order,
                        reservation.scope_id,
                        *reservation_id,
                    ))
                })
                .collect();
            // Group and order by victim root first. Scope order and
            // reservation id are deterministic intra-root tie-breakers only,
            // so extra children neither advance nor delay a root's turn as a
            // victim.
            candidates.sort_by_key(|(victim_root, victim_order, _, reservation_id)| {
                (
                    *victim_root == requester_root,
                    cursor.is_some_and(|cursor| *victim_root <= cursor),
                    *victim_root,
                    *victim_order,
                    *reservation_id,
                )
            });

            let mut selected = Vec::new();
            for (victim_root, _victim_order, victim_scope, reservation_id) in candidates {
                if deficit.is_zero() {
                    break;
                }
                let Some(reservation) = state.reservations.get(&reservation_id) else {
                    Self::poison(state, ResourceClass::OpaqueDependencyResidual);
                    return false;
                };
                let Ok(charge) = Self::reservation_charge(reservation.claim) else {
                    Self::poison(state, ResourceClass::OpaqueDependencyResidual);
                    return false;
                };
                let contributes = ResourceClass::ALL.into_iter().any(|dimension| {
                    deficit.amount(dimension) != 0 && charge.amount(dimension) != 0
                });
                if !contributes {
                    continue;
                }
                for dimension in ResourceClass::ALL {
                    deficit.amounts[dimension.index()] = deficit
                        .amount(dimension)
                        .saturating_sub(charge.amount(dimension));
                }
                let target = if reservation.lifecycle == ReservationLifecycle::Live {
                    let Some(target) = reservation.reclaim_target.as_ref() else {
                        Self::poison(state, ResourceClass::OpaqueDependencyResidual);
                        return false;
                    };
                    Some(target.clone())
                } else {
                    None
                };
                // The exact victim scope and its owner are retained; only the
                // sequencing is root-keyed.
                selected.push((victim_root, victim_scope, reservation_id, target));
            }
            if !deficit.is_zero() {
                return false;
            }
            for (_, _, reservation_id, _) in &selected {
                let Some(reservation) = state.reservations.get_mut(reservation_id) else {
                    Self::poison(state, ResourceClass::OpaqueDependencyResidual);
                    return false;
                };
                if reservation.lifecycle == ReservationLifecycle::Live {
                    reservation.lifecycle = ReservationLifecycle::ReclaimRequested;
                }
            }
            for (_, _, _, target) in &selected {
                if let Some(target) = target {
                    target.request();
                }
            }
            // Rotate the reclaim cursor past the last victim root, so the next
            // shortfall starts at a different root rather than a different
            // child of the same one.
            if let Some((last_root, _, _, _)) = selected.last() {
                state.reclaim_cursor = Some(*last_root);
            }
            true
        }

        fn arbitrate(state: &mut State) {
            loop {
                let Some(scope_id) = Self::select_active_demand(state) else {
                    state.active_demand = None;
                    return;
                };
                let pending_data = state
                    .scopes
                    .get(&scope_id)
                    .and_then(|scope| scope.pending.as_ref())
                    .map(|pending| {
                        (
                            pending.authority,
                            pending.claim,
                            pending.identity.duplicate(),
                            pending.placement,
                            pending.lease_scope_id(scope_id),
                            pending.charge(),
                        )
                    });
                let Some((authority, claim, identity, placement, lease_scope_id, charge)) =
                    pending_data
                else {
                    Self::poison(state, ResourceClass::OpaqueDependencyResidual);
                    return;
                };
                let Ok(charge) = charge else {
                    Self::poison(state, ResourceClass::OpaqueDependencyResidual);
                    return;
                };
                if Self::pressure_for_charge(state, lease_scope_id, authority, charge).is_none() {
                    // Every fallible allocation happens before the pending
                    // handle is taken, so a failure here cannot strand a demand
                    // in `Waiting` with its turn already removed. The demand
                    // owner is the parent, so a new child inherits that scope's
                    // root verbatim.
                    //
                    // Scope bookkeeping is finite and fallible. Exhaustion is a
                    // refusal, not a provider bug: leave the pending demand, its
                    // turn, accounting, topology, cursors, and the decision
                    // trace exactly as they are, and return without poisoning so
                    // the same demand promotes on a later retry once capacity
                    // returns.
                    let prepared = match placement {
                        DemandPlacement::NewChild { .. } => {
                            match Self::prepare_child_scope(state, scope_id) {
                                Ok(prepared) => Some(prepared),
                                Err(_) => return,
                            }
                        }
                        DemandPlacement::ExistingScope => None,
                    };
                    let reservation = match Self::allocate_reservation_id_tracked(state) {
                        Ok(reservation) => reservation,
                        Err(_) => {
                            // Same reasoning: return the prepared order and
                            // leave the demand retryable.
                            if let Some(prepared) = prepared {
                                Self::rollback_prepared_child(state, prepared);
                            }
                            return;
                        }
                    };
                    let reservation_id = reservation.id;
                    // Only now, with every refusable step behind us, is the
                    // pending handle consumed.
                    let Some(pending) = state
                        .scopes
                        .get_mut(&scope_id)
                        .and_then(|scope| scope.pending.take())
                    else {
                        if let Some(prepared) = prepared {
                            Self::rollback_prepared_child(state, prepared);
                        }
                        Self::rollback_reservation_id(state, reservation);
                        Self::poison(state, ResourceClass::OpaqueDependencyResidual);
                        return;
                    };
                    // Beyond this point a failure is an impossible-invariant
                    // failure, because pressure was already checked. It poisons
                    // — but the demand is resolved fail-closed rather than left
                    // waiting forever.
                    let next = match state.in_use.checked_add(charge) {
                        Ok(next) => next,
                        Err(_) => {
                            if let Some(prepared) = prepared {
                                Self::rollback_prepared_child(state, prepared);
                            }
                            Self::rollback_reservation_id(state, reservation);
                            identity.signal.set(DemandOutcome::Cancelled);
                            Self::poison(state, ResourceClass::OpaqueDependencyResidual);
                            return;
                        }
                    };
                    if let (
                        Some(prepared),
                        DemandPlacement::NewChild {
                            scope_id: child_scope_id,
                        },
                    ) = (prepared, placement)
                    {
                        if Self::commit_child_scope(state, child_scope_id, prepared).is_err() {
                            // The map was left untouched, so both tokens are
                            // still ours to return. The demand is resolved
                            // fail-closed rather than left waiting.
                            Self::rollback_reservation_id(state, reservation);
                            Self::rollback_prepared_child(state, prepared);
                            identity.signal.set(DemandOutcome::Cancelled);
                            Self::poison(state, ResourceClass::OpaqueDependencyResidual);
                            return;
                        }
                    }
                    state.reservations.insert(
                        reservation_id,
                        Reservation {
                            scope_id: lease_scope_id,
                            authority,
                            claim,
                            lifecycle: ReservationLifecycle::Live,
                            reclaim_target: pending.reclaim_target,
                            holders: 1,
                        },
                    );
                    state.in_use = next;
                    // Exact requested claim, plus the internal charge kept
                    // separately so an oracle never accumulates the latter.
                    #[cfg(test)]
                    state.decision_log.push(ProviderDecision::ArbitrationGrant {
                        scope_id,
                        demand_key: demand_key_of(&identity),
                        requested: claim,
                        charged: charge,
                    });
                    // Rotate past the served root, not the served scope, so a
                    // root cannot gain extra turns by holding extra children.
                    state.demand_cursor[Self::authority_index(authority)] = state
                        .scopes
                        .get(&scope_id)
                        .map(|record| Self::turn_key(state, record));
                    state.active_demand = None;
                    identity.signal.set(DemandOutcome::Granted {
                        reservation_id,
                        created_scope_id: match placement {
                            DemandPlacement::ExistingScope => None,
                            DemandPlacement::NewChild { scope_id } => Some(scope_id),
                        },
                    });
                    continue;
                }

                // Resolve the requester's root from the scope that actually
                // owns the pending demand, never from `lease_scope_id`. For a
                // `NewChild` demand the lease scope is a prospective child that
                // does not exist yet, so using it would lose the root and
                // disable the own-root-last ordering.
                //
                // Fail closed if it cannot resolve. A scope that owns a pending
                // demand necessarily has a record and therefore a root, so this
                // is an impossible state rather than a refusal — and reclaiming
                // without attribution is precisely the route-around this rule
                // exists to prevent, so it must never proceed unattributed.
                let Some(requester_root) = Self::root_of(state, scope_id) else {
                    Self::poison(state, ResourceClass::OpaqueDependencyResidual);
                    return;
                };
                if Self::select_reclaim_victims(state, requester_root, charge) {
                    return;
                }

                let Some(pressure) =
                    Self::pressure_for_charge(state, lease_scope_id, authority, charge)
                else {
                    Self::poison(state, ResourceClass::OpaqueDependencyResidual);
                    return;
                };
                let removed = state
                    .scopes
                    .get_mut(&scope_id)
                    .and_then(|scope| scope.pending.take());
                if removed.is_none() {
                    Self::poison(state, ResourceClass::OpaqueDependencyResidual);
                    return;
                }
                #[cfg(test)]
                state.decision_log.push(ProviderDecision::TerminalPressure {
                    scope_id,
                    demand_key: demand_key_of(&identity),
                    dimension: pressure.dimension,
                });
                state.demand_cursor[Self::authority_index(authority)] = state
                    .scopes
                    .get(&scope_id)
                    .map(|record| Self::turn_key(state, record));
                state.active_demand = None;
                identity.signal.set(DemandOutcome::Pressured(pressure));
            }
        }

        fn bind_provider_authority(
            state: &mut State,
            provider_authority: &ResourceProviderAuthority,
        ) -> Result<(), ResourceUnavailable> {
            match state.provider_authority.as_ref() {
                Some(bound) if Arc::ptr_eq(bound, &provider_authority.identity) => Ok(()),
                Some(_) => Err(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                }),
                None => {
                    state.provider_authority = Some(Arc::clone(&provider_authority.identity));
                    Ok(())
                }
            }
        }

        fn require_provider_authority(
            state: &State,
            provider_authority: &ResourceProviderAuthority,
        ) -> Result<(), ResourceUnavailable> {
            if state
                .provider_authority
                .as_ref()
                .is_some_and(|bound| Arc::ptr_eq(bound, &provider_authority.identity))
            {
                Ok(())
            } else {
                Err(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                })
            }
        }

        fn checked_admission(
            state: &mut State,
            base: ResourceClaim,
            scope_id: ResourceScopeId,
            authority: ResourceAuthorityClass,
            parts: &[ResourceClaim],
        ) -> Result<(ResourceClaim, ResourceClaim), ResourceUnavailable> {
            let mut requested = ResourceClaim::ZERO;
            let mut next = base;
            for dimension in ResourceClass::ALL {
                let in_use = base.amount(dimension);
                let capacity = state.grant.amount(dimension);
                if in_use > capacity {
                    Self::poison(state, dimension);
                    return Err(ResourceUnavailable::ProviderInvariant { dimension });
                }
                let total = parts
                    .iter()
                    .fold(0_u128, |sum, part| sum + u128::from(part.amount(dimension)));
                let total = u64::try_from(total)
                    .map_err(|_| ResourceUnavailable::ProviderInvariant { dimension })?;
                let available = capacity - in_use;
                if total > available {
                    return Err(ResourceUnavailable::Pressure(ResourcePressure {
                        scope_id,
                        authority,
                        dimension,
                        requested: total,
                        in_use,
                        capacity,
                    }));
                }
                requested.amounts[dimension.index()] = total;
                next.amounts[dimension.index()] = in_use
                    .checked_add(total)
                    .ok_or(ResourceUnavailable::ProviderInvariant { dimension })?;
            }
            Ok((requested, next))
        }

        fn poisoned(state: &State) -> Result<(), ResourceUnavailable> {
            if let Some(dimension) = state.poisoned {
                Err(ResourceUnavailable::ProviderInvariant { dimension })
            } else {
                Ok(())
            }
        }

        fn poison(state: &mut State, dimension: ResourceClass) {
            state.poisoned.get_or_insert(dimension);
        }

        #[cfg(test)]
        fn scripted_pressure(
            state: &mut State,
            scope_id: ResourceScopeId,
            authority: ResourceAuthorityClass,
            claim: ResourceClaim,
        ) -> Option<ResourceUnavailable> {
            let dimension = *state.scripted_pressure.front()?;
            if claim.amount(dimension) == 0 {
                return None;
            }
            state.scripted_pressure.pop_front();
            Some(ResourceUnavailable::Pressure(ResourcePressure {
                scope_id,
                authority,
                dimension,
                requested: claim.amount(dimension),
                in_use: state.in_use.amount(dimension),
                capacity: state.grant.amount(dimension),
            }))
        }
    }

    impl ResourceProvider for FiniteResourceProvider {
        fn create_scope(
            &self,
            provider_authority: &ResourceProviderAuthority,
            scope_id: ResourceScopeId,
            parent_scope_id: Option<ResourceScopeId>,
        ) -> Result<(), ResourceUnavailable> {
            let mut state = self.lock_state();
            Self::poisoned(&state)?;
            Self::bind_provider_authority(&mut state, provider_authority)?;
            if let Some(parent_scope_id) = parent_scope_id {
                if !state.scopes.contains_key(&parent_scope_id) {
                    return Err(ResourceUnavailable::UnknownScope {
                        scope_id: parent_scope_id,
                    });
                }
            }
            if state.scopes.contains_key(&scope_id) {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return Err(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                });
            }
            let bookkeeping = Self::bookkeeping_claim();
            if let Some(pressure) = Self::active_demand_gate(
                &state,
                scope_id,
                ResourceAuthorityClass::Speculative,
                bookkeeping,
            ) {
                return Err(pressure);
            }
            // Resolve the root before allocating anything, so a refusal below
            // leaves both the topology and the order pool untouched.
            let inherited = match parent_scope_id {
                Some(parent_scope_id) => Some(Self::inherited_root(&state, parent_scope_id)?),
                None => None,
            };
            let base = state.in_use;
            let (_, next) = Self::checked_admission(
                &mut state,
                base,
                scope_id,
                ResourceAuthorityClass::Speculative,
                &[bookkeeping],
            )?;
            // Only now that creation has certainly succeeded does an order
            // leave the pool.
            let (order, _provenance) = Self::allocate_scope_order(&mut state)?;
            // `parent_scope_id == None` is the provider-authority-minted
            // fairness-root scope: the initial process scope, or a crate-local
            // trusted extra root. It mints a root from its own order. No caller
            // supplies, names, or observes that value. An ordinary child always
            // arrives with `Some(parent)` and inherits verbatim.
            let root = inherited.unwrap_or(FairnessRoot(order));
            state.scopes.insert(
                scope_id,
                ScopeRecord {
                    pending: None,
                    root,
                    order,
                },
            );
            state.in_use = next;
            Ok(())
        }

        fn create_scope_and_acquire(
            &self,
            provider_authority: &ResourceProviderAuthority,
            scope_id: ResourceScopeId,
            parent_scope_id: ResourceScopeId,
            authority: ResourceAuthorityClass,
            claim: ResourceClaim,
        ) -> Result<u64, ResourceUnavailable> {
            let mut state = self.lock_state();
            Self::poisoned(&state)?;
            Self::require_provider_authority(&state, provider_authority)?;
            if !state.scopes.contains_key(&parent_scope_id) {
                return Err(ResourceUnavailable::UnknownScope {
                    scope_id: parent_scope_id,
                });
            }
            if state.scopes.contains_key(&scope_id) {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return Err(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                });
            }
            let bookkeeping = Self::bookkeeping_claim();
            let base = state.in_use;
            let (_transaction_claim, replacement) = Self::checked_admission(
                &mut state,
                base,
                scope_id,
                authority,
                &[claim, bookkeeping, bookkeeping],
            )?;
            if let Some(pressure) =
                Self::active_demand_gate(&state, parent_scope_id, authority, _transaction_claim)
            {
                return Err(pressure);
            }
            #[cfg(test)]
            if let Some(pressure) =
                Self::scripted_pressure(&mut state, scope_id, authority, _transaction_claim)
            {
                return Err(pressure);
            }
            // Both fallible allocations happen before any mutation, and the
            // first is returned if the second fails, so a refusal consumes no
            // order, no reservation id, and no capacity.
            let prepared = Self::prepare_child_scope(&mut state, parent_scope_id)?;
            let reservation = match Self::allocate_reservation_id_tracked(&mut state) {
                Ok(reservation) => reservation,
                Err(error) => {
                    Self::rollback_prepared_child(&mut state, prepared);
                    return Err(error);
                }
            };
            let reservation_id = reservation.id;
            if let Err(error) = Self::commit_child_scope(&mut state, scope_id, prepared) {
                // Invariant path, but it must still leak nothing.
                Self::rollback_reservation_id(&mut state, reservation);
                Self::rollback_prepared_child(&mut state, prepared);
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return Err(error);
            }
            state.reservations.insert(
                reservation_id,
                Reservation {
                    scope_id,
                    authority,
                    claim,
                    lifecycle: ReservationLifecycle::Live,
                    reclaim_target: None,
                    holders: 1,
                },
            );
            state.in_use = replacement;
            Ok(reservation_id)
        }

        fn create_scope_and_acquire_cooperatively(
            &self,
            provider_authority: &ResourceProviderAuthority,
            scope_id: ResourceScopeId,
            parent_scope_id: ResourceScopeId,
            claim: ResourceClaim,
            reclaim_target: ResourceReclaimTarget,
        ) -> Result<ResourceProviderAdmission, ResourceUnavailable> {
            let mut state = self.lock_state();
            Self::poisoned(&state)?;
            Self::require_provider_authority(&state, provider_authority)?;
            if !state.scopes.contains_key(&parent_scope_id) {
                return Err(ResourceUnavailable::UnknownScope {
                    scope_id: parent_scope_id,
                });
            }
            if state.scopes.contains_key(&scope_id) {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return Err(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                });
            }
            // No pending-demand gate here. A claim that fits outside the
            // selected demand's exact reservation must still be admitted
            // immediately, even when this scope or a sibling on the same root
            // already holds that root's turn. The one-pending-per-root rule is
            // applied below, where a pending demand would actually be created,
            // and it covers the exact scope as a member of its own root.
            let charge = Self::reservation_charge(claim)?
                .checked_add(Self::bookkeeping_claim())
                .map_err(|_| ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                })?;
            Self::charge_can_ever_fit(
                &state,
                scope_id,
                ResourceAuthorityClass::Speculative,
                charge,
            )?;
            let gated = Self::active_demand_gate(
                &state,
                parent_scope_id,
                ResourceAuthorityClass::Speculative,
                charge,
            )
            .is_some();
            let pressured = Self::pressure_for_charge(
                &state,
                scope_id,
                ResourceAuthorityClass::Speculative,
                charge,
            )
            .is_some();
            if !gated && !pressured {
                #[cfg(test)]
                if let Some(pressure) = Self::scripted_pressure(
                    &mut state,
                    scope_id,
                    ResourceAuthorityClass::Speculative,
                    charge,
                ) {
                    return Err(pressure);
                }
                // Every fallible step runs before `state.in_use` is touched,
                // and earlier allocations are returned on later failure, so a
                // refusal leaves accounting, topology, and the order pool
                // exactly as they were.
                let prepared = Self::prepare_child_scope(&mut state, parent_scope_id)?;
                let reservation = match Self::allocate_reservation_id_tracked(&mut state) {
                    Ok(reservation) => reservation,
                    Err(error) => {
                        Self::rollback_prepared_child(&mut state, prepared);
                        return Err(error);
                    }
                };
                let reservation_id = reservation.id;
                let next_in_use = match state.in_use.checked_add(charge) {
                    Ok(next_in_use) => next_in_use,
                    Err(
                        ResourceClaimArithmeticError::Overflow { dimension }
                        | ResourceClaimArithmeticError::Underflow { dimension },
                    ) => {
                        Self::rollback_reservation_id(&mut state, reservation);
                        Self::rollback_prepared_child(&mut state, prepared);
                        return Err(ResourceUnavailable::ProviderInvariant { dimension });
                    }
                };
                if let Err(error) = Self::commit_child_scope(&mut state, scope_id, prepared) {
                    Self::rollback_reservation_id(&mut state, reservation);
                    Self::rollback_prepared_child(&mut state, prepared);
                    Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                    return Err(error);
                }
                state.in_use = next_in_use;
                state.reservations.insert(
                    reservation_id,
                    Reservation {
                        scope_id,
                        authority: ResourceAuthorityClass::Speculative,
                        claim,
                        lifecycle: ReservationLifecycle::Live,
                        reclaim_target: Some(reclaim_target),
                        holders: 1,
                    },
                );
                // Recorded only here, once the whole atomic transaction has
                // committed: the child scope exists, `in_use` is updated, and
                // the reservation is inserted. Appending earlier would put a
                // grant in the trace that a later failure could still undo.
                //
                // The scope recorded is the child that received the admission,
                // matching the reservation's owner.
                #[cfg(test)]
                state.decision_log.push(ProviderDecision::ImmediateGrant {
                    scope_id,
                    requested: claim,
                    charged: charge,
                });
                return Ok(ResourceProviderAdmission::Acquired(reservation_id));
            }

            // Only from here can this call create another pending demand. The
            // new child inherits the parent's root, so the rule is evaluated
            // against that root.
            if let Some(root) = Self::root_of(&state, parent_scope_id) {
                if let Some(holder) = Self::pending_holder(&state, parent_scope_id, root) {
                    #[cfg(test)]
                    state.decision_log.push(ProviderDecision::PendingRefused {
                        scope_id: parent_scope_id,
                        holder,
                        requested: claim,
                    });
                    return Err(ResourceUnavailable::DemandPending { scope_id: holder });
                }
            }

            let identity = ResourceDemandIdentity {
                signal: Arc::new(DemandSignal {
                    outcome: Mutex::new(DemandOutcome::Waiting),
                    ready: Notify::new(),
                }),
            };
            #[cfg(test)]
            state.decision_log.push(ProviderDecision::PendingAccepted {
                scope_id: parent_scope_id,
                demand_key: demand_key_of(&identity),
                requested: claim,
            });
            let Some(parent) = state.scopes.get_mut(&parent_scope_id) else {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return Err(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                });
            };
            parent.pending = Some(PendingDemand {
                authority: ResourceAuthorityClass::Speculative,
                claim,
                reclaim_target: Some(reclaim_target),
                identity: identity.duplicate(),
                placement: DemandPlacement::NewChild { scope_id },
            });
            Self::arbitrate(&mut state);
            match identity.signal.outcome() {
                DemandOutcome::Waiting => Ok(ResourceProviderAdmission::Pending(identity)),
                DemandOutcome::Granted {
                    reservation_id,
                    created_scope_id: Some(created),
                } if created == scope_id => {
                    identity.signal.set(DemandOutcome::Cancelled);
                    Ok(ResourceProviderAdmission::Acquired(reservation_id))
                }
                DemandOutcome::Pressured(pressure) => Err(ResourceUnavailable::Pressure(pressure)),
                DemandOutcome::Granted { .. } | DemandOutcome::Cancelled => {
                    Err(ResourceUnavailable::ProviderInvariant {
                        dimension: ResourceClass::OpaqueDependencyResidual,
                    })
                }
            }
        }

        fn release_scope(
            &self,
            provider_authority: &ResourceProviderAuthority,
            scope_id: ResourceScopeId,
        ) {
            let mut state = self.lock_state();
            if Self::require_provider_authority(&state, provider_authority).is_err() {
                return;
            }
            if !state.scopes.contains_key(&scope_id) {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return;
            }
            if state
                .reservations
                .values()
                .any(|reservation| reservation.scope_id == scope_id)
            {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return;
            }
            let Ok(next) = state.in_use.checked_sub(Self::bookkeeping_claim()) else {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return;
            };
            if let Some(pending) = state
                .scopes
                .get_mut(&scope_id)
                .and_then(|scope| scope.pending.take())
            {
                pending.identity.signal.set(DemandOutcome::Cancelled);
            }
            // A true scope release, and only a true release, retires the
            // record, invalidates any cursor naming a now-empty root, and
            // returns the order for reissue.
            Self::retire_scope_record(&mut state, scope_id);
            state.in_use = next;
            Self::arbitrate(&mut state);
        }

        fn acquire(
            &self,
            provider_authority: &ResourceProviderAuthority,
            scope_id: ResourceScopeId,
            authority: ResourceAuthorityClass,
            claim: ResourceClaim,
        ) -> Result<u64, ResourceUnavailable> {
            let mut state = self.lock_state();
            Self::poisoned(&state)?;
            Self::require_provider_authority(&state, provider_authority)?;
            if !state.scopes.contains_key(&scope_id) {
                return Err(ResourceUnavailable::UnknownScope { scope_id });
            }
            let bookkeeping = Self::bookkeeping_claim();
            let base = state.in_use;
            let (_charged_claim, replacement) = Self::checked_admission(
                &mut state,
                base,
                scope_id,
                authority,
                &[claim, bookkeeping],
            )?;
            #[cfg(test)]
            if let Some(pressure) =
                Self::scripted_pressure(&mut state, scope_id, authority, _charged_claim)
            {
                return Err(pressure);
            }
            if let Some(pressure) =
                Self::active_demand_gate(&state, scope_id, authority, _charged_claim)
            {
                return Err(pressure);
            }
            let reservation_id = Self::allocate_reservation_id(&mut state)?;
            state.reservations.insert(
                reservation_id,
                Reservation {
                    scope_id,
                    authority,
                    claim,
                    lifecycle: ReservationLifecycle::Live,
                    reclaim_target: None,
                    holders: 1,
                },
            );
            state.in_use = replacement;
            Ok(reservation_id)
        }

        fn acquire_cooperatively(
            &self,
            provider_authority: &ResourceProviderAuthority,
            scope_id: ResourceScopeId,
            authority: ResourceAuthorityClass,
            claim: ResourceClaim,
            reclaim_target: Option<ResourceReclaimTarget>,
        ) -> Result<ResourceProviderAdmission, ResourceUnavailable> {
            let mut state = self.lock_state();
            Self::poisoned(&state)?;
            Self::require_provider_authority(&state, provider_authority)?;
            if !state.scopes.contains_key(&scope_id) {
                return Err(ResourceUnavailable::UnknownScope { scope_id });
            }
            let target_matches = match authority {
                ResourceAuthorityClass::Speculative => reclaim_target.is_some(),
                ResourceAuthorityClass::Cleanup | ResourceAuthorityClass::Admitted => {
                    reclaim_target.is_none()
                }
            };
            if !target_matches {
                return Err(ResourceUnavailable::ReclaimTargetMismatch {
                    scope_id,
                    authority,
                });
            }
            // No pending-demand gate here, for the same reason: the immediate
            // path below must remain reachable while a turn is held. The
            // one-pending-per-root rule is applied where a demand is created.
            Self::claim_can_ever_fit(&state, scope_id, authority, claim)?;

            let charge = Self::reservation_charge(claim)?;
            let gated = Self::active_demand_gate(&state, scope_id, authority, charge).is_some();
            let pressured = Self::pressure_for_claim(&state, scope_id, authority, claim).is_some();
            if !gated && !pressured {
                #[cfg(test)]
                if let Some(pressure) =
                    Self::scripted_pressure(&mut state, scope_id, authority, charge)
                {
                    return Err(pressure);
                }
                let reservation_id = Self::allocate_reservation_id(&mut state)?;
                state.in_use = state
                    .in_use
                    .checked_add(charge)
                    .map_err(|error| match error {
                        ResourceClaimArithmeticError::Overflow { dimension }
                        | ResourceClaimArithmeticError::Underflow { dimension } => {
                            ResourceUnavailable::ProviderInvariant { dimension }
                        }
                    })?;
                state.reservations.insert(
                    reservation_id,
                    Reservation {
                        scope_id,
                        authority,
                        claim,
                        lifecycle: ReservationLifecycle::Live,
                        reclaim_target,
                        holders: 1,
                    },
                );
                #[cfg(test)]
                state.decision_log.push(ProviderDecision::ImmediateGrant {
                    scope_id,
                    requested: claim,
                    charged: charge,
                });
                return Ok(ResourceProviderAdmission::Acquired(reservation_id));
            }

            // Only from here can this call create another pending demand, so
            // this is the only place the one-pending-per-root rule applies.
            // Deliberately after the immediate path above: a claim that fits
            // outside the selected demand's exact reservation is admitted even
            // when a sibling scope on the same root already holds that root's
            // turn.
            if let Some(root) = Self::root_of(&state, scope_id) {
                if let Some(holder) = Self::pending_holder(&state, scope_id, root) {
                    #[cfg(test)]
                    state.decision_log.push(ProviderDecision::PendingRefused {
                        scope_id,
                        holder,
                        requested: claim,
                    });
                    return Err(ResourceUnavailable::DemandPending { scope_id: holder });
                }
            }

            let identity = ResourceDemandIdentity {
                signal: Arc::new(DemandSignal {
                    outcome: Mutex::new(DemandOutcome::Waiting),
                    ready: Notify::new(),
                }),
            };
            #[cfg(test)]
            state.decision_log.push(ProviderDecision::PendingAccepted {
                scope_id,
                demand_key: demand_key_of(&identity),
                requested: claim,
            });
            let Some(scope) = state.scopes.get_mut(&scope_id) else {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return Err(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                });
            };
            scope.pending = Some(PendingDemand {
                authority,
                claim,
                reclaim_target,
                identity: identity.duplicate(),
                placement: DemandPlacement::ExistingScope,
            });
            Self::arbitrate(&mut state);
            match identity.signal.outcome() {
                DemandOutcome::Pressured(pressure) => Err(ResourceUnavailable::Pressure(pressure)),
                DemandOutcome::Granted {
                    reservation_id,
                    created_scope_id: None,
                } => {
                    identity.signal.set(DemandOutcome::Cancelled);
                    Ok(ResourceProviderAdmission::Acquired(reservation_id))
                }
                DemandOutcome::Granted {
                    created_scope_id: Some(_),
                    ..
                } => Err(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                }),
                DemandOutcome::Waiting => Ok(ResourceProviderAdmission::Pending(identity)),
                DemandOutcome::Cancelled => Err(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                }),
            }
        }

        fn acquire_reclaimable_now(
            &self,
            provider_authority: &ResourceProviderAuthority,
            scope_id: ResourceScopeId,
            claim: ResourceClaim,
            reclaim_target: ResourceReclaimTarget,
        ) -> Result<u64, ResourceUnavailable> {
            let mut state = self.lock_state();
            Self::poisoned(&state)?;
            Self::require_provider_authority(&state, provider_authority)?;
            if !state.scopes.contains_key(&scope_id) {
                return Err(ResourceUnavailable::UnknownScope { scope_id });
            }
            let bookkeeping = Self::bookkeeping_claim();
            let base = state.in_use;
            let (_charge, replacement) = Self::checked_admission(
                &mut state,
                base,
                scope_id,
                ResourceAuthorityClass::Speculative,
                &[claim, bookkeeping],
            )?;
            if let Some(pressure) = Self::active_demand_gate(
                &state,
                scope_id,
                ResourceAuthorityClass::Speculative,
                _charge,
            ) {
                return Err(pressure);
            }
            #[cfg(test)]
            if let Some(pressure) = Self::scripted_pressure(
                &mut state,
                scope_id,
                ResourceAuthorityClass::Speculative,
                _charge,
            ) {
                return Err(pressure);
            }
            let reservation_id = Self::allocate_reservation_id(&mut state)?;
            state.reservations.insert(
                reservation_id,
                Reservation {
                    scope_id,
                    authority: ResourceAuthorityClass::Speculative,
                    claim,
                    lifecycle: ReservationLifecycle::Live,
                    reclaim_target: Some(reclaim_target),
                    holders: 1,
                },
            );
            state.in_use = replacement;
            Ok(reservation_id)
        }

        fn retry_demand(
            &self,
            provider_authority: &ResourceProviderAuthority,
            scope_id: ResourceScopeId,
            demand: &ResourceDemandIdentity,
        ) -> Result<ResourceProviderAdmission, ResourceUnavailable> {
            let state = self.lock_state();
            Self::poisoned(&state)?;
            Self::require_provider_authority(&state, provider_authority)?;
            if !state.scopes.contains_key(&scope_id) {
                return Err(ResourceUnavailable::UnknownScope { scope_id });
            }
            match demand.signal.outcome() {
                DemandOutcome::Waiting => {
                    let exact = state
                        .scopes
                        .get(&scope_id)
                        .and_then(|scope| scope.pending.as_ref())
                        .is_some_and(|pending| Self::demand_matches(pending, demand));
                    if !exact {
                        return Err(ResourceUnavailable::ProviderInvariant {
                            dimension: ResourceClass::OpaqueDependencyResidual,
                        });
                    }
                    Ok(ResourceProviderAdmission::Pending(demand.duplicate()))
                }
                DemandOutcome::Granted {
                    reservation_id,
                    created_scope_id,
                } => {
                    let exact =
                        state
                            .reservations
                            .get(&reservation_id)
                            .is_some_and(|reservation| {
                                reservation.scope_id == created_scope_id.unwrap_or(scope_id)
                            });
                    if !exact {
                        return Err(ResourceUnavailable::ProviderInvariant {
                            dimension: ResourceClass::OpaqueDependencyResidual,
                        });
                    }
                    demand.signal.set(DemandOutcome::Cancelled);
                    Ok(ResourceProviderAdmission::Acquired(reservation_id))
                }
                DemandOutcome::Pressured(pressure) => Err(ResourceUnavailable::Pressure(pressure)),
                DemandOutcome::Cancelled => Err(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                }),
            }
        }

        fn cancel_demand(
            &self,
            provider_authority: &ResourceProviderAuthority,
            scope_id: ResourceScopeId,
            demand: &ResourceDemandIdentity,
        ) {
            let mut state = self.lock_state();
            if Self::require_provider_authority(&state, provider_authority).is_err() {
                return;
            }
            match demand.signal.outcome() {
                DemandOutcome::Waiting => {
                    let exact = state
                        .scopes
                        .get(&scope_id)
                        .and_then(|scope| scope.pending.as_ref())
                        .is_some_and(|pending| Self::demand_matches(pending, demand));
                    if !exact {
                        Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                        return;
                    }
                    state
                        .scopes
                        .get_mut(&scope_id)
                        .and_then(|scope| scope.pending.take());
                    if state.active_demand.as_ref().is_some_and(|active| {
                        active.scope_id == scope_id
                            && Arc::ptr_eq(&active.identity.signal, &demand.signal)
                    }) {
                        state.active_demand = None;
                    }
                    #[cfg(test)]
                    state.decision_log.push(ProviderDecision::Cancelled {
                        scope_id,
                        demand_key: demand_key_of(demand),
                    });
                    demand.signal.set(DemandOutcome::Cancelled);
                    Self::arbitrate(&mut state);
                }
                DemandOutcome::Granted {
                    reservation_id,
                    created_scope_id,
                } => {
                    // Validate everything first. No removal, free-set insert,
                    // `in_use` change, trace append, or signal write happens
                    // until every check has passed, so an invariant failure
                    // poisons without partially unwinding the grant and without
                    // recording a cancellation that did not occur.
                    let Some(reservation) = state.reservations.get(&reservation_id) else {
                        Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                        return;
                    };
                    if reservation.scope_id != created_scope_id.unwrap_or(scope_id) {
                        Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                        return;
                    }
                    let Ok(mut charge) = Self::reservation_charge(reservation.claim) else {
                        Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                        return;
                    };
                    if created_scope_id.is_some() {
                        let Ok(with_scope) = charge.checked_add(Self::bookkeeping_claim()) else {
                            Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                            return;
                        };
                        charge = with_scope;
                    }
                    let Ok(next) = state.in_use.checked_sub(charge) else {
                        Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                        return;
                    };
                    // The created child must exist and be free of a pending
                    // demand before anything is removed, not after.
                    if let Some(created_scope_id) = created_scope_id {
                        let removable = state
                            .scopes
                            .get(&created_scope_id)
                            .is_some_and(|scope| scope.pending.is_none());
                        if !removable {
                            Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                            return;
                        }
                    }

                    // Commit: every step below is infallible.
                    state.reservations.remove(&reservation_id);
                    if let Some(created_scope_id) = created_scope_id {
                        // Cancelling a granted new-child demand truly retires
                        // that scope, returning its order and clearing any
                        // cursor that named its root.
                        Self::retire_scope_record(&mut state, created_scope_id);
                    }
                    state.free_reservation_ids.insert(reservation_id);
                    state.in_use = next;
                    // Recorded after the rollback commits and before
                    // re-arbitration, so any grant that re-arbitration produces
                    // follows this cancellation in the trace rather than
                    // preceding it.
                    #[cfg(test)]
                    state.decision_log.push(ProviderDecision::Cancelled {
                        scope_id,
                        demand_key: demand_key_of(demand),
                    });
                    demand.signal.set(DemandOutcome::Cancelled);
                    Self::arbitrate(&mut state);
                }
                DemandOutcome::Pressured(_) | DemandOutcome::Cancelled => {
                    demand.signal.set(DemandOutcome::Cancelled);
                }
            }
        }

        fn transition(
            &self,
            provider_authority: &ResourceProviderAuthority,
            current: ResourceReservationState,
            replacement_authority: ResourceAuthorityClass,
            replacement: ResourceClaim,
        ) -> Result<(), ResourceUnavailable> {
            let mut state = self.lock_state();
            Self::poisoned(&state)?;
            Self::require_provider_authority(&state, provider_authority)?;
            if !state.scopes.contains_key(&current.scope_id) {
                return Err(ResourceUnavailable::UnknownScope {
                    scope_id: current.scope_id,
                });
            }
            let Some(reservation) = state.reservations.get(&current.reservation_id) else {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return Err(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                });
            };
            if reservation.scope_id != current.scope_id
                || reservation.authority != current.authority
                || reservation.claim != current.claim
            {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return Err(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                });
            }
            if reservation.lifecycle == ReservationLifecycle::ReclaimRequested
                && replacement_authority != ResourceAuthorityClass::Cleanup
            {
                return Err(ResourceUnavailable::ReclaimRequested {
                    scope_id: current.scope_id,
                });
            }
            let current_charge = Self::reservation_charge(current.claim)?;
            let replacement_charge = Self::reservation_charge(replacement)?;
            if reservation.lifecycle != ReservationLifecycle::ReclaimRequested {
                let mut added_charge = ResourceClaim::ZERO;
                for dimension in ResourceClass::ALL {
                    added_charge.amounts[dimension.index()] = replacement_charge
                        .amount(dimension)
                        .saturating_sub(current_charge.amount(dimension));
                }
                if let Some(pressure) = Self::active_demand_gate(
                    &state,
                    current.scope_id,
                    replacement_authority,
                    added_charge,
                ) {
                    return Err(pressure);
                }
            }
            let without_current =
                state
                    .in_use
                    .checked_sub(current_charge)
                    .map_err(|error| match error {
                        ResourceClaimArithmeticError::Overflow { dimension }
                        | ResourceClaimArithmeticError::Underflow { dimension } => {
                            ResourceUnavailable::ProviderInvariant { dimension }
                        }
                    })?;
            let (_replacement_charge, next) = Self::checked_admission(
                &mut state,
                without_current,
                current.scope_id,
                replacement_authority,
                &[replacement, Self::bookkeeping_claim()],
            )?;
            #[cfg(test)]
            if let Some(pressure) = Self::scripted_pressure(
                &mut state,
                current.scope_id,
                replacement_authority,
                _replacement_charge,
            ) {
                return Err(pressure);
            }
            state.in_use = next;
            let Some(reservation) = state.reservations.get_mut(&current.reservation_id) else {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return Err(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                });
            };
            reservation.authority = replacement_authority;
            reservation.claim = replacement;
            if replacement_authority != ResourceAuthorityClass::Speculative
                && reservation.lifecycle == ReservationLifecycle::Live
            {
                reservation.reclaim_target = None;
            }
            Self::arbitrate(&mut state);
            Ok(())
        }

        fn release(
            &self,
            provider_authority: &ResourceProviderAuthority,
            reservation_id: u64,
            scope_id: ResourceScopeId,
            authority: ResourceAuthorityClass,
            claim: ResourceClaim,
        ) {
            let mut state = self.lock_state();
            if Self::require_provider_authority(&state, provider_authority).is_err() {
                return;
            }
            if !state.scopes.contains_key(&scope_id) {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return;
            }
            let Some(reservation) = state.reservations.get(&reservation_id) else {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return;
            };
            if reservation.scope_id != scope_id
                || reservation.authority != authority
                || reservation.claim != claim
                // A multiply held reservation must never reach an outright
                // release: its capacity belongs to owners this call does not
                // speak for. `release_shared` decrements down to one holder and
                // only then delegates here, so anything else arriving with a
                // count above one is a caller that bypassed the shared handle.
                || reservation.holders != 1
            {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return;
            }
            let Ok(charged_claim) = Self::reservation_charge(claim) else {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return;
            };
            let Ok(next) = state.in_use.checked_sub(charged_claim) else {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return;
            };
            state.reservations.remove(&reservation_id);
            state.free_reservation_ids.insert(reservation_id);
            state.in_use = next;
            Self::arbitrate(&mut state);
        }

        /// One more owner of an already-admitted reservation.
        ///
        /// Deliberately touches nothing but the count. `in_use` does not move,
        /// no arbitration runs, and no reclaim decision is revisited, because
        /// nothing about the provider's capacity has changed — the same claim
        /// is simply held by one more owner than before.
        fn retain_shared(
            &self,
            provider_authority: &ResourceProviderAuthority,
            reservation_id: u64,
            scope_id: ResourceScopeId,
        ) -> Result<(), ResourceUnavailable> {
            let mut state = self.lock_state();
            Self::require_provider_authority(&state, provider_authority)?;
            if !state.scopes.contains_key(&scope_id) {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return Err(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                });
            }
            let Some(reservation) = state.reservations.get(&reservation_id) else {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return Err(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                });
            };
            // A retired or reclaiming reservation must not gain owners: the
            // holder that would arrive is one this provider has already decided
            // the fate of.
            if reservation.scope_id != scope_id
                || reservation.lifecycle != ReservationLifecycle::Live
                || reservation.holders == 0
            {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return Err(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                });
            }
            let Some(next) = reservation.holders.checked_add(1) else {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return Err(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                });
            };
            state
                .reservations
                .get_mut(&reservation_id)
                .expect("the reservation was found under this same held lock")
                .holders = next;
            Ok(())
        }

        /// One fewer owner, and a full release only for the last of them.
        ///
        /// The lock is released before delegating, because [`Self::release`]
        /// takes it again and this provider's state mutex is not reentrant.
        fn release_shared(
            &self,
            provider_authority: &ResourceProviderAuthority,
            reservation_id: u64,
            scope_id: ResourceScopeId,
            authority: ResourceAuthorityClass,
            claim: ResourceClaim,
        ) {
            {
                let mut state = self.lock_state();
                if Self::require_provider_authority(&state, provider_authority).is_err() {
                    return;
                }
                if !state.scopes.contains_key(&scope_id) {
                    Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                    return;
                }
                let Some(reservation) = state.reservations.get(&reservation_id) else {
                    Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                    return;
                };
                // The same exact reservation identity `release` demands, checked
                // on the non-final path too. A decrement is a claim on ownership
                // of this reservation, so it has to prove the same thing an
                // outright release proves — otherwise the one path that changes
                // no capacity would be the one path that never checked whose
                // capacity it was.
                //
                // Lifecycle is deliberately not constrained here: a retiring
                // reservation must remain releasable by its owners, and only
                // `retain_shared` requires a `Live` one, because gaining an
                // owner is the operation that would contradict a decision the
                // provider has already taken.
                let holders = reservation.holders;
                if reservation.scope_id != scope_id
                    || reservation.authority != authority
                    || reservation.claim != claim
                    || holders == 0
                {
                    Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                    return;
                }
                if holders > 1 {
                    // Not the last owner. Capacity stays exactly where it is:
                    // the allocation this claim funds is still reachable.
                    state
                        .reservations
                        .get_mut(&reservation_id)
                        .expect("the reservation was found under this same held lock")
                        .holders = holders - 1;
                    return;
                }
            }
            self.release(
                provider_authority,
                reservation_id,
                scope_id,
                authority,
                claim,
            );
        }

        fn retain_after_failed_cleanup(
            &self,
            provider_authority: &ResourceProviderAuthority,
            reservation_id: u64,
            scope_id: ResourceScopeId,
            authority: ResourceAuthorityClass,
            claim: ResourceClaim,
        ) -> ReclaimResult {
            let mut state = self.lock_state();
            if Self::require_provider_authority(&state, provider_authority).is_err() {
                return ReclaimResult::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                };
            }
            if !state.scopes.contains_key(&scope_id) {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return ReclaimResult::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                };
            }
            let Some(reservation) = state.reservations.get(&reservation_id) else {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return ReclaimResult::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                };
            };
            if reservation.scope_id != scope_id
                || reservation.authority != authority
                || reservation.claim != claim
            {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return ReclaimResult::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                };
            }
            let Ok(retained) = state.retained_after_failed_cleanup.checked_add(claim) else {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return ReclaimResult::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                };
            };
            let Ok(next) = state.in_use.checked_sub(Self::bookkeeping_claim()) else {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return ReclaimResult::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                };
            };
            state.reservations.remove(&reservation_id);
            state.free_reservation_ids.insert(reservation_id);
            state.retained_after_failed_cleanup = retained;
            state.in_use = next;
            Self::arbitrate(&mut state);
            ReclaimResult::Retained(claim)
        }

        fn pressure(
            &self,
            _provider_authority: &ResourceProviderAuthority,
            scope_id: ResourceScopeId,
            authority: ResourceAuthorityClass,
            dimension: ResourceClass,
        ) -> ResourcePressure {
            let state = self.lock_state();
            ResourcePressure {
                scope_id,
                authority,
                dimension,
                requested: 0,
                in_use: state.in_use.amount(dimension),
                capacity: state.grant.amount(dimension),
            }
        }

        fn reclaim(
            &self,
            provider_authority: &ResourceProviderAuthority,
            _scope_id: ResourceScopeId,
            pressure: &ResourcePressure,
        ) -> ReclaimResult {
            let state = self.lock_state();
            if Self::require_provider_authority(&state, provider_authority).is_err() {
                return ReclaimResult::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                };
            }
            ReclaimResult::Deferred(*pressure)
        }
    }
}

pub use finite::FiniteResourceProvider;

#[cfg(test)]
pub(crate) use finite::{FiniteProviderSnapshot, ProviderDecision};

#[cfg(test)]
pub(crate) mod test_support {
    pub(crate) use super::FiniteResourceProvider as DeterministicGrantProvider;
}

#[cfg(test)]
mod tests {
    use super::test_support::DeterministicGrantProvider;
    use super::*;
    use std::collections::{BTreeMap, VecDeque};

    fn claim(entries: &[(ResourceClass, u64)]) -> ResourceClaim {
        ResourceClaim::try_from_entries(entries.iter().copied()).expect("finite test claim")
    }

    fn acquired(admission: ResourceAdmission) -> ResourceLease {
        match admission {
            ResourceAdmission::Acquired(lease) => lease,
            ResourceAdmission::Pending(_) => panic!("fixture expected immediate admission"),
        }
    }

    fn pending(admission: ResourceAdmission) -> ResourceAcquireDemand {
        match admission {
            ResourceAdmission::Pending(demand) => demand,
            ResourceAdmission::Acquired(_) => panic!("fixture expected bounded pressure"),
        }
    }

    #[test]
    fn composite_claim_arithmetic_reports_the_exact_dimension() {
        let base = claim(&[
            (ResourceClass::QueuedBytes, u64::MAX),
            (ResourceClass::WorkerOrTask, 1),
        ]);
        let overflow = base
            .checked_add(ResourceClaim::single(ResourceClass::QueuedBytes, 1))
            .expect_err("finite arithmetic must not wrap or treat max as unlimited");
        assert_eq!(
            overflow,
            ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::QueuedBytes
            }
        );

        let underflow = ResourceClaim::ZERO
            .checked_sub(ResourceClaim::single(ResourceClass::StorageObject, 1))
            .expect_err("finite arithmetic must not underflow");
        assert_eq!(
            underflow,
            ResourceClaimArithmeticError::Underflow {
                dimension: ResourceClass::StorageObject
            }
        );
    }

    #[test]
    fn one_process_grant_is_conserved_across_unequal_scopes_and_authorities() {
        let grant = claim(&[
            (ResourceClass::AccountedMemoryBytes, 19),
            (ResourceClass::WorkerOrTask, 3),
            (ResourceClass::OpaqueDependencyResidual, 6),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).expect("process scope bookkeeping");
        let process_scope = port.process_scope();
        let first_scope = port.create_scope(&process_scope).expect("first scope");
        let second_scope = port.create_scope(&process_scope).expect("second scope");
        assert_eq!(
            provider.in_use(),
            ResourceClaim::single(ResourceClass::OpaqueDependencyResidual, 3)
        );

        let first_claim = claim(&[
            (ResourceClass::AccountedMemoryBytes, 7),
            (ResourceClass::WorkerOrTask, 1),
        ]);
        let second_claim = claim(&[
            (ResourceClass::AccountedMemoryBytes, 11),
            (ResourceClass::WorkerOrTask, 2),
        ]);
        let first = port
            .acquire(
                &first_scope,
                ResourceAuthorityClass::Speculative,
                first_claim,
            )
            .expect("first unequal claim");
        let second = port
            .acquire(&second_scope, ResourceAuthorityClass::Cleanup, second_claim)
            .expect("second unequal claim");
        assert_eq!(
            provider.in_use(),
            first_claim
                .checked_add(second_claim)
                .unwrap()
                .checked_add(ResourceClaim::single(
                    ResourceClass::OpaqueDependencyResidual,
                    5,
                ))
                .unwrap()
        );
        assert_eq!(provider.active_reservations(), 2);
        let snapshot = port
            .pressure(
                &first_scope,
                ResourceAuthorityClass::Admitted,
                ResourceClass::AccountedMemoryBytes,
            )
            .expect("diagnostic pressure query");
        assert_eq!(snapshot.requested, 0);
        assert_eq!(snapshot.in_use, 18);
        assert_eq!(snapshot.capacity, 19);

        let pressure = port
            .acquire(
                &second_scope,
                ResourceAuthorityClass::Admitted,
                ResourceClaim::single(ResourceClass::AccountedMemoryBytes, 2),
            )
            .expect_err("the shared process grant has only one byte left");
        assert_eq!(
            pressure.dimension(),
            Some(ResourceClass::AccountedMemoryBytes)
        );

        drop(first);
        assert_eq!(
            provider.in_use(),
            second_claim
                .checked_add(ResourceClaim::single(
                    ResourceClass::OpaqueDependencyResidual,
                    4,
                ))
                .unwrap()
        );
        drop(second);
        assert_eq!(provider.active_reservations(), 0);
        drop(first_scope);
        drop(second_scope);
        drop(process_scope);
        drop(port);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
    }

    #[test]
    fn lease_transition_is_atomic_and_failed_transition_preserves_the_old_claim() {
        let grant = claim(&[
            (ResourceClass::QueuedBytes, 13),
            (ResourceClass::NativeTransportObject, 1),
            (ResourceClass::OpaqueDependencyResidual, 3),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).expect("process scope bookkeeping");
        let process_scope = port.process_scope();
        let scope = port.create_scope(&process_scope).expect("child scope");
        let opening = claim(&[
            (ResourceClass::QueuedBytes, 3),
            (ResourceClass::NativeTransportObject, 1),
        ]);
        let connected = claim(&[
            (ResourceClass::QueuedBytes, 9),
            (ResourceClass::NativeTransportObject, 1),
        ]);
        let mut lease = port
            .acquire(&scope, ResourceAuthorityClass::Speculative, opening)
            .expect("opening claim");

        provider.script_pressure(ResourceClass::QueuedBytes);
        let unavailable = lease
            .transition(connected)
            .expect_err("scripted pressure rejects the whole transition");
        assert_eq!(unavailable.dimension(), Some(ResourceClass::QueuedBytes));
        assert_eq!(lease.claim(), opening);
        assert_eq!(
            provider.in_use(),
            opening
                .checked_add(ResourceClaim::single(
                    ResourceClass::OpaqueDependencyResidual,
                    3,
                ))
                .unwrap()
        );

        lease
            .transition_to(ResourceAuthorityClass::Cleanup, connected)
            .expect("atomic authority and claim replacement");
        assert_eq!(lease.claim(), connected);
        assert_eq!(lease.authority(), ResourceAuthorityClass::Cleanup);
        drop(lease);
        drop(scope);
        drop(process_scope);
        drop(port);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
    }

    #[test]
    fn scripted_pressure_names_its_dimension_without_consuming_capacity() {
        let grant = claim(&[
            (ResourceClass::CallbackOrScheduledWork, 4),
            (ResourceClass::ParsingOrCpuWork, 8),
            (ResourceClass::OpaqueDependencyResidual, 2),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).expect("process scope bookkeeping");
        provider.script_pressure(ResourceClass::ParsingOrCpuWork);
        let requested = claim(&[
            (ResourceClass::CallbackOrScheduledWork, 1),
            (ResourceClass::ParsingOrCpuWork, 2),
        ]);

        let unavailable = port
            .acquire(
                &port.process_scope(),
                ResourceAuthorityClass::Admitted,
                requested,
            )
            .expect_err("scripted pressure must be deterministic");
        let ResourceUnavailable::Pressure(pressure) = unavailable else {
            panic!("expected typed pressure")
        };
        assert_eq!(pressure.dimension, ResourceClass::ParsingOrCpuWork);
        assert_eq!(pressure.requested, 2);
        assert_eq!(
            provider.in_use(),
            ResourceClaim::single(ResourceClass::OpaqueDependencyResidual, 1)
        );
        assert_eq!(provider.active_reservations(), 0);
    }

    #[test]
    fn scope_creation_grants_no_capacity_and_unknown_scopes_are_rejected() {
        let provider = DeterministicGrantProvider::new(ResourceClaim::single(
            ResourceClass::OpaqueDependencyResidual,
            4,
        ));
        let port = ResourceProviderPort::new(provider.clone()).expect("process scope bookkeeping");
        assert!(port.same_provider(&port.clone()));
        let process_scope = port.process_scope();
        let child = port.create_scope(&process_scope).expect("child scope");
        let grandchild = port.create_scope(&child).expect("grandchild scope");
        assert_ne!(child, grandchild);
        assert_eq!(
            provider.in_use(),
            ResourceClaim::single(ResourceClass::OpaqueDependencyResidual, 3)
        );
        assert_eq!(provider.active_reservations(), 0);

        let zero = port
            .acquire(
                &grandchild,
                ResourceAuthorityClass::Cleanup,
                ResourceClaim::ZERO,
            )
            .expect("a zero claim is tracked but consumes no capacity");
        assert_eq!(
            provider.in_use(),
            ResourceClaim::single(ResourceClass::OpaqueDependencyResidual, 4)
        );
        assert_eq!(provider.active_reservations(), 1);
        drop(zero);
        assert_eq!(provider.active_reservations(), 0);
        drop(grandchild);
        drop(child);
        drop(process_scope);
        drop(port);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
    }

    #[test]
    fn refused_scope_and_first_lease_transaction_leaves_no_orphan_state() {
        let provider = DeterministicGrantProvider::new(ResourceClaim::single(
            ResourceClass::OpaqueDependencyResidual,
            2,
        ));
        let port = ResourceProviderPort::new(provider.clone()).expect("process bookkeeping");
        let process = port.process_scope();
        let baseline = provider.in_use();

        let unavailable = port
            .create_scope_with_lease(
                &process,
                ResourceAuthorityClass::Speculative,
                ResourceClaim::ZERO,
            )
            .expect_err("one remaining bookkeeping unit cannot hold a scope and reservation");
        assert!(matches!(
            unavailable,
            ResourceUnavailable::Pressure(ResourcePressure {
                dimension: ResourceClass::OpaqueDependencyResidual,
                requested: 2,
                in_use: 1,
                capacity: 2,
                ..
            })
        ));
        assert_eq!(provider.in_use(), baseline);
        assert_eq!(provider.active_scopes(), 1);
        assert_eq!(provider.active_reservations(), 0);

        let child = port
            .create_scope(&process)
            .expect("the refused transaction consumed no scope bookkeeping");
        assert_eq!(provider.active_scopes(), 2);
        drop(child);
        assert_eq!(provider.in_use(), baseline);
        assert_eq!(provider.active_scopes(), 1);
    }

    #[test]
    fn first_lease_keeps_its_scope_live_and_releases_both_exact_charges() {
        let protected = ResourceClaim::single(ResourceClass::QueuedBytes, 1);
        let provider = DeterministicGrantProvider::new(claim(&[
            (ResourceClass::QueuedBytes, 1),
            (ResourceClass::OpaqueDependencyResidual, 3),
        ]));
        let port = ResourceProviderPort::new(provider.clone()).expect("process bookkeeping");
        let process = port.process_scope();
        let baseline = provider.in_use();
        let (child, lease) = port
            .create_scope_with_lease(&process, ResourceAuthorityClass::Admitted, protected)
            .expect("scope and first lease commit together");
        assert_eq!(provider.active_scopes(), 2);
        assert_eq!(provider.active_reservations(), 1);

        drop(child);
        assert_eq!(provider.active_scopes(), 2);
        assert_eq!(provider.active_reservations(), 1);
        assert_eq!(provider.in_use().amount(ResourceClass::QueuedBytes), 1);

        drop(lease);
        assert_eq!(provider.active_scopes(), 1);
        assert_eq!(provider.active_reservations(), 0);
        assert_eq!(provider.in_use(), baseline);
    }

    #[test]
    fn concurrent_scope_and_first_lease_transactions_share_one_finite_slot() {
        let protected = ResourceClaim::single(ResourceClass::NativeTransportObject, 1);
        let provider = DeterministicGrantProvider::new(claim(&[
            (ResourceClass::NativeTransportObject, 1),
            (ResourceClass::OpaqueDependencyResidual, 3),
        ]));
        let port = ResourceProviderPort::new(provider.clone()).expect("process bookkeeping");
        let process = port.process_scope();
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let port = port.clone();
                let process = process.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    port.create_scope_with_lease(
                        &process,
                        ResourceAuthorityClass::Speculative,
                        protected,
                    )
                })
            })
            .collect();
        barrier.wait();
        let outcomes: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().expect("scope worker joins"))
            .collect();

        assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
        assert_eq!(provider.active_scopes(), 2);
        assert_eq!(provider.active_reservations(), 1);
        assert_eq!(
            provider
                .in_use()
                .amount(ResourceClass::NativeTransportObject),
            1
        );
        drop(outcomes);
        assert_eq!(provider.active_scopes(), 1);
        assert_eq!(provider.active_reservations(), 0);
        assert_eq!(
            provider.in_use(),
            ResourceClaim::single(ResourceClass::OpaqueDependencyResidual, 1)
        );
    }

    #[test]
    fn every_resource_class_is_generic_and_independently_accounted() {
        let requested = ResourceClaim::try_from_entries(
            ResourceClass::ALL
                .into_iter()
                .enumerate()
                .map(|(index, dimension)| (dimension, index as u64 + 1)),
        )
        .expect("all dimensions fit");
        let grant = requested
            .checked_add(ResourceClaim::single(
                ResourceClass::OpaqueDependencyResidual,
                2,
            ))
            .expect("provider bookkeeping fits");
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).expect("process scope bookkeeping");
        let lease = port
            .acquire(
                &port.process_scope(),
                ResourceAuthorityClass::Admitted,
                requested,
            )
            .expect("the exact process grant is admissible");
        assert_eq!(provider.in_use(), grant);
        assert_eq!(ResourceClass::ALL.len(), RESOURCE_CLASS_COUNT);
        drop(lease);
        assert_eq!(
            provider.in_use(),
            ResourceClaim::single(ResourceClass::OpaqueDependencyResidual, 1)
        );
        drop(port);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
    }

    #[test]
    fn failed_cleanup_transfers_exact_charge_without_a_forgotten_lease() {
        let protected = claim(&[
            (ResourceClass::NativeTransportObject, 1),
            (ResourceClass::AccountedMemoryBytes, 5),
        ]);
        let grant = claim(&[
            (ResourceClass::NativeTransportObject, 1),
            (ResourceClass::AccountedMemoryBytes, 9),
            (ResourceClass::WorkerOrTask, 1),
            (ResourceClass::OpaqueDependencyResidual, 3),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).expect("process scope bookkeeping");
        let scope = port
            .create_scope(&port.process_scope())
            .expect("connector scope bookkeeping");
        let lease = port
            .acquire(&scope, ResourceAuthorityClass::Cleanup, protected)
            .expect("protected native allocation");

        assert_eq!(
            lease.retain_after_failed_cleanup(),
            ReclaimResult::Retained(protected)
        );
        assert_eq!(provider.retained_after_failed_cleanup(), protected);
        assert_eq!(provider.active_reservations(), 0);
        let unrelated = port
            .acquire(
                &scope,
                ResourceAuthorityClass::Admitted,
                claim(&[
                    (ResourceClass::AccountedMemoryBytes, 4),
                    (ResourceClass::WorkerOrTask, 1),
                ]),
            )
            .expect("an exact retained failure does not poison unrelated capacity");
        drop(unrelated);
    }

    #[test]
    fn impossible_release_poisons_the_aggregate_and_refuses_later_admission() {
        let grant = claim(&[
            (ResourceClass::QueuedBytes, 2),
            (ResourceClass::OpaqueDependencyResidual, 2),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).expect("process scope bookkeeping");
        let scope = port.process_scope();
        ResourceProvider::release(
            &provider,
            &port.inner.provider_authority,
            u64::MAX,
            scope.id(),
            ResourceAuthorityClass::Admitted,
            ResourceClaim::ZERO,
        );

        let unavailable = port
            .acquire(
                &scope,
                ResourceAuthorityClass::Admitted,
                ResourceClaim::single(ResourceClass::QueuedBytes, 1),
            )
            .expect_err("a poisoned aggregate must fail closed");
        assert_eq!(
            unavailable,
            ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::OpaqueDependencyResidual,
            }
        );
        assert_eq!(
            provider.in_use(),
            ResourceClaim::single(ResourceClass::OpaqueDependencyResidual, 1)
        );
    }

    #[test]
    fn foreign_port_authority_cannot_release_or_reuse_a_live_reservation() {
        let protected_claim = ResourceClaim::single(ResourceClass::QueuedBytes, 1);
        let victim_provider = DeterministicGrantProvider::new(claim(&[
            (ResourceClass::QueuedBytes, 1),
            (ResourceClass::OpaqueDependencyResidual, 2),
        ]));
        let victim_port =
            ResourceProviderPort::new(victim_provider.clone()).expect("victim process bookkeeping");
        let victim_scope = victim_port.process_scope();
        let live = victim_port
            .acquire(
                &victim_scope,
                ResourceAuthorityClass::Admitted,
                protected_claim,
            )
            .expect("victim reservation");

        let foreign_provider = DeterministicGrantProvider::new(ResourceClaim::single(
            ResourceClass::OpaqueDependencyResidual,
            1,
        ));
        let foreign_port =
            ResourceProviderPort::new(foreign_provider).expect("foreign process bookkeeping");
        ResourceProvider::release(
            &victim_provider,
            &foreign_port.inner.provider_authority,
            1,
            victim_scope.id(),
            ResourceAuthorityClass::Admitted,
            protected_claim,
        );

        assert_eq!(victim_provider.active_reservations(), 1);
        assert_eq!(
            victim_provider.in_use(),
            claim(&[
                (ResourceClass::QueuedBytes, 1),
                (ResourceClass::OpaqueDependencyResidual, 2),
            ])
        );
        let unavailable = victim_port
            .acquire(
                &victim_scope,
                ResourceAuthorityClass::Admitted,
                protected_claim,
            )
            .expect_err("foreign authority cannot make the live slot reusable");
        assert!(matches!(
            unavailable,
            ResourceUnavailable::Pressure(ResourcePressure {
                dimension: ResourceClass::QueuedBytes,
                requested: 1,
                in_use: 1,
                capacity: 1,
                ..
            })
        ));

        drop(live);
        let replacement = victim_port
            .acquire(
                &victim_scope,
                ResourceAuthorityClass::Admitted,
                protected_claim,
            )
            .expect("the exact owner release restores the slot");
        assert_eq!(victim_provider.active_reservations(), 1);
        drop(replacement);
    }

    #[test]
    fn one_finite_provider_cannot_back_two_distinct_authority_roots() {
        let provider = DeterministicGrantProvider::new(ResourceClaim::single(
            ResourceClass::OpaqueDependencyResidual,
            2,
        ));
        let first = ResourceProviderPort::new(provider.clone()).expect("first authority root");
        let second = ResourceProviderPort::new(provider.clone())
            .expect_err("a second authority identity must not enter the same provider state");
        assert_eq!(
            second,
            ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::OpaqueDependencyResidual,
            }
        );
        assert_eq!(
            provider.in_use(),
            ResourceClaim::single(ResourceClass::OpaqueDependencyResidual, 1)
        );
        drop(first);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
    }

    #[test]
    fn finite_over_admission_reports_typed_pressure_without_integer_wrap() {
        let grant = claim(&[
            (ResourceClass::QueuedBytes, u64::MAX),
            (ResourceClass::OpaqueDependencyResidual, 3),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).expect("process bookkeeping");
        let scope = port.process_scope();
        let retained = port
            .acquire(
                &scope,
                ResourceAuthorityClass::Admitted,
                ResourceClaim::single(ResourceClass::QueuedBytes, u64::MAX - 1),
            )
            .expect("the finite claim fits");

        let unavailable = port
            .acquire(
                &scope,
                ResourceAuthorityClass::Speculative,
                ResourceClaim::single(ResourceClass::QueuedBytes, 2),
            )
            .expect_err("the exact finite remainder is one byte");
        let ResourceUnavailable::Pressure(pressure) = unavailable else {
            panic!("finite over-admission must be typed pressure")
        };
        assert_eq!(pressure.dimension, ResourceClass::QueuedBytes);
        assert_eq!(pressure.requested, 2);
        assert_eq!(pressure.in_use, u64::MAX - 1);
        assert_eq!(pressure.capacity, u64::MAX);
        assert_eq!(
            retained.claim().amount(ResourceClass::QueuedBytes),
            u64::MAX - 1
        );
    }

    #[test]
    fn composite_request_overflow_is_not_reported_as_exact_pressure() {
        let provider = DeterministicGrantProvider::new(ResourceClaim::single(
            ResourceClass::OpaqueDependencyResidual,
            u64::MAX,
        ));
        let port = ResourceProviderPort::new(provider.clone()).expect("process bookkeeping");
        let baseline = provider.in_use();

        let unavailable = port
            .acquire(
                &port.process_scope(),
                ResourceAuthorityClass::Speculative,
                ResourceClaim::single(ResourceClass::OpaqueDependencyResidual, u64::MAX),
            )
            .expect_err("the request plus its provider record exceeds the exact quantity type");
        assert_eq!(
            unavailable,
            ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::OpaqueDependencyResidual,
            }
        );
        assert_eq!(provider.in_use(), baseline);
    }

    #[test]
    fn provider_rejects_an_unknown_scope_even_with_port_authority() {
        let provider = DeterministicGrantProvider::new(claim(&[
            (ResourceClass::QueuedBytes, 1),
            (ResourceClass::OpaqueDependencyResidual, 2),
        ]));
        let port = ResourceProviderPort::new(provider.clone()).expect("process bookkeeping");
        let unknown = ResourceScopeId(NonZeroU64::new(1).expect("nonzero test scope"));
        assert_ne!(unknown, port.process_scope().id());

        let unavailable = ResourceProvider::acquire(
            &provider,
            &port.inner.provider_authority,
            unknown,
            ResourceAuthorityClass::Admitted,
            ResourceClaim::single(ResourceClass::QueuedBytes, 1),
        )
        .expect_err("the provider validates its own scope registry");
        assert_eq!(
            unavailable,
            ResourceUnavailable::UnknownScope { scope_id: unknown }
        );
    }

    #[test]
    fn releasing_a_scope_with_a_live_reservation_poisons_later_admission() {
        let provider = DeterministicGrantProvider::new(claim(&[
            (ResourceClass::QueuedBytes, 2),
            (ResourceClass::OpaqueDependencyResidual, 4),
        ]));
        let port = ResourceProviderPort::new(provider.clone()).expect("process bookkeeping");
        let scope = port
            .create_scope(&port.process_scope())
            .expect("child scope bookkeeping");
        let lease = port
            .acquire(
                &scope,
                ResourceAuthorityClass::Admitted,
                ResourceClaim::single(ResourceClass::QueuedBytes, 1),
            )
            .expect("live reservation");

        ResourceProvider::release_scope(&provider, &port.inner.provider_authority, scope.id());
        let unavailable = port
            .acquire(
                &scope,
                ResourceAuthorityClass::Admitted,
                ResourceClaim::single(ResourceClass::QueuedBytes, 1),
            )
            .expect_err("scope corruption must fail closed");
        assert_eq!(
            unavailable,
            ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::OpaqueDependencyResidual,
            }
        );
        assert_eq!(lease.claim().amount(ResourceClass::QueuedBytes), 1);
    }

    #[test]
    fn accounting_mutex_poison_becomes_an_explicit_provider_invariant() {
        let provider = DeterministicGrantProvider::new(claim(&[
            (ResourceClass::QueuedBytes, 1),
            (ResourceClass::OpaqueDependencyResidual, 2),
        ]));
        let port = ResourceProviderPort::new(provider.clone()).expect("process bookkeeping");
        provider.poison_accounting_mutex();

        let unavailable = port
            .acquire(
                &port.process_scope(),
                ResourceAuthorityClass::Admitted,
                ResourceClaim::single(ResourceClass::QueuedBytes, 1),
            )
            .expect_err("a poisoned accounting mutex must not admit new work");
        assert_eq!(
            unavailable,
            ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::OpaqueDependencyResidual,
            }
        );
    }

    #[test]
    fn increasing_one_granted_dimension_admits_exactly_one_more_claim() {
        fn admit(grant_bytes: u64, claims: &[u64]) -> Vec<bool> {
            let grant = claim(&[
                (ResourceClass::QueuedBytes, grant_bytes),
                // One process-scope record plus one reservation record for
                // every successful claim in this fixture.
                (
                    ResourceClass::OpaqueDependencyResidual,
                    1 + claims.len() as u64,
                ),
            ]);
            let provider = DeterministicGrantProvider::new(grant);
            let port = ResourceProviderPort::new(provider).expect("process scope bookkeeping");
            let scope = port.process_scope();
            let mut leases = Vec::new();
            claims
                .iter()
                .map(|bytes| {
                    match port.acquire(
                        &scope,
                        ResourceAuthorityClass::Admitted,
                        ResourceClaim::single(ResourceClass::QueuedBytes, *bytes),
                    ) {
                        Ok(lease) => {
                            leases.push(lease);
                            true
                        }
                        Err(_) => false,
                    }
                })
                .collect()
        }

        assert_eq!(admit(8, &[8, 1]), vec![true, false]);
        assert_eq!(admit(9, &[8, 1]), vec![true, true]);
    }

    #[test]
    fn unequal_claim_cost_not_object_count_controls_admission() {
        let grant = claim(&[
            (ResourceClass::AccountedMemoryBytes, 12),
            // Process scope plus three live reservations.
            (ResourceClass::OpaqueDependencyResidual, 4),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).expect("process scope bookkeeping");
        let scope = port.process_scope();

        let small_a = port
            .acquire(
                &scope,
                ResourceAuthorityClass::Admitted,
                ResourceClaim::single(ResourceClass::AccountedMemoryBytes, 2),
            )
            .expect("first small claim");
        let small_b = port
            .acquire(
                &scope,
                ResourceAuthorityClass::Admitted,
                ResourceClaim::single(ResourceClass::AccountedMemoryBytes, 2),
            )
            .expect("second small claim");
        let large = port
            .acquire(
                &scope,
                ResourceAuthorityClass::Admitted,
                ResourceClaim::single(ResourceClass::AccountedMemoryBytes, 8),
            )
            .expect("one larger claim uses the remaining resource quantity");
        assert_eq!(
            provider
                .in_use()
                .amount(ResourceClass::AccountedMemoryBytes),
            12
        );
        assert!(port
            .acquire(
                &scope,
                ResourceAuthorityClass::Admitted,
                ResourceClaim::single(ResourceClass::AccountedMemoryBytes, 1),
            )
            .is_err());
        drop((small_a, small_b, large));
    }

    #[test]
    fn unused_capacity_is_borrowable_across_mesh_attribution_scopes() {
        let grant = claim(&[
            (ResourceClass::WorkerOrTask, 7),
            // Process scope, two children, and two reservations.
            (ResourceClass::OpaqueDependencyResidual, 5),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).expect("process scope bookkeeping");
        let process = port.process_scope();
        let first = port.create_scope(&process).expect("first Mesh scope");
        let second = port.create_scope(&process).expect("second Mesh scope");

        let borrowed = port
            .acquire(
                &first,
                ResourceAuthorityClass::Admitted,
                ResourceClaim::single(ResourceClass::WorkerOrTask, 6),
            )
            .expect("unused process capacity is not partitioned by scope");
        let concurrent = port
            .acquire(
                &second,
                ResourceAuthorityClass::Admitted,
                ResourceClaim::single(ResourceClass::WorkerOrTask, 1),
            )
            .expect("the other scope can consume the exact remainder");
        assert_eq!(provider.in_use().amount(ResourceClass::WorkerOrTask), 7);
        drop((borrowed, concurrent));
    }

    #[test]
    fn slow_storage_work_retains_only_its_finite_lease_until_explicit_drop() {
        let storage = claim(&[
            (ResourceClass::StorageBytes, 5),
            (ResourceClass::StorageObject, 1),
        ]);
        let grant = storage
            .checked_add(ResourceClaim::single(
                ResourceClass::OpaqueDependencyResidual,
                2,
            ))
            .expect("process and reservation bookkeeping");
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).expect("process scope bookkeeping");
        let scope = port.process_scope();
        let lease = port
            .acquire(&scope, ResourceAuthorityClass::Admitted, storage)
            .expect("storage-backed work");

        std::thread::yield_now();
        assert_eq!(lease.claim(), storage);
        assert_eq!(provider.in_use().amount(ResourceClass::StorageBytes), 5);
        assert!(port
            .acquire(
                &scope,
                ResourceAuthorityClass::Speculative,
                ResourceClaim::single(ResourceClass::StorageBytes, 1),
            )
            .is_err());

        drop(lease);
        assert_eq!(provider.in_use().amount(ResourceClass::StorageBytes), 0);
        let replacement = port
            .acquire(&scope, ResourceAuthorityClass::Admitted, storage)
            .expect("explicit release restores the storage grant");
        drop(replacement);
    }

    #[test]
    fn cooperative_pressure_requests_exact_speculation_and_prevents_reacquisition() {
        let grant = claim(&[
            (ResourceClass::QueuedBytes, 4),
            (ResourceClass::OpaqueDependencyResidual, 5),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).expect("process bookkeeping");
        let process = port.process_scope();
        let first = port.create_scope(&process).expect("first scope");
        let second = port.create_scope(&process).expect("second scope");
        let queue = ResourceClaim::single(ResourceClass::QueuedBytes, 4);
        let (target, subscription) = ResourceReclaimSubscription::channel();
        let first_lease = acquired(
            port.acquire_cooperatively(
                &first,
                ResourceAuthorityClass::Speculative,
                queue,
                Some(target),
            )
            .expect("first speculative admission"),
        );
        let second_demand = pending(
            port.acquire_cooperatively(&second, ResourceAuthorityClass::Admitted, queue, None)
                .expect("second scope owns one pending turn"),
        );

        assert!(subscription.is_requested());
        assert!(matches!(
            port.acquire(
                &first,
                ResourceAuthorityClass::Speculative,
                ResourceClaim::single(ResourceClass::QueuedBytes, 1),
            ),
            Err(ResourceUnavailable::Pressure(_))
        ));
        drop(first_lease);
        let second_lease = acquired(second_demand.retry().expect("pre-granted exact lease"));
        assert_eq!(second_lease.scope_id(), second.id());
        assert_eq!(provider.in_use().amount(ResourceClass::QueuedBytes), 4);
        drop(second_lease);
    }

    #[test]
    fn active_turn_fences_plain_scope_bookkeeping() {
        let grant = claim(&[
            (ResourceClass::QueuedBytes, 1),
            (ResourceClass::OpaqueDependencyResidual, 5),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider).expect("process bookkeeping");
        let process = port.process_scope();
        let first = port.create_scope(&process).expect("first scope");
        let second = port.create_scope(&process).expect("second scope");
        let queue = ResourceClaim::single(ResourceClass::QueuedBytes, 1);
        let (target, subscription) = ResourceReclaimSubscription::channel();
        let first_lease = port
            .acquire_reclaimable_now(&first, queue, target)
            .expect("first reclaimable queue");
        let demand = pending(
            port.acquire_cooperatively(&second, ResourceAuthorityClass::Admitted, queue, None)
                .expect("second scope owns the selected turn"),
        );

        assert!(subscription.is_requested());
        assert!(matches!(
            port.create_scope(&process),
            Err(ResourceUnavailable::Pressure(ResourcePressure {
                dimension: ResourceClass::OpaqueDependencyResidual,
                ..
            }))
        ));

        drop(demand);
        drop(first_lease);
    }

    #[test]
    fn active_demander_cannot_reacquire_ahead_of_its_exact_turn() {
        let grant = claim(&[
            (ResourceClass::QueuedBytes, 2),
            (ResourceClass::OpaqueDependencyResidual, 6),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).expect("process bookkeeping");
        let process = port.process_scope();
        let requester = port.create_scope(&process).expect("requester scope");
        let victim = port.create_scope(&process).expect("victim scope");
        let one = ResourceClaim::single(ResourceClass::QueuedBytes, 1);
        let two = ResourceClaim::single(ResourceClass::QueuedBytes, 2);
        let (target, subscription) = ResourceReclaimSubscription::channel();
        let victim_lease = port
            .acquire_reclaimable_now(&victim, one, target)
            .expect("victim owns one queue unit");
        let demand = pending(
            port.acquire_cooperatively(&requester, ResourceAuthorityClass::Admitted, two, None)
                .expect("requester owns an exact two-unit turn"),
        );

        assert!(subscription.is_requested());
        assert!(matches!(
            port.acquire(&requester, ResourceAuthorityClass::Admitted, one),
            Err(ResourceUnavailable::Pressure(_))
        ));
        drop(victim_lease);
        let requester_lease = acquired(demand.retry().expect("the exact turn is granted"));
        assert_eq!(requester_lease.claim(), two);
        assert_eq!(provider.in_use().amount(ResourceClass::QueuedBytes), 2);
        drop(requester_lease);
    }

    /// The full shape of one live run, so a control can assert the trace is
    /// what it expects before drawing conclusions from inequalities over it.
    #[derive(Clone, Debug)]
    struct LiveTrace {
        /// The complete ordered disposition sequence. Prefixes are taken over
        /// **this**, so a decision index counts every disposition — acceptance,
        /// refusal, immediate grant, arbitration grant, terminal pressure,
        /// cancellation — not only the grants. Cumulative selections and
        /// admitted quantities are derived from the grant events inside a
        /// prefix of this sequence.
        events: Vec<LiveEvent>,
        /// Offers refused because their scheduling key already held a turn.
        refused: usize,
        /// Offers accepted as pending demands.
        accepted: usize,
    }

    /// One disposition in the compared trace, resolved to logical demand ids
    /// that were bound at issue time.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum LiveEvent {
        Accepted {
            demand_id: u32,
            root: usize,
            requested: ResourceClaim,
        },
        Refused {
            demand_id: u32,
            root: usize,
            requested: ResourceClaim,
        },
        ImmediateGrant {
            demand_id: u32,
            root: usize,
            requested: ResourceClaim,
        },
        Granted {
            demand_id: u32,
            root: usize,
            requested: ResourceClaim,
        },
        Pressured {
            demand_id: u32,
            root: usize,
        },
        Cancelled {
            demand_id: u32,
            root: usize,
        },
    }

    /// Cumulative admitted vector for `root` at prefix `k`, over every
    /// dimension, with terminal stuttering past the end of the run.
    /// The grant events for `root` within the first `prefix` dispositions.
    ///
    /// Terminal stuttering is implicit: taking more than the sequence length
    /// yields the whole sequence, so a shorter run holds its final cumulative
    /// values while the longer one continues.
    fn grants_in_prefix(
        events: &[LiveEvent],
        root: usize,
        prefix: usize,
    ) -> impl Iterator<Item = ResourceClaim> + '_ {
        events
            .iter()
            .take(prefix.min(events.len()))
            .filter_map(move |event| match event {
                LiveEvent::Granted {
                    root: grant_root,
                    requested,
                    ..
                }
                | LiveEvent::ImmediateGrant {
                    root: grant_root,
                    requested,
                    ..
                } if *grant_root == root => Some(*requested),
                _ => None,
            })
    }

    /// Index in the full disposition sequence at which `demand_id` was granted.
    fn grant_index(events: &[LiveEvent], demand_id: u32) -> Option<usize> {
        events.iter().position(|event| {
            matches!(
                event,
                LiveEvent::Granted { demand_id: id, .. }
                | LiveEvent::ImmediateGrant { demand_id: id, .. } if *id == demand_id
            )
        })
    }

    fn live_cumulative_admitted(events: &[LiveEvent], root: usize, prefix: usize) -> ResourceClaim {
        let mut total = ResourceClaim::ZERO;
        for requested in grants_in_prefix(events, root, prefix) {
            for dimension in ResourceClass::ALL {
                total.amounts[dimension.index()] = total
                    .amount(dimension)
                    .saturating_add(requested.amount(dimension));
            }
        }
        total
    }

    /// Cumulative selection count for `root` at prefix `k`, stuttering past the
    /// end of the run.
    fn live_cumulative_selections(events: &[LiveEvent], root: usize, prefix: usize) -> usize {
        grants_in_prefix(events, root, prefix).count()
    }

    /// Run the fixed Construction A workload against the real provider.
    ///
    /// Both runs are built identically: same grant, same root set, same
    /// pre-created child topology and therefore the same bookkeeping charge,
    /// same initial state, same logical demand ids, claims, authority, and
    /// reclaimability. `mapping[i]` is the only thing that varies — it selects
    /// which pre-created child of root A issues demand `i`.
    ///
    /// Every lease admitted during the compared prefix is held to the end, so
    /// the accounting is monotone across the comparison.
    fn run_live_construction_a(mapping: &[usize], scope_keyed: bool) -> LiveTrace {
        const A: usize = 0;
        const B: usize = 1;
        // Every workload claim is nonzero in every dimension, so the
        // per-dimension inequalities in the oracle are not vacuous outside one
        // selected dimension. QueuedBytes stays the constraining dimension.
        let unit = unit_claim();
        // Queue capacity 6, matched by a blocker claiming all 6, so the full
        // pending set can be granted once the blocker releases.
        let mut grant_entries: Vec<(ResourceClass, u64)> = ResourceClass::ALL
            .into_iter()
            .map(|dimension| (dimension, 4096u64))
            .collect();
        for entry in &mut grant_entries {
            if entry.0 == ResourceClass::QueuedBytes {
                entry.1 = 6;
            }
        }
        let grant = claim(&grant_entries);
        let provider = DeterministicGrantProvider::new(grant);
        provider.set_scope_keyed_selection_for_test(scope_keyed);
        let port = ResourceProviderPort::new(provider.clone()).expect("process bookkeeping");
        let root_a = port.create_fairness_root_scope().expect("fairness root a");
        let root_b = port.create_fairness_root_scope().expect("fairness root b");
        // Identical topology, bookkeeping, and initial state in both runs:
        // three children under each root exist before the measured prefix
        // begins, so subdivision creates no scope inside the comparison.
        let a_children: Vec<ResourceScope> = (0..3)
            .map(|_| port.create_scope(&root_a).expect("pre-created a child"))
            .collect();
        let b_children: Vec<ResourceScope> = (0..3)
            .map(|_| port.create_scope(&root_b).expect("pre-created b child"))
            .collect();

        // A reclaimable blocker holds the whole constraining dimension, so
        // every demand below must queue and be selected by arbitration.
        let blocker_root = port.create_fairness_root_scope().expect("blocker root");
        let blocker_claim =
            ResourceClaim::try_from_entries(ResourceClass::ALL.into_iter().map(|dimension| {
                if dimension == ResourceClass::QueuedBytes {
                    (dimension, 6u64)
                } else {
                    (dimension, 1u64)
                }
            }))
            .expect("finite blocker claim");
        let (blocker_target, _blocker_subscription) = ResourceReclaimSubscription::channel();
        let blocker = port
            .acquire_reclaimable_now(&blocker_root, blocker_claim, blocker_target)
            .expect("blocker holds the constraining dimension");

        // Fixed clock-free issue order with stable logical demand ids. Only the
        // A-side child mapping differs between runs.
        let workload: Vec<(u32, usize, usize)> = vec![
            (100, A, mapping[0]),
            (200, B, 0),
            (101, A, mapping[1]),
            (201, B, 1),
            (102, A, mapping[2]),
            (202, B, 2),
        ];

        // Logical ids are bound to provider-side dispositions at issue time, by
        // two complementary mechanisms, neither of which reconstructs an
        // association afterwards:
        //
        // - `issued_by_key` binds a demand key minted by the provider, taken
        //   from the returned handle at the moment of acceptance. It resolves
        //   every later disposition of that demand — arbitration grant,
        //   terminal pressure, cancellation.
        // - `bound_by_log_index` binds the exact decision-log indices appended
        //   during one synchronous call. Refusals and immediate grants carry no
        //   demand handle, so this is how they are attributed. Keying those by
        //   scope would be unsound: the baseline offers several demands from one
        //   child and refuses more than one of them, so a scope-keyed map would
        //   overwrite and assign every refusal to the last id.
        let mut issued_by_key: BTreeMap<usize, (u32, usize)> = BTreeMap::new();
        let mut bound_by_log_index: BTreeMap<usize, (u32, usize)> = BTreeMap::new();
        let mut queued: VecDeque<(u32, usize, ResourceScope)> = VecDeque::new();
        for (demand_id, root, child) in workload {
            let scope = if root == A {
                a_children[child].clone()
            } else {
                b_children[child].clone()
            };
            queued.push_back((demand_id, root, scope));
        }

        let mut held = Vec::new();
        let mut outstanding: Vec<(u32, ResourceScopeId, ResourceAcquireDemand)> = Vec::new();
        let mut refused = 0usize;
        let mut accepted = 0usize;

        // The compared prefix is exactly one fixed offer pass, plus the blocker
        // release and the arbitration it enables. Every offer happens while the
        // blocker still holds the constraining dimension, so nothing can be
        // admitted immediately and every admission passes through arbitration
        // and is therefore logged.
        //
        // A demand refused because its scheduling key already holds a turn
        // stays refused for the whole prefix and is never re-offered. Re-offering
        // would acquire immediately once capacity freed, and such an admission
        // never reaches `arbitrate`, so it would be a real decision the oracle
        // could not see. This refusal count is precisely what differs between
        // the two policies: under per-root keying root A accepts one demand,
        // under per-scope keying it accepts one per child.
        for (demand_id, root, scope) in queued.drain(..) {
            // Every decision-log entry appended by this synchronous call
            // belongs to this logical demand.
            let log_before = provider.decision_log_for_test().len();
            let outcome =
                port.acquire_cooperatively(&scope, ResourceAuthorityClass::Admitted, unit, None);
            let log_after = provider.decision_log_for_test().len();
            for index in log_before..log_after {
                bound_by_log_index.insert(index, (demand_id, root));
            }
            match outcome {
                Ok(ResourceAdmission::Pending(demand)) => {
                    // Bind the logical id to the provider's own demand key at
                    // the moment of issue, so later dispositions of the same
                    // demand resolve without positional reconstruction.
                    issued_by_key.insert(demand.demand_key_for_test(), (demand_id, root));
                    outstanding.push((demand_id, scope.id(), demand));
                    accepted += 1;
                }
                Ok(ResourceAdmission::Acquired(lease)) => {
                    // The blocker holds the whole constraining dimension, so an
                    // immediate admission here would mean the fixture is not
                    // testing arbitration at all. Fail loudly rather than
                    // silently holding a lease the oracle cannot see.
                    drop(lease);
                    panic!(
                        "demand {demand_id} was admitted immediately; the blocker \
                         should make every offer queue through arbitration"
                    );
                }
                Err(ResourceUnavailable::DemandPending { .. }) => refused += 1,
                Err(other) => panic!(
                    "demand {demand_id} failed for an unexpected reason: {other:?}; \
                     the only expected refusal is an already-held turn"
                ),
            }
        }

        // Release the blocker so arbitration grants the accepted pending set.
        // Every newly admitted lease is held to the end of the comparison.
        drop(blocker);

        let mut progressed = true;
        while progressed {
            progressed = false;
            let mut still_outstanding = Vec::new();
            for (demand_id, scope_id, demand) in outstanding.drain(..) {
                match demand.retry() {
                    Ok(ResourceAdmission::Acquired(lease)) => {
                        held.push(lease);
                        progressed = true;
                    }
                    Ok(ResourceAdmission::Pending(demand)) => {
                        still_outstanding.push((demand_id, scope_id, demand));
                    }
                    Err(error) => panic!(
                        "demand {demand_id} on scope {} failed on retry: {error:?}; \
                         under this fixture the released blocker leaves room for \
                         every accepted demand, so a failure here silently shrinks \
                         the compared trace",
                        scope_id.get()
                    ),
                }
            }
            outstanding = still_outstanding;
        }

        assert!(
            outstanding.is_empty(),
            "every accepted pending demand must be served before the trace ends; \
             {} were left unserved",
            outstanding.len()
        );
        assert_eq!(
            accepted,
            held.len(),
            "every accepted pending demand must yield exactly one held lease"
        );

        // The compared trace is the provider's own complete ordered decision
        // log, not the order this test retried its handles. Logical ids were
        // bound to provider-side demand keys at issue time, so nothing is
        // reconstructed positionally here.
        let log = provider.decision_log_for_test();
        let mut events = Vec::new();
        let mut granted_count = 0usize;
        for (index, entry) in log.iter().enumerate() {
            // Resolve by the demand key bound at acceptance where the
            // disposition carries one; otherwise by the log index bound during
            // the issuing call. Every entry must resolve by one route or the
            // other, or the trace and the workload disagree.
            let by_index = bound_by_log_index.get(&index).copied();
            let event = match *entry {
                ProviderDecision::PendingAccepted {
                    demand_key,
                    requested,
                    ..
                } => {
                    let (demand_id, root) = issued_by_key
                        .get(&demand_key)
                        .copied()
                        .or(by_index)
                        .expect("accepted demand bound at issue time");
                    LiveEvent::Accepted {
                        demand_id,
                        root,
                        requested,
                    }
                }
                ProviderDecision::PendingRefused { requested, .. } => {
                    let (demand_id, root) =
                        by_index.expect("refusal bound to its issuing call by log index");
                    LiveEvent::Refused {
                        demand_id,
                        root,
                        requested,
                    }
                }
                ProviderDecision::ImmediateGrant { requested, .. } => {
                    let (demand_id, root) =
                        by_index.expect("immediate grant bound to its issuing call by log index");
                    LiveEvent::ImmediateGrant {
                        demand_id,
                        root,
                        requested,
                    }
                }
                ProviderDecision::ArbitrationGrant {
                    demand_key,
                    requested,
                    ..
                } => {
                    let (demand_id, root) = issued_by_key
                        .get(&demand_key)
                        .copied()
                        .expect("granted demand bound at issue time");
                    granted_count += 1;
                    // `requested` is the demand's exact claim as the provider
                    // recorded it. The internal charge is deliberately unused:
                    // FORMAL 14.5e accumulates the exact claim.
                    LiveEvent::Granted {
                        demand_id,
                        root,
                        requested,
                    }
                }
                // Both terminal dispositions can occur *synchronously inside the
                // issuing call*: a demand is accepted, arbitration runs inline,
                // resolves it to pressure, and the call returns `Err`. The test
                // then never receives a handle, so no demand key was ever bound
                // and the key route alone would panic on a disposition the
                // trace itself recorded. The per-call log-index binding spans
                // exactly that window, so it is the correct fallback.
                ProviderDecision::TerminalPressure { demand_key, .. } => {
                    let (demand_id, root) = issued_by_key
                        .get(&demand_key)
                        .copied()
                        .or(by_index)
                        .expect("pressured demand bound by key or by issuing call");
                    LiveEvent::Pressured { demand_id, root }
                }
                ProviderDecision::Cancelled { demand_key, .. } => {
                    let (demand_id, root) = issued_by_key
                        .get(&demand_key)
                        .copied()
                        .or(by_index)
                        .expect("cancelled demand bound by key or by issuing call");
                    LiveEvent::Cancelled { demand_id, root }
                }
            };
            events.push(event);
        }
        assert_eq!(
            granted_count,
            held.len(),
            "every arbitration grant must correspond to exactly one held lease"
        );

        drop(held);
        LiveTrace {
            events,
            refused,
            accepted,
        }
    }

    /// Evaluate the live trace oracle, returning the first violation found.
    ///
    /// Quantified over every prefix to the longer execution with terminal
    /// stuttering, every `ResourceClass` dimension, and every competitor root.
    fn evaluate_live_non_amplification(
        baseline_trace: &LiveTrace,
        subdivided_trace: &LiveTrace,
        competitor_roots: &[usize],
        competitor_demand_ids: &[u32],
    ) -> Result<(), String> {
        // Prefixes are taken over the complete disposition sequence, not over
        // grants alone. A decision index therefore counts refusals, immediate
        // grants, and terminal outcomes too, which is what makes "at every
        // prefix" mean every decision the provider made rather than every
        // decision that happened to be a grant.
        let baseline = &baseline_trace.events[..];
        let subdivided = &subdivided_trace.events[..];
        let horizon = baseline.len().max(subdivided.len());
        for prefix in 0..=horizon {
            let baseline_selections = live_cumulative_selections(baseline, 0, prefix);
            let subdivided_selections = live_cumulative_selections(subdivided, 0, prefix);
            if subdivided_selections > baseline_selections {
                return Err(format!(
                    "subdividing root A gained selections at prefix {prefix}: \
                     {subdivided_selections} > {baseline_selections}"
                ));
            }
            let baseline_admitted = live_cumulative_admitted(baseline, 0, prefix);
            let subdivided_admitted = live_cumulative_admitted(subdivided, 0, prefix);
            for dimension in ResourceClass::ALL {
                if subdivided_admitted.amount(dimension) > baseline_admitted.amount(dimension) {
                    return Err(format!(
                        "subdividing root A gained admitted quantity in {dimension:?} at \
                         prefix {prefix}: {} > {}",
                        subdivided_admitted.amount(dimension),
                        baseline_admitted.amount(dimension)
                    ));
                }
            }
            for competitor in competitor_roots {
                let baseline_competitor = live_cumulative_selections(baseline, *competitor, prefix);
                let subdivided_competitor =
                    live_cumulative_selections(subdivided, *competitor, prefix);
                if subdivided_competitor < baseline_competitor {
                    return Err(format!(
                        "competitor root {competitor} was delayed at prefix {prefix}: \
                         {subdivided_competitor} < {baseline_competitor}"
                    ));
                }
            }
        }
        for demand_id in competitor_demand_ids {
            // Selection index is a position in the full decision sequence.
            let before = grant_index(baseline, *demand_id);
            let after = grant_index(subdivided, *demand_id);
            if let Some(before) = before {
                // Absence counts as infinity.
                let after = after.unwrap_or(usize::MAX);
                if after > before {
                    return Err(format!(
                        "competitor demand {demand_id} was delayed: {after} > {before}"
                    ));
                }
            }
        }
        Ok(())
    }

    /// Assert the trace has the shape a control depends on before that control
    /// draws any conclusion from inequalities over it.
    ///
    /// Without this, a provider that refused everything would produce two empty
    /// traces, every inequality would hold vacuously, and the positive control
    /// would pass while proving nothing.
    /// The logical demand ids in the order the provider actually selected them.
    fn decision_ids(trace: &LiveTrace) -> Vec<u32> {
        trace
            .events
            .iter()
            .filter_map(|event| match event {
                LiveEvent::Granted { demand_id, .. }
                | LiveEvent::ImmediateGrant { demand_id, .. } => Some(*demand_id),
                _ => None,
            })
            .collect()
    }

    /// Every logical demand id that reached a grant, in grant order.
    fn granted_count(trace: &LiveTrace) -> usize {
        decision_ids(trace).len()
    }

    /// One disposition reduced to its comparable signature: what kind it was,
    /// which logical demand it concerned, and which root that demand belongs to.
    ///
    /// Counts and grant order alone do not pin the trace: the six offer
    /// dispositions could be reordered and still satisfy both. Comparing exact
    /// signature vectors binds the ordering itself.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct EventSignature {
        kind: &'static str,
        demand_id: u32,
        root: usize,
    }

    /// The single workload claim used by the Construction A fixture: nonzero in
    /// every dimension, with `QueuedBytes` the constraining one.
    fn unit_claim() -> ResourceClaim {
        ResourceClaim::try_from_entries(
            ResourceClass::ALL
                .into_iter()
                .map(|dimension| (dimension, 1u64)),
        )
        .expect("finite uniform claim")
    }

    fn sig(kind: &'static str, demand_id: u32, root: usize) -> EventSignature {
        EventSignature {
            kind,
            demand_id,
            root,
        }
    }

    fn event_signatures(trace: &LiveTrace) -> Vec<EventSignature> {
        trace
            .events
            .iter()
            .map(|event| match *event {
                LiveEvent::Accepted {
                    demand_id, root, ..
                } => sig("accepted", demand_id, root),
                LiveEvent::Refused {
                    demand_id, root, ..
                } => sig("refused", demand_id, root),
                LiveEvent::ImmediateGrant {
                    demand_id, root, ..
                } => sig("immediate", demand_id, root),
                LiveEvent::Granted {
                    demand_id, root, ..
                } => sig("granted", demand_id, root),
                LiveEvent::Pressured { demand_id, root } => sig("pressured", demand_id, root),
                LiveEvent::Cancelled { demand_id, root } => sig("cancelled", demand_id, root),
            })
            .collect()
    }

    /// Every disposition carrying a claim must carry the exact workload claim.
    ///
    /// The signature vectors omit the claim to stay readable; this binds it
    /// separately, so a trace that reported a different admitted quantity than
    /// the workload requested would still fail.
    fn assert_all_requested_claims_are(trace: &LiveTrace, expected: ResourceClaim, label: &str) {
        for event in &trace.events {
            let requested = match *event {
                LiveEvent::Accepted { requested, .. }
                | LiveEvent::Refused { requested, .. }
                | LiveEvent::ImmediateGrant { requested, .. }
                | LiveEvent::Granted { requested, .. } => Some(requested),
                LiveEvent::Pressured { .. } | LiveEvent::Cancelled { .. } => None,
            };
            if let Some(requested) = requested {
                assert_eq!(
                    requested, expected,
                    "{label}: a disposition reported a claim other than the exact \
                     workload claim"
                );
            }
        }
    }

    /// Counts of each disposition kind in the full ordered trace.
    fn event_shape(trace: &LiveTrace) -> (usize, usize, usize, usize, usize, usize) {
        let mut accepted = 0;
        let mut refused = 0;
        let mut immediate = 0;
        let mut granted = 0;
        let mut pressured = 0;
        let mut cancelled = 0;
        for event in &trace.events {
            match event {
                LiveEvent::Accepted { .. } => accepted += 1,
                LiveEvent::Refused { .. } => refused += 1,
                LiveEvent::ImmediateGrant { .. } => immediate += 1,
                LiveEvent::Granted { .. } => granted += 1,
                LiveEvent::Pressured { .. } => pressured += 1,
                LiveEvent::Cancelled { .. } => cancelled += 1,
            }
        }
        (accepted, refused, immediate, granted, pressured, cancelled)
    }

    fn assert_trace_shape(trace: &LiveTrace, refused: usize, accepted: usize, label: &str) {
        // The full ordered trace must agree with the aggregate counts, and must
        // contain no disposition kind the fixture does not intend. An immediate
        // grant here would mean the blocker is not forcing arbitration; a
        // pressure or cancellation would mean a demand died unserved.
        let (trace_accepted, trace_refused, immediate, granted, pressured, cancelled) =
            event_shape(trace);
        assert_eq!(
            trace_accepted, accepted,
            "{label}: accepted count disagrees with the ordered trace"
        );
        assert_eq!(
            trace_refused, refused,
            "{label}: refused count disagrees with the ordered trace"
        );
        assert_eq!(
            immediate, 0,
            "{label}: an immediate grant means arbitration was bypassed"
        );
        assert_eq!(
            granted, accepted,
            "{label}: every accepted demand must reach an arbitration grant"
        );
        assert_eq!(
            pressured, 0,
            "{label}: no demand should end in terminal pressure"
        );
        assert_eq!(
            cancelled, 0,
            "{label}: no demand should end cancelled inside the compared prefix"
        );
        assert_eq!(
            trace.refused, refused,
            "{label}: expected {refused} offers refused for already holding a turn"
        );
        assert_eq!(
            trace.accepted, accepted,
            "{label}: expected {accepted} offers accepted as pending demands"
        );
        assert_eq!(
            granted_count(trace),
            accepted,
            "{label}: every accepted pending demand must reach a grant"
        );
        assert!(
            granted_count(trace) > 0,
            "{label}: an empty trace would satisfy every inequality vacuously"
        );
        assert_eq!(
            trace.events.len(),
            accepted * 2 + refused,
            "{label}: the ordered trace must contain exactly one acceptance and \
             one grant per accepted demand, plus one refusal per refusal, and \
             nothing else"
        );
    }

    #[test]
    fn construction_a_against_live_provider_does_not_amplify() {
        // Only the demand-to-child mapping differs between the two runs.
        let baseline = run_live_construction_a(&[0, 0, 0], false);
        let subdivided = run_live_construction_a(&[0, 1, 2], false);

        // Under root keying each root holds one turn at a time, so of six
        // offers two are accepted and four are refused, in both mappings.
        assert_trace_shape(&baseline, 4, 2, "production baseline");
        assert_trace_shape(&subdivided, 4, 2, "production subdivided");

        // Exact ordered dispositions, with logical ids bound at issue time
        // rather than reconstructed. Counts and grant order alone would let the
        // six offer dispositions be reordered undetected, so the whole sequence
        // is pinned. Root A is created before root B, so A holds the earlier
        // turn key and is served first; offers alternate A, B, A, B, A, B, and
        // every offer after the first on each root is refused because that root
        // already holds its single turn.
        let expected = vec![
            sig("accepted", 100, 0),
            sig("accepted", 200, 1),
            sig("refused", 101, 0),
            sig("refused", 201, 1),
            sig("refused", 102, 0),
            sig("refused", 202, 1),
            sig("granted", 100, 0),
            sig("granted", 200, 1),
        ];
        assert_eq!(
            event_signatures(&baseline),
            expected,
            "production baseline: one turn per root, A before B"
        );
        assert_eq!(
            event_signatures(&subdivided),
            expected,
            "subdividing A across children changes no disposition, in kind, \
             order, or which demand it concerned"
        );
        assert_all_requested_claims_are(&baseline, unit_claim(), "production baseline");
        assert_all_requested_claims_are(&subdivided, unit_claim(), "production subdivided");
        for trace in [&baseline, &subdivided] {
            let roots: BTreeSet<usize> = trace
                .events
                .iter()
                .filter_map(|event| match event {
                    LiveEvent::Granted { root, .. } | LiveEvent::ImmediateGrant { root, .. } => {
                        Some(*root)
                    }
                    _ => None,
                })
                .collect();
            assert_eq!(
                roots,
                BTreeSet::from([0, 1]),
                "both roots must appear, or the comparison has no competitor"
            );
        }

        if let Err(reason) =
            evaluate_live_non_amplification(&baseline, &subdivided, &[1], &[200, 201, 202])
        {
            panic!("root-keyed production selection must not amplify: {reason}");
        }
    }

    #[test]
    fn live_oracle_rejects_scope_keyed_selection() {
        // The same live provider, the same workload, the same oracle — with
        // production selection reverted to the superseded scope-keyed rule.
        // If this ever passes, the positive control above is vacuous.
        let baseline = run_live_construction_a(&[0, 0, 0], true);
        let subdivided = run_live_construction_a(&[0, 1, 2], true);

        // Under scope keying the turn belongs to each child. The baseline maps
        // all three A demands to one child, so A still accepts one; the
        // subdivided run spreads them and A accepts three. That 4-vs-6 shape is
        // the amplification the oracle must reject.
        assert_trace_shape(&baseline, 2, 4, "scope-keyed baseline");
        assert_trace_shape(&subdivided, 0, 6, "scope-keyed subdivided");

        // Exact ordered dispositions, not merely grant order. Turn keys are
        // (root, scope order) here, and the pre-created children were minted
        // A0, A1, A2 then B0, B1, B2, so the cursor walks A's children before
        // reaching B's. Offers alternate A, B, A, B, A, B.
        //
        // Baseline maps all three A demands to A0, so the second and third are
        // refused for that scope's turn while each distinct B child accepts.
        assert_eq!(
            event_signatures(&baseline),
            vec![
                sig("accepted", 100, 0),
                sig("accepted", 200, 1),
                sig("refused", 101, 0),
                sig("accepted", 201, 1),
                sig("refused", 102, 0),
                sig("accepted", 202, 1),
                sig("granted", 100, 0),
                sig("granted", 200, 1),
                sig("granted", 201, 1),
                sig("granted", 202, 1),
            ],
            "scope-keyed baseline: A holds one scope turn, each B child its own"
        );
        // Subdivided spreads A across three children, so every offer is
        // accepted and A takes three consecutive grants before B is served.
        assert_eq!(
            event_signatures(&subdivided),
            vec![
                sig("accepted", 100, 0),
                sig("accepted", 200, 1),
                sig("accepted", 101, 0),
                sig("accepted", 201, 1),
                sig("accepted", 102, 0),
                sig("accepted", 202, 1),
                sig("granted", 100, 0),
                sig("granted", 101, 0),
                sig("granted", 102, 0),
                sig("granted", 200, 1),
                sig("granted", 201, 1),
                sig("granted", 202, 1),
            ],
            "scope-keyed subdivided: subdivision buys A three consecutive turns \
             ahead of the competitor — the amplification the oracle must reject"
        );
        assert_all_requested_claims_are(&baseline, unit_claim(), "scope-keyed baseline");
        assert_all_requested_claims_are(&subdivided, unit_claim(), "scope-keyed subdivided");

        let verdict =
            evaluate_live_non_amplification(&baseline, &subdivided, &[1], &[200, 201, 202]);
        assert!(
            verdict.is_err(),
            "scope-keyed selection must fail the live oracle: subdividing root A \
             across pre-created child scopes obtains extra turns and delays the \
             competing root"
        );
    }

    #[test]
    fn extra_child_scopes_beneath_one_root_add_no_turn() {
        // Same live provider, same roots, more children beneath A. Root keying
        // must yield A exactly the same number of selections.
        let one_child = run_live_construction_a(&[0, 0, 0], false);
        let three_children = run_live_construction_a(&[0, 1, 2], false);
        assert_trace_shape(&one_child, 4, 2, "one child");
        assert_trace_shape(&three_children, 4, 2, "three children");
        let selections_with_one =
            live_cumulative_selections(&one_child.events, 0, one_child.events.len());
        let selections_with_three =
            live_cumulative_selections(&three_children.events, 0, three_children.events.len());
        assert_eq!(
            selections_with_one, selections_with_three,
            "extra child scopes create no additional turns"
        );
    }

    #[test]
    fn trusted_root_scopes_are_distinct_and_children_inherit() {
        let grant = claim(&[
            (ResourceClass::QueuedBytes, 4),
            (ResourceClass::OpaqueDependencyResidual, 12),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider).expect("process bookkeeping");
        let first_root = port
            .create_fairness_root_scope()
            .expect("one trusted extra root");
        let second_root = port
            .create_fairness_root_scope()
            .expect("another trusted extra root");
        assert_ne!(first_root.id(), second_root.id());
        assert_eq!(
            first_root.parent_id(),
            None,
            "a trusted root scope has no parent to inherit attribution from"
        );

        // An ordinary child still takes no root argument and inherits.
        let child = port.create_scope(&first_root).expect("ordinary child");
        assert_eq!(child.parent_id(), Some(first_root.id()));
    }

    /// One reclaimable victim on a named root, with its subscription and lease.
    struct VictimRoot {
        scope: ResourceScope,
        subscription: ResourceReclaimSubscription,
        /// Held solely to keep the victim's reservation alive for the test's
        /// duration. Never read, and named with a leading underscore so that
        /// intent is explicit and no `dead_code` allow is needed.
        _lease: ResourceLease,
    }

    /// A requester root plus `competitors` other roots, each holding exactly
    /// one reclaimable speculative unit.
    ///
    /// A struct rather than a tuple so no `clippy::type_complexity` allow is
    /// needed and each victim stays individually addressable.
    struct VictimFixture {
        provider: DeterministicGrantProvider,
        port: ResourceProviderPort,
        own: VictimRoot,
        others: Vec<VictimRoot>,
    }

    fn victim_fixture(competitors: usize) -> VictimFixture {
        victim_fixture_around_requester(0, competitors)
    }

    /// As above, but with `before` competing roots created **before** the
    /// requester's root and `after` created after it.
    ///
    /// Creation order fixes root order, and root order is what the reclaim sort
    /// compares. A requester at the lowest root order is a degenerate case: once
    /// any cursor is set, `victim_root <= cursor` already sorts the requester
    /// last, so the dedicated own-root component of the sort key becomes
    /// unobservable. Placing competitors on both sides of the requester is what
    /// makes that component load-bearing.
    ///
    /// `others` is ordered earliest-created first, so indices `0..before` are
    /// the roots preceding the requester and the rest follow it.
    fn victim_fixture_around_requester(before: usize, after: usize) -> VictimFixture {
        let competitors = before + after;
        let roots = competitors + 1;
        let grant = claim(&[
            (ResourceClass::QueuedBytes, roots as u64),
            (ResourceClass::OpaqueDependencyResidual, 1024),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).expect("process bookkeeping");
        let one = ResourceClaim::single(ResourceClass::QueuedBytes, 1);

        let new_competitor = |port: &ResourceProviderPort| {
            let scope = port.create_fairness_root_scope().expect("competing root");
            let (target, subscription) = ResourceReclaimSubscription::channel();
            let lease = port
                .acquire_reclaimable_now(&scope, one, target)
                .expect("competing reclaimable unit");
            VictimRoot {
                scope,
                subscription,
                _lease: lease,
            }
        };

        // Competing roots created before the requester.
        let mut others: Vec<VictimRoot> = (0..before).map(|_| new_competitor(&port)).collect();

        // The requester's own root. With `before == 0` it holds the lowest root
        // order, so own-root-last ordering must beat plain root order rather
        // than coincide with it. With `before > 0` it sits mid-order, which is
        // what makes the own-root sort component observable once a cursor has
        // advanced past the earlier competitors.
        let own_scope = port.create_fairness_root_scope().expect("requester root");
        let (own_target, own_subscription) = ResourceReclaimSubscription::channel();
        let own_lease = port
            .acquire_reclaimable_now(&own_scope, one, own_target)
            .expect("own-root reclaimable unit");
        let own = VictimRoot {
            scope: own_scope,
            subscription: own_subscription,
            _lease: own_lease,
        };

        // Competing roots created after the requester.
        others.extend((0..after).map(|_| new_competitor(&port)));

        VictimFixture {
            provider,
            port,
            own,
            others,
        }
    }

    /// The kind name of one recorded provider disposition.
    fn decision_kind(decision: &ProviderDecision) -> &'static str {
        match decision {
            ProviderDecision::PendingAccepted { .. } => "accepted",
            ProviderDecision::PendingRefused { .. } => "refused",
            ProviderDecision::ImmediateGrant { .. } => "immediate",
            ProviderDecision::ArbitrationGrant { .. } => "granted",
            ProviderDecision::TerminalPressure { .. } => "pressured",
            ProviderDecision::Cancelled { .. } => "cancelled",
        }
    }

    /// Bind a before/after pair to "nothing changed except reclaim bookkeeping".
    ///
    /// Everything a cancellation could plausibly leak is compared exactly: full
    /// scope survivor equality, both free sets, both allocator frontiers,
    /// `in_use`, the demand cursors, and the active demand. Reservations must
    /// keep their ids, owning scopes, authorities and claims; only a
    /// `Live -> ReclaimRequested` lifecycle transition is permitted, since that
    /// is the intentional effect of the reclaim request. `reclaim_cursor` is
    /// checked against the caller's exact expectation rather than ignored.
    ///
    /// The decision trace is append-only, so it is not compared for equality:
    /// the pre-existing prefix must be byte-equal and the appended suffix must
    /// be exactly `expected_new_decisions`, which may legitimately contain an
    /// acceptance and its cancellation but never a grant of any kind.
    fn assert_no_mutation_except_reclaim(
        before: &FiniteProviderSnapshot,
        after: &FiniteProviderSnapshot,
        expected_reclaim_cursor: Option<u64>,
        expected_new_decisions: &[&str],
        label: &str,
    ) {
        assert_eq!(
            after.scopes, before.scopes,
            "{label}: scope topology changed"
        );
        assert_eq!(
            after.free_scope_orders, before.free_scope_orders,
            "{label}: free scope orders changed"
        );
        assert_eq!(
            after.free_reservation_ids, before.free_reservation_ids,
            "{label}: free reservation ids changed"
        );
        assert_eq!(
            after.next_scope_order, before.next_scope_order,
            "{label}: scope-order frontier advanced"
        );
        assert_eq!(
            after.next_reservation_id, before.next_reservation_id,
            "{label}: reservation-id frontier advanced"
        );
        assert_eq!(after.in_use, before.in_use, "{label}: in_use changed");
        assert_eq!(
            after.retained_after_failed_cleanup, before.retained_after_failed_cleanup,
            "{label}: retention changed"
        );
        assert_eq!(after.poisoned, before.poisoned, "{label}: poison changed");
        assert_eq!(
            after.demand_cursor, before.demand_cursor,
            "{label}: a rotation cursor advanced"
        );
        assert_eq!(
            after.active_demand, before.active_demand,
            "{label}: an active demand was left selected"
        );
        // The decision trace is append-only, so equality is the wrong test: a
        // demand that is accepted and later cancelled legitimately appends
        // those dispositions. What must hold is that the pre-existing prefix is
        // byte-equal and the appended suffix is exactly the expected sequence —
        // in particular containing no grant of any kind, which is what "no
        // unintended selection" actually means here.
        assert!(
            after.decision_log.len() >= before.decision_log.len(),
            "{label}: the decision trace is append-only and cannot shrink"
        );
        assert_eq!(
            &after.decision_log[..before.decision_log.len()],
            &before.decision_log[..],
            "{label}: an existing decision-trace entry was rewritten"
        );
        let appended: Vec<&'static str> = after.decision_log[before.decision_log.len()..]
            .iter()
            .map(decision_kind)
            .collect();
        assert_eq!(
            appended, expected_new_decisions,
            "{label}: appended dispositions are not the expected sequence"
        );
        assert!(
            !appended.contains(&"granted") && !appended.contains(&"immediate"),
            "{label}: no grant of any kind may be recorded here"
        );

        assert_eq!(
            after.reservations.len(),
            before.reservations.len(),
            "{label}: a reservation was created or destroyed"
        );
        let mut reclaim_transitions = 0usize;
        for (old, new) in before.reservations.iter().zip(after.reservations.iter()) {
            assert_eq!(new.0, old.0, "{label}: reservation id changed");
            assert_eq!(new.1, old.1, "{label}: reservation owner changed");
            assert_eq!(new.2, old.2, "{label}: reservation authority changed");
            assert_eq!(new.3, old.3, "{label}: reservation claim changed");
            if new.4 != old.4 {
                // Qualified through the private `finite` module rather than
                // re-exported: `ReservationLifecycle` is `pub(crate)` inside it,
                // and `tests` is a child of this module, so the path resolves
                // without widening any internal surface.
                assert_eq!(
                    (old.4, new.4),
                    (
                        super::finite::ReservationLifecycle::Live,
                        super::finite::ReservationLifecycle::ReclaimRequested
                    ),
                    "{label}: the only permitted lifecycle change is Live -> ReclaimRequested"
                );
                reclaim_transitions += 1;
            }
        }
        // Both fixtures create a one-unit deficit and therefore claim exactly
        // one victim. Asserting the count binds the intentional delta rather
        // than merely tolerating whatever transitions happen to occur: zero
        // would mean no victim was notified at all, and more than one would
        // mean the provider swept in reservations the deficit did not require.
        assert_eq!(
            reclaim_transitions, 1,
            "{label}: exactly one reservation should transition to ReclaimRequested"
        );

        assert_eq!(
            after.reclaim_cursor, expected_reclaim_cursor,
            "{label}: reclaim cursor is not where the selected victim's root puts it"
        );
    }

    /// Which competitor subscriptions have been notified, in fixture order.
    fn notified_competitors(fixture: &VictimFixture) -> Vec<bool> {
        fixture
            .others
            .iter()
            .map(|other| other.subscription.is_requested())
            .collect()
    }

    /// Every `ProviderDecision` variant, paired with the exact path that
    /// produces it and the control that exercises that path.
    ///
    /// This is the completeness table for the trace's stated scope. If a
    /// variant is added without a producing path, or a producing path is
    /// removed, this list is where the mismatch should be caught rather than
    /// discovered as a silent hole in a control.
    ///
    /// Scope is unchanged: cooperative admission on the non-failing path, plus
    /// owner cancellation. Fail-closed invariant cancellation inside
    /// `arbitrate` and teardown cancellation in `release_scope` remain
    /// deliberately untraced, as does every non-cooperative path.
    #[test]
    fn every_decision_variant_has_a_producing_path() {
        // (variant kind, producing path, exercising control)
        let table: [(&str, &str, &str); 6] = [
            (
                "accepted",
                "acquire_cooperatively / create_scope_and_acquire_cooperatively, \
                 when the claim does not fit immediately",
                "construction_a_against_live_provider_does_not_amplify",
            ),
            (
                "refused",
                "the same two calls, when the demand's root already holds a turn",
                "one_pending_demand_per_root_not_per_scope",
            ),
            (
                "immediate",
                "the same two calls, when the claim fits without arbitration",
                // Deliberately *not* the P4-surplus control: that one admits
                // through `acquire`, which is non-cooperative and therefore
                // untraced, so naming it here would point at a path that
                // produces no `ImmediateGrant` at all.
                "reservation_id_failure_rolls_back_exactly_on_cooperative_immediate_creation",
            ),
            (
                "granted",
                "arbitrate, when a selected pending demand is admitted",
                "construction_a_against_live_provider_does_not_amplify",
            ),
            (
                "pressured",
                "arbitrate, when the selected demand cannot be covered",
                "insufficient_reclaim_set_is_not_published",
            ),
            (
                "cancelled",
                "cancel_demand, both the Waiting branch and the Granted branch \
                 that unwinds an uncollected grant",
                "cancelling_a_granted_existing_scope_demand_records_grant_then_cancellation",
            ),
        ];

        // Each kind appears exactly once, and the set is exactly the set
        // `decision_kind` can return.
        let kinds: BTreeSet<&str> = table.iter().map(|(kind, _, _)| *kind).collect();
        assert_eq!(
            kinds.len(),
            table.len(),
            "each decision kind is listed exactly once"
        );
        assert_eq!(
            kinds,
            BTreeSet::from([
                "accepted",
                "refused",
                "immediate",
                "granted",
                "pressured",
                "cancelled",
            ]),
            "the table must cover exactly the kinds `decision_kind` produces; a \
             new variant without a producing path is a hole in the trace"
        );
        for (kind, path, control) in &table {
            assert!(
                !path.is_empty() && !control.is_empty(),
                "{kind}: every variant needs a named producing path and control"
            );
        }
    }

    /// Assert the decision trace is append-only across a before/after pair.
    ///
    /// Slicing from `before.decision_log.len()` alone would let a provider that
    /// rewrote earlier events pass on the strength of a correct suffix, so the
    /// retained prefix is compared byte-for-byte first.
    fn assert_trace_prefix_intact(before: &FiniteProviderSnapshot, after: &FiniteProviderSnapshot) {
        assert!(
            after.decision_log.len() >= before.decision_log.len(),
            "the decision trace is append-only and never shrinks"
        );
        assert_eq!(
            after.decision_log[..before.decision_log.len()],
            before.decision_log[..],
            "the pre-existing decision-log prefix was rewritten"
        );
    }

    /// The `(kind, demand_key)` pairs appended after `before_len`, in order.
    fn appended_with_keys(
        before_len: usize,
        after: &FiniteProviderSnapshot,
    ) -> Vec<(&'static str, usize)> {
        after.decision_log[before_len..]
            .iter()
            .map(|decision| {
                let key = match *decision {
                    ProviderDecision::PendingAccepted { demand_key, .. }
                    | ProviderDecision::ArbitrationGrant { demand_key, .. }
                    | ProviderDecision::TerminalPressure { demand_key, .. }
                    | ProviderDecision::Cancelled { demand_key, .. } => demand_key,
                    ProviderDecision::PendingRefused { .. }
                    | ProviderDecision::ImmediateGrant { .. } => 0,
                };
                (decision_kind(decision), key)
            })
            .collect()
    }

    #[test]
    fn cancelling_a_granted_existing_scope_demand_records_grant_then_cancellation() {
        // A demand granted by arbitration whose owner drops the handle before
        // collecting the lease, with a second demand on another root staged
        // beforehand so re-arbitration has somewhere to go. That second grant
        // is what proves arbitration resumed *after* the corrected decision
        // index rather than before it.
        let grant = claim(&[
            (ResourceClass::QueuedBytes, 1),
            (ResourceClass::OpaqueDependencyResidual, 512),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).expect("process bookkeeping");
        let holder = port.create_fairness_root_scope().expect("holder root");
        let first_root = port
            .create_fairness_root_scope()
            .expect("first requester root");
        let later_root = port
            .create_fairness_root_scope()
            .expect("later requester root");
        let one = ResourceClaim::single(ResourceClass::QueuedBytes, 1);

        let (holder_target, _holder_subscription) = ResourceReclaimSubscription::channel();
        let holder_lease = port
            .acquire_reclaimable_now(&holder, one, holder_target)
            .expect("holder owns the only unit");

        // Both demands are Speculative with live reclaim targets so each can
        // legitimately pend: the later demand's deficit is coverable by the
        // first demand's reclaimable grant, which is what keeps it pending
        // rather than resolving to terminal pressure.
        let (first_target, _first_subscription) = ResourceReclaimSubscription::channel();
        let first = pending(
            port.acquire_cooperatively(
                &first_root,
                ResourceAuthorityClass::Speculative,
                one,
                Some(first_target),
            )
            .expect("first turn"),
        );
        let first_key = first.demand_key_for_test();
        let (later_target, _later_subscription) = ResourceReclaimSubscription::channel();
        let later = pending(
            port.acquire_cooperatively(
                &later_root,
                ResourceAuthorityClass::Speculative,
                one,
                Some(later_target),
            )
            .expect("later turn, staged before the first is granted"),
        );
        let later_key = later.demand_key_for_test();

        let before = provider.transactional_snapshot_for_test();
        let before_len = before.decision_log.len();

        // Releasing the holder lets arbitration grant the first demand. Its
        // owner never retries, so that lease is never collected.
        drop(holder_lease);
        let granted = provider.transactional_snapshot_for_test();
        assert_trace_prefix_intact(&before, &granted);
        assert_eq!(
            appended_with_keys(before_len, &granted),
            vec![("granted", first_key)],
            "arbitration grants the first demand and records it"
        );

        // Bind the granted reservation exactly, so the rollback can be checked
        // against it rather than against counts. Bound by owner rather than by
        // id-absence from `before`: releasing the holder
        // returns its reservation id, and the grant's allocator reuses the
        // smallest free id, so the granted reservation can legitimately carry
        // an id that already appears in `before`.
        let owned_by_first = granted
            .reservations
            .iter()
            .filter(|(_, owner, _, _, _)| *owner == first_root.id())
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(
            owned_by_first.len(),
            1,
            "the grant installed exactly one reservation for the first requester"
        );
        let granted_record = owned_by_first[0];
        let (granted_id, granted_owner, granted_authority, granted_claim, _) = granted_record;

        // Cancel the uncollected grant.
        drop(first);
        let after = provider.transactional_snapshot_for_test();

        // Global order: grant, then cancellation, then the later grant.
        assert_trace_prefix_intact(&granted, &after);
        assert_eq!(
            appended_with_keys(before_len, &after),
            vec![
                ("granted", first_key),
                ("cancelled", first_key),
                ("granted", later_key),
            ],
            "the cancellation is recorded before re-arbitration's grant, so the \
             later grant follows it in the trace"
        );
        // Restricted to the first demand key, the appended trace is exactly
        // its grant and its cancellation, with nothing else attributed to it.
        assert_eq!(
            appended_with_keys(before_len, &after)
                .into_iter()
                .filter(|(_, key)| *key == first_key)
                .map(|(kind, _)| kind)
                .collect::<Vec<_>>(),
            vec!["granted", "cancelled"],
            "the first demand contributes exactly one grant and one cancellation"
        );
        assert_eq!(after.poisoned, None);

        // Exact rollback of the first grant, against the granted snapshot.
        assert_eq!(
            granted_owner,
            first_root.id(),
            "the cancelled reservation was owned by the first requester"
        );
        assert!(
            !after
                .reservations
                .iter()
                .any(|(_, owner, _, _, _)| *owner == first_root.id()),
            "the first requester's reservation record is gone"
        );
        // The exact record — id, owner, authority, claim and lifecycle — is
        // absent, so the lifecycle field is carried into the check rather than
        // pinned to a value. By this point arbitration may already have marked
        // it `ReclaimRequested` on the later demand's behalf.
        assert!(
            !after.reservations.contains(&granted_record),
            "the exact granted reservation record is removed, not rewritten"
        );

        // The cancellation returns the id, then re-arbitration immediately
        // reallocates from the same free set, so the id does not stay free.
        // Bind that exact return-and-reallocate rather than asserting it
        // remains available: the allocator reuses the smallest free id.
        let mut freed: Vec<u64> = granted.free_reservation_ids.clone();
        assert!(
            !freed.contains(&granted_id),
            "the cancelled id was in use at the granted state"
        );
        freed.push(granted_id);
        freed.sort_unstable();
        let reused = freed[0];
        let later_reservation = after
            .reservations
            .iter()
            .find(|(_, owner, _, _, _)| *owner == later_root.id())
            .copied()
            .expect("re-arbitration installed the later owner's reservation");
        let (later_id, _, later_authority, later_claim, _) = later_reservation;
        assert_eq!(
            later_id, reused,
            "the later grant takes the deterministically reused id, evidencing \
             that the cancelled id was returned before re-arbitration"
        );
        assert_eq!(
            after.free_reservation_ids,
            freed[1..].to_vec(),
            "the free set is exactly the granted set plus the returned id, \
             minus the one re-arbitration consumed"
        );
        assert_eq!(
            after.reservations.len(),
            granted.reservations.len(),
            "one reservation out, one in: no duplicate and no leak"
        );
        assert_eq!(
            after.next_reservation_id, granted.next_reservation_id,
            "cancellation and the reuse mint no reservation id: the frontier \
             is untouched"
        );
        assert_eq!(
            after.next_scope_order, granted.next_scope_order,
            "an existing-scope cancellation mints no scope order"
        );
        assert_eq!(
            after.free_scope_orders, granted.free_scope_orders,
            "an existing-scope cancellation frees no scope order"
        );
        assert_eq!(
            after.scopes.iter().map(|(id, ..)| *id).collect::<Vec<_>>(),
            granted
                .scopes
                .iter()
                .map(|(id, ..)| *id)
                .collect::<Vec<_>>(),
            "an existing-scope cancellation changes no topology"
        );

        // Charge arithmetic across every dimension, stated as the explicit
        // whole-claim equation rather than inferred from equal inputs: the
        // cancelled reservation's charge comes off and the later grant's goes
        // on. Both are existing-scope grants, so neither carries a scope
        // bookkeeping charge.
        let first_charge = FiniteResourceProvider::reservation_charge_for_test(granted_claim)
            .expect("the cancelled grant's charge is representable");
        let later_charge = FiniteResourceProvider::reservation_charge_for_test(later_claim)
            .expect("the later grant's charge is representable");
        let expected_in_use = granted
            .in_use
            .checked_sub(first_charge)
            .expect("the cancelled charge was in use at the granted state")
            .checked_add(later_charge)
            .expect("the later charge is representable");
        assert_eq!(
            after.in_use, expected_in_use,
            "in_use is exactly granted - reservation_charge(first) + \
             reservation_charge(later), in every dimension: the cancelled \
             charge is restored exactly once"
        );
        assert_eq!(
            after.retained_after_failed_cleanup, granted.retained_after_failed_cleanup,
            "a cancellation is not a failed cleanup, so nothing is retained"
        );
        assert_eq!(
            (granted_authority, later_authority),
            (
                ResourceAuthorityClass::Speculative,
                ResourceAuthorityClass::Speculative
            ),
            "both grants are Speculative, so the equation above compares like \
             charges rather than hiding an authority-class difference"
        );
        assert!(
            after
                .scopes
                .iter()
                .all(|(_, _, _, pending)| pending.is_none()),
            "no pending demand survives"
        );
        assert_eq!(after.active_demand, None, "no turn is outstanding");

        // Collecting proves re-arbitration produced a real, usable lease from
        // the corrected index rather than merely logging a grant.
        let later_lease = acquired(later.retry().expect("the later demand collects its lease"));
        assert_eq!(
            later_lease.claim(),
            granted_claim,
            "the later demand takes the exact claim the cancelled grant released"
        );
        drop(later_lease);
    }

    #[test]
    fn cancelling_a_granted_new_child_demand_retires_the_child_exactly_once() {
        let grant = claim(&[
            (ResourceClass::SocketOrHandle, 1),
            (ResourceClass::OpaqueDependencyResidual, 512),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).expect("process bookkeeping");
        let process = port.process_scope();
        let socket = ResourceClaim::single(ResourceClass::SocketOrHandle, 1);

        let (blocker_target, _blocker_subscription) = ResourceReclaimSubscription::channel();
        let blocker = acquired(
            port.create_scope_with_reclaimable_lease_cooperatively(
                &process,
                socket,
                blocker_target,
            )
            .expect("blocker holds the only socket"),
        );
        let (demand_target, _demand_subscription) = ResourceReclaimSubscription::channel();
        let demand = pending(
            port.create_scope_with_reclaimable_lease_cooperatively(&process, socket, demand_target)
                .expect("a pending new-child demand"),
        );

        let demand_key = demand.demand_key_for_test();

        let before = provider.transactional_snapshot_for_test();
        let before_len = before.decision_log.len();
        drop(blocker);
        let granted = provider.transactional_snapshot_for_test();
        assert_trace_prefix_intact(&before, &granted);
        assert_eq!(
            appended_with_keys(before_len, &granted),
            vec![("granted", demand_key)],
            "arbitration grants the new-child demand"
        );

        // Derive the exact records the atomic child path created, so the
        // rollback is checked against those identities rather than counts.
        // Bound by identity, not by delta against `before`: the blocker's
        // release returns both its scope order and its reservation id, and
        // both allocators reuse the smallest free token, so the created child
        // can legitimately carry tokens that already appear in `before` (and
        // even a recycled `ResourceScopeId`, whose value derives from an
        // allocation address). At the granted state the blocker is gone, so
        // the child is the unique non-process scope.
        let process_id = process.id();
        let children = granted
            .scopes
            .iter()
            .filter(|(id, ..)| *id != process_id)
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(
            children.len(),
            1,
            "the blocker is released, so the granted child is the only non-process scope"
        );
        let (created_id, created_root, created_order, _) = children[0];
        let owned_by_child = granted
            .reservations
            .iter()
            .filter(|(_, owner, ..)| *owner == created_id)
            .copied()
            .collect::<Vec<_>>();
        assert_eq!(
            owned_by_child.len(),
            1,
            "the atomic child path installed exactly one reservation on the child"
        );
        assert_eq!(
            granted.reservations.len(),
            1,
            "no other reservation survives, so the delta below is unambiguous"
        );
        let (created_reservation_id, _, _, created_claim, _) = owned_by_child[0];

        // The owner never collects, then drops. Nothing else is pending, so
        // re-arbitration produces no further grant and the post-cancel state
        // must be exactly the granted state minus the child it created.
        drop(demand);
        let after = provider.transactional_snapshot_for_test();
        assert_trace_prefix_intact(&granted, &after);
        assert_eq!(
            appended_with_keys(before_len, &after),
            vec![("granted", demand_key), ("cancelled", demand_key)],
            "grant then exactly one cancellation, both attributed to this demand"
        );
        assert_eq!(after.poisoned, None);

        // Whole-vector deltas: exactly the created child and its reservation
        // are gone, and nothing else moved.
        assert_eq!(
            after.scopes,
            granted
                .scopes
                .iter()
                .copied()
                .filter(|(id, ..)| *id != created_id)
                .collect::<Vec<_>>(),
            "the scope table is the granted table minus exactly the created child"
        );
        assert_eq!(
            after.reservations,
            granted
                .reservations
                .iter()
                .copied()
                .filter(|(id, ..)| *id != created_reservation_id)
                .collect::<Vec<_>>(),
            "the reservation table is the granted table minus exactly its reservation"
        );

        // Allocator bookkeeping: both tokens are returned exactly once, and
        // neither frontier moves.
        let mut expected_free_orders = granted.free_scope_orders.clone();
        assert!(
            !expected_free_orders.contains(&created_order),
            "the created order was in use at the granted state"
        );
        expected_free_orders.push(created_order);
        expected_free_orders.sort_unstable();
        assert_eq!(
            after.free_scope_orders, expected_free_orders,
            "exactly the created scope order is returned, once"
        );
        let mut expected_free_ids = granted.free_reservation_ids.clone();
        assert!(
            !expected_free_ids.contains(&created_reservation_id),
            "the created reservation id was in use at the granted state"
        );
        expected_free_ids.push(created_reservation_id);
        expected_free_ids.sort_unstable();
        assert_eq!(
            after.free_reservation_ids, expected_free_ids,
            "exactly the created reservation id is returned, once"
        );
        assert_eq!(
            (after.next_scope_order, after.next_reservation_id),
            (granted.next_scope_order, granted.next_reservation_id),
            "cancellation returns tokens rather than minting, so both frontiers hold"
        );

        // Charge: the child's bookkeeping and its reservation are both undone,
        // returning the pre-grant total in every dimension.
        let child_total =
            FiniteResourceProvider::child_scope_with_reservation_charge_for_test(created_claim)
                .expect("the child's combined charge is representable");
        let expected_in_use = granted
            .in_use
            .checked_sub(child_total)
            .expect("the child's combined charge was in use at the granted state");
        assert_eq!(
            after.in_use, expected_in_use,
            "in_use subtracts exactly the child scope bookkeeping plus the \
             reservation charge, once, in every dimension"
        );
        // Deliberately not compared against `before`: that snapshot was taken
        // while the blocker's child and reservation were still live, so it
        // carries the blocker's combined charge and its scope record. The
        // granted snapshot is the only correct baseline for this rollback.
        assert_eq!(
            after.retained_after_failed_cleanup, granted.retained_after_failed_cleanup,
            "a cancellation is not a failed cleanup, so nothing is retained"
        );
        assert!(
            after
                .scopes
                .iter()
                .all(|(_, _, _, pending)| pending.is_none()),
            "no pending demand survives the cancellation"
        );
        assert_eq!(after.active_demand, None, "no turn is outstanding");

        // The parent root stays live, so nothing justifies a cursor move.
        let parent_root = after
            .scopes
            .iter()
            .find(|(id, ..)| *id == process_id)
            .map(|(_, root, ..)| *root)
            .expect("the process scope outlives the child");
        assert_eq!(
            created_root, parent_root,
            "the retired child belonged to the still-live process root"
        );
        assert_eq!(
            (&after.demand_cursor, after.reclaim_cursor),
            (&granted.demand_cursor, granted.reclaim_cursor),
            "retiring a child of a still-live root moves no cursor"
        );
    }

    #[test]
    fn reclaim_prefers_another_root_before_the_requesters_own_from_an_existing_scope() {
        let fixture = victim_fixture(1);
        let one = ResourceClaim::single(ResourceClass::QueuedBytes, 1);

        // One unit of deficit: exactly one victim is needed, so ordering is
        // observable rather than incidental.
        let turn = pending(
            fixture
                .port
                .acquire_cooperatively(
                    &fixture.own.scope,
                    ResourceAuthorityClass::Admitted,
                    one,
                    None,
                )
                .expect("a turn that needs one reclaimed unit"),
        );
        assert_eq!(
            notified_competitors(&fixture),
            vec![true],
            "the competing root's reservation is victimized first"
        );
        assert!(
            !fixture.own.subscription.is_requested(),
            "the requester's own root is victimized last, even though it holds \
             the lowest root order"
        );
        drop(turn);
    }

    #[test]
    fn a_prospective_child_cannot_route_around_own_root_victim_ordering() {
        // The same request as a NewChild demand. The prospective child is not
        // in the scope map yet, so a provider resolving the requester root from
        // the lease scope would find `None`, lose the own-root-last ordering,
        // and become willing to victimize the requester's own root first.
        let fixture = victim_fixture(1);
        let one = ResourceClaim::single(ResourceClass::QueuedBytes, 1);

        let (child_target, _child_subscription) = ResourceReclaimSubscription::channel();
        let turn = pending(
            fixture
                .port
                .create_scope_with_reclaimable_lease_cooperatively(
                    &fixture.own.scope,
                    one,
                    child_target,
                )
                .expect("a new-child turn that needs one reclaimed unit"),
        );
        assert_eq!(
            notified_competitors(&fixture),
            vec![true],
            "a new-child demand victimizes the competing root first, exactly as \
             an existing-scope demand does"
        );
        assert!(
            !fixture.own.subscription.is_requested(),
            "demanding through an uncommitted child must not route around the \
             own-root-last ordering"
        );
        drop(turn);
    }

    #[test]
    fn reclaim_notifies_the_exact_victim_owner_only() {
        let fixture = victim_fixture(2);
        let one = ResourceClaim::single(ResourceClass::QueuedBytes, 1);
        let before = fixture.provider.transactional_snapshot_for_test();

        let turn = pending(
            fixture
                .port
                .acquire_cooperatively(
                    &fixture.own.scope,
                    ResourceAuthorityClass::Admitted,
                    one,
                    None,
                )
                .expect("a turn that needs one reclaimed unit"),
        );

        // Exactly one competitor is notified — the second competitor is not
        // swept in — and the requester's own root is untouched.
        assert_eq!(
            notified_competitors(&fixture),
            vec![true, false],
            "only the single victim needed to cover the deficit is notified"
        );
        assert!(!fixture.own.subscription.is_requested());

        // While the turn is outstanding the provider legitimately holds a
        // pending record and may hold an active demand, so the strong
        // no-residual comparison cannot be made here. Capture only the reclaim
        // cursor that victim selection set.
        let during = fixture.provider.transactional_snapshot_for_test();
        assert!(
            during.reclaim_cursor.is_some(),
            "selecting a victim records its root as the reclaim cursor"
        );
        assert_eq!(
            during
                .scopes
                .iter()
                .filter(|(_, _, _, pending)| pending.is_some())
                .count(),
            1,
            "exactly one scope holds the outstanding turn"
        );

        // Retire the turn, then assert that nothing but the reclaim survives:
        // the appended dispositions are exactly the acceptance and its
        // cancellation, with no grant of any kind, and the victim's lifecycle
        // transition is the only other difference.
        drop(turn);
        let after = fixture.provider.transactional_snapshot_for_test();
        assert_no_mutation_except_reclaim(
            &before,
            &after,
            during.reclaim_cursor,
            &["accepted", "cancelled"],
            "reclaim request then cancellation",
        );
    }

    #[test]
    fn cancelling_a_new_child_turn_after_reclaim_leaves_only_the_victim_delta() {
        let fixture = victim_fixture(1);
        let one = ResourceClaim::single(ResourceClass::QueuedBytes, 1);
        let before = fixture.provider.transactional_snapshot_for_test();

        let (child_target, _child_subscription) = ResourceReclaimSubscription::channel();
        let turn = pending(
            fixture
                .port
                .create_scope_with_reclaimable_lease_cooperatively(
                    &fixture.own.scope,
                    one,
                    child_target,
                )
                .expect("a new-child turn"),
        );
        assert_eq!(notified_competitors(&fixture), vec![true]);
        let after_request = fixture.provider.transactional_snapshot_for_test();

        // Cancelling must undo everything the demand introduced. The only
        // permitted differences from the pre-demand state are the victim's
        // single lifecycle transition, the reclaim cursor that selecting it
        // set, and the two appended dispositions recording the acceptance and
        // its cancellation. No child scope, order, reservation id, free-set
        // entry, charge, or rotation cursor may survive, and no grant or other
        // unexpected trace entry may appear.
        drop(turn);
        let after_cancel = fixture.provider.transactional_snapshot_for_test();
        assert_no_mutation_except_reclaim(
            &before,
            &after_cancel,
            after_request.reclaim_cursor,
            // The demand was accepted and then cancelled: those two
            // dispositions are required, and no grant may appear.
            &["accepted", "cancelled"],
            "new-child turn cancelled after reclaim",
        );

        // The victim was asked to retire and did not, so its charge is intact
        // and its notification stands.
        assert_eq!(notified_competitors(&fixture), vec![true]);
        // The failure half of this path — an allocator refusal rather than a
        // cancellation — is covered by
        // `pending_new_child_promotion_survives_scope_order_failure_and_promotes_exactly_once`
        // and `reservation_id_failure_during_arbitrate_preserves_pending_new_child`.
    }

    #[test]
    fn reclaim_cursor_wrap_selects_the_same_next_victim_for_existing_and_new_child_requests() {
        // One competitor before the requester's root and one after, so the
        // requester sits mid-order. That arrangement is what makes the
        // `victim_root == requester_root` component of the sort key
        // load-bearing.
        //
        // With the requester at the lowest root order — as a plain
        // `victim_fixture` produces — the test would be degenerate: once the
        // first victim sets a cursor, `victim_root <= cursor` already sorts the
        // requester last, so deleting the own-root component would leave the
        // selection unchanged and the control would prove nothing.
        //
        // Here, after the first request sets the cursor on the *earlier*
        // competitor, the requester is no longer covered by that cursor
        // predicate. Only the own-root component keeps it last, so removing
        // that component makes the second request select the requester's own
        // root — which this control detects.
        fn wrap_victim(new_child: bool) -> (Vec<bool>, bool) {
            let fixture = victim_fixture_around_requester(1, 1);
            let one = ResourceClaim::single(ResourceClass::QueuedBytes, 1);

            // Premise: creation order really did place the requester between
            // the two competitors in root order. Root values are visible in the
            // snapshot, so this is checked rather than assumed.
            let snapshot = fixture.provider.transactional_snapshot_for_test();
            let root_of_scope = |scope: &ResourceScope| {
                snapshot
                    .scopes
                    .iter()
                    .find(|(scope_id, _, _, _)| *scope_id == scope.id())
                    .map(|(_, root, _, _)| *root)
                    .expect("every live scope appears in the snapshot")
            };
            let earlier = root_of_scope(&fixture.others[0].scope);
            let requester = root_of_scope(&fixture.own.scope);
            let later = root_of_scope(&fixture.others[1].scope);
            assert!(
                earlier < requester && requester < later,
                "fixture premise: the requester's root must sit between the two \
                 competing roots, or the own-root sort component is unobservable \
                 ({earlier} < {requester} < {later})"
            );

            let first = pending(
                fixture
                    .port
                    .acquire_cooperatively(
                        &fixture.own.scope,
                        ResourceAuthorityClass::Admitted,
                        one,
                        None,
                    )
                    .expect("first turn fixes the reclaim cursor"),
            );
            assert_eq!(
                notified_competitors(&fixture),
                vec![true, false],
                "the first request victimizes the earlier competing root, \
                 setting the cursor below the requester's own root"
            );
            drop(first);

            let second = if new_child {
                let (target, _subscription) = ResourceReclaimSubscription::channel();
                pending(
                    fixture
                        .port
                        .create_scope_with_reclaimable_lease_cooperatively(
                            &fixture.own.scope,
                            one,
                            target,
                        )
                        .expect("second turn as a new-child demand"),
                )
            } else {
                pending(
                    fixture
                        .port
                        .acquire_cooperatively(
                            &fixture.own.scope,
                            ResourceAuthorityClass::Admitted,
                            one,
                            None,
                        )
                        .expect("second turn from an existing scope"),
                )
            };
            let notified = notified_competitors(&fixture);
            let own_notified = fixture.own.subscription.is_requested();
            drop(second);
            (notified, own_notified)
        }

        let (existing_notified, existing_own) = wrap_victim(false);
        let (new_child_notified, new_child_own) = wrap_victim(true);

        assert_eq!(
            existing_notified, new_child_notified,
            "the wrapped next victim must be the same for an existing-scope and \
             a new-child request"
        );
        assert_eq!(
            existing_notified,
            vec![true, true],
            "the second request skips the requester's own root and selects the \
             later competitor. Without the own-root sort component the requester \
             would be chosen here, since the cursor no longer covers it"
        );
        assert!(
            !existing_own && !new_child_own,
            "the requester's own root is not reached while competing roots remain"
        );
    }

    #[test]
    fn one_pending_demand_per_root_not_per_scope() {
        // The grant must be able to satisfy the pending claim eventually, or
        // `claim_can_ever_fit` refuses outright and no turn is ever created.
        // Two units: one held by the blocker, two demanded, so the demand is
        // pressured rather than impossible.
        let grant = claim(&[
            (ResourceClass::QueuedBytes, 2),
            (ResourceClass::OpaqueDependencyResidual, 256),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).expect("process bookkeeping");
        let root = port.create_fairness_root_scope().expect("one root");
        let first_child = port.create_scope(&root).expect("first child");
        let second_child = port.create_scope(&root).expect("second child");
        let one = ResourceClaim::single(ResourceClass::QueuedBytes, 1);
        let two = ResourceClaim::single(ResourceClass::QueuedBytes, 2);
        // The blocker must be Speculative with a live reclaim target. A pending
        // turn only survives arbitration when some eligible victim can cover
        // the deficit; against a nonreclaimable Admitted blocker the provider
        // correctly resolves the demand to typed Pressure and no turn exists
        // for the sibling to be refused against.
        let (blocker_target, blocker_subscription) = ResourceReclaimSubscription::channel();
        let blocker = port
            .acquire_reclaimable_now(&first_child, one, blocker_target)
            .expect("one reclaimable queue unit of the root's two");

        // The first child takes the root's one turn.
        let turn = pending(
            port.acquire_cooperatively(&first_child, ResourceAuthorityClass::Admitted, two, None)
                .expect("the root's single pending turn"),
        );
        // The turn is sustained by an outstanding reclaim request, and its owner
        // never releases, so it is still held for the assertion below.
        assert!(
            blocker_subscription.is_requested(),
            "the pending turn is sustained by an outstanding reclaim request"
        );

        // A sibling beneath the same root cannot mint a second turn.
        let before = provider.transactional_snapshot_for_test();
        assert!(
            matches!(
                port.acquire_cooperatively(
                    &second_child,
                    ResourceAuthorityClass::Admitted,
                    two,
                    None
                ),
                Err(ResourceUnavailable::DemandPending { .. })
            ),
            "a second child beneath one root must not obtain a second turn"
        );

        // This control is the named producer of `PendingRefused` in the
        // completeness table, so it asserts that variant rather than resting on
        // the typed error alone.
        let after = provider.transactional_snapshot_for_test();
        assert_trace_prefix_intact(&before, &after);
        assert_eq!(
            after.decision_log[before.decision_log.len()..]
                .iter()
                .map(decision_kind)
                .collect::<Vec<_>>(),
            vec!["refused"],
            "the refused sibling turn is recorded exactly once"
        );

        // Retire the turn before the blocker. Releasing the blocker first would
        // free the contended dimension and let arbitration promote the
        // outstanding turn, ending the test through a path this control is not
        // about.
        drop(turn);
        drop(blocker);
    }

    #[test]
    fn fitting_immediate_acquisition_succeeds_on_a_root_that_already_holds_a_turn() {
        // P4 surplus: capacity beyond the selected demand's exact reservation
        // stays borrowable, including by a sibling on the same root.
        // The surplus must lie in a dimension the pending demand does not
        // reserve. On the demand's own dimension there is never any: a demand
        // is pending precisely because its charge exceeds what is available,
        // so `available - pending_charge` is zero there by construction. Queue
        // is the contended dimension; sockets are the untouched surplus.
        let grant = claim(&[
            (ResourceClass::QueuedBytes, 2),
            (ResourceClass::SocketOrHandle, 2),
            (ResourceClass::OpaqueDependencyResidual, 256),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider).expect("process bookkeeping");
        let root = port.create_fairness_root_scope().expect("one root");
        let demander = port.create_scope(&root).expect("demanding child");
        let sibling = port.create_scope(&root).expect("sibling child");
        let one_queue = ResourceClaim::single(ResourceClass::QueuedBytes, 1);
        let two_queue = ResourceClaim::single(ResourceClass::QueuedBytes, 2);
        let one_socket = ResourceClaim::single(ResourceClass::SocketOrHandle, 1);
        // The blocker must be Speculative with a live reclaim target. A pending
        // turn only survives arbitration when some eligible victim can cover
        // the deficit: against a nonreclaimable Admitted blocker the provider
        // correctly resolves the demand to typed Pressure, so it never becomes
        // pending and the surplus assertion below is never reached.
        let (blocker_target, blocker_subscription) = ResourceReclaimSubscription::channel();
        let blocker = port
            .acquire_reclaimable_now(&demander, one_queue, blocker_target)
            .expect("one reclaimable queue unit held");
        let turn = pending(
            port.acquire_cooperatively(
                &demander,
                ResourceAuthorityClass::Admitted,
                two_queue,
                None,
            )
            .expect("a two-unit queue turn that cannot fit yet"),
        );
        // The turn exists because a victim was asked to retire. That owner does
        // not release, so the turn stays outstanding for the rest of the test.
        assert!(
            blocker_subscription.is_requested(),
            "the pending turn is sustained by an outstanding reclaim request"
        );

        // The pending turn reserves queue capacity only, so socket capacity
        // stays borrowable — including by a sibling on the same root, whose
        // root already holds the turn.
        let surplus = port.acquire(&sibling, ResourceAuthorityClass::Admitted, one_socket);
        assert!(
            surplus.is_ok(),
            "a fitting immediate claim in an unreserved dimension must still be \
             admitted while a sibling on the same root holds the turn"
        );
        // Retire in a deliberate order: the surplus lease, then the turn, then
        // the blocker. Dropping the blocker first would free the contended
        // dimension, let arbitration grant the still-outstanding turn, and end
        // the test by exercising the granted-then-cancelled path, which this
        // control is not about.
        drop(surplus.ok());
        drop(turn);
        drop(blocker);
    }

    /// A grant roomy enough that only the forced allocator failure can refuse.
    fn transactional_test_port() -> (DeterministicGrantProvider, ResourceProviderPort) {
        let grant = claim(&[
            (ResourceClass::QueuedBytes, 64),
            (ResourceClass::SocketOrHandle, 64),
            (ResourceClass::OpaqueDependencyResidual, 4096),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).expect("process bookkeeping");
        (provider, port)
    }

    #[test]
    fn scope_order_failure_consumes_nothing_on_plain_child_creation() {
        let (provider, port) = transactional_test_port();
        let process = port.process_scope();
        let before = provider.transactional_snapshot_for_test();

        provider.fail_scope_order_allocation_for_test(true);
        assert!(
            port.create_scope(&process).is_err(),
            "a failed order allocation must refuse"
        );
        assert_eq!(
            provider.transactional_snapshot_for_test(),
            before,
            "a refused creation consumes no capacity, topology, reservation, or order"
        );

        provider.fail_scope_order_allocation_for_test(false);
        let recovered = port
            .create_scope(&process)
            .expect("creation succeeds once the allocator is restored");
        drop(recovered);
    }

    /// Assert that the only difference between two snapshots is the intentional
    /// release of exactly one blocker child scope and its one reservation.
    ///
    /// A subset check is not enough: it permits spurious extra free ids or
    /// orders appearing from nowhere, which is precisely what a leaking
    /// rollback would look like. This binds the delta exactly, so anything the
    /// refused promotion touched shows up as a failure.
    fn assert_only_blocker_release_changed(
        before: &FiniteProviderSnapshot,
        after: &FiniteProviderSnapshot,
        label: &str,
    ) {
        // Exactly one scope disappeared, none appeared, and every survivor is
        // byte-identical including its root, order, and pending shape.
        let removed_scopes: Vec<_> = before
            .scopes
            .iter()
            .filter(|entry| !after.scopes.iter().any(|kept| kept.0 == entry.0))
            .collect();
        let added_scopes: Vec<_> = after
            .scopes
            .iter()
            .filter(|entry| !before.scopes.iter().any(|old| old.0 == entry.0))
            .collect();
        assert_eq!(
            removed_scopes.len(),
            1,
            "{label}: exactly the blocker child scope should disappear"
        );
        assert!(
            added_scopes.is_empty(),
            "{label}: a refused promotion created a scope"
        );
        for kept in &after.scopes {
            let old = before
                .scopes
                .iter()
                .find(|old| old.0 == kept.0)
                .expect("survivors were present before");
            assert_eq!(
                old, kept,
                "{label}: a surviving scope's root, order, or pending shape changed"
            );
        }

        // Exactly one reservation disappeared, none appeared, survivors equal.
        let removed_reservations: Vec<_> = before
            .reservations
            .iter()
            .filter(|entry| !after.reservations.iter().any(|kept| kept.0 == entry.0))
            .collect();
        let added_reservations: Vec<_> = after
            .reservations
            .iter()
            .filter(|entry| !before.reservations.iter().any(|old| old.0 == entry.0))
            .collect();
        assert_eq!(
            removed_reservations.len(),
            1,
            "{label}: exactly the blocker reservation should disappear"
        );
        assert!(
            added_reservations.is_empty(),
            "{label}: a refused promotion created a reservation"
        );

        // The freed order and reservation id are exactly the released ones, and
        // nothing else joined either free set.
        let released_order = removed_scopes[0].2;
        let released_reservation = removed_reservations[0].0;
        let released_claim = removed_reservations[0].3;

        let mut expected_free_orders = before.free_scope_orders.clone();
        expected_free_orders.push(released_order);
        expected_free_orders.sort_unstable();
        let mut actual_free_orders = after.free_scope_orders.clone();
        actual_free_orders.sort_unstable();
        assert_eq!(
            actual_free_orders, expected_free_orders,
            "{label}: free scope orders differ by something other than the released order"
        );

        let mut expected_free_ids = before.free_reservation_ids.clone();
        expected_free_ids.push(released_reservation);
        expected_free_ids.sort_unstable();
        let mut actual_free_ids = after.free_reservation_ids.clone();
        actual_free_ids.sort_unstable();
        assert_eq!(
            actual_free_ids, expected_free_ids,
            "{label}: free reservation ids differ by something other than the released id"
        );

        // Neither frontier may advance: a release returns values, and a refused
        // promotion must mint none.
        assert_eq!(
            after.next_scope_order, before.next_scope_order,
            "{label}: scope-order frontier advanced"
        );
        assert_eq!(
            after.next_reservation_id, before.next_reservation_id,
            "{label}: reservation-id frontier advanced"
        );

        // `in_use` falls by exactly what the blocker held. That is not the raw
        // claim: a reservation is charged `claim + bookkeeping`, and the child
        // scope record carries a further bookkeeping unit. Subtracting the raw
        // claim would undercount by one `OpaqueDependencyResidual` unit and
        // would fail even on correct behaviour.
        let released_total =
            FiniteResourceProvider::child_scope_with_reservation_charge_for_test(released_claim)
                .expect("the blocker's combined charge is representable");
        let expected_in_use = before
            .in_use
            .checked_sub(released_total)
            .expect("the blocker's charges were in use before release");
        assert_eq!(
            after.in_use, expected_in_use,
            "{label}: in_use changed by something other than the blocker's release"
        );

        // Everything else must be untouched.
        assert_eq!(
            after.retained_after_failed_cleanup, before.retained_after_failed_cleanup,
            "{label}: retention changed"
        );
        assert_eq!(after.poisoned, before.poisoned, "{label}: poison changed");
        assert_eq!(
            after.demand_cursor, before.demand_cursor,
            "{label}: a rotation cursor advanced"
        );
        assert_eq!(
            after.reclaim_cursor, before.reclaim_cursor,
            "{label}: the reclaim cursor advanced"
        );
        assert_eq!(
            after.active_demand, before.active_demand,
            "{label}: the active demand changed"
        );
        // Equality is correct here, unlike in the cancellation helper: a
        // refused promotion creates no demand, so it must append nothing at
        // all — not merely no grant.
        assert_eq!(
            after.decision_log, before.decision_log,
            "{label}: a refused promotion appended a decision"
        );
    }

    #[test]
    fn trusted_root_creation_is_fallible_and_burns_nothing() {
        // The directive's root-creation no-burn claim, asserted directly
        // against `create_fairness_root_scope` rather than inferred from
        // ordinary child creation.
        let (provider, port) = transactional_test_port();
        let before = provider.transactional_snapshot_for_test();

        provider.fail_scope_order_allocation_for_test(true);
        assert!(
            port.create_fairness_root_scope().is_err(),
            "root creation is fallible and refuses when bookkeeping cannot be allocated"
        );
        assert_eq!(
            provider.transactional_snapshot_for_test(),
            before,
            "a refused root mint adds no scope, advances no allocator, moves no \
             cursor, appends no decision, and consumes no capacity"
        );

        provider.fail_scope_order_allocation_for_test(false);
        let root = port
            .create_fairness_root_scope()
            .expect("one root is creatable once the allocator is restored");
        assert_eq!(
            root.parent_id(),
            None,
            "a trusted root scope inherits from nothing"
        );
        drop(root);
    }

    #[test]
    fn reservation_id_failure_after_scope_preparation_rolls_back_exactly() {
        // Exercises the rollback branch that only runs after a scope order has
        // already been successfully prepared, which the order-failure controls
        // can never reach.
        let (provider, port) = transactional_test_port();
        let process = port.process_scope();
        let socket = ResourceClaim::single(ResourceClass::SocketOrHandle, 1);
        let before = provider.transactional_snapshot_for_test();

        provider.fail_reservation_id_allocation_for_test(true);
        assert!(
            port.create_scope_with_lease(&process, ResourceAuthorityClass::Admitted, socket)
                .is_err(),
            "reservation-id exhaustion refuses the transaction"
        );
        assert_eq!(
            provider.transactional_snapshot_for_test(),
            before,
            "the prepared scope order is returned to exactly where it came from, \
             so the allocator is byte-identical rather than merely capacity-equal"
        );

        provider.fail_reservation_id_allocation_for_test(false);
        let recovered = port
            .create_scope_with_lease(&process, ResourceAuthorityClass::Admitted, socket)
            .expect("the transaction succeeds once allocation is restored");
        drop(recovered);
    }

    #[test]
    fn scope_order_failure_consumes_nothing_on_atomic_create_and_acquire() {
        let (provider, port) = transactional_test_port();
        let process = port.process_scope();
        let socket = ResourceClaim::single(ResourceClass::SocketOrHandle, 1);
        let before = provider.transactional_snapshot_for_test();

        provider.fail_scope_order_allocation_for_test(true);
        assert!(
            port.create_scope_with_lease(&process, ResourceAuthorityClass::Admitted, socket)
                .is_err(),
            "a failed order allocation must refuse the whole transaction"
        );
        assert_eq!(
            provider.transactional_snapshot_for_test(),
            before,
            "no reservation id, capacity, or order is burned by the refusal"
        );

        provider.fail_scope_order_allocation_for_test(false);
        let recovered = port
            .create_scope_with_lease(&process, ResourceAuthorityClass::Admitted, socket)
            .expect("the transaction succeeds once the allocator is restored");
        drop(recovered);
    }

    #[test]
    fn scope_order_failure_consumes_nothing_on_cooperative_immediate_creation() {
        let (provider, port) = transactional_test_port();
        let process = port.process_scope();
        let socket = ResourceClaim::single(ResourceClass::SocketOrHandle, 1);
        let before = provider.transactional_snapshot_for_test();

        provider.fail_scope_order_allocation_for_test(true);
        let (target, subscription) = ResourceReclaimSubscription::channel();
        assert!(
            port.create_scope_with_reclaimable_lease_cooperatively(&process, socket, target)
                .is_err(),
            "a failed order allocation must refuse the cooperative transaction"
        );
        assert_eq!(
            provider.transactional_snapshot_for_test(),
            before,
            "the immediate cooperative path leaves accounting untouched on refusal"
        );
        assert!(
            !subscription.is_requested(),
            "a refused creation requests no victim"
        );

        provider.fail_scope_order_allocation_for_test(false);
        let (retry_target, _retry_subscription) = ResourceReclaimSubscription::channel();
        let recovered = port
            .create_scope_with_reclaimable_lease_cooperatively(&process, socket, retry_target)
            .expect("the transaction succeeds once the allocator is restored");
        drop(recovered);
    }

    #[test]
    fn pending_new_child_promotion_survives_scope_order_failure_and_promotes_exactly_once() {
        // A pending NewChild demand whose order allocation fails at promotion
        // must stay pending and retryable: the failure is finite bookkeeping,
        // not a provider bug, so nothing is poisoned and the turn is not lost.
        let grant = claim(&[
            (ResourceClass::SocketOrHandle, 1),
            (ResourceClass::OpaqueDependencyResidual, 4096),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).expect("process bookkeeping");
        let process = port.process_scope();
        let socket = ResourceClaim::single(ResourceClass::SocketOrHandle, 1);

        // The only socket is held by a reclaimable blocker, so the cooperative
        // child creation below must queue as a pending NewChild demand.
        let (blocker_target, _blocker_subscription) = ResourceReclaimSubscription::channel();
        let blocker = port
            .create_scope_with_reclaimable_lease_cooperatively(&process, socket, blocker_target)
            .expect("blocker holds the only socket");
        let blocker = acquired(blocker);

        let (demand_target, _demand_subscription) = ResourceReclaimSubscription::channel();
        let demand = pending(
            port.create_scope_with_reclaimable_lease_cooperatively(&process, socket, demand_target)
                .expect("a pending new-child demand"),
        );

        // Fail the allocator, then free the capacity the demand was waiting on.
        // The snapshot is taken after failing but before the release, so the
        // blocker's intentional effects are attributed to the release and not
        // to the failed promotion.
        provider.fail_scope_order_allocation_for_test(true);
        let before_release = provider.transactional_snapshot_for_test();
        drop(blocker);

        let during_failure = provider.transactional_snapshot_for_test();
        assert_eq!(
            during_failure.poisoned, None,
            "an exhausted scope-order allocator is a refusal, not a provider bug"
        );
        // The only permitted difference is the blocker's intentional release.
        assert_only_blocker_release_changed(
            &before_release,
            &during_failure,
            "scope-order failure at promotion",
        );
        assert!(
            during_failure
                .scopes
                .iter()
                .any(|(_, _, _, pending)| pending.is_some()),
            "the pending demand and its turn survive the failed promotion"
        );

        // Restoring the allocator must let the same demand promote, exactly
        // once, with no duplicate scope or reservation.
        provider.fail_scope_order_allocation_for_test(false);
        let promoted = acquired(demand.retry().expect("the same demand promotes on retry"));
        let after = provider.transactional_snapshot_for_test();
        assert_eq!(after.poisoned, None);
        assert_eq!(
            after.reservations.len(),
            1,
            "promotion creates exactly one reservation"
        );
        assert!(
            after
                .scopes
                .iter()
                .all(|(_, _, _, pending)| pending.is_none()),
            "no pending demand remains after promotion"
        );
        drop(promoted);
    }

    #[test]
    fn reservation_id_failure_rolls_back_exactly_on_cooperative_immediate_creation() {
        // The cooperative immediate path prepares a scope order, then allocates
        // a reservation id, then mutates `in_use`. Failing the second step is
        // the only way to reach its rollback branch.
        let (provider, port) = transactional_test_port();
        let process = port.process_scope();
        let socket = ResourceClaim::single(ResourceClass::SocketOrHandle, 1);
        let before = provider.transactional_snapshot_for_test();

        provider.fail_reservation_id_allocation_for_test(true);
        let (target, subscription) = ResourceReclaimSubscription::channel();
        assert!(
            port.create_scope_with_reclaimable_lease_cooperatively(&process, socket, target)
                .is_err(),
            "reservation-id exhaustion refuses the cooperative transaction"
        );
        assert_eq!(
            provider.transactional_snapshot_for_test(),
            before,
            "the prepared order returns to exactly where it came from and \
             `in_use` is never mutated ahead of the failure"
        );
        assert!(
            !subscription.is_requested(),
            "a refused creation requests no victim"
        );

        provider.fail_reservation_id_allocation_for_test(false);
        let restored = provider.transactional_snapshot_for_test();
        let (retry_target, _retry_subscription) = ResourceReclaimSubscription::channel();
        let recovered = acquired(
            port.create_scope_with_reclaimable_lease_cooperatively(&process, socket, retry_target)
                .expect("the transaction succeeds once allocation is restored"),
        );

        // This control is the named producer of `ImmediateGrant` in the
        // completeness table, so it asserts that variant rather than leaving
        // the table pointing at an unexercised path. The cooperative call fit
        // without arbitration, so exactly one immediate grant is appended.
        let after = provider.transactional_snapshot_for_test();
        assert_trace_prefix_intact(&restored, &after);
        assert_eq!(
            after.decision_log[restored.decision_log.len()..]
                .iter()
                .map(decision_kind)
                .collect::<Vec<_>>(),
            vec!["immediate"],
            "a cooperative claim that fits records exactly one immediate grant"
        );
        drop(recovered);
    }

    #[test]
    fn reservation_id_failure_during_arbitrate_preserves_pending_new_child() {
        // The same later-step rollback, but reached through arbitration rather
        // than a direct call: the demand must stay pending and retryable.
        let grant = claim(&[
            (ResourceClass::SocketOrHandle, 1),
            (ResourceClass::OpaqueDependencyResidual, 4096),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).expect("process bookkeeping");
        let process = port.process_scope();
        let socket = ResourceClaim::single(ResourceClass::SocketOrHandle, 1);

        let (blocker_target, _blocker_subscription) = ResourceReclaimSubscription::channel();
        let blocker = acquired(
            port.create_scope_with_reclaimable_lease_cooperatively(
                &process,
                socket,
                blocker_target,
            )
            .expect("blocker holds the only socket"),
        );
        let (demand_target, _demand_subscription) = ResourceReclaimSubscription::channel();
        let demand = pending(
            port.create_scope_with_reclaimable_lease_cooperatively(&process, socket, demand_target)
                .expect("a pending new-child demand"),
        );

        // Fail the *second* allocation, then free the capacity the demand needs.
        // Snapshot after failing but before the release, so the release's
        // intentional effects are attributed to it rather than to the refusal.
        provider.fail_reservation_id_allocation_for_test(true);
        let before_release = provider.transactional_snapshot_for_test();
        drop(blocker);

        let during_failure = provider.transactional_snapshot_for_test();
        assert_eq!(
            during_failure.poisoned, None,
            "a later-step allocation refusal during arbitration is not a provider bug"
        );
        // Exact delta: the prepared scope order must have been returned to
        // precisely where it came from, leaving no spurious free value behind.
        assert_only_blocker_release_changed(
            &before_release,
            &during_failure,
            "reservation-id failure at promotion",
        );
        assert!(
            during_failure
                .scopes
                .iter()
                .any(|(_, _, _, pending)| pending.is_some()),
            "the pending demand and its turn survive the failed promotion"
        );

        provider.fail_reservation_id_allocation_for_test(false);
        let promoted = acquired(demand.retry().expect("the same demand promotes on retry"));
        let after = provider.transactional_snapshot_for_test();
        assert_eq!(after.poisoned, None);
        assert_eq!(
            after.reservations.len(),
            1,
            "promotion creates exactly one reservation"
        );
        drop(promoted);
    }

    #[test]
    fn authority_order_holds_across_distinct_roots() {
        // Cleanup > Admitted > Speculative is resolved before any rotation, so
        // it must hold between demands owned by different fairness roots.
        let grant = claim(&[
            (ResourceClass::WorkerOrTask, 1),
            (ResourceClass::OpaqueDependencyResidual, 4096),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider).expect("process bookkeeping");
        let holder = port.create_fairness_root_scope().expect("holder root");
        let speculative_root = port
            .create_fairness_root_scope()
            .expect("speculative demander root");
        let admitted_root = port
            .create_fairness_root_scope()
            .expect("admitted demander root");
        let cleanup_root = port
            .create_fairness_root_scope()
            .expect("cleanup demander root");
        let worker = ResourceClaim::single(ResourceClass::WorkerOrTask, 1);

        let (holder_target, _holder_subscription) = ResourceReclaimSubscription::channel();
        let holder_lease = port
            .acquire_reclaimable_now(&holder, worker, holder_target)
            .expect("holder owns the only worker");

        // Offered lowest authority first, and on the earliest-created root, so
        // neither offer order nor rotation position can explain the outcome.
        let (spec_target, _spec_subscription) = ResourceReclaimSubscription::channel();
        let speculative = pending(
            port.acquire_cooperatively(
                &speculative_root,
                ResourceAuthorityClass::Speculative,
                worker,
                Some(spec_target),
            )
            .expect("speculative turn"),
        );
        let admitted = pending(
            port.acquire_cooperatively(
                &admitted_root,
                ResourceAuthorityClass::Admitted,
                worker,
                None,
            )
            .expect("admitted turn"),
        );
        let cleanup = pending(
            port.acquire_cooperatively(
                &cleanup_root,
                ResourceAuthorityClass::Cleanup,
                worker,
                None,
            )
            .expect("cleanup turn"),
        );

        drop(holder_lease);
        // Cleanup wins despite being offered last and owning the latest root.
        let cleanup_lease = acquired(cleanup.retry().expect("cleanup outranks across roots"));
        assert!(matches!(
            admitted.retry(),
            Err(ResourceUnavailable::Pressure(_))
        ));
        assert!(matches!(
            speculative.retry(),
            Err(ResourceUnavailable::Pressure(_))
        ));
        drop(cleanup_lease);
    }

    #[test]
    fn distinct_roots_share_one_process_grant() {
        // Roots partition attribution, never capacity. Two roots draw from the
        // same finite grant, and creating a root adds none.
        let grant = claim(&[
            (ResourceClass::QueuedBytes, 2),
            (ResourceClass::OpaqueDependencyResidual, 4096),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).expect("process bookkeeping");
        let first_root = port.create_fairness_root_scope().expect("first root");
        let second_root = port.create_fairness_root_scope().expect("second root");
        let one = ResourceClaim::single(ResourceClass::QueuedBytes, 1);

        let first = port
            .acquire(&first_root, ResourceAuthorityClass::Admitted, one)
            .expect("first root takes one unit");
        let second = port
            .acquire(&second_root, ResourceAuthorityClass::Admitted, one)
            .expect("second root takes the other unit from the same grant");
        assert_eq!(provider.in_use().amount(ResourceClass::QueuedBytes), 2);

        // The grant is exhausted for every root, including a freshly minted one.
        let third_root = port.create_fairness_root_scope().expect("third root");
        assert!(
            matches!(
                port.acquire(&third_root, ResourceAuthorityClass::Admitted, one),
                Err(ResourceUnavailable::Pressure(_))
            ),
            "minting another root creates no capacity"
        );
        drop((first, second));
    }

    #[test]
    fn scope_orders_are_recycled_on_true_release() {
        let grant = claim(&[
            (ResourceClass::QueuedBytes, 1),
            (ResourceClass::OpaqueDependencyResidual, 256),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider).expect("process bookkeeping");
        let process = port.process_scope();
        // Repeated create/release cycles must not exhaust anything: a released
        // order returns to the free set and is reissued.
        for _ in 0..64 {
            let scope = port.create_scope(&process).expect("child scope");
            drop(scope);
        }
        let after = port.create_scope(&process).expect("still admissible");
        drop(after);
    }

    #[test]
    fn refused_scope_creation_changes_neither_topology_nor_order_pool() {
        // Bookkeeping is finite and fallible: exhaust it, and confirm the
        // refusal leaves the surviving topology able to create again once
        // capacity returns.
        let grant = claim(&[
            (ResourceClass::QueuedBytes, 1),
            (
                ResourceClass::OpaqueDependencyResidual,
                FiniteResourceProvider::scope_record_charge_for_test()
                    .amount(ResourceClass::OpaqueDependencyResidual)
                    * 2,
            ),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider).expect("process bookkeeping");
        let process = port.process_scope();
        let held = port.create_scope(&process).expect("first child fits");
        // The next creation must be refused rather than silently admitted.
        let refused = port.create_scope(&process);
        assert!(
            refused.is_err(),
            "scope bookkeeping is finite and refusal is real"
        );
        drop(held);
        // After a true release the order returned and creation succeeds again.
        let again = port.create_scope(&process).expect("capacity returned");
        drop(again);
    }

    #[test]
    fn insufficient_reclaim_set_is_not_published() {
        let grant = claim(&[
            (ResourceClass::QueuedBytes, 2),
            (ResourceClass::OpaqueDependencyResidual, 7),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).expect("process bookkeeping");
        let process = port.process_scope();
        let admitted_scope = port.create_scope(&process).expect("admitted scope");
        let speculative_scope = port.create_scope(&process).expect("speculative scope");
        let requester_scope = port.create_scope(&process).expect("requester scope");
        let one = ResourceClaim::single(ResourceClass::QueuedBytes, 1);
        let admitted = port
            .acquire(&admitted_scope, ResourceAuthorityClass::Admitted, one)
            .expect("one nonreclaimable admitted unit");
        let (target, subscription) = ResourceReclaimSubscription::channel();
        let speculative = port
            .acquire_reclaimable_now(&speculative_scope, one, target)
            .expect("one reclaimable speculative unit");

        let before = provider.transactional_snapshot_for_test();
        assert!(matches!(
            port.acquire_cooperatively(
                &requester_scope,
                ResourceAuthorityClass::Admitted,
                ResourceClaim::single(ResourceClass::QueuedBytes, 2),
                None,
            ),
            Err(ResourceUnavailable::Pressure(_))
        ));
        assert!(
            !subscription.is_requested(),
            "an insufficient victim set is never published"
        );

        // This control is the named producer of `TerminalPressure` in the
        // completeness table, so it asserts that variant rather than resting on
        // the typed error alone: the turn is accepted, then resolved to
        // terminal pressure once no sufficient victim set exists.
        let after = provider.transactional_snapshot_for_test();
        assert_trace_prefix_intact(&before, &after);
        assert_eq!(
            after.decision_log[before.decision_log.len()..]
                .iter()
                .map(decision_kind)
                .collect::<Vec<_>>(),
            vec!["accepted", "pressured"],
            "a refused cooperative turn records its acceptance and its terminal pressure"
        );
        drop((speculative, admitted));
    }

    #[test]
    fn dropping_pending_demand_cancels_its_turn_without_releasing_a_victim() {
        let grant = claim(&[
            (ResourceClass::QueuedBytes, 5),
            (ResourceClass::OpaqueDependencyResidual, 6),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider).expect("process bookkeeping");
        // Victim and requester are distinct fairness roots, so cancelling the
        // requester's turn is observed against a holder on another root rather
        // than against its own root's reservation.
        let first = port.create_fairness_root_scope().expect("victim root");
        let second = port.create_fairness_root_scope().expect("requester root");
        let queue = ResourceClaim::single(ResourceClass::QueuedBytes, 4);
        let (first_target, first_subscription) = ResourceReclaimSubscription::channel();
        let first_lease = acquired(
            port.acquire_cooperatively(
                &first,
                ResourceAuthorityClass::Speculative,
                queue,
                Some(first_target),
            )
            .expect("first speculative admission"),
        );
        let demand = pending(
            port.acquire_cooperatively(&second, ResourceAuthorityClass::Admitted, queue, None)
                .expect("pending demand"),
        );
        assert!(first_subscription.is_requested());
        drop(demand);

        let extra = port
            .acquire(
                &first,
                ResourceAuthorityClass::Speculative,
                ResourceClaim::single(ResourceClass::QueuedBytes, 1),
            )
            .expect("cancelled turn no longer fences free capacity");
        assert_eq!(first_lease.claim(), queue);
        drop((extra, first_lease));
    }

    #[test]
    fn nonwaiting_reclaimable_admission_returns_pressure_without_requesting_cleanup() {
        let grant = claim(&[
            (ResourceClass::QueuedBytes, 1),
            (ResourceClass::OpaqueDependencyResidual, 5),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider).expect("process bookkeeping");
        let process = port.process_scope();
        let first = port.create_scope(&process).expect("first scope");
        let second = port.create_scope(&process).expect("second scope");
        let queue = ResourceClaim::single(ResourceClass::QueuedBytes, 1);
        let (first_target, first_subscription) = ResourceReclaimSubscription::channel();
        let first_lease = port
            .acquire_reclaimable_now(&first, queue, first_target)
            .expect("first reclaimable lease");
        let (second_target, second_subscription) = ResourceReclaimSubscription::channel();
        assert!(matches!(
            port.acquire_reclaimable_now(&second, queue, second_target),
            Err(ResourceUnavailable::Pressure(_))
        ));
        assert!(!first_subscription.is_requested());
        assert!(!second_subscription.is_requested());
        drop(first_lease);
    }

    #[test]
    fn pending_turn_blocks_only_overlapping_resource_dimensions() {
        let grant = claim(&[
            (ResourceClass::QueuedBytes, 1),
            (ResourceClass::StorageObject, 1),
            (ResourceClass::OpaqueDependencyResidual, 7),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider).expect("process bookkeeping");
        let process = port.process_scope();
        let first = port.create_scope(&process).expect("first scope");
        let second = port.create_scope(&process).expect("second scope");
        let third = port.create_scope(&process).expect("third scope");
        let queue = ResourceClaim::single(ResourceClass::QueuedBytes, 1);
        let (first_target, _first_subscription) = ResourceReclaimSubscription::channel();
        let first_lease = port
            .acquire_reclaimable_now(&first, queue, first_target)
            .expect("queue owner");
        let queue_demand = pending(
            port.acquire_cooperatively(&second, ResourceAuthorityClass::Admitted, queue, None)
                .expect("queue demand"),
        );

        let (storage_target, _storage_subscription) = ResourceReclaimSubscription::channel();
        let storage = port
            .acquire_reclaimable_now(
                &third,
                ResourceClaim::single(ResourceClass::StorageObject, 1),
                storage_target,
            )
            .expect("unrelated dimension remains work-conserving");
        drop(storage);
        drop(queue_demand);
        drop(first_lease);
    }

    #[test]
    fn pending_turn_reserves_its_exact_charge_without_fencing_overlapping_surplus() {
        let grant = claim(&[
            (ResourceClass::QueuedBytes, 1),
            (ResourceClass::StorageBytes, 10),
            (ResourceClass::OpaqueDependencyResidual, 8),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider).expect("process bookkeeping");
        let process = port.process_scope();
        let first = port.create_scope(&process).expect("first scope");
        let second = port.create_scope(&process).expect("second scope");
        let third = port.create_scope(&process).expect("third scope");
        let queue = ResourceClaim::single(ResourceClass::QueuedBytes, 1);
        let (first_target, _first_subscription) = ResourceReclaimSubscription::channel();
        let first_lease = port
            .acquire_reclaimable_now(&first, queue, first_target)
            .expect("queue owner");
        let active_claim = claim(&[
            (ResourceClass::QueuedBytes, 1),
            (ResourceClass::StorageBytes, 2),
        ]);
        let demand = pending(
            port.acquire_cooperatively(
                &second,
                ResourceAuthorityClass::Admitted,
                active_claim,
                None,
            )
            .expect("active composite demand"),
        );

        let borrowed_surplus = port
            .acquire(
                &third,
                ResourceAuthorityClass::Admitted,
                ResourceClaim::single(ResourceClass::StorageBytes, 7),
            )
            .expect("capacity beyond the active turn remains borrowable");
        assert!(matches!(
            port.acquire(
                &third,
                ResourceAuthorityClass::Admitted,
                ResourceClaim::single(ResourceClass::StorageBytes, 2),
            ),
            Err(ResourceUnavailable::Pressure(_))
        ));
        drop(borrowed_surplus);
        drop(demand);
        drop(first_lease);
    }

    #[test]
    fn pending_turn_cannot_be_bypassed_by_new_child_bookkeeping() {
        let grant = claim(&[
            (ResourceClass::QueuedBytes, 1),
            (ResourceClass::StorageObject, 1),
            (ResourceClass::OpaqueDependencyResidual, 6),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider).expect("process bookkeeping");
        let process = port.process_scope();
        let first = port.create_scope(&process).expect("first scope");
        let second = port.create_scope(&process).expect("second scope");
        let queue = ResourceClaim::single(ResourceClass::QueuedBytes, 1);
        let (first_target, _first_subscription) = ResourceReclaimSubscription::channel();
        let first_lease = port
            .acquire_reclaimable_now(&first, queue, first_target)
            .expect("queue owner");
        let demand = pending(
            port.acquire_cooperatively(&second, ResourceAuthorityClass::Admitted, queue, None)
                .expect("active queue demand"),
        );

        assert!(matches!(
            port.create_scope_with_lease(
                &process,
                ResourceAuthorityClass::Admitted,
                ResourceClaim::single(ResourceClass::StorageObject, 1),
            ),
            Err(ResourceUnavailable::Pressure(ResourcePressure {
                dimension: ResourceClass::OpaqueDependencyResidual,
                ..
            }))
        ));
        drop(demand);
        drop(first_lease);
    }

    #[test]
    fn cleanup_demand_supersedes_a_speculative_turn_without_reclaiming_cleanup() {
        let grant = claim(&[
            (ResourceClass::WorkerOrTask, 1),
            (ResourceClass::OpaqueDependencyResidual, 7),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider).expect("process bookkeeping");
        let process = port.process_scope();
        let first = port.create_scope(&process).expect("first scope");
        // This control needs two simultaneous turns, so the demanding scopes
        // must be distinct fairness roots. One pending demand exists per root,
        // so two ordinary children of the process scope would share a single
        // turn and the second cooperative call would be refused.
        let second = port
            .create_fairness_root_scope()
            .expect("speculative demander root");
        let third = port
            .create_fairness_root_scope()
            .expect("cleanup demander root");
        let worker = ResourceClaim::single(ResourceClass::WorkerOrTask, 1);
        let (first_target, first_subscription) = ResourceReclaimSubscription::channel();
        let first_lease = port
            .acquire_reclaimable_now(&first, worker, first_target)
            .expect("first speculative owner");
        let (second_target, _second_subscription) = ResourceReclaimSubscription::channel();
        let speculative = pending(
            port.acquire_cooperatively(
                &second,
                ResourceAuthorityClass::Speculative,
                worker,
                Some(second_target),
            )
            .expect("speculative turn"),
        );
        let cleanup = pending(
            port.acquire_cooperatively(&third, ResourceAuthorityClass::Cleanup, worker, None)
                .expect("cleanup turn"),
        );
        assert!(first_subscription.is_requested());
        drop(first_lease);
        let cleanup_lease = acquired(cleanup.retry().expect("cleanup has structural priority"));
        assert!(matches!(
            speculative.retry(),
            Err(ResourceUnavailable::Pressure(_))
        ));
        drop(cleanup_lease);
    }

    #[test]
    fn impossible_claim_creates_no_demand_and_requests_no_victim() {
        let grant = claim(&[
            (ResourceClass::StorageBytes, 1),
            (ResourceClass::OpaqueDependencyResidual, 5),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider).expect("process bookkeeping");
        let process = port.process_scope();
        let first = port.create_scope(&process).expect("first scope");
        let second = port.create_scope(&process).expect("second scope");
        let one = ResourceClaim::single(ResourceClass::StorageBytes, 1);
        let (victim_target, victim_subscription) = ResourceReclaimSubscription::channel();
        let victim = port
            .acquire_reclaimable_now(&first, one, victim_target)
            .expect("finite victim");
        let (impossible_target, impossible_subscription) = ResourceReclaimSubscription::channel();
        assert!(matches!(
            port.acquire_cooperatively(
                &second,
                ResourceAuthorityClass::Speculative,
                ResourceClaim::single(ResourceClass::StorageBytes, 2),
                Some(impossible_target),
            ),
            Err(ResourceUnavailable::Pressure(_))
        ));
        assert!(!victim_subscription.is_requested());
        assert!(!impossible_subscription.is_requested());
        drop(victim);
    }

    #[test]
    fn dropping_a_pregranted_child_demand_releases_scope_and_reservation() {
        let grant = claim(&[
            (ResourceClass::SocketOrHandle, 1),
            (ResourceClass::OpaqueDependencyResidual, 5),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).expect("process bookkeeping");
        let process = port.process_scope();
        let socket = ResourceClaim::single(ResourceClass::SocketOrHandle, 1);
        let (first_target, _first_subscription) = ResourceReclaimSubscription::channel();
        let first = acquired(
            port.create_scope_with_reclaimable_lease_cooperatively(&process, socket, first_target)
                .expect("first child"),
        );
        let (second_target, _second_subscription) = ResourceReclaimSubscription::channel();
        let second = pending(
            port.create_scope_with_reclaimable_lease_cooperatively(&process, socket, second_target)
                .expect("second provisional child"),
        );
        drop(first);
        assert_eq!(provider.active_reservations(), 1);
        drop(second);
        assert_eq!(provider.active_reservations(), 0);
        assert_eq!(provider.active_scopes(), 1);
        assert_eq!(provider.in_use().amount(ResourceClass::SocketOrHandle), 0);
    }

    #[test]
    fn slow_speculation_has_no_elapsed_time_reclaim_semantics() {
        let grant = claim(&[
            (ResourceClass::WorkerOrTask, 1),
            (ResourceClass::OpaqueDependencyResidual, 2),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider).expect("process bookkeeping");
        let (target, subscription) = ResourceReclaimSubscription::channel();
        let lease = acquired(
            port.acquire_cooperatively(
                &port.process_scope(),
                ResourceAuthorityClass::Speculative,
                ResourceClaim::single(ResourceClass::WorkerOrTask, 1),
                Some(target),
            )
            .expect("slow speculative work"),
        );
        std::thread::yield_now();
        std::thread::yield_now();
        assert!(!subscription.is_requested());
        assert_eq!(lease.authority(), ResourceAuthorityClass::Speculative);
        drop(lease);
    }

    #[test]
    fn reclaim_and_promotion_are_linearized_in_both_orders() {
        let grant = claim(&[
            (ResourceClass::NativeTransportObject, 1),
            (ResourceClass::OpaqueDependencyResidual, 5),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider).expect("process bookkeeping");
        // Victim and requester must be distinct fairness roots. Reclaim
        // sequencing keys the requester by root, so a same-root requester would
        // be asking to victimize its own root's reservation and the test would
        // no longer exercise cross-holder reclaim.
        let first = port.create_fairness_root_scope().expect("victim root");
        let second = port.create_fairness_root_scope().expect("requester root");
        let native = ResourceClaim::single(ResourceClass::NativeTransportObject, 1);

        let (promoted_target, promoted_subscription) = ResourceReclaimSubscription::channel();
        let mut promoted = acquired(
            port.acquire_cooperatively(
                &first,
                ResourceAuthorityClass::Speculative,
                native,
                Some(promoted_target),
            )
            .expect("speculative lease"),
        );
        promoted
            .transition_to(ResourceAuthorityClass::Admitted, native)
            .expect("promotion wins provider lock");
        assert!(matches!(
            port.acquire_cooperatively(&second, ResourceAuthorityClass::Admitted, native, None,),
            Err(ResourceUnavailable::Pressure(_))
        ));
        assert!(!promoted_subscription.is_requested());
        drop(promoted);

        let (reclaimed_target, reclaimed_subscription) = ResourceReclaimSubscription::channel();
        let mut reclaimed = acquired(
            port.acquire_cooperatively(
                &first,
                ResourceAuthorityClass::Speculative,
                native,
                Some(reclaimed_target),
            )
            .expect("replacement speculative lease"),
        );
        let waiter = pending(
            port.acquire_cooperatively(&second, ResourceAuthorityClass::Admitted, native, None)
                .expect("replacement demand"),
        );
        assert!(reclaimed_subscription.is_requested());
        assert!(matches!(
            reclaimed.transition_to(ResourceAuthorityClass::Admitted, native),
            Err(ResourceUnavailable::ReclaimRequested { .. })
        ));
        reclaimed
            .transition_to(ResourceAuthorityClass::Cleanup, native)
            .expect("cleanup authority preserves the reclaim obligation");
        drop(reclaimed);
        drop(acquired(
            waiter.retry().expect("waiter receives released capacity"),
        ));
    }

    #[test]
    fn failed_reclaim_cleanup_retains_charge_and_reports_exact_pressure() {
        let grant = claim(&[
            (ResourceClass::NativeTransportObject, 1),
            (ResourceClass::OpaqueDependencyResidual, 5),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).expect("process bookkeeping");
        // Victim and Cleanup requester are distinct fairness roots. Reclaim
        // sequencing keys the requester by root and orders its own root's
        // reservations last, so a same-root pair would no longer exercise
        // cross-holder reclaim and failed-cleanup retention.
        let first = port.create_fairness_root_scope().expect("victim root");
        let second = port
            .create_fairness_root_scope()
            .expect("cleanup requester root");
        let native = ResourceClaim::single(ResourceClass::NativeTransportObject, 1);
        let (target, subscription) = ResourceReclaimSubscription::channel();
        let victim = acquired(
            port.acquire_cooperatively(
                &first,
                ResourceAuthorityClass::Speculative,
                native,
                Some(target),
            )
            .expect("speculative native object"),
        );
        let demand = pending(
            port.acquire_cooperatively(&second, ResourceAuthorityClass::Cleanup, native, None)
                .expect("cleanup demand"),
        );
        assert!(subscription.is_requested());
        assert_eq!(
            victim.retain_after_failed_cleanup(),
            ReclaimResult::Retained(native)
        );
        assert_eq!(provider.retained_after_failed_cleanup(), native);
        assert!(matches!(
            demand.retry(),
            Err(ResourceUnavailable::Pressure(ResourcePressure {
                dimension: ResourceClass::NativeTransportObject,
                ..
            }))
        ));
        assert_eq!(
            provider
                .in_use()
                .amount(ResourceClass::NativeTransportObject),
            1
        );
    }

    #[test]
    fn cooperative_child_scope_and_first_lease_remain_one_transaction() {
        let grant = claim(&[
            (ResourceClass::SocketOrHandle, 1),
            (ResourceClass::OpaqueDependencyResidual, 5),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).expect("process bookkeeping");
        let process = port.process_scope();
        let socket = ResourceClaim::single(ResourceClass::SocketOrHandle, 1);
        let (first_target, first_subscription) = ResourceReclaimSubscription::channel();
        let first = acquired(
            port.create_scope_with_reclaimable_lease_cooperatively(&process, socket, first_target)
                .expect("first atomic child admission"),
        );
        let first_scope_id = first.scope_id();
        let (second_target, _second_subscription) = ResourceReclaimSubscription::channel();
        let second = pending(
            port.create_scope_with_reclaimable_lease_cooperatively(&process, socket, second_target)
                .expect("second child remains provisional"),
        );
        assert!(first_subscription.is_requested());
        assert_eq!(provider.active_scopes(), 2);
        drop(first);
        let second = acquired(second.retry().expect("second atomic child is committed"));
        assert_ne!(second.scope_id(), first_scope_id);
        assert_eq!(provider.active_reservations(), 1);
        drop(second);
    }

    #[test]
    fn equal_authority_demands_rotate_without_cross_scope_reacquisition() {
        let grant = claim(&[
            (ResourceClass::CallbackOrScheduledWork, 1),
            (ResourceClass::OpaqueDependencyResidual, 7),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider).expect("process bookkeeping");
        // Rotation is across turn holders, and a turn belongs to a fairness
        // root. These three must therefore be distinct trusted roots: as
        // ordinary children of the process scope they would share one turn and
        // the second pending demand would be refused.
        let first = port.create_fairness_root_scope().expect("first root");
        let second = port.create_fairness_root_scope().expect("second root");
        let third = port.create_fairness_root_scope().expect("third root");
        let callback = ResourceClaim::single(ResourceClass::CallbackOrScheduledWork, 1);
        let (target, subscription) = ResourceReclaimSubscription::channel();
        let first_lease = acquired(
            port.acquire_cooperatively(
                &first,
                ResourceAuthorityClass::Speculative,
                callback,
                Some(target),
            )
            .expect("first owner"),
        );
        let (second_target, second_subscription) = ResourceReclaimSubscription::channel();
        let second_demand = pending(
            port.acquire_cooperatively(
                &second,
                ResourceAuthorityClass::Speculative,
                callback,
                Some(second_target),
            )
            .expect("second demand"),
        );
        let (third_target, _third_subscription) = ResourceReclaimSubscription::channel();
        let third_demand = pending(
            port.acquire_cooperatively(
                &third,
                ResourceAuthorityClass::Speculative,
                callback,
                Some(third_target),
            )
            .expect("third demand"),
        );
        assert!(subscription.is_requested());
        drop(first_lease);
        let second_lease = acquired(second_demand.retry().expect("second scope receives turn"));
        assert!(second_subscription.is_requested());
        drop(second_lease);
        let third_lease = acquired(
            third_demand
                .retry()
                .expect("third scope receives next turn"),
        );
        drop(third_lease);
    }

    /// One claim funds one shared allocation, and funds it until the last
    /// handle of *either* kind is gone.
    ///
    /// Three separate things would each break this, and each is asserted apart
    /// from the others rather than folded into one end-to-end number:
    ///
    /// - **Cloning must share, not re-acquire.** If a clone took out its own
    ///   reservation the ledger would climb with every handle, so the grant is
    ///   deliberately far larger than one unit — a control that could only fail
    ///   by running out of capacity would be measuring the wrong thing. The
    ///   assertion is that `in_use` does not move at all across three strong
    ///   clones and a weak one.
    /// - **A weak handle must keep the funding.** This is the discriminating
    ///   arm. Dropping every strong handle destroys the value but *not* the
    ///   allocation, because a live `Weak` keeps the backing storage alive. A
    ///   design that released on the last strong drop would pass every other
    ///   assertion here and still be telling the provider that occupied memory
    ///   was free. `upgrade` returning `None` is what proves the value really
    ///   is gone at that point, so the funding that remains is funding for
    ///   storage and not for a value still in use.
    /// - **The last handle must release exactly the original claim.** Not less,
    ///   which would leak; not more, which would mean the shared handles had
    ///   been charged for separately after all.
    #[test]
    fn v4_r3_core_one_claim_funds_a_shared_allocation_until_its_last_handle() {
        let grant = claim(&[
            (ResourceClass::QueuedBytes, 8),
            (ResourceClass::OpaqueDependencyResidual, 4096),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).expect("process bookkeeping");
        let scope = port.process_scope();
        let one = ResourceClaim::single(ResourceClass::QueuedBytes, 1);

        let idle = provider.in_use().amount(ResourceClass::QueuedBytes);
        let lease = port
            .acquire(&scope, ResourceAuthorityClass::Admitted, one)
            .expect("the grant funds one shared allocation");
        let funded = FundedArc::new(7_u32, lease).expect("an admitted lease may be shared");
        let held = provider.in_use().amount(ResourceClass::QueuedBytes);
        assert_eq!(held, idle + 1, "the allocation is funded exactly once");

        let second = funded.clone();
        let third = funded.clone();
        let weak = funded.downgrade();
        assert_eq!(
            provider.in_use().amount(ResourceClass::QueuedBytes),
            held,
            "four handles share one reservation and take out no second one"
        );
        assert_eq!(*second, 7, "a clone reaches the same value");
        assert_eq!(*third, 7);
        assert_eq!(funded.strong_count(), 3);

        drop((funded, second, third));
        assert!(
            weak.upgrade().is_none(),
            "every strong handle is gone, so the value is destroyed"
        );
        assert_eq!(
            provider.in_use().amount(ResourceClass::QueuedBytes),
            held,
            "a live weak handle still reaches the allocation, so the funding stays"
        );

        drop(weak);
        assert_eq!(
            provider.in_use().amount(ResourceClass::QueuedBytes),
            idle,
            "the final handle releases exactly the claim the first one took"
        );
    }

    /// A speculative lease is refused for sharing, and comes back funding
    /// exactly what it funded before.
    ///
    /// The refusal returns the lease itself rather than an error code, so the
    /// arm that matters is the ledger: a refusal that dropped the lease on the
    /// way out would look like a clean rejection and would silently release the
    /// caller's funding underneath it.
    #[test]
    fn v4_r3_core_a_speculative_lease_is_refused_for_sharing_and_keeps_its_funding() {
        let grant = claim(&[
            (ResourceClass::QueuedBytes, 4),
            (ResourceClass::OpaqueDependencyResidual, 4096),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).expect("process bookkeeping");
        let scope = port.process_scope();
        let one = ResourceClaim::single(ResourceClass::QueuedBytes, 1);

        let idle = provider.in_use().amount(ResourceClass::QueuedBytes);
        let lease = port
            .acquire(&scope, ResourceAuthorityClass::Speculative, one)
            .expect("the grant funds one speculative allocation");
        let held = provider.in_use().amount(ResourceClass::QueuedBytes);
        assert_eq!(held, idle + 1);

        let returned = FundedArc::new(7_u32, lease)
            .err()
            .expect("a speculative reservation may not be shared");
        assert_eq!(
            provider.in_use().amount(ResourceClass::QueuedBytes),
            held,
            "the refused lease still funds its allocation"
        );

        drop(returned);
        assert_eq!(
            provider.in_use().amount(ResourceClass::QueuedBytes),
            idle,
            "and releases normally when the caller is done with it"
        );
    }
}
