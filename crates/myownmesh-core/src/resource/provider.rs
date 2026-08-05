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

/// Result of a cooperative resource acquisition.
#[must_use = "a pending demand owns a fairness turn and dropping it cancels that turn"]
#[derive(Debug)]
pub enum ResourceAdmission {
    Acquired(ResourceLease),
    Pending(ResourceAcquireDemand),
}

/// Move-only ownership of one scope's bounded pending admission demand.
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
    enum ReservationLifecycle {
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
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum DemandPlacement {
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

    #[derive(Debug, Default)]
    struct ScopeRecord {
        pending: Option<PendingDemand>,
    }

    #[derive(Debug)]
    struct ActiveDemand {
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
        demand_cursor: [Option<ResourceScopeId>; 3],
        reclaim_cursor: Option<ResourceScopeId>,
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
                    #[cfg(test)]
                    scripted_pressure: VecDeque::new(),
                })),
            }
        }

        #[cfg(any(test, feature = "transport-lab"))]
        pub(crate) fn scope_record_charge_for_test() -> ResourceClaim {
            Self::bookkeeping_claim()
        }

        #[cfg(any(test, feature = "transport-lab"))]
        pub(crate) fn reservation_charge_for_test(
            claim: ResourceClaim,
        ) -> Result<ResourceClaim, ResourceUnavailable> {
            Self::reservation_charge(claim)
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
            if let Some(reused) = state.free_reservation_ids.pop_first() {
                return Ok(reused);
            }
            let next = state
                .next_reservation_id
                .ok_or(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                })?;
            state.next_reservation_id = next.checked_add(1);
            Ok(next)
        }

        fn demand_matches(pending: &PendingDemand, identity: &ResourceDemandIdentity) -> bool {
            Arc::ptr_eq(&pending.identity.signal, &identity.signal)
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

        fn select_scope_after_cursor(
            state: &State,
            authority: ResourceAuthorityClass,
        ) -> Option<ResourceScopeId> {
            let cursor = state.demand_cursor[Self::authority_index(authority)];
            state
                .scopes
                .iter()
                .filter(|(scope_id, _)| cursor.is_none_or(|cursor| **scope_id > cursor))
                .find_map(|(scope_id, scope)| {
                    scope
                        .pending
                        .as_ref()
                        .is_some_and(|pending| pending.authority == authority)
                        .then_some(*scope_id)
                })
                .or_else(|| {
                    state.scopes.iter().find_map(|(scope_id, scope)| {
                        scope
                            .pending
                            .as_ref()
                            .is_some_and(|pending| pending.authority == authority)
                            .then_some(*scope_id)
                    })
                })
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
            let scope_id = Self::select_scope_after_cursor(state, highest)?;
            let Some(identity) = state
                .scopes
                .get(&scope_id)
                .and_then(|scope| scope.pending.as_ref())
                .map(|pending| pending.identity.duplicate())
            else {
                Self::poison(state, ResourceClass::OpaqueDependencyResidual);
                return None;
            };
            state.active_demand = Some(ActiveDemand { scope_id, identity });
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

        fn select_reclaim_victims(
            state: &mut State,
            requester_scope: ResourceScopeId,
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
            let mut candidates: Vec<(ResourceScopeId, u64)> = state
                .reservations
                .iter()
                .filter_map(|(reservation_id, reservation)| {
                    ((reservation.authority == ResourceAuthorityClass::Speculative
                        && reservation.reclaim_target.is_some())
                        || reservation.lifecycle == ReservationLifecycle::ReclaimRequested)
                        .then_some((reservation.scope_id, *reservation_id))
                })
                .collect();
            candidates.sort_by_key(|(scope_id, reservation_id)| {
                (
                    *scope_id == requester_scope,
                    cursor.is_some_and(|cursor| *scope_id <= cursor),
                    *scope_id,
                    *reservation_id,
                )
            });

            let mut selected = Vec::new();
            for (victim_scope, reservation_id) in candidates {
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
                selected.push((victim_scope, reservation_id, target));
            }
            if !deficit.is_zero() {
                return false;
            }
            for (_, reservation_id, _) in &selected {
                let Some(reservation) = state.reservations.get_mut(reservation_id) else {
                    Self::poison(state, ResourceClass::OpaqueDependencyResidual);
                    return false;
                };
                if reservation.lifecycle == ReservationLifecycle::Live {
                    reservation.lifecycle = ReservationLifecycle::ReclaimRequested;
                }
            }
            for (_, _, target) in &selected {
                if let Some(target) = target {
                    target.request();
                }
            }
            if let Some((last_selected, _, _)) = selected.last() {
                state.reclaim_cursor = Some(*last_selected);
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
                    let Some(pending) = state
                        .scopes
                        .get_mut(&scope_id)
                        .and_then(|scope| scope.pending.take())
                    else {
                        Self::poison(state, ResourceClass::OpaqueDependencyResidual);
                        return;
                    };
                    let reservation_id = match Self::allocate_reservation_id(state) {
                        Ok(reservation_id) => reservation_id,
                        Err(_) => {
                            Self::poison(state, ResourceClass::OpaqueDependencyResidual);
                            return;
                        }
                    };
                    let next = match state.in_use.checked_add(charge) {
                        Ok(next) => next,
                        Err(_) => {
                            Self::poison(state, ResourceClass::OpaqueDependencyResidual);
                            return;
                        }
                    };
                    if let DemandPlacement::NewChild { scope_id } = placement {
                        if state
                            .scopes
                            .insert(scope_id, ScopeRecord::default())
                            .is_some()
                        {
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
                        },
                    );
                    state.in_use = next;
                    state.demand_cursor[Self::authority_index(authority)] = Some(scope_id);
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

                if Self::select_reclaim_victims(state, lease_scope_id, charge) {
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
                state.demand_cursor[Self::authority_index(authority)] = Some(scope_id);
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
            let base = state.in_use;
            let (_, next) = Self::checked_admission(
                &mut state,
                base,
                scope_id,
                ResourceAuthorityClass::Speculative,
                &[bookkeeping],
            )?;
            state.scopes.insert(scope_id, ScopeRecord::default());
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
            let reservation_id = Self::allocate_reservation_id(&mut state)?;
            state.scopes.insert(scope_id, ScopeRecord::default());
            state.reservations.insert(
                reservation_id,
                Reservation {
                    scope_id,
                    authority,
                    claim,
                    lifecycle: ReservationLifecycle::Live,
                    reclaim_target: None,
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
            if state
                .scopes
                .get(&parent_scope_id)
                .is_some_and(|scope| scope.pending.is_some())
            {
                return Err(ResourceUnavailable::DemandPending {
                    scope_id: parent_scope_id,
                });
            }
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
                state.scopes.insert(scope_id, ScopeRecord::default());
                state.reservations.insert(
                    reservation_id,
                    Reservation {
                        scope_id,
                        authority: ResourceAuthorityClass::Speculative,
                        claim,
                        lifecycle: ReservationLifecycle::Live,
                        reclaim_target: Some(reclaim_target),
                    },
                );
                return Ok(ResourceProviderAdmission::Acquired(reservation_id));
            }

            let identity = ResourceDemandIdentity {
                signal: Arc::new(DemandSignal {
                    outcome: Mutex::new(DemandOutcome::Waiting),
                    ready: Notify::new(),
                }),
            };
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
            state.scopes.remove(&scope_id);
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
            if state
                .scopes
                .get(&scope_id)
                .is_some_and(|scope| scope.pending.is_some())
            {
                return Err(ResourceUnavailable::DemandPending { scope_id });
            }
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
                    },
                );
                return Ok(ResourceProviderAdmission::Acquired(reservation_id));
            }

            let identity = ResourceDemandIdentity {
                signal: Arc::new(DemandSignal {
                    outcome: Mutex::new(DemandOutcome::Waiting),
                    ready: Notify::new(),
                }),
            };
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
                    demand.signal.set(DemandOutcome::Cancelled);
                    Self::arbitrate(&mut state);
                }
                DemandOutcome::Granted {
                    reservation_id,
                    created_scope_id,
                } => {
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
                    state.reservations.remove(&reservation_id);
                    if let Some(created_scope_id) = created_scope_id {
                        let removable = state
                            .scopes
                            .get(&created_scope_id)
                            .is_some_and(|scope| scope.pending.is_none());
                        if !removable {
                            Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                            return;
                        }
                        state.scopes.remove(&created_scope_id);
                    }
                    state.free_reservation_ids.insert(reservation_id);
                    state.in_use = next;
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
pub(crate) mod test_support {
    pub(crate) use super::FiniteResourceProvider as DeterministicGrantProvider;
}

#[cfg(test)]
mod tests {
    use super::test_support::DeterministicGrantProvider;
    use super::*;

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

    #[test]
    fn insufficient_reclaim_set_is_not_published() {
        let grant = claim(&[
            (ResourceClass::QueuedBytes, 2),
            (ResourceClass::OpaqueDependencyResidual, 7),
        ]);
        let provider = DeterministicGrantProvider::new(grant);
        let port = ResourceProviderPort::new(provider).expect("process bookkeeping");
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
        let process = port.process_scope();
        let first = port.create_scope(&process).expect("first scope");
        let second = port.create_scope(&process).expect("second scope");
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
        let second = port.create_scope(&process).expect("second scope");
        let third = port.create_scope(&process).expect("third scope");
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
        let process = port.process_scope();
        let first = port.create_scope(&process).expect("first scope");
        let second = port.create_scope(&process).expect("second scope");
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
        let process = port.process_scope();
        let first = port.create_scope(&process).expect("first scope");
        let second = port.create_scope(&process).expect("second scope");
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
        let process = port.process_scope();
        let first = port.create_scope(&process).expect("first scope");
        let second = port.create_scope(&process).expect("second scope");
        let third = port.create_scope(&process).expect("third scope");
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
}
