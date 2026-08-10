//! Provider-backed process and per-Mesh connector resource ownership.

use super::*;
use crate::resource::{
    ReclaimResult, ResourceAdmission, ResourceAuthorityClass, ResourceClaim, ResourceClass,
    ResourceLease, ResourceProviderPort, ResourceReclaimSubscription, ResourceReclaimTarget,
    ResourceScope, ResourceUnavailable,
};
use futures_util::FutureExt;

/// Point-in-time diagnostics for one exact live Mesh connector scope.
///
/// These values report ownership events. They never grant capacity or reject
/// provider-approved work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MeshConnectorResourceReport {
    pub active_candidates: usize,
    pub failed_cleanup_candidates: usize,
    pub accounting_poisoned: bool,
}

/// The selected resource provider could not issue a Mesh attribution scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MeshConnectorResourceScopeIssueError {
    #[error("the process resource provider is not installed")]
    ResourceProviderMissing,
    #[error("the connector resource provider refused the Mesh scope: {0}")]
    ResourceUnavailable(#[from] ResourceUnavailable),
}

#[derive(Default)]
struct ConnectorResourceDiagnosticsState {
    active_candidates: usize,
    failed_cleanup_candidates: usize,
    accounting_poisoned: bool,
}

#[derive(Default)]
pub(super) struct ConnectorResourceDiagnostics {
    state: Mutex<ConnectorResourceDiagnosticsState>,
}

impl ConnectorResourceDiagnostics {
    fn note_acquired(&self) {
        let mut state = self.lock();
        match state.active_candidates.checked_add(1) {
            Some(active) => state.active_candidates = active,
            None => state.accounting_poisoned = true,
        }
    }

    fn note_released(&self) {
        let mut state = self.lock();
        match state.active_candidates.checked_sub(1) {
            Some(active) => state.active_candidates = active,
            None => state.accounting_poisoned = true,
        }
    }

    fn note_failed_cleanup(&self) {
        let mut state = self.lock();
        match state.failed_cleanup_candidates.checked_add(1) {
            Some(failed) => state.failed_cleanup_candidates = failed,
            None => state.accounting_poisoned = true,
        }
    }

    fn poison(&self) {
        self.lock().accounting_poisoned = true;
    }

    fn report(&self) -> MeshConnectorResourceReport {
        let state = self.lock();
        MeshConnectorResourceReport {
            active_candidates: state.active_candidates,
            failed_cleanup_candidates: state.failed_cleanup_candidates,
            accounting_poisoned: state.accounting_poisoned,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ConnectorResourceDiagnosticsState> {
        self.state.lock().unwrap_or_else(|poisoned| {
            let mut state = poisoned.into_inner();
            state.accounting_poisoned = true;
            state
        })
    }
}

pub(super) fn poison_reservation_diagnostics(
    process_diagnostics: &ConnectorResourceDiagnostics,
    mesh_diagnostics: &ConnectorResourceDiagnostics,
) {
    process_diagnostics.poison();
    mesh_diagnostics.poison();
}

pub(super) struct ConnectorResourceOwnerInner {
    provider: ResourceProviderPort,
    process_scope: ResourceScope,
    diagnostics: Arc<ConnectorResourceDiagnostics>,
    cleanup_executor: ConnectorCleanupExecutor,
}

impl ConnectorResourceOwnerInner {
    fn new(provider: ResourceProviderPort) -> Self {
        let process_scope = provider.process_scope();
        Self {
            provider,
            process_scope,
            diagnostics: Arc::new(ConnectorResourceDiagnostics::default()),
            cleanup_executor: ConnectorCleanupExecutor::new(),
        }
    }

    fn issue_mesh_scope(
        self: &Arc<Self>,
    ) -> Result<MeshConnectorResourceScope, MeshConnectorResourceScopeIssueError> {
        self.cleanup_executor
            .prepare(&self.provider, &self.process_scope)?;
        let scope = self.provider.create_scope(&self.process_scope)?;
        Ok(MeshConnectorResourceScope {
            token: Arc::new(MeshConnectorResourceScopeToken {
                owner: Arc::clone(self),
                scope,
                diagnostics: Arc::new(ConnectorResourceDiagnostics::default()),
            }),
        })
    }

    fn report(&self) -> ConnectorResourceOwnerReport {
        let diagnostics = self.diagnostics.report();
        ConnectorResourceOwnerReport {
            active_candidates: diagnostics.active_candidates,
            failed_cleanup_candidates: diagnostics.failed_cleanup_candidates,
            accounting_poisoned: diagnostics.accounting_poisoned,
            cleanup: self.cleanup_executor.report(),
        }
    }
}

/// Cloneable administrative port into one process resource provider.
///
/// It cannot admit work directly. It only issues attribution scopes that draw
/// from the exact provider identity supplied by the process owner.
#[derive(Clone)]
pub struct ConnectorResourceOwnerPort {
    inner: Arc<ConnectorResourceOwnerInner>,
}

impl ConnectorResourceOwnerPort {
    pub(crate) fn new(provider: ResourceProviderPort) -> Self {
        Self {
            inner: Arc::new(ConnectorResourceOwnerInner::new(provider)),
        }
    }

    pub fn report(&self) -> ConnectorResourceOwnerReport {
        self.inner.report()
    }

    pub(crate) fn issue_mesh_scope(
        &self,
    ) -> Result<MeshConnectorResourceScope, MeshConnectorResourceScopeIssueError> {
        self.inner.issue_mesh_scope()
    }

    pub(crate) fn same_provider(&self, provider: &ResourceProviderPort) -> bool {
        self.inner.provider.same_provider(provider)
    }
}

/// One-shot proof that an exact connector reservation has entered cleanup.
///
/// The capability retains the reservation state, including its move-only
/// provider lease, until the queued or running cleanup job is destroyed. It
/// cannot be cloned and one reservation can mint it only once.
pub(crate) struct ConnectorCleanupCapability {
    pub(super) reservation: Arc<ConnectorCandidateReservationState>,
}

pub(super) struct MeshConnectorResourceScopeToken {
    pub(super) owner: Arc<ConnectorResourceOwnerInner>,
    pub(super) scope: ResourceScope,
    diagnostics: Arc<ConnectorResourceDiagnostics>,
}

/// Exact process-local resource scope for work owned by one connector.
///
/// Cloning this port preserves attribution to the same connector. It does not
/// grant capacity. Every successful acquisition still creates a distinct,
/// finite provider lease.
#[derive(Clone)]
pub(crate) struct ConnectorWorkResourceScope {
    provider: ResourceProviderPort,
    scope: ResourceScope,
    reclaim_target: Option<ResourceReclaimTarget>,
}

impl ConnectorWorkResourceScope {
    pub(crate) fn scope_id(&self) -> crate::resource::ResourceScopeId {
        self.scope.id()
    }

    pub(crate) fn acquire(
        &self,
        authority: ResourceAuthorityClass,
        claim: ResourceClaim,
    ) -> Result<ResourceLease, ResourceUnavailable> {
        match (authority, self.reclaim_target.as_ref()) {
            (ResourceAuthorityClass::Speculative, Some(target)) => self
                .provider
                .acquire_reclaimable_now(&self.scope, claim, target.clone()),
            _ => self.provider.acquire(&self.scope, authority, claim),
        }
    }

    #[cfg(test)]
    pub(crate) fn pressure(
        &self,
        authority: ResourceAuthorityClass,
        dimension: ResourceClass,
    ) -> Result<crate::resource::ResourcePressure, ResourceUnavailable> {
        self.provider.pressure(&self.scope, authority, dimension)
    }
}

/// Unforgeable attribution and admission scope for one live [`crate::Mesh`]
/// runtime.
///
/// Scope creation grants no capacity. Clones retain the same provider child
/// scope, and every connector candidate acquires a separate child lease from
/// the process owner's shared finite grant.
#[derive(Clone)]
pub struct MeshConnectorResourceScope {
    pub(super) token: Arc<MeshConnectorResourceScopeToken>,
}

impl MeshConnectorResourceScope {
    pub fn report(&self) -> MeshConnectorResourceReport {
        self.token.diagnostics.report()
    }

    pub(crate) fn process_report(&self) -> ConnectorResourceOwnerReport {
        self.token.owner.report()
    }

    pub(crate) fn submit_cleanup(
        &self,
        capability: ConnectorCleanupCapability,
        cleanup: ConnectorCleanupFuture,
        on_complete: ConnectorCleanupCompletion,
        on_failure: ConnectorCleanupFailure,
    ) -> std::result::Result<(), ConnectorCleanupJob> {
        if !Arc::ptr_eq(
            &capability.reservation.process_diagnostics,
            &self.token.owner.diagnostics,
        ) {
            return Err(ConnectorCleanupJob::new(
                capability,
                cleanup,
                on_complete,
                on_failure,
            ));
        }
        self.token
            .owner
            .cleanup_executor
            .submit(ConnectorCleanupJob::new(
                capability,
                cleanup,
                on_complete,
                on_failure,
            ))
    }

    /// Mark the diagnostics inexact without replacing provider truth.
    pub(crate) fn poison_accounting(&self) {
        self.token.owner.diagnostics.poison();
        self.token.diagnostics.poison();
    }

    #[cfg(test)]
    pub(crate) fn fail_cleanup_executor_for_test(&self) {
        self.token.owner.cleanup_executor.fail_for_test();
    }

    /// Reserve post-authentication session capacity from this Mesh's grant.
    ///
    /// `Admitted` authority, not `Speculative`: a promoted session is not
    /// candidate work and must not be reclaimed as though it were. This is the
    /// explicit resource transition promotion performs — a successful
    /// pre-authentication lease is not reusable as proof that this capacity
    /// exists, so the claim is acquired fresh here or the promotion refuses.
    ///
    /// The lease is returned bare rather than wrapped in a candidate
    /// reservation: a session has no candidate lifecycle, no cleanup job, and no
    /// reclaim subscription. Dropping it releases exactly this reservation.
    pub(crate) fn reserve_session(
        &self,
        claim: ResourceClaim,
    ) -> Result<ResourceLease, ResourceUnavailable> {
        self.token.owner.provider.acquire(
            &self.token.scope,
            ResourceAuthorityClass::Admitted,
            claim,
        )
    }

    pub(super) fn reserve(
        &self,
        claim: ResourceClaim,
    ) -> Result<ConnectorCandidateReservation, ResourceUnavailable> {
        let (connector_scope, lease) = self.token.owner.provider.create_scope_with_lease(
            &self.token.scope,
            ResourceAuthorityClass::Speculative,
            claim,
        )?;
        let work_scope = ConnectorWorkResourceScope {
            provider: self.token.owner.provider.clone(),
            scope: connector_scope,
            reclaim_target: None,
        };
        self.token.owner.diagnostics.note_acquired();
        self.token.diagnostics.note_acquired();
        Ok(ConnectorCandidateReservation {
            state: Arc::new(ConnectorCandidateReservationState {
                lease: Mutex::new(Some(lease)),
                work_scope,
                process_diagnostics: Arc::clone(&self.token.owner.diagnostics),
                mesh_diagnostics: Arc::clone(&self.token.diagnostics),
                cleanup_capability_issued: AtomicBool::new(false),
                cleanup_lifecycle: Mutex::new(Default::default()),
            }),
        })
    }

    /// Wait for one fair process turn, then atomically install the child scope
    /// and its first reclaimable speculative lease.
    ///
    /// No time limit applies. The pending demand is move-only and cancellation
    /// drops its fairness turn without installing an empty child scope.
    pub(super) async fn reserve_cooperatively(
        &self,
        claim: ResourceClaim,
    ) -> Result<(ConnectorCandidateReservation, ResourceReclaimSubscription), ResourceUnavailable>
    {
        let (reclaim_target, reclaim_subscription) = ResourceReclaimSubscription::channel();
        let work_reclaim_target = reclaim_target.clone();
        let mut admission = self
            .token
            .owner
            .provider
            .create_scope_with_reclaimable_lease_cooperatively(
                &self.token.scope,
                claim,
                reclaim_target,
            )?;
        let lease = loop {
            match admission {
                ResourceAdmission::Acquired(lease) => break lease,
                ResourceAdmission::Pending(demand) => {
                    demand.ready().await?;
                    admission = demand.retry()?;
                }
            }
        };
        let work_scope = ConnectorWorkResourceScope {
            provider: self.token.owner.provider.clone(),
            scope: lease.scope(),
            reclaim_target: Some(work_reclaim_target),
        };
        self.token.owner.diagnostics.note_acquired();
        self.token.diagnostics.note_acquired();
        Ok((
            ConnectorCandidateReservation {
                state: Arc::new(ConnectorCandidateReservationState {
                    lease: Mutex::new(Some(lease)),
                    work_scope,
                    process_diagnostics: Arc::clone(&self.token.owner.diagnostics),
                    mesh_diagnostics: Arc::clone(&self.token.diagnostics),
                    cleanup_capability_issued: AtomicBool::new(false),
                    cleanup_lifecycle: Mutex::new(Default::default()),
                }),
            },
            reclaim_subscription,
        ))
    }

    #[cfg(test)]
    pub(super) fn same_provider(&self, other: &Self) -> bool {
        self.token
            .owner
            .provider
            .same_provider(&other.token.owner.provider)
    }
}

pub(crate) type ConnectorCleanupFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
pub(crate) type ConnectorCleanupCompletion = Box<dyn FnOnce() + Send + 'static>;
pub(crate) type ConnectorCleanupFailure = Box<dyn FnOnce(String) + Send + 'static>;

/// Exact connector-owned claim reserved before one cleanup job can exist.
/// Inline bytes cover the queued record and its two linked queue pointers.
/// Four residual units name the boxed close future, boxed completion callback,
/// boxed failure callback, and channel-node allocator metadata whose byte
/// sizes are dependency-owned.
pub(crate) fn cleanup_job_claim(
) -> Result<ResourceClaim, crate::resource::ResourceClaimArithmeticError> {
    let links = std::mem::size_of::<usize>().checked_mul(2).ok_or(
        crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        },
    )?;
    let bytes = std::mem::size_of::<ConnectorCleanupJob>()
        .checked_add(links)
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        })?;
    let bytes = u64::try_from(bytes).map_err(|_| {
        crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        }
    })?;
    ResourceClaim::try_from_entries([
        (ResourceClass::AccountedMemoryBytes, bytes),
        (ResourceClass::WorkerOrTask, 1),
        (ResourceClass::CallbackOrScheduledWork, 1),
        (ResourceClass::OpaqueDependencyResidual, 4),
    ])
}

pub(crate) struct ConnectorCleanupJob {
    _capability: ConnectorCleanupCapability,
    future: Option<ConnectorCleanupFuture>,
    on_complete: Option<ConnectorCleanupCompletion>,
    on_failure: Option<ConnectorCleanupFailure>,
}

impl ConnectorCleanupJob {
    fn new(
        capability: ConnectorCleanupCapability,
        future: ConnectorCleanupFuture,
        on_complete: ConnectorCleanupCompletion,
        on_failure: ConnectorCleanupFailure,
    ) -> Self {
        Self {
            _capability: capability,
            future: Some(future),
            on_complete: Some(on_complete),
            on_failure: Some(on_failure),
        }
    }

    fn fail(&mut self, reason: String) {
        self.future = None;
        self.on_complete = None;
        if let Some(on_failure) = self.on_failure.take() {
            on_failure(reason);
        }
    }

    fn complete(mut self) -> ConnectorCleanupCompletion {
        self.future = None;
        self.on_failure = None;
        let completion = self
            .on_complete
            .take()
            .expect("a successful cleanup job owns one completion callback");
        drop(self);
        completion
    }
}

impl Drop for ConnectorCleanupJob {
    fn drop(&mut self) {
        if self.on_failure.is_some() {
            self.fail("cleanup job terminated before completion".to_string());
        }
    }
}

struct ConnectorCleanupHealthState {
    queued_jobs: AtomicUsize,
    active_jobs: AtomicUsize,
    completed_jobs: std::sync::atomic::AtomicU64,
    failed_jobs: std::sync::atomic::AtomicU64,
    executor_failed: AtomicBool,
}

struct ConnectorCleanupExecutorState {
    sender: Option<tokio::sync::mpsc::UnboundedSender<ConnectorCleanupJob>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// One process-local cleanup executor.
///
/// Submission does not wait and has no second producer queue. The channel is
/// intentionally unbounded because each one-shot job is already backed by the
/// connector lease's pre-reserved `CallbackOrScheduledWork` cleanup claim.
struct ConnectorCleanupExecutor {
    state: Mutex<ConnectorCleanupExecutorState>,
    health: Arc<ConnectorCleanupHealthState>,
    #[cfg(test)]
    forced_termination: Arc<tokio::sync::Notify>,
}

impl ConnectorCleanupExecutor {
    fn new() -> Self {
        Self {
            state: Mutex::new(ConnectorCleanupExecutorState {
                sender: None,
                thread: None,
            }),
            health: Arc::new(ConnectorCleanupHealthState {
                queued_jobs: AtomicUsize::new(0),
                active_jobs: AtomicUsize::new(0),
                completed_jobs: std::sync::atomic::AtomicU64::new(0),
                failed_jobs: std::sync::atomic::AtomicU64::new(0),
                executor_failed: AtomicBool::new(false),
            }),
            #[cfg(test)]
            forced_termination: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Reserve the process cleanup infrastructure before constructing its
    /// runtime, channel, or OS thread. The lease moves into the executor
    /// thread and remains live until every submitted cleanup future ends.
    fn prepare(
        &self,
        provider: &ResourceProviderPort,
        process_scope: &ResourceScope,
    ) -> Result<(), ResourceUnavailable> {
        if self.health.executor_failed.load(Ordering::Acquire) {
            return Err(ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::WorkerOrTask,
            });
        }
        let mut state = self.state.lock().map_err(|_| {
            self.health.executor_failed.store(true, Ordering::Release);
            ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::WorkerOrTask,
            }
        })?;
        if state.sender.is_some() {
            return Ok(());
        }

        let infrastructure_lease = provider.acquire(
            process_scope,
            ResourceAuthorityClass::Cleanup,
            cleanup_executor_infrastructure_claim().map_err(|error| match error {
                crate::resource::ResourceClaimArithmeticError::Overflow { dimension }
                | crate::resource::ResourceClaimArithmeticError::Underflow { dimension } => {
                    ResourceUnavailable::ProviderInvariant { dimension }
                }
            })?,
        )?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::WorkerOrTask,
            })?;
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel::<ConnectorCleanupJob>();
        let health = Arc::clone(&self.health);
        #[cfg(test)]
        let forced_termination = Arc::clone(&self.forced_termination);
        let thread = std::thread::Builder::new()
            .name("myownmesh-connector-cleanup".to_string())
            .spawn(move || {
                let _infrastructure_lease = infrastructure_lease;
                let loop_health = Arc::clone(&health);
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    runtime.block_on(async move {
                        let mut jobs = tokio::task::JoinSet::new();
                        let mut receiver_open = true;
                        let forced_failure = async move {
                            #[cfg(test)]
                            forced_termination.notified().await;
                            #[cfg(not(test))]
                            std::future::pending::<()>().await;
                        };
                        tokio::pin!(forced_failure);
                        loop {
                            if !receiver_open && jobs.is_empty() {
                                break;
                            }
                            tokio::select! {
                                _ = &mut forced_failure => {
                                    panic!("injected cleanup executor termination");
                                }
                                received = receiver.recv(), if receiver_open => {
                                    match received {
                                        Some(mut cleanup) => {
                                            loop_health.queued_jobs.fetch_sub(1, Ordering::AcqRel);
                                            let job_health = Arc::clone(&loop_health);
                                            jobs.spawn(async move {
                                                job_health.active_jobs.fetch_add(1, Ordering::AcqRel);
                                                let future = cleanup
                                                    .future
                                                    .take()
                                                    .expect("queued cleanup job owns one future");
                                                let outcome = std::panic::AssertUnwindSafe(future)
                                                    .catch_unwind()
                                                    .await;
                                                match outcome {
                                                    Ok(()) => {
                                                        let completion = cleanup.complete();
                                                        completion();
                                                        job_health.completed_jobs.fetch_add(1, Ordering::AcqRel);
                                                    }
                                                    Err(_) => {
                                                        cleanup.fail("cleanup future panicked".to_string());
                                                        drop(cleanup);
                                                        job_health.failed_jobs.fetch_add(1, Ordering::AcqRel);
                                                    }
                                                }
                                                job_health.active_jobs.fetch_sub(1, Ordering::AcqRel);
                                            });
                                        }
                                        None => receiver_open = false,
                                    }
                                }
                                completed = jobs.join_next(), if !jobs.is_empty() => {
                                    if completed.is_some_and(|result| result.is_err()) {
                                        loop_health.failed_jobs.fetch_add(1, Ordering::AcqRel);
                                    }
                                }
                            }
                        }
                    });
                }));
                if outcome.is_err() {
                    health.failed_jobs.fetch_add(1, Ordering::AcqRel);
                }
                health.executor_failed.store(true, Ordering::Release);
            })
            .map_err(|_| ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::WorkerOrTask,
            })?;
        state.sender = Some(sender);
        state.thread = Some(thread);
        Ok(())
    }

    fn submit(
        &self,
        mut cleanup: ConnectorCleanupJob,
    ) -> std::result::Result<(), ConnectorCleanupJob> {
        if self.health.executor_failed.load(Ordering::Acquire) {
            self.health.failed_jobs.fetch_add(1, Ordering::AcqRel);
            cleanup.fail("cleanup executor is unavailable".to_string());
            return Err(cleanup);
        }
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => {
                self.health.failed_jobs.fetch_add(1, Ordering::AcqRel);
                cleanup.fail("cleanup executor state is poisoned".to_string());
                return Err(cleanup);
            }
        };
        let Some(sender) = state.sender.as_ref() else {
            self.health.failed_jobs.fetch_add(1, Ordering::AcqRel);
            cleanup.fail("cleanup executor has no submission port".to_string());
            return Err(cleanup);
        };
        self.health.queued_jobs.fetch_add(1, Ordering::AcqRel);
        if let Err(error) = sender.send(cleanup) {
            self.health.queued_jobs.fetch_sub(1, Ordering::AcqRel);
            self.health.failed_jobs.fetch_add(1, Ordering::AcqRel);
            let mut cleanup = error.0;
            cleanup.fail("cleanup executor queue is closed".to_string());
            return Err(cleanup);
        }
        Ok(())
    }

    fn report(&self) -> ConnectorCleanupHealth {
        ConnectorCleanupHealth {
            queued_jobs: self.health.queued_jobs.load(Ordering::Acquire),
            active_jobs: self.health.active_jobs.load(Ordering::Acquire),
            completed_jobs: self.health.completed_jobs.load(Ordering::Acquire),
            failed_jobs: self.health.failed_jobs.load(Ordering::Acquire),
            executor_failed: self.health.executor_failed.load(Ordering::Acquire),
        }
    }

    #[cfg(test)]
    fn fail_for_test(&self) {
        self.health.executor_failed.store(true, Ordering::Release);
        self.forced_termination.notify_one();
        if let Ok(mut state) = self.state.lock() {
            state.sender.take();
        }
    }
}

/// Mechanically derived process claim for the persistent cleanup owner.
///
/// Inline bytes cover the runtime value, channel sender, thread handle, and
/// health state. Four residual units name the runtime heap, channel heap,
/// native thread stack, and platform runtime internals that Rust does not
/// expose as exact byte quantities.
pub(crate) fn cleanup_executor_infrastructure_claim(
) -> Result<ResourceClaim, crate::resource::ResourceClaimArithmeticError> {
    let bytes = std::mem::size_of::<tokio::runtime::Runtime>()
        .checked_add(std::mem::size_of::<
            tokio::sync::mpsc::UnboundedSender<ConnectorCleanupJob>,
        >())
        .and_then(|value| value.checked_add(std::mem::size_of::<std::thread::JoinHandle<()>>()))
        .and_then(|value| value.checked_add(std::mem::size_of::<ConnectorCleanupHealthState>()))
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        })?;
    let bytes = u64::try_from(bytes).map_err(|_| {
        crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        }
    })?;
    ResourceClaim::try_from_entries([
        (ResourceClass::AccountedMemoryBytes, bytes),
        (ResourceClass::SocketOrHandle, 1),
        (ResourceClass::WorkerOrTask, 1),
        (ResourceClass::CallbackOrScheduledWork, 1),
        (ResourceClass::OpaqueDependencyResidual, 4),
    ])
}

pub(super) fn release_reservation(
    lease: ResourceLease,
    process_diagnostics: &ConnectorResourceDiagnostics,
    mesh_diagnostics: &ConnectorResourceDiagnostics,
) {
    drop(lease);
    process_diagnostics.note_released();
    mesh_diagnostics.note_released();
}

pub(super) fn retain_failed_reservation(
    lease: ResourceLease,
    process_diagnostics: &ConnectorResourceDiagnostics,
    mesh_diagnostics: &ConnectorResourceDiagnostics,
) {
    let expected = lease.claim();
    match lease.retain_after_failed_cleanup() {
        ReclaimResult::Retained(retained) if retained == expected => {
            process_diagnostics.note_failed_cleanup();
            mesh_diagnostics.note_failed_cleanup();
        }
        ReclaimResult::NotNeeded
        | ReclaimResult::Reclaimed(_)
        | ReclaimResult::Retained(_)
        | ReclaimResult::Deferred(_)
        | ReclaimResult::ProviderInvariant { .. } => {
            process_diagnostics.poison();
            mesh_diagnostics.poison();
        }
    }
}
