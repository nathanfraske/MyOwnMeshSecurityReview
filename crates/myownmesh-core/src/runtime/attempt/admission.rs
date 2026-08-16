//! Reserve-before-allocation connector-candidate admission and promotion.

use super::*;

pub(super) struct ConnectorCandidateReservation {
    pub(super) state: Arc<ConnectorCandidateReservationState>,
}

impl ConnectorCandidateReservation {
    fn release_after_cleanup_success(&mut self) {
        let mut cleanup = self
            .state
            .cleanup_lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if cleanup.capability_live {
            cleanup.release_after_success = true;
            return;
        }
        drop(cleanup);
        Self::release_state_after_cleanup_success(&self.state);
    }

    fn release_state_after_cleanup_success(state: &ConnectorCandidateReservationState) {
        let mut lease = state
            .lease
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(lease) = lease.take() {
            release_reservation(lease, &state.process_diagnostics, &state.mesh_diagnostics);
        }
    }

    fn transition(
        &mut self,
        authority: crate::resource::ResourceAuthorityClass,
        next: crate::resource::ResourceClaim,
    ) -> Result<(), crate::resource::ResourceUnavailable> {
        let mut lease = self.state.lease.lock().unwrap_or_else(|poisoned| {
            poison_reservation_diagnostics(
                &self.state.process_diagnostics,
                &self.state.mesh_diagnostics,
            );
            poisoned.into_inner()
        });
        let lease = lease
            .as_mut()
            .expect("a live connector candidate owns one resource lease");
        lease.transition_to(authority, next)
    }

    fn issue_cleanup_capability(
        &mut self,
    ) -> Result<ConnectorCleanupCapability, ConnectorCleanupCapabilityIssueError> {
        self.state
            .cleanup_capability_issued
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ConnectorCleanupCapabilityIssueError::AlreadyIssued)?;
        self.state
            .cleanup_lifecycle
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .capability_live = true;
        Ok(ConnectorCleanupCapability {
            reservation: Arc::clone(&self.state),
        })
    }

    /// Convert this exact live claim into a process-owned failed-cleanup slot.
    /// The aggregate already includes the claim, so this records the terminal
    /// disposition and prevents `Drop` from making the slot reusable.
    fn retain_after_cleanup_failure(&mut self) {
        let mut lease = self
            .state
            .lease
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if lease.is_none() {
            return;
        }
        if lease.as_ref().is_some_and(|lease| {
            lease.authority() != crate::resource::ResourceAuthorityClass::Cleanup
        }) {
            let claim = lease.as_ref().expect("checked above").claim();
            if lease
                .as_mut()
                .expect("checked above")
                .transition_to(crate::resource::ResourceAuthorityClass::Cleanup, claim)
                .is_err()
            {
                poison_reservation_diagnostics(
                    &self.state.process_diagnostics,
                    &self.state.mesh_diagnostics,
                );
            }
        }
        let lease = lease
            .take()
            .expect("the cleanup failure still owns its exact lease");
        retain_failed_reservation(
            lease,
            &self.state.process_diagnostics,
            &self.state.mesh_diagnostics,
        );
    }
}

pub(super) struct ConnectorCandidateReservationState {
    pub(super) lease: Mutex<Option<crate::resource::ResourceLease>>,
    pub(super) work_scope: ConnectorWorkResourceScope,
    pub(super) process_diagnostics: Arc<ConnectorResourceDiagnostics>,
    pub(super) mesh_diagnostics: Arc<ConnectorResourceDiagnostics>,
    pub(super) cleanup_capability_issued: AtomicBool,
    pub(super) cleanup_lifecycle: Mutex<ConnectorCleanupLifecycle>,
}

#[derive(Default)]
pub(super) struct ConnectorCleanupLifecycle {
    capability_live: bool,
    release_after_success: bool,
}

impl Drop for ConnectorCandidateReservationState {
    fn drop(&mut self) {
        if let Some(lease) = self
            .lease
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            release_reservation(lease, &self.process_diagnostics, &self.mesh_diagnostics);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ConnectorCleanupCapabilityIssueError {
    #[error("the connector cleanup capability was already issued")]
    AlreadyIssued,
}

impl ConnectorCleanupCapability {
    /// Move the exact connector reservation to cleanup authority before its
    /// one permitted cleanup submission.
    pub(crate) fn begin_cleanup(&mut self) -> Result<(), crate::resource::ResourceUnavailable> {
        let mut lease = self
            .reservation
            .lease
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // A terminal cleanup failure may be recorded before the close owner is
        // started. In that state the exact lease has already moved into the
        // provider's failed-cleanup retention, but this one-shot capability
        // must still be allowed to carry the native close job. The retained
        // claim remains charged and cannot be released by this later attempt.
        let Some(lease) = lease.as_mut() else {
            return Ok(());
        };
        let claim = lease.claim();
        lease.transition_to(crate::resource::ResourceAuthorityClass::Cleanup, claim)
    }
}

impl Drop for ConnectorCleanupCapability {
    fn drop(&mut self) {
        let release = {
            let mut cleanup = self
                .reservation
                .cleanup_lifecycle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            cleanup.capability_live = false;
            std::mem::take(&mut cleanup.release_after_success)
        };
        if release {
            ConnectorCandidateReservation::release_state_after_cleanup_success(&self.reservation);
        }
    }
}

/// Proof that pre-authentication work was admitted for one attempt.
///
/// The private field prevents public IDs, wire values, and serialized state
/// from being treated as a permit. The permit is intentionally neither
/// `Clone` nor serializable.
#[allow(dead_code, reason = "Arc 03 moves the production attempt caller")]
pub struct PreAuthAttemptPermit {
    pub(super) attempt: Arc<AttemptOwnership>,
    pub(super) resource_scope: MeshConnectorResourceScope,
}

#[allow(dead_code, reason = "Arc 03 moves the production attempt caller")]
impl PreAuthAttemptPermit {
    // The attempt owner will call this only after the resource owner admits
    // the work. It stays private until that production port is migrated.
    pub(super) fn admitted(
        runtime: RuntimeIncarnation,
        resource_scope: impl Into<MeshConnectorResourceScope>,
    ) -> (Self, AttemptLifetime) {
        let resource_scope = resource_scope.into();
        let (retired, _retirement_receiver) = watch::channel(false);
        let attempt = Arc::new(AttemptOwnership {
            runtime,
            active: AtomicBool::new(true),
            transition: Mutex::new(()),
            retired,
        });
        let lifetime = AttemptLifetime {
            attempt: Arc::clone(&attempt),
        };
        (
            Self {
                attempt,
                resource_scope,
            },
            lifetime,
        )
    }

    /// Reserve one child and only then run the candidate allocation.
    ///
    /// The attempt permit remains alive and may issue more child reservations
    /// from the same aggregate. The closure is never called when admission
    /// fails.
    pub(super) fn allocate_connector_candidate<T>(
        &self,
        claim: ConnectorCandidateResourceClaim,
        allocate: impl FnOnce() -> T,
    ) -> Option<(ConnectorCandidateCapability, T)> {
        let capability = self.reserve_connector_candidate(claim)?;
        let candidate = allocate();
        Some((capability, candidate))
    }

    /// Reserve the opening claim before asynchronous connector construction.
    /// The attempt permit remains available for other racing candidates.
    pub(crate) fn reserve_connector_candidate(
        &self,
        claim: ConnectorCandidateResourceClaim,
    ) -> Option<ConnectorCandidateCapability> {
        self.reserve_connector_candidate_checked(claim)
            .ok()
            .flatten()
    }

    /// Typed provider admission used by the connector owner. Compatibility
    /// call sites may temporarily map this error to `None`, but the resource
    /// dimension is preserved here.
    pub(crate) fn reserve_connector_candidate_checked(
        &self,
        claim: ConnectorCandidateResourceClaim,
    ) -> Result<Option<ConnectorCandidateCapability>, crate::resource::ResourceUnavailable> {
        let Ok(_transition) = self.attempt.transition.lock() else {
            return Ok(None);
        };
        if !self.attempt.active.load(Ordering::Acquire) {
            return Ok(None);
        }
        let reservation = self.resource_scope.reserve(claim.opening)?;
        Ok(Some(ConnectorCandidateCapability {
            attempt: Arc::clone(&self.attempt),
            reservation,
            connected_claim: claim.connected,
        }))
    }
}

/// Admit one single-candidate attempt at the exact Arc 03 connector floor.
/// This attempt-local capacity is not a process or ingress limit.
pub(crate) fn admit_single_connector_candidate(
    runtime: RuntimeIncarnation,
    resource_scope: MeshConnectorResourceScope,
) -> (
    PreAuthAttemptPermit,
    AttemptLifetime,
    ConnectorCandidateResourceClaim,
) {
    let claim = ConnectorCandidateResourceClaim::exact_connector_floor();
    let (permit, lifetime) = PreAuthAttemptPermit::admitted(runtime, resource_scope);
    (permit, lifetime, claim)
}

/// Local authority to attempt one connector candidate.
///
/// The capability owns one child resource reservation and an exact, local
/// witness for the attempt that issued it. It does not consume the attempt
/// permit. One admitted attempt can therefore own multiple candidates under
/// one aggregate reservation. The capability has no public constructor and is
/// neither `Clone` nor serializable.
///
/// A public peer label cannot create a candidate capability:
///
/// ```compile_fail,E0308
/// use myownmesh_core::runtime::attempt::ConnectorCandidateCapability;
///
/// let public_peer_id = String::new();
/// let _candidate = ConnectorCandidateCapability::from(public_peer_id);
/// ```
#[allow(dead_code, reason = "Arc 03 moves the production attempt caller")]
pub struct ConnectorCandidateCapability {
    attempt: Arc<AttemptOwnership>,
    reservation: ConnectorCandidateReservation,
    connected_claim: crate::resource::ResourceClaim,
}

#[allow(dead_code, reason = "Arc 03 moves the production attempt caller")]
impl ConnectorCandidateCapability {
    pub(crate) fn runtime(&self) -> &RuntimeIncarnation {
        &self.attempt.runtime
    }

    pub(crate) fn liveness(&self) -> AttemptLiveness {
        AttemptLiveness {
            attempt: Arc::clone(&self.attempt),
        }
    }

    /// Resource authority for callback, parsing, queue, and other work owned
    /// by this exact connector candidate.
    pub(crate) fn work_resource_scope(&self) -> ConnectorWorkResourceScope {
        self.reservation.state.work_scope.clone()
    }

    pub(crate) fn is_live(&self) -> bool {
        let Ok(_transition) = self.attempt.transition.lock() else {
            return false;
        };
        self.attempt.active.load(Ordering::Acquire)
    }

    pub(crate) fn retain_after_cleanup_failure(&mut self) {
        self.reservation.retain_after_cleanup_failure();
    }

    pub(crate) fn release_after_cleanup_success(&mut self) {
        self.reservation.release_after_cleanup_success();
    }

    /// Mint the sole cleanup-submission capability for this reservation.
    /// Authority changes only when the close owner actually starts cleanup.
    pub(crate) fn issue_cleanup_capability(
        &mut self,
    ) -> Result<ConnectorCleanupCapability, ConnectorCleanupCapabilityIssueError> {
        self.reservation.issue_cleanup_capability()
    }

    pub(crate) fn promote_if_live<T>(self, promote: impl FnOnce(Self) -> T) -> Option<T> {
        self.try_promote_if_live(promote).ok()
    }

    /// Promote without losing cleanup ownership when retirement or a
    /// fail-closed aggregate refuses the transition.
    #[allow(
        clippy::result_large_err,
        reason = "boxing the move-only cleanup claim would add an unaccounted allocation"
    )]
    pub(crate) fn try_promote_if_live<T>(
        mut self,
        promote: impl FnOnce(Self) -> T,
    ) -> std::result::Result<T, Self> {
        let attempt = Arc::clone(&self.attempt);
        let _transition = match attempt.transition.lock() {
            Ok(transition) => transition,
            Err(_) => return Err(self),
        };
        if !attempt.active.load(Ordering::Acquire) {
            return Err(self);
        }
        if self
            .reservation
            .transition(
                crate::resource::ResourceAuthorityClass::Admitted,
                self.connected_claim,
            )
            .is_err()
        {
            return Err(self);
        }
        Ok(promote(self))
    }

    #[cfg(test)]
    pub(crate) fn reservation_is_active_for_test(&self) -> bool {
        self.reservation
            .state
            .lease
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
    }

    #[cfg(test)]
    pub(super) fn belongs_to(&self, permit: &PreAuthAttemptPermit) -> bool {
        Arc::ptr_eq(&self.attempt, &permit.attempt)
            && self
                .reservation
                .state
                .lease
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .is_some_and(|lease| {
                    lease.scope().parent_id() == Some(permit.resource_scope.token.scope.id())
                })
    }
}
