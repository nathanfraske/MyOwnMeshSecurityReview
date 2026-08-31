//! Capability boundary for one bounded connection attempt.
//!
//! The attempt owner admits connector candidates before allocation, retires
//! losing work, and transfers an exact child claim when a candidate connects.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

use crate::resource::{
    LeasedMap, ResourceClaim, ResourceClaimArithmeticError, ResourceClass, ResourceLease,
};

use super::RuntimeIncarnation;

mod admission;
mod lifetime;
pub(crate) use admission::admit_single_connector_candidate;
#[cfg(test)]
use admission::ConnectorCleanupCapabilityIssueError;
pub use admission::{ConnectorCandidateCapability, PreAuthAttemptPermit};
use admission::{ConnectorCandidateReservation, ConnectorCandidateReservationState};
use lifetime::AttemptOwnership;
pub(crate) use lifetime::{AttemptLifetime, AttemptLiveness};

mod policy;
mod remote_candidate;
mod resource_owner;
pub use policy::*;
pub(crate) use remote_candidate::*;
pub use resource_owner::*;

/// Provider-funded custody for live attempt-owned records.
///
/// Speculative candidates are retained by the attempt boundary rather than a
/// growable engine collection. Each record owns one map node and its lease;
/// there is no spare capacity that can outlive the exact candidate.
pub(crate) struct AttemptOwnerSet<T> {
    entries: LeasedMap<usize, T>,
    next: usize,
}

impl<T> AttemptOwnerSet<T> {
    pub(crate) fn new() -> Self {
        Self {
            entries: LeasedMap::new(),
            next: 0,
        }
    }

    pub(crate) fn entry_claim() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
        LeasedMap::<usize, T>::entry_claim()
    }

    /// Insert one already-funded owner node. Key exhaustion is unreachable
    /// while the provider can fund a node; both value and lease then drop.
    pub(crate) fn insert(&mut self, value: T, lease: ResourceLease) -> bool {
        let Some(next) = self.next.checked_add(1) else {
            drop(lease);
            drop(value);
            return false;
        };
        let key = self.next;
        self.next = next;
        self.entries.insert(key, value, lease).is_ok()
    }

    /// Observe the first matching entry while keeping the leased map's borrow
    /// inside this call. Returning a reference would outlive the map walk's
    /// closure and incorrectly suggest that the map can expose node borrows.
    pub(crate) fn with<R>(
        &self,
        mut predicate: impl FnMut(&T) -> bool,
        mut observe: impl FnMut(&T) -> R,
    ) -> Option<R> {
        let mut observed = None;
        self.entries.for_each(|_, value| {
            if observed.is_none() && predicate(value) {
                observed = Some(observe(value));
            }
        });
        observed
    }

    pub(crate) fn find_mut(&mut self, mut predicate: impl FnMut(&T) -> bool) -> Option<&mut T> {
        self.entries.find_value_mut(|value| predicate(value))
    }

    pub(crate) fn any(&self, predicate: impl FnMut(&T) -> bool) -> bool {
        self.entries.any_value(predicate)
    }

    pub(crate) fn for_each(&self, mut visit: impl FnMut(&T)) {
        self.entries.for_each(|_, value| visit(value));
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn remove_where(&mut self, mut predicate: impl FnMut(&T) -> bool) -> Option<T> {
        let mut key = None;
        self.entries.for_each(|entry_key, value| {
            if key.is_none() && predicate(value) {
                key = Some(*entry_key);
            }
        });
        self.entries.remove(&key?)
    }

    pub(crate) fn pop(&mut self) -> Option<T> {
        self.entries.pop_first_entry().map(|(_, value)| value)
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        !self.entries.any_value(|_| true)
    }
}

/// Resource claim for exactly one connector candidate.
///
/// The opening claim contains only mechanically proven ownership: one native
/// transport, one connector worker, one pre-reserved cleanup obligation, one
/// bounded late-terminal custodian, and one opaque native dependency residual.
/// It contains no guessed codec or media quantity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ConnectorCandidateResourceClaim {
    opening: ResourceClaim,
    connected: ResourceClaim,
}

impl ConnectorCandidateResourceClaim {
    #[cfg(test)]
    fn checked(opening: ResourceClaim, connected: ResourceClaim) -> Option<Self> {
        let floor = Self::exact_connector_floor().opening;
        let structurally_valid = |claim: ResourceClaim| {
            ResourceClass::ALL
                .into_iter()
                .all(|dimension| claim.amount(dimension) >= floor.amount(dimension))
        };
        (structurally_valid(opening) && structurally_valid(connected))
            .then_some(Self { opening, connected })
    }

    /// The mechanically fixed Arc 03 claim. It describes one native peer
    /// connection, one connector worker, one cleanup callback obligation, and
    /// one opaque dependency residual. It is not a complete WebRTC allocation
    /// budget and does not select process capacity.
    pub(crate) fn exact_connector_floor() -> Self {
        let connector = ResourceClaim::try_from_entries([
            (ResourceClass::NativeTransportObject, 1),
            (ResourceClass::WorkerOrTask, 1),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
        .expect("the fixed connector floor cannot overflow");
        let claim = connector
            .checked_add(
                resource_owner::cleanup_job_claim()
                    .expect("the fixed cleanup-job claim cannot overflow"),
            )
            .and_then(|claim| {
                claim.checked_add(
                    resource_owner::late_transport_custodian_claim()
                        .expect("the fixed late-transport custodian claim cannot overflow"),
                )
            })
            .and_then(|claim| {
                claim.checked_add(
                    remote_candidate::remote_candidate_attempt_root_claim()
                        .expect("the candidate-attempt root claim cannot overflow"),
                )
            })
            .expect("the fixed connector and cleanup claims cannot overflow");
        Self {
            opening: claim,
            connected: claim,
        }
    }
}

/// Mechanically derived Arc 03 structural claims for provider planning.
///
/// These claims contain the Rust-owned connector floor, cleanup executor, and
/// named opaque residual units proven by this implementation. They do not
/// estimate dependency-internal WebRTC allocations, OS resources beyond the
/// named handle, callback payloads, candidate content, or real-time units.
/// Reading them grants no authority and selects no product cardinality.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorResourceStructuralClaims {
    process_infrastructure: ResourceClaim,
    connector_opening: ResourceClaim,
    connector_connected: ResourceClaim,
    connector_operation: ResourceClaim,
}

impl ConnectorResourceStructuralClaims {
    pub const fn process_infrastructure(self) -> ResourceClaim {
        self.process_infrastructure
    }

    pub const fn connector_opening(self) -> ResourceClaim {
        self.connector_opening
    }

    pub const fn connector_connected(self) -> ResourceClaim {
        self.connector_connected
    }

    /// Finite work claim acquired for one connector-owned native operation.
    /// This is a resource quantity, not a connector-operation count ceiling.
    pub const fn connector_operation(self) -> ResourceClaim {
        self.connector_operation
    }
}

pub(crate) fn connector_operation_claim() -> ResourceClaim {
    ResourceClaim::try_from_entries([
        (ResourceClass::CallbackOrScheduledWork, 1),
        (ResourceClass::ParsingOrCpuWork, 1),
    ])
    .expect("the connector operation claim cannot overflow")
}

/// Return the current implementation-derived structural claims.
pub fn connector_resource_structural_claims() -> ConnectorResourceStructuralClaims {
    let connector = ConnectorCandidateResourceClaim::exact_connector_floor();
    ConnectorResourceStructuralClaims {
        process_infrastructure: resource_owner::cleanup_executor_infrastructure_claim()
            .expect("the cleanup executor infrastructure claim cannot overflow"),
        connector_opening: connector.opening,
        connector_connected: connector.connected,
        connector_operation: connector_operation_claim(),
    }
}

#[cfg(test)]
fn candidate_claim() -> ConnectorCandidateResourceClaim {
    ConnectorCandidateResourceClaim::exact_connector_floor()
}

#[cfg(test)]
pub(crate) fn explicit_test_grant(candidate_count: u64, mesh_scope_count: u64) -> ResourceClaim {
    let candidate = scale_test_claim(
        ConnectorCandidateResourceClaim::exact_connector_floor().opening,
        candidate_count,
    );
    // The local test provider deliberately admits one concurrently held
    // connector operation per fixture candidate. Tests that need a different
    // concurrency shape construct their own finite provider grant.
    let operation = scale_test_claim(connector_operation_claim(), candidate_count);
    let infrastructure = resource_owner::cleanup_executor_infrastructure_claim()
        .expect("the cleanup infrastructure claim is representable");
    let bookkeeping = 1_u64
        .checked_add(mesh_scope_count)
        .and_then(|value| value.checked_add(candidate_count))
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(candidate_count))
        .and_then(|value| value.checked_add(candidate_count))
        .and_then(|value| value.checked_add(candidate_count))
        .expect("the bounded fixture bookkeeping is representable");
    candidate
        .checked_add(operation)
        .and_then(|claim| claim.checked_add(infrastructure))
        .and_then(|claim| {
            claim.checked_add(ResourceClaim::single(
                ResourceClass::OpaqueDependencyResidual,
                bookkeeping,
            ))
        })
        .expect("the bounded test grant is representable")
}

#[cfg(test)]
fn scale_test_claim(claim: ResourceClaim, factor: u64) -> ResourceClaim {
    ResourceClaim::try_from_entries(ResourceClass::ALL.into_iter().map(|dimension| {
        (
            dimension,
            claim
                .amount(dimension)
                .checked_mul(factor)
                .expect("the bounded fixture claim is representable"),
        )
    }))
    .expect("the bounded fixture claim is representable")
}

#[cfg(test)]
pub(crate) fn explicit_test_provider(
    candidate_count: u64,
    mesh_scope_count: u64,
) -> crate::resource::ResourceProviderPort {
    crate::resource::ResourceProviderPort::new(crate::resource::FiniteResourceProvider::new(
        explicit_test_grant(candidate_count, mesh_scope_count),
    ))
    .expect("the explicit test grant accounts for the process scope")
}

#[cfg(test)]
fn test_mesh_scope(candidate_count: u64) -> MeshConnectorResourceScope {
    let provider = explicit_test_provider(candidate_count, 1);
    ConnectorResourceOwnerPort::new(provider)
        .issue_mesh_scope()
        .expect("the explicit grant accounts for the Mesh scope")
}

#[cfg(test)]
pub(crate) fn connector_candidate_for_test(
    runtime: RuntimeIncarnation,
) -> (ConnectorCandidateCapability, AttemptLifetime) {
    let claim = candidate_claim();
    let (permit, lifetime) = PreAuthAttemptPermit::admitted(runtime, test_mesh_scope(1));
    let capability = permit
        .allocate_connector_candidate(claim, || ())
        .map(|(capability, ())| capability)
        .expect("the explicit provider grant admits its one candidate");
    (capability, lifetime)
}

#[cfg(test)]
pub(crate) fn two_connector_candidates_for_test(
    runtime: RuntimeIncarnation,
) -> (
    ConnectorCandidateCapability,
    ConnectorCandidateCapability,
    AttemptLifetime,
) {
    let claim = candidate_claim();
    let (permit, lifetime) = PreAuthAttemptPermit::admitted(runtime, test_mesh_scope(2));
    let first = permit
        .allocate_connector_candidate(claim, || ())
        .map(|(capability, ())| capability)
        .expect("the explicit provider grant admits its first candidate");
    let second = permit
        .allocate_connector_candidate(claim, || ())
        .map(|(capability, ())| capability)
        .expect("the explicit provider grant admits its second candidate");
    (first, second, lifetime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::{
        FiniteResourceProvider, ResourceAuthorityClass, ResourceProviderPort, ResourceUnavailable,
    };
    use crate::transport::webrtc::WebRtcConnectorProfile;

    fn owner_and_scopes(
        provider: &FiniteResourceProvider,
        mesh_scopes: usize,
    ) -> (ConnectorResourceOwnerPort, Vec<MeshConnectorResourceScope>) {
        let port = ResourceProviderPort::new(provider.clone())
            .expect("the explicit test grant accounts for its process scope");
        let owner = ConnectorResourceOwnerPort::new(port);
        let scopes = (0..mesh_scopes)
            .map(|_| {
                owner
                    .issue_mesh_scope()
                    .expect("the explicit test grant accounts for this Mesh scope")
            })
            .collect();
        (owner, scopes)
    }

    fn data_only_webrtc_profile() -> WebRtcConnectorProfile {
        WebRtcConnectorProfile::new(ConnectorCallbackPolicy::elastic_data_only())
    }

    const MAX_ARC03_OBSERVED_DIMENSION: usize = 64;

    fn arc03_observed_count(name: &str, default: usize) -> usize {
        let value = match std::env::var(name) {
            Ok(raw) => raw
                .parse::<usize>()
                .unwrap_or_else(|error| panic!("{name} must be a positive integer: {error}")),
            Err(std::env::VarError::NotPresent) => default,
            Err(error) => panic!("{name} is not valid Unicode: {error}"),
        };
        assert!(
            (1..=MAX_ARC03_OBSERVED_DIMENSION).contains(&value),
            "{name} must be between 1 and {MAX_ARC03_OBSERVED_DIMENSION}, got {value}"
        );
        value
    }

    fn observe_arc03_mesh_shape(
        mesh_scope_count: usize,
        candidates_per_mesh: usize,
    ) -> ((usize, usize, usize, u64), usize) {
        let candidate_total = mesh_scope_count
            .checked_mul(candidates_per_mesh)
            .expect("the bounded fixture candidate product is representable");
        let grant = explicit_test_grant(
            u64::try_from(candidate_total).expect("the fixture candidate count fits in u64"),
            u64::try_from(mesh_scope_count).expect("the fixture mesh count fits in u64"),
        );
        let provider = FiniteResourceProvider::new(grant);
        let (owner, scopes) = owner_and_scopes(&provider, mesh_scope_count);
        assert_eq!(scopes.len(), mesh_scope_count);
        let owner_mesh_scope_total = mesh_scope_count + 1;
        assert_eq!(provider.active_scopes(), owner_mesh_scope_total);
        let baseline = provider.in_use();

        let mut attempts = Vec::with_capacity(mesh_scope_count);
        let mut lifetimes = Vec::with_capacity(mesh_scope_count);
        let mut candidates = Vec::with_capacity(candidate_total);
        for scope in &scopes {
            let (attempt, lifetime) =
                PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), scope.clone());
            for _ in 0..candidates_per_mesh {
                candidates.push(
                    attempt
                        .reserve_connector_candidate(candidate_claim())
                        .expect("the requested provider-derived mesh shape is admitted"),
                );
            }
            attempts.push(attempt);
            lifetimes.push(lifetime);
        }

        let observed_scopes = provider.active_scopes();
        let observed_candidates = owner.report().active_candidates;
        let observed_native_transport_objects = provider
            .in_use()
            .amount(ResourceClass::NativeTransportObject);
        let observed_active_reservations = provider.active_reservations();
        let active_candidate_scope_total = owner_mesh_scope_total + candidate_total;
        assert_eq!(observed_scopes, active_candidate_scope_total);
        assert_eq!(observed_candidates, candidate_total);
        assert_eq!(observed_native_transport_objects, candidate_total as u64);
        let owner_cleanup_reservation_total = 1;
        assert_eq!(
            provider.active_reservations(),
            candidate_total + owner_cleanup_reservation_total
        );

        drop(candidates);
        assert_eq!(provider.active_scopes(), owner_mesh_scope_total);
        assert_eq!(provider.in_use(), baseline);
        assert_eq!(
            provider.active_reservations(),
            owner_cleanup_reservation_total
        );
        assert_eq!(owner.report().active_candidates, 0);

        drop(attempts);
        drop(lifetimes);
        assert_eq!(provider.active_scopes(), owner_mesh_scope_total);
        assert_eq!(
            provider.active_reservations(),
            owner_cleanup_reservation_total
        );
        assert_eq!(provider.in_use(), baseline);
        drop(scopes);
        assert_eq!(provider.active_scopes(), 1);
        assert_eq!(provider.active_reservations(), 1);
        drop(owner);
        const CLEANUP_EXECUTOR_EXIT_YIELD_LIMIT: usize = 10_000;
        for _ in 0..CLEANUP_EXECUTOR_EXIT_YIELD_LIMIT {
            if provider.active_scopes() == 0
                && provider.active_reservations() == 0
                && provider.in_use() == ResourceClaim::ZERO
            {
                break;
            }
            std::thread::yield_now();
        }
        assert_eq!(
            provider.active_scopes(),
            0,
            "cleanup executor did not release the provider root scope after {CLEANUP_EXECUTOR_EXIT_YIELD_LIMIT} scheduler yields"
        );
        assert_eq!(
            provider.active_reservations(),
            0,
            "cleanup executor did not release its root reservation after {CLEANUP_EXECUTOR_EXIT_YIELD_LIMIT} scheduler yields"
        );
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);

        (
            (
                mesh_scope_count,
                candidate_total,
                observed_scopes,
                observed_native_transport_objects,
            ),
            observed_active_reservations,
        )
    }

    #[test]
    fn v4_arc03_provider_policy_clone_shares_exact_provider_identity() {
        let grant = explicit_test_grant(1, 2);
        let provider = FiniteResourceProvider::new(grant);
        let port = ResourceProviderPort::new(provider)
            .expect("the explicit grant accounts for its process scope");
        let policy = WebRtcConnectorCapablePolicy::new(port, data_only_webrtc_profile());
        let clone = policy.clone();

        assert!(policy.resources().same_provider(&clone.resources()));
        assert_eq!(policy.webrtc(), clone.webrtc());
    }

    #[test]
    fn v4_arc03_mesh_scopes_share_one_grant_and_creation_does_not_multiply_it() {
        let observation_requested = std::env::var_os("MYOWNMESH_ARC03_OBSERVE_MESHES").is_some()
            || std::env::var_os("MYOWNMESH_ARC03_OBSERVE_CANDIDATES_PER_MESH").is_some();
        if observation_requested {
            let mesh_scope_count = arc03_observed_count("MYOWNMESH_ARC03_OBSERVE_MESHES", 2);
            let candidates_per_mesh =
                arc03_observed_count("MYOWNMESH_ARC03_OBSERVE_CANDIDATES_PER_MESH", 1);
            let owner_mesh_scope_baseline = mesh_scope_count + 1;
            let (
                (
                    observed_mesh_scope_count,
                    observed_candidate_total,
                    observed_active_scope_total,
                    observed_native_transport_objects,
                ),
                observed_active_reservations,
            ) = observe_arc03_mesh_shape(mesh_scope_count, candidates_per_mesh);
            assert_eq!(observed_mesh_scope_count, mesh_scope_count);
            assert_eq!(
                observed_candidate_total,
                mesh_scope_count * candidates_per_mesh
            );
            assert_eq!(
                observed_active_scope_total,
                owner_mesh_scope_baseline + observed_candidate_total
            );
            assert_eq!(
                observed_native_transport_objects,
                observed_candidate_total as u64
            );
            assert_eq!(observed_active_reservations, observed_candidate_total + 1);
            if std::env::var_os("MYOWNMESH_ARC03_OBSERVE_RAW").is_some() {
                println!(
                    "arc03_multi_mesh_raw requested_meshes={mesh_scope_count} candidates_per_mesh={candidates_per_mesh} observed_meshes={observed_mesh_scope_count} owner_mesh_scope_baseline={owner_mesh_scope_baseline} observed_active_scopes={observed_active_scope_total} observed_candidates={observed_candidate_total} observed_native_transport_objects={observed_native_transport_objects} observed_active_reservations={observed_active_reservations} provider_baseline_restored=true"
                );
            }
            return;
        }

        let refused_claim_without_native = ConnectorCandidateResourceClaim::exact_connector_floor()
            .opening
            .checked_sub(ResourceClaim::single(
                ResourceClass::NativeTransportObject,
                1,
            ))
            .expect("the refused fixture omits only its native transport");
        let grant = explicit_test_grant(1, 2)
            .checked_add(refused_claim_without_native)
            .and_then(|grant| {
                grant.checked_add(ResourceClaim::single(
                    ResourceClass::OpaqueDependencyResidual,
                    2,
                ))
            })
            .expect("the fixture admits one refused connector-scope and reservation record");
        let provider = FiniteResourceProvider::new(grant);
        let (_owner, scopes) = owner_and_scopes(&provider, 2);
        assert!(scopes[0].same_provider(&scopes[1]));

        let (first_attempt, _first_lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), scopes[0].clone());
        let (second_attempt, _second_lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), scopes[1].clone());
        let first = first_attempt
            .reserve_connector_candidate(candidate_claim())
            .expect("the shared grant admits one candidate");
        let pressure = match second_attempt.reserve_connector_candidate_checked(candidate_claim()) {
            Err(error) => error,
            Ok(_) => panic!("a second Mesh scope must not mint another candidate grant"),
        };
        assert_eq!(
            pressure.dimension(),
            Some(ResourceClass::NativeTransportObject)
        );

        drop(first);
        assert!(second_attempt
            .reserve_connector_candidate(candidate_claim())
            .is_some());
    }

    #[test]
    fn v4_arc03_mesh_observation_shapes_are_discriminating() {
        let (one_by_one, one_by_one_reservations) = observe_arc03_mesh_shape(1, 1);
        let (three_by_four, three_by_four_reservations) = observe_arc03_mesh_shape(3, 4);

        assert_eq!(one_by_one, (1, 1, 3, 1));
        assert_eq!(three_by_four, (3, 12, 16, 12));
        assert_eq!(one_by_one_reservations, 2);
        assert_eq!(three_by_four_reservations, 13);
        assert_ne!(one_by_one, three_by_four);
    }

    #[test]
    fn v4_arc03_concurrent_mesh_children_cannot_oversubscribe_shared_provider() {
        let grant = explicit_test_grant(1, 2);
        let provider = FiniteResourceProvider::new(grant);
        let (_owner, scopes) = owner_and_scopes(&provider, 2);
        let barrier = Arc::new(std::sync::Barrier::new(3));

        let workers: Vec<_> = scopes
            .into_iter()
            .map(|scope| {
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let (attempt, _lifetime) =
                        PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), scope);
                    barrier.wait();
                    attempt.reserve_connector_candidate(candidate_claim())
                })
            })
            .collect();
        barrier.wait();
        let outcomes: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().expect("candidate worker joins"))
            .collect();

        assert_eq!(outcomes.iter().filter(|result| result.is_some()).count(), 1);
        assert_eq!(
            provider
                .in_use()
                .amount(ResourceClass::NativeTransportObject),
            1
        );
    }

    #[test]
    fn v4_arc03_failed_cleanup_does_not_poison_unrelated_shared_capacity() {
        let grant = explicit_test_grant(2, 2);
        let provider = FiniteResourceProvider::new(grant);
        let (owner, scopes) = owner_and_scopes(&provider, 2);
        let (failed_attempt, _failed_lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), scopes[0].clone());
        let mut failed = failed_attempt
            .reserve_connector_candidate(candidate_claim())
            .expect("the first provider slot is admitted");
        let mut cleanup_capability = failed
            .issue_cleanup_capability()
            .expect("the first claim issues its cleanup capability");
        cleanup_capability
            .begin_cleanup()
            .expect("the first claim enters cleanup");
        failed.retain_after_cleanup_failure();
        drop(failed);

        let (unrelated_attempt, _unrelated_lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), scopes[1].clone());
        let unrelated = unrelated_attempt
            .reserve_connector_candidate(candidate_claim())
            .expect("the unrelated Mesh uses the remaining provider capacity");
        assert!(unrelated_attempt
            .reserve_connector_candidate(candidate_claim())
            .is_none());
        assert_eq!(owner.report().active_candidates, 2);
        assert_eq!(owner.report().failed_cleanup_candidates, 1);
        assert!(!owner.report().accounting_poisoned);
        drop(unrelated);
        assert_eq!(owner.report().active_candidates, 1);
    }

    #[test]
    fn v4_arc03_unequal_claim_transition_is_exact() {
        let mut grant = explicit_test_grant(1, 1);
        grant = grant
            .checked_add(ResourceClaim::single(ResourceClass::ParsingOrCpuWork, 1))
            .expect("the test parsing grant is representable");
        let provider = FiniteResourceProvider::new(grant);
        let (_owner, scopes) = owner_and_scopes(&provider, 1);
        let baseline = provider.in_use();
        let floor = ConnectorCandidateResourceClaim::exact_connector_floor();
        let opening = floor
            .opening
            .checked_add(ResourceClaim::single(ResourceClass::ParsingOrCpuWork, 1))
            .expect("the test opening claim is representable");
        let claim = ConnectorCandidateResourceClaim::checked(opening, floor.connected)
            .expect("both phases retain the fixed connector floor");
        let (attempt, _lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), scopes[0].clone());
        let candidate = attempt
            .reserve_connector_candidate(claim)
            .expect("the explicit grant admits the larger opening claim");
        assert_eq!(provider.in_use().amount(ResourceClass::ParsingOrCpuWork), 1);

        let connected = candidate
            .try_promote_if_live(|candidate| candidate)
            .ok()
            .expect("the active attempt atomically promotes");
        assert_eq!(provider.in_use().amount(ResourceClass::ParsingOrCpuWork), 0);
        drop(connected);
        assert_eq!(provider.in_use(), baseline);
    }

    #[test]
    fn v4_arc03_successful_drop_releases_the_exact_provider_claim() {
        let grant = explicit_test_grant(1, 1);
        let provider = FiniteResourceProvider::new(grant);
        let (owner, scopes) = owner_and_scopes(&provider, 1);
        let baseline = provider.in_use();
        let (attempt, _lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), scopes[0].clone());
        let candidate = attempt
            .reserve_connector_candidate(candidate_claim())
            .expect("the explicit grant admits one candidate");
        assert_eq!(owner.report().active_candidates, 1);
        drop(candidate);

        assert_eq!(provider.in_use(), baseline);
        assert_eq!(owner.report().active_candidates, 0);
        assert_eq!(scopes[0].report().active_candidates, 0);
    }

    #[test]
    fn v4_arc03_attempt_issues_multiple_provider_backed_candidates() {
        let grant = explicit_test_grant(2, 1);
        let provider = FiniteResourceProvider::new(grant);
        let (owner, scopes) = owner_and_scopes(&provider, 1);
        let (attempt, _lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), scopes[0].clone());
        let first = attempt
            .reserve_connector_candidate(candidate_claim())
            .expect("the first provider-backed child is admitted");
        let second = attempt
            .reserve_connector_candidate(candidate_claim())
            .expect("the attempt permit is not consumed by its first child");
        assert_eq!(owner.report().active_candidates, 2);
        assert!(first.belongs_to(&attempt));
        assert!(second.belongs_to(&attempt));
        drop(first);
        drop(second);
        assert_eq!(owner.report().active_candidates, 0);
    }

    #[test]
    fn v4_arc03_allocation_runs_only_after_provider_acquisition() {
        let grant = explicit_test_grant(1, 1);
        let provider = FiniteResourceProvider::new(grant);
        let (_owner, scopes) = owner_and_scopes(&provider, 1);
        let (attempt, _lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), scopes[0].clone());
        let first = attempt
            .allocate_connector_candidate(candidate_claim(), || {
                provider
                    .in_use()
                    .amount(ResourceClass::NativeTransportObject)
            })
            .expect("the first child is admitted");
        assert_eq!(first.1, 1);

        let allocation_called = std::cell::Cell::new(false);
        let refused =
            attempt.allocate_connector_candidate(candidate_claim(), || allocation_called.set(true));
        assert!(refused.is_none());
        assert!(!allocation_called.get());
        drop(first);
    }

    #[test]
    fn v4_arc03_failed_cleanup_retains_the_exact_claim_without_global_poison() {
        let grant = explicit_test_grant(1, 1);
        let provider = FiniteResourceProvider::new(grant);
        let (owner, scopes) = owner_and_scopes(&provider, 1);
        let (attempt, _lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), scopes[0].clone());
        let mut candidate = attempt
            .reserve_connector_candidate(candidate_claim())
            .expect("the explicit grant admits one candidate");
        let mut cleanup_capability = candidate
            .issue_cleanup_capability()
            .expect("the candidate issues its cleanup capability");
        cleanup_capability
            .begin_cleanup()
            .expect("cleanup authority transition does not increase the claim");
        candidate.retain_after_cleanup_failure();
        drop(candidate);

        assert_eq!(
            provider.retained_after_failed_cleanup(),
            ConnectorCandidateResourceClaim::exact_connector_floor().connected
        );
        let process = owner.report();
        assert_eq!(process.active_candidates, 1);
        assert_eq!(process.failed_cleanup_candidates, 1);
        assert!(!process.accounting_poisoned);
        assert_eq!(scopes[0].report().failed_cleanup_candidates, 1);
    }

    #[test]
    fn v4_arc03_cleanup_submission_consumes_one_exact_reservation_capability() {
        let grant = explicit_test_grant(1, 1);
        let provider = FiniteResourceProvider::new(grant);
        let (owner, scopes) = owner_and_scopes(&provider, 1);
        let (attempt, _lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), scopes[0].clone());
        let mut candidate = attempt
            .reserve_connector_candidate(candidate_claim())
            .expect("the explicit provider grant admits one candidate");
        let mut cleanup = candidate
            .issue_cleanup_capability()
            .expect("the exact reservation mints one cleanup capability");
        assert!(matches!(
            candidate.issue_cleanup_capability(),
            Err(ConnectorCleanupCapabilityIssueError::AlreadyIssued)
        ));
        cleanup
            .begin_cleanup()
            .expect("the exact claim enters cleanup before submission");
        drop(candidate);
        assert_eq!(owner.report().active_candidates, 1);

        assert!(
            !scopes[0]
                .submit_cleanup(
                    cleanup,
                    Box::pin(async {}),
                    Box::new(|| {}),
                    Box::new(|_| {}),
                )
                .was_refused(),
            "the exact Mesh owner accepts its cleanup capability"
        );
        for _ in 0..10_000 {
            if owner.report().cleanup.completed_jobs == 1 {
                break;
            }
            std::thread::yield_now();
        }
        assert_eq!(owner.report().cleanup.completed_jobs, 1);
        assert_eq!(owner.report().active_candidates, 0);
    }

    #[test]
    fn v4_arc03_cleanup_queue_cannot_outgrow_pre_reserved_connector_claims() {
        let grant = explicit_test_grant(2, 1);
        let provider = FiniteResourceProvider::new(grant);
        let (owner, scopes) = owner_and_scopes(&provider, 1);
        let (attempt, _lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), scopes[0].clone());
        let gate = Arc::new(tokio::sync::Notify::new());

        for _ in 0..2 {
            let mut candidate = attempt
                .reserve_connector_candidate(candidate_claim())
                .expect("the explicit provider grant admits its declared connector");
            let mut cleanup = candidate
                .issue_cleanup_capability()
                .expect("the exact reservation mints one cleanup capability");
            cleanup
                .begin_cleanup()
                .expect("cleanup begins under the pre-reserved claim");
            drop(candidate);
            let job_gate = Arc::clone(&gate);
            assert!(
                !scopes[0]
                    .submit_cleanup(
                        cleanup,
                        Box::pin(async move { job_gate.notified().await }),
                        Box::new(|| {}),
                        Box::new(|_| {}),
                    )
                    .was_refused(),
                "the exact Mesh owner accepts its cleanup claim"
            );
        }

        for _ in 0..10_000 {
            if owner.report().cleanup.active_jobs == 2 {
                break;
            }
            std::thread::yield_now();
        }
        let health = owner.report().cleanup;
        assert_eq!(health.active_jobs, 2);
        assert_eq!(health.queued_jobs, 0);
        assert!(
            attempt
                .reserve_connector_candidate(candidate_claim())
                .is_none(),
            "the cleanup channel cannot manufacture a third connector claim"
        );
        assert_eq!(owner.report().active_candidates, 2);

        gate.notify_waiters();
        for _ in 0..10_000 {
            if owner.report().cleanup.completed_jobs == 2 {
                break;
            }
            std::thread::yield_now();
        }
        assert_eq!(owner.report().cleanup.completed_jobs, 2);
        assert_eq!(owner.report().active_candidates, 0);
    }

    #[test]
    fn v4_arc03_cleanup_claim_survives_until_the_final_capability_owner_drops() {
        let grant = explicit_test_grant(1, 1);
        let provider = FiniteResourceProvider::new(grant);
        let (owner, scopes) = owner_and_scopes(&provider, 1);
        let (attempt, _lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), scopes[0].clone());
        let mut candidate = attempt
            .reserve_connector_candidate(candidate_claim())
            .expect("the explicit provider grant admits one candidate");
        let cleanup = candidate
            .issue_cleanup_capability()
            .expect("the exact reservation mints one cleanup capability");

        candidate.release_after_cleanup_success();
        assert!(candidate.reservation_is_active_for_test());
        assert_eq!(owner.report().active_candidates, 1);
        drop(candidate);
        assert_eq!(
            owner.report().active_candidates,
            1,
            "the move-only cleanup capability is still the final job owner"
        );

        drop(cleanup);
        assert_eq!(owner.report().active_candidates, 0);
    }

    #[test]
    fn v4_arc03_provider_pressure_names_the_exhausted_dimension() {
        let grant = explicit_test_grant(1, 1)
            .checked_sub(ResourceClaim::single(
                ResourceClass::NativeTransportObject,
                1,
            ))
            .expect("the pressure fixture omits only its native transport");
        let provider = FiniteResourceProvider::new(grant);
        let (_owner, scopes) = owner_and_scopes(&provider, 1);
        let (attempt, _lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), scopes[0].clone());

        let error = match attempt.reserve_connector_candidate_checked(candidate_claim()) {
            Err(error) => error,
            Ok(_) => panic!("the provider grant contains no native transport object"),
        };
        assert!(matches!(
            error,
            ResourceUnavailable::Pressure(pressure)
                if pressure.dimension == ResourceClass::NativeTransportObject
                    && pressure.authority == ResourceAuthorityClass::Speculative
        ));
    }

    #[test]
    fn v4_arc03_promotion_and_retirement_share_one_attempt_transition() {
        let (candidate, lifetime) =
            connector_candidate_for_test(crate::runtime::runtime_for_test());
        let lifetime = Arc::new(lifetime);
        let (promotion_entered_tx, promotion_entered_rx) = std::sync::mpsc::channel();
        let (release_promotion_tx, release_promotion_rx) = std::sync::mpsc::channel();
        let promotion = std::thread::spawn(move || {
            candidate
                .try_promote_if_live(|candidate| {
                    promotion_entered_tx
                        .send(())
                        .expect("the test observes the promotion lock");
                    release_promotion_rx
                        .recv()
                        .expect("the test releases promotion");
                    candidate
                })
                .ok()
        });
        promotion_entered_rx
            .recv()
            .expect("promotion acquires the attempt transition");

        let retire_lifetime = Arc::clone(&lifetime);
        let retirement = std::thread::spawn(move || retire_lifetime.retire());
        release_promotion_tx
            .send(())
            .expect("release the promotion transition");
        let promoted = promotion
            .join()
            .expect("promotion thread joins")
            .expect("promotion linearized before retirement");
        retirement.join().expect("retirement thread joins");
        assert!(!promoted.is_live());
    }

    #[test]
    fn v4_arc03_attempt_retirement_invalidates_every_connector_candidate() {
        let (first, second, lifetime) =
            two_connector_candidates_for_test(crate::runtime::runtime_for_test());
        assert!(first.is_live());
        assert!(second.is_live());
        lifetime.retire();
        assert!(!first.is_live());
        assert!(!second.is_live());
    }

    #[test]
    fn v4_arc03_retired_attempt_refuses_later_provider_acquisition() {
        let grant = explicit_test_grant(1, 1);
        let provider = FiniteResourceProvider::new(grant);
        let (_owner, scopes) = owner_and_scopes(&provider, 1);
        let baseline = provider.in_use();
        let (attempt, lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), scopes[0].clone());
        lifetime.retire();
        let allocation_called = std::cell::Cell::new(false);
        assert!(attempt
            .allocate_connector_candidate(candidate_claim(), || allocation_called.set(true))
            .is_none());
        assert!(!allocation_called.get());
        assert_eq!(provider.in_use(), baseline);
    }

    #[test]
    fn v4_arc03_attempt_retirement_signal_replays_to_late_subscriber() {
        let (candidate, lifetime) =
            connector_candidate_for_test(crate::runtime::runtime_for_test());
        let liveness = candidate.liveness();
        lifetime.retire();
        assert!(!liveness.is_active());
        assert!(*liveness.subscribe_retirement().borrow());
    }

    #[test]
    fn v4_arc03_reservation_precedes_allocation_and_retirement_fences_result() {
        let grant = explicit_test_grant(1, 1);
        let provider = FiniteResourceProvider::new(grant);
        let (_owner, scopes) = owner_and_scopes(&provider, 1);
        let (attempt, lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), scopes[0].clone());
        let lifetime = Arc::new(lifetime);
        let (allocation_entered_tx, allocation_entered_rx) = std::sync::mpsc::channel();
        let (release_allocation_tx, release_allocation_rx) = std::sync::mpsc::channel();
        let allocation = std::thread::spawn(move || {
            attempt.allocate_connector_candidate(candidate_claim(), || {
                allocation_entered_tx
                    .send(())
                    .expect("the test observes admitted allocation");
                release_allocation_rx
                    .recv()
                    .expect("the test releases allocation");
            })
        });
        allocation_entered_rx
            .recv()
            .expect("provider acquisition precedes the allocation closure");
        lifetime.retire();
        release_allocation_tx
            .send(())
            .expect("release the allocation closure");
        let (candidate, ()) = allocation
            .join()
            .expect("allocation thread joins")
            .expect("the admitted allocation returns its fenced capability");
        assert!(!candidate.is_live());
    }

    #[test]
    fn v4_arc03_connector_floor_rejects_missing_cleanup_obligation() {
        let floor = ConnectorCandidateResourceClaim::exact_connector_floor();
        let without_cleanup = floor
            .opening
            .checked_sub(ResourceClaim::single(
                ResourceClass::CallbackOrScheduledWork,
                1,
            ))
            .expect("the fixed floor contains the cleanup obligation");
        assert!(
            ConnectorCandidateResourceClaim::checked(without_cleanup, floor.connected).is_none()
        );
    }
}
