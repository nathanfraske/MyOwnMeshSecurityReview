//! Codec-neutral connector-local real-time flow ownership and accounting.

use super::*;
use crate::resource::{
    ResourceAuthorityClass, ResourceClaim, ResourceClaimArithmeticError, ResourceClass,
    ResourceLease, ResourceUnavailable,
};
use crate::runtime::attempt::ConnectorWorkResourceScope;

/// Opaque process-local identity for one connector real-time flow.
///
/// The key is scheduling identity only. It is not serialized and grants no
/// authority. Codec, lane, and application-purpose names stay in the WebRTC
/// compatibility adapter that owns the corresponding flow port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct RealtimeFlowKey(usize);

/// Allocation-backed process-local identity for one admitted flow.
///
/// Its address is used only while this token remains alive. The flow lease is
/// acquired before this token is allocated, and the token remains inside the
/// flow lifetime until after the registry entry is removed. Refused opens
/// therefore consume no monotonic identity space.
struct RealtimeFlowIdentity;

impl RealtimeFlowKey {
    fn from_identity(identity: &Arc<RealtimeFlowIdentity>) -> Self {
        Self(Arc::as_ptr(identity) as usize)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RealtimeFlowDropReason {
    OwnerPolicyMissing,
    LocalFlowCeiling,
    FragmentOversize,
    FragmentCount,
    UnitOversize,
    InProgressLimit,
    AggregateBytes,
    FlowQueueFull,
    Retired,
    OwnershipMismatch,
    ResourceUnavailable(ResourceUnavailable),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RealtimeFlowDomain {
    InboundQuarantine,
    OutboundCompatibility,
}

impl RealtimeFlowDomain {
    pub(super) const fn index(self) -> usize {
        match self {
            Self::InboundQuarantine => 0,
            Self::OutboundCompatibility => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RealtimeObservedQuantity {
    Exact(usize),
    Inexact,
}

impl PartialEq<usize> for RealtimeObservedQuantity {
    fn eq(&self, other: &usize) -> bool {
        matches!(self, Self::Exact(value) if value == other)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RealtimeFlowObservation {
    Flow {
        key: RealtimeFlowKey,
        domain: RealtimeFlowDomain,
        active_flows: RealtimeObservedQuantity,
    },
    Assembly {
        key: RealtimeFlowKey,
        in_progress_units: RealtimeObservedQuantity,
        retained_bytes: RealtimeObservedQuantity,
    },
    Queue {
        key: RealtimeFlowKey,
        units: usize,
        retained_bytes: RealtimeObservedQuantity,
    },
    Service {
        key: RealtimeFlowKey,
        queue_age: Duration,
        payload_bytes: usize,
    },
    Drop {
        key: Option<RealtimeFlowKey>,
        reason: RealtimeFlowDropReason,
        queue_age: Duration,
        payload_bytes: usize,
    },
}

/// Observation seam for the owner-run measurement harness.
///
/// Production installs no recorder. Test and lab recorders receive raw values
/// and own their own bounded storage or streaming output.
pub(super) trait RealtimeFlowObserver: Send + Sync {
    fn observe(&self, observation: RealtimeFlowObservation);
}

struct QueuedRealtimeEvent {
    event: QueuedTransportEvent,
    queued_at: Instant,
    payload_bytes: usize,
    /// Exact ownership of the queue record and its logical queued bytes.
    /// The payload lease remains attached to `event` after dequeue.
    _queue_lease: ResourceLease,
}

impl QueuedRealtimeEvent {
    fn transition_to_delivered_payload(
        &mut self,
    ) -> std::result::Result<(), RealtimeFlowDropReason> {
        let reservation = match &mut self.event.event {
            TransportEvent::RealtimeUnit(delivery) => delivery.payload_mut(),
            _ => None,
        }
        .ok_or(RealtimeFlowDropReason::OwnershipMismatch)?;
        reservation.transition_to_retained_payload()
    }
}

#[derive(Default)]
pub(super) struct RealtimeReadyQueue {
    head: Option<RealtimeFlowKey>,
    tail: Option<RealtimeFlowKey>,
    len: usize,
}

impl RealtimeReadyQueue {
    #[cfg(test)]
    pub(super) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[cfg(test)]
    pub(super) const fn len(&self) -> usize {
        self.len
    }
}

struct RealtimeFragmentLeaseNode {
    _lease: ResourceLease,
    next: Option<Box<Self>>,
}

#[derive(Default)]
struct RealtimeFragmentLeases {
    head: Option<Box<RealtimeFragmentLeaseNode>>,
}

impl RealtimeFragmentLeases {
    fn push(&mut self, lease: ResourceLease) {
        self.head = Some(Box::new(RealtimeFragmentLeaseNode {
            _lease: lease,
            next: self.head.take(),
        }));
    }
}

impl Drop for RealtimeFragmentLeases {
    fn drop(&mut self) {
        // Avoid recursive destruction when a generic provider admits many
        // fragments. Provider capacity bounds every node even when no local
        // compatibility ceiling is installed.
        while let Some(mut node) = self.head.take() {
            self.head = node.next.take();
        }
    }
}

pub(super) struct RealtimeFlowQueue {
    domain: RealtimeFlowDomain,
    events: std::collections::LinkedList<QueuedRealtimeEvent>,
    scheduled: bool,
    ready_previous: Option<RealtimeFlowKey>,
    ready_next: Option<RealtimeFlowKey>,
    ready_lease: Option<ResourceLease>,
    in_progress_units: usize,
}

pub(super) struct RealtimeFlowRegistryState {
    pub(super) flows: std::collections::BTreeMap<RealtimeFlowKey, RealtimeFlowQueue>,
    pub(super) ready: RealtimeReadyQueue,
    pub(super) active_flows_by_domain: [usize; 2],
    pub(super) retained_bytes_by_domain: [usize; 2],
    pub(super) in_progress_units_by_domain: [usize; 2],
    pub(super) accounting_poisoned_by_domain: [bool; 2],
    pub(super) retired: bool,
}

pub(super) struct RealtimeFlowRegistry {
    /// Presence of this exact connector scope enables generic real-time work.
    /// It grants no capacity by itself.
    resources: Option<ConnectorWorkResourceScope>,
    /// Optional local or compatibility ceilings. Basal admission never
    /// requires these values and is governed by provider leases.
    local_ceiling: Option<EnabledRealtimeConnectorPolicy>,
    /// The owner's per-unit byte ceiling, when the owner selected one.
    ///
    /// `None` is absence, and absence is not zero. It used to be stored as `0`
    /// with the two readers below testing `local_ceiling.is_some()` first, so
    /// the real meaning lived in a second field and a reader that forgot the
    /// guard would refuse every unit. `Option` puts the absence in the value,
    /// where it cannot be read past.
    pub(super) max_unit_bytes: Option<NonZeroUsize>,
    pub(super) state: SyncMutex<RealtimeFlowRegistryState>,
    pub(super) ready: tokio::sync::Notify,
    observer: Option<Arc<dyn RealtimeFlowObserver>>,
}

/// The resource objects an elastic control registry stands on.
///
/// Held by the control for as long as the registry is used. They are never
/// read — dropping them would retire the scope the registry acquires against,
/// so a control that discarded them would be measuring a dead provider rather
/// than an elastic one.
///
/// `cfg(test)` rather than the lab feature: every caller is an in-crate
/// control, and the lab controls are `#[test]`s too, so a feature-only library
/// build has nothing that could construct one.
#[cfg(test)]
pub(super) struct ElasticControlResources {
    /// The provider underneath, so a control can read what its registry is
    /// actually holding. Without it an elastic control could only assert that
    /// operations succeed — which is exactly what a path that charged nothing
    /// would also do.
    provider: crate::resource::FiniteResourceProvider,
    /// Retention, and nothing else. Dropping any of these retires the scope the
    /// registry acquires against, so a control that discarded them would be
    /// measuring a dead provider.
    _owner: crate::runtime::attempt::ConnectorResourceOwnerPort,
    _candidate: ConnectorCandidateCapability,
    _attempt: AttemptLifetime,
}

#[cfg(test)]
impl ElasticControlResources {
    /// How many accounted bytes the provider is currently holding out.
    ///
    /// One dimension rather than the whole claim, because what an elastic
    /// control needs to distinguish is "charged something" from "charged
    /// nothing", and bytes is the dimension every real-time lease touches.
    pub(super) fn accounted_bytes(&self) -> u64 {
        self.provider
            .in_use()
            .amount(ResourceClass::AccountedMemoryBytes)
    }
}

/// Exact finite ownership of the work one inbound RTP packet costs.
///
/// Held by the pump for the whole of that packet's iteration — classification,
/// reassembly, framing — and released when the iteration ends, whatever the
/// outcome. Retention that outlives the packet takes its own longer-lived
/// lease, so this one measures work rather than storage.
pub(super) struct RealtimeSessionPacketWorkLease {
    _lease: ResourceLease,
}

/// Exact ownership of one in-flight read from the opaque native RTP source.
///
/// The dependency chooses the returned packet size, so this guard owns the
/// read operation and one opaque dependency result until the caller replaces
/// it with the exact content-byte work lease.
pub(super) struct RealtimeNativeReadLease {
    _lease: ResourceLease,
}

impl RealtimeFlowRegistry {
    pub(super) fn new(
        resources: Option<ConnectorWorkResourceScope>,
        local_ceiling: Option<EnabledRealtimeConnectorPolicy>,
    ) -> Arc<Self> {
        Self::with_observer(resources, local_ceiling, None)
    }

    /// An elastic registry over a real provider: resources, and **no** owner
    /// ceilings.
    ///
    /// `Enabled(None)` as a deployment actually states it. Controls that mint a
    /// label or move a unit against this are proving the elastic path admits
    /// through real leases — absence of a ceiling is not absence of accounting
    /// — rather than proving that admission was skipped.
    #[cfg(test)]
    pub(super) fn elastic_for_control(
        grant: ResourceClaim,
    ) -> (Arc<Self>, ElasticControlResources) {
        use crate::resource::{FiniteResourceProvider, ResourceProviderPort};
        use crate::runtime::attempt::{
            admit_single_connector_candidate, ConnectorResourceOwnerPort,
        };
        let provider = FiniteResourceProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone())
            .expect("the control grant accounts for the process scope");
        let owner = ConnectorResourceOwnerPort::new(port);
        let mesh_scope = owner
            .issue_mesh_scope()
            .expect("the control grant accounts for the Mesh scope");
        let (permit, attempt, claim) =
            admit_single_connector_candidate(crate::runtime::RuntimeIncarnation::new(), mesh_scope);
        let candidate = permit
            .reserve_connector_candidate_checked(claim)
            .expect("the control grant has no provider invariant failure")
            .expect("the exact attempt remains active");
        let registry = Self::new(Some(candidate.work_resource_scope()), None);
        (
            registry,
            ElasticControlResources {
                provider,
                _owner: owner,
                _candidate: candidate,
                _attempt: attempt,
            },
        )
    }

    pub(super) fn with_observer(
        resources: Option<ConnectorWorkResourceScope>,
        local_ceiling: Option<EnabledRealtimeConnectorPolicy>,
        observer: Option<Arc<dyn RealtimeFlowObserver>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            resources,
            local_ceiling,
            // Absence stays absence. An owner that selected no ceiling is
            // elastic — admission is the provider's leases — not capped at
            // zero and not unlimited.
            max_unit_bytes: local_ceiling.map(|enabled| enabled.max_unit_bytes()),
            state: SyncMutex::new(RealtimeFlowRegistryState {
                flows: std::collections::BTreeMap::new(),
                ready: RealtimeReadyQueue::default(),
                active_flows_by_domain: [0; 2],
                retained_bytes_by_domain: [0; 2],
                in_progress_units_by_domain: [0; 2],
                accounting_poisoned_by_domain: [false; 2],
                retired: false,
            }),
            ready: tokio::sync::Notify::new(),
            observer,
        })
    }

    fn record(&self, observation: RealtimeFlowObservation) {
        if let Some(observer) = self.observer.as_ref() {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                observer.observe(observation);
            }));
        }
    }

    fn claim_arithmetic_unavailable(error: ResourceClaimArithmeticError) -> ResourceUnavailable {
        let dimension = match error {
            ResourceClaimArithmeticError::Overflow { dimension }
            | ResourceClaimArithmeticError::Underflow { dimension } => dimension,
        };
        ResourceUnavailable::ProviderInvariant { dimension }
    }

    fn measured_bytes(bytes: usize) -> std::result::Result<u64, ResourceUnavailable> {
        u64::try_from(bytes).map_err(|_| ResourceUnavailable::ProviderInvariant {
            dimension: ResourceClass::AccountedMemoryBytes,
        })
    }

    fn claim(
        entries: impl IntoIterator<Item = (ResourceClass, u64)>,
    ) -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        ResourceClaim::try_from_entries(entries).map_err(Self::claim_arithmetic_unavailable)
    }

    pub(super) fn flow_claim() -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        let record_bytes = std::mem::size_of::<RealtimeFlowQueue>()
            .checked_add(std::mem::size_of::<RealtimeFlowLifetime>())
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<RealtimeFlowKey>()))
            .ok_or(ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::AccountedMemoryBytes,
            })?;
        Self::claim([
            (
                ResourceClass::AccountedMemoryBytes,
                Self::measured_bytes(record_bytes)?,
            ),
            // One live flow owns one scheduling or pump obligation. Generic
            // flows may satisfy it without a dedicated task, but no provider
            // can admit the obligation without finite worker capacity.
            (ResourceClass::WorkerOrTask, 1),
            // The identity and lifetime allocations plus one ordered-map node
            // are allocator-owned residuals for this exact live flow. Ready
            // scheduling has a separate lease that follows the ready state.
            (ResourceClass::OpaqueDependencyResidual, 3),
        ])
    }

    pub(super) fn ready_claim() -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        // Ready links are embedded in RealtimeFlowQueue and were included in
        // flow_claim. This lease owns only the live scheduling obligation.
        Self::claim([(ResourceClass::CallbackOrScheduledWork, 1)])
    }

    pub(super) fn assembly_claim() -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        Self::claim([
            (
                ResourceClass::AccountedMemoryBytes,
                Self::measured_bytes(std::mem::size_of::<RealtimeAssemblyReservation>())?,
            ),
            (ResourceClass::CallbackOrScheduledWork, 1),
        ])
    }

    /// The cost of retaining one inbound fragment until its unit completes.
    ///
    /// Two dependency nodes: one owns the fragment lease and one owns the
    /// ordered payload entry the assembler keeps it in. Both persist for
    /// exactly the assembly lifetime.
    pub(super) fn ordered_fragment_claim(
        content_bytes: usize,
    ) -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        let retained_bytes = std::mem::size_of::<RealtimeFragmentLeaseNode>()
            .checked_add(content_bytes)
            .ok_or(ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::AccountedMemoryBytes,
            })?;
        Self::claim([
            (
                ResourceClass::AccountedMemoryBytes,
                Self::measured_bytes(retained_bytes)?,
            ),
            (ResourceClass::ParsingOrCpuWork, 1),
            (ResourceClass::OpaqueDependencyResidual, 2),
        ])
    }

    pub(super) fn output_claim(
        content_bytes: usize,
    ) -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        let retained_bytes = std::mem::size_of::<RealtimePayloadReservation>()
            .checked_add(content_bytes)
            .ok_or(ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::AccountedMemoryBytes,
            })?;
        Self::claim([
            (
                ResourceClass::AccountedMemoryBytes,
                Self::measured_bytes(retained_bytes)?,
            ),
            (ResourceClass::CallbackOrScheduledWork, 1),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
    }

    pub(super) fn retained_payload_claim(
        content_bytes: usize,
    ) -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        let retained_bytes = std::mem::size_of::<RealtimePayloadReservation>()
            .checked_add(content_bytes)
            .ok_or(ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::AccountedMemoryBytes,
            })?;
        Self::claim([
            (
                ResourceClass::AccountedMemoryBytes,
                Self::measured_bytes(retained_bytes)?,
            ),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
    }

    pub(super) fn queue_claim(
        content_bytes: usize,
    ) -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        Self::claim([
            (
                ResourceClass::AccountedMemoryBytes,
                Self::measured_bytes(std::mem::size_of::<QueuedRealtimeEvent>())?,
            ),
            (
                ResourceClass::QueuedBytes,
                Self::measured_bytes(content_bytes)?,
            ),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
    }

    /// The per-packet cost of classifying and framing one inbound RTP payload.
    ///
    /// Sized by the payload it covers, so a large packet costs more than a small
    /// one and the provider is the thing that says no. Retained fragments and
    /// complete outputs acquire their own longer-lived leases on top of this.
    pub(super) fn session_packet_work_claim(
        content_bytes: usize,
    ) -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        Self::claim([
            (
                ResourceClass::AccountedMemoryBytes,
                Self::measured_bytes(content_bytes)?,
            ),
            (ResourceClass::ParsingOrCpuWork, 1),
        ])
    }

    pub(super) fn native_read_claim() -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        Self::claim([
            (ResourceClass::CallbackOrScheduledWork, 1),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
    }

    /// Everything one shared label record costs, for as long as anything holds
    /// it.
    ///
    /// `record_bytes` is `size_of::<LeasedLabel>()` — the struct itself, which
    /// contains the name's boxed-slice header and the lease handle.
    /// `content_bytes` is the byte buffer that header points at, and it is
    /// exact rather than approximate: the name is a `Box<[u8]>`, so it has no
    /// spare capacity and its length *is* its allocation. `arc_counters` is the
    /// strong/weak pair the `Arc` puts beside the record. Three terms because
    /// the allocation genuinely has three parts, and stating fewer would
    /// under-charge by whichever was omitted.
    ///
    /// The residual is 2 because the representation retains two allocations:
    /// the `Arc` block and the byte buffer. It follows the representation — an
    /// inline single-allocation DST would make it 1 — and it counts allocator
    /// overhead, which has no portable size. It is a count, never a substitute
    /// for the bytes above.
    ///
    /// Charged once against the record every copy of the label shares, so a
    /// label sitting simultaneously in the held set, the flows map, a queued
    /// arrival, an inbound binding and a close event is paid for once and paid
    /// for until the *last* of those drops, not until the flow does.
    pub(super) fn label_claim(
        record_bytes: usize,
        content_bytes: usize,
    ) -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        let overflow = || ResourceUnavailable::ProviderInvariant {
            dimension: ResourceClass::AccountedMemoryBytes,
        };
        let arc_counters = std::mem::size_of::<usize>()
            .checked_mul(2)
            .ok_or_else(overflow)?;
        let retained_bytes = record_bytes
            .checked_add(content_bytes)
            .and_then(|bytes| bytes.checked_add(arc_counters))
            .ok_or_else(overflow)?;
        Self::claim([
            (
                ResourceClass::AccountedMemoryBytes,
                Self::measured_bytes(retained_bytes)?,
            ),
            (ResourceClass::OpaqueDependencyResidual, 2),
        ])
    }

    /// Take the lease that owns one label's bytes.
    ///
    /// Separate from every other acquisition here because a label is not a
    /// flow: it is minted when a session accepts the name and released when the
    /// last retained copy drops, and those are different moments from the
    /// flow's open and close. Refusal is the ordinary typed refusal — a
    /// provider under pressure declines the name and the open fails closed,
    /// rather than retaining bytes nothing accounted for.
    pub(super) fn acquire_label_lease(
        &self,
        record_bytes: usize,
        content_bytes: usize,
    ) -> std::result::Result<ResourceLease, RealtimeFlowDropReason> {
        self.acquire(Self::label_claim(record_bytes, content_bytes))
            .map_err(|reason| self.record_drop(None, reason, 0))
    }

    /// Everything one shared real-time profile costs on the heap.
    ///
    /// A profile is deep: a `Vec` of codecs, each carrying a `mime` and `fmtp`
    /// `String` and a `Vec` of feedback entries with two `String`s apiece. Every
    /// promotion used to clone all of it and pay for none of it. It is now
    /// shared behind an `Arc` instead, so this is charged once — by the
    /// connector that registered it — and a promotion clones a pointer.
    ///
    /// Measured by walking the actual strings and vectors rather than by any
    /// per-codec estimate: the deployed profile is five H.264 variants whose
    /// `fmtp` lines differ in length, so an average would be wrong in both
    /// directions.
    /// Three terms, the same shape as [`Self::label_claim`] and for the same
    /// reason: the record itself, the heap it points at, and the strong/weak
    /// counter pair the `Arc` puts beside the record. The counters are not
    /// optional bookkeeping — they are retained for exactly as long as the
    /// record is — and omitting them here while charging them for a label
    /// would have made two shared records of the same shape cost differently.
    pub(super) fn profile_claim(
        record_bytes: usize,
        content_bytes: usize,
        allocations: u64,
    ) -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        let overflow = || ResourceUnavailable::ProviderInvariant {
            dimension: ResourceClass::AccountedMemoryBytes,
        };
        let arc_counters = std::mem::size_of::<usize>()
            .checked_mul(2)
            .ok_or_else(overflow)?;
        let retained_bytes = record_bytes
            .checked_add(content_bytes)
            .and_then(|bytes| bytes.checked_add(arc_counters))
            .ok_or_else(overflow)?;
        Self::claim([
            (
                ResourceClass::AccountedMemoryBytes,
                Self::measured_bytes(retained_bytes)?,
            ),
            (ResourceClass::OpaqueDependencyResidual, allocations),
        ])
    }

    /// Take the lease that owns one shared profile record.
    ///
    /// Separate from every other acquisition here for the same reason the
    /// label's is: a profile is minted when the connector accepts the
    /// application's registration and released when the last session holding it
    /// drops, and neither moment is a flow's open or close.
    pub(super) fn acquire_profile_lease(
        &self,
        record_bytes: usize,
        content_bytes: usize,
        allocations: u64,
    ) -> std::result::Result<ResourceLease, RealtimeFlowDropReason> {
        self.acquire(Self::profile_claim(
            record_bytes,
            content_bytes,
            allocations,
        ))
        .map_err(|reason| self.record_drop(None, reason, 0))
    }

    fn acquire(
        &self,
        claim: std::result::Result<ResourceClaim, ResourceUnavailable>,
    ) -> std::result::Result<ResourceLease, RealtimeFlowDropReason> {
        let claim = claim.map_err(RealtimeFlowDropReason::ResourceUnavailable)?;
        let resources = self
            .resources
            .as_ref()
            .ok_or(RealtimeFlowDropReason::OwnerPolicyMissing)?;
        resources
            .acquire(ResourceAuthorityClass::Speculative, claim)
            .map_err(RealtimeFlowDropReason::ResourceUnavailable)
    }

    fn record_drop(
        &self,
        key: Option<RealtimeFlowKey>,
        reason: RealtimeFlowDropReason,
        payload_bytes: usize,
    ) -> RealtimeFlowDropReason {
        self.record(RealtimeFlowObservation::Drop {
            key,
            reason,
            queue_age: Duration::ZERO,
            payload_bytes,
        });
        reason
    }

    #[allow(
        clippy::result_large_err,
        reason = "the failure returns the exact move-only ready-node lease without allocating under pressure"
    )]
    fn push_ready_locked(
        state: &mut RealtimeFlowRegistryState,
        key: RealtimeFlowKey,
        lease: ResourceLease,
    ) -> std::result::Result<(), ResourceLease> {
        let previous = state.ready.tail;
        let can_link = state
            .flows
            .get(&key)
            .is_some_and(|flow| !flow.scheduled && flow.ready_lease.is_none())
            && previous.is_none_or(|previous| state.flows.contains_key(&previous));
        let Some(next_len) = state.ready.len.checked_add(1) else {
            return Err(lease);
        };
        if !can_link {
            return Err(lease);
        }

        if let Some(previous) = previous {
            state
                .flows
                .get_mut(&previous)
                .expect("the ready predecessor was validated")
                .ready_next = Some(key);
        } else {
            state.ready.head = Some(key);
        }
        let flow = state
            .flows
            .get_mut(&key)
            .expect("the ready flow was validated");
        flow.scheduled = true;
        flow.ready_previous = previous;
        flow.ready_next = None;
        flow.ready_lease = Some(lease);
        state.ready.tail = Some(key);
        state.ready.len = next_len;
        Ok(())
    }

    fn pop_ready_locked(
        state: &mut RealtimeFlowRegistryState,
    ) -> Option<(RealtimeFlowKey, ResourceLease)> {
        let key = state.ready.head?;
        let (next, lease) = {
            let flow = state.flows.get_mut(&key)?;
            let lease = flow.ready_lease.take()?;
            let next = flow.ready_next.take();
            flow.ready_previous = None;
            flow.scheduled = false;
            (next, lease)
        };
        state.ready.head = next;
        if let Some(next) = next {
            state
                .flows
                .get_mut(&next)
                .expect("a ready successor remains in the registry")
                .ready_previous = None;
        } else {
            state.ready.tail = None;
        }
        state.ready.len = state
            .ready
            .len
            .checked_sub(1)
            .expect("a ready head contributes one ready entry");
        Some((key, lease))
    }

    fn unlink_ready_locked(
        state: &mut RealtimeFlowRegistryState,
        key: RealtimeFlowKey,
    ) -> Option<ResourceLease> {
        let (previous, next, lease) = {
            let flow = state.flows.get_mut(&key)?;
            if !flow.scheduled {
                return None;
            }
            let lease = flow.ready_lease.take()?;
            let previous = flow.ready_previous.take();
            let next = flow.ready_next.take();
            flow.scheduled = false;
            (previous, next, lease)
        };
        if let Some(previous) = previous {
            state
                .flows
                .get_mut(&previous)
                .expect("a ready predecessor remains in the registry")
                .ready_next = next;
        } else {
            state.ready.head = next;
        }
        if let Some(next) = next {
            state
                .flows
                .get_mut(&next)
                .expect("a ready successor remains in the registry")
                .ready_previous = previous;
        } else {
            state.ready.tail = previous;
        }
        state.ready.len = state
            .ready
            .len
            .checked_sub(1)
            .expect("a linked flow contributes one ready entry");
        Some(lease)
    }

    fn open_flow_checked(
        self: &Arc<Self>,
        domain: RealtimeFlowDomain,
    ) -> std::result::Result<RealtimeFlowPort, RealtimeFlowDropReason> {
        if self.resources.is_none() {
            return Err(self.record_drop(None, RealtimeFlowDropReason::OwnerPolicyMissing, 0));
        }
        // Admission happens before either the flow owner or its registry entry
        // is allocated. The lease follows the flow lifetime through removal.
        let lease = self
            .acquire(Self::flow_claim())
            .map_err(|reason| self.record_drop(None, reason, 0))?;
        let identity = Arc::new(RealtimeFlowIdentity);
        let key = RealtimeFlowKey::from_identity(&identity);
        let mut state = self.state.lock();
        if state.retired {
            return Err(RealtimeFlowDropReason::Retired);
        }
        if self.local_ceiling.is_some() && state.accounting_poisoned_by_domain[domain.index()] {
            return Err(RealtimeFlowDropReason::AggregateBytes);
        }
        let active_in_domain = state.active_flows_by_domain[domain.index()];
        if let Some(policy) = self.local_ceiling {
            let limit = match domain {
                RealtimeFlowDomain::InboundQuarantine => {
                    policy.flows().max_inbound_active_flows().get()
                }
                RealtimeFlowDomain::OutboundCompatibility => {
                    policy.flows().max_outbound_active_flows().get()
                }
            };
            if active_in_domain >= limit {
                drop(state);
                return Err(self.record_drop(
                    Some(key),
                    RealtimeFlowDropReason::LocalFlowCeiling,
                    0,
                ));
            }
        }
        state.flows.insert(
            key,
            RealtimeFlowQueue {
                domain,
                events: std::collections::LinkedList::new(),
                scheduled: false,
                ready_previous: None,
                ready_next: None,
                ready_lease: None,
                in_progress_units: 0,
            },
        );
        let Some(active_flows) = active_in_domain.checked_add(1) else {
            self.poison_domain_locked(&mut state, domain);
            state.flows.remove(&key);
            return Err(RealtimeFlowDropReason::ResourceUnavailable(
                ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::AccountedMemoryBytes,
                },
            ));
        };
        state.active_flows_by_domain[domain.index()] = active_flows;
        drop(state);
        self.record(RealtimeFlowObservation::Flow {
            key,
            domain,
            active_flows: RealtimeObservedQuantity::Exact(active_flows),
        });
        Ok(RealtimeFlowPort {
            lifetime: Arc::new(RealtimeFlowLifetime {
                key,
                registry: Arc::clone(self),
                _identity: identity,
                _lease: lease,
            }),
        })
    }

    pub(super) fn open_inbound_flow_checked(
        self: &Arc<Self>,
    ) -> std::result::Result<RealtimeFlowPort, RealtimeFlowDropReason> {
        self.open_flow_checked(RealtimeFlowDomain::InboundQuarantine)
    }

    #[cfg(test)]
    pub(super) fn open_inbound_flow(self: &Arc<Self>) -> Option<RealtimeFlowPort> {
        self.open_inbound_flow_checked().ok()
    }

    pub(super) fn open_outbound_flow_checked(
        self: &Arc<Self>,
    ) -> std::result::Result<RealtimeFlowPort, RealtimeFlowDropReason> {
        self.open_flow_checked(RealtimeFlowDomain::OutboundCompatibility)
    }

    #[cfg(test)]
    pub(super) fn open_outbound_flow(self: &Arc<Self>) -> Option<RealtimeFlowPort> {
        self.open_outbound_flow_checked().ok()
    }

    fn remove_flow(&self, key: RealtimeFlowKey) {
        let mut state = self.state.lock();
        let ready_lease = Self::unlink_ready_locked(&mut state, key);
        if let Some(flow) = state.flows.remove(&key) {
            let domain = flow.domain;
            let active_flows = match state.active_flows_by_domain[domain.index()].checked_sub(1) {
                Some(active) => {
                    state.active_flows_by_domain[domain.index()] = active;
                    RealtimeObservedQuantity::Exact(active)
                }
                None => {
                    self.poison_domain_locked(&mut state, domain);
                    RealtimeObservedQuantity::Inexact
                }
            };
            drop(state);
            self.record(RealtimeFlowObservation::Flow {
                key,
                domain,
                active_flows,
            });
            // Drop queued payloads after releasing the registry mutex. Their
            // exact byte leases return capacity through the same registry.
            drop(ready_lease);
            drop(flow);
        }
    }

    fn retained_bytes(state: &RealtimeFlowRegistryState) -> RealtimeObservedQuantity {
        if state
            .accounting_poisoned_by_domain
            .into_iter()
            .any(|poisoned| poisoned)
        {
            return RealtimeObservedQuantity::Inexact;
        }
        state.retained_bytes_by_domain[0]
            .checked_add(state.retained_bytes_by_domain[1])
            .map(RealtimeObservedQuantity::Exact)
            .unwrap_or(RealtimeObservedQuantity::Inexact)
    }

    pub(super) fn in_progress_units(state: &RealtimeFlowRegistryState) -> RealtimeObservedQuantity {
        if state
            .accounting_poisoned_by_domain
            .into_iter()
            .any(|poisoned| poisoned)
        {
            return RealtimeObservedQuantity::Inexact;
        }
        state.in_progress_units_by_domain[0]
            .checked_add(state.in_progress_units_by_domain[1])
            .map(RealtimeObservedQuantity::Exact)
            .unwrap_or(RealtimeObservedQuantity::Inexact)
    }

    fn domain_byte_limit(&self, domain: RealtimeFlowDomain) -> Option<usize> {
        let budgets = self.local_ceiling?.flows().byte_budgets();
        Some(match domain {
            RealtimeFlowDomain::InboundQuarantine => budgets.max_inbound_bytes().get(),
            RealtimeFlowDomain::OutboundCompatibility => budgets.max_outbound_bytes().get(),
        })
    }

    fn poison_domain_locked(
        &self,
        state: &mut RealtimeFlowRegistryState,
        domain: RealtimeFlowDomain,
    ) {
        let index = domain.index();
        state.accounting_poisoned_by_domain[index] = true;
        if let Some(limit) = self.domain_byte_limit(domain) {
            state.retained_bytes_by_domain[index] = limit;
        }
    }

    fn release_bytes_locked(
        &self,
        state: &mut RealtimeFlowRegistryState,
        domain: RealtimeFlowDomain,
        bytes: usize,
    ) -> bool {
        let index = domain.index();
        if state.accounting_poisoned_by_domain[index] {
            return false;
        }
        match state.retained_bytes_by_domain[index].checked_sub(bytes) {
            Some(retained) => {
                state.retained_bytes_by_domain[index] = retained;
                true
            }
            None => {
                self.poison_domain_locked(state, domain);
                false
            }
        }
    }

    fn release_unit_locked(
        &self,
        state: &mut RealtimeFlowRegistryState,
        domain: RealtimeFlowDomain,
    ) -> bool {
        if state.accounting_poisoned_by_domain[domain.index()] {
            return false;
        }
        let index = domain.index();
        match state.in_progress_units_by_domain[index].checked_sub(1) {
            Some(units) => {
                state.in_progress_units_by_domain[index] = units;
                true
            }
            None => {
                self.poison_domain_locked(state, domain);
                false
            }
        }
    }

    pub(super) fn begin_unit_checked(
        self: &Arc<Self>,
        lifetime: Arc<RealtimeFlowLifetime>,
    ) -> std::result::Result<RealtimeAssemblyReservation, RealtimeFlowDropReason> {
        let key = lifetime.key;
        let lease = self
            .acquire(Self::assembly_claim())
            .map_err(|reason| self.record_drop(Some(key), reason, 0))?;
        let mut state = self.state.lock();
        if state.retired {
            return Err(RealtimeFlowDropReason::Retired);
        }
        let domain = state
            .flows
            .get(&key)
            .ok_or(RealtimeFlowDropReason::Retired)?
            .domain;
        if self.local_ceiling.is_some() && state.accounting_poisoned_by_domain[domain.index()] {
            return Err(RealtimeFlowDropReason::AggregateBytes);
        }
        let current_flow_units = state
            .flows
            .get(&key)
            .ok_or(RealtimeFlowDropReason::Retired)?
            .in_progress_units;
        if self.local_ceiling.is_some_and(|policy| {
            current_flow_units >= policy.flows().max_in_progress_units_per_flow().get()
        }) {
            drop(state);
            return Err(self.record_drop(Some(key), RealtimeFlowDropReason::InProgressLimit, 0));
        }
        let Some(next_flow_units) = current_flow_units.checked_add(1) else {
            self.poison_domain_locked(&mut state, domain);
            return Err(RealtimeFlowDropReason::ResourceUnavailable(
                ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::CallbackOrScheduledWork,
                },
            ));
        };
        let index = domain.index();
        let Some(next_domain_units) = state.in_progress_units_by_domain[index].checked_add(1)
        else {
            self.poison_domain_locked(&mut state, domain);
            return Err(RealtimeFlowDropReason::ResourceUnavailable(
                ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::CallbackOrScheduledWork,
                },
            ));
        };
        let Some(flow) = state.flows.get_mut(&key) else {
            self.poison_domain_locked(&mut state, domain);
            return Err(RealtimeFlowDropReason::Retired);
        };
        flow.in_progress_units = next_flow_units;
        state.in_progress_units_by_domain[index] = next_domain_units;
        let in_progress_units = Self::in_progress_units(&state);
        let retained_bytes = Self::retained_bytes(&state);
        drop(state);
        self.record(RealtimeFlowObservation::Assembly {
            key,
            in_progress_units,
            retained_bytes,
        });
        Ok(RealtimeAssemblyReservation {
            registry: Arc::clone(self),
            key,
            domain,
            _lifetime: lifetime,
            _lease: lease,
            fragment_leases: RealtimeFragmentLeases::default(),
            retained_bytes: 0,
            retained_fragments: 0,
            active: true,
        })
    }

    /// Admit the work of classifying one inbound RTP packet on an open flow.
    ///
    /// **Accounting, not admission.** The caller is the pump for a track that
    /// already attached to a binding the promoted session established, so the
    /// question of whether this packet may be processed at all was answered
    /// before this pump existed. What is decided here is whether the provider
    /// can currently afford the work, and whether this domain's accounting is
    /// still trustworthy.
    ///
    /// There is deliberately no cumulative packet or byte envelope. A ceiling
    /// that latches would end a long-lived session at an arbitrary packet
    /// count, and one that resets would be a timer by another name. Sustained
    /// inbound pressure is bounded where it is actually held — the per-packet
    /// claim above, the per-flow in-progress and fragment limits, the queue
    /// depth, and the aggregate retained-byte ceiling — every one of which
    /// releases as the work completes.
    pub(super) fn admit_session_packet_checked(
        &self,
        payload_bytes: usize,
    ) -> std::result::Result<RealtimeSessionPacketWorkLease, RealtimeFlowDropReason> {
        let work = self
            .acquire(Self::session_packet_work_claim(payload_bytes))
            .map_err(|reason| self.record_drop(None, reason, payload_bytes))?;
        let state = self.state.lock();
        let domain = RealtimeFlowDomain::InboundQuarantine;
        if state.retired {
            return Err(RealtimeFlowDropReason::Retired);
        }
        // Same answer as every other acquisition on a damaged domain: the
        // aggregate is no longer trustworthy, so nothing more is admitted
        // against it.
        if self.local_ceiling.is_some() && state.accounting_poisoned_by_domain[domain.index()] {
            return Err(RealtimeFlowDropReason::AggregateBytes);
        }
        Ok(RealtimeSessionPacketWorkLease { _lease: work })
    }

    pub(super) fn begin_native_read_checked(
        &self,
    ) -> std::result::Result<RealtimeNativeReadLease, RealtimeFlowDropReason> {
        let lease = self
            .acquire(Self::native_read_claim())
            .map_err(|reason| self.record_drop(None, reason, 0))?;
        if self.state.lock().retired {
            return Err(RealtimeFlowDropReason::Retired);
        }
        Ok(RealtimeNativeReadLease { _lease: lease })
    }

    #[cfg(test)]
    pub(super) fn admit_session_packet(&self, payload_bytes: usize) -> bool {
        self.admit_session_packet_checked(payload_bytes).is_ok()
    }

    pub(super) fn reserve_output_checked(
        self: &Arc<Self>,
        key: RealtimeFlowKey,
        bytes: usize,
    ) -> std::result::Result<RealtimeOutputReservation, RealtimeFlowDropReason> {
        // No ceiling selected means no oversize refusal: the lease below is the
        // admission, and a provider under pressure is what says no.
        if self.max_unit_bytes.is_some_and(|max| bytes > max.get()) {
            return Err(self.record_drop(Some(key), RealtimeFlowDropReason::UnitOversize, bytes));
        }
        let lease = self
            .acquire(Self::output_claim(bytes))
            .map_err(|reason| self.record_drop(Some(key), reason, bytes))?;
        let mut state = self.state.lock();
        if state.retired {
            return Err(RealtimeFlowDropReason::Retired);
        }
        let domain = state
            .flows
            .get(&key)
            .ok_or(RealtimeFlowDropReason::Retired)?
            .domain;
        if self.local_ceiling.is_some() && state.accounting_poisoned_by_domain[domain.index()] {
            return Err(RealtimeFlowDropReason::AggregateBytes);
        }
        let index = domain.index();
        let next_domain = match state.retained_bytes_by_domain[index].checked_add(bytes) {
            Some(next) => Some(next),
            None if self.local_ceiling.is_some() => {
                self.poison_domain_locked(&mut state, domain);
                return Err(RealtimeFlowDropReason::AggregateBytes);
            }
            None => {
                // Provider accounting remains authoritative. Mark the local
                // observation inexact without inventing a replacement value.
                state.accounting_poisoned_by_domain[index] = true;
                None
            }
        };
        if next_domain.is_some_and(|next| {
            self.domain_byte_limit(domain)
                .is_some_and(|limit| next > limit)
        }) {
            drop(state);
            return Err(self.record_drop(Some(key), RealtimeFlowDropReason::AggregateBytes, bytes));
        }
        if let Some(next_domain) = next_domain {
            state.retained_bytes_by_domain[index] = next_domain;
        }
        drop(state);
        Ok(RealtimeOutputReservation {
            registry: Arc::clone(self),
            key,
            domain,
            lease: Some(lease),
            bytes,
            active: true,
        })
    }

    pub(super) fn enqueue_checked(
        &self,
        key: RealtimeFlowKey,
        mut event: QueuedTransportEvent,
        reservation: RealtimeOutputReservation,
    ) -> std::result::Result<bool, RealtimeFlowDropReason> {
        if !std::ptr::eq(self, Arc::as_ref(&reservation.registry))
            || reservation.key != key
            || !reservation.active
        {
            return Err(RealtimeFlowDropReason::OwnershipMismatch);
        }
        // The queue record and queued-byte claim are separate from the payload
        // lease. Dequeue releases this lease while payload clones retain theirs.
        let queue_lease = self
            .acquire(Self::queue_claim(reservation.bytes))
            .map_err(|reason| self.record_drop(Some(key), reason, reservation.bytes))?;
        let now = Instant::now();
        let domain = reservation.domain;
        let payload_bytes = reservation.bytes;
        let reservation = reservation.into_payload_lease();
        if let Err(reservation) = event.attach_realtime_reservation(reservation) {
            drop(reservation);
            return Err(RealtimeFlowDropReason::OwnershipMismatch);
        }
        let mut event = Some(event);
        let mut queue_lease = Some(queue_lease);
        let mut ready_lease = None;
        let (units, retained_bytes) = loop {
            let mut state = self.state.lock();
            if state.retired {
                return Err(RealtimeFlowDropReason::Retired);
            }
            if self.local_ceiling.is_some() && state.accounting_poisoned_by_domain[domain.index()] {
                return Err(RealtimeFlowDropReason::AggregateBytes);
            }
            let Some(flow) = state.flows.get(&key) else {
                drop(state);
                return Err(self.record_drop(
                    Some(key),
                    RealtimeFlowDropReason::Retired,
                    payload_bytes,
                ));
            };
            if flow.domain != domain {
                self.poison_domain_locked(&mut state, domain);
                return Err(RealtimeFlowDropReason::OwnershipMismatch);
            }
            if self.local_ceiling.is_some_and(|policy| {
                flow.events.len() >= policy.flows().queue_capacity_per_flow().get()
            }) {
                drop(state);
                self.record_drop(
                    Some(key),
                    RealtimeFlowDropReason::FlowQueueFull,
                    payload_bytes,
                );
                return Ok(
                    match self
                        .local_ceiling
                        .expect("checked local ceiling")
                        .flows()
                        .overflow_rule()
                    {
                        crate::runtime::attempt::RealtimeQueueOverflowRule::DropNewest => true,
                    },
                );
            }
            let needs_ready = flow.events.is_empty() && !flow.scheduled;
            if needs_ready && ready_lease.is_none() {
                drop(state);
                ready_lease = Some(
                    self.acquire(Self::ready_claim())
                        .map_err(|reason| self.record_drop(Some(key), reason, payload_bytes))?,
                );
                continue;
            }

            state
                .flows
                .get_mut(&key)
                .expect("the validated flow remains under the registry lock")
                .events
                .push_back(QueuedRealtimeEvent {
                    event: event
                        .take()
                        .expect("the event is moved exactly once into its admitted queue"),
                    queued_at: now,
                    payload_bytes,
                    _queue_lease: queue_lease
                        .take()
                        .expect("the queue lease is moved with its exact queue record"),
                });
            if needs_ready {
                let lease = ready_lease
                    .take()
                    .expect("ready admission acquired the exact scheduling lease");
                if let Err(lease) = Self::push_ready_locked(&mut state, key, lease) {
                    let event = state
                        .flows
                        .get_mut(&key)
                        .and_then(|flow| flow.events.pop_back());
                    drop(state);
                    drop(lease);
                    drop(event);
                    return Err(RealtimeFlowDropReason::OwnershipMismatch);
                }
            }
            let units = state.flows.get(&key).map_or(0, |flow| flow.events.len());
            let retained_bytes = Self::retained_bytes(&state);
            break (units, retained_bytes);
        };
        drop(ready_lease);
        self.record(RealtimeFlowObservation::Queue {
            key,
            units,
            retained_bytes,
        });
        self.ready.notify_one();
        Ok(true)
    }

    pub(super) fn try_recv(&self) -> Option<QueuedTransportEvent> {
        loop {
            let now = Instant::now();
            let mut state = self.state.lock();
            if state.retired {
                return None;
            }
            let (key, ready_lease) = Self::pop_ready_locked(&mut state)?;
            let Some(flow) = state.flows.get_mut(&key) else {
                drop(state);
                drop(ready_lease);
                continue;
            };
            let Some(mut event) = flow.events.pop_front() else {
                drop(state);
                drop(ready_lease);
                continue;
            };
            let unused_ready_lease = if !flow.events.is_empty() {
                if let Err(lease) = Self::push_ready_locked(&mut state, key, ready_lease) {
                    drop(state);
                    drop(lease);
                    drop(event);
                    self.record_drop(Some(key), RealtimeFlowDropReason::OwnershipMismatch, 0);
                    continue;
                }
                None
            } else {
                Some(ready_lease)
            };
            drop(state);
            drop(unused_ready_lease);
            if let Err(reason) = event.transition_to_delivered_payload() {
                self.record_drop(Some(key), reason, event.payload_bytes);
                drop(event);
                continue;
            }
            self.record(RealtimeFlowObservation::Service {
                key,
                queue_age: now.saturating_duration_since(event.queued_at),
                payload_bytes: event.payload_bytes,
            });
            return Some(event.event);
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.state
            .lock()
            .flows
            .values()
            .all(|flow| flow.events.is_empty())
    }

    /// Stop all later flow work and release every queued complete unit.
    /// In-progress assembly reservations remain with their exact owners and
    /// release when those owners return or are cancelled.
    pub(super) fn retire(&self) {
        {
            let mut state = self.state.lock();
            if state.retired {
                return;
            }
            state.retired = true;
        }
        loop {
            let ready_lease = {
                let mut state = self.state.lock();
                Self::pop_ready_locked(&mut state).map(|(_, lease)| lease)
            };
            let Some(ready_lease) = ready_lease else {
                break;
            };
            drop(ready_lease);
        }
        let queued = {
            let mut state = self.state.lock();
            let mut queued = std::collections::LinkedList::new();
            for flow in state.flows.values_mut() {
                queued.append(&mut flow.events);
            }
            queued
        };
        drop(queued);
        self.ready.notify_waiters();
    }
}

pub(super) struct RealtimeFlowLifetime {
    key: RealtimeFlowKey,
    pub(super) registry: Arc<RealtimeFlowRegistry>,
    _identity: Arc<RealtimeFlowIdentity>,
    _lease: ResourceLease,
}

impl Drop for RealtimeFlowLifetime {
    fn drop(&mut self) {
        self.registry.remove_flow(self.key);
    }
}

#[derive(Clone)]
pub(super) struct RealtimeFlowPort {
    pub(super) lifetime: Arc<RealtimeFlowLifetime>,
}

impl RealtimeFlowPort {
    pub(super) fn key(&self) -> RealtimeFlowKey {
        self.lifetime.key
    }

    pub(super) fn begin_unit_checked(
        &self,
    ) -> std::result::Result<RealtimeAssemblyReservation, RealtimeFlowDropReason> {
        self.lifetime
            .registry
            .begin_unit_checked(Arc::clone(&self.lifetime))
    }

    pub(super) fn begin_unit(&self) -> Option<RealtimeAssemblyReservation> {
        self.begin_unit_checked().ok()
    }

    pub(super) fn reserve_output_checked(
        &self,
        bytes: usize,
    ) -> std::result::Result<RealtimeOutputReservation, RealtimeFlowDropReason> {
        self.lifetime
            .registry
            .reserve_output_checked(self.key(), bytes)
    }

    pub(super) fn reserve_output(&self, bytes: usize) -> Option<RealtimeOutputReservation> {
        self.reserve_output_checked(bytes).ok()
    }

    pub(super) fn enqueue_checked(
        &self,
        event: QueuedTransportEvent,
        reservation: RealtimeOutputReservation,
    ) -> std::result::Result<bool, RealtimeFlowDropReason> {
        self.lifetime
            .registry
            .enqueue_checked(self.key(), event, reservation)
    }

    pub(super) fn enqueue(
        &self,
        event: QueuedTransportEvent,
        reservation: RealtimeOutputReservation,
    ) -> bool {
        self.enqueue_checked(event, reservation).unwrap_or(false)
    }
}

pub(super) struct RealtimeAssemblyReservation {
    registry: Arc<RealtimeFlowRegistry>,
    key: RealtimeFlowKey,
    domain: RealtimeFlowDomain,
    _lifetime: Arc<RealtimeFlowLifetime>,
    _lease: ResourceLease,
    fragment_leases: RealtimeFragmentLeases,
    retained_bytes: usize,
    retained_fragments: usize,
    active: bool,
}

impl RealtimeAssemblyReservation {
    fn poison_domain(&self) {
        let mut state = self.registry.state.lock();
        self.registry.poison_domain_locked(&mut state, self.domain);
    }

    pub(super) fn retain_ordered_fragment_checked(
        &mut self,
        bytes: usize,
    ) -> std::result::Result<(), RealtimeFlowDropReason> {
        let claim = RealtimeFlowRegistry::ordered_fragment_claim(bytes);
        let local_ceiling = self
            .registry
            .local_ceiling
            .map(EnabledRealtimeConnectorPolicy::flows);
        if local_ceiling.is_some_and(|policy| bytes > policy.max_inbound_fragment_bytes().get()) {
            self.registry.record(RealtimeFlowObservation::Drop {
                key: Some(self.key),
                reason: RealtimeFlowDropReason::FragmentOversize,
                queue_age: Duration::ZERO,
                payload_bytes: bytes,
            });
            return Err(RealtimeFlowDropReason::FragmentOversize);
        }
        let Some(fragment_count) = self.retained_fragments.checked_add(1) else {
            self.poison_domain();
            return Err(RealtimeFlowDropReason::ResourceUnavailable(
                ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::ParsingOrCpuWork,
                },
            ));
        };
        if local_ceiling
            .is_some_and(|policy| fragment_count > policy.max_inbound_fragments_per_unit().get())
        {
            self.registry.record(RealtimeFlowObservation::Drop {
                key: Some(self.key),
                reason: RealtimeFlowDropReason::FragmentCount,
                queue_age: Duration::ZERO,
                payload_bytes: bytes,
            });
            return Err(RealtimeFlowDropReason::FragmentCount);
        }
        let Some(unit_bytes) = self.retained_bytes.checked_add(bytes) else {
            self.poison_domain();
            return Err(RealtimeFlowDropReason::ResourceUnavailable(
                ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::AccountedMemoryBytes,
                },
            ));
        };
        if self
            .registry
            .max_unit_bytes
            .is_some_and(|max| unit_bytes > max.get())
        {
            self.registry.record(RealtimeFlowObservation::Drop {
                key: Some(self.key),
                reason: RealtimeFlowDropReason::UnitOversize,
                queue_age: Duration::ZERO,
                payload_bytes: unit_bytes,
            });
            return Err(RealtimeFlowDropReason::UnitOversize);
        }

        // Acquire before the compatibility assembler retains its payload
        // clone. Each accepted fragment keeps one distinct finite lease until
        // the complete unit, cancellation, replacement, or flow retirement
        // drops this assembly owner.
        let fragment_lease = self
            .registry
            .acquire(claim)
            .map_err(|reason| self.registry.record_drop(Some(self.key), reason, bytes))?;
        let mut state = self.registry.state.lock();
        if self.registry.local_ceiling.is_some()
            && state.accounting_poisoned_by_domain[self.domain.index()]
        {
            return Err(RealtimeFlowDropReason::AggregateBytes);
        }
        let index = self.domain.index();
        let next_domain = match state.retained_bytes_by_domain[index].checked_add(bytes) {
            Some(next) => Some(next),
            None if self.registry.local_ceiling.is_some() => {
                self.registry.poison_domain_locked(&mut state, self.domain);
                return Err(RealtimeFlowDropReason::AggregateBytes);
            }
            None => {
                state.accounting_poisoned_by_domain[index] = true;
                None
            }
        };
        if next_domain.is_some_and(|next| {
            self.registry
                .domain_byte_limit(self.domain)
                .is_some_and(|limit| next > limit)
        }) {
            drop(state);
            self.registry.record(RealtimeFlowObservation::Drop {
                key: Some(self.key),
                reason: RealtimeFlowDropReason::AggregateBytes,
                queue_age: Duration::ZERO,
                payload_bytes: bytes,
            });
            return Err(RealtimeFlowDropReason::AggregateBytes);
        }
        if let Some(next_domain) = next_domain {
            state.retained_bytes_by_domain[index] = next_domain;
        }
        self.fragment_leases.push(fragment_lease);
        self.retained_bytes = unit_bytes;
        self.retained_fragments = fragment_count;
        let in_progress_units = RealtimeFlowRegistry::in_progress_units(&state);
        let retained_bytes = RealtimeFlowRegistry::retained_bytes(&state);
        drop(state);
        self.registry.record(RealtimeFlowObservation::Assembly {
            key: self.key,
            in_progress_units,
            retained_bytes,
        });
        Ok(())
    }

    pub(super) fn retain_ordered_fragment(&mut self, bytes: usize) -> bool {
        self.retain_ordered_fragment_checked(bytes).is_ok()
    }
}

impl Drop for RealtimeAssemblyReservation {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = self.registry.state.lock();
        let flow_released = state.flows.get_mut(&self.key).is_some_and(|flow| {
            match flow.in_progress_units.checked_sub(1) {
                Some(units) => {
                    flow.in_progress_units = units;
                    true
                }
                None => false,
            }
        });
        if !flow_released {
            self.registry.poison_domain_locked(&mut state, self.domain);
        }
        self.registry
            .release_bytes_locked(&mut state, self.domain, self.retained_bytes);
        self.registry.release_unit_locked(&mut state, self.domain);
        let in_progress_units = RealtimeFlowRegistry::in_progress_units(&state);
        let retained_bytes = RealtimeFlowRegistry::retained_bytes(&state);
        drop(state);
        self.registry.record(RealtimeFlowObservation::Assembly {
            key: self.key,
            in_progress_units,
            retained_bytes,
        });
    }
}

pub(super) struct RealtimeOutputReservation {
    registry: Arc<RealtimeFlowRegistry>,
    key: RealtimeFlowKey,
    domain: RealtimeFlowDomain,
    lease: Option<ResourceLease>,
    bytes: usize,
    active: bool,
}

impl RealtimeOutputReservation {
    pub(super) fn into_payload_lease(mut self) -> RealtimePayloadLease {
        self.active = false;
        RealtimePayloadLease(Arc::new(RealtimePayloadReservation {
            registry: Arc::clone(&self.registry),
            key: self.key,
            domain: self.domain,
            lease: self
                .lease
                .take()
                .expect("an active output reservation owns one provider lease"),
            bytes: self.bytes,
        }))
    }
}

impl Drop for RealtimeOutputReservation {
    fn drop(&mut self) {
        if self.active {
            let mut state = self.registry.state.lock();
            self.registry
                .release_bytes_locked(&mut state, self.domain, self.bytes);
        }
    }
}

struct RealtimePayloadReservation {
    registry: Arc<RealtimeFlowRegistry>,
    key: RealtimeFlowKey,
    domain: RealtimeFlowDomain,
    lease: ResourceLease,
    bytes: usize,
}

impl Drop for RealtimePayloadReservation {
    fn drop(&mut self) {
        let mut state = self.registry.state.lock();
        self.registry
            .release_bytes_locked(&mut state, self.domain, self.bytes);
        let retained_bytes = RealtimeFlowRegistry::retained_bytes(&state);
        drop(state);
        self.registry.record(RealtimeFlowObservation::Queue {
            key: self.key,
            units: 0,
            retained_bytes,
        });
    }
}

#[derive(Clone)]
pub(super) struct RealtimePayloadLease(Arc<RealtimePayloadReservation>);

impl RealtimePayloadLease {
    fn transition_to_retained_payload(
        &mut self,
    ) -> std::result::Result<(), RealtimeFlowDropReason> {
        let reservation =
            Arc::get_mut(&mut self.0).ok_or(RealtimeFlowDropReason::OwnershipMismatch)?;
        let replacement = RealtimeFlowRegistry::retained_payload_claim(reservation.bytes)
            .map_err(RealtimeFlowDropReason::ResourceUnavailable)?;
        reservation
            .lease
            .transition(replacement)
            .map_err(RealtimeFlowDropReason::ResourceUnavailable)
    }

    #[cfg(test)]
    fn claim(&self) -> ResourceClaim {
        self.0.lease.claim()
    }
}

impl std::fmt::Debug for RealtimePayloadLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RealtimePayloadLease")
            .field("key", &self.0.key)
            .field("bytes", &self.0.bytes)
            .finish()
    }
}

#[cfg(test)]
mod elastic_resource_tests {
    use super::*;
    use crate::resource::{FiniteResourceProvider, ResourceProviderPort};
    use crate::runtime::attempt::ConnectorResourceOwnerPort;

    struct TestContext {
        provider: FiniteResourceProvider,
        registry: Arc<RealtimeFlowRegistry>,
        _owner: ConnectorResourceOwnerPort,
        _candidate: ConnectorCandidateCapability,
        _attempt: AttemptLifetime,
    }

    /// The name every delivery in these controls arrives on.
    fn fixture_flow_name() -> RealtimeFlowName {
        RealtimeFlowName::new(b"fixture".to_vec()).expect("the fixture name is within the bound")
    }

    /// Four payload bytes on a label, leaseless — `enqueue_checked` attaches
    /// the output reservation these controls are actually measuring.
    ///
    /// The label is a real minted one, cloned per delivery. A hand-built label
    /// would be bytes nothing had paid for, and the exact grants below would
    /// then be exact about everything except the one thing the delivery carries
    /// for as long as it is queued.
    fn fixture_realtime_unit(label: &RealtimeFlowLabel) -> TransportEvent {
        TransportEvent::RealtimeUnit(RealtimeInboundDelivery::new(
            label.clone(),
            RealtimeRecvUnit {
                timestamp: 0,
                marker: true,
                data: Bytes::from_static(b"test"),
            },
        ))
    }

    /// Derive the finite test grant from the exact claims exercised by one
    /// scenario. `explicit_test_grant` also reserves capacity for one connector
    /// operation. This fixture owns none, so remove that claim and the provider
    /// reservation record paired with it before adding the exact real-time
    /// leases under test.
    ///
    /// The remaining residuals account for the process, Mesh, and connector
    /// scope records, cleanup and candidate reservations, and one provider
    /// reservation record for each real-time lease. They are test accounting,
    /// not a product cardinality or production policy value.
    fn grant_for(realtime_claims: &[ResourceClaim]) -> ResourceClaim {
        let grant = crate::runtime::attempt::explicit_test_grant(1, 1)
            .checked_sub(crate::runtime::attempt::connector_operation_claim())
            .and_then(|grant| {
                grant.checked_sub(ResourceClaim::single(
                    ResourceClass::OpaqueDependencyResidual,
                    1,
                ))
            })
            .expect("the broad fixture contains the unused claim and its reservation record");
        add_provider_reservations(grant, realtime_claims)
    }

    fn add_provider_reservations(
        mut base: ResourceClaim,
        leased_claims: &[ResourceClaim],
    ) -> ResourceClaim {
        for claim in leased_claims {
            base = base
                .checked_add(*claim)
                .and_then(|base| {
                    base.checked_add(ResourceClaim::single(
                        ResourceClass::OpaqueDependencyResidual,
                        1,
                    ))
                })
                .expect("fixture real-time bookkeeping is representable");
        }
        base
    }

    fn context(realtime_claims: &[ResourceClaim]) -> TestContext {
        let provider = FiniteResourceProvider::new(grant_for(realtime_claims));
        let port = ResourceProviderPort::new(provider.clone())
            .expect("the derived grant accounts for the process scope");
        let owner = ConnectorResourceOwnerPort::new(port);
        let mesh_scope = owner
            .issue_mesh_scope()
            .expect("the derived grant accounts for the Mesh scope");
        let (permit, attempt, claim) =
            admit_single_connector_candidate(crate::runtime::RuntimeIncarnation::new(), mesh_scope);
        let candidate = permit
            .reserve_connector_candidate_checked(claim)
            .expect("the derived grant has no provider invariant failure")
            .expect("the exact attempt remains active");
        let registry = RealtimeFlowRegistry::new(Some(candidate.work_resource_scope()), None);
        TestContext {
            provider,
            registry,
            _owner: owner,
            _candidate: candidate,
            _attempt: attempt,
        }
    }

    fn assert_claim_dimensions(actual: ResourceClaim, expected: ResourceClaim) {
        for dimension in ResourceClass::ALL {
            assert_eq!(
                actual.amount(dimension),
                expected.amount(dimension),
                "resource mismatch in {dimension:?}"
            );
        }
    }

    #[test]
    fn elastic_flow_admission_uses_provider_capacity_not_a_product_count() {
        let flow_claim = RealtimeFlowRegistry::flow_claim().expect("flow claim is representable");
        let fixture = context(&[flow_claim, flow_claim]);

        let first = fixture
            .registry
            .open_inbound_flow_checked()
            .expect("the first exact flow claim is available");
        let _second = fixture
            .registry
            .open_inbound_flow_checked()
            .expect("the second exact flow claim is available");
        let refusal = match fixture.registry.open_inbound_flow_checked() {
            Err(refusal) => refusal,
            Ok(_) => panic!("a third flow must not exceed the finite provider grant"),
        };
        assert!(matches!(
            refusal,
            RealtimeFlowDropReason::ResourceUnavailable(ResourceUnavailable::Pressure(
                crate::resource::ResourcePressure {
                    dimension: ResourceClass::AccountedMemoryBytes,
                    ..
                }
            ))
        ));

        drop(first);
        fixture
            .registry
            .open_inbound_flow_checked()
            .expect("dropping the exact flow lease restores provider capacity");
    }

    #[test]
    fn every_retained_fragment_keeps_its_exact_provider_lease() {
        let flow_claim = RealtimeFlowRegistry::flow_claim().expect("flow claim is representable");
        let assembly_claim =
            RealtimeFlowRegistry::assembly_claim().expect("assembly claim is representable");
        let fragment_claim = RealtimeFlowRegistry::ordered_fragment_claim(4)
            .expect("fragment claim is representable");
        let fixture = context(&[flow_claim, assembly_claim, fragment_claim]);
        let flow = fixture
            .registry
            .open_inbound_flow_checked()
            .expect("the flow claim is available");
        let before_assembly = fixture.provider.in_use();
        let mut assembly = flow
            .begin_unit_checked()
            .expect("the unit claim is available");
        assembly
            .retain_ordered_fragment_checked(4)
            .expect("the exact fragment claim is available");
        let with_fragment = fixture.provider.in_use();
        assert_eq!(
            with_fragment.amount(ResourceClass::AccountedMemoryBytes),
            grant_for(&[flow_claim, assembly_claim, fragment_claim])
                .amount(ResourceClass::AccountedMemoryBytes)
        );
        assert!(matches!(
            assembly.retain_ordered_fragment_checked(1),
            Err(RealtimeFlowDropReason::ResourceUnavailable(
                ResourceUnavailable::Pressure(crate::resource::ResourcePressure {
                    dimension: ResourceClass::AccountedMemoryBytes,
                    ..
                })
            ))
        ));

        drop(assembly);
        assert_eq!(fixture.provider.in_use(), before_assembly);
    }

    #[test]
    fn session_packet_work_guard_holds_capacity_through_the_caller_iteration() {
        let work_claim = RealtimeFlowRegistry::session_packet_work_claim(4)
            .expect("work claim is representable");
        let fixture = context(&[work_claim]);
        let before_work = fixture.provider.in_use();
        let work = fixture
            .registry
            .admit_session_packet_checked(4)
            .expect("the exact packet work claim is available");
        assert!(matches!(
            fixture.registry.admit_session_packet_checked(1),
            Err(RealtimeFlowDropReason::ResourceUnavailable(
                ResourceUnavailable::Pressure(crate::resource::ResourcePressure {
                    dimension: ResourceClass::AccountedMemoryBytes,
                    ..
                })
            ))
        ));

        drop(work);
        assert_eq!(fixture.provider.in_use(), before_work);
        fixture
            .registry
            .admit_session_packet_checked(1)
            .expect("dropping the exact work guard restores provider capacity");
    }

    #[test]
    fn native_read_guard_owns_the_opaque_result_until_content_admission() {
        let read_claim =
            RealtimeFlowRegistry::native_read_claim().expect("read claim is representable");
        let fixture = context(&[read_claim]);
        let before_read = fixture.provider.in_use();
        let read = fixture
            .registry
            .begin_native_read_checked()
            .expect("the exact native-read claim is available");
        assert!(matches!(
            fixture.registry.begin_native_read_checked(),
            Err(RealtimeFlowDropReason::ResourceUnavailable(
                ResourceUnavailable::Pressure(crate::resource::ResourcePressure {
                    dimension: ResourceClass::CallbackOrScheduledWork,
                    ..
                })
            ))
        ));

        drop(read);
        assert_claim_dimensions(fixture.provider.in_use(), before_read);
        fixture
            .registry
            .begin_native_read_checked()
            .expect("dropping the native-read guard restores its exact capacity");
    }

    #[test]
    fn slow_fragment_owner_does_not_expire_without_an_owner_transition() {
        let flow_claim = RealtimeFlowRegistry::flow_claim().expect("flow claim is representable");
        let assembly_claim =
            RealtimeFlowRegistry::assembly_claim().expect("assembly claim is representable");
        let fragment_claim = RealtimeFlowRegistry::ordered_fragment_claim(4)
            .expect("ordered fragment claim is representable");
        let fixture = context(&[flow_claim, assembly_claim, fragment_claim]);
        let flow = fixture
            .registry
            .open_inbound_flow_checked()
            .expect("the flow claim is available");
        let mut assembly = flow
            .begin_unit_checked()
            .expect("the assembly claim is available");
        assembly
            .retain_ordered_fragment_checked(4)
            .expect("the ordered fragment claim is available");

        let (owner_waiting_tx, owner_waiting_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let owner = std::thread::spawn(move || {
            owner_waiting_tx
                .send(())
                .expect("the test owner reports that it is waiting");
            release_rx
                .recv()
                .expect("the test controls the concrete release transition");
            drop(assembly);
        });
        owner_waiting_rx
            .recv()
            .expect("the fragment owner reached its owner-controlled wait");
        assert!(matches!(
            fixture
                .registry
                .acquire(RealtimeFlowRegistry::ordered_fragment_claim(1)),
            Err(RealtimeFlowDropReason::ResourceUnavailable(
                ResourceUnavailable::Pressure(_)
            ))
        ));
        release_tx
            .send(())
            .expect("the test explicitly releases the slow owner");
        owner.join().expect("the slow owner exits without a timer");
        let _lease = fixture
            .registry
            .acquire(RealtimeFlowRegistry::ordered_fragment_claim(1))
            .expect("only the concrete owner drop restores fragment capacity");
    }

    #[test]
    fn dequeue_releases_queue_ownership_but_payload_clones_keep_content_ownership() {
        let flow_claim = RealtimeFlowRegistry::flow_claim().expect("flow claim is representable");
        let output_claim =
            RealtimeFlowRegistry::output_claim(4).expect("output claim is representable");
        let queue_claim =
            RealtimeFlowRegistry::queue_claim(4).expect("queue claim is representable");
        let ready_claim =
            RealtimeFlowRegistry::ready_claim().expect("ready claim is representable");
        let retained_payload_claim = RealtimeFlowRegistry::retained_payload_claim(4)
            .expect("retained payload claim is representable");
        let name = fixture_flow_name();
        let label_claim = RealtimeFlowLabel::mint_claim(name.as_bytes().len())
            .expect("label claim is representable");
        let fixture = context(&[
            flow_claim,
            output_claim,
            queue_claim,
            ready_claim,
            label_claim,
        ]);
        // Minted ahead of the baseline, so the label's own lease is part of the
        // constant this control measures its deltas against. It is held for the
        // whole test on purpose: a label outlives the units that carry it.
        let label =
            RealtimeFlowLabel::mint(name, &fixture.registry).expect("the label claim is available");
        let flow = fixture
            .registry
            .open_inbound_flow_checked()
            .expect("the flow claim is available");
        let flow_only = fixture.provider.in_use();
        let output = flow
            .reserve_output_checked(4)
            .expect("the complete output claim is available");
        assert_eq!(
            fixture.provider.in_use(),
            add_provider_reservations(flow_only, &[output_claim]),
            "the output reservation owns its exact provider claim",
        );
        flow.enqueue_checked(
            QueuedTransportEvent {
                event: fixture_realtime_unit(&label),
                observation: None,
                callback_work: None,
            },
            output,
        )
        .expect("the queue claim is available");
        {
            let state = fixture.registry.state.lock();
            let queued = state
                .flows
                .get(&flow.key())
                .and_then(|flow| flow.events.front())
                .expect("the exact payload is queued");
            assert_eq!(queued._queue_lease.claim(), queue_claim);
            let payload = match &queued.event.event {
                TransportEvent::RealtimeUnit(delivery) => delivery
                    .payload
                    .as_ref()
                    .expect("the queued payload owns its output lease"),
                _ => panic!("the fixture queues one real-time unit"),
            };
            assert_eq!(payload.claim(), output_claim);
            assert_eq!(
                state
                    .flows
                    .get(&flow.key())
                    .and_then(|flow| flow.ready_lease.as_ref())
                    .expect("the queued flow owns its ready lease")
                    .claim(),
                ready_claim
            );
        }
        assert_eq!(
            fixture.provider.in_use(),
            add_provider_reservations(flow_only, &[output_claim, queue_claim, ready_claim]),
            "the queued unit owns output, queue, and ready claims",
        );

        let event = fixture
            .registry
            .try_recv()
            .expect("the queued event remains available");
        let retained = match &event.event {
            TransportEvent::RealtimeUnit(delivery) => delivery
                .payload
                .as_ref()
                .expect("the delivered payload retains its exact lease"),
            _ => panic!("the fixture delivers one real-time unit"),
        };
        assert_eq!(retained.claim(), retained_payload_claim);
        assert_eq!(
            fixture.provider.in_use(),
            add_provider_reservations(flow_only, &[retained_payload_claim]),
            "dequeue retains only the delivered payload claim",
        );
        drop(event);
        assert_eq!(
            fixture.provider.in_use(),
            flow_only,
            "dropping the delivered payload restores the flow-only baseline",
        );
    }

    #[test]
    fn dropping_a_scheduled_flow_releases_its_embedded_ready_node() {
        let flow_claim = RealtimeFlowRegistry::flow_claim().expect("flow claim is representable");
        let output_claim =
            RealtimeFlowRegistry::output_claim(4).expect("output claim is representable");
        let queue_claim =
            RealtimeFlowRegistry::queue_claim(4).expect("queue claim is representable");
        let ready_claim =
            RealtimeFlowRegistry::ready_claim().expect("ready claim is representable");
        let name = fixture_flow_name();
        let label_claim = RealtimeFlowLabel::mint_claim(name.as_bytes().len())
            .expect("label claim is representable");
        let fixture = context(&[
            flow_claim,
            output_claim,
            queue_claim,
            ready_claim,
            label_claim,
        ]);
        // Minted before the baseline and held past the flow drop: the label is
        // not the flow's, so a flow going away must not be what releases it.
        let label =
            RealtimeFlowLabel::mint(name, &fixture.registry).expect("the label claim is available");
        let before_flow = fixture.provider.in_use();
        let flow = fixture
            .registry
            .open_inbound_flow_checked()
            .expect("the flow claim is available");
        let output = flow
            .reserve_output_checked(4)
            .expect("the output claim is available");
        flow.enqueue_checked(
            QueuedTransportEvent {
                event: fixture_realtime_unit(&label),
                observation: None,
                callback_work: None,
            },
            output,
        )
        .expect("the queue and ready claims are available");
        assert_eq!(fixture.registry.state.lock().ready.len(), 1);

        drop(flow);
        assert!(fixture.registry.state.lock().ready.is_empty());
        assert_claim_dimensions(fixture.provider.in_use(), before_flow);
    }
}
