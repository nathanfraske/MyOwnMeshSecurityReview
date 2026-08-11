use std::num::NonZeroUsize;
use std::sync::OnceLock;

use myownmesh_core::transport::Transport;
use myownmesh_core::{
    ConnectorCallbackMailboxCapacities, ConnectorCallbackPolicy, ConnectorCallbackServiceWeights,
    FiniteResourceProvider, PendingRemoteCandidatePolicy, RealtimeConnectorPolicy, ResourceClaim,
    ResourceClass, ResourceProviderPort, WebRtcConnectorCapablePolicy, WebRtcConnectorProfile,
};

static TEST_RESOURCE_PROVIDER: OnceLock<ResourceProviderPort> = OnceLock::new();

/// Explicit integration-test resource owner.
///
/// These values cover the known in-process multi-device test fixtures. They
/// are test inputs only and make no production sizing claim.
pub fn test_transport() -> Transport {
    // Every integration-test binary has one real process resource root, while
    // libtest runs up to one test case per worker concurrently. The fixture
    // grant is process-global and work-conserving. This count sizes only the
    // explicit test workload and does not partition capacity by Mesh.
    let mesh_connector_count =
        NonZeroUsize::new(16).expect("fixture per-Mesh connector bound is nonzero");
    let test_workers = std::env::var("RUST_TEST_THREADS")
        .ok()
        .map(|raw| {
            raw.parse::<NonZeroUsize>()
                .expect("RUST_TEST_THREADS must be a nonzero integer")
        })
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .expect("integration-test worker concurrency must be observable")
        });
    let process_connector_count = NonZeroUsize::new(
        mesh_connector_count
            .get()
            .checked_mul(test_workers.get())
            .expect("integration-test process connector bound must fit usize"),
    )
    .expect("derived integration-test process connector bound is nonzero");
    let callback_capacity = NonZeroUsize::new(16).expect("fixture callback capacity is nonzero");
    let callbacks = ConnectorCallbackPolicy::new(
        ConnectorCallbackMailboxCapacities::new(callback_capacity, callback_capacity),
        ConnectorCallbackServiceWeights::data_only(callback_capacity, callback_capacity),
        RealtimeConnectorPolicy::Disabled,
    )
    .expect("fixture data-only callback policy is valid");
    let webrtc_profile =
        WebRtcConnectorProfile::new(callbacks, PendingRemoteCandidatePolicy::elastic());
    let provider = TEST_RESOURCE_PROVIDER.get_or_init(|| {
        let connectors = u64::try_from(process_connector_count.get())
            .expect("fixture connector concurrency fits u64");
        let mesh_scopes =
            u64::try_from(test_workers.get()).expect("fixture worker concurrency fits u64");
        let queued_items = connectors
            .checked_mul(
                u64::try_from(callback_capacity.get()).expect("fixture callback count fits u64"),
            )
            .expect("fixture queued-item envelope fits u64");
        let retained_bytes = queued_items
            .checked_mul(
                u64::try_from(myownmesh_core::engine::MAX_ENDPOINT_FRAME_BYTES)
                    .expect("the protocol frame limit fits u64"),
            )
            .expect("fixture retained-byte envelope fits u64");
        let residual = 1u64
            .checked_add(mesh_scopes)
            .and_then(|value| value.checked_add(connectors.checked_mul(3)?))
            .and_then(|value| value.checked_add(queued_items))
            .expect("fixture provider bookkeeping fits u64");
        let structural = myownmesh_core::connector_resource_structural_claims();
        let structural = structural
            .connector_opening()
            .checked_scale(connectors)
            .and_then(|claim| claim.checked_add(structural.process_infrastructure()))
            .expect("fixture structural claims are representable");
        let workload = ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, retained_bytes),
            (ResourceClass::QueuedBytes, retained_bytes),
            (
                ResourceClass::CallbackOrScheduledWork,
                connectors
                    .checked_add(queued_items)
                    .expect("fixture callback-work envelope fits u64"),
            ),
            (ResourceClass::StorageObject, queued_items),
            (ResourceClass::ParsingOrCpuWork, retained_bytes),
            (ResourceClass::OpaqueDependencyResidual, residual),
        ])
        .expect("the fixture workload claim is representable");
        let grant = structural
            .checked_add(workload)
            .expect("the fixture provider grant is representable");
        // One post-authentication Session Broker reservation per connector.
        //
        // The connector count is the ceiling on *concurrent promoted sessions*,
        // not an estimate of them: a session is promoted from the authenticated
        // channel of exactly one live connector and is dropped with it, so no
        // fixture here can hold more sessions than it has connector slots to
        // promote them from. Scaling by anything else would be a guess.
        //
        // The charge is taken from the broker rather than restated. It is
        // denominated in the accounted memory of the session record and the
        // roots promotion allocates, plus the record the provider keeps for the
        // lease carrying it — none of which this fixture may name for itself,
        // and all of which change on the broker's side rather than this one.
        //
        // Budgeting it explicitly is the point. The session claim used to be one
        // `WorkerOrTask` unit, which could bind on slack the connector
        // structural capacity above happened to leave, so an unbudgeted session
        // was invisible until some unrelated term moved. Nothing else here is
        // denominated in what the session claim now names, so a shortfall
        // surfaces as a refused promotion rather than as a fixture that quietly
        // stopped promoting.
        //
        // Gated with the accessor, and the reason is narrower than it looks.
        // Default-feature integration tests *do* promote ordinary sessions — a
        // session is post-authentication, not post-realtime — so this is not a
        // case of feature-off needing no capacity. It is that the accessor is
        // deliberately not in the default public API, and an integration test is
        // a separate crate that can only call what is `pub`.
        //
        // The authoritative workspace gate unifies `transport-lab`, so the run
        // that decides this branch gets the exact term. A standalone feature-off
        // `cargo test -p myownmesh-core --test ...` keeps the conservative
        // process grant above and budgets no session — the same position it has
        // always been in, and a real residual rather than a claim of exactness.
        #[cfg(feature = "transport-lab")]
        let grant = myownmesh_core::transport_lab_session_reservation_claim()
            .checked_scale(connectors)
            .and_then(|sessions| grant.checked_add(sessions))
            .expect("the fixture session reservation capacity is representable");
        ResourceProviderPort::new(FiniteResourceProvider::new(grant))
            .expect("the fixture provider accounts for its process scope")
    });
    let policy = WebRtcConnectorCapablePolicy::new(provider.clone(), webrtc_profile);
    Transport::new()
        .expect("transport")
        .with_connector_resource_policy(policy)
        .expect("fixture process connector policy is consistent")
}
