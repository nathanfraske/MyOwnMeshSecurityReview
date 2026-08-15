use std::num::NonZeroUsize;
use std::sync::OnceLock;

use myownmesh_core::transport::Transport;
use myownmesh_core::{
    ConnectorCallbackPolicy, FiniteResourceProvider, ResourceClaim, ResourceClass,
    ResourceProviderPort, WebRtcConnectorCapablePolicy, WebRtcConnectorProfile,
};

static TEST_RESOURCE_PROVIDER: OnceLock<ResourceProviderPort> = OnceLock::new();

/// The largest JSON frame these fixtures fund the *parse* of.
///
/// Its own number, deliberately not borrowed from the callback payload ceilings
/// below. Those bound what a connector may hold queued; this bounds what the
/// application gateway may allocate turning one frame into a `serde_json::Value`
/// tree, which is a different quantity with a different denomination — the
/// tree's claim is per input byte because a JSON value can hold as many
/// independent allocations as it has bytes.
///
/// Test workload capacity only, and no wire gate: a frame is admitted against
/// its own actual length. This fixture's grant used to leave that claim funded
/// only by a residual counted in records, which is why it passed at eight
/// libtest workers and failed the same handshake at one — the record count
/// happened to exceed the frame length, or happened not to.
const FIXTURE_JSON_FRAME_BYTES: usize = 8 * 1024;

/// Simultaneous JSON input claims one connector can hold: the peer's `Hello`,
/// whose claim is retained for the connection's whole life, plus one protocol
/// or application frame being parsed. One would fund the retained `Hello` and
/// refuse everything after it; more would be capacity with no nameable holder.
const FIXTURE_JSON_CLAIMS_PER_CONNECTOR: u64 = 2;

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
    // The largest single payload this fixture funds, stated per callback class.
    //
    // This provider is minted here rather than drawn from a process owner, so
    // these two numbers are the only thing that can size its byte grant, and the
    // arithmetic below reads them back off the policy rather than repeating
    // them. They are fixture inputs and make no production sizing claim, and
    // neither is borrowed from another layer — not the protocol's endpoint frame
    // maximum, not the signaling frame limit.
    //
    // Control covers one gathered ICE candidate's JSON. Endpoint covers the
    // application payloads these multi-device fixtures exchange; it keeps the
    // byte figure this fixture has always run with, now stated as what it is
    // instead of appearing once as an unnamed multiplier.
    let control_payload_ceiling =
        NonZeroUsize::new(4_096).expect("fixture control payload ceiling is nonzero");
    let endpoint_payload_ceiling =
        NonZeroUsize::new(16 * 1024 * 1024).expect("fixture endpoint payload ceiling is nonzero");
    let webrtc_profile = WebRtcConnectorProfile::new(ConnectorCallbackPolicy::elastic_data_only());
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
        // Each class funds its own slots from its own stated ceiling, summed.
        // One number multiplied across the combined slot count is what this
        // replaces: it made the endpoint figure silently pay for every control
        // callback too, so neither class's budget meant what it said and removing
        // the figure would have left control funded for nothing.
        //
        // The two ceilings used to be read back off the installed policy so the
        // grant and the declaration could not drift. The policy no longer
        // carries them — nothing enforces a per-class payload ceiling any more —
        // so they are what they always really were here: this fixture's own
        // statement of the largest payload it intends to fund.
        let ceiling = |bytes: NonZeroUsize, class: &str| -> u64 {
            u64::try_from(bytes.get())
                .unwrap_or_else(|_| panic!("the stated {class} payload ceiling fits u64"))
        };
        let control_bytes = queued_items
            .checked_mul(ceiling(control_payload_ceiling, "control"))
            .expect("fixture control byte envelope fits u64");
        let endpoint_bytes = queued_items
            .checked_mul(ceiling(endpoint_payload_ceiling, "endpoint-data"))
            .expect("fixture endpoint byte envelope fits u64");
        let retained_bytes = control_bytes
            .checked_add(endpoint_bytes)
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
        // JSON input work, as its own term. The claim comes from the gateway
        // rather than being restated here, so the grant and the admission it has
        // to satisfy cannot be derived from two different formulas. Added apart
        // from the provider-record `residual` above because the two are
        // different quantities that merely share a dimension: one counts this
        // fixture's bookkeeping objects, the other a decoded JSON tree's
        // allocations.
        let json_input_work =
            myownmesh_core::application_gateway::json_input_work_claim(FIXTURE_JSON_FRAME_BYTES)
                .expect("the fixture JSON input claim is representable")
                .checked_scale(
                    connectors
                        .checked_mul(FIXTURE_JSON_CLAIMS_PER_CONNECTOR)
                        .expect("the fixture JSON claim count is representable"),
                )
                .expect("the fixture JSON input grant is representable");
        let grant = structural
            .checked_add(workload)
            .and_then(|claim| claim.checked_add(json_input_work))
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
        // Unconditional because default-feature connectors promote the same
        // sessions as transport-lab connectors. Omitting this exact broker term
        // would make promotion depend on unrelated residual slack.
        let grant = myownmesh_core::session_reservation_planning_claim()
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
