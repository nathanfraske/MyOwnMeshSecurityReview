#![cfg(feature = "transport-lab")]

use std::future::Future;
use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::Arc;
use std::time::Duration;

use myownmesh_core::config::{
    ClosedRelayPolicyConfig, NetworkConfig, SignalingConfig, TopologyMode,
};
use myownmesh_core::network_state::NetworkKind;
use myownmesh_core::resource::ResourceReport;
use myownmesh_core::semantic::VerifiedBootstrap;
use myownmesh_core::semantic::{DeviceId, FactBody, FactContent, Role};
use myownmesh_core::{
    ConnectorCallbackPolicy, FactGraph, FiniteResourceProvider, Identity, Mesh, MeshConfig,
    ResourceClaim, ResourceClass, ResourceProviderPort, SignedFact, TransportLabCallbackWorkload,
    WebRtcConnectorCapablePolicy, WebRtcConnectorProfile,
};

const STAGE_TIMEOUT: Duration = Duration::from_secs(10);

async fn bounded_value<T>(
    stage: &'static str,
    future: impl Future<Output = T>,
) -> myownmesh_core::Result<T> {
    tokio::time::timeout(STAGE_TIMEOUT, future)
        .await
        .map_err(|_| {
            myownmesh_core::Error::Network(format!("closed relay stage timed out: {stage}"))
        })
}

async fn bounded_result<T>(
    stage: &'static str,
    future: impl Future<Output = myownmesh_core::Result<T>>,
) -> myownmesh_core::Result<T> {
    bounded_value(stage, future).await?
}

fn init_relay_trace() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "myownmesh_core::engine=trace,myownmesh_core::transport=debug",
        ))
        .with_test_writer()
        .try_init();
}

fn assert_live_custody_baseline(label: &str, before: &ResourceReport, after: &ResourceReport) {
    for (before, after) in before
        .pre_authentication
        .iter()
        .zip(after.pre_authentication.iter())
    {
        assert_eq!(
            after.active, before.active,
            "{label} live custody returned to baseline"
        );
        assert_eq!(
            after.active_lease_count, before.active_lease_count,
            "{label} live lease count returned to baseline"
        );
        assert_eq!(
            after.oldest_active_lifetime.is_some(),
            before.oldest_active_lifetime.is_some(),
            "{label} oldest-active presence returned to baseline"
        );
        assert_eq!(
            after.oldest_active_lifetime_inexact, before.oldest_active_lifetime_inexact,
            "{label} oldest-active precision state returned to baseline"
        );
    }
    for (before, after) in before
        .post_authentication
        .iter()
        .zip(after.post_authentication.iter())
    {
        assert_eq!(
            after.active, before.active,
            "{label} live custody returned to baseline"
        );
        assert_eq!(
            after.active_lease_count, before.active_lease_count,
            "{label} live lease count returned to baseline"
        );
        assert_eq!(
            after.oldest_active_lifetime.is_some(),
            before.oldest_active_lifetime.is_some(),
            "{label} oldest-active presence returned to baseline"
        );
        assert_eq!(
            after.oldest_active_lifetime_inexact, before.oldest_active_lifetime_inexact,
            "{label} oldest-active precision state returned to baseline"
        );
    }
}

fn connector_policy() -> WebRtcConnectorCapablePolicy {
    let profile = WebRtcConnectorProfile::new(ConnectorCallbackPolicy::elastic_data_only());
    let connector_count = NonZeroU64::new(4).expect("connector count is nonzero");
    let max_relay_frame_bytes = usize::try_from(
        myownmesh_core::protocol::relay::closed_relay_worst_case_json_bytes(
            myownmesh_core::protocol::relay::CLOSED_RELAY_MAX_PLAINTEXT_BYTES
                + myownmesh_core::protocol::relay::CLOSED_RELAY_AEAD_TAG_BYTES,
        )
        .expect("the maximum Closed relay frame size is representable"),
    )
    .expect("the maximum Closed relay frame size fits usize");
    let frame_bytes = NonZeroU64::new(
        u64::try_from(myownmesh_signaling::mdns::wire::MAX_FRAME_BYTES)
            .expect("frame limit fits u64"),
    )
    .expect("frame limit is nonzero");
    let candidate_content = NonZeroU64::new(
        frame_bytes
            .get()
            .checked_mul(connector_count.get())
            .expect("candidate content capacity fits u64"),
    )
    .expect("candidate content capacity is nonzero");
    let candidate_strings = NonZeroU64::new(
        candidate_content
            .get()
            .checked_mul(3)
            .expect("candidate string capacity fits u64"),
    )
    .expect("candidate string capacity is nonzero");
    let workload = TransportLabCallbackWorkload {
        control_slots: NonZeroUsize::new(64).expect("control slots are nonzero"),
        endpoint_slots: NonZeroUsize::new(64).expect("endpoint slots are nonzero"),
        control_payload_bytes: 16 * 1024,
        endpoint_payload_bytes: u64::try_from(max_relay_frame_bytes)
            .expect("the maximum Closed relay frame payload fits u64"),
        realtime: None,
    };
    // The raw connector grant funds callback/opening work only. Promotion
    // retains one exact Session Broker reservation per real-link endpoint, so
    // price four promoted sessions separately rather than borrowing slack
    // from connector construction.
    let promoted_sessions = myownmesh_core::session_reservation_planning_claim()
        .checked_scale(connector_count.get())
        .expect("four promoted-session planning claims are representable");
    // Native inbound frames are parsed twice at a live connector boundary:
    // one retained Hello and one current application frame. Use the public
    // gateway formula at the maximum serialized Closed relay frame, then add
    // the provider reservation bookkeeping for each of the two claims and
    // each of the four connectors. The raw connector grant does not fund
    // promoted-session or application JSON parsing retention.
    let json_frame_reservation =
        myownmesh_core::FiniteResourceProvider::reservation_planning_charge(
            myownmesh_core::application_gateway::json_input_work_claim(max_relay_frame_bytes)
                .expect("the maximum-frame JSON claim is representable"),
        )
        .expect("the maximum-frame JSON reservation charge is representable");
    let json_parsing = json_frame_reservation
        .checked_scale(2)
        .and_then(|claim| claim.checked_scale(connector_count.get()))
        .expect("two maximum-frame JSON claims per connector are representable");
    let claim = myownmesh_core::transport_lab_connector_fixture_grant(
        &[
            profile.clone(),
            profile.clone(),
            profile.clone(),
            profile.clone(),
        ],
        NonZeroU64::new(3).expect("mesh scope count is nonzero"),
        workload,
    )
    .expect("the finite connector fixture grant is representable")
    .checked_add(promoted_sessions)
    .and_then(|claim| claim.checked_add(json_parsing))
    .expect("the connector, session, and JSON grants combine without overflow")
    .checked_add(
        myownmesh_core::transport_lab_remote_candidate_fixture_grant(
            connector_count,
            connector_count,
            candidate_strings,
            candidate_content,
            frame_bytes,
        )
        .expect("the finite remote-candidate grant is representable"),
    )
    .expect("the candidate grant combines without overflow")
    .checked_add(
        ResourceClaim::try_from_entries([
            (
                ResourceClass::StorageObject,
                connector_count
                    .get()
                    .checked_mul(2)
                    .expect("applied candidate storage capacity fits u64"),
            ),
            (
                ResourceClass::OpaqueDependencyResidual,
                connector_count
                    .get()
                    .checked_mul(3)
                    .expect("applied candidate residual capacity fits u64"),
            ),
        ])
        .expect("the applied candidate retention claim is representable"),
    )
    .expect("the applied candidate retention combines without overflow")
    .checked_add(
        myownmesh_core::transport_lab_remote_description_fixture_grant(
            connector_count,
            frame_bytes,
            NonZeroU64::new(1).expect("one media section is nonzero"),
            NonZeroU64::new(1).expect("one active binding is nonzero"),
            frame_bytes,
        )
        .expect("the finite remote-description grant is representable"),
    )
    .expect("the combined finite connector grant is representable");
    let resources = ResourceProviderPort::new(FiniteResourceProvider::new(claim))
        .expect("the finite provider accounts for its process scope");
    WebRtcConnectorCapablePolicy::new(resources, profile)
}

fn network_config(id: &str, network_id: &str, relay: &str) -> NetworkConfig {
    NetworkConfig {
        id: id.into(),
        network_id: network_id.into(),
        label: id.into(),
        kind: NetworkKind::Closed,
        topology: TopologyMode::Star { hub: relay.into() },
        signaling: SignalingConfig::default(),
        closed_relay: ClosedRelayPolicyConfig {
            enabled: true,
            ..ClosedRelayPolicyConfig::default()
        },
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        roster_path: None,
        pinned_peers: Vec::new(),
        auto_approve: true,
    }
}

fn member_grant(graph: &FactGraph, signer: &Identity, target: DeviceId) -> SignedFact {
    let author = DeviceId::from_public_key_bytes(*signer.verifying_key().as_bytes())
        .expect("signer id is canonical");
    let body = FactBody::RoleGrant {
        target,
        role: Role::Member,
    };
    let witness = graph.authoring_witness(&body, &author);
    SignedFact::sign(
        FactContent::from_authoring_witness(graph, body, &witness, []),
        signer.signing_key(),
    )
    .expect("root-signed member grant is valid")
}

#[tokio::test]
async fn closed_members_exchange_opaque_payloads_only_through_relay() -> myownmesh_core::Result<()>
{
    init_relay_trace();
    let home = tempfile::tempdir().expect("temporary mesh home");
    // This control runs as one isolated integration-test process. The public
    // Mesh constructors retain the provider and all durable network state;
    // the temporary home prevents fixture state from crossing test runs.
    std::env::set_var("MYOWNMESH_HOME", home.path());

    let alice = Arc::new(Identity::ephemeral());
    let relay = Arc::new(Identity::ephemeral());
    let carol = Arc::new(Identity::ephemeral());
    let alice_id = alice.public_id().to_string();
    let relay_id = relay.public_id().to_string();
    let carol_id = carol.public_id().to_string();
    let network_id = "closed-opaque-relay-e2e";

    let bootstrap = VerifiedBootstrap::create_closed(network_id, [alice.signing_key()], [0x91; 32])
        .expect("closed bootstrap is valid");
    let record = bootstrap.record().clone();
    let context_id = bootstrap.context_id();
    let mut fact_graph = FactGraph::from_bootstrap(&bootstrap);
    let grant_relay = member_grant(
        &fact_graph,
        &alice,
        DeviceId::from_canonical_str(&relay_id).expect("relay id is canonical"),
    );
    fact_graph
        .admit(grant_relay.clone())
        .expect("relay member grant admits");
    let grant_carol = member_grant(
        &fact_graph,
        &alice,
        DeviceId::from_canonical_str(&carol_id).expect("target id is canonical"),
    );
    let signed_members = vec![grant_relay, grant_carol];

    let policy = connector_policy();
    let alice_mesh = bounded_result(
        "open Alice mesh",
        Mesh::open_connector_capable_with_identity(MeshConfig::default(), alice, policy.clone()),
    )
    .await?;
    let relay_mesh = bounded_result(
        "open relay mesh",
        Mesh::open_connector_capable_with_identity(MeshConfig::default(), relay, policy.clone()),
    )
    .await?;
    let carol_mesh = bounded_result(
        "open Carol mesh",
        Mesh::open_connector_capable_with_identity(MeshConfig::default(), carol, policy),
    )
    .await?;
    let baseline_alice = alice_mesh.resource_report();
    let baseline_relay = relay_mesh.resource_report();
    let baseline_carol = carol_mesh.resource_report();

    let alice_net = bounded_result(
        "create Alice network",
        alice_mesh.create_network(network_config("alice", network_id, &relay_id), [0x91; 32]),
    )
    .await?;
    let relay_net = bounded_result(
        "import relay network",
        relay_mesh.import_network(
            network_config("relay", network_id, &relay_id),
            context_id,
            record.clone(),
        ),
    )
    .await?;
    let carol_net = bounded_result(
        "import Carol network",
        carol_mesh.import_network(
            network_config("carol", network_id, &relay_id),
            context_id,
            record,
        ),
    )
    .await?;

    // Membership is admitted through the public durable reducer on every
    // member. No engine/runtime/key state is used by this control.
    bounded_result(
        "import Alice membership facts",
        alice_net.import_signed_facts(signed_members.clone()),
    )
    .await?;
    bounded_result(
        "import relay membership facts",
        relay_net.import_signed_facts(signed_members.clone()),
    )
    .await?;
    bounded_result(
        "import Carol membership facts",
        carol_net.import_signed_facts(signed_members),
    )
    .await?;
    for network in [&alice_net, &relay_net, &carol_net] {
        let roster = bounded_result("read member roster", network.roster_list()).await?;
        assert!(roster.iter().any(|peer| peer.device_id == relay_id));
        assert!(roster.iter().any(|peer| peer.device_id == carol_id));
    }

    let alice_relay = bounded_value(
        "install Alice-relay link",
        alice_net.install_promoted_peer_over_real_link(&relay_net),
    )
    .await?;
    let relay_carol = bounded_value(
        "install relay-Carol link",
        relay_net.install_promoted_peer_over_real_link(&carol_net),
    )
    .await?;
    assert_eq!(alice_relay.peer_device_id(), relay_id);
    assert_eq!(relay_carol.peer_device_id(), carol_id);
    assert!(alice_net.peer(&carol_id).is_none(), "no direct A-C session");
    assert!(carol_net.peer(&alice_id).is_none(), "no direct C-A session");
    assert!(alice_net.peer(&relay_id).is_some());
    assert!(carol_net.peer(&relay_id).is_some());

    // A route that names C as the relay has no authenticated A-C leg and is
    // refused before a relay allocation is admitted.
    assert!(bounded_result(
        "reject direct Alice-Carol route",
        alice_net.open_closed_relay(&carol_id, &carol_id),
    )
    .await
    .is_err());

    let a_to_c = bounded_result(
        "open Alice-to-Carol relay",
        alice_net.open_closed_relay(&relay_id, &carol_id),
    )
    .await?;
    let c_from_a = bounded_result(
        "accept Alice-to-Carol relay",
        carol_net.accept_closed_relay(),
    )
    .await?;
    assert_eq!(a_to_c.peer_device_id(), carol_id);
    assert_eq!(a_to_c.relay_device_id(), relay_id);
    assert_eq!(c_from_a.peer_device_id(), alice_id);
    assert_eq!(c_from_a.relay_device_id(), relay_id);
    assert_eq!(a_to_c.session_id(), c_from_a.session_id());
    assert_ne!(a_to_c.session_id(), [0; 16]);

    let max_plaintext =
        usize::try_from(ClosedRelayPolicyConfig::default().max_frame_ciphertext_bytes)
            .expect("configured relay plaintext bound fits usize");
    let max_a_to_c: Vec<u8> = (0..max_plaintext)
        .map(|index| (index % 251) as u8)
        .collect();
    let oversized_a_to_c = vec![0xa5; max_plaintext + 1];
    let oversized = bounded_result(
        "reject oversized Alice-to-Carol payload",
        a_to_c.send(&oversized_a_to_c),
    )
    .await;
    assert!(matches!(
        oversized,
        Err(myownmesh_core::Error::Network(message))
            if message.contains("Closed relay send refused")
    ));
    bounded_result(
        "send maximum Alice-to-Carol payload",
        a_to_c.send(&max_a_to_c),
    )
    .await?;
    assert_eq!(
        bounded_result("receive maximum Alice-to-Carol payload", c_from_a.recv()).await?,
        max_a_to_c
    );
    bounded_result("close Carol endpoint", c_from_a.close()).await?;
    assert!(bounded_result(
        "reject send after Carol close",
        a_to_c.send(b"after target close")
    )
    .await
    .is_err());
    let _ = bounded_result("close Alice endpoint", a_to_c.close()).await;

    let c_to_a = bounded_result(
        "open Carol-to-Alice relay",
        carol_net.open_closed_relay(&relay_id, &alice_id),
    )
    .await?;
    let a_from_c = bounded_result(
        "accept Carol-to-Alice relay",
        alice_net.accept_closed_relay(),
    )
    .await?;
    assert_eq!(c_to_a.peer_device_id(), alice_id);
    assert_eq!(c_to_a.relay_device_id(), relay_id);
    assert_eq!(a_from_c.peer_device_id(), carol_id);
    assert_eq!(a_from_c.relay_device_id(), relay_id);
    assert_eq!(c_to_a.session_id(), a_from_c.session_id());

    let max_c_to_a: Vec<u8> = (0..max_plaintext)
        .map(|index| ((index * 3) % 251) as u8)
        .collect();
    let oversized_c_to_a = vec![0x5a; max_plaintext + 1];
    let oversized = bounded_result(
        "reject oversized Carol-to-Alice payload",
        c_to_a.send(&oversized_c_to_a),
    )
    .await;
    assert!(matches!(
        oversized,
        Err(myownmesh_core::Error::Network(message))
            if message.contains("Closed relay send refused")
    ));
    bounded_result(
        "send maximum Carol-to-Alice payload",
        c_to_a.send(&max_c_to_a),
    )
    .await?;
    assert_eq!(
        bounded_result("receive maximum Carol-to-Alice payload", a_from_c.recv()).await?,
        max_c_to_a
    );
    bounded_result("close Alice endpoint", a_from_c.close()).await?;
    assert!(bounded_result(
        "reject send after Alice close",
        c_to_a.send(b"after target close")
    )
    .await
    .is_err());
    let _ = bounded_result("close Carol endpoint", c_to_a.close()).await;

    let _ = bounded_value("retire relay-Carol link", relay_carol.retire()).await?;
    let _ = bounded_value("retire Alice-relay link", alice_relay.retire()).await?;
    bounded_result("shutdown Alice network", alice_net.shutdown()).await?;
    bounded_result("shutdown relay network", relay_net.shutdown()).await?;
    bounded_result("shutdown Carol network", carol_net.shutdown()).await?;
    drop(alice_net);
    drop(relay_net);
    drop(carol_net);
    let live_alice = alice_mesh.resource_report();
    let live_relay = relay_mesh.resource_report();
    let live_carol = carol_mesh.resource_report();
    assert_live_custody_baseline("Alice", &baseline_alice, &live_alice);
    assert_live_custody_baseline("relay", &baseline_relay, &live_relay);
    assert_live_custody_baseline("Carol", &baseline_carol, &live_carol);
    Ok(())
}
