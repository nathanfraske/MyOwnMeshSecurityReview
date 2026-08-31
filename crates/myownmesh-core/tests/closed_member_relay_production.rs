use std::sync::Arc;
use std::time::Duration;

use myownmesh_core::config::{
    ClosedRelayPolicyConfig, NetworkConfig, NetworkKind, SignalingConfig, TopologyMode,
};
use myownmesh_core::engine::connection::PeerStatus;
use myownmesh_core::events::{MeshEvent, PeerEvent};
use myownmesh_core::resource::{
    FiniteResourceProvider, ResourceClaim, ResourceClass, ResourceProviderPort, ResourceReport,
};
use myownmesh_core::semantic::VerifiedBootstrap;
use myownmesh_core::semantic::{DeviceId, FactBody, FactContent, FactGraph, Role, SignedFact};
use myownmesh_core::{
    ConnectorCallbackPolicy, Identity, Mesh, MeshConfig, WebRtcConnectorCapablePolicy,
    WebRtcConnectorProfile,
};
use myownmesh_signaling::local::LocalBroker;

// Native ICE gathering and endpoint-auth promotion are intentionally the same
// production path as the shipped two-daemon runner. Give that path the same
// bounded window instead of imposing a unit-test-sized deadline.
const STAGE_TIMEOUT: Duration = Duration::from_secs(90);

async fn bounded<T>(
    stage: &'static str,
    future: impl std::future::Future<Output = T>,
) -> myownmesh_core::Result<T> {
    eprintln!("production-relay stage begin: {stage}");
    match tokio::time::timeout(STAGE_TIMEOUT, future).await {
        Ok(value) => {
            eprintln!("production-relay stage complete: {stage}");
            Ok(value)
        }
        Err(_) => {
            eprintln!("production-relay stage timed out: {stage}");
            Err(myownmesh_core::Error::Network(format!(
                "relay stage timed out: {stage}"
            )))
        }
    }
}

fn finite_connector_policy() -> WebRtcConnectorCapablePolicy {
    // This is deliberately finite and per Mesh instance.  The three-node
    // control has one connector-capable runtime per node; every named resource
    // dimension is bounded, including provider bookkeeping.
    let grant = ResourceClaim::try_from_entries(
        ResourceClass::ALL
            .into_iter()
            .map(|class| (class, 100_000_000)),
    )
    .expect("finite three-node connector grant is representable");
    let resources = ResourceProviderPort::new(FiniteResourceProvider::new(grant))
        .expect("finite provider is valid");
    WebRtcConnectorCapablePolicy::new(
        resources,
        WebRtcConnectorProfile::new(ConnectorCallbackPolicy::elastic_data_only()),
    )
}

fn network_config(id: &str, network_id: &str, relay: &str) -> NetworkConfig {
    NetworkConfig {
        id: id.into(),
        network_id: network_id.into(),
        event_capacity: 256,
        connection_trace_capacity: 512,
        label: id.into(),
        kind: NetworkKind::Closed,
        scheduler: Default::default(),
        topology: TopologyMode::Star {
            hub: relay.to_string(),
        },
        signaling: SignalingConfig {
            strategy: "none".into(),
            mdns: false,
            ..SignalingConfig::default()
        },
        closed_relay: ClosedRelayPolicyConfig {
            enabled: true,
            pending_handshake_timeout_ms: ClosedRelayPolicyConfig::default()
                .pending_handshake_timeout_ms,
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

async fn wait_for_authenticated_and_approved(
    events: &mut tokio::sync::broadcast::Receiver<MeshEvent>,
    expected: &[String],
) {
    let mut authenticated = vec![false; expected.len()];
    let mut approved = vec![false; expected.len()];
    while approved.iter().any(|ready| !ready) {
        let event = events.recv().await.expect("mesh event stream remains live");
        let (device_id, is_authenticated, is_approved) = match event {
            MeshEvent::Peer(PeerEvent::Authenticated { device_id, .. }) => (device_id, true, false),
            MeshEvent::Peer(PeerEvent::Approved { device_id, .. }) => (device_id, false, true),
            _ => continue,
        };
        let Some(index) = expected.iter().position(|peer| peer == &device_id) else {
            continue;
        };
        if is_authenticated {
            authenticated[index] = true;
        }
        if is_approved {
            assert!(
                authenticated[index],
                "promotion must follow authenticated Hello/AuthResponse for {device_id}"
            );
            approved[index] = true;
        }
    }
}

fn assert_active_profile(network: &myownmesh_core::JoinedNetwork, peer: &str) {
    let info = network
        .peer(peer)
        .expect("the exact promoted peer is observable");
    assert!(matches!(info.status, PeerStatus::Active));
    assert!(info.authenticated);
    let profile = info
        .authenticated_profile()
        .expect("active peer has a redacted authenticated profile");
    assert_eq!(profile.protocol_version, myownmesh_core::PROTOCOL_VERSION);
    assert!(profile.endpoint_auth_v1);
}

fn assert_baseline(label: &str, before: &ResourceReport, after: &ResourceReport) {
    for (before, after) in before
        .pre_authentication
        .iter()
        .zip(after.pre_authentication.iter())
    {
        assert_eq!(
            after.active, before.active,
            "{label} pre-auth {:?} active baseline",
            before.family
        );
        assert_eq!(
            after.active_lease_count, before.active_lease_count,
            "{label} pre-auth {:?} lease baseline",
            before.family
        );
    }
    for (before, after) in before
        .post_authentication
        .iter()
        .zip(after.post_authentication.iter())
    {
        assert_eq!(
            after.active, before.active,
            "{label} post-auth {:?} active baseline",
            before.family
        );
        assert_eq!(
            after.active_lease_count, before.active_lease_count,
            "{label} post-auth {:?} lease baseline",
            before.family
        );
    }
}

// Match the shipped daemon's multi-thread Tokio runtime. Native WebRTC owns
// callbacks and worker threads that are not representative on the macro's
// default current-thread test runtime.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closed_members_relay_through_production_local_broker() -> myownmesh_core::Result<()> {
    let home = tempfile::tempdir().expect("temporary mesh home");
    std::env::set_var("MYOWNMESH_HOME", home.path());

    let alice = Arc::new(Identity::ephemeral());
    let relay = Arc::new(Identity::ephemeral());
    let carol = Arc::new(Identity::ephemeral());
    let alice_id = alice.public_id().to_string();
    let relay_id = relay.public_id().to_string();
    let carol_id = carol.public_id().to_string();
    let network_id = "closed-member-relay-production";

    let bootstrap = VerifiedBootstrap::create_closed(network_id, [alice.signing_key()], [0x91; 32])
        .expect("closed bootstrap is valid");
    let record = bootstrap.record().clone();
    let context_id = bootstrap.context_id();
    let mut graph = FactGraph::from_bootstrap(&bootstrap);
    let grant_relay = member_grant(
        &graph,
        &alice,
        DeviceId::from_canonical_str(&relay_id).expect("relay id is canonical"),
    );
    graph
        .admit(grant_relay.clone())
        .expect("relay grant admits");
    let grant_carol = member_grant(
        &graph,
        &alice,
        DeviceId::from_canonical_str(&carol_id).expect("Carol id is canonical"),
    );
    let member_facts = vec![grant_relay, grant_carol];

    let policy = finite_connector_policy();
    let alice_mesh = bounded(
        "open Alice mesh",
        Mesh::open_connector_capable_with_identity(MeshConfig::default(), alice, policy.clone()),
    )
    .await??;
    let relay_mesh = bounded(
        "open relay mesh",
        Mesh::open_connector_capable_with_identity(MeshConfig::default(), relay, policy.clone()),
    )
    .await??;
    let carol_mesh = bounded(
        "open Carol mesh",
        Mesh::open_connector_capable_with_identity(MeshConfig::default(), carol, policy),
    )
    .await??;
    let baseline_alice = alice_mesh.resource_report();
    let baseline_relay = relay_mesh.resource_report();
    let baseline_carol = carol_mesh.resource_report();

    let alice_net = bounded(
        "create Alice network",
        alice_mesh.create_network(network_config("alice", network_id, &relay_id), [0x91; 32]),
    )
    .await??;
    let relay_net = bounded(
        "import relay network",
        relay_mesh.import_network(
            network_config("relay", network_id, &relay_id),
            context_id,
            record.clone(),
        ),
    )
    .await??;
    let carol_net = bounded(
        "import Carol network",
        carol_mesh.import_network(
            network_config("carol", network_id, &relay_id),
            context_id,
            record,
        ),
    )
    .await??;
    for network in [&alice_net, &relay_net, &carol_net] {
        bounded(
            "import member facts",
            network.import_signed_facts(member_facts.clone()),
        )
        .await??;
    }

    let mut alice_events = alice_mesh.events();
    let mut relay_events = relay_mesh.events();
    let mut carol_events = carol_mesh.events();
    let relay_expected = [alice_id.clone(), carol_id.clone()];
    let broker = LocalBroker::new();
    alice_net.attach_local(&broker);
    relay_net.attach_local(&broker);
    carol_net.attach_local(&broker);

    let (alice_ready, relay_ready, carol_ready) = tokio::join!(
        bounded(
            "Alice-relay production handshake",
            wait_for_authenticated_and_approved(&mut alice_events, std::slice::from_ref(&relay_id)),
        ),
        bounded(
            "relay production handshakes",
            wait_for_authenticated_and_approved(&mut relay_events, &relay_expected),
        ),
        bounded(
            "Carol-relay production handshake",
            wait_for_authenticated_and_approved(&mut carol_events, std::slice::from_ref(&relay_id)),
        ),
    );
    alice_ready?;
    relay_ready?;
    carol_ready?;

    assert_active_profile(&alice_net, &relay_id);
    assert_active_profile(&relay_net, &alice_id);
    assert_active_profile(&relay_net, &carol_id);
    assert_active_profile(&carol_net, &relay_id);
    assert!(!alice_net
        .peer(&carol_id)
        .is_some_and(|peer| matches!(peer.status, PeerStatus::Active)));
    assert!(!carol_net
        .peer(&alice_id)
        .is_some_and(|peer| matches!(peer.status, PeerStatus::Active)));

    let (alice_channel, carol_channel) = tokio::join!(
        bounded(
            "open Alice-Carol relay",
            alice_net.open_closed_relay(&relay_id, &carol_id),
        ),
        bounded("accept Alice-Carol relay", carol_net.accept_closed_relay()),
    );
    let alice_channel = alice_channel??;
    let carol_channel = carol_channel??;
    assert_eq!(alice_channel.peer_device_id(), carol_id);
    assert_eq!(alice_channel.relay_device_id(), relay_id);
    assert_eq!(carol_channel.peer_device_id(), alice_id);
    assert_eq!(carol_channel.relay_device_id(), relay_id);
    assert_eq!(alice_channel.session_id(), carol_channel.session_id());
    assert_ne!(alice_channel.session_id(), [0; 16]);

    let sentinel = b"closed-relay plaintext must not reach B".to_vec();
    bounded(
        "send Alice-to-Carol opaque payload",
        alice_channel.send(&sentinel),
    )
    .await??;
    assert_eq!(
        bounded("receive Alice-to-Carol payload", carol_channel.recv()).await??,
        sentinel
    );
    let reverse = b"Carol-to-Alice opaque reply".to_vec();
    bounded(
        "send Carol-to-Alice opaque payload",
        carol_channel.send(&reverse),
    )
    .await??;
    assert_eq!(
        bounded("receive Carol-to-Alice payload", alice_channel.recv()).await??,
        reverse
    );
    // B owns only the authenticated relay legs.  No public endpoint handle or
    // plaintext receive path exists on B; the sentinel crossed only A's/C's
    // endpoint sessions while the B leg remained a keyless forwarder.

    bounded("close Carol endpoint", carol_channel.close()).await??;
    let _ = bounded("close Alice endpoint", alice_channel.close()).await;
    bounded("shutdown Alice network", alice_net.shutdown()).await??;
    bounded("shutdown relay network", relay_net.shutdown()).await??;
    bounded("shutdown Carol network", carol_net.shutdown()).await??;
    drop(alice_net);
    drop(relay_net);
    drop(carol_net);
    assert_baseline("Alice", &baseline_alice, &alice_mesh.resource_report());
    assert_baseline("relay", &baseline_relay, &relay_mesh.resource_report());
    assert_baseline("Carol", &baseline_carol, &carol_mesh.resource_report());
    Ok(())
}
