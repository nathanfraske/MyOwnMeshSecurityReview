#![cfg(feature = "transport-lab")]

//! Production-shaped R3 controls for durable stand-down proof delivery.
//!
//! These controls intentionally use the public outbox and proof-wire APIs
//! from the proof-delivery lane.  The checkout on which this file was first
//! authored may not yet contain those exports; that is an integration
//! dependency, not a test-local substitute for durable custody.

use std::sync::Arc;

use myownmesh_core::config::{NetworkConfig, SignalingConfig, TopologyMode};
use myownmesh_core::engine::transport_lab::ingest_semantic_fact;
use myownmesh_core::engine::{
    create_network_in_instance_root, governance, import_network_in_instance_root,
    spawn_network_in_instance_root,
};
use myownmesh_core::identity::Identity;
use myownmesh_core::network_state::NetworkKind;
use myownmesh_core::protocol::{ProofAckMessage, ProofDeliveryMessage};
use myownmesh_core::semantic::{
    AttestationDecision, DeviceId, DurableProofOutbox, FactBody, FactContent, FactGraph,
    ProofRecord, ProofRecordState, SignedFact, VerifiedBootstrap,
};
use tempfile::TempDir;

mod support;

fn closed_config(id: &str) -> NetworkConfig {
    NetworkConfig {
        id: id.to_string(),
        network_id: format!("{id}-wire"),
        label: id.to_string(),
        kind: NetworkKind::Closed,
        topology: TopologyMode::FullMesh,
        signaling: SignalingConfig::default(),
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        roster_path: None,
        pinned_peers: Vec::new(),
        auto_approve: false,
    }
}

fn device(identity: &Identity) -> DeviceId {
    DeviceId::from_canonical_str(identity.public_id()).expect("identity has canonical device id")
}

fn authored(graph: &FactGraph, signer: &Identity, body: FactBody) -> SignedFact {
    let signer_id = device(signer);
    let witness = graph.authoring_witness(&body, &signer_id);
    let content = FactContent::from_authoring_witness(graph, body, &witness, Vec::new());
    SignedFact::sign(content, signer.signing_key()).expect("fixture fact signs")
}

/// Build a complete, causal eviction proof.  It is deliberately returned in
/// causal order so production ingestion can persist each fact before the next
/// one is admitted; the wire envelope re-sorts it by FactId independently.
fn stand_down_facts(
    bootstrap: &VerifiedBootstrap,
    owner: &Identity,
    target: &Identity,
    member: &Identity,
) -> Vec<SignedFact> {
    let target_id = device(target);
    let member_id = device(member);
    let mut graph = FactGraph::from_bootstrap(bootstrap);

    let grant = authored(
        &graph,
        owner,
        FactBody::RoleGrant {
            target: member_id.clone(),
            role: myownmesh_core::semantic::Role::Member,
        },
    );
    graph.admit(grant.clone()).expect("member grant admits");

    let proposal = authored(
        &graph,
        owner,
        FactBody::Evict {
            target: target_id.clone(),
        },
    );
    graph
        .admit(proposal.clone())
        .expect("eviction proposal admits");

    let attestation = authored(
        &graph,
        member,
        FactBody::Attestation {
            target: target_id.clone(),
            proposal: proposal.id,
            decision: AttestationDecision::Evict,
            signer: member_id,
            contributions: Vec::new(),
        },
    );
    graph
        .admit(attestation.clone())
        .expect("member eviction attestation admits");

    let proof = authored(
        &graph,
        owner,
        FactBody::EvictionProof {
            target: target_id,
            evidence: vec![attestation.id],
        },
    );
    graph.admit(proof.clone()).expect("eviction proof admits");

    vec![grant, proposal, attestation, proof]
}

fn receiver_admits_delivery(
    bootstrap: &VerifiedBootstrap,
    delivery: &ProofDeliveryMessage,
) -> FactGraph {
    let mut receiver = FactGraph::from_bootstrap(bootstrap);
    for fact in delivery.facts.iter().cloned() {
        receiver
            .admit(fact)
            .expect("receiver durably admits proof fact");
    }
    receiver
        .retry_quarantined()
        .expect("receiver resolves proof dependencies");
    receiver
}

async fn create_fixture(
    root: &TempDir,
    id: &str,
) -> (
    Arc<myownmesh_core::engine::NetworkState>,
    tokio::task::JoinHandle<()>,
    Arc<Identity>,
    Identity,
    Vec<SignedFact>,
    myownmesh_core::semantic::MeshContextId,
    NetworkConfig,
) {
    let identity = Arc::new(Identity::ephemeral());
    let target = Identity::ephemeral();
    let member = Identity::ephemeral();
    let config = closed_config(id);
    let (state, driver) = create_network_in_instance_root(
        config.clone(),
        identity.clone(),
        support::test_transport(),
        root.path().to_path_buf(),
        [0x73; 32],
    )
    .await
    .expect("create Closed network");
    let context = state.mesh_context_id();
    let facts = stand_down_facts(
        state.verified_bootstrap(),
        identity.as_ref(),
        &target,
        &member,
    );
    for fact in facts.iter().cloned() {
        ingest_semantic_fact(&state, fact).await;
    }
    state
        .compact_semantic_state()
        .expect("compact the adopted semantic proof");
    (state, driver, identity, target, facts, context, config)
}

#[tokio::test]
async fn r3_pending_proof_is_persisted_before_send_and_replayed_after_restart() {
    let root = TempDir::new().expect("instance root");
    let (state, driver, _identity, target, facts, context, config) =
        create_fixture(&root, "r3-replay").await;
    let target_id = device(&target);
    let outbox = DurableProofOutbox::new(root.path(), &config.id);
    let record = ProofRecord::pending(
        context,
        target_id.clone(),
        facts.iter().map(|fact| fact.id).collect(),
        "owner-before-send",
        "binding-before-send",
    )
    .expect("pending proof record");
    let persisted = outbox
        .enqueue(record.clone())
        .expect("persist before transport send");
    assert_eq!(persisted.delivery_id, record.delivery_id);
    assert_eq!(outbox.pending(context).expect("pending records").len(), 1);

    let delivery = ProofDeliveryMessage::new(context, target_id.clone(), facts.clone())
        .expect("typed proof delivery");
    assert_eq!(delivery.delivery_id, record.delivery_id);
    let duplicate = outbox
        .enqueue(record.clone())
        .expect("same delivery id is an idempotent enqueue");
    assert_eq!(duplicate, record);

    state.request_shutdown();
    driver.await.expect("first lifecycle shutdown");

    let (reopened, reopened_driver) = spawn_network_in_instance_root(
        config.clone(),
        _identity,
        support::test_transport(),
        root.path().to_path_buf(),
    )
    .await
    .expect("reopen after offline interval");
    let replay = DurableProofOutbox::new(root.path(), &config.id);
    let pending = replay.pending(context).expect("replayed pending records");
    assert_eq!(pending, vec![record.clone()]);
    assert_eq!(pending[0].state, ProofRecordState::Pending);
    assert_eq!(pending[0].delivery_id, delivery.delivery_id);

    let receiver = receiver_admits_delivery(reopened.verified_bootstrap(), &delivery);
    assert!(receiver.projection().is_stood_down(&target_id));
    let ack = ProofAckMessage::for_delivery(&delivery);
    assert!(
        ack.matches(&delivery),
        "ACK is typed to this exact delivery"
    );
    assert!(replay
        .settle(context, record.delivery_id)
        .expect("settle exact delivery"));
    assert!(replay
        .settle(context, record.delivery_id)
        .expect("duplicate ACK is idempotent"));
    assert!(replay
        .pending(context)
        .expect("settled records filter from replay")
        .is_empty());

    reopened.request_shutdown();
    reopened_driver.await.expect("reopened lifecycle shutdown");
}

#[tokio::test]
async fn r3_receiver_refuses_pre_stand_down_ack_and_stale_owner_binding() {
    let root = TempDir::new().expect("instance root");
    let (state, driver, _identity, target, facts, context, config) =
        create_fixture(&root, "r3-typed").await;
    let target_id = device(&target);
    let outbox = DurableProofOutbox::new(root.path(), &config.id);
    let record = ProofRecord::pending(
        context,
        target_id.clone(),
        facts.iter().map(|fact| fact.id).collect(),
        "owner-live",
        "binding-live",
    )
    .expect("typed pending record");
    outbox
        .enqueue(record.clone())
        .expect("enqueue typed record");

    assert!(matches!(
        outbox.rebind(
            context,
            record.delivery_id,
            "wrong-owner",
            "binding-live",
            "owner-next",
            "binding-next",
        ),
        Err(myownmesh_core::semantic::ProofOutboxError::StaleBinding)
    ));

    let prefix = ProofDeliveryMessage::new(context, target_id.clone(), facts[..3].to_vec())
        .expect("prefix delivery serializes");
    let prefix_receiver = receiver_admits_delivery(state.verified_bootstrap(), &prefix);
    assert!(
        !prefix_receiver.projection().is_stood_down(&target_id),
        "a receiver cannot ACK before canonical proof evidence is admitted"
    );

    let delivery = ProofDeliveryMessage::new(context, target_id.clone(), facts.clone())
        .expect("complete delivery serializes");

    // The receiver is a second durable NetworkState, not only an in-memory
    // reducer.  Its production ingress must adopt the exact proof facts before
    // the canonical projection can authorize an ACK.
    let receiver_root = TempDir::new().expect("receiver instance root");
    let receiver_identity = Arc::new(Identity::from_signing_key(
        target.signing_key().clone(),
        "r3-receiver",
    ));
    let (receiver_state, receiver_driver) = import_network_in_instance_root(
        config.clone(),
        receiver_identity,
        support::test_transport(),
        receiver_root.path().to_path_buf(),
        context,
        state.verified_bootstrap().record().clone(),
    )
    .await
    .expect("receiver imports the exact bootstrap");
    for fact in facts.iter().cloned() {
        ingest_semantic_fact(&receiver_state, fact).await;
    }
    receiver_state
        .compact_semantic_state()
        .expect("receiver durably commits the proof graph");
    assert!(
        governance::snapshot(&receiver_state)
            .stood_down
            .contains(target.public_id()),
        "receiver projection is stood down only after complete proof admission"
    );
    let ack = ProofAckMessage::for_delivery(&delivery);
    assert!(ack.matches(&delivery));
    assert!(outbox
        .settle(context, ack.delivery_id)
        .expect("exact ACK settles"));
    assert!(outbox
        .pending(context)
        .expect("settled proof filters")
        .is_empty());

    state.request_shutdown();
    driver.await.expect("typed delivery lifecycle shutdown");
    receiver_state.request_shutdown();
    receiver_driver.await.expect("receiver lifecycle shutdown");
}

#[tokio::test]
async fn r3_restart_preserves_adopted_graph_self_eviction_and_pending_receipt() {
    let root = TempDir::new().expect("instance root");
    let (state, driver, identity, target, facts, context, config) =
        create_fixture(&root, "r3-restart").await;
    let target_id = device(&target);
    let outbox = DurableProofOutbox::new(root.path(), &config.id);
    let record = ProofRecord::pending(
        context,
        target_id.clone(),
        facts.iter().map(|fact| fact.id).collect(),
        "owner-restart",
        "binding-restart",
    )
    .expect("restart pending record");
    outbox
        .enqueue(record.clone())
        .expect("persist restart receipt");
    state.request_shutdown();
    driver.await.expect("pre-restart shutdown");

    let (reopened, reopened_driver) = spawn_network_in_instance_root(
        config.clone(),
        identity,
        support::test_transport(),
        root.path().to_path_buf(),
    )
    .await
    .expect("restart durable network");
    let snapshot = governance::snapshot(&reopened);
    assert!(
        snapshot.stood_down.contains(target.public_id()),
        "restart preserves the adopted eviction/stand-down projection"
    );
    assert!(
        reopened.semantic_fact_count() >= facts.len(),
        "restart preserves every adopted proof fact"
    );
    let replay = DurableProofOutbox::new(root.path(), &config.id);
    assert_eq!(
        replay.pending(context).expect("restart pending receipt"),
        vec![record.clone()]
    );

    // Reopen the same signed log as the evicted device.  This is the
    // self-eviction boundary: the receiver's own durable projection must
    // remain stood down after it adopts the persisted proof facts.
    let receiver_root = TempDir::new().expect("self-evicted receiver root");
    let receiver_identity = Arc::new(Identity::from_signing_key(
        target.signing_key().clone(),
        "r3-self-evicted",
    ));
    let (receiver_state, receiver_driver) = import_network_in_instance_root(
        config.clone(),
        receiver_identity,
        support::test_transport(),
        receiver_root.path().to_path_buf(),
        context,
        reopened.verified_bootstrap().record().clone(),
    )
    .await
    .expect("self-evicted receiver imports bootstrap");
    for fact in facts.iter().cloned() {
        ingest_semantic_fact(&receiver_state, fact).await;
    }
    receiver_state
        .compact_semantic_state()
        .expect("self-evicted receiver commits proof graph");
    assert!(
        governance::snapshot(&receiver_state)
            .stood_down
            .contains(target.public_id()),
        "self-eviction remains active after receiver restart/adoption"
    );

    let delivery =
        ProofDeliveryMessage::new(context, target_id, facts).expect("restart replay delivery");
    let ack = ProofAckMessage::for_delivery(&delivery);
    assert!(ack.matches(&delivery));
    assert!(replay
        .settle(context, record.delivery_id)
        .expect("restart ACK settles"));
    assert!(replay
        .pending(context)
        .expect("restart receipt settles")
        .is_empty());

    reopened.request_shutdown();
    reopened_driver.await.expect("post-restart shutdown");
    receiver_state.request_shutdown();
    receiver_driver
        .await
        .expect("self-evicted receiver shutdown");
}
