#![cfg(feature = "transport-lab")]

//! Production-shaped R3 controls for durable stand-down proof delivery.
//!
//! These controls intentionally use the state-owned transport-lab façade and
//! proof-wire APIs from the proof-delivery lane.  The façade keeps each test
//! on the same durable semantic slot as production.

use std::collections::BTreeSet;
use std::sync::Arc;

use myownmesh_core::config::{NetworkConfig, SignalingConfig, TopologyMode};
use myownmesh_core::engine::transport_lab::{
    admit_durable_proof, durable_proof_records, materialize_durable_proof_delivery,
    pending_durable_proofs, proof_owner_for_device, rebind_durable_proof, settle_durable_proof_ack,
    supersede_durable_proof,
};
use myownmesh_core::engine::{
    attach_local, create_network_in_instance_root, governance, import_network_in_instance_root,
    spawn_network_in_instance_root, transport_lab::ingest_semantic_fact,
};
use myownmesh_core::identity::Identity;
use myownmesh_core::network_state::NetworkKind;
use myownmesh_core::protocol::{ProofAckMessage, ProofDeliveryMessage};
use myownmesh_core::semantic::{
    AttestationDecision, DeviceId, FactBody, FactContent, FactGraph, ProofRecord, ProofRecordState,
    SignedFact, VerifiedBootstrap,
};
use myownmesh_signaling::local::LocalBroker;
use tempfile::TempDir;
use tokio::time::{sleep, Duration, Instant};

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
        auto_approve: true,
    }
}

fn device(identity: &Identity) -> DeviceId {
    DeviceId::from_canonical_str(identity.public_id()).expect("identity has canonical device id")
}

fn authored(graph: &FactGraph, signer: &Identity, body: FactBody) -> SignedFact {
    authored_with_support(graph, signer, body, std::iter::empty())
}

fn authored_with_support<I>(
    graph: &FactGraph,
    signer: &Identity,
    body: FactBody,
    support: I,
) -> SignedFact
where
    I: IntoIterator<Item = myownmesh_core::semantic::FactId>,
{
    let signer_id = device(signer);
    let witness = graph.authoring_witness(&body, &signer_id);
    let content = FactContent::from_authoring_witness(graph, body, &witness, support);
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
            target: target_id.clone(),
            role: myownmesh_core::semantic::Role::Member,
        },
    );
    graph.admit(grant.clone()).expect("target grant admits");

    let member_grant = authored(
        &graph,
        owner,
        FactBody::RoleGrant {
            target: member_id.clone(),
            role: myownmesh_core::semantic::Role::Member,
        },
    );
    graph
        .admit(member_grant.clone())
        .expect("member grant admits");

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

    vec![grant, member_grant, proposal, attestation, proof]
}

/// Extend an adopted eviction with a causal regrant and a distinct second
/// eviction. The second closure includes the first history, but its new
/// regrant/proposal/attestation/proof identities force a new delivery id.
fn reissued_stand_down_facts(
    bootstrap: &VerifiedBootstrap,
    prior: &[SignedFact],
    owner: &Identity,
    target: &Identity,
    member: &Identity,
) -> Vec<SignedFact> {
    let target_id = device(target);
    let member_id = device(member);
    let mut graph = FactGraph::from_bootstrap(bootstrap);
    for fact in prior.iter().cloned() {
        graph.admit(fact).expect("prior eviction history admits");
    }

    let regrant = authored(
        &graph,
        owner,
        FactBody::RoleGrant {
            target: target_id.clone(),
            role: myownmesh_core::semantic::Role::Member,
        },
    );
    graph.admit(regrant.clone()).expect("causal regrant admits");

    let proposal = authored(
        &graph,
        owner,
        FactBody::Evict {
            target: target_id.clone(),
        },
    );
    graph
        .admit(proposal.clone())
        .expect("second eviction proposal admits");

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
        .expect("second eviction attestation admits");

    let proof = authored(
        &graph,
        owner,
        FactBody::EvictionProof {
            target: target_id,
            evidence: vec![attestation.id],
        },
    );
    graph
        .admit(proof.clone())
        .expect("second eviction proof admits");

    let mut facts = prior.to_vec();
    facts.extend([regrant, proposal, attestation, proof]);
    facts
}

fn regrant_after_eviction_fact(
    bootstrap: &VerifiedBootstrap,
    prior: &[SignedFact],
    owner: &Identity,
    target: &Identity,
) -> SignedFact {
    let target_id = device(target);
    let mut graph = FactGraph::from_bootstrap(bootstrap);
    for fact in prior.iter().cloned() {
        graph.admit(fact).expect("prior eviction history admits");
    }
    let regrant = authored(
        &graph,
        owner,
        FactBody::MembershipAdmit { target: target_id },
    );
    graph.admit(regrant.clone()).expect("causal regrant admits");
    regrant
}

struct CrossTargetFacts {
    facts: Vec<SignedFact>,
    cross_target_evict: SignedFact,
    target_evict: SignedFact,
}

/// Build a fresh target proof whose target Evict explicitly depends on an
/// Evict for a different device.  The dependency is carried through the real
/// authoring witness plus an exact causal support parent, so the receiver must
/// admit the cross-target fact before the target's terminal projection can
/// become authoritative.
fn cross_target_stand_down_facts(
    bootstrap: &VerifiedBootstrap,
    prior: &[SignedFact],
    owner: &Identity,
    target: &Identity,
    member: &Identity,
    cross_target: &Identity,
) -> CrossTargetFacts {
    let target_id = device(target);
    let member_id = device(member);
    let cross_target_id = device(cross_target);
    let mut graph = FactGraph::from_bootstrap(bootstrap);
    for fact in prior.iter().cloned() {
        graph.admit(fact).expect("prior eviction history admits");
    }

    let regrant = authored(
        &graph,
        owner,
        FactBody::RoleGrant {
            target: target_id.clone(),
            role: myownmesh_core::semantic::Role::Member,
        },
    );
    graph.admit(regrant.clone()).expect("target regrant admits");

    let cross_grant = authored(
        &graph,
        owner,
        FactBody::RoleGrant {
            target: cross_target_id.clone(),
            role: myownmesh_core::semantic::Role::Member,
        },
    );
    graph
        .admit(cross_grant.clone())
        .expect("cross-target grant admits");

    let cross_target_evict = authored(
        &graph,
        owner,
        FactBody::Evict {
            target: cross_target_id,
        },
    );
    graph
        .admit(cross_target_evict.clone())
        .expect("cross-target eviction admits");

    let target_evict = authored_with_support(
        &graph,
        owner,
        FactBody::Evict {
            target: target_id.clone(),
        },
        [cross_target_evict.id],
    );
    assert!(
        myownmesh_core::semantic::causal::dependencies(&target_evict)
            .contains(&cross_target_evict.id),
        "target Evict carries the cross-target causal dependency"
    );
    graph
        .admit(target_evict.clone())
        .expect("cross-target target eviction admits");

    let attestation = authored(
        &graph,
        member,
        FactBody::Attestation {
            target: target_id.clone(),
            proposal: target_evict.id,
            decision: AttestationDecision::Evict,
            signer: member_id,
            contributions: Vec::new(),
        },
    );
    graph
        .admit(attestation.clone())
        .expect("cross-target target attestation admits");

    let proof = authored(
        &graph,
        owner,
        FactBody::EvictionProof {
            target: target_id,
            evidence: vec![attestation.id],
        },
    );
    graph
        .admit(proof.clone())
        .expect("cross-target target proof admits");

    let mut facts = prior.to_vec();
    facts.extend([
        regrant,
        cross_grant,
        cross_target_evict.clone(),
        target_evict.clone(),
        attestation,
        proof,
    ]);
    CrossTargetFacts {
        facts,
        cross_target_evict,
        target_evict,
    }
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
    Arc<myownmesh_core::engine::NetworkState>,
    tokio::task::JoinHandle<()>,
    Arc<Identity>,
    Identity,
    Identity,
    Vec<SignedFact>,
    myownmesh_core::semantic::MeshContextId,
    NetworkConfig,
    LocalBroker,
    TempDir,
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

    // Keep a real authenticated target installation in the sender registry so
    // the transport-lab façade can issue the exact owner witness used by
    // rebind/settle.  The target receives the grants but not the eviction
    // closure: it remains a live carrier while the sender adopts the proof.
    let target_root = TempDir::new().expect("target instance root");
    let target_identity = Arc::new(Identity::from_signing_key(
        target.signing_key().clone(),
        "r3-target",
    ));
    let (target_state, target_driver) = import_network_in_instance_root(
        config.clone(),
        target_identity,
        support::test_transport(),
        target_root.path().to_path_buf(),
        context,
        state.verified_bootstrap().record().clone(),
    )
    .await
    .expect("target imports the exact bootstrap");
    for fact in facts.iter().take(2).cloned() {
        ingest_semantic_fact(&state, fact.clone()).await;
        ingest_semantic_fact(&target_state, fact).await;
    }
    state
        .compact_semantic_state()
        .expect("compact the admitted roster grants");
    target_state
        .compact_semantic_state()
        .expect("compact target roster grants");

    let broker = LocalBroker::new();
    let mut state_events = state.events_tx.subscribe();
    let mut target_events = target_state.events_tx.subscribe();
    attach_local(&state, &broker);
    attach_local(&target_state, &broker);
    wait_for_approval(&mut state_events, target.public_id()).await;
    wait_for_approval(&mut target_events, identity.public_id()).await;

    for fact in facts.iter().skip(2).cloned() {
        ingest_semantic_fact(&state, fact).await;
    }
    state
        .compact_semantic_state()
        .expect("compact the adopted semantic proof");
    (
        state,
        driver,
        target_state,
        target_driver,
        identity,
        target,
        member,
        facts,
        context,
        config,
        broker,
        target_root,
    )
}

async fn wait_for_approval(
    rx: &mut tokio::sync::broadcast::Receiver<myownmesh_core::MeshEvent>,
    peer_id: &str,
) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if Instant::now() > deadline {
            panic!("never saw PeerApproved for {peer_id}");
        }
        match tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
            Ok(Ok(myownmesh_core::MeshEvent::Peer(myownmesh_core::PeerEvent::Approved {
                device_id,
                ..
            }))) if device_id == peer_id => return,
            _ => continue,
        }
    }
}

async fn wait_for_proof_owner(
    state: &Arc<myownmesh_core::engine::NetworkState>,
    device_id: &str,
) -> myownmesh_core::engine::transport_lab::ProofOwner {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(owner) = proof_owner_for_device(state, device_id) {
            return owner;
        }
        if Instant::now() > deadline {
            panic!("never installed proof owner for {device_id}");
        }
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_no_proof_owner(
    state: &Arc<myownmesh_core::engine::NetworkState>,
    device_id: &str,
) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if proof_owner_for_device(state, device_id).is_none() {
            return;
        }
        if Instant::now() > deadline {
            panic!("stale proof owner remained installed for {device_id}");
        }
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_replayed_proof(
    state: &Arc<myownmesh_core::engine::NetworkState>,
    previous: &ProofRecord,
) -> (ProofRecord, bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let target = previous.target.to_string();
    loop {
        let Some(owner) = proof_owner_for_device(state, &target) else {
            if Instant::now() > deadline {
                panic!("production proof replay did not expose a current owner");
            }
            sleep(Duration::from_millis(20)).await;
            continue;
        };
        let expected = myownmesh_core::engine::transport_lab::new_durable_proof_record(
            state,
            &owner,
            &previous.fact_ids,
        )
        .expect("current owner proof identity");
        assert_eq!(expected.context_id, previous.context_id);
        assert_eq!(expected.target, previous.target);
        assert_eq!(expected.delivery_id, previous.delivery_id);
        assert_eq!(expected.fact_ids, previous.fact_ids);
        assert_eq!(expected.owner, previous.owner);
        assert_ne!(expected.binding, previous.binding);
        let current = durable_proof_records(state)
            .expect("replay durable records")
            .into_iter()
            .find(|record| record.delivery_id == previous.delivery_id);
        if let Some(current) = current {
            match current.state {
                ProofRecordState::Pending => {
                    if current == expected {
                        return (current, true);
                    }
                }
                ProofRecordState::Settled => {
                    assert_exact_delivery_metadata(&current, &expected);
                    return (current, false);
                }
                ProofRecordState::Superseded => {
                    panic!(
                        "replayed delivery {} was Superseded before the test terminal",
                        previous.delivery_id
                    );
                }
            }
        }
        if Instant::now() > deadline {
            panic!("production proof replay did not expose Pending or an exact Settled tombstone");
        }
        sleep(Duration::from_millis(20)).await;
    }
}

async fn wait_for_durable_record_state(
    state: &Arc<myownmesh_core::engine::NetworkState>,
    delivery_id: myownmesh_core::semantic::ProofDeliveryId,
    expected: ProofRecordState,
) -> ProofRecord {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let record = durable_proof_records(state)
            .expect("read exact durable replay state")
            .into_iter()
            .find(|record| record.delivery_id == delivery_id)
            .expect("durable delivery record remains observable");
        if record.state == expected {
            return record;
        }
        if Instant::now() > deadline {
            panic!(
                "durable delivery {delivery_id} remained {:?}, expected {expected:?}",
                record.state
            );
        }
        sleep(Duration::from_millis(20)).await;
    }
}

fn assert_exact_delivery_metadata(actual: &ProofRecord, expected: &ProofRecord) {
    assert_eq!(actual.context_id, expected.context_id);
    assert_eq!(actual.target, expected.target);
    assert_eq!(actual.delivery_id, expected.delivery_id);
    assert_eq!(actual.fact_ids, expected.fact_ids);
    assert_eq!(actual.owner, expected.owner);
    assert_eq!(actual.binding, expected.binding);
}

fn assert_settled_tombstone(
    state: &Arc<myownmesh_core::engine::NetworkState>,
    expected: &ProofRecord,
) {
    let tombstone = durable_proof_records(state)
        .expect("read exact durable terminal record")
        .into_iter()
        .find(|record| record.delivery_id == expected.delivery_id)
        .expect("exact delivery tombstone remains persisted");
    assert_exact_delivery_metadata(&tombstone, expected);
    assert_eq!(tombstone.state, ProofRecordState::Settled);
}

#[tokio::test]
async fn r3_pending_proof_is_persisted_before_send_and_replayed_after_restart() {
    let root = TempDir::new().expect("instance root");
    let (
        state,
        driver,
        target_state,
        target_driver,
        identity,
        target,
        _member,
        facts,
        _context,
        config,
        broker,
        _target_root,
    ) = create_fixture(&root, "r3-replay").await;
    let target_id = device(&target);
    let owner = wait_for_proof_owner(&state, target.public_id()).await;
    let record = myownmesh_core::engine::transport_lab::new_durable_proof_record(
        &state,
        &owner,
        &facts.iter().map(|fact| fact.id).collect::<Vec<_>>(),
    )
    .expect("pending proof record");
    let persisted =
        admit_durable_proof(&state, record.clone()).expect("persist before transport send");
    assert_eq!(persisted.delivery_id, record.delivery_id);
    assert_eq!(
        pending_durable_proofs(&state)
            .expect("pending records")
            .len(),
        1
    );

    let delivery =
        materialize_durable_proof_delivery(&state, &record).expect("typed proof delivery");
    assert_eq!(delivery.delivery_id, record.delivery_id);
    let duplicate = admit_durable_proof(&state, record.clone())
        .expect("same delivery id is an idempotent enqueue");
    assert_eq!(duplicate, record);

    state.request_shutdown();
    driver.await.expect("first lifecycle shutdown");
    drop(owner);
    drop(state);

    let (reopened, reopened_driver) = spawn_network_in_instance_root(
        config.clone(),
        identity,
        support::test_transport(),
        root.path().to_path_buf(),
    )
    .await
    .expect("reopen after offline interval");
    attach_local(&reopened, &broker);
    let reopened_owner = wait_for_proof_owner(&reopened, target.public_id()).await;
    let (rebound, replay_was_pending) = wait_for_replayed_proof(&reopened, &record).await;
    assert_eq!(
        rebound.state,
        if replay_was_pending {
            ProofRecordState::Pending
        } else {
            ProofRecordState::Settled
        }
    );
    assert_eq!(rebound.delivery_id, delivery.delivery_id);

    let receiver = receiver_admits_delivery(reopened.verified_bootstrap(), &delivery);
    assert!(receiver.projection().is_stood_down(&target_id));
    let ack = ProofAckMessage::for_delivery(&delivery);
    assert!(
        ack.matches(&delivery),
        "ACK is typed to this exact delivery"
    );
    if replay_was_pending {
        let first_settle =
            settle_durable_proof_ack(&reopened, &reopened_owner, &rebound, record.delivery_id)
                .expect("settle exact delivery");
        if !first_settle {
            assert_settled_tombstone(&reopened, &rebound);
        }
    }
    assert_settled_tombstone(&reopened, &rebound);
    if replay_was_pending {
        assert!(!settle_durable_proof_ack(
            &reopened,
            &reopened_owner,
            &rebound,
            record.delivery_id,
        )
        .expect("duplicate ACK is an idempotent no-op"));
    }
    assert!(pending_durable_proofs(&reopened)
        .expect("settled records filter from replay")
        .is_empty());

    reopened.request_shutdown();
    reopened_driver.await.expect("reopened lifecycle shutdown");
    target_state.request_shutdown();
    target_driver.await.expect("target lifecycle shutdown");
}

#[tokio::test]
async fn r3_pending_approval_proof_delivery_sends_one_ack_and_settles_sender() {
    let root = TempDir::new().expect("instance root");
    let (
        state,
        driver,
        target_state,
        target_driver,
        _identity,
        target,
        _member,
        facts,
        _context,
        config,
        broker,
        target_root,
    ) = create_fixture(&root, "r3-pending-ack").await;
    let owner = wait_for_proof_owner(&state, target.public_id()).await;
    let record = myownmesh_core::engine::transport_lab::new_durable_proof_record(
        &state,
        &owner,
        &facts.iter().map(|fact| fact.id).collect::<Vec<_>>(),
    )
    .expect("PendingApproval proof record");
    let delivery =
        materialize_durable_proof_delivery(&state, &record).expect("valid proof delivery");
    admit_durable_proof(&state, record.clone()).expect("persist PendingApproval proof");

    // The target was offline while the source adopted the eviction closure.
    // Close the original endpoint, then recreate the same identity/root with
    // auto-approval disabled so the proof is admitted through the real
    // PendingApproval semantic lane before the denial terminalizes the session.
    let target_signing_key = target.signing_key().clone();
    let target_bootstrap = state.verified_bootstrap().record().clone();
    target_state.request_shutdown();
    target_driver
        .await
        .expect("offline-evicted target shutdown");
    drop(owner);
    drop(target_state);
    wait_for_no_proof_owner(&state, target.public_id()).await;

    let mut target_config = config.clone();
    target_config.auto_approve = false;
    let restarted_target_identity = Arc::new(Identity::from_signing_key(
        target_signing_key,
        "r3-pending-ack-target",
    ));
    let (restarted_target, restarted_target_driver) = import_network_in_instance_root(
        target_config,
        restarted_target_identity,
        support::test_transport(),
        target_root.path().to_path_buf(),
        state.mesh_context_id(),
        target_bootstrap,
    )
    .await
    .expect("recreate offline-evicted target");
    for fact in facts.iter().take(2).cloned() {
        ingest_semantic_fact(&restarted_target, fact).await;
    }
    restarted_target
        .compact_semantic_state()
        .expect("target retains only pre-eviction facts");
    let target_initial_fact_count = restarted_target.semantic_fact_count();
    attach_local(&restarted_target, &broker);

    let rebound_owner = wait_for_proof_owner(&state, target.public_id()).await;
    let settled =
        wait_for_durable_record_state(&state, record.delivery_id, ProofRecordState::Settled).await;
    let expected = myownmesh_core::engine::transport_lab::new_durable_proof_record(
        &state,
        &rebound_owner,
        &record.fact_ids,
    )
    .expect("current owner proof identity");
    assert_exact_delivery_metadata(&settled, &expected);
    assert_eq!(
        durable_proof_records(&state)
            .expect("settled sender proof records")
            .into_iter()
            .filter(|candidate| candidate.delivery_id == record.delivery_id)
            .count(),
        1,
        "one exact sender record is settled by the matching ACK"
    );
    assert!(pending_durable_proofs(&state)
        .expect("settled proof leaves no pending sender record")
        .is_empty());

    let deadline = Instant::now() + Duration::from_secs(20);
    while !restarted_target
        .self_evicted
        .load(std::sync::atomic::Ordering::SeqCst)
    {
        if Instant::now() > deadline {
            panic!("PendingApproval target never adopted the valid ProofDelivery");
        }
        sleep(Duration::from_millis(20)).await;
    }
    assert!(
        restarted_target.semantic_fact_count() > target_initial_fact_count,
        "valid ProofDelivery adds the complete eviction closure"
    );
    assert_eq!(
        restarted_target.semantic_unresolved_count(),
        0,
        "PendingApproval proof admission resolves every dependency"
    );
    assert!(
        !settle_durable_proof_ack(&state, &rebound_owner, &settled, delivery.delivery_id,)
            .expect("duplicate matching ACK is idempotent")
    );

    state.request_shutdown();
    driver.await.expect("sender lifecycle shutdown");
    restarted_target.request_shutdown();
    restarted_target_driver
        .await
        .expect("recreated target lifecycle shutdown");
}

#[tokio::test]
async fn r3_cross_target_pending_approval_proof_acknowledges_exact_closure() {
    let root = TempDir::new().expect("instance root");
    let (
        state,
        driver,
        target_state,
        target_driver,
        _identity,
        target,
        member,
        prior,
        _context,
        config,
        broker,
        target_root,
    ) = create_fixture(&root, "r3-cross-target").await;
    let cross_target = Identity::ephemeral();
    let owner = wait_for_proof_owner(&state, target.public_id()).await;
    let cross = cross_target_stand_down_facts(
        state.verified_bootstrap(),
        &prior,
        state.identity.as_ref(),
        &target,
        &member,
        &cross_target,
    );
    for fact in cross.facts.iter().skip(prior.len()).cloned() {
        ingest_semantic_fact(&state, fact).await;
    }
    state
        .compact_semantic_state()
        .expect("durably commit cross-target eviction closure");
    assert!(
        governance::snapshot(&state)
            .stood_down
            .contains(target.public_id()),
        "the target's terminal projection is active before delivery"
    );

    let record = myownmesh_core::engine::transport_lab::canonical_durable_eviction_proof_record(
        &state, &owner,
    )
    .expect("derive canonical cross-target proof record")
    .expect("cross-target target eviction proof exists");
    assert!(
        record.fact_ids.contains(&cross.cross_target_evict.id),
        "canonical proof carries the cross-target Evict dependency"
    );
    assert!(
        record.fact_ids.contains(&cross.target_evict.id),
        "canonical proof carries the target Evict head"
    );
    let delivery =
        materialize_durable_proof_delivery(&state, &record).expect("cross-target proof delivery");
    assert!(
        delivery
            .facts
            .iter()
            .any(|fact| fact.id == cross.cross_target_evict.id),
        "wire delivery contains the exact cross-target dependency"
    );
    admit_durable_proof(&state, record.clone()).expect("persist cross-target proof");

    let target_signing_key = target.signing_key().clone();
    let target_bootstrap = state.verified_bootstrap().record().clone();
    target_state.request_shutdown();
    target_driver
        .await
        .expect("offline-evicted target shutdown");
    drop(owner);
    drop(target_state);
    wait_for_no_proof_owner(&state, target.public_id()).await;

    let mut target_config = config.clone();
    target_config.auto_approve = false;
    let restarted_target_identity = Arc::new(Identity::from_signing_key(
        target_signing_key,
        "r3-cross-target-target",
    ));
    let (restarted_target, restarted_target_driver) = import_network_in_instance_root(
        target_config,
        restarted_target_identity,
        support::test_transport(),
        target_root.path().to_path_buf(),
        state.mesh_context_id(),
        target_bootstrap,
    )
    .await
    .expect("recreate cross-target PendingApproval target");
    for fact in prior.iter().take(2).cloned() {
        ingest_semantic_fact(&restarted_target, fact).await;
    }
    restarted_target
        .compact_semantic_state()
        .expect("target retains the authenticated roster grants");
    let target_initial_fact_count = restarted_target.semantic_fact_count();
    attach_local(&restarted_target, &broker);

    let rebound_owner = wait_for_proof_owner(&state, target.public_id()).await;
    let settled =
        wait_for_durable_record_state(&state, record.delivery_id, ProofRecordState::Settled).await;
    let expected = myownmesh_core::engine::transport_lab::new_durable_proof_record(
        &state,
        &rebound_owner,
        &record.fact_ids,
    )
    .expect("current cross-target owner proof identity");
    assert_exact_delivery_metadata(&settled, &expected);
    assert_eq!(
        durable_proof_records(&state)
            .expect("settled cross-target sender records")
            .into_iter()
            .filter(|candidate| candidate.delivery_id == record.delivery_id)
            .count(),
        1,
        "one exact sender record is settled by the matching ACK"
    );
    assert!(pending_durable_proofs(&state)
        .expect("settled cross-target proof leaves no pending record")
        .is_empty());
    assert!(
        restarted_target
            .self_evicted
            .load(std::sync::atomic::Ordering::SeqCst),
        "PendingApproval target adopts the terminal cross-target proof"
    );
    assert!(
        restarted_target.semantic_fact_count() > target_initial_fact_count,
        "target receives the cross-target causal closure"
    );
    assert_eq!(
        restarted_target.semantic_unresolved_count(),
        0,
        "cross-target dependency is durably resolved before ACK"
    );
    assert!(
        governance::snapshot(&restarted_target)
            .stood_down
            .contains(target.public_id()),
        "target terminal projection holds after exact delivery"
    );
    let ack = ProofAckMessage::for_delivery(&delivery);
    assert!(ack.matches(&delivery));
    assert!(
        !settle_durable_proof_ack(&state, &rebound_owner, &settled, ack.delivery_id)
            .expect("duplicate matching ACK is idempotent"),
        "a second matching ACK does not settle twice"
    );

    state.request_shutdown();
    driver.await.expect("cross-target sender shutdown");
    restarted_target.request_shutdown();
    restarted_target_driver
        .await
        .expect("cross-target target shutdown");
}

#[tokio::test]
async fn r3_stale_e0_is_superseded_before_e1_reconnect_replay() {
    let root = TempDir::new().expect("instance root");
    let (
        state,
        driver,
        target_state,
        target_driver,
        identity,
        target,
        member,
        e0_facts,
        _context,
        config,
        broker,
        _target_root,
    ) = create_fixture(&root, "r3-supersede").await;
    let target_id = device(&target);
    let owner = wait_for_proof_owner(&state, target.public_id()).await;
    let e0 = myownmesh_core::engine::transport_lab::new_durable_proof_record(
        &state,
        &owner,
        &e0_facts.iter().map(|fact| fact.id).collect::<Vec<_>>(),
    )
    .expect("E0 pending proof record");
    let e0_delivery = materialize_durable_proof_delivery(&state, &e0).expect("E0 proof delivery");
    admit_durable_proof(&state, e0.clone()).expect("persist E0 before send");
    assert_eq!(e0_delivery.delivery_id, e0.delivery_id);

    // ACK loss is represented by shutting down with E0 still Pending. A
    // sender restart restores that exact durable obligation, not a new id.
    state.request_shutdown();
    driver.await.expect("sender restart boundary");
    drop(owner);
    drop(state);
    let (reopened, reopened_driver) = spawn_network_in_instance_root(
        config.clone(),
        identity,
        support::test_transport(),
        root.path().to_path_buf(),
    )
    .await
    .expect("sender reconnects from the durable slot");
    attach_local(&reopened, &broker);
    let reopened_owner = wait_for_proof_owner(&reopened, target.public_id()).await;
    let (e0_rebound, e0_was_pending) = wait_for_replayed_proof(&reopened, &e0).await;
    assert_eq!(
        e0_rebound.state,
        if e0_was_pending {
            ProofRecordState::Pending
        } else {
            ProofRecordState::Settled
        }
    );
    assert_eq!(e0_rebound.delivery_id, e0_delivery.delivery_id);

    // A causal regrant followed by a fresh eviction creates E1 with a new
    // canonical closure. The stale E0 is retired as Superseded, never as an
    // ACK, before the admitted reconnect can enumerate replayable records.
    let e0_before_e1 = durable_proof_records(&reopened)
        .expect("read E0 before constructing E1")
        .into_iter()
        .find(|record| record.delivery_id == e0.delivery_id)
        .expect("E0 remains durably observable before E1");
    assert_exact_delivery_metadata(&e0_before_e1, &e0_rebound);
    let e0_pending_before_e1 = match e0_before_e1.state {
        ProofRecordState::Pending => true,
        ProofRecordState::Settled => false,
        ProofRecordState::Superseded => {
            panic!("E0 cannot be Superseded before E1 is constructed")
        }
    };
    let e1_facts = reissued_stand_down_facts(
        reopened.verified_bootstrap(),
        &e0_facts,
        reopened.identity.as_ref(),
        &target,
        &member,
    );
    for fact in e1_facts.iter().skip(e0_facts.len()).cloned() {
        ingest_semantic_fact(&reopened, fact).await;
    }
    reopened
        .compact_semantic_state()
        .expect("compact the newly admitted E1 closure");
    let e1 = myownmesh_core::engine::transport_lab::new_durable_proof_record(
        &reopened,
        &reopened_owner,
        &e1_facts.iter().map(|fact| fact.id).collect::<Vec<_>>(),
    )
    .expect("E1 pending proof record");
    let e1_delivery =
        materialize_durable_proof_delivery(&reopened, &e1).expect("E1 proof delivery");
    assert_ne!(
        e0.delivery_id, e1.delivery_id,
        "E1 must not reuse E0 identity"
    );
    admit_durable_proof(&reopened, e1.clone()).expect("persist E1 closure");
    let supersede_result = if e0_pending_before_e1 {
        Some(supersede_durable_proof(
            &reopened,
            &reopened_owner,
            &e0,
            Some(e1.delivery_id),
        ))
    } else {
        assert_settled_tombstone(&reopened, &e0_rebound);
        None
    };
    let records = durable_proof_records(&reopened).expect("read E0/E1 terminal records");
    let e0_tombstone = records
        .iter()
        .find(|record| record.delivery_id == e0.delivery_id)
        .expect("exact E0 tombstone remains persisted");
    assert_exact_delivery_metadata(e0_tombstone, &e0_rebound);
    match supersede_result.as_ref() {
        None => assert_eq!(e0_tombstone.state, ProofRecordState::Settled),
        Some(Ok(true)) => assert_eq!(e0_tombstone.state, ProofRecordState::Superseded),
        Some(Ok(false)) => assert_eq!(
            e0_tombstone.state,
            ProofRecordState::Superseded,
            "an idempotent supersession is legal only with the exact Superseded tombstone"
        ),
        Some(Err(_)) => assert_eq!(
            e0_tombstone.state,
            ProofRecordState::Settled,
            "a supersession error is legal only when the exact ACK won the race"
        ),
    }
    assert_ne!(e0_tombstone.state, ProofRecordState::Pending);
    let e1_pending = records
        .iter()
        .find(|record| record.delivery_id == e1.delivery_id)
        .expect("exact E1 replacement remains persisted");
    assert_exact_delivery_metadata(e1_pending, &e1);
    assert_eq!(e1_pending.state, ProofRecordState::Pending);
    if e0_tombstone.state == ProofRecordState::Superseded {
        assert!(
            !supersede_durable_proof(&reopened, &reopened_owner, &e0, Some(e1.delivery_id))
                .expect("repeated E0 supersession is idempotent")
        );
    }

    let pending = pending_durable_proofs(&reopened).expect("enumerate reconnect replay");
    assert_eq!(
        pending,
        vec![e1.clone()],
        "reconnect must emit E1, never E0"
    );
    assert!(!pending
        .iter()
        .any(|record| record.delivery_id == e0.delivery_id));
    let receiver = receiver_admits_delivery(reopened.verified_bootstrap(), &e1_delivery);
    assert!(
        receiver.projection().is_stood_down(&target_id),
        "the fresh E1 closure still proves the target stand-down"
    );

    reopened.request_shutdown();
    reopened_driver.await.expect("reconnect lifecycle shutdown");
    target_state.request_shutdown();
    target_driver.await.expect("target lifecycle shutdown");
}

#[tokio::test]
async fn r3_external_transport_pause_supersedes_materialized_e0_before_resume() {
    let root = TempDir::new().expect("instance root");
    let (
        state,
        driver,
        target_state,
        target_driver,
        identity,
        target,
        member,
        facts,
        context,
        config,
        broker,
        target_root,
    ) = create_fixture(&root, "r3-external-pause").await;
    let target_id = device(&target);
    let owner = wait_for_proof_owner(&state, target.public_id()).await;

    // External transport is paused at the exact boundary after E0 selection
    // and materialization.  Until the final send admission below, E0 is only
    // an in-memory typed delivery and cannot be emitted by a carrier.
    let e0 = myownmesh_core::engine::transport_lab::new_durable_proof_record(
        &state,
        &owner,
        &facts.iter().map(|fact| fact.id).collect::<Vec<_>>(),
    )
    .expect("materialized E0 proof record");
    let e0_delivery = materialize_durable_proof_delivery(&state, &e0)
        .expect("materialize E0 while transport is paused");
    assert_eq!(e0_delivery.delivery_id, e0.delivery_id);
    assert!(
        durable_proof_records(&state)
            .expect("observe unadmitted E0")
            .into_iter()
            .all(|record| record.delivery_id != e0.delivery_id),
        "materialization alone must not admit E0 to the durable send queue"
    );

    // While E0 is paused, durably commit the causal G1 restoration and build
    // its exact successor E1.  The successor includes G1 and a fresh closure,
    // so its delivery identity cannot alias the materialized E0 identity.
    let g1 = regrant_after_eviction_fact(
        state.verified_bootstrap(),
        &facts,
        state.identity.as_ref(),
        &target,
    );
    ingest_semantic_fact(&state, g1.clone()).await;
    state
        .compact_semantic_state()
        .expect("durably commit G1 while E0 is paused");
    assert!(
        !governance::snapshot(&state)
            .stood_down
            .contains(target.public_id()),
        "G1 clears the old stand-down before E1 is authored"
    );
    let mut g1_history = facts.clone();
    g1_history.push(g1);
    let e1_facts = reissued_stand_down_facts(
        state.verified_bootstrap(),
        &g1_history,
        state.identity.as_ref(),
        &target,
        &member,
    );
    for fact in e1_facts.iter().skip(g1_history.len()).cloned() {
        ingest_semantic_fact(&state, fact).await;
    }
    state
        .compact_semantic_state()
        .expect("durably commit exact E1 closure");
    let e1 = myownmesh_core::engine::transport_lab::canonical_durable_eviction_proof_record(
        &state, &owner,
    )
    .expect("derive canonical E1 proof record")
    .expect("current E1 eviction proof exists");
    let e1_new_facts = &e1_facts[g1_history.len()..];
    assert!(
        e1.fact_ids.contains(&g1_history[g1_history.len() - 1].id),
        "canonical E1 includes causal G1"
    );
    let e1_role_head = e1_new_facts
        .iter()
        .find(|fact| matches!(&fact.content.body, FactBody::RoleGrant { .. }))
        .expect("E1 has a current role head");
    let e1_evict_head = e1_new_facts
        .iter()
        .find(|fact| matches!(&fact.content.body, FactBody::Evict { .. }))
        .expect("E1 has a current membership/Evict head");
    assert!(e1.fact_ids.contains(&e1_role_head.id));
    assert!(e1.fact_ids.contains(&e1_evict_head.id));
    let mut canonical_graph = FactGraph::from_bootstrap(state.verified_bootstrap());
    for fact in e1_facts.iter().cloned() {
        canonical_graph
            .admit(fact)
            .expect("E1 history rebuilds for canonical seed selection");
    }
    let selected_stand_down_seed = canonical_graph
        .projection()
        .stand_down(&target_id)
        .map(|stand_down| stand_down.proof);
    let mut reachable = BTreeSet::new();
    let mut pending = vec![e1_role_head.id, e1_evict_head.id];
    if let Some(proof) = selected_stand_down_seed {
        assert!(
            e1.fact_ids.contains(&proof),
            "canonical E1 contains its selected stand-down seed"
        );
        pending.push(proof);
    }
    while let Some(id) = pending.pop() {
        if !reachable.insert(id) {
            continue;
        }
        let fact = e1_facts
            .iter()
            .find(|fact| fact.id == id)
            .expect("every selected-head dependency is in E1 history");
        pending.extend(myownmesh_core::semantic::causal::dependencies(fact));
    }
    assert_eq!(
        e1.fact_ids.iter().copied().collect::<BTreeSet<_>>(),
        reachable,
        "canonical E1 is exactly the selected-head causal closure"
    );
    let e1_delivery =
        materialize_durable_proof_delivery(&state, &e1).expect("materialize exact E1 delivery");
    assert_ne!(e0.delivery_id, e1.delivery_id);
    assert_eq!(e1_delivery.delivery_id, e1.delivery_id);

    // Resume admits both records only after G1/E1 are durable.  Close both
    // endpoint lifecycles at this pause boundary, then recreate the same
    // target identity and root before the sender's next carrier attach.  The
    // following attach is therefore the sole replay trigger: production must
    // supersede stale E0 and send only the canonical E1.
    admit_durable_proof(&state, e0.clone()).expect("admit paused E0 for replay fencing");
    admit_durable_proof(&state, e1.clone()).expect("admit exact E1 for replay");
    let pending_before_resume = pending_durable_proofs(&state).expect("pending E0/E1");
    assert!(pending_before_resume.iter().any(|record| record == &e0));
    assert!(pending_before_resume.iter().any(|record| record == &e1));
    let target_signing_key = target.signing_key().clone();
    let target_bootstrap = state.verified_bootstrap().record().clone();
    state.request_shutdown();
    driver.await.expect("paused sender shutdown");
    target_state.request_shutdown();
    target_driver
        .await
        .expect("paused target endpoint shutdown");
    drop(owner);
    drop(state);
    drop(target_state);

    let restarted_target_identity =
        Arc::new(Identity::from_signing_key(target_signing_key, "r3-target"));
    let (restarted_target, restarted_target_driver) = import_network_in_instance_root(
        config.clone(),
        restarted_target_identity,
        support::test_transport(),
        target_root.path().to_path_buf(),
        context,
        target_bootstrap,
    )
    .await
    .expect("recreate target endpoint from the same identity");
    for fact in facts.iter().take(2).cloned() {
        ingest_semantic_fact(&restarted_target, fact).await;
    }
    restarted_target
        .compact_semantic_state()
        .expect("recreated target commits the authenticated roster grants");
    attach_local(&restarted_target, &broker);

    let (reopened, reopened_driver) = spawn_network_in_instance_root(
        config,
        identity,
        support::test_transport(),
        root.path().to_path_buf(),
    )
    .await
    .expect("resume sender after G1/E1 commit");
    attach_local(&reopened, &broker);
    let reopened_owner = wait_for_proof_owner(&reopened, target.public_id()).await;
    let e0_terminal =
        wait_for_durable_record_state(&reopened, e0.delivery_id, ProofRecordState::Superseded)
            .await;
    assert_exact_delivery_metadata(&e0_terminal, &e0);
    assert!(
        !pending_durable_proofs(&reopened)
            .expect("enumerate resumed exact replay")
            .iter()
            .any(|record| record.delivery_id == e0.delivery_id),
        "the stale, materialized E0 is never emitted after resume"
    );

    let rebound_e1 = myownmesh_core::engine::transport_lab::new_durable_proof_record(
        &reopened,
        &reopened_owner,
        &e1.fact_ids,
    )
    .expect("derive exact rebound E1 identity");
    assert_eq!(rebound_e1.context_id, e1.context_id);
    assert_eq!(rebound_e1.target, e1.target);
    assert_eq!(rebound_e1.delivery_id, e1.delivery_id);
    assert_eq!(rebound_e1.fact_ids, e1.fact_ids);
    assert_eq!(rebound_e1.owner, e1.owner);
    assert_ne!(rebound_e1.binding, e1.binding);
    let (e1_rebound, e1_was_pending) = wait_for_replayed_proof(&reopened, &e1).await;
    assert_eq!(
        e1_rebound.state,
        if e1_was_pending {
            ProofRecordState::Pending
        } else {
            ProofRecordState::Settled
        }
    );
    assert_eq!(e1_rebound.delivery_id, e1.delivery_id);
    assert_eq!(e1_rebound.context_id, context);
    assert_eq!(e1_rebound.target, target_id);
    assert_exact_delivery_metadata(&e1_rebound, &rebound_e1);
    let deadline = Instant::now() + Duration::from_secs(20);
    while !governance::snapshot(&restarted_target)
        .stood_down
        .contains(target.public_id())
    {
        if Instant::now() > deadline {
            panic!("canonical E1 was not sent after external transport resumed");
        }
        sleep(Duration::from_millis(20)).await;
    }

    reopened.request_shutdown();
    reopened_driver.await.expect("resumed sender shutdown");
    restarted_target.request_shutdown();
    restarted_target_driver
        .await
        .expect("recreated target lifecycle shutdown");
}

#[tokio::test]
async fn r3_regrant_before_resume_supersedes_e0_without_replay_or_stand_down() {
    let root = TempDir::new().expect("instance root");
    let (
        state,
        driver,
        target_state,
        target_driver,
        identity,
        target,
        _member,
        facts,
        _context,
        config,
        broker,
        _target_root,
    ) = create_fixture(&root, "r3-regrant-race").await;
    assert!(
        !governance::snapshot(&target_state)
            .stood_down
            .contains(target.public_id()),
        "initial authenticated target has not received a stand-down proof"
    );

    let owner = wait_for_proof_owner(&state, target.public_id()).await;
    let e0 = myownmesh_core::engine::transport_lab::new_durable_proof_record(
        &state,
        &owner,
        &facts.iter().map(|fact| fact.id).collect::<Vec<_>>(),
    )
    .expect("E0 proof record");
    let e0_delivery = materialize_durable_proof_delivery(&state, &e0).expect("E0 delivery");
    admit_durable_proof(&state, e0.clone()).expect("persist selected E0");
    assert_eq!(
        durable_proof_records(&state)
            .expect("observe selected E0")
            .into_iter()
            .find(|record| record.delivery_id == e0.delivery_id)
            .expect("selected E0 remains present")
            .state,
        ProofRecordState::Pending
    );
    assert_eq!(e0_delivery.delivery_id, e0.delivery_id);

    state.request_shutdown();
    driver.await.expect("selected E0 lifecycle shutdown");
    drop(owner);
    drop(state);

    // Deterministic resume barrier: reopen without attaching transport, commit
    // the causal G1 regrant, and only then resume the broker replay path.
    let (reopened, reopened_driver) = spawn_network_in_instance_root(
        config.clone(),
        identity,
        support::test_transport(),
        root.path().to_path_buf(),
    )
    .await
    .expect("reopen before replay");
    let g1 = regrant_after_eviction_fact(
        reopened.verified_bootstrap(),
        &facts,
        reopened.identity.as_ref(),
        &target,
    );
    ingest_semantic_fact(&reopened, g1).await;
    reopened
        .compact_semantic_state()
        .expect("durably commit G1 before resume");
    assert!(
        !governance::snapshot(&reopened)
            .stood_down
            .contains(target.public_id()),
        "G1 restoration clears the sender's active stand-down before replay"
    );
    let selected_before_resume = durable_proof_records(&reopened)
        .expect("observe E0 before resume")
        .into_iter()
        .find(|record| record.delivery_id == e0.delivery_id)
        .expect("E0 remains durable across the regrant");
    assert_exact_delivery_metadata(&selected_before_resume, &e0);
    assert_eq!(selected_before_resume.state, ProofRecordState::Pending);

    // Attaching the broker is the only resume action. Replay must inspect the
    // current proof selection, fence E0 as Superseded, and never send E0.
    attach_local(&reopened, &broker);
    let _reopened_owner = wait_for_proof_owner(&reopened, target.public_id()).await;
    let e0_terminal =
        wait_for_durable_record_state(&reopened, e0.delivery_id, ProofRecordState::Superseded)
            .await;
    assert_exact_delivery_metadata(&e0_terminal, &e0);
    assert!(
        !pending_durable_proofs(&reopened)
            .expect("enumerate resumed replay")
            .iter()
            .any(|record| record.delivery_id == e0.delivery_id),
        "the selected E0 is never replayed after G1 restoration"
    );
    assert!(
        !governance::snapshot(&target_state)
            .stood_down
            .contains(target.public_id()),
        "the stale E0 never reaches the target as a stand-down-causing proof"
    );

    reopened.request_shutdown();
    reopened_driver.await.expect("resumed sender shutdown");
    target_state.request_shutdown();
    target_driver.await.expect("target lifecycle shutdown");
}

#[tokio::test]
async fn r3_receiver_refuses_pre_stand_down_ack_and_stale_owner_binding() {
    let root = TempDir::new().expect("instance root");
    let (
        state,
        driver,
        target_state,
        target_driver,
        _identity,
        target,
        _member,
        facts,
        context,
        config,
        broker,
        target_root,
    ) = create_fixture(&root, "r3-typed").await;
    let target_id = device(&target);
    let owner = wait_for_proof_owner(&state, target.public_id()).await;
    let record = myownmesh_core::engine::transport_lab::new_durable_proof_record(
        &state,
        &owner,
        &facts.iter().map(|fact| fact.id).collect::<Vec<_>>(),
    )
    .expect("typed pending record");
    admit_durable_proof(&state, record.clone()).expect("enqueue typed record");
    let delivery =
        materialize_durable_proof_delivery(&state, &record).expect("complete delivery serializes");

    // Replace the target installation. The first witness is now stale, while
    // the replacement witness is the only one allowed to rebind the Pending
    // record through the state-owned façade.
    target_state.request_shutdown();
    target_driver
        .await
        .expect("stale target lifecycle shutdown");
    drop(target_state);
    wait_for_no_proof_owner(&state, target.public_id()).await;
    let replacement_identity = Arc::new(Identity::from_signing_key(
        target.signing_key().clone(),
        "r3-target-replacement",
    ));
    let (replacement, replacement_driver) = spawn_network_in_instance_root(
        config.clone(),
        replacement_identity,
        support::test_transport(),
        target_root.path().to_path_buf(),
    )
    .await
    .expect("replacement target lifecycle");
    attach_local(&replacement, &broker);
    let replacement_owner = wait_for_proof_owner(&state, target.public_id()).await;
    let (rebound, replay_was_pending) = wait_for_replayed_proof(&state, &record).await;
    assert!(!rebind_durable_proof(&state, &owner, &record).expect("stale owner refusal"));
    assert_eq!(
        rebound.state,
        if replay_was_pending {
            ProofRecordState::Pending
        } else {
            ProofRecordState::Settled
        }
    );

    let prefix = ProofDeliveryMessage::new(context, target_id.clone(), facts[..3].to_vec())
        .expect("prefix delivery serializes");
    let prefix_receiver = receiver_admits_delivery(state.verified_bootstrap(), &prefix);
    assert!(
        !prefix_receiver.projection().is_stood_down(&target_id),
        "a receiver cannot ACK before canonical proof evidence is admitted"
    );

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
    if replay_was_pending {
        let first_settle =
            settle_durable_proof_ack(&state, &replacement_owner, &rebound, ack.delivery_id)
                .expect("exact ACK settles");
        if !first_settle {
            assert_settled_tombstone(&state, &rebound);
        }
    }
    assert_settled_tombstone(&state, &rebound);
    assert!(pending_durable_proofs(&state)
        .expect("settled proof filters")
        .is_empty());

    state.request_shutdown();
    driver.await.expect("typed delivery lifecycle shutdown");
    replacement.request_shutdown();
    replacement_driver
        .await
        .expect("replacement target shutdown");
    receiver_state.request_shutdown();
    receiver_driver.await.expect("receiver lifecycle shutdown");
}

#[tokio::test]
async fn r3_restart_preserves_adopted_graph_self_eviction_and_pending_receipt() {
    let root = TempDir::new().expect("instance root");
    let (
        state,
        driver,
        target_state,
        target_driver,
        identity,
        target,
        _member,
        facts,
        context,
        config,
        broker,
        target_root,
    ) = create_fixture(&root, "r3-restart").await;
    let owner = wait_for_proof_owner(&state, target.public_id()).await;
    let record = myownmesh_core::engine::transport_lab::new_durable_proof_record(
        &state,
        &owner,
        &facts.iter().map(|fact| fact.id).collect::<Vec<_>>(),
    )
    .expect("restart pending record");
    admit_durable_proof(&state, record.clone()).expect("persist restart receipt");
    let delivery =
        materialize_durable_proof_delivery(&state, &record).expect("restart replay delivery");
    let target_signing_key = target.signing_key().clone();
    let target_bootstrap = state.verified_bootstrap().record().clone();
    state.request_shutdown();
    driver.await.expect("pre-restart shutdown");
    target_state.request_shutdown();
    target_driver
        .await
        .expect("target endpoint restart boundary");
    drop(owner);
    drop(state);
    drop(target_state);

    // Recreate the target from the same signing key and durable instance root
    // before the sender resumes.  This closes the old endpoint lifecycle so
    // the replay must cross a genuine authenticated transport boundary.
    let restarted_target_identity =
        Arc::new(Identity::from_signing_key(target_signing_key, "r3-target"));
    let (restarted_target, restarted_target_driver) = import_network_in_instance_root(
        config.clone(),
        restarted_target_identity,
        support::test_transport(),
        target_root.path().to_path_buf(),
        context,
        target_bootstrap,
    )
    .await
    .expect("recreate target endpoint from the same identity");
    for fact in facts.iter().take(2).cloned() {
        ingest_semantic_fact(&restarted_target, fact).await;
    }
    restarted_target
        .compact_semantic_state()
        .expect("recreated target commits the authenticated roster grants");
    attach_local(&restarted_target, &broker);

    let (reopened, reopened_driver) = spawn_network_in_instance_root(
        config.clone(),
        identity,
        support::test_transport(),
        root.path().to_path_buf(),
    )
    .await
    .expect("restart durable network");
    attach_local(&reopened, &broker);
    let reopened_owner = wait_for_proof_owner(&reopened, target.public_id()).await;
    let (rebound, replay_was_pending) = wait_for_replayed_proof(&reopened, &record).await;
    let snapshot = governance::snapshot(&reopened);
    assert!(
        snapshot.stood_down.contains(target.public_id()),
        "restart preserves the adopted eviction/stand-down projection"
    );
    assert!(
        reopened.semantic_fact_count() >= facts.len(),
        "restart preserves every adopted proof fact"
    );
    assert_eq!(
        rebound.state,
        if replay_was_pending {
            ProofRecordState::Pending
        } else {
            ProofRecordState::Settled
        }
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

    let ack = ProofAckMessage::for_delivery(&delivery);
    assert!(ack.matches(&delivery));
    if replay_was_pending {
        let first_settle =
            settle_durable_proof_ack(&reopened, &reopened_owner, &rebound, record.delivery_id)
                .expect("restart ACK settles");
        if !first_settle {
            assert_settled_tombstone(&reopened, &rebound);
        }
    }
    assert_settled_tombstone(&reopened, &rebound);
    assert!(pending_durable_proofs(&reopened)
        .expect("restart receipt settles")
        .is_empty());

    reopened.request_shutdown();
    reopened_driver.await.expect("post-restart shutdown");
    restarted_target.request_shutdown();
    restarted_target_driver
        .await
        .expect("recreated target lifecycle shutdown");
    receiver_state.request_shutdown();
    receiver_driver
        .await
        .expect("self-evicted receiver shutdown");
}
