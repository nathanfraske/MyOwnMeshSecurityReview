#![cfg(feature = "transport-lab")]

//! Differential controls for the durable semantic projection.
//!
//! The expected side is deliberately a direct `FactGraph` batch model.  It
//! never calls the engine reducer or a durable-store mutator.  The observed
//! side imports one fact at a time through `JoinedNetwork`, exports the
//! resulting canonical page, and compares the exact graph identity and pure
//! projection.  Five fixed closed orders cover dependency-first/last,
//! reverse, and two domain-interleaved schedules.  These orders are finite but
//! discriminate every causal edge and each adopted domain without depending on
//! randomness.  Open participation is ephemeral presence, so its lifecycle
//! control asserts a zero semantic/durable delta across leave and restart.

use std::collections::BTreeSet;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use myownmesh_core::config::{
    ClosedRelayPolicyConfig, NetworkConfig, NetworkKind, RoutingPolicyConfig, SignalingConfig,
    TopologyMode,
};
use myownmesh_core::resource::{
    FiniteResourceProvider, ResourceClaim, ResourceClass, ResourceProviderPort,
};
use myownmesh_core::semantic::{
    Admission, AttestationDecision, CellProjection, DeviceId, ExclusiveCell, FactBody, FactContent,
    FactGraph, FactId, Projection, Role, SignedFact, VerifiedBootstrap,
};
use myownmesh_core::{
    ConnectorCallbackPolicy, Identity, Mesh, MeshConfig, WebRtcConnectorCapablePolicy,
    WebRtcConnectorProfile,
};

mod support;

#[derive(Debug, Clone, PartialEq, Eq)]
struct GraphSnapshot {
    identity: IdentitySnapshot,
    /// `(id, admitted, canonical signed content bytes)` is the exact durable
    /// graph transcript, including unresolved custody and its status.
    canonical_graph: Vec<(FactId, bool, Vec<u8>)>,
    projection: Projection,
    authority_heads: Vec<(DeviceId, Vec<FactId>)>,
    conflict_heads: Vec<(ExclusiveCell, Option<Vec<FactId>>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IdentitySnapshot {
    context_id: myownmesh_core::semantic::MeshContextId,
    admitted_fact_count: u64,
    unresolved_fact_count: u64,
    projection_commitment: [u8; 32],
    state_commitment: [u8; 32],
}

struct Scenario {
    bootstrap: VerifiedBootstrap,
    local: DeviceId,
    facts: Vec<SignedFact>,
    continuation: SignedFact,
    foreign: SignedFact,
    subjects: Vec<DeviceId>,
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn device(key: &SigningKey) -> DeviceId {
    DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes()).expect("canonical device id")
}

fn authored(
    graph: &FactGraph,
    signer: &SigningKey,
    body: FactBody,
    support: Vec<FactId>,
) -> SignedFact {
    let author = device(signer);
    let witness = graph.authoring_witness(&body, &author);
    SignedFact::sign(
        FactContent::from_authoring_witness(graph, body, &witness, support),
        signer,
    )
    .expect("scenario fact signs")
}

fn admit(graph: &mut FactGraph, fact: SignedFact) {
    assert!(matches!(
        graph.admit(fact),
        Ok(Admission::Inserted | Admission::AlreadyPresent | Admission::Quarantined { .. })
    ));
    graph
        .retry_quarantined()
        .expect("causal quarantine retry remains valid");
}

fn closed_scenario(network_id: &str, root: &SigningKey) -> Scenario {
    let controller = key(42);
    let member = key(43);
    let bootstrap =
        VerifiedBootstrap::create_closed(network_id, [root], [0x41; 32]).expect("closed bootstrap");
    let local = device(root);
    let controller_id = device(&controller);
    let member_id = device(&member);
    let future_id = device(&key(44));

    let mut source = FactGraph::from_bootstrap(&bootstrap);
    let grant_controller = authored(
        &source,
        root,
        FactBody::RoleGrant {
            target: controller_id.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    admit(&mut source, grant_controller.clone());
    let grant_member = authored(
        &source,
        &controller,
        FactBody::RoleGrant {
            target: member_id.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    admit(&mut source, grant_member.clone());
    // This is concurrent with the controller's member grant.  It creates an
    // explicit AuthorityLineage fork, which the projection must retain.
    let revoke_controller = authored(
        &source,
        root,
        FactBody::RoleRevoke {
            target: controller_id.clone(),
        },
        Vec::new(),
    );
    admit(&mut source, revoke_controller.clone());
    let proposal = authored(
        &source,
        root,
        FactBody::Evict {
            target: member_id.clone(),
        },
        Vec::new(),
    );
    admit(&mut source, proposal.clone());
    let attestation = authored(
        &source,
        root,
        FactBody::Attestation {
            target: member_id.clone(),
            proposal: proposal.id,
            decision: AttestationDecision::Evict,
            signer: local.clone(),
            contributions: Vec::new(),
        },
        Vec::new(),
    );
    admit(&mut source, attestation.clone());
    let proof = authored(
        &source,
        root,
        FactBody::EvictionProof {
            target: member_id.clone(),
            evidence: vec![attestation.id],
        },
        Vec::new(),
    );
    admit(&mut source, proof.clone());
    let continuation = authored(
        &source,
        root,
        FactBody::MembershipAdmit {
            target: member_id.clone(),
        },
        Vec::new(),
    );

    let foreign_bootstrap =
        VerifiedBootstrap::create_closed("semantic-differential-foreign", [root], [0x42; 32])
            .expect("foreign bootstrap");
    let foreign = SignedFact::sign(
        FactContent::new(
            myownmesh_core::semantic::FactDomain::Governance,
            foreign_bootstrap.context_id(),
            FactBody::RoleGrant {
                target: future_id.clone(),
                role: Role::Member,
            },
            local.clone(),
            Vec::new(),
        ),
        root,
    )
    .expect("foreign fact signs");

    Scenario {
        bootstrap,
        local: local.clone(),
        facts: vec![
            grant_controller,
            grant_member,
            revoke_controller,
            proposal,
            attestation,
            proof,
        ],
        continuation,
        foreign,
        subjects: vec![local, controller_id, member_id, future_id],
    }
}

fn projection_commitment(projection: &Projection) -> [u8; 32] {
    let mut bytes = Vec::new();
    for (cell, value) in projection.cells() {
        bytes.extend_from_slice(cell.to_string().as_bytes());
        bytes.push(0);
        match value {
            CellProjection::Value(id) => {
                bytes.push(1);
                bytes.extend_from_slice(id.as_bytes());
            }
            CellProjection::Conflict(ids) => {
                bytes.push(2);
                for id in ids {
                    bytes.extend_from_slice(id.as_bytes());
                }
            }
        }
        bytes.push(0xff);
    }
    for target in projection.stand_down_targets() {
        bytes.extend_from_slice(b"stand_down:");
        bytes.extend_from_slice(target.to_string().as_bytes());
        if let Some(stand_down) = projection.stand_down(target) {
            bytes.extend_from_slice(stand_down.proof.as_bytes());
        }
        bytes.push(0xfe);
    }
    let digest = Sha256::digest(bytes);
    let mut commitment = [0; 32];
    commitment.copy_from_slice(&digest);
    commitment
}

fn identity(graph: &FactGraph) -> IdentitySnapshot {
    let fact_ids = graph.ids().copied().collect::<Vec<_>>();
    let unresolved_fact_ids = graph.quarantined().map(|(id, _)| *id).collect::<Vec<_>>();
    let admitted_fact_count =
        u64::try_from(fact_ids.len()).expect("admitted count fits production transcript");
    let unresolved_fact_count = u64::try_from(unresolved_fact_ids.len())
        .expect("unresolved count fits production transcript");
    let mut hasher = Sha256::new();
    hasher.update(b"myownmesh-semantic-state-v2\0context\0");
    hasher.update(graph.context_id().as_bytes());
    hasher.update(b"\0admitted-count\0");
    hasher.update(admitted_fact_count.to_le_bytes());
    hasher.update(b"\0admitted\0");
    for fact_id in &fact_ids {
        hasher.update(fact_id.as_bytes());
        let fact = graph.get(fact_id).expect("admitted fact remains present");
        hasher.update(serde_json::to_vec(fact).expect("fact serializes"));
        hasher.update([0]);
    }
    hasher.update(b"\0unresolved-count\0");
    hasher.update(unresolved_fact_count.to_le_bytes());
    hasher.update(b"\0unresolved\0");
    for fact_id in &unresolved_fact_ids {
        hasher.update(fact_id.as_bytes());
        let fact = graph
            .quarantined()
            .find(|(id, _)| **id == *fact_id)
            .map(|(_, fact)| fact)
            .expect("unresolved fact remains present");
        hasher.update(serde_json::to_vec(fact).expect("unresolved fact serializes"));
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    let mut state_commitment = [0; 32];
    state_commitment.copy_from_slice(&digest);
    IdentitySnapshot {
        context_id: graph.context_id(),
        admitted_fact_count,
        unresolved_fact_count,
        projection_commitment: projection_commitment(&graph.projection()),
        state_commitment,
    }
}

fn snapshot(graph: &FactGraph, subjects: &[DeviceId]) -> GraphSnapshot {
    let mut canonical_graph = graph
        .ids()
        .map(|id| {
            (
                *id,
                true,
                graph
                    .get(id)
                    .expect("admitted fact")
                    .content
                    .canonical_bytes(),
            )
        })
        .collect::<Vec<_>>();
    canonical_graph.extend(
        graph
            .quarantined()
            .map(|(id, fact)| (*id, false, fact.content.canonical_bytes())),
    );
    canonical_graph.sort_by_key(|(id, _, _)| *id);
    let cells = graph
        .ids()
        .filter_map(|id| graph.get(id))
        .flat_map(|fact| fact.content.body.exclusive_cells())
        .collect::<BTreeSet<_>>();
    let conflict_heads = cells
        .into_iter()
        .map(|cell| {
            let heads = graph.conflict_heads(&cell);
            (cell, heads)
        })
        .collect();
    let authority_heads = subjects
        .iter()
        .cloned()
        .map(|subject| {
            let heads = graph.authority_use_heads(&subject);
            (subject, heads)
        })
        .collect();
    GraphSnapshot {
        identity: identity(graph),
        canonical_graph,
        projection: graph.projection(),
        authority_heads,
        conflict_heads,
    }
}

fn config(id: &str, network_id: &str, kind: NetworkKind) -> NetworkConfig {
    NetworkConfig {
        id: id.to_string(),
        network_id: network_id.to_string(),
        event_capacity: 256,
        connection_trace_capacity: 512,
        label: id.to_string(),
        kind,
        semantic_policy: Default::default(),
        routing_policy: RoutingPolicyConfig::default(),
        scheduler: Default::default(),
        topology: TopologyMode::FullMesh,
        signaling: SignalingConfig {
            strategy: "none".to_string(),
            mdns: false,
            ..SignalingConfig::default()
        },
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        pinned_peers: Vec::new(),
        auto_approve: false,
        closed_relay: ClosedRelayPolicyConfig::default(),
    }
}

fn connector_policy() -> WebRtcConnectorCapablePolicy {
    let grant = ResourceClaim::try_from_entries(ResourceClass::ALL.into_iter().map(|class| {
        let amount = if class == ResourceClass::StorageBytes {
            256 * 1024 * 1024
        } else {
            100_000_000
        };
        (class, amount)
    }))
    .expect("finite semantic differential grant");
    let resources = ResourceProviderPort::new(FiniteResourceProvider::new(grant))
        .expect("finite semantic differential provider");
    WebRtcConnectorCapablePolicy::new(
        resources,
        WebRtcConnectorProfile::new(ConnectorCallbackPolicy::elastic_data_only()),
    )
}

fn one_fact_page(
    context_id: myownmesh_core::semantic::MeshContextId,
    fact: &SignedFact,
) -> myownmesh_core::semantic::SemanticFactPage {
    serde_json::from_value(serde_json::json!({
        "context_id": context_id,
        "facts": [fact],
        "next_cursor": null,
        "complete": true,
    }))
    .expect("public serde one-fact page remains canonical")
}

async fn import_one(
    network: &myownmesh_core::JoinedNetwork,
    context_id: myownmesh_core::semantic::MeshContextId,
    fact: &SignedFact,
) -> myownmesh_core::Result<()> {
    network
        .import_semantic_fact_page(one_fact_page(context_id, fact))
        .await?;
    Ok(())
}

async fn export_facts(
    network: &myownmesh_core::JoinedNetwork,
    bootstrap: &VerifiedBootstrap,
) -> myownmesh_core::Result<Vec<SignedFact>> {
    const MAX_EXPORT_PAGES: usize = 65_536;
    const MAX_ENCODED_BYTES: u32 =
        myownmesh_core::protocol::relay::CLOSED_RELAY_WEBRTC_CALLBACK_BYTES as u32;
    let mut cursor = None;
    let mut facts = Vec::new();
    let mut pages = 0usize;
    loop {
        pages += 1;
        assert!(
            pages <= MAX_EXPORT_PAGES,
            "semantic export exceeded page bound"
        );
        let page = network.export_semantic_fact_page(
            myownmesh_core::semantic::SemanticFactPageRequest {
                context_id: bootstrap.context_id(),
                cursor,
                max_facts: 64,
                max_encoded_bytes: MAX_ENCODED_BYTES,
            },
        )?;
        facts.extend(page.facts().iter().cloned());
        if page.is_complete() {
            break;
        }
        let next_cursor = page.next_cursor().expect("incomplete page has a cursor");
        assert!(
            cursor.map_or(true, |previous| next_cursor > previous),
            "incomplete page cursor must advance strictly"
        );
        cursor = Some(next_cursor);
    }
    Ok(facts)
}

fn fresh_oracle(bootstrap: &VerifiedBootstrap, transcript: &[SignedFact]) -> FactGraph {
    let mut graph = FactGraph::from_bootstrap(bootstrap);
    for fact in transcript {
        admit(&mut graph, fact.clone());
    }
    graph
}

fn graph_from_exported_facts(bootstrap: &VerifiedBootstrap, facts: &[SignedFact]) -> FactGraph {
    let mut graph = FactGraph::from_bootstrap(bootstrap);
    for fact in facts {
        admit(&mut graph, fact.clone());
    }
    graph
}

fn durable_fact_bytes(facts: &[SignedFact]) -> Vec<(FactId, Vec<u8>)> {
    let mut bytes = facts
        .iter()
        .map(|fact| (fact.id, fact.content.canonical_bytes()))
        .collect::<Vec<_>>();
    bytes.sort_by_key(|(id, _)| *id);
    bytes
}

async fn assert_open_presence_zero(
    network: &myownmesh_core::JoinedNetwork,
    bootstrap: &VerifiedBootstrap,
    expected: &GraphSnapshot,
    expected_bytes: &[(FactId, Vec<u8>)],
) -> myownmesh_core::Result<()> {
    let observed = export_facts(network, bootstrap).await?;
    let observed_graph = graph_from_exported_facts(bootstrap, &observed);
    let observed_snapshot = snapshot(&observed_graph, &[]);
    assert_eq!(
        observed_snapshot, *expected,
        "Open lifecycle presence does not create semantic identity, facts, quarantine, or proof state"
    );
    assert_eq!(
        durable_fact_bytes(&observed),
        expected_bytes,
        "Open lifecycle presence does not create durable fact bytes"
    );
    let production_identity = network.semantic_state_identity()?;
    assert_eq!(
        production_identity.context_id(),
        expected.identity.context_id,
        "Open lifecycle preserves semantic context identity"
    );
    assert_eq!(
        production_identity.admitted_fact_count(),
        expected.identity.admitted_fact_count,
        "Open lifecycle preserves admitted fact count"
    );
    assert_eq!(
        production_identity.unresolved_fact_count(),
        expected.identity.unresolved_fact_count,
        "Open lifecycle preserves quarantine count"
    );
    assert_eq!(
        production_identity.projection_commitment(),
        expected.identity.projection_commitment,
        "Open lifecycle preserves proof/projection commitment"
    );
    assert_eq!(
        production_identity.state_commitment(),
        expected.identity.state_commitment,
        "Open lifecycle preserves durable state commitment"
    );
    Ok(())
}

async fn assert_equal(
    network: &myownmesh_core::JoinedNetwork,
    scenario: &Scenario,
    transcript: &[SignedFact],
) -> myownmesh_core::Result<()> {
    let expected = fresh_oracle(&scenario.bootstrap, transcript);
    let observed = export_facts(network, &scenario.bootstrap).await?;
    let observed_graph = graph_from_exported_facts(&scenario.bootstrap, &observed);
    let expected_snapshot = snapshot(&expected, &scenario.subjects);
    let production_identity = network.semantic_state_identity()?;
    assert_eq!(
        production_identity.context_id(),
        expected_snapshot.identity.context_id,
        "semantic context identity"
    );
    assert_eq!(
        production_identity.admitted_fact_count(),
        expected_snapshot.identity.admitted_fact_count,
        "admitted fact count"
    );
    assert_eq!(
        production_identity.unresolved_fact_count(),
        expected_snapshot.identity.unresolved_fact_count,
        "unresolved fact count"
    );
    assert_eq!(
        production_identity.projection_commitment(),
        expected_snapshot.identity.projection_commitment,
        "exact projection commitment"
    );
    assert_eq!(
        production_identity.state_commitment(),
        expected_snapshot.identity.state_commitment,
        "exact state commitment"
    );
    let expected_bytes = expected_snapshot
        .canonical_graph
        .iter()
        .map(|(id, _, bytes)| (*id, bytes.clone()))
        .collect::<Vec<_>>();
    let mut observed_bytes = observed
        .iter()
        .map(|fact| (fact.id, fact.content.canonical_bytes()))
        .collect::<Vec<_>>();
    observed_bytes.sort_by_key(|(id, _)| *id);
    assert_eq!(
        observed_bytes, expected_bytes,
        "exact exported canonical graph"
    );
    assert_eq!(
        production_identity.admitted_fact_count() + production_identity.unresolved_fact_count(),
        u64::try_from(observed.len()).expect("exported count fits u64"),
        "production identity counts cover every exported fact"
    );
    assert_eq!(
        &expected_snapshot.projection,
        &expected.projection(),
        "batch oracle projection is canonical"
    );
    for (subject, heads) in &expected_snapshot.authority_heads {
        assert_eq!(
            heads,
            &expected.authority_use_heads(subject),
            "batch oracle AuthorityLineage heads are canonical"
        );
    }
    for (cell, heads) in &expected_snapshot.conflict_heads {
        assert_eq!(
            heads,
            &expected.conflict_heads(cell),
            "batch oracle conflict classification is canonical"
        );
    }
    for subject in &scenario.subjects {
        assert_eq!(
            observed_graph.admits_policy_session(&scenario.bootstrap, &scenario.local, subject),
            expected.admits_policy_session(&scenario.bootstrap, &scenario.local, subject),
            "roster admission is the canonical projection for {subject}"
        );
    }
    Ok(())
}

async fn run_closed_order(
    mesh: &myownmesh_core::MeshHandle,
    order: &[usize],
    ordinal: usize,
) -> myownmesh_core::Result<()> {
    let network_id = format!("semantic-differential-closed-{ordinal}");
    let scenario = closed_scenario(&network_id, mesh.identity().signing_key());
    let network = mesh
        .create_network(
            config(&network_id, &network_id, NetworkKind::Closed),
            [0x41; 32],
        )
        .await?;
    let mut transcript = Vec::new();
    assert_equal(&network, &scenario, &transcript).await?;
    for (prefix, index) in order.iter().copied().enumerate() {
        transcript.push(scenario.facts[index].clone());
        import_one(
            &network,
            scenario.bootstrap.context_id(),
            &scenario.facts[index],
        )
        .await?;
        assert_equal(&network, &scenario, &transcript).await?;
        let before_duplicate = network.semantic_state_identity()?;
        let before_duplicate_facts = export_facts(&network, &scenario.bootstrap).await?;
        import_one(
            &network,
            scenario.bootstrap.context_id(),
            &scenario.facts[index],
        )
        .await?;
        assert_eq!(
            network.semantic_state_identity()?,
            before_duplicate,
            "duplicate production admission does not change semantic identity"
        );
        assert_eq!(
            export_facts(&network, &scenario.bootstrap).await?,
            before_duplicate_facts,
            "duplicate production admission does not churn the canonical ledger"
        );
        if prefix == order.len() / 2 - 1 {
            network.compact_semantic_state()?;
            assert_equal(&network, &scenario, &transcript).await?;
            transcript.push(scenario.continuation.clone());
            import_one(
                &network,
                scenario.bootstrap.context_id(),
                &scenario.continuation,
            )
            .await?;
            assert_equal(&network, &scenario, &transcript).await?;
        }
    }
    network.compact_semantic_state()?;
    assert_equal(&network, &scenario, &transcript).await?;
    network.shutdown().await?;
    let network = mesh
        .join(config(&network_id, &network_id, NetworkKind::Closed))
        .await?;
    assert_equal(&network, &scenario, &transcript).await?;
    let before = network.semantic_state_identity()?;
    assert!(
        network
            .import_semantic_fact_page(one_fact_page(
                scenario.bootstrap.context_id(),
                &scenario.foreign,
            ))
            .await
            .is_err(),
        "foreign-context future input is refused before mutation"
    );
    let after = network.semantic_state_identity()?;
    assert_eq!(after.context_id(), before.context_id());
    assert_eq!(after.admitted_fact_count(), before.admitted_fact_count());
    assert_eq!(
        after.unresolved_fact_count(),
        before.unresolved_fact_count()
    );
    assert_eq!(
        after.projection_commitment(),
        before.projection_commitment()
    );
    assert_eq!(after.state_commitment(), before.state_commitment());
    network.shutdown().await
}

async fn run_open_presence_zero(
    mesh: &myownmesh_core::MeshHandle,
    ordinal: usize,
) -> myownmesh_core::Result<()> {
    let network_id = format!("semantic-presence-open-{ordinal}");
    let bootstrap = VerifiedBootstrap::open(&network_id).expect("open bootstrap");
    let baseline_graph = FactGraph::from_bootstrap(&bootstrap);
    let baseline = snapshot(&baseline_graph, &[]);
    let baseline_bytes = baseline
        .canonical_graph
        .iter()
        .map(|(id, _, bytes)| (*id, bytes.clone()))
        .collect::<Vec<_>>();
    let network = mesh
        .join(config(&network_id, &network_id, NetworkKind::Open))
        .await?;
    assert_open_presence_zero(&network, &bootstrap, &baseline, &baseline_bytes).await?;

    // These are the production lifecycle operations: reconnect is a
    // scheduling request, while announce_leave publishes ephemeral presence.
    network.reconnect(None);
    network.announce_leave().await;
    assert_open_presence_zero(&network, &bootstrap, &baseline, &baseline_bytes).await?;
    network.shutdown().await?;

    // Rejoining the same Open network is the restart boundary.  Its durable
    // semantic owner must still be the empty graph, regardless of prior
    // presence transitions.
    let restarted = mesh
        .join(config(&network_id, &network_id, NetworkKind::Open))
        .await?;
    assert_open_presence_zero(&restarted, &bootstrap, &baseline, &baseline_bytes).await?;
    restarted.reconnect(None);
    restarted.announce_leave().await;
    assert_open_presence_zero(&restarted, &bootstrap, &baseline, &baseline_bytes).await?;
    restarted.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn semantic_project_and_incremental_compaction_converge() -> myownmesh_core::Result<()> {
    let home = tempfile::tempdir().expect("semantic differential home");
    std::env::set_var("MYOWNMESH_HOME", home.path());
    let identity = Arc::new(Identity::ephemeral());
    let mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        identity,
        connector_policy(),
    )
    .await?;

    let closed_orders = [
        [0, 1, 2, 3, 4, 5],
        [5, 4, 3, 2, 1, 0],
        [1, 0, 3, 2, 5, 4],
        [2, 0, 4, 1, 5, 3],
        [3, 1, 5, 0, 4, 2],
    ];
    for (ordinal, order) in closed_orders.iter().enumerate() {
        run_closed_order(&mesh, order, ordinal).await?;
    }
    run_open_presence_zero(&mesh, 0).await?;
    Ok(())
}
