#![cfg(feature = "transport-lab")]

//! Dedicated controls for the transport-independent V4 semantic owner.

use std::collections::HashMap;

use ed25519_dalek::SigningKey;

use myownmesh_core::protocol::FactBundleMessage;
use myownmesh_core::semantic::{
    Admission, AttestationDecision, DeviceId, FactBody, FactContent, FactDomain, FactGraph, FactId,
    Role, SemanticError, SignedFact, VerifiedBootstrap,
};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn author(key: &SigningKey) -> DeviceId {
    DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes()).expect("valid device id")
}

fn closed_bootstrap(seed: u8, creation_id: u8) -> VerifiedBootstrap {
    VerifiedBootstrap::create_closed("semantic-controls", vec![key(seed)], [creation_id; 32])
        .expect("semantic bootstrap verifies")
}

fn fact(
    bootstrap: &VerifiedBootstrap,
    key: &SigningKey,
    body: FactBody,
    parents: Vec<FactId>,
) -> SignedFact {
    let domain = body.domain();
    SignedFact::sign(
        FactContent::new(domain, bootstrap.context_id(), body, author(key), parents),
        key,
    )
    .expect("semantic fixture fact signs")
}

fn authored(
    graph: &FactGraph,
    key: &SigningKey,
    body: FactBody,
    support: Vec<FactId>,
) -> SignedFact {
    let author = author(key);
    let witness = graph.authoring_witness(&body, &author);
    SignedFact::sign(
        FactContent::from_authoring_witness(graph, body, &witness, support),
        key,
    )
    .expect("authoring witness fact signs")
}

#[test]
fn canonical_field_mutation_is_refused() {
    let signing_key = key(1);
    let bootstrap = closed_bootstrap(1, 1);
    let original_target = author(&key(8));
    let mutated_target = author(&key(9));
    let mut signed = fact(
        &bootstrap,
        &signing_key,
        FactBody::RoleGrant {
            target: original_target,
            role: Role::Member,
        },
        Vec::new(),
    );
    signed.content.body = FactBody::RoleGrant {
        target: mutated_target,
        role: Role::Member,
    };
    assert!(matches!(
        signed.verify(),
        Err(SemanticError::FactIdMismatch)
    ));
}

#[test]
fn wire_file_and_cache_round_trips_preserve_one_fact_identity() {
    let signing_key = key(2);
    let bootstrap = closed_bootstrap(2, 2);
    let signed = fact(
        &bootstrap,
        &signing_key,
        FactBody::RoleGrant {
            target: author(&signing_key),
            role: Role::Member,
        },
        Vec::new(),
    );
    let wire = serde_json::to_vec(&FactBundleMessage {
        facts: vec![signed.clone()],
    })
    .expect("fact bundle serializes");
    let decoded: FactBundleMessage = serde_json::from_slice(&wire).expect("fact bundle decodes");
    assert_eq!(decoded.facts[0], signed);
    assert_eq!(decoded.facts[0].id, signed.id);

    let file = tempfile::NamedTempFile::new().expect("semantic fixture file opens");
    std::fs::write(file.path(), &wire).expect("canonical bundle writes to file");
    let from_file: FactBundleMessage =
        serde_json::from_slice(&std::fs::read(file.path()).expect("canonical bundle reads"))
            .expect("canonical file bundle decodes");
    assert_eq!(from_file.facts[0], signed);

    let mut cache = HashMap::new();
    cache.insert(decoded.facts[0].id, decoded.facts[0].clone());
    assert_eq!(cache.get(&signed.id), Some(&signed));
}

#[test]
fn arrival_order_is_independent_and_missing_parents_quarantine() {
    let signing_key = key(3);
    let bootstrap = closed_bootstrap(3, 3);
    let target = author(&key(6));
    let genesis = fact(
        &bootstrap,
        &signing_key,
        FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let successor = fact(
        &bootstrap,
        &signing_key,
        FactBody::RoleRevoke { target },
        vec![genesis.id],
    );

    let mut graph = FactGraph::from_bootstrap(&bootstrap);
    assert!(matches!(
        graph.admit(successor.clone()),
        Ok(Admission::Quarantined { .. })
    ));
    assert_eq!(graph.len(), 0);
    assert_eq!(graph.quarantined().count(), 1);
    graph.admit(genesis.clone()).expect("genesis admits");
    assert_eq!(graph.retry_quarantined().unwrap(), vec![successor.id]);

    let mut reverse = FactGraph::from_bootstrap(&bootstrap);
    reverse
        .admit(genesis)
        .expect("genesis admits in reverse fixture");
    reverse
        .admit(successor)
        .expect("successor admits after parent");
    assert_eq!(graph.projection(), reverse.projection());
}

#[test]
fn open_participation_is_self_authored_and_eviction_proof_stands_down() {
    let signing_key = key(4);
    let bootstrap = VerifiedBootstrap::open("semantic-controls").expect("open bootstrap");
    let device = author(&signing_key);
    let participation =
        FactContent::open_participation(bootstrap.context_id(), device.clone(), true, Vec::new());
    let signed_participation =
        SignedFact::sign(participation, &signing_key).expect("participation signs");
    assert!(signed_participation.verify().is_ok());

    let invalid = FactContent::new(
        FactDomain::Participation,
        bootstrap.context_id(),
        FactBody::OpenParticipation {
            device_id: author(&key(6)),
            joined: true,
        },
        device.clone(),
        Vec::new(),
    );
    assert!(matches!(
        SignedFact::sign(invalid, &signing_key),
        Err(SemanticError::InvalidOpenAuthor)
    ));

    let open_graph = {
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph
            .admit(signed_participation)
            .expect("self-authored participation admits");
        graph
    };
    assert_eq!(open_graph.context_id(), bootstrap.context_id());

    let eviction_bootstrap = closed_bootstrap(4, 4);
    let eviction_target = author(&key(6));
    let mut graph = FactGraph::from_bootstrap(&eviction_bootstrap);
    let proposal = authored(
        &graph,
        &signing_key,
        FactBody::Evict {
            target: eviction_target.clone(),
        },
        Vec::new(),
    );
    graph
        .admit(proposal.clone())
        .expect("eviction proposal admits");
    let attestation = authored(
        &graph,
        &signing_key,
        FactBody::Attestation {
            target: eviction_target.clone(),
            proposal: proposal.id,
            decision: AttestationDecision::Evict,
            signer: device.clone(),
            contributions: Vec::new(),
        },
        Vec::new(),
    );
    let proof = authored(
        &graph,
        &signing_key,
        FactBody::EvictionProof {
            target: eviction_target.clone(),
            evidence: vec![attestation.id],
        },
        Vec::new(),
    );
    graph
        .admit(proof)
        .expect("eviction proof quarantines until evidence arrives");
    assert!(!graph.projection().is_stood_down(&eviction_target));
    graph
        .admit(attestation)
        .expect("eviction attestation admits");
    let cells_before_proof_retry = graph
        .projection()
        .cells()
        .map(|(cell, projection)| (cell.clone(), projection.clone()))
        .collect::<Vec<_>>();
    graph
        .retry_quarantined()
        .expect("eviction proof retries after evidence");
    assert!(graph.projection().is_stood_down(&eviction_target));
    let cells_after_proof_retry = graph
        .projection()
        .cells()
        .map(|(cell, projection)| (cell.clone(), projection.clone()))
        .collect::<Vec<_>>();
    assert!(
        cells_before_proof_retry == cells_after_proof_retry,
        "proof evidence cannot itself mutate an exclusive semantic cell"
    );
}

#[test]
fn attestation_mutation_and_forged_eviction_are_rejected() {
    let signing_key = key(5);
    let bootstrap = closed_bootstrap(5, 5);
    let device = author(&signing_key);
    let mut attestation = SignedFact::sign(
        FactContent::new(
            FactDomain::Governance,
            bootstrap.context_id(),
            FactBody::Attestation {
                target: device.clone(),
                proposal: FactId::from_bytes([8; 32]),
                decision: AttestationDecision::Approve,
                signer: device.clone(),
                contributions: Vec::new(),
            },
            device.clone(),
            Vec::new(),
        ),
        &signing_key,
    )
    .expect("attestation signs");
    attestation.content.body = FactBody::Attestation {
        target: device.clone(),
        proposal: FactId::from_bytes([8; 32]),
        decision: AttestationDecision::Reject,
        signer: device.clone(),
        contributions: Vec::new(),
    };
    assert!(matches!(
        attestation.verify(),
        Err(SemanticError::FactIdMismatch)
    ));

    let other_device = author(&key(6));
    let mismatched_eviction = FactContent::new(
        FactDomain::EvictionProof,
        bootstrap.context_id(),
        FactBody::SelfStandDown {
            device_id: other_device,
            evidence: vec![FactId::from_bytes([7; 32])],
        },
        author(&signing_key),
        Vec::new(),
    );
    assert!(matches!(
        SignedFact::sign(mismatched_eviction, &signing_key),
        Err(SemanticError::InvalidOpenAuthor)
    ));
}

#[test]
fn foreign_context_is_rejected_before_quarantine() {
    let signing_key = key(7);
    let local = closed_bootstrap(7, 1);
    let foreign = closed_bootstrap(7, 2);
    assert_ne!(local.context_id(), foreign.context_id());

    let foreign_fact = fact(
        &foreign,
        &signing_key,
        FactBody::RoleGrant {
            target: author(&signing_key),
            role: Role::Member,
        },
        Vec::new(),
    );
    let mut graph = FactGraph::from_bootstrap(&local);
    assert!(matches!(
        graph.admit(foreign_fact),
        Err(SemanticError::ContextMismatch { .. })
    ));
    assert_eq!(graph.len(), 0);
    assert_eq!(graph.quarantined().count(), 0);
}

#[test]
fn open_resolution_is_recursive_and_foreign_resolution_fails_closed() {
    let participant_key = key(18);
    let participant = author(&participant_key);
    let bootstrap =
        VerifiedBootstrap::open("semantic-open-resolution").expect("open bootstrap verifies");
    let cell = myownmesh_core::semantic::ExclusiveCell::open_participation(participant.clone());
    let joined = fact(
        &bootstrap,
        &participant_key,
        FactBody::OpenParticipation {
            device_id: participant.clone(),
            joined: true,
        },
        Vec::new(),
    );
    let left = fact(
        &bootstrap,
        &participant_key,
        FactBody::OpenParticipation {
            device_id: participant.clone(),
            joined: false,
        },
        Vec::new(),
    );
    let mut graph = FactGraph::from_bootstrap(&bootstrap);
    graph
        .admit(joined.clone())
        .expect("joined participation admits");
    graph
        .admit(left.clone())
        .expect("left participation admits");
    let mut heads = graph.cell_heads(&cell);
    heads.sort();
    let first_resolution = fact(
        &bootstrap,
        &participant_key,
        FactBody::Resolution {
            cell: cell.clone(),
            cited_heads: heads.clone(),
            selected_head: joined.id,
        },
        heads,
    );
    graph
        .admit(first_resolution.clone())
        .expect("self-authored Open resolution admits");

    let right = fact(
        &bootstrap,
        &participant_key,
        FactBody::OpenParticipation {
            device_id: participant.clone(),
            joined: false,
        },
        vec![joined.id],
    );
    graph.admit(right).expect("successor participation admits");
    let mut current_heads = graph.cell_heads(&cell);
    current_heads.sort();
    let foreign_key = key(19);
    let foreign_resolution = fact(
        &bootstrap,
        &foreign_key,
        FactBody::Resolution {
            cell: cell.clone(),
            cited_heads: current_heads.clone(),
            selected_head: first_resolution.id,
        },
        current_heads.clone(),
    );
    assert_eq!(
        graph.admit(foreign_resolution),
        Err(SemanticError::InvalidOpenAuthor)
    );

    let nested_resolution = fact(
        &bootstrap,
        &participant_key,
        FactBody::Resolution {
            cell: cell.clone(),
            cited_heads: current_heads.clone(),
            selected_head: first_resolution.id,
        },
        current_heads,
    );
    graph
        .admit(nested_resolution)
        .expect("recursive self-authored Open resolution admits");
    assert_eq!(
        graph.evaluator().effective_open_participation(&participant),
        Some(true)
    );
}

#[test]
fn authoring_witness_makes_ids_and_projection_arrival_order_independent() {
    let root_key = key(20);
    let bootstrap = closed_bootstrap(20, 20);
    let target = author(&key(21));
    let mut left = FactGraph::from_bootstrap(&bootstrap);
    let mut right = FactGraph::from_bootstrap(&bootstrap);

    let member_left = authored(
        &left,
        &root_key,
        FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let owner_left = authored(
        &left,
        &root_key,
        FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Owner,
        },
        Vec::new(),
    );
    let member_right = authored(
        &right,
        &root_key,
        FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let owner_right = authored(
        &right,
        &root_key,
        FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Owner,
        },
        Vec::new(),
    );
    assert_eq!(member_left.id, member_right.id);
    assert_eq!(owner_left.id, owner_right.id);

    left.admit(member_left).expect("member branch admits");
    left.admit(owner_left).expect("owner branch admits");
    right
        .admit(owner_right)
        .expect("reverse owner branch admits");
    right
        .admit(member_right)
        .expect("reverse member branch admits");
    assert_eq!(left.projection(), right.projection());
    assert!(left
        .projection()
        .is_conflicted(&myownmesh_core::semantic::ExclusiveCell::role(target)));
}

#[test]
fn missing_authority_predecessor_does_not_become_valid_after_late_grant() {
    let root_key = key(22);
    let controller_key = key(23);
    let bootstrap = closed_bootstrap(22, 22);
    let target = author(&key(24));
    let controller = author(&controller_key);
    let controller_grant = fact(
        &bootstrap,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    let stale = fact(
        &bootstrap,
        &controller_key,
        FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let mut graph = FactGraph::from_bootstrap(&bootstrap);
    assert_eq!(
        graph.admit(stale.clone()),
        Err(SemanticError::UnauthorizedRoleGrant)
    );
    graph
        .admit(controller_grant.clone())
        .expect("late controller grant admits");
    assert_eq!(graph.evaluator().effective_role(&target), None);
    assert_eq!(
        graph.admit(stale),
        Err(SemanticError::UnauthorizedRoleGrant)
    );

    let causally_supported = authored(
        &graph,
        &controller_key,
        FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Member,
        },
        vec![controller_grant.id],
    );
    graph
        .admit(causally_supported)
        .expect("supported controller grant admits");
    assert_eq!(
        graph.evaluator().effective_role(&target),
        Some(Role::Member)
    );
}

#[test]
fn causally_valid_operation_survives_revoke_arriving_first() {
    let root_key = key(25);
    let controller_key = key(26);
    let bootstrap = closed_bootstrap(25, 25);
    let controller = author(&controller_key);
    let target = author(&key(27));
    let controller_grant = fact(
        &bootstrap,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    let mut source = FactGraph::from_bootstrap(&bootstrap);
    source
        .admit(controller_grant.clone())
        .expect("controller grant admits");
    let earlier_operation = authored(
        &source,
        &controller_key,
        FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Member,
        },
        vec![controller_grant.id],
    );
    let later_revoke = authored(
        &source,
        &root_key,
        FactBody::RoleRevoke {
            target: controller.clone(),
        },
        Vec::new(),
    );

    let mut reverse = FactGraph::from_bootstrap(&bootstrap);
    assert!(matches!(
        reverse.admit(earlier_operation.clone()),
        Ok(Admission::Quarantined { .. })
    ));
    assert!(matches!(
        reverse.admit(later_revoke.clone()),
        Ok(Admission::Quarantined { .. })
    ));
    reverse
        .admit(controller_grant)
        .expect("shared causal predecessor admits");
    reverse
        .retry_quarantined()
        .expect("both causally supported operations retry");
    assert_eq!(
        reverse.evaluator().effective_role(&target),
        Some(Role::Member)
    );
    assert_eq!(reverse.evaluator().effective_role(&controller), None);
}
