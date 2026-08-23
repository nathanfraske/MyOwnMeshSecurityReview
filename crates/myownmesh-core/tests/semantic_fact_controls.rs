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
    let genesis = fact(
        &bootstrap,
        &signing_key,
        FactBody::RoleGrant {
            target: author(&signing_key),
            role: Role::Member,
        },
        Vec::new(),
    );
    let successor = fact(
        &bootstrap,
        &signing_key,
        FactBody::RoleRevoke {
            target: author(&signing_key),
        },
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
    let proposal = fact(
        &eviction_bootstrap,
        &signing_key,
        FactBody::Evict {
            target: device.clone(),
        },
        Vec::new(),
    );
    let attestation = fact(
        &eviction_bootstrap,
        &signing_key,
        FactBody::Attestation {
            target: device.clone(),
            proposal: proposal.id,
            decision: AttestationDecision::Evict,
            signer: device.clone(),
            contributions: Vec::new(),
        },
        vec![proposal.id],
    );
    let proof = fact(
        &eviction_bootstrap,
        &signing_key,
        FactBody::EvictionProof {
            target: device.clone(),
            evidence: vec![attestation.id],
        },
        vec![attestation.id],
    );
    let mut graph = FactGraph::from_bootstrap(&eviction_bootstrap);
    graph.admit(proposal).expect("eviction proposal admits");
    graph
        .admit(proof)
        .expect("eviction proof quarantines until evidence arrives");
    assert!(!graph.projection().is_stood_down(&device));
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
    assert!(graph.projection().is_stood_down(&device));
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
