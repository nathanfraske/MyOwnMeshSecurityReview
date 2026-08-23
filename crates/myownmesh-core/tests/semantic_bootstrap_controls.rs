#![cfg(feature = "transport-lab")]

//! Bootstrap controls for the canonical V4 Semantic owner.

use ed25519_dalek::SigningKey;

use myownmesh_core::semantic::{
    FactBody, FactContent, FactDomain, FactGraph, GovernanceKind, SemanticError, SignedFact,
    VerifiedBootstrap,
};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn author(key: &SigningKey) -> String {
    data_encoding::BASE32_NOPAD
        .encode(key.verifying_key().as_bytes())
        .to_lowercase()
}

fn closed(seed: u8, creation_id: u8) -> VerifiedBootstrap {
    VerifiedBootstrap::create_closed("bootstrap-controls", vec![key(seed)], [creation_id; 32])
        .expect("closed bootstrap verifies")
}

fn fact(bootstrap: &VerifiedBootstrap, signing_key: &SigningKey) -> SignedFact {
    SignedFact::sign(
        FactContent::new(
            FactDomain::Governance,
            bootstrap.context_id().to_string(),
            FactBody::KindChange {
                to: GovernanceKind::Closed,
            },
            author(signing_key),
            Vec::new(),
        ),
        signing_key,
    )
    .expect("bootstrap fact signs")
}

#[test]
fn shared_bootstrap_context_is_required_by_every_graph() {
    let alice = closed(21, 1);
    let bob = VerifiedBootstrap::from_record(alice.record().clone()).expect("exact import");
    assert_eq!(alice.context_id(), bob.context_id());

    let signed = fact(&alice, &key(21));
    let mut alice_graph = FactGraph::from_bootstrap(&alice);
    let mut bob_graph = FactGraph::from_bootstrap(&bob);
    alice_graph
        .admit(signed.clone())
        .expect("Alice admits fact");
    bob_graph.admit(signed).expect("Bob admits exact fact");
    assert_eq!(alice_graph.context_id(), bob_graph.context_id());
    assert_eq!(alice_graph.projection(), bob_graph.projection());
}

#[test]
fn foreign_context_refuses_before_quarantine_or_projection() {
    let local = closed(22, 1);
    let foreign = closed(22, 2);
    let mut graph = FactGraph::from_bootstrap(&local);
    let result = graph.admit(fact(&foreign, &key(22)));
    assert!(matches!(result, Err(SemanticError::ContextMismatch { .. })));
    assert_eq!(graph.len(), 0);
    assert_eq!(graph.quarantined().count(), 0);
    assert!(graph.projection().cells().next().is_none());
}

#[test]
fn open_bootstrap_has_no_founder_and_only_self_participation() {
    let bootstrap = VerifiedBootstrap::open("bootstrap-controls").expect("open bootstrap");
    let signing_key = key(23);
    let device = data_encoding::BASE32_NOPAD
        .encode(signing_key.verifying_key().as_bytes())
        .to_lowercase();
    let participation = FactContent::open_participation(
        bootstrap.context_id().to_string(),
        device.clone(),
        true,
        "self",
        Vec::new(),
    );
    let mut graph = FactGraph::from_bootstrap(&bootstrap);
    graph
        .admit(SignedFact::sign(participation, &signing_key).expect("participation signs"))
        .expect("self-authored participation admits");
    assert!(!graph.is_authorized_signer(&device));
    assert_eq!(graph.context_id(), bootstrap.context_id());
}
