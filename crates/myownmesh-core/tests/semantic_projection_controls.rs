#![cfg(feature = "transport-lab")]

//! Projection and conflict controls for the V4 semantic owner.

use ed25519_dalek::SigningKey;

use myownmesh_core::semantic::{
    CellProjection, DeviceId, ExclusiveCell, FactBody, FactContent, FactGraph, FactId, Role,
    SignedFact, VerifiedBootstrap,
};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn author(key: &SigningKey) -> DeviceId {
    DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes()).expect("valid device id")
}

fn bootstrap(seed: u8, creation_id: u8) -> VerifiedBootstrap {
    VerifiedBootstrap::create_closed("projection-controls", vec![key(seed)], [creation_id; 32])
        .expect("projection bootstrap verifies")
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
    .expect("projection fixture fact signs")
}

#[test]
fn incomparable_heads_fail_closed_until_full_head_resolution() {
    let signing_key = key(11);
    let bootstrap = bootstrap(11, 11);
    let subject = author(&key(13));
    let first = fact(
        &bootstrap,
        &signing_key,
        FactBody::RoleGrant {
            target: subject.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let second = fact(
        &bootstrap,
        &signing_key,
        FactBody::RoleGrant {
            target: subject.clone(),
            role: Role::Owner,
        },
        Vec::new(),
    );
    let mut graph = FactGraph::from_bootstrap(&bootstrap);
    graph.admit(first.clone()).unwrap();
    graph.admit(second.clone()).unwrap();
    let cell = ExclusiveCell::role(subject.clone());
    assert!(graph.projection().is_conflicted(&cell));
    assert_eq!(graph.projection().value(&cell), None);

    let mut heads = graph.cell_heads(&cell);
    heads.sort();
    let incomplete = fact(
        &bootstrap,
        &signing_key,
        FactBody::Resolution {
            cell: cell.clone(),
            cited_heads: vec![heads[0]],
            selected_head: heads[0],
        },
        vec![heads[0]],
    );
    assert!(matches!(
        graph.admit(incomplete),
        Err(myownmesh_core::semantic::SemanticError::IncompleteResolution)
    ));

    let resolution = fact(
        &bootstrap,
        &signing_key,
        FactBody::Resolution {
            cell: cell.clone(),
            cited_heads: heads.clone(),
            selected_head: first.id,
        },
        heads,
    );
    graph
        .admit(resolution)
        .expect("full-head resolution admits");
    assert_eq!(graph.projection().value(&cell), Some(first.id));
    assert!(matches!(
        graph.projection().cell(&cell),
        Some(CellProjection::Value(id)) if *id == first.id
    ));
}

#[test]
fn conflict_projection_does_not_depend_on_arrival_order() {
    let signing_key = key(12);
    let bootstrap = bootstrap(12, 12);
    let subject = author(&key(13));
    let first = fact(
        &bootstrap,
        &signing_key,
        FactBody::RoleGrant {
            target: subject.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let second = fact(
        &bootstrap,
        &signing_key,
        FactBody::RoleGrant {
            target: subject.clone(),
            role: Role::Owner,
        },
        Vec::new(),
    );
    let mut left = FactGraph::from_bootstrap(&bootstrap);
    left.admit(first.clone()).unwrap();
    left.admit(second.clone()).unwrap();
    let mut right = FactGraph::from_bootstrap(&bootstrap);
    right.admit(second).unwrap();
    right.admit(first).unwrap();
    assert_eq!(left.projection(), right.projection());
    assert!(left
        .projection()
        .is_conflicted(&ExclusiveCell::role(subject)));
}
