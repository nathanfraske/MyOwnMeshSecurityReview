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
    .expect("projection authoring witness fact signs")
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
        .admit(resolution.clone())
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

#[test]
fn recursive_resolution_selects_a_terminal_head() {
    let signing_key = key(14);
    let bootstrap = bootstrap(14, 14);
    let subject = author(&key(15));
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
            role: Role::Controller,
        },
        Vec::new(),
    );
    let cell = ExclusiveCell::role(subject.clone());
    let mut graph = FactGraph::from_bootstrap(&bootstrap);
    graph.admit(first.clone()).expect("first role head admits");
    graph
        .admit(second.clone())
        .expect("second role head admits");

    let mut first_heads = graph.cell_heads(&cell);
    first_heads.sort();
    let first_resolution = fact(
        &bootstrap,
        &signing_key,
        FactBody::Resolution {
            cell: cell.clone(),
            cited_heads: first_heads.clone(),
            selected_head: first.id,
        },
        first_heads,
    );
    graph
        .admit(first_resolution.clone())
        .expect("first complete resolution admits");

    let third = fact(
        &bootstrap,
        &signing_key,
        FactBody::RoleGrant {
            target: subject.clone(),
            role: Role::Member,
        },
        vec![first.id],
    );
    graph.admit(third).expect("independent successor admits");
    let mut nested_heads = graph.cell_heads(&cell);
    nested_heads.sort();
    let nested_resolution = fact(
        &bootstrap,
        &signing_key,
        FactBody::Resolution {
            cell: cell.clone(),
            cited_heads: nested_heads.clone(),
            selected_head: first_resolution.id,
        },
        nested_heads,
    );
    graph
        .admit(nested_resolution)
        .expect("recursive complete resolution admits");
    assert_eq!(graph.projection().value(&cell), Some(first.id));
}

#[test]
fn stale_recursive_resolution_fails_closed() {
    let signing_key = key(16);
    let bootstrap = bootstrap(16, 16);
    let subject = author(&key(17));
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
            role: Role::Controller,
        },
        Vec::new(),
    );
    let cell = ExclusiveCell::role(subject.clone());
    let mut graph = FactGraph::from_bootstrap(&bootstrap);
    graph.admit(first.clone()).expect("first role head admits");
    graph
        .admit(second.clone())
        .expect("second role head admits");
    let mut heads = graph.cell_heads(&cell);
    heads.sort();
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
    graph.admit(resolution).expect("complete resolution admits");
    let third = fact(
        &bootstrap,
        &signing_key,
        FactBody::RoleGrant {
            target: subject.clone(),
            role: Role::Member,
        },
        vec![first.id],
    );
    let third_id = third.id;
    graph.admit(third).expect("new competing branch admits");

    let mut stale_heads = vec![first.id, second.id];
    stale_heads.sort();
    // Carry the later branch into the candidate causal past while retaining
    // the obsolete cited-head set.  Without this parent, candidate-relative
    // resolution correctly cannot observe `third` and the fixture is valid.
    let mut stale_parents = vec![first.id, second.id, third_id];
    stale_parents.sort();
    let stale = fact(
        &bootstrap,
        &signing_key,
        FactBody::Resolution {
            cell: cell.clone(),
            cited_heads: stale_heads.clone(),
            selected_head: second.id,
        },
        stale_parents,
    );
    assert_eq!(
        graph.admit(stale),
        Err(myownmesh_core::semantic::SemanticError::ResolutionNotCurrent)
    );
    assert!(graph.projection().is_conflicted(&cell));
    assert_eq!(graph.projection().value(&cell), None);
}

#[test]
fn resolution_requires_owner_for_owner_tier_but_controller_can_resolve_member_tier() {
    let root_key = key(20);
    let controller_key = key(21);
    let bootstrap = bootstrap(20, 20);
    let controller = author(&controller_key);
    let subject = author(&key(22));
    let mut graph = FactGraph::from_bootstrap(&bootstrap);
    let controller_grant = authored(
        &graph,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    graph
        .admit(controller_grant.clone())
        .expect("controller grant admits");
    let member = authored(
        &graph,
        &root_key,
        FactBody::RoleGrant {
            target: subject.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    graph.admit(member.clone()).expect("member head admits");

    let mut controller_graph = graph.clone();
    let controller_head = fact(
        &bootstrap,
        &root_key,
        FactBody::RoleGrant {
            target: subject.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    controller_graph
        .admit(controller_head.clone())
        .expect("controller-tier head admits");

    let cell = ExclusiveCell::role(subject.clone());
    let controller_resolution = authored(
        &controller_graph,
        &controller_key,
        FactBody::Resolution {
            cell: cell.clone(),
            cited_heads: vec![member.id, controller_head.id],
            selected_head: member.id,
        },
        vec![controller_grant.id],
    );
    controller_graph
        .admit(controller_resolution)
        .expect("controller resolves controller-tier candidates");
    assert_eq!(controller_graph.projection().value(&cell), Some(member.id));

    let owner = fact(
        &bootstrap,
        &root_key,
        FactBody::RoleGrant {
            target: subject.clone(),
            role: Role::Owner,
        },
        Vec::new(),
    );
    graph.admit(owner.clone()).expect("owner head admits");

    let controller_owner_resolution = authored(
        &graph,
        &controller_key,
        FactBody::Resolution {
            cell: cell.clone(),
            cited_heads: vec![member.id, owner.id],
            selected_head: owner.id,
        },
        vec![controller_grant.id],
    );
    assert_eq!(
        graph.admit(controller_owner_resolution),
        Err(myownmesh_core::semantic::SemanticError::UnauthorizedRoleGrant)
    );
    let owner_resolution = authored(
        &graph,
        &root_key,
        FactBody::Resolution {
            cell: cell.clone(),
            cited_heads: vec![member.id, owner.id],
            selected_head: owner.id,
        },
        Vec::new(),
    );
    graph
        .admit(owner_resolution)
        .expect("owner resolves an owner-tier value");
    assert_eq!(graph.projection().value(&cell), Some(owner.id));
}

#[test]
fn controller_can_resolve_member_revoke_using_its_candidate_causal_tier() {
    let root_key = key(28);
    let controller_key = key(29);
    let bootstrap = bootstrap(28, 28);
    let controller = author(&controller_key);
    let subject = author(&key(30));
    let unrelated_target = author(&key(31));
    let controller_grant = fact(
        &bootstrap,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    let member_a = fact(
        &bootstrap,
        &root_key,
        FactBody::RoleGrant {
            target: subject.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let unrelated = fact(
        &bootstrap,
        &root_key,
        FactBody::RoleGrant {
            target: unrelated_target,
            role: Role::Member,
        },
        Vec::new(),
    );
    let member_b = fact(
        &bootstrap,
        &root_key,
        FactBody::RoleGrant {
            target: subject.clone(),
            role: Role::Member,
        },
        vec![unrelated.id],
    );
    let revoke = fact(
        &bootstrap,
        &controller_key,
        FactBody::RoleRevoke {
            target: subject.clone(),
        },
        vec![controller_grant.id, member_a.id],
    );
    let mut graph = FactGraph::from_bootstrap(&bootstrap);
    for candidate in [
        controller_grant.clone(),
        member_a.clone(),
        unrelated.clone(),
        member_b.clone(),
    ] {
        graph
            .admit(candidate)
            .expect("independent predecessor admits");
    }
    graph
        .admit(revoke.clone())
        .expect("controller can revoke the causal Member head");
    let mut cited = vec![revoke.id, member_b.id];
    cited.sort();
    let resolution = authored(
        &graph,
        &controller_key,
        FactBody::Resolution {
            cell: ExclusiveCell::role(subject.clone()),
            cited_heads: cited,
            selected_head: revoke.id,
        },
        vec![controller_grant.id],
    );
    graph
        .admit(resolution.clone())
        .expect("controller resolves revoke plus concurrent Member sibling");
    assert_eq!(
        graph.evaluator().effective_role(&subject),
        None,
        "the selected revoke remains authority-negative"
    );

    let mut permuted = FactGraph::from_bootstrap(&bootstrap);
    for candidate in [controller_grant, unrelated, member_b, member_a, revoke] {
        permuted
            .admit(candidate)
            .expect("permuted predecessor order admits");
    }
    permuted
        .admit(resolution)
        .expect("permuted graph admits the same resolution");
    assert_eq!(permuted.projection(), graph.projection());
}

#[test]
fn authoring_witness_supports_controller_to_member_demotion() {
    let root_key = key(23);
    let controller_key = key(24);
    let bootstrap = bootstrap(23, 23);
    let controller = author(&controller_key);
    let mut graph = FactGraph::from_bootstrap(&bootstrap);
    let grant = authored(
        &graph,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    graph.admit(grant).expect("controller grant admits");
    assert_eq!(
        graph.evaluator().effective_role(&controller),
        Some(Role::Controller)
    );

    let demotion = authored(
        &graph,
        &controller_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    graph.admit(demotion).expect("controller demotion admits");
    assert_eq!(
        graph.evaluator().effective_role(&controller),
        Some(Role::Member)
    );
}
