#![cfg(feature = "transport-lab")]

//! Projection and conflict controls for the V4 semantic owner.

use ed25519_dalek::SigningKey;

use myownmesh_core::semantic::{
    AttestationDecision, CellProjection, DeviceId, ExclusiveCell, FactBody, FactContent, FactGraph,
    FactId, Role, SignedFact, VerifiedBootstrap,
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
fn effective_membership_restoration_supersedes_stand_down_in_any_arrival_order() {
    let root_key = key(72);
    let target = author(&key(73));
    let bootstrap = bootstrap(72, 72);
    let mut source = FactGraph::from_bootstrap(&bootstrap);
    let proposal = authored(
        &source,
        &root_key,
        FactBody::Evict {
            target: target.clone(),
        },
        Vec::new(),
    );
    source
        .admit(proposal.clone())
        .expect("eviction proposal admits");
    let attestation = authored(
        &source,
        &root_key,
        FactBody::Attestation {
            target: target.clone(),
            proposal: proposal.id,
            decision: AttestationDecision::Evict,
            signer: author(&root_key),
            contributions: Vec::new(),
        },
        Vec::new(),
    );
    source
        .admit(attestation.clone())
        .expect("eviction attestation admits");
    let proof = authored(
        &source,
        &root_key,
        FactBody::EvictionProof {
            target: target.clone(),
            evidence: vec![attestation.id],
        },
        Vec::new(),
    );
    source.admit(proof.clone()).expect("eviction proof admits");
    assert!(source.projection().is_stood_down(&target));
    let restoration = authored(
        &source,
        &root_key,
        FactBody::MembershipAdmit {
            target: target.clone(),
        },
        Vec::new(),
    );

    let mut permuted = FactGraph::from_bootstrap(&bootstrap);
    for candidate in [restoration.clone(), proof, attestation, proposal] {
        permuted
            .admit(candidate)
            .expect("out-of-order restoration dependencies quarantine safely");
    }
    permuted
        .retry_quarantined()
        .expect("restoration retries after every proof dependency arrives");
    assert!(
        !permuted.projection().is_stood_down(&target),
        "only the effective, proof-descending membership restoration clears stand-down"
    );
}

#[test]
fn incomparable_heads_fail_closed_until_full_head_resolution() {
    let root_key = key(11);
    let left_controller_key = key(12);
    let right_controller_key = key(13);
    let resolver_key = key(14);
    let bootstrap = bootstrap(11, 11);
    let subject = author(&key(15));
    let left_controller = author(&left_controller_key);
    let right_controller = author(&right_controller_key);
    let resolver = author(&resolver_key);
    let mut base = FactGraph::from_bootstrap(&bootstrap);
    let left_grant = authored(
        &base,
        &root_key,
        FactBody::RoleGrant {
            target: left_controller,
            role: Role::Controller,
        },
        Vec::new(),
    );
    base.admit(left_grant.clone()).unwrap();
    let right_grant = authored(
        &base,
        &root_key,
        FactBody::RoleGrant {
            target: right_controller,
            role: Role::Controller,
        },
        Vec::new(),
    );
    base.admit(right_grant.clone()).unwrap();
    let resolver_grant = authored(
        &base,
        &root_key,
        FactBody::RoleGrant {
            target: resolver,
            role: Role::Controller,
        },
        Vec::new(),
    );
    base.admit(resolver_grant.clone()).unwrap();
    let first = authored(
        &base,
        &left_controller_key,
        FactBody::RoleGrant {
            target: subject.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let second = authored(
        &base,
        &right_controller_key,
        FactBody::RoleGrant {
            target: subject.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    let mut graph = base.clone();
    graph.admit(first.clone()).unwrap();
    graph.admit(second.clone()).unwrap();
    let cell = ExclusiveCell::role(subject.clone());
    assert!(graph.projection().is_conflicted(&cell));
    assert_eq!(graph.projection().value(&cell), None);

    let mut heads = graph.cell_heads(&cell);
    heads.sort();
    let incomplete = fact(
        &bootstrap,
        &root_key,
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

    let resolution = authored(
        &graph,
        &resolver_key,
        FactBody::Resolution {
            cell: cell.clone(),
            cited_heads: heads.clone(),
            selected_head: first.id,
        },
        vec![resolver_grant.id],
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
fn authority_use_resolution_only_keeps_the_selected_subject_branch_effective() {
    let root_key = key(14);
    let member_controller_key = key(15);
    let controller_controller_key = key(16);
    let resolver_key = key(17);
    let bootstrap = bootstrap(14, 14);
    let subject = author(&key(18));
    let mut base = FactGraph::from_bootstrap(&bootstrap);
    let member_controller_grant = authored(
        &base,
        &root_key,
        FactBody::RoleGrant {
            target: author(&member_controller_key),
            role: Role::Controller,
        },
        Vec::new(),
    );
    base.admit(member_controller_grant)
        .expect("member signer grant admits");
    let controller_controller_grant = authored(
        &base,
        &root_key,
        FactBody::RoleGrant {
            target: author(&controller_controller_key),
            role: Role::Controller,
        },
        Vec::new(),
    );
    base.admit(controller_controller_grant)
        .expect("controller signer grant admits");
    let resolver_grant = authored(
        &base,
        &root_key,
        FactBody::RoleGrant {
            target: author(&resolver_key),
            role: Role::Controller,
        },
        Vec::new(),
    );
    base.admit(resolver_grant.clone())
        .expect("resolver grant admits");
    let member = authored(
        &base,
        &member_controller_key,
        FactBody::RoleGrant {
            target: subject.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let controller = authored(
        &base,
        &controller_controller_key,
        FactBody::RoleGrant {
            target: subject.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    let mut graph = base.clone();
    graph.admit(member.clone()).expect("member branch admits");
    graph
        .admit(controller.clone())
        .expect("controller branch admits");
    let mut heads = graph.cell_heads(&ExclusiveCell::role(subject.clone()));
    heads.sort();
    let resolution = authored(
        &graph,
        &resolver_key,
        FactBody::Resolution {
            cell: ExclusiveCell::role(subject.clone()),
            cited_heads: heads,
            selected_head: member.id,
        },
        vec![resolver_grant.id],
    );
    graph
        .admit(resolution)
        .expect("typed authority resolution admits");
    assert_eq!(
        graph.evaluator().effective_role(&subject),
        Some(Role::Member),
        "the selected AuthorityUse branch, not the losing controller fork, is effective"
    );
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
    let root_key = key(14);
    let first_controller_key = key(15);
    let second_controller_key = key(16);
    let resolver_key = key(17);
    let bootstrap = bootstrap(14, 14);
    let subject = author(&key(18));
    let mut base = FactGraph::from_bootstrap(&bootstrap);
    let first_controller_grant = authored(
        &base,
        &root_key,
        FactBody::RoleGrant {
            target: author(&first_controller_key),
            role: Role::Controller,
        },
        Vec::new(),
    );
    base.admit(first_controller_grant)
        .expect("first signer grant admits");
    let second_controller_grant = authored(
        &base,
        &root_key,
        FactBody::RoleGrant {
            target: author(&second_controller_key),
            role: Role::Controller,
        },
        Vec::new(),
    );
    base.admit(second_controller_grant)
        .expect("second signer grant admits");
    let resolver_grant = authored(
        &base,
        &root_key,
        FactBody::RoleGrant {
            target: author(&resolver_key),
            role: Role::Controller,
        },
        Vec::new(),
    );
    base.admit(resolver_grant.clone())
        .expect("resolver grant admits");
    let first = authored(
        &base,
        &first_controller_key,
        FactBody::RoleGrant {
            target: subject.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let second = authored(
        &base,
        &second_controller_key,
        FactBody::RoleGrant {
            target: subject.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    let cell = ExclusiveCell::role(subject.clone());
    let mut graph = base.clone();
    graph.admit(first.clone()).expect("first role head admits");
    graph
        .admit(second.clone())
        .expect("second role head admits");

    let mut first_heads = graph.cell_heads(&cell);
    first_heads.sort();
    let first_resolution = authored(
        &graph,
        &resolver_key,
        FactBody::Resolution {
            cell: cell.clone(),
            cited_heads: first_heads.clone(),
            selected_head: first.id,
        },
        vec![resolver_grant.id],
    );
    graph
        .admit(first_resolution.clone())
        .expect("first complete resolution admits");

    let mut successor_base = base.clone();
    successor_base
        .admit(first.clone())
        .expect("successor branch imports first head");
    successor_base
        .admit(second.clone())
        .expect("successor branch imports second head");
    let third = authored(
        &successor_base,
        &first_controller_key,
        FactBody::Resolution {
            cell: cell.clone(),
            cited_heads: vec![first.id, second.id],
            selected_head: first.id,
        },
        Vec::new(),
    );
    graph
        .admit(third)
        .expect("independent successor carries an explicit signer selection");
    let mut nested_heads = graph.cell_heads(&cell);
    nested_heads.sort();
    let nested_resolution = authored(
        &graph,
        &resolver_key,
        FactBody::Resolution {
            cell: cell.clone(),
            cited_heads: nested_heads.clone(),
            selected_head: first_resolution.id,
        },
        vec![resolver_grant.id],
    );
    graph
        .admit(nested_resolution)
        .expect("recursive complete resolution admits");
    assert_eq!(graph.projection().value(&cell), Some(first.id));
}

#[test]
fn stale_recursive_resolution_fails_closed() {
    let root_key = key(16);
    let first_controller_key = key(17);
    let second_controller_key = key(18);
    let resolver_key = key(19);
    let bootstrap = bootstrap(16, 16);
    let subject = author(&key(20));
    let mut base = FactGraph::from_bootstrap(&bootstrap);
    let first_controller_grant = authored(
        &base,
        &root_key,
        FactBody::RoleGrant {
            target: author(&first_controller_key),
            role: Role::Controller,
        },
        Vec::new(),
    );
    base.admit(first_controller_grant)
        .expect("first signer grant admits");
    let second_controller_grant = authored(
        &base,
        &root_key,
        FactBody::RoleGrant {
            target: author(&second_controller_key),
            role: Role::Controller,
        },
        Vec::new(),
    );
    base.admit(second_controller_grant)
        .expect("second signer grant admits");
    let resolver_grant = authored(
        &base,
        &root_key,
        FactBody::RoleGrant {
            target: author(&resolver_key),
            role: Role::Controller,
        },
        Vec::new(),
    );
    base.admit(resolver_grant.clone())
        .expect("resolver grant admits");
    let first = authored(
        &base,
        &first_controller_key,
        FactBody::RoleGrant {
            target: subject.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let second = authored(
        &base,
        &second_controller_key,
        FactBody::RoleGrant {
            target: subject.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    let cell = ExclusiveCell::role(subject.clone());
    let mut graph = base.clone();
    graph.admit(first.clone()).expect("first role head admits");
    graph
        .admit(second.clone())
        .expect("second role head admits");
    let mut heads = graph.cell_heads(&cell);
    heads.sort();
    let resolution = authored(
        &graph,
        &resolver_key,
        FactBody::Resolution {
            cell: cell.clone(),
            cited_heads: heads.clone(),
            selected_head: first.id,
        },
        vec![resolver_grant.id],
    );
    graph.admit(resolution).expect("complete resolution admits");
    let third = authored(
        &graph,
        &first_controller_key,
        FactBody::RoleGrant {
            target: subject.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let third_id = third.id;
    graph.admit(third).expect("new competing branch admits");

    let mut stale_heads = vec![first.id, second.id];
    stale_heads.sort();
    // Carry the later branch into the candidate causal past while retaining
    // the obsolete cited-head set.  Without this parent, candidate-relative
    // resolution correctly cannot observe `third` and the fixture is valid.
    let stale = authored(
        &graph,
        &resolver_key,
        FactBody::Resolution {
            cell: cell.clone(),
            cited_heads: stale_heads.clone(),
            selected_head: second.id,
        },
        vec![resolver_grant.id],
    );
    let live_value = graph.projection().value(&cell);
    assert_eq!(live_value, Some(third_id));
    assert_eq!(
        graph.admit(stale),
        Err(myownmesh_core::semantic::SemanticError::ResolutionNotCurrent)
    );
    assert_eq!(graph.projection().value(&cell), live_value);
    assert_eq!(
        graph.evaluator().effective_role(&subject),
        Some(Role::Member)
    );
}

#[test]
fn resolution_requires_owner_for_owner_tier_but_controller_can_resolve_member_tier() {
    let root_key = key(20);
    let controller_key = key(21);
    let member_owner_key = key(22);
    let owner_owner_key = key(23);
    let bootstrap = bootstrap(20, 20);
    let controller = author(&controller_key);
    let subject = author(&key(24));
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
    let member_controller_grant = authored(
        &graph,
        &root_key,
        FactBody::RoleGrant {
            target: author(&member_owner_key),
            role: Role::Controller,
        },
        Vec::new(),
    );
    graph
        .admit(member_controller_grant)
        .expect("member branch signer grant admits");
    let owner_controller_grant = authored(
        &graph,
        &root_key,
        FactBody::RoleGrant {
            target: author(&owner_owner_key),
            role: Role::Controller,
        },
        Vec::new(),
    );
    graph
        .admit(owner_controller_grant)
        .expect("owner branch signer grant admits");
    let base = graph.clone();
    let member = authored(
        &graph,
        &member_owner_key,
        FactBody::RoleGrant {
            target: subject.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    graph.admit(member.clone()).expect("member head admits");

    let mut controller_graph = base.clone();
    let controller_head = authored(
        &controller_graph,
        &owner_owner_key,
        FactBody::RoleGrant {
            target: subject.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    controller_graph
        .admit(controller_head.clone())
        .expect("controller-tier head admits");
    controller_graph
        .admit(member.clone())
        .expect("member branch imports into controller graph");

    let cell = ExclusiveCell::role(subject.clone());
    let mut controller_heads = controller_graph.cell_heads(&cell);
    controller_heads.sort();
    let controller_resolution = authored(
        &controller_graph,
        &controller_key,
        FactBody::Resolution {
            cell: cell.clone(),
            cited_heads: controller_heads,
            selected_head: member.id,
        },
        vec![controller_grant.id],
    );
    controller_graph
        .admit(controller_resolution)
        .expect("controller resolves controller-tier candidates");
    assert_eq!(controller_graph.projection().value(&cell), Some(member.id));

    let owner = authored(
        &base,
        &root_key,
        FactBody::RoleGrant {
            target: subject.clone(),
            role: Role::Owner,
        },
        Vec::new(),
    );
    graph.admit(owner.clone()).expect("owner head admits");
    let mut owner_heads = graph.cell_heads(&cell);
    owner_heads.sort();

    let controller_owner_resolution = authored(
        &graph,
        &controller_key,
        FactBody::Resolution {
            cell: cell.clone(),
            cited_heads: owner_heads.clone(),
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
            cited_heads: owner_heads,
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
    let member_a_key = key(31);
    let unrelated_key = key(32);
    let bootstrap = bootstrap(28, 28);
    let controller = author(&controller_key);
    let subject = author(&key(30));
    let unrelated_target = author(&key(34));
    let mut base = FactGraph::from_bootstrap(&bootstrap);
    let controller_grant = authored(
        &base,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    base.admit(controller_grant.clone())
        .expect("resolver grant admits");
    let member_a_grant = authored(
        &base,
        &root_key,
        FactBody::RoleGrant {
            target: author(&member_a_key),
            role: Role::Controller,
        },
        Vec::new(),
    );
    base.admit(member_a_grant.clone())
        .expect("member A signer grant admits");
    let unrelated_grant = authored(
        &base,
        &root_key,
        FactBody::RoleGrant {
            target: author(&unrelated_key),
            role: Role::Controller,
        },
        Vec::new(),
    );
    base.admit(unrelated_grant.clone())
        .expect("member B signer grant admits");
    let member_a = authored(
        &base,
        &member_a_key,
        FactBody::RoleGrant {
            target: subject.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let mut branch_b = base.clone();
    let unrelated = authored(
        &branch_b,
        &unrelated_key,
        FactBody::RoleGrant {
            target: unrelated_target.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    branch_b
        .admit(unrelated.clone())
        .expect("unrelated branch admits");
    let member_b = authored(
        &branch_b,
        &unrelated_key,
        FactBody::RoleGrant {
            target: subject.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let mut graph = base.clone();
    graph
        .admit(member_a.clone())
        .expect("member A branch admits");
    let revoke = authored(
        &graph,
        &controller_key,
        FactBody::RoleRevoke {
            target: subject.clone(),
        },
        Vec::new(),
    );
    graph
        .admit(revoke.clone())
        .expect("controller can revoke the causal Member head");
    graph
        .admit(unrelated.clone())
        .expect("unrelated branch admits");
    graph
        .admit(member_b.clone())
        .expect("concurrent Member sibling admits");
    let mut cited = graph.cell_heads(&ExclusiveCell::role(subject.clone()));
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
    for candidate in [
        controller_grant,
        member_a_grant,
        unrelated_grant,
        unrelated,
        member_b,
        member_a,
        revoke,
    ] {
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
