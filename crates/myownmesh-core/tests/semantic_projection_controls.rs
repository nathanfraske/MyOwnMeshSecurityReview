#![cfg(feature = "transport-lab")]

//! Projection and conflict controls for the V4 semantic owner.

use ed25519_dalek::SigningKey;

use myownmesh_core::protocol::FactBundleMessage;
use myownmesh_core::semantic::{
    Admission, AttestationDecision, CellProjection, DeviceId, ExclusiveCell, FactBody, FactContent,
    FactGraph, FactId, Role, SignedFact, VerifiedBootstrap,
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

fn authored_with_sorted_support(
    graph: &FactGraph,
    key: &SigningKey,
    body: FactBody,
    support: Vec<FactId>,
) -> SignedFact {
    let author = author(key);
    let witness = graph.authoring_witness(&body, &author);
    let mut content = FactContent::from_authoring_witness(graph, body, &witness, support);
    content.parents.sort();
    content.parents.dedup();
    SignedFact::sign(content, key).expect("projection redundant-support fact signs")
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
fn finite_authority_fork_projection_converges_for_every_arrival_permutation() {
    let root_key = key(114);
    let controller_key = key(115);
    let target = author(&key(116));
    let future_target = author(&key(117));
    let bootstrap = bootstrap(114, 114);
    let controller = author(&controller_key);
    let mut source = FactGraph::from_bootstrap(&bootstrap);

    let grant = authored(
        &source,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    source
        .admit(grant.clone())
        .expect("G controller grant admits");
    let operation = authored(
        &source,
        &controller_key,
        FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let revoke = authored(
        &source,
        &root_key,
        FactBody::RoleRevoke {
            target: controller.clone(),
        },
        Vec::new(),
    );
    let mut fork = source.clone();
    fork.admit(operation.clone()).expect("O operation admits");
    fork.admit(revoke.clone()).expect("R revoke admits");
    let resolution = authored(
        &fork,
        &root_key,
        FactBody::AuthorityLineageResolution {
            subject: controller.clone(),
            cited_heads: vec![operation.id, revoke.id],
            selected_head: revoke.id,
        },
        Vec::new(),
    );
    fork.admit(resolution.clone())
        .expect("Q selects the revoke branch");
    let regrant = authored(
        &fork,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    fork.admit(regrant.clone()).expect("N regrant admits");
    let future = authored(
        &fork,
        &controller_key,
        FactBody::RoleGrant {
            target: future_target.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );

    let candidates = [grant, operation, revoke, resolution, regrant, future];
    let mut expected = None;
    let mut order = [0, 1, 2, 3, 4, 5];
    let mut orders = Vec::new();
    fn permutations(order: &mut [usize; 6], start: usize, output: &mut Vec<[usize; 6]>) {
        if start == order.len() {
            output.push(*order);
            return;
        }
        for index in start..order.len() {
            order.swap(start, index);
            permutations(order, start + 1, output);
            order.swap(start, index);
        }
    }
    permutations(&mut order, 0, &mut orders);
    assert_eq!(
        orders.len(),
        720,
        "the control covers every arrival permutation"
    );

    for permutation in orders {
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        for index in permutation {
            assert!(matches!(
                graph.admit(candidates[index].clone()),
                Ok(Admission::Inserted | Admission::Quarantined { .. })
            ));
        }
        graph
            .retry_quarantined()
            .expect("all finite causal dependencies eventually resolve");
        assert!(graph.quarantined().next().is_none());
        assert_eq!(graph.ids().count(), candidates.len());
        assert_eq!(
            graph.evaluator().effective_role(&controller),
            Some(Role::Controller)
        );
        assert_eq!(
            graph.evaluator().effective_role(&future_target),
            Some(Role::Member)
        );
        assert_eq!(
            graph.evaluator().effective_role(&target),
            None,
            "the losing O branch never regains authority"
        );
        assert_eq!(
            graph
                .projection()
                .value(&ExclusiveCell::role(controller.clone())),
            Some(candidates[4].id)
        );
        if let Some(previous) = &expected {
            assert_eq!(graph.projection(), *previous);
        } else {
            expected = Some(graph.projection());
        }
    }
}

#[test]
fn cross_cell_payload_resolution_preserves_authority_fork_in_any_arrival_order() {
    let root_key = key(118);
    let controller_key = key(119);
    let bootstrap = bootstrap(118, 118);
    let controller = author(&controller_key);
    let target = author(&key(120));
    let mut source = FactGraph::from_bootstrap(&bootstrap);

    let grant = authored(
        &source,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    source
        .admit(grant.clone())
        .expect("G controller grant admits");
    let operation = authored(
        &source,
        &controller_key,
        FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let revoke = authored(
        &source,
        &root_key,
        FactBody::RoleRevoke {
            target: controller.clone(),
        },
        Vec::new(),
    );
    let mut fork = source.clone();
    fork.admit(operation.clone())
        .expect("O controller operation admits");
    fork.admit(revoke.clone()).expect("R root revoke admits");
    let authority_heads = fork.authority_use_heads(&controller);
    assert_eq!(
        authority_heads.len(),
        2,
        "G/O/R establishes the concurrent AuthorityUse fork before the payload"
    );

    // This payload cites the exact AuthorityUse(C) fork but resolves a
    // different exclusive cell. It must not turn O into a selected authority
    // branch or make O's RoleGrant(X) effective.
    let membership_resolution = authored(
        &fork,
        &root_key,
        FactBody::Resolution {
            cell: ExclusiveCell::membership(controller.clone()),
            cited_heads: authority_heads,
            selected_head: operation.id,
        },
        Vec::new(),
    );
    let candidates = [grant, operation, revoke];
    let mut order = [0, 1, 2];
    let mut orders = Vec::new();
    fn permutations(order: &mut [usize; 3], start: usize, output: &mut Vec<[usize; 3]>) {
        if start == order.len() {
            output.push(*order);
            return;
        }
        for index in start..order.len() {
            order.swap(start, index);
            permutations(order, start + 1, output);
            order.swap(start, index);
        }
    }
    permutations(&mut order, 0, &mut orders);
    assert_eq!(
        orders.len(),
        6,
        "the control covers every G/O/R arrival order"
    );

    let mut expected = None;
    for permutation in orders {
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        for index in permutation {
            assert!(matches!(
                graph.admit(candidates[index].clone()),
                Ok(Admission::Inserted | Admission::Quarantined { .. })
            ));
        }
        graph
            .retry_quarantined()
            .expect("G/O/R dependencies eventually resolve");
        assert!(graph.quarantined().next().is_none());
        assert_eq!(graph.ids().count(), candidates.len());

        // Attempt the exact same cross-cell payload only after every G/O/R
        // fact is present. Rejection here is intentionally distinct from a
        // missing-parent quarantine: a complete AuthorityUse fork still
        // cannot be resolved through Membership(C).
        assert_eq!(
            graph.admit(membership_resolution.clone()),
            Err(myownmesh_core::semantic::SemanticError::IncompleteResolution),
            "Membership(C) payload resolution is rejected after the fork is complete"
        );
        assert_eq!(
            graph.ids().count(),
            3,
            "rejected cross-cell payload does not enter the canonical graph"
        );
        assert_eq!(
            graph.authority_lineage(&controller).heads().len(),
            2,
            "every arrival order preserves the unresolved AuthorityUse(C) fork"
        );
        assert_eq!(
            graph.authority_lineage(&controller).selected_branch(),
            None,
            "Membership(C) cannot select an AuthorityUse(C) branch"
        );
        assert_eq!(
            graph.evaluator().effective_role(&controller),
            None,
            "the revoked controller remains inactive"
        );
        assert_eq!(
            graph.evaluator().effective_role(&target),
            None,
            "the losing O/RoleGrant(X) remains inactive"
        );
        if let Some(previous) = &expected {
            assert_eq!(graph.projection(), *previous);
        } else {
            expected = Some(graph.projection());
        }
    }
}

#[test]
fn second_order_payload_fork_converges_without_authority_join() {
    let root_key = key(128);
    let controller_key = key(129);
    let authority_a_key = key(130);
    let authority_d_key = key(131);
    let bootstrap = bootstrap(128, 128);
    let controller = author(&controller_key);
    let authority_a = author(&authority_a_key);
    let authority_d = author(&authority_d_key);
    let target = author(&key(132));
    let mut base = FactGraph::from_bootstrap(&bootstrap);

    let grant_controller = authored(
        &base,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    base.admit(grant_controller.clone())
        .expect("G controller grant admits");
    let grant_a = authored(
        &base,
        &root_key,
        FactBody::RoleGrant {
            target: authority_a.clone(),
            role: Role::Owner,
        },
        Vec::new(),
    );
    base.admit(grant_a).expect("A owner grant admits");
    let grant_d = authored(
        &base,
        &root_key,
        FactBody::RoleGrant {
            target: authority_d.clone(),
            role: Role::Owner,
        },
        Vec::new(),
    );
    base.admit(grant_d).expect("D owner grant admits");

    let operation = authored(
        &base,
        &controller_key,
        FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let revoke = authored(
        &base,
        &authority_a_key,
        FactBody::RoleRevoke {
            target: controller.clone(),
        },
        Vec::new(),
    );
    let membership = authored(
        &base,
        &authority_d_key,
        FactBody::MembershipAdmit {
            target: controller.clone(),
        },
        Vec::new(),
    );
    let evict = authored(
        &base,
        &authority_d_key,
        FactBody::Evict {
            target: controller.clone(),
        },
        Vec::new(),
    );
    let mut fork = base.clone();
    for branch in [
        operation.clone(),
        revoke.clone(),
        membership.clone(),
        evict.clone(),
    ] {
        fork.admit(branch)
            .expect("concurrent second-order branch admits");
    }
    let mut authority_heads = fork.authority_use_heads(&controller);
    authority_heads.sort();
    assert_eq!(authority_heads.len(), 4);
    let membership_cell = ExclusiveCell::membership(controller.clone());
    let mut payload_heads = fork.cell_heads(&membership_cell);
    payload_heads.sort();
    assert_eq!(payload_heads.len(), 2);
    assert!(payload_heads.contains(&membership.id));
    assert!(payload_heads.contains(&evict.id));
    let membership_resolution = authored(
        &fork,
        &root_key,
        FactBody::Resolution {
            cell: membership_cell,
            cited_heads: payload_heads,
            selected_head: evict.id,
        },
        Vec::new(),
    );

    let candidates = [operation, revoke, membership, evict, membership_resolution];
    let mut order = [0, 1, 2, 3, 4];
    let mut orders = Vec::new();
    fn permutations(order: &mut [usize; 5], start: usize, output: &mut Vec<[usize; 5]>) {
        if start == order.len() {
            output.push(*order);
            return;
        }
        for index in start..order.len() {
            order.swap(start, index);
            permutations(order, start + 1, output);
            order.swap(start, index);
        }
    }
    permutations(&mut order, 0, &mut orders);
    assert_eq!(
        orders.len(),
        120,
        "the control covers every O/R/M/E/Q arrival permutation"
    );

    let mut expected_q_admitted = None;
    let mut expected_projection = None;
    for permutation in orders {
        let mut graph = base.clone();
        for index in permutation {
            assert!(matches!(
                graph.admit(candidates[index].clone()),
                Ok(Admission::Inserted | Admission::Quarantined { .. })
            ));
        }
        let retry = graph.retry_quarantined();
        assert!(matches!(
            retry,
            Ok(_) | Err(myownmesh_core::semantic::SemanticError::IncompleteResolution)
        ));
        assert!(graph.quarantined().next().is_none());
        let q_admitted = graph.get(&candidates[4].id).is_some();
        if let Some(previous) = expected_q_admitted {
            assert_eq!(q_admitted, previous);
        } else {
            expected_q_admitted = Some(q_admitted);
        }
        assert_eq!(
            graph.ids().count(),
            7 + usize::from(q_admitted),
            "only Q's explicit safe/rejected outcome varies the admitted count"
        );
        assert!(graph
            .projection()
            .is_conflicted(&ExclusiveCell::role(controller.clone())));
        assert_eq!(
            graph.evaluator().effective_role(&controller),
            None,
            "C remains revoked/conflicted"
        );
        assert_eq!(
            graph.evaluator().effective_role(&target),
            None,
            "the O/RoleGrant(X) branch remains inactive"
        );
        assert_eq!(
            graph.authority_lineage(&controller).selected_branch(),
            None,
            "Q never invents an AuthorityUse(C) branch selection"
        );
        if !q_admitted {
            assert_eq!(graph.authority_use_heads(&controller).len(), 4);
        }
        if let Some(previous) = &expected_projection {
            assert_eq!(graph.projection(), *previous);
        } else {
            expected_projection = Some(graph.projection());
        }
    }
}

#[test]
fn self_authored_membership_resolution_is_order_independent_after_role_regrant() {
    let root_key = key(140);
    let controller_key = key(141);
    let future_target = author(&key(143));
    let bootstrap = bootstrap(140, 140);
    let controller = author(&controller_key);

    let mut source = FactGraph::from_bootstrap(&bootstrap);
    let grant = authored(
        &source,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    source.admit(grant).expect("G controller grant admits");

    let membership_m = authored(
        &source,
        &controller_key,
        FactBody::MembershipAdmit {
            target: controller.clone(),
        },
        Vec::new(),
    );
    let eviction_v = authored(
        &source,
        &root_key,
        FactBody::Evict {
            target: controller.clone(),
        },
        Vec::new(),
    );
    let mut fork = source.clone();
    fork.admit(membership_m.clone())
        .expect("M membership head admits");
    fork.admit(eviction_v.clone())
        .expect("V eviction head admits");
    let mut authority_heads = fork.authority_use_heads(&controller);
    authority_heads.sort();
    let mut expected_authority_heads = vec![membership_m.id, eviction_v.id];
    expected_authority_heads.sort();
    assert_eq!(authority_heads, expected_authority_heads);
    assert_eq!(fork.evaluator().effective_role(&controller), None);
    assert_eq!(fork.evaluator().effective_membership(&controller), None);
    let role_selection = authored(
        &fork,
        &root_key,
        FactBody::AuthorityLineageResolution {
            subject: controller.clone(),
            cited_heads: authority_heads,
            selected_head: eviction_v.id,
        },
        Vec::new(),
    );
    fork.admit(role_selection.clone())
        .expect("typed Role(C) selection of V admits");
    let regrant = authored(
        &fork,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Owner,
        },
        Vec::new(),
    );
    fork.admit(regrant.clone())
        .expect("causal Owner regrant admits");
    let post_n = fork.clone();

    let mut payload_heads = vec![membership_m.id, eviction_v.id];
    payload_heads.sort();
    let q = authored(
        &post_n,
        &controller_key,
        FactBody::Resolution {
            cell: ExclusiveCell::membership(controller.clone()),
            cited_heads: payload_heads,
            selected_head: membership_m.id,
        },
        Vec::new(),
    );
    let r = authored(
        &post_n,
        &root_key,
        FactBody::RoleRevoke {
            target: controller.clone(),
        },
        Vec::new(),
    );
    let q_id = q.id;
    let r_id = r.id;
    let mut settled = post_n.clone();
    settled
        .admit(q.clone())
        .expect("Q membership resolution admits");
    settled.admit(r.clone()).expect("R role revoke admits");
    let role_resolution = authored(
        &settled,
        &root_key,
        FactBody::AuthorityLineageResolution {
            subject: controller.clone(),
            cited_heads: vec![q_id, r_id],
            selected_head: r_id,
        },
        Vec::new(),
    );
    let mut after_selection = settled.clone();
    after_selection
        .admit(role_resolution.clone())
        .expect("typed Role(C) resolution over Q/R admits");
    let regrant_after_selection = authored(
        &after_selection,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Owner,
        },
        Vec::new(),
    );
    after_selection
        .admit(regrant_after_selection.clone())
        .expect("post-selection Owner regrant admits");
    let future = authored(
        &after_selection,
        &controller_key,
        FactBody::RoleGrant {
            target: future_target.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let candidates = [membership_m, eviction_v, role_selection, regrant, q, r];
    let mut expected_projection = None;
    let mut order = [0usize, 1, 2, 3, 4, 5];
    let mut orders = Vec::new();
    fn permutations(order: &mut [usize; 6], start: usize, output: &mut Vec<[usize; 6]>) {
        if start == order.len() {
            output.push(*order);
            return;
        }
        for index in start..order.len() {
            order.swap(start, index);
            permutations(order, start + 1, output);
            order.swap(start, index);
        }
    }
    permutations(&mut order, 0, &mut orders);
    assert_eq!(
        orders.len(),
        720,
        "all M/V/S/N/Q/R arrival orders are exercised"
    );

    for permutation in orders {
        let mut graph = source.clone();
        for index in permutation {
            assert!(matches!(
                graph.admit(candidates[index].clone()),
                Ok(Admission::Inserted | Admission::Quarantined { .. })
            ));
        }
        graph
            .retry_quarantined()
            .expect("all M/V/S/N/Q/R dependencies eventually resolve");
        assert!(graph.quarantined().next().is_none());
        assert_eq!(graph.ids().count(), source.len() + candidates.len());
        assert_eq!(
            graph.evaluator().effective_membership(&controller),
            None,
            "the Q/R AuthorityUse fork keeps Membership(C) fail-closed"
        );
        assert_eq!(
            graph.evaluator().effective_role(&controller),
            None,
            "concurrent R makes the final Role(C) effect fail closed"
        );
        assert_eq!(
            graph.authority_lineage(&controller).selected_branch(),
            None,
            "the concurrent Q/R fork has no selected Role(C) branch"
        );
        let mut authority_heads = graph.authority_use_heads(&controller);
        authority_heads.sort();
        let mut expected_authority_heads = vec![q_id, r_id];
        expected_authority_heads.sort();
        assert_eq!(authority_heads, expected_authority_heads);
        assert_eq!(
            graph
                .projection()
                .value(&ExclusiveCell::membership(controller.clone())),
            None,
            "Q cannot become the effective Membership(C) projection"
        );
        graph
            .admit(role_resolution.clone())
            .expect("typed Role(C) resolution selects R from the complete Q/R fork");
        assert_eq!(
            graph.authority_lineage(&controller).selected_branch(),
            Some(r_id),
            "the typed Role(C) resolution, not payload Q, selects R"
        );
        graph
            .admit(regrant_after_selection.clone())
            .expect("the causal post-selection Owner regrant admits");
        graph
            .admit(future.clone())
            .expect("post-regrant controller operation admits");
        assert_eq!(
            graph.evaluator().effective_role(&controller),
            Some(Role::Owner),
            "N restores C as Owner without reviving Q"
        );
        assert_eq!(
            graph.evaluator().effective_role(&future_target),
            Some(Role::Member),
            "the regranted Owner can author a future operation"
        );
        assert_eq!(
            graph.evaluator().effective_membership(&controller),
            None,
            "Q's membership restoration remains suppressed after regrant"
        );
        assert_eq!(
            graph
                .projection()
                .value(&ExclusiveCell::membership(controller.clone())),
            None,
            "Q remains suppressed after the post-selection regrant"
        );
        if let Some(previous) = &expected_projection {
            assert_eq!(graph.projection(), *previous);
        } else {
            expected_projection = Some(graph.projection());
        }
    }
}

#[test]
fn stale_selector_arrival_converges_with_distinct_owner_and_redundant_ancestor() {
    let root_key = key(160);
    let controller_key = key(161);
    let owner_a_key = key(162);
    let bootstrap = bootstrap(160, 160);
    let controller = author(&controller_key);

    let mut source = FactGraph::from_bootstrap(&bootstrap);
    let grant_controller = authored(
        &source,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    source
        .admit(grant_controller)
        .expect("controller grant admits");

    // T0 selects the old V branch.  M and V deliberately arrive as a fork;
    // neither branch is authoritative until a typed Role selector chooses it.
    let m = authored(
        &source,
        &controller_key,
        FactBody::MembershipAdmit {
            target: controller.clone(),
        },
        Vec::new(),
    );
    let v = authored(
        &source,
        &root_key,
        FactBody::Evict {
            target: controller.clone(),
        },
        Vec::new(),
    );
    let mut fork = source.clone();
    fork.admit(m.clone()).expect("M fork head admits");
    fork.admit(v.clone()).expect("V fork head admits");
    let mut old_heads = fork.authority_use_heads(&controller);
    old_heads.sort();
    let mut expected_old_heads = vec![m.id, v.id];
    expected_old_heads.sort();
    assert_eq!(old_heads, expected_old_heads);
    let t0 = authored(
        &fork,
        &root_key,
        FactBody::AuthorityLineageResolution {
            subject: controller.clone(),
            cited_heads: old_heads,
            selected_head: v.id,
        },
        Vec::new(),
    );
    fork.admit(t0.clone()).expect("T0 old selector admits");

    let regrant = authored(
        &fork,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Owner,
        },
        Vec::new(),
    );
    fork.admit(regrant.clone()).expect("causal regrant admits");
    let grant_owner_a = authored(
        &fork,
        &root_key,
        FactBody::RoleGrant {
            target: author(&owner_a_key),
            role: Role::Owner,
        },
        Vec::new(),
    );
    fork.admit(grant_owner_a.clone())
        .expect("distinct Owner A grant admits");

    // Q/R is the post-regrant fork.  Q is a payload selector for M, while R
    // is a role revoke.  They must not gain authority merely by arrival order.
    let mut payload_heads = vec![m.id, v.id];
    payload_heads.sort();
    let q = authored(
        &fork,
        &controller_key,
        FactBody::Resolution {
            cell: ExclusiveCell::membership(controller.clone()),
            cited_heads: payload_heads,
            selected_head: m.id,
        },
        Vec::new(),
    );
    let r = authored(
        &fork,
        &root_key,
        FactBody::RoleRevoke {
            target: controller.clone(),
        },
        Vec::new(),
    );
    let mut settled = fork.clone();
    settled.admit(q.clone()).expect("Q payload selector admits");
    settled.admit(r.clone()).expect("R role fork head admits");
    let mut qr_heads = settled.authority_use_heads(&controller);
    qr_heads.sort();
    let mut expected_qr_heads = vec![q.id, r.id];
    expected_qr_heads.sort();
    assert_eq!(qr_heads, expected_qr_heads);

    // T2 is signed by a distinct Owner and selects R.  U2 is a later root
    // regrant whose causal parents retain both the redundant R ancestor and
    // the exact T2 selector.
    // FactId is a SHA-256 digest, so the old traversal's first-hit order is
    // not implied by causality.  Choose from the finite 32 subsets of known
    // ancestors as redundant support; every option remains a valid signed
    // T2 with the same cell, cited heads, and selected R branch.
    let redundant_supports = [m.id, v.id, t0.id, regrant.id, grant_owner_a.id];
    let mut t2_options = Vec::new();
    for mask in 0u32..(1u32 << redundant_supports.len()) {
        let support = redundant_supports
            .iter()
            .enumerate()
            .filter_map(|(index, id)| ((mask & (1u32 << index)) != 0).then_some(*id))
            .collect();
        t2_options.push(authored_with_sorted_support(
            &settled,
            &owner_a_key,
            FactBody::AuthorityLineageResolution {
                subject: controller.clone(),
                cited_heads: qr_heads.clone(),
                selected_head: r.id,
            },
            support,
        ));
    }
    let t2 = t2_options
        .into_iter()
        .find(|candidate| r.id > candidate.id)
        .expect("bounded redundant support choices produce R > T2");
    assert!(
        r.id > t2.id,
        "R.id > T2.id makes the old first-hit traversal visit R first"
    );
    let mut after_t2 = settled.clone();
    after_t2
        .admit(t2.clone())
        .expect("T2 Owner A selector admits");
    let u2 = authored(
        &after_t2,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Owner,
        },
        vec![r.id],
    );
    assert!(
        u2.content.parents.contains(&r.id) && u2.content.parents.contains(&t2.id),
        "U2 retains the redundant R/T2 causal evidence"
    );

    let r_id = r.id;
    let candidates = [m, v, t0, regrant, grant_owner_a, q, r, t2, u2];
    let old_traversal_order = [0usize, 1, 2, 3, 4, 5, 6, 7, 8];
    let mut reference = source.clone();
    for index in old_traversal_order {
        assert!(matches!(
            reference.admit(candidates[index].clone()),
            Ok(Admission::Inserted | Admission::Quarantined { .. })
        ));
    }
    reference
        .retry_quarantined()
        .expect("old traversal-order counterfactual settles");
    assert!(reference.quarantined().next().is_none());
    assert_eq!(
        reference.authority_lineage(&controller).selected_branch(),
        Some(r_id),
        "the fixed traversal counterfactual selects R through T2"
    );
    assert_eq!(
        reference.evaluator().effective_membership(&controller),
        None,
        "Q/M is suppressed in the fixed traversal counterfactual"
    );
    let reference_projection = reference.projection();

    // These schedules cover causal, reverse, selector-first, fork-first, and
    // interleaved arrivals while keeping the control bounded at twelve runs.
    let schedules = [
        [0usize, 1, 2, 3, 4, 5, 6, 7, 8],
        [8, 7, 6, 5, 4, 3, 2, 1, 0],
        [2, 1, 0, 3, 6, 5, 4, 7, 8],
        [8, 6, 7, 5, 4, 3, 2, 1, 0],
        [1, 0, 4, 3, 2, 6, 5, 7, 8],
        [3, 2, 1, 0, 4, 5, 6, 7, 8],
        [6, 5, 4, 2, 1, 0, 7, 8, 3],
        [7, 8, 6, 5, 4, 3, 2, 1, 0],
        [4, 0, 2, 1, 8, 7, 6, 5, 3],
        [5, 6, 2, 3, 0, 1, 4, 7, 8],
        [8, 7, 3, 4, 5, 6, 2, 1, 0],
        [2, 3, 5, 6, 7, 8, 1, 0, 4],
    ];
    assert_eq!(schedules.len(), 12, "bounded meaningful arrival schedules");

    for schedule in schedules {
        let mut graph = source.clone();
        for index in schedule {
            assert!(matches!(
                graph.admit(candidates[index].clone()),
                Ok(Admission::Inserted | Admission::Quarantined { .. })
            ));
        }
        graph
            .retry_quarantined()
            .expect("quarantined dependencies converge to one projection");
        assert!(graph.quarantined().next().is_none());
        assert_eq!(graph.ids().count(), source.len() + candidates.len());
        assert_eq!(graph.projection(), reference_projection);
        assert_eq!(
            graph.authority_lineage(&controller).selected_branch(),
            Some(r_id),
            "T2 selects R regardless of arrival order"
        );
        assert_eq!(
            graph
                .projection()
                .value(&ExclusiveCell::membership(controller.clone())),
            None,
            "public projection does not select Q/M"
        );
        assert_eq!(
            graph.evaluator().effective_role(&controller),
            Some(Role::Owner),
            "public evaluator observes U2 while Q/M stays suppressed"
        );
        assert_eq!(
            graph.evaluator().effective_membership(&controller),
            None,
            "Q/M remains suppressed after the later U2 regrant"
        );
    }
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

#[test]
fn authority_lineage_selection_round_trips_and_regrant_is_future_only() {
    let root_key = key(230);
    let controller_key = key(231);
    let remote_key = key(232);
    let future_key = key(233);
    let bootstrap = bootstrap(230, 230);
    let controller = author(&controller_key);
    let remote = author(&remote_key);
    let future_target = author(&future_key);
    let role_cell = ExclusiveCell::role(controller.clone());

    let mut seed = FactGraph::from_bootstrap(&bootstrap);
    let controller_grant = authored(
        &seed,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    seed.admit(controller_grant.clone())
        .expect("controller grant admits");
    let membership = authored(
        &seed,
        &root_key,
        FactBody::MembershipAdmit {
            target: controller.clone(),
        },
        Vec::new(),
    );

    // Keep a pre-membership O/R fork solely for the ordinary-resolution
    // negatives below. Membership is an AuthorityUse(C) fact when admitted,
    // so it must not be introduced into that negative fixture.
    let negative_operation = authored(
        &seed,
        &controller_key,
        FactBody::RoleGrant {
            target: remote.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let negative_revoke = authored(
        &seed,
        &root_key,
        FactBody::RoleRevoke {
            target: controller.clone(),
        },
        Vec::new(),
    );
    let mut negative_fork = seed.clone();
    negative_fork
        .admit(negative_operation.clone())
        .expect("negative O role branch admits");
    negative_fork
        .admit(negative_revoke.clone())
        .expect("negative R role branch admits");
    let mut negative_heads = vec![negative_operation.id, negative_revoke.id];
    negative_heads.sort();
    assert_eq!(
        negative_fork.authority_use_heads(&controller),
        negative_heads
    );

    // A membership-cell Resolution cannot select an AuthorityUse(C) branch.
    // Construct it while the membership cell is still empty so the rejection
    // is specifically the ordinary Role-resolution separation, not a stale
    // membership head check.
    let cross_cell = authored(
        &negative_fork,
        &root_key,
        FactBody::Resolution {
            cell: ExclusiveCell::membership(controller.clone()),
            cited_heads: negative_heads.clone(),
            selected_head: negative_operation.id,
        },
        Vec::new(),
    );
    assert_eq!(
        negative_fork.admit(cross_cell),
        Err(myownmesh_core::semantic::SemanticError::IncompleteResolution),
        "only a typed AuthorityLineageResolution for C can select the AuthorityUse(C) fork"
    );
    let ordinary_role_selection = authored(
        &negative_fork,
        &root_key,
        FactBody::Resolution {
            cell: role_cell.clone(),
            cited_heads: negative_heads.clone(),
            selected_head: negative_operation.id,
        },
        Vec::new(),
    );
    assert_eq!(
        negative_fork.admit(ordinary_role_selection),
        Err(myownmesh_core::semantic::SemanticError::IncompleteResolution),
        "ordinary Role(C) resolution cannot select the cross-cell O lineage"
    );
    assert_eq!(
        negative_fork.authority_lineage(&controller).heads().len(),
        2,
        "ordinary Role(C) resolution leaves AuthorityLineage(C) unresolved"
    );
    assert_eq!(
        negative_fork
            .authority_lineage(&controller)
            .selected_branch(),
        None,
        "ordinary Role(C) resolution cannot collapse AuthorityLineage(C)"
    );

    // Admit membership first so it is a common ancestor of the positive O/R
    // fork rather than a third current AuthorityUse(C) head.
    let mut positive_seed = seed.clone();
    positive_seed
        .admit(membership.clone())
        .expect("membership common ancestor admits");
    let operation = authored(
        &positive_seed,
        &controller_key,
        FactBody::RoleGrant {
            target: remote.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let revoke = authored(
        &positive_seed,
        &root_key,
        FactBody::RoleRevoke {
            target: controller.clone(),
        },
        Vec::new(),
    );
    let mut fork = positive_seed.clone();
    fork.admit(operation.clone()).expect("O role branch admits");
    fork.admit(revoke.clone()).expect("R role branch admits");
    let mut expected_heads = vec![operation.id, revoke.id];
    expected_heads.sort();
    assert_eq!(fork.authority_use_heads(&controller), expected_heads);

    let selected_o = fork.clone();
    let resolution_o = authored(
        &selected_o,
        &root_key,
        FactBody::AuthorityLineageResolution {
            subject: controller.clone(),
            cited_heads: expected_heads.clone(),
            selected_head: operation.id,
        },
        Vec::new(),
    );
    let selected_r = fork.clone();
    let resolution_r = authored(
        &selected_r,
        &root_key,
        FactBody::AuthorityLineageResolution {
            subject: controller.clone(),
            cited_heads: expected_heads.clone(),
            selected_head: revoke.id,
        },
        Vec::new(),
    );

    for (selected, losing, resolution, expected_role) in [
        (operation.id, revoke.id, resolution_o, None),
        (revoke.id, operation.id, resolution_r, None),
    ] {
        let pre_resolution = fork.clone();
        let mut cited = expected_heads.clone();
        cited.sort();
        assert_eq!(
            pre_resolution.authority_lineage(&controller).heads(),
            cited.as_slice(),
            "the selector is built from the complete current AuthorityUse(C) set"
        );
        let FactBody::AuthorityLineageResolution {
            subject,
            cited_heads,
            selected_head,
        } = &resolution.content.body
        else {
            panic!("selector fixture must remain an AuthorityLineageResolution");
        };
        assert_eq!(subject, &controller);
        assert_eq!(cited_heads, &cited);
        assert_eq!(*selected_head, selected);
        let authority_use = resolution
            .content
            .authority_uses
            .iter()
            .find(|use_| use_.subject == controller)
            .expect("selector carries the controller AuthorityUse witness");
        assert_eq!(authority_use.predecessors, cited);

        let regrant = {
            let mut graph = pre_resolution.clone();
            graph
                .admit(resolution.clone())
                .expect("complete typed Role(C) resolution admits");
            authored(
                &graph,
                &root_key,
                FactBody::RoleGrant {
                    target: controller.clone(),
                    role: Role::Owner,
                },
                Vec::new(),
            )
        };
        let future = {
            let mut graph = pre_resolution.clone();
            graph
                .admit(resolution.clone())
                .expect("resolution admits for future witness");
            graph.admit(regrant.clone()).expect("regrant admits");
            authored(
                &graph,
                &controller_key,
                FactBody::RoleGrant {
                    target: future_target.clone(),
                    role: Role::Member,
                },
                Vec::new(),
            )
        };
        let candidates = vec![
            controller_grant.clone(),
            membership.clone(),
            operation.clone(),
            revoke.clone(),
            resolution.clone(),
            regrant.clone(),
            future.clone(),
        ];
        let wire = serde_json::to_vec(&FactBundleMessage { facts: candidates })
            .expect("durable semantic bundle serializes");
        let decoded: FactBundleMessage =
            serde_json::from_slice(&wire).expect("durable semantic bundle restores");
        assert_eq!(decoded.facts.len(), 7);

        let schedules = [
            [0usize, 1, 2, 3, 4],
            [4, 3, 2, 1, 0],
            [2, 0, 4, 1, 3],
            [3, 1, 0, 4, 2],
        ];
        let mut expected_base_projection = None;
        let mut expected_regrant_projection = None;
        let mut expected_projection = None;
        for schedule in schedules {
            let mut restarted = FactGraph::from_bootstrap(&bootstrap);
            for index in schedule {
                assert!(matches!(
                    restarted.admit(decoded.facts[index].clone()),
                    Ok(Admission::Inserted | Admission::Quarantined { .. })
                ));
            }
            restarted
                .retry_quarantined()
                .expect("restarted graph admits every durable dependency");
            assert!(restarted.quarantined().next().is_none());
            assert_eq!(restarted.ids().count(), 5);
            assert_eq!(
                restarted.evaluator().effective_role(&controller),
                expected_role,
                "selected O/R branch controls C's role"
            );
            assert_eq!(
                restarted.evaluator().effective_membership(&controller),
                Some(true),
                "role selection does not rewrite the independent membership cell"
            );
            assert_eq!(
                restarted
                    .evaluator()
                    .admits_closed_session(&controller, &remote),
                expected_role.is_some(),
                "Closed session admission follows role plus membership projection"
            );
            assert_eq!(
                restarted.authority_lineage(&controller).selected_branch(),
                Some(selected),
                "the typed selector remains attached after durable arrival"
            );
            assert!(
                restarted
                    .authority_lineage(&controller)
                    .selected_branch()
                    .is_some_and(|branch| branch != losing),
                "the losing AuthorityUse branch stays inactive"
            );
            let base_projection = restarted.projection();
            if let Some(previous) = &expected_base_projection {
                assert_eq!(base_projection, *previous);
            } else {
                expected_base_projection = Some(base_projection);
            }

            // The post-resolution regrant restores only future authority. It
            // must not change the selected branch or make the losing branch
            // effective merely because its FactId arrived earlier/later.
            restarted
                .admit(decoded.facts[5].clone())
                .expect("causal Owner regrant admits after restart");
            assert_eq!(restarted.ids().count(), 6);
            assert_eq!(
                restarted.evaluator().effective_role(&controller),
                Some(Role::Owner),
                "regrant restores current future authority at the boundary"
            );
            assert_eq!(
                restarted.authority_lineage(&controller).selected_branch(),
                Some(selected),
                "regrant preserves the typed selector at the boundary"
            );
            assert_eq!(
                restarted.projection().value(&role_cell),
                Some(decoded.facts[5].id),
                "the decoded regrant becomes the effective role-cell head"
            );
            let regrant_projection = restarted.projection();
            if let Some(previous) = &expected_regrant_projection {
                assert_eq!(regrant_projection, *previous);
            } else {
                expected_regrant_projection = Some(regrant_projection);
            }
            restarted
                .admit(decoded.facts[6].clone())
                .expect("future operation admits under the regrant");
            assert_eq!(restarted.ids().count(), 7);
            assert_eq!(
                restarted.evaluator().effective_role(&controller),
                Some(Role::Owner),
                "regrant restores current future authority"
            );
            assert_eq!(
                restarted.evaluator().effective_role(&future_target),
                Some(Role::Member)
            );
            assert_eq!(
                restarted.authority_lineage(&controller).selected_branch(),
                Some(selected),
                "regrant preserves the typed selector lineage"
            );
            assert_eq!(
                restarted.projection().value(&role_cell),
                Some(decoded.facts[5].id),
                "regrant is the effective role-cell head, not the losing branch"
            );
            if let Some(previous) = &expected_projection {
                assert_eq!(restarted.projection(), *previous);
            } else {
                expected_projection = Some(restarted.projection());
            }
        }
    }
}
