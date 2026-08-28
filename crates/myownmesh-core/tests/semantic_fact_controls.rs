#![cfg(feature = "transport-lab")]

//! Dedicated controls for the transport-independent V4 semantic owner.

use std::collections::HashMap;

use ed25519_dalek::SigningKey;

use myownmesh_core::protocol::FactBundleMessage;
use myownmesh_core::semantic::{
    Admission, AttestationDecision, DeviceId, ExclusiveCell, FactBody, FactContent, FactDomain,
    FactGraph, FactId, Role, SemanticError, SignedFact, VerifiedBootstrap,
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

fn fact_with_authority_predecessors(
    bootstrap: &VerifiedBootstrap,
    key: &SigningKey,
    body: FactBody,
    parents: Vec<FactId>,
    overrides: &[(DeviceId, Vec<FactId>)],
) -> SignedFact {
    let mut content = FactContent::new(
        body.domain(),
        bootstrap.context_id(),
        body,
        author(key),
        parents,
    );
    for authority_use in &mut content.authority_uses {
        if let Some((_, predecessors)) = overrides
            .iter()
            .find(|(subject, _)| subject == &authority_use.subject)
        {
            authority_use.predecessors = predecessors.clone();
        }
    }
    SignedFact::sign(content, key).expect("authority lineage fixture fact signs")
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
        Err(SemanticError::InvalidAuthorityUse)
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
fn ready_invalid_fact_does_not_starve_valid_sibling_in_either_arrival_order() {
    let root_key = key(63);
    let bad_key = key(64);
    let bootstrap = closed_bootstrap(63, 63);
    let genesis_target = author(&key(65));
    let good_target = author(&key(66));
    let genesis = fact(
        &bootstrap,
        &root_key,
        FactBody::RoleGrant {
            target: genesis_target,
            role: Role::Member,
        },
        Vec::new(),
    );
    let bad = fact(
        &bootstrap,
        &bad_key,
        FactBody::RoleGrant {
            target: good_target.clone(),
            role: Role::Member,
        },
        vec![genesis.id],
    );
    let good = fact_with_authority_predecessors(
        &bootstrap,
        &root_key,
        FactBody::RoleGrant {
            target: good_target.clone(),
            role: Role::Member,
        },
        vec![genesis.id],
        &[
            (author(&root_key), vec![genesis.id]),
            (good_target.clone(), vec![]),
        ],
    );

    for reverse_order in [false, true] {
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        if reverse_order {
            graph.admit(good.clone()).expect("good fact quarantines");
            graph.admit(bad.clone()).expect("bad fact quarantines");
        } else {
            graph.admit(bad.clone()).expect("bad fact quarantines");
            graph.admit(good.clone()).expect("good fact quarantines");
        }
        graph.admit(genesis.clone()).expect("genesis admits");
        assert_eq!(
            graph.retry_quarantined(),
            Err(SemanticError::UnauthorizedRoleGrant),
            "the rejected sibling remains observable without blocking valid work"
        );
        assert_eq!(
            graph.evaluator().effective_role(&good_target),
            Some(Role::Member)
        );
        assert_eq!(graph.quarantined().count(), 0);
    }
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
    graph
        .admit(attestation.clone())
        .expect("eviction attestation admits");
    let cells_before_proof = graph
        .projection()
        .cells()
        .map(|(cell, projection)| (cell.clone(), projection.clone()))
        .collect::<Vec<_>>();
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
        .expect("eviction proof admits after evidence");
    assert!(graph.projection().is_stood_down(&eviction_target));
    let cells_after_proof = graph
        .projection()
        .cells()
        .map(|(cell, projection)| (cell.clone(), projection.clone()))
        .collect::<Vec<_>>();
    assert!(
        cells_before_proof == cells_after_proof,
        "proof evidence does not mutate ordinary exclusive cells"
    );

    let restoration = authored(
        &graph,
        &signing_key,
        FactBody::MembershipAdmit {
            target: eviction_target.clone(),
        },
        Vec::new(),
    );
    assert!(
        restoration
            .content
            .parents
            .contains(&proof_id_for(&graph, &eviction_target)),
        "stand-down restoration must carry the active proof lineage"
    );
    graph.admit(restoration).expect("owner restoration admits");
    assert!(
        !graph.projection().is_stood_down(&eviction_target),
        "an effective causal MembershipAdmit supersedes stand-down evidence"
    );
}

fn proof_id_for(graph: &FactGraph, target: &DeviceId) -> FactId {
    graph
        .ids()
        .copied()
        .find(|id| {
            matches!(
                graph.get(id).map(|fact| &fact.content.body),
                Some(FactBody::EvictionProof { target: found, .. }) if found == target
            )
        })
        .expect("the graph contains the active eviction proof")
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
    let first_resolution = authored(
        &graph,
        &participant_key,
        FactBody::Resolution {
            cell: cell.clone(),
            cited_heads: heads.clone(),
            selected_head: joined.id,
        },
        Vec::new(),
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

    let nested_resolution = authored(
        &graph,
        &participant_key,
        FactBody::Resolution {
            cell: cell.clone(),
            cited_heads: current_heads.clone(),
            selected_head: first_resolution.id,
        },
        Vec::new(),
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
    assert_eq!(
        left.ids().copied().collect::<Vec<_>>(),
        right.ids().copied().collect::<Vec<_>>(),
        "the same signed branch set has identical accepted FactIds"
    );
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
fn stale_operation_is_explicit_but_arrival_order_independent() {
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

    source
        .admit(earlier_operation.clone())
        .expect("the operation is valid in its signed causal profile");
    source
        .admit(later_revoke.clone())
        .expect("the revoke admits after the shared controller grant");

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
    let retried = reverse
        .retry_quarantined()
        .expect("the same signed facts admit independent of delivery order");
    assert_eq!(
        retried
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        [earlier_operation.id, later_revoke.id]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
    );
    assert_eq!(
        source.ids().copied().collect::<Vec<_>>(),
        reverse.ids().copied().collect::<Vec<_>>(),
        "accepted FactIds are permutation-independent"
    );
    assert_eq!(source.projection(), reverse.projection());
    assert_eq!(reverse.evaluator().effective_role(&target), None);
    assert_eq!(reverse.evaluator().effective_role(&controller), None);
}

#[test]
fn omitted_concurrent_root_lineage_is_explicit_conflict_not_arrival_order_authority() {
    let root_key = key(67);
    let bootstrap = closed_bootstrap(67, 67);
    let root = author(&root_key);
    let mut graph = FactGraph::from_bootstrap(&bootstrap);
    let revoke = fact(
        &bootstrap,
        &root_key,
        FactBody::RoleRevoke {
            target: root.clone(),
        },
        Vec::new(),
    );
    graph
        .admit(revoke)
        .expect("root revoke advances its role cell");

    let omitted = fact(
        &bootstrap,
        &root_key,
        FactBody::RoleGrant {
            target: author(&key(68)),
            role: Role::Member,
        },
        Vec::new(),
    );
    graph
        .admit(omitted)
        .expect("a candidate-relative fork may be admitted without seeing the concurrent revoke");
    assert_eq!(graph.authority_use_heads(&root).len(), 2);
    assert_eq!(
        graph.evaluator().effective_role(&author(&key(68))),
        None,
        "the concurrent signed AuthorityUse fork fails closed"
    );
}

#[test]
fn signed_authority_use_omission_is_rejected_when_the_candidate_cites_a_predecessor() {
    let root_key = key(74);
    let controller_key = key(75);
    let bootstrap = closed_bootstrap(74, 74);
    let controller = author(&controller_key);
    let target = author(&key(76));
    let mut graph = FactGraph::from_bootstrap(&bootstrap);
    let grant = fact(
        &bootstrap,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    graph.admit(grant.clone()).expect("controller grant admits");
    let honest = authored(
        &graph,
        &controller_key,
        FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let mut malformed_content = honest.content.clone();
    malformed_content
        .authority_uses
        .iter_mut()
        .find(|use_| use_.subject == controller)
        .expect("author AuthorityUse is present")
        .predecessors
        .clear();
    let malformed = SignedFact::sign(malformed_content, &controller_key)
        .expect("malformed content remains internally signed");
    assert_eq!(
        graph.admit(malformed),
        Err(SemanticError::UnauthorizedRoleGrant),
        "the candidate must carry the exact signed authority predecessor"
    );

    let mut supersets_content = honest.content.clone();
    supersets_content
        .authority_uses
        .iter_mut()
        .find(|use_| use_.subject == target)
        .expect("target AuthorityUse is present")
        .predecessors = vec![grant.id];
    let supersets = SignedFact::sign(supersets_content, &controller_key)
        .expect("superset content remains internally signed");
    assert_eq!(
        graph.admit(supersets),
        Err(SemanticError::UnauthorizedRoleGrant),
        "an authority predecessor superset cannot smuggle unrelated lineage"
    );
}

#[test]
fn authority_use_fork_requires_explicit_typed_selection_across_arrival_orders() {
    let root_key = key(77);
    let controller_key = key(78);
    let bootstrap = closed_bootstrap(77, 77);
    let controller = author(&controller_key);
    let target = author(&key(79));
    let later_target = author(&key(80));

    let mut seeded = FactGraph::from_bootstrap(&bootstrap);
    let grant_controller = authored(
        &seeded,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    seeded
        .admit(grant_controller.clone())
        .expect("the controller grant admits");

    let operation = authored(
        &seeded,
        &controller_key,
        FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let revoke = authored(
        &seeded,
        &root_key,
        FactBody::RoleRevoke {
            target: controller.clone(),
        },
        Vec::new(),
    );

    let mut forward = seeded.clone();
    forward
        .admit(operation.clone())
        .expect("the controller branch admits");
    forward
        .admit(revoke.clone())
        .expect("the root revoke branch admits");
    let mut reverse = seeded;
    reverse
        .admit(revoke.clone())
        .expect("the root revoke branch admits first");
    reverse
        .admit(operation.clone())
        .expect("the controller branch admits second");

    assert_eq!(
        forward.authority_use_heads(&controller),
        reverse.authority_use_heads(&controller),
        "the concurrent AuthorityUse(C) fork is independent of arrival order"
    );
    assert_eq!(
        forward.evaluator().effective_role(&target),
        None,
        "an unresolved AuthorityUse fork cannot authorize the controller branch"
    );
    assert_eq!(forward.projection(), reverse.projection());

    let later = fact(
        &bootstrap,
        &controller_key,
        FactBody::RoleGrant {
            target: later_target.clone(),
            role: Role::Member,
        },
        vec![operation.id, revoke.id],
    );
    assert_eq!(
        forward.admit(later),
        Err(SemanticError::UnauthorizedRoleGrant),
        "an ordinary later fact cannot resolve or revive the fork"
    );

    let mut malformed = FactContent::new(
        FactDomain::Governance,
        bootstrap.context_id(),
        FactBody::RoleGrant {
            target: later_target,
            role: Role::Member,
        },
        controller.clone(),
        vec![operation.id, revoke.id],
    );
    malformed
        .authority_uses
        .iter_mut()
        .find(|use_| use_.subject == controller)
        .expect("the direct candidate carries AuthorityUse(C)")
        .predecessors = vec![operation.id];
    let malformed = SignedFact::sign(malformed, &controller_key)
        .expect("the malicious candidate remains internally signed");
    assert_eq!(
        reverse.admit(malformed),
        Err(SemanticError::UnauthorizedRoleGrant),
        "direct FactContent construction cannot omit the competing predecessor"
    );

    let make_selection = |graph: &FactGraph, selected_head| {
        authored(
            graph,
            &root_key,
            FactBody::Resolution {
                cell: ExclusiveCell::role(controller.clone()),
                cited_heads: vec![operation.id, revoke.id],
                selected_head,
            },
            Vec::new(),
        )
    };
    let selection_operation = make_selection(&forward, operation.id);
    let selection_operation_reverse = make_selection(&reverse, operation.id);
    assert_eq!(
        selection_operation.id, selection_operation_reverse.id,
        "typed AuthorityUse selection has one identity in either arrival order"
    );
    forward
        .admit(selection_operation)
        .expect("the typed selection of the controller branch admits");
    assert_eq!(
        forward.evaluator().effective_role(&target),
        Some(Role::Member),
        "the selected AuthorityUse branch is effective"
    );

    let selection_revoke = make_selection(&reverse, revoke.id);
    reverse
        .admit(selection_revoke)
        .expect("the typed selection of the revoke branch admits");
    assert_eq!(
        reverse.evaluator().effective_role(&target),
        None,
        "the unselected controller branch remains permanently ineffective"
    );
    assert_eq!(
        reverse.authority_use_heads(&controller).len(),
        1,
        "the explicit selection replaces, rather than preserves, the fork head set"
    );
}

#[test]
fn membership_admit_uses_controller_tier_with_owner_counterfactual() {
    let root_key = key(69);
    let controller_key = key(70);
    let member_key = key(71);
    let bootstrap = closed_bootstrap(69, 69);
    let controller = author(&controller_key);
    let member = author(&member_key);
    let target = author(&key(72));
    let mut graph = FactGraph::from_bootstrap(&bootstrap);

    let controller_grant = fact(
        &bootstrap,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    graph
        .admit(controller_grant)
        .expect("root controller grant admits");
    let member_grant = authored(
        &graph,
        &root_key,
        FactBody::RoleGrant {
            target: member.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    graph.admit(member_grant).expect("root member grant admits");

    let controller_admit = authored(
        &graph,
        &controller_key,
        FactBody::MembershipAdmit {
            target: target.clone(),
        },
        Vec::new(),
    );
    graph
        .admit(controller_admit)
        .expect("Controller may sign a member admission");

    let member_admit = authored(
        &graph,
        &member_key,
        FactBody::MembershipAdmit {
            target: author(&key(73)),
        },
        Vec::new(),
    );
    assert_eq!(
        graph.admit(member_admit),
        Err(SemanticError::UnauthorizedMembershipAdmit),
        "a plain Member cannot author a member-log admission"
    );

    let owner_admit = authored(
        &graph,
        &root_key,
        FactBody::MembershipAdmit {
            target: target.clone(),
        },
        Vec::new(),
    );
    graph
        .admit(owner_admit)
        .expect("Owner remains a valid higher-tier member-admission signer");
}

#[test]
fn finite_authority_fork_requires_complete_resolution_before_regrant() {
    let root_key = key(110);
    let controller_key = key(111);
    let target = author(&key(112));
    let future_target = author(&key(113));
    let bootstrap = closed_bootstrap(110, 110);
    let controller = author(&controller_key);
    let mut source = FactGraph::from_bootstrap(&bootstrap);

    // G grants C. O and R are then authored from the same exact G base: O is
    // the controller's operation, while R revokes that controller. Their
    // AuthorityUse(C) records therefore form an incomparable fork.
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
    assert_eq!(fork.authority_use_heads(&controller).len(), 2);
    assert_eq!(fork.evaluator().effective_role(&target), None);
    assert_eq!(fork.evaluator().effective_role(&controller), None);

    // No ordinary operation may smuggle a choice through the unresolved fork.
    let blocked = authored(
        &fork,
        &controller_key,
        FactBody::RoleGrant {
            target: future_target.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    assert_eq!(
        fork.admit(blocked),
        Err(SemanticError::UnauthorizedRoleGrant),
        "the unresolved AuthorityUse fork fails closed"
    );

    let incomplete = fact(
        &bootstrap,
        &root_key,
        FactBody::Resolution {
            cell: ExclusiveCell::role(controller.clone()),
            cited_heads: vec![operation.id],
            selected_head: operation.id,
        },
        vec![operation.id],
    );
    assert_eq!(
        fork.admit(incomplete),
        Err(SemanticError::IncompleteResolution),
        "Q must cite every incomparable AuthorityUse(C) head"
    );
    let wrong = fact(
        &bootstrap,
        &root_key,
        FactBody::Resolution {
            cell: ExclusiveCell::role(controller.clone()),
            cited_heads: vec![operation.id, revoke.id],
            selected_head: grant.id,
        },
        vec![operation.id, revoke.id],
    );
    assert_eq!(
        fork.admit(wrong),
        Err(SemanticError::ResolutionSelectionNotCited),
        "Q cannot select a head outside the complete conflict set"
    );

    // Q selects R. N is the only later regrant; O remains a historical loser.
    let resolution = authored(
        &fork,
        &root_key,
        FactBody::Resolution {
            cell: ExclusiveCell::role(controller.clone()),
            cited_heads: vec![operation.id, revoke.id],
            selected_head: revoke.id,
        },
        Vec::new(),
    );
    fork.admit(resolution)
        .expect("Q complete resolution selecting R admits");
    let regrant = authored(
        &fork,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    fork.admit(regrant).expect("N regrant admits");
    let future = authored(
        &fork,
        &controller_key,
        FactBody::RoleGrant {
            target: future_target.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    fork.admit(future)
        .expect("post-N controller operation admits");
    assert_eq!(
        fork.evaluator().effective_role(&controller),
        Some(Role::Controller)
    );
    assert_eq!(
        fork.evaluator().effective_role(&future_target),
        Some(Role::Member)
    );
    assert_eq!(
        fork.evaluator().effective_role(&target),
        None,
        "O remains permanently inactive after Q selects R and N regrants C"
    );
}
