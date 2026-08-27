#![cfg(feature = "transport-lab")]

//! Production-shaped R1 controls for the instance-owned semantic snapshot.
//!
//! The lower-level store controls cover torn writes, writer death, custody
//! validation, and compaction.  These controls prove the engine uses that
//! same store owner for a real Closed network lifecycle and does not rebuild a
//! fresh graph on restart.

use std::sync::Arc;

use myownmesh_core::config::{NetworkConfig, SignalingConfig, TopologyMode};
use myownmesh_core::engine::transport_lab::ingest_semantic_fact;
use myownmesh_core::engine::{
    create_network_in_instance_root, governance, spawn_network_in_instance_root,
};
use myownmesh_core::identity::Identity;
use myownmesh_core::network_state::{NetworkKind, Role, TransitionVariant};
use myownmesh_core::semantic::content::AuthorityUse;
use myownmesh_core::semantic::{DeviceId, FactBody, FactContent, FactDomain, SignedFact};
use tempfile::TempDir;

mod support;

fn closed_config(id: &str, network_id: &str) -> NetworkConfig {
    NetworkConfig {
        id: id.to_string(),
        network_id: network_id.to_string(),
        label: id.to_string(),
        kind: NetworkKind::Closed,
        topology: TopologyMode::FullMesh,
        signaling: SignalingConfig::default(),
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        roster_path: None,
        pinned_peers: Vec::new(),
        auto_approve: false,
    }
}

fn signed_role_grant(
    context: myownmesh_core::semantic::MeshContextId,
    signer: &Identity,
    target: DeviceId,
    parents: Vec<myownmesh_core::semantic::FactId>,
) -> SignedFact {
    SignedFact::sign(
        FactContent::new(
            FactDomain::Governance,
            context,
            FactBody::RoleGrant {
                target,
                role: myownmesh_core::semantic::Role::Member,
            },
            DeviceId::from_canonical_str(signer.public_id()).expect("signer id"),
            parents,
        ),
        signer.signing_key(),
    )
    .expect("signed role grant")
}

fn signed_role_grant_with_authority(
    context: myownmesh_core::semantic::MeshContextId,
    signer: &Identity,
    target: DeviceId,
    parents: Vec<myownmesh_core::semantic::FactId>,
    authority_uses: Vec<AuthorityUse>,
) -> SignedFact {
    let mut content = FactContent::new(
        FactDomain::Governance,
        context,
        FactBody::RoleGrant {
            target,
            role: myownmesh_core::semantic::Role::Member,
        },
        DeviceId::from_canonical_str(signer.public_id()).expect("signer id"),
        parents,
    );
    content.authority_uses = authority_uses;
    SignedFact::sign(content, signer.signing_key()).expect("signed role grant")
}

#[tokio::test]
async fn closed_network_restart_restores_the_committed_semantic_graph() {
    let root = TempDir::new().expect("instance root");
    let identity = Arc::new(Identity::ephemeral());
    let config = closed_config("r1-restart", "r1-wire-network");
    let target = Identity::ephemeral();

    let (state, driver) = create_network_in_instance_root(
        config.clone(),
        identity.clone(),
        support::test_transport(),
        root.path().to_path_buf(),
        [0x91; 32],
    )
    .await
    .expect("create Closed network");
    let context = state.mesh_context_id();
    governance::propose(
        &state,
        TransitionVariant::RoleGrant {
            target: target.public_id().to_string(),
            role: Role::Member,
        },
        None,
    )
    .await
    .expect("commit canonical member grant");
    assert_eq!(
        governance::snapshot(&state).roles.get(target.public_id()),
        Some(&Role::Member),
        "the live state observes the committed canonical grant"
    );
    state
        .compact_semantic_state()
        .expect("compact semantic snapshot");
    state.request_shutdown();
    driver.await.expect("first driver shutdown");

    let (reopened, reopened_driver) = spawn_network_in_instance_root(
        config,
        identity,
        support::test_transport(),
        root.path().to_path_buf(),
    )
    .await
    .expect("reopen Closed network");
    assert_eq!(reopened.mesh_context_id(), context);
    assert_eq!(
        governance::snapshot(&reopened)
            .roles
            .get(target.public_id()),
        Some(&Role::Member),
        "restart restores the exact admitted graph through NetworkState"
    );
    reopened.request_shutdown();
    reopened_driver.await.expect("reopened driver shutdown");
}

#[tokio::test]
async fn quarantine_unrelated_commit_restart_then_parent_settles_exact_custody() {
    let root = TempDir::new().expect("instance root");
    let identity = Arc::new(Identity::ephemeral());
    let config = closed_config("r1-quarantine", "r1-quarantine-wire");
    let target = Identity::ephemeral();
    let unrelated = Identity::ephemeral();

    let (state, driver) = create_network_in_instance_root(
        config.clone(),
        identity.clone(),
        support::test_transport(),
        root.path().to_path_buf(),
        [0x92; 32],
    )
    .await
    .expect("create Closed network");
    let context = state.mesh_context_id();
    let unrelated_fact = signed_role_grant(
        context,
        identity.as_ref(),
        DeviceId::from_canonical_str(unrelated.public_id()).expect("unrelated target id"),
        Vec::new(),
    );
    let root_device = DeviceId::from_canonical_str(identity.public_id()).expect("root id");
    let target_device = DeviceId::from_canonical_str(target.public_id()).expect("target id");
    let mut parent_authority_uses = vec![
        AuthorityUse {
            subject: root_device,
            predecessors: vec![unrelated_fact.id],
        },
        AuthorityUse {
            subject: target_device.clone(),
            predecessors: Vec::new(),
        },
    ];
    parent_authority_uses.sort_by(|left, right| left.subject.cmp(&right.subject));
    let parent = signed_role_grant_with_authority(
        context,
        identity.as_ref(),
        target_device,
        vec![unrelated_fact.id],
        parent_authority_uses,
    );
    let unresolved = signed_role_grant(
        context,
        identity.as_ref(),
        DeviceId::from_canonical_str(target.public_id()).expect("target id"),
        vec![parent.id],
    );

    ingest_semantic_fact(&state, unresolved).await;
    assert_eq!(state.semantic_fact_count(), 0);
    assert_eq!(state.semantic_unresolved_count(), 1);
    assert_eq!(state.semantic_provisional_custody_count(), 1);

    ingest_semantic_fact(&state, unrelated_fact).await;
    assert_eq!(state.semantic_fact_count(), 1);
    assert_eq!(state.semantic_unresolved_count(), 1);
    assert_eq!(state.semantic_provisional_custody_count(), 1);

    state.request_shutdown();
    driver.await.expect("first driver shutdown");
    let (reopened, reopened_driver) = spawn_network_in_instance_root(
        config,
        identity,
        support::test_transport(),
        root.path().to_path_buf(),
    )
    .await
    .expect("reopen unresolved snapshot");
    assert_eq!(reopened.semantic_fact_count(), 1);
    assert_eq!(reopened.semantic_unresolved_count(), 1);
    assert_eq!(reopened.semantic_provisional_custody_count(), 1);

    ingest_semantic_fact(&reopened, parent).await;
    assert_eq!(reopened.semantic_fact_count(), 3);
    assert_eq!(reopened.semantic_unresolved_count(), 0);
    assert_eq!(
        reopened.semantic_provisional_custody_count(),
        0,
        "resolving the exact parent settles its provisional custody"
    );
    assert_eq!(
        governance::snapshot(&reopened)
            .roles
            .get(target.public_id()),
        Some(&Role::Member),
        "the resolved child is projected after durable settlement"
    );
    reopened.request_shutdown();
    reopened_driver.await.expect("reopened driver shutdown");
}

#[tokio::test]
async fn rejected_quarantine_is_settled_without_starving_valid_restart_progress() {
    let root = TempDir::new().expect("instance root");
    let identity = Arc::new(Identity::ephemeral());
    let outsider = Identity::ephemeral();
    let config = closed_config("r1-rejected-quarantine", "r1-rejected-wire");
    let parent_target = Identity::ephemeral();
    let unrelated = Identity::ephemeral();

    let (state, driver) = create_network_in_instance_root(
        config.clone(),
        identity.clone(),
        support::test_transport(),
        root.path().to_path_buf(),
        [0x93; 32],
    )
    .await
    .expect("create Closed network");
    let context = state.mesh_context_id();
    let unrelated_fact = signed_role_grant(
        context,
        identity.as_ref(),
        DeviceId::from_canonical_str(unrelated.public_id()).expect("unrelated target id"),
        Vec::new(),
    );
    let root_device = DeviceId::from_canonical_str(identity.public_id()).expect("root id");
    let target_device = DeviceId::from_canonical_str(parent_target.public_id()).expect("target id");
    let mut parent_authority_uses = vec![
        AuthorityUse {
            subject: root_device,
            predecessors: vec![unrelated_fact.id],
        },
        AuthorityUse {
            subject: target_device.clone(),
            predecessors: Vec::new(),
        },
    ];
    parent_authority_uses.sort_by(|left, right| left.subject.cmp(&right.subject));
    let parent = signed_role_grant_with_authority(
        context,
        identity.as_ref(),
        target_device,
        vec![unrelated_fact.id],
        parent_authority_uses,
    );
    let rejected = signed_role_grant(
        context,
        &outsider,
        DeviceId::from_canonical_str(parent_target.public_id()).expect("target id"),
        vec![parent.id],
    );

    ingest_semantic_fact(&state, rejected).await;
    assert_eq!(state.semantic_fact_count(), 0);
    assert_eq!(state.semantic_unresolved_count(), 1);
    assert_eq!(state.semantic_provisional_custody_count(), 1);

    ingest_semantic_fact(&state, unrelated_fact).await;
    assert_eq!(state.semantic_fact_count(), 1);
    assert_eq!(state.semantic_unresolved_count(), 1);
    assert_eq!(state.semantic_provisional_custody_count(), 1);

    state.request_shutdown();
    driver.await.expect("first driver shutdown");
    let (reopened, reopened_driver) = spawn_network_in_instance_root(
        config.clone(),
        identity.clone(),
        support::test_transport(),
        root.path().to_path_buf(),
    )
    .await
    .expect("reopen rejected quarantine snapshot");
    assert_eq!(reopened.semantic_fact_count(), 1);
    assert_eq!(reopened.semantic_unresolved_count(), 1);
    assert_eq!(reopened.semantic_provisional_custody_count(), 1);

    ingest_semantic_fact(&reopened, parent).await;
    assert_eq!(reopened.semantic_fact_count(), 2);
    assert_eq!(reopened.semantic_unresolved_count(), 0);
    assert_eq!(reopened.semantic_provisional_custody_count(), 0);

    reopened.request_shutdown();
    reopened_driver.await.expect("second driver shutdown");
    let (restored, restored_driver) = spawn_network_in_instance_root(
        config,
        identity,
        support::test_transport(),
        root.path().to_path_buf(),
    )
    .await
    .expect("restart after rejected quarantine settlement");
    assert_eq!(restored.semantic_fact_count(), 2);
    assert_eq!(restored.semantic_unresolved_count(), 0);
    assert_eq!(restored.semantic_provisional_custody_count(), 0);
    restored.request_shutdown();
    restored_driver.await.expect("final driver shutdown");
}
