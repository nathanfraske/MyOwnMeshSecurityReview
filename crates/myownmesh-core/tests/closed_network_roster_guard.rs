//! Regression controls for canonical roster membership authority.
//!
//! `RosterEntries` is carrier material, not an authority-bearing fact. The
//! canonical signed governance projection is the only source that can add a
//! member to a Closed roster; an unsigned carrier must not do so regardless
//! of the sender's role. Open networks remain founderless through
//! self-authorized current participation; approval of an absent device is
//! refused, and unsigned roster carriers remain inert.
//!
//! The test uses explicit per-node bootstrap roots and drives the canonical
//! Closed RoleGrant path before exercising the inert carrier boundary.
//!
//! Companion to `roster_gossip.rs` (transport convergence) and
//! `closed_network_governance.rs` (signed transitions).

use std::sync::Arc;

use myownmesh_core::config::{NetworkConfig, SignalingConfig, TopologyMode};
use myownmesh_core::engine::{
    create_network_in_instance_root, governance, spawn_network_in_instance_root, NetworkState,
};
use myownmesh_core::identity::Identity;
use myownmesh_core::network_state::{NetworkKind, Role, TransitionVariant};
use myownmesh_core::protocol::governance::{RosterEntriesMessage, RosterEntry};
use myownmesh_core::semantic::{ClosedProfileId, VerifiedProjectPolicy};
use tempfile::TempDir;

fn fresh_network(id: &str, network_id: &str, kind: NetworkKind) -> NetworkConfig {
    NetworkConfig {
        id: id.to_string(),
        network_id: network_id.to_string(),
        label: id.to_string(),
        kind,
        topology: TopologyMode::FullMesh,
        signaling: SignalingConfig::default(),
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        roster_path: None,
        pinned_peers: Vec::new(),
        auto_approve: false,
    }
}

fn rostered(state: &Arc<NetworkState>, id: &str) -> bool {
    myownmesh_core::roster::is_authorized(&state.roster.read(), id)
}

/// One unsigned carrier entry introducing `id` as a plain member.
fn vouch(id: &str, label: &str) -> RosterEntriesMessage {
    RosterEntriesMessage {
        entries: vec![RosterEntry {
            device_id: id.to_string(),
            label: label.to_string(),
            approved_at: 0,
            role: Role::Member,
            granted_by: String::new(),
        }],
    }
}

#[tokio::test]
async fn roster_membership_authority_gate() {
    let transport = support::test_transport();
    let closed_root: TempDir = tempfile::tempdir().expect("closed per-node persistence root");
    let open_root: TempDir = tempfile::tempdir().expect("open per-node persistence root");

    // Bob and Carol become canonical Closed roles. The remaining identities
    // are fresh targets for the four non-authoritative carrier attempts.
    let bob = Arc::new(Identity::ephemeral());
    let carol = Arc::new(Identity::ephemeral());
    let mallory = Arc::new(Identity::ephemeral());
    let dave = Arc::new(Identity::ephemeral());
    let eve = Arc::new(Identity::ephemeral());
    let frank = Arc::new(Identity::ephemeral());

    // ---- Scenario 1: CLOSED network — only canonical authority may admit.
    let alice_id = Arc::new(Identity::ephemeral());
    let (alice, alice_driver) = create_network_in_instance_root(
        fresh_network("alice", "closed-roster-guard", NetworkKind::Closed),
        alice_id.clone(),
        transport.clone(),
        closed_root.path().to_path_buf(),
        [0x71; 32],
    )
    .await
    .expect("create explicit Closed root");
    assert!(matches!(
        alice.verified_policy(),
        VerifiedProjectPolicy::Closed(policy)
            if policy.profile() == ClosedProfileId::SingleRootSignedMemberLogV1
    ));
    assert_eq!(
        alice.verified_bootstrap().context().scope,
        "closed-roster-guard"
    );
    let initial_snapshot = governance::snapshot(&alice);
    assert_eq!(
        initial_snapshot.roles.get(alice_id.public_id()),
        Some(&Role::Owner),
        "the explicit Closed creator is the canonical root owner"
    );

    let bob_fact = governance::propose(
        &alice,
        TransitionVariant::RoleGrant {
            target: bob.public_id().to_string(),
            role: Role::Member,
        },
        None,
    )
    .await
    .expect("root signs Bob's canonical Member grant");
    let carol_fact = governance::propose(
        &alice,
        TransitionVariant::RoleGrant {
            target: carol.public_id().to_string(),
            role: Role::Controller,
        },
        None,
    )
    .await
    .expect("root signs Carol's canonical Controller grant");
    assert_ne!(
        bob_fact, carol_fact,
        "each RoleGrant is a distinct canonical fact"
    );
    let canonical_snapshot = governance::snapshot(&alice);
    assert_eq!(
        canonical_snapshot.roles.get(bob.public_id()),
        Some(&Role::Member)
    );
    assert_eq!(
        canonical_snapshot.roles.get(carol.public_id()),
        Some(&Role::Controller)
    );
    assert!(
        rostered(&alice, bob.public_id()) && rostered(&alice, carol.public_id()),
        "canonical RoleGrants must project into the compatibility roster"
    );

    // A MEMBER carries a brand-new id — it must be ignored.
    governance::on_roster_entries(
        &alice,
        bob.public_id(),
        vouch(mallory.public_id(), "mallory"),
    )
    .await;
    assert!(!rostered(&alice, mallory.public_id()));

    // An unknown sender carries another new id — it must be ignored.
    governance::on_roster_entries(&alice, mallory.public_id(), vouch(dave.public_id(), "dave"))
        .await;
    assert!(!rostered(&alice, dave.public_id()));

    // A CONTROLLER's unsigned carrier is not a membership fact.
    governance::on_roster_entries(&alice, carol.public_id(), vouch(eve.public_id(), "eve")).await;
    assert!(!rostered(&alice, eve.public_id()));

    // Neither is the verified root's unsigned carrier.
    governance::on_roster_entries(
        &alice,
        alice_id.public_id(),
        vouch(frank.public_id(), "frank"),
    )
    .await;
    assert!(!rostered(&alice, frank.public_id()));

    // ---- Scenario 2: OPEN is founderless, but carriers stay inert --------
    // Deliberately do not join Open participation: this negative control
    // proves that unsigned carriers cannot bootstrap a founderless roster.
    let alice2_id = Arc::new(Identity::ephemeral());
    let (alice2, alice2_driver) = spawn_network_in_instance_root(
        fresh_network("alice-open", "open-roster-guard", NetworkKind::Open),
        alice2_id.clone(),
        transport,
        open_root.path().to_path_buf(),
    )
    .await
    .expect("spawn founderless Open network");
    assert!(matches!(
        alice2.verified_policy(),
        VerifiedProjectPolicy::Open
    ));
    assert!(alice2.verified_authority_root().is_none());
    assert!(
        alice2.approve_roster(eve.public_id(), "eve").await.is_err(),
        "Open approval of an absent device is refused without self-authored participation"
    );
    assert!(
        !rostered(&alice2, eve.public_id()),
        "a refused Open approval must leave the compatibility roster unchanged"
    );

    governance::on_roster_entries(
        &alice2,
        alice2_id.public_id(),
        vouch(mallory.public_id(), "mallory"),
    )
    .await;
    assert!(
        !rostered(&alice2, mallory.public_id()),
        "unsigned roster carriers must not mutate a founderless Open roster"
    );

    alice.request_shutdown();
    alice2.request_shutdown();
    let _ = alice_driver.await;
    let _ = alice2_driver.await;
}

mod support;
