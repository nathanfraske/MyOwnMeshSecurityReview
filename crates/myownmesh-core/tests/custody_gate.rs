#![cfg(feature = "transport-lab")]

//! Integration test: the per-device custody MFA gate on governance authoring.
//!
//! Proves that once a device enrolls a custody lock for a network,
//! `governance::propose` refuses to author a transition without a valid
//! second factor — and proceeds once one is supplied. (The same
//! `custody::require` chokepoint guards `sign_proposal`; see the unit tests
//! in `custody.rs` for the verify/enroll/disable mechanics.)

use std::sync::Arc;

use myownmesh_core::config::{NetworkConfig, SignalingConfig, TopologyMode};
use myownmesh_core::engine::governance;
use myownmesh_core::engine::transport_lab::create_network_in_instance_root;
use myownmesh_core::identity::Identity;
use myownmesh_core::network_state::{NetworkKind, Role, TransitionVariant};

fn fresh_network(id: &str, network_id: &str) -> NetworkConfig {
    NetworkConfig {
        id: id.to_string(),
        network_id: network_id.to_string(),
        label: id.to_string(),
        kind: Default::default(),
        topology: TopologyMode::FullMesh,
        signaling: SignalingConfig::default(),
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        roster_path: None,
        pinned_peers: Vec::new(),
        auto_approve: false,
    }
}

#[tokio::test]
async fn custody_gate_blocks_unauthenticated_governance_authoring() {
    let custody_root = tempfile::tempdir().expect("test custody root");
    std::env::set_var("MYOWNMESH_HOME", custody_root.path());
    let instance_root = tempfile::tempdir().expect("per-instance root");
    let transport = support::test_transport();

    let alice = Arc::new(Identity::ephemeral());
    let net_id = format!("custody-gate-{}", &alice.public_id()[..12]);
    let mut config = fresh_network("alice", &net_id);
    // This test starts from an explicit verified Closed bootstrap. Alice is
    // its SingleRoot authority; there is no founderless Open→Closed step.
    config.kind = NetworkKind::Closed;
    let (state, driver) = create_network_in_instance_root(
        config,
        alice.clone(),
        transport,
        instance_root.path().to_path_buf(),
        [0xC7; 32],
    )
    .await
    .expect("create Closed bootstrap for alice");
    assert_eq!(state.verified_authority_root(), Some(alice.public_id()));
    assert_eq!(governance::snapshot(&state).kind, NetworkKind::Closed);

    // Enroll a custody lock for this network on this device.
    let enrolled = myownmesh_core::custody::enroll(&net_id, "alice-laptop").expect("enroll");
    assert!(myownmesh_core::custody::is_enrolled(&net_id));

    let target = Identity::ephemeral();
    let target_id = target.public_id().to_string();

    // Authoring with no second factor is refused *at the gate* — before any
    // signing happens.
    let err = governance::propose(
        &state,
        TransitionVariant::RoleGrant {
            target: target_id.clone(),
            role: Role::Member,
        },
        None,
    )
    .await
    .expect_err("propose without a code must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("custody") || msg.contains("authenticator"),
        "expected a custody-gate error, got: {msg}"
    );

    // With a valid one-time recovery code, the root-authorized member grant
    // proceeds and projects into the canonical read-only snapshot and the
    // production roster.
    let fact_id = governance::propose(
        &state,
        TransitionVariant::RoleGrant {
            target: target_id.clone(),
            role: Role::Member,
        },
        Some(&enrolled.recovery_codes[0]),
    )
    .await
    .expect("root-authorized RoleGrant with a valid recovery code");
    assert_eq!(fact_id.to_string().len(), 52, "returned canonical FactId");
    let projected = governance::snapshot(&state);
    assert_eq!(
        projected.roles.get(&target_id).copied(),
        Some(Role::Member),
        "recovery-authored grant must project to Member"
    );
    assert!(projected.pending.is_empty());
    assert!(state.is_rostered(&target_id));
    assert_eq!(
        state
            .roster
            .read()
            .authorized_devices
            .iter()
            .find(|peer| peer.device_id == myownmesh_core::signing::pubkey_part(&target_id))
            .map(|peer| peer.role),
        Some(Role::Member),
        "recovery-authored grant must tag the authorized roster entry"
    );

    // Disable the lock (with another recovery code), and the gate is a no-op
    // again — governance authoring no longer demands a factor.
    myownmesh_core::custody::disable(&net_id, &enrolled.recovery_codes[1]).expect("disable");
    assert!(!myownmesh_core::custody::is_enrolled(&net_id));
    assert!(
        myownmesh_core::custody::require(&net_id, None).is_ok(),
        "with no enrollment the gate must be a no-op"
    );

    state.request_shutdown();
    driver
        .await
        .expect("Closed bootstrap driver shuts down cleanly");
}
mod support;
