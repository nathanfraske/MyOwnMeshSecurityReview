//! End-to-end engine integration test: roster persistence + gossip.
//!
//! Covers the "remember bilateral membership while keeping local approvals
//! local" contract:
//!
//!   1. When two peers complete the bilateral approve handshake and the
//!      link goes ACTIVE, each side persists the other into its roster —
//!      even on an `auto_approve` network where no human clicked Approve.
//!      (Before this landed, auto-approved peers reached ACTIVE but were
//!      never remembered — the "we keep losing our roster" symptom.)
//!
//!   2. A local approval for a peer that isn't directly connected remains
//!      local authority. It must not become a cross-member authorization just
//!      because unsigned roster-entry gossip can carry the name elsewhere.
//!
//! Both scenarios live in ONE test on purpose: each integration-test file
//! is its own process, but the tests *within* a file share it, and the
//! engine keys its data dir off the process-global `MYOWNMESH_HOME` env
//! var (see the SAFETY note in `two_peer_handshake.rs`). Two parallel
//! `#[test]`s here would race that var. Running the scenarios in sequence
//! under one `MYOWNMESH_HOME` keeps them isolated (distinct network_ids ⇒
//! distinct roster files) without that race.
//!
//! Companion to `two_peer_handshake.rs` (open-network handshake) and
//! `closed_network_governance.rs` (signed transitions).

use std::sync::Arc;
use std::time::Duration;

use myownmesh_core::config::{NetworkConfig, SignalingConfig, TopologyMode};
use myownmesh_core::engine::NetworkState;
use myownmesh_core::engine::{attach_local, spawn_network, NetworkCmd};
use myownmesh_core::identity::Identity;
use myownmesh_core::transport::Transport;
use myownmesh_core::{MeshEvent, PeerEvent};
use myownmesh_signaling::local::LocalBroker;
use tokio::time::Instant;

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
        // Auto-approve fires the wire-level approve automatically so both
        // peers reach ACTIVE without a human Approve click — which is the
        // exact path we want to prove now persists the roster on its own.
        auto_approve: true,
    }
}

async fn wait_for_approval(rx: &mut tokio::sync::broadcast::Receiver<MeshEvent>, peer_id: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if Instant::now() > deadline {
            panic!("never saw PeerApproved for {peer_id}");
        }
        match tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
            Ok(Ok(MeshEvent::Peer(PeerEvent::Approved { device_id, .. })))
                if device_id == peer_id =>
            {
                return;
            }
            _ => continue,
        }
    }
}

fn rostered(state: &Arc<NetworkState>, device_id: &str) -> bool {
    myownmesh_core::roster::is_authorized(&state.roster.read(), device_id)
}

/// Bring two auto-approve peers up on `network_id` over a fresh broker and
/// wait until both have seen the bilateral approve land (ACTIVE). Returns
/// all ownership so the caller can close both production drivers before their
/// persistence roots and brokers are dropped.
async fn bring_up_pair(
    network_id: &str,
    transport: &Transport,
) -> (
    Arc<NetworkState>,
    Arc<Identity>,
    Arc<NetworkState>,
    Arc<Identity>,
    LocalBroker,
    tokio::task::JoinHandle<()>,
    tokio::task::JoinHandle<()>,
) {
    let broker = LocalBroker::new();
    let a_id = Arc::new(Identity::ephemeral());
    let b_id = Arc::new(Identity::ephemeral());

    let (a_state, a_driver) = spawn_network(
        fresh_network("a", network_id),
        a_id.clone(),
        transport.clone(),
    )
    .await
    .expect("spawn a");
    let (b_state, b_driver) = spawn_network(
        fresh_network("b", network_id),
        b_id.clone(),
        transport.clone(),
    )
    .await
    .expect("spawn b");

    let mut a_events = a_state.events_tx.subscribe();
    let mut b_events = b_state.events_tx.subscribe();

    attach_local(&a_state, &broker);
    attach_local(&b_state, &broker);

    wait_for_approval(&mut a_events, b_id.public_id()).await;
    wait_for_approval(&mut b_events, a_id.public_id()).await;

    (a_state, a_id, b_state, b_id, broker, a_driver, b_driver)
}

#[tokio::test]
async fn roster_persists_on_mutual_approve_and_local_approval_stays_local() {
    // One MYOWNMESH_HOME for the whole test; distinct network_ids below
    // keep the two scenarios' roster files apart. It remains alive until every
    // production driver has been explicitly shut down and joined.
    let tmp = tempfile::tempdir().expect("tempdir");
    std::env::set_var("MYOWNMESH_HOME", tmp.path());

    let transport = support::test_transport();

    // --- Scenario 1: the double handshake persists the roster ---------
    let (a1, a1_id, b1, b1_id, broker1, a1_driver, b1_driver) =
        bring_up_pair("roster-gossip-persist", &transport).await;
    assert!(
        rostered(&a1, b1_id.public_id()),
        "alice should have rostered bob on mutual ACTIVE"
    );
    assert!(
        rostered(&b1, a1_id.public_id()),
        "bob should have rostered alice on mutual ACTIVE"
    );

    // --- Scenario 2: a local approval does not authorize another peer ---
    let (a2, _a2_id, b2, _b2_id, broker2, a2_driver, b2_driver) =
        bring_up_pair("roster-gossip-local-authority", &transport).await;
    // Carol never connects — she's only ever a roster entry Alice vouches
    // for. Approve her through the command queue (the path the GUI's Approve
    // takes), which persists Alice's local approval. That local decision must
    // not authorize Bob through unsigned RosterEntries gossip.
    let carol_id = Arc::new(Identity::ephemeral());
    let (tx, rx) = tokio::sync::oneshot::channel();
    assert!(
        a2.cmd_tx
            .send(NetworkCmd::ApproveRoster {
                device_id: carol_id.public_id().to_string(),
                label: "carol".into(),
                reply: tx,
            })
            .is_ok(),
        "queue approve"
    );
    rx.await.expect("approve reply").expect("approve ok");

    assert!(
        rostered(&a2, carol_id.public_id()),
        "Alice's explicit local approval must persist in Alice's roster"
    );
    assert!(
        !rostered(&b2, carol_id.public_id()),
        "Bob must not gain authorization from Alice's unsigned roster gossip"
    );

    // Shut down every production driver before releasing the brokers or the
    // persistence root. This keeps the test's lifecycle boundary explicit and
    // prevents background work from observing reclaimed state.
    a1.request_shutdown();
    b1.request_shutdown();
    a2.request_shutdown();
    b2.request_shutdown();
    a1_driver
        .await
        .expect("Alice persistence driver shuts down cleanly");
    b1_driver
        .await
        .expect("Bob persistence driver shuts down cleanly");
    a2_driver
        .await
        .expect("Alice local-authority driver shuts down cleanly");
    b2_driver
        .await
        .expect("Bob local-authority driver shuts down cleanly");
    drop(a1);
    drop(b1);
    drop(a2);
    drop(b2);
    drop(broker1);
    drop(broker2);
    drop(tmp);
}
mod support;
