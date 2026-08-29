//! Regression test for the "reconnect strands peers" bug: a graceful
//! departure must make the *other* peer drop our session immediately,
//! instead of waiting out the ~90 s heartbeat timeout.
//!
//! Two peers handshake through an in-process `LocalBroker`; one departs; the
//! other must emit `PeerEvent::Dropped { UserLeft }` within a couple of
//! seconds. Before the fix the engine had no way to *say* it was leaving (only
//! an intelligent relay synthesised one), so on the default public relays a
//! leave-then-rejoin — which is exactly what the app's "reconnect" button does
//! — left peers showing online-but-unconnectable until the heartbeat backstop
//! fired.
//!
//! The departure it drives is the authenticated one: a `SessionControl::Depart`
//! over the live session, which is the only thing that may retire a healthy
//! authenticated session. The carrier-side hint this test used to send is now
//! reachability evidence with no teardown authority, so sending it here would
//! assert the opposite of the boundary. The bound and the reason are unchanged;
//! only the path is.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use myownmesh_core::config::{NetworkConfig, SignalingConfig, TopologyMode};
use myownmesh_core::engine::transport_lab::{
    attach_local, channel, depart_for_lab, departure_receipt_gate_arrival_for_lab,
    install_departure_receipt_gate_for_lab, join_open_participation,
    pending_departure_count_for_lab, release_departure_receipt_gate_for_lab, spawn_network,
};
use myownmesh_core::events::DropReason;
use myownmesh_core::identity::Identity;
use myownmesh_core::{MeshEvent, PeerEvent};
use myownmesh_signaling::local::LocalBroker;
use tokio::time::Instant;

static PROCESS_CONTROL_LOCK: OnceLock<Arc<tokio::sync::Mutex<()>>> = OnceLock::new();

struct ProcessControlGuard {
    _lock: tokio::sync::OwnedMutexGuard<()>,
    previous_home: Option<std::ffi::OsString>,
}

impl Drop for ProcessControlGuard {
    fn drop(&mut self) {
        match &self.previous_home {
            Some(previous) => std::env::set_var("MYOWNMESH_HOME", previous),
            None => std::env::remove_var("MYOWNMESH_HOME"),
        }
    }
}

async fn exclusive_process_controls() -> ProcessControlGuard {
    let lock = PROCESS_CONTROL_LOCK
        .get_or_init(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
        .lock_owned()
        .await;
    ProcessControlGuard {
        _lock: lock,
        previous_home: std::env::var_os("MYOWNMESH_HOME"),
    }
}

fn fresh_network(id: &str) -> NetworkConfig {
    NetworkConfig {
        id: id.to_string(),
        network_id: "peer-leave-test".into(),
        label: id.to_string(),
        kind: Default::default(),
        topology: TopologyMode::FullMesh,
        signaling: SignalingConfig::default(),
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        roster_path: None,
        pinned_peers: Vec::new(),
        auto_approve: true,
    }
}

#[tokio::test]
async fn graceful_departure_drops_peer_without_waiting_for_heartbeat() {
    let _process_controls = exclusive_process_controls().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    // SAFETY: set process-wide; leave-tests must not run in parallel against
    // the same env var (same constraint as two_peer_handshake).
    std::env::set_var("MYOWNMESH_HOME", tmp.path());

    let broker = LocalBroker::new();
    let transport = support::test_transport();
    let provider_baseline = transport
        .connector_resource_report()
        .expect("fixture provider report is available");

    let alice_id = Arc::new(Identity::ephemeral());
    let bob_id = Arc::new(Identity::ephemeral());

    let (alice_state, alice_driver) =
        spawn_network(fresh_network("alice"), alice_id.clone(), transport.clone())
            .await
            .expect("alice engine");
    let (bob_state, bob_driver) =
        spawn_network(fresh_network("bob"), bob_id.clone(), transport.clone())
            .await
            .expect("bob engine");

    join_open_participation(&alice_state)
        .await
        .expect("alice joins Open participation");
    join_open_participation(&bob_state)
        .await
        .expect("bob joins Open participation");

    let mut alice_events = alice_state.events_tx.subscribe();
    let mut bob_events = bob_state.events_tx.subscribe();

    attach_local(&alice_state, &broker);
    attach_local(&bob_state, &broker);

    // Both sides connected.
    wait_for_approval(&mut alice_events, bob_id.public_id()).await;
    wait_for_approval(&mut bob_events, alice_id.public_id()).await;

    // A carrying-channel receipt is observed before the authenticated
    // departure is sent. This keeps the control honest about ordering: the
    // data path settled first, then the exact session was retired.
    let alice_channel = channel::<String>("receipt-before-close".into(), alice_state.clone());
    let mut bob_channel = channel::<String>("receipt-before-close".into(), bob_state.clone())
        .subscribe()
        .expect("bob subscribes to the carrying channel");
    alice_channel
        .send_to(bob_id.public_id(), &"receipt".to_string())
        .await
        .expect("carrying-channel receipt is accepted");
    let received = tokio::time::timeout(Duration::from_secs(5), bob_channel.recv())
        .await
        .expect("carrying-channel receipt timed out")
        .expect("carrying channel closed before receipt")
        .expect("carrying-channel receipt is valid");
    assert_eq!(received.body(), "receipt");

    // Alice makes a deliberate exit. This is what the daemon runs before
    // tearing a network down on remove / restart / shutdown, reached in
    // production through `MeshHandle::announce_leave`. Arm the production
    // receipt gate before publishing the carrier hint: the gate is reached
    // only by the authenticated Depart path, so it gives this test a causal
    // boundary instead of guessing that a short quiet interval means the
    // carrier hint did not retire the session.
    let arrival = departure_receipt_gate_arrival_for_lab(&bob_state);
    tokio::pin!(arrival);
    arrival.as_mut().enable();
    install_departure_receipt_gate_for_lab(&bob_state);
    alice_state.announce_departure();
    let departure_state = Arc::clone(&alice_state);
    let departure_task = tokio::spawn(async move { depart_for_lab(&departure_state).await });
    tokio::time::timeout(Duration::from_secs(5), &mut arrival)
        .await
        .expect("authenticated departure receipt entered the production hold");
    assert_eq!(
        alice_state.peer_count(),
        1,
        "carrier leave does not retire the exact authenticated session"
    );
    assert_eq!(
        pending_departure_count_for_lab(&alice_state),
        1,
        "the exact session owns one pending authenticated departure"
    );
    release_departure_receipt_gate_for_lab(&bob_state);
    let departure = tokio::time::timeout(Duration::from_secs(5), departure_task)
        .await
        .expect("authenticated departure completes after its receipt is released")
        .expect("authenticated departure task joins");
    assert_eq!(departure.observed, 1);
    assert_eq!(departure.cancelled, 0);

    // Bob must drop Alice promptly with `UserLeft`, not sit on a dead
    // session until the heartbeat timeout. A generous-but-far-below-90 s
    // window: the heartbeat backstop is HEARTBEAT_TIMEOUT_MS (30 s) +
    // WAKE_DETECTION_THRESHOLD_MS (60 s), so anything under that proves the
    // leave drove the drop, not the timeout.
    let reason = wait_for_drop(
        &mut bob_events,
        alice_id.public_id(),
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(
        alice_state.peer_count(),
        0,
        "authenticated departure closes Alice only after its waiter completes"
    );
    assert_eq!(
        reason,
        DropReason::UserLeft,
        "a graceful departure should drop the peer as UserLeft"
    );

    // A duplicate departure is a no-op after the exact authenticated session
    // is retired. It must not manufacture a second drop event or touch a
    // successor that could be installed later under the same device id.
    let duplicate_departure = depart_for_lab(&alice_state).await;
    assert_eq!(duplicate_departure.observed, 0);
    assert_eq!(duplicate_departure.cancelled, 0);
    assert_eq!(
        alice_state.peer_count(),
        0,
        "a duplicate Depart has no exact authenticated session to retire"
    );

    // Shutdown is an explicit lifecycle boundary, not an implicit cleanup
    // side effect of the carrier withdrawal. Await both production drivers so
    // the provider-backed fixture has a settled terminal state before the
    // test exits.
    alice_state.request_shutdown();
    bob_state.request_shutdown();
    alice_driver.await.expect("alice driver shuts down cleanly");
    bob_driver.await.expect("bob driver shuts down cleanly");
    assert_eq!(
        pending_departure_count_for_lab(&alice_state),
        0,
        "Alice has no pending departure custody after shutdown"
    );
    assert_eq!(
        pending_departure_count_for_lab(&bob_state),
        0,
        "Bob has no pending departure custody after shutdown"
    );
    let settled = transport
        .connector_resource_report()
        .expect("fixture provider report remains available");
    assert_eq!(
        settled.active_candidates,
        provider_baseline.active_candidates
    );
    assert_eq!(settled.failed_cleanup_candidates, 0);
    assert!(!settled.accounting_poisoned);
}

#[tokio::test]
async fn bilateral_departures_are_observed_once_on_both_exact_sessions() {
    let _process_controls = exclusive_process_controls().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    std::env::set_var("MYOWNMESH_HOME", tmp.path());
    let broker = LocalBroker::new();
    let transport = support::test_transport();
    let provider_baseline = transport
        .connector_resource_report()
        .expect("fixture provider report is available");
    let alice_id = Arc::new(Identity::ephemeral());
    let bob_id = Arc::new(Identity::ephemeral());
    let (alice_state, alice_driver) = spawn_network(
        fresh_network("alice-bilateral"),
        Arc::clone(&alice_id),
        transport.clone(),
    )
    .await
    .expect("alice engine");
    let (bob_state, bob_driver) = spawn_network(
        fresh_network("bob-bilateral"),
        Arc::clone(&bob_id),
        transport.clone(),
    )
    .await
    .expect("bob engine");
    join_open_participation(&alice_state)
        .await
        .expect("alice joins Open participation");
    join_open_participation(&bob_state)
        .await
        .expect("bob joins Open participation");
    let mut alice_events = alice_state.events_tx.subscribe();
    let mut bob_events = bob_state.events_tx.subscribe();
    attach_local(&alice_state, &broker);
    attach_local(&bob_state, &broker);
    wait_for_approval(&mut alice_events, bob_id.public_id()).await;
    wait_for_approval(&mut bob_events, alice_id.public_id()).await;

    let alice_sender = channel::<String>("bilateral-proof".into(), alice_state.clone());
    let mut bob_receiver = channel::<String>("bilateral-proof".into(), bob_state.clone())
        .subscribe()
        .expect("bob subscribes to bilateral proof channel");
    let bob_sender = channel::<String>("bilateral-proof".into(), bob_state.clone());
    let mut alice_receiver = channel::<String>("bilateral-proof".into(), alice_state.clone())
        .subscribe()
        .expect("alice subscribes to bilateral proof channel");
    alice_sender
        .send_to(bob_id.public_id(), &"alice-to-bob".to_string())
        .await
        .expect("Alice's exact promoted session sends the proof");
    bob_sender
        .send_to(alice_id.public_id(), &"bob-to-alice".to_string())
        .await
        .expect("Bob's exact promoted session sends the proof");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), bob_receiver.recv())
            .await
            .expect("Bob's proof receive timed out")
            .expect("Bob's proof channel closed")
            .expect("Bob's proof payload is valid")
            .body(),
        "alice-to-bob"
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), alice_receiver.recv())
            .await
            .expect("Alice's proof receive timed out")
            .expect("Alice's proof channel closed")
            .expect("Alice's proof payload is valid")
            .body(),
        "bob-to-alice"
    );

    let (alice_departure, bob_departure) =
        tokio::join!(depart_for_lab(&alice_state), depart_for_lab(&bob_state));
    assert_eq!(alice_departure.observed, 1);
    assert_eq!(alice_departure.cancelled, 0);
    assert_eq!(bob_departure.observed, 1);
    assert_eq!(bob_departure.cancelled, 0);
    assert_eq!(
        wait_for_drop(
            &mut alice_events,
            bob_id.public_id(),
            Duration::from_secs(5)
        )
        .await,
        DropReason::UserLeft
    );
    assert_eq!(
        wait_for_drop(
            &mut bob_events,
            alice_id.public_id(),
            Duration::from_secs(5)
        )
        .await,
        DropReason::UserLeft
    );
    assert_eq!(alice_state.peer_count(), 0);
    assert_eq!(bob_state.peer_count(), 0);
    alice_state.request_shutdown();
    bob_state.request_shutdown();
    alice_driver
        .await
        .expect("alice bilateral driver shuts down");
    bob_driver.await.expect("bob bilateral driver shuts down");
    assert_eq!(
        pending_departure_count_for_lab(&alice_state),
        0,
        "Alice has no pending bilateral departure custody after shutdown"
    );
    assert_eq!(
        pending_departure_count_for_lab(&bob_state),
        0,
        "Bob has no pending bilateral departure custody after shutdown"
    );
    let settled = transport
        .connector_resource_report()
        .expect("fixture provider report remains available");
    assert_eq!(
        settled.active_candidates,
        provider_baseline.active_candidates
    );
    assert_eq!(settled.failed_cleanup_candidates, 0);
    assert!(!settled.accounting_poisoned);
}

#[tokio::test]
async fn authenticated_departure_withheld_receipt_cancels_on_shutdown() {
    let _process_controls = exclusive_process_controls().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    std::env::set_var("MYOWNMESH_HOME", tmp.path());
    let broker = LocalBroker::new();
    let transport = support::test_transport();
    let baseline = transport
        .connector_resource_report()
        .expect("fixture provider report is available");
    let alice_id = Arc::new(Identity::ephemeral());
    let bob_id = Arc::new(Identity::ephemeral());
    let (alice_state, alice_driver) = spawn_network(
        fresh_network("alice-queued-shutdown"),
        Arc::clone(&alice_id),
        transport.clone(),
    )
    .await
    .expect("alice engine");
    let (bob_state, bob_driver) = spawn_network(
        fresh_network("bob-queued-shutdown"),
        Arc::clone(&bob_id),
        transport.clone(),
    )
    .await
    .expect("bob engine");
    join_open_participation(&alice_state)
        .await
        .expect("alice joins Open participation");
    join_open_participation(&bob_state)
        .await
        .expect("bob joins Open participation");
    let mut alice_events = alice_state.events_tx.subscribe();
    let mut bob_events = bob_state.events_tx.subscribe();
    attach_local(&alice_state, &broker);
    attach_local(&bob_state, &broker);
    wait_for_approval(&mut alice_events, bob_id.public_id()).await;
    wait_for_approval(&mut bob_events, alice_id.public_id()).await;

    let alice_sender = channel::<String>("withheld-proof".into(), alice_state.clone());
    let mut bob_receiver = channel::<String>("withheld-proof".into(), bob_state.clone())
        .subscribe()
        .expect("bob subscribes to withheld proof channel");
    let bob_sender = channel::<String>("withheld-proof".into(), bob_state.clone());
    let mut alice_receiver = channel::<String>("withheld-proof".into(), alice_state.clone())
        .subscribe()
        .expect("alice subscribes to withheld proof channel");
    alice_sender
        .send_to(bob_id.public_id(), &"alice-to-bob".to_string())
        .await
        .expect("Alice's exact promoted session sends the proof");
    bob_sender
        .send_to(alice_id.public_id(), &"bob-to-alice".to_string())
        .await
        .expect("Bob's exact promoted session sends the proof");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), bob_receiver.recv())
            .await
            .expect("Bob's proof receive timed out")
            .expect("Bob's proof channel closed")
            .expect("Bob's proof payload is valid")
            .body(),
        "alice-to-bob"
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), alice_receiver.recv())
            .await
            .expect("Alice's proof receive timed out")
            .expect("Alice's proof channel closed")
            .expect("Alice's proof payload is valid")
            .body(),
        "bob-to-alice"
    );

    // Subscribe before arming the gate so the production receipt arrival
    // cannot be missed. The gate is reached only after Bob has admitted the
    // authenticated Depart and Alice's exact data-channel send has settled.
    let arrival = departure_receipt_gate_arrival_for_lab(&bob_state);
    tokio::pin!(arrival);
    arrival.as_mut().enable();
    install_departure_receipt_gate_for_lab(&bob_state);
    let departure_state = Arc::clone(&alice_state);
    let departure_task = tokio::spawn(async move { depart_for_lab(&departure_state).await });
    tokio::time::timeout(Duration::from_secs(5), &mut arrival)
        .await
        .expect("remote receipt entered the production hold");
    assert_eq!(
        alice_state.peer_count(),
        1,
        "the authenticated local session remains while DepartObserved is withheld"
    );
    assert_eq!(
        pending_departure_count_for_lab(&alice_state),
        1,
        "the exact logical session still owns one pending observation"
    );

    // Shutdown wins the real waiter while the remote receipt is held: this is
    // the lifecycle cancellation branch, not a carrier hint or timed fallback.
    alice_state.request_shutdown();
    let departure = tokio::time::timeout(Duration::from_secs(5), departure_task)
        .await
        .expect("local departure cancellation completes")
        .expect("local departure task joins");
    assert_eq!(departure.observed, 0);
    assert_eq!(departure.cancelled, 1);
    assert_eq!(alice_state.peer_count(), 0);
    alice_driver
        .await
        .expect("alice lifecycle cancellation joins");

    // The remote handler is intentionally parked until this point. Release it
    // before shutting Bob down so its receipt lease and handler future settle.
    release_departure_receipt_gate_for_lab(&bob_state);
    bob_state.request_shutdown();
    bob_driver.await.expect("bob lifecycle cancellation joins");
    assert_eq!(
        pending_departure_count_for_lab(&alice_state),
        0,
        "Alice has no pending withheld departure custody after shutdown"
    );
    assert_eq!(
        pending_departure_count_for_lab(&bob_state),
        0,
        "Bob has no pending withheld departure custody after shutdown"
    );
    let settled = transport
        .connector_resource_report()
        .expect("fixture provider report remains available");
    assert_eq!(settled.active_candidates, baseline.active_candidates);
    assert_eq!(settled.failed_cleanup_candidates, 0);
    assert!(!settled.accounting_poisoned);
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

async fn wait_for_drop(
    rx: &mut tokio::sync::broadcast::Receiver<MeshEvent>,
    peer_id: &str,
    within: Duration,
) -> DropReason {
    let deadline = Instant::now() + within;
    loop {
        if Instant::now() > deadline {
            panic!("never saw PeerDropped for {peer_id} within {within:?}");
        }
        match tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
            Ok(Ok(MeshEvent::Peer(PeerEvent::Dropped {
                device_id, reason, ..
            }))) if device_id == peer_id => {
                return reason;
            }
            _ => continue,
        }
    }
}

mod support;
