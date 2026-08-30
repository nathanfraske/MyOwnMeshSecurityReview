#![cfg(feature = "transport-lab")]

//! Engine-level integration tests for mDNS signaling and the
//! multi-driver fan-out.
//!
//! - `two_peers_handshake_over_mdns_only`: a LAN-only network
//!   (`strategy: "none", mdns: true`) — the local-claiming shape —
//!   completes a full engine handshake with SDP exchanged over the
//!   mDNS driver's TCP exchange. Skips loudly when the environment
//!   has no working multicast (probed with two raw drivers first).
//! - `two_peers_handshake_with_nostr_and_mdns_fanout`: both drivers
//!   attached (`strategy: "nostr"` against a self-hosted relay, plus
//!   `mdns: true`). Every offer/answer/candidate is emitted through
//!   BOTH transports, so the handshake completing at all proves the
//!   bridge's cross-driver dedup gate works — a duplicate
//!   `set_remote_description` wedges WebRTC permanently. This test
//!   passes with or without multicast (the relay path suffices).

use std::sync::Arc;
use std::time::Duration;

use myownmesh_core::config::{NetworkConfig, SignalingConfig, TopologyMode};
use myownmesh_core::engine::conn_trace::ConnTrace;
use myownmesh_core::engine::transport_lab::{
    attach_signaling, join_open_participation, spawn_network,
};
use myownmesh_core::identity::Identity;
use myownmesh_core::semantic::DeviceId;
use myownmesh_core::{MeshEvent, PeerEvent};
use myownmesh_signaling::mdns::driver::{
    AliasProvider, AliasRefusal, AliasRetention, ConnectionIdentityRetention, ConnectionRetention,
    PeerRetention,
};
use myownmesh_signaling::ErasedOwner;
use tokio::time::Instant;

/// Serializes the tests in this file — they mutate the process-wide
/// `MYOWNMESH_HOME`. Async-aware so holding it across the tests'
/// await points is well-defined.
static HOME_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn accept_any(_: &str) -> bool {
    true
}

struct TestAliasProvider;

impl AliasProvider for TestAliasProvider {
    fn retain_alias(
        &self,
        _key: &str,
        _peer: &str,
        _retention: AliasRetention,
    ) -> Result<ErasedOwner, AliasRefusal> {
        Ok(Box::new(()))
    }

    fn retain_peer(
        &self,
        _peer: &str,
        _retention: PeerRetention,
    ) -> Result<ErasedOwner, AliasRefusal> {
        Ok(Box::new(()))
    }

    fn retain_connection(
        &self,
        _peer: Option<&str>,
        _retention: ConnectionRetention,
    ) -> Result<ErasedOwner, AliasRefusal> {
        Ok(Box::new(()))
    }

    fn retain_connection_identity(
        &self,
        _peer: &str,
        _retention: ConnectionIdentityRetention,
    ) -> Result<ErasedOwner, AliasRefusal> {
        Ok(Box::new(()))
    }
}

fn network_config(id: &str, network_id: &str, signaling: SignalingConfig) -> NetworkConfig {
    NetworkConfig {
        id: id.to_string(),
        network_id: network_id.to_string(),
        label: id.to_string(),
        kind: Default::default(),
        topology: TopologyMode::FullMesh,
        signaling,
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        roster_path: None,
        pinned_peers: Vec::new(),
        auto_approve: true,
    }
}

/// Probe whether this environment supports same-host mDNS discovery
/// at all, using two raw drivers. CI containers frequently block
/// multicast; the driver- and engine-level mdns tests skip there.
async fn multicast_available() -> bool {
    use myownmesh_signaling::mdns::{self, MdnsDriverConfig, MdnsInbound, MdnsOutbound};
    use tokio::sync::mpsc;

    let network = format!("mdns-probe-{}", std::process::id());
    let cfg = |device: &str| MdnsDriverConfig {
        app_id: "myownmesh-mdns-probe".into(),
        network_id: network.clone(),
        device_id: device.into(),
        service_port: 0,
        device_id_validator: accept_any,
        alias_provider: Arc::new(TestAliasProvider),
        limits: myownmesh_signaling::mdns::driver::MdnsLimits::default(),
    };
    let (_a_out_tx, a_out_rx) = mpsc::unbounded_channel::<MdnsOutbound>();
    let (a_in_tx, mut a_in_rx) = mpsc::unbounded_channel::<MdnsInbound>();
    let (_b_out_tx, b_out_rx) = mpsc::unbounded_channel::<MdnsOutbound>();
    let (b_in_tx, _b_in_rx) = mpsc::unbounded_channel::<MdnsInbound>();
    let a_in = myownmesh_signaling::InboundSink::from_unbounded(a_in_tx);
    let b_in = myownmesh_signaling::InboundSink::from_unbounded(b_in_tx);
    let Ok(_a) = mdns::start(
        cfg("probe-a"),
        Box::new(myownmesh_signaling::UnboundedSource::new(a_out_rx)),
        a_in,
    ) else {
        return false;
    };
    let Ok(_b) = mdns::start(
        cfg("probe-b"),
        Box::new(myownmesh_signaling::UnboundedSource::new(b_out_rx)),
        b_in,
    ) else {
        return false;
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(200), a_in_rx.recv()).await {
            Ok(Some(MdnsInbound::PeerAnnounced { device_id, .. })) if device_id == "probe-b" => {
                return true;
            }
            Ok(Some(_)) => continue,
            Ok(None) => return false,
            Err(_) => continue,
        }
    }
    false
}

#[tokio::test]
async fn mdns_injected_core_validator_rejects_noncanonical_local_identity() {
    use myownmesh_signaling::mdns::{self, MdnsDriverConfig, MdnsInbound, MdnsOutbound};
    use tokio::sync::mpsc;

    let (_out_tx, out_rx) = mpsc::unbounded_channel::<MdnsOutbound>();
    let (in_tx, _in_rx) = mpsc::unbounded_channel::<MdnsInbound>();
    let invalid = format!("{}-display", Identity::ephemeral().public_id());
    let result = mdns::start(
        MdnsDriverConfig {
            app_id: "mdns-validator-test".into(),
            network_id: "validator-network".into(),
            device_id: invalid,
            service_port: 0,
            device_id_validator: |value| DeviceId::from_canonical_str(value).is_ok(),
            alias_provider: Arc::new(TestAliasProvider),
            limits: myownmesh_signaling::mdns::driver::MdnsLimits::default(),
        },
        Box::new(myownmesh_signaling::UnboundedSource::new(out_rx)),
        myownmesh_signaling::InboundSink::from_unbounded(in_tx),
    );
    assert!(
        result.is_err(),
        "noncanonical local identity must fail before publication"
    );
}

async fn wait_for_approval(
    side: &str,
    state: &Arc<myownmesh_core::engine::transport_lab::NetworkState>,
    rx: &mut tokio::sync::broadcast::Receiver<MeshEvent>,
    trace_rx: &mut tokio::sync::broadcast::Receiver<ConnTrace>,
    peer_id: &str,
    deadline: Duration,
) {
    let deadline = Instant::now() + deadline;
    let mut observed_events = std::collections::VecDeque::with_capacity(64);
    let mut observed_traces = std::collections::VecDeque::with_capacity(64);
    loop {
        if Instant::now() > deadline {
            while let Ok(trace) = trace_rx.try_recv() {
                if observed_traces.len() == 64 {
                    observed_traces.pop_front();
                }
                observed_traces.push_back(format!("{trace:?}"));
            }
            panic!(
                "{side} never saw PeerApproved for {peer_id}; phase={:?}; peer={:#?}; events={observed_events:#?}; traces={observed_traces:#?}",
                *state.current_phase.read(),
                state.peer_info(peer_id),
            );
        }
        let next = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await;
        match next {
            Ok(Ok(MeshEvent::Peer(PeerEvent::Approved { device_id, .. })))
                if device_id == peer_id =>
            {
                return;
            }
            Ok(Ok(event)) => {
                if observed_events.len() == 64 {
                    observed_events.pop_front();
                }
                observed_events.push_back(format!("{event:?}"));
            }
            Ok(Err(error)) => {
                if observed_events.len() == 64 {
                    observed_events.pop_front();
                }
                observed_events.push_back(format!("event receiver error: {error:?}"));
            }
            Err(_) => {}
        }
        while let Ok(trace) = trace_rx.try_recv() {
            if observed_traces.len() == 64 {
                observed_traces.pop_front();
            }
            observed_traces.push_back(format!("{trace:?}"));
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn two_peers_handshake_over_mdns_only() {
    let _guard = HOME_LOCK.lock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    std::env::set_var("MYOWNMESH_HOME", tmp.path());

    if !multicast_available().await {
        eprintln!(
            "SKIP two_peers_handshake_over_mdns_only: no same-host mDNS discovery here \
             (multicast blocked) — driver logic is covered by unit tests"
        );
        return;
    }

    let lan_only = SignalingConfig {
        strategy: "none".into(),
        mdns: true,
        ..SignalingConfig::default()
    };
    let network_id = format!("mdns-only-handshake-{}", std::process::id());

    let transport = support::test_transport();
    let alice_id = Arc::new(Identity::ephemeral());
    let bob_id = Arc::new(Identity::ephemeral());

    let (alice_state, _alice_driver) = spawn_network(
        network_config("alice", &network_id, lan_only.clone()),
        alice_id.clone(),
        transport.clone(),
    )
    .await
    .expect("alice engine");
    let (bob_state, _bob_driver) = spawn_network(
        network_config("bob", &network_id, lan_only),
        bob_id.clone(),
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
    let mut alice_traces = alice_state.subscribe_conn_trace();
    let mut bob_traces = bob_state.subscribe_conn_trace();

    let alice_drivers = attach_signaling(&alice_state)
        .expect("alice signaling resources")
        .expect("alice signaling");
    let bob_drivers = attach_signaling(&bob_state)
        .expect("bob signaling resources")
        .expect("bob signaling");
    assert_eq!(alice_drivers.describe(), "mdns");
    assert_eq!(bob_drivers.describe(), "mdns");

    // Full engine handshake — discovery, SDP over the TCP exchange,
    // WebRTC, ed25519 mutual auth — with zero remote infrastructure.
    wait_for_approval(
        "alice",
        &alice_state,
        &mut alice_events,
        &mut alice_traces,
        bob_id.public_id(),
        Duration::from_secs(60),
    )
    .await;
    wait_for_approval(
        "bob",
        &bob_state,
        &mut bob_events,
        &mut bob_traces,
        alice_id.public_id(),
        Duration::from_secs(60),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn two_peers_handshake_with_nostr_and_mdns_fanout() {
    let _guard = HOME_LOCK.lock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    std::env::set_var("MYOWNMESH_HOME", tmp.path());

    // Self-hosted relay so the Nostr driver needs no public
    // infrastructure either.
    let relay = myownmesh_signaling::server::SignalingServer::start(
        "127.0.0.1",
        0,
        myownmesh_signaling::server::Limits::default(),
    )
    .await
    .expect("relay");
    let relay_url = format!("ws://127.0.0.1:{}", relay.local_addr().port());

    let both = SignalingConfig {
        strategy: "nostr".into(),
        mdns: true,
        servers: vec![relay_url],
        public_fallback: false,
        ..SignalingConfig::default()
    };
    let network_id = format!("fanout-handshake-{}", std::process::id());

    let transport = support::test_transport();
    let alice_id = Arc::new(Identity::ephemeral());
    let bob_id = Arc::new(Identity::ephemeral());

    let (alice_state, alice_driver) = spawn_network(
        network_config("alice", &network_id, both.clone()),
        alice_id.clone(),
        transport.clone(),
    )
    .await
    .expect("alice engine");
    let (bob_state, bob_driver) = spawn_network(
        network_config("bob", &network_id, both),
        bob_id.clone(),
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
    let mut alice_traces = alice_state.subscribe_conn_trace();
    let mut bob_traces = bob_state.subscribe_conn_trace();

    let alice_drivers = attach_signaling(&alice_state)
        .expect("alice signaling resources")
        .expect("alice signaling");
    let bob_drivers = attach_signaling(&bob_state)
        .expect("bob signaling resources")
        .expect("bob signaling");
    // mDNS may or may not come up depending on the environment; the
    // Nostr side must. Either way the handshake has to complete —
    // and when both are up, completing proves the cross-driver dedup
    // gate (a doubly-applied offer wedges WebRTC).
    assert!(
        alice_drivers.describe().contains("nostr"),
        "nostr driver must attach, got {}",
        alice_drivers.describe()
    );
    let _ = &bob_drivers;

    wait_for_approval(
        "alice",
        &alice_state,
        &mut alice_events,
        &mut alice_traces,
        bob_id.public_id(),
        Duration::from_secs(60),
    )
    .await;
    wait_for_approval(
        "bob",
        &bob_state,
        &mut bob_events,
        &mut bob_traces,
        alice_id.public_id(),
        Duration::from_secs(60),
    )
    .await;

    bob_drivers.shutdown().await;
    alice_drivers.shutdown().await;
    alice_state.request_shutdown();
    bob_state.request_shutdown();
    alice_driver.await.expect("alice engine driver");
    bob_driver.await.expect("bob engine driver");
    relay.stop_and_wait().await;
}
mod support;
