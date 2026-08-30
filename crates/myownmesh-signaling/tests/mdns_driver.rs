//! Two mDNS drivers on one host discover each other and exchange a
//! directed signaling message — the driver-level proof that LAN
//! signaling works end to end (DNS-SD resolve → PeerAnnounced →
//! TCP exchange → Message).
//!
//! Multicast is not available in every environment (CI containers
//! frequently block it). When discovery doesn't happen inside the
//! grace window the test SKIPS — loudly — instead of failing, so the
//! suite stays deterministic; the wire-format logic is covered by
//! always-run unit tests in `mdns::wire`.

use std::time::Duration;

use myownmesh_signaling::mdns::driver::{
    AliasProvider, AliasRefusal, AliasRetention, ConnectionIdentityRetention, ConnectionRetention,
    PeerRetention,
};
use myownmesh_signaling::mdns::{self, MdnsDriverConfig, MdnsInbound, MdnsOutbound};
use myownmesh_signaling::{ErasedOwner, InboundSink, SignalingMessage, UnboundedSource};
use tokio::sync::mpsc;
use tokio::time::timeout;

/// How long we give same-host multicast discovery before deciding the
/// environment doesn't support it. Generous — resolution normally
/// lands in well under two seconds.
const DISCOVERY_GRACE: Duration = Duration::from_secs(15);

fn driver_config(network: &str, device: &str) -> MdnsDriverConfig {
    MdnsDriverConfig {
        app_id: "myownmesh-mdns-test".into(),
        network_id: network.into(),
        device_id: device.into(),
        service_port: 0,
        device_id_validator: accept_any,
        alias_provider: std::sync::Arc::new(TestAliasProvider),
        limits: myownmesh_signaling::mdns::driver::MdnsLimits::default(),
    }
}

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

struct CountingOwner(std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl Drop for CountingOwner {
    fn drop(&mut self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

struct RefusingAliasProvider;

impl AliasProvider for RefusingAliasProvider {
    fn retain_alias(
        &self,
        _key: &str,
        _peer: &str,
        _retention: AliasRetention,
    ) -> Result<ErasedOwner, AliasRefusal> {
        Err(AliasRefusal::Provider("capacity".into()))
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

#[test]
fn advertised_profile_excludes_other_room_and_recipient() {
    use myownmesh_signaling::mdns::wire::{frame_is_for_us, Frame, PROTOCOL_VERSION};

    let frame = Frame {
        v: PROTOCOL_VERSION,
        room: "room-a".into(),
        from: "peer-a".into(),
        to: "device-b".into(),
        msg: SignalingMessage::Offer {
            peer_id: "device-b".into(),
            offer_id: "attempt-1".into(),
            sdp: "v=0".into(),
        },
    };
    assert!(frame_is_for_us(&frame, "room-a", "device-b", accept_any));
    assert!(!frame_is_for_us(&frame, "room-b", "device-b", accept_any));
    assert!(!frame_is_for_us(&frame, "room-a", "device-c", accept_any));
}

#[test]
fn discovery_hints_are_bounded_and_coalesced_per_service_instance() {
    use myownmesh_signaling::mdns::discovery::{
        DiscoveryLimits, ResolveCompletion, ResolveHint, ResolveOwnership,
    };

    let ownership = ResolveOwnership::new();
    let first = match ownership.admit("service-a") {
        ResolveHint::Started(lease) => lease,
        other => panic!("first service hint was not admitted: {other:?}"),
    };
    assert_eq!(first.instance(), "service-a");
    assert_eq!(ownership.active_count(), 1);
    assert_eq!(ownership.pending_count(), 0);
    assert!(matches!(
        ownership.admit("service-a"),
        ResolveHint::Coalesced
    ));
    assert!(matches!(
        ownership.admit("service-a"),
        ResolveHint::Coalesced
    ));
    assert_eq!(ownership.active_count(), 1);
    assert_eq!(ownership.pending_count(), 1);

    let followup = match first.complete() {
        ResolveCompletion::Followup(lease) => lease,
        ResolveCompletion::Finished => panic!("coalesced hint lost its follow-up"),
    };
    assert_eq!(ownership.active_count(), 1);
    assert_eq!(ownership.pending_count(), 0);
    assert!(matches!(followup.complete(), ResolveCompletion::Finished));
    assert_eq!(ownership.active_count(), 0);

    let mut leases = Vec::new();
    let max_owners = DiscoveryLimits::default().max_resolve_owners;
    for index in 0..max_owners {
        match ownership.admit(format!("service-{index}")) {
            ResolveHint::Started(lease) => leases.push(lease),
            other => panic!("bounded service hint {index} was not admitted: {other:?}"),
        }
    }
    assert_eq!(ownership.active_count(), max_owners);
    assert!(matches!(
        ownership.admit("service-over-capacity"),
        ResolveHint::Refused
    ));
    ownership.shutdown();
    assert_eq!(ownership.active_count(), 0);
    assert_eq!(ownership.pending_count(), 0);
    drop(leases);
}

#[test]
fn discovery_hint_cancellation_fences_stale_service_instance_owners() {
    use myownmesh_signaling::mdns::discovery::{ResolveHint, ResolveOwnership};

    let ownership = ResolveOwnership::new();
    let stale = match ownership.admit("service-replaced") {
        ResolveHint::Started(lease) => lease,
        other => panic!("stale service hint was not admitted: {other:?}"),
    };
    assert!(matches!(
        ownership.admit("service-replaced"),
        ResolveHint::Coalesced
    ));
    assert!(ownership.cancel("service-replaced"));
    assert_eq!(ownership.active_count(), 0);
    assert_eq!(ownership.pending_count(), 0);

    let dropped = match ownership.admit("service-dropped") {
        ResolveHint::Started(lease) => lease,
        other => panic!("dropped service hint was not admitted: {other:?}"),
    };
    assert!(matches!(
        ownership.admit("service-dropped"),
        ResolveHint::Coalesced
    ));
    drop(dropped);
    assert_eq!(ownership.active_count(), 0);
    assert_eq!(ownership.pending_count(), 0);

    let current = match ownership.admit("service-replaced") {
        ResolveHint::Started(lease) => lease,
        other => panic!("replacement service hint was not admitted: {other:?}"),
    };
    assert!(
        !stale.cancel(),
        "stale generation cancelled the replacement"
    );
    assert_eq!(ownership.active_count(), 1);

    ownership.shutdown();
    assert_eq!(ownership.active_count(), 0);
    assert_eq!(ownership.pending_count(), 0);
    assert!(!current.cancel(), "shutdown left a live resolve owner");
}

#[test]
fn aliases_keep_a_peer_live_until_its_final_service_key_withdraws() {
    use myownmesh_signaling::mdns::AliasOwnership;

    let mut aliases = AliasOwnership::default();
    assert_eq!(
        aliases
            .bind("if-a".into(), "peer-a".into(), 1, Box::new(()))
            .unwrap(),
        None
    );
    assert_eq!(
        aliases
            .bind("if-b".into(), "peer-a".into(), 2, Box::new(()))
            .unwrap(),
        None
    );
    assert_eq!(aliases.alias_count("peer-a"), 2);
    assert_eq!(aliases.remove("if-a", 1), Some(("peer-a".into(), false)));
    assert_eq!(aliases.alias_count("peer-a"), 1);
    assert_eq!(aliases.remove("if-b", 2), Some(("peer-a".into(), true)));
    assert_eq!(aliases.alias_count("peer-a"), 0);
    assert_eq!(aliases.remove("if-b", 2), None);
}

#[test]
fn alias_replacement_withdraws_only_the_displaced_final_owner() {
    use myownmesh_signaling::mdns::AliasOwnership;

    let mut aliases = AliasOwnership::default();
    aliases
        .bind("shared".into(), "peer-old".into(), 1, Box::new(()))
        .unwrap();
    aliases
        .bind("other".into(), "peer-old".into(), 2, Box::new(()))
        .unwrap();
    assert_eq!(
        aliases
            .bind("shared".into(), "peer-new".into(), 3, Box::new(()))
            .unwrap(),
        None
    );
    assert_eq!(aliases.alias_count("peer-old"), 1);
    assert_eq!(aliases.alias_count("peer-new"), 1);
    assert_eq!(
        aliases.remove("shared", 1),
        None,
        "stale removal cannot delete successor"
    );
    assert_eq!(aliases.remove("other", 2), Some(("peer-old".into(), true)));
    assert_eq!(aliases.remove("shared", 3), Some(("peer-new".into(), true)));
}

#[test]
fn alias_provider_refusal_and_generation_fence_preserve_exact_state() {
    use myownmesh_signaling::mdns::driver::AliasOwnership;
    use std::sync::atomic::{AtomicUsize, Ordering};

    let released = std::sync::Arc::new(AtomicUsize::new(0));
    let mut aliases = AliasOwnership::default();
    aliases
        .bind(
            "stable".into(),
            "canonical-peer".into(),
            7,
            Box::new(CountingOwner(std::sync::Arc::clone(&released))),
        )
        .unwrap();
    assert_eq!(aliases.alias_count("canonical-peer"), 1);

    // A provider refusal occurs before bind, so the existing entry is not
    // altered and its owner remains live.
    let refused = RefusingAliasProvider.retain_alias(
        "stable",
        "replacement-peer",
        AliasRetention {
            key_capacity: 6,
            peer_capacity: 16,
            node_bytes: 1,
        },
    );
    assert!(refused.is_err());
    assert_eq!(aliases.alias_count("canonical-peer"), 1);
    assert_eq!(released.load(Ordering::SeqCst), 0);

    // The old generation cannot remove a replacement; the replacement's
    // owner is released only by its exact generation.
    aliases
        .bind(
            "stable".into(),
            "replacement-peer".into(),
            8,
            Box::new(CountingOwner(std::sync::Arc::clone(&released))),
        )
        .unwrap();
    assert_eq!(
        released.load(Ordering::SeqCst),
        1,
        "displaced owner released once"
    );
    assert!(aliases.remove("stable", 7).is_none());
    assert_eq!(aliases.alias_count("replacement-peer"), 1);
    assert!(aliases.remove("stable", 8).is_some());
    assert_eq!(released.load(Ordering::SeqCst), 2);
}

async fn wait_for_announce(
    rx: &mut mpsc::UnboundedReceiver<MdnsInbound>,
    expect_peer: &str,
) -> Option<()> {
    loop {
        match timeout(DISCOVERY_GRACE, rx.recv()).await {
            Ok(Some(MdnsInbound::PeerAnnounced { device_id, .. })) if device_id == expect_peer => {
                return Some(());
            }
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => return None,
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn two_drivers_discover_and_exchange() {
    let network = format!("mdns-driver-test-{}", std::process::id());

    let (a_out_tx, a_out_rx) = mpsc::unbounded_channel::<MdnsOutbound>();
    let (a_in_tx, mut a_in_rx) = mpsc::unbounded_channel::<MdnsInbound>();
    let (b_out_tx, b_out_rx) = mpsc::unbounded_channel::<MdnsOutbound>();
    let (b_in_tx, mut b_in_rx) = mpsc::unbounded_channel::<MdnsInbound>();

    let a_in = InboundSink::from_unbounded(a_in_tx);
    let b_in = InboundSink::from_unbounded(b_in_tx);

    let a = match mdns::start(
        driver_config(&network, "device-a"),
        Box::new(UnboundedSource::new(a_out_rx)),
        a_in,
    ) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP mdns_driver test: driver A failed to start ({e}) — no mDNS here");
            return;
        }
    };
    let b = match mdns::start(
        driver_config(&network, "device-b"),
        Box::new(UnboundedSource::new(b_out_rx)),
        b_in,
    ) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP mdns_driver test: driver B failed to start ({e}) — no mDNS here");
            return;
        }
    };

    // Mutual discovery. If multicast is blocked in this environment,
    // neither side ever resolves the other — skip.
    if wait_for_announce(&mut a_in_rx, "device-b").await.is_none() {
        eprintln!(
            "SKIP mdns_driver test: no discovery within {DISCOVERY_GRACE:?} — \
             multicast appears unavailable in this environment"
        );
        return;
    }
    wait_for_announce(&mut b_in_rx, "device-a")
        .await
        .expect("B discovers A once A has discovered B");

    // Directed exchange: A offers B over the TCP exchange.
    let offer = SignalingMessage::Offer {
        peer_id: "device-a".into(),
        offer_id: "offer-1".into(),
        sdp: "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n".into(),
    };
    a_out_tx
        .send(MdnsOutbound::DirectedToPeer {
            to: "device-b".into(),
            msg: offer.clone(),
        })
        .expect("outbound channel open");

    let got = loop {
        match timeout(DISCOVERY_GRACE, b_in_rx.recv()).await {
            Ok(Some(MdnsInbound::Message { from, msg })) => break (from, msg),
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => panic!("offer never arrived over the mdns TCP exchange"),
        }
    };
    assert_eq!(got.0, "device-a");
    assert_eq!(got.1, offer);

    // Withdrawal: B leaves; A hears PeerLeft via the mDNS goodbye.
    b_out_tx.send(MdnsOutbound::Leave).expect("channel open");
    let left = loop {
        match timeout(DISCOVERY_GRACE, a_in_rx.recv()).await {
            Ok(Some(MdnsInbound::PeerLeft { device_id, .. })) => break device_id,
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => panic!("goodbye never surfaced as PeerLeft"),
        }
    };
    assert_eq!(left, "device-b");

    a.stop_and_join().await;
    b.stop_and_join().await;
}
