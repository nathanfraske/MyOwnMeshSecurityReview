//! Behavioral controls for the closed-member relay.
//!
//! This module is included by `relay::tests`, so it can exercise the
//! crate-private admission and endpoint ports without widening the public API.
//! Every control uses real endpoint key agreement and a real provider-backed
//! relay allocation.

use super::*;

use crate::config::ClosedRelayPolicyConfig;
use crate::identity::Identity;
use crate::resource::{ResourceClaim, ResourceClass};
use crate::runtime::session_broker::{
    session_and_provider_for_test, session_funding_for_test, SessionCapability,
};
use crate::runtime::RuntimeIncarnation;
use crate::semantic::{DeviceId, MeshContextId};

fn profile() -> ClosedRelayPolicyConfig {
    ClosedRelayPolicyConfig {
        enabled: true,
        pending_handshake_timeout_ms: 30_000,
        ..ClosedRelayPolicyConfig::default()
    }
}

fn permit_claim(profile: &ClosedRelayPolicyConfig) -> ResourceClaim {
    RelayAllocationPermit::allocation_claim(profile).expect("test relay claim")
}

fn endpoint_fixture() -> (Identity, Identity, MeshContextId, DeviceId, DeviceId) {
    let requester = Identity::ephemeral();
    let target = Identity::ephemeral();
    let mesh = MeshContextId::from_bytes([3; 32]);
    let requester_id = DeviceId::from_canonical_str(requester.public_id()).expect("requester id");
    let target_id = DeviceId::from_canonical_str(target.public_id()).expect("target id");
    (requester, target, mesh, requester_id, target_id)
}

fn endpoint_sessions(
    profile: &ClosedRelayPolicyConfig,
    mesh: MeshContextId,
    session_id: [u8; 16],
    requester: &Identity,
    requester_id: DeviceId,
    target: &Identity,
    target_id: DeviceId,
) -> (OpaqueRelaySession, OpaqueRelaySession) {
    let (requester_pending, requester_share) =
        PendingEndpointKeyAgreement::begin(requester, mesh, target_id.clone(), session_id, profile)
            .expect("requester key share");
    let (target_pending, target_share) =
        PendingEndpointKeyAgreement::begin(target, mesh, requester_id, session_id, profile)
            .expect("target key share");
    (
        requester_pending
            .finish(&target_share)
            .expect("requester endpoint session"),
        target_pending
            .finish(&requester_share)
            .expect("target endpoint session"),
    )
}

fn funded_session(
    runtime: RuntimeIncarnation,
    profile: &ClosedRelayPolicyConfig,
) -> SessionCapability {
    session_funding_for_test(runtime, permit_claim(profile))
}

fn admitted_handle(
    profile: ClosedRelayPolicyConfig,
    requester: &SessionCapability,
    target: &SessionCapability,
    route: (MeshContextId, DeviceId, DeviceId, [u8; 16]),
    host_id: DeviceId,
) -> ClosedRelayHandle {
    let relay = ClosedRelayRuntime::new(profile.clone(), host_id).expect("relay runtime");
    let permit = RelayAllocationPermit::try_new(requester.validity_witness(), &profile)
        .expect("funded relay permit");
    let endpoints = ClosedRelayEndpoints::new(route.0, route.1, route.2, route.3, 1)
        .expect("exact relay endpoints");
    relay
        .admit_closed_relay(
            permit,
            requester.validity_witness(),
            target.validity_witness(),
            endpoints,
        )
        .expect("closed relay admission")
}

#[test]
fn closed_relay_key_agreement_rejects_tampered_signed_share() {
    let profile = profile();
    let (requester, target, mesh, requester_id, target_id) = endpoint_fixture();
    let (requester_pending, _requester_share) =
        PendingEndpointKeyAgreement::begin(&requester, mesh, target_id, [6; 16], &profile)
            .expect("requester key share");
    let (_, mut target_share) =
        PendingEndpointKeyAgreement::begin(&target, mesh, requester_id, [6; 16], &profile)
            .expect("target key share");
    target_share.signature.push('x');
    assert!(matches!(
        requester_pending.finish(&target_share),
        Err(ClosedRelayRefusal::Crypto(_))
    ));
}

#[tokio::test]
async fn closed_relay_forwards_opaque_ciphertext_both_directions_and_settles() {
    let profile = profile();
    let runtime = crate::runtime::runtime_for_test();
    let requester_owner = funded_session(runtime.clone(), &profile);
    let target_owner = session_funding_for_test(runtime, ResourceClaim::ZERO);
    let (requester, target, mesh, requester_id, target_id) = endpoint_fixture();
    let session_id = [7; 16];
    let (mut requester_session, mut target_session) = endpoint_sessions(
        &profile,
        mesh,
        session_id,
        &requester,
        requester_id.clone(),
        &target,
        target_id.clone(),
    );
    let mut relay = admitted_handle(
        profile,
        &requester_owner,
        &target_owner,
        (mesh, requester_id.clone(), target_id.clone(), session_id),
        DeviceId::from_canonical_str(Identity::ephemeral().public_id()).expect("relay id"),
    );

    let outbound = requester_session.seal(b"A-to-C").expect("requester seal");
    relay
        .try_forward(outbound)
        .expect("forward requester ciphertext");
    let delivered = relay
        .recv_checked()
        .await
        .expect("requester receive remains active")
        .expect("receive requester ciphertext");
    assert_eq!(
        target_session.open(&delivered).expect("target open"),
        b"A-to-C"
    );

    let reverse = target_session.seal(b"C-to-A").expect("target seal");
    relay
        .try_forward(reverse)
        .expect("forward target ciphertext");
    let delivered = relay
        .recv_checked()
        .await
        .expect("target receive remains active")
        .expect("receive target ciphertext");
    assert_eq!(
        requester_session.open(&delivered).expect("requester open"),
        b"C-to-A"
    );

    assert_eq!(relay.settle(), ClosedRelayTerminal::Settled);
}

#[tokio::test]
async fn closed_relay_rejects_route_tamper_and_endpoint_tamper_but_not_opaque_payload() {
    let profile = profile();
    let runtime = crate::runtime::runtime_for_test();
    let requester_owner = funded_session(runtime.clone(), &profile);
    let target_owner = session_funding_for_test(runtime, ResourceClaim::ZERO);
    let (requester, target, mesh, requester_id, target_id) = endpoint_fixture();
    let session_id = [8; 16];
    let (mut requester_session, mut target_session) = endpoint_sessions(
        &profile,
        mesh,
        session_id,
        &requester,
        requester_id.clone(),
        &target,
        target_id.clone(),
    );
    let host_id =
        DeviceId::from_canonical_str(Identity::ephemeral().public_id()).expect("relay id");
    let mut relay = admitted_handle(
        profile,
        &requester_owner,
        &target_owner,
        (mesh, requester_id.clone(), target_id.clone(), session_id),
        host_id,
    );

    let mut route_tamper = requester_session.seal(b"route").expect("seal route packet");
    route_tamper.to = requester_id.base32();
    assert!(matches!(
        relay.try_forward(route_tamper),
        Err(ClosedRelayRefusal::InvalidPacket(_))
    ));

    let mut ciphertext_tamper = requester_session
        .seal(b"tamper")
        .expect("seal tamper packet");
    ciphertext_tamper.ciphertext[0] ^= 1;
    relay
        .try_forward(ciphertext_tamper)
        .expect("relay forwards opaque ciphertext without endpoint keys");
    let tampered = relay
        .recv_checked()
        .await
        .expect("tampered receive remains active")
        .expect("receive tampered ciphertext");
    assert!(
        target_session.open(&tampered).is_err(),
        "endpoint AEAD must reject ciphertext tamper"
    );

    let packet = requester_session.seal(b"once").expect("seal replay packet");
    relay
        .try_forward(packet.clone())
        .expect("forward first packet");
    let first = relay
        .recv_checked()
        .await
        .expect("first receive remains active")
        .expect("receive first packet");
    assert_eq!(
        target_session.open(&first).expect("open first packet"),
        b"once"
    );
    relay
        .try_forward(packet)
        .expect("relay can carry opaque duplicate");
    let duplicate = relay
        .recv_checked()
        .await
        .expect("duplicate receive remains active")
        .expect("receive duplicate packet");
    assert!(
        target_session.open(&duplicate).is_err(),
        "endpoint replay window must reject the duplicate"
    );

    relay.settle();
}

#[tokio::test]
async fn closed_relay_queue_item_and_byte_pressure_refuse_without_losing_terminal_custody() {
    let (requester, target, mesh, requester_id, target_id) = endpoint_fixture();
    let runtime = crate::runtime::runtime_for_test();
    let mut item_profile = profile();
    item_profile.queue_items_per_direction = 1;
    item_profile.max_control_bytes = 1;
    let requester_owner = funded_session(runtime.clone(), &item_profile);
    let target_owner = session_funding_for_test(runtime, ResourceClaim::ZERO);
    let session_id = [9; 16];
    let (mut requester_session, _target_session) = endpoint_sessions(
        &item_profile,
        mesh,
        session_id,
        &requester,
        requester_id.clone(),
        &target,
        target_id.clone(),
    );
    let host_id =
        DeviceId::from_canonical_str(Identity::ephemeral().public_id()).expect("relay id");
    let mut item_relay = admitted_handle(
        item_profile,
        &requester_owner,
        &target_owner,
        (mesh, requester_id.clone(), target_id.clone(), session_id),
        host_id.clone(),
    );
    let control_packet = requester_session
        .seal(b"control")
        .expect("control packet seal");
    assert!(matches!(
        item_relay.try_forward_control(control_packet),
        Err(ClosedRelayRefusal::InvalidPacket(_))
    ));
    let first = requester_session.seal(b"first").expect("first seal");
    let second = requester_session.seal(b"second").expect("second seal");
    item_relay.try_forward(first).expect("first queue item");
    assert_eq!(
        item_relay.try_forward(second),
        Err(ClosedRelayRefusal::QueueFull)
    );
    let _ = item_relay
        .recv_checked()
        .await
        .expect("item receive remains active")
        .expect("queued first item");
    item_relay.settle();

    let mut byte_profile = profile();
    byte_profile.queue_items_per_direction = 4;
    byte_profile.queue_bytes_per_direction = 1;
    let byte_runtime = crate::runtime::runtime_for_test();
    let byte_owner = funded_session(byte_runtime.clone(), &byte_profile);
    let byte_target = session_funding_for_test(byte_runtime, ResourceClaim::ZERO);
    let mut byte_relay = admitted_handle(
        byte_profile.clone(),
        &byte_owner,
        &byte_target,
        (mesh, requester_id, target_id, [10; 16]),
        host_id,
    );
    let mut byte_requester = endpoint_sessions(
        &byte_profile,
        mesh,
        [10; 16],
        &requester,
        DeviceId::from_canonical_str(requester.public_id()).expect("requester id"),
        &target,
        DeviceId::from_canonical_str(target.public_id()).expect("target id"),
    )
    .0;
    let oversized_for_queue = byte_requester
        .seal(b"more-than-one-byte")
        .expect("byte seal");
    assert_eq!(
        byte_relay.try_forward(oversized_for_queue),
        Err(ClosedRelayRefusal::QueueFull)
    );
    byte_relay.settle();
}

#[test]
fn closed_relay_rejects_zero_limits_and_releases_provider_backed_settlement() {
    let fields = [
        ClosedRelayPolicyConfig {
            max_allocations: 0,
            pending_handshake_timeout_ms: profile().pending_handshake_timeout_ms,
            ..profile()
        },
        ClosedRelayPolicyConfig {
            max_allocations_per_member: 0,
            pending_handshake_timeout_ms: profile().pending_handshake_timeout_ms,
            ..profile()
        },
        ClosedRelayPolicyConfig {
            max_pending_handshakes: 0,
            pending_handshake_timeout_ms: profile().pending_handshake_timeout_ms,
            ..profile()
        },
        ClosedRelayPolicyConfig {
            replay_window: 0,
            pending_handshake_timeout_ms: profile().pending_handshake_timeout_ms,
            ..profile()
        },
        ClosedRelayPolicyConfig {
            max_frame_ciphertext_bytes: 0,
            pending_handshake_timeout_ms: profile().pending_handshake_timeout_ms,
            ..profile()
        },
        ClosedRelayPolicyConfig {
            queue_items_per_direction: 0,
            pending_handshake_timeout_ms: profile().pending_handshake_timeout_ms,
            ..profile()
        },
        ClosedRelayPolicyConfig {
            queue_bytes_per_direction: 0,
            pending_handshake_timeout_ms: profile().pending_handshake_timeout_ms,
            ..profile()
        },
        ClosedRelayPolicyConfig {
            bandwidth_rate_bytes_per_second: 0,
            pending_handshake_timeout_ms: profile().pending_handshake_timeout_ms,
            ..profile()
        },
        ClosedRelayPolicyConfig {
            bandwidth_burst_bytes: 0,
            pending_handshake_timeout_ms: profile().pending_handshake_timeout_ms,
            ..profile()
        },
        ClosedRelayPolicyConfig {
            idle_timeout_ms: 0,
            pending_handshake_timeout_ms: profile().pending_handshake_timeout_ms,
            ..profile()
        },
        ClosedRelayPolicyConfig {
            max_lifetime_ms: 0,
            pending_handshake_timeout_ms: profile().pending_handshake_timeout_ms,
            ..profile()
        },
        ClosedRelayPolicyConfig {
            max_control_bytes: 0,
            pending_handshake_timeout_ms: profile().pending_handshake_timeout_ms,
            ..profile()
        },
        ClosedRelayPolicyConfig {
            shutdown_grace_ms: 0,
            pending_handshake_timeout_ms: profile().pending_handshake_timeout_ms,
            ..profile()
        },
    ];
    let host_id =
        DeviceId::from_canonical_str(Identity::ephemeral().public_id()).expect("relay id");
    for invalid in fields {
        assert!(!invalid.validate());
        assert!(matches!(
            ClosedRelayRuntime::new(invalid, host_id.clone()),
            Err(ClosedRelayRefusal::InvalidProfile)
        ));
    }

    let valid = profile();
    let runtime = crate::runtime::runtime_for_test();
    let (owner, provider) = session_and_provider_for_test(runtime.clone(), permit_claim(&valid));
    let target = session_funding_for_test(runtime, ResourceClaim::ZERO);
    let baseline = provider.in_use();
    let (_, _, mesh, requester_id, target_id) = endpoint_fixture();
    let permit = RelayAllocationPermit::try_new(owner.validity_witness(), &valid)
        .expect("provider-backed permit");
    let after_permit = provider.in_use();
    let planned =
        crate::resource::FiniteResourceProvider::reservation_charge_for_test(permit_claim(&valid))
            .expect("the provider's permit reservation record is representable");
    for dimension in [
        ResourceClass::AccountedMemoryBytes,
        ResourceClass::QueuedBytes,
        ResourceClass::OpaqueDependencyResidual,
    ] {
        assert_eq!(
            after_permit.amount(dimension),
            baseline
                .amount(dimension)
                .checked_add(planned.amount(dimension))
                .expect("planned relay claim fits"),
            "relay permit must charge the exact {dimension:?} claim",
        );
    }
    let relay = ClosedRelayRuntime::new(
        valid,
        DeviceId::from_canonical_str(Identity::ephemeral().public_id()).expect("relay id"),
    )
    .expect("relay runtime");
    let handle = relay
        .admit_closed_relay(
            permit,
            owner.validity_witness(),
            target.validity_witness(),
            ClosedRelayEndpoints::new(mesh, requester_id, target_id, [11; 16], 1)
                .expect("relay endpoints"),
        )
        .expect("relay admission");
    assert_eq!(handle.settle(), ClosedRelayTerminal::Settled);
    assert_ne!(provider.in_use(), baseline);
    drop(relay);
    assert_eq!(provider.in_use(), baseline);
}

#[tokio::test]
async fn closed_relay_expiry_is_a_consumable_terminal_and_releases_exact_claim() {
    let valid = profile();
    let runtime = crate::runtime::runtime_for_test();
    let (owner, provider) = session_and_provider_for_test(runtime.clone(), permit_claim(&valid));
    let target = session_funding_for_test(runtime, ResourceClaim::ZERO);
    let baseline = provider.in_use();
    let (_, _, mesh, requester_id, target_id) = endpoint_fixture();
    let mut relay = admitted_handle(
        valid.clone(),
        &owner,
        &target,
        (mesh, requester_id, target_id, [16; 16]),
        DeviceId::from_canonical_str(Identity::ephemeral().public_id()).expect("relay id"),
    );
    relay.last_activity = Instant::now()
        .checked_sub(relay.idle_timeout)
        .expect("test clock can represent the configured idle interval");
    assert_eq!(
        relay
            .recv_direction_checked(RelayDirection::RequesterToTarget)
            .await,
        Err(ClosedRelayRefusal::Expired)
    );
    assert_eq!(relay.settle(), ClosedRelayTerminal::Settled);
    assert_eq!(provider.in_use(), baseline);
}

#[test]
fn closed_relay_pending_handshake_and_allocation_limits_release_exact_slots() {
    let mut profile = profile();
    profile.max_pending_handshakes = 1;
    profile.max_allocations = 1;
    profile.max_allocations_per_member = 1;
    let runtime = crate::runtime::runtime_for_test();
    let first_owner = funded_session(runtime.clone(), &profile);
    let second_owner = funded_session(runtime.clone(), &profile);
    let target = session_funding_for_test(runtime, ResourceClaim::ZERO);

    let relay = ClosedRelayRuntime::new(
        profile.clone(),
        DeviceId::from_canonical_str(Identity::ephemeral().public_id()).expect("relay id"),
    )
    .expect("relay runtime");
    let first_handshake = relay
        .try_begin_handshake()
        .expect("first pending handshake");
    assert!(matches!(
        relay.try_begin_handshake(),
        Err(ClosedRelayRefusal::QueueFull)
    ));
    drop(first_handshake);
    let second_handshake = relay
        .try_begin_handshake()
        .expect("released handshake slot");
    drop(second_handshake);

    let (_, _, mesh, requester_id, target_id) = endpoint_fixture();
    let first_permit = RelayAllocationPermit::try_new(first_owner.validity_witness(), &profile)
        .expect("first allocation permit");
    let first = relay
        .admit_closed_relay(
            first_permit,
            first_owner.validity_witness(),
            target.validity_witness(),
            ClosedRelayEndpoints::new(mesh, requester_id.clone(), target_id.clone(), [12; 16], 1)
                .expect("first endpoints"),
        )
        .expect("first allocation");
    let second_permit = RelayAllocationPermit::try_new(second_owner.validity_witness(), &profile)
        .expect("second allocation permit");
    assert!(matches!(
        relay.admit_closed_relay(
            second_permit,
            second_owner.validity_witness(),
            target.validity_witness(),
            ClosedRelayEndpoints::new(mesh, requester_id.clone(), target_id.clone(), [13; 16], 2)
                .expect("second endpoints"),
        ),
        Err(ClosedRelayRefusal::QueueFull)
    ));
    assert_eq!(first.settle(), ClosedRelayTerminal::Settled);

    let replacement_permit =
        RelayAllocationPermit::try_new(first_owner.validity_witness(), &profile)
            .expect("replacement allocation permit");
    let replacement = relay
        .admit_closed_relay(
            replacement_permit,
            first_owner.validity_witness(),
            target.validity_witness(),
            ClosedRelayEndpoints::new(mesh, requester_id, target_id, [14; 16], 3)
                .expect("replacement endpoints"),
        )
        .expect("released allocation slot");
    assert_eq!(replacement.settle(), ClosedRelayTerminal::Settled);
}

#[test]
fn closed_relay_refuses_stale_exact_session_witness() {
    let profile = profile();
    let runtime = crate::runtime::runtime_for_test();
    let requester = funded_session(runtime.clone(), &profile);
    let target = session_funding_for_test(runtime, ResourceClaim::ZERO);
    let stale = requester.validity_witness();
    let permit = RelayAllocationPermit::try_new(stale.clone(), &profile)
        .expect("live session can fund a relay permit");
    drop(requester);

    let relay = ClosedRelayRuntime::new(
        profile.clone(),
        DeviceId::from_canonical_str(Identity::ephemeral().public_id()).expect("relay id"),
    )
    .expect("relay runtime");
    assert!(!stale.is_live());
    let (_, _, mesh, requester_id, target_id) = endpoint_fixture();
    let endpoints = ClosedRelayEndpoints::new(mesh, requester_id, target_id, [15; 16], 1)
        .expect("stale-session endpoints");
    assert!(matches!(
        relay.admit_closed_relay(permit, stale.clone(), target.validity_witness(), endpoints,),
        Err(ClosedRelayRefusal::OwnerNotLive)
    ));
}

#[test]
fn closed_relay_epoch_allows_bounded_reuse_after_exact_settlement() {
    let profile = ClosedRelayPolicyConfig {
        max_allocations: 1,
        max_allocations_per_member: 1,
        pending_handshake_timeout_ms: profile().pending_handshake_timeout_ms,
        ..profile()
    };
    let runtime = crate::runtime::runtime_for_test();
    let (owner, provider) = session_and_provider_for_test(runtime.clone(), permit_claim(&profile));
    let target = session_funding_for_test(runtime, ResourceClaim::ZERO);
    let baseline = provider.in_use();
    let (_, _, mesh, requester_id, target_id) = endpoint_fixture();
    let host_id =
        DeviceId::from_canonical_str(Identity::ephemeral().public_id()).expect("relay id");
    let session_id = [17; 16];
    let relay = ClosedRelayRuntime::new(profile.clone(), host_id).expect("relay runtime");
    let permit = RelayAllocationPermit::try_new(owner.validity_witness(), &profile)
        .expect("provider-backed relay permit");
    let handle = relay
        .admit_closed_relay(
            permit,
            owner.validity_witness(),
            target.validity_witness(),
            ClosedRelayEndpoints::new(mesh, requester_id.clone(), target_id.clone(), session_id, 1)
                .expect("relay endpoints"),
        )
        .expect("relay admission");
    let duplicate_permit = RelayAllocationPermit::try_new(owner.validity_witness(), &profile)
        .expect("duplicate attempt is independently funded before admission");
    assert!(matches!(
        relay.admit_closed_relay(
            duplicate_permit,
            owner.validity_witness(),
            target.validity_witness(),
            ClosedRelayEndpoints::new(mesh, requester_id.clone(), target_id.clone(), session_id, 1)
                .expect("duplicate relay endpoints"),
        ),
        Err(ClosedRelayRefusal::OwnerMismatch)
    ));
    assert_eq!(relay.terminal_tombstone_epoch(session_id), None);
    assert_eq!(handle.settle(), ClosedRelayTerminal::Settled);
    assert_eq!(relay.terminal_tombstone_epoch(session_id), Some(1));
    assert_eq!(provider.in_use(), baseline);
    let replacement_permit = RelayAllocationPermit::try_new(owner.validity_witness(), &profile)
        .expect("replacement permit is independently funded before admission");
    let replacement = relay
        .admit_closed_relay(
            replacement_permit,
            owner.validity_witness(),
            target.validity_witness(),
            ClosedRelayEndpoints::new(mesh, requester_id.clone(), target_id.clone(), session_id, 2)
                .expect("reused relay endpoints"),
        )
        .expect("same session id is reusable with a fresh epoch");
    let delayed_duplicate_permit =
        RelayAllocationPermit::try_new(owner.validity_witness(), &profile)
            .expect("delayed duplicate is independently funded before admission");
    assert!(matches!(
        relay.admit_closed_relay(
            delayed_duplicate_permit,
            owner.validity_witness(),
            target.validity_witness(),
            ClosedRelayEndpoints::new(mesh, requester_id, target_id, session_id, 1)
                .expect("delayed duplicate relay endpoints"),
        ),
        Err(ClosedRelayRefusal::OwnerMismatch)
    ));
    assert_eq!(relay.terminal_tombstone_epoch(session_id), Some(1));
    assert_eq!(replacement.settle(), ClosedRelayTerminal::Settled);
    drop(relay);
    assert_eq!(provider.in_use(), baseline);
}
