//! Public protocol/resource boundary controls for Closed-member relay sizing.
//!
//! The relay allocation claim itself is intentionally crate-private: creating
//! one requires a live session witness. These controls therefore exercise the
//! public, protocol-derived sizing and profile refusal boundary, while the
//! in-crate relay tests cover provider-backed permit admission and settlement.

use myownmesh_core::config::ClosedRelayPolicyConfig;
use myownmesh_core::identity::Identity;
use myownmesh_core::protocol::relay::{
    closed_relay_worst_case_json_bytes, OpaqueRelayPacket, OPAQUE_RELAY_MAX_PLAINTEXT_BYTES,
    OPAQUE_RELAY_NONCE_BYTES, OPAQUE_RELAY_SESSION_BYTES, OPAQUE_RELAY_VERSION,
};
use myownmesh_core::resource::{FiniteResourceProvider, ResourceClaim};
use myownmesh_core::semantic::MeshContextId;

#[test]
fn closed_relay_public_sizing_rejects_max_plus_one_and_preserves_baseline() {
    let provider = FiniteResourceProvider::new(ResourceClaim::ZERO);
    let baseline = provider.in_use();
    let profile = ClosedRelayPolicyConfig::default();
    assert!(profile.validate(), "default relay profile must be finite");

    let requester = Identity::ephemeral();
    let target = Identity::ephemeral();
    let mesh = MeshContextId::from_bytes([0x42; 32]);
    let requester_id = requester.public_id().to_string();
    let target_id = target.public_id().to_string();
    let mesh_id = mesh.base32();
    assert_eq!(
        requester_id.len(),
        52,
        "canonical endpoint strings are bounded"
    );
    assert_eq!(
        target_id.len(),
        52,
        "canonical endpoint strings are bounded"
    );
    assert_eq!(mesh_id.len(), 52, "canonical mesh strings are bounded");

    let max_plaintext = usize::try_from(OPAQUE_RELAY_MAX_PLAINTEXT_BYTES)
        .expect("protocol plaintext ceiling fits usize");
    let max_ciphertext = max_plaintext
        .checked_add(16)
        .expect("AEAD tag fits the packet bound");
    let packet = OpaqueRelayPacket {
        version: OPAQUE_RELAY_VERSION,
        mesh: mesh_id.clone(),
        session_id: [0x11; OPAQUE_RELAY_SESSION_BYTES],
        from: requester_id.clone(),
        to: target_id.clone(),
        sequence: 0,
        nonce: [0x22; OPAQUE_RELAY_NONCE_BYTES],
        ciphertext: vec![0xa5; max_ciphertext],
    };
    assert!(packet.validate(max_ciphertext).is_ok());
    assert!(packet.validate(max_ciphertext - 1).is_err());
    let encoded = serde_json::to_vec(&packet).expect("opaque packet serializes");
    let worst_case = closed_relay_worst_case_json_bytes(
        u64::try_from(max_ciphertext).expect("ciphertext length fits u64"),
    )
    .expect("wire sizing is representable");
    assert!(
        u64::try_from(encoded.len()).expect("encoded packet length fits u64") <= worst_case,
        "protocol-derived String/ciphertext sizing must cover the encoded packet"
    );

    let mut over_packet = packet.clone();
    over_packet.ciphertext.push(0x5a);
    assert!(over_packet.validate(max_ciphertext).is_err());

    let mut over_plaintext_profile = profile.clone();
    over_plaintext_profile.max_frame_ciphertext_bytes = OPAQUE_RELAY_MAX_PLAINTEXT_BYTES + 1;
    assert!(
        !over_plaintext_profile.validate(),
        "plaintext ceiling max+1 must be refused"
    );

    let replay_max =
        u64::try_from(tokio::sync::Semaphore::MAX_PERMITS).expect("Tokio replay bound fits u64");
    let exact_replay_profile = ClosedRelayPolicyConfig {
        replay_window: replay_max,
        pending_handshake_timeout_ms: profile.pending_handshake_timeout_ms,
        ..profile.clone()
    };
    assert!(
        exact_replay_profile.validate(),
        "exact replay allocation bound is valid"
    );
    let above_replay_profile = ClosedRelayPolicyConfig {
        replay_window: replay_max
            .checked_add(1)
            .expect("Tokio replay bound has a max+1 value"),
        pending_handshake_timeout_ms: profile.pending_handshake_timeout_ms,
        ..profile
    };
    assert!(
        !above_replay_profile.validate(),
        "replay-window allocation max+1 must be refused"
    );

    // Public sizing/validation does not acquire relay custody. The actual
    // provider-backed permit and its exact settlement are covered in the
    // crate-private relay behavior controls.
    assert_eq!(provider.in_use(), baseline);
}
