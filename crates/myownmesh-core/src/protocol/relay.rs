//! Closed-member opaque relay wire values.
//!
//! These values deliberately contain routing metadata and ciphertext only.
//! The relay can validate and forward them, but it has no endpoint key or
//! authority-bearing capability with which to decrypt or mint a session.

use serde::{Deserialize, Serialize};

use crate::semantic::{DeviceId, MeshContextId};

pub const OPAQUE_RELAY_VERSION: u8 = 1;
pub const OPAQUE_RELAY_NONCE_BYTES: usize = 12;
pub const OPAQUE_RELAY_SESSION_BYTES: usize = 16;
pub const OPAQUE_RELAY_EPHEMERAL_KEY_BYTES: usize = 32;
pub const CLOSED_RELAY_CONTROL_VERSION: u8 = 1;
pub const OPAQUE_RELAY_MAX_MESH_BYTES: usize = 256;
pub const OPAQUE_RELAY_MAX_SIGNATURE_BYTES: usize = 256;

/// The current WebRTC/SCTP user-message budget accepted by the SCTP writer.
pub const CLOSED_RELAY_SCTP_USER_MESSAGE_BYTES: u64 = 65_536;
/// The largest user message the WebRTC 0.13 data-channel receive callback can
/// deliver. Its read loop uses a 65,535-byte buffer, so this is the effective
/// relay ceiling even though the SCTP writer accepts one more byte.
pub const CLOSED_RELAY_WEBRTC_CALLBACK_BYTES: u64 = 65_535;
/// AES-GCM appends this many bytes to every endpoint plaintext.
pub const CLOSED_RELAY_AEAD_TAG_BYTES: u64 = 16;
/// Conservative compact-JSON envelope overhead for one `ClosedRelayData`.
///
/// Every ciphertext byte can occupy up to three JSON digits plus a comma;
/// this fixed term covers the route, nonce, session, and JSON punctuation.
pub const CLOSED_RELAY_JSON_ENVELOPE_OVERHEAD_BYTES: u64 = 772;
/// Maximum plaintext that keeps the complete worst-case JSON message within
/// the receive-safe WebRTC callback budget. The writer's SCTP ceiling is one
/// byte larger, but a message that reaches it cannot be delivered by the
/// callback read loop:
/// `4 * (plaintext + AEAD tag) + envelope overhead <= callback budget`.
pub const CLOSED_RELAY_MAX_PLAINTEXT_BYTES: u64 =
    (CLOSED_RELAY_WEBRTC_CALLBACK_BYTES - CLOSED_RELAY_JSON_ENVELOPE_OVERHEAD_BYTES) / 4
        - CLOSED_RELAY_AEAD_TAG_BYTES;

/// Conservative worst-case compact-JSON size for a ciphertext array.
pub const fn closed_relay_worst_case_json_bytes(ciphertext_len: u64) -> Option<u64> {
    match ciphertext_len.checked_mul(4) {
        Some(bytes) => bytes.checked_add(CLOSED_RELAY_JSON_ENVELOPE_OVERHEAD_BYTES),
        None => None,
    }
}

/// An authenticated endpoint key share. The signature covers every field
/// except `signature`, including both endpoint identities and the session
/// nonce, so a visible relay cannot substitute an endpoint or session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayKeyShare {
    pub version: u8,
    pub mesh: String,
    pub session_id: [u8; OPAQUE_RELAY_SESSION_BYTES],
    pub from: String,
    pub to: String,
    pub ephemeral_public: [u8; OPAQUE_RELAY_EPHEMERAL_KEY_BYTES],
    pub signature: String,
}

impl RelayKeyShare {
    pub(crate) fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            32 + self.mesh.len() + self.from.len() + self.to.len() + self.ephemeral_public.len(),
        );
        bytes.extend_from_slice(b"myownmesh-closed-opaque-relay-key-v1:");
        bytes.push(self.version);
        push_field(&mut bytes, self.mesh.as_bytes());
        bytes.extend_from_slice(&self.session_id);
        push_field(&mut bytes, self.from.as_bytes());
        push_field(&mut bytes, self.to.as_bytes());
        bytes.extend_from_slice(&self.ephemeral_public);
        bytes
    }

    /// Cheap structural validation before signature verification or key work.
    pub fn validate(&self) -> Result<(), String> {
        if self.version != OPAQUE_RELAY_VERSION {
            return Err("unsupported opaque relay key-share version".into());
        }
        if self.mesh.is_empty() || self.mesh.len() > OPAQUE_RELAY_MAX_MESH_BYTES {
            return Err("opaque relay mesh context is empty or oversized".into());
        }
        crate::semantic::DeviceId::from_canonical_str(&self.from)
            .map_err(|error| format!("invalid key-share sender: {error}"))?;
        crate::semantic::DeviceId::from_canonical_str(&self.to)
            .map_err(|error| format!("invalid key-share recipient: {error}"))?;
        if self.from == self.to {
            return Err("opaque relay endpoints must be distinct".into());
        }
        if self.ephemeral_public.iter().all(|byte| *byte == 0) {
            return Err("opaque relay ephemeral key is all zero".into());
        }
        if self.signature.is_empty() || self.signature.len() > OPAQUE_RELAY_MAX_SIGNATURE_BYTES {
            return Err("opaque relay key-share signature is empty or oversized".into());
        }
        Ok(())
    }
}

/// End-to-end ciphertext routed through a visible relay.
///
/// `from`, `to`, `mesh`, and `session_id` are routing/binding metadata only;
/// they are authenticated by the endpoint key-share exchange and AEAD AAD.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OpaqueRelayPacket {
    pub version: u8,
    pub mesh: String,
    pub session_id: [u8; OPAQUE_RELAY_SESSION_BYTES],
    pub from: String,
    pub to: String,
    pub sequence: u64,
    pub nonce: [u8; OPAQUE_RELAY_NONCE_BYTES],
    pub ciphertext: Vec<u8>,
}

impl OpaqueRelayPacket {
    /// Validate route metadata and the configured ciphertext bound. This does
    /// not authenticate the packet; the endpoint session does that on open.
    pub fn validate(&self, max_ciphertext_bytes: usize) -> Result<(), String> {
        if self.version != OPAQUE_RELAY_VERSION {
            return Err("unsupported opaque relay packet version".into());
        }
        if self.mesh.is_empty() || self.mesh.len() > OPAQUE_RELAY_MAX_MESH_BYTES {
            return Err("opaque relay mesh context is empty or oversized".into());
        }
        crate::semantic::DeviceId::from_canonical_str(&self.from)
            .map_err(|error| format!("invalid packet sender: {error}"))?;
        crate::semantic::DeviceId::from_canonical_str(&self.to)
            .map_err(|error| format!("invalid packet recipient: {error}"))?;
        if self.from == self.to {
            return Err("opaque relay endpoints must be distinct".into());
        }
        if self.ciphertext.is_empty() || self.ciphertext.len() > max_ciphertext_bytes {
            return Err("opaque relay ciphertext exceeds configured bound".into());
        }
        Ok(())
    }
}

/// A typed control for one exact Closed relay allocation.
///
/// Every control repeats the complete semantic binding.  The relay may use
/// that binding to route one allocation, but it cannot turn any field into a
/// peer lookup, a fan-out selector, or a recursive next hop.  Endpoint key
/// material appears only as an authenticated [`RelayKeyShare`]; no raw
/// address or endpoint secret is representable here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClosedRelayControl {
    /// The requester opens one route through the exact local relay to target.
    Open {
        version: u8,
        context_id: MeshContextId,
        requester: DeviceId,
        relay: DeviceId,
        target: DeviceId,
        session_id: [u8; OPAQUE_RELAY_SESSION_BYTES],
        requester_share: RelayKeyShare,
    },
    /// The relay forwards the requester's authenticated share to the target.
    Offer {
        version: u8,
        context_id: MeshContextId,
        requester: DeviceId,
        relay: DeviceId,
        target: DeviceId,
        session_id: [u8; OPAQUE_RELAY_SESSION_BYTES],
        allocation_epoch: u64,
        requester_share: RelayKeyShare,
    },
    /// The target accepts the exact route and returns its endpoint share.
    Accept {
        version: u8,
        context_id: MeshContextId,
        requester: DeviceId,
        relay: DeviceId,
        target: DeviceId,
        session_id: [u8; OPAQUE_RELAY_SESSION_BYTES],
        allocation_epoch: u64,
        target_share: RelayKeyShare,
    },
    /// Close the exact route and session.  There is no peer selector or
    /// free-form reason that could be mistaken for another route identity.
    Close {
        version: u8,
        context_id: MeshContextId,
        requester: DeviceId,
        relay: DeviceId,
        target: DeviceId,
        session_id: [u8; OPAQUE_RELAY_SESSION_BYTES],
        allocation_epoch: u64,
    },
}

/// The complete, exact identity of one Closed relay route.
///
/// This is deliberately separate from any one control operation so pending
/// consumption can compare every binding field without resolving a peer by
/// device id or accepting a partial route match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosedRelayRoute {
    pub context_id: MeshContextId,
    pub requester: DeviceId,
    pub relay: DeviceId,
    pub target: DeviceId,
    pub session_id: [u8; OPAQUE_RELAY_SESSION_BYTES],
    /// Checked epoch minted by the relay for this allocation. Open routes
    /// use zero because admission has not happened yet.
    pub allocation_epoch: u64,
}

impl ClosedRelayRoute {
    pub fn new(
        context_id: MeshContextId,
        requester: DeviceId,
        relay: DeviceId,
        target: DeviceId,
        session_id: [u8; OPAQUE_RELAY_SESSION_BYTES],
    ) -> Self {
        Self::with_epoch(context_id, requester, relay, target, session_id, 0)
    }

    pub fn with_epoch(
        context_id: MeshContextId,
        requester: DeviceId,
        relay: DeviceId,
        target: DeviceId,
        session_id: [u8; OPAQUE_RELAY_SESSION_BYTES],
        allocation_epoch: u64,
    ) -> Self {
        Self {
            context_id,
            requester,
            relay,
            target,
            session_id,
            allocation_epoch,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        validate_binding(
            CLOSED_RELAY_CONTROL_VERSION,
            &self.context_id,
            &self.requester,
            &self.relay,
            &self.target,
            &self.session_id,
        )
    }
}

impl ClosedRelayControl {
    /// Return the complete route identity carried by this operation.
    pub fn route(&self) -> ClosedRelayRoute {
        match self {
            Self::Open {
                context_id,
                requester,
                relay,
                target,
                session_id,
                ..
            } => ClosedRelayRoute::new(
                *context_id,
                requester.clone(),
                relay.clone(),
                target.clone(),
                *session_id,
            ),
            Self::Offer {
                context_id,
                requester,
                relay,
                target,
                session_id,
                allocation_epoch,
                ..
            } => ClosedRelayRoute::with_epoch(
                *context_id,
                requester.clone(),
                relay.clone(),
                target.clone(),
                *session_id,
                *allocation_epoch,
            ),
            Self::Accept {
                context_id,
                requester,
                relay,
                target,
                session_id,
                allocation_epoch,
                ..
            }
            | Self::Close {
                context_id,
                requester,
                relay,
                target,
                session_id,
                allocation_epoch,
                ..
            } => ClosedRelayRoute::with_epoch(
                *context_id,
                requester.clone(),
                relay.clone(),
                target.clone(),
                *session_id,
                *allocation_epoch,
            ),
        }
    }

    /// Compare every route field exactly, suitable for pending-record
    /// consumption before any operation-specific handling.
    pub fn matches_route(&self, expected: &ClosedRelayRoute) -> bool {
        self.route() == *expected
    }

    pub fn validate_against_route(&self, expected: &ClosedRelayRoute) -> Result<(), String> {
        self.validate()?;
        expected.validate()?;
        if self.matches_route(expected) {
            Ok(())
        } else {
            Err("closed relay control does not match the exact route".into())
        }
    }

    /// Return the complete serialized MeshMessage size, including its kind
    /// envelope, before a configured control-byte ceiling is applied.
    pub fn encoded_len(&self) -> Result<usize, String> {
        serde_json::to_vec(&crate::protocol::MeshMessage::ClosedRelayControl(
            self.clone(),
        ))
        .map(|encoded| encoded.len())
        .map_err(|error| format!("closed relay control serialization failed: {error}"))
    }

    /// Validate both semantic binding and the finite receive-safe wire size.
    pub fn validate_for_wire(&self, max_control_bytes: u64) -> Result<(), String> {
        self.validate()?;
        let encoded_len = self.encoded_len()?;
        let encoded_len = u64::try_from(encoded_len)
            .map_err(|_| "closed relay control length exceeds u64".to_string())?;
        if max_control_bytes == 0 || encoded_len > max_control_bytes {
            return Err("closed relay control exceeds configured encoded-byte bound".into());
        }
        Ok(())
    }

    /// Validate the complete semantic route before a relay handler uses it.
    /// The control contains no signature by itself: endpoint shares are
    /// independently authenticated by the endpoint session, while this check
    /// prevents malformed, aliased, or cross-session routing metadata.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Open {
                version,
                context_id,
                requester,
                relay,
                target,
                session_id,
                requester_share,
            } => {
                validate_binding(*version, context_id, requester, relay, target, session_id)?;
                validate_share(
                    requester_share,
                    context_id,
                    session_id,
                    requester,
                    target,
                    "requester",
                )
            }
            Self::Offer {
                version,
                context_id,
                requester,
                relay,
                target,
                session_id,
                allocation_epoch,
                requester_share,
            } => {
                validate_binding(*version, context_id, requester, relay, target, session_id)?;
                validate_epoch(*allocation_epoch)?;
                validate_share(
                    requester_share,
                    context_id,
                    session_id,
                    requester,
                    target,
                    "requester",
                )
            }
            Self::Accept {
                version,
                context_id,
                requester,
                relay,
                target,
                session_id,
                allocation_epoch,
                target_share,
            } => {
                validate_binding(*version, context_id, requester, relay, target, session_id)?;
                validate_epoch(*allocation_epoch)?;
                validate_share(
                    target_share,
                    context_id,
                    session_id,
                    target,
                    requester,
                    "target",
                )
            }
            Self::Close {
                version,
                context_id,
                requester,
                relay,
                target,
                session_id,
                allocation_epoch,
            } => {
                validate_binding(*version, context_id, requester, relay, target, session_id)?;
                validate_epoch(*allocation_epoch)
            }
        }
    }
}

/// The only two packet directions a validated Closed relay route can carry.
/// This protocol-local type intentionally mirrors the runtime's direction
/// vocabulary without importing runtime ownership into the wire layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClosedRelayDataDirection {
    RequesterToTarget,
    TargetToRequester,
}

/// Ciphertext carried through one exact Closed relay route.
///
/// The nested packet is opaque endpoint data.  It has no address field and is
/// checked against this envelope before a relay queue accepts it, so a packet
/// cannot be transplanted to another context, endpoint pair, or session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClosedRelayData {
    pub version: u8,
    pub context_id: MeshContextId,
    pub requester: DeviceId,
    pub relay: DeviceId,
    pub target: DeviceId,
    pub session_id: [u8; OPAQUE_RELAY_SESSION_BYTES],
    pub allocation_epoch: u64,
    pub packet: OpaqueRelayPacket,
}

impl ClosedRelayData {
    pub fn route(&self) -> ClosedRelayRoute {
        ClosedRelayRoute::with_epoch(
            self.context_id,
            self.requester.clone(),
            self.relay.clone(),
            self.target.clone(),
            self.session_id,
            self.allocation_epoch,
        )
    }

    pub fn matches_route(&self, expected: &ClosedRelayRoute) -> bool {
        self.route() == *expected
    }

    pub fn validate_against_route(&self, expected: &ClosedRelayRoute) -> Result<(), String> {
        self.validate(usize::MAX)?;
        expected.validate()?;
        if self.matches_route(expected) {
            Ok(())
        } else {
            Err("closed relay data does not match the exact route".into())
        }
    }

    /// Return the exact endpoint direction after validating the route and
    /// packet. A relay may forward only one of these two directions; a packet
    /// naming the relay or any unrelated endpoint is refused.
    pub fn direction(
        &self,
        max_ciphertext_bytes: usize,
    ) -> Result<ClosedRelayDataDirection, String> {
        validate_binding(
            self.version,
            &self.context_id,
            &self.requester,
            &self.relay,
            &self.target,
            &self.session_id,
        )?;
        validate_epoch(self.allocation_epoch)?;
        self.packet.validate(max_ciphertext_bytes)?;
        if self.packet.mesh != self.context_id.to_string()
            || self.packet.session_id != self.session_id
        {
            return Err("opaque relay data does not match its route binding".into());
        }
        if self.packet.from == self.requester.base32() && self.packet.to == self.target.base32() {
            return Ok(ClosedRelayDataDirection::RequesterToTarget);
        }
        if self.packet.from == self.target.base32() && self.packet.to == self.requester.base32() {
            return Ok(ClosedRelayDataDirection::TargetToRequester);
        }
        Err("opaque relay data endpoint direction is not this route".into())
    }

    /// Validate route identity and the configured ciphertext bound before the
    /// packet reaches relay queue admission.
    pub fn validate(&self, max_ciphertext_bytes: usize) -> Result<(), String> {
        self.direction(max_ciphertext_bytes).map(|_| ())
    }
}

fn validate_binding(
    version: u8,
    context_id: &MeshContextId,
    requester: &DeviceId,
    relay: &DeviceId,
    target: &DeviceId,
    session_id: &[u8; OPAQUE_RELAY_SESSION_BYTES],
) -> Result<(), String> {
    if version != CLOSED_RELAY_CONTROL_VERSION {
        return Err("unsupported closed relay control version".into());
    }
    if requester == relay || requester == target || relay == target {
        return Err("closed relay requester, relay, and target must be distinct".into());
    }
    if session_id.iter().all(|byte| *byte == 0) {
        return Err("closed relay session id must not be all zero".into());
    }
    if context_id.as_bytes().iter().all(|byte| *byte == 0) {
        return Err("closed relay context id must not be all zero".into());
    }
    Ok(())
}

fn validate_epoch(epoch: u64) -> Result<(), String> {
    if epoch == 0 {
        Err("closed relay allocation epoch must be nonzero after admission".into())
    } else {
        Ok(())
    }
}

fn validate_share(
    share: &RelayKeyShare,
    context_id: &MeshContextId,
    session_id: &[u8; OPAQUE_RELAY_SESSION_BYTES],
    from: &DeviceId,
    to: &DeviceId,
    label: &str,
) -> Result<(), String> {
    share.validate()?;
    if share.mesh != context_id.to_string()
        || share.session_id != *session_id
        || share.from != from.base32()
        || share.to != to.base32()
    {
        return Err(format!(
            "{label} relay key share does not match its route binding"
        ));
    }
    Ok(())
}

fn push_field(output: &mut Vec<u8>, field: &[u8]) {
    output.extend_from_slice(&u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
    output.extend_from_slice(field);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(seed: u8) -> DeviceId {
        let identity = crate::Identity::from_signing_key(
            ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
            format!("relay-test-{seed}"),
        );
        DeviceId::from_canonical_str(identity.public_id()).expect("test identity id")
    }

    fn id(seed: u8) -> String {
        device(seed).base32().to_string()
    }

    #[test]
    fn opaque_packet_rejects_noncanonical_route_before_forwarding() {
        let packet = OpaqueRelayPacket {
            version: OPAQUE_RELAY_VERSION,
            mesh: "mesh".into(),
            session_id: [1; OPAQUE_RELAY_SESSION_BYTES],
            from: id(1).to_uppercase(),
            to: id(2),
            sequence: 0,
            nonce: [0; OPAQUE_RELAY_NONCE_BYTES],
            ciphertext: vec![1],
        };
        assert!(packet.validate(16).is_err());
    }

    fn route() -> (MeshContextId, DeviceId, DeviceId, DeviceId, [u8; 16]) {
        let context = MeshContextId::from_bytes([7; 32]);
        let requester = device(1);
        let relay = device(2);
        let target = device(3);
        (context, requester, relay, target, [9; 16])
    }

    fn share(
        context: &MeshContextId,
        session_id: [u8; 16],
        from: &DeviceId,
        to: &DeviceId,
        seed: u8,
    ) -> RelayKeyShare {
        RelayKeyShare {
            version: OPAQUE_RELAY_VERSION,
            mesh: context.to_string(),
            session_id,
            from: from.base32(),
            to: to.base32(),
            ephemeral_public: [seed; OPAQUE_RELAY_EPHEMERAL_KEY_BYTES],
            signature: "endpoint-signature".into(),
        }
    }

    #[test]
    fn closed_relay_control_round_trips_and_validates_exact_binding() {
        let (context, requester, relay, target, session_id) = route();
        let control = ClosedRelayControl::Open {
            version: CLOSED_RELAY_CONTROL_VERSION,
            context_id: context,
            requester: requester.clone(),
            relay: relay.clone(),
            target: target.clone(),
            session_id,
            requester_share: share(&context, session_id, &requester, &target, 4),
        };
        control.validate().expect("exact Closed route validates");
        let expected_route = ClosedRelayRoute::new(
            context,
            requester.clone(),
            relay.clone(),
            target.clone(),
            session_id,
        );
        expected_route.validate().expect("route validates");
        control
            .validate_against_route(&expected_route)
            .expect("control matches exact route");
        let mut wrong_route = expected_route.clone();
        wrong_route.session_id[0] ^= 1;
        assert!(!control.matches_route(&wrong_route));
        assert!(control.validate_against_route(&wrong_route).is_err());
        let message = crate::protocol::MeshMessage::ClosedRelayControl(control.clone());
        let encoded = serde_json::to_string(&message).expect("relay control serializes");
        assert!(encoded.contains(r#""kind":"closed_relay_control""#));
        assert!(encoded.contains(r#""op":"open""#));
        let decoded: crate::protocol::MeshMessage =
            serde_json::from_str(&encoded).expect("relay control decodes");
        assert!(matches!(
            decoded,
            crate::protocol::MeshMessage::ClosedRelayControl(value) if value == control
        ));
    }

    #[test]
    fn closed_relay_control_rejects_aliases_share_mismatch_and_unknown_fields() {
        let (context, requester, relay, target, session_id) = route();
        let close = ClosedRelayControl::Close {
            version: CLOSED_RELAY_CONTROL_VERSION,
            context_id: context,
            requester: requester.clone(),
            relay: relay.clone(),
            target: target.clone(),
            session_id,
            allocation_epoch: 1,
        };
        close.validate().expect("close binding validates");

        let duplicate = ClosedRelayControl::Close {
            version: CLOSED_RELAY_CONTROL_VERSION,
            context_id: context,
            requester: requester.clone(),
            relay: requester.clone(),
            target: target.clone(),
            session_id,
            allocation_epoch: 1,
        };
        assert!(duplicate.validate().is_err());

        let mismatched_share = ClosedRelayControl::Offer {
            version: CLOSED_RELAY_CONTROL_VERSION,
            context_id: context,
            requester: requester.clone(),
            relay: relay.clone(),
            target: target.clone(),
            session_id,
            allocation_epoch: 1,
            requester_share: share(&context, session_id, &requester, &relay, 5),
        };
        assert!(mismatched_share.validate().is_err());

        let encoded =
            serde_json::to_string(&crate::protocol::MeshMessage::ClosedRelayControl(close))
                .expect("close serializes");
        let with_unknown = encoded.replacen(r#""session_id""#, r#""extra":1,"session_id""#, 1);
        assert!(serde_json::from_str::<crate::protocol::MeshMessage>(&with_unknown).is_err());

        let open = serde_json::to_string(&requester).expect("requester serializes");
        assert!(serde_json::from_str::<DeviceId>(&open.to_uppercase()).is_err());

        let oversized = RelayKeyShare {
            signature: "x".repeat(OPAQUE_RELAY_MAX_SIGNATURE_BYTES + 1),
            ..share(&context, session_id, &requester, &target, 6)
        };
        assert!(oversized.validate().is_err());
    }

    #[test]
    fn closed_relay_control_wire_bound_is_encoded_and_finite() {
        let (context, requester, relay, target, session_id) = route();
        let control = ClosedRelayControl::Open {
            version: CLOSED_RELAY_CONTROL_VERSION,
            context_id: context,
            requester: requester.clone(),
            relay,
            target: target.clone(),
            session_id,
            requester_share: share(&context, session_id, &requester, &target, 8),
        };
        let encoded_len = control.encoded_len().expect("control encodes");
        assert!(encoded_len > 0);
        control
            .validate_for_wire(u64::try_from(encoded_len).expect("length fits u64"))
            .expect("exact encoded control bound accepts");
        assert!(control
            .validate_for_wire(u64::try_from(encoded_len - 1).expect("length fits u64"))
            .is_err());
    }

    #[test]
    fn closed_relay_data_validates_packet_route_without_address_fields() {
        let (context, requester, relay, target, session_id) = route();
        let mut data = ClosedRelayData {
            version: CLOSED_RELAY_CONTROL_VERSION,
            context_id: context,
            requester: requester.clone(),
            relay: relay.clone(),
            target: target.clone(),
            session_id,
            allocation_epoch: 1,
            packet: OpaqueRelayPacket {
                version: OPAQUE_RELAY_VERSION,
                mesh: context.to_string(),
                session_id,
                from: requester.base32(),
                to: target.base32(),
                sequence: 0,
                nonce: [1; OPAQUE_RELAY_NONCE_BYTES],
                ciphertext: vec![2, 3],
            },
        };
        data.validate(8).expect("exact relay data validates");
        let expected_route = ClosedRelayRoute::with_epoch(
            context,
            requester.clone(),
            relay.clone(),
            target.clone(),
            session_id,
            1,
        );
        data.validate_against_route(&expected_route)
            .expect("data matches exact route");
        assert!(data
            .validate_against_route(&ClosedRelayRoute::with_epoch(
                context,
                requester.clone(),
                relay.clone(),
                target.clone(),
                session_id,
                2,
            ))
            .is_err());
        assert_eq!(
            data.direction(8).expect("forward direction"),
            ClosedRelayDataDirection::RequesterToTarget
        );

        data.packet.from = target.base32();
        data.packet.to = requester.base32();
        assert_eq!(
            data.direction(8).expect("reverse direction"),
            ClosedRelayDataDirection::TargetToRequester
        );

        data.packet.from = relay.base32();
        assert!(data.direction(8).is_err(), "relay is not an endpoint");
        assert!(!data.matches_route(&ClosedRelayRoute::with_epoch(
            context,
            requester.clone(),
            relay.clone(),
            device(4),
            session_id,
            1,
        )));

        data.packet.from = requester.base32();
        data.packet.to = target.base32();
        let message = crate::protocol::MeshMessage::ClosedRelayData(data);
        let encoded = serde_json::to_string(&message).expect("relay data serializes");
        assert!(encoded.contains(r#""kind":"closed_relay_data""#));
        let value: serde_json::Value = serde_json::from_str(&encoded).expect("relay data JSON");
        fn assert_no_address_keys(value: &serde_json::Value) {
            match value {
                serde_json::Value::Object(object) => {
                    for forbidden in ["ip", "addr", "address", "host", "port", "socket_addr"] {
                        assert!(
                            !object.contains_key(forbidden),
                            "raw address field {forbidden:?} was serialized"
                        );
                    }
                    for child in object.values() {
                        assert_no_address_keys(child);
                    }
                }
                serde_json::Value::Array(values) => {
                    for child in values {
                        assert_no_address_keys(child);
                    }
                }
                _ => {}
            }
        }
        assert_no_address_keys(&value);
    }

    fn worst_case_data(
        plaintext_len: usize,
        direction: ClosedRelayDataDirection,
    ) -> ClosedRelayData {
        let (context, requester, relay, target, session_id) = route();
        let (from, to) = match direction {
            ClosedRelayDataDirection::RequesterToTarget => (requester.base32(), target.base32()),
            ClosedRelayDataDirection::TargetToRequester => (target.base32(), requester.base32()),
        };
        ClosedRelayData {
            version: CLOSED_RELAY_CONTROL_VERSION,
            context_id: context,
            requester: requester.clone(),
            relay,
            target: target.clone(),
            session_id,
            allocation_epoch: 1,
            packet: OpaqueRelayPacket {
                version: OPAQUE_RELAY_VERSION,
                mesh: context.to_string(),
                session_id,
                from,
                to,
                sequence: u64::MAX,
                nonce: [255; OPAQUE_RELAY_NONCE_BYTES],
                ciphertext: vec![
                    255;
                    plaintext_len
                        + usize::try_from(CLOSED_RELAY_AEAD_TAG_BYTES)
                            .expect("AEAD tag fits usize")
                ],
            },
        }
    }

    #[test]
    fn closed_relay_sctp_receive_boundary_locks_json_shape_and_arithmetic() {
        let max_plaintext = usize::try_from(CLOSED_RELAY_MAX_PLAINTEXT_BYTES)
            .expect("safe plaintext boundary fits usize");
        let ciphertext_len = max_plaintext
            .checked_add(usize::try_from(CLOSED_RELAY_AEAD_TAG_BYTES).expect("AEAD tag fits usize"))
            .expect("ciphertext length is representable");
        for direction in [
            ClosedRelayDataDirection::RequesterToTarget,
            ClosedRelayDataDirection::TargetToRequester,
        ] {
            let exact = crate::protocol::MeshMessage::ClosedRelayData(worst_case_data(
                max_plaintext,
                direction,
            ));
            let encoded_len = serde_json::to_vec(&exact)
                .expect("worst-case ClosedRelayData serializes")
                .len();
            assert!(
                u64::try_from(encoded_len).expect("encoded length fits u64")
                    <= CLOSED_RELAY_WEBRTC_CALLBACK_BYTES,
                "exact receive-safe payload fits in both directions: {direction:?}"
            );
            assert_eq!(
                worst_case_data(max_plaintext, direction)
                    .direction(ciphertext_len)
                    .expect("exact payload direction validates"),
                direction
            );
            let over = crate::protocol::MeshMessage::ClosedRelayData(worst_case_data(
                max_plaintext + 1,
                direction,
            ));
            let over_len = serde_json::to_vec(&over)
                .expect("over-boundary ClosedRelayData serializes")
                .len();
            assert!(
                u64::try_from(over_len).expect("over-boundary length fits u64")
                    > CLOSED_RELAY_WEBRTC_CALLBACK_BYTES,
                "plaintext + 1 exceeds the callback boundary in both directions: {direction:?}"
            );
        }
        assert!(
            closed_relay_worst_case_json_bytes(
                u64::try_from(ciphertext_len).expect("ciphertext length fits u64"),
            )
            .expect("boundary arithmetic is representable")
                <= CLOSED_RELAY_WEBRTC_CALLBACK_BYTES
        );
        let exact_formula = closed_relay_worst_case_json_bytes(
            u64::try_from(ciphertext_len).expect("ciphertext length fits u64"),
        );
        assert!(
            exact_formula.expect("boundary arithmetic is representable")
                <= CLOSED_RELAY_WEBRTC_CALLBACK_BYTES
        );
        assert_eq!(exact_formula, Some(65_532));
        assert_eq!(CLOSED_RELAY_MAX_PLAINTEXT_BYTES, 16_174);
        assert_eq!(CLOSED_RELAY_WEBRTC_CALLBACK_BYTES, 65_535);
        assert_eq!(
            CLOSED_RELAY_WEBRTC_CALLBACK_BYTES + 1,
            CLOSED_RELAY_SCTP_USER_MESSAGE_BYTES
        );
        assert!(
            closed_relay_worst_case_json_bytes(
                u64::try_from(ciphertext_len + 1).expect("next ciphertext length fits u64"),
            )
            .expect("next boundary arithmetic is representable")
                > CLOSED_RELAY_WEBRTC_CALLBACK_BYTES
        );
        assert_eq!(
            closed_relay_worst_case_json_bytes(
                u64::try_from(ciphertext_len + 1).expect("next ciphertext length fits u64"),
            ),
            Some(65_536)
        );
    }
}
