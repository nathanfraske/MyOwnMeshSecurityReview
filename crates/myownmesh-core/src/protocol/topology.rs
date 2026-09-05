//! Topology negotiation frames. Each peer runs the topology selector
//! locally and emits `shelve`/`unshelve` to peers based on the diff
//! between the previous and new preferred sets.
//!
//! Receivers track shelving direction independently:
//!   - `local_shelved`  — we sent `shelve` to them (they're not in our preferred set)
//!   - `remote_shelved` — they sent `shelve` to us (we're not in theirs)
//!
//! A connection is effectively shelved when either flag is true.
//! Either side can `unshelve` later when the selector promotes them.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::semantic::{DeviceId, MeshContextId};

/// The routed application payload may use at most the protocol receive-frame
/// ceiling; the complete envelope is checked separately against that ceiling.
pub const MAX_ROUTED_APPLICATION_PAYLOAD_BYTES: usize = super::RECEIVE_FRAME_BYTES;
pub const MAX_ROUTED_HOP_BUDGET: u8 = 4;
const ROUTED_APPLICATION_DOMAIN: &[u8] = b"myownmesh-routed-application-v1\0";
const ROUTED_HOP_DOMAIN: &[u8] = b"myownmesh-routed-application-hop-v1\0";

/// "I'm not going to send you application traffic for now — keep the
/// data channel open as a heartbeat so we can flip back to active
/// quickly when the topology rebalances."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShelveMessage {
    /// Why we're shelving — surfaced in the Activity log so the
    /// user can see "shelved bob (out-of-ring)" vs "shelved bob
    /// (over capacity)". Optional.
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnshelveMessage {}

/// The only payload admitted by the routed application envelope.  In
/// particular, handshake, fact, and nested routed-envelope values are not
/// protocol payload variants.  The JSON value inside a channel frame is
/// opaque application data and is bounded by the enclosing envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClosedRoutedPayload {
    ChannelFrame { channel: String, payload: Value },
}

/// One authenticated handoff in a routed envelope's bounded hop chain.
/// `remaining_ttl` is exactly one less than the preceding carrier's value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutedHop {
    pub forwarder: DeviceId,
    pub previous_remaining_ttl: u8,
    pub remaining_ttl: u8,
    pub prior_digest: [u8; 32],
    pub signature: String,
}

/// A signed, context-bound application message that can cross a bounded
/// number of topology-selected hops.  Origin authorization is immutable;
/// each mutable TTL change must be represented by an authenticated hop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutedApplicationEnvelope {
    context_id: MeshContextId,
    origin: DeviceId,
    destination: DeviceId,
    message_id: [u8; 16],
    initial_hop_budget: u8,
    remaining_ttl: u8,
    payload: ClosedRoutedPayload,
    origin_signature: String,
    hops: Vec<RoutedHop>,
}

/// Checked limits supplied by the owning network policy. The protocol maxima
/// are the only defaults; a network may select stricter limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutedApplicationLimits {
    pub max_payload_bytes: usize,
    pub max_hop_budget: u8,
}

impl Default for RoutedApplicationLimits {
    fn default() -> Self {
        Self {
            max_payload_bytes: MAX_ROUTED_APPLICATION_PAYLOAD_BYTES,
            max_hop_budget: MAX_ROUTED_HOP_BUDGET,
        }
    }
}

impl RoutedApplicationLimits {
    pub fn checked(
        max_payload_bytes: usize,
        max_hop_budget: u8,
    ) -> Result<Self, RoutedApplicationError> {
        if max_payload_bytes == 0
            || max_payload_bytes > MAX_ROUTED_APPLICATION_PAYLOAD_BYTES
            || max_hop_budget == 0
            || max_hop_budget > MAX_ROUTED_HOP_BUDGET
        {
            return Err(RoutedApplicationError::InvalidLimits);
        }
        Ok(Self {
            max_payload_bytes,
            max_hop_budget,
        })
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RoutedApplicationError {
    #[error("routed envelope contains a non-canonical device id")]
    NonCanonicalDeviceId,
    #[error("routed envelope origin does not match the signing key")]
    OriginKeyMismatch,
    #[error("routed envelope origin and destination must differ")]
    EndpointsMustDiffer,
    #[error("routed envelope message id must not be all zero")]
    InvalidMessageId,
    #[error("routed envelope hop budget is outside the bounded range")]
    InvalidHopBudget,
    #[error("routed envelope limits are outside the protocol maxima")]
    InvalidLimits,
    #[error("routed envelope hop budget is exhausted")]
    HopBudgetExhausted,
    #[error("routed envelope hop chain is invalid")]
    InvalidHopChain,
    #[error("routed envelope channel is empty or oversized")]
    InvalidChannel,
    #[error("routed envelope payload is oversized")]
    PayloadTooLarge,
    #[error("routed envelope exceeds the receive-frame ceiling")]
    WireTooLarge,
    #[error("routed envelope signature is invalid")]
    InvalidSignature,
    #[error("routed envelope signature encoding is invalid")]
    SignatureEncoding,
    #[error("routed envelope canonical encoding failed")]
    Encoding,
    #[error("routed envelope context does not match")]
    ContextMismatch,
    #[error("routed envelope was not carried by the expected previous hop")]
    PreviousHopMismatch,
}

impl RoutedApplicationEnvelope {
    /// Create an origin-authorized envelope.  The caller supplies the exact
    /// message id so engine-level replay/correlation policy remains explicit.
    pub fn new(
        context_id: MeshContextId,
        origin: DeviceId,
        destination: DeviceId,
        message_id: [u8; 16],
        initial_hop_budget: u8,
        payload: ClosedRoutedPayload,
        signing_key: &SigningKey,
    ) -> Result<Self, RoutedApplicationError> {
        Self::new_with_limits(
            context_id,
            origin,
            destination,
            message_id,
            initial_hop_budget,
            payload,
            signing_key,
            RoutedApplicationLimits::default(),
        )
    }

    pub fn new_with_limits(
        context_id: MeshContextId,
        origin: DeviceId,
        destination: DeviceId,
        message_id: [u8; 16],
        initial_hop_budget: u8,
        payload: ClosedRoutedPayload,
        signing_key: &SigningKey,
        limits: RoutedApplicationLimits,
    ) -> Result<Self, RoutedApplicationError> {
        let expected_origin =
            DeviceId::from_public_key_bytes(*signing_key.verifying_key().as_bytes())
                .map_err(|_| RoutedApplicationError::OriginKeyMismatch)?;
        if origin != expected_origin {
            return Err(RoutedApplicationError::OriginKeyMismatch);
        }
        let envelope = Self {
            context_id,
            origin,
            destination,
            message_id,
            initial_hop_budget,
            remaining_ttl: initial_hop_budget,
            payload,
            origin_signature: String::new(),
            hops: Vec::new(),
        };
        envelope.validate_unsigned(limits)?;
        let mut envelope = envelope;
        envelope.origin_signature =
            crate::signing::sign_with(signing_key, &envelope.origin_signing_bytes()?);
        envelope.validate_wire()?;
        Ok(envelope)
    }

    pub fn context_id(&self) -> MeshContextId {
        self.context_id
    }

    pub fn origin(&self) -> &DeviceId {
        &self.origin
    }

    pub fn destination(&self) -> &DeviceId {
        &self.destination
    }

    pub fn message_id(&self) -> [u8; 16] {
        self.message_id
    }

    pub fn initial_hop_budget(&self) -> u8 {
        self.initial_hop_budget
    }

    pub fn remaining_ttl(&self) -> u8 {
        self.remaining_ttl
    }

    pub fn payload(&self) -> &ClosedRoutedPayload {
        &self.payload
    }

    /// Transfer the opaque application payload to the destination without
    /// cloning its potentially peer-sized JSON value.
    pub(crate) fn into_payload(self) -> ClosedRoutedPayload {
        self.payload
    }

    pub fn hops(&self) -> &[RoutedHop] {
        &self.hops
    }

    pub fn origin_signature(&self) -> &str {
        &self.origin_signature
    }

    /// Count the exact compact JSON envelope without allocating an encoded
    /// buffer. Routing admission uses this count before taking payload/dedup
    /// custody; the count walks the same derived `Serialize` implementation
    /// used for the eventual wire frame.
    pub(crate) fn encoded_len(&self) -> Option<usize> {
        super::encoded_json_len(self)
    }

    /// Verify an envelope at its currently authenticated carrier.
    pub fn verify(&self) -> Result<(), RoutedApplicationError> {
        self.verify_for_previous_hop(self.current_carrier(), self.context_id)
    }

    /// Append a signed handoff for `forwarder`.  The new TTL is forced to be
    /// exactly one below the previous carrier's TTL and can never be raised.
    pub fn append_hop(
        &mut self,
        forwarder: DeviceId,
        signing_key: &SigningKey,
    ) -> Result<(), RoutedApplicationError> {
        self.append_hop_with_limits(forwarder, signing_key, RoutedApplicationLimits::default())
    }

    pub fn append_hop_with_limits(
        &mut self,
        forwarder: DeviceId,
        signing_key: &SigningKey,
        limits: RoutedApplicationLimits,
    ) -> Result<(), RoutedApplicationError> {
        self.verify_for_previous_hop_with_limits(self.current_carrier(), self.context_id, limits)?;
        let expected_forwarder =
            DeviceId::from_public_key_bytes(*signing_key.verifying_key().as_bytes())
                .map_err(|_| RoutedApplicationError::InvalidHopChain)?;
        if forwarder != expected_forwarder {
            return Err(RoutedApplicationError::InvalidHopChain);
        }
        if self.hops.len() >= usize::from(limits.max_hop_budget)
            || self.hops.len() >= usize::from(self.initial_hop_budget)
        {
            return Err(RoutedApplicationError::HopBudgetExhausted);
        }
        let remaining_ttl = self
            .remaining_ttl
            .checked_sub(1)
            .ok_or(RoutedApplicationError::HopBudgetExhausted)?;
        let prior_digest = self.chain_digest()?;
        let mut hop = RoutedHop {
            forwarder,
            previous_remaining_ttl: self.remaining_ttl,
            remaining_ttl,
            prior_digest,
            signature: String::new(),
        };
        hop.signature = crate::signing::sign_with(signing_key, &self.hop_signing_bytes(&hop)?);
        let mut candidate = self.clone();
        candidate.hops.push(hop);
        candidate.remaining_ttl = remaining_ttl;
        candidate.validate_wire()?;
        *self = candidate;
        Ok(())
    }

    /// Verify the origin authorization, every hop signature, the exact
    /// context, and the carrier identity for this delivery attempt.
    pub fn verify_for_previous_hop(
        &self,
        previous_owner: &DeviceId,
        context_id: MeshContextId,
    ) -> Result<(), RoutedApplicationError> {
        self.verify_for_previous_hop_with_limits(
            previous_owner,
            context_id,
            RoutedApplicationLimits::default(),
        )
    }

    pub fn verify_for_previous_hop_with_limits(
        &self,
        previous_owner: &DeviceId,
        context_id: MeshContextId,
        limits: RoutedApplicationLimits,
    ) -> Result<(), RoutedApplicationError> {
        if self.context_id != context_id {
            return Err(RoutedApplicationError::ContextMismatch);
        }
        self.validate_unsigned(limits)?;
        if self.hops.len() > usize::from(limits.max_hop_budget)
            || self.hops.len() > usize::from(self.initial_hop_budget)
        {
            return Err(RoutedApplicationError::InvalidHopChain);
        }
        let origin_bytes = self.origin_signing_bytes()?;
        let valid = crate::signing::verify(&self.origin, &origin_bytes, &self.origin_signature)
            .map_err(|_| RoutedApplicationError::SignatureEncoding)?;
        if !valid {
            return Err(RoutedApplicationError::InvalidSignature);
        }
        let mut expected_digest = Self::digest(&origin_bytes);
        let mut expected_previous_ttl = self.initial_hop_budget;
        for hop in &self.hops {
            Self::validate_device(&hop.forwarder)?;
            if expected_previous_ttl == 0
                || hop.prior_digest != expected_digest
                || hop.previous_remaining_ttl != expected_previous_ttl
                || hop.remaining_ttl != expected_previous_ttl - 1
            {
                return Err(RoutedApplicationError::InvalidHopChain);
            }
            let hop_bytes = self.hop_signing_bytes(hop)?;
            let valid = crate::signing::verify(&hop.forwarder, &hop_bytes, &hop.signature)
                .map_err(|_| RoutedApplicationError::SignatureEncoding)?;
            if !valid {
                return Err(RoutedApplicationError::InvalidSignature);
            }
            expected_digest =
                Self::digest_with_signature(&expected_digest, &hop_bytes, &hop.signature);
            expected_previous_ttl = hop.remaining_ttl;
        }
        let expected_ttl = self
            .hops
            .last()
            .map_or(self.initial_hop_budget, |hop| hop.remaining_ttl);
        if self.remaining_ttl != expected_ttl
            || self.hops.len() > usize::from(limits.max_hop_budget)
            || self.hops.len() > usize::from(self.initial_hop_budget)
        {
            return Err(RoutedApplicationError::InvalidHopChain);
        }
        if self.current_carrier() != previous_owner {
            return Err(RoutedApplicationError::PreviousHopMismatch);
        }
        self.validate_wire()
    }

    fn current_carrier(&self) -> &DeviceId {
        self.hops.last().map_or(&self.origin, |hop| &hop.forwarder)
    }

    fn validate_unsigned(
        &self,
        limits: RoutedApplicationLimits,
    ) -> Result<(), RoutedApplicationError> {
        Self::validate_device(&self.origin)?;
        Self::validate_device(&self.destination)?;
        if self.origin == self.destination {
            return Err(RoutedApplicationError::EndpointsMustDiffer);
        }
        if self.message_id.iter().all(|byte| *byte == 0) {
            return Err(RoutedApplicationError::InvalidMessageId);
        }
        if self.initial_hop_budget == 0 || self.initial_hop_budget > limits.max_hop_budget {
            return Err(RoutedApplicationError::InvalidHopBudget);
        }
        if self.remaining_ttl > self.initial_hop_budget {
            return Err(RoutedApplicationError::InvalidHopBudget);
        }
        if self.remaining_ttl != self.initial_hop_budget && self.hops.is_empty() {
            return Err(RoutedApplicationError::InvalidHopChain);
        }
        self.validate_payload(limits)
    }

    fn validate_payload(
        &self,
        limits: RoutedApplicationLimits,
    ) -> Result<(), RoutedApplicationError> {
        let ClosedRoutedPayload::ChannelFrame { channel, payload } = &self.payload;
        if channel.is_empty() || channel.len() > 256 {
            return Err(RoutedApplicationError::InvalidChannel);
        }
        if canonical_json_bytes(payload)?.len() > limits.max_payload_bytes {
            return Err(RoutedApplicationError::PayloadTooLarge);
        }
        Ok(())
    }

    fn validate_device(device: &DeviceId) -> Result<(), RoutedApplicationError> {
        let canonical = DeviceId::from_canonical_str(device)
            .map_err(|_| RoutedApplicationError::NonCanonicalDeviceId)?;
        if canonical != *device {
            return Err(RoutedApplicationError::NonCanonicalDeviceId);
        }
        Ok(())
    }

    fn origin_signing_bytes(&self) -> Result<Vec<u8>, RoutedApplicationError> {
        let payload = canonical_payload_bytes(&self.payload)?;
        let mut bytes = Vec::with_capacity(128 + payload.len());
        bytes.extend_from_slice(ROUTED_APPLICATION_DOMAIN);
        append_len_prefixed(&mut bytes, self.context_id.as_bytes())?;
        append_len_prefixed(&mut bytes, self.origin.as_bytes().as_slice())?;
        append_len_prefixed(&mut bytes, self.destination.as_bytes().as_slice())?;
        bytes.extend_from_slice(&self.message_id);
        bytes.push(self.initial_hop_budget);
        append_len_prefixed(&mut bytes, &payload)?;
        Ok(bytes)
    }

    fn hop_signing_bytes(&self, hop: &RoutedHop) -> Result<Vec<u8>, RoutedApplicationError> {
        let mut bytes = Vec::with_capacity(128);
        bytes.extend_from_slice(ROUTED_HOP_DOMAIN);
        bytes.extend_from_slice(&hop.prior_digest);
        append_len_prefixed(&mut bytes, self.context_id.as_bytes())?;
        append_len_prefixed(&mut bytes, self.origin.as_bytes().as_slice())?;
        append_len_prefixed(&mut bytes, self.destination.as_bytes().as_slice())?;
        bytes.extend_from_slice(&self.message_id);
        append_len_prefixed(&mut bytes, hop.forwarder.as_bytes().as_slice())?;
        bytes.push(hop.previous_remaining_ttl);
        bytes.push(hop.remaining_ttl);
        Ok(bytes)
    }

    fn chain_digest(&self) -> Result<[u8; 32], RoutedApplicationError> {
        let mut digest = Self::digest(&self.origin_signing_bytes()?);
        for hop in &self.hops {
            let hop_bytes = self.hop_signing_bytes(hop)?;
            digest = Self::digest_with_signature(&digest, &hop_bytes, &hop.signature);
        }
        Ok(digest)
    }

    fn digest(bytes: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hasher.finalize().into()
    }

    fn digest_with_signature(previous: &[u8; 32], bytes: &[u8], signature: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(previous);
        hasher.update(bytes);
        hasher.update(signature.as_bytes());
        hasher.finalize().into()
    }

    fn validate_wire(&self) -> Result<(), RoutedApplicationError> {
        if serde_json::to_vec(self)
            .map_err(|_| RoutedApplicationError::Encoding)?
            .len()
            > super::RECEIVE_FRAME_BYTES
        {
            return Err(RoutedApplicationError::WireTooLarge);
        }
        Ok(())
    }
}

fn append_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), RoutedApplicationError> {
    let length = u32::try_from(bytes.len()).map_err(|_| RoutedApplicationError::Encoding)?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, RoutedApplicationError> {
    let mut output = Vec::new();
    write_canonical_json(value, &mut output)?;
    Ok(output)
}

fn canonical_payload_bytes(
    payload: &ClosedRoutedPayload,
) -> Result<Vec<u8>, RoutedApplicationError> {
    let ClosedRoutedPayload::ChannelFrame { channel, payload } = payload;
    let mut output = Vec::new();
    // Keys are emitted in lexicographic order, independently of serde's wire
    // field order, so signatures cover one canonical strict-payload form.
    output.extend_from_slice(b"{\"channel\":");
    serde_json::to_writer(&mut output, channel).map_err(|_| RoutedApplicationError::Encoding)?;
    output.extend_from_slice(b",\"kind\":\"channel_frame\",\"payload\":");
    write_canonical_json(payload, &mut output)?;
    output.push(b'}');
    Ok(output)
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) -> Result<(), RoutedApplicationError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) => output.extend_from_slice(value.to_string().as_bytes()),
        Value::String(value) => output.extend_from_slice(
            &serde_json::to_vec(value).map_err(|_| RoutedApplicationError::Encoding)?,
        ),
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            let mut keys: Vec<&String> = values.keys().collect();
            keys.sort_unstable();
            output.push(b'{');
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                output.extend_from_slice(
                    &serde_json::to_vec(key).map_err(|_| RoutedApplicationError::Encoding)?,
                );
                output.push(b':');
                write_canonical_json(&values[key], output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod routed_tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn device(key: &SigningKey) -> DeviceId {
        DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes()).unwrap()
    }

    fn envelope() -> (RoutedApplicationEnvelope, SigningKey, DeviceId) {
        let origin_key = key(7);
        let destination_key = key(8);
        let origin = device(&origin_key);
        let destination = device(&destination_key);
        let context = MeshContextId::from_bytes([3; 32]);
        let envelope = RoutedApplicationEnvelope::new(
            context,
            origin,
            destination.clone(),
            [9; 16],
            4,
            ClosedRoutedPayload::ChannelFrame {
                channel: "chat".into(),
                payload: serde_json::json!({"text": "hello", "n": 1}),
            },
            &origin_key,
        )
        .unwrap();
        (envelope, origin_key, destination)
    }

    #[test]
    fn signed_envelope_round_trips_and_binds_exact_fields() {
        let (envelope, _, _) = envelope();
        envelope
            .verify_for_previous_hop(envelope.origin(), envelope.context_id())
            .unwrap();
        let wire = serde_json::to_vec(&envelope).unwrap();
        let decoded: RoutedApplicationEnvelope = serde_json::from_slice(&wire).unwrap();
        assert_eq!(decoded, envelope);
        decoded
            .verify_for_previous_hop(decoded.origin(), decoded.context_id())
            .unwrap();
    }

    #[test]
    fn encoded_len_matches_wire_at_zero_and_max_hops() {
        let (mut envelope, _, _) = envelope();
        assert_eq!(
            envelope.encoded_len(),
            Some(serde_json::to_vec(&envelope).unwrap().len())
        );
        for seed in [20, 21, 22, 23] {
            let hop_key = key(seed);
            envelope
                .append_hop(device(&hop_key), &hop_key)
                .expect("bounded hop is admitted");
        }
        assert_eq!(envelope.remaining_ttl(), 0);
        assert_eq!(
            envelope.encoded_len(),
            Some(serde_json::to_vec(&envelope).unwrap().len())
        );
    }

    #[test]
    fn max_sized_payload_can_be_moved_without_cloning() {
        let origin_key = key(24);
        let origin = device(&origin_key);
        let destination = device(&key(25));
        let text = "x".repeat(MAX_ROUTED_APPLICATION_PAYLOAD_BYTES - 1024 - 2);
        let envelope = RoutedApplicationEnvelope::new_with_limits(
            MeshContextId::from_bytes([6; 32]),
            origin,
            destination,
            [2; 16],
            1,
            ClosedRoutedPayload::ChannelFrame {
                channel: "chat".into(),
                payload: Value::String(text.clone()),
            },
            &origin_key,
            RoutedApplicationLimits::checked(MAX_ROUTED_APPLICATION_PAYLOAD_BYTES - 1024, 1)
                .unwrap(),
        )
        .unwrap();
        match envelope.into_payload() {
            ClosedRoutedPayload::ChannelFrame { channel, payload } => {
                assert_eq!(channel, "chat");
                assert_eq!(payload, Value::String(text));
            }
        }
    }

    #[test]
    fn hop_chain_is_signed_bounded_and_ttl_cannot_increase() {
        let (mut envelope, origin_key, _) = envelope();
        let next_key = key(10);
        let next = device(&next_key);
        envelope.append_hop(next.clone(), &next_key).unwrap();
        assert_eq!(envelope.remaining_ttl(), 3);
        envelope
            .verify_for_previous_hop(&next, envelope.context_id())
            .unwrap();
        assert!(envelope
            .append_hop(device(&origin_key), &origin_key)
            .is_ok());

        let mut forged = serde_json::to_value(&envelope).unwrap();
        forged["remaining_ttl"] = serde_json::json!(4);
        let forged: RoutedApplicationEnvelope = serde_json::from_value(forged).unwrap();
        assert!(matches!(
            forged.verify_for_previous_hop(forged.current_carrier(), forged.context_id()),
            Err(RoutedApplicationError::InvalidHopChain)
                | Err(RoutedApplicationError::InvalidHopBudget)
        ));
    }

    #[test]
    fn unknown_nested_protocol_kinds_and_unknown_fields_are_rejected() {
        let (envelope, _, _) = envelope();
        let mut wire = serde_json::to_value(envelope).unwrap();
        wire["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<RoutedApplicationEnvelope>(wire).is_err());

        let nested = serde_json::json!({"kind":"routed_application_envelope","context_id":"x"});
        assert!(serde_json::from_value::<ClosedRoutedPayload>(nested).is_err());
        let handshake = serde_json::json!({"kind":"handshake","payload":{}});
        assert!(serde_json::from_value::<ClosedRoutedPayload>(handshake).is_err());
        let fact = serde_json::json!({"kind":"fact","payload":{}});
        assert!(serde_json::from_value::<ClosedRoutedPayload>(fact).is_err());
    }

    #[test]
    fn forgery_context_and_payload_changes_fail_verification() {
        let (envelope, _, _) = envelope();
        for (field, value) in [
            (
                "destination",
                serde_json::to_value(device(&key(11))).unwrap(),
            ),
            (
                "context_id",
                serde_json::to_value(MeshContextId::from_bytes([4; 32])).unwrap(),
            ),
            (
                "message_id",
                serde_json::json!([8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8]),
            ),
        ] {
            let mut wire = serde_json::to_value(&envelope).unwrap();
            wire[field] = value;
            let changed: RoutedApplicationEnvelope = serde_json::from_value(wire).unwrap();
            assert!(changed
                .verify_for_previous_hop(changed.origin(), changed.context_id())
                .is_err());
        }
        let mut wire = serde_json::to_value(&envelope).unwrap();
        wire["payload"]["payload"]["text"] = serde_json::json!("tampered");
        let changed: RoutedApplicationEnvelope = serde_json::from_value(wire).unwrap();
        assert!(changed
            .verify_for_previous_hop(changed.origin(), changed.context_id())
            .is_err());
    }

    #[test]
    fn payload_and_message_bounds_are_enforced() {
        let origin_key = key(12);
        let origin = device(&origin_key);
        let destination = device(&key(13));
        let result = RoutedApplicationEnvelope::new(
            MeshContextId::from_bytes([5; 32]),
            origin,
            destination,
            [0; 16],
            1,
            ClosedRoutedPayload::ChannelFrame {
                channel: "chat".into(),
                payload: Value::Null,
            },
            &origin_key,
        );
        assert_eq!(result, Err(RoutedApplicationError::InvalidMessageId));

        let result = RoutedApplicationEnvelope::new(
            MeshContextId::from_bytes([5; 32]),
            device(&origin_key),
            device(&key(13)),
            [1; 16],
            1,
            ClosedRoutedPayload::ChannelFrame {
                channel: "chat".into(),
                payload: Value::String("x".repeat(MAX_ROUTED_APPLICATION_PAYLOAD_BYTES + 1)),
            },
            &origin_key,
        );
        assert_eq!(result, Err(RoutedApplicationError::PayloadTooLarge));
    }
}
