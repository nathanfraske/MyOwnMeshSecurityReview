//! Wire wrappers for the transport-independent V4 semantic facts.
//!
//! Canonical content, FactId computation, signatures, and projection belong
//! exclusively to `crate::semantic`.  This module deliberately re-exports
//! those exact types instead of defining a second protocol-local hash or body
//! representation.  A fact therefore has one identity regardless of whether
//! it arrived over a peer, from a cache, or from a durable store.

use serde::{de::Error as _, Deserialize, Deserializer, Serialize};

pub use crate::semantic::{
    CanonicalFact, DeviceId, FactContent, FactId, MeshContextId, ProofDeliveryId, SignedFact,
};

/// One exact durable stand-down proof delivery.
///
/// The delivery identity is derived from the authenticated mesh context,
/// target, and canonical fact identities. Transport custody is deliberately
/// absent from the wire envelope: a sender validates the current owner and
/// binding separately, and a receiver acknowledges only this stable identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProofDeliveryMessage {
    pub context_id: MeshContextId,
    pub target: DeviceId,
    pub delivery_id: ProofDeliveryId,
    pub facts: Vec<SignedFact>,
}

impl ProofDeliveryMessage {
    pub fn new(
        context_id: MeshContextId,
        target: DeviceId,
        mut facts: Vec<SignedFact>,
    ) -> Result<Self, String> {
        facts.sort_by_key(|fact| fact.id);
        let delivery_id = ProofDeliveryId::digest(
            context_id,
            &target,
            &facts.iter().map(|fact| fact.id).collect::<Vec<_>>(),
        );
        let message = Self {
            context_id,
            target,
            delivery_id,
            facts,
        };
        message.validate()?;
        Ok(message)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.facts.is_empty() {
            return Err("proof delivery must contain at least one signed fact".into());
        }
        if self.facts.windows(2).any(|pair| pair[0].id >= pair[1].id) {
            return Err("proof facts must be sorted by unique FactId".into());
        }
        if self
            .facts
            .iter()
            .any(|fact| fact.content.mesh_context != self.context_id)
        {
            return Err("proof fact mesh context does not match delivery context".into());
        }
        let fact_ids: Vec<_> = self.facts.iter().map(|fact| fact.id).collect();
        let expected = ProofDeliveryId::digest(self.context_id, &self.target, &fact_ids);
        if self.delivery_id != expected {
            return Err("proof delivery identity does not match its exact payload".into());
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct RawProofDeliveryMessage {
    context_id: MeshContextId,
    target: DeviceId,
    delivery_id: ProofDeliveryId,
    facts: Vec<SignedFact>,
}

impl<'de> Deserialize<'de> for ProofDeliveryMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawProofDeliveryMessage::deserialize(deserializer)?;
        let message = Self {
            context_id: raw.context_id,
            target: raw.target,
            delivery_id: raw.delivery_id,
            facts: raw.facts,
        };
        message.validate().map_err(D::Error::custom)?;
        Ok(message)
    }
}

/// Verified durable receipt for one exact proof delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofAckMessage {
    pub context_id: MeshContextId,
    pub target: DeviceId,
    pub delivery_id: ProofDeliveryId,
}

impl ProofAckMessage {
    pub fn for_delivery(delivery: &ProofDeliveryMessage) -> Self {
        Self {
            context_id: delivery.context_id,
            target: delivery.target.clone(),
            delivery_id: delivery.delivery_id,
        }
    }

    pub fn matches(&self, delivery: &ProofDeliveryMessage) -> bool {
        self.context_id == delivery.context_id
            && self.target == delivery.target
            && self.delivery_id == delivery.delivery_id
    }
}

/// A wire grouping of canonical semantic facts.
///
/// Bundle membership is transport framing only. Each embedded `SignedFact`
/// must be verified and reduced independently by the semantic owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactBundleMessage {
    pub facts: Vec<SignedFact>,
}

/// A non-authoritative inventory of canonical facts known by one peer.
///
/// The context is exact and the identifiers are canonicalized at construction
/// time. The inventory contains no fact bodies and therefore cannot authorize,
/// replace, or project anything; it only lets a peer decide which signed facts
/// to request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FactInventory {
    context_id: crate::semantic::MeshContextId,
    fact_ids: Vec<FactId>,
}

impl FactInventory {
    pub fn new(
        context_id: crate::semantic::MeshContextId,
        fact_ids: impl IntoIterator<Item = FactId>,
    ) -> Self {
        Self {
            context_id,
            fact_ids: canonical_fact_ids(fact_ids),
        }
    }

    pub fn context_id(&self) -> crate::semantic::MeshContextId {
        self.context_id
    }

    pub fn fact_ids(&self) -> &[FactId] {
        &self.fact_ids
    }
}

/// A non-authoritative request for exact canonical facts.
///
/// Only the identifiers are requested. The response must carry the signed
/// bodies in [`FactBundleMessage`]; this request itself is never an authority
/// input and cannot install a fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FactRequest {
    context_id: crate::semantic::MeshContextId,
    fact_ids: Vec<FactId>,
}

impl FactRequest {
    pub fn new(
        context_id: crate::semantic::MeshContextId,
        fact_ids: impl IntoIterator<Item = FactId>,
    ) -> Self {
        Self {
            context_id,
            fact_ids: canonical_fact_ids(fact_ids),
        }
    }

    pub fn context_id(&self) -> crate::semantic::MeshContextId {
        self.context_id
    }

    pub fn fact_ids(&self) -> &[FactId] {
        &self.fact_ids
    }
}

fn canonical_fact_ids(fact_ids: impl IntoIterator<Item = FactId>) -> Vec<FactId> {
    let mut fact_ids: Vec<_> = fact_ids.into_iter().collect();
    fact_ids.sort_unstable();
    fact_ids.dedup();
    fact_ids
}

#[derive(Deserialize)]
struct RawFactSet {
    context_id: crate::semantic::MeshContextId,
    fact_ids: Vec<FactId>,
}

fn deserialize_canonical_fact_ids<E>(
    raw: RawFactSet,
) -> Result<(crate::semantic::MeshContextId, Vec<FactId>), E>
where
    E: serde::de::Error,
{
    let canonical = canonical_fact_ids(raw.fact_ids.clone());
    if raw.fact_ids != canonical {
        return Err(E::custom(
            "fact identifiers must be sorted and deduplicated",
        ));
    }
    Ok((raw.context_id, canonical))
}

impl<'de> Deserialize<'de> for FactInventory {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawFactSet::deserialize(deserializer)?;
        let (context_id, fact_ids) = deserialize_canonical_fact_ids(raw)?;
        Ok(Self {
            context_id,
            fact_ids,
        })
    }
}

impl<'de> Deserialize<'de> for FactRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawFactSet::deserialize(deserializer)?;
        let (context_id, fact_ids) = deserialize_canonical_fact_ids(raw)?;
        Ok(Self {
            context_id,
            fact_ids,
        })
    }
}

/// Compatibility names matching the other protocol DTOs' `*Message` style.
pub type FactInventoryMessage = FactInventory;
pub type FactRequestMessage = FactRequest;

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    fn signed_fact(context_id: MeshContextId) -> SignedFact {
        let key = SigningKey::from_bytes(&[11; 32]);
        let device = DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes()).unwrap();
        SignedFact::sign(
            FactContent::open_participation(context_id, device, true, Vec::new()),
            &key,
        )
        .unwrap()
    }

    #[test]
    fn proof_delivery_round_trips_with_exact_identity() {
        let context_id = MeshContextId::from_bytes([7; 32]);
        let target_key = SigningKey::from_bytes(&[12; 32]);
        let target =
            DeviceId::from_public_key_bytes(*target_key.verifying_key().as_bytes()).unwrap();
        let delivery =
            ProofDeliveryMessage::new(context_id, target, vec![signed_fact(context_id)]).unwrap();
        let ack = ProofAckMessage::for_delivery(&delivery);
        assert!(ack.matches(&delivery));

        let encoded = serde_json::to_vec(&delivery).unwrap();
        let decoded: ProofDeliveryMessage = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, delivery);
    }

    #[test]
    fn proof_delivery_rejects_payload_or_context_mutation() {
        let context_id = MeshContextId::from_bytes([8; 32]);
        let target_key = SigningKey::from_bytes(&[13; 32]);
        let target =
            DeviceId::from_public_key_bytes(*target_key.verifying_key().as_bytes()).unwrap();
        let delivery =
            ProofDeliveryMessage::new(context_id, target, vec![signed_fact(context_id)]).unwrap();
        let mut wire = serde_json::to_value(&delivery).unwrap();
        wire["context_id"] = serde_json::to_value(MeshContextId::from_bytes([9; 32])).unwrap();
        assert!(serde_json::from_value::<ProofDeliveryMessage>(wire).is_err());
    }
}
