//! Wire wrappers for the transport-independent V4 semantic facts.
//!
//! Canonical content, FactId computation, signatures, and projection belong
//! exclusively to `crate::semantic`.  This module deliberately re-exports
//! those exact types instead of defining a second protocol-local hash or body
//! representation.  A fact therefore has one identity regardless of whether
//! it arrived over a peer, from a cache, or from a durable store.

use serde::{Deserialize, Deserializer, Serialize};

pub use crate::semantic::{CanonicalFact, FactContent, FactId, SignedFact};

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
