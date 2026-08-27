//! Transport-independent V4 semantic ownership.
//!
//! The semantic owner is deliberately smaller than the engine: it admits
//! canonical signed facts, maintains causal heads, and computes a projection.
//! Wire envelopes, peer/session routes, courier choice, and compatibility
//! facades remain outside this module.

use serde::{Deserialize, Serialize};

pub mod bootstrap;
pub mod causal;
pub mod content;
pub mod fact;
pub mod projection;
pub mod proof_outbox;
pub(crate) mod store;
pub mod verify;

pub use bootstrap::{
    BasisCore, BootstrapError, BootstrapRecord, ClosedProfileId, ExpectedMeshContext, GenesisBasis,
    MeshContext, MeshContextId, VerifiedBootstrap, VerifiedClosedPolicy, VerifiedProjectPolicy,
    BASIS_VERSION, CONTEXT_VERSION,
};
pub use causal::{Admission, FactGraph};
pub use content::{
    AttestationDecision, CanonicalDeviceId, DeviceId, ExclusiveCell, FactBody, FactDomain, Role,
};
pub use fact::{CanonicalFact, FactContent, FactId, SignedFact};
pub use projection::{CellProjection, Projection, StandDown};
pub use proof_outbox::{
    DurableProofOutbox, ProofDeliveryId, ProofOutboxError, ProofRecord, ProofRecordState,
};
pub use verify::{verify_fact, SemanticError};

pub const SEMANTIC_SCHEMA_VERSION: u32 = 4;

/// A durable checkpoint reference.  This is a semantic foundation value; the
/// durable store, recovery protocol, and deferred R1/R2/R3 work are separate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableCheckpoint {
    pub checkpoint_id: String,
    pub heads: Vec<FactId>,
}

impl DurableCheckpoint {
    pub fn new(checkpoint_id: impl Into<String>, mut heads: Vec<FactId>) -> Self {
        heads.sort();
        heads.dedup();
        Self {
            checkpoint_id: checkpoint_id.into(),
            heads,
        }
    }
}

/// A durable eviction-proof reference, without choosing a transport or store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvictionProofReference {
    pub target: DeviceId,
    pub evidence: Vec<FactId>,
}

impl EvictionProofReference {
    pub fn new(target: DeviceId, mut evidence: Vec<FactId>) -> Self {
        evidence.sort();
        evidence.dedup();
        Self { target, evidence }
    }

    pub fn body(&self) -> FactBody {
        FactBody::EvictionProof {
            target: self.target.clone(),
            evidence: self.evidence.clone(),
        }
    }
}

/// Self-authored stand-down evidence, kept separate from the wire envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelfStandDownReference {
    pub device_id: DeviceId,
    pub evidence: Vec<FactId>,
}

impl SelfStandDownReference {
    pub fn new(device_id: DeviceId, mut evidence: Vec<FactId>) -> Self {
        evidence.sort();
        evidence.dedup();
        Self {
            device_id,
            evidence,
        }
    }

    pub fn body(&self) -> FactBody {
        FactBody::SelfStandDown {
            device_id: self.device_id.clone(),
            evidence: self.evidence.clone(),
        }
    }
}

/// Persistence boundary for canonical facts.  Adapters own concrete stores.
pub trait FactStore {
    type Error;

    fn persist_fact(&mut self, fact: &SignedFact) -> Result<(), Self::Error>;
    fn load_fact(&self, id: &FactId) -> Result<Option<SignedFact>, Self::Error>;
}

/// Persistence boundary for checkpoint evidence.
pub trait CheckpointStore {
    type Error;

    fn persist_checkpoint(&mut self, checkpoint: &DurableCheckpoint) -> Result<(), Self::Error>;
}

/// Persistence boundary for eviction proof evidence.
pub trait EvictionProofStore {
    type Error;

    fn persist_eviction_proof(&mut self, proof: &EvictionProofReference)
        -> Result<(), Self::Error>;
}
