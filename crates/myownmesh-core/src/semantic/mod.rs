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
pub use content::{AttestationDecision, DeviceId, ExclusiveCell, FactBody, FactDomain, Role};
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
