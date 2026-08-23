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
pub(crate) mod store;
pub mod verify;

pub use bootstrap::{
    BasisCore, BootstrapError, BootstrapRecord, ClosedProfileId, ExpectedMeshContext, GenesisBasis,
    MeshContext, MeshContextId, VerifiedBootstrap, VerifiedClosedPolicy, VerifiedProjectPolicy,
    BASIS_VERSION, CONTEXT_VERSION,
};
pub use causal::{Admission, FactGraph};
pub use content::{
    AttestationDecision, ExclusiveCell, FactBody, FactDomain, GovernanceKind, Role, Topology,
};
pub use fact::{CanonicalFact, FactContent, FactId, SignedFact};
pub use projection::{CellProjection, Projection, StandDown};
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

    pub fn body(&self) -> FactBody {
        FactBody::Checkpoint {
            checkpoint_id: self.checkpoint_id.clone(),
            heads: self.heads.clone(),
        }
    }
}

/// A durable eviction-proof reference, without choosing a transport or store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvictionProofReference {
    pub target: String,
    pub evidence: Vec<FactId>,
}

impl EvictionProofReference {
    pub fn new(target: impl Into<String>, mut evidence: Vec<FactId>) -> Self {
        evidence.sort();
        evidence.dedup();
        Self {
            target: target.into(),
            evidence,
        }
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
    pub device_id: String,
    pub evidence: Vec<FactId>,
}

impl SelfStandDownReference {
    pub fn new(device_id: impl Into<String>, mut evidence: Vec<FactId>) -> Self {
        evidence.sort();
        evidence.dedup();
        Self {
            device_id: device_id.into(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn author(key: &SigningKey) -> String {
        use data_encoding::BASE32_NOPAD;
        BASE32_NOPAD
            .encode(key.verifying_key().as_bytes())
            .to_lowercase()
    }

    fn bootstrap(key: &SigningKey) -> VerifiedBootstrap {
        VerifiedBootstrap::create_closed("mesh-a", vec![key.clone()], [0; 32])
            .expect("test bootstrap")
    }

    fn context_for(key: &SigningKey) -> String {
        bootstrap(key).context_id().to_string()
    }

    fn graph(key: &SigningKey) -> FactGraph {
        let bootstrap = bootstrap(key);
        FactGraph::from_bootstrap(&bootstrap)
    }

    fn fact(key: &SigningKey, body: FactBody, parents: Vec<FactId>) -> SignedFact {
        let context = context_for(key);
        fact_in_context(&context, key, body, parents)
    }

    fn fact_in_context(
        context: &str,
        key: &SigningKey,
        body: FactBody,
        parents: Vec<FactId>,
    ) -> SignedFact {
        let domain = body.domain();
        SignedFact::sign(
            FactContent::new(domain, context, body, author(key), parents),
            key,
        )
        .expect("test fact signs")
    }

    #[test]
    fn canonical_content_is_independent_of_member_order() {
        let signing_key = key(7);
        let first = fact(
            &signing_key,
            FactBody::Split {
                new_network_id: "child".into(),
                members: vec!["b".into(), "a".into()],
            },
            Vec::new(),
        );
        let second = fact(
            &signing_key,
            FactBody::Split {
                new_network_id: "child".into(),
                members: vec!["a".into(), "b".into()],
            },
            Vec::new(),
        );
        assert_eq!(first.id, second.id);
        assert_eq!(
            first.content.canonical_bytes(),
            second.content.canonical_bytes()
        );
        assert_eq!(first.id.to_string(), first.id.base32());
        assert_eq!(first.id.to_string().len(), 52);
        let mut noncanonical = first.content.clone();
        if let FactBody::Split { members, .. } = &mut noncanonical.body {
            members.reverse();
        }
        assert!(matches!(
            noncanonical.validate(),
            Err(SemanticError::NonCanonicalSet("Split.members"))
        ));
        assert_ne!(FactId::from_content(&noncanonical), first.id);
    }

    #[test]
    fn unsupported_version_is_not_admitted() {
        let signing_key = key(6);
        let mut content = FactContent::new(
            FactDomain::Governance,
            "mesh-a",
            FactBody::KindChange {
                to: GovernanceKind::Open,
            },
            author(&signing_key),
            Vec::new(),
        );
        content.version = 3;
        assert!(matches!(
            SignedFact::sign(content, &signing_key),
            Err(SemanticError::UnsupportedVersion(3))
        ));
    }

    #[test]
    fn missing_parent_is_quarantined_outside_projection() {
        let signing_key = key(5);
        let orphan = fact(
            &signing_key,
            FactBody::KindChange {
                to: GovernanceKind::Open,
            },
            vec![FactId::from_bytes([44; 32])],
        );
        let mut graph = graph(&signing_key);
        assert!(matches!(
            graph.admit(orphan),
            Ok(Admission::Quarantined { .. })
        ));
        assert_eq!(graph.len(), 0);
        assert_eq!(graph.quarantined().count(), 1);
        assert!(graph.projection().cells().next().is_none());
    }

    #[test]
    fn quarantine_retry_reaches_a_causal_fixed_point() {
        let signing_key = key(3);
        let root = fact(
            &signing_key,
            FactBody::Checkpoint {
                checkpoint_id: "root".into(),
                heads: Vec::new(),
            },
            Vec::new(),
        );
        let parent = fact(
            &signing_key,
            FactBody::Checkpoint {
                checkpoint_id: "parent".into(),
                heads: vec![root.id],
            },
            vec![root.id],
        );
        let child = fact(
            &signing_key,
            FactBody::Checkpoint {
                checkpoint_id: "child".into(),
                heads: vec![parent.id],
            },
            vec![parent.id],
        );
        let mut graph = graph(&signing_key);
        assert!(matches!(
            graph.admit(child),
            Ok(Admission::Quarantined { .. })
        ));
        assert!(matches!(
            graph.admit(parent),
            Ok(Admission::Quarantined { .. })
        ));
        graph.admit(root).unwrap();
        assert_eq!(graph.retry_quarantined().unwrap().len(), 2);
        assert_eq!(graph.len(), 3);
        assert_eq!(graph.quarantined().count(), 0);
    }

    #[test]
    fn eviction_requires_present_evidence_before_stand_down_projects() {
        let signing_key = key(4);
        let device = author(&signing_key);
        let proposal = fact(
            &signing_key,
            FactBody::Checkpoint {
                checkpoint_id: "eviction-proposal".into(),
                heads: Vec::new(),
            },
            Vec::new(),
        );
        let attestation = fact(
            &signing_key,
            FactBody::Attestation {
                target: device.clone(),
                proposal: proposal.id,
                decision: AttestationDecision::Evict,
                signer: device.clone(),
                contributions: Vec::new(),
            },
            vec![proposal.id],
        );
        let proof = fact(
            &signing_key,
            FactBody::EvictionProof {
                target: device.clone(),
                evidence: vec![attestation.id],
            },
            vec![attestation.id],
        );
        let mut graph = graph(&signing_key);
        graph.admit(proposal).unwrap();
        assert!(matches!(
            graph.admit(proof),
            Ok(Admission::Quarantined { .. })
        ));
        assert!(!graph.projection().is_stood_down(&device));
        graph.admit(attestation).unwrap();
        graph.retry_quarantined().unwrap();
        assert!(graph.projection().is_stood_down(&device));
    }

    #[test]
    fn eviction_requires_authorized_same_target_attestation() {
        let owner_key = key(11);
        let owner_id = author(&owner_key);
        let mut graph = graph(&owner_key);
        let role = fact(
            &owner_key,
            FactBody::RoleGrant {
                target: owner_id.clone(),
                role: Role::Owner,
            },
            Vec::new(),
        );
        graph.admit(role).unwrap();
        let proposal = fact(
            &owner_key,
            FactBody::Checkpoint {
                checkpoint_id: "eviction-proposal".into(),
                heads: Vec::new(),
            },
            Vec::new(),
        );
        let contribution = fact(
            &owner_key,
            FactBody::Checkpoint {
                checkpoint_id: "contribution".into(),
                heads: Vec::new(),
            },
            Vec::new(),
        );
        graph.admit(proposal.clone()).unwrap();
        graph.admit(contribution.clone()).unwrap();
        let stranger_key = key(13);
        let stranger_id = author(&stranger_key);
        let context = context_for(&owner_key);
        let unauthorized = fact_in_context(
            &context,
            &stranger_key,
            FactBody::Attestation {
                target: "victim".into(),
                proposal: proposal.id,
                decision: AttestationDecision::Evict,
                signer: stranger_id,
                contributions: vec![contribution.id],
            },
            vec![proposal.id, contribution.id],
        );
        assert!(matches!(
            graph.admit(unauthorized),
            Err(SemanticError::UnauthorizedAttestation)
        ));
        let attestation = fact(
            &owner_key,
            FactBody::Attestation {
                target: "victim".into(),
                proposal: proposal.id,
                decision: AttestationDecision::Evict,
                signer: owner_id.clone(),
                contributions: vec![contribution.id],
            },
            vec![proposal.id, contribution.id],
        );
        graph.admit(attestation.clone()).unwrap();
        let proof = fact(
            &owner_key,
            FactBody::EvictionProof {
                target: "victim".into(),
                evidence: vec![attestation.id],
            },
            vec![attestation.id],
        );
        graph.admit(proof.clone()).unwrap();
        assert!(graph.projection().is_stood_down("victim"));

        let arbitrary = fact(
            &owner_key,
            FactBody::Checkpoint {
                checkpoint_id: "arbitrary".into(),
                heads: Vec::new(),
            },
            Vec::new(),
        );
        graph.admit(arbitrary.clone()).unwrap();
        let forged_evidence = fact(
            &owner_key,
            FactBody::EvictionProof {
                target: "other-victim".into(),
                evidence: vec![arbitrary.id],
            },
            vec![arbitrary.id],
        );
        assert!(matches!(
            graph.admit(forged_evidence),
            Err(SemanticError::InvalidEvictionEvidence)
        ));

        let mut mutated = proof;
        if let FactBody::EvictionProof { target, .. } = &mut mutated.content.body {
            *target = "other-victim".into();
        }
        assert!(matches!(
            graph.admit(mutated),
            Err(SemanticError::FactIdMismatch)
        ));
    }

    #[test]
    fn self_stand_down_requires_same_target_eviction_proof() {
        let device_key = key(12);
        let device_id = author(&device_key);
        let mut graph = graph(&device_key);
        let role = fact(
            &device_key,
            FactBody::RoleGrant {
                target: device_id.clone(),
                role: Role::Controller,
            },
            Vec::new(),
        );
        graph.admit(role).unwrap();
        let proposal = fact(
            &device_key,
            FactBody::Checkpoint {
                checkpoint_id: "self-eviction".into(),
                heads: Vec::new(),
            },
            Vec::new(),
        );
        graph.admit(proposal.clone()).unwrap();
        let attestation = fact(
            &device_key,
            FactBody::Attestation {
                target: device_id.clone(),
                proposal: proposal.id,
                decision: AttestationDecision::Evict,
                signer: device_id.clone(),
                contributions: Vec::new(),
            },
            vec![proposal.id],
        );
        graph.admit(attestation.clone()).unwrap();
        let proof = fact(
            &device_key,
            FactBody::EvictionProof {
                target: device_id.clone(),
                evidence: vec![attestation.id],
            },
            vec![attestation.id],
        );
        graph.admit(proof.clone()).unwrap();
        let stand_down = fact(
            &device_key,
            FactBody::SelfStandDown {
                device_id: device_id.clone(),
                evidence: vec![proof.id],
            },
            vec![proof.id],
        );
        graph.admit(stand_down).unwrap();
        assert!(graph.projection().is_stood_down(&device_id));
    }

    #[test]
    fn direct_descendant_supersedes_but_incomparable_heads_conflict() {
        let signing_key = key(8);
        let genesis = fact(
            &signing_key,
            FactBody::KindChange {
                to: GovernanceKind::Open,
            },
            Vec::new(),
        );
        let mut graph = graph(&signing_key);
        graph.admit(genesis.clone()).unwrap();
        let successor = fact(
            &signing_key,
            FactBody::KindChange {
                to: GovernanceKind::Closed,
            },
            vec![genesis.id],
        );
        graph.admit(successor.clone()).unwrap();
        assert_eq!(
            graph.cell_heads(&ExclusiveCell::new("network", "kind")),
            vec![successor.id]
        );
        let conflict = fact(
            &signing_key,
            FactBody::KindChange {
                to: GovernanceKind::Silent,
            },
            Vec::new(),
        );
        graph.admit(conflict.clone()).unwrap();
        let cell = ExclusiveCell::new("network", "kind");
        assert!(graph.projection().is_conflicted(&cell));
        let mut heads = graph.cell_heads(&cell);
        heads.sort();
        let incomplete = fact(
            &signing_key,
            FactBody::Resolution {
                cell: cell.clone(),
                cited_heads: vec![heads[0]],
                selected_head: heads[0],
            },
            vec![heads[0]],
        );
        assert!(matches!(
            graph.admit(incomplete),
            Err(SemanticError::IncompleteResolution)
        ));
        let resolution = fact(
            &signing_key,
            FactBody::Resolution {
                cell: cell.clone(),
                cited_heads: heads.clone(),
                selected_head: successor.id,
            },
            heads,
        );
        graph.admit(resolution.clone()).unwrap();
        assert_eq!(graph.projection().value(&cell), Some(successor.id));
    }

    #[test]
    fn every_governance_mutator_requires_current_or_root_authority() {
        let root_key = key(14);
        let stranger_key = key(15);
        let context = context_for(&root_key);
        let mut graph = graph(&root_key);
        let bodies = [
            FactBody::KindChange {
                to: GovernanceKind::Open,
            },
            FactBody::RoleGrant {
                target: "victim".into(),
                role: Role::Member,
            },
            FactBody::RoleRevoke {
                target: "victim".into(),
            },
            FactBody::Evict {
                target: "victim".into(),
            },
            FactBody::Split {
                new_network_id: "child".into(),
                members: vec!["a".into(), "b".into()],
            },
            FactBody::TopologyChange {
                to: Topology::FullMesh,
            },
        ];
        for body in bodies {
            let unauthorized = fact_in_context(&context, &stranger_key, body, Vec::new());
            assert!(matches!(
                graph.admit(unauthorized),
                Err(SemanticError::UnauthorizedRoleGrant)
            ));
        }
    }

    #[test]
    fn attestation_and_resolution_require_current_or_root_authority() {
        let root_key = key(16);
        let stranger_key = key(17);
        let stranger_id = author(&stranger_key);
        let context = context_for(&root_key);
        let mut graph = graph(&root_key);

        let proposal = fact(
            &root_key,
            FactBody::Checkpoint {
                checkpoint_id: "authority-proposal".into(),
                heads: Vec::new(),
            },
            Vec::new(),
        );
        graph.admit(proposal.clone()).unwrap();
        let unauthorized_attestation = fact_in_context(
            &context,
            &stranger_key,
            FactBody::Attestation {
                target: "victim".into(),
                proposal: proposal.id,
                decision: AttestationDecision::Approve,
                signer: stranger_id,
                contributions: Vec::new(),
            },
            vec![proposal.id],
        );
        assert!(matches!(
            graph.admit(unauthorized_attestation),
            Err(SemanticError::UnauthorizedAttestation)
        ));

        let first = fact(
            &root_key,
            FactBody::KindChange {
                to: GovernanceKind::Open,
            },
            Vec::new(),
        );
        let second = fact(
            &root_key,
            FactBody::KindChange {
                to: GovernanceKind::Closed,
            },
            Vec::new(),
        );
        graph.admit(first).unwrap();
        graph.admit(second).unwrap();
        let cell = ExclusiveCell::new("network", "kind");
        let heads = graph.cell_heads(&cell);
        let unauthorized_resolution = fact_in_context(
            &context,
            &stranger_key,
            FactBody::Resolution {
                cell,
                selected_head: heads[0],
                cited_heads: heads.clone(),
            },
            heads,
        );
        assert!(matches!(
            graph.admit(unauthorized_resolution),
            Err(SemanticError::UnauthorizedRoleGrant)
        ));
    }

    #[test]
    fn revoked_current_authority_cannot_mutate_governance() {
        let root_key = key(18);
        let controller_key = key(19);
        let controller_id = author(&controller_key);
        let context = context_for(&root_key);
        let mut graph = graph(&root_key);
        let grant = fact(
            &root_key,
            FactBody::RoleGrant {
                target: controller_id.clone(),
                role: Role::Controller,
            },
            Vec::new(),
        );
        graph.admit(grant.clone()).unwrap();
        let revoke = fact(
            &root_key,
            FactBody::RoleRevoke {
                target: controller_id,
            },
            vec![grant.id],
        );
        graph.admit(revoke).unwrap();
        let stale_authority = fact_in_context(
            &context,
            &controller_key,
            FactBody::TopologyChange {
                to: Topology::FullMesh,
            },
            Vec::new(),
        );
        assert!(matches!(
            graph.admit(stale_authority),
            Err(SemanticError::UnauthorizedRoleGrant)
        ));
    }

    #[test]
    fn governance_body_mutation_cannot_reuse_a_valid_signature() {
        let signing_key = key(20);
        let bodies = [
            FactBody::KindChange {
                to: GovernanceKind::Open,
            },
            FactBody::RoleGrant {
                target: "victim".into(),
                role: Role::Controller,
            },
            FactBody::RoleRevoke {
                target: "victim".into(),
            },
            FactBody::Evict {
                target: "victim".into(),
            },
            FactBody::Split {
                new_network_id: "child".into(),
                members: vec!["a".into(), "b".into()],
            },
            FactBody::TopologyChange {
                to: Topology::FullMesh,
            },
            FactBody::Attestation {
                target: "victim".into(),
                proposal: FactId::from_bytes([21; 32]),
                decision: AttestationDecision::Approve,
                signer: author(&signing_key),
                contributions: Vec::new(),
            },
            FactBody::Resolution {
                cell: ExclusiveCell::new("network", "kind"),
                cited_heads: vec![FactId::from_bytes([22; 32])],
                selected_head: FactId::from_bytes([22; 32]),
            },
        ];
        for body in bodies {
            let mut mutated = fact(&signing_key, body, Vec::new());
            mutated.content.body = FactBody::RoleRevoke {
                target: "different-victim".into(),
            };
            assert!(matches!(
                graph(&signing_key).admit(mutated),
                Err(SemanticError::FactIdMismatch)
            ));
        }
    }

    #[test]
    fn open_participation_is_self_authored() {
        let signing_key = key(9);
        let content = FactContent::open_participation(
            "mesh-a",
            author(&signing_key),
            true,
            "join",
            Vec::new(),
        );
        let fact = SignedFact::sign(content, &signing_key).unwrap();
        assert!(fact.verify().is_ok());
    }

    #[test]
    fn projection_does_not_depend_on_arrival_order() {
        let signing_key = key(10);
        let first = fact(
            &signing_key,
            FactBody::KindChange {
                to: GovernanceKind::Open,
            },
            Vec::new(),
        );
        let second = fact(
            &signing_key,
            FactBody::KindChange {
                to: GovernanceKind::Closed,
            },
            Vec::new(),
        );
        let mut left = graph(&signing_key);
        left.admit(first.clone()).unwrap();
        left.admit(second.clone()).unwrap();
        let mut right = graph(&signing_key);
        right.admit(second).unwrap();
        right.admit(first).unwrap();
        assert_eq!(left.projection(), right.projection());
        assert!(left
            .projection()
            .is_conflicted(&ExclusiveCell::new("network", "kind")));
    }
}
