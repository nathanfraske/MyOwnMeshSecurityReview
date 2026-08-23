//! Canonical, transport-independent V4 semantic content.
//!
//! This module deliberately contains no wire envelope, session route, clock,
//! or courier field.  The byte encoding is explicit so a future serializer
//! cannot accidentally make map order or serde representation authoritative.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::FactId;

/// Domain separation for canonical semantic facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactDomain {
    Governance,
    Participation,
    Checkpoint,
    EvictionProof,
}

impl FactDomain {
    pub(crate) fn tag(self) -> &'static str {
        match self {
            Self::Governance => "governance",
            Self::Participation => "participation",
            Self::Checkpoint => "checkpoint",
            Self::EvictionProof => "eviction_proof",
        }
    }
}

/// V4 governance kind.  This is intentionally independent of the legacy wire
/// `NetworkKind`; adapters may translate it during migration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceKind {
    Open,
    Closed,
    Silent,
}

/// V4 role tier, kept in the Semantic owner rather than borrowed from a wire
/// projection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Member,
    Controller,
    Owner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationDecision {
    Evict,
    Approve,
    Reject,
}

/// Canonical topology body.  Lists are normalized before encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Topology {
    FullMesh,
    Ring {
        preferred: Option<u32>,
    },
    Star {
        hub: String,
    },
    Hubs {
        hubs: Vec<String>,
        spoke_redundancy: Option<u32>,
    },
}

/// The exclusive semantic cell a fact may advance.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ExclusiveCell {
    pub subject: String,
    pub field: String,
}

impl ExclusiveCell {
    pub fn new(subject: impl Into<String>, field: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            field: field.into(),
        }
    }
}

/// Typed V4 bodies mirroring the current transition fields without retaining
/// the legacy envelope, timestamp, or parallel signer-vector shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum FactBody {
    KindChange {
        to: GovernanceKind,
    },
    RoleGrant {
        target: String,
        role: Role,
    },
    RoleRevoke {
        target: String,
    },
    Evict {
        target: String,
    },
    Split {
        new_network_id: String,
        members: Vec<String>,
    },
    TopologyChange {
        to: Topology,
    },
    /// Self-authored Open/Silent participation.  The author must equal
    /// `device_id` after display-suffix normalization.
    OpenParticipation {
        device_id: String,
        joined: bool,
        label: String,
    },
    /// Foundation type for later durable-store checkpoints.  It is content
    /// and verification only; persistence/recovery remains a later unit.
    Checkpoint {
        checkpoint_id: String,
        heads: Vec<FactId>,
    },
    /// Foundation type for later durable eviction proof delivery.
    EvictionProof {
        target: String,
        evidence: Vec<FactId>,
    },
    /// A device may author its own stand-down with complete evidence.
    SelfStandDown {
        device_id: String,
        evidence: Vec<FactId>,
    },
    /// A signed decision binds its proposal, target, decision, signer, and
    /// every contribution into one canonical semantic fact.
    Attestation {
        target: String,
        proposal: FactId,
        decision: AttestationDecision,
        signer: String,
        contributions: Vec<FactId>,
    },
    /// A resolution explicitly names every incomparable head it resolves.
    /// `selected_head` must be one of `cited_heads`.
    Resolution {
        cell: ExclusiveCell,
        cited_heads: Vec<FactId>,
        selected_head: FactId,
    },
}

impl FactBody {
    /// Normalize constructor input. Wire deserialization and validation use
    /// `validate_canonical` instead, so alternate list order never hashes to
    /// the same identity as canonical wire content.
    pub fn normalize(&mut self) {
        match self {
            Self::Split { members, .. } => {
                members.sort();
                members.dedup();
            }
            Self::TopologyChange { to } => to.normalize(),
            Self::Checkpoint { heads, .. } => {
                heads.sort();
                heads.dedup();
            }
            Self::EvictionProof { evidence, .. } => {
                evidence.sort();
                evidence.dedup();
            }
            Self::SelfStandDown { evidence, .. } => {
                evidence.sort();
                evidence.dedup();
            }
            Self::Attestation { contributions, .. } => {
                contributions.sort();
                contributions.dedup();
            }
            Self::Resolution { cited_heads, .. } => {
                cited_heads.sort();
                cited_heads.dedup();
            }
            _ => {}
        }
    }

    pub(crate) fn validate_canonical(&self) -> Result<(), super::SemanticError> {
        match self {
            Self::Split { members, .. } => require_sorted_unique(members, "Split.members"),
            Self::TopologyChange { to } => to.validate_canonical(),
            Self::Checkpoint { heads, .. } => require_sorted_unique(heads, "Checkpoint.heads"),
            Self::EvictionProof { target, evidence } => {
                if target.is_empty() || evidence.is_empty() {
                    return Err(super::SemanticError::IncompleteEvictionProof);
                }
                require_sorted_unique(evidence, "EvictionProof.evidence")
            }
            Self::SelfStandDown {
                device_id,
                evidence,
            } => {
                if device_id.is_empty() || evidence.is_empty() {
                    return Err(super::SemanticError::IncompleteEvictionProof);
                }
                require_sorted_unique(evidence, "SelfStandDown.evidence")
            }
            Self::Attestation {
                target,
                signer,
                contributions,
                ..
            } => {
                if target.is_empty() || signer.is_empty() {
                    return Err(super::SemanticError::EmptyField(
                        "attestation target/signer",
                    ));
                }
                require_sorted_unique(contributions, "Attestation.contributions")
            }
            Self::Resolution { cited_heads, .. } => {
                require_sorted_unique(cited_heads, "Resolution.cited_heads")
            }
            _ => Ok(()),
        }
    }

    pub fn domain(&self) -> FactDomain {
        match self {
            Self::OpenParticipation { .. } => FactDomain::Participation,
            Self::Checkpoint { .. } => FactDomain::Checkpoint,
            Self::EvictionProof { .. } | Self::SelfStandDown { .. } => FactDomain::EvictionProof,
            Self::Attestation { .. } => FactDomain::Governance,
            _ => FactDomain::Governance,
        }
    }

    /// Return every exclusive cell affected by this body.  Eviction advances
    /// both role and membership, so it intentionally contributes two cells.
    pub fn exclusive_cells(&self) -> Vec<ExclusiveCell> {
        match self {
            Self::KindChange { .. } => vec![ExclusiveCell::new("network", "kind")],
            Self::RoleGrant { target, .. } | Self::RoleRevoke { target } => {
                vec![ExclusiveCell::new(target, "role")]
            }
            Self::Evict { target } => vec![
                ExclusiveCell::new(target, "role"),
                ExclusiveCell::new(target, "membership"),
            ],
            Self::Split { new_network_id, .. } => {
                vec![ExclusiveCell::new(new_network_id, "split")]
            }
            Self::TopologyChange { .. } => vec![ExclusiveCell::new("network", "topology")],
            Self::OpenParticipation { device_id, .. } => {
                vec![ExclusiveCell::new(device_id, "open_participation")]
            }
            Self::Checkpoint { .. } | Self::EvictionProof { .. } | Self::SelfStandDown { .. } => {
                Vec::new()
            }
            Self::Attestation { proposal, .. } => {
                vec![ExclusiveCell::new(proposal.to_string(), "decision")]
            }
            Self::Resolution { cell, .. } => vec![cell.clone()],
        }
    }

    pub(crate) fn encode(&self, out: &mut Encoder) {
        match self {
            Self::KindChange { to } => {
                out.tag("kind_change");
                out.tag(match to {
                    GovernanceKind::Open => "open",
                    GovernanceKind::Closed => "closed",
                    GovernanceKind::Silent => "silent",
                });
            }
            Self::RoleGrant { target, role } => {
                out.tag("role_grant");
                out.text(target);
                out.tag(match role {
                    Role::Member => "member",
                    Role::Controller => "controller",
                    Role::Owner => "owner",
                });
            }
            Self::RoleRevoke { target } => {
                out.tag("role_revoke");
                out.text(target);
            }
            Self::Evict { target } => {
                out.tag("evict");
                out.text(target);
            }
            Self::Split {
                new_network_id,
                members,
            } => {
                out.tag("split");
                out.text(new_network_id);
                out.list_text(members);
            }
            Self::TopologyChange { to } => {
                out.tag("topology_change");
                to.encode(out);
            }
            Self::OpenParticipation {
                device_id,
                joined,
                label,
            } => {
                out.tag("open_participation");
                out.text(device_id);
                out.bool(*joined);
                out.text(label);
            }
            Self::Checkpoint {
                checkpoint_id,
                heads,
            } => {
                out.tag("checkpoint");
                out.text(checkpoint_id);
                out.list_ids(heads);
            }
            Self::EvictionProof { target, evidence } => {
                out.tag("eviction_proof");
                out.text(target);
                out.list_ids(evidence);
            }
            Self::SelfStandDown {
                device_id,
                evidence,
            } => {
                out.tag("self_stand_down");
                out.text(device_id);
                out.list_ids(evidence);
            }
            Self::Attestation {
                target,
                proposal,
                decision,
                signer,
                contributions,
            } => {
                out.tag("attestation");
                out.text(target);
                out.id(*proposal);
                out.tag(match decision {
                    AttestationDecision::Evict => "evict",
                    AttestationDecision::Approve => "approve",
                    AttestationDecision::Reject => "reject",
                });
                out.text(signer);
                out.list_ids(contributions);
            }
            Self::Resolution {
                cell,
                cited_heads,
                selected_head,
            } => {
                out.tag("resolution");
                cell.encode(out);
                out.list_ids(cited_heads);
                out.id(*selected_head);
            }
        }
    }
}

impl Topology {
    fn normalize(&mut self) {
        if let Self::Hubs { hubs, .. } = self {
            hubs.sort();
            hubs.dedup();
        }
    }

    fn validate_canonical(&self) -> Result<(), super::SemanticError> {
        match self {
            Self::Hubs { hubs, .. } => require_sorted_unique(hubs, "Topology.hubs"),
            _ => Ok(()),
        }
    }

    fn encode(&self, out: &mut Encoder) {
        match self {
            Self::FullMesh => out.tag("full_mesh"),
            Self::Ring { preferred } => {
                out.tag("ring");
                out.option_u32(*preferred);
            }
            Self::Star { hub } => {
                out.tag("star");
                out.text(hub);
            }
            Self::Hubs {
                hubs,
                spoke_redundancy,
            } => {
                out.tag("hubs");
                out.list_text(hubs);
                out.option_u32(*spoke_redundancy);
            }
        }
    }
}

fn require_sorted_unique<T: Ord>(
    values: &[T],
    field: &'static str,
) -> Result<(), super::SemanticError> {
    if values.windows(2).all(|pair| pair[0] < pair[1]) {
        Ok(())
    } else {
        Err(super::SemanticError::NonCanonicalSet(field))
    }
}

impl ExclusiveCell {
    pub(crate) fn encode(&self, out: &mut Encoder) {
        out.text(&self.subject);
        out.text(&self.field);
    }
}

/// Small length-delimited canonical encoder.  Length prefixes prevent field
/// concatenation ambiguity without relying on a serializer's map ordering.
pub(crate) struct Encoder {
    bytes: Vec<u8>,
}

impl Encoder {
    pub(crate) fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub(crate) fn tag(&mut self, value: &str) {
        self.text(value);
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) {
        self.bytes
            .extend_from_slice(&(value.len() as u64).to_be_bytes());
        self.bytes.extend_from_slice(value);
    }

    pub(crate) fn text(&mut self, value: &str) {
        self.bytes
            .extend_from_slice(&(value.len() as u64).to_be_bytes());
        self.bytes.extend_from_slice(value.as_bytes());
    }

    pub(crate) fn bool(&mut self, value: bool) {
        self.bytes.push(u8::from(value));
    }

    pub(crate) fn option_u32(&mut self, value: Option<u32>) {
        match value {
            Some(value) => {
                self.bool(true);
                self.bytes.extend_from_slice(&value.to_be_bytes());
            }
            None => self.bool(false),
        }
    }

    pub(crate) fn id(&mut self, value: FactId) {
        self.bytes.extend_from_slice(value.as_bytes());
    }

    pub(crate) fn list_ids(&mut self, values: &[FactId]) {
        self.bytes
            .extend_from_slice(&(values.len() as u64).to_be_bytes());
        for value in values {
            self.id(*value);
        }
    }

    pub(crate) fn list_text(&mut self, values: &[String]) {
        self.bytes
            .extend_from_slice(&(values.len() as u64).to_be_bytes());
        for value in values {
            self.text(value);
        }
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

impl fmt::Display for ExclusiveCell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.subject, self.field)
    }
}
