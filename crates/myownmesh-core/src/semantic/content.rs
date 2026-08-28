//! Canonical, transport-independent V4 semantic content.
//!
//! Authority-bearing values in this module are deliberately typed.  A display
//! label, carrier spelling, or alternate serialization cannot become a second
//! semantic identity or exclusive-cell key.

use std::fmt;

use data_encoding::BASE32_NOPAD;
use ed25519_dalek::VerifyingKey;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};

use super::FactId;

/// Domain separation for the adopted V4 durable fact union.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactDomain {
    Governance,
    Participation,
    EvictionProof,
}

impl FactDomain {
    pub(crate) fn tag(self) -> &'static str {
        match self {
            Self::Governance => "governance",
            Self::Participation => "participation",
            Self::EvictionProof => "eviction_proof",
        }
    }
}

/// The only authority-bearing device identity accepted by canonical facts.
///
/// This is the raw Ed25519 public key in its canonical lowercase base32 form.
/// Display suffixes, uppercase encodings, padding, and alternate base32 forms
/// are rejected before a value can enter a fact or cell.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceId(String);

pub type CanonicalDeviceId = DeviceId;

/// Signed, typed authority lineage for one authority-bearing subject.  The
/// predecessor list is part of FactContent (and therefore of FactId), so a
/// receiver cannot silently substitute a later or unrelated role head.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AuthorityUse {
    pub subject: DeviceId,
    pub predecessors: Vec<FactId>,
}

impl AuthorityUse {
    pub(crate) fn new(subject: DeviceId, mut predecessors: Vec<FactId>) -> Self {
        predecessors.sort();
        predecessors.dedup();
        Self {
            subject,
            predecessors,
        }
    }
}

/// The semantic owner's typed authority relation for one subject.
///
/// `heads` is the complete current AuthorityUse head set, calculated from the
/// causal graph rather than copied from a caller. An ordinary operation is
/// authorizable only when this relation is singular (or empty for the
/// bootstrap root). A typed `Resolution` may cite the complete conflicting
/// set and select one branch; once admitted, that resolution is itself the
/// sole lineage head for descendants and re-grants.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthorityLineage {
    subject: DeviceId,
    heads: Vec<FactId>,
    selected_branch: Option<FactId>,
}

impl AuthorityLineage {
    pub(crate) fn from_heads(
        subject: DeviceId,
        mut heads: Vec<FactId>,
        selected_branch: Option<FactId>,
    ) -> Self {
        heads.sort();
        heads.dedup();
        Self {
            subject,
            heads,
            selected_branch,
        }
    }

    pub fn subject(&self) -> &DeviceId {
        &self.subject
    }

    pub fn heads(&self) -> &[FactId] {
        &self.heads
    }

    pub fn effective_head(&self) -> Option<FactId> {
        (self.heads.len() == 1).then_some(self.heads[0])
    }

    /// Return the branch selected by the effective typed resolution, when
    /// this lineage descends from one. The selection remains attached to the
    /// subject relation even after a later regrant replaces the raw head.
    pub fn selected_branch(&self) -> Option<FactId> {
        self.selected_branch
    }

    /// Whether this relation has at most one effective head. An empty
    /// relation is the bootstrap state; an ordinary relation must be
    /// singular before it can authorize another ordinary operation.
    pub fn is_singular(&self) -> bool {
        self.heads.len() <= 1
    }

    /// Return the complete conflict set when this relation is forked. A
    /// lineage resolution must cite this exact set.
    pub fn complete_conflict_set(&self) -> Option<&[FactId]> {
        self.is_conflicted().then_some(self.heads.as_slice())
    }

    pub fn is_conflicted(&self) -> bool {
        self.heads.len() > 1
    }
}

impl DeviceId {
    pub fn from_public_key_bytes(bytes: [u8; 32]) -> Result<Self, String> {
        VerifyingKey::from_bytes(&bytes)
            .map_err(|error| format!("invalid Ed25519 public key: {error}"))?;
        let encoded = BASE32_NOPAD.encode(&bytes).to_lowercase();
        Ok(Self(encoded))
    }

    pub fn from_canonical_str(value: &str) -> Result<Self, String> {
        if value.is_empty() || value != value.to_lowercase() {
            return Err("DeviceId must use lowercase unpadded base32".into());
        }
        let bytes = BASE32_NOPAD
            .decode(value.to_uppercase().as_bytes())
            .map_err(|error| format!("DeviceId is not canonical base32: {error}"))?;
        if bytes.len() != 32 {
            return Err("DeviceId must decode to 32 bytes".into());
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        let id = Self::from_public_key_bytes(key)?;
        if id.base32() != value {
            return Err("DeviceId is not the canonical base32 spelling".into());
        }
        Ok(id)
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        let bytes = BASE32_NOPAD
            .decode(self.0.to_uppercase().as_bytes())
            .expect("DeviceId stores canonical base32");
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        key
    }

    pub fn base32(&self) -> String {
        self.0.clone()
    }
}

impl std::ops::Deref for DeviceId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Debug for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("DeviceId").field(&self.base32()).finish()
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.base32())
    }
}

impl Serialize for DeviceId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.base32())
    }
}

impl<'de> Deserialize<'de> for DeviceId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_canonical_str(&value).map_err(D::Error::custom)
    }
}

/// V4 role tier.  The selected Closed profile determines which tier may
/// author each governance operation; the fact body does not flatten that rule.
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

/// Closed typed union of semantic cells.  The subject type is fixed by the
/// variant, so a free-form `(subject, field)` pair cannot alias authority.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ExclusiveCell {
    Role { subject: DeviceId },
    Membership { subject: DeviceId },
    OpenParticipation { subject: DeviceId },
    Decision { proposal: FactId },
}

impl ExclusiveCell {
    pub fn role(subject: DeviceId) -> Self {
        Self::Role { subject }
    }

    pub fn membership(subject: DeviceId) -> Self {
        Self::Membership { subject }
    }

    pub fn open_participation(subject: DeviceId) -> Self {
        Self::OpenParticipation { subject }
    }

    pub fn decision(proposal: FactId) -> Self {
        Self::Decision { proposal }
    }

    pub(crate) fn encode(&self, out: &mut Encoder) {
        match self {
            Self::Role { subject } => {
                out.tag("role");
                out.device(subject);
            }
            Self::Membership { subject } => {
                out.tag("membership");
                out.device(subject);
            }
            Self::OpenParticipation { subject } => {
                out.tag("open_participation");
                out.device(subject);
            }
            Self::Decision { proposal } => {
                out.tag("decision");
                out.id(*proposal);
            }
        }
    }
}

impl fmt::Display for ExclusiveCell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Role { subject } => write!(f, "role:{subject}"),
            Self::Membership { subject } => write!(f, "membership:{subject}"),
            Self::OpenParticipation { subject } => write!(f, "open_participation:{subject}"),
            Self::Decision { proposal } => write!(f, "decision:{proposal}"),
        }
    }
}

/// The adopted V4 durable semantic union.  Context selection, topology, and
/// compaction evidence are outside this ordinary fact graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum FactBody {
    RoleGrant {
        target: DeviceId,
        role: Role,
    },
    RoleRevoke {
        target: DeviceId,
    },
    Evict {
        target: DeviceId,
    },
    /// Controller-authorized Closed membership restoration. Role authority
    /// remains a separate role-cell fact and must be carried causally when
    /// both are needed to restore session admission.
    MembershipAdmit {
        target: DeviceId,
    },
    /// Self-authored Open participation.  Presentation labels are local UI
    /// data and are intentionally not signed into membership authority.
    OpenParticipation {
        device_id: DeviceId,
        joined: bool,
    },
    EvictionProof {
        target: DeviceId,
        evidence: Vec<FactId>,
    },
    SelfStandDown {
        device_id: DeviceId,
        evidence: Vec<FactId>,
    },
    Attestation {
        target: DeviceId,
        proposal: FactId,
        decision: AttestationDecision,
        signer: DeviceId,
        contributions: Vec<FactId>,
    },
    Resolution {
        cell: ExclusiveCell,
        cited_heads: Vec<FactId>,
        selected_head: FactId,
    },
}

impl FactBody {
    pub fn normalize(&mut self) {
        match self {
            Self::EvictionProof { evidence, .. }
            | Self::SelfStandDown { evidence, .. }
            | Self::Attestation {
                contributions: evidence,
                ..
            }
            | Self::Resolution {
                cited_heads: evidence,
                ..
            } => {
                evidence.sort();
                evidence.dedup();
            }
            _ => {}
        }
    }

    pub(crate) fn validate_canonical(&self) -> Result<(), super::SemanticError> {
        match self {
            Self::EvictionProof { evidence, .. } | Self::SelfStandDown { evidence, .. } => {
                if evidence.is_empty() {
                    return Err(super::SemanticError::IncompleteEvictionProof);
                }
                require_sorted_unique(evidence, "eviction evidence")
            }
            Self::Attestation { contributions, .. } => {
                require_sorted_unique(contributions, "attestation contributions")
            }
            Self::Resolution { cited_heads, .. } => {
                require_sorted_unique(cited_heads, "resolution cited heads")
            }
            _ => Ok(()),
        }
    }

    pub fn domain(&self) -> FactDomain {
        match self {
            Self::OpenParticipation { .. } => FactDomain::Participation,
            Self::EvictionProof { .. } | Self::SelfStandDown { .. } => FactDomain::EvictionProof,
            _ => FactDomain::Governance,
        }
    }

    pub fn exclusive_cells(&self) -> Vec<ExclusiveCell> {
        match self {
            Self::RoleGrant { target, .. } | Self::RoleRevoke { target } => {
                vec![ExclusiveCell::role(target.clone())]
            }
            Self::Evict { target } => vec![
                ExclusiveCell::role(target.clone()),
                ExclusiveCell::membership(target.clone()),
            ],
            Self::MembershipAdmit { target } => {
                vec![ExclusiveCell::membership(target.clone())]
            }
            Self::OpenParticipation { device_id, .. } => {
                vec![ExclusiveCell::open_participation(device_id.clone())]
            }
            Self::EvictionProof { .. } | Self::SelfStandDown { .. } => Vec::new(),
            Self::Attestation { proposal, .. } => vec![ExclusiveCell::decision(*proposal)],
            Self::Resolution { cell, .. } => vec![cell.clone()],
        }
    }

    pub(crate) fn authority_use_subjects(&self, author: &DeviceId) -> Vec<DeviceId> {
        let mut subjects = match self {
            Self::RoleGrant { target, .. }
            | Self::RoleRevoke { target }
            | Self::Evict { target } => vec![author.clone(), target.clone()],
            Self::MembershipAdmit { target } | Self::EvictionProof { target, .. } => {
                vec![author.clone(), target.clone()]
            }
            Self::SelfStandDown { device_id, .. } => vec![author.clone(), device_id.clone()],
            Self::Attestation { .. } => vec![author.clone()],
            Self::Resolution { cell, .. } => {
                let mut subjects = vec![author.clone()];
                match cell {
                    ExclusiveCell::Role { subject }
                    | ExclusiveCell::Membership { subject }
                    | ExclusiveCell::OpenParticipation { subject } => {
                        subjects.push(subject.clone())
                    }
                    ExclusiveCell::Decision { .. } => {}
                }
                subjects
            }
            _ => Vec::new(),
        };
        subjects.sort();
        subjects.dedup();
        subjects
    }

    /// Return the non-cell facts that must be in the causal past of this
    /// body.  Exclusive-cell predecessors come from `FactGraph`'s
    /// authoring witness; evidence and cited heads are body-owned support and
    /// must be carried explicitly as parents as well.
    pub fn causal_support(&self) -> Vec<FactId> {
        let mut support = match self {
            Self::EvictionProof { evidence, .. } | Self::SelfStandDown { evidence, .. } => {
                evidence.clone()
            }
            Self::Attestation {
                proposal,
                contributions,
                ..
            } => {
                let mut ids = vec![*proposal];
                ids.extend(contributions.iter().copied());
                ids
            }
            Self::Resolution { cited_heads, .. } => cited_heads.clone(),
            _ => Vec::new(),
        };
        support.sort();
        support.dedup();
        support
    }

    pub(crate) fn encode(&self, out: &mut Encoder) {
        match self {
            Self::RoleGrant { target, role } => {
                out.tag("role_grant");
                out.device(target);
                out.tag(match role {
                    Role::Member => "member",
                    Role::Controller => "controller",
                    Role::Owner => "owner",
                });
            }
            Self::RoleRevoke { target } => {
                out.tag("role_revoke");
                out.device(target);
            }
            Self::Evict { target } => {
                out.tag("evict");
                out.device(target);
            }
            Self::MembershipAdmit { target } => {
                out.tag("membership_admit");
                out.device(target);
            }
            Self::OpenParticipation { device_id, joined } => {
                out.tag("open_participation");
                out.device(device_id);
                out.bool(*joined);
            }
            Self::EvictionProof { target, evidence } => {
                out.tag("eviction_proof");
                out.device(target);
                out.list_ids(evidence);
            }
            Self::SelfStandDown {
                device_id,
                evidence,
            } => {
                out.tag("self_stand_down");
                out.device(device_id);
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
                out.device(target);
                out.id(*proposal);
                out.tag(match decision {
                    AttestationDecision::Evict => "evict",
                    AttestationDecision::Approve => "approve",
                    AttestationDecision::Reject => "reject",
                });
                out.device(signer);
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

    pub(crate) fn id(&mut self, value: FactId) {
        self.bytes.extend_from_slice(value.as_bytes());
    }

    pub(crate) fn device(&mut self, value: &DeviceId) {
        self.bytes.extend_from_slice(&value.as_bytes());
    }

    pub(crate) fn context(&mut self, value: super::MeshContextId) {
        self.bytes.extend_from_slice(value.as_bytes());
    }

    pub(crate) fn list_ids(&mut self, values: &[FactId]) {
        self.bytes
            .extend_from_slice(&(values.len() as u64).to_be_bytes());
        for value in values {
            self.id(*value);
        }
    }

    pub(crate) fn list_authority_uses(&mut self, values: &[AuthorityUse]) {
        self.bytes
            .extend_from_slice(&(values.len() as u64).to_be_bytes());
        for value in values {
            self.device(&value.subject);
            self.list_ids(&value.predecessors);
        }
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device() -> DeviceId {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]);
        DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes()).unwrap()
    }

    #[test]
    fn device_aliases_are_rejected_before_fact_construction() {
        let canonical = device().base32();
        assert!(DeviceId::from_canonical_str(&canonical).is_ok());
        assert!(DeviceId::from_canonical_str(&canonical.to_uppercase()).is_err());
        assert!(DeviceId::from_canonical_str(&format!("{canonical}-label")).is_err());
        assert!(DeviceId::from_canonical_str(&format!("{canonical}=")).is_err());
    }

    #[test]
    fn exclusive_cells_are_a_closed_typed_union() {
        let id = device();
        assert_ne!(
            ExclusiveCell::role(id.clone()),
            ExclusiveCell::membership(id.clone())
        );
        assert_eq!(
            ExclusiveCell::role(id.clone()).to_string(),
            format!("role:{id}")
        );
        assert_eq!(
            ExclusiveCell::open_participation(id.clone()).to_string(),
            format!("open_participation:{id}")
        );
    }
}
