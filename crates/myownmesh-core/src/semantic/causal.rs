//! Deterministic causal admission for canonical semantic facts.

use std::collections::{BTreeMap, BTreeSet};

use super::content::{DeviceId, ExclusiveCell, FactBody, Role};
use super::{FactId, MeshContextId, Projection, SemanticError, SignedFact, VerifiedBootstrap};

/// Return the complete canonical dependency set for one fact.  Every caller
/// that decides whether a fact is ready must use this function: parents,
/// durable evidence, attestation inputs, and explicitly cited resolution
/// heads are all causal inputs, regardless of their arrival order.
pub fn dependencies(fact: &SignedFact) -> Vec<FactId> {
    let mut dependencies = fact.content.parents.clone();
    match &fact.content.body {
        FactBody::EvictionProof { evidence, .. } | FactBody::SelfStandDown { evidence, .. } => {
            dependencies.extend(evidence.iter().copied())
        }
        FactBody::Attestation {
            proposal,
            contributions,
            ..
        } => {
            dependencies.push(*proposal);
            dependencies.extend(contributions.iter().copied());
        }
        FactBody::Resolution { cited_heads, .. } => {
            dependencies.extend(cited_heads.iter().copied())
        }
        _ => {}
    }
    dependencies.sort();
    dependencies.dedup();
    dependencies
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    Inserted,
    AlreadyPresent,
    Quarantined { missing: Vec<FactId> },
}

/// An arrival-order-independent set of verified canonical facts.
#[derive(Debug, Clone)]
pub struct FactGraph {
    pub(crate) facts: BTreeMap<FactId, SignedFact>,
    pub(crate) quarantined: BTreeMap<FactId, SignedFact>,
    context_id: MeshContextId,
    authority_roots: BTreeSet<DeviceId>,
}

impl FactGraph {
    /// Construct the graph from the verified, exact bootstrap context. The
    /// graph owns the policy snapshot, so callers cannot supply an unrelated
    /// root set or leave the graph context unbound.
    pub fn from_bootstrap(bootstrap: &VerifiedBootstrap) -> Self {
        Self {
            facts: BTreeMap::new(),
            quarantined: BTreeMap::new(),
            context_id: bootstrap.context_id(),
            authority_roots: bootstrap
                .authority_roots()
                .iter()
                .filter_map(|root| DeviceId::from_canonical_str(root).ok())
                .collect(),
        }
    }

    pub fn context_id(&self) -> MeshContextId {
        self.context_id
    }

    pub fn len(&self) -> usize {
        self.facts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.facts.is_empty()
    }

    pub fn get(&self, id: &FactId) -> Option<&SignedFact> {
        self.facts.get(id)
    }

    pub fn ids(&self) -> impl Iterator<Item = &FactId> {
        self.facts.keys()
    }

    pub fn admit(&mut self, fact: SignedFact) -> Result<Admission, SemanticError> {
        fact.verify()?;
        if fact.content.mesh_context != self.context_id {
            return Err(SemanticError::ContextMismatch {
                expected: self.context_id,
                found: fact.content.mesh_context.to_string(),
            });
        }
        if let Some(existing) = self.facts.get(&fact.id) {
            return if existing == &fact {
                Ok(Admission::AlreadyPresent)
            } else {
                Err(SemanticError::DuplicateFact(fact.id))
            };
        }
        if let Some(existing) = self.quarantined.get(&fact.id) {
            return if existing == &fact {
                Ok(Admission::AlreadyPresent)
            } else {
                Err(SemanticError::DuplicateFact(fact.id))
            };
        }
        if fact.content.parents.contains(&fact.id) {
            return Err(SemanticError::SelfParent);
        }
        let missing = self.missing_dependencies(&fact);
        if !missing.is_empty() {
            self.quarantined.insert(fact.id, fact);
            return Ok(Admission::Quarantined { missing });
        }
        for parent in &fact.content.parents {
            if !self.facts.contains_key(parent) {
                return Err(SemanticError::MissingParent(*parent));
            }
        }
        if let FactBody::Resolution {
            cell,
            cited_heads,
            selected_head,
        } = &fact.content.body
        {
            if !cited_heads.contains(selected_head) {
                return Err(SemanticError::ResolutionSelectionNotCited);
            }
            let mut cited = cited_heads.clone();
            cited.sort();
            cited.dedup();
            if cited.len() < 2
                || cited.len() != cited_heads.len()
                || cited.as_slice() != cited_heads.as_slice()
            {
                return Err(SemanticError::IncompleteResolution);
            }
            for head in &cited {
                if !self.facts.contains_key(head) {
                    return Err(SemanticError::UnknownResolutionHead(*head));
                }
                if !fact.content.parents.contains(head) {
                    return Err(SemanticError::IncompleteResolution);
                }
                if !super::verify::body_advances_cell(&self.facts[head].content.body, cell) {
                    return Err(SemanticError::IncompleteResolution);
                }
            }
            if self.cell_heads(cell) != cited {
                return Err(SemanticError::ResolutionNotCurrent);
            }
        }
        if let Some(error) = Self::authorization_error(&fact.content.body) {
            if !self.is_authorized_for(&fact.content.body, &fact.content.author) {
                return Err(error);
            }
        }
        match &fact.content.body {
            FactBody::EvictionProof { target, evidence } => {
                self.validate_eviction_proof(target, evidence, &fact.content.author)?;
            }
            FactBody::SelfStandDown {
                device_id,
                evidence,
            } => {
                self.validate_self_stand_down(device_id, evidence, &fact.content.author)?;
            }
            _ => {}
        }
        self.facts.insert(fact.id, fact);
        Ok(Admission::Inserted)
    }

    fn validate_eviction_proof(
        &self,
        target: &DeviceId,
        evidence: &[FactId],
        author: &DeviceId,
    ) -> Result<(), SemanticError> {
        if !self.is_authorized_for(
            &FactBody::Evict {
                target: target.clone(),
            },
            author,
        ) {
            return Err(SemanticError::UnauthorizedEviction);
        }
        for evidence_id in evidence {
            let Some(attestation) = self.facts.get(evidence_id) else {
                return Err(SemanticError::InvalidEvictionEvidence);
            };
            let FactBody::Attestation {
                target: attestation_target,
                decision: super::AttestationDecision::Evict,
                signer,
                ..
            } = &attestation.content.body
            else {
                return Err(SemanticError::InvalidEvictionEvidence);
            };
            if attestation_target != target
                || !self.has_tier(signer, Role::Member)
                || *signer != attestation.content.author
            {
                return Err(SemanticError::InvalidEvictionEvidence);
            }
        }
        Ok(())
    }

    /// Return the existing domain-specific admission error for every fact that
    /// can mutate governance or an exclusive cell. Participation and durable
    /// evidence retain their separate self-author/proof rules below; they do
    /// not become implicitly authorized by this table.
    fn authorization_error(body: &FactBody) -> Option<SemanticError> {
        match body {
            FactBody::RoleGrant { .. }
            | FactBody::RoleRevoke { .. }
            | FactBody::Evict { .. }
            | FactBody::Resolution { .. } => Some(SemanticError::UnauthorizedRoleGrant),
            FactBody::Attestation { .. } => Some(SemanticError::UnauthorizedAttestation),
            _ => None,
        }
    }

    fn validate_self_stand_down(
        &self,
        device_id: &DeviceId,
        evidence: &[FactId],
        author: &DeviceId,
    ) -> Result<(), SemanticError> {
        if device_id != author {
            return Err(SemanticError::InvalidStandDownProof);
        }
        for evidence_id in evidence {
            let Some(proof) = self.facts.get(evidence_id) else {
                return Err(SemanticError::InvalidStandDownProof);
            };
            let FactBody::EvictionProof { target, .. } = &proof.content.body else {
                return Err(SemanticError::InvalidStandDownProof);
            };
            if target != device_id {
                return Err(SemanticError::InvalidStandDownProof);
            }
        }
        Ok(())
    }

    pub fn is_authorized_signer(&self, signer: &DeviceId) -> bool {
        self.current_role(signer).is_some()
    }

    fn current_role(&self, subject: &DeviceId) -> Option<Role> {
        if self.authority_roots.contains(subject) {
            return Some(Role::Owner);
        }
        let id = self
            .projection()
            .value(&ExclusiveCell::role(subject.clone()))?;
        let fact = self.facts.get(&id)?;
        match &fact.content.body {
            FactBody::RoleGrant { target, role } if target == subject => Some(*role),
            _ => None,
        }
    }

    fn has_tier(&self, signer: &DeviceId, required: Role) -> bool {
        let Some(actual) = self.current_role(signer) else {
            return false;
        };
        matches!(
            (actual, required),
            (Role::Owner, _)
                | (Role::Controller, Role::Controller | Role::Member)
                | (Role::Member, Role::Member)
        )
    }

    fn target_tier(&self, target: &DeviceId) -> Role {
        match self.current_role(target) {
            Some(Role::Owner) => Role::Owner,
            Some(Role::Controller) => Role::Controller,
            Some(Role::Member) => Role::Controller,
            None => Role::Owner,
        }
    }

    fn resolution_tier(&self, cell: &ExclusiveCell, cited_heads: &[FactId]) -> Role {
        match cell {
            ExclusiveCell::Role { subject } => match self.current_role(subject) {
                Some(_) => self.target_tier(subject),
                None => cited_heads
                    .iter()
                    .filter_map(|id| self.facts.get(id))
                    .map(|fact| match &fact.content.body {
                        FactBody::RoleGrant {
                            role: Role::Member, ..
                        } => Role::Controller,
                        _ => Role::Owner,
                    })
                    .max()
                    .unwrap_or(Role::Owner),
            },
            ExclusiveCell::Membership { subject } => self.target_tier(subject),
            ExclusiveCell::Decision { .. } | ExclusiveCell::OpenParticipation { .. } => {
                Role::Member
            }
        }
    }

    fn is_authorized_for(&self, body: &FactBody, author: &DeviceId) -> bool {
        let required = match body {
            FactBody::RoleGrant { role, .. } => match role {
                Role::Member => Role::Controller,
                Role::Controller | Role::Owner => Role::Owner,
            },
            FactBody::RoleRevoke { target } | FactBody::Evict { target } => {
                self.target_tier(target)
            }
            FactBody::Attestation { .. } => Role::Member,
            FactBody::Resolution {
                cell, cited_heads, ..
            } => self.resolution_tier(cell, cited_heads),
            _ => return true,
        };
        self.has_tier(author, required)
    }

    pub fn missing_dependencies(&self, fact: &SignedFact) -> Vec<FactId> {
        dependencies(fact)
            .into_iter()
            .filter(|dependency| !self.facts.contains_key(dependency))
            .collect()
    }

    /// Retry quarantined facts whose dependencies have since arrived.
    /// Quarantined facts never participate in heads or projection until this
    /// succeeds. Each successful round strictly decreases quarantine; an
    /// empty ready set or a round with no insertion terminates, so malformed
    /// dependency cycles cannot spin forever.
    pub fn retry_quarantined(&mut self) -> Result<Vec<FactId>, SemanticError> {
        let expected = self.context_id;
        if let Some(fact) = self
            .quarantined
            .values()
            .find(|fact| fact.content.mesh_context != expected)
        {
            return Err(SemanticError::ContextMismatch {
                expected: self.context_id,
                found: fact.content.mesh_context.to_string(),
            });
        }
        let mut inserted = Vec::new();
        loop {
            let ready: Vec<_> = self
                .quarantined
                .values()
                .filter(|fact| self.missing_dependencies(fact).is_empty())
                .map(|fact| fact.id)
                .collect();
            if ready.is_empty() {
                return Ok(inserted);
            }
            let mut round_progress = false;
            for id in ready {
                let fact = self
                    .quarantined
                    .remove(&id)
                    .expect("ready quarantine entry remains present");
                match self.admit(fact.clone()) {
                    Ok(Admission::Inserted) => {
                        round_progress = true;
                        inserted.push(id)
                    }
                    Ok(Admission::AlreadyPresent | Admission::Quarantined { .. }) => {}
                    Err(error) => {
                        self.quarantined.insert(id, fact);
                        return Err(error);
                    }
                }
            }
            if !round_progress {
                return Ok(inserted);
            }
        }
    }

    pub fn quarantined(&self) -> impl Iterator<Item = (&FactId, &SignedFact)> {
        self.quarantined.iter()
    }

    pub fn cell_heads(&self, cell: &super::ExclusiveCell) -> Vec<FactId> {
        let ids: Vec<_> = self
            .facts
            .iter()
            .filter_map(|(id, fact)| {
                fact.content
                    .body
                    .exclusive_cells()
                    .contains(cell)
                    .then_some(*id)
            })
            .collect();
        ids.iter()
            .copied()
            .filter(|candidate| {
                !ids.iter()
                    .any(|other| candidate != other && self.is_ancestor(candidate, other))
            })
            .collect()
    }

    /// Return the incomparable head set only when the cell is conflicted.
    pub fn conflict_heads(&self, cell: &super::ExclusiveCell) -> Option<Vec<FactId>> {
        let heads = self.cell_heads(cell);
        (heads.len() > 1).then_some(heads)
    }

    pub fn is_ancestor(&self, ancestor: &FactId, descendant: &FactId) -> bool {
        let mut pending = vec![*descendant];
        let mut seen = BTreeSet::new();
        while let Some(id) = pending.pop() {
            if !seen.insert(id) {
                continue;
            }
            let Some(fact) = self.facts.get(&id) else {
                continue;
            };
            for parent in &fact.content.parents {
                if parent == ancestor {
                    return true;
                }
                pending.push(*parent);
            }
        }
        false
    }

    pub fn projection(&self) -> Projection {
        Projection::from_graph(self)
    }
}
