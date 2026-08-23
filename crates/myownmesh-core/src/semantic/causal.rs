//! Deterministic causal admission for canonical semantic facts.

use std::collections::{BTreeMap, BTreeSet};

use super::content::FactBody;
use super::{FactId, MeshContextId, Projection, SemanticError, SignedFact, VerifiedBootstrap};

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
    authority_roots: BTreeSet<String>,
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
            authority_roots: bootstrap.authority_roots().iter().cloned().collect(),
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
        let expected = self.context_id.to_string();
        if fact.content.mesh_context != expected {
            return Err(SemanticError::ContextMismatch {
                expected: self.context_id,
                found: fact.content.mesh_context,
            });
        }
        if let Some(existing) = self.facts.get(&fact.id) {
            return if existing == &fact {
                Ok(Admission::AlreadyPresent)
            } else {
                Err(SemanticError::DuplicateFact(fact.id))
            };
        }
        if fact.content.parents.contains(&fact.id) {
            return Err(SemanticError::SelfParent);
        }
        let mut missing: Vec<_> = fact
            .content
            .parents
            .iter()
            .copied()
            .filter(|parent| !self.facts.contains_key(parent))
            .collect();
        let proof_evidence = match &fact.content.body {
            FactBody::EvictionProof { evidence, .. } | FactBody::SelfStandDown { evidence, .. } => {
                Some(evidence)
            }
            _ => None,
        };
        if let Some(evidence) = proof_evidence {
            missing.extend(
                evidence
                    .iter()
                    .copied()
                    .filter(|evidence| !self.facts.contains_key(evidence)),
            );
        }
        if let FactBody::Attestation {
            proposal,
            contributions,
            ..
        } = &fact.content.body
        {
            if !self.facts.contains_key(proposal) {
                missing.push(*proposal);
            }
            missing.extend(
                contributions
                    .iter()
                    .copied()
                    .filter(|contribution| !self.facts.contains_key(contribution)),
            );
        }
        missing.sort();
        missing.dedup();
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
            }
            if self.cell_heads(cell) != cited {
                return Err(SemanticError::ResolutionNotCurrent);
            }
        }
        if let Some(error) = Self::unauthorized_governance_error(&fact.content.body) {
            if !self.is_authorized_signer(&fact.content.author) {
                return Err(error);
            }
        }
        match &fact.content.body {
            FactBody::RoleGrant { .. } => {
                if !self.is_authorized_signer(&fact.content.author) {
                    return Err(SemanticError::UnauthorizedRoleGrant);
                }
            }
            FactBody::Attestation { signer, .. } => {
                if !self.is_authorized_signer(signer) {
                    return Err(SemanticError::UnauthorizedAttestation);
                }
            }
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
        target: &str,
        evidence: &[FactId],
        author: &str,
    ) -> Result<(), SemanticError> {
        if !self.is_authorized_signer(author) {
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
                || !self.is_authorized_signer(signer)
                || crate::signing::pubkey_part(signer)
                    != crate::signing::pubkey_part(&attestation.content.author)
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
    fn unauthorized_governance_error(body: &FactBody) -> Option<SemanticError> {
        match body {
            FactBody::KindChange { .. }
            | FactBody::RoleGrant { .. }
            | FactBody::RoleRevoke { .. }
            | FactBody::Evict { .. }
            | FactBody::Split { .. }
            | FactBody::TopologyChange { .. }
            | FactBody::Resolution { .. } => Some(SemanticError::UnauthorizedRoleGrant),
            FactBody::Attestation { .. } => Some(SemanticError::UnauthorizedAttestation),
            _ => None,
        }
    }

    fn validate_self_stand_down(
        &self,
        device_id: &str,
        evidence: &[FactId],
        author: &str,
    ) -> Result<(), SemanticError> {
        if crate::signing::pubkey_part(device_id) != crate::signing::pubkey_part(author) {
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

    pub fn is_authorized_signer(&self, signer: &str) -> bool {
        if self
            .authority_roots
            .iter()
            .any(|root| crate::signing::pubkey_part(root) == crate::signing::pubkey_part(signer))
        {
            return true;
        }
        let projection = self.projection();
        self.facts.iter().any(|(id, fact)| {
            let FactBody::RoleGrant { target, role } = &fact.content.body else {
                return false;
            };
            if !matches!(role, super::Role::Controller | super::Role::Owner)
                || crate::signing::pubkey_part(target) != crate::signing::pubkey_part(signer)
            {
                return false;
            }
            projection.value(&super::ExclusiveCell::new(target, "role")) == Some(*id)
        })
    }

    /// Retry quarantined facts whose parents have since arrived.  Quarantined
    /// facts never participate in heads or projection until this succeeds.
    pub fn retry_quarantined(&mut self) -> Result<Vec<FactId>, SemanticError> {
        let expected = self.context_id.to_string();
        if let Some(fact) = self
            .quarantined
            .values()
            .find(|fact| fact.content.mesh_context != expected)
        {
            return Err(SemanticError::ContextMismatch {
                expected: self.context_id,
                found: fact.content.mesh_context.clone(),
            });
        }
        let mut inserted = Vec::new();
        loop {
            let ready: Vec<_> = self
                .quarantined
                .values()
                .filter(|fact| {
                    let parents_ready = fact
                        .content
                        .parents
                        .iter()
                        .all(|parent| self.facts.contains_key(parent));
                    let evidence_ready = match &fact.content.body {
                        FactBody::EvictionProof { evidence, .. }
                        | FactBody::SelfStandDown { evidence, .. } => evidence
                            .iter()
                            .all(|evidence| self.facts.contains_key(evidence)),
                        _ => true,
                    };
                    parents_ready && evidence_ready
                })
                .map(|fact| fact.id)
                .collect();
            if ready.is_empty() {
                return Ok(inserted);
            }
            for id in ready {
                let fact = self
                    .quarantined
                    .remove(&id)
                    .expect("ready quarantine entry remains present");
                match self.admit(fact.clone()) {
                    Ok(Admission::Inserted) => inserted.push(id),
                    Ok(Admission::AlreadyPresent | Admission::Quarantined { .. }) => {}
                    Err(error) => {
                        self.quarantined.insert(id, fact);
                        return Err(error);
                    }
                }
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
