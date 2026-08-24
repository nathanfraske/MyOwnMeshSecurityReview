//! Deterministic causal admission for canonical semantic facts.

use std::collections::{BTreeMap, BTreeSet};

use super::content::{DeviceId, ExclusiveCell, FactBody, Role};
use super::{
    FactId, MeshContextId, Projection, SemanticError, SignedFact, VerifiedBootstrap,
    VerifiedProjectPolicy,
};

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
    policy: VerifiedProjectPolicy,
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
            policy: bootstrap.policy().clone(),
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
        self.validate_domain(&fact)?;
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

    fn validate_domain(&self, fact: &SignedFact) -> Result<(), SemanticError> {
        let open = matches!(&self.policy, VerifiedProjectPolicy::Open);
        match &fact.content.body {
            FactBody::OpenParticipation { device_id, .. } => {
                if !open {
                    return Err(SemanticError::DomainMismatch);
                }
                if device_id != &fact.content.author {
                    return Err(SemanticError::InvalidOpenAuthor);
                }
            }
            FactBody::Resolution { cell, .. } => match (open, cell) {
                (true, ExclusiveCell::OpenParticipation { subject }) => {
                    if subject != &fact.content.author {
                        return Err(SemanticError::InvalidOpenAuthor);
                    }
                }
                (true, _) | (false, ExclusiveCell::OpenParticipation { .. }) => {
                    return Err(SemanticError::DomainMismatch);
                }
                (false, _) => {}
            },
            FactBody::RoleGrant { .. }
            | FactBody::RoleRevoke { .. }
            | FactBody::Evict { .. }
            | FactBody::EvictionProof { .. }
            | FactBody::SelfStandDown { .. }
            | FactBody::Attestation { .. }
                if open =>
            {
                return Err(SemanticError::DomainMismatch)
            }
            _ => {}
        }
        Ok(())
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
                || !self.evaluator().has_tier(signer, Role::Member)
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
        self.evaluator().effective_role(signer).is_some()
    }

    fn is_authorized_for(&self, body: &FactBody, author: &DeviceId) -> bool {
        self.evaluator().authorizes(author, body)
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

    /// Construct the sealed evaluator for this graph's exact bootstrap policy.
    /// Callers cannot provide an alternate root, profile, or policy snapshot.
    pub fn evaluator(&self) -> SemanticEvaluator<'_> {
        SemanticEvaluator {
            graph: self,
            projection: self.projection(),
        }
    }
}

/// Canonical authority evaluator for the validated V4 semantic profile.
///
/// The evaluator is intentionally constructed only by [`FactGraph::evaluator`];
/// its private graph and projection fields prevent callers from substituting a
/// display identity, compatibility role map, or unrelated bootstrap roots.
#[derive(Debug)]
pub struct SemanticEvaluator<'a> {
    graph: &'a FactGraph,
    projection: Projection,
}

impl<'a> SemanticEvaluator<'a> {
    /// Resolve the effective role from the projected role cell. The bootstrap
    /// root is an Owner only while its role cell has never advanced. A revoke,
    /// eviction, conflict, or stand-down therefore removes authority rather
    /// than falling back to the root.
    pub fn effective_role(&self, subject: &DeviceId) -> Option<Role> {
        if self.projection.is_stood_down(subject) {
            return None;
        }
        let role_cell = ExclusiveCell::role(subject.clone());
        if self.projection.is_conflicted(&role_cell) {
            return None;
        }
        let Some(id) = self
            .projection
            .role_cell(subject)
            .and_then(|cell| match cell {
                super::CellProjection::Value(id) => Some(*id),
                super::CellProjection::Conflict(_) => None,
            })
        else {
            return self
                .graph
                .authority_roots
                .contains(subject)
                .then_some(Role::Owner);
        };
        self.effective_role_from_fact(&id, subject)
    }

    fn effective_role_from_fact(&self, id: &FactId, subject: &DeviceId) -> Option<Role> {
        let fact = self.graph.facts.get(id)?;
        match &fact.content.body {
            FactBody::Resolution { selected_head, .. } => {
                self.graph.facts.get(selected_head).and_then(|selected| {
                    super::verify::projected_role(&selected.content.body, subject)
                })
            }
            body => super::verify::projected_role(body, subject),
        }
    }

    /// Whether an author may create the supplied operation under the current
    /// projected authority. Controllers may grant or demote Controllers, but
    /// only an Owner may grant an Owner.
    pub fn authorizes(&self, author: &DeviceId, body: &FactBody) -> bool {
        let required = match body {
            FactBody::RoleGrant { role, .. } => match role {
                Role::Member | Role::Controller => Role::Controller,
                Role::Owner => Role::Owner,
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

    /// Closed-profile session admission. Open participation remains governed
    /// by its local transport profile; this method is only the canonical
    /// membership gate for a validated Closed project.
    pub fn admits_closed_session(&self, local: &DeviceId, remote: &DeviceId) -> bool {
        if matches!(&self.graph.policy, VerifiedProjectPolicy::Open) {
            return true;
        }
        self.role_admits(local) && self.role_admits(remote)
    }

    pub fn is_conflicted(&self, cell: &ExclusiveCell) -> bool {
        self.projection.is_conflicted(cell)
    }

    pub fn is_stood_down(&self, subject: &DeviceId) -> bool {
        self.projection.is_stood_down(subject)
    }

    fn role_admits(&self, subject: &DeviceId) -> bool {
        if self.effective_role(subject).is_none() {
            return false;
        }
        if matches!(
            self.projection.membership_cell(subject),
            Some(super::CellProjection::Conflict(_))
        ) {
            return false;
        }
        self.projection
            .membership_cell(subject)
            .and_then(|cell| match cell {
                super::CellProjection::Value(id) => Some(*id),
                super::CellProjection::Conflict(_) => None,
            })
            .and_then(|id| self.graph.facts.get(&id))
            .is_none_or(|fact| {
                !matches!(
                    &fact.content.body,
                    FactBody::Evict { target } if target == subject
                )
            })
    }

    fn has_tier(&self, signer: &DeviceId, required: Role) -> bool {
        let Some(actual) = self.effective_role(signer) else {
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
        match self.effective_role(target) {
            Some(Role::Owner) => Role::Owner,
            Some(Role::Controller) => Role::Controller,
            Some(Role::Member) => Role::Controller,
            None => Role::Owner,
        }
    }

    fn resolution_tier(&self, cell: &ExclusiveCell, cited_heads: &[FactId]) -> Role {
        match cell {
            ExclusiveCell::Role { subject } => match self.effective_role(subject) {
                Some(_) => self.target_tier(subject),
                None => cited_heads
                    .iter()
                    .filter_map(|id| self.graph.facts.get(id))
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
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn device(key: &SigningKey) -> DeviceId {
        DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes())
            .expect("test key produces a canonical device")
    }

    fn closed(seed: u8) -> (VerifiedBootstrap, SigningKey) {
        let signing_key = key(seed);
        (
            VerifiedBootstrap::create_closed(
                "causal-evaluator",
                vec![signing_key.clone()],
                [seed; 32],
            )
            .expect("closed bootstrap verifies"),
            signing_key,
        )
    }

    fn fact(
        bootstrap: &VerifiedBootstrap,
        signing_key: &SigningKey,
        body: FactBody,
        parents: Vec<FactId>,
    ) -> SignedFact {
        SignedFact::sign(
            super::super::FactContent::new(
                body.domain(),
                bootstrap.context_id(),
                body,
                device(signing_key),
                parents,
            ),
            signing_key,
        )
        .expect("test fact signs")
    }

    #[test]
    fn root_owner_fallback_stops_after_root_cell_advances() {
        let (bootstrap, root_key) = closed(41);
        let root = device(&root_key);
        let revoke = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleRevoke {
                target: root.clone(),
            },
            Vec::new(),
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        assert_eq!(graph.evaluator().effective_role(&root), Some(Role::Owner));
        graph
            .admit(revoke)
            .expect("the root may revoke its own role cell");
        let evaluator = graph.evaluator();
        assert_eq!(evaluator.effective_role(&root), None);
        assert!(!evaluator.admits_closed_session(&root, &root));
    }

    #[test]
    fn conflicted_root_role_cell_fails_closed() {
        let (bootstrap, root_key) = closed(47);
        let root = device(&root_key);
        let member = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: root.clone(),
                role: Role::Member,
            },
            Vec::new(),
        );
        let controller = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: root.clone(),
                role: Role::Controller,
            },
            Vec::new(),
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        member.verify().expect("first root branch verifies");
        controller.verify().expect("second root branch verifies");
        graph.facts.insert(member.id, member);
        graph.facts.insert(controller.id, controller);
        let evaluator = graph.evaluator();
        assert!(evaluator.is_conflicted(&ExclusiveCell::role(root.clone())));
        assert_eq!(evaluator.effective_role(&root), None);
        assert!(!evaluator.admits_closed_session(&root, &root));
    }

    #[test]
    fn controller_can_grant_controller_but_not_owner() {
        let (bootstrap, root_key) = closed(42);
        let controller_key = key(43);
        let controller = device(&controller_key);
        let target_key = key(44);
        let target = device(&target_key);
        let grant_controller = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: controller.clone(),
                role: Role::Controller,
            },
            Vec::new(),
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph
            .admit(grant_controller.clone())
            .expect("the root grants the controller tier");
        let controller_grant = fact(
            &bootstrap,
            &controller_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Controller,
            },
            vec![grant_controller.id],
        );
        graph
            .admit(controller_grant.clone())
            .expect("a controller may grant another controller");
        assert_eq!(
            graph.evaluator().effective_role(&target),
            Some(Role::Controller)
        );
        let owner_grant = fact(
            &bootstrap,
            &controller_key,
            FactBody::RoleGrant {
                target,
                role: Role::Owner,
            },
            vec![controller_grant.id],
        );
        assert_eq!(
            graph.admit(owner_grant),
            Err(SemanticError::UnauthorizedRoleGrant)
        );
    }

    #[test]
    fn eviction_removes_closed_session_admission() {
        let (bootstrap, root_key) = closed(45);
        let controller_key = key(46);
        let controller = device(&controller_key);
        let root = device(&root_key);
        let grant = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: controller.clone(),
                role: Role::Member,
            },
            Vec::new(),
        );
        let eviction = fact(
            &bootstrap,
            &root_key,
            FactBody::Evict {
                target: controller.clone(),
            },
            vec![grant.id],
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph.admit(grant).expect("member grant admits");
        assert!(graph.evaluator().admits_closed_session(&root, &controller));
        graph.admit(eviction).expect("root eviction admits");
        let evaluator = graph.evaluator();
        assert!(!evaluator.is_conflicted(&ExclusiveCell::role(controller.clone())));
        assert_eq!(evaluator.effective_role(&controller), None);
        assert!(!evaluator.admits_closed_session(&root, &controller));
    }

    #[test]
    fn graph_enforces_open_and_closed_fact_domains() {
        let open = VerifiedBootstrap::open("causal-open-domain").expect("open bootstrap verifies");
        let participant_key = key(48);
        let participant = device(&participant_key);
        let mut open_graph = FactGraph::from_bootstrap(&open);
        let closed_body = fact(
            &open,
            &participant_key,
            FactBody::RoleGrant {
                target: participant.clone(),
                role: Role::Member,
            },
            Vec::new(),
        );
        assert_eq!(
            open_graph.admit(closed_body),
            Err(SemanticError::DomainMismatch)
        );
        let participation = fact(
            &open,
            &participant_key,
            FactBody::OpenParticipation {
                device_id: participant.clone(),
                joined: true,
            },
            Vec::new(),
        );
        open_graph
            .admit(participation.clone())
            .expect("self-authored Open participation admits");
        let foreign_resolution = fact(
            &open,
            &participant_key,
            FactBody::Resolution {
                cell: ExclusiveCell::open_participation(device(&key(49))),
                cited_heads: vec![participation.id],
                selected_head: participation.id,
            },
            vec![participation.id],
        );
        assert_eq!(
            open_graph.admit(foreign_resolution),
            Err(SemanticError::InvalidOpenAuthor)
        );

        let (closed, root_key) = closed(50);
        let root = device(&root_key);
        let participation = fact(
            &closed,
            &root_key,
            FactBody::OpenParticipation {
                device_id: root,
                joined: true,
            },
            Vec::new(),
        );
        assert_eq!(
            FactGraph::from_bootstrap(&closed).admit(participation),
            Err(SemanticError::DomainMismatch)
        );
    }
}
