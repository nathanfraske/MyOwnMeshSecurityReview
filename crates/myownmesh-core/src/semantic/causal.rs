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

/// The causal inputs a caller must carry when authoring a fact.
///
/// Exclusive-cell predecessors are derived from the graph rather than guessed
/// by a caller.  Evidence and other non-cell dependencies remain explicit in
/// the signed body and are added by [`dependencies`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoringWitness {
    author: DeviceId,
    parents: Vec<FactId>,
    required_tier: Option<Role>,
}

impl AuthoringWitness {
    pub fn author(&self) -> &DeviceId {
        &self.author
    }

    pub fn parents(&self) -> &[FactId] {
        &self.parents
    }

    pub fn required_tier(&self) -> Option<Role> {
        self.required_tier
    }

    pub fn into_parents(self) -> Vec<FactId> {
        self.parents
    }
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
        let causal = self.causal_past(&fact)?;
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
                if !causal.facts.contains_key(head) {
                    return Err(SemanticError::UnknownResolutionHead(*head));
                }
                if !fact.content.parents.contains(head) {
                    return Err(SemanticError::IncompleteResolution);
                }
                if !super::verify::body_advances_cell(&causal.facts[head].content.body, cell) {
                    return Err(SemanticError::IncompleteResolution);
                }
            }
            if causal.raw_cell_heads(cell) != cited {
                return Err(SemanticError::ResolutionNotCurrent);
            }
        }
        if let Some(error) = Self::authorization_error(&fact.content.body) {
            causal.validate_authority_lineage(&fact, error.clone())?;
            if !causal.is_authorized_for(&fact.content.body, &fact.content.author) {
                return Err(error);
            }
        }
        match &fact.content.body {
            FactBody::EvictionProof { target, evidence } => {
                causal.validate_authority_lineage(&fact, SemanticError::UnauthorizedEviction)?;
                causal.validate_eviction_proof(target, evidence, &fact.content.author)?;
            }
            FactBody::SelfStandDown {
                device_id,
                evidence,
            } => {
                causal.validate_authority_lineage(&fact, SemanticError::InvalidStandDownProof)?;
                causal.validate_self_stand_down(device_id, evidence, &fact.content.author)?;
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
            | FactBody::MembershipAdmit { .. }
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
            FactBody::MembershipAdmit { .. } => Some(SemanticError::UnauthorizedMembershipAdmit),
            FactBody::Attestation { .. } => Some(SemanticError::UnauthorizedAttestation),
            _ => None,
        }
    }

    /// Require an authority-bearing candidate to carry each signed
    /// AuthorityUse predecessor set in its own causal past. Receiver arrival
    /// order is intentionally irrelevant; concurrent omitted forks remain
    /// explicit conflicts in projection.
    fn validate_authority_lineage(
        &self,
        fact: &SignedFact,
        error: SemanticError,
    ) -> Result<(), SemanticError> {
        for subject in fact
            .content
            .body
            .authority_use_subjects(&fact.content.author)
        {
            let Some(use_) = fact
                .content
                .authority_uses
                .iter()
                .find(|use_| use_.subject == subject)
            else {
                return Err(error);
            };
            let expected = self.raw_authority_use_heads(&subject);
            if !expected.iter().all(|head| use_.predecessors.contains(head)) {
                return Err(error);
            }
        }
        Ok(())
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

    /// Build the exact graph visible to a candidate fact.  Facts that merely
    /// arrived earlier in this process, but are not ancestors or explicitly
    /// cited evidence, are deliberately excluded from authorization and head
    /// resolution.
    fn causal_past(&self, fact: &SignedFact) -> Result<Self, SemanticError> {
        let mut ids = BTreeSet::new();
        let mut pending = dependencies(fact);
        while let Some(id) = pending.pop() {
            if !ids.insert(id) {
                continue;
            }
            let Some(parent) = self.facts.get(&id) else {
                return Err(SemanticError::MissingParent(id));
            };
            pending.extend(dependencies(parent));
        }
        Ok(Self {
            facts: ids
                .into_iter()
                .filter_map(|id| self.facts.get(&id).cloned().map(|fact| (id, fact)))
                .collect(),
            quarantined: BTreeMap::new(),
            context_id: self.context_id,
            authority_roots: self.authority_roots.clone(),
            policy: self.policy.clone(),
        })
    }

    /// Derive exclusive-cell predecessors and typed AuthorityUse predecessors
    /// from the current canonical graph. This signed profile prevents stale
    /// forks from silently regaining root fallback.
    pub fn authoring_witness(&self, body: &FactBody, author: &DeviceId) -> AuthoringWitness {
        let required_tier = self.evaluator().required_tier(body);
        let mut parents = body
            .exclusive_cells()
            .into_iter()
            .flat_map(|cell| self.cell_heads(&cell))
            .collect::<Vec<_>>();
        for subject in body.authority_use_subjects(author) {
            parents.extend(self.authority_use_heads(&subject));
        }
        if let FactBody::MembershipAdmit { target } = body {
            parents.extend(self.stand_down_heads(target));
        }
        parents.sort();
        parents.dedup();
        AuthoringWitness {
            author: author.clone(),
            parents,
            required_tier,
        }
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
        let mut first_error = None;
        loop {
            let ready: Vec<_> = self
                .quarantined
                .values()
                .filter(|fact| self.missing_dependencies(fact).is_empty())
                .map(|fact| fact.id)
                .collect();
            if ready.is_empty() {
                return first_error.map_or(Ok(inserted), Err);
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
                        // A ready fact can still fail causal authorization or
                        // canonical validation.  It is rejected and removed;
                        // retaining it would let one malformed FactId starve
                        // every valid sibling in the same ready round.
                        first_error.get_or_insert(error);
                    }
                }
            }
            if !round_progress {
                return first_error.map_or(Ok(inserted), Err);
            }
        }
    }

    pub fn quarantined(&self) -> impl Iterator<Item = (&FactId, &SignedFact)> {
        self.quarantined.iter()
    }

    pub fn cell_heads(&self, cell: &super::ExclusiveCell) -> Vec<FactId> {
        let raw = self.raw_cell_heads(cell);
        let authoritative = raw
            .iter()
            .copied()
            .filter(|id| self.fact_is_authoritative(id))
            .collect::<Vec<_>>();
        if authoritative.is_empty() && raw.len() > 1 {
            // A concurrent AuthorityUse fork may make each branch
            // individually ineligible; retain the raw incomparable set so
            // projection exposes an explicit conflict rather than silently
            // erasing the cell.
            raw
        } else {
            authoritative
        }
    }

    pub fn authority_use_heads(&self, subject: &DeviceId) -> Vec<FactId> {
        self.raw_authority_use_heads(subject)
    }

    fn raw_authority_use_heads(&self, subject: &DeviceId) -> Vec<FactId> {
        let ids: Vec<_> = self
            .facts
            .iter()
            .filter_map(|(id, fact)| {
                fact.content
                    .authority_uses
                    .iter()
                    .any(|use_| &use_.subject == subject)
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

    pub(crate) fn raw_cell_heads(&self, cell: &super::ExclusiveCell) -> Vec<FactId> {
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

    /// Whether one admitted fact still belongs to its signed profile lineage.
    /// The signed predecessor set is evaluated against the fact's own causal
    /// past, not receiver arrival order. Concurrent forks remain explicit
    /// conflicting heads and therefore fail closed in projection.
    pub(crate) fn fact_is_authoritative(&self, id: &FactId) -> bool {
        let Some(fact) = self.facts.get(id) else {
            return false;
        };
        if matches!(&fact.content.body, FactBody::OpenParticipation { device_id, .. } if device_id == &fact.content.author)
        {
            return true;
        }
        for subject in fact
            .content
            .body
            .authority_use_subjects(&fact.content.author)
        {
            if self.raw_authority_use_heads(&subject).len() > 1 {
                // Concurrent signed uses are an explicit authority fork. A
                // later Resolution can supersede the fork because it becomes
                // the sole AuthorityUse head and cites both branches.
                return false;
            }
            if !self.authority_resolution_selects(fact, &subject) {
                return false;
            }
            let Some(use_) = fact
                .content
                .authority_uses
                .iter()
                .find(|use_| use_.subject == subject)
            else {
                return false;
            };
            if !self
                .authority_use_heads_from_parents(fact, &subject)
                .iter()
                .all(|head| use_.predecessors.contains(head))
            {
                return false;
            }
        }
        true
    }

    fn authority_resolution_selects(&self, fact: &SignedFact, subject: &DeviceId) -> bool {
        for head in self.raw_authority_use_heads(subject) {
            let Some(resolution) = self.facts.get(&head) else {
                continue;
            };
            let FactBody::Resolution {
                cell:
                    ExclusiveCell::Role {
                        subject: cell_subject,
                    },
                selected_head,
                ..
            } = &resolution.content.body
            else {
                continue;
            };
            if cell_subject != subject || fact.id == head {
                continue;
            }
            if fact.id != *selected_head && !self.is_ancestor(&fact.id, selected_head) {
                return false;
            }
        }
        true
    }

    fn authority_use_heads_from_parents(
        &self,
        fact: &SignedFact,
        subject: &DeviceId,
    ) -> Vec<FactId> {
        let mut visible = BTreeSet::new();
        let mut pending = fact.content.parents.clone();
        while let Some(id) = pending.pop() {
            if !visible.insert(id) {
                continue;
            }
            if let Some(parent) = self.facts.get(&id) {
                pending.extend(parent.content.parents.iter().copied());
            }
        }
        let candidates: Vec<_> = visible
            .iter()
            .copied()
            .filter(|id| {
                self.facts.get(id).is_some_and(|parent| {
                    parent
                        .content
                        .authority_uses
                        .iter()
                        .any(|use_| &use_.subject == subject)
                })
            })
            .collect();
        candidates
            .iter()
            .copied()
            .filter(|candidate| {
                !candidates
                    .iter()
                    .any(|other| candidate != other && self.is_ancestor(candidate, other))
            })
            .collect()
    }

    /// Return the maximal active stand-down evidence for one subject.  These
    /// facts are outside the ordinary exclusive-cell union, so a restoration
    /// must carry them explicitly rather than silently omitting the proof.
    fn stand_down_heads(&self, subject: &DeviceId) -> Vec<FactId> {
        let ids: Vec<_> = self
            .facts
            .iter()
            .filter_map(|(id, fact)| {
                (self.fact_is_authoritative(id)
                    && match &fact.content.body {
                        FactBody::EvictionProof { target, .. } if target == subject => true,
                        FactBody::SelfStandDown { device_id, .. } if device_id == subject => true,
                        _ => false,
                    })
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
        super::verify::projected_role(&fact.content.body, subject)
    }

    /// Effective membership is explicit when a membership cell has advanced;
    /// callers may treat `None` as the bootstrap-era implicit membership.
    pub fn effective_membership(&self, subject: &DeviceId) -> Option<bool> {
        let cell = ExclusiveCell::membership(subject.clone());
        let fact = self.projected_fact(&cell)?;
        super::verify::projected_membership(&fact.content.body, subject)
    }

    /// Open participation is a profile-specific, self-authored value. Closed
    /// graphs never derive it, and a selected fact authored by another device
    /// cannot become participation authority through a resolution.
    pub fn effective_open_participation(&self, subject: &DeviceId) -> Option<bool> {
        if !matches!(&self.graph.policy, VerifiedProjectPolicy::Open) {
            return None;
        }
        let cell = ExclusiveCell::open_participation(subject.clone());
        let fact = self.projected_fact(&cell)?;
        super::verify::projected_open_participation(
            &fact.content.body,
            &fact.content.author,
            subject,
        )
    }

    /// Effective attestation decision for one proposal. Conflicts and
    /// malformed resolution chains return `None` through `projected_fact`.
    pub fn effective_decision(&self, proposal: &FactId) -> Option<super::AttestationDecision> {
        let cell = ExclusiveCell::decision(*proposal);
        let fact = self.projected_fact(&cell)?;
        super::verify::projected_decision(&fact.content.body, proposal)
    }

    fn projected_fact(&self, cell: &ExclusiveCell) -> Option<&SignedFact> {
        let id = self.projection.value(cell)?;
        let fact = self.graph.facts.get(&id)?;
        super::verify::body_advances_cell(&fact.content.body, cell).then_some(fact)
    }

    /// Whether an author may create the supplied operation under the current
    /// projected authority. Controllers may grant or demote Controllers, but
    /// only an Owner may grant an Owner.
    pub fn authorizes(&self, author: &DeviceId, body: &FactBody) -> bool {
        if matches!(&self.graph.policy, VerifiedProjectPolicy::Open) {
            if let FactBody::Resolution {
                cell: ExclusiveCell::OpenParticipation { subject },
                ..
            } = body
            {
                return author == subject;
            }
        }
        let required = match body {
            FactBody::RoleGrant { role, .. } => match role {
                Role::Member | Role::Controller => Role::Controller,
                Role::Owner => Role::Owner,
            },
            FactBody::RoleRevoke { target } | FactBody::Evict { target } => {
                self.target_tier(target)
            }
            FactBody::EvictionProof { target, .. } => self.target_tier(target),
            FactBody::MembershipAdmit { .. } => Role::Controller,
            FactBody::Attestation { .. } => Role::Member,
            FactBody::Resolution {
                cell,
                cited_heads,
                selected_head,
            } => self.resolution_tier(cell, cited_heads, selected_head),
            FactBody::OpenParticipation { device_id, .. }
            | FactBody::SelfStandDown { device_id, .. } => {
                return author == device_id;
            }
        };
        self.has_tier(author, required)
    }

    /// The tier required by an authoring witness.  This is public so an
    /// authoring caller can use the same candidate-relative rule as admission
    /// without reconstructing predecessor state itself.
    pub fn required_tier(&self, body: &FactBody) -> Option<Role> {
        if matches!(&self.graph.policy, VerifiedProjectPolicy::Open) {
            return None;
        }
        match body {
            FactBody::RoleGrant { role, .. } => Some(match role {
                Role::Member | Role::Controller => Role::Controller,
                Role::Owner => Role::Owner,
            }),
            FactBody::RoleRevoke { target } | FactBody::Evict { target } => {
                Some(self.target_tier(target))
            }
            FactBody::EvictionProof { target, .. } => Some(self.target_tier(target)),
            FactBody::MembershipAdmit { .. } => Some(Role::Controller),
            FactBody::Attestation { .. } => Some(Role::Member),
            FactBody::Resolution {
                cell,
                cited_heads,
                selected_head,
            } => Some(self.resolution_tier(cell, cited_heads, selected_head)),
            _ => None,
        }
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
        self.effective_membership(subject)
            .is_none_or(|joined| joined)
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

    fn resolution_tier(
        &self,
        cell: &ExclusiveCell,
        cited_heads: &[FactId],
        _selected_head: &FactId,
    ) -> Role {
        let mut visited = BTreeSet::new();
        self.resolution_tier_with_visited(cell, cited_heads, &mut visited)
    }

    fn resolution_tier_with_visited(
        &self,
        cell: &ExclusiveCell,
        cited_heads: &[FactId],
        visited: &mut BTreeSet<FactId>,
    ) -> Role {
        match cell {
            ExclusiveCell::Role { subject } => cited_heads
                .iter()
                .filter_map(|head| {
                    let mut branch_visited = visited.clone();
                    self.resolution_candidate_tier(cell, head, subject, &mut branch_visited)
                })
                .max()
                .unwrap_or_else(|| self.target_tier(subject)),
            ExclusiveCell::Membership { subject } => self.target_tier(subject),
            ExclusiveCell::Decision { .. } | ExclusiveCell::OpenParticipation { .. } => {
                Role::Member
            }
        }
    }

    fn resolution_candidate_tier(
        &self,
        cell: &ExclusiveCell,
        head: &FactId,
        subject: &DeviceId,
        visited: &mut BTreeSet<FactId>,
    ) -> Option<Role> {
        if !visited.insert(*head) {
            return None;
        }
        let fact = self.graph.facts.get(head)?;
        match &fact.content.body {
            FactBody::RoleGrant { target, role } if target == subject => Some(match role {
                Role::Member | Role::Controller => Role::Controller,
                Role::Owner => Role::Owner,
            }),
            FactBody::RoleRevoke { target } if target == subject => {
                let causal = self
                    .graph
                    .causal_past(fact)
                    .ok()?
                    .evaluator()
                    .effective_role(subject);
                Some(match causal {
                    Some(Role::Owner) => Role::Owner,
                    Some(Role::Controller) => Role::Controller,
                    Some(Role::Member) => Role::Controller,
                    None => Role::Owner,
                })
            }
            FactBody::Resolution {
                cell: nested_cell,
                cited_heads,
                ..
            } if nested_cell == cell => {
                Some(self.resolution_tier_with_visited(nested_cell, cited_heads, visited))
            }
            _ => None,
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
    fn authoring_witness_carries_root_revoke_into_later_root_authored_fact() {
        let (bootstrap, root_key) = closed(48);
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
        graph
            .admit(revoke.clone())
            .expect("the root revoke is admitted into the canonical graph");

        let body = FactBody::RoleGrant {
            target: device(&key(49)),
            role: Role::Member,
        };
        let witness = graph.authoring_witness(&body, &root);
        assert!(
            witness.parents().contains(&revoke.id),
            "tiered root-authored work must carry the signed AuthorityUse predecessor"
        );
        let candidate = SignedFact::sign(
            super::super::FactContent::from_authoring_witness(
                &graph,
                body,
                &witness,
                std::iter::empty(),
            ),
            &root_key,
        )
        .expect("witness-derived candidate signs");
        assert_eq!(
            graph.admit(candidate),
            Err(SemanticError::UnauthorizedRoleGrant),
            "the revoked root must not regain bootstrap-owner fallback"
        );
    }

    #[test]
    fn projection_follows_nested_same_cell_resolutions() {
        let (bootstrap, root_key) = closed(40);
        let target = device(&key(41));
        let first = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Member,
            },
            Vec::new(),
        );
        let second = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Controller,
            },
            Vec::new(),
        );
        let third = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Owner,
            },
            Vec::new(),
        );
        let first_resolution = fact(
            &bootstrap,
            &root_key,
            FactBody::Resolution {
                cell: ExclusiveCell::role(target.clone()),
                cited_heads: vec![first.id, second.id],
                selected_head: first.id,
            },
            vec![first.id, second.id],
        );
        let second_resolution = fact(
            &bootstrap,
            &root_key,
            FactBody::Resolution {
                cell: ExclusiveCell::role(target.clone()),
                cited_heads: vec![first_resolution.id, third.id],
                selected_head: first_resolution.id,
            },
            vec![first_resolution.id, third.id],
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph.facts.insert(first.id, first.clone());
        graph.facts.insert(second.id, second);
        graph.facts.insert(third.id, third);
        graph.facts.insert(first_resolution.id, first_resolution);
        graph.facts.insert(second_resolution.id, second_resolution);
        let evaluator = graph.evaluator();
        assert_eq!(
            evaluator.effective_role(&target),
            Some(Role::Member),
            "nested resolution selects the terminal same-cell head"
        );
    }

    #[test]
    fn shared_nested_controller_resolution_dag_is_path_local_and_accepted() {
        let (bootstrap, root_key) = closed(67);
        let controller_key = key(68);
        let controller = device(&controller_key);
        let left_key = key(70);
        let right_key = key(71);
        let left = device(&left_key);
        let right = device(&right_key);
        let target = device(&key(69));
        let controller_grant = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: controller.clone(),
                role: Role::Controller,
            },
            Vec::new(),
        );
        let left_grant = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: left.clone(),
                role: Role::Controller,
            },
            vec![controller_grant.id],
        );
        let right_grant = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: right.clone(),
                role: Role::Controller,
            },
            vec![left_grant.id],
        );
        let base_a = fact(
            &bootstrap,
            &left_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Member,
            },
            vec![left_grant.id],
        );
        let base_b = fact(
            &bootstrap,
            &right_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Controller,
            },
            vec![right_grant.id],
        );
        let mut base_heads = vec![base_a.id, base_b.id];
        base_heads.sort();
        let nested_a = fact(
            &bootstrap,
            &left_key,
            FactBody::Resolution {
                cell: ExclusiveCell::role(target.clone()),
                cited_heads: base_heads.clone(),
                selected_head: base_a.id,
            },
            [vec![left_grant.id], base_heads.clone()].concat(),
        );
        let nested_b = fact(
            &bootstrap,
            &right_key,
            FactBody::Resolution {
                cell: ExclusiveCell::role(target.clone()),
                cited_heads: base_heads,
                selected_head: base_b.id,
            },
            [vec![right_grant.id], vec![base_a.id, base_b.id]].concat(),
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        for fact in [
            controller_grant.clone(),
            left_grant,
            right_grant,
            base_a,
            base_b,
            nested_a.clone(),
            nested_b.clone(),
        ] {
            graph.facts.insert(fact.id, fact);
        }
        let mut nested_heads = vec![nested_a.id, nested_b.id];
        nested_heads.sort();
        let top = fact(
            &bootstrap,
            &controller_key,
            FactBody::Resolution {
                cell: ExclusiveCell::role(target.clone()),
                cited_heads: nested_heads.clone(),
                selected_head: nested_a.id,
            },
            vec![controller_grant.id, nested_a.id, nested_b.id],
        );
        graph
            .admit(top)
            .expect("Controller may resolve shared nested Controller-tier branches");
        assert_eq!(
            graph.evaluator().effective_role(&target),
            Some(Role::Member),
            "the selected nested branch remains the effective proposition"
        );
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
    fn authorization_uses_candidate_causal_past_not_later_target_role() {
        let (bootstrap, root_key) = closed(51);
        let controller_key = key(52);
        let controller = device(&controller_key);
        let target_key = key(53);
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
        let grant_member = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Member,
            },
            vec![grant_controller.id],
        );
        let later_owner = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Owner,
            },
            vec![grant_member.id],
        );
        let revoke = fact(
            &bootstrap,
            &controller_key,
            FactBody::RoleRevoke {
                target: target.clone(),
            },
            vec![grant_controller.id, grant_member.id],
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph
            .admit(grant_controller)
            .expect("root controller grant admits");
        graph
            .admit(grant_member.clone())
            .expect("root member grant admits");
        graph.admit(later_owner).expect("later owner grant admits");
        graph
            .admit(revoke)
            .expect("controller is authorized by the candidate's causal target role");
    }

    #[test]
    fn resolution_authority_uses_selected_controller_proposition() {
        let (bootstrap, root_key) = closed(54);
        let controller_key = key(55);
        let controller = device(&controller_key);
        let left_key = key(57);
        let right_key = key(58);
        let left = device(&left_key);
        let right = device(&right_key);
        let target = device(&key(56));
        let controller_grant = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: controller.clone(),
                role: Role::Controller,
            },
            Vec::new(),
        );
        let left_grant = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: left,
                role: Role::Controller,
            },
            vec![controller_grant.id],
        );
        let right_grant = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: right,
                role: Role::Controller,
            },
            vec![left_grant.id],
        );
        let member_head = fact(
            &bootstrap,
            &left_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Member,
            },
            vec![left_grant.id],
        );
        let controller_head = fact(
            &bootstrap,
            &right_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Controller,
            },
            vec![right_grant.id],
        );
        let resolution = fact(
            &bootstrap,
            &controller_key,
            FactBody::Resolution {
                cell: ExclusiveCell::role(target),
                cited_heads: vec![member_head.id, controller_head.id],
                selected_head: controller_head.id,
            },
            vec![controller_grant.id, member_head.id, controller_head.id],
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph
            .admit(controller_grant)
            .expect("root controller grant admits");
        graph
            .admit(left_grant)
            .expect("left branch signer grant admits");
        graph
            .admit(right_grant)
            .expect("right branch signer grant admits");
        graph.admit(member_head).expect("first target head admits");
        graph
            .admit(controller_head)
            .expect("second target head admits");
        graph
            .admit(resolution)
            .expect("a controller may resolve to a controller proposition");
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
        assert_eq!(graph.evaluator().effective_membership(&controller), None);
        graph.admit(eviction).expect("root eviction admits");
        let evaluator = graph.evaluator();
        assert!(!evaluator.is_conflicted(&ExclusiveCell::role(controller.clone())));
        assert_eq!(evaluator.effective_role(&controller), None);
        assert_eq!(evaluator.effective_membership(&controller), Some(false));
        assert!(!evaluator.admits_closed_session(&root, &controller));
    }

    #[test]
    fn membership_admit_restores_membership_but_not_role() {
        let (bootstrap, root_key) = closed(57);
        let root = device(&root_key);
        let target_key = key(58);
        let target = device(&target_key);
        let grant = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Member,
            },
            Vec::new(),
        );
        let eviction = fact(
            &bootstrap,
            &root_key,
            FactBody::Evict {
                target: target.clone(),
            },
            vec![grant.id],
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph.admit(grant).expect("initial member grant admits");
        graph.admit(eviction.clone()).expect("eviction admits");
        assert_eq!(graph.evaluator().effective_membership(&target), Some(false));

        let membership_body = FactBody::MembershipAdmit {
            target: target.clone(),
        };
        let witness = graph.authoring_witness(&membership_body, &root);
        assert!(witness.parents().contains(&eviction.id));
        let membership = SignedFact::sign(
            super::super::FactContent::from_authoring_witness(
                &graph,
                membership_body,
                &witness,
                std::iter::empty(),
            ),
            &root_key,
        )
        .expect("owner membership admit signs");
        graph.admit(membership).expect("membership admit admits");
        let evaluator = graph.evaluator();
        assert_eq!(evaluator.effective_membership(&target), Some(true));
        assert_eq!(evaluator.effective_role(&target), None);
        assert!(!evaluator.admits_closed_session(&root, &target));

        let role_body = FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Member,
        };
        let role_witness = graph.authoring_witness(&role_body, &root);
        assert!(
            role_witness.parents().contains(&eviction.id),
            "role restoration must retain the evicted role-cell head"
        );
        let role = SignedFact::sign(
            super::super::FactContent::from_authoring_witness(
                &graph,
                role_body,
                &role_witness,
                std::iter::empty(),
            ),
            &root_key,
        )
        .expect("owner role grant signs");
        graph.admit(role).expect("causal role restoration admits");
        assert!(graph.evaluator().admits_closed_session(&root, &target));
    }

    #[test]
    fn membership_admit_rejects_self_and_open_profile_facts() {
        let (bootstrap, root_key) = closed(59);
        let target_key = key(60);
        let target = device(&target_key);
        let grant = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Member,
            },
            Vec::new(),
        );
        let eviction = fact(
            &bootstrap,
            &root_key,
            FactBody::Evict {
                target: target.clone(),
            },
            vec![grant.id],
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph.admit(grant).expect("initial member grant admits");
        graph.admit(eviction).expect("eviction admits");
        let self_body = FactBody::MembershipAdmit {
            target: target.clone(),
        };
        let self_witness = graph.authoring_witness(&self_body, &target);
        let self_admit = SignedFact::sign(
            super::super::FactContent::from_authoring_witness(
                &graph,
                self_body,
                &self_witness,
                std::iter::empty(),
            ),
            &target_key,
        )
        .expect("self-authored candidate signs");
        assert_eq!(
            graph.admit(self_admit),
            Err(SemanticError::UnauthorizedMembershipAdmit)
        );

        let open = VerifiedBootstrap::open("membership-open").expect("open bootstrap");
        let open_key = key(61);
        let open_target = device(&key(62));
        let open_admit = fact(
            &open,
            &open_key,
            FactBody::MembershipAdmit {
                target: open_target,
            },
            Vec::new(),
        );
        let mut open_graph = FactGraph::from_bootstrap(&open);
        assert_eq!(
            open_graph.admit(open_admit),
            Err(SemanticError::DomainMismatch)
        );
    }

    #[test]
    fn evaluator_derives_decision_from_the_selected_attestation() {
        let (bootstrap, root_key) = closed(46);
        let target = device(&key(47));
        let proposal = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Member,
            },
            Vec::new(),
        );
        let attestation = fact(
            &bootstrap,
            &root_key,
            FactBody::Attestation {
                target,
                proposal: proposal.id,
                decision: super::super::AttestationDecision::Approve,
                signer: device(&root_key),
                contributions: Vec::new(),
            },
            vec![proposal.id],
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph.admit(proposal.clone()).expect("proposal admits");
        graph.admit(attestation).expect("attestation admits");
        assert_eq!(
            graph.evaluator().effective_decision(&proposal.id),
            Some(super::super::AttestationDecision::Approve)
        );
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
        let left = fact(
            &open,
            &participant_key,
            FactBody::OpenParticipation {
                device_id: participant.clone(),
                joined: false,
            },
            Vec::new(),
        );
        open_graph
            .admit(left.clone())
            .expect("second participation admits");
        let participation_resolution = fact(
            &open,
            &participant_key,
            FactBody::Resolution {
                cell: ExclusiveCell::open_participation(participant.clone()),
                cited_heads: vec![participation.id, left.id],
                selected_head: participation.id,
            },
            vec![participation.id, left.id],
        );
        open_graph
            .admit(participation_resolution)
            .expect("self-authored participation resolution admits");
        assert_eq!(
            open_graph
                .evaluator()
                .effective_open_participation(&participant),
            Some(true)
        );
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
