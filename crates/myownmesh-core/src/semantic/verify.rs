//! Validation errors and signature checks for canonical semantic facts.

use thiserror::Error;

use super::{ExclusiveCell, FactBody, FactId, MeshContextId, SignedFact};

/// Errors raised before a fact can enter the canonical causal graph.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SemanticError {
    #[error("unsupported semantic version {0}; only V4 is admitted")]
    UnsupportedVersion(u32),
    #[error("{0} must not be empty")]
    EmptyField(&'static str),
    #[error("fact domain does not match its body")]
    DomainMismatch,
    #[error("fact parents are not in canonical order")]
    UnsortedParents,
    #[error("fact contains a duplicate parent")]
    DuplicateParent,
    #[error("open participation must be authored by its device")]
    InvalidOpenAuthor,
    #[error("fact content author does not match the signing key")]
    AuthorMismatch,
    #[error("{0} contains a noncanonical set")]
    NonCanonicalSet(&'static str),
    #[error("eviction proof is incomplete")]
    IncompleteEvictionProof,
    #[error("fact id does not match canonical content")]
    FactIdMismatch,
    #[error("fact signature is invalid")]
    InvalidSignature,
    #[error("fact {0} is missing")]
    MissingParent(FactId),
    #[error("fact cannot cite itself as a parent")]
    SelfParent,
    #[error("fact context {found} does not match graph context {expected}")]
    ContextMismatch {
        expected: MeshContextId,
        found: String,
    },
    #[error("fact graph contains a causal cycle")]
    Cycle,
    #[error("resolution cites an unknown head {0}")]
    UnknownResolutionHead(FactId),
    #[error("resolution must cite every incomparable current head")]
    IncompleteResolution,
    #[error("resolution selected a head it did not cite")]
    ResolutionSelectionNotCited,
    #[error("fact {0} is already present with different content")]
    DuplicateFact(FactId),
    #[error("resolution does not apply to its current exclusive cell")]
    ResolutionNotCurrent,
    #[error("eviction proof author is not currently authorized")]
    UnauthorizedEviction,
    #[error("attestation signer is not currently authorized")]
    UnauthorizedAttestation,
    #[error("role grant author is not currently authorized")]
    UnauthorizedRoleGrant,
    #[error("eviction evidence is not a valid same-target authorized attestation")]
    InvalidEvictionEvidence,
    #[error("self-stand-down does not cite a valid same-target eviction proof")]
    InvalidStandDownProof,
}

/// Verify canonical content, its content-derived identifier, and its signature.
pub fn verify_fact(fact: &SignedFact) -> Result<(), SemanticError> {
    fact.content.validate()?;
    if FactId::from_content(&fact.content) != fact.id {
        return Err(SemanticError::FactIdMismatch);
    }
    let valid = crate::signing::verify(&fact.content.author, fact.id.as_bytes(), &fact.signature)
        .map_err(|_| SemanticError::InvalidSignature)?;
    if !valid {
        return Err(SemanticError::InvalidSignature);
    }
    Ok(())
}

/// Whether a body is a candidate for the exact exclusive cell named by a
/// resolution.  Keeping this check beside the canonical fact verifier avoids
/// letting a caller use a merely related cell (or a stringly-typed alias) as
/// resolution authority.
pub(crate) fn body_advances_cell(body: &FactBody, cell: &ExclusiveCell) -> bool {
    body.exclusive_cells()
        .iter()
        .any(|candidate| candidate == cell)
}
