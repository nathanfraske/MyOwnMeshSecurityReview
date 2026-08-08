//! Immutable construction context for one endpoint-authentication task.
//!
//! Everything a task authenticates *against* is fixed here, once, before any
//! contribution is drawn or any proof is built. Nothing in this type changes
//! for the life of the task, so a later caller cannot substitute a mesh, a
//! Device identity, a profile, or a channel binding after the fact.
//!
//! The context also owns the one place canonical ordering is decided. The role
//! is derived from the exact Device pair, never supplied, and the connector's
//! endpoint-relative binding components are ordered by that derived role. A
//! transport therefore cannot choose roles, and no caller can pick whichever
//! ordering makes a signature verify.

use super::{EndpointAuthError, EndpointAuthProfile, EndpointRole};
use crate::connector::{EndpointAuthBinding, EndpointAuthBindingProfile};

/// The fixed facts one task authenticates under.
///
/// Crate-private, with no public constructor, no `Clone`, and no serialization:
/// a context is built once by the owner that knows these facts and then only
/// read.
pub(crate) struct EndpointAuthContext {
    mesh_context: String,
    local_device_id: String,
    expected_remote_device_id: String,
    profile: EndpointAuthProfile,
    binding: EndpointAuthBinding,
    local_role: EndpointRole,
}

impl EndpointAuthContext {
    /// Fix the context for one attempt.
    ///
    /// `mesh_context` is the canonical mesh identifier in the same form the
    /// durable layer signs under, not a display string. `binding` is the
    /// connector's own supplied material, already fail-closed on a missing
    /// component.
    ///
    /// The profile is **derived here** from the closed binding profile, not
    /// supplied. A connector states what it can prove; endpoint authentication
    /// decides what that means. No caller — engine included — selects profile
    /// semantics, so a peer cannot cause a weaker variant to be chosen.
    ///
    /// Empty identifiers are refused here rather than deeper in transcript
    /// framing, so an attempt cannot exist with a field that would produce an
    /// ambiguous signed record.
    pub(crate) fn new(
        mesh_context: &str,
        local_device_id: &str,
        expected_remote_device_id: &str,
        binding: EndpointAuthBinding,
    ) -> Result<Self, EndpointAuthError> {
        let profile = Self::profile_for(binding.profile());
        if mesh_context.is_empty()
            || local_device_id.is_empty()
            || expected_remote_device_id.is_empty()
        {
            return Err(EndpointAuthError::MissingTranscriptField);
        }
        // Derived from the pair, never supplied by a caller or a peer.
        let local_role = if local_device_id < expected_remote_device_id {
            EndpointRole::Initiator
        } else {
            EndpointRole::Responder
        };
        Ok(Self {
            mesh_context: mesh_context.to_owned(),
            local_device_id: local_device_id.to_owned(),
            expected_remote_device_id: expected_remote_device_id.to_owned(),
            profile,
            binding,
            local_role,
        })
    }

    /// The endpoint-authentication profile implied by a connector binding.
    ///
    /// This mapping is owned here, in endpoint authentication, precisely so it
    /// cannot be influenced from outside: a new connector binding profile must
    /// be given its meaning by an edit to this function.
    fn profile_for(binding_profile: EndpointAuthBindingProfile) -> EndpointAuthProfile {
        match binding_profile {
            EndpointAuthBindingProfile::WebRtcDtlsCertificateFingerprintPair => {
                EndpointAuthProfile::V1Ed25519Dtls
            }
        }
    }

    pub(crate) fn mesh_context(&self) -> &str {
        &self.mesh_context
    }

    pub(crate) fn local_device_id(&self) -> &str {
        &self.local_device_id
    }

    /// The one remote identity this task may ever authenticate.
    ///
    /// Named "expected" because it is fixed at construction: a proof that
    /// verifies under a different Device is not this task's proof.
    ///
    /// This is the canonical cryptographic Device ID — the raw public-key form
    /// peers exchange on the wire, with any display suffix already stripped by
    /// the caller — not the display string. The transcript and every signature
    /// check bind that canonical form, so a display spelling can never widen
    /// what a proof covers.
    pub(crate) fn expected_remote_device_id(&self) -> &str {
        &self.expected_remote_device_id
    }

    pub(crate) fn profile(&self) -> EndpointAuthProfile {
        self.profile
    }

    pub(crate) fn binding(&self) -> &EndpointAuthBinding {
        &self.binding
    }

    /// This endpoint's derived role.
    pub(crate) fn local_role(&self) -> EndpointRole {
        self.local_role
    }

    /// Whether this context is the one for that exact mesh and Device pair.
    ///
    /// The mismatch controls use this: a task built for one mesh or one remote
    /// Device answers `false` for any other, before any cryptographic work.
    pub(crate) fn matches(&self, mesh_context: &str, remote_device_id: &str) -> bool {
        self.mesh_context == mesh_context && self.expected_remote_device_id == remote_device_id
    }

    /// The binding components in role-canonical order.
    ///
    /// Returns `(initiator_component, responder_component)`. Ordering is a pure
    /// function of the derived role, so both endpoints compute the same pair
    /// from their own endpoint-relative view and neither side chooses it.
    pub(crate) fn canonical_binding_pair(&self) -> (&str, &str) {
        match self.local_role {
            EndpointRole::Initiator => (
                self.binding.local_component(),
                self.binding.remote_component(),
            ),
            EndpointRole::Responder => (
                self.binding.remote_component(),
                self.binding.local_component(),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> EndpointAuthBinding {
        EndpointAuthBinding::webrtc_certificate_fingerprints("local-fp", "remote-fp")
            .expect("both components present")
    }

    fn context(local: &str, remote: &str) -> EndpointAuthContext {
        EndpointAuthContext::new("mesh-1", local, remote, binding()).expect("non-empty identifiers")
    }

    #[test]
    fn v4_arc04b_profile_is_derived_from_the_binding_not_supplied() {
        let context = context("device-a", "device-b");

        assert_eq!(
            context.binding().profile(),
            crate::connector::EndpointAuthBindingProfile::WebRtcDtlsCertificateFingerprintPair
        );
        assert_eq!(context.profile(), EndpointAuthProfile::V1Ed25519Dtls);
    }

    #[test]
    fn v4_arc04b_context_derives_role_and_canonical_binding_order() {
        let initiator = context("device-a", "device-b");
        let responder = context("device-b", "device-a");

        assert_eq!(initiator.local_role(), EndpointRole::Initiator);
        assert_eq!(responder.local_role(), EndpointRole::Responder);

        // Each endpoint sees its own components as local, yet both order the
        // pair identically once the derived role is applied.
        assert_eq!(
            initiator.canonical_binding_pair(),
            ("local-fp", "remote-fp")
        );
        assert_eq!(
            responder.canonical_binding_pair(),
            ("remote-fp", "local-fp")
        );
    }

    #[test]
    fn v4_arc04b_context_is_fixed_to_one_mesh_and_one_remote_device() {
        let context = context("device-a", "device-b");

        assert!(context.matches("mesh-1", "device-b"));
        assert!(!context.matches("mesh-2", "device-b"));
        assert!(!context.matches("mesh-1", "device-c"));
    }

    #[test]
    fn v4_arc04b_context_refuses_an_empty_identifier() {
        for (mesh, local, remote) in [
            ("", "device-a", "device-b"),
            ("mesh-1", "", "device-b"),
            ("mesh-1", "device-a", ""),
        ] {
            assert!(matches!(
                EndpointAuthContext::new(mesh, local, remote, binding()),
                Err(EndpointAuthError::MissingTranscriptField)
            ));
        }
    }
}
