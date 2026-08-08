//! Private provenance for an authenticated channel.
//!
//! Arc 05 must be able to read what was actually authenticated without
//! reconstructing it from parallel mutable engine state, and without a caller
//! being able to supply a replacement. That is what this record is: an exact,
//! immutable, non-serializable statement of the facts one completed exchange
//! proved, derived from the task's own context and proof state rather than
//! assembled from a bag of caller-supplied fields.

use super::context::EndpointAuthContext;
use super::{EndpointAuthProfile, EndpointRole};
use crate::connector::{
    ConnectedChannelHandoff, ConnectorIncarnation, EndpointAuthBindingProfile,
    EndpointAuthBindingProvenance,
};
use crate::runtime::RuntimeIncarnation;
use std::sync::Arc;

/// One completed authentication, recorded exactly.
///
/// Crate-private, no public constructor, no `Clone`, no serialization: there is
/// deliberately no session handle to hand out. Readback is by narrow accessor
/// only, so a consumer reads what was proved and cannot substitute anything.
pub(crate) struct AuthenticatedBindingRecord {
    mesh_context: String,
    local_device_id: String,
    remote_device_id: String,
    profile: EndpointAuthProfile,
    /// The exact role this endpoint proved under. Compared by
    /// [`super::EndpointAuthTask::issued`], so a record proved under the peer's
    /// role cannot be installed through this task.
    local_role: EndpointRole,
    /// The connector-side binding profile, likewise compared on install rather
    /// than only recorded.
    binding_profile: EndpointAuthBindingProfile,
    /// How the connector established the binding material this proof covers.
    ///
    /// Load-bearing rather than recorded-and-ignored: `issued` compares it
    /// against the current context's provenance, so a record whose provenance
    /// does not match the task's cannot be installed through it.
    binding_provenance: EndpointAuthBindingProvenance,
    /// Digest of the exact binding pair in role-canonical order.
    binding_digest: String,
    /// Digest of the exact transcript both halves verified over.
    transcript_digest: String,
    connector: Arc<ConnectorIncarnation>,
    runtime: RuntimeIncarnation,
}

impl AuthenticatedBindingRecord {
    /// Derive the record from the task's own immutable state.
    ///
    /// Every field comes from the context the task fixed at construction or
    /// from the transcript it actually verified. Nothing here is caller
    /// supplied, which is the property that lets a later consumer trust it.
    pub(crate) fn from_verified_exchange(
        context: &EndpointAuthContext,
        transcript: &[u8],
        connector: Arc<ConnectorIncarnation>,
        runtime: RuntimeIncarnation,
    ) -> Self {
        let (initiator_component, responder_component) = context.canonical_binding_pair();
        Self {
            mesh_context: context.mesh_context().to_owned(),
            local_device_id: context.local_device_id().to_owned(),
            remote_device_id: context.expected_remote_device_id().to_owned(),
            profile: context.profile(),
            local_role: context.local_role(),
            binding_profile: context.binding().profile(),
            binding_provenance: context.binding().provenance(),
            binding_digest: digest_of(&[
                initiator_component.as_bytes(),
                responder_component.as_bytes(),
            ]),
            transcript_digest: digest_of(&[transcript]),
            connector,
            runtime,
        }
    }

    pub(crate) fn mesh_context(&self) -> &str {
        &self.mesh_context
    }

    pub(crate) fn local_device_id(&self) -> &str {
        &self.local_device_id
    }

    pub(crate) fn remote_device_id(&self) -> &str {
        &self.remote_device_id
    }

    pub(crate) fn profile(&self) -> EndpointAuthProfile {
        self.profile
    }

    pub(crate) fn local_role(&self) -> EndpointRole {
        self.local_role
    }

    pub(crate) fn binding_profile(&self) -> EndpointAuthBindingProfile {
        self.binding_profile
    }

    /// How the connector established the binding this proof covers.
    ///
    /// The one narrow accessor the install path needs: `issued` compares this
    /// against the current context's provenance.
    pub(crate) fn binding_provenance(&self) -> EndpointAuthBindingProvenance {
        self.binding_provenance
    }

    pub(crate) fn binding_digest(&self) -> &str {
        &self.binding_digest
    }

    pub(crate) fn transcript_digest(&self) -> &str {
        &self.transcript_digest
    }

    pub(crate) fn connector(&self) -> &Arc<ConnectorIncarnation> {
        &self.connector
    }

    pub(crate) fn runtime(&self) -> &RuntimeIncarnation {
        &self.runtime
    }

    /// Whether this record is the one for that exact mesh and remote Device.
    ///
    /// The cross-context install controls use this: a capability from one
    /// context answers `false` for another even when a caller supplies the
    /// current task alongside it.
    pub(crate) fn authenticated_for(&self, mesh_context: &str, remote_device_id: &str) -> bool {
        // Through the accessors, so there is exactly one reader per field and a
        // future change to how either is stored cannot leave this comparison
        // reading a stale representation.
        self.mesh_context() == mesh_context && self.remote_device_id() == remote_device_id
    }
}

/// Attestation of the connected-channel ownership a promotion is built on.
///
/// Deliberately **not** described as proof that bounded work was admitted:
/// there is no independent Arc 04 resource admission. It carries the runtime
/// ownership the connected capability already had. It has no public
/// constructor, no serialization, and no cloning path.
pub struct EndpointAuthPermit {
    runtime: RuntimeIncarnation,
}

/// Local proof that both Device identities were freshly authenticated on one
/// exact connected channel.
///
/// Issued only by [`super::EndpointAuthTask`], from a verified exchange. It has
/// no public constructor, so a connected channel cannot become an authenticated
/// one by any other route.
///
/// It privately retains the exact authenticated binding record, so a later
/// consumer reads what was actually proved instead of reconstructing it from
/// parallel mutable state — and cannot substitute anything, because there is no
/// setter and no serializable handle.
///
/// A connected channel has no implicit conversion into authentication:
///
/// ```compile_fail,E0308
/// use myownmesh_core::connector::ConnectedChannelCapability;
/// use myownmesh_core::endpoint_auth::AuthenticatedChannelCapability;
///
/// fn connected() -> ConnectedChannelCapability { unimplemented!() }
/// fn requires_authentication(_: AuthenticatedChannelCapability) {}
///
/// requires_authentication(connected());
/// ```
pub struct AuthenticatedChannelCapability {
    record: AuthenticatedBindingRecord,
    /// The whole handoff, not the bare capability: its `Drop` is what returns
    /// the connected claim to connector retention, so a capability dropped on
    /// retirement or a refused install cannot release the claim early.
    handoff: ConnectedChannelHandoff,
    permit: EndpointAuthPermit,
}

impl AuthenticatedChannelCapability {
    /// The one construction path: a verified exchange, nothing else.
    ///
    /// The record and the handoff arrive together from the task that proved
    /// them, so no caller can pair a record with a different channel.
    pub(crate) fn from_verified_exchange(
        record: AuthenticatedBindingRecord,
        handoff: ConnectedChannelHandoff,
    ) -> Self {
        let permit = EndpointAuthPermit {
            runtime: record.runtime().clone(),
        };
        Self {
            record,
            handoff,
            permit,
        }
    }

    /// The runtime this capability is bound to.
    pub(crate) fn runtime(&self) -> &RuntimeIncarnation {
        &self.permit.runtime
    }

    /// Whether this capability was promoted from that exact connector
    /// incarnation.
    ///
    /// Install must check this, not merely that the *task* it was handed is
    /// current. Checking the task alone would accept a capability promoted from
    /// a superseded channel as long as the caller passed the current task
    /// alongside it — precisely the cross-channel relay the non-session-unique
    /// binding cannot rule out on its own.
    pub(crate) fn belongs_to(&self, incarnation: &Arc<ConnectorIncarnation>) -> bool {
        self.handoff.belongs_to(incarnation)
    }

    /// The private authenticated binding record.
    ///
    /// Crate-private readback: a consumer reads the proved facts, and there is
    /// no path to replace them.
    pub(crate) fn record(&self) -> &AuthenticatedBindingRecord {
        &self.record
    }

    /// Whether this capability authenticates that exact mesh and remote Device.
    ///
    /// Install rechecks this even when the caller supplies the current task, so
    /// a capability from one context cannot be installed into another.
    pub(crate) fn authenticated_for(&self, mesh_context: &str, remote_device_id: &str) -> bool {
        self.record
            .authenticated_for(mesh_context, remote_device_id)
    }
}

/// One genuine capability over a fixture channel.
///
/// Test-only. It builds a real record from a real context and a real handoff,
/// so a control that consumes it exercises the same type production issues —
/// what it skips is the exchange that would have proved it, which is covered
/// by the task controls instead.
#[cfg(test)]
pub(crate) fn authenticated_for_test(
    runtime: RuntimeIncarnation,
) -> AuthenticatedChannelCapability {
    let binding = crate::connector::EndpointAuthBinding::webrtc_certificate_fingerprints(
        "fixture-local-fp",
        "fixture-remote-fp",
    )
    .expect("both fixture components present");
    let context = EndpointAuthContext::new(
        "fixture-mesh",
        "fixture-device-local",
        "fixture-device-remote",
        binding,
    )
    .expect("non-empty fixture identifiers");
    let handoff = crate::connector::handoff_for_test(runtime);
    let channel_runtime = handoff
        .capability()
        .expect("fixture handoff holds its capability")
        .runtime()
        .clone();
    let record = AuthenticatedBindingRecord::from_verified_exchange(
        &context,
        b"fixture-transcript",
        Arc::clone(handoff.incarnation()),
        channel_runtime,
    );
    AuthenticatedChannelCapability::from_verified_exchange(record, handoff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_arc02_authenticated_channel_preserves_runtime_binding() {
        // The capability answers with the runtime of the channel it was
        // promoted from, read from its own record rather than from a caller.
        let runtime = crate::runtime::runtime_for_test();
        let capability = authenticated_for_test(runtime.clone());

        assert!(capability.runtime().is_same(&runtime));
        assert!(capability.record().runtime().is_same(&runtime));
    }

    #[test]
    fn v4_arc02_legacy_adapter_cannot_manufacture_authentication() {
        // The adapter accepts an already-issued capability and cannot mint one:
        // there is no constructor that takes a legacy value alone.
        let capability = authenticated_for_test(crate::runtime::runtime_for_test());
        let wrapper = super::super::LegacyAuthenticatedChannel::new(capability, "legacy channel");

        let _ = wrapper.capability();
    }

    #[test]
    fn v4_arc04_capability_context_and_runtime_are_exact_and_not_caller_supplied() {
        // Replacement for the old unreachable `RuntimeMismatch` control. The
        // record answers for exactly one mesh, one remote Device, one runtime,
        // and one proof, and two capabilities over different fixture channels
        // are distinguishable by their transcript identity — which is what the
        // install-side comparison relies on.
        let first = authenticated_for_test(crate::runtime::runtime_for_test());
        let second = authenticated_for_test(crate::runtime::runtime_for_test());

        assert!(first.authenticated_for("fixture-mesh", "fixture-device-remote"));
        assert!(!first.authenticated_for("other-mesh", "fixture-device-remote"));
        assert!(!first.authenticated_for("fixture-mesh", "other-device"));
        assert!(!first.record().runtime().is_same(second.record().runtime()));
        assert!(!first.belongs_to(second.record().connector()));
    }

    #[test]
    fn v4_arc04b_record_carries_the_connector_stated_binding_context() {
        // Every retained binding fact is recorded from the context the exchange
        // ran under, not defaulted and not caller-supplied — which is what lets
        // `EndpointAuthTask::issued` compare them on install. Deleting any of
        // these fields or their derivation in `from_verified_exchange` breaks
        // this control.
        //
        // The limit is stated rather than hidden: `EndpointAuthBindingProfile`
        // and `EndpointAuthBindingProvenance` each currently have exactly one
        // variant, so no fixture can produce a record whose profile or
        // provenance disagrees with its context, and no control can falsify
        // those two conjuncts in `issued` today. They become discriminating the
        // moment a second closed variant exists. Role is already discriminating
        // — the pair below derives opposite roles from the same fixture.
        let binding = crate::connector::EndpointAuthBinding::webrtc_certificate_fingerprints(
            "provenance-local-fp",
            "provenance-remote-fp",
        )
        .expect("both fixture components present");
        let stated = binding.provenance();
        let context = EndpointAuthContext::new(
            "fixture-mesh",
            "fixture-device-local",
            "fixture-device-remote",
            binding,
        )
        .expect("non-empty fixture identifiers");
        let handoff = crate::connector::handoff_for_test(crate::runtime::runtime_for_test());
        let channel_runtime = handoff
            .capability()
            .expect("fixture handoff holds its capability")
            .runtime()
            .clone();
        let record = AuthenticatedBindingRecord::from_verified_exchange(
            &context,
            b"fixture-transcript",
            Arc::clone(handoff.incarnation()),
            channel_runtime,
        );

        assert_eq!(
            record.binding_provenance(),
            stated,
            "the record must carry the connector's stated provenance"
        );
        assert_eq!(
            record.binding_provenance(),
            context.binding().provenance(),
            "and it must be the provenance of the exact context it was derived from"
        );
        assert_eq!(
            record.binding_profile(),
            context.binding().profile(),
            "the connector-side binding profile is carried too"
        );
        assert_eq!(
            record.local_role(),
            context.local_role(),
            "and the exact role this endpoint proved under"
        );

        // Role is the conjunct that already discriminates: the same fixture
        // with the Device pair reversed derives the opposite role, so a record
        // built under one role does not match a context built under the other.
        let mirrored = EndpointAuthContext::new(
            "fixture-mesh",
            "fixture-device-remote",
            "fixture-device-local",
            crate::connector::EndpointAuthBinding::webrtc_certificate_fingerprints(
                "provenance-remote-fp",
                "provenance-local-fp",
            )
            .expect("both fixture components present"),
        )
        .expect("non-empty fixture identifiers");
        assert_ne!(
            record.local_role(),
            mirrored.local_role(),
            "non-vacuity: the two endpoints of one attempt hold different roles, so the role comparison in `issued` can fail"
        );
    }
}

/// Length-prefixed digest input, so two different field tuples cannot produce
/// the same digest.
fn digest_of(fields: &[&[u8]]) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update(field.len().to_string().as_bytes());
        hasher.update(b":");
        hasher.update(field);
    }
    data_encoding::BASE32_NOPAD
        .encode(&hasher.finalize())
        .to_lowercase()
}
