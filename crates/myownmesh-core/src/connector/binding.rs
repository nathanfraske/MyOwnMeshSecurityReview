//! Closed connector-supplied channel binding for endpoint authentication.
//!
//! A connector states what it can prove about the channel it produced. It does
//! not state what that proof means for authentication, and it does not choose
//! endpoint-authentication roles or byte ordering: those belong to the endpoint
//! authentication owner, which derives the role from its own context.
//!
//! The type is closed on purpose. There is no free-form string constructor and
//! no open extension point, so a future exporter or pairing profile is added as
//! a named variant here rather than by smuggling bytes through this one.

/// The closed set of connector binding profiles.
///
/// One variant per proof a connector can actually supply. Adding a profile is
/// a deliberate edit here, and the selected profile is what the endpoint
/// authentication transcript binds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EndpointAuthBindingProfile {
    /// The two endpoint DTLS certificate fingerprints of one WebRTC channel.
    ///
    /// The accepted residual is stated exactly: this pair defeats a terminating
    /// signaling-path MITM because each terminated leg presents a different
    /// certificate. It is not session-unique, does not cover the DTLS key
    /// exchange, and is not an RFC 5705 exporter.
    WebRtcDtlsCertificateFingerprintPair,
}

/// One closed, non-serializable connector binding.
///
/// The components are private and are named by endpoint, not by role: the
/// connector knows which fingerprint is local and which is remote, and it knows
/// nothing about who is initiator or responder. Canonical ordering is applied
/// by the endpoint authentication owner from its derived role, so no caller —
/// and in particular no transport — chooses the ordering that the transcript
/// commits to.
pub(crate) struct EndpointAuthBinding {
    profile: EndpointAuthBindingProfile,
    local_component: String,
    remote_component: String,
}

impl EndpointAuthBinding {
    /// Supply the accepted WebRTC certificate-fingerprint pair.
    ///
    /// This is the only constructor, it names its profile rather than accepting
    /// one, and it takes the two components separately so neither the caller
    /// nor the transport can pre-order them. Both components must be present:
    /// a missing local or remote fingerprint yields no binding at all rather
    /// than a binding with an empty side.
    pub(crate) fn webrtc_certificate_fingerprints(
        local_component: &str,
        remote_component: &str,
    ) -> Option<Self> {
        if local_component.is_empty() || remote_component.is_empty() {
            return None;
        }
        Some(Self {
            profile: EndpointAuthBindingProfile::WebRtcDtlsCertificateFingerprintPair,
            local_component: local_component.to_owned(),
            remote_component: remote_component.to_owned(),
        })
    }

    /// The closed profile this binding supplies.
    pub(crate) fn profile(&self) -> EndpointAuthBindingProfile {
        self.profile
    }

    /// The component belonging to this endpoint.
    ///
    /// Endpoint-relative, never role-relative. The endpoint authentication
    /// owner pairs this with its derived role to produce canonical order.
    pub(crate) fn local_component(&self) -> &str {
        &self.local_component
    }

    /// The component belonging to the remote endpoint.
    pub(crate) fn remote_component(&self) -> &str {
        &self.remote_component
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_arc04b_binding_requires_both_components_and_names_its_profile() {
        assert!(EndpointAuthBinding::webrtc_certificate_fingerprints("", "remote").is_none());
        assert!(EndpointAuthBinding::webrtc_certificate_fingerprints("local", "").is_none());

        let binding = EndpointAuthBinding::webrtc_certificate_fingerprints("local", "remote")
            .expect("both components present");

        assert_eq!(
            binding.profile(),
            EndpointAuthBindingProfile::WebRtcDtlsCertificateFingerprintPair
        );
        assert_eq!(binding.local_component(), "local");
        assert_eq!(binding.remote_component(), "remote");
    }
}
