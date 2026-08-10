//! Local-principal and application-queue capability boundary for V4.
//!
//! The principal binding selected here is the **local process itself**: the
//! application operations this crate serves run in-process with the embedder, so
//! the operating-system principal that authenticated is the one already running
//! this code. That is a real binding, not a placeholder, and it is deliberately
//! the narrowest one that is true — there is no per-request principal inference,
//! no client label, and no identity or attestation framework.

use crate::runtime::RuntimeIncarnation;

/// Local proof that an operating-system principal was authenticated and is
/// eligible for a Session Broker policy check.
///
/// One per process, minted by [`Self::for_local_process`] and shared through an
/// `Arc` by every session that speaks for it. A second value would be a second
/// principal, which is why there is no other constructor.
///
/// A public user, client, request, or peer label cannot construct this type:
///
/// ```compile_fail,E0308
/// use myownmesh_core::application_gateway::LocalPrincipalCapability;
///
/// let public_client_label = String::new();
/// let _principal = LocalPrincipalCapability::from(public_client_label);
/// ```
pub struct LocalPrincipalCapability {
    runtime: RuntimeIncarnation,
}

impl LocalPrincipalCapability {
    /// Bind the principal for this process's runtime.
    ///
    /// Crate-private and called once, by the Session Broker. The authority is
    /// the running process's own: no evidence is parsed, because none is
    /// transmitted — an in-process embedder cannot present a principal other
    /// than the one it is.
    ///
    /// The daemon's control clients are deliberately **not** separate
    /// principals. A Device value arriving over control IPC is a selector, and
    /// which local process may call the daemon at all is the operating system's
    /// socket boundary to decide. Each supervising application gets this
    /// principal through its own daemon process, so per-client identities would
    /// add a second identity system without adding a second trust boundary.
    pub(crate) fn for_local_process(runtime: RuntimeIncarnation) -> Self {
        Self { runtime }
    }

    pub(crate) fn runtime(&self) -> &RuntimeIncarnation {
        &self.runtime
    }

    #[cfg(test)]
    pub(crate) fn for_test(runtime: RuntimeIncarnation) -> Self {
        Self::for_local_process(runtime)
    }
}

/// Proof that post-authentication application-queue capacity was admitted.
///
/// Arc 02 creates no production issuer and supplies no conversion from any
/// pre-authentication permit.
#[allow(dead_code, reason = "Arc 06 moves the production gateway caller")]
pub struct ApplicationQueuePermit {
    runtime: RuntimeIncarnation,
}

impl ApplicationQueuePermit {
    #[cfg(test)]
    pub(crate) fn for_test(runtime: RuntimeIncarnation) -> Self {
        Self { runtime }
    }

    #[cfg(test)]
    pub(crate) fn runtime(&self) -> &RuntimeIncarnation {
        &self.runtime
    }
}

/// Arc 06 compatibility container for an already-authenticated local
/// principal.
#[allow(
    dead_code,
    reason = "Arc 06 installs and deletes this migration adapter"
)]
pub(crate) struct LegacyPrincipal<T> {
    capability: LocalPrincipalCapability,
    legacy: T,
}

#[allow(
    dead_code,
    reason = "Arc 06 installs and deletes this migration adapter"
)]
impl<T> LegacyPrincipal<T> {
    pub(crate) fn new(capability: LocalPrincipalCapability, legacy: T) -> Self {
        Self { capability, legacy }
    }

    pub(crate) fn capability(&self) -> &LocalPrincipalCapability {
        &self.capability
    }

    fn into_parts(self) -> (LocalPrincipalCapability, T) {
        (self.capability, self.legacy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_arc02_principal_and_queue_permit_are_runtime_bound() {
        let runtime = crate::runtime::runtime_for_test();
        let principal = LocalPrincipalCapability::for_test(runtime.clone());
        let queue = ApplicationQueuePermit::for_test(runtime.clone());

        assert!(principal.runtime().is_same(&runtime));
        assert!(queue.runtime().is_same(&runtime));
    }

    #[test]
    fn v4_arc02_legacy_principal_requires_existing_authority() {
        let principal = LocalPrincipalCapability::for_test(crate::runtime::runtime_for_test());
        let wrapper = LegacyPrincipal::new(principal, "legacy principal");
        let _ = wrapper.capability();
        let (_capability, legacy) = wrapper.into_parts();

        assert_eq!(legacy, "legacy principal");
    }
}
