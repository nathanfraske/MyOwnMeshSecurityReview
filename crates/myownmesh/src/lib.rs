//! The MyOwnMesh **daemon**, as a library.
//!
//! The `myownmesh` binary (this package's bin target) is a thin CLI over the
//! modules here. They are exposed as a library for one reason: so a host
//! application that is **forbidden from spawning processes**, such as an iOS
//! app where the sandbox allows neither fork nor exec, can run the same daemon
//! inside its own process via [`embedded::start_connector_capable`], instead of
//! re-implementing the daemon's behaviour piece by piece.
//!
//! Everything else about the daemon is unchanged: it still listens on the
//! control socket (a unix socket inside the app sandbox on iOS; sockets are
//! allowed; processes aren't), speaks the same wire protocol, and hosts the
//! same registry/services, so existing clients (`myownmesh ctl`, the GUIs, and
//! any embedding application's own sidecar) work against it identically whether
//! it runs as a process or embedded.

pub mod control;
pub mod embedded;
pub mod ipc;
pub mod registry;
pub mod services;

#[cfg(test)]
pub(crate) const TEST_PROCESS_CONNECTOR_CAPACITY: usize = 4;

/// One explicitly finite provider shared by daemon-library tests.
///
/// These are fixture resources, not production defaults. The callback and
/// payload quantities are derived from the existing test policies below. The
/// opaque residual covers this test binary's process, Mesh, connector, and
/// provider-bookkeeping objects.
#[cfg(test)]
pub(crate) fn test_resource_provider() -> myownmesh_core::ResourceProviderPort {
    static PROVIDER: std::sync::OnceLock<myownmesh_core::ResourceProviderPort> =
        std::sync::OnceLock::new();
    PROVIDER
        .get_or_init(|| {
            let connectors = TEST_PROCESS_CONNECTOR_CAPACITY as u64;
            let callback_items_per_connector = 32_u64;
            let queued_bytes = connectors
                .checked_mul(callback_items_per_connector)
                .and_then(|items| {
                    items.checked_mul(myownmesh_core::engine::MAX_ENDPOINT_FRAME_BYTES as u64)
                })
                .expect("daemon test queued-byte grant is representable");
            let work_items = connectors
                .checked_mul(callback_items_per_connector)
                .expect("daemon test work-item grant is representable");
            let residual = 1u64
                .checked_add(connectors)
                .and_then(|value| value.checked_add(connectors.checked_mul(3)?))
                .and_then(|value| value.checked_add(work_items))
                .expect("daemon test provider bookkeeping is representable");
            let structural = myownmesh_core::connector_resource_structural_claims();
            let structural = structural
                .connector_opening()
                .checked_scale(connectors)
                .and_then(|claim| claim.checked_add(structural.process_infrastructure()))
                .expect("daemon test structural claims are representable");
            let workload = myownmesh_core::ResourceClaim::try_from_entries([
                (
                    myownmesh_core::ResourceClass::AccountedMemoryBytes,
                    queued_bytes,
                ),
                (myownmesh_core::ResourceClass::QueuedBytes, queued_bytes),
                (
                    myownmesh_core::ResourceClass::CallbackOrScheduledWork,
                    connectors * (1 + callback_items_per_connector),
                ),
                (myownmesh_core::ResourceClass::StorageBytes, 0),
                (myownmesh_core::ResourceClass::StorageObject, work_items),
                (myownmesh_core::ResourceClass::RelayOrProviderAllocation, 0),
                (
                    myownmesh_core::ResourceClass::ParsingOrCpuWork,
                    queued_bytes,
                ),
                (
                    myownmesh_core::ResourceClass::OpaqueDependencyResidual,
                    residual,
                ),
            ])
            .expect("daemon test workload claim is representable");
            let claim = structural
                .checked_add(workload)
                .expect("daemon test resource grant is representable");
            myownmesh_core::ResourceProviderPort::new(myownmesh_core::FiniteResourceProvider::new(
                claim,
            ))
            .expect("daemon test resource provider admits its process scope")
        })
        .clone()
}
