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
/// The largest single payload this binary's fixtures fund, per callback class.
///
/// Two numbers rather than one, and named rather than inlined, because a single
/// byte figure multiplied across the combined callback count is a grant in which
/// neither class's budget means what it says: the larger class silently pays for
/// the smaller, and removing the larger leaves the smaller funded for nothing.
/// Control covers one gathered ICE candidate's JSON; endpoint data keeps the
/// figure these fixtures have always run with, now stated as what it is.
///
/// They live at the provider rather than on a policy because the connector
/// policies in `ipc::bridge`, `registry` and `embedded` all draw on this one
/// grant, so there is no single policy that could state them for the rest.
#[cfg(test)]
const TEST_CONTROL_CALLBACK_BYTES: u64 = 4 * 1024;
#[cfg(test)]
const TEST_ENDPOINT_CALLBACK_BYTES: u64 = 16 * 1024 * 1024;

/// The largest JSON frame this binary's fixtures fund the *parse* of.
///
/// Its own number, deliberately not borrowed from either callback ceiling
/// above. Those bound what a connector may hold queued; this bounds what the
/// application gateway may allocate while turning one frame into a
/// `serde_json::Value` tree, which is a different quantity with a different
/// denomination — the tree's claim is per input byte because a JSON value can
/// hold as many independent allocations as it has bytes. Sizing one from the
/// other is what left this provider granting a residual counted in records
/// against a claim counted in bytes, so the first inbound `Hello` was refused
/// with every latch false and nothing logged above `trace!`.
///
/// Test workload capacity only. It gates nothing on the wire: a frame is
/// admitted against its own actual length, and a fixture that funds too little
/// sees a refusal, never a truncation.
#[cfg(test)]
const TEST_JSON_FRAME_BYTES: usize = 8 * 1024;

/// Simultaneous JSON input claims one connector can hold.
///
/// Exactly two, and both are real rather than headroom: the peer's `Hello`
/// retains its claim for the connection's whole life (the engine parks it in
/// `hello_retention`), and one further protocol or application frame is being
/// parsed at any moment. One would fund the retained `Hello` and refuse every
/// frame after it; more would be capacity nothing here can name a holder for.
#[cfg(test)]
const TEST_JSON_CLAIMS_PER_CONNECTOR: u64 = 2;

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
            // Each class funds its own callback slots from its own stated
            // ceiling, summed — not one figure spread across both.
            let queued_bytes = connectors
                .checked_mul(callback_items_per_connector)
                .and_then(|items| {
                    let control = items.checked_mul(TEST_CONTROL_CALLBACK_BYTES)?;
                    let endpoint = items.checked_mul(TEST_ENDPOINT_CALLBACK_BYTES)?;
                    control.checked_add(endpoint)
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
            // JSON input work, kept as its own term. The claim is taken from the
            // gateway rather than restated here, so this grant and the admission
            // it has to satisfy can never be derived from two different formulas
            // — which is exactly how they diverged. It is added separately from
            // the provider-record `residual` above because the two are different
            // quantities that happen to share a dimension: one counts this
            // fixture's own bookkeeping objects, the other covers a decoded JSON
            // tree's allocations.
            let json_input_work =
                myownmesh_core::application_gateway::json_input_work_claim(TEST_JSON_FRAME_BYTES)
                    .expect("daemon test JSON input claim is representable")
                    .checked_scale(
                        connectors
                            .checked_mul(TEST_JSON_CLAIMS_PER_CONNECTOR)
                            .expect("daemon test JSON claim count is representable"),
                    )
                    .expect("daemon test JSON input grant is representable");
            let claim = structural
                .checked_add(workload)
                .and_then(|claim| claim.checked_add(json_input_work))
                .expect("daemon test resource grant is representable");
            myownmesh_core::ResourceProviderPort::new(myownmesh_core::FiniteResourceProvider::new(
                claim,
            ))
            .expect("daemon test resource provider admits its process scope")
        })
        .clone()
}

/// Exclusive use of the connector budget above, for the whole lifetime of one
/// connector-consuming test's fixture.
///
/// One owner, because there is one budget. [`test_resource_provider`] is a
/// `OnceLock`, so its grant — [`TEST_PROCESS_CONNECTOR_CAPACITY`] connectors —
/// belongs to the test *binary* and not to each module that draws on it. Any
/// fixture that installs a connector policy is therefore spending from the same
/// finite pool as every other module's, and must serialize against them rather
/// than only against its own.
///
/// That is the whole claim, and it is the only one this guard can make good on.
/// A daemon test that opens a `Mesh` without a connector policy draws nothing
/// here and correctly takes no guard — `services`'s infrastructure-only tests
/// are the live example. Nothing in this workspace enforces one `Mesh` per
/// process, so do not read this guard as an identity or incarnation lock.
///
/// This replaces one mutex per test module — `ipc::bridge`, `embedded` and
/// `registry` each had their own. Each stopped a family racing itself and none
/// stopped the families racing each other, so with `libtest` running the binary
/// in parallel, three tests could draw on a budget of four connectors at once.
/// Three owners for one resource is the same defect shape the registry
/// supervisor itself exists to remove, and correcting that ownership is the
/// whole reason this guard exists — not a repair for any particular observed
/// failure. It was written while the bridge round trips were timing out waiting
/// for `PeerApproved`, and it did not fix them: they time out identically when
/// run alone with no other connector fixture in flight, so whatever those tests
/// are waiting on, it is not this budget.
///
/// Hold the guard for the fixture's whole life, teardown included. Releasing it
/// at the last assertion would let the next test ask for capacity the previous
/// one has not finished returning.
///
/// The `static` lives inside this function so there is exactly one and no module
/// can declare a second by accident.
#[cfg(test)]
pub(crate) async fn exclusive_connector_fixture() -> tokio::sync::MutexGuard<'static, ()> {
    static FIXTURE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    FIXTURE.lock().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use myownmesh_core::ResourceClass;

    /// The provider this binary actually hands out funds two simultaneous JSON
    /// inputs per connector, and exactly two.
    ///
    /// Behavioural rather than arithmetic on purpose. Restating the formula and
    /// asserting it equals itself would pass against a provider that dropped the
    /// term, mis-scaled it, or merged it into the record residual — the three
    /// ways this has actually gone wrong. So this acquires real leases from
    /// [`test_resource_provider`] on its own process scope and holds every one of
    /// them live to the end.
    ///
    /// The end-to-end bridge and silent-area round trips cannot stand in for it
    /// either: real handshake frames are far under the stated fixture frame size,
    /// so a grant of one claim per connector still carries them, and those tests
    /// would pass against a provider that refuses the second frame on any larger
    /// input.
    ///
    /// The refusal is asserted on `OpaqueDependencyResidual` specifically. That
    /// is the dimension the JSON term is denominated in and the one the record
    /// residual could never have covered; a refusal on any other dimension would
    /// mean this control passed for a reason unrelated to the defect.
    ///
    /// Takes the connector fixture guard because it spends from the one binary
    /// budget every connector-consuming fixture draws on.
    #[tokio::test]
    async fn v4_f8_the_daemon_provider_funds_exactly_two_json_inputs_per_connector() {
        let _fixture = exclusive_connector_fixture().await;
        let provider = test_resource_provider();
        let scope = provider.process_scope();
        let one = myownmesh_core::application_gateway::json_input_work_claim(TEST_JSON_FRAME_BYTES)
            .expect("one JSON input claim is representable");

        let funded = (TEST_PROCESS_CONNECTOR_CAPACITY as u64)
            .checked_mul(TEST_JSON_CLAIMS_PER_CONNECTOR)
            .expect("the fixture JSON claim count is representable");
        let mut leases = Vec::new();
        for index in 0..funded {
            let lease = provider
                .acquire(
                    &scope,
                    myownmesh_core::ResourceAuthorityClass::Admitted,
                    one,
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "JSON input {index} of {funded} must be funded while the earlier ones are \
                         still held: {error:?}"
                    )
                });
            leases.push(lease);
        }

        let refused = provider.acquire(
            &scope,
            myownmesh_core::ResourceAuthorityClass::Admitted,
            one,
        );
        let Err(unavailable) = refused else {
            panic!(
                "the provider funded a {}th simultaneous JSON input, so the two-per-connector term \
                 is not what bounds it",
                funded + 1
            )
        };
        assert_eq!(
            unavailable.dimension(),
            Some(ResourceClass::OpaqueDependencyResidual),
            "the bound must be the JSON term's own dimension"
        );

        // Held to the end. Releasing any earlier would let the refusal above
        // pass against capacity an earlier acquisition had already returned.
        drop(leases);
    }
}
