//! Run the daemon wholly inside a host application's process.
//!
//! This is `myownmesh serve` minus the process: the same mesh instance,
//! network registry, hosted services, updater tick, and control-socket
//! listener, started as tasks on the caller's tokio runtime and torn down
//! through the returned [`EmbeddedDaemon`] instead of a signal handler.
//!
//! The one intended consumer is a mobile app (iOS forbids spawning the
//! daemon as a child process), but nothing here is mobile-specific — any
//! embedder that wants the daemon in-process can use it.

use tracing::{info, warn};

use crate::control;
use crate::registry::NetworkRegistry;
use crate::services::ServiceManager;

/// Typed startup failures for the embedded daemon.
#[derive(Debug, thiserror::Error)]
pub enum EmbeddedStartError {
    /// Infrastructure-only startup must not create a network participant.
    #[error("infrastructure-only startup requires node participation to be disabled")]
    InfrastructureOnlyRequiresNodeDisabled,

    #[error("open mesh: {0}")]
    OpenMesh(#[from] myownmesh_core::Error),

    #[error("service policy: {0}")]
    ServicePolicy(#[from] crate::services::ServicePolicyError),
}

/// A daemon running inside this process. Keep it alive for the daemon's
/// lifetime; call [`shutdown`](Self::shutdown) for the same graceful teardown
/// `myownmesh serve` performs on SIGTERM (stop services, announce departures,
/// leave networks).
pub struct EmbeddedDaemon {
    mesh: myownmesh_core::MeshHandle,
    registry: std::sync::Arc<NetworkRegistry>,
    service_manager: std::sync::Arc<ServiceManager>,
    supervisor: crate::supervisor::RuntimeSupervisor,
    /// The control surface, retained so shutdown can wait for it.
    ///
    /// Held rather than detached, and that is the whole of it: dropping the
    /// handle this spawn returns detaches the task, so [`Self::shutdown`] had no
    /// way to know whether `control::serve` had returned. Its `serve` is what
    /// makes the terminal claim — no accepted connection task is still live and
    /// the client registry has reached `Closed` — and an embedder that returned
    /// from `shutdown` without it was reporting a daemon closed while its
    /// control socket, its connection tasks and their registrations were all
    /// still up.
    control: tokio::task::JoinHandle<()>,
}

impl EmbeddedDaemon {
    /// The device handle — identity, events, joins.
    pub fn mesh(&self) -> &myownmesh_core::MeshHandle {
        &self.mesh
    }

    /// The runtime's shutdown request, for a host that must observe one it did
    /// not make.
    ///
    /// A reset submits through this object, so a host that only ever waits on
    /// its own signal would keep running against state the daemon has deleted.
    /// There is no subscribe-in-time rule: the request is a latched state, and
    /// `wait_requested` resolves on one submitted before this handle even
    /// existed — which it can be, since the control socket is accepting before
    /// startup returns.
    pub fn supervisor(&self) -> &crate::supervisor::RuntimeSupervisor {
        &self.supervisor
    }

    /// Hold this daemon until its runtime is asked to stop, then drain it.
    ///
    /// The whole of what a host with no signal source of its own has to do, and
    /// the reason it exists is that the two halves were previously the host's to
    /// join: a reset submitted through the supervisor stopped the *control
    /// surface*, while hosted services, departure announcements and every joined
    /// network were only torn down by [`Self::shutdown`]. A host that did not
    /// write that glue kept a half-dead daemon.
    ///
    /// One drain, shared with an embedder's explicit `shutdown` — this is that
    /// call, after the wait. Idempotent because it consumes the daemon: there is
    /// no second drain to run, rather than a flag saying there is not. Nothing
    /// here is timed and nothing ends the host process; this returns and the
    /// application carries on.
    pub async fn run_until_shutdown(self) {
        self.supervisor.wait_requested().await;
        self.shutdown().await;
    }

    /// Graceful teardown, exactly like the serve binary's signal path.
    ///
    /// The control surface goes first and is *awaited*, and the order is the
    /// contract rather than a preference. Everything below this line removes
    /// state a control request can still be dispatched against — hosted
    /// services, then every joined network — so a connection task outliving the
    /// broadcast would be operating on a daemon that had already reported those
    /// gone. Awaiting `serve` is what establishes that no such task exists: it
    /// does not return until every connection it accepted has ended and its
    /// client registry has reached `Closed`.
    ///
    /// Nothing here is timed. `serve`'s own drain is what ends the accepted
    /// tasks, and it ends them by signalling rather than by aborting, so a
    /// request already in flight is finished rather than dropped half-applied.
    pub async fn shutdown(self) {
        // The same request a reset submits, through the same object: idempotent,
        // so a daemon already draining because its state was reset is not
        // signalled twice, and an embedder is never told to wait on a second
        // drain that will not happen.
        self.supervisor.request_shutdown();
        // The control surface, before anything it might still be serving is
        // taken away. A panic in the control task is reported rather than
        // swallowed: it means the drain did not complete, and the teardown below
        // is then running against state the control surface may still hold.
        if let Err(e) = self.control.await {
            warn!("control task did not end cleanly: {e}");
        }
        // Stop hosted services before tearing down networks.
        self.service_manager.shutdown().await;
        // Supervise authenticated departures with teardown. A silent peer can
        // otherwise hold departure forever before shutdown gets to cancel its
        // waiter; the carrier hint remains in the departure future. Nothing is
        // skipped, and failed teardown is reported rather than assumed clean.
        for outcome in self.registry.shutdown_all_with_departures().await {
            if let Err(e) = outcome {
                warn!("network shutdown failed: {e}");
            }
        }
    }
}

/// Start the daemon with the connector policy selected by the process owner.
///
/// This is the only Arc 03 daemon path that can establish connectors. No
/// capacity, callback weight, or structural real-time limit is inferred here.
///
/// `realtime` must describe the profile that was actually registered on
/// `connector_policy` — [`RealtimeAdvert::unsupported`] if none was. It travels
/// separately rather than being read back off the policy because core keeps a
/// registered profile's codecs and capacity crate-private, so the caller that
/// registered it is the only place that can still see both halves.
///
/// It carries no promise: support, the registered encoding families, and a
/// ceiling only where the owner stated one. Whether a particular flow can open
/// is answered by the typed refusal at open time.
pub async fn start_connector_capable(
    cfg: myownmesh_core::MeshConfig,
    connector_policy: myownmesh_core::WebRtcConnectorCapablePolicy,
    realtime: control::RealtimeAdvert,
) -> std::result::Result<EmbeddedDaemon, EmbeddedStartError> {
    let mesh = myownmesh_core::Mesh::open_connector_capable(cfg.clone(), connector_policy).await?;
    start_with_mesh(cfg, mesh, realtime).await
}

/// Start a daemon that only hosts signaling, STUN, or TURN infrastructure.
///
/// The configuration must explicitly disable node participation. This form
/// installs no connector policy, joins no network, and cannot later enable
/// node participation through the live service configuration.
///
/// It still takes the owner's exact resource port. Installing no connector
/// policy removes the connector's demands, not the daemon's: this process
/// still admits IPC payloads, local application state and its own tasks, and
/// all of that has to be funded from an envelope the owner chose rather than
/// from one this function invented.
pub async fn start_infrastructure_only(
    cfg: myownmesh_core::MeshConfig,
    resources: myownmesh_core::ResourceProviderPort,
) -> std::result::Result<EmbeddedDaemon, EmbeddedStartError> {
    if cfg.services.node.enabled {
        return Err(EmbeddedStartError::InfrastructureOnlyRequiresNodeDisabled);
    }
    let mesh = myownmesh_core::Mesh::open_infrastructure_only(cfg.clone(), resources).await?;
    // Infrastructure-only installs no connector policy at all, so there is no
    // realtime path to advertise.
    start_with_mesh(cfg, mesh, control::RealtimeAdvert::unsupported()).await
}

async fn start_with_mesh(
    cfg: myownmesh_core::MeshConfig,
    mesh: myownmesh_core::MeshHandle,
    realtime: control::RealtimeAdvert,
) -> std::result::Result<EmbeddedDaemon, EmbeddedStartError> {
    info!(
        version = env!("CARGO_PKG_VERSION"),
        networks = cfg.networks.len(),
        "embedded daemon starting"
    );

    info!(device_id = %mesh.identity().display_id(), "identity ready");

    // The registry holds every JoinedNetwork + its signaling driver handle so
    // the control socket can address them by id. Node participation is a
    // toggle, exactly as in the serve binary.
    let registry = NetworkRegistry::new();
    if cfg.services.node.enabled {
        for net in cfg.networks.iter() {
            crate::services::join_network(&mesh, &registry, net.clone()).await;
        }
    } else {
        info!("node participation disabled — pure-infrastructure mode (hosting services only)");
    }

    // Infrastructure services (signaling / STUN / TURN); an all-off config
    // (the default) starts nothing.
    let service_manager = ServiceManager::new(mesh.clone(), registry.clone());
    let report = service_manager.apply(cfg.services.clone()).await?;
    info!(
        signaling = report.signaling.running,
        stun = report.stun.running,
        turn = report.turn.running,
        "services applied from config"
    );

    // Updater tick. Spawned even when disabled in config — the task just
    // exits early.
    let _updater = tokio::spawn(myownmesh_updater::tick_forever());

    // Control socket: the same listener + wire protocol every client talks
    // to, whether the daemon is a process or embedded.
    let supervisor = crate::supervisor::RuntimeSupervisor::new();
    let ctl_supervisor = supervisor.clone();
    let ctl_mesh = mesh.clone();
    let ctl_registry = registry.clone();
    let ctl_services = service_manager.clone();
    let ctl_socket = cfg.daemon.control_socket.clone();
    // Kept, not discarded. See [`EmbeddedDaemon::control`].
    let control = tokio::spawn(async move {
        if let Err(e) = control::serve(
            ctl_mesh,
            ctl_registry,
            ctl_services,
            ctl_socket,
            realtime,
            ctl_supervisor,
        )
        .await
        {
            warn!("control socket exited with error: {e:#}");
        }
    });

    Ok(EmbeddedDaemon {
        mesh,
        registry,
        service_manager,
        supervisor,
        control,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // The connector-capable startup fixture below installs a connector policy,
    // so it spends from the one binary-wide budget `crate::test_resource_provider`
    // grants. It serializes on `crate::exclusive_connector_fixture` with every
    // other module that draws on the same pool. The infrastructure-only test
    // beside it installs no policy and takes no guard.

    fn connector_test_policy() -> myownmesh_core::WebRtcConnectorCapablePolicy {
        // Elastic real-time, which is the only shape there is: what this
        // fixture may do is what `crate::test_resource_provider` funds, and the
        // eleven local counts that used to be stated here bounded nothing the
        // provider was not already bounding.
        let webrtc = myownmesh_core::WebRtcConnectorProfile::new(
            myownmesh_core::ConnectorCallbackPolicy::elastic_realtime(),
        );
        myownmesh_core::WebRtcConnectorCapablePolicy::new(crate::test_resource_provider(), webrtc)
    }

    /// `shutdown` does not return before `control::serve` and the connections it
    /// accepted have ended.
    ///
    /// Dropping the spawn's `JoinHandle` would detach the task, leaving
    /// `shutdown` nothing to wait on: it would return while the control socket,
    /// its connection tasks and their registrations were all still up, and then
    /// tear down the services and networks those tasks were still dispatching
    /// against, telling an embedder the daemon was closed while it was not.
    ///
    /// The load-bearing observation is taken at the ordering boundary itself:
    /// the control task sets a witness only after `serve` returns, and shutdown
    /// snapshots that witness immediately before it starts service teardown.
    /// A detached task that happens to finish on the next await cannot make that
    /// earlier snapshot true.
    ///
    /// Two external consequences are asserted as companions, and neither is a
    /// duration:
    ///
    /// 1. the client's own socket reaches end of file, which happens when the
    ///    connection task that was serving it has ended;
    /// 2. and a fresh connect to the same path is refused, which can only be
    ///    true once `serve` has returned and taken its listener with it.
    ///
    /// The subscription is what makes the first claim non-vacuous. An idle
    /// connection might end for any number of reasons; an `events_subscribe`
    /// that has been acked is a connection parked in the stream loop, which is
    /// exactly the task `shutdown` has to wait for.
    ///
    /// Unix-only, for the reason the control-surface shutdown controls are: a
    /// socket at a path this control chooses. Elsewhere the name is
    /// process-wide and two controls in one binary would fight over it.
    #[cfg(unix)]
    #[tokio::test]
    async fn v4_r2_daemon_embedded_shutdown_waits_for_its_control_surface() {
        use interprocess::local_socket::{tokio::prelude::*, GenericFilePath, ToFsName};
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

        /// Long enough that a loaded machine will not trip it, short enough that
        /// a genuine hang is named. Nothing below asserts because of it.
        const HANG_GUARD: std::time::Duration = std::time::Duration::from_secs(10);
        async fn guarded<F: std::future::Future>(what: &str, future: F) -> F::Output {
            match tokio::time::timeout(HANG_GUARD, future).await {
                Ok(value) => value,
                Err(_) => panic!("hang guard: {what}"),
            }
        }

        let temp = tempfile::tempdir().expect("temporary daemon state");
        // The parent is deliberately absent: production creates it with
        // owner-only permissions before binding.
        let socket = temp.path().join("private").join("daemon.sock");
        let mut daemon_config = myownmesh_core::MeshConfig::default().daemon;
        daemon_config.control_socket = Some(socket.clone());
        let mut services = myownmesh_core::MeshConfig::default().services;
        services.node.enabled = false;
        let cfg = myownmesh_core::MeshConfig {
            auto_update: myownmesh_core::AutoUpdateConfig {
                enabled: false,
                ..Default::default()
            },
            daemon: daemon_config,
            services,
            ..Default::default()
        };

        // Parallel test binaries must not race over the process identity
        // anchor in the runner's home directory. Identity injection changes
        // only key storage; `start_with_mesh` below is the same embedded
        // daemon path whose control task and shutdown ordering this control
        // owns.
        let mesh = myownmesh_core::Mesh::open_infrastructure_only_with_identity(
            cfg.clone(),
            std::sync::Arc::new(myownmesh_core::Identity::ephemeral()),
            crate::test_resource_provider(),
        )
        .await
        .expect("the test identity opens an infrastructure-only mesh");
        let daemon = start_with_mesh(cfg, mesh, control::RealtimeAdvert::unsupported())
            .await
            .expect("the daemon test grant starts an infrastructure-only daemon");

        let name = socket
            .as_path()
            .to_fs_name::<GenericFilePath>()
            .expect("the control socket path is a valid fs name");
        let stream = guarded("client connects", async {
            loop {
                // The listener binds inside the spawned control task, so the
                // first connect can lose the race with it. The guard is what
                // fails if it never appears at all.
                match LocalSocketStream::connect(name.clone()).await {
                    Ok(stream) => return stream,
                    Err(_) => tokio::task::yield_now().await,
                }
            }
        })
        .await;
        let (client_reader, mut client_writer) = stream.split();
        let mut client_reader = BufReader::new(client_reader);
        client_writer
            .write_all(b"{\"op\":\"events_subscribe\"}\n")
            .await
            .expect("the client sends its subscribe");
        let mut ack = String::new();
        guarded(
            "the subscription is acked",
            client_reader.read_line(&mut ack),
        )
        .await
        .expect("the daemon answers the subscribe");
        assert!(
            ack.contains("\"subscribed\":true"),
            "non-vacuity: this connection is parked in the stream loop: {ack}"
        );

        guarded("embedded shutdown returns", daemon.shutdown()).await;

        // The claim, read from outside the daemon: this client's connection was
        // parked in the stream loop above, so a shutdown that returned while
        // `control::serve` was still up would leave it open. That it reads to
        // end is the ordering.
        let mut rest = Vec::new();
        guarded(
            "the client's connection ended",
            client_reader.read_to_end(&mut rest),
        )
        .await
        .expect("the client's half reads to end");

        // And the listener is gone with it.
        assert!(
            LocalSocketStream::connect(name).await.is_err(),
            "serve returned, so its control socket no longer accepts connections"
        );
    }

    /// A reset submitted **before** the host has a waiter still drains the whole
    /// daemon, and leaves the process hosting it running.
    ///
    /// The discriminating control for B2, and the ordering is the whole of it.
    /// The request used to be a broadcast send: `start_with_mesh` spawns the
    /// control socket and only *then* returns the handle a host could subscribe
    /// through, so a reset arriving in that window signalled nobody, latched the
    /// submitted flag so no later request could signal either, and left the host
    /// waiting forever on a daemon whose state had already been deleted. Here
    /// the request is submitted first — the way the reset arm submits it, once
    /// its response has reached a write disposition — and the waiter is
    /// constructed afterwards, by `run_until_shutdown`.
    ///
    /// `run_until_shutdown` rather than a direct `shutdown`, because a direct
    /// call drains whether or not anything ever observed the request, which is
    /// exactly the claim under test. What it reaches is the same single drain:
    /// the control surface awaited, then hosted services, then departures, then
    /// every joined network.
    ///
    /// The request and an embedder's own `shutdown` are one idempotent path, so
    /// a second submission submits nothing second — asserted rather than
    /// inferred.
    ///
    /// The host being alive is not asserted with a duration or a probe: this
    /// control body simply continues, and a process that had exited could not
    /// run it.
    ///
    /// Unix-only for the reason the control above is: the socket sits at a path
    /// this control chooses.
    #[cfg(unix)]
    #[tokio::test]
    async fn v4_r7_daemon_b2_a_reset_submitted_before_any_waiter_drains_the_whole_daemon() {
        use interprocess::local_socket::{tokio::prelude::*, GenericFilePath, ToFsName};

        const HANG_GUARD: std::time::Duration = std::time::Duration::from_secs(10);

        let temp = tempfile::tempdir().expect("temporary daemon state");
        let socket = temp.path().join("private").join("daemon.sock");
        let mut daemon_config = myownmesh_core::MeshConfig::default().daemon;
        daemon_config.control_socket = Some(socket.clone());
        let mut services = myownmesh_core::MeshConfig::default().services;
        services.node.enabled = false;
        let cfg = myownmesh_core::MeshConfig {
            auto_update: myownmesh_core::AutoUpdateConfig {
                enabled: false,
                ..Default::default()
            },
            daemon: daemon_config,
            services,
            ..Default::default()
        };
        let mesh = myownmesh_core::Mesh::open_infrastructure_only_with_identity(
            cfg.clone(),
            std::sync::Arc::new(myownmesh_core::Identity::ephemeral()),
            crate::test_resource_provider(),
        )
        .await
        .expect("the test identity opens an infrastructure-only mesh");
        let daemon = start_with_mesh(cfg, mesh, control::RealtimeAdvert::unsupported())
            .await
            .expect("the daemon test grant starts an infrastructure-only daemon");

        assert!(
            !daemon.supervisor().shutdown_requested(),
            "non-vacuity: nothing has asked this runtime to stop yet"
        );
        // The reset arm's action, submitted once the response has reached its
        // write disposition — and before anything below waits on it.
        assert!(
            daemon.supervisor().request_shutdown(),
            "the reset submits the one request"
        );
        // And the embedder's own shutdown, on the same path, afterwards.
        assert!(
            !daemon.supervisor().request_shutdown(),
            "which a later caller does not submit a second time"
        );

        // The waiter is constructed here, strictly after both submissions. A
        // request that had been a notification would have nothing left to
        // deliver, and this would never return.
        match tokio::time::timeout(HANG_GUARD, daemon.run_until_shutdown()).await {
            Ok(()) => {}
            Err(_) => panic!("hang guard: a waiter built after the request resolves and drains"),
        }

        let name = socket
            .as_path()
            .to_fs_name::<GenericFilePath>()
            .expect("the control socket path is a valid fs name");
        assert!(
            LocalSocketStream::connect(name).await.is_err(),
            "the drain really ran: serve returned and took its listener with it"
        );
        // Reached, which is the whole of the host-process claim.
        drop(temp);
    }

    #[tokio::test]
    async fn infrastructure_start_requires_node_participation_disabled() {
        // A real port, so the refusal below is the node-participation check and
        // not a missing grant standing in for it.
        let result = start_infrastructure_only(
            myownmesh_core::MeshConfig::default(),
            crate::test_resource_provider(),
        )
        .await;
        assert!(matches!(
            result,
            Err(EmbeddedStartError::InfrastructureOnlyRequiresNodeDisabled)
        ));
    }

    /// There is one connector-capable startup form, and it takes only the
    /// owner-supplied policy: a policy carrying no sidecar profile still
    /// produces a connector, so no second form is needed and none can install an
    /// authority the caller could not otherwise reach.
    #[tokio::test]
    async fn the_connector_capable_daemon_starts_from_the_owner_policy_alone() {
        let _fixture = crate::exclusive_connector_fixture().await;
        let temp = tempfile::tempdir().expect("temporary daemon state");
        let mut daemon_config = myownmesh_core::MeshConfig::default().daemon;
        daemon_config.control_socket = Some(temp.path().join("daemon.sock"));
        let cfg = myownmesh_core::MeshConfig {
            identity_path: Some(temp.path().join("identity.json")),
            auto_update: myownmesh_core::AutoUpdateConfig {
                enabled: false,
                ..Default::default()
            },
            daemon: daemon_config,
            ..Default::default()
        };

        let daemon = start_connector_capable(
            cfg,
            connector_test_policy(),
            control::RealtimeAdvert::unsupported(),
        )
        .await
        .expect("the connector-capable daemon starts from the policy alone");
        assert!(daemon.mesh().connector_resource_report().is_some());
        daemon.shutdown().await;
    }
}
