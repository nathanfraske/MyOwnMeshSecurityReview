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

use tokio::sync::broadcast;
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
    shutdown_tx: broadcast::Sender<()>,
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
    /// Test witness set by the control task after `serve` returns.
    #[cfg(all(test, unix))]
    control_finished: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Snapshot of `control_finished` at the boundary before service teardown.
    #[cfg(all(test, unix))]
    control_drained_before_teardown: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl EmbeddedDaemon {
    /// The device handle — identity, events, joins.
    pub fn mesh(&self) -> &myownmesh_core::MeshHandle {
        &self.mesh
    }

    /// Observe the ordering boundary the embedded-shutdown control owns.
    #[cfg(all(test, unix))]
    fn control_drained_before_teardown_for_test(
        &self,
    ) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        std::sync::Arc::clone(&self.control_drained_before_teardown)
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
        let _ = self.shutdown_tx.send(());
        // The control surface, before anything it might still be serving is
        // taken away. A panic in the control task is reported rather than
        // swallowed: it means the drain did not complete, and the teardown below
        // is then running against state the control surface may still hold.
        if let Err(e) = self.control.await {
            warn!("control task did not end cleanly: {e}");
        }
        #[cfg(all(test, unix))]
        self.control_drained_before_teardown.store(
            self.control_finished
                .load(std::sync::atomic::Ordering::Acquire),
            std::sync::atomic::Ordering::Release,
        );
        // Stop hosted services before tearing down networks.
        self.service_manager.shutdown().await;
        // Say goodbye before we go: a graceful `leave` per network so peers
        // drop our sessions immediately rather than waiting out a heartbeat.
        self.registry.announce_all_departures().await;
        // Every distinct network, through the registry's own teardown. It used
        // to hand back only the networks it could take sole ownership of, so a
        // network held by one in-flight request at shutdown was silently left
        // running and its peers waited out a heartbeat instead of seeing a
        // leave. Nothing is skipped now, and a failed teardown is reported
        // rather than assumed clean.
        for outcome in self.registry.shutdown_all().await {
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
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let ctl_mesh = mesh.clone();
    let ctl_registry = registry.clone();
    let ctl_services = service_manager.clone();
    let ctl_shutdown = shutdown_tx.subscribe();
    let ctl_socket = cfg.daemon.control_socket.clone();
    #[cfg(all(test, unix))]
    let control_finished = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    #[cfg(all(test, unix))]
    let control_finished_by_task = std::sync::Arc::clone(&control_finished);
    #[cfg(all(test, unix))]
    let control_drained_before_teardown =
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    // Kept, not discarded. See [`EmbeddedDaemon::control`].
    let control = tokio::spawn(async move {
        if let Err(e) = control::serve(
            ctl_mesh,
            ctl_registry,
            ctl_services,
            ctl_socket,
            realtime,
            ctl_shutdown,
        )
        .await
        {
            warn!("control socket exited with error: {e:#}");
        }
        #[cfg(all(test, unix))]
        control_finished_by_task.store(true, std::sync::atomic::Ordering::Release);
    });

    Ok(EmbeddedDaemon {
        mesh,
        registry,
        service_manager,
        shutdown_tx,
        control,
        #[cfg(all(test, unix))]
        control_finished,
        #[cfg(all(test, unix))]
        control_drained_before_teardown,
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

    fn nz(value: usize) -> std::num::NonZeroUsize {
        std::num::NonZeroUsize::new(value).expect("startup fixture is nonzero")
    }

    fn connector_test_policy() -> myownmesh_core::WebRtcConnectorCapablePolicy {
        // These values belong only to this one-process startup fixture. They
        // make no production sizing or queue-capacity recommendation.
        let realtime = myownmesh_core::ConnectorRealtimeFlowPolicy::new(
            myownmesh_core::ConnectorRealtimeFlowCapacities::new(nz(2), nz(2), nz(2)),
            myownmesh_core::ConnectorRealtimeInboundLimits::new(nz(1_200), nz(8), nz(2)),
            myownmesh_core::ConnectorRealtimeByteBudgets::new(nz(32_768), nz(32_768)),
            myownmesh_core::RealtimeQueueOverflowRule::DropNewest,
        );
        let callbacks = myownmesh_core::ConnectorCallbackPolicy::new(
            myownmesh_core::ConnectorCallbackMailboxCapacities::new(nz(4), nz(4)),
            myownmesh_core::ConnectorCallbackServiceWeights::new(nz(1), nz(1), nz(1)),
            myownmesh_core::RealtimeConnectorPolicy::enabled_with_local_ceiling(
                nz(16_384),
                realtime,
            )
            .expect("startup fixture is internally consistent"),
        )
        .expect("callback fixture is internally consistent");
        let webrtc = myownmesh_core::WebRtcConnectorProfile::new(
            callbacks,
            myownmesh_core::PendingRemoteCandidatePolicy::new(nz(8), nz(16_384), nz(8), nz(8)),
        );
        myownmesh_core::WebRtcConnectorCapablePolicy::new(crate::test_resource_provider(), webrtc)
    }

    /// `shutdown` does not return before `control::serve` and the connections it
    /// accepted have ended.
    ///
    /// The finding this pins is that the spawn's `JoinHandle` used to be
    /// dropped. Dropping one detaches the task, so `shutdown` had nothing to
    /// wait on and returned while the control socket, its connection tasks and
    /// their registrations were all still up — and it then tore down the
    /// services and networks those tasks were still dispatching against. An
    /// embedder was told the daemon was closed while it was not.
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
    /// exactly the task the old shape returned without waiting for.
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
            identity_path: Some(temp.path().join("identity.json")),
            auto_update: myownmesh_core::AutoUpdateConfig {
                enabled: false,
                ..Default::default()
            },
            daemon: daemon_config,
            services,
            ..Default::default()
        };

        let daemon = start_infrastructure_only(cfg, crate::test_resource_provider())
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

        let drained_before_teardown = daemon.control_drained_before_teardown_for_test();

        // The claim. The witness was sampled inside shutdown, before its first
        // service-teardown await, rather than after this call returned.
        guarded("embedded shutdown returns", daemon.shutdown()).await;
        assert!(
            drained_before_teardown.load(std::sync::atomic::Ordering::Acquire),
            "control::serve and every connection it accepted ended before \
             embedded shutdown began tearing down services"
        );

        // External companion (1): the connection that served this client ended.
        let mut rest = Vec::new();
        guarded(
            "the client's connection ended",
            client_reader.read_to_end(&mut rest),
        )
        .await
        .expect("the client's half reads to end");

        // External companion (2): the listener is gone with it.
        assert!(
            LocalSocketStream::connect(name).await.is_err(),
            "serve returned, so its control socket no longer accepts connections"
        );
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
