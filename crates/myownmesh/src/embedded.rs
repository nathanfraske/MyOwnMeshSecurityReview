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
}

impl EmbeddedDaemon {
    /// The device handle — identity, events, joins.
    pub fn mesh(&self) -> &myownmesh_core::MeshHandle {
        &self.mesh
    }

    /// Graceful teardown, exactly like the serve binary's signal path.
    pub async fn shutdown(self) {
        let _ = self.shutdown_tx.send(());
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
    tokio::spawn(async move {
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
    });

    Ok(EmbeddedDaemon {
        mesh,
        registry,
        service_manager,
        shutdown_tx,
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
