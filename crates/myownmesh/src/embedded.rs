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

    #[cfg(feature = "legacy-media")]
    #[error("legacy media profile: {0}")]
    LegacyMediaProfile(#[from] myownmesh_core::WebRtcConnectorProfileError),
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

enum ServiceCompatibility {
    V4,
    #[cfg(feature = "legacy-v1")]
    LegacyV1(myownmesh_core::legacy_v1::LegacyV1Runtime),
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
        for net in self.registry.take_all() {
            if let Err(e) = net.leave().await {
                warn!("leave failed: {e:#}");
            }
        }
    }
}

/// Start the daemon with the connector policy selected by the process owner.
///
/// This is the only Arc 03 daemon path that can establish connectors. No
/// capacity, callback weight, or structural real-time limit is inferred here.
pub async fn start_connector_capable(
    cfg: myownmesh_core::MeshConfig,
    connector_policy: myownmesh_core::WebRtcConnectorCapablePolicy,
) -> std::result::Result<EmbeddedDaemon, EmbeddedStartError> {
    ServiceManager::validate_config(&cfg.services)?;
    let mesh = myownmesh_core::Mesh::open_connector_capable(cfg.clone(), connector_policy).await?;
    start_with_mesh(cfg, mesh, ServiceCompatibility::V4).await
}

/// Start the temporary H.264 and Opus compatibility adapter from an explicit,
/// reviewed media profile. Normal V4 startup never infers or installs it.
#[cfg(feature = "legacy-media")]
#[allow(
    deprecated,
    reason = "this exact function is the temporary legacy media deployment boundary"
)]
#[deprecated(
    since = "0.3.2",
    note = "temporary H.264 and Opus deployment path for downstream migration"
)]
pub async fn start_connector_capable_with_legacy_media(
    cfg: myownmesh_core::MeshConfig,
    connector_policy: myownmesh_core::WebRtcConnectorCapablePolicy,
    media_profile: myownmesh_core::LegacyWebRtcMediaProfile,
) -> std::result::Result<EmbeddedDaemon, EmbeddedStartError> {
    let connector_policy = connector_policy_with_legacy_media(connector_policy, media_profile)?;
    start_connector_capable(cfg, connector_policy).await
}

#[cfg(feature = "legacy-media")]
#[allow(
    deprecated,
    reason = "this exact helper is confined to the temporary legacy media deployment boundary"
)]
fn connector_policy_with_legacy_media(
    connector_policy: myownmesh_core::WebRtcConnectorCapablePolicy,
    media_profile: myownmesh_core::LegacyWebRtcMediaProfile,
) -> std::result::Result<
    myownmesh_core::WebRtcConnectorCapablePolicy,
    myownmesh_core::WebRtcConnectorProfileError,
> {
    let webrtc = connector_policy
        .webrtc()
        .with_legacy_webrtc_media(media_profile)?;
    Ok(myownmesh_core::WebRtcConnectorCapablePolicy::new(
        connector_policy.process(),
        connector_policy.mesh(),
        webrtc,
    ))
}

/// Start the connector-capable daemon with an explicit frozen LegacyV1
/// compatibility runtime.
///
/// The normal V4 startup path cannot construct or reach this authority. This
/// function exists only with the `legacy-v1` feature and is scheduled for
/// deletion after downstream relay migration.
#[cfg(feature = "legacy-v1")]
#[allow(
    deprecated,
    reason = "this API is the explicit frozen LegacyV1 boundary"
)]
#[deprecated(
    since = "0.3.2",
    note = "LegacyV1 application routing is frozen and scheduled for removal after downstream migration"
)]
pub async fn start_connector_capable_with_legacy_v1(
    cfg: myownmesh_core::MeshConfig,
    connector_policy: myownmesh_core::WebRtcConnectorCapablePolicy,
    runtime: myownmesh_core::legacy_v1::LegacyV1Runtime,
) -> std::result::Result<EmbeddedDaemon, EmbeddedStartError> {
    let mesh = myownmesh_core::Mesh::open_connector_capable(cfg.clone(), connector_policy).await?;
    start_with_mesh(cfg, mesh, ServiceCompatibility::LegacyV1(runtime)).await
}

/// Start the frozen LegacyV1 routing runtime with the temporary reviewed
/// H.264 and Opus provider attached as an explicit sidecar profile.
///
/// This is the only deployment form that composes both compatibility paths.
/// Normal V4 startup cannot infer either authority.
#[cfg(all(feature = "legacy-v1", feature = "legacy-media"))]
#[allow(
    deprecated,
    reason = "this API is the explicit LegacyV1 plus legacy-media sidecar boundary"
)]
#[deprecated(
    since = "0.3.2",
    note = "temporary LegacyV1 and H.264/Opus sidecar for downstream migration"
)]
pub async fn start_connector_capable_with_legacy_v1_and_media(
    cfg: myownmesh_core::MeshConfig,
    connector_policy: myownmesh_core::WebRtcConnectorCapablePolicy,
    runtime: myownmesh_core::legacy_v1::LegacyV1Runtime,
    media_profile: myownmesh_core::LegacyWebRtcMediaProfile,
) -> std::result::Result<EmbeddedDaemon, EmbeddedStartError> {
    let connector_policy = connector_policy_with_legacy_media(connector_policy, media_profile)?;
    let mesh = myownmesh_core::Mesh::open_connector_capable(cfg.clone(), connector_policy).await?;
    start_with_mesh(cfg, mesh, ServiceCompatibility::LegacyV1(runtime)).await
}

/// Start a daemon that only hosts signaling, STUN, or TURN infrastructure.
///
/// The configuration must explicitly disable node participation. This form
/// installs no connector policy, joins no network, and cannot later enable
/// node participation through the live service configuration.
pub async fn start_infrastructure_only(
    cfg: myownmesh_core::MeshConfig,
) -> std::result::Result<EmbeddedDaemon, EmbeddedStartError> {
    if cfg.services.node.enabled {
        return Err(EmbeddedStartError::InfrastructureOnlyRequiresNodeDisabled);
    }
    ServiceManager::validate_config(&cfg.services)?;
    let mesh = myownmesh_core::Mesh::open_infrastructure_only(cfg.clone()).await?;
    start_with_mesh(cfg, mesh, ServiceCompatibility::V4).await
}

async fn start_with_mesh(
    cfg: myownmesh_core::MeshConfig,
    mesh: myownmesh_core::MeshHandle,
    compatibility: ServiceCompatibility,
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

    // Infrastructure services (relay / signaling / STUN / TURN); an all-off
    // config (the default) starts nothing.
    let service_manager = match compatibility {
        ServiceCompatibility::V4 => ServiceManager::new(mesh.clone(), registry.clone()),
        #[cfg(feature = "legacy-v1")]
        ServiceCompatibility::LegacyV1(runtime) => {
            ServiceManager::new_with_legacy_v1(mesh.clone(), registry.clone(), runtime)
        }
    };
    let report = service_manager.apply(cfg.services.clone()).await?;
    info!(
        relay = report.relay.enabled,
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

    #[cfg(feature = "legacy-media")]
    fn nz(value: usize) -> std::num::NonZeroUsize {
        std::num::NonZeroUsize::new(value).expect("legacy-media deployment fixture is nonzero")
    }

    #[cfg(feature = "legacy-media")]
    fn legacy_media_test_policy() -> myownmesh_core::WebRtcConnectorCapablePolicy {
        // These values belong only to this one-process startup fixture. They
        // make no production sizing or queue-capacity recommendation.
        let realtime = myownmesh_core::ConnectorRealtimeFlowPolicy::new(
            myownmesh_core::ConnectorRealtimeFlowCapacities::new(nz(2), nz(2), nz(2)),
            myownmesh_core::ConnectorRealtimeInboundLimits::new(
                nz(1_200),
                nz(8),
                nz(2),
                nz(16),
                nz(16_384),
            ),
            myownmesh_core::ConnectorRealtimeByteBudgets::new(nz(32_768), nz(32_768)),
            myownmesh_core::RealtimeQueueOverflowRule::DropNewest,
        );
        let callbacks = myownmesh_core::ConnectorCallbackPolicy::new(
            myownmesh_core::ConnectorCallbackMailboxCapacities::new(nz(4), nz(4)),
            myownmesh_core::ConnectorCallbackServiceWeights::new(nz(1), nz(1), nz(1)),
            myownmesh_core::RealtimeConnectorPolicy::enabled(nz(16_384), realtime)
                .expect("legacy-media deployment fixture is internally consistent"),
        )
        .expect("legacy-media callback fixture is internally consistent");
        let webrtc = myownmesh_core::WebRtcConnectorProfile::new(
            callbacks,
            myownmesh_core::PendingRemoteCandidatePolicy::new(nz(8), nz(16_384), nz(8), nz(8)),
        );
        myownmesh_core::WebRtcConnectorCapablePolicy::new(
            myownmesh_core::ConnectorResourcePolicy::new(nz(
                crate::TEST_PROCESS_CONNECTOR_CAPACITY,
            ))
            .expect("legacy-media cleanup fixture fits Tokio's queue bound"),
            myownmesh_core::MeshConnectorResourcePolicy::new(nz(2)),
            webrtc,
        )
    }

    #[tokio::test]
    async fn infrastructure_start_requires_node_participation_disabled() {
        let result = start_infrastructure_only(myownmesh_core::MeshConfig::default()).await;
        assert!(matches!(
            result,
            Err(EmbeddedStartError::InfrastructureOnlyRequiresNodeDisabled)
        ));
    }

    #[cfg(feature = "legacy-media")]
    #[allow(
        deprecated,
        reason = "this test proves the explicit temporary deployment boundary"
    )]
    #[tokio::test]
    async fn v4_arc03h_legacy_media_profile_uses_the_supported_deployment_form() {
        let temp = tempfile::tempdir().expect("temporary daemon state");
        let mut daemon = myownmesh_core::MeshConfig::default().daemon;
        daemon.control_socket = Some(temp.path().join("daemon.sock"));
        let cfg = myownmesh_core::MeshConfig {
            identity_path: Some(temp.path().join("identity.json")),
            auto_update: myownmesh_core::AutoUpdateConfig {
                enabled: false,
                ..Default::default()
            },
            daemon,
            ..Default::default()
        };

        let media_profile = myownmesh_core::LegacyWebRtcMediaProfile::h264_opus(nz(2), 1, 1)
            .expect("reviewed compatibility fixture is valid");
        let policy = connector_policy_with_legacy_media(legacy_media_test_policy(), media_profile)
            .expect("explicit compatibility profile attaches");
        assert_eq!(policy.webrtc().legacy_media(), Some(media_profile));

        let daemon = start_connector_capable_with_legacy_media(
            cfg,
            legacy_media_test_policy(),
            media_profile,
        )
        .await
        .expect("temporary legacy-media daemon starts only from the explicit profile");
        assert!(daemon.mesh().connector_resource_report().is_some());
        daemon.shutdown().await;
    }

    #[cfg(all(feature = "legacy-v1", feature = "legacy-media"))]
    #[allow(
        deprecated,
        reason = "this test proves the explicit temporary sidecar deployment boundary"
    )]
    #[tokio::test]
    async fn v4_arc03j_legacy_media_sidecar_composes_only_with_explicit_legacy_v1_runtime() {
        let temp = tempfile::tempdir().expect("temporary daemon state");
        let mut daemon_config = myownmesh_core::MeshConfig::default().daemon;
        daemon_config.control_socket = Some(temp.path().join("daemon-sidecar.sock"));
        let cfg = myownmesh_core::MeshConfig {
            identity_path: Some(temp.path().join("identity-sidecar.json")),
            auto_update: myownmesh_core::AutoUpdateConfig {
                enabled: false,
                ..Default::default()
            },
            daemon: daemon_config,
            ..Default::default()
        };
        let media_profile = myownmesh_core::LegacyWebRtcMediaProfile::h264_opus(nz(2), 1, 1)
            .expect("reviewed sidecar fixture is valid");
        let daemon = start_connector_capable_with_legacy_v1_and_media(
            cfg,
            legacy_media_test_policy(),
            myownmesh_core::legacy_v1::LegacyV1Runtime::frozen(),
            media_profile,
        )
        .await
        .expect("the explicit combined compatibility constructor starts");
        assert!(daemon.mesh().connector_resource_report().is_some());
        daemon.shutdown().await;
    }
}
